# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Upstream-Research-Worker (Block AI, ADR-0063, P5).

Eigenstaendiger Worker-Prozess (``python -m app.workers.research_worker``) in
einem **separaten Container**. Pollt ausschliesslich ``upstream_check_results``
(NICHT ``llm_jobs`` — saubere Trennung zum ``llm_worker``) und faehrt fuer jede
``status='queued'``-Zeile den agentischen Upstream-Check
(:func:`app.services.upstream_research.research_upstream_sync`).

Architektur — **bewusst einfacher** als der ``llm_worker``:

* **Eine Tabelle = Queue + Request + Cache.** Kein ``depends_on``, kein
  Sibling-Pass, keine In-Process-Concurrency, **kein** Token-Budget (der Check
  ist interaktiv/niederfrequent, ADR-0055-Geist wie der Group-Chat).
* **Claim** mit ``SELECT … FOR UPDATE SKIP LOCKED`` (Multi-Worker-sicher).
* **Gate:** ist das Feature nicht konfiguriert, wird die Zeile sofort auf
  ``error='not_configured'`` gesetzt (kein Retry-Sturm). Air-Gap-tauglich:
  der Container darf einfach idle laufen wenn das Feature aus ist.
* **Stale-Reaper** fuer haengende ``running``-Zeilen.
* **Heartbeat-Daemon-Thread** schreibt ``settings.research_worker_heartbeat_at``
  unabhaengig vom (potentiell langen) Agent-Run.
* **Graceful Shutdown** auf SIGTERM/SIGINT.

**Security:** persistierte Fehler sind generische Codes (``provider_error`` etc.)
— niemals der rohe Stacktrace/die rohe Exception (kein Key-/Secret-Leak). Der
``encryption_key`` wird wie im ``llm_worker`` aus ``cfg.encryption_key`` gezogen
und nie geloggt.
"""

from __future__ import annotations

import logging
import os
import re
import signal
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.config import load_settings
from app.models import UpstreamCheckResult
from app.services.upstream_research import (
    build_search_config,
    is_upstream_check_configured,
    research_upstream_sync,
)
from app.services.upstream_seed import ResearchSeed
from app.settings_service import ensure_settings_row

log = logging.getLogger("fathometer.research_worker")


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

WORKER_ID: str = f"{socket.gethostname()}:{os.getpid()}"
HEARTBEAT_INTERVAL_SEC: float = 10.0
STALE_REAPER_INTERVAL_SEC: float = 60.0


def _poll_interval() -> float:
    """Poll-Intervall (Sekunden) — ``FM_RESEARCH_WORKER_POLL_INTERVAL_SEC``."""
    raw = os.environ.get("FM_RESEARCH_WORKER_POLL_INTERVAL_SEC")
    if raw is None:
        return 5.0
    try:
        value = float(raw)
    except ValueError:
        return 5.0
    return value if value >= 0.1 else 5.0


def _max_attempts() -> int:
    """Max. Versuche pro Zeile — ``FM_RESEARCH_WORKER_MAX_ATTEMPTS`` (Default 3)."""
    raw = os.environ.get("FM_RESEARCH_WORKER_MAX_ATTEMPTS")
    if raw is None:
        return 3
    try:
        value = int(raw)
    except ValueError:
        return 3
    return value if value >= 1 else 3


def _stale_timeout_min() -> int:
    """Stale-Timeout (Minuten) — ``FM_RESEARCH_WORKER_STALE_TIMEOUT_MIN`` (Default 10)."""
    raw = os.environ.get("FM_RESEARCH_WORKER_STALE_TIMEOUT_MIN")
    if raw is None:
        return 10
    try:
        value = int(raw)
    except ValueError:
        return 10
    return value if value >= 1 else 10


# Modul-State.
_shutdown: bool = False
_last_reaper_at: float = 0.0
_heartbeat_thread: threading.Thread | None = None
_heartbeat_thread_stop: threading.Event = threading.Event()
_session_factory: sessionmaker[Session] | None = None


# ---------------------------------------------------------------------------
# Session-Management
# ---------------------------------------------------------------------------


def _get_session_factory() -> sessionmaker[Session]:
    """Lazy-baut die Worker-Session-Factory aus ``FM_DATABASE_URL``."""
    global _session_factory
    if _session_factory is None:
        cfg = load_settings()
        engine = create_engine(
            cfg.database_url,
            pool_pre_ping=True,
            future=True,
        )
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    return _session_factory


def set_session_factory_for_tests(factory: sessionmaker[Session]) -> None:
    """Test-Hook — uebergibt eine vorgebackene Session-Factory."""
    global _session_factory
    _session_factory = factory


@contextmanager
def get_session() -> Iterator[Session]:
    """Context-Manager mit rollback-on-error + close."""
    factory = _get_session_factory()
    session = factory()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Signal-Handling / Test-Hooks
# ---------------------------------------------------------------------------


def _signal_handler(signum: int, frame: Any) -> None:
    """Setzt das Shutdown-Flag — der aktuelle Tick faehrt zu Ende."""
    global _shutdown
    log.info("research_worker.shutdown_requested signum=%s", signum)
    _shutdown = True


def request_shutdown_for_tests() -> None:
    """Test-Hook — setzt das Shutdown-Flag von aussen."""
    global _shutdown
    _shutdown = True


def reset_shutdown_for_tests() -> None:
    """Test-Hook — setzt Worker-State zwischen Tests zurueck."""
    global _shutdown, _last_reaper_at
    _shutdown = False
    _last_reaper_at = 0.0
    _heartbeat_thread_stop.clear()


# ---------------------------------------------------------------------------
# Fehler-Code-Mapping (Security: kein Stacktrace-/Key-Leak)
# ---------------------------------------------------------------------------


#: Substrings, die im Exception-Preview ein Geheimnis tragen koennten
#: (Query-Param/Header/Basic-Auth). Der Worker nutzt stdlib ``logging`` — der
#: structlog-Redaction-Processor greift hier NICHT, also redacten wir den
#: untrusted Exception-Text vor dem Loggen selbst (kein DB-Persist davon).
_SECRET_REDACT_RE = re.compile(
    r"""(?ix)
    (                                   # 1: key=value / key: value Geheimnisse
        (?:password|passwd|pwd|api[_-]?key|apikey|token|secret|authorization)
        \s*[=:]\s*
    )
    (?:bearer\s+|basic\s+)?             # optionales Auth-Scheme-Prefix (verworfen)
    \S+
    |
    (https?://)[^/\s:@]+:[^/\s@]+@       # 2: userinfo in einer URL (user:pass@host)
    """,
    re.VERBOSE,
)


def _redact_preview(text_value: str) -> str:
    """Maskiert Secret-tragende Substrings in einem Log-Preview.

    Deckt ``password=``/``api_key=``/``token=``/``Authorization:``-Paare und
    URL-Userinfo (``https://user:pass@host``) ab. Best-effort, leck-armer
    Forensik-Preview — die DB sieht weiterhin nur den generischen
    :func:`classify_error`-Code.
    """

    def _sub(m: re.Match[str]) -> str:
        if m.group(2):  # URL-Userinfo
            return f"{m.group(2)}[REDACTED]@"
        return f"{m.group(1)}[REDACTED]"

    return _SECRET_REDACT_RE.sub(_sub, text_value)


def classify_error(exc: BaseException) -> str:
    """Mappt eine Exception auf einen generischen, leck-freien Fehler-Code.

    Wir persistieren NIE den rohen Exception-Text (kann API-Keys, URLs mit
    Credentials oder andere Geheimnisse enthalten). Stattdessen ein kurzer,
    stabiler Code fuer die UI/Operator-Diagnose.

    Mapping (best-effort, klassenname-basiert damit keine optionalen
    Abhaengigkeiten importiert werden muessen):

    * Timeout/Deadline -> ``timeout``
    * httpx-/Connection-/Netz-Fehler -> ``search_error``
    * Provider-/LLM-/Agent-Fehler (UsageLimit, OpenAI, Auth) -> ``provider_error``
    * alles andere -> ``internal_error``
    """
    name = type(exc).__name__.lower()
    module = type(exc).__module__.lower()

    if "timeout" in name or "deadline" in name:
        return "timeout"
    if "httpx" in module or "connect" in name or "network" in name or "dns" in name:
        return "search_error"
    if (
        "openai" in module
        or "pydantic_ai" in module
        or "usagelimit" in name
        or "auth" in name
        or "apikey" in name
        or "ratelimit" in name
    ):
        return "provider_error"
    return "internal_error"


# ---------------------------------------------------------------------------
# Claim
# ---------------------------------------------------------------------------


def _pick_next_row_id() -> int | None:
    """Claimt die naechste ``queued``-Zeile mit FOR UPDATE SKIP LOCKED.

    Setzt sie atomar auf ``running`` (``picked_up_at``/``picked_up_by``,
    ``attempts+1``) und gibt die ID zurueck. ``None`` wenn nichts faellig ist.
    """
    sql = text(
        """
        WITH job AS (
          SELECT id FROM upstream_check_results
          WHERE status = 'queued'
            AND (next_attempt_at IS NULL OR next_attempt_at <= now())
          ORDER BY requested_at
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE upstream_check_results SET
          status = 'running',
          picked_up_by = :worker_id,
          picked_up_at = now(),
          attempts = attempts + 1
        WHERE id IN (SELECT id FROM job)
        RETURNING id
        """
    )
    with get_session() as session:
        row = session.execute(sql, {"worker_id": WORKER_ID}).fetchone()
        session.commit()
        if row is None:
            return None
        return int(row[0])


# ---------------------------------------------------------------------------
# Job-Processing
# ---------------------------------------------------------------------------


def _seed_from_row(row: UpstreamCheckResult) -> ResearchSeed:
    """Rekonstruiert den :class:`ResearchSeed` aus dem Zeilen-Snapshot.

    Bewusst aus der Zeile (nicht aus dem Finding) — das Finding kann zwischen
    Enqueue und Worker-Run geloescht worden sein. Die Snapshot-Felder wurden
    beim Enqueue gefuellt; defensive Fallbacks fuer den (eigentlich nie
    eintretenden) None-Fall der Pflicht-Snapshot-Felder.
    """
    return ResearchSeed(
        artifact_module=row.artifact_module,
        installed_component_version=row.installed_version,
        ecosystem=row.ecosystem or "unknown",
        finding_class="lang-pkgs",
        binary_path=row.binary_path or "",
        vulnerable_component=row.vulnerable_component or "",
        fixing_component_version=row.fixing_component_version or "",
        cve=row.cve or "",
        description=row.description,
        search_hint=row.search_hint,
    )


def _process_row(row_id: int) -> None:
    """Verarbeitet eine geclaimte Zeile: Gate -> Run -> Persist.

    Der (potentiell lange) Agent-Run laeuft ausserhalb einer offenen DB-Session;
    persistiert wird in einer frischen Session (Pattern wie llm_worker/group_chat).
    """
    # 1) Gate + Seed-Rekonstruktion (kurze Session).
    with get_session() as session:
        row = session.get(UpstreamCheckResult, row_id)
        if row is None:
            log.warning("research_worker.row_missing row_id=%s", row_id)
            return
        settings_row = ensure_settings_row(session)
        if not is_upstream_check_configured(settings_row):
            # Kein Retry-Sturm: sofort auf error='not_configured'.
            row.status = "error"
            row.error = "not_configured"
            row.checked_at = datetime.now(UTC)
            session.commit()
            log.info("research_worker.not_configured row_id=%s", row_id)
            return
        seed = _seed_from_row(row)
        cfg = load_settings()
        encryption_key = cfg.encryption_key.get_secret_value()
        # SearchConfig + Modellname innerhalb der Session bauen (entschluesselt
        # Secrets ueber dieselbe Fernet-Pipeline wie der Reviewer/Chat).
        search_cfg = build_search_config(settings_row, encryption_key=encryption_key)
        model_name = getattr(settings_row, "llm_research_model", None)

    # 2) Agent-Run ausserhalb jeder DB-Session (kann 30-120s dauern).
    log.info("research_worker.run_started row_id=%s artifact=%s", row_id, seed.artifact_module)
    verdict = research_upstream_sync(
        seed,
        settings_row=settings_row,
        encryption_key=encryption_key,
        search_cfg=search_cfg,
    )

    # 3) Persist in frischer Session.
    with get_session() as session:
        row = session.get(UpstreamCheckResult, row_id)
        if row is None:  # pragma: no cover — Zeile zwischenzeitlich geloescht
            log.warning("research_worker.row_vanished_after_run row_id=%s", row_id)
            return
        row.delivery = verdict.delivery
        row.fixing_component_version = verdict.fixing_component_version
        row.latest_release_component_version = verdict.latest_release_component_version
        row.fixed_build_release = verdict.fixed_build_release
        row.fixed_build_release_date = verdict.fixed_build_release_date
        row.operator_action = verdict.operator_action
        row.confidence = verdict.confidence
        row.sources_used = list(verdict.sources_used)
        row.reasoning = verdict.reasoning
        row.model = model_name
        row.status = "done"
        row.error = None
        row.checked_at = datetime.now(UTC)
        session.commit()
    log.info("research_worker.run_done row_id=%s delivery=%s", row_id, verdict.delivery)


def _fail_or_requeue(row_id: int, error_code: str) -> None:
    """Behandelt einen Verarbeitungsfehler: Backoff-Requeue oder finaler Fehler.

    ``attempts < MAX`` -> zurueck auf ``queued`` mit Backoff
    (``next_attempt_at = now() + attempts * 1 minute``); sonst ``status='error'``
    mit dem generischen ``error_code`` (KEIN roher Stacktrace).
    """
    max_attempts = _max_attempts()
    with get_session() as session:
        row = session.get(UpstreamCheckResult, row_id)
        if row is None:  # pragma: no cover
            return
        if row.attempts < max_attempts:
            session.execute(
                text(
                    """
                    UPDATE upstream_check_results
                    SET status = 'queued',
                        picked_up_by = NULL,
                        picked_up_at = NULL,
                        next_attempt_at = now() + (attempts * interval '1 minute')
                    WHERE id = :id
                    """
                ),
                {"id": row_id},
            )
            log.warning(
                "research_worker.requeued row_id=%s attempts=%s error=%s",
                row_id,
                row.attempts,
                error_code,
            )
        else:
            row.status = "error"
            row.error = error_code
            row.checked_at = datetime.now(UTC)
            log.warning(
                "research_worker.failed row_id=%s attempts=%s error=%s",
                row_id,
                row.attempts,
                error_code,
            )
        session.commit()


def _process_one(row_id: int) -> None:
    """Wrapper: faengt alle Exceptions, mappt auf Fehler-Code, requeue/fail."""
    try:
        _process_row(row_id)
    except Exception as exc:
        error_code = classify_error(exc)
        # Den rohen Exception-Text NICHT persistieren — nur ein gekapptes,
        # redactetes Log-Preview (Operator-Forensik), kein DB-Persist (kein
        # UI-Leak). stdlib-logging hat keinen structlog-Redaction-Processor,
        # also vor dem Loggen Secret-Substrings selbst maskieren.
        preview = _redact_preview(str(exc))[:200]
        log.warning(
            "research_worker.process_failed row_id=%s error_code=%s preview=%s",
            row_id,
            error_code,
            preview,
        )
        _fail_or_requeue(row_id, error_code)


# ---------------------------------------------------------------------------
# Stale-Reaper
# ---------------------------------------------------------------------------


def _run_stale_reaper() -> None:
    """Reset't ``running``-Zeilen deren ``picked_up_at`` zu alt ist.

    ``attempts < MAX`` -> zurueck auf ``queued`` mit Backoff; sonst
    ``status='error'``, ``error='stale_timeout'``.
    """
    timeout_min = _stale_timeout_min()
    max_attempts = _max_attempts()
    with get_session() as session:
        requeued = session.execute(
            text(
                """
                UPDATE upstream_check_results
                SET status = 'queued',
                    picked_up_by = NULL,
                    picked_up_at = NULL,
                    next_attempt_at = now() + (attempts * interval '1 minute')
                WHERE status = 'running'
                  AND picked_up_at < now() - make_interval(mins => :mins)
                  AND attempts < :max_attempts
                RETURNING id
                """
            ),
            {"mins": timeout_min, "max_attempts": max_attempts},
        ).fetchall()
        failed = session.execute(
            text(
                """
                UPDATE upstream_check_results
                SET status = 'error',
                    error = 'stale_timeout',
                    checked_at = now()
                WHERE status = 'running'
                  AND picked_up_at < now() - make_interval(mins => :mins)
                  AND attempts >= :max_attempts
                RETURNING id
                """
            ),
            {"mins": timeout_min, "max_attempts": max_attempts},
        ).fetchall()
        session.commit()
        if requeued or failed:
            log.info(
                "research_worker.stale_reaped requeued=%s failed=%s",
                len(requeued),
                len(failed),
            )


def _maybe_run_stale_reaper() -> None:
    """Stale-Reaper-Sub-Tick mit Cadence-Tracking (alle 60s)."""
    global _last_reaper_at
    now_mono = time.monotonic()
    if now_mono - _last_reaper_at > STALE_REAPER_INTERVAL_SEC:
        try:
            _run_stale_reaper()
        except Exception:  # pragma: no cover — DB-Hickup darf Worker nicht killen
            log.exception("research_worker.stale_reaper_failed")
        _last_reaper_at = now_mono


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def _write_heartbeat() -> None:
    """Schreibt ``settings.research_worker_heartbeat_at = now()``."""
    try:
        with get_session() as session:
            row = ensure_settings_row(session)
            row.research_worker_heartbeat_at = datetime.now(UTC)
            session.commit()
    except Exception:  # pragma: no cover — DB-Hickup
        log.exception("research_worker.heartbeat_failed")


def _heartbeat_loop() -> None:
    """Daemon-Loop der unabhaengig vom Tick alle 10s den Heartbeat schreibt.

    Wie im ``llm_worker``: der Heartbeat darf nicht hinter einem 30-120s langen
    Agent-Run veralten, sonst kickt der Healthcheck den Container mitten im Run.
    """
    log.info("research_worker.heartbeat_thread_started interval_sec=%s", HEARTBEAT_INTERVAL_SEC)
    while not _heartbeat_thread_stop.is_set():
        try:
            _write_heartbeat()
        except Exception:  # pragma: no cover
            log.exception("research_worker.heartbeat_thread_write_failed")
        _heartbeat_thread_stop.wait(timeout=HEARTBEAT_INTERVAL_SEC)
    log.info("research_worker.heartbeat_thread_stopped")


def _start_heartbeat_thread() -> threading.Thread:
    """Startet den Heartbeat-Daemon-Thread (idempotent)."""
    global _heartbeat_thread
    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        return _heartbeat_thread
    _heartbeat_thread_stop.clear()
    _heartbeat_thread = threading.Thread(
        target=_heartbeat_loop, daemon=True, name="research-worker-hb"
    )
    _heartbeat_thread.start()
    return _heartbeat_thread


def _stop_heartbeat_thread(timeout: float = 5.0) -> None:
    """Stoppt den Heartbeat-Thread (Stop-Event + Join). Idempotent."""
    global _heartbeat_thread
    _heartbeat_thread_stop.set()
    t = _heartbeat_thread
    if t is not None and t.is_alive():
        t.join(timeout=timeout)
    _heartbeat_thread = None


# ---------------------------------------------------------------------------
# Tick-Loop und Entrypoint
# ---------------------------------------------------------------------------


def _tick() -> bool:
    """Ein Tick: Stale-Reaper-Sub-Tick + maximal einen Job claimen/verarbeiten.

    Returns ``True`` wenn ein Job verarbeitet wurde (Caller pollt dann sofort
    weiter), ``False`` bei leerer Queue (Caller schlaeft ``_poll_interval()``).
    """
    try:
        _maybe_run_stale_reaper()
    except Exception:  # pragma: no cover — Sub-Tick-Sicherheitsnetz
        log.exception("research_worker.subtick_failed continuing")

    try:
        row_id = _pick_next_row_id()
    except Exception:  # pragma: no cover — DB-Hickup
        log.exception("research_worker.pickup_failed")
        return False
    if row_id is None:
        return False
    _process_one(row_id)
    return True


def main() -> None:
    """Worker-Entrypoint.

    Setup synchron (Logging, Signal-Handler, Heartbeat-Daemon-Thread), dann
    Endlos-Tick-Loop bis SIGTERM/SIGINT. Robust gegen fehlende Feature-Config:
    laeuft auch wenn das Feature aus ist (claimt dann nichts bzw. markiert
    geclaimte Zeilen als ``not_configured``).
    """
    logging.basicConfig(
        level=load_settings().log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    _start_heartbeat_thread()
    log.info(
        "research_worker.starting worker_id=%s poll=%ss stale_timeout_min=%s",
        WORKER_ID,
        _poll_interval(),
        _stale_timeout_min(),
    )

    try:
        while not _shutdown:
            processed = _tick()
            if not processed and not _shutdown:
                time.sleep(_poll_interval())
    finally:
        _stop_heartbeat_thread(timeout=5.0)
        log.info("research_worker.shutdown_complete worker_id=%s", WORKER_ID)


if __name__ == "__main__":  # pragma: no cover
    main()
