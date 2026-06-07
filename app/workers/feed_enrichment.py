# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""External-EPSS/KEV-Feed-Pull-Worker (ADR-0024, Block Q Phase 1).

Wird vom ``llm_worker``-Sub-Tick ``_run_feed_enrichment_check`` aufgerufen.
Pullt einmal pro Feed alle 24h (±Jitter) das Daily-EPSS-Snapshot von
FIRST.org und den CISA-KEV-Catalog, validiert Pydantic-strikt und
UPSERTet in ``epss_scores`` bzw. ``cisa_kev_catalog``.

Phase-1-Scope (NUR diese Funktionen):

* :func:`pull_epss` — Stream-Decompress des gzipped CSV, Pydantic-
  Validation pro Row, Batch-UPSERT.
* :func:`pull_kev` — Single-Shot-JSON-Parse, Pydantic-Validation der
  ganzen Struktur, Batch-UPSERT in einer Charge.
* :func:`feed_enrichment_tick` — Entry-Point fuer den Worker-Sub-Tick.
  Liest letzten erfolgreichen Pull pro Feed, entscheidet ob ein neuer
  Pull faellig ist, ruft Pull-Funktionen mit einer gemeinsamen httpx-
  Client-Instanz.

Was NICHT hier ist (Phase 2/3/4):

* Ingest-Anreicherung in ``findings_ingest.py`` — Phase 2.
* Bootstrap-Backfill ueber bestehende Findings — Phase 3.
* UI-Feed-Status-Anzeige — Phase 4.
"""

from __future__ import annotations

import contextlib
import csv
import gzip
import io
import random
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.audit import log_event
from app.config import load_settings
from app.models import CisaKevCatalog, EpssScore, FeedPullLog
from app.schemas.feed_enrichment import EpssRow, KevEntry, KevFeed
from app.services.feed_backfill import backfill_epss, backfill_kev

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Konstanten
# ---------------------------------------------------------------------------

# Batch-Groesse fuer EPSS-UPSERT. ~250k Rows / 5000 = 50 Chunks. Postgres-
# Bind-Param-Limit ist 65535; 5000 Rows * 4 Bind-Params = 20000, gut unter
# dem Cap.
_EPSS_UPSERT_CHUNK: int = 5000

# Hard-Cap auf die feed_pull_log-Tabelle pro feed_name. Wird beim erfolg-
# reichen Pull am Ende geprueft (ADR-0024 "Eviction in feed_pull_log: hard-
# cap 100 Zeilen pro feed_name").
_FEED_PULL_LOG_KEEP_ROWS: int = 100

# Wenn mehr als dieser Anteil der EPSS-Rows ungueltig ist, abortet der Pull.
# Schuetzt gegen ein hypothetisches Feed-Schema-Bruch (z.B. Spalten-Rename)
# wo wir lieber nichts importieren als Mist persistieren.
_EPSS_INVALID_ROW_RATIO_ABORT: float = 0.01

# Chunked-Read-Groesse fuer gzip-Stream. 64 KB = guter Trade-off zwischen
# Syscall-Overhead und RAM-Footprint.
_GZIP_READ_CHUNK_BYTES: int = 64 * 1024

# Per-Pull-HTTP-Timeout. Großzuegig fuer 50 MB CSV-Download auf
# langsameren Verbindungen.
_HTTP_TIMEOUT_SEC: float = 120.0


# ---------------------------------------------------------------------------
# Hilfs-API fuer das Audit-Log
# ---------------------------------------------------------------------------


def _log_start(session: Session, feed_name: str) -> int:
    """Schreibt einen ``running``-Audit-Eintrag und committet sofort.

    Returns die ID damit der Caller den Eintrag am Ende per UPDATE auf
    ``success`` oder ``failed`` setzen kann (eine einzige Audit-Row pro
    Pull, kein doppelter Eintrag).
    """
    entry = FeedPullLog(feed_name=feed_name, status="running")
    session.add(entry)
    session.flush()
    session.commit()
    return int(entry.id)


def _log_success(
    session: Session,
    log_id: int,
    *,
    row_count: int,
    bytes_downloaded: int,
) -> None:
    """Setzt den Audit-Eintrag auf ``success`` mit Row-/Byte-Counts."""
    entry = session.get(FeedPullLog, log_id)
    if entry is None:  # pragma: no cover — Audit-Row wird in derselben Tx erzeugt
        return
    entry.status = "success"
    entry.completed_at = datetime.now(UTC)
    entry.row_count = row_count
    entry.bytes_downloaded = bytes_downloaded
    session.commit()


def _log_failure(session: Session, log_id: int, error_message: str) -> None:
    """Setzt den Audit-Eintrag auf ``failed`` mit Fehler-Text.

    Defensiv: die DB-Session koennte schon kaputt sein (z.B. nach einem
    ungefangenen UPSERT-Fehler). Wir rollback'en sicherheitshalber bevor
    wir die Failure-Row schreiben.
    """
    with contextlib.suppress(Exception):
        session.rollback()
    try:
        entry = session.get(FeedPullLog, log_id)
        if entry is None:  # pragma: no cover
            return
        entry.status = "failed"
        entry.completed_at = datetime.now(UTC)
        # Trim auf 8 KB damit ein riesiger Traceback die Tabelle nicht
        # aufblaeht. TEXT-Spalte ist zwar unlimited, aber 8 KB sind fuer
        # Operator-Triage mehr als genug.
        entry.error_message = error_message[:8192]
        session.commit()
    except Exception:  # pragma: no cover — DB komplett tot
        log.exception("feed.audit_failure_write_failed", log_id=log_id)


def _evict_old_audit_rows(session: Session, feed_name: str) -> None:
    """Haelt ``feed_pull_log`` pro ``feed_name`` auf max 100 Zeilen.

    Idempotent — wird nach jedem erfolgreichen Pull aufgerufen. Loescht
    alle Zeilen jenseits der jungsten 100 (per ``started_at DESC``).
    """
    # DELETE über Subquery damit wir den Index ix_feed_pull_log_feed_started
    # nutzen koennen.
    ids_to_keep = (
        select(FeedPullLog.id)
        .where(FeedPullLog.feed_name == feed_name)
        .order_by(FeedPullLog.started_at.desc())
        .limit(_FEED_PULL_LOG_KEEP_ROWS)
        .subquery()
    )
    stmt = (
        delete(FeedPullLog)
        .where(FeedPullLog.feed_name == feed_name)
        .where(~FeedPullLog.id.in_(select(ids_to_keep)))
    )
    session.execute(stmt)
    session.commit()


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------


def _stream_decompress_with_cap(
    response: httpx.Response,
    *,
    max_decompressed_bytes: int,
) -> tuple[bytes, int]:
    """Liest die gzipped HTTP-Response chunk-weise, decompressed mit Cap.

    Returns das vollstaendige dekomprimierte Bytes-Objekt + die Anzahl
    der komprimierten (raw HTTP) Bytes. Wir streamen das Compressed-Body
    in einen ``BytesIO``-Buffer, dann oeffnen wir den als ``GzipFile`` und
    lesen chunk-weise mit Byte-Counter — abort wenn das dekomprimierte
    Volumen die Cap-Grenze ueberschreitet (Gzip-Bomb-Schutz).

    Das ist ein bewusster Trade-off: wir halten max ``max_decompressed_bytes``
    im RAM (50 MB Default), nicht beides. EPSS-CSV ist klein genug.
    """
    compressed_bytes = bytearray()
    for chunk in response.iter_bytes(chunk_size=_GZIP_READ_CHUNK_BYTES):
        compressed_bytes.extend(chunk)
    bytes_downloaded = len(compressed_bytes)

    decompressed = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(bytes(compressed_bytes)), mode="rb") as gz:
        while True:
            chunk = gz.read(_GZIP_READ_CHUNK_BYTES)
            if not chunk:
                break
            if len(decompressed) + len(chunk) > max_decompressed_bytes:
                raise ValueError(
                    f"decompressed size exceeds cap of {max_decompressed_bytes} bytes "
                    "(possible gzip bomb)"
                )
            decompressed.extend(chunk)
    return bytes(decompressed), bytes_downloaded


def pull_epss(
    session: Session,
    *,
    http_client: httpx.Client,
) -> tuple[int, int]:
    """Pullt den EPSS-Daily-CSV-Snapshot und UPSERTet ihn in ``epss_scores``.

    Returns ``(row_count, bytes_downloaded)``. Bei Failure: ``ValueError``
    oder ``httpx.HTTPError`` werden propagiert — der Caller
    (:func:`feed_enrichment_tick`) faengt sie ab und schreibt das
    Audit-Log auf ``failed``.

    Format des CSV (laut FIRST.org-Spec):

    * Optionale Kommentarzeilen am Anfang die mit ``#`` beginnen (z.B.
      ``#model_version:v2024.12.10,score_date:2026-05-20T00:00:00+0000``).
    * Header-Zeile: ``cve,epss,percentile``.
    * Datenzeilen: ``CVE-2024-1234,0.00123,0.45678``.
    """
    cfg = load_settings()
    log_id = _log_start(session, "epss")

    started_mono = time.monotonic()
    try:
        with http_client.stream(
            "GET",
            cfg.feed_epss_url,
            headers={"Accept": "application/gzip, */*"},
        ) as response:
            response.raise_for_status()
            max_bytes = cfg.feed_max_decompressed_mb_epss * 1024 * 1024
            decompressed, bytes_downloaded = _stream_decompress_with_cap(
                response, max_decompressed_bytes=max_bytes
            )

        # CSV parsen. FIRST.org praefixed manchmal ein "#"-Kommentar als
        # erste Zeile; csv.reader erwartet den Header danach. Wir
        # ueberspringen alle initialen "#"-Zeilen.
        text_io = io.StringIO(decompressed.decode("utf-8", errors="strict"))
        reader = csv.reader(text_io)

        # Header (skipping leading comments).
        header: list[str] | None = None
        for row in reader:
            if not row:
                continue
            if row[0].startswith("#"):
                continue
            header = [c.strip().lower() for c in row]
            break
        if header is None or header[:3] != ["cve", "epss", "percentile"]:
            raise ValueError(f"unexpected EPSS CSV header: {header!r}")

        # Datenzeilen parsen + validieren.
        validated: list[dict[str, Any]] = []
        invalid_count = 0
        total_count = 0
        for raw_row in reader:
            if not raw_row or raw_row[0].startswith("#"):
                continue
            total_count += 1
            if len(raw_row) < 3:
                invalid_count += 1
                continue
            try:
                parsed = EpssRow(
                    cve=raw_row[0].strip(),
                    epss=float(raw_row[1]),
                    percentile=float(raw_row[2]),
                )
            except (ValidationError, ValueError):
                invalid_count += 1
                continue
            validated.append(
                {
                    "cve_id": parsed.cve,
                    "epss_score": parsed.epss,
                    "epss_percentile": parsed.percentile,
                    "updated_at": datetime.now(UTC),
                }
            )

        # Abort wenn zu viele Rows kaputt — wahrscheinlich ein
        # Schema-Bruch, dann lieber gar nicht persistieren.
        if total_count > 0 and (invalid_count / total_count) > _EPSS_INVALID_ROW_RATIO_ABORT:
            raise ValueError(
                f"EPSS pull aborted: {invalid_count}/{total_count} rows invalid "
                f"(> {_EPSS_INVALID_ROW_RATIO_ABORT * 100:.1f}% threshold)"
            )

        # Batch-UPSERT in Chunks.
        for chunk_start in range(0, len(validated), _EPSS_UPSERT_CHUNK):
            chunk = validated[chunk_start : chunk_start + _EPSS_UPSERT_CHUNK]
            stmt = pg_insert(EpssScore).values(chunk)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "epss_score": stmt.excluded.epss_score,
                    "epss_percentile": stmt.excluded.epss_percentile,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            session.execute(stmt)
        session.commit()

        row_count = len(validated)
        duration_ms = int((time.monotonic() - started_mono) * 1000)
        _log_success(
            session,
            log_id,
            row_count=row_count,
            bytes_downloaded=bytes_downloaded,
        )

        # Phase 3 (ADR-0024) — Backfill ueber bestehende Findings, idempotent.
        # Failure hier killt den als-erfolgreich-geloggten Pull NICHT (Audit
        # bleibt success); Backfill kann beim naechsten Tick wiederholt werden.
        backfilled = 0
        try:
            backfilled = backfill_epss(session)
        except Exception:  # pragma: no cover — defensiv gegen DB-Hickups
            log.exception("feed.epss_backfill_failed")

        _evict_old_audit_rows(session, "epss")
        log.info(
            "feed.epss_pulled",
            row_count=row_count,
            invalid_rows=invalid_count,
            bytes_downloaded=bytes_downloaded,
            duration_ms=duration_ms,
        )

        # Phase 4 (ADR-0024) — Audit-Event fuer Operator-Sichtbarkeit.
        with contextlib.suppress(Exception):
            log_event(
                "feed.epss_pulled",
                target_type="feed",
                target_id="epss",
                metadata={
                    "row_count": row_count,
                    "invalid_rows": invalid_count,
                    "bytes_downloaded": bytes_downloaded,
                    "duration_ms": duration_ms,
                    "findings_backfilled": backfilled,
                },
                session=session,
            )
            session.commit()
        return row_count, bytes_downloaded
    except Exception as exc:
        duration_ms = int((time.monotonic() - started_mono) * 1000)
        log.exception("feed.epss_pull_failed", duration_ms=duration_ms)
        _log_failure(session, log_id, f"{type(exc).__name__}: {exc}")
        with contextlib.suppress(Exception):
            log_event(
                "feed.epss_pull_failed",
                target_type="feed",
                target_id="epss",
                metadata={
                    "error": f"{type(exc).__name__}: {exc}"[:512],
                    "duration_ms": duration_ms,
                },
                session=session,
            )
            session.commit()
        raise


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------


def _kev_ransomware_flag(raw: str | None) -> bool:
    """Mappt das CISA-String-Feld auf den DB-Boolean.

    CISA liefert ``"Known"`` | ``"Unknown"`` (case-insensitive in der
    Praxis tolerant). Alles andere wird als ``False`` interpretiert.
    """
    if raw is None:
        return False
    return raw.strip().lower() == "known"


def pull_kev(
    session: Session,
    *,
    http_client: httpx.Client,
) -> tuple[int, int]:
    """Pullt den CISA-KEV-JSON-Feed und UPSERTet ihn in ``cisa_kev_catalog``.

    Returns ``(row_count, bytes_downloaded)``. Bei Failure: Exception wird
    propagiert (Caller schreibt Audit auf ``failed``).

    KEV-Feed ist mit ~1500 Eintraegen / ~1 MB klein genug fuer Single-
    Shot-Read + Single-Shot-Validation. UPSERT laeuft in einer Charge.
    """
    cfg = load_settings()
    log_id = _log_start(session, "cisa_kev")

    started_mono = time.monotonic()
    try:
        max_bytes = cfg.feed_max_bytes_kev_mb * 1024 * 1024
        with http_client.stream(
            "GET",
            cfg.feed_kev_url,
            headers={"Accept": "application/json"},
        ) as response:
            response.raise_for_status()
            body_bytes = bytearray()
            for chunk in response.iter_bytes(chunk_size=_GZIP_READ_CHUNK_BYTES):
                body_bytes.extend(chunk)
                if len(body_bytes) > max_bytes:
                    raise ValueError(f"KEV response exceeds cap of {max_bytes} bytes")
        bytes_downloaded = len(body_bytes)

        # Pydantic-Single-Shot-Validation der ganzen Struktur.
        feed = KevFeed.model_validate_json(bytes(body_bytes))

        rows = _kev_rows_from_feed(feed.vulnerabilities)
        if rows:
            stmt = pg_insert(CisaKevCatalog).values(rows)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_={
                    "vendor_project": stmt.excluded.vendor_project,
                    "product": stmt.excluded.product,
                    "vulnerability_name": stmt.excluded.vulnerability_name,
                    "date_added": stmt.excluded.date_added,
                    "short_description": stmt.excluded.short_description,
                    "required_action": stmt.excluded.required_action,
                    "due_date": stmt.excluded.due_date,
                    "known_ransomware": stmt.excluded.known_ransomware,
                    "updated_at": stmt.excluded.updated_at,
                },
            )
            session.execute(stmt)
        session.commit()

        row_count = len(rows)
        duration_ms = int((time.monotonic() - started_mono) * 1000)
        _log_success(
            session,
            log_id,
            row_count=row_count,
            bytes_downloaded=bytes_downloaded,
        )

        # Phase 3 (ADR-0024) — Backfill ueber bestehende Findings, idempotent.
        backfilled = 0
        try:
            backfilled = backfill_kev(session)
        except Exception:  # pragma: no cover — defensiv gegen DB-Hickups
            log.exception("feed.kev_backfill_failed")

        _evict_old_audit_rows(session, "cisa_kev")
        log.info(
            "feed.kev_pulled",
            row_count=row_count,
            bytes_downloaded=bytes_downloaded,
            duration_ms=duration_ms,
        )

        # Phase 4 (ADR-0024) — Audit-Event fuer Operator-Sichtbarkeit.
        with contextlib.suppress(Exception):
            log_event(
                "feed.kev_pulled",
                target_type="feed",
                target_id="cisa_kev",
                metadata={
                    "row_count": row_count,
                    "bytes_downloaded": bytes_downloaded,
                    "duration_ms": duration_ms,
                    "findings_backfilled": backfilled,
                },
                session=session,
            )
            session.commit()
        return row_count, bytes_downloaded
    except Exception as exc:
        duration_ms = int((time.monotonic() - started_mono) * 1000)
        log.exception("feed.kev_pull_failed", duration_ms=duration_ms)
        _log_failure(session, log_id, f"{type(exc).__name__}: {exc}")
        with contextlib.suppress(Exception):
            log_event(
                "feed.kev_pull_failed",
                target_type="feed",
                target_id="cisa_kev",
                metadata={
                    "error": f"{type(exc).__name__}: {exc}"[:512],
                    "duration_ms": duration_ms,
                },
                session=session,
            )
            session.commit()
        raise


def _kev_rows_from_feed(entries: list[KevEntry]) -> list[dict[str, Any]]:
    """Konvertiert Pydantic-Modelle in UPSERT-Dicts.

    Deduplicate auf ``cve_id`` — falls CISA jemals einen doppelten CVE in
    derselben Datei liefern sollte, gewinnt der letzte Eintrag (UPSERT
    waere sonst kein gueltiges Statement: Postgres beschwert sich ueber
    "ON CONFLICT DO UPDATE command cannot affect row a second time").
    """
    now = datetime.now(UTC)
    out: dict[str, dict[str, Any]] = {}
    for entry in entries:
        out[entry.cve_id] = {
            "cve_id": entry.cve_id,
            "vendor_project": entry.vendor_project,
            "product": entry.product,
            "vulnerability_name": entry.vulnerability_name,
            "date_added": entry.date_added,
            "short_description": entry.short_description,
            "required_action": entry.required_action,
            "due_date": entry.due_date,
            "known_ransomware": _kev_ransomware_flag(entry.known_ransomware_campaign_use),
            "updated_at": now,
        }
    return list(out.values())


# ---------------------------------------------------------------------------
# Tick-Entry-Point
# ---------------------------------------------------------------------------


def _last_success_at(session: Session, feed_name: str) -> datetime | None:
    """Letzter ``status='success'``-Timestamp pro Feed (oder None).

    Nutzt den Index ``ix_feed_pull_log_feed_started`` (Partial ginge
    auch, ein normaler DESC-Index reicht hier — die Tabelle ist mit max
    200 Zeilen winzig).
    """
    stmt = (
        select(FeedPullLog.completed_at)
        .where(FeedPullLog.feed_name == feed_name)
        .where(FeedPullLog.status == "success")
        .order_by(FeedPullLog.started_at.desc())
        .limit(1)
    )
    return session.execute(stmt).scalar_one_or_none()


def _is_pull_due(
    last_success: datetime | None,
    *,
    interval_hours: int,
    jitter_max_min: int,
) -> bool:
    """``True`` wenn der naechste Pull faellig ist.

    First-Run-Fall (``last_success is None``): immer faellig — der Worker
    soll beim ersten Start sofort pullen, damit das System nicht 24h
    ohne EPSS/KEV-Daten startet.

    Sonst: ``now - last_success >= interval - jitter`` (random jitter aus
    [-jitter_max_min, +jitter_max_min]). Wir ziehen den Jitter VOM
    Intervall ab und nicht hinzu — sonst koennte ein Worker mit Pech
    nie pullen.
    """
    if last_success is None:
        return True
    jitter_min = random.randint(-jitter_max_min, jitter_max_min)  # noqa: S311
    threshold = timedelta(hours=interval_hours, minutes=jitter_min)
    now = datetime.now(UTC)
    # last_success kann tz-naive sein wenn die DB als naive zurueckkommt
    # (sollte nicht, weil Spalte TIMESTAMP WITH TIME ZONE ist). Defensiv:
    if last_success.tzinfo is None:
        last_success = last_success.replace(tzinfo=UTC)
    return (now - last_success) >= threshold


def feed_enrichment_tick(session: Session) -> None:
    """Worker-Sub-Tick-Entry-Point.

    Pro Feed:

    1. Wenn ``feed_pull_disabled`` gesetzt: sofort return (kein
       Log-Spam — der Operator hat das absichtlich abgeschaltet).
    2. Letzten erfolgreichen Pull aus ``feed_pull_log`` lesen.
    3. Wenn faellig (``now - last >= interval + jitter``): pullen.
    4. Defensiv try/except pro Feed — eine EPSS-Failure darf den
       KEV-Pull nicht killen und umgekehrt.

    Es wird genau eine httpx-Client-Instanz pro Tick erzeugt und beiden
    Pull-Funktionen weitergereicht (Connection-Pool wiederverwendet,
    sauberes Close per Context-Manager).
    """
    cfg = load_settings()
    if cfg.feed_pull_disabled:
        return

    interval_h = cfg.feed_pull_interval_hours
    jitter = cfg.feed_jitter_max_min

    epss_due = _is_pull_due(
        _last_success_at(session, "epss"),
        interval_hours=interval_h,
        jitter_max_min=jitter,
    )
    kev_due = _is_pull_due(
        _last_success_at(session, "cisa_kev"),
        interval_hours=interval_h,
        jitter_max_min=jitter,
    )
    if not (epss_due or kev_due):
        return

    # Eine Client-Instanz pro Tick — Connection-Reuse + sauberes Close.
    with httpx.Client(
        timeout=_HTTP_TIMEOUT_SEC,
        follow_redirects=True,
        headers={"User-Agent": "fathometer-feed-enrichment/1.0"},
    ) as client:
        # _log_failure wird bereits innerhalb pull_epss/pull_kev geschrieben;
        # hier nur sicherstellen dass der naechste Feed nicht gekillt wird.
        if epss_due:
            with contextlib.suppress(Exception):  # pragma: no cover — bereits geloggt
                pull_epss(session, http_client=client)
        if kev_due:
            with contextlib.suppress(Exception):  # pragma: no cover — bereits geloggt
                pull_kev(session, http_client=client)


__all__ = [
    "feed_enrichment_tick",
    "pull_epss",
    "pull_kev",
]
