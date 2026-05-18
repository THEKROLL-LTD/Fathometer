# Block P — LLM-Risk-Reviewer mit Application-Grouping (Two-Pass, async Worker)

**Typ:** Feature + Backend + UI + Worker · **Branch-Vorschlag:** `feat/block-p-llm-reviewer` · **Zielversion:** v0.9.0 · **Vorgänger:** Block O (v0.8.0, ADR-0022) · **Spec:** [ADR-0023](../decisions/0023-llm-risk-reviewer-and-application-grouping.md)

## Ziel

Fünf zusammenhängende Bausteine:

1. **Application-Group-Schicht.** Neue Tabelle `application_groups` plus FK `Finding.application_group_id`. Findings werden nach Owner-Application gruppiert (k3s, openssh-server, etc.). Group-Bewertung wird auf alle enthaltenen Findings vererbt (Worst-Case-Band).

2. **Two-Pass-LLM-Architektur.** Pass 1 (Group-Detection) erzeugt aus ungroupierten Findings neue Application-Groups mit wiederverwendbaren Match-Patterns. Pass 2 (Risk-Evaluation) bewertet pro Group das `risk_band` mit Server-Kontext aus Block O.

3. **Asynchroner Worker via `llm_jobs`-Tabelle.** Separater Container `secscan-llm-worker` im docker-compose, Single-Concurrency-Default, 2s-Polling mit `SELECT FOR UPDATE SKIP LOCKED`. Pass-2-Jobs warten via `depends_on` auf Pass-1-Jobs.

4. **Two-Level-Caching.** Pass-1-Cache *ist* die `application_groups`-Library (deterministischer Pattern-Match). Pass-2-Cache ist die `llm_risk_cache`-Tabelle mit `(group_id, group_findings_fp, cve_data_fp, server_context_fp)`-Key, TTL 30d + LRU bei > 100K.

5. **UI-Redesign auf Group-Cards** mit `evaluating`-State während Worker arbeitet. Feature-Flag `BLOCK_P_LLM_MODE ∈ {off, observation, live}` für stufenweise Inbetriebnahme.

Reasons bleiben deskriptiv — **keine** konkreten Update-Befehle, **keine** spezifischen Application-Version-Empfehlungen (Operator muss selbst evaluieren).

## Vorbereitung — zu lesende Sektionen

- [ADR-0023](../decisions/0023-llm-risk-reviewer-and-application-grouping.md) (komplett)
- [ADR-0022](../decisions/0022-risk-based-prioritization.md) komplett — Pre-Triage und Snapshot sind Eingaben für Block P
- [ADR-0010](../decisions/0010-deepseek-v3-default.md) — LLM-Provider-Wahl, Block-G-Wrapper-Pattern
- [ADR-0014](../decisions/0014-token-cap-best-effort.md) — Token-Cap-Semantik (gilt analog für Risk-Reviewer)
- [ADR-0015](../decisions/0015-gunicorn-gthread-for-sse.md) — gthread-Pattern (Worker nutzt das gleiche Pattern für DB-Connections nicht relevant; aber gilt für Web-Container)
- `app/services/llm_chat.py` und `app/services/llm_client.py` (oder wo der Block-G-AsyncOpenAI-Wrapper lebt) — Block P setzt darauf auf
- `app/models.py` `class Finding` (wird erweitert), `class Server` (FK-Ziel)
- `app/api/scans.py` (Ingest-Pfad, Block-O-Pre-Triage-Block)
- `app/__init__.py` (Worker-Liveness-Endpoint registrieren)
- `app/templates/dashboard/_findings_section.html`, `_findings_filter_bar.html` (Block M)
- `app/templates/servers/_findings_section.html`, `detail.html` (Block O)
- `docker-compose.yml` (neuer Worker-Service)
- `Dockerfile` (gleicher Image, anderer Entrypoint)
- `ARCHITECTURE.md §6, §7, §11, §12, §17`
- `tests/fixtures/trivy/` (besonders K3s-Fixture für Group-Tests)

Subagent-Aufrufe nennen die Sektionen explizit.

## Aufgaben

### Phase A — Modelle, Schema, Migration

#### Task #1 — `application_groups` Modell (`backend-implementer`)

`app/models.py` neue Klasse:

```python
class ApplicationGroup(Base):
    __tablename__ = "application_groups"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    label: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    explanation: Mapped[str | None] = mapped_column(String(512), nullable=True)
    path_prefixes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    pkg_name_exact: Mapped[list[str]] = mapped_column(ARRAY(String(256)), nullable=False, default=list)
    pkg_name_glob: Mapped[list[str]] = mapped_column(ARRAY(String(256)), nullable=False, default=list)
    pkg_purl_pattern: Mapped[list[str]] = mapped_column(ARRAY(String(512)), nullable=False, default=list)

    # Bewertung (auf Group-Ebene, von Pass 2 gesetzt)
    risk_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_band_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    risk_band_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_band_computed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    worst_finding_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    group_findings_fingerprint: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Lifecycle / Audit
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="llm")  # llm | manual
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "risk_band IS NULL OR risk_band IN "
            "('escalate','act','mitigate','monitor','noise')",
            name="ck_application_groups_band",
        ),
        CheckConstraint(
            "source IN ('llm','manual')",
            name="ck_application_groups_source",
        ),
    )
```

`label`-Eindeutigkeit ist Pflicht — Pass 1-Output mit existierendem Label wird gemerged, nicht dupliziert.

`Finding`-Klasse Erweiterung:

```python
application_group_id: Mapped[int | None] = mapped_column(
    BigInteger,
    ForeignKey("application_groups.id", ondelete="SET NULL"),
    nullable=True,
)
```

Plus Relationship-Definition für Drill-down-Queries.

**DoD:**

- `mypy --strict` PASS.
- Unit-Test in `tests/models/test_application_group.py`:
  - Insert mit valid label und leeren Pattern-Arrays funktioniert.
  - Insert mit `risk_band="pending"` failed CheckConstraint (Bands sind hier final).
  - Insert mit `source="something"` failed CheckConstraint.
  - Insert mit dupliziertem label failed UNIQUE.
  - Finding mit nicht-existierender `application_group_id` failed FK.
  - Finding mit gelöschter Group: FK setzt auf NULL.

#### Task #2 — `llm_jobs` Modell (`backend-implementer`)

```python
class LLMJob(Base):
    __tablename__ = "llm_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    server_id: Mapped[int | None] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=True
    )
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    depends_on: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("llm_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    picked_up_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    picked_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "job_type IN ('group_detection','risk_evaluation')",
            name="ck_llm_jobs_type",
        ),
        CheckConstraint(
            "status IN ('queued','in_progress','done','failed')",
            name="ck_llm_jobs_status",
        ),
        CheckConstraint("attempts >= 0", name="ck_llm_jobs_attempts"),
        Index(
            "ix_llm_jobs_pickup",
            "status", "next_attempt_at",
            postgresql_where="status = 'queued'",
        ),
        Index(
            "ix_llm_jobs_stale",
            "status", "picked_up_at",
            postgresql_where="status = 'in_progress'",
        ),
        Index("ix_llm_jobs_server", "server_id", "status"),
    )
```

**DoD:**

- `mypy --strict` PASS.
- Unit-Test in `tests/models/test_llm_job.py`:
  - Insert mit allen Pflichtfeldern + JSONB-payload funktioniert.
  - CheckConstraint-Verstöße werden geblockt.
  - `ON DELETE CASCADE` auf server_id räumt zugehörige Jobs auf.
  - `ON DELETE SET NULL` auf depends_on lässt Jobs verwaist aber lebend.

#### Task #3 — `llm_risk_cache` Modell (`backend-implementer`)

```python
class LLMRiskCache(Base):
    __tablename__ = "llm_risk_cache"

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("application_groups.id", ondelete="CASCADE"), nullable=False
    )
    group_findings_fp: Mapped[str] = mapped_column(String(16), nullable=False)
    cve_data_fp: Mapped[str] = mapped_column(String(16), nullable=False)
    server_context_fp: Mapped[str] = mapped_column(String(16), nullable=False)

    risk_band: Mapped[str] = mapped_column(String(16), nullable=False)
    worst_finding_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    llm_model: Mapped[str | None] = mapped_column(String(64), nullable=True)

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    used_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        CheckConstraint(
            "risk_band IN ('escalate','act','mitigate','monitor','noise')",
            name="ck_llm_risk_cache_band",
        ),
        Index("ix_llm_risk_cache_lru", "last_used_at"),
        Index("ix_llm_risk_cache_group", "group_id"),
    )
```

**DoD:**

- `mypy --strict` PASS.
- Unit-Test in `tests/models/test_llm_risk_cache.py`:
  - Insert mit allen Feldern.
  - CheckConstraint blockt ungültige Bands (auch `pending`, `unknown` — die sind Pre-Triage-only).
  - PK-Duplicate-Insert wirft Conflict.

#### Task #4 — DB-Migration (`backend-implementer`)

Alembic-Migration `XXXX_block_p_llm_groups_jobs_cache.py`:

- `op.create_table` für `application_groups`, `llm_jobs`, `llm_risk_cache` mit allen CheckConstraints und Indizes.
- `op.add_column('findings', sa.Column('application_group_id', ...))` mit FK.
- `op.create_index` zusätzlich `ix_findings_application_group` auf `findings(application_group_id)` (für Drill-down-Queries).
- Settings-Tabelle (existiert aus Block H/I) bekommt drei Einträge mit Defaults: `BLOCK_P_LLM_MODE = "off"`, `LLM_WORKER_HEARTBEAT_AT = NULL`, `LLM_TOKEN_BUDGET_USED_TODAY = 0`.
- Downgrade: spiegelbildlich. FK auf findings.application_group_id muss vor dem Drop von application_groups gedropped werden — Reihenfolge wichtig.

**DoD:**

- `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS im Container.
- Schema-Smoke in `tests/migrations/test_block_p_schema.py`: prüft Existenz aller drei Tabellen + FK + Indizes + Settings-Einträge.

### Phase B — Service-Bausteine

#### Task #5 — Fingerprint-Helper (`backend-implementer`)

Neue Datei `app/services/llm_fingerprints.py`:

```python
import hashlib
import json

def group_findings_fingerprint(findings: list[Finding]) -> str:
    """SHA256[:16] über sortierte Tupel-Liste (cve_id, package_purl)."""
    tuples = sorted((f.identifier_key, f.package_purl or "") for f in findings)
    payload = json.dumps(tuples, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def cve_data_fingerprint(findings: list[Finding]) -> str:
    """SHA256[:16] über (cve_id, severity, severity_by_provider_normalized,
    epss_score, is_kev, vendor_status) der Findings."""
    tuples = sorted(
        (
            f.identifier_key,
            f.severity.value,
            json.dumps(f.severity_by_provider or {}, sort_keys=True),
            round(f.epss_score, 4) if f.epss_score is not None else None,
            f.is_kev,
            f.vendor_status,
        )
        for f in findings
    )
    payload = json.dumps(tuples, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def server_context_fingerprint(server: Server) -> str:
    """SHA256[:16] über semantisch-stabile Host-Felder. PIDs, args, snapshot_at,
    user-Feld der Prozesse fließen NICHT ein."""
    # Listener: nur (proto, addr, port, process_comm) tuples, sortiert
    listeners = sorted(
        (l.proto, l.addr, l.port, l.process or "") for l in server.listeners
    )
    # Process-comms: nur unique, sortiert
    process_comms = sorted({p.comm for p in server.processes if p.comm})
    modules = sorted(m.name for m in server.kernel_modules)
    services = sorted(s.name for s in server.services)
    tags = sorted(t.name for t in server.tag_links if t.tag)
    gaps = sorted(server.host_state_gaps or [])

    payload = json.dumps({
        "os_family": server.os_family,
        "os_version": server.os_version,
        "tags": tags,
        "listeners": listeners,
        "process_comms": process_comms,
        "kernel_modules": modules,
        "services": services,
        "gaps": gaps,
    }, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def make_cache_key(group_id: int, group_findings_fp: str,
                   cve_data_fp: str, server_context_fp: str) -> str:
    """SHA256-hex (full 64 chars) über die vier Inputs."""
    payload = f"{group_id}|{group_findings_fp}|{cve_data_fp}|{server_context_fp}"
    return hashlib.sha256(payload.encode()).hexdigest()
```

**DoD:**

- Unit-Tests in `tests/services/test_llm_fingerprints.py`:
  - Gleicher Input → gleicher Hash (Determinismus).
  - Anders sortierter Input → gleicher Hash (Canonical-Serialization).
  - PID-Änderung auf Process → gleicher Server-Context-Fingerprint.
  - args-Änderung auf Process → gleicher Fingerprint.
  - Snapshot_at-Änderung → gleicher Fingerprint.
  - Listener-Add → anderer Fingerprint.
  - Kernel-Module-Add → anderer Fingerprint.
  - Tag-Add → anderer Fingerprint.
  - `cache_key` ist 64 chars hex.
- `mypy --strict` PASS.

#### Task #6 — Pattern-Matcher (`backend-implementer`)

Neue Datei `app/services/group_matcher.py`:

```python
from threading import Lock
from typing import Optional

import fnmatch


class GroupMatcher:
    """Singleton mit In-Memory-Cache der application_groups-Library.
    Refresh bei Insert/Update via expliziten reload()-Call."""

    _instance: Optional["GroupMatcher"] = None
    _lock = Lock()

    def __init__(self):
        self._groups: list[ApplicationGroup] = []
        self._loaded = False

    @classmethod
    def get(cls) -> "GroupMatcher":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def reload(self, session: Session) -> None:
        with self._lock:
            self._groups = session.query(ApplicationGroup).all()
            self._loaded = True

    def match(self, finding: Finding) -> ApplicationGroup | None:
        """Returns Group nach Match-Reihenfolge:
        1) path_prefixes (längster Match gewinnt)
        2) pkg_name_exact
        3) pkg_name_glob
        4) pkg_purl_pattern
        """
        if not self._loaded:
            return None

        # 1) Path-Prefix-Match
        target = finding.target_path or ""
        best_match: tuple[int, ApplicationGroup] | None = None
        for grp in self._groups:
            for prefix in grp.path_prefixes:
                if target.startswith(prefix):
                    candidate = (len(prefix), grp)
                    if best_match is None or candidate[0] > best_match[0]:
                        best_match = candidate
        if best_match:
            return best_match[1]

        # 2) pkg_name_exact (strippt ADR-0011-@-Suffix)
        pkg_name_base = finding.package_name.split("@", 1)[0]
        for grp in self._groups:
            if pkg_name_base in grp.pkg_name_exact:
                return grp

        # 3) pkg_name_glob
        for grp in self._groups:
            for pattern in grp.pkg_name_glob:
                if fnmatch.fnmatchcase(pkg_name_base, pattern):
                    return grp

        # 4) pkg_purl_pattern (Prefix-Match)
        purl = finding.package_purl or ""
        for grp in self._groups:
            for pattern in grp.pkg_purl_pattern:
                if purl.startswith(pattern):
                    return grp

        return None


def apply_matches_for_server(session: Session, server_id: int) -> int:
    """Findet alle ungroupierten Findings dieses Servers und versucht zu matchen.
    Returns Anzahl der neu gematcht Findings."""
    matcher = GroupMatcher.get()
    count = 0
    findings = session.query(Finding).filter_by(
        server_id=server_id,
        application_group_id=None,
    ).all()
    for f in findings:
        grp = matcher.match(f)
        if grp:
            f.application_group_id = grp.id
            grp.last_used_at = func.now()
            count += 1
    return count
```

**DoD:**

- Unit-Tests in `tests/services/test_group_matcher.py`:
  - Path-Prefix-Match findet längsten Match (k3s mit `/var/lib/rancher/k3s/agent/containerd/...` matched k3s nicht containerd, weil k3s-Prefix länger).
  - pkg_name_exact greift wenn kein Path-Match.
  - pkg_name_glob greift wenn kein Exact-Match (`k3s-server` → glob `k3s-*`).
  - pkg_purl_pattern als letzte Stufe.
  - Keine Match → None.
  - ADR-0011-`@target`-Suffix wird beim pkg_name_exact-Match weggeschnitten.
  - Library-Reload pickt neue Groups auf.
- `mypy --strict` PASS.

#### Task #7 — Cache-Helper (`backend-implementer`)

Neue Datei `app/services/llm_cache.py`:

```python
from datetime import datetime, timedelta, timezone

from app.config import settings


def lookup(session: Session, cache_key: str) -> LLMRiskCache | None:
    """TTL-aware Lookup. Returns None wenn Eintrag älter als TTL."""
    cached = session.query(LLMRiskCache).filter_by(cache_key=cache_key).first()
    if cached is None:
        return None
    if (datetime.now(timezone.utc) - cached.computed_at) > timedelta(days=settings.LLM_CACHE_TTL_DAYS):
        return None
    return cached


def record_hit(session: Session, cached: LLMRiskCache) -> None:
    cached.used_count += 1
    cached.last_used_at = func.now()


def store(session: Session, cache_key: str, group_id: int,
          group_findings_fp: str, cve_data_fp: str, server_context_fp: str,
          risk_band: str, worst_finding_id: int | None,
          reason: str, llm_model: str) -> LLMRiskCache:
    entry = LLMRiskCache(
        cache_key=cache_key,
        group_id=group_id,
        group_findings_fp=group_findings_fp,
        cve_data_fp=cve_data_fp,
        server_context_fp=server_context_fp,
        risk_band=risk_band,
        worst_finding_id=worst_finding_id,
        reason=reason,
        llm_model=llm_model,
    )
    session.add(entry)
    return entry


def lru_evict_if_needed(session: Session) -> int:
    """Wenn Tabellengröße > LLM_CACHE_MAX_ROWS, löscht älteste last_used_at.
    Returns Anzahl gelöschter Rows."""
    count = session.query(LLMRiskCache).count()
    if count <= settings.LLM_CACHE_MAX_ROWS:
        return 0
    excess = count - settings.LLM_CACHE_MAX_ROWS
    victims = (
        session.query(LLMRiskCache)
        .order_by(LLMRiskCache.last_used_at.asc())
        .limit(excess)
        .all()
    )
    for v in victims:
        session.delete(v)
    return excess
```

**DoD:**

- Unit-Tests in `tests/services/test_llm_cache.py`:
  - Lookup mit existierendem Key + frischem Eintrag → returns entry.
  - Lookup mit existierendem Key + abgelaufenem Eintrag → returns None.
  - Lookup mit unbekanntem Key → returns None.
  - `record_hit` erhöht used_count und last_used_at.
  - `store` legt Eintrag an.
  - `lru_evict_if_needed` löscht älteste wenn über Limit.

#### Task #8 — LLM-Risk-Reviewer-Service (`backend-implementer`)

Neue Datei `app/services/llm_risk_reviewer.py`:

```python
from app.services.llm_client import get_llm_client  # Block-G-Wrapper
from app.config import settings


class LLMRiskReviewer:
    def __init__(self, client=None):
        self.client = client or get_llm_client()

    async def pass1_detect_groups(
        self,
        findings: list[Finding],
    ) -> Pass1Result:
        """LLM-Call mit kompakter Finding-Identität. Returns Groups + Patterns.
        Raises LLMInvalidResponseError bei Halluzinationen, LLMTimeoutError bei Timeout."""
        prompt = self._render_pass1_prompt(findings)
        response = await self.client.chat_completion_json(
            prompt=prompt,
            schema=PASS1_RESPONSE_SCHEMA,
            max_tokens=settings.LLM_PASS1_MAX_TOKENS,
        )
        return self._validate_pass1_response(response, findings)

    async def pass2_evaluate_groups(
        self,
        server: Server,
        groups_with_findings: list[tuple[ApplicationGroup, list[Finding]]],
    ) -> Pass2Result:
        """LLM-Call mit Server-Kontext + Groups. Returns Band+Reason pro Group."""
        prompt = self._render_pass2_prompt(server, groups_with_findings)
        response = await self.client.chat_completion_json(
            prompt=prompt,
            schema=PASS2_RESPONSE_SCHEMA,
            max_tokens=settings.LLM_PASS2_MAX_TOKENS,
        )
        return self._validate_pass2_response(response, groups_with_findings)

    def _render_pass1_prompt(self, findings):
        # System-Prompt aus ADR-0023 §Pass-1
        # Findings als kompakte Tabelle, Felder finding_id/package_name/
        # target_path/package_purl/result_type
        ...

    def _render_pass2_prompt(self, server, groups_with_findings):
        # System-Prompt aus ADR-0023 §Pass-2
        # Server-Context-Block (compact), groups_to_evaluate-Block
        # Anweisung NICHT konkrete Application-Version zu raten
        ...

    def _validate_pass1_response(self, response, findings):
        # Schema-Validation, ID-Whitelist-Check, label-Regex-Check
        # Vollständigkeits-Check: jeder Input-Finding in genau einer Group oder ungrouped
        ...

    def _validate_pass2_response(self, response, groups_with_findings):
        # Schema-Validation, group_label im Input?, band ∈ {escalate,act,mitigate,monitor,noise}?,
        # worst_finding_id Group-Mitglied?, reason ≤ 256 chars, NUL-frei
        ...
```

JSON-Schemas `PASS1_RESPONSE_SCHEMA` und `PASS2_RESPONSE_SCHEMA` als Konstanten, Pydantic-Modelle für Output (`Pass1Group`, `Pass1Result`, `Pass2Evaluation`, `Pass2Result`).

**DoD:**

- Unit-Tests in `tests/services/test_llm_risk_reviewer.py` mit Mock-LLM-Client:
  - Pass 1 mit Mock-Response → korrekte Output-Parsing, Groups extrahiert.
  - Pass 1 mit halluzinierter finding_id im Response → Validation-Error.
  - Pass 1 mit fehlendem Input-Finding in der Output (weder in Group noch ungrouped) → Validation-Error.
  - Pass 1 mit Label-Regex-Verstoß → Validation-Error.
  - Pass 2 mit Mock-Response → Band + Reason korrekt.
  - Pass 2 mit `risk_band="pending"` → Validation-Error (pending ist Pre-Triage-only).
  - Pass 2 mit halluziniertem group_label → Validation-Error.
  - Pass 2 mit worst_finding_id außerhalb der Group → Validation-Error.
  - Pass 2 mit Reason mit NUL-Byte → Validation-Error.
- `mypy --strict` PASS.

### Phase C — Worker

#### Task #9 — Worker-Hauptschleife (`backend-implementer`)

Neue Datei `app/workers/llm_worker.py`:

```python
import asyncio
import logging
import os
import signal
import socket
import time
from contextlib import contextmanager

from app.config import settings
from app.db import get_session
from app.services.group_matcher import GroupMatcher
from app.services.llm_risk_reviewer import LLMRiskReviewer
from app.services.llm_cache import lookup, record_hit, store, lru_evict_if_needed
from app.services.llm_fingerprints import (
    group_findings_fingerprint, cve_data_fingerprint,
    server_context_fingerprint, make_cache_key,
)

log = logging.getLogger("secscan.llm_worker")

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"
POLL_INTERVAL = settings.WORKER_POLL_INTERVAL_SEC
STALE_TIMEOUT_MIN = settings.WORKER_STALE_TIMEOUT_MIN
MAX_ATTEMPTS = 3

_shutdown = False
_last_reaper_at = 0.0
_last_heartbeat_at = 0.0


def _signal_handler(signum, frame):
    global _shutdown
    log.info(f"received signal {signum}, shutting down gracefully")
    _shutdown = True


def main():
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    log.info(f"llm_worker starting, worker_id={WORKER_ID}, mode={settings.BLOCK_P_LLM_MODE}")

    while not _shutdown:
        try:
            _tick()
        except Exception:
            log.exception("unexpected error in worker loop, sleeping then retry")
            time.sleep(POLL_INTERVAL * 2)

    log.info("llm_worker shutdown complete")


def _tick():
    global _last_reaper_at, _last_heartbeat_at
    now = time.monotonic()

    # Heartbeat alle 10s in Settings-Tabelle
    if now - _last_heartbeat_at > 10.0:
        _write_heartbeat()
        _last_heartbeat_at = now

    # Stale-Reaper alle 60s
    if now - _last_reaper_at > 60.0:
        _run_stale_reaper()
        _last_reaper_at = now

    if settings.BLOCK_P_LLM_MODE == "off":
        time.sleep(POLL_INTERVAL)
        return

    job = _pick_next_job()
    if job is None:
        time.sleep(POLL_INTERVAL)
        return

    _process_job(job)


def _pick_next_job() -> LLMJob | None:
    with get_session() as session:
        # SELECT FOR UPDATE SKIP LOCKED, mit depends_on-Check
        row = session.execute(text("""
            WITH job AS (
              SELECT id FROM llm_jobs
              WHERE status = 'queued'
                AND next_attempt_at <= now()
                AND (
                  depends_on IS NULL
                  OR depends_on IN (SELECT id FROM llm_jobs WHERE status = 'done')
                )
              ORDER BY created_at
              LIMIT 1
              FOR UPDATE SKIP LOCKED
            )
            UPDATE llm_jobs SET
              status = 'in_progress',
              picked_up_by = :worker_id,
              picked_up_at = now(),
              attempts = attempts + 1
            WHERE id IN (SELECT id FROM job)
            RETURNING id
        """), {"worker_id": WORKER_ID}).fetchone()
        session.commit()
        if row is None:
            return None
        return session.query(LLMJob).get(row.id)


def _process_job(job: LLMJob):
    try:
        if settings.BLOCK_P_LLM_MODE == "observation":
            _process_observation(job)
        elif settings.BLOCK_P_LLM_MODE == "live":
            asyncio.run(_process_live(job))
        # ... mark done, audit
    except Exception as e:
        _requeue_or_fail(job, str(e))


def _process_observation(job: LLMJob):
    # Pass-1: estimate tokens, write would_call marker
    # Pass-2: cache-lookup as if real, write would_call+cache_hit marker
    ...


async def _process_live(job: LLMJob):
    if job.job_type == "group_detection":
        await _do_pass1(job)
    elif job.job_type == "risk_evaluation":
        await _do_pass2(job)


def _run_stale_reaper():
    # UPDATE statt in_progress jobs zurück, siehe ADR-0023
    ...


def _write_heartbeat():
    # Settings-Tabelle: LLM_WORKER_HEARTBEAT_AT = now()
    ...


def _requeue_or_fail(job: LLMJob, error: str):
    # Exponential backoff: next_attempt_at = now() + (attempts * 1 minute)
    # Bei attempts >= MAX_ATTEMPTS: status = failed
    ...


if __name__ == "__main__":
    main()
```

**DoD:**

- Unit-Tests in `tests/workers/test_llm_worker.py`:
  - `_pick_next_job` mit leerer Queue → None.
  - `_pick_next_job` setzt status=in_progress, picked_up_by/at, attempts+1.
  - Concurrency-Test: zwei simultane picks → genau einer kriegt den Job (SKIP LOCKED).
  - Dependency-Check: Pass-2-Job mit depends_on auf nicht-done Pass-1-Job wird NICHT gepickt.
  - Stale-Reaper resettet status zurück auf queued, attempts steigt, next_attempt_at backoff.
  - Stale-Reaper bei attempts >= 3 setzt status=failed.
  - Mode=off: kein Pickup.
  - Mode=observation: würde Mock-Result schreiben.
  - Mode=live: würde echten LLM-Mock aufrufen.
  - SIGTERM stoppt graceful nach aktueller Iteration.
- `mypy --strict` PASS.

#### Task #10 — Token-Budget (`backend-implementer`)

Settings-Tabelle bekommt drei Einträge:

- `LLM_TOKEN_BUDGET_USED_TODAY` (int) — wird pro Job um die verbrauchten Tokens hochgezählt.
- `LLM_TOKEN_BUDGET_RESET_AT` (timestamp) — nächster Reset-Zeitpunkt (00:00 UTC).
- `BLOCK_P_LLM_MODE` (string, off/observation/live).

Worker prüft vor jedem Pickup:

```python
def _budget_check():
    used = settings_get_int("LLM_TOKEN_BUDGET_USED_TODAY")
    if used >= settings.LLM_TOKEN_BUDGET_DAILY:
        return False  # pausiert
    return True

def _budget_consume(tokens: int):
    settings_increment("LLM_TOKEN_BUDGET_USED_TODAY", tokens)
```

Reset-Tick im Worker (täglich 00:00 UTC):

```python
def _maybe_reset_budget():
    reset_at = settings_get_timestamp("LLM_TOKEN_BUDGET_RESET_AT")
    if datetime.now(timezone.utc) >= reset_at:
        settings_set_int("LLM_TOKEN_BUDGET_USED_TODAY", 0)
        next_reset = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=0, minute=0, second=0)
        settings_set_timestamp("LLM_TOKEN_BUDGET_RESET_AT", next_reset)
```

Bei Erreichen wird ein Audit-Event `llm.budget_exhausted` geschrieben (einmalig pro Tag, nicht jedes Tick).

Im Observation-Mode wird `estimate_tokens(job)` gegen das Budget verrechnet — damit Cost-Math realistisch ist auch ohne echte Calls.

**DoD:**

- Unit-Test `tests/workers/test_token_budget.py`:
  - Budget-Check returns True wenn used < daily.
  - Budget-Consume erhöht Wert.
  - Wenn used >= daily: Worker pausiert (kein Pickup).
  - Reset um 00:00 UTC: used wird auf 0 gesetzt, next_reset auf morgen.
  - Audit-Event `llm.budget_exhausted` einmalig pro Tag.

### Phase D — Ingest-Integration

#### Task #11 — Job-Queueing im Scan-Ingest (`backend-implementer`)

`app/api/scans.py` nach Block-O-Pre-Triage-Block:

```python
# (existing Block-O code: pre-triage läuft, risk_band gesetzt für jedes Finding)

if settings.BLOCK_P_LLM_MODE != "off":
    # 1) Apply pattern-match für alle ungroupierten Findings dieses Servers
    GroupMatcher.get().reload(session)  # falls Library erweitert seit App-Start
    matched_count = apply_matches_for_server(session, server.id)

    # 2) Wenn noch ungroupierte Findings übrig: Pass-1-Job queuen
    ungrouped = session.query(Finding).filter_by(
        server_id=server.id,
        application_group_id=None,
        status=FindingStatus.OPEN,
        risk_band='pending',  # nur pending, nicht noise/monitor/unknown
    ).all()
    if ungrouped:
        pass1_job = LLMJob(
            job_type='group_detection',
            server_id=server.id,
            payload={'finding_ids': [f.id for f in ungrouped]},
        )
        session.add(pass1_job)
        session.flush()
        pass1_job_id = pass1_job.id
    else:
        pass1_job_id = None

    # 3) Für jede Group dieses Servers: Pass-2-Job wenn noch nicht bewertet
    #    oder group_findings_fingerprint sich geändert hat
    groups_in_server = session.query(ApplicationGroup).join(Finding).filter(
        Finding.server_id == server.id,
        Finding.application_group_id == ApplicationGroup.id,
    ).distinct().all()

    for grp in groups_in_server:
        findings_in_group = session.query(Finding).filter_by(
            server_id=server.id, application_group_id=grp.id,
            status=FindingStatus.OPEN,
        ).all()
        if not findings_in_group:
            continue

        new_fp = group_findings_fingerprint(findings_in_group)
        if grp.group_findings_fingerprint == new_fp and grp.risk_band is not None:
            # Up-to-date, kein Job nötig
            continue

        pass2_job = LLMJob(
            job_type='risk_evaluation',
            server_id=server.id,
            payload={
                'group_id': grp.id,
                'server_id': server.id,
            },
            depends_on=pass1_job_id,  # falls Pass 1 läuft, erst danach
        )
        session.add(pass2_job)

    audit_event("llm.jobs_queued", server_id=server.id, body={
        "pass1_queued": int(pass1_job_id is not None),
        "pass2_queued": session.new_pass2_count,  # Counter
    })

session.commit()
return Response(status=202)
```

**DoD:**

- Integration-Test in `tests/api/test_scans_block_p_job_queueing.py`:
  - Scan ohne Findings → keine Jobs queued.
  - Scan mit pending Findings, leere Library → Pass-1-Job queued, keine Pass-2-Jobs.
  - Scan mit pending Findings, gefüllte Library trifft → keine Pass-1-Job, Pass-2-Jobs für die Groups.
  - Scan mit Mix (manche pattern-match, manche nicht) → Pass-1-Job für ungroupierte + Pass-2-Jobs für gematcht Groups, Pass-2 hat depends_on=Pass-1-Job.
  - Re-Ingest mit unverändertem group_findings_fingerprint → keine neuen Pass-2-Jobs (idempotent).
  - Re-Ingest nach KEV-DB-Update (Finding wird neu KEV-flagged): cve_data_fingerprint ändert sich → Pass-2-Job queued (Cache-Miss).
  - Mode=off: keine Jobs queued.

### Phase E — UI

#### Task #12 — Group-Card-Partials (`frontend-implementer`)

`app/templates/_partials/application_group_card.html`:

```jinja
<div class="card bg-base-200/40 rounded-box p-4 mb-3" data-test="group-card-{{ group.id }}">
  <div class="flex items-start justify-between gap-3">
    <div>
      <div class="text-[10px] uppercase tracking-[0.12em] font-mono opacity-65">
        APPLICATION GROUP
      </div>
      <h3 class="font-mono text-xl">{{ group.label }}</h3>
      {% if group.explanation %}
        <p class="text-xs opacity-70 mt-1">{{ group.explanation }}</p>
      {% endif %}
    </div>
    <div class="flex flex-col items-end gap-1">
      {% include "_partials/risk_band_pill.html" with context %}
      <span class="badge badge-ghost badge-sm">{{ findings|length }} findings</span>
    </div>
  </div>

  {% if group.risk_band_reason %}
    <div class="bg-base-300/40 rounded p-2 mt-3 font-mono text-xs">
      {{ group.risk_band_reason }}
    </div>
  {% endif %}

  {% if group.worst_finding_id and worst_finding %}
    <div class="mt-3 border-l-4 border-error pl-3" data-test="group-worst-finding">
      <div class="text-[10px] uppercase tracking-wider opacity-65">WORST FINDING</div>
      <a class="link link-hover" hx-get="{{ url_for('findings.detail', finding_id=worst_finding.id) }}"
         hx-target="#detail-pane">{{ worst_finding.identifier_key }}</a>
      <span class="text-xs opacity-70">{{ worst_finding.package_name }}</span>
    </div>
  {% endif %}

  <details class="mt-3" data-test="group-findings-details">
    <summary class="cursor-pointer text-sm opacity-80">
      Show all {{ findings|length }} findings
    </summary>
    {% include "_partials/findings_table.html" with context %}
  </details>
</div>
```

`app/templates/_partials/group_evaluating_card.html`:

```jinja
<div class="card bg-base-200/40 rounded-box p-4 mb-3" data-test="group-evaluating-{{ group.id }}">
  <div class="flex items-center justify-between">
    <div>
      <div class="text-[10px] uppercase tracking-[0.12em] font-mono opacity-65">APPLICATION GROUP</div>
      <h3 class="font-mono text-xl">{{ group.label }}</h3>
    </div>
    <div class="flex items-center gap-2 opacity-70">
      <span class="loading loading-spinner loading-sm"></span>
      <span class="text-xs">Evaluating risk for {{ findings|length }} findings...</span>
    </div>
  </div>
</div>
```

**DoD:**

- View-Tests in `tests/views/test_application_group_cards.py`:
  - Group mit risk_band gesetzt → normales Card-Markup.
  - Group ohne risk_band (evaluating) → Spinner-Card.
  - worst_finding-Block taucht nur auf wenn worst_finding_id gesetzt.
  - Drill-down via `<details>`-Element listet alle Findings.

#### Task #13 — Server-Detail-Findings-Section umbauen (`frontend-implementer`)

`app/templates/servers/_findings_section.html`:

- Findings werden nach `application_group_id` gruppiert, default-Reihenfolge nach Group-`risk_band` (escalate → act → mitigate → pending → unknown → monitor → noise).
- Findings ohne `application_group_id` werden am Ende in einer „Pending grouping"-Sektion gelistet (heute-Block-K-Tabellen-Markup wiederverwendet).
- Group-Cards default-expanded für escalate/act/mitigate/pending/unknown. Default-collapsed für monitor/noise.
- Bulk-Ack-noise bleibt verfügbar — operiert weiter auf Finding-Ebene (Server-Side-Filter `risk_band="noise"`), nicht auf Group-Ebene.

`app/views/server_detail.py` lädt zusätzlich:

```python
groups = (
    session.query(ApplicationGroup)
    .join(Finding, Finding.application_group_id == ApplicationGroup.id)
    .filter(Finding.server_id == server.id, Finding.status == FindingStatus.OPEN)
    .options(
        contains_eager(ApplicationGroup.findings).filter(...).load_only(...),
    )
    .distinct()
    .order_by(case(RISK_BAND_SORT_RANK).desc())
    .all()
)
ungrouped_findings = (
    session.query(Finding).filter_by(
        server_id=server.id,
        application_group_id=None,
        status=FindingStatus.OPEN,
    ).all()
)
```

**DoD:**

- View-Tests:
  - Server mit drei Groups (escalate/act/noise) → 3 Cards in dieser Reihenfolge, escalate-Card expanded, noise-Card collapsed.
  - Server mit ungroupierten Findings → „Pending grouping"-Sektion am Ende.
  - Server mit Group ohne risk_band (evaluating) → evaluating-Card statt normale Card.
  - Bulk-Ack-Noise-Modal-Liste enthält noise-Findings aus allen Groups, keine non-noise.

#### Task #14 — Dashboard-Findings-Section: Group-Spalte (`frontend-implementer`)

`app/templates/dashboard/_findings_section.html`:

- Neue Tabellen-Spalte `Group` nach der Risk-Spalte. Sortierbar.
- Filter-Bar: neuer `<select name="application_group">`-Filter mit allen Library-Groups als Optionen.

`app/schemas/dashboard_filter.py` und `findings_view_filter.py`:

```python
application_group_id: int | None = None
```

`app/services/findings_query.py`: SQL-Filter und Sort.

**DoD:**

- View-Tests:
  - `?application_group=42` filtert auf Group ID 42.
  - Sort-Header-Klick auf Group-Spalte sortiert nach Label asc/desc.
  - Findings ohne Group zeigen `—` in der Spalte.

#### Task #15 — Settings-Tab „LLM Risk Reviewer" (`frontend-implementer` + `backend-implementer`)

`app/views/settings.py` neue Route `/settings/llm-reviewer`:

- GET: rendert Stats + Mode-Anzeige.
- POST mit `master_key`-Confirm: Mode-Wechsel.
- POST mit `master_key`-Confirm: Re-queue would-call-Backlog.

`app/templates/settings/llm_reviewer.html`:

```
LLM Risk Reviewer

Current mode: [off | observation | live]  [Change mode...]

Queue stats (last 24h):
  queued       N
  in_progress  M
  done         X
  failed       Y

Library stats:
  application_groups   N
  Top groups by usage  (table)

Cache stats:
  entries              M
  hit rate (7d)        87.3%

Token budget:
  used today           NNN,NNN tokens
  daily limit          1,000,000 tokens
  resets at            00:00 UTC tomorrow

Worker liveness:
  last heartbeat       3s ago  [healthy]

Observation-mode (when active):
  would-have-called    K times in last 24h
  estimated cost       $X
  [Re-queue would-call backlog (K jobs)]
```

`base_app.html` Sidebar bekommt neuen Eintrag „LLM Reviewer" im Settings-Akkordeon.

**DoD:**

- View-Tests in `tests/views/test_settings_llm_reviewer.py`:
  - GET zeigt Mode, Stats, Token-Budget.
  - POST Mode-Wechsel ohne master_key → 403.
  - POST Mode-Wechsel mit master_key → Mode aktualisiert, Audit-Event `llm.mode_changed`.
  - Re-queue-Backlog-Button bei observation→live setzt would-call-Jobs zurück auf queued.

### Phase F — Docker-Compose + Healthcheck

#### Task #16 — Worker-Container (`backend-implementer`)

`docker-compose.yml`:

```yaml
secscan-llm-worker:
  image: secscan:latest
  entrypoint: python -m app.workers.llm_worker
  depends_on:
    secscan-postgres:
      condition: service_healthy
    secscan-web:
      condition: service_started
  environment:
    DATABASE_URL: ${DATABASE_URL}
    BLOCK_P_LLM_MODE: ${BLOCK_P_LLM_MODE:-off}
    WORKER_CONCURRENCY: ${WORKER_CONCURRENCY:-1}
    WORKER_POLL_INTERVAL_SEC: 2
    WORKER_STALE_TIMEOUT_MIN: 10
    LLM_TOKEN_BUDGET_DAILY: ${LLM_TOKEN_BUDGET_DAILY:-1000000}
    LLM_CACHE_TTL_DAYS: 30
    LLM_CACHE_MAX_ROWS: 100000
    LOG_LEVEL: ${LOG_LEVEL:-INFO}
  healthcheck:
    test: ["CMD", "python", "-m", "app.workers.healthcheck"]
    interval: 30s
    timeout: 5s
    retries: 3
    start_period: 20s
  restart: unless-stopped
```

`app/workers/healthcheck.py` — kleines Skript: liest `LLM_WORKER_HEARTBEAT_AT` aus Settings-Tabelle, prüft Alter < 30s, exit 0/1.

**DoD:**

- `docker compose up -d --build` startet beide Container.
- `docker compose ps` zeigt `secscan-llm-worker` als healthy nach 20s.
- `docker compose logs secscan-llm-worker` zeigt `llm_worker starting` und ggf. `idle, sleeping`.

### Phase G — Spec-Updates

#### Task #17 — ARCHITECTURE.md erweitern (`backend-implementer`)

- §6 Envelope: kein Change (Block-O-Stand bleibt).
- §7 Dashboard: neue Group-Spalte erwähnen; Block-O-Stand bleibt sonst.
- §11 Agent: kein Change.
- §12 LLM-Integration: neuen Subabschnitt „Risk-Reviewer (Block P)" mit Two-Pass-Architektur, Worker-Pattern, Mode-Flag.
- §17 Out-of-Scope: bewusst weggelassene Punkte aus ADR-0023 nachtragen (Update-Befehl-Mapping, manueller Override, Multi-Provider, DSGVO-Snapshot-Notice).

#### Task #18 — ADR-Index aktualisieren (`backend-implementer`)

`docs/decisions/README.md`: ADR-0023 Status auf „Akzeptiert" nach Reviewer-Freigabe.

### Phase H — Tests-Sammelphase

#### Task #19 — Integration-Tests E2E

`tests/integration/test_block_p_e2e_observation.py`:

- Scan-Ingest mit pending Findings.
- Worker pickt Jobs in Observation-Mode.
- would-call-Marker im Job-Result.
- Settings-Tab zeigt korrekte Stats.

`tests/integration/test_block_p_e2e_live.py`:

- Mock-LLM-Client mit deterministischen Responses.
- Pass 1 → Library wird befüllt.
- Pass 2 → Group bekommt risk_band, Findings erben.
- Cache-Eintrag wird angelegt.
- Re-Scan derselben Findings → Cache-Hit, kein zweiter LLM-Call.

`tests/integration/test_block_p_mode_switch.py`:

- Mode-Wechsel off → observation → live.
- Backlog-Re-Queue-Action.
- Audit-Events korrekt.

#### Task #20 — Adversarial-Tests

- `tests/adversarial/test_pass1_hallucinated_finding_id.py`
- `tests/adversarial/test_pass1_missing_finding.py`
- `tests/adversarial/test_pass1_label_regex_violation.py`
- `tests/adversarial/test_pass2_hallucinated_group_label.py`
- `tests/adversarial/test_pass2_invalid_band.py` (pending/unknown verboten)
- `tests/adversarial/test_pass2_worst_finding_not_in_group.py`
- `tests/adversarial/test_pass2_reason_with_nul_byte.py`
- `tests/adversarial/test_worker_race_condition_skip_locked.py`
- `tests/adversarial/test_worker_corrupted_job_payload.py`
- `tests/adversarial/test_cache_key_collision.py`

Erwartete Test-Anzahl nach Block P: ~120 neue Tests.

### Phase I — Reviewer + Security-Auditor + Release

#### Task #21 — DoD-Checks (`reviewer`)

```
ruff check . && ruff format --check .
mypy app/
shellcheck agent/*.sh
pytest -v --cov=app --cov-fail-under=85
pytest tests/adversarial/ -v
pytest tests/integration/test_block_p_e2e_*.py -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build
docker compose ps  # beide Container healthy
curl -fsSL http://localhost:8000/healthz  # 200
docker compose logs secscan-llm-worker | grep "llm_worker starting"
```

Plus visueller Smoke. Screenshots unter `docs/blocks/P-evidence/`:

- `server-detail-group-cards.png`
- `server-detail-group-evaluating.png`
- `dashboard-group-filter.png`
- `settings-llm-reviewer-observation.png`
- `settings-llm-reviewer-live.png`
- `settings-mode-change-modal.png`

#### Task #22 — Security-Auditor (`security-auditor`)

Pflicht für Block P. Audit-Punkte:

1. **LLM-Output-Validation ist strikt.** Halluzinierte IDs, falsche Bands (pending/unknown), NUL-Bytes in Reasons werden geblockt. Adversarial-Tests verifizieren.
2. **`pending`/`unknown` sind LLM-Output-verboten** — schemata haben Whitelist, Backend-Code validiert. Pre-Triage-only.
3. **Worker-Container hat keine eingehenden Ports.** Nur DB- und LLM-Provider-Egress. Healthcheck ist interner Python-Aufruf, kein HTTP.
4. **Mode-Wechsel erfordert master_key.** Audit-Event bei jedem Wechsel.
5. **Token-Budget-Cap funktioniert.** Test mit künstlich gefülltem Counter → Worker pausiert, Audit-Event.
6. **`risk_band` auf Finding bekommt keinen direkten User-Input-Pfad.** Bands kommen nur aus Pre-Triage oder LLM-Pass-2.
7. **Worker race condition mit SKIP LOCKED.** Adversarial-Test mit zwei simulierten Workern → genau einer kriegt den Job.
8. **Snapshot-Daten an externen Provider.** DSGVO-Aspekt: Setup-Wizard und Settings-Tab zeigen Warnung beim Wechsel auf live-Mode mit nicht-EU-Provider. Audit dokumentiert.
9. **Group-Pattern-Injection.** Adversarial-Test: LLM-Response mit path_prefix `/etc/passwd` oder `*` → wird vom Backend defensiv getrimmt (Pattern muss mit `/` beginnen und 1-256 chars haben).
10. **Cache-Poisoning.** Verändertes Finding-Set ändert group_findings_fingerprint → kein Cache-Hit → frischer LLM-Call. Adversarial-Test.

#### Task #23 — Spec- und State-Updates (`reviewer`)

- ARCHITECTURE.md aktualisiert (Task #17).
- `docs/decisions/README.md` ADR-0023 Status „Akzeptiert".
- `docs/decisions/0023-llm-risk-reviewer-and-application-grouping.md` Status auf „Akzeptiert".
- `docs/blocks/STATE.md`: Block P unter „Completed".
- `CHANGELOG.md`: v0.9.0-Eintrag.

#### Task #24 — Tag `v0.9.0`

```
git tag -a v0.9.0 -m "Block P — LLM-Risk-Reviewer + Application-Grouping (ADR-0023)"
git push --tags
```

## Was NICHT in diesem Block

- **Konkrete Update-Befehle in Reason-Texten** (`apt-get install ...`, `kubectl upgrade ...`). Block-O-Decision bleibt: deskriptiv, keine Befehle.
- **Konkrete Versions-Empfehlungen** („Update k3s auf v1.30.4-rc1"). LLM kann das nicht zuverlässig.
- **Manueller Risk-Band-Override per Finding oder Server-Tag.** Acknowledgement bleibt einziger Operator-Hebel.
- **Manueller Group-Merge/Split per UI.** Falls Library-Drift Probleme macht, manueller SQL-Eingriff.
- **Group-Detection-Re-Run-Trigger im UI.** Automatisch on-write beim Ingest.
- **Daily-Re-Eval-Job für stale Cache-Einträge.** Cache-TTL räumt das passiv.
- **Multi-Provider-LLM-Switch** speziell für Risk-Reviewer. Aktuell gleicher Block-G-Default-Provider wie Chat.
- **Detail-LLM-Begründung pro Finding** (vs. pro Group). Drill-down zeigt CVE-Daten, aber LLM-Reasoning lebt auf Group-Ebene.
- **Worker-Skalierung mit Provider-Rate-Limit-Sniffing.** ENV-Variable WORKER_CONCURRENCY reicht.
- **Pre-Triage-Cuts in Block O ändern.** Bleibt Block-O-Sache; Block-P-Realdaten können später eine Anpassung motivieren.
- **Group-Trend-Reports** (Historisierung von Band-Wechseln).
- **Container/Pod-Scans als Risk-Quelle.** Out-of-Scope ADR-0017.
- **Notifications** (Email/Discord/Webhook bei escalate-Band).

## Definition of Done

### Datei-Existenz

- [ ] `app/services/llm_risk_reviewer.py`, `group_matcher.py`, `llm_cache.py`, `llm_fingerprints.py` existieren.
- [ ] `app/workers/llm_worker.py`, `app/workers/healthcheck.py` existieren.
- [ ] `app/models.py` enthält `ApplicationGroup`, `LLMJob`, `LLMRiskCache`.
- [ ] `app/templates/_partials/application_group_card.html`, `group_evaluating_card.html` existieren.
- [ ] `app/templates/settings/llm_reviewer.html` existiert.
- [ ] Neue Alembic-Migration existiert.
- [ ] `docker-compose.yml` enthält `secscan-llm-worker`-Service.
- [ ] `docs/decisions/0023-...md` Status „Akzeptiert".
- [ ] `CHANGELOG.md` v0.9.0-Eintrag.

### Statische Checks

- [ ] `ruff check . && ruff format --check . && mypy app/` → exit 0.
- [ ] `shellcheck agent/*.sh` → exit 0.
- [ ] `pytest -v --cov=app --cov-fail-under=85` → exit 0.
- [ ] `pytest tests/adversarial/ -v` → alle grün, mindestens 10 neue Cases.
- [ ] `pytest tests/integration/test_block_p_e2e_*.py -v` → alle grün.
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` → exit 0.

### Build und Deploy

- [ ] `docker build -t secscan:latest .` → exit 0.
- [ ] `docker compose up -d --build` startet beide Container.
- [ ] Web-Container healthy, Worker-Container healthy nach 20s.
- [ ] `/healthz` → 200.
- [ ] `/settings/llm-reviewer` → 200, zeigt Mode + Stats.
- [ ] Image-Size < 200 MB (Delta < 2 MB vs. v0.8.0, kein neues Python-Package nötig falls Block-G-LLM-Wrapper schon `httpx`/`openai` enthält).

### Visueller Smoke

- [ ] Mode=off: keine Group-Cards, Findings wie Block-O-Stand.
- [ ] Mode=observation für eine Woche laufen lassen mit Real-Scans → Settings-Tab zeigt Job-Counts und estimated cost.
- [ ] Mode-Wechsel auf live → Backlog läuft durch, Group-Cards erscheinen graduell, evaluating-State sichtbar.

### E2E-Manual

- [ ] K3s-Test-Host scannt durch im live-Mode: Findings werden in `k3s`-Group gruppiert, Group bekommt act/escalate, Drill-down zeigt einzelne Findings.
- [ ] Re-Scan ohne Änderung: Cache-Hit (kein neuer LLM-Call sichtbar in Audit).
- [ ] Re-Scan nach KEV-DB-Update: Cache-Miss, neuer Pass-2-Call.
- [ ] Worker-Crash (SIGKILL): nach 10min Stale-Reaper resettet in-progress Jobs.
- [ ] Token-Budget künstlich auf 100 setzen, Pass-2-Call überschreitet: Worker pausiert, Audit-Event.
- [ ] Mehrere Worker (compose scale=3) → keine doppelten Pickups (SKIP LOCKED).

### State-Update

- [ ] `docs/blocks/STATE.md` Block P unter „Completed".
- [ ] Tag `v0.9.0` gesetzt.

## Risiken und Mitigation

- **LLM halluziniert in Pass 1 und produziert unsinnige Groups.** Mitigation: strikte Validierung (Vollständigkeits-Check, Label-Regex, ID-Whitelist). Adversarial-Tests. Operator kann manuell SQL-Eingriff machen, Re-Open-Trigger für UI-Merge.
- **LLM gibt in Pass 2 trotz System-Prompt eine konkrete Versions-Empfehlung.** Mitigation: System-Prompt-Test mit verschiedenen Modellen, README-Disclaimer „LLM-Schätzung, Operator-Eigenprüfung". Bei wiederholtem Verstoß Re-Open-Trigger für Post-Processing-Filter.
- **Worker hängt bei einem Job (LLM-Provider down).** Mitigation: HTTP-Client-Timeout im Block-G-Wrapper, Stale-Reaper greift nach 10min, exponential backoff bei Retry.
- **Token-Budget wird durch Halluzinations-Schleife in Sekunden verbrannt.** Mitigation: Hard-Cap, Audit-Event bei Exhaustion, Mode-Switch auf off bei wiederholten Validation-Errors (TBD: Re-Open-Trigger).
- **Concurrency-Probleme mit mehreren Workern.** Mitigation: SKIP LOCKED, Adversarial-Test. Default ist Single-Worker; Skalierung optional.
- **Group-Library wächst zu groß für In-Memory-Cache.** Mitigation: bei > 10000 Library-Entries DB-Lookup statt In-Memory. Re-Open-Trigger; realistisch werden es < 1000 Entries.
- **Cache-Tabelle wächst unkontrolliert.** Mitigation: LRU-Eviction bei > 100K Rows, TTL 30d Read-side.
- **Settings-Tabellen-Heartbeat bei Worker-Crash.** Mitigation: Healthcheck schlägt nach 30s an, Container-Restart durch Docker-Daemon.
- **Operator vergisst Mode=live zurück auf off zu setzen, Token-Cost läuft weiter.** Mitigation: Token-Budget-Hard-Cap, Settings-Tab zeigt cumulative-cost, Audit-Events. Plus README-Hinweis.
- **DSGVO-Implikation Snapshot-Daten an externen Provider.** Mitigation: Settings-Tab zeigt Hinweis beim Wechsel auf live, Setup-Wizard erwähnt das. Out-of-Scope: lokales LLM-Modell als Alternative.
- **Pass-1-Output mit injizierten Pattern (`/`, `*`, leerer String).** Mitigation: Validator droppt unsinnige Pattern (Mindest-Länge, Pflicht-Prefix `/`).

## Reihenfolge

Phase A (Modelle, Migration) → Phase B (Service-Bausteine) → Phase C (Worker) → Phase D (Ingest-Integration) → Phase E (UI) → Phase F (Compose) → Phase G (Spec) → Phase H (Tests) → Phase I (Reviewer + Auditor + Release).

Innerhalb von Phase A: Tasks #1/#2/#3 parallel, #4 nach allen drei.

Innerhalb von Phase B: Tasks #5/#6/#7 parallel, #8 nach allen drei.

Phase C wartet auf Phase B (Service-Bausteine).

Phase D wartet auf Phase B + C.

Phase E kann parallel zu C/D laufen ab Phase-A-Schema-Verfügbarkeit.

Phase F nach Phase C (Worker-Code).

## Implementer-Brief (für `Agent`-Delegation)

1. **`backend-implementer`** Phase A (Tasks #1–#4): Modelle + Migration. Liest ADR-0023 §Application-Group-Schicht + §Asynchroner Worker + §Caching, `app/models.py` komplett. Branch-LOC-Delta: ~+500.

2. **`backend-implementer`** Phase B (Tasks #5–#8): Fingerprints + Matcher + Cache + LLM-Reviewer-Service. Liest ADR-0023 §Pass-1 + §Pass-2 + §Caching, `app/services/llm_*.py` (Block-G-Code) komplett. Branch-LOC-Delta: ~+800.

3. **`backend-implementer`** Phase C (Tasks #9–#10): Worker + Token-Budget. Liest ADR-0023 §Asynchroner Worker komplett. Branch-LOC-Delta: ~+500.

4. **`backend-implementer`** Phase D (Task #11): Ingest-Integration. Liest ADR-0023 §Re-Evaluation, `app/api/scans.py` komplett. Branch-LOC-Delta: ~+150.

5. **`frontend-implementer`** Phase E (Tasks #12–#15): UI-Group-Cards + Dashboard + Settings-Tab. Liest ADR-0023 §UI-Konsequenzen + §Feature-Flag, Block-O-Brief Findings-Section + KPI-Cards. Branch-LOC-Delta: ~+700.

6. **`backend-implementer`** Phase F (Task #16): Docker-Compose-Worker. Liest ADR-0023 §Deployment. Branch-LOC-Delta: ~+50.

7. **`backend-implementer`** Phase G (Tasks #17–#18): Spec-Updates. Liest ARCHITECTURE.md §6, §7, §12, §17.

8. **`test-writer`** Phase H (Tasks #19–#20): Integration + Adversarial. Mock-LLM-Client erforderlich. Branch-LOC-Delta: ~+1500.

9. **`reviewer`** Phase I mit DoD-Checkliste.

10. **`security-auditor`** Phase I mit Audit-Punkten.

Bestehende Blöcke außerhalb des Scopes:

- Block-G-LLM-Chat-Stack bleibt unangetastet; Block P nutzt nur den Provider-Client. Falls Chat-Feature parallel umgebaut wird: gemeinsame Service-Schicht für Provider-Aufrufe.
- Block-N-Bootstrap-Installer unverändert.
- Block-O-Pre-Triage-Engine unverändert; nur Job-Queueing-Hook im Ingest-Pfad wird ergänzt.

## Roll-Back-Plan

Block P führt drei neue Tabellen ein (`application_groups`, `llm_jobs`, `llm_risk_cache`), eine neue FK auf `findings`, einen neuen Worker-Container, drei neue Settings-Tabelle-Einträge. Roll-Back-Szenarien:

1. **LLM produziert problematische Outputs.** Mode-Switch auf `off`, Worker stoppt Job-Verarbeitung. Bestehende `risk_band`-Werte mit `source=llm` bleiben, sind aber operativ untouched. Hotfix in Validierung, Mode zurück auf `live`.

2. **Worker crasht chronisch.** Mode auf `off` schaltet Worker-Pickup ab. Container kann gestoppt werden ohne Web-Service-Impact. Web-UI zeigt weiter alle vorhandenen Bewertungen.

3. **Cache-Korruption oder Pattern-Drift.** `TRUNCATE llm_risk_cache; UPDATE application_groups SET risk_band=NULL, group_findings_fingerprint=NULL`. Nächster Scan-Re-Ingest re-evaluiert.

4. **Komplett-Roll-Back nötig.** Branch verwerfen oder Revert-PR. `alembic downgrade -1` entfernt die drei Tabellen plus FK + Spalte. Bestehende Findings haben dann wieder Block-O-Stand (Bands aus Pre-Triage, Source=engine).

5. **Live-System läuft auf v0.8.0 weiter** falls Block P verworfen wird; alle Operator-Workflows aus Block A-O bleiben funktional. UI ist Block-O-Risk-zentrisches Layout ohne Group-Layer.
