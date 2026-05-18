# Block O — Pre-Triage-Risk-Engine, Host-Snapshot, Vendor-Severity, UI-Redesign

**Typ:** Feature + Backend + UI · **Branch-Vorschlag:** `feat/block-o-risk-engine` · **Zielversion:** v0.8.0 · **Vorgänger:** Block N (v0.7.0, ADR-0021) · **Nachfolger:** Block P (LLM-Final-Bewertung) · **Spec:** [ADR-0022](../decisions/0022-risk-based-prioritization.md)

## Ziel

Vier zusammenhängende Bausteine:

1. **Agent-side Host-Snapshot.** Agent sammelt zusätzlich zu Trivy-Output vier Host-State-Blöcke (`ss`-Listener, `ps`-Prozesse, `lsmod`-Kernel-Module, `systemctl`-Services) und liefert sie im Wrapper-Envelope als `host_state`-Feld. Größenordnung gzipped: +10-30 KB pro Scan. Wird in Block O zwar **gesammelt und persistiert**, aber **nicht** von der Risk-Engine konsumiert — die LLM-Phase (Block P) liest ihn.

2. **CVSS-Vendor-Resolver.** Pro Server wird die Severity aus der zur Host-Distro passenden Vendor-Source bestimmt (Ubuntu→ubuntu→nvd, RHEL/Alma→redhat→nvd, lang-pkgs→ghsa→nvd, …). Bestehende `Finding.severity`-Spalte bleibt; neue `severity_by_provider` (JSONB) hält die Provider-Map. `max_severity_across_providers()` ist Eingabe für die Pre-Triage.

3. **Deterministische Pre-Triage-Engine.** Pro Finding ein Band aus `{noise, monitor, pending, unknown}` allein basierend auf max-Severity-aller-Provider + EPSS + KEV-Flag. **Kein** Host-Kontext-Abgleich, **kein** Mapping-Asset, **kein** Exposure-Matcher. Reine Vor-Auswertung: entscheidet, welche Findings später vom LLM (Block P) genauer angeschaut werden.

4. **UI-Redesign Dashboard + Server-Detail.** Risk-zentrisch: zwei primäre Action-Required-Cards (binär yes/no), sieben sekundäre Risk-Band-Pills, CVSS-Severity-Counter als kompakte Tertiär-Reihe. Server-Detail bekommt Action-Required-Pill im Header und neue „Host snapshot"-Sektion. Findings-Tabelle gruppiert nach `risk_band`, default-expanded ab `pending` aufwärts, default-collapsed für `monitor`/`noise`/`unknown`. Bulk-Ack-„noise"-Workflow per Klick mit Server-Side-Filter.

LLM-Final-Bewertung (Auswertung des Host-Snapshots, Setzen der finalen Bands `escalate`/`act`/`mitigate` plus Demote zu `monitor`/`noise`) ist explizit out-of-scope. Block P kommt nach Block O.

## Vorbereitung — zu lesende Sektionen

- [ADR-0022](../decisions/0022-risk-based-prioritization.md) (komplett)
- [ADR-0021](../decisions/0021-agent-bootstrap-installer.md) §Ursachen-Felder-pro-Finding (`vendor_status` aus Block O baut nicht auf den Block-N-Spalten auf, aber das gemeinsame Pydantic-Schema wird parallel erweitert)
- [ADR-0020](../decisions/0020-dashboard-cross-server-findings.md) (Dashboard-Pane-Struktur, KPI-Cards, Filter-Bar)
- [ADR-0018](../decisions/0018-server-detail-visual-alignment.md) (Server-Detail-Layout, Header-Pill-Reihe)
- [ADR-0011](../decisions/0011-lang-pkgs-target-disambiguation.md) (`@target`-Format im `package_name` — Pre-Triage liest `package_name` nicht für Klassifikation, daher unproblematisch)
- [ADR-0003](../decisions/0003-push-not-pull.md) (Push-Modell — Snapshot kommt im selben Envelope wie Trivy-Daten, kein separater Endpoint)
- [ADR-0010](../decisions/0010-deepseek-v3-default.md) (LLM-Default-Provider — Block P nutzt das, Block O berührt LLM-Code nicht)
- `ARCHITECTURE.md` §6 (Envelope, wird erweitert)
- `ARCHITECTURE.md` §7 (Dashboard-Layout, wird umgebaut)
- `ARCHITECTURE.md` §9 (Sicherheits-Hardening, Validatoren für die neuen Felder)
- `ARCHITECTURE.md` §11 (Client-Agent, wird erweitert)
- `ARCHITECTURE.md` §15 (Sortier-Defaults — `risk_band` wird Primary)
- `ARCHITECTURE.md` §17 (Out-of-Scope, neuen Block prüfen — LLM-Reasoning bleibt out-of-scope für Block O)
- `app/api/scans.py` (Ingest-Pfad — Reihenfolge Auth → Body-Parse → Findings → Snapshot → Pre-Triage)
- `app/schemas/scan_envelope.py` (Pydantic-Modelle, werden erweitert)
- `app/models.py` `class Finding` und `class Server` (werden erweitert, plus vier neue Modelle)
- `app/services/findings_ingest.py` (Ingest-Mapper)
- `app/services/findings_query.py` (Filter-Anwendung)
- `app/templates/dashboard/_kpi_cards.html` und `dashboard/_findings_section.html` (Block-M-Output, wird umgebaut)
- `app/templates/servers/detail.html` und `servers/_findings_section.html` (Block-K-Output, wird umgebaut)
- `tests/fixtures/trivy/` (Real-Fixtures, Basis für Engine-Tabellen-Tests)
- `agent/secscan-agent.sh` (wird erweitert um Snapshot-Funktionen)

Subagent-Aufrufe nennen die Sektionen explizit.

## Aufgaben

### Phase A — Enums, Schema, Migration

#### Task #1 — Enums und Konstanten (`backend-implementer`)

Neue Datei `app/services/risk_engine.py` (Skelett):

```python
from enum import Enum

class RiskBand(str, Enum):
    ESCALATE = "escalate"  # LLM-Output (Block P)
    ACT = "act"            # LLM-Output (Block P)
    MITIGATE = "mitigate"  # LLM-Output (Block P)
    PENDING = "pending"    # Pre-Triage-Output (Block O)
    UNKNOWN = "unknown"    # Pre-Triage-Output (Block O, kein Snapshot)
    MONITOR = "monitor"    # Pre-Triage- ODER LLM-Output
    NOISE = "noise"        # Pre-Triage- ODER LLM-Output

class ActionRequired(str, Enum):
    YES = "yes"
    NO = "no"

ACTION_REQUIRED_MAP: dict[RiskBand, ActionRequired] = {
    RiskBand.ESCALATE: ActionRequired.YES,
    RiskBand.ACT:      ActionRequired.YES,
    RiskBand.MITIGATE: ActionRequired.YES,
    RiskBand.PENDING:  ActionRequired.YES,
    RiskBand.UNKNOWN:  ActionRequired.YES,
    RiskBand.MONITOR:  ActionRequired.NO,
    RiskBand.NOISE:    ActionRequired.NO,
}

RISK_BAND_SORT_RANK: dict[RiskBand, int] = {
    RiskBand.ESCALATE: 70,
    RiskBand.ACT:      60,
    RiskBand.MITIGATE: 50,
    RiskBand.PENDING:  40,
    RiskBand.UNKNOWN:  30,
    RiskBand.MONITOR:  20,
    RiskBand.NOISE:    10,
}

# Pre-Triage-Cuts (siehe ADR-0022 §Pre-Triage-Algorithmus)
EPSS_PENDING_THRESHOLD = 0.1  # >= 0.1 → pending (KEV unabhängig)
```

Plus eine Whitelist für `vendor_status` mit Normalisierungs-Map (Werte aus Trivys `Status`-Feld):

```python
_VENDOR_STATUS_MAP = {
    "affected":            "affected",
    "fixed":               "fixed",
    "under_investigation": "investigating",
    "will_not_fix":        "will_not_fix",
    "end_of_life":         "eol",
    "not_affected":        "not_affected",
}

def normalize_vendor_status(raw: str | None) -> str | None:
    if raw is None or raw == "":
        return None
    return _VENDOR_STATUS_MAP.get(raw.strip().lower(), "unknown")
```

**DoD:**

- `mypy --strict` PASS.
- Unit-Tests in `tests/services/test_risk_engine_enums.py`:
  - `ACTION_REQUIRED_MAP` deckt alle `RiskBand`-Werte ab (kein KeyError).
  - `RISK_BAND_SORT_RANK` ist streng monoton fallend von ESCALATE bis NOISE.
  - `normalize_vendor_status("will_not_fix") == "will_not_fix"`, `("Foo") == "unknown"`, `(None) is None`.

#### Task #2 — DB-Migration (`backend-implementer`)

`app/models.py`:

Vier neue Modelle:

```python
class ServerListener(Base):
    __tablename__ = "server_listeners"
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    proto: Mapped[str] = mapped_column(String(8), primary_key=True)  # tcp/udp/tcp6/udp6
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    addr: Mapped[str] = mapped_column(String(64), primary_key=True)
    process: Mapped[str | None] = mapped_column(String(64))
    pid: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (
        Index("ix_server_listeners_port", "server_id", "port"),
        CheckConstraint("port >= 0 AND port <= 65535", name="ck_server_listeners_port_range"),
    )


class ServerProcess(Base):
    __tablename__ = "server_processes"
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str | None] = mapped_column(String(32))
    comm: Mapped[str | None] = mapped_column(String(64))
    args: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (Index("ix_server_processes_comm", "server_id", "comm"),)


class ServerKernelModule(Base):
    __tablename__ = "server_kernel_modules"
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), primary_key=True)


class ServerService(Base):
    __tablename__ = "server_services"
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), primary_key=True)
```

`class Server`:

```python
host_state_snapshot_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
```

`class Finding`:

```python
risk_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
risk_band_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
risk_band_source: Mapped[str | None] = mapped_column(String(16), nullable=True, default="engine")
risk_band_computed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
severity_by_provider: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
vendor_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
```

Plus zwei Indizes:

```python
Index("ix_findings_risk_band_open", "risk_band", postgresql_where="status = 'open'")
Index("ix_findings_server_risk_band", "server_id", "risk_band")
```

Alembic-Migration `XXXX_block_o_risk_and_host_state.py`:

- 4 × `create_table`.
- `op.add_column('servers', sa.Column('host_state_snapshot_at', ...))`.
- 6 × `op.add_column('findings', ...)`.
- 2 × `op.create_index(...)` auf `findings`.
- `downgrade`: spiegelbildlich.

Kein Backfill.

**DoD:**

- `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS.
- Schema-Smoke in `tests/migrations/test_block_o_schema.py`: prüft alle acht neuen Finding-/Server-Spalten + vier Tabellen + zwei Findings-Indizes.
- `mypy --strict` PASS.

#### Task #3 — Envelope-Schema-Erweiterung (`backend-implementer`)

`app/schemas/scan_envelope.py`:

Neue Sub-Modelle `ListenerEntry`, `ProcessEntry`, `HostStateBlock` (siehe ADR-0022 §Host-Snapshot-Datenmodell) mit strikten Validatoren:

- IPv4/IPv6-Literal-Validierung für `addr` (ASCII-only, NUL-frei).
- Port-Range-Check (0..65535).
- ASCII-only + NUL-frei + Length-Cap auf allen Listen-Items.
- Max-Length-Bounds aus ADR (4096 Listener/Prozesse, 1024 Modules/Services, 32 Tools/Gaps).

`Envelope` um `host_state: HostStateBlock | None = None`.

Zusätzlich: `TrivyVulnerability` um `vendor_severity: dict[str, str] | None = None` (alias `VendorSeverity`). Sub-Validator: max 16 Provider, Keys + Values ASCII-only, NUL-frei.

**DoD:**

- Unit-Tests in `tests/schemas/test_host_state_envelope.py`:
  - Vollständiger `host_state`-Block parst → alle Felder gesetzt.
  - `host_state = None` → Envelope-Parse erfolgreich (Forward-Compat).
  - Listener mit `port=70000` → ValidationError.
  - Process mit `args` länger als 4096 → ValidationError.
  - `tools_available` mit non-ASCII-Item → Item wird verworfen, andere bleiben.
  - 5000 Listener → ValidationError oder Cap auf 4096 je nach Pydantic-Verhalten.
  - `VendorSeverity` mit 20 Providern → Cap auf 16, oder Reject je nach Field-Constraint.
- `mypy --strict` PASS.

### Phase B — Risk-Engine-Bausteine (deterministisch)

#### Task #4 — Severity-Resolver (`backend-implementer`)

Neue Datei `app/services/severity_resolver.py`:

```python
_VENDOR_PRIORITY: dict[str, tuple[str, ...]] = {
    "ubuntu":     ("ubuntu", "debian", "nvd"),
    "debian":     ("debian", "ubuntu", "nvd"),
    "rhel":       ("redhat", "nvd"),
    "centos":     ("redhat", "nvd"),
    "rocky":      ("redhat", "nvd"),
    "alma":       ("redhat", "nvd"),
    "fedora":     ("redhat", "nvd"),
    "amazon":     ("amazon", "redhat", "nvd"),
    "opensuse-leap":       ("suse", "nvd"),
    "opensuse-tumbleweed": ("suse", "nvd"),
    "sles":       ("suse", "nvd"),
    "alpine":     ("alpine", "nvd"),
    "oracle":     ("oracle", "redhat", "nvd"),
}

_LANG_PRIORITY = ("ghsa", "nvd")


def severity_for(finding: Finding, server: Server) -> tuple[Severity, str]:
    """Returns (severity_value, severity_source) — die UI-Anzeige-Severity
    plus den Provider-Namen ('ubuntu', 'nvd', 'ghsa', ...).

    Fallback-Kette: priorisierte Provider in Reihenfolge durchgehen, erstes
    gesetztes Feld nehmen. Wenn nichts → finding.severity + 'trivy'-Source."""


def max_severity_across_providers(finding: Finding) -> Severity:
    """Returns das Maximum ueber alle bekannten Provider plus den
    Top-Level-Trivy-Wert. Eingabe fuer pretriage().

    Wenn severity_by_provider None oder leer ist: fallback auf
    finding.severity (Status quo)."""


def _score_to_severity(score: float) -> Severity:
    if score >= 9.0: return Severity.CRITICAL
    if score >= 7.0: return Severity.HIGH
    if score >= 4.0: return Severity.MEDIUM
    if score > 0.0:  return Severity.LOW
    return Severity.UNKNOWN
```

**DoD:**

- Unit-Tests in `tests/services/test_severity_resolver.py`:
  - `server.os_family="ubuntu"`, `severity_by_provider={"ubuntu":"low","nvd":"critical"}` → `severity_for` returns `(LOW, "ubuntu")`.
  - Gleicher Server: `max_severity_across_providers` returns `CRITICAL` (NVD ist im Max enthalten).
  - `server.os_family="alma"`, `severity_by_provider={"redhat":"medium"}` → `(MEDIUM, "redhat")`.
  - `server.os_family="ubuntu"`, `severity_by_provider={"nvd":"high"}` (kein Ubuntu) → `(HIGH, "nvd")`.
  - `finding_class="lang-pkgs"`, `severity_by_provider={"ghsa":"high"}` → `(HIGH, "ghsa")`.
  - `severity_by_provider=None` → `severity_for` fällt auf `finding.severity + "trivy"`. `max_severity_across_providers` returns `finding.severity`.
  - Server-Family unbekannt → fällt auf NVD.

#### Task #5 — Vendor-Status aus Trivy extrahieren (`backend-implementer`)

`app/services/findings_ingest.py`:

- Mapper-Erweiterung: aus `TrivyVulnerability.status` wird `vendor_status` via `normalize_vendor_status()` gesetzt.
- Aus `TrivyVulnerability.vendor_severity` wird `severity_by_provider` als Python-Dict persistiert (Keys/Values nach `_score_to_severity` normalisiert wenn nötig).

**DoD:**

- Unit-Tests in `tests/services/test_findings_ingest_vendor_status.py`:
  - Trivy `Status="will_not_fix"` → Finding `vendor_status="will_not_fix"`.
  - Trivy `Status="end_of_life"` → `vendor_status="eol"`.
  - Trivy `Status="Foobar"` → `vendor_status="unknown"`.
  - Trivy `Status=None` → `vendor_status=None`.
  - Trivy `VendorSeverity={"nvd":"high","ubuntu":"medium"}` → `severity_by_provider={"nvd":"high","ubuntu":"medium"}`.
  - Trivy `VendorSeverity={"nvd":3,"ubuntu":2}` (numerische Severity wie Trivy schreibt) → `severity_by_provider={"nvd":"high","ubuntu":"medium"}` via Mapping-Tabelle.

#### Task #6 — Pre-Triage-Engine (`backend-implementer`)

`app/services/risk_engine.py` Vollimplementierung:

```python
@dataclass
class RiskEvaluation:
    band: RiskBand
    reason: str
    computed_at: datetime
    source: str = "engine"  # 'engine' | 'llm' | 'manual'


def pretriage(finding: Finding, server: Server, snapshot_available: bool) -> RiskEvaluation:
    """Reine Vor-Auswertung — kein Host-Kontext-Abgleich.
    Output ist einer aus {NOISE, MONITOR, PENDING, UNKNOWN}."""
    now = datetime.now(timezone.utc)

    if not snapshot_available:
        return RiskEvaluation(
            band=RiskBand.UNKNOWN,
            reason="host snapshot missing — update agent to ≥ 0.3.0",
            computed_at=now,
        )

    max_sev = max_severity_across_providers(finding)
    epss = finding.epss_score or 0.0
    kev = finding.is_kev

    if kev:
        return RiskEvaluation(
            band=RiskBand.PENDING,
            reason=_format_pending_reason(max_sev, epss, kev=True),
            computed_at=now,
        )
    if max_sev >= Severity.HIGH:
        return RiskEvaluation(
            band=RiskBand.PENDING,
            reason=_format_pending_reason(max_sev, epss, kev=False),
            computed_at=now,
        )
    if epss >= EPSS_PENDING_THRESHOLD:
        return RiskEvaluation(
            band=RiskBand.PENDING,
            reason=f"EPSS {epss:.2f} ≥ 0.1 · pending LLM review",
            computed_at=now,
        )
    if max_sev == Severity.MEDIUM:
        return RiskEvaluation(
            band=RiskBand.MONITOR,
            reason=f"max-severity MEDIUM · EPSS {epss:.3f} · not KEV",
            computed_at=now,
        )
    return RiskEvaluation(
        band=RiskBand.NOISE,
        reason=f"all providers ≤ LOW · EPSS {epss:.3f} · not KEV",
        computed_at=now,
    )


def _format_pending_reason(max_sev: Severity, epss: float, kev: bool) -> str:
    parts: list[str] = []
    if kev:
        parts.append("KEV listed")
    if max_sev >= Severity.HIGH:
        parts.append(f"max-severity {max_sev.value.upper()}")
    if epss >= EPSS_PENDING_THRESHOLD:
        parts.append(f"EPSS {epss:.2f}")
    parts.append("pending LLM review")
    return " · ".join(parts)[:256]
```

**Wichtig:** `pretriage()` darf einen bestehenden `risk_band` mit `risk_band_source = 'llm'` **nicht** überschreiben. Diese Logik lebt im Caller (Task #8), nicht in `pretriage()` selbst — Single-Responsibility.

**DoD:**

- Unit-Tests in `tests/services/test_risk_engine_pretriage.py` — Tabellen-getrieben, ~25 Cases:
  - Severity LOW + EPSS 0.001 + not KEV → `NOISE`.
  - Severity MEDIUM + EPSS 0.05 + not KEV → `MONITOR`.
  - Severity MEDIUM + EPSS 0.15 + not KEV → `PENDING` (EPSS-Trigger).
  - Severity MEDIUM + EPSS 0.001 + KEV → `PENDING` (KEV-Override).
  - Severity HIGH + EPSS 0.001 + not KEV → `PENDING` (HIGH-Trigger).
  - Severity CRITICAL + EPSS 0.9 + KEV → `PENDING`.
  - Severity LOW + EPSS 0.001 + KEV → `PENDING` (KEV-Override).
  - `snapshot_available=False` mit jeglicher Severity → `UNKNOWN`.
  - max-Severity über alle Provider: NVD=HIGH, Ubuntu=LOW → max ist HIGH → `PENDING`.
- Reason-Strings enthalten erwartete Substrings für jeden Band.
- Performance-Bench `@pytest.mark.bench`: 10000 Findings × pretriage() < 100 ms.
- `mypy --strict` PASS.

### Phase C — Ingest und Persistenz

#### Task #7 — Snapshot-Persistenz im Ingest (`backend-implementer`)

`app/api/scans.py`:

Nach dem bestehenden Findings-Ingest-Block ein neuer Snapshot-Persist-Block:

```python
if envelope.host_state is not None:
    try:
        persist_host_state(session, server, envelope.host_state)
        server.host_state_snapshot_at = envelope.host_state.snapshot_at or now
        audit_event("host_state.snapshot_received", server_id=server.id,
                    body={"tools_available": envelope.host_state.tools_available,
                          "gaps": envelope.host_state.gaps,
                          "listener_count": len(envelope.host_state.listeners),
                          "process_count": len(envelope.host_state.processes)})
        snapshot_available = True
    except SQLAlchemyError as e:
        audit_event("host_state.parse_failed", server_id=server.id, body={"error": str(e)[:256]})
        snapshot_available = False
else:
    snapshot_available = False
```

Neue Helper-Funktion `persist_host_state(session, server, block)`:

- Truncate + Insert (in einer Transaktion) auf den vier Snapshot-Tabellen für diesen Server.
- Listener-Tabelle: dedup auf `(proto, addr, port)` — falls Tool doppelte Einträge meldet, ersten gewinnen.
- Process-Tabelle: dedup auf `pid`.
- Module / Service-Tabellen: dedup auf `name`.

**DoD:**

- Integration-Test in `tests/api/test_scans_host_state.py`:
  - Envelope mit komplettem `host_state` → vier Tabellen korrekt befüllt.
  - Envelope ohne `host_state` → keine Snapshot-Tabellen-Änderung, kein Crash, Pre-Triage läuft mit `snapshot_available=False`.
  - Re-Ingest mit anderem Snapshot → alte Daten weg, neue da (Truncate-Verhalten).
  - Envelope mit `gaps=["listeners"]` und leerer Listener-Liste → Snapshot-Tabelle leer, `host_state.snapshot_received`-Event mit `gaps=["listeners"]`.
  - Malformed Listener (non-ASCII in `addr`) → ValidationError im Pydantic-Layer, ganzer Snapshot wird verworfen, Findings-Ingest läuft trotzdem.

#### Task #8 — Pre-Triage-Aufruf im Ingest (`backend-implementer`)

`app/api/scans.py` nach Snapshot-Persist:

```python
band_counters: Counter = Counter()

for f in session.query(Finding).filter_by(server_id=server.id, status=FindingStatus.OPEN).all():
    # LLM-gesetzte Bands nicht ueberschreiben
    if f.risk_band_source == "llm":
        band_counters[f.risk_band or "unset"] += 1
        continue

    eval_ = pretriage(f, server, snapshot_available)

    if f.risk_band != eval_.band.value:
        audit_event("risk.band_changed",
                    target_id=str(f.id),
                    body={"from": f.risk_band, "to": eval_.band.value,
                          "source": "engine", "reason": eval_.reason})

    f.risk_band = eval_.band.value
    f.risk_band_reason = eval_.reason
    f.risk_band_source = "engine"
    f.risk_band_computed_at = eval_.computed_at
    band_counters[eval_.band.value] += 1

audit_event("risk.pretriage_evaluated", server_id=server.id,
            body={"counters": dict(band_counters)})
```

**DoD:**

- Integration-Test in `tests/api/test_scans_risk_pretriage.py`:
  - Vollständiger Ingest mit Snapshot → alle Findings haben gesetzten `risk_band ∈ {noise, monitor, pending, unknown}`.
  - Re-Ingest mit gleichem Snapshot + gleichen Findings → Bands unverändert, keine `risk.band_changed`-Audits.
  - Re-Ingest nach Trivy-DB-Update mit KEV-Listing eines vorher harmlosen CVE → Finding ändert Band auf `pending`, Audit-Event geschrieben.
  - Ingest ohne `host_state` (alter Agent) → alle Findings haben `risk_band="unknown"`.
  - Finding mit `risk_band_source="llm"` und `risk_band="act"` aus Block-P-Simulation → Re-Ingest überschreibt das **nicht**.

### Phase D — UI-Redesign

#### Task #9 — Dashboard-KPI-Cards umbauen (`frontend-implementer`)

`app/templates/dashboard/_kpi_cards.html` Komplett-Umbau gemäß ADR-0022 §UI-Redesign:

- Zwei primäre Action-Required-Cards (Action needed / Safe), groß. Beide klickbar als Filter.
- Sieben sekundäre Risk-Band-Pills (Escalate/Act/Mitigate/Pending/Unknown/Monitor/Noise), kompakt. Pulse-Animation für Escalate.
- Tertiäre Severity-Strip (kleine Pill-Reihe ohne Sparkline, kein Filter).

`app/views/dashboard.py:_build_pane_context()` baut die neuen Counter:

```python
yes_bands = ("escalate", "act", "mitigate", "pending", "unknown")
no_bands  = ("monitor", "noise")

action_yes_servers = session.query(Finding.server_id).filter(
    Finding.status == FindingStatus.OPEN,
    Finding.risk_band.in_(yes_bands)
).distinct().count()

action_no_servers = total_active_servers - action_yes_servers

risk_band_counts = dict(session.query(Finding.risk_band, func.count()).filter(
    Finding.status == FindingStatus.OPEN
).group_by(Finding.risk_band).all())
```

**DoD:**

- View-Test in `tests/views/test_dashboard_risk_kpis.py`:
  - 3 Server mit unterschiedlichen Bands → Counter korrekt.
  - Klick auf Action-Needed-Card → URL `?action_required=yes`, Tabelle gefiltert.
  - Klick auf Risk-Band-Pill (z.B. Pending) → URL `?risk_band=pending`.

#### Task #10 — Filter-Bar + Findings-Tabelle erweitern (`frontend-implementer`)

`app/schemas/dashboard_filter.py` und `app/schemas/findings_view_filter.py`:

```python
risk_band: Literal["escalate","act","mitigate","pending","unknown","monitor","noise"] | None = None
action_required: Literal["yes","no"] | None = None
```

`app/templates/dashboard/_findings_filter_bar.html` und `servers/_findings_filter_bar.html`: zwei neue `<select>`-Felder.

`app/templates/dashboard/_findings_section.html` und `servers/_findings_section.html`: neue Tabellen-Spalte `Risk` als erste Sort-Spalte (nach Bulk-Select-Checkbox), CVSS-Severity-Spalte rutscht nach hinten.

`app/services/findings_query.py`: Filter-Anwendung für `risk_band` direkt; für `action_required=yes` → `risk_band IN ('escalate','act','mitigate','pending','unknown')`. Default-Sort-Key wird zu `risk` (DESC) mit `RISK_BAND_SORT_RANK`-Mapping (Constant aus Task #1). Tiebreak weiter wie ADR-0020-Defaults.

**DoD:**

- View-Tests:
  - `?risk_band=pending` filtert korrekt.
  - `?action_required=yes` filtert auf alle fünf Yes-Bänder.
  - Default-Sortierung zeigt escalate/act/mitigate ganz oben, pending davor unknown davor monitor davor noise.
  - Sort-Header-Klick auf Risk-Spalte toggelt asc/desc.

#### Task #11 — Server-Detail Action-Required-Pill + Snapshot-Sektion (`frontend-implementer`)

`app/templates/servers/detail.html`:

- Header-Pill-Reihe bekommt als erste Pill die Action-Required-Pill mit Sub-Counter.
- Direkt unter dem Header neue Sektion `<section id="host-snapshot">` mit kompakter Listener-/Services-Anzeige. Default-collapsed mit Toggle. Inline-Default zeigt max 5 Listener + „N more" Hinweis.

`app/templates/servers/_findings_section.html`:

- Findings-Tabelle gruppiert nach `risk_band` mit Section-Headers.
- Default-expanded ab `pending` aufwärts, default-collapsed für `monitor`/`noise`/`unknown`.
- Per-Finding-Detail-Box zeigt `risk_band_reason` in Mono-Font.

**DoD:**

- View-Tests:
  - Server mit `pending`-Finding → rote Action-Pill, Anzahl in Sub-Counter korrekt.
  - Server ohne Findings mit `action_required=yes` → grüne Safe-Pill.
  - Server ohne Snapshot → graue Update-Agent-Pill mit Hint im Tooltip.
  - Snapshot-Sektion zeigt erste 5 Listener, „X more"-Toggle expandiert.
  - Finding-Detail zeigt `risk_band_reason`.

#### Task #12 — Bulk-Ack „noise"-Workflow (`frontend-implementer` + `backend-implementer`)

`app/templates/servers/_findings_section.html`: neuer Button „Acknowledge all noise on this server (N)" neben dem CSV-Dropdown. Klick öffnet Modal `_bulk_ack_noise_modal.html` mit Liste der `noise`-Findings.

`app/views/findings.py:bulk_acknowledge` erweitern um optionalen Parameter `risk_band_filter: Literal["noise"] | None = None`:

- Wenn gesetzt: Server-Side fügt `Finding.risk_band == "noise"`-Bedingung hinzu, unabhängig von mitgesendeten IDs.
- Sicherheits-Default: eingeschleuste IDs anderer Bänder werden server-side aus dem Set gefiltert. Response-Body listet die übersprungenen IDs.
- Audit-Event `bulk.acknowledged` enthält die geprüfte Endliste.

**DoD:**

- Adversarial-Test `tests/adversarial/test_bulk_ack_noise_strict.py`:
  - Request mit `risk_band_filter="noise"` und 4 IDs (1 noise, 1 monitor, 1 act, 1 pending) → nur die noise-ID wird acked, andere unangetastet, Response-Body listet die drei übersprungenen IDs.
- View-Test: Modal-Liste zeigt korrekt nur noise-Findings.

### Phase E — Agent-Erweiterung

#### Task #13 — Agent-Snapshot-Sammlung (`backend-implementer`)

`agent/secscan-agent.sh`:

- `readonly AGENT_VERSION="0.3.0"`.
- Vier neue Funktionen (`collect_listeners`/`collect_processes`/`collect_kernel_modules`/`collect_services`) mit Tool-Verfügbarkeits-Check.
- Tool-Verfügbarkeit wird in `tools_available`/`gaps`-Arrays getrackt.
- Envelope-Erweiterung um `host_state`-Block. Größenordnung gzipped: typisch +10-30 KB.
- Fallback-Pfade: kein `ss` → `netstat`; kein `lsmod` → leerer Block + `gaps=["kernel_modules"]`; kein `systemctl` → leerer Block + `gaps=["services"]`.

Parser-Helper bauen das JSON inkrementell mit `jq`.

**DoD:**

- `shellcheck agent/secscan-agent.sh` PASS.
- Bash-Unit-Test `tests/services/test_agent_host_state.py` (Python via subprocess):
  - Auf einem CI-Container mit allen vier Tools → alle Blöcke populated.
  - Container ohne `systemctl` (z.B. Alpine in CI) → `services=[]`, `gaps=["services"]`.
  - JSON ist valid und parsed durch Backend-Pydantic-Modell ohne Fehler.
- Manueller Smoke gegen Test-Backend: Envelope enthält `host_state` mit allen vier Blöcken.

### Phase F — ARCHITECTURE-Updates

#### Task #14 — ARCHITECTURE.md erweitern (`backend-implementer`)

- §6 Envelope-Beispiel um `host_state`-Sub-Block.
- §7 Dashboard-Beschreibung neu schreiben: Risk-zentrisch (zwei Action-Required-Cards prominent, sieben Risk-Band-Pills, Severity-Strip kompakt). Block-M-Beschreibung wird abgelöst.
- §11 Agent-Beschreibung um Snapshot-Sammlung erweitern.
- §15 Sortier-Defaults: `risk_band` als Primary-Sort, CVSS-Severity als Tiebreak-Tail.
- §17 Out-of-Scope ergänzen: LLM-Risk-Reasoning (Block P), Host-Snapshot-Historisierung, manueller Risk-Override, Patch-Alter-Eskalation, Exposure-Mapping (kommt nicht — LLM macht das).

#### Task #15 — ADR-Index aktualisieren (`backend-implementer`)

`docs/decisions/README.md`: ADR-0022 Status auf „Akzeptiert" nach Reviewer-Freigabe.

### Phase G — Tests (Sammelphase)

#### Task #16 — Komplette Test-Suite

Erwartete neue Tests:

- ~25 Pre-Triage-Tabellen-Tests (`test_risk_engine_pretriage.py`).
- ~10 Severity-Resolver-Tests.
- ~8 Envelope-Schema-Tests.
- ~6 Ingest-Snapshot-Tests.
- ~6 Ingest-Pretriage-Tests.
- ~10 Dashboard-View-Tests.
- ~8 Server-Detail-View-Tests.
- ~6 Bulk-Ack-Tests.
- ~6 Vendor-Status-Tests.
- ~10 Adversarial-Tests.

Erwartete Test-Anzahl nach Block O: bestehend ~890 (Stand v0.7.0) + ~90 neue = ~980. Coverage-Target weiterhin ≥ 85 %.

#### Task #17 — Adversarial-Tests

- `tests/adversarial/test_host_state_xss.py` — Prozess-`args` mit `<script>` rendert escaped.
- `tests/adversarial/test_listener_addr_validation.py` — Malformed-IP-Literale gerejected.
- `tests/adversarial/test_bulk_ack_noise_strict.py` — Einschleusen von non-noise-IDs blockt.
- `tests/adversarial/test_pretriage_no_snapshot_safety.py` — Findings ohne Snapshot bekommen IMMER `unknown` (kein silent-Fallback auf CVSS).
- `tests/adversarial/test_pretriage_no_llm_override.py` — Re-Ingest überschreibt LLM-gesetzte Bands nicht.
- `tests/adversarial/test_host_state_max_lengths.py` — Snapshot mit jeweils 10000 Listenern/Prozessen wird vom Pydantic-Layer auf Bounds gekappt oder gerejected.

### Phase H — Reviewer + Security-Auditor + Release

#### Task #18 — DoD-Checks (`reviewer`)

```
ruff check . && ruff format --check .
mypy app/
shellcheck agent/*.sh
pytest -v --cov=app --cov-fail-under=85
pytest tests/adversarial/ -v
pytest tests/services/test_risk_engine_pretriage.py -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build && curl -fsSL http://localhost:8000/healthz
```

Plus visueller Smoke. Screenshots unter `docs/blocks/O-evidence/`:

- `dashboard-risk-kpis.png`
- `server-detail-action-pill.png`
- `server-detail-host-snapshot-section.png`
- `findings-grouped-by-risk.png`
- `bulk-ack-noise-modal.png`

#### Task #19 — Security-Auditor (`security-auditor`)

Pflicht für Block O. Audit-Punkte:

1. **Pre-Triage kann keine echten Eskalationen schlucken.** Tabellen-Tests müssen alle KEV+HIGH+EPSS-Kombinationen abdecken, die in `pending` landen müssen.
2. **`unknown`-Default ist konservativ** (action_required=yes). Wenn Snapshot fehlt, soll der Operator das sehen, nicht automatisch ignorieren.
3. **Bulk-Ack-Noise-Endpoint filtert server-side.** Adversarial-Test muss zeigen dass eingeschleuste IDs nicht durchkommen.
4. **Snapshot-Pydantic-Validatoren sind strikt** für IP-Literal, Port-Range, ASCII-only.
5. **`risk_band`-Spalte hat keinen direkten User-Input-Pfad.** Operator kann nur via Acknowledgement entscheiden, nicht via Risk-Band-API.
6. **Audit-Events sind vollständig.** Jede Band-Bewegung produziert `risk.band_changed`. Test verifiziert.
7. **Host-Snapshot-Daten DSGVO-Aspekt.** Prozess-Args können User-Pfade enthalten (z.B. `/home/alice/...`). Auditor prüft Privacy-Implikationen — Mitigation falls relevant: Privacy-Notice im Setup-Wizard (Block B).
8. **LLM-gesetzte Bands überleben Re-Ingest.** Test verifiziert dass `risk_band_source='llm'` nicht durch Pre-Triage überschrieben wird.

#### Task #20 — Spec- und State-Updates (`reviewer`)

- ARCHITECTURE.md aktualisiert (Task #14).
- `docs/decisions/README.md` ADR-0022 Status „Akzeptiert" (Task #15).
- `docs/decisions/0022-risk-based-prioritization.md` Status auf „Akzeptiert".
- `docs/blocks/STATE.md`: Block O unter „Completed" mit Datum, Branch, Test-Anzahl, Coverage.
- `CHANGELOG.md`: v0.8.0-Eintrag mit:
  - Risk-Band-Klassifikation mit binärem `action_required`-Modell.
  - Host-Snapshot-Sammlung (Agent 0.3.0).
  - DB-Migration mit sechs neuen Finding-Spalten, vier neuen Snapshot-Tabellen.
  - Bulk-Ack-„noise"-Workflow.
  - Hinweis: alte Agents weiterhin akzeptiert, Findings landen in `risk_band=unknown`.
  - Hinweis: LLM-Final-Bewertung kommt in v0.9.0 (Block P).

#### Task #21 — Tag `v0.8.0`

Nach Reviewer- und Security-Auditor-Freigabe und allen DoD-Checks grün:

```
git tag -a v0.8.0 -m "Block O — Pre-Triage Risk-Engine + Host-Snapshot (ADR-0022)"
git push --tags
```

## Was NICHT in diesem Block

- **Keine LLM-Final-Bewertung** — kommt als Block P. Schema-Slot `risk_band_source = 'llm'` ist da, Block P füllt ihn.
- **Kein Exposure-Mapping**, keine `package_exposure_map.json`, kein `app/services/exposure_matcher.py`. Die Frage „passt das verwundbare Modul zu diesem Host?" beantwortet das LLM, nicht eine Regel-Engine mit Hunderten Mapping-Einträgen.
- **Kein Daily-Re-Eval-Job** für EPSS/KEV-DB-Updates zwischen Scans. Pre-Triage läuft ausschließlich bei Scan-Ingest.
- **Kein manueller Operator-Override** (Tag oder pro Finding). Acknowledgement ist der einzige Override.
- **Keine Patch-Alter-Eskalation.**
- **Keine Host-Snapshot-Historisierung.** Nur der letzte Snapshot pro Server.
- **Kein Aggregat-Trend** wie „X Server haben sich diese Woche verschlechtert".
- **Kein Alpine/OpenRC-Service-Support** — `services`-Block bleibt auf systemd-Hosts gefüllt; andere Hosts liefern leer mit `gaps=["services"]`.
- **Keine UI-editierbare Pre-Triage-Schwelle.** Cuts sind Code-Konstanten.
- **Keine Container/Pod-Scans** (out-of-scope ARCHITECTURE §17 unverändert).
- **Kein Multi-Tenant-Risk-View** (Single-User-MVP, ADR-0004).
- **Keine Notifications.**

## Definition of Done

### Datei-Existenz

- [ ] `app/services/risk_engine.py` existiert mit `pretriage()`, `RiskBand`, `ActionRequired`, `ACTION_REQUIRED_MAP`, `RISK_BAND_SORT_RANK`.
- [ ] `app/services/severity_resolver.py` existiert mit `severity_for()` und `max_severity_across_providers()`.
- [ ] `app/templates/_partials/host_snapshot.html` existiert.
- [ ] `app/templates/_partials/risk_band_pill.html` existiert.
- [ ] `app/templates/_partials/action_required_card.html` existiert.
- [ ] Neue Alembic-Migration mit 4 `create_table` + 7 `add_column` + 2 `create_index` existiert.
- [ ] Datei `app/services/exposure_matcher.py` und `app/data/package_exposure_map.json` existieren **nicht** (bewusst, gehört nicht in diesen Block).
- [ ] `docs/decisions/0022-risk-based-prioritization.md` Status „Akzeptiert".
- [ ] `CHANGELOG.md` enthält v0.8.0-Eintrag mit allen vier Bausteinen.

### Statische Checks

- [ ] `ruff check . && ruff format --check . && mypy app/` → exit 0.
- [ ] `shellcheck agent/*.sh` → exit 0.
- [ ] `pytest -v --cov=app --cov-fail-under=85` → exit 0.
- [ ] `pytest tests/services/test_risk_engine_pretriage.py -v` → ≥ 25 Tests grün.
- [ ] `pytest tests/adversarial/ -v` → alle grün, mindestens 6 neue Cases.
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` → exit 0.

### Build und Image

- [ ] `docker build -t secscan:latest .` → exit 0.
- [ ] Image-Size < 200 MB (Delta vs. v0.7.0 < 1 MB; Engine ist reines Python).
- [ ] `docker compose up -d --build` → alle Container healthy.
- [ ] `curl -fsSL http://localhost:8000/healthz` → 200.

### Visueller Smoke

- [ ] Dashboard zeigt zwei Action-Required-Cards prominent, sieben Risk-Band-Pills, Severity-Strip kompakt.
- [ ] Server-Detail zeigt Action-Required-Pill im Header, „Host snapshot"-Sektion direkt darunter.
- [ ] Findings-Tabelle gruppiert nach `risk_band` mit Section-Headern, default-expanded ab `pending`.
- [ ] Bulk-Ack-Noise-Modal mit Liste der zu-acked Findings.

### E2E-Manual

- [ ] Test-Host mit Agent 0.3.0 scannt durch: Server-Detail zeigt vollständigen Host-Snapshot, Findings haben Risk-Bands.
- [ ] Test-Host mit ausschließlich LOW-Severity-Findings → alle landen in `noise`-Band, Action-Required-Pill ist grün.
- [ ] Test-Host mit einem HIGH-NVD-Finding aber LOW-Vendor-Severity → Finding landet in `pending` (max-over-providers).
- [ ] Test-Host mit KEV-gelistetem MEDIUM-CVE → Finding landet in `pending` (KEV-Override).
- [ ] Test-Host mit alter Agent 0.2.0: alle Findings landen in `unknown`-Band, Pill „Update agent" im Header sichtbar.
- [ ] Bulk-Ack-Noise auf einem Server mit 50 noise-Findings: Modal-Bestätigung, alle 50 acked.
- [ ] Bulk-Ack-Noise-Modal verweigert IDs aus `pending`/`monitor`/`act`/etc.
- [ ] Dashboard-Action-Needed-Counter passt zur Beispiel-Flotte.

### State-Update

- [ ] `docs/blocks/STATE.md` Block O unter „Completed" mit Datum, Test-Anzahl, Coverage, Branch.
- [ ] Tag `v0.8.0` gesetzt nach Reviewer- und Security-Auditor-Freigabe.

## Risiken und Mitigation

- **Pre-Triage klassifiziert ein wirklich kritisches Finding als `noise`/`monitor`.** Mitigation: defensive Cuts (User-Wille), Tabellen-Tests decken alle Severity-EPSS-KEV-Kombinationen ab. False-Positives (zu viel pending) sind harmlos — LLM klärt im Block-P-Pass.
- **Snapshot-Daten enthalten sensitive Cmdlines** (z.B. `mysql -u root -psecret123`). Mitigation: README-Hinweis an Operator. Keine automatische Redaction im MVP. Auditor-Punkt 7.
- **Trivys `VendorSeverity` nicht in jeder DB-Version.** Mitigation: Fallback-Chain im Resolver (Status quo).
- **Snapshot-Truncate+Insert in einer großen Transaktion** könnte bei großen Flotten kurzzeitige Locks erzeugen. Mitigation: pro Server, nicht global; bei typisch < 10K Rows pro Server unkritisch.
- **Ingest-Latenz steigt** durch Pre-Triage-Schleife. Mitigation: Bench-Test < 100 ms für 10K Findings; deterministisch, kein I/O.
- **UI-Layout-Bruch durch zu viele neue Elemente.** Mitigation: visueller Smoke gegen Mockup-Anhang (falls vorhanden); bei Drift: Refinement-ADR.
- **Operator versucht Bulk-Ack-Noise auf einem `pending`-Cluster.** Mitigation: Modal-Text macht klar „nur `noise`-Findings"; Server-Side-Filter blockt; Adversarial-Test.
- **EPSS/KEV-DB-Update zwischen Scans landet nicht in den Bändern.** Mitigation: Re-Open-Trigger dokumentiert.
- **Severity-Resolver bei Server ohne `os_family`.** Mitigation: defensive Default auf NVD.
- **Snapshot-Parse-Fehler trotz Agent 0.3.0.** Mitigation: try/except im Ingest, Snapshot verworfen, Findings-Ingest läuft trotzdem, Pre-Triage mit `snapshot_available=False` → `unknown`.
- **Pre-Triage überschreibt LLM-gesetzte Bands.** Mitigation: harter Check auf `risk_band_source == 'llm'` im Ingest-Caller. Adversarial-Test.
- **`severity_by_provider` JSONB-Spalte ist nicht-indexierbar mit B-Tree.** Mitigation: Pre-Triage liest die Spalte pro Finding zur Eval-Zeit, kein WHERE-Filter darauf nötig. Wenn doch: GIN-Index in Re-Open-Trigger.

## Reihenfolge

Phase A (Enums, Schema, Migration) → Phase B (Resolver, Pre-Triage-Engine) → Phase C (Ingest-Integration) → Phase D (UI) → Phase E (Agent) → Phase F (Spec-Updates) → Phase G (Tests Sammelphase) → Phase H (Reviewer + Security-Auditor + Release).

Innerhalb von Phase A: Tasks #1/#2/#3 parallel.

Innerhalb von Phase B: Task #4 (Severity-Resolver) parallel zu #5 (Vendor-Status-Mapper). Task #6 (Pre-Triage-Engine) braucht #4 + Phase-A-Enums.

Phase C wartet auf Phase A + B. Tasks #7 + #8 sequentiell.

Phase D kann parallel zu Phase C laufen ab Phase-A-Schema-Verfügbarkeit. Tasks #9/#10/#11/#12 parallel.

Phase E (Task #13, Agent) unabhängig — parallel zu allem ab Phase-A.

Phase F nach allen anderen.

Phase G ist Sammelphase.

Phase H ist Reviewer/Security-Auditor/Release.

## Implementer-Brief (für `Agent`-Delegation)

Empfohlene Aufteilung:

1. **`backend-implementer`** Phase A (Tasks #1–#3): Enums, Migration, Envelope-Schema. Liest ADR-0022 §Risk-Band-Modell + §Host-Snapshot-Datenmodell + §Finding-Schema-Erweiterung, `app/models.py` `Server`/`Finding`, `app/schemas/scan_envelope.py` komplett. Branch-LOC-Delta: ~+400.

2. **`backend-implementer`** Phase B (Tasks #4–#6): Severity-Resolver + Vendor-Status + Pre-Triage-Engine. Liest ADR-0022 §Pre-Triage-Algorithmus + §CVSS-Vendor-Resolver + §vendor_status. Branch-LOC-Delta: ~+300.

3. **`backend-implementer`** Phase C (Tasks #7–#8): Snapshot-Persist + Pre-Triage-Aufruf im Ingest. Liest ADR-0022 §Re-Evaluation, `app/api/scans.py` komplett, Block-C-Brief Audit-Pattern. Branch-LOC-Delta: ~+200.

4. **`frontend-implementer`** Phase D (Tasks #9–#12): Dashboard-KPI-Umbau + Filter-Bar + Findings-Tabelle + Server-Detail-Header + Snapshot-Sektion + Bulk-Ack-Modal. Liest ADR-0022 §UI-Redesign komplett, Block-M-Brief KPI-Cards + Filter-Bar + Findings-Section, Block-K-Brief Header-Pills + Findings-Tabellen-Grouping. Branch-LOC-Delta: ~+600.

5. **`backend-implementer`** Phase E (Task #13): Agent-Snapshot-Sammlung. Liest ADR-0022 §Host-Snapshot, `agent/secscan-agent.sh` komplett, Block-N-Brief Task #9. Branch-LOC-Delta: ~+150.

6. **`backend-implementer`** Phase F (Tasks #14–#15): Spec-Updates. Liest ARCHITECTURE.md §6, §7, §11, §15, §17 komplett.

7. **`test-writer`** Phase G (Tasks #16–#17): Test-Sammelphase. Adversarial-Tests neu.

8. **`reviewer`** Phase H mit DoD-Checkliste oben.

9. **`security-auditor`** Phase H mit Audit-Punkten oben.

Bestehende Blöcke außerhalb des Scopes:

- LLM-Chat-Stack (Block G, ADR-0010) bleibt unangetastet. Block P wird die Service-Schicht nutzen.
- Notifications bleiben out-of-scope.
- Block-N-Code (Installer, Output-Strip, Ursachen-Felder) bleibt unangetastet — Block O baut nicht direkt auf den Ursachen-Feldern auf, sondern fügt parallel weitere Spalten am `Finding` hinzu.

## Roll-Back-Plan

Block O führt eine substantielle Migration ein (4 neue Tabellen + 7 Finding-Spalten + 1 Server-Spalte + 2 Indizes) plus Agent-Version-Bump 0.2.0 → 0.3.0. Roll-Back-Szenarien:

1. **Pre-Triage-Bug entdeckt nach Release.** Hotfix in `app/services/risk_engine.py` als v0.8.1. Migration bleibt. Worst-Case: DB-Update setzt alle `risk_band`-Spalten auf NULL, UI zeigt „pending evaluation", nächster Scan re-evaluiert.

2. **UI-Layout-Bruch.** Revert der Template-Dateien. Engine + DB bleiben — Findings haben weiterhin `risk_band`-Werte, alte UI ignoriert sie. v0.6.0-/v0.7.0-Verhalten ist Default-Zustand.

3. **Snapshot-Sammlung produziert nicht-parsebaren Output.** Agent-Hotfix v0.3.1. Backend ist resilient — `host_state`-Parse-Fehler führt zu Snapshot-Drop, Findings-Ingest läuft.

4. **Komplett-Roll-Back nötig.** Branch verwerfen oder Revert-PR. `alembic downgrade -1` entfernt alle Block-O-Spalten/Tabellen ohne Datenverlust. Agent 0.3.0 sendet `host_state`, bei v0.7.0-Backend wegen `extra="ignore"` ignoriert.

5. **Live-System läuft auf v0.7.0 weiter** falls Block O verworfen wird; alle Operator-Workflows aus Block A-N bleiben funktional. UI ist Block-M-Layout (KPI-Cards mit Sparklines, CVSS-zentrisch).
