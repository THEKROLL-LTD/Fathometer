# Block N — Agent-Bootstrap-Installer + Output-Strip + Ursachen-Felder pro Finding

**Typ:** Feature + Backend + UI · **Branch-Vorschlag:** `feat/block-n-agent-installer` · **Zielversion:** v0.7.0 · **Vorgänger:** Block M (v0.6.0, ADR-0020) · **Spec:** [ADR-0021](../decisions/0021-agent-bootstrap-installer.md)

## Ziel

Vier zusammenhängende Teile:

1. **Bootstrap-Installer.** Operator-Standardpfad für Agent-Installation wird zu einem einzigen Befehl: `curl -fsSL https://secscan.example.com/install.sh | sudo bash`. Backend hostet einen interaktiven Wizard-Installer, sechs sichtbare Phasen, englischsprachige TTY-UI mit Box-Borders/Farben/Status-Symbolen. Master-Key wird im Lauf interaktiv (silent) abgefragt — kein Argv. Kein Auto-Update.

2. **Veraltet-Indikatoren.** Backend kennt aus dem Envelope `agent_version` und neu `trivy_version` und zeigt in der Server-Detail-Header-Pill-Reihe sowie in der Sidebar-Server-Liste „veraltet"-Indikatoren wenn unter Mindestversion oder Trivy-DB älter als 7 Tage.

3. **Agent-side Trivy-Output-Strip.** Agent strippt `Results[].Packages` per `jq` vor dem Envelope-Build. Erwarteter Win: raw 4.95 MB → 400-700 KB; gzipped 560 KB → 100-200 KB. Fallback auf ungestripped bei `jq`-Fehler.

4. **Ursachen-Felder pro Finding.** Schema-Erweiterung um `package_purl`, `target_path`, `result_type`, `severity_source`, `vendor_ids`. UI zeigt pro Finding eine Sub-Zeile mit der **Ursache** (Distro-Paket-Beschreibung für `os-pkgs`, Datei-Pfad + Library-Type für `lang-pkgs`). **Kein** statisches Update-Befehl-Mapping — LLM-basierte Fix-Empfehlung ist eigener späterer Block.

Hintergrund und Begründung: siehe ADR-0021.

## Vorbereitung — zu lesende Sektionen

- [ADR-0021](../decisions/0021-agent-bootstrap-installer.md) (komplett)
- `ARCHITECTURE.md` §6 (Wrapper-Envelope-Schema, wird in diesem Block erweitert)
- `ARCHITECTURE.md` §11 (Client-Agent, wird in diesem Block erweitert)
- `ARCHITECTURE.md` §9 (Sicherheits-Hardening, PUBLIC_PATHS-Pattern)
- `ARCHITECTURE.md` §17 (Out-of-Scope, neuen Block prüfen — Installer ist nicht out-of-scope, aber Container-Scans und Multi-Arch bleiben es)
- `agent/secscan-agent.sh` (Bestand komplett)
- `agent/secscan-register.sh` (Bestand komplett)
- `app/api/scans.py` (Ingest-Pfad — Envelope-Parse)
- `app/schemas/scan_envelope.py` (Docstring komplett — Erkenntnisse aus den Fixtures, die jetzt teilweise revidiert werden)
- `app/services/findings_ingest.py` Sektionen `_disambiguated_package_name` und der Vuln→Finding-Mapper (`_extract_*`-Helpers, falls vorhanden)
- `app/models.py` `class Finding` und seine `__table_args__`
- `app/__init__.py` Blueprint-Registrierung + PUBLIC_PATHS-Allowlist
- `app/templates/servers/detail.html` (Block K Header-Pill-Reihe)
- `app/templates/servers/_findings_section.html` und `app/templates/dashboard/_findings_section.html` (Block K und M Tabellen-Rendering — die zweite Sub-Zeile pro Row wird in diesem Block umgebaut)
- `tests/fixtures/trivy/ubuntu-22.04-rke2.json` und `tests/fixtures/trivy/adversarial.json` (Echtdaten-Referenz für die neuen Felder)
- ADR-0003 (Push statt Pull — bleibt unverändert, hier nur Kontext)
- ADR-0006 (Keine Pflicht-Kommentare — Modal-Dialoge im Pill-Tooltip bleiben kommentar-frei)
- ADR-0011 (`package_name@target`-Disambiguation — wird durch diesen Block teilweise abgelöst; Übergangsformat in der Re-Ingest-Phase respektieren)

Subagent-Aufrufe nennen die Sektionen explizit.

## Aufgaben

### Phase A — Backend-Services, Schemas, Migration

#### Task #1 — Settings-Konstanten ergänzen (`backend-implementer`)

`app/config.py` (oder die zentrale Settings-Klasse):

- `MIN_AGENT_VERSION: str = "0.1.0"` — niedrigste Agent-Version, die das Backend noch akzeptiert.
- `CURRENT_AGENT_VERSION: str = "0.2.0"` — Version, die der Installer als „aktuell" ausliefert (matched `AGENT_VERSION` in `secscan-agent.sh`).
- `MIN_TRIVY_VERSION: str = "0.70.0"` — niedrigste Trivy-Version, die als „nicht veraltet" gilt (Quelle: ARCHITECTURE §11 Mindestversion für vollständige EPSS-/KEV-/Attack-Vector-Felder).
- `RECOMMENDED_TRIVY_VERSION: str = "0.71.0"` — Version, die der Installer als pinned Binary herunterlädt **und** auf die der Agent-Lauf eine managed Trivy-Binary hebt (`auto_update_trivy`, TICKET-015). Wird beim Bump im selben Commit aktualisiert.
- `TRIVY_RELEASE_URL_TEMPLATE: str = "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-{arch}.tar.gz"`
- `TRIVY_DB_STALE_THRESHOLD_DAYS: int = 7` — Schwelle für „Trivy-DB veraltet"-Pill.

Werte sind Code-Konstanten, keine User-Settings. Begründung in ADR-0021 (Selbstabschaltungs-Falle vermeiden).

**DoD:**

- `mypy --strict` PASS.
- Unit-Test in `tests/config/test_agent_constants.py`: Konstanten sind gesetzt und plausibel (`version_lt(MIN_AGENT_VERSION, CURRENT_AGENT_VERSION)` ist True, `MIN_TRIVY_VERSION <= RECOMMENDED_TRIVY_VERSION`).

#### Task #2 — Semver-Vergleich-Helper (`backend-implementer`)

Neue Datei `app/services/agent_version.py`:

```python
from datetime import datetime, timedelta, timezone
from packaging.version import InvalidVersion, Version

from app.config import settings
from app.models.server import Server


def version_lt(a: str | None, b: str | None) -> bool:
    """True wenn a < b im Semver-Sinne. None oder ungültige Strings gelten als
    'unbekannt' und damit als 'veraltet' (returns True wenn a None/invalid und b
    set, False sonst). Bewusste Heuristik: unbekannte Agent-Versionen sind
    konservativ als 'update required' markiert."""
    if b is None:
        return False  # ohne Referenz keine Vergleichbarkeit
    if a is None:
        return True
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return True


def is_agent_outdated(server: Server) -> bool:
    return version_lt(server.agent_version, settings.MIN_AGENT_VERSION)


def is_trivy_outdated(server: Server) -> bool:
    return version_lt(server.trivy_version, settings.MIN_TRIVY_VERSION)


def is_trivy_db_outdated(server: Server, *, now: datetime | None = None) -> bool:
    if server.trivy_db_updated_at is None:
        return True
    now = now or datetime.now(timezone.utc)
    threshold = timedelta(days=settings.TRIVY_DB_STALE_THRESHOLD_DAYS)
    return (now - server.trivy_db_updated_at) > threshold
```

`packaging` ist transitive Dependency von `pip` und in den meisten Python-Setups schon da; explizit nach `pyproject.toml` ergänzen.

**DoD:**

- Unit-Tests in `tests/services/test_agent_version.py`:
  - `version_lt("0.1.0", "0.2.0") is True`
  - `version_lt("0.2.0", "0.1.0") is False`
  - `version_lt("0.10.0", "0.9.0") is False` (10 > 9 numerisch)
  - `version_lt(None, "0.1.0") is True`
  - `version_lt("0.1.0", None) is False`
  - `version_lt("nonsense", "0.1.0") is True`
  - `is_trivy_db_outdated` mit `trivy_db_updated_at=None` → True
  - `is_trivy_db_outdated` mit `trivy_db_updated_at=now-3d` → False
  - `is_trivy_db_outdated` mit `trivy_db_updated_at=now-10d` → True
- `mypy --strict` PASS.

#### Task #3 — DB-Migration: Server- + Finding-Spalten (`backend-implementer`)

`app/models.py` `class Server`: drei neue Spalten ergänzen:

```python
agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
trivy_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
agent_version_seen_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True), nullable=True
)
```

`app/models.py` `class Finding`: fünf neue Spalten ergänzen:

```python
package_purl: Mapped[str | None] = mapped_column(String(512), nullable=True)
target_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
result_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
severity_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
vendor_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String(128)), nullable=True)
```

UNIQUE-Constraint `uq_findings_natural_key` bleibt unverändert — `package_name` mit `@target`-Suffix für lang-pkgs reicht weiterhin. Keine neuen Indizes im Block (Performance-Hot-Paths sind Block-K/M-Indizes; `package_purl`/`target_path` als Filter-Dimensionen sind out-of-scope).

Alembic-Migration (`alembic revision -m "block_n_agent_and_finding_cause"`):

- `op.add_column('servers', sa.Column('agent_version', sa.String(32), nullable=True))`
- `op.add_column('servers', sa.Column('trivy_version', sa.String(32), nullable=True))`
- `op.add_column('servers', sa.Column('agent_version_seen_at', sa.DateTime(timezone=True), nullable=True))`
- `op.add_column('findings', sa.Column('package_purl', sa.String(512), nullable=True))`
- `op.add_column('findings', sa.Column('target_path', sa.String(512), nullable=True))`
- `op.add_column('findings', sa.Column('result_type', sa.String(64), nullable=True))`
- `op.add_column('findings', sa.Column('severity_source', sa.String(64), nullable=True))`
- `op.add_column('findings', sa.Column('vendor_ids', postgresql.ARRAY(sa.String(128)), nullable=True))`
- `downgrade`: acht `op.drop_column` in umgekehrter Reihenfolge.

Atomare Single-Migration für beide Tabellen — sauberer Roll-Back. Kein Backfill: bestehende Findings ziehen sich beim nächsten Scan via UPSERT auf Re-Ingest selbst nach.

**DoD:**

- `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` PASS.
- DB-Schema-Smoke-Test in `tests/migrations/test_block_n_columns.py`: prüft Existenz und Nullability der acht Spalten (3 Server + 5 Finding).
- `mypy --strict` PASS.

#### Task #4 — Envelope-Schema: `trivy_version` und Ursachen-Felder (`backend-implementer`)

`app/schemas/scan_envelope.py`:

- `HostBlock` um `trivy_version: str | None = None` ergänzen mit `_no_nul_bytes` + `_PRINTABLE_ASCII_RE`-Validator, max_length=64.
- Neues Sub-Modell `TrivyPkgIdentifier(BaseModel)` mit `purl: str | None = None` (alias `PURL`, max_length=512, NUL-frei, ASCII-only) und `uid: str | None = None` (alias `UID`, max_length=64). `model_config = ConfigDict(extra="ignore", populate_by_name=True)`.
- `TrivyVulnerability` um drei neue Felder ergänzen:
  - `pkg_identifier: TrivyPkgIdentifier | None = None` (alias `PkgIdentifier`).
  - `severity_source: str | None = None` (alias `SeveritySource`, max_length=64, ASCII-only via `_validate_ascii_field`).
  - `vendor_ids: list[str] | None = None` (alias `VendorIDs`). Validator analog `cwe_ids`/`references`: defensives Trim, **kein** `max_length` am Field. Reject pro Item bei NUL/non-ASCII/len>128; Cap auf `MAX_VENDOR_IDS_PER_VULN = 32`.
- Convenience-Property `package_purl` auf `TrivyVulnerability`:
  ```python
  @property
  def package_purl(self) -> str | None:
      return self.pkg_identifier.purl if self.pkg_identifier else None
  ```
- `model_config = ConfigDict(extra="ignore")` bleibt überall — Forward-Compat unverändert.
- Docstring oben im File aktualisieren: Hinweis dass `PkgIdentifier`/`SeveritySource`/`VendorIDs` jetzt extrahiert und persistiert werden (Revision der „Wir mappen nur die relevanten ab"-Aussage).

`app/api/scans.py` Ingest (Schema-Teil — Persistierung der Finding-Spalten kommt in Task #4b):

- Nach erfolgreichem Parse: `server.agent_version = envelope.agent_version`, `server.trivy_version = envelope.host.trivy_version`, `server.agent_version_seen_at = datetime.now(timezone.utc)`. Gleichzeitiger Commit mit dem `Scan`-Insert (gleicher Transaction-Boundary).
- Wenn `version_lt(envelope.agent_version, settings.MIN_AGENT_VERSION)`: 400 Response mit Body `{"error": "agent version <X> is below minimum <Y>, please update"}` und logge `audit_event("agent.rejected_outdated", server_id=...)`. **Wichtig:** Auth-Check und Body-Parse-Reihenfolge aus Block C bleibt erhalten — 401 vor 400.

**DoD:**

- Unit-Tests in `tests/api/test_scans_envelope_trivy_version.py`:
  - Envelope mit `host.trivy_version="0.70.0"` → Server-Feld gesetzt nach Ingest.
  - Envelope ohne `host.trivy_version` → Server-Feld bleibt None, Ingest erfolgreich (Forward-Compat).
  - Envelope mit `agent_version="0.0.5"` und `MIN_AGENT_VERSION="0.1.0"` → 400, Audit-Event geschrieben.
  - Envelope mit `agent_version="0.2.0"` (>= MIN) → 202 wie bisher.
- Unit-Tests in `tests/schemas/test_envelope_cause_fields.py`:
  - `TrivyVulnerability` mit `PkgIdentifier={"PURL":"pkg:deb/ubuntu/openssl@...","UID":"abc"}` → `package_purl`-Property gibt die PURL zurück.
  - `PkgIdentifier=None` → `package_purl == None`.
  - `VendorIDs` mit 50 Einträgen → getrimmt auf 32 (`MAX_VENDOR_IDS_PER_VULN`).
  - `VendorIDs` mit NUL-Byte-Item → Item still verworfen, andere bleiben.
  - `SeveritySource` mit non-ASCII → Validation-Fehler (Vuln wird vom Ingest-Service verworfen, ganzer Scan überlebt).
  - PURL mit 1024 Chars → Reject (max_length=512).
- `mypy --strict` PASS.

#### Task #4b — Finding-Persistenz: Ursachen-Felder schreiben (`backend-implementer`)

`app/services/findings_ingest.py`:

- Neuer interner Helper `_extract_cause_fields(vuln: TrivyVulnerability, result: TrivyResult) -> dict`:
  ```python
  return {
      "package_purl":   vuln.package_purl,
      "target_path":    result.target,
      "result_type":    result.type_,
      "severity_source": vuln.severity_source,
      "vendor_ids":     vuln.vendor_ids,
  }
  ```
- `_disambiguated_package_name()` aus ADR-0011 bleibt **unverändert** — `package_name` enthält weiterhin `pkg_name@/path` für lang-pkgs während der Übergangsphase. Der zusätzliche `target_path`-Wert ist redundante Information, aber das ist Absicht (Re-Ingest-Konsolidierung).
- Im Insert/Update-Pfad (UPSERT auf `uq_findings_natural_key`): die fünf neuen Spalten werden bei jedem Re-Ingest geschrieben — sodass alte Findings beim nächsten Scan automatisch die neuen Werte bekommen.
- Bei Update-Pfad: wenn `vuln.severity_source` jetzt `None` ist und vorher gesetzt war (z.B. Agent strippt oder Trivy DB-Update hat das Feld weggelassen), wird die Spalte auf `NULL` gesetzt. Bewusst — wir bewahren keinen historischen Wert auf, weil der aktuelle Scan die Quelle der Wahrheit ist.

**DoD:**

- Unit-Tests in `tests/services/test_findings_ingest_cause_mapping.py`:
  - Trivy-Result-Fixture mit `Class="os-pkgs"`, `Type="ubuntu"`, `Target="rke2-sv-0 (ubuntu 22.04)"` und Vuln mit `PkgIdentifier.PURL="pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?..."` → Finding hat alle fünf Felder korrekt gesetzt, `package_name="openssl"` (unverändert ADR-0011 für os-pkgs).
  - Trivy-Result mit `Class="lang-pkgs"`, `Type="gobinary"`, `Target="usr/local/bin/kubelet"` und Vuln `golang.org/x/net` → Finding hat `target_path="usr/local/bin/kubelet"`, `result_type="gobinary"`, `package_name="golang.org/x/net@usr/local/bin/kubelet"` (ADR-0011-Übergangsformat).
  - Re-Ingest mit identischen Werten → UPSERT, kein Duplikat, kein `IntegrityError`.
  - Re-Ingest mit jetzt fehlenden `SeveritySource` (Field None) auf einem Finding, das vorher `"nvd"` hatte → Spalte wird auf NULL gesetzt.
- `mypy --strict` PASS.

#### Task #4c — Trivy-Fixtures erweitern (`test-writer`)

`tests/fixtures/trivy/`:

- Bestehende `ubuntu-22.04-rke2.json`: prüfen ob `PkgIdentifier`/`SeveritySource`/`VendorIDs` real drin sind (laut Schema-Docstring sind sie observed). Falls eine Fixture diese Felder nicht hat, eine kleine zusätzliche Fixture `lang-pkgs-gobinary.json` anlegen mit einem realistischen `Result.Type="gobinary"`, `Result.Target="usr/local/bin/kubelet"` und einer Vuln mit allen drei neuen Feldern. ≤ 20 Zeilen JSON, reine Test-Fixture.
- Bestehende `adversarial.json` erweitern um zwei Cases: `_attack=15: PURL with <script>`, `_attack=16: VendorIDs with NUL byte`.

**DoD:**

- Fixtures liegen unter `tests/fixtures/trivy/`.
- Bestehende Parse-Tests bleiben grün (zusätzliche Felder werden via `extra="ignore"` toleriert).

#### Task #5 — `/agent/version`-Endpoint (`backend-implementer`)

Neue Datei `app/views/agent_install.py`:

```python
from flask import Blueprint, jsonify, current_app, Response, abort, send_from_directory
from app.config import settings

agent_install_bp = Blueprint("agent_install", __name__)


@agent_install_bp.route("/agent/version", methods=["GET"])
def agent_version():
    return jsonify({
        "current_agent_version": settings.CURRENT_AGENT_VERSION,
        "min_agent_version": settings.MIN_AGENT_VERSION,
        "recommended_trivy_version": settings.RECOMMENDED_TRIVY_VERSION,
        "min_trivy_version": settings.MIN_TRIVY_VERSION,
        "trivy_release_url_template": settings.TRIVY_RELEASE_URL_TEMPLATE,
    })
```

`app/__init__.py`: `app.register_blueprint(agent_install_bp)`, `/agent/version` in die PUBLIC_PATHS-Allowlist.

**DoD:**

- View-Test in `tests/views/test_agent_install.py`: `GET /agent/version` ohne Auth → 200 mit erwartetem JSON-Shape.

#### Task #6 — `/agent/files/<name>`-Endpoint (`backend-implementer`)

`app/views/agent_install.py` ergänzen:

```python
_AGENT_FILE_WHITELIST = {"secscan-agent.sh", "secscan-register.sh"}

@agent_install_bp.route("/agent/files/<name>", methods=["GET"])
def agent_file(name: str):
    if name not in _AGENT_FILE_WHITELIST:
        abort(404)
    agent_dir = current_app.config["AGENT_FILES_DIR"]  # /opt/secscan/agent oder repo-relativ
    return send_from_directory(
        agent_dir, name,
        mimetype="text/x-shellscript",
        max_age=300,  # 5min Browser-Cache
    )
```

`AGENT_FILES_DIR` in `app/__init__.py` setzen: dev = `Path(__file__).parent.parent / "agent"`, prod = `/app/agent` (Docker-Image hat das in Block A schon kopiert — falls nicht: Dockerfile-Patch in diesem Block).

PUBLIC_PATHS-Allowlist um `/agent/files/` (prefix) erweitern.

**DoD:**

- View-Tests:
  - `GET /agent/files/secscan-agent.sh` → 200, Content-Type `text/x-shellscript`, Body enthält `AGENT_VERSION=`.
  - `GET /agent/files/secscan-register.sh` → 200, Body enthält `# secscan-register.sh`.
  - `GET /agent/files/install.sh` → 404 (Whitelist hard).
  - `GET /agent/files/../../etc/passwd` → 404 (Whitelist hard, `send_from_directory` schützt zusätzlich).
- Adversarial: `tests/adversarial/test_agent_files_path_traversal.py` — fünf Pfad-Traversal-Patterns alle → 404.

#### Task #7 — `/install.sh`-Endpoint mit Jinja-Template (`backend-implementer`)

`app/views/agent_install.py` ergänzen:

```python
from flask import render_template

@agent_install_bp.route("/install.sh", methods=["GET"])
def install_sh():
    rendered = render_template(
        "agent/install.sh.j2",
        secscan_url=current_app.config["EXTERNAL_BASE_URL"],
        recommended_trivy_version=settings.RECOMMENDED_TRIVY_VERSION,
        min_trivy_version=settings.MIN_TRIVY_VERSION,
        trivy_release_url_template=settings.TRIVY_RELEASE_URL_TEMPLATE,
        current_agent_version=settings.CURRENT_AGENT_VERSION,
    )
    response = Response(rendered, mimetype="text/x-shellscript")
    response.headers["Cache-Control"] = "public, max-age=300"
    return response
```

`EXTERNAL_BASE_URL` ist die per Setup-Wizard (Block B) konfigurierte öffentliche URL. PUBLIC_PATHS-Allowlist um `/install.sh` erweitern.

`app/templates/agent/install.sh.j2` neu (siehe Task #8).

**DoD:**

- View-Test in `tests/views/test_agent_install.py`:
  - `GET /install.sh` → 200, Content-Type `text/x-shellscript`.
  - Body beginnt mit `#!/usr/bin/env bash`.
  - Body enthält `{{ secscan_url }}` als gerenderten String (nicht als Template-Marker).
  - Body enthält `RECOMMENDED_TRIVY_VERSION=` mit dem korrekten Wert.

#### Task #8 — Installer-Template (`backend-implementer` oder `frontend-implementer` — Mischrolle, Bash + Backend-Render)

`app/templates/agent/install.sh.j2`. Skelett (Auszug — vollständige Implementierung siehe Block-N-Implementer-Brief unten):

```bash
#!/usr/bin/env bash
#
# secscan-agent bootstrap installer
# Generated at backend render time. Do not edit on the host.
#
# Usage (recommended):
#   curl -fsSL {{ secscan_url }}/install.sh | sudo bash
#
# Or, to keep stdin attached to your terminal:
#   sudo bash <(curl -fsSL {{ secscan_url }}/install.sh)
#
# Unattended mode (CI/Provisioning):
#   SECSCAN_UNATTENDED=1 SECSCAN_MASTER_KEY=... SECSCAN_SERVER_NAME=host01 \
#     sudo -E bash <(curl -fsSL {{ secscan_url }}/install.sh)
#

set -euo pipefail

readonly SECSCAN_URL="{{ secscan_url }}"
readonly RECOMMENDED_TRIVY_VERSION="{{ recommended_trivy_version }}"
readonly MIN_TRIVY_VERSION="{{ min_trivy_version }}"
readonly CURRENT_AGENT_VERSION="{{ current_agent_version }}"
readonly TRIVY_RELEASE_URL_TEMPLATE="{{ trivy_release_url_template }}"

# --- TTY handling ---------------------------------------------------------
# When invoked via `curl | bash`, stdin is the pipe. We read prompts from
# /dev/tty explicitly so the wizard still works.
if [[ -t 0 ]]; then
  TTY_INPUT=/dev/stdin
elif [[ -r /dev/tty ]]; then
  TTY_INPUT=/dev/tty
else
  # No TTY at all → force unattended mode.
  : "${SECSCAN_UNATTENDED:=1}"
fi
readonly TTY_INPUT
readonly UNATTENDED="${SECSCAN_UNATTENDED:-0}"

# --- Output helpers (Box + colors) ---------------------------------------
# Detect color support; respect NO_COLOR (https://no-color.org/).
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'; C_DIM=$'\e[2m'; C_BOLD=$'\e[1m'
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_FAIL=$'\e[31m'; C_INFO=$'\e[36m'
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_OK=""; C_WARN=""; C_FAIL=""; C_INFO=""
fi

phase() {
  local n="$1" total="$2" title="$3"
  printf "\n${C_BOLD}[%s/%s] %s${C_RESET}\n" "$n" "$total" "$title"
}
ok()   { printf "  ${C_OK}[ok]${C_RESET}   %s\n" "$*"; }
info() { printf "  ${C_INFO}[..]${C_RESET}   %s\n" "$*"; }
warn() { printf "  ${C_WARN}[!! ]${C_RESET}  %s\n" "$*" >&2; }
fail() { printf "  ${C_FAIL}[fail]${C_RESET} %s\n" "$*" >&2; }

box_header() {
  local title="$1" subtitle="$2"
  local width=64
  printf "${C_BOLD}"
  printf "╔"; printf '═%.0s' $(seq 1 $((width-2))); printf "╗\n"
  printf "║%*s║\n" $((width-2)) ""
  printf "║%*s%s%*s║\n" $(((width-2-${#title})/2)) "" "$title" $(((width-2-${#title}+1)/2)) ""
  printf "║%*s%s%*s║\n" $(((width-2-${#subtitle})/2)) "" "$subtitle" $(((width-2-${#subtitle}+1)/2)) ""
  printf "║%*s║\n" $((width-2)) ""
  printf "╚"; printf '═%.0s' $(seq 1 $((width-2))); printf "╝\n"
  printf "${C_RESET}"
}

ask() {
  local prompt="$1" default="${2:-}" silent="${3:-0}" answer=""
  if [[ "$UNATTENDED" == "1" ]]; then
    echo "$default"; return
  fi
  local p="$prompt"
  [[ -n "$default" ]] && p="$p [$default]"
  if [[ "$silent" == "1" ]]; then
    read -rsp "  $p: " answer < "$TTY_INPUT"
    echo >&2
  else
    read -rp  "  $p: " answer < "$TTY_INPUT"
  fi
  echo "${answer:-$default}"
}

# ... (Phasen 1-6: System detection, Dependencies, Trivy, Registration,
#      Scheduler, Probe scan — siehe ADR-0021 für Detail-Verhalten pro Phase)

box_header "secscan-agent installer" "Backend: $SECSCAN_URL"

phase 1 6 "System detection"
# ... os-release parse, systemd check, arch detect ...

phase 2 6 "Dependencies"
# ... curl/jq/gzip check + install via apt/dnf/yum/zypper ...

phase 3 6 "Trivy"
# ... command -v trivy, version compare, optional pinned install ...

phase 4 6 "Server registration"
# ... ask name/interval/master-key, call /opt/secscan/bin/secscan-register.sh,
#     write /etc/secscan/agent.env (mode 0600) ...

phase 5 6 "Scheduler"
# ... systemd unit + timer OR cron fallback ...

phase 6 6 "Probe scan"
# ... run /opt/secscan/bin/secscan-agent.sh synchronously,
#     stderr passthrough so user sees trivy output ...

printf "\n${C_OK}${C_BOLD}Done.${C_RESET} View server: %s/servers/%s\n" "$SECSCAN_URL" "$SERVER_ID"
```

Erwartete File-Größe: 400-500 Zeilen Bash. Sektions-Kommentare am Anfang jeder Phase, damit der Operator das Skript vor `bash` lesen kann (`curl -fsSL .../install.sh | less`).

**Wichtig:** Alle `read`-Calls gehen über die `ask()`-Funktion → liest aus `$TTY_INPUT` (`/dev/tty` im Pipe-Modus, `/dev/stdin` sonst). Niemals direktes `read -p` ohne Redirect — sonst hängt der Wizard im `curl | bash`-Fall.

**DoD:**

- `shellcheck` über das Template läuft mit nur den dokumentierten Warning-Suppressions (`SC1091` für `. /etc/os-release`).
- Manueller Smoke: `curl -fsSL http://localhost:8000/install.sh | head -100` zeigt rendered Bash-Header mit eingebackener URL.
- View-Test in `tests/views/test_agent_install_render.py`: gerendertes Skript enthält alle sechs `phase X 6` Marker, beginnt mit `#!/usr/bin/env bash`, hat `set -euo pipefail`, hat `< "$TTY_INPUT"` mindestens einmal pro Prompt-Aufruf.

#### Task #9 — Agent-Skript: Version-Bump + `trivy_version` + Output-Strip (`backend-implementer`)

`agent/secscan-agent.sh`:

- `readonly AGENT_VERSION="0.2.0"` (von `0.1.0`).
- Neue Zeile nach Host-Info-Sammlung:
  ```bash
  trivy_version="$("$TRIVY_BIN" --version 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")"
  ```
- **Trivy-Scan-Aufruf um Strip-Pipeline erweitern.** Statt Trivy direkt nach `$trivy_out` zu schreiben:
  ```bash
  trivy_raw="$(mktemp -t secscan-trivy-raw.XXXXXX.json)"
  trap 'rm -f "$trivy_raw" "$trivy_out" "$response_body"' EXIT

  if ! "$TRIVY_BIN" rootfs "$SCAN_PATH" \
         --format json --quiet --scanners vuln \
         --output "$trivy_raw"; then
    log "Error: trivy scan failed"
    exit 2
  fi

  if jq 'del(.Results[].Packages)' "$trivy_raw" > "$trivy_out" 2>/dev/null; then
    log "Stripped Packages[] block from trivy output ($(stat -c%s "$trivy_raw") -> $(stat -c%s "$trivy_out") bytes)"
  else
    log "Warning: jq strip failed, sending raw trivy output"
    cp "$trivy_raw" "$trivy_out"
  fi
  ```
  Fallback-Pfad ist absichtlich tolerant — wenn `jq` aus irgendeinem Grund (alte Version, unerwartetes Trivy-Schema) den Filter nicht anwenden kann, wird der ungestrippte Output gesendet. Backend verarbeitet beides identisch.
- jq-Aufruf für Envelope erweitern um `trivy_version`:
  ```bash
  payload="$(jq -n \
    --arg agent_version "$AGENT_VERSION" \
    --arg os_family     "$os_family" \
    ...
    --arg trivy_ver     "$trivy_version" \
    --slurpfile scan    "$trivy_out" \
    '{
      agent_version: $agent_version,
      host: {
        os_family:      $os_family,
        ...
        trivy_version:  $trivy_ver
      },
      scan: $scan[0]
    }')"
  ```
- User-Strings (Header-Kommentare + `log` calls) von Deutsch auf Englisch normalisieren.
- Exit-Codes unverändert (0/1/2/3).
- Header-Kommentar dokumentiert: `trivy_version` ist neu in 0.2.0, Output-Strip ist neu in 0.2.0; ältere Backends verarbeiten beides via `extra="ignore"` ohne Bruch.

**DoD:**

- `shellcheck agent/secscan-agent.sh` PASS.
- Bash-Unit-Test `tests/services/test_agent_strip.py` (Python ruft Bash via `subprocess` auf): füttert eine Real-Fixture in den Strip-Pfad, vergleicht Vuln-Counts vor/nach (müssen identisch sein), prüft dass Bytes-Größe nach Strip < 40% der Original-Größe ist.
- Manueller Smoke gegen ein Test-Backend: Envelope-Body enthält `host.trivy_version` und keine `Results[].Packages` mehr (`jq '.scan.Results[0] | has("Packages")'` muss `false` zurückgeben).

#### Task #10 — Register-Skript Strings auf Englisch (`backend-implementer`)

`agent/secscan-register.sh`:

- Header-Kommentare und alle `log` calls auf Englisch normalisieren (Server-Antwort-Texte bleiben unverändert, kommen ja vom Backend).
- Exit-Codes unverändert.
- Aufruf-Hinweis aktualisiert: erwähnt zusätzlich `curl -fsSL .../install.sh | sudo bash` als bevorzugten Standardpfad.

**DoD:**

- `shellcheck agent/secscan-register.sh` PASS.

### Phase B — UI-Indikatoren

#### Task #11 — Pills im Server-Detail-Header (`frontend-implementer`)

`app/templates/servers/detail.html` Header-Pill-Reihe erweitern. Drei neue Pills, jede conditional:

```jinja
{% if is_agent_outdated(server) %}
  <span class="badge badge-error tooltip"
        data-tip="Agent {{ server.agent_version or 'unknown' }} is below minimum {{ min_agent_version }}. Run: curl -fsSL {{ external_base_url }}/install.sh | sudo bash"
        data-test="pill-agent-outdated">
    ⚠ agent {{ server.agent_version or '?' }}
  </span>
{% endif %}

{% if is_trivy_outdated(server) %}
  <span class="badge badge-warning tooltip"
        data-tip="Trivy {{ server.trivy_version or 'unknown' }} is below minimum {{ min_trivy_version }}. Re-run installer to update."
        data-test="pill-trivy-outdated">
    ⚠ trivy {{ server.trivy_version or '?' }}
  </span>
{% endif %}

{% if is_trivy_db_outdated(server) %}
  <span class="badge badge-warning tooltip"
        data-tip="Trivy DB last updated {{ server.trivy_db_updated_at | humanize_delta }} ago. Threshold: {{ trivy_db_stale_threshold_days }} days."
        data-test="pill-trivy-db-stale">
    ⚠ trivy-db stale
  </span>
{% endif %}
```

Context-Funktionen (`is_agent_outdated` etc.) via Jinja-Globals oder Context-Processor (`@app.context_processor`) registrieren — analog `_inject_sidebar_context` aus Block I.

**DoD:**

- View-Test in `tests/views/test_server_detail_outdated_pills.py`:
  - Server mit `agent_version="0.0.5"`, `MIN_AGENT_VERSION="0.1.0"` → Agent-Pill sichtbar.
  - Server mit `agent_version="0.2.0"` → keine Agent-Pill.
  - Server mit `trivy_version=None` → Trivy-Pill sichtbar.
  - Server mit `trivy_db_updated_at = now - 10d` → DB-Pill sichtbar.
  - Server mit `trivy_db_updated_at = now - 3d` → keine DB-Pill.

#### Task #12 — Sidebar-Sub-Marker pro Server (`frontend-implementer`)

`app/templates/_partials/sidebar.html` (oder wo die Sidebar-Server-Liste rendert; aus Block I bekannt): pro Server-Eintrag ein kleiner Marker rechts neben dem Namen, falls einer der drei Indikatoren greift:

```jinja
{% if is_agent_outdated(server) or is_trivy_outdated(server) or is_trivy_db_outdated(server) %}
  <span class="text-warning text-xs tooltip"
        data-tip="Update required — see server detail"
        data-test="sidebar-marker-outdated-{{ server.id }}">
    ⚠
  </span>
{% endif %}
```

Polling-Wrapper aus Block L (10-s-Reload der Sidebar-Server-Liste) sorgt automatisch dafür, dass die Marker nach einem erfolgreichen Update-Scan verschwinden.

**DoD:**

- View-Test in `tests/views/test_sidebar_outdated_marker.py`: Marker erscheint/verschwindet je nach Server-Zustand.

#### Task #12a — Ursachen-Zeile pro Finding in der Tabelle (`frontend-implementer`)

Neuer Helper `app/services/finding_display.py`:

```python
_DISTRO_TYPES = frozenset({
    "ubuntu", "debian", "rhel", "centos", "rocky", "alma",
    "fedora", "amazon", "alpine",
    "opensuse-leap", "opensuse-tumbleweed", "sles", "oracle",
})


def format_finding_cause(f: Finding) -> dict:
    """Returns rendering hints for the cause sub-row.

    Output:
      {
        "kind": "os" | "lang" | "unknown",
        "type_label": "ubuntu"  |  "gobinary"  |  "" ,
        "path": "/usr/local/bin/kubelet" | None,
        "vendor_ids": ["USN-6543-1", ...] | [],
        "purl": "pkg:deb/..." | None,
        "severity_source": "nvd" | None,
      }
    """
    rt = f.result_type
    kind = "os" if rt in _DISTRO_TYPES else ("lang" if rt else "unknown")

    # Fallback fuer Alt-Daten ohne target_path: aus package_name das @-Suffix
    # extrahieren (ADR-0011-Format).
    path = f.target_path
    if path is None and kind == "lang" and "@" in f.package_name:
        _, _, suffix = f.package_name.partition("@")
        path = suffix or None

    return {
        "kind": kind,
        "type_label": rt or "",
        "path": path,
        "vendor_ids": f.vendor_ids or [],
        "purl": f.package_purl,
        "severity_source": f.severity_source,
    }
```

Helper via `@app.context_processor` als Jinja-Global registrieren.

Templates `app/templates/servers/_findings_section.html` und `app/templates/dashboard/_findings_section.html` — Paket-Spalte-Sub-Zeile rendert die Ursache:

```jinja
{% set cause = format_finding_cause(finding) %}
<div class="text-xs opacity-70 mt-0.5">
  {% if cause.kind == "lang" %}
    <span class="badge badge-ghost badge-xs uppercase tracking-wider">{{ cause.type_label }}</span>
    {% if cause.path %}
      <span class="font-mono">in /{{ cause.path | trim('/') }}</span>
    {% endif %}
  {% elif cause.kind == "os" %}
    <span class="badge badge-ghost badge-xs uppercase tracking-wider">{{ cause.type_label }}</span>
    {% if finding.installed_version %}
      <span>{{ finding.installed_version }}</span>
    {% endif %}
    {% for vid in cause.vendor_ids[:3] %}
      <span class="badge badge-outline badge-xs" data-test="finding-vendor-id">{{ vid }}</span>
    {% endfor %}
  {% endif %}
</div>
{% if cause.purl or cause.severity_source %}
  <div class="hidden" data-test="finding-row-tooltip-data"
       data-purl="{{ cause.purl or '' }}"
       data-severity-source="{{ cause.severity_source or '' }}"></div>
{% endif %}
```

Tooltip-Mechanik: ein kleines Alpine-/DaisyUI-Tooltip auf der Row, das `data-purl` und `data-severity-source` zeigt. Implementer wählt zwischen DaisyUI-`tooltip`-Class und einem leichten `x-tooltip`-Pattern; das Markup-Pattern oben ist eine Vorlage, kein Pflicht-Stand.

**Bewusst weggelassen** (gehört zum „LLM-Update-Empfehlung"-Folge-Block):
- Kein `update_command`-Helper.
- Keine "Fix:"-Zeile in der Tabelle.
- Kein `apt-get install`-Snippet, kein Copy-Button.

**DoD:**

- View-Test in `tests/views/test_findings_section_cause_row.py`:
  - Finding mit `result_type="ubuntu"`, `installed_version="3.0.2-0ubuntu1.10"`, `vendor_ids=["USN-6543-1"]` → Sub-Zeile enthält `ubuntu`-Pill, Version-String, `USN-6543-1`-Pill.
  - Finding mit `result_type="gobinary"`, `target_path="usr/local/bin/kubelet"` → Sub-Zeile enthält `gobinary`-Pill und `/usr/local/bin/kubelet` in Mono-Font.
  - Finding mit `result_type=NULL` und `package_name="github.com/foo/bar@/opt/app/binary"` (Alt-Daten) → Fallback-Split aus `package_name`, Sub-Zeile zeigt `/opt/app/binary`.
  - Finding mit `package_purl="pkg:deb/..."` → `data-purl` Attribut im Markup für Tooltip.
- Helper-Unit-Test in `tests/services/test_finding_display.py`:
  - `format_finding_cause()` mit allen drei `kind`-Pfaden + Fallback-Split.
- Visueller Smoke: Dashboard- und Server-Detail-Findings-Tabelle zeigen die neue Sub-Zeile für mindestens einen real-Fixture-Finding.

### Phase C — ARCHITECTURE-Spec-Update

#### Task #13 — ARCHITECTURE.md §11 erweitern (`backend-implementer`)

§11 umschreiben:

- Installer-Flow als **Standardpfad**:
  ```
  curl -fsSL https://secscan.example.com/install.sh | sudo bash
  ```
- Sechs-Phasen-Wizard kurz beschreiben (Verweis auf ADR-0021 für Details).
- Power-User-Pfad (manuelles Klonen + `secscan-register.sh`) bleibt erwähnt als Alternative für Ansible/Salt.
- Forward-Compat-Absatz präzisieren: heutiger Text spricht nur von Server-400. Ergänzen: „Zusätzlich zeigt das Backend pro Server in der UI eine Status-Pill `agent veraltet` / `trivy veraltet` / `trivy-db stale`, sobald die im Envelope gemeldete Version unter den im Settings-Code gepflegten Mindest-Werten liegt. Operator erkennt den Update-Bedarf, ohne dass ein Scan vorher fehlschlagen muss."
- Neue Subsektion „Backend-hosted bootstrap installer": kurze Beschreibung der drei Endpoints (`/install.sh`, `/agent/files/<name>`, `/agent/version`), Auth-Status (public), Inhalts-Beschreibung.

#### Task #14 — ARCHITECTURE.md §6 erweitern (`backend-implementer`)

`host.trivy_version` im Envelope-Schema-Beispiel ergänzen, Hinweis dass das Feld optional ist (Forward-Compat).

#### Task #15 — ADR-Index aktualisieren (`backend-implementer`)

`docs/decisions/README.md` Index-Tabelle: ADR-0021 ergänzen mit Status „Akzeptiert" nach Reviewer-Freigabe.

### Phase D — Tests

#### Task #16 — Service- und View-Unit-Tests

Siehe Tasks #2, #4, #5, #6, #7, #8, #11, #12 — jeder Task hat dort genannte Cases. Sammelplan:

- `tests/services/test_agent_version.py` (≈8 Cases)
- `tests/api/test_scans_envelope_trivy_version.py` (≈4 Cases)
- `tests/views/test_agent_install.py` (≈8 Cases — `/install.sh`, `/agent/files/*`, `/agent/version`, 404-Pfade)
- `tests/views/test_agent_install_render.py` (≈3 Cases — Rendered-Body-Sanity)
- `tests/views/test_server_detail_outdated_pills.py` (≈6 Cases)
- `tests/views/test_sidebar_outdated_marker.py` (≈3 Cases)
- `tests/config/test_agent_constants.py` (≈3 Cases — Settings-Plausibilität)
- `tests/migrations/test_block_n_columns.py` (≈3 Cases — Spalten-Existenz)

#### Task #17 — Adversarial-Tests

- `tests/adversarial/test_agent_files_path_traversal.py` — fünf Pfad-Patterns (`../`, `..\`, `%2e%2e/`, absolute Pfade, Null-Bytes) → 404.
- `tests/adversarial/test_install_sh_no_secrets.py` — `GET /install.sh` Body enthält keine Master-Key-Patterns, keine API-Key-Patterns, kein `SECSCAN_MASTER_KEY=` mit Wert.
- `tests/adversarial/test_outdated_agent_rejected.py` — POST /api/scans mit `agent_version="0.0.1"` → 400 mit klarem Error-Body, Audit-Event `agent.rejected_outdated`.
- `tests/adversarial/test_agent_version_endpoint_no_auth.py` — `/agent/version` ohne Cookie → 200 (PUBLIC), nicht 302.

#### Task #18 — Installer-Integrationstests in Docker (`test-writer`)

Zwei neue Dockerfiles unter `tests/integration/installer/`:

- `Dockerfile.ubuntu-24.04` — minimaler Ubuntu-Container mit `bash`, `curl`, `sudo`.
- `Dockerfile.almalinux-9` — minimaler AlmaLinux-Container mit `bash`, `curl`, `sudo`, `systemd` (für Timer-Test).

Test-Skript `tests/integration/installer/run.sh`:

1. Mock-Backend hochfahren (Python-Flask-Stub auf `127.0.0.1:8080` der `/api/register`/`/api/scans` mit fixen Responses bedient).
2. `docker run --rm <image> bash -c "curl -fsSL http://host.docker.internal:8000/install.sh | SECSCAN_UNATTENDED=1 SECSCAN_MASTER_KEY=test SECSCAN_SERVER_NAME=test-host SECSCAN_INSTALL_TRIVY=yes bash"`.
3. Assertions im Container nach Lauf:
   - `/etc/secscan/agent.env` existiert mit mode 0600.
   - `/etc/systemd/system/secscan-agent.timer` existiert (Ubuntu) bzw. `/etc/cron.d/secscan-agent` (kein-systemd-Variante).
   - `/opt/secscan/bin/trivy --version` returns 0.
   - Mock-Backend-Log zeigt `/api/register` + `/api/scans` Requests.

Diese Tests stehen unter `@pytest.mark.integration` und sind aus der Default-Suite ausgeschlossen (`pytest -m "not integration"`). Laufen über separate Make-Target `make test-installer` oder eigenen CI-Job. Erlauben dem Reviewer, den Installer ohne manuellen VM-Setup zu validieren.

**DoD:**

- `make test-installer` läuft lokal grün (Voraussetzung: Docker daemon).
- Beide Distros (Ubuntu 24.04, AlmaLinux 9) durchlaufen alle sechs Phasen.

### Phase E — Reviewer + Security-Auditor + Release

#### Task #19 — DoD-Checks (`reviewer`)

```
ruff check . && ruff format --check .
mypy app/
shellcheck agent/*.sh
pytest -v --cov=app --cov-fail-under=85
pytest tests/adversarial/ -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build && curl -fsSL http://localhost:8000/healthz
curl -fsSL http://localhost:8000/install.sh | head -50  # visueller Smoke
make test-installer  # optional, wenn Docker verfügbar
```

Plus Screenshot der Server-Detail-Pills + Sidebar-Marker unter `docs/blocks/N-evidence/`:
- `pills-agent-outdated.png`
- `pills-trivy-db-stale.png`
- `sidebar-marker.png`
- `installer-wizard-phase-3.png` (Terminal-Screenshot vom Wizard-Lauf in einer VM)

#### Task #20 — Security-Auditor (`security-auditor`)

Pflicht für Block N, weil drei neue PUBLIC-Endpoints und ein neues UI-Surface, das Update-Befehle anzeigt (XSS-Vektor falls Tooltip-Text aus User-Daten käme — tut er hier nicht, aber explizit prüfen).

Audit-Punkte:

1. **`/install.sh` enthält keine Geheimnisse.** Body grep über Master-Key-Patterns, API-Key-Patterns, DB-URL-Patterns, LLM-Key-Patterns — alle leer.
2. **`/agent/files/<name>` ist Path-Traversal-sicher.** Whitelist-Check + `send_from_directory`-Sicherheit verifiziert.
3. **PUBLIC_PATHS-Allowlist ist minimal.** Nur die drei neuen Routen plus die existierenden — kein Wildcard.
4. **Pill-Tooltip-Text ist nicht XSS-anfällig.** `data-tip` rendert via DaisyUI als Plain-Text (kein HTML); zusätzlich autoescape standardmäßig aktiv. Keine `|safe` auf Server-Daten.
5. **Envelope mit zu altem `agent_version` wird abgelehnt** und nicht stillschweigend akzeptiert. Audit-Event `agent.rejected_outdated` ist geschrieben.
6. **`SECSCAN_API_KEY` im `agent.env`-File.** Installer schreibt es mit `chmod 0600 root:root`. Mode-Bit-Test in `tests/integration/installer/`.
7. **Trivy-Binary-Download verifiziert SHA256.** Installer-Code prüft `sha256sum -c` gegen das `*.sha256`-File desselben GitHub-Releases.
8. **Master-Key niemals in Argv, History, oder Files.** Installer liest via `read -srp`, sendet als JSON-Body an `/api/register`, schreibt nichts auf Disk außer dem zurückgegebenen API-Key.

#### Task #21 — Spec- und State-Updates (`reviewer`)

- ARCHITECTURE.md §6 + §11 aktualisiert (Tasks #13, #14).
- `docs/decisions/README.md` ADR-0021 ergänzt (Task #15).
- `docs/decisions/0021-agent-bootstrap-installer.md` Status auf „Akzeptiert" (von „Draft").
- `docs/blocks/STATE.md`: Block N unter „Completed" mit Datum, Branch, Test-Anzahl, Coverage.
- `CHANGELOG.md`: v0.7.0-Eintrag mit:
  - Neuer Bootstrap-Installer `curl -fsSL .../install.sh | sudo bash`.
  - Agent-Version-Bump 0.1.0 → 0.2.0 (neues optionales Envelope-Feld `host.trivy_version`).
  - DB-Migration mit drei neuen Server-Spalten.
  - UI-Pills für veraltete Agents / Trivy / Trivy-DB.
  - Englischsprachige User-Strings in `agent/*.sh` (Breaking für Operator, der die Skript-Outputs gegrept hat — unwahrscheinlich, dokumentiert).

#### Task #22 — Tag `v0.7.0`

Nach Reviewer- und Security-Auditor-Freigabe und allen DoD-Checks grün:

```
git tag -a v0.7.0 -m "Block N — Agent-Bootstrap-Installer + Veraltet-Indikatoren (ADR-0021)"
git push --tags
```

## Was NICHT in diesem Block

- Kein Auto-Update-Mechanismus (Operator führt den Einzeiler manuell nochmal aus).
- Kein Container-Agent (anti-pattern für `trivy rootfs /`).
- Kein Alpine/OpenRC-Support (User-Entscheidung).
- Kein DB-Prefetch (User-Entscheidung — erster echter Scan zieht die DB).
- Kein Aggregat-Counter „X agents outdated" auf dem Dashboard (Re-Open-Trigger).
- Keine Auth auf `/install.sh` (kein Geheimnis im Inhalt; Re-Open-Trigger falls Operator-Wunsch).
- Keine Distro-Pakete (.deb/.rpm) (Re-Open-Trigger).
- Keine Signatur auf den Bash-Files (Re-Open-Trigger für Sigstore/Cosign).
- Keine Multi-Arch über `linux/amd64` und `linux/arm64` hinaus (kein `armv7l`).
- Keine Settings-UI für `MIN_AGENT_VERSION` etc. — bewusst Code-Konstanten (Selbstabschaltungs-Falle).
- **Kein Update-Befehl-Mapping** (`apt-get`-/`dnf`-/`apk`-Snippets pro Finding). UI zeigt nur die **Ursache** (Distro-Paket vs. eingebettete Library, Pfad, Vendor-IDs), nicht **was zu tun ist**. Begründete LLM-basierte Fix-Empfehlung kommt als eigener Block nach v0.7.0 (Re-Open-Trigger ADR-0021).
- **Kein PURL-Parser** (`pkg:deb/...` als opaker String persistiert). Strukturierte Zerlegung erst wenn das LLM-Feature kommt oder Dashboard nach Distro-Familie filtern soll.
- **Kein VendorSeverity-Disagreement-Indikator** (Trivy liefert die Map, wir nutzen sie noch nicht — eigene ADR).
- **Keine UNIQUE-Constraint-Umstellung** auf `(package_name, target_path)`. ADR-0011-Übergangsformat bleibt während Re-Ingest-Phase aktiv; Constraint-Migration ist eigener späterer Block.
- **Keine Daten-Migration** für bestehende Findings. `target_path` und die anderen vier Cause-Spalten befüllen sich via natürlicher Re-Ingest, sobald aktive Server scannen. Stale/retire-Server bleiben mit `target_path=NULL` und Render-Fallback aus `package_name`-`@`-Split.

## Definition of Done

### Datei-Existenz

- [ ] `app/views/agent_install.py` existiert mit drei Routes
- [ ] `app/templates/agent/install.sh.j2` existiert
- [ ] `app/services/agent_version.py` existiert
- [ ] `app/services/finding_display.py` existiert mit `format_finding_cause()`
- [ ] Neue Alembic-Migration mit acht `add_column` (3 Server + 5 Finding) existiert
- [ ] `tests/integration/installer/Dockerfile.ubuntu-24.04` und `Dockerfile.almalinux-9` existieren
- [ ] `tests/fixtures/trivy/lang-pkgs-gobinary.json` existiert (oder Erweiterung der Bestands-Fixture)
- [ ] `docs/decisions/0021-agent-bootstrap-installer.md` Status „Akzeptiert"
- [ ] `CHANGELOG.md` enthält v0.7.0-Eintrag mit allen vier Teilen (Installer, Indikatoren, Strip, Ursachen-Felder)

### Statische Checks

- [ ] `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] `shellcheck agent/*.sh` → exit 0
- [ ] `pytest -v --cov=app --cov-fail-under=85` → exit 0
- [ ] `pytest tests/adversarial/ -v` → alle grün
- [ ] `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` → exit 0

### Build und Image

- [ ] `docker build -t secscan:latest .` → exit 0
- [ ] `docker images secscan:latest --format '{{.Size}}'` → < 200 MB (Delta vs. v0.6.0 < 1 MB)
- [ ] `docker compose up -d --build` → alle Container healthy
- [ ] `curl -fsSL http://localhost:8000/healthz` → 200
- [ ] `curl -fsSL http://localhost:8000/install.sh | head -20` zeigt rendered Bash mit eingebackener URL
- [ ] `curl -fsSL http://localhost:8000/agent/version` → JSON mit allen fünf erwarteten Keys
- [ ] `curl -fsSL http://localhost:8000/agent/files/secscan-agent.sh | grep AGENT_VERSION` → matched

### Visueller Smoke

- [ ] Server-Detail-View mit künstlich gesetztem `agent_version="0.0.1"` zeigt rote Agent-Pill.
- [ ] Sidebar-Server-Eintrag zeigt `⚠` Marker.
- [ ] Wizard-Lauf in Test-VM oder Docker-Container alle sechs Phasen erfolgreich.
- [ ] Screenshots unter `docs/blocks/N-evidence/`.

### E2E-Manual

- [ ] In einer Ubuntu-24.04-VM ohne Trivy: `curl -fsSL https://secscan.example.com/install.sh | sudo bash` läuft komplett durch, Server taucht im Dashboard auf.
- [ ] In einer AlmaLinux-9-VM mit vorhandener (alter) Trivy 0.50.0: Wizard erkennt veraltete Version, bietet Pinned-Install an, fragt nach Bestätigung.
- [ ] Re-Run desselben Einzeilers auf demselben Host erkennt vorhandene Registrierung, fragt „re-register?", überspringt Phase 4 bei No, scharfschaltet Timer erneut.
- [ ] `SECSCAN_UNATTENDED=1 SECSCAN_MASTER_KEY=... bash <(curl ...)` läuft ohne Prompt durch.
- [ ] Nach `agent_version`-Bump auf `0.2.0` und nächstem Scan-Run: rote Pill verschwindet im UI.
- [ ] Nach erstem Scan eines Hosts mit Agent v0.2.0: Findings-Tabelle zeigt für `os-pkgs`-Findings die Distro-Pill (`ubuntu`/`debian`/...) plus Vendor-IDs, für `lang-pkgs`-Findings den Library-Type-Pill (`gobinary`/...) plus Datei-Pfad.
- [ ] Server mit altem Agent (0.1.0): Findings haben kein `target_path`, UI fällt auf `@`-Split aus `package_name` zurück.
- [ ] Envelope-Größe-Check: `tcpdump`/`mitmproxy` auf einem v0.2.0-Agent-Run zeigt gzipped Body-Größe < 250 KB für eine 306-Vuln-Flotte (vs. ~560 KB vor Block N).

### State-Update

- [ ] `docs/blocks/STATE.md` Block N unter „Completed" mit Datum, Test-Anzahl, Coverage, Branch.
- [ ] Tag `v0.7.0` gesetzt nach Reviewer- und Security-Auditor-Freigabe.

## Risiken und Mitigation

- **Pipe-zu-bash blockiert auf `read`** weil stdin die Pipe ist. → Alle `read`-Calls über `ask()`-Helper, der von `/dev/tty` liest (Code-Pattern in Task #8).
- **Trivy-GitHub-Release-URL ändert sich** (Aqua ändert Asset-Naming). → URL-Template als Config-Konstante; Bei Bruch: Bump in einem Patch-Release (v0.7.1).
- **Cron-Fallback hat keinen Jitter** wie systemd `RandomizedDelaySec`. → `sleep $((RANDOM % 7200))` als Inline-Workaround in der `/etc/cron.d/secscan-agent`-Zeile. Mini-Test im Integration-Test verifiziert die Zeile.
- **`/install.sh` als Drive-by-Vektor** wenn ein Angreifer den DNS umbiegt. → Operator soll `curl -fsSL` *immer* gegen die ihm bekannte Backend-URL machen. Mitigation auf User-Ebene; Backend kann nichts dagegen tun. Dokumentiert in `README.md` und im Installer-Header-Kommentar.
- **Server-Detail-Pills produzieren viel visuelle Unruhe** wenn die Flotte gemischt ist. → Pills sind klein und farbcodiert; bei mehr als ~5 gleichzeitigen Pills sollten wir das Layout neu denken (Re-Open-Trigger).
- **Bestehende `agent_version=0.1.0`-Hosts werden nach dem Backend-Upgrade sofort als „veraltet" markiert**, obwohl sie funktional ok sind. → Bewusst — der Operator soll auf den neuen Installer-Flow migrieren. `MIN_AGENT_VERSION` bleibt aber bei `0.1.0`, der 400-Reject greift erst beim nächsten Bump. Pill ist „warnung", nicht „bricht".
- **`packaging.version.Version` ist in `pyproject.toml` nicht explizit gelistet**, könnte aber transitive Dependency sein. → Explizit ergänzen (`packaging>=24.0` in den deps).
- **Installer-Skript hat hohe Komplexität** (Distro-Detection × 4, Paketmanager × 4, systemd vs. cron, drei Trivy-Fälle). → Sechs Phasen visuell separiert, jede Phase < 80 Bash-Zeilen, gut testbar mit den zwei Integration-Tests.
- **Multi-Arch:** `aarch64`-Mapping zu Trivy-Release-Asset-Naming (`ARM64`) muss korrekt sein, sonst 404 beim Download. → Smoke-Test in Integration-Tests (optional dritter Dockerfile `Dockerfile.ubuntu-24.04-arm64`, nur wenn QEMU-Setup verfügbar).
- **Forward-Compat des Envelope-Schemas:** Wenn ein zukünftiger Agent ein neues Pflichtfeld einführt, müssen alle alten Agents als „veraltet" markiert werden, bevor der `MIN_AGENT_VERSION` gebumpt wird — sonst Service-Outage. → Operator-Workflow dokumentiert in `CHANGELOG.md` zu jedem Bump.
- **`jq 'del(.Results[].Packages)'` greift versehentlich auf `.Vulnerabilities`** durch Tippfehler/Refactor. → Bash-Unit-Test `tests/services/test_agent_strip.py` vergleicht Vuln-Counts vor/nach Strip auf Real-Fixture. CI-blocker.
- **PURL-Tooltip als XSS-Vektor:** Trivy-DB könnte theoretisch eine PURL mit `<script>` enthalten. → Pydantic-Validator akzeptiert nur ASCII, autoescape im Jinja-Template, Adversarial-Test `test_purl_xss.py`.
- **Vendor-IDs als XSS- oder Inhalt-Spoof-Vektor:** Distro-Advisory-IDs sind in der Praxis `[A-Z]{2,4}-\d+(-\d+)?`, aber Trivy validiert das nicht. → Pydantic-Validator droppt non-ASCII/NUL items; UI rendert Pills mit autoescape; Adversarial-Test.
- **Alt-Daten ohne `target_path` mischen sich mit Neu-Daten in der UI:** Operator könnte den Eindruck haben, manche lang-pkgs-Findings „verlieren" den Pfad. → `format_finding_cause()`-Fallback aus `package_name`-Split deckt Alt-Daten ab. Visueller Smoke-Test mit gemischten Datensatz im Phase-E-Reviewer-Schritt.
- **Trivy schreibt `PkgIdentifier` doch nicht zuverlässig pro Vuln in allen Versionen:** Schema-Docstring sagt „observed in real fixtures", aber ältere Trivy-Versionen könnten es nur in `Packages[]` schreiben — das wir strippen. → Vor Block-N-Start auf der jeweils ältesten unterstützten Trivy-Version (0.70.0) per Smoke-Test verifizieren. Falls negativ: Strip-Filter konditional auf Trivy ≥ 0.X.Y machen, oder PURL aus `Packages[]` extrahieren VOR dem Strip.
- **UNIQUE-Constraint-Reibung bei `target_path`-Konsolidierung:** wenn die spätere Constraint-Umstellung auf `(server_id, finding_type, identifier_key, package_name_clean, target_path)` kommt, müssen alle Findings konsolidiert sein. Block N legt nur die Datenbasis; die Constraint-Migration ist eigener Block. → Re-Open-Trigger in ADR-0021 dokumentiert.

## Reihenfolge

Phase A (Backend + Migration + Skripte) → Phase B (UI-Pills + Sidebar) → Phase C (Spec-Updates) → Phase D (Tests) → Phase E (Reviewer + Security-Auditor + Release).

Innerhalb von Phase A:
- Tasks #1, #2, #3 parallel (Settings, Helper, Migration sind unabhängig).
- Task #4 nach #3 (Envelope schreibt in die neuen Spalten).
- Tasks #5, #6, #7, #8 parallel (alle drei Endpoints + Template).
- Tasks #9, #10 parallel zu allem (Bash-Skript-Änderungen).

Innerhalb von Phase B:
- Tasks #11, #12 parallel.
- Beide brauchen Phase A Task #2 (Context-Funktionen).

Phase D wartet auf Phase A + B + C.

## Implementer-Brief (für `Agent`-Delegation)

Empfohlene Aufteilung:

1. **`backend-implementer`** mit Scope „Phase A Tasks #1–#4c + #5–#7 + #9–#10". Liest ADR-0021 komplett, ARCHITECTURE.md §6 + §11, `app/api/scans.py`, `app/schemas/scan_envelope.py` (Docstring + Modelle), `app/services/findings_ingest.py`, `app/models.py` (`Server` + `Finding`), `tests/fixtures/trivy/`. Erwartete Branch-LOC-Delta: +900 / -100.
2. **`backend-implementer`** (zweite Runde, Mischrolle) mit Scope „Phase A Task #8". Liest ADR-0021 §Installer-Verhalten + §Detail-Verhalten-pro-Phase, beide Bestands-Skripte `agent/*.sh`. Erwartete Branch-LOC-Delta: +500. **Kein** Frontend-Implementer hier — das Template ist Bash, nicht HTML/JS.
3. **`frontend-implementer`** mit Scope „Phase B Tasks #11–#12a". Liest ADR-0021 §UI-Indikatoren + §Ursachen-Felder-pro-Finding, Block-K-Brief Header-Pill-Reihe und Findings-Section, Block-I-Brief Sidebar-Server-Liste, Block-M-Brief Dashboard-Findings-Section.
4. **`backend-implementer`** (dritte Runde) mit Scope „Phase C Tasks #13–#15". Liest ARCHITECTURE.md §6 + §11 + §17 komplett.
5. **`test-writer`** mit Scope „Phase D Tasks #16–#18". Integration-Tests in Task #18 erfordern Docker-Verfügbarkeit. Bash-Unit-Test für den Agent-Strip kommt in den selben Lauf.
6. **`reviewer`** mit der DoD-Checkliste oben.
7. **`security-auditor`** mit Task #20-Scope.

Block-K-Code (`app/views/server_detail.py`, `app/templates/servers/detail.html`) wird nur in Header-Pill-Reihe minimal ergänzt — keine Layout-Änderung. Block-I-Code (Sidebar) wird nur um Sub-Marker pro Server-Eintrag ergänzt — keine Layout-Änderung. Block-L-Polling-Wrapper bleibt unangetastet. Block-M-Dashboard wird nicht angefasst.

LLM-Chat-Code, Bulk-Ack-Code, CSV-Export-Code bleiben außerhalb des Scopes.

## Roll-Back-Plan

Block N führt eine DB-Migration ein (acht nullable Spalten auf zwei Tabellen) und drei neue Public-Endpoints, plus eine Agent-Skript-Erweiterung. Roll-Back-Szenarien:

1. **Installer-Bug auf bestimmter Distro:** Operator nutzt den bestehenden Klone-Repo-Pfad weiter (ARCHITECTURE §11 alt). Kein DB-Roll-Back nötig.
2. **Envelope-Schema-Bug (z.B. `trivy_version` oder `PkgIdentifier` Parse-Fehler):** Hotfix in `app/schemas/scan_envelope.py` als v0.7.1. Migration bleibt — neue Spalten bleiben nullable und werden eben nicht befüllt.
3. **Strip-Bug (versehentlich `.Vulnerabilities` weggestrippt):** Agent-Hotfix v0.2.1 als emergency-Release. Backend ist nicht betroffen — `extra="ignore"` toleriert auch leere `Vulnerabilities`. Findings würden für den betroffenen Scan-Run still „resolved" (UPSERT-Pfad), beim nächsten korrekten Scan wieder auftauchen. Mitigation: Bash-Unit-Test in Task #9 ist CI-Pflicht.
4. **Komplett-Roll-Back nötig:** Branch verwerfen oder Revert-PR. `alembic downgrade -1` entfernt die acht Spalten ohne Datenverlust auf bestehenden Tabellen. Agent-Skripte 0.2.0 senden zusätzliche Felder und stripped Output, beides bei v0.6.0-Backend per `extra="ignore"` toleriert — Roll-Back ist symmetrisch.
5. **Live-System läuft auf v0.6.0 weiter** falls Block N verworfen wird; alle Operator-Workflows aus Block A-M bleiben funktional. Findings-UI rendert die Sub-Zeile nicht (Helper-Aufruf fehlt) oder fällt auf den alten `@`-Split aus `package_name` zurück.
