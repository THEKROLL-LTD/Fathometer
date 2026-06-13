# ADR-0062 — Host-Agent meldet host-applizierbare Update-Verfügbarkeit pro Finding

**Status:** Akzeptiert · **Datum:** 2026-06-12

Bezug: [ADR-0061](0061-fix-ownership-lang-pkgs-upstream-lane.md) (Fix-Ownership / `upstream`-Lane — diese ADR verfeinert die Lane-Zuordnung mit einem autoritativen Host-Flag), [ADR-0021](0021-agent-bootstrap-installer.md) (Agent-Bootstrap + Host-Introspektion), [ADR-0003](0003-push-not-pull.md) (Push statt Pull, keine Server-Credentials), [ADR-0042](0042-agent-fire-and-forget-ingest.md) (Agent fire-and-forget), [ADR-0022](0022-risk-based-prioritization.md) (Host-Snapshot-Schema + Agent-Version-Gate).

## Kontext

ADR-0061 klassifiziert lang-pkgs-Fixes deterministisch als `upstream` (nicht host-applizierbar). Das ist konservativ korrekt, aber **pauschal**: es übersieht den Fall, in dem das lang-pkgs-Finding zu einem Binary gehört, das sehr wohl von einem OS-Paket **besessen** wird, für das ein Repo-Update bereitsteht. Beispiel: Tailscale liefert ein neues `tailscale`-rpm, gebaut mit gepatchtem Go — dann ist der stdlib-Fix sehr wohl per `dnf upgrade tailscale` applizierbar, obwohl Trivy ihn als lang-pkgs meldet.

Die einzige **autoritative** Quelle dafür, ob ein host-applizierbares Update existiert, ist der Host selbst — nicht das Internet (das Upstream-Release sagt nichts über die konfigurierten Repos *dieses* Hosts) und nicht das LLM (kennt den Paketstatus nicht). Der Agent läuft bereits auf dem Host und sammelt Host-Introspektion (os/kernel/arch, Listener, systemd-Services, kernel_modules — ADR-0022, Block X). Paketauflösung ist dieselbe Kategorie Arbeit, kein neues Sammel-Feld.

## Entscheidung

Der Agent löst pro Finding-Binary das **besitzende OS-Paket** auf und meldet einen deterministischen, lokal ermittelten Flag **`host_update_available`**.

### Auflösung (eng geschnitten)

- **Binary → Paket:** `rpm -qf <path>` (deckt dnf/yum/zypper — alle rpm-Distros) bzw. `dpkg -S <path>` (apt). Zwei Familien decken die unterstützten Distros (README: Debian/Ubuntu, RHEL-Familie, SUSE).
- **Update-Verfügbarkeit:** `dnf check-update <pkg>` / `apt-get -s upgrade` (Simulation, kein State-Change) → Boolean „neuere Version im aktuell konfigurierten Repo verfügbar".

### Bewusst NICHT im Scope des Agents

- **Kein Distro-Upgrade-/EOL-Reasoning.** Der Agent beantwortet ausschließlich „mit den **aktuell konfigurierten Repos** dieses Hosts: neuere Version ja/nein". Er räsoniert nicht „wenn du RHEL 8→9 hebst, gäb's einen Fix" — das ist unzuverlässig und gehört zu [ADR-0063](0063-agentic-upstream-update-search.md) bzw. zum Operator. Der EOL-/zu-alt-Fall fällt korrekt als `host_update_available=false` heraus.
- **Keine Paketmanager-Aktion.** Nur Simulation/Query, nie `upgrade`/`install`. Read-only.
- **Kein State-Change am Host** (ADR-0003-Geist: der Agent meldet, ändert nichts).

### Datenfluss

`host_update_available` (plus optional `owning_package` und `available_version` für die UI) wird pro Finding im Scan-Envelope mitgeschickt und persistiert (neue nullable Finding-Felder; `NULL` = Agent zu alt / nicht aufgelöst). Die Lane-Ableitung aus ADR-0061 wird verfeinert:

| `finding_class` | `has_fix` | `host_update_available` | `fix_lane` |
|---|---|---|---|
| os-pkgs | true | (egal) | `patch` |
| lang-pkgs | true | **true** | **`patch`** |
| lang-pkgs | true | false / NULL | `upstream` |
| any | false | — | `mitigate` |

Ein lang-pkgs-Finding mit bestätigtem Host-Update wird also wieder `patch` (host-applizierbar) — präzise statt pauschal. `NULL` (Agent ohne Capability) bleibt konservativ `upstream` (ADR-0061-Default).

### Versionierung / Forward-Compat

Agent-Version-Gate wie beim Host-Snapshot (ADR-0022 „update agent to ≥ x.y.z"). Alte Agenten liefern das Feld nicht → `NULL` → ADR-0061-Verhalten. Kein Hard-Break. Pydantic `extra="ignore"` (CLAUDE.md Forward-Compat-Konvention) trägt das neue Envelope-Feld.

## Begründung

- **Autoritative, lokale, air-gap-sichere Quelle.** Der Host kennt seine Repos; das ist die einzige verlässliche Antwort auf „kann ich das per Paketmanager patchen?". Kein Outbound, kein LLM, deterministisch und cachebar.
- **Eng geschnitten:** zwei Resolver-Kommandos (rpm/dpkg, +apk falls je nötig), zwei Check-Update-Kommandos, ein Boolean. Kein „N Paketmanager"-Wildwuchs.
- **Promotet ADR-0061 von pauschal zu präzise:** „Apply app update" erscheint nur noch, wenn `dnf`/`apt` wirklich etwas hätte.

## Konsequenzen

- Agent-Skript: Paket-Resolver + Check-Update-Probe, gebündelt pro Paket (Dedup über Binary-Pfade), read-only, Timeout-gekapselt. shellcheck-sauber.
- Envelope-Schema (`scan_envelope.py`): neue optionale Felder; `extra="ignore"` hält Forward-Compat.
- Finding-Schema: nullable `host_update_available` (+ optional `owning_package`/`available_version`), Migration. `alembic downgrade -1 && upgrade head` grün.
- Lane-Ableitung (`fix_lane_for` aus ADR-0061) bekommt den Flag als dritten Input; der SQL-Spiegel zieht das Feld mit.
- UI: „host update ready: `<pkg> <version>`" auf der patch-Card, wenn aus lang-pkgs promotet.
- Tests (nur erlaubte Gates): Resolver-Output-Parsing (rpm/dpkg/dnf/apt-Ausgaben als String-Fixtures), Lane-Ableitung mit Flag-Matrix, `NULL`-Fallback. Agent-Shell-Logik per shellcheck; **keine** neuen `.bats`-/Live-Paketmanager-Tests ohne explizite User-Genehmigung (CLAUDE.md Test-Konvention).
- ARCHITECTURE.md Agent-/Envelope-/Datenmodell-Sektionen nachziehen.

## Re-Open-Trigger

- Alpine/apk-Hosts sind laut README unsupported; falls sie dazukommen, apk-Resolver (`apk info --who-owns`) ergänzen.
- Manifest-verwaltete lang-pkgs (operator-gebumpte `requirements.txt`/`package-lock.json` im eigenen Deploy) sind Host-Scan-Scope-fremd (ARCHITECTURE §17, keine Code-Repo-Scans) — bei Bedarf eigene ADR.
- Performance: viele Findings × `check-update` könnte den Scan verlängern → ein einziger `dnf check-update`-Aufruf, dessen Ergebnis im Agent gegen die Paketliste gejoint wird, statt pro Finding zu proben.
