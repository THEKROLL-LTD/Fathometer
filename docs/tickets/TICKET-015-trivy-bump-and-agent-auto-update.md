# TICKET-015 — Trivy-Bump 0.70.0 → 0.71.0 + Trivy-Auto-Update im Agent-Lauf

**Status:** Umgesetzt (2026-06-11, security-auditor APPROVED) · **Datum:** 2026-06-11 · **Bezug:** ADR-0021 (Agent-Bootstrap + Versions-Modell), TICKET-001 (Agent-Selbst-Update `auto_update_self`), ADR-0049 (Uninstaller), `docs/operations.md` (Air-Gap / Outbound-URLs).
**Komponenten:** `app/config.py` (Versions-Konstanten), `agent/fathometer-agent.sh` (neuer Trivy-Update-Step + Version-Bump), ggf. `agent/lib_host_state.sh` (nur falls Helper-Reuse), `app/templates/agent/install.sh.j2` (nur Kommentar/Versionszeile), `CHANGELOG.md`, Tests (`tests/agent/test_auto_update.sh`, `tests/config/test_agent_constants.py`).
**Umfang:** Zwei Teile. Teil A trivial (Konstanten). Teil B neues **root-laufendes Binär-Replace** im Agent → **security-relevant**, `security-auditor` Pflicht in der DoD. Kein Backend-Schema, keine Migration.

## Teil A — Version-Bump 0.70.0 → 0.71.0

`app/config.py`:

- `RECOMMENDED_TRIVY_VERSION: ClassVar[str] = "0.71.0"` (war `"0.70.0"`).
- `MIN_TRIVY_VERSION` **bleibt `"0.70.0"`** (Empfehlung): 0.71.0 ist ein Minor-Release ohne erwartete Breaking-Changes am konsumierten Scan-/JSON-Schema. Ein MIN-Bump würde jeden Host auf 0.70.0 als „outdated" rot-pillen, obwohl die Daten-/Scan-Kompatibilität gegeben ist. Der Auto-Update (Teil B) zielt ohnehin auf **recommended**, hebt also 0.70.0-Hosts auf 0.71.0 — ohne sie vorher als hart-veraltet zu markieren. *(Falls der Operator 0.70.0 hart ausmustern will: MIN ebenfalls auf `"0.71.0"` — bewusste, separate Entscheidung.)*

`/agent/version` liefert die Konstanten bereits aus (`app/views/agent_install.py:54-67`) — kein Endpoint-Touch nötig. `install.sh.j2` rendert `recommended_trivy_version` dynamisch — kein Template-Touch außer ggf. einem Kommentar.

Header-Kommentar in `agent/fathometer-agent.sh` (`Requirements: … trivy (>= 0.70.0)`, Z. 42) und ARCHITECTURE.md/Doku-Verweise auf die Version nachziehen.

## Teil B — Trivy-Auto-Update im wiederkehrenden Agent-Lauf

### Heute

`fathometer-agent.sh` macht beim Lauf **kein** Trivy-Update: `auto_update_self` (Selbst-Update, Z. 127-219) existiert, danach nur `require_cmd "$TRIVY_BIN"` (Z. 241) + Version lesen (Z. 294). Der Backend zeigt zwar „trivy outdated"-Pills (ADR-0021 / `agent_version.py`), aber der Agent zieht nie nach.

### Ziel

Neuer Step `auto_update_trivy`, aufgerufen **nach** `auto_update_self` (also im bereits selbst-aktualisierten Skript) und **vor** dem Scan. Spiegelt die Mechanik von `auto_update_self` und wiederverwendet die in `install.sh.j2::download_pinned_trivy` bereits vetted Logik:

1. **Opt-out / Air-Gap-Guard.** Step no-op wenn `FM_TRIVY_AUTO_UPDATE=0` (Default an) **oder** `FM_URL` leer. Air-gapped Hosts ohne GitHub-Outbound setzen `FM_TRIVY_AUTO_UPDATE=0` in `agent.env`.
2. **Ziel-Version holen.** `recommended_trivy_version` aus `${FM_URL}/agent/version` (derselbe Call wie der Selbst-Update; ein gemeinsamer Fetch ist erlaubt). Server unerreichbar → fail-soft skip.
3. **Trigger.** Update nur wenn `version_lt "$installed_trivy_version" "$recommended"` (die bestehende `version_lt`-Funktion im Agent, Z. 78, parst major.minor.patch — `0.70.0 < 0.71.0` → true). Gleich oder neuer → skip.
4. **Nur fathometer-managed Binary anfassen.** Update **nur** wenn `$TRIVY_BIN` unter `/opt/fathometer/bin/` liegt (die vom Installer gepinnte Binary). Zeigt `FM_TRIVY_PATH` auf ein System-Trivy (z. B. `/usr/bin/trivy` aus apt), **nicht** ersetzen — nur `log`-Hinweis (sonst Kampf mit dem Paketmanager). Die UI-Pill deckt diesen Fall ab.
5. **Download + Verifikation (Port aus `download_pinned_trivy`).** Arch-Map `x86_64|amd64→64bit`, `aarch64|arm64→ARM64` (im Recurring-Agent heute nur roh `uname -m` für den Envelope — Mapping ergänzen). URL aus `trivy_release_url_template` (aus `/agent/version`); Tarball + `trivy_<v>_checksums.txt` laden; **SHA256 gegen den Checksum-Eintrag** prüfen; `tar -xzf … trivy` extrahieren.
6. **Atomar ersetzen, mit Backup.** `cp -p` der alten Binary auf `…/trivy.bak`, `install -m 0755 -o root -g root` der neuen, dann `"$TRIVY_BIN" --version` re-prüfen — meldet die neue Version nicht ≥ recommended, Rollback aus `.bak` und fail-soft weiter mit der alten.
7. **Fail-soft überall.** Jeder Fehler (Download, Checksum, tar fehlt, Replace) → `log` + **weiter mit der vorhandenen Trivy-Version**; der Scan darf an einem fehlgeschlagenen Update **nie** scheitern (Exit-Code-Semantik unverändert: 0/1/2/3 wie im Header). `tar` ist neue Soft-Abhängigkeit nur für den Update-Pfad — fehlt sie, Update skip statt Abbruch.

### Reihenfolge & Re-Exec

`auto_update_self` re-exect bei Selbst-Update (`exec`, Z. 218) — nach dem Re-Exec läuft das **neue** Skript, das `auto_update_trivy` enthält. Erst danach der Trivy-Update, dann `require_cmd "$TRIVY_BIN"` und der Scan. Also genau die vom User gewünschte Sequenz: „beim nächsten Run self-update wenn nötig **und** Trivy-Update".

### Agent-Version-Bump (sonst rollt Teil B nie aus)

Das Agent-Skript ändert sich → `AGENT_VERSION` in `agent/fathometer-agent.sh` (Z. 70) **und** `CURRENT_AGENT_VERSION` in `app/config.py` (Z. 175) von `0.5.0` → `0.6.0` (gemeinsam, im selben Commit — ADR-0021-Konvention). Der Selbst-Update-Gate prüft `grep AGENT_VERSION="<server_version>"` (Z. 179), daher müssen beide exakt übereinstimmen. Ohne Bump bemerkt der Selbst-Update das neue Skript nicht und der Trivy-Update käme nie auf die Hosts.

## Definition of Done (maschinell prüfbar)

- [x] `app/config.py`: `RECOMMENDED_TRIVY_VERSION == "0.71.0"`, `CURRENT_AGENT_VERSION == "0.6.0"`; `MIN_TRIVY_VERSION` unverändert (`0.70.0`).
- [x] `agent/fathometer-agent.sh`: `AGENT_VERSION="0.6.0"`; neue Funktion `auto_update_trivy`, aufgerufen nach `auto_update_self`, vor `require_cmd "$TRIVY_BIN"`.
- [x] `shellcheck agent/fathometer-agent.sh` grün (Linter — erlaubtes Gate).
- [x] `tests/config/test_agent_constants.py` prüft die neuen Konstanten-Werte (`test_ticket015_version_bump_values`).
- [x] `tests/agent/test_auto_update.sh` um Trivy-Update-Fälle erweitert: (a) happy Download/Verify/Replace, (b) skip bei >= recommended, (c) System-Binary → kein Replace, (d) Checksum-Mismatch → kein Replace, (e) `FM_TRIVY_AUTO_UPDATE=0` → skip, (f) Download-Fail → fail-soft, **(g) Post-Replace-Reverify-Fail → Rollback aus `.bak`**. Hermetisch (env -i, curl/install/tar/sha256sum/uname gemockt). Erweiterung der bestehenden Datei (keine neue `.sh`-Datei).
- [x] `ruff check . && ruff format --check .` grün, `mypy app/` grün.
- [x] **security-auditor APPROVED** (kein Action-Item). Geprüfte Härtung: Checksum-Pflicht nicht umgehbar (kein Replace-Pfad vor bestandener SHA256); Guard `readlink -f` + exakter `$managed_dir/trivy`-Vergleich (System-Trivy nie angefasst, `FM_TRIVY_MANAGED_DIR` nur lokal/root, nicht aus Server-Antwort); fail-soft lückenlos (kein `return 1`-Pfad, Aufruf unbedingt vor `require_cmd`); Rollback intakt; keine Endlosschleife (`version_lt(rec,rec)=false`); mktemp-0700 + `tar … trivy` literal-member (kein Path-Traversal); keine Shell-Injection über `recommended`/`url_template` (Bash-Substitution statt `eval`, `grep -F`, gequotetes curl). **Restrisiko (dokumentiert, = Ticket-Nicht-Ziel):** SHA256 sichert Transport-Integrität, nicht Origin-Kompromittierung (Tarball + Checksums teilen den Kanal); Cosign-Signaturprüfung bleibt Re-Open-Kandidat.
- [ ] **Operator (Heavy, nur auf Anweisung):** Installer-Integration (`tests/integration/installer/`) und ein echter End-to-End-Lauf gegen GitHub — **steht beim User an**, nicht im Pure-Unit-Lauf.

## Test-Konvention (Subagent-Pflicht, wörtlich)

Erlaubte Quality-Gates: ruff, mypy, shellcheck (Linter), pytest Default-Selektion (Pure-Unit). Verboten: db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Compose/Browser-Tests — keine proaktiven Aufrufe, **keine neuen** `.bats`-/`.sh`-Test-Dateien (Erweiterung der bestehenden `tests/agent/test_auto_update.sh` ist erlaubt; neue Dateien nur mit User-Genehmigung). Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf).

## Design-Entscheidungen (zur Bestätigung, sonst als Default umgesetzt)

1. **Bezugsweg GitHub-direkt** (wie `download_pinned_trivy`), nicht backend-proxied — konsistent mit dem Bootstrap-Installer, kein Binär-Storage im Backend. Air-Gap via `FM_TRIVY_AUTO_UPDATE=0`.
2. **Nur fathometer-managed Binary** (`/opt/fathometer/bin/trivy`) wird ersetzt; System-Trivy nie.
3. **Trigger auf `< recommended`** (nicht nur `< min`); `MIN` bleibt 0.70.0.
4. **Fail-soft**: ein Update-Fehler bricht den Scan nie ab.

## Risiken / Nicht-Ziele

- **Endlosschleife:** nach Update auf 0.71.0 ist `version_lt(0.71.0, 0.71.0)` false → kein erneuter Download. Keine Schleife (mirror des Selbst-Update-Verhaltens).
- **Supply-Chain:** SHA256-Verifikation gegen `trivy_<v>_checksums.txt` ist **Pflicht** (kein ungeprüftes Binär-Replace). Cosign-Signatur-Prüfung ist Nicht-Ziel dieses Tickets (Re-Open-Kandidat, falls gewünscht).
- **Air-Gap:** Hosts ohne GitHub-Outbound müssen `FM_TRIVY_AUTO_UPDATE=0` setzen; Default ist an. `docs/operations.md` um diesen Schalter ergänzen.
- **Kein Backend-Trivy-Proxy** in diesem Ticket (Re-Open, falls Air-Gap-Hosts Trivy doch übers Backend ziehen sollen).
