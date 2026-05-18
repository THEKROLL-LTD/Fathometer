## ADR-0021 — Agent-Distribution via Bootstrap-Installer, Trivy-Output-Strip, Ursachen-Felder pro Finding

**Status:** Akzeptiert · **Datum:** 2026-05-17 · **Bezug:** ARCHITECTURE §11 (Client-Agent) wird erweitert, nicht abgelöst. ADR-0003 (Push statt Pull) bleibt unverändert — der Installer ändert nichts am Push-Modell, er macht das Aufsetzen des Push-Senders nur einmalig einfacher. ADR-0011 (`package_name@target`-Disambiguation) wird **teilweise abgelöst**: der dort als „Alternative" erwähnte Weg „eigene `target`-Spalte" wird jetzt umgesetzt, der `@target`-Suffix im `package_name` bleibt während einer natürlichen Re-Ingest-Phase als Übergangsformat erhalten.

## Kontext

Heutiger Installations-Flow (ARCHITECTURE §11): Operator klont das Repo oder lädt die zwei Skripte (`agent/secscan-register.sh`, `agent/secscan-agent.sh`) auf den Ziel-Host, installiert Trivy plus `curl`/`jq`/`gzip` selbst, ruft `secscan-register.sh` einmal interaktiv auf, speichert den zurückgegebenen Server-Key in `/etc/secscan/api-key` mit `chmod 600`, schreibt selbst einen Cron-Eintrag oder eine systemd-Unit.

Pain-Points aus User-Sicht (Cowork-Konsultation vom 2026-05-17):

1. **Trivy installieren ist pro Distro unterschiedlich.** Ubuntu/Debian via Aqua-APT-Repo, AlmaLinux/RHEL via Aqua-DNF-Repo, andere Distros manuell. Operator muss pro Host dokumentieren, was er gemacht hat — kein einheitlicher Pfad.
2. **Drei separate Schritte** (Trivy, register, cron/timer) heißen drei separate Fehlerquellen. Hosts werden in inkonsistenten Zuständen aufgebaut.
3. **Kein zentraler Update-Pfad.** Wenn `secscan-agent.sh` v0.2.0 ein Pflichtfeld im Envelope einführt, muss der Operator auf jeden Host gehen, das Skript ersetzen, evtl. Trivy mit-upgraden. Aktuell hat das Backend keinen Mechanismus, dem User zu sagen „dein Agent ist veraltet" — der erste Hinweis ist ein 400 beim Scan-Upload.

4. **Trivy-Output enthält viel, das wir wegwerfen — und wenig, das wir bräuchten aber nicht extrahieren.** Realität aus `tests/fixtures/trivy/`-Analyse und `trivy-scan.json` (4.95 MB raw → 0.56 MB gzipped): in einer Ubuntu-22.04-RKE2-Fixture beginnen die ersten Vulnerabilities erst bei Zeile 56178, davor sind 56000+ Zeilen `Results[i].Packages[]` — Inventarliste *aller* installierten Pakete inklusive `InstalledFiles[]`, `Maintainer`, `DependsOn`, `Licenses`, `Identifier.PURL/UID`. Geschätzt 80-90% des Raw-JSONs. Dieser Block ist explizit out-of-scope nach ARCHITECTURE §17 („SBOM-Erfassung, License-Findings") und wird im Ingest still per `extra="ignore"` verworfen. Gleichzeitig wirft Pydantic Felder *pro Vulnerability* weg, die wir produktiv nutzen könnten — insbesondere `PkgIdentifier.PURL` (Distro-Familie + Architektur + kanonischer Paketname), `SeveritySource` (Quelle der Severity-Entscheidung), `VendorIDs` (Distro-Advisory-IDs wie `USN-6543-1`/`RHSA-2024:1234`). Plus eine Spec-Schuld aus ADR-0011: der Datei-Pfad für `lang-pkgs`-Findings (z.B. `/usr/local/bin/kubelet` für eine eingebettete Go-Library) wird in den `package_name` mit `@/path` reinkodiert statt als eigene Spalte zu existieren — funktional korrekt, aber UI-unfreundlich und nicht abfragbar.

Was bewusst NICHT als Lösung gewählt wurde:

- **Distro-spezifische Pakete (deb/rpm/Copr/Open-Build-Service).** Pro Distro/Release eigene Pipeline + Repo-Hosting + Signatur-Key — Overkill für Single-User-MVP. User-Entscheidung: ausgeschlossen.
- **Container-basierter Agent.** `trivy rootfs /` will explizit das Host-FS sehen; ein Container müsste mit `--privileged --pid=host -v /:/host:ro` laufen und verliert damit die Einfachheit, die ein Container bringen sollte. Außerdem ein-Container-pro-Host ist Ops-Overhead ohne Mehrwert.
- **Auto-Update via Updater-Daemon.** ARCHITECTURE §11 sagt explizit „keine Auto-Updates des Agents (sonst Supply-Chain-Risiko)" und User hat das bestätigt. UI-Indikator für veraltete Agents reicht.

## Entscheidung

Das Backend hostet einen interaktiven Bootstrap-Installer. Der Operator-Standardpfad wird zu **einem einzigen Befehl**:

```
curl -fsSL https://secscan.example.com/install.sh | sudo bash
```

Der Installer ist ein Wizard, der den Operator durch sechs Schritte führt (System-Detection, Dependencies, Trivy, Registrierung, systemd-Unit/Timer, Probe-Scan) mit hübscher TTY-Ausgabe (Box-Borders, ANSI-Farben, Status-Symbole `[ok] / [..] / [fail]`). Master-Key und Server-Name werden **im laufenden Prozess** interaktiv abgefragt — kein Argv, keine Shell-History, keine ENV-Var.

### Wizard-Sprache

Alle Operator-Strings auf **Englisch**. Konsistent mit der Code-String-Konvention aus CLAUDE.md (`Code selbst (Bezeichner, Strings) auf Englisch`). Die bestehenden deutschen Strings in `agent/secscan-register.sh` werden im Zuge dieses Blocks ebenfalls auf Englisch normalisiert, damit Installer und Helper konsistent sind.

### Backend-Endpoints

Drei neue Routes auf dem Backend, alle **ohne Auth** (kein Geheimnis im Response, Operator braucht sie vor Master-Key-Eingabe):

- `GET /install.sh` — rendert ein Jinja-Template (`app/templates/agent/install.sh.j2`) mit `SECSCAN_URL` und `RECOMMENDED_TRIVY_VERSION` als eingebackene Konstanten. Content-Type `text/x-shellscript`. ETag basierend auf `(template_mtime, recommended_trivy_version)` für `If-None-Match` cache busting.
- `GET /agent/files/<name>` — liefert `agent/secscan-agent.sh` und `agent/secscan-register.sh` als statische Files (`send_from_directory` mit Whitelist auf die zwei bekannten Namen, alles andere → 404). ETag + Last-Modified.
- `GET /agent/version` — JSON-Endpoint:
  ```json
  {
    "current_agent_version": "0.2.0",
    "min_agent_version": "0.1.0",
    "recommended_trivy_version": "0.70.2",
    "min_trivy_version": "0.70.0",
    "trivy_release_url_template": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-{arch}.tar.gz"
  }
  ```
  Werte kommen aus App-Settings (Block-N-Task #5), nicht aus User-Settings — der Operator-User soll keine Mindest-Version setzen können.

`/install.sh`, `/agent/files/<name>` und `/agent/version` sind explizit in der `PUBLIC_PATHS`-Allowlist (analog `/healthz` und Setup-Routen). CSRF und Login-Required gelten nicht.

### Installer-Verhalten

Sechs Phasen, jede mit eigener Box-Header-Anzeige:

```
╔══════════════════════════════════════════════════════════════╗
║                    secscan-agent installer                   ║
║                  Backend: https://secscan.example.com        ║
╚══════════════════════════════════════════════════════════════╝

[1/6] System detection
  [ok] Ubuntu 24.04 (linux/amd64)
  [ok] systemd available
  [ok] /etc/os-release readable, ID=ubuntu

[2/6] Dependencies
  [ok] curl already present (8.5.0)
  [..] installing jq via apt-get
  [ok] jq 1.7.1
  [ok] gzip already present

[3/6] Trivy
  [..] no trivy found in PATH
  Install pinned trivy 0.70.2 to /opt/secscan/bin/trivy? [Y/n] _
  [..] downloading trivy_0.70.2_Linux-64bit.tar.gz (32 MB)
  [..] verifying sha256
  [ok] trivy 0.70.2 installed

[4/6] Server registration
  Server name (a-z, 0-9, ._- and spaces): prod-web-01
  Expected scan interval in hours [24]: 24
  Master-Key (input hidden): _
  [..] POST https://secscan.example.com/api/register
  [ok] registered (server_id=42)
  [ok] api-key written to /etc/secscan/agent.env (mode 0600)

[5/6] Scheduler
  [ok] systemd unit /etc/systemd/system/secscan-agent.service written
  [ok] systemd timer /etc/systemd/system/secscan-agent.timer written (daily, +2h jitter)
  [ok] systemctl enable --now secscan-agent.timer

[6/6] Probe scan
  [..] running trivy rootfs / (this can take 1-5 minutes)
  [ok] 47 findings (3 CRITICAL, 12 HIGH, 32 others)
  [..] uploading envelope to https://secscan.example.com/api/scans
  [ok] HTTP 202 — server accepted

Done. View server: https://secscan.example.com/servers/42
```

### Detail-Verhalten pro Phase

**Phase 1 — System detection.** Liest `/etc/os-release` (`ID`, `ID_LIKE`, `VERSION_ID`). Detektiert `arm64`/`amd64` via `uname -m`. Prüft `command -v systemctl` für systemd vs. Cron-Fallback. Wenn keine der bekannten Distros (`ubuntu`/`debian`/`almalinux`/`rocky`/`rhel`/`centos`/`fedora`/`opensuse`/`sles`): Warnung und Frage „Continue with manual dependency install? [y/N]". Bei `n`: exit 1.

**Phase 2 — Dependencies.** Pro fehlendem Paket: passender Befehl (`apt-get install -y`, `dnf install -y`, `yum install -y`, `zypper install -y`). Kein Repo-Hinzufügen, kein GPG-Key — `curl`/`jq`/`gzip` sind in allen unterstützten Distro-Default-Repos drin. Bei Fehlschlag: zeige Befehl + Fehler, biete `[r]etry / [s]kip / [a]bort` — `skip` nur für `curl` (extrem unwahrscheinlich fehlend) sinnvoll.

**Phase 3 — Trivy.** Prüft `command -v trivy`. Drei Fälle:

- **Nicht gefunden:** Frage „Install pinned trivy <RECOMMENDED_TRIVY_VERSION> to /opt/secscan/bin/trivy? [Y/n]" (Default Yes bei leerer Antwort). Bei Yes: lädt Tarball von `https://github.com/aquasecurity/trivy/releases/download/v<version>/trivy_<version>_Linux-<arch>.tar.gz` (`arch` aus `uname -m` gemappt: `x86_64→64bit`, `aarch64→ARM64`), verifiziert SHA256 gegen den `*.sha256`-File desselben Releases, extrahiert nach `/opt/secscan/bin/trivy`, `chmod 0755`. `SECSCAN_TRIVY_PATH=/opt/secscan/bin/trivy` in die `agent.env`. Bei No: exit 1 mit Hinweis „install trivy manually and re-run".
- **Gefunden + Version ≥ MIN_TRIVY_VERSION:** Hinweis „trivy <X.Y.Z> found, using it", `SECSCAN_TRIVY_PATH=$(command -v trivy)` in `agent.env`.
- **Gefunden + Version < MIN_TRIVY_VERSION:** Warnung „trivy <X.Y.Z> is older than required <MIN_TRIVY_VERSION>". Frage „Install pinned <RECOMMENDED_TRIVY_VERSION> alongside? [Y/n]". Bei Yes: gleicher Pfad wie „nicht gefunden". Bei No: weiter mit System-Trivy, Hinweis „scans may fail or be incomplete".

Kein `trivy --download-db-only` Prefetch (User-Entscheidung) — Phase 6 zieht die DB beim ersten echten Scan.

**Phase 4 — Server registration.** Existiert `/etc/secscan/agent.env` mit bereits gesetztem `SECSCAN_API_KEY` und der gemeldete `server_id` ist beim Backend bekannt (`GET /api/whoami` mit dem Key gibt 200)? Dann Frage „Already registered as server_id=<id>. Re-register and rotate key? [y/N]". Default No → Phase 4 wird übersprungen.

Sonst: interaktive Eingabe von Server-Name (Default `$(hostname -s)`, Validierung gegen `^[a-z0-9._\- ]{1,64}$`), Scan-Intervall in Stunden (Default `24`, Validierung `1..168`), Master-Key (`read -srp`, Validierung non-empty). Aufruf der Register-Logik aus `agent/secscan-register.sh` (entweder Inline-Re-Implementierung oder Aufruf des aus Phase 0 nach `/opt/secscan/bin/` geladenen Originals). API-Key wird nach `/etc/secscan/agent.env` geschrieben:

```
SECSCAN_URL=https://secscan.example.com
SECSCAN_API_KEY=<key>
SECSCAN_TRIVY_PATH=/opt/secscan/bin/trivy
```

`chmod 0600`, `chown root:root`. Bei Backend-Fehler: zeige HTTP-Status + Response-Body, biete `[r]etry / [a]bort`.

**Phase 5 — Scheduler.** Standardpfad systemd:

- `/etc/systemd/system/secscan-agent.service`:
  ```
  [Unit]
  Description=secscan agent (trivy rootfs scan + upload)
  Documentation=https://secscan.example.com/

  [Service]
  Type=oneshot
  EnvironmentFile=/etc/secscan/agent.env
  ExecStart=/opt/secscan/bin/secscan-agent.sh
  Nice=10
  IOSchedulingClass=idle
  ```
- `/etc/systemd/system/secscan-agent.timer`:
  ```
  [Unit]
  Description=Daily secscan agent run

  [Timer]
  OnCalendar=daily
  RandomizedDelaySec=2h
  Persistent=true

  [Install]
  WantedBy=timers.target
  ```
- `systemctl daemon-reload && systemctl enable --now secscan-agent.timer`.

Cron-Fallback wenn `command -v systemctl` leer ist: `/etc/cron.d/secscan-agent`:

```
# Daily secscan agent run with 2h jitter
SHELL=/bin/bash
0 3 * * * root sleep $((RANDOM \% 7200)); . /etc/secscan/agent.env; /opt/secscan/bin/secscan-agent.sh
```

(Alpine/OpenRC explizit nicht supportet — User-Entscheidung.)

**Phase 6 — Probe scan.** Synchroner Aufruf `/opt/secscan/bin/secscan-agent.sh` mit Live-stderr-Passthrough (das bestehende Skript loggt jeden Schritt nach stderr). User sieht: Trivy-Scan läuft, Envelope wird gebaut, gzipped, POST-Response. Bei `exit 0`: Phase-OK + Print der Server-Detail-URL. Bei `exit != 0`: Phase-fail mit Hinweis, dass Timer trotzdem scharfgeschaltet ist — nächster reguläre Tick versucht es erneut.

### Nicht-interaktiver Modus

Wenn `[[ ! -t 0 ]]` (stdin ist kein TTY) ODER wenn `SECSCAN_UNATTENDED=1` ENV gesetzt ist:

- Alle Prompts entfallen.
- Werte kommen ausschließlich aus ENV-Vars (`SECSCAN_MASTER_KEY`, `SECSCAN_SERVER_NAME`, `SECSCAN_INTERVAL_HOURS`, `SECSCAN_INSTALL_TRIVY=yes|no`).
- Fehlt ein Pflichtwert: hard exit mit klarem Hinweis, welche Variable fehlt.
- Defaults für nicht-Pflicht: Server-Name = `$(hostname -s)`, Intervall = 24, Install-Trivy = yes wenn nicht vorhanden.

Für den Einzeiler-Pipe-Fall (`curl … | sudo bash`) gilt: stdin ist die Pipe, also kein TTY. Damit der Wizard trotzdem läuft, lesen alle `read`-Calls explizit von `/dev/tty` (`read -p "..." answer < /dev/tty`). Wenn `/dev/tty` nicht verfügbar ist (Headless-Container ohne TTY): Fallback auf unattended-Mode mit ENV-Vars.

Alternative-Aufruf-Form für Operatoren, die das sauberer finden: `sudo bash <(curl -fsSL https://secscan.example.com/install.sh)` — Process-Substitution behält stdin als TTY. Beide Formen werden in der UI-Anleitung gezeigt.

### Agent-Envelope-Erweiterung

`agent/secscan-agent.sh` sendet zusätzlich `trivy_version`:

```json
{
  "agent_version": "0.2.0",
  "host": {
    "os_family": "ubuntu",
    "os_version": "24.04",
    "os_pretty_name": "Ubuntu 24.04 LTS",
    "kernel_version": "6.8.0-39-generic",
    "architecture": "x86_64",
    "trivy_version": "0.70.2"
  },
  "scan": { ... }
}
```

`trivy_version` ist **optional** im Backend-Schema (`Pydantic` `str | None = None`). Altere Agents (0.1.0) ohne das Feld werden weiter akzeptiert; der UI-„Agent veraltet"-Indikator triggert dann ohnehin und der Operator wird zum Update geleitet.

### Backend-Schema-Erweiterung für Ursachen-Felder

`app/schemas/scan_envelope.py`:

- Neues Sub-Modell `TrivyPkgIdentifier(BaseModel)` mit `purl: str | None`, `uid: str | None`.
- `TrivyVulnerability` bekommt drei neue Felder:
  - `pkg_identifier: TrivyPkgIdentifier | None = None` (alias `PkgIdentifier`).
  - `severity_source: str | None = None` (alias `SeveritySource`, max 64).
  - `vendor_ids: list[str] | None = None` (alias `VendorIDs`, defensiv getrimmt analog `cwe_ids` auf max 32 Items × 128 Chars, ASCII-only).
- Convenience-Property `package_purl: str | None` auf `TrivyVulnerability` liefert `pkg_identifier.purl` direkt für den Ingest-Mapper.

PURL-Validierung minimal: NUL-Byte-Check, ASCII-only, max 512 Chars. Keine strukturelle Validierung der PURL-Komponenten (Distro/Type/Namespace) — das ist Sache eines späteren Parsers, falls/wenn das Update-Befehl-Feature kommt.

`Finding`-Persistierung (siehe nächste Sektion „Konsequenzen → DB-Schema"): `package_purl`, `target_path`, `result_type`, `severity_source`, `vendor_ids` als fünf neue nullable Spalten plus die `Result.Type`-/`Result.Target`-Propagation aus dem Ingest-Service.

### Backend-Schema und DB-Schema

Neue Felder in `Server`:

- `agent_version: Mapped[str | None]` — letzter beobachteter Wert aus dem Envelope.
- `trivy_version: Mapped[str | None]` — letzter beobachteter Wert aus dem Envelope.
- `agent_version_seen_at: Mapped[datetime | None]` — Timestamp, damit der UI-Indikator nicht auf einem 6-Monate-alten Wert hängt, wenn der Server stale ist.

Migration: `alembic revision -m "add agent_version/trivy_version to server"` mit drei `ADD COLUMN`-Statements (alle nullable, kein Backfill nötig).

Ingest-Code (`app/api/scans.py`): nach erfolgreichem Parse setzt er auf dem `Server` die drei Felder und commited zusammen mit dem `Scan`-Insert.

### UI-Indikatoren für „veraltet"

**Server-Detail-Header (Block K, `servers/detail.html`):** zusätzliche Status-Pills in der Header-Pill-Reihe, neben den bestehenden Pills:

- **Agent veraltet** (rot-orange) — wenn `Server.agent_version is None OR version_lt(Server.agent_version, min_agent_version)`. Tooltip: „Agent-Version <X> ist unter dem minimum <Y>. Run `curl -fsSL <URL>/install.sh | sudo bash` to update".
- **Trivy veraltet** (gelb) — wenn `Server.trivy_version is None OR version_lt(Server.trivy_version, min_trivy_version)`. Tooltip mit Update-Hinweis.
- **Trivy-DB veraltet** (gelb) — wenn `Server.trivy_db_updated_at < now - 7d` (Schwelle ist Konstante in Settings, default 7 Tage). Trivy zieht die DB normalerweise automatisch bei jedem Scan-Run; wenn die DB-Frische trotzdem alt ist, ist meistens der Trivy-Aufruf selbst veraltet oder die DB-Quelle (`ghcr.io/aquasecurity/trivy-db`) war zeitweise unerreichbar.

Pills sind reine Anzeigen — Klick öffnet eine kleine Info-Modal mit Update-Befehl, keine Aktion.

**Dashboard-Sidebar (Block I, `_partials/sidebar`):** in der Server-Liste bekommt jeder Server-Eintrag einen kleinen Sub-Marker `⚠ agent` / `⚠ trivy` rechts neben dem Namen, falls einer der Indikatoren greift. Tooltip mit Detail.

Kein eigener „X agents outdated"-Aggregat-Counter auf dem Dashboard im Scope dieses Blocks. Re-Open-Trigger wenn der User danach fragt.

### Agent-side Trivy-Output-Stripping

Der Agent strippt den größten irrelevanten Block aus dem Trivy-Output, bevor das Envelope gebaut wird. Konkret:

```bash
"$TRIVY_BIN" rootfs "$SCAN_PATH" --format json --quiet --scanners vuln --output - \
  | jq 'del(.Results[].Packages)' > "$trivy_out"
```

Was wegfällt: die `Packages[]`-Inventarliste pro Result-Block (Paketname, Version, Lizenzen, `InstalledFiles[]`, `Maintainer`, `DependsOn`, `Identifier.PURL/UID`, `SrcName`/`SrcVersion`). Was bleibt: alles unter `Results[i].Vulnerabilities[]` plus die Top-Level-Metadaten — also exakt das, was wir tatsächlich persistieren. **Wichtig:** Trivy schreibt `PkgIdentifier.PURL` und alle anderen pro-Finding-Felder zusätzlich in jeden Vulnerability-Eintrag, sodass der Strip die in der nächsten Sektion eingeführten Ursachen-Felder nicht entwertet.

Erwarteter Win: raw 4.95 MB → 400-700 KB (80-90% Reduktion). gzipped 560 KB → 100-200 KB (2-3× nach Strip, weil gzip die hochrepetitiven `InstalledFiles`-Pfade ohnehin gut komprimiert hat). Backend-CPU-Win durch wegfallenden Pydantic-Walk über tote Sub-Trees: geschätzt 50-200 ms pro Scan, signifikant bei Flotten ab ~50 Hosts.

Fallback-Pfad: wenn der `jq`-Aufruf fehlschlägt (`jq` veraltet, unerwarteter Trivy-Output) sendet der Agent den ungestrippten Output und loggt eine Warnung nach stderr. Der Backend-Ingest verarbeitet beides identisch (`extra="ignore"`), also kein Funktionalitäts-Risiko — nur Bandbreiten-Risiko.

Adversarial-Test in Block N: vergleicht `jq 'del(.Results[].Packages) | [.Results[].Vulnerabilities | length] | add'` vor und nach Strip — Anzahl Vulnerabilities muss identisch bleiben. Wenn jemand versehentlich `.Vulnerabilities` strippt, schlägt der Test sofort an.

### Ursachen-Felder pro Finding

Aus dem Trivy-Output werden zusätzlich zu den bestehenden Finding-Feldern fünf neue Felder extrahiert und persistiert, ausschließlich zur **Anzeige der Ursache** in der UI:

| Feld | Trivy-Quelle | Beispiel-Werte | Zweck |
|------|--------------|----------------|-------|
| `package_purl` | `Vulnerability.PkgIdentifier.PURL` | `pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=arm64&distro=ubuntu-22.04` | Kanonische Maschinen-ID; macht Distro/Architektur/Origin maschinenlesbar. |
| `target_path` | `Result.Target` | `usr/local/bin/kubelet` (lang-pkgs) oder `rke2-sv-0 (ubuntu 22.04)` (os-pkgs) | Bei `lang-pkgs` der Datei-Pfad der Binary/JAR/etc.; bei `os-pkgs` der Distro-Marker. |
| `result_type` | `Result.Type` | `ubuntu`, `debian`, `rhel`, `alpine`, `gobinary`, `jar`, `npm`, `pip`, `gem` | Typ-Pill in der UI; disambiguiert OS-Paket vs. eingebettete Library. |
| `severity_source` | `Vulnerability.SeveritySource` | `nvd`, `ubuntu`, `redhat`, `ghsa` | Tooltip-Indikator „Severity stammt von X" — relevant wenn Vendor und NVD unterschiedlich bewerten. |
| `vendor_ids` | `Vulnerability.VendorIDs` | `["USN-6543-1"]`, `["RHSA-2024:1234"]` | Distro-Advisory-IDs als kleine Pills; oft der einzige direkte Weg zum Vendor-Tracker. |

**Bewusst NICHT in diesem Block:**

- Kein **Update-Befehl-Mapping** (`UPDATE_TEMPLATES`-Dict, das aus `result_type` plus `package_name` und `fixed_version` einen konkreten `apt`/`dnf`/`apk`-Befehl baut). Begründung: ein verlässlicher „Wie fixe ich das"-Hinweis braucht Kontext, den ein statisches Mapping nicht liefert — z.B. ob der Host paket-aktualisiert wird oder per Image-Rebuild, ob der User Root hat, ob es einen abhängigen Service-Restart braucht, bei `gobinary` welches Build-System die Binary erzeugt. Das ist ein klassisches LLM-Anwendungsgebiet (siehe Re-Open-Trigger), nicht statisches Bash-Template.
- Kein **VendorSeverity-Disagreement-Indikator** (z.B. „Vendor sagt low, NVD sagt critical"). Wertvolles Feature, aber eigenständig — separate ADR später wenn jemand danach fragt.
- Kein **PURL-Parser-Helper** im Backend, der z.B. Distro-Familie aus der PURL extrahiert. Wir persistieren PURL als opaken String; die UI rendert sie als Tooltip-Text. Strukturierte Verarbeitung von PURL-Sub-Komponenten wäre erst nötig wenn das Update-Befehl-Mapping kommt.

**UI-Vertrag (für Block N und nachfolgende Blöcke):**

In der Findings-Tabelle bekommt jede Zeile als zweite Sub-Zeile (`text-xs opacity-70`) eine **„Ursache"-Anzeige** statt der bisherigen reinen Pfad-Anzeige aus dem `@target`-Suffix:

- Bei `result_type ∈ {ubuntu, debian, rhel, centos, rocky, alma, fedora, amazon, alpine, opensuse-leap, opensuse-tumbleweed, sles}`: `{package_name} {installed_version} ({result_type})` plus optional `vendor_ids` als kleine Pill-Reihe daneben.
- Bei `result_type ∈ {gobinary, jar, npm, pip, gem, cargo, composer, maven, ...}`: `{package_name} {installed_version} in {target_path}` mit Mono-Font für den Pfad.
- Hover-Tooltip auf der Zeile zeigt `PURL: {package_purl}` und `Quelle: {severity_source}`, falls gesetzt.

Konkret heißt das: die Findings-Tabelle zeigt dem Operator auf einen Blick, ob es ein Distro-Paket ist (dann weiß er „Paketmanager-Update"), oder eine eingebettete Library mit konkretem Pfad (dann weiß er „Anwendung neu deployen/builden") — ohne dass das Backend einen konkreten Update-Befehl vorschlägt.

### `target_path` und das ADR-0011-Übergangsformat

ADR-0011 kodiert für `lang-pkgs`-Findings den Datei-Pfad in den `package_name` als `pkg_name@/usr/local/bin/kubelet`, weil ohne diese Disambiguation die natürliche-Key-Constraint `(server_id, finding_type, identifier_key, package_name)` für Findings derselben Library in mehreren Binaries kollidiert. Mit `target_path` als eigene Spalte ist diese Disambiguation maschinell und nicht mehr im `package_name` versteckt.

Migrations-Strategie:

- **Neue Findings ab v0.7.0:** `target_path` wird direkt befüllt aus `Result.Target`. `package_name` bleibt vorerst weiter im `@target`-Format, damit die UNIQUE-Constraint nicht bricht — Doppelschreibung ist akzeptabel, kostet ~50 Bytes pro lang-pkgs-Finding.
- **Bestehende Findings:** keine Daten-Migration im Block. Stattdessen **natürlicher Re-Ingest**: sobald ein Server seinen nächsten Scan macht, wird das Finding über die natural-key-Constraint geupdated und `target_path` befüllt sich. Nach typisch einem Scan-Intervall (24 h) sind alle aktiven Server konsolidiert.
- **Stale-/retire-Server:** ihre Findings bleiben mit `target_path = NULL`. UI rendert in diesem Fall den Fallback aus dem `@target`-Suffix im `package_name` (kleiner Render-Helper, `package_name.partition('@')` → falls Teil 2 nicht leer ist, verwende ihn als Pfad).
- **Späterer Block (out-of-scope für N):** sobald alle aktiven Server konsolidiert sind, kann die UNIQUE-Constraint auf `(server_id, finding_type, identifier_key, package_name, target_path)` umgestellt werden und der `@target`-Suffix im `package_name` entfernt werden. Eigene ADR.

### Bestehende Skripte

`agent/secscan-register.sh` und `agent/secscan-agent.sh` bleiben im Repo erhalten (User-Entscheidung „beide bleiben, Installer nutzt sie"). Der Installer lädt sie zur Laufzeit vom Backend (`GET /agent/files/<name>`), legt sie in `/opt/secscan/bin/`, ruft `secscan-register.sh` für die Registrierung auf.

Vorteile dieses Setups:

- Keine Code-Duplikation zwischen Installer und Helper-Skripten.
- Power-User-Pfad bleibt offen: wer Ansible benutzt, kann weiter direkt die zwei Skripte ziehen + sein eigenes systemd-Template schreiben.
- Die Backend-Versionierung (`/agent/version`) trifft alle drei Files konsistent (Installer prüft `If-None-Match` beim Re-Download, Operator-Update-Schritt ist immer derselbe Befehl wie der Install-Befehl).

Anpassung an den beiden Bestands-Skripten:

- `secscan-agent.sh`: `trivy_version` ergänzen (kleines `trivy_ver=$($TRIVY_BIN --version | head -1 | awk '{print $2}')` plus jq-Feld), Wizard-User-Strings auf Englisch normalisieren, Exit-Code-Semantik bleibt.
- `secscan-register.sh`: User-Strings auf Englisch normalisieren, Exit-Code-Semantik bleibt.

## Begründung

**Warum Bootstrap-Installer und nicht Distro-Pakete.** Pro Distro/Release eine Pipeline + Repo + Signing-Key + Update-Disziplin ist für ein Single-User-MVP überzogen. Der Installer ist ein einzelner Bash-File, läuft auf jeder Distro mit `bash >= 4`, hat keine Build-Pipeline. Wenn der User später Distro-Pakete bauen will (z.B. um zentral via FreeIPA-Ansible auszurollen), ist das eine eigene ADR — der Installer macht es nicht unmöglich.

**Warum interaktiver Wizard.** „Einzeiler für dummies" (wörtliches User-Zitat) heißt, der Operator soll nichts vorher konfigurieren müssen — alle Werte werden im Lauf abgefragt, mit sensiblen Defaults. Hübsche TTY-Ausgabe (Box, Farben, Status-Symbole) macht den Schritt von „ich tippe blind einen Befehl" zu „ich sehe, was passiert" und gibt Vertrauen.

**Warum nicht-interaktiver Fallback trotzdem.** Provisioning (Ansible, Terraform, Cloud-Init) ist ein realer Sekundär-Use-Case. Der Installer bricht in diesen Setups stumm ab statt am Master-Key-Prompt zu hängen, sobald `[[ ! -t 0 ]]` oder `SECSCAN_UNATTENDED=1`.

**Warum kein DB-Prefetch.** User-Entscheidung — schlanker Installer, der erste Scan-Run lädt die DB selbst. Verkauft den Wizard-Schritt 6 als „dauert 1-5 Minuten" statt „dauert 30 Sekunden". Macht die Wizard-Ausgabe vorhersagbarer (kein zusätzlicher Download-Progress-Block).

**Warum synchroner Probe-Scan am Ende.** User-Entscheidung. Beste Lehrwirkung — der Operator sieht im selben Terminal, dass die End-to-End-Kette funktioniert (Scan → Envelope → POST → 202). Vermeidet die häufige Klasse „Installer sagt OK, im Dashboard taucht aber nichts auf".

**Warum kein Auto-Update.** ARCHITECTURE §11 + User-Bestätigung. Auto-Update bedeutet implizite Root-Vertrauensbeziehung Backend → Host; wenn das Backend-Hosting selbst kompromittiert wird, hat der Angreifer Root auf der gesamten Flotte. Statt dessen: Backend kennt aus `agent_version` im Envelope den Stand jedes Hosts, UI zeigt den veralteten Stand prominent, Operator entscheidet wann er den selben Einzeiler nochmal ausführt (`curl … | sudo bash` ist auch der Update-Befehl, weil der Installer ein bestehendes `agent.env` erkennt und Phase 4 überspringt).

**Warum drei separate Backend-Endpoints und nicht ein einzelner Tarball.** Ein Tarball mit `install.sh` + `secscan-agent.sh` + `secscan-register.sh` wäre kompakter, aber der Operator müsste ihn entpacken (Schritt vor dem Einzeiler) oder der Installer müsste sich selbst entpacken (zusätzliche Komplexität). Drei kleine Endpoints sind transparenter — der Operator kann mit `curl -L https://…/install.sh` reinschauen, bevor er pipet zu bash. Das ist die Erwartung an einen Bash-Bootstrap-Installer.

**Warum keine Auth auf `/install.sh` und `/agent/files/<name>`.** Drei Gründe: (a) der Inhalt ist kein Geheimnis — kein Master-Key, kein API-Key, nur generische Bash-Logik plus die eingebackene Backend-URL; (b) der Operator soll das Skript vor dem Ausführen ansehen können (Auth würde das verkomplizieren); (c) der Master-Key wird ohnehin im Wizard-Lauf abgefragt, die Authentifizierung passiert da gegen `/api/register`. Re-Open-Trigger falls Operatoren später eine IP-Allowlist wollen — das ist ein nginx/Caddy-Setup-Thema, kein App-Thema.

**Warum `/etc/secscan/agent.env` statt drei separate Files.** Eine `EnvironmentFile`-Datei für systemd, die das Agent-Skript per `set -a; . /etc/secscan/agent.env` auch in Cron-Setups einlesen kann. Single Source of Truth für API-Key, Backend-URL und Trivy-Pfad. `chmod 0600 root:root` deckt den API-Key ab.

**Warum `version_lt`-Vergleich für „veraltet" und kein simpler Equals.** Semver-Vergleich (`packaging.version.Version` aus dem Python-Stdlib-Ökosystem oder ein 30-Zeilen-Helper) erkennt `0.1.0 < 0.2.0` korrekt und lässt zukünftige Patch-Releases (`0.2.1`) ohne Backend-Update als „aktuell" durchgehen. Strikter Equals würde bei jeder Patch-Version False-Positive-Indikatoren produzieren.

**Warum Trivy-Strip + Ursachen-Felder in *demselben* Block.** Die zwei Themen sind logisch verschränkt: der Strip dropt nur die `Packages[]`-Inventarliste, lässt aber `PkgIdentifier`/`SeveritySource`/`VendorIDs` *pro Vulnerability* intakt. Ohne Schema-Erweiterung wäre der Strip ein reiner Bandbreiten-Win ohne UI-Wirkung; ohne Strip würden die Ursachen-Felder über doppelt-vorhandene Daten (im Packages-Block + im Vuln-Block) aus dem 4.95-MB-Payload extrahiert, was Verschwendung wäre. Außerdem läuft beides über denselben Code-Pfad (Agent-Skript bumpt auf 0.2.0, Pydantic-Schema bekommt neue Felder, Ingest persistiert, UI zeigt an) — ein Block mit klarer DoD-Kette ist sauberer als zwei dünne Folge-Blöcke.

**Warum `target_path` als eigene Spalte statt weiter ADR-0011-Codierung.** ADR-0011 selbst nennt die eigene Spalte als „Alternative" und begründet die `@target`-Codierung mit Vermeiden einer Migration. Block N braucht eh eine Migration (Server-Spalten + Finding-Spalten); die ADR-0011-Spec-Schuld dabei mit-aufzulösen kostet eine zusätzliche `add_column`-Zeile in derselben Migration. Die UNIQUE-Constraint bleibt während der Re-Ingest-Phase erstmal auf `package_name` mit `@target`-Suffix; eine spätere ADR kann die Constraint sauber umstellen, sobald alle aktiven Server konsolidiert sind. Die UI rendert ab v0.7.0 aus `target_path` (neu) mit Fallback auf das `@`-Split aus `package_name` (alt-Daten) — Operator sieht einheitliche Darstellung.

**Warum kein statisches Update-Befehl-Mapping (`UPDATE_TEMPLATES`).** Auf den ersten Blick ist ein Dict `{"ubuntu": "sudo apt-get install --only-upgrade {pkg}={fixed}", "rhel": "sudo dnf upgrade {pkg}", ...}` trivial und nützlich. In der Realität: Distro-Familie aus PURL/`result_type` alleine ist nicht ausreichend Kontext für einen verlässlichen Befehl. Beispiele wo das Mapping daneben läge — Snap-/Flatpak-Pakete (PURL sagt `deb`, der Befehl wäre falsch); RKE2/k3s-Hosts (Distro-Update bringt nichts, weil k3s seine eigene Binary mitbringt); Container-Hosts (Update muss auf Image-Ebene passieren, nicht auf Host); embedded `gobinary`-Findings (kein Paketmanager-Befehl möglich, nur App-Rebuild). Ein LLM (Block-G-Stack ist da) kann den Server-Kontext (Tags, OS-Pretty-Name, Finding-Cluster) berücksichtigen und einen begründeten Vorschlag machen — separates Feature, eigene ADR. Bis dahin zeigt die UI nur **was die Ursache ist** (Distro-Paket vs. eingebettete Library, Pfad, Vendor-IDs), nicht **was zu tun ist**.

Alternativen verworfen:

- **Container-Agent.** Wie oben begründet (privileged + Host-FS-Mount = anti-pattern).
- **Pull-statt-Push** (Backend SSH'd auf den Host, läuft Trivy remote). ADR-0003 explizit ausgeschlossen (keine Server-Credentials beim Backend).
- **Eigener Updater-Daemon** mit lokalem Versions-Polling. Auto-Update-Risiko + Daemon-Komplexität. UI-Indikator + manueller Re-Run des Installers ist die ausgewählte Mitigation.
- **Repo-Verteilung via `git pull` auf dem Host.** Operator müsste Git installieren, SSH-Keys hinterlegen, Branch-Disziplin halten. Bash-Installer hat keine dieser Abhängigkeiten.

## Konsequenzen

**Code (neu):**

- `app/views/agent_install.py` neu — Blueprint mit den drei Routes `/install.sh`, `/agent/files/<name>`, `/agent/version`.
- `app/templates/agent/install.sh.j2` neu — Wizard-Template, ca. 400-500 Bash-Zeilen, ANSI-Farben + Box-Drawing-Chars (UTF-8).
- `app/services/agent_version.py` neu — `version_lt(a, b) -> bool`-Helper plus `is_agent_outdated(server, settings) -> bool` / `is_trivy_outdated(...)` / `is_trivy_db_outdated(...)`.
- `app/templates/servers/_status_pills.html` (oder Erweiterung des bestehenden Header-Markups in `detail.html`) — drei neue Pills mit Tooltip.
- `app/templates/_partials/sidebar.html` (oder wo immer die Sidebar-Server-Liste rendert) — Sub-Marker pro Server-Eintrag.

**Code (geändert):**

- `agent/secscan-agent.sh`: `AGENT_VERSION` auf `0.2.0` bumpen, `trivy_version` ins Envelope, `jq 'del(.Results[].Packages)'` als Strip-Filter zwischen Trivy-Aufruf und Envelope-Build, Fallback auf ungestripped bei `jq`-Fehlschlag, User-Strings auf Englisch.
- `agent/secscan-register.sh`: User-Strings auf Englisch.
- `app/api/scans.py`: Envelope-Parse extrahiert `agent_version`, `host.trivy_version`, setzt sie auf dem `Server` plus `agent_version_seen_at = now`. Ingest-Mapper propagiert `Result.Target`/`Result.Type` in jedes `Finding` (als `target_path`/`result_type`) und extrahiert `PkgIdentifier.PURL`/`SeveritySource`/`VendorIDs` aus jeder Vulnerability in die entsprechenden Finding-Spalten.
- `app/schemas/scan_envelope.py`: `host.trivy_version: str | None = None` ergänzen. `TrivyVulnerability` um `pkg_identifier: TrivyPkgIdentifier | None`, `severity_source: str | None`, `vendor_ids: list[str] | None` ergänzen — letztere mit defensivem Trim-Validator analog `cwe_ids` (max 32 Items × 128 Chars, ASCII-only, NUL-Byte-frei). Neues Sub-Modell `TrivyPkgIdentifier(BaseModel)` mit `purl`/`uid`.
- `app/models.py`: `Server` bekommt drei neue Spalten (`agent_version`, `trivy_version`, `agent_version_seen_at`), alle nullable. `Finding` bekommt fünf neue Spalten (`package_purl: String(512) | None`, `target_path: String(512) | None`, `result_type: String(64) | None`, `severity_source: String(64) | None`, `vendor_ids: ARRAY(String(128)) | None`), alle nullable, keine Index-Erweiterung im Block (Findings-Triage geht weiter über die Block-K/M-Indizes; `package_purl` als zusätzliche Filter-Dimension ist out-of-scope).
- `app/__init__.py`: `agent_install_bp` registrieren; `/install.sh`, `/agent/files/`, `/agent/version` in die `PUBLIC_PATHS`-Allowlist (oder analog dazu) eintragen.
- `app/config.py` (oder wo App-Settings leben): neue Konstanten `MIN_AGENT_VERSION`, `RECOMMENDED_TRIVY_VERSION`, `MIN_TRIVY_VERSION`, `TRIVY_DB_STALE_THRESHOLD_DAYS` (default 7). Werte werden im Code als Konstanten gepflegt (Block-Commit-Zeit), nicht zur Laufzeit änderbar — das ist Absicht, weil eine UI zum Setzen der Mindest-Version eine Selbstabschaltungs-Falle wäre.
- `app/services/findings_ingest.py`: `_disambiguated_package_name()` behält das ADR-0011-`@target`-Format vorerst. Zusätzlich neuer Mapper `_extract_cause_fields(vuln, result)` der die fünf Ursachen-Felder aus dem Trivy-Block extrahiert. PURL-Convenience-Property `Vulnerability.package_purl` aus dem Schema vereinfacht den Aufruf.
- `app/templates/dashboard/_findings_section.html` und `app/templates/servers/_findings_section.html`: Paket-Spalte-Sub-Zeile rendert ab v0.7.0 aus `target_path`/`result_type` statt aus dem `@`-Split. Fallback-Helper `format_finding_cause(finding) -> str` (in `app/services/finding_display.py`, neu) liefert die fertige Ursachen-Zeile mit `result_type`-Pill plus Distro-Paket-Format oder Pfad-Format. Helper ist via Jinja-Global registriert.
- `ARCHITECTURE.md §6`: Envelope-Beispiel um `host.trivy_version`. Hinweis dass Agent-side `Packages[]`-Strip ab Agent-Version 0.2.0 üblich ist.
- `ARCHITECTURE.md §11`: Installer-Abschnitt ergänzen, Forward-Compat-Absatz präzisieren (Verweis auf UI-Indikator statt nur Server-400-Fehler). Sub-Sektion „Output-Stripping" mit kurzer Begründung.
- `ARCHITECTURE.md §17`: Out-of-Scope-Liste prüfen — „LLM-basierte Update-Befehl-Empfehlung" als zusätzlicher Out-of-Scope-Punkt für v0.7.0 vermerken, damit kein Implementer das versehentlich mit-aufmacht.

**Migrations:**

- Eine neue Alembic-Migration `XXXX_block_n_agent_and_finding_cause.py` mit acht `add_column` (drei auf `servers`, fünf auf `findings`, alle nullable, kein Backfill). `alembic downgrade -1 && upgrade head` muss grün bleiben. Bewusst eine einzige Migration für beide Tabellen, damit Roll-Back atomar ist und Reviewer nicht zwei separate Migrationen in einem PR prüfen muss.

**Tests (neu):**

- `tests/views/test_agent_install.py` — `GET /install.sh` → 200, Content-Type `text/x-shellscript`, enthält `SECSCAN_URL` und `RECOMMENDED_TRIVY_VERSION` als eingebackene Strings; ETag-Roundtrip; `GET /agent/files/secscan-agent.sh` → 200; `GET /agent/files/../../etc/passwd` → 404 (Whitelist-Check); `GET /agent/version` → JSON-Shape-Check.
- `tests/services/test_agent_version.py` — `version_lt` mit semver-Edge-Cases (0.1.0 < 0.2.0, 0.2.0 < 0.2.1, 0.10.0 > 0.9.0, ungültige Strings → False/safe).
- `tests/views/test_server_detail_outdated_pills.py` — Pills rendern oder nicht, je nach Server-Zustand.
- `tests/api/test_scans_envelope_trivy_version.py` — Envelope mit `trivy_version` setzt das Feld; ohne `trivy_version` bleibt es None (Forward-Compat).
- `tests/api/test_scans_cause_fields.py` — Envelope mit `PkgIdentifier.PURL`/`SeveritySource`/`VendorIDs` und `Result.Target`/`Result.Type` persistiert die fünf Finding-Spalten korrekt. Edge-Cases: PURL fehlt (Finding bleibt mit `package_purl=NULL`), `VendorIDs` mit 100 Einträgen (Trim auf 32), `SeveritySource` mit non-ASCII (Reject).
- `tests/services/test_findings_ingest_cause_mapping.py` — `_extract_cause_fields()` Roundtrip: real-life Trivy-Fixture-Snippets für deb/rpm/apk/gobinary/jar/npm produzieren erwartete `result_type`-Werte und `target_path`-Strings.
- `tests/services/test_agent_strip.py` — Bash-Unit-Test via `bats` oder Python-Subprocess-Test: `jq 'del(.Results[].Packages)'` auf einer Real-Fixture lässt `Vulnerabilities`-Anzahl unverändert, lässt `PkgIdentifier`/`SeveritySource`/`VendorIDs` im Vuln-Block intakt, reduziert Bytes-Größe um >= 60%.
- `tests/services/test_finding_display.py` — `format_finding_cause()` rendert für `result_type=ubuntu` das Distro-Format, für `result_type=gobinary` das Pfad-Format, für `target_path=NULL` (Alt-Daten) den `@`-Split-Fallback aus `package_name`.
- `tests/views/test_findings_section_cause_row.py` — Findings-Tabelle rendert für eine Vuln mit `result_type=gobinary` und `target_path=/usr/local/bin/kubelet` die erwartete Sub-Zeile inkl. Mono-Font für den Pfad. Tooltip enthält `PURL: pkg:golang/...`.
- `tests/integration/test_installer_ubuntu_24.py` und `tests/integration/test_installer_almalinux_9.py` — Docker-basierte E2E: minimaler Container, `curl … | bash` mit gemockten Backend-Responses, verifiziert dass `/etc/systemd/system/secscan-agent.timer` existiert und `/etc/secscan/agent.env` korrekt geschrieben ist. Diese zwei Tests stehen unter `@pytest.mark.integration` und laufen nicht in der normalen Suite — nur in einer separaten CI-Stage / `make test-installer` (manueller Trigger).
- Adversarial: `tests/adversarial/test_agent_install_no_master_key_in_url.py` — `GET /install.sh` enthält keine Auth-Header-Beispiele mit Master-Key in der URL. `tests/adversarial/test_agent_files_path_traversal.py` — `/agent/files/../../passwd` → 404. `tests/adversarial/test_purl_xss.py` — `PkgIdentifier.PURL` mit `<script>`-Payload rendert escaped im Tooltip. `tests/adversarial/test_vendor_ids_injection.py` — `VendorIDs` mit Control-Chars/NUL werden im Validator verworfen.

**Tests (geändert oder gelöscht):**

- Falls es bestehende View-Tests für `servers/detail.html` gibt, die die Header-Pill-Reihe assertieren: erweitern um die drei neuen Pills.
- Keine bestehenden Tests werden gelöscht.

**Image-Größe:**

- Backend-Image bleibt unverändert; das Installer-Template ist ein normales Jinja-File. Erwarteter Image-Size-Delta: < 50 KB.

**Spec-Updates:**

- `ARCHITECTURE.md §11` umschreiben: Installer-Flow als Standardpfad, alter „klone Repo"-Pfad bleibt als Power-User-Variante erwähnt. UI-Indikator als Forward-Compat-Mechanismus ergänzen (heute steht dort nur 400-Fehler).
- `ARCHITECTURE.md §6` (Envelope-Schema): `host.trivy_version` als optional ergänzen.
- `docs/decisions/README.md` Index-Tabelle: ADR-0021 ergänzen.
- `CHANGELOG.md`: v0.7.0-Eintrag mit Verweis auf ADR-0021 und den neuen Endpoints, Agent-Bump 0.1.0 → 0.2.0, neue DB-Spalten.

## Re-Open-Trigger

- **LLM-basierte Update-Befehl-Empfehlung.** Block-G-Stack liefert bereits den AsyncOpenAI-Wrapper plus Streaming-Chat. Ein eigener Block kann einen „Wie fixe ich das"-Snippet pro Finding via LLM-Anfrage bauen: Input ist `(server.tags, server.os_pretty_name, finding.result_type, finding.package_purl, finding.package_name, finding.installed_version, finding.fixed_version, finding.target_path, cluster_of_findings)`, Output ist ein begründeter Befehl plus Caveats („Diese Library ist eingebettet in k3s; Update via k3s-Release X.Y.Z; Service-Restart `systemctl restart k3s` nötig"). Eigene ADR mit Token-Budget-Plan, Caching-Strategie (gleicher Befehl für gleiches Cluster-Tuple), und UI-Trigger (per-Finding-Button vs. Bulk-Auto-Run).
- **VendorSeverity-Disagreement-Indikator.** Pill „NVD: critical, Vendor (ubuntu): low" als zusätzliches Triage-Signal. Daten sind verfügbar (Trivys `VendorSeverity`-Map), aber wir extrahieren sie heute nicht. Eigene ADR mit UI-Vorschlag, evtl. zusätzlicher `severity_disagreement: bool` Computed-Column.
- **PURL-Parser für strukturierte Filter.** Sobald das LLM-Update-Befehl-Feature kommt oder das Dashboard auf „filter by purl distro family" erweitert wird, lohnt sich ein `app/services/purl_parser.py`. Heute ist PURL ein opaker String. Trigger: erstes Feature, das PURL-Komponenten braucht.
- **UNIQUE-Constraint von `package_name` auf `(package_name, target_path)` umstellen.** Sobald alle aktiven Server konsolidiert sind (typisch nach einem Scan-Intervall, max 7 Tagen) und keine retire-Server-Findings mehr mit `target_path=NULL` für lang-pkgs existieren, kann die Constraint sauber umgestellt und der `@target`-Suffix im `package_name` entfernt werden. Eigene ADR.
- **Container-/k8s-Hosts** als Scan-Ziel werden in den Out-of-Scope-Listen für `trivy image` und Code-Repos klar exkludiert; falls trotzdem ein DaemonSet-Pattern gewünscht wird, eigene ADR.
- **Auth auf `/install.sh`** falls Operatoren Skript-Hosting nicht öffentlich haben wollen (z.B. internes Netz mit externer Backend-Adresse). Lösung wäre IP-Allowlist auf nginx/Caddy-Ebene und/oder ein einmaliger Token-Parameter — eigene ADR mit Threat-Modell.
- **Signed-Releases.** Aktueller Installer prüft SHA256 von Trivy gegen die `*.sha256`-Datei des Releases, aber das Agent-Skript selbst hat keine Signatur. Bei „Backend kompromittiert"-Szenario wäre eine Detached-Signature (Sigstore/Cosign) sinnvoll — aktuell out-of-scope, eigene ADR.
- **Distro-Pakete** falls jemand wirklich `apt install secscan-agent` will. Bedeutet COPR/OBS/Aptly-Pipelines plus GPG-Key-Verteilung. Eigene ADR.
- **Aggregat-Counter „X agents outdated"** auf dem Dashboard als sechste KPI-Card. Aktuell out-of-scope; falls die per-Server-Pills nicht ausreichen, neuer Block mit ADR.
- **Trivy-Version-Self-Update** als optionaler Sub-Befehl `secscan-agent.sh upgrade-trivy`. Out-of-Scope wegen Auto-Update-Risiko; Operator führt den Installer-Einzeiler nochmal aus, das überschreibt `/opt/secscan/bin/trivy` mit der aktuell empfohlenen Version.
- **Multi-Architektur** (`linux/arm64`, `linux/arm/v7`). Aktueller Installer mappt `aarch64`. `armv7l` wird nicht supportet — eigene ADR falls jemand Raspberry-Pi-Hosts scannen will.
