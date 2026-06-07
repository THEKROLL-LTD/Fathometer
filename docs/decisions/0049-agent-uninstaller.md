## ADR-0049 — Agent-Uninstaller: lokales Skript (air-gap-first) + `/uninstall.sh`-Alias, rein lokal

**Status:** Akzeptiert · **Datum:** 2026-06-07 · **Bezug:** Ergänzt ADR-0021 (Agent-Bootstrap-Installer) um den Gegen-Lebenszyklus. ADR-0003 (Push statt Pull) bleibt unberührt. Keine Änderung an ARCHITECTURE §17 (Out-of-Scope) — Uninstall ist die symmetrische Ergänzung zum bereits spezifizierten Install, kein neues Feature-Gebiet.

## Kontext

Der Agent wird seit ADR-0021 per Einzeiler installiert:

```
sudo bash <(curl -fsSL https://fathometer.example.com/install.sh)
```

Es gibt aber **keinen Uninstaller**. Wer den Agent wieder loswerden will, muss
manuell wissen, was der Installer alles angelegt hat — über mehrere Phasen
verteilt:

- `/opt/fathometer/bin/` (trivy, `fathometer-agent.sh`, `lib_host_state.sh`, `.bak`-Backups)
- `/etc/fathometer/agent.env` (enthält den **API-Key**, mode 0600)
- `/etc/systemd/system/fathometer-agent.{service,timer}` **oder** `/etc/cron.d/fathometer-agent`
- der Trivy-DB-Cache (typisch `/root/.cache/trivy`, beim ersten Scan-Run angelegt)

Das ist Operator-Wissen, das nirgends als ausführbares Artefakt existiert.
Ein von einem `curl | sudo bash`-Tool installierter, root-laufender
systemd-Timer-Agent **muss** einen erwartbaren Uninstall-Pfad haben — das ist
State-of-the-Art (vgl. k3s `k3s-uninstall.sh`, rustup `rustup self uninstall`).

### Constraints aus dem Projekt

1. **Air-Gap ist ein First-Class-Setup** (`docs/operations.md`). Ein
   Uninstaller, der zwingend das Backend braucht, funktioniert dort nicht.
2. **Es gibt einen serverseitigen Record.** Der Host ist per `POST /api/register`
   registriert; `server_id` + API-Key liegen in der Backend-DB. Ein
   serverseitiges Deregister setzt einen neuen authentifizierten Endpoint
   voraus, den es nicht gibt.
3. **Lokal existiert quasi kein Daten-State** — nur das Secret in `agent.env`.
   „Purge vs. keep data" ist deshalb kaum relevant; Default ist vollständige
   Entfernung dessen, was der Installer mitbringt.

## Entscheidung

### Mechanismus: lokales Skript (primär) + `/uninstall.sh`-Alias (Fallback)

Ein **einziges statisches Bash-File** `agent/fathometer-uninstall.sh` ist die
Single Source of Truth. Weil der Uninstaller **keine** backend-spezifischen
Konstanten braucht — alle Pfade und Unit-Namen sind fix —, ist es kein
Jinja-Template, sondern wird byte-identisch über drei Wege ausgeliefert:

```
agent/fathometer-uninstall.sh        ← Single Source of Truth (statisch, kein .j2)
   │
   ├─ Installer dropt es nach  → /opt/fathometer/bin/fathometer-uninstall.sh   (primär, air-gap)
   ├─ /agent/files/…           → über bestehende Whitelist
   └─ /uninstall.sh            → Convenience-Alias (curl-Pipe), serviert dasselbe File
```

- **Primärer Pfad (lokal):** `sudo /opt/fathometer/bin/fathometer-uninstall.sh`.
  Der Installer (`install.sh.j2`, `download_agent_script()`) legt das Skript
  beim Install/Update mit ab. Funktioniert offline/air-gapped, kein
  Backend-Zugriff, kein „curl-to-delete"-Paradox.
- **Fallback-Pfad (Netz):** `sudo bash <(curl -fsSL .../uninstall.sh)`.
  Symmetrisch zum Install-Befehl, discoverable neben dem Install-Einzeiler,
  greift auch Alt-Installs ohne lokale Kopie. Neuer Endpoint `GET /uninstall.sh`
  serviert byte-identisch dasselbe statische File wie
  `/agent/files/fathometer-uninstall.sh` (kein Render → keine Template-Drift).

`/uninstall.sh` ist wie die anderen Installer-Endpoints **ohne Auth** und in
`_SETUP_EXEMPT_PREFIXES` — der Inhalt ist kein Geheimnis und enthält keine
host-spezifischen Daten.

### Entfernungs-Umfang: alles, was der Installer mitbringt

Default entfernt der Uninstaller **vollständig**, was der Installer anlegt:

1. **Scheduler:** `systemctl disable --now fathometer-agent.timer`, Service
   stoppen, Unit-Files löschen, `daemon-reload`, `reset-failed`. Plus
   `/etc/cron.d/fathometer-agent` (Cron-Fallback-Pfad).
2. **Files + Secrets:** `rm -rf /opt/fathometer /etc/fathometer`.
3. **Trivy-Cache:** `rm -rf ${XDG_CACHE_HOME:-/root/.cache}/trivy` —
   best-effort, abschaltbar per `--keep-cache`.

Flags: `-y` / `--yes` (bzw. `FM_UNATTENDED=1`) überspringt die Rückfrage,
`--keep-cache` behält den Trivy-DB-Cache.

### Rein lokal — kein serverseitiges Deregister

Der Uninstaller meldet den Host **nicht** beim Backend ab. Der Server-Record
bleibt bestehen und wird im UI als stale/dead sichtbar; der Operator löscht ihn
dort manuell. Als UX-Kompensation liest der Uninstaller `FM_URL` aus
`agent.env` (bevor er es löscht) und gibt am Ende den Hinweis aus, wo der Host
weiterhin gelistet ist.

Begründung: ein sauberes Deregister bräuchte einen neuen authentifizierten
`DELETE`-Endpoint plus Threat-Model (ein kompromittierter API-Key könnte sonst
fremde Hosts entfernen). Das ist ein eigenständiges Feature mit eigener
Entscheidung — siehe Re-Open-Trigger. Für den MVP-Uninstall ist die
manuelle UI-Löschung ausreichend und vermeidet die neue Angriffsfläche.

### Selbst-Löschungs-Schutz

Beim lokalen Lauf liegt das Skript unter `/opt/fathometer/bin/`, das es selbst
per `rm -rf /opt/fathometer` entfernt. Bash liest Skripte inkrementell — wird
das File mitten im Lauf gelöscht, kann das Nachladen späterer Zeilen fehlschlagen.
Mitigation: ein Self-Relocation-Guard kopiert das Skript zu Beginn nach
`mktemp` und `exec`'t von dort, falls `BASH_SOURCE` unter `$FM_PREFIX` liegt.
Beim curl-Pipe-/Process-Substitution-Lauf ist `BASH_SOURCE` `/dev/fd/*` (nicht
unter `$FM_PREFIX`) — der Guard greift dann nicht und ist auch nicht nötig.

## Begründung

**Warum lokales Skript primär und nicht nur curl-Pipe.** Air-Gap. Ein
`curl`-Pipe-Uninstaller kann auf einem vom Backend getrennten Host nicht laufen
— ausgerechnet beim Entfernen, dessen Ziel ja die Trennung vom Backend ist,
wäre Netz-Zwang absurd. Das lokale Skript ist self-contained und kennt exakt,
was installiert wurde.

**Warum trotzdem `/uninstall.sh`-Alias.** Discoverability (eine Zeile neben dem
Install-Befehl in UI/README) und Abdeckung von Alt-Installs, die das lokale
Skript noch nicht haben. Da es byte-identisch dasselbe File serviert, entsteht
keine zweite Quelle und keine Drift.

**Warum ein statisches File und kein Jinja-Template.** Der Uninstaller braucht
keine gerenderten Werte — alle Pfade (`/opt/fathometer`, `/etc/fathometer`) und
Unit-Namen sind Konstanten. Statisch = eine Quelle, drei Lieferwege, kein
Render-Pfad der driften kann (vgl. HTMX-Single-Source-Doktrin in CLAUDE.md).

**Warum Trivy-Cache standardmäßig löschen.** User-Entscheidung: „uninstall
gleich alles was wir mitbringen wieder entfernen". Der Cache ist eine Folge
unseres Agents; ein vollständiger Uninstall lässt keine Trivy-DB-Reste zurück.
`--keep-cache` als Opt-out für Operatoren, die Trivy anderweitig nutzen.

**Warum kein Deregister im MVP.** Neuer authentifizierter Endpoint +
Threat-Model wären nötig (API-Key-Missbrauch). Die manuelle UI-Löschung deckt
den Bedarf, der Uninstaller weist explizit darauf hin. Re-Open offen.

## Konsequenzen

**Code (neu):**

- `agent/fathometer-uninstall.sh` — statisches Bash-Skript (root-required,
  Self-Relocation-Guard, Confirm-Prompt, `--yes`/`--keep-cache`).
- `app/views/agent_install.py`: `fathometer-uninstall.sh` in
  `_AGENT_FILE_WHITELIST`; neue Route `GET /uninstall.sh` (`send_from_directory`,
  `text/x-shellscript`).

**Code (geändert):**

- `app/__init__.py`: `/uninstall.sh` in `_SETUP_EXEMPT_PREFIXES`.
- `app/templates/agent/install.sh.j2`: `download_agent_script()`-Loop um
  `fathometer-uninstall.sh` erweitert; Schluss-Ausgabe der Probe-Phase nennt
  den Uninstall-Befehl.

**Docs / UI:**

- `README.md`: Abschnitt „Remove a server".
- `agent/README.md`: Abschnitt „Deinstallation".
- `app/templates/settings/servers.html`: Uninstall-Hinweis im „Add a server"-Block.
- `docs/decisions/README.md`: Index-Eintrag ADR-0049.

**Tests (neu, pure-unit):**

- `tests/views/test_uninstall_sh.py` — `GET /uninstall.sh` → 200 +
  `text/x-shellscript`; `GET /agent/files/fathometer-uninstall.sh` → 200;
  Whitelist-Negativfall → 404; Content-Guard (Body enthält die erwarteten
  Removal-Targets `/opt/fathometer`, `/etc/fathometer`,
  `fathometer-agent.timer`, `/etc/cron.d/fathometer-agent`).
- shellcheck auf `agent/fathometer-uninstall.sh` (Linter-Gate).

**Bewusst NICHT:**

- Kein serverseitiges Deregister, kein `DELETE`-Endpoint.
- Kein Entfernen von `curl`/`jq`/`gzip`/`tar` (vom Installer ggf. via
  Paketmanager nachgezogen) — die könnten andere Prozesse brauchen, ihre
  Entfernung ist nicht sicher attributierbar.

## Re-Open-Trigger

- **Serverseitiges Deregister.** Authentifizierter `DELETE /api/servers/{id}`
  (Key aus `agent.env`), den der Uninstaller best-effort aufruft (air-gapped
  lautlos überspringen). Braucht Threat-Model gegen API-Key-Missbrauch
  (nur eigenen Host löschbar). Eigene ADR.
- **`install.sh --uninstall`-Flag.** Falls sich herausstellt, dass Operatoren
  Install und Uninstall lieber in einem Artefakt hätten. Aktuell verworfen
  (vereint die Schwächen des Netz-Pfads ohne Discovery-Vorteil).
- **Paket-Cleanup.** Optionales `--purge-deps`, das vom Installer gezogene
  Pakete entfernt — nur wenn verlässlich attributierbar. Aktuell out-of-scope.
