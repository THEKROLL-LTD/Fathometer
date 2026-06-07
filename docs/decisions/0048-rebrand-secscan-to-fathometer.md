# ADR-0048 — Technischer Rename: `secscan` → Fathometer (Env-Prefix, Pfade, Volume, Skripte)

**Status:** Akzeptiert · **Datum:** 2026-06-06 · **Block:** (eigener Rename-Durchgang)

Bezug: [ADR-0033](0033-brand-identity-fathometer.md) (Brand-Identity „Fathometer" — legte den Marken-Namen fest, ließ den technischen Codenamen `secscan` aber bewusst stehen), [ADR-0021](0021-agent-bootstrap-installer.md) (Agent-Bootstrap-Installer, Skript-Namen + Pfade), [ADR-0013](0013-fernet-kdf.md) (`SECSCAN_ENCRYPTION_KEY`).

## Kontext

Die Marke ist seit ADR-0033 **Fathometer** — Wordmark, Logo, Page-Titles, Footer-GitHub-Link (`THEKROLL-LTD/fathometer`) und seit dieser Doku-Runde auch README und alle user-sichtbaren UI-Strings tragen den Namen. Die **technische Schicht** ist dagegen noch durchgängig `secscan`: ~74 `SECSCAN_*`-Environment-Variablen, die Pfade `/etc/secscan` und `/opt/secscan`, das Docker-Volume `secscan-db`, Service-/Container-Namen, die Agent-Skripte `secscan-agent.sh` / `secscan-register.sh` und die Postgres-Default-Credentials `secscan`.

Stand 2026-06-06: **1.268 Treffer über 758 Dateien** (inkl. Tests, ADRs, Block-Specs, Fixtures, Docs).

User-Entscheidung 2026-06-06: **Vollständiger technischer Rename auf Fathometer.** Env-Prefix `FM_`, **harter Schnitt ohne Back-Compat**, **alles** umbenennen inkl. Pfade, DB-Volume (mit Daten-Migration) und Agent-Skript-Dateinamen. Ausführung erst nach Freigabe dieses ADR + Plans.

## Entscheidung

1. **Env-Prefix `SECSCAN_` → `FM_`** für alle Variablen. Pydantic-`env_prefix` in `app/config.py` (`env_prefix="SECSCAN_"` → `"FM_"`) zieht die Field-Reads automatisch; alle **hartkodierten** `SECSCAN_`-Vorkommen (Error-Messages, Docstrings/Kommentare, `.env.example`, `docker-compose.yml`, Agent-Skripte, Installer-Template, Tests) werden manuell mitgezogen.
2. **Harter Schnitt, keine Back-Compat.** Es gibt **keinen** Fallback auf alte `SECSCAN_`-Namen oder `/etc/secscan`-Pfade. Ab Deploy gilt ausschließlich der neue Name. Bestehende `.env` und alle Agent-`agent.env` müssen migriert / Hosts neu registriert werden (siehe Migrations-Plan).
3. **Pfade umbenennen:** `/etc/secscan` → `/etc/fathometer`, `/opt/secscan` → `/opt/fathometer` (inkl. `bin/`, `agent.env`, `api-key`).
4. **Agent-Skripte umbenennen:** `secscan-agent.sh` → `fathometer-agent.sh`, `secscan-register.sh` → `fathometer-register.sh`. `lib_host_state.sh` und `install.sh` behalten ihre Namen (generisch). Die `/agent/files/<name>`-Whitelist in `app/views/agent_install.py` wird entsprechend angepasst.
5. **Docker:** Service `secscan-llm-worker` → `fathometer-llm-worker`, Volume `secscan-db` → `fathometer-db`, Postgres-Default-Credentials `POSTGRES_USER/PASSWORD/DB` `secscan` → `fathometer`. Volume-Rename = **Daten-Migration** (pg_dump/restore), kein In-Place-Rename.
6. **systemd-Units / Cron:** Unit-Namen `secscan-agent.timer/.service` → `fathometer-agent.*`; im Installer-Template (`app/templates/agent/install.sh.j2`) und im Power-User-Pfad mitgezogen.
7. **Distributions-Name:** `pyproject.toml` `name = "secscan"` → `"fathometer"` (Import-Package heißt bereits `app`, kein Code-Import betroffen; `secscan.egg-info` wird beim Reinstall neu erzeugt).
8. **Agent-Version-Bump:** `CURRENT_AGENT_VERSION` `0.4.0` → `0.5.0` (config.py + `fathometer-agent.sh` synchron, da die Selbst-Update-Logik beide vergleicht). Markiert den Rebrand-Release.
9. **Docs-Scope (Repo-Konvention):** Aktualisiert werden **lebende** Docs — `CLAUDE.md`, `ARCHITECTURE.md`, `README.md`, `docs/operations.md`, `docs/techdebt.md`. **Historische Records bleiben unangetastet** (analog ADR-0045 → ADR-0033, abgelöst statt überschrieben): `docs/decisions/` (alte ADRs), `docs/blocks/`, `docs/tickets/`, `CHANGELOG.md`, `docs/design/`. Dieses ADR ist der maßgebliche Rename-Record; `grep secscan` liefert danach bewusst noch Treffer in diesen historischen Dateien.
10. **Repo-Verzeichnis** `code_local/secscan` → optional `code_local/fathometer` (lokaler Move, separat, Operator-Sache).

## Token-Mapping

| Kategorie | Alt | Neu |
|---|---|---|
| Env-Prefix (Pydantic) | `SECSCAN_` | `FM_` |
| Beispiel-Vars | `SECSCAN_ENCRYPTION_KEY`, `SECSCAN_SECRET_KEY`, `SECSCAN_PUBLIC_URL`, `SECSCAN_DATABASE_URL`, `SECSCAN_MASTER_KEY`, `SECSCAN_API_KEY`, `SECSCAN_URL`, `SECSCAN_SERVER_NAME`, `SECSCAN_UNATTENDED`, … (~74) | `FM_ENCRYPTION_KEY`, `FM_SECRET_KEY`, `FM_PUBLIC_URL`, `FM_DATABASE_URL`, `FM_MASTER_KEY`, `FM_API_KEY`, `FM_URL`, `FM_SERVER_NAME`, `FM_UNATTENDED`, … |
| Conf-Pfad | `/etc/secscan/{agent.env,api-key,env}` | `/etc/fathometer/{agent.env,api-key,env}` |
| Bin-Pfad | `/opt/secscan/bin/` | `/opt/fathometer/bin/` |
| Agent-Skripte | `secscan-agent.sh`, `secscan-register.sh` | `fathometer-agent.sh`, `fathometer-register.sh` |
| Generische Skripte | `lib_host_state.sh`, `install.sh` | _unverändert_ |
| Docker-Service | `secscan-llm-worker` | `fathometer-llm-worker` |
| Docker-Volume | `secscan-db` | `fathometer-db` |
| Postgres-Creds (Default) | `secscan` (user/pass/db) | `fathometer` |
| systemd-Units | `secscan-agent.{timer,service}` | `fathometer-agent.{timer,service}` |
| GitHub-Repo | `THEKROLL-LTD/fathometer` | _bereits umgestellt_ |

## Migrations-Plan (phasiert)

**Phase 0 — Branch.** Branch `feat/rebrand-fathometer`. Inventar-Snapshot (`grep -rniE secscan`) als Vorher-Zähler. Kein DB-Backup nötig — der Operator macht einen Clean-Wipe + Fresh-Start (siehe Phase 4-Hinweis).

**Phase 1 — Code & Config (atomar, ein Commit).**
- `app/config.py`: `env_prefix="FM_"`; alle hartkodierten `SECSCAN_`-Strings in Error-/Hint-Messages.
- `docker-compose.yml`: Env-Keys, Service-Name, Volume-Name, Postgres-Defaults.
- `.env.example`: alle Keys auf `FM_`.
- `app/templates/agent/install.sh.j2` + `agent/*.sh`: Pfade, Skript-Namen, env-Keys, Unit-Namen.
- `app/views/agent_install.py`: `_AGENT_FILE_WHITELIST` auf `fathometer-*.sh`; Datei-Umbenennung im `agent/`-Verzeichnis.
- Routen/Strings, die Skript-Dateinamen referenzieren.

**Phase 2 — Tests mitziehen.** Alle Test-Assertions/Fixtures, die `SECSCAN_`, Pfade oder Skript-Namen erwarten. **Quality-Gates lokal:** `ruff check`, `ruff format --check`, `mypy app/`, `shellcheck` der Agent-/Installer-Skripte, `pytest` Default-Selektion (Pure-Unit). Heavy-Suiten (`db_integration`/`acceptance`/`integration`) nur auf ausdrückliche User-Anweisung pro Lauf (CLAUDE.md).

**Phase 3 — Docs.** `CLAUDE.md`, `ARCHITECTURE.md`, ADRs/Block-Specs, `docs/operations.md`, `README.md` (env-Var-Beispiele) auf neue Namen. Verifikation: `grep -rniE "secscan"` liefert nur noch bewusst belassene historische Erwähnungen in alten ADRs (oder null).

**Phase 4 — entfällt.** Keine Daten-Migration. Der Operator macht einen **Clean-Wipe**: alte Instanz + Volume(s) deinstallieren/löschen, neue `.env` mit `FM_*`-Keys + `POSTGRES_*=fathometer` schreiben, `docker compose up -d --build` mit frischem `fathometer-db`-Volume, `alembic upgrade head`, Setup-Wizard neu durchlaufen (neuer Master-Key).

**Phase 5 — Agents auf den Hosts (Operator, manuell).** Pro Host den Installer **neu** ausführen (`sudo bash <(curl -fsSL https://fathometer.example.com/install.sh)`) — legt `/etc/fathometer/agent.env` + `fathometer-agent.*`-Units an, registriert gegen den neuen Master-Key (Fresh-Start = neue DB, also neue Server-Keys). Alte `/etc/secscan`, `/opt/secscan` und `secscan-agent.*`-Units manuell entfernen.

## Konsequenzen

- **Breaking ab Deploy.** Ohne neue `.env` startet die App nicht (fehlende `FM_ENCRYPTION_KEY`). Clean-Wipe + Fresh-Start (Phase 4) und Agent-Re-Install (Phase 5) sind Pflicht.
- **Keine Daten-Migration** (bewusst: Fresh-Start). Bestehende Findings/History gehen verloren — vom Operator so gewählt.
- **Jeder Host** muss einmalig neu installiert + registriert werden. Bei vielen Hosts via Ansible/unattended (`FM_UNATTENDED=1`).
- Großer Diff (~1.268 Stellen), aber reiner Identifier-/String-Touch ohne Logik-Umbau — gut reviewbar, da mechanisch.
- `tests/test_ui_language.py` ist nicht betroffen (scannt deutsche Marker, nicht `secscan`).

## Verworfen

- **Back-Compat-Fallback** (alte `SECSCAN_`-Namen als Zweitquelle lesen): vom User abgewählt („harter Schnitt"). Hätte den Schnitt weicher gemacht, aber dauerhaften Doppel-Code und Verwirrung erzeugt.
- **Volume-Name behalten** (`secscan-db` bleibt): vom User abgewählt („alles umbenennen"). Beim Fresh-Start ohnehin kostenlos umbenennbar.
- **Kürzere/andere Prefixes** (`FATHOMETER_`, `FATHO_`): `FM_` gewählt (knapp, kollisionsarm im Code).
- **Repo-/Package-Rename im selben Durchgang**: Package ist schon `app`; Repo-Verzeichnis-Move ist ein separater, risikoarmer lokaler Schritt.

## Re-Open-Trigger

- Falls sich `FM_` als zu generisch/kollisionsanfällig erweist (Konflikt mit fremden Env-Vars in geteilten Umgebungen): neue ADR für einen distinkteren Prefix.
