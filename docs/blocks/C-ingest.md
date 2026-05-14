# Block C — Ingest, Server-Verwaltung und Agent-E2E

## Ziel

Server registrieren sich per Master-Key und bekommen einen Server-Key. Der Agent pusht gzipped Trivy-Scans, der Server validiert (Auth-vor-Body-Parse), parst durch ein striktes Pydantic-Schema, extrahiert alle Triage-Felder (CVSS/EPSS/KEV/CWE/Attack-Vector), läuft Dedup/Resolve und persistiert nur die Findings (kein Roh-JSON). Server-Verwaltung mit Key-Rotation und Retirement-Workflow funktioniert. Nach Block C kann ein realer Server registriert werden, sein `secscan-agent.sh` läuft erfolgreich gegen den lokalen Backend.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §5 (Datenmodell — `findings`, `scans`-Buchhaltung, Dedup/Resolve)
- `ARCHITECTURE.md` §6 (API — Wrapper-Envelope, Endpoints, Content-Encoding gzip)
- `ARCHITECTURE.md` §9 (DoS — Auth-vor-Body-Parse, gzip-Bomb-Schutz)
- `ARCHITECTURE.md` §10 (Input-Validierung — Pydantic, Regex-Whitelists für alle Felder)
- `ARCHITECTURE.md` §11 (Client-Agent — vorhandene Bash-Skripte unter `agent/`)
- `ARCHITECTURE.md` §13 (Audit-Log — Action-Liste)
- `ARCHITECTURE.md` §14 (Stale-Detection — Server und Trivy-DB)
- `tests/fixtures/trivy/README.md` und alle Fixture-Dateien
- `docs/decisions/0005-no-raw-json-storage.md`, `0007-gzip-compression.md`, `0008-secrets-out-of-mvp.md`

## Aufgaben

1. Pydantic-Envelope-Schema in `app/schemas/scan_envelope.py`: `Envelope`, `HostBlock`, `TrivyReport`, `TrivyResult`, `TrivyVulnerability` mit allen Feld-Constraints aus §10. `extra="ignore"` für Forward-Compat.
2. Gzip-Streaming-Decompress in `app/middleware/gzip.py` mit hartem Decompress-Bound (Default 100 MB, env `SECSCAN_MAX_DECOMPRESSED_MB`).
3. `app/api/register.py`: `POST /api/register` mit Master-Key-Verifikation (Argon2id), Server-Key-Generierung (256-bit Token, base64), SHA-256-Hash in `servers.api_key_hash`. Klartext einmal in Response, danach nicht abrufbar.
4. `app/api/scans.py`: `POST /api/scans` in strikter Reihenfolge (1) Bearer lesen, (2) Token gegen Hash mit `compare_digest`, (3) bei 401 sofort exit, (4) gzip-Decompress mit Bound, (5) Pydantic-Parse mit 422 bei Validierungsfehler, (6) Findings-Extraktion, (7) Dedup-Upsert, (8) Resolve-Phase, (9) Audit-Event, (10) 202 Response.
5. `app/services/findings_ingest.py`: Dedup-Logik via `INSERT … ON CONFLICT … DO UPDATE`, Resolve-Logik als `UPDATE … WHERE NOT IN (current_set)`. Trivy-DB-Felder aus `Metadata.DataSource`/`Metadata.UpdatedAt` extrahieren und in `servers` denormalisieren.
6. `app/api/keys.py`: `POST /api/keys/rotate` (Master- oder Server-Key rotieren).
7. `app/views/servers.py`: Server-Listen-View in Settings, Revoke-Knopf, Retire-Knopf mit Bestätigung (Findings auf resolved markieren, Audit-Event mit Liste).
8. Templates: `settings/servers.html` mit Tabelle (Name, Tags-Pills, Last-Seen, Status, Actions).
9. Adversarial-Tests in `tests/adversarial/`: NUL-Bytes, Skript-Tags in CVE-Title, EPSS=1.5, übergroße References-Liste, ungültige CVE-IDs, manipuliertes Host-Block, gzip-Bomb (1 KB → 200 MB), Body-ohne-Auth über 10 MB.
10. E2E-Test: `secscan-agent.sh` gegen lokalen Server mit Real-Fixture als Trivy-Output-Stub.

## Was NICHT in diesem Block

- Kein Dashboard (Block D).
- Keine Findings-Detail-View (Block E).
- Keine Bulk-Operationen (Block F).
- Keine LLM-Anbindung (Block G).

## Definition of Done

### Datei-Existenz

- [ ] `app/schemas/scan_envelope.py`, `app/middleware/gzip.py`
- [ ] `app/api/register.py`, `app/api/scans.py`, `app/api/keys.py`
- [ ] `app/services/findings_ingest.py`
- [ ] `app/views/servers.py`, Template `settings/servers.html`
- [ ] `tests/api/test_register.py`, `tests/api/test_scans_ingest.py`, `tests/api/test_keys_rotate.py`
- [ ] `tests/adversarial/` mit mindestens 8 Test-Cases (siehe Aufgabe 9)

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] grep: `compare_digest` in `app/api/scans.py` (Auth-Vergleich)
- [ ] grep: `extra="ignore"` in `app/schemas/scan_envelope.py`
- [ ] grep: `INSERT.*ON CONFLICT` ODER `merge(` in `app/services/findings_ingest.py`

### Tests

- [ ] cmd: `pytest tests/api/test_register.py -v` → alle grün
- [ ] cmd: `pytest tests/api/test_scans_ingest.py -v` → alle grün, inkl. Dedup über Re-Scans, Resolve bei verschwundenen CVEs, Trivy-DB-Extraktion
- [ ] cmd: `pytest tests/api/test_keys_rotate.py -v` → alle grün
- [ ] cmd: `pytest tests/adversarial/ -v` → alle grün
- [ ] cmd: `pytest tests/services/test_findings_ingest.py -v` → mit echter Fixture `tests/fixtures/trivy/ubuntu-22.04-rke2.json`: 306 Vulns parsed, korrekte Class-Verteilung (296 lang-pkgs, 10 os-pkgs)
- [ ] cmd: `pytest -v --cov=app --cov-fail-under=80` → exit 0

### Migration und DB-Verhalten

- [ ] cmd: `alembic downgrade -1 && alembic upgrade head` → exit 0 (kein Block-B-Schemabruch)
- [ ] cmd: nach 2× Re-Scan derselben Fixture: `findings`-Tabelle hat keine Duplikate (UNIQUE-Constraint hält)

### Verhaltens-Checks (gegen lokalen Server)

- [ ] cmd: `bash agent/secscan-register.sh http://localhost:8000 testhost <<< "$MASTER_KEY"` → druckt Server-Key, Server taucht in `/settings/servers` auf
- [ ] cmd: `SECSCAN_URL=http://localhost:8000 SECSCAN_API_KEY=<key> bash agent/secscan-agent.sh` mit `SECSCAN_TRIVY_PATH` auf einem Mock-Skript der die Fixture ausgibt → 202, Findings sichtbar in DB
- [ ] cmd: `curl -X POST http://localhost:8000/api/scans -H 'Authorization: Bearer falsch' --data 'x' -i` → 401 in <50ms (Auth ist VOR Body-Parse)
- [ ] cmd: gzip-Bomb: `python -c "import gzip; print(gzip.compress(b'A'*200_000_000)[:5000])" | curl -X POST ... -H 'Content-Encoding: gzip' --data-binary @-` → 413 mit Decompress-Limit-Hinweis
- [ ] manual: `tests/adversarial/run_adversarial.sh` durchläuft alle Bad-Input-Pfade gegen lokalen Server

### Dokumentation

- [ ] `STATE.md` aktualisiert: Block C → completed, Block D → aktueller Block.
- [ ] Etwaige neue Erkenntnisse aus den realen Fixtures als ADR oder als Kommentar im Pydantic-Schema dokumentiert.
