# Block B — Datenmodell, Setup-Wizard und Auth

## Ziel

Vollständiges Datenmodell als SQLAlchemy + Alembic-Migration, First-Boot-Wizard `/setup` zum initialen Konfigurieren, Admin-Login mit Argon2id, Tag-Verwaltung. Nach Block B kann man die App initial konfigurieren, sich einloggen und Tags pflegen — Dashboard ist noch leer.

## Vorbereitung — zu lesende Sektionen

- `ARCHITECTURE.md` §5 (Datenmodell — alle Tabellen mit Feldern und Constraints)
- `ARCHITECTURE.md` §7 (UI — `/setup`, `/login`, Settings-Tag-Verwaltung)
- `ARCHITECTURE.md` §8 (Auth — Argon2id, Single-User, Master-Key)
- `ARCHITECTURE.md` §10 (Input-Validierung — Tag-Regex, ORM-only)
- `docs/decisions/0004-single-user-auth.md`, `0006-no-forced-comments.md`

## Aufgaben

1. SQLAlchemy-Models in `app/models.py`: `users`, `servers`, `scans`, `tags`, `server_tags`, `findings`, `finding_notes`, `llm_conversations`, `llm_messages`, `llm_conversation_findings`, `audit_events`, `settings`. Alle Felder, Enums (`Severity`, `FindingType`, `FindingClass`, `FindingStatus`, `AttackVector`), Indizes (siehe §5 "Indizes") und Generated-Columns (`has_fix`).
2. Alembic-Migration mit allen Tabellen und Indizes.
3. `app/settings_service.py`: Singleton-Pattern, Lazy-Init bei erstem Request, `setup_completed_at`-Flag.
4. `app/auth.py`: Flask-Login, Argon2id-Hash (Cost-Parameter aus pydantic-settings), `hmac.compare_digest` für Master-Key/Server-Key.
5. `app/views/setup.py`: drei Wizard-Schritte (Admin-Account, Master-Key generieren+anzeigen, Defaults wählen). `/setup` ist nur erreichbar wenn `setup_completed_at IS NULL`.
6. `app/views/auth.py`: `/login`, `/logout` mit Rate-Limit aus §9.
7. `app/views/settings.py`: Tag-CRUD-Routen plus Tag-Verwaltungs-Template.
8. Templates: `base.html` (mit Theme-Toggle aus Block A), `setup/step{1,2,3}.html`, `login.html`, `settings/tags.html`. CSRF-Tokens auf allen Forms via `flask-wtf`.
9. Audit-Log-Helper `app/audit.py` mit zentraler `log_event(action, target_type, target_id, comment=None, metadata=None)`-Funktion.

## Was NICHT in diesem Block

- Keine Server-Registrierungs-API (Block C).
- Keine Scan-Ingest-API (Block C).
- Kein Dashboard (Block D).
- Keine LLM-Settings-Felder im UI (Block G — Skelett im Datenmodell genügt).

## Definition of Done

### Datei-Existenz

- [ ] `app/models.py` mit allen 12 Tabellen aus §5
- [ ] `alembic/versions/<rev>_initial_schema.py`
- [ ] `app/settings_service.py`, `app/auth.py`, `app/audit.py`
- [ ] `app/views/setup.py`, `app/views/auth.py`, `app/views/settings.py`
- [ ] Templates: `setup/step1.html`, `setup/step2.html`, `setup/step3.html`, `login.html`, `settings/tags.html`

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] grep: keine `text(` Aufrufe ohne `:param`-Bind in `app/`
- [ ] grep: `Argon2idHasher` oder `argon2.PasswordHasher` in `app/auth.py`
- [ ] grep: `hmac.compare_digest` in `app/auth.py`
- [ ] grep: `setup_completed_at` Check in `app/views/setup.py`

### Migration-Smoke

- [ ] cmd: `docker compose exec app alembic upgrade head` → exit 0
- [ ] cmd: `docker compose exec app alembic downgrade base && docker compose exec app alembic upgrade head` → exit 0
- [ ] cmd: `docker compose exec db psql -U secscan -c "\dt"` → 12 Tabellen sichtbar
- [ ] cmd: `docker compose exec db psql -U secscan -c "\d findings"` → enthält `cvss_v3_score`, `epss_score`, `is_kev`, `cwe_ids`, `attack_vector`, `finding_class`, `has_fix`

### Tests

- [ ] cmd: `pytest tests/auth/ -v` → alle grün (Login-Erfolg, Login-Fehler, Rate-Limit, Logout, Session-Timeout)
- [ ] cmd: `pytest tests/setup/ -v` → alle grün (Wizard-Step-Reihenfolge, Master-Key-Anzeige nur 1×, Lock nach Abschluss)
- [ ] cmd: `pytest tests/audit/ -v` → log_event schreibt korrekte Spalten
- [ ] cmd: `pytest tests/adversarial/test_tag_validation.py -v` → ungültige Tag-Namen werden abgelehnt (Regex aus §10)

### Manuelle Verifikation

- [ ] `/setup` durchklicken: Admin anlegen, Master-Key wird genau einmal angezeigt mit "Habe ich notiert"-Bestätigung, Defaults setzen, Wizard schließt sich. Screenshot unter `docs/blocks/B-evidence/setup-flow.png`.
- [ ] Nach Setup: `/setup` redirected auf `/login`.
- [ ] Login-Page funktioniert, Login mit falschem Passwort erzeugt `auth.failed`-Audit-Event.
- [ ] Tag erstellen, löschen, ungültiger Name (`Foo Bar` mit Großbuchstaben) wird abgelehnt mit klarer Fehlermeldung.

### Dokumentation

- [ ] `STATE.md` aktualisiert: Block B → completed, Block C → aktueller Block.
