# Block AB — English UI Migration

**Spec-Quelle:** [ADR-0045](../decisions/0045-english-only-ui.md) (löst ADR-0033 §8 Phase-2-Strategie ab)
**Branch:** `feat/block-ab-english-ui`
**Zielversion:** v0.17.0
**Vorgänger:** TICKET-009 (v0.16.x, ADR-0044)
**Status:** Geplant (2026-06-04)

## Ziel

Die gesamte Operator-sichtbare UI wird englisch. Reiner String-Touch: **kein Markup-Umbau, keine Logik-Änderung, keine CSS-Änderung, keine Schema-Migration.** Jede Phase ist ein eigener Commit mit fokussierter Test-Anpassung. Am Ende verhindert ein Sprach-Sweep-Test im Default-`pytest` jeden Rückfall.

## Inventar (Stand 2026-06-04)

| Bereich | Umfang | Fundort |
|---|---|---|
| Templates deutsch/gemischt | ~60 Dateien | `app/templates/{settings,servers,findings,audit,setup,chat,_partials,_empty,dashboard,sidebar}/`, `_macros.html`, `base.html`, `base_app.html` |
| Flash-Messages | 74 `flash(`-Aufrufe, Mehrheit deutsch | `settings.py` (39), `server_settings.py` (12), `findings.py` (8), `servers.py` (8), `llm_settings.py` (3), `auth.py` (2), `setup.py` (2) |
| Form-Validator-Messages | ~40 deutsche Strings | `app/forms.py` (+ vereinzelt View-lokale Messages) |
| JS-Strings | 6 Dateien | `llm_chat.js`, `stale.js`, `sidebar.js`, `bulk_ack.js`, `bucket_bulk_ack.js`, `bulk_ack_band.js` |
| Relative-Time-Filter | `"gerade eben"`, `"vor 5min"`, `"vor 3 Tagen"` … | `app/__init__.py` (`format_relative`) |
| Chat-LLM-System-Prompt | `"Antworte auf Deutsch, …"` + deutsche Prompt-Bausteine | `app/services/llm_prompt.py` |
| Tests mit Deutsch-Assertions | unbekannt, per Sweep zu finden | `tests/` (Template-/View-/Form-Tests) |

**Achtung Transliterationen:** Deutsche Strings liegen teils ASCII-transliteriert vor (`Ungueltige`, `fuer`, `Gewaehlte`, `pruefen`) — Umlaut-Grep allein findet sie nicht. Sweep-Wortliste muss beide Formen abdecken.

**Bereits englisch (nicht anfassen):** Login, Topbar, Profile-Dropdown, Sidebar-Grundgerüst, Dashboard-Pane, Footer (Block W); Agent-/Installer-Shell-Strings (ADR-0021); Risk-Band-/State-Labels (ADR-0022); Pass-2-LLM-Prompts (`llm_prompts.py`, ADR-0043).

## Übersetzungs-Glossar (verbindlich, für Konsistenz)

| Deutsch (heute) | Englisch (Ziel) |
|---|---|
| `Ungueltige Eingabe.` | `Invalid input.` |
| `Ungueltiger CSRF-Token.` | `Invalid CSRF token.` |
| `… gespeichert.` | `… saved.` |
| `… geloescht.` / `… entfernt.` | `… deleted.` / `… removed.` |
| `… widerrufen.` | `… revoked.` |
| `Server nicht gefunden.` | `Server not found.` |
| `Keine offenen Findings …` | `No open findings …` |
| `Notiz darf nicht leer sein.` | `Note must not be empty.` |
| `Gewaehlte Group existiert nicht (mehr).` | `Selected group no longer exists.` |
| `Scan-Intervall muss zwischen 1 und 168 Stunden liegen.` | `Scan interval must be between 1 and 168 hours.` |
| `Abgemeldet.` | `Logged out.` |
| `Login fehlgeschlagen.` | `Login failed.` |
| `gerade eben` / `vor {n}min` / `vor {n}h` / `vor {n} Tagen` | `just now` / `{n}m ago` / `{n}h ago` / `{n}d ago` |
| `Anlegen` / `Speichern` / `Abbrechen` / `Loeschen` | `Create` / `Save` / `Cancel` / `Delete` |
| `Einstellungen` / `Gruppen` | `Settings` / `Groups` |

Ton: knapp, imperativ, lowercase-Doctrine der Brand beachten wo die Surface das heute schon tut (Login/Dashboard-Stil aus Block W ist die Referenz). Keine Höflichkeitsfloskeln (`Bitte …` ersatzlos streichen, z.B. `Ungueltige Eingaben. Bitte Felder pruefen.` → `Invalid input. Check the fields.`).

## Phasen

### Phase A — Querschnitt: Filter, Forms, Shared-Templates

- `app/__init__.py`: `format_relative` auf englischen Output (`just now`, `5m ago`, `2h ago`, `3d ago`, `2mo ago`, `1y ago`). Alle Aufrufer sind Templates — Output-Format-Tests anpassen.
- `app/forms.py`: alle Validator-/Error-Messages englisch (geteilte Konstanten zuerst).
- `app/templates/base.html`, `base_app.html`, `_macros.html`, `_partial_shell.html`, `_empty/*` (3 Dateien): Restdeutsch raus.
- Tests: Form-Message-Assertions + Relative-Time-Tests umstellen.

### Phase B — Flash- und View-Messages

- Alle 74 `flash(`-Aufrufe + View-lokale Error-Strings in `app/views/*.py` gemäß Glossar.
- Audit-Event-Typen/Keys (`group.created` etc.) sind Bezeichner, **nicht anfassen**.
- Tests: View-Tests mit Flash-Assertions umstellen.

### Phase C — Settings-Surfaces

- `app/templates/settings/*` (10 Dateien inkl. `_shell.html`-Nav: „Gruppen" → „Groups"), `app/templates/servers/settings.html`, `_tag_editor.html`.
- Tests: Settings-Template-Tests.

### Phase D — Server-Detail + Findings (größte Phase)

- `app/templates/servers/*` (detail.html, Sections, `_partials/*`-Fragmente), `app/templates/findings/*` (index, Modals, Notes-Thread), `app/templates/_partials/*` (Band-Sections, Bucket-/Group-Tables, Bulk-Ack-Modals, `finding_inline_body.html`, Pills, Skeletons).
- **OOB-Single-Source-Pattern beachten:** Strings nur im jeweiligen Single-Source-Partial ändern; Drift-Regression-Tests müssen unverändert grün bleiben (struktureller Vergleich — Klassen/IDs unangetastet).
- Tests: Template-/Fragment-Tests mit String-Assertions.

### Phase E — Audit, Setup-Wizard, Chat

- `app/templates/audit/list.html`, `app/templates/setup/*` (4 Dateien), `app/templates/chat/conversation.html`, `app/templates/dashboard/*`-Restdeutsch (einzelne Strings, Surface ist seit Block W überwiegend englisch).
- `app/services/llm_prompt.py`: Chat-System-Prompt komplett englisch (`Antworte auf Deutsch` → englische Antworten); Injection-Guard-Text mitübersetzen. **Invarianten:** Marker-Konstanten `TRIVY_DATA_START`/`TRIVY_DATA_END` und der Daten-Block-Aufbau bleiben byte-identisch; Pass-2-Prompts (`llm_prompts.py`, bereits englisch, JSON-Schema-Vertrag) werden nicht angefasst. Kein Code parst Chat-Antworten sprachabhängig — Übersetzung ist verhaltenssicher. Pure-Unit-Tests auf Prompt-Inhalt anpassen (Marker-/Sanitization-Tests bleiben unverändert grün).
- `app/api/llm_chat.py`: deutsche JSON-Error-Messages (`Conversation ist archiviert.`, `Feld 'content' erforderlich`, …) englisch.
- Tests: Audit-/Setup-/Chat-/Prompt-Tests.

### Phase F — JS, Sweep, Guard, Doku

- 6 JS-Dateien: Toasts, Confirm-Texte, Loading-/Error-Strings englisch. Kein Verhalten ändern.
- **Sprach-Sweep-Test `tests/test_ui_language.py`** (Pure-Unit): scannt `app/templates/**`, `app/static/js/*.js` und String-Literale in `app/views/*.py` + `app/forms.py` gegen eine Marker-Wortliste (Umlaute `ä ö ü ß Ä Ö Ü` + Transliterationen/Wörter: `ungueltig`, `fuer `, `gespeichert`, `geloescht`, `gewaehlt`, `pruefen`, `wurde`, `Bitte`, `Anlegen`, `Abbrechen`, `Eingabe`, `Hinweis`, `Keine `, `nicht `, …). Ausnahme-Mechanismus per expliziter Allowlist im Test (z.B. Jinja-Kommentare/Code-Kommentare in Templates sind ok — Kommentare bleiben deutsch, der Scanner strippt `{# … #}`, `<!-- … -->`, `//`- und `/* … */`-Kommentare vor dem Match).
- Finaler manueller Grep-Sweep über `app/` (siehe DoD).
- CHANGELOG (v0.17.0), `decisions/README.md`-Verweis prüfen, STATE.md-Update.

## Definition of Done (maschinell prüfbar)

1. `ruff check . && ruff format --check .` grün.
2. `mypy app/` grün.
3. Default-`pytest` grün (Pure-Unit, Timeout-Konvention aus CLAUDE.md), inkl. neuem `tests/test_ui_language.py`.
4. Sweep leer: `grep -rinE 'ungueltig|gespeichert|geloescht|gewaehlt|fuer |bitte |anlegen|abbrechen' app/templates/ app/static/js/` liefert nach Kommentar-Abzug keine Treffer (der Sweep-Test ist die präzise, kommentar-bereinigte Form davon).
5. Kein Markup-/Logik-Diff: Diff besteht ausschließlich aus String-Literal-Änderungen + Test-Anpassungen (Reviewer-Check; OOB-Drift-Tests unverändert grün als maschineller Anteil).
6. Bestehende Test-Anzahl nicht gesunken (außer ersetzten String-Assertions 1:1).

**Nicht in diesem Block / vom User abzuhaken:** Operator-Browser-Smoke (Stichprobe je Surface: Settings-Save-Flash, Bulk-Ack-Modal, Setup-Wizard-Step, Chat-Antwort auf Englisch). Heavy-Suiten (db_integration/acceptance) laufen nur auf User-Anweisung.

## Out of Scope

- Doc-Sprache, Code-Kommentare, Docstrings, ADRs (bleiben deutsch, ADR-0045 §Scope).
- i18n-Infrastruktur (gettext/babel, Locale-Switch).
- Migration persistierter deutscher Strings (Audit-Metadata, Notes-Bestand).
- Jegliches Redesign, Markup- oder CSS-Refactoring.
