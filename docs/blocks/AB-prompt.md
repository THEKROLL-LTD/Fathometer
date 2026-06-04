# Block AB — Orchestrator-Prompt

Implementiere **Block AB** (English UI Migration: alle Operator-sichtbaren Strings auf Englisch — reiner String-Touch, kein Markup-/Logik-/CSS-Umbau, keine Migration).

## Pflicht-Lektüre vor dem ersten Codestrich

1. `CLAUDE.md` — komplett (Test-Konvention, Timeout-Regeln, OOB-Single-Source-Pattern, neue UI-Sprachregel §Kommunikations-Sprache).
2. `docs/blocks/AB-english-ui-migration.md` — Block-Spec: Inventar-Tabelle, **verbindliches Glossar**, sechs Phasen A–F, maschinell prüfbare DoD, Out-of-Scope.
3. `docs/decisions/0045-english-only-ui.md` — ADR: Scope-Abgrenzung (Doku/Kommentare bleiben deutsch, keine i18n, kein Daten-Rollout), Sweep-Test-Anforderung.
4. `docs/decisions/0033-brand-identity-fathometer.md` §8 — bereits englische Surfaces (Block W) als Ton-Referenz: knapp, imperativ, lowercase wo die Surface das tut.
5. `app/__init__.py` — `format_relative` (Phase A, Ziel-Format im Glossar).
6. `app/forms.py` — Validator-Messages (Phase A, geteilte Konstanten zuerst).
7. `app/services/llm_prompt.py` — Chat-System-Prompt (Phase E). **Invarianten:** `TRIVY_DATA_START`/`TRIVY_DATA_END` und Daten-Block-Aufbau byte-identisch; `llm_prompts.py` (Pass-2, bereits englisch) ist tabu.
8. `app/api/llm_chat.py` — deutsche JSON-Error-Messages (Phase E).

## Arbeitsweise

- **Branch `feat/block-ab-english-ui`, Reihenfolge A → B → C → D → E → F, ein Commit pro Phase.** C/D/E können nach A+B parallel als separate Implementer-Agents laufen (disjunkte Dateien).
- Pro Phase: Strings gemäß Glossar übersetzen → betroffene Test-Assertions 1:1 mitziehen → `ruff check . && ruff format --check .` → `mypy app/` → `pytest` (Default-Selektion, Bash-Timeout ≤ 120000 ms; fokussierte Läufe ≤ 60000 ms) → Phasen-DoD per grep prüfen.
- **Diff-Disziplin:** ausschließlich String-Literale + Test-Anpassungen. Keine Umbenennung von Bezeichnern, IDs, CSS-Klassen, `data-*`-Keys, Audit-Event-Typen, Form-Feldnamen, URL-Pfaden. OOB-Drift-Tests müssen **unverändert** grün bleiben.
- **Glossar ist verbindlich.** Wiederkehrende Begriffe (Invalid input, saved, deleted, revoked, …) exakt wie in der Spec-Tabelle. Bei Strings ohne Glossar-Eintrag: Ton der Block-W-Surfaces. `Bitte …`-Floskeln ersatzlos streichen.
- **Transliterationen beachten:** deutsche Strings liegen teils als `Ungueltige`/`fuer`/`Gewaehlte` vor — Umlaut-Suche allein reicht nicht. Suchliste aus Spec §Inventar verwenden.
- **Kommentare/Docstrings nicht übersetzen** — die bleiben deutsch (ADR-0045 §Scope). Nur Operator-sichtbare Strings.
- Phase F: Sprach-Sweep-Test `tests/test_ui_language.py` als Pure-Unit-Test gemäß Spec (Kommentar-Stripping, Marker-Wortliste mit Umlauten + Transliterationen, explizite Allowlist). CHANGELOG v0.17.0, STATE.md-Update.
- **Keine** db_integration/acceptance/integration/bench/bats/RUN_E2E/Docker-Tests, keine neuen `.bats`-/`.sh`-Testdateien. Erlaubte Gates: ruff, mypy, shellcheck, pytest Default-Selektion.
- Wenn ein Quality-Gate rot ist: selbst fixen, nicht den User fragen.
- Wenn ein String nicht eindeutig übersetzbar ist, weil er Logik transportiert (z.B. geparst wird): **STOP**, User fragen — nicht raten.
- Nach Phase F: Block-Gesamt-DoD aus der Spec prüfen (alle sechs Punkte), Zusammenfassung mit Test-Zahlen (vorher/nachher) melden. Operator-Browser-Smoke bleibt beim User. Erst dann stoppt der Agent.

## Was NICHT im Prompt steht (weil in Block-Spec + ADR)

Datei-Inventar mit Zählungen, vollständiges Glossar, Phasen-Zuschnitt im Detail, Sweep-Wortliste, DoD-Grep-Kommandos, LLM-Invarianten-Begründung, Out-of-Scope-Liste — alles in `AB-english-ui-migration.md` + ADR-0045. Dort nachschlagen, nicht raten.
