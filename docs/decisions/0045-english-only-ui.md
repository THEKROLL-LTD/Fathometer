# ADR-0045 — English-only UI: vollständige Übersetzung in einem dedizierten Block

**Status:** Akzeptiert · **Datum:** 2026-06-04 · **Block:** AB — English UI Migration

Bezug: [ADR-0033](0033-brand-identity-fathometer.md) §8 Sprach-Policy (wird hier teilweise abgelöst), [ADR-0021](0021-agent-bootstrap-installer.md) (Agent-/Installer-Strings bereits englisch), [ADR-0022](0022-risk-based-prioritization.md) (Risk-Band-Labels bereits englisch).

## Kontext

ADR-0033 §8 legte fest: Ziel-Sprache der UI ist Englisch, aber die Migration läuft **pro Surface-Redesign** (Phase 2), ein dedizierter „nur Übersetzung"-Block war explizit ausgeschlossen. Begründung damals: Translation-Drift-Risiko, wenn Strings ohne gleichzeitiges UX-Redesign übersetzt werden.

Stand 2026-06-04 ist daraus ein dauerhafter Misch-Zustand geworden: Login, Topbar, Sidebar, Dashboard und Footer sind englisch (Block W), aber Settings, Server-Detail, Findings, Audit, Setup-Wizard und Chat sind deutsch — inklusive Flash-Messages, Form-Validator-Messages, JS-Strings, dem Relative-Time-Filter (`vor 5min`) und dem Chat-LLM-System-Prompt (`Antworte auf Deutsch`). Da Server-Detail und Findings seit Block X/Y/AA bereits redesignt wurden, ohne dass die Übersetzung mitlief (Phase-2-Regel wurde dort nicht durchgesetzt), funktioniert die Kopplung „Übersetzung pro Redesign" in der Praxis nicht.

User-Entscheidung 2026-06-04: **Eine Sprache, sauber. Die gesamte UI wird jetzt englisch**, in einem dedizierten Block, nicht weiter inkrementell.

## Entscheidung

1. **Die gesamte UI ist ausschließlich englisch.** Das umfasst alle Operator-sichtbaren Strings:
   - Jinja-Templates (`app/templates/**`) inkl. Partials, Empty-States, Modals, Setup-Wizard, Chat
   - Flash-Messages und Fehlermeldungen in allen Views (`app/views/*.py`)
   - WTForms-/Pydantic-Validator-Messages, die in der UI gerendert werden (`app/forms.py` u. a.)
   - JS-Strings (`app/static/js/*.js`): Toasts, Confirm-Texte, Loading-/Error-States
   - Jinja-Filter mit sichtbarem Output, insbesondere der Relative-Time-Filter in `app/__init__.py` (`vor 5min` → `5min ago`)
   - Chat-LLM-System-Prompt (`app/services/llm_prompt.py`): `Antworte auf Deutsch` → englische Antworten; LLM-Output ist UI-Output
2. **Ein dedizierter Übersetzungs-Block (Block AB)** setzt das um — die Phase-2-Regel aus ADR-0033 („Übersetzung nur pro Redesign-Block, kein eigener Übersetzungs-Block") ist damit **abgelöst**. Das damalige Drift-Argument entfällt: die großen Surfaces sind inzwischen redesignt, übersetzt wird in den bestehenden Layouts.
3. **Hart geprüfte Policy statt Soft-Policy.** Die Reviewer-Soft-Policy aus ADR-0033 §Konsequenzen wird durch einen maschinellen Sweep ergänzt: ein Pure-Unit-Test (`tests/test_ui_language.py`) scannt Templates, JS und View-Flash-Strings gegen eine deutsche Marker-Wortliste (Umlaute, `ae/oe/ue`-Transliterationen wie `Ungueltige`, häufige Wörter wie `wurde`, `gespeichert`, `Bitte`). Neue deutsche UI-Strings schlagen damit im Default-`pytest` fehl.
4. **Keine i18n-Infrastruktur.** Kein `gettext`/`babel`, keine Locale-Dateien, kein Sprach-Switch. Strings bleiben hart codiert, nur eben englisch. Single-User-Tool, eine Sprache (siehe ADR-0004-Geist).

## Nicht Teil dieser Entscheidung (Scope-Abgrenzung)

- **Doc-Sprache und Code-Kommentare bleiben Deutsch** (User-Entscheidung 2026-06-04, bestätigt). ADRs, Block-Specs, ARCHITECTURE.md, README, techdebt.md, Docstrings, Inline-Kommentare: unverändert deutsch gemäß CLAUDE.md-Konvention.
- **Audit-Log-Bestandsdaten** werden nicht migriert. Persistierte deutsche Strings in `audit_events`-Metadata oder Notes bleiben wie sie sind; nur neu erzeugte Einträge sind englisch.
- **Persistierte LLM-Reasons** (Pass-2-Output) sind bereits englisch (ADR-0043-Prompts sind englisch); kein Daten-Rollout nötig.
- **Test-Bezeichner und Test-Docstrings** bleiben wie sie sind; nur Assertions auf deutsche UI-Strings werden auf die neuen englischen Strings umgestellt.

## Konsequenzen

- ~60 Templates, ~70 Flash-Aufrufe, `app/forms.py`, 6 JS-Dateien, der Relative-Time-Filter und der Chat-System-Prompt werden in Block AB angefasst. Reiner String-Touch, kein Markup-/Logik-Umbau (Detail-Inventar in `docs/blocks/AB-english-ui-migration.md`).
- Bestehende Tests, die deutsche Strings asserten, müssen im selben Block mitgezogen werden — Template-Drift-Tests (OOB-Pattern) sind davon nicht betroffen, da sie strukturell vergleichen.
- Der Sprach-Sweep-Test wird Teil des Default-`pytest` und verhindert Rückfall.
- ADR-0033 §8 erhält einen Ablöse-Vermerk; Brand-/Design-Doctrine-Teile von ADR-0033 bleiben unberührt.

## Verworfen

- **Weiter inkrementell pro Redesign-Block** (Status quo ADR-0033 Phase 2): hat den Misch-Zustand produziert und wurde bei Block X/Y/AA nicht durchgehalten.
- **i18n-Framework (Flask-Babel)**: Overkill für Single-User-Tool mit genau einer Zielsprache; widerspricht „eine Sprache, sauber".
- **Übersetzung der Doku ins Englische**: explizit vom User abgewählt (nur UI).

## Re-Open-Trigger

- Wenn jemals eine zweite UI-Sprache gewünscht wird: neue ADR für i18n-Infrastruktur (gettext + Locale-Handling), dieser hart codierte Ansatz trägt das nicht.
