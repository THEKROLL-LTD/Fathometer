# ADR-0031 — Theme-Switcher entfernt

**Status:** Akzeptiert · **Datum:** 2026-05-23 · **Block:** kein eigener Block (Tech-Debt-Removal)

Bezug: [ADR-0001](0001-no-node-build.md) (kein Node-Build, bleibt unverändert), [ADR-0016](0016-header-and-profile-dropdown.md) §"Theme-Toggle als sichtbares Header-Icon" (wird teilweise abgelöst).

## Kontext

Der Theme-Switcher (Light/Dark/Auto) existiert seit Block A im MVP. ADR-0016 §"Theme-Toggle als sichtbares Header-Icon" hat ihn als Sun/Moon-Icon in der Topbar etabliert. Operator-Praxis: alle Sessions laufen ausschließlich im Dark-Theme; der Toggle ist toter Code mit Maintenance-Overhead:

- Cookie-Handling (`before_request`-Hook `_resolve_theme`, `after_request`-Hook `_persist_theme`)
- Context-Processor `_inject_theme` mit `theme`-Variable in jedem Template
- No-Flash-Theme-Resolver-Script im `<head>` beider Shell-Templates
- 94 LOC JavaScript (`static/js/theme.js` — Alpine-Komponente, Cookie-Write, MediaQuery-Listener)
- DB-Spalte `settings.default_theme` mit Check-Constraint `ck_settings_theme`
- Setup-Wizard-Step (Schritt 3: Theme-Auswahl-Select)
- `THEME_CHOICES`-Konstante und `default_theme`-Feld in `SetupStep3Form`
- `_VALID_THEMES`-Konstante in `app/__init__.py`

## Entscheidung

Der Theme-Switcher wird ersatzlos entfernt. `<html data-theme="dark">` ist statisch gesetzt.

Die DaisyUI-CDN-Datei (`full.min.css`) bleibt unverändert — sie enthält weiterhin alle Themes als CSS, aber nur `[data-theme="dark"]`-Regeln greifen im Browser. ADR-0001 (kein Node-Build) bleibt unangetastet.

Entfernt wurden:

- `static/js/theme.js` (ersatzlos gelöscht)
- `_VALID_THEMES`, `_resolve_theme()`, `_inject_theme()`, `_persist_theme()` aus `app/__init__.py`
- `settings.default_theme`-Spalte + `ck_settings_theme`-Constraint (Alembic-Migration 0013)
- `THEME_CHOICES`, `default_theme`-Feld aus `app/forms.py` und `app/views/setup.py`
- No-Flash-Theme-Resolver-Script und `theme.js`-Include aus `base.html` / `base_app.html`
- Theme-Toggle-Dropdown-Block aus `app/templates/layout/_header.html`
- Theme-Auswahl-Formblock aus `app/templates/setup/step3.html`
- `tests/test_theme_cookie.py` (4 Tests)
- `default_theme`-Assertions und -Form-Felder aus `tests/setup/test_wizard.py`
- `test_header_theme_toggle_present_with_sun_and_moon` aus `tests/integration/test_header_navigation_db.py`
- `"js/theme.js"`-Einträge aus `tests/views/test_script_load_order.py`

## Konsequenzen

- ADR-0016 §"Theme-Toggle als sichtbares Header-Icon" ist durch diese ADR abgelöst (Header-Vermerk dort ergänzt).
- ARCHITECTURE.md §7 (Topbar), §6 (Settings), Block A und Block D enthalten keine Theme-Toggle-Referenzen mehr.
- Setup-Wizard Schritt 3 enthält keine Theme-Auswahl mehr.
- DaisyUI-CDN lädt weiterhin alle Themes (~30 kB toter CSS-Code). Das ist der akzeptierte Kompromiss solange ADR-0001 (kein Node-Build) gilt.

## Geplante Folge-Arbeit (Option D, separater ADR)

Single-Theme-DaisyUI-Build via npm + Tailwind + DaisyUI-Plugin (`themes: ["dark"]`-Config) → eigenes statisches CSS committen. Macht den DaisyUI-CDN-Ballast weg. Bricht ADR-0001 — eigene Folge-ADR erforderlich. Bis dahin lädt DaisyUI weiterhin alle Themes per CDN als toter CSS-Code.

## Verworfen

- **Variante B** (DaisyUI-File-Splitting `styled.min.css` + `themes/dark.min.css`): Unklar ob DaisyUI 4.12.14 diese Split-Files in der CDN-Distribution anbietet; verifizierungsaufwendig, Bandbreiten-Gewinn marginal.
- **Variante C** (DaisyUI als Tailwind-Play-CDN-Plugin mit `themes: ["dark"]`): Zerbrechlich — Tailwind-Play-CDN-Plugin-Loader ist für DaisyUI nicht offiziell unterstützt.
- **Variante D** (npm-Build) — als Folge-ADR geplant, nicht verworfen.
