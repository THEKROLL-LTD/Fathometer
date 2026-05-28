# Block Z — Group + Tag Hybrid-Lifecycle (Inline-Create + Manage-Only-Surfaces)

**Spec-Quelle:** [ADR-0040](../decisions/0040-group-and-tag-hybrid-lifecycle.md)
**Branch:** `feat/block-z-group-tag-hybrid`
**Zielversion:** v0.15.0
**Vorgänger:** Block W (ADR-0034, Host-Group-Datenmodell), Block X (ADR-0038, Server-Settings-Sub-View).
**Status:** Geplant

## Ziel

Operator kann Gruppen und Tags **inline** im Server-Settings-Sub-View anlegen — kein Context-Switch nötig. `/settings/groups` (neu) und `/settings/tags` (refactored) sind Manage-Only-Seiten für Rename, Delete, Color-Edit (Tags), Position-Reorder (Gruppen). Keine Auto-Delete-Magie bei leeren Gruppen; sie bleiben sichtbar und löschbar in der Verwaltungsseite, werden aber aus der Sidebar weggeblendet wenn keine Member vorhanden sind (bestehendes Verhalten).

**Erwartetes Ergebnis:** Schließt den ADR-0034-Re-Open-Trigger „CRUD-UI für Gruppen" und stellt Symmetrie zu Tags her, ohne `psql` als Power-User-Workaround zu brauchen.

## Spec-Referenzen (Pflicht-Lektüre)

1. **ADR-0040 komplett** — Architektur-Entscheidung, Endpoint-Übersicht, Verworfenes, Re-Open.
2. **ADR-0034 §Schema + §Sidebar-Verhalten** — `server_groups`-Tabelle, `name`-Regex, `position`-Semantik, Sidebar-Aggregation.
3. **ADR-0038 §Phase B** — bestehender Server-Settings-Sub-View, `ServerGroupForm`, `_render_settings`-Context.
4. **ADR-0006** — keine Pflicht-Felder in der UI.
5. **ADR-0032 + ADR-0033** — `sd-*`-CSS-Klassen, kein DaisyUI/Tailwind in neuen Templates.
6. **`app/views/server_settings.py`** — bestehende Endpoints, `_load_server_with_settings`, `_all_groups`, `_render_settings`.
7. **`app/views/settings.py`** — bestehende Tag-CRUD-Endpoints (`tags_list`, `tags_create`, `tags_delete`) + `render_settings`-Shell-Pattern.
8. **`app/forms.py`** — `TagForm`, `ServerGroupForm`, `ServerSettingsForm`, `TAG_NAME_REGEX`.
9. **`app/templates/servers/settings.html`** — heutiger Tag-Select + Group-Select.
10. **`app/templates/settings/tags.html`** — heutige Tag-Verwaltungs-UI (Legacy-DaisyUI, wird refactored).
11. **`app/services/sidebar_group_aggregates.py`** — `group_counts()` filtert heute schon `NULL`/leere Gruppen weg (Regressions-Test, kein Code-Change).
12. **CLAUDE.md §HTMX-OOB-Single-Source-Pattern** — falls Templates in zwei Pfaden (Initial-Render + HX-Fragment) gerendert werden.

## Out of scope (explizit)

- Schema-Migration (keine neue Spalte, keine neue Tabelle).
- Drag-Drop-Reorder (siehe ADR-0040 §Re-Open).
- Bulk-Server-zu-Gruppe-Move.
- Group-Filter im Dashboard/Findings (`?group=N`-URL-Param).
- Group-Beschreibung / Icon / per-Group-Farbe.
- `Tag.position`-Spalte (Symmetrie nur für Lifecycle, nicht für Sidebar-Sortierung).
- Multi-Group-Zugehörigkeit (M:N).
- Auto-Delete leerer Gruppen.
- Sidebar-Re-Design (nutzt das bestehende `sidebar_group_aggregates.group_counts()`-Verhalten; Block W ist Quelle der Wahrheit).

## Modell-Änderungen

**Keine.** Block Z ist Code-only — keine Alembic-Migration.

## Phasen

### Phase A — Inline-Create-Endpoints (Server-Settings-Sub-View)

**Ziel:** Backend-Endpoints für Inline-Anlage einer Gruppe und eines Tags im Server-Settings-Kontext. Atomar mit der direkten Zuweisung an den aktuellen Server.

**Dateien:**

- `app/forms.py` — zwei neue Forms:
  - `ServerGroupCreateForm`: `name` StringField, `DataRequired() + Length(1, 64) + Regexp(r'^[A-Za-z0-9 _.-]+$')`.
  - `ServerTagCreateForm`: `name` StringField, `DataRequired() + Length(1, 32) + Regexp(TAG_NAME_REGEX)`. Color wird **nicht** im Form geführt — Backend setzt Default `#6b7280` analog `TagForm.color.default`.
- `app/views/server_settings.py` — zwei neue Routen:
  - `POST /servers/<server_id>/settings/group/create`:
    1. `_load_server_with_settings(server_id)` + revoked/retired-404-Guard.
    2. `ServerGroupCreateForm` validieren (Regex/Length/CSRF).
    3. `position = max(position) + 1` per `SELECT COALESCE(MAX(position), -1) + 1 FROM server_groups`.
    4. `sess.add(ServerGroup(name=…, position=…))` → `sess.flush()` → Race-Catch (`IntegrityError`):
       - Bei Konflikt: `sess.rollback()`, `SELECT … WHERE name = :name` nachladen.
    5. `server.group_id = group.id`.
    6. Audit `group.created` (`metadata={"name": …, "position": …, "via": "server_settings"}`) **und** `server.group_changed` (`metadata={"from": old, "to": group.id}`) in einer Transaktion.
    7. `sess.commit()` + `_redirect_to_settings(server_id)`.
  - `POST /servers/<server_id>/settings/tags/create`:
    1. `_load_server_with_settings` + revoked/retired-404-Guard.
    2. `ServerTagCreateForm` validieren.
    3. `sess.add(Tag(name=…, color="#6b7280"))` → `sess.flush()` → Race-Catch wie oben.
    4. `ServerTag(server_id=…, tag_id=tag.id)` anhängen (idempotent: existing-Link via `SELECT` checken).
    5. Audit `tag.created` (`metadata={"name": …, "color": "#6b7280", "via": "server_settings"}`) + `server.tag.added`.
    6. `sess.commit()` + `_redirect_to_settings(server_id)`.
- `app/views/server_settings.py::_render_settings` — Context-Erweiterung:
  - `group_create_form = ServerGroupCreateForm()`
  - `tag_create_form = ServerTagCreateForm()`

**Tests:**

- `tests/views/test_server_settings_group_create.py` (neu, ~8 Tests):
  - Happy-Path: Form valid, Group wird angelegt, `server.group_id` gesetzt, Audit-Events gefeuert, Redirect.
  - Race-Path: Mock `sess.flush()` wirft `IntegrityError` → existing Group wird nachgeladen.
  - Invalid Name: Regex-Verstoß (`prod/eu`) → 302 mit Flash-Error, keine DB-Mutation.
  - Length-Edge: 65-char-Name → Reject.
  - Auth: `@login_required`-Guard.
  - Revoked-Server: 404.
  - CSRF: invalid Token → Reject.
  - `position`-Berechnung bei leerer Tabelle (`COALESCE` → 0).
- `tests/views/test_server_settings_tag_create.py` (neu, ~7 Tests, analog).
- `tests/forms/test_server_group_create_form.py` (neu, ~5 Tests, Validierungs-Edges).
- `tests/forms/test_server_tag_create_form.py` (neu, ~5 Tests).

**DoD-A:**

1. `POST /servers/<id>/settings/group/create` mit gültigem Namen legt eine Gruppe an + weist sie dem Server zu (verifiziert per Test).
2. `POST /servers/<id>/settings/tags/create` analog für Tags.
3. Race-Pfad: zweimal mit identischem Namen → kein 500, Endergebnis identisch.
4. Audit-Events `group.created` + `tag.created` haben `metadata.via == "server_settings"`.
5. `ruff check . && ruff format --check . && mypy app/` PASS.
6. Default-`pytest` PASS, mindestens 25 neue Tests grün.

### Phase B — Server-Settings-Sub-View: Combobox-UI

**Ziel:** Operator sieht im Settings-Form sowohl den existierenden Picker als auch einen Inline-Anlage-Pfad. Kein Modal, kein Page-Wechsel.

**Dateien:**

- `app/templates/servers/settings.html` — Erweiterung der `Tags`- und `Gruppe`-Sektionen:
  - **Tags:** über dem bestehenden „+ Tag wählen…"-Select kommt eine neue Zeile mit einem Inline-Eingabefeld + „+ Anlegen"-Button. Submit zielt auf das neue Hidden-Sub-Form `tag-create-form` (analog zum bestehenden `tag-add-form`-Pattern via HTML5 `form="…"`-Attribute).
  - **Gruppe:** unter dem bestehenden `settings_form.group_id`-Select kommt eine zweite Zeile mit Eingabefeld + „+ Neue Gruppe anlegen"-Button. Submit zielt auf neues Hidden-Sub-Form `group-create-form`.
  - Hint-Texte erweitert um den Inline-Pfad-Hinweis.
- `app/templates/servers/settings.html` — am Ende analog zu `tag-add-form`/`tag-remove-*` zwei neue Hidden-Sub-Forms:

  ```jinja
  <form id="group-create-form"
        method="post"
        action="{{ url_for('server_settings.group_create', server_id=server.id) }}"
        style="display: none;">
    {{ group_create_form.hidden_tag() }}
  </form>
  <form id="tag-create-form"
        method="post"
        action="{{ url_for('server_settings.tag_create', server_id=server.id) }}"
        style="display: none;">
    {{ tag_create_form.hidden_tag() }}
  </form>
  ```

- `frontend/src/css/components/server-detail.css` — Erweiterung um `.sd-inline-create` (Flex-Row: Input + Button) im sd-* Token-Stil. Keine neuen Farben — bestehende `--border-subtle`, `--accent-cyan` reichen.

**Tests:**

- `tests/templates/test_server_settings_inline_create.py` (neu, ~6 Tests):
  - Template rendert Inline-Eingabefeld für Group + Tag.
  - `form="group-create-form"` / `form="tag-create-form"`-Attribute auf Buttons korrekt gesetzt.
  - Hidden-Sub-Forms enthalten CSRF-Token.
  - `data-test`-Hooks: `group-inline-create-input`, `group-inline-create-submit`, `tag-inline-create-input`, `tag-inline-create-submit`.
  - Bestehende „aus existierenden auswählen"-Pfade unverändert (Negativ-Regression).
- Visuell: keine Pure-Unit-Verifikation; Operator-Smoke vor Merge.

**DoD-B:**

1. `/servers/<id>/settings/` rendert sichtbar zwei neue Inline-Anlage-Felder (Tag + Group).
2. Bestehende „aus existierenden auswählen"-Selects funktionieren weiter.
3. CSS-Bundle baut sauber (`cd frontend && npm run build`).
4. `ruff check . && ruff format --check . && mypy app/` PASS.
5. Default-`pytest` PASS, mindestens 6 neue Template-Tests grün.

### Phase C — `/settings/groups` Manage-Only-Seite

**Ziel:** Zentrale Verwaltung von Gruppen für Rename, Delete, Reorder. Kein Create-Form.

**Dateien:**

- `app/forms.py` — drei neue Forms:
  - `GroupRenameForm`: `name` StringField (gleiche Regex wie `ServerGroupCreateForm`).
  - `GroupMoveForm`: `direction` SelectField mit Choices `("up", "down")`.
  - `GroupDeleteForm`: `CSRFOnlyForm` (Confirmation passiert client-side via `confirm()` analog Tag-Delete).
- `app/views/settings.py` — neuer Sub-Bereich:
  - `GET /settings/groups`: `render_settings(active="groups", content_template="settings/groups.html", groups=…, rename_form=…, delete_form=…)`. `groups` ist eine Liste von Dicts mit `id`, `name`, `position`, `member_count` (aggregiert per `SELECT g.id, g.name, g.position, COUNT(s.id) FROM server_groups g LEFT JOIN servers s ON s.group_id = g.id GROUP BY g.id ORDER BY g.position, g.name`).
  - `POST /settings/groups/<id>/rename`: `GroupRenameForm` validieren; Audit `group.renamed` mit `{from, to}`; no-op bei identischem Namen; `IntegrityError` → Flash „Name bereits vergeben".
  - `POST /settings/groups/<id>/delete`: `CSRFOnlyForm` validieren; `member_count` einlesen; `sess.delete(group)` (ON-DELETE-SET-NULL setzt `server.group_id = NULL`); Audit `group.deleted` mit `{name, member_count_before}`.
  - `POST /settings/groups/<id>/move`: `GroupMoveForm` validieren; Swap-Pattern: finde Nachbar mit `position < this.position` (up) bzw. `position > this.position` (down) per `ORDER BY position {ASC|DESC} LIMIT 1`; tausche beide `position`-Werte atomar; Audit `group.moved` mit `{from_position, to_position}`. Wenn kein Nachbar (Top/Bottom): No-Op + flash „Bereits ganz oben/unten".
- `app/templates/settings/groups.html` (neu):
  - Markup analog `/settings/tags.html`-Struktur aber in `sd-*`-Klassen.
  - Header + Hint.
  - **Kein Create-Form**, stattdessen ein `<p class="sd-settings-section__hint">`-Block:
    > „Gruppen entstehen, indem du im Server-Detail-Settings eine neue Gruppe zuweist."
  - Tabelle mit Spalten: `Reihenfolge` (Up/Down-Buttons), `Name`, `Server`, `Aktion` (Rename via Inline-Edit oder Modal, Delete).
  - Empty-State wenn `0 Gruppen`.
- `app/views/_settings_shell.py` (oder Pendant) — Nav-Eintrag „Gruppen" zwischen „Tags" und nächstem Eintrag.

**Tests:**

- `tests/views/test_settings_groups_list.py` (neu, ~5 Tests): Listen-Render, Member-Count korrekt, Empty-State, Sort-Reihenfolge.
- `tests/views/test_settings_groups_rename.py` (neu, ~6 Tests): Happy, Invalid-Name, Duplicate-Name, No-Op, Auth, Audit.
- `tests/views/test_settings_groups_delete.py` (neu, ~5 Tests): Happy mit Members → SET NULL verifiziert, Audit `member_count_before`, Auth, Unknown-ID.
- `tests/views/test_settings_groups_move.py` (neu, ~6 Tests): Swap-up, Swap-down, Top-No-Op, Bottom-No-Op, Audit, Whitelist `direction`.

**DoD-C:**

1. `/settings/groups` listet Gruppen mit Member-Count.
2. Rename, Delete, Up/Down funktional verifiziert per Test.
3. Delete einer Gruppe mit Membern setzt `server.group_id = NULL` (kein Server gelöscht).
4. Move auf der ersten/letzten Gruppe ist No-Op + Flash.
5. Kein Create-Pfad ausgehend von dieser Seite (`grep "groups_create"` liefert nichts in der View).
6. Audit-Events `group.renamed`, `group.deleted`, `group.moved` mit korrekter Metadata.
7. `ruff check . && ruff format --check . && mypy app/` PASS.
8. Default-`pytest` PASS, mindestens 22 neue Tests grün.

### Phase D — `/settings/tags`-Refactor (Manage-Only + sd-* Markup)

**Ziel:** Symmetrie zu Gruppen herstellen. Anlege-Form raus, Rename + Color-Edit rein, Markup auf `sd-*`-Klassen.

**Dateien:**

- `app/forms.py` — zwei neue Forms:
  - `TagRenameForm`: `name` StringField (gleiche Regex wie `TagForm.name`).
  - `TagColorForm`: `color` StringField (gleiche Regex wie `TagForm.color`, `^#[0-9a-fA-F]{6}$`).
- `app/views/settings.py`:
  - **Entfernen:** `tags_create` (`POST /settings/tags`). Optional als 410-Gone-Stub belassen, der den Operator auf den Server-Settings-Pfad lenkt (Flash + Redirect auf `tags_list`), aber sauberer ist das ersatzlose Entfernen.
  - **Neu:** `POST /settings/tags/<id>/rename` mit `TagRenameForm` — Audit `tag.renamed` mit `{from, to}`, IntegrityError-Catch (Duplicate-Name) → Flash.
  - **Neu:** `POST /settings/tags/<id>/color` mit `TagColorForm` — Audit `tag.color_changed` mit `{from, to}`.
  - `tags_delete` bleibt unverändert.
  - `tags_list` Context-Erweiterung um `rename_form` und `color_form`.
- `app/templates/settings/tags.html` — kompletter Rewrite:
  - DaisyUI/Tailwind-Klassen (`card`, `btn`, `badge`, `table`, `input-bordered`) raus.
  - `sd-*`-Klassen (analog `/settings/groups.html` aus Phase C).
  - **Anlege-Form ersatzlos raus**, dafür Hint-Block:
    > „Tags entstehen, indem du im Server-Detail-Settings einen neuen Tag zuweist."
  - Per-Row-Actions: Rename, Color-Edit (Color-Picker direkt in der Row), Delete.
  - Empty-State angepasst.
- `frontend/src/css/components/legacy-shim.css` — falls die alten Tag-Template-Klassen ausschließlich von `/settings/tags` benutzt waren, werden die jeweiligen Shim-Einträge gestrichen. Sonst belassen.

**Tests:**

- `tests/views/test_settings_tags_create_removed.py` (neu, ~3 Tests): `POST /settings/tags` ohne neue Anlage-Logik liefert 404/405; alte Tests aus `test_settings_tags.py` für `tags_create` werden gelöscht oder auf den neuen Server-Settings-Pfad migriert.
- `tests/views/test_settings_tags_rename.py` (neu, ~6 Tests): Happy, Invalid-Name, Duplicate-Name, No-Op, Auth, Audit.
- `tests/views/test_settings_tags_color.py` (neu, ~5 Tests): Happy, Invalid-Hex, No-Op, Auth, Audit.
- `tests/templates/test_settings_tags_no_create_form.py` (neu, ~2 Tests): Template enthält Hint-Block, keine `<input name="name">` auf Anlage-Form-Höhe.

**DoD-D:**

1. `/settings/tags` rendert keine Anlage-Form mehr.
2. Rename + Color-Edit funktional verifiziert.
3. Markup nutzt `sd-*`-Klassen (Stichprobe-Grep auf `class="card"` und `class="btn"` im neuen Template liefert nichts).
4. `legacy-shim.css` verkleinert sich um mindestens die `.card`/`.input-bordered`-Verwendungen aus diesem Template (Größen-Stichprobe vor/nach).
5. `tag.renamed` + `tag.color_changed` Audit-Events korrekt.
6. `ruff check . && ruff format --check . && mypy app/` PASS.
7. Default-`pytest` PASS, mindestens 16 neue Tests grün, gestrichene Create-Tests aus dem Repo entfernt.

### Phase E — Aufräumen + Konsistenz-Tests

**Ziel:** Verifizieren dass die zwei Surfaces (Server-Settings-Sub-View + Manage-Only-Seite) konsistent sind und keine Karteileichen entstehen.

**Dateien:**

- `app/services/sidebar_group_aggregates.py` — Regressions-Test verschärfen (keine Code-Änderung): Gruppe ohne Member darf nicht in der Sidebar-Aggregation auftauchen. Existing-Test schon vorhanden? Wenn nicht: ergänzen.
- `app/audit.py` — Sanity-Check dass alle neuen Event-Typen in der Audit-Filter-Liste auftauchen (falls `/settings/audit` Event-Typen explizit whitelistet).
- `docs/operations.md` — Stichwort ergänzen wenn Operator-Workflow geändert wurde („Gruppen entstehen jetzt inline im Server-Detail-Settings; `/settings/groups` ist nur für Rename/Delete/Sort.").

**Tests:**

- `tests/services/test_sidebar_group_aggregates_empty.py` (neu, ~2 Tests): leere Gruppe ist nicht im Aggregations-Result.
- `tests/views/test_audit_event_types.py` (neu, ~1 Test): `group.created`, `group.renamed`, `group.deleted`, `group.moved`, `tag.renamed`, `tag.color_changed` sind in der Event-Type-Filter-Liste (falls vorhanden).
- Grep-Verifikation in der DoD:
  - `grep -rn "tags_create" app/views/` liefert nichts (Endpoint ist weg).
  - `grep -rn "settings_groups\|server_settings.group_create\|server_settings.tag_create" app/` liefert nur in den erwarteten Files.

**DoD-E:**

1. Sidebar-Aggregations-Regressions-Test sichert: leere Gruppe wird nicht gerendert.
2. Audit-Event-Types in `/settings/audit` filterbar (falls Filter-Mechanismus existiert).
3. `docs/operations.md` reflektiert den neuen Workflow (ein kurzer Absatz reicht).
4. Final-Grep aus Phase D ist sauber.
5. `ruff check . && ruff format --check . && mypy app/` PASS.
6. Default-`pytest` PASS, keine Test-Regressions.

## Phasen-Abhängigkeiten

```
A (Inline-Create-Endpoints)   → keine externe Abhängigkeit
B (Combobox-UI)               → braucht A (Endpoints existieren)
C (/settings/groups)          → unabhängig von A/B, kann parallel
D (/settings/tags-Refactor)   → unabhängig von A/B/C, kann parallel
E (Aufräumen + Konsistenz)    → braucht A + B + C + D
```

Empfohlene Reihenfolge: **A → B → C → D → E**. C und D können nach A parallel laufen wenn separate Implementer verfügbar sind. E ist der Abschluss-Sweep.

Jede Phase ist ein eigener Commit auf `feat/block-z-group-tag-hybrid`. Reviewer-Approval am Ende jeder Phase. Sicherheits-relevant: alle neuen POST-Endpoints (CSRF, `@login_required`, Whitelist-Validierung der Inputs) — Security-Auditor-Pass am Ende von Phase A und Phase C/D.

## Risiken & Mitigation

| Risiko | Mitigation |
|---|---|
| **Race bei doppeltem Inline-Create** (Operator klickt „+ Anlegen" zweimal schnell hintereinander) | `IntegrityError`-Catch + Re-Fetch der existing Row → Idempotenz. Pure-Unit-Test mit Mock-`IntegrityError`. |
| **`legacy-shim.css`-Footprint wächst statt schrumpft** weil neues `groups.html` und das refactored `tags.html` neue Klassen einführen | Alle neuen Klassen mit `sd-*`-Prefix; CSS lebt in `server-detail.css` oder einer neuen `settings.css`-Komponente, nicht im Shim. Visuelle Stichprobe vor Merge. |
| **Up/Down-Reorder erzeugt Position-Konflikte** (zwei Gruppen mit gleicher Position nach unsauberem Swap) | Swap als zwei atomare UPDATEs in einer Transaktion. UNIQUE-Constraint auf `position` wäre defensiv aber bricht beim Swap; statt UNIQUE-Constraint reicht ein Pure-Unit-Test der Position-Eindeutigkeit nach 10 zufälligen Swaps verifiziert. |
| **Operator löscht eine Gruppe ohne den Member-Count zu lesen** | Confirm-Dialog client-side (`confirm("X Server werden in 'ungrouped' zurückfallen — wirklich löschen?")`) analog zum heutigen Tag-Delete-Dialog. ADR-0006 betrifft Pflicht-**Felder**, nicht Bestätigungs-Dialoge. |
| **Tag-Color-Default `#6b7280` führt zu Farben-Einheitsbrei** in der Tag-Liste | Akzeptiert für MVP: Operator kann in `/settings/tags` nachfärben. Beobachten, ob in der Praxis schmerzhaft. |
| **Audit-Event-Volumen steigt** durch häufigere Inline-Anlagen | `tag.created` + `group.created` sind ohnehin schon Events; nur das `via=server_settings`-Metadata-Feld ist neu. Kein neuer Volumen-Treiber. |
| **Drift zwischen Server-Settings-Inline-Create und `/settings/groups`-Rename-Pfad** (z. B. unterschiedliche Regex-Validierung) | Beide nutzen dieselbe `Regexp`-Konstante (`^[A-Za-z0-9 _.-]+$`) — eine Quelle der Wahrheit in `app/forms.py`. Test verifiziert identische Regex-Konstante in beiden Forms. |

## NICHT in Block Z

- Drag-Drop-Reorder, Bulk-Server-Move, Group-Filter, Group-Beschreibung/Icon/Farbe → ADR-0040 Re-Open.
- `Tag.position`-Spalte → ADR-0040 Verworfen.
- Auto-Delete leerer Gruppen → ADR-0040 Verworfen.
- Sidebar-Re-Design oder Sidebar-Aggregations-Änderung → ADR-0034 + Block W bleiben Quelle der Wahrheit; Block Z verlässt sich auf das bestehende Filter-Verhalten von `group_counts()`.
- Migration `secscan` → `fathometer` (Repo-Rename) → separater ADR.
