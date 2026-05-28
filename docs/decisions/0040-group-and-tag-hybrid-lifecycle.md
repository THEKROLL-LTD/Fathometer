# ADR-0040 — Hybrid-Lifecycle für Gruppen und Tags (Inline-Create, /Settings nur Manage)

**Status:** Akzeptiert · **Datum:** 2026-05-28 · **Block:** Z — Group + Tag Hybrid-Lifecycle

Bezug: [ADR-0034](0034-host-group-data-model.md) (Host-Group-Datenmodell, §Re-Open-Trigger CRUD-UI), [ADR-0006](0006-no-forced-comments.md) (keine Pflicht-Felder), [ADR-0038](0038-server-detail-triage-refactor.md) (Server-Settings-Sub-View), [ADR-0033](0033-brand-identity-fathometer.md) (sd-* CSS-Klassen, kein DaisyUI).

## Kontext

Heute existieren zwei verwandte, aber unterschiedlich gepflegte Metadaten-Konzepte:

- **Tags** (M:N): CRUD unter `/settings/tags` (Liste + Anlege-Form + Per-Row-Löschen). Im Server-Settings-Sub-View `/servers/<id>/settings/` kann der Operator nur aus **existierenden** Tags wählen — neue Tags muss er vorher auf der Settings-Seite anlegen, das ist ein Context-Switch.
- **Gruppen** (1:N, ADR-0034): Schema existiert, der Server-Settings-Sub-View kann einen Server in eine bestehende Gruppe stecken. **Es gibt keine CRUD-Oberfläche** zum Anlegen, Umbenennen, Löschen oder Reihenfolge-Ändern von Gruppen — der Operator muss heute per `psql` ran. ADR-0034 hat das explizit als Re-Open-Trigger markiert.

Die Asymmetrie ist störend (Tags global verwaltbar, Gruppen gar nicht), und der Zwang, eine Gruppe vorher anzulegen, bevor man einen Server zuweisen kann, passt nicht zur Memory-Linie [feedback_server_detail_less_is_more] („ruhige Triage-Arbeitsfläche, weniger Klicks").

Drei Modellierungs-Optionen wurden im Brainstorm-Round (2026-05-28) geprüft:

1. **Rein implizit** — Anlegen ausschließlich im Server-Settings-Sub-View, Auto-Delete bei `member_count == 0`. Verworfen weil:
   - Auto-Delete ist unsichtbar und überraschend: kurzes Wegnehmen aller Server tilgt die Gruppe; beim Wieder-Hinzufügen muss der Operator den Namen retippen (Capitalization, Typo-Risiko).
   - Rename und Sortier-Reihenfolge brauchen trotzdem irgendwo ein UI. „Über einen Member-Server umbenennen" ist mental verwirrend (lokale Action → globaler Effekt).

2. **Rein zentral** (analog `/settings/tags` für Gruppen). Verworfen weil:
   - Erstellung im Flow ist Reibung: zwei Klicks Context-Switch nach `/settings/groups`, Form ausfüllen, zurück zum Server, Gruppe zuweisen. Bei vielen Servern multipliziert sich das.
   - Inkonsistent zur ADR-0006-Linie und zum Memory-Anker [feedback_server_detail_less_is_more].

3. **Hybrid** — Inline-Create im Server-Settings-Sub-View, `/settings/groups` + `/settings/tags` als Manage-Only-Seiten (Rename, Delete, Sortier-Position bei Gruppen). Gewählt.

Modernes UX-Pattern in vergleichbaren Tools (Linear-Labels, Notion-Tags, Datadog-Tags, Tailscale-Tags): inline erstellen wo zugewiesen wird, zentrale Verwaltung nur für Edge-Cases. Dieser Pattern wird hier auf **beide** Konzepte angewandt (Symmetrie).

## Entscheidung

### Schema

**Keine Schema-Migration.** `server_groups` (ADR-0034) und `tags` bleiben unverändert. Block Z ist Code-only.

### Inline-Create im Server-Settings-Sub-View

**Gruppe:**

- Markup-Pattern: Combobox / Datalist mit zwei Sektionen — „Existierende" (alle `server_groups`) + Eingabefeld „Neue Gruppe anlegen". Optional ein expliziter „+ Anlegen"-Button neben dem Select; Klick öffnet ein Inline-Eingabefeld (kein Modal, kein Page-Wechsel).
- POST auf neuen Endpoint `POST /servers/<server_id>/settings/group/create` mit Feld `name` (gleiche Validation wie ADR-0034 §Schema: 1–64 Zeichen, Regex `^[A-Za-z0-9 _.-]+$`). Auf Erfolg: neue Group wird mit `position = max(position) + 1` angelegt, `server.group_id` direkt auf die neue ID gesetzt, Audit-Event `group.created` + `server.group_changed` (atomar in einer Transaktion). Redirect zurück auf `/servers/<id>/settings/`.
- Race-Sicherheit: Bei `UNIQUE name`-Konflikt (parallele Anlage „prod-eu" von zwei Tabs) wird `IntegrityError` gefangen, die existierende Gruppe per `SELECT … WHERE name = :name` nachgeladen und dem Server zugewiesen — keine Fehlermeldung an den Operator, das gewünschte Endergebnis ist erreicht.
- Idempotent bei `name` matched existing: kein Fehler, einfach assignen.

**Tag:**

- Markup-Pattern: gleicher Combobox-Pattern wie bei Gruppen. Heute existiert nur ein „aus existierenden auswählen"-Select; dieser wird erweitert um den Inline-Anlage-Pfad.
- POST auf neuen Endpoint `POST /servers/<server_id>/settings/tags/create` mit Feld `name` (gleiche Validation wie bestehende `TagForm`: 1–32 Zeichen, Regex `TAG_NAME_REGEX`). Color wird auf den existierenden Default `#6b7280` gesetzt — **kein Color-Picker im Inline-Flow** (Operator kann später in `/settings/tags` editieren). Audit-Event `tag.created` + `server.tag.added` atomar.
- Race-Sicherheit analog Group: `IntegrityError` → existing Tag nachladen → Link anlegen.

**Konsequenz für ADR-0006:** Keine Pflicht-Eingaben jenseits des `name` (Single-Field-Form). Color ist server-default. Description gibt es weder bei Group noch bei Tag — bewusst keine zusätzlichen Felder.

### `/settings/groups` — neue Manage-Only-Seite

Analog zu `/settings/tags`, aber **ohne Anlege-Form**:

- `GET /settings/groups` listet alle Gruppen mit `name`, `position`, `member_count` (aggregiert via einem `LEFT JOIN servers GROUP BY group_id`), Aktionen (Rename, Delete, Up/Down).
- `POST /settings/groups/<id>/rename` — Form mit einem `name`-Field, gleiche Regex/Length-Validation, Audit `group.renamed` mit `{from, to}`.
- `POST /settings/groups/<id>/delete` — Bestätigungs-Dialog mit Member-Count-Hinweis (`„X Server werden in 'ungrouped' zurückfallen"`); ON-DELETE-SET-NULL aus ADR-0034 greift weiter. Audit `group.deleted`.
- `POST /settings/groups/<id>/move` — Position-Reorder mit `direction=up|down`. Swap-Pattern (simple Up/Down-Arrows). Drag-Drop ist Re-Open-Trigger.
- **Kein Create-Button.** Wenn die Tabelle leer ist, zeigt ein Empty-State-Block: „Noch keine Gruppen. Lege deine erste Gruppe im Server-Detail-Settings an, indem du einem Server eine Gruppe zuweist."

### `/settings/tags` — Refactor auf Manage-Only

- Anlege-Formular ersatzlos entfernt. Tags entstehen ausschließlich inline.
- Tabelle bleibt mit Per-Row-Actions: Rename (neu), Color-Edit (neu), Delete (existing). Audit `tag.renamed` mit `{from, to}`, `tag.color_changed` mit `{from, to}`.
- **Markup-Refactor auf `sd-*`-Klassen** parallel: heutige DaisyUI-/Tailwind-Klassen (`card`, `btn`, `badge`, `table`) raus, einheitliches Look-and-Feel mit `/settings/groups` und Server-Settings-Sub-View. Reduziert gleichzeitig den `legacy-shim.css`-Footprint (siehe ADR-0032-Addendum).
- Empty-State bei `0 Tags`: „Noch keine Tags. Lege deinen ersten Tag im Server-Detail-Settings an, indem du einem Server einen Tag zuweist."

### Empty-Group-/Empty-Tag-Verhalten

**Auto-Delete bei leer ist ausdrücklich verworfen.** Stattdessen:

- **Sidebar** (ADR-0034 §Sidebar-Verhalten): Gruppen mit `member_count == 0` werden **nicht** in der Sidebar als Bucket-Header gerendert. `sidebar_group_aggregates.group_counts()` liefert sie schon heute nur, wenn ≥1 Server eingehängt ist (`WHERE s.group_id IS NOT NULL` + GROUP BY filtert leere implicit weg). Block Z bestätigt diesen Pfad, kein Code-Change.
- **`/settings/groups`** zeigt sie weiterhin mit `member_count = 0` — der Operator kann sie explizit umbenennen oder löschen. Keine versteckten Karteileichen, aber auch kein automatischer Aufräumer.
- **`/settings/tags`** identisch: leere Tags bleiben sichtbar in der Verwaltungs-Tabelle, sind aber im Filter-Dropdown des Dashboards nicht relevant (greift auf `server_tags`-Junction).

Begründung: das Risiko, einen Operator-Eingabe-Aufwand durch versehentlichen Auto-Delete zu verlieren („alle Server kurz wegnehmen und wieder zuordnen"), wiegt schwerer als die marginal aufgeräumte Tabelle. Sichtbar-aber-leer signalisiert dem Operator außerdem, dass er evtl. ein Refactor-Restposten in der Hand hat.

### Sortier-Position für Tags

**Nicht erweitert.** Tags haben heute keine `position`-Spalte; sie werden in der Sidebar nicht als Reihenfolge-relevante Sektionen gerendert (nur als Filter-Chips). Block Z gibt Tags **keine** `position` — die Symmetrie zu Gruppen gilt nur für Lifecycle (Inline-Create + Manage-Only-Seite), nicht für Sidebar-Sortierung.

### Audit-Events

Neue Events (alle mit `target_type` + `target_id` + `metadata`):

| Event                  | target_type | metadata-Beispiel                                  |
|------------------------|-------------|----------------------------------------------------|
| `group.created`        | `group`     | `{"name": "prod-eu", "position": 3, "via": "server_settings"}` oder `{"via": "settings_groups"}` (in dem Fall nie da Create raus ist) |
| `group.renamed`        | `group`     | `{"from": "prod_eu", "to": "prod-eu"}`             |
| `group.deleted`        | `group`     | `{"name": "prod-eu", "member_count_before": 4}`    |
| `group.moved`          | `group`     | `{"from_position": 3, "to_position": 2}`           |
| `tag.renamed`          | `tag`       | `{"from": "prod_eu", "to": "prod-eu"}`             |
| `tag.color_changed`    | `tag`       | `{"from": "#6b7280", "to": "#22d3ee"}`             |

`tag.created` existiert bereits, bekommt zusätzlich `metadata.via = "server_settings"` wenn inline angelegt (Diagnostik für späteres Behavior-Audit).

### CSRF + Auth

Alle neuen Endpoints `@login_required` + CSRF via `FlaskForm.hidden_tag()`. Single-User-Setup, keine RBAC.

## Konsequenzen

- **Workflow für den Operator:** „Server-Detail öffnen → Settings → Tag/Gruppe tippen → angelegt + zugewiesen in einem Flow." `/settings/groups` und `/settings/tags` werden zu Wartungs-Surfaces für Rename/Delete/Sort, nicht zum primären Anlage-Pfad.
- **Konsistenz mit ADR-0034:** Die `position`-Spalte wird endlich benutzt (heute immer `0`); neue Inline-Anlage setzt `max(position) + 1`, `/settings/groups` exposed Up/Down-Reorder. Sidebar-Sort-Order (`ORDER BY position, name`) wird zum ersten Mal nicht-trivial.
- **`/settings/tags`-Redesign** im selben Block reduziert `legacy-shim.css`-Bedarf für eine weitere Surface (siehe ADR-0032-Addendum) — kleiner Aufräum-Bonus.
- **Tests:**
  - Pure-Unit: Inline-Create-Endpoints (Happy-Path + Race-mit-existing + invalid-Name + auth-Guard).
  - Pure-Unit: `/settings/groups` Listen-/Rename-/Delete-/Move-Endpoints (gleiche Surfaces).
  - Pure-Unit: `/settings/tags` Refactor — Rename + Color-Edit neu, Create-Path entfernt (Negativ-Test: `POST /settings/tags` ohne neue Anlage liefert 404/405 oder leitet auf Edit).
  - Pure-Unit: Audit-Events mit korrekter Metadata-Shape.
  - Pure-Unit: Sidebar-Aggregation rendert leere Gruppen nicht (Regression auf bestehenden `group_counts()`-Test).
- **Keine Schema-Migration**, keine Alembic-Datei. Keine `db_integration`-Tests im Default-Lauf.
- **Out-of-Scope für Block Z:** Drag-Drop-Reorder, Group-Beschreibung/Icon/Farbe, Multi-Group-Zugehörigkeit (M:N — ADR-0034 Re-Open), Bulk-Server-zu-Gruppe-Move, Group-Filter im Dashboard (`?group=N`-URL-Param), Tag-`position`-Spalte.

## Verworfen

- **Auto-Delete leerer Gruppen:** siehe Kontext §1. Überraschungs-Risiko > Aufräum-Nutzen.
- **Modal für Inline-Create:** zusätzlicher Klick + Focus-Trap; Inline-Eingabefeld unterhalb des Selects ist friction-ärmer und passt zur „less is more"-Linie.
- **Color-Picker im Inline-Tag-Create:** verlangsamt den primären Pfad; Default `#6b7280` ist neutral genug, Color-Edit in `/settings/tags` zugänglich.
- **Reine `<datalist>`-HTML5-Lösung** (Browser-native): keine saubere Disambiguierung zwischen „bestehenden Tag picken" und „neuen Tag erstellen". Expliziter „+ Anlegen"-Pfad ist eindeutig.
- **`Tag.position`-Erweiterung für Symmetrie:** Tags haben keine Sortier-Funktion in der Sidebar; eine ungenutzte Spalte ist unhygienisch.
- **`group.description`-Spalte:** keine erkennbare operative Notwendigkeit; ADR-0006 spricht gegen optionale Freitext-Felder.

## Re-Open-Trigger

- **Drag-Drop-Reorder** für `/settings/groups`-Position: separate ADR über das Reorder-Pattern (Optimistic-UI mit `hx-trigger="end"` + Batch-PATCH oder einzelne Up/Down-Buttons in Bulk). Heute genügen Up/Down-Pfeile.
- **Bulk-Server-zu-Gruppe-Move** (z. B. von der Sidebar aus mehrere Server selektieren und in eine Gruppe schieben): eigener Folge-Block.
- **Group-Filter im Dashboard/Findings** (`?group=N`): heute ist Filtern nur über Tags möglich (M:N). Wenn Operator-Bedarf entsteht: separate ADR.
- **Auto-Delete leerer Gruppen** wenn die Tabelle wirklich zu unübersichtlich wird (Operator-Feedback nach ≥6 Monaten Praxis-Einsatz): separater ADR mit Soft-Delete-Grace-Period + Undo.
- **Multi-Group-Zugehörigkeit (M:N)**: siehe ADR-0034 §Re-Open-Trigger.
- **Group-Beschreibung/Icon/Farbe**: nur falls Operator-Feedback substantiellen Nutzen zeigt — sonst bleibt es „leichtgewichtiges Label".
