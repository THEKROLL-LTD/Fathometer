# ADR-0034 — Host-Group-Datenmodell (1:N, nullable, ohne Default-Group)

**Status:** Akzeptiert · **Datum:** 2026-05-23 · **Block:** W — Redesign Phase 1

Bezug: [ADR-0003](0003-push-not-pull.md) (Server-Registrierung via Agent-Bootstrap), [ADR-0021](0021-agent-bootstrap-installer.md) (Bootstrap-Token-Flow), [ADR-0035](0035-daily-risk-state-heartbeat-mapping.md) (Sidebar-Aggregation-Pattern), keine Berührung zu Tag-Modell ([Tag](../../app/models.py) bleibt unangetastet).

## Kontext

Heute sind alle Server in der Sidebar eine flache Liste (`sidebar/_server_list.html`, sortiert nach `Server.id`). Tags existieren als M:N-Junction (`server_tags`) und werden im Filter genutzt — sie sind aber semantisch "free-form labels" (z.B. `prod`, `db`, `customer-x`) und kein Hierarchie-Werkzeug.

Das Design (`docs/design/app.jsx`) führt **gruppierte Sidebar-Sektionen** ein: collapsible Group-Headers mit Name + Host-Count + aggregierten ESCALATE/ACT-Counts. Im Design-Mock werden die Gruppen aus Hostname-Prefixen abgeleitet (`deriveGroup()`-JS-Funktion: `db-` → `DB`, `edge-` → `Edge` etc.) — das ist Demo-Code. Real brauchen wir ein echtes, vom Operator pflegbares Group-Modell.

Drei Modellierungs-Optionen wurden geprüft:

1. **1:N (`Server.group_id` nullable FK auf `server_groups`-Tabelle)** — gewählt.
2. **M:N (Junction-Table `server_group_links`)**: Server kann in mehreren Gruppen sein. Verworfen weil:
   - Sidebar-Anzeige wird mehrdeutig (Server taucht in mehreren Group-Buckets auf?).
   - Aggregat-Counts pro Group werden double-count-fähig (`SUM(escalate) GROUP BY group_id` zählt einen Server in zwei Gruppen doppelt).
   - Single-User-MVP — kein operativer Bedarf für mehrfache Gruppen-Zugehörigkeit.
3. **Tag-Erweiterung (`Tag.kind`-Diskriminator: `'group'` vs. `'free'`)**: Verworfen weil:
   - Tags sind M:N, Group ist 1:N — die zwei Semantiken passen schlecht in eine Tabelle.
   - Tag-CRUD-UI (`app/templates/settings/tags.html`) müsste `kind`-Filter überall mitziehen.
   - Reihenfolge-Konzept (Group.position) existiert in Tag nicht.

## Entscheidung

### Schema

**Neue Tabelle `server_groups`** (Migration 0014):

| Spalte       | Typ                       | Constraint                                           |
|--------------|---------------------------|------------------------------------------------------|
| `id`         | INTEGER                   | PRIMARY KEY, IDENTITY                                |
| `name`       | VARCHAR(64)               | NOT NULL, UNIQUE, CHECK `name ~ '^[A-Za-z0-9 _.-]+$'` |
| `position`   | INTEGER                   | NOT NULL, DEFAULT 0                                  |
| `created_at` | TIMESTAMPTZ               | NOT NULL, DEFAULT now()                              |

- Name-Regex erlaubt alphanumerisch + Space, Underscore, Dot, Dash. **Keine** `<`/`>`/`&`/Quote/etc. — verhindert HTML-Injection bei freier Anzeige (zusätzlich zur Jinja-Autoescape).
- Name-Länge 1–64 Zeichen (CHECK `length(name) BETWEEN 1 AND 64` in Alembic-Migration als Pflicht).
- `position` ist die Sidebar-Sortier-Reihenfolge (kleinster Wert zuerst). Bei Ties: alphabetisch nach `name` (ORDER BY position, name). Default 0 erlaubt Operator-Insert ohne Reihenfolge-Sorge.

**`servers`-Spalten-Erweiterung** (in derselben Migration 0014):

| Spalte     | Typ      | Constraint                                              |
|------------|----------|---------------------------------------------------------|
| `group_id` | INTEGER  | NULLABLE, FOREIGN KEY → `server_groups(id)` ON DELETE SET NULL |

- `NULL` → Server hat keine Group, gehört zur „ungrouped"-Sektion in der Sidebar.
- `ON DELETE SET NULL` → Wenn eine Gruppe gelöscht wird, fallen die Server in die ungrouped-Sektion zurück (keine Server gehen verloren).
- **Kein** Foreign-Key-Constraint auf Group-Side mit `ON DELETE CASCADE` — wir wollen explizit kein Server-Delete bei Group-Delete.

**Keine Default-Group wird seed-installiert.** Tabelle ist nach Migration leer.

### Sidebar-Verhalten

**Wenn `server_groups` leer ist** (Phase-1-Default, kein Group-CRUD-UI):
- Sidebar rendert eine **flache Liste** aller Server. Kein Group-Header, kein Bucket-Concept.
- Header oben (`N hosts · N alarm`) und Spalten-Header (`host · escalate · act`) bleiben.
- Optisch identisch zum Pre-Block-W-Zustand (außer den anderen Design-Tokens).

**Wenn ≥1 Group existiert und ≥1 Server zugeordnet ist:**
- Sidebar rendert **zwei Sektionen**, in dieser Reihenfolge:
  1. **Groups zuerst** (oben), sortiert nach `position` aufsteigend, Ties alphabetisch.
     - Jeder Group-Header: chevron, Group-Name (uppercase mono bold), Host-Count, aggregierte ESCALATE + ACT (Summe der Server in der Gruppe).
     - **Default eingeklappt** (`collapsed`-Set initial enthält alle Group-Keys).
     - Klick auf Header toggelt collapse.
     - Auto-Expand bei aktiver Filter-Suche wenn die Group ≥1 Match enthält (Such-Surfacing — Pattern aus Design-Mock).
  2. **Ungrouped flach darunter** — alle Server mit `group_id IS NULL`, kein Bucket-Header, kein Indent. Liegen visuell „nach" den eingeklappten Gruppen.

**Begründung der Reihenfolge "Gruppen oben, ungrouped unten":** wenn ungrouped 50+ Server enthält und Gruppen unten lägen, würden die Group-Headers off-screen rutschen → Operator findet sie nicht. Gruppen oben + eingeklappt → immer sichtbar, immer erreichbar, ungrouped ist „inbox" für noch-nicht-klassifizierte Server.

### Aggregat-Counts pro Group

Service-Funktion `app/services/sidebar_group_aggregates.py::group_counts(session) -> dict[int, dict[str, int]]`:
- Eine GROUP-BY-Query auf `findings` + Server-Join:
  ```sql
  SELECT s.group_id,
         COUNT(*) FILTER (WHERE f.risk_band = 'escalate') AS escalate,
         COUNT(*) FILTER (WHERE f.risk_band = 'act')      AS act,
         COUNT(DISTINCT s.id)                              AS hosts
  FROM findings f
  JOIN servers s ON s.id = f.server_id
  WHERE f.status = 'open' AND s.group_id IS NOT NULL
  GROUP BY s.group_id
  ```
- Rückgabe: `{group_id: {"escalate": n, "act": m, "hosts": h}}`.
- `NULL`-Group wird separat aggregiert (Header-Counter, nicht pro-Bucket-Header).
- Konsistent mit `escalate_act_counts_by_server` aus Block V (Phase C) — Pattern wiederverwendet.

### CRUD-UI (Out of Scope für Block W)

**Block W liefert kein UI für:**
- Anlegen einer neuen Group
- Umbenennen einer Group
- Löschen einer Group
- Server zu einer Group zuordnen oder umbuchen
- Reihenfolge ändern (`position` editieren)

**CRUD kommt in einem späteren Block** (vermutlich gemeinsam mit dem Server-Detail-Redesign, weil dort die Group-Auswahl pro Server am natürlichsten ist). Bis dahin sind Gruppen leer (Migration legt nur Tabelle an, keine Seed-Daten). Operator kann technisch via `psql` oder einer Maintenance-Skript-CLI Gruppen anlegen, das ist Power-User-Workaround.

### Migration 0014

```python
# alembic/versions/0014_block_w_server_groups.py
revision: str = "0014_block_w_server_groups"
down_revision: str | None = "0013_remove_default_theme"

def upgrade() -> None:
    op.create_table(
        "server_groups",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
        sa.Column("position", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("length(name) BETWEEN 1 AND 64", name="ck_server_groups_name_length"),
        sa.CheckConstraint("name ~ '^[A-Za-z0-9 _.-]+$'", name="ck_server_groups_name_charset"),
    )
    op.add_column(
        "servers",
        sa.Column("group_id", sa.Integer, sa.ForeignKey("server_groups.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_servers_group_id", "servers", ["group_id"])

def downgrade() -> None:
    op.drop_index("ix_servers_group_id", "servers")
    op.drop_column("servers", "group_id")
    op.drop_table("server_groups")
```

Roundtrip-Pflicht: `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` muss in Block-W-DoD grün laufen.

## Konsequenzen

- **Backwards-compatibility:** Heutige Server-Records bekommen `group_id = NULL` durch das Default-Verhalten von ADD COLUMN ohne DEFAULT — keine Daten-Migration, keine Downtime, kein Backfill.
- **`ServerCard`/`ServerRowContext`-Datatypes** (siehe `app/views/_sidebar_context.py`) bekommen ein optionales `group_id: int | None`-Feld plus die Group-Liste als separater Context-Key (`sidebar_groups: list[GroupContext]`). Render-Template entscheidet pro Server: ist `group_id` gesetzt → in `groups[group_id].hosts` einsortieren; sonst → in `ungrouped`-Liste.
- **Sidebar-Polling-Endpoint** (`/_partials/sidebar`) und der neue Viewport-Batch-Endpoint (ADR-0035) müssen `group_id` mitgeben damit das Frontend weiß welche Sektion das Host gehört. JSON-Schema-Erweiterung im Polling-Response (Pure-Unit-Test pflichtig).
- **Filter mit Tag**: bleibt unverändert (Tag-Filter operiert auf `server_tags`-Junction). Group-Filter ist explizit **nicht** Teil von Block W (kein `?group=N`-URL-Param). Wenn ein Operator nur die DB-Server sehen will: heute via Tag, kein neuer Code.
- **Tests:**
  - Pure-Unit: `tests/services/test_sidebar_group_aggregates.py` für die GROUP-BY-Aggregation (Mock-Session, Tuple-Return).
  - Pure-Unit: `tests/views/test_sidebar_context.py` erweitert um Group-Sektion-Aufbau (leere Groups, gemischt, alle ungrouped, alle grouped).
  - Pure-Unit: Template-Smoke-Test gegen Jinja-Render (`tests/templates/test_sidebar_group_render.py`) — bei leeren Groups flache Liste, bei ≥1 Group zwei Sektionen mit Reihenfolge "Groups oben, ungrouped unten".
  - Pure-Unit: Filter-Auto-Expand-Test (`tests/templates/test_sidebar_filter_expand.py` falls JS-Pure-Test-fähig — sonst als Doc-Note für manuellen Smoke).
  - **Keine** `db_integration`-Tests pflichtig — die `group_id`-Spalte ist eine simple FK, die Aggregations-Logik ist getestet ohne echte DB.

## Verworfen

- **Default-Group seed („Ungrouped" als echte DB-Row)**: würde implizieren dass Group existiert, aber die Sidebar zeigt sie als Bucket-Header an — `NULL` = ungrouped ohne Bucket-Header ist sauberer.
- **M:N (`server_group_links`-Junction)**: siehe Kontext §2.
- **Tag-Erweiterung mit `kind`-Diskriminator**: siehe Kontext §3.
- **Hostname-Prefix-Derivation** (Design-Mock-Logik): keine echte CRUD, brittle, jede neue Hostname-Konvention bricht die Mapping-Tabelle.
- **`Server.group_id NOT NULL` mit Default-Group**: würde Schema-mäßig sauberer wirken, aber Default-Group ist UI-Schmier (Bucket-Header für „Ungrouped" lenkt vom Inhalt ab). User-Anweisung (2026-05-23): „flach, keine ungrouped oder default erfinden".

## Re-Open-Trigger

- Wenn ein Operator den Bedarf für Multi-Group-Zugehörigkeit äußert (z.B. „Server X ist sowohl `prod` als auch `db`"): Modell-Wechsel auf M:N + Tag-Refactor als Folge-ADR.
- Wenn Group-Hierarchien (verschachtelte Gruppen, z.B. `Prod > DB > Hetzner`) gewünscht werden: separate ADR mit Tree-Model (Closure-Table o.ä.).
- Wenn `server_groups.position` als Drag-Drop-Reorder im UI implementiert wird: separate ADR über das Reorder-Pattern (Optimistic-UI mit `hx-trigger="end"` + Batch-PATCH oder einzelne Up/Down-Buttons).
