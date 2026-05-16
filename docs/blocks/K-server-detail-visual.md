# Block K — Server-Detail-Redesign (Layout, KPI-Sparklines, Trend, sortierbare Findings-Tabelle)

**Typ:** Visual + Backend-Feature-Block · **Branch:** `feat/block-k-server-detail-visual` · **Vorgänger:** Block J (v0.3.1, ADR-0017) · **Spec:** [ADR-0018](../decisions/0018-server-detail-visual-alignment.md) · **Visueller Soll-Stand:** [`K-mockup-prototype.html`](K-mockup-prototype.html) — Pixel-Referenz mit funktionierenden Sort/Mode/Range/Bulk-Interaktionen und Inline-SVG-Charts in unserem Ziel-Stack (Tailwind/DaisyUI/Alpine, kein React).

## Geltungsbereich

ADR-0018 spezifiziert das Server-Detail-Redesign nach dem dritten Design-Bundle (`S5lepfeL8MeibyHP1ojRbw`). Block K setzt diese Spec vollständig um:

1. **Header-Refactor:** Hostname-Größe, Hashtag-Tags, OS-Zeile mit inline „letzter scan", Status-Pill-Reihe (active + ggf. stale + ggf. db veraltet), KI-Bewertung-Button als Primary rechts.
2. **HeaderStats:** Großer Total-Findings-Counter + Tendenz-Label links; vier KPI-Kacheln mit Sparklines rechts (KEV/Critical/High/Medium).
3. **Lebenszeichen-Sektion:** Eigene Sektion mit `HeartbeatLarge` (height=56) plus 4-Spalten-Meta-Grid (Erwarteter Intervall · Letzter Scan · Trivy-DB-Alter · KEV-Ereignisse · 50T).
4. **Severity-Trend-Sektion:** StackedBarChart mit täglichen Severity-Counts über 50 Tage, Range-Toggle (24h/7T/30T/50T), Legende mit Counts und Prozenten.
5. **FindingsTable-Refactor:** Filter-Bar weg; sortierbare Spalten-Header; Mode-Toggle (flach/gruppiert/diff) + Bulk-Ack-Button + CSV-Button in der Toolbar; Bulk-Select-Checkboxes pro Zeile.
6. **Backend-Services:** Tendenz-Berechnung, On-the-fly-Daily-Severity-Snapshots, KEV-Event-50T-Counter, Server-Side-Sortierung.
7. **CSV-Export:** mode-abhängige Ausgabe (flach/gruppiert/diff).

**Out of Scope (siehe ADR-0018 §Was explizit nicht im MVP):**

- 1J-Range-Toggle.
- Suche-Input in der Findings-Toolbar (globale `/search`-View bleibt).
- Klasse-Toggle (OS+Lang/nur OS/nur Lang).
- Persistente `finding_severity_daily`-Tabelle.

## Tasks

### Phase A — Backend-Services

#### Task #1 — `Tendency`-Enum + `compute_tendency()`

Neue Datei `app/services/trend.py`:

```python
from enum import Enum
from datetime import datetime

class Tendency(str, Enum):
    STABLE = "stable"
    RISING = "rising"
    FALLING = "falling"

    @property
    def label(self) -> str:
        # Lowercase nach Design ("über 50 tage stabil").
        return {
            Tendency.STABLE: "über 50 tage stabil",
            Tendency.RISING: "über 50 tage steigend",
            Tendency.FALLING: "über 50 tage fallend",
        }[self]

def compute_tendency(
    session: Session,
    server_id: int,
    *,
    days_short: int = 7,
    days_long: int = 50,
    threshold: float = 0.05,
    now: datetime | None = None,
) -> Tendency:
    """avg(Daily-OPEN-Total über days_short) vs avg(über days_long)."""
```

**DoD:** Unit-Tests gegen vier Szenarien: stabile Reihe, klar steigend, klar fallend, leere History (`STABLE` als Default). Magic-Numbers (`5%`, `7`, `50`) sind Default-Parameter, nicht hardcodiert in der Logic.

#### Task #2 — `severity_snapshots_for_server()` + `daily_severity_counts_for_server()`

Neue Datei `app/services/severity_history.py`:

```python
def severity_snapshots_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> dict[Severity, list[int]]:
    """Pro Severity eine Liste von 50 ints: jeden Tag-Ende OPEN-Count."""

def daily_severity_counts_for_server(
    session: Session,
    server_id: int,
    *,
    days: int = 50,
    now: datetime | None = None,
) -> list[DailySeverityCount]:
    """Pro Tag ein Record (day, critical, high, medium, low, kev).
    
    `kev` ist die Anzahl der neuen KEV-Markierungen an dem Tag, nicht der
    OPEN-KEV-Count. Wird für das KEV-Event-Marker-Overlay im
    StackedBarChart benutzt.
    """

@dataclass(frozen=True)
class DailySeverityCount:
    day: date
    critical: int
    high: int
    medium: int
    low: int
    kev: int  # Anzahl Findings, die an diesem Tag kev_added_at hatten
```

OPEN-am-Tag-T-Definition (siehe ADR-0018):
- `first_seen_at <= end_of_day(T)`
- `acknowledged_at IS NULL OR acknowledged_at > end_of_day(T)`
- `resolved_at IS NULL OR resolved_at > end_of_day(T)`

Implementierung: eine `SELECT` pro Tag wäre N+1; statt dessen eine einzige aggregierte Query mit `generate_series(now()-50d, now(), '1 day')` × `LATERAL` join auf Findings, oder Python-side: Findings einmal laden und in 50 Buckets sortieren. Letztere ist einfacher und für die erwartete Größenordnung (≤10k Findings/Server) ausreichend schnell.

**DoD:** Unit-Tests gegen drei Setups: nur OPEN, gemischt OPEN/ack/resolved, mit kev_added_at. Performance-Mini-Bench mit 10k Findings × 50 Tage muss <100 ms bleiben.

#### Task #3 — `count_kev_events_50d()`

Neue Function in `app/services/severity_history.py` oder als eigenständiger Helper:

```python
def count_kev_events_50d(session: Session, server_id: int, *, now=None) -> int:
    """Anzahl distincter Findings, die in den letzten 50 Tagen entweder
    neu als KEV markiert wurden (kev_added_at >= now-50d) oder neu
    erstmalig mit is_kev=True ingestet wurden (first_seen_at >= now-50d
    AND is_kev=True)."""
```

Eine einzige `SELECT COUNT(DISTINCT id) FROM findings WHERE server_id=? AND (kev_added_at >= now-50d OR (first_seen_at >= now-50d AND is_kev=TRUE))`.

**DoD:** Unit-Test mit drei Findings: eines mit `kev_added_at` vor 30 Tagen, eines mit `kev_added_at` vor 90 Tagen, eines neu ingestet mit `is_kev=true` vor 5 Tagen → Counter zeigt `2`.

#### Task #4 — `FindingsViewFilter` um `sort` + `dir` erweitern

`app/schemas/findings_view_filter.py`:

- Neue Felder `sort: Literal["cve", "pkg", "epss", "cvss", "sev", "status", "first_seen"]` (Default `"sev"`) und `dir: Literal["asc", "desc"]` (Default `"desc"`).
- `from_request()` parst beide aus dem Query-String, validiert gegen Whitelists, fällt bei Ungültigkeit auf Default zurück.
- `to_query_string()` propagiert beide Werte.

`app/services/findings_query.py:list_findings()`:

- Neuer Parameter `sort, dir`. Build `ORDER BY` aus einem festen `dict[SortKey, Column]`-Mapping (KEIN dynamisches `text()`, ADR-Coding-Convention).

Filter-Felder aus FindingsViewFilter, die jetzt überflüssig sind (`search`, `kev_only`, `severity_min`, `finding_class`, `status`) werden zunächst **behalten**, damit URL-Bookmarks nicht brechen. Sie werden in Block K nicht mehr aus der UI gesetzt, aber der View-Handler respektiert sie weiterhin als URL-Params. Wenn ein Block-K-Reviewer aufräumen will: separate Sub-Task — nicht in dieser Phase.

**DoD:** Tests gegen `?sort=cvss&dir=desc`, `?sort=epss&dir=asc`, ungültiger `sort`-Wert fällt auf Default, ungültiger `dir`-Wert fällt auf `desc`.

#### Task #5 — CSV-Export mode-abhängig

`app/views/findings.py:export_csv` (oder wo der CSV-Endpoint lebt):

- Liest `mode`-Parameter aus dem Query-String.
- `mode=flach` → bestehendes Verhalten.
- `mode=gruppiert` → zusätzliche Spalte `Group` mit `package_name`, Sortierung: nach Gruppe, dann nach aktuellem `sort`.
- `mode=diff` → eingegrenzt auf Diff-Findings (Logik aus `app/services/diff_view.py` wiederverwenden), zusätzliche Spalte `DiffStatus ∈ {neu, resolved}`.

**DoD:** Tests in `tests/services/test_csv_export.py` für alle drei Modi.

### Phase B — Frontend-Templates und Partials

#### Task #6 — Neue Partials: KPI-Card, HeartbeatLarge, StackedBarChart

Drei neue Includes:

- `app/templates/servers/_kpi_card.html` — erwartet Variablen `label, value, tone, sparkline (list[int]), kev_indicator: bool`. SVG inline, 50 Punkte als Line + Area-Fill.
- `app/templates/servers/_heartbeat_large.html` — erwartet `cells: list[DailyStatus]` (gleiche Daten wie Sidebar-Heartbeat). Cells mit `height=56`-Äquivalent, größere Gaps, KEV-Dot-Overlay.
- `app/templates/servers/_stacked_bar_chart.html` — erwartet `days_data: list[DailySeverityCount]`. SVG mit 50 gestapelten Daily-Bars.

Plus zwei kleine Helper:

- `_macros.html` bekommt ein Macro `sort_header(field, label, current_sort, current_dir, server_id)` — erzeugt einen `<th>` mit korrektem `aria-sort`, Sort-Indikator (`↕ / ↑ / ↓`) und `hx-get`-Link.
- `_macros.html` bekommt `tendency_label(tendency)` — erzeugt den lowercased Label-Text aus dem `Tendency`-Enum.

**DoD:** Jinja-Template-Parse aller drei Partials grün. Sparkline mit 5 Datenpunkten rendert valide SVG (manuell prüfen).

#### Task #7 — `servers/detail.html` komplett neu

Header + HeaderStats + Lebenszeichen + Trend + FindingsTable in der ADR-Reihenfolge. Tag-Editor bleibt unverändert eingebunden (Block-E-Feature), allerdings unterhalb der Header-Sektion (Position klären in Block-K-Reviewer — möglicherweise als ausklappbares Akkordeon, weil der Editor visuell aufdringlich ist).

Status-Pill-Reihe: `active` als Default-Pill, plus `stale` (Pill `badge-warning badge-sm`) und `db veraltet` (Pill `badge-warning badge-sm`) wenn anwendbar — alle nebeneinander rechts vom Hostname.

`max-w-5xl mx-auto` entfällt; Container wird `max-w-[1600px]` aus dem Design.

**DoD:** Visueller Smoke gegen das Design-Mockup. `grep -nE "(card bg-base-200 shadow-sm|max-w-5xl)" app/templates/servers/detail.html` liefert keinen Treffer.

#### Task #8 — `servers/_findings_section.html` komplett neu

- Filter-Form (Zeilen 75-150 alt) ersatzlos entfernen.
- Findings-Header-Zeile umbauen: Eyebrow + Title links; Toolbar rechts mit Mode-Segment + Bulk-Ack + CSV.
- Tabelle: neue `<thead>` mit `sort_header()`-Macros und Checkbox-Spalte.
- Body-Render: mode-abhängig (`_view_list.html` / `_view_group.html` / `_view_diff.html`) bleibt erhalten — die drei View-Partials werden minimal angepasst, dass sie die Bulk-Checkbox-Spalte einbinden.
- Counts-Pills (open/ack/resolved/KEV) werden **aus der Findings-Header-Zeile entfernt** — die Information lebt jetzt in der HeaderStats-Sektion oben (KPI-Kacheln + Tendenz).

**DoD:** Filter-Form-Markup ist weg. Sort-Header reagiert auf Klick mit HTMX-Swap der Tabelle. Toolbar-Buttons funktionieren.

#### Task #9 — Bulk-Ack-Modal als Partial

Neu: `app/templates/servers/_bulk_ack_modal.html`. DaisyUI-Modal, das auf den `auswahl ack`-Button reagiert (Alpine `@click="$dispatch('open-modal', { ids: selected })"`). Inhalt: Trefferliste (max 10, Rest als „...+N weitere" gekürzt), optionales Kommentar-Textfeld (`<textarea name="note" class="textarea textarea-bordered" placeholder="Optionaler Kommentar (nicht pflichtig)">`), Submit-Button → POST auf den bestehenden Block-F-Bulk-Acknowledge-Endpoint mit `dry_run=false`.

**DoD:** Modal öffnet sich beim Klick, schließt sich nach erfolgreichem Submit. Audit-Event `bulk.acknowledged` wird ausgelöst.

### Phase C — View-Code

#### Task #10 — `server_detail.py:show()` erweitern

Im Pre-Render-Context-Build:

```python
from app.services.trend import compute_tendency
from app.services.severity_history import (
    severity_snapshots_for_server,
    daily_severity_counts_for_server,
    count_kev_events_50d,
)
from app.services.heartbeat_aggregation import heartbeats_for_servers

tendency = compute_tendency(sess, server.id)
sparklines = severity_snapshots_for_server(sess, server.id, days=50)
trend_data = daily_severity_counts_for_server(sess, server.id, days=50)
kev_events_50d = count_kev_events_50d(sess, server.id)
heartbeat_cells = heartbeats_for_servers(sess, [server.id], days=50)[server.id]
```

Alle als zusätzliche Variablen ans `servers/detail.html` reichen.

**DoD:** `mypy --strict app/views/server_detail.py` PASS. Manueller Render mit Test-Daten zeigt alle vier neuen Sektionen.

### Phase D — Tests

#### Task #11 — Service-Unit-Tests

- `tests/services/test_trend.py` — Tendency-Computation gegen handgeschriebene Daten.
- `tests/services/test_severity_history.py` — Daily-Snapshots-Korrektheit gegen ack/resolved-Lifecycles.
- `tests/services/test_kev_events.py` — KEV-Event-Counter-Logik.

#### Task #12 — View-Tests umziehen + erweitern

- Bestehende `tests/views/test_server_detail.py`-Tests gegen Filter-Bar (Status-Dropdown, Klasse-Toggle, Severity-Min, KEV-Checkbox, „filtern"-Button) **werden gelöscht** — die UI-Elemente existieren nicht mehr. URL-Param-Tests gegen `?severity=high&status=acknowledged` bleiben (die Filter-Felder bleiben im Schema erhalten, siehe Task #4-Hinweis), aber UI-Render-Tests entfallen.
- Neue Tests:
  - `test_detail_renders_tendency_label` — Tendenz-String erscheint im Header.
  - `test_detail_renders_kpi_sparklines` — 4 KPI-Kacheln mit SVG-Marker.
  - `test_detail_renders_heartbeat_large` — größere Heartbeat-Sektion mit Meta-Grid.
  - `test_detail_renders_trend_section` — StackedBarChart-SVG-Marker.
  - `test_detail_table_supports_sort_by_column` — `?sort=cvss&dir=desc` ändert die Reihenfolge.
  - `test_detail_table_renders_sort_indicator` — `aria-sort` Attribute auf den Headers.
  - `test_detail_bulk_ack_button_disabled_without_selection` — Button-State.
  - `test_detail_status_pill_shows_stale_when_stale` — Multi-Pill-Reihe.
  - `test_detail_status_pill_shows_db_veraltet_when_db_stale` — analog.
  - `test_csv_export_mode_grouped_includes_group_column` — CSV-Export-Mode.
  - `test_csv_export_mode_diff_only_diff_findings` — CSV-Export-Diff.

#### Task #13 — Adversarial-Tests

- `tests/adversarial/test_sort_param_injection.py` — `?sort=<böser-string>` fällt auf Default zurück, kein SQL-Injection-Surface.

### Phase E — Reviewer + Release

#### Task #14 — Reviewer-Checks

DoD aus dem ADR-Block:

```
ruff check . && ruff format --check .
mypy app/
pytest -v
pytest tests/services/test_trend.py tests/services/test_severity_history.py -v
pytest tests/views/test_server_detail.py -v
pytest tests/adversarial/ -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
# (Block K hat keine Migrationen, der Check ist trotzdem sinnvoll.)
docker compose up -d --build
curl -fsSL http://localhost:8000/healthz

# Visueller Smoke gegen das Design-Mockup (Screenshot-Vergleich).
# Performance-Smoke: Server mit 10k Findings, Detail-View-Render-Time <500 ms.
```

#### Task #15 — STATE.md + Tag

- Block K als „completed" eintragen mit Test-Zahl, Coverage, Performance-Werten.
- Tag-Vorschlag `v0.4.0` (User-sichtbare Detail-View-Änderungen).

## Definition of Done (zusammengefasst)

Siehe Reviewer-Checks oben. Wichtige Schwellen:

- Alle Service-Unit-Tests (Tasks #11) grün.
- Alle View-Tests (Task #12) grün, inklusive der gelöschten Filter-Bar-Tests sauber entfernt.
- Adversarial-Test (Task #13) grün.
- `mypy --strict` auf `app/services/trend.py`, `app/services/severity_history.py`, `app/schemas/findings_view_filter.py`, `app/views/server_detail.py` PASS.
- **Visueller Diff gegen [`K-mockup-prototype.html`](K-mockup-prototype.html):** zwei Browser-Tabs nebeneinander, Mockup links, laufende App rechts. Pro Sektion (Header, HeaderStats, Lebenszeichen, Trend, FindingsTable) muss das Layout, die Typografie, die Farben, die Spacings und das Interaktionsverhalten 1:1 übereinstimmen — kleine Abweichungen (±2 px) sind okay, strukturelle Unterschiede nicht. Screenshot beider Tabs als Block-K-Evidence unter `docs/blocks/K-evidence/`.
- Performance-Smoke <500 ms Server-Detail-Render bei 10k Findings.

## Risiken und Mitigation

- **Daily-Snapshot-Performance bei Server mit ≥100k Findings.** Mitigation: Mini-Bench in Task #2 muss <100 ms zeigen. Wenn der Production-Server diese Schwelle nicht hält → Re-Open-Trigger ADR-0018 (persistente Tabelle).
- **Sortier-Param als SQL-Injection-Surface.** Mitigation: Whitelist-Enum in `FindingsViewFilter`, `order_by` mappt auf statisches `dict[SortKey, Column]`-Objekt. Adversarial-Test (Task #13) sichert das ab.
- **Re-Open-Verschmierung in den Sparklines.** Mitigation: ADR-0018-Limitation dokumentiert, Re-Open-Trigger für persistente Status-History-Tabelle benannt.
- **CSV-Export-Diff-Mode produziert leere CSV bei nur einem Scan.** Mitigation: bestehende `diff_view`-Logik liefert leeren Set, CSV ist dann nur Header-Zeile. Mit klarer Hinweis-Zeile „Kein vorheriger Scan zum Vergleich" als erster Body-Zeile.
- **Inline-SVG-Skalierung bei sehr großen Bildschirmen.** Mitigation: `viewBox` mit `preserveAspectRatio="none"` und CSS-Width/Height. Vorab nicht messbar; visueller Smoke bei verschiedenen Viewport-Breiten.
- **Bulk-Ack-Modal-Hotkey-Konflikt mit globalem `/`-Shortcut.** Mitigation: Modal nutzt `keydown.stop` für Focus-Events innerhalb des Textareas, damit `/` als normales Zeichen funktioniert.

## Reihenfolge

Phase A (Backend) → Phase B (Templates) → Phase C (View) → Phase D (Tests) → Phase E (Reviewer + Release).

Innerhalb von Phase A: Tasks #1–#5 sind unabhängig und können parallel laufen.

Innerhalb von Phase B: Task #6 muss vor #7 und #8 liegen (Partials werden von beiden inkludiert). #9 (Bulk-Ack-Modal) kann parallel zu #7/#8.

Phase C wartet auf Phase A.

Phase D wartet auf Phase A + B + C.
