# Block J — Dashboard-Pane-Konsolidierung (ADR-0017)

**Typ:** Bugfix-/Refactor-Block · **Branch:** `feat/block-j-dashboard-pane` · **Vorgänger:** Block-I-Refinement (v0.3.0) · **Spec:** [ADR-0017](../decisions/0017-dashboard-pane-single-partial.md)

## Geltungsbereich

ADR-0017 legt fest, dass der Dashboard-Detail-Pane aus genau **einem** Jinja-Partial gerendert wird, das sowohl vom Full-Page-Render-Pfad als auch vom HX-Request-Pfad konsumiert wird. Dieser Block setzt das Pattern um, beseitigt das parallele `_pane/welcome.html`-Template und sichert per Test, dass beide Render-Pfade identisches Pane-Markup liefern.

**Out of Scope:**

- Visuelle Änderungen am Dashboard-Pane jenseits dessen, was ADR-0016 vorschreibt. Die fünf KPI-Kacheln, Headline + Server-Count, Filter-Bar, Attention-Sektion und Platzhalter existieren bereits im Full-Page-Pfad — sie werden nicht neu entworfen, sondern aus dem Drift-Partial entfernt.
- Server-Detail, Settings-Sub-Tabs, Audit, Suche. ADR-0017 ist normativ für sie, aber Refactor-Arbeit dort ist ein eigener Block. Treffen wir hier nur am Rand bei den Tests.
- Neue Routen oder geänderter Variablen-Vertrag in der View-Schicht. `app/views/dashboard.py` behält Signatur und Datenfluss; nur der Render-Aufruf ändert sich.

## Ausgangslage (Stand 2026-05-16)

Konkret beobachtet beim Vergleich der laufenden App gegen das Design-Bundle `ui_kits/secscan/`:

- `app/templates/dashboard/index.html` enthält bereits Headline `<h1>Dashboard</h1>`, `{{ servers | length }} Server sichtbar`, `{% include "dashboard/_quick_stats.html" %}` mit den fünf Kacheln, Filter-Bar, Attention-Sektion und dashed-border-Platzhalter. Entspricht ADR-0016.
- `app/views/dashboard.py:177-179` rendert auf dem HX-Pfad stattdessen `app/templates/_pane/welcome.html`. Dieses Partial:
  - Keine `<h1>Dashboard</h1>`-Headline, kein Server-Count.
  - Quick-Stats als kleines Inline-`<dl>` *innerhalb* der Welcome-Card (`text-[10px]`-Labels, `text-base`-Werte) — keine Kacheln mit `bg-base-200`/`bg-error/10`/`bg-warning/10`, `p-4`, `text-2xl font-bold font-mono`.
  - CTA-Reihenfolge invertiert (`Server registrieren` als `btn-primary`).
  - Kein Platzhalter-Block.
- Resultat: jeder Reload (Full-Page) zeigt das ADR-0016-Layout, jeder Klick auf den **Dashboard**-Header-Button (HTMX-Swap) zeigt das alte Welcome-Layout.

## Tasks

### Task #1 — Pane-Partial extrahieren

`app/templates/dashboard/_detail_pane.html` neu anlegen. Inhalt ist der bisherige `{% block detail_pane %}`-Inhalt aus `dashboard/index.html` (Header mit Headline + Server-Count, `_quick_stats.html`-Include, `_filter_bar.html`-Include, optionaler `_attention.html`-Include, Platzhalter-Box).

**Variablen-Vertrag oben im Template dokumentieren:**

- `servers` — list, für `servers | length` im Count.
- `filter` — `DashboardFilter`, für `filter.is_active`.
- `quick_stats` — für `_quick_stats.html`.
- `available_tags`, `severity_threshold`, `db_stale_threshold_h`, `filter_tags` — für `_filter_bar.html`.
- `attention` — `AttentionSection`, für `_attention.html`.
- `events_url` — für die SSE-`x-data`-Wrapper.

**DoD:** Template existiert, parst ohne Jinja-Fehler, enthält keine `{% extends %}`-Direktive (es ist ein Fragment).

### Task #2 — `dashboard/index.html` zum dünnen Shell machen

`{% block detail_pane %}` reduziert sich auf `{% include "dashboard/_detail_pane.html" %}`. Der `x-data="dashboardSse(...)"`-Wrapper bleibt im Pane-Partial selbst, damit der Wrapper auch auf dem HX-Pfad aktiv ist.

**DoD:** Full-Page-Render auf `/` zeigt visuell identisches Markup wie vor dem Refactor. `tests/views/test_dashboard.py` bleibt grün ohne Anpassung der Asserts.

### Task #3 — `dashboard.py` HX-Branch umstellen

`app/views/dashboard.py:177-179`:

```python
if is_hx_request(request):
    qs = get_quick_stats(sess, filter_tags=filt.tags or None, now=now)
    return render_template("_pane/welcome.html", quick_stats=qs)
```

ersetzen durch einen Render-Aufruf auf `dashboard/_detail_pane.html` mit demselben Context-Dict wie der Full-Page-Branch. Empfohlen: einen lokalen `_build_pane_context(...)`-Helper extrahieren, den beide Branches benutzen, damit die Variablen-Liste **eine** Wartungsstelle hat.

**DoD:**

- `curl -fsSL -H 'HX-Request: true' http://localhost:8000/` liefert das Pane-Fragment mit `<h1>Dashboard</h1>`, fünf Kacheln, Platzhalter.
- `curl -fsSL http://localhost:8000/` liefert dasselbe Pane-Fragment eingebettet in `base_app.html`.
- Die beiden Responses unterscheiden sich nur im Outer-Layout (Header, Sidebar), nicht im Pane-Markup.

### Task #4 — `_pane/welcome.html` löschen

Datei entfernen. Wenn andere Templates oder Views darauf referenzieren, im selben Commit auf das neue Ziel umlenken. Vor dem Löschen:

```
grep -r "_pane/welcome" app/ tests/
```

ausführen und jeden Treffer adressieren.

**DoD:** `find app/templates -name "welcome.html"` liefert keinen Treffer. `grep -r "_pane/welcome" .` liefert höchstens noch Treffer in Doku/ADRs/Changelogs, nicht in Code oder Tests.

### Task #5 — Test gegen Re-Drift

Neuer Test `tests/views/test_dashboard_pane_consistency.py`:

```python
def test_dashboard_pane_is_identical_between_hx_and_full(client, db_app):
    full = client.get("/").get_data(as_text=True)
    hx = client.get("/", headers={"HX-Request": "true"}).get_data(as_text=True)
    # Pane-spezifische Marker: Headline, Server-Count-Span, KPI-Container, Platzhalter
    for marker in ['<h1', 'Dashboard</h1>', 'Server sichtbar',
                   'id="quick-stats"', 'Platzhalter']:
        assert marker in full
        assert marker in hx
```

Das ist der strukturelle Schutz, der ADR-0017 für die Zukunft absichert. Wenn jemand erneut zwei Templates anlegt, schlägt der Test sofort an.

**DoD:** Test grün im CI.

### Task #6 — Bestehende Test-Treffer auf `_pane/welcome` umziehen

`grep -r "_pane/welcome\|Willkommen bei secscan" tests/` durchgehen:

- `tests/views/test_sidebar_layout.py` — Treffer auf `Willkommen bei secscan`. Prüfen ob er den HX-Pfad meint; wenn ja, auf den neuen Pane-Inhalt (Headline `Dashboard`, Platzhalter-Text) umstellen. Wenn er nur prüft dass die Sidebar bei einem leeren Detail-Pane korrekt rendert, kann die Welcome-Card-Sub-Assertion entfernt werden.
- Sonstige Treffer dokumentieren und einzeln entscheiden.

**DoD:** Alle Tests aus `tests/views/` grün. Keine `_pane/welcome`-String-Konstanten mehr in `tests/`.

### Task #7 — Reviewer + Update STATE.md

`reviewer`-Agent läuft mit der DoD-Checkliste oben. Bei PASS:

- `docs/blocks/STATE.md` aktualisiert mit Block-J-Eintrag in "Completed".
- Status-Zeile auf "MVP + UI v2 + ADR-0016/0017 ready" anheben.
- ADR-0016-Header bekommt einen Vermerk: "Render-Pattern: siehe ADR-0017".
- Kein neuer Tag (Patch-Release `v0.3.1` optional, aber Block-J ändert kein User-sichtbares Verhalten außer dem Bugfix).

## Definition of Done (zusammengefasst)

```
ruff check . && ruff format --check .
mypy app/
pytest -v
pytest tests/views/test_dashboard_pane_consistency.py -v
alembic upgrade head && alembic downgrade -1 && alembic upgrade head
docker compose up -d --build
curl -fsSL http://localhost:8000/healthz
diff <(curl -sSL http://localhost:8000/ | grep -oE 'id="quick-stats"|<h1[^>]*>Dashboard</h1>|Platzhalter') \
     <(curl -sSL -H 'HX-Request: true' http://localhost:8000/ | grep -oE 'id="quick-stats"|<h1[^>]*>Dashboard</h1>|Platzhalter')
# beide Streams müssen identisch sein
```

## Risiken und Mitigation

- **`_pane/welcome.html` wird von einer weiteren View benutzt, die ich übersehen habe.** Mitigation: `grep -r` aus Task #4 ist der Cut-Point — Block startet nicht, bevor der Grep gemacht ist und alle Treffer adressiert sind.
- **`x-data="dashboardSse(...)"`-Wrapper verhält sich auf dem HX-Pfad anders, weil der `x-init` zweimal feuert.** Mitigation: Alpine.js initialisiert `x-data`-Wrapper bei jedem DOM-Insert sauber, `dashboardSse` hat einen `destroy()` der per `@beforeunload.window` greift; nochmal verifizieren dass der Wrapper bei HX-Swap keine doppelten SSE-Verbindungen aufmacht.
- **Tests, die explizit auf den alten `card-title text-base`-Welcome-Header zielen.** Mitigation: Task #6 adressiert das. Wenn ein Test verlangt dass die alte Welcome-Card existiert, ist er per ADR-0016 ohnehin veraltet und gehört umgeschrieben.

## Reihenfolge

Tasks #1 → #2 → #3 → #5 (Test schreiben **bevor** #4 läuft, damit man sieht, dass er auch vorher rot ist) → #4 → #6 → #7.
