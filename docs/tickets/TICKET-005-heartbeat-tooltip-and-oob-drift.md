# TICKET-005 — Heartbeat-Bar: Template-Bug, OOB-Drift, Mouseover-Overlay

**Status:** Offen (entdeckt 2026-05-24 als Post-Block-W-Bugfix-Bedarf)
**Komponenten:** `app/templates/sidebar/_heartbeat_bar.html`, `app/templates/sidebar/_server_row.html`, `app/templates/_partials/sidebar_batch_oob.html`, `frontend/src/css/components/sidebar.css`, `frontend/src/js/app.js`, `tests/templates/test_heartbeat_30_ticks.py`, `tests/views/test_sidebar_batch.py`
**Umfang:** Frontend-Template-Bug + neuer Hover-Overlay + Drift-Fix zwischen Initial-Render und OOB-Response. Keine Schema-Migration, keine Backend-Architektur-Änderung, keine neuen Routen.
**Branch:** `fix/block-w-heartbeat-tooltip`
**Geschätzter Aufwand:** ~2,25 h (Minimum + Split-Commits, ohne ADR)
**Verwandte ADRs:** [ADR-0033](../decisions/0033-brand-identity-fathometer.md) §3 Color-Reduction, [ADR-0035](../decisions/0035-daily-risk-state-heartbeat-mapping.md) §Frontend-Mapping
**Verwandte CLAUDE.md-Sektion:** „HTMX-OOB-Single-Source-Pattern" (mit diesem Ticket eingeführt — Ticket ist der konkrete erste Anwendungsfall)

## Problem

Sidebar-Heartbeat-Bar (Block W Phase C, Commit `101e27d`) zeigt in der Live-Umgebung drei Defekte gleichzeitig — verifiziert am 2026-05-24 mit echter k3s-Fixture-DB:

### Defekt 1 — Alle 30 Cells erscheinen uniform grau (Root-Cause: Template-Bug)

`app/templates/sidebar/_heartbeat_bar.html:30`:

```jinja
{% set band = cell.dominant_risk_band.value if cell.dominant_risk_band else None %}
```

`.value` ist falsch. `DailyStatus.dominant_risk_band` ist ein plain `str | None` (`RiskBand = str` in `app/services/heartbeat_aggregation.py:60`; `Finding.risk_band: Mapped[str | None]` in `app/models.py:399`), **kein Enum**. Jinja resolved `.value` auf einem String stillschweigend zu `Undefined`. Jeder nachfolgende `{% if band == 'escalate' %}`/`{% elif band in ('act', 'mitigate') %}` ist `False`, alles fällt in den `{% else %}`-Zweig → immer `beat--ok` (grau), immer `band` leer im `title` und `data-band`.

**Symptom-Verifikation:** Auf rke2-sv-0 existieren 6392 OPEN-Findings mit `risk_band IN ('escalate','act')`, davon ~4246 escalate, alle mit `first_seen_at` zwischen 2026-05-22 und 2026-05-24. Die letzten 2–3 Heartbeat-Cells (heute, gestern, vorgestern) müssten cyan (`beat--alarm`) sein. Sie sind grau. Sidebar-Counts daneben zeigen die 4246 korrekt — die Aggregations-Pipeline arbeitet sauber, nur das Template wirft das Ergebnis weg.

### Defekt 2 — OOB-Batch-Response targetet IDs die nirgendwo existieren

`app/templates/_partials/sidebar_batch_oob.html` rendert Heartbeats und Counts mit eigenen IDs:

```jinja
<span id="sidebar-host-{{ server.id }}-heartbeat" hx-swap-oob="outerHTML:#sidebar-host-{{ server.id }}-heartbeat" …>
```

Der Initial-Render-Pfad (`_heartbeat_bar.html` + `_server_row.html`) emittiert diese IDs **nicht**. Zusätzlich verwendet die OOB-Response eigene CSS-Klassen-Schemata (`host__beat__cell host__beat__cell--alarm`) statt der Konvention aus dem Initial-Render (`host__beat-tick beat--alarm`). Konsequenz: jeder POST an `/_partials/sidebar/batch` (Viewport-IntersectionObserver-Trigger, alle 60 s oder beim Scroll-Debounce) findet seine Swap-Targets nicht — der Per-Row-Viewport-Update-Pfad ist seit Block-W-Merge tot. Das eigentliche Sidebar-Update läuft heute ausschließlich über den `outerHTML`-Swap der gesamten `#server-list` via `GET /_partials/sidebar`.

### Defekt 3 — Hover-Tooltip ist nativer Browser-Tooltip statt Design-Overlay

Pro Heartbeat-Tick steht ein `title="…"`-Attribut, das den Browser-Default-Tooltip zeigt („2026-05-17 · no scan"). Das ist nicht der Soll-Zustand. Design-Mockup (`docs/design/app.jsx::HeartbeatStrip` Zeilen 66–105, `docs/design/styles.css:485-530`) spezifiziert ein **Custom-Overlay**: positioniertes `.heartbeat-tip`-DIV oberhalb des Strips, mit formatiertem Datum („May 15, 2026") und uppercase Mono-State-Label (`ESCALATE`/`ACT`/`NOMINAL`/`UNKNOWN`) in passender Farbe (cyan für alarm, primary/secondary/tertiary für die anderen Zustände). Phase C hat nur das Farb-Mapping aus dem Design portiert, den Custom-Overlay übersehen — DoD-C #6 hat nur „30 Cells" gefordert, der Overlay tauchte in der Phase-C-Spec nicht explizit auf.

### Warum die Test-Suite den Bug nicht gefangen hat

`tests/templates/test_heartbeat_30_ticks.py:28-35` baut Mocks **mit `.value`-Attribut**:

```python
# dominant_risk_band kann ein Enum-Objekt oder None sein.
# Das Template macht: band = cell.dominant_risk_band.value if cell.dominant_risk_band else None
if dominant_risk_band is None:
    cell.dominant_risk_band = None
else:
    rb_mock = MagicMock()
    rb_mock.value = dominant_risk_band
    cell.dominant_risk_band = rb_mock
```

Der Helper hat die falsche Annahme über die Production-Type-Signatur eingefroren. Die 7 Mapping-Tests (`test_heartbeat_bar_dominant_risk_band_*_to_*`) waren grün, obwohl das Template in Produktion immer den `else`-Zweig nimmt. Klassischer Fall „Tests bestätigen die Implementierung, statt sie zu verifizieren".

## Ziel

1. Heartbeat-Cells rendern die korrekte Farbe basierend auf `dominant_risk_band` (Defekt 1).
2. Per-Row-OOB-Update-Pfad funktioniert wieder (Defekt 2): POST an `/_partials/sidebar/batch` findet seine Swap-Targets und ersetzt einzelne Heartbeat-Bars + Counts ohne Full-List-Reload.
3. Hover über einen Heartbeat-Tick zeigt das Design-konforme `.heartbeat-tip`-Overlay (Defekt 3).
4. Regression-Tests schützen vor Wiederholung: Drift-Test verhindert dass Initial-Render und OOB-Response wieder auseinanderlaufen; Mock-Helper-Korrektur verhindert dass `dominant_risk_band` wieder als Enum behandelt wird.

## Out of Scope

- Server-Detail-Heatmap (`app/templates/servers/_heartbeat_large.html`): bleibt auf `max_severity` bis zum Server-Detail-Redesign (eigener Folge-Block, vermutlich W+1).
- Clipping des `.heartbeat-tip`-Overlays am Sidebar-Rand bei den ersten und letzten Cells: erstmal akzeptieren wie im Mockup. Re-Open-Trigger falls Operator es als störend meldet.
- Repo-weiter OOB-Audit: dieses Ticket etabliert das Pattern (CLAUDE.md-Sektion), zieht aber nicht alle anderen OOB-Endpoints (Dashboard-KPIs etc.) gleich mit. Sie werden bei nächster Berührung migriert oder als separates Cleanup-Ticket.
- Rename des `host__beat__cell`-Klassen-Schemas im Production-CSS: das Schema existiert nur im (toten) OOB-Pfad, wird durch den Drift-Fix mit eliminiert. Kein eigener Migration-Schritt nötig.

## Leitplanken

- **Test-Konvention** (CLAUDE.md §Test-Konvention) strikt einhalten: nur ruff, mypy, pytest Default-Selektion. Kein db_integration/acceptance/bats/RUN_E2E/Docker-Compose proaktiv. Browser-Smoke übernimmt der Operator.
- **pytest-Timeout** (CLAUDE.md §pytest-Aufruf): jeder Bash-Aufruf mit `timeout: 120000` (Default) oder `timeout: 60000` (fokussiert).
- **HTMX-OOB-Single-Source-Pattern** (CLAUDE.md §HTMX-OOB-Single-Source-Pattern): dieses Ticket etabliert das Pattern und ist sein erster Anwendungsfall. Drift-Regression-Test ist Pflicht.
- **Color-Reduction-Doctrine** (ADR-0033 §3): „nur escalate trägt cyan, alles andere ist grau". Das Overlay-Label `--alarm` darf cyan tragen, `--warn`/`--ok`/`--unknown` müssen text-primary/secondary/tertiary-grau bleiben.
- **Sprach-Policy** (ADR-0033 §Sprach-Policy): Hover-Labels englisch (`ESCALATE`, `ACT`, `NOMINAL`, `UNKNOWN`, optional `NO SCAN`).
- **Keine Pflicht-Kommentare** (ADR-0006) — hier nicht relevant, aber als Reminder gelistet.

## Umsetzung

### Schritt 0 — Root-Cause-Template-Bug fixen (Bugfix, Top-Prio)

**`app/templates/sidebar/_heartbeat_bar.html`:**

```diff
-      {% set band = cell.dominant_risk_band.value if cell.dominant_risk_band else None %}
+      {% set band = cell.dominant_risk_band %}
```

**`tests/templates/test_heartbeat_30_ticks.py`** Helper umbauen:

```diff
 def _make_cell(
     day: date, dominant_risk_band: str | None = None, had_scan: bool = True
 ) -> MagicMock:
-    """Minimal-Mock eines DailyStatus-Objekts."""
+    """Minimal-Mock eines DailyStatus-Objekts.
+
+    `dominant_risk_band` ist im echten Code `str | None` (RiskBand = str),
+    KEIN Enum. Der Mock setzt das Attribut direkt als String."""
     cell = MagicMock()
     cell.day = day
     cell.had_scan = had_scan
-    # dominant_risk_band kann ein Enum-Objekt oder None sein.
-    # Das Template macht: band = cell.dominant_risk_band.value if cell.dominant_risk_band else None
-    if dominant_risk_band is None:
-        cell.dominant_risk_band = None
-    else:
-        rb_mock = MagicMock()
-        rb_mock.value = dominant_risk_band
-        cell.dominant_risk_band = rb_mock
+    cell.dominant_risk_band = dominant_risk_band
     return cell
```

**Verifikation:** ohne den `_heartbeat_bar.html`-Fix müssen die 7 existierenden `test_heartbeat_bar_dominant_risk_band_*_to_*`-Tests **rot** werden. Mit dem Fix grün. Damit ist der Root-Cause durch genau die Tests verifiziert, die ihn bisher verschleiert haben. Zusätzlich greppen ob noch weitere Tests im Repo das gleiche `.value`-Mock-Pattern nutzen (`grep -rn "rb_mock.value\|\.value = dominant_risk_band" tests/`) und ggf. mitziehen.

### Schritt 1 — Drift-Fix `sidebar_batch_oob.html` ↔ `_heartbeat_bar.html` (Single-Source-Pattern)

**Architektur-Entscheidung:** beide Pfade includieren dasselbe Sub-Template. OOB-Attribute kommen via Conditional-Flag.

**`app/templates/sidebar/_heartbeat_bar.html`:**
- Outer-`<div>` bekommt `id="sidebar-host-{{ server.id }}-heartbeat"` (Pflicht — bisher kein id).
- Conditional `{% if oob_swap %}hx-swap-oob="outerHTML:#sidebar-host-{{ server.id }}-heartbeat"{% endif %}` am Outer.
- Klassen-Schema bleibt: `host__beat-tick beat--alarm/warn/ok/unknown`. Das ist die 1:1-Konvention aus `docs/design/styles.css`. Das `host__beat__cell`-Schema aus dem alten OOB-Template entfällt komplett (wird durch Schritt 1 niemandem mehr ausgeliefert).
- Erwartete neue Variable: `server` (für die ID-Konstruktion); `oob_swap: bool = false` als optionales Default.

**`app/templates/sidebar/_counts.html` — NEU**, extrahiert aus `_server_row.html`:
- Wrapper-`<span>` mit `id="sidebar-host-{{ server.id }}-counts"` + Conditional `hx-swap-oob`.
- Enthält die beiden `host__count`-Spans für escalate/act-Counts (Markup 1:1 aus heutigem `_server_row.html`).
- Erwartete Variablen: `server`, `risk`, `is_loading: bool = false`, `oob_swap: bool = false`.

**`app/templates/sidebar/_server_row.html`:**
- Inline-Counts-Markup ersetzen durch `{% include "sidebar/_counts.html" %}` (mit `oob_swap=false` per Default).
- Heartbeat-Include bleibt wie heute, `oob_swap`-Variable wird per Default `false`.

**`app/templates/_partials/sidebar_batch_oob.html` — komplett ersetzen:**
- Statt eigenes Markup nur noch Schleife über `batch_servers`, pro Server `_heartbeat_bar.html` und `_counts.html` mit `oob_swap=true` includieren (`cells`/`risk` aus den Batch-Dicts wie heute).
- Vorteil: garantiert identisches Markup, kein zukünftiges Drift-Risiko.

**Tests:**
- `tests/templates/test_sidebar_heartbeat_drift.py` (neu): rendert `_server_row.html` und `sidebar_batch_oob.html` mit identischen Test-Fixtures, vergleicht strukturell:
  - Gleiche IDs (`sidebar-host-{N}-heartbeat`, `sidebar-host-{N}-counts`).
  - Gleiche Klassen-Sätze pro Heartbeat-Cell (kein `host__beat__cell` mehr — nur `host__beat-tick beat--*`).
  - Gleiche `data-*`-Attribut-Keys (`data-day`, `data-band`, `data-had-scan`).
  - Gleiche Cell-Count (30).
  - Counts-Wrapper hat in beiden Pfaden die ID + im OOB-Pfad zusätzlich `hx-swap-oob`.
- `tests/views/test_sidebar_batch.py` (existierend): Assertions auf das alte `host__beat__cell--alarm`-Schema müssen auf `host__beat-tick beat--alarm` umgestellt werden. Annahme über das OOB-Markup ändert sich, der View-Test selbst funktional gleich.

### Schritt 2 — Template-Anpassung für Custom-Tooltip

**`app/templates/sidebar/_heartbeat_bar.html`:**
- `title="…"`-Attribut **komplett raus** (Browser-Native-Tooltip weg, sonst konkurriert er mit dem JS-Overlay).
- Pro Tick setzen:
  - `data-day="{{ cell.day.isoformat() }}"` (bleibt wie heute).
  - `data-band="{{ band or '' }}"` (statt heute `band or 'none'` — leeres String macht JS-Mapping einfacher).
  - `data-had-scan="{{ '1' if cell.had_scan else '0' }}"` (NEU).
- `aria-hidden="true"` bleibt — Screenreader liest das `role="img" aria-label="30-day heartbeat"` am Outer-`<div>`.
- Skeleton-Path (cells leer): keine Tooltip-Daten, keine Änderung nötig.

### Schritt 3 — CSS für `.heartbeat-tip`-Overlay

**`frontend/src/css/components/sidebar.css`** im Abschnitt „Heartbeat-Bar" ergänzen — 1:1 aus `docs/design/styles.css:496-530` portiert:

- `.heartbeat-tip` — `position: absolute; bottom: calc(100% + 8px); transform: translateX(-50%); background: var(--surface-elevated); border: var(--border); padding: 7px 10px 8px; font-family: var(--font-mono); white-space: nowrap; pointer-events: none; z-index: 5; animation: heartbeat-tip-in 200ms var(--ease-materialize) both;`
- `.heartbeat-tip__date` — `font-size: 11px; letter-spacing: 0.04em; color: var(--text-primary);`
- `.heartbeat-tip__state` — `margin-top: 4px; font-size: 9px; font-weight: 700; letter-spacing: 0.18em; text-transform: uppercase;`
- `.heartbeat-tip__state--alarm   { color: var(--accent); }`
- `.heartbeat-tip__state--warn    { color: var(--text-primary); }`
- `.heartbeat-tip__state--ok      { color: var(--text-secondary); }`
- `.heartbeat-tip__state--unknown { color: var(--text-tertiary); }`
- `@keyframes heartbeat-tip-in { from { opacity: 0; transform: translate(-50%, 4px); } to { opacity: 1; transform: translate(-50%, 0); } }`

**Design-Entscheidung „no scan" im Overlay:** separate **Hint-Zeile** unter dem State (nicht eigene State-Variante). Begründung: „no scan" ist orthogonal zum Risk-Band — ein Tag kann theoretisch beides haben (fortbestehende Findings + kein neuer Scan an dem Tag). Eine Hint-Zeile bleibt komponierbar. Neue CSS-Regel:

- `.heartbeat-tip__hint { margin-top: 3px; font-size: 9px; letter-spacing: 0.04em; color: var(--text-tertiary); }` (kein Bold, neutrale Farbe).

### Schritt 4 — JS-Hover-Handler

**`frontend/src/js/sidebar_heartbeat_tip.js` — NEU:**

- IIFE, kein Build-Time-Framework, Event-Delegation auf `document.body` für `mouseover`/`mouseout`. Filter via `event.target.closest('.host__beat-tick:not(.host__beat-tick--skel)')` — Skeleton-Cells bekommen kein Tooltip.
- State-Mapping als Konstante:
  ```js
  const STATE_MAP = {
    escalate: { label: 'ESCALATE', cls: 'alarm' },
    act:      { label: 'ACT',      cls: 'warn'  },
    mitigate: { label: 'ACT',      cls: 'warn'  },
    pending:  { label: 'NOMINAL',  cls: 'ok'    },
    monitor:  { label: 'NOMINAL',  cls: 'ok'    },
    noise:    { label: 'NOMINAL',  cls: 'ok'    },
    unknown:  { label: 'UNKNOWN',  cls: 'unknown' },
    '':       { label: 'NOMINAL',  cls: 'ok'    },  // band leer = kein Finding
  };
  ```
- Beim `mouseover`:
  - `day = tick.dataset.day` (z.B. `"2026-05-17"`), `band = tick.dataset.band ?? ''`, `hadScan = tick.dataset.hadScan === '1'`.
  - Datum formatieren: `new Date(day + 'T00:00:00Z').toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' })` → `"May 17, 2026"`.
  - State-Lookup via `STATE_MAP[band]` (Fallback `STATE_MAP['']`).
  - Overlay-DOM bauen:
    ```html
    <div class="heartbeat-tip">
      <div class="heartbeat-tip__date">{date}</div>
      <div class="heartbeat-tip__state heartbeat-tip__state--{cls}">{label}</div>
      <div class="heartbeat-tip__hint" hidden-or-shown>no scan</div>
    </div>
    ```
    Hint-Zeile nur einfügen wenn `hadScan === false`.
  - In `tick.closest('.host__beat')` einhängen.
  - Position: `idx = Array.from(tick.parentElement.children).indexOf(tick)` → `tip.style.left = (((idx + 0.5) / 30) * 100) + '%'`.
- Beim `mouseout`: das eingefügte Overlay-Element entfernen. Referenz via WeakMap auf den Tick (`const tipByTick = new WeakMap();`), beim Leave `tipByTick.get(tick)?.remove()` und WeakMap-Eintrag clearen.
- Edge-Case Tick-Wechsel ohne Leave (z.B. schnelles Bewegen): `mouseover` auf neuen Tick → Cleanup für alten Tick triggern bevor neuer Tooltip eingefügt wird.

**`frontend/src/js/app.js`:**
- Ein neuer `import './sidebar_heartbeat_tip.js';`.

### Schritt 5 — Pure-Unit-Tests

**Erlaubte Quality-Gates** (CLAUDE.md): ruff, mypy, pytest Default-Selektion.

- **`tests/templates/test_heartbeat_30_ticks.py`** — Helper-Korrektur aus Schritt 0. Die 7 existierenden `_to_*`-Tests sind der Backstop für den Root-Cause-Fix.
- **`tests/templates/test_heartbeat_tooltip_data_attrs.py`** (neu):
  - `title=`-Attribut darf NICHT mehr im Live-Pfad-Markup vorkommen.
  - `data-day`, `data-band`, `data-had-scan` sind in jedem Live-Tick gesetzt.
  - `data-band` ist der echte String aus `dominant_risk_band` (z.B. `"escalate"`), nicht `"none"`/`""`-Default wenn der Cell einen Band hat.
  - `data-had-scan` ist `"1"` oder `"0"`.
- **`tests/templates/test_sidebar_heartbeat_drift.py`** (neu): Initial-Pfad und Batch-OOB-Pfad mit identischen Cells → strukturell gleicher Heartbeat- und Counts-Output (gleiche IDs, gleiche Klassen-Sätze, gleiche Cell-Count, gleiche `data-*`-Keys). OOB-Pfad hat zusätzlich `hx-swap-oob="outerHTML:#…"`-Attribute, Initial-Pfad nicht — sonst identisch.
- **`tests/templates/test_heartbeat_ids_present.py`** (neu, kann auch in `test_sidebar_heartbeat_drift.py` integriert werden):
  - Heartbeat-Container hat `id="sidebar-host-{N}-heartbeat"`.
  - Counts-Container hat `id="sidebar-host-{N}-counts"`.
  - In Batch-OOB-Render zusätzlich `hx-swap-oob="outerHTML:#sidebar-host-{N}-heartbeat"` bzw. `…-counts`.
- **`tests/views/test_sidebar_batch.py`** (existierend): Class-Name-Assertions umstellen (`host__beat__cell` → `host__beat-tick beat--…`).

**Bewusst weggelassen** (Operator-Smoke):
- JS-Hover-Verhalten — kein Jest/JSDOM im Repo, Browser-Smoke macht der Operator.
- Pixel-Position des Overlays — Browser-Smoke.
- Clipping-Verhalten am Sidebar-Rand — Browser-Smoke + Re-Open-Trigger falls störend.

### Schritt 6 — Lint / Type / Build / Operator-Smoke

```bash
ruff check . && ruff format --check .       # PASS Pflicht
mypy app/                                    # PASS Pflicht
.venv/bin/pytest 2>&1 | tail -30            # Bash timeout: 120000, Default-Suite PASS Pflicht
cd frontend && npm run build                 # esbuild + manifest update Pflicht
```

**Operator-Smoke (User übernimmt):**
1. Sidebar lädt — letzte 2–3 Cells für rke2-sv-0 sind cyan (`beat--alarm`), ältere grau.
2. Hover über cyan-Cell zeigt Overlay mit Datum (z.B. „May 24, 2026") + `ESCALATE`-Label in cyan, keine Hint-Zeile (had_scan=true).
3. Hover über graue Cell ohne Scan zeigt Datum + `NOMINAL` + Hint-Zeile „no scan".
4. Hover-Animation läuft (200 ms fade-in mit slight Y-translate).
5. Kein nativer Browser-Tooltip mehr.
6. Nach 60 s Polling-Tick: Heartbeat-Bar wird via OOB-Batch korrekt aktualisiert (Cell-Zustand passt zu DB-State, Scan-Beam läuft durchgehend nicht relevant — nur Cells, kein Action-Card).
7. IntersectionObserver-Scroll: bei großer Flotte (>20 Server, schmales Fenster) zeigt Scroll-Verhalten Skeleton für neu sichtbare Rows, Live-Daten kommen via Batch-Endpoint nach. (Mit nur 2–3 Hosts wahrscheinlich nicht testbar — auf späteren Operator-Test verschoben.)
8. Keine Console-Errors.

## DoD-Checkliste

1. ☐ `_heartbeat_bar.html:30` nutzt `cell.dominant_risk_band` direkt (kein `.value`).
2. ☐ `grep -rn "dominant_risk_band\.value\|risk_band\.value" app/` liefert nichts.
3. ☐ `grep -rn "rb_mock.value\|\.value = dominant_risk_band" tests/` liefert nichts.
4. ☐ Heartbeat-Container hat `id="sidebar-host-{N}-heartbeat"`, Counts-Container hat `id="sidebar-host-{N}-counts"` — sowohl im Initial-Render als auch im Batch-OOB.
5. ☐ `_partials/sidebar_batch_oob.html` includiert `sidebar/_heartbeat_bar.html` und `sidebar/_counts.html` mit `oob_swap=true` (keine duplizierte Markup-Wartung mehr).
6. ☐ `host__beat__cell`-Klassen-Schema kommt im Repo nicht mehr vor (`grep -rn "host__beat__cell" app/ frontend/ tests/` liefert nichts außer evtl. CSS-Cleanup-Reste — die mit raus).
7. ☐ Heartbeat-Tick hat keine `title=`-Attribute mehr im Live-Pfad.
8. ☐ Heartbeat-Tick hat `data-day`, `data-band`, `data-had-scan`.
9. ☐ `frontend/src/css/components/sidebar.css` enthält `.heartbeat-tip`, `.heartbeat-tip__date`, `.heartbeat-tip__state` (+ 4 Varianten), `.heartbeat-tip__hint`, `@keyframes heartbeat-tip-in`.
10. ☐ `frontend/src/js/sidebar_heartbeat_tip.js` existiert, ist in `app.js` importiert.
11. ☐ Default-`pytest` PASS, mind. 3 neue Test-Files grün (drift, tooltip-data-attrs, ids-present — oder konsolidiert).
12. ☐ `ruff check . && ruff format --check . && mypy app/` PASS.
13. ☐ `npm run build` im `frontend/`-Verzeichnis PASS, neue Assets im Manifest.
14. ☐ Operator-Smoke-Check (8 Punkte oben) durch den User abgehakt.
15. ☐ STATE.md-Eintrag unter Block W als Post-W-Bugfix mit Commit-Refs und neuen Tests.

## Risiken

| Risiko | Mitigation |
|---|---|
| **Helper-Korrektur in Schritt 0 lässt weitere Tests rot werden** (z.B. wenn andere Tests denselben Mock-Pattern nutzen). | `grep -rn "rb_mock.value\|\.value = dominant_risk_band" tests/` vor dem Fix laufen lassen, alle Hits in einem Commit mitziehen. Erwartung: nur `test_heartbeat_30_ticks.py`. |
| **Drift-Fix bricht existierende `test_sidebar_batch.py`-Assertions.** | Erwartet und Teil des Tickets (Schritt 1) — Tests umstellen, neue Erwartung ist das vereinheitlichte Markup. |
| **OOB-Conditional-Pattern (`oob_swap`-Flag) verwirrt zukünftige Implementer.** | Inline-Kommentar in beiden Partials (`_heartbeat_bar.html`, `_counts.html`) erklärt das Flag und verweist auf CLAUDE.md §HTMX-OOB-Single-Source-Pattern. |
| **`.heartbeat-tip`-Overlay wird vom Sidebar-Container geclippt** (sidebar hat `overflow-y: auto`, Overlay ragt über die Sidebar-Breite hinaus an den Rand-Ticks). | Akzeptiert in Phase 1 wie im Mockup. Re-Open-Trigger falls Operator es als störend meldet. Optionaler Folge-Fix: dynamisches Position-Klemmen via JS (Tooltip-Position messen, bei Überschreitung `left` clampen statt `translateX(-50%)`). |
| **Tick-Wechsel-Race im Hover-Handler:** schnelle Mausbewegung kann `mouseover` auf neuen Tick triggern bevor `mouseout` auf altem feuert. | WeakMap-basiertes Cleanup: bei jedem `mouseover` zuerst alten Tooltip (falls vorhanden) entfernen. Defensive Programmierung im Handler. |
| **Performance bei MouseMove über alle 30 Cells:** 30 Create/Destroy-Zyklen pro Hover-Sweep. | Akzeptabel weil DOM-Element trivial klein ist. Wenn doch spürbar (Browser-Smoke): später Overlay re-positionieren statt rebuilden (Tooltip-Pool-Pattern). |
| **Tests werden komplexer als erwartet** (Jinja-Render-Setup für drei verschiedene Templates mit Variable-Passing). | Test-Fixture-Helper teilen (`_make_cell`, `_render_heartbeat_bar`, `_render_sidebar_batch_oob`) in `tests/templates/_helpers.py` oder Conftest extrahieren. |

## Commit-Strategie

Zwei logische Commits auf `fix/block-w-heartbeat-tooltip`:

**Commit 1 — `fix(block-w): heartbeat dominant_risk_band template bug + oob drift`**
- Schritt 0: Template-Bug + Helper-Korrektur
- Schritt 1: Drift-Fix (Single-Source-Partial, neuer `_counts.html`, OOB-Template-Rewrite)
- Tests: drift, ids-present, helper-update, batch-asserts
- Reasoning: zwei verwandte Bugfixes die zusammen das tote OOB-Pattern reanimieren

**Commit 2 — `feat(block-w): heartbeat hover overlay`**
- Schritt 2: Template `title=` raus, neue `data-*`-Attrs
- Schritt 3: CSS `.heartbeat-tip`
- Schritt 4: JS-Hover-Handler
- Tests: tooltip-data-attrs (das Template-Verhalten gehört zum Feature, nicht zum Bugfix)
- Reasoning: nachgeholtes Design-Feature, in Phase C übersehen

**Branch-Merge:** nach beiden Commits + Operator-Smoke direkt auf `main` (Pattern wie TICKET-004), kein Block-Tag (kein Release-Trigger, kein neues Feature aus Operator-Sicht — Bugfix-Releases laufen ohne Tag mit).

## Aufwand

| Schritt | Aufwand |
|---|---|
| Schritt 0 — Root-Cause-Fix + Helper | 5 min |
| Schritt 1 — Drift-Fix (Partials extrahieren, Tests) | 30 min |
| Schritt 2 — Template `title=` raus, `data-*` ergänzen | 5 min |
| Schritt 3 — CSS-Block kopieren + `.heartbeat-tip__hint` | 10 min |
| Schritt 4 — JS-Hover-Handler | 45 min |
| Schritt 5 — Test-Files (3 neu, 2 existierend angepasst) | 20 min |
| Schritt 6 — Lint/Type/Build + Operator-Smoke-Übergabe | 10 min |
| **Total** | **~2,25 h** |

Nicht eingerechnet: ADR-0037 (entschieden: kein ADR, CLAUDE.md-Sektion reicht) und Operator-Browser-Smoke-Zeit.
