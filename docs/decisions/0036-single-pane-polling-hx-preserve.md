# ADR-0036 — Single-Pane Dashboard-Polling mit hx-preserve + OOB-Swaps

**Status:** Akzeptiert · **Datum:** 2026-05-23 · **Block:** W — Redesign Phase 1

Bezug: [ADR-0017](0017-dashboard-pane-single-partial.md) (Dashboard-Pane als ein gemeinsames Partial), [ADR-0019](0019-dashboard-polling-not-sse.md) (Polling statt SSE), [ADR-0030](0030-server-detail-performance.md) (Sidebar-Lazy-Pattern aus Block V), [ADR-0033](0033-brand-identity-fathometer.md) §4 (Easing-Doctrine, Animation-Lifecycle), [ADR-0035](0035-daily-risk-state-heartbeat-mapping.md) (Polling-Cadence-Konsolidierung 60 s).

## Kontext

Das Block-W-Design (`docs/design/app.jsx::ActionNeededCard`, `docs/design/styles.css` `.stat--alarm`) führt eine **kontinuierliche Scan-Beam-Animation** auf der Action-Needed-Card ein:

- `.stat--alarm::before` ist ein 5.4-s-linear-infinite-Sweep mit cyan-Gradient (`mix-blend-mode: screen`) der von `-110%` translateX bis `+245%` wandert
- `.stat--alarm::after` ist ein scanlines-Pattern-Overlay mit Opacity-Cycle synchron zum Beam
- `.scan-flash`-Spans (auf `[action needed]`-Bracket, auf jedem Char der großen Zahl via `<ScanChars>`, auf dem CTA-Text + Pfeil) haben einen 5.4-s-Color-Cycle mit per-Element-`animation-delay` der per `useScanFlashSync`-JS-Hook so gesetzt wird, dass jedes Element exakt cyan-flasht wenn der Scan-Beam-Center darüber wandert

Die Animation ist das **wichtigste Brand-Signal** der ganzen Dashboard-Page (Operator sieht sofort: „da brennt was, das System scannt"). Sie muss kontinuierlich laufen.

### Konflikt mit dem heutigen Polling-Pattern

`dashboard/_detail_pane.html` heute:
```html
<div id="dashboard-pane"
     hx-trigger="every 10s [...]"
     hx-target="this"
     hx-swap="outerHTML">
  ...
</div>
```

Alle 10 s wird das gesamte `#dashboard-pane`-DOM-Element ersetzt. Konsequenzen für die neuen Animationen:

- **CSS-Animationen restarten bei jedem Swap**: das Pseudo-Element `.stat--alarm::before` wird mit dem `<div class="stat--alarm">`-Wrapper neu erzeugt → die `stat-scan` Keyframe-Animation beginnt jedes Mal bei `0%`. Visueller Effekt: alle 10 s zuckt der Scan-Beam zurück nach links.
- **`useScanFlashSync`-Hook muss bei jedem Swap die Layout-Messung neu machen**: `getBoundingClientRect()` für jeden `.scan-flash`-Span, `animation-delay` setzen. Performance ~10 ms, aber visueller Jitter weil der erste Frame nach dem Swap den per-Element-Delay noch nicht angewendet hat.
- **Sub-Sekunden-Sync-Glitch**: der Polling-Response ankommt → Browser parsed → DOM-Insert → CSS-Re-Apply → Animation-Start. In dieser Zeit (~50–150 ms) ist die Card animations-frei. Operator sieht „die wichtigste Card der App freezed alle 10 s".

### Drei Lösungen geprüft

1. **Granulares Polling pro Komponente**: Action-Card, Triage-Row, Severity-Strip, Sysline je eigener `hx-trigger` + eigener Backend-Endpoint. **Verworfen** weil:
   - 4–5 parallele HTTP-Requests pro Polling-Tick → 4× Server-Last
   - Out-of-Sync-Risiken (Action-Card 8 s alt, Triage-Row 9 s alt → Counts addieren sich nicht mehr sauber zur Sysline)
   - Mehr Backend-Code (eigene View + Context-Builder pro Container)
   - Komplexere Cache-Invalidation bei User-Aktionen (Bulk-Ack im Findings)
   - Sync-Wettlauf beim Initial-Render (4 Trigger feuern fast gleichzeitig, 4 Skeletons werden parallel ersetzt)

2. **Single-Pane outerHTML beibehalten** (heute): Animation-Restart akzeptieren. **Verworfen** weil die Scan-Beam-Animation das wichtigste Brand-Element ist — 10-s-Restart-Flash widerspricht der „kontinuierlichen Operational"-Doctrine.

3. **Single-Pane innerHTML + `hx-preserve` auf Animations-Wrappers + OOB-Swaps für Werte** — gewählt. Siehe Entscheidung.

## Entscheidung

### Polling-Pattern für das neue Dashboard

**Ein Backend-Endpoint:** `GET /_partials/dashboard/kpis` (neuer Endpoint, `app/views/dashboard_partials.py::kpis_partial`). Antwortet mit einem konsolidierten HTML-Fragment das **mehrere disjunkte OOB-Targets** enthält.

**Polling-Cadence:** 60 s sichtbarer-Tab (`hx-trigger="every 60s [document.visibilityState === 'visible']"`). Konsolidiert mit Sidebar (ADR-0035).

**Pane-Layout in `dashboard/_detail_pane.html`** (neu strukturiert):

```html
<div id="dashboard-pane"
     hx-get="/_partials/dashboard/kpis"
     hx-trigger="every 60s [document.visibilityState === 'visible']"
     hx-swap="none">          <!-- nicht den Pane selbst swappen -->

  <p class="eyebrow" id="dashboard-eyebrow">
    Dashboard · Fleet overview · last refresh ·
    <span id="dashboard-last-refresh" data-test="dashboard-last-refresh">10:37 UTC</span>
  </p>

  <section class="stats">
    <!-- Action-Needed-Card: Wrapper bleibt, Werte werden OOB getauscht -->
    <div class="stat stat--alarm" id="action-needed-card" hx-preserve="true">
      <p class="stat__label">
        <span class="bracket scan-flash">[</span>action needed<span class="bracket scan-flash">]</span>
      </p>
      <div class="stat__figure">
        <span class="stat__num" id="action-needed-num">
          <!-- ScanChars-Spans für jeden Char -->
        </span>
        <span class="stat__unit">/ <span id="action-needed-hosts-total">N</span> hosts</span>
      </div>
      <p class="stat__sub" id="action-needed-sub">
        <b>N</b> escalate · <b>N</b> act · <b>N</b> pending
      </p>
      <button class="stat__cta scan-flash" onclick="...">
        <span class="stat__cta-text">
          <!-- ScanChars-Spans für "open triage queue" -->
        </span>
        <span class="stat__cta-arrow scan-flash">→</span>
      </button>
    </div>

    <!-- Nominal-Card: nicht-animiert, kann ohne hx-preserve normal swappen -->
    <div class="stat stat--safe" id="nominal-card">
      ...
    </div>
  </section>

  <p class="section-label">Triage queue</p>
  <div class="triage" id="triage-row">
    ...
  </div>

  <p class="section-label">CVSS Severity distribution · all hosts</p>
  <div class="severity" id="severity-strip">
    ...
  </div>

  <div class="sysline" id="sysline">
    <!-- > last scan Nm ago · epss-feed synced · ... -->
  </div>
</div>
```

**Endpoint-Response `/_partials/dashboard/kpis`:**

Liefert mehrere `hx-swap-oob="true"`-Fragmente plus einen leeren Root (weil `hx-swap="none"` am Pane-Trigger):

```html
<!-- Action-Card-Werte werden gezielt aktualisiert, Wrapper bleibt erhalten -->
<span id="action-needed-num" hx-swap-oob="true">
  <span class="scan-chars">
    <span class="scan-flash">2</span><span class="scan-flash">4</span>
  </span>
</span>
<span id="action-needed-hosts-total" hx-swap-oob="true">20</span>
<p id="action-needed-sub" hx-swap-oob="true" class="stat__sub">
  <b>24</b> escalate · <b>53</b> act · <b>2982</b> pending
</p>

<!-- Nominal-Card komplett ersetzen (keine Animation) -->
<div id="nominal-card" hx-swap-oob="true" class="stat stat--safe">
  ...
</div>

<!-- Triage / Severity / Sysline komplett ersetzen -->
<div id="triage-row" hx-swap-oob="true" class="triage">
  ...
</div>
<div id="severity-strip" hx-swap-oob="true" class="severity">
  ...
</div>
<div id="sysline" hx-swap-oob="true" class="sysline">
  ...
</div>
```

**Wichtig:**
- `<div class="stat--alarm" hx-preserve="true">` ist **nicht** Teil der Response. HTMX evaluiert `hx-preserve` beim Swap-Vorgang: weil das Element existiert und `hx-preserve` trägt, wird es **nicht** ersetzt. Innere Children mit eigener `id` + `hx-swap-oob` werden aber gezielt getauscht.
- CSS-Animationen auf dem `stat--alarm`-Wrapper (Scan-Beam-`::before`, scanlines-`::after`) laufen kontinuierlich, weil das DOM-Element nie ersetzt wird.
- `useScanFlashSync`-Hook muss nach jedem Werte-Swap **einmal** die `<span class="scan-flash">`-Elemente neu vermessen (weil die Anzahl der Ziffern in der großen Zahl sich ändern kann — `24 → 28` ändert kein Layout, `99 → 100` schon). Hook lauscht auf `htmx:oobAfterSwap`-Event, debounced 50 ms, re-applied `animation-delay` pro Element.

### Last-Refresh-Eyebrow

**Clientseitig** via `setInterval(30_000)` aktualisiert. JS-Komponente (Alpine oder vanilla, Implementer-Wahl):

```js
function updateLastRefresh() {
  const el = document.getElementById('dashboard-last-refresh');
  if (!el) return;
  const d = new Date();
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  el.textContent = `${hh}:${mm} UTC`;
}
updateLastRefresh();
setInterval(updateLastRefresh, 30_000);
```

Beim Polling-Swap wird der Wert ebenfalls überschrieben (Server setzt seinen `now()` ein) — der lokale `setInterval` läuft danach mit dem neuen Wert weiter. Bei `document.hidden` (Tab unsichtbar) pausiert das HTMX-Polling, aber `setInterval` läuft weiter → wenn Tab sichtbar wird, ist die Uhr aktuell.

### Sidebar bleibt eigenes Polling-Target

`/_partials/sidebar` und `/_partials/sidebar/batch` (ADR-0035) sind **eigene** Endpoints mit eigenem Polling-Trigger (am `<ul id="server-list">` bzw. via Viewport-Pattern). Dashboard und Sidebar pollen unabhängig.

### Was geht nicht in den Dashboard-OOB-Response

- Sidebar-Updates: separater Pfad
- Header/Topbar-Updates: statisch, kein Polling
- Footer: statisch, kein Polling
- Flash-Messages: bleiben request-bound (kein Polling)

## Konsequenzen

### Animation-Verhalten

- `.stat--alarm::before` Scan-Beam läuft kontinuierlich seit Page-Load, ohne Restart-Glitch.
- `.stat--alarm::after` scanlines-Pattern synchron.
- `.scan-flash`-Color-Cycle läuft kontinuierlich; nach jedem Werte-OOB-Swap wird der Sync-Hook re-run, alle Elemente bekommen frische `animation-delay`-Werte.
- `.topbar__logo-sweep`/`.topbar__logo-echo`: kontinuierlich (Topbar ist nicht in der Polling-Response).

### Test-Strategie

- Pure-Unit: `tests/views/test_dashboard_kpis_partial.py` für den Endpoint — prüft OOB-Marker (`hx-swap-oob="true"`) auf den richtigen Targets (`action-needed-num`, `action-needed-sub`, `triage-row`, etc.), prüft dass **kein** `action-needed-card`-Wrapper in der Response steht (sonst würde der OOB-Swap das `hx-preserve` überschreiben).
- Pure-Unit: `tests/templates/test_dashboard_pane_structure.py` — prüft dass `dashboard/_detail_pane.html` exakt die erwarteten IDs trägt (`action-needed-card` mit `hx-preserve="true"`, `action-needed-num`, `nominal-card`, `triage-row`, `severity-strip`, `sysline`).
- Pure-Unit: `tests/services/test_sysline_context.py` für die Sysline-Datenquellen (last_scan, epss_feed_age, kev_feed_age, worker_alive).
- **Kein** db_integration/acceptance-Test pflichtig.

### Risiken

- **HTMX-OOB-Pattern ist neu im Repo**: Reviewer-Aufwand bei der ersten Implementierung höher. Pattern wird in der Implementer-Spec mit Beispiel-Markup verankert.
- **`hx-preserve` auf einem Element mit dynamischen Children**: HTMX-Doku-Edge-Case — wenn das Element komplett aus der Response fehlt UND die Children einen OOB-Marker tragen, swapped HTMX die Children durch das `hx-swap-oob`. Verifiziert in HTMX v2.0.4. Pattern wird mit Test-Coverage (`test_dashboard_kpis_partial.py`) abgesichert.
- **JavaScript-disabled Browser**: `useScanFlashSync` läuft nicht → alle `.scan-flash`-Spans haben `animation-delay: 0` → alle flashen synchron, nicht per-Element-getimed. Funktional OK (Animation läuft, nur visuell weniger spektakulär). Kein NoScript-Fallback nötig.
- **Server-Zeit für `/dashboard/kpis`-Endpoint**: heute `_load_open_aggregates` + `_load_risk_kpi_counters` (Block V Phase D) macht das in 2 Findings-Queries. Sysline kostet 2 weitere Queries (feed_pull_log Max, settings.llm_worker_heartbeat_at). Total ~4 Queries, Wallclock <300 ms erwartet. Wenn das eng wird: weiter konsolidieren.

### Performance

- Polling-Last halbiert (10 s → 60 s). Pro offenem Tab: 1 Request pro 60 s statt 6.
- OOB-Response-Größe minimal größer als heutige Full-Pane-Response (mehrere `<div id="..." hx-swap-oob="true">`-Wrapper statt einer Wurzel), aber die Markup-Wiederholung ist marginal (~10 % more bytes).
- Browser-Cost: HTMX OOB-Swap-Logik ist O(N) über die Top-Level-Elemente der Response. Bei 5–7 OOB-Targets praktisch instant.

## Verworfen

- **Granulares Polling pro Komponente:** siehe Kontext §1. 4–5 parallele Endpoints, Out-of-Sync-Risk, mehr Backend-Code.
- **Single-Pane outerHTML beibehalten:** siehe Kontext §2. Scan-Beam-Restart-Glitch alle 10 s widerspricht der Brand-Doctrine.
- **SSE-Push vom Server:** ADR-0019 hat SSE bewusst zugunsten von Polling verworfen (Gunicorn-Worker-Bind-Problem ausser bei `gthread`-Class). Wir bleiben bei Polling.
- **DOM-Diffing-Library (z.B. Idiomorph als HTMX-Extension):** würde Animation-Preservation ohne `hx-preserve` ermöglichen. Aber: zusätzliche Library-Dependency, neues Pattern im Repo, debugging-Aufwand bei Diff-Edge-Cases. OOB-Pattern ist HTMX-nativ und ausreichend.

## Re-Open-Trigger

- Wenn ein zukünftiger Block weitere animations-tragende Komponenten ins Dashboard bringt (z.B. animierte Sparklines, animierte Trend-Graphen): das hx-preserve+OOB-Pattern muss als Standard-Anweisung in der Frontend-Doku gefasst werden.
- Wenn HTMX `hx-preserve`-Verhalten in einer zukünftigen Version (3.x?) sich ändert: Test-Coverage (`test_dashboard_kpis_partial.py`) und der Code müssen revalidiert werden.
- Wenn Operator-Feedback „Counts updaten mir nicht oft genug" lautet (60 s zu lang): zurück auf 30 s oder 20 s. Animation-Preservation bleibt unangetastet (Cadence ist nur eine Zahl im `hx-trigger`).
- Wenn die `useScanFlashSync`-Logik in einer dritten Surface (z.B. animierte Header-Stats auf Server-Detail) wiederverwendet wird: als generischer Utility-Hook ausfaktorieren.
