# ADR-0019 — Dashboard-Live-Updates via HTMX-Polling statt SSE

**Status:** Akzeptiert · **Datum:** 2026-05-16

## Kontext

Block H hat `GET /events` als Server-Sent-Events-Stream gebaut, an dem das
Dashboard via `EventSource` hängt (`app/static/js/sse.js`, `app/api/events.py`,
`app/services/event_bus.py`). Live-Smoke gegen einen einzelnen Browser im
`docker compose`-Stack zeigt seit v0.4.0 instabiles Verhalten: nach kurzer
Bedienung (Tabs auf, Reload, parallele HTMX-Fragment-Loads) hängen Requests
im Browser bis sie nach Sekunden weiterlaufen oder timeouten. Der Server
ist dabei nicht ausgelastet (`docker stats` ruhig, `ss -tan` zeigt offene
Connections die nichts tun). Diagnose:

1. **Browser-Slot-Limit (HTTP/1.1).** Chrome und Firefox erlauben pro
   Origin maximal 6 parallele TCP-Connections. Ein `EventSource` hält
   einen dieser sechs Slots **dauerhaft** belegt, solange der Tab offen
   ist. Ohne Reverse-Proxy mit HTTP/2 vor Gunicorn (im `docker-compose.yml`
   nicht enthalten, ARCHITECTURE §9 nennt es nur als Production-Empfehlung)
   addieren sich offene Tabs, Chat-Stream-Connections und „Zombie"-Streams
   nach Reload schnell zu 3–4 belegten Slots. Die verbleibenden 2–3 reichen
   nicht für die parallel feuernden HTMX-Fragments (Sidebar-Heartbeats,
   Quick-Stats, Pane-Swap). HTMX-Requests queuen im Browser, der Server
   sieht sie gar nicht — aus User-Sicht „hängt" alles.

2. **Server-Thread-Pin.** Jede offene SSE-Verbindung blockiert einen
   `gthread`-Worker-Slot für die gesamte Lebensdauer der Connection. Mit
   Default `2 × 8 = 16` Threads ist das im Single-User-Setup reichlich,
   aber im Mix mit dem Browser-Slot-Limit verstärken sich die beiden
   Probleme: der Server hat freie Threads, der Browser nicht.

3. **EventBus-Worker-Affinity.** Der `EventBus` ist in-process pro
   Gunicorn-Worker (`app/services/event_bus.py:19-26` warnt explizit
   davor). Subscribed der Browser-Tab bei Worker A und der Scan-Push
   landet bei Worker B, kommt das `scan.received`-Event nie an. Im
   Single-User-Setup ist das selten, aber wenn es passiert wirkt das
   Dashboard kaputt — und triggert Reloads, die wiederum Zombie-Slots
   produzieren.

Diese drei Effekte überlagern sich. ARCHITECTURE §6 nennt SSE als
Mechanismus für Dashboard-Live-Updates und §7 schreibt explizit
„Das Dashboard reagiert per SSE auf neue Scans und animiert das Update
der betroffenen Karte". Diese Spec-Stelle ist die Quelle der drei
Probleme — sie unterstellt einen Anwendungsfall (Multi-Subscriber-
Fan-out mit Sub-Sekunden-Latenz), den der Single-User-MVP gar nicht
braucht und mit dem aktuellen Stack nur instabil hinbekommt.

## Entscheidung

Dashboard-Live-Updates laufen ab v0.5.0 über **HTMX-Polling**, nicht
über SSE. Konkret:

- `GET /events`, `app/services/event_bus.py`, `event_bus.publish(...)`-
  Aufrufe in `app/services/findings_ingest.py`, `app/static/js/sse.js`-
  Komponente `dashboardSse` werden ersatzlos entfernt.
- Der Dashboard-Pane (`app/templates/dashboard/_detail_pane.html`) bekommt
  ein HTMX-Polling-Wrapper-Element mit
  `hx-get="<aktuelle Pane-URL>" hx-trigger="every 10s [document.visibilityState === 'visible']" hx-swap="outerHTML"`.
- Der Sidebar-Container für Server-Liste und Quick-Stats bekommt einen
  analogen Polling-Trigger auf die Sidebar-Partial-Route.
- Optional `If-None-Match`/`ETag` für 304-Antworten bei unverändertem
  State (Performance-Optimierung, kein Pflicht-Item für v0.5.0).
- Die clientseitige Stale-Re-Render-Logik (`staleTick` in `sse.js`)
  bleibt unverändert — sie pollt nur lokale Timestamps, kein
  Server-Round-Trip.

SSE bleibt **ausschließlich** für `GET /chat/{conversation_id}/stream`
erhalten — Token-Streaming einer LLM-Antwort ist der seltene Fall, in
dem die Verbindung von Natur aus kurzlebig ist (Dauer einer einzelnen
Antwort, typisch 10–60 s), und Token-Granularität ist Teil des UX-
Vertrags des Chats.

## Begründung

Polling löst alle drei oben genannten Probleme gleichzeitig:

- **Kein dauerhaft belegter Browser-Slot.** Jeder Poll ist ein normaler
  HTTP-Request, Connection wird nach der Antwort wieder freigegeben.
  Das HTTP/1.1-Slot-Limit ist kein Faktor mehr; ein Reverse-Proxy mit
  HTTP/2 ist nicht mehr Voraussetzung für Stabilität (bleibt
  Production-Empfehlung aus anderen Gründen — TLS-Terminierung,
  Static-Files-Caching, IP-Allowlist).
- **Kein dauerhaft belegter Server-Thread.** Jeder Poll bindet einen
  Thread für die Render-Dauer (typisch < 100 ms). 16 Thread-Slots
  reichen für massiv mehr gleichzeitige Tabs als ein Single-User-Setup
  je hat.
- **Kein Worker-Affinity-Bug.** Jeder Poll fragt frisch die DB; egal
  welcher Worker antwortet, der State ist konsistent.
- **Weniger Code, weniger Lifecycle.** `EventBus`, `_stream`-Generator,
  Heartbeat-Logik, `X-Accel-Buffering`-Header, `GeneratorExit`-
  Cleanup, EventSource-Reconnect-Verhalten — alles weg. Schätzwert
  ~480 LoC App-Code plus zugehörige Tests entfernen.
- **Funktioniert mit jedem Reverse-Proxy out of the box.** Keine
  proxy-spezifischen Buffer-Disable-Header nötig, kein HTTP/2-Pflicht.
- **Latenz-Vergleich.** SSE liefert Updates < 1 s, Polling im Schnitt
  N/2 s (bei 10 s-Intervall also ~5 s im Mittel). Für ein Trivy-
  Dashboard, das einmal pro Tag durchgeschaut wird (siehe ARCHITECTURE
  §1: „einmal am Tag kurz durchschaut"), ist das mit großem Abstand
  ausreichend. uptime-kuma — das selbst-erklärte UX-Vorbild — pollt
  ebenfalls.

Alternativen verworfen:

- **HTTP/2-SSE via Caddy/Traefik.** Löst nur das Browser-Slot-Problem,
  nicht den Thread-Pin und nicht den Worker-Affinity-Bug. Verlangt
  außerdem zusätzliche Compose-Service-Komplexität, die der MVP nicht
  braucht.
- **WebSockets.** Erfordert ASGI/`gevent`/`eventlet`, bricht ADR-0015
  und die `gthread`-Tech-Stack-Konstante aus `CLAUDE.md`. Asymmetrischer
  Use-Case (Server → Client) braucht keine Bidirektionalität. Selbes
  Browser-Slot-Problem (1 WebSocket = 1 von 6 Slots).
- **Postgres `LISTEN/NOTIFY` mit Long-Polling.** Löst den Worker-
  Affinity-Bug, behält aber den Thread-Pin und addiert Komplexität.
  Erwägung wenn Multi-User oder externer Push-Channel kommt.
- **Kein Live-Update.** Dashboard reagiert erst auf manuellen Reload.
  Funktional gangbar, aber UX-Regression gegenüber v0.4.0.

## Konsequenzen

**Code:**

- `app/api/events.py` (117 LoC) entfernt; `events_bp` aus
  `app/__init__.py` raus.
- `app/services/event_bus.py` (164 LoC) entfernt; `init_event_bus(app)`
  und `get_event_bus(...)`-Calls in der App-Factory raus.
- `event_bus.publish(...)`-Aufrufe in
  `app/services/findings_ingest.py` (und ggf. weitere Stellen) raus —
  Polling pflegt selbst die UI; kein Publish-Side-Effect mehr nötig.
- `app/static/js/sse.js`: Komponente `dashboardSse(...)` und der
  Bootstrap im Dashboard-Template entfernt. `staleTick(...)` bleibt
  unverändert. `window.dashboardSse`-Export raus. Datei wird zu
  `app/static/js/stale.js` umbenannt oder behält den Namen aus
  Pragmatik (Empfehlung: umbenennen, sonst irreführend).
- `csrf.exempt(stream_events)` raus.
- Polling-Trigger in `app/templates/dashboard/_detail_pane.html`
  und `app/templates/base_app.html` (Sidebar-Wrapper) eingebaut.
- `app/templates/sidebar/_server_row.html` und
  `app/templates/dashboard/_card.html`: kein `data-*`-Attribut, das
  ausschließlich SSE-Highlights triggert, entfernen (die `transition`-
  Klassen können bleiben, sie schaden nicht).

**Tests:**

- Tests gegen `/events`, `EventBus`, `dashboardSse` werden gelöscht.
- Neue Tests: Dashboard-Pane und Sidebar-Partial sind als Standalone-
  Fragmente abrufbar (geben `HX-Request`-konformes HTML zurück, kein
  `<html>`/`<head>`/`<body>`); Pane antwortet auf Polling-Trigger
  korrekt; `If-None-Match` + ETag falls implementiert.
- Adversarial: Polling-Endpoint hat dieselbe Auth-Anforderung wie der
  Dashboard-Pane (`login_required`); Rate-Limit-Verhalten gegen 60
  Polls/min ohne Effekt (Limiter darf nicht für Polling-Pfade
  triggern — andernfalls Whitelist setzen).

**Spec:**

- ARCHITECTURE §6 letzter Absatz (SSE-Beschreibung) wird umformuliert
  auf Polling.
- ARCHITECTURE §7 Dashboard-Absatz: Satz „Das Dashboard reagiert per
  SSE auf neue Scans …" entfällt; ersetzt durch Polling-Beschreibung.
- ARCHITECTURE §7a „Subtle Fade-In bei SSE-Updates" wird angepasst:
  Fade-In läuft jetzt bei HTMX-`htmx:afterSwap`-Event auf der
  gepollten Container, nicht mehr SSE-getriggert.

**ADR-Beziehungen:**

- ADR-0015 (`gthread`-Worker-Class) bleibt **„Akzeptiert"**. Die
  Begründung „zwei SSE-Endpoints, davon einer fürs Dashboard" wird
  in der Praxis auf einen reduziert (LLM-Stream). 16 Thread-Slots
  bleiben angemessen, da Polling-Requests sich Slots dauerhaft teilen
  und der LLM-Stream weiter SSE-basiert bleibt. Keine Spec-Änderung
  an ADR-0015 nötig; bei Re-Read im Kontext dieser ADR ist der
  Bezug klar.
- ADR-0017 (Dashboard-Pane-Konsolidierung) ist eine Pre-Condition
  für die saubere Polling-Implementierung: weil Pane und Full-Page
  dasselbe Partial nutzen, lässt sich `hx-get` direkt gegen die
  bestehende Pane-Route ziehen, ohne neue Endpoints zu bauen.

**Versionsstand:**

- Umbau läuft als Block L (Datei `docs/blocks/L-dashboard-polling.md`).
- Reviewer-Freigabe + Test-Grün → Tag `v0.5.0` (Spec-Korrektur mit
  substantiellem Code-Umbau und Removal eines API-Endpoints rechtfertigt
  Minor-Bump). CHANGELOG-Eintrag mit Hinweis: `GET /events` ist weg —
  aber kein extern dokumentierter API-Endpoint, kein Abwärtskompatibilitäts-
  Problem.

## Re-Open-Trigger

- Multi-User-Setup mit > 10 aktiven Tabs gleichzeitig: dann Polling-
  Last messen und ggf. auf `LISTEN/NOTIFY` mit Long-Polling umstellen
  (eigene neue ADR).
- Anforderung an Sub-Sekunden-Latenz für Dashboard-Updates (z. B. für
  einen NOC-artigen Wall-Mount-Use-Case): Polling-Intervall verkürzen
  oder SSE über HTTP/2 wiedereinführen mit explizitem Reverse-Proxy-
  Pflicht-ADR.
- Polling-Last wird DB-spürbar (> 5 % CPU-Auslastung durch reines
  Polling): ETag/304-Fast-Path nachrüsten oder Polling-Intervall auf
  20–30 s anheben.
