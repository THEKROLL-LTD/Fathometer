# Block L — Dashboard-Polling statt SSE (ADR-0019)

**Branch-Vorschlag:** `feat/block-l-dashboard-polling` · **Zielversion:** v0.5.0 · **ADR:** [0019](../decisions/0019-dashboard-polling-not-sse.md)

## Ziel

Den in Block H eingebauten `/events`-SSE-Channel inklusive in-process
EventBus, Publish-Hook im Ingest und `dashboardSse`-JS-Komponente
**ersatzlos entfernen** und durch HTMX-Polling auf dem Dashboard-Pane
und der Sidebar-Server-Liste ersetzen. SSE bleibt **ausschließlich**
für `GET /chat/{conversation_id}/stream` erhalten — LLM-Token-Streaming
ist die einzige Verwendung in der App nach Block L.

Funktional gegenüber v0.4.0 aus User-Sicht unverändert bis auf die
Update-Latenz: statt < 1 s (SSE-Push) zeigt das Dashboard Änderungen
mit durchschnittlich ~5 s Verzögerung an (Polling-Intervall 10 s).
Animations-Verhalten beim Update bleibt identisch — `sse_highlight.js`
hört bereits auf `htmx:afterSettle`, das reicht ohne Änderung.

Hintergrund und Begründung: siehe ADR-0019.

## Vorbereitung — zu lesende Sektionen

- [ADR-0019](../decisions/0019-dashboard-polling-not-sse.md) (komplett)
- `ARCHITECTURE.md` §6 (Polling-Beschreibung, aktualisiert)
- `ARCHITECTURE.md` §7 (Dashboard-Polling-Absatz, aktualisiert)
- `ARCHITECTURE.md` §7a „Subtle Fade-In bei Polling-Updates" (aktualisiert)
- [ADR-0015](../decisions/0015-gunicorn-gthread-for-sse.md) (`gthread` bleibt — bleibt für LLM-Stream relevant)
- [ADR-0017](../decisions/0017-dashboard-pane-single-partial.md) (gemeinsames Pane-Partial — Polling hängt sich direkt an die bestehende Route)

## Aufgaben

### Backend (`backend-implementer`)

1. **App-Factory** `app/__init__.py`:
   - Import `from app.services.event_bus import init_event_bus` raus.
   - Aufruf `init_event_bus(app)` (Zeilen 229–234) raus.
   - Import `from app.api.events import events_bp` raus.
   - `app.register_blueprint(events_bp)` raus.
2. **Endpoint** `app/api/events.py` (komplett 117 LoC): Datei löschen.
3. **Service** `app/services/event_bus.py` (komplett 164 LoC): Datei löschen.
4. **Ingest-Hook** `app/api/scans.py`:
   - Block bei Zeilen 283–302 (`SSE-Live-Update-Hook (Block H)`) komplett raus.
   - Der `sess.commit()` im Anschluss bleibt erhalten.
5. **Pane-Context** `app/views/dashboard.py` `_build_pane_context()`:
   - `events_url`-Block (Zeilen 172–176) raus.
   - `"events_url": events_url` aus dem Return-Dict raus.
6. **Variablen-Vertrag** im Docstring von `dashboard/_detail_pane.html`:
   - `events_url`-Bullet im Kommentar entfernen.
7. **Optional Performance (kann auch Folge-Block sein):** ETag/304 auf
   `dashboard.index` und auf die Sidebar-Server-Liste-Partial-Route.
   Hash auf `(severity_counts_signature, last_seen_max, kev_count)`-
   Tupel, `If-None-Match`-Header prüfen. Nicht-blocking für Block L —
   im Re-Open-Trigger von ADR-0019 dokumentiert.

### Frontend (`frontend-implementer`)

8. **JS** `app/static/js/sse.js`:
   - Komponente `dashboardSse(...)` (Zeilen 50–134) entfernen.
   - Export `window.dashboardSse = dashboardSse;` (Zeile 194) entfernen.
   - Datei umbenennen in `app/static/js/stale.js`. `staleTick()` bleibt
     unverändert. Top-Of-File-Doc-Kommentar entsprechend zuschneiden.
   - **Hinweis:** `sse_highlight.js` bleibt wie es ist — der Code hört
     bereits auf `htmx:afterSettle` und färbt Polling-Swaps korrekt
     ein. Der `secscan:scan-received`-Custom-Event-Listener (Zeilen
     49–56) kann entfernt werden (nie mehr gefeuert), schadet aber
     auch nicht wenn er bleibt; Empfehlung: entfernen plus
     Datei-Header-Kommentar aktualisieren.
9. **Script-Tag** `app/templates/base_app.html` Zeile 80:
   - `js/sse_highlight.js` bleibt eingebunden (Polling-Highlight läuft
     darüber).
   - `js/sse.js` → `js/stale.js` umstellen.
   - Kommentar-Zeile 65 (Alpine-Komponenten-Liste): `dashboardSse` raus,
     `staleTick` bleibt.
10. **Script-Tag** `app/templates/base.html`:
    - Zeilen 71 und 90: `dashboardSse` aus Kommentaren entfernen,
      `staleTick` bleibt.
    - Falls `base.html` `<script src=".../sse.js">` direkt einbindet:
      analog zu `base_app.html` umstellen.
11. **Dashboard-Pane** `app/templates/dashboard/_detail_pane.html`:
    - `x-data="dashboardSse(...)"` und `x-init="init()"` am Wrapper
      (Zeilen 26–29) entfernen.
    - Der Wrapper wird zum Polling-Container:

      ```jinja
      <div id="dashboard-pane"
           class="p-6"
           hx-get="{{ request.path }}{% if request.query_string %}?{{ request.query_string.decode() }}{% endif %}"
           hx-trigger="every 10s [document.visibilityState === 'visible']"
           hx-target="this"
           hx-swap="outerHTML"
           hx-headers='{"HX-Request": "true"}'>
      ```

      Begründung: `request.path` plus optionaler `query_string` erhält
      aktive Filter (`?severity=...`, `?tag=...`) im Re-Fetch. (Nicht
      `request.full_path` direkt — Flask hängt dort auch bei leerem Query
      ein `?` an, das Re-Fetch-URL kosmetisch verfälscht.) Pane rendert
      sich selbst (`hx-target="this"`, `outerHTML`) — das ID-Attribut
      `dashboard-pane` bleibt nach jedem Swap erhalten, damit der Trigger
      weiterläuft. **Wichtig:** `id` ist Pflicht, sonst frisst HTMX den
      Trigger nach dem ersten Swap.
    - `staleTick()`-Wrapper auf dem inneren Container (Zeile 54) bleibt
      unverändert.
    - Kommentar-Block Zeilen 30–35 („`dashboardSse` und `staleTick`
      (Block H) bleiben aktiv …") aktualisieren auf: Polling-Pane,
      `staleTick` bleibt lokal.
12. **Sidebar** `app/templates/base_app.html`:
    - Sidebar-Server-Liste-Container ebenfalls polling-fähig machen
      (gleicher Trigger wie Dashboard-Pane), Quelle ist die bestehende
      Partial-Route, die der Context-Processor `_inject_sidebar_context`
      bereits liefert. Implementer: neue thin Route
      `GET /_partials/sidebar` oder existierende Route mit
      `HX-Request: true`-Aware-Rendering nutzen (frontend-implementer
      sucht sich den simplesten Pfad; **bevorzugt** eine eigene Route,
      damit Logik nicht in noch einem View-Handler dupliziert wird).
    - Wenn eigene Route: `app/views/_sidebar_context.py` um einen
      passenden View ergänzen, der nur das Sidebar-Partial mit
      `HX-Request: true`-Set rendert.
13. **Templates** Quick-Stats-Counter `app/templates/dashboard/_quick_stats.html`
    und `app/templates/sidebar/_quick_stats.html`: nichts zu tun, die
    `hx-get`-Links auf `dashboard.index` funktionieren weiter.
14. **Card-Highlight** `app/templates/dashboard/_card.html`:
    - Die `data-server-id`-Attribute bleiben (werden von
      `sse_highlight.js` per `htmx:afterSettle` weiter benutzt).
    - Keine Änderung nötig.

### Aufräum-Stellen (low-prio, gleiche PR)

15. **Dockerfile** Zeilen 156–169: Kommentar-Block über `gthread` und
    `EventBus` updaten — Begründung verlagert sich auf den
    LLM-Stream-Endpoint allein. Konkret: Zeilenbereich „Long-lived-SSE-
    Endpoints (`GET /events` fuers Dashboard, `GET /chat/.../stream` …)"
    umformulieren auf „Long-lived-SSE-Endpoint (`GET /chat/.../stream`)".
    Threadzahlen 2×8 bleiben (LLM-Stream + parallele Polling-Requests).
16. **README.md** Zeilen 43, 76–84 (nginx-Snippet), 138–145 (Caddy-Snippet):
    - `/events` aus den Beispiel-Configs entfernen.
    - Buffering-Off-Block bleibt für `/chat/*/stream` relevant.
17. **CHANGELOG.md** v0.5.0-Sektion neu anlegen mit Verweis auf ADR-0019
    und Liste der entfernten Symbole (`/events`, `EventBus`,
    `event_bus.publish`, `dashboardSse`). Entwurf:

    ```markdown
    ## [v0.5.0] — 2026-MM-DD

    ### Geändert
    - Dashboard-Live-Updates laufen jetzt über HTMX-Polling (Pane + Sidebar
      alle 10 s, nur bei sichtbarem Tab) statt über Server-Sent-Events.
      Hintergrund: ADR-0019 — beobachtete Instabilität durch HTTP/1.1-
      Slot-Limit, Thread-Pinning und EventBus-Worker-Affinity.
    - LLM-Chat-Streaming (`GET /chat/<id>/stream`) bleibt unverändert SSE.

    ### Entfernt
    - `GET /events` (kein extern dokumentierter Endpoint, kein Compat-Bruch).
    - `app/services/event_bus.py`, `app/api/events.py`.
    - `dashboardSse`-Alpine-Komponente.
    - `event_bus.publish`-Hook aus dem Scan-Ingest.
    ```

### Tests (`test-writer`, anschließend)

18. **Löschen:**
    - alle Tests in `tests/api/test_events.py` (oder vergleichbar)
    - alle Tests in `tests/services/test_event_bus.py` (oder vergleichbar)
    - JS-Tests / Snapshots für `dashboardSse` falls vorhanden
19. **Neu:**
    - Test: `GET /` mit `HX-Request: true` liefert nur das Pane-Partial
      (Marker `id="dashboard-pane"`, kein `<html>`-Wrapper). (Existiert
      ggf. schon aus ADR-0017-Regression — prüfen, ggf. erweitern.)
    - Test: Sidebar-Partial-Route (sofern neu) gibt Sidebar-Markup
      ohne Page-Shell zurück und hat `@login_required`.
    - Test: Pane-HTML enthält `hx-trigger="every 10s [document.visibilityState === 'visible']"`.
    - Test: Adversarial — Rate-Limiter darf den Polling-Endpoint **nicht**
      triggern. Im Default-Limit-Setup mit `60/minute` läuft das schon
      sauber (6 Polls/min), aber explizit assertieren oder gezielt
      whitelisten.
    - Test: Filter-Persistenz — Dashboard mit `?severity=high` polled
      `dashboard.index?severity=high` (nicht `dashboard.index` ohne
      Filter).
20. **Coverage:** Suite bleibt > 90 % auf den geänderten Modulen. Insgesamt
    nach Block L erwartet ~720–740 Tests (797 vor Block L minus
    EventBus-/SSE-Tests).

### Reviewer-Aufgaben (`reviewer`)

- Komplette `git grep`-Suche nach den entfernten Symbolen — darf kein
  Treffer mehr außerhalb von ADR/Block-Brief/CHANGELOG geben:
  - `event_bus`, `EventBus`, `publish(`, `dashboardSse`, `/events`,
    `events_bp`, `stream_events`, `scan.received`
- ADR-Kohärenz: §6/§7/§7a-Updates konsistent mit ADR-0019.
- Performance-Sanity: Polling-Intervall × Anzahl Tabs × Pane-Render-
  Zeit darf nicht mehr als ~2 % CPU im Idle ausmachen. Quick-Check
  via `docker stats` während eines offenen Tabs für 60 s.
- Security: Polling-Endpoint-Auth (`@login_required`) ist da; Rate-
  Limiter triggert nicht; CSRF-Exempt darf **nicht** nötig sein (GETs
  ohnehin nicht CSRF-geschützt).

## Was NICHT in diesem Block

- Keine Multi-User-Vorbereitung (`LISTEN/NOTIFY`, Redis-Pub/Sub) —
  Re-Open-Trigger in ADR-0019.
- Keine Polling-Konfigurierbarkeit (Intervall via Settings) — 10 s
  hartkodiert reicht.
- Kein ETag/304-Fast-Path als Pflicht-Item (optional, Aufgabe 7).
- Keine Änderung am LLM-Chat-Stream — der bleibt SSE und unangetastet.
- Keine Anpassung an `tests/adversarial/` über die unter 19 genannten
  Punkte hinaus.

## Definition of Done

### Datei-Existenz

- [ ] `app/api/events.py` existiert nicht mehr
- [ ] `app/services/event_bus.py` existiert nicht mehr
- [ ] `app/static/js/sse.js` umbenannt zu `app/static/js/stale.js`
- [ ] `docs/decisions/0019-dashboard-polling-not-sse.md` vorhanden (von Spec-Phase)
- [ ] `CHANGELOG.md` enthält v0.5.0-Eintrag mit ADR-0019-Verweis

### Statische Checks

- [ ] cmd: `ruff check . && ruff format --check . && mypy app/` → exit 0
- [ ] cmd: `pytest -v --cov=app --cov-fail-under=85` → exit 0
- [ ] cmd: `pytest tests/adversarial/ -v` → alle grün
- [ ] cmd: `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` → exit 0 (keine neuen Migrations erwartet, aber Roundtrip muss weiter laufen)

### Symbol-Sweep

- [ ] cmd: `git grep -nE '/events|event_bus|EventBus|dashboardSse|scan\.received|events_bp|stream_events' -- ':!docs/decisions/0019-*' ':!docs/blocks/L-*' ':!CHANGELOG.md' ':!docs/blocks/H-*' ':!docs/SECURITY-AUDIT-*'` → leer (Treffer in historischen Docs ok)

### Build und Image

- [ ] cmd: `docker build -t secscan:latest .` → exit 0
- [ ] cmd: `docker images secscan:latest --format '{{.Size}}'` → < 200 MB
- [ ] cmd: `docker compose up -d --build` → alle Container healthy
- [ ] cmd: `curl -fsSL http://localhost:8000/healthz` → 200

### E2E-Manual

- [ ] Browser-DevTools-Network während offenem Dashboard: nur Polling-
      Requests alle 10 s gegen `dashboard.index`, **kein** offener
      `EventSource` mehr (in DevTools-Network Tab Filter „EventStream"
      → leer).
- [ ] Tab in Hintergrund schalten → Polling stoppt nach max. 10 s,
      Tab wieder aktiv → Polling läuft wieder.
- [ ] Agent pusht einen neuen Scan via `scripts/e2e_smoke.sh` (oder
      `agent/secscan-register.sh`); innerhalb der nächsten ~10 s
      animiert die Server-Karte mit dem `bg-info/20`-Fade (über
      `sse_highlight.js`'s `htmx:afterSettle`-Listener).
- [ ] LLM-Chat öffnen, eine Nachricht schicken, Token-by-Token-Stream
      kommt weiter live (Regression-Check: ADR-0019 hat den
      LLM-Stream explizit nicht angefasst).

### State-Update

- [ ] `docs/blocks/STATE.md` Block L unter „Completed" verschoben mit Datum,
      Test-Anzahl, Coverage, Branch.
- [ ] Tag `v0.5.0` gesetzt nach Reviewer-Freigabe.

## Roll-Back-Plan

Block L ist eine reine Removal-Aktion ohne DB-Migration. Falls Probleme
auftauchen die einen Roll-Back erfordern:

1. Branch `feat/block-l-dashboard-polling` verwerfen.
2. ADR-0019 auf Status „Verworfen" setzen, README-Erklärung warum.
3. Alternative Lösungsrichtung in neuer ADR dokumentieren.
4. Live-System läuft auf `v0.4.0` weiter — SSE-Hänger sind nervig aber
   nicht datenschädigend.

## Implementer-Brief (für `Agent`-Delegation)

Empfohlene Aufteilung in zwei sequenzielle Implementer-Calls plus eine
Test- und eine Review-Phase:

1. **`backend-implementer`** mit Scope „Aufgaben 1–7 + 15 (Dockerfile-
   Kommentar)". Liest ADR-0019, §6, §7, Block-Brief Punkte 1–7+15.
2. **`frontend-implementer`** mit Scope „Aufgaben 8–14 + 16 (README-
   Snippets)". Liest ADR-0019, §7, §7a, Block-Brief Punkte 8–14+16.
3. **`test-writer`** mit Scope „Aufgaben 18–20". Liest Block-Brief
   Punkte 18–20 und die geänderten View- und Template-Dateien.
4. **`reviewer`** mit der DoD-Checkliste oben.

LLM-Chat-Code (`app/api/llm_chat.py`, `app/static/js/llm_chat.js`,
`app/templates/chat/*`) ist in keinem dieser Scopes — der bleibt
unangetastet. Wer als Implementer eine Änderung dort vorschlägt:
ablehnen und auf ADR-0019 verweisen.
