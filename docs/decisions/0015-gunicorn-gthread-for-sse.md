# ADR-0015 — Gunicorn `gthread`-Worker-Class für SSE-Endpoints

**Status:** Akzeptiert · **Datum:** 2026-05-15

## Kontext

Die App betreibt zwei Long-lived Server-Sent-Events-Endpoints: `GET /events` für Dashboard-Live-Updates (Block H) und `GET /chat/{cid}/stream` für LLM-Token-Streaming (Block G). Beide nutzen `flask.stream_with_context` und halten die HTTP-Connection offen, solange der Browser-Tab offen ist (Heartbeats alle 30s, Reconnect durch Browser-`EventSource`).

Der Dockerfile-Default war `gunicorn --workers 2` ohne explizite Worker-Class. Gunicorn-Default ist dann `sync` — ein Worker = ein Prozess = ein Request gleichzeitig. Eine offene SSE-Connection bindet diesen Slot dauerhaft. Mit zwei Workers reichen schon ein Browser-Tab + ein zweiter Request, um den Server unresponsiv zu machen (beobachtet 2026-05-15: Dashboard lädt einmal, dann hängt jeder Folge-Request, bis ein Tab geschlossen wird).

## Entscheidung

Gunicorn läuft mit `--worker-class gthread --threads 8` (Default, per Env-Var `SECSCAN_GUNICORN_THREADS` überschreibbar). Workers bleiben bei Default 2. Effektive Default-Kapazität: 2 × 8 = 16 gleichzeitig offene Connections.

## Begründung

`gthread` ist die einfachste Lösung mit den geringsten Konsequenzen:

- **In Gunicorn enthalten** — kein neuer Dependency, kein Monkey-Patching wie bei `gevent`/`eventlet`.
- **Thread-Safety bereits gegeben.** Die App nutzt SQLAlchemy mit scoped sessions (thread-safe), structlog (thread-safe), und der `EventBus` baut auf `queue.Queue` (thread-safe). Es gibt keinen globalen mutables State außerhalb dieser.
- **Single-User-Setup.** 16 gleichzeitige Connections decken den Use-Case (ein paar offene Tabs, vielleicht ein paar parallele HTMX-Fragment-Loads) mit großem Sicherheitspuffer ab.
- **Minimaler Memory-Overhead.** Threads teilen den Prozess-Speicher; der Sprung von 2 zu 16 Connection-Slots kostet praktisch nichts gegenüber 16 Worker-Prozessen.

Alternativen verworfen:

- **`gevent`/`eventlet`** — Async-Worker, monkey-patcht `socket`/`ssl`/`time`. Funktioniert mit Flask, aber: zusätzlicher Dependency, Risiko von Inkompatibilitäten mit `psycopg`-C-Extension, schwerer zu debuggen. Overkill für Single-User.
- **`--workers` einfach erhöhen** — skaliert nicht (n Browser-Tabs → n Worker-Prozesse), Memory-teuer, löst das Problem nur quantitativ.
- **SSE durch HTMX-Polling ersetzen** — würde §6/§7 der ARCHITECTURE umschreiben. Mehr Latenz, mehr DB-Load.

## Konsequenzen

- Worker-Class ist im Dockerfile hartkodiert (`--worker-class gthread`). Worker-Anzahl, Thread-Anzahl und Timeout sind per Env steuerbar (`SECSCAN_GUNICORN_WORKERS`, `SECSCAN_GUNICORN_THREADS`, `SECSCAN_GUNICORN_TIMEOUT`).
- Neuer Default in `.env.example`: `SECSCAN_GUNICORN_THREADS=8`.
- Block-H- und Block-G-Implementer dürfen davon ausgehen, dass mehrere gleichzeitige SSE-Streams unterstützt werden. Wer neue Long-lived-Endpoints baut, muss nichts Spezifisches tun.
- Code in Request-Handlern und Services darf **keine** Process-Global-Mutables ohne Lock anfassen. Bisherige Stellen (`event_bus`-Subscriber-Set) sind bereits thread-safe.

## Re-Open-Trigger

Wenn die App mehr als ~16 gleichzeitige aktive Tabs unterstützen muss (z. B. Multi-User durch späteres SSO), oder wenn ein DB-Query unter `gthread` blockend wird und Throughput limitiert, dann `gevent`/`eventlet` evaluieren — inklusive Verträglichkeit mit `psycopg` und `argon2-cffi`.
