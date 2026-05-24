# Technische Schulden

Lebende Liste bekannter technischer Schulden. Jeder Eintrag enthaelt Was/
Warum/Loesung/Aufwand/Wann. Reihenfolge nicht prio-sortiert — Prioritaet
wird beim Aufgreifen entschieden.

---

## TD-001 — Pull-Worker: Pydantic-Validation pro Row in `pull_epss`

**Was:** Im EPSS-Pull validiert `app/workers/feed_enrichment.py:pull_epss`
jede der ~250000 CSV-Zeilen einzeln mit `EpssRow.model_validate(...)`.

**Warum (Symptom):** Beobachtet 2026-05-21 unter k8s: erster EPSS-Pull
nach Worker-Start blockt `_tick()` fuer **~2:44 Minuten**, waehrend dieser
Zeit CPU am Limit (500m = 100% des cgroup-Caps), Memory bei 191% Request.
k8s-Liveness-Probe failed nach 30s × 3 = 90s → SIGTERM exit 137 →
CrashLoopBackOff bis k8s-Probes gelockert wurden (siehe TD-006).

Pydantic-v2 ist kein langsames Tool, aber pro-Row-Validation × 250000
× Slot-Allocation × Field-Defaults summiert sich. Per `cProfile` (lokal
2026-05-21) ist `model_validate` der dominierende Hotspot.

**Loesung:** Per-Row-Pydantic durch Inline-Validation ersetzen — manueller
CVE-Regex + Float-Range-Check + Append in Dict. Erwartete Wirkung:
250k Rows in <5s statt ~2 min.

```python
# Heute:
parsed = EpssRow.model_validate({"cve": row[0], "epss": float(row[1]), "percentile": float(row[2])})

# Schneller:
if not _CVE_RE.match(row[0]):
    invalid_count += 1; continue
try:
    epss = float(row[1]); pct = float(row[2])
except ValueError:
    invalid_count += 1; continue
if not (0.0 <= epss <= 1.0 and 0.0 <= pct <= 1.0):
    invalid_count += 1; continue
validated.append({"cve_id": row[0], "epss_score": epss, "epss_percentile": pct, "updated_at": now})
```

`EpssRow` bleibt fuer Tests und API-aehnliche Use-Cases bestehen.

**Aufwand:** ~30 Min Code + Tests-Anpassung. Bestehende
`tests/services/test_feed_enrichment.py`-Tests fuer `pull_epss` testen
das Verhalten end-to-end, nicht die interne Validation — sollten
unveraendert passen.

**Wann:** Bevor naechster Bug-Report aufgrund von CPU-Spikes auftaucht.
Wenn TD-002 zuerst angefasst wird, evtl. obsolet (Pull laeuft dann im
eigenen Worker-Process und blockt nichts mehr).

---

## TD-002 — Worker-Tick selbstgebaut: durch fertiges Framework ersetzen

**Was:** `app/workers/llm_worker.py` ist eine eigene Implementierung von
Heartbeat-Thread, Tick-Schleife, Sub-Tick-Scheduling (Stale-Reaper,
Debug-Log-Eviction, Feed-Pull-Check), Idle-Backoff, Mode/Budget-
Throttling-Caches, Job-Pickup mit `SELECT FOR UPDATE SKIP LOCKED`,
Worker-ID-Generation, Graceful-Shutdown-Handling. Inzwischen ~1700 Zeilen
nur Worker-Infrastruktur.

**Warum (Symptom):** Wir haben das Rad neu erfunden. Jeder neue
Sub-Tick (TD-003 Healthcheck-Robustness, EPSS-Pull, ...) braucht
defensive Try/Except, Interval-State, Wakeup-Logik, Logging. Tests
sind brittle (Threads + DB-State + Timing). Operative Risiken (z.B.
TD-001 Hotspot blockt den Hauptloop, keine Pool-Isolation) entstehen
aus dem monolithischen `_tick()`-Modell. Business-Logik (Pass-1,
Pass-2, Job-Pickup) macht <30% des Files aus.

**Loesung:** Migration auf ein etabliertes Background-Job-Framework.
Da wir per ADR-0024-Konventionen kein Redis akzeptieren wollen,
priorisieren wir Postgres-native Optionen:

| Framework | Backend | Async | Status | Kommentar |
|---|---|---|---|---|
| **procrastinate** | Postgres | sync+async | aktiv, 1.6k Stars | Top-Kandidat — Postgres-Listen/Notify, Cron-Syntax, Admin-Web-UI, OpenTelemetry. Lock-Mechanismus baut auf SKIP LOCKED — passt zu unserem Modell. |
| pgqueuer | Postgres | async-first | aktiv, kleiner | Leichtgewichtiger, aber weniger Features (kein Cron, kein Retry). |
| RQ | Redis | sync | mature | Redis-Pflicht — gegen ADR-0024. |
| dramatiq | Redis/RabbitMQ | sync | mature | Redis-Pflicht. |
| Celery | Redis/RabbitMQ | sync | mature, schwer | Overkill fuer Single-Instance. |
| APScheduler | optional Postgres | sync+async | mature | Nur Scheduler, kein Worker — waere nur fuer Sub-Ticks ausreichend, nicht fuer Job-Pickup. |

**Empfehlung:** procrastinate. Modelliert genau unser Pattern:
- Jobs in Postgres-Tabelle, Worker holt via SKIP LOCKED.
- Periodische Tasks (Cron-Syntax) ersetzen Sub-Ticks (Stale-Reaper alle
  60s, Debug-Log-Eviction alle 10min, Feed-Pull alle 24h ±Jitter).
- Job-Lifecycle (queued → started → succeeded/failed) eingebaut, inkl.
  Retry-Policy mit Backoff.
- Heartbeat ist intrinsisch (Worker-Registrierung in der DB).
- Graceful Shutdown via Signal-Handling vorgegeben.

**Migration-Skizze:**
1. Bestehende `llm_jobs`-Tabelle bleibt fuer Business-Bedeutung (Pass-1/
   Pass-2-Kontext). Procrastinate bekommt eigene `procrastinate_jobs`-
   Tabelle. Worker wird zu Adapter: pickt procrastinate-Job, lookt up
   `llm_jobs`-Zeile, fuehrt Pass-1/Pass-2 aus.
2. Sub-Ticks werden `@app.periodic`-Tasks. Stale-Reaper, Debug-Log-
   Eviction, Feed-Pull-Check.
3. Heartbeat → procrastinate-Worker-Health-API.
4. Healthcheck-Skript ruft procrastinate-Status statt eigene Heartbeat-
   Spalte. TD-006 wird damit obsolet.
5. `app/workers/llm_worker.py` schrumpft auf <500 Zeilen reine
   Job-Body-Funktionen.

**Aufwand:** ~3-5 Tage. Migration-Risiko ist real (Worker-Verhalten ist
operativ kritisch). Sollte einen eigenen ADR und mindestens einen
Schatten-Lauf gegen Live-DB bekommen bevor wir auf prod umschalten.

**Wann:** Nach Block Q-Stabilisierung. Vor weiteren Block-Erweiterungen
die neue Sub-Ticks einbringen wuerden — sonst rentiert sich die
Migration weniger.

---

## TD-003 — Healthcheck koppelt an DB-Lock-Verfuegbarkeit

**Was:** `app/workers/healthcheck.py` startet eine eigene DB-Connection
und liest `settings.llm_worker_heartbeat_at`. Wenn ein laufender
UPSERT (z.B. EPSS-Pull) Locks auf `settings` haelt, blockt der
Healthcheck.

**Warum:** Beobachtet bei TD-001 — waehrend des 2:44min-Pull-Blocks
konnte der Healthcheck nicht durchkommen. SIGTERM.

**Loesung:** Healthcheck soll **nicht** an einer DB-Connection haengen
die mit dem Worker-Hauptprocess konkurriert. Optionen:

a) **File-basiert**: Worker schreibt alle 10s `mtime` einer Pseudo-Datei
   (`/tmp/secscan-worker-heartbeat`). Healthcheck checkt File-Age.
   Keine DB-Connection im Hot-Path.
b) **Read-Replica / Read-Only-Connection** mit kuerzerem
   `statement_timeout`. Komplexer und braucht zweite DB-Connection-
   Setup.
c) **TD-002-Migration**: procrastinate hat eigene Worker-Status-API
   ohne Sub-System-Konkurrenz.

**Empfehlung:** (a) als Quick-Win wenn TD-002 nicht zeitnah kommt. Sonst
mit TD-002 obsolet.

**Aufwand:** ~1 Std fuer (a).

**Wann:** Wenn TD-002 noch >4 Wochen entfernt ist.

---

## TD-004 — `_truncate_all`-Test-Fixture macht `pg_terminate_backend`

**Was:** `tests/conftest.py:_truncate_all` ruft vor jedem `db_app`-Test
`pg_terminate_backend(pid)` auf allen DB-Connections ausser der
eigenen — als Defensive gegen Connection-Leaks aus vorherigen Tests.

**Warum:** Bei der Block-Q-Phase-1-Vollsuite trat eine Race auf:
`migrated_db`-Fixture laeuft `command.upgrade(cfg, "head")`, ein
nachfolgender `db_app`-Test trifft `_truncate_all` waehrend die
Migration noch nicht ganz geschlossen ist → `psycopg.AdminShutdown`
mitten in `CREATE TABLE scans`. Symptom: 24 setup-ERRORs in der
Vollsuite, alle mit `UndefinedTable: relation "feed_pull_log" does
not exist`.

Heute durch die Acceptance-Markierung (Migration-Tests + Model-Tests
laufen nicht mehr in der Default-Suite) maskiert.

**Loesung:** Bei RC-Vorbereitung wenn die Acceptance-Suite reaktiviert
wird:

a) `_truncate_all` soll nur Connections killen die nicht zu unserem
   eigenen Engine-Pool gehoeren — `pg_terminate_backend` mit
   `application_name`-Filter.
b) `migrated_db`-Fixture soll explizit warten bis alle Migration-
   Connections geschlossen sind bevor sie yield't.
c) Pytest in xdist-Mode-Verbot — die Race tritt sowieso nur seriell
   auf, parallel waere noch schlimmer.

**Empfehlung:** (b) zuerst — kleinster Eingriff.

**Aufwand:** ~2 Std + Validierung der vollen Acceptance-Suite (~10 min
Laufzeit).

**Wann:** Vor jedem RC.

---

## TD-005 — Test-Migration MED/HIGH zu Mocks

**Was:** 880 Tests in der Default-Suite haben `todo_mock`-Marker
(siehe `tests/conftest.py::_MOCKED_UNIT_FILES`-Negativ-Logik). Sie
laufen heute mit echter Postgres-DB.

**Warum:** Konvention `feedback_tests_unit_only` sagt pytest =
Unit-Test ohne DB. Heute eingehaltbar nur fuer die 756 Pure-Unit-Tests
plus 39 schon-refactorte LOW-Files. Der Rest braucht Service-Refactor:
- **MED** (SQL-Aggregations-Tests): `quick_stats`, `severity_history`,
  `csv_export`, `findings_query`, `llm_cache`, `llm_debug_log`,
  `group_matcher`, `stale_detection`, `trend`, `heartbeat_aggregation`,
  `llm_provider_switch`. Brauchen Repository-Pattern: Service-Methode
  bekommt `Repository`-Protokoll als Dependency-Injection, Tests
  uebergeben einen `FakeRepository`.
- **HIGH** (View/API-Tests mit Jinja/Flask-Test-Client): brauchen
  Context-Builder als reine Funktion isoliert, oder Service-DI auf der
  Endpoint-Ebene.

**Loesung:** Pro Service ein Refactor zu Repository-Pattern, dann
zugehoerige Tests umstellen. Inkrementell, nicht alles auf einmal.

**Aufwand:** ~3-5 Stunden pro Service-Familie, ~80 Stunden total fuer
alle MED+HIGH. Realistisch ein Quartals-Vorhaben.

**Wann:** Inkrementell wenn ein Service ohnehin angefasst wird.

Querverweis: TD-012 (View-Route-Architektur-Schuld) ist Vorarbeit fuer
die HIGH-Bucket-Migration — ohne saubere Context-Builder bleiben die
View-Tests notwendig db_app-gebunden. TD-011 ist die spezifische
Auspraegung fuer drei API-Endpoints ohne Service-Layer.

---

## TD-006 — k8s-Probes zu aggressiv fuer langlaufende Sub-Ticks

**Was:** Liveness/Readiness `timeoutSeconds=30 periodSeconds=30
failureThreshold=3` toleriert nur ~90s Blockzeit. Lang laufende
Sub-Ticks (TD-001 EPSS-Pull, kuenftig potentiell Backfill auf grosser
Findings-Tabelle) sprengen das.

**Warum:** Beobachtet 2026-05-21 — Worker im CrashLoop bis Probes
manuell auf `timeoutSeconds=60 periodSeconds=60 failureThreshold=5`
angehoben wurden.

**Loesung:** Probes sind heute (post-Quickfix) tolerant genug. Wenn
TD-002 oder TD-003 umgesetzt sind, koennen Probes wieder enger
eingestellt werden — der Healthcheck blockt dann nicht mehr.

Bis dahin: Probes-Settings im Helm-Chart / Deployment-Yaml
dokumentieren plus Hinweis warum die Werte hoch sind.

**Aufwand:** ~20 Min Doku.

**Wann:** Sobald TD-002 oder TD-003 erledigt — dann Probes
zurueckdrehen + Doku updaten.

---

## TD-007 — Pull-Worker komplett-blockierend statt async/Daemon

**Was:** `feed_enrichment_tick` ruft `pull_epss` und `pull_kev`
synchron im `_tick()`. Waehrend der ~10-30s (post-TD-001) ist der
Worker blockiert fuer Job-Pickup.

**Warum:** Heute funktional unkritisch (Pull dauert kurz, Job-Pickup
hat 2s Poll-Intervall, Verzug max 30s). Wenn aber TD-001 nicht
gefixt ist, blockt der Pull den Worker fuer Minuten.

**Loesung:** Mit TD-002 obsolet (procrastinate macht periodische Tasks
in eigenen Worker-Process-Pools). Standalone-Fix waere: Pull in
Daemon-Thread (analog `_heartbeat_loop`), aber das oeffnet ein Thread-
vs-Session-Bowel — Session ist nicht thread-safe, ein paralleler
Pull braucht eigene Engine-Connection-Pool-Konfiguration.

**Empfehlung:** Mit TD-002 erschlagen, nicht separat.

**Wann:** Mit TD-002.

---

## TD-008 — Auto-Update ohne End-to-End-Verifikation des Skript-Inhalts

**Was:** ``agent/secscan-agent.sh::auto_update_self`` laedt das neue Skript
ueber HTTPS, prueft Shebang + ``AGENT_VERSION="..."`` als Sanity-Marker,
sendet seit TICKET-001-Review optional einen ``Authorization: Bearer
$SECSCAN_API_KEY``-Header mit. Aber keine kryptografische Verifikation
des Skript-Inhalts.

**Warum:** Wenn ein Angreifer den DNS hijacken, eine eigene CA in
``/etc/ssl/certs`` einschleusen, oder direkt das Backend kompromittieren
kann, kann er ein malicious Skript ausliefern das beim naechsten Cron-
Run als root ausgefuehrt wird (Agent laeuft typischerweise als root weil
Trivy rootfs-Scan root braucht).

**Loesung:** Server liefert ``X-Content-SHA256``-Header im
``/agent/files/...``-Response. Agent berechnet ``sha256sum`` der
heruntergeladenen Datei und vergleicht. Bei Mismatch: Replace abbrechen,
``.bak`` bleibt unangetastet.

Optional zusaetzlich: Server signiert das Skript mit einem Build-Key
(``cosign`` o.ae.), Agent verifiziert Signatur. Hoeherer Aufwand
(Key-Management).

**Aufwand:** Hash-Verify ~30 Min (Server-Endpoint-Erweiterung + Agent-
Check + Test). Signatur-Verify ~1 Tag plus Key-Rotation-Konzept.

**Wann:** Bevor wir Multi-Tenant gehen oder ein Operator ein internet-
exponiertes Backend deployed.

---

## TD-009 — Auto-Update Race bei parallelen Cron-Runs

**Was:** Zwei Agent-Instanzen die gleichzeitig den Auto-Update-Pfad
durchlaufen koennen sich die ``.bak``-Recovery-Datei gegenseitig
ueberschreiben. Atomic-``mv`` garantiert dass das Skript selbst nicht
korrupt wird, aber das ``.bak`` enthaelt nach einer Race ggf. den
bereits-ersetzten Stand statt des Original-Skripts.

**Warum:** Cron-Intervalle <5 Min sind unueblich aber moeglich. Wenn das
Update das einzige Verteidigungsmittel gegen einen kaputten Agent-Stand
ist, sollte Recovery deterministisch funktionieren.

**Loesung:** ``flock`` um den Auto-Update-Block:
```bash
exec 200>"/var/run/secscan-agent-update.lock"
if ! flock -n 200; then
  log "Auto-Update: another instance is updating, skipping"
  return 0
fi
```

**Aufwand:** ~15 Min Code + Test.

**Wann:** Wenn ein Operator <5 Min Cron-Intervalle braucht oder ein
parallel-Update-Vorfall beobachtet wird.

---

## TD-010 — Tailwind via CDN-JIT, nicht via Vite-Build

**Was:** Die App laedt Tailwind v3 als Browser-JIT-Compiler ueber
`<script src="https://cdn.tailwindcss.com/3.4.16">` (`app/templates/base_app.html`
und `app/templates/base.html`). Das CDN-Skript scannt zur Browser-Runtime
den DOM, generiert CSS on-the-fly fuer gefundene Klassen und reagiert
ueber einen MutationObserver auf DOM-Aenderungen.

**Warum (Symptom):** Beobachtet 2026-05-21 nach Phase-Q-Merge: Klick vom
Dashboard auf einen Sidebar-Server-Link rendert `/servers/<id>` per HTMX-
Pane-Swap. Die KPI-Sparkline-SVGs (`_kpi_card.html`, viewBox 0 0 100 100,
`class="w-full h-full block"`) fielen auf intrinsische Default-Hoehe von
300 px statt 22 px — Layout komplett zerschossen, bis der Operator manuell
reloadete. Browser-DevTools bestaetigt: nach HTMX-Swap fehlt die CSS-Regel
`.h-full { height: 100%; }` komplett in den generierten Rules. `.w-full`
und `.block` sind da, weil sie schon im Dashboard-Initial-DOM vorkommen.

Ursache: der CDN-JIT-MutationObserver erfasst Klassen-Strings, die noch
nie im DOM auftauchten, nicht zuverlaessig. Klassen wie `h-full`, die nur
in HTMX-nachgeladenen Subtrees vorkommen (Server-Detail, Settings-Sub-
Pages), bekommen kein generiertes CSS. Tailwinds offizielle Doku sagt
das CDN-Skript ist "for development only, not for production".

**Mitigation aktuell (eingebaut Block-Q-Followup, 2026-05-21):**

1. *Schicht 3:* SVG-Container-Hoehe per Attribut statt CSS-Klasse:
   `<svg width="100%" height="22" class="block">` statt
   `class="w-full h-full block"`. Drei Chart-Templates angepasst
   (`_kpi_card.html`, `_stacked_bar_chart.html`, `_heartbeat_large.html`).
   SVG-Attribute sind layout-immun gegen jede CSS-Race.
2. *Schicht 2:* Inline-Safelist im `base_app.html` vor dem CDN-Script-Tag:
   `window.tailwind.config = { safelist: ["h-full", ...] }`. Garantiert
   dass die gelisteten Klassen schon beim initialen JIT-Bootstrap CSS
   bekommen, unabhaengig davon ob sie im Initial-DOM auftauchen.
3. *Lint-Test:* `tests/templates/test_tailwind_safelist.py` prueft per
   Unit-Test (kein DB/HTTP), dass alle als high-risk markierten Klassen
   (`h-full`, `h-screen`, `h-fit`, `min-h-full`, `min-h-screen`), die
   irgendwo in einem Template benutzt werden, in der Safelist stehen.
   Verhindert dass ein Frontend-Implementer das Problem unbemerkt
   reproduziert.

Die Mitigation funktioniert, aber sie ist Pflege-Last: jede neue high-
risk-Klasse muss in `_HIGH_RISK_CLASSES` und in die Safelist nachgezogen
werden. Bei arbitrary-value-Klassen (`h-[42px]`, `w-[180px]`) skaliert
das schlecht.

**Loesung:** Tailwind-CDN-Skript komplett austauschen gegen einen Vite-
Build-Step, der zur Image-Build-Zeit alle Templates scannt und ein
deterministisches CSS-Bundle erzeugt. Damit faellt der Browser-Runtime-
JIT weg, alle Klassen werden Build-Zeit-deterministisch erkannt, der
MutationObserver-Race ist obsolet.

Stack-Implikation: Vite braucht Node/npm im Build-Stage. ADR-001 hat
das im MVP-Scope verboten. Mit dieser Migration faellt diese Vorgabe —
also separate ADR oder Update von ADR-001 als Vorbedingung. Eine ADR-
konforme Zwischen-Variante waere das Tailwind-Standalone-Binary (~30 MB
Linux-Binary, kein Node), das den Build ohne npm macht — dafuer fehlt
aber das Vite-Eco-System (Asset-Versioning, Source-Maps, DaisyUI-Plugin-
Integration), das mittelfristig ohnehin gewuenscht ist.

Vite-Build-Skizze:

- `frontend/package.json` mit `tailwindcss`, `daisyui`, `@tailwindcss/forms`,
  `@tailwindcss/typography`, `vite`.
- `frontend/tailwind.config.js` mit `content: ["../app/templates/**/*.html",
  "../app/static/js/**/*.js"]` — Tailwind scannt alle Jinja-Templates
  Build-Zeit.
- Multi-Stage-Dockerfile: Stage 1 (Node) `npm ci && npm run build` →
  generiert `app/static/css/app.css`. Stage 2 (Python) kopiert nur das
  fertige CSS, hat keine Node-Abhaengigkeit zur Runtime.
- `base_app.html` / `base.html` ersetzen den CDN-Script-Tag durch
  `<link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">`.
- Safelist + Lint-Test obsolet, koennen geloescht werden.

**Aufwand:** ~3-4 Std fuer den ersten Build-Setup (Vite-Config, Tailwind-
Config-Migration der CDN-Optionen `?plugins=forms,typography`, Multi-
Stage-Dockerfile, CI-Anpassung). Plus eine ADR zum ADR-001-Update bzw.
neuer ADR die Vite-Build-Pipeline begruenden.

**Wann:** Sobald die naechste high-risk-Klasse das Symptom reproduziert
oder die Safelist >5 Eintraege hat (= Skalierungs-Grenze der Mitigation
erreicht). Spaetestens bei v1.0 vor Production-Release — CDN-JIT in
Produktion ist offiziell nicht supported und kann jederzeit von Tailwind
deprecated werden.

**Update 2026-05-23 (Block W geplant):** [ADR-0032](decisions/0032-frontend-build-plain-css.md)
fuehrt esbuild-Build-Stage ein. Block W Phase 1 baut die neuen Surfaces
(Login, Dashboard, App-Shell) als Plain-CSS — Tailwind-CDN bleibt fuer
Legacy-Templates (Settings, Server-Detail, Findings, Audit, Setup) im
Dual-Stack-Modus aktiv. Die Safelist + der Lint-Test bleiben in Phase 1
unangetastet, weil die Legacy-Templates Tailwind weiter brauchen. Eine
spaetere Phase 2 (separater Block, vermutlich nach Server-Detail-Redesign)
loescht Tailwind/DaisyUI komplett und erledigt damit TD-010 final. Bis
dahin bleibt der Mitigations-Code in `base_app.html` Z. 52-73 stehen.

**ERLEDIGT 2026-05-23 (Block W Addendum):** Phase 2 vorgezogen.
Tailwind-CDN + DaisyUI-CDN + Alpine-CDN + HTMX-CDN sind komplett aus
base.html + base_app.html entfernt. `window.tailwind.config`-Safelist-
Script weg. `frontend/src/css/components/legacy-shim.css` (~450 Zeilen)
liefert Minimal-Styles fuer die noch nicht redesignten Templates damit
sie benutzbar bleiben. Alpine + HTMX kommen jetzt ausschliesslich aus
`vendor.js`-Bundle. `tests/templates/test_tailwind_safelist.py` ist als
deprecated markiert (pytest.skip), zu loeschen beim naechsten Repo-
Cleanup. TD-010 ist damit final geschlossen. Siehe ADR-0032 Addendum
2026-05-23 und docs/blocks/W-redesign-phase-1.md Addendum.

---

## TD-011 — Default-Coverage-Luecke fuer register/keys_rotate/bulk_acknowledge nach Phase-3.2-Bulk-Migration

**Was:** Im Zuge von TICKET-004 Phase 3.2 wandern alle 9 API-Test-Files
(`tests/api/test_*.py`) als Bulk-Migration nach
`tests/integration/test_*_db.py`. Damit verschwinden sie aus dem
Default-`pytest`-Lauf. Fuer fuenf Endpoints ist das harmlos, weil die
Geschaeftslogik in Service-Modulen liegt die separat unit-getestet sind
(`findings_ingest`, `host_state_ingest`, `risk_engine`, `llm_client`,
`llm_sanitize`, `llm_prompts`). Fuer drei Endpoints fehlt dieser
Service-Layer **komplett** — die Route-Handler SIND die Geschaeftslogik:

- `POST /api/register` (`app/api/register.py`, 138 LOC, kein Service-Modul)
- `POST /api/keys/rotate` (`app/api/keys.py`, 142 LOC, kein Service-Modul)
- `POST /api/findings/acknowledge` (`app/api/bulk.py`, 357 LOC, nur zwei
  kleine Pure-Helper `_build_match_query`/`_build_ids_query`)

Plus eine partielle Luecke fuer `POST /api/llm/chat` (Chat-Orchestrierung,
SSE-Streaming, Konversations-Lifecycle — die LLM-Calls selbst sind ueber
`llm_client`/`llm_sanitize`/`llm_prompts` abgedeckt).

**Warum (Symptom):** Nach dem Slice-8-Commit ist der Default-`pytest`-Lauf
fuer diese Endpoints **0 % abgedeckt**. Body-Validation, Rate-Limit-
Keying, Audit-Event-Logik, Master-Key-Pruefung, Bulk-Match-Query-Bau
laufen nur noch im `pytest -m db_integration`-Lauf. Regressions an einer
dieser Routes wuerden im Default-Lauf nicht mehr auffallen.

**Loesung:** Pro Endpoint kleine Service-Layer-Extraktion plus dazu-
gehoerige Pure-Unit-Tests:

- `register.py`: `validate_register_request(payload) -> RegisterRequest`
  als pure Funktion mit Pydantic-Schema; `_register_rate_limit()`
  pure-testbar. Plus eine `_register_server(sess, request) -> Server`-
  Service-Funktion, die der Route-Handler aufruft.
- `keys.py`: analog `validate_rotate_request` + `_rotate_key(sess, server)`.
- `bulk.py`: `_build_match_query` und `_build_ids_query` mit Fake-Filter-
  Objekten unit-testen; `validate_bulk_ack_request` als Pydantic-Pure-
  Layer.
- `llm_chat.py`: `_sse_payload`, `_collect_history`, `_json_error` als
  Pure-Helper-Tests.

Test-Erwartung: ~30-50 neue Pure-Unit-Tests in `tests/services/` oder
`tests/api/unit/`.

**Aufwand:** ~4-6 Stunden Refactor + Tests. Etwas weniger als TD-005-HIGH
weil hier nur die drei kritischen Endpoints + Pure-Helper-Layer von
llm_chat angefasst werden, nicht die kompletten View-Tests.

**Wann:** Vor Phase-3.2-Abschluss in TICKET-004 NICHT erzwungen — Phase
3.2 schliesst bewusst mit dieser dokumentierten Luecke ab. Folge-Aufgabe
sobald jemand ohnehin an register/keys_rotate/bulk_acknowledge-Route
arbeitet, ODER vor v1.0-Release.

Hinweis: Verwandt mit TD-005 (das ist die Test-Migration-Schiene fuer
Files die schon einen Service-Layer haben — TD-011 ist die Schiene fuer
Files OHNE Service-Layer und braucht erst die Extraktion).

---

## TD-012 — View-Route-Handler enthalten noch inline Geschaeftslogik / SQL-Queries

**Was:** Mehrere Route-Handler unter `app/views/` haben Geschaeftslogik
direkt im Funktions-Body, statt sie konsequent in Modul-private Helper
zu schieben. Sichtbar an drei Stellen:

- `app/views/server_detail.py::show()` (Z. 415-501, 90 LOC): die meisten
  Aggregations-Calls sind sauber extrahiert (`_render_findings_section`,
  `_build_action_sections`, `compute_tendency`, `severity_snapshots_for_server`,
  `_load_action_required_counts`, `_load_host_snapshot`, `_quick_counts_for_server`).
  ABER zwei inline `select(Finding)`-Queries fuer `noise_findings`/
  `noise_total` (Z. 451-474) haengen im Route-Body. Plus 18 Keyword-Args
  an `render_template(...)` (Z. 480-501), die als zusammenhaengendes
  Context-Dict klarer waeren.
- `app/views/findings.py::index()` (Z. 144 ff., ~74 LOC): Mischung aus
  Helper-Aufrufen und inline-Logik (`_filter_is_active`, `_explicit_sort`,
  `_count_open_findings`, `_count_active_servers` sind extrahiert, aber
  der Render-Pfad muss noch im Detail geprueft werden).
- Weitere Kandidaten (nicht inspiziert): `app/views/audit_view.py`
  (295 LOC), `app/views/settings.py` (684 LOC), `app/views/llm_settings.py`
  (279 LOC). Vermutlich aehnlicher Mix.

Positiv-Beispiel als Vorlage: `app/views/dashboard.py::index()` (21 LOC)
delegiert komplett an `_load_risk_kpi_counters`, `_build_pane_context`,
`_load_servers`, `_load_open_aggregates`, `_apply_filters`,
`_card_tag_names`. Saubere Trennung Route-Handler vs.
Daten-/Context-Aufbau.

**Warum (Symptome):** Die Schuld ist unabhaengig vom Test-Refactor
schaedlich:

1. *Regression-Risiko beim Anfassen:* inline SQL- oder
   Aggregations-Logik im Route-Body ist beim Refactor leicht uebersehen.
   Block-Q hat z.B. `compute_diff` aus einem solchen Inline-Block
   entfernt — wenn die Logik in einem benannten Helper gewesen waere,
   waere das eine Loeschung der Helper-Funktion gewesen, statt mehrerer
   versteckter Branch-Removals im Route-Body.
2. *Lesbarkeit:* "Lies das ganze 90-LOC-`show()` um zu verstehen was
   gerendert wird" vs. "Lies acht Helper-Namen + ein `render_template`-
   Context-Dict".
3. *Stille Drift zwischen Route und Template:* 18 einzelne
   Keyword-Args an `render_template` werden bei Template-Aenderungen
   leicht inkonsistent gepflegt (ein neuer Template-Block braucht einen
   neuen Arg, aber der Route-Code merkt das nicht — Template rendert
   stillschweigend leer).

Diese Schuld ist **Voraussetzung fuer TD-005-HIGH** (View-Test-Migration
zu Pure-Units), weil ohne saubere Context-Builder die Tests nicht
DB-frei werden koennen. Aber sie hat auch ohne Test-Refactor Wert —
deshalb eigenstaendig dokumentiert.

**Loesung:** Pro View-Modul ein kleines Refactor in zwei Schritten:

1. **Inline-Logik in Modul-private Helper extrahieren.** Beispiel
   `server_detail.show()`: `_load_noise_findings(sess, server_id) ->
   tuple[list[Finding], int]` erzeugt das `(noise_findings, noise_total)`-
   Tupel, Route ruft nur diesen Helper.
2. **Context-Dict-Pattern.** Statt `render_template("x.html", a=…, b=…, c=…)`
   mit 18 Args → `context = _build_show_context(server, sess); return
   render_template("x.html", **context)`. Der `_build_show_context`-Helper
   ist dann pure-testbar mit einem Fake-Session-Argument.

Beide Schritte sind Refactor ohne Verhalten-Aenderung — `render_template`
sieht weiterhin denselben Context, nur die Code-Struktur ist explizit.

**Aufwand:** ~1-2 Stunden pro View-Modul. Sieben Module total (`dashboard`
ist sauber, `auth` ist klein, `agent_install`, `setup`, `_settings_shell`
sind klein) — realistisch ~8-10 Stunden fuer die fuenf groesseren Files
(`server_detail`, `findings`, `audit_view`, `settings`, `llm_settings`).

**Wann:** Inkrementell wenn ein View-Modul ohnehin angefasst wird (z.B.
neue Sektion einbauen, ADR-Spec-Aenderung). Nicht eigenstaendig
priorisieren, ausser TD-005-HIGH (Test-Migration) wird aktiv angegangen
— dann ist TD-012 die noetige Vorarbeit pro Modul.

Querverweis: TD-005 (Test-Migrations-Schuld die TD-012 als Vorarbeit
braucht), TD-011 (analoges API-Coverage-Problem mit Bulk-Migration als
Kurzschluss).

---

## TD-013 — Materialized `daily_risk_state`-Tabelle

**Was:** Heute aggregiert `app/services/heartbeat_aggregation.py` die Tages-
Aggregate fuer die Sidebar-Heartbeat-Bar **live** bei jedem Polling-Tick
(eine schmale Projektion-Query auf `findings` + Python-Loop ueber 30 Tage
pro Server). Mit der Block-W-Erweiterung kommt ein weiteres Aggregat-Feld
(`dominant_risk_band`) parallel zur Severity-Reduktion. Performance heute
unkritisch bei kleinen-bis-mittleren Flotten (50–200 Server).

**Warum (Symptom):** Bei sehr grossen Flotten (500+ Server, 100k+ Findings)
koennte die Live-Aggregation pro Polling-Tick im Sidebar-Batch-Endpoint
(`POST /_partials/sidebar/batch`) das Server-Zeit-Budget reissen
(>500 ms pro Tick). Heute kein konkretes Operator-Symptom, sondern
prophylaktisch dokumentiert weil die Skalierungs-Eigenschaft bekannt ist
(`heartbeat_aggregation.py` Datei-Header: "MVP-Zielwert 50 Server x 50
Tage = 2500 Cells in einer Batch-Query unter 200 ms").

**Loesung:** Neue Tabelle `daily_risk_state` (server_id, day,
dominant_risk_band, max_severity, kev_count, had_scan). Befuellt
inkrementell:

a) **Worker-Sub-Tick** (analog zum heutigen `feed_enrichment_tick`-Pattern
   in `app/workers/llm_worker.py`): einmal pro 5 Minuten alle Tages-
   Aggregate fuer den aktuellen Tag refresh'en, plus an Tagesgrenzen die
   Vortags-Zeile finalisieren. Aggregations-Query laeuft im Worker-Process,
   schreibt UPSERT auf `(server_id, day)`-PK.
b) **Backfill-Migration**: einmaliger Backfill der letzten 50 Tage fuer
   alle existierenden Server beim ersten Deploy.
c) **Sidebar-Endpoint liest direkt** die Tabelle (`SELECT … FROM
   daily_risk_state WHERE server_id IN (…) AND day >= now()::date - 29`)
   statt die Live-Aggregation aufzurufen. O(1) pro Sidebar-Render statt
   O(N × F) wo F = Findings pro Server.

Schema-Skizze:
```sql
CREATE TABLE daily_risk_state (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    dominant_risk_band TEXT,
    max_severity TEXT,
    kev_count INTEGER NOT NULL DEFAULT 0,
    had_scan BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (server_id, day)
);
CREATE INDEX ix_daily_risk_state_day ON daily_risk_state(day);
```

**Aufwand:** ~1-2 Tage. Migration + Backfill-Skript + Worker-Sub-Tick
+ Tests + Operator-Smoke. Plus ADR weil das eine neue Schema-Schicht
zwischen `findings` und der Sidebar einfuehrt.

**Wann:** Sobald Live-Aggregation in einer Operator-Umgebung die Polling-
Latency ueber ein akzeptables Budget (~500 ms Server-Zeit pro Batch)
drueckt. Heute kein konkreter Trigger — wird beim ersten 500+-Server-
Deployment relevant. Vermutlich frueher relevant als TD-001 (EPSS-Pull-
Hotspot) weil Sidebar-Polling viel haeufiger laeuft als EPSS-Pull.

Querverweis: [ADR-0035](decisions/0035-daily-risk-state-heartbeat-mapping.md)
§Verworfen — die materialized-Variante wurde fuer Block W zugunsten der
Live-Aggregation verworfen, dieser TD-Eintrag haelt sie als Folge-Option
fest.

---

## TD-014 — Sidebar-Polling-Endpoints ohne expliziten Rate-Limit

**Was:** Beide Sidebar-Polling-Endpoints (`GET /_partials/sidebar`,
`POST /_partials/sidebar/batch`) haben keinen `@limiter.limit(...)`-
Decorator. `flask-limiter` ist initialisiert (siehe `app/__init__.py`),
aber ohne `default_limits`-Konfiguration greift es nur, wenn Endpoints
explizit gelimitet werden.

**Warum:** Single-User-MVP plus `@login_required` mildert den Impact —
es gibt keinen offen erreichbaren Endpoint. Aber ein kompromittierter
Session-Cookie oder ein bug-getriebenes Client-Polling im Loop kann den
Endpoint frei spammen und unnoetige DB-Roundtrips verursachen
(`heartbeats_for_servers` + `escalate_act_counts_by_server` +
`group_counts` pro Batch). Bei N=200 sichtbaren Servern und 60-s-
Polling-Cadence ist die normale Last <2 RPS — ein Bug mit setInterval(0)
wuerde das auf 100+ RPS hochziehen.

**Loesung:** `@limiter.limit("120/minute")` auf beide Endpoints in
`app/views/_sidebar_context.py`. Die `120/min`-Schranke gibt ~2 RPS
Headroom (Default-Polling ist 1 Batch pro 60 s, plus Scroll-Trigger).
Test in `tests/views/test_sidebar_batch.py` ergaenzen der bei 121 POSTs
einen 429 erwartet.

**Aufwand:** ~30 Min. Decorator-Add + ein Pure-Unit-Test mit
`@override_settings(RATELIMIT_ENABLED=True)` (oder via
`flask-limiter`-Test-Hook).

**Wann:** Im naechsten Block-Uebergang (W+1 oder Folge-PR). Kein
akuter Blocker. security-auditor hat das in Phase C als GELB-1
gemeldet — kein Phase-C-Block weil konsistent mit dem GET-Pendant.

Querverweis: Block W Phase C Security-Audit.

---

## TD-015 — Orphaned `_render_tag_editor`-Helper nach Block X / Phase B6

**Was:** `app/views/server_detail.py` enthaelt einen `_render_tag_editor`-
Helper-Funktion. Nach Block X / Phase B6 ist der Tag-Editor-Akkordeon aus
`detail.html` entfernt und `_tag_editor.html` wird ausschliesslich von
`servers/settings.html` included. Der Helper in `server_detail.py` hat
keinen Aufrufer mehr.

**Warum:** Der backend-implementer hat den Helper bewusst stehen gelassen
("Cleanup nach B6") um einen sauberen Split-Commit zu gewaehrleisten.

**Loesung:** `_render_tag_editor` aus `app/views/server_detail.py` entfernen
sobald `_tag_editor.html` und das Settings-Sub-View stabil sind (d.h. nach
erfolgreichem Block-X-Abschluss + Review). Keine Auswirkung auf Laufzeit,
da der Helper nie aufgerufen wird.

**Aufwand:** < 5 Min. (Funktion loeschen + ggf. zugehoerige `add_tag`/
`remove_tag`-Routen aus `server_detail.py` pruefen ob ebenfalls orphaned).

**Wann:** Cleanup-PR nach Block X / v0.13.0-Merge auf main. Kein Blocker.

Querverweis: Block X Phase B6, ADR-0038 §(2).

---

## Konventionen fuer neue Eintraege

- ID: `TD-NNN`, fortlaufend.
- Felder: Was / Warum / Loesung / Aufwand / Wann.
- Bezuege auf konkrete Datei + Zeile wenn aufgreifbar.
- Bei Auswahl-Entscheidungen (z.B. Framework-Migration): kurze
  Vergleichstabelle mit Empfehlung.
- Wenn ein TD durch einen anderen obsolet wird, kreuzweise verlinken.
