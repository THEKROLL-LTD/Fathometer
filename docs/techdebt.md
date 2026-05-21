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

## Konventionen fuer neue Eintraege

- ID: `TD-NNN`, fortlaufend.
- Felder: Was / Warum / Loesung / Aufwand / Wann.
- Bezuege auf konkrete Datei + Zeile wenn aufgreifbar.
- Bei Auswahl-Entscheidungen (z.B. Framework-Migration): kurze
  Vergleichstabelle mit Empfehlung.
- Wenn ein TD durch einen anderen obsolet wird, kreuzweise verlinken.
