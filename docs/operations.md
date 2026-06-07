# Operations-Notizen

Kurze Pointer fuer Operator-Setup. Detailliertere Architektur-Entscheidungen in `docs/decisions/`.

## Outbound-Network-Anforderungen

Der Server braucht HTTPS-Zugriff auf folgende externe Endpunkte:

| Endpunkt | Zweck | Block | Frequenz |
|---|---|---|---|
| `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | EPSS-Scores-Feed (FIRST.org) | Q (ADR-0024) | alle 24h |
| `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` | KEV-Katalog (CISA-GitHub-Mirror) | Q (ADR-0024) | alle 24h |
| LLM-Provider-Endpunkt (vom Operator gewaehlt) | Pass-1/Pass-2-LLM-Calls | G/P | pro Scan |
| `https://github.com/aquasecurity/trivy/releases/...` | Trivy-Binary-Download (Agent) | N (ADR-0021) | einmalig pro Agent-Install |

## Air-Gap-Setup

Wenn der Server keinen Outbound-Zugriff hat:

- **`FM_FEED_PULL_DISABLED=true`** schaltet die EPSS/KEV-Pulls ab.
  Findings werden ohne EPSS/KEV ingestet; der Pass-2-LLM-Prompt sagt
  explizit "treat ``epss=n/a`` as unknown — do NOT escalate solely
  because EPSS is missing", funktioniert also auch ohne Feed-Daten.
- LLM-Provider muss intern erreichbar sein (z.B. eigener Ollama).
- Trivy-Binary muss vorab im Agent-Image bzw. Host verfuegbar sein.

## Agent-Updates

Ab Agent `0.3.1` aktualisiert sich `fathometer-agent.sh` vor jedem Scan selbst,
wenn `/agent/version` eine neuere `current_agent_version` meldet. Das Skript
laedt die neue Version ueber `/agent/files/fathometer-agent.sh`, legt
`fathometer-agent.sh.bak` als Operator-Recovery an und re-exec't sich einmalig.
Falls `lib_host_state.sh` vorhanden ist, wird sie best-effort mit aktualisiert;
Versions-Mismatch fuehrt nur dazu, dass `host_state` ausgelassen wird.

Bestehende Agents kleiner `0.3.1` haben den Auto-Update-Code noch nicht. Diese
Hosts muessen einmalig manuell auf `0.3.1` aktualisiert werden; danach sind
Folgeversionen self-updating. Alte Agents bleiben serverseitig erlaubt
(`MIN_AGENT_VERSION=0.1.0`), koennen aber weiterhin leere
`trivy_db_*`-Spalten liefern, bis sie aktualisiert sind.

**Recovery via `.bak`-Files:** wenn ein Auto-Update funktional kaputtgeht,
liegt der vorherige Skript-Stand unter `fathometer-agent.sh.bak` bzw.
`lib_host_state.sh.bak`. Rollback: `mv fathometer-agent.sh.bak fathometer-agent.sh`.

**Race-Limitation:** bei sehr kurzen Cron-Intervallen (<5 Min) koennen zwei
parallel laufende Agent-Instanzen sich beim Auto-Update gegenseitig die
`.bak`-Datei ueberschreiben — Recovery-File enthaelt dann ggf. den bereits
ersetzten Stand statt des urspruenglichen. Empfehlung: Cron-Intervalle
&ge;5 Min halten. Echter Fix via `flock` ist als TechDebt vorgemerkt.

## Group-Risk-Backfill

Nach dem Deploy des Group-Risk-Inheritance-Fixes einmalig ausfuehren:

```bash
python -m app.cli.inherit_group_risk_backfill
```

Der Befehl ist idempotent. Er kopiert finale ``ApplicationGroup.risk_band``-
Verdicts auf alle zugeordneten Findings, damit bestehende UI-Counter und
Filter ohne Re-Scan konsistent sind.

## Gruppen & Tags — Lifecycle (Block Z, ADR-0040)

Gruppen und Tags entstehen seit Block Z **inline im Server-Detail-Settings**
(`/servers/<id>/settings/`): Name eintippen, „+ Anlegen" — die Gruppe/der Tag
wird in einem Flow angelegt und dem aktuellen Server zugewiesen. Ein
`psql`-Workaround zum Anlegen von Gruppen ist nicht mehr nötig.

`/settings/groups` und `/settings/tags` sind reine **Verwaltungs-Surfaces**:
Rename, Delete, Color-Edit (Tags), Position-Reorder via Up/Down (Gruppen). Es
gibt dort **kein** Anlege-Formular mehr.

Leere Gruppen werden **nicht** automatisch gelöscht (bewusst, ADR-0040). Sie
bleiben in `/settings/groups` mit `member_count = 0` sichtbar und sind dort
löschbar, werden aber aus der Sidebar weggeblendet (die Aggregation
`sidebar_group_aggregates.group_counts()` liefert nur Gruppen mit ≥1 Server).
Delete einer Gruppe setzt `server.group_id = NULL` für alle Member
(ON-DELETE-SET-NULL, ADR-0034) — kein Server wird gelöscht.

## Block-Q-Feed-Pull (ADR-0024)

### Health-Checks

- **UI**: ``/settings/llm`` zeigt am unteren Ende einen zweizeiligen
  Block mit dem letzten erfolgreichen Pull pro Feed plus Row-Count.
  Rot bei stale (>7 Tage) oder failed letztem Versuch.
- **SQL**:
  ```sql
  SELECT feed_name, MAX(completed_at) AS last_success
  FROM feed_pull_log
  WHERE status = 'success'
  GROUP BY feed_name;
  ```
- **Logs**: ``feed.epss_pulled``/``feed.kev_pulled`` (structlog
  ``info``) am Ende eines erfolgreichen Pulls,
  ``feed.epss_pull_failed``/``feed.kev_pull_failed`` (``exception``)
  bei Fehler.
- **Audit**: ``audit_events`` mit ``action='feed.<name>_pulled'`` und
  ``event_metadata`` (row_count, bytes, duration).

### Tuning

Default-Settings sind fuer Single-Host-Setups dimensioniert; alle
ueber ``FM_FEED_*``-Env-Vars ueberschreibbar:

| Env-Var | Default | Bedeutung |
|---|---|---|
| `FM_FEED_PULL_DISABLED` | `false` | Master-Switch |
| `FM_FEED_EPSS_URL` | empirsec-CSV | EPSS-Quelle |
| `FM_FEED_KEV_URL` | CISA-JSON | KEV-Quelle |
| `FM_FEED_PULL_INTERVAL_HOURS` | `24` | Pull-Frequenz |
| `FM_FEED_JITTER_MAX_MIN` | `30` | Symmetric-Jitter um den Interval |
| `FM_FEED_MAX_DECOMPRESSED_MB_EPSS` | `50` | Gzip-Bomb-Cap fuer EPSS |
| `FM_FEED_MAX_BYTES_KEV_MB` | `10` | Body-Cap fuer KEV-JSON |

### Initial-Bootstrap

Nach dem ersten Deploy von Block Q:

1. Worker laeuft an, sieht leeres ``feed_pull_log``, triggert sofort
   einen EPSS- und KEV-Pull (max +30min Jitter).
2. Pulls dauern ~10-30s je nach Netzwerk + Postgres-Bulk-UPSERT-
   Performance.
3. ``backfill_epss`` / ``backfill_kev`` reichert bestehende Findings
   in einem ``UPDATE ... FROM`` an (idempotent, IS DISTINCT FROM-
   gefiltert).
4. Naechster Agent-Scan-Push wird via Phase-2-Ingest-Lookup
   automatisch angereichert; Backfill bleibt fuer historische Findings
   die nicht mehr re-gescannt werden.

### Failure-Modes

- **HTTP-Failure** (5xx, Connection-Refused, Timeout): wird als
  ``feed_pull_log.status='failed'`` mit Error-String persistiert.
  Bestehende Daten bleiben unveraendert (kein TRUNCATE). Naechster
  Tick versucht erneut.
- **Gzip-Bomb / Validation-Ratio-Abort**: hardgecappt, abort mit
  ValueError, Pull als ``failed`` markiert.
- **CISA-Schema-Drift**: Pydantic-Modelle haben ``extra="ignore"``,
  unbekannte Felder im JSON werden geschluckt. Hartes Schema-Break
  (z.B. ``cveID`` umbenannt) wuerde den Pull als ``failed`` markieren.

## Block-R-Async-Ingest (ADR-0026)

### Operator-Sicht

`POST /api/scans` antwortet seit v0.11.0 binnen <1s mit 202 + Job-ID.
Die volle Verarbeitung (Findings-UPSERT, Host-State-Persist, Pre-Triage,
Group-Matching, LLM-Job-Queueing) laeuft im `fathometer-llm-worker`-Container
als Sub-Tick `scan_ingest_tick` (vor LLM-Pickup priorisiert).

### Async-only seit v0.12.0

Das urspruengliche Feature-Flag `FM_SCAN_INGEST_ASYNC` (Cutover-Schutz
aus Block R Phase H) ist mit v0.12.0 ersatzlos entfernt — Async ist der
einzige Pfad. Voraussetzung im Deployment: der `fathometer-llm-worker`-Container
muss laufen, sonst stehen die `scan_ingest_jobs`-Rows fuer immer queued.
Der Operator-Login + Setup-Wizard bleibt unabhaengig vom Worker erreichbar
(Web-Container und Worker sind getrennt).

Der Agent beendet nach der 202-Annahme sofort (Fire-and-Forget, ADR-0042) —
er pollt **nicht** auf einen Job-Status-Endpoint (dieser ist entfernt). Den
Verarbeitungs-Fortschritt und -Ausgang (inkl. `failed`) sieht der Operator
serverseitig: in der `scan_ingest_jobs`-Tabelle (Queue-Inspect-SQL unten),
im Dashboard (HTMX-Polling, ADR-0019) und über die Audit-Events
`scan.queued` / `scan.ingested` / `scan.ingest_failed`.

### Queue-Inspect

| Frage | SQL |
|---|---|
| Wie tief ist die Queue? | `SELECT status, COUNT(*) FROM scan_ingest_jobs GROUP BY status` |
| Welche Jobs haengen? | `SELECT id, server_id, attempts, picked_up_at FROM scan_ingest_jobs WHERE status='in_progress' AND picked_up_at < now() - interval '5 min'` |
| Manuelle Requeue eines stale Jobs | `UPDATE scan_ingest_jobs SET status='queued', picked_up_by=NULL, picked_up_at=NULL WHERE id=?` |
| Failed-Jobs der letzten 24h | `SELECT id, server_id, error FROM scan_ingest_jobs WHERE status='failed' AND finished_at > now() - interval '24 hours'` |

### Retention-Verhalten

| Status | `payload_gzip` | Zeile |
|---|---|---|
| `queued`/`in_progress` | Original gzipped Body | bleibt bis Pickup-/Stale-Reaper |
| `done` | NULL (atomar im Status-Wechsel-UPDATE) | bleibt unbegrenzt (Counts in `result` JSONB) |
| `failed` | Original Body (24h-Debugging-Fenster) | DELETE per Retention-Sweep nach 24h |

Retention-Sweep laeuft stuendlich im Worker (`SCAN_INGEST_RETENTION_INTERVAL_SEC=3600`).
Done-Crash-Reste (`payload_gzip` nicht-NULL trotz `status='done'` aus
einem hypothetischen Mid-Statement-Crash) werden binnen <2h auf NULL gesetzt.

### Soft-Cap

| Env-Var | Default | Wirkung |
|---|---|---|
| `FM_MAX_QUEUED_INGEST_JOBS` | `50` | Per-Server-Limit auf `(queued|in_progress)`-Jobs. `429 queue_full` beim Insert wenn ueberschritten. |

Wenn ein Server wiederholt 429s sieht: Stale-Reaper-Lauf abwarten (5min)
oder manuelle Queue-Bereinigung via SQL oben. Im Steady-State sollte die
Queue-Tiefe pro Server bei <5 liegen — alles darueber deutet auf einen
Worker-Backlog hin (siehe Multi-Worker-Re-Open-Trigger in ADR-0026).

### Worker-Logs

Phasen-Marker im `fathometer-llm-worker`-Container:
- `scan_ingest.job_picked_up` — `{job_id, server_id, attempts}` beim Pickup
- `scan_ingest.job_done` — `{job_id, scan_id, duration_ms, counts}` bei Erfolg
- `scan_ingest.job_failed` — `{job_id, error_class, attempts}` bei finalem Fail
- `scan_ingest.retention_sweep_done` — `{cleared_payloads, deleted_failed}` stuendlich
- `scan_ingest.stale_reaped` — `{requeued, failed}` bei Stale-Reaper-Pass

## Block-T-Application-Group-Evaluations (ADR-0028)

### Operator-Sicht

`application_groups` traegt seit Block T keine Eval-Spalten mehr — die
sieben server-abhaengigen Felder (`risk_band`, `risk_band_reason`,
`risk_band_source`, `risk_band_computed_at`, `worst_finding_id`,
`group_findings_fingerprint`, `action_type`) leben in der neuen
Junction-Tabelle `application_group_evaluations` mit Composite-PK
`(group_id, server_id)`. Pass-2 schreibt per UPSERT, Findings erben
ihren Band aus der fuer ihren Server zustaendigen Junction-Row — der
Cross-Server-Leak aus ADR-0023 ist behoben.

### Erwartete UI-Luecke nach Deploy

**Nach dem Cutover:** Migration `0011_app_group_evals` legt die
Junction-Tabelle **leer** an und droppt die alten Eval-Spalten auf
`application_groups`. Bestehende Bewertungen werden **nicht** migriert
(ADR-0028 §Migration — Drop & Rebuild begruendet).

Konsequenz: auf jeder Server-Detail-Seite zeigen alle Application-Group-
Cards die **„Nicht bewertet"-Pille** mit Spinner, bis der jeweilige
Server seinen naechsten regulaeren Scan abliefert. Der Block-P-Hook im
Worker-Pfad (`app/services/scan_processing.py`) prueft pro Scan ob eine
Junction-Row fuer `(group, server)` existiert und triggert Pass-2 wenn
nicht — der Re-Build der Junction passiert also organisch ueber das
natuerliche Scan-Intervall des Agents (typisch 24h, oft 1-6h).

Cache-Hit-Rate aus `llm_risk_cache` macht den Re-Eval-Lauf nahezu
kostenlos: die _Bewertung_ pro `(group, group_findings_fp, cve_data_fp,
server_context_fp)` ist schon im Cache. Pass-2 muss nur die Junction-Row
schreiben — kein LLM-Token-Verbrauch (~95% Cache-Hits erwartet).

### Manueller Re-Eval (optional)

Operator kann pro Server einen Force-Scan triggern statt zu warten:

```bash
# Direkt am Agent-Host:
fathometer-agent  # Cron-Script, sofort ausfuehren

# Oder Backend-seitig fuer einen einzelnen Server-Key:
curl -X POST https://<fathometer>/api/scans \
  -H "Authorization: Bearer <SERVER_KEY>" \
  -H "Content-Encoding: gzip" \
  -H "Content-Type: application/json" \
  --data-binary @scan.json.gz
```

### Junction-Inspect (SQL)

| Frage | SQL |
|---|---|
| Wie viele Bewertungen liegen vor? | `SELECT count(*) FROM application_group_evaluations` |
| Welche Server haben noch keine Bewertung? | `SELECT s.id, s.name FROM servers s LEFT JOIN application_group_evaluations e ON e.server_id = s.id WHERE e.group_id IS NULL` |
| Bewertungs-Verteilung pro Server | `SELECT server_id, risk_band, count(*) FROM application_group_evaluations GROUP BY server_id, risk_band ORDER BY server_id` |
| Stale-Bewertungen (>30 Tage) | `SELECT group_id, server_id, risk_band_computed_at FROM application_group_evaluations WHERE risk_band_computed_at < now() - interval '30 days'` |
