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

- **`SECSCAN_FEED_PULL_DISABLED=true`** schaltet die EPSS/KEV-Pulls ab.
  Findings werden ohne EPSS/KEV ingestet; der Pass-2-LLM-Prompt sagt
  explizit "treat ``epss=n/a`` as unknown — do NOT escalate solely
  because EPSS is missing", funktioniert also auch ohne Feed-Daten.
- LLM-Provider muss intern erreichbar sein (z.B. eigener Ollama).
- Trivy-Binary muss vorab im Agent-Image bzw. Host verfuegbar sein.

## Agent-Updates

Ab Agent `0.3.1` aktualisiert sich `secscan-agent.sh` vor jedem Scan selbst,
wenn `/agent/version` eine neuere `current_agent_version` meldet. Das Skript
laedt die neue Version ueber `/agent/files/secscan-agent.sh`, legt
`secscan-agent.sh.bak` als Operator-Recovery an und re-exec't sich einmalig.
Falls `lib_host_state.sh` vorhanden ist, wird sie best-effort mit aktualisiert;
Versions-Mismatch fuehrt nur dazu, dass `host_state` ausgelassen wird.

Bestehende Agents kleiner `0.3.1` haben den Auto-Update-Code noch nicht. Diese
Hosts muessen einmalig manuell auf `0.3.1` aktualisiert werden; danach sind
Folgeversionen self-updating. Alte Agents bleiben serverseitig erlaubt
(`MIN_AGENT_VERSION=0.1.0`), koennen aber weiterhin leere
`trivy_db_*`-Spalten liefern, bis sie aktualisiert sind.

**Recovery via `.bak`-Files:** wenn ein Auto-Update funktional kaputtgeht,
liegt der vorherige Skript-Stand unter `secscan-agent.sh.bak` bzw.
`lib_host_state.sh.bak`. Rollback: `mv secscan-agent.sh.bak secscan-agent.sh`.

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
ueber ``SECSCAN_FEED_*``-Env-Vars ueberschreibbar:

| Env-Var | Default | Bedeutung |
|---|---|---|
| `SECSCAN_FEED_PULL_DISABLED` | `false` | Master-Switch |
| `SECSCAN_FEED_EPSS_URL` | empirsec-CSV | EPSS-Quelle |
| `SECSCAN_FEED_KEV_URL` | CISA-JSON | KEV-Quelle |
| `SECSCAN_FEED_PULL_INTERVAL_HOURS` | `24` | Pull-Frequenz |
| `SECSCAN_FEED_JITTER_MAX_MIN` | `30` | Symmetric-Jitter um den Interval |
| `SECSCAN_FEED_MAX_DECOMPRESSED_MB_EPSS` | `50` | Gzip-Bomb-Cap fuer EPSS |
| `SECSCAN_FEED_MAX_BYTES_KEV_MB` | `10` | Body-Cap fuer KEV-JSON |

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

`POST /api/scans` antwortet im Async-Modus binnen <1s mit 202 + Job-ID.
Die volle Verarbeitung (Findings-UPSERT, Host-State-Persist, Pre-Triage,
Group-Matching, LLM-Job-Queueing) laeuft im `secscan-llm-worker`-Container
als neuer Sub-Tick `scan_ingest_tick` (vor LLM-Pickup priorisiert).

### Feature-Flag-Cutover

Verhalten wird via Env-Variable gesteuert:

```
SECSCAN_SCAN_INGEST_ASYNC=false   # Default: Sync-Pfad aktiv (Status-Quo)
SECSCAN_SCAN_INGEST_ASYNC=true    # Async-Fast-Path aktiv
```

Empfohlener Cutover (analog ADR-0026 Block R Phase H):

1. Deploy Backend mit Block-R-Code, Flag auf `false`. Schema-Migration
   `0010_scan_ingest_jobs` lauft mit; Worker-Sub-Tick steht bereit aber
   bekommt keine Jobs.
2. Sanity-Check: manueller Job-Insert via `psql` plus `worker_logs |
   grep scan_ingest` zeigt Pickup + Status-Wechsel.
3. Flag auf `true`. Edge-Handler schaltet auf 202-Response um.
4. Agent-Auto-Update zieht 0.4.0 sukzessive. Bis dahin akzeptieren alte
   Agents (`<0.4.0`, ohne Polling-Loop) das 202-Body ohne Counts und
   beenden mit Exit 0 (siehe `agent/secscan-agent.sh` v0.3.x).
5. Nach 7 Tagen Beobachtung: `MIN_AGENT_VERSION` auf `0.4.0` (separate
   ENV-Variable im Web-Container).

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
| `SECSCAN_MAX_QUEUED_INGEST_JOBS` | `50` | Per-Server-Limit auf `(queued|in_progress)`-Jobs. `429 queue_full` beim Insert wenn ueberschritten. |
| `SECSCAN_SCAN_INGEST_ASYNC` | `false` | Master-Switch fuer den Fast-Path. |

Wenn ein Server wiederholt 429s sieht: Stale-Reaper-Lauf abwarten (5min)
oder manuelle Queue-Bereinigung via SQL oben. Im Steady-State sollte die
Queue-Tiefe pro Server bei <5 liegen — alles darueber deutet auf einen
Worker-Backlog hin (siehe Multi-Worker-Re-Open-Trigger in ADR-0026).

### Worker-Logs

Phasen-Marker im `secscan-llm-worker`-Container:
- `scan_ingest.job_picked_up` — `{job_id, server_id, attempts}` beim Pickup
- `scan_ingest.job_done` — `{job_id, scan_id, duration_ms, counts}` bei Erfolg
- `scan_ingest.job_failed` — `{job_id, error_class, attempts}` bei finalem Fail
- `scan_ingest.retention_sweep_done` — `{cleared_payloads, deleted_failed}` stuendlich
- `scan_ingest.stale_reaped` — `{requeued, failed}` bei Stale-Reaper-Pass
