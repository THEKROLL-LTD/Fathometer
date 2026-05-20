# Operations-Notizen

Kurze Pointer fuer Operator-Setup. Detailliertere Architektur-Entscheidungen in `docs/decisions/`.

## Outbound-Network-Anforderungen

Der Server braucht HTTPS-Zugriff auf folgende externe Endpunkte:

| Endpunkt | Zweck | Block | Frequenz |
|---|---|---|---|
| `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | EPSS-Scores-Feed (FIRST.org) | Q (ADR-0024) | alle 24h |
| `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | KEV-Katalog | Q (ADR-0024) | alle 24h |
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
