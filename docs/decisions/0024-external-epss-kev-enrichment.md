# ADR-0024 — EPSS- und KEV-Anreicherung via taeglichen Server-Side-Feed-Pull

**Status:** Akzeptiert · **Datum:** 2026-05-21

## Kontext

Block P (LLM-Risk-Reviewer, ADR-0023) braucht für die Pass-2-Risk-Bewertung pro Finding:

- **EPSS-Score** (Probability of Exploitation in den naechsten 30 Tagen)
- **KEV-Flag** (CISA "Known Exploited Vulnerabilities")

Die Finding-Tabelle hat dafuer die Spalten `epss_score`, `epss_percentile`, `is_kev`, `kev_added_at`. Der Trivy-Pydantic-Parser (`app/schemas/scan_envelope.py`) liest beide Felder. Die Ingest-Pipeline (`app/services/findings_ingest.py:204-207`) persistiert sie korrekt.

**Aber: Trivy 0.70 mit `--scanners vuln` schreibt EPSS und KEV in der Praxis nicht in den JSON-Output**, weil die aquasec-Vuln-DB diese Annotations nicht enthaelt. Beobachtet in Production (2026-05-20):

```sql
SELECT COUNT(*) FROM findings WHERE epss_score IS NOT NULL;  -- 0
SELECT COUNT(*) FROM findings WHERE is_kev = TRUE;           -- 0
```

Ueber alle 35 Application-Groups und ~5000 Findings. Konsequenz: das Pass-2-LLM bekommt `epss=n/a` und `kev=no` als Default — der Eskalations-Pfad "KEV-listed → escalate" und "EPSS very-high → escalate" ist faktisch tot.

Geprueft und verworfen: **Migration zu Grype als Scanner-Backend**. Grype liefert EPSS/KEV out-of-the-box. Aber: Grype hat kein `title`-Feld, keine `severity_by_provider`-Map (Trivy liefert beides), und der Schema-Rewrite betrifft `app/schemas/scan_envelope.py`, `app/services/findings_ingest.py`, alle Fixtures und 20+ Tests. Plus Agent-Forced-Upgrade. Aufwand und Verlust an Datenreichtum stehen nicht im Verhaeltnis zum Gewinn.

## Entscheidung

Wir reichern EPSS und KEV **serverseitig** aus zwei oeffentlichen Daily-Feeds an, persistiert in zwei eigenen Tabellen. Trivy bleibt unveraendert als Scanner-Backend.

**Datenquellen:**

- **EPSS:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` — taegliches Full-Dataset von FIRST.org, CSV-Format mit `cve,epss,percentile`. ~250k Zeilen, ~3 MB gzipped, ~25 MB ungezippt. Update um ~06:00 UTC.
- **KEV:** `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` — CISA-GitHub-Mirror als JSON, ~1500 Eintraege, ~1 MB. Update unregelmaessig (mehrmals pro Woche).

  Hinweis: cisa.gov-Direktquelle (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) ist identisch im Schema, wird aber von Cloudflare/WAF auf Cloud-IP-Ranges (Hetzner, DigitalOcean, ...) mit 403 Forbidden geblockt. Beobachtet 2026-05-21 auf Hetzner-RZ. Der GitHub-Mirror ist von CISA offiziell betrieben (`cisagov`-Org) und hat keinen Bot-Block.

**Worker-Tick:**

Im bestehenden LLM-Worker (`app/workers/llm_worker.py`) als Sub-Tick analog zu Stale-Reaper und Debug-Log-Eviction. Lauf alle 24h pro Feed, mit Jitter +- 30 Min. First-Run sofort beim Worker-Start wenn Tabelle leer.

**Anreicherung:**

In `app/services/findings_ingest.py` direkt im Insert-Pfad: pro Finding wird `cve_id` gegen `epss_scores` und `cisa_kev_catalog` per LEFT JOIN gelookupt. Felder werden gesetzt wenn Treffer, sonst bleiben NULL/FALSE.

**Bestehende Findings:**

Nach dem ersten erfolgreichen Pull beider Feeds wird ein einmaliger Backfill-Job ausgefuehrt (`UPDATE findings SET epss_score = es.epss_score, ... FROM epss_scores es WHERE findings.identifier_key = es.cve_id`). Idempotent, kann beliebig oft wiederholt werden.

## Begruendung

1. **Minimaler Code-Footprint** — zwei neue Tabellen, ein neuer Worker-Sub-Tick, drei zusaetzliche Spalten-Lookups im bestehenden Ingest-Pfad. Kein Schema-Rewrite, keine Fixture-Migration, keine Agent-Aenderung.

2. **Trivy's Datenreichtum bleibt** — `severity_by_provider`-Map, `title`, `cwe_ids` bleiben aus dem Trivy-Output erhalten. Nur die zwei wirklich fehlenden Felder werden extern angereichert.

3. **Single-Source-of-Truth fuer Exploit-Signale** — FIRST.org (EPSS) und CISA (KEV) sind die offiziellen Quellen. Scanner-Tools sind nur Konsumenten dieser Feeds, nie Original-Quelle. Direkter Pull schneidet einen Intermediary aus.

4. **Update-Latenz besser als beim Scanner** — Trivy-DB-Updates haengen vom aquasec-Build-Cycle ab (oft mehrere Tage Verzoegerung). Direkter EPSS/KEV-Pull ist <24h zur Original-Publikation.

5. **Operative Einfachheit** — kein Agent-Forced-Upgrade, keine Operator-Migration-Schritte, keine DB-Reset-Empfehlung. Release ist additiv: Server-Update → erste EPSS/KEV-Pulls innerhalb 24h → naechster Scan-Cycle nutzt die Daten.

## Konsequenzen

### Neue DB-Tabellen

```sql
-- Migration 0008_block_p_external_enrichment.py

CREATE TABLE epss_scores (
    cve_id          VARCHAR(32) NOT NULL PRIMARY KEY,
    epss_score      FLOAT NOT NULL,
    epss_percentile FLOAT NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    CONSTRAINT ck_epss_scores_range CHECK (
        epss_score >= 0.0 AND epss_score <= 1.0 AND
        epss_percentile >= 0.0 AND epss_percentile <= 1.0
    )
);
-- Hot-Path: bei Ingest mit ~5000 Findings ist ein single-row-PK-Lookup
-- pro Finding billig genug; kein zusaetzlicher Index noetig.

CREATE TABLE cisa_kev_catalog (
    cve_id              VARCHAR(32) NOT NULL PRIMARY KEY,
    vendor_project      VARCHAR(256),
    product             VARCHAR(256),
    vulnerability_name  VARCHAR(512),
    date_added          DATE NOT NULL,
    short_description   TEXT,
    required_action     TEXT,
    due_date            DATE,
    known_ransomware    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE feed_pull_log (
    id              BIGSERIAL PRIMARY KEY,
    feed_name       VARCHAR(32) NOT NULL,
    started_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    completed_at    TIMESTAMP WITH TIME ZONE,
    row_count       INT,
    bytes_downloaded BIGINT,
    status          VARCHAR(16) NOT NULL,  -- 'running' | 'success' | 'failed'
    error_message   TEXT,
    CONSTRAINT ck_feed_pull_log_name CHECK (feed_name IN ('epss', 'cisa_kev'))
);
CREATE INDEX ix_feed_pull_log_feed_started
    ON feed_pull_log (feed_name, started_at DESC);
```

Eviction in `feed_pull_log`: hard-cap 100 Zeilen pro `feed_name`, im selben Worker-Sub-Tick wie der Pull.

### Worker-Sub-Tick (`app/workers/feed_enrichment.py` neu)

```
class FeedEnrichmentWorker:
    EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    KEV_URL  = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

    EPSS_INTERVAL_HOURS = 24
    KEV_INTERVAL_HOURS  = 24
    JITTER_MAX_MIN      = 30

    MAX_DECOMPRESSED_BYTES_EPSS = 50 * 1024 * 1024  # 50 MB Cap
    MAX_BYTES_KEV               = 10 * 1024 * 1024  # 10 MB Cap

    def tick(self, session) -> None:
        # 1. Letzten Pull-Zeitpunkt pro Feed nachschauen
        # 2. Wenn aelter als Interval (+/- Jitter) → pullen
        # 3. Bei Erfolg: Bootstrap-Backfill triggern wenn vorher leer
```

Im LLM-Worker-Mainloop wird der Tick beim selben Sub-Tick-Pattern aufgerufen wie der Stale-Reaper (siehe `app/workers/llm_worker.py` heute).

### Pydantic-Schemas

```
class EpssRow(BaseModel):
    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    epss: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)

class KevEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cveID: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    vendorProject: str | None = Field(default=None, max_length=256)
    product: str | None = Field(default=None, max_length=256)
    vulnerabilityName: str | None = Field(default=None, max_length=512)
    dateAdded: date
    shortDescription: str | None = None
    requiredAction: str | None = None
    dueDate: date | None = None
    knownRansomwareCampaignUse: str | None = None  # "Known" | "Unknown" | null

class KevFeed(BaseModel):
    model_config = ConfigDict(extra="ignore")
    catalogVersion: str
    dateReleased: datetime
    count: int
    vulnerabilities: list[KevEntry]
```

### Ingest-Anreicherung (`app/services/findings_ingest.py`)

Vor dem `pg_insert(Finding)`-Bulk: zwei Lookups gegen `epss_scores` und `cisa_kev_catalog` per `cve_id IN (...)`, in Maps gepackt, dann pro Row gesetzt:

```python
cve_ids = {row["identifier_key"] for row in rows if row["identifier_key"].startswith("CVE-")}
epss_map = {r.cve_id: r for r in session.scalars(
    select(EpssScore).where(EpssScore.cve_id.in_(cve_ids))
)}
kev_map = {r.cve_id: r for r in session.scalars(
    select(CisaKevCatalog).where(CisaKevCatalog.cve_id.in_(cve_ids))
)}

for row in rows:
    cve = row["identifier_key"]
    if (e := epss_map.get(cve)) is not None:
        row["epss_score"] = e.epss_score
        row["epss_percentile"] = e.epss_percentile
    if (k := kev_map.get(cve)) is not None:
        row["is_kev"] = True
        row["kev_added_at"] = datetime.combine(k.date_added, time.min, tzinfo=timezone.utc)
```

Trivy-gelieferte EPSS/KEV-Werte (falls eines Tages vorhanden) gewinnen NICHT — wir ueberschreiben mit unseren Feed-Werten, weil unsere Quelle frischer ist. Konflikt zu loggen (structlog `info`-Level, einmal pro Ingest).

### Backfill-Mechanik

Nach dem ersten erfolgreichen Pull pro Feed wird ein Bootstrap-Backfill ausgefuehrt:

```sql
-- EPSS
UPDATE findings
SET epss_score = es.epss_score,
    epss_percentile = es.epss_percentile
FROM epss_scores es
WHERE findings.identifier_key = es.cve_id
  AND (findings.epss_score IS NULL OR findings.epss_score <> es.epss_score);

-- KEV
UPDATE findings
SET is_kev = TRUE,
    kev_added_at = (kev.date_added::timestamp AT TIME ZONE 'UTC')
FROM cisa_kev_catalog kev
WHERE findings.identifier_key = kev.cve_id
  AND findings.is_kev = FALSE;
```

Idempotent. Wird auch nach jedem nachfolgenden Pull ausgefuehrt, weil neue KEV-Eintraege bestehende Findings betreffen koennen ("ein bekanntes CVE wird in CISA-KEV nachgetragen → unsere bestehenden Findings dafuer werden zu is_kev=TRUE").

### Operative Aspekte

- **Outbound-Network-Anforderung neu**: Server braucht HTTPS-Zugriff auf `epss.empiricalsecurity.com` und `raw.githubusercontent.com`. Dokumentieren in `docs/operations.md`.
- **Air-Gap-Setup**: per `SECSCAN_FEED_DISABLED=true`-Env-Var komplett abschaltbar. Findings bleiben dann ohne EPSS/KEV-Anreicherung. UI/Pass-2 funktionieren weiter (Prompt sagt explizit "treat `epss=n/a` as unknown").
- **Pull-Failure-Verhalten**: log + `status='failed'` in `feed_pull_log`, naechster Tick versucht erneut. Bestehende Daten bleiben unveraendert (kein TRUNCATE bei Failure).
- **Feed-Freshness-Anzeige im UI (MVP)**: zweizeiliger Block am Ende der LLM-Settings-Seite (`app/views/llm_settings.py`), gerendert aus `feed_pull_log`. Format:

  ```
  EPSS:     letzter Pull 2026-05-21 06:12 UTC · 247.382 Eintraege
  CISA-KEV: letzter Pull 2026-05-21 03:45 UTC · 1.453 Eintraege
  ```

  Bei stale (>7 Tage) oder failed letztem Pull: Zeile rot gefaerbt mit Status-String, z.B. ``... · 9 Tage alt`` oder ``... letzter Versuch fehlgeschlagen (HTTP 503)``. Kein eigenes Setting-Panel, keine eigene Seite, kein Refresh-Button — reine Anzeige-Pflicht damit der Operator sieht wenn die Pulls nicht klappen.

### Was bleibt unveraendert

- Trivy als Scanner
- Agent-Code (`agent/secscan-agent.sh`)
- Finding-Tabelle (Spalten existieren bereits)
- LLM-Risk-Reviewer Pass 1 + Pass 2
- UI/Dashboard

## Re-Open-Trigger

- Wenn Trivy in einer kommenden Version EPSS/KEV in der Standard-Vuln-DB integriert (laufendes CHANGELOG-Monitoring).
- Wenn der EPSS-CSV-Endpunkt oder das CISA-KEV-JSON-Schema breaking-change (Feld-Umbenennung, neuer Pfad). Falls EPSS jemals auf `cve_id,risk_score,...`-Schema wechselt: ADR-Update.
- Wenn die Pull-Mechanik in einem Multi-Instance-Deploy zur Race-Condition wird (heute single-instance gemaess Out-of-Scope-Liste).

## Implementierungs-Skizze (informativ)

Phasen-Plan, getrennt nach Risiko:

**Phase 1 — Datenmodell + Worker-Tick (low risk):**

1. Migration `0008_block_p_external_enrichment.py` — drei neue Tabellen
2. SQLAlchemy-Modelle `EpssScore`, `CisaKevCatalog`, `FeedPullLog` in `app/models.py`
3. Pydantic-Schemas `EpssRow`, `KevEntry`, `KevFeed` in `app/schemas/feed_enrichment.py` (neu)
4. `app/workers/feed_enrichment.py` (neu): Pull + Decompress + Parse + UPSERT
5. Integration in `app/workers/llm_worker.py` als Sub-Tick
6. Settings-Eintraege: `SECSCAN_FEED_DISABLED`, Intervalle, Caps

**Phase 2 — Ingest-Anreicherung (medium risk):**

7. `app/services/findings_ingest.py` — Lookup-Pfad in `_finding_rows_from_envelope()`
8. Tests: positive (Finding mit EPSS-Match wird angereichert), negative (CVE ohne Treffer bleibt NULL), Edge (`identifier_key` kein CVE-Format → kein Lookup-Versuch)

**Phase 3 — Backfill (low risk, einmalig):**

9. `app/services/feed_backfill.py` (neu): die zwei UPDATE-Statements als ORM-Wrapper
10. Aufruf vom Worker nach jedem erfolgreichen Pull
11. Adversarial-Test: gleichzeitiges Ingest + Backfill darf keine Duplicate-Keys triggern

**Phase 4 — Operative Reife:**

12. `docs/operations.md`-Eintrag mit Outbound-URLs, Optional-Disable-Env, Feed-Health-Query
13. Audit-Event: `feed.epss_pulled`, `feed.kev_pulled` mit `event_metadata = {row_count, bytes, duration_ms}`
14. CHANGELOG-Eintrag

### Geklaerte Design-Entscheidungen (2026-05-21)

1. **Hot-Reload bei neuem KEV-Eintrag** — laufender Pass-2-Job laeuft durch mit dem Stand zum Render-Zeitpunkt. Neuer Stand wirkt beim naechsten Ingest. Konsistent mit Lazy-Eval-Semantik.

2. **EPSS-Updates ueberschreiben Trivy-Werte** — unsere Feed-Werte sind fuehrend, auch wenn Trivy spaeter mal EPSS liefern sollte. Eine autoritative Quelle, kein Drift.

3. **Nicht-CVE-Identifiers** (GHSA, RHSA, etc.) — Lookup skippt, EPSS/KEV bleiben NULL/FALSE. Korrekt, fuer diese Identifier gibt es keine EPSS/KEV-Quellen.

4. **DB-Wachstum** (~11 MB total) — vernachlaessigbar, keine Vacuum-/Maintenance-Strategie noetig.

5. **Feed-Stale-Detection** — structlog-WARNING wenn letzter erfolgreicher Pull > 7 Tage. Kein UI-Banner. Die Two-Liner-Anzeige in der LLM-Settings-Seite (mit rot-Markierung bei stale) deckt das visuell ab.
