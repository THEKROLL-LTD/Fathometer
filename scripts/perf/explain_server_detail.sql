-- explain_server_detail.sql — EXPLAIN-Messung der heissen Server-Detail-Queries
-- ===========================================================================
-- Zweck: vor dem Anlegen neuer Indizes messen, welche Server-Detail-Widget-
-- Queries bei >10k Findings/Server tatsaechlich teuer sind und welchen Plan
-- (Seq Scan / Index Scan / Index-Only Scan) der Planner heute waehlt.
--
-- Die SQL spiegelt 1:1 die SQLAlchemy-Queries in app/views/server_detail.py
-- und app/services/heartbeat_aggregation.py (Stand 2026-06-07), inkl.
-- CASE-Severity-Sort (_triage_severity_sort_expr) und Enum-Literalen
-- ('open' / 'critical' …).
--
-- Aufruf (gegen die ECHTE 10k-DB, read-only — nur EXPLAIN, keine Mutation):
--   psql "$DATABASE_URL" -f scripts/perf/explain_server_detail.sql
-- oder im Container:
--   docker compose exec db psql -U <user> -d <db> -f /…/explain_server_detail.sql
--
-- Hinweis: EXPLAIN ANALYZE FUEHRT die Query wirklich aus (SELECT, kein Write),
-- misst also echte Zeiten + Buffer-I/O. BUFFERS zeigt heap-fetch vs.
-- index-only (shared hit/read).
-- ===========================================================================

\timing on

-- Optional: JIT aus, um die in Migration 0015 erwaehnte JIT-Latenz bei
-- Aggregaten aus der Messung zu nehmen. Auskommentiert lassen, um den realen
-- Default-Plan zu sehen; einkommentieren fuer den "JIT-off"-Vergleich.
-- SET jit = off;

-- Defaults, falls ein \gset unten keine Zeile liefert (Server ohne Gruppen etc.)
\set sid 0
\set band 'escalate'
\set gid 0

-- --- 0. Hottest Server (meiste OPEN-Findings) automatisch waehlen -----------
SELECT server_id AS sid
FROM findings
WHERE status = 'open'
GROUP BY server_id
ORDER BY count(*) DESC
LIMIT 1
\gset

-- Groesstes Risk-Band dieses Servers
SELECT risk_band AS band
FROM findings
WHERE server_id = :sid AND status = 'open' AND risk_band IS NOT NULL
GROUP BY risk_band
ORDER BY count(*) DESC
LIMIT 1
\gset

-- Groesste Application-Group dieses Servers
SELECT application_group_id AS gid
FROM findings
WHERE server_id = :sid AND status = 'open' AND application_group_id IS NOT NULL
GROUP BY application_group_id
ORDER BY count(*) DESC
LIMIT 1
\gset

\echo '==================================================================='
\echo 'Gewaehlter Test-Server (sid), groesstes Band, groesste Group (gid):'
SELECT :sid AS sid, :'band' AS band, :gid AS gid;
\echo 'OPEN-Findings auf diesem Server / in diesem Band / in dieser Group:'
SELECT
  (SELECT count(*) FROM findings WHERE server_id = :sid AND status = 'open') AS open_total,
  (SELECT count(*) FROM findings WHERE server_id = :sid AND status = 'open' AND risk_band = :'band') AS open_band,
  (SELECT count(*) FROM findings WHERE server_id = :sid AND status = 'open' AND application_group_id = :gid) AS open_group,
  (SELECT count(*) FROM findings WHERE server_id = :sid) AS all_total;
\echo '==================================================================='


-- ===========================================================================
-- Q1  triage_band_fragment — COUNT (server_detail.py:1076)
--     Verdaechtigt-#1: zaehlt ALLE offenen Rows eines Bands, fette Heap-Rows.
--     Kandidat-Index #1: (server_id, risk_band) WHERE status='open'  -> Index-Only.
-- ===========================================================================
\echo '### Q1 triage COUNT (server_id, status=open, risk_band)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT count(findings.id)
FROM findings
WHERE findings.server_id = :sid
  AND findings.status = 'open'
  AND findings.risk_band = :'band';


-- ===========================================================================
-- Q2  triage_band_fragment — LIST (server_detail.py:1081), Seite 1, Size 10
--     CASE-Severity-Sort exakt wie _triage_severity_sort_expr().
-- ===========================================================================
\echo '### Q2 triage LIST (limit 10, CASE-severity-sort)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT findings.*
FROM findings
WHERE findings.server_id = :sid
  AND findings.status = 'open'
  AND findings.risk_band = :'band'
ORDER BY
  findings.is_kev DESC,
  CASE
    WHEN findings.severity = 'critical' THEN 0
    WHEN findings.severity = 'high'     THEN 1
    WHEN findings.severity = 'medium'   THEN 2
    WHEN findings.severity = 'low'      THEN 3
    WHEN findings.severity = 'unknown'  THEN 4
    ELSE 5
  END ASC,
  findings.epss_score DESC NULLS LAST
LIMIT 10 OFFSET 0;


-- ===========================================================================
-- Q3  _risk_band_header_counts (server_detail.py:445)
--     GROUP BY risk_band — Kandidat-Index #1 deckt das index-only ab.
-- ===========================================================================
\echo '### Q3 header risk_band counts (GROUP BY risk_band WHERE server+open)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT findings.risk_band, count(findings.id)
FROM findings
WHERE findings.server_id = :sid
  AND findings.status = 'open'
GROUP BY findings.risk_band;


-- ===========================================================================
-- Q4  _load_server_band_aggregates (server_detail.py:526)
--     wie Q3 + FILTER (application_group_id IS NULL).
-- ===========================================================================
\echo '### Q4 band aggregates (+ pending-count filter)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT
  findings.risk_band,
  count(findings.id) AS total,
  count(*) FILTER (WHERE findings.application_group_id IS NULL) AS pending
FROM findings
WHERE findings.server_id = :sid
  AND findings.status = 'open'
GROUP BY findings.risk_band;


-- ===========================================================================
-- Q5  _load_application_groups_for_server Query 1 (server_detail.py:233)
--     GROUP BY application_group_id — Kandidat-Index #2:
--       (server_id, application_group_id) WHERE status='open'
-- ===========================================================================
\echo '### Q5 app-group counts (GROUP BY application_group_id)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT findings.application_group_id, count(findings.id)
FROM findings
WHERE findings.server_id = :sid
  AND findings.status = 'open'
  AND findings.application_group_id IS NOT NULL
GROUP BY findings.application_group_id;


-- ===========================================================================
-- Q6  group_findings_fragment (server_detail.py:798)
--     Liste einer Group, voller Sort — Kandidat-Index #2 hilft beim Filter.
-- ===========================================================================
\echo '### Q6 group_findings list (server+group+open, full sort)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT findings.*
FROM findings
WHERE findings.server_id = :sid
  AND findings.application_group_id = :gid
  AND findings.status = 'open'
ORDER BY
  findings.is_kev DESC,
  findings.epss_score DESC NULLS LAST,
  findings.cvss_v3_score DESC NULLS LAST,
  findings.first_seen_at ASC;


-- ===========================================================================
-- Q7  _tendency_quick (server_detail.py:495)
--     Zeitfenster-Counts — first_seen_at ist INCLUDE im Covering-Index.
-- ===========================================================================
\echo '### Q7 tendency window counts (first_seen_at buckets)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT
  count(*) FILTER (WHERE findings.first_seen_at >= now() - interval '7 days')  AS current_7,
  count(*) FILTER (WHERE findings.first_seen_at >= now() - interval '14 days'
                     AND findings.first_seen_at <  now() - interval '7 days')  AS prev_7
FROM findings
WHERE findings.server_id = :sid
  AND findings.status = 'open';


-- ===========================================================================
-- Q8  heartbeats_for_servers — Findings-Query (heartbeat_aggregation.py:312)
--     Sidebar-Batch ueber ALLE sichtbaren Server; resolved_at-Fenster statt
--     status-Filter. Worst-Case: alle Server. Covering-Index deckt Projektion.
--     (Python-Aggregation danach = TD-013, nicht index-loesbar.)
-- ===========================================================================
\echo '### Q8 heartbeat batch findings (all servers, resolved_at window)'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT
  findings.server_id, findings.severity, findings.first_seen_at,
  findings.acknowledged_at, findings.resolved_at, findings.is_kev,
  findings.kev_added_at, findings.risk_band
FROM findings
WHERE findings.server_id IN (SELECT id FROM servers)
  AND (findings.resolved_at IS NULL OR findings.resolved_at >= now() - interval '29 days');


\echo '==================================================================='
\echo 'Fertig. Interpretation:'
\echo '  * "Seq Scan on findings" bei Q1/Q3/Q4/Q5  -> Kandidat-Index greift,'
\echo '    Composite-Partial-Index anlegen und gegenmessen.'
\echo '  * "Index Only Scan using ix_findings_server_covering" + heap fetches=0'
\echo '    -> bereits optimal (Q7/Q8 erwartet).'
\echo '  * "Heap Fetches: <hoch>" trotz Index -> VACUUM ANALYZE findings; noetig.'
\echo '==================================================================='
