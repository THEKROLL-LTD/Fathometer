-- ============================================================================
-- Findings + Caches Reset (keep servers / host context)
-- ----------------------------------------------------------------------------
-- Wipes all findings, scans, application-group evaluations and LLM
-- state/caches so a fresh evaluation attempt starts clean — WITHOUT touching
-- servers and their host-context (listeners/processes/services/kernel-modules/
-- tags/groups). The next agent scan re-upserts findings against the existing
-- servers; with unchanged host context the llm_risk_cache fingerprint already
-- starts empty here, so every (group, server) is a cache-miss = fresh LLM run.
--
-- KEPT: servers, server_*, server_groups, users, tags, settings (identity),
--       epss_scores, cisa_kev_catalog, audit_events, feed_pull_log,
--       alembic_version.
--
-- Schema-tolerant: only tables that to_regclass() resolves are truncated.
-- Usage:
--   psql -h <host> -p <port> -U <user> -d <db> -f scripts/reset_findings_caches.sql
-- ============================================================================

BEGIN;

DO $$
DECLARE
  targets text[] := ARRAY[
    'upstream_check_results',
    'group_chat_messages',
    'group_chat_conversations',
    'llm_debug_log',
    'llm_risk_cache',
    'llm_jobs',
    'daily_risk_state',
    'application_group_evaluations',
    'application_groups',
    'scan_ingest_jobs',
    'finding_notes',
    'findings',
    'scans'
  ];
  existing text[] := ARRAY[]::text[];
  t text;
  c bigint;
  total bigint := 0;
BEGIN
  RAISE NOTICE 'BEFORE — row counts of tables to be cleared:';
  FOREACH t IN ARRAY targets LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('SELECT count(*) FROM %I', t) INTO c;
      RAISE NOTICE '  %-32s % rows', t, c;
      total := total + c;
      existing := existing || quote_ident(t);
    ELSE
      RAISE NOTICE '  %-32s  (does not exist — skip)', t;
    END IF;
  END LOOP;
  RAISE NOTICE 'BEFORE — total: % rows', total;

  IF array_length(existing, 1) IS NULL THEN
    RAISE NOTICE 'No target tables exist — nothing to truncate.';
  ELSE
    RAISE NOTICE 'TRUNCATE % tables ...', array_length(existing, 1);
    EXECUTE 'TRUNCATE TABLE ' || array_to_string(existing, ', ')
            || ' RESTART IDENTITY CASCADE';
  END IF;
END $$;

-- Reset worker/budget bookkeeping in settings (identity columns untouched).
DO $$
BEGIN
  IF to_regclass('settings') IS NULL THEN RETURN; END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='settings' AND column_name='llm_worker_heartbeat_at') THEN
    UPDATE settings SET llm_worker_heartbeat_at = NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='settings' AND column_name='llm_token_budget_used_today') THEN
    UPDATE settings SET llm_token_budget_used_today = 0;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='settings' AND column_name='llm_token_budget_reset_at') THEN
    UPDATE settings SET llm_token_budget_reset_at = now();
  END IF;
  RAISE NOTICE 'settings worker/budget state reset (identity columns untouched).';
END $$;

-- After-counters (incl. kept tables for sanity).
DO $$
DECLARE t text; c bigint;
BEGIN
  RAISE NOTICE 'AFTER — state:';
  FOREACH t IN ARRAY ARRAY[
    'findings','scans','application_groups','application_group_evaluations',
    'daily_risk_state','llm_jobs','llm_risk_cache','llm_debug_log',
    'group_chat_conversations','upstream_check_results',
    'servers','server_listeners','server_processes','server_services',
    'server_kernel_modules','server_groups','users','settings',
    'epss_scores','cisa_kev_catalog','audit_events'
  ] LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('SELECT count(*) FROM %I', t) INTO c;
      RAISE NOTICE '  %-32s % rows', t, c;
    END IF;
  END LOOP;
END $$;

COMMIT;
