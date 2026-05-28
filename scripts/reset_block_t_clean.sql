-- ============================================================================
-- Clean-Reset (Block T / ADR-0028)
-- ----------------------------------------------------------------------------
-- Loescht **alle Server-bezogenen Daten** plus alle LLM-State-Tabellen, sodass
-- der Cluster mit leerer Findings-/Application-Group-/Junction-Sicht neu
-- startet. Master-Key, Admin-User, LLM-Provider-Konfig, Tag-Definitionen,
-- EPSS/KEV-Feed-Daten bleiben erhalten.
--
-- Schema-tolerant: nur Tabellen die `to_regclass()` aufloest werden truncated.
-- Damit laeuft das Skript egal ob die DB auf Pre-Block-T (kein
-- `application_group_evaluations`), auf Block T (kein
-- `application_groups.risk_band` mehr) oder mittendrin steht.
--
-- Anwendung:
--   psql -U secscan -d secscan -f scripts/reset_block_t_clean.sql
--   docker compose exec -T db psql -U secscan -d secscan < scripts/reset_block_t_clean.sql
--
-- Was BLEIBT:
--   - users, tags, settings (State-Felder werden resetted, Identity-Felder
--     wie master_key_hash + llm_*-Config nicht angefasst), epss_scores,
--     cisa_kev_catalog, alembic_version.
-- ============================================================================

BEGIN;

-- ---- 1. Vorab-Counter (schema-tolerant via to_regclass) -------------------
-- Wir benennen alle Kandidat-Tabellen und counten nur die die existieren.
DO $$
DECLARE
  t text;
  c bigint;
  total bigint := 0;
BEGIN
  RAISE NOTICE 'BEFORE — Row-Counts der zu loeschenden Tabellen:';
  FOREACH t IN ARRAY ARRAY[
    'audit_events',
    'llm_messages',
    'llm_conversation_findings',
    'llm_conversations',
    'llm_debug_log',
    'llm_risk_cache',
    'llm_jobs',
    'application_group_evaluations',
    'application_groups',
    'scan_ingest_jobs',
    'finding_notes',
    'findings',
    'scans',
    'server_listeners',
    'server_processes',
    'server_kernel_modules',
    'server_services',
    'server_tags',
    'servers',
    'feed_pull_log'
  ]
  LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('SELECT count(*) FROM %I', t) INTO c;
      RAISE NOTICE '  %-32s % rows', t, c;
      total := total + c;
    ELSE
      RAISE NOTICE '  %-32s  (Tabelle existiert nicht — skip)', t;
    END IF;
  END LOOP;
  RAISE NOTICE 'BEFORE — Summe: % rows', total;
END $$;

-- ---- 2. TRUNCATE (nur existierende Tabellen) ------------------------------
-- Wir bauen den TRUNCATE dynamisch zusammen, sodass nicht-vorhandene Tabellen
-- nicht zu Fehlern fuehren. CASCADE folgt ON DELETE CASCADE auf allen FKs.
-- RESTART IDENTITY setzt BIGSERIAL/SERIAL-Sequenzen auf 1 zurueck.
DO $$
DECLARE
  existing text[];
  t text;
BEGIN
  existing := ARRAY[]::text[];
  FOREACH t IN ARRAY ARRAY[
    'audit_events',
    'llm_messages',
    'llm_conversation_findings',
    'llm_conversations',
    'llm_debug_log',
    'llm_risk_cache',
    'llm_jobs',
    'application_group_evaluations',
    'application_groups',
    'scan_ingest_jobs',
    'finding_notes',
    'findings',
    'scans',
    'server_listeners',
    'server_processes',
    'server_kernel_modules',
    'server_services',
    'server_tags',
    'servers',
    'feed_pull_log'
  ]
  LOOP
    IF to_regclass(t) IS NOT NULL THEN
      existing := existing || quote_ident(t);
    END IF;
  END LOOP;

  IF array_length(existing, 1) IS NULL THEN
    RAISE NOTICE 'Keine der Ziel-Tabellen existiert — nichts zu truncaten.';
  ELSE
    RAISE NOTICE 'TRUNCATE % Tabellen ...', array_length(existing, 1);
    EXECUTE 'TRUNCATE TABLE ' || array_to_string(existing, ', ')
            || ' RESTART IDENTITY CASCADE';
  END IF;
END $$;

-- ---- 3. settings-State zuruecksetzen --------------------------------------
-- KEINE Identity-Felder anfassen (master_key_hash, llm_api_key_encrypted,
-- llm_base_url, llm_model, llm_provider_name, setup_completed_at).
-- Nur die ehedem-laufende Worker-/Budget-Buchhaltung leeren.
-- Schema-tolerant: nur Spalten die existieren werden gesetzt.
DO $$
BEGIN
  IF to_regclass('settings') IS NULL THEN
    RAISE NOTICE 'settings-Tabelle existiert nicht — skip.';
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'settings' AND column_name = 'block_p_llm_mode'
  ) THEN
    UPDATE settings SET block_p_llm_mode = 'off';
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'settings' AND column_name = 'llm_worker_heartbeat_at'
  ) THEN
    UPDATE settings SET llm_worker_heartbeat_at = NULL;
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'settings' AND column_name = 'llm_token_budget_used_today'
  ) THEN
    UPDATE settings SET llm_token_budget_used_today = 0;
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'settings' AND column_name = 'llm_token_budget_reset_at'
  ) THEN
    UPDATE settings SET llm_token_budget_reset_at = now();
  END IF;
  RAISE NOTICE 'settings-State zurueckgesetzt (Identity-Felder unangetastet).';
END $$;

-- ---- 4. Nach-Counter ------------------------------------------------------
DO $$
DECLARE
  t text;
  c bigint;
BEGIN
  RAISE NOTICE 'AFTER — Stand der relevanten Tabellen:';
  FOREACH t IN ARRAY ARRAY[
    'servers',
    'scans',
    'findings',
    'application_groups',
    'application_group_evaluations',
    'llm_jobs',
    'llm_risk_cache',
    'scan_ingest_jobs',
    'audit_events',
    'users',
    'tags',
    'settings',
    'epss_scores',
    'cisa_kev_catalog'
  ]
  LOOP
    IF to_regclass(t) IS NOT NULL THEN
      EXECUTE format('SELECT count(*) FROM %I', t) INTO c;
      RAISE NOTICE '  %-32s % rows', t, c;
    END IF;
  END LOOP;
END $$;

COMMIT;

-- ============================================================================
-- Nach dem Lauf:
--   - Operator-Login funktioniert unveraendert (users + settings.* intakt).
--   - Server-Liste in der UI ist leer; Operator muss Server via
--     `secscan-register` neu anlegen (neuer Server-Key pro Host).
--   - Erster Agent-Scan eines Servers triggert:
--       1. Findings-UPSERT (frisch, alle als first_seen_at = now()).
--       2. Pass-1 -> baut application_groups + (bei Block T) Junction-Rows auf.
--       3. Pass-2 -> fuellt application_group_evaluations bzw. die alten
--          ApplicationGroup-Eval-Felder, je nach DB-Stand.
--       4. inherit_group_risk_to_findings setzt Finding-Bands.
--   - Bei aktivem `SECSCAN_SCAN_INGEST_ASYNC=true` laeuft das via
--     scan_ingest_jobs; sonst synchron.
--   - Feed-Pull (EPSS/KEV) wird beim naechsten Worker-Tick getriggert (feed_
--     pull_log ist leer); die Daten in epss_scores/cisa_kev_catalog waren
--     aber erhalten, der Re-Pull ist nur Audit-Eintrag.
-- ============================================================================
