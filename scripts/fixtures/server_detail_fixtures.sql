-- ============================================================================
-- Server-Detail UI-Smoke Fixtures
-- ----------------------------------------------------------------------------
-- Erstellt drei Test-Server mit unterschiedlichen Zustaenden, damit alle
-- visuellen Elemente der `/servers/<id>` Seite (Block X Re-Implementation,
-- 2026-05-25) verifizierbar sind.
--
-- Server-Profile:
--   prod-edge-01    — voll: KEV+Critical+High, ESCALATE+ACT+MITIGATE Bands,
--                     Host-Snapshot mit loopback+public-exposed Listenern,
--                     systemd-Services, noise-Findings fuer Bulk-Ack-Button,
--                     llm-evaluated Application-Group fuer Operator-Workflow,
--                     recent scan + trivy-db.
--   staging-app-02  — mittel: ACT+MITIGATE+PENDING Bands, snapshot vorhanden
--                     aber nur loopback Listener, kein KEV, ein
--                     pending-grouping Finding (kein application_group_id).
--   legacy-db-03    — stale: last_scan > 24h alt, trivy-db > 7d alt,
--                     agent_version veraltet, host_state_snapshot_at IS NULL
--                     (Pills disabled), nur monitor/noise Findings.
--
-- Idempotenz:
--   Skript ist re-runnable — kapselt alles in einer Transaction und loescht
--   die drei Test-Server vorher (CASCADE saeubert findings/listeners/services
--   /processes/evaluations). Existierende Production-Server bleiben unberuehrt
--   (DELETE filtert ueber Namen).
--
-- Aufruf (vom Host):
--   docker exec -i secscan-db-1 psql -U secscan -d secscan \
--     < scripts/fixtures/server_detail_fixtures.sql
--
-- Reset:
--   DELETE FROM servers WHERE name IN ('prod-edge-01','staging-app-02','legacy-db-03');
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 0) Cleanup (idempotent re-run)
-- ----------------------------------------------------------------------------
-- ON DELETE CASCADE auf servers raeumt findings/listeners/services/processes
-- /evaluations/scans automatisch ab.
DELETE FROM servers WHERE name IN ('prod-edge-01', 'staging-app-02', 'legacy-db-03');

-- Test-spezifische Application-Groups loeschen (keine FK auf andere Server,
-- da das Skript hier sein eigenes Owner-Set hat).
DELETE FROM application_groups WHERE label IN (
    'fixture-openssl',     -- ESCALATE bundle, prod-edge-01
    'fixture-nginx',       -- ACT bundle,      prod-edge-01
    'fixture-curl',        -- MITIGATE,        prod-edge-01
    'fixture-libxml2',     -- ACT,             staging-app-02
    'fixture-glibc'        -- monitor,         legacy-db-03
);

-- Test-spezifische Server-Group loeschen (FK SET NULL).
DELETE FROM server_groups WHERE name IN ('fixtures-prod', 'fixtures-stage');

-- KEV-Eintraege aus dem Fixture-Lauf raeumen.
DELETE FROM cisa_kev_catalog WHERE cve_id IN (
    'CVE-2024-3094',       -- xz backdoor (KEV)
    'CVE-2024-6387'        -- OpenSSH regreSSHion (KEV)
);

-- EPSS-Scores fuer die Fixtures (idempotent reset).
DELETE FROM epss_scores WHERE cve_id LIKE 'CVE-2024-%' OR cve_id LIKE 'CVE-2023-99%';

-- ----------------------------------------------------------------------------
-- 1) Server-Groups
-- ----------------------------------------------------------------------------
INSERT INTO server_groups (name, position) VALUES
    ('fixtures-prod',  10),
    ('fixtures-stage', 20);

-- ----------------------------------------------------------------------------
-- 2) Server-Stammdaten
-- ----------------------------------------------------------------------------
-- api_key_hash ist NOT NULL. Wir nutzen einen offensichtlich-fake Hash, der
-- nicht versehentlich von einem echten Agent gematched werden kann.
INSERT INTO servers (
    name, api_key_hash, expected_scan_interval_h,
    last_scan_at, created_at,
    os_family, os_version, os_pretty_name, kernel_version, architecture,
    agent_version, trivy_version, trivy_db_version, trivy_db_updated_at,
    agent_version_seen_at, host_state_snapshot_at,
    group_id
) VALUES
    -- prod-edge-01: alles aktuell, snapshot vorhanden, vollausgestattet
    ('prod-edge-01',
     'fixture$argon2id$dummy$prodedge01' || repeat('0', 64),
     24,
     now() - interval '2 hours',     -- last_scan_at: aktuell
     now() - interval '90 days',
     'ubuntu', '24.04', 'Ubuntu 24.04.1 LTS',
     '6.8.0-45-generic', 'x86_64',
     '0.4.0',                          -- agent_version: aktuell
     '0.55.2',                         -- trivy_version: aktuell
     '2026.05.25.0',
     now() - interval '6 hours',     -- trivy_db_updated_at: frisch
     now() - interval '2 hours',
     now() - interval '2 hours',     -- snapshot vorhanden -> Pills aktiv
     (SELECT id FROM server_groups WHERE name = 'fixtures-prod')),

    -- staging-app-02: snapshot da, nur loopback, PENDING-Findings
    ('staging-app-02',
     'fixture$argon2id$dummy$stagingapp02' || repeat('0', 60),
     12,
     now() - interval '4 hours',
     now() - interval '60 days',
     'debian', '12', 'Debian GNU/Linux 12 (bookworm)',
     '6.1.0-25-amd64', 'x86_64',
     '0.4.0', '0.55.2', '2026.05.25.0',
     now() - interval '8 hours',
     now() - interval '4 hours',
     now() - interval '4 hours',
     (SELECT id FROM server_groups WHERE name = 'fixtures-stage')),

    -- legacy-db-03: stale + outdated, snapshot IS NULL
    ('legacy-db-03',
     'fixture$argon2id$dummy$legacydb03' || repeat('0', 62),
     24,
     now() - interval '5 days',      -- stale: weit jenseits 24h
     now() - interval '400 days',
     'ubuntu', '20.04', 'Ubuntu 20.04.6 LTS',
     '5.15.0-119-generic', 'x86_64',
     '0.2.5',                          -- agent_version: outdated (min 0.3.0)
     '0.50.0',                         -- trivy_version: outdated
     '2026.05.14.0',
     now() - interval '11 days',     -- trivy-db stale (>7d)
     now() - interval '5 days',
     NULL,                             -- snapshot IS NULL -> Pills disabled
     (SELECT id FROM server_groups WHERE name = 'fixtures-prod'));

-- ----------------------------------------------------------------------------
-- 3) Host-State-Snapshot (Listener + Services + Processes)
-- ----------------------------------------------------------------------------

-- prod-edge-01: mix aus loopback + public-exposed
INSERT INTO server_listeners (server_id, proto, port, addr, process, pid) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'tcp', 22,   '0.0.0.0',   'sshd',    1024),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'tcp', 80,   '0.0.0.0',   'nginx',   1500),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'tcp', 443,  '0.0.0.0',   'nginx',   1500),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'tcp', 5432, '127.0.0.1', 'postgres', 1800),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'tcp', 6379, '127.0.0.1', 'redis-server', 1900),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'tcp', 9100, '::1',       'node_exporter', 2000);

INSERT INTO server_services (server_id, name) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'nginx.service'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'postgresql.service'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'redis-server.service'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'ssh.service'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'systemd-resolved.service'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'node_exporter.service'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 'fail2ban.service');

INSERT INTO server_processes (server_id, pid, "user", comm, args) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 1500, 'www-data', 'nginx',    '/usr/sbin/nginx -g daemon off;'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 1800, 'postgres', 'postgres', '/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'), 1900, 'redis',    'redis-server', '/usr/bin/redis-server 127.0.0.1:6379');

-- staging-app-02: nur loopback Listener
INSERT INTO server_listeners (server_id, proto, port, addr, process, pid) VALUES
    ((SELECT id FROM servers WHERE name='staging-app-02'), 'tcp', 22,   '127.0.0.1', 'sshd',    1024),
    ((SELECT id FROM servers WHERE name='staging-app-02'), 'tcp', 8080, '127.0.0.1', 'gunicorn', 1700),
    ((SELECT id FROM servers WHERE name='staging-app-02'), 'tcp', 5432, '127.0.0.1', 'postgres', 1800);

INSERT INTO server_services (server_id, name) VALUES
    ((SELECT id FROM servers WHERE name='staging-app-02'), 'gunicorn.service'),
    ((SELECT id FROM servers WHERE name='staging-app-02'), 'postgresql.service'),
    ((SELECT id FROM servers WHERE name='staging-app-02'), 'ssh.service');

INSERT INTO server_processes (server_id, pid, "user", comm, args) VALUES
    ((SELECT id FROM servers WHERE name='staging-app-02'), 1700, 'app',      'gunicorn', 'gunicorn --bind 127.0.0.1:8080 app:wsgi'),
    ((SELECT id FROM servers WHERE name='staging-app-02'), 1800, 'postgres', 'postgres', '/usr/lib/postgresql/15/bin/postgres');

-- legacy-db-03: KEINE Snapshot-Daten (host_state_snapshot_at IS NULL).

-- ----------------------------------------------------------------------------
-- 4) Application-Groups (LLM-Source mock)
-- ----------------------------------------------------------------------------
INSERT INTO application_groups (label, explanation, pkg_name_exact, source, detected_at, group_kind) VALUES
    ('fixture-openssl',
     'OpenSSL cryptography library — CVE-Cluster mit hohem Impact',
     ARRAY['openssl', 'libssl3', 'libssl-dev'],
     'llm', now() - interval '30 days', 'os_package'),
    ('fixture-nginx',
     'nginx web server distribution',
     ARRAY['nginx', 'nginx-core', 'nginx-common'],
     'llm', now() - interval '20 days', 'os_package'),
    ('fixture-curl',
     'curl + libcurl utilities',
     ARRAY['curl', 'libcurl4'],
     'llm', now() - interval '15 days', 'os_package'),
    ('fixture-libxml2',
     'libxml2 XML parsing library',
     ARRAY['libxml2'],
     'llm', now() - interval '10 days', 'os_package'),
    ('fixture-glibc',
     'GNU C Library — system base package',
     ARRAY['libc6', 'libc-bin'],
     'llm', now() - interval '40 days', 'os_package');

-- ----------------------------------------------------------------------------
-- 5) KEV-Catalog (fuer is_kev=true Findings + KEV-Tile)
-- ----------------------------------------------------------------------------
INSERT INTO cisa_kev_catalog (cve_id, vendor_project, product, date_added, short_description) VALUES
    ('CVE-2024-3094',
     'xz', 'liblzma',
     '2024-03-30',
     'xz/liblzma 5.6.0/5.6.1 backdoor allowing remote code execution via ssh.'),
    ('CVE-2024-6387',
     'OpenSSH', 'OpenSSH server',
     '2024-07-01',
     'OpenSSH regreSSHion: signal handler race condition allowing unauthenticated RCE.');

-- ----------------------------------------------------------------------------
-- 6) EPSS-Scores fuer alle Fixture-CVEs
-- ----------------------------------------------------------------------------
INSERT INTO epss_scores (cve_id, epss_score, epss_percentile, updated_at) VALUES
    ('CVE-2024-3094',  0.94,  0.998, now() - interval '2 days'),
    ('CVE-2024-6387',  0.87,  0.995, now() - interval '2 days'),
    ('CVE-2024-2961',  0.42,  0.92,  now() - interval '2 days'),
    ('CVE-2024-4577',  0.78,  0.99,  now() - interval '2 days'),
    ('CVE-2024-7264',  0.15,  0.76,  now() - interval '2 days'),
    ('CVE-2024-8088',  0.08,  0.55,  now() - interval '2 days'),
    ('CVE-2024-25062', 0.05,  0.40,  now() - interval '2 days'),
    ('CVE-2024-34750', 0.21,  0.83,  now() - interval '2 days'),
    ('CVE-2023-99001', 0.01,  0.10,  now() - interval '2 days'),
    ('CVE-2023-99002', 0.02,  0.18,  now() - interval '2 days');

-- ----------------------------------------------------------------------------
-- 7) Findings — prod-edge-01 (vollausgestattetes Triage-Profil)
-- ----------------------------------------------------------------------------

-- ESCALATE Cluster (openssl) — 2 CVEs, eines KEV
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, description, cvss_v3_score, epss_score, epss_percentile,
    is_kev, kev_added_at, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band, risk_band_reason, risk_band_source, risk_band_computed_at,
    application_group_id, target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2024-6387',
     'openssh-server', '1:8.9p1-3ubuntu0.10', '1:8.9p1-3ubuntu0.11', 'critical',
     'regreSSHion: signal handler race condition in OpenSSH',
     'A signal handler race condition in OpenSSH server allows unauthenticated remote code execution as root on glibc-based Linux systems.',
     8.1, 0.87, 0.995, true, '2024-07-01', 'network',
     'open', now() - interval '14 days', now() - interval '2 hours',
     'escalate',
     'KEV-listed RCE in network-exposed SSH service. Patch immediately.',
     'llm', now() - interval '2 hours',
     (SELECT id FROM application_groups WHERE label='fixture-openssl'),
     'ubuntu', 'os-pkgs', 'vendor'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2024-2961',
     'libc6', '2.39-0ubuntu8.3', '2.39-0ubuntu8.4', 'high',
     'glibc iconv() heap overflow via ISO-2022-CN-EXT',
     'A buffer overflow in glibc iconv() conversion routines for ISO-2022-CN-EXT encoding can lead to remote code execution.',
     8.8, 0.42, 0.92, false, NULL, 'network',
     'open', now() - interval '20 days', now() - interval '2 hours',
     'escalate',
     'Heap overflow exploitable via PHP iconv() filter chains. Active exploitation in PHP web apps.',
     'llm', now() - interval '2 hours',
     (SELECT id FROM application_groups WHERE label='fixture-openssl'),
     'ubuntu', 'os-pkgs', 'vendor');

-- ACT Cluster (nginx) — 1 CVE
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, epss_score, epss_percentile,
    is_kev, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band, risk_band_reason, risk_band_source, risk_band_computed_at,
    application_group_id, target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2024-7347',
     'nginx', '1.24.0-2ubuntu7', '1.24.0-2ubuntu7.1', 'high',
     'nginx HTTP/3 NULL pointer dereference (DoS)',
     5.7, 0.05, 0.45, false, 'network',
     'open', now() - interval '7 days', now() - interval '2 hours',
     'act',
     'Network-exposed nginx but DoS-only — patch in normalem Wartungsfenster.',
     'llm', now() - interval '2 hours',
     (SELECT id FROM application_groups WHERE label='fixture-nginx'),
     'ubuntu', 'os-pkgs', 'vendor');

-- MITIGATE Cluster (curl) — 1 CVE, has_fix=false (kein fix verfuegbar -> mitigate)
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, epss_score, epss_percentile,
    is_kev, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band, risk_band_reason, risk_band_source, risk_band_computed_at,
    application_group_id, target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2024-7264',
     'libcurl4', '8.5.0-2ubuntu10.4', NULL, 'medium',
     'curl ASN.1 date parser out-of-bounds read',
     6.5, 0.15, 0.76, false, 'network',
     'open', now() - interval '5 days', now() - interval '2 hours',
     'mitigate',
     'No upstream fix yet. Disable curl usage for untrusted TLS certificates or use --insecure off.',
     'llm', now() - interval '2 hours',
     (SELECT id FROM application_groups WHERE label='fixture-curl'),
     'ubuntu', 'os-pkgs', 'vendor');

-- NOISE Findings (3x) — fuer "Acknowledge all noise"-Button-Test
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, epss_score, epss_percentile,
    is_kev, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band, risk_band_reason, risk_band_source, risk_band_computed_at,
    target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2023-99001',
     'libxslt1.1', '1.1.35-1ubuntu0.1', '1.1.35-1ubuntu0.2', 'low',
     'libxslt XPath expression evaluation memory leak',
     3.3, 0.01, 0.10, false, 'local',
     'open', now() - interval '50 days', now() - interval '2 hours',
     'noise',
     'Local-only memory leak. Library not used by network-exposed services on this host.',
     'llm', now() - interval '2 hours',
     'ubuntu', 'os-pkgs', 'vendor'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2023-99002',
     'libtiff6', '4.5.1+git230720-4ubuntu2', '4.5.1+git230720-4ubuntu2.1', 'low',
     'libtiff DoS via crafted TIFF file',
     5.5, 0.02, 0.18, false, 'local',
     'open', now() - interval '45 days', now() - interval '2 hours',
     'noise',
     'Library only loaded by image-processing tools, not in network path.',
     'llm', now() - interval '2 hours',
     'ubuntu', 'os-pkgs', 'vendor'),
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2024-25062',
     'libxml2', '2.9.14+dfsg-1.3ubuntu0.4', '2.9.14+dfsg-1.3ubuntu0.5', 'low',
     'libxml2 use-after-free in XPointer',
     5.5, 0.05, 0.40, false, 'local',
     'open', now() - interval '30 days', now() - interval '2 hours',
     'noise',
     'XPointer feature not used by any installed application on this host.',
     'llm', now() - interval '2 hours',
     'ubuntu', 'os-pkgs', 'vendor');

-- Ein RESOLVED Finding (zaehlt in total_findings_count, nicht in open)
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, is_kev, attack_vector,
    status, first_seen_at, last_seen_at, resolved_at,
    risk_band, target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     'vulnerability', 'os-pkgs', 'CVE-2024-OLD-HIGH',
     'openssl', '3.0.13-0ubuntu3.3', '3.0.13-0ubuntu3.4', 'high',
     'OpenSSL old cert chain parsing CVE (already patched on this host)',
     7.5, false, 'network',
     'resolved', now() - interval '40 days', now() - interval '35 days', now() - interval '30 days',
     'act', 'ubuntu', 'os-pkgs', 'vendor');

-- ----------------------------------------------------------------------------
-- 8) Findings — staging-app-02 (PENDING + ACT)
-- ----------------------------------------------------------------------------

-- ACT-band libxml2 finding
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, epss_score, epss_percentile,
    is_kev, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band, risk_band_reason, risk_band_source, risk_band_computed_at,
    application_group_id, target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='staging-app-02'),
     'vulnerability', 'os-pkgs', 'CVE-2024-34459',
     'libxml2', '2.9.14+dfsg-1.3+deb12u1', '2.9.14+dfsg-1.3+deb12u2', 'high',
     'libxml2 use-after-free in XML schema validation',
     7.1, 0.12, 0.70, false, 'network',
     'open', now() - interval '8 days', now() - interval '4 hours',
     'act',
     'Used by gunicorn application for XML request parsing. Patch in next deploy.',
     'llm', now() - interval '4 hours',
     (SELECT id FROM application_groups WHERE label='fixture-libxml2'),
     'debian', 'os-pkgs', 'vendor');

-- PENDING Findings (kein application_group_id, kein risk_band_reason)
-- Diese landen im pending-grouping-block.
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, is_kev, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band,
    target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='staging-app-02'),
     'vulnerability', 'lang-pkgs', 'CVE-2024-PEND-001',
     'flask', '3.0.0', '3.0.3', 'medium',
     'Flask session signing weakness',
     5.4, false, 'network',
     'open', now() - interval '3 days', now() - interval '4 hours',
     'act', 'requirements.txt', 'lang-pkgs', 'vendor'),
    ((SELECT id FROM servers WHERE name='staging-app-02'),
     'vulnerability', 'lang-pkgs', 'CVE-2024-PEND-002',
     'requests', '2.31.0', '2.32.0', 'medium',
     'requests cookie leakage on redirect',
     5.3, false, 'network',
     'open', now() - interval '2 days', now() - interval '4 hours',
     'mitigate', 'requirements.txt', 'lang-pkgs', 'vendor');

-- ----------------------------------------------------------------------------
-- 9) Findings — legacy-db-03 (nur monitor/noise)
-- ----------------------------------------------------------------------------
INSERT INTO findings (
    server_id, finding_type, finding_class, identifier_key,
    package_name, installed_version, fixed_version, severity,
    title, cvss_v3_score, is_kev, attack_vector,
    status, first_seen_at, last_seen_at,
    risk_band, risk_band_reason, risk_band_source, risk_band_computed_at,
    application_group_id, target_path, result_type, severity_source
) VALUES
    ((SELECT id FROM servers WHERE name='legacy-db-03'),
     'vulnerability', 'os-pkgs', 'CVE-2024-8088',
     'libc6', '2.31-0ubuntu9.16', '2.31-0ubuntu9.17', 'medium',
     'glibc minor memory safety in regex compiler',
     4.7, false, 'local', 'open',
     now() - interval '20 days', now() - interval '5 days',
     'monitor',
     'Local-only impact on internal DB host. No attacker path.',
     'llm', now() - interval '5 days',
     (SELECT id FROM application_groups WHERE label='fixture-glibc'),
     'ubuntu', 'os-pkgs', 'vendor'),
    ((SELECT id FROM servers WHERE name='legacy-db-03'),
     'vulnerability', 'os-pkgs', 'CVE-2024-NOISE-DB',
     'logrotate', '3.14.0-4ubuntu3', '3.14.0-4ubuntu3.1', 'low',
     'logrotate state file race condition',
     3.3, false, 'local',
     'open', now() - interval '60 days', now() - interval '5 days',
     'noise',
     'Local privilege escalation only — requires existing local user.',
     'llm', now() - interval '5 days',
     NULL, 'ubuntu', 'os-pkgs', 'vendor');

-- ----------------------------------------------------------------------------
-- 10) Application-Group-Evaluations (Operator-Workflows)
-- ----------------------------------------------------------------------------
-- ESCALATE: openssl auf prod-edge-01 (action_type=patch -> ESCALATE bundle patchen)
INSERT INTO application_group_evaluations (
    group_id, server_id, risk_band, risk_band_reason, risk_band_source,
    risk_band_computed_at, worst_finding_id, action_type
) VALUES (
    (SELECT id FROM application_groups WHERE label='fixture-openssl'),
    (SELECT id FROM servers WHERE name='prod-edge-01'),
    'escalate',
    'OpenSSH KEV-RCE auf network-exposed Port 22. Sofort patchen.',
    'llm', now() - interval '2 hours',
    (SELECT id FROM findings WHERE identifier_key='CVE-2024-6387' AND server_id=(SELECT id FROM servers WHERE name='prod-edge-01')),
    'patch');

-- ACT: nginx auf prod-edge-01
INSERT INTO application_group_evaluations (
    group_id, server_id, risk_band, risk_band_reason, risk_band_source,
    risk_band_computed_at, worst_finding_id, action_type
) VALUES (
    (SELECT id FROM application_groups WHERE label='fixture-nginx'),
    (SELECT id FROM servers WHERE name='prod-edge-01'),
    'act',
    'nginx HTTP/3 DoS — Patch im naechsten Wartungsfenster.',
    'llm', now() - interval '2 hours',
    (SELECT id FROM findings WHERE identifier_key='CVE-2024-7347' AND server_id=(SELECT id FROM servers WHERE name='prod-edge-01')),
    'patch');

-- MITIGATE: curl auf prod-edge-01
INSERT INTO application_group_evaluations (
    group_id, server_id, risk_band, risk_band_reason, risk_band_source,
    risk_band_computed_at, worst_finding_id, action_type
) VALUES (
    (SELECT id FROM application_groups WHERE label='fixture-curl'),
    (SELECT id FROM servers WHERE name='prod-edge-01'),
    'mitigate',
    'Kein Upstream-Patch. curl --insecure deaktivieren / cert-pinning aktivieren.',
    'llm', now() - interval '2 hours',
    (SELECT id FROM findings WHERE identifier_key='CVE-2024-7264' AND server_id=(SELECT id FROM servers WHERE name='prod-edge-01')),
    'mitigate');

-- ACT: libxml2 auf staging-app-02
INSERT INTO application_group_evaluations (
    group_id, server_id, risk_band, risk_band_reason, risk_band_source,
    risk_band_computed_at, worst_finding_id, action_type
) VALUES (
    (SELECT id FROM application_groups WHERE label='fixture-libxml2'),
    (SELECT id FROM servers WHERE name='staging-app-02'),
    'act',
    'XML-Parser im Request-Pfad. Patch zum naechsten Deploy.',
    'llm', now() - interval '4 hours',
    (SELECT id FROM findings WHERE identifier_key='CVE-2024-34459' AND server_id=(SELECT id FROM servers WHERE name='staging-app-02')),
    'patch');

-- monitor: glibc auf legacy-db-03
INSERT INTO application_group_evaluations (
    group_id, server_id, risk_band, risk_band_reason, risk_band_source,
    risk_band_computed_at, worst_finding_id, action_type
) VALUES (
    (SELECT id FROM application_groups WHERE label='fixture-glibc'),
    (SELECT id FROM servers WHERE name='legacy-db-03'),
    'monitor',
    'Internal DB-Host, kein attacker-Pfad zu glibc-Codepath.',
    'llm', now() - interval '5 days',
    (SELECT id FROM findings WHERE identifier_key='CVE-2024-8088' AND server_id=(SELECT id FROM servers WHERE name='legacy-db-03')),
    'watch');

-- ----------------------------------------------------------------------------
-- 11) Scan-History (fuer Heartbeat-Aggregation)
-- ----------------------------------------------------------------------------
-- Heartbeat-Sektion liest aus heartbeat_aggregation, das sich aus scan-events
-- plus dominant-risk-band-per-day errechnet. Wir streuen Scans ueber 30 Tage,
-- damit alle vier Bands (escalate/act/nominal/unknown) im Strip vorkommen.
INSERT INTO scans (server_id, received_at, agent_version, trivy_scanner_version, trivy_db_version, os_family)
SELECT
    s.id,
    -- Scans alle 24h zurueck, leichtes Jitter
    (date_trunc('day', now()) - (d || ' days')::interval) + (random() * interval '6 hours'),
    s.agent_version,
    s.trivy_version,
    s.trivy_db_version,
    s.os_family
FROM servers s
CROSS JOIN generate_series(1, 30) AS d
WHERE s.name IN ('prod-edge-01', 'staging-app-02');
-- legacy-db-03: scans nur sporadisch (Tag 2, 7, 15, 25) -> Heartbeat zeigt
-- UNKNOWN-Luecken
INSERT INTO scans (server_id, received_at, agent_version, trivy_scanner_version, trivy_db_version, os_family)
SELECT
    (SELECT id FROM servers WHERE name='legacy-db-03'),
    (date_trunc('day', now()) - (d || ' days')::interval) + interval '3 hours',
    '0.2.5', '0.50.0', '2026.05.14.0', 'ubuntu'
FROM unnest(ARRAY[2, 7, 15, 25]) AS d;

-- ----------------------------------------------------------------------------
-- 12) Server-Tags
-- ----------------------------------------------------------------------------
-- Erstmal vorhandene Tags wiederverwenden, fehlende anlegen.
INSERT INTO tags (name) VALUES ('prod'), ('edge'), ('staging'), ('legacy')
ON CONFLICT (name) DO NOTHING;

INSERT INTO server_tags (server_id, tag_id) VALUES
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     (SELECT id FROM tags WHERE name='prod')),
    ((SELECT id FROM servers WHERE name='prod-edge-01'),
     (SELECT id FROM tags WHERE name='edge')),
    ((SELECT id FROM servers WHERE name='staging-app-02'),
     (SELECT id FROM tags WHERE name='staging')),
    ((SELECT id FROM servers WHERE name='legacy-db-03'),
     (SELECT id FROM tags WHERE name='legacy'));

-- ----------------------------------------------------------------------------
-- 13) Verifizierung — Counts pro Server
-- ----------------------------------------------------------------------------
\echo '--- Fixtures geladen, Counts pro Test-Server: ---'
SELECT
    s.name,
    s.last_scan_at::timestamp(0) AS last_scan,
    s.host_state_snapshot_at::timestamp(0) AS snapshot,
    s.agent_version,
    (SELECT count(*) FROM findings f WHERE f.server_id = s.id AND f.status = 'open') AS open_findings,
    (SELECT count(*) FROM findings f WHERE f.server_id = s.id) AS total_findings,
    (SELECT count(*) FROM findings f WHERE f.server_id = s.id AND f.is_kev = true) AS kev,
    (SELECT count(*) FROM findings f WHERE f.server_id = s.id AND f.risk_band = 'noise' AND f.status='open') AS noise,
    (SELECT count(*) FROM server_listeners l WHERE l.server_id = s.id) AS listeners,
    (SELECT count(*) FROM server_services sv WHERE sv.server_id = s.id) AS services,
    (SELECT count(*) FROM application_group_evaluations e WHERE e.server_id = s.id) AS evaluations
FROM servers s
WHERE s.name IN ('prod-edge-01', 'staging-app-02', 'legacy-db-03')
ORDER BY s.name;

COMMIT;

\echo ''
\echo 'Detail-URLs:'
\echo '  http://localhost:8000/servers/<id>'
\echo '  ergo z.B. fuer prod-edge-01:'
SELECT format('  http://localhost:8000/servers/%s  (%s)', id, name) AS url
FROM servers
WHERE name IN ('prod-edge-01', 'staging-app-02', 'legacy-db-03')
ORDER BY name;
