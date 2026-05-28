/* Fathometer — Findings page mock data.
   Cross-fleet (server × application_group) buckets, junction Risk-Band model.
   Pending-Bucket is cross-server, sorts last. */

window.FINDINGS_DATA = (() => {
  // ── Deterministic PRNG ─────────────────────────────────────
  function rng(seedStr) {
    let h = 1779033703 ^ seedStr.length;
    for (let i = 0; i < seedStr.length; i++) {
      h = Math.imul(h ^ seedStr.charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }
    let s = h >>> 0;
    return () => {
      s |= 0; s = (s + 0x6D2B79F5) | 0;
      let t = Math.imul(s ^ (s >>> 15), 1 | s);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // ── Filter option lists ────────────────────────────────────
  const TAGS = ['prod', 'staging', 'edge', 'db', 'ci', 'k8s', 'public-exposed', 'pci'];
  const APPLICATION_GROUPS = [
    'linux-modules-5.15.0-177-generic',
    'linux-modules-extra-5.15.0-177-generic',
    'openssl-libs',
    'libcurl4',
    'libxml2',
    'glibc',
    'systemd',
    'docker.io',
    'nginx-core',
    'postgresql-15',
    'php8.1-fpm',
    'go-stdlib',
  ];

  // ── Finding templates pool (we recycle these into rows) ────
  const CVE_POOL = [
    { cve: 'CVE-2026-31431', kev: true,  title: 'kernel: out-of-bounds write in n_tty_receive_…',         pkg: 'linux-modules-5.15.0-177-generic@Ubuntu', from: '5.15.0-177', to: '5.15.0-178',          epss: '82.4%', cvss: '8.8', severity: 'HIGH',
      ai: 'ssh on 0.0.0.0:22 PUBLIC-EXPOSED; kernel modules reachable via network traffic; KEV mit aktivem Exploit, Patch in 5.15.0-178 verfügbar.' },
    { cve: 'CVE-2024-5535',  kev: false, title: 'openssl: SSL_select_next_proto buffer overread',          pkg: 'openssl-libs@Ubuntu',  from: '3.0.2-0ubuntu1.18', to: '3.0.2-0ubuntu1.19',     epss: '54.2%', cvss: '9.1', severity: 'CRITICAL',
      ai: 'TLS auf :443 PUBLIC-EXPOSED; nginx + curl gegen vulnerable libssl gelinkt; OOB-Read über speziell konstruierte EC-Zertifikate. Patch verfügbar.' },
    { cve: 'CVE-2024-9143',  kev: false, title: 'openssl: out-of-bounds read in BN_GF2m_pol…',             pkg: 'openssl-libs@Ubuntu',  from: '3.0.2-0ubuntu1.18', to: '3.0.2-0ubuntu1.19',     epss: '8.1%',  cvss: '7.5', severity: 'HIGH',
      ai: 'Affected nur bei expliziten GF(2^m) ECs; auf diesem Host nicht in der TLS-Config aktiv, aber via nginx-stream weiterhin erreichbar.' },
    { cve: 'CVE-2024-7264',  kev: false, title: 'curl: ASN.1 parser stack overflow on malformed cert',     pkg: 'libcurl4@Ubuntu',      from: '7.81.0-1ubuntu1.16', to: '7.81.0-1ubuntu1.18',  epss: '4.1%',  cvss: '7.5', severity: 'HIGH',
      ai: 'curl wird vom cron job ext-feeds täglich gegen externe URLs aufgerufen; theoretisch ausnutzbar, fix in 1.18 bereit.' },
    { cve: 'CVE-2024-25062', kev: false, title: 'libxml2: use-after-free in xmlValidatePopElement',        pkg: 'libxml2@Ubuntu',       from: '2.9.13+dfsg-1ubuntu0.4', to: '2.9.13+dfsg-1ubuntu0.6', epss: '1.8%', cvss: '6.5', severity: 'MEDIUM',
      ai: 'libxml2 von nginx-mod-http-xslt beim Start geladen; keine externen XML-Inputs derzeit aktiv.' },
    { cve: 'CVE-2024-2961',  kev: false, title: 'glibc: iconv() buffer overflow ISO-2022-CN-EXT',          pkg: 'glibc@Ubuntu',         from: '2.35-0ubuntu3.7', to: '2.35-0ubuntu3.8',         epss: '12.3%', cvss: '7.4', severity: 'HIGH',
      ai: 'glibc-iconv im PHP-Stack erreicht; verifizierter Defer-Override 14 Tage abgelaufen.' },
    { cve: 'CVE-2024-2398',  kev: false, title: 'curl: HTTP/2 push streams memory leak',                   pkg: 'libcurl4@Ubuntu',      from: '7.81.0-1ubuntu1.16', to: '7.81.0-1ubuntu1.18',  epss: '2.4%',  cvss: '5.9', severity: 'MEDIUM',
      ai: 'HTTP/2-push beim Outbound-Fetch nicht genutzt; Patch-Zug deckt mit ab.' },
    { cve: 'CVE-2024-37372', kev: false, title: 'openssl: timing oracle on RSA decrypt',                   pkg: 'openssl-libs@Ubuntu',  from: '3.0.2-0ubuntu1.18', to: '3.0.2-0ubuntu1.19',    epss: '0.9%',  cvss: '5.3', severity: 'MEDIUM',
      ai: 'Timing-oracle relevant nur für lokale Threat-Modelle; Patch ohnehin im Zug.' },
    { cve: 'CVE-2023-50387', kev: false, title: 'systemd-resolved: DNSSEC validation NSEC bypass',         pkg: 'systemd@Ubuntu',       from: '249.11-0ubuntu3.12', to: 'unfixed',              epss: '0.7%',  cvss: '5.0', severity: 'MEDIUM',
      ai: 'Kein Upstream-Fix; mitigation: DNSSEC=allow-downgrade in resolved.conf, lokal angewendet.' },
    { cve: 'CVE-2024-12345', kev: false, title: 'docker-proxy: improper iptables cleanup',                 pkg: 'docker.io@Ubuntu',     from: '24.0.7-0ubuntu1', to: 'unfixed',                  epss: '0.4%',  cvss: '4.4', severity: 'MEDIUM',
      ai: 'Workaround: explicit iptables -F docker am Restart. Skript in /etc/systemd/system/docker.service.d/ aktiv.' },
    { cve: 'CVE-2023-44487', kev: true,  title: 'nghttp2: HTTP/2 Rapid-Reset DDoS amplifier',              pkg: 'nginx-core@Ubuntu',    from: '1.18.0-6ubuntu14.4', to: '1.18.0-6ubuntu14.5',   epss: '78.6%', cvss: '7.5', severity: 'HIGH',
      ai: 'KEV — Rapid-Reset über HTTP/2 auf :443 erreichbar; rate-limit-Patch in 14.5 enthalten.' },
    { cve: 'CVE-2024-6387',  kev: true,  title: 'openssh: regreSSHion signal-handler race (RCE)',          pkg: 'openssh-server@Ubuntu',from: '8.9p1-3ubuntu0.7',  to: '8.9p1-3ubuntu0.10',     epss: '91.2%', cvss: '8.1', severity: 'HIGH',
      ai: 'sshd auf 0.0.0.0:22 PUBLIC-EXPOSED; pre-auth RCE über race-condition. KEV — patchen, jetzt.' },
    { cve: 'CVE-2024-3094',  kev: false, title: 'xz-utils: malicious build-time backdoor (sshd)',          pkg: 'xz-utils@Ubuntu',      from: '5.2.5-2ubuntu1',     to: '5.2.5-2ubuntu1.1',      epss: '6.7%',  cvss: '10.0', severity: 'CRITICAL',
      ai: 'Affected liblzma nicht auf diesem Host installiert — Trivy-Match falsch-positiv für 5.2.5-2ubuntu1. Bestätigt benign.' },
    { cve: 'CVE-2024-0727',  kev: false, title: 'openssl: NULL deref on PKCS12 parse',                     pkg: 'openssl-libs@Ubuntu',  from: '3.0.2-0ubuntu1.18',  to: '3.0.2-0ubuntu1.19',     epss: '0.3%',  cvss: '5.5', severity: 'MEDIUM',
      ai: 'Kein Endpoint nimmt PKCS12-Bytes von außen entgegen — Patch im Zug, Risk gering.' },
    { cve: 'CVE-2024-26581', kev: false, title: 'linux: netfilter nft_set_rbtree skip element loop',       pkg: 'linux-image-5.15.0-177-generic@Ubuntu', from: '5.15.0-177', to: '5.15.0-178',  epss: '2.1%',  cvss: '5.5', severity: 'MEDIUM',
      ai: 'Erreichbar nur via local-priv; angreifbar wenn jemand bereits einen Shell-User hat. Patch-Zug genügt.' },
    { cve: 'CVE-2024-1086',  kev: true,  title: 'linux: nf_tables UAF (LPE to root)',                      pkg: 'linux-image-5.15.0-177-generic@Ubuntu', from: '5.15.0-177', to: '5.15.0-178',  epss: '88.4%', cvss: '7.8', severity: 'HIGH',
      ai: 'KEV — local-priv exploit kursiert öffentlich; mitigieren via unprivileged_userns_clone=0 bis Patch eingespielt.' },
    { cve: 'CVE-2024-21626', kev: false, title: 'runc: container escape via /proc/self/fd file-descriptor',pkg: 'docker.io@Ubuntu',     from: '24.0.7-0ubuntu1',     to: '24.0.9-0ubuntu1',     epss: '14.8%', cvss: '8.6', severity: 'HIGH',
      ai: 'Container-escape via runc; mitigation: --no-new-privileges + AppArmor profile, Patch in 24.0.9.' },
    { cve: 'CVE-2024-45490', kev: false, title: 'libexpat: XML_ParseBuffer integer overflow',              pkg: 'libexpat1@Ubuntu',     from: '2.4.7-1ubuntu0.3',    to: '2.4.7-1ubuntu0.4',    epss: '1.2%',  cvss: '6.5', severity: 'MEDIUM',
      ai: 'libexpat indirekt via libxml2; XML-Inputs auf diesem Pfad nicht aktiv.' },
    { cve: 'CVE-2024-28085', kev: false, title: 'util-linux: wall(1) command injection via escape seqs',   pkg: 'util-linux@Ubuntu',    from: '2.37.2-4ubuntu3',     to: '2.37.2-4ubuntu3.4',   epss: '0.2%',  cvss: '3.3', severity: 'LOW',
      ai: 'wall(1) lokal von messaging-Konsolen — nicht in Skripten verwendet. Low-Prio.' },
    { cve: 'CVE-2024-22195', kev: false, title: 'jinja2: xmlattr filter accepts attacker keys',            pkg: 'python3-jinja2@Ubuntu',from: '3.0.3-1',             to: '3.0.3-1ubuntu0.1',    epss: '0.5%',  cvss: '4.7', severity: 'MEDIUM',
      ai: 'jinja2 von Ansible-Playbooks genutzt; xmlattr-Filter nicht in production Templates aufgerufen.' },
    { cve: 'CVE-2024-23334', kev: false, title: 'aiohttp: path traversal in static file routes',           pkg: 'python3-aiohttp@Ubuntu',from: '3.8.1-1ubuntu0.3',    to: '3.8.1-1ubuntu0.5',   epss: '7.4%',  cvss: '5.9', severity: 'MEDIUM',
      ai: 'aiohttp serviert keine statischen Files in diesem Deployment — nur als REST-Client geladen.' },
    { cve: 'CVE-2023-39325', kev: false, title: 'go: net/http HTTP/2 rapid-reset DoS',                     pkg: 'go-stdlib',            from: '1.20.10',             to: '1.20.11',             epss: '52.1%', cvss: '7.5', severity: 'HIGH',
      ai: 'Wir kompilieren mit go 1.20.10; alle services auf :443 hinter haproxy mit timeout-rules — Patch trotzdem im nächsten Build.' },
    { cve: 'CVE-2022-1996',  kev: false, title: 'go-restful: incorrect handling of allowed-origins',      pkg: 'go-restful',           from: '2.15.0',              to: '2.16.0',              epss: '3.1%',  cvss: '5.3', severity: 'MEDIUM',
      ai: 'Wir nutzen go-restful nicht — Trivy false-match auf go.sum-residual. Sollte ge-ack-t werden.' },
    { cve: 'CVE-2024-0397',  kev: false, title: 'python3: ssl-default-context not honored on macOS',      pkg: 'python3@Ubuntu',       from: '3.10.6-1~22.04',      to: '3.10.6-1~22.04.6',    epss: '0.1%',  cvss: '3.4', severity: 'LOW',
      ai: 'macOS-only-Pfad; auf aarch64-Linux nicht aktiv.' },
    { cve: 'CVE-2024-34062', kev: false, title: 'tqdm: arbitrary code execution via crafted format string',pkg: 'python3-tqdm@Ubuntu',  from: '4.64.0-1',            to: '4.64.0-1ubuntu0.1',   epss: '0.3%',  cvss: '6.6', severity: 'MEDIUM',
      ai: 'tqdm nur in CI als progress-bar; Format-Strings hardcoded — nicht angreifbar.' },
  ];

  // ── Bucket assembly ────────────────────────────────────────
  // 12 buckets total: 2 escalate, 3 act, 2 mitigate, 2 monitor, 2 noise + 1 pending.
  // ~150 findings spread across them. Bucket order on render: escalate → act → mitigate
  // → pending → monitor → noise, with pending always last.

  function pick(pool, n, seed) {
    const r = rng(seed);
    const out = [];
    // Recycle pool with stable CVE-suffix mutation so we never repeat a CVE id in a bucket.
    for (let i = 0; i < n; i++) {
      const base = pool[i % pool.length];
      const yr = 2024 + Math.floor(r() * 3);
      const num = 10000 + Math.floor(r() * 89999);
      const suffix = i < pool.length ? '' : `-r${Math.floor(r() * 999)}`;
      out.push({
        ...base,
        cve: i < pool.length ? base.cve : `CVE-${yr}-${num}`,
        firstSeen: `vor ${1 + Math.floor(r() * 28)}T`,
        suffix,
      });
    }
    return out;
  }

  // Sort within bucket: KEV desc → EPSS desc → CVSS desc → first_seen asc.
  function sortBucket(items) {
    return [...items].sort((a, b) => {
      if (a.kev !== b.kev) return b.kev - a.kev;
      const ea = parseFloat(a.epss);
      const eb = parseFloat(b.epss);
      if (eb !== ea) return eb - ea;
      const ca = parseFloat(a.cvss);
      const cb = parseFloat(b.cvss);
      if (cb !== ca) return cb - ca;
      const fa = parseInt(a.firstSeen.match(/\d+/)[0], 10);
      const fb = parseInt(b.firstSeen.match(/\d+/)[0], 10);
      return fa - fb;
    });
  }

  const BUCKETS = [
    // ── ESCALATE ──
    {
      id: 'b-escalate-edge-cy-04-kernel',
      band: 'escalate',
      server: 'edge-cy-04',
      group: 'linux-modules-5.15.0-177-generic',
      findings: sortBucket(pick(CVE_POOL, 14, 'esc-1')),
    },
    {
      id: 'b-escalate-rke2-sv-0-openssh',
      band: 'escalate',
      server: 'rke2-sv-0',
      group: 'openssh-server',
      findings: sortBucket(pick(CVE_POOL, 9, 'esc-2')),
    },
    // ── ACT ──
    {
      id: 'b-act-db-fsn1-01-openssl',
      band: 'act',
      server: 'db-fsn1-01',
      group: 'openssl-libs',
      findings: sortBucket(pick(CVE_POOL, 11, 'act-1')),
    },
    {
      id: 'b-act-edge-cy-01-nginx',
      band: 'act',
      server: 'edge-cy-01',
      group: 'nginx-core',
      findings: sortBucket(pick(CVE_POOL, 17, 'act-2')),
    },
    {
      id: 'b-act-rke2-sv-2-docker',
      band: 'act',
      server: 'rke2-sv-2',
      group: 'docker.io',
      findings: sortBucket(pick(CVE_POOL, 8, 'act-3')),
    },
    // ── MITIGATE ──
    {
      id: 'b-mitigate-mail-fsn-01-systemd',
      band: 'mitigate',
      server: 'mail-fsn-01',
      group: 'systemd',
      findings: sortBucket(pick(CVE_POOL, 6, 'mit-1')),
    },
    {
      id: 'b-mitigate-backup-bx-01-glibc',
      band: 'mitigate',
      server: 'backup-bx-01',
      group: 'glibc',
      findings: sortBucket(pick(CVE_POOL, 13, 'mit-2')),
    },
    // ── MONITOR ──
    {
      id: 'b-monitor-gitlab-runner-01-libxml2',
      band: 'monitor',
      server: 'gitlab-runner-01',
      group: 'libxml2',
      findings: sortBucket(pick(CVE_POOL, 21, 'mon-1')),
    },
    {
      id: 'b-monitor-rke2-cp-0-go-stdlib',
      band: 'monitor',
      server: 'rke2-cp-0',
      group: 'go-stdlib',
      findings: sortBucket(pick(CVE_POOL, 12, 'mon-2')),
    },
    // ── NOISE ──
    {
      id: 'b-noise-prom-01-python3',
      band: 'noise',
      server: 'prom-01',
      group: 'python3-stdlib',
      findings: sortBucket(pick(CVE_POOL, 19, 'noi-1')),
    },
    {
      id: 'b-noise-log-loki-01-util-linux',
      band: 'noise',
      server: 'log-loki-01',
      group: 'util-linux',
      findings: sortBucket(pick(CVE_POOL, 14, 'noi-2')),
    },
  ];

  // ── Pending-Bucket (cross-server, no group) ───────────────
  // 4 findings across 2 servers — group label rendered as "— ohne Group —".
  const PENDING_BUCKET = {
    id: 'b-pending',
    band: 'pending',
    server: null,                    // cross-server
    group: null,                     // "— ohne Group —"
    findings: [
      { ...CVE_POOL[10], server: 'edge-cy-04',       firstSeen: 'vor 2T' },
      { ...CVE_POOL[15], server: 'edge-cy-04',       firstSeen: 'vor 4T' },
      { ...CVE_POOL[3],  server: 'gitlab-runner-02', firstSeen: 'vor 6T' },
      { ...CVE_POOL[20], server: 'gitlab-runner-02', firstSeen: 'vor 9T' },
    ],
  };

  // ── Aggregates for header counter / empty-state ────────────
  const totalBuckets = BUCKETS.length + 1; // + pending
  const totalFindings = BUCKETS.reduce((a, b) => a + b.findings.length, 0) + PENDING_BUCKET.findings.length;
  const totalServers = 20;
  const fleetFindings = 2317;

  return {
    TAGS,
    APPLICATION_GROUPS,
    BUCKETS,
    PENDING_BUCKET,
    AGGREGATES: { totalBuckets, totalFindings, totalServers, fleetFindings },
  };
})();
