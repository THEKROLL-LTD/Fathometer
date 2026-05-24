/* Fathometer — Server-detail mock data for srv-prod-edge-01.
   Shape mirrors docs/design/data.js: deterministic, no shimmer between renders. */

window.SERVER_DETAIL = (() => {
  // Deterministic PRNG (mulberry32) seeded per hostname — same trick as data.js.
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

  const HOST = {
    host:    'srv-prod-edge-01',
    os:      'Ubuntu 22.04.5 LTS',
    kernel:  '5.15.0-177-generic',
    arch:    'aarch64',
    lastScan: 'vor 11m',
    trivyDb:  'vor 12 Tagen',
    expectedInterval: '24h',
    trivyStale: true,
    actionPending: 12,
  };

  // ── Listeners (process · addr:port · proto · exposed) ─────────
  const LISTENERS = [
    { process: 'sshd',         addr: '0.0.0.0:22',   proto: 'tcp', exposed: true  },
    { process: 'nginx',        addr: '0.0.0.0:443',  proto: 'tcp', exposed: true  },
    { process: 'nginx',        addr: '0.0.0.0:80',   proto: 'tcp', exposed: true  },
    { process: 'haproxy',      addr: '0.0.0.0:8443', proto: 'tcp', exposed: true  },
    { process: 'coturn',       addr: '0.0.0.0:3478', proto: 'udp', exposed: true  },
    { process: 'node_exporter',addr: '127.0.0.1:9100',proto:'tcp', exposed: false },
    { process: 'postgres',     addr: '127.0.0.1:5432',proto:'tcp', exposed: false },
    { process: 'systemd-resolved', addr: '127.0.0.53:53', proto: 'udp', exposed: false },
    { process: 'docker-proxy', addr: '0.0.0.0:8080', proto: 'tcp', exposed: true  },
  ];

  // ── Active services (systemd units) ───────────────────────────
  const SERVICES = [
    'ssh.service', 'nginx.service', 'postgresql.service',
    'node_exporter.service', 'coturn.service', 'cron.service',
    'unattended-upgrades.service', 'snapd.service',
    'systemd-resolved.service', 'systemd-timesyncd.service',
    'rsyslog.service', 'dbus.service', 'containerd.service', 'docker.service',
  ];

  // ── Heartbeat: 30 days, 4 states ──────────────────────────────
  // States per brief: unknown / nominal / act / escalate
  function heartbeat() {
    const r = rng('srv-prod-edge-01-heartbeat');
    const out = new Array(30).fill('nominal');
    // Default = nominal. Sprinkle in 4-5 unknowns (missed/late scans early),
    // 6-8 acts (high-load patch days), and 4-5 escalates (cyan) clustered
    // toward the present — exactly the pattern that produces "Action needed".
    for (let i = 0; i < 30; i++) {
      const v = r();
      if (i < 4 && v < 0.55)        out[i] = 'unknown';
      else if (v < 0.20)            out[i] = 'act';
      else if (v < 0.05)            out[i] = 'escalate';
    }
    // Force 4 cyan escalates: today + a recent cluster.
    [29, 28, 26, 23, 21, 18].forEach((i) => { if (r() < 0.7) out[i] = 'escalate'; });
    [27, 25, 24, 20, 19, 17, 15, 13].forEach((i) => { if (r() < 0.55) out[i] = 'act'; });
    out[29] = 'escalate';
    out[28] = 'escalate';
    return out;
  }

  // ── Severity trend: 30 days of stacked totals ─────────────────
  function severityTrend() {
    const r = rng('srv-prod-edge-01-sev');
    const out = [];
    for (let i = 0; i < 30; i++) {
      const base = 6 + Math.floor(r() * 8);
      const critical = r() < 0.45 ? 0 : Math.floor(r() * 2);  // sparse
      const high     = 1 + Math.floor(r() * 4);
      const medium   = base + Math.floor(r() * 6);
      const low      = 2 + Math.floor(r() * 4);
      out.push({ critical, high, medium, low });
    }
    // Today's bar matches HEADER_STATS totals roughly
    out[29] = { critical: 3, high: 8, medium: 1, low: 0 };
    return out;
  }

  // ── HeaderStats: open / total + per-severity sparklines ───────
  const HEADER_STATS = {
    open: 12,
    total: 319,
    delta: 3,                    // "+3 since yesterday"
    deltaLabel: '+3 seit gestern',
    tiles: [
      // 7-day sparkline. KEV + Critical wear cyan only when non-zero.
      { key: 'kev',      label: 'KEV',      n: 1, spark: [0, 0, 0, 1, 0, 1, 1] },
      { key: 'critical', label: 'CRITICAL', n: 3, spark: [1, 2, 1, 3, 2, 3, 3] },
      { key: 'high',     label: 'HIGH',     n: 8, spark: [5, 6, 6, 7, 8, 7, 8] },
      { key: 'medium',   label: 'MEDIUM',   n: 1, spark: [0, 1, 0, 2, 1, 0, 1] },
    ],
  };

  // ── Workflows ("Was zu tun ist") ──────────────────────────────
  const WORKFLOWS = [
    {
      phase: 'ESCALATE',
      title: 'Distro patchen',
      subline: 'linux-modules-5.15.0-177-generic, linux-modules-extra-5.15.0-177-generic',
      rows: [
        {
          group: 'linux-modules-5.15.0-177-generic',
          worst: 'CVE-2026-31431',
          reason: 'ssh on 0.0.0.0:22 PUBLIC-EXPOSED; kernel modules reachable via network traffic; CVE-2026-31431 high KEV active exploit, fix available',
        },
        {
          group: 'linux-modules-extra-5.15.0-177-generic',
          worst: 'CVE-2026-31431',
          reason: 'kernel-modules NO-LISTENER upgraded via PUBLIC-EXPOSED services (ssh, haproxy) handling network traffic; CVE-2026-31431 KEV high severity, fix available',
        },
      ],
    },
    {
      phase: 'ACT',
      title: 'App-Update einspielen (normal cycle)',
      subline: 'openssl-libs, libcurl4, libxml2',
      rows: [
        { group: 'openssl-libs', worst: 'CVE-2024-5535',  reason: 'TLS on :443 PUBLIC-EXPOSED; nginx + curl linked against vulnerable libssl; OOB-Memory-Read via EC certs. Patch available 3.0.2-0ubuntu1.19.' },
        { group: 'libcurl4',     worst: 'CVE-2024-7264',  reason: 'curl uses ASN.1 parser with stack-overflow on malformed cert; in use by automated cron job pulling external feeds.' },
        { group: 'libxml2',      worst: 'CVE-2024-25062', reason: 'libxml2 use-after-free in xmlValidatePopElement; loaded by nginx-mod-http-xslt at startup. Patch in 2.9.13+dfsg-1ubuntu0.6.' },
      ],
    },
    {
      phase: 'ACT',
      title: 'Defer-Frist erreicht — Re-Triage',
      subline: 'glibc, curl',
      rows: [
        { group: 'glibc', worst: 'CVE-2024-2961', reason: 'iconv() buffer overflow on ISO-2022-CN-EXT input. Deferred 14d ago — frist reached, requires re-evaluation.' },
        { group: 'curl',  worst: 'CVE-2024-2398', reason: 'HTTP/2 push streams memory leak under attacker control. Deferred 21d ago — re-triage now.' },
      ],
    },
  ];

  // ── Triage queue findings (per risk-band) ─────────────────────
  const TRIAGE = {
    escalate: [
      {
        cve: 'CVE-2026-31431',
        kev: true,
        title: 'kernel: out-of-bounds write in n_tty_receive_…',
        pkg: 'linux-modules-5.15.0-177-generic@Ubuntu',
        from: '5.15.0-177', to: '5.15.0-178',
        epss: '82.4%', cvss: '8.8', severity: 'HIGH',
        ai: 'ssh on 0.0.0.0:22 PUBLIC-EXPOSED; kernel modules reachable via network traffic; CVE-2026-31431 high KEV active exploit, fix available in 5.15.0-178.',
      },
      {
        cve: 'CVE-2024-5535',
        kev: false,
        title: 'openssl: SSL_select_next_proto buffer overre…',
        pkg: 'openssl-libs@Ubuntu',
        from: '3.0.2-0ubuntu1.18', to: '3.0.2-0ubuntu1.19',
        epss: '54.2%', cvss: '9.1', severity: 'CRITICAL',
        ai: 'TLS auf :443 PUBLIC-EXPOSED; nginx und curl beide gegen vulnerable libssl gelinkt; OOB-Memory-Read über speziell konstruierte EC-Zertifikate. Patch verfügbar.',
      },
      {
        cve: 'CVE-2024-9143',
        kev: false,
        title: 'openssl: out-of-bounds read in BN_GF2m_pol…',
        pkg: 'openssl-libs@Ubuntu',
        from: '3.0.2-0ubuntu1.18', to: '3.0.2-0ubuntu1.19',
        epss: '8.1%', cvss: '7.5', severity: 'HIGH',
        ai: 'Affected nur bei expliziten GF(2^m) ECs; auf diesem Host nicht in der TLS-Config aktiv, aber via nginx-stream weiterhin erreichbar. Patch-Zug nutzen.',
      },
    ],
    act: [
      { cve: 'CVE-2024-7264',   kev: false, title: 'curl: ASN.1 parser stack overflow on malformed cert', pkg: 'libcurl4@Ubuntu', from: '7.81.0-1ubuntu1.16', to: '7.81.0-1ubuntu1.18', epss: '4.1%', cvss: '7.5', severity: 'HIGH',
        ai: 'curl wird vom cron job ext-feeds täglich gegen externe URLs aufgerufen; theoretisch ausnutzbar, fix in 1.18 bereit.' },
      { cve: 'CVE-2024-25062',  kev: false, title: 'libxml2: use-after-free in xmlValidatePopElement', pkg: 'libxml2@Ubuntu',   from: '2.9.13+dfsg-1ubuntu0.4', to: '2.9.13+dfsg-1ubuntu0.6', epss: '1.8%', cvss: '6.5', severity: 'MEDIUM',
        ai: 'libxml2 von nginx-mod-http-xslt beim Start geladen; keine externen XML-Inputs derzeit aktiv.' },
      { cve: 'CVE-2024-2961',   kev: false, title: 'glibc: iconv() buffer overflow ISO-2022-CN-EXT',   pkg: 'glibc@Ubuntu',      from: '2.35-0ubuntu3.7', to: '2.35-0ubuntu3.8', epss: '12.3%', cvss: '7.4', severity: 'HIGH',
        ai: 'glibc-iconv im PHP-Stack erreicht; verifizierter Defer-Override 14 Tage abgelaufen.' },
      { cve: 'CVE-2024-2398',   kev: false, title: 'curl: HTTP/2 push streams memory leak',            pkg: 'libcurl4@Ubuntu',   from: '7.81.0-1ubuntu1.16', to: '7.81.0-1ubuntu1.18', epss: '2.4%', cvss: '5.9', severity: 'MEDIUM',
        ai: 'HTTP/2-push beim Outbound-Fetch nicht genutzt; Patch-Zug deckt mit ab.' },
      { cve: 'CVE-2024-37372',  kev: false, title: 'openssl: timing oracle on RSA decrypt',            pkg: 'openssl-libs@Ubuntu', from: '3.0.2-0ubuntu1.18', to: '3.0.2-0ubuntu1.19', epss: '0.9%', cvss: '5.3', severity: 'MEDIUM',
        ai: 'Timing-oracle relevant nur für lokale Threat-Modelle; Patch ohnehin im Zug.' },
    ],
    mitigate: [
      { cve: 'CVE-2023-50387', kev: false, title: 'systemd-resolved: DNSSEC validation NSEC bypass', pkg: 'systemd@Ubuntu', from: '249.11-0ubuntu3.12', to: 'unfixed', epss: '0.7%', cvss: '5.0', severity: 'MEDIUM',
        ai: 'Kein Upstream-Fix; mitigation: DNSSEC=allow-downgrade in resolved.conf, lokal angewendet.' },
      { cve: 'CVE-2024-12345',  kev: false, title: 'docker-proxy: improper iptables cleanup',         pkg: 'docker.io@Ubuntu', from: '24.0.7-0ubuntu1', to: 'unfixed', epss: '0.4%', cvss: '4.4', severity: 'MEDIUM',
        ai: 'Workaround: explicit iptables -F docker am Restart. Skript in /etc/systemd/system/docker.service.d/ aktiv.' },
    ],
    pending: 79,
    monitor: 187,
    noise: 120,
  };

  return { HOST, LISTENERS, SERVICES, HEADER_STATS, WORKFLOWS, TRIAGE, heartbeat: heartbeat(), severityTrend: severityTrend() };
})();
