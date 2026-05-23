/* SecScan — fleet + heartbeat data. Realistic 2025/2026 Debian/Ubuntu/Alpine.
   Heartbeats are deterministic per-host so visuals don't shimmer between renders. */

window.SECSCAN_DATA = (() => {
  const FLEET = [
    { host: 'db-fsn1-01',       os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '4m',  state: 'alarm',  critical: 4,  high: 12,  medium: 87,  low: 14, pending: 51,  monitor: 32, noise: 4 },
    { host: 'db-fsn1-02',       os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '4m',  state: 'alarm',  critical: 4,  high: 12,  medium: 89,  low: 14, pending: 51,  monitor: 34, noise: 4 },
    { host: 'db-hel1-01',       os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '6m',  state: 'warn',   critical: 0,  high: 8,   medium: 142, low: 22, pending: 88,  monitor: 78, noise: 6 },
    { host: 'edge-cy-01',       os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', lastScan: '3m',  state: 'warn',   critical: 0,  high: 14,  medium: 311, low: 38, pending: 198, monitor: 154,noise: 11 },
    { host: 'edge-cy-04',       os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', lastScan: '3m',  state: 'alarm',  critical: 2,  high: 28,  medium: 421, low: 41, pending: 287, monitor: 198,noise: 7 },
    { host: 'edge-fra-02',      os: 'Ubuntu 24.04 LTS', kernel: '6.8.0-49-generic',   arch: 'x86_64',  lastScan: '5m',  state: 'ok',     critical: 0,  high: 3,   medium: 41,  low: 8,  pending: 12,  monitor: 38, noise: 2 },
    { host: 'gitlab-runner-01', os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'x86_64',  lastScan: '12m', state: 'ok',     critical: 0,  high: 4,   medium: 198, low: 27, pending: 102, monitor: 121,noise: 6 },
    { host: 'gitlab-runner-02', os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'x86_64',  lastScan: '11m', state: 'warn',   critical: 0,  high: 7,   medium: 204, low: 29, pending: 121, monitor: 119,noise: 6 },
    { host: 'gitlab-runner-03', os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'x86_64',  lastScan: '11m', state: 'alarm',  critical: 1,  high: 9,   medium: 211, low: 31, pending: 134, monitor: 112,noise: 5 },
    { host: 'rke2-cp-0',        os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'x86_64',  lastScan: '5m',  state: 'ok',     critical: 0,  high: 2,   medium: 78,  low: 11, pending: 32,  monitor: 56, noise: 3 },
    { host: 'rke2-sv-0',        os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', lastScan: '5m',  state: 'alarm',  critical: 8,  high: 91,  medium: 2147,low: 84, pending: 1421,monitor: 891,noise: 18 },
    { host: 'rke2-sv-1',        os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', lastScan: '5m',  state: 'warn',   critical: 0,  high: 18,  medium: 487, low: 44, pending: 312, monitor: 224,noise: 13 },
    { host: 'rke2-sv-2',        os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', lastScan: '5m',  state: 'alarm',  critical: 5,  high: 67,  medium: 1389,low: 62, pending: 921, monitor: 593,noise: 9 },
    { host: 'mail-fsn-01',      os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '8m',  state: 'ok',     critical: 0,  high: 5,   medium: 134, low: 18, pending: 64,  monitor: 89, noise: 4 },
    { host: 'backup-bx-01',     os: 'Debian 11.9',      kernel: '5.10.0-30-amd64',    arch: 'x86_64',  lastScan: '14m', state: 'warn',   critical: 0,  high: 11,  medium: 287, low: 32, pending: 187, monitor: 138,noise: 5 },
    { host: 'ci-build-04',      os: 'Ubuntu 22.04 LTS', kernel: '5.15.0-177-generic', arch: 'x86_64',  lastScan: '7m',  state: 'ok',     critical: 0,  high: 2,   medium: 67,  low: 9,  pending: 28,  monitor: 47, noise: 3 },
    { host: 'prom-01',          os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '2m',  state: 'ok',     critical: 0,  high: 1,   medium: 23,  low: 6,  pending: 7,   monitor: 21, noise: 2 },
    { host: 'log-loki-01',      os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '2m',  state: 'ok',     critical: 0,  high: 1,   medium: 26,  low: 6,  pending: 8,   monitor: 23, noise: 2 },
    { host: 'vpn-wg-01',        os: 'Alpine 3.19',      kernel: '6.6.30-0-lts',       arch: 'x86_64',  lastScan: '6m',  state: 'ok',     critical: 0,  high: 0,   medium: 4,   low: 1,  pending: 1,   monitor: 4,  noise: 0 },
    { host: 'jumphost-01',      os: 'Debian 12.5',      kernel: '6.1.0-21-amd64',     arch: 'x86_64',  lastScan: '9m',  state: 'unknown',critical: 0,  high: 0,   medium: 0,   low: 0,  pending: 0,   monitor: 0,  noise: 0 },
  ];

  // Deterministic PRNG (mulberry32) seeded per hostname so heartbeats are stable.
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

  // Generate N daily heartbeat ticks for one host. Tail (today) reflects current state.
  // "Stille Severity": cyan (alarm) ticks are rare on purpose — at most a handful
  // even for alarm hosts, clustered near the present. Background is dim grey OK with
  // occasional brighter-grey warn ticks. Cyan is the eye-catcher, not the wallpaper.
  function heartbeat(host, n = 30) {
    const r = rng(host.host);
    const out = new Array(n).fill('ok');

    if (host.state === 'unknown') {
      for (let i = 0; i < n; i++) out[i] = r() < 0.7 ? 'unknown' : 'ok';
      out[n - 1] = 'unknown';
      return out;
    }

    // Baseline warn probability — quiet drumming behind everything
    const warnBase = { ok: 0.05, warn: 0.18, alarm: 0.25 }[host.state] ?? 0.05;
    for (let i = 0; i < n; i++) {
      const v = r();
      if (v < 0.015) out[i] = 'unknown';        // very occasional missed scan
      else if (v < warnBase + 0.015) out[i] = 'warn';
      else out[i] = 'ok';
    }

    // Place a few cyan alarm ticks ONLY for alarm hosts. Cluster them near today.
    if (host.state === 'alarm') {
      // 2–4 alarm days in the last 7, plus maybe 1 older
      const recentCount = 2 + Math.floor(r() * 3); // 2..4
      const slots = new Set();
      while (slots.size < recentCount) {
        slots.add(n - 1 - Math.floor(r() * 7));   // last 7 days
      }
      if (r() < 0.45) slots.add(n - 1 - (8 + Math.floor(r() * 14))); // optional older spike
      for (const i of slots) if (i >= 0) out[i] = 'alarm';
    }

    // Warn hosts get a couple of yesterday-ish bumps but no cyan
    if (host.state === 'warn') {
      out[n - 1] = 'warn';
      if (r() < 0.6) out[n - 2] = 'warn';
    }

    // Pin "today" to the current declared state
    out[n - 1] = host.state;
    return out;
  }

  // Fleet totals (used for the headline numbers).
  function totals() {
    const t = { hosts: FLEET.length, alarm: 0, warn: 0, ok: 0, unknown: 0,
                critical: 0, high: 0, medium: 0, low: 0,
                pending: 0, monitor: 0, noise: 0,
                escalate: 0, act: 0, mitigate: 0 };
    for (const h of FLEET) {
      t[h.state]++;
      t.critical += h.critical; t.high += h.high; t.medium += h.medium; t.low += h.low;
      t.pending += h.pending;   t.monitor += h.monitor; t.noise += h.noise;
    }
    // Synthetic triage assignment: escalate≈critical, act≈high subset, mitigate≈small
    t.escalate = t.critical;             // 24
    t.act = Math.round(t.high * 0.18);   // ~ 53
    t.mitigate = Math.round(t.high * 0.08); // ~ 23
    return t;
  }

  return {
    FLEET,
    heartbeat,
    totals: totals(),
  };
})();
