/* Fathometer — audit-log data (plain JS, no Babel).
   Deterministic mock of the immutable audit ledger. Page 1 is dominated by the
   LLM worker pipeline (job_picked → pass2 → cache_hit → job_done), the way the
   live ledger looks under load, with human + system events sprinkled in so the
   COMMENT / METADATA column has something to say.

   Shape:
     ACTIONS  — catalogue { id, level }  (level: info | notice | alert)
     ACTORS   — distinct actor names for the filter dropdown
     TAGS     — filter tags
     ENTRIES  — pre-sorted newest-first; each row carries structured metadata
     VOLUME   — 48 × 30-min buckets of event counts for the activity strip
     TOTAL_ENTRIES / PAGE / PAGES — pager context
*/

window.AUDIT_DATA = (() => {
  // ── Action catalogue ──────────────────────────────────────
  // level drives the pill colour. `alert` is the only one that wears cyan —
  // the brand's single signal reserved for "look here". Everything else is the
  // calm neutral outline.
  const ACTIONS = [
    { id: 'llm.job_picked',                   level: 'info'   },
    { id: 'llm.pass2_started_with_failed_pass1', level: 'notice' },
    { id: 'llm.cache_hit',                    level: 'info'   },
    { id: 'llm.job_done',                     level: 'info'   },
    { id: 'llm.job_failed',                   level: 'alert'  },
    { id: 'scan.started',                     level: 'info'   },
    { id: 'scan.completed',                   level: 'info'   },
    { id: 'nvd.sync',                         level: 'info'   },
    { id: 'kev.sync',                         level: 'notice' },
    { id: 'finding.acknowledged',             level: 'notice' },
    { id: 'finding.escalated',                level: 'alert'  },
    { id: 'export.csv',                       level: 'info'   },
    { id: 'config.changed',                   level: 'notice' },
    { id: 'auth.login',                       level: 'info'   },
    { id: 'auth.login_failed',                level: 'alert'  },
  ];

  const ACTORS = ['worker', 'scheduler', 'system', 'sven', 'api'];
  const TAGS   = ['pipeline', 'scan', 'feed', 'triage', 'auth', 'config'];

  // ── Deterministic PRNG (mulberry32) ───────────────────────
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
  const r = rng('fathometer-audit-ledger-2026-06-05');
  const pick = (arr) => arr[Math.floor(r() * arr.length)];
  const randint = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));

  const MODELS = ['qwen2.5-coder:14b', 'llama3.1:8b', 'mistral-nemo:12b'];
  const HOSTS  = ['rke2-sv-0', 'rke2-sv-1', 'edge-cy-04', 'db-fsn1-01', 'gitlab-runner-03'];
  const CVES   = ['CVE-2026-31431', 'CVE-2024-6387', 'CVE-2024-5535', 'CVE-2025-1094', 'CVE-2025-26465'];

  // ── Clock: walk backwards from 2026-06-05 04:49:31 ────────
  let clock = Date.UTC(2026, 5, 5, 4, 49, 31);
  function fmt(ms) {
    const d = new Date(ms);
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  }
  function rel(ms) {
    const diff = Math.max(0, 1749098971000 + 0 - 0); // unused; relative computed below
    return diff;
  }
  // Relative-time string from a delta in seconds.
  function relFrom(deltaSec) {
    if (deltaSec < 60)      return `${deltaSec}s ago`;
    if (deltaSec < 3600)    return `${Math.floor(deltaSec / 60)}m ago`;
    if (deltaSec < 86400)   return `${Math.floor(deltaSec / 3600)}h ago`;
    return `${Math.floor(deltaSec / 86400)}d ago`;
  }

  const NOW = clock;

  // ── Per-action row builder ────────────────────────────────
  let llmJob = 6694;   // counts down as we walk back in time
  let llmId  = 26;

  function buildLLMQuartet() {
    // Emit a realistic worker quartet for one llm_job, newest-first:
    //   job_done → cache_hit → pass2_started_with_failed_pass1 → job_picked
    const job = llmJob--;
    const id  = llmId--;
    const model = pick(MODELS);
    const cve = pick(CVES);
    const rows = [];

    rows.push({
      action: 'llm.job_done', actor: 'worker', tag: 'pipeline',
      target: `llm_job ${job}`,
      meta: {
        model, cve,
        tokens_in: randint(2400, 8200),
        tokens_out: randint(280, 1400),
        latency_ms: randint(900, 6400),
        cost_usd: (r() * 0.018 + 0.001).toFixed(4),
        band: pick(['act', 'mitigate', 'monitor', 'escalate']),
      },
    });
    rows.push({
      action: 'llm.cache_hit', actor: 'worker', tag: 'pipeline',
      target: `llm ${id}`,
      meta: {
        cve, model,
        cache_key: `sha256:${Math.floor(r() * 0xffffff).toString(16).padStart(6, '0')}…`,
        saved_tokens: randint(1800, 7600),
      },
    });
    rows.push({
      action: 'llm.pass2_started_with_failed_pass1', actor: 'worker', tag: 'pipeline',
      target: `llm ${job}`,
      meta: {
        cve, model,
        pass1_error: pick(['schema_validation_failed', 'truncated_json', 'empty_completion']),
        retry: 1,
        temperature: 0.2,
      },
    });
    rows.push({
      action: 'llm.job_picked', actor: 'worker', tag: 'pipeline',
      target: `llm_job ${job}`,
      meta: {
        cve, model,
        queue: 'pass2',
        priority: pick(['normal', 'high', 'low']),
        attempt: 1,
      },
    });
    return rows;
  }

  // Human / system events keyed by a recipe.
  function buildSpecial(kind) {
    switch (kind) {
      case 'scan.completed':
        { const host = pick(HOSTS);
          return [{ action: 'scan.completed', actor: 'scheduler', tag: 'scan',
            target: host,
            comment: 'periodic fleet scan',
            meta: { host, packages: randint(640, 2140), findings: randint(120, 980),
                    duration_s: randint(38, 412), trivy: '0.58.1' } }]; }
      case 'nvd.sync':
        return [{ action: 'nvd.sync', actor: 'system', tag: 'feed',
          target: 'nvd-2.0',
          meta: { added: randint(4, 61), modified: randint(20, 240),
                  window_h: 2, source: 'services.nvd.nist.gov' } }];
      case 'kev.sync':
        return [{ action: 'kev.sync', actor: 'system', tag: 'feed',
          target: 'cisa-kev',
          comment: 'catalog delta applied',
          meta: { added: randint(0, 3), total: 1284, source: 'cisa.gov/kev' } }];
      case 'finding.acknowledged':
        { const host = pick(HOSTS); const cve = pick(CVES);
          return [{ action: 'finding.acknowledged', actor: 'sven', tag: 'triage',
            target: cve,
            comment: 'risk accepted — patch scheduled in next maint. window',
            meta: { cve, server: host, band: 'act', ticket: `OPS-${randint(2100, 2400)}` } }]; }
      case 'finding.escalated':
        { const host = pick(HOSTS); const cve = pick(CVES);
          return [{ action: 'finding.escalated', actor: 'sven', tag: 'triage',
            target: cve,
            comment: 'KEV + reachable from edge — paged on-call',
            meta: { cve, server: host, band: 'escalate', kev: true } }]; }
      case 'export.csv':
        return [{ action: 'export.csv', actor: 'sven', tag: 'triage',
          target: 'findings',
          meta: { rows: randint(40, 480), filter: 'band=escalate;status=open', format: 'csv' } }];
      case 'config.changed':
        return [{ action: 'config.changed', actor: 'sven', tag: 'config',
          target: 'scan.schedule',
          comment: 'tightened cadence on edge tier',
          meta: { key: 'scan.interval_min', old: 360, new: 180 } }];
      case 'auth.login':
        return [{ action: 'auth.login', actor: 'sven', tag: 'auth',
          target: 'session',
          meta: { ip: '88.97.x.x', mfa: 'totp', ua: 'Firefox/126 · Linux' } }];
      case 'auth.login_failed':
        return [{ action: 'auth.login_failed', actor: 'api', tag: 'auth',
          target: 'session',
          comment: 'invalid token — bearer expired',
          meta: { ip: '203.0.113.x', reason: 'token_expired', attempts: 3 } }];
      case 'llm.job_failed':
        { const job = llmJob; const cve = pick(CVES);
          return [{ action: 'llm.job_failed', actor: 'worker', tag: 'pipeline',
            target: `llm_job ${job}`,
            comment: 'pass2 exhausted retries — requeued to DLQ',
            meta: { cve, model: pick(MODELS), error: 'context_length_exceeded',
                    retries: 3, dlq: true } }]; }
      default:
        return [];
    }
  }

  // ── Assemble the page ─────────────────────────────────────
  // Interleave: mostly worker quartets, with a special event every ~2 quartets.
  const SPECIAL_CYCLE = [
    'scan.completed', 'nvd.sync', 'finding.escalated', 'config.changed',
    'export.csv', 'kev.sync', 'finding.acknowledged', 'auth.login',
    'llm.job_failed', 'auth.login_failed',
  ];

  const raw = [];
  let specialIdx = 0;
  while (raw.length < 64) {
    raw.push(...buildLLMQuartet());
    if (r() < 0.55) {
      raw.push(...buildSpecial(SPECIAL_CYCLE[specialIdx % SPECIAL_CYCLE.length]));
      specialIdx++;
    }
  }

  // Stamp times: walk back from NOW with small gaps; cluster the first ~16 at
  // "4m ago / 04:49" like the live ledger.
  const ENTRIES = raw.slice(0, 60).map((row, i) => {
    // First 16 rows share the 04:49 burst (4m ago); then gaps widen.
    let gap;
    if (i === 0) gap = 0;
    else if (i < 16) gap = randint(0, 2);
    else if (i < 32) gap = randint(3, 40);
    else gap = randint(30, 900);
    clock -= gap * 1000;
    const deltaSec = Math.round((NOW - clock) / 1000) + 240; // +4m baseline offset
    return {
      id: `evt-${100000 + i}`,
      ts: clock,
      timeAbs: fmt(clock),
      timeRel: relFrom(deltaSec),
      actor: row.actor,
      action: row.action,
      level: (ACTIONS.find(a => a.id === row.action) || {}).level || 'info',
      target: row.target,
      comment: row.comment || null,
      tag: row.tag,
      meta: row.meta || {},
    };
  });

  // ── Activity volume — 48 × 30-min buckets (last 24h) ──────
  const VOLUME = (() => {
    const v = rng('audit-volume');
    const out = [];
    for (let i = 0; i < 48; i++) {
      // Diurnal-ish base with a load spike near "now" (last few buckets).
      const base = 18 + Math.round(14 * Math.sin((i / 48) * Math.PI * 2));
      const noise = Math.round(v() * 22);
      const recentBoost = i > 42 ? randint(20, 60) : 0;
      out.push(Math.max(2, base + noise + recentBoost));
    }
    return out;
  })();
  const VOLUME_MAX = Math.max(...VOLUME);
  const VOLUME_TOTAL = VOLUME.reduce((a, b) => a + b, 0);

  return {
    ACTIONS, ACTORS, TAGS,
    ENTRIES,
    VOLUME, VOLUME_MAX, VOLUME_TOTAL,
    TOTAL_ENTRIES: 23768,
    PAGE: 1,
    PAGES: 476,
  };
})();
