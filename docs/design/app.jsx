/* SecScan Dashboard — React app
   Loaded as JSX with Babel. Uses window.SECSCAN_DATA + window.SECSCAN_CAMERA. */

const { useEffect, useLayoutEffect, useMemo, useRef, useState, useCallback } = React;
const { FLEET, heartbeat, totals } = window.SECSCAN_DATA;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "stayLoading": false,
  "loadDurationMs": 2600
}/*EDITMODE-END*/;

// ── Loading-state controller ──────────────────────────────────
// Holds the set of host-names that are currently "loading" their heartbeat + stats.
// On mount (and on replay), every host enters loading; they resolve in a staggered
// L→R wave so the user can watch the fleet come online.
function useFleetLoading({ stayLoading, loadDurationMs }) {
  const allKeys = useMemo(() => FLEET.map(h => h.host), []);
  const [loading, setLoading] = useState(() => new Set(allKeys));
  const [resolvedAt, setResolvedAt] = useState({});   // host -> ms-since-epoch when it finished
  const timersRef = useRef([]);

  const clearTimers = useCallback(() => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
  }, []);

  const replay = useCallback(() => {
    clearTimers();
    setLoading(new Set(allKeys));
    setResolvedAt({});
    if (stayLoading) return;
    // stagger resolution: each host gets a slot, plus a small per-host jitter
    const slotMs = loadDurationMs / Math.max(1, allKeys.length);
    allKeys.forEach((h, i) => {
      const jitter = 80 + Math.random() * 240;
      const delay = 220 + i * slotMs + jitter;
      const t = setTimeout(() => {
        setLoading(prev => {
          const next = new Set(prev);
          next.delete(h);
          return next;
        });
        setResolvedAt(prev => ({ ...prev, [h]: performance.now() }));
      }, delay);
      timersRef.current.push(t);
    });
  }, [allKeys, stayLoading, loadDurationMs, clearTimers]);

  // Re-run whenever stayLoading or duration changes (so tweak edits feel live).
  useEffect(() => { replay(); return clearTimers; }, [replay]);

  return { loading, resolvedAt, replay };
}

// ── Heartbeat strip ────────────────────────────────────────────
const HEARTBEAT_STATE_LABEL = {
  alarm: 'ESCALATE',
  warn: 'ACT',
  ok: 'NOMINAL',
  unknown: 'UNKNOWN',
};
function fmtHeartbeatDate(d) {
  return d.toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
}

function HeartbeatStrip({ host, ticks = 30, className = 'host__beat', tickClass = 'host__beat-tick', resolvedAt }) {
  const beats = useMemo(() => heartbeat(host, ticks), [host.host, ticks]);
  const tickDates = useMemo(() => {
    const today = new Date();
    return Array.from({ length: ticks }, (_, i) => {
      const d = new Date(today);
      d.setHours(0, 0, 0, 0);
      d.setDate(d.getDate() - (ticks - 1 - i));
      return d;
    });
  }, [ticks]);
  const [hoverIdx, setHoverIdx] = useState(null);
  // If this host just resolved, stagger-fade each tick in from its skeleton position.
  const justResolved = resolvedAt && (performance.now() - resolvedAt) < 1200;
  return (
    <div className={`${className} ${justResolved ? 'host__beat--materialize' : ''}`}>
      {beats.map((b, i) => (
        <div
          key={i}
          className={`${tickClass} beat--${b} ${hoverIdx === i ? `${tickClass}--hover` : ''}`}
          onMouseEnter={() => setHoverIdx(i)}
          onMouseLeave={() => setHoverIdx(null)}
          style={justResolved ? { animationDelay: `${i * 18}ms` } : undefined}
        />
      ))}
      {hoverIdx !== null && (
        <div
          className="heartbeat-tip"
          style={{ left: `${((hoverIdx + 0.5) / ticks) * 100}%` }}
          aria-hidden="true"
        >
          <div className="heartbeat-tip__date">{fmtHeartbeatDate(tickDates[hoverIdx])}</div>
          <div className={`heartbeat-tip__state heartbeat-tip__state--${beats[hoverIdx]}`}>
            {HEARTBEAT_STATE_LABEL[beats[hoverIdx]] || 'UNKNOWN'}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Heartbeat skeleton ────────────────────────────────────────
// 30 dim ticks with a soft accent scan probe sweeping L→R (radar/
// oscilloscope feel — per DS §1 "materialization, not animation").
function HeartbeatSkeleton({ ticks = 30, className = 'host__beat', tickClass = 'host__beat-tick' }) {
  return (
    <div
      className={`${className} ${className}--skel ${className}--skel-scan`}
      role="presentation"
      aria-busy="true"
      aria-label="loading heartbeat"
    >
      {Array.from({ length: ticks }).map((_, i) => (
        <div key={i} className={`${tickClass} ${tickClass}--skel`} />
      ))}
      <div className={`${className}__probe`} />
    </div>
  );
}

// ── Stat skeleton (crit / high / scan placeholder dash) ───────
function StatSkeleton({ width = 16, align = 'right' }) {
  return (
    <div className={`stat-skel stat-skel--${align}`} aria-busy="true">
      <span className="stat-skel__dash" style={{ width }} />
    </div>
  );
}

// ── Host groups ───────────────────────────────────────────────
// Groups are derived from hostname prefix — the dashboard doesn't create or
// edit groups, it only renders whatever grouping exists for the fleet.
function deriveGroup(host) {
  const h = host.host.toLowerCase();
  if (h.startsWith('db-'))            return 'DB';
  if (h.startsWith('edge-'))          return 'Edge';
  if (h.startsWith('gitlab-runner'))  return 'CI';
  if (h.startsWith('ci-build'))       return 'CI';
  if (h.startsWith('mail-'))          return 'Mail';
  if (h.startsWith('backup-'))        return 'Backup';
  if (h.startsWith('prom-'))          return 'Observability';
  if (h.startsWith('log-'))           return 'Observability';
  if (h.startsWith('vpn-'))           return 'Network';
  if (h.startsWith('jumphost-'))      return 'Network';
  return null;
}

// All known named group keys, used to set the default-collapsed state.
const NAMED_GROUP_KEYS = (() => {
  const set = new Set();
  FLEET.forEach(h => { const g = deriveGroup(h); if (g) set.add(g); });
  return set;
})();

// ── Sidebar ────────────────────────────────────────────────────
function HostRow({ host: h, isLoading, active, onSelect, resolvedAt }) {
  return (
    <div
      className={`host ${active === h.host ? 'host--active' : ''} ${isLoading ? 'host--loading' : ''}`}
      onClick={() => onSelect(h.host)}
      aria-busy={isLoading || undefined}
    >
      <div className="host__top">
        <span className={`host__dot ${isLoading ? 'host__dot--skel' : `host__dot--${h.state}`}`} />
        <div className="host__name">{h.host}</div>
        {isLoading ? (
          <>
            <StatSkeleton width={18} />
            <StatSkeleton width={14} />
          </>
        ) : (
          <>
            <div className={`host__count ${h.critical ? 'host__count--crit' : 'host__count--zero'}`}>{h.critical || '—'}</div>
            <div className={`host__count ${h.high ? '' : 'host__count--zero'}`}>{h.high || '—'}</div>
          </>
        )}
      </div>
      <div className="host__os">{h.os} · {h.kernel} · {h.arch}</div>
      {isLoading
        ? <HeartbeatSkeleton ticks={30} />
        : <HeartbeatStrip host={h} ticks={30} resolvedAt={resolvedAt[h.host]} />}
      <div className="host__beat-axis"><span>-30d</span><span>today</span></div>
    </div>
  );
}

// Stable group order — keeps the sidebar visually consistent across renders.
const GROUP_ORDER = ['DB', 'K8s', 'Edge', 'CI', 'Mail', 'Observability', 'Network', 'Backup'];

function Sidebar({ active, onSelect, query, setQuery, sort, setSort, loading, resolvedAt }) {
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    let arr = !q ? [...FLEET]
      : FLEET.filter(h => h.host.toLowerCase().includes(q) || h.os.toLowerCase().includes(q));
    if (sort === 'severity') {
      const w = { alarm: 3, warn: 2, ok: 1, unknown: 0 };
      arr.sort((a, b) => w[b.state] - w[a.state] || b.critical - a.critical || b.high - a.high);
    } else if (sort === 'host') {
      arr.sort((a, b) => a.host.localeCompare(b.host));
    } else if (sort === 'pending') {
      arr.sort((a, b) => b.pending - a.pending);
    }
    return arr;
  }, [query, sort]);

  // Bucket the filtered hosts into groups, compute aggregate stats.
  const groups = useMemo(() => {
    const map = new Map();
    filtered.forEach(h => {
      const name = deriveGroup(h);
      const key = name || '__ungrouped__';
      if (!map.has(key)) map.set(key, { key, name, hosts: [] });
      map.get(key).hosts.push(h);
    });
    const arr = Array.from(map.values()).map(g => ({
      ...g,
      escalate: g.hosts.reduce((a, h) => a + (h.critical || 0), 0),
      act:      g.hosts.reduce((a, h) => a + (h.high     || 0), 0),
      alarm:    g.hosts.filter(h => h.state === 'alarm').length,
    }));
    // Sort: known order first, then alphabetic, ungrouped last.
    arr.sort((a, b) => {
      if (a.key === '__ungrouped__') return 1;
      if (b.key === '__ungrouped__') return -1;
      const ai = GROUP_ORDER.indexOf(a.name);
      const bi = GROUP_ORDER.indexOf(b.name);
      if (ai !== -1 && bi !== -1) return ai - bi;
      if (ai !== -1) return -1;
      if (bi !== -1) return 1;
      return (a.name || '').localeCompare(b.name || '');
    });
    return arr;
  }, [filtered]);

  // Collapse state — Set of group keys that are collapsed. Default: all
  // named groups collapsed (ungrouped bucket has no header and is always open).
  const [collapsed, setCollapsed] = useState(() => new Set(NAMED_GROUP_KEYS));
  const toggleGroup = useCallback((key) => {
    setCollapsed(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  }, []);

  // When filtering, auto-expand groups that have any matching hosts — surfaces results.
  const filteredKey = query.trim();
  useEffect(() => {
    if (!filteredKey) return;
    setCollapsed(prev => {
      if (prev.size === 0) return prev;
      const next = new Set(prev);
      groups.forEach(g => next.delete(g.key));
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filteredKey]);

  const inputRef = useRef(null);
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === '/' && document.activeElement !== inputRef.current) {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const alarms = filtered.filter(h => h.state === 'alarm').length;

  return (
    <aside className="sidebar">
      <div className="sidebar__filter">
        <input
          ref={inputRef}
          className="sidebar__input"
          placeholder="filter hosts                                                ( / )"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
      </div>
      <div className="sidebar__meta">
        <span><b>{filtered.length}</b> hosts · {alarms ? <span style={{ color: 'var(--accent)' }}>{alarms} alarm</span> : 'all quiet'}</span>
      </div>
      <div className="sidebar__colhead">
        <span></span>
        <span>host</span>
        <span>escalate</span>
        <span>act</span>
      </div>
      <div className="sidebar__list">
        {groups.map(group => {
          const isOpen = !collapsed.has(group.key);
          return (
            <div key={group.key} className={`hostgroup ${isOpen ? 'hostgroup--open' : 'hostgroup--closed'}`}>
              {group.name && (
                <button
                  type="button"
                  className="hostgroup__header"
                  onClick={() => toggleGroup(group.key)}
                  aria-expanded={isOpen}
                  aria-controls={`group-${group.key}`}
                >
                  <span className="hostgroup__chevron" aria-hidden="true">
                    <svg viewBox="0 0 12 12" width="10" height="10" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square">
                      <polyline points="4 2 8 6 4 10" />
                    </svg>
                  </span>
                  <span className="hostgroup__title">
                    <span className="hostgroup__name">{group.name}</span>
                    <span className="hostgroup__count">{group.hosts.length}</span>
                  </span>
                  <span className={`hostgroup__stat ${group.escalate ? 'hostgroup__stat--crit' : 'hostgroup__stat--zero'}`}>{group.escalate || '—'}</span>
                  <span className={`hostgroup__stat ${group.act ? '' : 'hostgroup__stat--zero'}`}>{group.act || '—'}</span>
                </button>
              )}
              {isOpen && (
                <div className="hostgroup__body" id={`group-${group.key}`}>
                  {group.hosts.map(h => (
                    <HostRow
                      key={h.host}
                      host={h}
                      isLoading={loading.has(h.host)}
                      active={active}
                      onSelect={onSelect}
                      resolvedAt={resolvedAt}
                    />
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}

// ── Triage row ─────────────────────────────────────────────────
const TRIAGE_BUCKETS = [
  { key: 'escalate', label: 'escalate', accent: true },
  { key: 'act',      label: 'act',      accent: true },
  { key: 'mitigate', label: 'mitigate' },
  { key: 'pending',  label: 'pending'  },
  { key: 'monitor',  label: 'monitor'  },
  { key: 'noise',    label: 'noise'    },
  { key: 'unknown',  label: 'unknown'  },
];

function fmt(n) {
  if (n >= 10000) return n.toLocaleString('en-US');
  return String(n);
}

function TriageRow({ values }) {
  return (
    <div className="triage">
      {TRIAGE_BUCKETS.map(b => {
        const n = values[b.key] || 0;
        return (
          <div key={b.key} className={`triage__cell ${b.accent && n > 0 ? 'triage__cell--accent' : ''}`}>
            <div className="triage__cell-label">{b.label}</div>
            <div className={`triage__cell-num ${n === 0 ? 'triage__cell-num--zero' : ''}`}>{fmt(n)}</div>
          </div>
        );
      })}
    </div>
  );
}

// ── Severity strip ─────────────────────────────────────────────
function SeverityStrip({ critical, high, medium, low }) {
  const max = Math.max(critical, high, medium, low);
  const items = [
    { key: 'crit',   label: 'critical', n: critical, mod: 'severity__item--crit' },
    { key: 'high',   label: 'high',     n: high },
    { key: 'medium', label: 'medium',   n: medium },
    { key: 'low',    label: 'low',      n: low },
  ];
  return (
    <div className="severity">
      {items.map(it => (
        <div key={it.key} className={`severity__item ${it.mod || ''}`}>
          <div className="severity__label">{it.label}</div>
          <div className="severity__num">{fmt(it.n)}</div>
          <div className="severity__bar">
            <div className="severity__bar-fill" style={{ width: `${max ? (it.n / max) * 100 : 0}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Fleet table ────────────────────────────────────────────────
function FleetTable({ rows, onSelect, sort, setSort }) {
  const sorted = useMemo(() => {
    const arr = [...rows];
    if (sort === 'severity') {
      const w = { alarm: 3, warn: 2, ok: 1, unknown: 0 };
      arr.sort((a, b) => w[b.state] - w[a.state] || b.critical - a.critical || b.high - a.high);
    } else if (sort === 'host') {
      arr.sort((a, b) => a.host.localeCompare(b.host));
    } else if (sort === 'pending') {
      arr.sort((a, b) => b.pending - a.pending);
    }
    return arr;
  }, [rows, sort]);

  return (
    <>
      <div className="fleet-hdr">
        <h2>Fleet</h2>
        <div className="fleet-actions">
          <span>sort:</span>
          <button className={sort === 'severity' ? 'active' : ''} onClick={() => setSort('severity')}>severity</button>
          <button className={sort === 'host' ? 'active' : ''}     onClick={() => setSort('host')}>host</button>
          <button className={sort === 'pending' ? 'active' : ''}  onClick={() => setSort('pending')}>pending</button>
        </div>
      </div>
      <div className="fleet">
        <div className="fleet__head">
          <span>host</span>
          <span>30d heartbeat</span>
          <span>crit</span>
          <span>high</span>
          <span>pending</span>
          <span>scan</span>
        </div>
        {sorted.map(h => (
          <div
            key={h.host}
            className={`fleet__row fleet__row--${h.state}`}
            onClick={() => onSelect(h.host)}
          >
            <div>
              <div className="fleet__hostname">
                <span className={`host__dot host__dot--${h.state}`} />
                {h.host}
              </div>
              <div className="fleet__os">{h.os} · {h.kernel} · {h.arch}</div>
            </div>
            <HeartbeatStrip host={h} ticks={30} className="fleet__beat" tickClass="fleet__beat-tick" />
            <div className={`fleet__num ${h.critical ? 'fleet__num--crit' : 'fleet__num--zero'}`}>{h.critical || '—'}</div>
            <div className={`fleet__num ${h.high ? '' : 'fleet__num--zero'}`}>{h.high || '—'}</div>
            <div className={`fleet__num ${h.pending ? '' : 'fleet__num--zero'}`}>{fmt(h.pending) || '—'}</div>
            <div className="fleet__last">{h.lastScan}</div>
          </div>
        ))}
      </div>
    </>
  );
}

// ── Profile menu (SK avatar dropdown) ─────────────────────────
function ProfileWidget() {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div ref={wrapRef} className="topbar__profile">
      <button
        type="button"
        className={`topbar__user ${open ? 'topbar__user--open' : ''}`}
        onClick={() => setOpen(o => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Profile menu"
      >SK</button>
      {open && (
        <div className="profile-menu" role="menu">
          <div className="profile-menu__user">
            <div className="profile-menu__label">Angemeldet als</div>
            <div className="profile-menu__name">sven.kroll</div>
          </div>
          <button type="button" className="profile-menu__item" role="menuitem">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1.03-1.56V3a2 2 0 1 1 4 0v.09A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.56 1.03H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1.03Z" />
            </svg>
            <span>Settings</span>
          </button>
          <button type="button" className="profile-menu__item" role="menuitem">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
              <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
              <path d="M14 3v6h6" />
              <path d="M8 13h8" />
              <path d="M8 17h5" />
            </svg>
            <span>Audit</span>
          </button>
          <button type="button" className="profile-menu__item profile-menu__item--danger" role="menuitem">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <path d="M16 17l5-5-5-5" />
              <path d="M21 12H9" />
            </svg>
            <span>Logout</span>
          </button>
        </div>
      )}
    </div>
  );
}

// ── Fathometer logo ───────────────────────────────────────────
// 1930s depth-sounder visual language: half-circle dial with three tick
// marks, horizontal water-line at the equator, stylised seabed wave below,
// and a sweep needle ending in an echo dot that pulses (the "ping return").
function FathometerLogo({ className = 'topbar__logo' }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="Fathometer">
      {/* Outer half-circle dial (the sweep range) */}
      <path d="M 8 32 A 24 24 0 0 1 56 32"
            fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" />
      {/* Cardinal tick marks at the three dial extremes */}
      <line x1="8"  y1="32" x2="11.5" y2="32" stroke="currentColor" strokeWidth="1.25" />
      <line x1="32" y1="8"  x2="32"   y2="11.5" stroke="currentColor" strokeWidth="1.25" />
      <line x1="56" y1="32" x2="52.5" y2="32" stroke="currentColor" strokeWidth="1.25" />
      {/* Water / depth line — hairline across the equator */}
      <line x1="2" y1="32" x2="62" y2="32" stroke="currentColor" strokeWidth="0.85" opacity="0.55" />
      {/* Seabed wave (sonar return signature, lower hemisphere) */}
      <path d="M 4 49 Q 12 44 20 49 T 36 49 T 52 49 T 60 49"
            fill="none" stroke="currentColor" strokeWidth="1" opacity="0.45" strokeLinecap="square" />
      {/* Sweep needle group — rotates around the pivot. Origin set via CSS. */}
      <g className="topbar__logo-sweep">
        <line x1="32" y1="32" x2="32" y2="10"
              stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="square" />
        {/* Echo return at the needle tip — pulses with the operational cadence */}
        <circle cx="32" cy="10" r="2.6" fill="var(--accent)" className="topbar__logo-echo" />
      </g>
      {/* Pivot */}
      <circle cx="32" cy="32" r="1.6" fill="currentColor" />
    </svg>
  );
}

// ── Topbar ────────────────────────────────────────────────────
function TopBar({ now }) {
  return (
    <header className="topbar">
      <div className="topbar__brand">
        <FathometerLogo />
        <div className="topbar__wordmark">
          <div className="topbar__wordmark-name">Fathometer</div>
          <div className="topbar__wordmark-sub">CVE Intelligence</div>
        </div>
      </div>
      <div className="topbar__right">
        <nav className="topbar__nav">
          <button className="topbar__navitem topbar__navitem--active">Dashboard</button>
          <button className="topbar__navitem">Findings</button>
        </nav>
        <ProfileWidget />
      </div>
    </header>
  );
}

// ── Sonar / scan-flash sync ───────────────────────────────────
// Measures each `.scan-flash` element inside the action-needed card and
// sets its CSS animation-delay so the cyan-peak keyframe (at 14% of the
// 5.4s cycle) lines up with the wall-clock moment the scan beam's center
// crosses that element's center. Result: elements ripple gray→cyan→gray
// in sequence from left to right as the beam sweeps, like a sonar return.
const SCAN_CYCLE_S       = 5.4;
const SCAN_PEAK_FRAC     = 0.14;                       // keyframe at 14%
const SCAN_SWEEP_S       = SCAN_CYCLE_S * 0.44;        // beam moves 0→44%
const BEAM_CENTER_START  = -25.2;                      // % of card width
const BEAM_CENTER_END    = 123.9;
function ScanChars({ text }) {
  const str = String(text ?? '');
  return (
    <span aria-label={str} className="scan-chars">
      {Array.from(str).map((ch, i) => (
        <span key={i} className="scan-flash" aria-hidden="true">
          {ch === ' ' ? '\u00A0' : ch}
        </span>
      ))}
    </span>
  );
}

function useScanFlashSync(rootRef, deps = []) {
  useLayoutEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    const peakS = SCAN_CYCLE_S * SCAN_PEAK_FRAC;
    const apply = () => {
      const cardRect = root.getBoundingClientRect();
      if (cardRect.width === 0) return;
      const range = BEAM_CENTER_END - BEAM_CENTER_START;
      root.querySelectorAll('.scan-flash').forEach(el => {
        const r = el.getBoundingClientRect();
        if (r.width === 0) return;
        const centerPct = ((r.left + r.width / 2 - cardRect.left) / cardRect.width) * 100;
        const tBeamS = ((centerPct - BEAM_CENTER_START) / range) * SCAN_SWEEP_S;
        // Negative delays allowed — pre-advance into the cycle so first-paint
        // already shows the correct phase for that element's position.
        el.style.animationDelay = `${(tBeamS - peakS).toFixed(3)}s`;
      });
    };
    apply();
    // Re-measure after web fonts resolve (text reflows when JetBrains Mono lands).
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(apply).catch(() => {});
    }
    const ro = new ResizeObserver(apply);
    ro.observe(root);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

// ── Action-needed KPI card ────────────────────────────────────
function ActionNeededCard({ totals, onOpenTriage }) {
  const cardRef = useRef(null);
  useScanFlashSync(cardRef, [totals.alarm, totals.hosts, totals.escalate, totals.act, totals.pending]);
  return (
    <div className="stat stat--alarm" ref={cardRef}>
      <p className="stat__label">
        <span className="bracket scan-flash">[</span>action needed<span className="bracket scan-flash">]</span>
      </p>
      <div className="stat__figure">
        <span className="stat__num">
          <ScanChars text={totals.alarm} />
        </span>
        <span className="stat__unit">/ {totals.hosts} hosts</span>
      </div>
      <p className="stat__sub">
        <b>{fmt(totals.escalate)}</b> escalate &nbsp;·&nbsp; <b>{fmt(totals.act)}</b> act &nbsp;·&nbsp; <b>{fmt(totals.pending)}</b> pending
      </p>
      <button className="stat__cta scan-flash" onClick={onOpenTriage}>
        <span className="stat__cta-text">
          <ScanChars text="open triage queue" />
        </span>
        <span className="stat__cta-arrow scan-flash">→</span>
      </button>
    </div>
  );
}

// ── App ───────────────────────────────────────────────────────
function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(null); // null = fleet view
  const [sort, setSort] = useState('severity');
  const [now, setNow] = useState(() => fmtNow());

  const { loading, resolvedAt, replay } = useFleetLoading({
    stayLoading: t.stayLoading,
    loadDurationMs: t.loadDurationMs,
  });

  useEffect(() => {
    const id = setInterval(() => setNow(fmtNow()), 30_000);
    return () => clearInterval(id);
  }, []);

  // Worst offender = alarm host with most criticals, then most highs
  const worst = useMemo(() => {
    return [...FLEET]
      .filter(h => h.state === 'alarm')
      .sort((a, b) => b.critical - a.critical || b.high - a.high)[0]
      || FLEET[0];
  }, []);

  return (
    <>
      <div className="bg-grid" />
      <div className="app">
        <TopBar now={now} />
        <Sidebar
          active={active} onSelect={setActive}
          query={query} setQuery={setQuery}
          sort={sort} setSort={setSort}
          loading={loading} resolvedAt={resolvedAt}
        />
        <main className="main">
          <div className="main__inner">
            <p className="eyebrow">Dashboard · Fleet overview · last refresh · {now}</p>

            {/* Stat blocks */}
            <section className="stats">
              <ActionNeededCard totals={totals} onOpenTriage={() => setActive(worst.host)} />
              <div className="stat stat--safe">
                <p className="stat__label"><span className="bracket">[</span>nominal<span className="bracket">]</span></p>
                <div className="stat__figure">
                  <span className="stat__num">{totals.ok + totals.warn}</span>
                  <span className="stat__unit">/ {totals.hosts} hosts</span>
                </div>
                <p className="stat__sub">
                  <b>{fmt(totals.monitor)}</b> monitor &nbsp;·&nbsp; <b>{fmt(totals.noise)}</b> noise &nbsp;·&nbsp; <b>{totals.unknown}</b> unknown
                </p>
              </div>
            </section>

            {/* Triage row */}
            <p className="section-label">Triage queue</p>
            <TriageRow values={totals} />

            {/* Severity */}
            <p className="section-label">CVSS Severity distribution · all hosts</p>
            <SeverityStrip critical={totals.critical} high={totals.high} medium={totals.medium} low={totals.low} />

            {/* System status terminal line */}
            <div className="sysline">
              <span><span className="prompt">&gt;</span> last scan <b>3m ago</b></span>
              <span>· epss-feed <b>synced</b></span>
              <span>· kev-feed <b>synced</b></span>
              <span>· worker <b>healthy</b></span>
            </div>
          </div>
        </main>
        <footer className="footer">
          <a href="https://github.com/THEKROLL-LTD/fathometer/releases" target="_blank" rel="noopener noreferrer">v2.4.1</a>
          <span className="footer__sep">·</span>
          <a href="#">docs</a>
          <span className="footer__sep">·</span>
          <a href="https://github.com/THEKROLL-LTD/fathometer" target="_blank" rel="noopener noreferrer" className="footer__link footer__link--icon">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
              <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.4 5.4 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
              <path d="M9 18c-4.51 2-5-2-7-2" />
            </svg>
            <span>github</span>
          </a>
          <span style={{ marginLeft: 'auto' }}>thekroll ltd · human intent. machine precision.</span>
        </footer>
      </div>
      <TweaksPanel title="Tweaks">
        <TweakSection label="Heartbeat skeleton" />
        <TweakSlider
          label="Resolve duration"
          value={t.loadDurationMs}
          min={600} max={8000} step={200} unit="ms"
          onChange={(v) => setTweak('loadDurationMs', v)}
        />
        <TweakToggle
          label="Stay loading (inspect)"
          value={t.stayLoading}
          onChange={(v) => setTweak('stayLoading', v)}
        />
        <TweakButton label="Replay loading" onClick={replay} />
      </TweaksPanel>
    </>
  );
}

function fmtNow() {
  const d = new Date();
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  return `${hh}:${mm} UTC`;
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
