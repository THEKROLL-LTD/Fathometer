/* Fathometer — Findings page app shell.
   Mounts Findings.jsx into the existing .main slot, surrounded by the same
   topbar / sidebar / footer chrome the Dashboard and Server-Detail pages use.

   Tweaks panel exposes the canvas-required states:
   - Filter active (default off → empty state visible)
   - Expanded bucket (none / escalate / pending)
   - Bulk-selection prefilled
   - Skeleton on one expanded bucket (lazy-load)
*/

const { useState: ffaUseState, useMemo: ffaUseMemo } = React;
const { FLEET: FFA_FLEET, heartbeat: ffaHeartbeat } = window.SECSCAN_DATA;

const FFA_TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "state": "filter-bucket-expanded",
  "skeletonOnExpanded": false,
  "bulkSelection": false
}/*EDITMODE-END*/;

// ── Reused topbar logo (verbatim copy from Server-Detail shell) ─
function FFALogo({ className = 'topbar__logo' }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="Fathometer">
      <path d="M 8 32 A 24 24 0 0 1 56 32" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" />
      <line x1="8"  y1="32" x2="11.5" y2="32" stroke="currentColor" strokeWidth="1.25" />
      <line x1="32" y1="8"  x2="32"   y2="11.5" stroke="currentColor" strokeWidth="1.25" />
      <line x1="56" y1="32" x2="52.5" y2="32" stroke="currentColor" strokeWidth="1.25" />
      <line x1="2" y1="32" x2="62" y2="32" stroke="currentColor" strokeWidth="0.85" opacity="0.55" />
      <path d="M 4 49 Q 12 44 20 49 T 36 49 T 52 49 T 60 49" fill="none" stroke="currentColor" strokeWidth="1" opacity="0.45" strokeLinecap="square" />
      <g className="topbar__logo-sweep">
        <line x1="32" y1="32" x2="32" y2="10" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="square" />
        <circle cx="32" cy="10" r="2.6" fill="var(--accent)" className="topbar__logo-echo" />
      </g>
      <circle cx="32" cy="32" r="1.6" fill="currentColor" />
    </svg>
  );
}

function FFAProfile() {
  return (
    <div className="topbar__profile">
      <button type="button" className="topbar__user" aria-label="Profile menu">SK</button>
    </div>
  );
}

function FFATopBar() {
  return (
    <header className="topbar">
      <div className="topbar__brand">
        <FFALogo />
        <div className="topbar__wordmark">
          <div className="topbar__wordmark-name">Fathometer</div>
          <div className="topbar__wordmark-sub">CVE Intelligence</div>
        </div>
      </div>
      <div className="topbar__right">
        <nav className="topbar__nav">
          <button className="topbar__navitem">Dashboard</button>
          <button className="topbar__navitem topbar__navitem--active">Findings</button>
        </nav>
        <FFAProfile />
      </div>
    </header>
  );
}

function FFAHeartbeatStrip({ host, ticks = 30 }) {
  const beats = ffaUseMemo(() => ffaHeartbeat(host, ticks), [host.host, ticks]);
  return (
    <div className="host__beat">
      {beats.map((b, i) => (
        <div key={i} className={`host__beat-tick beat--${b}`} />
      ))}
    </div>
  );
}

function FFASidebar() {
  // No host is "active" on the /findings page — it is cross-fleet.
  const visible = FFA_FLEET.slice(0, 8);
  return (
    <aside className="sidebar">
      <div className="sidebar__filter">
        <input
          className="sidebar__input"
          placeholder="filter hosts                                                ( / )"
          readOnly
        />
      </div>
      <div className="sidebar__meta">
        <span><b>{FFA_FLEET.length}</b> hosts · <span style={{ color: 'var(--accent)' }}>cross-fleet view</span></span>
      </div>
      <div className="sidebar__colhead">
        <span></span>
        <span>host</span>
        <span>escalate</span>
        <span>act</span>
      </div>
      <div className="sidebar__list">
        {visible.map(h => (
          <div key={h.host} className="host">
            <div className="host__top">
              <span className={`host__dot host__dot--${h.state}`} />
              <div className="host__name">{h.host}</div>
              <div className={`host__count ${h.critical ? 'host__count--crit' : 'host__count--zero'}`}>{h.critical || '—'}</div>
              <div className={`host__count ${h.high ? '' : 'host__count--zero'}`}>{h.high || '—'}</div>
            </div>
            <div className="host__os">{h.os} · {h.kernel} · {h.arch}</div>
            <FFAHeartbeatStrip host={h} ticks={30} />
            <div className="host__beat-axis"><span>-30d</span><span>today</span></div>
          </div>
        ))}
      </div>
    </aside>
  );
}

function FFAFooter() {
  return (
    <footer className="footer">
      <a href="#">v2.4.1</a>
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
  );
}

// ── State → Findings props mapping ──────────────────────────
// The brief asks that all six canvas states are reachable. We expose a single
// state-select tweak that switches between them, so the user can click through
// the whole flow in one mount.
//
//   empty            — default-empty (no filter, only filter-bar + empty state)
//   filter-active    — filter committed, all buckets render collapsed
//   bucket-expanded  — escalate bucket open
//   pending-expanded — Pending-Bucket open (cross-server, server column visible)
//   bulk-active      — bulk-selection toolbar visible (one bucket + 3 rows selected)
//   skeleton         — escalate bucket open, body is the 5-row scan-probe skel

const STATE_PROPS = {
  'empty': {
    initialFilterActive: false,
    expandedBucketId: null,
    prefilledSelection: null,
    skeletonBucketId: null,
  },
  'filter-active': {
    initialFilterActive: true,
    expandedBucketId: null,
    prefilledSelection: null,
    skeletonBucketId: null,
  },
  'filter-bucket-expanded': {
    initialFilterActive: true,
    expandedBucketId: 'b-escalate-edge-cy-04-kernel',
    prefilledSelection: null,
    skeletonBucketId: null,
  },
  'filter-pending-expanded': {
    initialFilterActive: true,
    expandedBucketId: 'pending',
    prefilledSelection: null,
    skeletonBucketId: null,
  },
  'filter-bulk-active': {
    initialFilterActive: true,
    expandedBucketId: 'b-escalate-edge-cy-04-kernel',
    prefilledSelection: {
      buckets: [],
      findings: [
        'b-escalate-edge-cy-04-kernel::CVE-2026-31431',
        'b-escalate-edge-cy-04-kernel::CVE-2024-5535',
        'b-escalate-edge-cy-04-kernel::CVE-2024-6387',
      ],
    },
    skeletonBucketId: null,
  },
  'filter-skeleton': {
    initialFilterActive: true,
    expandedBucketId: 'b-escalate-edge-cy-04-kernel',
    prefilledSelection: null,
    skeletonBucketId: 'b-escalate-edge-cy-04-kernel',
  },
};

// ── App ─────────────────────────────────────────────────────
function FFAApp() {
  const [t, setTweak] = useTweaks(FFA_TWEAK_DEFAULTS);

  // Apply tweak-extra fine-grained overrides on top of the chosen state.
  const propsForState = ffaUseMemo(() => {
    const base = { ...(STATE_PROPS[t.state] || STATE_PROPS['empty']) };
    if (t.bulkSelection && !base.prefilledSelection) {
      base.prefilledSelection = {
        buckets: [],
        findings: [
          'b-escalate-edge-cy-04-kernel::CVE-2026-31431',
          'b-escalate-edge-cy-04-kernel::CVE-2024-5535',
          'b-escalate-edge-cy-04-kernel::CVE-2024-6387',
        ],
      };
    }
    if (t.skeletonOnExpanded) {
      base.skeletonBucketId = base.expandedBucketId && base.expandedBucketId !== 'pending'
        ? base.expandedBucketId
        : 'b-escalate-edge-cy-04-kernel';
    }
    return base;
  }, [t.state, t.bulkSelection, t.skeletonOnExpanded]);

  return (
    <>
      <div className="bg-grid" />
      <div className="app">
        <FFATopBar />
        <FFASidebar />
        <main className="main" data-screen-label="Findings · cross-fleet">
          {/* Re-mount on state change so the inner component gets fresh
              initial-filter / expanded / selection values from props. */}
          <Findings key={JSON.stringify(propsForState)} {...propsForState} />
        </main>
        <FFAFooter />
      </div>

      <TweaksPanel title="Tweaks">
        <TweakSection label="Canvas state" />
        <TweakSelect
          label="State"
          value={t.state}
          onChange={(v) => setTweak('state', v)}
          options={[
            { value: 'empty',                    label: 'Default empty (no filter)' },
            { value: 'filter-active',            label: 'Filter active — collapsed buckets' },
            { value: 'filter-bucket-expanded',   label: 'Filter active — bucket expanded' },
            { value: 'filter-pending-expanded',  label: 'Filter active — Pending-Bucket expanded' },
            { value: 'filter-bulk-active',       label: 'Filter active — bulk-selection' },
            { value: 'filter-skeleton',          label: 'Filter active — bucket skeleton' },
          ]}
        />
        <TweakToggle
          label="Bulk selection prefilled"
          value={t.bulkSelection}
          onChange={(v) => setTweak('bulkSelection', v)}
        />
        <TweakToggle
          label="Skeleton on expanded bucket"
          value={t.skeletonOnExpanded}
          onChange={(v) => setTweak('skeletonOnExpanded', v)}
        />
      </TweaksPanel>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<FFAApp />);
