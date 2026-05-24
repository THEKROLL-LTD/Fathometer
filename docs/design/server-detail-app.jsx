/* Fathometer — minimal app shell that mounts ServerDetail in the .main slot.
   Reproduces topbar + sidebar + footer chrome from Dashboard.html so the user
   can review the new view in realistic context. The ServerDetail component
   itself only renders the inner content of .main (the brief's hard rule). */

const { useState: sdUseState, useEffect: sdUseEffect, useMemo: sdUseMemo, useRef: sdUseRef, useCallback: sdUseCallback } = React;
const { FLEET: SDX_FLEET, heartbeat: sdxHeartbeat } = window.SECSCAN_DATA;

const SDX_TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "skeletonMode": false,
  "openWorkflow": true,
  "openTriage": true
}/*EDITMODE-END*/;

// ── Fathometer logo (copied verbatim from Dashboard) ──────────
function SDXFathometerLogo({ className = 'topbar__logo' }) {
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

// ── Profile widget (minimal, no dropdown — just the avatar chip) ─
function SDXProfile() {
  return (
    <div className="topbar__profile">
      <button type="button" className="topbar__user" aria-label="Profile menu">SK</button>
    </div>
  );
}

function SDXTopBar() {
  return (
    <header className="topbar">
      <div className="topbar__brand">
        <SDXFathometerLogo />
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
        <SDXProfile />
      </div>
    </header>
  );
}

// ── Compact sidebar — derives from FLEET, the active host is fixed
//    to srv-prod-edge-01 (we add it synthetically since it's not in
//    the dashboard's fleet roster). ───────────────────────────────
const SDX_VIRTUAL_HOST = {
  host: 'srv-prod-edge-01',
  os: 'Ubuntu 22.04.5 LTS',
  kernel: '5.15.0-177-generic',
  arch: 'aarch64',
  lastScan: '11m',
  state: 'alarm',
  critical: 3,
  high: 8,
  medium: 1,
  low: 0,
  pending: 12,
  monitor: 187,
  noise: 120,
};

function SDXHeartbeatStrip({ host, ticks = 30 }) {
  const beats = sdUseMemo(() => sdxHeartbeat(host, ticks), [host.host, ticks]);
  return (
    <div className="host__beat">
      {beats.map((b, i) => (
        <div key={i} className={`host__beat-tick beat--${b}`} />
      ))}
    </div>
  );
}
function SDXSidebar({ activeHost }) {
  // Show a slim host list: virtual host first (active), then a few real hosts
  // from FLEET so the sidebar feels populated.
  const visible = sdUseMemo(() => {
    const real = SDX_FLEET.slice(0, 6);
    return [SDX_VIRTUAL_HOST, ...real];
  }, []);
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
        <span><b>{visible.length}</b> hosts · <span style={{ color: 'var(--accent)' }}>2 alarm</span></span>
      </div>
      <div className="sidebar__colhead">
        <span></span>
        <span>host</span>
        <span>escalate</span>
        <span>act</span>
      </div>
      <div className="sidebar__list">
        {visible.map(h => (
          <div key={h.host} className={`host ${h.host === activeHost ? 'host--active' : ''}`}>
            <div className="host__top">
              <span className={`host__dot host__dot--${h.state}`} />
              <div className="host__name">{h.host}</div>
              <div className={`host__count ${h.critical ? 'host__count--crit' : 'host__count--zero'}`}>{h.critical || '—'}</div>
              <div className={`host__count ${h.high ? '' : 'host__count--zero'}`}>{h.high || '—'}</div>
            </div>
            <div className="host__os">{h.os} · {h.kernel} · {h.arch}</div>
            <SDXHeartbeatStrip host={h} ticks={30} />
            <div className="host__beat-axis"><span>-30d</span><span>today</span></div>
          </div>
        ))}
      </div>
    </aside>
  );
}

function SDXFooter() {
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

// ── App ─────────────────────────────────────────────────────────
function SDXApp() {
  const [t, setTweak] = useTweaks(SDX_TWEAK_DEFAULTS);
  return (
    <>
      <div className="bg-grid" />
      <div className="app">
        <SDXTopBar />
        <SDXSidebar activeHost="srv-prod-edge-01" />
        <main className="main" data-screen-label="Server detail · srv-prod-edge-01">
          {/* ServerDetail re-mounts when skeletonMode changes so the user can
              flip between the loaded view and the skeleton-loading view live. */}
          <ServerDetail key={t.skeletonMode ? 'skel' : 'live'} skeletonMode={t.skeletonMode} />
        </main>
        <SDXFooter />
      </div>
      <TweaksPanel title="Tweaks">
        <TweakSection label="Server detail" />
        <TweakToggle
          label="Skeleton loading state"
          value={t.skeletonMode}
          onChange={(v) => setTweak('skeletonMode', v)}
        />
      </TweaksPanel>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<SDXApp />);
