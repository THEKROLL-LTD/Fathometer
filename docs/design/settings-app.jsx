/* SecScan — Settings page app shell.
   Topbar (with Settings added to nav), left settings subnav, main panel slot, footer.
   Tweaks panel switches active subtab + a few state variants. */

const { useState: saUseState, useMemo: saUseMemo, useRef: saUseRef, useEffect: saUseEffect } = React;
const { FLEET: SA_FLEET, heartbeat: saHeartbeat } = window.SECSCAN_DATA;

const SA_TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "tab": "servers",
  "reviewerSubtab": "overview",
  "tagsEmpty": false,
  "groupsEmpty": false,
  "masterKeyRevealed": false
}/*EDITMODE-END*/;

// ── Reused topbar logo (verbatim from the rest of the app) ─────────────
function SALogo({ className = 'topbar__logo' }) {
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

function SAProfileMenu() {
  const [open, setOpen] = saUseState(false);
  const wrapRef = saUseRef(null);
  saUseEffect(() => {
    if (!open) return;
    const onDoc = (e) => { if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false); };
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
          <button type="button" className="profile-menu__item profile-menu__item--active" role="menuitem" aria-current="page">
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

function SATopBar() {
  return (
    <header className="topbar">
      <div className="topbar__brand">
        <SALogo />
        <div className="topbar__wordmark">
          <div className="topbar__wordmark-name">Fathometer</div>
          <div className="topbar__wordmark-sub">CVE Intelligence</div>
        </div>
      </div>
      <div className="topbar__right">
        <nav className="topbar__nav">
          <button className="topbar__navitem">Dashboard</button>
          <button className="topbar__navitem">Findings</button>
        </nav>
        <SAProfileMenu />
      </div>
    </header>
  );
}

// ── Fleet sidebar (verbatim pattern from Findings / Dashboard shell) ───
function SAHeartbeatStrip({ host, ticks = 30 }) {
  const beats = saUseMemo(() => saHeartbeat(host, ticks), [host.host, ticks]);
  return (
    <div className="host__beat">
      {beats.map((b, i) => (
        <div key={i} className={`host__beat-tick beat--${b}`} />
      ))}
    </div>
  );
}

function SAFleetSidebar() {
  const visible = SA_FLEET.slice(0, 8);
  return (
    <aside className="sidebar" data-screen-label="Fleet sidebar">
      <div className="sidebar__filter">
        <input
          className="sidebar__input"
          placeholder="filter hosts                                                ( / )"
          readOnly
        />
      </div>
      <div className="sidebar__meta">
        <span><b>{SA_FLEET.length}</b> hosts · <span style={{ color: 'var(--accent)' }}>fleet view</span></span>
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
            <SAHeartbeatStrip host={h} ticks={30} />
            <div className="host__beat-axis"><span>-30d</span><span>today</span></div>
          </div>
        ))}
      </div>
    </aside>
  );
}

// ── Settings tab nav (horizontal, top of the .main column) ─────────────
const SA_NAV = [
  { id: 'servers',     label: 'Servers' },
  { id: 'tags',        label: 'Tags' },
  { id: 'groups',      label: 'Groups' },
  { id: 'llm',         label: 'LLM Provider' },
  { id: 'reviewer',    label: 'LLM Reviewer' },
  { id: 'master-key',  label: 'Master-Key', badge: 'neu' },
  { id: 'about',       label: 'About' },
];

function SATabs({ tab, onSelect }) {
  return (
    <nav className="settings-tabs" role="tablist" aria-label="Settings sections">
      {SA_NAV.map(item => (
        <button
          key={item.id}
          type="button"
          role="tab"
          aria-selected={tab === item.id}
          className={`settings-tabs__item ${tab === item.id ? 'settings-tabs__item--active' : ''}`}
          onClick={() => onSelect(item.id)}
        >
          <span>{item.label}</span>
          {item.badge && <span className="settings-tabs__badge">{item.badge}</span>}
        </button>
      ))}
    </nav>
  );
}

function SAFooter() {
  return (
    <footer className="footer">
      <a href="#">v2.4.1</a>
      <span className="footer__sep">·</span>
      <a href="#">docs</a>
      <span className="footer__sep">·</span>
      <a href="https://github.com/THEKROLL-LTD/secscan" target="_blank" rel="noopener noreferrer" className="footer__link footer__link--icon">
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

// ── Panel router ───────────────────────────────────────────────────────
function SAPanel({ tab, t }) {
  const P1 = window.SettingsPanels1;
  const P2 = window.SettingsPanels2;
  switch (tab) {
    case 'servers':    return <P1.ServersPanel />;
    case 'tags':       return <P1.TagsPanel empty={t.tagsEmpty} />;
    case 'groups':     return <P1.GroupsPanel empty={t.groupsEmpty} />;
    case 'llm':        return <P2.LLMProviderPanel />;
    case 'reviewer':   return <P2.LLMReviewerPanel subtab={t.reviewerSubtab} />;
    case 'master-key': return <P2.MasterKeyPanel revealed={t.masterKeyRevealed} />;
    case 'about':      return <P2.AboutPanel />;
    default:           return <P1.ServersPanel />;
  }
}

// ── App ────────────────────────────────────────────────────────────────
function SAApp() {
  const [t, setTweak] = useTweaks(SA_TWEAK_DEFAULTS);

  return (
    <>
      <div className="bg-grid" />
      <div className="app">
        <SATopBar />
        <SAFleetSidebar />
        <main className="main" data-screen-label={`Settings · ${t.tab}`}>
          <SATabs tab={t.tab} onSelect={(id) => setTweak('tab', id)} />
          <div className="settings">
            {/* Remount on tab change so each panel gets fresh state. */}
            <SAPanel key={t.tab + ':' + t.reviewerSubtab + ':' + t.tagsEmpty + ':' + t.groupsEmpty + ':' + t.masterKeyRevealed} tab={t.tab} t={t} />
          </div>
        </main>
        <SAFooter />
      </div>

      <TweaksPanel title="Tweaks">
        <TweakSection label="Settings sub-tab" />
        <TweakSelect
          label="Tab"
          value={t.tab}
          onChange={(v) => setTweak('tab', v)}
          options={SA_NAV.map(n => ({ value: n.id, label: n.label }))}
        />
        {t.tab === 'reviewer' && (
          <TweakRadio
            label="Reviewer view"
            value={t.reviewerSubtab}
            options={['overview', 'debug']}
            onChange={(v) => setTweak('reviewerSubtab', v)}
          />
        )}

        <TweakSection label="States" />
        {t.tab === 'tags' && (
          <TweakToggle
            label="Empty state"
            value={t.tagsEmpty}
            onChange={(v) => setTweak('tagsEmpty', v)}
          />
        )}
        {t.tab === 'groups' && (
          <TweakToggle
            label="Empty state"
            value={t.groupsEmpty}
            onChange={(v) => setTweak('groupsEmpty', v)}
          />
        )}
        {t.tab === 'master-key' && (
          <TweakToggle
            label="Show generated key"
            value={t.masterKeyRevealed}
            onChange={(v) => setTweak('masterKeyRevealed', v)}
          />
        )}
        {t.tab !== 'tags' && t.tab !== 'groups' && t.tab !== 'master-key' && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-tertiary)', padding: '8px 0', letterSpacing: '0.02em' }}>
            No state toggles for this tab.
          </div>
        )}
      </TweaksPanel>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<SAApp />);
