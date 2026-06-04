/* SecScan — Settings page app shell.
   Topbar (with Settings added to nav), left settings subnav, main panel slot, footer.
   Tweaks panel switches active subtab + a few state variants. */

const { useState: saUseState, useMemo: saUseMemo } = React;

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
          <button className="topbar__navitem topbar__navitem--active">Settings</button>
        </nav>
        <div className="topbar__profile">
          <button type="button" className="topbar__user" aria-label="Profile menu">SK</button>
        </div>
      </div>
    </header>
  );
}

// ── Settings subnav (left rail) ────────────────────────────────────────
const SA_NAV = [
  { id: 'servers',     label: 'Servers' },
  { id: 'tags',        label: 'Tags' },
  { id: 'groups',      label: 'Groups' },
  { id: 'llm',         label: 'LLM Provider' },
  { id: 'reviewer',    label: 'LLM Reviewer' },
  { id: 'master-key',  label: 'Master-Key', badge: 'neu' },
  { id: 'about',       label: 'About' },
];

function SASubnav({ tab, onSelect }) {
  return (
    <aside className="sidebar settings-nav" data-screen-label="Settings · subnav">
      <div className="settings-nav__eyebrow">Settings</div>
      <div className="settings-nav__list">
        {SA_NAV.map(item => (
          <button
            key={item.id}
            type="button"
            className={`settings-nav__item ${tab === item.id ? 'settings-nav__item--active' : ''}`}
            onClick={() => onSelect(item.id)}
          >
            <span>{item.label}</span>
            {item.badge && <span className="settings-nav__badge">{item.badge}</span>}
          </button>
        ))}
      </div>
    </aside>
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
      <div className="app app--settings">
        <SATopBar />
        <SASubnav tab={t.tab} onSelect={(id) => setTweak('tab', id)} />
        <main className="main" data-screen-label={`Settings · ${t.tab}`}>
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
