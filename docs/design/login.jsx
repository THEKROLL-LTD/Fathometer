/* Fathometer Login — minimal authentication page.
   Shares design tokens + styles with Dashboard.html.
   No signup, no reset, no SSO — username + password only. */

const { useState, useRef } = React;

// ── Fathometer logo (inline copy — keep login.jsx self-contained) ──
function FathometerLogo({ className = 'topbar__logo' }) {
  return (
    <svg viewBox="0 0 64 64" className={className} role="img" aria-label="Fathometer">
      <path d="M 8 32 A 24 24 0 0 1 56 32"
            fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" />
      <line x1="8"  y1="32" x2="11.5" y2="32" stroke="currentColor" strokeWidth="1.25" />
      <line x1="32" y1="8"  x2="32"   y2="11.5" stroke="currentColor" strokeWidth="1.25" />
      <line x1="56" y1="32" x2="52.5" y2="32" stroke="currentColor" strokeWidth="1.25" />
      <line x1="2" y1="32" x2="62" y2="32" stroke="currentColor" strokeWidth="0.85" opacity="0.55" />
      <path d="M 4 49 Q 12 44 20 49 T 36 49 T 52 49 T 60 49"
            fill="none" stroke="currentColor" strokeWidth="1" opacity="0.45" strokeLinecap="square" />
      <g className="topbar__logo-sweep">
        <line x1="32" y1="32" x2="32" y2="10"
              stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="square" />
        <circle cx="32" cy="10" r="2.6" fill="var(--accent)" className="topbar__logo-echo" />
      </g>
      <circle cx="32" cy="32" r="1.6" fill="currentColor" />
    </svg>
  );
}

function TopBar() {
  return (
    <header className="topbar topbar--auth">
      <div className="topbar__brand">
        <FathometerLogo />
        <div className="topbar__wordmark">
          <div className="topbar__wordmark-name">Fathometer</div>
          <div className="topbar__wordmark-sub">CVE Intelligence</div>
        </div>
      </div>
    </header>
  );
}

function Footer() {
  return (
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
  );
}

function AuthPanel() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const userRef = useRef(null);

  function onSubmit(e) {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('credentials required');
      userRef.current?.focus();
      return;
    }
    setError(null);
    setBusy(true);
    // Mock auth — pretend we're checking, then route to the dashboard.
    setTimeout(() => { window.location.href = 'Dashboard.html'; }, 800);
  }

  return (
    <section className="auth">
      <div className="auth__panel">
        <p className="auth__eyebrow">
          <span className="auth__prompt">&gt;</span>
          <span>authenticate</span>
        </p>
        <h1 className="auth__title">Operator credentials.</h1>
        <p className="auth__sub">No signup. No reset. No SSO. Internal operators only.</p>

        <form className="auth__form" onSubmit={onSubmit} noValidate>
          <label className="auth__field">
            <span className="auth__field-label">username</span>
            <input
              ref={userRef}
              type="text"
              className="auth__input"
              autoComplete="username"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck="false"
              value={username}
              onChange={(e) => { setUsername(e.target.value); if (error) setError(null); }}
              disabled={busy}
            />
          </label>

          <label className="auth__field">
            <span className="auth__field-label">password</span>
            <input
              type="password"
              className="auth__input"
              autoComplete="current-password"
              value={password}
              onChange={(e) => { setPassword(e.target.value); if (error) setError(null); }}
              disabled={busy}
            />
          </label>

          <div className="auth__status" role="status" aria-live="polite">
            {error
              ? <span className="auth__error"><span className="bracket">[</span>access denied<span className="bracket">]</span> &nbsp;·&nbsp; {error}</span>
              : busy
                ? <span className="auth__pending"><span className="auth__prompt">&gt;</span> verifying…</span>
                : null}
          </div>

          <button type="submit" className={`auth__submit ${busy ? 'auth__submit--busy' : ''}`} disabled={busy}>
            <span>{busy ? 'verifying' : 'authenticate'}</span>
            <span className="auth__submit-arrow">→</span>
          </button>
        </form>
      </div>
    </section>
  );
}

function App() {
  return (
    <>
      <div className="bg-grid" />
      <div className="app app--auth">
        <TopBar />
        <main className="main main--auth">
          <AuthPanel />
        </main>
        <Footer />
      </div>
    </>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
