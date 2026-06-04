/* SecScan — Settings panels (LLM Provider, LLM Reviewer, Master-Key, About). */

const { SHeader, SSection } = window.SettingsPanels1;
const { useState: sUseState2, useEffect: sUseEffect2 } = React;

// ──────────────────────────────────────────────────────────────────────
//   LLM-Provider
// ──────────────────────────────────────────────────────────────────────
function LLMProviderPanel() {
  const [preset, setPreset] = sUseState2('custom');
  const [name, setName]     = sUseState2('novita');
  const [base, setBase]     = sUseState2('https://api.novita.ai/openai');
  const [model, setModel]   = sUseState2('openai/gpt-oss-120b');
  const [apiKey, setApiKey] = sUseState2('');
  const [cap, setCap]       = sUseState2(1_000_000);

  return (
    <div data-screen-label="Settings · LLM Provider">
      <SHeader eyebrow="Settings · 04 / 07" title="LLM Provider">
        Konfiguration für die „Bewertung anfordern"-Funktion auf der Server-Detail-Seite.
        Wechsel von Provider oder Modell archiviert alle aktiven Bewertungen.
      </SHeader>

      <SSection label="Active provider">
        <div className="s-card">
          <div className="s-fields-grid">
            <div className="s-field">
              <label className="s-field__label">Preset</label>
              <select className="s-select" value={preset} onChange={e => setPreset(e.target.value)}>
                <option value="custom">— frei wählen —</option>
                <option value="openai">OpenAI · gpt-4o-mini</option>
                <option value="anthropic">Anthropic · claude-haiku</option>
                <option value="novita">Novita · openai/gpt-oss-120b</option>
                <option value="ollama">Ollama · localhost</option>
              </select>
              <span className="s-field__hint">Setzt Base-URL und Modell. API-Key musst du selbst eintragen.</span>
            </div>
            <div className="s-field">
              <label className="s-field__label">Display name</label>
              <input className="s-input" value={name} onChange={e => setName(e.target.value)} />
              <span className="s-field__hint">Erscheint im Server-Detail neben jeder Bewertung.</span>
            </div>
            <div className="s-field s-field--span">
              <label className="s-field__label">Base URL</label>
              <input className="s-input s-input--mono" value={base} onChange={e => setBase(e.target.value)} />
              <span className="s-field__hint">HTTPS oder http://localhost / http://127.0.0.1.</span>
            </div>
            <div className="s-field">
              <label className="s-field__label">Model name</label>
              <input className="s-input s-input--mono" value={model} onChange={e => setModel(e.target.value)} />
            </div>
            <div className="s-field">
              <label className="s-field__label">API Key</label>
              <input className="s-input s-input--mono" type="password" placeholder="•••• gesetzt — leer lassen zum Behalten" value={apiKey} onChange={e => setApiKey(e.target.value)} />
              <span className="s-field__hint">Neuen Wert eintragen, um den bestehenden Key zu ersetzen.</span>
            </div>
          </div>

          <hr className="s-card__divider" />

          <div className="s-fields-grid">
            <div className="s-field">
              <label className="s-field__label">Daily token cap</label>
              <input className="s-input s-input--mono" type="number" value={cap} onChange={e => setCap(Number(e.target.value))} />
              <span className="s-field__hint">Reset 00:00 UTC. 80 % löst Warn-Banner aus, 100 % hartes 429.</span>
            </div>
            <div className="s-field">
              <label className="s-field__label">Today</label>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 14 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 22, color: 'var(--text-primary)' }}>16 000</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-tertiary)', letterSpacing: '0.04em' }}>/ {cap.toLocaleString('de-DE')} · 1.6 %</span>
              </div>
              <div style={{ height: 2, background: 'var(--border-subtle)', marginTop: 8, position: 'relative' }}>
                <div style={{ position: 'absolute', inset: 0, width: '1.6%', background: 'var(--text-secondary)' }} />
              </div>
            </div>
          </div>

          <div className="s-actions">
            <span className="s-actions__hint">
              „Verbindung testen" probiert den aktuell <b style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>gespeicherten</b> Provider — nicht die hier editierten Werte. Erst speichern, dann testen.
            </span>
            <div className="s-actions__spacer" />
            <button type="button" className="s-btn">Verbindung testen</button>
            <button type="button" className="s-btn s-btn--primary">Speichern</button>
          </div>
        </div>
      </SSection>

      <SSection label="External feeds" meta="read-only">
        <div className="s-feeds">
          <div className="s-feed">
            <p className="s-feed__name">EPSS</p>
            <div className="s-feed__value">335 449 entries</div>
            <div className="s-feed__meta">letzter Pull 2026-05-27 15:44 UTC</div>
          </div>
          <div className="s-feed">
            <p className="s-feed__name">CISA KEV</p>
            <div className="s-feed__value">1 603 entries</div>
            <div className="s-feed__meta">letzter Pull 2026-05-27 15:14 UTC</div>
          </div>
        </div>
      </SSection>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
//   LLM Reviewer  (Overview + Debug Log via internal sub-tabs)
// ──────────────────────────────────────────────────────────────────────
const REVIEWER_GROUPS = [
  { label: 'tailscale',                          kind: 'application_bundle', last: '3 days ago' },
  { label: 'trivy',                              kind: 'application_bundle', last: '3 days ago' },
  { label: 'k3s',                                kind: 'application_bundle', last: '3 days ago' },
  { label: 'longhorn',                           kind: 'application_bundle', last: '3 days ago' },
  { label: 'linux-modules-extra-5.15.0-179-generic', kind: 'os_package',     last: '3 days ago' },
];

const DEBUG_LINES = [
  { t: '15:44:21', level: 'info',  msg: 'job picked',          meta: 'id=j-9c7a · group=tailscale · attempt=1' },
  { t: '15:44:23', level: 'info',  msg: 'prompt assembled',    meta: '1 218 tokens · context=audit' },
  { t: '15:44:31', level: 'done',  msg: 'job complete',        meta: 'id=j-9c7a · 8.4 s · 1 218 → 412 tokens' },
  { t: '15:44:42', level: 'info',  msg: 'job picked',          meta: 'id=j-9c7b · group=trivy · attempt=1' },
  { t: '15:44:50', level: 'warn',  msg: 'provider 429 — backoff 30 s', meta: 'provider=novita · cap=1 000 000' },
  { t: '15:45:20', level: 'info',  msg: 'job retried',         meta: 'id=j-9c7b · attempt=2' },
  { t: '15:45:31', level: 'done',  msg: 'job complete',        meta: 'id=j-9c7b · 11.2 s · 1 042 → 387 tokens' },
  { t: '15:45:44', level: 'error', msg: 'job failed · upstream timeout', meta: 'id=j-9c7c · group=k3s · attempt=3' },
  { t: '15:45:44', level: 'info',  msg: 'audit·event=llm_review.failed', meta: 'id=j-9c7c' },
  { t: '15:46:02', level: 'info',  msg: 'job picked',          meta: 'id=j-9c7d · group=longhorn · attempt=1' },
  { t: '15:46:11', level: 'done',  msg: 'job complete',        meta: 'id=j-9c7d · 9.1 s · 1 384 → 502 tokens' },
];

function ReviewerOverview() {
  return (
    <>
      {/* Top status strip — mode + model + worker on one line */}
      <div className="s-statusbar">
        <div className="s-statusbar__cell">
          <span className="s-statusbar__label">Mode</span>
          <span className="s-statusbar__value s-statusbar__value--accent">live</span>
        </div>
        <div className="s-statusbar__cell">
          <span className="s-statusbar__label">Active model</span>
          <span className="s-statusbar__value">openai/gpt-oss-120b</span>
        </div>
        <div className="s-statusbar__cell">
          <span className="s-statusbar__label">Worker</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--status-operational)', boxShadow: '0 0 6px rgba(57,255,20,0.45)' }} />
            <span className="s-statusbar__value">healthy · heartbeat just now</span>
          </span>
        </div>
        <button type="button" className="s-btn">Change mode…</button>
      </div>

      {/* Concurrency */}
      <section className="s-section">
        <div className="s-section__head">
          <h2 className="s-section__label">Worker concurrency</h2>
          <span className="s-section__meta">Hot-reload, no pod restart needed</span>
        </div>
        <div className="s-slider-row">
          <span className="s-slider-row__value">10</span>
          <input type="range" min="1" max="200" defaultValue="10" />
          <span className="s-slider-row__range">1 – 200</span>
          <button type="button" className="s-btn s-btn--primary">Apply</button>
        </div>
        <p className="s-section__hint">
          Parallele LLM-Jobs im Worker. Hot-Reload binnen 30 s nach Änderung. Live-Werte
          (in_flight, Durchsatz) im Container-Log via <code style={{ color: 'var(--text-primary)' }}>llm_worker.status</code>.
        </p>
      </section>

      {/* Job queue */}
      <section className="s-section">
        <div className="s-section__head">
          <h2 className="s-section__label">Job queue</h2>
          <span className="s-section__meta">live</span>
        </div>
        <div className="s-kpis">
          <div className="s-kpi"><p className="s-kpi__label">Queued</p><div className="s-kpi__num s-kpi__num--zero">0</div></div>
          <div className="s-kpi"><p className="s-kpi__label">In progress</p><div className="s-kpi__num s-kpi__num--zero">0</div></div>
          <div className="s-kpi"><p className="s-kpi__label">Done · 24h</p><div className="s-kpi__num">8</div></div>
          <div className="s-kpi"><p className="s-kpi__label">Failed · 24h</p><div className="s-kpi__num s-kpi__num--alarm">1</div></div>
        </div>
        <div style={{ marginTop: 18, display: 'flex', gap: 12 }}>
          <button type="button" className="s-btn s-btn--sm">Requeue backlog</button>
          <button type="button" className="s-btn s-btn--sm s-btn--ghost">Open debug log →</button>
        </div>
      </section>

      {/* Two-up: token budget + risk cache */}
      <section className="s-section">
        <div className="s-section__head">
          <h2 className="s-section__label">Budget & cache</h2>
        </div>
        <div className="s-twoup">
          <div>
            <div className="s-kv">
              <div className="s-kv__k">Used today</div>
              <div className="s-kv__v">16 000</div>
              <div className="s-kv__k">Daily limit</div>
              <div className="s-kv__v">2 000 000</div>
              <div className="s-kv__k">Reset</div>
              <div className="s-kv__v">2026-05-29 00:00 UTC</div>
            </div>
            <div style={{ height: 2, background: 'var(--border-subtle)', marginTop: 14, position: 'relative' }}>
              <div style={{ position: 'absolute', inset: 0, width: '0.8%', background: 'var(--text-secondary)' }} />
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-tertiary)', letterSpacing: '0.04em', marginTop: 8 }}>
              0.8 % of daily cap consumed
            </div>
          </div>
          <div>
            <div className="s-kv">
              <div className="s-kv__k">Risk-cache entries</div>
              <div className="s-kv__v">136</div>
              <div className="s-kv__k">Hit-rate (7d)</div>
              <div className="s-kv__v" style={{ color: 'var(--text-tertiary)' }}>n/a</div>
              <div className="s-kv__k">Last evicted</div>
              <div className="s-kv__v" style={{ color: 'var(--text-tertiary)' }}>—</div>
            </div>
            <p className="s-section__hint" style={{ marginTop: 14 }}>
              Audit-basierte Cache-Trefferquote wird in einem späteren Block ergänzt.
            </p>
          </div>
        </div>
      </section>

      {/* Application Group Library */}
      <section className="s-section">
        <div className="s-section__head">
          <h2 className="s-section__label">Application Group Library</h2>
          <span className="s-section__meta">41 groups</span>
        </div>
        <div className="s-table">
          <div className="s-table__head" style={{ gridTemplateColumns: 'minmax(0, 1.6fr) 180px 140px' }}>
            <span>Label</span>
            <span>Group kind</span>
            <span className="s-table__cell--right">Last used</span>
          </div>
          {REVIEWER_GROUPS.map(g => (
            <div key={g.label} className="s-table__row" style={{ gridTemplateColumns: 'minmax(0, 1.6fr) 180px 140px' }}>
              <span>{g.label}</span>
              <span style={{ color: 'var(--text-tertiary)' }}>{g.kind}</span>
              <span className="s-table__cell--right" style={{ color: 'var(--text-tertiary)' }}>{g.last}</span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}

function ReviewerDebugLog() {
  const [filter, setFilter] = sUseState2('');
  const [level, setLevel]   = sUseState2('all');
  const filtered = DEBUG_LINES.filter(l =>
    (level === 'all' || l.level === level) &&
    (filter === '' || (l.msg + ' ' + l.meta).toLowerCase().includes(filter.toLowerCase()))
  );
  return (
    <>
      <div className="s-log-filters">
        <input
          className="s-input"
          placeholder="filter log…  ( / )"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
        <select className="s-select" style={{ width: 140 }} value={level} onChange={e => setLevel(e.target.value)}>
          <option value="all">All levels</option>
          <option value="info">info</option>
          <option value="done">done</option>
          <option value="warn">warn</option>
          <option value="error">error</option>
        </select>
        <button type="button" className="s-btn s-btn--sm">Pause</button>
        <button type="button" className="s-btn s-btn--sm s-btn--ghost">Copy</button>
      </div>
      <div className="s-log">
        {filtered.map((l, i) => (
          <div key={i} className="s-log__line">
            <span className="s-log__time">{l.t}</span>
            <span className={`s-log__level s-log__level--${l.level}`}>{l.level}</span>
            <span className="s-log__msg">
              {l.msg}<br />
              <span className="s-log__meta">{l.meta}</span>
            </span>
          </div>
        ))}
      </div>
      <p className="s-section__hint" style={{ marginTop: 16 }}>
        Read-only Sub-View. Letzte ~500 Zeilen, gestreamt aus <code style={{ color: 'var(--text-primary)' }}>llm_worker</code>.
      </p>
    </>
  );
}

function LLMReviewerPanel({ subtab = 'overview' }) {
  const [tab, setTab] = sUseState2(subtab);
  sUseEffect2(() => { setTab(subtab); }, [subtab]);
  return (
    <div data-screen-label={`Settings · LLM Reviewer · ${tab}`}>
      <SHeader eyebrow="Settings · 05 / 07" title="LLM Risk Reviewer">
        Asynchroner LLM-Worker für Application-Grouping und Risiko-Bewertung (ADR-0023).
        Wechsel des Modes erfordert die Master-Key-Bestätigung.
      </SHeader>
      <div className="s-subtabs" role="tablist">
        <button type="button" role="tab" className={`s-subtabs__item ${tab === 'overview' ? 's-subtabs__item--active' : ''}`} onClick={() => setTab('overview')}>Overview</button>
        <button type="button" role="tab" className={`s-subtabs__item ${tab === 'debug' ? 's-subtabs__item--active' : ''}`} onClick={() => setTab('debug')}>Debug log</button>
      </div>
      {tab === 'overview' ? <ReviewerOverview /> : <ReviewerDebugLog />}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
//   Master-Key
// ──────────────────────────────────────────────────────────────────────
function MasterKeyPanel({ revealed = false }) {
  const [shown, setShown] = sUseState2(revealed);
  return (
    <div data-screen-label="Settings · Master-Key">
      <SHeader eyebrow="Settings · 06 / 07" title="Master-Key">
        Der Master-Key authentifiziert die Registrierung neuer Server und die Rotation
        von Server-Keys. Er wird nur einmalig im Klartext angezeigt — bitte sicher notieren.
      </SHeader>

      <SSection label="Current key">
        <div className="s-key-status">
          <div>
            <div className="s-key-status__row">
              <span className="label">Status</span>
              <span className="v" style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--status-operational)', boxShadow: '0 0 6px rgba(57,255,20,0.45)' }} />
                active
              </span>
            </div>
            <div className="s-key-status__row">
              <span className="label">Last rotation</span>
              <span className="v">vor 11 Tagen · 2026-05-17 09:21 UTC</span>
            </div>
            <div className="s-key-status__row">
              <span className="label">Audit event</span>
              <span className="v"><code>master_key.rotated</code></span>
            </div>
          </div>
        </div>
      </SSection>

      <SSection label="Rotate the master-key">
        <div className="s-warning">
          <svg className="s-warning__icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" aria-hidden="true">
            <path d="M12 9v4" />
            <path d="M12 17h.01" />
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          </svg>
          <span>
            <b>Bei Rotation</b> bleiben alte Server-Keys gültig. Neue Registrierungen
            brauchen ab sofort den neuen Master-Key. Der Klartext-Key wird einmalig nach
            Generation angezeigt — speichere ihn sicher.
          </span>
        </div>

        <button type="button" className="s-btn s-btn--primary" onClick={() => setShown(true)}>
          Neuen Master-Key generieren
        </button>

        {shown && (
          <div className="s-key-reveal">
            <div className="s-key-reveal__label">Neuer Master-Key — einmalig angezeigt</div>
            <div className="s-key-reveal__value">mk_2026_d8f1a47e0c93b6e2891f7c4a5b3e6d28aa1c95f0742b6e3</div>
            <div className="s-key-reveal__warn">
              Kopiere den Key jetzt. Nach Schließen dieses Tabs ist er nicht mehr abrufbar.
            </div>
            <div style={{ marginTop: 14, display: 'flex', gap: 10 }}>
              <button type="button" className="s-btn s-btn--sm">Copy</button>
              <button type="button" className="s-btn s-btn--sm s-btn--ghost" onClick={() => setShown(false)}>I have stored it</button>
            </div>
          </div>
        )}
      </SSection>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
//   About
// ──────────────────────────────────────────────────────────────────────
function AboutPanel() {
  return (
    <div data-screen-label="Settings · About">
      <SHeader eyebrow="Settings · 07 / 07" title="About">
        Versions- und Build-Informationen. Read-only.
      </SHeader>

      <SSection label="Build">
        <dl className="s-about-grid">
          <dt>App version</dt>            <dd>0.1.0</dd>
          <dt>Build revision</dt>         <dd>dev</dd>
          <dt>DB schema (Alembic)</dt>    <dd>0015_findings_covering_idx</dd>
          <dt>Python</dt>                 <dd>3.13.9</dd>
          <dt>Flask</dt>                  <dd>3.1.3</dd>
          <dt>SQLAlchemy</dt>             <dd>2.0.49</dd>
        </dl>
      </SSection>

      <SSection label="Runtime">
        <dl className="s-about-grid">
          <dt>Trivy-DB stale</dt>         <dd><span className="warn">2 servers</span></dd>
          <dt>Healthcheck</dt>            <dd><a href="#" onClick={e => e.preventDefault()}>/healthz</a></dd>
          <dt>License</dt>                <dd>Internal · THEKROLL LTD</dd>
          <dt>Source</dt>                 <dd><a href="#" onClick={e => e.preventDefault()}>github.com/THEKROLL-LTD/secscan</a></dd>
        </dl>
      </SSection>
    </div>
  );
}

window.SettingsPanels2 = { LLMProviderPanel, LLMReviewerPanel, MasterKeyPanel, AboutPanel };
