/* Fathometer — Audit.jsx
   Immutable audit ledger view. Inner content of `.main` only. Mirrors the
   Findings page system: serif header + mono filter-bar + hairline table with
   expandable rows. Cyan is reserved for `alert`-level actions (the single
   signal). No comment/justification inputs — the ledger is read-only.
*/

const AD = window.AUDIT_DATA;
const {
  useState:  audUseState,
  useMemo:   audUseMemo,
  useCallback: audUseCallback,
} = React;

// ── Icons (inline, DS Lucide-style 1.5px) ────────────────────
function IconDownload() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
      <path d="M12 3v14" />
      <path d="M6 11l6 6 6-6" />
      <path d="M4 21h16" />
    </svg>
  );
}

// ── 1) Header ────────────────────────────────────────────────
function AuditHeader() {
  return (
    <div className="audit__header">
      <div>
        <p className="sd-eyebrow">Ledger</p>
        <h1 className="audit__title">Audit log</h1>
      </div>
      <div className="audit__header-right">
        <span className="audit__counter">
          <b>{AD.TOTAL_ENTRIES.toLocaleString('de-DE')}</b> Einträge
          <span className="sep">·</span>
          Seite <b>{AD.PAGE}</b> / {AD.PAGES}
        </span>
        <button type="button" className="audit__export">
          <IconDownload />
          <span>CSV export</span>
        </button>
      </div>
    </div>
  );
}

// ── 2) Activity strip ────────────────────────────────────────
function ActivityStrip() {
  const peakIdx = audUseMemo(
    () => AD.VOLUME.indexOf(AD.VOLUME_MAX),
    []
  );
  return (
    <div className="audit__activity" role="img" aria-label={`${AD.VOLUME_TOTAL} Ereignisse in den letzten 24 Stunden`}>
      <div className="audit__activity-head">
        <span className="audit__activity-label">Aktivität · letzte 24 h</span>
        <span className="audit__activity-total"><b>{AD.VOLUME_TOTAL.toLocaleString('de-DE')}</b> Ereignisse</span>
      </div>
      <div className="audit__bars">
        {AD.VOLUME.map((v, i) => (
          <div
            key={i}
            className={`audit__bar ${i === peakIdx ? 'audit__bar--peak' : ''}`}
            style={{ height: `${Math.max(6, Math.round((v / AD.VOLUME_MAX) * 100))}%` }}
            title={`${v} Ereignisse`}
          />
        ))}
      </div>
      <div className="audit__bars-axis">
        <span>-24h</span>
        <span>-12h</span>
        <span>jetzt</span>
      </div>
    </div>
  );
}

// ── 3) Filter-bar ────────────────────────────────────────────
function FilterBar({ draft, setDraft, onSubmit, onReset }) {
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value });
  return (
    <form
      className="audit__filter-bar"
      role="search"
      onSubmit={(e) => { e.preventDefault(); onSubmit(); }}
    >
      <div className="audit__field">
        <label className="audit__field-label" htmlFor="aud-from">von</label>
        <input id="aud-from" className="ff-input ff-date" type="date" value={draft.from} onChange={set('from')} />
      </div>
      <div className="audit__field">
        <label className="audit__field-label" htmlFor="aud-to">bis</label>
        <input id="aud-to" className="ff-input ff-date" type="date" value={draft.to} onChange={set('to')} />
      </div>
      <div className="audit__field">
        <label className="audit__field-label" htmlFor="aud-actor">Actor</label>
        <input id="aud-actor" className="ff-input ff-actor" type="text" value={draft.actor} onChange={set('actor')} placeholder="username / server-name" />
      </div>
      <div className="audit__field">
        <label className="audit__field-label" htmlFor="aud-action">Action</label>
        <select id="aud-action" className="ff-select" value={draft.action} onChange={set('action')}>
          <option value="">— alle —</option>
          {AD.ACTIONS.map(a => <option key={a.id} value={a.id}>{a.id}</option>)}
        </select>
      </div>
      <div className="audit__field">
        <label className="audit__field-label" htmlFor="aud-server">Server name</label>
        <input id="aud-server" className="ff-input ff-server" type="text" value={draft.server} onChange={set('server')} placeholder="substring" />
      </div>
      <div className="audit__field">
        <label className="audit__field-label" htmlFor="aud-tag">Tag</label>
        <select id="aud-tag" className="ff-select" value={draft.tag} onChange={set('tag')}>
          <option value="">— alle —</option>
          {AD.TAGS.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      <div className="audit__filter-actions">
        <button type="submit" className="ff-submit">
          <span>filter</span>
          <span aria-hidden="true">→</span>
        </button>
        <button type="button" className="ff-reset" onClick={onReset}>zurücksetzen</button>
      </div>
    </form>
  );
}

// ── Active filter chips ──────────────────────────────────────
const CHIP_LABEL = { from: 'von', to: 'bis', actor: 'actor', action: 'action', server: 'server', tag: 'tag' };

function FilterChips({ filter, onRemove }) {
  const chips = Object.keys(CHIP_LABEL).filter(k => filter[k]);
  if (chips.length === 0) return null;
  return (
    <div className="audit__filter-chips" role="region" aria-label="Aktive Filter">
      {chips.map(k => (
        <span key={k} className="ff-chip">
          <b>{CHIP_LABEL[k]}</b>
          <span>{filter[k]}</span>
          <button type="button" className="ff-chip__x" aria-label={`Filter ${CHIP_LABEL[k]} entfernen`} onClick={() => onRemove(k)}>×</button>
        </span>
      ))}
    </div>
  );
}

// ── 4) Log row ───────────────────────────────────────────────
const HUMAN_ACTORS = new Set(['sven']);

function metaIsAccent(k, v) {
  if (k === 'kev' && v === true) return true;
  if (k === 'band' && v === 'escalate') return true;
  if (k === 'dlq' && v === true) return true;
  return false;
}

function AuditRow({ e }) {
  const isHuman = HUMAN_ACTORS.has(e.actor);
  const metaEntries = Object.entries(e.meta);
  return (
    <details className={`audit-row ${e.level === 'alert' ? 'audit-row--alert' : ''}`}>
      <summary className="audit-row__summary">
        <div className="audit-row__time">
          <div className="audit-row__time-rel">{e.timeRel}</div>
          <div className="audit-row__time-abs">{e.timeAbs}</div>
        </div>
        <div className={`audit-row__actor ${isHuman ? 'audit-row__actor--human' : ''}`}>{e.actor}</div>
        <div className="audit-row__action">
          <span className={`audit-pill ${e.level === 'alert' ? 'audit-pill--alert' : e.level === 'notice' ? 'audit-pill--notice' : ''}`} title={e.action}>
            {e.action}
          </span>
        </div>
        <div className="audit-row__target" title={e.target}>{renderTarget(e.target)}</div>
        <div className="audit-row__meta-cell">
          {e.comment
            ? <span className="audit-row__comment" title={e.comment}>{e.comment}</span>
            : <span className="audit-row__meta-toggle"><span className="tri" aria-hidden="true">▸</span> metadata</span>}
        </div>
        <span className="audit-row__chev" aria-hidden="true">›</span>
      </summary>
      <div className="audit-row__body">
        <p className="audit-row__body-eyebrow">Metadata</p>
        <div className="audit-meta-grid">
          {metaEntries.map(([k, v]) => (
            <div key={k} className="audit-meta-kv">
              <span className="audit-meta-kv__k">{k}</span>
              <span className={`audit-meta-kv__v ${metaIsAccent(k, v) ? 'audit-meta-kv__v--accent' : ''}`}>{String(v)}</span>
            </div>
          ))}
        </div>
        <div className="audit-row__raw">
          <span><b>tag</b> {e.tag}</span>
          <span><b>level</b> {e.level}</span>
          <span><b>event_id</b> {e.id}</span>
          {e.comment && <span><b>comment</b> {e.comment}</span>}
        </div>
      </div>
    </details>
  );
}

// Bold the numeric id portion of a target like "llm_job 6682".
function renderTarget(target) {
  const m = /^(.*?)(\s)(\S+)$/.exec(target);
  if (!m) return target;
  return (<>{m[1]} <b>{m[3]}</b></>);
}

// ── 5) Pager ─────────────────────────────────────────────────
function Pager({ page, pages }) {
  // Compact window: 1 … 3 4 [5] 6 7 … N
  const nums = audUseMemo(() => {
    const out = new Set([1, pages, page, page - 1, page + 1, page - 2, page + 2]);
    return [...out].filter(n => n >= 1 && n <= pages).sort((a, b) => a - b);
  }, [page, pages]);

  const withGaps = [];
  let prev = 0;
  for (const n of nums) {
    if (n - prev > 1) withGaps.push('gap-' + n);
    withGaps.push(n);
    prev = n;
  }

  return (
    <div className="audit__footer">
      <span>{AD.TOTAL_ENTRIES.toLocaleString('de-DE')} Einträge · Seite {page} von {pages}</span>
      <span className="audit__pager">
        <button type="button" disabled={page <= 1} aria-label="Vorherige Seite">‹</button>
        {withGaps.map(item =>
          typeof item === 'number'
            ? <button key={item} type="button" className={item === page ? 'is-current' : ''} aria-current={item === page ? 'page' : undefined}>{item}</button>
            : <span key={item} className="gap" aria-hidden="true">…</span>
        )}
        <button type="button" aria-label="Nächste Seite">›</button>
      </span>
    </div>
  );
}

// ── Top-level Audit page ─────────────────────────────────────
function Audit({ initialFilter = null } = {}) {
  const EMPTY = { from: '', to: '', actor: '', action: '', server: '', tag: '' };
  const start = initialFilter ? { ...EMPTY, ...initialFilter } : EMPTY;

  const [draft, setDraft]   = audUseState(start);
  const [filter, setFilter] = audUseState(start);

  const onSubmit = audUseCallback(() => setFilter({ ...draft }), [draft]);
  const onReset  = audUseCallback(() => { setDraft(EMPTY); setFilter(EMPTY); }, []);
  const removeChip = audUseCallback((k) => {
    const next = { ...filter, [k]: '' };
    setFilter(next); setDraft(next);
  }, [filter]);

  // Demo filtering: action + actor/server substring + tag narrow the visible
  // rows so the filter feels live. Dates are display-only (ledger is one day).
  const rows = audUseMemo(() => {
    return AD.ENTRIES.filter(e => {
      if (filter.action && e.action !== filter.action) return false;
      if (filter.tag && e.tag !== filter.tag) return false;
      if (filter.actor) {
        const q = filter.actor.toLowerCase();
        if (!(e.actor.toLowerCase().includes(q) || e.target.toLowerCase().includes(q))) return false;
      }
      if (filter.server) {
        const q = filter.server.toLowerCase();
        const hay = (e.target + ' ' + JSON.stringify(e.meta)).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [filter]);

  return (
    <div className="audit">
      <AuditHeader />
      <ActivityStrip />
      <FilterBar draft={draft} setDraft={setDraft} onSubmit={onSubmit} onReset={onReset} />
      <FilterChips filter={filter} onRemove={removeChip} />

      <div className="audit__log">
        <div className="audit-head">
          <span>Time</span>
          <span>Actor</span>
          <span>Action</span>
          <span>Target</span>
          <span>Comment / Metadata</span>
          <span aria-hidden="true"></span>
        </div>
        {rows.map(e => <AuditRow key={e.id} e={e} />)}
      </div>

      <Pager page={AD.PAGE} pages={AD.PAGES} />
    </div>
  );
}

window.Audit = Audit;
