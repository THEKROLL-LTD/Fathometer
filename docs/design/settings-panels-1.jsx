/* SecScan — Settings panels (Servers, Tags, Groups, LLM, Reviewer, Master-Key, About).
   Loaded as JSX. Each panel renders the inner content of `.settings`.
   No state lives here that other panels need — switching panels is a hard remount. */

const { useState: sUseState, useMemo: sUseMemo, useRef: sUseRef, useEffect: sUseEffect } = React;

// ── Shared bits ────────────────────────────────────────────────────────
function SHeader({ eyebrow, title, children }) {
  return (
    <>
      <p className="settings__eyebrow">{eyebrow}</p>
      <h1 className="settings__title">{title}</h1>
      <p className="settings__lede">{children}</p>
    </>
  );
}

function SSection({ label, meta, children, hint }) {
  return (
    <section className="s-section">
      <div className="s-section__head">
        <h2 className="s-section__label">{label}</h2>
        {meta && <span className="s-section__meta">{meta}</span>}
      </div>
      {children}
      {hint && <p className="s-section__hint">{hint}</p>}
    </section>
  );
}

function StatusPill({ kind, children }) {
  return (
    <span className={`s-pill s-pill--${kind}`}>
      <span className="s-pill__dot" aria-hidden="true" />
      <span>{children}</span>
    </span>
  );
}

function OverflowMenu({ items }) {
  const [open, setOpen] = sUseState(false);
  const ref = sUseRef(null);
  sUseEffect(() => {
    if (!open) return;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);
  return (
    <div className={`s-overflow ${open ? 's-overflow--open' : ''}`} ref={ref}>
      <button
        type="button"
        className="s-overflow__btn"
        onClick={() => setOpen(o => !o)}
        aria-label="Actions"
        aria-expanded={open}
      >
        <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
          <circle cx="3" cy="8" r="1.3" /><circle cx="8" cy="8" r="1.3" /><circle cx="13" cy="8" r="1.3" />
        </svg>
      </button>
      {open && (
        <div className="s-overflow__menu" role="menu">
          {items.map((it, i) => (
            <button
              key={i}
              type="button"
              role="menuitem"
              className={`s-overflow__item ${it.danger ? 's-overflow__item--danger' : ''}`}
              onClick={() => { setOpen(false); it.onClick?.(); }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
//   Servers
// ──────────────────────────────────────────────────────────────────────
const SERVERS = [
  { host: 'rke2-sv-1', os: 'Ubuntu 22.04.5 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', tags: [],            last: 'vor 8h', status: 'active'  },
  { host: 'rke2-sv-0', os: 'Ubuntu 22.04.5 LTS', kernel: '5.15.0-177-generic', arch: 'aarch64', tags: ['prod'],      last: 'vor 7h', status: 'active'  },
  { host: 'mail-edge', os: 'Debian 12.5',         kernel: '6.1.0-21-amd64',    arch: 'x86_64',  tags: ['edge'],      last: 'vor 2h', status: 'active'  },
  { host: 'pg-backup-01', os: 'Ubuntu 24.04 LTS', kernel: '6.8.0-39-generic',  arch: 'x86_64',  tags: ['backup','db'], last: 'vor 4d', status: 'retired' },
];

function ServersPanel() {
  return (
    <div data-screen-label="Settings · Servers">
      <SHeader eyebrow="Settings · 01 / 07" title="Servers">
        Registered servers reporting to this instance. Revoke macht den API-Key sofort
        unbrauchbar; Retire stilllegt den Server und resolved alle offenen Findings.
      </SHeader>

      <SSection
        label="Registered servers"
        meta={`${SERVERS.length} total · ${SERVERS.filter(s => s.status === 'active').length} active`}
      >
        <div className="s-table s-servers__table">
          <div className="s-table__head s-servers__head">
            <span>Host</span>
            <span>Tags</span>
            <span className="s-table__cell--right">Last scan</span>
            <span className="s-table__cell--right">Status</span>
            <span aria-hidden="true" />
          </div>
          {SERVERS.map(s => (
            <div key={s.host} className="s-table__row s-servers__row">
              <div className="s-servers__hostcol">
                <div className="s-servers__hostname">{s.host}</div>
                <div className="s-servers__hostmeta">{s.os} · {s.kernel} · {s.arch}</div>
              </div>
              <div className="s-servers__tags">
                {s.tags.length === 0
                  ? <span style={{ color: 'var(--text-ghost)' }}>—</span>
                  : s.tags.map(t => (
                      <span key={t} className="s-tag">
                        <span className="s-tag__swatch" style={{ background: 'var(--text-tertiary)' }} aria-hidden="true" />
                        {t}
                      </span>
                    ))}
              </div>
              <div className="s-servers__last">{s.last}</div>
              <div className="s-table__cell--right">
                <StatusPill kind={s.status}>{s.status}</StatusPill>
              </div>
              <OverflowMenu items={[
                { label: 'Key rotieren' },
                { label: 'Retire' },
                { label: 'Revoke', danger: true },
              ]} />
            </div>
          ))}
        </div>
      </SSection>

      <SSection label="Add a server">
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-tertiary)', letterSpacing: '0.02em', lineHeight: 1.7, margin: 0 }}>
          Server registrieren sich per <code style={{ color: 'var(--text-primary)', background: 'var(--surface-raised)', padding: '2px 6px' }}>secscan-register.sh</code> auf dem Host —
          mit dem aktuellen Master-Key. Kein UI-Onboarding nötig.
        </p>
      </SSection>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
//   Tags
// ──────────────────────────────────────────────────────────────────────
const TAG_PALETTE = ['#7B8794', '#00E5FF', '#39FF14', '#FF9500', '#FF4444', '#B388FF', '#FFD600'];

function TagRow({ tag, onDelete }) {
  const [name, setName] = sUseState(tag.name);
  const [color, setColor] = sUseState(tag.color);
  const [pickerOpen, setPickerOpen] = sUseState(false);
  const dirty = name !== tag.name || color !== tag.color;
  return (
    <div className="s-table__row s-tags__row">
      <div style={{ position: 'relative' }}>
        <button
          type="button"
          className="s-tags__swatch"
          style={{ '--swatch-color': color }}
          onClick={() => setPickerOpen(o => !o)}
          aria-label="Pick color"
        />
        {pickerOpen && (
          <div className="s-overflow__menu" style={{ left: 0, right: 'auto', minWidth: 0, padding: 8, display: 'grid', gridTemplateColumns: 'repeat(7, 18px)', gap: 6 }}>
            {TAG_PALETTE.map(c => (
              <button
                key={c}
                type="button"
                onClick={() => { setColor(c); setPickerOpen(false); }}
                style={{ width: 18, height: 18, background: c, border: c === color ? '1px solid var(--accent)' : '1px solid var(--border-visible)', cursor: 'pointer', padding: 0 }}
                aria-label={`Color ${c}`}
              />
            ))}
          </div>
        )}
      </div>
      <input
        type="text"
        className="s-tags__name"
        value={name}
        onChange={e => setName(e.target.value)}
      />
      <div className="s-tags__count">{tag.count} {tag.count === 1 ? 'server' : 'servers'}</div>
      <div className="s-tags__actions">
        {dirty && <button type="button" className="s-btn s-btn--primary s-btn--sm">Save</button>}
        <button type="button" className="s-btn s-btn--ghost s-btn--sm" onClick={onDelete}>Delete</button>
      </div>
    </div>
  );
}

function TagsPanel({ empty = false }) {
  const initial = empty ? [] : [
    { name: 'prod',    color: '#00E5FF', count: 2 },
    { name: 'edge',    color: '#FF9500', count: 1 },
    { name: 'backup',  color: '#7B8794', count: 1 },
    { name: 'db',      color: '#B388FF', count: 1 },
  ];
  const [tags, setTags] = sUseState(initial);

  return (
    <div data-screen-label="Settings · Tags">
      <SHeader eyebrow="Settings · 02 / 07" title="Tags">
        Tags gruppieren Server für Filter und Dashboard-Übersichten. Hier verwaltest du
        Farbe, Name und Löschung. Tags entstehen, indem du im Server-Detail einen neuen
        Tag zuweist.
      </SHeader>

      <SSection label="All tags" meta={`${tags.length} tag${tags.length === 1 ? '' : 's'}`}>
        {tags.length === 0 ? (
          <div className="s-empty">
            <b>Keine Tags vorhanden.</b><br />
            Tags entstehen im Server-Detail unter „Tags zuweisen".
          </div>
        ) : (
          <div className="s-table s-tags__table">
            <div className="s-table__head s-tags__head">
              <span>Color</span>
              <span>Name</span>
              <span>Usage</span>
              <span style={{ textAlign: 'right' }}>Actions</span>
            </div>
            {tags.map((t, i) => (
              <TagRow
                key={t.name + i}
                tag={t}
                onDelete={() => setTags(tags.filter((_, j) => j !== i))}
              />
            ))}
          </div>
        )}
      </SSection>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────────────
//   Groups
// ──────────────────────────────────────────────────────────────────────
function GroupsPanel({ empty = false }) {
  const initial = empty ? [] : [
    { name: 'HZ',      count: 1 },
    { name: 'Edge',    count: 2 },
    { name: 'Backup',  count: 1 },
  ];
  const [groups, setGroups] = sUseState(initial);
  const move = (i, dir) => {
    const j = i + dir;
    if (j < 0 || j >= groups.length) return;
    const copy = groups.slice();
    [copy[i], copy[j]] = [copy[j], copy[i]];
    setGroups(copy);
  };

  return (
    <div data-screen-label="Settings · Groups">
      <SHeader eyebrow="Settings · 03 / 07" title="Groups">
        Gruppen bündeln Server für die Sidebar-Übersicht. Hier verwaltest du Reihenfolge,
        Namen und Löschung. Gruppen entstehen, indem du im Server-Detail eine neue Gruppe
        zuweist.
      </SHeader>

      <SSection label="All groups" meta={`${groups.length} group${groups.length === 1 ? '' : 's'}`}>
        {groups.length === 0 ? (
          <div className="s-empty">
            <b>Keine Gruppen vorhanden.</b><br />
            Gruppen entstehen im Server-Detail unter „Gruppe zuweisen".
          </div>
        ) : (
          <div className="s-table s-groups__table">
            <div className="s-table__head s-groups__head">
              <span>Order</span>
              <span>Name</span>
              <span>Servers</span>
              <span style={{ textAlign: 'right' }}>Actions</span>
            </div>
            {groups.map((g, i) => (
              <div key={g.name} className="s-table__row s-groups__row">
                <div className="s-groups__reorder">
                  <button type="button" className="s-groups__arrow" disabled={i === 0} onClick={() => move(i, -1)} aria-label="Move up">
                    <svg width="10" height="10" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <path d="M2 7l4-4 4 4" strokeLinecap="square" />
                    </svg>
                  </button>
                  <button type="button" className="s-groups__arrow" disabled={i === groups.length - 1} onClick={() => move(i, 1)} aria-label="Move down">
                    <svg width="10" height="10" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <path d="M2 5l4 4 4-4" strokeLinecap="square" />
                    </svg>
                  </button>
                </div>
                <input type="text" defaultValue={g.name} className="s-tags__name" />
                <div className="s-tags__count">{g.count} {g.count === 1 ? 'server' : 'servers'}</div>
                <div className="s-tags__actions">
                  <button type="button" className="s-btn s-btn--ghost s-btn--sm" onClick={() => setGroups(groups.filter((_, j) => j !== i))}>Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </SSection>
    </div>
  );
}

window.SettingsPanels1 = { SHeader, SSection, StatusPill, OverflowMenu, ServersPanel, TagsPanel, GroupsPanel };
