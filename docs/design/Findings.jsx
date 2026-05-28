/* Fathometer — Findings.jsx
   Cross-fleet (server × application-group) triage inbox. Inner content of `.main`
   only. Reuses sd-* patterns from server-detail.css; adds findings-specific
   structure (filter-bar, bucket-card, pending-bucket, bulk-toolbar, skel-rows).

   Hard rules per brief:
   - Default empty (no filter → no buckets, only filter-bar + empty-state).
   - No outer pagination; sub-pager inside each expanded bucket.
   - Fixed sort: bucket-order escalate→act→mitigate→pending→monitor→noise
     (Pending always last), within-bucket KEV desc → EPSS desc → CVSS desc →
     first_seen asc — already pre-sorted in findings-data.js.
   - Outline-only badges; cyan reserved for escalate / KEV / CRITICAL.
   - No comment / note / justification inputs anywhere (ADR-0006).
*/

const FF = window.FINDINGS_DATA;
const {
  useState:   ffUseState,
  useMemo:    ffUseMemo,
  useEffect:  ffUseEffect,
  useCallback: ffUseCallback,
} = React;

// ── Band ordering (Pending always last) ───────────────────────
const BAND_ORDER = ['escalate', 'act', 'mitigate', 'monitor', 'noise'];
const BAND_LABEL = {
  escalate: 'ESCALATE',
  act:      'ACT',
  mitigate: 'MITIGATE',
  monitor:  'MONITOR',
  noise:    'NOISE',
  pending:  'PENDING',
};

const PAGE_SIZE = 20;

// ── 1) Header strip ──────────────────────────────────────────
function FindingsHeader({ filterActive, bucketCount, findingCount }) {
  return (
    <div className="findings__header">
      <div>
        <p className="sd-eyebrow">Findings</p>
        <h1 className="findings__title">Findings</h1>
      </div>
      {filterActive ? (
        <div className="findings__counter">
          <b>{bucketCount}</b> Gruppen <span style={{ color: 'var(--border-visible)' }}>·</span> <b>{findingCount}</b> Findings
        </div>
      ) : null}
    </div>
  );
}

// ── 2) Filter-bar ────────────────────────────────────────────
function FilterBar({ draft, setDraft, onSubmit, onReset }) {
  const set = (k) => (e) => setDraft({ ...draft, [k]: e.target.value });
  const setToggle = (k) => () => setDraft({ ...draft, [k]: !draft[k] });

  return (
    <form
      className="findings__filter-bar"
      role="search"
      onSubmit={(e) => { e.preventDefault(); onSubmit(); }}
    >
      <input
        className="ff-input ff-q"
        type="search"
        name="q"
        value={draft.q}
        onChange={set('q')}
        placeholder="suche CVE, paket, titel, server…"
        aria-label="Suche"
      />

      <select className="ff-select" value={draft.tag} onChange={set('tag')} aria-label="Tag">
        <option value="">tag · alle</option>
        {FF.TAGS.map(t => <option key={t} value={t}>tag · {t}</option>)}
      </select>

      <select className="ff-select" value={draft.band} onChange={set('band')} aria-label="Risk-Band">
        <option value="all">risk-band · alle</option>
        <option value="escalate">risk-band · escalate</option>
        <option value="act">risk-band · act</option>
        <option value="mitigate">risk-band · mitigate</option>
        <option value="pending">risk-band · pending</option>
        <option value="monitor">risk-band · monitor</option>
        <option value="noise">risk-band · noise</option>
      </select>

      <select className="ff-select" value={draft.group} onChange={set('group')} aria-label="Application-Group">
        <option value="">app-group · alle</option>
        {FF.APPLICATION_GROUPS.map(g => <option key={g} value={g}>app-group · {g}</option>)}
      </select>

      <select className="ff-select" value={draft.actionRequired} onChange={set('actionRequired')} aria-label="Action required">
        <option value="all">action · alle</option>
        <option value="yes">action · required</option>
        <option value="no">action · none</option>
      </select>

      <select className="ff-select" value={draft.severity} onChange={set('severity')} aria-label="Severity min">
        <option value="all">severity · alle</option>
        <option value="critical">severity ≥ critical</option>
        <option value="high">severity ≥ high</option>
        <option value="medium">severity ≥ medium</option>
        <option value="low">severity ≥ low</option>
      </select>

      <select className="ff-select" value={draft.status} onChange={set('status')} aria-label="Status">
        <option value="all">status · alle</option>
        <option value="open">status · open</option>
        <option value="acknowledged">status · acknowledged</option>
        <option value="resolved">status · resolved</option>
      </select>

      <button
        type="button"
        className="ff-toggle"
        aria-pressed={draft.kevOnly}
        onClick={setToggle('kevOnly')}
      >
        <span className="ff-toggle__dot" aria-hidden="true" />
        <span>KEV only</span>
      </button>

      <button
        type="button"
        className="ff-toggle"
        aria-pressed={draft.staleOnly}
        onClick={setToggle('staleOnly')}
      >
        <span className="ff-toggle__dot" aria-hidden="true" />
        <span>Stale only</span>
      </button>

      <button type="submit" className="ff-submit">
        <span>filter</span>
        <span aria-hidden="true">→</span>
      </button>
      <button type="button" className="ff-reset" onClick={onReset}>zurücksetzen</button>
    </form>
  );
}

// ── Active filter chips ──────────────────────────────────────
const CHIP_LABEL = {
  q: 'q',
  tag: 'tag',
  band: 'risk-band',
  group: 'app-group',
  actionRequired: 'action',
  severity: 'severity',
  status: 'status',
  kevOnly: 'kev',
  staleOnly: 'stale',
};

function activeChips(filter) {
  const out = [];
  if (filter.q)              out.push({ k: 'q',              v: filter.q });
  if (filter.tag)            out.push({ k: 'tag',            v: filter.tag });
  if (filter.band && filter.band !== 'all')              out.push({ k: 'band',           v: filter.band });
  if (filter.group)          out.push({ k: 'group',          v: filter.group });
  if (filter.actionRequired && filter.actionRequired !== 'all') out.push({ k: 'actionRequired', v: filter.actionRequired });
  if (filter.severity && filter.severity !== 'all')      out.push({ k: 'severity',       v: filter.severity });
  if (filter.status && filter.status !== 'all')          out.push({ k: 'status',         v: filter.status });
  if (filter.kevOnly)        out.push({ k: 'kevOnly',        v: 'on' });
  if (filter.staleOnly)      out.push({ k: 'staleOnly',      v: 'on' });
  return out;
}

function FilterChips({ chips, onRemove }) {
  if (chips.length === 0) return null;
  return (
    <div className="findings__filter-chips" role="region" aria-label="Aktive Filter">
      {chips.map(c => (
        <span key={c.k} className="ff-chip">
          <b>{CHIP_LABEL[c.k]}</b>
          <span>{c.v}</span>
          <button
            type="button"
            className="ff-chip__x"
            aria-label={`Filter ${CHIP_LABEL[c.k]} entfernen`}
            onClick={() => onRemove(c.k)}
          >×</button>
        </span>
      ))}
    </div>
  );
}

// ── 3) Empty state ───────────────────────────────────────────
function EmptyState() {
  const { totalServers, fleetFindings } = FF.AGGREGATES;
  return (
    <div className="findings__empty" role="status">
      <p className="findings__empty-line">
        <b>{fleetFindings.toLocaleString('de-DE')}</b> findings im fleet, <b>{totalServers}</b> servers.
      </p>
      <p className="findings__empty-line">
        setze einen filter oder suche nach CVE, paket oder server.
      </p>
    </div>
  );
}

// ── 4) Bulk-action toolbar ───────────────────────────────────
function BulkToolbar({ selectionCount, onClear }) {
  if (selectionCount <= 0) return null;
  return (
    <div className="findings__bulk-toolbar" role="region" aria-label="Bulk-Aktionen">
      <span className="ff-bulk-count">
        <b>{selectionCount}</b> ausgewählt
      </span>
      <button type="button" className="ff-bulk-ack">
        <span>Auswahl ack</span>
        <span aria-hidden="true">→</span>
      </button>
      <button type="button" className="ff-bulk-link">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
          <path d="M12 3v14" />
          <path d="M6 11l6 6 6-6" />
          <path d="M4 21h16" />
        </svg>
        <span>CSV exportieren</span>
      </button>
      <button
        type="button"
        className="ff-bulk-link ff-bulk-link--right"
        onClick={onClear}
      >
        Auswahl aufheben
      </button>
    </div>
  );
}

// ── 5+6) Finding row ─────────────────────────────────────────
function FindingRow({ f, includeServer, checked, onToggle }) {
  return (
    <details className="bucket-finding">
      <summary className="bucket-finding__summary">
        <input
          type="checkbox"
          className="sd-checkbox"
          checked={!!checked}
          onChange={(e) => { e.stopPropagation(); onToggle(); }}
          onClick={(e) => e.stopPropagation()}
          aria-label={`${f.cve} auswählen`}
        />
        {includeServer && (
          <span className="bucket-finding__server" title={f.server}>{f.server}</span>
        )}
        <div className="sd-finding__cve">
          <span className="sd-finding__cve-id">
            <span>{f.cve}</span>
            {f.kev && <span className="sd-badge sd-badge--kev">KEV</span>}
          </span>
          <span className="sd-finding__title">{f.title}</span>
        </div>
        <div className="sd-finding__pkg">
          <span className="sd-finding__pkg-name">{f.pkg}</span>
          <span className="sd-finding__pkg-diff">
            <span className="sd-finding__pkg-from">{f.from}</span>
            <span className="sd-finding__pkg-arrow">→</span>
            <span className="sd-finding__pkg-to">{f.to}</span>
          </span>
        </div>
        <span className="sd-cap sd-cap--neutral">{f.epss}</span>
        <span className="sd-cap sd-cap--neutral">{f.cvss}</span>
        <span className={`sd-cap ${f.severity === 'CRITICAL' ? 'sd-cap--accent' : 'sd-cap--neutral'}`}>
          {f.severity}
        </span>
        <span className="bucket-finding__first-seen">{f.firstSeen}</span>
      </summary>
      <div className="bucket-finding__body">
        <p className="sd-ai-eyebrow">KI-Bewertung</p>
        <p className="sd-ai-text">{f.ai}</p>
      </div>
    </details>
  );
}

// ── Bucket-body skeleton (5 rows, scan-probe sweep) ─────────
function BucketSkeleton() {
  return (
    <div>
      <div className="bucket-findings-head">
        <span />
        <span>CVE / Titel</span>
        <span>Paket</span>
        <span className="bucket-findings-head__right">EPSS</span>
        <span className="bucket-findings-head__right">CVSS</span>
        <span className="bucket-findings-head__right">Severity</span>
        <span className="bucket-findings-head__right">First seen</span>
      </div>
      <div className="bucket-skel-rows sd-skel-frame">
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} className="bucket-skel-row">
            <span className="bucket-skel-bar bucket-skel-bar--short" style={{ width: 14 }} />
            <span className="bucket-skel-bar bucket-skel-bar--full" />
            <span className="bucket-skel-bar bucket-skel-bar--mid" />
            <span className="bucket-skel-bar bucket-skel-bar--short" />
            <span className="bucket-skel-bar bucket-skel-bar--short" />
            <span className="bucket-skel-bar bucket-skel-bar--short" />
            <span className="bucket-skel-bar bucket-skel-bar--short" />
          </div>
        ))}
      </div>
      <div className="bucket-card__footer">
        <span>— · —</span>
        <span className="bucket-card__pager">
          <button type="button" disabled aria-label="Vorherige Seite">‹</button>
          <button type="button" disabled aria-label="Nächste Seite">›</button>
        </span>
      </div>
    </div>
  );
}

// ── Bucket card ──────────────────────────────────────────────
function BucketCard({
  bucket, isPending, defaultOpen, skeletonOnExpand,
  selectionState,
  onToggleBucket,
  onToggleFinding,
}) {
  const [open, setOpen] = ffUseState(defaultOpen);
  const [page, setPage] = ffUseState(1);
  const isLazy = skeletonOnExpand;

  const findings = bucket.findings;
  const pages = Math.max(1, Math.ceil(findings.length / PAGE_SIZE));
  const slice = ffUseMemo(
    () => findings.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [findings, page]
  );

  // Selection state for this bucket:
  //   bucketChecked = bucket-level checkbox (selects all findings logically)
  //   sel: Set<cve> of individually-ticked findings
  const bucketChecked = selectionState.buckets.has(bucket.id);
  const sel = selectionState.findings;

  // Header click toggles open; checkbox + server-link must not bubble.
  const stop = (e) => e.stopPropagation();

  const handleHeadClick = (e) => {
    // Let inner controls handle themselves; only toggle for clicks on the
    // summary surface itself.
    setOpen(o => !o);
  };

  return (
    <details
      className={`bucket-card ${isPending ? 'pending-bucket' : ''}`}
      open={open}
    >
      <summary
        className="bucket-card__head"
        onClick={(e) => { e.preventDefault(); handleHeadClick(e); }}
      >
        <input
          type="checkbox"
          className="sd-checkbox"
          checked={bucketChecked}
          onChange={(e) => { e.stopPropagation(); onToggleBucket(bucket); }}
          onClick={stop}
          aria-label={`Alle Findings in ${isPending ? 'Pending-Bucket' : `${bucket.server} · ${bucket.group}`} auswählen`}
        />
        <span className={`sd-badge sd-badge--${bucket.band}`}>{BAND_LABEL[bucket.band]}</span>
        {isPending ? (
          <span
            className="bucket-card__server"
            style={{ color: 'var(--text-tertiary)', cursor: 'default' }}
            aria-label="Pending-Bucket"
          >
            cross-server
          </span>
        ) : (
          <a
            href={`#/servers/${bucket.server}`}
            className="bucket-card__server"
            onClick={stop}
          >{bucket.server}</a>
        )}
        <span className="bucket-card__group">
          {isPending ? '— ohne Group —' : bucket.group}
        </span>
        <span>
          <span className="bucket-card__count">{findings.length}</span>
          <span className="bucket-card__count-label">findings</span>
        </span>
        <span className="bucket-card__chev" aria-hidden="true">›</span>
      </summary>

      {open && (
        <div className="bucket-card__body">
          {isLazy ? (
            <BucketSkeleton />
          ) : (
            <>
              <div className="bucket-findings-head">
                <span />
                {isPending && <span>Server</span>}
                <span>CVE / Titel</span>
                <span>Paket</span>
                <span className="bucket-findings-head__right">EPSS</span>
                <span className="bucket-findings-head__right">CVSS</span>
                <span className="bucket-findings-head__right">Severity</span>
                <span className="bucket-findings-head__right">First seen</span>
              </div>
              {slice.map(f => {
                const checked = bucketChecked || sel.has(`${bucket.id}::${f.cve}`);
                return (
                  <FindingRow
                    key={`${bucket.id}::${f.cve}`}
                    f={f}
                    includeServer={isPending}
                    checked={checked}
                    onToggle={() => onToggleFinding(bucket.id, f.cve)}
                  />
                );
              })}
              <div className="bucket-card__footer">
                <span>Seite {page} von {pages} · {findings.length} Findings</span>
                <span className="bucket-card__pager">
                  <button
                    type="button"
                    aria-label="Vorherige Seite"
                    disabled={page <= 1}
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                  >‹</button>
                  <button
                    type="button"
                    aria-label="Nächste Seite"
                    disabled={page >= pages}
                    onClick={() => setPage(p => Math.min(pages, p + 1))}
                  >›</button>
                </span>
              </div>
            </>
          )}
        </div>
      )}
    </details>
  );
}

// ── Top-level Findings page ──────────────────────────────────
function Findings({ initialFilterActive = false, expandedBucketId = null, prefilledSelection = null, skeletonBucketId = null } = {}) {
  // Filter draft = the form's working state; `filter` = committed state.
  const EMPTY_FILTER = {
    q: '',
    tag: '',
    band: 'all',
    group: '',
    actionRequired: 'all',
    severity: 'all',
    status: 'all',
    kevOnly: false,
    staleOnly: false,
  };

  const SAMPLE_FILTER = {
    ...EMPTY_FILTER,
    q: '',
    tag: 'prod',
    band: 'all',
    severity: 'high',
    status: 'open',
  };

  const [draft, setDraft] = ffUseState(initialFilterActive ? SAMPLE_FILTER : EMPTY_FILTER);
  const [filter, setFilter] = ffUseState(initialFilterActive ? SAMPLE_FILTER : EMPTY_FILTER);

  // Selection: bucket-level + finding-level sets coexist.
  const [selection, setSelection] = ffUseState(() => {
    if (prefilledSelection) {
      return {
        buckets:  new Set(prefilledSelection.buckets  || []),
        findings: new Set(prefilledSelection.findings || []),
      };
    }
    return { buckets: new Set(), findings: new Set() };
  });

  const chips = ffUseMemo(() => activeChips(filter), [filter]);
  const filterActive = chips.length > 0;

  const onSubmit = ffUseCallback(() => setFilter({ ...draft }), [draft]);
  const onReset  = ffUseCallback(() => {
    setDraft(EMPTY_FILTER);
    setFilter(EMPTY_FILTER);
  }, []);

  const removeChip = ffUseCallback((k) => {
    const next = { ...filter };
    if (k === 'kevOnly' || k === 'staleOnly') next[k] = false;
    else if (k === 'band' || k === 'actionRequired' || k === 'severity' || k === 'status') next[k] = 'all';
    else next[k] = '';
    setFilter(next);
    setDraft(next);
  }, [filter]);

  // Toggle a bucket-level checkbox. When ticked, it implies "select all
  // findings in this bucket" — but we keep the bucket-set as the authority
  // (so per-row checkboxes appear checked by virtue of the bucket flag).
  const toggleBucket = ffUseCallback((bucket) => {
    setSelection(prev => {
      const buckets = new Set(prev.buckets);
      const findings = new Set(prev.findings);
      if (buckets.has(bucket.id)) {
        buckets.delete(bucket.id);
      } else {
        buckets.add(bucket.id);
        // Clear individual ticks for that bucket — they're now implied.
        for (const key of [...findings]) {
          if (key.startsWith(`${bucket.id}::`)) findings.delete(key);
        }
      }
      return { buckets, findings };
    });
  }, []);

  const toggleFinding = ffUseCallback((bucketId, cve) => {
    setSelection(prev => {
      const findings = new Set(prev.findings);
      const key = `${bucketId}::${cve}`;
      findings.has(key) ? findings.delete(key) : findings.add(key);
      return { ...prev, findings };
    });
  }, []);

  const clearSelection = ffUseCallback(() => {
    setSelection({ buckets: new Set(), findings: new Set() });
  }, []);

  // Ordered bucket list per the brief: escalate→act→mitigate→pending→monitor→noise
  // …but the spec also says risk_band desc → server asc → group asc with
  // Pending always last. Both interpretations resolve to the same ordering
  // for the demo's deterministic mock data — we explicitly stitch it here.
  const orderedBuckets = ffUseMemo(() => {
    const groups = BAND_ORDER.map(b =>
      FF.BUCKETS
        .filter(x => x.band === b)
        .sort((a, b) => a.server.localeCompare(b.server) || a.group.localeCompare(b.group))
    );
    return {
      escalate: groups[0],
      act:      groups[1],
      mitigate: groups[2],
      monitor:  groups[3],
      noise:    groups[4],
    };
  }, []);

  // Count selection — bucket-level ticks contribute their full findings count.
  const selectionCount = ffUseMemo(() => {
    let n = 0;
    for (const bid of selection.buckets) {
      const bucket = FF.BUCKETS.find(b => b.id === bid)
        ?? (FF.PENDING_BUCKET.id === bid ? FF.PENDING_BUCKET : null);
      if (bucket) n += bucket.findings.length;
    }
    n += selection.findings.size;
    return n;
  }, [selection]);

  // Bucket count + finding count for the header counter (only on filter active).
  const headerCounts = ffUseMemo(() => {
    if (!filterActive) return { bucketCount: 0, findingCount: 0 };
    // For the demo: when filter is active we render all 12 buckets — match.
    let buckets = FF.BUCKETS.length + 1;
    let findings = FF.BUCKETS.reduce((a, b) => a + b.findings.length, 0)
                 + FF.PENDING_BUCKET.findings.length;
    return { bucketCount: buckets, findingCount: findings };
  }, [filterActive]);

  // Insertion order on screen: escalate → act → mitigate → pending → monitor → noise
  const inOrderBuckets = ffUseMemo(() => [
    ...orderedBuckets.escalate,
    ...orderedBuckets.act,
    ...orderedBuckets.mitigate,
    FF.PENDING_BUCKET,
    ...orderedBuckets.monitor,
    ...orderedBuckets.noise,
  ], [orderedBuckets]);

  return (
    <div className="findings">
      <FindingsHeader
        filterActive={filterActive}
        bucketCount={headerCounts.bucketCount}
        findingCount={headerCounts.findingCount}
      />

      <FilterBar
        draft={draft}
        setDraft={setDraft}
        onSubmit={onSubmit}
        onReset={onReset}
      />

      {chips.length > 0 && (
        <FilterChips chips={chips} onRemove={removeChip} />
      )}

      {!filterActive ? (
        <EmptyState />
      ) : (
        <>
          <BulkToolbar
            selectionCount={selectionCount}
            onClear={clearSelection}
          />

          <div className="findings__list">
            {inOrderBuckets.map(b => {
              const isPending = b.band === 'pending';
              return (
                <BucketCard
                  key={b.id}
                  bucket={b}
                  isPending={isPending}
                  defaultOpen={expandedBucketId === b.id || expandedBucketId === 'pending' && isPending}
                  skeletonOnExpand={skeletonBucketId === b.id}
                  selectionState={selection}
                  onToggleBucket={toggleBucket}
                  onToggleFinding={toggleFinding}
                />
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

window.Findings = Findings;
