/* Fathometer — ServerDetail.jsx
   The inner content of `.main` when the operator clicks a host in the sidebar.
   Renders sections 1-8 of the brief in order. Settings sub-view is a separate
   component (ServerSettings.jsx) — this file toggles between the two.

   Brand discipline:
   - Outline-only badges, no fills. Cyan reserved for KEV / Critical / escalate.
   - No box-shadows, no gradients except the sonar/scan-flash beam.
   - Skeleton states for heartbeat, trend, and KPI tiles (reused scan-probe).
*/

const { useEffect, useLayoutEffect, useMemo, useRef, useState, useCallback } = React;
const SD = window.SERVER_DETAIL;

// ── Header status pill — scan-flash count ──────────────────────
// Reuses the sonar scan-flash sync hook from app.jsx. The hook splits the
// count digits into spans and times each one to peak cyan as the beam passes.
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

const SCAN_CYCLE_S       = 5.4;
const SCAN_PEAK_FRAC     = 0.14;
const SCAN_SWEEP_S       = SCAN_CYCLE_S * 0.44;
const BEAM_CENTER_START  = -25.2;
const BEAM_CENTER_END    = 123.9;
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
        el.style.animationDelay = `${(tBeamS - peakS).toFixed(3)}s`;
      });
    };
    apply();
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(apply).catch(() => {});
    const ro = new ResizeObserver(apply);
    ro.observe(root);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

// ── 1) Header strip ────────────────────────────────────────────
function HeaderStrip({ host, onOpenSettings }) {
  const pillRef = useRef(null);
  useScanFlashSync(pillRef, [host.actionPending]);

  return (
    <div className="server-detail__header sd-header">
      <div className="sd-header__left">
        <h1 className="server-detail__hostname sd-hostname">{host.host}</h1>

        <div className="sd-header__tags">
          <span className="sd-status-pill" ref={pillRef} role="status" aria-live="polite">
            <span className="sd-status-pill__label">
              <ScanChars text="Action needed" />
            </span>
          </span>

          {host.trivyStale && (
            <span className="sd-status-flag" title="trivy-db ist älter als 7 Tage">trivy-db stale</span>
          )}
        </div>
      </div>

      <div className="sd-header__right">
        <button
          type="button"
          className="sd-icon-button"
          onClick={onOpenSettings}
          aria-label="Einstellungen"
          title="Einstellungen"
        >
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.03 1.56V21a2 2 0 1 1-4 0v-.09A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.56-1.03H3a2 2 0 1 1 0-4h.09A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1.03-1.56V3a2 2 0 1 1 4 0v.09A1.7 1.7 0 0 0 15 4.6a1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9a1.7 1.7 0 0 0 1.56 1.03H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.51 1.03Z" />
          </svg>
        </button>
      </div>
    </div>
  );
}

// ── 2 + 3) Sysline + listeners/services chips ──────────────────
function Sysline({ host }) {
  // `null` = closed; 'listeners' or 'services' = one open at a time.
  const [open, setOpen] = useState(null);
  const toggle = (k) => setOpen(o => (o === k ? null : k));

  return (
    <>
      <div className="sd-sysline">
        <span className="sd-sysline__prompt">&gt;</span>
        <span className="sd-sysline__seg">{host.os}</span>
        <span className="sd-sysline__sep">·</span>
        <span className="sd-sysline__seg">{host.kernel}</span>
        <span className="sd-sysline__sep">·</span>
        <span className="sd-sysline__seg">{host.arch}</span>
        <span className="sd-sysline__sep">·</span>
        <span className="sd-sysline__seg">last scan <b>{host.lastScan}</b></span>
        <span className="sd-sysline__sep">·</span>
        <span className="sd-sysline__seg">trivy-db <b>{host.trivyDb}</b></span>
        <span className="sd-sysline__sep">·</span>
        <span className="sd-sysline__seg">expected interval <b>{host.expectedInterval}</b></span>

        <button
          type="button"
          className="sd-chip"
          aria-expanded={open === 'listeners'}
          aria-controls="sd-flyout-listeners"
          onClick={() => toggle('listeners')}
        >
          <span>Listeners &amp; services</span>
          <span className="sd-chip__count">{SD.LISTENERS.length}</span>
          <span className="sd-chip__caret" aria-hidden="true">›</span>
        </button>

        <button
          type="button"
          className="sd-chip"
          aria-expanded={open === 'services'}
          aria-controls="sd-flyout-services"
          onClick={() => toggle('services')}
        >
          <span>Active services</span>
          <span className="sd-chip__count">{SD.SERVICES.length}</span>
          <span className="sd-chip__caret" aria-hidden="true">›</span>
        </button>
      </div>

      {open === 'listeners' && (
        <div className="sd-flyout" id="sd-flyout-listeners" role="region" aria-label="Listeners and services">
          <div className="sd-flyout__head">
            <span className="sd-flyout__title"><b>{SD.LISTENERS.length}</b> open listeners · process · addr:port · proto</span>
            <button type="button" className="sd-flyout__close" onClick={() => setOpen(null)} aria-label="Schließen">×</button>
          </div>
          <div className="sd-flyout__body">
            <table className="sd-listener-table">
              <thead>
                <tr><th>Process</th><th>Addr:port</th><th>Proto</th><th>Exposure</th></tr>
              </thead>
              <tbody>
                {SD.LISTENERS.map((l, i) => (
                  <tr key={i}>
                    <td className="sd-listener-proc">{l.process}</td>
                    <td>{l.addr}</td>
                    <td>{l.proto}</td>
                    <td>
                      <span className={`sd-listener-tag ${l.exposed ? 'sd-listener-tag--exposed' : ''}`}>
                        {l.exposed ? 'public-exposed' : 'loopback'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {open === 'services' && (
        <div className="sd-flyout" id="sd-flyout-services" role="region" aria-label="Active systemd services">
          <div className="sd-flyout__head">
            <span className="sd-flyout__title"><b>{SD.SERVICES.length}</b> systemd units · active &amp; running</span>
            <button type="button" className="sd-flyout__close" onClick={() => setOpen(null)} aria-label="Schließen">×</button>
          </div>
          <div className="sd-flyout__body">
            <div className="sd-services-list">
              {SD.SERVICES.map(s => <code key={s}>{s}</code>)}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ── 4) Operator Workflows ──────────────────────────────────────
function ChatGlyph() {
  return (
    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
      <path d="M21 11.5a8.4 8.4 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.4 8.4 0 0 1-3.8-.9L3 21l1.9-5.7a8.4 8.4 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.4 8.4 0 0 1 3.8-.9h.5a8.5 8.5 0 0 1 8 8v.5z" />
    </svg>
  );
}

function WorkflowCard({ wf, onChat }) {
  return (
    <details className="workflow-card">
      <summary className="workflow-card__summary">
        <span className={`sd-badge sd-badge--${wf.phase.toLowerCase()}`}>{wf.phase}</span>
        <span className="workflow-card__title">{wf.title}</span>
        <span className="workflow-card__subline">{wf.subline}</span>
        <span className="workflow-card__count">{wf.rows.length}</span>
        <span className="workflow-card__chev" aria-hidden="true">›</span>
      </summary>
      <div className="workflow-card__body">
        <table className="workflow-table">
          <thead>
            <tr>
              <th className="workflow-table__group">Group</th>
              <th className="workflow-table__cve">Worst Finding</th>
              <th className="workflow-table__reason">Reason</th>
              <th className="workflow-table__ask" aria-label="KI-Assistent"></th>
            </tr>
          </thead>
          <tbody>
            {wf.rows.map((r, i) => (
              <tr key={i}>
                <td className="workflow-table__group">{r.group}</td>
                <td className="workflow-table__cve">{r.worst}</td>
                <td className="workflow-table__reason">{r.reason}</td>
                <td className="workflow-table__ask">
                  <button
                    type="button"
                    className="sd-ask-btn"
                    onClick={() => onChat({ ...r, phase: wf.phase, title: wf.title })}
                    aria-label={`Ask AI about ${r.group}`}
                    title={`Ask AI about ${r.group}`}
                  >
                    <ChatGlyph />
                    <span>Help</span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="workflow-card__footer">
          <span>{wf.rows.length} Findings · Seite 1 von 1</span>
          <span className="workflow-card__pager">
            <button type="button" aria-label="Vorherige Seite" disabled>‹</button>
            <button type="button" aria-label="Nächste Seite" disabled>›</button>
          </span>
        </div>
      </div>
    </details>
  );
}

// ── Per-group KI chat drawer ───────────────────────────────────
const CHAT_SUGGESTIONS = [
  'How real is the risk here?',
  'In what order should I patch?',
  'Are there known active exploits?',
  'Can I safely defer this?',
];

function buildPreamble(ctx) {
  const h = SD.HOST;
  return (
    `You are the Fathometer AI triage assistant for security operators. ` +
    `Answer concisely, precisely and technically in English — short paragraphs, no marketing fluff, no Markdown headings. ` +
    `If you are unsure, say so. You advise on exactly one package group.\n\n` +
    `HOST: ${h.host} · ${h.os} · kernel ${h.kernel} · ${h.arch}. Last scan ${h.lastScan}.\n` +
    `WORKFLOW PHASE: ${ctx.phase} (${ctx.title}).\n` +
    `GROUP: ${ctx.group}.\n` +
    `WORST FINDING: ${ctx.worst}.\n` +
    `SCANNER REASON: ${ctx.reason}\n\n` +
    `Answer the operator's questions strictly in the context of this group.`
  );
}

function TypingDots() {
  return (
    <span className="sd-chat-typing" aria-label="AI is typing">
      <span className="sd-chat-typing__dot" />
      <span className="sd-chat-typing__dot" />
      <span className="sd-chat-typing__dot" />
    </span>
  );
}

function WorkflowChat({ host, ctx, conversations, setConversations, onBack }) {
  const key = ctx.group;
  const messages = conversations[key] || [];
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const threadRef = useRef(null);
  const inputRef = useRef(null);

  // Escape returns to the detail view; focus the composer on open.
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onBack(); };
    window.addEventListener('keydown', onKey);
    const t = setTimeout(() => inputRef.current && inputRef.current.focus(), 260);
    return () => { window.removeEventListener('keydown', onKey); clearTimeout(t); };
  }, [onBack]);

  // Keep the thread pinned to the latest message (no scrollIntoView).
  useEffect(() => {
    const el = threadRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, busy]);

  const setMessages = useCallback((updater) => {
    setConversations(prev => {
      const cur = prev[key] || [];
      const next = typeof updater === 'function' ? updater(cur) : updater;
      return { ...prev, [key]: next };
    });
  }, [key, setConversations]);

  const send = useCallback(async (raw) => {
    const text = (raw != null ? raw : input).trim();
    if (!text || busy) return;
    setInput('');
    setError(null);
    const history = messages.concat({ role: 'user', content: text });
    setMessages(history);
    setBusy(true);
    try {
      const apiMessages = [
        { role: 'user', content: buildPreamble(ctx) },
        { role: 'assistant', content: 'Understood. I will advise on this group.' },
        ...history,
      ];
      const reply = await window.claude.complete({ messages: apiMessages });
      setMessages(h => h.concat({ role: 'assistant', content: (reply || '').trim() || '—' }));
    } catch (err) {
      setError('Could not load a response. Please try again.');
    } finally {
      setBusy(false);
    }
  }, [input, busy, messages, setMessages, ctx]);

  const onKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  };

  const newChat = useCallback(() => {
    if (busy) return;
    setMessages([]);
    setInput('');
    setError(null);
    if (inputRef.current) inputRef.current.focus();
  }, [busy, setMessages]);

  return (
    <div className="server-detail sd-chat-view">
      {/* Header strip — back link + centred title, mirrors Settings */}
      <div className="sd-settings-head">
        <button type="button" className="sd-back" onClick={onBack} aria-label="Back">
          <span className="sd-back__arrow" aria-hidden="true">←</span>
          <span>Back</span>
        </button>
        <h1 className="sd-settings-title">
          AI Assistant · <b>{host.host}</b>
        </h1>
        <button
          type="button"
          className="sd-newchat"
          onClick={newChat}
          disabled={busy || messages.length === 0}
          aria-label="New chat"
          title="Clear history and start over"
        >
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
            <path d="M12 5v14M5 12h14" />
          </svg>
          <span>New Chat</span>
        </button>
      </div>

      {/* Context line — slim inline meta, styled like the header sysline.
         Server lives in the page title above. */}
      <div className="sd-chat-meta">
        <span className="sd-chat-meta__prompt" aria-hidden="true">›</span>
        <span className="sd-chat-meta__seg">
          <span className="sd-chat-meta__k">Group</span>
          <span className={`sd-badge sd-badge--${ctx.phase.toLowerCase()}`}>{ctx.phase}</span>
          <span className="sd-chat-meta__group">{ctx.group}</span>
        </span>
        <span className="sd-chat-meta__sep" aria-hidden="true">·</span>
        <span className="sd-chat-meta__seg">
          <span className="sd-chat-meta__k">Worst</span>
          <span className="sd-chat-meta__v">{ctx.worst}</span>
        </span>
        <span className="sd-chat-meta__seg sd-chat-meta__seg--reason">
          <span className="sd-chat-meta__k">Reason</span>
          <span className="sd-chat-meta__v">{ctx.reason}</span>
        </span>
      </div>

      {/* Conversation */}
      <div className="sd-chat-thread" ref={threadRef}>
        {messages.length === 0 && !busy && (
          <div className="sd-chat__empty">
            <p className="sd-chat__empty-line">
              Ask the AI anything about <b>{ctx.group}</b> — risk, patch order,
              exploit status, or whether a defer is worth it.
            </p>
            <div className="sd-chat__suggest">
              {CHAT_SUGGESTIONS.map(s => (
                <button key={s} type="button" className="sd-chat__chip" onClick={() => send(s)}>
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={`sd-msg sd-msg--${m.role}`}>
            {m.role === 'assistant' && <span className="sd-msg__tag">AI</span>}
            <div className="sd-msg__bubble">{m.content}</div>
          </div>
        ))}

        {busy && (
          <div className="sd-msg sd-msg--assistant">
            <span className="sd-msg__tag">AI</span>
            <div className="sd-msg__bubble sd-msg__bubble--typing"><TypingDots /></div>
          </div>
        )}

        {error && <div className="sd-chat__error">{error}</div>}
      </div>

      {/* Composer — sticks to the bottom of the scroll viewport */}
      <div className="sd-chat-dock">
        <div className="sd-chat__composer">
          <textarea
            ref={inputRef}
            className="sd-chat__input"
            rows={1}
            placeholder="Ask about this group…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKeyDown}
          />
          <button
            type="button"
            className="sd-chat__send"
            onClick={() => send()}
            disabled={!input.trim() || busy}
            aria-label="Send"
          >
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="square" strokeLinejoin="miter" aria-hidden="true">
              <path d="M4 12h13M11 6l6 6-6 6" />
            </svg>
          </button>
        </div>
        <p className="sd-chat__foot">Enter to send · Shift+Enter for a new line · Esc to go back</p>
      </div>
    </div>
  );
}

function Workflows({ onChat }) {
  return (
    <section className="sd-section">
      <p className="sd-eyebrow">Was zu tun ist</p>
      <h2 className="sd-h3">Operator-Workflows</h2>
      <div className="sd-workflows">
        {SD.WORKFLOWS.map((wf, i) => <WorkflowCard key={i} wf={wf} onChat={onChat} />)}
      </div>
    </section>
  );
}

// ── 5) HeaderStats — total open + 4 KPI tiles ──────────────────
function Sparkline({ values, accent }) {
  const max = Math.max(1, ...values);
  return (
    <div className="sd-spark" aria-hidden="true">
      {values.map((v, i) => (
        <div
          key={i}
          className="sd-spark__bar"
          style={{ height: `${Math.max(8, (v / max) * 100)}%` }}
        />
      ))}
    </div>
  );
}
function HeaderStats({ skel }) {
  const s = SD.HEADER_STATS;
  return (
    <section className="sd-section sd-stats">
      <div className="sd-stats__primary">
        <p className="sd-eyebrow">Findings · open · total</p>
        <div className="sd-stats__num">
          <strong>{s.open}</strong>
          <span className="sd-stats__delta">{s.deltaLabel}</span>
        </div>
        <p className="sd-stats__total">von {s.total} Findings gesamt</p>
      </div>
      <div className="sd-tiles">
        {s.tiles.map(t => {
          // Only KEV and Critical wear cyan, and only when non-zero.
          const accent = (t.key === 'kev' || t.key === 'critical') && t.n > 0;
          return (
            <div key={t.key} className={`sd-tile ${accent ? 'sd-tile--accent' : ''} ${skel ? 'sd-tile--skel sd-skel-frame' : ''}`}>
              <div className="sd-tile__label">
                <span>{t.label}</span>
                {t.key === 'kev' && t.n > 0 && !skel && <span className="sd-tile__dot" aria-hidden="true" />}
              </div>
              <div className={`sd-tile__num ${t.n === 0 ? 'sd-tile__num--zero' : ''}`}>
                {skel ? '—' : t.n}
              </div>
              <Sparkline values={t.spark} accent={accent} />
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ── 6) Heartbeat ───────────────────────────────────────────────
const HEARTBEAT_LABELS = {
  unknown:  'UNKNOWN',
  nominal:  'NOMINAL',
  act:      'ACT',
  escalate: 'ESCALATE',
};
function fmtTickDate(daysAgo) {
  const d = new Date();
  d.setDate(d.getDate() - daysAgo);
  return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function Heartbeat({ skel }) {
  const ticks = SD.heartbeat;
  const [hoverIdx, setHoverIdx] = useState(null);
  return (
    <section className="sd-section">
      <p className="sd-eyebrow">Lebenszeichen · 30 Tage</p>
      <h2 className="sd-h3">Tägliche Scans · Worst-Risk-Band pro Tag</h2>

      <div className={`sd-heartbeat-frame ${skel ? 'sd-skel-frame' : ''}`}>
        <div className="sd-heartbeat" role="img" aria-label="Lebenszeichen — letzte 30 Tage">
          {ticks.map((state, i) => (
            <button
              key={i}
              type="button"
              className={`sd-heartbeat__tick ${skel ? 'sd-heartbeat__tick--skel' : `sd-heartbeat__tick--${state}`} ${hoverIdx === i ? 'sd-heartbeat__tick--hover' : ''}`}
              aria-label={`${fmtTickDate(29 - i)}: ${HEARTBEAT_LABELS[state]}`}
              onMouseEnter={() => setHoverIdx(i)}
              onMouseLeave={() => setHoverIdx(null)}
            />
          ))}
          {hoverIdx !== null && !skel && (
            <div
              className="heartbeat-tip"
              style={{ left: `${((hoverIdx + 0.5) / ticks.length) * 100}%` }}
              aria-hidden="true"
            >
              <div className="heartbeat-tip__date">{fmtTickDate(29 - hoverIdx)}</div>
              <div className={`heartbeat-tip__state heartbeat-tip__state--${ticks[hoverIdx] === 'escalate' ? 'alarm' : ticks[hoverIdx] === 'act' ? 'warn' : ticks[hoverIdx]}`}>
                {HEARTBEAT_LABELS[ticks[hoverIdx]]}
              </div>
            </div>
          )}
        </div>
        <div className="sd-heartbeat__axis">
          <span>-30T</span>
          <span>Heute</span>
        </div>
      </div>

      <div className="sd-heartbeat__legend">
        <span className="sd-legend-swatch sd-legend-swatch--unknown"><span className="sd-legend-swatch__dot" />Unknown</span>
        <span className="sd-legend-swatch sd-legend-swatch--nominal"><span className="sd-legend-swatch__dot" />Nominal</span>
        <span className="sd-legend-swatch sd-legend-swatch--act"><span className="sd-legend-swatch__dot" />Act</span>
        <span className="sd-legend-swatch sd-legend-swatch--escalate"><span className="sd-legend-swatch__dot" />Escalate</span>
      </div>
    </section>
  );
}

// ── 7) Severity trend ──────────────────────────────────────────
function SeverityTrend({ skel }) {
  const [range, setRange] = useState('30T');
  const data = SD.severityTrend;
  // Take last N days based on range — `range` just slices, not regenerates.
  const slice = useMemo(() => {
    const map = { '24h': 1, '7T': 7, '30T': 30 };
    return data.slice(-(map[range] || 30));
  }, [range, data]);

  const max = useMemo(
    () => Math.max(1, ...slice.map(d => d.critical + d.high + d.medium + d.low)),
    [slice]
  );

  const totals = useMemo(() => slice.reduce((a, d) => ({
    critical: a.critical + d.critical,
    high:     a.high     + d.high,
    medium:   a.medium   + d.medium,
    low:      a.low      + d.low,
  }), { critical: 0, high: 0, medium: 0, low: 0 }), [slice]);
  const grand = totals.critical + totals.high + totals.medium + totals.low;
  const pct = (n) => grand === 0 ? '0,0%' : `${(n / grand * 100).toFixed(1).replace('.', ',')}%`;

  // Axis label depends on range.
  const axisLeft = range === '24h' ? '-24h' : range === '7T' ? '-6T' : '-29T';

  return (
    <section className="sd-section">
      <p className="sd-eyebrow">Severity trend · pro Tag</p>
      <h2 className="sd-h3">Verteilung der offenen Findings über {range === '24h' ? '24 Stunden' : range === '7T' ? '7 Tage' : '30 Tage'}</h2>

      <div className={`sd-trend-frame ${skel ? 'sd-skel-frame' : ''}`}>
        <div className="sd-trend-head">
          <span className="sd-eyebrow" style={{ margin: 0 }}>Severity trend</span>
          <div className="sd-trend-range" role="group" aria-label="Zeitraum">
            {['24h', '7T', '30T'].map(r => (
              <button
                key={r}
                type="button"
                className={range === r ? 'active' : ''}
                aria-pressed={range === r}
                onClick={() => setRange(r)}
              >{r}</button>
            ))}
          </div>
        </div>

        <div className="sd-trend-chart" role="img" aria-label="Severity-Verlauf">
          {slice.map((d, i) => {
            const total = d.critical + d.high + d.medium + d.low;
            const h = total ? (total / max) * 100 : 4;
            return (
              <div
                key={i}
                className={`sd-trend-col ${skel ? 'sd-trend-col--skel' : ''}`}
                style={{ height: `${h}%` }}
                title={`${d.critical} critical · ${d.high} high · ${d.medium} medium · ${d.low} low`}
              >
                {!skel && d.low      > 0 && <div className="sd-trend-seg sd-trend-seg--low"      style={{ flex: d.low }} />}
                {!skel && d.medium   > 0 && <div className="sd-trend-seg sd-trend-seg--medium"   style={{ flex: d.medium }} />}
                {!skel && d.high     > 0 && <div className="sd-trend-seg sd-trend-seg--high"     style={{ flex: d.high }} />}
                {!skel && d.critical > 0 && <div className="sd-trend-seg sd-trend-seg--critical" style={{ flex: d.critical }} />}
              </div>
            );
          })}
        </div>

        <div className="sd-trend-axis">
          <span>{axisLeft}</span>
          <span>Heute</span>
        </div>
      </div>

      <div className="sd-trend-legend">
        <span className="sd-trend-legend__item">
          <span className="sd-trend-seg sd-trend-seg--critical" style={{ width: 10, height: 10 }} />
          <span>Critical</span>
          <span className="sd-trend-legend__count">{totals.critical}</span>
          <span className="sd-trend-legend__pct">{pct(totals.critical)}</span>
        </span>
        <span className="sd-trend-legend__item">
          <span className="sd-trend-seg sd-trend-seg--high" style={{ width: 10, height: 10 }} />
          <span>High</span>
          <span className="sd-trend-legend__count">{totals.high}</span>
          <span className="sd-trend-legend__pct">{pct(totals.high)}</span>
        </span>
        <span className="sd-trend-legend__item">
          <span className="sd-trend-seg sd-trend-seg--medium" style={{ width: 10, height: 10 }} />
          <span>Medium</span>
          <span className="sd-trend-legend__count">{totals.medium}</span>
          <span className="sd-trend-legend__pct">{pct(totals.medium)}</span>
        </span>
        <span className="sd-trend-legend__item">
          <span className="sd-trend-seg sd-trend-seg--low" style={{ width: 10, height: 10 }} />
          <span>Low</span>
          <span className="sd-trend-legend__count">{totals.low}</span>
          <span className="sd-trend-legend__pct">{pct(totals.low)}</span>
        </span>
      </div>
    </section>
  );
}

// ── 8) Triage Queue ────────────────────────────────────────────
const QUEUE_BANDS = [
  { key: 'escalate', label: 'ESCALATE' },
  { key: 'act',      label: 'ACT'      },
  { key: 'mitigate', label: 'MITIGATE' },
  { key: 'pending',  label: 'PENDING'  },
  { key: 'monitor',  label: 'MONITOR'  },
  { key: 'noise',    label: 'NOISE'    },
];

function FindingRow({ f, checked, onToggle }) {
  return (
    <details className="sd-finding">
      <summary className="sd-finding__summary">
        <input
          type="checkbox"
          className="sd-checkbox"
          checked={checked}
          onChange={(e) => { e.stopPropagation(); onToggle(f.cve); }}
          onClick={(e) => e.stopPropagation()}
          aria-label={`${f.cve} auswählen`}
        />
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
        <span className={`sd-cap ${f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'sd-cap--accent' : 'sd-cap--neutral'}`}>
          {f.severity}
        </span>
      </summary>
      <div className="sd-finding__body">
        <p className="sd-ai-eyebrow">KI-Bewertung</p>
        <p className="sd-ai-text">{f.ai}</p>
      </div>
    </details>
  );
}

function Band({ band, defaultOpen, selected, toggleSelected, acked, onAck, onUndo }) {
  const [armed, setArmed] = useState(false);
  const items = Array.isArray(SD.TRIAGE[band.key]) ? SD.TRIAGE[band.key] : [];
  const count = Array.isArray(SD.TRIAGE[band.key]) ? items.length : SD.TRIAGE[band.key];
  const isPending = band.key === 'pending';

  // Stop the summary from toggling the <details> when interacting with controls.
  const swallow = (e) => { e.preventDefault(); e.stopPropagation(); };

  // ── Acknowledged rest-state — band is closed, struck, undoable ──
  if (acked) {
    return (
      <div className="sd-band sd-band--acked">
        <div className="sd-band__summary">
          <span className="sd-band__chev" aria-hidden="true">›</span>
          <span className={`sd-badge sd-badge--${band.key}`}>{band.label}</span>
          <span className="sd-band__acked-tag">
            <span className="dot" aria-hidden="true" />
            {count} acknowledged
          </span>
          <button type="button" className="sd-band__undo" onClick={() => onUndo(band.key)}>
            Undo
          </button>
          <span className="sd-band__count sd-band__count--acked"><b>{count}</b>findings</span>
        </div>
      </div>
    );
  }

  return (
    <details className="sd-band" open={defaultOpen}>
      <summary className="sd-band__summary">
        <span className="sd-band__chev" aria-hidden="true">›</span>
        <span className={`sd-badge sd-badge--${band.key}`}>{band.label}</span>
        <span aria-hidden="true" />
        <span className="sd-band__actions">
          {isPending ? null : armed ? (
            <span className="sd-band-ack-confirm" onClick={swallow}>
              <span className="sd-band-ack-confirm__q">Acknowledge <b>{count}</b> findings?</span>
              <button
                type="button"
                className="sd-band-ack-confirm__yes"
                onClick={(e) => { swallow(e); setArmed(false); onAck(band.key); }}
              >
                Confirm
              </button>
              <button
                type="button"
                className="sd-band-ack-confirm__no"
                onClick={(e) => { swallow(e); setArmed(false); }}
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              className="sd-band-ack"
              onClick={(e) => { swallow(e); setArmed(true); }}
            >
              <span className="sd-band-ack__check" aria-hidden="true">
                <svg width="9" height="9" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6">
                  <path d="M2.5 6.5 5 9l4.5-5.5" strokeLinecap="square" />
                </svg>
              </span>
              Acknowledge all
            </button>
          )}
        </span>
        <span className="sd-band__count"><b>{count}</b>findings</span>
      </summary>
      {items.length > 0 && (
        <div className="sd-band__body">
          <div className="sd-findings-head" role="row">
            <span />
            <span>CVE / Titel</span>
            <span>Paket</span>
            <span className="sd-findings-head__right">EPSS</span>
            <span className="sd-findings-head__right">CVSS</span>
            <span className="sd-findings-head__right">Severity</span>
          </div>
          {items.map(f => (
            <FindingRow
              key={f.cve}
              f={f}
              checked={selected.has(f.cve)}
              onToggle={toggleSelected}
            />
          ))}
        </div>
      )}
    </details>
  );
}

function TriageQueue() {
  const [selected, setSelected] = useState(() => new Set());
  const [ackedBands, setAckedBands] = useState(() => new Set());
  const toggleSelected = useCallback((cve) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(cve) ? next.delete(cve) : next.add(cve);
      return next;
    });
  }, []);

  const ackBand = useCallback((key) => {
    setAckedBands(prev => new Set(prev).add(key));
  }, []);
  const undoBand = useCallback((key) => {
    setAckedBands(prev => { const next = new Set(prev); next.delete(key); return next; });
  }, []);

  // Total open (matches HEADER_STATS.open) — actionable finding count.
  const open = SD.HEADER_STATS.open;

  return (
    <section className="sd-section">
      <p className="sd-eyebrow">Triage queue · findings</p>
      <div className="sd-queue-head">
        <h2 className="sd-h3 sd-queue-h3">{open} offen · sortiert nach Risk-Band</h2>
        <span className="sd-queue-meta">{SD.HEADER_STATS.total} Findings gesamt</span>
      </div>

      <div className="sd-queue-toolbar">
        <button type="button" disabled={selected.size === 0}>
          Auswahl ack {selected.size > 0 ? `(${selected.size})` : ''}
        </button>
        <button type="button" style={{ marginLeft: 'auto' }}>
          ↓ CSV exportieren
        </button>
      </div>

      {QUEUE_BANDS.map(b => (
        <Band
          key={b.key}
          band={b}
          defaultOpen={b.key === 'escalate'}
          selected={selected}
          toggleSelected={toggleSelected}
          acked={ackedBands.has(b.key)}
          onAck={ackBand}
          onUndo={undoBand}
        />
      ))}

      <div className="workflow-card__footer" style={{ paddingTop: 22, justifyContent: 'center' }}>
        <span>{SD.HEADER_STATS.total} Findings gesamt</span>
      </div>
    </section>
  );
}

// ── Top-level ServerDetail ────────────────────────────────────
function ServerDetail({ skeletonMode = false } = {}) {
  const [view, setView] = useState('detail');   // 'detail' | 'settings' | 'chat'
  const [chatCtx, setChatCtx] = useState(null);
  // Persist threads per group across opening/closing the chat sub-view.
  const [conversations, setConversations] = useState({});
  const host = SD.HOST;

  const openChat = useCallback((ctx) => { setChatCtx(ctx); setView('chat'); }, []);

  if (view === 'settings') {
    return <ServerSettings host={host} onBack={() => setView('detail')} />;
  }

  if (view === 'chat' && chatCtx) {
    return (
      <WorkflowChat
        host={host}
        ctx={chatCtx}
        conversations={conversations}
        setConversations={setConversations}
        onBack={() => setView('detail')}
      />
    );
  }

  return (
    <div className="server-detail">
      <HeaderStrip host={host} onOpenSettings={() => setView('settings')} />
      <Sysline host={host} />

      <Workflows onChat={openChat} />
      <HeaderStats skel={skeletonMode} />
      <Heartbeat   skel={skeletonMode} />
      <SeverityTrend skel={skeletonMode} />
      <TriageQueue />
    </div>
  );
}

window.ServerDetail = ServerDetail;
