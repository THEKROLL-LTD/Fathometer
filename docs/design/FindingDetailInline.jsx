/* Fathometer — FindingDetailInline.jsx (Block AA, ADR-0041 Mockup)
   ---------------------------------------------------------------
   Zweck: Layout-Vorlage für die erweiterte `<details class="sd-finding">`-
   Row in Server-Detail-Triage, Bucket-View und Pending-Sammler. Ersetzt das
   bisherige Detail-Modal und den `?flat=1`-Switch.

   Was hier gezeigt wird:
     1. Row collapsed (Status quo, unverändert).
     2. Row expanded — voller neuer Body mit AI-Reason + Abhaken-Button,
        Description, Primary-URL, References, Notes-Thread.
     3. Row expanded ohne AI-Reason (LLM-Pass-2 noch nicht gelaufen).
     4. Row expanded im Status "acknowledged" — Button wird "Re-open".

   Was hier NICHT mehr auftaucht (Doppel-Daten zur Summary, bewusst weg):
     - CVSS, EPSS, KEV-Badge, Title, Paket, Severity — alle in der Summary-
       Zeile bereits sichtbar.

   CSS-Klassen: maximaler Reuse der existierenden `sd-finding*`-Klassen aus
   `frontend/src/css/components/server-detail.css`. Neue Sub-Klassen für die
   Body-Sektionen werden hier als Inline-Styles skizziert — der Übersetzer
   nach Jinja+HTMX zieht sie in `server-detail.css` als BEM-Sub-Klassen ein
   (z. B. `.sd-finding__cve-body`, `.sd-finding__refs`, `.sd-finding__primary`,
   `.sd-finding__notes`).

   Memory-Anker:
     - [feedback_no_forced_comments]   — Notes-Add-Form ohne required.
     - [feedback_server_detail_less_is_more] — keine doppelten Metrik-Pills.
     - [feedback_design_mockups_react] — Mockup-Format React+JSX.
*/

const { useState } = React;

// ── Mock-Daten ──────────────────────────────────────────────
const MOCK_FINDINGS = [
  {
    id: 4711,
    identifier_key: 'CVE-2018-1121',
    title: 'procps: process hiding through race condition enumerating /proc',
    package_name: 'linux-modules-5.15.0-179-generic',
    installed_version: '5.15.0-179.189',
    fixed_version: null,
    epss_score: 0.020,
    cvss_v3_score: 5.9,
    severity: 'low',
    is_kev: false,
    status: 'open',
    risk_band: 'escalate',
    risk_band_reason:
      'haproxy on 0.0.0.0:80 PUBLIC-EXPOSED; kernel modules loaded system-wide, ' +
      'reachable via network; CVE-2024-53179 high severity, no fix',
    description:
      'procps-ng, in versions prior to 3.3.15, is vulnerable to a local privilege ' +
      'escalation in top. If a user runs top with HOME unset in an attacker-controlled ' +
      'directory, the attacker can achieve privilege escalation by exploiting one of ' +
      'several vulnerabilities in the config_file() function.',
    primary_url: 'https://avd.aquasec.com/nvd/cve-2018-1121',
    references: [
      'https://www.openwall.com/lists/oss-security/2018/05/22/7',
      'https://lists.debian.org/debian-lts-announce/2018/06/msg00010.html',
      'https://access.redhat.com/security/cve/CVE-2018-1121',
      'https://ubuntu.com/security/CVE-2018-1121',
      'https://nvd.nist.gov/vuln/detail/CVE-2018-1121',
      'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
    ],
    notes: [
      { id: 1, author: 'sven', created_at_rel: 'vor 2 Tagen', text: 'Triage: niedrige Priorität, nicht produktionsrelevant.' },
    ],
  },
  {
    // Variante: noch ohne AI-Reason (Pass-2 ausstehend)
    id: 4712,
    identifier_key: 'CVE-2024-7264',
    title: 'curl: ASN.1 date parser overread',
    package_name: 'libcurl4',
    installed_version: '7.81.0-1ubuntu1.20',
    fixed_version: '7.81.0-1ubuntu1.21',
    epss_score: 0.001,
    cvss_v3_score: 5.3,
    severity: 'medium',
    is_kev: false,
    status: 'open',
    risk_band: 'act',
    risk_band_reason: null,
    description:
      'libcurl performs ASN.1 date parsing in a way that may read one byte beyond ' +
      'the end of the input buffer. The risk of impact is considered low, as the ' +
      'overread is constrained and the typical use does not expose the byte.',
    primary_url: 'https://curl.se/docs/CVE-2024-7264.html',
    references: [
      'https://curl.se/docs/CVE-2024-7264.html',
      'https://hackerone.com/reports/2559516',
    ],
    notes: [],
  },
  {
    // Variante: bereits acknowledged → Button "Re-open"
    id: 4713,
    identifier_key: 'CVE-2023-39320',
    title: 'golang: html/template: improper handling of empty HTML attributes',
    package_name: 'github.com/foo/bar@/srv/app/go.mod',
    installed_version: 'v1.4.0',
    fixed_version: 'v1.5.1',
    epss_score: 0.004,
    cvss_v3_score: 6.1,
    severity: 'medium',
    is_kev: false,
    status: 'acknowledged',
    risk_band: 'monitor',
    risk_band_reason:
      'lang-pkg in einer internen Tool-Binary; nicht öffentlich gemounted, kein ' +
      'http-Handler.',
    description:
      'Templates containing actions in unquoted HTML attributes (e.g. `attr={{.}}`) ' +
      'do not consider whether the attribute contains whitespace, allowing for ' +
      'injection of additional attributes when the action value contains a space.',
    primary_url: 'https://pkg.go.dev/vuln/GO-2023-2041',
    references: [
      'https://pkg.go.dev/vuln/GO-2023-2041',
      'https://github.com/advisories/GHSA-9j7m-gj95-hwfg',
    ],
    notes: [
      { id: 11, author: 'system-ack', created_at_rel: 'gestern', text: 'Akzeptiertes Restrisiko, Tool nicht extern erreichbar.' },
    ],
  },
];

// ── Reusable Sub-Components ─────────────────────────────────

function SummaryRow({ f }) {
  // Spiegel der heutigen .sd-finding__summary — unverändert, hier nur als
  // visuelle Referenz reproduziert (Brand-Sache, kein Layout-Vorschlag).
  const sev = (f.severity || '').toLowerCase();
  const sevAccent = sev === 'critical' || sev === 'high';
  return (
    <summary className="sd-finding__summary" style={summaryStyle}>
      <input type="checkbox" className="sd-checkbox" aria-label={`Finding ${f.identifier_key} auswählen`} onClick={(e) => e.stopPropagation()} />

      <div className="sd-finding__cve">
        <span className="sd-finding__cve-id">{f.identifier_key}{f.is_kev ? <span style={kevBadge}> KEV</span> : null}</span>
        {f.title ? <span className="sd-finding__title" title={f.title}>{f.title}</span> : null}
      </div>

      <div className="sd-finding__pkg">
        <span className="sd-finding__pkg-name">{f.package_name}</span>
        {f.installed_version ? (
          <span className="sd-finding__pkg-diff">
            <span className="sd-finding__pkg-from">{f.installed_version}</span>
            {f.fixed_version ? (
              <>
                <span className="sd-finding__pkg-arrow">→</span>
                <span className="sd-finding__pkg-to">{f.fixed_version}</span>
              </>
            ) : null}
          </span>
        ) : null}
      </div>

      <span className="sd-cap sd-cap--neutral" style={capStyle}>{f.epss_score != null ? f.epss_score.toFixed(3) : '—'}</span>
      <span className="sd-cap sd-cap--neutral" style={capStyle}>{f.cvss_v3_score != null ? f.cvss_v3_score.toFixed(1) : '—'}</span>
      <span className={`sd-cap ${sevAccent ? 'sd-cap--accent' : 'sd-cap--neutral'}`} style={capStyle}>
        {sev ? sev.toUpperCase() : '—'}
      </span>
    </summary>
  );
}

function BodyHeader({ f, onAckClick }) {
  // Zeile 1 im Body: KI-Bewertung (oder Skel) + Abhaken-/Reopen-Button rechts.
  const isAck = f.status === 'acknowledged';
  return (
    <div className="sd-finding__bodyhead" style={bodyHeadStyle}>
      <div style={{ flex: 1, minWidth: 0 }}>
        {f.risk_band_reason ? (
          <>
            <p className="sd-finding__reason-eyebrow" style={eyebrowStyle}>KI-Bewertung</p>
            <p className="sd-finding__reason-text" style={reasonStyle}>{f.risk_band_reason}</p>
          </>
        ) : (
          <p style={{ ...reasonStyle, color: 'var(--text-tertiary)' }}>
            KI-Bewertung steht aus — Pass 2 läuft asynchron.
          </p>
        )}
      </div>
      <div style={{ flexShrink: 0, paddingLeft: 16 }}>
        <button type="button" onClick={onAckClick} className="sd-finding__action-btn" style={actionBtnStyle}>
          {isAck ? 'Re-open …' : 'Abhaken …'}
        </button>
      </div>
    </div>
  );
}

function PrimaryLink({ url }) {
  if (!url) return null;
  return (
    <div className="sd-finding__primary" style={{ marginTop: 18 }}>
      <p className="sd-finding__reason-eyebrow" style={eyebrowStyle}>Quelle</p>
      <a href={url} target="_blank" rel="noopener noreferrer" style={primaryLinkStyle}>
        {url}
      </a>
    </div>
  );
}

function Description({ text }) {
  if (!text) return null;
  return (
    <div className="sd-finding__desc" style={{ marginTop: 18 }}>
      <p className="sd-finding__reason-eyebrow" style={eyebrowStyle}>Beschreibung</p>
      <p style={descStyle}>{text}</p>
    </div>
  );
}

function References({ urls }) {
  if (!urls || urls.length === 0) return null;
  return (
    <div className="sd-finding__refs" style={{ marginTop: 18 }}>
      <p className="sd-finding__reason-eyebrow" style={eyebrowStyle}>References ({urls.length})</p>
      <ul style={refsListStyle}>
        {urls.map((u) => (
          <li key={u} style={{ margin: 0, padding: 0 }}>
            <a href={u} target="_blank" rel="noopener noreferrer" style={refLinkStyle} title={u}>{u}</a>
          </li>
        ))}
      </ul>
    </div>
  );
}

function NotesThread({ finding }) {
  // Mock — entspricht dem bestehenden findings/_notes_thread.html.
  const [draft, setDraft] = useState('');
  const [notes, setNotes] = useState(finding.notes || []);
  const submitNote = (e) => {
    e.preventDefault();
    const body = draft.trim();
    if (!body) return;
    setNotes([{ id: Date.now(), author: 'sven', created_at_rel: 'gerade eben', text: body }, ...notes]);
    setDraft('');
  };
  return (
    <div className="sd-finding__notes" style={{ marginTop: 18 }}>
      <p className="sd-finding__reason-eyebrow" style={eyebrowStyle}>Notizen</p>
      {notes.length === 0 ? (
        <p style={{ ...descStyle, color: 'var(--text-tertiary)', margin: '0 0 10px' }}>Noch keine Notizen.</p>
      ) : (
        <ul style={notesListStyle}>
          {notes.map((n) => (
            <li key={n.id} style={noteItemStyle}>
              <header style={noteHeaderStyle}>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{n.author}</span>
                <time style={{ color: 'var(--text-tertiary)' }}>{n.created_at_rel}</time>
              </header>
              <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--text-secondary)' }}>{n.text}</p>
            </li>
          ))}
        </ul>
      )}

      {/* Add-Note-Form — kein required, kein Pflicht-Hint (ADR-0006) */}
      <form onSubmit={submitNote} style={{ marginTop: 10 }}>
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={2}
          placeholder="Hinweis für das Team … (Markdown-Subset)"
          aria-label="Notiz-Text"
          style={textareaStyle}
        />
        <div style={{ textAlign: 'right', marginTop: 6 }}>
          <button type="submit" disabled={!draft.trim()} style={noteSubmitStyle}>Note hinzufügen</button>
        </div>
      </form>
    </div>
  );
}

function ExpandedFinding({ f, open, onToggle }) {
  const [modalOpen, setModalOpen] = useState(false);
  return (
    <details open={open} onClick={(e) => { e.preventDefault(); onToggle(); }} className="sd-finding" style={detailsStyle}>
      <SummaryRow f={f} />
      {open ? (
        <div className="sd-finding__body" style={bodyStyle}>
          <BodyHeader f={f} onAckClick={() => setModalOpen(true)} />
          <Description text={f.description} />
          <PrimaryLink url={f.primary_url} />
          <References urls={f.references} />
          <NotesThread finding={f} />
        </div>
      ) : null}

      {modalOpen ? (
        <FakeAckModal f={f} onClose={() => setModalOpen(false)} />
      ) : null}
    </details>
  );
}

function FakeAckModal({ f, onClose }) {
  // Mockup-Stub für das beibehaltene `findings/_ack_modal.html` / `_status_change_modal.html`.
  // Im echten System bleibt das Modal ein eigenständiges Partial — nur die
  // *Detail*-Inhalte ziehen aus dem Modal in den Inline-Body um.
  const isAck = f.status === 'acknowledged';
  return (
    <div onClick={onClose} style={modalBackdropStyle}>
      <div onClick={(e) => e.stopPropagation()} style={modalBoxStyle}>
        <h3 style={{ margin: '0 0 12px', fontSize: 16, color: 'var(--text-primary)' }}>
          {isAck ? 'Finding wieder öffnen' : 'Finding abhaken'}: <span style={{ fontFamily: 'var(--font-mono)' }}>{f.identifier_key}</span>
        </h3>
        <p style={{ ...descStyle, marginBottom: 12 }}>
          Optional kannst du einen Kommentar dazu hinterlegen. Der Kommentar erscheint als Note im
          Thread und ist <strong>niemals Pflicht</strong>.
        </p>
        <textarea rows={3} placeholder="Kommentar (optional)" style={textareaStyle} />
        <div style={{ marginTop: 12, textAlign: 'right' }}>
          <button type="button" onClick={onClose} style={{ ...noteSubmitStyle, background: 'transparent', marginRight: 8 }}>Abbrechen</button>
          <button type="button" onClick={onClose} style={noteSubmitStyle}>{isAck ? 'Re-open' : 'Abhaken'}</button>
        </div>
      </div>
    </div>
  );
}

// ── Root ────────────────────────────────────────────────────

function Mockup() {
  // Drei Rows: nur die zweite ist initial collapsed, damit der User beide
  // Zustände gleichzeitig sieht.
  const [openMap, setOpenMap] = useState({ 4711: true, 4712: false, 4713: true });
  const toggle = (id) => setOpenMap({ ...openMap, [id]: !openMap[id] });

  return (
    <div style={{ maxWidth: 1200, margin: '40px auto', padding: 24, background: 'var(--surface-base)' }}>
      <h2 style={{ marginTop: 0, marginBottom: 4, fontSize: 18, color: 'var(--text-primary)' }}>
        Block AA · Mockup — Finding-Detail Inline
      </h2>
      <p style={{ ...descStyle, marginTop: 0, marginBottom: 24 }}>
        Vorlage für die erweiterte <code style={codeStyle}>&lt;details class="sd-finding"&gt;</code>-Row.
        Ersetzt das bisherige Detail-Modal und den <code style={codeStyle}>?flat=1</code>-Switch.
        Drei Beispiel-Zeilen: <i>mit AI-Reason</i> (collapsed Beispiel weglassen), <i>ohne AI-Reason</i>,
        <i> bereits acknowledged</i>.
      </p>

      <div style={{ borderTop: 'var(--hairline)' }}>
        <div className="sd-findings-head" style={headStyle} aria-hidden="true">
          <span></span>
          <span>CVE / Titel</span>
          <span>Paket</span>
          <span style={{ textAlign: 'right' }}>EPSS</span>
          <span style={{ textAlign: 'right' }}>CVSS</span>
          <span style={{ textAlign: 'right' }}>Severity</span>
        </div>
        {MOCK_FINDINGS.map((f) => (
          <ExpandedFinding key={f.id} f={f} open={openMap[f.id]} onToggle={() => toggle(f.id)} />
        ))}
      </div>
    </div>
  );
}

// ── Inline-Styles (Mockup-only — Production zieht sie nach server-detail.css)

const summaryStyle = {
  display: 'grid',
  gridTemplateColumns: '28px 1.4fr 1.2fr 70px 60px 84px',
  gap: 16,
  alignItems: 'center',
  padding: '14px 16px',
  cursor: 'pointer',
  fontSize: 12.5,
  fontFamily: 'var(--font-mono)',
};

const headStyle = {
  display: 'grid',
  gridTemplateColumns: '28px 1.4fr 1.2fr 70px 60px 84px',
  gap: 16,
  padding: '8px 16px',
  fontSize: 10,
  letterSpacing: '0.15em',
  textTransform: 'uppercase',
  color: 'var(--text-tertiary)',
  borderBottom: 'var(--hairline)',
};

const detailsStyle = {
  borderBottom: 'var(--hairline)',
  background: 'transparent',
};

const bodyStyle = {
  padding: '0 16px 22px 60px',
  animation: 'sd-flyout-in 240ms var(--ease-materialize)',
};

const bodyHeadStyle = {
  display: 'flex',
  alignItems: 'flex-start',
  gap: 16,
  paddingTop: 4,
  paddingBottom: 8,
  borderTop: 'var(--hairline)',
};

const eyebrowStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 9.5,
  letterSpacing: '0.2em',
  textTransform: 'uppercase',
  color: 'var(--accent)',
  margin: '0 0 6px',
};

const reasonStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  lineHeight: 1.7,
  color: 'var(--text-secondary)',
  margin: 0,
  maxWidth: '78ch',
};

const descStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 12.5,
  lineHeight: 1.7,
  color: 'var(--text-secondary)',
  margin: 0,
  maxWidth: '78ch',
  whiteSpace: 'pre-line',
};

const actionBtnStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 11,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  padding: '8px 14px',
  background: 'transparent',
  color: 'var(--text-primary)',
  border: '1px solid var(--accent)',
  borderRadius: 'var(--radius-sm)',
  cursor: 'pointer',
};

const primaryLinkStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 12.5,
  color: 'var(--accent)',
  textDecoration: 'none',
  borderBottom: '1px solid var(--accent-glow)',
  paddingBottom: 1,
};

const refsListStyle = {
  listStyle: 'none',
  margin: 0,
  padding: 0,
  display: 'grid',
  gap: 4,
  maxWidth: '78ch',
};

const refLinkStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 11.5,
  color: 'var(--text-secondary)',
  textDecoration: 'none',
  borderBottom: '1px dotted var(--border-visible)',
  paddingBottom: 1,
  display: 'inline-block',
  maxWidth: '100%',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
};

const notesListStyle = {
  listStyle: 'none',
  margin: '0 0 10px',
  padding: 0,
  display: 'grid',
  gap: 8,
};

const noteItemStyle = {
  background: 'var(--surface-raised)',
  border: 'var(--hairline)',
  padding: '8px 10px',
  borderRadius: 'var(--radius-sm)',
};

const noteHeaderStyle = {
  display: 'flex',
  justifyContent: 'space-between',
  fontSize: 10.5,
  letterSpacing: '0.05em',
  marginBottom: 4,
  color: 'var(--text-tertiary)',
};

const textareaStyle = {
  width: '100%',
  background: 'var(--surface-raised)',
  border: '1px solid var(--border-visible)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-mono)',
  fontSize: 12,
  padding: '8px 10px',
  resize: 'vertical',
  outline: 'none',
};

const noteSubmitStyle = {
  fontFamily: 'var(--font-mono)',
  fontSize: 11,
  letterSpacing: '0.08em',
  textTransform: 'uppercase',
  padding: '6px 12px',
  background: 'var(--accent)',
  color: 'var(--surface-base)',
  border: '1px solid var(--accent)',
  borderRadius: 'var(--radius-sm)',
  cursor: 'pointer',
};

const capStyle = {
  display: 'inline-block',
  padding: '2px 8px',
  border: 'var(--hairline)',
  borderRadius: 'var(--radius-sm)',
  fontFamily: 'var(--font-mono)',
  fontSize: 11,
  textAlign: 'right',
};

const kevBadge = {
  marginLeft: 6,
  padding: '0 5px',
  fontSize: 10,
  color: 'var(--accent)',
  border: '1px solid var(--accent)',
  borderRadius: 'var(--radius-sm)',
};

const codeStyle = {
  fontFamily: 'var(--font-mono)',
  background: 'var(--surface-raised)',
  padding: '1px 5px',
  border: 'var(--hairline)',
  borderRadius: 'var(--radius-sm)',
};

const modalBackdropStyle = {
  position: 'fixed',
  inset: 0,
  background: 'var(--backdrop-modal)',
  backdropFilter: 'var(--backdrop-blur)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 100,
};

const modalBoxStyle = {
  background: 'var(--surface-elevated)',
  border: 'var(--border)',
  padding: 24,
  width: 'min(540px, 90vw)',
  borderRadius: 'var(--radius-md)',
};

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<Mockup />);
