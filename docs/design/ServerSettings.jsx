/* Fathometer — ServerSettings sub-view.
   Mounted as inner-content of `.main` when the operator clicks the gear icon.
   No comment fields. No justification fields. Save = single outlined-cyan button. */

const SD_AVAILABLE_TAGS = ['#staging', '#kubernetes', '#dmz', '#mail', '#db', '#backup', '#monitoring'];
const SD_GROUPS = ['Prod', 'Staging', 'CI', 'Backup', 'Edge', 'Observability'];

function ServerSettings({ host, onBack }) {
  const [tags, setTags]         = React.useState(['#prod', '#edge', '#eu-west']);
  const [group, setGroup]       = React.useState('Prod');
  const [interval, setInterval_] = React.useState(24);
  const [pickedTag, setPickedTag] = React.useState('');

  const removeTag = (t) => setTags(tags.filter(x => x !== t));
  const addTag    = () => {
    if (!pickedTag || tags.includes(pickedTag)) return;
    setTags([...tags, pickedTag]);
    setPickedTag('');
  };

  return (
    <div className="server-detail">
      {/* Header strip — back link, centred title */}
      <div className="sd-settings-head">
        <button type="button" className="sd-back" onClick={onBack} aria-label="Zurück">
          <span className="sd-back__arrow" aria-hidden="true">←</span>
          <span>Zurück</span>
        </button>
        <h1 className="sd-settings-title">
          Einstellungen · <b>{host.host}</b>
        </h1>
        <span aria-hidden="true" />
      </div>

      <div className="sd-settings-sections">
        {/* ── Tags ─────────────────────────────────────────── */}
        <section className="sd-settings-section">
          <h2 className="sd-settings-section__title">Tags</h2>
          <div className="sd-tags" role="list">
            {tags.map(t => (
              <span key={t} className="sd-tag" role="listitem">
                <span>{t}</span>
                <button
                  type="button"
                  className="sd-tag__x"
                  onClick={() => removeTag(t)}
                  aria-label={`Tag ${t} entfernen`}
                >×</button>
              </span>
            ))}
          </div>
          <div className="sd-tag-add">
            <select
              className="sd-select"
              value={pickedTag}
              onChange={e => setPickedTag(e.target.value)}
              aria-label="Tag wählen"
            >
              <option value="">+ Tag wählen…</option>
              {SD_AVAILABLE_TAGS.filter(t => !tags.includes(t)).map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <button
              type="button"
              className="sd-add-btn"
              onClick={addTag}
              disabled={!pickedTag}
            >Hinzufügen</button>
          </div>
          <p className="sd-settings-section__hint">Tags helfen beim Filtern in der Server-Liste.</p>
        </section>

        {/* ── Gruppe ───────────────────────────────────────── */}
        <section className="sd-settings-section">
          <h2 className="sd-settings-section__title">Gruppe</h2>
          <select
            className="sd-select"
            value={group}
            onChange={e => setGroup(e.target.value)}
            aria-label="Gruppe wählen"
          >
            {SD_GROUPS.map(g => <option key={g} value={g}>{g}</option>)}
          </select>
          <p className="sd-settings-section__hint">Server-Gruppen-Feature kommt bald.</p>
        </section>

        {/* ── Scan-Intervall ───────────────────────────────── */}
        <section className="sd-settings-section">
          <h2 className="sd-settings-section__title">Scan-Intervall</h2>
          <div className="sd-number-wrap">
            <input
              className="sd-input"
              type="number"
              min={1}
              max={168}
              value={interval}
              onChange={e => setInterval_(Number(e.target.value))}
              aria-label="Scan-Intervall in Stunden"
            />
            <span className="sd-number-wrap__suffix">Stunden</span>
          </div>
          <p className="sd-settings-section__hint">Wird vom Agent beim Install gesetzt.</p>
        </section>
      </div>

      <div className="sd-settings-footer">
        <button type="button" className="sd-save">Speichern</button>
      </div>
    </div>
  );
}

window.ServerSettings = ServerSettings;
