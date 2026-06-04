## ADR-0044 — Server-scoped Bulk-Acknowledge pro Risk-Band

**Status:** Akzeptiert · **Datum:** 2026-06-04 · **Bezug:** Loest **ADR-0022 §Bulk-Ack-„noise"-Workflow** ab (noise-only-Beschraenkung und ID-Listen-Transport entfallen); loest **ADR-0039 §2** (Fragment-Endpoint `GET /<id>/fragments/noise`) ab — das Noise-Fragment entfaellt ersatzlos. **ADR-0006** (keine Pflicht-Kommentare) gilt unveraendert. **ADR-0037 §(4)** (`POST /findings/bulk/acknowledge` der Bucket-View) ist ein anderer Endpoint und bleibt unberuehrt. Einzel-Acknowledge (`POST /findings/<id>/acknowledge`) bleibt unveraendert.

**Amendment 2026-06-04 (TICKET-009-Nachzügler):** Die UI-Mechanik aus §(2)/§(3) wurde vor dem Merge auf die Design-Vorgabe (`docs/design/ServerDetail.jsx`) angepasst: **kein Modal und keine Kommentar-Eingabe** mehr, stattdessen ein **Inline-Confirm/Cancel** direkt im Band-Header. Die `examples` in der dry_run-Response entfallen ersatzlos. Details in §(2)/§(3) unten (mit Amendment-Markierung).

## Kontext

Die Server-Detail-Seite (`/servers/<id>`) hat heute genau einen Bulk-Shortcut: „Acknowledge all noise on this server (N)" (Block O, ADR-0022). Der Mechanismus dahinter hat zwei Probleme — eines davon ist ein Bug, das andere eine Funktionsluecke.

### Problem 1 — „all noise" ackt maximal 50 Findings

Die Implementierung transportiert die zu ackenden Findings als **explizite ID-Liste durch den Client**:

1. `server_detail.noise_fragment` laedt noise-Findings mit `.limit(50)` (`app/views/server_detail.py:1046`, ADR-0039 §2: „Limit 50 deckelt die Hydrations-Kosten").
2. `noise_fragment.html` bettet diese (max. 50) IDs ins Template ein und reicht sie an die Alpine-Komponente `bulkAckNoise(() => [...])`.
3. `bulk_ack_noise.js` postet genau diese ID-Liste als Flavor A (`finding_ids`) mit `risk_band_filter="noise"` an `POST /api/findings/bulk-acknowledge`.

Der Endpoint koennte bis zu 10.000 IDs (`_MAX_FINDING_IDS`), bekommt aber nie mehr als 50. Folge auf einer Production-DB mit 2.816 noise-Findings auf einem Host: der Button verspricht „all noise (2816)", der dry_run-Preview im Modal zeigt 50, Apply ackt 50 — der Operator muesste 57-mal klicken und neu laden.

### Problem 2 — nur `noise` ist bulk-abhakbar

ADR-0022 hat den Bulk-Workflow bewusst auf `noise` beschraenkt (Sicherheits-Default gegen versehentliches Mass-Ack; `monitor` war explizit ausgenommen). Seit ADR-0043 ist das Risk-Band ein LLM-Angreifbarkeits-Urteil pro `(Group, Server)` — der Operator-Befund 2026-06-04 zeigt: nach einem Patch-Rollout oder einer Akzeptanz-Entscheidung will der Operator auch `monitor`, `mitigate`, `act` oder `escalate` eines Servers in einem Schritt abraeumen, nicht Finding fuer Finding. Die Einzelfall-Begruendung „monitor ist ein Im-Auge-behalten-Signal" traegt nicht mehr: das Abhaken ist die dokumentierte Operator-Entscheidung, das Signal zur Kenntnis genommen zu haben.

`pending` ist die Ausnahme: diese Findings warten auf die Pass-2-Bewertung (ADR-0023/0043). Ein Bulk-Ack auf `pending` waere ein Urteil ohne Bewertungsgrundlage — das bleibt verboten, und zwar server-seitig, nicht nur per UI.

## Entscheidung

### (1) Neuer Request-Flavor „Server-Scope" — der Server resolved selbst

`BulkAckRequest` (`app/schemas/bulk_request.py`) bekommt einen dritten Flavor:

```python
class BulkAckServerScope(BaseModel):
    server_id: int                      # > 0
    risk_band: Literal["escalate", "act", "mitigate", "monitor", "noise"]

class BulkAckRequest(BaseModel):
    finding_ids: list[int] | None = None      # Flavor A (unveraendert)
    match: BulkAckMatchCriterion | None = None # Flavor B (unveraendert)
    server_scope: BulkAckServerScope | None = None  # Flavor C (neu)
    dry_run: bool = True
    comment: str | None = ...
```

- Genau **einer** der drei Flavors muss befuellt sein (XOR-Validator wie bisher, erweitert auf drei).
- Der Endpoint resolved Flavor C server-seitig: `SELECT ... FROM findings WHERE server_id = :sid AND status = 'open' AND risk_band = :band`. Es wird **keine ID-Liste durch den Client transportiert** — das 50er-Limit ist damit strukturell beseitigt, nicht durch ein groesseres Limit ersetzt.
- `pending` ist nicht im `Literal` → Pydantic lehnt mit 422 ab. `unknown` ebenfalls nicht: unknown-Findings haben keine eigene Band-Sektion (ADR-0038 subsumiert sie unter dem Pending-Block) und sind damit konsistent nicht bulk-abhakbar.
- Server-Existenz-/revoked-/retired-Guard wie bei den Fragment-Endpoints (404).
- Das Feld `risk_band_filter: Literal["noise"]` (Block O) **entfaellt ersatzlos**. Sein einziger Consumer war `bulk_ack_noise.js`. Der Injection-Schutz aus ADR-0022 (eingeschleuste non-noise-IDs werden gedropped) ist bei Flavor C **per Konstruktion** obsolet: der Client liefert gar keine IDs mehr, die er manipulieren koennte. Der adversarial Fokus verschiebt sich auf den Flavor selbst (siehe §5).

### (2) dry_run liefert Count (Beispiele entfallen — Amendment 2026-06-04)

Der Zwei-Phasen-Ablauf (dry_run → apply) bleibt als generische Endpoint-Faehigkeit erhalten. Die dry_run-Response fuer Flavor C enthaelt `count` und das `server_scope`-Echo:

```json
{
  "dry_run": true,
  "count": 2816,
  "server_scope": {"server_id": 42, "risk_band": "noise"}
}
```

**Amendment 2026-06-04:** Die urspruenglich vorgesehenen `examples` (max. 5 Beispiel-Findings fuer die Modal-Preview) sind **ersatzlos entfallen** — das Band-UI nutzt keinen Modal-Preview mehr (siehe §(3)) und rendert den Count direkt aus dem server-seitig bekannten `total_count` der Band-Sektion (kein dry_run-Roundtrip im UI-Pfad). `finding_ids` war in der Flavor-C-dry_run-Response ohnehin nie enthalten (bei 100k-Findings-Servern ein MB-Payload ohne Consumer).

### (3) UI: Per-Band Inline-Confirm/Cancel im Summary-Header (Amendment 2026-06-04)

- Der Toolbar-Link „Acknowledge all noise on this host (N)" und der `sd-noise-toolbar`-Slot **entfallen**.
- Jede Risk-Band-Sektion der Triage-Queue (`_partials/risk_band_section.html`) **ausser `pending`** bekommt im `<summary>`-Header ein Hover-Control: ein „Acknowledge all"-Button mit rein **visuellem** SVG-Haekchen (`.sd-band-ack__check`, **keine** echte Checkbox). Sichtbar nur bei Hover ueber der Band-Zeile (CSS-Reveal via `opacity`); grau (`--text-tertiary`) → cyan (`--accent`) bei Hover genau ueber dem Control.
- Klick auf das Control darf das `<details>`-Akkordeon **nicht** togglen (`@click.prevent.stop`).
- **Amendment 2026-06-04 — Inline-Confirm statt Modal:** Der Klick oeffnet **kein Modal**, sondern schaltet im selben `.sd-band__actions`-Slot in einen Inline-Confirm-Zustand (`.sd-band-ack-confirm`): „Acknowledge **N** findings?  Confirm  Cancel" (N = `total_count` der Sektion, server-gerendert). „Confirm" fuehrt das Apply aus (Flavor C, `dry_run=false`), „Cancel" kehrt in den Ruhezustand zurueck. Das generische Modal-Partial, die dry_run-Beispiel-Vorschau und die **optionale Kommentar-Eingabe entfallen** — der Per-Band-Bulk-Ack schreibt **keine Notiz** mehr (ADR-0006 bleibt fuer Einzel-Ack und Flavor A/B unberuehrt; der `comment`-Parameter des Endpoints bleibt fuer jene erhalten). Markup-Struktur 1:1 aus `docs/design/ServerDetail.jsx` (`.sd-band-ack` / `.sd-band-ack-confirm`).
- Nach Apply: Toast + `window.location.reload()`. Ein gezielter OOB-Refresh der Band-Counts ist bewusst nicht Teil dieser ADR (siehe Re-Open-Trigger).

### (4) Grosse Mengen: Audit-Metadata gecappt, Notes als Bulk-Insert

Flavor C operiert realistisch auf tausenden Findings. Zwei Folge-Entscheidungen am Endpoint (gelten fuer alle Flavors):

- **Audit:** weiterhin **ein** Event `finding.bulk_acknowledged`, aber `metadata.finding_ids` wird auf die ersten **50** IDs gecappt (Praezedenz: `llm_worker.py` cappt `failed_pass1_ids[:50]`); `metadata.count` traegt immer die volle Zahl, `metadata.server_scope` den Scope. Die vollstaendige ID-Liste ist aus dem Scope + `acknowledged_at`-Zeitstempel rekonstruierbar — sie redundant in die Audit-Row zu schreiben blaeht `audit_events` ohne Erkenntnisgewinn auf.
- **Notes:** der Kommentar wird weiterhin pro Finding als `FindingNote` (`author='system-bulk-ack'`) angehaengt, aber als **ein** Bulk-Insert (`sess.execute(insert(FindingNote), rows)`) statt N× `sess.add` — bei 2.816 Findings sonst 2.816 Einzel-Statements.
- Rate-Limit bleibt 30/min pro IP (ein Flavor-C-Request ersetzt 57 Flavor-A-Requests — das Limit wird dadurch entspannter, nicht enger).

### (5) Sicherheits-Abwaegung: Aufgabe der noise-only-Beschraenkung

Diese ADR hebt eine bewusste Block-O-Sicherheitsentscheidung auf — auch `escalate`/`act` sind kuenftig per Ein-Klick-Workflow abhakbar. Das ist vertretbar, weil die Schutzschichten erhalten bleiben bzw. staerker werden:

1. **Scope-Bindung:** Flavor C ist immer auf genau einen Server und genau ein Band beschraenkt. Ein „alle offenen Findings der Flotte"-Request bleibt unmoeglich (Flavor-B-Validator unveraendert: `match` braucht `cve_id` oder `package_name`).
2. **pending-Verbot im Schema:** nicht per UI versteckt, sondern per `Literal`-Whitelist mit 422 — adversarial getestet.
3. **Zwei-Phasen + Pflicht-Bestaetigung:** dry_run-Preview mit ehrlichem Count (vorher: log, falscher 50er-Count) plus Confirm-Checkbox vor Apply.
4. **Idempotenz:** nur `status='open'` wird gewechselt; Audit-Event dokumentiert Scope, Count und Actor.
5. **Reversibilitaet:** Acknowledge ist kein destruktiver Endzustand — Re-Open pro Finding existiert (Block E).

## Konsequenzen

### Positiv

- „Acknowledge all" haelt was es verspricht — der Count am Control, im Preview und im Apply ist per Konstruktion derselbe.
- Operator kann jede abgeschlossene Band-Entscheidung (Patch-Rollout erledigt, Risiko akzeptiert) in einem Schritt dokumentieren — pro Band, pro Server.
- Drei tote Artefakte entfallen (Fragment-Endpoint, Noise-Modal, `bulk_ack_noise.js`); ein Fragment-Roundtrip pro Server-Detail-Aufruf entfaellt.
- Der Client transportiert keine ID-Listen mehr → kleinere Requests, kein Injection-Vektor, kein Drift zwischen UI-Liste und Server-Zustand.

### Negativ

- Mass-Ack auf hohen Baendern (`escalate`) ist jetzt moeglich — Fehlbedienung ackt schlimmstenfalls tausende kritische Findings. Mitigiert durch §5 (Confirm, dry_run, Scope-Bindung, Re-Open); akzeptiert.
- `UPDATE ... WHERE server_id AND risk_band AND status='open'` auf 100k-Findings-Servern haelt Locks laenger als der 50er-Batch. Akzeptiert fuer Single-User-MVP (keine konkurrierenden Writer ausser Ingest; Ingest-UPSERT trifft dieselben Rows nur beim Re-Scan desselben Servers).
- Nach Apply laedt die Seite voll neu statt die Counts per OOB zu patchen. Akzeptiert — identisches Verhalten wie heute.

### Re-Open-Trigger

- **OOB-Count-Refresh statt Full-Reload** nach Apply (Band-Counts, Tiles, Sidebar): lohnt erst, wenn der Full-Reload auf grossen Servern stoert. Dann gilt das HTMX-OOB-Single-Source-Pattern (CLAUDE.md).
- **Batched UPDATE** (Chunks à 10k) falls Lock-Dauer auf sehr grossen Servern messbar stoert.
- **Bulk-Ack fuer `pending`** nur falls sich ein legitimer Operator-Bedarf zeigt (z. B. „Server wird dekommissioniert") — dann eigene ADR mit eigenem Guard.

## Verworfene Alternativen

**(a) Limit anheben (50 → 10.000) und weiter IDs einbetten.** Verworfen: heilt das Symptom, nicht die Architektur. 10k IDs im HTML-Attribut + im JSON-Body sind MB-Payloads; bei >10k Findings ist das Problem sofort wieder da; der Drift zwischen eingebetteter Liste und DB-Zustand (Scan zwischen Render und Klick) bleibt.

**(b) Client-seitiges Batching (Loop ueber 50er-Pages).** Verworfen: N Requests, N Audit-Events, Abbruch-Zwischenzustaende, Rate-Limit-Kollision (30/min) — genau das Endlos-Iterations-Muster, gegen das das Rate-Limit existiert.

**(c) Flavor B (`match`) um `server_id`/`risk_band` erweitern.** Verworfen: Flavor B ist der Flotten-Match (cross-server per CVE/Package) mit eigener Sicherheits-Invariante („mindestens cve_id oder package_name"). Ein server-gebundener Scope in demselben Kriterium wuerde diese Invariante aufweichen und zwei Semantiken in ein Objekt mischen. Ein eigener Flavor haelt beide Invarianten trivial pruefbar.

**(d) Band-Auswahl im bestehenden Noise-Modal (Dropdown) statt Hover-Controls pro Sektion.** Verworfen: der Operator steht beim Triagieren bereits an der Band-Sektion — das Control gehoert an die Sektion, nicht in einen globalen Dialog mit Band-Selektor (ein Klick + ein Select mehr, und der Toolbar-Link suggeriert weiter „noise-Sonderfall").

**(e) `pending` zulassen mit Extra-Warnung.** Verworfen: ein Ack vor der Pass-2-Bewertung ist ein Urteil ohne Grundlage; eine Warnung macht es nicht fundierter. Wer pending-Findings abraeumen will, wartet die Bewertung ab oder ackt einzeln (bewusste Friktion).

## Bezug zu anderen ADRs

- **ADR-0022 §Bulk-Ack-„noise"-Workflow** — abgeloest durch diese ADR (noise-only, ID-Listen-Transport, `risk_band_filter`). Die uebrigen ADR-0022-Teile (Pre-Triage, Host-Snapshot, Bands) bleiben gueltig.
- **ADR-0039 §2** — der Fragment-Endpoint `GET /<id>/fragments/noise` entfaellt ersatzlos; die uebrigen Fragment-Endpoints bleiben.
- **ADR-0043** — Band-Semantik (LLM-Angreifbarkeits-Urteil) ist die fachliche Grundlage dafuer, dass jedes bewertete Band bulk-abhakbar ist und `pending` nicht.
- **ADR-0037 §(4)** — der Bucket-Bulk-Ack auf `/findings` (`POST /findings/bulk/acknowledge`) ist ein separater Endpoint und bleibt unveraendert.
- **ADR-0006** — Kommentar bleibt optional, keine Pflicht-Eingabe.

## Implementierung

Siehe `docs/tickets/TICKET-009-per-band-bulk-acknowledge.md` (drei Etappen: Schema+API, Frontend, Cleanup+Doku) mit Definition-of-Done.
