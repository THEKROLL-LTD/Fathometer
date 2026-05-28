# Architecture Decision Records (ADRs)

Kurze, datierte Entscheidungs-Dokumente zu Architektur-Punkten die später nicht ohne Begründung "verbessert" werden sollen. Format pro ADR: Kontext, Entscheidung, Begründung, Konsequenzen, Re-Open-Trigger.

## Index

| Nummer | Thema | Status |
|--------|-------|--------|
| [0001](0001-no-node-build.md) | Kein Node-Build im MVP | Superseded by 0032 (Block W führt esbuild-Build-Stage ein, Addendum 2026-05-23 zieht Tailwind/DaisyUI komplett raus) |
| [0002](0002-openai-compatible-llm.md) | OpenAI-kompatible LLM-Abstraktion | Akzeptiert |
| [0003](0003-push-not-pull.md) | Push statt Pull, keine Server-Credentials | Akzeptiert |
| [0004](0004-single-user-auth.md) | Single-User Admin-Auth im MVP | Akzeptiert |
| [0005](0005-no-raw-json-storage.md) | Roh-Trivy-JSON wird nicht persistiert | Akzeptiert |
| [0006](0006-no-forced-comments.md) | Niemals Pflicht-Kommentare in der UI | Akzeptiert |
| [0007](0007-gzip-compression.md) | Gzip-Kompression auf der Wire | Akzeptiert |
| [0008](0008-secrets-out-of-mvp.md) | Secret-Scanning out of MVP | Akzeptiert |
| [0009](0009-no-mobile.md) | Mobile-responsive Layout out of scope | Akzeptiert |
| [0010](0010-deepseek-v3-default.md) | DeepSeek V3 als LLM-Default-Modell | Akzeptiert |
| [0011](0011-lang-pkgs-target-disambiguation.md) | `package_name@target`-Disambiguation für lang-pkgs | Akzeptiert |
| [0012](0012-block-i-ui-v2.md) | Block I bringt UI v2 als separate Phase nach MVP-Abschluss | Akzeptiert |
| [0013](0013-fernet-kdf.md) | Fernet-KDF beibehalten, Schutz via README-Empfehlung + Entropie-Warning | Akzeptiert |
| [0014](0014-token-cap-best-effort.md) | Token-Cap als Best-Effort, keine Pre-Reservation | Akzeptiert |
| [0015](0015-gunicorn-gthread-for-sse.md) | Gunicorn `gthread`-Worker-Class für SSE-Endpoints | Akzeptiert |
| [0016](0016-header-and-profile-dropdown.md) | Header-Navigation kompakt, Settings und Audit ins Profile-Dropdown (Block-I-Refinement) | Teilweise abgelöst durch 0020 (Dashboard-Pane-Layout) |
| [0017](0017-dashboard-pane-single-partial.md) | Dashboard-Detail-Pane als ein gemeinsames Partial (kein HX-vs-Full-Page-Drift) | Akzeptiert |
| [0018](0018-server-detail-visual-alignment.md) | Server-Detail-Redesign (Layout, KPI-Sparklines, Trend-Berechnung, sortierbare Findings-Tabelle) | Teilweise abgelöst durch 0025 (Modi-Reduktion, Header-Pille, Lazy-Load) und 0038 (Lebenszeichen-`<dl>`-Block, Header-Sektions-Reihenfolge, 50/7→30/4) |
| [0019](0019-dashboard-polling-not-sse.md) | Dashboard-Live-Updates via HTMX-Polling statt SSE (LLM-Stream bleibt SSE) | Akzeptiert |
| [0020](0020-dashboard-cross-server-findings.md) | Dashboard-Redesign: Cross-Server-Findings-Tabelle, KPI-Sparklines, Entfernung von /findings/search (Block M) | Teilweise abgelöst durch 0025 (Findings-Section wandert auf eigene Seite) |
| [0021](0021-agent-bootstrap-installer.md) | Agent-Bootstrap-Installer + Trivy-Output-Strip + Ursachen-Felder pro Finding (Block N) | Akzeptiert |
| [0022](0022-risk-based-prioritization.md) | Risk-basierte Priorisierung: Pre-Triage-Engine, Host-Snapshot, Vendor-Severity, UI-Redesign (Block O) | Akzeptiert (§Audit-Events teilweise abgelöst durch 0027; §UI-Redesign Host-Snapshot-Sektion teilweise abgelöst durch 0038 — Pills + Slide-Down) |
| [0023](0023-llm-risk-reviewer-and-application-grouping.md) | LLM-Risk-Reviewer mit Application-Grouping (Two-Pass) und asynchroner Job-Queue (Block P) | Akzeptiert (§UI-Konsequenzen amendet durch 0038 — Workflow-Card-Drilldown, Inline-Reason) |
| [0024](0024-external-epss-kev-enrichment.md) | Externe EPSS-/KEV-Anreicherung | Akzeptiert |
| [0025](0025-server-detail-and-findings-slim-down.md) | Server-Detail- und Dashboard-Entschlackung, dedizierte Findings-Seite (Block Q) | Teilweise abgelöst durch 0037 (Cross-Server-Findings-Bucket-View) und 0041 (Flat-Switch `?flat=1` entfernt) |
| [0026](0026-async-scan-ingest.md) | Asynchroner Scan-Ingest mit `scan_ingest_jobs`-Queue (Block R) | Akzeptiert (§Status-Endpoint + §Agent-Polling teilweise abgelöst durch 0042) |
| [0027](0027-no-per-finding-risk-band-audit.md) | Keine per-Finding-`risk_band`-Audit-Events | Akzeptiert |
| [0028](0028-application-group-evaluations-junction.md) | Application-Group-Evaluations als Junction-Tabelle (Block T) | Akzeptiert |
| [0029](0029-parallel-llm-worker-concurrency.md) | Parallele LLM-Job-Verarbeitung im Worker (Single-Worker, In-Process-Concurrency, Block U) | Akzeptiert |
| [0030](0030-server-detail-performance.md) | Performance-Tuning UI-Views (Dashboard + Server-Detail + Sidebar-Lazy-Load, Block V) | Akzeptiert |
| [0031](0031-theme-switcher-removed.md) | Theme-Switcher entfernt, `data-theme="dark"` statisch (Tech-Debt-Removal) | Akzeptiert |
| [0032](0032-frontend-build-plain-css.md) | Frontend-Build-Toolchain: Plain CSS + esbuild, kein Tailwind/DaisyUI (Block W; Addendum 2026-05-23 zieht Phase 2 vor — Tailwind/DaisyUI komplett raus + Legacy-Shim für ungerefactorte Templates) | Akzeptiert |
| [0033](0033-brand-identity-fathometer.md) | Brand-Identity Fathometer + Design-Doctrine + Sprach-Policy (Block W) | Akzeptiert |
| [0034](0034-host-group-data-model.md) | Host-Group-Datenmodell (1:N, nullable, ohne Default-Group, Block W) | Akzeptiert |
| [0035](0035-daily-risk-state-heartbeat-mapping.md) | Daily-Risk-State als Heartbeat-Mapping + Viewport-Lazy-Loading (Block W) | Akzeptiert |
| [0036](0036-single-pane-polling-hx-preserve.md) | Single-Pane Dashboard-Polling mit hx-preserve + OOB-Swaps (Block W) | Akzeptiert |
| [0037](0037-findings-cross-server-bucket-view.md) | `/findings`: Cross-Server Bucket-View nach (Server, ApplicationGroup) — ersetzt ADR-0025 §(5) | Akzeptiert |
| [0038](0038-server-detail-triage-refactor.md) | Server-Detail Triage-First Content-Refactor (Sektions-/Inhalts-Umbau, Styling out-of-Scope; Block X) | Akzeptiert |
| [0039](0039-server-detail-lazy-render-architecture.md) | Server-Detail Lazy-Render-Architektur + Triage-Queue-Pagination (Block Y) | Akzeptiert |
| [0040](0040-group-and-tag-hybrid-lifecycle.md) | Hybrid-Lifecycle für Gruppen und Tags: Inline-Create im Server-Settings, `/settings/{groups,tags}` als Manage-Only (Block Z) — schließt ADR-0034 §Re-Open-Trigger CRUD-UI | Akzeptiert |
| [0041](0041-finding-detail-inline.md) | Finding-Detail Inline: `?flat=1` + Detail-Modal + flache Tabelle entfernt, erweiterter `<details>`-Body (AI-Reason, Description, Primary-URL, References, Notes), `primary_url` persistiert (Block AA) — löst ADR-0025 §Flat-Switch ab | Akzeptiert |
| [0042](0042-agent-fire-and-forget-ingest.md) | Agent-Fire-and-Forget: Job-Status-Endpoint + Polling-Loop entfernt, Agent beendet nach 202 — löst ADR-0026 §Status-Endpoint/§Agent-Polling teilweise ab | Akzeptiert |

## Wann eine neue ADR schreiben

- Wenn eine Architektur-Entscheidung getroffen wird, die nicht aus `ARCHITECTURE.md` direkt ableitbar ist.
- Wenn eine bestehende Entscheidung revidiert wird (alte ADR auf "Superseded by ADR-XXXX" setzen, neue ADR schreiben).
- Wenn ein Implementer in einem Block auf eine Wahl trifft die nachfolgende Blöcke betrifft.

ADR-Nummern sind monoton aufsteigend, vierstellig, ohne Lücken. Status-Werte: `Akzeptiert`, `Superseded`, `Verworfen`.
