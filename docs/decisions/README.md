# Architecture Decision Records (ADRs)

Kurze, datierte Entscheidungs-Dokumente zu Architektur-Punkten die später nicht ohne Begründung "verbessert" werden sollen. Format pro ADR: Kontext, Entscheidung, Begründung, Konsequenzen, Re-Open-Trigger.

## Index

| Nummer | Thema | Status |
|--------|-------|--------|
| [0001](0001-no-node-build.md) | Kein Node-Build im MVP | Akzeptiert |
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
| [0018](0018-server-detail-visual-alignment.md) | Server-Detail-Redesign (Layout, KPI-Sparklines, Trend-Berechnung, sortierbare Findings-Tabelle) | Akzeptiert |
| [0019](0019-dashboard-polling-not-sse.md) | Dashboard-Live-Updates via HTMX-Polling statt SSE (LLM-Stream bleibt SSE) | Akzeptiert |
| [0020](0020-dashboard-cross-server-findings.md) | Dashboard-Redesign: Cross-Server-Findings-Tabelle, KPI-Sparklines, Entfernung von /findings/search (Block M) | Akzeptiert |
| [0021](0021-agent-bootstrap-installer.md) | Agent-Bootstrap-Installer + Trivy-Output-Strip + Ursachen-Felder pro Finding (Block N) | Akzeptiert |
| [0022](0022-risk-based-prioritization.md) | Risk-basierte Priorisierung: Pre-Triage-Engine, Host-Snapshot, Vendor-Severity, UI-Redesign (Block O) | Akzeptiert |

## Wann eine neue ADR schreiben

- Wenn eine Architektur-Entscheidung getroffen wird, die nicht aus `ARCHITECTURE.md` direkt ableitbar ist.
- Wenn eine bestehende Entscheidung revidiert wird (alte ADR auf "Superseded by ADR-XXXX" setzen, neue ADR schreiben).
- Wenn ein Implementer in einem Block auf eine Wahl trifft die nachfolgende Blöcke betrifft.

ADR-Nummern sind monoton aufsteigend, vierstellig, ohne Lücken. Status-Werte: `Akzeptiert`, `Superseded`, `Verworfen`.
