# Changelog

Alle nennenswerten Aenderungen an diesem Projekt werden hier dokumentiert.
Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/),
und das Projekt folgt [Semantic Versioning](https://semver.org/).

## [v0.3.0] — 2026-05-15

UI-Refinement-Release aus ADR-0016. Funktional gegenueber v0.2.0
unveraendert — Layout wird kompakter und an uptime-kuma-Konvention
angeglichen. Plus zwei neue Settings-Sub-Views: Master-Key-Rotation
(schliesst §8-Spec-Luecke) und About.

### Added — Block-I-Refinement (ADR-0016)

- **Header kompakt** in `app/templates/layout/_header.html`: Logo +
  Dashboard-Button + Suche-Button + Theme-Toggle (sichtbares Sun/Moon-
  Icon) + Profile-Avatar mit Initial. Drei Top-Level-Items statt
  vorher fuenf. Logo-Klick und Dashboard-Button identischer Effekt
  (Dashboard-Default).
- **Profile-Dropdown** in `app/templates/layout/_profile_dropdown.html`:
  flache Eintraege Settings → Audit → Logout. Kein Sub-Menue.
  `@click.outside`-Close, `@keydown.escape.window`-Close. Logout als
  CSRF-geschuetztes POST-Form.
- **Settings-View mit Sekundaer-Navigation** im Detail-Pane:
  linke Nav-Liste (`app/templates/settings/_nav.html`) mit Tags,
  LLM-Provider, Server-Verwaltung, Master-Key (Badge "neu"), About.
  Aktiver Eintrag visuell hervorgehoben. Klick swappt nur den
  Content-Bereich rechts via HTMX (`hx-target="#settings-content"`,
  `hx-swap="innerHTML"`, `hx-push-url="true"`).
- **3-Modi-Render-Helper** `app/views/_settings_shell.py`:
  Vollseite (Direkt-URL/Bookmark), Shell-Fragment (HX mit
  `hx-target="#detail-pane"`), Content-only (HX mit
  `hx-target="settings-content"`). Saubere Trennung pro `HX-Target`-
  Header.
- **`/settings`-Alias** → 302 auf `/settings/servers/` (User-
  Klarstellung — Server-Verwaltung ist der haeufiger genutzte Default
  als Tags).
- **Master-Key-Rotation** (`/settings/master-key`):
  - `GET`: rendert Hinweis-Box mit Last-Set-Datum.
  - `POST /rotate` mit Confirm-Modal davor: generiert neuen Master-
    Key via `secrets.token_urlsafe(32)`, Hash-Update in `settings.
    master_key_hash`, einmalige Klartext-Anzeige mit Copy-Button.
  - Audit-Event `master_key.rotated` mit nur `metadata.hash_prefix`
    (8 Hex-Zeichen) — NIEMALS Klartext oder voller Hash.
  - Server-Keys bleiben gueltig (Hash-Trennung).
  - CSRF zwingend.
- **About-View** (`/settings/about`): read-only Versions-Info:
  `app_version` (via `importlib.metadata`), `build_revision`
  (Env-Var `SECSCAN_BUILD_REVISION` mit Fallback `dev`),
  `alembic_revision`, Python-/Flask-/SQLAlchemy-Versionen,
  Trivy-DB-Stale-Server-Count, Healthcheck-Link. Kein
  Secret-Leak (`SECSCAN_ENCRYPTION_KEY`, `master_key_hash`,
  `llm_api_key_encrypted` explizit nicht im Context).
- **Dashboard-Default-Pane** uebernimmt die ehemaligen Sidebar-
  Inhalte: Quick-Stats horizontal (Total open / KEV / Critical /
  High / Stale-Server), Filter-Bar (Tag/Severity/KEV/Stale),
  Platzhalter-Bereich mit expliziter "bewusst leer"-Notiz.
- **Sidebar reduziert** auf reine Server-Liste mit Sticky-Search
  (Placeholder umbenannt auf "Server filtern…") + Heartbeat-Bars.
  Quick-Stats / Filter-Chips / Settings-Footer entfernt.
- **`MasterKeyRotateForm`** in `app/forms.py`: CSRF-only WTForm.
- **`Dockerfile`** mit `ARG SECSCAN_BUILD_REVISION=dev` → `ENV` in
  Runtime-Stage, fuer GitHub-Actions-Release-Workflow per
  `--build-arg ${{ github.sha }}`.

### Fixed

- **Test-Suite-Haenger** (`tests/conftest.py:_truncate_all`):
  `TRUNCATE ... CASCADE` haengte stillschweigend wenn ein
  vorheriger Test eine Connection mit offener Transaction
  hinterlassen hat. Fix: `lock_timeout = '5s'` + `statement_
  timeout = '10s'` + `pg_terminate_backend(pid)`-Cleanup vor dem
  TRUNCATE. Volle Suite laeuft jetzt deterministisch in ~30s
  statt potentiell Endlos-Hang.
- **`pytest-timeout`-Dependency**: ergaenzt, sodass kuenftige
  Haenger nicht den ganzen Lauf blockieren. Alle Test-Aufrufe
  jetzt mit `--timeout=15 --timeout-method=thread`.

### Tests

- 48 neue Tests in `tests/views/`:
  - `test_master_key_rotation.py` (9): Auth, CSRF, Hash-Aenderung,
    Audit-Event mit hash_prefix, Klartext-Schutz, Server-Key-
    Invarianz.
  - `test_about_view.py` (10): alle Versions-Strings, Secret-
    Leak-Check.
  - `test_header_navigation.py` (8): Active-Marker, Logo-Href,
    Dropdown-Reihenfolge, Logout-CSRF, Theme-Toggle.
  - `test_settings_dropdown_swap.py` (20): 3 Render-Modi pro
    5 Sub-Routes.
  - `test_settings_alias_redirect.py` (4): `/settings` →
    `/settings/servers/`.
- 10 bestehende `test_dashboard.py`-Tests umgeschrieben auf neuen
  Detail-Pane-Inhalt (Quick-Stats statt Card-Grid).
- `test_settings_sidebar_swap.py` ersetzt durch
  `test_settings_dropdown_swap.py`.
- **Total: 722 passed**, Coverage 92.21 %.

### Security

- security-auditor-Verdict: **ACCEPTABLE WITH NOTES**.
- CSRF auf `POST /settings/master-key/rotate` zwingend, Test
  verifiziert 400 ohne Token.
- Master-Key-Klartext: nur einmal im UI gerendert (Jinja-
  Autoescape), nie in Logs (structlog redact pattern
  `key|password|token|hash|authorization`), nie in Audit-
  Metadata (nur hash_prefix[:8]).
- About-View Secret-Leak-Tests gruen.
- HX-Target-Header: kein Open-Redirect-/XSS-Vektor (reiner
  String-Vergleich, kein URL-Build).
- 1 low CONCERN: kein dedizierter XSS-Adversarial-Test fuer
  Master-Key-Klartext-Render. Kein realer Angriffsvektor weil
  `secrets.token_urlsafe(32)` zeichen-eingeschraenkt ist
  ([A-Za-z0-9_-]). Defense-in-Depth-Test ist optional
  fuer einen Folge-Block.

### Architektur-Entscheidungen

- **ADR-0016** (Header-Navigation kompakt, Settings und Audit ins
  Profile-Dropdown): Block-I-Plan und ARCHITECTURE §7a werden nicht
  editiert, Deltas im Addendum `docs/blocks/I-addendum-header-
  layout.md` ausgewiesen.
- Default-Settings-Sub-Tab: **Server-Verwaltung** (User-Klarstellung
  gegenueber Addendum-Default Tags) — Server-Verwaltung ist
  haeufiger genutzter Ops-View.

### Screenshots

- `docs/blocks/I-refinement-evidence/dashboard.png` — Header + Sidebar + Quick-Stats + Platzhalter.
- `docs/blocks/I-refinement-evidence/profile-dropdown.png` — flaches Dropdown.
- `docs/blocks/I-refinement-evidence/settings-servers.png` — Settings mit Sekundaer-Nav.
- `docs/blocks/I-refinement-evidence/settings-master-key.png` — Rotations-View.
- `docs/blocks/I-refinement-evidence/settings-about.png` — Versions-Info.

---

## [v0.2.0] — 2026-05-15

UI-Modernisierung als Folge-Release nach v0.1.0. Funktional unveraendert
— gleiche Routen, Endpoints, Daten-Vertraege. Layout wechselt von
Multi-Page-Card-Grid zu Single-Page-Sidebar + Detail-Pane im
uptime-kuma-Spirit.

### Added — Block I: UI-Modernisierung

- **Single-Page-Layout** in neuer `base_app.html`. Sidebar links
  (320/384px) mit Quick-Stats, Sticky-Search (`/`-Shortcut), Tag-Filter,
  Server-Liste mit Heartbeat-Bars, Settings-Akkordeon. Detail-Pane
  rechts mit HTMX-Swap und `hx-push-url`.
- **Heartbeat-Bars** pro Server-Eintrag in der Sidebar. 50 Tage als
  vertikale Pillen, Severity-Farb-Mapping (critical=error,
  high=warning, medium=accent, low=info, unknown=ghost, clean=success/40,
  no-scan=base-300). KEV-Tage zusaetzlich mit `ring-1 ring-error`.
  Tooltip mit 300ms-Delay zeigt Datum, max Severity, KEV-Count,
  Scan-Status. Aggregation als Python-Service (Variante B),
  Performance unter 200 ms fuer 50 Server x 50 Tage.
- **Quick-Stats** als Mini-Block oben in der Sidebar: 5 Counter
  (open / KEV / critical / high / stale-server) mit Filter-Klicks.
- **Sticky-Search-Header** mit `/`-Shortcut. Live-Filter der
  Server-Liste clientseitig (Substring auf Name + Tag-Namen).
  `Enter` oeffnet globale Suche im Detail-Pane, `Esc` leert.
- **Settings als Sidebar-Tab**: kompakte Akkordeon-Liste am unteren
  Sidebar-Rand mit "Server", "Tags", "LLM-Provider", "API-Keys &
  Master-Key", "About".
- **HTMX-Routing-Refactor**: alle authentifizierten View-Routen
  (`/`, `/servers/<id>`, `/findings/search`, `/audit/`, `/settings/*`)
  liefern bei `HX-Request: true` nur das Detail-Pane-Fragment.
  Direkt-URL und Bookmarks funktionieren weiter.
- **Sidebar-Context-Processor**: Flask-`@app.context_processor`
  injiziert Sidebar-Variablen automatisch fuer alle authentifizierten
  Vollseiten-Renders, skipt bei HX-Request und unauthentifizierten
  Routen.
- **Empty-States** mit klaren CTAs unter `app/templates/_empty/`
  (no_servers, no_findings, no_audit, no_search_results).
- **Quick-Copy-Macro-Regression-Fix** aus Block F: `tojson | forceescape`
  verhindert dass JS-Code im Attribut den DOM-Body verschmutzt.
- **Subtle Fade-In bei SSE-Updates**: `htmx:afterSettle`-Listener und
  `secscan:scan-received`-Custom-Event fuegen 1 s `bg-info/20`-Akzent
  an Swap-Targets bzw. Sidebar-Rows.
- **Monospace-Cleanup**: `font-mono`-Klasse auf CVE-IDs, Paketen,
  Versionen, Hostnames, Kerneln, Pfaden, Hash-IDs ueber 6 zentrale
  Templates.

### Tests

- 45 neue Block-I-Tests (Heartbeat-Aggregation, Quick-Stats,
  Sidebar-Layout, Keyboard-Shortcut, Settings-Sidebar-Swap,
  XSS-in-Heartbeat-Tooltip).
- **674 Tests gruen** (629 + 45), Coverage **92.54 %**, Adversarial-
  Suite weiterhin 131/131.
- Performance-Sanity-Test: 50 Server x 50 Tage Heartbeat-Aggregation
  unter 200 ms.

### Security

- security-auditor-Verdict: **CLEAN**.
- XSS-Tests in Server-Namen, Heartbeat-Tooltip-Daten-Attributen,
  Tag-Filter-Pfaden — alle escapeed via Jinja-Autoescape und JS
  `textContent`.
- Quick-Stats SQL ueber SQLAlchemy-ORM mit Bind-Parametern.
- Open-Redirect via `hx-push-url`/`pushState` ausgeschlossen
  (alle HTMX-URLs aus `url_for()`, Search-Pfad mit
  `encodeURIComponent`-Schutz).
- CSRF-Verhalten unveraendert (alle Block-I-Routen sind GET).

### Architektur-Entscheidungen

- **Heartbeat-Aggregation Variante B**: Python-Service mit on-the-fly-
  Aggregation, keine Postgres-Materialized-View. Re-Open-Trigger:
  wenn Sidebar-Render > 200 ms wird.
- **`base.html` vs `base_app.html` Clean-Split**: `base.html` bleibt
  fuer Pre-Auth-Routen (Login, Setup), `base_app.html` ist die App-
  Shell fuer authentifizierte Routen. HX-Fragmente extenden
  `_partial_shell.html`.
- ADR-0012 dokumentiert warum Block I separater Block ist und
  was bewusst draussen bleibt (Dark-Mode-Default, Mobile, Cmd-K,
  Vim-Shortcuts, Optimistic-Updates).

### Was bewusst draussen bleibt (siehe ADR-0012)

- Mobile-Layout (ADR-0009 weiterhin in Kraft).
- Dark-Mode als Default.
- Cmd-K Command-Palette.
- Vim-Style-Keyboard-Shortcuts.
- Optimistic-Updates.
- Loading-Skeletons (HTMX-Default reicht).

### Screenshots

- `docs/blocks/I-evidence/dashboard.png` — Sidebar mit 4 Servern,
  Heartbeat-Bars, Quick-Stats; Detail-Pane mit Dashboard.
- `docs/blocks/I-evidence/server-detail.png` — Sidebar mit aktiver
  Server-Row, Detail-Pane mit Findings-Tabelle.

---

## [v0.1.0] — 2026-05-15

Erstes MVP-Release. Selbst-gehostete Web-App fuer Triage von
Trivy-Filesystem-Scans auf Root-Servern. Spirit: uptime-kuma fuer CVEs.

### Added — Block A: Skelett und Basis

- Flask-App-Factory mit Cross-Cutting-Defaults (Body-Limit 10 MB,
  `flask-limiter` In-Memory, `structlog` JSON-Logging mit Redaction-Filter,
  Jinja-Autoescape, Theme-Cookie).
- `pydantic-settings` Config mit Pflicht-`SECSCAN_ENCRYPTION_KEY` und
  `SECSCAN_SECRET_KEY` aus der Umgebung.
- `/healthz` (DB-Ping) und `/readyz` (unabhaengig vom DB-Zustand).
- Multi-stage `Dockerfile`, `docker-compose.yml` mit Postgres 17 in
  eigenem Container.
- Alembic-Setup mit leerer Baseline-Migration.

### Added — Block B: Datenmodell, Setup-Wizard und Auth

- 12-Tabellen-Datenmodell: `servers`, `scans`, `findings`, `finding_notes`,
  `tags`, `server_tags`, `llm_conversations`, `llm_messages`,
  `llm_conversation_findings`, `users`, `audit_events`, `settings`.
- Setup-Wizard `/setup/{step1,step2,step3}` mit einmaliger
  Master-Key-Anzeige in Step 2.
- Argon2id-Passwort-Hashing fuer Admin-Accounts und Master-Key,
  SHA-256 + `hmac.compare_digest` fuer hochentropische Server-Keys.
- Tag-CRUD-View `/settings/tags` mit Color-Picker.
- Audit-Helper `log_event()` mit strukturiertem Metadata-JSONB.

### Added — Block C: Ingest, Server-Verwaltung und Agent-E2E

- Pydantic-Envelope-Schema mit Regex-Whitelists pro Feldtyp, NUL-Byte-
  Reject und Tiefenlimit (32) gegen JSON-Bomben.
- Gzip-Streaming-Decompress mit 100-MB-Limit gegen Zip-Bombs.
- `POST /api/register` mit einmaliger Server-Key-Vergabe.
- `POST /api/scans` mit strikter Auth-vor-Body-Parse-Reihenfolge
  (Bearer-Vergleich via `hmac.compare_digest` vor Body-Read),
  Dedup-Upsert via `INSERT ... ON CONFLICT`, automatischer Resolve-Phase
  fuer im neuen Scan fehlende Findings.
- `POST /api/keys/rotate` fuer Master- und Server-Key.
- Server-Verwaltungs-View `/settings/servers` mit Revoke und Retire.
- ADR-0011: `package_name@target`-Disambiguation fuer lang-pkgs (zwei
  Findings mit gleicher CVE in unterschiedlichen Targets sind separate
  Findings).
- Referenz-Agent `agent/secscan-agent.sh` und `agent/secscan-register.sh`.

### Added — Block D: Dashboard mit Tags und Stale-Detection

- Dashboard `/` mit Server-Karten, Severity-Badges, KEV-Counter, EPSS-
  Top-Hits.
- Tag-Filter mit OR-/AND-Modus, URL-persistent fuer teilbare Views.
- "Aufmerksamkeit noetig"-Sektion fuer stale Server, KEV-Findings und
  Trivy-DB-veraltet.
- Stale-Detection-Service mit `is_stale` (kein Scan im konfigurierten
  Fenster) und `is_db_stale` (Trivy-DB-Update zu alt).
- Server-Detail-Header mit HTMX-Tag-Inline-Editor.
- Theme-Toggle (Light/Dark) in `static/js/theme.js` extrahiert.

### Added — Block E: Triage in der Server-Detail-View

- Drei View-Modi: Liste, Group-by-Package und Diff-seit-letztem-Scan.
- Triage-Sortierung KEV -> EPSS -> CVSS -> Severity -> `first_seen_at`.
- Finding-Detail-Modal mit Notes-Thread (mehrere Notizen pro Finding).
- Acknowledge- und Re-Open-Flow mit OPTIONALEM Kommentar (ADR-0006 —
  keine Pflicht-Kommentare).
- Markdown-Subset-Rendering fuer Notizen durch `nh3`-Allowlist
  (`p`, `strong`, `em`, `code`, `pre`, `a`, `ul`/`ol`/`li`, `br`).
- Quick-Copy-Icon-Macro mit Toast-Bestaetigung.
- Sicherheits-Fix: `delete_note` mit Owner-Check und 403 fuer
  System-Notes.

### Added — Block F: Bulk-Operationen und globale Suche

- Bulk-Acknowledge mit `dry_run`-Phase (Default true) und zwei Flavors:
  `finding_ids` (explizite Liste) ODER `match` (Kriterien-basiert).
- Globale Suche `/findings/search` mit CVE-, Paket- und Server-Modus.
  Bei CVE-Suche zusaetzlich Aggregations-Header (Anzahl betroffener
  Server, gesamt offene Instanzen).
- Audit-View `/audit` mit Datum-/Actor-/Action-/Server-/Tag-Filtern und
  CSV-Export.
- CSV-Export aus Findings-Liste und Audit-View.
- CSV-Injection-Mitigation per Apostroph-Prefix auf `=`, `+`, `-`, `@`,
  `\t`, `\r` (OWASP-Recommendation).

### Added — Block G: LLM-Integration mit Streaming-Chat

- `AsyncOpenAI`-Wrapper mit Fernet-verschluesseltem API-Key in der DB.
- LLM-Provider-Settings mit Preset-Dropdown (DeepInfra, OpenAI, Ollama,
  custom) und Test-Verbindungs-Button.
- Prompt-Injection-Marker `<<TRIVY_DATA_START>>` / `<<TRIVY_DATA_END>>`
  im System-Prompt, plus explizite Anti-Injection-Instruktion.
- LLM-Chat-View `/chat/<conversation_id>` mit SSE-Token-Streaming.
- Tages-Token-Cap mit 80%-Warn-Banner und 100%-Hard-Block (Reset um
  00:00 UTC).
- Provider-Wechsel archiviert aktive Conversations automatisch.
- `nh3`-Sanitization auf LLM-Output (gleiche Allowlist wie Notizen).
- `llm_base_url`-Whitelist: HTTPS Pflicht ausser `http://localhost`
  und `http://127.0.0.1`.
- ADR-0013: Fernet-KDF (`sha256[:32]`) beibehalten, dafuer
  Weak-Key-Warning beim App-Start und Pflicht-Doku zur Random-Generierung.
- ADR-0014: Token-Cap als Best-Effort dokumentiert (parallele Streams
  koennen den Cap geringfuegig ueberschreiten — Cost-Cap, kein
  Security-Cap).

### Added — Block H: Live-Updates und Production-Hardening

- In-process Event-Bus mit `GET /events` SSE-Endpoint, Heartbeat alle
  30 s.
- Dashboard-Live-Update bei neuen Scans (Card-Highlight-Animation
  ohne Page-Reload).
- Client-seitiger Stale-Re-Render-Timer alle 60 s, damit Stale-Badges
  live aufpoppen ohne neuen Scan.
- `validate_base_url` mit Port-Range-Check (1..65535) — schliesst
  ADR-0014-Action-Item.
- `@limiter.limit("60/hour")` auf SSE-Stream und LLM-Test-Connection.
- `Authorization`-Header im `structlog`-Redaction-Pattern ergaenzt.
- E2E-Smoke-Skript `scripts/e2e_smoke.sh` (Setup-Wizard via curl,
  Agent-Register, Ingest gegen Real-Fixture, Health-/Auth-/Bomb-
  Verifikation).
- Reverse-Proxy-Snippets fuer nginx und Caddy in der README.
- IP-Allowlist-Empfehlung fuer `/api/scans` mit Beispiel-CIDRs.
- Deploy-Checkliste in der README.

### Sicherheits-Eigenschaften (final)

- Auth-vor-Body-Parse auf `/api/scans` — 401 in 22 ms gegen ungueltigen
  Bearer (gemessen in Block-C-Audit).
- Gzip-Bomb-Bound: 413 bei mehr als 100 MB Decompress, Streaming-
  Abbruch.
- Prompt-Injection-Marker und explizite Anti-Injection-Instruktion im
  LLM-System-Prompt.
- LLM-Output durchlaeuft `nh3`-Allowlist (gleiche wie User-Markdown).
- LLM-API-Key Fernet-verschluesselt mit deterministischer Ableitung —
  Pflicht-Doku zur Random-Generierung des `SECSCAN_ENCRYPTION_KEY`.
- `structlog`-Redaction auf `password`, `key`, `token`, `hash`,
  `authorization` in allen Keys und Stack-Traces.
- CSRF-Schutz auf allen state-changing POSTs via Flask-WTF.
- ADR-0006: keine Pflicht-Kommentare auf Comment-Feldern — verhindert
  Bypass-Pseudo-Kommentare und passt zur leisen UX.

### Tests

- 600+ Tests gruen ueber alle Bloecke verteilt (Block A: 25, B: 71,
  C: 71, D: 99, E: 67, F: 71, G: 149, H: noch im Test-Writer).
- Coverage > 85 % auf Block-spezifischen Modulen, `--cov-fail-under=85`
  als CI-Gate.
- Adversarial-Suite: NUL-Bytes, Skript-Tags, gzip-Bomb, Auth-vor-Body-
  Reihenfolge, CSV-Injection, XSS-in-CVE-Title, Prompt-Injection,
  Owner-Bypass auf Notes.

### Bekannte Limitationen

- **Single-User-MVP**: kein RBAC, kein OIDC, ein Admin-Account pro
  Instanz (siehe ARCHITECTURE.md §17 — Multi-User ist explizit out
  of scope).
- **Kein Mobile-Layout**: Desktop-first, Tailwind-Defaults skalieren
  Notfall-tauglich aber nicht optimiert (ADR-0009).
- **Token-Cap ist Best-Effort**: parallele LLM-Streams koennen den Cap
  marginal ueberschreiten (ADR-0014).
- **Fernet-KDF ohne Salt**: `SECSCAN_ENCRYPTION_KEY` muss
  hochentropisch sein (`secrets.token_urlsafe(48)` oder
  `openssl rand -base64 48`); siehe ADR-0013 und README-Quick-Start.
- **In-process Event-Bus**: kein verteilter PubSub, daher Single-
  Instance-Deploy. Mehrere Gunicorn-Worker subscriben unabhaengig —
  Browser-Tabs sehen Updates nur fuer ihren angeschlossenen Worker.
- **Keine Notifications**: Email, Webhook und Discord sind explizit
  v2-Feature, damit der secscan-Server keine zusaetzlichen Secrets
  haelt (siehe ARCHITECTURE.md §1, "Sicherheits-Stance").
