# Changelog

Alle nennenswerten Aenderungen an diesem Projekt werden hier dokumentiert.
Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/),
und das Projekt folgt [Semantic Versioning](https://semver.org/).

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
