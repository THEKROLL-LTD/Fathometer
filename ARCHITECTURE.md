# Fathometer — Architektur

Fathometer ist eine selbst-gehostete Web-App, die Trivy-Filesystem-Scans von Root-Servern einsammelt und in einem ruhigen Dashboard zur Triage anbietet.

Dieses Dokument beschreibt den **Ist-Zustand** der Architektur. Die Begründungen einzelner Entscheidungen liegen als ADRs unter [`docs/decisions/`](docs/decisions/); auf relevante ADRs wird punktuell verwiesen.

## 1. Vision

Der Fokus ist eng: schnell sehen, ob kritische Lücken auf den eigenen Servern offen sind und gepatcht werden müssen, mit lückenloser Historie für Audits und einer LLM-gestützten Bewertung, die CVE-Details vorkaut. Vorbild für UX und Self-Hosting-Spirit ist [uptime-kuma](https://github.com/louislam/uptime-kuma): minimal-friction Setup, ein Container-Compose, unaufgeregtes UI, keine externen Abhängigkeiten außer der Datenbank.

Fathometer kümmert sich darum, was **auf dem laufenden Server** installiert ist — OS-Pakete (apt/dnf/apk) genauso wie statisch installierte Binaries (k3s, tailscale, eigene Tools). Trivys Filesystem-Scan deckt beide Klassen ab. Container-Image-Scans, Kubernetes-Operator-Workflows und Code-Repo-Scans gehören in andere Werkzeuge und sind explizit nicht der Job dieser App.

**Zielgruppe:** Operator mit einer Handvoll bis ein paar Dutzend Root-Servern — kleinere Unternehmen, Hosting-Kunden, Vereine, gut betreute Hobby-Infrastruktur. Fathometer füllt die Lücke zwischen „cron-Plugin das Update-Mails schickt" (keine Übersicht, keine Priorisierung, keine Historie) und „vollwertiges SIEM/Vuln-Management" (zu komplex, zu teuer). Fathometer ist für jemanden außerhalb des Cybersec-/DevOps-Felds bedienbar, der ein- bis zweimal pro Woche reinschaut.

### Sicherheits-Stance: Push statt Pull

Eine zentrale Entscheidung prägt alles Weitere: **die App hat keinen Zugriff auf die Server, die sie überwacht.** Server pushen ihre Trivy-Scans aktiv (über Cron oder systemd-Timer); Fathometer initiiert keine Verbindung zur Flotte. Es gibt im System keine SSH-Keys, keine Server-Passwörter, keine Sudo-Credentials und keine Inbound-Verbindungen zu den überwachten Hosts.

Hintergrund ist eine reale Angriffsklasse: ein zentrales Management-Tool sammelt Credentials für viele Server an einem Ort und wird damit zum lohnenden Ziel — wer es kompromittiert, bekommt die ganze Flotte. Bei Fathometer sieht ein Angreifer, der den Server kompromittiert, nur die Schwachstellen-Liste — keinen direkten Zugang zu den Servern. Der einzige geheime Wert ist der **Master-Key**, mit dem Server sich registrieren und einen eigenen Server-Key aushandeln. Ein Leak erlaubt nur das Registrieren von Phantom-Servern (im Audit-Log sofort sichtbar) und schadet den echten Servern nicht.

## 2. Scope

**In Scope:** Server-Registrierung über Master-Key; Empfang von Trivy-JSON-Scans (nur Vuln-Scanner); Dedup von Findings über Re-Scans; Status-Workflow (`open` → `acknowledged`, automatisch `resolved` wenn weg); globale Severity-Schwelle; **EPSS- und CISA-KEV-Signale** plus numerischer CVSS-v3-Score als zentrale Triage-Hebel; „Fix verfügbar"-Filter; Bulk-Acknowledge über Server hinweg; Group-by-Package-View; Stale-Server- und Stale-Trivy-DB-Erkennung; Server-Tags mit Filter; globale CVE-Suche; URL-persistente Filter für teilbare Views; mehrere Notizen pro Finding (Discussion-Thread); Server-Retirement-Workflow; CSV-Export gefilterter Findings; asynchroner LLM-Risk-Reviewer pro Application-Group; vollständiger Audit-Log; Single-User-Auth und First-Boot-Wizard.

**Out of Scope:** Notifications jeder Art; Multi-User/RBAC/SSO; Mobile-responsive Layout (Desktop-first); Container-Image- und Code-Repo-Scans; Secret-/Misconfig-Findings im UI (Schema vorbereitet); Trend-Graphen über lange Zeiträume; PDF-Export; verteiltes Rate-Limit-Backend (Redis) / Multi-Instance; SBOM- und License-Findings. Das Datenmodell ist über das `finding_type`-Enum so vorbereitet, dass Secret/Misconfig später ohne Migration aktiviert werden können.

## 3. Tech-Stack

**Backend:** Python 3.13, Flask, SQLAlchemy 2.x + Alembic, Pydantic v2. Persistenz auf PostgreSQL 17 in eigenem Container. `structlog` (Logging mit Redaction-Filter), `flask-limiter` (Rate-Limits), `nh3` (HTML/Markdown-Sanitization), `argon2-cffi` (Passwort-/Master-Key-Hashing), `cryptography` Fernet (LLM-API-Key-Verschlüsselung).

**Frontend:** Jinja2 serverseitig gerendert, HTMX für partielle DOM-Updates und SSE, Alpine.js für clientseitige UI-Zustände (Modals, Dropdowns, Filter). Styling ist **100 % handgeschriebenes Plain CSS** auf Basis eines eigenen Design-Token-Sets (`frontend/src/css/tokens.css`) plus BEM-artiger Komponenten-Stylesheets — kein Tailwind, kein DaisyUI (ADR-0032). Der Build läuft über **esbuild** (JS: Alpine + HTMX vendored als `vendor.js`, App-Module als `app.js`) und **lightningcss** (CSS-Minify, Autoprefix, Hash-Naming) in einer Build-only Docker-Stage (`node:20-alpine`). Das Production-Image (`python:3.13-slim`) enthält keine Node-Runtime, nur die fertigen Static-Files unter `app/static/dist/`. Ein `manifest.json` mappt logische Namen auf gehashte Dateien; ein Jinja-Context-Processor stellt den `{{ asset_url(...) }}`-Helper bereit. Alle Assets (Fonts, JS, CSS) sind selbst-gehostet — keine externen CDN-Ressourcen (air-gap-tauglich).

**LLM:** Der Client spricht ausschließlich das OpenAI-kompatible Chat-Completions-Protokoll über das offizielle `openai`-Python-SDK mit konfigurierbarem `base_url`/`api_key`/`model`. Default-Provider ist DeepInfra mit `deepseek-ai/DeepSeek-V3`; nur OpenAI-Standard-Features werden genutzt, sodass ein Wechsel zu OpenAI, Together, Groq, lokalem Ollama/vLLM oder einem LiteLLM-Proxy reine Setting-Änderung ist.

**Deployment:** App-Image + Postgres-Image via docker-compose. UI- und Doc-Sprache: siehe `CLAUDE.md` (UI englisch, Docs deutsch).

## 4. Architektur-Überblick

```
   ┌─────────────────────────────────────┐
   │           User Browser              │
   │  (Jinja-rendered HTML + HTMX/Alpine)│
   └─────────────────┬───────────────────┘
                     │ HTTPS (Session-Auth)
                     ▼
   ┌─────────────────────────────────────┐    ┌──────────────┐
   │      Fathometer App-Container        │───▶│  LLM-Provider│
   │  Flask · SQLAlchemy · Jinja · SSE   │    │  (DeepInfra) │
   └─────────────────┬───────────────────┘    └──────────────┘
                     │ psycopg
                     ▼
   ┌─────────────────────────────────────┐
   │      Postgres-Container             │
   └─────────────────────────────────────┘
                     ▲
                     │ HTTP POST /api/scans
                     │ (Bearer: server-key)
   ┌─────────────────┴───────────────────┐
   │   N × Root-Server mit Trivy + Cron  │
   └─────────────────────────────────────┘
```

Der Web-Container ist zustandslos — alle persistenten Daten leben in Postgres. Sessions in signierten Cookies (Flask-Login mit `SECRET_KEY` aus den Settings). Der asynchrone Scan-Ingest und der LLM-Risk-Reviewer laufen in einem separaten Worker-Container (`fathometer-llm-worker`, derselbe Image-Build, kein eingehender Port — nur DB-Connect und LLM-Egress).

## 5. Datenmodell

Wenige Tabellen, klare Beziehungen. Roh-Trivy-JSON wird **nicht** persistiert — nach Pydantic-Parse und Findings-Extraktion wird der Body verworfen (Scans sind groß, der Forensik-Wert gering, weil `findings` plus Audit-Log alles Relevante behalten).

- **`users`** — genau ein Admin-User (Username, Argon2-Hash). Mehr-User später ohne Schemabruch.
- **`servers`** — registrierter Host: Name, gehashter API-Key, erwartetes Scan-Intervall (für Stale-Detection), Last-Scan-Zeitstempel, nullable `revoked_at` (statt Löschen, wegen Audit) und `retired_at`. Plus denormalisierte Host-Info aus dem letzten Scan (`os_family`, `os_version`, `os_pretty_name`, `kernel_version`, `architecture`, `agent_version`) und Trivy-DB-Frische (`trivy_db_version`, `trivy_db_updated_at`).
- **`scans`** — reine Empfangs-Buchhaltung pro eingegangenem Scan (Server, `received_at`, Versionen, historisierte Host-Felder). Kein Roh-JSON.
- **`tags` / `server_tags`** — freie Tag-Namen (`prod`, `web`, `region-eu`) als m:n-Brücke. Im Dashboard Filter-Chips, UND-Verknüpfung unterstützt.
- **`findings`** — operative Kern-Tabelle. Unique pro `(server_id, finding_type, identifier_key, package_name)`. `finding_type` Enum (`vulnerability`/`secret`/`misconfig`; im MVP nur `vulnerability`), `identifier_key` ist die natürliche ID je Typ (Vuln: CVE-ID). `finding_class` Enum (`os-pkgs`/`lang-pkgs`/`other`) aus dem Trivy-`Class`-Feld erlaubt Filter „nur OS-Pakete" vs. Library-Findings. Gemeinsame Felder: installierte/gefixte Version, Severity-Enum, Titel/Beschreibung, `first_seen_at`, `last_seen_at`, `status` (`open`/`acknowledged`/`resolved`) mit `acknowledged_at/by` und `resolved_at`. Vuln-Felder: `cvss_v3_score`, `cvss_v3_vector`, `epss_score`, `epss_percentile`, `is_kev`, `kev_added_at`, `cwe_ids`, `attack_vector`, `references`. `has_fix` ist eine generierte Spalte (`fixed_version IS NOT NULL AND != ''`). Ursachen-Felder (`package_purl`, `target_path`, `result_type`, `severity_source`, `vendor_ids`) zeigen Distro-Paket vs. eingebettete Library. Risk-Felder: `risk_band`, `risk_band_reason`, `risk_band_source`, `application_group_id`, `primary_url`. Ein Acknowledge-/Reopen-Kommentar ist **immer optional** — wenn vorhanden, landet er als erste Notiz im Thread, sonst belegt allein der Audit-Event den Vorgang.
- **`finding_notes`** — Discussion-Thread pro Finding (`author`, `text`, `created_at`, `deleted_at` für Soft-Delete; Notes werden nie hart gelöscht).
- **`application_groups` / `application_group_evaluations`** — Application-Group-Gruppierung. Die Group hält fleet-weite Identität + Match-Patterns (`label`, `path_prefixes`, `pkg_name_*`, `pkg_purl_pattern`, `group_kind`, `source`). Die server-abhängige Bewertung (`risk_band`, `reason`, `worst_finding_id`, `action_type` …) liegt in der Junction mit Composite-PK `(group_id, server_id)`, sodass mehrere Server denselben Group-Pattern ohne last-write-wins-Konflikt bewerten. Findings erben ihren Band aus der für ihren Server zuständigen Junction-Row.
- **`audit_events`** — jede zustandsverändernde Aktion mit `ts`, `actor` (Username/Server-Name/`system`), `action` (Enum, §11), `target_type/id`, optionalem `comment` und `metadata`-jsonb.
- **`settings`** — Single-Row: Severity-Schwelle, gehashter Master-Key, LLM-Provider-Block (`llm_provider_name`, `llm_base_url`, `llm_api_key_encrypted`, `llm_model`, `llm_daily_token_cap`), Stale-Threshold, Stale-DB-Threshold, `setup_completed_at`-Flag. Theme ist statisch dark (kein Toggle).

**Indizes** (zusätzlich zu PKs/FKs): `findings(server_id, status)`, `findings(cve_id)`, `findings(is_kev) WHERE is_kev`, `findings(epss_score DESC) WHERE status='open'`, `findings(package_name, server_id) WHERE status='open'`, `audit_events(ts DESC)`, plus die Junction-Indizes.

**Dedup & Resolve:** Beim Ingest läuft pro Finding ein Upsert auf `(server_id, finding_type, identifier_key, package_name)` — existiert es, werden die volatilen Felder (Versionen, Severity, CVSS, EPSS, KEV, …) aktualisiert, der Status bleibt; sonst wird es `open` mit `first_seen_at=now()` angelegt. In einer zweiten Phase werden alle `open`/`acknowledged`-Findings dieses Servers, die nicht mehr im aktuellen Scan-Set sind, auf `resolved` gesetzt. Das ist (neben Server-Retirement) die einzige Auto-Resolve-Stelle.

## 6. API

Zwei Aspekte: server-facing (Trivy-Push-Clients, Bearer-/Master-Key-Auth) und browser-facing (UI, größtenteils HTMX-HTML-Fragmente, Session-Auth).

### Server-facing

- **`POST /api/register`** — Body `{master_key, name, expected_scan_interval_h?}`. Validiert den Master-Key, legt einen Server an, generiert einen 256-bit Server-Key und gibt `{server_id, api_key}` zurück. Nur der Hash wird gespeichert.
- **`POST /api/scans`** — `Authorization: Bearer <server_key>`. Body ist ein **Wrapper-Envelope** (nicht das nackte Trivy-JSON):

```json
{
  "agent_version": "0.3.0",
  "host": { "os_family": "ubuntu", "os_version": "22.04", "os_pretty_name": "...",
            "kernel_version": "...", "architecture": "x86_64", "trivy_version": "0.70.0" },
  "host_state": { "snapshot_at": "...", "tools_available": [...], "gaps": [],
                  "listeners": [...], "processes": [...],
                  "kernel_modules": [...], "services": [...] },
  "scan": { /* trivy rootfs --format json, ab Agent v0.2.0 ohne Results[].Packages[] */ }
}
```

  `host` und `agent_version` sind Pflicht; `host.trivy_version` (ab Agent 0.2.0) und `host_state` (ab Agent 0.3.0) sind optional und forward-kompatibel als `… | None` typisiert. Die Trivy-DB-Frische extrahiert der Server selbst aus `scan.Metadata`. Der `host_state`-Block wird defensiv begrenzt (max 4096 `listeners`/`processes`, 1024 `kernel_modules`/`services`, 32 `tools_available`/`gaps`); schlägt seine Validierung fehl, wird nur er verworfen (Audit `host_state.parse_failed`), der Findings-Ingest läuft durch und die Pre-Triage markiert die Findings als `risk_band=unknown`.

  Der Endpunkt akzeptiert `Content-Encoding: gzip` (typisch 8–10× Kompression) und dekomprimiert streaming mit hartem Decompress-Bound (§8) vor dem Pydantic-Parse. **Verarbeitung ist asynchron:** der Edge-Handler antwortet binnen <1 s mit `202 Accepted` und `{job_id, status:"queued"}`; die volle Verarbeitung (Parse, Findings-Upsert, Host-State-Persist, Pre-Triage, Group-Matching, LLM-Job-Queueing) läuft im Worker. Idempotenz über einen partial-unique Index auf dem `payload_sha256` der queued/in_progress-Jobs. Der Agent ist Fire-and-Forget (kein Polling, kein Status-Endpoint); Fortschritt ist serverseitig über die Job-Zeile und das Dashboard sichtbar. Der gzipped Payload wird beim Status-Wechsel auf `done` atomar genullt; bei `failed` bleibt er 24 h für Debug, dann Retention-DELETE.
- **`POST /api/keys/rotate`** — Master-only, Body `{master_key, target:'master'|'server', server_id?}`. Rotiert den Key, gibt den neuen Klartext einmalig zurück.
- **`DELETE /api/servers/{id}`** — Master- oder Session-Auth. Setzt `revoked_at`, behält Findings und Scans.

### Browser-facing (HTMX)

Endpunkte liefern HTML-Fragmente (gepaart mit Jinja-Partials in `templates/_partials/`).

- **Findings:** `POST /findings/{id}/acknowledge`, `/reopen` (beide optional `comment`); `POST /findings/{id}/notes`, `DELETE …/notes/{note_id}` (Soft-Delete); `GET /findings/export.csv?<filter>` (Cross-Server-Modus ohne Row-Limit).
- **Bulk-Acknowledge** (`POST /findings/bulk-acknowledge`) in drei Flavors, genau einer befüllt: **A** explizite `finding_ids`; **B** `match` (CVE-ID/Paketname, optional Tag/Status) über die ganze Flotte; **C** `server_scope` (`{server_id, risk_band}`) — der Server resolved selbst alle offenen Findings dieses Bands (kein ID-Transport, kein Limit; `risk_band` Whitelist `escalate/act/mitigate/monitor/noise`, `pending`/`unknown` → 422). `dry_run:true` liefert eine Vorschau für das Modal. Audit-Event mit den Finding-IDs (auf 50 gecappt) und vollem `count` in `metadata`.
- **Tags/Server:** `POST /tags`, `DELETE /tags/{id}`; `POST /servers/{id}/tags`, `DELETE …/tags/{tag_id}`; `POST /servers/{id}/retire` (markiert offene Findings als `resolved`, Grund „server retired").
- **Dashboard/Filter:** `GET /` und `GET /servers/{id}` mit allen Filtern URL-kodiert → Bookmarks und Share-Links funktionieren ohne separate Persistenz.

**Live-Updates** laufen über **HTMX-Polling**, nicht SSE: Dashboard-Pane und Sidebar-Server-Liste pollen alle 10 s ihre eigene Partial-Route, gedrosselt auf sichtbare Tabs (`document.visibilityState`). Die App hat keinen SSE-Endpunkt (der frühere LLM-Chat-Token-Stream `GET /chat/{conversation_id}/stream` ist mit ADR-0050 entfernt).

## 7. UI und Routes

Single-Page-Layout im uptime-kuma-„Inbox"-Schema mit zwei Bereichen: **Sidebar links** (sticky, Quick-Stats + Suche + Filter-Chips + Server-Liste mit Heartbeat-Bars) und **Detail-Pane rechts** (scrollt eigenständig). Browser-Back/Forward über `pushState`/`popstate`; Direkt-URLs rendern die volle Seite mit vorausgewähltem Pane, HTMX-Requests (`HX-Request: true`) nur das Pane-Fragment. Obere Nav: Dashboard, Findings, plus Profile-Dropdown (Settings/Audit/Logout). Theme statisch dark.

**Heartbeat-Bars:** jeder Server trägt ~50 vertikale Segmente (eins pro Tag). Farbe = schlimmster Zustand der offenen Findings am Tagesende: grün (nichts über Schwelle), gelb (alle acknowledged), orange (offene High), rot (offene Critical oder KEV), grau (kein Scan). Hover-Tooltip mit Datum, Severity-Counts und KEV-Count.

**`/` (Dashboard)** ist eine reine Risk-Übersicht in drei Tiers: (1) zwei große Action-Required-Cards, die „muss ich was tun?" binär beantworten — `Action needed — N servers` (mind. ein `escalate`/`act`/`mitigate`/`pending`/`unknown`-Finding) und `Safe — N servers`, beide mit Sub-Countern und klickbar als Findings-Filter; (2) sieben Risk-Band-Pills (`Escalate · Act · Mitigate · Pending · Unknown · Monitor · Noise`) mit Findings-Count, `Escalate` pulsiert bei Count > 0; (3) ein Severity-Strip (`CRITICAL · HIGH · MEDIUM · LOW`) als Referenz. Die Cross-Server-Findings-Tabelle liegt auf der eigenen Seite `/findings`.

**`/findings`** ist die Cross-Server-Triage-Surface als Bucket-View nach `(Server, ApplicationGroup)`. Filter-Bar als `<form method="get">` (`q`, `tag`, `risk_band`, `application_group`, `action_required`, `severity`, `status`, `kev_only`, `stale_only`) mit explizitem Submit. Ohne Filter ein Empty-State. Pro Bucket eine Card mit Risk-Pill, Server-Link, Group-Label und Findings-Count; der Bucket-Body wird per HTMX lazy nachgeladen (20 Findings/Seite). Bucket-Sortierung: Risk-Band-Rank desc, dann Server-Name, dann Group-Label. Findings ohne Group landen im Pending-Bucket am Ende. Bulk-Acknowledge mischt Bucket- und Finding-Auswahl (server-side dedupliziert, idempotent).

**`/servers/{id}` (Server-Detail)** ist die Triage-Hauptansicht. Header mit Server-Info und einer Status-Pill-Reihe **nur für auffällige Zustände** (Action-Required, revoked/retired, stale, DB-veraltet, agent-/trivy-outdated) — aktive Server ohne Auffälligkeit zeigen keine Pille. Darunter eine collapsible **Host-Snapshot-Sektion** (Listener-Auszug + Service-Pills; bei fehlendem Snapshot ein Update-Hinweis) und die nach **Application-Group** gruppierte Findings-Ansicht: pro Group eine default-collapsed Card mit Group-Label, Count, Risk-Band-Pill, `risk_band_reason` (Mono) und Worst-Finding; die Drill-down-Tabelle wird beim Aufklappen via HTMX geladen. Solange die LLM-Bewertung läuft, zeigt die Card einen `evaluating`-Spinner; ungrouperte Findings laufen in eine „Pending grouping"-Sektion. Jede Risk-Band-Sektion außer `pending` trägt ein „Acknowledge all"-Hover-Control (Flavor C). Klick auf eine Finding-Zeile klappt einen Inline-Body auf (KI-Bewertung, CVE-Beschreibung, Primary-URL, References, Notizen-Thread). Default-Sort innerhalb einer Gruppe: KEV, EPSS desc, CVSS desc. Am Seitenende ein „Server retiren"-Gefahren-Bereich.

**Weitere Routes:** `/audit` (Event-Log chronologisch, Filter nach Actor/Action/Server/Tag/Datum, CSV-Export der Live-Filterung); `/settings` (horizontale Sticky-Tabs: Servers, Tags, Groups, LLM Provider, LLM Reviewer, Master-Key, About — Tab-Swap per HTMX, `href`-Fallback für No-JS); `/setup` (First-Boot-Wizard, nur erreichbar solange `setup_completed_at` NULL — Admin-Account, Master-Key einmalig anzeigen, Default-Schwellen); `/login`.

## 8. Auth und DoS-Schutz

**Auth.** UI-Auth ist Single-User, Session-basiert, Argon2id-Passwort, Flask-Login mit 7-Tage-Timeout. Server-Auth läuft zweischichtig: der **Master-Key** (256-bit, Argon2id-Hash in `settings`) nur für `register` und `keys/rotate`; **Server-Keys** (256-bit pro Server, SHA-256-Hash genügt wegen Hochentropie) für Scans, Klartext nur einmal ausgegeben. Der LLM-Provider-API-Key wird mit Fernet verschlüsselt (Key aus ENV `FM_ENCRYPTION_KEY` — fehlt sie, refused die App den Start). CSRF-Schutz auf allen state-changing Browser-Endpunkten (Flask-WTF, HTMX schickt das Token im Header).

**DoS.** Die unauthenticated Endpunkte sind die Hauptangriffsfläche. Reihenfolge in `/api/scans` ist strikt: **Body-Size-Limit** (`MAX_CONTENT_LENGTH`, Default 64 MB Wire, konfigurierbar via `FM_MAX_BODY_MB`) → **Auth-Check** (Bearer gegen `api_key_hash` mit `hmac.compare_digest`, bei Mismatch sofort 401) → **gzip-Decompress** mit Bound (`FM_MAX_DECOMPRESSED_MB`) gegen Zip-Bombs → Parse. Damit kann ein anonymer Angreifer keine großen JSON-Strukturen durch den Parser jagen. **Rate-Limiting** (`flask-limiter`, per IP und per Server-Key, alles via ENV überschreibbar): `register` 10/min, `login` 5/min, `scans` unauth 20/min, scans auth 60/h. **Per-Server-Soft-Cap** auf offene Ingest-Jobs (`FM_MAX_QUEUED_INGEST_JOBS`, Default 50 → 429), damit ein Server die Worker-Queue nicht flutet. **Sanity-Checks** nach Parse: max 50.000 Vulns/Scan, max 64 KB/String-Feld → 422. **Login-Brute-Force** ist durch Argon2id (100 ms+) plus Rate-Limit natürlich gedeckelt; Failed-Logins landen im Audit-Log. **LLM-Kostenschutz:** der einzige LLM-Verbraucher ist der Risk-Reviewer-Worker (§11); ein globaler Tages-Token-Cap (`llm_daily_token_cap`, Default 1 M, Reset 00:00 UTC) pausiert ihn bei Erschöpfung.

**Production-Empfehlung (README):** die App allein ist nicht gegen Layer-4 gehärtet — ein Reverse-Proxy (nginx/Caddy/Traefik) gehört davor für TLS, Connection-Limits, Slow-Loris-Schutz und idealerweise IP-Allowlist auf `/api/scans`.

## 9. Input-Validierung und Sanitization

Jedes Trivy-JSON wird als feindliche Eingabe behandelt — ein gültiger Server-Key sagt nur „berechtigt", nicht „sicher". Defense in Depth: Pydantic + Regex + ORM + Jinja-Autoescape sind redundant gegen Injection.

- **Strict Pydantic-Schema:** `Severity` ist `Literal[...]`, Längen-Limits pro Feld, unbekannte Top-Level-Felder werden ignoriert (Forward-Compat), unbekannte Felder in validierten Strukturen gestrippt. Validierungsfehler → 422 mit Feldnamen.
- **Regex-Whitelists pro Feldtyp:** CVE-IDs `^CVE-\d{4}-\d{4,}$`, Paketnamen `^[a-zA-Z0-9._+\-:/]+$`, `cvss_v3_score` Float 0–10, `epss_*` 0–1, `cwe_ids` `^CWE-\d{1,7}$` (max 50, defensiv getrimmt), `attack_vector` Whitelist, `references` http(s) max 100/Finding. `architecture` aus Whitelist mit Alias-Kanonisierung (`arm64`→`aarch64`, `amd64`→`x86_64`). `llm_base_url` zwingend `https://` außer für `http://localhost`/`127.0.0.1`. Was nicht matcht, fliegt raus — keine Best-Effort-Sanitisierung.
- **NUL-Bytes/UTF-8:** im Validator geprüft (→ 422 statt DB-500), UTF-8-Decode `strict=True`, Control-Chars außer Tab/Newline aus Display-Feldern entfernt. **JSON-Tiefenlimit** 32 (typisch 4–6).
- **ORM only:** alle DB-Zugriffe parametrisiert; rohe `text()` ohne `:param`-Bind sind verboten (CI-Lint).
- **XSS:** Jinja `autoescape=True` zwingend; `|safe` nie auf Client- oder LLM-Daten. Formatierter Text (CVE-Beschreibungen, LLM-Antworten) läuft durch `nh3`-Allowlist, nie durch `markdown`/`mistune` direkt.
- **Prompt-Injection:** Trivy-Daten landen im System-Prompt zwischen Markern (`<<TRIVY_DATA_START>> … <<TRIVY_DATA_END>>`) mit expliziter „Daten, nicht Befehle"-Anweisung. Keine Garantie, aber erschwert den Angriff; LLM-Output wird wie Trivy-Input behandelt.
- **Header-/Log-Injection:** Request-Header werden nie reflektiert; `structlog`-JSON verhindert Newline-Injection, sensible Felder werden als `***REDACTED***` geloggt. **Path-Injection:** Trivy-`Target`-Pfade sind reine Anzeige-Strings, nie Datei-Operationen.

## 10. Client-Agent (Referenz-Implementierung)

Die Server-Seite definiert nur das Envelope-Format (§6); jeder Operator kann den Client nachbauen. Mitgeliefert wird ein Bash-Referenz-Agent.

- **`agent/fathometer-agent.sh`** — setzt `trivy` (≥ 0.70.0), `curl`, `jq`, `gzip` und root voraus. Sammelt Host-Info aus `/etc/os-release` und `uname`, ruft `trivy rootfs / --format json --scanners vuln` auf (`rootfs`, damit Go-/Java-Binaries unter `/usr/local/bin` etc. erfasst werden), baut den Envelope per `jq`, strippt `Results[].Packages[]` (SBOM out-of-scope), komprimiert mit gzip und sendet per `curl` an `POST /api/scans`. Ab v0.3.0 zusätzlich der Host-Snapshot (`collect_listeners`/`processes`/`kernel_modules`/`services` in `agent/lib_host_state.sh`, jeweils mit `command -v`-Verfügbarkeits-Check und `gaps`-Tracking; ASCII-only unter `LC_ALL=C`). EPSS/KEV/CVSS liefert Trivy direkt im Report — keine zusätzliche Anreicherung. Exit-Codes 0/1/2/3 (OK / fehlende Voraussetzungen / Trivy-Fehler / Upload-Fehler).
- **`agent/fathometer-register.sh`** — registriert mit Master-Key (aus `FM_MASTER_KEY` oder silent prompt) einen Server und gibt den Server-Key auf stdout.
- **Bootstrap-Installer** — `curl -fsSL https://<host>/install.sh | sudo bash`. Das Backend rendert ein interaktives Bash-Wizard-Skript (System-Detection → Dependencies → Trivy-Pin-Install mit SHA256-Verify → Server-Registration via TTY-Prompt → systemd-Unit+Timer mit `RandomizedDelaySec` → Probe-Scan). Master-Key nie via Argv/ENV, nur im Prompt. Nicht-interaktiv via `FM_UNATTENDED=1`. Drei öffentliche Routes (kein Auth, in `PUBLIC_PATHS`): `GET /install.sh`, `GET /agent/files/<name>` (Whitelist), `GET /agent/version` (Mindest-/Empfohlen-Versionen aus Code-Konstanten).
- **Was der Agent NICHT macht:** keine Auto-Updates (Supply-Chain-Risiko), kein Datei-Versand außer dem Scan, kein Inbound-Listening, kein Schreiben außerhalb `/tmp` und `/opt/fathometer/`. Push-Only-Cron-Job, kein Daemon.

**Versions-Gating:** liegt eine gemeldete Version unter `MIN_AGENT_VERSION`/`MIN_TRIVY_VERSION` oder ist die Trivy-DB zu alt, zeigt das Backend eine `agent veraltet` / `trivy veraltet` / `trivy-db stale`-Pill (Server-Header + Sidebar-Marker) mit Update-Befehl im Info-Modal — bevor ein Scan fehlschlägt. Vergleich via Semver (`packaging.version`). Zu alte Envelopes werden mit klarem 400 abgelehnt.

**Privacy-Hinweis:** Prozess-`args` können sensible Tokens enthalten (z. B. `mysql -psecret`). MVP-Mitigation ist ein Operator-Hinweis (Cmdline-Args für sensible Dienste über Env-Files statt CLI-Flags); kein Schema-Redaction.

## 11. LLM-Integration

Ein Use-Case: der asynchrone **Risk-Reviewer pro Application-Group**. (Der frühere interaktive **Chat pro Server** — „Bewertung anfordern" → Conversation → SSE-Stream — ist mit **ADR-0050 (2026-06-07) ersatzlos entfernt**, inklusive der drei `llm_*`-Conversation-Tabellen.)

**Provider-Abstraktion.** `AsyncOpenAI` mit `base_url`/`api_key`/`model` aus den Settings. Bekannte kompatible Provider (alle per Setting umschaltbar): DeepInfra (Default), OpenAI, Together, Groq, Mistral, Ollama/vLLM (lokal), LiteLLM-Proxy. Nur Standard-Features (`messages`, `model`, `stream`, `temperature`, `max_tokens`) — kein Function-Calling, keine Assistants-API. Ein „Verbindung testen"-Knopf in den Settings schickt eine 1-Token-Anfrage und zeigt Status, Latenz, Modell und Token-Count.

**Risk-Reviewer (Worker, Two-Pass).** Die deterministische Pre-Triage (§12) liefert `pending`-Findings als Eingabe. **Pass 1 (Group-Detection)** erzeugt aus ungrouperten Findings wiederverwendbare `application_groups` mit Match-Patterns — Eingabe nur Finding-Identität, kein Server-Kontext. **Pass 2 (Risk-Evaluation)** bewertet pro Group mit Server-Kontext-Excerpt und schreibt `risk_band ∈ {escalate, act, mitigate, monitor, noise}` plus `worst_finding_id` und `reason` (max 256 chars); `pending`/`unknown` sind als LLM-Output verboten. Pass 2 setzt `risk_band_source='llm'`; die Pre-Triage überschreibt diese Findings beim Re-Ingest nicht.

Der Worker (`fathometer-llm-worker`) pollt eine Job-Tabelle mit `SELECT … FOR UPDATE SKIP LOCKED` (concurrency-safe), respektiert `depends_on` (Pass 2 wartet auf Pass 1) und fährt einen Stale-Reaper (in_progress > 10 min → requeue mit Backoff, ab Attempt 3 → failed). Liveness via Heartbeat-Spalte, kein HTTP-Endpunkt.

**Betriebs-Schalter.** `BLOCK_P_LLM_MODE ∈ {off, observation, live}` (Settings, Default `off`); Wechsel auf `live` braucht Master-Key-Bestätigung und zeigt eine **DSGVO-Notice** (Snapshot- und Findings-Kontext gehen an den externen Provider). Im `observation`-Mode schreibt der Worker `would_call`-Ergebnisse statt echter Calls, sodass der Operator Call-Frequenz und Token-Math vor `live` sieht. **Token-Budget** `LLM_TOKEN_BUDGET_DAILY` (Default 1 M, Reset 00:00 UTC) pausiert den Worker bei Erschöpfung. **Two-Level-Caching:** Pass-1-Cache ist die `application_groups`-Library (deterministischer Pattern-Match Python-side: längster `path_prefix` → `pkg_name_exact` → `_glob` → `purl_pattern`); Pass-2-Cache ist `llm_risk_cache` mit `cache_key = SHA256(group | findings_fp | cve_fp | server_context_fp)`, TTL 30 Tage, LRU bei > 100 K. Cross-Server-Reuse: identische Nodes teilen sich einen Cache-Eintrag (8 RKE2-Nodes → ein Call). **Output-Validierung** ist strikt: JSON-Schema, Label-Regex, Vollständigkeits-Check in Pass 1, Band-Whitelist und Pattern-Defensiv-Trim in Pass 2 (`path_prefixes` müssen mit `/` beginnen, ASCII, Bounds).

## 12. Triage-Signale und Risk-Engine

Das zentrale UX-Problem ist Priorisierung — eine mittlere Flotte produziert leicht mehrere hundert offene Findings. Gelöst durch Anzeige und Sortierung nach den Signalen, die Trivy selbst liefert:

- **KEV (CISA Known Exploited Vulnerabilities)** — das schärfste Signal: wird *gerade* ausgenutzt, nicht nur theoretisch. Deutliches rotes Badge, kommt zuerst in jeder Sortierung.
- **EPSS** — Wahrscheinlichkeit der Ausnutzung in 30 Tagen (0–1), farb-codiert (grün < 1 %, gelb 1–10 %, orange 10–50 %, rot > 50 %).
- **CVSS-v3-Base-Score** numerisch (z. B. `8.7`) zur Differenzierung innerhalb einer Severity-Stufe, aufklappbar zum Vector.
- **Attack-Vector** (N/A/L/P) — eine Local-Lücke ohne lokale Logins ist weniger dringlich als ein Network-Vector auf einem exponierten Dienst.
- **Fix-Verfügbarkeit** als binärer Filter („was kann ich heute updaten").
- **CWE-Kategorie** kompakt, damit erfahrene User Klassen wegfiltern können.

**Risk-Band** ist der Primary-Sort-Key (deterministisches Mapping `RISK_BAND_SORT_RANK` in `app/services/risk_engine.py`): `escalate=70, act=60, mitigate=50, pending=40, unknown=30, monitor=20, noise=10, NULL=0`. Sortier-Kette: **`risk_band` DESC → KEV DESC → EPSS DESC → CVSS-Severity-Rank DESC → `identifier_key` ASC** (letzter Key für deterministische Reihenfolge). UI filtert auf `?risk_band=<band>` bzw. `?action_required=yes|no` (aggregiert `escalate`/`act`/`mitigate`/`pending`/`unknown`).

**Pre-Triage** (deterministisch, kein LLM, kein Host-Match) läuft beim Ingest direkt nach dem Snapshot-Persist. Eingaben: Max-Severity über alle Provider, EPSS, KEV-Flag, `snapshot_available`. Erste Treffer-Regel gewinnt, defensiv-konservativ:

1. kein Snapshot → **`unknown`** („update agent to ≥ 0.3.0")
2. KEV-gelistet → **`pending`**
3. Max-Severity ≥ HIGH → **`pending`**
4. EPSS ≥ 0.1 → **`pending`**
5. Max-Severity == MEDIUM → **`monitor`**
6. sonst (≤ LOW, EPSS < 0.1, nicht KEV) → **`noise`**

`pending` ist die Übergabe an den LLM-Reviewer; `escalate`/`act`/`mitigate` setzt ausschließlich der LLM. Findings mit `risk_band_source='llm'` überspringt die Pre-Triage. Die Schwellen leben im Code (ohne Migration nachjustierbar).

## 13. Audit-Log

Jede zustandsverändernde Aktion landet in `audit_events` mit Actor (Admin-Username / Server-Name / `system`). Geloggte Actions u. a.: `finding.acknowledged|unack|bulk_acknowledged|resolved|note_added|note_deleted`, `tag.created|deleted`, `server.registered|revoked|retired|tagged|untagged`, `key.rotated.master|server`, `llm.provider_changed|mode_changed|budget_exhausted`, `risk.llm_group_skipped`, `settings.updated`, `auth.login|logout|failed`, `ratelimit.tripped`, `scan.queued|ingested|ingest_failed`. Bulk-Operationen halten die betroffenen IDs in `metadata`. Im Async-Pfad emittiert ein Scan `scan.queued` (Edge) → Worker-Events → `scan.ingested` oder `scan.ingest_failed`; idempotente Re-Inserts emittieren kein zweites `queued`. Die `/audit`-View ist paginiert (50/Seite), Filter nach Datum/Actor/Action/Server, CSV-Export der Live-Filterung.

## 14. Stale-Detection

Beide live im SQL berechnet, nichts persistiert. **Stale Server:** `now() - last_scan_at > expected_scan_interval_h` (Default 26 h) → gelbe Pill. **Stale Trivy-DB:** `now() - trivy_db_updated_at > stale_db_threshold_h` (Default 30 h) → orange Pill mit Hinweis, dass Findings unvollständig sein könnten. Beide triggern nur das visuelle Signal (keine Notifications im MVP) und sind über `scan.ingested`-Events indirekt im Audit nachvollziehbar.
