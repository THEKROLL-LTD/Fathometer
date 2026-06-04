# secscan

Selbst-gehostete Web-App, die Trivy-Filesystem-Scans von Root-Servern einsammelt und in einem ruhigen Dashboard zur Triage anbietet. Spirit: uptime-kuma für CVEs auf laufenden Servern. Vision und Detail-Spec in [`ARCHITECTURE.md`](ARCHITECTURE.md).

**Status: Spec-Phase abgeschlossen, Implementierung steht aus.**

## Worum es geht

secscan beantwortet genau eine Frage pro Finding: **Muss ich etwas tun — und wie dringend?** Kein Zahlenfriedhof aus CVSS, EPSS und KEV-Flags, keine Wand aus „kritisch"-Bannern. Ein einzelner Root-Server wirft schnell hunderte CVEs aus, die meisten als High/Critical eingestuft — und die wenigsten davon sind in *deinem* Setup real angreifbar. Das manuell durchzuarbeiten ist nicht mehr leistbar.

Der Kern ist deshalb ein LLM, das jedes Finding auf **tatsächliche Angreifbarkeit im Kontext** prüft, nicht auf rohe Scores:

1. **Netzwerk-Position** — kommt ein Angreifer überhaupt an den Dienst?
2. **Code-Pfad** — wird der verwundbare Code in diesem Deployment überhaupt ausgeführt?
3. **Vorbedingungen** — braucht der Exploit Auth, Config oder Input, den es hier nicht gibt?

CVSS, EPSS und KEV fließen als **Gewichte** ein, sind aber kein Urteil. Ein CVSS-10-CVE in einem nicht erreichbaren Code-Pfad landet bei secscan auf „beobachten" — und die wenigen Findings, die wirklich zählen, stehen oben. Übrig bleibt eine kurze, ehrliche To-do-Liste statt eines Alarm-Dauerfeuers.

secscan ist ein pragmatisches Alltags-Tool für Leute, die ihre eigenen Root-Server betreiben. Es ist **nicht fehlerfrei** und ersetzt kein Enterprise-Vulnerability-Management (das braucht einen anderen Ansatz). Aber es ist besser, als blind jeden Distro-Patch einzuspielen oder Stunden mit hunderten nicht angreifbaren „kritischen" CVEs zu verbrennen.

## Wie secscan einstuft

Jeder Befund wird auf **zwei Achsen** bewertet und in eine von vier Stufen gefasst.

**Achse 1 — ist es auf diesem Host überhaupt angreifbar?** Drei Bedingungen müssen *alle* zutreffen:

1. **Erreichbar** — lauscht der Dienst nach außen (oder ist er über einen anderen erreichbaren Dienst erreichbar)?
2. **Code-Pfad** — wird der verwundbare Code in deinem Setup tatsächlich ausgeführt (Funktion aktiviert, Branch genutzt)?
3. **Vorbedingungen** — kann ein Angreifer die Voraussetzungen erfüllen (keine Auth-Hürde, passender Input)?

Fehlt auch nur eine, ist der CVSS-Score egal — es ist hier nicht angreifbar.

**Achse 2 — was wäre der Schaden?** Von Code-Ausführung/System-Übernahme über Datendiebstahl und Manipulation bis hin zu bloßem Dienst-Absturz (DoS).

Daraus die vier Stufen:

- **Eskalieren** — angreifbar *und* schwerer Schaden (Übernahme, Datenverlust). Sofort handeln.
- **Handeln** — angreifbar, aber begrenzter Schaden; oder schwer, aber nur plausibel erreichbar. Im normalen Zyklus patchen.
- **Beobachten** — läuft, ist hier aber nicht erreichbar (z.B. Funktion deaktiviert) — trotz hoher Score-Werte.
- **Rauschen** — die Komponente läuft auf diesem Host gar nicht (liegt z.B. nur als Datei herum).

CVSS, EPSS und KEV fließen als **Gewichte** ein, entscheiden aber nicht allein: ein „kritischer" CVE, der hier nicht erreichbar ist, landet bei *Beobachten*, nicht im Alarm. Reiner Dienst-Absturz (DoS) eskaliert nie automatisch — der Worst-Case ist ein Neustart. Jede Herabstufung wird begründet (welche Bedingung fehlt), damit du sie nachvollziehen kannst.

## Quick-Start

Voraussetzung: Docker und Docker Compose. Kein Node, kein lokales Python noetig — alles laeuft im Container.

```bash
cp .env.example .env
# Fernet-Key generieren und in .env unter SECSCAN_ENCRYPTION_KEY eintragen:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Flask-Session-Geheimnis erzeugen und in .env unter SECSCAN_SECRET_KEY eintragen:
python -c "import secrets; print(secrets.token_urlsafe(48))"

docker compose up -d --build
curl -fsS http://localhost:8000/healthz
```

Erwartet wird eine JSON-Antwort `{"status":"ok"}`. `/readyz` antwortet unabhaengig vom DB-Zustand mit 200, sobald der App-Container lebt.

### SECSCAN_ENCRYPTION_KEY generieren — Pflicht

Der `SECSCAN_ENCRYPTION_KEY` schuetzt die in der DB gespeicherten LLM-API-Keys via Fernet. Aus historischen Gruenden leiten wir den Fernet-Key deterministisch aus dem Eingabe-String via `sha256` ohne Salt/Iterations ab (siehe `docs/decisions/0013-fernet-kdf.md`). Damit ein offline Dictionary-Angriff aussichtslos bleibt, muss der Eingabe-String **hochentropisch** sein. Verwende eines der folgenden Snippets — niemals ein selbst gewaehltes Passwort:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
# oder
openssl rand -base64 48
```

Beide Generatoren liefern mehr als 256 Bit Entropie. Trivial-Keys (`changeme`, `password`, `aaaaaaaaaaaaa`, ...) loesen beim App-Start eine `secscan.weak_encryption_key`-Warnung in den Logs aus — die App startet trotzdem, aber die Warnung sollte ernst genommen werden.

### Reverse-Proxy in Produktion

Die App lauscht im Container auf Port 8000 in Klartext-HTTP. **Sie ist nicht dafuer gedacht, direkt am Internet zu haengen.** Setze einen Reverse-Proxy davor (nginx, Caddy oder Traefik) und uebernimm dort TLS-Termination, Connection-Limits, Slow-Loris-Schutz und idealerweise eine IP-Allowlist auf `/api/scans` (nur die eigenen Server-IPs zulassen). Details und Empfehlungen in `ARCHITECTURE.md` §9.

Wichtige Punkte fuer die Proxy-Konfiguration:

- **`/api/scans`**: erlaubt gzipped Bodies bis 10 MB on the wire (Default `MAX_CONTENT_LENGTH`), die Wire-Cap des Proxy sollte mindestens 12-15 MB sein damit der Backend-413 den Job macht, nicht der Proxy. `proxy_request_buffering off` empfohlen, damit grosse Scans nicht zuerst im Proxy-RAM gepuffert werden.
- **`/chat/<id>/stream`**: SSE-Endpoint fuer den LLM-Token-Stream (einzige verbliebene SSE-Verwendung nach ADR-0019). Buffering muss aus, Read-Timeout mindestens 1h (Heartbeat alle 30s) und HTTP/1.1 ohne `Connection: keep-alive`-Header damit der Stream nicht wegen Idle-Timeout abreisst. Dashboard-Live-Updates laufen seit v0.5.0 ueber HTMX-Polling (Pane + Sidebar alle 10s, nur bei sichtbarem Tab) und brauchen keine Proxy-Spezialbehandlung.
- **HSTS, moderne Ciphers, HTTP-zu-HTTPS-Redirect** macht der Proxy. Im Backend ist nichts davon konfiguriert — bewusst, damit die App auch hinter exotischen Proxies funktioniert.

#### nginx-Snippet

```nginx
server {
  listen 443 ssl http2;
  server_name secscan.example.com;

  ssl_certificate     /etc/letsencrypt/live/secscan.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/secscan.example.com/privkey.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
  ssl_prefer_server_ciphers on;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

  # /api/scans — Ingest von Server-Agents. IP-Allowlist, grosse Bodies,
  # kein Buffering. Anpassen an eigene VPN-/Backbone-Netze.
  location = /api/scans {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;

    client_max_body_size 15M;
    proxy_request_buffering off;

    proxy_pass http://localhost:8000;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }

  # /chat/<id>/stream — LLM-Token-Stream (einzige SSE-Verbindung nach
  # ADR-0019). Lange Verbindungen, kein Buffer.
  location ~ ^/chat/[^/]+/stream$ {
    proxy_pass http://localhost:8000;
    proxy_http_version 1.1;
    proxy_set_header Connection      "";
    proxy_set_header Host            $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering   off;
    proxy_cache       off;
    proxy_read_timeout 3600s;
  }

  # Restliche UI-Routes.
  location / {
    proxy_pass http://localhost:8000;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}

# HTTP -> HTTPS Redirect.
server {
  listen 80;
  server_name secscan.example.com;
  return 301 https://$host$request_uri;
}
```

#### Caddy-Snippet

```caddy
secscan.example.com {
  # Automatisches TLS via Lets Encrypt.

  # IP-Allowlist auf /api/scans — anpassen an eigene Server-IPs.
  @api_scans_blocked {
    path /api/scans
    not remote_ip 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
  }
  respond @api_scans_blocked "Forbidden" 403

  # Body-Limit fuer Ingest.
  request_body /api/scans {
    max_size 15MB
  }

  # SSE-Endpoint (LLM-Token-Stream, ADR-0019): Buffering aus, lange
  # Read-Timeouts. `/events` ist mit Block L weggefallen — Dashboard-
  # Updates laufen jetzt ueber HTMX-Polling auf den normalen UI-Routes.
  @sse {
    path /chat/*/stream
  }
  reverse_proxy @sse localhost:8000 {
    flush_interval -1
    transport http {
      versions 1.1
      read_timeout 1h
      keepalive 1h
    }
  }

  # Restliche Routes inkl. /api/scans (passt schon durch die Allowlist).
  reverse_proxy localhost:8000 {
    header_up X-Forwarded-For   {remote_host}
    header_up X-Forwarded-Proto {scheme}
    header_up Host              {host}
  }

  header Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
```

#### IP-Allowlist auf `/api/scans` — empfohlen

`/api/scans` ist der einzige Endpoint, der von externen Maschinen (den ueberwachten Servern) angesprochen werden muss. Login, Setup, Dashboard und alle Triage-Views laufen ueber das normale Web-UI. In typischen Deployments leben die ueberwachten Server in einem privaten Netz oder einem VPN (Tailscale, WireGuard, internes RFC-1918-Subnet) — der Reverse-Proxy sollte den Ingest-Endpoint auf genau diese CIDRs beschraenken.

Beispiel-CIDRs in den Snippets oben: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — das ist ein Platzhalter, der nahezu jedes RFC-1918-Setup matcht. Operator passt die Liste an die echte Topologie an (etwa `100.64.0.0/10` fuer Tailscale-CGNAT-Range oder die feste Public-IP des Bastion-Hosts).

Das Backend lehnt unauthentifizierte Push-Versuche bereits in unter 50 ms ab (Auth-vor-Body-Parse, Block C), aber die IP-Allowlist ist Defense-in-Depth: ein verlorener Server-Key wird vom Internet aus unbrauchbar, und unauth-DoS-Versuche erreichen den App-Worker gar nicht erst.

### Postgres-Backups

Der Datenbank-Container persistiert in das Docker-Volume `secscan-db`. Wichtig ist hier ein regelmaessiger logischer Dump, kein Datei-Snapshot — Postgres-Datendateien sind zwischen Major-Versionen nicht binaerkompatibel und reine Volume-Backups verlieren beim naechsten Upgrade ihre Brauchbarkeit. Setze einen Cron-Job auf dem Host (oder einen Backup-Sidecar) auf, der den Dump auf eine externe Ablage rotiert und das wiederherstellbare Format nutzt das eure Org-Standards vorsehen. Wir liefern bewusst kein fertiges Backup-Snippet mit — die Wahl von Zielort, Verschluesselung und Retention ist eine Operator-Entscheidung. Hintergrund zur Speicher-Strategie und welche Daten ueberhaupt persistiert werden steht in `docs/decisions/0005-no-raw-json-storage.md`.

## Repo-Struktur

```
secscan/
├── ARCHITECTURE.md          # die Spec — primäre Quelle aller Implementierungs-Entscheidungen
├── CLAUDE.md                # Master-Kontext für Claude Code (Tech-Stack, Workflow, Out-of-Scope)
├── README.md                # diese Datei
├── docs/
│   ├── blocks/
│   │   ├── STATE.md         # Orchestrator-State (aktueller Block, Blocker)
│   │   ├── A-skeleton.md    # Block-Plan + Definition of Done
│   │   ├── B-models.md      # …
│   │   └── …                # bis H-polish.md
│   └── decisions/           # ADRs (Architecture Decision Records)
│       ├── 0001-no-node-build.md
│       └── …
├── .claude/
│   └── agents/              # Subagent-Definitionen für Claude Code
│       ├── backend-implementer.md
│       ├── frontend-implementer.md
│       ├── test-writer.md
│       ├── reviewer.md
│       └── security-auditor.md
├── agent/                   # Referenz-Implementierung des Push-Agents (Bash)
│   ├── secscan-agent.sh
│   ├── secscan-register.sh
│   └── README.md
└── tests/
    └── fixtures/
        └── trivy/           # echte Trivy-JSON-Outputs für Tests
            ├── README.md
            ├── ubuntu-22.04-rke2.json     # realer 5-MB-Scan
            └── adversarial.json            # synthetische Bad-Inputs
```

Die Verzeichnisse `app/`, `alembic/`, `tests/api/` etc. werden ab Block A vom `backend-implementer`-Agent erzeugt.

## Implementierung mit Claude Code

Diese Spec ist darauf ausgelegt, dass Claude Code als Orchestrator mit spezialisierten Subagenten arbeitet. Der grobe Loop:

1. Du startest `claude` im Repo-Root.
2. Claude Code liest `CLAUDE.md`, `ARCHITECTURE.md`, `docs/blocks/STATE.md` und den aktuellen Block-Plan.
3. Delegiert Implementierung an den passenden Implementer-Agent, danach Tests an den `test-writer`, danach Review gegen die Block-DoD-Checkliste an den `reviewer` (read-only).
4. Bei Sicherheits-relevanten Blöcken zusätzlich `security-auditor`.
5. STOP an jedem Block-Übergang — du gibst explizit frei.

Standing-Order-Prompt zum Start eines neuen Blocks:

```
Lies CLAUDE.md, ARCHITECTURE.md sowie docs/blocks/STATE.md und den aktuellen
Block-Plan. Starte den im STATE.md vermerkten Block. Delegiere an Subagenten
gemäß CLAUDE.md-Workflow. Frage mich vor jedem destruktiven oder ungeklärten
Schritt. Stoppe vor dem nächsten Block-Übergang.
```

## Implementierungs-Reihenfolge (acht Blöcke)

| Block | Inhalt | Plan |
|-------|--------|------|
| A | Skelett, Compose, App-Factory mit Limits/Logging | [`docs/blocks/A-skeleton.md`](docs/blocks/A-skeleton.md) |
| B | Datenmodell, Setup-Wizard, Admin-Auth | [`docs/blocks/B-models.md`](docs/blocks/B-models.md) |
| C | Ingest, Server-Verwaltung, Agent-E2E-Tests | [`docs/blocks/C-ingest.md`](docs/blocks/C-ingest.md) |
| D | Dashboard mit Tags und Stale-Detection | [`docs/blocks/D-dashboard.md`](docs/blocks/D-dashboard.md) |
| E | Triage-View (Liste, Group-by-Package, Diff) | [`docs/blocks/E-triage.md`](docs/blocks/E-triage.md) |
| F | Bulk-Operationen und globale Suche | [`docs/blocks/F-bulk.md`](docs/blocks/F-bulk.md) |
| G | LLM-Integration mit Streaming-Chat | [`docs/blocks/G-llm.md`](docs/blocks/G-llm.md) |
| H | SSE-Live-Updates, Polish, Production-Smoke | [`docs/blocks/H-polish.md`](docs/blocks/H-polish.md) |
| I | UI-Modernisierung — Single-Page-Layout, Heartbeat-Bars, Density (uptime-kuma-Spirit) | [`docs/blocks/I-ui-modernization.md`](docs/blocks/I-ui-modernization.md) |

Aufwandsschätzung: ~8 Wochen Vollzeit für die MVP-Blöcke A–H, plus weitere 1.5–2 Wochen für Block I (UI v2). Block I ist optional für ein erstes Release (v0.1.0 = nach Block H, v0.2.0 = nach Block I) und kann nach MVP-Launch je nach User-Feedback priorisiert werden — siehe ADR-0012.

## Deploy-Checkliste

Reihenfolge fuer ein frisches Production-Deployment:

1. `.env.example` nach `.env` kopieren. `SECSCAN_ENCRYPTION_KEY` mit `python -c "import secrets; print(secrets.token_urlsafe(48))"` erzeugen und eintragen — niemals selbst tippen, siehe ADR-0013.
2. `SECSCAN_SECRET_KEY` (Flask-Session) ebenfalls erzeugen und eintragen. **`SECSCAN_PUBLIC_URL`** auf die externe HTTPS-URL setzen (z.B. `https://secscan.example.com`) — sonst rendert der Bootstrap-Installer in Schritt 7 die interne HTTP-URL und der erste `POST /api/register` laeuft in einen 301-Redirect.
3. `docker compose up -d --build`, dann `curl -fsS http://localhost:8000/healthz` zur Bestaetigung.
4. Reverse-Proxy konfigurieren (nginx- oder Caddy-Snippet oben), TLS-Zertifikat einrichten, IP-Allowlist auf `/api/scans` setzen.
5. Setup-Wizard im Browser durchklicken (`https://secscan.example.com/setup/step1`): Admin-Account anlegen, Master-Key generieren, Defaults setzen.
6. **Master-Key in einen Password-Manager kopieren.** Er wird nie wieder angezeigt — Verlust bedeutet Rotation aller Server-Keys.
7. Pro Server den Bootstrap-Installer als root ausfuehren (siehe naechster Abschnitt). Ein Einzeiler installiert Trivy + Agent-Skripte, registriert den Host mit dem Master-Key und scharft systemd-Timer (oder Cron-Fallback).
8. **Optional**: LLM-Provider unter `Settings -> LLM` konfigurieren (Provider-Preset, API-Key, Tages-Token-Cap). Ohne LLM laeuft die App normal, der Chat-Button ist dann ausgegraut.
9. Postgres-Backup-Cron einrichten (siehe oben).

## Agent-Installation auf einem Server

Standardpfad (ADR-0021, ab v0.7.0):

```bash
curl -fsSL https://secscan.example.com/install.sh | sudo bash
```

Wenn `curl | bash` das Terminal als stdin verliert, gleichwertig mit erhaltenem TTY:

```bash
sudo bash <(curl -fsSL https://secscan.example.com/install.sh)
```

Der Installer ist ein sechs-Phasen-Wizard (System-Detection, Dependencies, Trivy, Server-Registrierung, Scheduler, Probe-Scan). Master-Key und Server-Name werden interaktiv abgefragt (Master-Key silent ueber `/dev/tty`, kein Argv/keine History). Trivy wird per `sha256sum -c` gegen das offizielle GitHub-Release verifiziert. Die `agent.env`-Datei landet als `/etc/secscan/agent.env` mit `chmod 0600 root:root`. systemd-Timer (`daily`, `RandomizedDelaySec=2h`) ist Default; Cron-Fallback mit Jitter wenn `systemctl` fehlt.

**Re-Run** desselben Befehls auf demselben Host erkennt eine vorhandene Registrierung und ueberspringt Phase 4 (kein erneuter Master-Key-Prompt) — geeignet fuer Agent-Updates.

**Unattended-Modus** (Ansible, Cloud-Init, Terraform):

```bash
SECSCAN_UNATTENDED=1 \
SECSCAN_MASTER_KEY=... \
SECSCAN_SERVER_NAME=host01 \
SECSCAN_INTERVAL_HOURS=24 \
SECSCAN_INSTALL_TRIVY=yes \
  sudo -E bash <(curl -fsSL https://secscan.example.com/install.sh)
```

### Unterstuetzte Plattformen

| Familie | Distros | Paketmanager |
|---|---|---|
| Debian | `ubuntu`, `debian` | `apt-get` |
| RHEL | `almalinux`, `rocky`, `rhel`, `centos`, `fedora`, `amazon`, `oracle` | `dnf` (Fallback `yum`) |
| SUSE | `opensuse-leap`, `opensuse-tumbleweed`, `sles` | `zypper` |

Architekturen: `x86_64` und `aarch64`. Andere Architekturen werden mit klarer Fehlermeldung abgelehnt.

**Bewusst nicht unterstuetzt** (ADR-0021): Alpine/OpenRC, `armv7l`, Container-Hosts (`trivy rootfs /` will Host-FS sehen — anti-pattern fuer einen privilegierten Container).

### Power-User-Pfad (Ansible/Salt ohne Wizard)

Wer den Wizard nicht will, kann weiterhin die zwei Skripte direkt aus dem Repo oder vom Backend ziehen und sein eigenes systemd-Template schreiben:

```bash
curl -fsSL https://secscan.example.com/agent/files/secscan-register.sh -o /opt/secscan/bin/secscan-register.sh
curl -fsSL https://secscan.example.com/agent/files/secscan-agent.sh -o /opt/secscan/bin/secscan-agent.sh
chmod 0755 /opt/secscan/bin/secscan-{register,agent}.sh

/opt/secscan/bin/secscan-register.sh https://secscan.example.com <name> <interval-hours>
# -> druckt Server-Key; in /etc/secscan/agent.env als SECSCAN_API_KEY=... eintragen,
#    chmod 0600 root:root.

# Cron oder systemd-Timer fuer secscan-agent.sh einrichten (typisch 0 3 * * *
# taeglich); SECSCAN_URL und SECSCAN_API_KEY werden aus /etc/secscan/agent.env
# via EnvironmentFile (systemd) oder . agent.env (cron) gelesen.
```

### Veraltete Agents erkennen

Backend kennt aus dem Envelope `agent_version` und `trivy_version`. Im Server-Detail-View sowie in der Sidebar-Server-Liste erscheinen Pills `agent veraltet` / `trivy veraltet` / `trivy-db stale` (Schwelle `TRIVY_DB_STALE_THRESHOLD_DAYS=7`). Update = derselbe Einzeiler nochmal ausfuehren. Kein Auto-Update — bewusst (siehe ADR-0021).

## E2E-Smoke ausfuehren

Vollstaendiger Stack-Test inkl. Setup-Wizard, Agent-Registrierung, Ingest und Bombe-Schutz:

```bash
bash scripts/e2e_smoke.sh
```

Das Skript faehrt `docker compose down -v` vorher und nachher, baut frisch und prueft anschliessend Healthz, Findings-Count gegen die Real-Fixture (306 Findings), 401-Latenz auf ungueltigem Bearer und 413-Reject auf 200-MB-gzip-Bomb. Exit-Code 0 bedeutet voller Erfolg.

## Wenn etwas unklar ist

Frage in dieser Reihenfolge:

1. Steht es in `ARCHITECTURE.md`? Dann gilt das.
2. Steht es in einem ADR unter `docs/decisions/`? Dann gilt das.
3. Sonst: User fragen, Antwort als neue ADR festhalten, dann implementieren.
