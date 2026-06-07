# fathometer-agent — Referenz-Implementierung

Zwei kleine Bash-Skripte, die das Push-Format aus
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) (Sektion 6 + 11) abdecken. Sie sind
absichtlich klein gehalten — vor dem Ausführen lesen, dann installieren.

Die Skripte sind eine Referenz, kein Pflicht-Client. Wer den Agent in Python,
Go, Ansible oder als systemd-Unit eigener Wahl nachbauen möchte, kann das tun,
solange das Envelope-Schema eingehalten wird.

## Voraussetzungen auf dem Ziel-Server

- `bash` (>= 4)
- `curl`
- `jq`
- `gzip`
- `trivy` (>= 0.70.0) — Installation siehe https://aquasecurity.github.io/trivy/
  Ältere Versionen funktionieren u.U., aber EPSS-, KEV- und Attack-Vector-Felder
  fehlen oder sind unvollständig — die Triage-Sortierung verliert dann ihre Schärfe.
- root-Rechte für den Scan (`trivy rootfs /` muss alle installierten Pakete
  sehen, sowohl OS-Pakete als auch eingebettete Library-Findings in
  installierten Binaries — Go-Binaries unter `/usr/local/bin`,
  `/var/lib/rancher` etc.)

## Installation in drei Schritten

**1. Master-Key generieren.** In der fathometer Web-UI: Settings → Master-Key
generieren und einmalig anzeigen lassen. Notieren oder direkt als ENV
für Schritt 2 verwenden.

**2. Server registrieren.** Auf dem Ziel-Host:

```bash
FM_MASTER_KEY="<dein-master-key>" \
  ./fathometer-register.sh https://fathometer.example.com prod-web-01 24 \
  | install -m 600 /dev/stdin /etc/fathometer/api-key
```

Das druckt nur den Server-Key auf stdout (alles andere geht nach stderr),
sodass die Pipe in `install -m 600` direkt funktioniert. Wenn der Key verloren
geht, in der UI rotieren — verlorene Keys sind nicht wiederherstellbar.

**3. Agent in Cron einhängen.**

```cron
# /etc/cron.d/fathometer
0 4 * * * root FM_URL=https://fathometer.example.com FM_API_KEY="$(cat /etc/fathometer/api-key)" /usr/local/bin/fathometer-agent.sh >>/var/log/fathometer.log 2>&1
```

Oder als systemd-Timer wenn das vorgezogen wird:

```ini
# /etc/systemd/system/fathometer.service
[Unit]
Description=fathometer trivy push
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/fathometer/env   # FM_URL=… FM_API_KEY=…
ExecStart=/usr/local/bin/fathometer-agent.sh
```

```ini
# /etc/systemd/system/fathometer.timer
[Unit]
Description=fathometer tägliche Ausführung

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
```

Aktivieren mit `systemctl enable --now fathometer.timer`.

## Was wird gesendet?

Der Agent baut einen JSON-Envelope (Schema siehe ARCHITECTURE.md Sektion 6) und sendet ihn **gzip-komprimiert** mit `Content-Encoding: gzip`. Reale Trivy-Scans komprimieren typisch 8–10× (Beispiel: 4.95 MB JSON → 0.56 MB on the wire):

```json
{
  "agent_version": "0.1.0",
  "host": {
    "os_family": "ubuntu",
    "os_version": "22.04",
    "os_pretty_name": "Ubuntu 22.04.4 LTS",
    "kernel_version": "5.15.0-91-generic",
    "architecture": "x86_64"
  },
  "scan": { /* unveränderter trivy rootfs --format json Output */ }
}
```

Der `scan`-Block ist 1:1 die Trivy-Ausgabe. `host` wird aus
`/etc/os-release` und `uname -r` zusammengestellt. `agent_version` zeigt
dem Server an, mit welcher Skript-Version gepusht wurde.

## Konfiguration via Umgebungsvariablen

| Variable                | Pflicht | Default       | Bedeutung                              |
|-------------------------|---------|---------------|----------------------------------------|
| `FM_URL`           | ja      | —             | Backend-URL ohne Trailing-Slash        |
| `FM_API_KEY`       | ja      | —             | Server-Key aus `fathometer-register.sh`   |
| `FM_TRIVY_PATH`    | nein    | `trivy`       | Pfad zur Trivy-Binary                  |
| `FM_SCAN_PATH`     | nein    | `/`           | Was Trivy scannen soll                 |
| `FM_TIMEOUT_SEC`   | nein    | `60`          | curl-Upload-Timeout                    |
| `FM_MASTER_KEY`    | nein    | (interaktiv)  | nur für `fathometer-register.sh`          |

## Exit-Codes

`fathometer-agent.sh`:

- `0` — Scan erfolgreich übertragen
- `1` — fehlende Voraussetzungen (Tools, ENV)
- `2` — Trivy-Scan fehlgeschlagen
- `3` — Upload fehlgeschlagen (Netzwerk oder HTTP-Fehler)

`fathometer-register.sh`:

- `0` — registriert, Server-Key auf stdout
- `1` — fehlende Voraussetzungen oder ungültige Argumente
- `2` — HTTP-Fehler oder ungültige Server-Antwort

## Was der Agent NICHT macht

Keine Auto-Updates, kein Datei-Versand außer dem Scan-Envelope, kein
Inbound-Listener, kein Schreiben außerhalb von `/tmp` (über `mktemp`).
Der Agent ist ein Push-Only-Cron-Job, kein Daemon.
