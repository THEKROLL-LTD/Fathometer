## ADR-0022 — Risk-basierte Priorisierung: Pre-Triage, Host-Snapshot, Vendor-Severity, UI-Redesign

**Status:** Akzeptiert · **Akzeptiert:** 2026-05-18 · **Datum:** 2026-05-18 · **Bezug:** ARCHITECTURE §6 (Wrapper-Envelope wird um `host_state`-Block erweitert), §7 (Dashboard-Layout wird umgebaut — Risk-zentrisch statt CVSS-zentrisch), §11 (Client-Agent sammelt zusätzliche Host-Daten), §15 (Sortier-Defaults bekommen `risk_band` als primären Sort-Key, CVSS-Severity rutscht zum Tiebreak). ADR-0020 (Dashboard-Cross-Server-Findings) bleibt strukturell unberührt — Tabelle und Filter-Bar bleiben, KPI-Cards werden inhaltlich umgebaut. ADR-0021 (Agent-Bootstrap, Ursachen-Felder) wird durch diesen Block **erweitert**, nicht abgelöst — die fünf Ursachen-Spalten am `Finding` bleiben Eingaben für die spätere LLM-Phase.

## Kontext

Heutige Priorisierung im Dashboard und in der Server-Detail-View basiert ausschließlich auf CVSS-Severity. Quick-Stats zeigen „CRITICAL · HIGH · MEDIUM · LOW", KPI-Cards (Block M, ADR-0020) zeigen `Total Open` / `KEV` / `Critical` / `High` / `Stale-Server`, Findings-Tabelle sortiert nach CVSS-Severity-Rank.

Das hat zwei Schwächen:

1. **CVSS ist eine produktunabhängige Severity-Skala, keine Risikoaussage.** Ein Kernel-CVE mit CVSS 9.8 im `bluetooth`-Modul auf einem öffentlichen Webserver, der kein Bluetooth geladen hat, ist faktisch kein Risiko — der Angriffsvektor existiert auf diesem Host nicht. Die heutige UI zeigt es als „CRITICAL" und drängt den Operator zum Patchen, der dann nach Aufwand das System-Image neu baut oder neu bootet — für nichts.

2. **Wichtige Zusatz-Signale werden visuell flach.** EPSS (Exploit-Wahrscheinlichkeit) und KEV (Known-Exploited-Vulnerabilities) sind im Backend verfügbar (Trivy liefert sie wenn die DB sie führt), werden aber heute nur als kleine Pill neben dem Severity-Badge gezeigt. Ein CVE mit CVSS „MEDIUM" aber KEV-gelistet + EPSS 0.85 ist real gefährlicher als ein „CRITICAL"-CVE mit EPSS 0.001.

User-Aussage aus Cowork-Konsultation 2026-05-18, prägnant: „Hauptsächlich will der User nur wissen: muss ich was patchen oder schlimmer weil kein patch verfügbar ist?"

Die Antwort darauf braucht **Server-Kontext** den wir heute nicht haben (welche Komponenten laufen, welche Ports lauschen, welche Kernel-Module sind geladen). Diesen Kontext per statischem Mapping (`package → expected processes/modules/services`) selbst auszuwerten wäre wartungsintensiv und fehleranfällig — die wirkliche Auswertung der „passt das Modul zum Bug?"-Frage gehört zum LLM (Block P). Block O liefert die Datenbasis dafür plus eine konservative deterministische **Vor-Sortierung**, die offensichtlich-harmlose Findings ohne LLM-Aufruf erkennt und die wirklich-kritischen ans LLM weiterreicht.

## Entscheidung

Block O führt vier zusammenhängende Bausteine ein:

1. **Agent-side Host-Snapshot** — der Agent sammelt zusätzlich zu Trivy-Output vier Host-State-Blöcke (Listener, Prozesse, Kernel-Module, Services) und schickt sie im Wrapper-Envelope als neues `host_state`-Feld mit. Das Backend persistiert sie in vier separaten Tabellen.

2. **CVSS-Vendor-Resolver** — pro Finding wird die anzuzeigende Severity aus der zur Host-Distro passenden Vendor-Source bestimmt, mit GHSA-Bevorzugung für `lang-pkgs` und NVD als Fallback. Außerdem wird die Provider-Map (`VendorSeverity`) extrahiert und persistiert, weil die Pre-Triage-Engine das `max-over-providers`-Signal braucht.

3. **Deterministische Pre-Triage-Engine** — eine reine Regel-Engine ohne Host-Kontext-Auswertung. Inputs: max-Severity-aller-Provider, EPSS, KEV-Flag, `vendor_status`. Output: einer von vier Bands (`noise`, `monitor`, `pending`, `unknown`). Pre-Triage entscheidet im Wesentlichen *nur* die Frage „muss diese CVE überhaupt vom LLM (Block P) angeschaut werden?". Sie macht keine Aussage zur tatsächlichen Server-Exposure.

4. **UI-Redesign Dashboard + Server-Detail** — Risk-zentrisch statt CVSS-zentrisch. CVSS-Severity-Counts bleiben sichtbar, rutschen aber zur sekundären Anzeige. Action-Required ist binär (`yes`/`no`).

LLM-basierte Final-Bewertung (Auswertung des Host-Snapshots gegen die `pending`-Findings, Setzen der finalen Bands `escalate`/`act`/`mitigate` plus Demote zu `monitor`/`noise`) ist explizit out-of-scope für diesen Block und kommt als Block P. Block O legt Datenstruktur und Schema so an, dass Block P rein additiv funktionieren wird (`risk_band_source = 'engine' | 'llm' | 'manual'`).

### Risk-Band-Modell (zwei Achsen)

**Level 1 — `action_required`:** binär, nicht ternär. Beantwortet die Bauchgefühl-Frage.

- `yes` — Operator muss aktiv werden ODER selbst einschätzen. Deckt `escalate`, `act`, `mitigate`, `pending`, `unknown`.
- `no` — Operator kann durchatmen. Deckt `monitor` und `noise`.

`unknown` und `pending` fallen bewusst auf `yes`, weil beide bedeuten „die Engine konnte nicht abschließend urteilen, schau selber drauf". Aus User-Perspektive ist das identisch zur Aufforderung zu handeln.

**Level 2 — `risk_band`:** sieben Werte. Drei davon sind Block-O-Outputs (deterministisch), drei sind Block-P-Outputs (LLM), `unknown` ist Block-O-Output für „Snapshot fehlt".

| Band | Gesetzt von | `action_required` | Trigger | Visuell |
|------|------------|-------------------|---------|---------|
| `escalate` | Block P (LLM) | `yes` | LLM-Final-Urteil: kritisch + exposed + (kein Patch ODER KEV-getrieben) | Rot pulsierend, oberste Sektion |
| `act` | Block P (LLM) | `yes` | LLM-Final-Urteil: handlungsbedürftig + Patch verfügbar | Orange, „Patchen"-Sektion |
| `mitigate` | Block P (LLM) | `yes` | LLM-Final-Urteil: exposed + kein Patch / EOL → anders eindämmen | Gelb-Orange, „Kein Patch — anders eindämmen"-Sektion |
| `pending` | Block O (Pre-Triage) | `yes` | Pre-Triage erkennt kritisches Potenzial, LLM hat noch nicht final geurteilt | Blau-Grau, „Pending review"-Sektion mit Hint |
| `unknown` | Block O (Pre-Triage) | `yes` | Kein Host-Snapshot (alter Agent, `host_state`-Block fehlt) | Grau mit Hint „Update agent for context-aware risk" |
| `monitor` | Block O (Pre-Triage) ODER Block P (LLM-Demote) | `no` | Pre-Triage: Mittelfeld ohne Exploit-Signal · oder · LLM-Demote: nicht exposed aber CVE besteht latent | Gelb, Sammelliste „Beobachten" |
| `noise` | Block O (Pre-Triage) ODER Block P (LLM-Demote) | `no` | Pre-Triage: alle Provider niedrig + EPSS klein + nicht KEV · oder · LLM-Demote: Komponente nachweisbar nicht aktiv | Grau, batch-ack-tauglich |

Mapping `risk_band → action_required` ist deterministisch im Code (`app/services/risk_engine.py::ACTION_REQUIRED_MAP`), nicht in der DB. Persistiert wird nur `risk_band`. Single-Source-of-Truth, keine Migration nötig wenn das Mapping mal angepasst wird.

### Pre-Triage-Algorithmus

Sehr klein, sehr defensiv. Vollständige Implementierung in Block O Task #7:

```python
def pretriage(finding: Finding, server: Server, snapshot_available: bool) -> RiskBand:
    if not snapshot_available:
        return RiskBand.UNKNOWN

    # max-Severity ueber alle Provider (NVD, Vendor, GHSA, ...).
    # Wenn severity_by_provider leer ist: fallback auf Finding.severity.
    max_sev = max_severity_across_providers(finding)

    epss = finding.epss_score or 0.0
    kev = finding.is_kev

    # Defensive Cuts: lieber 1-2 mehr zum LLM-Bucket als zu wenig.
    if kev:
        return RiskBand.PENDING  # KEV ueberschreibt alles
    if max_sev >= Severity.HIGH:
        return RiskBand.PENDING  # ein einziger HIGH-Provider reicht
    if epss >= 0.1:
        return RiskBand.PENDING  # EPSS-Trigger ueber CISA-aehnliche Schwelle
    if max_sev == Severity.MEDIUM:
        return RiskBand.MONITOR
    # alle Provider <= LOW + EPSS < 0.1 + nicht KEV
    return RiskBand.NOISE
```

Pre-Triage-Reason-String wird gleich mitgeneriert für die UI-Begründungs-Box:

- `noise`: `"alle Provider ≤ LOW · EPSS 0.001 · not KEV"`
- `monitor`: `"max-Severity MEDIUM (ubuntu) · EPSS 0.04 · not KEV"`
- `pending`: `"vendor (redhat) severity HIGH · pending LLM review"` oder `"KEV listed (added 2024-04-12) · pending LLM review"`
- `unknown`: `"host snapshot missing — update agent to ≥ 0.3.0"`

Block P (LLM) überschreibt den Reason-String wenn er final urteilt. `risk_band_source` wechselt von `engine` zu `llm`.

### Erwartetes Mengen-Verhältnis und LLM-Volumen

Schätzung auf Basis typischer Linux-Server-Findings (Ubuntu 22.04 LTS Stock, +100-300 CVE-Einträge pro Scan):

- ~40-60% `noise` — die meisten Distro-CVEs sind LOW-Severity ohne aktives Exploit-Signal.
- ~20-30% `monitor` — MEDIUM-Severity-Block mit kleinem EPSS.
- ~15-30% `pending` — HIGH/CRITICAL irgendwo, EPSS ≥ 0.1, oder KEV.

Bei einer 200-Server-Flotte × 300 Findings/Server = 60K Findings, davon **geschätzt** ~15K in `pending`. Mit Application-Grouping (ADR-0023) reduziert sich das auf ~5-15 Groups pro Server × ~10 unique Server-Context-Fingerprints = wenige hundert eindeutige LLM-Calls für den initialen Library-Aufbau. Bei DeepSeek-V3-Preisen (Block-G-Default-Provider) ist das pro Monat im niedrigen einstelligen Dollar-Bereich nach Library-Stabilisierung.

**Diese Schätzung wird vor Block-P-Scharfschaltung empirisch validiert** — Block P startet mit einem Observation-Mode (Jobs werden geschrieben, Worker schreibt `would_call`-Marker statt echter LLM-Calls), und erst nach 1-2 Wochen Realbetrieb wird das Feature-Flag auf `live` umgelegt. Falls die echten Zahlen außerhalb des erwarteten Bereichs liegen, werden die Pre-Triage-Cuts in Block O nachjustiert (Konstanten im Code, keine Schema-Migration). Details der Block-P-Architektur in ADR-0023.

### Host-Snapshot — Datenmodell

Der Agent sendet im Envelope einen neuen `host_state`-Block:

```json
{
  "agent_version": "0.3.0",
  "host": { ... },
  "host_state": {
    "snapshot_at": "2026-05-18T03:14:22Z",
    "tools_available": ["ss", "ps", "lsmod", "systemctl"],
    "gaps": [],
    "listeners": [
      { "proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd", "pid": 1234 },
      { "proto": "tcp", "addr": "127.0.0.1", "port": 5432, "process": "postgres", "pid": 5678 },
      { "proto": "udp", "addr": "0.0.0.0", "port": 53, "process": "named", "pid": 901 }
    ],
    "processes": [
      { "pid": 1234, "user": "root", "comm": "sshd", "args": "/usr/sbin/sshd -D" },
      { "pid": 5678, "user": "postgres", "comm": "postgres", "args": "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main" }
    ],
    "kernel_modules": ["ext4", "nf_conntrack", "xt_conntrack", "br_netfilter", "overlay", "bridge"],
    "services": ["sshd.service", "postgresql.service", "nginx.service"]
  },
  "scan": { ... }
}
```

Backend-Schema-Bounds:

- `host_state` ist **optional** im Envelope (Forward-Compat — Agent 0.2.0 sendet es nicht, das Backend muss damit umgehen).
- `listeners`: max 4096 Einträge, `port ∈ [0..65535]`, `addr` als IPv4/IPv6-Literal (ASCII), `proto ∈ {tcp,udp,tcp6,udp6}`, `process` max 64 Chars, `pid ∈ [0..2^31)`.
- `processes`: max 4096 Einträge, `user` max 32 Chars, `comm` max 64 Chars, `args` max 4096 Chars (Java-Cmdlines können lang werden).
- `kernel_modules`: max 1024 Strings, jeder max 64 Chars.
- `services`: max 1024 Strings, jeder max 128 Chars (Unit-Namen mit `@instance` können lang werden).
- `tools_available` / `gaps`: max 32 Strings, jeder max 32 Chars.

Persistenz: **vier separate Tabellen**, eine pro Block. Vorteil: SQL-abfragbar („zeige alle Server mit `sshd` auf 0.0.0.0:22") und indexierbar — wertvoll für die Server-Detail-UI in Block O und unverzichtbar für Block P (LLM-Filter auf für den Finding relevante Snapshot-Excerpts). JSONB-Spalte als Alternative wäre kompakter, aber Abfragbarkeit überwiegt.

DB-Tabellen:

- `server_listeners(server_id, proto, addr, port, process, pid)` — `(server_id, proto, port, addr)` ist natural key. Index auf `(server_id, port)`.
- `server_processes(server_id, pid, user, comm, args)` — `(server_id, pid)` ist natural key. Index auf `(server_id, comm)`.
- `server_kernel_modules(server_id, name)` — `(server_id, name)` ist natural key.
- `server_services(server_id, name)` — `(server_id, name)` ist natural key.

Plus eine Tracking-Spalte am `Server`:

- `host_state_snapshot_at: Mapped[datetime | None]` — Zeitstempel des letzten Snapshot-Updates.

Update-Strategie pro Server: **truncate + insert** in einer Transaktion. Bewusst nicht UPSERT — wir wollen den vollständigen aktuellen State, kein Merge mit alten Daten. Performance: 4096 + 4096 + 1024 + 1024 = 10K Zeilen pro Server pro Scan; bei 200 Servern × 1 Scan/Tag = 2M Zeilen-Operationen, innerhalb Postgres-Latenz-Budget.

### Wer konsumiert den Host-Snapshot in Block O?

- **Risk-Engine (Pre-Triage):** ja — aber nur als „existiert oder existiert nicht"-Signal für die `unknown`-Entscheidung. Pre-Triage liest Snapshot-Inhalte nicht.
- **Server-Detail-UI:** ja — neue Sektion „Host snapshot" zeigt Listener, Services, optional Module für den menschlichen Operator. Wertvoll auch *ohne* LLM-Final-Urteil — Operator kann selbst die Frage „läuft sshd?" beantworten.
- **Block P (LLM, später):** ja — bekommt für jeden `pending`-Finding einen Snapshot-Excerpt (gefiltert auf das Paket).

Block O sammelt also die Daten *vollständig*, nutzt sie *teilweise* (UI + Pre-Triage-Existenz-Check), und gibt Block P einen direkt-nutzbaren Datensatz.

### CVSS-Vendor-Resolver

`app/services/severity_resolver.py` (neu):

```python
# Mapping host-os-family → bevorzugte CVSS-Provider-Reihenfolge
_VENDOR_PRIORITY: dict[str, tuple[str, ...]] = {
    "ubuntu":     ("ubuntu", "debian", "nvd"),
    "debian":     ("debian", "ubuntu", "nvd"),
    "rhel":       ("redhat", "nvd"),
    "centos":     ("redhat", "nvd"),
    "rocky":      ("redhat", "nvd"),
    "alma":       ("redhat", "nvd"),
    "fedora":     ("redhat", "nvd"),
    "amazon":     ("amazon", "redhat", "nvd"),
    "opensuse-leap":       ("suse", "nvd"),
    "opensuse-tumbleweed": ("suse", "nvd"),
    "sles":       ("suse", "nvd"),
    "alpine":     ("alpine", "nvd"),
    "oracle":     ("oracle", "redhat", "nvd"),
}

_LANG_PRIORITY = ("ghsa", "nvd")


def severity_for(finding: Finding, server: Server) -> tuple[Severity, str]:
    """Returns (severity_value, severity_source) — die UI-Anzeige-Severity
    plus den Provider-Namen ('ubuntu', 'nvd', 'ghsa', ...)."""


def max_severity_across_providers(finding: Finding) -> Severity:
    """Returns das Maximum ueber alle bekannten Provider plus den
    Top-Level-Trivy-Wert. Das ist der Input fuer pretriage()."""
```

Neue Finding-Spalte `severity_by_provider: dict[str, str] | None` (JSONB) hält die Provider-Map aus `TrivyVulnerability.VendorSeverity`. Wenn nichts vorhanden ist, fällt der Resolver auf `finding.severity` + `severity_source="trivy"` zurück.

Severity-Score-zu-Label-Mapping (für Provider, die nur Scores liefern): ≥9 CRITICAL, ≥7 HIGH, ≥4 MEDIUM, >0 LOW, sonst UNKNOWN.

### `vendor_status`

Trivy schreibt im `Vulnerability.Status`-Feld Werte wie `affected`, `fixed`, `under_investigation`, `will_not_fix`, `end_of_life`, `not_affected`. Heute wird das Feld zwar geparst, aber nicht persistiert. Block O führt eine neue Finding-Spalte `vendor_status: Mapped[str | None]` (max 32 Chars) ein, mit Whitelist-Normalisierung auf `{affected, fixed, investigating, will_not_fix, eol, not_affected, unknown}`.

Pre-Triage konsumiert `vendor_status` zunächst nicht — sie macht ihre Aussage allein über Severity + EPSS + KEV. Block P (LLM) bekommt `vendor_status` als Eingabe-Signal: ein `will_not_fix`-Finding kann das LLM zur `mitigate`-Final-Entscheidung führen.

### Finding-Schema-Erweiterung

Neue Spalten in `Finding`:

| Spalte | Typ | Zweck |
|--------|-----|-------|
| `risk_band` | `String(16)` | `escalate`/`act`/`mitigate`/`pending`/`unknown`/`monitor`/`noise`, nullable bis erste Engine-Auswertung. |
| `risk_band_reason` | `String(256)` | Engine- oder LLM-generierter Begründungs-String, nullable. |
| `risk_band_source` | `String(16)` | `engine` / `llm` / `manual`, default `engine`. |
| `risk_band_computed_at` | `DateTime(tz)` | Timestamp der letzten Engine-Auswertung. |
| `severity_by_provider` | `JSONB` | Map `provider → severity_label`, nullable. |
| `vendor_status` | `String(32)` | Normalisierter Trivy-Status, nullable. |

Plus zwei Indizes auf `risk_band` für die UI-Filter:

- `ix_findings_risk_band_open` partial-index `WHERE status = 'open'` für die typische Dashboard-Sortierung.
- `ix_findings_server_risk_band` für die Server-Detail-Gruppierung.

`action_required` ist **keine eigene Spalte** — der Wert wird beim Render aus dem `ACTION_REQUIRED_MAP` abgeleitet.

### Sort-Order für die UI

Default-Sort-Key wird `risk` (DESC), mit numerischem Mapping:

```
escalate = 70
act      = 60
mitigate = 50
pending  = 40
unknown  = 30
monitor  = 20
noise    = 10
NULL     =  0
```

Tiebreak weiter wie ADR-0020-Defaults (KEV, EPSS, CVSS).

### UI-Redesign

**Dashboard-Layout (`dashboard/_detail_pane.html`, baut auf ADR-0020 auf):**

Der bisherige KPI-Card-Strip aus Block M wird neu organisiert:

- **Primäre KPI-Reihe** (zwei große Cards links, prominent):
  - `Action needed — N servers` — Zahl der Server mit mindestens einem `escalate`/`act`/`mitigate`/`pending`/`unknown`-Finding. Klick filtert die Tabelle auf `?action_required=yes`.
  - `Safe — N servers` — Zahl der Server ohne `action_required=yes`-Findings. Klick filtert auf `?action_required=no`.

- **Sekundäre Risk-Band-Reihe** (sieben kompakte Pills rechts):
  - `Escalate` · `Act` · `Mitigate` · `Pending` · `Unknown` · `Monitor` · `Noise` — Findings-Counts (nicht Server-Counts). Pulse-Animation für `escalate`.

- **Tertiäre Severity-Strip** (kleine horizontale Pill-Reihe unten):
  - `CRITICAL 12 · HIGH 47 · MEDIUM 130 · LOW 88` — kompakt, ohne Sparkline, ohne Klick-Filter (Severity-Filter bleibt in der Filter-Bar erreichbar).

Findings-Tabelle (Block M) bekommt eine neue erste sortierbare Spalte `Risk` mit Default-Sort (siehe Sort-Order). CVSS-Severity-Spalte rutscht nach hinten zwischen `Status` und `Erstmals`. Filter-Bar bekommt einen zusätzlichen `risk_band`-Filter neben den bestehenden.

**Server-Detail-Layout (`servers/detail.html`, baut auf ADR-0018 auf):**

Header-Pill-Reihe bekommt **vor** den bestehenden Status-Pills und vor den Block-N-Pills eine **Action-Required-Pill**:

- `Action needed — 1 escalate · 2 act · 3 pending` (rot mit Sub-Counter, jede Sub-Zahl klickbar als Filter)
- `Safe — 4 monitor · 96 noise` (grün mit Sub-Counter)

Direkt unter dem Header eine neue Sektion „**Host snapshot**" mit kompakter Anzeige der wichtigsten Snapshot-Daten:

```
Listeners
  sshd       0.0.0.0:22         tcp
  nginx      0.0.0.0:443        tcp
  postgres   127.0.0.1:5432     tcp

(11 more — show all)

Active services: nginx · postgresql · sshd · cron · systemd-logind  (+8)
```

Sektion bleibt collapsible, default `escalate`/`act`-Header expanded. Tooltip pro Listener-Zeile zeigt den vollen Prozess-Args-String.

Findings-Tabelle in der Server-Detail-View wird gruppiert nach `risk_band`, default-expanded ab `pending` aufwärts, default-collapsed für `monitor`/`noise`/`unknown`. Sortierung innerhalb jeder Gruppe nach den Block-K-Defaults (KEV, EPSS, CVSS).

**Per-Finding-Detail-Box** in der Tabelle bekommt eine **Begründungs-Zeile** mit dem `risk_band_reason`. Beispiel für ein `pending`-Finding in Block O:

```
pending
vendor (redhat) severity HIGH · EPSS 0.34 · KEV not listed
→ awaiting LLM final review
```

Sobald Block P läuft und das Finding final bewertet, ersetzt der LLM-Output diesen Block:

```
act (LLM, 2026-06-01)
sshd listens 0.0.0.0:22 on this host. Patch available in
openssh-server=1:9.6p1-3ubuntu13.5. Apply via apt-get upgrade
or analogous mechanism.
```

**Bulk-Ack-„noise"-Workflow:** in der Server-Detail-View bekommt der Findings-Section-Header neben dem bestehenden CSV-Dropdown einen Button „Acknowledge all noise on this server (N)". Klick öffnet ein Modal mit Liste der `noise`-Findings, max 50 inline plus „... and N more"-Truncation, Pflicht-Bestätigung, dann Aufruf des bestehenden Block-F-Bulk-Acknowledge-Endpoints mit `finding_ids`-Flavor und zusätzlichem `risk_band_filter="noise"`-Parameter, der server-side hart filtert. Sicherheits-Default: selbst wenn der Operator versuchen würde, `pending`/`act`-IDs einzuschleusen, dropped der Endpoint sie. `monitor`-Findings sind aus dem Bulk-Workflow ausgenommen — sie können einzeln acked werden, aber das System macht keinen Bulk-Vorschlag, weil monitor ein „im Auge behalten"-Signal ist.

### Re-Evaluation

Pre-Triage läuft **ausschließlich bei Scan-Ingest**, pro Finding, im Block mit dem `Scan`-Insert. Drei Schritte im Ingest:

1. Bestehender Block-C-Pfad: Trivy-Envelope parsen, Findings UPSERT, Audit-Events.
2. Neu in Block O: `host_state` aus dem Envelope parsen, vier Snapshot-Tabellen truncate+insert für diesen Server, `host_state_snapshot_at` setzen.
3. Neu in Block O: Pre-Triage über alle aktuell offenen Findings dieses Servers laufen lassen, `risk_band`/`risk_band_reason`/`risk_band_source='engine'`/`risk_band_computed_at` updaten. Audit-Event `risk.pretriage_evaluated` einmal pro Scan mit Counters.

EPSS/KEV-Datenbank-Updates zwischen Scans schlagen sich erst beim nächsten Scan in der Pre-Triage nieder. Dokumentiert in der Stale-Pill aus Block N.

**Wichtige Eigenschaft:** Pre-Triage überschreibt LLM-Outputs **nicht**. Wenn ein Finding bereits einen LLM-gesetzten Band hat (`risk_band_source = 'llm'`), bleibt der Band stehen — die Pre-Triage-Engine springt für dieses Finding gar nicht an. Erst Block P (LLM) entscheidet bei Snapshot-Drift oder neuen CVE-Daten, ob ein Re-Eval nötig ist. Re-Open-Trigger falls Pre-Triage doch LLM-Outputs überstimmen soll.

### Audit-Events

Neue Audit-Event-Typen:

- `risk.pretriage_evaluated` — pro Scan, Body `{counters: {pending: N, monitor: N, noise: N, unknown: N}, server_id: ...}`.
- `risk.band_changed` — pro Finding wenn der Band sich ändert. Body enthält alt + neu + Source (engine/llm/manual) + Reason. Deckt sowohl Pre-Triage-Klassifikation als auch zukünftige LLM-Updates und Demote-Events ab.
- `host_state.snapshot_received` — pro Scan mit Snapshot, Body `{tools_available: [...], gaps: [...], listener_count: N, process_count: N}`.

## Begründung

**Warum Risk-Band statt CVSS-Severity primär.** Die Operator-Bauchgefühl-Frage ist „muss ich was tun?", nicht „wie bewertet NVD?". CVSS-Severity ist eine bauteilunabhängige Skala; ein und derselbe CVSS-9.8-Bug ist auf einem Web-Server ohne Bluetooth-Stack faktisch nicht ausnutzbar.

**Warum zwei-Ebenen-Modell mit binärem Level 1.** Die Bauchgefühl-Frage ist binär (yes/no), die operative Frage ist granularer. Ein einziger Band-Wert müsste beide gleichzeitig kommunizieren; das macht die UI komplexer als nötig. `unknown` und `pending` fallen auf `yes`, weil beide die gleiche Operator-Aufgabe auslösen („schau drauf").

**Warum sieben Bands (sechs produktive + unknown).** Pre-Triage liefert vier Werte (`noise`, `monitor`, `pending`, `unknown`); LLM liefert drei zusätzliche (`escalate`, `act`, `mitigate`) plus Demote-Möglichkeit zu `monitor`/`noise`. Sieben Bands sind die kombinierte Endmenge. Weniger Granularität würde entweder die Pre-Triage- oder die LLM-Phase verarmen lassen.

**Warum kein eigenes Exposure-Mapping in Block O.** Statisches Mapping `package_name → expected processes/modules/services` müsste hunderte Einträge pflegen, Versions-spezifische Edge-Cases abdecken (`openssh-server` vs. `openssh-server-portable`), neue Pakete handhaben (Custom-Builds, Snap, Flatpak). Der Wartungsaufwand übersteigt den Nutzen, vor allem da das LLM dieselbe Aufgabe mit weit besserer Generalisierung machen kann — es liest den CVE-Titel, sieht die Snapshot-Daten und macht eine fundierte Aussage statt einer Regel-Heuristik. Block O liefert die Datenbasis, das LLM macht das Reasoning.

**Warum Pre-Triage trotzdem deterministisch.** Drei Gründe: (a) LLM-Cost und -Latenz für 60K Findings pro Eval wären unverhältnismäßig — die meisten CVEs sind harmlos und brauchen keine Kontext-Auswertung. (b) Deterministische Vor-Auswertung ist erklärbar und audit-bar — der `risk_band_reason`-String trace die Regel, kein Black-Box-LLM-Output. (c) Pre-Triage funktioniert auch ohne konfigurierten LLM-Provider — Operator hat Tag eins eine konsistente Sicht, auch wenn alles Kritische erst mal `pending` ist.

**Warum defensive Pre-Triage-Cuts.** User-Aussage: „lieber 1-2 mehr durchs LLM jagen". Ein einzelner HIGH-Provider, EPSS ≥ 0.1, oder KEV-Flag schiebt ins `pending`. False-Negatives in der Vor-Auswertung (echt kritisches Finding fälschlich als `noise`/`monitor` markiert) sind schwer zu erkennen — der Operator würde sie nicht sehen, weil sie versteckt sind. False-Positives (eigentlich harmloses Finding fälschlich als `pending` markiert) sind harmlos: LLM klärt das im nächsten Pass, demoted das Finding zu `monitor` oder `noise`, einmaliger LLM-Call. Konservatives Bias ist hier billiger.

**Warum `pending` als eigener Band-Wert statt NULL + Source-Flag.** Single-Source-of-Truth in der `risk_band`-Spalte. DB-Queries sind simpel (`WHERE risk_band = 'pending'`). UI-Filter-Logik ist konsistent (`?risk_band=pending` analog `?risk_band=escalate`). NULL würde mehrere semantische Zustände vermischen (noch nie ausgewertet vs. Pre-Triage-pending vs. LLM-Fehler).

**Warum Host-Snapshot schon in Block O.** Snapshot-Daten haben Wert auch ohne LLM: Operator kann selbst „läuft sshd?"-Fragen in der UI beantworten; Snapshot ist Eingabe für andere zukünftige Features (Compliance-Reports, Health-Dashboards); Block P kommt ohne Snapshot-Sammlung nicht aus, also vorziehen vermeidet doppelte Agent-Bumps. Single-Agent-Push, Single-Datenmodell, Block P ist additiv.

**Warum nicht alles ans LLM.** User-Aussage: „nicht für jeder der zig tausend findings". Wirtschaftlich: LLM-Tokens kosten, der `noise`-Bucket macht 40-60% der Findings aus und ist deterministisch sicher klassifizierbar. Strategisch: deterministische Klassifikation ist erklärbar und audit-fähig — bei Compliance-Fragen („warum wurde das CVE als noise eingestuft?") gibt es eine Regel-Antwort, kein „das LLM hat es so gesagt". LLM bleibt für die Cases reserviert, wo Server-Kontext entscheidet.

**Warum monitor nicht ans LLM.** Pre-Triage-`monitor` ist „Mittelfeld ohne Exploit-Signal" — nicht actionable, kein Eskalations-Risiko. Wenn der User in Zukunft sagt „das LLM soll auch monitor angucken", lassen sich die Pre-Triage-Cuts verschärfen (monitor-Definition enger ziehen, mehr ins pending schieben). Aktuell: monitor ist Operator-Zeit-Schutz, nicht Engine-Beschränkung.

Alternativen verworfen:

- **CVSS-Severity beibehalten und nur EPSS/KEV-Pills prominenter machen.** Liefert nicht die Exposure-Dimension — der Bluetooth-Beispiel-Bug auf dem Webserver bleibt „CRITICAL".
- **Selbst gepflegtes Exposure-Mapping als JSON-Asset.** Wartungsaufwand zu hoch (siehe oben), LLM-Lösung ist überlegen.
- **Direktes LLM ohne deterministische Vor-Stufe.** Token-Last, Latenz, nicht-audit-bar.
- **Risk-Score als einzelner Float (0..1).** UI-Aufgabe: was bedeutet 0.73? Bands sind klar buckable und kommunizierbar.
- **Container-Workloads als zusätzliche Snapshot-Quelle.** Container-Scans sind out-of-scope (ARCHITECTURE §17). Wenn `kubelet` läuft, sehen wir es in `ps`/`ss` — das reicht für die Pre-Triage- und spätere LLM-Bewertung des Hosts.

## Konsequenzen

**Code (neu):**

- `app/services/risk_engine.py` — Pre-Triage-Funktion `pretriage(finding, server, snapshot_available) -> RiskEvaluation`. Konstanten `RiskBand`-Enum, `ActionRequired`-Enum, `ACTION_REQUIRED_MAP`, `RISK_BAND_SORT_RANK` (für UI-Sortierung).
- `app/services/severity_resolver.py` — Vendor-CVSS-Priorität, `severity_for()` und `max_severity_across_providers()`.
- `app/models.py` neue Modelle: `ServerListener`, `ServerProcess`, `ServerKernelModule`, `ServerService`. Bestehende `Finding`-Klasse um sechs neue Spalten erweitert. `Server` um `host_state_snapshot_at`.
- `app/templates/_partials/host_snapshot.html` — Server-Detail-Sektion „Host snapshot".
- `app/templates/_partials/risk_band_pill.html` — wiederverwendbares Pill-Markup mit Tooltip.
- `app/templates/_partials/action_required_card.html` — Dashboard-Primary-KPI-Card.
- `app/views/dashboard.py` — KPI-Counter-Builder um Action-Required und Risk-Band-Counts erweitert.
- `app/views/server_detail.py` — Snapshot-Sektion-Builder, Findings-Gruppierung nach `risk_band`.
- `app/views/findings.py` — Bulk-Ack-Endpoint bekommt `risk_band_filter="noise"`-Parameter für den Noise-Bulk-Workflow.

**Code (geändert):**

- `agent/secscan-agent.sh`: `AGENT_VERSION` auf `0.3.0` bumpen. Vier neue Snapshot-Funktionen (`collect_listeners`, `collect_processes`, `collect_kernel_modules`, `collect_services`). Tool-Verfügbarkeits-Check → `tools_available` / `gaps` im Output. Envelope-Erweiterung um `host_state`. Größenordnung gzipped: +10-30 KB pro Scan.
- `app/schemas/scan_envelope.py`: Envelope um `host_state: HostStateBlock | None = None`. Neue Sub-Modelle `HostStateBlock`, `ListenerEntry`, `ProcessEntry`. Validatoren für IPv4/IPv6-Literale, Port-Bounds, ASCII-only, NUL-frei. Plus `TrivyVulnerability.vendor_severity: dict[str, str] | None` (alias `VendorSeverity`).
- `app/api/scans.py`: Ingest-Pfad um `host_state`-Parse + Snapshot-Tabellen-Update + Pre-Triage-Engine-Aufruf. **Wichtig:** Reihenfolge ist strikt Auth → Body-Parse → Trivy-Findings → Snapshot → Pre-Triage. Bei Snapshot-Parse-Fehler: Snapshot-Block wird verworfen, Findings-Ingest geht durch, Pre-Triage läuft mit `snapshot_available=False` (`unknown`-Band). Audit-Event `host_state.parse_failed`.
- `app/__init__.py`: Jinja-Globals registrieren für `risk_band_label()`, `action_required_label()`, `format_risk_band_reason()`.
- `app/templates/dashboard/_kpi_cards.html`: Komplett-Umbau (siehe UI-Redesign-Sektion).
- `app/templates/dashboard/_findings_section.html` und `app/templates/servers/_findings_section.html`: Tabellen-Spalten-Set um Risk-Spalte ergänzt, CVSS-Severity-Spalte rutscht nach hinten. Filter-Bar bekommt `risk_band`-Select.
- `app/templates/servers/detail.html`: Header bekommt Action-Required-Pill als erste Pill. Snapshot-Sektion direkt darunter.
- `app/schemas/dashboard_filter.py` und `app/schemas/findings_view_filter.py`: neue Felder `risk_band: Literal[...] | None = None`, `action_required: Literal["yes","no"] | None = None`. Whitelist-Validierung.
- `app/services/findings_query.py` und `app/services/findings_ingest.py`: Filter-Anwendung für `risk_band`/`action_required`. Ingest-Mapper extrahiert `vendor_status` und `severity_by_provider`.
- `ARCHITECTURE.md §6`: Envelope-Beispiel um `host_state`.
- `ARCHITECTURE.md §7`: Dashboard-Beschreibung umschreiben — Risk-zentrisch.
- `ARCHITECTURE.md §11`: Agent-Beschreibung erweitern um Snapshot-Sammlung.
- `ARCHITECTURE.md §15`: Sortier-Defaults — `risk_band` ist Primary, CVSS-Severity rutscht in den Tiebreak-Tail.
- `ARCHITECTURE.md §17`: Out-of-Scope ergänzen: LLM-Risk-Reasoning (Block P), Host-Snapshot-Historisierung, manueller Risk-Override, Patch-Alter-Eskalation, Exposure-Matcher (= entfällt zugunsten LLM).

**Migration:**

- Eine neue Alembic-Migration `XXXX_block_o_risk_and_host_state.py`:
  - Vier `CREATE TABLE` für die Snapshot-Tabellen mit Indizes.
  - Sechs `ADD COLUMN` auf `findings`.
  - Ein `ADD COLUMN` auf `servers` (`host_state_snapshot_at`).
  - Zwei `CREATE INDEX` auf `findings.risk_band`.
  - Downgrade: spiegelbildlich.
- Kein Backfill — Werte werden beim nächsten Scan-Ingest gesetzt. Existierende Findings bleiben mit `risk_band = NULL` bis zum nächsten Scan; UI rendert in diesem Fall „pending pre-triage" (visuell wie pending, aber mit anderem Reason-String).

**Tests:**

Detaillierte Liste siehe Block-O-Brief. Zusammenfassung:

- `tests/services/test_risk_engine_pretriage.py` — Tabellen-getrieben mit ~25 Cases für jede Severity-EPSS-KEV-Kombination.
- `tests/services/test_severity_resolver.py` — Vendor-Priorität pro Distro, Fallback-Pfade.
- `tests/api/test_scans_host_state.py` — Envelope-Parse, Snapshot-Tabellen-Update, Idempotenz bei Re-Ingest.
- `tests/views/test_dashboard_risk_kpis.py`, `tests/views/test_server_detail_action_required.py`, `tests/views/test_findings_filter_risk_band.py`.
- Adversarial: `tests/adversarial/test_host_state_xss.py` (Prozess-args mit `<script>`), `tests/adversarial/test_listener_addr_validation.py`, `tests/adversarial/test_bulk_ack_noise_strict.py` (Einschleusen von non-noise-IDs blockt).

Erwartete Test-Anzahl nach Block O: ca. +90 Tests.

## Re-Open-Trigger

- **LLM-Final-Bewertung mit Application-Grouping (Block P).** Block O liefert `pending`-Findings. Block P führt eine Application-Group-Schicht ein (Findings gruppiert nach Owner-Application via wachsender LLM-gepflegter Pattern-Library), eine Two-Pass-LLM-Architektur (Pass 1 Group-Detection, Pass 2 Risk-Bewertung pro Group), und einen asynchronen Worker-Container für die LLM-Aufrufe. Schema-Slot `risk_band_source = 'llm'` ist da, Block P füllt ihn. Detail-Spec in [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md).
- **Pre-Triage-Cuts anpassen.** Wenn LLM-Volumen sich als zu groß erweist (z.B. 50%+ aller Findings landen in pending): HIGH-Trigger auf CRITICAL verschärfen oder EPSS-Trigger von 0.1 auf 0.3 anheben. Konstanten im Code, keine Migration nötig.
- **Daily-Re-Eval-Job für EPSS/KEV-DB-Updates.** Engine läuft heute nur bei Scan-Ingest. Falls Operator-Feedback nach EPSS-Stale-Findings fragt, Hintergrund-Job nachrüsten.
- **Manueller Operator-Override per Finding oder per Server-Tag.** Acknowledgement reicht heute — wenn realer Workflow zeigt, dass Operator regelmäßig „aber wir haben WAF davor"-Diskussionen führt: eigene ADR mit Override-Spalte und UI-Surface.
- **VendorSeverity-Disagreement-Indikator.** Pill „NVD: critical, Vendor (ubuntu): low" als zusätzliches Triage-Signal. Daten sind ab Block O persistiert (`severity_by_provider`-JSONB).
- **Aggregierte Risk-Trend-Reports.** „Wie viele Server haben sich diese Woche verschlechtert?" — Historisierungs-Tabelle für `risk_band`-Änderungen.
- **Host-Snapshot-Historie.** Wer Process-History will, eigenes Feature mit eigener ADR und DSGVO-Betrachtung.
- **Snapshot-Sammlung für nicht-systemd-Hosts (Alpine/OpenRC).** Block-O `services`-Block ist auf systemd zugeschnitten. OpenRC-Support: andere CLI (`rc-status`).
- **Privatnetz-IP-Klassifikation in der LLM-Phase.** Block O liefert `addr`-Roh-Werte; LLM klassifiziert ggf. „IP gehört zu VPN-Interface — internet-exposed trotz private-Range".
- **Patch-Verfügbarkeit-Alter-Reporting.** Nicht als Engine-Trigger (ADR-0022-Entscheidung), aber als separater Reporting-Tab. Eigener Block.
- **Pre-Triage darf LLM-Outputs überstimmen.** Aktuell läuft Pre-Triage nur auf Findings ohne LLM-Source. Falls neue CVE-Daten (z.B. KEV-Listing nach LLM-Bewertung) ein eindeutigeres Signal liefern als das LLM kannte, könnte Pre-Triage eine „Re-Eval requested"-Flagge setzen, die Block P beim nächsten Pass priorisiert anwendet.
