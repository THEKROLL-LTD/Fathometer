## ADR-0023 — LLM-Risk-Reviewer mit Application-Grouping (Two-Pass) und asynchroner Job-Queue

**Status:** Akzeptiert · **Akzeptiert:** 2026-05-18 · **Datum:** 2026-05-18 · **Bezug:** ADR-0022 (Pre-Triage, Snapshot, Vendor-Severity) wird durch diesen Block **erweitert**, nicht abgelöst — Block O liefert `pending`-Findings und die Datenbasis (Snapshot, severity_by_provider, vendor_status), Block P macht das Group-Layer obendrauf und die finale Risk-Bewertung. ADR-0010 (LLM-Provider-Abstraktion) bleibt unverändert; Block-G-`AsyncOpenAI`-Wrapper wird wiederverwendet. ADR-0014 (Token-Cap Best-Effort) gilt analog für die neuen LLM-Use-Cases. ADR-0003 (Push-not-Pull) unberührt — Worker liest Findings aus der DB, kein Pull vom Agent.

## Kontext

Block O liefert deterministische Pre-Triage und persistiert `pending`-Findings für die der menschliche/maschinelle Profi noch ein Urteil über Server-Exposure abgeben muss. Während Block O in Arbeit war, sind drei Realität-Punkte aufgetaucht, die die ursprüngliche Block-P-Skizze aus ADR-0022 §Re-Open-Trigger zu naiv machen:

1. **Findings sind nicht semantisch unabhängig.** Ein K3s-Cluster-Node hat realistisch 80-150 Trivy-Findings, von denen ~80-90% Library-Findings *innerhalb derselben Bundle-Application* sind — eingebettete Go-Stdlib in k3s-Binaries, containerd-in-k3s, kubelet-in-k3s. Ein Operator der 150 individuelle Findings sieht ist überfordert; die ehrliche Aktion ist „k3s updaten", nicht „150 CVEs einzeln triagieren". Das Per-Finding-LLM-Call-Modell verfehlt die Operator-Realität.

2. **Trivys `fixed_version`-Hinweis lügt für Library-Findings.** Beispiel: Finding meldet „fix in Go-Stdlib 1.24.12", aber der Operator kann nicht die Stdlib in einem k3s-Binary austauschen — er muss auf eine k3s-Release warten die diese Go-Toolchain mit-zieht. Per-Finding-Bewertung erzeugt damit für Library-Findings falsche Erwartungen („Update-Befehl: …"); das einzig ehrliche Output ist „Patch existiert in der Library, Operator muss eigenständig prüfen welche Application-Version den Patch mitbringt".

3. **LLM-Call pro Finding ist sowohl synchron unrealistisch als auch unverhältnismäßig.** Synchron beim Scan-Ingest hätte 30-60s LLM-Latenz, das ist gunicorn-Timeout. Pro Finding wäre außerdem die Token-Math katastrophal — wir würden Server-Kontext und Group-Kontext zigfach wiederholen.

Block P löst alle drei Punkte gleichzeitig: durch eine **Application-Group-Schicht** zwischen Server und Finding, durch einen **deterministischen Pattern-Match plus LLM-Group-Detection** als Pass 1, durch **LLM-Risk-Bewertung auf Group-Ebene** als Pass 2, und durch eine **asynchrone Worker-Queue** statt synchroner Ingest-Path-Integration.

## Entscheidung

Block P führt fünf Bausteine ein:

1. **`application_groups`-Tabelle plus `Finding.application_group_id`** — Group als eigene Entität, mit wiederverwendbaren Match-Patterns. Findings werden nach Owner-Application gruppiert (k3s, openssh-server, etc.).

2. **Zwei-Pass-LLM-Architektur** — Pass 1 detect neue Groups und schreibt Patterns in die Library; Pass 2 bewertet pro Group das Risk-Band mit Server-Kontext. Beide Pässe laufen über die `llm_risk_reviewer`-Service-Klasse, die auf dem Block-G-LLM-Wrapper aufsetzt.

3. **Asynchrone Worker-Queue über `llm_jobs`-Tabelle** — Scan-Ingest queued nur Jobs, ein separater Worker-Container prozessiert sie sequenziell (Default `WORKER_CONCURRENCY=1`). Polling alle 2s mit `SELECT … FOR UPDATE SKIP LOCKED`.

4. **Two-Level-Caching** — Pass-1-Cache *ist* die `application_groups`-Library (Pattern-Match deterministisch). Pass-2-Cache ist die `llm_risk_cache`-Tabelle mit `(group_id, group_findings_fingerprint, cve_data_fingerprint, server_context_fingerprint)`-Key, TTL 30 Tage plus LRU bei > 100K Einträgen.

5. **UI-Redesign auf Group-Karten** mit `evaluating`-State während Worker arbeitet, und Feature-Flag `BLOCK_P_LLM_MODE ∈ {off, observation, live}` für stufenweise Inbetriebnahme.

### Risk-Band-Modell bleibt unverändert

Die sieben Bänder aus ADR-0022 (`escalate`/`act`/`mitigate`/`pending`/`unknown`/`monitor`/`noise`) bleiben unverändert. Block P füllt zusätzlich die finalen Bands `escalate`/`act`/`mitigate` und kann zu `monitor`/`noise` demoten. `risk_band_source` wechselt von `engine` zu `llm`.

**Neue Semantik:** das Band wird primär auf der `application_group` gesetzt, nicht auf dem einzelnen `Finding`. Findings erben den Band ihrer Group nach Worst-Case-Logik (`Finding.risk_band = max_band_in_group`). Bei Cross-Server-Reuse identischer Groups erben hunderte Finding-Rows den Band aus einem einzigen LLM-Call.

### Pass 1 — Group-Detection

**Input** pro Call: Liste von Findings minimal beschrieben (keine CVE-Details, kein Server-Kontext):

```
finding_id  package_name  target_path                              package_purl                          result_type
12345       stdlib        /var/lib/rancher/k3s/agent/.../snapshotter pkg:golang/stdlib@1.23.5             gobinary
12346       stdlib        /var/lib/rancher/k3s/data/.../k3s-server   pkg:golang/stdlib@1.23.5             gobinary
12347       openssh-server  -                                        pkg:deb/ubuntu/openssh-server@9.0p1  -
...
```

**System-Prompt** (Inhalts-Skizze, finale Formulierung in der Implementierung):

```
Du gruppierst Vulnerability-Findings auf einem Linux-Host nach
Owner-Application. Eine Owner-Application ist die Software die der
Operator als Einheit installiert/updated (z.B. "k3s", "openssh-server",
"grafana"). Sub-Komponenten die mit der Owner-Application kommen
(containerd in k3s, coredns in k3s, kubelet in k3s) gehören in die
Owner-Group, NICHT in eigene Sub-Groups.

WICHTIG für die Group-Labels:
- Wähle Namen so generisch wie möglich, damit Pfad-Änderungen bei
  minor/patch-Updates derselben Application weiter matchen. Beispiel:
  "k3s", nicht "k3s-1.23". 
- Verschiedene Major-Produkte sind verschiedene Groups: RKE und RKE2 ja,
  k3s und rke2 ja. Sub-Komponenten einer Application bleiben in derselben
  Group: kein "k3s-containerd", "k3s-coredns".
- Distro-OS-Pakete bekommen ihren package_name als Group-Label (z.B.
  "openssh-server", "openssl"), kein Sub-Splitting.

Liefere für jede Group:
- label (kurz, kleinbuchstaben, max 64 chars)
- explanation (max 256 chars, was die Group ist)
- match_rules: path_prefixes[], pkg_name_exact[], pkg_name_glob[],
  pkg_purl_pattern[] — so dass zukünftige ähnliche Findings ohne
  weiteren LLM-Call automatisch zugeordnet werden können
- finding_ids: Liste der zugeordneten IDs aus dem Input

Antworte ausschließlich mit gültigem JSON nach dem Schema unten.
```

**Output-Schema:**

```json
{
  "groups": [
    {
      "label": "k3s",
      "explanation": "Rancher K3s. Eingebettete Bundle mit Go-Stdlib, containerd, runc, kubelet, cni-plugins.",
      "match_rules": {
        "path_prefixes": ["/var/lib/rancher/k3s/", "/usr/local/bin/k3s"],
        "pkg_name_exact": ["k3s"],
        "pkg_name_glob": ["k3s-*"],
        "pkg_purl_pattern": []
      },
      "finding_ids": [12345, 12346, ..., 12432]
    },
    {
      "label": "openssh-server",
      "explanation": "OS distro package OpenSSH server.",
      "match_rules": {
        "path_prefixes": [],
        "pkg_name_exact": ["openssh-server"],
        "pkg_name_glob": [],
        "pkg_purl_pattern": []
      },
      "finding_ids": [12347, 12348, 12349]
    }
  ],
  "ungrouped": []
}
```

**Backend-Validierung:**

- Jedes `finding_id` im Output muss im Input enthalten gewesen sein (sonst Halluzination, droppen).
- Jedes Finding aus dem Input muss in genau einer Group oder in `ungrouped` landen (Backend prüft Vollständigkeit; bei Lücken: Retry-mit-Hint „du hast IDs vergessen: …").
- `label` muss regex `^[a-z0-9][a-z0-9._-]{0,63}$` matchen.
- Bei `ungrouped`-Findings: Backend behält `application_group_id = NULL`, Findings bleiben in der Per-Finding-Anzeige bis ein späterer Pass-1-Call sie greift.

**Pattern-Persistierung:** Backend führt für jede Group im Output:

- Falls Group mit identischem Label schon existiert → match_rules **mergen** (path_prefixes union, pkg_name_exact union, …). Keine Duplikate.
- Sonst → neue Row in `application_groups`.

Anschließend: für *alle* Findings (nicht nur die im Pass-1-Input, sondern auch existierende mit `application_group_id IS NULL`) wird der deterministische Pattern-Match neu durchgeführt. Damit wird die neu gelernte k3s-Pattern auch für später hinzukommende Findings automatisch angewendet.

### Pattern-Match-Logik (deterministisch, Python-side)

Reihenfolge pro Finding:

1. **`path_prefixes`** — längster Prefix-Match gewinnt. Findet `/var/lib/rancher/k3s/agent/containerd/...` → Group `k3s` weil der k3s-Prefix länger trifft als ein hypothetischer containerd-Prefix.
2. Wenn kein Path-Match: **`pkg_name_exact`** → exakter Match auf `Finding.package_name` (für lang-pkgs das Basis-Paket ohne `@target`-Suffix).
3. Wenn kein Exact-Match: **`pkg_name_glob`** → glob-Match (z.B. `k3s-*`).
4. Wenn kein Glob-Match: **`pkg_purl_pattern`** → simpler Prefix-Match auf `package_purl`.
5. Wenn nichts greift: `application_group_id` bleibt NULL → Kandidat für nächsten Pass-1-Call.

`app/services/group_matcher.py` implementiert das mit eager-loaded Library-Cache (Singleton beim App-Start, refresh bei `application_groups`-Insert).

### Pass 2 — Risk-Bewertung pro Group

**Input** pro Call: Server-Kontext (kompakt, ~2-4K Tokens, siehe ADR-0022 §Host-Snapshot) plus eine Liste von Groups (1-3 pro Batch typischerweise):

```
host_context:
  os: Ubuntu 24.04 LTS
  tags: prod, internet-exposed, k8s-master
  listeners (proto/addr:port → process):
    tcp 0.0.0.0:22       sshd
    tcp 0.0.0.0:443      nginx
    tcp 0.0.0.0:6443     kube-apiserver
    ...
  kernel_modules: ext4, nf_conntrack, br_netfilter, overlay, bridge, ...
  active_services: nginx, postgresql, sshd, kubelet, containerd, ...
  process_commands (unique): sshd, nginx, postgres, kubelet, ...
  notable_processes:
    /usr/local/bin/k3s server --cluster-init
    /usr/bin/java -jar /opt/jenkins/jenkins.war

groups_to_evaluate:
  group: k3s
    explanation: "Rancher K3s. Eingebettete Bundle mit Go-Stdlib, ..."
    findings_in_group (87 total, compact summary):
      CVE-2025-61728 stdlib/archive/zip CVSS 7.5 ubuntu=high nvd=high
      CVE-2024-XXXXX stdlib/crypto/tls CVSS 9.1 ubuntu=critical nvd=critical kev=yes(2024-08-15)
      CVE-2025-61726 stdlib/net/http   CVSS 8.1 ubuntu=high  epss=0.12
      ... (84 more, same package_purl pattern)
    vendor_status_summary: all "affected", no will_not_fix
    has_fix_summary: 87/87 have fix in Go ≥ 1.24.12 (transitive)
    worst_finding_id_hint: 99001 (the KEV-listed one)

  group: openssh-server
    ...
```

**System-Prompt** (Inhalts-Skizze):

```
Du bist ein erfahrener IT-Sicherheits-Analyst. Du bewertest pro
Application-Group das Risiko auf einem konkreten Host.

Bewerte jede Group in eines von fünf Risikobändern:
- escalate: KEV-gelistet und Application ist auf diesem Host aktiv
  und/oder erreichbar (oder: kritisch ohne Patch-Pfad)
- act: Application aktiv/erreichbar, Patch verfügbar oder erwartbar
  (Operator soll updaten)
- mitigate: Application aktiv/erreichbar, KEIN Patch verfügbar oder
  will_not_fix (Operator muss anders eindämmen)
- monitor: Application nicht klar aktiv ODER ohne klare Exposure,
  beobachten
- noise: Application erkennbar nicht aktiv (z.B. kein Bluetooth-Modul
  geladen, kein bluetoothd-Prozess)

WICHTIG für den Reason-Text:
- Sage NICHT konkret welche Application-Version den Patch mitbringt.
  Beispiel verboten: "Update auf k3s ≥ v1.30.4-rc1". Du kannst nicht
  zuverlässig wissen welche k3s-Release welche Go-Toolchain mitzieht.
- Stattdessen formuliere ehrlich: "Patch in der zugrundeliegenden
  Library verfügbar — Operator muss prüfen welche k3s-Release diese
  Library-Version enthält oder Mitigation einsetzen."
- Bei OS-Distro-Paketen (openssh-server, openssl, etc.) kannst du
  sagen "Patch verfügbar im Distro-Repository" oder "Vendor markiert
  als will-not-fix", aber KEIN konkreter Befehl wie "apt-get install".
- Reason max 256 chars.

Liefere pro Group: risk_band, worst_finding_id, reason.
```

**Output-Schema:**

```json
{
  "evaluations": [
    {
      "group_label": "k3s",
      "risk_band": "escalate",
      "worst_finding_id": 99001,
      "reason": "K3s embeddet verwundbare Go-Stdlib (87 CVEs); CVE-2024-XXXXX KEV-gelistet seit 2024-08-15, dominiert Bewertung. Patch ist in Go ≥1.24.12 — Operator muss prüfen welche k3s-Release das mitzieht oder anders mitigieren."
    },
    {
      "group_label": "openssh-server",
      "risk_band": "act",
      "worst_finding_id": 12347,
      "reason": "sshd lauscht auf 0.0.0.0:22 (Tag: internet-exposed). Patch verfügbar im Distro-Repository."
    }
  ]
}
```

**Backend-Validierung:**

- `group_label` muss in der Input-Liste vorkommen (sonst halluziniert, droppen).
- `risk_band` muss `{escalate, act, mitigate, monitor, noise}` sein. **`pending` und `unknown` sind verboten** als LLM-Output — diese sind reine Pre-Triage-Werte.
- `worst_finding_id` muss zur Group gehören (im Cache-Group-Findings-Set sein).
- `reason` max 256 chars, NUL-frei.
- Fehlende `group_label`s aus Input → Retry für die fehlenden Groups (max 2 Retries, dann bleiben Groups in `pending` mit Audit `risk.llm_group_skipped`).

### Asynchroner Worker via `llm_jobs`-Tabelle

Schema:

```
llm_jobs
  id              bigserial PK
  job_type        enum('group_detection', 'risk_evaluation')
  server_id       FK servers.id ON DELETE CASCADE
  payload         jsonb         -- {finding_ids: [...]} oder
                                -- {group_id: ..., server_context_fp: ...}
  depends_on      bigint NULL FK llm_jobs.id ON DELETE SET NULL
  status          varchar(16)   -- 'queued'|'in_progress'|'done'|'failed'
  attempts        int default 0
  next_attempt_at timestamp tz NOT NULL DEFAULT now()
  picked_up_by    text NULL     -- Worker-ID (hostname:pid) für Stale-Detection
  picked_up_at    timestamp tz NULL
  result          jsonb NULL    -- LLM-Output oder {would_call: true, ...} im Observation-Mode
  error           text NULL
  created_at      timestamp tz NOT NULL DEFAULT now()
  completed_at    timestamp tz NULL

Indizes:
  ix_llm_jobs_pickup   (status, next_attempt_at) WHERE status = 'queued'
  ix_llm_jobs_stale    (status, picked_up_at) WHERE status = 'in_progress'
  ix_llm_jobs_server   (server_id, status)
```

**Worker-Loop** (`app/workers/llm_worker.py`):

```python
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"
POLL_INTERVAL = 2.0  # seconds

while not shutdown_requested:
    job = pick_next_job()  # SELECT FOR UPDATE SKIP LOCKED, mit depends_on-Check
    if job is None:
        run_stale_reaper_if_due()
        time.sleep(POLL_INTERVAL)
        continue

    if settings.BLOCK_P_LLM_MODE == "observation":
        result = {"would_call": True, "estimated_tokens": estimate_tokens(job)}
        mark_done(job, result)
        continue

    try:
        with token_budget_check():
            result = process_job(job)  # echter LLM-Call
        mark_done(job, result)
    except LLMTimeoutError:
        requeue_with_backoff(job)
    except LLMInvalidResponseError as e:
        if job.attempts >= MAX_ATTEMPTS:
            mark_failed(job, str(e))
        else:
            requeue_with_backoff(job)
```

**Pickup-Query:**

```sql
WITH job AS (
  SELECT id FROM llm_jobs
  WHERE status = 'queued'
    AND next_attempt_at <= now()
    AND (
      depends_on IS NULL
      OR depends_on IN (SELECT id FROM llm_jobs WHERE status = 'done')
    )
  ORDER BY created_at
  LIMIT 1
  FOR UPDATE SKIP LOCKED
)
UPDATE llm_jobs SET
  status = 'in_progress',
  picked_up_by = $1,
  picked_up_at = now(),
  attempts = attempts + 1
WHERE id IN (SELECT id FROM job)
RETURNING *;
```

`FOR UPDATE SKIP LOCKED` macht das concurrency-safe ohne Application-Lock; falls Operator irgendwann auf `WORKER_CONCURRENCY=4` skaliert, funktioniert dasselbe Schema ohne Code-Änderung.

**Stale-Reaper** (läuft alle 60s im selben Worker-Prozess als Sub-Tick):

```sql
-- Stale in_progress jobs zurück in die Queue mit backoff
UPDATE llm_jobs
SET status = 'queued',
    picked_up_by = NULL,
    picked_up_at = NULL,
    next_attempt_at = now() + (attempts * interval '1 minute')
WHERE status = 'in_progress'
  AND picked_up_at < now() - interval '10 minutes'
  AND attempts < 3;

-- Nach 3 Stale-Attempts: failed
UPDATE llm_jobs
SET status = 'failed', error = 'max attempts after stale'
WHERE status = 'in_progress'
  AND picked_up_at < now() - interval '10 minutes'
  AND attempts >= 3;
```

### Deployment

**Neuer Container** `secscan-llm-worker` im `docker-compose.yml`. Gleiches Image wie der Web-Container, anderer Entrypoint (`python -m app.workers.llm_worker`). Eigene Healthcheck-Variante: Worker schreibt einen Liveness-Heartbeat in eine Settings-Tabelle, Healthcheck prüft Alter < 30s.

ENV-Variablen:

- `WORKER_CONCURRENCY` (default `1`) — wieviele parallele Job-Loops im Worker-Prozess.
- `BLOCK_P_LLM_MODE` (`off` | `observation` | `live`, default `off` direkt nach Deploy).
- `WORKER_POLL_INTERVAL_SEC` (default `2`).
- `WORKER_STALE_TIMEOUT_MIN` (default `10`).
- `LLM_TOKEN_BUDGET_DAILY` (default `1000000` — 1M Tokens/Tag, dann pausiert Worker bis Mitternacht UTC).

`BLOCK_P_LLM_MODE` ist zusätzlich über die Settings-UI änderbar (mit `master_key`-Bestätigung) — siehe UI-Section. Audit-Event `llm.mode_changed` bei jedem Wechsel.

### Caching auf zwei Ebenen

**Pass-1-Cache = `application_groups`-Library.** Pattern-Match deterministisch im Backend, kein expliziter Cache-Lookup nötig. Library wird über Zeit befüllt durch Pass-1-LLM-Calls, danach stabil. Re-Open-Trigger falls Library nach längerer Zeit drift-Probleme zeigt (manueller Re-Detect-Trigger).

**Pass-2-Cache = `llm_risk_cache`-Tabelle.**

```
llm_risk_cache
  cache_key               char(64) PRIMARY KEY  -- SHA256-hex
  group_id                FK application_groups.id
  group_findings_fp       char(16)               -- inspectable
  cve_data_fp             char(16)               -- inspectable
  server_context_fp       char(16)               -- inspectable
  risk_band               varchar(16)
  worst_finding_id        bigint                 -- aus den Group-Findings
  reason                  text
  llm_model               varchar(64)            -- z.B. "deepseek-v3-0728"
  computed_at             timestamp tz
  used_count              int default 1
  last_used_at            timestamp tz

Indizes:
  ix_llm_risk_cache_lru   (last_used_at)
  ix_llm_risk_cache_group (group_id)
```

**Fingerprint-Definitionen** (alle SHA256-hex auf 16 chars trimmt für Inspection-Zwecke; cache_key ist voller 64-char-Hash über die vier inputs):

- `group_findings_fingerprint` = SHA256 über die sortierte Tupel-Liste `(cve_id, package_purl)` aller Findings in der Group. Ändert sich genau dann wenn ein neues CVE in die Group kommt oder eines resolved wird.
- `cve_data_fingerprint` = SHA256 über die sortierte Tupel-Liste `(cve_id, severity, severity_by_provider_hash, epss_score, is_kev, vendor_status)` der enthaltenen Findings.
- `server_context_fingerprint` = SHA256 über die kanonisch-serialisierten Snapshot-Felder: `(os_family, os_version, sorted(tags), sorted_listeners, sorted_unique_comm, sorted_kernel_modules, sorted_services, sorted_gaps)`. **PIDs, args, snapshot_at, user-Feld der Prozesse fließen NICHT ein.**

**Cache-Lookup-Logik** im Pass-2-Job-Handler:

```python
cache_key = sha256(group.id, group_findings_fp, cve_data_fp, server_context_fp)
hit = session.query(LLMRiskCache).filter_by(cache_key=cache_key).first()
if hit and (now() - hit.computed_at) < TTL:
    apply_cached_result_to_findings(hit, group)
    hit.used_count += 1
    hit.last_used_at = now()
    return

# Cache miss → echter LLM-Call
result = llm_pass2(server_context, group)
session.add(LLMRiskCache(cache_key=cache_key, ...))
apply_result_to_findings(result, group)
```

**Eviction:**

- TTL 30 Tage: Read-side, kein aktives Löschen. Cache-Eintrag älter als 30 Tage gilt als invalid und triggert neuen Call.
- LRU: Hintergrund-Job (täglich, im Worker-Prozess als Sub-Tick) löscht älteste `last_used_at` wenn Tabelle > 100K Einträge hat.

**Cross-Server-Reuse:** Cache-Eintrag wird auf *alle* Findings angewendet die zur Group gehören und denselben Server-Context-Fingerprint haben. Bei 8 identischen RKE2-Nodes mit derselben k3s-Group bedient ein Cache-Eintrag 8 × Group-Findings-Rows.

### Mixed-Band-Aggregation auf Group-Ebene

LLM bekommt in Pass 2 pro Group die enthaltenen Findings mit ihren Severity-/EPSS-/KEV-Hints und urteilt nach Worst-Case-Logik. Backend setzt:

- `application_groups.risk_band` = LLM-Output
- `application_groups.worst_finding_id` = LLM-Output (validiert auf Zugehörigkeit zur Group)
- `application_groups.risk_band_reason` = LLM-Output
- `application_groups.risk_band_source` = `llm`
- `application_groups.risk_band_computed_at` = now()

**Vererbung auf Findings:** alle Findings mit dieser `application_group_id` bekommen denselben `risk_band` und `risk_band_source=llm`. Die individuelle `risk_band_reason` pro Finding wird leer gelassen (oder zeigt einen Verweis-String `"see group {label}"`); die eigentliche Begründung lebt auf der Group.

UI-Default: Findings zeigen den Group-Band, nicht ihre Pre-Triage-Pre-Band. Drill-down ins Finding-Detail zeigt zusätzlich CVE-spezifische Pre-Triage-Daten (Severity, EPSS, KEV).

### UI-Konsequenzen

**Server-Detail-View (`servers/detail.html`):**

- Findings-Tabelle gruppiert primär nach `application_group`, default-collapsed außer `escalate`/`act`/`mitigate`-Groups die default-expanded sind.
- Pro Group eine Card mit:
  - Group-Label (z.B. „k3s"), Finding-Count, Risk-Band-Pill
  - `risk_band_reason` als Mono-Font-Block
  - Worst-Finding als hervorgehobener Eintrag direkt unter der Card-Header
  - Expandable Liste aller Findings der Group (heutiges Block-K-Tabellen-Markup wiederverwendet)
- **`evaluating`-State:** Group existiert (Pass 1 durch), aber `risk_band IS NULL` → graue Card mit Spinner-Icon, Text „Evaluating risk for N findings, this may take a few minutes...". Block-L-Polling sorgt für graduelle Auflösung.
- **Findings ohne `application_group_id`:** bleiben in einer „Pending grouping"-Sektion am Ende der Tabelle, eigene flache Liste. Verschwindet sobald Pass 1 für diese Findings durch ist.

**Dashboard (`dashboard/_detail_pane.html`):**

- KPI-Reihe aus Block O bleibt strukturell (Action needed / Safe Cards plus Risk-Band-Pills).
- Findings-Tabelle bekommt eine zusätzliche `Group`-Spalte (sortierbar, filterbar).
- Filter-Bar bekommt einen `application_group`-Select neben den bestehenden Filtern.
- Bulk-Ack-noise-Workflow aus Block O bleibt — wirkt jetzt auf Group-Findings, der Server-Side-Filter `risk_band="noise"` greift weiterhin pro Finding (nicht pro Group), damit auch einzelne `noise`-Findings innerhalb einer ansonsten-`act`-Group ack-bar sind.

**Settings-Seite — neuer Tab „LLM Risk Reviewer":**

- Anzeige `BLOCK_P_LLM_MODE` mit Wechsel-Button (`master_key`-Bestätigung).
- Übersichts-Stats:
  - Queue: N queued, M in_progress, X done (letzte 24h), Y failed (letzte 24h)
  - Library: N application_groups, jeweils mit `used_count` und `detected_at`
  - Cache: M entries, Hit-Rate letzte 7 Tage
  - Token-Budget heute: verbraucht / total
- Bei `observation`-Mode zusätzlich:
  - „Would have called LLM: N times in last 24h, estimated cost: $X"
- Audit-Log-Quick-Link für `llm.*`-Events.

### Feature-Flag und Mode-Wechsel

`BLOCK_P_LLM_MODE` Werte und Verhalten:

- **`off`** — keine `llm_jobs`-Inserts beim Ingest. Library und Cache-Tabellen bleiben leer (oder erhalten Stand). Pattern-Match läuft, aber matched gegen leere Library → alle pending-Findings bleiben ungrouped. UI zeigt „LLM evaluation disabled" im Settings-Tab.

- **`observation`** — Jobs werden erzeugt. Worker holt sie aber führt nur Mock-Process aus: schreibt `result = {"would_call": true, "estimated_input_tokens": ..., "estimated_output_tokens": ..., "estimated_cost_usd": ...}`. `mark_done(job, result)` läuft normal. Pass-2-Jobs evaluieren cache-key trotzdem und schreiben `would-call`-Marker auch dann nicht wenn der Cache hit wäre — damit der Operator die echte Call-Frequenz sieht. UI zeigt im Settings-Tab die `would_call`-Summen.

- **`live`** — Echter LLM-Call. Bei Wechsel von `observation` → `live`:
  - `would-call`-Jobs (status=`done` mit `result.would_call=true`) werden NICHT automatisch re-queued. Begründung: das Backlog kann groß sein und Operator soll bewusst starten. Stattdessen ein Settings-Button „Re-queue would-call backlog (N jobs)" der `status` zurück auf `queued` setzt und `attempts` zurück auf 0.
  - Neue Jobs ab Mode-Wechsel laufen direkt live.

Audit-Event `llm.mode_changed` mit `{from, to, by, queued_backlog_count}` bei jedem Wechsel.

### Token-Budget

Eine Hard-Grenze pro Tag (default `LLM_TOKEN_BUDGET_DAILY=1000000`, also 1M Tokens). Worker hat ein Counter in einer Settings-Tabelle. Bei Erreichen:

- Worker pausiert: kein Pickup neuer Jobs, Settings-Tab zeigt „Token budget exhausted, resumes at 00:00 UTC".
- Audit-Event `llm.budget_exhausted`.
- Reset um 00:00 UTC.

Pro Job wird der tatsächliche Token-Verbrauch aus dem Provider-Response gemessen (analog Block-G-Pattern) und gegen das Budget verrechnet. Im Observation-Mode wird der `estimated_tokens`-Wert gegen das Budget verrechnet (damit Observation-Phase realistische Last simuliert).

## Begründung

**Warum Application-Groups statt Per-Finding.** Operator-Realität (Cowork-Konsultation 2026-05-18): bei einem K3s-Node sind ~85% der Findings semantisch ein einziges Thema („k3s shippt verwundbare Go-Stdlib"), und der Update-Pfad ist Cluster-Operations-Realität („update k3s-Release"), nicht Per-CVE. Per-Finding-UI ist nicht-handhabbar bei realistischen Flotten-Größen.

**Warum LLM für Group-Detection statt JSON-Asset.** Statisches Mapping wäre eine never-ending Pflegearbeit (jede neue Distro-Variante, jede neue Container-Lösung, jedes neue Hersteller-Bundle). LLM macht das einmal pro neue Software-Identität auf der Flotte, danach matched der deterministische Pattern-Cache. Cost konvergiert gegen Null nach Library-Stabilisierung.

**Warum Two-Pass statt Ein-Call.** Pass 1 braucht keinen Server-Kontext und keine CVE-Details — nur Identität (Pfad + Paketname). Pass 2 braucht Server-Kontext aber kein Pattern-Wissen. Trennung erlaubt:

- Pass-1-Output (Group-Library) wird flotten-weit geteilt — eine Pass-1-Antwort hilft allen Servern mit ähnlichem Software-Stack.
- Pass-2-Caching ist sauberer weil der Cache-Key nicht mit Pattern-Drift verschmutzt wird.
- Halluzinations-Risiko sinkt weil pro Call weniger semantische Achsen.

**Warum kein Spec-Wissen über Application-Versionen im Reason-Text.** Das LLM kann nicht zuverlässig wissen welche k3s-Release welche Go-Toolchain-Version mitzieht — das ist Vendor-spezifisches Release-Engineering, und LLM-Training-Daten sind aktuell genug für „existiert Go 1.24.12" aber nicht für „ist es in k3s v1.30.4-rc1 enthalten". Falsches LLM-Versions-Statement würde den Operator zu einem Update führen, das das Problem nicht löst. Reason bleibt ehrlich-deskriptiv: „Patch existiert in der Library, Operator-Eigenprüfung erforderlich".

**Warum kein konkreter Update-Befehl für os-pkgs entweder.** Konsistent mit der bewussten Out-of-Scope-Entscheidung aus ADR-0021 / Block N: Update-Befehl-Mapping ist eigene spätere ADR. Block-P-Reason bleibt deskriptiv („Patch verfügbar im Distro-Repository") ohne Cmd-Snippet.

**Warum asynchroner Worker statt synchron im Ingest.** Latenz: pro Scan vermutlich 30-90s LLM-Latenz bei realistischer Group-Anzahl. Synchron würde gunicorn-Timeout treffen, Agent-Retry-Loop verursachen, falsche „Scan failed"-Signale produzieren. Worker entkoppelt: Scan-Ingest-HTTP ist in < 1s durch (Pre-Triage + Pattern-Match), Worker arbeitet im Hintergrund, UI füllt sich graduell auf.

**Warum Postgres-Queue statt Redis/RabbitMQ.** Wir haben Postgres ohnehin (ADR-0001 etc.). `SELECT FOR UPDATE SKIP LOCKED` ist concurrency-safe. Eine zusätzliche Job-Queue-Infrastruktur wäre Setup-Last für Operator (Container, Config, Backup-Strategie). Skalierungs-Pfad nach oben (Redis/Celery) ist offen falls Last steigt — aktuelles Pattern kompatibel.

**Warum Polling statt LISTEN/NOTIFY.** 2s-Polling-Latenz ist gegenüber 30-90s LLM-Calls irrelevant. LISTEN/NOTIFY wäre konzeptuell hübscher, bringt aber Connection-Lifecycle-Code (Reconnect-Logik, Heartbeat) und schwer testbare Edge-Cases. Polling ist trivial in jeder Test-Umgebung.

**Warum separater Worker-Container.** Lifecycle-Trennung: Web-Server-Restart killt nicht den Worker und vice versa. Healthcheck-Klarheit: zwei Containers mit zwei Status. Scaling-Möglichkeit: Operator kann `secscan-llm-worker` separat von `secscan-web` skalieren wenn Last das verlangt. Image-Größe-Overhead null (gleiches Image, anderer Entrypoint).

**Warum drei Mode-Werte (off/observation/live) statt zwei (off/live).** Observation-Mode ist der Schlüssel zur risikoarmen Inbetriebnahme: Operator sieht die echte Job-Volumen-Math (welche Group-Häufigkeit, wie viele Cache-Misses pro Tag, geschätzte Tokens) bevor das Geld-fressende `live` aktiviert wird. Out-of-the-Box-Default `off` weil viele Operatoren erstmal Block O ohne LLM betreiben wollen — Block P scharf zu schalten ist eine bewusste Operator-Entscheidung mit Cost-Verantwortung.

**Warum Worst-Case-Band für Mixed-Band-Groups.** Ein einzelnes KEV-Finding in einer ansonsten-act-Group muss den Operator alarmieren — er muss ja ohnehin die ganze Group updaten (Update-Pfad ist einer für alle 87 Findings). Worst-Case-Band ist die ehrliche Aussage „die schlimmste enthaltene Vulnerability dominiert die Aktion". Drill-down zeigt dem interessierten Operator welches Finding der Treiber war.

**Warum keine Hint-Übergabe an Pass 1 von bestehenden Groups.** User-Aussage 2026-05-18: würde ausarten, könnte das LLM zu Sub-Splitting verleiten („k3s-containerd" als Sub-Group neben „k3s"). Statt dessen klare Anti-Drift-Anweisung im System-Prompt („generische Labels, Sub-Komponenten gehören in Owner-Group"). Falls trotzdem Drift auftritt (Rancher-Pfad-Renaming bei major-update): Pattern-Match misst → neuer Pass-1-Call → neue Patterns werden zu existing Group hinzugefügt (Backend merged auf Label-Identität).

Alternativen verworfen:

- **Per-Finding-LLM-Call.** Token-Cost katastrophal (~50× mehr als Group-Modell), Operator-UX katastrophal (100+ Per-Finding-Bewertungen statt 5-10 Group-Cards).
- **Redis/Celery für Job-Queue.** Operator-Setup-Last, Backup-Risiko, kein erkennbarer Vorteil gegenüber Postgres-Queue bei aktuellen Latenzen.
- **JSON-Asset für Application-Mapping.** Pflege-Albtraum, never-ending Story für jede neue Software-Identität.
- **Synchroner LLM-Aufruf im Ingest mit Streaming-Response an Agent.** Agent-HTTP-Lifecycle würde an LLM-Latenz hängen, jede LLM-Provider-Störung wäre Scan-Failure. Entkopplung ist Pflicht.
- **Ein Mega-LLM-Call der gleichzeitig Group-Detection und Risk-Bewertung macht.** Mehr Halluzinations-Risiko (mehr semantische Achsen in einem Call), schlechtere Cache-Granularität (Group-Detection und Risk-Bewertung haben unterschiedliche Invalidierungs-Trigger).

## Konsequenzen

**Code (neu):**

- `app/services/llm_risk_reviewer.py` — Service-Klasse mit `pass1_detect_groups()` und `pass2_evaluate_group()`. Setzt auf Block-G-LLM-Wrapper (`AsyncOpenAI`).
- `app/services/group_matcher.py` — Pattern-Match-Logik (deterministisch, Python-side, Library-Cache als Singleton).
- `app/services/llm_cache.py` — Cache-Lookup + Insert + LRU-Helper.
- `app/services/llm_fingerprints.py` — Hash-Funktionen für die drei Fingerprints.
- `app/workers/llm_worker.py` — Worker-Hauptschleife mit Pickup, Job-Dispatch, Stale-Reaper, Token-Budget-Check.
- `app/workers/__init__.py` und Entrypoint für `python -m app.workers.llm_worker`.
- `app/models.py` neue Klassen: `ApplicationGroup`, `LLMJob`, `LLMRiskCache`. Bestehende `Finding`-Klasse um `application_group_id`-FK erweitert.
- `app/templates/_partials/application_group_card.html` — Group-Card-Render.
- `app/templates/_partials/group_evaluating_card.html` — Spinner-Variante.
- `app/templates/settings/llm_reviewer.html` — neuer Settings-Tab.
- `app/views/settings.py` — neue Route `/settings/llm-reviewer` mit Mode-Wechsel-Action.
- `app/views/server_detail.py` — Findings-Render umgestellt auf Group-First.

**Code (geändert):**

- `app/api/scans.py` — nach Pre-Triage zusätzlich: Pattern-Match gegen Library, ungroupierte Findings → `group_detection`-Job in `llm_jobs` queuen, vorhandene Groups mit veraltetem `group_findings_fp` → `risk_evaluation`-Job queuen.
- `app/schemas/dashboard_filter.py` und `app/schemas/findings_view_filter.py` — neuer Filter `application_group_id`.
- `app/services/findings_query.py` — Group-Filter, Group-Sort.
- `app/templates/dashboard/_findings_section.html`, `_findings_filter_bar.html` — Group-Spalte und -Filter.
- `app/templates/servers/_findings_section.html` und `servers/detail.html` — Group-Card-Layout.
- `app/templates/base_app.html` — Settings-Sidebar bekommt „LLM Reviewer" Eintrag.
- `app/config.py` — neue Settings-Konstanten (`BLOCK_P_LLM_MODE`, `WORKER_*`, `LLM_TOKEN_BUDGET_DAILY`, `LLM_CACHE_TTL_DAYS`, `LLM_CACHE_MAX_ROWS`).
- `app/__init__.py` — Worker-Liveness-Endpoint `/internal/llm-worker-health` (intern, Healthcheck-only).
- `docker-compose.yml` — neuer Service `secscan-llm-worker` mit gleichem Image, Entrypoint `python -m app.workers.llm_worker`, Healthcheck, eigenen ENV-Vars.
- `Dockerfile` — kein Change (gleiches Image bedient beide Entrypoints).
- `ARCHITECTURE.md §6` — Envelope-Änderungen aus Block O bleiben, plus Hinweis dass Findings-Group-Bewertung asynchron im Backend nach Scan-Ingest passiert.
- `ARCHITECTURE.md §7` — Dashboard-Layout aktualisieren um Group-Spalte.
- `ARCHITECTURE.md §11` — kein Change (Agent unverändert in Block P).
- `ARCHITECTURE.md §12` — LLM-Integration-Sektion erweitern um Risk-Reviewer-Use-Case neben dem bestehenden Chat.
- `ARCHITECTURE.md §17` — Out-of-Scope ergänzen: Update-Befehl-Mapping bleibt out-of-scope; spezifische Versions-Empfehlung von LLM bleibt out-of-scope.

**Migration:**

- Eine neue Alembic-Migration `XXXX_block_p_llm_groups_jobs_cache.py`:
  - `create_table` für `application_groups`, `llm_jobs`, `llm_risk_cache`.
  - `add_column` für `findings.application_group_id` plus FK-Constraint mit `ON DELETE SET NULL`.
  - Indizes wie oben dokumentiert.
  - Settings-Tabelle (falls noch nicht da als generisches Key-Value) bekommt Einträge für Worker-Liveness-Heartbeat und Token-Counter.
  - Downgrade: spiegelbildlich.

**Tests:**

- `tests/services/test_group_matcher.py` — Pattern-Match-Logik mit allen vier Match-Reihenfolgen, Edge-Cases (kein Match, mehrere Matches längster-Prefix-gewinnt, Glob-Match).
- `tests/services/test_llm_fingerprints.py` — Fingerprint-Stabilität (gleicher Input → gleicher Hash, anders sortierter Input → gleicher Hash, PID-Änderung → gleicher Hash).
- `tests/services/test_llm_cache.py` — Cache-Hit, Cache-Miss, TTL-Verfall, LRU-Eviction.
- `tests/services/test_llm_risk_reviewer.py` — Mocks für LLM-Aufruf, Validierung der Pass-1- und Pass-2-Output-Parsing (Halluzinations-Reject, fehlende IDs, ungültige Bands).
- `tests/workers/test_llm_worker.py` — Job-Pickup (SKIP LOCKED), Dependency-Check (Pass 2 wartet auf Pass 1), Stale-Reaper, Mode-Wechsel-Verhalten, Token-Budget-Exhaustion.
- `tests/api/test_scans_block_p_job_queueing.py` — Scan-Ingest queued korrekt Jobs, kein Doppelqueueing bei Re-Ingest derselben Group, Dependencies werden gesetzt.
- `tests/views/test_settings_llm_reviewer.py` — Mode-Wechsel-UI, Stats-Rendering, Re-queue-Backlog-Action.
- `tests/views/test_server_detail_groups.py` — Group-Card-Rendering, evaluating-State, Drill-down, Group-mit-mehreren-Findings vs. Single-Finding-Group.
- `tests/integration/test_block_p_e2e_observation.py` — End-to-End mit gemocktem LLM: Scan ingest → Jobs queued → Worker pickt → Mode=observation produziert would-call-Marker → Settings-Stats korrekt.
- `tests/integration/test_block_p_e2e_live.py` — wie oben aber Mode=live mit mock-LLM-Response, vollständiger Lifecycle bis `Finding.risk_band` gesetzt.
- Adversarial: Pass-1 mit halluzinierten finding_ids, Pass-2 mit halluzinierten group_labels, Worker mit corrupted job-payloads, Cache-Key-Collision-Test, Race-Condition zwei Worker auf demselben Job.

Erwartete Test-Anzahl: ~120 neue.

**Performance:**

- Pickup-Query mit `SELECT FOR UPDATE SKIP LOCKED` bei 100K queued jobs: < 5ms (Index auf status+next_attempt_at).
- Pattern-Match pro Finding mit Library < 10K Einträge: < 1ms (in-memory dict-Lookup nach Pre-Index).
- Cache-Lookup-Query: < 5ms (PK-Lookup).
- Worker-Throughput im `observation`-Mode (kein LLM-Call): ~100-200 Jobs/Sekunde (Job-Update-Limit).
- Worker-Throughput im `live`-Mode: limitiert durch LLM-Latenz (~5-15s pro Call), ~5-15 Jobs/Minute bei single concurrency.

**Sicherheit:**

- LLM-Output wird strikt JSON-validiert (Schema, Whitelist auf Band-Werte, ID-Existenz-Check). Adversarial-Tests verhindern dass halluzinierte oder injizierte LLM-Outputs Findings auf unsichere Bands setzen.
- Worker-Container hat keine eingehenden Ports (kein HTTP-Endpunkt extern). Nur DB- und LLM-Provider-Egress.
- Token-Budget verhindert ungebremstes Geldverbrennen bei LLM-Provider-Bug oder Halluzinations-Schleife.
- Mode-Wechsel erfordert `master_key`-Bestätigung (analog Settings-Änderungen in Block H).

## Re-Open-Trigger

- **Daily-Re-Eval-Job für stale Findings.** Heute läuft Block P nur on-write beim Scan-Ingest (analog Block O). Falls EPSS/KEV-DB-Updates zwischen Scans relevante Bewegung zeigen, Background-Job nachrüsten der `llm_risk_cache`-Einträge mit veraltetem `cve_data_fingerprint` invalidiert und Re-Jobs queued.
- **Manueller Group-Merge/Split-UI.** Wenn Library-Drift nach längerem Betrieb Doppel-Labels produziert (z.B. „k3s" und „k3s-rancher" für dieselbe Software): UI-Surface zum manuellen Merge der Groups. Aktuell nur via SQL/Migration möglich.
- **Manueller Group-Re-Detect-Trigger.** Settings-Action „re-run Pass 1 for all ungrouped findings" — falls neue Software im Stack auftaucht und der Operator nicht auf den nächsten Scan warten will. Aktuell automatisch on-write.
- **Manuelle Risk-Band-Korrektur durch Operator.** ADR-0022 hat „kein manueller Override" entschieden — gilt weiter. Falls Operator-Feedback nach längerem Block-P-Betrieb das fordert: eigene ADR.
- **Multi-Provider-LLM-Switch.** Aktuell nutzt Block P denselben Provider wie Block-G-Chat (DeepSeek-V3-Default via Block-G-Wrapper). Falls für Risk-Reviewer ein anderer Provider sinnvoll wird (z.B. lokales Modell wegen DSGVO bei Snapshot-Daten): Provider-Whitelist und Settings-Toggle erweitern. Eigene ADR.
- **DSGVO-Betrachtung der Snapshot-Daten an externen Provider.** Aktueller Default-Provider (DeepInfra/DeepSeek-V3) ist außereuropäisch. Operator muss heute selbst entscheiden ob er das vertretbar findet. Setup-Wizard-Hinweis bei `live`-Mode-Wechsel? Eigene ADR oder Setup-Doc-Erweiterung.
- **Detaillierter Group-Insights-View.** Aktuelle UI zeigt Group-Card mit Top-Level-Reason. Falls Operator detaillierte Per-Finding-LLM-Begründung möchte („warum hat das LLM Finding X für diese Group als worst-case identifiziert?"): eigener Block, eigener Modal-Trigger, Per-Finding-LLM-Call (Re-Open des „kein Per-Finding-Call"-Defaults).
- **Worker-Skalierungs-Patterns.** Aktuell Single-Worker default. Falls Realbetrieb zeigt dass parallele Worker sinnvoll wären: Provider-Rate-Limit-Sniffer plus adaptive Concurrency. Aktuell ENV-Variable.
- **Group-Card-Aggregation auf Dashboard-Ebene.** Aktuell zeigt Dashboard pro Finding eine Tabellen-Zeile (mit Group-Spalte). Falls Operator stattdessen pro-Server-pro-Group eine aggregierte Card-View will: eigener UI-Block.
- **Group-Trend-Reports** (z.B. „k3s-Group ist seit 3 Scans escalate"). Historisierungs-Tabelle für Group-Band-Wechsel.
- **Pre-Triage-Cuts feinjustieren** basierend auf Block-P-Realdaten — wenn `live`-Mode zeigt dass 80% der `pending`-Findings vom LLM auf `noise` demoted werden, ist die Pre-Triage zu großzügig. Konstanten in Block O anpassen (kein Schema-Change), eigene Bug-Fix-Iteration.
