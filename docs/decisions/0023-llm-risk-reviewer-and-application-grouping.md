## ADR-0023 — LLM-Risk-Reviewer mit Application-Grouping (Two-Pass) und asynchroner Job-Queue

**Status:** Akzeptiert (Persistenz-Schicht aktualisiert durch ADR-0028: Eval-Felder leben jetzt in Junction `application_group_evaluations`, nicht mehr auf `ApplicationGroup`) · **Akzeptiert:** 2026-05-18 · **Datum:** 2026-05-18 · **Bezug:** ADR-0022 (Pre-Triage, Snapshot, Vendor-Severity) wird durch diesen Block **erweitert**, nicht abgelöst — Block O liefert `pending`-Findings und die Datenbasis (Snapshot, severity_by_provider, vendor_status), Block P macht das Group-Layer obendrauf und die finale Risk-Bewertung. ADR-0010 (LLM-Provider-Abstraktion) bleibt unverändert; Block-G-`AsyncOpenAI`-Wrapper wird wiederverwendet. ADR-0014 (Token-Cap Best-Effort) gilt analog für die neuen LLM-Use-Cases. ADR-0003 (Push-not-Pull) unberührt — Worker liest Findings aus der DB, kein Pull vom Agent.

> **Hinweis Block T (ADR-0028, 2026-05-22):** `ApplicationGroup` traegt seit Block T keine Eval-Spalten mehr. Pass-2 schreibt per UPSERT in `application_group_evaluations` mit Composite-PK `(group_id, server_id)`; `inherit_group_risk_to_findings` joint auf die Junction mit Composite-Match. Last-write-wins-Bug zwischen Servern ist behoben. Cache-Layer (`llm_risk_cache`) bleibt unveraendert — der Cache-Key war schon korrekt per-(group, server-context) geschnitten.

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

## Update v0.9.3 (2026-05-XX) — Prompt-Iteration und Modell-Default-Wechsel

Nach Block-P-Abschluss (v0.9.0) und zwei Test-Runden mit insgesamt sieben LLM-Modellen wurde der Pass-1-System-Prompt iteriert und der Default-Provider gewechselt. Patch in v0.9.3 ohne Schema-Migration.

**Modell-Default-Wechsel:** von DeepSeek-V3 (vom Block-G-Wrapper geerbt) auf `openai/gpt-oss-120b`. Begründung in drei Punkten: (a) semantisch stärkstes Modell in der Test-Suite, alle zehn Test-2-Kriterien fehlerfrei bestanden; (b) Apache 2.0 lizenziert und self-hostable — DSGVO-Operator-Option ohne Code-Change; (c) Provider-Flexibilität (DeepInfra, Groq, vLLM, Ollama).

**Prompt-Iteration:** der ursprüngliche Pass-1-Prompt aus ADR-0023 §Pass-1 wurde um sieben Härtungs-Aspekte ergänzt, die aus den Test-Befunden hervorgegangen sind:

1. Cross-Language-Bundle-Regel (Regel 6) — Multi-Library-Findings unter gemeinsamem Verzeichnis-Pfad werden als eine Application gruppiert, nicht als mehrere Library-Groups.
2. Multi-Path-Application-Regel (Regel 7) — Application mit Pfaden in `/usr/local/bin/<app>` UND `/var/lib/<vendor>/<app>/` ist eine Group, nicht zwei.
3. Trailing-Slash-Pflicht für Directory-Path-Prefixes.
4. Defense-in-Depth-Vorgabe — Pattern-Layers sollen so vollständig wie sinnvoll befüllt werden.
5. Anti-Generic-Pattern-Liste — konkrete verbotene Beispiele (`pkg:golang/stdlib`, `pkg:maven/`, Versions-Hashes in Pfaden).
6. Halluzinations-Schutz — explizites „NEVER invent finding_ids that were not in the input".
7. Bundle-vs-Library-PURL-Unterscheidung — für Application-Bundles dürfen nur Application-Vendor-PURLs als Pattern, niemals transitive Library-PURLs.

**Volltext des finalen Prompts** plus die Test-Evidenz-Matrix aller sieben Modelle: siehe [`docs/blocks/P-evidence/prompt-pass1-final.md`](../blocks/P-evidence/prompt-pass1-final.md). Das File ist die Quelle der Wahrheit für `PASS1_SYSTEM_PROMPT` in `app/services/llm_prompts.py` und für künftige Prompt-Iterations-Vergleiche.

**Code-Änderungen** für v0.9.3:

- `app/services/llm_prompts.py::PASS1_SYSTEM_PROMPT` — verbatim aus dem Prompt-Final-File übernehmen.
- `app/config.py::BLOCK_P_LLM_MODEL` (oder die entsprechende Settings-Spalte) — Default auf `"openai/gpt-oss-120b"` umstellen. Operator-Override via Settings-Tab bleibt.
- `tests/services/test_llm_prompts.py` — neuer Anti-Regression-Test prüft, dass der Prompt-Text die kritischen Regel-Marker enthält („CROSS-LANGUAGE BUNDLES", „MULTI-PATH APPLICATIONS", „DEFENSE IN DEPTH", „AVOID OVER-GENERIC PATTERNS", „BUNDLE PURLs MUST IDENTIFY THE APPLICATION ITSELF").
- Bestehende Pass-1-Tests in `tests/services/test_llm_risk_reviewer.py` — Mock-Responses mit dem Default-Modell-Bezug aktualisieren falls hartkodiert.

**Backend-Validatoren** (`_validate_pass1_response()`) bleiben unverändert — die drei Validations-Schichten (ID-Treue, Pattern-Konsistenz, Pattern-Generizität) wurden schon in v0.9.0 implementiert und greifen auch bei dem neuen Default-Modell.

**Pass 2 (`risk_evaluation`)** wird in v0.9.3 ebenfalls mit angepasst — drei zusammenhängende Änderungen:

**(a) Tags raus aus dem Host-Context.** Server-Tags sind User-vergebene Freitext-Labels (Block D) für UI-Gruppierung und -Filterung. Sie tragen keine garantierte Semantik („internet-exposed" kann beim einen Operator wörtlich gemeint sein, beim nächsten kosmetisch). Block-P-Risk-Engine verlässt sich deshalb ausschließlich auf objektive Snapshot-Daten (Listener-Adressen für Exposure-Bestimmung). Tags werden weder in den Pass-2-Host-Context aufgenommen noch als Match-Signal in der Engine genutzt. Spätere ADR kann explizite Server-Flags für Exposure-Override einführen (z.B. `network_exposure: public | private | airgapped`, `is_honeypot`, `is_decommissioned`), das wäre dann separates Schema mit garantierter Semantik.

Code-Änderung: `_render_pass2_prompt()` in `app/services/llm_risk_reviewer.py` strippt die Tags aus dem Host-Context-Block (oder hat sie nie aufgenommen falls Implementer-Glück). Bestehende `_validate_pass2_response()`-Logik unverändert.

**(b) Risk-Band-Reduktion auf vier aktive Werte.** Operator-Feedback und Pass-2-Testlauf-Erkenntnis: die Trennlinie zwischen `escalate` (KEV+exposed) und `mitigate` (HIGH+exposed+no-patch) hat sich in der Praxis nicht als hilfreich erwiesen. Beide Bänder kommunizieren „sofort handeln", unterscheiden sich nur in der Aktions-Art (patchen vs. anders mitigieren). Diese Aktions-Art gehört semantisch in den `risk_band_reason`-Text, nicht in einen eigenen Band-Wert.

Neues Mapping:

| Band | Aktiv ab v0.9.3 | Trigger |
|------|------------------|---------|
| `escalate` | ja | KEV+exposed · oder · HIGH/CRITICAL+exposed+no-patch (will_not_fix/EOL/keine-Fix-Version) |
| `act` | ja | HIGH/CRITICAL+exposed+has-patch+not-KEV |
| `mitigate` | **deprecated** | (LLM produziert keine `mitigate`-Bewertungen mehr; Enum-Wert bleibt für historische Daten und Validator-Backward-Compat erhalten) |
| `monitor` | ja | moderate Severity · oder · nur RFC1918/Loopback-Listener · oder · unklare Exposure |
| `noise` | ja | Application nachweislich nicht aktiv |
| `pending` / `unknown` | ja | Pre-Triage-Output aus Block O, unverändert |

Reason-Texte für escalate-Findings müssen jetzt explizit erwähnen ob ein Patch verfügbar ist (`"Patch available — update immediately"`) oder Mitigation nötig ist (`"No patch available (vendor will_not_fix) — apply firewall rule or disable service"`). Damit sieht der Operator beim Klick aufs escalate-Pill sofort welche Art von Aktion fällig ist.

`ACTION_REQUIRED_MAP` bleibt strukturell:
- `yes` deckt: escalate, act, mitigate (legacy), pending, unknown
- `no` deckt: monitor, noise

Code-Änderungen:

- `_render_pass2_prompt()` in `app/services/llm_risk_reviewer.py`: Band-Definitionen im System-Prompt auf vier Werte reduzieren, mitigate-Definition entfällt.
- `_validate_pass2_response()`: weiterhin alle fünf Werte akzeptieren (`mitigate` für Backward-Compat), aber bei `mitigate`-Ausgabe vom LLM eine Warnung loggen und intern auf `escalate` mappen.
- DB-CheckConstraint auf `application_groups.risk_band`: unverändert, akzeptiert weiterhin alle fünf Werte.
- Migration für bestehende `mitigate`-Findings: keine Forced-Migration. Beim nächsten Scan-Re-Ingest werden Findings via natural Re-Evaluation neu bewertet und landen automatisch im neuen Schema (escalate oder act je nach Patch-Status). Nicht-aktive Server mit Alt-Bewertungen behalten `mitigate` für ihre Historie.
- UI (Dashboard-KPI-Pills + Server-Detail-Group-Cards): `mitigate`-Pill bleibt für historische Daten gerendert (mit Hinweis-Tooltip „legacy band, see reason"), neue Bewertungen produzieren ihn nicht mehr.

**(c) `action_type` plus `group_kind` plus „Was zu tun ist"-UI-Sektion.** Die 4-Band-Reduktion aus Punkt (b) löst das Operator-Problem nur halb: Operator sieht zwar dass ein Finding `escalate`/`act` ist, aber nicht ob er patchen oder anders mitigieren muss. Die Aktions-Art steckt nur im Free-Text-Reason — operativ ungenügend bei mehreren escalate-Groups pro Server.

Drei semantisch unterschiedliche Operator-Workflows müssen visuell getrennt werden:

| Workflow | Aktions-Realität | Wann |
|----------|------------------|------|
| Distro patchen | `apt`/`dnf upgrade` löst es | OS-Paket-Group + Patch verfügbar |
| App-Update einspielen | Vendor-Release abwarten, manuell updaten | Application-Bundle-Group + Patch verfügbar |
| Mitigieren | Operator brainstormt non-patch Maßnahme | egal welche Group-Kind + kein Patch |

Daraus folgen zwei neue Group-Felder:

**`action_type: varchar(16)`** — vom LLM in Pass 2 gesetzt:

| Wert | Trigger | Erlaubt für risk_band |
|------|---------|----------------------|
| `patch` | Patch ist verfügbar, sofort/im Cycle einspielen | escalate (Pfad a) · act |
| `mitigate` | Kein Patch (will_not_fix/eol/has_fix=no) | escalate (Pfad b) |
| `watch` | Beobachten, kein Handlungsbedarf | monitor |
| `none` | Komponente nicht aktiv | noise |
| `investigate` | LLM hat noch nicht bewertet | pending · unknown |

Backend-Validator prüft erlaubte `(risk_band, action_type)`-Kombinationen analog zu den anderen Validations-Schichten.

**`group_kind: varchar(20)`** — **deterministisch** vom Backend beim Group-Insert aus `match_rules` abgeleitet, **nicht** vom LLM:

| Wert | Ableitung |
|------|-----------|
| `application_bundle` | `path_prefixes` ist non-empty (k3s, jenkins, apache2, grafana, …) |
| `os_package` | nur `pkg_name_exact` und/oder `pkg_purl_pattern` befüllt (openssh-server, openssl, glibc, …) |

Backfill für bestehende Groups in der Migration: `group_kind` wird deterministisch aus den vorhandenen `match_rules` berechnet, `action_type` bleibt NULL bis zum nächsten Pass-2-Re-Eval (LLM setzt es beim nächsten Call).

**Pass-2-Output-Schema** erweitert um das eine Feld:

```json
{
  "evaluations": [
    {
      "group_label": "apache2",
      "risk_band": "escalate",
      "action_type": "mitigate",
      "worst_finding_id": 2001,
      "reason": "apache2 listens 0.0.0.0:8080; vendor will_not_fix"
    }
  ]
}
```

Reason wird kürzer (max ~180 Chars statt 256), weil die Aktions-Art nicht mehr im Free-Text kommuniziert werden muss — sie steckt im strukturierten Feld.

**Neue Server-Detail-UI-Sektion „Was zu tun ist"** zwischen Sub-Line und Host-Snapshot. Sektion wird **komplett ausgeblendet** wenn keine Group mit `risk_band ∈ {escalate, act}` existiert. Sektion enthält bis zu fünf Cards, leere Cards skippen:

| Card | Filter | Sub-Line | Counter |
|------|--------|----------|---------|
| ESCALATE · Distro patchen | escalate + patch + os_package | Komma-Liste der Group-Labels (max 3-5 inline, dann „+N more") | Anzahl Groups |
| ESCALATE · App-Update einspielen | escalate + patch + application_bundle | Komma-Liste der App-Labels | Anzahl Apps |
| ESCALATE · Kein Patch — mitigieren | escalate + mitigate | Komma-Liste der Group-Labels | Anzahl Groups |
| ACT · Distro patchen (normal cycle) | act + os_package | **keine** Sub-Liste — bei act zu viel Visual-Noise | Anzahl Groups |
| ACT · App-Update einspielen (normal cycle) | act + application_bundle | **keine** Sub-Liste | Anzahl Apps |

Jede Card hat `<details>`-Drill-down (default collapsed) mit der Findings-Tabelle für die zugehörigen Groups.

**Was bleibt unverändert** am Server-Detail-View: Header-Pill-Reihe (inkl. „Action needed"-Pill als Top-Level-Bauchgefühl), Host-snapshot-Sektion, Tags-Akkordeon, KPI-Cards mit Sparklines, Lebenszeichen, Severity-Trend, Findings-Tabelle ganz unten.

**Code-Touchpoints** für diesen Punkt:

- `app/models.py::ApplicationGroup` — zwei neue Spalten (`action_type`, `group_kind`) plus CheckConstraints.
- Migration: zwei `add_column` plus Backfill-Update für `group_kind` aus existierenden `match_rules`.
- `app/services/group_matcher.py` — Helper `derive_group_kind(match_rules) -> str` für Insert-Time-Derivation.
- `app/schemas/llm_responses.py` (oder wo das Pass-2-Output-Modell lebt) — `action_type` als Literal im Output-Schema.
- `app/services/llm_risk_reviewer.py::_validate_pass2_response()` — `(risk_band, action_type)`-Kombinations-Whitelist.
- `app/views/server_detail.py` — neuer Helper `_build_action_sections(groups)` der die fünf Cards baut, leere skippt, in der dokumentierten Reihenfolge sortiert.
- `app/templates/servers/_action_needed_section.html` (neu) — Card-Layout mit `<details>`-Drill-down.
- `app/templates/servers/detail.html` — Sektion einschleusen zwischen Sub-Line und Host-Snapshot, nur rendern wenn `action_sections` non-empty.

**(d) Reasoning-Block-Handling im Response-Parser.** Der Default-Provider-Wechsel auf GPT-OSS-120B (Punkt a) bringt ein Reasoning-Modell ins Spiel — anders als die nativen OpenAI-Strukturierte-Outputs-Modelle aus v0.9.0 produziert GPT-OSS einen `analysis`-Channel (Harmony-Format) bevor es das eigentliche JSON ausliefert. Beobachtetes Token-Volumen im Pass-2-Test: ~1400 Tokens für 5 Groups, davon ~900 Tokens Reasoning. Je nach Provider-Adapter (DeepInfra, Groq, lokales vLLM/Ollama) landet dieser Reasoning-Block entweder in einem separaten `message.reasoning`-Feld, wird komplett gestrippt, oder erscheint in `message.content` vor dem JSON. Letztgenanntes würde unser bestehendes `json.loads(content)` in `chat_completion_json` mit `LLMInvalidResponseError` zerschießen — alle Block-P-Jobs würden silently in `failed` enden.

**Defensive Extraktions-Logik** in `app/services/llm_risk_reviewer.py::_extract_json_from_response()` (neu), drei Schichten in Reihenfolge:

1. **Bekannte Reasoning-Wrapper-Patterns strippen** via Regex:
   - GPT-OSS Harmony: `<\|channel\|>analysis<\|message\|>.*?<\|end\|>` (mit DOTALL)
   - DeepSeek-R1 / generic: `<think>.*?</think>`
   - Llama-Style: `\[REASONING\].*?\[/REASONING\]`
2. **Markdown-Code-Fences strippen** falls vorhanden: ` ```json\n...\n``` ` → reines JSON.
3. **Greedy-Brace-Extraktion als Fallback**: vom ersten `{` bis zum letzten `}`, falls noch Begleittext im Response steht.

Der Helper läuft IMMER zwischen `getattr(choices[0].message, "content", ...)` und `json.loads(content)` — auch wenn der aktuelle Provider sauberen JSON liefert, kostet das nichts und schützt vor Provider-Wechsel.

**Reasoning-Extraktion über mehrere Provider-Patterns** — verifiziert durch DeepInfra-Probe-Lauf 2026-05-XX. DeepInfra+GPT-OSS-120B liefert das Reasoning **nicht** als direkt-zugängliches Attribut auf `message`, sondern in der Pydantic-V2-`extra="allow"`-Bucket unter `message.model_extra["reasoning_content"]`. Naive `getattr(message, "reasoning", None)` würde das nicht finden.

```python
def _extract_reasoning(message) -> str | None:
    """Reads reasoning content from various provider patterns:
    - OpenAI o1-style: message.reasoning (direct attribute)
    - DeepSeek-R1: message.reasoning_content (direct attribute)
    - DeepInfra GPT-OSS via OpenAI SDK: message.model_extra["reasoning_content"]
      (Pydantic V2 extra-bucket — content on message itself is clean JSON)
    - Fallback: None
    """
    for attr in ("reasoning", "reasoning_content", "thinking"):
        val = getattr(message, attr, None)
        if val:
            return str(val)
    extra = getattr(message, "model_extra", None) or {}
    for key in ("reasoning_content", "reasoning", "thinking"):
        val = extra.get(key)
        if val:
            return str(val)
    return None
```

Wert wird ins `llm_debug_log.response_body.reasoning_field` geschrieben (separat von `raw_content` und `extracted_json`), damit Operator beim Debug-Inspect sieht wie das Modell „gedacht" hat.

**DeepInfra-Probe-Befunde (2026-05-XX, openai/gpt-oss-120b):**

- `message.content` ist clean JSON (kein Strip nötig für diesen Provider)
- `message.model_extra["reasoning_content"]` enthält das Reasoning (Plain-Text, kein Wrapper)
- Keine `completion_tokens_details.reasoning_tokens`-Aufschlüsselung in `response.usage` (Reasoning-Tokens werden in `completion_tokens` mitgezählt, nicht separat ausgewiesen)
- Token-Ratio bei 3 Test-Groups: 543 prompt + 616 completion = 1159 total, davon geschätzt ~370 Reasoning und ~240 JSON

Der `_extract_json_from_response`-Helper bleibt trotzdem als Defense-in-Depth implementiert — schützt vor Provider-Wechsel (Groq, vLLM, Ollama liefern möglicherweise nicht so sauber wie DeepInfra) und vor Modell-Updates die das Format ändern können.

**Token-Budget-Konsequenz:** beobachtete Pass-2-Reality ist ~3× höher als die initiale Schätzung (~500 Tokens) wegen Reasoning. Der `LLM_TOKEN_BUDGET_DAILY`-Default wird in v0.9.3 von 1M auf **2M Tokens** angehoben — bei realer Flotte (~100 Pass-2-Calls/Tag × ~1500 Tokens) bleibt das immer noch günstig (~$1-2/Monat bei DeepInfra-Preisen). Operator kann den Wert via ENV-Var weiter justieren.

**Code-Touchpoints für diesen Punkt:**

- `app/services/llm_risk_reviewer.py` — neuer Helper `_extract_json_from_response(content: str) -> str` plus `_REASONING_BLOCK_PATTERNS`-Konstante. Caller in `chat_completion_json` ruft den Helper vor `json.loads()`.
- `app/services/llm_risk_reviewer.py::chat_completion_json` — liest `message.reasoning`/`reasoning_content` als optionales Feld, gibt es im Rückgabewert-Dict zusätzlich zurück oder loggt es separat für den Debug-Log-Insert.
- `app/workers/llm_worker.py` — Debug-Log-Insert (Punkt e unten) schreibt `raw_content`, `extracted_json` und `reasoning_field` separat in `response_body`.
- `app/config.py::LLM_TOKEN_BUDGET_DAILY` — Default von 1_000_000 auf 2_000_000.
- `tests/services/test_llm_risk_reviewer.py` — vier neue Unit-Tests: `_extract_json_strips_harmony_channel`, `_extract_json_strips_think_tags`, `_extract_json_strips_markdown_fences`, `_extract_json_fallback_greedy_braces`.

**(e) LLM-Debug-Log-Tabelle für Operator-Inspektion.** Block P macht heute LLM-Calls im Worker ohne dass Operator die Request/Response-Bodies nachsehen kann (außer Worker-Log-File, ungroupiert). Für Debugging — vor allem in der Observation-Phase, beim Modell-Wechsel, bei unerwarteten Bewertungen — soll Operator pro Job das Request/Response-Tupel einsehen können.

Neues Schema `llm_debug_log`:

```
llm_debug_log
  id              bigserial PK
  job_type        varchar(32)   -- 'pass1_group_detection' | 'pass2_risk_evaluation'
  job_id          bigint NULL   -- FK llm_jobs.id ON DELETE SET NULL (referenz lebt
                                --   Lifecycle-länger als der Job selbst)
  server_id       int NULL      -- FK servers.id ON DELETE SET NULL (für Filter im UI)
  group_id        bigint NULL   -- FK application_groups.id ON DELETE SET NULL
  model           varchar(64)   -- welches Modell, z.B. "openai/gpt-oss-120b"
  request_body    jsonb         -- vollständiger Request-Body, gecappt
  response_body   jsonb NULL    -- vollständige Response, gecappt; NULL bei Fehler
  duration_ms     int
  status          varchar(16)   -- 'success' | 'failed' | 'timeout' | 'validation_error'
  error           text NULL
  created_at      timestamp tz NOT NULL DEFAULT now()

Indizes:
  ix_llm_debug_log_created  (created_at)  -- für Eviction
  ix_llm_debug_log_job_type (job_type, created_at DESC)
  ix_llm_debug_log_group    (group_id) WHERE group_id IS NOT NULL
```

Eviction-Strategie kombiniert Count- und Time-Based-Limit:

- `LLM_DEBUG_LOG_MAX_ROWS = 500` (Standard) — älteste werden gelöscht wenn Tabelle größer
- `LLM_DEBUG_LOG_MAX_AGE_DAYS = 14` — Einträge älter werden gelöscht unabhängig vom Count
- Per-Row Body-Size-Cap: Request/Response werden auf max **64 KB** pro Body getrimmt (Truncation-Marker am Ende), damit ein einzelner Riesen-Response die Tabelle nicht aufbläht

Eviction-Sub-Tick im Worker alle 10 Minuten (analog Stale-Reaper):

```sql
DELETE FROM llm_debug_log
WHERE created_at < now() - interval '14 days';

DELETE FROM llm_debug_log
WHERE id NOT IN (
  SELECT id FROM llm_debug_log
  ORDER BY created_at DESC
  LIMIT 500
);
```

Bei realistischer Last (3k Findings, ~100 Application-Groups, ~10 Server-Context-Cluster, Re-Eval täglich) sind das pro Tag etwa 50-150 neue Log-Einträge. Mit dem 500-Row-Cap deckt das 3-10 Tage Historie ab. Bei Bedarf kann Operator den Cap erhöhen, Cost ist nur Disk.

UI: in v0.9.3 zunächst nur DB-Tabelle plus optional ein kompakter Tab unter `/settings/llm-reviewer` der die letzten 50 Einträge listet (job_type/group_label/status/duration/timestamp), Klick auf Eintrag expandiert Request+Response-JSON inline. Mehr UI-Komfort später.

Code-Touchpoints:

- `app/models.py` — neue Klasse `LLMDebugLog`.
- Alembic-Migration für die neue Tabelle plus Indizes.
- `app/workers/llm_worker.py::_process_live()` — nach LLM-Call zusätzlich `llm_debug_log`-Insert vor `mark_done()`.
- `app/workers/llm_worker.py` Eviction-Sub-Tick im Stale-Reaper-Block.
- `app/config.py` — neue Konstanten `LLM_DEBUG_LOG_MAX_ROWS`, `LLM_DEBUG_LOG_MAX_AGE_DAYS`, `LLM_DEBUG_LOG_BODY_SIZE_CAP`.
- `app/views/settings.py` — neuer Sub-Tab oder Erweiterung von `/settings/llm-reviewer` mit Debug-Log-Listing.
- Tests: Insert-Hook im Worker, Eviction greift bei Cap-Überschreitung, Body-Trim wirkt bei großen Bodies, FK-ON-DELETE-SET-NULL beim Löschen eines Jobs.

**(f) Listener-Interpretation: PUBLIC-EXPOSED inkl. RFC1918, LLM-Reasoning statt Hartlogik.** Die ursprüngliche Pass-2-Definition behandelte RFC1918-Listener (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`) als „internal only" und schob entsprechende Findings automatisch auf `monitor`. Operator-Feedback: das ist Wunschdenken. Listener-Adresse alleine ist nur **ein** Indikator für Exposure, nicht die ganze Wahrheit. Realistische Bedrohungsvektoren für einen `10.0.0.5:5432`-Listener:

- **Lateral Movement** — Angreifer kompromittiert irgendeinen anderen Host im selben Netz, danach ist die App trivial erreichbar
- **Port-Forward am Router** — Operator hat eine DNAT-Regel von public → 10.0.0.5:5432, das LLM weiß das nicht
- **Reverse-Proxy davor** — nginx auf 0.0.0.0:443 proxied zu `postgres:5432`, de facto public-exposed
- **VPN-Zugang** — jeder mit VPN-Credentials kann zugreifen
- **Kompromittierter Endpoint im selben Netz** — Workstation, IoT-Gerät, Drucker mit known CVE

Wir können aus Listener-Daten **nicht** beweisen dass etwas nicht erreichbar ist. Nur das Gegenteil können wir beweisen: `127.0.0.1`/`::1`-Bind ist beweisbar nicht netzwerk-erreichbar (außer Local-Privilege-Escalation, die als separate Angriffsklasse out-of-scope ist für diese Bewertung).

Neue Listener-Klassifikation mit drei Zuständen:

| Zustand | Kriterium | Risk-Interpretation |
|---------|-----------|---------------------|
| `PUBLIC-EXPOSED` | Bind auf `0.0.0.0`/`::` ODER auf eine spezifische IP (RFC1918 wie 10.x/172.16.x/192.168.x, IPv6 ULA fc00::/7, ODER eine Public-IP) | Reachable mindestens vom selben Netz-Segment, potenziell von extern via Port-Forward/Reverse-Proxy/VPN/Lateral-Movement. Defensive Annahme: exposed. |
| `LOOPBACK-ONLY` | Bind ausschließlich auf `127.0.0.1`/`::1` | Beweisbar nicht netzwerk-erreichbar. |
| `NO-LISTENER` | Komponente aktiv (Prozess, Service, Modul) aber kein Netzwerk-Socket | Library-Code kann theoretisch über andere Prozesse missbraucht werden, kein direkter Netzwerk-Angriffsvektor. |

**Wichtig: LLM-Reasoning statt Hartlogik.** Die Listener-Klassifikation ist nur Input für eine **vom LLM ausgeführte Angriffsketten-Bewertung**. Zwei Korrektur-Pfade die das LLM eigenständig anwenden darf:

1. **LOOPBACK-ONLY/NO-LISTENER → escalate/act hochstufen** wenn das LLM erkennt dass die verwundbare Komponente über einen anderen exposed Service erreichbar ist. Beispiel: eine `liblzma`-Decompression-CVE in einer Library die von einem PUBLIC-EXPOSED-File-Upload-Handler genutzt wird → behandle als PUBLIC-EXPOSED. Eine `liblzma`-CVE in einem Daemon der nur lokal Logs komprimiert → bleibt monitor.

2. **PUBLIC-EXPOSED nicht blind hochstufen** wenn das LLM erkennt dass die spezifische Code-Pfad-Schwachstelle auf diesem Host gar nicht erreicht werden kann. Beispiel: eine LDAP-Parsing-CVE in einem Daemon der LDAP-Support kompiliert hat aber per Config disabled → monitor reicht.

System-Prompt-Anweisung explizit: „Be a thinking analyst. Cite the chain of reasoning in your reason text: which listener observation, which attack path, why exposed/not exposed."

**Konsequenzen:**

- `monitor` wird operativ enger. Default für „aktive Komponente mit verfügbarem Patch" ist jetzt `act`, nicht mehr `monitor`. Operator wird häufiger zur Handlung aufgefordert — defensive Default-Linie.
- LLM-Bewertung wird weniger deterministisch. Derselbe Finding kann beim Re-Eval anders bewertet werden wenn das Modell die Angriffsketten anders abwägt. Cache (`llm_risk_cache` aus v0.9.0) stabilisiert das auf Cache-Key-Ebene; bei manuellem Cache-Bust oder Modell-Update kann es Drift geben — akzeptabel weil Block-P-Reasoning-Modell sowieso natürliche Varianz zeigt.
- Reason-Cap muss auf 256 Chars zurück (vorher 200 in Iteration 5), weil die Begründungs-Kette manchmal länger braucht: Listener-Observation + Angriffspfad + Severity-Bezug.

**Spätere Operator-Override-Möglichkeit** als eigene ADR (v0.10.x oder später, wenn Block-P-Realbetrieb zeigt dass die defensive Annahme zu viel `act`/`escalate` produziert): expliziter Server-Flag `network_exposure: airgapped | restricted | open`, der die Listener-Heuristik überschreibt. `airgapped` würde alle PUBLIC-EXPOSED-Listener als LOOPBACK-ONLY behandeln, `restricted` würde nur 0.0.0.0/:: hochstufen aber spezifische RFC1918-IPs als nicht-extern-exposed werten. Out-of-Scope für v0.9.3.

**Test-Case-Auswirkung** (gleiche fünf Groups aus Iteration 5):

| Group | Listener | Iteration 5 | Iteration 6 |
|-------|----------|-------------|-------------|
| openssh-server | 0.0.0.0:22 | escalate · patch | escalate · patch (unverändert) |
| apache2 | 0.0.0.0:8080 | escalate · mitigate | escalate · mitigate (unverändert) |
| postgresql | 10.0.0.5:5432 | monitor · watch | **act · patch** (RFC1918 jetzt als PUBLIC-EXPOSED) |
| nginx | 0.0.0.0:443 | escalate · patch | escalate · patch (unverändert) |
| bluetooth | (kein Modul) | noise · none | noise · none (unverändert) |

**Code-Touchpoints für diesen Punkt:**

- `app/services/llm_prompts.py::PASS2_SYSTEM_PROMPT` — kompletter Exposure-Block neu (3-Zustände-Klassifikation, LLM-Reasoning-Anweisung).
- `app/services/llm_risk_reviewer.py::_validate_pass2_response()` — Reason-Cap von 200 zurück auf 256 Chars (war in Iteration 5 verkürzt, wird zurückgenommen).
- `tests/services/test_llm_prompts.py` — Anti-Regression-Test ergänzt um die neuen Marker `PUBLIC-EXPOSED`, `LOOPBACK-ONLY`, `NO-LISTENER`, `Be a thinking analyst`.
- `docs/blocks/P-evidence/prompt-pass2-final.md` — Iteration 6 als finaler Stand mit der neuen Listener-Klassifikation, alte Iteration 5 als Historie.

## Nachtrag 2026-05-24 — `Vulnerability.PkgPath` bevorzugen + Pass2-Pfad-Reasoning

**Hintergrund.** Dev-Beobachtung (Ticket-006-Phase): ein Agent-Upload mit AdminLTE-Webprojekt erzeugt 380 Findings, von denen Pass1 nur eine einzige Group (`adminlte-master`) findet. 191 Findings bleiben ungroupiert, Pass2 läuft entsprechend nur einmal. Ursache liegt nicht im LLM-Reasoning sondern im Ingest:

- Trivys `Result.Target` ist nur bei File-Level-Analyzern (`gobinary`, `jar`, `pyinstaller`, alle OS-Distro-Typen) ein echter Pfad. Bei Walker-Analyzern für Sprach-Paketmanager (`node-pkg`, `python-pkg`, `gemspec`, `cargo`, `composer`, …) aggregiert Trivy alle Funde eines Ökosystems in einem einzigen Result und setzt `Result.Target` auf das Ökosystem-Label (`"Node.js"`, `"Python"`).
- Die echte Per-Paket-Location steht in diesem Fall ausschließlich in `Vulnerability.PkgPath` (z. B. `AdminLTE-master/node_modules/vite/package.json`).
- Unser Ingest las bisher nur `Result.Target` und schrieb diesen Wert nach `findings.target_path`. Für alle `node-pkg`/`python-pkg`-Findings landete damit `target_path="Node.js"` bzw. `"Python"` — und der Pass1-System-Prompt (Rules 4-6) kann ohne Pfad-Info keine Owner-Application ableiten. Das LLM hat in seinen Reasoning-Logs explizit notiert: „we have no path info … so they go to ungrouped."

**Entscheidung.** Der Ingest bevorzugt `Vulnerability.PkgPath` über `Result.Target`, sowohl für die DB-Spalte `target_path` als auch für den `@target`-Disambiguator aus ADR-0011. Pass2 reicht den Per-Finding-Pfad zusätzlich an das LLM weiter, weil die Pfad-Klassifikation (`PROJECT-LOCAL`/`SYSTEM-BASELINE`/`ECOSYSTEM-ONLY`) ein eigenes starkes Exposure-Signal ist neben Listener und Attack-Chain.

Konkretes Mapping pro Finding:

```python
target_path = vuln.pkg_path.strip() or result.target
```

Kein Trivy-Type-Switch nötig — `PkgPath` ist per Konstruktion präziser als `Target`, fehlt nur dort wo `Target` schon der korrekte Pfad ist. Backward-kompatibel für gobinary/jar/os-pkgs (deren `PkgPath` leer ist → Fallback greift unverändert).

**Pass2-Erweiterung.** `_render_pass2_prompt` schreibt pro Finding-Zeile `path=<gecapptes target_path bis 128 Chars>` (bzw. `path=n/a` wenn nichts vorhanden). `PASS2_SYSTEM_PROMPT` führt das als drittes Exposure-Signal neben Listener und Attack-Chain ein, mit drei Klassen:

| Klasse | Kriterium | Bedeutung |
|--------|-----------|-----------|
| `PROJECT-LOCAL` | Pfad unter `/opt/<app>/`, `/srv/<app>/`, `/home/<user>/`, `/var/www/`, `/var/lib/<app>/`, oder relativer Bundle-Root (`AdminLTE-master/node_modules/...`) | Operator-eigener Application-Deploy — Listener-Evidenz greift normal |
| `SYSTEM-BASELINE` | Pfad unter `/usr/lib/python3/...`, `/usr/lib/node_modules/...`, `/usr/share/...`, `/usr/local/lib/...`, Distro-Metadata | OS-Baseline; meist kein Owner-App, Reach hängt von UPGRADE-Chain ab |
| `ECOSYSTEM-ONLY` | `path=Python`/`Node.js`/… oder `path=n/a` | Kein Pfad-Reasoning möglich → ausschließlich Listener/Prozess/Service-Evidenz |

Die Klassifikation **überschreibt nicht** die Listener-Evidenz (`PROJECT-LOCAL` an `127.0.0.1` bleibt `LOOPBACK-ONLY`); sie verfeinert nur die Reach-Plausibilität.

**Ungroupierte Findings bleiben out-of-scope für Pass2.** Pass2 läuft per `application_group`, nicht per Finding. Findings ohne Owner-App bekommen weiterhin keine Risk-Bewertung — das ist beabsichtigt: nach dem Path-Fix sollte „ungrouped" der seltene Rest sein, und für diesen Rest fehlt schlicht das gruppen-aggregierte Kontext-Signal das Pass2 brauchen würde. Falls die ungrouped-Rate empirisch hoch bleibt, ist die Antwort ein besserer Pass1-Prompt (Fallback-Regel pro `package_name` für language-pkgs ohne Bundle-Pfad), nicht ein per-Finding-Pass2.

**Code-Touchpoints für diesen Nachtrag:**

- `app/schemas/scan_envelope.py::TrivyVulnerability` — neues Feld `pkg_path: str | None = Field(default=None, alias="PkgPath", max_length=512)` mit eigenem Validator (NUL-Bytes und Control-Chars stripp/reject, kein ASCII-Zwang weil Unicode-Pfade möglich sind).
- `app/services/findings_ingest.py::_effective_target_path()` — neue Helper-Funktion: `vuln.pkg_path.strip() or result.target`.
- `app/services/findings_ingest.py::_extract_cause_fields()` — verwendet `_effective_target_path()` statt direkt `result.target`.
- `app/services/findings_ingest.py::_build_finding_row()` — Disambiguator-Argument ebenfalls auf `_effective_target_path()` umgestellt, damit `package_name` und `target_path` konsistent denselben Pfad sehen.
- `app/services/llm_risk_reviewer.py::_render_pass2_prompt()` — pro Finding-Zeile `path=<…|n/a>` mit 128-Char-Cap.
- `app/services/llm_prompts.py::PASS2_SYSTEM_PROMPT` — neuer Abschnitt „3. Per-finding install path" mit `PROJECT-LOCAL`/`SYSTEM-BASELINE`/`ECOSYSTEM-ONLY`-Klassifikation.
- `tests/schemas/test_envelope_cause_fields.py` — `PkgPath`-Validator-Tests (accept Slash/Punkt, default None, NUL/512-Reject).
- `tests/services/test_findings_ingest_cause_mapping.py` — Pfad-Precedence-Tests: node-pkg/python-pkg nehmen PkgPath, gobinary fällt auf Result.Target zurück, Whitespace-PkgPath wird wie leer behandelt, Disambiguator verhindert UNIQUE-Kollision bei zwei PkgPaths desselben Pakets.
- `tests/services/test_llm_risk_reviewer.py` — Pass2-Render-Tests: `path=` pro Finding, `path=n/a` für fehlende Pfade, 128-Char-Truncation.
- `tests/services/test_llm_prompts.py` — Anti-Regression-Marker `PROJECT-LOCAL`/`SYSTEM-BASELINE`/`ECOSYSTEM-ONLY`/`path=`/`path=n/a` in PASS2_SYSTEM_PROMPT.

Keine Migration nötig: `findings.target_path` existiert schon, der Wert wird beim nächsten Scan-Ingest pro Server überschrieben (Quelle-der-Wahrheit-Semantik des aktuellen Scans).
