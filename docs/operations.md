# Operator-Notizen — fathometer

Lebende Sammlung von Betriebs-Hinweisen: Outbound-Ziele, Air-Gap-Setup,
Feed-Pull-Health-Checks. Ergaenzt um neue Abschnitte pro Feature.

---

## Upstream-Update-Suche (ADR-0063, optional)

Die agentische Upstream-Update-Suche ist ein **optionales, operator-gated**
Feature (ADR-0063). Es sieht on-demand beim Upstream nach, ob ein neuerer
Build eines Artefakts existiert (z. B. fuer Ansible-/manuell ausgerollte
Binaries ohne Paketmanager-Eintrag oder im EOL-/zu-alt-Distro-Fall). Das
Ergebnis ist **beratend** — es flippt nie automatisch einen `risk_band` oder
`fix_lane`. Der Operator entscheidet.

### Default: AUS (Air-Gap-first)

Das Feature ist **standardmaessig deaktiviert** (`upstream_check_enabled =
false`). Outbound-Browsing widerspricht dem air-gap-first-Default. Es muss
bewusst in den Settings aktiviert und konfiguriert werden (Such-Backend +
Modell), sonst ist der Check-Button inaktiv.

### Air-Gap-Deployment

In einem Air-Gap-Setup bleibt das Feature schlicht **aus**:

- `upstream_check_enabled` nicht aktivieren (Default).
- Den optionalen **`research-worker`-Container** im Compose-Setup **weglassen**.

Es entsteht kein Outbound-Traffic, solange das Feature aus ist.

### Outbound-Ziele (nur bei aktiviertem Feature)

Wenn aktiviert, erzeugt der Research-Agent zwei Arten von Outbound-Calls:

1. **Such-Backend** — die konfigurierte `upstream_search_base_url`
   (SearXNG-Instanz, Tavily-/Serper-/Firecrawl-API). Ein Call pro Suche.
2. **Vom Agenten gefetchte Quell-URLs** — Release-/Repo-/Changelog-Seiten und
   Roh-Dateien (z. B. `go.mod` am Release-Tag, Lockfiles, SBOMs) auf
   GitHub/Vendor-Hosts, die der Agent aus den Suchtreffern auswaehlt. Diese
   Ziele sind **nicht vorab fix** — sie ergeben sich aus den Treffern.

**Egress-Allowlist:** mindestens das Such-Backend-Host + die ueblichen
Quell-Hosts (`github.com`, `raw.githubusercontent.com`, `objects.githubusercontent.com`,
Release-CDNs, Vendor-Domains der ueberwachten Artefakte). Wer eine strikte
Allowlist faehrt, beobachtet die tatsaechlich gefetchten Hosts beim Pilot-Lauf
und ergaenzt sie.

### SSRF-Schutz (Code-seitig) + Container-Isolation

Die vom Agenten gewaehlten Fetch-Ziele (Punkt 2 oben) sind **untrusted** (sie
stammen aus Suchtreffern und LLM-Entscheidungen, die per Prompt-Injection in
Webseiten beeinflussbar sind). `fetch_url` erzwingt daher eine **Code-seitige
SSRF-Allowlist** (`_is_fetch_url_allowed` in `upstream_research.py`): nur
`http`/`https`, DNS-Auflösung **aller** Ziel-IPs und Ablehnung von privaten,
loopback-, link-local- (inkl. `169.254.169.254`-Cloud-Metadata), reservierten
und multicast-Adressen; eigener `httpx`-Download mit `follow_redirects=False`
(Redirects werden geblockt, kein SSRF-Bypass) und festem 30s-Timeout. Die
operator-konfigurierte Such-`base_url` ist davon ausgenommen (darf bewusst eine
interne SearXNG sein) — nur ihr Scheme wird geprueft.

**Defense-in-Depth (Deployment):** zusaetzlich empfohlen, den
`research-worker`-Container per Egress-Firewall auf die Allowlist-Hosts zu
beschraenken und ihm **keinen** Zugriff auf interne Dienste ausser der DB zu
geben (er braucht nur `db` + Internet-Egress, **nicht** `app` oder andere
interne Hosts). Restrisiko DNS-Rebinding (TOCTOU zwischen Auflösung und Connect)
ist dokumentiert in TD-019 — fuer den niederfrequenten on-demand-Charakter
vernachlaessigbar, eine pin-to-resolved-IP-Lösung waere der naechste Schritt.

### Such-Backend-Empfehlung: SearXNG (self-hosted, $0)

Empfohlener Default ist eine **self-hosted SearXNG-Instanz**: kein API-Key,
keine Per-Query-Kosten, kein Free-Tier-Treadmill (passt zum Fathometer-Modell).
Optional mit Basic-Auth (`upstream_search_username` + Fernet-verschluesseltes
Passwort). Verprobt lieferte SearXNG bessere Treffer als die paid-APIs
(Tavily/Serper/Firecrawl). Paid-APIs brauchen einen Fernet-verschluesselten
API-Key (`upstream_search_api_key_encrypted`).

### Modell

Geteilter LLM-Provider wie Risk-Reviewer/Chat (ein `llm_base_url`/Key), aber
**eigenes Modell** (`llm_research_model`, App-Default
`deepseek-ai/DeepSeek-V4-Flash`). **Tipp:** ein grosses Reasoning-/Thinking-
Modell erhoeht die Treffsicherheit deutlich (Spike-Befund ADR-0063 §Modell);
schwache Instruction-Follower halluzinieren und sind ungeeignet. Such-/
Fetch-Kosten sind $0 (SearXNG + lokales Fetch), nur LLM-Tokens fallen an
(Cent-Bereich pro Lauf, gecached pro `(Artefakt, installierte Version)`).

---

## Why container vulnerabilities do not appear (ADR-0067)

The agent scans the live root filesystem (`trivy rootfs /`) but, by design,
**excludes the well-known container-runtime data-roots**:

- `**/io.containerd.runtime.*.task` (live running-container rootfs under the `/run` task tree — all containerd distros)
- `**/io.containerd.snapshotter.*` (unpacked image layers / snapshots — all containerd distros)
- `/var/lib/docker` (Docker overlay2 layers)
- `/var/lib/containerd` (containerd snapshot store)
- `/var/lib/rancher/k3s/agent/containerd` (k3s embedded containerd)
- `/var/lib/containers` (podman / CRI-O storage)
- `/run/containers` (podman / CRI-O runtime state)

The two `io.containerd.*` glob entries were added by TICKET-019 so the **live**
running-container rootfs under `/run/.../io.containerd.runtime.*.task/` is now
excluded too, not just the persistent stores — covering all containerd distros
(k3s/RKE2/k0s/MicroK8s/standalone/CRI) distro-agnostically.

The contents of those directories are **unpacked container-image layers**, and
container-image scanning is out of scope for Fathometer (ARCHITECTURE §17). So if
an operator expects to see CVEs from a containerized application (e.g. a GitLab
Omnibus image, a Postgres container) on the host's finding list — those are not
collected, and that is intentional. Host OS package databases (`/var/lib/dpkg`,
`/var/lib/rpm`, `/lib/apk/db`) and statically installed host binaries (k3s,
tailscale, the etcd version compiled into the k3s binary) live **outside** these
roots and remain fully covered.

This also fixes a failure mode: before ADR-0067, `rootfs /` descended into the
image layers, the file tree exploded, and the scan tripped Trivy's silent
5-minute default timeout — the agent exited "scan failed" before sending anything,
so the host ingested **no** data at all, and the systemd-timer retry hit the same
cause every cycle.

### Tuning

| Variable | Default | Note |
|---|---|---|
| `FM_SCAN_SKIP_DIRS` | _(empty)_ | Comma-separated absolute paths appended to the built-in list. Use for a Docker `data-root` / podman `graphroot` relocated via `daemon.json` / `storage.conf` (not auto-discovered). |
| `FM_SCAN_TIMEOUT` | `5m` | Explicit `--timeout` for the `rootfs` scan. |

**Rule of thumb:** a scan that still exceeds 5 minutes after the built-in skips
is a signal to **exclude more** (`FM_SCAN_SKIP_DIRS`), not to blindly raise
`FM_SCAN_TIMEOUT`. Raising the timeout is the deliberate choice only for a host
with a genuinely large *in-scope* tree.

### Cleaning up stale container-layer findings

Older successful Docker scans (image tree small enough to finish under the old
default) may have ingested findings whose `target_path` is under a data-root.
After upgrading the agent these stop appearing in the scan set; the ingest's
resolve phase marks findings absent from the current scan as `RESOLVED`
(ADR-0052) — they age out on the next successful scan, no manual cleanup needed.
To check whether any such rows exist (advisory, not a migration):

```sql
SELECT count(*) FROM findings
WHERE target_path LIKE '/var/lib/docker/%'
   OR target_path LIKE '/var/lib/containerd/%'
   OR target_path LIKE '/var/lib/containers/%'
   OR target_path LIKE '/var/lib/rancher/k3s/agent/containerd/%'
   OR target_path LIKE '/run/%/containerd/%'
   OR target_path LIKE '/run/containers/%';
```
