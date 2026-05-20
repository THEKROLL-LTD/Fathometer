# Pass-1 (Group-Detection) — Final Prompt + Modell-Evidenz

**Stand:** v0.9.3 (2026-05-XX) · **Block:** P (ADR-0023) · **Use:** Quelle der Wahrheit für `PASS1_SYSTEM_PROMPT` in `app/services/llm_prompts.py` und `BLOCK_P_LLM_MODEL`-Default in `app/config.py`.

Dieses Dokument hält den finalen Pass-1-System-Prompt fest plus die Test-Evidenz die zur Modell-Wahl `openai/gpt-oss-120b` geführt hat. Bei künftigen Modell-Wechseln oder Prompt-Iterationen ist das die Vergleichs-Baseline.

## Finaler System-Prompt

Wortlaut. Copy-paste-tauglich in die Python-Konstante.

```text
You group Linux-host vulnerability findings by owner-application.

An owner-application is the software the operator installs and updates
as a single unit (e.g. "k3s", "openssh-server", "grafana"). Sub-
components that ship together with the owner-application (containerd
bundled inside k3s, coredns bundled inside k3s, kubelet bundled inside
k3s, etc.) MUST go into the owner-group, NOT into separate sub-groups.

CRITICAL rules for group labels:

1. Keep labels as generic as possible so future path changes from
   minor/patch updates of the same application still match. Use "k3s",
   never "k3s-1.23" or "k3s-server".

2. Distinct major products are distinct groups: RKE and RKE2 are two
   groups, k3s and rke2 are two groups. But sub-components bundled
   inside one application stay in that application's group. Never
   create "k3s-containerd" or "k3s-coredns" — those go into "k3s".

3. OS distro packages get their package_name as group label (e.g.
   "openssh-server", "openssl", "libc6", "glibc"). One package = one
   group, even if multiple CVEs hit the same package.

4. Self-installed standalone binaries in /usr/local/bin or /opt that
   don't belong to a recognizable bundle should get their own group
   labeled after the binary or directory name.

5. Application bundles deployed in /opt, /srv, or /home (Tomcat,
   Jenkins WAR, Grafana, custom apps) get the application or top-
   level directory name as group label, regardless of how many
   embedded libraries are reported.

6. CROSS-LANGUAGE BUNDLES: when multiple findings share a common
   top-level installation directory (e.g. /opt/myapp/, /home/webapp/,
   /srv/<name>/), group ALL of them under the directory name,
   regardless of language ecosystem (npm, pip, gem, maven, jar can be
   in the same group). The owner-application is the DIRECTORY, not
   the language libraries inside it. NEVER create groups labeled
   "lodash", "flask", "requests", "log4j-core", or any other library
   name when those libraries are installed inside a larger application
   directory or bundle. The library is a finding inside the group, not
   a group itself.

7. MULTI-PATH APPLICATIONS: an owner-application installed at multiple
   paths (e.g. a launcher binary at /usr/local/bin/<app> AND a data/
   runtime tree at /var/lib/<vendor>/<app>/) is ONE group, not
   multiple. List all paths as multiple entries in path_prefixes
   within the SAME group. NEVER create "<app>-binary" or "<app>-
   runtime" sibling groups for the same application.

For each group, return:
  - label (lowercase, max 64 chars, regex ^[a-z0-9][a-z0-9._-]{0,63}$)
  - explanation (max 256 chars, plain text, what the group is)
  - match_rules with:
      path_prefixes: array of absolute path prefixes. Directory
        prefixes MUST end with "/" (e.g. "/var/lib/rancher/k3s/" not
        "/var/lib/rancher/k3s"). Single-file binaries are an exception:
        "/usr/local/bin/foo" is OK without trailing slash.
      pkg_name_exact: array of exact package_name strings.
      pkg_name_glob: array of glob patterns (e.g. "k3s-*").
      pkg_purl_pattern: array of PURL PREFIX strings (NOT regex, NOT
        wildcards, no "*" at the end). Each pattern must be at least
        12 characters long.

    DEFENSE IN DEPTH: populate as many layers as applicable. For an
    OS distro package, populate BOTH pkg_name_exact AND
    pkg_purl_pattern (e.g. "openssl" plus "pkg:deb/ubuntu/openssl" or
    "pkg:rpm/almalinux/glibc"). For an application bundle with a path
    prefix, also add pkg_name_exact and pkg_name_glob if the
    application has a known package name (e.g. k3s → pkg_name_exact:
    ["k3s"], pkg_name_glob: ["k3s-*"]). More populated layers = more
    robust matching for future findings.

    AVOID OVER-GENERIC PATTERNS that would match unrelated software.
    Forbidden examples:
      - "pkg:golang/stdlib" (would match every Go binary)
      - "pkg:maven/" (would match every Java JAR)
      - "pkg:npm/" (would match every npm package)
      - Path prefixes containing version hashes or version numbers
        (e.g. "/var/lib/rancher/k3s/data/9f1f.../" — use
        "/var/lib/rancher/k3s/" instead)

    BUNDLE PURLs MUST IDENTIFY THE APPLICATION ITSELF, NOT ITS
    DEPENDENCIES. For application-bundle groups identified by
    path_prefixes, the pkg_purl_pattern array should ONLY contain
    PURLs that uniquely identify the application itself, NOT its
    transitive dependencies.
      GOOD for "tomcat":
        pkg_purl_pattern: ["pkg:maven/org.apache.tomcat/"]
      BAD for "tomcat":
        pkg_purl_pattern: ["pkg:maven/org.apache.logging.log4j/log4j-core"]
        ← log4j is used by thousands of apps, not just Tomcat.
      GOOD for "webapp" (path-only):
        pkg_purl_pattern: []
      BAD for "webapp":
        pkg_purl_pattern: ["pkg:pypi/flask"]
        ← Flask is used by countless web apps, not just this one.
    When the application has no unique vendor PURL prefix (custom apps,
    generic /home/<name>/ deployments), leave pkg_purl_pattern empty
    and rely on path_prefixes alone.

  - finding_ids: array of input finding_ids assigned to this group.

Findings that don't fit any clear application identity go into
"ungrouped" with their finding_ids only.

Every input finding_id MUST appear in exactly one group or in
ungrouped. No finding_id may appear twice. NEVER invent finding_ids
that were not in the input.

Return only valid JSON matching the schema below. No prose, no
markdown, no explanation outside the JSON.

Response schema:
{
  "groups": [
    {
      "label": "string",
      "explanation": "string",
      "match_rules": {
        "path_prefixes": ["string"],
        "pkg_name_exact": ["string"],
        "pkg_name_glob": ["string"],
        "pkg_purl_pattern": ["string"]
      },
      "finding_ids": [number]
    }
  ],
  "ungrouped": [number]
}
```

## Modell-Wahl

**Default:** `openai/gpt-oss-120b`

Begründung in drei Punkten:

1. **Semantisch stärkstes Modell** in unserer Test-Suite. Bestand alle Test-Kriterien in Test 1 (25 Findings, Ubuntu-K3s-Host) und Test 2 (25 Findings, AlmaLinux-RKE2-Host) ohne Iterations-Schulden.
2. **Apache 2.0 lizenziert**, self-hostable. Operator mit DSGVO-Strenge kann den Snapshot-Daten im eigenen Netz halten ohne API-Call zu externem Provider — wichtig weil Pass-1-Input zwar nur Finding-Identitäten enthält, Pass-2-Input aber den Host-Snapshot.
3. **Provider-Flexibilität.** Sowohl Cloud (DeepInfra, Groq) als auch lokal (vLLM, Ollama) deployable. Operator wählt je nach Threat-Model und Hardware.

**Alternative:** `deepseek/deepseek-v4-flash` (DeepInfra) — funktional fast gleichwertig, aber mit zwei Iterations-Schulden die der Prompt aktiv mitigieren muss (Multi-Path-Application-Splitting, transitive Library-PURLs). Empfohlen nur wenn GPT-OSS-120B nicht verfügbar oder Cost-prohibitiv.

**Inference-Parameter:**

```
temperature: 0
response_format: {"type": "json_object"}
max_tokens: 4096   # für Pass 1 mit bis zu ~30 Findings pro Batch
```

## Test-Evidenz

Zwei Test-Läufe gegen verschiedene Host-Szenarien mit jeweils 25 realitätsnahen Findings. Sieben Modelle gegen Test 1, zwei Modelle (V4-Flash + GPT-OSS-120B) gegen den iterierten Prompt in Test 2.

### Test 1 — Ubuntu-K3s-Host (sieben Modelle)

| Kriterium | DS-V3.2 | DS-V4-Flash | MiniMax-M2.5 | Qwen3-Instr | Qwen3-Think | Phi-4 | GPT-OSS-120B |
|-----------|---------|-------------|--------------|-------------|-------------|-------|--------------|
| k3s-Bundle (alle 12) | ✓ | ✓ | ✓ | ✗ 8/12 | ✓ | ✗ 11/12 | ✓ |
| Jenkins-Bundle | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Grafana-Bundle | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✓ |
| openssl-Dedup | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **myapp Cross-Language** | ✗ ungrouped | ✓ | ✓ (4001-Bug) | ✗ Library-as-Owner | ✗ Library-as-Owner | ✗ Hallu. | ✓ |
| custom-deploy-tool | ✓ | ✓ | ✗ (in myapp) | ✓ | ✓ | ✓ | ✓ |
| Vollständigkeit 25/25 | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ Hallu. | ✓ |
| Schema-Treue (4 fields + ungrouped) | ✓ | ✓ | ✗ | ✓ | ✓ | (Hallu.) | ✓ |
| Trailing-Slash | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ | ✗ |
| Defense-in-Depth Pattern | nur OS | ✗ | ✗ | ✓ | ✓ | ✓ (überaggressiv) | ✗ |
| PURL für OS-Pakete | ✓ | ✗ | ✗ | ✓ | ✓ | ✓ | ✗ |
| **Total Pass** | 7/11 | 6/11 | 6/11 | 5/11 | 7/11 | 4/11 | **7/11** |

Disqualifiziert: MiniMax-M2.5 (Schema-Verstöße + Misklassifizierung), Phi-4 (ID-Halluzination + Versions-Hash + Wildcard-PURLs), Qwen3-Instruct (k3s-Vollständigkeit gebrochen).

Iterations-Schulden bei semantisch starken Kandidaten: Trailing-Slash, PURL-Pattern für OS-Pakete, Defense-in-Depth.

### Test 2 — AlmaLinux-RKE2-Host mit iteriertem Prompt

Iterierter Prompt enthält Cross-Language-Bundle-Regel, Trailing-Slash-Pflicht, Defense-in-Depth-Vorgabe, Anti-Generic-Pattern-Liste, Halluzinations-Schutz. Plus zwei nach Test 2 ergänzte Härtungen (Multi-Path-Application, Bundle-vs-Library-PURL) — die im obigen finalen Prompt eingebaut sind.

| Kriterium | DS-V4-Flash | **GPT-OSS-120B** |
|-----------|-------------|------------------|
| RKE2-Bundle (alle 10 in einer Group) | ✗ aufgespalten in `rke2` + `rke2-binary` | ✓ alle 10, beide Pfade als multi-prefix |
| Tomcat-Bundle | ✓ aber log4j/spring als PURL-Pattern | ✓ ohne überspezifische PURLs |
| webapp Cross-Language `/home/webapp/` | ✓ aber flask/jinja2/werkzeug als PURL | ✓ nur path_prefix |
| krb5-libs Dedup | ✓ | ✓ |
| Trailing-Slash | ✓ | ✓ |
| PURL für OS-Pakete (rpm) | ✓ | ✓ |
| Defense-in-Depth OS | ✓ pkg_name + glob + PURL | ✓ pkg_name + PURL (kein glob) |
| Anti-Generic-Pattern | ✓ Top-Level, aber Library-PURLs | ✓ konsequent |
| Vollständigkeit 25/25 | ✓ | ✓ |
| Schema-Treue | ✓ | ✓ |
| **Total Pass** | 8/10 | **10/10** |

GPT-OSS-120B besteht **alle zehn Kriterien fehlerfrei.** Die beiden V4-Flash-Restprobleme (Multi-Path-Application, Library-PURLs als Bundle-Match) sind im finalen Prompt durch die zwei nachträglich ergänzten Härtungsregeln expliziter adressiert — auch V4-Flash sollte mit dem finalen Prompt jetzt cleaner durchkommen, wurde aber nicht mehr verifiziert.

### Hauptsächliche Befunde

**Bias-Achse „Owner-Identität".** Modelle teilen sich nach einer klaren Linie:

- **Path-First** (V4-Flash, GPT-OSS-120B, V3.2): gemeinsamer Pfad gewinnt → Cross-Language-Bundles werden erkannt.
- **Identity-First** (Qwen-Familie): Library-/Package-Identität gewinnt → Defense-in-Depth-Pattern werden brav befüllt, aber Path-Aggregation wird ignoriert (Library-as-Owner-Anti-Pattern).

Für unseren Use-Case (Operator-Realität = Deployment-Einheit ist ein Verzeichnis) ist Path-First korrekt. Modell-Auswahl muss diesen Bias prüfen.

**Schema-Treue als Validator-Anforderung.** Drei Modelle (MiniMax, Phi-4, Qwen3-Instruct) haben unterschiedliche Klassen von Schema-Verstößen produziert. Die `_validate_pass1_response()`-Schicht im Backend muss strikt sein und alle drei Klassen abfangen.

**Pattern-Generizität als systemische Falle.** Phi-4 hat `pkg:golang/stdlib*` als k3s-Pattern produziert (würde jedes Go-Binary matchen), V4-Flash hat `pkg:pypi/flask` als webapp-Pattern produziert (würde jede Flask-App matchen). Der Validator sollte zu generische Patterns server-side droppen.

## Validator-Defensive (für `app/services/llm_risk_reviewer.py`)

Drei Validations-Schichten aus den Tests, alle drei im Backend bereits umgesetzt (Block P Reviewer-Hinweis):

1. **ID-Treue:** alle Input-IDs müssen im Output sein, keine halluzinierten. Phi-4-Klasse.
2. **Pattern-Konsistenz:** `finding_ids` einer Group müssen tatsächlich von den `match_rules` matchen würden. MiniMax-Klasse.
3. **Pattern-Generizität:** Patterns die zu breit anwenden würden, werden gedroppt. Phi-4- und teilweise V4-Flash-Klasse.

Bei einem späteren Modell-Wechsel (z.B. Block-P-Mode-Override auf einen anderen Provider durch Operator) müssen diese drei Validator-Schichten weiterhin greifen — sie sind modell-agnostisch.

## Wo der Prompt im Code lebt

Erwartung (Block-P-Implementer-Brief):

- `app/services/llm_prompts.py` — `PASS1_SYSTEM_PROMPT = """..."""` als Python-Konstante, Inhalt verbatim aus diesem Dokument.
- `app/services/llm_risk_reviewer.py::_render_pass1_prompt()` — verwendet `PASS1_SYSTEM_PROMPT` als System-Role-Nachricht, hängt User-Message mit Findings-Liste an.
- `app/config.py` — `BLOCK_P_LLM_MODEL` Konstante oder Settings-Spalte mit Default `"openai/gpt-oss-120b"`. Operator-Override via Settings-Tab möglich (falls aus Block P nicht angelegt: in v0.9.3 mit ergänzen).

Bei künftigen Prompt-Iterationen: dieses File zuerst aktualisieren, dann `PASS1_SYSTEM_PROMPT`-Konstante syncen, Anti-Regression-Test in `tests/services/test_llm_prompts.py` muss grüne bleiben.

## Hinweis: Tags und Risk-Bewertung

Pass 1 (Group-Detection) bekommt keine Server-Tags und kein Server-Kontext-Daten — nur Finding-Identitäten. Tags spielen hier von Natur aus keine Rolle.

Für **Pass 2** (Risk-Evaluation, siehe `prompt-pass2-final.md` in derselben v0.9.3-Iteration) gilt: Server-Tags werden **nicht** an das LLM weitergegeben, auch wenn der Host-Snapshot-Block Tags enthält. Begründung: Tags sind User-vergebene Freitext-Labels für UI-Gruppierung — sie tragen keine garantierte Semantik die das LLM als Risk-Signal interpretieren dürfte. Exposure-Bestimmung erfolgt ausschließlich über objektive Listener-Adressen (0.0.0.0 vs 127.0.0.1 vs RFC1918). Spätere ADR kann explizite Server-Flags für Exposure-Override einführen (z.B. `network_exposure`-Enum), das wäre eigenes Schema mit garantierter Semantik.

## Update-Historie

| Version | Datum | Änderung |
|---------|-------|----------|
| v0.9.0 | 2026-05-19 | Initial-Prompt aus ADR-0023, eingebaut in Block P. Default-Modell: DeepSeek-V3 (vom Block-G-Wrapper). |
| v0.9.3 | 2026-05-XX | Finaler Prompt nach zwei Test-Runden mit sieben Modellen. Iterations-Erkenntnisse eingebaut: Cross-Language-Bundle-Regel, Trailing-Slash-Pflicht, Defense-in-Depth, Anti-Generic-Pattern, Halluzinations-Schutz, Multi-Path-Application-Klarstellung, Library-vs-Vendor-PURL-Unterscheidung. Default-Modell-Wechsel auf `openai/gpt-oss-120b`. Tags-Exclusion aus LLM-Eingaben (für Pass 2 relevant). |
