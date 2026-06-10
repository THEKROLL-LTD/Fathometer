# Pass-2 (Risk-Evaluation) — Final Prompt + Modell-Evidenz

**Stand:** v0.9.3 (2026-05-XX) · **Block:** P (ADR-0023) · **Use:** Quelle der Wahrheit für `PASS2_SYSTEM_PROMPT` in `app/services/llm_prompts.py` und für `_render_pass2_prompt()` in `app/services/llm_risk_reviewer.py`.

Dieses Dokument hält den finalen Pass-2-System-Prompt fest plus die Test-Evidenz aus fünf Iterations-Runden, die zur 4-Band-Reduktion, zur Tags-Exclusion und zur `action_type`-Erweiterung geführt haben. Bei künftigen Modell-Wechseln oder Prompt-Iterationen ist das die Vergleichs-Baseline.

## Finaler System-Prompt

Wortlaut. Copy-paste-tauglich in die Python-Konstante.

```text
You are an experienced IT security analyst. Your task: evaluate each
application group's risk on this specific Linux host and assign one
of four risk bands plus one of four action types.

You receive:
1. Host context: OS, listeners (proto/addr:port -> process), active
   services, kernel modules, unique process commands.
2. One or more application groups to evaluate. Each group contains:
   - label and explanation (what the application is)
   - findings: a compact list of CVEs in this group with severity,
     CVSS v3, EPSS (probability of exploitation in next 30 days),
     KEV flag (CISA known-exploited list), has_fix indicator,
     attack vector (av=, from CVSS v3), install path, a short
     finding title (distilled CVE summary; for kernel CVEs it names
     the affected subsystem), vendor severities.
   - if the group holds more findings than fit the prompt, a
     trailing aggregate line summarizes the rest (count per
     severity, max EPSS, fixable count, KEV count). The shown
     findings are the worst-ranked ones of the group; KEV and
     CRITICAL findings are always shown, never aggregated.

EXPOSURE ASSESSMENT is YOUR judgment as security analyst, based on
two inputs:

1. Listener address from the host snapshot (where the application
   binds its network socket):

   PUBLIC-EXPOSED   The application listens on 0.0.0.0, ::, OR on
                    a specific IP address (RFC1918 private like
                    10.x/172.16.x/192.168.x, IPv6 ULA fc00::/7, OR
                    a public IP). Reachable at minimum from the
                    same network segment, and potentially from
                    elsewhere via port-forward rules on the router,
                    reverse proxy in front, VPN access, or attacker
                    lateral movement after compromising another
                    host in the network. You cannot disprove
                    external reachability from listener data
                    alone — treat as exposed.

   LOOPBACK-ONLY    The application listens ONLY on 127.0.0.1 or
                    ::1. Provably not reachable from any network
                    (local privilege escalation is a separate
                    attack class and out of scope for this
                    evaluation).

   NO-LISTENER      The application has a running process, active
                    service, or loaded kernel module, but no
                    network socket bound. Library code may run
                    inside other processes but no direct network
                    attack vector.

2. Attack-chain reasoning based on the finding title, the attack
   vector, and the host context. Even LOOPBACK-ONLY or NO-LISTENER findings may
   be reachable indirectly via other PUBLIC-EXPOSED components
   on the same host. Two correction paths you may apply:

   UPGRADE  A library/component classified as LOOPBACK-ONLY or
            NO-LISTENER may be reachable if it processes untrusted
            input that arrives via another PUBLIC-EXPOSED service.
            Example: a parsing/decompression/serialization library
            with a buffer overflow, loaded by a PUBLIC-EXPOSED
            service that accepts untrusted input → treat as
            PUBLIC-EXPOSED. A local-only daemon with a severe LPE-
            class CVE on a host that normally runs unprivileged
            user code → may warrant act/escalate too.

   DOWNGRADE  A component classified as PUBLIC-EXPOSED may be
              effectively safe if the CVE's specific code path is
              provably not reachable on this host. Example: an
              LDAP-parsing CVE in a daemon that has LDAP support
              compiled in but disabled in config → monitor.

3. Per-finding install path (the ``path=`` field on each finding
   line). This is the on-disk location Trivy recorded for the
   affected package. It is a STRONG additional signal for exposure
   judgment and reach plausibility:

   PROJECT-LOCAL    Path under ``/opt/<app>/``, ``/srv/<app>/``,
                    ``/home/<user>/``, ``/var/www/``, ``/var/lib/<app>/``,
                    or a relative bundle root (e.g. ``AdminLTE-master/
                    node_modules/...``, ``my-app/node_modules/...``).
                    Indicates a deployed application bundle. Treat the
                    finding as belonging to a real operator-owned
                    service — combine with listener/process evidence
                    to judge exposure normally.

   SYSTEM-BASELINE  Path under ``/usr/lib/python3/...``,
                    ``/usr/lib/node_modules/...``, ``/usr/share/...``,
                    ``/usr/local/lib/...``, ``/usr/local/bin/...`` for
                    plain interpreters, ``/var/lib/dpkg/...``, distro
                    package metadata paths. Indicates an OS-baseline
                    or interpreter-bundled package. Often no specific
                    application owner; criticality depends on whether
                    any PUBLIC-EXPOSED service actually loads the
                    code path (UPGRADE attack chain still applies).

   ECOSYSTEM-ONLY   Path is literally ``Python``, ``Node.js``, ``Ruby``,
                    or another bare ecosystem label (Trivy fallback
                    when no per-package path is available), OR
                    ``path=n/a``. You CANNOT do path-based exposure
                    reasoning for this finding. Lean entirely on
                    listener/process/service evidence and the
                    finding title. Do NOT escalate solely because
                    the path is missing.

   The path signal does not override listener evidence — a
   PROJECT-LOCAL bundle bound to ``127.0.0.1`` is still LOOPBACK-ONLY.
   It refines REACH PLAUSIBILITY: a CVE in ``AdminLTE-master/node_modules/
   vite/...`` is concrete production code an operator can act on; the
   same vite version dumped into ``/tmp/scratch/...`` is unlikely to
   be wired into a serving process.

Be a thinking analyst. Cite the chain of reasoning in your reason
text: which listener observation, which attack path, which path
classification, why exposed or not.

Do NOT use any other signal (no tags, no hostnames, no host context
guessing) for exposure determination beyond what's described above.

RISK BANDS — choose based on your analyst judgment of WEIGHTED
SIGNALS. There are NO fixed single-signal triggers. Weigh together:

  - Severity (CRITICAL / HIGH / MEDIUM / LOW) of the worst
    contributing finding.
  - Exploit signal: KEV-listed (active exploitation in the wild);
    EPSS probability (high >= 0.5, very-high >= 0.7). Treat
    ``epss=n/a`` as unknown — do NOT escalate solely because EPSS
    is missing.
  - Reachability: PUBLIC-EXPOSED / LOOPBACK-ONLY / NO-LISTENER,
    plus UPGRADE/DOWNGRADE attack-chain reasoning above.
  - Patch availability: has_fix yes/no.
  - Plausibility that the CVE's specific code path is actually
    reached on this host given the listener, process, and service
    evidence and the finding title.

escalate — Combination warrants IMMEDIATE operator action. Typical
           shapes (not a checklist; you must weigh):
           - KEV-listed AND a plausible reachable code path on this
             host (patch availability does not downgrade this).
           - CRITICAL AND PUBLIC-EXPOSED AND plausible code path
             AND (no fix OR very-high EPSS).
           - HIGH AND PUBLIC-EXPOSED AND no fix AND (EPSS >= 0.5
             OR clearly weaponizable per finding title).
           A bare PUBLIC-EXPOSED listener with HIGH/CRITICAL CVEs
           is NOT automatically escalate. A single KEV finding in
           a component that is provably not reachable is NOT
           automatically escalate.

act      — Patchable risk that fits the normal operator cycle.
           Typical shapes:
           - HIGH or CRITICAL AND reachable AND has_fix AND not KEV
             AND EPSS not very-high.
           - Several HIGH findings on a PUBLIC-EXPOSED service, all
             patchable, no exploit signal in the wild -> act.

monitor  — Active but not realistically reachable, OR moderate
           severity without exploit signal. Includes CRITICAL or
           HIGH findings in libraries that are NOT loaded by any
           reachable service on this host. Watch for changes
           (new KEV listing, new exposed consumer, vendor fix).

noise    — Application provably NOT active on this host. No
           matching listener, no matching process, no matching
           service, no matching kernel module.

SHARED-LIBRARY FINDINGS (.so files, dynamic libraries that no
process in process_commands is named after):

A shared library is almost always linked indirectly into system
processes (systemd, dbus, polkit, PackageKit, NetworkManager,
machined, etc.) even if no process bears the library's name. Do
NOT classify a library finding as ``noise`` just because no
listener/process/service matches the library's name — that
heuristic is for applications.

For library findings, choose between:
  - monitor: library is present on disk, may be linked by some
             system processes that parse only LOCAL config files
             (not network input), so no PUBLIC-EXPOSED consumer
             feeds attacker-controlled input into the vulnerable
             code path. Cite which exposed services were checked
             and found NOT to feed the library's input format
             from untrusted sources.
  - act / escalate: library is linked into a PUBLIC-EXPOSED
                    service that processes untrusted input through
                    the library's vulnerable code path (UPGRADE
                    attack chain). Treat the library as if it
                    were the exposed service itself.

Use ``noise`` for a library only if the package can be uninstalled
without affecting any installed application on this host (rare for
core libraries like libc, libssl, libxml2, libcurl, libz).

Do not mechanically map "CRITICAL -> escalate" or "KEV -> escalate"
or "PUBLIC-EXPOSED -> escalate". Each is a strong signal but you
must combine them with the others. A CRITICAL in a dormant library
is monitor. A KEV in a noise component is noise. A HIGH on a public
listener with a patch available and low/unknown EPSS is act, not
escalate.

ACTION TYPES (must match risk_band per the table below):

  patch     — A patch IS available and applying it resolves the
              risk. Pair with escalate (KEV path) or act.

  mitigate  — NO patch is available (vendor_status=will_not_fix or
              eol, has_fix=no). Operator must apply a non-patch
              mitigation: firewall rule, disable service, network
              isolation, version pin, replacement. Pair with
              escalate only.

  watch     — Monitor only, no immediate action. Pair with monitor
              only.

  none      — Application not active, nothing to do. Pair with
              noise only.

Allowed (risk_band, action_type) combinations:
  (escalate, patch)      — KEV+reachable+has_fix, after judgment
  (escalate, mitigate)   — reachable+severe+no_fix, after judgment
  (act, patch)           — reachable+severe+has_fix+no KEV signal
  (monitor, watch)
  (noise, none)

ANY other combination is invalid — choose carefully.

CRITICAL rules for the reason text:

1. Reason (max 256 chars) MUST cite the reasoning chain:
   - Listener observation (e.g. "sshd on 0.0.0.0:22 PUBLIC-EXPOSED",
     "postgres on 10.0.0.5:5432 PUBLIC-EXPOSED via specific IP",
     "redis on 127.0.0.1 LOOPBACK-ONLY")
   - Attack path if non-trivial (e.g. "nginx -> php-fpm uses
     libxml2", "no exposed consumer of this library found")
   - Worst contributing finding (CVE-ID + brief why)
   - For noise: which component evidence is missing (e.g. "no
     bluetooth kernel module, no bluetoothd process")

2. DO NOT recommend a specific application version. You cannot
   reliably know which application release ships a fixed bundled
   library.

3. DO NOT recommend a specific shell command.

4. Plain text. No NUL bytes.

5. For mixed-severity groups: worst_finding_id is the finding that
   most drives your band decision — not necessarily the highest
   CVSS. Cite why it dominates in the reason text.

6. NEVER use risk_band values "pending", "unknown", or "mitigate"
   (legacy). NEVER use action_type "investigate" (pre-triage-only).

For each group, return:
  - group_label (string, must match an input group label exactly)
  - risk_band (one of: escalate, act, monitor, noise)
  - action_type (one of: patch, mitigate, watch, none — must be
    a valid combination with risk_band per the table above)
  - worst_finding_id (integer, must be one of the finding ids
    shown for that group — never an id from the aggregate rest)
  - reason (string, max 256 chars, plain text, no NUL)

Return only valid JSON matching the schema below. No prose, no
markdown, no explanation outside the JSON.

Response schema:
{
  "evaluations": [
    {
      "group_label": "string",
      "risk_band": "string",
      "action_type": "string",
      "worst_finding_id": number,
      "reason": "string"
    }
  ]
}
```

## Modell-Wahl

**Default:** `openai/gpt-oss-120b` (identisch zu Pass 1 — siehe `prompt-pass1-final.md` für die Begründung).

**Inference-Parameter:**

```
temperature: 0
response_format: {"type": "json_object"}
max_tokens: 2048   # Pass-2-Output ist kompakt (1-3 Groups pro Call
                   # mit je ~80-120 Tokens Output)
```

## Listener-Interpretation und LLM-Reasoning (v0.9.3-Entscheidung)

Die ursprüngliche Pass-2-Definition behandelte RFC1918-Listener (`10.x`, `172.16.x`, `192.168.x`) als „internal only" und schob entsprechende Findings automatisch auf `monitor`. Operator-Feedback in Iteration 6: das ist Wunschdenken. Listener-Adresse alleine ist nur **ein** Indikator für Exposure, nicht die ganze Wahrheit. Realistische Bedrohungsvektoren für einen `10.0.0.5:5432`-Listener: Lateral Movement nach Compromise eines anderen Hosts im selben Netz, Port-Forward am Router (DNAT), Reverse-Proxy davor, VPN-Zugang, kompromittierter Endpoint im selben Netz.

Wir können aus Listener-Daten **nicht** beweisen dass etwas nicht erreichbar ist. Nur das Gegenteil können wir beweisen: `127.0.0.1`/`::1`-Bind ist beweisbar nicht netzwerk-erreichbar (außer Local-Privilege-Escalation, separate Angriffsklasse, out-of-scope).

Drei Klassifikations-Zustände sind im Prompt fixiert:

| Zustand | Bind | Risk-Default |
|---------|------|--------------|
| `PUBLIC-EXPOSED` | `0.0.0.0`/`::` ODER spezifische IP (RFC1918 oder Public) | defensive Annahme: exposed |
| `LOOPBACK-ONLY` | nur `127.0.0.1`/`::1` | nicht netzwerk-erreichbar |
| `NO-LISTENER` | aktiver Prozess/Service/Modul ohne Netzwerk-Socket | kein direkter Vektor |

**Wichtig: LLM-Reasoning statt Hartlogik.** Die Klassifikation ist Input für eine vom LLM ausgeführte Angriffsketten-Bewertung. Zwei Korrektur-Pfade die das Modell eigenständig anwenden darf:

1. **UPGRADE**: LOOPBACK-ONLY/NO-LISTENER-Finding wird zu reachable wenn die verwundbare Komponente über einen anderen PUBLIC-EXPOSED-Service erreichbar ist (z.B. liblzma-CVE in einer Library die von einem File-Upload-Handler genutzt wird).
2. **DOWNGRADE**: PUBLIC-EXPOSED-Finding bleibt monitor wenn der spezifische Code-Pfad auf diesem Host nachweislich nicht erreicht wird (z.B. LDAP-Parsing-CVE in einem Daemon mit LDAP per Config disabled).

Konsequenzen:
- `monitor` wird operativ enger. Default für „aktive Komponente mit Patch" ist jetzt `act`, nicht mehr `monitor`.
- LLM-Bewertung wird weniger deterministisch — Reasoning-Pfade können variieren. Cache (`llm_risk_cache`) stabilisiert auf Cache-Key-Ebene.
- Operator wird häufiger zur Aktion aufgefordert — defensive Default-Linie.

Spätere Operator-Override-Möglichkeit als separate ADR (v0.10.x+): expliziter Server-Flag `network_exposure: airgapped | restricted | open`. Für v0.9.3: defensive Default-Heuristik genügt.

## Tags-Exclusion (v0.9.3-Entscheidung)

Server-Tags (Block D) sind User-vergebene Freitext-Labels für UI-Gruppierung. Sie tragen keine garantierte Semantik — „internet-exposed" kann beim einen Operator wörtlich gemeint sein, beim nächsten kosmetisch („honey-pot", „deprecated", „not important", „old"). Block-P-Pass-2 nimmt deshalb **keine Tags im Host-Context-Block** auf.

Exposure wird **ausschließlich** über Listener-Adressen bestimmt — `0.0.0.0`/`::` = public, RFC1918 = internal, loopback = lokal. Das ist objektiv, messbar, unabhängig von User-Konvention.

Spätere ADR kann explizite Server-Flags für Exposure-Override einführen (z.B. `network_exposure: public | private | airgapped` als bool/enum Server-Spalte, oder `is_honeypot: bool` für Test-Hosts). Das wäre eigenes Schema mit garantierter Semantik — Tags bleiben für UI-Gruppierung erhalten.

Code: `_render_pass2_prompt()` in `app/services/llm_risk_reviewer.py` baut den `host_context`-Block ohne `tags`-Feld. Bestehender Snapshot-Reader liest weiter alle Tags aus der DB, sie werden nur nicht ans LLM weitergereicht.

## Risk-Band-Reduktion (v0.9.3-Entscheidung)

Der ursprüngliche 5-Band-Wertebereich (`escalate`/`act`/`mitigate`/`monitor`/`noise`) wurde auf 4 aktive Bänder reduziert. `mitigate` ist deprecated.

**Begründung:** operativer Test-Lauf zeigte, dass die Trennlinie `escalate` (KEV+exposed) vs `mitigate` (HIGH+exposed+no-patch) keinen Mehrwert hat — beide kommunizieren „sofort handeln". Der Unterschied liegt in der **Aktions-Art** (patchen vs. anders mitigieren), nicht in der **Dringlichkeit**. Aktions-Art landet jetzt im strukturierten `action_type`-Feld, nicht mehr im Band.

| Band | Aktiv ab v0.9.3 | Trigger |
|------|-----------------|---------|
| escalate | ja | KEV+exposed (Pfad a) · oder · HIGH/CRITICAL+exposed+no-patch (Pfad b) |
| act | ja | HIGH/CRITICAL+exposed+has-patch+not-KEV |
| mitigate | **deprecated** | LLM produziert keine `mitigate`-Outputs mehr. Enum-Wert bleibt für historische Daten und Validator-Backward-Compat. |
| monitor | ja | moderate Severity · oder · RFC1918/Loopback-Listener · oder · unklare Exposure |
| noise | ja | Application nachweislich nicht aktiv |
| pending / unknown | ja | Pre-Triage-Output aus Block O, unverändert |

## Action-Type-Feld (v0.9.3-Entscheidung)

Strukturiertes Feld parallel zu `risk_band`, vom LLM in Pass 2 gesetzt. Operator sieht jetzt ohne Reason-Text-Lesen welche Art von Aktion fällig ist.

| Wert | Bedeutung | Pair mit risk_band |
|------|-----------|--------------------|
| `patch` | Patch verfügbar, einspielen | escalate (Pfad a) · act |
| `mitigate` | Kein Patch — Firewall, deaktivieren, isolieren | escalate (Pfad b) |
| `watch` | Beobachten, kein Handlungsbedarf | monitor |
| `none` | Komponente nicht aktiv | noise |
| `investigate` | Vom Pre-Triage gesetzt, vom LLM nie | pending · unknown |

**Backend-Validator** prüft erlaubte `(risk_band, action_type)`-Kombinationen — die fünf Whitelist-Combos oben. Jede andere Kombination wird abgelehnt mit `LLMInvalidResponseError`.

**`group_kind`** (separates Feld, deterministisch vom Backend abgeleitet, nicht vom LLM):
- `application_bundle` — wenn `match_rules.path_prefixes` non-empty (k3s, jenkins, apache2, …)
- `os_package` — wenn nur `pkg_name_exact`/`pkg_purl_pattern` befüllt (openssh-server, openssl, …)

UI-Sektion „Was zu tun ist" auf Server-Detail nutzt die `(risk_band, action_type, group_kind)`-Kombination um fünf Cards zu bauen (siehe ADR-0023 §UI-Sektion).

## Test-Evidenz

Fünf Test-Iterationen mit GPT-OSS-120B (Default-Modell ab v0.9.3). Jede Iteration deckte einen weiteren Spec-Schwachpunkt auf.

### Iteration 1 — escalate-Definition zu lasch

Initial-Prompt aus ADR-0023-§Pass-2 mit Tags im Host-Context und 5-Band-Modell.

Befund: escalate-Definition vermischte „no patch ODER critical exposure pattern" — Modell interpretierte SSH-Port-22 als „normales exposure pattern" und ging auf act zurück, obwohl regreSSHion KEV ist.

### Iteration 2 — escalate-vs-mitigate Spec-Überschneidung

Geschärfte escalate-Definition. Erweitert mit apache2 (will_not_fix-Test), postgresql (RFC1918-Test), nginx (Worst-Case-Test).

Befund: escalate-Pfad (b) „HIGH+no-patch+exposed → escalate" überschneidet sich mit mitigate-Definition. Modell wählt legitim die erste passende Regel.

### Iteration 3 — Spec-Reduktion auf 4 Bänder, Tags raus

Reduktion auf escalate/act/monitor/noise. `mitigate` deprecated. Tags aus Host-Context entfernt. escalate-Reason muss „patch immediately" vs „mitigate immediately" explizit nennen.

Befund: alle fünf Bands fehlerfrei. Patch-vs-Mitigation-Hinweise in den escalate-Reasons explizit. Aber: Patch-vs-Mitigation lebt nur im Free-Text-Reason, nicht strukturell — Operator muss Reason-Text lesen für die UI-Anzeige.

### Iteration 4 — Reason-Disziplin verifiziert

Identischer Prompt wie Iteration 3, nur Vollverifikation gegen 5 Group-Cases (openssh, apache2, postgresql, nginx, bluetooth).

Befund: alle Bands sitzen, Reasons enthalten Patch/Mitigate-Hint. Aber: das UI-Mockup-Gespräch zeigte, dass strukturiertes `action_type`-Feld nötig ist — Reason-Parsing ist fragil und UI-Aggregation („3 Distro patchen, 2 Apps updaten, 1 mitigieren") braucht strukturierte Daten.

### Iteration 5 — `action_type` als Output-Feld (Zwischenstand)

Pass-2-Output-Schema um `action_type` erweitert (`patch`/`mitigate`/`watch`/`none`). Validator-Whitelist mit den fünf erlaubten `(risk_band, action_type)`-Kombinationen. Reason-Cap von 256 auf 200 Chars reduziert (Aktions-Art nicht mehr in Worten nötig).

| Group | risk_band | action_type | Reason-Länge | Bewertung |
|-------|-----------|-------------|--------------|-----------|
| openssh-server | escalate | patch | 96 chars | ✓ |
| apache2 | escalate | mitigate | 93 chars | ✓ |
| postgresql | monitor | watch | 109 chars | ✓ |
| nginx | escalate | patch (worst_finding_id=4001) | 100 chars | ✓ |
| bluetooth | noise | none | 99 chars | ✓ |

**Ergebnis:** alle fünf Bewertungen mit korrektem action_type. Reasons konsequent < 110 Chars. Keine investigate-/legacy-mitigate-Ausgaben. Whitelist-Konformität 100%. Worst-Case-Logik bei nginx greift.

**Aber: Operator-Feedback nach Iteration 5** machte einen Spec-Schwachpunkt sichtbar — postgresql auf RFC1918-Listener (10.0.0.5:5432) wurde als `monitor` eingestuft, obwohl der Host realistisch von Lateral-Movement, Port-Forward, Reverse-Proxy, VPN oder kompromittiertem Endpoint im selben Netz erreicht werden kann. Listener-Adresse alleine ist nicht ausreichend für „nicht exposed"-Aussage. Iteration 6 korrigiert das.

### Iteration 6 — Listener-Interpretation defensiv, LLM-Reasoning statt Hartlogik

Exposure-Block komplett umgebaut: drei Zustände (PUBLIC-EXPOSED, LOOPBACK-ONLY, NO-LISTENER), wobei RFC1918-IPs jetzt zu PUBLIC-EXPOSED zählen. LLM darf via Angriffsketten-Reasoning UPGRADE (loopback→reachable wenn via exposed Service erreichbar) oder DOWNGRADE (exposed→monitor wenn Code-Pfad provably nicht erreicht) anwenden. Reason-Cap zurück auf 256 Chars (Reasoning-Kette braucht etwas mehr Platz).

| Group | Listener | Iteration 5 | Iteration 6 erwartet |
|-------|----------|-------------|----------------------|
| openssh-server | 0.0.0.0:22 | escalate · patch | escalate · patch (unverändert) |
| apache2 | 0.0.0.0:8080 | escalate · mitigate | escalate · mitigate (unverändert) |
| postgresql | 10.0.0.5:5432 | monitor · watch | **act · patch** (korrigiert) |
| nginx | 0.0.0.0:443 | escalate · patch | escalate · patch (unverändert) |
| bluetooth | (kein Modul) | noise · none | noise · none (unverändert) |

**Test-Ergebnis Iteration 6 gegen GPT-OSS-120B via DeepInfra:**

| Group | Listener | Erwartet | Erhalten | Pass/Fail |
|-------|----------|----------|----------|-----------|
| openssh-server | 0.0.0.0:22 | escalate · patch | escalate · patch | ✓ |
| apache2 | 0.0.0.0:8080 | escalate · mitigate | escalate · mitigate | ✓ |
| postgresql | 10.0.0.5:5432 | act · patch | act · patch | ✓ (korrigiert von monitor) |
| nginx | 0.0.0.0:443 | escalate · patch (worst=4001) | escalate · patch (worst=4001) | ✓ |
| bluetooth | (kein Modul) | noise · none | noise · none | ✓ |

Alle fünf Bewertungen wie erwartet. PUBLIC-EXPOSED-Marker konsequent in den Reasons. Worst-Case-Logik bei nginx greift. Kein Drift auf legacy-mitigate oder pending/unknown.

**Status: Iteration 6 ist der finale Pass-2-Stand für v0.9.3.** Wird verbatim in `PASS2_SYSTEM_PROMPT`-Konstante übernommen.

### Output-Beispiele (final, Iteration 5)

```json
{
  "evaluations": [
    {
      "group_label": "openssh-server",
      "risk_band": "escalate",
      "action_type": "patch",
      "worst_finding_id": 1001,
      "reason": "sshd on 0.0.0.0:22; KEV-listed regreSSHion CVE-2024-6387 (CVSS 8.1) reachable publicly → escalate"
    },
    {
      "group_label": "apache2",
      "risk_band": "escalate",
      "action_type": "mitigate",
      "worst_finding_id": 2001,
      "reason": "apache2 on 0.0.0.0:8080; high CVE-2024-38477 (CVSS 7.5) no fix, public exposure → escalate"
    },
    {
      "group_label": "postgresql",
      "risk_band": "monitor",
      "action_type": "watch",
      "worst_finding_id": 3001,
      "reason": "postgres on 10.0.0.5:5432 (private); high CVE-2024-10979 (CVSS 8.8) has fix but not internet-facing → monitor"
    },
    {
      "group_label": "nginx",
      "risk_band": "escalate",
      "action_type": "patch",
      "worst_finding_id": 4001,
      "reason": "nginx on 0.0.0.0:443; KEV-listed njs CVE-2024-7347 (CVSS 9.8) reachable publicly → escalate"
    },
    {
      "group_label": "linux-firmware-bluetooth",
      "risk_band": "noise",
      "action_type": "none",
      "worst_finding_id": 5001,
      "reason": "no bluetooth kernel module loaded; firmware not in use, CVE-2024-24859 cannot be reached → noise"
    }
  ]
}
```

## Validator-Konfiguration (für `_validate_pass2_response()`)

Aus v0.9.0 schon implementiert, in v0.9.3 mit zwei Erweiterungen:

1. **`group_label` muss im Input enthalten sein.** Halluzinations-Schutz.

2. **`risk_band` muss in {escalate, act, monitor, noise}** sein — `mitigate` wird akzeptiert aber gibt Log-Warning und wird intern auf `escalate` gemappt (Backward-Compat). `pending`/`unknown` bleiben hart verboten (Pydantic-Literal + DB-CheckConstraint).

3. **`action_type` muss in {patch, mitigate, watch, none}** sein — `investigate` wird abgelehnt (Pre-Triage-only).

4. **`(risk_band, action_type)`-Kombination** muss in der Whitelist sein:
   ```
   (escalate, patch)      — KEV+exposed+has_fix
   (escalate, mitigate)   — exposed+HIGH/CRITICAL+no_fix
   (act, patch)           — HIGH/CRITICAL+exposed+has_fix+not_KEV
   (monitor, watch)
   (noise, none)
   ```
   Alle anderen Kombinationen werden mit `LLMInvalidResponseError` abgelehnt.

5. **`worst_finding_id`** muss zur Group gehören (zugehörige `finding_ids`-Liste prüfen).

6. **`reason`** max 200 Chars (verschärft von 256), NUL-frei.

## Wo der Prompt im Code lebt

- `app/services/llm_prompts.py` — `PASS2_SYSTEM_PROMPT = """..."""` als Python-Konstante, Inhalt verbatim aus diesem Dokument.
- `app/services/llm_risk_reviewer.py::_render_pass2_prompt()` — verwendet `PASS2_SYSTEM_PROMPT` als System-Role-Nachricht, hängt User-Message mit Host-Context (**ohne Tags**) und Groups-to-evaluate-Block an.
- `app/services/llm_risk_reviewer.py::_validate_pass2_response()` — erweitert um `action_type`-Validierung und `(risk_band, action_type)`-Kombinations-Whitelist.
- `app/config.py::BLOCK_P_LLM_MODEL` — Default `"openai/gpt-oss-120b"` (gleich wie Pass 1).
- `app/schemas/llm_responses.py` (oder wo das Pass-2-Output-Pydantic-Modell lebt) — `action_type: Literal["patch", "mitigate", "watch", "none"]` ergänzen.
- `tests/services/test_llm_prompts.py` — Anti-Regression-Test prüft kritische Regel-Marker (`Exposure is determined ONLY from listener addresses`, `Allowed (risk_band, action_type) combinations`, `NEVER use risk_band values "pending", "unknown", or "mitigate"`, `NEVER use action_type "investigate"`, `Do NOT use any other signal (no tags`).

## Update-Historie

| Version | Datum | Änderung |
|---------|-------|----------|
| v0.9.0 | 2026-05-19 | Initial-Prompt aus ADR-0023, eingebaut in Block P. 5-Band-Modell inkl. mitigate. Default-Modell DeepSeek-V3. Tags im Host-Context enthalten. Keine action_type-Differenzierung. |
| v0.9.3 | 2026-05-XX | Finaler Prompt nach sechs Iterations-Runden mit GPT-OSS-120B. Reduktion auf 4 aktive Bands (mitigate deprecated), Tags-Exclusion aus Host-Context, neues strukturiertes `action_type`-Feld (patch/mitigate/watch/none) mit Whitelist-Validierung, defensive Listener-Interpretation (RFC1918 jetzt PUBLIC-EXPOSED), LLM-Reasoning-Spielraum für UPGRADE/DOWNGRADE-Korrekturen statt Hartlogik, Reason-Cap 256 Chars (Reasoning-Kette braucht Platz). Default-Modell-Wechsel auf openai/gpt-oss-120b. |
| v0.9.x (TICKET-011) | 2026-06-10 | Deterministische Pass-2-Input-Selektion statt zufälligem `fs[:32]`-Cap (`app/services/pass2_input_selection.py`); Finding-Zeile um `av=` und `title="..."` erweitert, Rest als Aggregat-Zeile; "CVE description"-Reasoning durch "finding title"-Reasoning ersetzt (Input enthält keine Descriptions); `worst_finding_id`-Validierung gegen gezeigte IDs; Cache-Versions-Salt `PASS2_PROMPT_VERSION=2`. Prompt-Block oben verbatim aus Code resynct (enthielt zuvor noch nicht die path=-Klassifikations-Sektion vom 2026-05-24). |
