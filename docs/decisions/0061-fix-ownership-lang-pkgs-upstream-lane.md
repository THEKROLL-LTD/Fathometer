# ADR-0061 — Fix-Ownership: lang-pkgs-Fixes sind nicht host-applizierbar (`upstream`-Lane)

**Status:** Akzeptiert · **Datum:** 2026-06-12 · **Teil-amendiert durch [ADR-0064](0064-upstream-fix-finding-level-not-lane.md) (2026-06-13, Block AK):** Der **Korrektheits-Kern bleibt** (lang-pkgs-Fix ist nicht host-applizierbar, landet nie in `patch`/`act`). Die **separate `upstream`-Lane + Card wird zurückgenommen** — sie kollabiert in `mitigate`, die „Fix existiert upstream"-Info wird Finding-Level-Enrichment (Fix-Version-Anzeige + Upstream-Check-Button pro Row). `fix_lane ∈ {patch, mitigate}` wieder. Begründung: identische Operator-Aktion, keine actionable Foresight für upstream-vs-mitigate, nicht-autoritatives Trivy-Signal (siehe ADR-0064).

Bezug: [ADR-0053](0053-fix-lane-evaluation.md) (Fix-Lane-Evaluation — diese ADR erweitert die Lane-Partition um eine dritte Lane, nutzt deren §Re-Open-Trigger „fix_lane-Enum erweitern statt neuer Tabelle"), [ADR-0043](0043-llm-risk-band-exploitability-model.md) (Risk-Band als Exploitability-Urteil, `action_type` Backend-abgeleitet, Fix-Verfügbarkeit aus dem Band entkoppelt), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Two-Pass-Reviewer), [ADR-0021](0021-agent-bootstrap-installer.md) (Trivy-Ursachen-Felder: `finding_class`, `result_type`), [ADR-0011](0011-lang-pkgs-target-disambiguation.md) (lang-pkgs `@target`-Disambiguation).

## Kontext

ADR-0053 partitioniert die OPEN-Findings einer `(Group, Server)` deterministisch in zwei Fix-Lanes: `patch` (`fixed_version` gesetzt) und `mitigate` (kein `fixed_version`). Die Lane ist die Action-Achse, das LLM bandet nur das Risiko, und `act` ist per Whitelist patch-only.

Diese Zweiteilung verwechselt zwei verschiedene Dinge unter „`fixed_version` ist gesetzt": **dass ein Fix existiert** und **dass der Operator ihn einspielen kann**. Für OS-Pakete (`finding_class == os-pkgs`) stimmt die Gleichsetzung — `fixed_version` heißt `dnf/apt upgrade` wirkt. Für Sprach-Pakete (`finding_class == lang-pkgs`: gobinary, jar, node-pkg, …) ist `fixed_version` die **Dependency-/Toolchain-Version, mit der ein Rebuild erfolgen müsste** — kein Paket, das der Host-Paketmanager liefert.

Konkreter Befund (2026-06-12): CVE-2026-42504 (Go-stdlib MIME-Decode-DoS) wird von Trivy aus der Go-Build-Info im Binary `/usr/sbin/tailscaled` gelesen — `finding_class=lang-pkgs`, `result_type=gobinary`, `PkgName=stdlib`, `fixed_version="1.25.11, 1.26.4"` (Go-Toolchain-Versionen). tailscaled ist public-exposed (`0.0.0.0:41641`), das LLM bandet die `patch`-Lane folgerichtig auf `act` → Operator-Workflow-Card „Apply app update (normal cycle)". Auf dem Host quittiert `dnf upgrade tailscale` aber „Nothing to do" — das installierte `tailscale 1.98.4-1` ist die neueste Paketversion; die Lücke sitzt in der einkompilierten stdlib, die nur ein Tailscale-Upstream-Rebuild schließt. Das System schlägt eine Aktion vor, die der Operator nicht ausführen kann.

Trivy liegt nicht falsch — die rpm-Metadaten können diese Vuln-Klasse per Konstruktion nicht sehen (statisch gelinkte stdlib). Der Schalter `--pkg-types os` würde lang-pkgs/gobinary-Findings ausblenden, macht aber blind für genau die dominante Vuln-Klasse moderner statisch-gelinkter Infra-Binaries (tailscale, kubelet, containerd). Die Detektion ist wertvoll; falsch ist allein die Folgerung „host-applizierbarer Patch".

Das LLM halluziniert dabei nicht: der Pass-2-Prompt der `patch`-Lane sagt laut ADR-0053 „alle Findings im Call haben dieselbe Patch-Verfügbarkeit". Die falsche Lane-Zuordnung liefert dem LLM ein falsches Faktum; es antwortet konsistent. Der Fehler sitzt **vor** dem LLM, in der deterministischen Lane-Ableitung.

## Entscheidung

Eine dritte Fix-Lane **`upstream`** für lang-pkgs-Findings mit Fix. Die Lane-Partition wird:

| Bedingung | `fix_lane` |
|---|---|
| `has_fix` AND `finding_class == os-pkgs` | `patch` |
| `has_fix` AND `finding_class == lang-pkgs` | `upstream` |
| NOT `has_fix` | `mitigate` |

(`finding_class == other` mit Fix ist heute leer; fällt konservativ nach `upstream` — „nicht nachweisbar host-applizierbar".)

Das ist exakt der in ADR-0053 §Re-Open-Trigger vorgesehene Pfad: mehr als zwei Remediation-Achsen → `fix_lane`-Enum erweitern statt neuer Tabelle.

### Zentrale Ableitung statt verstreuter CASE

`fix_lane` wird heute an mehreren Stellen aus `fixed_version IS NOT NULL` abgeleitet (`finding_group_inheritance.py` SQL-CASE, `pass2_enqueue.py`, `pass2_input_selection.py`-Caller, `llm_fingerprints.py`). Diese ADR führt **eine** Single-Source-Definition ein — `fix_lane_for(finding_class, has_fix) -> Literal["patch","upstream","mitigate"]` in `risk_engine.py` — plus **einen** spiegelnden SQL-Ausdruck (CASE über `finding_class`/`has_fix`). Kein Re-Implementieren der Klassen-Logik pro Call-Site (Drift-Vermeidung im Sinn der HTMX-OOB-Single-Source-Doktrin, übertragen auf die Lane-Logik).

### Band-Whitelist pro Lane

`upstream` bekommt dieselbe Whitelist wie `mitigate`: **escalate, monitor, noise — kein `act`**. Begründung identisch zu ADR-0053 §„act ist patch-only": `act` heißt „es gibt einen Patch, im normalen Zyklus einspielen". Ohne host-applizierbaren Patch ist `act` bedeutungslos — ein upstream-only-Fix ist entweder dringend genug für `escalate` (anders absichern, bis der Rebuild kommt) oder nicht dringend, dann `monitor`/`noise`.

Durchsetzung wie bei mitigate: der `upstream`-Lane-Prompt nennt `act` nicht als Option und beschreibt explizit, dass ein fixierter Dependency-/Toolchain-Stand existiert, **aber ein Upstream-Rebuild nötig ist** und nicht angenommen werden darf, der Operator könne ihn applizieren. `_validate_pass2_response` lehnt `act` ab, wenn der Job-`fix_lane == 'upstream'`.

### `action_type`-Ableitung

`_upsert_evaluation` leitet `action_type` weiter deterministisch ab; neue Zeilen:

| `fix_lane` | `risk_band` | abgeleiteter `action_type` |
|---|---|---|
| upstream | escalate | `mitigate` |
| upstream | monitor | `watch` |
| upstream | noise | `none` |

Es gibt **kein** eigenes `action_type=upstream` — die bestehende `ck_app_group_evals_action_type`-Whitelist (`patch/mitigate/watch/none/investigate`) bleibt unangetastet. Die Lane trägt die Upstream-Semantik, nicht der `action_type`.

### Card-Matrix

Neue Karte in `_build_action_sections`, in Action-Needed sichtbar nur bei `escalate`:

| Karte | `risk_band` | `fix_lane` |
|---|---|---|
| ESCALATE · Upstream fix — mitigate until rebuild | escalate | upstream |

`upstream`+`monitor`/`noise` erscheinen in den bestehenden Monitor-/Noise-Buckets (jetzt pro Lane gebandet), nicht in Action-Needed. Die Card-Copy macht klar: ein Fix existiert upstream (die `1.25.11, 1.26.4`-Angabe bleibt sichtbar), ist aber nicht per Paketmanager applizierbar — anders absichern / Vendor-Release verfolgen. Damit widerspricht die UI nicht mehr der sichtbaren Fix-Angabe — die Konsistenz, die ein „Fold-in-mitigate" (lang-pkgs unter „no patch") verloren hätte.

### Schema / Migration

`fix_lane`-CHECK von `IN ('patch','mitigate')` auf `IN ('patch','mitigate','upstream')` erweitern. Drop-&-Rebuild der Eval-Rows analog ADR-0053 (Pass 2 refüllt organisch beim nächsten Scan). PK/Index unverändert (`fix_lane` ist bereits PK-Bestandteil). `PASS2_PROMPT_VERSION` hochzählen (Prompt-Semantik der neuen Lane → Cache-Invalidation).

### Fingerprint / Cache / Selektion / Enqueue / Inheritance

Mechanik unverändert gegenüber ADR-0053 — es wird nur über **drei** statt zwei Lanes iteriert. `group_findings_fingerprint` per Lane-OPEN-Set; eine Group kann jetzt bis zu drei Eval-Rows tragen. Der Inheritance-CASE spiegelt die Drei-Wege-Partition (`finding_class`/`has_fix`).

## Begründung

- Trennt **Fakt** (ein Fix existiert) von **Applizierbarkeit** (der Operator kann ihn einspielen) — beides deterministisch aus Daten, die schon da sind (`finding_class`), kein LLM-Urteil, kein Per-Paket-Allowlist, ecosystem-agnostisch (Go/Java/Node/Rust).
- Behebt die falsche `act`/„Apply update"-Empfehlung an der Wurzel (Lane-Ableitung), nicht kosmetisch im Prompt.
- Erhält die sichtbare Fix-Information statt sie unter „no patch — mitigate" zu verstecken — die ehrliche, nicht-verwirrende Darstellung.
- Konservativ: im Zweifel (`other`/`lang-pkgs`) „nicht host-applizierbar" statt einen Patch vorzugaukeln.
- Korrektheits-Boden **ohne** Agent- oder Outbound-Änderung; ADR-0062/0063 verfeinern darauf auf.

## Konsequenzen

- Migration (CHECK-Erweiterung, Eval-Rebuild), `PASS2_PROMPT_VERSION`-Bump. `alembic downgrade -1 && upgrade head` muss grün sein.
- `risk_engine.py`: neue `fix_lane_for(...)`-Single-Source + spiegelnder SQL-Ausdruck.
- LLM-Layer: `upstream`-Prompt-Variante (kein `act`), `_validate_pass2_response` lehnt `act` bei `upstream` ab.
- `_upsert_evaluation`: `action_type`-Ableitung um die upstream-Zeilen ergänzt.
- View/Template: neue ESCALATE·Upstream-Card in `_build_action_sections`/`_action_needed_section.html`/`application_group_card.html`; Monitor/Noise-Buckets pro Lane.
- Tests (nur erlaubte Gates — ruff/mypy/shellcheck + pytest Pure-Unit): `fix_lane_for`-Wahrheitstabelle, Validator-act-Reject-bei-upstream, `action_type`-Ableitung, Card-Matrix inkl. Group-in-mehreren-Cards, Inheritance-Drei-Wege-CASE.
- ARCHITECTURE.md §5 (Junction/Lane) + §12 (Risk-Reviewer) bei Umsetzung nachziehen.

## Re-Open-Trigger

- Sollten manche `lang-pkgs` doch host-applizierbar sein (z. B. ein lang-pkgs-Binary, das ein OS-Paket mit verfügbarem Repo-Update besitzt), liefert [ADR-0062](0062-agent-host-update-availability.md) den präzisen Host-Flag, der `upstream`→`patch` promotet. Diese ADR ist der deterministische Default; 0062 verfeinert ihn.
- Weitere Achsen (`will_not_fix`/`eol` als eigene Lane) bleiben Re-Open via `fix_lane`-Erweiterung.
