# ADR-0053 — Fix-Lane-Evaluation: Pass-2 pro `(group, server, fix_lane)`

**Status:** Akzeptiert (Umsetzung offen, siehe TICKET-013)
**Datum:** 2026-06-11
**Vorgänger / erweitert:** ADR-0023 (LLM-Risk-Reviewer + Two-Pass), ADR-0028 (`application_group_evaluations`-Junction), TICKET-011 (Pass-2-Input-Selektion), ADR-0052 / TICKET-010 (OPEN-only-Eval-Input, Live-Worst). **Tangiert** TICKET-012 (AI-Assessment ist Group-Level — die Reason-Quelle ändert sich hier auf Lane-Level).

## Kontext

Pass 2 bewertet heute eine Application-Group als Ganzes: **ein** `(risk_band, action_type, worst_finding_id, reason)` pro `(group, server)`-Junction-Row (ADR-0028). Der `action_type` aus `{patch, mitigate, watch, none}` zwingt das LLM, sich pro Gruppe für **eine** Remediation-Achse zu entscheiden — obwohl eine Gruppe regelmäßig **gemischt** ist: ein Kernel-Bundle enthält CVEs mit verfügbarem Fix (`fixed_version` gesetzt) **und** CVEs ohne Fix (`fixed_version IS NULL`).

Konkreter Befund (Triage-Queue 2026-06-11, Operator-Workflows-Card): Group `linux-tools-6.8.0-90` landet komplett unter „ESCALATE · No patch — mitigate", weil das worst finding (CVE-2026-43304, no fix) die Gruppen-Action auf `mitigate` setzt. Die patchbaren CVEs derselben Gruppe (z. B. CVE-2026-31431, Fix `6.8.0-117.117`) erscheinen damit **nicht** unter „Patch", obwohl sie sofort patchbar wären.

Zwei Achsen werden hier auf einen Wert kollabiert:

1. **Action-Achse (patch vs. mitigate)** — das ist ein **deterministischer Fakt** pro Finding: `fixed_version` ist gesetzt oder nicht. Keine LLM-Beurteilung nötig.
2. **Risiko-Achse (escalate/act/monitor/noise)** — das **ist** LLM-Beurteilung (Severity/EPSS/KEV × Exposure), und sie kann sich zwischen patchbarem und nicht-patchbarem Teil **unterscheiden**.

Aus (2) folgt das eigentliche Problem: Mit einem Group-Level-Band sieht der Operator **nicht**, ob der nicht-patchbare Rest escalate (muss anders abgesichert werden) oder noise (ignorierbar) ist — der angezeigte Band stammt vom Gruppen-Worst, das auch ein patchbares Finding sein kann. Genau die Foresight „was bleibt nach dem Patchen übrig und ist es gefährlich?" fehlt heute und ist erst nach Patch + Rescan + Re-Eval sichtbar.

Eine reine Projektions-Lösung (Action-Lanes nur beim Render splitten, Band bleibt Group-Level) wurde **verworfen**: beide Lanes läsen dasselbe `ev.risk_band` und beantworten die Risiko-pro-Subset-Frage nicht (siehe Alternativen).

## Entscheidung

Pass 2 bewertet **pro Fix-Lane** statt pro Gruppe. Die Gruppen-**Identität** bleibt unverändert (Pass 1 unangetastet) — nur die **Bewertung** wird zweigeteilt.

### Begriff: `fix_lane`

Deterministische Partition der OPEN-Findings einer Group auf einem Server:

- **`patch`** — Findings mit `fixed_version IS NOT NULL`.
- **`mitigate`** — Findings mit `fixed_version IS NULL`.

`fix_lane` ist kein LLM-Output und keine persistierte Finding-Spalte, sondern wird aus `Finding.fixed_version` abgeleitet (Render-, Enqueue- und Inheritance-Zeit).

### Zwei getrennte LLM-Requests pro Gruppe

Eine Group mit beiden Lane-Typen erzeugt **zwei** Pass-2-Requests (je einen pro nicht-leerer Lane), **nicht** einen kombinierten Call mit Lane-Array-Output. Begründung (Operator-Entscheidung 2026-06-11, Kosten nicht ausschlaggebend):

- **Homogener, einfacher Prompt** je Call — geringeres Verwirrungs-/Instruction-Following-Risiko als ein konditionaler Doppel-Verdikt.
- **Volles Selektions-Budget pro Lane** (`PASS2_FINDINGS_BUDGET = 32`) — der Lane-Worst ist garantiert im Fenster; keine Lane verdrängt die andere.
- **Output-Schema bleibt formgleich zu heute** — genau **ein** Verdikt pro Call (`risk_band` + `worst_finding_id` + `reason`); der Validator ändert sich minimal.
- **Fehler-Isolation** — schlägt die mitigate-Lane fehl/timeoutet, bleibt das patch-Verdikt gültig.
- **Isolation ist hier erwünscht**, nicht ein Verlust: unabhängige Verdikte pro Subset sind genau das Ziel.

Der Host-/Exposure-Kontext-Block (`_render_pass2_prompt` Zeilen ~906–934: os, listeners, kernel_modules, services, process_commands) wird in **beiden** Prompts identisch gerendert (ein Renderer, zweimal aufgerufen) — kein Drift zwischen den zwei Exposure-Narrativen.

### `action_type` wird abgeleitet, nicht mehr vom LLM emittiert

Die Lane **ist** die Action-Achse. Das LLM-Pass-2-Output-Schema (`PASS2_RESPONSE_SCHEMA`, `Pass2Evaluation`) verliert `action_type`; der Validator (`_validate_pass2_response`) prüft es nicht mehr und die `ALLOWED_BAND_ACTION_COMBOS`-Whitelist entfällt. Stattdessen leitet `_upsert_evaluation` den `action_type` deterministisch aus `(fix_lane, risk_band)` ab und persistiert ihn weiter (damit `_build_action_sections` weiterhin auf `action_type` filtern kann):

| fix_lane | risk_band | abgeleiteter action_type |
|---|---|---|
| patch | escalate / act | `patch` |
| patch | monitor | `watch` |
| patch | noise | `none` |
| mitigate | escalate | `mitigate` |
| mitigate | monitor | `watch` |
| mitigate | noise | `none` |

`risk_band` bleibt voll LLM-Beurteilung pro Lane. (Erwogene Variante: patch-Lane-Band ebenfalls deterministisch ableiten, da die Action trivial ist — verworfen, weil escalate-vs-act für patchbare Findings exposure-getrieben ist und LLM-Mehrwert hat. Siehe Alternativen.)

### Erlaubte Bands pro Lane — `act` ist patch-only

Band und Fix-Lane sind **nicht** orthogonal. `act` bedeutet semantisch „es gibt einen Patch, aber nicht dringend — im normalen Zyklus einspielen". Ohne Patch ist `act` bedeutungslos: ein nicht-patchbares Finding ist entweder dringend genug, um es **escalate** (sofort anders absichern), oder es ist nicht dringend — und dann ist es per Definition **monitor** (very low risk) oder **noise** (no risk). Ein „act + no patch" würde „nichts zu tun, kein Patch, nicht kritisch" heißen, also genau monitor/noise.

Daraus folgt die Band-Whitelist **pro Lane**:

| fix_lane | erlaubte risk_bands |
|---|---|
| `patch` | escalate, act, monitor, noise |
| `mitigate` | escalate, monitor, noise — **kein `act`** |

Durchsetzung an zwei Stellen: der mitigate-Lane-Prompt nennt `act` gar nicht als Option, und `_validate_pass2_response` lehnt `act` ab, wenn der Job-`fix_lane == 'mitigate'` ist. Diese Asymmetrie ersetzt die alte `ALLOWED_BAND_ACTION_COMBOS`-Whitelist: statt `(band, action)`-Tupel zu validieren, gilt jetzt `(fix_lane, band)`.

### Schema: `fix_lane` in den Composite-PK

`application_group_evaluations` bekommt eine dritte PK-Spalte. Bis zu zwei Rows pro `(group, server)`.

```python
fix_lane: Mapped[str] = mapped_column(String(8), primary_key=True, nullable=False)
# CHECK fix_lane IN ('patch','mitigate')
```

PK wird `(group_id, server_id, fix_lane)`. Index `ix_app_group_evals_server` wird auf `(server_id, fix_lane, risk_band)` erweitert. `ck_app_group_evals_action_type` bleibt (abgeleiteter Wert erfüllt die Whitelist weiterhin).

Migration analog ADR-0028 **Drop & Rebuild, kein Backfill**: bestehende Eval-Rows werden gedroppt (sie tragen kein `fix_lane` und sind nach der Logik-Änderung ohnehin neu zu berechnen), `fix_lane` als NOT-NULL-PK-Spalte hinzugefügt, neuer PK/Index. Pass 2 refüllt organisch beim nächsten Scan jedes Servers. Der LLM-Cache-Key ändert sich (Lane-Komponente, s. u.) → einmaliger Cache-Miss pro `(group, server, lane)` nach Deploy, danach wieder Cache-Hits. Einmalige LLM-Kosten akzeptiert.

### Fingerprint & Cache pro Lane

`group_findings_fingerprint` wird über das **Lane-OPEN-Set** berechnet (nur die Findings dieser Lane), nicht mehr über das volle Group-OPEN-Set. Da die Lane-Zugehörigkeit aus `fixed_version` folgt, ändert ein Finding, das einen Fix bekommt (mitigate→patch wandert), **beide** Lane-Fingerprints (eine Lane verliert, die andere gewinnt das Finding) → beide Lanes werden neu enqueued. Damit ist „Fix wurde verfügbar" ein Re-Eval-Trigger, ohne `fixed_version` separat in den Fingerprint aufzunehmen.

`make_cache_key` bekommt `fix_lane` als zusätzliche Salt-Komponente, damit patch- und mitigate-Lane derselben Gruppe nie denselben Cache-Eintrag treffen.

### Selektion pro Lane

`select_pass2_findings` wird pro Lane mit vollem Budget aufgerufen (Input = nur die Lane-Findings). Keine Änderung am Selektor selbst — nur der Caller (`_select_for_groups`) iteriert jetzt über `(group, lane)` statt `(group)`.

### Enqueue pro Lane

`enqueue_pass2_for_server` enqueued bis zu zwei Jobs pro betroffener Group. Job-Payload wird `{group_id, server_id, fix_lane}`. Doppel-Enqueue-Guard und Fingerprint-Skip arbeiten auf `(group_id, server_id, fix_lane)` statt `(group_id, server_id)`. Leere Lane → kein Job, keine Row.

### Inheritance pro Lane

`inherit_group_risk_to_findings` joint zusätzlich auf die Lane: ein Finding erbt aus der Junction-Row seiner **eigenen** Lane.

```sql
... ON Finding.application_group_id = eval.group_id
   AND Finding.server_id = eval.server_id
   AND eval.fix_lane = (CASE WHEN Finding.fixed_version IS NOT NULL
                             THEN 'patch' ELSE 'mitigate' END)
```

Folge — und das ist der Kern-Gewinn: ein patchbares und ein nicht-patchbares Finding **derselben** Group können jetzt **unterschiedliche** Bands tragen.

### View & Card-Matrix

`_load_application_groups_for_server` lädt bis zu zwei Eval-Rows pro Group (Junction-Batch `WHERE server_id = ? AND group_id IN (...)` liefert jetzt mehrere Rows pro Group). `_build_action_sections` matcht Lane-Rows; eine Group kann in mehreren Cards erscheinen, jeweils mit ihrem **Lane-Worst** (live aus den offenen Findings der Lane, ADR-0052). Card-Spec-Matrix (Action-Needed = escalate/act):

| Karte | risk_band | fix_lane | group_kind |
|---|---|---|---|
| ESCALATE · Patch distro | escalate | patch | os_package |
| ESCALATE · Apply app update | escalate | patch | application_bundle |
| ESCALATE · No patch — mitigate | escalate | mitigate | — |
| ACT · Patch distro (normal cycle) | act | patch | os_package |
| ACT · Apply app update (normal cycle) | act | patch | application_bundle |

Die fünf Karten sind **identisch** zum heutigen Bestand in `_build_action_sections` — es kommt **keine** neue Karte hinzu. Es gibt insbesondere **kein** `act + mitigate`: `act` ist per Band-Whitelist (oben) patch-only. Ein nicht-patchbares Finding ohne Dringlichkeit ist monitor/noise, nicht „act".

Lanes mit `risk_band ∈ {monitor, noise}` erscheinen nicht in Action-Needed, sondern in den bestehenden Monitor-/Noise-Buckets — jetzt pro Lane gebandet, nicht pro Group. Die Sortier-Position einer Group in der Group-Liste richtet sich nach dem **Max-Band über ihre Lanes**.

Group-Card (`application_group_card.html`) zeigt bis zu zwei Lane-Assessments (patch / no-patch) mit je eigener AI-Reason und eigenem Worst — passt zu TICKET-012 (Reason ist Group-/Lane-Level, nicht Per-Finding).

## Begründung

- **Trennt Fakt von Urteil.** `fixed_version` ist eine Tatsache und gehört nicht ins LLM-Urteil; das LLM beurteilt nur noch Risiko. Konsistent mit TICKET-011 Entscheidung 1 („Fix-Verfügbarkeit ist KEIN Selektionskriterium").
- **Beantwortet die Operator-Frage vor dem Patchen.** „No-patch-Lane: escalate" vs. „No-patch-Lane: noise" wird sofort sichtbar — Planung, ohne erst patchen/rescannen zu müssen.
- **Keine Gruppen-Identitäts-Kopplung an Volatiles.** Im Gegensatz zum Pre-LLM-Subgrouping bleibt `fix_lane` aus der Group-Identität heraus; ein neu verfügbarer Fix verschiebt nur Lane-Mitgliedschaft, kein Re-Grouping, keine Label-Churn, kein Matcher-Eingriff.
- **Output-Vertrag bleibt einfach.** Ein Verdikt pro Call; der teure kombinierte Lane-Array-Output entfällt.

## Konsequenzen

**Schema / Migration**
- Neue Migration: `fix_lane`-Spalte, PK `(group_id, server_id, fix_lane)`, Index-Erweiterung, CHECK `fix_lane IN ('patch','mitigate')`. Drop & Rebuild der Bestands-Rows (kein Backfill). `alembic downgrade -1 && upgrade head` muss grün sein.
- `ApplicationGroupEvaluation`-Model: `fix_lane` als dritter PK-Mapped-Column.

**LLM-Layer**
- `PASS2_RESPONSE_SCHEMA` / `Pass2Evaluation` / `_validate_pass2_response`: `action_type` raus, `ALLOWED_BAND_ACTION_COMBOS` + `VALID_ACTION_TYPES`-Prüfung entfällt. **Neu:** wenn der Job-`fix_lane == 'mitigate'`, lehnt der Validator `risk_band == 'act'` ab (Band-Whitelist pro Lane). `worst_finding_id`-Validierung gegen die gezeigten (Lane-)IDs bleibt.
- `_render_pass2_prompt`: scoped auf eine Lane; Host-Kontext-Renderer ausgelagert/zweifach aufrufbar. System-Prompt-Hinweis, dass alle Findings im Call dieselbe Patch-Verfügbarkeit haben; im mitigate-Lane-Prompt wird `act` **nicht** als wählbares Band genannt (nur escalate/monitor/noise).
- `PASS2_PROMPT_VERSION` hochzählen (Cache-Invalidation, da Prompt-Semantik ändert).

**Fingerprint / Cache**
- `group_findings_fingerprint` per Lane-OPEN-Set. `make_cache_key` + `fix_lane`-Komponente.

**Selektion / Enqueue / Worker**
- `_select_for_groups` iteriert `(group, lane)`. `enqueue_pass2_for_server` enqueued pro Lane, Payload `+fix_lane`, Guard/Skip auf `(group, server, lane)`. `_upsert_evaluation` bekommt `fix_lane`-Param + abgeleiteten `action_type`; `on_conflict` index_elements `["group_id","server_id","fix_lane"]`. Worker-Pickup (`_do_pass2`) liest `fix_lane` aus dem Payload, fingerprintet die Lane.

**Service / View / Template**
- `inherit_group_risk_to_findings`: Composite-Join + Lane-CASE.
- `_load_application_groups_for_server`: Junction-Batch liefert ≤2 Rows/Group; Render-Dict gruppiert nach Lane.
- `_build_action_sections`: neue Card-Spec `act + mitigate`; Matching auf Lane-Rows; ein Group-Eintrag wird zu `(group, lane)`-Eintrag mit Lane-Worst.
- `application_group_card.html` / `_action_needed_section.html`: bis zu zwei Lane-Verdikte pro Group rendern.

**ARCHITECTURE.md**
- §5 (Datenmodell): Junction-PK um `fix_lane` erweitern. §12 (Risk-Reviewer): Pass-2-Pro-Lane-Semantik dokumentieren.

**Tests** (nur erlaubte Quality-Gates — ruff/mypy/shellcheck + pytest Default/Pure-Unit; keine db_integration/acceptance/integration/bench/bats ohne explizite User-Genehmigung)
- Neu: Lane-Split-Selektion (pure), Fingerprint-pro-Lane, `action_type`-Ableitungstabelle, Enqueue-zwei-Jobs, Card-Matrix inkl. Group-in-zwei-Cards, Inheritance-Lane-CASE.
- Geändert: alle Tests die `Pass2Evaluation.action_type` / Whitelist / Single-Eval-pro-(group,server) annehmen.

## Abgewogene Alternativen

| Alternative | Ablehnung |
|---|---|
| **Status quo** (ein Band/Action pro Group) | Gemischte Gruppen kollabieren auf das Worst-Verdikt; patchbare Findings unsichtbar unter „mitigate"; Residual-Risiko nicht sichtbar. |
| **Projektion-only** (Action-Lanes nur beim Render, Band bleibt Group-Level) | Beide Lanes lesen dasselbe `risk_band` → beantwortet „Rest escalate oder noise?" nicht. Genau der Punkt, um den es geht. Verworfen. |
| **Pre-LLM-Subgrouping** (zwei Pass-1-Groups nach Fix-Verfügbarkeit) | Koppelt Gruppen-Identität an den volatilen `fixed_version`; Re-Grouping-/Label-/Matcher-Churn bei jedem Feed-Update, das einen Fix nachliefert; zwei getrennte Pass-1-Pfade. Verworfen. |
| **Ein kombinierter Pass-2-Call mit Lane-Array-Output** | Komplexeres Output-Schema/Validator, Budget muss zwischen Lanes geteilt werden (Worst-Verdrängung), höheres Instruction-Following-Risiko. Zwei getrennte Calls sind einfacher und robuster. |
| **Patch-Lane-Band deterministisch ableiten (kein LLM für patch-Lane)** | Spart einen Call, verliert aber die exposure-getriebene escalate-vs-act-Unterscheidung für patchbare Findings (public-exposed High = jetzt patchen vs. isoliert = normaler Zyklus). Als Re-Open-Trigger vermerkt, falls Call-Volumen stört. |

## Re-Open-Trigger

- Wenn das doppelte Call-Volumen (zwei Requests pro gemischter Group × Server) operativ stört: patch-Lane-Band deterministisch aus Pre-Triage + Exposure-Flag ableiten, nur mitigate-Lane ans LLM.
- Wenn mehr als zwei Remediation-Achsen nötig werden (z. B. `will_not_fix`/`eol` als eigene Lane neben `mitigate`): `fix_lane`-Enum erweitern statt neuer Tabelle.
- Wenn die Group-Card mit zwei Lane-Verdikten zu unruhig wird (Widerspruch zu „less is more", `feedback_server_detail_less_is_more`): kollabierte Darstellung mit Max-Band + Lane-Aufklappung.

## Bedrohungsmodell-Implikationen

- **Lane-Manipulation.** `fix_lane` folgt aus `fixed_version`, das aus Trivy/CVE-Feed kommt — kein Operator-Input, keine neue Injection-Fläche. Reason bleibt LLM-Output, weiterhin nie `|safe`.
- **Junction-Wachstum.** Worst-Case verdoppelt sich auf `O(2 × groups × servers)`; bei 200 Groups × 100 Servern ≈ 40k Rows à ~200 B ≈ 8 MB. Unkritisch.
- **UPSERT-Race pro Lane.** `ON CONFLICT (group_id, server_id, fix_lane)` bleibt atomar; Sibling-Wait-Pattern unverändert.

## Quellen / Verweise

- `app/models.py:884-958` — `ApplicationGroupEvaluation` (PK-Erweiterung).
- `app/workers/llm_worker.py:1778-1823` — `_upsert_evaluation` (+`fix_lane`, abgeleiteter `action_type`); `_do_pass2`-Pickup (Lane aus Payload).
- `app/services/pass2_enqueue.py:49-183` — `enqueue_pass2_for_server` (pro Lane, Payload/Guard/Skip).
- `app/services/llm_fingerprints.py:61-76,203-223` — `group_findings_fingerprint` (Lane-Set), `make_cache_key` (Lane-Salt).
- `app/services/pass2_input_selection.py` — Selektor unverändert, Caller iteriert `(group, lane)`.
- `app/services/llm_risk_reviewer.py:176-203,238-253,841-1008,1010-1120` — Schema/Modell/Render/Validator (action_type raus, Lane-Scope).
- `app/services/finding_group_inheritance.py` — Composite-Join + Lane-CASE.
- `app/views/server_detail.py:368-462` — `_build_action_sections` (Card-Matrix, Lane-Einträge).
- `app/templates/_partials/application_group_card.html`, `app/templates/servers/_action_needed_section.html` — Lane-Render.
- ADR-0023, ADR-0028, ADR-0052, TICKET-010, TICKET-011, TICKET-012.
