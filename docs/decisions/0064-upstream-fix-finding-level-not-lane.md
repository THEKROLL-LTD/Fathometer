# ADR-0064 — Upstream-Fix als Finding-Level-Enrichment statt eigener Lane (amendet ADR-0061)

**Status:** Akzeptiert · **Datum:** 2026-06-13 · **Block:** AK

Bezug: [ADR-0061](0061-fix-ownership-lang-pkgs-upstream-lane.md) (Fix-Ownership / `upstream`-Lane — **diese ADR löst den §Re-Open-Trigger „kollabierte Darstellung" ein und nimmt die Lane-Separierung zurück**), [ADR-0053](0053-fix-lane-evaluation.md) (Fix-Lane-Evaluation — Per-Lane-Bänder; deren Re-Open „Group-Card mit zwei Lane-Verdikten zu unruhig → kollabierte Darstellung" greift hier), [ADR-0062](0062-agent-host-update-availability.md) (Host-Update-Flag — bleibt), [ADR-0063](0063-agentic-upstream-update-search.md) (agentischer Upstream-Check — bleibt funktional), [ADR-0052](0052-operator-sichten-jetzt-zustand.md) (Live-Worst / Jetzt-Zustand).

## Kontext

ADR-0061 führte für lang-pkgs-Fixes eine **dritte Fix-Lane `upstream`** plus eine eigene Operator-Workflows-Card ein (`ESCALATE · Upstream fix — mitigate until rebuild`). Operator-Feedback (server 8, `k3s`): eine gemischte gobinary-Group erscheint gleichzeitig in **zwei** Cards — `No patch — mitigate` **und** `Upstream fix — mitigate until rebuild` — obwohl die Operator-Aktion **identisch** ist: „auf dem Host gibt es jetzt keinen Patch, mitigieren". Das verwirrt; der Operator erwartet beide CVEs im selben Eimer.

Der einzige reale Unterschied zwischen den beiden Lanes ist: **kennt Trivy eine fixende Version der jeweiligen einkompilierten Komponente?** (z. B. pgx-Fix bekannt → `upstream`; Docker-lib-Fix unbekannt → `mitigate`). Das ist eine **Eigenschaft des einzelnen Findings**, kein eigener Triage-Eimer.

Drei Befunde zeigen, dass die Lane-Separierung zu viel war:

1. **Identische Operator-Aktion.** `upstream` und `mitigate` leiten beide `action_type ∈ {mitigate, watch, none}` ab (kein `act`, kein Host-Patch). Für den Operator beides „mitigieren bis ein Upstream-Rebuild kommt".
2. **Keine actionable Foresight.** Die Per-Lane-Bänder aus ADR-0053 rechtfertigen sich durch „patch jetzt den patchbaren Teil, ist der Rest gefährlich?" — das gilt für `patch` vs `mitigate` (man **kann** den patch-Teil sofort einspielen). Für `upstream` vs `mitigate` gilt es **nicht**: beide warten auf denselben Upstream-Rebuild, es gibt kein „jetzt-Teil-fixen". Ein separates `upstream`-Band liefert null Handlungs-Insight und widerspricht ADR-0053s eigenem Prinzip „Fix-Verfügbarkeit ist KEIN Risiko-Kriterium".
3. **Schwaches Signal.** Trivys „kein `FixedVersion`" ist bei lang-pkgs **nicht autoritativ** (Advisory-Lücken — kann „noch nicht erfasst" statt „existiert nicht" bedeuten). Eine eigene Lane auf diese wackelige Unterscheidung zu stützen war zu viel Struktur.

## Entscheidung

Die `upstream`-Lane **entfällt als eigene Lane**; sie kollabiert in `mitigate`. Die „Fix existiert upstream"-Information wird **Finding-Level-Enrichment** innerhalb der `mitigate`-Card.

### Lane-Partition zurück auf zwei

```
not has_fix                          -> mitigate
has_fix AND os-pkgs                  -> patch
has_fix AND host_update_available    -> patch       # ADR-0062 bleibt
has_fix AND lang-pkgs/other (sonst)  -> mitigate     # war upstream
```

`fix_lane ∈ {patch, mitigate}` (wie vor ADR-0061). Die Single-Source `risk_engine.fix_lane_for` / `fix_lane_sql_case` verliert den `upstream`-Zweig.

### Was erhalten bleibt

- **AGs Korrektheits-Kern (ADR-0061):** ein lang-pkgs-Fix landet **nie** in `patch`/`act` → **keine falsche „Apply app update"-Empfehlung** (der ursprüngliche tailscaled-Bug bleibt behoben). Er liegt jetzt in `mitigate` statt in einer eigenen `upstream`-Lane — host-seitig unverändert „nicht patchbar".
- **ADR-0062 (Host-Flag):** `host_update_available=true` promotet lang-pkgs weiter nach `patch` (echt host-updatebar) — unverändert.
- **ADR-0063 (Upstream-Check) + Block AJ (Verdikt im Chat):** funktional unverändert — sie keyen auf `upstream_check_results` bzw. die Finding-Seed, **nicht** auf die Lane.

### Finding-Level-Enrichment

Existiert für ein Finding eine `fixed_version` (has-fix lang-pkgs in der `mitigate`-Lane), zeigt der Operator-Workflow das an: „**fixed upstream: `<component> <version>` — needs rebuild**". Der **„Check for upstream fix"-Button** (ADR-0063 / AI-2) erscheint pro Group-Row nur, wenn das schlimmste **researchbare** Finding der Lane einen Seed hat (`build_research_seed != None`, d. h. lang-pkgs **mit** `fixed_version`). No-fix-Findings (keine Fix-Version): kein Button, kein Versions-Hinweis.

### Band

Pass-2 bewertet nur noch `patch` + `mitigate` (eine `mitigate`-Eval über **alle** nicht-host-patchbaren Findings einer Group). Der damit verbundene Wegfall der has-fix-vs-no-fix-Band-Granularität ist **kein** Verlust: er betrifft nur lang-pkgs/other (os-pkgs-`patch`-vs-`mitigate`-Split bleibt), das Signal war ohnehin nicht-autoritativ, und das `upstream`-Band war nicht actionable (s. §Kontext).

### Card

Die Card `ESCALATE · Upstream fix — mitigate until rebuild` entfällt. Die bestehende Card deckt beide Fälle ab; **Label `No host patch — mitigate`** (präziser als „No patch", weil ein Upstream-Fix existieren kann — der dann pro Row angezeigt wird). `act` bleibt patch-only.

## Begründung

- **Operator-Mental-Modell:** ein Eimer „kein Host-Patch" statt zweier verwirrender Lanes für dieselbe Aktion.
- **Konsistenz mit ADR-0053:** „Fix-Verfügbarkeit ist kein Risiko-Kriterium" — ein gemeinsames Band über has-fix/no-fix-nicht-host-patchbar ist konsistenter als ein Split auf ein nicht-actionables Kriterium. Dies ist der in ADR-0053 §Re-Open vorgesehene „kollabierte Darstellung"-Pfad.
- **Ehrlichkeit ohne Verstecken:** ADR-0061s Sorge „Fix-Info nicht unter no-patch verstecken" wird durch die Finding-Level-Anzeige erfüllt — die Fix-Version steht an der richtigen Granularität (am Finding), nicht in einer eigenen Card.
- **Weniger Kosten:** eine mitigate-Eval statt mitigate+upstream pro gemischter Group → ein LLM-Call weniger.

## Konsequenzen

- `risk_engine.fix_lane_for` / `fix_lane_sql_case`: `upstream`-Zweig entfernt.
- Migration (`0028`): CHECK `ck_app_group_evals_fix_lane` zurück auf `IN ('patch','mitigate')`; Drop-&-Rebuild der Eval-Rows (Pass-2 refüllt organisch); `PASS2_PROMPT_VERSION` hochzählen. ORM-Modell-CHECK synchron. `alembic downgrade -1 && upgrade head` grün (beim User).
- LLM-Layer: `upstream`-Prompt-Variante entfernt; `mitigate`-Prompt umformuliert (nicht mehr „fixed_version is null" — jetzt „kein host-applizierbarer Patch; für manche Findings existiert evtl. ein Upstream-Fix"); Validator-`act`-Reject deckt `mitigate` (upstream-Zweig weg); `_ACTION_TYPE_BY_LANE_BAND` ohne upstream-Zeilen.
- View/Template: `escalate-upstream`-Card + `fix_lane`-Diskriminator entfernt; Card-Label `No host patch — mitigate`; Finding-Level-Fix-Version-Anzeige; Lane-Label 2-wertig.
- AI-2: Button/Panel von der `escalate-upstream`-Card auf die `mitigate`-Card-Row mit researchbarem Finding umgehängt; `worst_upstream_finding` auf „researchbares Finding innerhalb mitigate" re-scoped. Routen/`derive_state`/Cache unverändert.
- ARCHITECTURE.md §5 (Lane-Partition wieder zwei) + §11/§17 (kein separater upstream-Lane-Konsument; Upstream-Check bleibt) nachziehen.
- Tests (nur erlaubte Gates): `fix_lane_for`-2-Wege-Matrix, Card-Matrix ohne upstream, Fix-Version-Anzeige, Button-Re-Gate, AJ-Verdikt-Pfad unverändert.

## Re-Open-Trigger

- **Upstream-Check für no-fix lang-pkgs** (offene Recherche ohne Fix-Versions-Anker): heute liefert `build_research_seed` `None` ohne `fixed_version`, der Check läuft also nur für has-fix. Eine Erweiterung auf no-fix (Frage „existiert *überhaupt* ein gefixtes Release?") ist ein eigenes Feature/TD.
- Sollte sich die has-fix-vs-no-fix-Band-Unterscheidung doch als operativ wertvoll erweisen, ließe sie sich als Finding-Level-Sortierung/Hinweis nachrüsten, ohne die Lane wieder zu spalten.
