# ADR-0058 — Group-Chat-Kontext: Findings-Budget statt „alle OPEN-Findings"

**Status:** Akzeptiert · **Datum:** 2026-06-12 · **Block:** AE (`feat/block-ae-group-chat`)

Bezug: [ADR-0055](0055-per-group-ai-chat.md) (Per-Group-Chat — **amendet Entscheidung 3**: nicht mehr „alle OPEN-Findings", sondern ein deterministisches Budget + Aggregat), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Risk-Reviewer — Quelle der Selektions-Heuristik), TICKET-011 / [`pass2_input_selection`](../../app/services/pass2_input_selection.py) (deterministische Worst-Selektion — wird hier wiederverwendet), [ADR-0014](0014-token-cap-best-effort.md) (Token-Cap — gilt weiterhin **nicht** für den Chat; dieses ADR senkt die Last anders).

## Kontext

ADR-0055 §3 friert beim Chat-Start **alle OPEN-Findings der Group** in den System-Prompt ein. Beobachtung 2026-06-12 (Server 8, Group `linux-tools-common`): 745 OPEN-Findings ergeben einen Findings-Block von ~20–25k Tokens. Der Snapshot liegt als `system`-Message in der Konversation und wird über `_collect_history` bei **jedem** Folge-Turn erneut an den Provider geschickt (kein Stream-Resume, volle Historie pro Request). Das ist teuer, langsam und läuft bei sehr großen Groups Richtung Context-Limit/Timeout — der Operator stellt eine kurze Triage-Frage und bezahlt jedes Mal den gesamten Findings-Dump.

Der Risk-Reviewer (Block P, Pass 2) hat dasselbe Problem bereits gelöst: `select_pass2_findings` wählt deterministisch die wichtigsten Findings (alle KEV, alle CRITICAL als Pflicht-Slots, dann EPSS-/Pfad-Quote, Rest als Aggregat). Diese Logik ist getestet, idempotent und genau die Einheit, in der der Operator ohnehin urteilt.

## Entscheidung

Der Group-Chat-Snapshot rendert **nicht mehr alle** OPEN-Findings, sondern die nach `select_pass2_findings` ausgewählten **wichtigsten `GROUP_CHAT_FINDINGS_BUDGET = 15`** plus eine **Aggregat-Zeile** für den nicht gezeigten Rest (Severity-Counts, max EPSS, KEV-Count, Fixable-Count). Pflicht-Invariante der Selektion bleibt: **alle KEV- und CRITICAL-Findings sind enthalten**, solange sie ins Budget passen.

- **Budget = 15** (nicht die Pass-2-`32`): Pass 2 ist ein **einmaliger** Band-Entscheid, der Chat re-sendet den Snapshot **pro Turn**. 15 ist der Kompromiss aus „genug Kontext für die Triage-Frage" und „bezahlbar pro Nachricht" (~1.5–2k Tokens statt ~25k). Wiederverwendet wird die Funktion `select_pass2_findings(findings, budget=15)`; die Budget-Konstante lebt in `group_chat_prompt.py` (Chat-Domäne).
- **Aggregat-Zeile** statt stillem Weglassen: das Modell sieht ehrlich „N weitere nicht gezeigt: a critical, b high, …; max_epss=x.xx; k kev; m fixable", damit Breiten-Signale (viele Mediums, hohes Rest-EPSS) nicht unsichtbar werden.
- **Operator-Transparenz (Pflicht):** Wird tatsächlich gekürzt (`rest_count > 0`), zeigt der Chat **ganz oben im Thread** einen **gelben Info-Hinweis** (`--status-notice`, `#FFD60A`), der erklärt, dass nur die X wichtigsten von N Findings an das LLM gehen und warum. Der Hinweis ist klar als Info markiert (eigene Klasse `sd-chat-notice`, `role="note"`, gelb abgesetzt — **kein** Chat-Bubble-Look) und scrollt im Verlauf nach oben aus dem sichtbaren Bereich. Bei Groups ≤ Budget (nichts gekürzt) erscheint **kein** Hinweis (sonst irreführend).

## Begründung

- **Single-Source-Heuristik:** dieselbe Auswahl wie der Band, den der Operator in der Group-Row sieht — kein zweites, divergierendes „Wichtigkeits"-Konzept.
- **Pro-Turn-Kosten sind das eigentliche Problem**, nicht die einmalige Snapshot-Größe — deshalb ein kleineres Budget als Pass 2.
- **Ehrlichkeit vor Vollständigkeit:** das Aggregat + der sichtbare Hinweis sagen dem Operator *und* dem Modell, dass gekürzt wurde. Verdeckte Kürzung wäre ein stiller Reasoning-Bias.
- **Kein Pflicht-Kommentar/-Dialog (ADR-0006):** der Hinweis ist rein informativ, blockiert nichts.

## Bekannte Vereinfachung

`select_pass2_findings` nutzt die Modul-Konstante `EPSS_QUOTA = PASS2_FINDINGS_BUDGET // 4 = 8`, die vom Pass-2-Budget (32) abgeleitet ist — auch wenn der Chat mit `budget=15` aufruft. Effekt: die EPSS-Quote ist relativ zum 15er-Budget großzügiger. Funktional unkritisch (Auswahl bleibt ≤ 15 und deterministisch); ein chat-eigenes `EPSS_QUOTA` wäre Scope-Creep in die Pass-2-Funktion und wird bewusst nicht gemacht.

## Konsequenzen

- **`app/services/group_chat_prompt.py`:** neue Konstante `GROUP_CHAT_FINDINGS_BUDGET`, `FindingsAggregate`-NamedTuple, `build_group_system_prompt(..., findings_aggregate=None)` rendert die Aggregat-Zeile zwischen den Markern. `group_findings` ist jetzt die **selektierte** Teilmenge.
- **`app/api/group_chat.py`:** `post_message` selektiert vor dem Snapshot-Bau; `_render_chat_view` berechnet `findings_total`/`findings_shown`/`findings_truncated` (Live-Preview aus aktuellen OPEN-Findings) und reicht sie ans Template.
- **Frontend:** `--status-notice`-Token, `.sd-chat-notice`-Komponente, Banner-Block in `servers/group_chat.html` (außerhalb des Messages-Containers, damit „New Chat" ihn nicht entfernt).
- **Snapshot-Konsistenz (ADR-0055 §3) bleibt:** der gekürzte Block wird weiterhin **eingefroren**; der gelbe Hinweis ist eine Live-Preview der *aktuellen* Selektion und kann nach einem Re-Scan leicht von der eingefrorenen abweichen — akzeptiert (gleiche Staleness-Doktrin wie ADR-0055, „New Chat" für frischen Snapshot).
- **Token-Budget (ADR-0055 §4):** weiterhin kein Cap; dieses ADR reduziert die Last strukturell statt per Limit.
- **Tests:** Pure-Unit-Abdeckung für Aggregat-Rendering (Prompt), Banner-Sichtbarkeit (Template), Trim + Kontext-Helper (API).

## Re-Open-Trigger

- **Budget-Wert (15)** justierbar, falls Operator-Feedback zu wenig/zu viel Kontext meldet — reine Konstanten-Änderung, kein neues ADR nötig.
- **Live- statt Snapshot-Kontext:** weiterhin ADR-0055 §Re-Open-Trigger (eigene Entscheidung).
- **Chat-eigenes EPSS-Quota** (falls die Pass-2-Ableitung sich als unpassend erweist): eigenes ADR oder TICKET.
