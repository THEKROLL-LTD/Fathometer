# ADR-0066 — Pass-2 erkennt Trivy-Stale-Artifact-False-Positives (`fixed ≤ installiert/laufend`)

**Status:** Akzeptiert · **Datum:** 2026-06-14

Bezug: [ADR-0062](0062-agent-host-update-availability.md) (Host-Update-Flag — diese ADR weitet die schon berechnete `dnf check-update`-Wahrheit auf os-pkgs aus, statt sie zu verwerfen), [ADR-0043](0043-llm-risk-band-exploitability-model.md) (Risk-Band als LLM-Angreifbarkeits-Urteil — die FP-Korrektur ist ein Pass-2-Urteil, keine deterministische Lane-Regel), [ADR-0064](0064-upstream-fix-finding-level-not-lane.md) / [ADR-0061](0061-fix-ownership-lang-pkgs-upstream-lane.md) (Fix-Lane-Modell — **unverändert**: os-pkgs bleibt `patch`), [ADR-0022](0022-risk-based-prioritization.md) (Host-Snapshot inkl. `kernel_version`), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Two-Pass-Reviewer, Prompt-Aufbau), [ADR-0005](0005-no-raw-json-storage.md) (Roh-Trivy bleibt unberührt).

## Kontext

Trivy scannt **alle installierten** RPMs, nicht nur den laufenden Kernel. Der Kernel ist ein `installonly`-Paket — mehrere Versionen koexistieren (`installonly_limit`). Auf einem AlmaLinux-9.8-k3s-Node lag neben dem laufenden `kernel 5.14.0-687.15.1.el9_8` noch der alte, nicht gebootete `5.14.0-611.54.6.el9_7`. Trivy meldet für das alte Artefakt korrekt `installed=5.14.0-611.54.6.el9_7`, `fixed=5.14.0-687.12.1.el9_8` → verwundbar. Dass der **laufende** Kernel (`687.15.1`) den Fix längst übererfüllt, sieht Trivy nicht, weil es nicht-verwundbare Artefakte gar nicht meldet.

Folge in der UI: das Finding landet (os-pkgs + `has_fix`) deterministisch in der `patch`-Lane, der Pass-2-Reviewer sieht „Patch verfügbar + network-AV + public-exposed haproxy" und vergibt `ACT`. Der Operator führt `dnf update` aus — **„Nothing to do"**. Klassischer Stale-Artifact-False-Positive.

Trivy macht hier das Richtige (es soll verwundbare Artefakte auf der Platte finden). Die Lücke ist in **Fathometers Einstufung**: dem Reviewer fehlen im Prompt genau die Felder, die den FP entlarven würden — er sieht heute `fix=<version>`, aber **weder** das per-Finding `installed_version` **noch** den laufenden Kernel (`Server.kernel_version`, liegt in der DB) **noch** das deterministische dnf-Ergebnis für os-pkgs.

Zwei Wege wären denkbar gewesen:

1. **Deterministische Lane-/Pre-Triage-Regel** (Versionsvergleich im Code) — verworfen: EVR-Vergleich (Epoch/Release, `.el9_7` vs `.el9_8`) ist genau die Art Semantik, die wir nicht über `finding_class` hinaus hart kodieren wollen, und der „gefixt installiert, aber nicht gebootet"-Fall ist semantisch **kein** FP (läuft bis zum Reboot weiter verwundbar). Eine starre Regel würde diese beiden Fälle verwechseln.
2. **Pass-2-LLM entscheidet** — gewählt: nur der Reviewer sieht die volle Exposure-/Kontext-Lage und kann „`fixed ≤ laufend/installiert` ⇒ Stale-Artifact ⇒ `noise`" von „`fixed > laufend`, Fix nur installiert-nicht-gebootet ⇒ bleibt actionable (Reboot)" unterscheiden. Voraussetzung: die nötigen Felder müssen in den Prompt.

## Entscheidung

**Der Pass-2-Reviewer korrigiert Stale-Artifact-False-Positives selbst** (typisch `act → noise`). Band **und** Action folgen daraus automatisch (`ACTION_REQUIRED_MAP`: `noise → action_required=no`). Dafür bekommt er die entscheidenden Daten in den Prompt; die **Fix-Lane-Ableitung bleibt unverändert** (os-pkgs ⇒ `patch`).

### 1 — Prompt-Anreicherung (Pflicht)

In `_render_pass2_prompt` / `_render_host_context` (`app/services/llm_risk_reviewer.py`):

- **Per-Finding-Zeile** um `installed=<installed_version>` ergänzen, direkt neben `fix=` (Z. ~1003/1025).
- **Host-Kontext** um den laufenden Kernel ergänzen: `kernel (running): <server.kernel_version>` (`_render_host_context`, Z. ~902).
- **Per-Finding** `host_update=<available|none>` aus `Finding.host_update_available` — der deterministische Anker (siehe 2).
- **System-Prompt** (`app/services/llm_prompts.py`): neuer Correction-Path analog zu den bestehenden („Two correction paths…"). Wortlaut-Kern: *„If `fixed_version` is already satisfied by the running kernel / installed baseline (e.g. an older, non-booted kernel is flagged while a newer fixed kernel runs), treat it as a Trivy stale-artifact false positive → `noise`. `host_update=none` corroborates (the host package manager offers no update). If `fixed_version` is NEWER than the running version (fix installed but not yet booted, or not installed), it is NOT a false positive — keep it actionable."*
- `PASS2_PROMPT_VERSION` **5 → 6** (invalidiert den Pass-2-Cache; Fingerprint zieht die Version, ADR-0023).

### 2 — os-pkgs-Host-Update-Anker (Option B)

ADR-0062 berechnet bereits **einen** `dnf check-update`-Lauf, dessen Ergebnis alle Pakete kennt — **verwirft** os-pkgs aber (`collect_host_updates` filtert `select(.Class == "lang-pkgs")`, `agent/lib_host_state.sh:549`). Wir hören auf zu verwerfen und reichen den schon vorhandenen Boolean auch für os-pkgs durch:

- **Agent** (`collect_host_updates`): zusätzlich os-pkgs-Findings berücksichtigen. **Wichtige Abweichung zum lang-pkgs-Pfad:** os-pkgs-Findings haben **keinen Binary-`Target`-Pfad** (Trivy-`Result.Target` ist der Distro-String), daher **kein** `rpm -qf`. Das besitzende Paket **ist** der Trivy-`PkgName`. Dessen Update-Status kommt aus der bereits gebauten `_upgradable`-Map (Paketname → Kandidatenversion). Emittiert wird ein Eintrag mit Join-Key **Paketname** statt `path`.
- **Schema** (`app/schemas/scan_envelope.py`, `HostUpdateEntry`): additives, optionales Feld als Paketnamen-Join-Key (z. B. `pkg_name: str | None`), `extra="ignore"` trägt Forward-Compat. Kein neuer Pflicht-Block.
- **Ingest** (`app/services/findings_ingest.py`): zweite Join-Map keyed by `package_name`; os-pkgs-Findings ziehen `host_update_available`/`available_version` darüber, lang-pkgs weiter über `target_path` (Z. ~278/314).
- **Lane bleibt unberührt:** `fix_lane_for` short-circuit `os-pkgs ⇒ patch` (`risk_engine.py:105`) liegt **vor** der Flag-Auswertung; auch der SQL-Spiegel (`fix_lane_sql_case`) prüft `os-pkgs` vor `host_update`. Das Flag ist für os-pkgs reines **Reviewer-Enrichment**, kein Lane-Input. → keine Eval-Rebuild-Migration nötig.

### Forward-Compat / Versionierung

- Alte Agenten senden für os-pkgs keinen Eintrag → `host_update_available = NULL` für Kernel-Findings → der Reviewer fällt auf den reinen Versionsvergleich (`fixed` vs. `kernel running`) zurück. Kein Hard-Break, kein Agent-Gate-Zwang.
- Agent-/Lib-Bump per AH-Präzedenz: `AGENT_VERSION`/`CURRENT_AGENT_VERSION` `0.7.0 → 0.8.0`, `LIB_HOST_STATE_VERSION` `0.4.0 → 0.5.0`. `MIN_AGENT_VERSION` bleibt.

### Bewusst NICHT im Scope

- **Keine deterministische Lane-/Pre-Triage-Versionslogik** — die Korrektur ist und bleibt ein Pass-2-Urteil (Begründung oben).
- **Kein installiertes Vollinventar / `rpm -qa`.** Der „installonly: gefixte Version installiert, aber nicht gebootet"-Eckfall (Phase-C der Vorüberlegung) bleibt offen — er ist ohnehin **kein** FP. Re-Open-Trigger.
- **Kein Outbound, kein neuer LLM-Call, kein neues `pydantic-ai`-Tool.** Nur Prompt-Felder + ein schon berechneter Boolean.
- **Kein automatischer Band-Flip im Code.** Nur der Reviewer entscheidet (ADR-0043-Geist).

## Begründung

- **Single-Source-Daten, schon vorhanden.** `installed_version`/`fixed_version` (Trivy, per Finding), `kernel_version` (uname -r, `agent/fathometer-agent.sh:476` → `HostBlock.kernel_version` → `models.py:231`) und das os-pkgs-dnf-Ergebnis (ADR-0062, heute verworfen) sind alle da. Der teuerste Teil ist „aufhören wegzuwerfen".
- **Semantisch korrekt in beide Richtungen.** `running ≥ fixed` ⇒ Fix gebootet ⇒ FP. `running < fixed` ⇒ läuft verwundbar ⇒ actionable. Der laufende Kernel ist der exploitability-relevante Komparator — genau das, was der Reviewer braucht.
- **Deterministischer Anker gegen LLM-Versionsmathematik.** EVR-Vergleich im Modell ist fehleranfällig; `host_update=none` ist ein hartes, lokal ermitteltes Korroborat, sodass das Modell nicht allein rechnen muss.
- **Air-Gap-konform.** Keine neue Outbound-Fläche; der Anker stammt vom Host selbst.

## Konsequenzen

- `llm_risk_reviewer.py`: drei Prompt-Felder (`installed=`, `kernel (running):`, `host_update=`) + System-Prompt-Correction-Path; `PASS2_PROMPT_VERSION` 5 → 6.
- `scan_envelope.py`: additives optionales `pkg_name` (oder äquivalenter os-pkgs-Join-Key) auf `HostUpdateEntry`.
- `findings_ingest.py`: zweiter Join-Pfad (package_name) für os-pkgs; bestehender `target_path`-Pfad unverändert.
- `agent/lib_host_state.sh`: `collect_host_updates` emittiert os-pkgs-Einträge (Paketname-Join, kein `rpm -qf`), read-only, ein `check-update`-Aufruf wie gehabt. Version-Bumps (Agent 0.8.0, Lib 0.5.0).
- **Keine Lane-Änderung, kein CHECK/Eval-Rebuild.** Migration nur falls das additive Schema-Feld eine Spalte braucht — `host_update_available` etc. existieren seit ADR-0062 (`0026`); ein reiner Envelope-Feld-Zusatz braucht **keine** DB-Migration. (DoD prüft das.)
- Tests (nur erlaubte Gates): Pass-2-Prompt-Render enthält `installed=`/`kernel (running)`/`host_update=`; Reviewer-Verdikt-Tests mit Fixtures (laufend ≥ fixed → noise; laufend < fixed → bleibt actionable); Agent-Parser os-pkgs-Join (String-Fixtures); Ingest-Join-by-package-name + NULL-Fallback; Lane-Invarianz (os-pkgs bleibt `patch` unabhängig vom Flag); Sprach-Sweep.

## Re-Open-Trigger

- **installonly, gefixt-aber-nicht-gebootet** voll abdecken: dann Agent um die installierten Versionen des besitzenden Pakets erweitern (`rpm -q --qf '%{EVR}'` / `dpkg-query -W`), neues `installed_versions`-Feld — eigene ADR (war Option C). Heute bewusst ausgelassen, weil semantisch kein FP.
- Apt/dpkg-Hosts: os-pkgs-Mehrversions-Fälle sind dort selten; falls relevant, den Join-Pfad gegenprüfen.
- Falls der Reviewer trotz Daten zu oft falsch korrigiert: Correction-Path-Wortlaut nachschärfen oder den Anker von „beratend" auf „bei `host_update=none ∧ fixed ≤ running` deterministisch `noise`-Vorschlag" anheben — Messung vor Verschärfung.
