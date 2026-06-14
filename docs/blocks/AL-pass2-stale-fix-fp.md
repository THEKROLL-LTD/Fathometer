# Block AL — Pass-2 sortiert Trivy-Stale-Artifact-False-Positives aus (ADR-0066)

**Spec:** [ADR-0066](../decisions/0066-pass2-stale-fix-false-positive.md). **Linie:** Fortsetzung der Fix-Ownership-Reihe (AG→AH→AI→AJ→AK). **Zielversion:** v0.27.0. **Branch (Vorschlag):** `feat/block-al-stale-fix-fp`.

## Problem (1 Absatz)

Trivy meldet den alten, nicht gebooteten `installonly`-Kernel (`5.14.0-611.54.6.el9_7`, `fixed=5.14.0-687.12.1.el9_8`) als verwundbar, obwohl der **laufende** Kernel (`5.14.0-687.15.1.el9_8`) den Fix übererfüllt → `dnf update` sagt „Nothing to do", Fathometer zeigt aber `ACT`. Der Pass-2-Reviewer soll diesen Stale-Artifact-FP selbst auf `noise` korrigieren — dafür fehlen ihm nur die Felder im Prompt. **Lane bleibt `patch` (unverändert).** Band+Action folgen aus dem Reviewer-Verdikt.

## Scope-Entscheidung (User, 2026-06-14)

**Option B** umgesetzt: Phase 1 (Pass-2-Prompt + System-Prompt) **plus** os-pkgs-Host-Update-Anker (ADR-0062-`dnf check-update`-Ergebnis nicht mehr verwerfen). **Nicht** in diesem Block: installiertes Vollinventar / `installed_versions` (Option C, Re-Open-Trigger in ADR-0066 — der „gefixt installiert, aber nicht gebootet"-Eckfall ist ohnehin kein FP).

## Tasks

### P1 — Pass-2-Prompt-Anreicherung (`backend-implementer`)
1. `app/services/llm_risk_reviewer.py`, `_render_pass2_prompt` Per-Finding-Zeile (Z. ~1003/1025): `installed=<f.installed_version>` neben `fix=` rendern; fehlend → `installed=n/a`.
2. `_render_host_context` (Z. ~902): Zeile `kernel (running): <server.kernel_version>` ergänzen (NULL → weglassen, kein leerer Marker).
3. Per-Finding `host_update=<available|none>` aus `Finding.host_update_available` (`True→available`, `False/None→none`).
4. `app/services/llm_prompts.py`: neuer Correction-Path im System-Prompt (Wortlaut-Kern siehe ADR-0066 §1). `PASS2_PROMPT_VERSION` **5 → 6**.

### P2 — os-pkgs-Host-Update-Anker (`backend-implementer`)
5. `agent/lib_host_state.sh` `collect_host_updates`: os-pkgs-Findings zusätzlich verarbeiten. **Kein `rpm -qf`** (os-pkgs hat keinen Binary-`Target`); besitzendes Paket = Trivy-`PkgName`, Status aus der bestehenden `_upgradable`-Map. Eintrag mit Paketnamen-Join-Key. Read-only, **ein** `check-update`-Aufruf (unverändert), Timeout, shellcheck-clean. Version-Bumps: `AGENT_VERSION` `0.7.0→0.8.0`, `LIB_HOST_STATE_VERSION` `0.4.0→0.5.0`, `app/config.py` `CURRENT_AGENT_VERSION` `0.7.0→0.8.0` (`MIN_AGENT_VERSION` bleibt).
6. `app/schemas/scan_envelope.py` `HostUpdateEntry`: additives optionales `pkg_name: str | None` (os-pkgs-Join-Key), `extra="ignore"`. ASCII/NUL-Validator analog `owning_package`.
7. `app/services/findings_ingest.py`: zweite Join-Map keyed by `package_name` für os-pkgs; lang-pkgs weiter über `target_path` (Z. ~278/314). `host_update_available`/`available_version`/`owning_package` werden für os-pkgs-Findings gesetzt.

### P3 — Tests + Doku (`test-writer`, dann Hauptsession)
8. Pure-Unit-Tests (siehe DoD).
9. ARCHITECTURE.md (§6 Envelope `host_updates` os-pkgs-Join, §12 Pass-2-Prompt-Felder + Correction-Path), CHANGELOG (v0.27.0), `decisions/README.md`-Index (0066 + Status-Note auf 0062), STATE.md.

## Definition of Done (maschinell prüfbar — nur erlaubte Gates: ruff/mypy/shellcheck + pytest Pure-Unit)

- [ ] `ruff check . && ruff format --check .` grün; `mypy app/` grün.
- [ ] `shellcheck agent/lib_host_state.sh agent/fathometer-agent.sh` exit 0.
- [ ] Default-`pytest` grün (Bash `timeout: 120000`), keine `db_integration|acceptance|integration|bench`-Marker, keine neuen `.bats`/`.sh`-Test-Dateien ohne explizite User-Genehmigung.
- [ ] **Prompt-Render** (Pure-Unit): `_render_pass2_prompt` enthält `installed=` pro Finding, `_render_host_context` enthält `kernel (running):` wenn `server.kernel_version` gesetzt, `host_update=` pro Finding (available/none-Matrix inkl. NULL).
- [ ] **Reviewer-Verdikt** (Pure-Unit, gemockte LLM-Antwort / Validator-Pfad): Fixture `running ≥ fixed` → Modell darf `noise` setzen und besteht die Validierung im `patch`-Call; Fixture `running < fixed` (gefixt-nicht-gebootet) bleibt actionable. (Kein Live-LLM.)
- [ ] **System-Prompt** enthält den Correction-Path-Text; `PASS2_PROMPT_VERSION == 6`.
- [ ] **Agent-Parser** (Pure-Unit, String-Fixtures): os-pkgs-Pfad emittiert Eintrag mit Paketnamen-Join ohne `rpm -qf`; lang-pkgs-Pfad unverändert; `dnf check-update`-leer → `update_available=false`.
- [ ] **Ingest-Join** (Pure-Unit): os-pkgs-Finding zieht `host_update_available` über `package_name`; lang-pkgs über `target_path`; kein Eintrag → `NULL` (Fallback).
- [ ] **Lane-Invarianz** (Pure-Unit, Regression): os-pkgs-Finding bleibt `fix_lane='patch'` **unabhängig** von `host_update_available` (True/False/NULL) — Python (`fix_lane_for`) und SQL-Spiegel (`fix_lane_sql_case`). **Keine** Eval-Rebuild-Migration.
- [ ] **Forward-Compat**: alter Agent (kein os-pkgs-Eintrag) → Kernel-Finding `host_update_available=NULL`, Prompt rendert `host_update=none`, Reviewer fällt auf Versionsvergleich zurück.
- [ ] **Sprach-Sweep** (`tests/test_ui_language.py`) grün — neue System-Prompt-Strings sind englisch.
- [ ] **Regression (der konkrete Fall)**: Fixture „alter el9_7-Kernel-Leftover, laufend el9_8 ≥ fixed, `host_update=none`" → Prompt enthält alle drei Signale, sodass das Modell `noise` herleiten kann (Prompt-Inhalts-Assertion, kein Live-Call).

## Beim User anstehend (nicht proaktiv — CLAUDE.md Test-Konvention)
- `alembic upgrade head && downgrade -1 && upgrade head` — **nur falls** P2 doch eine Spalte braucht; Erwartung: **keine** Migration (reiner Envelope-Feld-Zusatz, `host_update_available` existiert seit `0026`). DoD-Item oben prüft „keine Eval-Rebuild-Migration".
- `bats`/Live-Host-Smoke gegen echten Paketmanager: AlmaLinux-Box mit Alt-Kernel → `collect_host_updates` emittiert os-pkgs-`kernel*`-Eintrag `update_available=false`; nach Re-Scan zeigt der Reviewer `noise` statt `act` für den Leftover. (On-Demand, User-Genehmigung für `.bats`.)
- Operator-Browser-Smoke: Screenshot-Fall (k3s-sv-1) zeigt den Kernel-Leftover nicht mehr unter `ACT`.

## Nicht in diesem Block (ADR-0066 §Scope / Re-Open)
- `installed_versions`-Vollmeldung (Option C) — eigene ADR, nur falls installonly-gefixt-nicht-gebootet je relevant wird.
- Jede deterministische Versions-Lane-/Pre-Triage-Regel — die Korrektur bleibt Pass-2-Urteil.
- Apt/dpkg-os-pkgs-Mehrversions-Sonderfälle (selten) — Join-Pfad bei Bedarf gegenprüfen.
