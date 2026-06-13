# Fix-Ownership — Umsetzungs-Roadmap (ADR-0061 / 0062 / 0063)

> **Nachtrag 2026-06-13 (Block AK, ADR-0064):** AG→AH→AI sind umgesetzt (AI gesplittet in AI-1 Backend + AI-2 UI; AJ = Upstream-Verdikt im Chat-Snapshot). **Block AK** nimmt die *separate* `upstream`-**Lane** aus AG zurück: sie kollabiert in `mitigate` (`fix_lane ∈ {patch, mitigate}`), die „Fix existiert upstream"-Info + der „Check for upstream fix"-Button werden **Finding-Level** (pro Row in der `No host patch — mitigate`-Card). AGs Korrektheits-Kern (lang-pkgs-Fix nie host-applizierbar) sowie AH/AI/AJ bleiben. Die unten beschriebene `upstream`-Lane-Struktur ist damit historischer Planungsstand — maßgeblich ist ADR-0064.

Drei aufeinander aufbauende Blöcke. Jeder ist eigenständig mergebar und liefert für sich Wert; spätere verfeinern frühere, brauchen sie aber als Fundament.

**Reihenfolge & Abhängigkeit:** AG (Tier 0) → AH (Tier 1) → AI (Tier 2). AH setzt AGs `fix_lane_for`-Single-Source und die `upstream`-Lane voraus. AI setzt die `upstream`-/`host_update_available=false`-Markierung aus AG/AH als Trigger-Fläche voraus.

**Kern-Prinzip über alle drei:** Fakt ≠ Applizierbarkeit ≠ Empfehlung. Deterministisch was deterministisch ist (AG/AH), beratend was unsicher ist (AI). Nichts Non-Deterministisches flippt je still einen Risk-Band.

---

## Block AG — `upstream`-Lane (ADR-0061) · Korrektheits-Boden

**Ziel:** lang-pkgs-Fixes nicht mehr als host-applizierbar behaupten. Kein Agent-Change, kein Outbound.

**Tasks**
1. `risk_engine.py`: `fix_lane_for(finding_class, has_fix) -> Literal["patch","upstream","mitigate"]` als Single-Source + spiegelnder SQL-CASE-Helper.
2. Call-Sites auf den Single-Source umstellen: `finding_group_inheritance.py`, `pass2_enqueue.py`, `pass2_input_selection.py`-Caller, `llm_fingerprints.py` (Lane-Iteration über drei Werte).
3. Migration: `fix_lane`-CHECK → `IN ('patch','mitigate','upstream')`, Drop-&-Rebuild der Eval-Rows. `PASS2_PROMPT_VERSION`-Bump.
4. LLM-Layer: `upstream`-Prompt-Variante (kein `act`, „Upstream-Rebuild nötig"-Hinweis); `_validate_pass2_response` lehnt `act` bei `fix_lane=='upstream'` ab.
5. `_upsert_evaluation`: `action_type`-Ableitung um upstream-Zeilen (escalate→mitigate, monitor→watch, noise→none).
6. View/Template: ESCALATE·Upstream-Card in `_build_action_sections` + `_action_needed_section.html` + `application_group_card.html`; Card-Copy „Upstream fix — mitigate until rebuild", Fix-Version bleibt sichtbar.

**DoD (nur erlaubte Gates: ruff/mypy/shellcheck + pytest Pure-Unit)**
- `ruff check . && ruff format --check .` grün, `mypy app/` grün.
- Pure-Unit: `fix_lane_for`-Wahrheitstabelle (os-pkgs/lang-pkgs/other × has_fix), Validator-act-Reject-bei-upstream, `action_type`-Ableitung, Card-Matrix inkl. Group-in-mehreren-Cards, Inheritance-Drei-Wege-CASE.
- `alembic downgrade -1 && upgrade head` grün — **steht beim User an** (db_integration, nicht proaktiv).
- Regression: CVE-2026-42504/tailscaled landet in `upstream`, nicht `patch`; keine „Apply app update"-Card mehr dafür.

---

## Block AH — Host-Update-Flag (ADR-0062) · präzise statt pauschal

**Ziel:** `upstream`→`patch` promoten, wenn der Host das besitzende Paket wirklich updaten kann.

**Tasks**
1. Agent-Skript: Binary→Paket (`rpm -qf` / `dpkg -S`), Update-Probe (`dnf check-update` / `apt-get -s upgrade`), read-only, gebündelt pro Paket, Timeout-gekapselt. → ein Boolean `host_update_available` (+ optional `owning_package`/`available_version`).
2. `scan_envelope.py`: neue optionale Envelope-Felder (`extra="ignore"`).
3. Finding-Schema: nullable `host_update_available` (+ optional Felder), Migration.
4. `fix_lane_for` um den Flag erweitern (lang-pkgs+has_fix+flag=true → patch; false/NULL → upstream); SQL-Spiegel zieht das Feld mit. Agent-Version-Gate.
5. UI: „host update ready: `<pkg> <version>`" auf der patch-Card bei Promotion aus lang-pkgs.

**DoD**
- ruff/mypy grün; Agent-Shell shellcheck-grün.
- Pure-Unit: Resolver-Output-Parsing (rpm/dpkg/dnf/apt als String-Fixtures), Lane-Ableitung mit Flag-Matrix, NULL-Fallback = ADR-0061-Verhalten.
- Migration-Roundtrip + Live-Paketmanager-Verprobung **beim User** (db_integration/Host-Smoke, nicht proaktiv; keine neuen `.bats`/Live-Tests ohne Genehmigung).

---

## Block AI — agentische Upstream-Suche (ADR-0063) · beratend, optional

**Ziel:** on-demand-Lookup für nicht-paketierte / EOL-Fälle. Operator-gated, nie Auto-Band-Flip.

**Tasks**
1. Optionales Feature-Flag/Config (Outbound-Endpoint + Allowlist), Default aus; Doku in `docs/operations.md`.
2. Lookup-Service als eigener Pfad (nicht `llm_worker`/`group_chat`): Seed aus Buildinfo (Go-Main-Module/PURL + installierte Version), agentischer Web-Lookup, zitiertes Ergebnis.
3. Cache pro `(Modul, installierte Version)` + TTL; Rate-Limit + Kosten-Cap.
4. UI: Button „Check for upstream update" pro escalate-/no-host-patch-Finding; advisory-Panel „candidate · verify" mit Quellen-Links, kein `|safe`, Marker-Neutralisierung wie group_chat.
5. ARCHITECTURE §17: fokussiertes on-demand-Lookup als Ausnahme zu ADR-0050 führen (analog ADR-0055).

**DoD**
- ruff/mypy grün.
- Pure-Unit: Seed-Extraktion, Output-Parsing/Escaping (XSS/Marker), Cache-Key/TTL, „flippt-Band-nie"-Regression.
- Air-Gap-Default-aus verifiziert; Live-Browsing-Tests nur nach User-Genehmigung.

---

## Was bewusst NICHT passiert

- Kein Trivy-`--pkg-types os` (würde die wertvolle gobinary-Detektion abschalten).
- Kein Distro-Upgrade-/EOL-Reasoning im Agent (AH) — das ist AIs/Operators Job.
- Keine stille Band-Änderung durch Web-Ergebnisse (AI).
- Kein Per-Paket-Allowlist — die Achse ist `finding_class`, ecosystem-agnostisch.
