# Block Y — Orchestrator-Prompt

Implementiere **Block Y** (Server-Detail Lazy-Render + Triage-Queue-Pagination).

## Pflicht-Lektüre vor dem ersten Codestrich

1. `CLAUDE.md` — komplett (Tech-Stack, Conventions, Test-Konvention, OOB-Single-Source-Pattern, Timeout-Regeln).
2. `docs/blocks/Y-server-detail-lazy-render.md` — Block-Spec mit allen vier Phasen, DoD pro Phase, DoD Block-Gesamt.
3. `docs/decisions/0039-server-detail-lazy-render-architecture.md` — ADR mit Architektur-Entscheidung, Endpoint-Tabelle, Projektions-Spalten, Skeleton-Spec, Verworfenes.
4. `app/views/server_detail.py` — aktueller Code, alle zu ändernden Funktionen.
5. `app/templates/servers/detail.html` + `_view_groups.html` + `_partials/risk_band_section.html` + `_partials/group_findings_table.html` — aktuelles Markup.
6. `docs/design/ServerDetail.jsx` + `docs/design/server-detail.css` — Skeleton-Klassen (`sd-skel-frame`, `sd-heartbeat__tick--skel`, `sd-trend-col--skel`, `sd-tile--skel`).

## Arbeitsweise

- **Reihenfolge: A → B → C → D** (B und C können nach A parallel als separate Agents laufen).
- Pro Phase: implementieren → Tests schreiben → `ruff check . && ruff format --check .` → `mypy app/` → `pytest` (Default-Selektion, Timeout ≤ 120 s) → DoD-Checkliste der Phase maschinell prüfen (grep-Checks etc.).
- **Keine** db_integration/acceptance/integration/bench/bats/Docker-Tests. Keine neuen .bats/.sh-Testdateien.
- **Keine** Schema-Migration. Block Y ist Code-only.
- Wenn ein Quality-Gate rot ist: selbst fixen, nicht den User fragen.
- Wenn ein architektonischer Blocker auftritt der von der Spec abweicht: **STOP**, User fragen.
- Nach Phase D: Block-Gesamt-DoD prüfen, Ergebnis als Zusammenfassung melden. Erst dann stoppt der Agent.

## Was NICHT im Prompt steht (weil in Block-Spec + ADR)

Datei-Listen, Query-SQL, Endpoint-Signaturen, Template-Markup, Sort-Reihenfolge, Projektions-Spalten, Skeleton-Details, Pagination-Logik, Risiken — alles in den Spec-Dokumenten. Dort nachschlagen, nicht raten.
