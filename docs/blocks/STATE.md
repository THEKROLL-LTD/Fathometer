# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Aktueller Block

**E — Triage** (noch nicht gestartet)

Plan: [`E-triage.md`](E-triage.md)

## Completed

- **A — Skelett und Basis** · abgeschlossen 2026-05-14 · Branch `feat/block-a` · Reviewer-Freigabe nach Re-Review (Gunicorn `HOME=/app` + `--worker-tmp-dir /dev/shm`-Fix).
- **B — Datenmodell, Setup-Wizard und Auth** · abgeschlossen 2026-05-14 · Branch `feat/block-b` · Reviewer-Freigabe nach Template-Fix (Pattern-Escape) und Re-Run der adversarial-Tests. 96 Tests grün. Setup-Flow-Screenshot unter `docs/blocks/B-evidence/setup-flow.png`.
- **C — Ingest, Server-Verwaltung und Agent-E2E** · abgeschlossen 2026-05-14 · Branch `feat/block-c` · Reviewer-Freigabe 24 PASS / 0 FAIL. 207 Tests grün, Coverage 91 %. Real-Fixture mit 306 Findings (296 lang-pkgs + 10 os-pkgs) durchläuft Ingest mit Auth-vor-Body-Parse (401 in 22 ms), gzip-Bomb-Bound (413 bei >100 MB), Idempotenz auf Re-Scan. Neue ADR-0011 (`package_name@target`-Disambiguation).
- **D — Dashboard mit Tags und Stale-Detection** · abgeschlossen 2026-05-14 · Branch `feat/block-d` · Reviewer-Freigabe 8 PASS / 0 FAIL / 5 PENDING (Operator-UX). 306 Tests grün (99 neue Block-D-Tests), Coverage 93 %. Dashboard-Screenshot unter `docs/blocks/D-evidence/dashboard.png` mit 3 Servern, KEV-Badge, Stale-Marker, Tag-Filter-Form und Aufmerksamkeits-Sektion.

## Backlog (in Reihenfolge)

| Block | Datei | Status |
|-------|-------|--------|
| A | [A-skeleton.md](A-skeleton.md) | completed 2026-05-14 |
| B | [B-models.md](B-models.md) | completed 2026-05-14 |
| C | [C-ingest.md](C-ingest.md) | completed 2026-05-14 |
| D | [D-dashboard.md](D-dashboard.md) | completed 2026-05-14 |
| E | [E-triage.md](E-triage.md) | aktueller Block |
| F | [F-bulk.md](F-bulk.md) | wartet auf E |
| G | [G-llm.md](G-llm.md) | wartet auf F |
| H | [H-polish.md](H-polish.md) | wartet auf G |

## Aktive Blocker

(keine)

## Offene ADR-Wünsche

(keine — wenn Implementer eine neue Architektur-Entscheidung braucht, hier eintragen und Spec ergänzen bevor Code geschrieben wird)

## Update-Konvention

- Beim Block-Start: Status auf "in progress" setzen, Branch-Name notieren.
- Beim Block-Abschluss (nach `reviewer`-Freigabe): Block in "Completed" verschieben mit Datum, nächsten Block als "Aktueller Block" markieren.
- Bei neuen Blockern: in "Aktive Blocker" eintragen mit Datum und Beschreibung.
- Aktive Blocker MÜSSEN aufgelöst sein bevor der Block als completed markiert wird.
