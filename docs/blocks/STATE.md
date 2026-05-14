# Orchestrator-State

Single source of truth für den Implementierungs-Fortschritt. Wird von der Hauptsession bei jedem Start gelesen und nach jedem Block-Übergang aktualisiert.

## Aktueller Block

**C — Ingest und Registrierung** (noch nicht gestartet)

Plan: [`C-ingest.md`](C-ingest.md)

## Completed

- **A — Skelett und Basis** · abgeschlossen 2026-05-14 · Branch `feat/block-a` · Reviewer-Freigabe nach Re-Review (Gunicorn `HOME=/app` + `--worker-tmp-dir /dev/shm`-Fix).
- **B — Datenmodell, Setup-Wizard und Auth** · abgeschlossen 2026-05-14 · Branch `feat/block-b` · Reviewer-Freigabe nach Template-Fix (Pattern-Escape) und Re-Run der adversarial-Tests. 96 Tests grün. Setup-Flow-Screenshot unter `docs/blocks/B-evidence/setup-flow.png`.

## Backlog (in Reihenfolge)

| Block | Datei | Status |
|-------|-------|--------|
| A | [A-skeleton.md](A-skeleton.md) | completed 2026-05-14 |
| B | [B-models.md](B-models.md) | completed 2026-05-14 |
| C | [C-ingest.md](C-ingest.md) | aktueller Block |
| D | [D-dashboard.md](D-dashboard.md) | wartet auf C |
| E | [E-triage.md](E-triage.md) | wartet auf D |
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
