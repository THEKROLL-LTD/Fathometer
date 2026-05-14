# secscan

Selbst-gehostete Web-App, die Trivy-Filesystem-Scans von Root-Servern einsammelt und in einem ruhigen Dashboard zur Triage anbietet. Spirit: uptime-kuma für CVEs auf laufenden Servern. Vision und Detail-Spec in [`ARCHITECTURE.md`](ARCHITECTURE.md).

**Status: Spec-Phase abgeschlossen, Implementierung steht aus.**

## Repo-Struktur

```
secscan/
├── ARCHITECTURE.md          # die Spec — primäre Quelle aller Implementierungs-Entscheidungen
├── CLAUDE.md                # Master-Kontext für Claude Code (Tech-Stack, Workflow, Out-of-Scope)
├── README.md                # diese Datei
├── docs/
│   ├── blocks/
│   │   ├── STATE.md         # Orchestrator-State (aktueller Block, Blocker)
│   │   ├── A-skeleton.md    # Block-Plan + Definition of Done
│   │   ├── B-models.md      # …
│   │   └── …                # bis H-polish.md
│   └── decisions/           # ADRs (Architecture Decision Records)
│       ├── 0001-no-node-build.md
│       └── …
├── .claude/
│   └── agents/              # Subagent-Definitionen für Claude Code
│       ├── backend-implementer.md
│       ├── frontend-implementer.md
│       ├── test-writer.md
│       ├── reviewer.md
│       └── security-auditor.md
├── agent/                   # Referenz-Implementierung des Push-Agents (Bash)
│   ├── secscan-agent.sh
│   ├── secscan-register.sh
│   └── README.md
└── tests/
    └── fixtures/
        └── trivy/           # echte Trivy-JSON-Outputs für Tests
            ├── README.md
            ├── ubuntu-22.04-rke2.json     # realer 5-MB-Scan
            └── adversarial.json            # synthetische Bad-Inputs
```

Die Verzeichnisse `app/`, `alembic/`, `tests/api/` etc. werden ab Block A vom `backend-implementer`-Agent erzeugt.

## Implementierung mit Claude Code

Diese Spec ist darauf ausgelegt, dass Claude Code als Orchestrator mit spezialisierten Subagenten arbeitet. Der grobe Loop:

1. Du startest `claude` im Repo-Root.
2. Claude Code liest `CLAUDE.md`, `ARCHITECTURE.md`, `docs/blocks/STATE.md` und den aktuellen Block-Plan.
3. Delegiert Implementierung an den passenden Implementer-Agent, danach Tests an den `test-writer`, danach Review gegen die Block-DoD-Checkliste an den `reviewer` (read-only).
4. Bei Sicherheits-relevanten Blöcken zusätzlich `security-auditor`.
5. STOP an jedem Block-Übergang — du gibst explizit frei.

Standing-Order-Prompt zum Start eines neuen Blocks:

```
Lies CLAUDE.md, ARCHITECTURE.md sowie docs/blocks/STATE.md und den aktuellen
Block-Plan. Starte den im STATE.md vermerkten Block. Delegiere an Subagenten
gemäß CLAUDE.md-Workflow. Frage mich vor jedem destruktiven oder ungeklärten
Schritt. Stoppe vor dem nächsten Block-Übergang.
```

## Implementierungs-Reihenfolge (acht Blöcke)

| Block | Inhalt | Plan |
|-------|--------|------|
| A | Skelett, Compose, App-Factory mit Limits/Logging | [`docs/blocks/A-skeleton.md`](docs/blocks/A-skeleton.md) |
| B | Datenmodell, Setup-Wizard, Admin-Auth | [`docs/blocks/B-models.md`](docs/blocks/B-models.md) |
| C | Ingest, Server-Verwaltung, Agent-E2E-Tests | [`docs/blocks/C-ingest.md`](docs/blocks/C-ingest.md) |
| D | Dashboard mit Tags und Stale-Detection | [`docs/blocks/D-dashboard.md`](docs/blocks/D-dashboard.md) |
| E | Triage-View (Liste, Group-by-Package, Diff) | [`docs/blocks/E-triage.md`](docs/blocks/E-triage.md) |
| F | Bulk-Operationen und globale Suche | [`docs/blocks/F-bulk.md`](docs/blocks/F-bulk.md) |
| G | LLM-Integration mit Streaming-Chat | [`docs/blocks/G-llm.md`](docs/blocks/G-llm.md) |
| H | SSE-Live-Updates, Polish, Production-Smoke | [`docs/blocks/H-polish.md`](docs/blocks/H-polish.md) |

Aufwandsschätzung: ~8 Wochen Vollzeit oder 12–15 Wochen Teilzeit für einen Solo-Entwickler.

## Wenn etwas unklar ist

Frage in dieser Reihenfolge:

1. Steht es in `ARCHITECTURE.md`? Dann gilt das.
2. Steht es in einem ADR unter `docs/decisions/`? Dann gilt das.
3. Sonst: User fragen, Antwort als neue ADR festhalten, dann implementieren.
