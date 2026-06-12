# ADR-0056 — Risk-Reviewer-Tages-Cap kommt aus der DB (`llm_daily_token_cap`), nicht aus dem Env

**Status:** Akzeptiert · **Datum:** 2026-06-12

Bezug: [ADR-0014](0014-token-cap-best-effort.md) (definiert `Setting.llm_daily_token_cap` als **den** Tages-Token-Cost-Cap — diese ADR stellt die Block-P-Implementierung wieder darauf zurück), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Block-P-Risk-Reviewer + Token-Budget-Service — dessen Env-basiertes `llm_token_budget_daily` war die Drift), [ADR-0055](0055-per-group-ai-chat.md) (Per-Group-Chat zählt bewusst **nicht** gegen `llm_daily_token_cap` — unverändert).

## Kontext

Es existierten **zwei** Tages-Cap-Mechanismen nebeneinander:

1. **`Setting.llm_daily_token_cap`** (DB-Spalte, Operator-steuerbar über den Provider-Tab „Daily token cap"). Das ist der von ADR-0014 definierte Cap und der, auf den sich ARCHITECTURE.md §5/§13 (DoS-LLM-Kostenschutz) beziehen.
2. **`config.llm_token_budget_daily`** (Pydantic-Settings-Layer, Env `FM_LLM_TOKEN_BUDGET_DAILY`, Default 2 M). Eingeführt mit dem Block-P-Budget-Service (`app/services/llm_budget.py`).

Der Worker hat über `budget_check` **ausschließlich (2)** erzwungen und **(1) komplett ignoriert**. Folgen:

- **Operator-Verwirrung:** Der Operator setzte im UI „Daily token cap" auf 3.000.000 (`llm_daily_token_cap = 3_000_000`), der Worker hielt sich aber an den Env-Wert. Die UI-Eingabe war wirkungslos.
- **Web-vs-Worker-Drift:** `llm_token_budget_daily` ist Pod-lokales Env. Der Web-Pod (kein Env → Code-Default 2 M) und der Worker-Pod (`FM_LLM_TOKEN_BUDGET_DAILY=1000000`) sahen **unterschiedliche** Caps. Der „Budget & cache"-Screen (Web-Pod) zeigte 2 M, der Worker pausierte bei 1 M (`budget_pct=101`, `job_pickup_paused`) mit 64 wartenden Jobs.
- **Spec-Inkonsistenz:** ARCHITECTURE.md §13 nennt korrekt `llm_daily_token_cap`, §11 nannte fälschlich `LLM_TOKEN_BUDGET_DAILY`.

## Entscheidung

Der Block-P-Risk-Reviewer-Budget-Service erzwingt den **DB-Cap `Setting.llm_daily_token_cap`** — den ADR-0014-Cap, Operator-steuerbar über den bestehenden Provider-Tab.

- `llm_budget.budget_check` und der `budget_pct`-Status-Snapshot (`llm_worker._maybe_emit_status_snapshot`) lesen `row.llm_daily_token_cap`.
- Der „Budget & cache"-Screen (`/settings/llm-reviewer`) zeigt denselben DB-Wert — kein Pod-Drift mehr, Web und Worker stimmen per Konstruktion überein.
- Worker liest den neuen Wert binnen ≤ 60 s (`_budget_ok_throttled`-Cache) — kein Pod-Restart nötig.

`config.llm_token_budget_daily` / `FM_LLM_TOKEN_BUDGET_DAILY` wird **zum reinen Install-Seed degradiert**: `ensure_settings_row` initialisiert `llm_daily_token_cap` frischer Installs aus diesem Wert. Zur Laufzeit ist es **nicht mehr** die Cap-Autorität. Der Env-Knopf bleibt erhalten (Default 2 M), damit Greenfield-Deploys den Initial-Cap ohne UI-Schritt setzen können.

## Begründung

- **Single Source of Truth:** Ein Cap, in der DB, von beiden Pods gelesen. Strukturell drift-frei.
- **Spec-Treue:** ADR-0014 und ARCHITECTURE.md §13 nannten immer `llm_daily_token_cap`. Der Env-Pfad war eine unbeabsichtigte Block-P-Drift, kein bewusster zweiter Mechanismus.
- **Operator-Erwartung:** „Im UI gesetzt" muss „vom Worker befolgt" bedeuten. Der Provider-Tab-Edit-Pfad existierte bereits — er war nur an nichts angeschlossen.
- **Minimal-invasiv:** Keine neue Migration (Spalte existiert seit `0002`), kein neues Formular, kein neuer Edit-Punkt. Reines Umverdrahten des Lese-Pfads + Doku-Reconciliation.

## Konsequenzen

- Bestehende Installs: der Worker honoriert ab sofort den im Provider-Tab gesetzten `llm_daily_token_cap`. Wer bisher implizit auf den Env-Wert vertraut hat, sollte den UI-Wert prüfen.
- Deployment-Manifeste, die `FM_LLM_TOKEN_BUDGET_DAILY` auf dem Worker setzen, beeinflussen den Laufzeit-Cap **nicht mehr** (nur noch Fresh-Install-Seed). Der Env-Override sollte aus den Worker-Manifesten entfernt werden, um Verwirrung zu vermeiden.
- `llm_token_budget_daily` bleibt als Config-Field bestehen (Seed-Rolle), mit Deprecation-Hinweis im Docstring.

## Re-Open-Trigger

- Falls ein verteiltes Multi-Instance-Deploy (heute Out-of-Scope, ARCHITECTURE §17) kommt, braucht der Cap-Reset (`maybe_reset_budget`) ggf. eine Leader-Election oder Advisory-Lock, damit nicht mehrere Worker gleichzeitig zurücksetzen.
