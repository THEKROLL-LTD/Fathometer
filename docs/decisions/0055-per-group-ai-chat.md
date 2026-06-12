# ADR-0055 — Per-Group AI-Chat auf der Server-Detail-Seite

**Status:** Akzeptiert · **Datum:** 2026-06-11 · **Block:** AE (`feat/block-ae-group-chat`)

Bezug: [ADR-0050](0050-remove-llm-chat-assessment.md) (server-weites Chat-Assessment entfernt — diese ADR nutzt dessen **Re-Open-Trigger** „neu konzipierte, fokussierte LLM-Assistenz pro Application-Group"; ADR-0050 bleibt **akzeptiert**, wird nicht abgelöst, da das *server-weite* Feature endgültig weg bleibt), [ADR-0002](0002-openai-compatible-llm.md) (OpenAI-kompatible Abstraktion, kein Function-Calling — gilt weiter), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md)/[ADR-0043](0043-llm-risk-band-exploitability-model.md) (Risk-Reviewer/Application-Grouping — liefert Reason + Worst-Finding, bleibt unverändert), [ADR-0014](0014-token-cap-best-effort.md) (Token-Cap — gilt **nicht** für den Chat, siehe Entscheidung 4), [ADR-0045](0045-english-only-ui.md) (English-only-UI — Chat-Strings + System-Prompt englisch), [ADR-0052](0052-operator-sichten-jetzt-zustand.md) (Jetzt-Zustand — der Chat-Kontext ist bewusst ein **Snapshot**, siehe Entscheidung 3).

## Kontext

ADR-0050 hat das server-weite „Request AI Assessment"-Chat-Feature (Block G) ersatzlos entfernt, mit dem expliziten Re-Open-Trigger: eine künftige LLM-Assistenz wird *fokussiert* (pro Application-Group oder Finding statt „alles auf einmal"), neu konzipiert, mit eigenem Schema und eigenen Prompts.

Die Server-Detail-Seite ist seit ADR-0038/0041/0052 triage-first: Operator-Workflows gruppieren die Application-Groups nach Lane (ESCALATE/ACT/…), pro Group-Row zeigt der Risk-Reviewer (Block P) ein Worst-Finding und eine Reason. Operatoren brauchen an genau dieser Stelle die Möglichkeit, gezielt nachzufragen — „warum ist das kritisch", „in welcher Reihenfolge patchen", „kann ich das deferren" — ohne die Seite zu verlassen und ohne ein unfokussiertes Server-Gesamt-Assessment.

Das Mockup (`docs/design/ServerDetail.jsx`, `WorkflowChat`/`WorkflowCard`) zeigt den Ziel-Flow: ein „Help"-Button pro Group-Row öffnet einen Chat-Sub-View, eingebettet in dieselbe Detail-Pane wie der Settings-Sub-View.

## Entscheidung

Wir führen einen **fokussierten LLM-Chat pro (Server, Application-Group)** ein. Einstieg ausschließlich über einen **„Help"-Button pro Group-Row in den Operator-Workflows** — nirgends sonst. Es gibt **keinen** server-weiten Chat.

Wiederverwendet wird der erhaltene `app/services/llm_client.py` (`LlmClient.stream_chat`, `build_client_from_settings`) und die geteilte Provider-Config. Frontend, Prompt-Builder, Routen und Schema sind **neu**.

### 1. Persistenz — eine Konversation pro (Server, Group), kein Archiv

Genau **eine** Konversation pro `(server_id, application_group_id)`, DB-persistiert über Reloads/Sessions (`UNIQUE`-Constraint). Es gibt **kein Archiv** und keine Mehrfach-Historie. Der „New Chat"-Button **löscht** die Konversation unwiderruflich (CASCADE auf die Messages); die nächste Nachricht legt sie frisch an. So existiert pro Group immer höchstens eine Konversation.

### 2. Delivery — SSE-Streaming

Antworten streamen token-by-token per Server-Sent-Events über `LlmClient.stream_chat`. Die Assistant-Message wird nach Stream-Ende in einer eigenen Session persistiert (Muster aus dem entfernten `llm_chat.stream`, übernommen — nicht das Feature, nur das Streaming-Pattern).

### 3. Kontext — Snapshot bei Chat-Start

Beim Anlegen der Konversation (erste User-Nachricht) wird der Kontext **eingefroren**: Host-Fingerprint, Active Services, Listener (inkl. Exposure) und **alle OPEN-Findings der Group** werden zum Snapshot-Zeitpunkt in den System-Prompt gerendert und persistiert. `findings_snapshot_at` hält den Zeitpunkt. Ein Re-Scan ändert eine laufende Konversation **nicht** — bewusste Abweichung von der Jetzt-Zustand-Doktrin (ADR-0052), damit die Konversation in sich konsistent bleibt. Frischer Kontext nach Re-Scan = „New Chat".

### 4. Token-Budget — kein Cap

Der Chat zählt **nicht** gegen `llm_daily_token_cap` und ruft `llm_budget` nicht auf. Der Cap (ADR-0014) gilt weiterhin allein dem Risk-Reviewer. Begründung: interaktive Operator-Nutzung ist niederfrequent und manuell ausgelöst; ein Cap würde im Triage-Moment blockieren. Optional werden Stream-Metriken in `llm_debug_log` für Observability geschrieben.

### Neu

- **Schema (Migration `0023`):** `group_chat_conversations` (`id`, `server_id` FK CASCADE, `application_group_id` FK CASCADE, `model`, `created_at`, `last_message_at`, `findings_snapshot_at`, `UNIQUE(server_id, application_group_id)`) + `group_chat_messages` (`id`, `conversation_id` FK CASCADE, `role` ENUM `chat_message_role` (`system`/`user`/`assistant`), `content`, `created_at`, `prompt_tokens?`, `completion_tokens?`, INDEX `(conversation_id, created_at, id)`). Kein Findings-Bridge-Table — der Snapshot lebt im persistierten System-Prompt. `downgrade()` droppt beide Tabellen + Enum (Muster `0017`).
- **Prompt-Builder** `app/services/group_chat_prompt.py`: `build_group_system_prompt(...)` (englisch, Anti-Injection-Marker `<<TRIVY_DATA_START>>`/`<<TRIVY_DATA_END>>`, Display-Sanitization `_safe` portiert aus dem alten `llm_prompt.py`), plus die `CHAT_SUGGESTIONS`-Konstante (single-source für Template + Test).
- **Blueprint** `app/api/group_chat.py`: `GET .../chat` (Sub-View-Fragment + Vollseite), `POST .../chat/messages` (Lazy-Create + Snapshot), `GET .../chat/stream` (SSE), `POST .../chat/new` (Delete). Alle `@login_required`, CSRF auf POST, `flask-limiter`, 404-Guard (Server aktiv + Group hat OPEN-Findings auf diesem Server).
- **Frontend:** Help-Button (`sd-ask-btn`) als 4. Spalte in `_action_needed_section.html`; Chat-Sub-View-Template + Single-Source-Bubble-Partial; JS-Modul `frontend/src/js/group_chat.js` (Alpine + EventSource, Deltas via `textContent`); CSS-Port der `sd-chat-*`/`sd-ask-btn`-Klassen aus `docs/design/server-detail.css`.

### Bewusst behalten / unverändert

`llm_client.py`, Provider-Config auf `Setting`, `/settings/llm`, der gesamte Risk-Reviewer (Block P), `llm_budget.py` (nur vom Reviewer genutzt).

## Begründung

- **Fokus schlägt Breite:** der entfernte Server-weit-Chat war unspezifisch (ADR-0050). Pro-Group-Kontext (Exposure + Findings einer Group) ist genau die Einheit, in der der Operator triagiert und der Reviewer bereits urteilt.
- **Re-Use ohne Altlast:** der erhaltene `llm_client` + SSE-Pattern werden wiederverwendet, aber Schema/Prompt/UI sind neu und nicht durch das tote Block-G-Design vorbelastet (wie in ADR-0050 §Re-Open-Trigger zugesagt).
- **Snapshot statt Live:** eine in sich konsistente Konversation ist im Triage-Dialog wichtiger als Live-Aktualität; der Operator zieht bei Bedarf bewusst einen frischen Snapshot via „New Chat".
- **Kein Cap:** manuelle, seltene Interaktion; ein Block im Triage-Moment wäre schädlicher als das Kostenrisiko.

## Konsequenzen

- **ARCHITECTURE.md** wird ergänzt: In-Scope-Liste (fokussierter Group-Chat; server-weiter Chat bleibt out-of-scope), Datenmodell (`group_chat_*`), §10 (Marker-Konvention — gilt jetzt auch für den Chat-Prompt), §11/§12 (LLM-Integration — zweiter Konsument neben dem Reviewer, group-scoped, kein Cap), Routen-Liste (`/servers/<id>/groups/<gid>/chat[...]`), §7 (SSE-Endpoint wieder vorhanden).
- **CLAUDE.md §Out of Scope:** Notiz, dass der *server-weite* Chat weiterhin out-of-scope ist; der *Group*-Chat ist ab Block AE in-scope.
- **Migration `0023`** ist additiv (zwei neue Tabellen, ein Enum) — Alembic-Roundtrip steht beim User an (db_integration).
- **Prompt-Injection-Härtung:** die Marker-Doktrin (ARCHITECTURE §10) gilt für den neuen Chat-Prompt; eine dedizierte Adversarial-Suite (`tests/adversarial/`) ist Pflicht-Teil von Block AE.
- **Sprache:** Chat-UI-Strings + System-Prompt englisch (ADR-0045); die deutschen Screenshots (`KI-Assistent`/`Zurück`) sind ein älterer Design-Stand und nicht maßgeblich.

## Re-Open-Trigger

- **Server-weiter Chat** bleibt verworfen (ADR-0050) — kein Re-Open.
- **Live-Kontext statt Snapshot** (falls Operator-Feedback Snapshot-Staleness als störend meldet): eigene Entscheidung, würde Entscheidung 3 amenden.
- **Token-Cap für den Chat** (falls Kosten-Runaway beobachtet wird): würde Entscheidung 4 amenden, neues Settings-Feld + Tracking.
- **Chat pro Finding** (statt pro Group) oder von anderen Surfaces (`/findings`): eigene ADR.
