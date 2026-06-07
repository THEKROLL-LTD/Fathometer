# ADR-0050 — Server-weites "Request AI Assessment"-Chat-Feature entfernt

**Status:** Akzeptiert · **Datum:** 2026-06-07 · **Block:** kein eigener Block (Feature-Removal)

Bezug: [ADR-0002](0002-openai-compatible-llm.md) (OpenAI-kompatible LLM-Abstraktion — bleibt, geteilt mit dem Risk-Reviewer), [ADR-0014](0014-token-cap-best-effort.md) (Token-Cap — Cap-Spalte bleibt, gilt jetzt allein dem Risk-Reviewer), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (LLM-Risk-Reviewer — bleibt unverändert, ist ab jetzt der einzige LLM-Konsument im UI), [ADR-0026](0026-async-scan-ingest.md) (Scan-Ingest — der Chat-Update-Hook wird aus dem Ingest-Pfad entfernt). Block G (LLM-Chat) ist durch diese ADR abgelöst.

## Kontext

Block G hat ein server-weites, interaktives LLM-Chat-Feature eingeführt: ein "Request AI assessment"-Button auf der Server-Detail-Seite startet eine `LlmConversation`, snapshotted alle offenen Findings, baut einen System-Prompt über **alle** Findings + Server-Details und streamt die Antwort per SSE. Folge-Fragen sind möglich, Conversations werden archiviert und beim Provider-/Modell-Wechsel automatisch geschlossen.

Operator-Praxis: das "die KI soll einfach mal über alle Findings + Server-Details drüberschauen" liefert keinen nützlichen Mehrwert gegenüber dem **per-Finding/per-Group Risk-Reviewer** (Block P, ADR-0023/0043), der bereits eine fokussierte, gecachte und auditierbare Risk-Band-Bewertung pro Application-Group erzeugt. Das freie Chat-Assessment ist zu unspezifisch, kostet Token und Wartung, und das UI/Prompt-Design passt nicht mehr zur triage-first-Server-Detail-Ansicht (ADR-0038/0041).

Das Feature soll **ersatzlos** entfernt werden. Eine künftige LLM-Assistenz auf der Server-Detail-Seite wird, falls überhaupt, **neu und anders** konzipiert (eigene ADR) — die alten Prompts und UI-Templates werden dafür nicht wiederverwendet.

## Entscheidung

Das Chat-Assessment-Feature wird komplett entfernt — UI, Routes, Prompts, Chat-Services, JS, DB-Tabellen, Tests. Die **geteilte LLM-Provider-Config** und der **Risk-Reviewer** bleiben unangetastet.

### Entfernt

- **Routes/Blueprint:** `app/api/llm_chat.py` (`llm_chat_bp` — `POST /servers/<id>/chat`, `POST /chat/<id>/messages`, `GET /chat/<id>/stream` (SSE), `GET /chat/<id>`, `POST /chat/<id>/archive`); Blueprint-Registration in `app/__init__.py`.
- **Prompt-Builder:** `app/services/llm_prompt.py` (`build_system_prompt`, `build_user_prompt_intro`, `build_update_system_note` — Chat-Prompt über alle Findings, gruppiert nach Paket). **Nicht** zu verwechseln mit `app/services/llm_prompts.py` (Plural, PASS1/PASS2 des Risk-Reviewers — bleibt).
- **Scan-Update-Hook:** `app/services/llm_update_hook.py` (`notify_conversations_for_scan`) + dessen Aufruf in `app/services/scan_processing.py` (Schritt 7).
- **Token-Tracker:** `app/services/llm_token_tracker.py` (summierte `LlmMessage`-Tokens für die Chat-80%/100%-Cap-Banner). Der Risk-Reviewer hat ein eigenes Budget-System (`app/services/llm_budget.py` — bleibt).
- **Templates/JS:** `app/templates/chat/` (komplett), `app/static/js/llm_chat.js`, der "Request AI assessment"-Button-Block + `sd-ai-button`-CSS in `servers/detail.html` / `server-detail.css`.
- **DB:** Models `LlmConversation` / `LlmMessage` / `LlmConversationFinding` + Enums `LlmConversationStatus` / `LlmMessageRole` (inkl. `__all__`-Exporte und Enum-Namens-Konstanten) aus `app/models.py`; Migration `0017_remove_llm_chat` droppt die drei Tabellen und die zwei Postgres-Enums (`downgrade()` rekonstruiert sie leer aus der `0002`-DDL).
- **Provider-Switch-Archivierung:** `_archive_active_conversations()` + die "X aktive Conversations werden archiviert"-Logik/Flash/Confirm-Modal in `app/views/llm_settings.py`, `settings/llm_provider.html`, `static/js/llm_settings.js`. Das Audit-Event `llm.provider_changed` **bleibt** (ohne `archived_conversations`-Metadata) — ein Provider-/Modell-Wechsel betrifft weiterhin den Risk-Reviewer.
- **Context-Processor** `_inject_llm_configured` (`llm_configured`) — existierte nur für den entfernten Button.
- **Audit:** `llm.queried` aus `audit_view.KNOWN_ACTIONS` (wird nicht mehr emittiert; Bestands-Audit-Rows bleiben sichtbar, nur nicht mehr filterbar).
- **Tests:** `tests/integration/test_llm_chat_db.py`, `tests/integration/test_llm_provider_switch_db.py`, `tests/services/test_llm_update_hook.py`, `tests/services/test_llm_token_tracker.py`, `tests/services/test_llm_prompt.py` (Singular), `tests/adversarial/test_prompt_injection.py` (testete den Chat-System-Prompt). Anpassungen in `conftest.py` (Truncate-/Acceptance-Listen), `test_settings_subpages_smoke.py`, `test_server_detail_fragments.py`.

### Bewusst behalten (geteilt mit dem Risk-Reviewer)

- `app/services/llm_client.py` (AsyncOpenAI-Wrapper, Fernet-Encrypt/Decrypt, `validate_base_url`, `build_client_from_settings`, `test_connection`).
- Provider-Config-Felder auf `Setting`: `llm_base_url`, `llm_model`, `llm_api_key_encrypted`, `llm_daily_token_cap`, `llm_provider_name`. **Keine** Spalten-Drops auf `settings` — nur die drei Chat-Tabellen fallen.
- `app/views/llm_settings.py` `show()` / `update()` / `test_connection()` und der `/settings/llm`-Tab (Provider-Konfiguration).
- Der gesamte Risk-Reviewer (Block P): `llm_prompts.py` (Plural), `llm_risk_reviewer.py`, `llm_budget.py`, `llm_worker.py`, `application_group_evaluations`, der `/settings/llm_reviewer`-Tab.

## Begründung

- **Kein Nutzwert:** das pauschale "drüberschauen über alles" konkurriert mit dem fokussierten Risk-Reviewer und verliert. Token-Kosten ohne Ertrag.
- **Wartungslast:** SSE-Streaming-Endpoint, Token-Tracker, Update-Hook im Ingest-Pfad, Provider-Switch-Archivierung, ein eigenes JS-Modul und ~1600 Zeilen Chat-Tests — alles tote Komplexität sobald das Feature wegfällt.
- **Sauberer Schnitt statt Dormant-Code:** voll entfernen inkl. Drop-Migration (User-Entscheidung). Eine künftige Neu-Implementierung wird anders aussehen und soll nicht durch ein totes Schema/totes UI vorbelastet sein.

## Konsequenzen

- **ARCHITECTURE.md** ist nach dem parallel laufenden Rewrite synchronisiert: §2 (In-Scope-Liste), §4 (Datenmodell — `llm_*`-Conversation-Bullet raus), §7 (HTMX-Polling — kein SSE-Endpunkt mehr), §8 (Server-Detail-Routes — `/chat`-Route raus), §9 (DoS — LLM-Kostenschutz auf den Worker-Cap umgestellt), §11 (LLM-Integration — Chat-Abschnitt entfernt, nur noch Risk-Reviewer) und die `audit_events`-Liste (`llm.queried` → `llm.provider_changed`). Die **Provider-Abstraktion / Test-Verbindung**-Teile von §11 bleiben gültig (Risk-Reviewer-Konsument).
- **ADR-0023** bleibt akzeptiert; der dort erwähnte "Block-G-`AsyncOpenAI`-Wrapper wird wiederverwendet" bezieht sich auf `llm_client.py`, das erhalten bleibt — nur das Chat-Feature obendrauf ist weg.
- **ADR-0026:** der Scan-Ingest-Pfad ruft keinen Chat-Update-Hook mehr auf; der Async-Ingest-Kern ist davon unberührt.
- **Migration 0017** ist destruktiv für Conversation-Bestandsdaten (kein Restore im `downgrade()`). Air-Gap-/Operator-Hinweis: `alembic upgrade head` löscht vorhandene Chat-Historie.
- **`llm.provider_changed`** bleibt als Audit-Event erhalten (ohne Conversation-IDs), ist aber weiterhin nicht in `KNOWN_ACTIONS` als Filter gelistet (war es vorher auch nicht).

## Re-Open-Trigger

- Eine **neu konzipierte** LLM-Assistenz auf der Server-Detail-Seite (z.B. fokussiert auf eine einzelne Application-Group oder ein einzelnes Finding statt "alles auf einmal") — eigene ADR, eigenes Schema, eigene Prompts. Diese ADR präjudiziert das Design nicht.
- Prompt-Injection-Härtung: der entfernte `tests/adversarial/test_prompt_injection.py` deckte den **Chat**-System-Prompt ab. Die Injektions-Marker-Doktrin (ARCHITECTURE §10) gilt weiterhin für die Risk-Reviewer-Prompts; eine dedizierte Adversarial-Suite dafür ist ein offener Punkt, falls noch nicht vorhanden.
