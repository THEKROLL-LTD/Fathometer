# Block AE — Implementer-Prompts (Dev-Handoff)

Scoped Prompts für die Subagenten. Reihenfolge ist verbindlich (Schema → Prompt → Backend → Frontend → Review). Jeder Prompt nennt die zu lesenden Sektionen explizit. **Pflicht-Lektüre vorab für jeden Agenten:** `docs/decisions/0055-per-group-ai-chat.md`, `docs/blocks/AE-group-chat.md`, `CLAUDE.md` (Test-Konvention + HTMX-OOB-Single-Source).

---

## Gemeinsamer Test-/Quality-Gate-Block (wörtlich in JEDEN Prompt einfügen)

> Erlaubte Quality-Gates: `ruff check`, `ruff format --check`, `shellcheck` (Linter), `mypy app/` (Static Analyzer), `pytest` Default-Selektion (Pure-Unit, Mocks/Stubs/Fakes wo nötig). Verboten — keine proaktiven Aufrufe: `pytest -m db_integration|acceptance|integration|bench`, `bats`/`.sh`-Test-Frameworks, `RUN_E2E=1`, Docker-Compose/`docker build`/`curl /healthz`, Alembic-Roundtrip gegen echte DB, Browser-/Playwright-/Selenium-Tests, Performance-Benches. Keine neuen `.bats`/`.sh`-Test-Dateien. Wenn Logik nur mit echter Postgres/Docker/HTTP testbar ist: DoD-Item als „beim User anstehen lassen" markieren, **nicht** selbst laufen lassen. Jeder `pytest`-Bash-Aufruf hat ein `timeout`-Argument ≤ 120000 ms (Default-Suite) bzw. ≤ 60000 ms (fokussierter Sub-Lauf); zusätzlich `--timeout=30 --timeout-method=thread` wo `pytest-timeout` verfügbar. UI-Strings + LLM-System-Prompt **englisch** (ADR-0045); Sprach-Sweep-Test `tests/test_ui_language.py` muss grün bleiben. Niemals `|safe` auf Client-/LLM-/Scanner-Daten. Niemals `text()` ohne `:param`-Bind.

---

## Prompt 1 — `backend-implementer`: Schema + Migration + ORM

**Lies:** ADR-0055 §Entscheidung/§Neu, AE-group-chat.md §3, ARCHITECTURE.md Datenmodell-Sektion, bestehende Migration `alembic/versions/0017_remove_llm_chat.py` (Enum-Create/Drop-Muster) und `0022_fix_lane_evaluation.py` (aktuelle Head-Revision).

**Aufgabe:**
1. Migration `alembic/versions/0023_block_ae_group_chat.py`, `down_revision = "0022_fix_lane_evaluation"`. Erzeugt Enum `chat_message_role` (`system`/`user`/`assistant`) + Tabellen `group_chat_conversations` und `group_chat_messages` exakt nach AE-group-chat.md §3 (FK CASCADE, `UNIQUE(server_id, application_group_id)`, INDEX `(conversation_id, created_at, id)`). `downgrade()` droppt beide Tabellen (child→parent) + Enum (`checkfirst=False`), Muster wie `0017`.
2. ORM-Modelle in `app/models.py`: `GroupChatConversation`, `GroupChatMessage`, Enum `ChatMessageRole` (Python-Enum, `values_callable`-Muster wie bestehende Enums prüfen). `__all__`-Exporte. Relationship `messages` mit `cascade="all, delete-orphan"`, `order_by` auf `(created_at, id)`.

**DoD (maschinell prüfbar, Pure-Unit-Teil):** `ruff`/`mypy app/` grün; Pure-Unit-Modell-Tests (`tests/models/test_group_chat.py`): Enum-Werte, Relationship-Cascade-Config, `__all__`-Präsenz. **Beim User anstehend:** `alembic upgrade head && downgrade -1 && upgrade head` + UNIQUE/CASCADE-Semantik (db_integration).

[+ Gemeinsamer Test-Block]

---

## Prompt 2 — `backend-implementer`: Prompt-Builder + Suggestions

**Lies:** ADR-0055 §Neu, AE-group-chat.md §4/§6, ARCHITECTURE.md §10 (Marker-Konvention), das alte `app/services/llm_prompt.py` aus der Historie (`git show cd2d65e^:app/services/llm_prompt.py`) für `_safe`/`_format_finding_line`, sowie `_load_host_snapshot` in `app/views/server_detail.py` für die Kontext-Datenform (`listeners`/`services`/`processes`).

**Aufgabe:** `app/services/group_chat_prompt.py`:
- `CHAT_SUGGESTIONS = ["Explain attack vector"]` (single-source).
- `build_group_system_prompt(*, server, group_label, lane, worst_finding, reason, host_snapshot, group_findings) -> str` — Aufbau exakt nach AE-group-chat.md §4 (Intro englisch, Anti-Injection-Guard, Marker, Fingerprint, Services, Listener mit Exposure, Group-Kontext, Findings-Zeilen). `_safe`-Sanitization portieren (Control-Chars raus außer `\t`/`\n`, Längen-Cap).
- Optional `build_user_intro(group_label) -> str`.

**DoD:** `ruff`/`mypy app/` grün; Pure-Unit-Tests (`tests/services/test_group_chat_prompt.py`): Marker-Disziplin, `_safe` (NUL/Control/Übergröße), Findings-Zeilen-Format, leere Group („No open findings…"), Listener-Exposure-Rendering, alle Felder zwischen den Markern. Adversarial (`tests/adversarial/test_group_chat_prompt_injection.py`): manipulierter Finding-Title/Reason mit Marker-/Instruction-Strings bricht die Marker nicht.

[+ Gemeinsamer Test-Block]

---

## Prompt 3 — `backend-implementer`: Blueprint + SSE-Routen

**Lies:** ADR-0055 §Entscheidung 1–4, AE-group-chat.md §5, das alte `app/api/llm_chat.py` aus der Historie (`git show cd2d65e^:app/api/llm_chat.py`) für SSE-Generator + Assistant-Persistenz-Muster, `app/services/llm_client.py` (`build_client_from_settings`/`stream_chat`), `group_findings_fragment` + `_load_application_groups_for_server`/`_build_action_sections` in `app/views/server_detail.py` (Worst/Reason/Lane), `app/__init__.py` (Blueprint-Registration).

**Aufgabe:** `app/api/group_chat.py` (`group_chat_bp`), registriert in `app/__init__.py`:
- `GET /servers/<int:sid>/groups/<int:gid>/chat` — Sub-View-Fragment (`#detail-pane-content`) + Vollseite; rendert bestehende Konversation oder Empty-State mit `CHAT_SUGGESTIONS`-Chips. Legt **nichts** an.
- `POST .../chat/messages` — User-Message anhängen; existiert keine Konversation → anlegen + Snapshot (System-Prompt via `build_group_system_prompt` bauen+persistieren, `findings_snapshot_at=now`, `model=Setting.llm_model`). Antwort: User-Bubble-Partial + `stream_url`. `400 llm_not_configured` bei fehlendem Provider.
- `GET .../chat/stream` — SSE (`text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`): letzte Historie an Provider, Deltas als `data:`-Frames, `event: done`; Assistant-Message + Usage in eigener Session nach Stream-Ende persistieren; `last_message_at` updaten.
- `POST .../chat/new` — Konversation löschen (CASCADE), Empty-State zurück.

Alle `@login_required`, CSRF auf POST (Flask-WTF), `flask-limiter`, 404-Guard: Server aktiv **und** Group hat OPEN-Findings auf diesem Server (Cross-Server/Cross-Group-Probing). **Kein** `llm_budget`-Aufruf. Optional `llm_debug_log`-Eintrag pro Stream. Kein Function-Calling (ADR-0002), Modell nur `Setting.llm_model`.

**DoD:** `ruff`/`mypy app/` grün; Pure-Unit/Mock-Tests (`tests/api/test_group_chat.py`): 404 Cross-Server/Cross-Group, `llm_not_configured`-400, CSRF, Lazy-Create-bei-erstem-POST (Snapshot-Persistenz), Resume vs. Create, New-Chat-Delete-Statement, SSE-Generator mit Mock-Client (Delta- + `done`-Frame, Assistant-Persistenz). **Beim User anstehend:** SSE-E2E gegen Live-Provider (integration).

[+ Gemeinsamer Test-Block]

---

## Prompt 4 — `frontend-implementer`: Sub-View + Help-Button + JS + CSS

**Lies:** ADR-0055 §Neu/§Frontend, AE-group-chat.md §7/§8, `docs/design/ServerDetail.jsx` (Z.198–468: `ChatGlyph`/`WorkflowCard`/`WorkflowChat`/`CHAT_SUGGESTIONS`), `docs/design/server-detail.css` (`sd-chat-*`/`sd-ask-btn`/`sd-newchat`/`workflow-table__ask`), `app/templates/servers/_action_needed_section.html` (Workflow-Table — Einbau-Stelle), das alte `app/static/js/llm_chat.js` aus der Historie (EventSource-Muster), `CLAUDE.md` §HTMX-OOB-Single-Source-Pattern.

**Aufgabe:**
1. **Help-Button** als 4. Spalte `workflow-table__ask` (`sd-ask-btn`, ChatGlyph + „Help") in `_action_needed_section.html`, pro Group-Row genau einer; `hx-get` auf die Chat-Route, Target `#detail-pane-content` (analog Zahnrad→Settings). **Nur hier** — nicht in `application_group_card.html` (orphaned).
2. **Chat-Sub-View-Template** `servers/group_chat.html` + Partials (Header-Strip mit Back/Titel/New-Chat, `sd-chat-meta`-Context-Line, `sd-chat-thread`, Composer `sd-chat-dock`, Foot-Hint). **Single-Source-Bubble-Partial** `_partials/group_chat_message.html` für Initial-Render **und** Stream-Append (gleiche IDs/Klassen).
3. **JS-Modul** `frontend/src/js/group_chat.js` (Alpine): Submit→POST `/messages`→`EventSource(stream_url)`→Deltas via **`textContent`** (kein `innerHTML`); `done` finalisiert; Suggestion-Chip = Prefill+Send; New-Chat→POST `/new`+Thread leeren; Enter senden / Shift+Enter Zeilenumbruch / Esc zurück; Autoscroll (`scrollTop=scrollHeight`). In `app.js` registrieren.
4. **CSS-Port** der genannten Klassen aus `docs/design/server-detail.css` → `frontend/src/css/components/server-detail.css`, **token-only** (kein Raw-Hex), manuell.

**DoD:** `ruff`/`mypy app/` grün; Frontend-Build grün; Pure-Unit-Template-Tests (`tests/templates/test_group_chat_render.py`): Empty-State rendert `CHAT_SUGGESTIONS`, Help-Button-Präsenz/`hx-*`-Attribute in der Workflow-Table, **Drift-Test** Initial-Bubble == Stream-Append-Bubble (IDs/Klassen-Set), kein `|safe`. Adversarial: XSS-String in Message-Content wird escaped gerendert (`tests/adversarial/test_group_chat_xss.py`). **Beim User anstehend:** Operator-Browser-Smoke (Help→Sub-View-Swap, Stream-Tippen, New-Chat-Wipe, Esc/Enter).

[+ Gemeinsamer Test-Block]

---

## Prompt 5 — `reviewer` (+ `security-auditor`)

**Lies:** ADR-0055 (vollständig), AE-group-chat.md §11 (DoD-Checkliste), CLAUDE.md §Test-Konvention. Der `reviewer` führt die **Default-Pure-Unit-Suite selbst** aus (mit Timeout), hat kein Schreibrecht.

**Reviewer-Checkliste:**
- Migration `0023` additiv, `down_revision` korrekt, `downgrade` vollständig (Tabellen + Enum).
- 404-Guards greifen (Cross-Server/Cross-Group), CSRF auf allen POST, `flask-limiter` gesetzt.
- Snapshot wird genau einmal bei Create gebaut; Resume baut nicht neu; New-Chat löscht CASCADE.
- Kein `llm_budget`-Aufruf im Chat-Pfad.
- SSE persistiert Assistant nach Stream-Ende; `last_message_at` aktualisiert.
- Single-Source-Bubble-Partial (Initial == Stream-Append), Drift-Test vorhanden und grün.
- Streaming via `textContent` (kein `innerHTML`); kein `|safe`; UI englisch (Sprach-Sweep grün).
- `CHAT_SUGGESTIONS == ["Explain attack vector"]` single-source.

**Security-Auditor** (Pflicht — neue LLM-Eingabefläche + SSE + untrusted Scanner-Daten im Prompt): Prompt-Injection-Marker-Härte, XSS im Stream-/Reason-Pfad, IDOR über Group/Server-IDs, CSRF, Rate-Limit, kein Key-Leak in Logs/SSE-Fehler.

Bei ROT → Feedback an den jeweiligen Implementer, Loop. Bei Grün → `STATE.md` updaten, **kein Commit/Tag ohne explizite User-Anweisung** ([No-Auto-Commit], [Tag-only-on-main-after-Merge]).

[+ Gemeinsamer Test-Block]
