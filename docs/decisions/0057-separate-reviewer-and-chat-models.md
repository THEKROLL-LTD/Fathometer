# ADR-0057 — Getrennte LLM-Modelle für Risk-Reviewer und Per-Group-Chat

**Status:** Akzeptiert · **Datum:** 2026-06-12

Bezug: [ADR-0002](0002-openai-compatible-llm.md) (OpenAI-kompatible Provider-Abstraktion — ein `base_url`/`api_key`, gilt unverändert), [ADR-0010](0010-deepseek-v3-default.md) (DeepSeek als Default-Modell-Linie — diese ADR führt die V4-Flash-Variante als **Chat**-Default ein), [ADR-0023](0023-llm-risk-reviewer-and-application-grouping.md) (Block-P-Risk-Reviewer, Two-Pass — bleibt auf `openai/gpt-oss-120b`), [ADR-0055](0055-per-group-ai-chat.md) (Per-Group-Chat — Modellquelle wechselt von `llm_model` auf `llm_chat_model`), [ADR-0056](0056-budget-cap-db-not-env.md) (Cap aus DB — der Cap betrifft weiterhin nur den Reviewer, der Chat zählt nicht).

## Kontext

Es gibt genau **ein** persistiertes Modell-Feld, `Setting.llm_model` (`String(128)`, default-leer, im UI über den Provider-Tab gesetzt, Preset `openai/gpt-oss-120b`). Beide LLM-Konsumenten lesen dasselbe Feld:

1. **Risk-Reviewer (Block P, Pass 1 + Pass 2)** — `app/workers/llm_worker.py`. Der persistente Async-Client wird über `_get_or_build_async_client` gebaut, Fingerprint-Cache `(base_url, model, sha256(api_key))`. Beide Pässe nutzen dasselbe Modell.
2. **Per-Group-Chat (Block AE)** — `app/api/group_chat.py`. `_run_stream` → `build_client_from_settings(settings_row)` nutzt `setting.llm_model`; beim Anlegen einer Konversation wird `llm_model` als `GroupChatConversation.model` eingefroren (Snapshot).

Die beiden Workloads haben **unterschiedliche Anforderungen**. Der Reviewer braucht ein striktes, schema-treues Urteilsmodell (JSON-Pass-2, ADR-0043-Risk-Band-Logik); der interaktive Chat profitiert von einem schnelleren, dialog-orientierten Modell. Ein gemeinsames Modell zwingt einen Kompromiss auf, der für mindestens einen der beiden Pfade suboptimal ist. Der Operator soll beide Modelle **unabhängig** wählen können.

`base_url` und `api_key` bleiben **geteilt** — es ist *ein* Provider, *zwei* Modelle, kein Multi-Provider-Setup. Beide Modelle müssen vom konfigurierten Provider unter derselben Base-URL gehostet werden.

## Entscheidung

**Zwei explizit benannte Modell-Felder auf der Singleton-`settings`-Row, ein geteilter Provider.**

1. **Schema (Migration `0024`).** `settings.llm_model` wird zu **`llm_reviewer_model`** umbenannt; neu hinzu kommt **`llm_chat_model`** (`String(128)`, NOT NULL nach Backfill). Beide sind druckbares ASCII, max 128 Zeichen.
   - **Backfill (User-Entscheidung 2026-06-12):**
     - `llm_reviewer_model` = alter `llm_model`-Wert (semantik-erhaltend — der Reviewer behält exakt sein bisheriges Modell).
     - `llm_chat_model` = **`deepseek-ai/DeepSeek-V4-Flash`** für **alle** Zeilen (forced default), unabhängig vom alten `llm_model`.
   - `downgrade()` benennt `llm_reviewer_model` zurück nach `llm_model` und droppt `llm_chat_model` (Daten-Verlust des Chat-Modells ist beim Downgrade akzeptiert — vorher gab es das Feld nicht).

2. **Defaults / Presets.**
   - Reviewer-Default: `openai/gpt-oss-120b` (unverändert, ADR-0023 §"Update v0.9.3").
   - Chat-Default: `deepseek-ai/DeepSeek-V4-Flash`.
   - Beide sind in `app/views/llm_settings.py` als benannte Konstanten hinterlegt; der Provider-Tab füllt beide Felder beim Preset-Pick vor. Operator kann **beide frei überschreiben**.

3. **Konsumenten-Verdrahtung.**
   - Reviewer-Pfad (`llm_worker.py`, Fingerprint-Cache) liest `llm_reviewer_model`.
   - Chat-Pfad (`group_chat.py`) liest `llm_chat_model`; `GroupChatConversation.model` snapshottet `llm_chat_model`.
   - `build_client_from_settings(setting, *, encryption_key, model_override=None)` bekommt einen optionalen `model_override`; der Chat-Pfad übergibt `llm_chat_model`. Ohne Override bleibt das Verhalten auf das Reviewer-Modell bezogen (rückwärtskompatibel für interne Aufrufer).

4. **Test-Connection probt beide Modelle (User-Entscheidung 2026-06-12).** `POST /settings/llm/test-connection` führt **zwei** 1-Token-Proben aus (Reviewer-Modell + Chat-Modell, geteilter `base_url`/`api_key`) und liefert ein Ergebnis pro Modell. Damit fällt sofort auf, wenn der Provider nur eines der beiden Modelle hostet.

5. **Audit.** `llm.provider_changed` feuert künftig, wenn `base_url`, `llm_reviewer_model` **oder** `llm_chat_model` sich ändert; Metadata trägt alte/neue Werte für beide Modelle.

6. **Budget.** Unverändert (ADR-0056): nur der Reviewer zählt gegen `llm_daily_token_cap`; der Chat ruft `llm_budget` nicht (ADR-0055 §4). Die Modell-Trennung ändert daran nichts.

## Begründung

- **Workload-Fit:** Striktes Urteilsmodell für den Reviewer, dialog-schnelles Modell für den Chat — ohne den jeweils anderen Pfad zu kompromittieren.
- **Explizite Benennung statt Doppeldeutigkeit:** `llm_model` für „das Reviewer-Modell" wäre nach der Trennung irreführend. `llm_reviewer_model` / `llm_chat_model` machen die Bedeutung am Feld selbst klar — wichtig für ein langlebiges Single-Row-Settings-Schema. Der größere Rename-Diff (Worker-Fingerprint, `build_client_from_settings`, Test-Conn, Chat-Snapshot, `settings.py::active_model`, Tests) ist der bewusst gewählte Preis (User-Entscheidung).
- **Ein Provider, zwei Modelle:** Hält die ADR-0002-Abstraktion (eine Base-URL, ein Key) intakt — kein Multi-Provider-Apparat, keine zweite Verschlüsselungs-Pipeline.
- **Forced Chat-Default:** Der Operator-Wunsch ist ein dedizierter Chat-Default `DeepSeek-V4-Flash`. Der Backfill setzt ihn für alle Installs (statt das alte Reviewer-Modell zu übernehmen) — siehe Konsequenz unten zum 404-Risiko.

## Konsequenzen

- **404-Risiko bei bestehenden Installs:** Da `llm_chat_model` per Backfill auf `deepseek-ai/DeepSeek-V4-Flash` gesetzt wird, der Chat aber denselben Provider/`base_url` wie der Reviewer nutzt, schlägt der Chat mit Provider-`404` fehl, wenn der konfigurierte Provider dieses Modell **nicht** hostet. Der Operator muss nach dem Upgrade im Provider-Tab das Chat-Modell prüfen/anpassen. Die **Test-Connection-Doppelprobe** (Entscheidung 4) macht genau diesen Fall sofort sichtbar. Dieses Risiko wurde bewusst akzeptiert (Alternative „Backfill aus altem `llm_model`" wurde verworfen).
- **Rename berührt mehrere Module:** `models.py`, Migration `0024`, `forms.py` (zweites Feld), `llm_settings.py` (View + Presets + Audit), `llm_provider.html` + `llm_settings.js` (zweites Eingabefeld + Preset-Wiring), `llm_client.build_client_from_settings` (Override-Param), `group_chat.py` (Chat-Modell + Snapshot), `llm_worker.py` (Feldname), `settings.py::active_model` (Reviewer-Screen). Bestehende Tests, die `llm_model` referenzieren, werden mitgezogen.
- **Laufende Chat-Konversationen** bleiben an ihr gesnapshottetes Modell gebunden (`GroupChatConversation.model`) — eine Modell-Umstellung im Provider-Tab ändert eine offene Konversation nicht (ADR-0055-Prinzip, unverändert). Erst „New Chat" zieht das neue Chat-Modell.
- **Worker-Reload:** Der Fingerprint-Cache schließt das (umbenannte) Reviewer-Modell ein — eine Reviewer-Modell-Änderung rebuildet den Client binnen ≤ 60 s wie bisher, kein Pod-Restart nötig.

## Re-Open-Trigger

- **Getrennte Provider** (eigene `base_url`/`api_key` pro Workload) sind weiterhin out-of-scope. Falls Chat und Reviewer auf physisch verschiedenen Endpoints laufen sollen, braucht es eine neue ADR (zweiter verschlüsselter Key, zweite Base-URL-Whitelist, doppelte Client-Lifecycle-Verwaltung).
- **Pro-Konversation-Modellwahl** im Chat (Operator wählt Modell pro Chat statt global) ist bewusst nicht Teil dieser ADR (ADR-0055 §"keine Modellwahl pro Konversation" bleibt) — Re-Open bei Bedarf.
- **Per-Pass-Modelle** (Pass 1 ≠ Pass 2) bleiben verworfen: beide Reviewer-Pässe teilen `llm_reviewer_model`.
