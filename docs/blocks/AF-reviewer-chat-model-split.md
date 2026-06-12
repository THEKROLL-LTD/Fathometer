# Block AF — Getrennte Modelle für Risk-Reviewer und Per-Group-Chat

> **Status:** geplant (noch nicht gestartet).
>
> **Branch (Vorschlag):** `feat/block-af-reviewer-chat-model-split`
> **Ziel-ADR:** [ADR-0057](../decisions/0057-separate-reviewer-and-chat-models.md).
> **Zielversion (Vorschlag):** v0.21.0.

## 0. Kontext & Abgrenzung

Heute liest **ein** Feld `Setting.llm_model` von **beiden** LLM-Konsumenten — dem Risk-Reviewer (Block P, Pass 1 + Pass 2, `app/workers/llm_worker.py`) und dem Per-Group-Chat (Block AE, `app/api/group_chat.py`). Block AF trennt das in zwei Felder: **`llm_reviewer_model`** (umbenannt aus `llm_model`) und **`llm_chat_model`** (neu). **Ein** Provider bleibt geteilt (`llm_base_url` / `llm_api_key_encrypted` / `llm_provider_name`) — *ein Provider, zwei Modelle*, kein Multi-Provider.

Bestätigte User-Entscheidungen (2026-06-12):

1. **Schema:** explizit umbenennen — `llm_reviewer_model` + neu `llm_chat_model` (nicht additiv `llm_model` behalten).
2. **Backfill:** `llm_chat_model` = `deepseek-ai/DeepSeek-V4-Flash` **forced für alle** Zeilen; `llm_reviewer_model` = alter `llm_model`.
3. **Test-Connection** probt **beide** Modelle einzeln.

| | Reviewer | Chat |
|---|---|---|
| Feld | `llm_reviewer_model` | `llm_chat_model` |
| Default | `openai/gpt-oss-120b` (unverändert) | `deepseek-ai/DeepSeek-V4-Flash` (neu) |
| Konsument | `llm_worker.py` (Pass 1 + Pass 2) | `group_chat.py` (SSE-Stream + Snapshot) |
| Budget | zählt gegen `llm_daily_token_cap` (ADR-0056) | kein Cap (ADR-0055 §4) |
| Provider | **geteilt** (`llm_base_url` / `llm_api_key_encrypted`) | **geteilt** |

**Pass 1 und Pass 2 teilen** weiterhin **ein** Reviewer-Modell — keine Per-Pass-Modelle.

## 1. Datenmodell (Migration `alembic/versions/0024_reviewer_chat_model_split.py`)

`down_revision = "0023_block_ae_group_chat"` (aktueller Head). Reine `settings`-Spalten-Operation, keine neue Tabelle, kein Enum.

**User-Entscheidung 2026-06-12 (final):** `llm_chat_model` ist **`NOT NULL` mit DB-`server_default`** `'deepseek-ai/DeepSeek-V4-Flash'` — konsistent mit ADR-0057 §Entscheidung 1. Der `server_default` (a) backfillt bestehende Zeilen beim `ADD COLUMN NOT NULL DEFAULT` automatisch und (b) sorgt dafür, dass frische Installs / `ensure_settings_row`-Inserts (die kein Modell seeden) das NOT-NULL-Constraint nicht verletzen. Der `server_default` bleibt **permanent** auf der Spalte (nicht im selben Migrationsschritt wieder gedroppt). `llm_reviewer_model` behält die alte `NULL`-Semantik des ehemaligen `llm_model` (ein System ohne Provider hat hier `NULL`).

```
ALTER TABLE settings RENAME COLUMN llm_model TO llm_reviewer_model;
ALTER TABLE settings ADD COLUMN llm_chat_model VARCHAR(128) NOT NULL
  DEFAULT 'deepseek-ai/DeepSeek-V4-Flash';   -- backfillt bestehende Zeilen + schützt frische Inserts
```

`downgrade()`:

```
ALTER TABLE settings DROP COLUMN llm_chat_model;
ALTER TABLE settings RENAME COLUMN llm_reviewer_model TO llm_model;
```

ORM (`app/models.py`, `class Setting`): `llm_model` → `llm_reviewer_model: Mapped[str | None] = mapped_column(String(128))` (nullable, unverändert); neu `llm_chat_model: Mapped[str] = mapped_column(String(128), nullable=False, server_default="deepseek-ai/DeepSeek-V4-Flash")`. Kommentar-Block am Feld aktualisieren (Reviewer- vs. Chat-Semantik).

**Hinweis „nicht konfiguriert":** Da `llm_chat_model` durch `server_default` nie `NULL` ist, gilt der Chat-Pfad als „nicht konfiguriert" allein wenn `llm_base_url` leer ist (nicht am Modell-Feld). `ensure_settings_row` muss **nicht** angefasst werden (es seedet kein Modell; den Chat-Default liefert der `server_default`).

**Alembic-Roundtrip `0024` läuft beim User** (db_integration, nicht proaktiv).

## 2. Touchpoints (alle Konsumenten)

| Datei | Änderung |
|---|---|
| `app/models.py` | `Setting`: Rename + neue Spalte (s. §1). |
| `alembic/versions/0024_reviewer_chat_model_split.py` | Rename + Add (`NOT NULL` + `server_default`) + Downgrade (s. §1). |
| `app/forms.py` | `LlmSettingsForm`: Feld `model` → `reviewer_model` (Label „Reviewer model"), neu `chat_model` (Label „Chat model", `DataRequired`, `Length(max=128)`). |
| `app/views/llm_settings.py` | Default-Konstanten `DEFAULT_REVIEWER_MODEL="openai/gpt-oss-120b"` / `DEFAULT_CHAT_MODEL="deepseek-ai/DeepSeek-V4-Flash"`; `LLM_PRESETS`-Einträge tragen beide Modelle; `show()`/`update()` lesen/schreiben beide Felder; Provider-Changed-Audit + `changed_fields` um beide Modelle erweitern; `test_connection()` probt beide (s. §3). |
| `app/templates/settings/llm_provider.html` | Zweites Modell-Eingabefeld; Alpine-State `reviewerModel`/`chatModel`; Preset-Apply füllt beide; Test-Result rendert beide Modell-Zeilen. |
| `app/static/js/llm_settings.js` | Alpine-Component: `reviewerModel`/`chatModel`-State, Preset-Handler setzt beide, Test-Result-Struktur (zwei Modelle). |
| `app/services/llm_client.py` | `build_client_from_settings(setting, *, encryption_key, timeout=240.0, model_override: str \| None = None)` — `model = model_override or setting.llm_reviewer_model`; `LlmNotConfiguredError`-Check auf das effektiv genutzte Modell. |
| `app/api/group_chat.py` | `_run_stream` ruft `build_client_from_settings(..., model_override=settings_row.llm_chat_model)`; Konversations-Snapshot `model=settings_row.llm_chat_model`; `_llm_configured`/`stream`-Guards prüfen `llm_chat_model` (statt `llm_model`). |
| `app/workers/llm_worker.py` | Alle `settings_row.llm_model`-Lesungen → `llm_reviewer_model` (`_get_or_build_async_client`, `_build_reviewer`, Fingerprint). Keine Logik-Änderung, nur Feldname. |
| `app/views/settings.py` | `active_model` (Reviewer-Screen, Z. ~652) → `setting_row.llm_reviewer_model`. |
| `app/services/llm_cache.py` | `llm_model`-Parameter/Feld prüfen — bezieht sich auf das **Reviewer**-Eval (Cache-Eintrag des Two-Pass-Reviewers). Auf `llm_reviewer_model` umstellen, falls es aus `Setting` gespeist wird; das `LLMCacheEntry.model`/`ApplicationGroupEvaluation`-Snapshot-Feld selbst **nicht** umbenennen (eigene Spalte, keine Settings-Referenz). |

**grep-Pflicht vor „fertig":** `grep -rn "llm_model" app/ --include=*.py` darf danach **nur** noch Treffer liefern, die sich auf **andere** Tabellen-Spalten beziehen (`GroupChatConversation.model`, `LLMCacheEntry.model`/`application_group_evaluations`-Snapshot, `LLMDebugLog`) — **kein** Treffer mehr auf `Setting.llm_model`.

## 3. Test-Connection — beide Modelle

`POST /settings/llm/test-connection` (`llm_settings.py::test_connection`) führt **zwei** Proben gegen den geteilten `base_url`/`api_key` aus:

- Reviewer-Probe: `build_client_from_settings(setting, encryption_key=…)` (Default = `llm_reviewer_model`).
- Chat-Probe: `build_client_from_settings(setting, encryption_key=…, model_override=setting.llm_chat_model)`.

Response-Shape (**User-Entscheidung 2026-06-12 final: neues 2-Teil-Objekt**, kein Single-Result-Rückbau):

```json
{ "reviewer": {"success": true, "latency_ms": 412, "model": "openai/gpt-oss-120b", "error": null},
  "chat":     {"success": false, "latency_ms": null, "model": "deepseek-ai/DeepSeek-V4-Flash", "error": "model_not_found"} }
```

`400 llm_not_configured` nur, wenn `base_url` fehlt (der gemeinsame Gate). `llm_chat_model` ist durch `server_default` nie leer; ist `llm_reviewer_model` `NULL`, wird das **Reviewer-Teilergebnis** als „nicht konfiguriert" markiert (`success:false`, `error:"not_configured"`) statt 400. `validate_base_url` einmalig (geteilt). Rate-Limit `60/hour` bleibt (zwei Proben = ein Request). Das bestehende `app/static/js/llm_settings.js` (handgeschrieben, **nicht** Teil der esbuild-`frontend/src/js/`-Pipeline) muss die neue Shape rendern (zwei Zeilen statt einem `testResult`).

## 4. Frontend — Provider-Tab

- Zwei `s-field`-Blöcke „Reviewer model" / „Chat model" (mono-Input, `x-model="reviewerModel"` / `x-model="chatModel"`), beide unter dem geteilten Base-URL/API-Key-Block.
- Preset-Dropdown setzt **beide** Modelle (`base_url` + `reviewer_model` + `chat_model`); Hint anpassen („Sets base URL and both models …").
- Test-Result-Panel zeigt **zwei** Zeilen (Reviewer / Chat) mit je `success`/`latency`/`model`/`error`.
- CSS: bestehende `s-*`-Klassen wiederverwenden (Block AD), **keine** neuen Komponentenklassen nötig. UI-Strings **englisch** (ADR-0045) — Sprach-Sweep (`tests/test_ui_language.py`) muss grün bleiben.

## 5. Tests (CLAUDE.md-konform: nur Pure-Unit proaktiv)

- **Form** (`LlmSettingsForm`): `reviewer_model`/`chat_model` required + Length-Cap; leeres Chat-Modell → Validation-Error.
- **View `update()`**: beide Felder werden persistiert; `llm.provider_changed` feuert bei Reviewer- **oder** Chat-Modell-Änderung; `changed_fields` enthält beide; No-Op (kein Modell geändert) feuert **kein** provider_changed.
- **`build_client_from_settings`**: ohne Override → `llm_reviewer_model`; mit `model_override` → übergebenes Modell; `LlmNotConfiguredError` bei fehlendem effektivem Modell.
- **`group_chat`**: `_run_stream` baut Client mit `llm_chat_model`; Konversations-Snapshot persistiert `llm_chat_model`; `stream`/`messages`-Guard nutzt `llm_chat_model` (mock-Session).
- **`llm_worker`**: Reviewer-Pfad + Fingerprint lesen `llm_reviewer_model` (mock-Session, kein echter Client).
- **`test_connection`** (mock-Client/`asyncio.run`-Hook): zwei Teilergebnisse, je Modell; `400` wenn base_url fehlt; Teil-„nicht konfiguriert" bei einem leeren Modell.
- **Sprach-Sweep**: neue Strings englisch.
- **grep-Regression** (optional als Test oder manuell): kein `Setting.llm_model`-Treffer mehr.

**Beim User anstehend (db_integration / E2E / Browser, nicht proaktiv):** Alembic-Roundtrip `0024` (Rename + Add + Backfill + Downgrade-Roundtrip), Migration-Backfill-Semantik gegen echte DB, Test-Connection-Doppelprobe gegen Live-Provider, Operator-Browser-Smoke (Provider-Tab zeigt zwei Modell-Felder, Preset füllt beide, Test-Result zwei Zeilen, Chat nutzt Chat-Modell, Reviewer-Job nutzt Reviewer-Modell).

## 6. Out of Scope (neue ADR nötig)

- **Getrennte Provider** (eigene `base_url`/`api_key` pro Workload) — ADR-0057 §Re-Open.
- **Pro-Konversation-Modellwahl** im Chat — ADR-0055-Prinzip bleibt.
- **Per-Pass-Modelle** (Pass 1 ≠ Pass 2) — verworfen.
- **Zweite Verschlüsselungs-Pipeline / zweiter API-Key** — ein geteilter Key.

## 7. Definition of Done (maschinell prüfbar wo möglich)

1. `ruff check . && ruff format --check .` grün.
2. `mypy app/` grün.
3. Default-`pytest` (Pure-Unit) grün, inkl. der neuen §5-Tests; keine Regression in der bestehenden Suite.
4. `grep -rn "llm_model" app/ --include=*.py` liefert **keinen** Treffer auf `Setting.llm_model` mehr (nur Fremd-Spalten `GroupChatConversation.model`/`LLMCacheEntry`/`LLMDebugLog`).
5. `grep -rn "llm_reviewer_model\|llm_chat_model" app/` zeigt beide Felder konsistent in Model + View + Form + Worker + Chat + `llm_client`.
6. Sprach-Sweep `tests/test_ui_language.py` grün (neue UI-Strings englisch).
7. Frontend-Build (esbuild + lightningcss) grün (läuft beim nächsten Docker-Build; lokal nicht proaktiv).
8. Doku synchron: ARCHITECTURE.md (§7 Provider-Block + §12 geteilte Config → „zwei Modelle, ein Provider"; §11/§13 Budget-Hinweis unverändert), CHANGELOG (v0.21.0), `decisions/README.md`-Index (0057), `STATE.md`.
9. **Beim User anstehend** korrekt markiert (Alembic-Roundtrip `0024`, Live-Test-Connection, Browser-Smoke) — **nicht** proaktiv ausgeführt.

## 8. Offene Punkte vor Start

1. ~~**Block-Letter/Branch-Naming**~~ → **geklärt:** `AF` / `feat/block-af-reviewer-chat-model-split` (in STATE.md bestätigt).
2. ~~**Test-Connection-Response-Shape**~~ → **geklärt (2026-06-12):** neues 2-Teil-Objekt `{reviewer, chat}` (§3), kein Single-Result-Rückbau.
3. ~~**`llm_chat_model` NULL-barkeit**~~ → **geklärt (2026-06-12):** `NOT NULL` + permanenter `server_default` `'deepseek-ai/DeepSeek-V4-Flash'` (§1), konsistent mit ADR-0057.
4. **`DeepSeek-V4-Flash`-Modell-String** exakt so beim Ziel-Provider (DeepInfra) verifizieren — Backfill/`server_default` schreiben den Literal-String; ein Tippfehler ergibt Provider-404 (die Test-Connection-Doppelprobe deckt es auf). **Nicht proaktiv prüfbar — beim User anstehend.**
