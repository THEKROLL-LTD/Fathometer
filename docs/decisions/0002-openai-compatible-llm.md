# ADR-0002 — OpenAI-kompatible LLM-Abstraktion

**Status:** Akzeptiert · **Datum:** 2026-05-14

## Kontext

Welches LLM-API verwenden wir und wie binden wir es an? Optionen: provider-spezifisches SDK (DeepInfra direkt), OpenAI-kompatibles Protokoll, oder Multi-Provider-Router (LiteLLM lib).

## Entscheidung

Wir bauen ausschließlich gegen das **OpenAI-kompatible Chat-Completions-Protokoll** über das offizielle `openai`-Python-SDK mit konfigurierbarem `base_url`/`api_key`/`model`. Default-Provider ist DeepInfra mit `deepseek-ai/DeepSeek-V3`. Nur OpenAI-Standard-Features: Chat-Completions mit Streaming. Keine Assistants-API, kein Function-Calling, keine provider-spezifischen Erweiterungen.

## Begründung

Praktisch alle modernen Inference-Provider sprechen das OpenAI-Protokoll als Standard: DeepInfra, OpenAI, Together, Anyscale, Groq, Mistral, Ollama (via Shim), vLLM, LiteLLM-Proxy. Provider-Wechsel ist reine Setting-Änderung, kein Code-Change. Verzicht auf Function-Calling und andere "Standard-Plus"-Features verhindert versehentliche Lock-in zu OpenAI selbst.

## Konsequenzen

- `settings.llm_*`-Block (`base_url`, `api_key_encrypted`, `model`, `daily_token_cap`) genügt für jeden Provider.
- Multi-Provider-Routing (verschiedene Modelle pro Workflow) ist v2-fähig ohne Schemabruch — neue Tabelle `llm_providers` lässt sich nachziehen.
- Wir geben provider-spezifische Optimierungen auf (z.B. DeepInfra Custom Endpoints) — bewusste Akzeptanz.

## Re-Open-Trigger

Wenn ein konkreter Workflow Function-Calling oder Structured-Outputs braucht und das OpenAI-Protokoll dafür kein portierbarer Subset bietet.
