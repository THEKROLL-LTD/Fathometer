# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""LLM-Client-Wrapper um das `openai`-Python-SDK.

Siehe ARCHITECTURE.md §12 (Provider-Abstraktion) und §10 (Whitelist auf
`llm_base_url`). Der Client wird **per Request** instanziiert — wir halten
keinen globalen Singleton, damit Tests den Client deterministisch
ersetzen koennen und damit ein Provider-Wechsel zur Laufzeit ohne
State-Reset wirkt.

Verantwortlichkeiten:

1. URL-Whitelist-Check (`validate_base_url`): HTTPS oder
   `http://localhost`/`http://127.0.0.1` (port optional). Andere Schemes/
   Hosts -> `ValueError`.
2. Decryption des `Setting.llm_api_key_encrypted`-Werts mit Fernet aus
   `FM_ENCRYPTION_KEY`. Klartext-Key bleibt strikt im Memory der
   Funktion — niemals geloggt.
3. Stream-API (`stream_chat`) als `AsyncIterator[str]` von Token-Deltas
   plus finalem `usage`-Counter.
4. `test_connection()` macht eine 1-Token-Probe-Anfrage und gibt
   Latenz + Modell + Erfolg zurueck.

Sicherheits-Konvention: der API-Key wird *nie* als Argument durch das
strukturierte Logging gereicht. structlog-Redaction-Filter greift auf
Keys mit dem Substring `key` — wir verlassen uns darauf, aber loggen
ihn ohnehin nie aktiv.
"""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, cast

import structlog
from cryptography.fernet import Fernet, InvalidToken
from openai import AsyncOpenAI

from app.models import Setting

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# URL-Whitelist
# ---------------------------------------------------------------------------


_HTTPS_RE = re.compile(r"^https://([^/\s:]+)(?::(\d{1,5}))?(/[^\s]*)?$")
# `http://localhost(:port)?(/path)?` ODER `http://127.0.0.1(:port)?(/path)?`.
_LOCAL_HTTP_RE = re.compile(r"^http://(?:localhost|127\.0\.0\.1)(?::(\d{1,5}))?(?:/[^\s]*)?$")
_BASE_URL_MAX = 256
_PORT_MIN = 1
_PORT_MAX = 65535


def _check_port_range(port_str: str | None) -> None:
    """Validiert dass ein Port-String im Range 1..65535 liegt.

    `port_str` ist der Wert aus der Regex-Capture-Group (ohne `:`). Bei
    `None` (kein Port in der URL) ist nichts zu pruefen — Default-Ports
    sind erlaubt.
    """
    if port_str is None or port_str == "":
        return
    try:
        port = int(port_str)
    except ValueError as exc:  # pragma: no cover — Regex erlaubt nur Digits
        raise ValueError(f"llm_base_url has invalid port: {port_str!r}") from exc
    if not (_PORT_MIN <= port <= _PORT_MAX):
        raise ValueError(f"llm_base_url port {port} out of range ({_PORT_MIN}..{_PORT_MAX})")


def validate_base_url(base_url: str) -> str:
    """Strikte Whitelist fuer `llm_base_url`.

    Erlaubt:
    - `https://*` (jeder Host, der TLS spricht).
    - `http://localhost(:port)?` und `http://127.0.0.1(:port)?` fuer
      lokale Ollama/vLLM-Setups.

    Port (wenn vorhanden) muss im Range 1..65535 liegen — siehe Block-H-
    Action-Item aus dem Block-G-Security-Audit.

    Wirft `ValueError` bei jeder anderen Form (`http://example.com`,
    `ftp://`, leere Strings, ueberlange Werte, Whitespace, `:0`,
    `:99999`).
    """
    if not isinstance(base_url, str):
        raise ValueError("llm_base_url must be a string")
    if not base_url or len(base_url) > _BASE_URL_MAX:
        raise ValueError("llm_base_url has invalid length")
    m_https = _HTTPS_RE.fullmatch(base_url)
    if m_https:
        _check_port_range(m_https.group(2))
        return base_url
    m_local = _LOCAL_HTTP_RE.fullmatch(base_url)
    if m_local:
        _check_port_range(m_local.group(1))
        return base_url
    raise ValueError("llm_base_url must use https:// or http://localhost / http://127.0.0.1")


# ---------------------------------------------------------------------------
# Fernet-Decrypt
# ---------------------------------------------------------------------------


def _fernet_from_settings_value(secret_value: str) -> Fernet:
    """Baut ein Fernet-Objekt aus `FM_ENCRYPTION_KEY`.

    Der Settings-Validator erzwingt min. 32 Zeichen. Fernet erwartet aber
    *exakt* 32 URL-safe Base64-Bytes — wir leiten deterministisch ueber
    `urlsafe_b64encode(sha256(raw)[:32])` ab. So ist jede 32+-Eingabe
    valider Fernet-Key. Begruendung: fathometer akzeptiert generierte
    Passphrases, nicht zwingend echte Fernet-Keys.
    """
    import base64
    import hashlib

    raw = secret_value.encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_api_key(plain: str, encryption_key: str) -> bytes:
    """Verschluesselt einen API-Key fuer die Persistenz in `llm_api_key_encrypted`."""
    f = _fernet_from_settings_value(encryption_key)
    return f.encrypt(plain.encode("utf-8"))


def decrypt_api_key(encrypted: bytes, encryption_key: str) -> str:
    """Entschluesselt einen `llm_api_key_encrypted`-Wert.

    Wirft `ValueError` bei korruptem/fremdem Ciphertext.
    """
    f = _fernet_from_settings_value(encryption_key)
    try:
        return f.decrypt(bytes(encrypted)).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("llm_api_key_encrypted is not decryptable") from exc


# ---------------------------------------------------------------------------
# Streaming-Wrapper
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StreamUsage:
    """Token-Counts am Ende eines Streams. Werte koennen `None` sein."""

    prompt_tokens: int | None
    completion_tokens: int | None


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    """Ergebnis einer `test_connection()`-Probe."""

    success: bool
    latency_ms: int
    model: str | None
    error: str | None


class LlmClient:
    """Duenner Wrapper um `AsyncOpenAI`.

    Wird typisch per Aufruf ueber `build_client_from_settings(...)` erzeugt.
    """

    def __init__(self, *, base_url: str, api_key: str, model: str, timeout: float = 240.0):
        validated = validate_base_url(base_url)
        self._model = model
        self._timeout = timeout
        # `openai` SDK akzeptiert leere API-Keys nicht; lokale Ollama-Setups
        # nehmen aber jeden Dummy-String. Wir setzen auf "ollama" wenn leer.
        effective_key = api_key or "ollama"
        # v0.9.x: SDK-interne Retries ausschalten. Wir haben unseren eigenen
        # Worker-Retry-Mechanismus (`_requeue_or_fail` mit MAX_ATTEMPTS=3 und
        # exponential Backoff in `llm_jobs.next_attempt_at`). Doppelte Retries
        # blockieren den Worker bei DeepInfra-Stoerungen 4-6 Minuten pro
        # Versuch — beobachtet 2026-05-20: Pass-1-Job 1 mit 6m13s SDK-Retry-
        # Schleife → Job-Latency vervielfacht, Visibility-Luecke (Debug-Log
        # bleibt leer waehrend SDK still retried). Mit max_retries=0 fliegt
        # ein DeepInfra-Fehler sofort hoch, Worker entscheidet via
        # `_requeue_or_fail` ob requeue-mit-Backoff oder Final-Fail.
        self._sdk: AsyncOpenAI = AsyncOpenAI(
            base_url=validated,
            api_key=effective_key,
            timeout=timeout,
            max_retries=0,
        )
        # Capture letzte Usage damit der Caller sie nach dem Stream lesen kann.
        self._last_usage: StreamUsage = StreamUsage(prompt_tokens=None, completion_tokens=None)

    @property
    def model(self) -> str:
        return self._model

    @property
    def last_usage(self) -> StreamUsage:
        return self._last_usage

    async def stream_chat(
        self,
        messages: Sequence[dict[str, str]],
        *,
        max_tokens: int | None = None,
    ) -> AsyncIterator[str]:
        """Streamt Token-Deltas vom Provider.

        Der `usage`-Block wird (falls vom Provider geliefert) im finalen
        Chunk gefuehrt und in `self._last_usage` abgelegt.
        """
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": list(messages),
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens

        # AsyncOpenAI's `chat.completions.create(..., stream=True)` returns
        # an AsyncStream object. Each yielded chunk hat `choices[0].delta`
        # und am Ende einen Chunk mit `usage` (falls `include_usage`).
        stream = await self._sdk.chat.completions.create(**kwargs)
        try:
            async for chunk in stream:
                choices = getattr(chunk, "choices", None)
                if choices:
                    delta = getattr(choices[0], "delta", None)
                    content = getattr(delta, "content", None) if delta is not None else None
                    if content:
                        yield cast(str, content)
                usage = getattr(chunk, "usage", None)
                if usage is not None:
                    self._last_usage = StreamUsage(
                        prompt_tokens=getattr(usage, "prompt_tokens", None),
                        completion_tokens=getattr(usage, "completion_tokens", None),
                    )
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                try:
                    await close()
                except Exception:  # pragma: no cover — best effort
                    log.debug("llm_client.stream_close_failed")

    async def test_connection(self) -> ConnectionTestResult:
        """Schickt eine 1-Token-Probe-Anfrage und misst Round-Trip-Latenz."""
        start = time.monotonic()
        try:
            response = await self._sdk.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": "Hi"}],
                stream=False,
                max_tokens=1,
            )
            latency_ms = int((time.monotonic() - start) * 1000)
            model_used = getattr(response, "model", None) or self._model
            return ConnectionTestResult(
                success=True,
                latency_ms=latency_ms,
                model=model_used,
                error=None,
            )
        except Exception as exc:
            latency_ms = int((time.monotonic() - start) * 1000)
            # Bewusst nur Exception-Class und kurze Message — niemals
            # potentiell sensible Header/Body-Werte aus dem SDK leaken.
            err = f"{type(exc).__name__}: {str(exc)[:200]}"
            log.warning("llm_client.test_connection_failed", error=err)
            return ConnectionTestResult(success=False, latency_ms=latency_ms, model=None, error=err)

    async def aclose(self) -> None:
        """Schliesst den unterliegenden httpx-Pool."""
        try:
            await self._sdk.close()
        except Exception:  # pragma: no cover
            log.debug("llm_client.aclose_failed")


# ---------------------------------------------------------------------------
# Factory aus Settings-Row
# ---------------------------------------------------------------------------


class LlmNotConfiguredError(RuntimeError):
    """Wird geworfen wenn der LLM-Provider noch nicht in Settings konfiguriert ist."""


def build_client_from_settings(
    setting: Setting, *, encryption_key: str, timeout: float = 240.0
) -> LlmClient:
    """Baut einen `LlmClient` aus der `Setting`-Zeile.

    Wirft `LlmNotConfiguredError` wenn `llm_base_url` oder `llm_model`
    fehlen. API-Key darf leer sein (Ollama-Localhost), wird dann beim
    Decrypt auf "ollama" gemappt.
    """
    if not setting.llm_base_url or not setting.llm_model:
        raise LlmNotConfiguredError("LLM-Provider noch nicht konfiguriert")
    plain_key = ""
    if setting.llm_api_key_encrypted:
        plain_key = decrypt_api_key(setting.llm_api_key_encrypted, encryption_key)
    return LlmClient(
        base_url=setting.llm_base_url,
        api_key=plain_key,
        model=setting.llm_model,
        timeout=timeout,
    )


__all__ = [
    "ConnectionTestResult",
    "LlmClient",
    "LlmNotConfiguredError",
    "StreamUsage",
    "build_client_from_settings",
    "decrypt_api_key",
    "encrypt_api_key",
    "validate_base_url",
]
