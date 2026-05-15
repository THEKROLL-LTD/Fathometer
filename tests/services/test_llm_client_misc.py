"""Pure-Unit-Tests fuer `app.services.llm_client`-Helpers ohne Netzwerk.

Deckt:
- `validate_base_url`-Whitelist.
- `encrypt_api_key`/`decrypt_api_key`-Roundtrip.
- `build_client_from_settings`-Fehlerpfad bei unkonfigurierten Settings.
"""

from __future__ import annotations

import pytest

from app.models import Setting
from app.services.llm_client import (
    LlmNotConfiguredError,
    build_client_from_settings,
    decrypt_api_key,
    encrypt_api_key,
    validate_base_url,
)

# ---------------------------------------------------------------------------
# validate_base_url
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://api.openai.com/v1",
        "https://api.deepinfra.com/v1/openai",
        "https://example.com",
        "https://example.com/path",
        "http://localhost",
        "http://localhost:11434",
        "http://localhost:11434/v1",
        "http://127.0.0.1",
        "http://127.0.0.1:8080/v1",
    ],
)
def test_validate_base_url_accepts_allowed_forms(url: str) -> None:
    assert validate_base_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://example.com",  # plain http to non-localhost
        "http://evil.com:8080",
        "ftp://example.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://api with spaces.com",
        "x" * 300,  # too long
        "http://localhostevil.com",  # not localhost
        "http://127.0.0.1.evil.com",  # not 127.0.0.1
    ],
)
def test_validate_base_url_rejects_bad_forms(url: str) -> None:
    with pytest.raises(ValueError):
        validate_base_url(url)


def test_validate_base_url_rejects_non_str() -> None:
    with pytest.raises(ValueError):
        validate_base_url(123)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Port-Range (Block H — Block-G-Security-Audit-Action-Item)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:0",
        "http://127.0.0.1:0",
        "https://example.com:0",
        "http://localhost:99999",
        "https://example.com:99999",
        "http://localhost:65536",
        "https://example.com:65536",
    ],
)
def test_validate_base_url_rejects_invalid_ports(url: str) -> None:
    """Port `0` und Port > 65535 muessen als ungueltig abgelehnt werden."""
    with pytest.raises(ValueError):
        validate_base_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:1",
        "https://example.com:65535",
        "https://example.com:443",
        "http://localhost:1",
        "http://localhost:65535",
        "http://127.0.0.1:65535",
    ],
)
def test_validate_base_url_accepts_edge_port_values(url: str) -> None:
    """Ports 1 und 65535 sind die Grenzen — beide muessen akzeptiert werden."""
    assert validate_base_url(url) == url


# ---------------------------------------------------------------------------
# encrypt/decrypt-Roundtrip
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip() -> None:
    secret = "x" * 32
    plain = "sk-some-secret-api-key-value-12345"
    enc = encrypt_api_key(plain, secret)
    assert isinstance(enc, bytes)
    assert plain.encode() not in enc  # not plaintext
    dec = decrypt_api_key(enc, secret)
    assert dec == plain


def test_decrypt_with_wrong_key_raises() -> None:
    enc = encrypt_api_key("hello", "x" * 32)
    with pytest.raises(ValueError):
        decrypt_api_key(enc, "y" * 32)


def test_encrypt_deterministic_kdf_but_nondeterministic_ciphertext() -> None:
    """KDF aus Settings ist deterministisch (gleicher Schluessel zweimal),
    aber Fernet-Ciphertext ist non-deterministisch (Nonce)."""
    secret = "x" * 32
    enc1 = encrypt_api_key("hello", secret)
    enc2 = encrypt_api_key("hello", secret)
    # Ciphertexte unterscheiden sich.
    assert enc1 != enc2
    # Beide entschluesseln zum gleichen Klartext.
    assert decrypt_api_key(enc1, secret) == "hello"
    assert decrypt_api_key(enc2, secret) == "hello"


# ---------------------------------------------------------------------------
# build_client_from_settings — Fehlerpfad
# ---------------------------------------------------------------------------


def test_build_client_from_settings_raises_when_unconfigured() -> None:
    row = Setting(id=1, llm_base_url=None, llm_model=None, llm_daily_token_cap=1000)
    with pytest.raises(LlmNotConfiguredError):
        build_client_from_settings(row, encryption_key="x" * 32)


def test_build_client_from_settings_works_without_api_key() -> None:
    """Ollama-Localhost-Setup: kein api_key noetig."""
    row = Setting(
        id=1,
        llm_base_url="http://localhost:11434/v1",
        llm_model="llama3.1",
        llm_daily_token_cap=1000,
        llm_api_key_encrypted=None,
    )
    client = build_client_from_settings(row, encryption_key="x" * 32)
    assert client.model == "llama3.1"


def test_build_client_from_settings_decrypts_api_key() -> None:
    secret = "x" * 32
    enc = encrypt_api_key("my-key", secret)
    row = Setting(
        id=1,
        llm_base_url="https://api.deepinfra.com/v1/openai",
        llm_model="deepseek-ai/DeepSeek-V3",
        llm_daily_token_cap=1000,
        llm_api_key_encrypted=enc,
    )
    client = build_client_from_settings(row, encryption_key=secret)
    assert client.model == "deepseek-ai/DeepSeek-V3"
