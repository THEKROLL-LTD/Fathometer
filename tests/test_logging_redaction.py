"""Tests fuer den structlog-Redaction-Processor.

Verifiziert, dass sensible Feldnamen (password, key, token, hash) im
Event-Dict ueberschrieben werden, bevor der JSON-Renderer das Event
ausgibt. Siehe ARCHITECTURE.md §10.
"""

from __future__ import annotations

from app.logging_setup import _REDACTED, _redact_sensitive


def _scrub(event: dict[str, object]) -> dict[str, object]:
    """Helper — ruft den Processor mit Dummy-Logger/Method-Name auf."""
    return _redact_sensitive(None, "info", event)  # type: ignore[arg-type]


def test_password_field_is_redacted() -> None:
    result = _scrub({"password": "hunter2"})
    assert result["password"] == _REDACTED, result


def test_api_key_field_is_redacted() -> None:
    result = _scrub({"api_key": "sk-abc123"})
    assert result["api_key"] == _REDACTED, result


def test_token_field_is_redacted() -> None:
    result = _scrub({"token": "ey.AAA.BBB"})
    assert result["token"] == _REDACTED, result


def test_master_key_hash_is_redacted() -> None:
    result = _scrub({"master_key_hash": "$argon2id$..."})
    assert result["master_key_hash"] == _REDACTED, result


def test_authorization_header_is_redacted_case_insensitive() -> None:
    """`Authorization`-Felder werden ab Block H ebenfalls redacted.

    Pattern: `password|key|token|hash|authorization`. Case-insensitive,
    Substring-Match. Verifiziert sowohl `key`-Felder als auch
    `Authorization`-Header.
    """
    # Felder die `key` enthalten matchen case-insensitive.
    result = _scrub({"API_KEY": "abc"})
    assert result["API_KEY"] == _REDACTED, result

    # Authorization wird ab Block H ebenfalls geredacted.
    result_auth = _scrub({"Authorization": "Bearer xyz"})
    assert result_auth["Authorization"] == _REDACTED, result_auth

    # Auch klein geschrieben.
    result_lower = _scrub({"authorization": "Bearer xyz"})
    assert result_lower["authorization"] == _REDACTED, result_lower


def test_nested_dict_redacts_inner_keys() -> None:
    event = {"user": {"api_key": "abc", "email": "u@example.com"}}
    result = _scrub(event)
    inner = result["user"]
    assert isinstance(inner, dict), inner
    assert inner["api_key"] == _REDACTED, inner
    assert inner["email"] == "u@example.com", inner


def test_harmless_fields_remain_unchanged() -> None:
    event = {
        "email": "user@example.com",
        "path": "/api/scans",
        "count": 42,
        "status": "ok",
    }
    result = _scrub(event)
    assert result == event, result


def test_list_of_dicts_is_traversed() -> None:
    event = {"items": [{"token": "t1"}, {"name": "ok"}]}
    result = _scrub(event)
    items = result["items"]
    assert isinstance(items, list), items
    assert items[0]["token"] == _REDACTED, items
    assert items[1]["name"] == "ok", items


# ---------------------------------------------------------------------------
# Block H — Authorization-Header-Redaction (Case-Permutationen)
# ---------------------------------------------------------------------------


def test_authorization_lowercase_redacted() -> None:
    """`authorization` (lowercase) ist redacted."""
    result = _scrub({"authorization": "Bearer xyz123"})
    assert result["authorization"] == _REDACTED


def test_authorization_titlecase_redacted() -> None:
    """`Authorization` (Title-Case) ist redacted."""
    result = _scrub({"Authorization": "Bearer xyz123"})
    assert result["Authorization"] == _REDACTED


def test_authorization_uppercase_redacted() -> None:
    """`AUTHORIZATION` (Uppercase) ist redacted."""
    result = _scrub({"AUTHORIZATION": "Bearer xyz123"})
    assert result["AUTHORIZATION"] == _REDACTED


def test_authorization_substring_in_key_redacted() -> None:
    """Substring-Match: `http_authorization` enthaelt `authorization` -> redact."""
    result = _scrub({"http_authorization": "Bearer xyz123"})
    assert result["http_authorization"] == _REDACTED


def test_bearer_token_value_never_in_rendered_event() -> None:
    """Der eigentliche Bearer-Wert darf nirgendwo im gerenderten Event-Dict
    auftauchen — der Filter ueberschreibt das ganze Feld bevor renderer laeuft.

    Wir simulieren genau das was strukturlogs Pipeline tut: Event-Dict an
    den Redaction-Processor uebergeben, danach JSON-rendern und sicherstellen
    dass das Geheimnis nicht im Output ist.
    """
    import json

    raw = {
        "method": "POST",
        "path": "/api/scans",
        "headers": {"Authorization": "Bearer SUPER_SECRET_TOKEN_123"},
        "authorization": "Bearer SUPER_SECRET_TOKEN_123",
    }
    cleaned = _scrub(raw)
    rendered = json.dumps(cleaned)
    assert "SUPER_SECRET_TOKEN_123" not in rendered, rendered
    assert _REDACTED in rendered, rendered
    # Top-Level authorization-Feld direkt ueberschrieben.
    assert cleaned["authorization"] == _REDACTED
    # Inneres Authorization-Header ebenfalls.
    headers = cleaned["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == _REDACTED
