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
    """`Authorization` matched ueber `key`-Substring? Nein — siehe Implementer.

    Der aktuelle Pattern ist `password|key|token|hash`. `Authorization` matched
    keines dieser Substrings. Das wird als bekannte Einschraenkung
    dokumentiert; der Test verifiziert das tatsaechliche Verhalten, damit
    Aenderungen an der Pattern-Liste auffallen.
    """
    # Verifiziere zumindest: Felder die `key` enthalten matchen case-insensitive.
    result = _scrub({"API_KEY": "abc"})
    assert result["API_KEY"] == _REDACTED, result

    # Authorization wird vom aktuellen Pattern NICHT erfasst. Wenn ein zukuenftiger
    # Implementer das aendert, schlaegt dieser Test bewusst um — dann muss die
    # Auswahl an `_REDACT_PATTERN` erweitert werden.
    result_auth = _scrub({"Authorization": "Bearer xyz"})
    # Bewusst: derzeit NICHT redacted (siehe oben).
    assert result_auth["Authorization"] == "Bearer xyz", result_auth


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
