"""Pure-Unit-Tests fuer `server_settings.tag_create` (Block Z, Phase A, ADR-0040).

Inline-Anlage eines Tags direkt im Server-Settings-Kontext, atomar mit dem
ServerTag-Link. Race-sicher via IntegrityError-Catch + Re-Fetch der existing Row.
Link wird idempotent angehaengt (existing-Link via SELECT geprueft).

Render-Strategie analog `test_server_settings.py`:
  - Handler via `func.__wrapped__` (umgeht @login_required).
  - `_load_server_with_settings`, `get_session`, `log_event`, `flash` gestubbt.
  - `Tag`/`ServerTag`-Symbole werden NICHT ersetzt (der Handler nutzt sie in
    `select(...)`-Queries). Ein `sess.flush`-Side-Effect vergibt die PK auf dem
    zuletzt via `sess.add` hinzugefuegten Objekt (wie ein echter Postgres-Flush).

Alle Tests sind reine Pure-Unit-Tests (kein db_integration-Marker).
"""

from __future__ import annotations

import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from sqlalchemy.exc import IntegrityError

# ---------------------------------------------------------------------------
# Helpers — Mock-Objekte
# ---------------------------------------------------------------------------


def _make_server(
    *,
    id: int = 42,
    revoked_at: Any = None,
    retired_at: Any = None,
) -> types.SimpleNamespace:
    return types.SimpleNamespace(id=id, revoked_at=revoked_at, retired_at=retired_at)


def _make_tag(*, id: int = 5, name: str = "prod", color: str = "#6b7280") -> types.SimpleNamespace:
    return types.SimpleNamespace(id=id, name=name, color=color)


def _capture_adds(sess: MagicMock, *, tag_id: int | None = None) -> list[Any]:
    """Konfiguriert `sess.add`/`sess.flush`: add zeichnet auf, flush vergibt PK.

    Wenn `tag_id` gesetzt ist, bekommt das zuletzt hinzugefuegte Objekt beim
    flush diese `id` (simuliert Autoincrement). ServerTag-Links haben keine
    Autoincrement-PK die der Handler braucht; sie werden nur aufgezeichnet.
    Gibt die capture-Liste zurueck.
    """
    captured: list[Any] = []

    def fake_add(obj: Any) -> None:
        captured.append(obj)

    def fake_flush() -> None:
        if tag_id is not None and captured:
            captured[-1].id = tag_id

    sess.add.side_effect = fake_add
    sess.flush.side_effect = fake_flush
    return captured


# ---------------------------------------------------------------------------
# Fixture: App mit CSRF disabled
# ---------------------------------------------------------------------------


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


# ---------------------------------------------------------------------------
# Render-Helper
# ---------------------------------------------------------------------------


def _call_tag_create(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    server: Any,
    name: str,
    mock_sess: MagicMock,
    log_event_calls: list[dict] | None = None,
    flashes: list[tuple[str, str]] | None = None,
    server_id: int = 42,
) -> Any:
    from app.views.server_settings import tag_create

    inner = getattr(tag_create, "__wrapped__", tag_create)

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)

    if log_event_calls is not None:

        def fake_log_event(action: str, **kwargs: Any) -> Any:
            log_event_calls.append({"action": action, **kwargs})
            return MagicMock()

        monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    if flashes is not None:

        def fake_flash(msg: str, category: str = "message") -> None:
            flashes.append((msg, category))

        monkeypatch.setattr("app.views.server_settings.flash", fake_flash)

    with app.test_request_context(
        f"/servers/{server_id}/settings/tags/create",
        method="POST",
        data={"name": name},
    ):
        return inner(server_id=server_id)


# ===========================================================================
# 1. Happy-Path: Tag angelegt (color #6b7280) + Link + beide Events
# ===========================================================================


def test_tag_create_happy_path(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST mit gueltigem Namen -> Tag mit Default-Color, Link, beide Audits, 302."""
    server = _make_server(id=42)
    mock_sess = MagicMock()
    # existing-Link-Lookup liefert None (Link noch nicht vorhanden)
    link_result = MagicMock()
    link_result.scalar_one_or_none.return_value = None
    mock_sess.execute.return_value = link_result
    captured = _capture_adds(mock_sess, tag_id=5)

    log_event_calls: list[dict] = []

    resp = _call_tag_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod",
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
    )

    assert resp.status_code == 302, f"tag_create soll 302 liefern, got {resp.status_code}"
    mock_sess.commit.assert_called_once()

    # captured[0] = neuer Tag, captured[1] = ServerTag-Link
    assert len(captured) == 2, f"Tag + ServerTag-Link erwartet (2 adds), captured: {captured}"
    new_tag, new_link = captured[0], captured[1]
    assert new_tag.color == "#6b7280", f"Tag.color soll Default #6b7280 sein, ist: {new_tag.color}"
    assert new_tag.name == "prod", f"Tag.name falsch: {new_tag.name}"
    assert new_link.server_id == 42, f"ServerTag.server_id falsch: {new_link.server_id}"
    assert new_link.tag_id == 5, f"ServerTag.tag_id falsch: {new_link.tag_id}"

    actions = [c["action"] for c in log_event_calls]
    assert "tag.created" in actions, f"tag.created fehlt. Calls: {log_event_calls}"
    assert "server.tag.added" in actions, f"server.tag.added fehlt. Calls: {log_event_calls}"

    created = next(c for c in log_event_calls if c["action"] == "tag.created")
    assert created["target_type"] == "tag", f"target_type falsch: {created}"
    assert created["target_id"] == 5, f"target_id falsch: {created}"
    md = created.get("metadata", {})
    assert md.get("via") == "server_settings", f"via-Metadata falsch: {md}"
    assert md.get("name") == "prod", f"name-Metadata falsch: {md}"
    assert md.get("color") == "#6b7280", f"color-Metadata falsch: {md}"

    added = next(c for c in log_event_calls if c["action"] == "server.tag.added")
    assert added.get("metadata", {}).get("tag_id") == 5, f"tag_id-Metadata falsch: {added}"
    assert added.get("metadata", {}).get("tag_name") == "prod", f"tag_name-Metadata falsch: {added}"


# ===========================================================================
# 2. Race-Path: IntegrityError -> existing Tag, KEIN tag.created
# ===========================================================================


def test_tag_create_race_refetches_existing(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """flush() wirft IntegrityError -> rollback, existing Tag nachladen, kein tag.created.

    Link existiert noch nicht -> server.tag.added wird trotzdem gefeuert.
    """
    server = _make_server(id=42)
    existing = _make_tag(id=8, name="prod", color="#abcdef")

    mock_sess = MagicMock()
    refetch_result = MagicMock()
    refetch_result.scalar_one.return_value = existing
    link_result = MagicMock()
    link_result.scalar_one_or_none.return_value = None
    # 1. execute (nach Rollback): Re-Fetch existing Tag; 2. execute: existing-Link-Lookup.
    mock_sess.execute.side_effect = [refetch_result, link_result]
    captured = _capture_adds(mock_sess, tag_id=None)
    mock_sess.flush.side_effect = IntegrityError("dup", None, Exception("dup"))

    log_event_calls: list[dict] = []

    resp = _call_tag_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod",
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
    )

    assert resp.status_code == 302, f"Race-Path soll 302 liefern, got {resp.status_code}"
    mock_sess.rollback.assert_called_once()
    mock_sess.commit.assert_called_once()

    actions = [c["action"] for c in log_event_calls]
    assert "tag.created" not in actions, (
        f"tag.created darf im Race-Path NICHT gefeuert werden. Calls: {log_event_calls}"
    )
    assert "server.tag.added" in actions, (
        f"server.tag.added muss bei neuem Link gefeuert werden. Calls: {actions}"
    )
    # Link wurde mit existing.id=8 angelegt (Tag-add wurde rolled-back, captured behaelt es;
    # entscheidend ist der zuletzt hinzugefuegte ServerTag-Link).
    new_link = captured[-1]
    assert new_link.server_id == 42, f"ServerTag.server_id falsch: {new_link.server_id}"
    assert new_link.tag_id == 8, (
        f"Link soll existing tag_id=8 referenzieren, ist: {new_link.tag_id}"
    )


# ===========================================================================
# 3. Idempotenter Link: existing_link != None -> kein server.tag.added
# ===========================================================================


def test_tag_create_idempotent_link(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tag neu angelegt, aber Link existiert bereits -> kein server.tag.added, kein Duplikat."""
    server = _make_server(id=42)
    existing_link = types.SimpleNamespace(server_id=42, tag_id=5)

    mock_sess = MagicMock()
    link_result = MagicMock()
    link_result.scalar_one_or_none.return_value = existing_link
    mock_sess.execute.return_value = link_result
    captured = _capture_adds(mock_sess, tag_id=5)

    log_event_calls: list[dict] = []

    resp = _call_tag_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod",
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
    )

    assert resp.status_code == 302
    actions = [c["action"] for c in log_event_calls]
    # tag.created wird gefeuert (Tag war neu), aber kein server.tag.added (Link existierte).
    assert "tag.created" in actions, f"tag.created erwartet (Tag neu). Calls: {actions}"
    assert "server.tag.added" not in actions, (
        f"server.tag.added darf bei existierendem Link NICHT gefeuert werden. Calls: {actions}"
    )
    # Nur der Tag wurde via add hinzugefuegt, kein zweiter ServerTag-Link.
    assert len(captured) == 1, (
        f"Nur der Tag-add erwartet, kein ServerTag-Link bei existierendem Link. "
        f"captured: {captured}"
    )


# ===========================================================================
# 4. Invalid-Name -> 302 flash, keine Anlage
# ===========================================================================


@pytest.mark.parametrize(
    "bad_name",
    ["Prod", "prod eu", "x" * 33, "", "-prod", "@bad"],
    ids=["uppercase", "space", "too_long_33", "empty", "leading_dash", "at_sign"],
)
def test_tag_create_invalid_name_rejected(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch, bad_name: str
) -> None:
    """Ungueltiger Name -> Form-Validation faellt -> flash + 302, kein add/commit."""
    server = _make_server(id=42)
    mock_sess = MagicMock()
    captured = _capture_adds(mock_sess, tag_id=5)

    log_event_calls: list[dict] = []
    flashes: list[tuple[str, str]] = []

    resp = _call_tag_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name=bad_name,
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
        flashes=flashes,
    )

    assert resp.status_code == 302, f"Invalid-Name soll 302 liefern, got {resp.status_code}"
    assert captured == [], f"Kein add bei Invalid-Name. captured: {captured}"
    mock_sess.commit.assert_not_called()
    assert len(flashes) > 0, "Flash-Message erwartet bei Invalid-Name."
    assert log_event_calls == [], f"Kein Audit-Event bei Invalid-Name. Calls: {log_event_calls}"


# ===========================================================================
# 5. Revoked-Server -> 404
# ===========================================================================


def test_tag_create_404_when_revoked(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit revoked_at -> abort(404)."""
    from datetime import UTC, datetime

    from werkzeug.exceptions import NotFound

    server = _make_server(id=42, revoked_at=datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import tag_create

    inner = getattr(tag_create, "__wrapped__", tag_create)
    with (
        no_csrf_app.test_request_context(
            "/servers/42/settings/tags/create",
            method="POST",
            data={"name": "prod"},
        ),
        pytest.raises(NotFound),
    ):
        inner(server_id=42)


# ===========================================================================
# 6. Retired-Server -> 404
# ===========================================================================


def test_tag_create_404_when_retired(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit retired_at -> abort(404)."""
    from datetime import UTC, datetime

    from werkzeug.exceptions import NotFound

    server = _make_server(id=42, retired_at=datetime(2026, 2, 1, tzinfo=UTC))
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import tag_create

    inner = getattr(tag_create, "__wrapped__", tag_create)
    with (
        no_csrf_app.test_request_context(
            "/servers/42/settings/tags/create",
            method="POST",
            data={"name": "prod"},
        ),
        pytest.raises(NotFound),
    ):
        inner(server_id=42)


# ===========================================================================
# 7. Auth + Route-Registrierung
# ===========================================================================


def test_tag_create_is_login_required(no_csrf_app: Flask) -> None:
    """tag_create traegt @login_required (hat __wrapped__) und ist als Route registriert."""
    from app.views.server_settings import tag_create

    assert hasattr(tag_create, "__wrapped__"), (
        "tag_create muss mit @login_required dekoriert sein (kein __wrapped__ gefunden)."
    )

    rules = [
        r.rule
        for r in no_csrf_app.url_map.iter_rules()
        if r.endpoint == "server_settings.tag_create"
    ]
    assert rules, "Route 'server_settings.tag_create' ist nicht registriert."
    assert any(rule.endswith("/tags/create") for rule in rules), (
        f"tag_create-Route soll auf /tags/create enden. Rules: {rules}"
    )
