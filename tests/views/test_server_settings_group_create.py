"""Pure-Unit-Tests fuer `server_settings.group_create` (Block Z, Phase A, ADR-0040).

Inline-Anlage einer ServerGroup direkt im Server-Settings-Kontext, atomar mit
der Zuweisung an den aktuellen Server. Race-sicher via IntegrityError-Catch +
Re-Fetch der existing Row (Idempotenz).

Render-Strategie analog `test_server_settings.py`:
  - Handler werden via `func.__wrapped__` direkt aufgerufen (umgeht
    `@login_required` ohne Auth-Bypass-Mock).
  - `_load_server_with_settings`, `get_session`, `log_event`, `flash` werden
    per `monkeypatch.setattr` gestubbt — kein echter DB-Zugriff.
  - Das `ServerGroup`-Symbol wird NICHT ersetzt (der Handler nutzt es auch in
    `select(ServerGroup)`-Queries). Stattdessen vergibt ein `sess.flush`-
    Side-Effect die PK auf dem zuletzt via `sess.add` hinzugefuegten Objekt —
    so wie ein echter Postgres-Flush die Autoincrement-ID setzen wuerde.

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
    group_id: int | None = None,
    revoked_at: Any = None,
    retired_at: Any = None,
) -> types.SimpleNamespace:
    """Erstellt ein minimales Server-Mock-Objekt fuer group_create-Tests."""
    return types.SimpleNamespace(
        id=id,
        group_id=group_id,
        revoked_at=revoked_at,
        retired_at=retired_at,
    )


def _make_group(*, id: int = 7, name: str = "prod-eu", position: int = 0) -> types.SimpleNamespace:
    """Erstellt ein minimales ServerGroup-Mock-Objekt (fuer Race-Re-Fetch)."""
    return types.SimpleNamespace(id=id, name=name, position=position)


def _flush_assigns_id(sess: MagicMock, *, assigned_id: int) -> None:
    """Konfiguriert `sess.add`/`sess.flush` so, dass flush eine PK vergibt.

    Echter Postgres-Flush setzt die Autoincrement-`id` auf der neuen Row.
    Da hier kein echter Flush laeuft, simulieren wir das: `sess.add` merkt
    sich das Objekt, `sess.flush` setzt darauf `.id = assigned_id`.
    """
    captured: list[Any] = []

    def fake_add(obj: Any) -> None:
        captured.append(obj)

    def fake_flush() -> None:
        if captured:
            captured[-1].id = assigned_id

    sess.add.side_effect = fake_add
    sess.flush.side_effect = fake_flush
    # Test-Zugriff auf das zuletzt hinzugefuegte Objekt.
    sess._captured = captured  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Fixture: App mit CSRF disabled
# ---------------------------------------------------------------------------


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    """App mit deaktiviertem CSRF und TESTING=True."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


# ---------------------------------------------------------------------------
# Render-Helper: ruft group_create.__wrapped__ mit gemockten Dependencies auf.
# ---------------------------------------------------------------------------


def _call_group_create(
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
    """Ruft group_create.__wrapped__ mit gemockten Dependencies auf."""
    from app.views.server_settings import group_create

    inner = getattr(group_create, "__wrapped__", group_create)

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
        f"/servers/{server_id}/settings/group/create",
        method="POST",
        data={"name": name},
    ):
        return inner(server_id=server_id)


# ===========================================================================
# 1. Happy-Path: Group angelegt + zugewiesen + beide Audit-Events
# ===========================================================================


def test_group_create_happy_path(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST mit gueltigem Namen -> Group anlegen, server.group_id setzen, 302.

    Erwartet group.created (via=server_settings) + server.group_changed.
    """
    server = _make_server(id=42, group_id=None)
    mock_sess = MagicMock()
    # Positions-Query: COALESCE(MAX(position), -1) + 1 -> 0 (leere Tabelle)
    pos_result = MagicMock()
    pos_result.scalar_one.return_value = 0
    mock_sess.execute.return_value = pos_result
    _flush_assigns_id(mock_sess, assigned_id=7)

    log_event_calls: list[dict] = []

    resp = _call_group_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod-eu",
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
    )

    assert resp.status_code == 302, f"group_create soll 302 liefern, got {resp.status_code}"
    assert server.group_id == 7, f"server.group_id soll 7 sein, ist: {server.group_id}"
    mock_sess.commit.assert_called_once()

    actions = [c["action"] for c in log_event_calls]
    assert "group.created" in actions, f"group.created fehlt. Calls: {log_event_calls}"
    assert "server.group_changed" in actions, (
        f"server.group_changed fehlt. Calls: {log_event_calls}"
    )

    created = next(c for c in log_event_calls if c["action"] == "group.created")
    assert created["target_type"] == "group", f"target_type falsch: {created}"
    assert created["target_id"] == 7, f"target_id falsch: {created}"
    md = created.get("metadata", {})
    assert md.get("via") == "server_settings", f"via-Metadata falsch: {md}"
    assert md.get("name") == "prod-eu", f"name-Metadata falsch: {md}"
    assert md.get("position") == 0, f"position-Metadata falsch: {md}"

    changed = next(c for c in log_event_calls if c["action"] == "server.group_changed")
    assert changed.get("metadata", {}).get("from") is None, f"from-Metadata falsch: {changed}"
    assert changed.get("metadata", {}).get("to") == 7, f"to-Metadata falsch: {changed}"


# ===========================================================================
# 2. Position-Berechnung bei leerer Tabelle -> 0
# ===========================================================================


def test_group_create_position_zero_on_empty_table(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """COALESCE(MAX(position), -1) + 1 = 0 bei leerer Tabelle -> position=0 am ServerGroup."""
    server = _make_server(id=42, group_id=None)
    mock_sess = MagicMock()
    pos_result = MagicMock()
    pos_result.scalar_one.return_value = 0
    mock_sess.execute.return_value = pos_result
    _flush_assigns_id(mock_sess, assigned_id=7)

    _call_group_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod-eu",
        mock_sess=mock_sess,
        log_event_calls=[],
    )

    captured = mock_sess._captured
    assert captured, "ServerGroup wurde nicht via sess.add hinzugefuegt."
    assert captured[-1].position == 0, (
        f"position soll 0 sein bei leerer Tabelle, ist: {captured[-1].position}"
    )


# ===========================================================================
# 3. Position-Berechnung bei bestehenden Gruppen -> MAX+1
# ===========================================================================


def test_group_create_position_increments(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positions-Query liefert 5 (= MAX(4)+1) -> ServerGroup.position == 5."""
    server = _make_server(id=42, group_id=None)
    mock_sess = MagicMock()
    pos_result = MagicMock()
    pos_result.scalar_one.return_value = 5
    mock_sess.execute.return_value = pos_result
    _flush_assigns_id(mock_sess, assigned_id=9)

    _call_group_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="staging",
        mock_sess=mock_sess,
        log_event_calls=[],
    )

    captured = mock_sess._captured
    assert captured, "ServerGroup wurde nicht via sess.add hinzugefuegt."
    assert captured[-1].position == 5, f"position soll 5 sein, ist: {captured[-1].position}"


# ===========================================================================
# 4. Race-Path: IntegrityError -> existing Group nachladen, KEIN group.created
# ===========================================================================


def test_group_create_race_refetches_existing(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """flush() wirft IntegrityError -> rollback, existing Group nachladen.

    KEIN group.created-Event; aber server.group_changed wenn old != existing.id.
    Kein 500.
    """
    server = _make_server(id=42, group_id=None)
    existing = _make_group(id=3, name="prod-eu", position=2)

    mock_sess = MagicMock()
    pos_result = MagicMock()
    pos_result.scalar_one.return_value = 0
    refetch_result = MagicMock()
    refetch_result.scalar_one.return_value = existing
    # 1. execute: Positions-Query; 2. execute (nach Rollback): Re-Fetch existing.
    mock_sess.execute.side_effect = [pos_result, refetch_result]
    mock_sess.flush.side_effect = IntegrityError("dup", None, Exception("dup"))

    log_event_calls: list[dict] = []

    resp = _call_group_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod-eu",
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
    )

    assert resp.status_code == 302, f"Race-Path soll 302 (kein 500) liefern, got {resp.status_code}"
    mock_sess.rollback.assert_called_once()
    mock_sess.commit.assert_called_once()
    assert server.group_id == 3, (
        f"server.group_id soll existing.id (3) sein, ist: {server.group_id}"
    )

    actions = [c["action"] for c in log_event_calls]
    assert "group.created" not in actions, (
        f"group.created darf im Race-Path NICHT gefeuert werden. Calls: {log_event_calls}"
    )
    assert "server.group_changed" in actions, (
        f"server.group_changed muss bei old(None)!=existing(3) gefeuert werden. Calls: {actions}"
    )


# ===========================================================================
# 5. Race-Path + bereits zugewiesen -> kein server.group_changed
# ===========================================================================


def test_group_create_race_no_change_when_already_assigned(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """IntegrityError + server.group_id == existing.id -> kein server.group_changed."""
    server = _make_server(id=42, group_id=3)
    existing = _make_group(id=3, name="prod-eu", position=2)

    mock_sess = MagicMock()
    pos_result = MagicMock()
    pos_result.scalar_one.return_value = 0
    refetch_result = MagicMock()
    refetch_result.scalar_one.return_value = existing
    mock_sess.execute.side_effect = [pos_result, refetch_result]
    mock_sess.flush.side_effect = IntegrityError("dup", None, Exception("dup"))

    log_event_calls: list[dict] = []

    resp = _call_group_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name="prod-eu",
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
    )

    assert resp.status_code == 302
    actions = [c["action"] for c in log_event_calls]
    assert "group.created" not in actions, f"kein group.created im Race-Path. Calls: {actions}"
    assert "server.group_changed" not in actions, (
        f"kein server.group_changed wenn bereits zugewiesen. Calls: {actions}"
    )


# ===========================================================================
# 6. Invalid-Name (Regex-Verstoss) -> 302 flash, keine Anlage
# ===========================================================================


@pytest.mark.parametrize(
    "bad_name",
    ["prod/eu", "prod@eu", "x" * 65, ""],
    ids=["slash", "at_sign", "too_long_65", "empty"],
)
def test_group_create_invalid_name_rejected(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch, bad_name: str
) -> None:
    """Ungueltiger Name -> Form-Validation faellt -> flash + 302, kein add/commit."""
    server = _make_server(id=42, group_id=None)
    original_group_id = server.group_id
    mock_sess = MagicMock()

    log_event_calls: list[dict] = []
    flashes: list[tuple[str, str]] = []

    resp = _call_group_create(
        no_csrf_app,
        monkeypatch,
        server=server,
        name=bad_name,
        mock_sess=mock_sess,
        log_event_calls=log_event_calls,
        flashes=flashes,
    )

    assert resp.status_code == 302, f"Invalid-Name soll 302 liefern, got {resp.status_code}"
    assert server.group_id == original_group_id, (
        f"group_id darf sich nicht aendern bei Invalid-Name. ist: {server.group_id}"
    )
    mock_sess.add.assert_not_called()
    mock_sess.commit.assert_not_called()
    assert len(flashes) > 0, "Flash-Message erwartet bei Invalid-Name."
    assert log_event_calls == [], f"Kein Audit-Event bei Invalid-Name. Calls: {log_event_calls}"


# ===========================================================================
# 7. Revoked-Server -> 404
# ===========================================================================


def test_group_create_404_when_revoked(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit revoked_at -> abort(404)."""
    from datetime import UTC, datetime

    from werkzeug.exceptions import NotFound

    server = _make_server(id=42, revoked_at=datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import group_create

    inner = getattr(group_create, "__wrapped__", group_create)
    with (
        no_csrf_app.test_request_context(
            "/servers/42/settings/group/create",
            method="POST",
            data={"name": "prod"},
        ),
        pytest.raises(NotFound),
    ):
        inner(server_id=42)


# ===========================================================================
# 8. Retired-Server -> 404
# ===========================================================================


def test_group_create_404_when_retired(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit retired_at -> abort(404)."""
    from datetime import UTC, datetime

    from werkzeug.exceptions import NotFound

    server = _make_server(id=42, retired_at=datetime(2026, 2, 1, tzinfo=UTC))
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import group_create

    inner = getattr(group_create, "__wrapped__", group_create)
    with (
        no_csrf_app.test_request_context(
            "/servers/42/settings/group/create",
            method="POST",
            data={"name": "prod"},
        ),
        pytest.raises(NotFound),
    ):
        inner(server_id=42)


# ===========================================================================
# 9. Nonexistent-Server (None) -> 404
# ===========================================================================


def test_group_create_404_when_server_none(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_load_server_with_settings -> None -> abort(404)."""
    from werkzeug.exceptions import NotFound

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: None)

    from app.views.server_settings import group_create

    inner = getattr(group_create, "__wrapped__", group_create)
    with (
        no_csrf_app.test_request_context(
            "/servers/9999/settings/group/create",
            method="POST",
            data={"name": "prod"},
        ),
        pytest.raises(NotFound),
    ):
        inner(server_id=9999)


# ===========================================================================
# 10. Auth: group_create ist mit @login_required dekoriert
# ===========================================================================


def test_group_create_is_login_required(no_csrf_app: Flask) -> None:
    """group_create traegt das @login_required-Wrapping (hat __wrapped__).

    Zusaetzlich: die Route ist im Blueprint registriert.
    """
    from app.views.server_settings import group_create

    assert hasattr(group_create, "__wrapped__"), (
        "group_create muss mit @login_required dekoriert sein (kein __wrapped__ gefunden)."
    )

    rules = [
        r.rule
        for r in no_csrf_app.url_map.iter_rules()
        if r.endpoint == "server_settings.group_create"
    ]
    assert rules, "Route 'server_settings.group_create' ist nicht registriert."
    assert any(rule.endswith("/group/create") for rule in rules), (
        f"group_create-Route soll auf /group/create enden. Rules: {rules}"
    )
