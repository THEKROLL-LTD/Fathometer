"""Pure-Unit-Tests fuer `POST /_partials/sidebar/batch` (ADR-0035, Block W).

Testet den Viewport-Batch-Endpoint in zwei Ebenen:
  1. Pydantic-Schema-Level (pure, kein Flask-Overhead):
     - Extra-Felder -> ValidationError
     - >200 IDs -> ValidationError
     - Nicht-int IDs -> ValidationError
     - Negative IDs -> ValidationError
  2. View-Funktion-Level (via __wrapped__ + Mock-Request, kein Auth-Bypass-Problem):
     - Valider Request -> 200 + OOB-Fragment
     - Leere Liste -> 200
     - Kein JSON -> abort(400)
     - DB-Whitelist filtert unbekannte IDs
  3. Endpoint-Registrierung (pytest-App-Fixture):
     - Route ist als POST /_partials/sidebar/batch registriert
  4. Auth-Pruefung (Flask-Testclient, unauthentiziert):
     - Ohne Auth -> 302 zu Login

Kein echter DB-Zugriff — Mock-Session und Mock-Services.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Pydantic-Schema direkt (pure unit, kein Flask-Overhead)
# ---------------------------------------------------------------------------


def test_sidebar_batch_schema_accepts_valid_payload() -> None:
    """SidebarBatchRequest akzeptiert valide Payload ohne Exception."""
    from app.schemas.sidebar_batch import SidebarBatchRequest

    req = SidebarBatchRequest.model_validate({"server_ids": [1, 2, 3]})
    assert req.server_ids == [1, 2, 3]


def test_sidebar_batch_schema_rejects_bool_ids() -> None:
    """Booleans sind technisch int in Python — der Validator prueft darauf."""
    from pydantic import ValidationError

    from app.schemas.sidebar_batch import SidebarBatchRequest

    with pytest.raises(ValidationError):
        SidebarBatchRequest.model_validate({"server_ids": [True, False]})


def test_sidebar_batch_rejects_extra_fields_schema() -> None:
    """Extra-Felder (Pydantic extra='forbid') -> ValidationError."""
    from pydantic import ValidationError

    from app.schemas.sidebar_batch import SidebarBatchRequest

    with pytest.raises(ValidationError):
        SidebarBatchRequest.model_validate({"server_ids": [], "rogue": 42})


def test_sidebar_batch_rejects_more_than_200_ids_schema() -> None:
    """201 IDs -> ValidationError (max_length=200)."""
    from pydantic import ValidationError

    from app.schemas.sidebar_batch import SidebarBatchRequest

    with pytest.raises(ValidationError):
        SidebarBatchRequest.model_validate({"server_ids": list(range(1, 202))})


def test_sidebar_batch_schema_exactly_200_ids_ok() -> None:
    """Genau 200 IDs sind erlaubt (Grenzwert)."""
    from app.schemas.sidebar_batch import SidebarBatchRequest

    req = SidebarBatchRequest.model_validate({"server_ids": list(range(1, 201))})
    assert len(req.server_ids) == 200


def test_sidebar_batch_rejects_non_int_ids_schema() -> None:
    """Nicht-int IDs -> ValidationError."""
    from pydantic import ValidationError

    from app.schemas.sidebar_batch import SidebarBatchRequest

    with pytest.raises(ValidationError):
        SidebarBatchRequest.model_validate({"server_ids": [1, "two", 3]})


def test_sidebar_batch_rejects_negative_ids_schema() -> None:
    """Negative IDs -> ValidationError (Validator prueft item > 0)."""
    from pydantic import ValidationError

    from app.schemas.sidebar_batch import SidebarBatchRequest

    with pytest.raises(ValidationError):
        SidebarBatchRequest.model_validate({"server_ids": [-1]})


def test_sidebar_batch_rejects_zero_id_schema() -> None:
    """ID=0 -> ValidationError (nur positive Integer erlaubt)."""
    from pydantic import ValidationError

    from app.schemas.sidebar_batch import SidebarBatchRequest

    with pytest.raises(ValidationError):
        SidebarBatchRequest.model_validate({"server_ids": [0]})


# ---------------------------------------------------------------------------
# View-Funktion direkt — kein Auth/CSRF-Problem
# ---------------------------------------------------------------------------


def _make_mock_request(body: Any, *, as_valid_json: bool = True) -> MagicMock:
    """Baut einen Flask-Request-Mock fuer die sidebar_batch-View-Funktion."""
    req = MagicMock()
    if as_valid_json:
        req.get_json.return_value = body
    else:
        req.get_json.return_value = None
    req.args.getlist.return_value = []
    return req


def _stub_services(
    monkeypatch: pytest.MonkeyPatch,
    visible_ids: list[int],
    batch_servers: list[MagicMock] | None = None,
) -> None:
    """Patcht alle Services die sidebar_batch intern aufruft."""
    monkeypatch.setattr(
        "app.views._sidebar_context._filter_visible_server_ids",
        lambda sess, raw_ids, **kw: visible_ids,
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.heartbeats_for_servers",
        lambda sess, ids, **kw: {sid: [] for sid in ids},
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.escalate_act_counts_by_server",
        lambda sess, ids: {sid: {"escalate": 0, "act": 0} for sid in ids},
    )
    # Session-Mock fuer den Server-Query im nicht-leeren Pfad
    mock_sess = MagicMock()
    servers_result = MagicMock()
    servers_result.scalars.return_value.all.return_value = batch_servers or []
    mock_sess.execute.return_value = servers_result
    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)


def _call_batch_inner(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    body: Any,
    *,
    visible_ids: list[int] | None = None,
    batch_servers: list[MagicMock] | None = None,
    as_valid_json: bool = True,
) -> Any:
    """Ruft sidebar_batch.__wrapped__ direkt auf (bypassed @login_required).

    Gibt ein Ergebnis-Dict zurueck:
      - "template": Name des gerenderten Templates
      - "ctx": Template-Context-Dict
      - "abort": HTTP-Status-Code wenn abort() gerufen wurde
    """
    _stub_services(monkeypatch, visible_ids or [], batch_servers)

    mock_req = _make_mock_request(body, as_valid_json=as_valid_json)

    captured: dict[str, Any] = {}

    def fake_render(template: str, **ctx: Any) -> str:
        captured["template"] = template
        captured["ctx"] = ctx
        return "<div>oob</div>"

    monkeypatch.setattr("app.views._sidebar_context.render_template", fake_render)

    from werkzeug.exceptions import HTTPException

    from app.views._sidebar_context import sidebar_batch

    inner = getattr(sidebar_batch, "__wrapped__", sidebar_batch)

    with (
        app.test_request_context("/_partials/sidebar/batch", method="POST"),
        patch("app.views._sidebar_context.request", mock_req),
    ):
        try:
            inner()
        except HTTPException as e:
            captured["abort"] = e.code

    return captured


# ---------------------------------------------------------------------------
# Valide Requests (via __wrapped__)
# ---------------------------------------------------------------------------


def test_sidebar_batch_valid_request_calls_render_template(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valider Request mit server_ids=[1,2,3] -> render_template wird aufgerufen."""
    result = _call_batch_inner(app, monkeypatch, {"server_ids": [1, 2, 3]}, visible_ids=[1, 2, 3])
    assert "template" in result, f"render_template wurde nicht aufgerufen: {result}"
    assert "sidebar_batch_oob" in result["template"], (
        f"OOB-Template nicht gerendert: {result['template']}"
    )


def test_sidebar_batch_empty_list_calls_render_template(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leere server_ids-Liste -> render_template mit leeren Listen."""
    result = _call_batch_inner(app, monkeypatch, {"server_ids": []}, visible_ids=[])
    assert "template" in result, f"render_template nicht aufgerufen: {result}"


def test_sidebar_batch_empty_response_has_empty_batch_servers(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leere visible_ids -> batch_servers=[] im Template-Context."""
    result = _call_batch_inner(app, monkeypatch, {"server_ids": []}, visible_ids=[])
    assert result.get("ctx", {}).get("batch_servers") == [], (
        f"batch_servers soll leer sein: {result}"
    )


# ---------------------------------------------------------------------------
# Validierungs-Fehler -> abort(400) via __wrapped__
# ---------------------------------------------------------------------------


def test_sidebar_batch_rejects_extra_fields_abort_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Extra-Felder (Pydantic extra='forbid') -> abort(400)."""
    result = _call_batch_inner(app, monkeypatch, {"server_ids": [], "foo": "bar"}, visible_ids=[])
    assert result.get("abort") == 400, f"Extra-Felder muessen zu abort(400) fuehren: {result}"


def test_sidebar_batch_rejects_more_than_200_ids_abort_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mehr als 200 IDs -> abort(400)."""
    result = _call_batch_inner(
        app, monkeypatch, {"server_ids": list(range(1, 202))}, visible_ids=[]
    )
    assert result.get("abort") == 400, f">200 IDs muessen zu abort(400) fuehren: {result}"


def test_sidebar_batch_rejects_non_int_ids_abort_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nicht-int IDs -> abort(400)."""
    result = _call_batch_inner(app, monkeypatch, {"server_ids": [1, "two", 3]}, visible_ids=[])
    assert result.get("abort") == 400, f"String-IDs muessen zu abort(400) fuehren: {result}"


def test_sidebar_batch_rejects_negative_ids_abort_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative IDs -> abort(400)."""
    result = _call_batch_inner(app, monkeypatch, {"server_ids": [-1]}, visible_ids=[])
    assert result.get("abort") == 400, f"Negative IDs muessen zu abort(400) fuehren: {result}"


def test_sidebar_batch_rejects_invalid_json_abort_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Body kein valides JSON -> abort(400)."""
    result = _call_batch_inner(app, monkeypatch, None, visible_ids=[], as_valid_json=False)
    assert result.get("abort") == 400, f"Invalides JSON muss zu abort(400) fuehren: {result}"


# ---------------------------------------------------------------------------
# DB-Whitelist: unbekannte IDs werden gefiltert (via __wrapped__)
# ---------------------------------------------------------------------------


def test_sidebar_batch_filters_unknown_server_ids(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """IDs die nicht in DB existieren werden weggefiltert.

    _filter_visible_server_ids gibt nur [1] zurueck, obwohl [1, 99, 999] angefragt.
    """
    filter_spy = MagicMock(return_value=[1])
    monkeypatch.setattr(
        "app.views._sidebar_context._filter_visible_server_ids",
        filter_spy,
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.heartbeats_for_servers",
        lambda sess, ids, **kw: {sid: [] for sid in ids},
    )
    monkeypatch.setattr(
        "app.views._sidebar_context.escalate_act_counts_by_server",
        lambda sess, ids: {sid: {"escalate": 0, "act": 0} for sid in ids},
    )
    mock_sess = MagicMock()
    servers_result = MagicMock()
    servers_result.scalars.return_value.all.return_value = []
    mock_sess.execute.return_value = servers_result
    monkeypatch.setattr("app.views._sidebar_context.get_session", lambda: mock_sess)

    captured_render: dict = {}

    def fake_render(template: str, **ctx: Any) -> str:
        captured_render["template"] = template
        captured_render["ctx"] = ctx
        return ""

    monkeypatch.setattr("app.views._sidebar_context.render_template", fake_render)

    mock_req = _make_mock_request({"server_ids": [1, 99, 999]})

    from werkzeug.exceptions import HTTPException

    from app.views._sidebar_context import sidebar_batch

    inner = getattr(sidebar_batch, "__wrapped__", sidebar_batch)

    with (
        app.test_request_context("/_partials/sidebar/batch", method="POST"),
        patch("app.views._sidebar_context.request", mock_req),
        contextlib.suppress(HTTPException),
    ):
        inner()

    # filter_spy muss aufgerufen worden sein
    filter_spy.assert_called_once()
    # Positional: (sess, raw_ids)
    raw_ids_arg = filter_spy.call_args[0][1]
    assert set(raw_ids_arg) == {1, 99, 999}, f"Filter soll alle 3 IDs sehen: {raw_ids_arg}"
    # Template wurde gerendert
    assert "template" in captured_render, "render_template nicht aufgerufen"


# ---------------------------------------------------------------------------
# Endpoint-Registrierung (Flask-URL-Map)
# ---------------------------------------------------------------------------


def test_sidebar_batch_route_registered(app: Flask) -> None:
    """POST /_partials/sidebar/batch ist als Route registriert."""
    rules = {rule.rule: list(rule.methods or []) for rule in app.url_map.iter_rules()}
    assert "/_partials/sidebar/batch" in rules, (
        f"Route /_partials/sidebar/batch nicht gefunden: {list(rules.keys())}"
    )
    assert "POST" in rules["/_partials/sidebar/batch"], (
        f"POST-Methode nicht registriert: {rules['/_partials/sidebar/batch']}"
    )


# ---------------------------------------------------------------------------
# Auth-Pruefung via Flask-Testclient (CSRF=False, unauthentifiziert)
# ---------------------------------------------------------------------------


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    """App ohne CSRF fuer Auth-Test."""
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


def test_sidebar_batch_requires_auth_302(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne Auth -> Redirect (302) zu Login."""
    # Kein Mock-User -> flask_login redirectet zu /login
    client = no_csrf_app.test_client()
    resp = client.post(
        "/_partials/sidebar/batch",
        data=json.dumps({"server_ids": [1]}),
        content_type="application/json",
    )
    assert resp.status_code in (302, 401), (
        f"Ohne Auth muss 302 oder 401 kommen, got {resp.status_code}"
    )
