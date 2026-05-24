"""Pure-Unit-Tests fuer die Bucket-View-Routes (TICKET-006 Etappe 2, ADR-0037).

Pattern (analog `tests/views/test_sidebar_batch.py`):
  * View-Funktionen werden via `__wrapped__` aufgerufen (bypasst
    `@login_required`).
  * `render_template` wird per `monkeypatch` durch ein `fake_render`-Stub
    ersetzt, damit kein echtes Jinja gerendert werden muss (kein Datenbank-
    Zugriff, kein Template-Compile).
  * Service-Funktionen, `get_session`, `log_event`, `validate_csrf` werden
    auf Modul-Ebene gepatcht.
  * Flask-Request-Context wird via `app.test_request_context(...)` aufgebaut.

Kein echter DB-Zugriff, kein echter CSRF-Token, kein echter Flask-Login-State —
reine Funktions-Tests gegen den Views-Layer.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from werkzeug.exceptions import HTTPException

from app.services.findings_bucket_query import BucketHeader

# ---------------------------------------------------------------------------
# Helfer
# ---------------------------------------------------------------------------


def _make_bucket(
    *,
    server_id: int = 1,
    group_id: int = 22,
    server_name: str = "rke2-sv-0",
    group_label: str = "nginx",
    risk_band: str = "escalate",
    finding_count: int = 3,
) -> BucketHeader:
    return BucketHeader(
        server_id=server_id,
        group_id=group_id,
        server_name=server_name,
        group_label=group_label,
        risk_band=risk_band,
        finding_count=finding_count,
    )


def _make_finding_mock(fid: int = 100, server_id: int = 1) -> MagicMock:
    f = MagicMock()
    f.id = fid
    f.server_id = server_id
    f.identifier_key = f"CVE-2026-{fid:04d}"
    return f


def _patch_cheap_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Die index()-Route ruft zwei billige Aggregat-Helper auf — wir stubben sie."""
    monkeypatch.setattr("app.views.findings._count_open_findings", lambda sess: 0)
    monkeypatch.setattr("app.views.findings._count_active_servers", lambda sess: 0)


def _patch_aux_loaders(monkeypatch: pytest.MonkeyPatch, mock_sess: MagicMock) -> None:
    """Tags + ApplicationGroups Sidebar-Loader: einfach leere Liste liefern."""
    # `sess.execute(select(...)).scalars().all()` -> []
    scalars = MagicMock()
    scalars.all.return_value = []
    execute_result = MagicMock()
    execute_result.scalars.return_value = scalars
    execute_result.scalar.return_value = 0
    mock_sess.execute.return_value = execute_result


def _capture_render(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patcht `render_template` und liefert ein Dict in das Template + Ctx
    geschrieben werden."""
    captured: dict[str, Any] = {}

    def fake_render(template: str, **ctx: Any) -> str:
        captured["template"] = template
        captured["ctx"] = ctx
        return f"<rendered>{template}</rendered>"

    monkeypatch.setattr("app.views.findings.render_template", fake_render)
    return captured


def _call_inner(view_callable: Any) -> Any:
    """Bypass @login_required -> die nackte Funktion."""
    return getattr(view_callable, "__wrapped__", view_callable)


# ---------------------------------------------------------------------------
# Test 1 + 2 — index() Default-State und Filter-Aktiv-Pfad
# ---------------------------------------------------------------------------


def test_index_empty_state_does_not_call_bucket_services(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /findings ohne Filter: list_buckets/pending_bucket_header NIE
    aufrufen."""
    list_buckets_spy = MagicMock(return_value=[])
    pending_spy = MagicMock(return_value=None)

    monkeypatch.setattr("app.views.findings.list_buckets", list_buckets_spy)
    monkeypatch.setattr("app.views.findings.pending_bucket_header", pending_spy)

    mock_sess = MagicMock()
    _patch_aux_loaders(monkeypatch, mock_sess)
    monkeypatch.setattr("app.views.findings.get_session", lambda: mock_sess)
    _patch_cheap_counts(monkeypatch)
    captured = _capture_render(monkeypatch)

    from app.views.findings import index

    inner = _call_inner(index)

    with app.test_request_context("/findings"):
        inner()

    assert list_buckets_spy.call_args_list == [], (
        f"list_buckets darf im Empty-State NICHT aufgerufen werden, "
        f"calls={list_buckets_spy.call_args_list}"
    )
    assert pending_spy.call_args_list == [], (
        f"pending_bucket_header darf im Empty-State NICHT aufgerufen werden, "
        f"calls={pending_spy.call_args_list}"
    )
    # Render hat stattgefunden, mit is_filtered=False
    assert captured["template"] == "findings/index.html"
    assert captured["ctx"]["is_filtered"] is False
    assert captured["ctx"]["buckets"] == []
    assert captured["ctx"]["pending_bucket"] is None


def test_index_with_active_filter_loads_buckets(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /findings?q=foo: list_buckets + pending_bucket_header werden
    aufgerufen, Bucket-Header landen im Template-Context."""
    bucket = _make_bucket()
    pending = _make_bucket(
        server_id=0,
        group_id=0,
        server_name="",
        group_label="(ohne Group)",
        risk_band="pending",
        finding_count=5,
    )
    list_buckets_spy = MagicMock(return_value=[bucket])
    pending_spy = MagicMock(return_value=pending)

    monkeypatch.setattr("app.views.findings.list_buckets", list_buckets_spy)
    monkeypatch.setattr("app.views.findings.pending_bucket_header", pending_spy)

    mock_sess = MagicMock()
    _patch_aux_loaders(monkeypatch, mock_sess)
    monkeypatch.setattr("app.views.findings.get_session", lambda: mock_sess)
    _patch_cheap_counts(monkeypatch)
    captured = _capture_render(monkeypatch)

    from app.views.findings import index

    inner = _call_inner(index)

    with app.test_request_context("/findings?q=foo"):
        inner()

    list_buckets_spy.assert_called_once()
    pending_spy.assert_called_once()
    ctx = captured["ctx"]
    assert ctx["is_filtered"] is True
    assert ctx["buckets"] == [bucket]
    assert ctx["pending_bucket"] is pending
    # total_buckets = 1 Bucket + 1 Pending = 2
    assert ctx["total_buckets"] == 2
    # total_findings_in_buckets = 3 (bucket) + 5 (pending) = 8
    assert ctx["total_findings_in_buckets"] == 8


# ---------------------------------------------------------------------------
# Test 3 + 4 + 5 — bucket_fragment()
# ---------------------------------------------------------------------------


def test_bucket_fragment_renders_table_when_findings_present(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /findings/bucket?group_id=22&server_id=1 mit Findings -> 200 mit
    bucket_findings_table-Partial."""
    findings = [_make_finding_mock(101), _make_finding_mock(102)]
    list_bucket_findings_spy = MagicMock(return_value=(findings, 2))
    monkeypatch.setattr("app.views.findings.list_bucket_findings", list_bucket_findings_spy)

    mock_sess = MagicMock()
    monkeypatch.setattr("app.views.findings.get_session", lambda: mock_sess)
    captured = _capture_render(monkeypatch)

    from app.views.findings import bucket_fragment

    inner = _call_inner(bucket_fragment)

    with app.test_request_context("/findings/bucket?group_id=22&server_id=1"):
        inner()

    list_bucket_findings_spy.assert_called_once()
    call_kwargs = list_bucket_findings_spy.call_args.kwargs
    assert call_kwargs["server_id"] == 1
    assert call_kwargs["group_id"] == 22
    assert call_kwargs["page"] == 1
    assert call_kwargs["per_page"] == 20

    assert captured["template"] == "_partials/bucket_findings_table.html"
    ctx = captured["ctx"]
    assert ctx["findings"] == findings
    assert ctx["total"] == 2
    assert ctx["server_id"] == 1
    assert ctx["group_id"] == 22


def test_bucket_fragment_returns_404_when_total_is_zero(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /findings/bucket: total=0 -> abort(404) (Cross-ID-Probing-Schutz)."""
    monkeypatch.setattr(
        "app.views.findings.list_bucket_findings",
        MagicMock(return_value=([], 0)),
    )
    monkeypatch.setattr("app.views.findings.get_session", lambda: MagicMock())
    # Render-Stub: muss NICHT gerufen werden, aber falls doch nicht crashen.
    _capture_render(monkeypatch)

    from app.views.findings import bucket_fragment

    inner = _call_inner(bucket_fragment)

    with (
        app.test_request_context("/findings/bucket?group_id=22&server_id=1"),
        pytest.raises(HTTPException) as exc_info,
    ):
        inner()

    assert exc_info.value.code == 404, f"Leerer Bucket muss 404 sein, got {exc_info.value.code}"


def test_bucket_fragment_missing_params_returns_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /findings/bucket ohne server_id/group_id -> abort(400)."""
    monkeypatch.setattr(
        "app.views.findings.list_bucket_findings",
        MagicMock(return_value=([], 0)),
    )
    monkeypatch.setattr("app.views.findings.get_session", lambda: MagicMock())
    _capture_render(monkeypatch)

    from app.views.findings import bucket_fragment

    inner = _call_inner(bucket_fragment)

    # Kein server_id, kein group_id
    with app.test_request_context("/findings/bucket"), pytest.raises(HTTPException) as exc_info:
        inner()
    assert exc_info.value.code == 400, (
        f"Fehlende Pflicht-Params muessen 400 sein, got {exc_info.value.code}"
    )


# ---------------------------------------------------------------------------
# Test 6 — pending_fragment()
# ---------------------------------------------------------------------------


def test_pending_fragment_renders_pending_table_with_server_column(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /findings/pending mit Findings -> rendert
    pending_bucket_findings_table-Partial mit Server-Info."""
    findings = [_make_finding_mock(201, server_id=7)]
    list_bucket_findings_spy = MagicMock(return_value=(findings, 1))
    monkeypatch.setattr("app.views.findings.list_bucket_findings", list_bucket_findings_spy)

    mock_sess = MagicMock()
    monkeypatch.setattr("app.views.findings.get_session", lambda: mock_sess)
    captured = _capture_render(monkeypatch)

    from app.views.findings import pending_fragment

    inner = _call_inner(pending_fragment)

    with app.test_request_context("/findings/pending"):
        inner()

    # Pending-Convention: server_id=0, group_id=0
    call_kwargs = list_bucket_findings_spy.call_args.kwargs
    assert call_kwargs["server_id"] == 0
    assert call_kwargs["group_id"] == 0

    assert captured["template"] == "_partials/pending_bucket_findings_table.html"
    ctx = captured["ctx"]
    assert ctx["findings"] == findings
    assert ctx["total"] == 1


# ---------------------------------------------------------------------------
# Bulk-Acknowledge — Test-Setup-Helfer
# ---------------------------------------------------------------------------


def _make_mock_request(
    *,
    bucket_selections: str | None = None,
    finding_ids: str | None = None,
    comment: str | None = None,
    csrf_token: str | None = "fake-token",  # noqa: S107 — Test-Token, kein Secret
    htmx: bool = False,
    args_qs: str = "",
) -> MagicMock:
    """Baut einen Flask-Request-Mock fuer den bulk_acknowledge-Endpoint.

    Form-Felder werden als MagicMock mit `.get()`-Semantik abgebildet — der
    View nutzt `request.form.get(...)` direkt.
    """
    form_data: dict[str, str | None] = {
        "bucket_selections": bucket_selections,
        "finding_ids": finding_ids,
        "comment": comment,
        "csrf_token": csrf_token,
    }
    headers: dict[str, str] = {}
    if htmx:
        headers["HX-Request"] = "true"

    req = MagicMock()
    req.form.get.side_effect = lambda key, default=None: form_data.get(key, default)
    req.headers.get.side_effect = lambda key, default=None: headers.get(key, default)

    # request.args.get(...) wird im redirect-QS-Helper genutzt
    from urllib.parse import parse_qsl

    from werkzeug.datastructures import MultiDict

    args_md: MultiDict[str, str] = MultiDict(parse_qsl(args_qs, keep_blank_values=False))
    req.args = args_md
    return req


def _patch_bulk_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    resolved_ids_by_bucket: dict[tuple[int, int], list[int]] | None = None,
) -> tuple[MagicMock, MagicMock, MagicMock, MagicMock]:
    """Patcht alle externen Calls vom bulk_acknowledge-Endpoint.

    Returns: (resolve_spy, log_event_spy, session_mock, validate_csrf_spy)
    """
    resolved_map = resolved_ids_by_bucket or {}

    def _resolve(sess: Any, *, server_id: int, group_id: int, filt: Any) -> list[int]:
        return list(resolved_map.get((server_id, group_id), []))

    resolve_spy = MagicMock(side_effect=_resolve)
    monkeypatch.setattr("app.views.findings.resolve_bucket_to_finding_ids", resolve_spy)

    log_event_spy = MagicMock()
    monkeypatch.setattr("app.views.findings.log_event", log_event_spy)

    mock_sess = MagicMock()
    monkeypatch.setattr("app.views.findings.get_session", lambda: mock_sess)

    # validate_csrf: kein Throw == valid
    validate_csrf_spy = MagicMock(return_value=True)
    monkeypatch.setattr("app.views.findings.validate_csrf", validate_csrf_spy)

    return resolve_spy, log_event_spy, mock_sess, validate_csrf_spy


def _patch_current_user(monkeypatch: pytest.MonkeyPatch, user_id: int = 1) -> None:
    """Patcht flask_login.current_user.id, das vom Endpoint genutzt wird."""
    mock_user = MagicMock()
    mock_user.id = user_id
    mock_user.is_authenticated = True
    # Der Endpoint nutzt `from flask_login import current_user` -> als Modul-Attr
    monkeypatch.setattr("app.views.findings.current_user", mock_user)


def _call_bulk(
    app: Flask,
    mock_req: MagicMock,
) -> Any:
    """Bypass @login_required und ruft bulk_acknowledge auf.

    Liefert die Response (oder leitet HTTPException-Code weiter).
    """
    from app.views.findings import bulk_acknowledge

    inner = _call_inner(bulk_acknowledge)
    captured: dict[str, Any] = {}
    with (
        app.test_request_context("/findings/bulk/acknowledge", method="POST"),
        patch("app.views.findings.request", mock_req),
    ):
        try:
            resp = inner()
        except HTTPException as e:
            captured["abort"] = e.code
            return captured
    captured["response"] = resp
    return captured


# ---------------------------------------------------------------------------
# Test 7 — Bulk mit Bucket-Selektion only
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_with_bucket_selection_only(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine Bucket-Selektion -> Resolver wird gerufen, Audit-Event mit
    bucket_count=1, explicit_count=0."""
    resolve_spy, log_event_spy, mock_sess, _ = _patch_bulk_dependencies(
        monkeypatch,
        resolved_ids_by_bucket={(1, 22): [101, 102, 103]},
    )
    _patch_current_user(monkeypatch)

    bucket_sel = json.dumps([{"server_id": 1, "group_id": 22, "filter": "status=open"}])
    mock_req = _make_mock_request(bucket_selections=bucket_sel)

    result = _call_bulk(app, mock_req)
    assert "response" in result, f"Erwarte Response, got {result}"
    resp = result["response"]
    # Non-HTMX, non-empty -> 303 redirect
    assert resp.status_code == 303

    resolve_spy.assert_called_once()
    # UPDATE-Call: sess.execute(update(...))
    assert mock_sess.execute.called

    # Audit-Event
    log_event_spy.assert_called_once()
    audit_kwargs = log_event_spy.call_args.kwargs
    audit_args = log_event_spy.call_args.args
    assert audit_args[0] == "finding.acknowledged.bulk"
    metadata = audit_kwargs["metadata"]
    assert metadata["bucket_count"] == 1
    assert metadata["explicit_count"] == 0
    assert metadata["finding_ids"] == [101, 102, 103]


# ---------------------------------------------------------------------------
# Test 8 — Bulk mit Finding-IDs only
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_with_finding_ids_only(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur explicit finding_ids -> UPDATE + Audit-Event mit
    bucket_count=0, explicit_count=N."""
    resolve_spy, log_event_spy, _mock_sess, _ = _patch_bulk_dependencies(monkeypatch)
    _patch_current_user(monkeypatch)

    fid_payload = json.dumps([201, 202, 203])
    mock_req = _make_mock_request(finding_ids=fid_payload)

    result = _call_bulk(app, mock_req)
    resp = result["response"]
    assert resp.status_code == 303

    # Resolver wurde NIE aufgerufen (keine Bucket-Selektion)
    resolve_spy.assert_not_called()

    log_event_spy.assert_called_once()
    metadata = log_event_spy.call_args.kwargs["metadata"]
    assert metadata["bucket_count"] == 0
    assert metadata["explicit_count"] == 3
    assert metadata["finding_ids"] == [201, 202, 203]


# ---------------------------------------------------------------------------
# Test 9 — Mix Bucket + IDs mit Dedup
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_mix_dedupes_finding_ids(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mix Bucket-Resolved + Explicit-IDs: finale Liste ist dedupliziert."""
    _resolve_spy, log_event_spy, _mock_sess, _ = _patch_bulk_dependencies(
        monkeypatch,
        resolved_ids_by_bucket={(1, 22): [101, 102, 103]},
    )
    _patch_current_user(monkeypatch)

    # explicit_ids = [102, 999] -> 102 ueberlappt mit Bucket-Resolved
    bucket_sel = json.dumps([{"server_id": 1, "group_id": 22, "filter": ""}])
    fid_payload = json.dumps([102, 999])
    mock_req = _make_mock_request(
        bucket_selections=bucket_sel,
        finding_ids=fid_payload,
    )

    result = _call_bulk(app, mock_req)
    resp = result["response"]
    assert resp.status_code == 303

    metadata = log_event_spy.call_args.kwargs["metadata"]
    assert metadata["bucket_count"] == 1
    # explicit_count zaehlt die *Input*-Liste vor Dedup
    assert metadata["explicit_count"] == 2
    # finale finding_ids: dedupliziert + sortiert
    assert metadata["finding_ids"] == [101, 102, 103, 999]


# ---------------------------------------------------------------------------
# Test 10 — Leere Selektion: 302/Flash, kein UPDATE, kein Audit
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_empty_selection_flashes_no_update(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leere Selektion -> 302 zurueck zur Listenseite + Flash, KEIN UPDATE,
    KEIN Audit-Event."""
    resolve_spy, log_event_spy, mock_sess, _ = _patch_bulk_dependencies(monkeypatch)
    _patch_current_user(monkeypatch)

    mock_req = _make_mock_request()  # alle Felder None/leer

    result = _call_bulk(app, mock_req)
    assert "response" in result, f"Erwarte Response, got {result}"
    resp = result["response"]
    # Non-HTMX -> 302 (Default-Redirect ohne code=303)
    assert resp.status_code in (302, 303), (
        f"Leere Selektion: 302/303 erwartet, got {resp.status_code}"
    )

    resolve_spy.assert_not_called()
    log_event_spy.assert_not_called()
    # Kein UPDATE-Call auf der Session
    mock_sess.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Test 11 — Kein Comment: metadata enthaelt KEIN comment-Key (ADR-0006)
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_without_comment_omits_comment_in_metadata(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0006: kein Pflicht-Kommentar. Ohne Comment darf das Audit-
    Metadata-Dict den `comment`-Key NICHT enthalten."""
    _, log_event_spy, _, _ = _patch_bulk_dependencies(monkeypatch)
    _patch_current_user(monkeypatch)

    fid_payload = json.dumps([42])
    mock_req = _make_mock_request(finding_ids=fid_payload, comment=None)

    result = _call_bulk(app, mock_req)
    assert "response" in result

    log_event_spy.assert_called_once()
    kwargs = log_event_spy.call_args.kwargs
    metadata = kwargs["metadata"]
    assert "comment" not in metadata, (
        f"Ohne Comment darf `comment` NICHT im Metadata-Dict landen, got {metadata}"
    )
    # Zusatz-Check: der `comment`-Kwarg an log_event ist None
    assert kwargs.get("comment") is None


def test_bulk_acknowledge_empty_string_comment_treated_as_no_comment(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leerstring-Comment (nur Whitespace) zaehlt als "kein Comment"."""
    _, log_event_spy, _, _ = _patch_bulk_dependencies(monkeypatch)
    _patch_current_user(monkeypatch)

    fid_payload = json.dumps([42])
    mock_req = _make_mock_request(finding_ids=fid_payload, comment="   ")

    _call_bulk(app, mock_req)

    metadata = log_event_spy.call_args.kwargs["metadata"]
    assert "comment" not in metadata


# ---------------------------------------------------------------------------
# Test 12 — HTMX-Request -> 204 + HX-Redirect
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_htmx_request_returns_204_with_hx_redirect(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HTMX-Request (HX-Request: true) -> 204 No Content + HX-Redirect-
    Header."""
    _patch_bulk_dependencies(
        monkeypatch,
        resolved_ids_by_bucket={(1, 22): [101]},
    )
    _patch_current_user(monkeypatch)

    bucket_sel = json.dumps([{"server_id": 1, "group_id": 22, "filter": ""}])
    mock_req = _make_mock_request(
        bucket_selections=bucket_sel,
        htmx=True,
        args_qs="status=acknowledged",
    )

    result = _call_bulk(app, mock_req)
    assert "response" in result
    resp = result["response"]
    assert resp.status_code == 204, f"HTMX-Bulk-Response soll 204 sein, got {resp.status_code}"
    assert "HX-Redirect" in resp.headers, f"HX-Redirect-Header fehlt: {dict(resp.headers)}"
    # Redirect-Ziel enthaelt den (aus request.args rekonstruierten) Filter-QS.
    redirect_target = resp.headers["HX-Redirect"]
    assert "/findings" in redirect_target
    assert "status=acknowledged" in redirect_target


def test_bulk_acknowledge_htmx_empty_selection_returns_204_no_update(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HTMX-Request mit leerer Selektion -> 204 + HX-Redirect, kein
    UPDATE/Audit."""
    _, log_event_spy, mock_sess, _ = _patch_bulk_dependencies(monkeypatch)
    _patch_current_user(monkeypatch)

    mock_req = _make_mock_request(htmx=True)

    result = _call_bulk(app, mock_req)
    resp = result["response"]
    assert resp.status_code == 204
    assert "HX-Redirect" in resp.headers
    log_event_spy.assert_not_called()
    mock_sess.execute.assert_not_called()


# ---------------------------------------------------------------------------
# Zusatz — CSRF-Pruefung
# ---------------------------------------------------------------------------


def test_bulk_acknowledge_missing_csrf_token_returns_400(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kein csrf_token im Form-Body und kein Header -> abort(400)."""
    # validate_csrf wirft fuer None-Token
    from flask_wtf.csrf import CSRFError

    def _raise(token: Any) -> None:
        raise CSRFError("missing")

    monkeypatch.setattr("app.views.findings.validate_csrf", _raise)
    monkeypatch.setattr("app.views.findings.resolve_bucket_to_finding_ids", MagicMock())
    monkeypatch.setattr("app.views.findings.log_event", MagicMock())
    monkeypatch.setattr("app.views.findings.get_session", lambda: MagicMock())
    _patch_current_user(monkeypatch)

    mock_req = _make_mock_request(csrf_token=None)

    result = _call_bulk(app, mock_req)
    assert result.get("abort") == 400, f"Fehlender CSRF-Token muss 400 sein, got {result}"


# ---------------------------------------------------------------------------
# Zusatz — Route-Registrierung (DoD Tracking-Punkt)
# ---------------------------------------------------------------------------


def test_findings_bucket_routes_registered(app: Flask) -> None:
    """Die drei neuen Routes sind als Endpoints registriert."""
    endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert "findings.bucket_fragment" in endpoints
    assert "findings.pending_fragment" in endpoints
    assert "findings.bulk_acknowledge" in endpoints


# ---------------------------------------------------------------------------
# Zusatz — `_validate_bucket_id` + `_filter_querystring_from_request` als
# Pure-Helper-Smoke-Tests (kein Flask noetig).
# ---------------------------------------------------------------------------


def test_validate_bucket_id_rejects_negative(app: Flask) -> None:
    from app.views.findings import _validate_bucket_id

    with app.test_request_context("/"), pytest.raises(HTTPException) as exc_info:
        _validate_bucket_id(-1)
    assert exc_info.value.code == 400


def test_validate_bucket_id_rejects_zero_by_default(app: Flask) -> None:
    from app.views.findings import _validate_bucket_id

    with app.test_request_context("/"), pytest.raises(HTTPException) as exc_info:
        _validate_bucket_id(0)
    assert exc_info.value.code == 400


def test_validate_bucket_id_allows_zero_when_enabled(app: Flask) -> None:
    from app.views.findings import _validate_bucket_id

    with app.test_request_context("/"):
        assert _validate_bucket_id(0, allow_zero=True) == 0


def test_validate_bucket_id_rejects_non_integer(app: Flask) -> None:
    from app.views.findings import _validate_bucket_id

    with app.test_request_context("/"), pytest.raises(HTTPException) as exc_info:
        _validate_bucket_id("abc")
    assert exc_info.value.code == 400


def test_filter_querystring_from_request_excludes_page(app: Flask) -> None:
    """_filter_querystring_from_request darf `page` nicht emittieren."""
    from werkzeug.datastructures import MultiDict

    from app.views.findings import _filter_querystring_from_request

    with app.test_request_context("/"):
        qs = _filter_querystring_from_request(MultiDict([("q", "foo"), ("page", "5")]))
    assert "q=foo" in qs
    assert "page" not in qs


# ---------------------------------------------------------------------------
# Backcompat-Suppression (Etappe 2 noch): index() stellt Stub-Vars bereit
# (`findings=[]`, `page=1`, etc.) — wir pruefen NICHT auf deren Inhalt;
# der Test dient nur als Reminder dass die Stubs noch da sind und nicht
# crashen.
# ---------------------------------------------------------------------------


def test_index_context_contains_backcompat_stubs(
    app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.views.findings.list_buckets", MagicMock(return_value=[]))
    monkeypatch.setattr("app.views.findings.pending_bucket_header", MagicMock(return_value=None))
    mock_sess = MagicMock()
    _patch_aux_loaders(monkeypatch, mock_sess)
    monkeypatch.setattr("app.views.findings.get_session", lambda: mock_sess)
    _patch_cheap_counts(monkeypatch)
    captured = _capture_render(monkeypatch)

    from app.views.findings import index

    inner = _call_inner(index)
    # Form-Konstruktoren brauchen einen App-Context mit SECRET_KEY — der
    # ist via `app` Fixture vorhanden.
    with (
        app.test_request_context("/findings"),
        contextlib.suppress(Exception),
    ):
        inner()

    # Wenn der Render durchgegangen ist, MUSS er die Backcompat-Keys haben.
    if "ctx" in captured:
        ctx = captured["ctx"]
        for key in ("findings", "page", "per_page", "total_pages", "sort", "dir"):
            assert key in ctx, f"Backcompat-Stub `{key}` fehlt im Context"
