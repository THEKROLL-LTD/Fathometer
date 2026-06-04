"""Pure-Unit-Tests fuer `app/views/server_settings.py` (Block X, Phase B, ADR-0038).

Deckt:
  1. GET-Show-Tests  (Tests 1-7):  Render Vollseite + HX-Fragment, 404-Faelle,
     Pre-Selection der aktuellen Group.
  2. POST-Tag-Tests  (Tests 8-14): add_tag / remove_tag, Idempotenz, Audit.
  3. POST-Group-Tests (Tests 15-18): update_group, No-Op, NULL-Set, Whitelist.
  4. POST-Scan-Interval-Tests (Tests 19-22): update_scan_interval, Range-Check.
  5. Detail-View-Header-Tests (Tests 23-25): Template-Source-Checks.
  6. Form-Class-Unit-Tests (Tests 26-27): ServerGroupForm + ServerScanIntervalForm.

Render-Strategie:
  - View-Handler werden via `func.__wrapped__` direkt aufgerufen (umgeht
    `@login_required` ohne Auth-Bypass-Mock), analog dem `__wrapped__`-Pattern
    aus `test_sidebar_batch.py`.
  - `_load_server_with_settings`, `_all_tags`, `_all_groups` und `get_session`
    werden per `monkeypatch.setattr` gestubbt — kein echter DB-Zugriff.
  - `log_event` wird per `monkeypatch.setattr` gemockt, damit Audit-Calls
    ohne ORM-Session verifiziert werden koennen.
  - Template-Source-Checks (Tests 23-25) lesen die Template-Datei direkt
    ohne Flask-Rendering - keine DB, kein Auth.
  - Form-Tests (26-27) instantiieren direkt im App-Context.

Alle Tests sind reine Pure-Unit-Tests (kein DB_integration-Marker).
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from werkzeug.datastructures import ImmutableMultiDict

# ---------------------------------------------------------------------------
# Template-Pfade
# ---------------------------------------------------------------------------

_DETAIL_TEMPLATE_PATH = (
    Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"
)

# ---------------------------------------------------------------------------
# Helpers — Mock-Objekte
# ---------------------------------------------------------------------------


def _make_tag(*, id: int = 1, name: str = "prod", color: str = "#6b7280") -> types.SimpleNamespace:
    """Erstellt ein minimales Tag-Mock-Objekt."""
    return types.SimpleNamespace(id=id, name=name, color=color)


def _make_server_tag(*, server_id: int = 42, tag: types.SimpleNamespace) -> types.SimpleNamespace:
    """Erstellt ein minimales ServerTag-Mock-Objekt."""
    return types.SimpleNamespace(server_id=server_id, tag_id=tag.id, tag=tag)


def _make_group(*, id: int = 1, name: str = "prod-group") -> types.SimpleNamespace:
    """Erstellt ein minimales ServerGroup-Mock-Objekt."""
    return types.SimpleNamespace(id=id, name=name)


def _make_server(
    *,
    id: int = 42,
    name: str = "test-host.example.com",
    group_id: int | None = None,
    expected_scan_interval_h: int = 24,
    revoked_at: Any = None,
    retired_at: Any = None,
    tag_links: list | None = None,
    group: Any = None,
) -> types.SimpleNamespace:
    """Erstellt ein minimales Server-Mock-Objekt fuer Settings-Tests."""
    return types.SimpleNamespace(
        id=id,
        name=name,
        group_id=group_id,
        expected_scan_interval_h=expected_scan_interval_h,
        revoked_at=revoked_at,
        retired_at=retired_at,
        tag_links=tag_links if tag_links is not None else [],
        group=group,
    )


def _make_mock_session() -> MagicMock:
    """Erstellt eine minimale Mock-Session (kein echter DB-Zugriff)."""
    sess = MagicMock()
    sess.execute.return_value.scalar_one_or_none.return_value = None
    return sess


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
# Render-Helper: ruft show.__wrapped__ mit gemockten Dependencies auf.
# ---------------------------------------------------------------------------


def _call_show(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    *,
    server_id: int = 42,
    server: Any,
    tags: list | None = None,
    groups: list | None = None,
    hx_request: bool = False,
) -> Any:
    """Ruft den show-Handler via __wrapped__ auf und gibt die Response zurueck.

    Stubbiert DB-Zugriffe; rendert das Template via echtem Flask-Jinja.
    """
    from app.views.server_settings import show

    inner = getattr(show, "__wrapped__", show)
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings._all_tags", lambda: tags or [])
    monkeypatch.setattr("app.views.server_settings._all_groups", lambda: groups or [])

    headers: dict[str, str] = {}
    if hx_request:
        headers["HX-Request"] = "true"

    with app.test_request_context(
        f"/servers/{server_id}/settings/",
        headers=headers,
    ):
        return inner(server_id=server_id)


# ===========================================================================
# 1. test_show_renders_full_page_for_existing_server
# ===========================================================================


def test_show_renders_full_page_for_existing_server(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /servers/<id>/settings/ — normaler Request ohne HX-Header rendert Vollseite.

    Erwartet 200 und settings-section-Marker im Output.
    Kein <html>-Body-Test wegen Template-Inheritance (base_app.html braucht
    kein echtes Layout um den detail_pane-Block zu rendern — gerendert wird
    nur der `detail_pane`-Block; der Vollseiten-Marker ist der settings-Section-Tag).
    """
    server = _make_server(id=42)
    result = _call_show(no_csrf_app, monkeypatch, server=server, hx_request=False)
    # show() gibt einen String (render_template) zurueck
    assert isinstance(result, str), f"show() muss einen String zurueckgeben, got: {type(result)}"
    assert 'data-test="settings-section-tags"' in result, (
        f"settings-section-tags fehlt im Output. Output-Anfang: {result[:500]!r}"
    )


# ===========================================================================
# 2. test_show_renders_hx_fragment_when_hx_request
# ===========================================================================


def test_show_renders_hx_fragment_when_hx_request(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET mit HX-Request: true -> kein <html>/<body>-Markup (Fragment-Pfad).

    _render_settings setzt hx_partial=True -> Template extends _partial_shell.html.
    Kein <html>-Block bedeutet: der Output enthaelt kein '<!DOCTYPE html>'.
    """
    server = _make_server(id=42)
    result = _call_show(no_csrf_app, monkeypatch, server=server, hx_request=True)
    assert isinstance(result, str), f"show() muss einen String zurueckgeben, got: {type(result)}"
    assert "<!DOCTYPE html>" not in result, (
        f"HX-Request darf kein vollstaendiges HTML-Dokument liefern. "
        f"Output-Anfang: {result[:400]!r}"
    )
    assert 'data-test="settings-section-tags"' in result, (
        f"settings-section-tags fehlt im HX-Fragment. Output-Anfang: {result[:500]!r}"
    )


# ===========================================================================
# 3. test_show_404_when_server_does_not_exist
# ===========================================================================


def test_show_404_when_server_does_not_exist(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_load_server_with_settings gibt None -> show() wirft 404.

    Simuliert eine fehlende Server-ID in der DB.
    """
    from werkzeug.exceptions import NotFound

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: None)
    monkeypatch.setattr("app.views.server_settings._all_tags", list)
    monkeypatch.setattr("app.views.server_settings._all_groups", list)

    from app.views.server_settings import show

    inner = getattr(show, "__wrapped__", show)
    with no_csrf_app.test_request_context("/servers/9999/settings/"), pytest.raises(NotFound):
        inner(server_id=9999)


# ===========================================================================
# 4. test_show_404_when_server_revoked
# ===========================================================================


def test_show_404_when_server_revoked(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit revoked_at gesetzt -> show() wirft 404."""
    from datetime import UTC, datetime

    from werkzeug.exceptions import NotFound

    server = _make_server(id=42, revoked_at=datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import show

    inner = getattr(show, "__wrapped__", show)
    with no_csrf_app.test_request_context("/servers/42/settings/"), pytest.raises(NotFound):
        inner(server_id=42)


# ===========================================================================
# 5. test_show_404_when_server_retired
# ===========================================================================


def test_show_404_when_server_retired(no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server mit retired_at gesetzt -> show() wirft 404."""
    from datetime import UTC, datetime

    from werkzeug.exceptions import NotFound

    server = _make_server(id=42, retired_at=datetime(2026, 2, 1, tzinfo=UTC))
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import show

    inner = getattr(show, "__wrapped__", show)
    with no_csrf_app.test_request_context("/servers/42/settings/"), pytest.raises(NotFound):
        inner(server_id=42)


# ===========================================================================
# 6. test_show_preselects_current_group_in_form
# ===========================================================================


def test_show_preselects_current_group_in_form(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Server mit group_id=1 -> rendered Output enthaelt selected-Option fuer ID 1.

    Regression-Test: _render_settings setzt
      `ServerGroupForm(data={"group_id": str(server.group_id) ...})`
    damit die aktuell zugewiesene Group im Select vorgewaehlt ist.
    """
    group = _make_group(id=1, name="prod-group")
    server = _make_server(id=42, group_id=1)
    result = _call_show(no_csrf_app, monkeypatch, server=server, groups=[group], hx_request=False)
    # WTForms rendert 'selected' oder 'selected=""' fuer die aktive Option.
    assert 'value="1"' in result, (
        f"Option value='1' fehlt im gerendertem Output. Output-Anfang: {result[:600]!r}"
    )
    assert "selected" in result, (
        f"'selected'-Attribut fehlt — group_id=1 sollte vorgewaehlt sein. "
        f"Output-Anfang: {result[:600]!r}"
    )


# ===========================================================================
# 7. test_show_preselects_none_when_server_has_no_group
# ===========================================================================


def test_show_preselects_none_when_server_has_no_group(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Server mit group_id=None -> 'none'-Option ist selected.

    _render_settings setzt group_initial='none' wenn server.group_id is None.
    """
    server = _make_server(id=42, group_id=None)
    result = _call_show(no_csrf_app, monkeypatch, server=server, groups=[], hx_request=False)
    assert 'value="none"' in result, (
        f"Option value='none' fehlt im gerendertem Output. Output-Anfang: {result[:600]!r}"
    )
    assert "selected" in result, (
        f"'selected'-Attribut fehlt — keine Gruppe sollte 'none' vorgewaehlt haben. "
        f"Output-Anfang: {result[:600]!r}"
    )


# ===========================================================================
# 8. test_add_tag_valid_redirects_to_settings
# ===========================================================================


def test_add_tag_valid_redirects_to_settings(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /tags/add mit gueltigem tag_name -> Redirect zu server_settings.show.

    Audit-Event 'server.tag.added' wird aufgerufen.
    """
    tag = _make_tag(id=5, name="production")
    server = _make_server(id=42, tag_links=[])

    mock_sess = _make_mock_session()
    # existing ServerTag = None (noch nicht vorhanden)
    mock_sess.execute.return_value.scalar_one_or_none.return_value = None
    tag_result = MagicMock()
    tag_result.scalar_one_or_none.return_value = tag
    # Erster execute: Tag-Lookup; zweiter: existing-Check
    mock_sess.execute.side_effect = [tag_result, MagicMock(scalar_one_or_none=lambda: None)]

    log_event_calls: list[dict] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append({"action": action, **kwargs})
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import add_tag

    inner = getattr(add_tag, "__wrapped__", add_tag)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/tags/add",
        method="POST",
        data={"tag_name": "production"},
    ):
        resp = inner(server_id=42)

    # Redirect zurueck zu den Settings
    assert resp.status_code == 302, f"add_tag soll 302 zurueckgeben, got {resp.status_code}"
    assert "settings" in resp.location or "42" in resp.location, (
        f"Redirect-Location soll auf Settings zeigen: {resp.location!r}"
    )

    # Audit-Event muss gefeuert haben
    assert any(c["action"] == "server.tag.added" for c in log_event_calls), (
        f"Audit-Event 'server.tag.added' wurde nicht ausgeloest. Calls: {log_event_calls}"
    )


# ===========================================================================
# 9. test_add_tag_invalid_tag_name_flashes_and_redirects
# ===========================================================================


def test_add_tag_invalid_tag_name_flashes_and_redirects(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST mit ungueltigem tag_name -> Flash-Message + Redirect zu Settings."""
    server = _make_server(id=42)
    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)

    from app.views.server_settings import add_tag

    inner = getattr(add_tag, "__wrapped__", add_tag)

    captured_flashes: list[tuple[str, str]] = []

    def fake_flash(msg: str, category: str = "message") -> None:
        captured_flashes.append((msg, category))

    monkeypatch.setattr("app.views.server_settings.flash", fake_flash)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: _make_mock_session())

    # Ungueltiger Name: enthaelt Grossbuchstaben (TAG_NAME_REGEX: ^[a-z0-9][a-z0-9._\-]{0,31}$)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/tags/add",
        method="POST",
        data={"tag_name": "INVALID TAG!"},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, (
        f"add_tag soll 302 liefern bei ungueltigem Namen, got {resp.status_code}"
    )
    assert any("Ungueltiger Tag-Name" in msg for msg, _ in captured_flashes), (
        f"Flash-Message 'Ungueltiger Tag-Name' erwartet. Flashes: {captured_flashes}"
    )


# ===========================================================================
# 10. test_add_tag_nonexistent_tag_flashes
# ===========================================================================


def test_add_tag_nonexistent_tag_flashes(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tag existiert nicht in DB -> Flash 'existiert nicht' + Redirect."""
    server = _make_server(id=42)
    mock_sess = _make_mock_session()
    # Tag-Lookup liefert None
    mock_sess.execute.return_value.scalar_one_or_none.return_value = None

    captured_flashes: list[tuple[str, str]] = []

    def fake_flash(msg: str, category: str = "message") -> None:
        captured_flashes.append((msg, category))

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.flash", fake_flash)

    from app.views.server_settings import add_tag

    inner = getattr(add_tag, "__wrapped__", add_tag)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/tags/add",
        method="POST",
        data={"tag_name": "nonexistent"},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, f"add_tag soll 302 liefern, got {resp.status_code}"
    assert any("existiert nicht" in msg for msg, _ in captured_flashes), (
        f"Flash 'existiert nicht' erwartet. Flashes: {captured_flashes}"
    )


# ===========================================================================
# 11. test_add_tag_idempotent_when_already_present
# ===========================================================================


def test_add_tag_idempotent_when_already_present(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tag ist bereits am Server -> kein Doppeleintrag, kein Crash, kein Audit-Event."""
    tag = _make_tag(id=5, name="production")
    existing_link = _make_server_tag(server_id=42, tag=tag)
    server = _make_server(id=42, tag_links=[existing_link])

    mock_sess = _make_mock_session()
    tag_result = MagicMock()
    tag_result.scalar_one_or_none.return_value = tag
    existing_result = MagicMock()
    existing_result.scalar_one_or_none.return_value = existing_link
    mock_sess.execute.side_effect = [tag_result, existing_result]

    log_event_calls: list[str] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append(action)
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import add_tag

    inner = getattr(add_tag, "__wrapped__", add_tag)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/tags/add",
        method="POST",
        data={"tag_name": "production"},
    ):
        resp = inner(server_id=42)

    # Idempotent: kein Crash, Redirect
    assert resp.status_code == 302, f"Idempotentes add_tag soll 302 liefern, got {resp.status_code}"
    # Kein Audit-Event wenn Tag schon vorhanden
    assert "server.tag.added" not in log_event_calls, (
        f"Kein Audit-Event darf bei Idempotenz ausgeloest werden. Calls: {log_event_calls}"
    )
    # sess.add darf nicht aufgerufen worden sein
    mock_sess.add.assert_not_called()


# ===========================================================================
# 12. test_add_tag_csrf_disabled_form_validates
# ===========================================================================


def test_add_tag_csrf_disabled_form_validates(
    no_csrf_app: Flask,
) -> None:
    """CSRFOnlyForm.validate_on_submit() gibt True zurueck wenn CSRF disabled ist.

    Prueft: bei WTF_CSRF_ENABLED=False wird das CSRF-Feld ignoriert und die Form
    validiert erfolgreich. Das ist der Test-App-Normalzustand.
    """
    from flask_wtf import FlaskForm

    with no_csrf_app.test_request_context(
        "/test",
        method="POST",
        data={},
    ):
        form = FlaskForm()
        # validate_on_submit() -> True weil CSRF disabled und Method=POST
        result = form.validate_on_submit()
    assert result is True, (
        "CSRFOnlyForm.validate_on_submit() soll True zurueckgeben wenn "
        f"WTF_CSRF_ENABLED=False und Method=POST. Ergebnis: {result}"
    )


# ===========================================================================
# 13. test_remove_tag_deletes_link_and_audits
# ===========================================================================


def test_remove_tag_deletes_link_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /tags/<tag_id>/remove -> ServerTag-Link wird geloescht + Audit-Event."""
    tag = _make_tag(id=5, name="old-tag")
    link = _make_server_tag(server_id=42, tag=tag)
    server = _make_server(id=42, tag_links=[link])

    mock_sess = _make_mock_session()
    link_result = MagicMock()
    link_result.scalar_one_or_none.return_value = link
    mock_sess.execute.return_value = link_result

    log_event_calls: list[dict] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append({"action": action, **kwargs})
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import remove_tag

    inner = getattr(remove_tag, "__wrapped__", remove_tag)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/tags/5/remove",
        method="POST",
    ):
        resp = inner(server_id=42, tag_id=5)

    assert resp.status_code == 302, f"remove_tag soll 302 zurueckgeben, got {resp.status_code}"
    # Link muss geloescht worden sein
    mock_sess.delete.assert_called_once_with(link)
    # Audit-Event
    assert any(c["action"] == "server.tag.removed" for c in log_event_calls), (
        f"Audit-Event 'server.tag.removed' fehlt. Calls: {log_event_calls}"
    )
    # Metadata pruefe
    audit_call = next(c for c in log_event_calls if c["action"] == "server.tag.removed")
    assert audit_call.get("metadata", {}).get("tag_id") == 5, (
        f"tag_id=5 fehlt in Audit-Metadata. Metadata: {audit_call.get('metadata')}"
    )
    assert audit_call.get("metadata", {}).get("tag_name") == "old-tag", (
        f"tag_name='old-tag' fehlt in Audit-Metadata. Metadata: {audit_call.get('metadata')}"
    )


# ===========================================================================
# 14. test_remove_tag_idempotent_when_not_present
# ===========================================================================


def test_remove_tag_idempotent_when_not_present(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tag ist nicht am Server -> kein Crash, kein Audit-Event."""
    server = _make_server(id=42, tag_links=[])

    mock_sess = _make_mock_session()
    not_found_result = MagicMock()
    not_found_result.scalar_one_or_none.return_value = None
    mock_sess.execute.return_value = not_found_result

    log_event_calls: list[str] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append(action)
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import remove_tag

    inner = getattr(remove_tag, "__wrapped__", remove_tag)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/tags/999/remove",
        method="POST",
    ):
        resp = inner(server_id=42, tag_id=999)

    assert resp.status_code == 302, (
        f"remove_tag (idempotent) soll 302 liefern, got {resp.status_code}"
    )
    mock_sess.delete.assert_not_called()
    assert "server.tag.removed" not in log_event_calls, (
        f"Kein Audit-Event bei nicht-vorhandenem Link. Calls: {log_event_calls}"
    )


# ===========================================================================
# 15. test_update_group_sets_group_id_and_audits
# ===========================================================================


def test_update_group_sets_group_id_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /group mit group_id=1 -> server.group_id=1, Audit 'server.group_changed'."""
    group = _make_group(id=1, name="prod-group")
    server = _make_server(id=42, group_id=None)

    mock_sess = _make_mock_session()
    groups_result = MagicMock()
    groups_result.scalars.return_value.all.return_value = [group]
    mock_sess.execute.return_value = groups_result

    log_event_calls: list[dict] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append({"action": action, **kwargs})
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import update_group

    inner = getattr(update_group, "__wrapped__", update_group)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/group",
        method="POST",
        data={"group_id": "1"},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, f"update_group soll 302 zurueckgeben, got {resp.status_code}"
    assert server.group_id == 1, f"server.group_id soll 1 sein, ist aber: {server.group_id}"
    assert any(c["action"] == "server.group_changed" for c in log_event_calls), (
        f"Audit-Event 'server.group_changed' fehlt. Calls: {log_event_calls}"
    )
    audit_call = next(c for c in log_event_calls if c["action"] == "server.group_changed")
    assert audit_call.get("metadata", {}).get("from") is None, (
        f"metadata.from soll None sein (vorher kein Group), got: {audit_call.get('metadata')}"
    )
    assert audit_call.get("metadata", {}).get("to") == 1, (
        f"metadata.to soll 1 sein, got: {audit_call.get('metadata')}"
    )


# ===========================================================================
# 16. test_update_group_sets_null_when_choice_is_none
# ===========================================================================


def test_update_group_sets_null_when_choice_is_none(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /group mit group_id=none -> server.group_id=None."""
    group = _make_group(id=1, name="prod-group")
    server = _make_server(id=42, group_id=1)

    mock_sess = _make_mock_session()
    groups_result = MagicMock()
    groups_result.scalars.return_value.all.return_value = [group]
    mock_sess.execute.return_value = groups_result

    log_event_calls: list[dict] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append({"action": action, **kwargs})
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import update_group

    inner = getattr(update_group, "__wrapped__", update_group)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/group",
        method="POST",
        data={"group_id": "none"},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, f"update_group soll 302 zurueckgeben, got {resp.status_code}"
    assert server.group_id is None, (
        f"server.group_id soll None sein nach 'none'-Auswahl, ist: {server.group_id}"
    )
    # Audit-Event weil Wert sich geaendert hat (1 -> None)
    assert any(c["action"] == "server.group_changed" for c in log_event_calls), (
        f"Audit-Event 'server.group_changed' fehlt bei NULL-Set. Calls: {log_event_calls}"
    )


# ===========================================================================
# 17. test_update_group_no_op_when_same_value
# ===========================================================================


def test_update_group_no_op_when_same_value(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /group mit unveraendertem group_id -> kein Audit-Event, kein DB-Touch."""
    group = _make_group(id=1, name="prod-group")
    server = _make_server(id=42, group_id=1)

    mock_sess = _make_mock_session()
    groups_result = MagicMock()
    groups_result.scalars.return_value.all.return_value = [group]
    mock_sess.execute.return_value = groups_result

    log_event_calls: list[str] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append(action)
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import update_group

    inner = getattr(update_group, "__wrapped__", update_group)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/group",
        method="POST",
        data={"group_id": "1"},  # Gleicher Wert wie server.group_id
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, f"update_group No-Op soll 302 liefern, got {resp.status_code}"
    assert "server.group_changed" not in log_event_calls, (
        f"Kein Audit-Event bei No-Op erwartet. Calls: {log_event_calls}"
    )
    mock_sess.commit.assert_not_called()


# ===========================================================================
# 18. test_update_group_rejects_nonexistent_group_id
# ===========================================================================


def test_update_group_rejects_nonexistent_group_id(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /group mit group_id=9999 (nicht vorhanden) -> Flash + kein Audit-Event."""
    group = _make_group(id=1, name="prod-group")
    server = _make_server(id=42, group_id=None)
    original_group_id = server.group_id

    mock_sess = _make_mock_session()
    groups_result = MagicMock()
    groups_result.scalars.return_value.all.return_value = [group]  # Nur ID 1 vorhanden
    mock_sess.execute.return_value = groups_result

    captured_flashes: list[tuple[str, str]] = []

    def fake_flash(msg: str, category: str = "message") -> None:
        captured_flashes.append((msg, category))

    log_event_calls: list[str] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append(action)
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.flash", fake_flash)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import update_group

    inner = getattr(update_group, "__wrapped__", update_group)

    # ID 9999 ist nicht in available (nur ID 1) -> Whitelist-Reject im View
    # Allerdings faellt WTForms die form.validate_on_submit() zuerst:
    # group_id=9999 ist nicht in choices -> Form-Validation schlaegt fehl.
    # Erwartung: Flash + Redirect, kein group_id-Update.
    with no_csrf_app.test_request_context(
        "/servers/42/settings/group",
        method="POST",
        data={"group_id": "9999"},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, (
        f"update_group soll 302 bei ungueltiger group_id liefern, got {resp.status_code}"
    )
    # group_id darf sich nicht geaendert haben
    assert server.group_id == original_group_id, (
        f"server.group_id soll unveraendert sein ({original_group_id}), ist aber: {server.group_id}"
    )
    # Kein Audit-Event
    assert "server.group_changed" not in log_event_calls, (
        f"Kein Audit-Event bei ungueltigem group_id. Calls: {log_event_calls}"
    )
    # Flash-Message erwartet (entweder von Form-Validation oder Whitelist)
    assert len(captured_flashes) > 0, (
        "Flash-Message erwartet bei ungueltigem group_id. Keine Flashes registriert."
    )


# ===========================================================================
# 19. test_update_scan_interval_sets_value_and_audits
# ===========================================================================


def test_update_scan_interval_sets_value_and_audits(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /scan-interval mit scan_interval_h=48 -> server.expected_scan_interval_h=48.

    Audit-Event 'server.scan_interval_changed' mit from/to-Metadata.
    """
    server = _make_server(id=42, expected_scan_interval_h=24)
    mock_sess = _make_mock_session()

    log_event_calls: list[dict] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append({"action": action, **kwargs})
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import update_scan_interval

    inner = getattr(update_scan_interval, "__wrapped__", update_scan_interval)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/scan-interval",
        method="POST",
        data={"scan_interval_h": "48"},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, (
        f"update_scan_interval soll 302 zurueckgeben, got {resp.status_code}"
    )
    assert server.expected_scan_interval_h == 48, (
        f"server.expected_scan_interval_h soll 48 sein, ist: {server.expected_scan_interval_h}"
    )
    assert any(c["action"] == "server.scan_interval_changed" for c in log_event_calls), (
        f"Audit-Event 'server.scan_interval_changed' fehlt. Calls: {log_event_calls}"
    )
    audit_call = next(c for c in log_event_calls if c["action"] == "server.scan_interval_changed")
    assert audit_call.get("metadata", {}).get("from") == 24, (
        f"metadata.from soll 24 sein, got: {audit_call.get('metadata')}"
    )
    assert audit_call.get("metadata", {}).get("to") == 48, (
        f"metadata.to soll 48 sein, got: {audit_call.get('metadata')}"
    )


# ===========================================================================
# 20. test_update_scan_interval_no_op_when_same_value
# ===========================================================================


def test_update_scan_interval_no_op_when_same_value(
    no_csrf_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POST /scan-interval mit gleichem Wert -> kein Audit-Event."""
    server = _make_server(id=42, expected_scan_interval_h=24)
    mock_sess = _make_mock_session()

    log_event_calls: list[str] = []

    def fake_log_event(action: str, **kwargs: Any) -> Any:
        log_event_calls.append(action)
        return MagicMock()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.log_event", fake_log_event)

    from app.views.server_settings import update_scan_interval

    inner = getattr(update_scan_interval, "__wrapped__", update_scan_interval)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/scan-interval",
        method="POST",
        data={"scan_interval_h": "24"},  # Gleicher Wert
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, (
        f"update_scan_interval No-Op soll 302 liefern, got {resp.status_code}"
    )
    assert "server.scan_interval_changed" not in log_event_calls, (
        f"Kein Audit-Event bei No-Op erwartet. Calls: {log_event_calls}"
    )
    mock_sess.commit.assert_not_called()


# ===========================================================================
# 21. test_update_scan_interval_rejects_out_of_range
# ===========================================================================


@pytest.mark.parametrize(
    "bad_value",
    ["0", "169", "-5", "200"],
    ids=["zero", "above_max", "negative", "way_above_max"],
)
def test_update_scan_interval_rejects_out_of_range(
    no_csrf_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    bad_value: str,
) -> None:
    """POST /scan-interval mit Out-of-Range-Wert -> Flash + kein DB-Update."""
    server = _make_server(id=42, expected_scan_interval_h=24)
    original_interval = server.expected_scan_interval_h

    captured_flashes: list[tuple[str, str]] = []

    def fake_flash(msg: str, category: str = "message") -> None:
        captured_flashes.append((msg, category))

    mock_sess = _make_mock_session()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.flash", fake_flash)

    from app.views.server_settings import update_scan_interval

    inner = getattr(update_scan_interval, "__wrapped__", update_scan_interval)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/scan-interval",
        method="POST",
        data={"scan_interval_h": bad_value},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, (
        f"update_scan_interval soll 302 liefern bei bad_value={bad_value}, got {resp.status_code}"
    )
    assert server.expected_scan_interval_h == original_interval, (
        f"expected_scan_interval_h soll unveraendert bleiben ({original_interval}) "
        f"bei bad_value={bad_value}, ist: {server.expected_scan_interval_h}"
    )
    assert len(captured_flashes) > 0, (
        f"Flash-Message erwartet bei bad_value={bad_value}. Keine Flashes registriert."
    )


# ===========================================================================
# 22. test_update_scan_interval_rejects_non_integer
# ===========================================================================


@pytest.mark.parametrize(
    "bad_value",
    ["abc", "", "12.5", "null"],
    ids=["letters", "empty", "float", "null_string"],
)
def test_update_scan_interval_rejects_non_integer(
    no_csrf_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    bad_value: str,
) -> None:
    """POST /scan-interval mit nicht-integer Wert -> Flash + kein DB-Update."""
    server = _make_server(id=42, expected_scan_interval_h=24)
    original_interval = server.expected_scan_interval_h

    captured_flashes: list[tuple[str, str]] = []

    def fake_flash(msg: str, category: str = "message") -> None:
        captured_flashes.append((msg, category))

    mock_sess = _make_mock_session()

    monkeypatch.setattr("app.views.server_settings._load_server_with_settings", lambda sid: server)
    monkeypatch.setattr("app.views.server_settings.get_session", lambda: mock_sess)
    monkeypatch.setattr("app.views.server_settings.flash", fake_flash)

    from app.views.server_settings import update_scan_interval

    inner = getattr(update_scan_interval, "__wrapped__", update_scan_interval)
    with no_csrf_app.test_request_context(
        "/servers/42/settings/scan-interval",
        method="POST",
        data={"scan_interval_h": bad_value} if bad_value else {},
    ):
        resp = inner(server_id=42)

    assert resp.status_code == 302, (
        f"update_scan_interval soll 302 liefern bei bad_value={bad_value!r}, got {resp.status_code}"
    )
    assert server.expected_scan_interval_h == original_interval, (
        f"expected_scan_interval_h soll unveraendert bleiben bei bad_value={bad_value!r}, "
        f"ist: {server.expected_scan_interval_h}"
    )


# ===========================================================================
# 23. test_detail_view_no_longer_renders_hashtag_zeile
# ===========================================================================


def test_detail_view_no_longer_renders_hashtag_zeile() -> None:
    """detail.html enthaelt keine Hashtag-Zeile mehr (Phase B Task B6).

    Prueft den Template-Source auf Abwesenheit der alten Hashtag-Markup-Pattern.
    """
    source = _DETAIL_TEMPLATE_PATH.read_text(encoding="utf-8")

    # Altes Hashtag-Render-Pattern: '#{{ link.tag.name }}'
    assert "#{{ link.tag.name }}" not in source, (
        "Hashtag-Pattern '#{{ link.tag.name }}' ist noch in detail.html. "
        "Phase B (ADR-0038) soll es entfernt haben. "
        f"Template-Pfad: {_DETAIL_TEMPLATE_PATH}"
    )

    # Klassen-String der Hashtag-<p>-Zeile (spezifisch genug fuer Eindeutigkeit)
    hashtag_classes = "font-mono text-xs mt-2 flex flex-wrap gap-x-3 gap-y-1"
    assert hashtag_classes not in source, (
        f"Hashtag-<p>-Klassen '{hashtag_classes}' sind noch in detail.html. "
        "Phase B soll die Hashtag-Zeile ersatzlos entfernt haben. "
        f"Template-Pfad: {_DETAIL_TEMPLATE_PATH}"
    )


# ===========================================================================
# 24. test_detail_view_no_longer_renders_tag_editor_accordion
# ===========================================================================


def test_detail_view_no_longer_renders_tag_editor_accordion() -> None:
    """detail.html enthaelt kein Tag-Editor-Akkordeon mehr (Phase B Task B6).

    Prueft auf Abwesenheit von:
    - '#tag-editor-body' ID
    - 'tagEditorOpen' Alpine-State
    """
    source = _DETAIL_TEMPLATE_PATH.read_text(encoding="utf-8")

    assert "tag-editor-body" not in source, (
        "'tag-editor-body' ID ist noch in detail.html. "
        "Das Tag-Editor-Akkordeon soll in Phase B entfernt worden sein. "
        f"Template-Pfad: {_DETAIL_TEMPLATE_PATH}"
    )

    assert "tagEditorOpen" not in source, (
        "'tagEditorOpen' Alpine-State ist noch in detail.html. "
        "Das Akkordeon-Alpine-State soll in Phase B entfernt worden sein. "
        f"Template-Pfad: {_DETAIL_TEMPLATE_PATH}"
    )


# ===========================================================================
# 25. test_detail_view_renders_settings_gear_link
# ===========================================================================


def test_detail_view_renders_settings_gear_link() -> None:
    """detail.html enthaelt Zahnrad-Settings-Button mit data-test und url_for (Phase B).

    Positiv-Checks:
    - 'data-test="server-settings-link"' ist im Template-Source vorhanden.
    - 'server_settings.show' url_for-Aufruf ist im Source vorhanden.
    """
    source = _DETAIL_TEMPLATE_PATH.read_text(encoding="utf-8")

    assert 'data-test="server-settings-link"' in source, (
        "'data-test=\"server-settings-link\"' fehlt in detail.html. "
        "Phase B soll den Zahnrad-Button mit diesem Attribut eingefuegt haben. "
        f"Template-Pfad: {_DETAIL_TEMPLATE_PATH}"
    )

    assert "server_settings.show" in source, (
        "'server_settings.show' fehlt in detail.html. "
        "Der Zahnrad-Button muss via url_for auf die Settings-Sub-View zeigen. "
        f"Template-Pfad: {_DETAIL_TEMPLATE_PATH}"
    )


# ===========================================================================
# 26. test_server_group_form_choices_built_from_available_groups
# ===========================================================================


def test_server_group_form_choices_built_from_available_groups(no_csrf_app: Flask) -> None:
    """ServerGroupForm.choices werden aus available_groups korrekt aufgebaut.

    Erwartet: [("none", "— keine —"), ("1", "prod"), ("2", "dev")].
    Coerce-Lambda: '1' -> 1, 'none' -> None.
    """
    from app.forms import ServerGroupForm

    group_prod = _make_group(id=1, name="prod")
    group_dev = _make_group(id=2, name="dev")

    with no_csrf_app.test_request_context("/"):
        form = ServerGroupForm(
            available_groups=[group_prod, group_dev],
            formdata=ImmutableMultiDict(),  # Leeres Formdata -> kein Request-Input
        )

    choices = form.group_id.choices
    assert choices is not None, "ServerGroupForm.group_id.choices darf nicht None sein"

    assert choices[0] == ("none", "— none —"), (
        f"Erste Choice soll ('none', '— none —') sein, ist: {choices[0]}"
    )
    assert ("1", "prod") in choices, f"('1', 'prod') soll in choices sein. Choices: {choices}"
    assert ("2", "dev") in choices, f"('2', 'dev') soll in choices sein. Choices: {choices}"
    assert len(choices) == 3, (
        f"Choices sollen 3 Eintraege haben (none + 2 groups), hat: {len(choices)}. "
        f"Choices: {choices}"
    )

    # Coerce-Lambda: 'none' -> None, '1' -> 1
    coerce = form.group_id.coerce
    assert coerce("none") is None, f"coerce('none') soll None zurueckgeben, got: {coerce('none')!r}"
    assert coerce("1") == 1, f"coerce('1') soll 1 (int) zurueckgeben, got: {coerce('1')!r}"
    assert coerce("2") == 2, f"coerce('2') soll 2 (int) zurueckgeben, got: {coerce('2')!r}"


# ===========================================================================
# 27. test_server_scan_interval_form_validates_bounds
# ===========================================================================


@pytest.mark.parametrize(
    ("value", "expected_valid"),
    [
        ("0", False),  # Unterhalb Minimum (1)
        ("1", True),  # Grenzwert Minimum
        ("168", True),  # Grenzwert Maximum
        ("169", False),  # Ueber Maximum (168)
        ("24", True),  # Typischer Wert
        ("100", True),  # Mittlerer Wert
    ],
    ids=["zero", "min_boundary", "max_boundary", "above_max", "typical", "middle"],
)
def test_server_scan_interval_form_validates_bounds(
    no_csrf_app: Flask,
    value: str,
    expected_valid: bool,
) -> None:
    """ServerScanIntervalForm.validate() prueft Range 1..168 korrekt.

    NumberRange(min=1, max=168): 0 und 169 sind invalide, 1 und 168 sind valid.
    """
    from app.forms import ServerScanIntervalForm

    with no_csrf_app.test_request_context("/"):
        form = ServerScanIntervalForm(formdata=ImmutableMultiDict([("scan_interval_h", value)]))
        result = form.validate()

    assert result is expected_valid, (
        f"ServerScanIntervalForm.validate() mit scan_interval_h={value!r}: "
        f"erwartet {expected_valid}, got {result}. "
        f"Fehler: {form.errors}"
    )
