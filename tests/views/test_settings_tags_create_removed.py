"""Pure-Unit-Tests: der fruehere `POST /settings/tags`-Create-Endpoint ist weg.

Block Z, Phase D (ADR-0040): Tags entstehen ausschliesslich inline im Server-
Settings-Sub-View. Der `tags_create`-Endpoint wurde ersatzlos entfernt — `GET
/settings/tags` existiert weiter (Manage-Liste), `POST` liefert jetzt 405.

Diese Tests laufen rein auf Routing-Ebene (kein Login, kein DB-Zugriff): das
Method-Matching im Werkzeug-URL-Map passiert vor der `@login_required`-Wrapper-
Logik, darum ist 405 ohne Auth-Mock erreichbar.
"""

from __future__ import annotations

import pytest
from flask import Flask
from werkzeug.routing import BuildError


@pytest.fixture
def no_csrf_app(app_env: None) -> Flask:
    from app import create_app

    flask_app = create_app()
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return flask_app


def test_post_settings_tags_returns_405(no_csrf_app: Flask) -> None:
    """POST /settings/tags -> 405 Method Not Allowed (Create-Endpoint entfernt).

    405 entsteht beim Routing — kein Login-Redirect, kein DB-Zugriff noetig.
    """
    client = no_csrf_app.test_client()
    resp = client.post("/settings/tags")
    assert resp.status_code == 405, (resp.status_code, resp.data[:200])


def test_settings_tags_rule_allows_get_not_post(no_csrf_app: Flask) -> None:
    """Die URL-Regel fuer `/settings/tags` erlaubt GET, aber NICHT POST."""
    rules = [r for r in no_csrf_app.url_map.iter_rules() if r.rule == "/settings/tags"]
    assert rules, "Route /settings/tags ist nicht registriert"
    methods = set().union(*(r.methods or set() for r in rules))
    assert "GET" in methods, f"GET muss erlaubt bleiben: {methods}"
    assert "POST" not in methods, f"POST darf nicht (mehr) erlaubt sein: {methods}"


def test_tags_create_endpoint_does_not_exist(no_csrf_app: Flask) -> None:
    """`url_for('settings.tags_create')` wirft BuildError — Endpoint ist entfernt."""
    with no_csrf_app.test_request_context():
        from flask import url_for

        with pytest.raises(BuildError):
            url_for("settings.tags_create")
