"""Pure-Unit-Tests fuer das Auth-Expiry-Verhalten bei HTMX-Requests.

Hintergrund: ein abgelaufener Login fuehrt bei `@login_required` zum
`unauthorized_handler`. Fuer HTMX-Requests muss daraus ein harter
Voll-Seiten-Redirect (`HX-Redirect`) werden statt eines 302, dem der HTMX-XHR
transparent folgt und so die Login-Seite ins Partial-Target swappt.

Bewusst OHNE echte DB: eine Minimal-Flask-App mit dem globalen `login_manager`
und einem geschuetzten Dummy-Endpoint reicht, um beide Pfade des Handlers und
den `safe_next`-Open-Redirect-Schutz abzudecken.
"""

from __future__ import annotations

import pytest
from flask import Blueprint, Flask
from flask.testing import FlaskClient
from flask_login import login_required

from app.auth import login_manager, safe_next


@pytest.fixture
def mini_app() -> Flask:
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test-secret", TESTING=True)
    login_manager.init_app(app)

    auth = Blueprint("auth", __name__)

    @auth.route("/login")
    def login() -> str:  # Dummy fuer url_for("auth.login")
        return "login page"

    app.register_blueprint(auth)

    @app.route("/protected")
    @login_required
    def protected() -> str:
        return "secret"

    return app


@pytest.fixture
def client(mini_app: Flask) -> FlaskClient:
    return mini_app.test_client()


# ---------------------------------------------------------------------------
# safe_next — Open-Redirect-Schutz (rein funktional).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("/dashboard", "/dashboard"),
        ("/findings?bucket=open&sort=sev", "/findings?bucket=open&sort=sev"),
        # Absolute URL -> Host wird verworfen, nur Pfad+Query bleibt.
        ("https://evil.example/dashboard?x=1", "/dashboard?x=1"),
        # Protokoll-relative URL (//host) -> Host wird verworfen, lokaler Pfad bleibt.
        ("//evil.example/pwn", "/pwn"),
        # Schema-only / kaputt -> kein brauchbarer lokaler Pfad.
        ("javascript:alert(1)", None),
    ],
)
def test_safe_next_sanitizes(raw: str | None, expected: str | None) -> None:
    assert safe_next(raw) == expected


def test_safe_next_keeps_query_for_local_path() -> None:
    assert safe_next("/x?a=1&b=2") == "/x?a=1&b=2"


# ---------------------------------------------------------------------------
# unauthorized_handler — klassischer Browser-Request.
# ---------------------------------------------------------------------------


def test_plain_request_gets_302_to_login(client: FlaskClient) -> None:
    resp = client.get("/protected")
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert "/login" in loc
    assert "next=%2Fprotected" in loc or "next=/protected" in loc, loc


# ---------------------------------------------------------------------------
# unauthorized_handler — HTMX-Request.
# ---------------------------------------------------------------------------


def test_htmx_request_gets_204_with_hx_redirect(client: FlaskClient) -> None:
    resp = client.get(
        "/protected",
        headers={"HX-Request": "true", "HX-Current-URL": "http://localhost/findings"},
    )
    assert resp.status_code == 204
    assert resp.data == b""
    # Kein Body-Swap: stattdessen harter Redirect via Header.
    hx = resp.headers["HX-Redirect"]
    assert hx.startswith("/login")
    assert "next=%2Ffindings" in hx or "next=/findings" in hx, hx
    # KEIN klassischer Location-Redirect, sonst wuerde der XHR folgen.
    assert "Location" not in resp.headers


def test_htmx_request_strips_foreign_host_from_next(client: FlaskClient) -> None:
    resp = client.get(
        "/protected",
        headers={
            "HX-Request": "true",
            "HX-Current-URL": "https://evil.example/findings",
        },
    )
    assert resp.status_code == 204
    hx = resp.headers["HX-Redirect"]
    assert "evil.example" not in hx, hx


def test_htmx_request_without_current_url_redirects_to_bare_login(client: FlaskClient) -> None:
    resp = client.get("/protected", headers={"HX-Request": "true"})
    assert resp.status_code == 204
    assert resp.headers["HX-Redirect"].rstrip("?") == "/login"
