"""Flask-App-Factory fuer secscan.

Konfiguriert in dieser Reihenfolge:

1. Settings laden (pydantic-settings) — Start-Refusal wenn
   `SECSCAN_ENCRYPTION_KEY` fehlt.
2. Logging (structlog mit JSON-Output + Redaction-Filter).
3. Flask-App mit `MAX_CONTENT_LENGTH=10 MB` Default und Jinja-Autoescape.
4. `flask-limiter` mit in-memory Backend und Default-Limits aus
   ARCHITECTURE.md §9.
5. DB-Engine + Session-Factory.
6. `flask-wtf` CSRF und `flask-login` LoginManager.
7. Blueprints (Health, Setup, Auth, Settings).
8. Theme-Cookie-Handler (light/dark/auto) und Setup-Guard.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import structlog
from flask import Flask, Response, g, redirect, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from pydantic import ValidationError
from werkzeug.wrappers import Response as WerkzeugResponse

from app.config import Settings, load_settings
from app.health import bp as health_bp
from app.logging_setup import configure_logging

if TYPE_CHECKING:
    pass

__all__ = ["create_app", "csrf", "limiter"]

# Global verfuegbarer Limiter — wird in `create_app` initialisiert. Andere
# Module duerfen ihn via `from app import limiter` importieren und Decorators
# wie `@limiter.limit("5/minute")` anwenden.
limiter: Limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
)

# CSRF-Schutz auf allen Browser-POSTs — HTMX-Requests muessen das Token im
# `X-CSRFToken`-Header mitschicken.
csrf: CSRFProtect = CSRFProtect()


_VALID_THEMES: frozenset[str] = frozenset({"light", "dark", "auto"})


def _relative_time(value: datetime | None) -> str:
    """Formatiere einen Zeitstempel als deutsche Relativangabe.

    Beispiele: "gerade eben", "vor 5min", "vor 2h", "vor 3 Tagen". Bei `None`
    gibt der Filter "noch nie" zurueck. Naive datetimes werden als UTC
    interpretiert (defensive).
    """
    if value is None:
        return "noch nie"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    delta = datetime.now(tz=UTC) - value
    seconds = int(delta.total_seconds())
    if seconds < 0:
        # Zukunft — selten (Clock-Skew). Wir zeigen "gerade eben".
        return "gerade eben"
    if seconds < 60:
        return "gerade eben"
    minutes = seconds // 60
    if minutes < 60:
        return f"vor {minutes}min"
    hours = minutes // 60
    if hours < 24:
        return f"vor {hours}h"
    days = hours // 24
    if days < 30:
        return f"vor {days} Tag" + ("" if days == 1 else "en")
    months = days // 30
    if months < 12:
        return f"vor {months} Monat" + ("" if months == 1 else "en")
    years = days // 365
    return f"vor {years} Jahr" + ("" if years == 1 else "en")


def _is_older_than_h(value: datetime | None, hours: int) -> bool:
    """`True` wenn `value` mehr als `hours` Stunden in der Vergangenheit liegt.

    Bei `None` -> `False` (Stale-Badge unterdrueckt, "noch nie" reicht aus).
    """
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    delta = datetime.now(tz=UTC) - value
    return delta.total_seconds() > hours * 3600


# Pfade, die ohne abgeschlossenes Setup erreichbar bleiben muessen.
_SETUP_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/setup",
    "/static",
    "/healthz",
    "/readyz",
)


def create_app() -> Flask:
    """Erzeugt eine konfigurierte Flask-App.

    Beendet den Prozess via `SystemExit`, wenn die Settings nicht valide sind
    (z.B. fehlender `SECSCAN_ENCRYPTION_KEY`).
    """
    # 1. Settings laden — bei Fehlern Start verweigern.
    try:
        settings: Settings = load_settings()
    except ValidationError as exc:
        # Bewusst kein structlog hier — Logger ist noch nicht konfiguriert.
        sys.stderr.write(
            "secscan: Konfigurations-Fehler — Start verweigert.\n"
            f"{exc}\n"
            "Pruefe die Pflicht-Environment-Variablen, "
            "insbesondere SECSCAN_ENCRYPTION_KEY.\n"
        )
        raise SystemExit(2) from exc

    # 2. Logging vor allem anderen aktivieren.
    configure_logging(settings.log_level)
    log = structlog.get_logger(__name__)

    # 3. Flask-App.
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.secret_key.get_secret_value() or "dev-only-insecure",
        MAX_CONTENT_LENGTH=settings.max_body_bytes,  # 10 MB Default — §9.
        SECSCAN_DATABASE_URL=settings.database_url,
        SECSCAN_SETTINGS=settings,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # in Produktion via Reverse-Proxy auf True.
        PERMANENT_SESSION_LIFETIME=timedelta(days=settings.session_lifetime_days),
        JSON_SORT_KEYS=False,
        WTF_CSRF_TIME_LIMIT=None,  # Session-Lifetime regelt das.
    )

    # Jinja-Autoescape ist Flask-Default — wir verifizieren das explizit und
    # erzwingen es, damit niemand es versehentlich abdreht (siehe §10).
    # Flask setzt autoescape standardmaessig fuer .html/.htm/.xml/.xhtml.
    # Wir zusaetzlich select_autoescape-aequivalent: alle Templates escapen.
    app.jinja_env.autoescape = True

    # Jinja-Filter: relative Zeitangaben fuer Templates. Minimal-invasiv,
    # damit alle Templates ohne Anpassung der Views "vor 2h" / "vor 3 Tagen"
    # rendern koennen. Bei `None` wird "noch nie" geliefert.
    app.jinja_env.filters["relative_time"] = _relative_time
    app.jinja_env.filters["is_older_than_h"] = _is_older_than_h

    # Markdown-Safe Filter fuer Notizen — `nh3.clean(...)` ist in der
    # Pipeline. Template ruft `{{ note.text | markdown_safe }}` auf, ohne
    # `|safe` (Filter gibt Markup-Objekt zurueck).
    from app.services.notes_render import render_note_markdown

    app.jinja_env.filters["markdown_safe"] = render_note_markdown

    # 4. Rate-Limiter initialisieren. Defaults: §9.
    limiter.init_app(app)
    # Default-Limits gelten fuer alle Routes; spezifische Endpoints koennen
    # via `@limiter.limit(...)` enger limitieren.
    app.config["SECSCAN_RATELIMITS"] = {
        "register": settings.ratelimit_register,
        "login": settings.ratelimit_login,
        "scans_unauth": settings.ratelimit_scans_unauth,
        "scans_auth": settings.ratelimit_scans_auth,
    }

    # 5. DB-Engine und Per-Request-Session-Lifecycle.
    from app.db import close_session, init_engine

    init_engine(app)
    app.teardown_request(close_session)

    # 6. CSRF und Login-Manager.
    csrf.init_app(app)
    from app.auth import init_auth

    init_auth(app)

    # 7. Blueprints.
    app.register_blueprint(health_bp)

    from app.views.auth import auth_bp
    from app.views.dashboard import dashboard_bp
    from app.views.findings import findings_bp
    from app.views.server_detail import server_detail_bp
    from app.views.servers import servers_bp
    from app.views.settings import settings_bp
    from app.views.setup import setup_bp

    app.register_blueprint(setup_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(server_detail_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(dashboard_bp)

    # API-Blueprint (Block C). Routes werden in `register_api_routes`
    # importiert (lazy, vermeidet Zirkulaere durch `from app import csrf,
    # limiter` in den Endpoint-Modulen).
    from app.api import api_bp, register_api_routes

    register_api_routes()
    app.register_blueprint(api_bp)

    # 8. Theme-Cookie-Handling — leichtgewichtiger Stub fuer Light/Dark/Auto.
    @app.before_request
    def _resolve_theme() -> None:
        raw = request.cookies.get("theme", "auto")
        g.theme = raw if raw in _VALID_THEMES else "auto"

    @app.context_processor
    def _inject_theme() -> dict[str, str]:
        return {"theme": getattr(g, "theme", "auto")}

    @app.after_request
    def _persist_theme(response: Response) -> Response:
        # Normalisierte Theme-Werte zurueckschreiben, falls invalides Cookie kam.
        raw = request.cookies.get("theme")
        if raw is not None and raw not in _VALID_THEMES:
            response.set_cookie(
                "theme",
                "auto",
                max_age=60 * 60 * 24 * 365,
                httponly=False,
                samesite="Lax",
            )
        return response

    # Setup-Guard: solange das Setup nicht abgeschlossen ist, leiten wir
    # alle Browser-Requests auf den Wizard. `is_setup_completed()` liest aus
    # der DB — wenn die DB nicht erreichbar ist, lassen wir den Request
    # durchlaufen (Healthchecks duerfen weiterhin antworten).
    @app.before_request
    def _setup_guard() -> WerkzeugResponse | None:
        path = request.path or "/"
        if any(path.startswith(prefix) for prefix in _SETUP_EXEMPT_PREFIXES):
            return None
        # API-Endpunkte (Block C) sollen den Wizard nicht triggern — sie
        # geben eigene 401-Antworten.
        if path.startswith("/api/"):
            return None
        try:
            from app.settings_service import is_setup_completed

            if not is_setup_completed():
                return redirect(url_for("setup.index"))
        except Exception as exc:  # pragma: no cover — DB-down edge case
            log.warning("setup_guard.db_unavailable", error=str(exc))
            return None
        return None

    log.info(
        "app.started",
        max_body_mb=settings.max_body_mb,
        autoescape=app.jinja_env.autoescape,
        workers=settings.gunicorn_workers,
    )
    return app
