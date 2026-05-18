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
from pathlib import Path
from typing import TYPE_CHECKING, Any

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


def _iso_or_empty(value: datetime | None) -> str:
    """Render einen Zeitstempel als ISO-8601-String, sonst leeren String.

    Wird in `data-*`-Attributen verwendet, damit `static/js/stale.js` die
    Relativzeit-Labels client-seitig re-rendern kann ohne den Server zu
    fragen. Naive datetimes werden als UTC behandelt.
    """
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


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


def _humanize_delta(value: datetime | None) -> str:
    """Render die Differenz zu jetzt als kurze Englisch-Phrase ("3 days ago").

    Wird in den Outdated-Pill-Tooltips (Block N, ADR-0021) verwendet. Bei
    `None` -> "never". Bewusst eigene Implementierung statt `relative_time`,
    weil die Tooltips dort Englisch sind (passt zum "Update required" /
    "Run: curl …"-Kontext).
    """
    if value is None:
        return "never"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    delta = datetime.now(tz=UTC) - value
    seconds = int(delta.total_seconds())
    if seconds < 0 or seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'' if minutes == 1 else 's'} ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'' if hours == 1 else 's'} ago"
    days = hours // 24
    if days < 30:
        return f"{days} day{'' if days == 1 else 's'} ago"
    months = days // 30
    if months < 12:
        return f"{months} month{'' if months == 1 else 's'} ago"
    years = days // 365
    return f"{years} year{'' if years == 1 else 's'} ago"


# Pfade, die ohne abgeschlossenes Setup erreichbar bleiben muessen.
_SETUP_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/setup",
    "/static",
    "/healthz",
    "/readyz",
    # Block N (ADR-0021) — Bootstrap-Installer-Endpoints sind bewusst ohne
    # Auth und ohne Setup-Gate erreichbar. Inhalt ist kein Geheimnis, der
    # Operator soll das Skript vor dem Pipen in `bash` inspizieren koennen.
    "/install.sh",
    "/agent/version",
    "/agent/files/",
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

    # Block H — ADR-0013: Schwacher Encryption-Key fuehrt zu einer
    # sichtbaren Warn-Zeile beim Start (kein Abbruch). Trivial-Keys wie
    # `aaaaaaaaaa…` (1 distinkter Byte-Wert) werden so erkannt; echte
    # zufaellige Keys (40+ distinkte Bytes) loggen nichts.
    if settings.encryption_key_has_low_entropy:
        log.warning(
            "secscan.weak_encryption_key",
            message=(
                "SECSCAN_ENCRYPTION_KEY hat weniger als 16 distinkte Byte-Werte. "
                "Empfohlen: 'python -c \"import secrets; "
                "print(secrets.token_urlsafe(48))\"' oder "
                "'openssl rand -base64 48'."
            ),
        )

    # 3. Flask-App.
    app = Flask(__name__)
    # Block N (ADR-0021): Verzeichnis fuer die statischen Agent-Skripte.
    # Im Repo-/Dev-Layout liegt das unter `<repo>/agent/`; in der Docker-
    # Image-Variante kopiert das Dockerfile dasselbe Verzeichnis nach
    # `/app/agent`. Wir leiten den Pfad relativ zum `app/`-Package ab,
    # damit beide Setups ohne extra ENV-Var funktionieren.
    agent_files_dir = (Path(__file__).resolve().parent.parent / "agent").as_posix()

    # v0.7.1: ProxyFix aktivieren, damit Flask hinter einem TLS-
    # terminierenden Reverse-Proxy (nginx/Caddy mit
    # `X-Forwarded-Proto $scheme`) `request.scheme` und damit
    # `request.host_url` korrekt als `https://` aufloest. Ohne ProxyFix
    # rendert `GET /install.sh` `SECSCAN_URL=http://...`, was beim
    # ersten `POST /api/register` einen HTTP->HTTPS-301-Redirect
    # ausloest, dem `curl -X POST` nicht folgt. `x_proto=1`/`x_host=1`/
    # `x_for=1` vertraut genau einem Proxy-Hop — die Defaults sind
    # bewusst konservativ.
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
        app.wsgi_app, x_proto=1, x_host=1, x_for=1
    )

    # v0.7.1: explizite Public-URL aus `SECSCAN_PUBLIC_URL`. Wenn gesetzt,
    # ueberschreibt sie `request.host_url`-Fallback im Installer-Render
    # und im `external_base_url`-Context-Processor. Deploy-eindeutige
    # Quelle der Wahrheit — empfohlen fuer alle Production-Setups.
    public_url = (settings.public_url or "").rstrip("/")

    app.config.update(
        SECRET_KEY=settings.secret_key.get_secret_value() or "dev-only-insecure",
        MAX_CONTENT_LENGTH=settings.max_body_bytes,  # 10 MB Default — §9.
        SECSCAN_DATABASE_URL=settings.database_url,
        SECSCAN_SETTINGS=settings,
        AGENT_FILES_DIR=agent_files_dir,
        EXTERNAL_BASE_URL=public_url,  # leer = Fallback auf `request.host_url`.
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
    app.jinja_env.filters["iso_or_empty"] = _iso_or_empty
    app.jinja_env.filters["humanize_delta"] = _humanize_delta

    # Markdown-Safe Filter fuer Notizen — `nh3.clean(...)` ist in der
    # Pipeline. Template ruft `{{ note.text | markdown_safe }}` auf, ohne
    # `|safe` (Filter gibt Markup-Objekt zurueck).
    from app.services.notes_render import render_note_markdown

    app.jinja_env.filters["markdown_safe"] = render_note_markdown

    # LLM-Output-Sanitization (Block G): `nh3.clean(...)` mit Allowlist
    # fuer `<a>`-Tags und erzwungenem `rel="noopener noreferrer nofollow"`.
    # Templates rufen `{{ message.content | llm_safe }}` auf — **ohne** `|safe`.
    from app.services.llm_sanitize import clean_llm_html

    app.jinja_env.filters["llm_safe"] = clean_llm_html

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

    from app.api.llm_chat import llm_chat_bp
    from app.views._sidebar_context import sidebar_partials_bp
    from app.views.agent_install import agent_install_bp
    from app.views.audit_view import audit_bp
    from app.views.auth import auth_bp
    from app.views.dashboard import dashboard_bp
    from app.views.findings import findings_bp
    from app.views.llm_settings import llm_settings_bp
    from app.views.server_detail import server_detail_bp
    from app.views.servers import servers_bp
    from app.views.settings import settings_bp
    from app.views.setup import setup_bp

    app.register_blueprint(setup_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(llm_settings_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(server_detail_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(llm_chat_bp)
    app.register_blueprint(sidebar_partials_bp)
    app.register_blueprint(agent_install_bp)

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

    @app.context_processor
    def _inject_llm_configured() -> dict[str, bool]:
        """`llm_configured` fuer Templates (Server-Detail-Button).

        True wenn `Setting.llm_base_url` UND `Setting.llm_model` gesetzt
        sind. Falls die DB nicht erreichbar oder die Settings-Row noch
        nicht existiert: False (fail-safe).
        """
        try:
            from app.db import get_session
            from app.settings_service import get_settings_row

            sess = get_session()
            row = get_settings_row(sess)
            return {
                "llm_configured": bool(row.llm_base_url and row.llm_model),
            }
        except Exception:  # pragma: no cover — DB/Setup-Edge-Case
            return {"llm_configured": False}

    @app.context_processor
    def _inject_agent_version_helpers() -> dict[str, Any]:
        """Block N (ADR-0021) — Outdated-Helper + Konstanten + Finding-Cause.

        Exponiert die Heuristik-Funktionen aus `app.services.agent_version`
        als Jinja-Globals (`is_agent_outdated`, `is_trivy_outdated`,
        `is_trivy_db_outdated`) plus die zugehoerigen Schwellwerte fuer
        Tooltip-Strings. `format_finding_cause` rendert die Ursachen-Sub-
        Zeile pro Finding (Task #12a).

        `external_base_url` liefert die im Setup-Wizard hinterlegte Public-
        URL — Fallback auf `request.host_url`, damit Dev-Setups ohne
        Konfiguration einen sinnvollen Wert anzeigen.
        """
        from app.services.agent_version import (
            is_agent_outdated,
            is_trivy_db_outdated,
            is_trivy_outdated,
        )
        from app.services.finding_display import format_finding_cause

        external_base_url = app.config.get("EXTERNAL_BASE_URL")
        if not external_base_url:
            try:
                external_base_url = request.host_url.rstrip("/")
            except RuntimeError:  # outside request context
                external_base_url = ""

        return {
            "is_agent_outdated": is_agent_outdated,
            "is_trivy_outdated": is_trivy_outdated,
            "is_trivy_db_outdated": is_trivy_db_outdated,
            "format_finding_cause": format_finding_cause,
            "min_agent_version": Settings.MIN_AGENT_VERSION,
            "min_trivy_version": Settings.MIN_TRIVY_VERSION,
            "trivy_db_stale_threshold_days": Settings.TRIVY_DB_STALE_THRESHOLD_DAYS,
            "external_base_url": external_base_url,
        }

    @app.context_processor
    def _inject_sidebar_context() -> dict[str, Any]:
        """Sidebar-Variablen fuer `base_app.html` (Block I).

        Wird nur fuer authentifizierte, nicht-HX-Requests gebaut — bei
        HTMX-Fragmenten extenden Templates `_partial_shell.html` und
        brauchen die Sidebar nicht. Bei Fehlern (DB-down, kein Setup):
        leerer dict, das Template faellt auf seine `or []`/`or {}`-
        Defaults zurueck.

        View-Kontext hat Vorrang vor Context-Processor (Flask-Default),
        d.h. `server_detail.show` kann `active_server_id` und Dashboard
        kann `quick_stats`/`available_tags` weiterhin selbst setzen.
        """
        # API-Endpoints und HTMX-Fragmente brauchen keinen Sidebar-Build.
        if request.headers.get("HX-Request") == "true":
            return {}
        from flask_login import current_user

        if not getattr(current_user, "is_authenticated", False):
            return {}
        try:
            from app.views._sidebar_context import build_sidebar_context

            return build_sidebar_context()
        except Exception as exc:  # pragma: no cover — DB/Setup-Edge-Case
            log.warning("sidebar_context.unavailable", error=str(exc))
            return {}

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
