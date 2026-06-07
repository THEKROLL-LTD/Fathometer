"""Login- und Logout-Endpunkte."""

from __future__ import annotations

from typing import Any, cast

import structlog
from flask import (
    Blueprint,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select

from app import limiter
from app.audit import log_event
from app.auth import AuthUser, verify_password
from app.db import get_session
from app.forms import LoginForm
from app.models import User
from app.settings_service import is_setup_completed

log = structlog.get_logger(__name__)
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: _login_rate_limit())
def login() -> Any:
    if not is_setup_completed():
        return redirect(url_for("setup.index"))

    if current_user.is_authenticated:
        return redirect(url_for("settings.tags_list"))

    form = LoginForm()
    if form.validate_on_submit():
        sess = get_session()
        username = cast(str, form.username.data).strip()
        password = cast(str, form.password.data)

        row = sess.execute(select(User).where(User.username == username)).scalar_one_or_none()
        # Konstantzeit-Path: auch bei nicht-existierendem User Argon2-Verify
        # durchlaufen lassen, damit die Antwortzeit gleich ist. Wir hashen ein
        # festes Dummy-Passwort gegen einen festen Hash — beide Werte sind
        # statisch und nicht sensitiv (haengen nicht von echten Credentials ab).
        if row is None:
            verify_password(_DUMMY_HASH, password)
            ok = False
        else:
            ok = verify_password(row.password_hash, password)

        ip = request.remote_addr or "unknown"
        if not ok:
            log_event(
                "auth.failed",
                target_type="user",
                target_id=username,
                metadata={"ip": ip},
                actor=username,
                session=sess,
            )
            sess.commit()
            flash("Login failed.", "error")
            return make_response(render_template("login.html", form=form), 401)

        assert row is not None  # fuer mypy/Logik bereits geprueft.
        login_user(AuthUser(id=row.id, username=row.username), remember=False)
        log_event(
            "auth.success",
            target_type="user",
            target_id=row.id,
            metadata={"ip": ip},
            actor=row.username,
            actor_id=row.id,
            session=sess,
        )
        sess.commit()
        log.info("auth.login.success", user_id=row.id)
        next_url = request.args.get("next")
        return redirect(next_url or url_for("settings.tags_list"))

    return render_template("login.html", form=form)


@auth_bp.post("/logout")
@login_required
def logout() -> Any:
    uid = getattr(current_user, "id", None)
    username = getattr(current_user, "username", None)
    sess = get_session()
    log_event(
        "auth.logout",
        target_type="user",
        target_id=uid,
        actor=username,
        actor_id=uid,
        session=sess,
    )
    sess.commit()
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))


# Dummy-Hash fuer Konstantzeit-Verify. argon2-cffi versteht das Format und
# liefert konsistent `False` zurueck (Mismatch) — wichtig: nicht im Logger
# loggen, aber das laeuft eh ueber den Redaction-Filter.
_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$ZHVtbXktc2FsdC1ub3QtcmVhbA$ZHVtbXktaGFzaC1ub3QtdXNlZA"


def _login_rate_limit() -> str:
    """Liest das Login-Rate-Limit aus den App-Settings."""
    from flask import current_app

    limits: dict[str, str] = current_app.config["FM_RATELIMITS"]
    return limits["login"]


__all__ = ["auth_bp"]
