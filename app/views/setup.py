"""First-Boot-Wizard `/setup`.

Drei Schritte:

1. `step1` — Admin-Account anlegen.
2. `step2` — Master-Key generieren, einmalig anzeigen, Notiz bestaetigen.
3. `step3` — Defaults (Severity-Schwelle, Stale-Threshold, Theme).

Der Wizard ist nur erreichbar solange `settings.setup_completed_at IS NULL`.
Nach Abschluss redirected `/setup*` immer auf `/login`.

Wir tracken den Fortschritt in der Server-Session, damit ein User nicht
mitten im Wizard wegnavigieren und an einer ungueltigen Stelle wieder
einsteigen kann.
"""

from __future__ import annotations

from typing import Any, cast

import structlog
from flask import Blueprint, flash, redirect, render_template, session, url_for
from sqlalchemy import select
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.auth import generate_master_key, hash_master_key, hash_password
from app.db import get_session
from app.forms import SetupStep1Form, SetupStep2Form, SetupStep3Form
from app.models import Setting, Severity, User
from app.settings_service import ensure_settings_row, is_setup_completed, mark_setup_completed

log = structlog.get_logger(__name__)
setup_bp = Blueprint("setup", __name__, url_prefix="/setup")

# Session-Keys.
_S_STEP1_DONE = "setup_step1_done"
_S_STEP2_DONE = "setup_step2_done"
_S_PENDING_MASTER_KEY = "setup_pending_master_key"  # Klartext nur in Server-Session.


def _redirect_to_step(step: int) -> WerkzeugResponse:
    if step == 1:
        return redirect(url_for("setup.step1"))
    if step == 2:
        return redirect(url_for("setup.step2"))
    return redirect(url_for("setup.step3"))


def _required_step() -> int:
    """Liefert den naechsten zu erledigenden Step (1, 2 oder 3)."""
    if not session.get(_S_STEP1_DONE):
        return 1
    if not session.get(_S_STEP2_DONE):
        return 2
    return 3


@setup_bp.before_request
def _guard() -> WerkzeugResponse | None:
    """Sperrt den Wizard nach Abschluss."""
    if is_setup_completed():
        return redirect(url_for("auth.login"))
    return None


@setup_bp.get("/")
def index() -> WerkzeugResponse:
    """Einstiegspunkt — leitet auf den passenden Step."""
    return _redirect_to_step(_required_step())


# ---------------------------------------------------------------------------
# Step 1 — Admin-Account.
# ---------------------------------------------------------------------------


@setup_bp.route("/step1", methods=["GET", "POST"])
def step1() -> Any:
    # Step-Reihenfolge: wenn schon abgeschlossen, weiter zum naechsten.
    if session.get(_S_STEP1_DONE):
        return _redirect_to_step(_required_step())

    form = SetupStep1Form()
    if form.validate_on_submit():
        sess = get_session()
        username = cast(str, form.username.data).strip()
        password = cast(str, form.password.data)

        existing = sess.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if existing is not None:
            flash("Benutzername existiert bereits.", "error")
            return render_template("setup/step1.html", form=form)

        user = User(username=username, password_hash=hash_password(password))
        sess.add(user)
        sess.flush()
        log_event(
            "setup.admin_created",
            target_type="user",
            target_id=user.id,
            actor=username,
            actor_id=user.id,
            session=sess,
        )
        sess.commit()

        session[_S_STEP1_DONE] = True
        log.info("setup.step1.completed", user_id=user.id)
        return redirect(url_for("setup.step2"))

    return render_template("setup/step1.html", form=form)


# ---------------------------------------------------------------------------
# Step 2 — Master-Key generieren und einmalig anzeigen.
# ---------------------------------------------------------------------------


@setup_bp.route("/step2", methods=["GET", "POST"])
def step2() -> Any:
    if not session.get(_S_STEP1_DONE):
        return _redirect_to_step(_required_step())
    if session.get(_S_STEP2_DONE):
        return _redirect_to_step(_required_step())

    # Bei GET: neuen Key generieren (falls noch nicht in Session) und anzeigen.
    # Bei POST mit gueltiger Bestaetigung: Hash persistieren, Session-Klartext loeschen.
    form = SetupStep2Form()

    master_key = session.get(_S_PENDING_MASTER_KEY)
    if master_key is None:
        master_key = generate_master_key()
        session[_S_PENDING_MASTER_KEY] = master_key

    if form.validate_on_submit():
        sess = get_session()
        settings_row = ensure_settings_row(sess)
        # Klartext kommt nicht in den Log — `hash_master_key` haengt nur den Hash an.
        settings_row.master_key_hash = hash_master_key(master_key)
        log_event(
            "setup.master_key_set",
            target_type="settings",
            target_id=1,
            session=sess,
        )
        sess.commit()

        session.pop(_S_PENDING_MASTER_KEY, None)
        session[_S_STEP2_DONE] = True
        log.info("setup.step2.completed")
        return redirect(url_for("setup.step3"))

    return render_template("setup/step2.html", form=form, master_key=master_key)


# ---------------------------------------------------------------------------
# Step 3 — Defaults und Abschluss.
# ---------------------------------------------------------------------------


@setup_bp.route("/step3", methods=["GET", "POST"])
def step3() -> Any:
    if not session.get(_S_STEP1_DONE) or not session.get(_S_STEP2_DONE):
        return _redirect_to_step(_required_step())

    form = SetupStep3Form()
    if form.validate_on_submit():
        sess = get_session()
        row: Setting = ensure_settings_row(sess)
        row.severity_threshold = Severity(form.severity_threshold.data)
        row.stale_threshold_h = int(cast(int, form.stale_threshold_h.data))
        row.stale_trivy_db_threshold_h = int(cast(int, form.stale_trivy_db_threshold_h.data))
        row.default_theme = cast(str, form.default_theme.data)

        log_event(
            "setup.defaults_set",
            target_type="settings",
            target_id=1,
            metadata={
                "severity_threshold": row.severity_threshold.value,
                "stale_threshold_h": row.stale_threshold_h,
                "stale_trivy_db_threshold_h": row.stale_trivy_db_threshold_h,
                "default_theme": row.default_theme,
            },
            session=sess,
        )
        sess.commit()

        mark_setup_completed(sess)
        log_event("setup.completed", target_type="settings", target_id=1, session=sess)
        sess.commit()

        # Session aufraeumen.
        for key in (_S_STEP1_DONE, _S_STEP2_DONE, _S_PENDING_MASTER_KEY):
            session.pop(key, None)
        log.info("setup.completed")
        flash("Setup abgeschlossen — bitte einloggen.", "success")
        return redirect(url_for("auth.login"))

    return render_template("setup/step3.html", form=form)


__all__ = ["setup_bp"]
