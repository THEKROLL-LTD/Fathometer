"""Settings-Browser-Views unter `/settings`.

Enthaelt:

- ``GET /settings`` — Alias-Redirect auf ``/settings/servers/`` (Default-
  Sub-Tab laut ADR-0016 + User-Klaerung).
- ``GET /settings/tags`` / ``POST /settings/tags`` / ``POST /settings/tags/<id>/delete``
  — Tag-Verwaltung (Block B).
- ``GET /settings/master-key`` / ``POST /settings/master-key/rotate``
  — Master-Key-Rotations-UI (ADR-0016, schliesst Spec-Luecke aus
  ``ARCHITECTURE.md §8``).
- ``GET /settings/about`` — Versions-/Build-Info (read-only).

Render-Strategie: alle Sub-Views nutzen `render_settings(...)` aus
`app.views._settings_shell` und werden je nach `HX-Request`/`HX-Target`
in drei Modi ausgespielt — siehe Helper-Docstring fuer Details.
"""

from __future__ import annotations

import importlib.metadata as ilm
import os
import sys
from typing import Any, cast

import structlog
from flask import Blueprint, flash, make_response, redirect, url_for
from flask_login import login_required
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from werkzeug.wrappers import Response as WerkzeugResponse

from app.audit import log_event
from app.auth import generate_master_key, hash_master_key
from app.db import get_session
from app.forms import CSRFOnlyForm, MasterKeyRotateForm, TagForm
from app.models import AuditEvent, Server, Tag
from app.services.stale_detection import is_db_stale
from app.settings_service import get_settings_row
from app.views._settings_shell import render_settings

log = structlog.get_logger(__name__)
settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


# ---------------------------------------------------------------------------
# Alias-Redirect (ADR-0016)
# ---------------------------------------------------------------------------


@settings_bp.get("/")
@login_required
def settings_index() -> WerkzeugResponse:
    """`/settings` -> `/settings/servers/`.

    Laut User-Klaerung ist Server-Verwaltung der Default-Sub-Tab; das
    Addendum hatte zwar `Tags` vorgesehen, der finale Wunsch ist aber
    Server. Direkt-URLs auf `/settings/tags` etc. bleiben erreichbar.
    """
    return redirect(url_for("servers.list_servers"))


# ---------------------------------------------------------------------------
# Tags — bestehende Routen (unveraendert in Verhalten, Templates kommen
# vom frontend-implementer auf den neuen `_shell.html`-Pfad).
# ---------------------------------------------------------------------------


@settings_bp.get("/tags")
@login_required
def tags_list() -> Any:
    sess = get_session()
    tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()
    return render_settings(
        active="tags",
        content_template="settings/tags.html",
        tags=tags,
        form=TagForm(),
        delete_form=CSRFOnlyForm(),
    )


@settings_bp.post("/tags")
@login_required
def tags_create() -> Any:
    sess = get_session()
    form = TagForm()
    if not form.validate_on_submit():
        tags = sess.execute(select(Tag).order_by(Tag.name)).scalars().all()
        for field_name, errors in form.errors.items():
            for err in errors:
                flash(f"{field_name}: {err}", "error")
        return make_response(
            render_settings(
                active="tags",
                content_template="settings/tags.html",
                tags=tags,
                form=form,
                delete_form=CSRFOnlyForm(),
            ),
            400,
        )

    tag = Tag(name=cast(str, form.name.data), color=cast(str, form.color.data))
    sess.add(tag)
    try:
        sess.flush()
    except IntegrityError:
        sess.rollback()
        flash("Tag existiert bereits.", "error")
        return redirect(url_for("settings.tags_list"))

    log_event(
        "tag.created",
        target_type="tag",
        target_id=tag.id,
        metadata={"name": tag.name, "color": tag.color},
        session=sess,
    )
    sess.commit()
    flash(f"Tag '{tag.name}' angelegt.", "success")
    return redirect(url_for("settings.tags_list"))


@settings_bp.post("/tags/<int:tag_id>/delete")
@login_required
def tags_delete(tag_id: int) -> Any:
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        return redirect(url_for("settings.tags_list"))

    sess = get_session()
    tag = sess.execute(select(Tag).where(Tag.id == tag_id)).scalar_one_or_none()
    if tag is None:
        flash("Tag nicht gefunden.", "error")
        return redirect(url_for("settings.tags_list"))

    name = tag.name
    sess.delete(tag)
    log_event(
        "tag.deleted",
        target_type="tag",
        target_id=tag_id,
        metadata={"name": name},
        session=sess,
    )
    sess.commit()
    flash(f"Tag '{name}' geloescht.", "success")
    return redirect(url_for("settings.tags_list"))


# ---------------------------------------------------------------------------
# Master-Key-Rotation (ADR-0016 — schliesst §8-Spec-Luecke).
# ---------------------------------------------------------------------------


def _last_master_key_rotation_at(sess: Any) -> Any:
    """Letztes `master_key.rotated`-Audit-Event oder Setup-Datum.

    Liefert ein `datetime | None`. Wenn weder Rotation noch Setup-Event
    existiert (frische DB, kein Setup), kommt `None` zurueck — der UI-
    Indikator zeigt dann "noch nie" via Jinja-Filter.
    """
    rotated = sess.execute(
        select(AuditEvent.ts)
        .where(AuditEvent.action == "master_key.rotated")
        .order_by(AuditEvent.ts.desc())
        .limit(1)
    ).scalar_one_or_none()
    if rotated is not None:
        return rotated

    # Fallback: Setup-Datum.
    setup = sess.execute(
        select(AuditEvent.ts)
        .where(AuditEvent.action == "setup.master_key_set")
        .order_by(AuditEvent.ts.desc())
        .limit(1)
    ).scalar_one_or_none()
    if setup is not None:
        return setup

    # Letzte Notnagel-Option: Settings.setup_completed_at.
    setting_row = get_settings_row(sess)
    return setting_row.setup_completed_at


@settings_bp.get("/master-key")
@login_required
def master_key_view() -> Any:
    """Rendert die Master-Key-Rotations-View.

    Zeigt:
      - Datum der letzten Rotation (oder Setup-Datum als Fallback).
      - "Neu generieren"-Button mit Confirm-Modal (Frontend baut das Modal).
      - **Niemals** den Klartext-Key, ausser direkt nach einer Rotation
        (`new_master_key`-Kontext aus dem POST-Re-Render).
    """
    sess = get_session()
    last_rotated_at = _last_master_key_rotation_at(sess)
    return render_settings(
        active="master_key",
        content_template="settings/master_key.html",
        rotate_form=MasterKeyRotateForm(),
        last_rotated_at=last_rotated_at,
        new_master_key=None,
    )


@settings_bp.post("/master-key/rotate")
@login_required
def master_key_rotate() -> Any:
    """Rotiert den Master-Key.

    Ablauf:
      1. CSRF-Validierung (Flask-WTF).
      2. Neuen 32-Byte-URL-safe-Key generieren (analog Setup, §8).
      3. SHA-256-Hash speichern in ``settings.master_key_hash``.
      4. Audit-Event ``master_key.rotated`` mit Hash-Prefix-Metadata —
         **niemals** den Klartext in Audit oder Logs.
      5. Re-render der View mit dem Klartext-Key als einmaliger Anzeige.

    Sicherheits-Hinweise:
      - `generate_master_key()` -> `secrets.token_urlsafe(32)`; entropisch
        wie der Setup-Pfad.
      - `hash_master_key()` -> SHA-256-Hex; Verifikation mit
        `hmac.compare_digest` in `app/auth.py::verify_master_key`.
      - Alte Server-Keys bleiben gueltig — die Rotation aendert nur den
        Master-Key, nicht die Server-Hashes (siehe ARCHITECTURE.md §8).
    """
    sess = get_session()
    form = MasterKeyRotateForm()
    if not form.validate_on_submit():
        flash("Ungueltiger CSRF-Token.", "error")
        # 400 statt 302, damit der Client den Submit als Fehler erkennt
        # und nicht stillschweigend einen neuen GET ausloest.
        last = _last_master_key_rotation_at(sess)
        return make_response(
            render_settings(
                active="master_key",
                content_template="settings/master_key.html",
                rotate_form=form,
                last_rotated_at=last,
                new_master_key=None,
            ),
            400,
        )

    new_master = generate_master_key()
    new_hash = hash_master_key(new_master)
    setting_row = get_settings_row(sess)
    setting_row.master_key_hash = new_hash

    log_event(
        "master_key.rotated",
        target_type="settings",
        target_id="1",
        comment=None,
        metadata={"hash_prefix": new_hash[:8]},
        session=sess,
    )
    sess.commit()

    # Bewusst KEIN structlog-Log mit dem Klartext — der Audit-Helfer hat
    # bereits `audit.logged` ohne Klartext geloggt, und `structlog` mit
    # Redaction-Filter wuerde den Wert eh maskieren. Doppelte Vorsicht:
    # wir leiten den Klartext direkt in den Template-Kontext und nirgendwo
    # sonst hin.
    last = _last_master_key_rotation_at(sess)
    return render_settings(
        active="master_key",
        content_template="settings/master_key.html",
        rotate_form=MasterKeyRotateForm(),
        last_rotated_at=last,
        new_master_key=new_master,
    )


# ---------------------------------------------------------------------------
# About (ADR-0016 — read-only Versions-/Build-Info).
# ---------------------------------------------------------------------------


def _safe_version(distribution_name: str) -> str:
    """Liefert die installierte Version eines Packages oder ``"unknown"``.

    Bewusst defensiv — Docker-Slim-Layer koennen einzelne Metadaten-
    Verzeichnisse loeschen. Niemals SystemExit/Crash wegen About-View.
    """
    try:
        return ilm.version(distribution_name)
    except ilm.PackageNotFoundError:
        return "unknown"


@settings_bp.get("/about")
@login_required
def about_view() -> Any:
    """Read-only About-Page (Versions-/Build-Info).

    Kontext-Dict enthaelt **ausschliesslich** unsensible Werte. Niemals
    ``SECSCAN_ENCRYPTION_KEY``, ``SECSCAN_SECRET_KEY``, ``master_key_hash``,
    ``llm_api_key_encrypted`` oder vergleichbare Geheimnisse — siehe
    Security-Auditor-Checkliste.
    """
    sess = get_session()

    alembic_rev = sess.execute(text("SELECT version_num FROM alembic_version")).scalar()

    # Trivy-DB-Stale-Counter: Anzahl Server mit veralteter DB.
    # Nicht-retired Server iterieren — `is_db_stale` respektiert das selbst,
    # aber wir filtern in der Query schon einmal vor.
    servers = sess.execute(select(Server).where(Server.retired_at.is_(None))).scalars().all()
    trivy_db_stale_count = sum(1 for srv in servers if is_db_stale(srv))

    about: dict[str, Any] = {
        "app_version": _safe_version("secscan"),
        "build_revision": os.environ.get("SECSCAN_BUILD_REVISION", "dev"),
        "alembic_revision": alembic_rev or "unknown",
        "python_version": sys.version.split()[0],
        "flask_version": _safe_version("flask"),
        "sqlalchemy_version": _safe_version("sqlalchemy"),
        "trivy_db_stale_count": trivy_db_stale_count,
        "healthz_url": url_for("health.healthz"),
    }

    return render_settings(
        active="about",
        content_template="settings/about.html",
        about=about,
    )


__all__ = ["settings_bp"]
