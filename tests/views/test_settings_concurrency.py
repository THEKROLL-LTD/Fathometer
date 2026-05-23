"""Block U Phase E — Settings-UI + Master-Key-Gate fuer Concurrency-Wechsel.

Sechs Cases laut ``docs/blocks/U-worker-concurrency.md`` §Phase E §Tests:

1. GET ``/settings/llm-reviewer`` zeigt Concurrency-Card mit aktuellem Wert.
2. POST ohne Master-Key (Form-Validation greift) -> 400, kein DB-Update.
3. POST mit falschem Master-Key -> 403, kein Audit-Event.
4. POST mit korrektem Master-Key + N=5 -> 302, Settings-Row aktualisiert,
   Audit-Event ``llm.concurrency_changed`` mit ``from``/``to``-Metadata.
5. POST mit N=0 / N=201 / N="abc" -> 400, Settings unveraendert.
6. POST mit N=5 bei bereits N=5 -> 302 (No-Op), kein Audit-Event.

Annahmen:
  - ``db_app``-Fixture haengt am auto-``todo_mock``-Marker (siehe
    ``tests/conftest.py``); der Default-``pytest``-Lauf inkludiert
    ``todo_mock`` (``addopts = -m "not bench and not integration and not
    acceptance"`` — ``todo_mock`` wird nicht ausgeschlossen).
  - CSRF ist in ``db_app`` deaktiviert; CSRF-Fail-Pfade decken die
    Master-Key-Bestaetigung im View-Handler ab. Der ``csrf_enabled_db_app``-
    Pfad wird hier bewusst nicht angetestet — analog ``test_settings_llm_
    reviewer_db.py`` aus Block P.
  - Master-Key-Vergleich laeuft via ``hmac.compare_digest`` in
    ``app/views/settings.py::_verify_master_key_from_form``.
"""

from __future__ import annotations

import pytest
from flask import Flask
from sqlalchemy import func, select

from app.db import get_session_factory
from app.models import AuditEvent
from app.settings_service import ensure_settings_row
from tests._helpers import (
    DEFAULT_TEST_MASTER_KEY,
    create_admin_user,
    login,
    set_master_key,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_concurrency(app: Flask) -> int:
    """Liest aktuellen ``llm_worker_job_concurrency`` aus der Settings-Row."""
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            return int(row.llm_worker_job_concurrency)
        finally:
            sess.close()


def _set_concurrency(app: Flask, value: int) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            row = ensure_settings_row(sess)
            row.llm_worker_job_concurrency = value
            sess.commit()
        finally:
            sess.close()


def _count_concurrency_audits(app: Flask) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            n = sess.execute(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "llm.concurrency_changed")
            ).scalar()
            return int(n or 0)
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Case 1 — GET zeigt Concurrency-Card
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_llm_reviewer_view_renders_concurrency_card(db_app: Flask) -> None:
    """GET ``/settings/llm-reviewer`` rendert die Concurrency-Card mit Wert."""
    create_admin_user(db_app)
    set_master_key(db_app)
    # Bewusst von Default 1 abweichen, damit der gerenderte Wert eindeutig
    # zur Setting-Row gehoert (Default 1 koennte zufaellig im Page-Body
    # auftauchen).
    _set_concurrency(db_app, 7)
    client = db_app.test_client()
    login(client)

    resp = client.get("/settings/llm-reviewer")
    assert resp.status_code == 200, resp.get_data(as_text=True)[:400]
    body = resp.get_data(as_text=True)

    assert 'data-test="llm-current-concurrency"' in body
    # Der gerenderte Wert steht direkt zwischen den </tag>-Markern.
    assert ">7<" in body, "current_concurrency=7 wird nicht gerendert"


# ---------------------------------------------------------------------------
# Case 2 — POST ohne Master-Key -> 400
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_llm_reviewer_concurrency_post_without_master_key_400(db_app: Flask) -> None:
    """POST ohne ``master_key`` -> Form-Validation 400, kein Update."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_concurrency(db_app, 1)
    before_audits = _count_concurrency_audits(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/concurrency",
        data={"concurrency": "5", "master_key": ""},
    )
    assert resp.status_code == 400, resp.get_data(as_text=True)[:400]
    assert _get_concurrency(db_app) == 1
    assert _count_concurrency_audits(db_app) == before_audits


# ---------------------------------------------------------------------------
# Case 3 — POST mit falschem Master-Key -> 403, kein Audit
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_llm_reviewer_concurrency_post_with_wrong_master_key_403(db_app: Flask) -> None:
    """POST mit falschem Master-Key -> 403, kein Update, kein Audit."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_concurrency(db_app, 1)
    before_audits = _count_concurrency_audits(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/concurrency",
        data={"concurrency": "5", "master_key": "wrong-master-key-abc-12345"},
    )
    assert resp.status_code == 403, resp.get_data(as_text=True)[:400]
    assert _get_concurrency(db_app) == 1
    assert _count_concurrency_audits(db_app) == before_audits


# ---------------------------------------------------------------------------
# Case 4 — POST mit korrektem Master-Key + N=5 -> 302 + Audit
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_llm_reviewer_concurrency_post_succeeds_with_correct_master_key(
    db_app: Flask,
) -> None:
    """Korrekter Master-Key + N=5 -> 302, Setting=5, Audit-Event mit
    ``{from:1, to:5}``."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_concurrency(db_app, 1)
    before_audits = _count_concurrency_audits(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/concurrency",
        data={"concurrency": "5", "master_key": DEFAULT_TEST_MASTER_KEY},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.get_data(as_text=True)[:400]
    assert _get_concurrency(db_app) == 5
    assert _count_concurrency_audits(db_app) == before_audits + 1

    # Letzten Audit-Event verifizieren.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            evt = sess.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "llm.concurrency_changed")
                .order_by(AuditEvent.ts.desc())
                .limit(1)
            ).scalar_one()
            assert evt.event_metadata is not None
            assert evt.event_metadata.get("from") == 1
            assert evt.event_metadata.get("to") == 5
            assert evt.target_type == "settings"
            assert evt.target_id == "1"
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# Case 5 — POST mit N=0 / N=201 / N="abc" -> 400, unveraendert
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
@pytest.mark.parametrize(
    "bad_value",
    ["0", "201", "abc"],
    ids=["below_min", "above_max", "non_int"],
)
def test_llm_reviewer_concurrency_post_invalid_bounds_400(db_app: Flask, bad_value: str) -> None:
    """Out-of-Range / Non-Int -> 400, Setting bleibt unveraendert, kein Audit."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_concurrency(db_app, 3)
    before_audits = _count_concurrency_audits(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/concurrency",
        data={"concurrency": bad_value, "master_key": DEFAULT_TEST_MASTER_KEY},
    )
    assert resp.status_code == 400, (
        bad_value,
        resp.status_code,
        resp.get_data(as_text=True)[:400],
    )
    assert _get_concurrency(db_app) == 3, f"Setting wurde fuer {bad_value!r} veraendert"
    assert _count_concurrency_audits(db_app) == before_audits


# ---------------------------------------------------------------------------
# Case 6 — No-Op (N=5 wenn aktueller Wert 5) -> 302, kein Audit
# ---------------------------------------------------------------------------


@pytest.mark.timeout(15)
def test_llm_reviewer_concurrency_post_noop_when_unchanged(db_app: Flask) -> None:
    """POST N=5 bei aktuellem Wert 5 -> 302 (Redirect), kein Audit-Event."""
    create_admin_user(db_app)
    set_master_key(db_app)
    _set_concurrency(db_app, 5)
    before_audits = _count_concurrency_audits(db_app)
    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/settings/llm-reviewer/concurrency",
        data={"concurrency": "5", "master_key": DEFAULT_TEST_MASTER_KEY},
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303), resp.get_data(as_text=True)[:400]
    assert _get_concurrency(db_app) == 5
    assert _count_concurrency_audits(db_app) == before_audits, (
        "No-Op darf keinen Audit-Event schreiben"
    )
