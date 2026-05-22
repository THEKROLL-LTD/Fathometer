"""Integration-Smokes fuer ``app.services.llm_budget`` gegen echte
Postgres-DB.

Diese Tests wurden aus ``tests/workers/test_token_budget.py`` ausgelagert
(TICKET-004, Slice 6). Die rein funktionalen Helfer (``_next_utc_midnight``,
``estimate_tokens``) liegen DB-frei in der Worker-Test-Datei. Hier verbleiben
die Roundtrips durch ``settings`` und ``audit_events``:

* ``budget_check`` (Tages-Cap-Lese-Vergleich).
* ``budget_consume`` (Increment + Commit).
* ``maybe_reset_budget`` (Reset bei Faelligkeit, naechste 00:00 UTC).
* ``mark_exhausted_audit_once`` (Idempotenz pro Reset-Zyklus).

Auto-Markierung als ``db_integration`` (und damit ``acceptance``) erfolgt
ueber ``tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES``.
"""

from __future__ import annotations

from datetime import UTC, datetime, time, timedelta

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AuditEvent
from app.services.llm_budget import (
    budget_check,
    budget_consume,
    mark_exhausted_audit_once,
    maybe_reset_budget,
)
from app.settings_service import ensure_settings_row


def _open_session(app: Flask) -> object:
    return get_session_factory(app)()


def test_budget_check_true_when_under_limit(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECSCAN_LLM_TOKEN_BUDGET_DAILY", "10000")
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 100
            sess.commit()
            assert budget_check(sess) is True
    finally:
        sess.close()


def test_budget_check_false_at_or_above_limit(
    db_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECSCAN_LLM_TOKEN_BUDGET_DAILY", "5000")
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 5000
            sess.commit()
            assert budget_check(sess) is False
            row.llm_token_budget_used_today = 7777
            sess.commit()
            assert budget_check(sess) is False
    finally:
        sess.close()


def test_budget_consume_increments(db_app: Flask) -> None:
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 100
            sess.commit()
            new = budget_consume(sess, 250)
            assert new == 350
            row = ensure_settings_row(sess)
            assert row.llm_token_budget_used_today == 350
    finally:
        sess.close()


def test_budget_consume_negative_caps_to_zero(db_app: Flask) -> None:
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 50
            sess.commit()
            new = budget_consume(sess, -999)
            assert new == 50  # unveraendert
    finally:
        sess.close()


def test_maybe_reset_budget_resets_when_due(db_app: Flask) -> None:
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 999
            # Reset-Zeitpunkt in der Vergangenheit.
            row.llm_token_budget_reset_at = datetime.now(UTC) - timedelta(hours=1)
            sess.commit()
            assert maybe_reset_budget(sess) is True
            row = ensure_settings_row(sess)
            assert row.llm_token_budget_used_today == 0
            # reset_at muss in der Zukunft sein und um 00:00 UTC liegen.
            assert row.llm_token_budget_reset_at > datetime.now(UTC)
            assert row.llm_token_budget_reset_at.astimezone(UTC).time() == time(0, 0, 0)
    finally:
        sess.close()


def test_maybe_reset_budget_noop_when_not_due(db_app: Flask) -> None:
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            row.llm_token_budget_used_today = 42
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=5)
            sess.commit()
            assert maybe_reset_budget(sess) is False
            row = ensure_settings_row(sess)
            assert row.llm_token_budget_used_today == 42
    finally:
        sess.close()


def test_mark_exhausted_audit_once(db_app: Flask) -> None:
    sess = _open_session(db_app)
    try:
        with db_app.app_context():
            row = ensure_settings_row(sess)
            # Reset-Zyklus startet in 6h.
            row.llm_token_budget_reset_at = datetime.now(UTC) + timedelta(hours=6)
            sess.commit()
            assert mark_exhausted_audit_once(sess) is True
            # Zweiter Aufruf: kein neuer Audit.
            assert mark_exhausted_audit_once(sess) is False
            audits = (
                sess.execute(select(AuditEvent).where(AuditEvent.action == "llm.budget_exhausted"))
                .scalars()
                .all()
            )
            assert len(audits) == 1
    finally:
        sess.close()
