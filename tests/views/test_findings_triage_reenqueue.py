"""Pure-Unit-Tests: TICKET-010 Etappe 4 — Triage-Aktionen triggern Pass-2-Re-Eval.

Getestete View-Endpunkte (``app/views/findings.py``):

- ``POST /findings/<id>/acknowledge``  → ``acknowledge``
- ``POST /findings/<id>/reopen``       → ``reopen``
- ``POST /findings/group/acknowledge`` → ``group_acknowledge``
- ``POST /findings/bulk/acknowledge``  → ``bulk_acknowledge``

Vertrag (Ticket-Etappe 4):

1. Nach erfolgreichem Status-Write wird ``enqueue_pass2_for_server`` genau
   einmal pro betroffenem Server aufgerufen — mit derselben Session und
   ``trigger="triage_action"``.
2. No-Op-Aktionen (Ack auf bereits-acknowledged, Reopen auf bereits-open,
   Bulk ohne OPEN-Treffer) und Validation-Fehler enqueuen NICHT.
3. Der Enqueue-Aufruf passiert VOR ``commit()`` derselben Session (der
   Helper added LLMJob-Rows in die laufende Transaktion).

Pattern analog ``tests/views/test_findings_bucket_view.py``: View-Funktionen
via ``__wrapped__`` (bypasst ``@login_required``), ``get_session`` /
``log_event`` / ``validate_csrf`` auf Modul-Ebene gepatcht, Spy-Session ohne
DB-Touch. Patch-Ziel fuer den Enqueue-Spy ist der Import-Ort
``app.views.findings.enqueue_pass2_for_server``.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask
from werkzeug.exceptions import HTTPException

import app.views.findings as findings_mod
from app.models import FindingStatus

# ---------------------------------------------------------------------------
# Spies / Fakes
# ---------------------------------------------------------------------------


class _ExecResult:
    """Minimaler Stand-in fuer das SQLAlchemy-`Result`-Objekt."""

    def __init__(self, rows: list[Any] | None = None) -> None:
        self._rows = rows or []

    def scalars(self) -> _ExecResult:
        return self

    def all(self) -> list[Any]:
        return list(self._rows)

    def scalar_one_or_none(self) -> Any:
        return self._rows[0] if self._rows else None


class _SpySession:
    """Spy-Session: SELECTs liefern `select_rows`, UPDATEs werden gezaehlt.

    `call_log` ist die geteilte Sequenz-Liste fuer die Reihenfolge-Asserts
    (Enqueue-Spy schreibt `enqueue:<server_id>`, `commit()` schreibt
    `commit`).
    """

    def __init__(
        self,
        *,
        select_rows: list[Any] | None = None,
        call_log: list[str] | None = None,
    ) -> None:
        self.select_rows = select_rows or []
        self.call_log = call_log if call_log is not None else []
        self.update_statements: list[Any] = []
        self.added: list[Any] = []
        self.flush_count = 0
        self.commit_count = 0

    def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
        sql = str(stmt).lower()
        if sql.startswith("update"):
            self.update_statements.append(stmt)
            return _ExecResult()
        return _ExecResult(rows=list(self.select_rows))

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flush_count += 1

    def commit(self) -> None:
        self.commit_count += 1
        self.call_log.append("commit")


class _FakeFinding:
    """Minimales Finding-Objekt fuer die Einzel-Endpoints."""

    def __init__(
        self,
        fid: int = 100,
        *,
        server_id: int = 7,
        status: FindingStatus = FindingStatus.OPEN,
    ) -> None:
        self.id = fid
        self.server_id = server_id
        self.status = status
        self.acknowledged_at: Any = None
        self.acknowledged_by: Any = None
        self.notes: list[Any] = []


def _patch_enqueue(
    monkeypatch: pytest.MonkeyPatch, call_log: list[str]
) -> list[tuple[Any, int, str]]:
    """Patcht `app.views.findings.enqueue_pass2_for_server` mit einem Spy.

    Returns die Call-Liste `[(session, server_id, trigger), ...]`.
    """
    calls: list[tuple[Any, int, str]] = []

    def spy(sess: Any, server_id: int, *, trigger: str) -> int:
        calls.append((sess, server_id, trigger))
        call_log.append(f"enqueue:{server_id}")
        return 1

    monkeypatch.setattr(findings_mod, "enqueue_pass2_for_server", spy)
    return calls


def _call_inner(view_callable: Any) -> Any:
    """Bypass @login_required -> die nackte Funktion."""
    return getattr(view_callable, "__wrapped__", view_callable)


def _assert_enqueue_before_commit(call_log: list[str]) -> None:
    """Alle Enqueue-Eintraege muessen VOR dem (ersten) commit liegen."""
    assert "commit" in call_log, f"Kein commit im call_log: {call_log}"
    commit_idx = call_log.index("commit")
    enqueue_idxs = [i for i, entry in enumerate(call_log) if entry.startswith("enqueue:")]
    assert enqueue_idxs, f"Kein Enqueue im call_log: {call_log}"
    assert all(i < commit_idx for i in enqueue_idxs), (
        f"Enqueue muss vor commit() derselben Session laufen: {call_log}"
    )


@pytest.fixture
def view_app(app: Flask) -> Flask:
    """App-Fixture ohne CSRF — Forms validieren dann gegen die Form-Daten."""
    app.config.update(WTF_CSRF_ENABLED=False)
    return app


def _setup_single_finding(
    monkeypatch: pytest.MonkeyPatch,
    *,
    finding: _FakeFinding | None,
    call_log: list[str],
) -> tuple[_SpySession, list[tuple[Any, int, str]]]:
    """Gemeinsames Patch-Setup fuer acknowledge/reopen."""
    sess = _SpySession(call_log=call_log)
    monkeypatch.setattr(findings_mod, "get_session", lambda: sess)
    monkeypatch.setattr(findings_mod, "_load_finding", lambda fid: finding)
    monkeypatch.setattr(findings_mod, "log_event", MagicMock())
    calls = _patch_enqueue(monkeypatch, call_log)
    return sess, calls


# ===========================================================================
# POST /findings/<id>/acknowledge
# ===========================================================================


def test_acknowledge_open_finding_enqueues_once_with_trigger_before_commit(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OPEN -> ACK: genau ein Enqueue mit (session, server_id, triage_action)."""
    call_log: list[str] = []
    finding = _FakeFinding(100, server_id=7, status=FindingStatus.OPEN)
    sess, calls = _setup_single_finding(monkeypatch, finding=finding, call_log=call_log)

    inner = _call_inner(findings_mod.acknowledge)
    with view_app.test_request_context("/findings/100/acknowledge", method="POST", data={}):
        inner(100)

    assert len(calls) == 1, f"Genau ein Enqueue erwartet, got {calls}"
    spy_sess, server_id, trigger = calls[0]
    assert spy_sess is sess, "Enqueue muss mit DERSELBEN Session laufen die committet wird"
    assert server_id == 7
    assert trigger == "triage_action"
    assert finding.status == FindingStatus.ACKNOWLEDGED
    assert sess.commit_count == 1
    _assert_enqueue_before_commit(call_log)


def test_acknowledge_already_acknowledged_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-Op-Ack (Finding bereits ACK) -> kein Enqueue, Commit laeuft trotzdem."""
    call_log: list[str] = []
    finding = _FakeFinding(100, server_id=7, status=FindingStatus.ACKNOWLEDGED)
    sess, calls = _setup_single_finding(monkeypatch, finding=finding, call_log=call_log)

    inner = _call_inner(findings_mod.acknowledge)
    with view_app.test_request_context("/findings/100/acknowledge", method="POST", data={}):
        inner(100)

    assert calls == [], f"No-Op-Ack darf NICHT enqueuen: {calls}"
    assert sess.commit_count == 1


def test_acknowledge_validation_error_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Form-Validation-Fehler (Comment > 8 KB) -> kein Enqueue, kein Commit."""
    call_log: list[str] = []
    finding = _FakeFinding(100, server_id=7, status=FindingStatus.OPEN)
    sess, calls = _setup_single_finding(monkeypatch, finding=finding, call_log=call_log)

    inner = _call_inner(findings_mod.acknowledge)
    with view_app.test_request_context(
        "/findings/100/acknowledge",
        method="POST",
        data={"comment": "x" * (8 * 1024 + 1)},
    ):
        inner(100)

    assert calls == [], f"Validation-Fehler darf NICHT enqueuen: {calls}"
    assert sess.commit_count == 0
    assert finding.status == FindingStatus.OPEN, "Status darf sich nicht aendern"


def test_acknowledge_unknown_finding_404_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unbekanntes Finding -> abort(404), kein Enqueue, kein Commit."""
    call_log: list[str] = []
    sess, calls = _setup_single_finding(monkeypatch, finding=None, call_log=call_log)

    inner = _call_inner(findings_mod.acknowledge)
    with (
        view_app.test_request_context("/findings/999/acknowledge", method="POST", data={}),
        pytest.raises(HTTPException) as exc_info,
    ):
        inner(999)

    assert exc_info.value.code == 404
    assert calls == []
    assert sess.commit_count == 0


# ===========================================================================
# POST /findings/<id>/reopen
# ===========================================================================


@pytest.mark.parametrize(
    "previous_status",
    [FindingStatus.ACKNOWLEDGED, FindingStatus.RESOLVED],
)
def test_reopen_enqueues_once_with_trigger_before_commit(
    view_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
    previous_status: FindingStatus,
) -> None:
    """ACK/RESOLVED -> OPEN: genau ein Enqueue mit triage_action vor commit."""
    call_log: list[str] = []
    finding = _FakeFinding(200, server_id=13, status=previous_status)
    sess, calls = _setup_single_finding(monkeypatch, finding=finding, call_log=call_log)

    inner = _call_inner(findings_mod.reopen)
    with view_app.test_request_context("/findings/200/reopen", method="POST", data={}):
        inner(200)

    assert len(calls) == 1, f"Genau ein Enqueue erwartet, got {calls}"
    spy_sess, server_id, trigger = calls[0]
    assert spy_sess is sess
    assert server_id == 13
    assert trigger == "triage_action"
    assert finding.status == FindingStatus.OPEN
    assert sess.commit_count == 1
    _assert_enqueue_before_commit(call_log)


def test_reopen_already_open_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-Op-Reopen (Finding bereits OPEN) -> kein Enqueue, Commit laeuft."""
    call_log: list[str] = []
    finding = _FakeFinding(200, server_id=13, status=FindingStatus.OPEN)
    sess, calls = _setup_single_finding(monkeypatch, finding=finding, call_log=call_log)

    inner = _call_inner(findings_mod.reopen)
    with view_app.test_request_context("/findings/200/reopen", method="POST", data={}):
        inner(200)

    assert calls == [], f"No-Op-Reopen darf NICHT enqueuen: {calls}"
    assert sess.commit_count == 1


def test_reopen_validation_error_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Form-Validation-Fehler -> kein Enqueue, kein Commit."""
    call_log: list[str] = []
    finding = _FakeFinding(200, server_id=13, status=FindingStatus.ACKNOWLEDGED)
    sess, calls = _setup_single_finding(monkeypatch, finding=finding, call_log=call_log)

    inner = _call_inner(findings_mod.reopen)
    with view_app.test_request_context(
        "/findings/200/reopen",
        method="POST",
        data={"comment": "x" * (8 * 1024 + 1)},
    ):
        inner(200)

    assert calls == []
    assert sess.commit_count == 0
    assert finding.status == FindingStatus.ACKNOWLEDGED, "Status darf sich nicht aendern"


# ===========================================================================
# POST /findings/group/acknowledge
# ===========================================================================


def _setup_group(
    monkeypatch: pytest.MonkeyPatch,
    *,
    affected: list[_FakeFinding],
    call_log: list[str],
) -> tuple[_SpySession, list[tuple[Any, int, str]]]:
    sess = _SpySession(select_rows=list(affected), call_log=call_log)
    monkeypatch.setattr(findings_mod, "get_session", lambda: sess)
    monkeypatch.setattr(findings_mod, "log_event", MagicMock())
    calls = _patch_enqueue(monkeypatch, call_log)
    return sess, calls


def test_group_acknowledge_enqueues_once_for_server_before_commit(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group-Ack mit OPEN-Treffern -> genau EIN Enqueue fuer die server_id."""
    call_log: list[str] = []
    affected = [
        _FakeFinding(1, server_id=7),
        _FakeFinding(2, server_id=7),
        _FakeFinding(3, server_id=7),
    ]
    sess, calls = _setup_group(monkeypatch, affected=affected, call_log=call_log)

    inner = _call_inner(findings_mod.group_acknowledge)
    with view_app.test_request_context(
        "/findings/group/acknowledge",
        method="POST",
        data={"server_id": "7", "package_name": "nginx"},
    ):
        inner()

    assert len(calls) == 1, f"Genau ein Enqueue pro Server erwartet, got {calls}"
    spy_sess, server_id, trigger = calls[0]
    assert spy_sess is sess
    assert server_id == 7
    assert trigger == "triage_action"
    assert len(sess.update_statements) == 1, "Status-UPDATE muss gelaufen sein"
    assert sess.commit_count == 1
    _assert_enqueue_before_commit(call_log)


def test_group_acknowledge_no_open_findings_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """0 OPEN-Treffer -> Early-Return: kein UPDATE, kein Enqueue, kein Commit."""
    call_log: list[str] = []
    sess, calls = _setup_group(monkeypatch, affected=[], call_log=call_log)

    inner = _call_inner(findings_mod.group_acknowledge)
    with view_app.test_request_context(
        "/findings/group/acknowledge",
        method="POST",
        data={"server_id": "7", "package_name": "nginx"},
    ):
        inner()

    assert calls == [], f"Leerer Treffer-Set darf NICHT enqueuen: {calls}"
    assert sess.update_statements == []
    assert sess.commit_count == 0


def test_group_acknowledge_validation_error_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlende server_id -> Form invalid: kein Enqueue, kein Commit."""
    call_log: list[str] = []
    sess, calls = _setup_group(
        monkeypatch,
        affected=[_FakeFinding(1, server_id=7)],
        call_log=call_log,
    )

    inner = _call_inner(findings_mod.group_acknowledge)
    with view_app.test_request_context(
        "/findings/group/acknowledge",
        method="POST",
        data={"package_name": "nginx"},  # server_id fehlt -> DataRequired schlaegt fehl
    ):
        inner()

    assert calls == []
    assert sess.update_statements == []
    assert sess.commit_count == 0


# ===========================================================================
# POST /findings/bulk/acknowledge (Bucket-View-Bulk, ADR-0037)
# ===========================================================================


def _setup_bulk(
    monkeypatch: pytest.MonkeyPatch,
    *,
    changed_server_ids: list[int],
    call_log: list[str],
) -> tuple[_SpySession, list[tuple[Any, int, str]]]:
    """Patch-Setup fuer den Bucket-Bulk-Endpoint.

    `changed_server_ids` ist das Ergebnis des distinct-SELECTs VOR dem
    UPDATE (die Spy-Session liefert es fuer jeden SELECT — der einzige
    SELECT im Explicit-IDs-Pfad ist genau dieser).
    """
    sess = _SpySession(select_rows=list(changed_server_ids), call_log=call_log)
    monkeypatch.setattr(findings_mod, "get_session", lambda: sess)
    monkeypatch.setattr(findings_mod, "log_event", MagicMock())
    monkeypatch.setattr(findings_mod, "validate_csrf", lambda token: None)
    calls = _patch_enqueue(monkeypatch, call_log)
    return sess, calls


def test_bulk_acknowledge_multi_server_enqueues_once_per_server(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findings auf 2 Servern -> genau 2 Enqueue-Aufrufe (distinct server_ids)."""
    call_log: list[str] = []
    sess, calls = _setup_bulk(monkeypatch, changed_server_ids=[1, 2], call_log=call_log)

    inner = _call_inner(findings_mod.bulk_acknowledge)
    with view_app.test_request_context(
        "/findings/bulk/acknowledge",
        method="POST",
        data={"finding_ids": json.dumps([5, 6, 7]), "csrf_token": "tok"},
    ):
        inner()

    assert len(calls) == 2, f"Genau 2 Enqueue-Aufrufe (1 pro Server) erwartet, got {calls}"
    assert [c[1] for c in calls] == [1, 2], f"Distinct server_ids erwartet: {calls}"
    assert all(c[0] is sess for c in calls), "Alle Aufrufe mit derselben Session"
    assert all(c[2] == "triage_action" for c in calls), f"Falscher Trigger: {calls}"
    assert len(sess.update_statements) == 1
    assert sess.commit_count == 1
    _assert_enqueue_before_commit(call_log)


def test_bulk_acknowledge_no_status_change_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Findings bereits ACK (changed_server_ids leer) -> kein Enqueue."""
    call_log: list[str] = []
    sess, calls = _setup_bulk(monkeypatch, changed_server_ids=[], call_log=call_log)

    inner = _call_inner(findings_mod.bulk_acknowledge)
    with view_app.test_request_context(
        "/findings/bulk/acknowledge",
        method="POST",
        data={"finding_ids": json.dumps([5, 6]), "csrf_token": "tok"},
    ):
        inner()

    assert calls == [], f"Ohne echten Status-Wechsel darf NICHT enqueued werden: {calls}"
    # Das idempotente UPDATE + Audit laufen trotzdem, der Commit auch.
    assert sess.commit_count == 1


def test_bulk_acknowledge_empty_selection_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leere Auswahl -> Early-Return: kein UPDATE, kein Enqueue, kein Commit."""
    call_log: list[str] = []
    sess, calls = _setup_bulk(monkeypatch, changed_server_ids=[1], call_log=call_log)

    inner = _call_inner(findings_mod.bulk_acknowledge)
    with view_app.test_request_context(
        "/findings/bulk/acknowledge",
        method="POST",
        data={"finding_ids": "[]", "csrf_token": "tok"},
    ):
        inner()

    assert calls == []
    assert sess.update_statements == []
    assert sess.commit_count == 0


def test_bulk_acknowledge_invalid_finding_ids_does_not_enqueue(
    view_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validation-Fehler (nicht-Integer-IDs) -> abort(400), kein Enqueue."""
    call_log: list[str] = []
    sess, calls = _setup_bulk(monkeypatch, changed_server_ids=[1], call_log=call_log)

    inner = _call_inner(findings_mod.bulk_acknowledge)
    with (
        view_app.test_request_context(
            "/findings/bulk/acknowledge",
            method="POST",
            data={"finding_ids": json.dumps(["nope"]), "csrf_token": "tok"},
        ),
        pytest.raises(HTTPException) as exc_info,
    ):
        inner()

    assert exc_info.value.code == 400
    assert calls == []
    assert sess.commit_count == 0
