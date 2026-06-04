"""Adversarial: server-scoped Bulk-Ack (Flavor C, ADR-0044 / TICKET-009).

Rohe JSON-POSTs gegen `POST /api/findings/bulk-acknowledge`. Schwerpunkt:
Band-Whitelist, XOR-Verletzung, SQL-Metazeichen/Array im `risk_band` und
fehlerhafte `server_id`-Typen. Erwartung durchgaengig: 422 (Pydantic) bzw.
404 (Guard) — NIE 500, und in keinem Fall ein DB-Write.

Diese Datei ist bewusst DB-FREI: `app.api.bulk.get_session` wird auf eine
Spy gepatcht, die jeden `execute`/`commit` aufzeichnet, damit „kein DB-Write"
hart verifiziert wird. Auth via `LOGIN_DISABLED=True`. 422-Faelle scheitern an
Pydantic VOR jedem Session-Zugriff; der Spy belegt das (keine UPDATE/Inserts).
"""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask

import app.api.bulk as bulk_mod


class _ExecResult:
    def __init__(self, *, rows: list[Any] | None = None, rowcount: int = 0) -> None:
        self._rows = rows or []
        self.rowcount = rowcount

    def first(self) -> Any:
        return self._rows[0] if self._rows else None

    def all(self) -> list[Any]:
        return list(self._rows)

    def scalar_one(self) -> Any:
        return self._rows[0]

    def scalar(self) -> Any:
        return self._rows[0] if self._rows else None

    def scalars(self) -> _ExecResult:
        return self


class _SpySession:
    """Zeichnet jeden Schreibpfad auf — server-Guard liefert „nicht aktiv"."""

    def __init__(self, *, server_active: bool = False) -> None:
        self.server_active = server_active
        self.writes: list[str] = []
        self.executed: list[Any] = []
        self.commit_count = 0

    def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
        self.executed.append(stmt)
        sql = str(stmt).lower()
        if sql.startswith(("update", "insert")):
            self.writes.append(sql.split()[0])
            return _ExecResult(rowcount=0)
        if "from servers" in sql:
            return _ExecResult(rows=[(1,)] if self.server_active else [])
        if "count(" in sql:
            return _ExecResult(rows=[0])
        return _ExecResult(rows=[])

    def add(self, obj: Any) -> None:
        self.writes.append(f"add:{obj.__class__.__name__}")

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.commit_count += 1


@pytest.fixture
def adv_app(app: Flask, monkeypatch: pytest.MonkeyPatch) -> tuple[Flask, _SpySession]:
    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=False)
    import contextlib

    from app import limiter

    with contextlib.suppress(Exception):
        limiter.reset()
    sess = _SpySession(server_active=False)
    monkeypatch.setattr(bulk_mod, "get_session", lambda: sess)
    return app, sess


def _assert_no_write(sess: _SpySession) -> None:
    assert sess.writes == [], f"Es darf kein DB-Write erfolgen, got {sess.writes}"
    assert sess.commit_count == 0


# ===========================================================================
# 1) risk_band="pending" -> 422, kein DB-Write
# ===========================================================================


@pytest.mark.parametrize("bad_band", ["pending", "unknown", "", "NOISE"])
def test_pending_band_rejected_422_no_write(
    adv_app: tuple[Flask, _SpySession], bad_band: str
) -> None:
    app, sess = adv_app
    client = app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 1, "risk_band": bad_band}, "dry_run": False},
    )
    assert resp.status_code == 422, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["error"]["code"] == "validation_error"
    _assert_no_write(sess)


# ===========================================================================
# 2) XOR — server_scope + finding_ids zusammen -> 422
# ===========================================================================


def test_server_scope_plus_finding_ids_is_422_not_both(
    adv_app: tuple[Flask, _SpySession],
) -> None:
    app, sess = adv_app
    client = app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "server_scope": {"server_id": 1, "risk_band": "noise"},
            "finding_ids": [1, 2, 3],
            "dry_run": False,
        },
    )
    assert resp.status_code == 422, resp.get_data(as_text=True)
    _assert_no_write(sess)


def test_server_scope_plus_match_is_422(adv_app: tuple[Flask, _SpySession]) -> None:
    app, sess = adv_app
    client = app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "server_scope": {"server_id": 1, "risk_band": "noise"},
            "match": {"cve_id": "CVE-2024-12345"},
            "dry_run": False,
        },
    )
    assert resp.status_code == 422, resp.get_data(as_text=True)
    _assert_no_write(sess)


# ===========================================================================
# 3) SQL-Metazeichen / Array in risk_band -> 422
# ===========================================================================


@pytest.mark.parametrize(
    "evil_band",
    [
        "noise' OR '1'='1",
        "noise; DROP TABLE findings;--",
        ["noise"],
        {"band": "noise"},
        123,
        "noise\x00",
    ],
)
def test_sql_metachar_or_wrong_type_band_is_422(
    adv_app: tuple[Flask, _SpySession], evil_band: Any
) -> None:
    app, sess = adv_app
    client = app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 1, "risk_band": evil_band}, "dry_run": False},
    )
    assert resp.status_code == 422, resp.get_data(as_text=True)
    _assert_no_write(sess)


# ===========================================================================
# 4) server_id als String/Float/Overflow -> 422 oder 404, nie 500
# ===========================================================================


@pytest.mark.parametrize(
    "evil_id",
    [
        "1; DROP TABLE servers",
        "abc",
        1.5,
        2.0,  # float ohne Nachkomma — Pydantic-strict lehnt float->int ggf. ab
        ["1"],
        {"id": 1},
        -1,
        0,
        10**30,  # Overflow weit jenseits int64
        "0x10",
    ],
)
def test_server_id_bad_type_is_422_or_404_never_500(
    adv_app: tuple[Flask, _SpySession], evil_id: Any
) -> None:
    app, sess = adv_app
    client = app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": evil_id, "risk_band": "noise"}, "dry_run": False},
    )
    assert resp.status_code in (422, 404), (
        f"server_id={evil_id!r} -> {resp.status_code}: {resp.get_data(as_text=True)}"
    )
    assert resp.status_code != 500
    # Egal ob 422 (Validierung) oder 404 (Guard, server_active=False):
    # in keinem Fall darf ein UPDATE/INSERT/Audit/Commit passieren.
    _assert_no_write(sess)


def test_missing_content_type_is_400_no_write(adv_app: tuple[Flask, _SpySession]) -> None:
    """Roher Body ohne application/json -> 400, kein DB-Write."""
    app, sess = adv_app
    client = app.test_client()
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        data=b'{"server_scope": {"server_id": 1, "risk_band": "noise"}}',
        content_type="text/plain",
    )
    assert resp.status_code == 400, resp.get_data(as_text=True)
    _assert_no_write(sess)
