"""Pure-Unit-API-Tests fuer `POST /api/findings/bulk-acknowledge` (Flavor C).

ADR-0044 / TICKET-009 Etappe 1. Diese Datei ist bewusst DB-FREI: statt der
echten Per-Request-Session wird `app.api.bulk.get_session` auf eine
`_FakeSession`-Spy gepatcht, die `execute`-Aufrufe nach Statement-Form
klassifiziert. Auth wird via `LOGIN_DISABLED=True` neutralisiert (der
`current_user` ist dann anonym -> `username='unknown'`, `id=None`).

So laufen Response-Shape-, SQL-Shape-, Note-Insert- und Audit-Metadata-Asserts
ohne echtes Postgres. Der Builder `_build_server_scope_query` wird zusaetzlich
direkt auf seine kompilierte SQL-Form geprueft (kein LIMIT, WHERE-Spalten).

Die DB-getriebenen Roundtrip-Tests (echter UPDATE, persistierter Audit-Row)
leben in `tests/integration/test_bulk_acknowledge_db.py` (db_integration) und
sind hier bewusst NICHT dupliziert.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from sqlalchemy import update
from sqlalchemy.dialects import postgresql

import app.api.bulk as bulk_mod
from app.models import Finding, FindingStatus
from app.schemas.bulk_request import BulkAckServerScope

# ---------------------------------------------------------------------------
# Fake-Session-Spy (kein DB-Touch)
# ---------------------------------------------------------------------------


class _ExecResult:
    """Minimaler Stand-in fuer das SQLAlchemy-`Result`-Objekt."""

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
        # Bei diesem Spy sind die Zeilen schon „skalar" (einfache Werte),
        # daher reicht es, dasselbe Result zurueckzugeben.
        return self


class _FakeSession:
    """Spy-Session: klassifiziert `execute`-Calls anhand der SQL-Form.

    Konfigurierbar pro Test:
      - `server_active`:   ob der Guard-SELECT eine Zeile liefert.
      - `count`:           Anzahl fuer den dry_run-COUNT.
      - `scope_ids`:       IDs, die der Scope-ID-Projektion zurueckgegeben werden.
      - `update_rowcount`: rowcount, das das Apply-UPDATE liefert.
      - `note_ids`:        IDs, die die Note-ID-Reselektion zurueckgibt.
    """

    def __init__(
        self,
        *,
        server_active: bool = True,
        count: int = 0,
        scope_ids: list[int] | None = None,
        update_rowcount: int = 0,
        note_ids: list[int] | None = None,
    ) -> None:
        self.server_active = server_active
        self._count = count
        self._scope_ids = scope_ids or []
        self._update_rowcount = update_rowcount
        self._note_ids = note_ids or []

        # Spy-Aufzeichnungen.
        self.executed: list[Any] = []
        self.update_statements: list[Any] = []
        self.insert_statements: list[tuple[Any, Any]] = []
        self.added: list[Any] = []
        self.flush_count = 0
        self.commit_count = 0

    # -- Klassifizierung --------------------------------------------------
    @staticmethod
    def _sql(stmt: Any) -> str:
        try:
            return str(stmt).lower()
        except Exception:  # pragma: no cover - defensiv
            return ""

    def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
        self.executed.append(stmt)
        sql = self._sql(stmt)

        # INSERT (Notes-Bulk-Insert).
        if sql.startswith("insert"):
            self.insert_statements.append((stmt, params))
            return _ExecResult(rowcount=len(params) if isinstance(params, list) else 1)

        # UPDATE (Apply).
        if sql.startswith("update"):
            self.update_statements.append(stmt)
            return _ExecResult(rowcount=self._update_rowcount)

        # SELECT-Varianten unterscheiden.
        # 1) Server-Guard: SELECT servers.id ... revoked_at IS NULL ...
        if "from servers" in sql:
            return _ExecResult(rows=[(1,)] if self.server_active else [])

        # 2) COUNT(*)
        if "count(" in sql:
            return _ExecResult(rows=[self._count])

        # 3) Note-ID-Reselect: SELECT finding_notes.id ...
        if "from finding_notes" in sql:
            return _ExecResult(rows=list(self._note_ids))

        # 4) Scope-ID-Projektion: SELECT findings.id ... (Apply-Pfad).
        if "findings.id" in sql:
            return _ExecResult(rows=list(self._scope_ids))

        return _ExecResult(rows=[])

    # -- Mutationen -------------------------------------------------------
    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        self.flush_count += 1

    def commit(self) -> None:
        self.commit_count += 1


@pytest.fixture
def nodb_app(app: Flask, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """App mit deaktiviertem Login + neutralisiertem Limiter — kein DB-Touch."""
    app.config.update(TESTING=True, LOGIN_DISABLED=True, WTF_CSRF_ENABLED=False)
    # Limiter zwischen Tests platt machen (sonst kumulieren 30/min ueber Tests).
    import contextlib

    from app import limiter

    with contextlib.suppress(Exception):
        limiter.reset()
    return app


def _patch_session(monkeypatch: pytest.MonkeyPatch, sess: _FakeSession) -> None:
    monkeypatch.setattr(bulk_mod, "get_session", lambda: sess)


def _audit_metadata(sess: _FakeSession) -> dict[str, Any]:
    """Liefert die `event_metadata` des einzigen Audit-Events der Spy."""
    events = [obj for obj in sess.added if obj.__class__.__name__ == "AuditEvent"]
    assert len(events) == 1, f"Erwartet genau 1 Audit-Event, got {len(events)}"
    md = events[0].event_metadata
    assert isinstance(md, dict)
    return md


# ===========================================================================
# SQL-Shape: Builder direkt
# ===========================================================================


def test_server_scope_query_shape_has_where_and_no_limit() -> None:
    """Test 7: kompiliertes SQL traegt server_id/risk_band/status, kein LIMIT."""
    scope = BulkAckServerScope(server_id=42, risk_band="noise")
    stmt = bulk_mod._build_server_scope_query(scope)
    sql = str(stmt.compile(dialect=postgresql.dialect())).lower()
    assert "server_id" in sql, sql
    assert "risk_band" in sql, sql
    assert "status" in sql, sql
    assert "limit" not in sql, f"Scope-Query darf kein LIMIT tragen: {sql}"


def test_apply_update_statement_shape_has_no_limit() -> None:
    """Der Apply-UPDATE-WHERE traegt server_id/risk_band/status, kein LIMIT."""
    scope = BulkAckServerScope(server_id=7, risk_band="act")
    stmt = (
        update(Finding)
        .where(
            Finding.server_id == scope.server_id,
            Finding.status == FindingStatus.OPEN,
            Finding.risk_band == scope.risk_band,
        )
        .values(status=FindingStatus.ACKNOWLEDGED)
    )
    sql = str(stmt.compile(dialect=postgresql.dialect())).lower()
    assert sql.startswith("update findings"), sql
    assert "server_id" in sql
    assert "risk_band" in sql
    assert "status" in sql
    assert "limit" not in sql, f"Apply-UPDATE darf kein LIMIT tragen: {sql}"


# ===========================================================================
# dry_run Flavor C
# ===========================================================================


def test_dry_run_flavor_c_returns_count_and_scope_no_update(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 5: dry_run -> count + server_scope, KEIN examples/finding_ids, kein UPDATE."""
    sess = _FakeSession(server_active=True, count=3)
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 1, "risk_band": "noise"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["dry_run"] is True
    assert body["count"] == 3
    assert body["server_scope"] == {"server_id": 1, "risk_band": "noise"}
    # Flavor-C-dry_run liefert KEIN examples / finding_ids / server_count
    # (ADR-0044-Amendment: Band-UI rendert den Count server-seitig).
    assert "examples" not in body
    assert "finding_ids" not in body
    assert "server_count" not in body
    # Kein UPDATE, kein Insert, kein Commit im dry_run.
    assert sess.update_statements == []
    assert sess.insert_statements == []
    assert sess.commit_count == 0


def test_dry_run_flavor_c_empty_band(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test 6: Band ohne Findings -> count=0, kein examples-Key."""
    sess = _FakeSession(server_active=True, count=0)
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 1, "risk_band": "monitor"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 0
    assert "examples" not in body
    assert "finding_ids" not in body
    assert sess.update_statements == []


# ===========================================================================
# apply Flavor C
# ===========================================================================


def test_apply_flavor_c_executes_update_no_limit(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 7: Apply fuehrt genau ein UPDATE aus, dessen SQL kein LIMIT traegt."""
    sess = _FakeSession(server_active=True, update_rowcount=12)
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 4, "risk_band": "act"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["dry_run"] is False
    assert body["applied"] is True
    assert body["count"] == 12
    assert body["server_scope"] == {"server_id": 4, "risk_band": "act"}
    # Kein finding_ids/skipped in der Flavor-C-Apply-Response.
    assert "finding_ids" not in body
    assert "skipped" not in body

    assert len(sess.update_statements) == 1, "Genau ein UPDATE erwartet"
    sql = str(sess.update_statements[0].compile(dialect=postgresql.dialect())).lower()
    assert sql.startswith("update findings")
    assert "server_id" in sql
    assert "risk_band" in sql
    assert "status" in sql
    assert "limit" not in sql
    assert sess.commit_count == 1


def test_apply_flavor_c_without_comment_no_notes(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne Kommentar wird kein Note-Insert ausgefuehrt (ADR-0006)."""
    sess = _FakeSession(server_active=True, update_rowcount=5, scope_ids=[10, 11, 12, 13, 14])
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 4, "risk_band": "noise"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert sess.insert_statements == [], "Ohne Kommentar darf kein Note-Insert laufen"
    # Audit traegt trotzdem finding_ids (befuellt, <=50) ohne Kommentar.
    md = _audit_metadata(sess)
    assert md["has_comment"] is False
    assert md["finding_ids"] == [10, 11, 12, 13, 14]


def test_apply_flavor_c_with_comment_single_note_insert(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 8: mit Kommentar -> genau EIN Insert-Execute, author='system-bulk-ack'."""
    scope_ids = [101, 102, 103]
    sess = _FakeSession(
        server_active=True,
        update_rowcount=3,
        scope_ids=scope_ids,
        note_ids=[201, 202, 203],
    )
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "server_scope": {"server_id": 4, "risk_band": "noise"},
            "dry_run": False,
            "comment": "Patch-Window naechste Woche",
        },
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)

    # GENAU ein Insert-Execute fuer FindingNotes.
    assert len(sess.insert_statements) == 1, "Notes muessen als EIN Bulk-Insert laufen"
    _stmt, rows = sess.insert_statements[0]
    assert isinstance(rows, list)
    assert len(rows) == len(scope_ids)
    for row in rows:
        assert row["author"] == "system-bulk-ack", row
        assert row["text"] == "Patch-Window naechste Woche"
    # Note-IDs landen im Audit.
    md = _audit_metadata(sess)
    assert md["note_ids"] == [201, 202, 203]
    assert md["has_comment"] is True


def test_apply_flavor_c_audit_caps_finding_ids_at_50(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 9: > 50 betroffene Findings -> finding_ids <=50, count voll.

    Mit Kommentar (open_ids = ALLE IDs) -> Audit cappt auf [:50].
    """
    scope_ids = list(range(1000, 1000 + 137))  # 137 betroffene IDs
    sess = _FakeSession(
        server_active=True,
        update_rowcount=137,
        scope_ids=scope_ids,
        note_ids=list(range(5000, 5000 + 137)),
    )
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "server_scope": {"server_id": 4, "risk_band": "escalate"},
            "dry_run": False,
            "comment": "Mass-ack",
        },
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 137, "Response-count traegt die volle Zahl"

    md = _audit_metadata(sess)
    assert md["count"] == 137, "Audit-count traegt die volle Zahl"
    assert len(md["finding_ids"]) == bulk_mod._AUDIT_FINDING_IDS_CAP == 50
    assert md["finding_ids"] == scope_ids[:50]
    assert md["server_scope"] == {"server_id": 4, "risk_band": "escalate"}


def test_apply_flavor_c_audit_finding_ids_populated_without_comment_over_50(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 9 (Ohne-Kommentar-Variante): finding_ids befuellt <=50, count voll.

    Ohne Kommentar holt der Endpoint nur bis zu 50 IDs (LIMIT 50) fuers Audit.
    Die Spy liefert genau diese (auf 50 begrenzten) IDs zurueck.
    """
    capped_ids = list(range(2000, 2050))  # 50 IDs (Endpoint LIMIT 50)
    sess = _FakeSession(
        server_active=True,
        update_rowcount=200,
        scope_ids=capped_ids,
    )
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 4, "risk_band": "noise"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 200

    md = _audit_metadata(sess)
    assert md["count"] == 200
    assert md["has_comment"] is False
    assert len(md["finding_ids"]) <= bulk_mod._AUDIT_FINDING_IDS_CAP
    assert md["finding_ids"] == capped_ids
    # Ohne Kommentar kein Note-Insert.
    assert sess.insert_statements == []


# ===========================================================================
# 404 — unbekannter/revoked/retired Server
# ===========================================================================


@pytest.mark.parametrize("dry_run", [True, False])
def test_flavor_c_unknown_server_returns_404_no_update(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch, dry_run: bool
) -> None:
    """Test 10: inaktiver Server -> 404 server_not_found, kein UPDATE/Commit."""
    sess = _FakeSession(server_active=False)
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 999, "risk_band": "noise"}, "dry_run": dry_run},
    )
    assert resp.status_code == 404, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["error"]["code"] == "server_not_found"
    assert sess.update_statements == []
    assert sess.insert_statements == []
    assert sess.commit_count == 0
    # Kein Audit-Event bei 404.
    assert [o for o in sess.added if o.__class__.__name__ == "AuditEvent"] == []


# ===========================================================================
# Regression Flavor A / B (Happy-Path, kein DB)
# ===========================================================================


def test_regression_flavor_a_dry_run(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test 11: Flavor A dry_run liefert weiter count/server_count/finding_ids."""

    class _Find:
        def __init__(self, fid: int, server_id: int) -> None:
            self.id = fid
            self.server_id = server_id
            self.status = FindingStatus.OPEN
            self.risk_band = "act"

    class _FlavorASession(_FakeSession):
        def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
            self.executed.append(stmt)
            sql = str(stmt).lower()
            if sql.startswith("select") and "from findings" in sql:
                return _ExecResult(rows=[_Find(1, 7), _Find(2, 7)])
            return _ExecResult(rows=[])

    sess = _FlavorASession()
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [1, 2], "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["dry_run"] is True
    assert body["count"] == 2
    assert body["server_count"] == 1
    assert sorted(body["finding_ids"]) == [1, 2]
    # dry_run schreibt nichts.
    assert sess.commit_count == 0


def test_regression_flavor_b_dry_run(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test 11: Flavor B (match) dry_run-Happy-Path unveraendert."""

    class _Find:
        def __init__(self, fid: int, server_id: int) -> None:
            self.id = fid
            self.server_id = server_id
            self.status = FindingStatus.OPEN
            self.risk_band = "act"

    class _FlavorBSession(_FakeSession):
        def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
            self.executed.append(stmt)
            sql = str(stmt).lower()
            if sql.startswith("select") and "from findings" in sql:
                return _ExecResult(rows=[_Find(11, 3), _Find(12, 4)])
            return _ExecResult(rows=[])

    sess = _FlavorBSession()
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-2024-12345"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 2
    assert body["server_count"] == 2
    assert sorted(body["finding_ids"]) == [11, 12]
    assert sess.commit_count == 0


# ===========================================================================
# TICKET-010 Etappe 4 — Triage-Aktion triggert Pass-2-Re-Eval
# ===========================================================================
#
# Vertrag: nach erfolgreichem Status-Write ruft der Endpoint
# `enqueue_pass2_for_server(sess, server_id, trigger="triage_action")` —
# genau einmal pro betroffenem Server, VOR `sess.commit()`. Bei dry_run,
# rowcount=0, leerem Treffer-Set oder Validation-Fehler: KEIN Aufruf.
# Patch-Ziel ist der Import-Ort `app.api.bulk.enqueue_pass2_for_server`.


class _FindingStub:
    """Finding-Stub fuer die Flavor-A/B-Apply-Pfade."""

    def __init__(
        self,
        fid: int,
        server_id: int,
        status: FindingStatus = FindingStatus.OPEN,
    ) -> None:
        self.id = fid
        self.server_id = server_id
        self.status = status
        self.risk_band = "act"


class _FindingsSelectSession(_FakeSession):
    """Spy-Session deren Findings-SELECT konfigurierte Stubs liefert."""

    def __init__(self, findings: list[_FindingStub], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._findings = findings

    def execute(self, stmt: Any, params: Any = None) -> _ExecResult:
        sql = self._sql(stmt)
        # COUNT-Statements (Flavor-C-dry_run) enthalten "from findings" im
        # Subquery — die gehoeren weiter der Basis-Klassifizierung.
        if sql.startswith("select") and "from findings" in sql and "count(" not in sql:
            self.executed.append(stmt)
            return _ExecResult(rows=list(self._findings))
        return super().execute(stmt, params)


def _patch_enqueue(
    monkeypatch: pytest.MonkeyPatch, call_log: list[str]
) -> list[tuple[Any, int, str]]:
    """Patcht `app.api.bulk.enqueue_pass2_for_server` mit einem Spy."""
    calls: list[tuple[Any, int, str]] = []

    def spy(sess: Any, server_id: int, *, trigger: str) -> int:
        calls.append((sess, server_id, trigger))
        call_log.append(f"enqueue:{server_id}")
        return 1

    monkeypatch.setattr(bulk_mod, "enqueue_pass2_for_server", spy)
    return calls


def _track_commit(sess: _FakeSession, call_log: list[str]) -> None:
    """Haengt einen `commit`-Eintrag in die geteilte Sequenz-Liste."""
    orig_commit = sess.commit

    def commit() -> None:
        call_log.append("commit")
        orig_commit()

    sess.commit = commit  # type: ignore[method-assign]


def _assert_enqueue_before_commit(call_log: list[str]) -> None:
    assert "commit" in call_log, f"Kein commit im call_log: {call_log}"
    commit_idx = call_log.index("commit")
    enqueue_idxs = [i for i, entry in enumerate(call_log) if entry.startswith("enqueue:")]
    assert enqueue_idxs, f"Kein Enqueue im call_log: {call_log}"
    assert all(i < commit_idx for i in enqueue_idxs), (
        f"Enqueue muss vor commit() derselben Session laufen: {call_log}"
    )


def test_apply_flavor_c_enqueues_pass2_once_before_commit(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flavor C Apply mit rowcount>0 -> genau ein Enqueue, vor commit."""
    call_log: list[str] = []
    sess = _FakeSession(server_active=True, update_rowcount=12, scope_ids=[10, 11])
    _track_commit(sess, call_log)
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 4, "risk_band": "act"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert len(calls) == 1, f"Genau ein Enqueue erwartet, got {calls}"
    spy_sess, server_id, trigger = calls[0]
    assert spy_sess is sess, "Enqueue muss mit DERSELBEN Session laufen die committet wird"
    assert server_id == 4
    assert trigger == "triage_action"
    _assert_enqueue_before_commit(call_log)


def test_apply_flavor_c_rowcount_zero_does_not_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flavor C Apply mit rowcount=0 (Band leer/schon ACK) -> kein Enqueue."""
    call_log: list[str] = []
    sess = _FakeSession(server_active=True, update_rowcount=0, scope_ids=[])
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 4, "risk_band": "noise"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert calls == [], f"rowcount=0 darf NICHT enqueuen: {calls}"
    assert sess.commit_count == 1, "Commit (Audit-Event) laeuft trotzdem"


@pytest.mark.parametrize(
    "body",
    [
        {"server_scope": {"server_id": 4, "risk_band": "act"}, "dry_run": True},
        {"finding_ids": [1, 2], "dry_run": True},
        {"match": {"cve_id": "CVE-2024-12345"}, "dry_run": True},
    ],
    ids=["flavor_c", "flavor_a", "flavor_b"],
)
def test_dry_run_does_not_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]
) -> None:
    """dry_run=true -> kein Status-Write, kein Enqueue (alle Flavors)."""
    call_log: list[str] = []
    sess = _FindingsSelectSession(
        [_FindingStub(1, 7), _FindingStub(2, 8)],
        server_active=True,
        count=2,
    )
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post("/api/findings/bulk-acknowledge", json=body)
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert calls == [], f"dry_run darf NICHT enqueuen: {calls}"
    assert sess.commit_count == 0


def test_flavor_c_unknown_server_does_not_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """404-Guard (revoked/retired/unbekannt) -> kein Enqueue."""
    call_log: list[str] = []
    sess = _FakeSession(server_active=False)
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 999, "risk_band": "act"}, "dry_run": False},
    )
    assert resp.status_code == 404, resp.get_data(as_text=True)
    assert calls == []


def test_apply_flavor_a_enqueues_once_per_distinct_server(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flavor A Apply, OPEN-Findings auf 2 Servern -> genau 2 Enqueue-Aufrufe."""
    call_log: list[str] = []
    findings = [
        _FindingStub(1, server_id=7),
        _FindingStub(2, server_id=8),
        _FindingStub(3, server_id=7),  # zweites Finding auf Server 7 -> kein 3. Call
    ]
    sess = _FindingsSelectSession(findings)
    _track_commit(sess, call_log)
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [1, 2, 3], "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert len(calls) == 2, f"Genau 2 Enqueue-Aufrufe (1 pro Server) erwartet, got {calls}"
    assert [c[1] for c in calls] == [7, 8], f"Distinct, sortierte server_ids erwartet: {calls}"
    assert all(c[0] is sess for c in calls), "Alle Aufrufe mit derselben Session"
    assert all(c[2] == "triage_action" for c in calls), f"Falscher Trigger: {calls}"
    _assert_enqueue_before_commit(call_log)


def test_apply_flavor_a_all_already_acknowledged_does_not_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flavor A Apply, alle Findings bereits ACK (skipped) -> kein Enqueue."""
    call_log: list[str] = []
    findings = [
        _FindingStub(1, server_id=7, status=FindingStatus.ACKNOWLEDGED),
        _FindingStub(2, server_id=8, status=FindingStatus.RESOLVED),
    ]
    sess = _FindingsSelectSession(findings)
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"finding_ids": [1, 2], "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 0
    assert body["skipped"] == 2
    assert calls == [], f"Ohne echten Status-Wechsel darf NICHT enqueued werden: {calls}"
    assert sess.update_statements == [], "Kein UPDATE wenn open_ids leer"
    assert sess.commit_count == 1


def test_apply_flavor_b_zero_matches_does_not_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Flavor B Apply ohne Treffer -> Leerlauf-Audit, kein Enqueue."""
    call_log: list[str] = []
    sess = _FindingsSelectSession([])
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"match": {"cve_id": "CVE-2024-12345"}, "dry_run": False},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 0
    assert calls == [], f"0 Treffer darf NICHT enqueuen: {calls}"
    assert sess.commit_count == 1


def test_validation_error_does_not_enqueue(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """422 (kein Flavor befuellt) -> kein Enqueue, kein Commit."""
    call_log: list[str] = []
    sess = _FakeSession()
    _patch_session(monkeypatch, sess)
    calls = _patch_enqueue(monkeypatch, call_log)
    client = nodb_app.test_client()

    resp = client.post("/api/findings/bulk-acknowledge", json={"dry_run": False})
    assert resp.status_code == 422, resp.get_data(as_text=True)
    assert calls == []
    assert sess.commit_count == 0
