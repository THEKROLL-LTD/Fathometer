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
      - `examples`:        Roh-Zeilen (Tuples) fuer die examples-Projektion.
      - `scope_ids`:       IDs, die der Scope-ID-Projektion zurueckgegeben werden.
      - `update_rowcount`: rowcount, das das Apply-UPDATE liefert.
      - `note_ids`:        IDs, die die Note-ID-Reselektion zurueckgibt.
    """

    def __init__(
        self,
        *,
        server_active: bool = True,
        count: int = 0,
        examples: list[tuple[str, str]] | None = None,
        scope_ids: list[int] | None = None,
        update_rowcount: int = 0,
        note_ids: list[int] | None = None,
    ) -> None:
        self.server_active = server_active
        self._count = count
        self._examples = examples or []
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

        # 4) examples-Projektion: identifier_key + package_name, order by ident
        if "identifier_key" in sql and "package_name" in sql:
            return _ExecResult(rows=list(self._examples))

        # 5) Scope-ID-Projektion: SELECT findings.id ... (Apply-Pfad).
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


def test_dry_run_flavor_c_returns_count_and_examples_no_update(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 5: dry_run -> count + examples (<=5), KEIN finding_ids, kein UPDATE."""
    sess = _FakeSession(
        server_active=True,
        count=3,
        examples=[
            ("CVE-2024-0001", "openssl"),
            ("CVE-2024-0002", "libxml2"),
            ("CVE-2024-0003", "zlib"),
        ],
    )
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
    assert len(body["examples"]) == 3
    assert body["examples"][0] == {"identifier_key": "CVE-2024-0001", "package_name": "openssl"}
    assert body["server_scope"] == {"server_id": 1, "risk_band": "noise"}
    # Flavor-C-dry_run liefert KEIN finding_ids / server_count.
    assert "finding_ids" not in body
    assert "server_count" not in body
    # Kein UPDATE, kein Insert, kein Commit im dry_run.
    assert sess.update_statements == []
    assert sess.insert_statements == []
    assert sess.commit_count == 0


def test_dry_run_flavor_c_caps_examples_at_five(
    nodb_app: Flask, monkeypatch: pytest.MonkeyPatch
) -> None:
    """examples ist auf max. 5 begrenzt (Builder traegt LIMIT 5)."""
    scope = BulkAckServerScope(server_id=1, risk_band="noise")
    example_stmt = (
        bulk_mod._build_server_scope_query(scope)
        .with_only_columns(Finding.identifier_key, Finding.package_name)
        .order_by(Finding.identifier_key.asc())
        .limit(bulk_mod._FLAVOR_C_EXAMPLES_LIMIT)
    )
    sql = str(example_stmt.compile(dialect=postgresql.dialect())).lower()
    assert "limit" in sql
    assert "order by" in sql and "identifier_key" in sql
    assert bulk_mod._FLAVOR_C_EXAMPLES_LIMIT == 5


def test_dry_run_flavor_c_empty_band(nodb_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test 6: Band ohne Findings -> count=0, examples=[]."""
    sess = _FakeSession(server_active=True, count=0, examples=[])
    _patch_session(monkeypatch, sess)
    client = nodb_app.test_client()

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={"server_scope": {"server_id": 1, "risk_band": "monitor"}, "dry_run": True},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["count"] == 0
    assert body["examples"] == []
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
