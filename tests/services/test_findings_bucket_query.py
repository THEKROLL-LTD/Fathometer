"""Pure-Unit-Tests fuer den Cross-Server Bucket-Query-Service (ADR-0037).

TICKET-006 Etappe 1, Tests 1-12. Mock-Sessions + SQL-Shape-Checks via
`str(stmt.compile(dialect=postgresql.dialect(), ...))` analog
``tests/services/test_finding_group_inheritance.py``.

Keine DB, kein Server-Roundtrip, kein Docker. Erlaubte Quality-Gates
sind ruff/mypy/shellcheck/pytest Default-Selektion (siehe CLAUDE.md
§Test-Konvention).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from sqlalchemy.dialects import postgresql

from app.schemas.dashboard_filter import DashboardFilter
from app.services import findings_bucket_query as fbq
from app.services.findings_bucket_query import (
    BucketHeader,
    list_bucket_findings,
    list_buckets,
    pending_bucket_header,
    resolve_bucket_to_finding_ids,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session_with_aggregate_rows(rows: list[tuple[Any, ...]] | None = None) -> MagicMock:
    """Mock-Session fuer `list_buckets` — `session.execute(...).all()` ist eine Liste von Aggregat-Tupeln."""
    session = MagicMock()
    session.execute.return_value.all.return_value = rows or []
    return session


def _session_with_scalar(value: int | None) -> MagicMock:
    """Mock-Session fuer `pending_bucket_header` — `session.execute(...).scalar()` liefert den COUNT."""
    session = MagicMock()
    session.execute.return_value.scalar.return_value = value
    return session


def _session_for_list_findings(findings_total: int = 0) -> MagicMock:
    """Mock-Session fuer `list_bucket_findings` — zwei `execute`-Aufrufe (COUNT + LIST)."""
    session = MagicMock()
    count_result = MagicMock()
    count_result.scalar.return_value = findings_total
    list_result = MagicMock()
    list_result.scalars.return_value.unique.return_value.all.return_value = []
    session.execute.side_effect = [count_result, list_result]
    return session


def _session_for_scalars_list(ids: list[int]) -> MagicMock:
    """Mock-Session fuer `resolve_bucket_to_finding_ids` — `session.execute(...).scalars().all()` liefert IDs."""
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = ids
    return session


def _compile_first_executed(session: MagicMock, call_index: int = 0) -> str:
    """Pickt das Statement aus der `call_index`-ten `session.execute(...)`-Invocation und compiled es."""
    call = session.execute.call_args_list[call_index]
    stmt = call.args[0]
    return str(
        stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )


# ---------------------------------------------------------------------------
# Test 1 — list_buckets ohne Filter: Aggregat-SQL-Shape
# ---------------------------------------------------------------------------


def test_list_buckets_no_filter_has_group_by_and_left_join_on_evaluations() -> None:
    session = _session_with_aggregate_rows()
    filt = DashboardFilter()

    list_buckets(session, filt)

    sql = _compile_first_executed(session)
    # GROUP BY auf (server_id, application_group_id) plus die mitselektierten
    # Server/Group/Eval-Spalten (sonst beschwert sich Postgres).
    assert "GROUP BY" in sql
    assert "findings.server_id" in sql
    assert "findings.application_group_id" in sql
    # LEFT OUTER JOIN auf die Junction-Tabelle (Composite-Match).
    assert "LEFT OUTER JOIN application_group_evaluations" in sql
    assert "application_group_evaluations.group_id = findings.application_group_id" in sql
    assert "application_group_evaluations.server_id = findings.server_id" in sql
    # Pending-Bucket gehoert NICHT in diese Aggregat-Query.
    assert "findings.application_group_id IS NOT NULL" in sql


# ---------------------------------------------------------------------------
# Test 2 — list_buckets mit `q`: Server-Subquery-Mitigation
# ---------------------------------------------------------------------------


def test_list_buckets_q_filter_uses_4col_ilike_or_with_server_subquery() -> None:
    session = _session_with_aggregate_rows()
    filt = DashboardFilter(q="rke2")

    list_buckets(session, filt)

    sql = _compile_first_executed(session)
    # 3-Spalten-ILIKE auf der Finding-Tabelle. Postgres-Dialect escaped die
    # `%` in literal_binds zu `%%` (printf-Konvention) — wir matchen daher
    # das doppelte Zeichen.
    assert "findings.identifier_key ILIKE '%%rke2%%'" in sql
    assert "findings.package_name ILIKE '%%rke2%%'" in sql
    assert "findings.title ILIKE '%%rke2%%'" in sql
    # Server-Name-Match als Subquery (Performance-Mitigation, ADR-0037 §(6)).
    assert "findings.server_id IN" in sql
    assert "servers.name ILIKE '%%rke2%%'" in sql


# ---------------------------------------------------------------------------
# Test 3 — list_buckets mit risk_band='escalate': WHERE-Filter
# ---------------------------------------------------------------------------


def test_list_buckets_risk_band_filter_emits_equality_where_clause() -> None:
    session = _session_with_aggregate_rows()
    filt = DashboardFilter(risk_band="escalate")

    list_buckets(session, filt)

    sql = _compile_first_executed(session)
    assert "findings.risk_band = 'escalate'" in sql


# ---------------------------------------------------------------------------
# Test 4 — list_buckets ORDER BY: rank desc, server.name asc, group.label asc
# ---------------------------------------------------------------------------


def test_list_buckets_order_by_has_rank_desc_then_server_name_then_group_label() -> None:
    session = _session_with_aggregate_rows()
    filt = DashboardFilter()

    list_buckets(session, filt)

    sql = _compile_first_executed(session)
    # ORDER BY enthaelt den Risk-Band-Rank-Ausdruck (CASE/COALESCE) als
    # ersten Sort-Key, dann Server-Name und Group-Label aufsteigend.
    order_by_pos = sql.find("ORDER BY")
    assert order_by_pos != -1, "ORDER BY fehlt im Statement"
    order_clause = sql[order_by_pos:]
    # Risk-Band-Rank ist eine CASE-Expression mit COALESCE — Marker:
    assert "CASE" in order_clause
    assert "coalesce(application_group_evaluations.risk_band, 'pending')" in order_clause
    # `DESC` taucht im Rank-Ausdruck auf, `servers.name ASC` und
    # `application_groups.label ASC` danach.
    assert "DESC" in order_clause
    server_pos = order_clause.find("servers.name")
    label_pos = order_clause.find("application_groups.label")
    assert server_pos != -1 and label_pos != -1
    assert server_pos < label_pos, "servers.name muss vor application_groups.label sortieren"


# ---------------------------------------------------------------------------
# Test 5 — Pending: separater Code-Pfad, NICHT in list_buckets()
# ---------------------------------------------------------------------------


def test_pending_bucket_lives_in_separate_function_not_in_list_buckets() -> None:
    """ADR-0037 §(1): Pending-Bucket erscheint immer als letzter Eintrag der
    Findings-Liste (View-Verantwortung). Der Service trennt das in zwei
    Funktionen: `list_buckets()` enthaelt NUR Buckets mit Group,
    `pending_bucket_header()` liefert den Pending-Sammler separat.
    """
    # (a) list_buckets() klammert Pending via WHERE IS NOT NULL aus.
    session_buckets = _session_with_aggregate_rows()
    list_buckets(session_buckets, DashboardFilter())
    list_buckets_sql = _compile_first_executed(session_buckets)
    assert "findings.application_group_id IS NOT NULL" in list_buckets_sql

    # (b) pending_bucket_header() ist die separate Quelle und nutzt den
    # gegenteiligen WHERE-Filter (`IS NULL`) und gibt einen Sammler-Header
    # mit Marker-IDs (server_id=0, group_id=0) zurueck.
    session_pending = _session_with_scalar(7)
    header = pending_bucket_header(session_pending, DashboardFilter())
    pending_sql = _compile_first_executed(session_pending)
    assert "findings.application_group_id IS NULL" in pending_sql
    assert header is not None
    assert header.server_id == 0
    assert header.group_id == 0
    assert header.group_label == "(ohne Group)"
    assert header.risk_band == "pending"
    assert header.finding_count == 7

    # (c) Leerer Pending-Bucket -> None.
    session_empty = _session_with_scalar(0)
    assert pending_bucket_header(session_empty, DashboardFilter()) is None


# ---------------------------------------------------------------------------
# Test 6 — list_bucket_findings(group_id=0): IS NULL-WHERE
# ---------------------------------------------------------------------------


def test_list_bucket_findings_group_id_zero_produces_is_null_where() -> None:
    session = _session_for_list_findings(findings_total=0)
    filt = DashboardFilter()

    list_bucket_findings(session, server_id=42, group_id=0, filt=filt, page=1, per_page=20)

    # Erstes execute = COUNT-Subselect; zweites execute = LIST-Statement.
    # Beide muessen die IS NULL-Bedingung enthalten.
    count_sql = _compile_first_executed(session, 0)
    list_sql = _compile_first_executed(session, 1)
    for sql in (count_sql, list_sql):
        assert "findings.application_group_id IS NULL" in sql
        assert "findings.server_id = 42" in sql


# ---------------------------------------------------------------------------
# Test 7 — list_bucket_findings(group_id=22, server_id=1): equality WHERE
# ---------------------------------------------------------------------------


def test_list_bucket_findings_concrete_ids_produces_equality_where_clauses() -> None:
    session = _session_for_list_findings(findings_total=0)
    filt = DashboardFilter()

    list_bucket_findings(session, server_id=1, group_id=22, filt=filt, page=1, per_page=20)

    list_sql = _compile_first_executed(session, 1)
    assert "findings.server_id = 1" in list_sql
    assert "findings.application_group_id = 22" in list_sql


# ---------------------------------------------------------------------------
# Test 8 — list_bucket_findings: COUNT-Subselect ohne ORDER BY/LIMIT
# ---------------------------------------------------------------------------


def test_list_bucket_findings_count_subselect_strips_order_and_limit() -> None:
    session = _session_for_list_findings(findings_total=0)
    filt = DashboardFilter()

    list_bucket_findings(session, server_id=1, group_id=22, filt=filt, page=2, per_page=20)

    count_sql = _compile_first_executed(session, 0)
    list_sql = _compile_first_executed(session, 1)
    # COUNT-Subselect: keine ORDER BY, keine LIMIT, keine OFFSET.
    # `is_kev` ist Marker fuer den Spec-fixen Finding-Sort.
    count_outer = count_sql.split("FROM")[0]
    assert "ORDER BY" not in count_outer
    assert "LIMIT" not in count_outer
    assert "OFFSET" not in count_outer
    # Das aeussere COUNT-Statement listet nur `count(*)`.
    assert count_outer.strip().lower().startswith("select count(*)")
    # LIST-Statement hat ORDER BY + LIMIT + OFFSET.
    assert "ORDER BY" in list_sql
    assert "LIMIT 20" in list_sql
    assert "OFFSET 20" in list_sql  # page=2, per_page=20 -> offset 20.
    assert "findings.is_kev DESC" in list_sql


# ---------------------------------------------------------------------------
# Test 9 — resolve_bucket_to_finding_ids: deterministisch sortierte IDs
# ---------------------------------------------------------------------------


def test_resolve_bucket_to_finding_ids_returns_sorted_int_list() -> None:
    session = _session_for_scalars_list([10, 4, 7])
    filt = DashboardFilter()

    ids = resolve_bucket_to_finding_ids(session, server_id=1, group_id=22, filt=filt)

    # Mock liefert die IDs in genau dieser Reihenfolge — der Test prueft,
    # dass die Funktion das DB-Result direkt durchreicht (kein Re-Sort in
    # Python), und dass der Sort-Order im SQL deterministisch ist.
    assert ids == [10, 4, 7]
    sql = _compile_first_executed(session)
    assert "ORDER BY findings.identifier_key ASC, findings.id ASC" in sql
    # Selektiert nur die ID-Spalte (Performance — siehe Docstring).
    assert sql.lstrip().lower().startswith("select findings.id")
    # WHERE-Filter sind aktiv.
    assert "findings.server_id = 1" in sql
    assert "findings.application_group_id = 22" in sql


# ---------------------------------------------------------------------------
# Test 10 — resolve_bucket_to_finding_ids: leerer Bucket -> []
# ---------------------------------------------------------------------------


def test_resolve_bucket_to_finding_ids_empty_bucket_returns_empty_list() -> None:
    session = _session_for_scalars_list([])
    filt = DashboardFilter()

    ids = resolve_bucket_to_finding_ids(session, server_id=99, group_id=0, filt=filt)

    assert ids == []
    sql = _compile_first_executed(session)
    # group_id=0 -> Pending-WHERE.
    assert "findings.application_group_id IS NULL" in sql


# ---------------------------------------------------------------------------
# Test 11 — `_apply_bucket_filters` wird von allen vier Public-Funktionen aufgerufen
# ---------------------------------------------------------------------------


def test_apply_bucket_filters_is_called_by_all_four_public_functions() -> None:
    """Spy auf den Helper: Pflicht-Disziplin (ADR-0037 §(3)). Verhindert
    Drift zwischen Header-Count und Bucket-Body."""
    filt = DashboardFilter()

    # Wir patchen den Helper so, dass er das uebergebene Statement
    # unveraendert weiterreicht — sonst kollabiert die SQL-Compilation der
    # vier Public-Funktionen.
    with patch(
        "app.services.findings_bucket_query._apply_bucket_filters",
        side_effect=lambda stmt, _filt: stmt,
    ) as spy:
        list_buckets(_session_with_aggregate_rows(), filt)
        pending_bucket_header(_session_with_scalar(0), filt)
        list_bucket_findings(
            _session_for_list_findings(0),
            server_id=1,
            group_id=2,
            filt=filt,
            page=1,
            per_page=20,
        )
        resolve_bucket_to_finding_ids(
            _session_for_scalars_list([]),
            server_id=1,
            group_id=2,
            filt=filt,
        )

    # Jede Public-Funktion ruft den Helper genau einmal mit `(stmt, filt)`.
    # `list_buckets`, `pending_bucket_header`, `resolve_bucket_to_finding_ids`
    # rufen einmal; `list_bucket_findings` ruft den Helper einmal vor dem
    # COUNT/LIST-Doppel — beide laufen auf demselben base_stmt.
    assert spy.call_count == 4
    for call in spy.call_args_list:
        # Zweites Argument ist der Filter.
        assert call.args[1] is filt


# ---------------------------------------------------------------------------
# Test 12 — Idempotenz: identische Inputs -> identische SQL-Shape
# ---------------------------------------------------------------------------


def test_idempotent_calls_with_identical_filter_produce_identical_sql() -> None:
    filt = DashboardFilter(q="nginx", risk_band="escalate", status="open")

    session_a = _session_with_aggregate_rows()
    list_buckets(session_a, filt)
    sql_a = _compile_first_executed(session_a)

    session_b = _session_with_aggregate_rows()
    list_buckets(session_b, filt)
    sql_b = _compile_first_executed(session_b)

    assert sql_a == sql_b


# ---------------------------------------------------------------------------
# Bonus-Smoke: BucketHeader ist frozen+slots — sicherstellen, dass das nicht
# versehentlich abgebrochen wird (frozen=False wuerde Mutationen erlauben).
# ---------------------------------------------------------------------------


def test_bucket_header_is_frozen_dataclass_with_slots() -> None:
    header = BucketHeader(
        server_id=1,
        group_id=2,
        server_name="srv",
        group_label="lbl",
        risk_band="escalate",
        finding_count=3,
    )
    # frozen=True -> Attribute-Set wirft FrozenInstanceError.
    import dataclasses

    try:
        header.finding_count = 4  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("BucketHeader muss frozen sein")

    # slots=True -> kein __dict__.
    assert not hasattr(header, "__dict__")


# Modul-Smoke: sicherstellen, dass das Modul den Helper exportbar haelt (nicht
# als versehentliches Public-API, aber referenzierbar fuer Test 11).
def test_helper_is_module_attribute() -> None:
    assert callable(fbq._apply_bucket_filters)


# ---------------------------------------------------------------------------
# group_bucket_findings_by_lane — Lane-Gruppierung + Reason-Anbindung
# (TICKET-016 / ADR-0065 Strategie a)
# ---------------------------------------------------------------------------

from types import SimpleNamespace  # noqa: E402

from app.services.findings_bucket_query import (  # noqa: E402
    BucketLaneGroup,
    group_bucket_findings_by_lane,
)


def _finding(fid: int, *, finding_class: str = "os-pkgs", has_fix: bool = True) -> SimpleNamespace:
    """Minimal-Finding fuer die Lane-Ableitung (`fix_lane_for`):
    os-pkgs + has_fix -> patch; not has_fix -> mitigate."""
    return SimpleNamespace(
        id=fid,
        finding_class=finding_class,
        has_fix=has_fix,
        host_update_available=None,
    )


def _eval(fix_lane: str, *, risk_band: str, reason: str | None) -> SimpleNamespace:
    return SimpleNamespace(fix_lane=fix_lane, risk_band=risk_band, risk_band_reason=reason)


def _session_with_evals(evals: list[SimpleNamespace]) -> MagicMock:
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = evals
    return session


def test_group_by_lane_pending_bucket_returns_empty() -> None:
    """group_id == 0 (Pending-Sammler) -> leere Liste, KEINE DB-Query, kein
    Fake-Reason (ADR-0065 §2)."""
    session = MagicMock()
    result = group_bucket_findings_by_lane(session, server_id=0, group_id=0, findings=[_finding(1)])
    assert result == []
    session.execute.assert_not_called()


def test_group_by_lane_empty_findings_returns_empty() -> None:
    session = MagicMock()
    result = group_bucket_findings_by_lane(session, server_id=42, group_id=7, findings=[])
    assert result == []
    session.execute.assert_not_called()


def test_group_by_lane_splits_patch_and_mitigate_with_reason() -> None:
    """Findings beider Lanes -> zwei BucketLaneGroups (patch zuerst), jede mit
    Band + voller Reason aus der passenden Junction-Row."""
    session = _session_with_evals(
        [
            _eval("patch", risk_band="act", reason="patch available, normal cycle"),
            _eval("mitigate", risk_band="monitor", reason="no attack path, deprioritised"),
        ]
    )
    findings = [
        _finding(1, finding_class="os-pkgs", has_fix=True),  # patch
        _finding(2, has_fix=False),  # mitigate
        _finding(3, finding_class="os-pkgs", has_fix=True),  # patch
    ]
    result = group_bucket_findings_by_lane(session, server_id=42, group_id=7, findings=findings)

    assert [g.fix_lane for g in result] == ["patch", "mitigate"]  # FIX_LANES-Reihenfolge
    patch_g, mit_g = result
    assert isinstance(patch_g, BucketLaneGroup)
    assert [f.id for f in patch_g.findings] == [1, 3]  # Reihenfolge erhalten
    assert patch_g.risk_band == "act"
    assert patch_g.risk_band_reason == "patch available, normal cycle"
    assert [f.id for f in mit_g.findings] == [2]
    assert mit_g.risk_band == "monitor"
    assert mit_g.risk_band_reason == "no attack path, deprioritised"


def test_group_by_lane_missing_eval_is_pending_band_no_reason() -> None:
    """Lane ohne Junction-Row -> Band 'pending', Reason None (kein Fake)."""
    session = _session_with_evals([])  # keine Evals
    result = group_bucket_findings_by_lane(
        session, server_id=42, group_id=7, findings=[_finding(1)]
    )
    assert len(result) == 1
    assert result[0].fix_lane == "patch"
    assert result[0].risk_band == "pending"
    assert result[0].risk_band_reason is None


def test_group_by_lane_only_lanes_present_on_page_get_headers() -> None:
    """Nur Lanes mit Findings auf der Seite erscheinen — eine vorhandene
    mitigate-Eval ohne mitigate-Findings erzeugt KEINEN leeren Header."""
    session = _session_with_evals(
        [
            _eval("patch", risk_band="act", reason="r-patch"),
            _eval("mitigate", risk_band="escalate", reason="r-mit"),
        ]
    )
    # nur patch-Findings auf dieser Seite
    result = group_bucket_findings_by_lane(
        session, server_id=42, group_id=7, findings=[_finding(1), _finding(2)]
    )
    assert [g.fix_lane for g in result] == ["patch"]


def test_bucket_lane_group_is_frozen_slots() -> None:
    g = BucketLaneGroup(fix_lane="patch", risk_band="act", risk_band_reason="x", findings=[])
    import dataclasses

    try:
        g.risk_band = "noise"  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("BucketLaneGroup muss frozen sein")
    assert not hasattr(g, "__dict__")
