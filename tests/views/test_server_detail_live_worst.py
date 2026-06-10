"""Pure-Unit-Tests fuer TICKET-010 Etappe 3 (Bug C) — Live-Worst-Finding im
Server-Detail-Loader `_load_application_groups_for_server`.

Deckt:
  * Live-Worst ersetzt Snapshot-Worst: Query (4) liefert eine andere
    Finding-ID als `evaluation.worst_finding_id` -> Entry traegt die
    Live-Row, `worst_finding_drift is True`.
  * Drift-Matrix: False bei ID-Match, False bei evaluation=None, False bei
    worst_finding_id=None, True wenn Snapshot-ID gesetzt aber kein
    Live-Worst mehr existiert (Snapshot-Finding geschlossen).
  * Statement-Inspektion Query (4): `DISTINCT ON (application_group_id)`,
    Status-Filter OPEN, `application_group_id IN (<group_ids>)`,
    ORDER BY beginnt mit application_group_id, danach §15-Triage-Order
    (is_kev DESC, epss DESC NULLS LAST, cvss DESC NULLS LAST,
    severity_rank DESC, first_seen_at ASC).

Die Statement-Checks kompilieren das abgefangene SQLAlchemy-Statement gegen
den postgresql-Dialekt — reine Statement-Kompilierung, KEINE DB. Das echte
`DISTINCT ON`-Laufzeitverhalten gegen Postgres ist db_integration und steht
beim User an (Ticket-DoD).
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.models import FindingStatus
from app.views.server_detail import _load_application_groups_for_server

# ---------------------------------------------------------------------------
# Helpers (Stil wie tests/views/test_server_detail_phase_a.py)
# ---------------------------------------------------------------------------


def _row(**fields: Any) -> SimpleNamespace:
    """Mini-Row-Object — SQLAlchemy-Row hat Attribut-Zugriff via Spaltenname."""
    return SimpleNamespace(**fields)


class _FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


class _RecordingSession:
    """Session-Fake: beantwortet `execute()` sequenziell und zeichnet die
    uebergebenen Statements fuer die Statement-Inspektion auf."""

    def __init__(self, execute_returns: list[list[Any]]) -> None:
        self.statements: list[Any] = []
        self._returns = iter(execute_returns)

    def execute(self, stmt: Any) -> _FakeResult:
        self.statements.append(stmt)
        return _FakeResult(next(self._returns))


def _eval_row(group_id: int, worst_finding_id: int | None) -> SimpleNamespace:
    return _row(
        group_id=group_id,
        risk_band="escalate",
        risk_band_reason="kev present",
        worst_finding_id=worst_finding_id,
        action_type="patch",
        risk_band_computed_at=None,
    )


def _group_row(group_id: int, label: str = "openssh") -> SimpleNamespace:
    return _row(id=group_id, label=label, group_kind="os_package", explanation=None)


def _worst_row(group_id: int, finding_id: int) -> SimpleNamespace:
    return _row(
        application_group_id=group_id,
        id=finding_id,
        identifier_key=f"CVE-2026-{finding_id}",
        package_name="openssh-server",
        title="some bug",
    )


def _run_loader(
    *,
    eval_rows: list[Any],
    worst_rows: list[Any],
    group_id: int = 10,
) -> tuple[list[dict[str, Any]], _RecordingSession]:
    """Fuehrt den Loader mit einer Single-Group-Konstellation aus.

    Query-Reihenfolge im Loader: (1) OPEN-Counts, (2) Group-Metadaten,
    (3) Eval-Junction, (4) Live-Worst-Batch.
    """
    counts_rows: list[Any] = [(group_id, 3)]
    group_rows = [_group_row(group_id)]
    sess = _RecordingSession([counts_rows, group_rows, eval_rows, worst_rows])
    result = _load_application_groups_for_server(sess, 1)
    return result, sess


# ---------------------------------------------------------------------------
# Live-Worst ersetzt Snapshot-Worst
# ---------------------------------------------------------------------------


def test_live_worst_replaces_snapshot_worst_and_flags_drift() -> None:
    """Query (4) liefert ID 200, der Eval-Snapshot zeigt auf ID 100 ->
    `worst_finding` ist die Live-Row (NICHT der Snapshot), Drift True."""
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=100)],
        worst_rows=[_worst_row(10, finding_id=200)],
    )

    assert len(result) == 1, result
    entry = result[0]
    assert entry["worst_finding"] is not None, "Live-Worst-Row muss im Entry landen"
    assert entry["worst_finding"].id == 200, (
        f"worst_finding muss die LIVE-Row (id=200) sein, nicht der Eval-Snapshot "
        f"(worst_finding_id=100); bekommen: {entry['worst_finding']!r}"
    )
    assert entry["worst_finding"].identifier_key == "CVE-2026-200"
    assert entry["worst_finding_drift"] is True, (
        "Snapshot-ID (100) != Live-ID (200) -> Drift-Hint muss gesetzt sein"
    )
    # Eval-Row bleibt unveraendert Datenquelle fuer Band/Reason.
    assert entry["evaluation"].risk_band == "escalate"


# ---------------------------------------------------------------------------
# Drift-Matrix
# ---------------------------------------------------------------------------


def test_drift_false_when_snapshot_matches_live() -> None:
    """Eval-Snapshot und Live-Worst zeigen auf dieselbe ID -> kein Drift."""
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=200)],
        worst_rows=[_worst_row(10, finding_id=200)],
    )
    entry = result[0]
    assert entry["worst_finding"].id == 200
    assert entry["worst_finding_drift"] is False, "ID-Match darf keinen Drift melden"


def test_drift_false_when_evaluation_missing() -> None:
    """Group ohne Junction-Row ('Nicht bewertet') -> kein Drift, Live-Worst
    rendert trotzdem."""
    result, _ = _run_loader(
        eval_rows=[],
        worst_rows=[_worst_row(10, finding_id=200)],
    )
    entry = result[0]
    assert entry["evaluation"] is None
    assert entry["worst_finding"] is not None
    assert entry["worst_finding_drift"] is False, (
        "Ohne Evaluation gibt es keinen Snapshot der driften koennte"
    )


def test_drift_false_when_snapshot_worst_id_is_none() -> None:
    """Eval-Row existiert, aber worst_finding_id=NULL -> kein Drift."""
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=None)],
        worst_rows=[_worst_row(10, finding_id=200)],
    )
    entry = result[0]
    assert entry["worst_finding"] is not None
    assert entry["worst_finding_drift"] is False, (
        "worst_finding_id=None ist kein Drift (Snapshot hat nie auf ein Finding gezeigt)"
    )


def test_drift_true_when_live_worst_missing_but_snapshot_set() -> None:
    """Snapshot-ID gesetzt, aber Query (4) liefert keine Row fuer die Group
    (Snapshot-Finding inzwischen geschlossen) -> Drift True, worst=None."""
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=100)],
        worst_rows=[],
    )
    entry = result[0]
    assert entry["worst_finding"] is None
    assert entry["worst_finding_drift"] is True, (
        "Snapshot zeigt auf ein Finding das nicht mehr im OPEN-Set ist -> Drift"
    )


def test_drift_per_group_independent() -> None:
    """Drift wird pro Group berechnet — eine driftende Group steckt die
    andere nicht an."""
    counts_rows: list[Any] = [(10, 2), (20, 1)]
    group_rows = [_group_row(10, "drifting"), _group_row(20, "in-sync")]
    eval_rows = [_eval_row(10, worst_finding_id=100), _eval_row(20, worst_finding_id=300)]
    worst_rows = [_worst_row(10, finding_id=200), _worst_row(20, finding_id=300)]
    sess = _RecordingSession([counts_rows, group_rows, eval_rows, worst_rows])
    result = _load_application_groups_for_server(sess, 1)

    by_label = {entry["group"].label: entry for entry in result}
    assert by_label["drifting"]["worst_finding_drift"] is True
    assert by_label["in-sync"]["worst_finding_drift"] is False
    assert by_label["in-sync"]["worst_finding"].id == 300


# ---------------------------------------------------------------------------
# Statement-Inspektion Query (4) — kompiliert gegen postgresql-Dialekt
# ---------------------------------------------------------------------------


def _compiled_worst_stmt(group_id: int = 10) -> Any:
    """Laesst den Loader laufen und kompiliert das 4. Statement (Live-Worst)."""
    _, sess = _run_loader(
        eval_rows=[_eval_row(group_id, worst_finding_id=200)],
        worst_rows=[_worst_row(group_id, finding_id=200)],
        group_id=group_id,
    )
    assert len(sess.statements) == 4, (
        f"Loader soll genau 4 Queries absetzen, gemessen: {len(sess.statements)}"
    )
    return sess.statements[3].compile(dialect=postgresql.dialect())


def test_worst_stmt_uses_distinct_on_application_group_id() -> None:
    """Query (4) ist ein Postgres `DISTINCT ON (application_group_id)`."""
    sql = str(_compiled_worst_stmt())
    assert "DISTINCT ON (findings.application_group_id)" in sql, (
        f"DISTINCT ON (findings.application_group_id) fehlt im kompilierten SQL:\n{sql}"
    )


def test_worst_stmt_filters_open_status() -> None:
    """Query (4) filtert auf status=OPEN — der Kern von Bug C."""
    compiled = _compiled_worst_stmt()
    sql = str(compiled)
    assert "findings.status =" in sql, f"Status-Filter fehlt im WHERE:\n{sql}"
    assert FindingStatus.OPEN in compiled.params.values(), (
        f"Status-Bind-Param muss FindingStatus.OPEN sein; Params: {compiled.params!r}"
    )


def test_worst_stmt_scopes_to_server_and_group_ids() -> None:
    """Query (4) ist auf server_id + die Group-IDs aus dem OPEN-Count
    eingeschraenkt — Groups ohne offene Findings tauchen damit nie auf."""
    compiled = _compiled_worst_stmt(group_id=77)
    sql = str(compiled)
    assert "findings.server_id =" in sql, f"server_id-Guard fehlt:\n{sql}"
    assert "findings.application_group_id IN" in sql, f"group_ids-IN-Filter fehlt:\n{sql}"
    assert [77] in compiled.params.values(), (
        f"IN-Filter muss exakt die Group-IDs aus dem OPEN-Count tragen ([77]); "
        f"Params: {compiled.params!r}"
    )


def test_worst_stmt_order_starts_with_group_then_triage_order() -> None:
    """ORDER BY beginnt mit application_group_id (DISTINCT-ON-Pflicht),
    danach §15-Triage: is_kev DESC, epss DESC NULLS LAST, cvss DESC NULLS
    LAST, severity_rank (CASE) DESC, first_seen_at ASC."""
    sql = str(_compiled_worst_stmt())
    match = re.search(r"ORDER BY (.+)$", sql, flags=re.DOTALL)
    assert match is not None, f"ORDER BY fehlt im kompilierten SQL:\n{sql}"
    order_by = match.group(1)

    expected_sequence = [
        "findings.application_group_id",
        "findings.is_kev DESC",
        "findings.epss_score DESC NULLS LAST",
        "findings.cvss_v3_score DESC NULLS LAST",
        "CASE",  # severity_rank via findings_query._severity_rank_expr
        "findings.first_seen_at ASC",
    ]
    positions: list[int] = []
    for fragment in expected_sequence:
        idx = order_by.find(fragment)
        assert idx >= 0, f"ORDER-BY-Fragment {fragment!r} fehlt in:\n{order_by}"
        positions.append(idx)
    assert positions == sorted(positions), (
        f"ORDER-BY-Reihenfolge falsch. Erwartet {expected_sequence} in dieser "
        f"Reihenfolge, kompiliert:\n{order_by}"
    )
    # Severity-Rank kommt nach dem CASE-Ende als DESC.
    case_idx = order_by.find("CASE")
    assert "END DESC" in order_by[case_idx:], f"Severity-Rank-CASE muss DESC sortieren:\n{order_by}"


def test_worst_stmt_severity_case_uses_enum_comparison() -> None:
    """Severity-Rank kommt aus `findings_query._severity_rank_expr` —
    CASE vergleicht die ENUM-Spalte direkt (kein varchar-Match)."""
    sql = str(_compiled_worst_stmt())
    assert "CASE WHEN (findings.severity =" in sql, (
        f"Severity-CASE muss direkt gegen die ENUM-Spalte vergleichen:\n{sql}"
    )


def test_worst_stmt_projects_template_contract_columns() -> None:
    """Projektion enthaelt genau die Spalten die Templates + Drift-Vergleich
    brauchen: application_group_id, id, identifier_key, package_name, title."""
    sql = str(_compiled_worst_stmt())
    select_clause = sql.split("FROM")[0]
    for col in (
        "findings.application_group_id",
        "findings.id",
        "findings.identifier_key",
        "findings.package_name",
        "findings.title",
    ):
        assert col in select_clause, f"Spalte {col} fehlt in der Projektion:\n{select_clause}"


# ---------------------------------------------------------------------------
# Group ohne offene Findings
# ---------------------------------------------------------------------------


def test_group_without_open_findings_never_rendered() -> None:
    """Eine Group ohne OPEN-Findings fehlt im Count-Aggregat (Query 1) und
    damit in group_ids — sie erscheint nicht im Ergebnis, selbst wenn eine
    (stale) Eval-Junction-Row existiert. Query (4) laeuft erst gar nicht
    fuer sie (IN-Filter, siehe Statement-Test oben)."""
    counts_rows: list[Any] = [(10, 1)]  # nur Group 10 hat offene Findings
    group_rows = [_group_row(10, "alive")]
    # Stale Eval-Row fuer Group 20 — darf nichts bewirken, weil Group 20
    # nie in group_ids gelandet ist (Query 2 wuerde sie nicht liefern).
    eval_rows = [_eval_row(10, worst_finding_id=200), _eval_row(20, worst_finding_id=999)]
    worst_rows = [_worst_row(10, finding_id=200)]
    sess = _RecordingSession([counts_rows, group_rows, eval_rows, worst_rows])
    result = _load_application_groups_for_server(sess, 1)

    assert [entry["group"].label for entry in result] == ["alive"]


@pytest.mark.parametrize("counts_rows", [[], [(None, 5)]])
def test_no_groups_short_circuits_before_worst_query(counts_rows: list[Any]) -> None:
    """Ohne Groups mit OPEN-Findings bricht der Loader nach Query (1) ab —
    Query (4) wird nie abgesetzt (kein sinnloser DISTINCT-ON-Roundtrip)."""
    sess = _RecordingSession([counts_rows])
    assert _load_application_groups_for_server(sess, 1) == []
    assert len(sess.statements) == 1
