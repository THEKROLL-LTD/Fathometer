"""Pure-Unit-Tests fuer den Live-Worst- und Drift-Hint-Pfad im Server-Detail-
Loader `_load_application_groups_for_server`.

Historie:
  * TICKET-010 / ADR-0052 (Bug C): Live-Worst ersetzt den Eval-Snapshot in der
    Anzeige-Spalte.
  * TICKET-013 / ADR-0053: Loader gruppiert pro Fix-Lane; jeder Entry traegt
    eine `lanes`-Liste. Die Single-Lane-Helper hier setzen has_fix=True (patch).
  * TICKET-014: der Drift-Hint ("re-evaluation pending") ist vom
    LLM-Worst-vs-Triage-Worst-Vergleich ENTKOPPELT und haengt jetzt am selben
    Kriterium wie das Enqueue-Gate — die gespeicherte Lane-Eval ist veraltet
    ggue. dem aktuellen Lane-OPEN-Set:
        drift  <=>  ev is not None and (
                        ev.group_findings_fingerprint != fp(lane_open_findings)
                        or ev.worst_finding_id not in {f.id for f in lane_open}
                    )
    Die Anzeige-Spalte (Query 4, Triage-Live-Worst) bleibt unveraendert; sie
    treibt den Hint nicht mehr.

Loader-Query-Reihenfolge: (1) OPEN-Counts (GROUP BY group_id, has_fix),
(2) Group-Metadaten, (3) Eval-Junction (inkl. group_findings_fingerprint),
(4) Live-Worst-Batch (DISTINCT ON), (5) Lane-OPEN-Set-Projektion.

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
from app.services.llm_fingerprints import group_findings_fingerprint
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


def _eval_row(
    group_id: int,
    worst_finding_id: int | None,
    *,
    fingerprint: str | None,
) -> SimpleNamespace:
    return _row(
        group_id=group_id,
        fix_lane="patch",
        risk_band="escalate",
        risk_band_reason="kev present",
        worst_finding_id=worst_finding_id,
        action_type="patch",
        risk_band_computed_at=None,
        group_findings_fingerprint=fingerprint,
    )


def _group_row(group_id: int, label: str = "openssh") -> SimpleNamespace:
    return _row(id=group_id, label=label, group_kind="os_package", explanation=None)


def _worst_row(group_id: int, finding_id: int) -> SimpleNamespace:
    """Query-(4)-Row: Triage-Live-Worst (DISTINCT ON), Anzeige-Spalte."""
    return _row(
        application_group_id=group_id,
        has_fix=True,
        id=finding_id,
        identifier_key=f"CVE-2026-{finding_id}",
        package_name="openssh-server",
        title="some bug",
    )


def _open_row(
    group_id: int,
    finding_id: int,
    *,
    identifier_key: str | None = None,
    package_purl: str = "",
    has_fix: bool = True,
) -> SimpleNamespace:
    """Query-(5)-Row: Lane-OPEN-Set-Projektion fuer Fingerprint + ID-Set."""
    return _row(
        application_group_id=group_id,
        has_fix=has_fix,
        id=finding_id,
        identifier_key=identifier_key or f"CVE-2026-{finding_id}",
        package_purl=package_purl,
    )


def _fp(open_rows: list[Any]) -> str:
    """Lane-Fingerprint wie ihn der Loader rechnet (Read-Reuse der Funktion)."""
    return group_findings_fingerprint(open_rows)


def _patch_lane(entry: dict[str, Any]) -> dict[str, Any]:
    """Liefert die patch-Lane eines Group-Entries (die Single-Lane-Tests
    erzeugen ausschliesslich has_fix=True -> patch)."""
    lanes = entry["lanes"]
    assert len(lanes) == 1, lanes
    assert lanes[0]["fix_lane"] == "patch"
    return lanes[0]


def _run_loader(
    *,
    eval_rows: list[Any],
    worst_rows: list[Any],
    open_rows: list[Any],
    group_id: int = 10,
) -> tuple[list[dict[str, Any]], _RecordingSession]:
    """Fuehrt den Loader mit einer Single-Group-Konstellation aus.

    Query-Reihenfolge: (1) OPEN-Counts, (2) Group-Metadaten, (3) Eval-Junction,
    (4) Live-Worst-Batch, (5) Lane-OPEN-Set-Projektion.
    """
    counts_rows: list[Any] = [(group_id, True, 3)]
    group_rows = [_group_row(group_id)]
    sess = _RecordingSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)
    return result, sess


# ---------------------------------------------------------------------------
# Live-Worst (Anzeige) ist entkoppelt vom Drift-Hint
# ---------------------------------------------------------------------------


def test_live_worst_replaces_snapshot_worst_in_display() -> None:
    """Query (4) liefert ID 200, der Eval-Snapshot zeigt auf ID 100 ->
    `worst_finding` ist die Live-Row (NICHT der Snapshot). Der Drift-Hint
    haengt aber NICHT mehr an diesem Vergleich (siehe Drift-Tests)."""
    open_rows = [_open_row(10, 100), _open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=100, fingerprint=_fp(open_rows))],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=open_rows,
    )

    assert len(result) == 1, result
    lane = _patch_lane(result[0])
    assert lane["worst_finding"] is not None, "Live-Worst-Row muss im Lane-Entry landen"
    assert lane["worst_finding"].id == 200, (
        f"worst_finding muss die LIVE-Row (id=200) sein, nicht der Eval-Snapshot "
        f"(worst_finding_id=100); bekommen: {lane['worst_finding']!r}"
    )
    assert lane["worst_finding"].identifier_key == "CVE-2026-200"
    # Eval-Row bleibt unveraendert Datenquelle fuer Band/Reason.
    assert lane["evaluation"].risk_band == "escalate"


# ---------------------------------------------------------------------------
# Drift-Matrix (TICKET-014: Fingerprint-/Worst-offen-Kriterium)
# ---------------------------------------------------------------------------


def test_drift_false_for_fresh_eval_even_if_llm_worst_differs_from_triage() -> None:
    """DER Regressionsfall dieses Tickets: frische Eval (Fingerprint stimmt,
    `worst_finding_id` offen) -> drift=False, OBWOHL der LLM-Worst (100) vom
    deterministischen Triage-Live-Worst (200) abweicht. Genau der
    Voll-Scan-Fall, der bisher dauerhaft 're-evaluation pending' zeigte."""
    open_rows = [_open_row(10, 100), _open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=100, fingerprint=_fp(open_rows))],
        worst_rows=[_worst_row(10, finding_id=200)],  # Triage-Live-Worst != LLM-Worst
        open_rows=open_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["worst_finding"].id == 200, "Anzeige bleibt der Triage-Live-Worst"
    assert lane["worst_finding_drift"] is False, (
        "Fingerprint stimmt und LLM-Worst (100) ist offen -> KEIN Drift, auch wenn "
        "der LLM-Worst nicht der Triage-Live-Worst ist"
    )


def test_drift_true_on_fingerprint_mismatch() -> None:
    """Geaendertes Lane-OPEN-Set -> gespeicherter Eval-Fingerprint != aktueller
    Lane-Fingerprint -> Drift True (beim naechsten Trigger wird enqueued)."""
    open_rows = [_open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=200, fingerprint="stalefp000000000")],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=open_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["worst_finding_drift"] is True, (
        "Fingerprint-Mismatch (gespeichert != aktuell) muss Drift melden"
    )


def test_drift_true_when_worst_finding_id_not_in_open_set() -> None:
    """`worst_finding_id` zeigt auf ein nicht mehr offenes Finding (999), der
    Fingerprint stimmt aber -> Drift True (deckt den TICKET-010-Fall ab)."""
    open_rows = [_open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=999, fingerprint=_fp(open_rows))],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=open_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["worst_finding_drift"] is True, (
        "Snapshot-Worst (999) nicht mehr im Lane-OPEN-Set -> Drift"
    )


def test_drift_false_when_evaluation_missing() -> None:
    """Group ohne Junction-Row ('Nicht bewertet') -> kein Drift, Live-Worst
    rendert trotzdem."""
    open_rows = [_open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=open_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["evaluation"] is None
    assert lane["worst_finding"] is not None
    assert lane["worst_finding_drift"] is False, (
        "Ohne Evaluation gibt es keinen Snapshot der driften koennte"
    )


def test_drift_false_when_worst_finding_id_none_and_fingerprint_matches() -> None:
    """Eval-Row existiert, `worst_finding_id`=NULL, Fingerprint stimmt -> kein
    Drift (Snapshot hat nie auf ein Finding gezeigt; OPEN-Set unveraendert)."""
    open_rows = [_open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=None, fingerprint=_fp(open_rows))],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=open_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["worst_finding"] is not None
    assert lane["worst_finding_drift"] is False, (
        "worst_finding_id=None bei passendem Fingerprint ist kein Drift"
    )


def test_drift_true_when_legacy_eval_has_no_fingerprint() -> None:
    """Legacy-Eval-Row ohne gespeicherten Fingerprint (NULL) gilt als veraltet
    -> Drift True; beim naechsten Trigger wird sie neu bewertet."""
    open_rows = [_open_row(10, 200)]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=200, fingerprint=None)],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=open_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["worst_finding_drift"] is True, (
        "NULL-Fingerprint (Legacy) != aktueller Fingerprint -> Drift"
    )


def test_drift_per_group_independent() -> None:
    """Drift wird pro Group berechnet — eine driftende Group steckt die
    andere nicht an."""
    open_10 = [_open_row(10, 200)]
    open_20 = [_open_row(20, 300)]
    counts_rows: list[Any] = [(10, True, 2), (20, True, 1)]
    group_rows = [_group_row(10, "drifting"), _group_row(20, "in-sync")]
    eval_rows = [
        _eval_row(10, worst_finding_id=200, fingerprint="stalefp000000000"),  # FP-Mismatch
        _eval_row(20, worst_finding_id=300, fingerprint=_fp(open_20)),  # frisch
    ]
    worst_rows = [_worst_row(10, finding_id=200), _worst_row(20, finding_id=300)]
    open_rows = open_10 + open_20
    sess = _RecordingSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)

    by_label = {entry["group"].label: _patch_lane(entry) for entry in result}
    assert by_label["drifting"]["worst_finding_drift"] is True
    assert by_label["in-sync"]["worst_finding_drift"] is False
    assert by_label["in-sync"]["worst_finding"].id == 300


def test_drift_uses_package_purl_in_fingerprint() -> None:
    """Der Lane-Fingerprint enthaelt `(identifier_key, package_purl)` — eine
    Aenderung am package_purl eines offenen Findings dreht den Fingerprint und
    damit den Drift, auch bei identischem identifier_key/ID-Set."""
    stored_rows = [_open_row(10, 200, identifier_key="CVE-2026-1", package_purl="pkg:deb/a")]
    live_rows = [_open_row(10, 200, identifier_key="CVE-2026-1", package_purl="pkg:deb/b")]
    result, _ = _run_loader(
        eval_rows=[_eval_row(10, worst_finding_id=200, fingerprint=_fp(stored_rows))],
        worst_rows=[_worst_row(10, finding_id=200)],
        open_rows=live_rows,
    )
    lane = _patch_lane(result[0])
    assert lane["worst_finding_drift"] is True, (
        "Geaenderter package_purl -> anderer Fingerprint -> Drift"
    )


# ---------------------------------------------------------------------------
# Statement-Inspektion Query (4) — Live-Worst, DISTINCT ON
# ---------------------------------------------------------------------------


def _compiled_worst_stmt(group_id: int = 10) -> Any:
    """Laesst den Loader laufen und kompiliert das 4. Statement (Live-Worst)."""
    open_rows = [_open_row(group_id, 200)]
    _, sess = _run_loader(
        eval_rows=[_eval_row(group_id, worst_finding_id=200, fingerprint=_fp(open_rows))],
        worst_rows=[_worst_row(group_id, finding_id=200)],
        open_rows=open_rows,
        group_id=group_id,
    )
    assert len(sess.statements) == 5, (
        f"Loader soll genau 5 Queries absetzen, gemessen: {len(sess.statements)}"
    )
    return sess.statements[3].compile(dialect=postgresql.dialect())


def test_worst_stmt_uses_distinct_on_group_and_has_fix() -> None:
    """Query (4) ist ein Postgres `DISTINCT ON (application_group_id, has_fix)`
    — pro `(group, lane)` ein eigener Live-Worst (TICKET-013)."""
    sql = str(_compiled_worst_stmt())
    assert "DISTINCT ON (findings.application_group_id, findings.has_fix)" in sql, (
        f"DISTINCT ON (findings.application_group_id, findings.has_fix) fehlt im "
        f"kompilierten SQL:\n{sql}"
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
    """ORDER BY beginnt mit (application_group_id, has_fix) (DISTINCT-ON-
    Pflicht), danach §15-Triage: is_kev DESC, epss DESC NULLS LAST, cvss
    DESC NULLS LAST, severity_rank (CASE) DESC, first_seen_at ASC."""
    sql = str(_compiled_worst_stmt())
    match = re.search(r"ORDER BY (.+)$", sql, flags=re.DOTALL)
    assert match is not None, f"ORDER BY fehlt im kompilierten SQL:\n{sql}"
    order_by = match.group(1)

    expected_sequence = [
        "findings.application_group_id",
        "findings.has_fix",
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
    """Projektion enthaelt genau die Spalten die Templates + Anzeige brauchen:
    application_group_id, has_fix, id, identifier_key, package_name, title."""
    sql = str(_compiled_worst_stmt())
    select_clause = sql.split("FROM")[0]
    for col in (
        "findings.application_group_id",
        "findings.has_fix",
        "findings.id",
        "findings.identifier_key",
        "findings.package_name",
        "findings.title",
    ):
        assert col in select_clause, f"Spalte {col} fehlt in der Projektion:\n{select_clause}"


# ---------------------------------------------------------------------------
# Statement-Inspektion Query (5) — Lane-OPEN-Set-Projektion (TICKET-014)
# ---------------------------------------------------------------------------


def _compiled_open_stmt(group_id: int = 10) -> Any:
    """Laesst den Loader laufen und kompiliert das 5. Statement (Lane-OPEN)."""
    open_rows = [_open_row(group_id, 200)]
    _, sess = _run_loader(
        eval_rows=[_eval_row(group_id, worst_finding_id=200, fingerprint=_fp(open_rows))],
        worst_rows=[_worst_row(group_id, finding_id=200)],
        open_rows=open_rows,
        group_id=group_id,
    )
    assert len(sess.statements) == 5
    return sess.statements[4].compile(dialect=postgresql.dialect())


def test_open_stmt_projects_fingerprint_and_id_columns() -> None:
    """Query (5) projiziert genau die Spalten fuer Fingerprint + ID-Set:
    application_group_id, has_fix, id, identifier_key, package_purl."""
    sql = str(_compiled_open_stmt())
    select_clause = sql.split("FROM")[0]
    for col in (
        "findings.application_group_id",
        "findings.has_fix",
        "findings.id",
        "findings.identifier_key",
        "findings.package_purl",
    ):
        assert col in select_clause, f"Spalte {col} fehlt in der Projektion:\n{select_clause}"


def test_open_stmt_filters_open_and_scopes_to_server_and_groups() -> None:
    """Query (5) filtert status=OPEN und ist auf server_id + Group-IDs
    eingeschraenkt — selbe Domaene wie das Enqueue-Gate."""
    compiled = _compiled_open_stmt(group_id=77)
    sql = str(compiled)
    assert "findings.status =" in sql, f"Status-Filter fehlt:\n{sql}"
    assert FindingStatus.OPEN in compiled.params.values(), (
        f"Status-Bind muss FindingStatus.OPEN sein; Params: {compiled.params!r}"
    )
    assert "findings.server_id =" in sql, f"server_id-Guard fehlt:\n{sql}"
    assert "findings.application_group_id IN" in sql, f"group_ids-IN-Filter fehlt:\n{sql}"
    assert [77] in compiled.params.values(), (
        f"IN-Filter muss die Group-IDs aus dem OPEN-Count tragen ([77]); "
        f"Params: {compiled.params!r}"
    )


# ---------------------------------------------------------------------------
# Group ohne offene Findings / Short-Circuit
# ---------------------------------------------------------------------------


def test_group_without_open_findings_never_rendered() -> None:
    """Eine Group ohne OPEN-Findings fehlt im Count-Aggregat (Query 1) und
    damit in group_ids — sie erscheint nicht im Ergebnis, selbst wenn eine
    (stale) Eval-Junction-Row existiert."""
    open_rows = [_open_row(10, 200)]
    counts_rows: list[Any] = [(10, True, 1)]  # nur Group 10 hat offene Findings
    group_rows = [_group_row(10, "alive")]
    # Stale Eval-Row fuer Group 20 — darf nichts bewirken, weil Group 20
    # nie in group_ids gelandet ist.
    eval_rows = [
        _eval_row(10, worst_finding_id=200, fingerprint=_fp(open_rows)),
        _eval_row(20, worst_finding_id=999, fingerprint="x"),
    ]
    worst_rows = [_worst_row(10, finding_id=200)]
    sess = _RecordingSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)

    assert [entry["group"].label for entry in result] == ["alive"]


@pytest.mark.parametrize("counts_rows", [[], [(None, True, 5)]])
def test_no_groups_short_circuits_before_later_queries(counts_rows: list[Any]) -> None:
    """Ohne Groups mit OPEN-Findings bricht der Loader nach Query (1) ab —
    weder Live-Worst (4) noch Lane-OPEN (5) werden abgesetzt."""
    sess = _RecordingSession([counts_rows])
    assert _load_application_groups_for_server(sess, 1) == []
    assert len(sess.statements) == 1
