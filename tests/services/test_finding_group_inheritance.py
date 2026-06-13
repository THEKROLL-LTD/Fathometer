"""Tests fuer Group-Risk-Vererbung auf Findings (Block T, ADR-0028).

Composite-Match (Block T): ``Finding.application_group_id ==
ApplicationGroupEvaluation.group_id AND Finding.server_id ==
ApplicationGroupEvaluation.server_id``. Verhindert Cross-Server-Leak
(Server-A's Findings erben nur aus ``(group, A)``-Junction).

Lane-Match (ADR-0053, erweitert ADR-0061): zusaetzlicher Join auf
``fix_lane == fix_lane_sql_case(finding_class, has_fix)`` — os-pkgs-Fix
(patch), lang-pkgs/other-Fix (upstream) und no-fix (mitigate) Findings
derselben Group erben aus verschiedenen Junction-Rows.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from sqlalchemy.dialects import postgresql

from app.models import Finding
from app.services.finding_group_inheritance import inherit_group_risk_to_findings


def _session_with_rowcount(rowcount: int | None = 3) -> MagicMock:
    session = MagicMock()
    session.execute.return_value = SimpleNamespace(rowcount=rowcount)
    return session


def _compiled_sql(session: MagicMock) -> str:
    stmt = session.execute.call_args.args[0]
    return str(
        stmt.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )


def test_inherits_junction_band_and_llm_source_without_action_type() -> None:
    session = _session_with_rowcount(5)

    updated = inherit_group_risk_to_findings(session)

    assert updated == 5
    sql = _compiled_sql(session)
    assert "UPDATE findings" in sql
    assert "FROM application_group_evaluations" in sql
    assert "risk_band=application_group_evaluations.risk_band" in sql
    # TICKET-012: risk_band_reason wird NICHT mehr auf Findings vererbt
    # (AI-Assessment ist Group-Level).
    assert "risk_band_reason" not in sql
    assert "risk_band_source='llm'" in sql
    assert "risk_band_computed_at=now()" in sql
    assert "action_type" not in sql
    assert not hasattr(Finding, "action_type")
    session.commit.assert_not_called()


def test_finding_has_no_risk_band_reason_column() -> None:
    """TICKET-012: Per-Finding-``risk_band_reason`` ist entfernt (Schema-Drop,
    Migration 0021). AI-Assessment lebt ausschliesslich auf der
    ``ApplicationGroupEvaluation`` (Group-Level)."""
    assert not hasattr(Finding, "risk_band_reason")


def test_composite_match_joins_group_id_and_server_id() -> None:
    """Block T: Finding erbt nur aus der Junction-Row die seinen Server matched."""
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    # Beide Bedingungen muessen im WHERE-Clause stehen — sonst ist es
    # last-write-wins-Cross-Server-Leak.
    assert "findings.application_group_id = application_group_evaluations.group_id" in sql
    assert "findings.server_id = application_group_evaluations.server_id" in sql


def test_lane_case_join_restricts_inheritance_to_own_lane() -> None:
    """TICKET-013/ADR-0053: Finding erbt aus der Junction-Row seiner eigenen
    Fix-Lane. Die dritte Join-Bedingung matcht ``fix_lane`` gegen eine
    deterministische CASE-Diskriminante ueber ``Finding.has_fix``."""
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    # Lane-Spalte der Junction muss gegen einen CASE-Ausdruck gejoint werden.
    assert "application_group_evaluations.fix_lane" in sql
    assert "CASE WHEN" in sql
    # Diskriminante ist die generierte has_fix-Spalte (== bool(fixed_version),
    # identisch zur Enqueue-/Worker-Partitionierung — kein Lane-Drift).
    assert "findings.has_fix" in sql
    # Beide Lane-Werte erscheinen als CASE-Zweige.
    assert "'patch'" in sql
    assert "'mitigate'" in sql


def test_lane_case_separates_patchable_and_nofix_findings() -> None:
    """Konzeptioneller Kern-Gewinn (ADR-0053, erweitert ADR-0061): die
    Lane-Bedingung stellt sicher, dass os-pkgs-Fix (→ 'patch'),
    lang-pkgs/other-Fix (→ 'upstream') und no-fix (→ 'mitigate') Findings
    derselben Group aus **verschiedenen** Junction-Rows erben — und damit
    unterschiedliche Bands tragen koennen.

    Geprueft an der kompilierten CASE-Form (Single-Source
    ``risk_engine.fix_lane_sql_case``): no-fix wird zuerst geprueft
    (→ mitigate), dann os-pkgs (→ patch), sonst upstream."""
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    # no-fix (has_fix=false) → 'mitigate' (erster CASE-Zweig).
    assert "WHEN NOT findings.has_fix THEN 'mitigate'" in sql
    # os-pkgs + Fix → 'patch'.
    assert "findings.finding_class = 'os-pkgs'" in sql
    assert "THEN 'patch'" in sql
    # sonst (lang-pkgs/other + Fix) → 'upstream' (ELSE).
    assert "ELSE 'upstream'" in sql
    # Die Lane-Bindung haengt an der Junction-fix_lane (Equality-Join), nicht
    # an einer freien Group-Row.
    assert "application_group_evaluations.fix_lane = CASE WHEN" in sql


def test_idempotency_filter_checks_band_and_source() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    assert "findings.risk_band IS DISTINCT FROM application_group_evaluations.risk_band" in sql
    assert "findings.risk_band_source IS DISTINCT FROM 'llm'" in sql
    # TICKET-012: kein risk_band_reason-Term mehr in der OR-Bedingung.
    assert "risk_band_reason" not in sql


def test_group_ids_filter_limits_update_to_given_groups() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session, group_ids=[10, 20])

    sql = _compiled_sql(session)
    assert "application_group_evaluations.group_id IN (10, 20)" in sql


def test_server_id_filter_limits_update_to_server() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session, server_id=42)

    sql = _compiled_sql(session)
    assert "findings.server_id = 42" in sql


def test_group_and_server_filters_can_be_combined() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session, group_ids=[7], server_id=42)

    sql = _compiled_sql(session)
    assert "application_group_evaluations.group_id IN (7)" in sql
    assert "findings.server_id = 42" in sql


def test_rowcount_none_is_normalized_to_zero() -> None:
    session = _session_with_rowcount(None)

    updated = inherit_group_risk_to_findings(session)

    assert updated == 0


def test_reingest_skip_source_is_existing_llm_value() -> None:
    session = _session_with_rowcount()
    finding = Finding(risk_band_source="llm")

    inherit_group_risk_to_findings(session)

    assert finding.risk_band_source == "llm"
    sql = _compiled_sql(session)
    assert "risk_band_source='llm'" in sql
