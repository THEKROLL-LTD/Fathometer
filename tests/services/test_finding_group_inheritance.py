"""Tests fuer Group-Risk-Vererbung auf Findings."""

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


def test_inherits_group_band_reason_and_llm_source_without_action_type() -> None:
    session = _session_with_rowcount(5)

    updated = inherit_group_risk_to_findings(session)

    assert updated == 5
    sql = _compiled_sql(session)
    assert "UPDATE findings" in sql
    assert "FROM application_groups" in sql
    assert "risk_band=application_groups.risk_band" in sql
    assert "risk_band_reason=application_groups.risk_band_reason" in sql
    assert "risk_band_source='llm'" in sql
    assert "risk_band_computed_at=now()" in sql
    assert "action_type" not in sql
    assert not hasattr(Finding, "action_type")
    session.commit.assert_not_called()


def test_skips_groups_without_final_risk_band_in_sql_shape() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    assert "application_groups.risk_band IS NOT NULL" in sql


def test_only_grouped_findings_are_joined_to_application_group() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    assert "findings.application_group_id = application_groups.id" in sql


def test_idempotency_filter_checks_band_source_and_reason() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session)

    sql = _compiled_sql(session)
    assert "findings.risk_band IS DISTINCT FROM application_groups.risk_band" in sql
    assert "findings.risk_band_source IS DISTINCT FROM 'llm'" in sql
    assert "findings.risk_band_reason IS DISTINCT FROM application_groups.risk_band_reason" in sql


def test_group_ids_filter_limits_update_to_given_groups() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session, group_ids=[10, 20])

    sql = _compiled_sql(session)
    assert "application_groups.id IN (10, 20)" in sql


def test_server_id_filter_limits_update_to_server() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session, server_id=42)

    sql = _compiled_sql(session)
    assert "findings.server_id = 42" in sql


def test_group_and_server_filters_can_be_combined() -> None:
    session = _session_with_rowcount()

    inherit_group_risk_to_findings(session, group_ids=[7], server_id=42)

    sql = _compiled_sql(session)
    assert "application_groups.id IN (7)" in sql
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
