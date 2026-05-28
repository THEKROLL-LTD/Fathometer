"""Block AA (ADR-0041) — `list_bucket_findings` eager-loaded Notes.

Pure-Unit-Tests (Mock-Session, kein DB-Roundtrip): der Bucket-Query-Service
muss `selectinload(Finding.notes)` als Loader-Option fuehren, damit der
Inline-Body (`finding_inline_body.html`) den Notes-Thread ohne N+1 rendern
kann. Findings ohne Notes liefern eine leere Liste.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from werkzeug.datastructures import ImmutableMultiDict

from app.schemas.dashboard_filter import DashboardFilter
from app.services.findings_bucket_query import list_bucket_findings

_EMPTY_ARGS: ImmutableMultiDict[str, str] = ImmutableMultiDict()


def _session_for_list(findings: list[Any], total: int) -> MagicMock:
    session = MagicMock()
    count_result = MagicMock()
    count_result.scalar.return_value = total
    list_result = MagicMock()
    list_result.scalars.return_value.unique.return_value.all.return_value = findings
    list_result.scalars.return_value.all.return_value = findings
    session.execute.side_effect = [count_result, list_result]
    return session


def test_list_bucket_findings_eager_loads_notes() -> None:
    """Die LIST-Query (zweites execute) traegt selectinload(Finding.notes)."""
    session = _session_for_list([], total=0)
    list_bucket_findings(
        session,
        server_id=1,
        group_id=2,
        filt=DashboardFilter.from_request(_EMPTY_ARGS),
        page=1,
        per_page=20,
    )
    # COUNT-Query ist call[0], LIST-Query ist call[1].
    list_stmt = session.execute.call_args_list[1].args[0]
    opts_repr = " ".join(str(getattr(o, "path", o)) for o in list_stmt._with_options)
    assert "Finding.notes" in opts_repr, (
        f"selectinload(Finding.notes) fehlt in Loader-Optionen: {opts_repr}"
    )


def test_list_bucket_findings_keeps_server_and_group_loaders() -> None:
    """Bestehende Eager-Loader (server, application_group) bleiben erhalten."""
    session = _session_for_list([], total=0)
    list_bucket_findings(
        session,
        server_id=1,
        group_id=2,
        filt=DashboardFilter.from_request(_EMPTY_ARGS),
        page=1,
        per_page=20,
    )
    list_stmt = session.execute.call_args_list[1].args[0]
    opts_repr = " ".join(str(getattr(o, "path", o)) for o in list_stmt._with_options)
    assert "Finding.server" in opts_repr
    assert "Finding.application_group" in opts_repr


def test_list_bucket_findings_empty_returns_empty_list() -> None:
    """total==0 liefert ([], 0) — keine Notes-Iteration noetig."""
    session = _session_for_list([], total=0)
    findings, total = list_bucket_findings(
        session,
        server_id=1,
        group_id=0,
        filt=DashboardFilter.from_request(_EMPTY_ARGS),
        page=1,
        per_page=20,
    )
    assert findings == []
    assert total == 0
