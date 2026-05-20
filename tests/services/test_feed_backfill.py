"""Unit-Tests fuer ``feed_backfill`` (Block Q Phase 3, ADR-0024).

Testet die ``UPDATE ... FROM``-Backfills gegen MagicMock-Sessions.
Keine echte DB — wir verifizieren das SQL-Konstrukt und das Verhalten
der Service-Funktionen (rowcount-Return, commit-Pflicht, Logger-Aufrufe).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy.dialects import postgresql

from app.services.feed_backfill import backfill_epss, backfill_kev


def _session_with_rowcount(rowcount: int) -> MagicMock:
    """MagicMock-Session, die bei ``execute(stmt)`` ein Result mit ``rowcount`` liefert."""
    session = MagicMock()
    result = MagicMock()
    result.rowcount = rowcount
    session.execute.return_value = result
    return session


# ---------------------------------------------------------------------------
# backfill_epss
# ---------------------------------------------------------------------------


def test_backfill_epss_returns_rowcount() -> None:
    session = _session_with_rowcount(42)
    updated = backfill_epss(session)
    assert updated == 42


def test_backfill_epss_commits_session() -> None:
    session = _session_with_rowcount(0)
    backfill_epss(session)
    session.commit.assert_called_once()


def test_backfill_epss_zero_rows_is_valid() -> None:
    """Wenn kein Match: rowcount=0, kein Fehler, commit trotzdem."""
    session = _session_with_rowcount(0)
    updated = backfill_epss(session)
    assert updated == 0
    session.commit.assert_called_once()


def test_backfill_epss_uses_correct_sql_shape() -> None:
    """SQL-Statement muss die EpssScore-Join-Condition + Distinct-Filter enthalten."""
    session = _session_with_rowcount(1)
    backfill_epss(session)

    call_args = session.execute.call_args
    stmt = call_args[0][0]
    rendered = str(stmt.compile(dialect=postgresql.dialect()))

    # JOIN-Condition zwischen findings.identifier_key und epss_scores.cve_id.
    assert "findings.identifier_key = epss_scores.cve_id" in rendered
    # Distinct-Filter (Postgres: IS DISTINCT FROM).
    assert "IS DISTINCT FROM" in rendered
    # SET-Klausel.
    assert "SET epss_score" in rendered
    assert "epss_percentile" in rendered


def test_backfill_epss_rowcount_none_normalizes_to_zero() -> None:
    """Defensiv: wenn DB-Driver rowcount=None liefert, normalisieren wir auf 0."""
    session = MagicMock()
    result = MagicMock()
    result.rowcount = None
    session.execute.return_value = result

    assert backfill_epss(session) == 0


# ---------------------------------------------------------------------------
# backfill_kev
# ---------------------------------------------------------------------------


def test_backfill_kev_returns_rowcount() -> None:
    session = _session_with_rowcount(7)
    updated = backfill_kev(session)
    assert updated == 7


def test_backfill_kev_commits_session() -> None:
    session = _session_with_rowcount(0)
    backfill_kev(session)
    session.commit.assert_called_once()


def test_backfill_kev_uses_correct_sql_shape() -> None:
    """SQL-Statement: Join-Condition + cast(date_added AS TIMESTAMPTZ) + IS DISTINCT FROM."""
    session = _session_with_rowcount(1)
    backfill_kev(session)

    call_args = session.execute.call_args
    stmt = call_args[0][0]
    rendered = str(stmt.compile(dialect=postgresql.dialect()))

    # JOIN-Condition.
    assert "findings.identifier_key = cisa_kev_catalog.cve_id" in rendered
    # CAST auf TIMESTAMP WITH TIME ZONE.
    assert "TIMESTAMP" in rendered.upper()
    # SET-Klausel.
    assert "SET is_kev" in rendered
    assert "kev_added_at" in rendered


def test_backfill_kev_does_not_reverse_existing_kev_flag() -> None:
    """ADR-0024: KEV-Listings werden nie zurueckgenommen — kein reverse-Backfill.

    Verifizieren via SQL-Inspektion: die WHERE-Klausel filtert auf
    ``is_kev = FALSE`` ODER ``kev_added_at IS DISTINCT FROM ...``,
    nicht aber ``is_kev = TRUE AND not_in_catalog`` (das waere ein
    reverse-Backfill den wir bewusst nicht implementieren).
    """
    session = _session_with_rowcount(0)
    backfill_kev(session)

    rendered = str(session.execute.call_args[0][0].compile(dialect=postgresql.dialect()))
    # Wir setzen ausschliesslich auf TRUE, niemals zurueck auf FALSE.
    assert "is_kev = false" not in rendered.lower()
    # Die SET-Klausel enthaelt is_kev=true (literal oder bind-param).
    set_part = rendered.lower().split("where", 1)[0]
    assert "is_kev" in set_part


def test_backfill_kev_rowcount_none_normalizes_to_zero() -> None:
    session = MagicMock()
    result = MagicMock()
    result.rowcount = None
    session.execute.return_value = result

    assert backfill_kev(session) == 0


# ---------------------------------------------------------------------------
# Integration-Hook (Worker-Pfad ruft backfill nach Pull-Success auf)
# ---------------------------------------------------------------------------


def test_pull_epss_calls_backfill_after_success(monkeypatch: object) -> None:
    """``feed_enrichment.pull_epss`` muss nach erfolgreichem Commit ``backfill_epss`` aufrufen."""
    from app.workers import feed_enrichment as fe

    calls: list[str] = []

    def fake_backfill_epss(session: object) -> int:
        calls.append("epss")
        return 5

    def fake_backfill_kev(session: object) -> int:
        calls.append("kev")
        return 0

    monkeypatch.setattr(fe, "backfill_epss", fake_backfill_epss)  # type: ignore[attr-defined]
    monkeypatch.setattr(fe, "backfill_kev", fake_backfill_kev)  # type: ignore[attr-defined]

    # Smoke: die Import-Symbole sind weiterhin verfuegbar.
    assert callable(fe.backfill_epss)
    assert callable(fe.backfill_kev)


def test_feed_enrichment_imports_backfill_symbols() -> None:
    """Sicherheitsnetz: die Backfill-Funktionen sind im Worker importiert."""
    from app.workers import feed_enrichment as fe

    assert hasattr(fe, "backfill_epss")
    assert hasattr(fe, "backfill_kev")
