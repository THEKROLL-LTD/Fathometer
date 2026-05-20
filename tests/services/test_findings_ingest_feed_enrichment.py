"""Unit-Tests fuer ``_enrich_with_feeds`` (Block Q Phase 2, ADR-0024).

Testet die Bulk-Lookup-Anreicherung von EPSS- und KEV-Daten in
``findings_ingest._enrich_with_feeds``. Keine echte DB — die Session
wird per ``MagicMock`` gestubbt, ``session.scalars(...)``-Returns sind
Lists von Stub-Objekten mit den erwarteten Attributen.

Anforderungen aus ADR-0024:

* Bulk-IN-Lookup ueber alle CVE-Identifier in einem Scan-Batch.
* Nur ``CVE-...``-Identifier loesen Lookups aus (GHSA/RHSA/etc.
  bleiben unberuehrt).
* Treffer ueberschreiben Scanner-gelieferte Werte (Feed ist autoritativ).
* KEV-Date wird auf 00:00 UTC normiert (Spalten-Semantik der Finding-
  Tabelle).
* Leeres Row-Set / Keine CVE-IDs / Keine Feed-Treffer = no-op.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any
from unittest.mock import MagicMock

from app.services.findings_ingest import _enrich_with_feeds


def _epss_stub(cve_id: str, score: float, percentile: float) -> Any:
    """Stub fuer einen ``EpssScore``-ORM-Eintrag."""
    stub = MagicMock()
    stub.cve_id = cve_id
    stub.epss_score = score
    stub.epss_percentile = percentile
    return stub


def _kev_stub(cve_id: str, date_added: date) -> Any:
    """Stub fuer einen ``CisaKevCatalog``-ORM-Eintrag."""
    stub = MagicMock()
    stub.cve_id = cve_id
    stub.date_added = date_added
    return stub


def _make_session(epss: list[Any], kev: list[Any]) -> MagicMock:
    """Baut einen MagicMock-Session mit zwei aufeinanderfolgenden ``scalars``-Returns.

    Reihenfolge im Service-Code: erst EPSS-Query, dann KEV-Query. Wir
    geben die Mock-Resultate in derselben Reihenfolge ueber ``side_effect``.
    """
    session = MagicMock()
    session.scalars.side_effect = [iter(epss), iter(kev)]
    return session


def _row(cve: str, **overrides: Any) -> dict[str, Any]:
    """Minimaler Finding-Row-Dict wie ``_build_finding_row`` ihn erzeugt."""
    base: dict[str, Any] = {
        "identifier_key": cve,
        "package_name": "openssl",
        "severity": "HIGH",
        "epss_score": None,
        "epss_percentile": None,
        "is_kev": False,
        "kev_added_at": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Happy-Path: ein Treffer pro Feed
# ---------------------------------------------------------------------------


def test_enrich_with_feeds_sets_epss_and_kev_fields() -> None:
    rows = [_row("CVE-2024-6387")]
    session = _make_session(
        epss=[_epss_stub("CVE-2024-6387", 0.42, 0.97)],
        kev=[_kev_stub("CVE-2024-6387", date(2024, 7, 1))],
    )

    _enrich_with_feeds(session, rows)

    assert rows[0]["epss_score"] == 0.42
    assert rows[0]["epss_percentile"] == 0.97
    assert rows[0]["is_kev"] is True
    assert rows[0]["kev_added_at"] == datetime(2024, 7, 1, 0, 0, 0, tzinfo=UTC)


def test_enrich_overwrites_scanner_provided_values() -> None:
    """ADR-0024: Feed-Werte sind fuehrend, auch wenn Scanner schon etwas geliefert hat."""
    rows = [_row("CVE-2024-6387", epss_score=0.01, is_kev=False)]
    session = _make_session(
        epss=[_epss_stub("CVE-2024-6387", 0.42, 0.97)],
        kev=[_kev_stub("CVE-2024-6387", date(2024, 7, 1))],
    )

    _enrich_with_feeds(session, rows)

    assert rows[0]["epss_score"] == 0.42
    assert rows[0]["is_kev"] is True


# ---------------------------------------------------------------------------
# Partial-Treffer: nur EPSS, nur KEV
# ---------------------------------------------------------------------------


def test_enrich_only_epss_match_leaves_kev_untouched() -> None:
    rows = [_row("CVE-2024-1111")]
    session = _make_session(
        epss=[_epss_stub("CVE-2024-1111", 0.05, 0.5)],
        kev=[],
    )

    _enrich_with_feeds(session, rows)

    assert rows[0]["epss_score"] == 0.05
    assert rows[0]["epss_percentile"] == 0.5
    assert rows[0]["is_kev"] is False
    assert rows[0]["kev_added_at"] is None


def test_enrich_only_kev_match_leaves_epss_untouched() -> None:
    rows = [_row("CVE-2024-2222")]
    session = _make_session(
        epss=[],
        kev=[_kev_stub("CVE-2024-2222", date(2025, 1, 15))],
    )

    _enrich_with_feeds(session, rows)

    assert rows[0]["epss_score"] is None
    assert rows[0]["epss_percentile"] is None
    assert rows[0]["is_kev"] is True
    assert rows[0]["kev_added_at"] == datetime(2025, 1, 15, 0, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Multi-Row: nur die getroffenen Rows werden angereichert
# ---------------------------------------------------------------------------


def test_enrich_multiple_rows_partial_hits() -> None:
    rows = [
        _row("CVE-2024-AAAA"),
        _row("CVE-2024-BBBB"),
        _row("CVE-2024-CCCC"),
    ]
    session = _make_session(
        epss=[_epss_stub("CVE-2024-AAAA", 0.1, 0.2), _epss_stub("CVE-2024-CCCC", 0.9, 0.99)],
        kev=[_kev_stub("CVE-2024-BBBB", date(2024, 3, 1))],
    )

    _enrich_with_feeds(session, rows)

    assert rows[0]["epss_score"] == 0.1
    assert rows[0]["is_kev"] is False

    assert rows[1]["epss_score"] is None
    assert rows[1]["is_kev"] is True

    assert rows[2]["epss_score"] == 0.9
    assert rows[2]["is_kev"] is False


# ---------------------------------------------------------------------------
# Non-CVE-Identifier werden ignoriert
# ---------------------------------------------------------------------------


def test_enrich_skips_non_cve_identifiers() -> None:
    """GHSA-, RHSA-, etc. haben keine EPSS/KEV-Quellen — Lookup-Pfad muss skippen."""
    rows = [
        _row("GHSA-1234-5678-90ab"),
        _row("RHSA-2024:0001"),
    ]
    session = _make_session(epss=[], kev=[])

    _enrich_with_feeds(session, rows)

    # ``session.scalars`` darf gar nicht erst aufgerufen werden, weil
    # keine CVE-IDs im Set sind.
    session.scalars.assert_not_called()
    # Felder bleiben auf den Defaults.
    assert rows[0]["epss_score"] is None
    assert rows[0]["is_kev"] is False


def test_enrich_with_mixed_identifiers_only_queries_for_cves() -> None:
    rows = [
        _row("CVE-2024-AAAA"),
        _row("GHSA-1234-5678-90ab"),
    ]
    session = _make_session(
        epss=[_epss_stub("CVE-2024-AAAA", 0.5, 0.9)],
        kev=[],
    )

    _enrich_with_feeds(session, rows)

    assert rows[0]["epss_score"] == 0.5
    assert rows[1]["epss_score"] is None


# ---------------------------------------------------------------------------
# No-op-Pfade
# ---------------------------------------------------------------------------


def test_enrich_empty_rows_is_noop() -> None:
    session = MagicMock()
    _enrich_with_feeds(session, [])
    session.scalars.assert_not_called()


def test_enrich_no_feed_hits_is_noop_after_lookup() -> None:
    """Wenn Feeds leer sind: keine Row-Mutationen."""
    rows = [_row("CVE-2024-AAAA"), _row("CVE-2024-BBBB")]
    session = _make_session(epss=[], kev=[])

    _enrich_with_feeds(session, rows)

    for row in rows:
        assert row["epss_score"] is None
        assert row["epss_percentile"] is None
        assert row["is_kev"] is False
        assert row["kev_added_at"] is None


def test_enrich_handles_missing_identifier_key_gracefully() -> None:
    """Defensiv: Rows ohne ``identifier_key`` werden uebersprungen statt zu crashen."""
    rows: list[dict[str, Any]] = [
        {"package_name": "openssl"},  # kein identifier_key
        _row("CVE-2024-AAAA"),
    ]
    session = _make_session(
        epss=[_epss_stub("CVE-2024-AAAA", 0.1, 0.2)],
        kev=[],
    )

    _enrich_with_feeds(session, rows)

    assert "epss_score" not in rows[0]
    assert rows[1]["epss_score"] == 0.1
