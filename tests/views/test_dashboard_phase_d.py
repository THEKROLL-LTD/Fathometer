"""Pure-Unit-Tests fuer Phase D (ADR-0030 Befund 5) — Dashboard-Risk-Aggregate-
Konsolidierung.

Deckt:
  * `_load_open_aggregates`: eine einzige Query (Query-Count-Beweis via
    session.execute-Spy). Verhaltens-Aequivalenz: liefert identische
    `counts_by_server`- und `kev_by_server`-Maps wie vor der Konsolidierung.
  * `_load_risk_kpi_counters`: zwei Queries (Findings + aktive Server).
    Verhaltens-Aequivalenz: liefert identisches `RiskKpiCounters`-Objekt.
  * `yes_servers`-Ableitung aus `risk_bands_by_server` (kein Distinct-JOIN).

Kein echter DB-Zugriff — Mock-Session mit Fake-Result-Sets.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from app.models import Severity
from app.views.dashboard import _load_open_aggregates, _load_risk_kpi_counters

# ---------------------------------------------------------------------------
# Helpers — Fake-Result-Row-Builder
# ---------------------------------------------------------------------------


def _make_row(**kwargs: int | str) -> Any:
    """Einfacher Namespace der Attribut-Zugriffe auf kwargs weiterleitet.

    Ersetzt eine echte SQLAlchemy-RowMapping fuer Unit-Tests.
    """
    obj = MagicMock()
    for key, value in kwargs.items():
        setattr(obj, key, value)
    return obj


def _mock_session_for_open_aggregates(rows: list[Any]) -> MagicMock:
    """Erzeugt eine Mock-Session, deren execute().all() die uebergebenen Rows
    liefert. Wird fuer `_load_open_aggregates` genutzt (eine Query).
    """
    sess = MagicMock()
    result = MagicMock()
    result.all.return_value = rows
    sess.execute.return_value = result
    return sess


def _mock_session_for_risk_kpi_counters(
    findings_row: Any,
    total_active: int,
) -> MagicMock:
    """Erzeugt eine Mock-Session fuer `_load_risk_kpi_counters`.

    Erster execute()-Call -> findings_row (konsolidierte Findings-Query).
    Zweiter execute()-Call -> Scalar total_active (aktive Server).
    """
    sess = MagicMock()
    findings_result = MagicMock()
    findings_result.one.return_value = findings_row

    scalar_result = MagicMock()
    scalar_result.scalar.return_value = total_active

    sess.execute.side_effect = [findings_result, scalar_result]
    return sess


# ---------------------------------------------------------------------------
# _load_open_aggregates — Query-Count-Beweis (DoD-D-1)
# ---------------------------------------------------------------------------


def test_load_open_aggregates_makes_exactly_one_execute_call() -> None:
    """DoD-D-1: `_load_open_aggregates` darf exakt einen session.execute-Call
    machen — Beweis dass Severity-, KEV- und Risk-Band-Aggregation in einer
    einzigen Query konsolidiert sind.
    """
    row = _make_row(
        server_id=1,
        crit=3,
        high=5,
        medium=1,
        low=0,
        unknown=0,
        kev=2,
        rb_escalate=1,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=2,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
    )
    sess = _mock_session_for_open_aggregates([row])

    _load_open_aggregates(sess)

    assert sess.execute.call_count == 1, (
        f"_load_open_aggregates muss genau 1 execute-Call machen, "
        f"hat aber {sess.execute.call_count} gemacht."
    )


# ---------------------------------------------------------------------------
# _load_open_aggregates — Verhaltens-Aequivalenz (counts_by_server)
# ---------------------------------------------------------------------------


def test_load_open_aggregates_returns_correct_severity_counts() -> None:
    """Severity-Buckets werden korrekt in SeverityCounts gemapped."""
    row = _make_row(
        server_id=42,
        crit=10,
        high=20,
        medium=5,
        low=2,
        unknown=1,
        kev=3,
        rb_escalate=4,
        rb_act=1,
        rb_mitigate=0,
        rb_pending=5,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
    )
    sess = _mock_session_for_open_aggregates([row])

    counts_by_server, _kev, _bands = _load_open_aggregates(sess)

    assert 42 in counts_by_server
    sc = counts_by_server[42]
    assert sc.critical == 10
    assert sc.high == 20
    assert sc.medium == 5
    assert sc.low == 2
    assert sc.unknown == 1
    assert sc.total == 38


def test_load_open_aggregates_returns_correct_kev_counts() -> None:
    """KEV-Counts werden korrekt in kev_by_server gemapped."""
    row = _make_row(
        server_id=7,
        crit=0,
        high=0,
        medium=0,
        low=0,
        unknown=0,
        kev=11,
        rb_escalate=0,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
    )
    sess = _mock_session_for_open_aggregates([row])

    _counts, kev_by_server, _bands = _load_open_aggregates(sess)

    assert kev_by_server.get(7) == 11


def test_load_open_aggregates_returns_correct_risk_bands() -> None:
    """risk_bands_by_server enthaelt alle sieben Band-Keys mit korrekten Werten."""
    row = _make_row(
        server_id=3,
        crit=0,
        high=0,
        medium=0,
        low=0,
        unknown=0,
        kev=0,
        rb_escalate=5,
        rb_act=2,
        rb_mitigate=1,
        rb_pending=3,
        rb_unknown=0,
        rb_monitor=7,
        rb_noise=4,
    )
    sess = _mock_session_for_open_aggregates([row])

    _, _, risk_bands_by_server = _load_open_aggregates(sess)

    assert 3 in risk_bands_by_server
    bands = risk_bands_by_server[3]
    assert bands["escalate"] == 5
    assert bands["act"] == 2
    assert bands["mitigate"] == 1
    assert bands["pending"] == 3
    assert bands["unknown"] == 0
    assert bands["monitor"] == 7
    assert bands["noise"] == 4


def test_load_open_aggregates_empty_findings_returns_empty_dicts() -> None:
    """Wenn keine OPEN-Findings vorhanden sind, werden leere Dicts zurueckgegeben."""
    sess = _mock_session_for_open_aggregates([])

    counts_by_server, kev_by_server, risk_bands_by_server = _load_open_aggregates(sess)

    assert counts_by_server == {}
    assert kev_by_server == {}
    assert risk_bands_by_server == {}


def test_load_open_aggregates_multiple_servers() -> None:
    """Mehrere Server werden korrekt als separate Eintraege gemapped."""
    rows = [
        _make_row(
            server_id=1,
            crit=3,
            high=0,
            medium=0,
            low=0,
            unknown=0,
            kev=1,
            rb_escalate=1,
            rb_act=0,
            rb_mitigate=0,
            rb_pending=0,
            rb_unknown=0,
            rb_monitor=0,
            rb_noise=0,
        ),
        _make_row(
            server_id=2,
            crit=0,
            high=2,
            medium=0,
            low=0,
            unknown=0,
            kev=0,
            rb_escalate=0,
            rb_act=2,
            rb_mitigate=0,
            rb_pending=0,
            rb_unknown=0,
            rb_monitor=0,
            rb_noise=0,
        ),
    ]
    sess = _mock_session_for_open_aggregates(rows)

    counts_by_server, kev_by_server, risk_bands_by_server = _load_open_aggregates(sess)

    assert len(counts_by_server) == 2
    assert counts_by_server[1].critical == 3
    assert counts_by_server[2].high == 2
    assert kev_by_server[1] == 1
    assert kev_by_server.get(2, 0) == 0
    assert risk_bands_by_server[1]["escalate"] == 1
    assert risk_bands_by_server[2]["act"] == 2


# ---------------------------------------------------------------------------
# _load_risk_kpi_counters — Query-Count-Beweis (DoD-D-2)
# ---------------------------------------------------------------------------


def test_load_risk_kpi_counters_makes_exactly_two_execute_calls() -> None:
    """DoD-D-2: `_load_risk_kpi_counters` darf exakt zwei execute-Calls machen
    (1 Findings-FILTER-Query + 1 aktive-Server-Count-Query).
    """
    findings_row = _make_row(
        rb_escalate=0,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=2)

    _load_risk_kpi_counters(sess, risk_bands_by_server={}, active_server_ids=set())

    assert sess.execute.call_count == 2, (
        f"_load_risk_kpi_counters muss genau 2 execute-Calls machen, "
        f"hat aber {sess.execute.call_count} gemacht."
    )


# ---------------------------------------------------------------------------
# _load_risk_kpi_counters — Verhaltens-Aequivalenz
# ---------------------------------------------------------------------------


def test_load_risk_kpi_counters_returns_correct_band_counts() -> None:
    """risk_band_counts spiegelt die Findings-Query-Ergebnisse korrekt."""
    findings_row = _make_row(
        rb_escalate=10,
        rb_act=5,
        rb_mitigate=3,
        rb_pending=2,
        rb_unknown=1,
        rb_monitor=7,
        rb_noise=4,
        sev_critical=8,
        sev_high=6,
        sev_medium=4,
        sev_low=2,
    )
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=5)

    result = _load_risk_kpi_counters(sess, risk_bands_by_server={}, active_server_ids=set())

    assert result.risk_band_counts["escalate"] == 10
    assert result.risk_band_counts["act"] == 5
    assert result.risk_band_counts["mitigate"] == 3
    assert result.risk_band_counts["pending"] == 2
    assert result.risk_band_counts["unknown"] == 1
    assert result.risk_band_counts["monitor"] == 7
    assert result.risk_band_counts["noise"] == 4


def test_load_risk_kpi_counters_returns_correct_severity_strip() -> None:
    """severity_strip_counts enthaelt die korrekten Werte ohne UNKNOWN."""
    findings_row = _make_row(
        rb_escalate=0,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=15,
        sev_high=10,
        sev_medium=5,
        sev_low=1,
    )
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=3)

    result = _load_risk_kpi_counters(sess, risk_bands_by_server={}, active_server_ids=set())

    assert result.severity_strip_counts[Severity.CRITICAL.value] == 15
    assert result.severity_strip_counts[Severity.HIGH.value] == 10
    assert result.severity_strip_counts[Severity.MEDIUM.value] == 5
    assert result.severity_strip_counts[Severity.LOW.value] == 1
    # UNKNOWN darf nicht im Severity-Strip erscheinen.
    assert Severity.UNKNOWN.value not in result.severity_strip_counts


def test_load_risk_kpi_counters_yes_servers_derived_from_risk_bands() -> None:
    """yes_servers wird aus risk_bands_by_server abgeleitet — kein separater
    Distinct-Count-JOIN. Server mit mindestens einem yes-Band-Finding werden
    als action_yes_servers gezaehlt.

    yes-Bands: escalate, act, mitigate, pending, unknown.
    """
    # Server 1: hat escalate-Findings -> yes.
    # Server 2: hat nur monitor/noise -> no.
    # Server 3: hat pending-Findings -> yes.
    risk_bands_by_server = {
        1: {
            "escalate": 3,
            "act": 0,
            "mitigate": 0,
            "pending": 0,
            "unknown": 0,
            "monitor": 0,
            "noise": 0,
        },
        2: {
            "escalate": 0,
            "act": 0,
            "mitigate": 0,
            "pending": 0,
            "unknown": 0,
            "monitor": 5,
            "noise": 2,
        },
        3: {
            "escalate": 0,
            "act": 0,
            "mitigate": 0,
            "pending": 1,
            "unknown": 0,
            "monitor": 0,
            "noise": 0,
        },
    }
    findings_row = _make_row(
        rb_escalate=3,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=1,
        rb_unknown=0,
        rb_monitor=5,
        rb_noise=2,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )
    # 3 aktive Server total: 2 yes, 1 no. Alle drei Server sind aktiv.
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=3)
    active_server_ids = {1, 2, 3}

    result = _load_risk_kpi_counters(
        sess,
        risk_bands_by_server=risk_bands_by_server,
        active_server_ids=active_server_ids,
    )

    assert result.action_yes_servers == 2, (
        f"Erwartet 2 yes-Server (Server 1 + 3), erhalten: {result.action_yes_servers}"
    )
    assert result.action_no_servers == 1, (
        f"Erwartet 1 no-Server (Server 2), erhalten: {result.action_no_servers}"
    )


def test_load_risk_kpi_counters_no_findings_empty_risk_bands() -> None:
    """Bei leerer risk_bands_by_server ist action_yes_servers == 0."""
    findings_row = _make_row(
        rb_escalate=0,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=4)

    result = _load_risk_kpi_counters(sess, risk_bands_by_server={}, active_server_ids={1, 2, 3, 4})

    assert result.action_yes_servers == 0
    assert result.action_no_servers == 4


def test_load_risk_kpi_counters_action_yes_subcounts_order() -> None:
    """action_yes_subcounts enthaelt alle yes-Band-Keys mit korrekten Werten.

    Die Reihenfolge muss yes_band_values() entsprechen (escalate first).
    """
    findings_row = _make_row(
        rb_escalate=10,
        rb_act=5,
        rb_mitigate=3,
        rb_pending=2,
        rb_unknown=1,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=1)

    result = _load_risk_kpi_counters(sess, risk_bands_by_server={}, active_server_ids=set())

    from app.services.risk_engine import yes_band_values

    yes_bands = yes_band_values()
    # Alle yes-Bands muessen im Subcount vorhanden sein.
    for band in yes_bands:
        assert band in result.action_yes_subcounts, f"Band {band!r} fehlt in action_yes_subcounts"
    # no-Bands (monitor, noise) duerfen NICHT im Subcount sein.
    assert "monitor" not in result.action_yes_subcounts
    assert "noise" not in result.action_yes_subcounts
    # Werte stimmen.
    assert result.action_yes_subcounts["escalate"] == 10
    assert result.action_yes_subcounts["act"] == 5


# ---------------------------------------------------------------------------
# Phase-D-Fix — Revoke/Retire-Edge-Cases (ADR-0030 Befund 5 Folge)
# ---------------------------------------------------------------------------


def test_load_risk_kpi_counters_revoked_server_excluded_from_yes_servers() -> None:
    """Revoke-Edge-Case: ein revoked Server mit yes-Band-Findings darf NICHT
    in action_yes_servers gezaehlt werden.

    Szenario:
      Server 1 (aktiv):  escalate=5  -> yes
      Server 2 (revoked): act=3      -> darf nicht mitgezaehlt werden

    Mit dem alten Bug (kein active_server_ids-Filter) waere das Ergebnis 2.
    Mit dem Fix muss es 1 sein.
    """
    risk_bands_by_server = {
        1: {
            "escalate": 5,
            "act": 0,
            "mitigate": 0,
            "pending": 0,
            "unknown": 0,
            "monitor": 0,
            "noise": 0,
        },
        2: {
            "escalate": 0,
            "act": 3,
            "mitigate": 0,
            "pending": 0,
            "unknown": 0,
            "monitor": 0,
            "noise": 0,
        },
    }
    findings_row = _make_row(
        rb_escalate=5,
        rb_act=3,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )
    # Nur Server 1 ist aktiv; Server 2 ist revoked und fehlt im Set.
    active_server_ids = {1}
    # total_active = 1 (nur Server 1 — Server 2 ist revoked, zaehlt nicht).
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=1)

    result = _load_risk_kpi_counters(
        sess,
        risk_bands_by_server=risk_bands_by_server,
        active_server_ids=active_server_ids,
    )

    assert result.action_yes_servers == 1, (
        f"Revoke-Edge-Case: Erwartet action_yes_servers == 1 (nur aktiver Server 1), "
        f"erhalten: {result.action_yes_servers}. "
        f"Revoked Server 2 mit act=3 darf nicht mitgezaehlt werden."
    )
    assert result.action_no_servers == 0, (
        f"Erwartet action_no_servers == 0, erhalten: {result.action_no_servers}"
    )


def test_load_risk_kpi_counters_all_servers_retired_or_revoked_gives_zero_yes() -> None:
    """Retire/Revoke-Edge-Case: wenn alle Server inactive sind, ist
    action_yes_servers == 0, auch wenn risk_bands_by_server Eintraege hat.

    Szenario: Server 1 ist retired. Retire loest zwar OPEN-Findings auf
    (Retire-Pfad in servers.py Z. 105-119), aber die Filter-Logik muss
    trotzdem korrekt sein — active_server_ids ist leer.
    """
    risk_bands_by_server = {
        1: {
            "escalate": 5,
            "act": 0,
            "mitigate": 0,
            "pending": 0,
            "unknown": 0,
            "monitor": 0,
            "noise": 0,
        },
    }
    findings_row = _make_row(
        rb_escalate=5,
        rb_act=0,
        rb_mitigate=0,
        rb_pending=0,
        rb_unknown=0,
        rb_monitor=0,
        rb_noise=0,
        sev_critical=0,
        sev_high=0,
        sev_medium=0,
        sev_low=0,
    )
    # Alle Server retired/revoked -> active_server_ids ist leer.
    active_server_ids: set[int] = set()
    # total_active = 0.
    sess = _mock_session_for_risk_kpi_counters(findings_row, total_active=0)

    result = _load_risk_kpi_counters(
        sess,
        risk_bands_by_server=risk_bands_by_server,
        active_server_ids=active_server_ids,
    )

    assert result.action_yes_servers == 0, (
        f"Retire-Edge-Case: Erwartet action_yes_servers == 0 (keine aktiven Server), "
        f"erhalten: {result.action_yes_servers}."
    )
    assert result.action_no_servers == 0, (
        f"Erwartet action_no_servers == 0 (total_active=0), erhalten: {result.action_no_servers}"
    )
