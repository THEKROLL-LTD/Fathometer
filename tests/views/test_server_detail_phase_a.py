"""Pure-Unit-Tests fuer Block Y Phase A — `app/views/server_detail.py`.

Deckt die neuen Helper:
  * `_risk_band_header_counts` — GROUP-BY-Aggregat, Insertion-Order,
    Default-0, NULL/unknown-Bands wandern in `pending`.
  * `_tendency_quick` — 7-vs-7-Tage-Vergleich -> RISING/FALLING/STABLE.
  * `_load_application_groups_for_server` — Projektions-Pfad, Rueckgabe
    enthaelt Row-aehnliche Objekte mit den richtigen Spalten.
  * `_load_server_band_aggregates` — unified Aggregat: pending_by_band +
    Action-Required-Sub-Counts in einer Query.
  * `_pick_default_open_band` — Escalate-First, sonst erstes nicht-leeres.
  * Initial-Render hat Skeleton-Placeholder fuer Heartbeat + Trend, KEINE
    Finding-Rows, dafuer Risk-Band-Header mit korrekten Counts.
  * `count_findings` — KEV-Count kommt aus dem unified Status-GROUP-BY.

Kein DB-Fixture noetig: SessionExecute wird gemockt via SimpleNamespace.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from app.services.trend import Tendency
from app.views.server_detail import (
    _PENDING_BANDS,
    _RISK_BAND_SECTION_ORDER,
    _load_application_groups_for_server,
    _load_server_band_aggregates,
    _pick_default_open_band,
    _risk_band_header_counts,
    _tendency_quick,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(**fields: Any) -> SimpleNamespace:
    """Mini-Row-Object — SQLAlchemy-Row hat Attribut-Zugriff via Spaltenname."""
    return SimpleNamespace(**fields)


class _FakeResult:
    """Minimaler Result-Mock: erlaubt `.all()` und `.one()`."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)

    def one(self) -> Any:
        return self._rows[0]


def _fake_session(execute_returns: list[list[Any] | Any]) -> Any:
    """Liefert ein Session-Mock, das `execute()` der Reihe nach mit `_FakeResult`
    beantwortet."""
    calls = iter(execute_returns)

    def _execute(_stmt: Any) -> _FakeResult:
        payload = next(calls)
        if isinstance(payload, list):
            return _FakeResult(payload)
        return _FakeResult([payload])

    sess = MagicMock()
    sess.execute.side_effect = _execute
    return sess


# ---------------------------------------------------------------------------
# _risk_band_header_counts
# ---------------------------------------------------------------------------


def test_risk_band_header_counts_empty() -> None:
    """Leere Tabelle -> alle Bands mit Count 0 in _RISK_BAND_SECTION_ORDER."""
    sess = _fake_session([[]])
    result = _risk_band_header_counts(sess, 1)
    assert list(result.keys()) == list(_RISK_BAND_SECTION_ORDER)
    for v in result.values():
        assert v == 0


def test_risk_band_header_counts_typical() -> None:
    """GROUP-BY-Resultat wird in die Order-Map ueberfuehrt."""
    rows = [("escalate", 3), ("act", 12), ("noise", 7)]
    sess = _fake_session([rows])
    result = _risk_band_header_counts(sess, 1)
    assert result["escalate"] == 3
    assert result["act"] == 12
    assert result["noise"] == 7
    assert result["mitigate"] == 0
    assert result["pending"] == 0
    assert result["monitor"] == 0


def test_risk_band_header_counts_null_band_lands_in_pending() -> None:
    """NULL/unknown Risk-Band wandert in den pending-Bucket."""
    rows = [(None, 4), ("unknown", 2), ("act", 1)]
    sess = _fake_session([rows])
    result = _risk_band_header_counts(sess, 1)
    assert result["pending"] == 6  # 4 (None) + 2 (unknown)
    assert result["act"] == 1


def test_risk_band_header_counts_insertion_order_stable() -> None:
    """Insertion-Order entspricht _RISK_BAND_SECTION_ORDER auch bei Misch-Input."""
    rows = [("noise", 1), ("act", 2), ("escalate", 3)]
    sess = _fake_session([rows])
    result = _risk_band_header_counts(sess, 1)
    assert list(result.keys()) == list(_RISK_BAND_SECTION_ORDER)


# ---------------------------------------------------------------------------
# _tendency_quick
# ---------------------------------------------------------------------------


def test_tendency_quick_rising() -> None:
    """current > prev * 1.05 -> RISING."""
    row = _row(current=20, prev=10)
    sess = _fake_session([row])
    assert _tendency_quick(sess, 1) == Tendency.RISING


def test_tendency_quick_falling() -> None:
    """current < prev * 0.95 -> FALLING."""
    row = _row(current=5, prev=20)
    sess = _fake_session([row])
    assert _tendency_quick(sess, 1) == Tendency.FALLING


def test_tendency_quick_stable_equal() -> None:
    """Gleiche Counts -> STABLE."""
    row = _row(current=10, prev=10)
    sess = _fake_session([row])
    assert _tendency_quick(sess, 1) == Tendency.STABLE


def test_tendency_quick_zero_zero_is_stable() -> None:
    """Frisches Server-Profil ohne Findings -> STABLE."""
    row = _row(current=0, prev=0)
    sess = _fake_session([row])
    assert _tendency_quick(sess, 1) == Tendency.STABLE


def test_tendency_quick_label_matches_enum() -> None:
    """Tendency.label spiegelt den Enum-Wert."""
    assert Tendency.RISING.label == "rising over 30 days"
    assert Tendency.FALLING.label == "falling over 30 days"
    assert Tendency.STABLE.label == "stable over 30 days"


# ---------------------------------------------------------------------------
# _load_application_groups_for_server (Projektionen)
# ---------------------------------------------------------------------------


def test_load_application_groups_empty_returns_early() -> None:
    """Server ohne ungrouppte Findings -> leere Liste, kein weiterer Call."""
    sess = _fake_session([[]])
    assert _load_application_groups_for_server(sess, 1) == []
    assert sess.execute.call_count == 1


def test_load_application_groups_projection_shape() -> None:
    """Projektion liefert Row-Objekte mit den erwarteten Spalten — die
    Rueckgabe-Dicts tragen jetzt eine `lanes`-Liste (TICKET-013).
    """
    # (group_id, fix_lane, count) — Query (1) projiziert jetzt den Lane-CASE
    # direkt (ADR-0061), nicht mehr has_fix.
    counts_rows: list[Any] = [(10, "patch", 3), (20, "patch", 5)]
    group_rows = [
        _row(id=10, label="openssh", group_kind="os_package", explanation="x"),
        _row(id=20, label="bundle-x", group_kind="application_bundle", explanation=None),
    ]
    eval_rows = [
        _row(
            group_id=10,
            fix_lane="patch",
            risk_band="escalate",
            risk_band_reason="kev",
            worst_finding_id=100,
            action_type="patch",
            risk_band_computed_at=None,
            group_findings_fingerprint=None,
        ),
        _row(
            group_id=20,
            fix_lane="patch",
            risk_band="act",
            risk_band_reason=None,
            worst_finding_id=None,
            action_type="patch",
            risk_band_computed_at=None,
            group_findings_fingerprint=None,
        ),
    ]
    # ADR-0061: Query (4) ist der Live-Worst-Finding-Batch pro Lane
    # (DISTINCT ON application_group_id, <lane_case>) — Rows projizieren jetzt
    # fix_lane direkt (Lane-CASE), nicht mehr has_fix.
    finding_rows = [
        _row(
            application_group_id=10,
            fix_lane="patch",
            id=100,
            identifier_key="CVE-2026-1",
            package_name="openssh",
            title="bug",
        ),
    ]
    # TICKET-014: Query (5) — Lane-OPEN-Set-Projektion (Fingerprint + ID-Set).
    # Drift wird hier nicht geprueft; leeres Set genuegt fuer die Form-Tests.
    open_rows: list[Any] = []
    sess = _fake_session([counts_rows, group_rows, eval_rows, finding_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)

    assert len(result) == 2
    # Escalate-Group muss zuerst kommen (Max-Band ueber Lanes desc).
    first = result[0]
    assert first["group"].label == "openssh"
    assert first["group"].group_kind == "os_package"
    assert first["count"] == 3
    assert len(first["lanes"]) == 1
    patch_lane = first["lanes"][0]
    assert patch_lane["fix_lane"] == "patch"
    assert patch_lane["evaluation"].risk_band == "escalate"
    assert patch_lane["evaluation"].action_type == "patch"
    assert patch_lane["count"] == 3
    assert patch_lane["worst_finding"] is not None
    assert patch_lane["worst_finding"].identifier_key == "CVE-2026-1"

    second = result[1]
    assert second["group"].label == "bundle-x"
    assert second["lanes"][0]["evaluation"].risk_band == "act"
    # Kein Live-Worst-Row fuer Group 20 im Fixture -> defensiv None.
    assert second["lanes"][0]["worst_finding"] is None


def test_load_application_groups_missing_evaluation_ranks_as_pending() -> None:
    """Group ohne Junction-Row landet in PENDING-Rank — sortiert ueber act."""
    counts_rows: list[Any] = [(10, "patch", 1), (20, "patch", 1)]
    group_rows = [
        _row(id=10, label="grp-act", group_kind="os_package", explanation=None),
        _row(id=20, label="grp-pending", group_kind="os_package", explanation=None),
    ]
    eval_rows = [
        _row(
            group_id=10,
            fix_lane="patch",
            risk_band="act",
            risk_band_reason=None,
            worst_finding_id=None,
            action_type="patch",
            risk_band_computed_at=None,
            group_findings_fingerprint=None,
        ),
    ]
    # TICKET-013: Query (4) — Live-Worst-Finding-Batch — laeuft jetzt immer;
    # leeres Resultat ist der defensive Fall (worst_finding -> None).
    # TICKET-014: Query (5) — Lane-OPEN-Set-Projektion (hier ebenfalls leer).
    sess = _fake_session([counts_rows, group_rows, eval_rows, [], []])
    result = _load_application_groups_for_server(sess, 1)
    # ACT-Rank (60) > PENDING-Rank (40) -> ACT zuerst, dann PENDING.
    assert [e["group"].label for e in result] == ["grp-act", "grp-pending"]
    # Die letzte Group hat keine Evaluation auf ihrer Lane -> Pending-Rank.
    assert result[-1]["lanes"][0]["evaluation"] is None


# ---------------------------------------------------------------------------
# _load_server_band_aggregates
# ---------------------------------------------------------------------------


def test_load_server_band_aggregates_keys() -> None:
    """Rueckgabe hat alle dokumentierten Top-Level-Keys."""
    sess = _fake_session([[]])
    result = _load_server_band_aggregates(sess, 1)
    expected_keys = {
        "pending_by_band",
        "yes_subcounts",
        "no_subcounts",
        "yes_count",
        "no_count",
        "noise_count",
    }
    assert set(result.keys()) == expected_keys


def test_load_server_band_aggregates_pending_order() -> None:
    """pending_by_band hat _PENDING_BANDS-Insertion-Order und Default-0."""
    rows = [
        _row(risk_band="escalate", total=5, pending=2),
        _row(risk_band="noise", total=10, pending=3),
    ]
    sess = _fake_session([rows])
    result = _load_server_band_aggregates(sess, 1)
    assert list(result["pending_by_band"].keys()) == list(_PENDING_BANDS)
    assert result["pending_by_band"]["escalate"] == 2
    assert result["pending_by_band"]["noise"] == 3
    assert result["pending_by_band"]["pending"] == 0


def test_load_server_band_aggregates_yes_no_split() -> None:
    """yes_count summiert Yes-Bands (escalate/act/mitigate/pending/unknown),
    no_count summiert No-Bands (monitor/noise). noise_count = noise-total."""
    rows = [
        _row(risk_band="escalate", total=5, pending=2),
        _row(risk_band="act", total=3, pending=0),
        _row(risk_band="monitor", total=4, pending=4),
        _row(risk_band="noise", total=8, pending=1),
    ]
    sess = _fake_session([rows])
    result = _load_server_band_aggregates(sess, 1)
    # yes_count = escalate(5) + act(3) + sonstige Yes-Bands(0).
    assert result["yes_count"] == 8
    # no_count = monitor(4) + noise(8).
    assert result["no_count"] == 12
    assert result["noise_count"] == 8


def test_load_server_band_aggregates_empty_session() -> None:
    """Empty Result -> alle Zaehler 0."""
    sess = _fake_session([[]])
    result = _load_server_band_aggregates(sess, 1)
    assert result["yes_count"] == 0
    assert result["no_count"] == 0
    assert result["noise_count"] == 0
    assert all(v == 0 for v in result["pending_by_band"].values())


# ---------------------------------------------------------------------------
# _pick_default_open_band
# ---------------------------------------------------------------------------


def test_pick_default_open_band_prefers_escalate() -> None:
    counts = {"escalate": 1, "act": 5, "mitigate": 2, "pending": 0, "monitor": 0, "noise": 0}
    assert _pick_default_open_band(counts) == "escalate"


def test_pick_default_open_band_falls_back_to_first_nonempty() -> None:
    counts = {"escalate": 0, "act": 0, "mitigate": 3, "pending": 0, "monitor": 1, "noise": 0}
    assert _pick_default_open_band(counts) == "mitigate"


def test_pick_default_open_band_all_zero_returns_none() -> None:
    counts = dict.fromkeys(_RISK_BAND_SECTION_ORDER, 0)
    assert _pick_default_open_band(counts) is None


# ---------------------------------------------------------------------------
# count_findings (KEV in single query)
# ---------------------------------------------------------------------------


def test_count_findings_kev_in_single_query() -> None:
    """`count_findings` macht jetzt nur noch einen Roundtrip — der zweite
    KEV-Subquery ist weg, kev_open kommt aus dem OPEN-Bucket des Aggregats.
    """
    from app.models import FindingStatus
    from app.services.findings_query import FindingsFilter, count_findings

    rows = [
        _row(status=FindingStatus.OPEN, total=10, kev_open=4),
        _row(status=FindingStatus.ACKNOWLEDGED, total=2, kev_open=0),
        _row(status=FindingStatus.RESOLVED, total=5, kev_open=0),
    ]
    sess = _fake_session([rows])
    result = count_findings(sess, 1, FindingsFilter())
    assert result["open"] == 10
    assert result["acknowledged"] == 2
    assert result["resolved"] == 5
    assert result["total"] == 17
    assert result["kev_open"] == 4
    # WICHTIG: nur EIN sess.execute()-Call.
    assert sess.execute.call_count == 1, f"Erwartet 1 Roundtrip, gemessen {sess.execute.call_count}"


def test_count_findings_no_open_results() -> None:
    """Ohne OPEN-Bucket bleibt kev_open=0."""
    from app.models import FindingStatus
    from app.services.findings_query import FindingsFilter, count_findings

    rows = [
        _row(status=FindingStatus.RESOLVED, total=3, kev_open=0),
    ]
    sess = _fake_session([rows])
    result = count_findings(sess, 1, FindingsFilter())
    assert result["open"] == 0
    assert result["kev_open"] == 0


# ---------------------------------------------------------------------------
# Initial-Render Smoke-Tests via Flask test_client
# ---------------------------------------------------------------------------


@pytest.fixture
def _patched_show(app: Flask) -> Any:
    """Patcht alle DB-Calls in `show()` mit deterministischen Stubs."""
    server = MagicMock()
    server.id = 1
    server.name = "test-host"
    server.revoked_at = None
    server.retired_at = None
    server.last_scan_at = None
    server.trivy_db_updated_at = None
    server.expected_scan_interval_h = 24
    server.host_state_snapshot_at = None
    server.os_pretty_name = "Debian"
    server.kernel_version = "6.1"
    server.architecture = "x86_64"
    server.agent_version = "0.3.0"
    server.trivy_version = "0.50.0"
    server.tag_links = []
    return server


def _setup_show_patches(server: Any, header_counts: dict[str, int]) -> Any:
    """Liefert einen Context-Manager-Wrapper, der alle DB-Calls in show() patched."""
    from contextlib import ExitStack

    es = ExitStack()
    es.enter_context(patch("app.views.server_detail._load_server_with_tags", return_value=server))
    es.enter_context(patch("app.views.server_detail._all_tags", return_value=[]))
    es.enter_context(patch("app.views.server_detail.get_session", return_value=MagicMock()))
    es.enter_context(
        patch("app.views.server_detail._load_application_groups_for_server", return_value=[])
    )
    es.enter_context(
        patch(
            "app.views.server_detail._load_server_band_aggregates",
            return_value={
                "pending_by_band": dict.fromkeys(_PENDING_BANDS, 0),
                "yes_subcounts": {},
                "no_subcounts": {},
                "yes_count": 0,
                "no_count": 0,
                "noise_count": 0,
            },
        )
    )
    es.enter_context(
        patch("app.views.server_detail._risk_band_header_counts", return_value=header_counts)
    )
    es.enter_context(
        patch(
            "app.views.server_detail._quick_counts_for_server",
            return_value={
                "total_all": 0,
                "total_open": 0,
                "kev_open": 0,
                "critical_open": 0,
                "high_open": 0,
                "medium_open": 0,
                "low_open": 0,
            },
        )
    )
    es.enter_context(patch("app.views.server_detail._tendency_quick", return_value=Tendency.STABLE))
    es.enter_context(
        patch(
            "app.views.server_detail.count_findings",
            return_value={"open": 0, "acknowledged": 0, "resolved": 0, "total": 0, "kev_open": 0},
        )
    )
    es.enter_context(
        patch(
            "app.views.server_detail.get_settings_row",
            return_value=MagicMock(severity_threshold=None),
        )
    )
    return es


def _make_authed_client(app: Flask) -> Any:
    """Erzeugt einen Testclient mit umgangenem @login_required."""
    # `login_required` checkt `current_user.is_authenticated`. Wir patchen
    # die Flask-Login-Funktion direkt aus damit kein DB-User noetig ist.
    return app.test_client()


def test_detail_initial_render_has_skeleton_placeholders(app: Flask, _patched_show: Any) -> None:
    """Initial-Render rendert die Skeleton-Markups fuer Heartbeat + Trend."""
    server = _patched_show
    server.host_state_snapshot_at = MagicMock()  # nicht None -> Heartbeat-Skeleton rendert
    header_counts = dict.fromkeys(_RISK_BAND_SECTION_ORDER, 0)

    with (
        _setup_show_patches(server, header_counts),
        patch("flask_login.utils._get_user") as mock_user,
    ):
        mock_user.return_value = MagicMock(
            is_authenticated=True, is_active=True, is_anonymous=False
        )
        client = _make_authed_client(app)
        resp = client.get("/servers/1")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Heartbeat-Skeleton: 30 ticks mit --skel.
    assert "sd-heartbeat__tick--skel" in body, "Heartbeat-Skeleton-Tick muss im HTML stehen"
    # Trend-Skeleton: 30 cols mit --skel.
    assert "sd-trend-col--skel" in body, "Trend-Skeleton-Col muss im HTML stehen"


def test_detail_initial_render_has_no_finding_rows(app: Flask, _patched_show: Any) -> None:
    """Kein `data-test=band-finding-` im Initial-HTML — alle Findings sind
    hinter dem Phase-C-Lazy-Slot."""
    server = _patched_show
    header_counts = {"escalate": 5, "act": 0, "mitigate": 0, "pending": 0, "monitor": 0, "noise": 0}

    with (
        _setup_show_patches(server, header_counts),
        patch("flask_login.utils._get_user") as mock_user,
    ):
        mock_user.return_value = MagicMock(
            is_authenticated=True, is_active=True, is_anonymous=False
        )
        client = _make_authed_client(app)
        resp = client.get("/servers/1")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "band-finding-" not in body, (
        "Initial-Render darf keine Finding-Rows enthalten (Phase C lazy-load)"
    )


def test_detail_initial_render_has_risk_band_headers_with_counts(
    app: Flask, _patched_show: Any
) -> None:
    """Pro nicht-leerem Band ein `data-test=risk-band-<band>` mit Count."""
    server = _patched_show
    header_counts = {
        "escalate": 7,
        "act": 0,
        "mitigate": 3,
        "pending": 0,
        "monitor": 0,
        "noise": 0,
    }

    with (
        _setup_show_patches(server, header_counts),
        patch("flask_login.utils._get_user") as mock_user,
    ):
        mock_user.return_value = MagicMock(
            is_authenticated=True, is_active=True, is_anonymous=False
        )
        client = _make_authed_client(app)
        resp = client.get("/servers/1")

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # Nicht-leere Bands rendern mit Marker.
    assert 'data-test="risk-band-escalate"' in body
    assert 'data-test="risk-band-mitigate"' in body
    # Leere Bands rendern nicht.
    assert 'data-test="risk-band-act"' not in body
    assert 'data-test="risk-band-noise"' not in body
    # Counts sind im Body sichtbar.
    assert ">7<" in body or "<b>7</b>" in body
    assert ">3<" in body or "<b>3</b>" in body
