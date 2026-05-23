"""Pure-Unit-Tests fuer `app/views/server_detail.py` (Phase B, ADR-0030).

Deckt:
  * `_is_flat_mode`: spiegelt die Template-Conditional korrekt.
    - Group-Default-Pfad (keine Filter, sort=risk/desc, kein ?flat=1) -> False.
    - Flat-Pfad bei ?flat=1 -> True.
    - Flat-Pfad bei aktivem status-Filter -> True.
    - Flat-Pfad bei abweichendem Sort -> True.
    - Flat-Pfad bei search-Filter -> True.
    - Flat-Pfad bei kev_only -> True.
  * `_render_findings_section` (via Spy): im Group-Default-Pfad wird
    `list_findings` nicht aufgerufen; im Flat-Pfad schon.

Kein DB-Fixture noetig: `_is_flat_mode` ist eine Pure-Funktion (liest nur
`view_filter` + `request.args`). Flask-Request-Context wird per
`app.test_request_context()` minimal aufgebaut.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flask import Flask

from app.schemas.findings_view_filter import FindingsViewFilter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _default_filter(**kwargs: object) -> FindingsViewFilter:
    """Erstellt einen FindingsViewFilter mit Default-Werten (Group-Default-Pfad).

    Keyword-Args ueberschreiben einzelne Felder.
    """
    defaults = {
        "status": "open",
        "finding_class": "both",
        "severity": None,
        "kev_only": False,
        "search": None,
        "sort": "risk",
        "dir": "desc",
        "risk_band": None,
        "action_required": None,
        "application_group_id": None,
    }
    defaults.update(kwargs)
    return FindingsViewFilter(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _is_flat_mode — Template-Conditional-Spiegel
# ---------------------------------------------------------------------------


def test_is_flat_mode_default_path_returns_false(app: Flask) -> None:
    """Im Group-Default-Pfad (alle Filter auf Default, kein ?flat=1) gibt
    _is_flat_mode False zurueck — kein list_findings-Call waere noetig.
    """
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter()
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is False, "Group-Default-Pfad erwartet False"


def test_is_flat_mode_force_flat_query_param(app: Flask) -> None:
    """?flat=1 erzwingt Flat-Pfad unabhaengig von anderen Filtern."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter()
    with app.test_request_context("/servers/1?flat=1"):
        result = _is_flat_mode(filt)
    assert result is True, "?flat=1 muss Flat-Pfad erzwingen"


def test_is_flat_mode_status_filter_active(app: Flask) -> None:
    """status != 'open' -> Flat-Pfad."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(status="acknowledged")
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "status-Filter aktiv muss Flat-Pfad ergeben"


def test_is_flat_mode_sort_non_default(app: Flask) -> None:
    """sort != 'risk' -> Flat-Pfad (Benutzer sortiert manuell)."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(sort="epss")
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "Nicht-Default-Sort muss Flat-Pfad ergeben"


def test_is_flat_mode_dir_non_default(app: Flask) -> None:
    """dir != 'desc' (z.B. 'asc') -> Flat-Pfad."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(dir="asc")
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "Nicht-Default-Dir muss Flat-Pfad ergeben"


def test_is_flat_mode_kev_only_filter(app: Flask) -> None:
    """kev_only=True -> Flat-Pfad."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(kev_only=True)
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "kev_only-Filter aktiv muss Flat-Pfad ergeben"


def test_is_flat_mode_search_query_active(app: Flask) -> None:
    """search != None -> Flat-Pfad."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(search="openssl")
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "Aktive Suche muss Flat-Pfad ergeben"


def test_is_flat_mode_risk_band_filter(app: Flask) -> None:
    """risk_band aktiv -> Flat-Pfad."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(risk_band="escalate")
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "risk_band-Filter aktiv muss Flat-Pfad ergeben"


def test_is_flat_mode_application_group_filter(app: Flask) -> None:
    """application_group_id aktiv -> Flat-Pfad."""
    from app.views.server_detail import _is_flat_mode

    filt = _default_filter(application_group_id=1)
    with app.test_request_context("/servers/1"):
        result = _is_flat_mode(filt)
    assert result is True, "application_group_id-Filter aktiv muss Flat-Pfad ergeben"


# ---------------------------------------------------------------------------
# _render_findings_section — list_findings-Call-Verhalten
# ---------------------------------------------------------------------------


def test_render_findings_section_group_default_skips_list_findings(app: Flask) -> None:
    """Im Group-Default-Pfad wird list_findings nicht aufgerufen.

    DoD-B-2-Beweis: `list_findings` darf im Group-Default-Pfad (keine aktiven
    Filter, sort=risk/desc, kein ?flat=1) nicht aufgerufen werden.
    """
    from app.views.server_detail import _render_findings_section

    filt = _default_filter()

    # Minimaler Server-Mock.
    server = MagicMock()
    server.id = 1

    # Alle internen Service-Calls patchen damit kein echter DB-Zugriff erfolgt.
    fake_counts = {"open": 5, "acknowledged": 0, "resolved": 0, "total": 5, "kev_open": 0}

    with (
        app.test_request_context("/servers/1"),
        patch("app.views.server_detail.get_session") as mock_get_session,
        patch("app.views.server_detail.count_findings", return_value=fake_counts),
        patch("app.views.server_detail.list_findings") as mock_list_findings,
        patch(
            "app.views.server_detail._load_application_groups_for_server",
            return_value=[],
        ),
        patch(
            "app.views.server_detail._load_pending_grouping_counts",
            return_value={},
        ),
    ):
        mock_get_session.return_value = MagicMock()
        ctx = _render_findings_section(server, filt)

    # list_findings darf NICHT aufgerufen worden sein.
    mock_list_findings.assert_not_called()
    # findings muss leer sein.
    assert ctx["findings"] == [], (
        f"findings im Group-Default-Pfad muss leer sein, ist: {ctx['findings']!r}"
    )


def test_render_findings_section_flat_path_calls_list_findings(app: Flask) -> None:
    """Im Flat-Pfad (?flat=1) wird list_findings aufgerufen.

    DoD-B-2-Beweis (Kontra-Seite): wenn Flat-Pfad aktiv ist, muss
    list_findings aufgerufen werden und findings darf nicht leer sein.
    """
    from app.views.server_detail import _render_findings_section

    filt = _default_filter()

    server = MagicMock()
    server.id = 1

    fake_counts = {"open": 5, "acknowledged": 0, "resolved": 0, "total": 5, "kev_open": 0}
    fake_findings = [MagicMock(), MagicMock()]

    with (
        app.test_request_context("/servers/1?flat=1"),
        patch("app.views.server_detail.get_session") as mock_get_session,
        patch("app.views.server_detail.count_findings", return_value=fake_counts),
        patch(
            "app.views.server_detail.list_findings", return_value=fake_findings
        ) as mock_list_findings,
        patch(
            "app.views.server_detail._load_application_groups_for_server",
            return_value=[],
        ),
        patch(
            "app.views.server_detail._load_pending_grouping_counts",
            return_value={},
        ),
    ):
        mock_get_session.return_value = MagicMock()
        ctx = _render_findings_section(server, filt)

    # list_findings muss aufgerufen worden sein.
    mock_list_findings.assert_called_once()
    assert ctx["findings"] == fake_findings


# ---------------------------------------------------------------------------
# Phase E (ADR-0030 Befund 3) — SQL-Aggregation aktiviert
# ---------------------------------------------------------------------------


def test_show_does_not_call_load_findings_for_server(app: Flask) -> None:
    """Phase-E-Aktivierung: `load_findings_for_server` wird im show()-Pfad
    nicht mehr aufgerufen.

    DoD-E-Beweis: die View nutzt den SQL-Default-Pfad von
    `severity_snapshots_for_server` und `daily_severity_counts_for_server`
    direkt — kein Python-Loop ueber vorgeladene Rows.
    """
    import app.views.server_detail as sd_module

    # load_findings_for_server ist nach Phase E nicht mehr im View-Modul
    # importiert — der Attribut-Zugriff schlaegt fehl wenn die Funktion
    # versehentlich wieder importiert wuerde.
    assert not hasattr(sd_module, "load_findings_for_server"), (
        "load_findings_for_server darf im server_detail-Modul nicht "
        "importiert sein (Phase E: SQL-Aggregation ist aktiviert)"
    )
