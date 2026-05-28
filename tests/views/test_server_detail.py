"""Pure-Unit-Tests fuer `app/views/server_detail.py`.

Block AA (ADR-0041): der Flat-Switch (`_is_flat_mode` + flache Tabelle) ist
entfernt — es gibt nur noch die Group-Card-Ansicht. Geprueft wird daher:
  * `_render_findings_section` rendert den Single-Group-Pfad: `findings` leer,
    Form-Objekte unkonditional im Context.
  * `_is_flat_mode` ist aus dem Modul verschwunden.

Kein DB-Fixture noetig: Flask-Request-Context wird per
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
# _render_findings_section — Single-Render-Pfad (Block AA, ADR-0041)
# ---------------------------------------------------------------------------


def test_render_findings_section_single_group_path(app: Flask) -> None:
    """Block AA: kein Flat-Pfad mehr. `findings` bleibt leer (Lazy-Fragmente
    hydrieren die Bodies), die Form-Objekte sind unkonditional im Context."""
    from app.views.server_detail import _render_findings_section

    filt = _default_filter()

    server = MagicMock()
    server.id = 1

    fake_counts = {"open": 5, "acknowledged": 0, "resolved": 0, "total": 5, "kev_open": 0}

    with (
        app.test_request_context("/servers/1"),
        patch("app.views.server_detail.get_session") as mock_get_session,
        patch("app.views.server_detail.count_findings", return_value=fake_counts),
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

    assert ctx["findings"] == [], (
        f"findings muss im Single-Render-Pfad leer sein, ist: {ctx['findings']!r}"
    )
    # Form-Objekte sind unkonditional vorhanden (Bulk-Toolbar + Fragment-Bodies).
    for key in ("ack_form", "reopen_form", "note_form", "bulk_form", "csrf_form"):
        assert key in ctx and ctx[key] is not None, f"{key} fehlt im Render-Context"


def test_is_flat_mode_removed(app: Flask) -> None:
    """Block AA: `_is_flat_mode` existiert nicht mehr im View-Modul."""
    import app.views.server_detail as sd_module

    assert not hasattr(sd_module, "_is_flat_mode"), (
        "_is_flat_mode darf nach Block AA (ADR-0041) nicht mehr existieren"
    )


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
