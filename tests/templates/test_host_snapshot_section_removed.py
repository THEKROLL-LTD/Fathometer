"""Sektion-Removal-Tests fuer Phase C / DoD-Punkt 3 (Block X, ADR-0038 §(3)).

Prueft:
  1. _partials/host_snapshot.html wurde geloescht (C11).
  2. detail.html enthaelt kein {% include "_partials/host_snapshot.html" %} mehr.
  3. detail.html enthaelt kein data-test='host-snapshot-section' mehr.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Pfade
# ---------------------------------------------------------------------------

_PARTIAL_PATH = (
    Path(__file__).parent.parent.parent / "app" / "templates" / "_partials" / "host_snapshot.html"
)

_DETAIL_PATH = Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"


# ---------------------------------------------------------------------------
# Test 1 — host_snapshot.html existiert nicht mehr
# ---------------------------------------------------------------------------


def test_host_snapshot_partial_does_not_exist() -> None:
    """Phase C / DoD-Punkt 3: _partials/host_snapshot.html ist geloescht.

    Das Partial wurde in Phase C durch die zwei neuen Pill-Panels ersetzt
    (ADR-0038 §(3) Task C8).
    """
    assert not _PARTIAL_PATH.exists(), (
        f"Erwartet host_snapshot.html geloescht (Phase C, ADR-0038 §(3) C8), "
        f"aber Datei existiert noch: {_PARTIAL_PATH}"
    )


# ---------------------------------------------------------------------------
# Test 2 — detail.html includet host_snapshot.html nicht mehr
# ---------------------------------------------------------------------------


def test_detail_html_no_longer_includes_host_snapshot() -> None:
    """Phase C: detail.html includet das geloeschte _partials/host_snapshot.html
    nicht mehr (ADR-0038 §(3) C8).

    Block Y Phase B (ADR-0039): detail.html referenziert weiterhin den
    Endpoint-Namen `server_detail.host_snapshot_fragment` via `url_for`
    fuer den HTMX-Slot. Dieser Verweis ist erlaubt; verboten ist nur das
    Include des alten Partials oder das alte data-test-Marker.
    """
    source = _DETAIL_PATH.read_text(encoding="utf-8")

    assert "_partials/host_snapshot.html" not in source, (
        f"Include-Pfad '_partials/host_snapshot.html' ist noch im detail.html-Source. "
        f"Erwartet: kein Include-Verweis auf das geloeschte Partial. "
        f"ADR-0038 §(3) Task C8. Template-Pfad: {_DETAIL_PATH}"
    )
    # Auch ein bloßer Include-Befehl mit dem Dateinamen ist verboten — wir
    # erlauben aber den Endpoint-Namen `host_snapshot_fragment` (Block Y
    # Phase B, ADR-0039) als legitime Referenz.
    assert "include " not in source.lower() or "host_snapshot.html" not in source, (
        f"'include ... host_snapshot.html' ist noch im detail.html-Source. "
        f"ADR-0038 §(3) Task C8. Template-Pfad: {_DETAIL_PATH}"
    )


# ---------------------------------------------------------------------------
# Test 3 — detail.html enthaelt kein altes data-test='host-snapshot-section'
# ---------------------------------------------------------------------------


def test_detail_html_no_host_snapshot_data_test() -> None:
    """Phase C: data-test='host-snapshot-section' ist aus detail.html entfernt.

    Das alte Host-Snapshot-Sektion-Markup (aus Block K/ADR-0022) hatte dieses
    data-test-Attribut. Nach Phase C darf es nicht mehr vorhanden sein
    (ADR-0038 §(3) C8 + C11).
    """
    source = _DETAIL_PATH.read_text(encoding="utf-8")

    assert "host-snapshot-section" not in source, (
        f"'host-snapshot-section' (altes data-test) ist noch im detail.html-Source. "
        f"Phase C soll die Host-Snapshot-Sektion ersatzlos entfernt haben. "
        f"ADR-0038 §(3) Task C8. Template-Pfad: {_DETAIL_PATH}"
    )
