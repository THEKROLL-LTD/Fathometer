"""Pure-Unit-Tests fuer die Status-Pill-Reihe in ``servers/detail.html`` Z. 70-101
(Block X Phase G2, ADR-0038 §G2).

Prueft (DoD-Punkt 7, Block X Phase G):
  1.  Kombinierte stale-Pill bei scan_stale=True AND db_stale=True.
  2.  Nur scan-stale-Pill bei scan_stale=True, db_stale=False.
  3.  Nur db-stale-Pill bei scan_stale=False, db_stale=True.
  4.  Kein stale-Pill wenn beide False.
  5.  Alle stale-Pill-Varianten nutzen sd-status-flag-Klasse.
  6.  Revoked-Tooltip enthaelt 'Revoked on' (englisch, NICHT 'Widerrufen am').
  7.  Retired-Tooltip enthaelt 'Decommissioned on' (englisch).
  8.  Stale-Tooltips enthalten englische Strings.

Render-Strategie:
  - Source-Read + Substring-Tests auf ``detail.html``-Source direkt
    (kein Render noetig — Tooltip-Text und data-test-Attribute sind
    statisch im Template).
  - Fuer Render-abhaengige Tests (kombinierte vs. einzelne Pill):
    ``app.jinja_env.from_string`` mit isoliertem Stale-Pill-Snippet
    aus detail.html (Z. 84-101) und minimalem Mock-Kontext.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Pfade
# ---------------------------------------------------------------------------

_DETAIL_PATH = Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_detail_source() -> str:
    """Laedt detail.html-Source direkt vom Filesystem."""
    return _DETAIL_PATH.read_text(encoding="utf-8")


def _extract_stale_pill_snippet(source: str) -> str:
    """Extrahiert den Stale-Pill-Block aus detail.html.

    Sucht vom Phase-G2-Kommentar bis zum Ende des db_stale-elif-Blocks.
    """
    # Suche nach dem Stale-Pill-Block anhand des Phase-G2-Kommentars
    start_marker = "{% if scan_stale and db_stale %}"
    end_marker = "{% endif %}"

    start = source.index(start_marker)
    # Finde das passende endif nach dem start
    end = source.index(end_marker, start) + len(end_marker)
    return source[start:end]


def _render_stale_snippet(
    app: Flask,
    *,
    scan_stale: bool,
    db_stale: bool,
    expected_scan_interval_h: int = 24,
) -> str:
    """Rendert den Stale-Pill-Snippet mit minimalem Mock-Server-Kontext."""
    snippet = _extract_stale_pill_snippet(_load_detail_source())

    # Der Snippet referenziert server.expected_scan_interval_h
    server = SimpleNamespace(expected_scan_interval_h=expected_scan_interval_h)

    with app.test_request_context("/"):
        tmpl = app.jinja_env.from_string(snippet)
        return tmpl.render(scan_stale=scan_stale, db_stale=db_stale, server=server)


# ===========================================================================
# Test 1 — kombinierte stale-Pill bei beiden stale
# ===========================================================================


def test_combined_stale_pill_when_both_stale(app: Flask) -> None:
    """scan_stale=True + db_stale=True: kombinierte Pill mit data-test='pill-stale-combined'.

    KEIN data-test='pill-scan-stale' und KEIN data-test='pill-db-stale'.
    """
    html = _render_stale_snippet(app, scan_stale=True, db_stale=True)

    assert 'data-test="pill-stale-combined"' in html, (
        f"'pill-stale-combined' fehlt bei scan_stale=True + db_stale=True. HTML: {html!r}"
    )
    assert 'data-test="pill-scan-stale"' not in html, (
        f"'pill-scan-stale' darf bei kombiniertem stale NICHT erscheinen. HTML: {html!r}"
    )
    assert 'data-test="pill-db-stale"' not in html, (
        f"'pill-db-stale' darf bei kombiniertem stale NICHT erscheinen. HTML: {html!r}"
    )


# ===========================================================================
# Test 2 — nur scan-stale-Pill bei scan_stale=True, db_stale=False
# ===========================================================================


def test_single_scan_stale_pill_when_only_scan_stale(app: Flask) -> None:
    """scan_stale=True + db_stale=False: nur data-test='pill-scan-stale'."""
    html = _render_stale_snippet(app, scan_stale=True, db_stale=False)

    assert 'data-test="pill-scan-stale"' in html, (
        f"'pill-scan-stale' fehlt bei scan_stale=True + db_stale=False. HTML: {html!r}"
    )
    assert 'data-test="pill-stale-combined"' not in html, (
        f"'pill-stale-combined' darf bei nur-scan-stale NICHT erscheinen. HTML: {html!r}"
    )
    assert 'data-test="pill-db-stale"' not in html, (
        f"'pill-db-stale' darf bei nur-scan-stale NICHT erscheinen. HTML: {html!r}"
    )


# ===========================================================================
# Test 3 — nur db-stale-Pill bei db_stale=True, scan_stale=False
# ===========================================================================


def test_single_db_stale_pill_when_only_db_stale(app: Flask) -> None:
    """scan_stale=False + db_stale=True: nur data-test='pill-db-stale'."""
    html = _render_stale_snippet(app, scan_stale=False, db_stale=True)

    assert 'data-test="pill-db-stale"' in html, (
        f"'pill-db-stale' fehlt bei scan_stale=False + db_stale=True. HTML: {html!r}"
    )
    assert 'data-test="pill-stale-combined"' not in html, (
        f"'pill-stale-combined' darf bei nur-db-stale NICHT erscheinen. HTML: {html!r}"
    )
    assert 'data-test="pill-scan-stale"' not in html, (
        f"'pill-scan-stale' darf bei nur-db-stale NICHT erscheinen. HTML: {html!r}"
    )


# ===========================================================================
# Test 4 — kein stale-Pill wenn beide False
# ===========================================================================


def test_no_stale_pill_when_neither_stale(app: Flask) -> None:
    """scan_stale=False + db_stale=False: kein stale-Pill."""
    html = _render_stale_snippet(app, scan_stale=False, db_stale=False)

    assert 'data-test="pill-stale-combined"' not in html, (
        f"'pill-stale-combined' darf nicht rendern wenn beide=False. HTML: {html!r}"
    )
    assert 'data-test="pill-scan-stale"' not in html, (
        f"'pill-scan-stale' darf nicht rendern wenn scan_stale=False. HTML: {html!r}"
    )
    assert 'data-test="pill-db-stale"' not in html, (
        f"'pill-db-stale' darf nicht rendern wenn db_stale=False. HTML: {html!r}"
    )
    # Kein sd-status-flag im Output
    assert "sd-status-flag" not in html, (
        f"'sd-status-flag' darf nicht im Output sein wenn keine stale-Condition. HTML: {html!r}"
    )


# ===========================================================================
# Test 5 — alle stale-Pill-Varianten nutzen sd-status-flag-Klasse (parametrize)
# ===========================================================================


@pytest.mark.parametrize(
    "scan_stale, db_stale, expected_data_test",
    [
        (True, True, "pill-stale-combined"),
        (True, False, "pill-scan-stale"),
        (False, True, "pill-db-stale"),
    ],
)
def test_stale_pills_use_sd_status_flag_class(
    app: Flask, scan_stale: bool, db_stale: bool, expected_data_test: str
) -> None:
    """Alle stale-Pill-Varianten nutzen class='sd-status-flag' (kein badge-* mehr)."""
    html = _render_stale_snippet(app, scan_stale=scan_stale, db_stale=db_stale)

    assert "sd-status-flag" in html, (
        f"'sd-status-flag'-Klasse fehlt fuer Variante data-test='{expected_data_test}'. "
        f"HTML: {html!r}"
    )
    # Sicherheitsnetz: kein altes Tailwind badge-error/badge-warning
    assert "badge-error" not in html, (
        f"Altes 'badge-error' darf nicht in stale-Pills vorkommen. HTML: {html!r}"
    )


# ===========================================================================
# Test 6 — Revoked-Tooltip ist englisch
# ===========================================================================


def test_revoked_tooltip_in_english() -> None:
    """Revoked-Tooltip enthaelt 'Revoked on', NICHT 'Widerrufen am'."""
    source = _load_detail_source()

    assert "Revoked on" in source, (
        "detail.html enthaelt keinen englischen 'Revoked on'-Tooltip. "
        "Block X Phase G2 erfordert englische Tooltips."
    )
    assert "Widerrufen am" not in source, (
        "Alter deutscher Tooltip 'Widerrufen am' ist noch in detail.html. "
        "Muss auf 'Revoked on' geaendert sein."
    )


# ===========================================================================
# Test 7 — Retired-Tooltip ist englisch
# ===========================================================================


def test_retired_tooltip_in_english() -> None:
    """Retired-Tooltip enthaelt 'Decommissioned on', NICHT 'Stillgelegt am'."""
    source = _load_detail_source()

    assert "Decommissioned on" in source, (
        "detail.html enthaelt keinen englischen 'Decommissioned on'-Tooltip. "
        "Block X Phase G2 erfordert englische Tooltips."
    )
    assert "Stillgelegt am" not in source, (
        "Alter deutscher Tooltip 'Stillgelegt am' ist noch in detail.html. "
        "Muss auf 'Decommissioned on' geaendert sein."
    )


# ===========================================================================
# Test 8 — Stale-Tooltips sind englisch
# ===========================================================================


def test_stale_tooltips_in_english() -> None:
    """Stale-Pill-Tooltips enthalten englische Strings.

    Erwartet mindestens einen der Strings:
      - 'Last scan older than' (scan-stale-Tooltip)
      - 'Trivy DB stale' (db-stale-Tooltip)
      - 'Last scan and Trivy DB' (kombinierter Tooltip)

    Kein Deutsch ('Scan veraltet', 'Trivy-DB veraltet', 'Letzter Scan').
    """
    source = _load_detail_source()

    # Englische Strings muessen alle vorkommen (gemaess detail.html Z. 84-101).
    for expected in [
        "Last scan older than",
        "Trivy DB stale",
        "Last scan and Trivy DB",
    ]:
        assert expected in source, (
            f"Englischer Tooltip-String '{expected}' fehlt in detail.html. "
            f"Block X Phase G2 erfordert englische Stale-Tooltips."
        )

    # Deutsche Strings duerfen nicht vorkommen.
    for forbidden in [
        "Scan veraltet",
        "Trivy-DB veraltet",
        "Letzter Scan aelter",
    ]:
        assert forbidden not in source, (
            f"Verbotener deutscher Tooltip-String '{forbidden}' in detail.html. "
            f"Block X Phase G2 erfordert englische Tooltips."
        )
