"""Pure-Unit-Tests fuer die Bulk-Ack-Noise-Toolbar in ``servers/_findings_section.html``
(Block X Phase G5, ADR-0038 §G5).

Prueft (DoD-Punkt 7, Block X Phase G):
  1.  Button rendert bei noise_total > 0 mit korrektem data-test-Anker.
  2.  Button rendert NICHT bei noise_total=0.
  3.  Button rendert NICHT wenn noise_total nicht gesetzt (default(0)-Filter greift).
  4.  Modal-Include ist im Output vorhanden wenn noise_total > 0.

Render-Strategie:
  - Der relevante Bulk-Ack-Noise-Block in ``_findings_section.html`` ist
    ein klar abgegrenzter ``{% if (noise_total | default(0)) > 0 %}``-Block.
  - ``_findings_section.html`` referenziert ``url_for``, ``view_filter``,
    ``server``, Macro-Imports etc. — ein vollstaendiger Render waere sehr
    aufwaendig (viele Context-Variablen + URL-Routing).
  - Fallback-Strategie: Source-Read mit Substring-Tests auf das Template
    (prueft Render-Condition + Markup-Strings statisch) PLUS isolierter
    Snippet-Render des Noise-Blocks fuer dynamische Checks.
  - Snippet-Extraktion: der ``{% if (noise_total | default(0)) > 0 %}``-Block
    bis zum schliessendem ``{% endif %}`` wird extrahiert und via
    ``app.jinja_env.from_string`` gerendert. Das ``{% include %}`` innerhalb
    des Blocks wird mit einem Stub-Template-Override ersetzt um
    Template-Lookup-Fehler zu vermeiden.

Sicherheit (ADR-0006): Comment-Feld ist optional (kein Pflicht-Kommentar).
ADR-0022: Modal erweitert Block-F-Bulk-Ack-Pattern mit risk_band_filter=noise.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from flask import Flask

# ---------------------------------------------------------------------------
# Pfade
# ---------------------------------------------------------------------------

_FINDINGS_SECTION_PATH = (
    Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "_findings_section.html"
)

_BULK_MODAL_PATH = (
    Path(__file__).parent.parent.parent
    / "app"
    / "templates"
    / "servers"
    / "_bulk_ack_noise_modal.html"
)


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def _load_findings_section_source() -> str:
    """Laedt _findings_section.html-Source direkt vom Filesystem."""
    return _FINDINGS_SECTION_PATH.read_text(encoding="utf-8")


def _load_bulk_modal_source() -> str:
    """Laedt _bulk_ack_noise_modal.html-Source direkt vom Filesystem."""
    return _BULK_MODAL_PATH.read_text(encoding="utf-8")


def _extract_noise_button_snippet(source: str) -> str:
    """Extrahiert den Bulk-Ack-Noise-Block aus _findings_section.html.

    Der Block beginnt mit dem Block-O-Kommentar und dem if-Statement und
    endet mit dem passenden {% endif %}.
    """
    start_marker = "{% if (noise_total | default(0)) > 0 %}"
    end_marker = "{% endif %}"

    start_idx = source.index(start_marker)
    end_idx = source.index(end_marker, start_idx) + len(end_marker)
    return source[start_idx:end_idx]


def _make_noise_finding(finding_id: int, identifier_key: str = "CVE-2024-0001") -> SimpleNamespace:
    """Minimaler Finding-Mock mit id + identifier_key + package_name."""
    return SimpleNamespace(
        id=finding_id,
        identifier_key=identifier_key,
        package_name="openssl",
    )


def _render_noise_snippet(
    app: Flask,
    *,
    noise_total: int | None,
    noise_findings: list[SimpleNamespace] | None = None,
) -> str:
    """Rendert den Noise-Button-Snippet mit einem Stub fuer das Modal-Include.

    Das ``{% include "servers/_bulk_ack_noise_modal.html" %}`` im Snippet
    wird aufgeloest, weil wir Flask-Env nutzen — das Modal wird real gerendert.
    Wir uebergeben minimale noise_findings und noise_total.
    """
    snippet = _extract_noise_button_snippet(_load_findings_section_source())

    ctx: dict[str, Any] = {}
    if noise_total is not None:
        ctx["noise_total"] = noise_total
    # noise_findings fuer das {% include %} Modal-Partial
    ctx["noise_findings"] = noise_findings or []

    # server wird im Modal-Partial referenziert (aria-labelledby etc.), nicht
    # direkt im Button-Block; wir uebergeben None — das Modal rendert ohne
    # server.name, aber das ist fuer diese Unit-Tests irrelevant.
    ctx["server"] = SimpleNamespace(id=1, name="test-server")

    with app.test_request_context("/servers/1"):
        tmpl = app.jinja_env.from_string(snippet)
        return tmpl.render(**ctx)


# ===========================================================================
# Source-Level-Tests (statisch, kein Render)
# ===========================================================================


def test_bulk_ack_noise_button_data_test_in_source() -> None:
    """Template-Source enthaelt data-test='bulk-ack-noise-button'."""
    source = _load_findings_section_source()

    assert 'data-test="bulk-ack-noise-button"' in source, (
        "'data-test=\"bulk-ack-noise-button\"' fehlt in _findings_section.html. "
        "Block X Phase G5 erfordert diesen Anker."
    )


def test_bulk_ack_noise_button_text_in_source() -> None:
    """Template-Source enthaelt 'Acknowledge all noise on this server'."""
    source = _load_findings_section_source()

    assert "Acknowledge all noise on this server" in source, (
        "'Acknowledge all noise on this server' fehlt in _findings_section.html. "
        "Block X Phase G5 erfordert diesen Button-Text."
    )


def test_bulk_ack_noise_render_condition_in_source() -> None:
    """Template-Source nutzt '(noise_total | default(0)) > 0' als Render-Condition."""
    source = _load_findings_section_source()

    assert "(noise_total | default(0)) > 0" in source, (
        "'(noise_total | default(0)) > 0'-Condition fehlt in _findings_section.html. "
        "default(0)-Filter muss vorhanden sein damit fehlende Variable == keine Pill."
    )


def test_bulk_ack_noise_modal_include_in_source() -> None:
    """Template-Source enthaelt den Modal-Include fuer _bulk_ack_noise_modal.html."""
    source = _load_findings_section_source()

    assert "_bulk_ack_noise_modal.html" in source, (
        "'_bulk_ack_noise_modal.html'-Include fehlt in _findings_section.html. "
        "Block X Phase G5 erfordert Modal-Einbindung."
    )


def test_bulk_ack_noise_comment_is_optional_in_modal() -> None:
    """Modal-Source zeigt Kommentar als optional (ADR-0006: kein Pflicht-Kommentar).

    Das Comment-Feld muss 'optional' enthalten (z.B. 'Kommentar (optional)').
    """
    source = _load_bulk_modal_source()

    assert "optional" in source.lower(), (
        "Bulk-Ack-Noise-Modal enthaelt kein 'optional'-Label fuer das Kommentar-Feld. "
        "ADR-0006 verbietet Pflicht-Kommentare — das Feld muss als optional markiert sein."
    )


# ===========================================================================
# Render-Tests (dynamisch via Snippet-Render)
# ===========================================================================


def test_bulk_ack_noise_button_renders_when_noise_total_positive(
    app: Flask,
) -> None:
    """Render mit noise_total=5: data-test='bulk-ack-noise-button' + 'Acknowledge all noise...' + '(5)'."""
    noise_findings = [_make_noise_finding(i) for i in range(5)]
    html = _render_noise_snippet(app, noise_total=5, noise_findings=noise_findings)

    assert 'data-test="bulk-ack-noise-button"' in html, (
        f"'bulk-ack-noise-button' fehlt bei noise_total=5. HTML: {html!r}"
    )
    assert "Acknowledge all noise on this server" in html, (
        f"Button-Text fehlt bei noise_total=5. HTML: {html!r}"
    )
    assert "(5)" in html, (
        f"'(5)' (noise_total-Counter) fehlt im Button bei noise_total=5. HTML: {html!r}"
    )


def test_bulk_ack_noise_button_not_rendered_when_noise_total_zero(
    app: Flask,
) -> None:
    """Render mit noise_total=0: kein data-test='bulk-ack-noise-button'."""
    html = _render_noise_snippet(app, noise_total=0, noise_findings=[])

    assert 'data-test="bulk-ack-noise-button"' not in html, (
        f"'bulk-ack-noise-button' darf bei noise_total=0 NICHT rendern. HTML: {html!r}"
    )


def test_bulk_ack_noise_button_not_rendered_when_noise_total_missing(
    app: Flask,
) -> None:
    """Render ohne noise_total-Variable (None/undefined): kein Button (default(0)-Filter greift)."""
    html = _render_noise_snippet(app, noise_total=None, noise_findings=[])

    assert 'data-test="bulk-ack-noise-button"' not in html, (
        f"'bulk-ack-noise-button' darf bei fehlendem noise_total NICHT rendern "
        f"(default(0)-Filter muss greifen). HTML: {html!r}"
    )


def test_bulk_ack_noise_modal_included_when_noise_total_positive(
    app: Flask,
) -> None:
    """Render mit noise_total > 0: Modal-Markup ist im Output vorhanden.

    Das Modal-Include (servers/_bulk_ack_noise_modal.html) muss gerendert sein.
    Prueft via 'data-test=\"bulk-ack-noise-modal\"' aus dem Modal-Template.
    """
    noise_findings = [_make_noise_finding(1, "CVE-2024-0001")]
    html = _render_noise_snippet(app, noise_total=1, noise_findings=noise_findings)

    assert 'data-test="bulk-ack-noise-modal"' in html, (
        f"Modal-Markup (data-test='bulk-ack-noise-modal') fehlt bei noise_total=1. "
        f"_bulk_ack_noise_modal.html muss eingebunden sein. HTML: {html!r}"
    )
