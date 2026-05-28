"""Pure-Unit Template-Render-Test fuer ``_partials/bucket_skeleton.html``.

Track Findings-Redesign (Spec §7): Platzhalter fuer den HTMX-Lazy-Slot bis die
Findings-Tabelle geladen ist. Reines Markup, keine Variablen.
"""

from __future__ import annotations

from flask import Flask


def _render(app: Flask) -> str:
    with app.test_request_context("/findings"):
        return app.jinja_env.get_template("_partials/bucket_skeleton.html").render()


def test_skeleton_wrapper_and_marker(app: Flask) -> None:
    """Wrapper bucket-skel-rows + sd-skel-frame mit data-test-Marker."""
    html = _render(app)
    assert "bucket-skel-rows" in html, html
    assert "sd-skel-frame" in html, html
    assert 'data-test="bucket-findings-skeleton"' in html, html


def test_skeleton_has_five_rows(app: Flask) -> None:
    """range(5) -> genau 5 bucket-skel-row Elemente."""
    html = _render(app)
    assert html.count('class="bucket-skel-row"') == 5, (
        f"Erwartet 5 Skeleton-Rows, gefunden {html.count('class="bucket-skel-row"')}: {html}"
    )


def test_skeleton_footer_placeholder(app: Flask) -> None:
    """Footer-Pager-Platzhalter: Text '— · —' + zwei disabled-Buttons."""
    html = _render(app)
    assert "bucket-card__footer" in html, html
    assert "— · —" in html, f"Pager-Platzhalter-Text fehlt: {html!r}"
    assert html.count("disabled") == 2, f"Erwartet 2 disabled-Buttons im Skeleton-Footer: {html}"
