"""TICKET-018 (d) — pure-unit render test for the ingest-failed banner.

`servers/detail.html` renders a warning callout
(``data-test="ingest-failed-banner"``) under ``{% if last_failed_ingest %}``
when the most recent scan upload was rejected and is newer than the last
successful scan. When ``last_failed_ingest`` is ``None`` the block must NOT
render (the banner stays hidden).

We extract the self-contained ``{% if last_failed_ingest %}…{% endif %}`` block
verbatim from the template source and render it via ``render_template_string``
inside a Flask app context (which registers the ``relative_time`` filter the
block uses). No live DB, no HTTP — the banner block reads only the
``last_failed_ingest`` dict the view passes in.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, render_template_string

_DETAIL_PATH = Path(__file__).parent.parent.parent / "app" / "templates" / "servers" / "detail.html"


def _extract_banner_block() -> str:
    """Return the verbatim `{% if last_failed_ingest %}…{% endif %}` snippet.

    The block is the first (and only) top-level `if last_failed_ingest` guard in
    detail.html. Extracting it verbatim keeps this test honest — it renders the
    real template markup, so a future edit to the banner is exercised here.
    """
    source = _DETAIL_PATH.read_text(encoding="utf-8")
    # The banner block contains nested `{% if … %}` guards, so a non-greedy
    # match would stop at the first inner `{% endif %}`. The block is the
    # contiguous span from the outer `if last_failed_ingest` up to (but not
    # including) the `{# ── 1) Header ── #}` marker that follows it.
    match = re.search(
        r"(\{%\s*if last_failed_ingest\s*%\}.*?\{%\s*endif\s*%\})\s*\{#\s*─",
        source,
        flags=re.DOTALL,
    )
    assert match is not None, (
        f"Could not find the `if last_failed_ingest` banner block in {_DETAIL_PATH}"
    )
    return match.group(1)


def _render(app: Flask, last_failed_ingest: object) -> str:
    block = _extract_banner_block()
    with app.test_request_context("/servers/7"):
        return render_template_string(block, last_failed_ingest=last_failed_ingest)


def test_banner_renders_when_failure_present(app: Flask) -> None:
    """A dict `last_failed_ingest` renders the banner with its data-test marker."""
    html = _render(
        app,
        {
            "job_id": 27,
            "failed_at": datetime(2026, 6, 17, 12, 0, tzinfo=UTC),
            "error_class": "validation_error",
        },
    )
    assert 'data-test="ingest-failed-banner"' in html, html
    assert "The most recent scan upload was rejected" in html
    # The error_class is mapped to a human phrase ("validation error").
    assert "validation error" in html


def test_banner_absent_when_none(app: Flask) -> None:
    """`last_failed_ingest=None` renders nothing (banner hidden)."""
    html = _render(app, None)
    assert 'data-test="ingest-failed-banner"' not in html
    assert "rejected" not in html
    assert html.strip() == ""


def test_banner_renders_without_error_class(app: Flask) -> None:
    """A `None` error_class still renders the banner (no parenthetical phrase)."""
    html = _render(
        app,
        {
            "job_id": 27,
            "failed_at": datetime(2026, 6, 17, 12, 0, tzinfo=UTC),
            "error_class": None,
        },
    )
    assert 'data-test="ingest-failed-banner"' in html
    # No error phrase parenthetical when error_class is absent.
    assert "()" not in html


def test_banner_renders_without_failed_at(app: Flask) -> None:
    """A missing `failed_at` does not break the render (no <time> emitted)."""
    html = _render(
        app,
        {"job_id": 27, "failed_at": None, "error_class": "validation_error"},
    )
    assert 'data-test="ingest-failed-banner"' in html
    assert "<time" not in html
