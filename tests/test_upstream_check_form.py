"""Pure-Unit-Tests fuer ``UpstreamCheckSettingsForm`` (Block AI-2, ADR-0063, P1).

Prueft die Form-Validatoren ohne DB/Request: Backend-Whitelist (Defense-in-Depth
zum SelectField), ``base_url``-Whitelist-Reuse (``validate_base_url``),
``llm_research_model`` printable-ASCII + Length, sowie das dokumentierte
Verhalten dass ``enabled=true`` ohne Backend/Base-URL auf Form-Ebene erlaubt ist
(scharfes Gating laeuft via ``is_upstream_check_configured`` im View/Route).

CSRF ist im App-Context deaktiviert (``WTF_CSRF_ENABLED=False``), damit
``form.validate()`` ohne Token-Theater laeuft.
"""

from __future__ import annotations

from flask import Flask
from werkzeug.datastructures import MultiDict

from app.forms import UPSTREAM_SEARCH_BACKENDS, UpstreamCheckSettingsForm


def _form(app: Flask, **data: object) -> UpstreamCheckSettingsForm:
    app.config.update(WTF_CSRF_ENABLED=False)
    with app.test_request_context("/settings/llm/upstream", method="POST", data=MultiDict(data)):
        form = UpstreamCheckSettingsForm()
        form.validate()
        return form


# ---------------------------------------------------------------------------
# Backend-Whitelist
# ---------------------------------------------------------------------------


def test_whitelist_constant_matches_select_choices() -> None:
    assert UPSTREAM_SEARCH_BACKENDS == ("searxng", "tavily", "firecrawl", "serper")


def test_valid_backend_passes(app: Flask) -> None:
    for backend in UPSTREAM_SEARCH_BACKENDS:
        form = _form(app, upstream_search_backend=backend)
        assert "upstream_search_backend" not in form.errors, (
            f"{backend!r} sollte gueltig sein: {form.errors}"
        )


def test_empty_backend_allowed(app: Flask) -> None:
    """Leer ist erlaubt solange das Feature disabled ist (View gated scharf)."""
    form = _form(app, upstream_search_backend="")
    assert "upstream_search_backend" not in form.errors, form.errors


def test_invalid_backend_rejected(app: Flask) -> None:
    form = _form(app, upstream_search_backend="googlesearch")
    # SelectField verwirft unbekannte Choices bereits ("Not a valid choice").
    assert "upstream_search_backend" in form.errors, form.errors


# ---------------------------------------------------------------------------
# base_url-Whitelist (Reuse validate_base_url)
# ---------------------------------------------------------------------------


def test_https_base_url_ok(app: Flask) -> None:
    form = _form(app, upstream_search_base_url="https://searx.internal/search")
    assert "upstream_search_base_url" not in form.errors, form.errors


def test_empty_base_url_allowed(app: Flask) -> None:
    form = _form(app, upstream_search_base_url="")
    assert "upstream_search_base_url" not in form.errors, form.errors


def test_plain_http_remote_base_url_rejected(app: Flask) -> None:
    """Reuse von validate_base_url: nicht-localhost http:// ist verboten."""
    form = _form(app, upstream_search_base_url="http://evil.example.com/search")
    assert "upstream_search_base_url" in form.errors, form.errors


def test_http_localhost_base_url_allowed(app: Flask) -> None:
    form = _form(app, upstream_search_base_url="http://localhost:8888/search")
    assert "upstream_search_base_url" not in form.errors, form.errors


# ---------------------------------------------------------------------------
# llm_research_model — printable ASCII + Length
# ---------------------------------------------------------------------------


def test_research_model_printable_ascii_ok(app: Flask) -> None:
    form = _form(app, llm_research_model="deepseek-ai/DeepSeek-V4-Flash")
    assert "llm_research_model" not in form.errors, form.errors


def test_research_model_empty_allowed(app: Flask) -> None:
    form = _form(app, llm_research_model="")
    assert "llm_research_model" not in form.errors, form.errors


def test_research_model_nul_byte_rejected(app: Flask) -> None:
    form = _form(app, llm_research_model="model\x00name")
    assert "llm_research_model" in form.errors, form.errors


def test_research_model_control_char_rejected(app: Flask) -> None:
    form = _form(app, llm_research_model="model\nname")
    assert "llm_research_model" in form.errors, form.errors


def test_research_model_non_ascii_rejected(app: Flask) -> None:
    form = _form(app, llm_research_model="modèle")
    assert "llm_research_model" in form.errors, form.errors


def test_research_model_over_128_chars_rejected(app: Flask) -> None:
    form = _form(app, llm_research_model="a" * 129)
    assert "llm_research_model" in form.errors, form.errors


def test_research_model_exactly_128_ok(app: Flask) -> None:
    form = _form(app, llm_research_model="a" * 128)
    assert "llm_research_model" not in form.errors, form.errors


# ---------------------------------------------------------------------------
# enabled=true ohne Backend/Base-URL — dokumentiertes Verhalten
# ---------------------------------------------------------------------------


def test_enabled_without_backend_passes_form_validation(app: Flask) -> None:
    """ADR-0063: das Form erzwingt KEINE Backend/Base-URL bei enabled=true —
    das scharfe Gating macht ``is_upstream_check_configured`` im View/Route.
    Dieser Test dokumentiert das Verhalten (Regression gegen versehentliches
    Required-Werden)."""
    form = _form(app, upstream_check_enabled="y", upstream_search_backend="")
    assert form.errors == {}, (
        "enabled=true ohne Backend darf auf Form-Ebene nicht failen (Gating ist View-Sache): "
        f"{form.errors}"
    )
    assert form.upstream_check_enabled.data is True
