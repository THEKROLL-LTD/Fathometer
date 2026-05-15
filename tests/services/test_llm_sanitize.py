"""Unit-Tests fuer `app.services.llm_sanitize.clean_llm_html`.

Pipeline:
  1. Markdown-Subset (inkl. `[text](url)`-Links) -> HTML mit `html_escape`
     auf allen Inline-Texten, d.h. **rohes HTML in der Eingabe ist bereits
     als Text gerendert, bevor nh3 ueberhaupt laeuft**.
  2. `nh3.clean(...)` mit strikter Allowlist als Defense-in-Depth.

Was wir verifizieren:
- Rohes HTML in der Eingabe wird escaped (sichtbar als Text, NICHT als Tag).
- Markdown-Subset rendert die erlaubten Tags korrekt (`<strong>`, `<em>`,
  `<code>`, `<pre>`, `<ul>`/`<ol>`/`<li>`, `<a>` mit `rel=...`).
- Markdown-Links mit `javascript:`/`data:`-Scheme tauchen NICHT als
  href im Output auf — der Markdown-Link-Regex matcht ohnehin nur
  `https?://...` / `mailto:...`, und nh3 wuerde fremde Schemes zusaetzlich
  rausfiltern.
- `clean_llm_html(...)` gibt `Markup` zurueck, damit Jinja2 nicht doppelt
  escaped.
"""

from __future__ import annotations

import pytest
from markupsafe import Markup

from app.services.llm_sanitize import clean_llm_html


def _clean(raw: str) -> str:
    """Hilfsfunktion: clean + zu str konvertieren fuer einfacheres Asserten."""
    result = clean_llm_html(raw)
    assert isinstance(result, Markup)
    return str(result)


# ---------------------------------------------------------------------------
# Raw HTML in input -> escaped, never live tags
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,forbidden_tag",
    [
        ("<script>alert(1)</script>", "<script"),
        ("<iframe src='evil'></iframe>", "<iframe"),
        ('<img src="x" onerror="alert(1)">', "<img"),
        ("<style>body{color:red}</style>", "<style"),
        ("<form action='/x'><input name='y'></form>", "<form"),
        ("<form action='/x'><input name='y'></form>", "<input"),
        ("<button>click</button>", "<button"),
        ("<object data='x'></object>", "<object"),
        ("<embed src='x'>", "<embed"),
        ("<svg><script>alert(1)</script></svg>", "<svg"),
    ],
)
def test_raw_html_tags_are_escaped_not_rendered(raw: str, forbidden_tag: str) -> None:
    """Rohes HTML aus dem LLM-Output darf nicht als aktiver Tag enden.

    Der Markdown-Renderer escaped via `html.escape(...)` alle Inputs, d.h.
    `<script>` wird zu `&lt;script&gt;`. nh3 strippt zusaetzlich; in keinem
    Fall darf ein aktiver `<forbidden>`-Tag im Output sein.
    """
    out = _clean(raw)
    # Der echte Tag (z.B. `<script`) darf NICHT direkt im Output stehen —
    # nur seine HTML-escaped Repraesentation (`&lt;script`).
    assert forbidden_tag not in out
    # Aber als Text-Marker fuer das Escape sollte das vorhanden sein.
    escaped_marker = forbidden_tag.replace("<", "&lt;")
    assert escaped_marker in out


def test_script_inner_content_visible_only_as_text() -> None:
    out = _clean("Hello <script>alert(1)</script> World")
    # Kein aktiver script-Tag.
    assert "<script" not in out
    # Inhalt ist als escaped Text vorhanden.
    assert "alert(1)" in out
    assert "&lt;script&gt;" in out


# ---------------------------------------------------------------------------
# Markdown-Link-Schemes: javascript: / data: werden vom Markdown-Regex
# nicht matched, d.h. der String bleibt Roh-Text und enthaelt KEIN <a>.
# ---------------------------------------------------------------------------


def test_markdown_link_with_javascript_scheme_not_rendered_as_link() -> None:
    out = _clean("Klick [hier](javascript:alert(1))")
    # Kein `<a`-Tag, weil das Pattern javascript: nicht matched.
    assert "<a " not in out
    # Inhalt darf als Text auftauchen, aber `javascript:` darf NICHT als
    # href-Attribut existieren.
    assert 'href="javascript:' not in out


def test_markdown_link_with_data_scheme_not_rendered_as_link() -> None:
    out = _clean("[evil](data:text/html,<script>x</script>)")
    assert "<a " not in out
    assert 'href="data:' not in out


def test_https_markdown_link_renders_and_gets_rel_noopener() -> None:
    out = _clean("Siehe [Beispiel](https://example.com)")
    assert 'href="https://example.com"' in out
    assert "Beispiel" in out
    # rel-Attribute werden via link_rel="noopener noreferrer nofollow" gesetzt.
    assert "noopener" in out
    assert "noreferrer" in out
    assert "nofollow" in out


def test_mailto_markdown_link_kept() -> None:
    out = _clean("Schreib uns: [mail](mailto:test@example.com)")
    assert 'href="mailto:test@example.com"' in out


# ---------------------------------------------------------------------------
# Markdown-Subset
# ---------------------------------------------------------------------------


def test_markdown_bold_renders_strong() -> None:
    out = _clean("**bold**")
    assert "<strong>bold</strong>" in out


def test_markdown_italic_renders_em() -> None:
    out = _clean("Das ist *kursiv* hier")
    assert "<em>kursiv</em>" in out


def test_markdown_inline_code_renders_code_tag() -> None:
    out = _clean("Benutze `make build` zum Bauen")
    assert "<code>make build</code>" in out


def test_markdown_fence_renders_pre_code() -> None:
    out = _clean("```\nhello\n```")
    assert "<pre>" in out
    assert "<code>" in out
    assert "hello" in out


def test_markdown_bullet_list_renders_ul() -> None:
    out = _clean("- a\n- b\n- c")
    assert "<ul>" in out
    assert out.count("<li>") == 3


def test_markdown_numbered_list_renders_ol() -> None:
    out = _clean("1. erstens\n2. zweitens")
    assert "<ol>" in out
    assert out.count("<li>") == 2


def test_paragraphs_wrapped_in_p_tag() -> None:
    out = _clean("Hello\n\nWorld")
    # Beide Absaetze in <p>...</p> gewrappt.
    assert out.count("<p>") == 2


# ---------------------------------------------------------------------------
# Empty / type guarantees
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_markup() -> None:
    assert str(clean_llm_html("")) == ""
    assert str(clean_llm_html(None)) == ""


def test_returns_markup_instance() -> None:
    """`clean_llm_html` muss Markup zurueckgeben, damit Jinja nicht doppelt escaped."""
    out = clean_llm_html("Hello")
    assert isinstance(out, Markup)


# ---------------------------------------------------------------------------
# Direkter nh3-Defense-in-Depth-Check
# ---------------------------------------------------------------------------


def test_nh3_allowlist_strips_known_bad_tags_directly() -> None:
    """Auch wenn der Markdown-Renderer mal ein rohes HTML-Fragment durchlaesst,
    muss nh3 als zweite Linie die gefaehrlichen Tags strippen.

    Wir koennen das hier nicht direkt provozieren — wir verifizieren das
    indirekt via Markdown-Subset, der HTML-escapet. Defense-in-Depth ist
    aber implementiert (siehe `_ALLOWED_TAGS` in llm_sanitize).

    Stattdessen: pruefen, dass die Funktion bei mixed Markdown + scheinbar
    "befreundeten" Tags nicht ploetzlich gefaehrliche Tags entstehen laesst.
    """
    out = _clean("Hier ein **bold** und ein <evil>tag</evil>.")
    assert "<strong>bold</strong>" in out
    # `<evil>` ist nicht in der Allowlist — egal ob aus Markdown oder
    # direkt: aktiver Tag <evil darf nicht vorkommen.
    assert "<evil" not in out
    # Statt dessen: HTML-escaped Text.
    assert "&lt;evil&gt;" in out


def test_on_event_handlers_via_markdown_link_not_introduced() -> None:
    """Wir setzen explizit eine "boese" URL — der Renderer darf keine
    aktiven `onclick`-Attribute oder vergleichbares anlegen.

    Wichtig: der Markdown-Link-Regex matcht nur `https?://[^\\s)]+`, d.h.
    Whitespace und `"` brechen den Match. In dem Fall faellt der String
    als reiner Text durch — `onclick` darf dann zwar als Text auftauchen,
    aber NICHT als aktives Attribut auf einem Tag.
    """
    # Mehrere Varianten, die ein boesartiger LLM-Output enthalten koennte.
    inputs = [
        'Schau [hier](https://example.com/" onclick="alert(1))',
        "[evil](https://example.com)",
        "Link [text](https://example.com#anchor)",
    ]
    for raw in inputs:
        out = _clean(raw)
        # Property: in keinem aktiven <a>-Tag im Output darf ein on*-Attribut
        # NEBEN dem href-Attribut entstehen. Wir parsen die Attribute des
        # ersten <a>-Tags und stellen sicher, dass nur `href` und `rel`
        # vorhanden sind.
        idx = 0
        while True:
            a_start = out.find("<a ", idx)
            if a_start == -1:
                break
            a_end = out.index(">", a_start)
            a_tag = out[a_start : a_end + 1]
            # Roher Attribute-String zwischen `<a` und `>`.
            attrs_blob = a_tag[3:-1].lower()
            # Wir splitten nicht voll, sondern pruefen Attribut-Namen-Boundaries:
            # ein `onclick`-Attribut waere von Whitespace gefolgt von einem `=`.
            for handler in ("onclick", "onerror", "onload", "onmouseover"):
                bad_attr = f" {handler}="
                assert bad_attr not in attrs_blob, (raw, a_tag)
            idx = a_end + 1
