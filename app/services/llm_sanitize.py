# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""LLM-Output-Sanitization mit nh3.

ARCHITECTURE.md §10 (`nh3.clean(...)` MUSS auf LLM-Output laufen) und
Block-G-DoD (Allowlist: `<p>`, `<strong>`, `<em>`, `<code>`, `<pre>`,
`<a>` mit `rel="noopener noreferrer nofollow"`, `<ul>`/`<ol>`/`<li>`,
`<br>`).

Wir erlauben das gleiche kleine Markdown-Subset wie `notes_render.py`
(Listen, Bold/Italic/Code, Fences) UND zusaetzlich `<a>`-Tags fuer
externe Referenzen, die das LLM gern in seine Antwort packt. `nh3`
erzwingt `rel="noopener noreferrer nofollow"` ueber sein
`link_rel`-Argument und whitelistet `href`-Schemes auf `http`/`https`/
`mailto`.

Der Filter wird in `create_app()` als Jinja-Filter `llm_safe`
registriert und gibt `Markup(...)` zurueck. Templates rufen ihn als
`{{ message.content | llm_safe }}` auf — **ohne** `|safe`.
"""

from __future__ import annotations

import re
from html import escape as html_escape

import nh3
from markupsafe import Markup

# Allowlist gemaess Block-G-DoD. Kein `<script>`, `<iframe>`, `<style>`,
# `<img>`, `<form>`, `<input>`, `<button>`.
_ALLOWED_TAGS: frozenset[str] = frozenset(
    {"p", "strong", "em", "code", "pre", "a", "ul", "ol", "li", "br"}
)

# Pro Tag erlaubte Attribute. `<a>` darf `href` tragen — `rel` setzt nh3
# automatisch via `link_rel`.
_ALLOWED_ATTRS: dict[str, set[str]] = {
    "a": {"href"},
}

# Schemes-Whitelist fuer Hrefs.
_URL_SCHEMES: set[str] = {"http", "https", "mailto"}

# nh3 erwartet `link_rel: str | None`. Wir setzen den ganzen rel-Wert,
# damit `nofollow`/`noopener`/`noreferrer` immer dranklebt.
_LINK_REL = "noopener noreferrer nofollow"


# Markdown-Subset (identisch zu notes_render, plus `[text](url)`-Links).
_FENCE_RE = re.compile(r"```([\s\S]*?)```")
_LINK_RE = re.compile(r"\[([^\]\n]+)\]\((https?://[^\s)]+|mailto:[^\s)]+)\)")
_BOLD_RE = re.compile(r"\*\*([^*\n]+)\*\*")
_ITALIC_RE = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")
_CODE_RE = re.compile(r"`([^`\n]+)`")
_BULLET_LINE_RE = re.compile(r"^\s*[-*]\s+(.*)$")
_NUMBERED_LINE_RE = re.compile(r"^\s*\d+\.\s+(.*)$")


def _render_inline(text: str) -> str:
    """Inline-Markdown: bold/italic/inline-code/links, sonst HTML-escaped."""
    escaped = html_escape(text, quote=False)
    # Links zuerst (vor Inline-Code, damit `[x](url)`-Pattern nicht
    # zerschossen wird).
    escaped = _LINK_RE.sub(
        lambda m: f'<a href="{html_escape(m.group(2), quote=True)}">{m.group(1)}</a>',
        escaped,
    )
    escaped = _CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
    escaped = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)
    escaped = _ITALIC_RE.sub(lambda m: f"<em>{m.group(1)}</em>", escaped)
    return escaped


def _render_block_content(text: str) -> str:
    """Block-Level: Absaetze + ungeordnete und geordnete Listen."""
    lines = text.split("\n")
    out: list[str] = []
    paragraph_buf: list[str] = []
    ul_buf: list[str] = []
    ol_buf: list[str] = []

    def _flush_paragraph() -> None:
        if paragraph_buf:
            joined = "<br>".join(_render_inline(line) for line in paragraph_buf)
            out.append(f"<p>{joined}</p>")
            paragraph_buf.clear()

    def _flush_ul() -> None:
        if ul_buf:
            items = "".join(f"<li>{_render_inline(item)}</li>" for item in ul_buf)
            out.append(f"<ul>{items}</ul>")
            ul_buf.clear()

    def _flush_ol() -> None:
        if ol_buf:
            items = "".join(f"<li>{_render_inline(item)}</li>" for item in ol_buf)
            out.append(f"<ol>{items}</ol>")
            ol_buf.clear()

    def _flush_all() -> None:
        _flush_paragraph()
        _flush_ul()
        _flush_ol()

    for raw_line in lines:
        line = raw_line.rstrip()
        if not line:
            _flush_all()
            continue
        bullet = _BULLET_LINE_RE.match(line)
        if bullet is not None:
            _flush_paragraph()
            _flush_ol()
            ul_buf.append(bullet.group(1))
            continue
        numbered = _NUMBERED_LINE_RE.match(line)
        if numbered is not None:
            _flush_paragraph()
            _flush_ul()
            ol_buf.append(numbered.group(1))
            continue
        _flush_ul()
        _flush_ol()
        paragraph_buf.append(line)

    _flush_all()
    return "".join(out)


def _render_with_fences(text: str) -> str:
    """Splittet an ```-Fences."""
    parts: list[str] = []
    pos = 0
    for match in _FENCE_RE.finditer(text):
        before = text[pos : match.start()]
        if before:
            parts.append(_render_block_content(before))
        code_body = match.group(1)
        parts.append(f"<pre><code>{html_escape(code_body, quote=False)}</code></pre>")
        pos = match.end()
    rest = text[pos:]
    if rest:
        parts.append(_render_block_content(rest))
    return "".join(parts)


def clean_llm_html(raw: str | None) -> Markup:
    """Rendert LLM-Output (Markdown-Subset) zu sicherem HTML.

    Pipeline:
      1. Markdown-Subset zu HTML (inkl. `[text](url)`-Links).
      2. `nh3.clean(...)` mit Allowlist und erzwungenem `link_rel`.
      3. `Markup(...)` damit Jinja2 nicht doppelt escaped.

    `nh3` strippt jeglichen `<script>`, `<iframe>`, `<style>`, `<form>`,
    `<img>`, on-Event-Handler etc. — Defense-in-Depth zum Markdown-Renderer.
    """
    if not raw:
        return Markup("")
    rendered = _render_with_fences(raw)
    cleaned = nh3.clean(
        rendered,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        url_schemes=_URL_SCHEMES,
        link_rel=_LINK_REL,
    )
    # Sicherheits-Begruendung: `cleaned` ist Ausgabe von `nh3.clean(...)`
    # mit strikter Allowlist (`<script>`, `<iframe>`, etc. werden
    # gestrippt) und erzwungenem `rel`-Attribut auf `<a>`-Tags. Damit
    # ist `Markup(...)` sicher.
    return Markup(cleaned)  # noqa: S704 — nh3.clean output ist sicher.


__all__ = ["clean_llm_html"]
