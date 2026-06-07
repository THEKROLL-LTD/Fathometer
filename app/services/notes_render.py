# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Markdown-/Plain-Text-Render fuer Notizen mit nh3-Sanitization.

ARCHITECTURE.md §10 (XSS-Praevention) und Block-Plan: `nh3.clean(` MUSS
explizit in der Render-Pipeline fuer User-Inhalte vorkommen.

Wir unterstuetzen ein kleines Markdown-Subset, das fuer Operator-Notizen
ausreicht:
- Absaetze (Leerzeile trennt).
- Inline `*kursiv*`, `**fett**`, `` `code` ``.
- Block-Code via ``` ```-Fences (Triple-Backtick).
- Bullet-Listen (`- foo` oder `* foo`).

Alles andere wird als reiner Text behandelt und HTML-escaped. **Niemals
`a`-Tags oder `img`-Tags** — Notizen brauchen keine Links, und externe
Bilder eroeffnen Tracking-Pixel-Vektoren. Die nh3-Whitelist bleibt klein.

Der Filter wird in `create_app()` als Jinja-Filter `markdown_safe`
registriert und gibt `Markup(...)` zurueck. Templates rufen ihn als
`{{ note.text | markdown_safe }}` auf — **ohne** `|safe`.
"""

from __future__ import annotations

import re
from html import escape as html_escape

import nh3
from markupsafe import Markup

# Erlaubte Tags fuer die nh3-Sanitization. Bewusst klein gehalten.
_ALLOWED_TAGS: frozenset[str] = frozenset(
    {"p", "strong", "em", "code", "pre", "ul", "ol", "li", "br"}
)

# Keine Attribute erlaubt — nh3 erwartet dict[str, set[str]].
_ALLOWED_ATTRS: dict[str, set[str]] = {}


_FENCE_RE = re.compile(r"```([\s\S]*?)```")
_BOLD_RE = re.compile(r"\*\*([^*\n]+)\*\*")
_ITALIC_RE = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")
_CODE_RE = re.compile(r"`([^`\n]+)`")
_BULLET_LINE_RE = re.compile(r"^\s*[-*]\s+(.*)$")


def _render_inline(text: str) -> str:
    """Inline-Markdown: bold/italic/inline-code, alles andere escaped."""
    # Wichtige Reihenfolge: zuerst escapen, dann Markdown-Patterns einfuegen.
    # Sonst koennte `<script>` als HTML interpretiert werden, bevor wir es
    # behandeln.
    escaped = html_escape(text, quote=False)
    escaped = _CODE_RE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
    escaped = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)
    escaped = _ITALIC_RE.sub(lambda m: f"<em>{m.group(1)}</em>", escaped)
    return escaped


def _render_block_content(text: str) -> str:
    """Block-Level-Markdown: Listen, Absaetze. Erwartet Inhalt OHNE Fences.

    Zeilen werden in Absaetze gruppiert, leere Zeilen trennen Absaetze. Eine
    Folge von `- `/`* `-Zeilen wird zu einer `<ul>`.
    """
    lines = text.split("\n")
    out: list[str] = []
    paragraph_buf: list[str] = []
    list_buf: list[str] = []

    def _flush_paragraph() -> None:
        if paragraph_buf:
            joined = "<br>".join(_render_inline(line) for line in paragraph_buf)
            out.append(f"<p>{joined}</p>")
            paragraph_buf.clear()

    def _flush_list() -> None:
        if list_buf:
            items = "".join(f"<li>{_render_inline(item)}</li>" for item in list_buf)
            out.append(f"<ul>{items}</ul>")
            list_buf.clear()

    for raw_line in lines:
        line = raw_line.rstrip()
        if not line:
            _flush_paragraph()
            _flush_list()
            continue
        bullet = _BULLET_LINE_RE.match(line)
        if bullet is not None:
            _flush_paragraph()
            list_buf.append(bullet.group(1))
            continue
        # Normale Textzeile.
        _flush_list()
        paragraph_buf.append(line)

    _flush_paragraph()
    _flush_list()
    return "".join(out)


def _render_with_fences(text: str) -> str:
    """Splittet an ```-Fences und rendert Block-Inhalte rundherum."""
    parts: list[str] = []
    pos = 0
    for match in _FENCE_RE.finditer(text):
        before = text[pos : match.start()]
        if before:
            parts.append(_render_block_content(before))
        code_body = match.group(1)
        # Code-Body bleibt komplett escaped, keine Markdown-Interpretation.
        parts.append(f"<pre><code>{html_escape(code_body, quote=False)}</code></pre>")
        pos = match.end()
    rest = text[pos:]
    if rest:
        parts.append(_render_block_content(rest))
    return "".join(parts)


def render_note_markdown(raw: str | None) -> Markup:
    """Rendert eine Notiz von Markdown-Subset zu sicherem HTML.

    Pipeline:
      1. Markdown-Subset zu HTML (mit Escape).
      2. `nh3.clean(...)` mit kleiner Tag-Whitelist als zweiter Verteidigungs-
         linie (verhindert auch versehentlich durchschlagende HTML-Tags wenn
         in einer kuenftigen Erweiterung der Renderer rohes HTML emittiert).
      3. `Markup(...)` damit Jinja2 das Ergebnis nicht erneut escaped.

    Bei leerer Eingabe wird ein leerer `Markup` zurueckgegeben.
    """
    if not raw:
        return Markup("")
    rendered = _render_with_fences(raw)
    cleaned = nh3.clean(rendered, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS)
    # Sicherheits-Begruendung: `cleaned` ist das Ergebnis von `nh3.clean(...)`
    # mit einer kleinen Tag-Whitelist und ohne Attribute. Damit ist ein
    # `Markup(...)`-Wrap sicher — die HTML-Sanitization hat ihn als XSS-frei
    # erklaert. Ruff `S704` greift hier zu pauschal.
    return Markup(cleaned)  # noqa: S704 — nh3.clean output ist sicher.


__all__ = ["render_note_markdown"]
