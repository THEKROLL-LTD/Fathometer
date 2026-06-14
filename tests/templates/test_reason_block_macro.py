"""Pure-Unit-Render-Tests fuer das Single-Source-Reason-Macro
``reason_block`` aus ``_macros.html`` (TICKET-016 / ADR-0065 §4).

Das Macro ist die EINE Quelle der Smart-Truncation-/Toggle-UI fuer die
LLM-``risk_band_reason`` an allen Render-Orten (Group-Card, Action-Needed-
Tabelle, Findings-Page-Lane-Header). Single-Source-Pflicht (CLAUDE.md
§HTMX-OOB-Single-Source-Pattern): ein Macro, kein kopiertes Markup.

Geprueft:
  1. Kurze Reason -> kein Toggle, voller Text gerendert.
  2. Lange Reason -> Wortgrenzen-Kuerzung + "Show all"/"Show less"-Toggle
     mit ``aria-expanded`` und Alpine ``x-data``/``x-show``.
  3. Sicherheit: LLM-Output bleibt autoescaped (kein ``|safe``-Leak) — auf
     beiden Pfaden (kurz + voll).
  4. Leere/None-Reason -> kein Markup.
"""

from __future__ import annotations

from flask import Flask, render_template_string

_SHORT = "kev present on openssh"
# > 160 Zeichen, klare Wortgrenzen.
_LONG = (
    "MIME-decode flaw unlikely to be triggered by WireGuard transport because "
    "the daemon never parses untrusted MIME in the reachable code path, and no "
    "listener is exposed beyond the tailnet interface, so no remote attack path."
)


def _render(app: Flask, reason: str | None, *, limit: int = 160) -> str:
    with app.test_request_context("/"):
        return render_template_string(
            "{% from '_macros.html' import reason_block %}{{ reason_block(reason, limit) }}",
            reason=reason,
            limit=limit,
        )


# ---------------------------------------------------------------------------
# Kurz / lang
# ---------------------------------------------------------------------------


def test_short_reason_renders_without_toggle(app: Flask) -> None:
    html = _render(app, _SHORT)
    assert _SHORT in html
    assert "reason-block__toggle" not in html, f"Kurze Reason darf keinen Toggle haben:\n{html}"
    assert "x-data" not in html


def test_long_reason_renders_toggle_with_a11y(app: Flask) -> None:
    html = _render(app, _LONG)
    # Toggle-Button mit a11y + Alpine.
    assert "reason-block__toggle" in html, html
    assert 'type="button"' in html
    assert "aria-expanded" in html
    assert "x-data" in html
    assert "x-show" in html
    # Beide Label-Varianten (ADR-0045 englisch).
    assert "Show all" in html
    assert "Show less" in html
    # Voller Text liegt im DOM (expandierter Pfad).
    assert _LONG in html


def test_long_reason_truncates_on_word_boundary(app: Flask) -> None:
    """Gekuerzte Variante endet mit Ellipsis und schneidet nicht mitten im
    Wort (killwords=False)."""
    html = _render(app, _LONG, limit=80)
    assert "…" in html, f"Ellipsis-Marker fehlt in der gekuerzten Variante:\n{html}"
    # Der gekuerzte Text-Span (x-show="!expanded") ist kuerzer als der volle.
    assert html.count("reason-block__text") == 2, "kurz + voll = zwei Text-Spans erwartet"


def test_reason_xss_payload_is_escaped(app: Flask) -> None:
    """risk_band_reason ist LLM-Output -> Autoescape muss greifen, auch in der
    Truncation. Kein ``|safe``."""
    payload = "<script>alert(1)</script> " + "padding text " * 20  # erzwingt Toggle
    html = _render(app, payload)
    assert "<script>alert(1)</script>" not in html, f"XSS UNESCAPED:\n{html}"
    assert "&lt;script&gt;" in html, f"Escaped-Variante fehlt — Autoescape kaputt:\n{html}"


def test_empty_reason_renders_nothing(app: Flask) -> None:
    assert _render(app, None).strip() == ""
    assert _render(app, "").strip() == ""
