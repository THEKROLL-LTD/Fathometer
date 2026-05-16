"""3-Modi-Render-Helper fuer die Settings-View (ADR-0016 / Block-I-Addendum).

Die Settings-View ist intern zweigeteilt (Sekundaer-Nav links + Content
rechts) und kann je nach Request-Kontext in drei unterschiedlichen
Granularitaeten ausgespielt werden:

1. **Vollseite** (kein HX-Request) — `base_app.html` mit der globalen
   Sidebar links plus dem Settings-Shell (Nav + Content) im Detail-Pane.
   Direkt-URL-Aufruf (Bookmark, Browser-Refresh).
2. **Detail-Pane-Fragment** (HX-Request mit anderem Target als
   `settings-content`, typisch `#detail-pane`) — Settings-Shell mit Nav
   + Content, eingewickelt in den `_partial_shell.html`-Wrapper.
   Klick auf "Settings" im Profile-Dropdown.
3. **Content-Fragment** (HX-Request mit `HX-Target: settings-content`)
   — nur der Content-Bereich rechts der Nav. Klick in der Settings-Nav
   selbst.

Der Helper kapselt diese Unterscheidung und setzt zugleich die
`hx_partial`-Variable im Template-Kontext, damit bestehende Templates
(Block-I-Tests pruefen darauf) das richtige dynamische `extends` waehlen.
"""

from __future__ import annotations

from typing import Any

from flask import render_template, request


def render_settings(active: str, content_template: str, **ctx: Any) -> str:
    """Rendert eine Settings-Sub-View in einem von drei Modi.

    Argumente:
      - `active`: Bezeichner des aktiven Settings-Tabs
        (z.B. ``"tags"``, ``"llm"``, ``"servers"``, ``"master_key"``,
        ``"about"``). Wird im Template fuer das `menu-active`-Highlight
        in der Settings-Nav verwendet.
      - `content_template`: Pfad des reinen Content-Templates
        (z.B. ``"settings/about.html"``). Das Template darf keinen
        `extends` enthalten, sondern liefert nur das Markup fuer den
        Content-Bereich rechts der Nav.
      - ``**ctx``: zusaetzliche Template-Variablen (Form-Objekte,
        Daten-Records, ...).

    Auswahl-Logik:
      - ``HX-Request: true`` UND ``HX-Target: settings-content``
        -> nur Content-Fragment rendern (innerstes Swap-Target).
      - ``HX-Request: true`` mit anderem Target
        -> Settings-Shell (Nav + Content) als HTMX-Detail-Pane-Fragment.
      - kein HX-Request
        -> volle Seite mit Sidebar + Settings-Shell im Detail-Pane.
    """
    hx_target = request.headers.get("HX-Target", "")
    hx_request = request.headers.get("HX-Request") == "true"

    # Mode 3: innerstes Swap-Ziel — nur Content, keine Nav, kein Wrapper.
    if hx_request and hx_target == "settings-content":
        return render_template(
            content_template,
            active=active,
            settings_partial="content",
            hx_partial=True,
            **ctx,
        )

    # Mode 2: Detail-Pane-Fragment — Nav + Content, ohne `<html>`-Wrapper.
    if hx_request:
        return render_template(
            "settings/_shell.html",
            active=active,
            content_template=content_template,
            settings_partial="shell",
            hx_partial=True,
            **ctx,
        )

    # Mode 1: volle Seite — Sidebar links + Settings-Shell rechts.
    return render_template(
        "settings/_page.html",
        active=active,
        content_template=content_template,
        settings_partial="page",
        hx_partial=False,
        **ctx,
    )


__all__ = ["render_settings"]
