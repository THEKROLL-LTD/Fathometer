"""Pure-Unit Template-Tests: Settings-Tab-Navigation (Block AD / ADR-0047).

Verifiziert `settings/_nav.html` (horizontale `.settings-tabs`):
  - genau 7 Tabs in Mockup-Reihenfolge (Servers, Tags, Groups, LLM Provider,
    LLM Reviewer, Master-Key, About),
  - aktiver Tab traegt `settings-tabs__item--active` + `aria-selected="true"`,
    alle anderen `aria-selected="false"`,
  - voller HTMX-Attribut-Satz pro Tab (1:1-Vertrag mit der alten Nav),
  - Master-Key-Badge (`settings-tabs__badge` "new"),
  - ARIA-Rollen (`role="tablist"` / `role="tab"`).

Render direkt via Jinja-Env im App-Context (Content-Partial ohne extends).
"""

from __future__ import annotations

import pytest
from flask import Flask

# Tab-Reihenfolge + active-Bezeichner + erwartetes Label (Mockup-Reihenfolge).
_TABS = [
    ("servers", "Servers"),
    ("tags", "Tags"),
    ("groups", "Groups"),
    ("llm", "LLM Provider"),
    ("llm_reviewer", "LLM Reviewer"),
    ("master_key", "Master-Key"),
    ("about", "About"),
]


def _render_nav(app: Flask, active: str) -> str:
    with app.test_request_context("/settings"):
        return app.jinja_env.get_template("settings/_nav.html").render(active=active)


def test_seven_tabs_in_order(app: Flask) -> None:
    html = _render_nav(app, "servers")
    # Reihenfolge ueber die Label-Positionen im gerenderten Markup pruefen.
    positions = [html.index(f"<span>{label}</span>") for _, label in _TABS]
    assert positions == sorted(positions), f"Tab-Reihenfolge weicht ab: {positions}"
    # Genau 7 Tab-Anker.
    assert html.count('role="tab"') == 7


def test_tablist_role_present(app: Flask) -> None:
    html = _render_nav(app, "servers")
    assert 'class="settings-tabs"' in html
    assert 'role="tablist"' in html


@pytest.mark.parametrize("active,_label", _TABS)
def test_active_marker_per_tab(app: Flask, active: str, _label: str) -> None:
    html = _render_nav(app, active)
    # Genau ein aktiver Tab.
    assert html.count("settings-tabs__item--active") == 1
    assert html.count('aria-selected="true"') == 1
    assert html.count('aria-selected="false"') == 6


def test_htmx_attributes_complete(app: Flask) -> None:
    html = _render_nav(app, "servers")
    # Pro Tab der volle HTMX-Vertrag — jeweils 7x vorhanden.
    assert html.count('hx-target="#settings-content"') == 7
    assert html.count('hx-swap="innerHTML"') == 7
    assert html.count('hx-push-url="true"') == 7
    assert html.count("""hx-headers='{"HX-Target": "settings-content"}'""") == 7
    assert html.count("hx-get=") == 7
    # href-Fallback fuer No-JS / Right-Click.
    assert html.count("href=") == 7


def test_master_key_no_badge(app: Flask) -> None:
    # Der "new"-Badge wurde aus der Nav entfernt (User-Wunsch, Folge-Fix Block AD).
    html = _render_nav(app, "master_key")
    assert "settings-tabs__badge" not in html
    assert ">new</span>" not in html
    # Master-Key-Tab existiert weiterhin.
    assert "<span>Master-Key</span>" in html


def test_no_legacy_nav_markup(app: Flask) -> None:
    html = _render_nav(app, "servers")
    # Alte vertikale DaisyUI-Nav-Indikatoren sind weg.
    assert "w-56" not in html
    assert "menu-active" not in html
    assert 'class="menu' not in html
