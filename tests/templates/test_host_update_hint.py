"""Pure-Unit-Render-Tests fuer den ADR-0062 "host update ready"-Hinweis.

Block AH promotet ein lang-pkgs-Finding von ``upstream`` nach ``patch``, wenn
der Host-Agent das besitzende OS-Paket als updatebar gemeldet hat
(``Finding.host_update_available is True`` + ``owning_package`` gesetzt). Beide
Patch-Card-Surfaces zeigen dann einen positiven Hinweis
``host update ready: <owning_package> <available_version>``:

  * ``_partials/application_group_card.html`` — pro Lane unter dem Worst-Block
    (``data-test="group-lane-host-update-<gid>-<lane>"``).
  * ``servers/_action_needed_section.html`` — pro Workflow-Row in der
    Worst-Finding-Zelle (``data-test="action-card-<id>-host-update"``).

Gate beide Male: ``worst_finding.host_update_available and
worst_finding.owning_package``. ``available_version`` ist optional (Hinweis
zeigt dann nur das Paket). Kein ``|safe`` — die Felder sind Envelope-validiertes
ASCII, Autoescape bleibt trotzdem Pflicht.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from flask import Flask, render_template

_GROUP_ID = 7


def _worst(
    *,
    host_update_available: Any = True,
    owning_package: str | None = "tailscale",
    available_version: str | None = "1.98.5-1",
    identifier_key: str = "CVE-2026-42504",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=200,
        identifier_key=identifier_key,
        package_name="stdlib",
        host_update_available=host_update_available,
        owning_package=owning_package,
        available_version=available_version,
    )


# ---------------------------------------------------------------------------
# Group-Card-Surface
# ---------------------------------------------------------------------------


def _render_group_card(
    app: Flask, *, worst: SimpleNamespace | None, fix_lane: str = "patch"
) -> str:
    ctx = {
        "group": SimpleNamespace(
            id=_GROUP_ID, label="tailscale", group_kind="application_bundle", explanation=None
        ),
        "count": 1,
        "lanes": [
            {
                "fix_lane": fix_lane,
                "evaluation": SimpleNamespace(
                    risk_band="escalate", risk_band_reason="public 41641"
                ),
                "count": 1,
                "worst_finding": worst,
                "worst_finding_drift": False,
            }
        ],
        "server": SimpleNamespace(id=42),
    }
    with app.test_request_context("/servers/42"):
        return render_template("_partials/application_group_card.html", **ctx)


def _card_hint(html: str, lane: str = "patch") -> str | None:
    m = re.search(
        rf'data-test="group-lane-host-update-{_GROUP_ID}-{lane}"[^>]*>([^<]*)<',
        html,
    )
    return m.group(1).strip() if m else None


def test_group_card_hint_renders_with_pkg_and_version(app: Flask) -> None:
    html = _render_group_card(app, worst=_worst())
    assert _card_hint(html) == "host update ready: tailscale 1.98.5-1"


def test_group_card_hint_without_version_shows_pkg_only(app: Flask) -> None:
    html = _render_group_card(app, worst=_worst(available_version=None))
    assert _card_hint(html) == "host update ready: tailscale"


def test_group_card_no_hint_when_flag_false(app: Flask) -> None:
    html = _render_group_card(app, worst=_worst(host_update_available=False))
    assert _card_hint(html) is None


def test_group_card_no_hint_when_flag_none(app: Flask) -> None:
    html = _render_group_card(app, worst=_worst(host_update_available=None))
    assert _card_hint(html) is None


def test_group_card_no_hint_when_owning_package_missing(app: Flask) -> None:
    html = _render_group_card(app, worst=_worst(owning_package=None))
    assert _card_hint(html) is None


def test_group_card_hint_owning_package_xss_escaped(app: Flask) -> None:
    payload = "</span><script>alert(1)</script>"
    html = _render_group_card(app, worst=_worst(owning_package=payload))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Workflow-Card-Surface (Operator-Workflows)
# ---------------------------------------------------------------------------


def _render_action_section(app: Flask, *, worst: SimpleNamespace | None) -> str:
    card = {
        "id": "escalate-app-update",
        "label": "ESCALATE · Apply app update",
        "variant": "escalate-app",
        "count": 1,
        "show_labels": True,
        "groups": [
            {
                "group": SimpleNamespace(id=_GROUP_ID, label="tailscale"),
                "fix_lane": "patch",
                "evaluation": SimpleNamespace(risk_band_reason="public 41641"),
                "count": 1,
                "worst_finding": worst,
                "worst_finding_drift": False,
            }
        ],
    }
    ctx = {"action_sections": [card], "server": SimpleNamespace(id=42)}
    with app.test_request_context("/servers/42"):
        return render_template("servers/_action_needed_section.html", **ctx)


def _action_hint(html: str) -> str | None:
    m = re.search(
        r'data-test="action-card-escalate-app-update-host-update"[^>]*>([^<]*)<',
        html,
    )
    return m.group(1).strip() if m else None


def test_action_card_hint_renders_with_pkg_and_version(app: Flask) -> None:
    html = _render_action_section(app, worst=_worst())
    assert _action_hint(html) == "host update ready: tailscale 1.98.5-1"


def test_action_card_no_hint_when_flag_false(app: Flask) -> None:
    html = _render_action_section(app, worst=_worst(host_update_available=False))
    assert _action_hint(html) is None


def test_action_card_no_hint_when_owning_package_missing(app: Flask) -> None:
    html = _render_action_section(app, worst=_worst(owning_package=None))
    assert _action_hint(html) is None
