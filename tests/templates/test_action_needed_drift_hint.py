"""Pure-Unit-Render-Tests fuer den Drift-Hint in
``servers/_action_needed_section.html`` — TICKET-010 Etappe 3.

Ergaenzt ``test_action_needed_drilldown.py`` (das den Drift-Key nicht kennt)
um die persistenten Faelle des Frontend-Smokes:

  1. ``worst_finding_drift=True`` -> Hint
     ``data-test="action-card-<id>-drift-hint"`` mit exakt
     "re-evaluation pending" (ADR-0052 Entscheidung 2, ADR-0045 englisch).
  2. Kein Hint bei ``worst_finding_drift=False`` und bei fehlendem Key
     (Jinja-Undefined ist falsy — Legacy-Entries brechen nicht).
  3. Hint rendert auch neben dem Em-Dash-Fallback (``evaluation=None``) —
     die Reason-Zelle traegt den Hint unabhaengig vom Reason-Text.
  4. Drift wird pro Row gerendert (gemischte Card).
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from flask import Flask, render_template

_HINT_WORDING = "re-evaluation pending"
_CARD_ID = "escalate-distro-patch"
_HINT_MARKER = f'data-test="action-card-{_CARD_ID}-drift-hint"'


# ---------------------------------------------------------------------------
# Fixtures + Render-Helper
# ---------------------------------------------------------------------------


def _entry(
    *,
    group_id: int = 1,
    drift: Any = ...,
    evaluation: Any = ...,
    worst_finding: Any = ...,
    fix_lane: str = "patch",
) -> dict[str, Any]:
    """Flacher (group, lane)-Entry im Vertrag von `_build_action_sections`
    (ADR-0053: zusaetzlich `fix_lane`)."""
    if evaluation is ...:
        evaluation = SimpleNamespace(risk_band_reason="vendor severity HIGH")
    if worst_finding is ...:
        worst_finding = SimpleNamespace(identifier_key=f"CVE-2026-{group_id}")
    entry: dict[str, Any] = {
        "group": SimpleNamespace(id=group_id, label=f"grp-{group_id}", group_kind="os_package"),
        "fix_lane": fix_lane,
        "evaluation": evaluation,
        "worst_finding": worst_finding,
        "count": 2,
    }
    if drift is not ...:
        entry["worst_finding_drift"] = drift
    return entry


def _card(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": _CARD_ID,
        "label": "ESCALATE · Patch distro",
        "variant": "escalate-distro",
        "filter": ("escalate", "patch", "os_package"),
        "count": len(entries),
        "show_labels": True,
        "groups": entries,
    }


def _render(app: Flask, entries: list[dict[str, Any]]) -> str:
    with app.test_request_context("/servers/42"):
        return render_template(
            "servers/_action_needed_section.html",
            action_sections=[_card(entries)],
        )


def _hint_texts(html: str) -> list[str]:
    """Inner-Texte aller Drift-Hint-Spans in Dokument-Reihenfolge."""
    return [
        m.strip()
        for m in re.findall(rf'data-test="action-card-{_CARD_ID}-drift-hint"[^>]*>([^<]*)<', html)
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_drift_hint_renders_with_exact_wording(app: Flask) -> None:
    html = _render(app, [_entry(drift=True)])
    assert _HINT_MARKER in html, f"Drift-Hint fehlt im Workflow-Card-HTML:\n{html}"
    assert _hint_texts(html) == [_HINT_WORDING], (
        f"Hint-Wording muss exakt {_HINT_WORDING!r} sein (ADR-0052 Entscheidung 2), "
        f"gerendert: {_hint_texts(html)!r}"
    )
    # Reason-Text rendert weiterhin daneben.
    assert "vendor severity HIGH" in html


def test_no_drift_hint_when_drift_false(app: Flask) -> None:
    html = _render(app, [_entry(drift=False)])
    assert _HINT_MARKER not in html, f"Hint darf bei drift=False nicht rendern:\n{html}"


def test_no_drift_hint_when_key_missing(app: Flask) -> None:
    """Legacy-Entry ohne Drift-Key: Undefined ist falsy, kein Render-Fehler."""
    html = _render(app, [_entry()])
    assert _HINT_MARKER not in html
    assert "CVE-2026-1" in html  # Row rendert normal weiter.


def test_drift_hint_renders_next_to_em_dash_fallback(app: Flask) -> None:
    """evaluation=None -> Reason-Zelle zeigt '—' UND den Hint (das Drift-Flag
    haengt nicht am Reason-Text)."""
    html = _render(app, [_entry(drift=True, evaluation=None)])
    assert "—" in html, f"Em-Dash-Fallback fehlt bei evaluation=None:\n{html}"
    assert _hint_texts(html) == [_HINT_WORDING], (
        f"Hint muss auch neben dem Em-Dash rendern:\n{html}"
    )


def test_lane_tag_renders_per_entry(app: Flask) -> None:
    """ADR-0053: jeder (group, lane)-Entry traegt einen dezenten Lane-Tag
    (patch/no patch) neben dem Group-Link."""
    html = _render(app, [_entry(group_id=1, fix_lane="patch")])
    assert f'data-test="action-card-{_CARD_ID}-lane"' in html, (
        f"Lane-Tag fehlt im Workflow-Card-HTML:\n{html}"
    )
    assert "patch" in html


def test_lane_tag_no_patch_label(app: Flask) -> None:
    """mitigate-Lane -> 'no patch'-Tag."""
    html = _render(app, [_entry(group_id=1, fix_lane="mitigate")])
    assert "no patch" in html


def test_drift_hint_is_per_row(app: Flask) -> None:
    """Gemischte Card: nur die driftende Row traegt den Hint."""
    html = _render(
        app,
        [
            _entry(group_id=1, drift=True),
            _entry(group_id=2, drift=False),
            _entry(group_id=3),  # Key fehlt
        ],
    )
    assert html.count(_HINT_MARKER) == 1, (
        f"Genau eine Row driftet -> genau ein Hint erwartet, HTML:\n{html}"
    )
    # Der Hint sitzt in der Row von grp-1: nach deren Group-Link, vor dem
    # Group-Link der naechsten Row. (Die Summary-Subline nennt die Labels
    # ebenfalls — daher Anker ueber die row-eindeutigen href-Attribute.)
    assert (
        html.index('href="#group-1"') < html.index(_HINT_MARKER) < html.index('href="#group-2"')
    ), "Hint muss in der driftenden Row (grp-1) sitzen"
