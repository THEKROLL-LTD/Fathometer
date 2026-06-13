"""Pure-Unit-Render-Tests fuer die Upstream-Sub-Zeile + Fix-Versions-Anzeige in
``servers/_action_needed_section.html`` (Block AK, ADR-0064).

ADR-0064 nimmt die eigene ``upstream``-Lane (ADR-0061) zurueck: sie kollabiert
in ``mitigate``. Die Information "ein Fix existiert upstream" wird
**Finding-Level-Enrichment** innerhalb der ``escalate-mitigate``-Card:

  * Ein **Panel** (das Single-Source-``upstream_check_panel.html``) und eine
    **Fix-Versions-Zeile** ("fixed upstream: ``<component> <version>`` — needs
    rebuild") rendern NUR, wenn ``card.id == 'escalate-mitigate'`` UND das
    Feature konfiguriert ist (``upstream_check_configured``) UND ein
    ``entry.upstream_check`` mit ``state != 'idle'`` angehaengt ist.
  * Sie rendern NICHT bei ``state == 'idle'``, NICHT bei
    ``entry.upstream_check is None``, NICHT bei
    ``upstream_check_configured == False`` und NICHT auf anderen Cards
    (``escalate-distro-patch``/``act-*``) — selbst wenn dort
    (inkonsistenterweise) ein ``upstream_check`` haengt.
  * XSS: ``seed.vulnerable_component``/``seed.fixing_component_version`` sind
    Scanner-/Trivy-Daten -> Jinja-Autoescape, kein ``|safe``-Leak.
  * Negativ (Sprach-/Label-Sweep, ADR-0064): das Wort "upstream" erscheint im
    gerenderten Markup nur in der "fixed upstream"-Fliesstext-Zeile bzw. in den
    Panel-Strings — NIE als Fix-Lane-Label (das ist 2-wertig "patch"/"no patch").

DB-frei: das Section-Template wird via ``render_template`` mit
``SimpleNamespace``-Stubs gerendert (analog ``test_action_needed_drift_hint.py``
+ ``test_upstream_check_panel_render.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from flask import Flask, render_template

_SID = 42
_MITIGATE_CARD = "escalate-mitigate"
_PATCH_CARD = "escalate-distro-patch"
_NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Stub-Fabriken
# ---------------------------------------------------------------------------


def _seed(
    *,
    vulnerable_component: str = "stdlib",
    fixing_component_version: str = "1.26.2",
) -> SimpleNamespace:
    return SimpleNamespace(
        artifact_module="tailscaled",
        installed_component_version="v1.26.1",
        vulnerable_component=vulnerable_component,
        fixing_component_version=fixing_component_version,
        cve="CVE-2026-0001",
    )


def _row(**over: Any) -> SimpleNamespace:
    base: dict[str, Any] = {
        "delivery": "fixed_release_exists",
        "fixed_build_release": "1.26.2",
        "fixed_build_release_date": "2026-05-01",
        "latest_release_component_version": "1.26.2",
        "operator_action": "Upgrade tailscale to 1.26.2.",
        "confidence": "high",
        "sources_used": ["https://tailscale.com/security/ts-2026-001"],
        "reasoning": "Release notes confirm the fix.",
        "error": None,
        "checked_at": _NOW,
    }
    base.update(over)
    return SimpleNamespace(**base)


def _upstream_check(
    *,
    state: str,
    row: SimpleNamespace | None = None,
    seed: SimpleNamespace | None = None,
    is_fresh: bool = False,
    checked_age: timedelta | None = None,
) -> SimpleNamespace:
    """Surrogat fuer ``UpstreamCheckState`` (das Template liest nur Attribute)."""
    return SimpleNamespace(
        state=state,
        row=row,
        seed=seed,
        is_fresh=is_fresh,
        checked_age=checked_age,
    )


def _entry(
    *,
    group_id: int = 1,
    fix_lane: str = "mitigate",
    upstream_check: Any = ...,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "group": SimpleNamespace(id=group_id, label=f"grp-{group_id}", group_kind="os_package"),
        "fix_lane": fix_lane,
        "evaluation": SimpleNamespace(risk_band_reason="exposed listener · HIGH"),
        "worst_finding": SimpleNamespace(
            identifier_key=f"CVE-2026-{group_id}",
            host_update_available=None,
            owning_package=None,
            available_version=None,
        ),
        "count": 2,
        "worst_finding_drift": False,
    }
    if upstream_check is not ...:
        entry["upstream_check"] = upstream_check
    return entry


def _card(card_id: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    is_mitigate = card_id == _MITIGATE_CARD
    return {
        "id": card_id,
        "label": (
            "ESCALATE · No host patch — mitigate" if is_mitigate else "ESCALATE · Patch distro"
        ),
        "variant": "escalate-mitigate" if is_mitigate else "escalate-distro",
        "filter": ("escalate", "mitigate" if is_mitigate else "patch", None),
        "count": len(entries),
        "show_labels": True,
        "groups": entries,
    }


def _render(
    app: Flask,
    cards: list[dict[str, Any]],
    *,
    upstream_check_configured: bool = True,
) -> str:
    from app.forms import CSRFOnlyForm

    app.config.update(WTF_CSRF_ENABLED=False)
    with app.test_request_context(f"/servers/{_SID}"):
        return render_template(
            "servers/_action_needed_section.html",
            action_sections=cards,
            server=SimpleNamespace(id=_SID, name="host-42"),
            upstream_check_configured=upstream_check_configured,
            csrf_form=CSRFOnlyForm(),
        )


_PANEL_ID = f"upstream-check-{_SID}-1-panel"
_UPSTREAM_ROW = f'data-test="action-card-{_MITIGATE_CARD}-upstream-row"'
_FIX_LINE = f'data-test="action-card-{_MITIGATE_CARD}-upstream-fix"'


# ---------------------------------------------------------------------------
# Panel + Fix-Zeile rendern bei state in {done, cached, running}
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "is_fresh"),
    [("done", False), ("cached", True), ("running", False)],
)
def test_panel_renders_on_mitigate_card_for_active_states(
    app: Flask, state: str, is_fresh: bool
) -> None:
    """state in {done, cached, running} (!= idle) -> Panel-Sub-Zeile rendert."""
    row = _row() if state in {"done", "cached"} else None
    check = _upstream_check(state=state, row=row, seed=_seed(), is_fresh=is_fresh)
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])])
    assert _UPSTREAM_ROW in html, f"Upstream-Sub-Zeile fehlt im State {state!r}:\n{html}"
    assert f'id="{_PANEL_ID}"' in html, f"Panel-ID fehlt im State {state!r}:\n{html}"
    assert f'data-state="{state}"' in html


@pytest.mark.parametrize(
    ("state", "is_fresh"),
    [("done", False), ("cached", True)],
)
def test_fix_version_line_renders_with_exact_wording(
    app: Flask, state: str, is_fresh: bool
) -> None:
    """Case 5: Fix-Versions-Zeile mit exaktem Wortlaut aus ``upstream_check.seed``."""
    check = _upstream_check(state=state, row=_row(), seed=_seed(), is_fresh=is_fresh)
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])])
    assert _FIX_LINE in html, f"Fix-Versions-Zeile fehlt:\n{html}"
    assert "fixed upstream: stdlib 1.26.2 — needs rebuild" in html, (
        f"Wortlaut der Fix-Versions-Zeile stimmt nicht:\n{html}"
    )


def test_fix_version_line_absent_when_seed_has_no_fixing_version(app: Flask) -> None:
    """Kein ``fixing_component_version`` (no-fix lang-pkgs) -> keine Fix-Zeile.

    Die Fix-Zeile haengt am ``seed.fixing_component_version``; ohne diesen
    Anker zeigen wir nichts (No-fix-Finding, ADR-0064 §Finding-Level)."""
    seed = _seed(fixing_component_version="")
    check = _upstream_check(state="done", row=_row(), seed=seed)
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])])
    assert _FIX_LINE not in html, f"Fix-Zeile darf ohne fixing_component_version fehlen:\n{html}"
    # Das Panel selbst rendert trotzdem (state != idle).
    assert _UPSTREAM_ROW in html


# ---------------------------------------------------------------------------
# Panel/Fix-Zeile NICHT bei idle / None / unkonfiguriert
# ---------------------------------------------------------------------------


def test_panel_absent_when_state_idle(app: Flask) -> None:
    """state == 'idle' (kein researchbares Finding) -> weder Panel noch Fix-Zeile."""
    check = _upstream_check(state="idle", row=None, seed=_seed())
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])])
    assert _UPSTREAM_ROW not in html, f"idle darf keine Sub-Zeile rendern:\n{html}"
    assert f'id="{_PANEL_ID}"' not in html
    # Die normale Group-Row rendert weiter.
    assert "grp-1" in html


def test_panel_absent_when_upstream_check_none(app: Flask) -> None:
    """``entry.upstream_check is None`` -> keine Sub-Zeile (Jinja-Truthiness)."""
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=None)])])
    assert _UPSTREAM_ROW not in html, f"upstream_check=None darf keine Sub-Zeile rendern:\n{html}"
    assert _FIX_LINE not in html


def test_panel_absent_when_upstream_check_key_missing(app: Flask) -> None:
    """Legacy-Entry ohne ``upstream_check``-Key (Jinja-Undefined ist falsy)."""
    html = _render(app, [_card(_MITIGATE_CARD, [_entry()])])
    assert _UPSTREAM_ROW not in html
    assert "grp-1" in html  # Row rendert normal weiter, kein Render-Fehler.


def test_panel_absent_when_not_configured(app: Flask) -> None:
    """``upstream_check_configured == False`` -> keine Sub-Zeile, selbst bei
    done-State + Seed (das Gate sitzt VOR dem state-Check)."""
    check = _upstream_check(state="done", row=_row(), seed=_seed())
    html = _render(
        app,
        [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])],
        upstream_check_configured=False,
    )
    assert _UPSTREAM_ROW not in html, f"unkonfiguriert darf keine Sub-Zeile rendern:\n{html}"
    assert f'id="{_PANEL_ID}"' not in html


# ---------------------------------------------------------------------------
# Panel/Fix-Zeile NICHT auf anderen Cards (patch / act)
# ---------------------------------------------------------------------------


def test_panel_absent_on_patch_card_even_with_upstream_check(app: Flask) -> None:
    """Andere Card (escalate-distro-patch): selbst ein angehaengtes
    ``upstream_check`` mit done-State darf KEINE Sub-Zeile rendern — das Gate
    ist auf ``card.id == 'escalate-mitigate'`` (ADR-0064)."""
    check = _upstream_check(state="done", row=_row(), seed=_seed())
    entry = _entry(fix_lane="patch", upstream_check=check)
    html = _render(app, [_card(_PATCH_CARD, [entry])])
    # Weder die Panel-Sub-Zeile der patch-Card noch ein Panel-Markup.
    assert f'data-test="action-card-{_PATCH_CARD}-upstream-row"' not in html, (
        f"patch-Card darf keine Upstream-Sub-Zeile rendern:\n{html}"
    )
    assert f"upstream-check-{_SID}-1-panel" not in html


def test_fix_version_line_renders_on_patch_card_too(app: Flask) -> None:
    """Die Fix-Versions-Zeile haengt am ``entry.upstream_check.seed`` und ist
    NICHT card-gated — sie kann (theoretisch) auch in einer anderen Card
    erscheinen, wenn ein seed mit Fix-Version anliegt. Das Panel hingegen ist
    strikt mitigate-card-gated (siehe Test oben). Wir dokumentieren das
    bewusst: die Fix-Zeile ist Finding-Level, das Panel ist Card-Level."""
    check = _upstream_check(state="done", row=_row(), seed=_seed())
    entry = _entry(fix_lane="patch", upstream_check=check)
    html = _render(app, [_card(_PATCH_CARD, [entry])])
    assert f'data-test="action-card-{_PATCH_CARD}-upstream-fix"' in html, (
        f"Fix-Versions-Zeile ist Finding-Level (seed-gated), nicht card-gated:\n{html}"
    )


# ---------------------------------------------------------------------------
# XSS — seed-Felder sind Scanner-/Trivy-Daten, kein |safe-Leak
# ---------------------------------------------------------------------------


def test_seed_vulnerable_component_xss_escaped(app: Flask) -> None:
    payload = "<script>alert(1)</script>"
    seed = _seed(vulnerable_component=payload)
    check = _upstream_check(state="done", row=_row(), seed=seed)
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])])
    assert "<script>alert(1)</script>" not in html, f"vulnerable_component UNESCAPED:\n{html}"
    assert "&lt;script&gt;" in html


def test_seed_fixing_version_xss_escaped(app: Flask) -> None:
    payload = '"><img src=x onerror="alert(2)">'
    seed = _seed(fixing_component_version=payload)
    check = _upstream_check(state="done", row=_row(), seed=seed)
    html = _render(app, [_card(_MITIGATE_CARD, [_entry(upstream_check=check)])])
    assert "<img src=x" not in html, f"fixing_component_version UNESCAPED:\n{html}"
    assert "&lt;img" in html or "&#34;&gt;&lt;img" in html


# ---------------------------------------------------------------------------
# Negativ: "upstream" NIE als Fix-Lane-Label im gerenderten Markup
# ---------------------------------------------------------------------------


def test_lane_label_is_two_valued_no_upstream(app: Flask) -> None:
    """ADR-0064: das Lane-Tag ist 2-wertig — ``patch`` ODER ``no patch``.
    "upstream" darf NIE als Lane-Label erscheinen (es ist keine Lane mehr)."""
    # mitigate-Lane -> Lane-Tag "no patch".
    check = _upstream_check(state="idle", row=None, seed=_seed())
    html = _render(
        app, [_card(_MITIGATE_CARD, [_entry(fix_lane="mitigate", upstream_check=check)])]
    )
    lane_marker = f'data-test="action-card-{_MITIGATE_CARD}-lane"'
    assert lane_marker in html
    import re

    lane_texts = re.findall(rf"{lane_marker}[^>]*>([^<]*)<", html)
    assert lane_texts == ["no patch"], f"Lane-Label muss 'no patch' sein, war: {lane_texts!r}"
    for text in lane_texts:
        assert "upstream" not in text.lower(), (
            f"'upstream' darf NIE ein Lane-Label sein (ADR-0064): {text!r}"
        )


def test_word_upstream_only_in_fix_line_not_as_lane_label(app: Flask) -> None:
    """Wenn "upstream" im gerenderten mitigate-Card-Markup vorkommt, dann nur in
    der "fixed upstream"-Fliesstext-Zeile bzw. in Panel-Strings — NICHT in einem
    Lane-Tag (``workflow-table__lane-tag``)."""
    check = _upstream_check(state="done", row=_row(), seed=_seed())
    html = _render(
        app, [_card(_MITIGATE_CARD, [_entry(fix_lane="mitigate", upstream_check=check)])]
    )
    # Die Fix-Zeile traegt "fixed upstream:" — das ist die einzige erlaubte
    # Lane-/Card-Stelle mit dem Wort "upstream" als Operator-Text.
    assert "fixed upstream:" in html
    # Der Lane-Tag (das data-test="...-lane"-Span) enthaelt KEIN "upstream".
    import re

    lane_spans = re.findall(rf'data-test="action-card-{_MITIGATE_CARD}-lane"[^>]*>([^<]*)<', html)
    for span in lane_spans:
        assert "upstream" not in span.lower(), (
            f"Lane-Tag-Span enthaelt 'upstream' (ADR-0064 verletzt): {span!r}"
        )
