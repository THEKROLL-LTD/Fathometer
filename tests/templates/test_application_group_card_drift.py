"""Pure-Unit-Render-Tests fuer ``_partials/application_group_card.html`` —
TICKET-013 Etappe 7 (Fix-Lane-Evaluation, ADR-0053) auf Basis des frueheren
TICKET-010-Drift-Smokes.

Render-Vertrag ist jetzt der Lane-Kontrakt: das Partial bekommt `group`,
`count` (Group-Total), `lanes` (Liste, patch zuerst) und `server`. Pro Lane:
`fix_lane`, `evaluation`, `count`, `worst_finding`, `worst_finding_drift`.

Persistiert:

  1. Per-Lane-Drift-Hint ``data-test="group-lane-drift-hint-<gid>-<lane>"`` mit
     exakt "re-evaluation pending" (ADR-0052 Entscheidung 2, ADR-0045 englisch).
  2. Kein Hint bei ``worst_finding_drift=False`` und bei fehlendem Key.
  3. Reason-Block rendert auch ohne Reason-Text solange Drift gemeldet wird
     (Gate: ``evaluation and (reason or drift)``).
  4. Worst-Block ist allein durch ``lane.worst_finding`` gegated — rendert auch
     ohne ``evaluation`` (Bug-C-Regression).
  5. Kein Worst-Block bei ``worst_finding=None``.
  6. Max-Band-Header: das Header-Badge zeigt das urgentste Band ueber die
     Lanes; ``pending`` ohne jede Lane-Evaluation.
  7. Gemischte Group rendert zwei Lane-Assessment-Bloecke (patch + no patch)
     mit je eigener Reason/Worst; reine patch-Group nur einen.
  8. XSS: ``risk_band_reason`` und ``package_name`` (LLM-/Scanner-Daten)
     bleiben escaped — kein ``|safe``-Leak.

Vollstaendiger DB-Render (ORM-Objekte) ist db_integration
(``tests/integration/test_application_group_cards_db.py``) und steht beim
User an.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from flask import Flask, render_template

_HINT_WORDING = "re-evaluation pending"
_GROUP_ID = 7


# ---------------------------------------------------------------------------
# Render-Helper
# ---------------------------------------------------------------------------


def _lane(
    *,
    fix_lane: str = "patch",
    risk_band: str | None = "escalate",
    risk_band_reason: str | None = "kev present on openssh",
    has_evaluation: bool = True,
    worst_id: int | None = 200,
    identifier_key: str = "CVE-2026-31431",
    package_name: str = "openssh-server",
    drift: Any = ...,
    count: int = 3,
) -> dict[str, Any]:
    """Baut einen Lane-Eintrag im Render-Vertrag von
    ``_load_application_groups_for_server``."""
    evaluation = (
        SimpleNamespace(risk_band=risk_band, risk_band_reason=risk_band_reason)
        if has_evaluation
        else None
    )
    worst_finding = (
        SimpleNamespace(id=worst_id, identifier_key=identifier_key, package_name=package_name)
        if worst_id is not None
        else None
    )
    lane: dict[str, Any] = {
        "fix_lane": fix_lane,
        "evaluation": evaluation,
        "count": count,
        "worst_finding": worst_finding,
    }
    if drift is not ...:
        lane["worst_finding_drift"] = drift
    return lane


def _make_context(*, lanes: list[dict[str, Any]] | None = None, count: int = 3) -> dict[str, Any]:
    """Default-Context: Group mit einer bewerteten patch-Lane."""
    if lanes is None:
        lanes = [_lane(drift=False)]
    return {
        "group": SimpleNamespace(
            id=_GROUP_ID, label="openssh", group_kind="os_package", explanation=None
        ),
        "count": count,
        "lanes": lanes,
        "server": SimpleNamespace(id=42),
    }


def _render_card(app: Flask, ctx: dict[str, Any]) -> str:
    """Rendert das echte Partial ueber den App-Jinja-Loader (url_for noetig)."""
    with app.test_request_context("/servers/42"):
        return render_template("_partials/application_group_card.html", **ctx)


def _hint_marker(lane: str = "patch", group_id: int = _GROUP_ID) -> str:
    return f'data-test="group-lane-drift-hint-{group_id}-{lane}"'


def _hint_text(html: str, lane: str = "patch", group_id: int = _GROUP_ID) -> str | None:
    """Extrahiert den Inner-Text des Lane-Drift-Hint-Spans (None wenn abwesend)."""
    match = re.search(
        rf'data-test="group-lane-drift-hint-{group_id}-{lane}"[^>]*>([^<]*)<',
        html,
    )
    if match is None:
        return None
    return match.group(1).strip()


# ---------------------------------------------------------------------------
# Drift-Hint (per Lane)
# ---------------------------------------------------------------------------


def test_drift_hint_renders_with_exact_wording(app: Flask) -> None:
    """worst_finding_drift=True -> Lane-Hint-Span mit exakt 're-evaluation pending'."""
    ctx = _make_context(lanes=[_lane(drift=True)])
    html = _render_card(app, ctx)

    assert _hint_marker() in html, f"Lane-Drift-Hint fehlt im HTML:\n{html}"
    assert _hint_text(html) == _HINT_WORDING, (
        f"Hint-Wording muss exakt {_HINT_WORDING!r} sein (ADR-0052 Entscheidung 2), "
        f"gerendert: {_hint_text(html)!r}"
    )


def test_no_drift_hint_when_drift_false(app: Flask) -> None:
    ctx = _make_context(lanes=[_lane(drift=False)])
    html = _render_card(app, ctx)
    assert _hint_marker() not in html, f"Hint darf bei drift=False nicht rendern:\n{html}"
    # Reason rendert weiterhin normal.
    assert "kev present on openssh" in html


def test_no_drift_hint_when_lane_key_missing(app: Flask) -> None:
    """Lane ohne `worst_finding_drift`-Key: Jinja-Undefined ist falsy — kein
    Hint, kein Render-Fehler."""
    ctx = _make_context(lanes=[_lane()])  # drift weggelassen
    assert "worst_finding_drift" not in ctx["lanes"][0]
    html = _render_card(app, ctx)
    assert _hint_marker() not in html


def test_drift_hint_renders_even_without_reason_text(app: Flask) -> None:
    """Gate ist `evaluation and (reason or drift)` — bei leerer Reason aber
    Drift rendert der Reason-Block nur mit dem Hint."""
    ctx = _make_context(lanes=[_lane(risk_band_reason=None, drift=True)])
    html = _render_card(app, ctx)
    assert f'data-test="group-lane-reason-{_GROUP_ID}-patch"' in html, (
        f"Reason-Block muss bei Drift auch ohne Reason-Text rendern:\n{html}"
    )
    assert _hint_text(html) == _HINT_WORDING


def test_no_reason_block_without_evaluation_even_if_drift_flag_set(app: Flask) -> None:
    """Ohne Evaluation gibt es keinen AI-Assessment-Block — auch ein
    (inkonsistent) gesetztes Drift-Flag erzwingt keinen."""
    ctx = _make_context(lanes=[_lane(has_evaluation=False, drift=True)])
    html = _render_card(app, ctx)
    assert f'data-test="group-lane-reason-{_GROUP_ID}-patch"' not in html
    assert _hint_marker() not in html


# ---------------------------------------------------------------------------
# Worst-Finding-Block-Gate (Bug-C-Regression, per Lane)
# ---------------------------------------------------------------------------


def test_worst_block_renders_without_evaluation(app: Flask) -> None:
    """`{% if lane.worst_finding %}` ist das einzige Gate — 'Nicht bewertet'-
    Lanes zeigen ihr Live-Worst trotzdem (TICKET-010: Eval-Snapshot ist keine
    Render-Bedingung mehr)."""
    ctx = _make_context(lanes=[_lane(has_evaluation=False, drift=False)])
    html = _render_card(app, ctx)
    assert f'data-test="group-lane-worst-{_GROUP_ID}-patch"' in html, (
        f"Worst-Block muss ohne Evaluation rendern:\n{html}"
    )
    assert "CVE-2026-31431" in html
    assert 'href="#finding-200"' in html, "Worst-Link muss auf die Live-Finding-ID zeigen"


def test_no_worst_block_when_live_worst_missing(app: Flask) -> None:
    """worst_finding=None -> kein Worst-Block, Rest der Card rendert."""
    ctx = _make_context(lanes=[_lane(worst_id=None, drift=True)])
    html = _render_card(app, ctx)
    assert f'data-test="group-lane-worst-{_GROUP_ID}-patch"' not in html
    assert f'data-test="group-card-{_GROUP_ID}"' in html
    assert _hint_text(html) == _HINT_WORDING


# ---------------------------------------------------------------------------
# Max-Band-Header & Lane-Blocks
# ---------------------------------------------------------------------------


def test_header_band_is_pending_without_any_evaluation(app: Flask) -> None:
    """Keine Lane bewertet -> Header-Badge ist PENDING."""
    ctx = _make_context(lanes=[_lane(has_evaluation=False, drift=False)])
    html = _render_card(app, ctx)
    match = re.search(r'data-test="group-band-badge"[^>]*>([^<]*)<', html)
    assert match is not None, f"Header-Band-Badge fehlt:\n{html}"
    assert match.group(1).strip() == "PENDING"


def test_header_band_is_max_over_lanes(app: Flask) -> None:
    """Gemischte Bands (patch=act, mitigate=escalate) -> Header zeigt das
    urgentste Band (ESCALATE)."""
    lanes = [
        _lane(fix_lane="patch", risk_band="act", drift=False),
        _lane(
            fix_lane="mitigate",
            risk_band="escalate",
            worst_id=300,
            identifier_key="CVE-2026-43304",
            drift=False,
        ),
    ]
    ctx = _make_context(lanes=lanes)
    html = _render_card(app, ctx)
    match = re.search(r'data-test="group-band-badge"[^>]*>([^<]*)<', html)
    assert match is not None, f"Header-Band-Badge fehlt:\n{html}"
    assert match.group(1).strip() == "ESCALATE", (
        f"Header muss das Max-Band (escalate) ueber die Lanes zeigen:\n{html}"
    )


def test_mixed_group_renders_two_lane_blocks(app: Flask) -> None:
    """Gemischte Group: zwei Lane-Assessment-Blocks (patch + no patch) mit je
    eigener Reason und eigenem Worst."""
    lanes = [
        _lane(
            fix_lane="patch",
            risk_band="act",
            risk_band_reason="patch available, normal cycle",
            worst_id=201,
            identifier_key="CVE-2026-31431",
            drift=False,
        ),
        _lane(
            fix_lane="mitigate",
            risk_band="escalate",
            risk_band_reason="no fix, public exposure",
            worst_id=302,
            identifier_key="CVE-2026-43304",
            drift=False,
        ),
    ]
    ctx = _make_context(lanes=lanes)
    html = _render_card(app, ctx)

    # Beide Lane-Container.
    assert f'data-test="group-lane-{_GROUP_ID}-patch"' in html
    assert f'data-test="group-lane-{_GROUP_ID}-mitigate"' in html
    # Lane-Labels.
    assert "Patch" in html
    assert "No patch" in html
    # Per-Lane-Reason.
    assert "patch available, normal cycle" in html
    assert "no fix, public exposure" in html
    # Per-Lane-Band-Badges.
    assert f'data-test="group-lane-band-{_GROUP_ID}-patch"' in html
    assert f'data-test="group-lane-band-{_GROUP_ID}-mitigate"' in html
    # Per-Lane-Worst.
    assert "CVE-2026-31431" in html
    assert "CVE-2026-43304" in html


def test_pure_patch_group_renders_single_lane_block(app: Flask) -> None:
    """Reine patch-Group: nur ein Lane-Block, keine mitigate-Lane."""
    ctx = _make_context(lanes=[_lane(fix_lane="patch", drift=False)])
    html = _render_card(app, ctx)
    assert f'data-test="group-lane-{_GROUP_ID}-patch"' in html
    assert f'data-test="group-lane-{_GROUP_ID}-mitigate"' not in html


# ---------------------------------------------------------------------------
# XSS — kein |safe auf LLM-/Scanner-Daten
# ---------------------------------------------------------------------------


def test_risk_band_reason_xss_payload_is_escaped(app: Flask) -> None:
    """risk_band_reason ist LLM-Output — Autoescape muss greifen."""
    payload = '<script>alert(1)</script><img src=x onerror="alert(2)">'
    ctx = _make_context(lanes=[_lane(risk_band_reason=payload, drift=True)])
    html = _render_card(app, ctx)

    assert "<script>alert(1)</script>" not in html, f"XSS-Payload UNESCAPED im HTML:\n{html}"
    assert "<img src=x" not in html, f"img/onerror-Payload UNESCAPED im HTML:\n{html}"
    assert "&lt;script&gt;" in html, f"Escaped-Variante fehlt — Autoescape kaputt:\n{html}"


def test_worst_finding_package_name_xss_payload_is_escaped(app: Flask) -> None:
    """package_name kommt aus Trivy/Agent-Input — ebenfalls escaped."""
    payload = "</span><script>alert(3)</script>"
    ctx = _make_context(lanes=[_lane(package_name=payload, drift=False)])
    html = _render_card(app, ctx)

    assert "<script>alert(3)</script>" not in html, f"XSS-Payload UNESCAPED im HTML:\n{html}"
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in html, (
        f"Escaped-Variante fehlt — Autoescape kaputt:\n{html}"
    )
