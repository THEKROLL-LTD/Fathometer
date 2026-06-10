"""Pure-Unit-Render-Tests fuer ``_partials/application_group_card.html`` —
TICKET-010 Etappe 3 (Live-Worst-Finding + Drift-Hint).

Persistiert die wichtigsten Render-Faelle des (inline gebliebenen)
Frontend-Smokes:

  1. Drift-Hint ``data-test="group-drift-hint"`` rendert bei
     ``worst_finding_drift=True`` mit exakt "re-evaluation pending"
     (ADR-0052 Entscheidung 2, ADR-0045 englisch).
  2. Kein Hint bei ``worst_finding_drift=False`` und bei fehlendem
     Context-Key (Jinja-Undefined ist falsy — Legacy-Caller brechen nicht).
  3. Reason-Block rendert auch wenn ``risk_band_reason`` leer ist, solange
     Drift gemeldet wird (Gate: ``evaluation and (reason or drift)``).
  4. Worst-Finding-Block ist allein durch ``worst_finding`` gegated —
     rendert auch ohne ``evaluation`` (frueher war der Eval-Snapshot die
     Render-Bedingung; das war Bug C).
  5. Kein Worst-Block bei ``worst_finding=None`` (Group driftet, Snapshot-
     Finding geschlossen).
  6. XSS: ``risk_band_reason`` und ``package_name`` (LLM-/Scanner-Daten)
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


# ---------------------------------------------------------------------------
# Render-Helper
# ---------------------------------------------------------------------------


def _make_context(
    *,
    evaluation: Any = ...,
    worst_finding: Any = ...,
    risk_band_reason: str | None = "kev present on openssh",
    package_name: str = "openssh-server",
) -> dict[str, Any]:
    """Default-Context: bewertete Group mit Live-Worst-Finding."""
    if evaluation is ...:
        evaluation = SimpleNamespace(
            risk_band="escalate",
            risk_band_reason=risk_band_reason,
        )
    if worst_finding is ...:
        worst_finding = SimpleNamespace(
            id=200,
            identifier_key="CVE-2026-31431",
            package_name=package_name,
        )
    return {
        "group": SimpleNamespace(id=7, label="openssh", group_kind="os_package", explanation=None),
        "evaluation": evaluation,
        "count": 3,
        "worst_finding": worst_finding,
        "server": SimpleNamespace(id=42),
    }


def _render_card(app: Flask, ctx: dict[str, Any]) -> str:
    """Rendert das echte Partial ueber den App-Jinja-Loader (url_for noetig)."""
    with app.test_request_context("/servers/42"):
        return render_template("_partials/application_group_card.html", **ctx)


def _hint_text(html: str) -> str | None:
    """Extrahiert den Inner-Text des Drift-Hint-Spans (None wenn abwesend)."""
    match = re.search(r'data-test="group-drift-hint"[^>]*>([^<]*)<', html)
    if match is None:
        return None
    return match.group(1).strip()


# ---------------------------------------------------------------------------
# Drift-Hint
# ---------------------------------------------------------------------------


def test_drift_hint_renders_with_exact_wording(app: Flask) -> None:
    """worst_finding_drift=True -> Hint-Span mit exakt 're-evaluation pending'."""
    ctx = _make_context()
    ctx["worst_finding_drift"] = True
    html = _render_card(app, ctx)

    assert 'data-test="group-drift-hint"' in html, f"Drift-Hint fehlt im HTML:\n{html}"
    assert _hint_text(html) == _HINT_WORDING, (
        f"Hint-Wording muss exakt {_HINT_WORDING!r} sein (ADR-0052 Entscheidung 2), "
        f"gerendert: {_hint_text(html)!r}"
    )


def test_no_drift_hint_when_drift_false(app: Flask) -> None:
    ctx = _make_context()
    ctx["worst_finding_drift"] = False
    html = _render_card(app, ctx)
    assert 'data-test="group-drift-hint"' not in html, (
        f"Hint darf bei drift=False nicht rendern:\n{html}"
    )
    # Reason rendert weiterhin normal.
    assert "kev present on openssh" in html


def test_no_drift_hint_when_context_key_missing(app: Flask) -> None:
    """Legacy-/Fremd-Caller ohne `worst_finding_drift`-Key: Jinja-Undefined
    ist falsy — kein Hint, kein Render-Fehler."""
    ctx = _make_context()
    assert "worst_finding_drift" not in ctx
    html = _render_card(app, ctx)
    assert 'data-test="group-drift-hint"' not in html


def test_drift_hint_renders_even_without_reason_text(app: Flask) -> None:
    """Gate ist `evaluation and (reason or drift)` — bei leerer Reason aber
    Drift rendert der Reason-Block nur mit dem Hint."""
    ctx = _make_context(risk_band_reason=None)
    ctx["worst_finding_drift"] = True
    html = _render_card(app, ctx)
    assert 'data-test="group-risk-reason"' in html, (
        f"Reason-Block muss bei Drift auch ohne Reason-Text rendern:\n{html}"
    )
    assert _hint_text(html) == _HINT_WORDING


def test_no_reason_block_without_evaluation_even_if_drift_flag_set(app: Flask) -> None:
    """Ohne Evaluation gibt es keinen AI-Assessment-Block — auch ein
    (inkonsistent) gesetztes Drift-Flag erzwingt keinen."""
    ctx = _make_context(evaluation=None)
    ctx["worst_finding_drift"] = True
    html = _render_card(app, ctx)
    assert 'data-test="group-risk-reason"' not in html
    assert 'data-test="group-drift-hint"' not in html


# ---------------------------------------------------------------------------
# Worst-Finding-Block-Gate (Bug-C-Regression)
# ---------------------------------------------------------------------------


def test_worst_block_renders_without_evaluation(app: Flask) -> None:
    """`{% if worst_finding %}` ist das einzige Gate — 'Nicht bewertet'-Groups
    zeigen ihr Live-Worst trotzdem (TICKET-010: Eval-Snapshot ist keine
    Render-Bedingung mehr)."""
    ctx = _make_context(evaluation=None)
    ctx["worst_finding_drift"] = False
    html = _render_card(app, ctx)
    assert 'data-test="group-worst-finding"' in html, (
        f"Worst-Block muss ohne Evaluation rendern:\n{html}"
    )
    assert "CVE-2026-31431" in html
    assert 'href="#finding-200"' in html, "Worst-Link muss auf die Live-Finding-ID zeigen"


def test_no_worst_block_when_live_worst_missing(app: Flask) -> None:
    """worst_finding=None (z. B. Snapshot-Finding geschlossen, kein offenes
    mehr im Batch) -> kein Worst-Block, Rest der Card rendert."""
    ctx = _make_context(worst_finding=None)
    ctx["worst_finding_drift"] = True
    html = _render_card(app, ctx)
    assert 'data-test="group-worst-finding"' not in html
    assert 'data-test="group-card-7"' in html
    assert _hint_text(html) == _HINT_WORDING


# ---------------------------------------------------------------------------
# XSS — kein |safe auf LLM-/Scanner-Daten
# ---------------------------------------------------------------------------


def test_risk_band_reason_xss_payload_is_escaped(app: Flask) -> None:
    """risk_band_reason ist LLM-Output — Autoescape muss greifen."""
    payload = '<script>alert(1)</script><img src=x onerror="alert(2)">'
    ctx = _make_context(risk_band_reason=payload)
    ctx["worst_finding_drift"] = True
    html = _render_card(app, ctx)

    assert "<script>alert(1)</script>" not in html, f"XSS-Payload UNESCAPED im HTML:\n{html}"
    assert "<img src=x" not in html, f"img/onerror-Payload UNESCAPED im HTML:\n{html}"
    assert "&lt;script&gt;" in html, f"Escaped-Variante fehlt — Autoescape kaputt:\n{html}"


def test_worst_finding_package_name_xss_payload_is_escaped(app: Flask) -> None:
    """package_name kommt aus Trivy/Agent-Input — ebenfalls escaped."""
    payload = "</span><script>alert(3)</script>"
    ctx = _make_context(package_name=payload)
    ctx["worst_finding_drift"] = False
    html = _render_card(app, ctx)

    assert "<script>alert(3)</script>" not in html, f"XSS-Payload UNESCAPED im HTML:\n{html}"
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in html, (
        f"Escaped-Variante fehlt — Autoescape kaputt:\n{html}"
    )
