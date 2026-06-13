"""Pure-Unit-Render-Tests fuer ``servers/_partials/upstream_check_panel.html``
(Block AI-2, ADR-0063, P2).

Single-Source-Partial fuer Initial-Render + POST-enqueue + GET-poll (HTMX-OOB-
Single-Source-Pattern, CLAUDE.md). Geprueft:

  * Drift/Poll: ueber alle States rendern; Panel-ID
    ``upstream-check-<sid>-<gid>-panel`` immer vorhanden; das HTMX-Poll-Attribut
    (``hx-get`` auf ``upstream_check.poll`` + ``hx-trigger``) NUR im
    ``running``-State, sonst abwesend.
  * XSS: UNTRUSTED Web-/LLM-Felder (``operator_action``/``reasoning``/
    ``fixed_build_release``) werden escaped (kein ``|safe``-Leak).
    ``sources_used`` mit ``javascript:``/``data:``/relativer URL -> KEIN
    ``href="javascript:``/``href="data:`` (als Text); ``https://`` -> echter
    ``<a href>``.
  * „candidate · verify"-Label in den Verdict-States vorhanden.

DB-frei: das Partial wird via ``render_template`` mit SimpleNamespace-Stubs
gerendert (analog ``tests/templates/test_application_group_card_drift.py``).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from flask import Flask, render_template

_TEMPLATE = "servers/_partials/upstream_check_panel.html"
_SID = 7
_GID = 3
_PANEL_ID = f"upstream-check-{_SID}-{_GID}-panel"


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
        "checked_at": datetime(2026, 6, 10, tzinfo=UTC),
    }
    base.update(over)
    return SimpleNamespace(**base)


def _seed() -> SimpleNamespace:
    return SimpleNamespace(
        artifact_module="tailscaled",
        installed_component_version="v1.26.1",
        vulnerable_component="stdlib",
        fixing_component_version="1.26.2",
        cve="CVE-2026-0001",
    )


def _render(
    app: Flask,
    *,
    state: str,
    row: SimpleNamespace | None,
    seed: SimpleNamespace | None,
    is_fresh: bool = False,
    checked_age: timedelta | None = None,
) -> str:
    from app.forms import CSRFOnlyForm

    app.config.update(WTF_CSRF_ENABLED=False)
    with app.test_request_context(f"/servers/{_SID}"):
        return render_template(
            _TEMPLATE,
            state=state,
            row=row,
            seed=seed,
            checked_age=checked_age,
            is_fresh=is_fresh,
            sid=_SID,
            gid=_GID,
            csrf_form=CSRFOnlyForm(),
        )


# ---------------------------------------------------------------------------
# Drift / Poll-Attribut
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["disabled", "idle", "running", "done", "cached"])
def test_panel_id_present_in_every_state(app: Flask, state: str) -> None:
    row = _row() if state in {"done", "cached"} else None
    seed = None if state == "disabled" else _seed()
    html = _render(app, state=state, row=row, seed=seed, is_fresh=(state == "cached"))
    assert f'id="{_PANEL_ID}"' in html, f"Panel-ID fehlt im State {state!r}:\n{html}"
    assert f'data-state="{state}"' in html


def test_poll_attribute_only_in_running_state(app: Flask) -> None:
    html = _render(app, state="running", row=None, seed=_seed())
    assert "hx-get=" in html, f"running muss das Poll-Attribut tragen:\n{html}"
    assert "hx-trigger=" in html
    # Ziel ist der GET-Poll-Endpoint.
    assert f"/servers/{_SID}/groups/{_GID}/upstream-check" in html


@pytest.mark.parametrize("state", ["disabled", "idle", "done", "cached"])
def test_poll_attribute_absent_outside_running(app: Flask, state: str) -> None:
    row = _row() if state in {"done", "cached"} else None
    seed = None if state == "disabled" else _seed()
    html = _render(app, state=state, row=row, seed=seed, is_fresh=(state == "cached"))
    # Das Selbst-Poll-Attribut darf NUR im running-State auf dem Panel sitzen.
    assert "hx-trigger=" not in html, (
        f"hx-trigger darf im State {state!r} nicht vorhanden sein (Poll-Selbststopp):\n{html}"
    )


def test_disabled_links_to_settings(app: Flask) -> None:
    html = _render(app, state="disabled", row=None, seed=None)
    assert 'data-test="upstream-check-disabled"' in html
    assert "Upstream update search is off." in html


def test_idle_renders_start_button(app: Flask) -> None:
    html = _render(app, state="idle", row=None, seed=_seed())
    assert 'data-test="upstream-check-start"' in html
    assert "hx-post=" in html


# ---------------------------------------------------------------------------
# candidate · verify Label
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "is_fresh"),
    [("done", False), ("cached", True)],
)
def test_candidate_verify_label_in_verdict_states(app: Flask, state: str, is_fresh: bool) -> None:
    html = _render(app, state=state, row=_row(), seed=_seed(), is_fresh=is_fresh)
    assert "candidate · verify" in html, f"candidate-Label fehlt im State {state!r}:\n{html}"


def test_cached_shows_checked_age(app: Flask) -> None:
    html = _render(app, state="cached", row=_row(), seed=_seed(), is_fresh=True)
    assert 'data-test="upstream-check-age"' in html


def test_none_yet_verdict_renders(app: Flask) -> None:
    row = _row(delivery="none_yet", fixed_build_release=None)
    html = _render(app, state="done", row=row, seed=_seed())
    assert 'data-verdict="none_yet"' in html
    assert "No fixed release yet" in html


def test_error_verdict_renders(app: Flask) -> None:
    row = _row(delivery=None, error="no sources found")
    html = _render(app, state="done", row=row, seed=_seed())
    assert 'data-verdict="error"' in html
    assert "Couldn't determine" in html


# ---------------------------------------------------------------------------
# XSS — kein |safe auf UNTRUSTED Web-/LLM-Feldern
# ---------------------------------------------------------------------------


def test_operator_action_xss_escaped(app: Flask) -> None:
    payload = '<script>alert(1)</script><img src=x onerror="alert(2)">'
    row = _row(operator_action=payload)
    html = _render(app, state="done", row=row, seed=_seed())
    assert "<script>alert(1)</script>" not in html, f"operator_action UNESCAPED:\n{html}"
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html


def test_fixed_build_release_xss_escaped(app: Flask) -> None:
    payload = "</span><script>alert(3)</script>"
    row = _row(fixed_build_release=payload)
    html = _render(app, state="cached", row=row, seed=_seed(), is_fresh=True)
    assert "<script>alert(3)</script>" not in html, f"fixed_build_release UNESCAPED:\n{html}"
    assert "&lt;script&gt;" in html


def test_reasoning_and_latest_version_xss_escaped(app: Flask) -> None:
    payload = '<img src=x onerror="alert(9)">'
    row = _row(
        delivery="none_yet",
        fixed_build_release=None,
        latest_release_component_version=payload,
        reasoning=payload,
    )
    html = _render(app, state="done", row=row, seed=_seed())
    assert "<img src=x" not in html, f"untrusted version/reasoning UNESCAPED:\n{html}"


def test_sources_javascript_scheme_not_rendered_as_href(app: Flask) -> None:
    row = _row(sources_used=["javascript:alert(1)"])
    html = _render(app, state="done", row=row, seed=_seed())
    assert 'href="javascript:' not in html, f"javascript:-URL als href geleakt:\n{html}"
    # Als Text gerendert (Span), nicht als Link.
    assert 'data-test="upstream-check-sources"' in html


def test_sources_data_scheme_not_rendered_as_href(app: Flask) -> None:
    row = _row(sources_used=["data:text/html,<script>alert(1)</script>"])
    html = _render(app, state="done", row=row, seed=_seed())
    assert 'href="data:' not in html, f"data:-URL als href geleakt:\n{html}"
    assert "<script>alert(1)</script>" not in html, "data:-Payload UNESCAPED"


def test_sources_relative_url_not_rendered_as_href(app: Flask) -> None:
    row = _row(sources_used=["/etc/passwd"])
    html = _render(app, state="done", row=row, seed=_seed())
    assert 'href="/etc/passwd"' not in html, f"relative URL als href geleakt:\n{html}"


def test_sources_https_url_rendered_as_real_link(app: Flask) -> None:
    url = "https://tailscale.com/security/ts-2026-001"
    row = _row(sources_used=[url])
    html = _render(app, state="done", row=row, seed=_seed())
    assert f'href="{url}"' in html, f"https-URL muss ein echter <a href> sein:\n{html}"
    assert 'rel="noopener noreferrer"' in html
    assert 'target="_blank"' in html


def test_sources_http_url_rendered_as_real_link(app: Flask) -> None:
    url = "http://internal.example/advisory"
    row = _row(sources_used=[url])
    html = _render(app, state="done", row=row, seed=_seed())
    assert f'href="{url}"' in html, f"http-URL muss ein echter <a href> sein:\n{html}"
