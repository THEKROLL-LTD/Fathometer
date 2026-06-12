"""Pure-Unit Smoke-Tests: alle 7 Settings-Subseiten rendern auf der s-*-Schicht.

Block AD / ADR-0047. Pro Subseite:
  - das Content-Only-Template (kein extends) rendert ohne Crash mit Mock-Kontext,
  - mindestens ein `s-*`-/`settings-*`-Schicht-Indikator ist vorhanden,
  - keine bare DaisyUI-Komponenten-Klasse (`card`/`btn`/`badge`/`alert`/`menu`/
    `modal`/`tabs`/`tab-active`/`input-bordered`/`select-bordered`/`form-control`/
    `range`/`checkbox`/`dropdown`/`loading`/`table-zebra`) als Class-Token.

Render-Strategie wie die uebrigen Settings-Template-Tests: direkt via
`flask.render_template` im App-Context, Mock-Kontext deckt nur was das Template
braucht. Kein DB-Zugriff, keine db_integration.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from flask import Flask, render_template

# DaisyUI-Komponenten-Klassen, die in den Settings-Surfaces nicht mehr
# vorkommen duerfen. Bewusst NICHT enthalten: `label` (die s-key-status-Schicht
# nutzt eine eigene gescopte `.s-key-status__row .label`-Regel aus der
# Mockup-CSS — kein DaisyUI).
_DAISY_TOKENS = {
    "card",
    "card-body",
    "card-title",
    "card-actions",
    "btn",
    "btn-ghost",
    "btn-primary",
    "btn-warning",
    "btn-sm",
    "btn-error",
    "badge",
    "badge-sm",
    "badge-xs",
    "badge-outline",
    "badge-success",
    "badge-error",
    "badge-warning",
    "badge-neutral",
    "alert",
    "alert-info",
    "alert-success",
    "alert-error",
    "alert-warning",
    "menu",
    "menu-sm",
    "menu-active",
    "modal",
    "modal-box",
    "modal-backdrop",
    "modal-action",
    "modal-open",
    "tabs",
    "tabs-bordered",
    "tab",
    "tab-active",
    "input",
    "input-bordered",
    "select",
    "select-bordered",
    "range",
    "range-warning",
    "range-sm",
    "checkbox",
    "checkbox-sm",
    "dropdown",
    "dropdown-end",
    "dropdown-content",
    "loading",
    "loading-spinner",
    "loading-xs",
    "form-control",
    "label-text",
    "label-text-alt",
    "table",
    "table-zebra",
    "table-sm",
    "table-xs",
    "w-56",
    "rounded-box",
}


def _daisy_tokens(html: str) -> list[str]:
    found: list[str] = []
    for m in re.finditer(r'class="([^"]*)"', html):
        for tok in m.group(1).split():
            if tok in _DAISY_TOKENS:
                found.append(tok)
    return found


def _csrf_form() -> SimpleNamespace:
    """CSRF-Only-Form-Stub: csrf_token rendert ein Hidden-Input."""

    class _Field:
        def __html__(self) -> str:
            return '<input type="hidden" name="csrf_token" value="t">'

    return SimpleNamespace(csrf_token=_Field())


# ---------------------------------------------------------------------------
# Kontext-Builder pro Subseite
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 6, 4, 12, 0, tzinfo=UTC)


def _ctx_servers() -> dict:
    srv = SimpleNamespace(
        id=1,
        name="rke2-sv-0",
        revoked_at=None,
        retired_at=None,
        last_scan_at=_NOW,
        expected_scan_interval_h=24,
        os_pretty_name="Ubuntu 22.04",
        kernel_version="5.15",
        architecture="aarch64",
        trivy_db_updated_at=_NOW,
        tag_links=[SimpleNamespace(tag=SimpleNamespace(name="prod", color="#00E5FF"))],
    )
    return {
        "servers": [srv],
        "revoke_form": _csrf_form(),
        "retire_form": _csrf_form(),
        "delete_findings_form": _csrf_form(),
        "delete_server_form": _csrf_form(),
    }


def _ctx_servers_revoked() -> dict:
    """Wie `_ctx_servers`, aber der Server ist revoked — exerziert den
    Delete-Server-Action-Zweig in `settings/servers.html`."""
    ctx = _ctx_servers()
    ctx["servers"][0].revoked_at = _NOW
    return ctx


def _ctx_tags() -> dict:
    from app.forms import CSRFOnlyForm, TagColorForm, TagRenameForm

    return {
        "tags": [SimpleNamespace(id=1, name="prod", color="#ff8800")],
        "rename_form": TagRenameForm(),
        "color_form": TagColorForm(),
        "delete_form": CSRFOnlyForm(),
    }


def _ctx_groups() -> dict:
    from app.forms import CSRFOnlyForm, GroupMoveForm, GroupRenameForm

    return {
        "groups": [{"id": 1, "name": "prod-eu", "position": 0, "member_count": 3}],
        "rename_form": GroupRenameForm(),
        "move_form": GroupMoveForm(),
        "delete_form": CSRFOnlyForm(),
    }


def _ctx_llm_provider() -> dict:
    from app.forms import LlmSettingsForm

    return {
        "form": LlmSettingsForm(),
        "has_existing_key": True,
        "presets": [
            {
                "name": "OpenAI",
                "base_url": "https://x",
                "reviewer_model": "gpt",
                "chat_model": "ds",
            }
        ],
    }


def _ctx_llm_reviewer() -> dict:
    from app.forms import (
        LlmReviewerConcurrencyForm,
        LlmReviewerModeForm,
        LlmReviewerRequeueForm,
    )

    grp = SimpleNamespace(label="tailscale", group_kind="application_bundle", last_used_at=_NOW)
    return {
        "current_mode": "live",
        "active_model": "deepseek",
        "current_concurrency": 10,
        "mode_form": LlmReviewerModeForm(),
        "requeue_form": LlmReviewerRequeueForm(),
        "concurrency_form": LlmReviewerConcurrencyForm(),
        "job_counts": {"queued": 0, "in_progress": 0, "done": 8, "failed": 1},
        "would_call_count": 3,
        "groups_total": 41,
        "top_groups": [grp],
        "cache_total": 136,
        "token_budget": {"used_today": 16000, "daily_limit": 2000000, "resets_at": _NOW},
        "heartbeat_at": _NOW,
        "heartbeat_age_s": 5.0,
        "heartbeat_healthy": True,
        "sub_tab": "overview",
    }


def _ctx_llm_debug_log() -> dict:
    entry = SimpleNamespace(
        id=7,
        model="deepseek-ai/DeepSeek-V3",
        group_id=3,
        status="success",
        response_body={"reasoning_field": "because"},
        request_body={"a": 1},
        error=None,
        created_at=_NOW,
        job_type="risk_eval",
        duration_ms=8400,
    )
    return {"debug_log_entries": [entry], "group_labels": {3: "trivy"}, "sub_tab": "debug_log"}


def _ctx_master_key() -> dict:
    return {"rotate_form": _csrf_form(), "last_rotated_at": _NOW, "new_master_key": "mk_test_1"}


def _ctx_about() -> dict:
    feed = SimpleNamespace(
        feed_name="epss",
        last_success_at=_NOW,
        last_success_row_count=335449,
        is_stale=False,
        last_attempt_status="success",
        last_attempt_at=None,
    )
    return {
        "about": {
            "app_version": "0.19.0",
            "build_revision": "dev",
            "alembic_revision": "0015",
            "python_version": "3.13",
            "flask_version": "3.1",
            "sqlalchemy_version": "2.0",
            "trivy_db_stale_count": 2,
            "healthz_url": "/healthz",
        },
        "feed_statuses": [feed],
    }


# template, active, needs-app-for-ctx, s-indicator
_PAGES = [
    ("settings/servers.html", "_ctx_servers", "s-servers__table"),
    ("settings/tags.html", "_ctx_tags", "s-tags__row"),
    ("settings/groups.html", "_ctx_groups", "s-groups__row"),
    ("settings/llm_provider.html", "_ctx_llm_provider", "s-card"),
    ("settings/llm_reviewer.html", "_ctx_llm_reviewer", "s-statusbar"),
    ("settings/llm_debug_log.html", "_ctx_llm_debug_log", "s-log"),
    ("settings/master_key.html", "_ctx_master_key", "s-key-status"),
    ("settings/about.html", "_ctx_about", "s-about-grid"),
]


def _render(app: Flask, template: str, builder: str) -> str:
    """Baut den Mock-Kontext UND rendert innerhalb desselben Request-Kontexts
    (WTForms-Instanziierung braucht den App-/Request-Kontext)."""
    with app.test_request_context("/settings"):
        ctx = globals()[builder]()
        return render_template(template, active="x", **ctx)


@pytest.mark.parametrize("template,builder,indicator", _PAGES)
def test_subpage_renders_with_s_layer(
    app: Flask, template: str, builder: str, indicator: str
) -> None:
    html = _render(app, template, builder)
    assert html and len(html) > 0
    assert indicator in html, f"{template}: s-Schicht-Indikator '{indicator}' fehlt"


@pytest.mark.parametrize("template,builder,indicator", _PAGES)
def test_subpage_has_no_daisyui(app: Flask, template: str, builder: str, indicator: str) -> None:
    html = _render(app, template, builder)
    leftovers = _daisy_tokens(html)
    assert not leftovers, f"{template}: DaisyUI-Rest {leftovers}"


def test_external_feeds_on_about_not_provider(app: Flask) -> None:
    """External-Feeds (EPSS/CISA-KEV) liegen jetzt auf About, nicht mehr auf
    LLM Provider (Block AD Folge-Fix)."""
    about_html = _render(app, "settings/about.html", "_ctx_about")
    assert "External feeds" in about_html
    assert "s-feeds" in about_html
    assert "EPSS" in about_html

    provider_html = _render(app, "settings/llm_provider.html", "_ctx_llm_provider")
    assert "External feeds" not in provider_html
    assert "s-feeds" not in provider_html


def test_revoked_server_offers_delete_action(app: Flask) -> None:
    """Ein revoked Server zeigt die 'Delete server'-Action; ein aktiver nicht."""
    revoked_html = _render(app, "settings/servers.html", "_ctx_servers_revoked")
    assert "Delete server" in revoked_html
    assert 'data-test="server-delete-1"' in revoked_html
    assert "/settings/servers/1/delete" in revoked_html

    active_html = _render(app, "settings/servers.html", "_ctx_servers")
    assert "Delete server" not in active_html
    assert "no actions" not in active_html  # aktiver Server hat das Actions-Menue


@pytest.mark.parametrize("template,builder,indicator", _PAGES)
def test_subpage_has_settings_header(
    app: Flask, template: str, builder: str, indicator: str
) -> None:
    """Jede Subseite traegt den Header-Pattern (eyebrow ohne Nummerierung + title)."""
    html = _render(app, template, builder)
    assert 'class="settings__eyebrow"' in html
    assert 'class="settings__title"' in html
    # Eyebrow-Nummerierung ("01 / 07") bewusst weggelassen (User-Entscheidung).
    assert "/ 07" not in html
