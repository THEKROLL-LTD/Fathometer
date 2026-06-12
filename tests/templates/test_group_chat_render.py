"""Pure-Unit-Template-Tests fuer den Per-Group-AI-Chat (ADR-0055, Block AE).

Deckt ab:
  - Empty-State rendert die CHAT_SUGGESTIONS-Chips (single-source).
  - Help-Button-Praesenz + hx-get/hx-target/hx-push-url in der Workflow-Table.
  - Single-Source-Drift: Initial-Render-Bubble == POST-Response-Bubble
    (gleiche IDs/Klassen-Set/data-*-Keys ueber beide Render-Pfade).
  - Kein `|safe` auf message.content / reason / worst (Source-Level).

Reine Template-Render-Tests (kein DB/HTTP) via `app.jinja_env`.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from flask import Flask

from app.forms import CSRFOnlyForm
from app.models import ChatMessageRole
from app.services.group_chat_prompt import CHAT_SUGGESTIONS

_TPL_DIR = Path(__file__).parent.parent.parent / "app" / "templates"
_BUBBLE_TPL = "servers/_partials/group_chat_message.html"
_VIEW_TPL = "servers/group_chat.html"
_WF_TPL = "servers/_action_needed_section.html"


def _msg(mid: int, role: ChatMessageRole, content: str) -> SimpleNamespace:
    return SimpleNamespace(id=mid, role=role, content=content)


def _worst() -> SimpleNamespace:
    return SimpleNamespace(identifier_key="CVE-2024-9999", title="Boom")


def _render_view(app: Flask, **over: Any) -> str:
    ctx: dict[str, Any] = {
        "server": SimpleNamespace(id=7, name="db-prod-01"),
        "sid": 7,
        "gid": 3,
        "group_label": "openssl",
        "lane": "patch",
        "worst_finding": _worst(),
        "reason": "Reachable service with a KEV-listed flaw.",
        "messages": [],
        "suggestions": CHAT_SUGGESTIONS,
        "conversation": None,
        "hx_partial": True,
        "findings_total": 4,
        "findings_shown": 4,
        "findings_truncated": False,
    }
    ctx.update(over)
    with app.test_request_context("/servers/7/groups/3/chat"):
        ctx.setdefault("csrf_form", CSRFOnlyForm())
        return app.jinja_env.get_template(_VIEW_TPL).render(**ctx)


def _render_bubble(app: Flask, message: SimpleNamespace) -> str:
    with app.test_request_context("/servers/7/groups/3/chat"):
        return app.jinja_env.get_template(_BUBBLE_TPL).render(
            message=message,
            stream_url="/servers/7/groups/3/chat/stream",
        )


def _render_workflow(app: Flask) -> str:
    group = SimpleNamespace(id=3, label="openssl")
    evaluation = SimpleNamespace(risk_band_reason="High EPSS on an exposed listener.")
    entry = {
        "group": group,
        "fix_lane": "patch",
        "evaluation": evaluation,
        "count": 4,
        "worst_finding": _worst(),
        "worst_finding_drift": False,
    }
    card = {
        "id": "escalate-distro",
        "label": "ESCALATE · Patch now",
        "variant": "escalate-distro",
        "count": 1,
        "groups": [entry],
    }
    with app.test_request_context("/servers/7"):
        return app.jinja_env.get_template(_WF_TPL).render(
            action_sections=[card],
            server=SimpleNamespace(id=7, name="db-prod-01"),
        )


# ── Empty-State + Suggestions ──────────────────────────────────────────────


def test_empty_state_renders_suggestion_chips(app: Flask) -> None:
    html = _render_view(app, messages=[])
    assert 'data-test="group-chat-empty"' in html
    for s in CHAT_SUGGESTIONS:
        # Label ist der sichtbare Chip-Text; der Prompt steckt im data-prompt-Attr.
        assert s.label in html
    # Der entkoppelte Prompt wird via data-prompt ausgeliefert (Substring ohne
    # HTML-escapebare Zeichen, da Jinja Apostrophe/Anfuehrungszeichen escaped).
    assert "data-prompt=" in html
    assert "concrete attack path" in html
    # Genau so viele Chips wie Suggestions.
    assert html.count('data-test="group-chat-chip"') == len(CHAT_SUGGESTIONS)


def test_chat_suggestions_is_the_known_constant() -> None:
    assert [s.label for s in CHAT_SUGGESTIONS] == ["Explain attack vector"]


def test_empty_state_hidden_when_messages_present(app: Flask) -> None:
    html = _render_view(app, messages=[_msg(1, ChatMessageRole.USER, "hi")])
    # Empty-State-Block vorhanden, aber initial display:none.
    assert 'data-test="group-chat-empty"' in html
    assert 'style="display: none;"' in html


# ── Findings-Budget-Hinweis (ADR-0058) ─────────────────────────────────────


def test_notice_shown_when_findings_truncated(app: Flask) -> None:
    html = _render_view(app, findings_truncated=True, findings_shown=15, findings_total=745)
    assert 'data-test="group-chat-notice"' in html
    assert 'class="sd-chat-notice"' in html
    assert 'role="note"' in html
    # Konkrete Zahlen sichtbar (X wichtigste von N).
    assert "15" in html
    assert "745" in html
    # Restzahl ausgerechnet (N - X).
    assert "730" in html


def test_notice_hidden_when_not_truncated(app: Flask) -> None:
    html = _render_view(app, findings_truncated=False, findings_shown=4, findings_total=4)
    assert 'data-test="group-chat-notice"' not in html


def test_notice_sits_outside_messages_container(app: Flask) -> None:
    """Der Hinweis steht VOR dem Messages-Container, damit „New Chat" (JS leert
    nur ``x-ref=messages``) ihn nicht mit entfernt."""
    html = _render_view(app, findings_truncated=True, findings_shown=15, findings_total=745)
    assert html.index('data-test="group-chat-notice"') < html.index(
        'data-test="group-chat-messages"'
    )


# ── Help-Button in der Workflow-Table ──────────────────────────────────────


def test_workflow_table_has_ask_header_and_button(app: Flask) -> None:
    html = _render_workflow(app)
    assert 'class="workflow-table__ask"' in html
    assert 'class="sd-ask-btn"' in html
    assert ">Help<" in html


def test_help_button_hx_attributes(app: Flask) -> None:
    html = _render_workflow(app)
    expected_url = "/servers/7/groups/3/chat"
    assert f'hx-get="{expected_url}"' in html
    assert 'hx-target="#detail-pane"' in html
    assert 'hx-push-url="true"' in html
    # Genau ein Help-Button pro Group-Row.
    assert html.count('data-test="action-card-escalate-distro-ask"') == 1
    assert html.count('class="sd-ask-btn"') == 1


# ── Single-Source-Drift: Initial-Render == POST-Response-Bubble ────────────


def _struct(html: str) -> dict[str, Any]:
    """Strukturelle Signatur einer gerenderten Bubble: alle class-Sets, IDs und
    data-*-Keys — vergleichbar ueber beide Render-Pfade."""
    classes = sorted(re.findall(r'class="([^"]*)"', html))
    ids = sorted(re.findall(r'id="([^"]*)"', html))
    data_keys = sorted(set(re.findall(r"(data-[a-z-]+)=", html)))
    return {"classes": classes, "ids": ids, "data_keys": data_keys}


def test_bubble_single_source_no_drift(app: Flask) -> None:
    """Dieselbe Fixture-Message ueber den Initial-Render (Thread-Schleife im
    View) UND den POST-Response-Pfad (Partial direkt) muss strukturell
    identisches Markup liefern."""
    msg = _msg(42, ChatMessageRole.USER, "How bad is it?")

    # Pfad A: POST-Response rendert das Partial direkt.
    bubble_post = _render_bubble(app, msg)

    # Pfad B: Initial-Render via View-Thread-Schleife -> Bubble herausschneiden.
    view = _render_view(app, messages=[msg])
    start = view.index('<div class="sd-msg ')
    end = view.index("</div>", view.index("data-msg-bubble", start)) + len("</div>")
    # Wrapper-</div> nach dem Bubble-</div>.
    end = view.index("</div>", end) + len("</div>")
    bubble_view = view[start:end]

    assert _struct(bubble_post) == _struct(bubble_view), (
        "Bubble-Markup driftet zwischen POST-Response und Initial-Render"
    )
    # Stabile ID-Konvention + data-Keys vorhanden.
    assert 'id="chat-msg-42"' in bubble_post
    assert "data-msg-bubble" in bubble_post
    assert 'data-msg-role="user"' in bubble_post


def test_user_bubble_partial_uses_real_template_path(app: Flask) -> None:
    """Regression (Browser-Smoke 2026-06-11, POST 500 TemplateNotFound):
    der echte ``_user_bubble_partial`` im Blueprint muss den vollen Pfad
    ``servers/_partials/group_chat_message.html`` rendern. Der Drift-Test
    rendert das Partial direkt ueber die korrekte Konstante und der API-Test
    stubt ``_user_bubble_partial`` weg — beide verdeckten ein fehlendes
    ``servers/``-Praefix im ``render_template``-Aufruf. Dieser Test ruft die
    echte Funktion und faengt TemplateNotFound."""
    from app.api.group_chat import _user_bubble_partial

    msg = _msg(42, ChatMessageRole.USER, "explain attack vector")
    with app.test_request_context("/servers/7/groups/3/chat/messages"):
        # Wuerde TemplateNotFound werfen, wenn der Pfad das `servers/`-Praefix
        # verliert — genau der Browser-Smoke-Bug. `stream_url` landet bewusst
        # NICHT im Markup (das JS liest es aus der JSON-Response), daher hier
        # nur die Bubble-Struktur pruefen.
        html = _user_bubble_partial(msg, 7, 3)

    assert 'id="chat-msg-42"' in html
    assert 'data-msg-role="user"' in html
    assert "explain attack vector" in html


def test_assistant_bubble_has_ai_tag(app: Flask) -> None:
    html = _render_bubble(app, _msg(9, ChatMessageRole.ASSISTANT, "It is reachable."))
    assert 'class="sd-msg__tag"' in html
    assert ">AI<" in html
    assert 'data-msg-role="assistant"' in html


# ── Kein |safe (Source-Level) ──────────────────────────────────────────────


def test_no_unsafe_filter_in_templates() -> None:
    # Jinja-Kommentare `{# ... #}` strippen — die dokumentieren die |safe-Regel
    # bewusst und sind kein Filter-Aufruf.
    comment_re = re.compile(r"\{#.*?#\}", re.DOTALL)
    for rel in (_BUBBLE_TPL, _VIEW_TPL):
        src = comment_re.sub("", (_TPL_DIR / rel).read_text(encoding="utf-8"))
        assert "|safe" not in src.replace(" ", ""), f"{rel} verwendet |safe"
