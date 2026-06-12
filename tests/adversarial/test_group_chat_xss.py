"""Adversarial-XSS-Tests fuer den Per-Group-AI-Chat (ADR-0055, Block AE).

Die Message-Bubble rendert ``message.content`` ausschliesslich autoescaped
(kein ``|safe``). LLM-/User-Content darf niemals als rohes HTML in den
DOM-Sink gelangen — Jinja-Autoescape ist die Server-seitige Defense, der
Stream-Pfad im JS nutzt ``textContent`` (siehe ``group_chat.js``).

Ergaenzend: Reason/Worst in der Chat-Context-Line werden ebenfalls escaped.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from flask import Flask

from app.forms import CSRFOnlyForm
from app.models import ChatMessageRole
from app.services.group_chat_prompt import CHAT_SUGGESTIONS

_BUBBLE_TPL = "servers/_partials/group_chat_message.html"
_VIEW_TPL = "servers/group_chat.html"

_XSS_PAYLOADS = [
    "<script>alert('x')</script>",
    '"><img src=x onerror="alert(1)">',
    "<svg/onload=alert(1)>",
    "</div><script>steal()</script>",
]


def _render_bubble(app: Flask, content: str) -> str:
    message = SimpleNamespace(id=1, role=ChatMessageRole.ASSISTANT, content=content)
    with app.test_request_context("/servers/1/groups/1/chat"):
        return app.jinja_env.get_template(_BUBBLE_TPL).render(
            message=message,
            stream_url="/servers/1/groups/1/chat/stream",
        )


def _render_view(app: Flask, **over: Any) -> str:
    ctx: dict[str, Any] = {
        "server": SimpleNamespace(id=1, name="host-01"),
        "sid": 1,
        "gid": 1,
        "group_label": "openssl",
        "lane": "patch",
        "worst_finding": SimpleNamespace(identifier_key="CVE-2024-0001", title="t"),
        "reason": "ok",
        "messages": [],
        "suggestions": CHAT_SUGGESTIONS,
        "conversation": None,
        "hx_partial": True,
    }
    ctx.update(over)
    with app.test_request_context("/servers/1/groups/1/chat"):
        ctx.setdefault("csrf_form", CSRFOnlyForm())
        return app.jinja_env.get_template(_VIEW_TPL).render(**ctx)


def test_message_content_is_autoescaped(app: Flask) -> None:
    for payload in _XSS_PAYLOADS:
        html = _render_bubble(app, payload)
        assert "<script>" not in html
        assert "<img src=x onerror=" not in html
        assert "<svg/onload=" not in html
        # Escapte Variante muss vorhanden sein (Content wurde gerendert).
        assert "&lt;" in html


def test_user_message_content_autoescaped(app: Flask) -> None:
    message = SimpleNamespace(id=2, role=ChatMessageRole.USER, content="<script>evil()</script>")
    with app.test_request_context("/servers/1/groups/1/chat"):
        html = app.jinja_env.get_template(_BUBBLE_TPL).render(message=message, stream_url="")
    assert "<script>evil()</script>" not in html
    assert "&lt;script&gt;" in html


def test_reason_in_context_line_autoescaped(app: Flask) -> None:
    html = _render_view(app, reason="<script>alert('reason')</script>")
    assert "<script>alert('reason')</script>" not in html
    assert "&lt;script&gt;" in html


def test_group_label_autoescaped(app: Flask) -> None:
    html = _render_view(app, group_label='<img src=x onerror="alert(1)">')
    assert '<img src=x onerror="alert(1)">' not in html
    assert "&lt;img" in html


def test_worst_identifier_autoescaped(app: Flask) -> None:
    worst = SimpleNamespace(identifier_key="<script>x</script>", title="t")
    html = _render_view(app, worst_finding=worst)
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html
