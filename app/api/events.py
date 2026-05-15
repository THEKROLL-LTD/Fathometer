"""`GET /events` — Server-Sent-Events-Stream fuer Dashboard-Live-Updates.

ARCHITECTURE.md §6 ("Im MVP genuegt ein einfacher in-process Dispatcher")
und §7 ("Das Dashboard reagiert per SSE auf neue Scans und animiert
das Update der betroffenen Karte").

Design:

- Login-Required (Session-Auth, kein Bearer-Token — der Stream ist
  Browser-facing).
- `Content-Type: text/event-stream`, `Cache-Control: no-cache`,
  `X-Accel-Buffering: no` (nginx soll nicht puffern).
- Subscribe an den App-Singleton-`EventBus`. Pro empfangenem Event ein
  `data: <json>\\n\\n` Frame mit `event: <type>` davor.
- Heartbeat alle 30 Sekunden in Form einer SSE-Kommentar-Zeile
  (`: heartbeat\\n\\n`), damit Reverse-Proxies mit Idle-Timeout die
  Verbindung nicht schliessen.
- Generator-Close (Browser-Disconnect) raeumt die Subscription auf.

Kein Rate-Limit — eine Connection pro Tab ist die natuerliche
Obergrenze, der Limiter wuerde den Tab beim Reconnect grundlos
ausbremsen.
"""

from __future__ import annotations

import json
import queue
from collections.abc import Iterator
from typing import Any

import structlog
from flask import Blueprint, Response, current_app, stream_with_context
from flask_login import login_required

from app import csrf
from app.services.event_bus import EventBus, get_event_bus

log = structlog.get_logger(__name__)

events_bp = Blueprint("events", __name__)


# Heartbeat-Intervall in Sekunden. 30s ist konservativ unter dem
# typischen 60s-Idle-Timeout vieler Reverse-Proxies (nginx Default 60s,
# Cloudflare 100s).
_HEARTBEAT_SECONDS = 30.0


def _sse_event(event_type: str, payload: dict[str, Any]) -> bytes:
    """Formatiert ein SSE-Event als `event: ... \\n data: ... \\n\\n`."""
    data = json.dumps(payload, default=str)
    out = f"event: {event_type}\n"
    # `data:` darf keine eingebetteten Newlines haben — JSON-encode dump
    # nimmt das von Haus aus weg, aber wir splitten defensiv.
    for line in data.splitlines() or [""]:
        out += f"data: {line}\n"
    out += "\n"
    return out.encode("utf-8")


def _sse_heartbeat() -> bytes:
    """SSE-Kommentar-Zeile als Heartbeat (Client ignoriert den Inhalt)."""
    return b": heartbeat\n\n"


def _stream(bus: EventBus) -> Iterator[bytes]:
    """Subscriber-Loop fuer den SSE-Stream.

    Sendet zuerst ein `ready`-Event damit der Client weiss, dass der
    Stream offen ist (auch fuer Tests nuetzlich, ohne dass etwas
    published wurde).
    """
    subscription = bus.subscribe()
    try:
        # Initiales Ready-Event — gibt dem Client die Sicherheit dass
        # die SSE-Verbindung steht.
        yield _sse_event("ready", {"subscriber_count": bus.subscriber_count})
        while True:
            try:
                event = subscription.q.get(timeout=_HEARTBEAT_SECONDS)
            except queue.Empty:
                yield _sse_heartbeat()
                continue
            yield _sse_event(event.event_type, event.payload)
    except GeneratorExit:
        # Client-Disconnect — sauber abmelden.
        raise
    finally:
        bus.unsubscribe(subscription)


@events_bp.get("/events")
@login_required
def stream_events() -> Response:
    """SSE-Stream fuer Dashboard-Live-Updates."""
    bus = get_event_bus(current_app._get_current_object())  # type: ignore[attr-defined]
    resp = Response(
        stream_with_context(_stream(bus)),
        mimetype="text/event-stream",
    )
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    # `Connection: keep-alive` ist HTTP/1.1-Default, wir setzen es
    # explizit fuer Klarheit bei manuellen `curl -i`-Pruefungen.
    resp.headers["Connection"] = "keep-alive"
    return resp


# SSE ist GET-only, CSRF interessiert sich nicht fuer GETs — der
# `csrf.exempt(stream_events)` ist defensiv fuer den Fall dass jemand
# spaeter eine `POST /events`-Variante anbaut.
csrf.exempt(stream_events)


__all__ = ["events_bp", "stream_events"]
