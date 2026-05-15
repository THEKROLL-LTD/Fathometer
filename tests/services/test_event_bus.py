"""Unit-Tests fuer `app.services.event_bus.EventBus`.

Pure-Logik-Tests ohne Flask-Request-Context. Decken die Block-H-DoD-Punkte:

- `subscribe()` liefert je Aufruf eine eigene `Subscription`.
- `publish(event_type, payload)` fan-outet an alle Subscribers.
- Multi-Subscriber: zwei Subscriptions empfangen dasselbe Event.
- `unsubscribe(sub)` ist idempotent; nach unsubscribe keine Events mehr.
- Full-Queue: N+1 Events bei Tiefe N -> letztes Event silent gedroppt
  und structlog-Warning (`event_bus.publish_drop`).
- `subscriber_count` reflektiert add/remove.
- `get_event_bus(app)` ohne `init_event_bus(app)` -> `RuntimeError`.
"""

from __future__ import annotations

import queue
from typing import Any

import pytest
import structlog
from flask import Flask

from app.services.event_bus import (
    _MAX_QUEUE_DEPTH,
    Event,
    EventBus,
    Subscription,
    get_event_bus,
    init_event_bus,
)


def _drain(sub: Subscription) -> list[Event]:
    """Holt alle Events aus einer Subscription nicht-blockierend."""
    out: list[Event] = []
    while True:
        try:
            out.append(sub.q.get_nowait())
        except queue.Empty:
            break
    return out


def test_subscribe_returns_subscription_with_own_queue() -> None:
    bus = EventBus()
    sub1 = bus.subscribe()
    sub2 = bus.subscribe()
    assert isinstance(sub1, Subscription)
    assert isinstance(sub2, Subscription)
    assert sub1.q is not sub2.q, "jede Subscription bekommt eine eigene Queue"
    assert bus.subscriber_count == 2


def test_publish_fans_out_to_all_subscribers() -> None:
    bus = EventBus()
    sub_a = bus.subscribe()
    sub_b = bus.subscribe()

    bus.publish("scan.received", {"server_id": 7})

    events_a = _drain(sub_a)
    events_b = _drain(sub_b)
    assert len(events_a) == 1
    assert len(events_b) == 1
    assert events_a[0].event_type == "scan.received"
    assert events_a[0].payload == {"server_id": 7}
    # Beide Subscribers sehen *dasselbe* Event-Objekt — Fan-out kopiert
    # nicht. Das ist akzeptabel, weil Subscribers das Event nur lesen.
    assert events_a[0] is events_b[0]


def test_multi_subscriber_independent_consumption() -> None:
    """Zwei Subscriptions konsumieren denselben Stream unabhaengig."""
    bus = EventBus()
    sub_a = bus.subscribe()
    sub_b = bus.subscribe()

    for i in range(3):
        bus.publish("e", {"i": i})

    # sub_a alle drei abholen, sub_b nur eines — Queues sind unabhaengig.
    a_events = _drain(sub_a)
    assert [e.payload["i"] for e in a_events] == [0, 1, 2]

    one_b = sub_b.q.get_nowait()
    assert one_b.payload["i"] == 0
    remaining_b = _drain(sub_b)
    assert [e.payload["i"] for e in remaining_b] == [1, 2]


def test_unsubscribe_is_idempotent() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    assert bus.subscriber_count == 1
    bus.unsubscribe(sub)
    assert bus.subscriber_count == 0
    # Zweites unsubscribe darf nicht raisen.
    bus.unsubscribe(sub)
    assert bus.subscriber_count == 0


def test_no_events_after_unsubscribe() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    bus.publish("first", {"n": 1})
    bus.unsubscribe(sub)
    bus.publish("second", {"n": 2})

    events = _drain(sub)
    assert [e.event_type for e in events] == ["first"]


def test_subscriber_count_reflects_add_remove() -> None:
    bus = EventBus()
    assert bus.subscriber_count == 0
    s1 = bus.subscribe()
    s2 = bus.subscribe()
    s3 = bus.subscribe()
    assert bus.subscriber_count == 3
    bus.unsubscribe(s2)
    assert bus.subscriber_count == 2
    bus.unsubscribe(s1)
    bus.unsubscribe(s3)
    assert bus.subscriber_count == 0


def test_full_queue_drops_silently_and_warns() -> None:
    """Wenn eine Subscription-Queue voll ist, droppt `publish` das Event
    silent, raised nicht und loggt eine `event_bus.publish_drop`-Warnung."""
    bus = EventBus()
    sub = bus.subscribe()
    # Queue vollstopfen — `_MAX_QUEUE_DEPTH` Events passen rein.
    for i in range(_MAX_QUEUE_DEPTH):
        bus.publish("fill", {"i": i})
    # Queue ist nun bei voller Tiefe.
    assert sub.q.qsize() == _MAX_QUEUE_DEPTH

    with structlog.testing.capture_logs() as logs:
        # +1 Event -> wird gedroppt, kein Raise.
        bus.publish("overflow", {"i": _MAX_QUEUE_DEPTH})

    # Queue ist immer noch voll, nicht ueber-voll.
    assert sub.q.qsize() == _MAX_QUEUE_DEPTH
    # Warnung wurde geloggt mit dem erwarteten Event-Name.
    drops = [
        entry
        for entry in logs
        if entry.get("event") == "event_bus.publish_drop" and entry.get("log_level") == "warning"
    ]
    assert len(drops) == 1, logs
    assert drops[0]["dropped_subscribers"] == 1
    assert drops[0]["event_type"] == "overflow"


def test_publish_never_raises_even_with_no_subscribers() -> None:
    """Ein publish ohne Subscribers ist ein No-Op und raised nicht."""
    bus = EventBus()
    # Soll einfach nichts tun.
    bus.publish("event", {"a": 1})
    assert bus.subscriber_count == 0


def test_get_event_bus_without_init_raises_runtime_error() -> None:
    """`get_event_bus(app)` ohne `init_event_bus(app)` -> RuntimeError."""
    app = Flask(__name__)
    # `app.extensions` muss explizit angelegt werden, sonst gibt es bei
    # `Flask < 2.0` einen AttributeError — hier `Flask 3.x`, Dict existiert.
    with pytest.raises(RuntimeError, match="event_bus"):
        get_event_bus(app)


def test_init_event_bus_attaches_singleton_to_app() -> None:
    app = Flask(__name__)
    bus1 = init_event_bus(app)
    bus2 = get_event_bus(app)
    assert bus1 is bus2


def test_get_event_bus_with_wrong_type_in_extensions_raises() -> None:
    """Defense-in-Depth: jemand legt einen Fremdwert in app.extensions['event_bus']."""
    app = Flask(__name__)
    app.extensions["event_bus"] = "not an EventBus"  # type: ignore[assignment]
    with pytest.raises(RuntimeError):
        get_event_bus(app)


def test_event_dataclass_has_emission_timestamp() -> None:
    """`Event.emitted_at` ist tz-aware UTC und wird bei Konstruktion gesetzt."""
    from datetime import UTC

    e = Event(event_type="t", payload={"x": 1})
    assert e.event_type == "t"
    assert e.payload == {"x": 1}
    assert e.emitted_at.tzinfo == UTC


def test_subscription_iter_events_with_timeout_raises_empty() -> None:
    """`iter_events(timeout=...)` raised `queue.Empty` wenn nichts kommt."""
    bus = EventBus()
    sub = bus.subscribe()
    iterator = sub.iter_events(timeout=0.05)
    with pytest.raises(queue.Empty):
        next(iterator)


def test_subscription_iter_events_returns_published_events() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    bus.publish("e1", {"i": 1})
    bus.publish("e2", {"i": 2})
    iterator = sub.iter_events(timeout=1.0)
    first = next(iterator)
    second = next(iterator)
    assert first.event_type == "e1"
    assert second.event_type == "e2"


def test_publish_to_one_full_subscriber_does_not_block_others() -> None:
    """Wenn sub_a voll ist, bekommt sub_b das neue Event trotzdem."""
    bus = EventBus()
    _sub_a = bus.subscribe()
    sub_b = bus.subscribe()

    for i in range(_MAX_QUEUE_DEPTH):
        bus.publish("fill", {"i": i})
    # sub_b leeren, sub_a bleibt voll.
    _ = _drain(sub_b)

    with structlog.testing.capture_logs() as logs:
        bus.publish("late", {"i": 999})

    # sub_b empfaengt das Event.
    events_b = _drain(sub_b)
    assert len(events_b) == 1
    assert events_b[0].payload["i"] == 999

    # Warning fuer sub_a wurde geloggt, aber nur 1 dropped_subscriber.
    drops = [entry for entry in logs if entry.get("event") == "event_bus.publish_drop"]
    assert len(drops) == 1
    assert drops[0]["dropped_subscribers"] == 1
    assert drops[0]["total_subscribers"] == 2


# Make `Any` "used" if needed by ruff (it isn't actually used; remove import).
_ = Any
