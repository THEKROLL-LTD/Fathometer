"""In-process Event-Dispatcher fuer SSE-Live-Updates.

ARCHITECTURE.md §6 ("`GET /events` ist ein Server-Sent-Events-Stream") und
§7 ("Das Dashboard reagiert per SSE auf neue Scans und animiert das
Update der betroffenen Karte").

Verhalten:

- `EventBus.subscribe()` liefert eine `Subscription` mit eigener
  `queue.Queue`. Mehrere Subscribers koennen parallel existieren —
  typisch ein Subscriber pro aktivem Browser-Tab.
- `EventBus.publish(event_type, payload)` ist non-blocking: das Event
  wird in jede Queue gelegt; volle Queues (langsamer Client, kein
  Reader) fuehren zu einem silenten Drop plus structlog-Warning.
- Subscription-Cleanup laeuft ueber das Context-Manager-Protokoll,
  damit ein Generator-Close beim Client-Disconnect den Subscriber
  abmeldet.

Worker-Limitation (Re-Open-Trigger): gunicorn faehrt im MVP zwei
Worker. Events erreichen nur Subscribers desselben Workers — wenn der
Browser-Tab in Worker A subscribed ist und der Scan-Push in Worker B
landet, bekommt der Tab das Event nicht. Fuer den Single-User-MVP ist
das akzeptabel, weil typisch nur ein Tab offen ist. Wenn Multi-User
oder mehrere Tabs gleichzeitig zum Use-Case werden, muss der
Dispatcher gegen einen Redis-PubSub-Channel oder Postgres-LISTEN
getauscht werden.

Keine Threads, keine Background-Tasks — `publish` ist synchron, der
SSE-Endpoint blockt selbst auf `Queue.get(timeout=...)`. Heartbeat-Logik
liegt im SSE-Endpoint, nicht hier.
"""

from __future__ import annotations

import contextlib
import queue
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from flask import Flask

log = structlog.get_logger(__name__)


# Maximale Queue-Tiefe pro Subscriber. Bei aktiver Nutzung sind 0-2
# Eintraege wahrscheinlich; ein langsamer Client soll nicht die ganze
# App ausbremsen — wenn 64 Events anstehen ohne Reader, droppen wir.
_MAX_QUEUE_DEPTH = 64


@dataclass(frozen=True, slots=True)
class Event:
    """Ein Event im Bus."""

    event_type: str
    payload: dict[str, Any]
    emitted_at: datetime = field(default_factory=lambda: datetime.now(tz=UTC))


@dataclass
class Subscription:
    """Eine Subscription mit eigener Event-Queue.

    Wird vom SSE-Endpoint via Context-Manager-Protokoll erzeugt und beim
    Verlassen automatisch abgemeldet — der Client-Disconnect schliesst
    den Generator und damit den Context.
    """

    bus: EventBus
    q: queue.Queue[Event]

    def iter_events(self, *, timeout: float | None = None) -> Iterator[Event]:
        """Iteriere Events; `timeout` blockt bis ein Event verfuegbar ist.

        Wird `timeout` ueberschritten, wirft `queue.Empty`. Der Caller
        (SSE-Endpoint) faengt das ab um Heartbeats zu senden.
        """
        while True:
            yield self.q.get(timeout=timeout)


class EventBus:
    """In-process Fan-out an mehrere Subscribers.

    Thread-safe via `threading.Lock` um die Subscriber-Liste. Die
    `queue.Queue`-Instanzen sind selbst thread-safe.
    """

    def __init__(self) -> None:
        self._subscribers: list[Subscription] = []
        self._lock = threading.Lock()

    def subscribe(self) -> Subscription:
        """Legt eine neue Subscription an und registriert sie."""
        sub = Subscription(bus=self, q=queue.Queue(maxsize=_MAX_QUEUE_DEPTH))
        with self._lock:
            self._subscribers.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        """Entfernt eine Subscription. Idempotent."""
        with self._lock, contextlib.suppress(ValueError):
            self._subscribers.remove(sub)

    def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Fan-out an alle Subscribers.

        Non-blocking: volle Queue -> drop + Warning. Niemals raisen, damit
        ein langsamer Client den Publisher nicht abreisst.
        """
        event = Event(event_type=event_type, payload=payload)
        with self._lock:
            subs = list(self._subscribers)
        dropped = 0
        for sub in subs:
            try:
                sub.q.put_nowait(event)
            except queue.Full:
                dropped += 1
        if dropped:
            log.warning(
                "event_bus.publish_drop",
                event_type=event_type,
                dropped_subscribers=dropped,
                total_subscribers=len(subs),
            )

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


def get_event_bus(app: Flask) -> EventBus:
    """Holt den `EventBus` aus den App-Extensions.

    Wird in der App-Factory einmalig per `init_event_bus(app)` initialisiert.
    Tests koennen direkt eine eigene `EventBus()`-Instanz halten.
    """
    bus = app.extensions.get("event_bus")
    if not isinstance(bus, EventBus):
        raise RuntimeError("event_bus is not initialized on this app")
    return bus


def init_event_bus(app: Flask) -> EventBus:
    """Initialisiert den `EventBus` als App-Extension."""
    bus = EventBus()
    app.extensions["event_bus"] = bus
    return bus


__all__ = [
    "Event",
    "EventBus",
    "Subscription",
    "get_event_bus",
    "init_event_bus",
]
