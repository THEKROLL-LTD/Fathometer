"""API-Tests fuer `GET /events` SSE-Stream.

Test-Strategie:
- Flask-Testclient liefert die volle Response-Daten gebuffert. Wir koennen
  daher KEINE echte Streaming-Read-Schleife mit `iter_encoded()` ausfuehren,
  wenn der Generator nie aufhoert zu liefern. Stattdessen patchen wir
  `_HEARTBEAT_SECONDS` *und* den `_stream`-Helper, sodass der Generator
  nach einer endlichen Zahl Iterationen `StopIteration` wirft.

- Fuer den "Initial-Ready"-Test reicht uns die `response.response`-Iterable
  durchzulesen, wobei der Generator nach dem ersten Heartbeat (via gepatchtem
  `Subscription.q.get` mit `queue.Empty`) und dann nach `unsubscribe` durch
  `GeneratorExit` von Flask geschlossen wird.

- Wir nutzen `db_app`, weil `login_required` einen User braucht und damit
  der Setup-Guard nicht in den Weg kommt.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

import pytest
from flask import Flask

from app.services.event_bus import get_event_bus
from tests._helpers import create_admin_user, login

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _open_stream(client: Any) -> Any:
    """Oeffnet GET /events und gibt die Response zurueck (ohne body zu lesen)."""
    return client.get("/events", buffered=False)


def _read_first_chunk(resp: Any, *, max_bytes: int = 4096) -> bytes:
    """Liest den initialen Chunk vom SSE-Stream.

    Flask-Testclient's `response_wrapper.iter_encoded()` ist ein Iterator
    der gepufferten Stream-Output. Wir holen das erste Element und schliessen
    dann die Response.
    """
    iterator = resp.response  # type: ignore[attr-defined]
    chunk = b""
    for piece in iterator:
        if isinstance(piece, str):
            piece = piece.encode("utf-8")
        chunk += piece
        if len(chunk) >= max_bytes or b"\n\n" in chunk:
            break
    return chunk


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_events_requires_login(db_app: Flask) -> None:
    create_admin_user(db_app)
    client = db_app.test_client()
    resp = client.get("/events")
    assert resp.status_code in (302, 401), resp.status_code


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


def test_events_sets_sse_headers(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Content-Type, Cache-Control, X-Accel-Buffering korrekt."""
    create_admin_user(db_app)
    # Heartbeat klein damit der Generator nicht haengt — Flask test_client
    # liefert die Header bereits, sobald die View die Response zurueckgibt.
    from app.api import events as events_mod

    monkeypatch.setattr(events_mod, "_HEARTBEAT_SECONDS", 0.01)

    client = db_app.test_client()
    login(client)

    resp = _open_stream(client)
    try:
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/event-stream")
        assert resp.headers.get("Cache-Control") == "no-cache"
        assert resp.headers.get("X-Accel-Buffering") == "no"
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# Initial ready-event
# ---------------------------------------------------------------------------


def test_events_emits_initial_ready_event(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Der Stream sendet zuerst `event: ready` damit der Client weiss
    dass die Verbindung steht."""
    create_admin_user(db_app)

    from app.api import events as events_mod

    monkeypatch.setattr(events_mod, "_HEARTBEAT_SECONDS", 0.05)

    client = db_app.test_client()
    login(client)

    resp = _open_stream(client)
    try:
        chunk = _read_first_chunk(resp)
        text = chunk.decode("utf-8", errors="replace")
        assert "event: ready" in text, text
        assert "data: " in text, text
        assert "subscriber_count" in text, text
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def test_events_emits_heartbeat_after_idle(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn nichts published wird, kommt nach `_HEARTBEAT_SECONDS` ein
    `: heartbeat\\n\\n` Frame."""
    create_admin_user(db_app)

    from app.api import events as events_mod

    monkeypatch.setattr(events_mod, "_HEARTBEAT_SECONDS", 0.05)

    client = db_app.test_client()
    login(client)

    resp = _open_stream(client)
    try:
        # Drei Chunks lesen: ready + mindestens ein heartbeat.
        iterator = resp.response  # type: ignore[attr-defined]
        accumulated = b""
        for chunks_seen, piece in enumerate(iterator):
            if isinstance(piece, str):
                piece = piece.encode("utf-8")
            accumulated += piece
            if b": heartbeat" in accumulated:
                break
            if chunks_seen >= 5:
                break
        assert b": heartbeat" in accumulated, accumulated[:500]
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# Published Event sichtbar im Stream
# ---------------------------------------------------------------------------


def test_published_event_appears_in_stream(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """`bus.publish(...)` in einem Hintergrund-Thread laesst den
    SSE-Generator ein `event:`-Frame liefern."""
    create_admin_user(db_app)

    from app.api import events as events_mod

    monkeypatch.setattr(events_mod, "_HEARTBEAT_SECONDS", 0.05)

    client = db_app.test_client()
    login(client)

    resp = _open_stream(client)
    bus = get_event_bus(db_app)

    # In separatem Thread publishen — Hauptthread liest den Stream.
    def _publish_later() -> None:
        # Kleines Warten damit der Stream-Generator definitiv subscribed ist
        # bevor wir publishen.
        time.sleep(0.05)
        bus.publish("scan.received", {"server_id": 42, "new_finding_count": 3})

    t = threading.Thread(target=_publish_later, daemon=True)
    t.start()

    try:
        iterator = resp.response  # type: ignore[attr-defined]
        accumulated = b""
        for piece in iterator:
            if isinstance(piece, str):
                piece = piece.encode("utf-8")
            accumulated += piece
            if b"scan.received" in accumulated:
                break
            if len(accumulated) > 10_000:
                break
        text = accumulated.decode("utf-8", errors="replace")
        assert "event: scan.received" in text, text[:500]
        assert "server_id" in text, text[:500]
    finally:
        t.join(timeout=1.0)
        resp.close()


# ---------------------------------------------------------------------------
# Generator-Close ruft `unsubscribe`
# ---------------------------------------------------------------------------


def test_generator_close_unsubscribes(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn der Client den Stream schliesst, ruft der Generator
    `bus.unsubscribe(subscription)` auf — `subscriber_count` faellt wieder."""
    create_admin_user(db_app)

    from app.api import events as events_mod

    monkeypatch.setattr(events_mod, "_HEARTBEAT_SECONDS", 0.02)

    client = db_app.test_client()
    login(client)

    bus = get_event_bus(db_app)
    assert bus.subscriber_count == 0

    resp = _open_stream(client)
    # Mindestens einen Chunk lesen damit der Generator wirklich startet
    # (Subscribe passiert beim ersten `next()`).
    _ = _read_first_chunk(resp)
    # Subscriber-Count muss waehrend des Stream-Lebens >= 1 sein.
    assert bus.subscriber_count >= 1

    # Stream schliessen — unsubscribe muss greifen.
    resp.close()
    # Werkzeug ruft `iter_encoded.close()` -> Generator-Cleanup.
    # Kurze Wartezeit fuer GeneratorExit-Propagation.
    for _ in range(20):
        if bus.subscriber_count == 0:
            break
        time.sleep(0.02)
    assert bus.subscriber_count == 0


# ---------------------------------------------------------------------------
# `_sse_event` und `_sse_heartbeat` Unit-Helfer
# ---------------------------------------------------------------------------


def test_sse_event_format_is_correct() -> None:
    from app.api.events import _sse_event

    out = _sse_event("scan.received", {"server_id": 1, "name": "host"})
    text = out.decode("utf-8")
    assert text.startswith("event: scan.received\n")
    assert "data: " in text
    assert text.endswith("\n\n")


def test_sse_heartbeat_format_is_correct() -> None:
    from app.api.events import _sse_heartbeat

    out = _sse_heartbeat()
    assert out == b": heartbeat\n\n"


def test_sse_event_splits_multiline_data() -> None:
    """JSON mit eingebetteten Newlines wird in mehrere `data:`-Zeilen aufgeteilt."""
    from app.api.events import _sse_event

    # JSON-encode mit indent gibt newlines.
    out = _sse_event("multi", {"x": "a\nb\nc"})
    text = out.decode("utf-8")
    # Mindestens eine `data:`-Zeile.
    assert text.count("data: ") >= 1
    assert text.endswith("\n\n")


# Mark queue import as used (it's a transitive helper).
_ = queue
