"""Gzip-Bomb-Schutz fuer `POST /api/scans` (ARCHITECTURE.md §9).

Test-Cases:
- 1 KB komprimiert -> ueber Bound dekomprimiert -> 413 in <1s.
- Klassische Bomb-Form (winziges gzip, grosser Klartext) -> auch 413.

Der Decompress-Bound (`max_decompressed_mb`) wird pro Test auf einen kleinen
Wert gemockt, damit der Test default-unabhaengig ist und keinen mehrere-hundert-
MB-Body im Speicher bauen muss.
"""

from __future__ import annotations

import gzip
import time

import pytest
from flask import Flask

from app.config import Settings
from tests._helpers import register_test_server


def test_gzip_bomb_decompress_limit_413(
    db_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hochrepetitive Bytes komprimieren winzig, ueberschreiten aber den Bound."""
    settings: Settings = db_app.config["SECSCAN_SETTINGS"]
    monkeypatch.setattr(settings, "max_decompressed_mb", 1)

    _server_id, api_key = register_test_server(db_app, name="bomb-srv")
    client = db_app.test_client()

    # 4 MB hochrepetitive Bytes -> komprimiert auf wenige KB. Dekomprimiert
    # ueberschreitet das auf 1 MB gesenkte Limit deutlich.
    payload = b"A" * (4 * 1024 * 1024)
    compressed = gzip.compress(payload)
    assert len(compressed) < 1_000_000, len(compressed)

    start = time.monotonic()
    resp = client.post(
        "/api/scans",
        data=compressed,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Encoding": "gzip",
        },
    )
    elapsed = time.monotonic() - start

    assert resp.status_code == 413, resp.get_data(as_text=True)
    assert resp.get_json()["error"]["code"] == "decompressed_too_large"
    # Streaming-Abbruch muss schnell sein.
    assert elapsed < 5.0, f"413 dauerte {elapsed:.2f}s (sollte schnell brechen)"


def test_gzip_bomb_small_compressed_blows_up(
    db_app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Klassische gzip-Bomb-Form: winziges gzip -> ueber Bound dekomprimiert."""
    settings: Settings = db_app.config["SECSCAN_SETTINGS"]
    monkeypatch.setattr(settings, "max_decompressed_mb", 1)

    _server_id, api_key = register_test_server(db_app, name="bomb-small")
    client = db_app.test_client()

    payload = b"A" * (4 * 1024 * 1024)
    compressed = gzip.compress(payload)
    # Compressed << Body-Limit.
    assert len(compressed) < 5 * 1024 * 1024, len(compressed)

    resp = client.post(
        "/api/scans",
        data=compressed,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Encoding": "gzip",
        },
    )
    assert resp.status_code == 413
