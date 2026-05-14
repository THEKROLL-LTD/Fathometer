"""Gzip-Bomb-Schutz fuer `POST /api/scans` (ARCHITECTURE.md §9).

Test-Cases:
- 1 KB komprimiert -> 200 MB dekomprimiert -> 413 in <1s.
- 200 MB Klartext durch gzip.compress() (kleiner aber laenger) -> auch 413.
"""

from __future__ import annotations

import gzip
import time

from flask import Flask

from tests._helpers import register_test_server


def test_gzip_bomb_decompress_limit_413(db_app: Flask) -> None:
    """200 MB hochrepetitiv 'A' komprimiert -> sehr kleines gzip-Payload."""
    _server_id, api_key = register_test_server(db_app, name="bomb-srv")
    client = db_app.test_client()

    # 200 MB hochrepetitive Bytes -> komprimiert auf ~200 KB (kleiner Header,
    # extrem hohe Kompressionsrate). gzip.compress() in einem Schwung — fuer
    # Test ist das ok, der Punkt ist nur, dass das Wire-Format <10 MB ist.
    payload = b"A" * (200 * 1024 * 1024)
    compressed = gzip.compress(payload)
    assert len(compressed) < 1_000_000, len(compressed)  # << 1 MB komprimiert.

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
    # Streaming-Abbruch muss schnell sein — wir haben 100 MB Bound.
    assert elapsed < 5.0, f"413 dauerte {elapsed:.2f}s (sollte schnell brechen)"


def test_gzip_bomb_small_compressed_blows_up(db_app: Flask) -> None:
    """Klassische gzip-Bomb-Form: 1 KB komprimiert -> > 100 MB dekomprimiert.

    Wir bauen einen verschachtelten Repeat: gzip.compress(b'A' * N) liefert
    extreme Ratios. Bei N=110 MB -> Compress ~110 KB -> Decompress > 100 MB
    triggert den Bound.
    """
    _server_id, api_key = register_test_server(db_app, name="bomb-small")
    client = db_app.test_client()

    payload = b"A" * (110 * 1024 * 1024)
    compressed = gzip.compress(payload)
    # Compressed << 10 MB Body-Limit.
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
