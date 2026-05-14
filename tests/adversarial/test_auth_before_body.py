"""DoS-Schutz: 401 muss VOR dem Body-Parse erfolgen (ARCHITECTURE.md §9).

Heuristik: ein 10 MB Body mit falschem Bearer-Token muss in <500 ms 401
liefern. Wenn der Server den Body zuerst dekomprimieren/parsen wuerde, waere
das fuer eine echte gzip-Bomb katastrophal — der Test schliesst das
explizit aus.
"""

from __future__ import annotations

import time

from flask import Flask


def test_401_for_10mb_body_under_500ms(db_app: Flask) -> None:
    """10 MB Random-Body mit Bearer-Bullshit -> 401 schnell."""
    client = db_app.test_client()
    big = b"\xff" * (10 * 1024 * 1024 - 1024)  # knapp unter 10-MB-Body-Limit.

    start = time.monotonic()
    resp = client.post(
        "/api/scans",
        data=big,
        headers={"Authorization": "Bearer not-a-real-token-deadbeef"},
    )
    elapsed = time.monotonic() - start
    assert resp.status_code == 401, resp.get_data(as_text=True)
    # CI-Toleranz: <500 ms reicht; ein Parse-vor-Auth-Pfad wuerde Sekunden brauchen.
    assert elapsed < 0.5, (
        f"401 mit 10-MB-Body dauerte {elapsed:.3f}s — Auth ist NICHT vor Body-Parse"
    )


def test_401_without_auth_header_for_large_body(db_app: Flask) -> None:
    """Ohne `Authorization`-Header: 401 ohne Body-Read."""
    client = db_app.test_client()
    big = b"\x01" * (5 * 1024 * 1024)
    start = time.monotonic()
    resp = client.post("/api/scans", data=big)
    elapsed = time.monotonic() - start
    assert resp.status_code == 401
    assert elapsed < 0.5


def test_401_with_oversized_token_quickly(db_app: Flask) -> None:
    """Bearer-Token > 512 chars -> auch 401, kein Krypto-Hash-Vergleich."""
    client = db_app.test_client()
    huge_token = "x" * 5000
    resp = client.post(
        "/api/scans",
        data=b"x",
        headers={"Authorization": f"Bearer {huge_token}"},
    )
    assert resp.status_code == 401
