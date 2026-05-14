"""Streaming-Gzip-Decompress-Middleware fuer `POST /api/scans`.

Architektur-Bezug:
- ARCHITECTURE.md §9 "Gzip-Bomb-Schutz": Decompress mit hartem Bytes-Bound.
- ADR-0007: gzip-Wire-Format ist Standard.

Implementiert als **Request-Level-Helper** statt als WSGI-Wrapper. Begruendung:
Wir brauchen den Decompress innerhalb des Auth-vor-Body-Parse-Flows (§9) — die
Auth muss VOR dem Lesen/Dekomprimieren laufen. Wenn wir das in der globalen
WSGI-Pipeline machen wuerden, wuerde jeder unauth Request schon dekomprimiert.

Stattdessen ruft `app/api/scans.py` `read_decompressed_body(request, limit_mb)`
nach dem Auth-Check auf. Die Funktion:

1. Liest den Stream chunk-weise (64 KB).
2. Wenn `Content-Encoding: gzip`: schiebt durch `zlib.decompressobj(16 + MAX_WBITS)`.
3. Bricht ab sobald die kumulierte dekomprimierte Groesse `limit_mb` ueberschreitet.
4. Gibt entweder `bytes` zurueck oder wirft `DecompressLimitError` /
   `DecompressError` — beide werden im Endpoint zu 413 / 400 gemappt.
"""

from __future__ import annotations

import zlib
from collections.abc import Iterator
from typing import IO

# Standard-Gzip-Header (RFC 1952). 16 + MAX_WBITS = "gzip + zlib auto-detect".
_GZIP_WBITS = 16 + zlib.MAX_WBITS

# Lese-Chunk-Groesse aus dem WSGI-Stream. 64 KB ist ein guter Balance-Punkt
# zwischen Syscalls und Speicher (§9 nennt 64 KB explizit).
_CHUNK = 64 * 1024


class DecompressError(Exception):
    """Korruptes oder ungueltiges gzip-Payload."""


class DecompressLimitError(Exception):
    """Dekomprimierte Daten haben den konfigurierten Bound ueberschritten."""

    def __init__(self, limit_bytes: int) -> None:
        super().__init__(f"Dekomprimierter Body groesser als {limit_bytes} Bytes")
        self.limit_bytes = limit_bytes


def _iter_stream(stream: IO[bytes], max_input_bytes: int) -> Iterator[bytes]:
    """Liest den WSGI-Stream chunk-weise mit einem Wire-Bytes-Bound.

    `max_input_bytes` ist der maximale komprimierte Body — wenn Flask schon
    `MAX_CONTENT_LENGTH` durchgesetzt hat, ist das eine Defense-in-Depth-
    Doppelung, kein Ersatz.
    """
    remaining = max_input_bytes
    while remaining > 0:
        to_read = min(_CHUNK, remaining)
        chunk = stream.read(to_read)
        if not chunk:
            return
        remaining -= len(chunk)
        yield chunk


def read_decompressed_body(
    stream: IO[bytes],
    *,
    content_encoding: str | None,
    max_compressed_bytes: int,
    max_decompressed_bytes: int,
) -> bytes:
    """Liest den Body und dekomprimiert ihn falls noetig — streamend.

    - `stream`: das `request.stream`-Objekt von Werkzeug.
    - `content_encoding`: Wert des `Content-Encoding`-Headers (case-insensitive).
    - `max_compressed_bytes`: harter Wire-Bound (typisch `MAX_CONTENT_LENGTH`).
    - `max_decompressed_bytes`: harter Decompress-Bound (gzip-Bomb-Schutz).

    Wirft:
      - `DecompressLimitError` wenn der Bound ueberschritten wird.
      - `DecompressError` bei korrupten gzip-Daten.
    """
    encoding = (content_encoding or "").strip().lower()

    if encoding == "":
        # Kein Content-Encoding — direkt einlesen mit Bound.
        out = bytearray()
        for chunk in _iter_stream(stream, max_compressed_bytes):
            out.extend(chunk)
            if len(out) > max_decompressed_bytes:
                raise DecompressLimitError(max_decompressed_bytes)
        return bytes(out)

    if encoding != "gzip":
        # `deflate`, `br`, `zstd` etc. sind nicht implementiert.
        raise DecompressError(f"Content-Encoding '{encoding}' wird nicht unterstuetzt")

    # Streaming-Decompress.
    decompressor = zlib.decompressobj(_GZIP_WBITS)
    out = bytearray()
    try:
        for chunk in _iter_stream(stream, max_compressed_bytes):
            decompressed = decompressor.decompress(chunk)
            if decompressed:
                out.extend(decompressed)
                if len(out) > max_decompressed_bytes:
                    raise DecompressLimitError(max_decompressed_bytes)
        # Restliche Daten aus dem Inflate-Puffer.
        tail = decompressor.flush()
        if tail:
            out.extend(tail)
            if len(out) > max_decompressed_bytes:
                raise DecompressLimitError(max_decompressed_bytes)
    except zlib.error as exc:
        raise DecompressError(f"gzip-Decompress fehlgeschlagen: {exc}") from exc

    return bytes(out)


__all__ = [
    "DecompressError",
    "DecompressLimitError",
    "read_decompressed_body",
]
