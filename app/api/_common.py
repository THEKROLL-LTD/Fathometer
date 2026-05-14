"""Gemeinsame Helper fuer API-Endpoints.

- `json_error` baut konsistente Fehler-Antworten.
- `format_pydantic_errors` reduziert eine `ValidationError` auf
  Field-Name + Kategorie — wir geben NICHT den vollen Pydantic-Trace zurueck
  (Fingerprinting-Schutz, siehe ARCHITECTURE.md §9 / §10).
"""

from __future__ import annotations

from typing import Any

from flask import jsonify
from pydantic import ValidationError
from werkzeug.wrappers import Response


def json_error(
    status_code: int,
    code: str,
    message: str,
    *,
    details: list[dict[str, str]] | None = None,
) -> Response:
    """Liefert eine kompakte JSON-Fehler-Antwort."""
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    response = jsonify(body)
    response.status_code = status_code
    return response


def format_pydantic_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Knappe Liste pro Feld: `[{"field": "...", "type": "..."}]`.

    Niemals die `input`-Werte oder lange Messages mitgeben — das wuerde
    bei NUL-Byte- oder XSS-Inputs zurueck-reflektieren.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(part) for part in err.get("loc", ()) if part != "")
        typ = str(err.get("type", "invalid"))
        key = (loc, typ)
        if key in seen:
            continue
        seen.add(key)
        out.append({"field": loc or "(root)", "type": typ})
        if len(out) >= 20:
            break
    return out


__all__ = ["format_pydantic_errors", "json_error"]
