"""API-Blueprint (`/api/...`).

Sammelt die server-facing JSON-Endpoints. Browser-facing Endpoints leben
in `app/views/`. CSRF-Schutz wird fuer das ganze API ueber `csrf.exempt`
abgeschaltet — die Auth erfolgt per Bearer-Token bzw. Master-Key im Body.
"""

from __future__ import annotations

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")


def register_api_routes() -> None:
    """Importiert alle API-View-Module damit ihre Route-Decorators feuern."""
    # Lazy-Import zur Vermeidung von Zirkulaeren.
    from app.api import bulk, keys, register, scans  # noqa: F401


__all__ = ["api_bp", "register_api_routes"]
