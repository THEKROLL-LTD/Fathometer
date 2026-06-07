"""API-Blueprint (`/api/...`).

Sammelt die JSON-Endpoints. Browser-facing Endpoints leben in `app/views/`.

CSRF-Schutz ist NICHT global fuer das Blueprint ausgeschaltet. Einzelne
Agent-Endpoints, die mit Bearer-Token/Master-Key authentifizieren
(`scans.py`, `register.py`, `keys.py`), sind
explizit per `@csrf.exempt` ausgenommen. Browser-facing API-Endpoints
(z. B. `bulk.py:bulk_acknowledge` aus dem Dashboard) bleiben CSRF-
geschuetzt und erwarten den Token per `X-CSRFToken`-Header (HTMX).
"""

from __future__ import annotations

from flask import Blueprint

api_bp = Blueprint("api", __name__, url_prefix="/api")


def register_api_routes() -> None:
    """Importiert alle API-View-Module damit ihre Route-Decorators feuern."""
    # Lazy-Import zur Vermeidung von Zirkulaeren.
    from app.api import bulk, keys, register, scans  # noqa: F401


__all__ = ["api_bp", "register_api_routes"]
