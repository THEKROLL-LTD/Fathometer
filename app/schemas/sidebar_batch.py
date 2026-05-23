"""Pydantic-Schema fuer `POST /_partials/sidebar/batch` (ADR-0035, Block W).

Validiert den Request-Body des Viewport-Lazy-Batch-Endpoints. Der Client
schickt eine Liste sichtbarer Server-IDs; der Server filtert gegen die DB
und liefert OOB-Heartbeat-Fragments nur fuer existierende IDs zurueck.

Sicherheits-Haertungen:
  - `extra="forbid"`: unbekannte Felder erzwingen 400 (kein Schema-Bleeding).
  - `max_length=200` auf `server_ids`: verhindert massive Payload-Angriffe.
  - Alle IDs muessen positive Integer sein (Field-Validator).
  - DB-Whitelist im View: nur tatsaechlich existierende Server-IDs in der Response.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Hartes Cap fuer die ID-Liste — verhindert Abuse via massiver Payload.
# Grosse Flotten haben typisch 200 sichtbare Rows maximal (Viewport-Lazy).
_MAX_SERVER_IDS = 200


class SidebarBatchRequest(BaseModel):
    """Request-Body fuer den Viewport-Batch-Endpoint."""

    model_config = ConfigDict(extra="forbid")

    server_ids: list[int] = Field(
        default_factory=list,
        description="Liste sichtbarer Server-IDs fuer den Batch-Fetch.",
        max_length=_MAX_SERVER_IDS,
    )

    @field_validator("server_ids", mode="before")
    @classmethod
    def _validate_ids(cls, v: object) -> object:
        """Sicherheitsprueung: alle Elemente muessen positive Integer sein."""
        if not isinstance(v, list):
            raise ValueError("server_ids muss eine Liste sein")
        for item in v:
            if not isinstance(item, int) or isinstance(item, bool):
                raise ValueError(f"server_ids enthaelt ungueltige Element: {item!r}")
            if item <= 0:
                raise ValueError(f"server_ids-Werte muessen positive Ganzzahlen sein, got {item}")
        return v


__all__ = ["SidebarBatchRequest"]
