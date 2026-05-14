"""Pydantic-Schema fuer den Dashboard-Filter-Query-String.

ARCHITECTURE.md §7 fordert: alle Filter (Tags, Severity-Schwelle-Override,
Status) sind im URL-Query-String — Bookmarks und Share-Links funktionieren
direkt. Es darf keinen Form-State im Server geben.

Tag-Liste wird **comma-separated** uebergeben (`?tags=prod,web`). Mehrfaches
`?tags=...&tags=...` wird zusaetzlich akzeptiert (Werte werden konkateniert),
um Browser-Form-Submits mit mehreren Checkboxen nicht zu brechen — beide
Varianten landen am Ende in derselben deduplizierten Liste.

Ungueltige Tag-Namen werden **stillschweigend verworfen** und nur geloggt.
Hintergrund: Bookmarks duerfen nach Tag-Loeschung oder Tippfehler nicht hart
brechen; UX > strenge Validierung an dieser Stelle. Komplett kaputter
Query-String fuehrt nicht zu 422 sondern zu "Filter ignoriert".
"""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlencode

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator
from werkzeug.datastructures import MultiDict

from app.forms import TAG_NAME_REGEX
from app.models import Severity

log = structlog.get_logger(__name__)

# Erlaubte Severity-Overrides aus dem Query-String. Wir mappen lowercase
# (URL-Konvention) auf das `Severity`-Enum (das selbst lowercase ist).
_VALID_SEVERITY_OVERRIDES: frozenset[str] = frozenset({"critical", "high", "medium", "low"})
_VALID_TAGS_MODE: frozenset[str] = frozenset({"or", "and"})
_BOOL_TRUE_TOKENS: frozenset[str] = frozenset({"1", "true", "on", "yes"})


class DashboardFilter(BaseModel):
    """Geparster Dashboard-Filter.

    Felder:
    - `tags`: ausgewaehlte Tag-Namen. Leere Liste bedeutet "kein Tag-Filter".
    - `tags_mode`: Verknuepfung zwischen mehreren Tags (`"or"` = mindestens
      einer, `"and"` = alle).
    - `severity`: optionaler Override der globalen Severity-Schwelle aus den
      Settings. `None` bedeutet "Default aus Settings verwenden".
    - `kev_only`: nur Server mit mindestens einem aktiven KEV-Finding.
    - `stale_only`: nur Server, die als stale gelten (Server-Stale).
    """

    model_config = ConfigDict(extra="ignore")

    tags: list[str] = Field(default_factory=list)
    tags_mode: Literal["or", "and"] = "or"
    severity: Severity | None = None
    kev_only: bool = False
    stale_only: bool = False

    @field_validator("tags", mode="before")
    @classmethod
    def _validate_tag_names(cls, value: Any) -> list[str]:
        """Filtert ungueltige Tag-Namen still raus.

        Akzeptiert eine Liste, einen einzelnen String oder `None`. Mehrfache
        Vorkommen werden dedupliziert; Reihenfolge bleibt stabil (erstes
        Vorkommen gewinnt).
        """
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple)):
            return []

        result: list[str] = []
        seen: set[str] = set()
        for raw in value:
            if not isinstance(raw, str):
                continue
            name = raw.strip().lower()
            if not name or name in seen:
                continue
            if not TAG_NAME_REGEX.match(name):
                log.debug("dashboard_filter.tag_rejected", value=name)
                continue
            seen.add(name)
            result.append(name)
        return result

    @classmethod
    def from_request(cls, args: MultiDict[str, str]) -> DashboardFilter:
        """Konstruiert den Filter aus `request.args`.

        Tag-Quellen (in dieser Reihenfolge konkateniert):
        - alle `?tags=...&tags=...` Werte (mehrfaches Vorkommen)
        - jeder einzelne Wert kann zusaetzlich comma-separated sein
        """
        raw_tags: list[str] = []
        for entry in args.getlist("tags"):
            for part in entry.split(","):
                stripped = part.strip()
                if stripped:
                    raw_tags.append(stripped)

        severity_raw = (args.get("severity") or "").strip().lower()
        severity: Severity | None = None
        if severity_raw in _VALID_SEVERITY_OVERRIDES:
            severity = Severity(severity_raw)
        elif severity_raw:
            log.debug("dashboard_filter.severity_rejected", value=severity_raw)

        tags_mode_raw = (args.get("tags_mode") or "or").strip().lower()
        tags_mode: Literal["or", "and"] = "and" if tags_mode_raw == "and" else "or"
        if tags_mode_raw not in _VALID_TAGS_MODE:
            log.debug("dashboard_filter.tags_mode_rejected", value=tags_mode_raw)

        return cls(
            tags=raw_tags,
            tags_mode=tags_mode,
            severity=severity,
            kev_only=_parse_bool(args.get("kev_only")),
            stale_only=_parse_bool(args.get("stale_only")),
        )

    def to_query_string(self) -> str:
        """Serialisiert den Filter in einen Query-String fuer Links.

        Leere bzw. Default-Felder werden weggelassen, damit URLs kompakt
        bleiben. Tag-Liste wird **comma-separated** unter einem einzelnen
        `tags`-Key abgelegt (siehe Modul-Docstring).
        """
        parts: list[tuple[str, str]] = []
        if self.tags:
            parts.append(("tags", ",".join(self.tags)))
        if self.tags_mode != "or":
            parts.append(("tags_mode", self.tags_mode))
        if self.severity is not None:
            parts.append(("severity", self.severity.value))
        if self.kev_only:
            parts.append(("kev_only", "1"))
        if self.stale_only:
            parts.append(("stale_only", "1"))
        return urlencode(parts)

    @property
    def is_active(self) -> bool:
        """`True` wenn irgendein Filter gesetzt ist."""
        return bool(self.tags or self.severity is not None or self.kev_only or self.stale_only)


def _parse_bool(value: str | None) -> bool:
    """Konsistentes Boolean-Parsing fuer Query-Parameter."""
    if value is None:
        return False
    return value.strip().lower() in _BOOL_TRUE_TOKENS


__all__ = ["DashboardFilter"]
