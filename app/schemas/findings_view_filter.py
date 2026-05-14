"""Pydantic-Schema fuer den Findings-View-Filter auf `/servers/<id>`.

ARCHITECTURE.md §7: alle Filter im URL-Query-String fuer teilbare Links.
Block-E nutzt zusaetzlich `mode` (list/group/diff).

Ungueltige Werte werden **stillschweigend auf den Default zurueckgesetzt**
und nur geloggt — eine Bookmark mit veraltetem `severity=xy` darf nicht in
422 enden.
"""

from __future__ import annotations

from typing import Any, Literal
from urllib.parse import urlencode

import structlog
from pydantic import BaseModel, ConfigDict, field_validator
from werkzeug.datastructures import MultiDict

from app.models import Severity
from app.services.findings_query import (
    FindingsClassFilter,
    FindingsFilter,
    FindingsStatusFilter,
)

log = structlog.get_logger(__name__)


ViewMode = Literal["list", "group", "diff"]

_VALID_MODES: frozenset[str] = frozenset({"list", "group", "diff"})
_VALID_STATUS: frozenset[str] = frozenset({"open", "acknowledged", "resolved", "all"})
_VALID_CLASS: frozenset[str] = frozenset({"os-pkgs", "lang-pkgs", "both"})
_VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "all"})
_BOOL_TRUE_TOKENS: frozenset[str] = frozenset({"1", "true", "on", "yes"})


class FindingsViewFilter(BaseModel):
    """Geparster Filter-State fuer den Server-Detail-View."""

    model_config = ConfigDict(extra="ignore")

    mode: ViewMode = "list"
    status: FindingsStatusFilter = "open"
    finding_class: FindingsClassFilter = "both"
    severity: Severity | None = None
    kev_only: bool = False
    search: str | None = None

    @field_validator("search", mode="before")
    @classmethod
    def _clean_search(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            return None
        # Sane caps gegen lange URLs.
        cleaned = value.strip()[:128]
        return cleaned or None

    @classmethod
    def from_request(cls, args: MultiDict[str, str]) -> FindingsViewFilter:
        """Konstruiert den Filter aus `request.args`. Ungueltiges -> Default."""
        mode_raw = (args.get("mode") or "list").strip().lower()
        if mode_raw not in _VALID_MODES:
            log.debug("findings_filter.mode_rejected", value=mode_raw)
            mode_raw = "list"

        status_raw = (args.get("status") or "open").strip().lower()
        if status_raw not in _VALID_STATUS:
            log.debug("findings_filter.status_rejected", value=status_raw)
            status_raw = "open"

        class_raw = (args.get("class") or "both").strip().lower()
        if class_raw not in _VALID_CLASS:
            log.debug("findings_filter.class_rejected", value=class_raw)
            class_raw = "both"

        sev_raw = (args.get("severity") or "all").strip().lower()
        severity: Severity | None
        if sev_raw == "all" or sev_raw not in _VALID_SEVERITIES:
            severity = None
        else:
            severity = Severity(sev_raw)

        return cls(
            mode=mode_raw,  # type: ignore[arg-type]
            status=status_raw,  # type: ignore[arg-type]
            finding_class=class_raw,  # type: ignore[arg-type]
            severity=severity,
            kev_only=_parse_bool(args.get("kev_only")),
            search=args.get("q"),
        )

    def to_findings_filter(self) -> FindingsFilter:
        """Konvertiert den View-Filter in den Service-Filter."""
        return FindingsFilter(
            status=self.status,
            severity_min=self.severity,
            finding_class=self.finding_class,
            kev_only=self.kev_only,
            search=self.search,
        )

    def to_query_string(self, *, override: dict[str, str] | None = None) -> str:
        """Serialisiert den Filter als Query-String fuer Links.

        `override` erlaubt Filter-Switches in der UI (z.B. "selber Filter,
        anderer Modus") ohne den State manuell zu kopieren.
        """
        parts: list[tuple[str, str]] = [
            ("mode", self.mode),
        ]
        if self.status != "open":
            parts.append(("status", self.status))
        if self.finding_class != "both":
            parts.append(("class", self.finding_class))
        if self.severity is not None:
            parts.append(("severity", self.severity.value))
        if self.kev_only:
            parts.append(("kev_only", "1"))
        if self.search:
            parts.append(("q", self.search))

        if override:
            # Bestehende Keys ersetzen, sonst anhaengen.
            seen_keys = {k for k, _ in parts}
            new_parts: list[tuple[str, str]] = []
            for k, v in parts:
                if k in override:
                    new_parts.append((k, override[k]))
                else:
                    new_parts.append((k, v))
            for k, v in override.items():
                if k not in seen_keys:
                    new_parts.append((k, v))
            parts = new_parts

        return urlencode(parts)


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in _BOOL_TRUE_TOKENS


__all__ = ["FindingsViewFilter", "ViewMode"]
