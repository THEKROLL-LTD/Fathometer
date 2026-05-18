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
from pydantic import BaseModel, ConfigDict, Field, field_validator
from werkzeug.datastructures import MultiDict

from app.models import Severity
from app.services.findings_query import (
    FindingsClassFilter,
    FindingsFilter,
    FindingsStatusFilter,
)

log = structlog.get_logger(__name__)


ViewMode = Literal["list", "group", "diff"]
SortKey = Literal["risk", "cve", "pkg", "epss", "cvss", "sev", "status", "first_seen", "group"]
SortDir = Literal["asc", "desc"]
RiskBandFilter = Literal["escalate", "act", "mitigate", "pending", "unknown", "monitor", "noise"]
ActionRequiredFilter = Literal["yes", "no"]

_VALID_MODES: frozenset[str] = frozenset({"list", "group", "diff"})
_VALID_STATUS: frozenset[str] = frozenset({"open", "acknowledged", "resolved", "all"})
_VALID_CLASS: frozenset[str] = frozenset({"os-pkgs", "lang-pkgs", "both"})
_VALID_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "all"})
# Block O (ADR-0022): `risk` als Default-Primary-Sort.
_VALID_SORTS: frozenset[str] = frozenset(
    {"risk", "cve", "pkg", "epss", "cvss", "sev", "status", "first_seen", "group"}
)
_VALID_DIRS: frozenset[str] = frozenset({"asc", "desc"})
_VALID_RISK_BANDS: frozenset[str] = frozenset(
    {"escalate", "act", "mitigate", "pending", "unknown", "monitor", "noise"}
)
_VALID_ACTION_REQUIRED: frozenset[str] = frozenset({"yes", "no"})
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
    # ADR-0018/ADR-0022: sortierbare Spalten-Header in der Server-Detail-
    # Tabelle. Default `sort=risk, dir=desc` (Block O) — escalate/act/mitigate
    # oben, dann pending/unknown/monitor/noise. CVSS-Severity rutscht in den
    # Tiebreak-Tail.
    sort: SortKey = "risk"
    dir: SortDir = "desc"
    # Block O (ADR-0022): Risk-Filter (kein Filter-Bar auf Server-Detail laut
    # ADR-0018, aber Bookmark-URLs sollen funktionieren).
    risk_band: RiskBandFilter | None = None
    action_required: ActionRequiredFilter | None = None
    # Block P (ADR-0023): Filter auf Application-Group-ID. `ge=1` haelt
    # negative/Null-Werte raus. Ungueltiges still auf None.
    application_group_id: int | None = Field(default=None, ge=1)

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
    def from_request(
        cls,
        args: MultiDict[str, str],
        *,
        user_default_severity: Severity | None = None,
    ) -> FindingsViewFilter:
        """Konstruiert den Filter aus `request.args`. Ungueltiges -> Default.

        `user_default_severity` ist die Severity-Schwelle aus den User-
        Settings (`settings.severity_threshold`, Default `HIGH`). Sie wird
        **nur** angewandt, wenn der `severity`-Key in `args` fehlt — ein
        explizites `?severity=all` setzt den Filter weiterhin auf "alles
        anzeigen" und uebersteuert das User-Setting. Damit zeigt ein frisch
        geoeffneter Server-Detail-Tab per Default nur HIGH+ statt aller 4000
        LOW-Findings, ohne dass Bookmark-URLs ihre Wirkung verlieren.
        """
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

        severity: Severity | None
        if "severity" not in args:
            # Kein expliziter Filter in URL -> User-Setting greift.
            severity = user_default_severity
        else:
            sev_raw = (args.get("severity") or "all").strip().lower()
            if sev_raw == "all" or sev_raw not in _VALID_SEVERITIES:
                severity = None
            else:
                severity = Severity(sev_raw)

        sort_raw = (args.get("sort") or "risk").strip().lower()
        if sort_raw not in _VALID_SORTS:
            log.debug("findings_filter.sort_rejected", value=sort_raw)
            sort_raw = "risk"

        dir_raw = (args.get("dir") or "desc").strip().lower()
        if dir_raw not in _VALID_DIRS:
            log.debug("findings_filter.dir_rejected", value=dir_raw)
            dir_raw = "desc"

        # Block O (ADR-0022): Risk-Filter aus dem Query-String. Ungueltige
        # Werte fallen still auf None zurueck.
        risk_band_raw = (args.get("risk_band") or "").strip().lower()
        risk_band: RiskBandFilter | None = None
        if risk_band_raw in _VALID_RISK_BANDS:
            risk_band = risk_band_raw  # type: ignore[assignment]
        elif risk_band_raw:
            log.debug("findings_filter.risk_band_rejected", value=risk_band_raw)

        action_required_raw = (args.get("action_required") or "").strip().lower()
        action_required: ActionRequiredFilter | None = None
        if action_required_raw in _VALID_ACTION_REQUIRED:
            action_required = action_required_raw  # type: ignore[assignment]
        elif action_required_raw:
            log.debug("findings_filter.action_required_rejected", value=action_required_raw)

        # Block P (ADR-0023): Application-Group-ID-Filter.
        ag_raw = (args.get("application_group") or "").strip()
        application_group_id: int | None = None
        if ag_raw:
            try:
                ag_int = int(ag_raw)
            except ValueError:
                log.debug("findings_filter.application_group_rejected", value=ag_raw)
            else:
                if ag_int >= 1:
                    application_group_id = ag_int
                else:
                    log.debug("findings_filter.application_group_rejected", value=ag_raw)

        return cls(
            mode=mode_raw,  # type: ignore[arg-type]
            status=status_raw,  # type: ignore[arg-type]
            finding_class=class_raw,  # type: ignore[arg-type]
            severity=severity,
            kev_only=_parse_bool(args.get("kev_only")),
            search=args.get("q"),
            sort=sort_raw,  # type: ignore[arg-type]
            dir=dir_raw,  # type: ignore[arg-type]
            risk_band=risk_band,
            action_required=action_required,
            application_group_id=application_group_id,
        )

    def to_findings_filter(self) -> FindingsFilter:
        """Konvertiert den View-Filter in den Service-Filter."""
        return FindingsFilter(
            status=self.status,
            severity_min=self.severity,
            finding_class=self.finding_class,
            kev_only=self.kev_only,
            search=self.search,
            risk_band=self.risk_band,
            action_required=self.action_required,
            application_group_id=self.application_group_id,
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
        # Sort/Dir immer mitgeben — Bookmarks sollen die explizite
        # Sortierung beibehalten, auch wenn sie zufaellig dem Default
        # entspricht. Macht URL kompakter ohne Wirkungsaenderung.
        if self.sort != "risk":
            parts.append(("sort", self.sort))
        if self.dir != "desc":
            parts.append(("dir", self.dir))
        # Block O (ADR-0022).
        if self.risk_band is not None:
            parts.append(("risk_band", self.risk_band))
        if self.action_required is not None:
            parts.append(("action_required", self.action_required))
        # Block P (ADR-0023).
        if self.application_group_id is not None:
            parts.append(("application_group", str(self.application_group_id)))

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


__all__ = [
    "ActionRequiredFilter",
    "FindingsViewFilter",
    "RiskBandFilter",
    "SortDir",
    "SortKey",
    "ViewMode",
]
