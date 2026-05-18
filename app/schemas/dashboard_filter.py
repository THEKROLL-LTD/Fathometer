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

Block M (ADR-0020) erweitert das Schema um die Cross-Server-Findings-Such-
und Sort-Felder: `q`, `status`, `sort`, `dir`. Same Logic: ungueltige Werte
fallen lautlos auf den Default zurueck (Bookmark-stabilitaet).
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

# Block M (ADR-0020): Whitelists fuer die neuen Felder.
_VALID_STATUS: frozenset[str] = frozenset({"open", "acknowledged", "resolved", "all"})
# Block O (ADR-0022): Risk-Sort-Key wird Default-Primary; bleibt in der
# Whitelist neben den Block-M-Keys.
_VALID_SORTS: frozenset[str] = frozenset(
    {
        "risk",
        "server",
        "cve",
        "pkg",
        "epss",
        "cvss",
        "sev",
        "status",
        "first_seen",
        # Block P (ADR-0023): Sort nach ApplicationGroup.label.
        "group",
    }
)
_VALID_DIRS: frozenset[str] = frozenset({"asc", "desc"})

# Block O (ADR-0022): Risk-Band-Whitelist + Action-Required-Whitelist.
_VALID_RISK_BANDS: frozenset[str] = frozenset(
    {"escalate", "act", "mitigate", "pending", "unknown", "monitor", "noise"}
)
_VALID_ACTION_REQUIRED: frozenset[str] = frozenset({"yes", "no"})

# Maximale Laenge des Such-Strings — schuetzt URLs und DB-Indices vor
# ueberlangen `ilike`-Patterns.
_Q_MAX_LEN: int = 128

DashboardStatusFilter = Literal["open", "acknowledged", "resolved", "all"]
DashboardSortKey = Literal[
    "risk",
    "server",
    "cve",
    "pkg",
    "epss",
    "cvss",
    "sev",
    "status",
    "first_seen",
    # Block P (ADR-0023).
    "group",
]
DashboardSortDir = Literal["asc", "desc"]
DashboardRiskBand = Literal["escalate", "act", "mitigate", "pending", "unknown", "monitor", "noise"]
DashboardActionRequired = Literal["yes", "no"]


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
    - `q`: Volltext-Suche ueber Server-Name, CVE-ID, Paketname und Title
      (case-insensitive substring). Max 128 Chars, leerer String -> None.
    - `status`: Status-Filter fuer die Findings-Tabelle (Cross-Server).
      KPI-Counter zaehlen weiterhin OPEN (filter-unabhaengig, siehe ADR-0020).
    - `sort`/`dir`: sortierbare Spaltenheader der Cross-Server-Tabelle.
      Default `sev/desc` entspricht §15.
    """

    model_config = ConfigDict(extra="ignore")

    tags: list[str] = Field(default_factory=list)
    tags_mode: Literal["or", "and"] = "or"
    severity: Severity | None = None
    kev_only: bool = False
    stale_only: bool = False
    # Block M (ADR-0020)
    q: str | None = None
    status: DashboardStatusFilter = "open"
    sort: DashboardSortKey = "risk"
    dir: DashboardSortDir = "desc"
    # Block O (ADR-0022)
    risk_band: DashboardRiskBand | None = None
    action_required: DashboardActionRequired | None = None
    # Block P (ADR-0023): Filter auf `Finding.application_group_id`. `None`
    # bedeutet "kein Filter"; `ge=1` schliesst negative/Null-IDs aus. Bookmark-
    # stabilitaet: ungueltige Werte (Strings, < 1) werden in `from_request()`
    # still auf None gemappt — keine 422.
    application_group_id: int | None = Field(default=None, ge=1)

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

    @field_validator("q", mode="before")
    @classmethod
    def _clean_q(cls, value: Any) -> str | None:
        """Normalisiert den Such-String.

        - `None`/Nicht-String -> `None`.
        - Strip + Cap auf `_Q_MAX_LEN` Chars.
        - Leerer String nach `strip()` -> `None` (kein No-Op-Filter).
        """
        if value is None:
            return None
        if not isinstance(value, str):
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        return cleaned[:_Q_MAX_LEN]

    @classmethod
    def from_request(cls, args: MultiDict[str, str]) -> DashboardFilter:
        """Konstruiert den Filter aus `request.args`.

        Tag-Quellen (in dieser Reihenfolge konkateniert):
        - alle `?tags=...&tags=...` Werte (mehrfaches Vorkommen)
        - jeder einzelne Wert kann zusaetzlich comma-separated sein
        Zusaetzlich wird `?tag=...` (Single-Form aus der Block-M-Filter-Bar)
        akzeptiert; dieselbe Sammel-Logik.
        """
        raw_tags: list[str] = []
        for key in ("tags", "tag"):
            for entry in args.getlist(key):
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

        # Block M (ADR-0020): status / sort / dir / q.
        status_raw = (args.get("status") or "open").strip().lower()
        if status_raw not in _VALID_STATUS:
            log.debug("dashboard_filter.status_rejected", value=status_raw)
            status_raw = "open"

        sort_raw = (args.get("sort") or "risk").strip().lower()
        if sort_raw not in _VALID_SORTS:
            log.debug("dashboard_filter.sort_rejected", value=sort_raw)
            sort_raw = "risk"

        dir_raw = (args.get("dir") or "desc").strip().lower()
        if dir_raw not in _VALID_DIRS:
            log.debug("dashboard_filter.dir_rejected", value=dir_raw)
            dir_raw = "desc"

        # Block O (ADR-0022): risk_band / action_required Whitelist.
        risk_band_raw = (args.get("risk_band") or "").strip().lower()
        risk_band: DashboardRiskBand | None = None
        if risk_band_raw in _VALID_RISK_BANDS:
            risk_band = risk_band_raw  # type: ignore[assignment]
        elif risk_band_raw:
            log.debug("dashboard_filter.risk_band_rejected", value=risk_band_raw)

        action_required_raw = (args.get("action_required") or "").strip().lower()
        action_required: DashboardActionRequired | None = None
        if action_required_raw in _VALID_ACTION_REQUIRED:
            action_required = action_required_raw  # type: ignore[assignment]
        elif action_required_raw:
            log.debug("dashboard_filter.action_required_rejected", value=action_required_raw)

        # Block P (ADR-0023): Application-Group-ID-Filter. Akzeptiert nur
        # positive Integer; alles andere (None/Strings/<1) wird still
        # verworfen — Bookmark-Stabilitaet ueber alles.
        ag_raw = (args.get("application_group") or "").strip()
        application_group_id: int | None = None
        if ag_raw:
            try:
                ag_int = int(ag_raw)
            except ValueError:
                log.debug("dashboard_filter.application_group_rejected", value=ag_raw)
            else:
                if ag_int >= 1:
                    application_group_id = ag_int
                else:
                    log.debug(
                        "dashboard_filter.application_group_rejected",
                        value=ag_raw,
                    )

        return cls(
            tags=raw_tags,
            tags_mode=tags_mode,
            severity=severity,
            kev_only=_parse_bool(args.get("kev_only")),
            stale_only=_parse_bool(args.get("stale_only")),
            q=args.get("q"),
            status=status_raw,  # type: ignore[arg-type]
            sort=sort_raw,  # type: ignore[arg-type]
            dir=dir_raw,  # type: ignore[arg-type]
            risk_band=risk_band,
            action_required=action_required,
            application_group_id=application_group_id,
        )

    def to_query_string(self, *, override: dict[str, str] | None = None) -> str:
        """Serialisiert den Filter in einen Query-String fuer Links.

        Leere bzw. Default-Felder werden weggelassen, damit URLs kompakt
        bleiben. Tag-Liste wird **comma-separated** unter einem einzelnen
        `tags`-Key abgelegt (siehe Modul-Docstring).

        `override` erlaubt Filter-Switches in der UI (z.B. "selber Filter,
        andere Sortier-Richtung") ohne den State manuell zu kopieren. Der
        Override gewinnt; existierende Keys werden ersetzt, neue ans Ende
        angehaengt. Auch ein leerer String im Override haengt den Param an
        (was zu `?key=` fuehrt) — Caller, die ein Feld komplett entfernen
        wollen, koennen einen leeren `to_query_string()`-Output bauen und
        manuell den gewuenschten Override anhaengen.
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
        if self.q:
            parts.append(("q", self.q))
        if self.status != "open":
            parts.append(("status", self.status))
        if self.sort != "risk":
            parts.append(("sort", self.sort))
        if self.dir != "desc":
            parts.append(("dir", self.dir))
        # Block O (ADR-0022): Risk-Filter im Query-String.
        if self.risk_band is not None:
            parts.append(("risk_band", self.risk_band))
        if self.action_required is not None:
            parts.append(("action_required", self.action_required))
        # Block P (ADR-0023): Application-Group-ID-Filter.
        if self.application_group_id is not None:
            parts.append(("application_group", str(self.application_group_id)))

        if override:
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

    @property
    def is_active(self) -> bool:
        """`True` wenn irgendein Filter gesetzt ist.

        `sort` und `dir` zaehlen explizit NICHT als "aktiv" — Sort ist eine
        UI-Aktion und keine inhaltliche Einschraenkung, der Reset-Button soll
        davon nicht ausgeloest werden (ADR-0020).
        """
        return bool(
            self.tags
            or self.severity is not None
            or self.kev_only
            or self.stale_only
            or self.q
            or self.status != "open"
            or self.risk_band is not None
            or self.action_required is not None
            or self.application_group_id is not None
        )


def _parse_bool(value: str | None) -> bool:
    """Konsistentes Boolean-Parsing fuer Query-Parameter."""
    if value is None:
        return False
    return value.strip().lower() in _BOOL_TRUE_TOKENS


__all__ = [
    "DashboardActionRequired",
    "DashboardFilter",
    "DashboardRiskBand",
    "DashboardSortDir",
    "DashboardSortKey",
    "DashboardStatusFilter",
]
