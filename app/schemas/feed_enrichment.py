# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pydantic-Schemas fuer die External-EPSS/KEV-Feeds (ADR-0024).

Strikte Validierung auf Eingaben aus dem FIRST.org-EPSS-CSV und dem
CISA-KEV-JSON. Beide Quellen sind public-Internet-Feeds — wir muessen
defensiv parsen (Regex-Whitelist auf CVE-IDs, Range-Limits auf EPSS-
Floats, Laengen-Limits auf String-Felder).

``model_config = ConfigDict(extra="ignore", populate_by_name=True)`` auf
jedem Modell, damit neue Spalten/Felder in einem zukuenftigen Feed-Schema
einfach mitkommen ohne Schema-Bump (analog ``app/schemas/scan_envelope.py``).
Felder werden als ``snake_case`` definiert mit ``alias=`` auf die
externen camelCase-Namen (CISA-Schema) bzw. lowercase-Header (EPSS-CSV).
"""

from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field

# CVE-ID-Whitelist — gleicher Regex wie in
# ``app/schemas/scan_envelope.py`` (Block N). Min 4 Suffix-Ziffern
# (CVE-Spec) bis hin zu groesseren CVE-Nummern (z.B. CVE-2024-1234567).
_CVE_PATTERN: str = r"^CVE-\d{4}-\d{4,}$"


class EpssRow(BaseModel):
    """Eine Zeile aus dem ``epss_scores-current.csv.gz`` von FIRST.org.

    CSV-Header: ``cve,epss,percentile``. Werte werden Stream-parsed, jede
    Row durch dieses Modell validiert. Ungueltige Rows werden vom
    Pull-Worker geloggt und gezaehlt (1%-Abort-Schwelle).

    Feldnamen folgen den CSV-Headern (lowercase, kein camelCase) — daher
    keine Alias-Indirektion noetig.
    """

    model_config = ConfigDict(extra="ignore")

    cve: str = Field(pattern=_CVE_PATTERN, max_length=32)
    epss: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)


class KevEntry(BaseModel):
    """Ein Eintrag aus dem CISA-KEV-JSON-Array ``vulnerabilities[]``.

    CISA verwendet camelCase-Feldnamen (``cveID``, ``vendorProject``,
    ...). Wir definieren die Felder snake_case und mappen ueber
    ``alias=``, damit der restliche Python-Code stilkonform bleibt.

    ``date_added`` ist Pflicht (CISA fuellt das immer), die Vendor-/Text-
    Felder sind optional damit eine CISA-Schema-Aenderung den Pull nicht
    sofort killt — der Worker persistiert dann ``NULL`` und gut.

    ``known_ransomware_campaign_use`` ist im CISA-Feed ein String
    (``"Known"`` | ``"Unknown"``). Der Pull-Worker mappt den String auf
    den DB-Boolean ``known_ransomware``.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    cve_id: str = Field(alias="cveID", pattern=_CVE_PATTERN, max_length=32)
    vendor_project: str | None = Field(default=None, alias="vendorProject", max_length=256)
    product: str | None = Field(default=None, max_length=256)
    vulnerability_name: str | None = Field(default=None, alias="vulnerabilityName", max_length=512)
    date_added: date = Field(alias="dateAdded")
    short_description: str | None = Field(default=None, alias="shortDescription", max_length=65536)
    required_action: str | None = Field(default=None, alias="requiredAction", max_length=65536)
    due_date: date | None = Field(default=None, alias="dueDate")
    known_ransomware_campaign_use: str | None = Field(
        default=None, alias="knownRansomwareCampaignUse", max_length=32
    )


class KevFeed(BaseModel):
    """Top-Level-Wrapper des CISA-KEV-JSON-Feeds.

    Wird als Ganzes validiert (single-shot, kein Streaming) — die
    KEV-Datei ist mit ~1500 Eintraegen / ~1 MB klein genug. Bei
    Validation-Failure wird der Pull als ``failed`` markiert und der
    naechste Tick versucht es erneut.
    """

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    catalog_version: str = Field(alias="catalogVersion", max_length=64)
    date_released: datetime = Field(alias="dateReleased")
    count: int = Field(ge=0, le=1_000_000)
    vulnerabilities: list[KevEntry] = Field(default_factory=list, max_length=1_000_000)


__all__ = [
    "EpssRow",
    "KevEntry",
    "KevFeed",
]
