# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""CVSS-Vendor-Resolver (Block O Phase B, ADR-0022 §CVSS-Vendor-Resolver).

Bestimmt pro Finding die anzuzeigende Severity aus der zur Host-Distro
passenden Vendor-Source und liefert das `max-over-providers`-Signal fuer
die Pre-Triage-Engine.

Eingaben sind `Finding.severity_by_provider` (JSONB-Map `provider -> label`,
befuellt vom Ingest-Mapper) plus `Server.os_family` als Routing-Key. Wenn
nichts gesetzt ist, faellt der Resolver auf `Finding.severity` zurueck
(Status quo).

Vendor-Severity-Werte aus Trivy sind im Envelope-Pre-Validator schon zu
lowercase-Strings normalisiert (`scan_envelope._normalize_vendor_severity`).
Der Resolver akzeptiert defensiv unbekannte Strings und mappt sie auf
`Severity.UNKNOWN` — Forward-Compat fuer neue Trivy-Labels.
"""

from __future__ import annotations

from typing import Any

from app.models import Finding, FindingClass, Server, Severity

# ---------------------------------------------------------------------------
# Mapping host-os-family -> bevorzugte Provider-Reihenfolge.
#
# Lowercase-Schluessel, getroffen wird per `server.os_family.lower()`. Wenn
# die Family unbekannt ist (z.B. `weirdistro`, `None`, leere Strings),
# faellt die Funktion auf NVD-only zurueck. Reihenfolge der Tuples bestimmt
# die Provider-Bevorzugung: erstes gesetztes Feld in `severity_by_provider`
# gewinnt.
# ---------------------------------------------------------------------------
_VENDOR_PRIORITY: dict[str, tuple[str, ...]] = {
    "ubuntu": ("ubuntu", "debian", "nvd"),
    "debian": ("debian", "ubuntu", "nvd"),
    "rhel": ("redhat", "nvd"),
    "centos": ("redhat", "nvd"),
    "rocky": ("redhat", "nvd"),
    "alma": ("redhat", "nvd"),
    "fedora": ("redhat", "nvd"),
    "amazon": ("amazon", "redhat", "nvd"),
    "opensuse-leap": ("suse", "nvd"),
    "opensuse-tumbleweed": ("suse", "nvd"),
    "sles": ("suse", "nvd"),
    "alpine": ("alpine", "nvd"),
    "oracle": ("oracle", "redhat", "nvd"),
}

# Lang-Pkgs (Go-Module, Python-Wheels, npm, ...) — GHSA ist die primaere
# Quelle, NVD der Fallback.
_LANG_PRIORITY: tuple[str, ...] = ("ghsa", "nvd")

# Default-Priority fuer unbekannte/None os_family: NVD-only.
_DEFAULT_PRIORITY: tuple[str, ...] = ("nvd",)


# ---------------------------------------------------------------------------
# Severity-Mapping. `Severity` ist `StrEnum` und vergleicht via String-Order
# (alphabetisch) — wir brauchen eine eigene Rank-Tabelle fuer `max()` und
# Schwellen-Vergleiche. Identisch zu `findings_query._SEVERITY_RANK_TABLE`
# (siehe DRY-Note: koennte zentralisiert werden, aktuell in beiden Modulen
# inline).
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}


# Normalisierter String -> Severity-Enum. Defensiv gegen unbekannte Labels
# (`"informational"`, `"negligible"`, leere Strings, ...) — alles ausserhalb
# der Whitelist landet als `UNKNOWN`.
_LABEL_TO_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unknown": Severity.UNKNOWN,
}


def _label_to_severity(label: Any) -> Severity:
    """Mappt einen lowercase-Label-String auf `Severity` (Forward-Compat-safe).

    Akzeptiert auch `None`/non-String-Werte (z.B. wenn die JSONB-Spalte
    haendisch befuellt wurde). Unbekannte Werte werden zu `UNKNOWN` — wir
    verlieren keine Findings, signalisieren aber dem Resolver dass der
    Wert nicht klassifizierbar ist.
    """
    if not isinstance(label, str):
        return Severity.UNKNOWN
    return _LABEL_TO_SEVERITY.get(label.strip().lower(), Severity.UNKNOWN)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def severity_for(finding: Finding, server: Server) -> tuple[Severity, str]:
    """Liefert `(severity, source)` — die UI-Anzeige-Severity plus Provider-Name.

    Routing:
      * `finding.finding_class == LANG_PKGS` -> `_LANG_PRIORITY` (GHSA-first).
      * sonst `_VENDOR_PRIORITY[server.os_family.lower()]` mit Default-Fallback
        auf NVD-only fuer unbekannte/None Family.

    Erstes Provider-Match in `finding.severity_by_provider` (case-insensitive)
    gewinnt. Wenn die Map None/leer ist oder keiner der priorisierten
    Provider gesetzt ist, fallback auf `(finding.severity, "trivy")` — wir
    persistieren die Top-Level-Trivy-Severity weiterhin als sicheren Default.
    """
    priority = _priority_for(finding, server)

    spm = _severity_by_provider_dict(finding)
    if spm:
        for provider in priority:
            if provider in spm:
                return (_label_to_severity(spm[provider]), provider)

    return (finding.severity, "trivy")


def max_severity_across_providers(finding: Finding) -> Severity:
    """Maximum aller Provider-Werte plus `finding.severity` selbst.

    Eingabe fuer `pretriage()` — Pre-Triage liest dieses Signal um zu
    entscheiden, ob *irgendein* Provider das Finding als HIGH/CRITICAL
    eingestuft hat (ein einzelner Treffer reicht).

    Wenn `severity_by_provider` None/leer ist: fallback auf
    `finding.severity` (Status quo).
    """
    spm = _severity_by_provider_dict(finding)
    best_rank = _SEVERITY_RANK[finding.severity]
    best_sev = finding.severity

    if spm:
        for raw_label in spm.values():
            sev = _label_to_severity(raw_label)
            rank = _SEVERITY_RANK[sev]
            if rank > best_rank:
                best_rank = rank
                best_sev = sev

    return best_sev


def _score_to_severity(score: float) -> Severity:
    """Mappt einen numerischen CVSS-Score auf die Severity-Bands.

    Cuts gemaess ADR-0022 §CVSS-Vendor-Resolver: >=9.0 CRITICAL, >=7.0 HIGH,
    >=4.0 MEDIUM, >0.0 LOW, sonst UNKNOWN. Wird vom Resolver aktuell nicht
    benutzt (Trivy liefert Provider-Labels direkt), ist aber Teil der
    Public-API fuer Block-P-Use-Cases (z.B. wenn ein Provider nur Scores
    schreibt).
    """
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Helpers (private)
# ---------------------------------------------------------------------------


def _priority_for(finding: Finding, server: Server) -> tuple[str, ...]:
    """Provider-Priority fuer dieses (Finding, Server)-Paar."""
    if finding.finding_class == FindingClass.LANG_PKGS:
        return _LANG_PRIORITY
    family = (server.os_family or "").strip().lower()
    if not family:
        return _DEFAULT_PRIORITY
    return _VENDOR_PRIORITY.get(family, _DEFAULT_PRIORITY)


def _severity_by_provider_dict(finding: Finding) -> dict[str, Any]:
    """Hilfsfunktion: liefert die Provider-Map als Dict (auch bei None).

    `Finding.severity_by_provider` ist als `dict[str, Any] | None` getypt.
    Wir wollen einen leeren Dict bei None plus case-insensitive Keys —
    der Pydantic-Pre-Validator hat die Keys schon lowercase normalisiert,
    aber wir sind defensiv (manuelle DB-Edits, Migrations-Faelle, ...).
    """
    raw = finding.severity_by_provider
    if not raw:
        return {}
    # Schon lowercase aus dem Pre-Validator — defensives `lower()` schadet
    # nicht und kostet kaum etwas bei <= 16 Providern.
    return {str(k).lower(): v for k, v in raw.items()}


__all__ = [
    "max_severity_across_providers",
    "severity_for",
]
