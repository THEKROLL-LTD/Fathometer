"""Block O Phase B (ADR-0022 §CVSS-Vendor-Resolver) — Severity-Resolver-Tests.

Cases (Block-O-Brief Task #4 DoD):
* Ubuntu mit `{"ubuntu":"low","nvd":"critical"}` → `(LOW, "ubuntu")`,
  `max == CRITICAL`.
* Alma mit `{"redhat":"medium"}` → `(MEDIUM, "redhat")`.
* Ubuntu mit `{"nvd":"high"}` (kein Ubuntu) → `(HIGH, "nvd")`.
* Lang-pkgs mit `{"ghsa":"high"}` → `(HIGH, "ghsa")`.
* `severity_by_provider=None` → `(finding.severity, "trivy")`.
* Server-Family unbekannt/None → NVD-Fallback.
* `_score_to_severity` Boundary-Cases.
* Unbekannter String-Severity-Wert in Provider-Map → `UNKNOWN`.
"""

from __future__ import annotations

from typing import Any

from app.models import Finding, FindingClass, FindingType, Server, Severity
from app.services.severity_resolver import (
    _score_to_severity,
    max_severity_across_providers,
    severity_for,
)

# ---------------------------------------------------------------------------
# Fixture-Helfer — keine DB, reine ORM-Objekte ohne Session-Bindung.
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    severity: Severity = Severity.UNKNOWN,
    severity_by_provider: dict[str, Any] | None = None,
    finding_class: FindingClass = FindingClass.OS_PKGS,
) -> Finding:
    """ORM-Instance ohne DB-Persist — wir testen reine Resolver-Logik."""
    f = Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=finding_class,
        identifier_key="CVE-2024-0001",
        package_name="testpkg",
        severity=severity,
    )
    f.severity_by_provider = severity_by_provider
    return f


def _make_server(*, os_family: str | None = "ubuntu") -> Server:
    s = Server(name="test", api_key_hash="x" * 64, expected_scan_interval_h=24)
    s.os_family = os_family
    return s


# ---------------------------------------------------------------------------
# severity_for — Vendor-Priority pro Distro
# ---------------------------------------------------------------------------


def test_severity_for_ubuntu_prefers_ubuntu_over_nvd() -> None:
    """Ubuntu-Server: `ubuntu` schlaegt `nvd` selbst wenn NVD critical sagt."""
    f = _make_finding(
        severity=Severity.CRITICAL,
        severity_by_provider={"ubuntu": "low", "nvd": "critical"},
    )
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.LOW
    assert source == "ubuntu"


def test_severity_for_alma_uses_redhat_provider() -> None:
    """Alma-Server: bekommt RedHat-Severity-Source."""
    f = _make_finding(severity_by_provider={"redhat": "medium"})
    s = _make_server(os_family="alma")
    sev, source = severity_for(f, s)
    assert sev is Severity.MEDIUM
    assert source == "redhat"


def test_severity_for_ubuntu_falls_back_to_nvd_when_no_vendor() -> None:
    """Ubuntu ohne Ubuntu-Provider: faellt durch nach NVD."""
    f = _make_finding(severity_by_provider={"nvd": "high"})
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.HIGH
    assert source == "nvd"


def test_severity_for_lang_pkgs_prefers_ghsa() -> None:
    """Lang-pkgs-Finding: GHSA-first unabhaengig von der Host-Distro."""
    f = _make_finding(
        finding_class=FindingClass.LANG_PKGS,
        severity_by_provider={"ghsa": "high", "nvd": "low"},
    )
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.HIGH
    assert source == "ghsa"


def test_severity_for_lang_pkgs_falls_back_to_nvd() -> None:
    """Lang-pkgs ohne GHSA: faellt auf NVD."""
    f = _make_finding(
        finding_class=FindingClass.LANG_PKGS,
        severity_by_provider={"nvd": "medium"},
    )
    s = _make_server(os_family="alpine")  # Distro egal bei lang-pkgs
    sev, source = severity_for(f, s)
    assert sev is Severity.MEDIUM
    assert source == "nvd"


def test_severity_for_no_provider_map_falls_back_to_trivy() -> None:
    """`severity_by_provider=None` → `(finding.severity, "trivy")`."""
    f = _make_finding(severity=Severity.HIGH, severity_by_provider=None)
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.HIGH
    assert source == "trivy"


def test_severity_for_empty_provider_map_falls_back_to_trivy() -> None:
    """Leerer Dict zaehlt wie None."""
    f = _make_finding(severity=Severity.MEDIUM, severity_by_provider={})
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.MEDIUM
    assert source == "trivy"


def test_severity_for_unknown_os_family_falls_back_to_nvd() -> None:
    """Unbekannte Distro: NVD-only Default-Priority."""
    f = _make_finding(
        severity_by_provider={"nvd": "critical", "ubuntu": "low"},
    )
    s = _make_server(os_family="weirdistro")
    sev, source = severity_for(f, s)
    # Default-Priority ist nur NVD -> NVD gewinnt, ubuntu wird ignoriert.
    assert sev is Severity.CRITICAL
    assert source == "nvd"


def test_severity_for_none_os_family_falls_back_to_nvd() -> None:
    """`os_family=None`: NVD-Fallback."""
    f = _make_finding(severity_by_provider={"nvd": "high"})
    s = _make_server(os_family=None)
    sev, source = severity_for(f, s)
    assert sev is Severity.HIGH
    assert source == "nvd"


def test_severity_for_no_priority_match_falls_back_to_trivy() -> None:
    """Provider gesetzt aber keiner in der Priority-Liste -> Trivy-Fallback."""
    # Ubuntu-Priority = (ubuntu, debian, nvd) — `foo` ist keiner davon.
    f = _make_finding(
        severity=Severity.LOW,
        severity_by_provider={"foo": "critical"},
    )
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.LOW
    assert source == "trivy"


def test_severity_for_unknown_label_string_resolves_to_unknown() -> None:
    """Provider-Wert ausserhalb der Whitelist -> Severity.UNKNOWN."""
    f = _make_finding(severity_by_provider={"ubuntu": "informational"})
    s = _make_server(os_family="ubuntu")
    sev, source = severity_for(f, s)
    assert sev is Severity.UNKNOWN
    assert source == "ubuntu"


# ---------------------------------------------------------------------------
# max_severity_across_providers
# ---------------------------------------------------------------------------


def test_max_severity_includes_nvd_even_when_ubuntu_lower() -> None:
    """Pre-Triage-Eingabe: ein einzelner HIGH/CRITICAL-Provider reicht."""
    f = _make_finding(
        severity=Severity.LOW,
        severity_by_provider={"ubuntu": "low", "nvd": "critical"},
    )
    assert max_severity_across_providers(f) is Severity.CRITICAL


def test_max_severity_uses_finding_severity_too() -> None:
    """`finding.severity` ist auch im Max-Set, nicht nur die Provider-Werte."""
    f = _make_finding(
        severity=Severity.HIGH,
        severity_by_provider={"ubuntu": "low"},
    )
    assert max_severity_across_providers(f) is Severity.HIGH


def test_max_severity_none_provider_map_falls_back_to_finding_severity() -> None:
    """`severity_by_provider=None` → max == finding.severity (Status quo)."""
    f = _make_finding(severity=Severity.MEDIUM, severity_by_provider=None)
    assert max_severity_across_providers(f) is Severity.MEDIUM


def test_max_severity_empty_provider_map_falls_back_to_finding_severity() -> None:
    f = _make_finding(severity=Severity.LOW, severity_by_provider={})
    assert max_severity_across_providers(f) is Severity.LOW


def test_max_severity_unknown_labels_treated_as_unknown() -> None:
    """Unbekannte Labels droppen auf UNKNOWN, ueberschreiben hoehere Werte nicht."""
    f = _make_finding(
        severity=Severity.MEDIUM,
        severity_by_provider={"ubuntu": "informational", "nvd": "weird"},
    )
    # MEDIUM bleibt das Max, weil beide Provider-Werte als UNKNOWN gelten.
    assert max_severity_across_providers(f) is Severity.MEDIUM


# ---------------------------------------------------------------------------
# _score_to_severity — Boundary-Cases
# ---------------------------------------------------------------------------


def test_score_to_severity_critical_boundary() -> None:
    assert _score_to_severity(9.0) is Severity.CRITICAL
    assert _score_to_severity(10.0) is Severity.CRITICAL
    assert _score_to_severity(8.99) is Severity.HIGH


def test_score_to_severity_high_boundary() -> None:
    assert _score_to_severity(7.0) is Severity.HIGH
    assert _score_to_severity(6.99) is Severity.MEDIUM


def test_score_to_severity_medium_boundary() -> None:
    assert _score_to_severity(4.0) is Severity.MEDIUM
    assert _score_to_severity(3.99) is Severity.LOW


def test_score_to_severity_low_and_unknown() -> None:
    assert _score_to_severity(0.1) is Severity.LOW
    assert _score_to_severity(0.0) is Severity.UNKNOWN
