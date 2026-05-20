"""Block O Phase B (ADR-0022) — Vendor-Status + Provider-Severity-Map-Mapping.

Unit-Tests fuer die pure Mapping-Logic von `_build_finding_row`/
`_extract_cause_fields`. Kein DB-Roundtrip noetig — wir verifizieren die
Felder direkt aus dem dict, das spaeter in den Bulk-Upsert geht.

Cases (Block-O-Brief Task #5 DoD):
* Trivy `Status="will_not_fix"` → Row-`vendor_status="will_not_fix"`.
* Trivy `Status="end_of_life"` → `vendor_status="eol"`.
* Trivy `Status="Foobar"` → `vendor_status="unknown"`.
* Trivy `Status=None` (kein Feld) → `vendor_status=None`.
* Trivy `VendorSeverity={"nvd":"high","ubuntu":"medium"}` → 1:1.
* Trivy `VendorSeverity={"nvd":3,"ubuntu":2}` (Integer-Variante) →
  `{"nvd":"high","ubuntu":"medium"}` durch Envelope-Pre-Validator normalisiert.
* Re-Ingest mit jetzt fehlenden Feldern → Row-Spalten `None`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas.scan_envelope import Envelope
from app.services.findings_ingest import _CLASS_MAP, _build_finding_row

_NOW = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


def _envelope(*, vulns: list[dict[str, Any]]) -> Envelope:
    return Envelope.model_validate(
        {
            "agent_version": "0.3.0",
            "host": {
                "os_family": "ubuntu",
                "os_version": "22.04",
                "os_pretty_name": "Ubuntu 22.04",
                "kernel_version": "5.15.0",
                "architecture": "x86_64",
                "trivy_version": "0.70.2",
            },
            "scan": {
                "SchemaVersion": 2,
                "Trivy": {"Version": "0.70.2"},
                "Results": [
                    {
                        "Target": "srv (ubuntu 22.04)",
                        "Class": "os-pkgs",
                        "Type": "ubuntu",
                        "Vulnerabilities": vulns,
                    }
                ],
            },
        }
    )


def _build_rows(env: Envelope) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for result in env.scan.results:
        fc = _CLASS_MAP[result.normalized_class()]
        for vuln in result.vulnerabilities or []:
            rows.append(
                _build_finding_row(
                    server_id=1,
                    vuln=vuln,
                    finding_class=fc,
                    target=result.target,
                    result=result,
                    now=_NOW,
                )
            )
    return rows


# ---------------------------------------------------------------------------
# vendor_status — Normalisierung
# ---------------------------------------------------------------------------


def test_vendor_status_will_not_fix() -> None:
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10001",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.2",
                "Severity": "HIGH",
                "Status": "will_not_fix",
            }
        ]
    )
    rows = _build_rows(env)
    assert len(rows) == 1
    assert rows[0]["vendor_status"] == "will_not_fix"


def test_vendor_status_end_of_life_normalized_to_eol() -> None:
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10002",
                "PkgName": "curl",
                "InstalledVersion": "7.0",
                "Severity": "MEDIUM",
                "Status": "end_of_life",
            }
        ]
    )
    rows = _build_rows(env)
    assert rows[0]["vendor_status"] == "eol"


def test_vendor_status_foobar_normalized_to_unknown() -> None:
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10003",
                "PkgName": "wget",
                "InstalledVersion": "1.21",
                "Severity": "LOW",
                "Status": "Foobar",
            }
        ]
    )
    rows = _build_rows(env)
    assert rows[0]["vendor_status"] == "unknown"


def test_vendor_status_missing_field_is_none() -> None:
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10004",
                "PkgName": "bash",
                "InstalledVersion": "5.0",
                "Severity": "MEDIUM",
            }
        ]
    )
    rows = _build_rows(env)
    assert rows[0]["vendor_status"] is None


# ---------------------------------------------------------------------------
# severity_by_provider — String + Integer-Varianten
# ---------------------------------------------------------------------------


def test_vendor_severity_string_variant_persisted() -> None:
    """Trivy schreibt `VendorSeverity` als lowercase-Strings → 1:1."""
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10005",
                "PkgName": "openssh-server",
                "InstalledVersion": "9.0",
                "Severity": "HIGH",
                "VendorSeverity": {"nvd": "high", "ubuntu": "medium"},
            }
        ]
    )
    rows = _build_rows(env)
    assert rows[0]["severity_by_provider"] == {"nvd": "high", "ubuntu": "medium"}


def test_vendor_severity_integer_variant_normalized() -> None:
    """Integer-Codes 1/2/3/4 werden durch den Envelope-Pre-Validator zu lowercase-Strings."""
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10006",
                "PkgName": "glibc",
                "InstalledVersion": "2.35",
                "Severity": "HIGH",
                # 3=high, 2=medium, 4=critical, 1=low.
                "VendorSeverity": {"nvd": 3, "ubuntu": 2},
            }
        ]
    )
    rows = _build_rows(env)
    assert rows[0]["severity_by_provider"] == {"nvd": "high", "ubuntu": "medium"}


def test_vendor_severity_missing_is_none() -> None:
    """Kein `VendorSeverity` im Envelope → Row-Spalte ist None."""
    env = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10007",
                "PkgName": "perl",
                "InstalledVersion": "5.34",
                "Severity": "LOW",
            }
        ]
    )
    rows = _build_rows(env)
    assert rows[0]["severity_by_provider"] is None


# ---------------------------------------------------------------------------
# Re-Ingest: fehlendes Feld -> None (aktueller Scan = Quelle der Wahrheit)
# ---------------------------------------------------------------------------


def test_re_ingest_drops_vendor_status_and_severity_map_when_missing() -> None:
    env1 = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10008",
                "PkgName": "rsync",
                "InstalledVersion": "3.2",
                "Severity": "MEDIUM",
                "Status": "will_not_fix",
                "VendorSeverity": {"nvd": "medium", "ubuntu": "low"},
            }
        ]
    )
    rows1 = _build_rows(env1)
    assert rows1[0]["vendor_status"] == "will_not_fix"
    assert rows1[0]["severity_by_provider"] == {"nvd": "medium", "ubuntu": "low"}

    # Zweiter Scan ohne Status und ohne VendorSeverity.
    env2 = _envelope(
        vulns=[
            {
                "VulnerabilityID": "CVE-2024-10008",
                "PkgName": "rsync",
                "InstalledVersion": "3.2",
                "Severity": "MEDIUM",
            }
        ]
    )
    rows2 = _build_rows(env2)
    assert len(rows2) == 1
    assert rows2[0]["vendor_status"] is None
    assert rows2[0]["severity_by_provider"] is None
