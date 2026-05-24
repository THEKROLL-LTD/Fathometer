"""Block N (ADR-0021) — Pydantic-Validator-Tests fuer die Ursachen-Felder.

Deckt Task #4 DoD ab:
* `TrivyVulnerability` mit `PkgIdentifier.PURL=...` → `package_purl`-Property.
* `PkgIdentifier=None` → `package_purl is None`.
* `VendorIDs` mit 50 Eintraegen → getrimmt auf `MAX_VENDOR_IDS_PER_VULN=32`.
* `VendorIDs` mit NUL-Byte-Item → still verworfen, andere bleiben.
* `SeveritySource` mit non-ASCII → Vuln-Reject (ValidationError).
* PURL mit 1024 Chars → Reject (max_length=512).
* `VendorIDs`-Item mit len>128 → Item verworfen.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import (
    MAX_VENDOR_ID_LENGTH,
    MAX_VENDOR_IDS_PER_VULN,
    TrivyPkgIdentifier,
    TrivyVulnerability,
)


def _minimal_vuln(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "VulnerabilityID": "CVE-2024-12345",
        "PkgName": "openssl",
        "InstalledVersion": "1.1.1",
        "Severity": "HIGH",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# PkgIdentifier / package_purl
# ---------------------------------------------------------------------------


def test_package_purl_property_returns_purl() -> None:
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(
            PkgIdentifier={
                "PURL": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64",
                "UID": "abc123",
            }
        )
    )
    assert vuln.pkg_identifier is not None
    assert vuln.pkg_identifier.purl == "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64"
    assert vuln.pkg_identifier.uid == "abc123"
    assert vuln.package_purl == "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64"


def test_package_purl_none_when_pkg_identifier_missing() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln())
    assert vuln.pkg_identifier is None
    assert vuln.package_purl is None


def test_pkg_identifier_purl_max_length_512_reject() -> None:
    long_purl = "pkg:deb/ubuntu/" + "a" * 1024
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(PkgIdentifier={"PURL": long_purl}))


def test_pkg_identifier_purl_non_ascii_rejected() -> None:
    """Non-ASCII (z.B. Unicode-Punkt) im PURL → Vuln-Reject."""
    with pytest.raises(ValidationError):
        TrivyPkgIdentifier.model_validate({"PURL": "pkg:deb/ubuntu/oepenssl‮evil"})


def test_pkg_identifier_purl_nul_byte_rejected() -> None:
    with pytest.raises(ValidationError):
        TrivyPkgIdentifier.model_validate({"PURL": "pkg:deb/ubuntu/openssl\x00@1.0"})


# ---------------------------------------------------------------------------
# SeveritySource
# ---------------------------------------------------------------------------


def test_severity_source_non_ascii_rejected() -> None:
    """ADR-0021 + Task #4: non-ASCII → Vuln-Reject."""
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(SeveritySource="ubuntué"))


def test_severity_source_nul_byte_rejected() -> None:
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(SeveritySource="nv\x00d"))


def test_severity_source_valid_ascii_passes() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(SeveritySource="nvd"))
    assert vuln.severity_source == "nvd"


# ---------------------------------------------------------------------------
# VendorIDs — defensiver Trim analog cwe_ids/references
# ---------------------------------------------------------------------------


def test_vendor_ids_capped_at_max() -> None:
    """50 Items → auf `MAX_VENDOR_IDS_PER_VULN` (32) gestutzt."""
    items = [f"USN-{i:04d}-1" for i in range(50)]
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(VendorIDs=items))
    assert vuln.vendor_ids is not None
    assert len(vuln.vendor_ids) == MAX_VENDOR_IDS_PER_VULN == 32
    # Reihenfolge erhalten (erste 32).
    assert vuln.vendor_ids[0] == "USN-0000-1"
    assert vuln.vendor_ids[-1] == f"USN-{31:04d}-1"


def test_vendor_ids_nul_byte_item_dropped_others_kept() -> None:
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(VendorIDs=["USN-1234-1", "USN-with-NUL\x00inside", "RHSA-2024:1234"])
    )
    assert vuln.vendor_ids == ["USN-1234-1", "RHSA-2024:1234"]


def test_vendor_ids_overlong_item_dropped() -> None:
    long_id = "USN-" + "A" * (MAX_VENDOR_ID_LENGTH + 1)
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(VendorIDs=["USN-1234-1", long_id, "RHSA-2024:1234"])
    )
    assert vuln.vendor_ids == ["USN-1234-1", "RHSA-2024:1234"]


def test_vendor_ids_non_ascii_item_dropped() -> None:
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(VendorIDs=["USN-1234-1", "ADV-é-2024", "RHSA-2024:1234"])
    )
    assert vuln.vendor_ids == ["USN-1234-1", "RHSA-2024:1234"]


def test_vendor_ids_non_string_item_rejects_whole_vuln() -> None:
    """Pydantic v2 erzwingt `list[str]` strikt — non-string Item → Vuln-Reject."""
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(
            _minimal_vuln(VendorIDs=["USN-1234-1", 12345, "RHSA-2024:1234"])
        )


def test_vendor_ids_none_stays_none() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln())
    assert vuln.vendor_ids is None


def test_vendor_ids_empty_list_becomes_empty_list() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(VendorIDs=[]))
    assert vuln.vendor_ids == []


# ---------------------------------------------------------------------------
# HostBlock.trivy_version (Schema-Erweiterung)
# ---------------------------------------------------------------------------


def test_host_trivy_version_nul_byte_rejected() -> None:
    from app.schemas.scan_envelope import HostBlock

    with pytest.raises(ValidationError):
        HostBlock.model_validate(
            {
                "os_family": "ubuntu",
                "os_version": "22.04",
                "os_pretty_name": "Ubuntu 22.04",
                "kernel_version": "5.15",
                "architecture": "x86_64",
                "trivy_version": "0.70.\x002",
            }
        )


def test_host_trivy_version_optional_none() -> None:
    from app.schemas.scan_envelope import HostBlock

    block = HostBlock.model_validate(
        {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15",
            "architecture": "x86_64",
        }
    )
    assert block.trivy_version is None


# ---------------------------------------------------------------------------
# Bugfix 2026-05-24 (ADR-0023 Nachtrag): PkgPath wird validiert und akzeptiert.
# ---------------------------------------------------------------------------


def test_pkg_path_accepted_with_filesystem_chars() -> None:
    """Pfade duerfen Slash, Punkt, Bindestrich, Unterstrich enthalten."""
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(PkgPath="AdminLTE-master/node_modules/vite/package.json")
    )
    assert vuln.pkg_path == "AdminLTE-master/node_modules/vite/package.json"


def test_pkg_path_default_none() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln())
    assert vuln.pkg_path is None


def test_pkg_path_nul_byte_rejected() -> None:
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(PkgPath="opt/app\x00/main"))


def test_pkg_path_max_length_512_reject() -> None:
    long_path = "opt/" + ("a" * 600)
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(PkgPath=long_path))
