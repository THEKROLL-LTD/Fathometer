"""Adversarial-Tests fuer das Pydantic-Envelope-Schema.

Quelle: ARCHITECTURE.md §10 (Input-Validierung-Whitelist).

Patterns:
- NUL-Byte in Strings -> ValidationError.
- Skript-Tags in Title -> erlaubt (Jinja escapt im Render).
- EPSS.Score=1.5 -> ValidationError.
- CVE-IDs ausserhalb des Patterns -> ValidationError.
- Severity ausserhalb der Whitelist -> ValidationError.
- PkgName mit Path-Traversal -> ValidationError.
- CVSS-Score > 10 -> ValidationError.
- CWE-IDs stripping (ungueltige Items raus).
- References stripping (nur https/http).
- JSON-Tiefe > 32 -> behandelt in HTTP-Layer.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import (
    Envelope,
    TrivyResult,
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


def _minimal_envelope(vulns: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "agent_version": "0.1.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15.0",
            "architecture": "x86_64",
        },
        "scan": {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.70.0"},
            "Results": [
                {
                    "Target": "test",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": vulns or [_minimal_vuln()],
                }
            ],
        },
    }


# ---------------------------------------------------------------------------
# Vuln-level Validierungen
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["Title", "Description", "PkgName", "InstalledVersion"],
)
def test_nul_byte_rejected_in_vuln_strings(field: str) -> None:
    vuln = _minimal_vuln(**{field: "before\x00after"})
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


def test_script_tag_in_title_allowed_no_escape_yet() -> None:
    """`<script>`-Tag in Title bleibt erhalten — Render escapt via Jinja."""
    vuln = _minimal_vuln(Title="<script>alert(1)</script>")
    parsed = TrivyVulnerability.model_validate(vuln)
    assert parsed.title == "<script>alert(1)</script>"


def test_epss_score_out_of_range_rejected() -> None:
    vuln = _minimal_vuln(EPSS={"Score": 1.5, "Percentile": 0.99})
    with pytest.raises(ValidationError) as ei:
        TrivyVulnerability.model_validate(vuln)
    # Field-Path zeigt auf score.
    locs = {".".join(str(p) for p in err.get("loc", ())) for err in ei.value.errors()}
    assert any("score" in loc.lower() for loc in locs), locs


def test_epss_percentile_out_of_range_rejected() -> None:
    vuln = _minimal_vuln(EPSS={"Score": 0.5, "Percentile": 1.5})
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


@pytest.mark.parametrize(
    "bad_cve",
    [
        "CVE-foo-bar",
        "CVE-123",
        "cve-2024-12345",
        "GHSA-1234567",
        "NOT-A-CVE",
        "CVE-24-1",
        "",
    ],
)
def test_invalid_cve_id_rejected(bad_cve: str) -> None:
    vuln = _minimal_vuln(VulnerabilityID=bad_cve)
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


def test_ghsa_id_accepted() -> None:
    vuln = _minimal_vuln(VulnerabilityID="GHSA-abcd-efgh-ijkl")
    parsed = TrivyVulnerability.model_validate(vuln)
    assert parsed.vulnerability_id == "GHSA-abcd-efgh-ijkl"


@pytest.mark.parametrize(
    "bad_severity",
    ["ULTRA_CRITICAL", "critical", "Important", "X", ""],
)
def test_invalid_severity_rejected(bad_severity: str) -> None:
    vuln = _minimal_vuln(Severity=bad_severity)
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


@pytest.mark.parametrize(
    "bad_pkg",
    [
        "../../../etc/passwd",
        "/absolute/path",
        "-leading-dash",
        "pkg with space",
        "pkg!",
        "pkg\x00name",
        "../pkg",
    ],
)
def test_invalid_pkg_name_rejected(bad_pkg: str) -> None:
    vuln = _minimal_vuln(PkgName=bad_pkg)
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


def test_cvss_score_above_10_rejected() -> None:
    vuln = _minimal_vuln(
        CVSS={"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "V3Score": 11.5}}
    )
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


def test_cvss_vector_with_bad_prefix_rejected() -> None:
    vuln = _minimal_vuln(CVSS={"nvd": {"V3Vector": "NOT-A-VECTOR/AV:N", "V3Score": 5.0}})
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(vuln)


def test_cwe_ids_invalid_items_stripped_not_rejected() -> None:
    """Pydantic-Schema strippt ungueltige CWE-IDs statt die ganze Vuln zu verwerfen."""
    vuln = _minimal_vuln(CweIDs=["CWE-79", "NOT-A-CWE", "CWE-12345678", "CWE-352"])
    parsed = TrivyVulnerability.model_validate(vuln)
    # CWE-12345678 hat 8 Stellen — Pattern erlaubt 1..7, also raus.
    assert parsed.cwe_ids == ["CWE-79", "CWE-352"], parsed.cwe_ids


def test_references_strip_non_http_schemes() -> None:
    vuln = _minimal_vuln(
        References=[
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<script>",
            "https://example.com/cve",
            "http://example.com/notice",
        ]
    )
    parsed = TrivyVulnerability.model_validate(vuln)
    assert parsed.references == ["https://example.com/cve", "http://example.com/notice"]


def test_references_trimmed_above_100() -> None:
    """120 References -> Parse OK, defensiv auf 100 getrimmt (v0.6.1).

    Vorher: harter HTTP-422-Reject durch `Field(max_length=50)`, weil der
    Built-in-Constraint VOR dem `@field_validator(mode="after")`-Trim
    feuerte. Trivy liefert fuer Distro-CVEs regelmaessig >50 Refs (NVD
    + Mailinglisten + Vendor-Advisories) — das hat real ein Ubuntu-22.04-
    aarch64-Scan vom Agent abgewuergt.
    """
    vuln = _minimal_vuln(References=[f"https://example.com/cve/{i}" for i in range(120)])
    parsed = TrivyVulnerability.model_validate(vuln)
    assert parsed.references is not None
    assert len(parsed.references) == 100
    # Reihenfolge erhalten — Trim am Tail.
    assert parsed.references[0] == "https://example.com/cve/0"
    assert parsed.references[-1] == "https://example.com/cve/99"


def test_references_at_100_boundary() -> None:
    """Boundary: 100 -> 100 erhalten; 101 -> auf 100 getrimmt."""
    at = _minimal_vuln(References=[f"https://example.com/cve/{i}" for i in range(100)])
    parsed_at = TrivyVulnerability.model_validate(at)
    assert parsed_at.references is not None
    assert len(parsed_at.references) == 100

    over = _minimal_vuln(References=[f"https://example.com/cve/{i}" for i in range(101)])
    parsed_over = TrivyVulnerability.model_validate(over)
    assert parsed_over.references is not None
    assert len(parsed_over.references) == 100


def test_cwe_ids_trimmed_above_50() -> None:
    """60 CWE-IDs -> Parse OK, defensiv auf 50 getrimmt (v0.6.1).

    Symmetrisch zu References — gleicher Bug-Pattern (Field-Constraint
    vor Validator), gleicher Fix (Validator ist einzige Cap-Quelle).
    """
    vuln = _minimal_vuln(CweIDs=[f"CWE-{i}" for i in range(1, 61)])
    parsed = TrivyVulnerability.model_validate(vuln)
    assert parsed.cwe_ids is not None
    assert len(parsed.cwe_ids) == 50


def test_cwe_ids_at_50_boundary() -> None:
    """Boundary: 50 -> 50 erhalten; 51 -> auf 50 getrimmt."""
    at = _minimal_vuln(CweIDs=[f"CWE-{i}" for i in range(1, 51)])
    parsed_at = TrivyVulnerability.model_validate(at)
    assert parsed_at.cwe_ids is not None
    assert len(parsed_at.cwe_ids) == 50

    over = _minimal_vuln(CweIDs=[f"CWE-{i}" for i in range(1, 52)])
    parsed_over = TrivyVulnerability.model_validate(over)
    assert parsed_over.cwe_ids is not None
    assert len(parsed_over.cwe_ids) == 50


def test_description_at_64kb_boundary() -> None:
    """64 KB exakt erlaubt, 64 KB + 1 abgelehnt."""
    ok = _minimal_vuln(Description="x" * 65536)
    TrivyVulnerability.model_validate(ok)

    too_big = _minimal_vuln(Description="x" * 65537)
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(too_big)


# ---------------------------------------------------------------------------
# Host-Block / Envelope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_os_family",
    ["ubuntu 22", "../../etc", "ubuntu\x00", "", "Übuntu", "1ubuntu", "-bad"],
)
def test_host_os_family_rejected(bad_os_family: str) -> None:
    env = _minimal_envelope()
    env["host"]["os_family"] = bad_os_family
    with pytest.raises(ValidationError):
        Envelope.model_validate(env)


def test_host_os_family_lowercased_implicitly() -> None:
    """Implementer-Choice: `Ubuntu` wird auf `ubuntu` ge-lowercased (siehe _validate_os_family)."""
    env = _minimal_envelope()
    env["host"]["os_family"] = "Ubuntu"
    parsed = Envelope.model_validate(env)
    assert parsed.host.os_family == "ubuntu"


def test_host_architecture_whitelist() -> None:
    env = _minimal_envelope()
    env["host"]["architecture"] = "fooarch"
    with pytest.raises(ValidationError):
        Envelope.model_validate(env)


@pytest.mark.parametrize(
    "alias,canonical",
    [
        ("arm64", "aarch64"),  # macOS, FreeBSD
        ("amd64", "x86_64"),  # Go-Style, Docker
        ("x86", "i686"),
        ("i386", "i686"),
        ("aarch64_be", "aarch64"),
        # Case-insensitive Eingabe
        ("ARM64", "aarch64"),
        ("AMD64", "x86_64"),
    ],
)
def test_host_architecture_alias_normalized_to_canonical(alias: str, canonical: str) -> None:
    """macOS/FreeBSD/Go-Aliase werden zur Linux-Canonical-Form normalisiert."""
    env = _minimal_envelope()
    env["host"]["architecture"] = alias
    parsed = Envelope.model_validate(env)
    assert parsed.host.architecture == canonical


def test_host_architecture_unknown_alias_still_rejected() -> None:
    """wasm32, mips u.ae. landen nicht in der Whitelist und werden 422."""
    env = _minimal_envelope()
    env["host"]["architecture"] = "wasm32"
    with pytest.raises(ValidationError):
        Envelope.model_validate(env)


def test_agent_version_strict_semver() -> None:
    env = _minimal_envelope()
    env["agent_version"] = "not-a-version"
    with pytest.raises(ValidationError):
        Envelope.model_validate(env)


def test_envelope_full_minimal_validates() -> None:
    """Smoke: das Minimum-Envelope geht durch."""
    env = _minimal_envelope()
    parsed = Envelope.model_validate(env)
    assert parsed.host.os_family == "ubuntu"


def test_result_class_normalisation() -> None:
    """Unbekannte Class -> `other`."""
    r = TrivyResult.model_validate(
        {"Target": "x", "Class": "weird", "Type": "x", "Vulnerabilities": []}
    )
    assert r.normalized_class() == "other"
