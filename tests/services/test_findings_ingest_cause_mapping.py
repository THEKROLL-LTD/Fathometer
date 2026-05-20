"""Block N (ADR-0021) — Ursachen-Felder-Mapping (Task #4b).

Unit-Tests fuer die pure Mapping-Logic von `_build_finding_row`/
`_extract_cause_fields`. Kein DB-Roundtrip noetig — die Funktionen lesen
nur das parsed Pydantic-Envelope und liefern ein dict zurueck.

Cases (Block-Brief Task #4b DoD):
* os-pkgs (ubuntu) mit voller `PkgIdentifier.PURL` → Row hat alle fuenf
  Cause-Felder + `package_name="openssl"` (ADR-0011 fuer os-pkgs: ohne
  `@target`-Suffix).
* lang-pkgs gobinary mit `Result.Target="usr/local/bin/kubelet"` →
  `target_path="usr/local/bin/kubelet"`, `result_type="gobinary"`,
  `package_name="golang.org/x/net@usr/local/bin/kubelet"` (Uebergangsformat).
* Re-Ingest identisch → zwei Aufrufe liefern dieselbe Row-Struktur (idempotent).
* Re-Ingest mit jetzt fehlendem `SeveritySource` → Spalte auf `None` gemappt.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models import FindingClass
from app.schemas.scan_envelope import Envelope
from app.services.findings_ingest import _CLASS_MAP, _build_finding_row

_NOW = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)


def _envelope(*, results: list[dict[str, Any]]) -> Envelope:
    return Envelope.model_validate(
        {
            "agent_version": "0.2.0",
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
                "Results": results,
            },
        }
    )


def _build_rows_from_envelope(env: Envelope, *, server_id: int = 1) -> list[dict[str, Any]]:
    """Repliziert die per-Vuln-Schleife aus `ingest_scan`, ohne DB."""
    rows: list[dict[str, Any]] = []
    for result in env.scan.results:
        fc = _CLASS_MAP[result.normalized_class()]
        for vuln in result.vulnerabilities or []:
            rows.append(
                _build_finding_row(
                    server_id=server_id,
                    vuln=vuln,
                    finding_class=fc,
                    target=result.target,
                    result=result,
                    now=_NOW,
                )
            )
    return rows


# ---------------------------------------------------------------------------
# os-pkgs ubuntu
# ---------------------------------------------------------------------------


def test_os_pkgs_ubuntu_writes_all_five_cause_fields() -> None:
    env = _envelope(
        results=[
            {
                "Target": "srv-os (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-12345",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.2-0ubuntu1.10",
                        "Severity": "HIGH",
                        "PkgIdentifier": {
                            "PURL": "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04",
                            "UID": "abc-uid-1",
                        },
                        "SeveritySource": "ubuntu",
                        "VendorIDs": ["USN-1234-1"],
                    }
                ],
            }
        ]
    )
    rows = _build_rows_from_envelope(env)
    assert len(rows) == 1
    row = rows[0]
    # ADR-0011: os-pkgs hat KEINEN `@target`-Suffix im package_name.
    assert row["package_name"] == "openssl"
    assert (
        row["package_purl"]
        == "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04"
    )
    assert row["target_path"] == "srv-os (ubuntu 22.04)"
    assert row["result_type"] == "ubuntu"
    assert row["severity_source"] == "ubuntu"
    assert row["vendor_ids"] == ["USN-1234-1"]
    assert row["finding_class"] == FindingClass.OS_PKGS.value


# ---------------------------------------------------------------------------
# lang-pkgs gobinary
# ---------------------------------------------------------------------------


def test_lang_pkgs_gobinary_uses_target_suffix_and_target_path() -> None:
    env = _envelope(
        results=[
            {
                "Target": "usr/local/bin/kubelet",
                "Class": "lang-pkgs",
                "Type": "gobinary",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-67890",
                        "PkgName": "golang.org/x/net",
                        "InstalledVersion": "v0.17.0",
                        "Severity": "MEDIUM",
                        "PkgIdentifier": {"PURL": "pkg:golang/golang.org/x/net@v0.17.0"},
                        "SeveritySource": "ghsa",
                    }
                ],
            }
        ]
    )
    rows = _build_rows_from_envelope(env)
    assert len(rows) == 1
    row = rows[0]
    # ADR-0011-Uebergangsformat: `<pkg>@<target>` im package_name.
    assert row["package_name"] == "golang.org/x/net@usr/local/bin/kubelet"
    assert row["target_path"] == "usr/local/bin/kubelet"
    assert row["result_type"] == "gobinary"
    assert row["severity_source"] == "ghsa"
    assert row["package_purl"] == "pkg:golang/golang.org/x/net@v0.17.0"
    assert row["finding_class"] == FindingClass.LANG_PKGS.value


# ---------------------------------------------------------------------------
# Re-Ingest: idempotente Row-Struktur
# ---------------------------------------------------------------------------


def test_re_ingest_identical_produces_identical_row_structure() -> None:
    """Zweimal dasselbe Envelope → zweimal exakt dieselbe Row-Struktur.

    Idempotenz lebt eigentlich auf DB-Ebene (ON CONFLICT). Auf Row-Builder-
    Ebene heisst Idempotenz: dasselbe Eingabe-Vuln liefert immer dieselben
    Felder.
    """
    env = _envelope(
        results=[
            {
                "Target": "srv-reingest (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77001",
                        "PkgName": "curl",
                        "InstalledVersion": "7.81.0",
                        "Severity": "HIGH",
                        "SeveritySource": "nvd",
                    }
                ],
            }
        ]
    )
    rows1 = _build_rows_from_envelope(env)
    rows2 = _build_rows_from_envelope(env)
    assert len(rows1) == 1
    assert len(rows2) == 1
    # `first_seen_at`/`last_seen_at` sind die einzigen variablen Felder, aber
    # wir fixieren `_NOW` -> sie sind identisch.
    assert rows1[0] == rows2[0]
    assert rows1[0]["severity_source"] == "nvd"


def test_re_ingest_drops_severity_source_when_missing_from_envelope() -> None:
    """Quelle der Wahrheit ist der aktuelle Scan — fehlendes Feld → row[...] is None."""
    env1 = _envelope(
        results=[
            {
                "Target": "srv-reingest-null (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77002",
                        "PkgName": "wget",
                        "InstalledVersion": "1.21.2",
                        "Severity": "MEDIUM",
                        "SeveritySource": "nvd",
                        "VendorIDs": ["USN-9999-1"],
                    }
                ],
            }
        ]
    )
    rows1 = _build_rows_from_envelope(env1)
    assert rows1[0]["severity_source"] == "nvd"
    assert rows1[0]["vendor_ids"] == ["USN-9999-1"]

    # Zweiter Scan: SeveritySource und VendorIDs sind weg.
    env2 = _envelope(
        results=[
            {
                "Target": "srv-reingest-null (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77002",
                        "PkgName": "wget",
                        "InstalledVersion": "1.21.2",
                        "Severity": "MEDIUM",
                    }
                ],
            }
        ]
    )
    rows2 = _build_rows_from_envelope(env2)
    assert len(rows2) == 1
    assert rows2[0]["severity_source"] is None
    assert rows2[0]["vendor_ids"] is None
