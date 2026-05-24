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


# ---------------------------------------------------------------------------
# Bugfix 2026-05-24 (ADR-0023 Nachtrag): Vulnerability.PkgPath bevorzugen
# ---------------------------------------------------------------------------


def test_lang_pkgs_node_pkg_prefers_pkg_path_over_ecosystem_target() -> None:
    """Walker-Analyzer (node-pkg): Result.Target ist nur das Oekosystem-Label.

    Echte Per-Paket-Location steht in Vulnerability.PkgPath. Ingest muss
    sowohl `target_path` als auch den `@target`-Disambiguator aus PkgPath
    bauen, sonst landen alle Node-Findings als ``<pkg>@Node.js`` und
    kollidieren auf demselben Server am UNIQUE-Constraint sobald dasselbe
    Package an mehreren Stellen liegt.
    """
    env = _envelope(
        results=[
            {
                "Target": "Node.js",
                "Class": "lang-pkgs",
                "Type": "node-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-31125",
                        "PkgName": "vite",
                        "PkgPath": "AdminLTE-master/node_modules/vite/package.json",
                        "InstalledVersion": "5.2.11",
                        "Severity": "MEDIUM",
                        "PkgIdentifier": {"PURL": "pkg:npm/vite@5.2.11"},
                        "SeveritySource": "ghsa",
                    }
                ],
            }
        ]
    )
    rows = _build_rows_from_envelope(env)
    assert len(rows) == 1
    row = rows[0]
    assert row["target_path"] == "AdminLTE-master/node_modules/vite/package.json"
    assert row["result_type"] == "node-pkg"
    # Disambiguator zieht denselben Pfad, damit zwei vite-Bundles am selben
    # Server kollisionsfrei nebeneinander existieren koennen.
    assert row["package_name"].startswith("vite@AdminLTE-master/node_modules/vite/")


def test_lang_pkgs_python_pkg_with_two_pkg_paths_disambiguates() -> None:
    """Dasselbe Package in zwei Paths → zwei verschiedene package_name-Werte.

    Stellt sicher dass der Disambiguator aus PkgPath einen UNIQUE-Constraint-
    Konflikt verhindert wenn ein Operator z.B. zwei venvs auf demselben Host
    hat oder eine OS-Python und eine /opt-App-Python-Installation.
    """
    env = _envelope(
        results=[
            {
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "PkgPath": "opt/app-a/venv/lib/python3.12/site-packages/requests-2.28.2.dist-info/METADATA",
                        "InstalledVersion": "2.28.2",
                        "Severity": "MEDIUM",
                        "SeveritySource": "ghsa",
                    },
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "PkgPath": "usr/lib/python3/dist-packages/requests-2.28.2.dist-info/METADATA",
                        "InstalledVersion": "2.28.2",
                        "Severity": "MEDIUM",
                        "SeveritySource": "ghsa",
                    },
                ],
            }
        ]
    )
    rows = _build_rows_from_envelope(env)
    assert len(rows) == 2
    names = {r["package_name"] for r in rows}
    assert len(names) == 2, f"Disambiguator hat kollidiert: {names}"
    paths = {r["target_path"] for r in rows}
    assert paths == {
        "opt/app-a/venv/lib/python3.12/site-packages/requests-2.28.2.dist-info/METADATA",
        "usr/lib/python3/dist-packages/requests-2.28.2.dist-info/METADATA",
    }


def test_lang_pkgs_gobinary_falls_back_to_result_target_when_no_pkg_path() -> None:
    """Backwards-Compat: gobinary liefert typischerweise kein PkgPath.

    Trivys File-Level-Analyzer setzen ``Result.Target`` auf den Binary-Pfad
    und lassen ``PkgPath`` leer — bestehendes Verhalten muss unveraendert
    bleiben.
    """
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
    assert row["target_path"] == "usr/local/bin/kubelet"
    assert row["package_name"] == "golang.org/x/net@usr/local/bin/kubelet"


def test_lang_pkgs_pkg_path_whitespace_treated_as_empty() -> None:
    """``PkgPath`` mit nur Whitespace darf nicht zu ``target_path=" "`` werden."""
    env = _envelope(
        results=[
            {
                "Target": "Python",
                "Class": "lang-pkgs",
                "Type": "python-pkg",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-99001",
                        "PkgName": "setuptools",
                        "PkgPath": "   ",
                        "InstalledVersion": "72.1.0",
                        "Severity": "MEDIUM",
                    }
                ],
            }
        ]
    )
    rows = _build_rows_from_envelope(env)
    assert len(rows) == 1
    # Fallback: leerer PkgPath → Result.Target greift.
    assert rows[0]["target_path"] == "Python"


def test_os_pkgs_keeps_result_target_when_pkg_path_absent() -> None:
    """OS-Distro-Findings haben keinen `PkgPath` — `target_path` bleibt der
    Hostname-String aus `Result.Target`."""
    env = _envelope(
        results=[
            {
                "Target": "srv-os (ubuntu 22.04)",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-77777",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.2-0ubuntu1.10",
                        "Severity": "HIGH",
                        "SeveritySource": "ubuntu",
                    }
                ],
            }
        ]
    )
    rows = _build_rows_from_envelope(env)
    assert len(rows) == 1
    assert rows[0]["target_path"] == "srv-os (ubuntu 22.04)"
    # ADR-0011: os-pkgs ohne @target-Suffix.
    assert rows[0]["package_name"] == "openssl"
