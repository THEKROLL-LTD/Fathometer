"""Block AA (ADR-0041) — primary_url-Persistierung im Ingest-Mapper.

Pure-Unit-Tests fuer die Mapping-Logik von `_build_finding_row` und die
Schema-Validierung von `TrivyVulnerability.primary_url`. Kein DB-Roundtrip:
die Funktion liest das parsed Pydantic-Envelope und liefert ein Row-Dict.

Cases (Block-AA-Spec §Phase A Tests):
* `_build_finding_row` schreibt `primary_url` aus `TrivyVulnerability.primary_url`.
* Bei fehlender `PrimaryURL` ist der Row-Dict-Eintrag `None`.
* Schema-Roundtrip: valide Aquasec-URL ueberlebt die Validierung.
* Schema-Reject: `javascript:`-URL wird auf `None` gemappt.
* Idempotenz: der `update_cols`-Set des Upserts enthaelt `primary_url`
  (autoritative Quelle = aktueller Scan).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.schemas.scan_envelope import Envelope, TrivyVulnerability
from app.services.findings_ingest import _CLASS_MAP, _build_finding_row

_NOW = datetime(2026, 5, 28, 12, 0, 0, tzinfo=UTC)

_PRIMARY_URL = "https://avd.aquasec.com/nvd/cve-2018-1121"


def _envelope(*, results: list[dict[str, Any]]) -> Envelope:
    return Envelope.model_validate(
        {
            "agent_version": "0.4.0",
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


def _first_row(env: Envelope, *, server_id: int = 1) -> dict[str, Any]:
    result = env.scan.results[0]
    fc = _CLASS_MAP[result.normalized_class()]
    vuln = (result.vulnerabilities or [])[0]
    return _build_finding_row(
        server_id=server_id,
        vuln=vuln,
        finding_class=fc,
        target=result.target,
        result=result,
        now=_NOW,
    )


def _result_with(*, primary_url: str | None) -> dict[str, Any]:
    vuln: dict[str, Any] = {
        "VulnerabilityID": "CVE-2018-1121",
        "PkgName": "procps",
        "InstalledVersion": "2:3.3.16-1ubuntu2",
        "Severity": "LOW",
    }
    if primary_url is not None:
        vuln["PrimaryURL"] = primary_url
    return {
        "Target": "srv-os (ubuntu 22.04)",
        "Class": "os-pkgs",
        "Type": "ubuntu",
        "Vulnerabilities": [vuln],
    }


# ---------------------------------------------------------------------------
# Mapper schreibt primary_url
# ---------------------------------------------------------------------------


def test_build_row_writes_primary_url() -> None:
    env = _envelope(results=[_result_with(primary_url=_PRIMARY_URL)])
    row = _first_row(env)
    assert row["primary_url"] == _PRIMARY_URL


def test_build_row_primary_url_none_when_absent() -> None:
    env = _envelope(results=[_result_with(primary_url=None)])
    row = _first_row(env)
    assert row["primary_url"] is None


# ---------------------------------------------------------------------------
# Schema-Validierung (Pydantic-Defense, Verifikation des Bestand-Validators)
# ---------------------------------------------------------------------------


def test_schema_accepts_https_aquasec_url() -> None:
    vuln = TrivyVulnerability.model_validate(
        {
            "VulnerabilityID": "CVE-2018-1121",
            "PkgName": "procps",
            "Severity": "LOW",
            "PrimaryURL": _PRIMARY_URL,
        }
    )
    assert vuln.primary_url == _PRIMARY_URL


def test_schema_rejects_javascript_url() -> None:
    vuln = TrivyVulnerability.model_validate(
        {
            "VulnerabilityID": "CVE-2018-1121",
            "PkgName": "procps",
            "Severity": "LOW",
            "PrimaryURL": "javascript:alert(1)",
        }
    )
    assert vuln.primary_url is None


def test_build_row_drops_javascript_primary_url() -> None:
    env = _envelope(results=[_result_with(primary_url="javascript:alert(1)")])
    row = _first_row(env)
    assert row["primary_url"] is None


# ---------------------------------------------------------------------------
# Upsert — primary_url im update_cols-Set (Re-Ingest-Idempotenz)
# ---------------------------------------------------------------------------


def test_upsert_update_cols_include_primary_url() -> None:
    """Der ON-CONFLICT-DO-UPDATE-Block muss primary_url ueberschreiben."""
    import inspect

    from app.services import findings_ingest

    src = inspect.getsource(findings_ingest.ingest_scan)
    assert '"primary_url": stmt.excluded.primary_url' in src
