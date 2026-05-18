"""Block N (ADR-0021, Task #9) — jq-Strip-Pipeline laesst Vulnerabilities intakt.

Der Agent strippt vor dem Envelope-Build per `jq 'del(.Results[].Packages)'`
den `Packages[]`-Inventarblock raus. Das ist ein reiner Bandbreiten-Win;
**die Anzahl der Vulnerabilities pro Result muss unveraendert bleiben**.
Wenn jemand versehentlich `.Vulnerabilities` strippt (Tippfehler/Refactor),
schlaegt dieser Test sofort an.

Zusaetzlich (DoD Block N): Bytes-Groesse nach Strip < 40% der Original-
Groesse fuer die Real-Fixture.

`jq` muss verfuegbar sein, sonst Skip.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent.parent / "fixtures" / "trivy" / "ubuntu-22.04-rke2.json"


@pytest.fixture(scope="module")
def jq_bin() -> str:
    bin_path = shutil.which("jq")
    if not bin_path:
        pytest.skip("jq not installed")
    return bin_path


def _vuln_count(doc: dict) -> int:
    total = 0
    for result in doc.get("Results", []):
        total += len(result.get("Vulnerabilities") or [])
    return total


def test_jq_strip_preserves_vulnerability_count(jq_bin: str) -> None:
    """Strip-Filter darf die Vuln-Anzahl nicht veraendern."""
    raw = FIXTURE.read_bytes()
    raw_doc = json.loads(raw)
    raw_count = _vuln_count(raw_doc)
    assert raw_count > 0, "Fixture muss Vulnerabilities enthalten"

    proc = subprocess.run(
        [jq_bin, "del(.Results[].Packages)"],
        input=raw,
        capture_output=True,
        check=True,
    )
    stripped_doc = json.loads(proc.stdout)
    assert _vuln_count(stripped_doc) == raw_count, (
        f"Strip darf Vuln-Anzahl nicht aendern: vorher={raw_count}, "
        f"nachher={_vuln_count(stripped_doc)}"
    )


def test_jq_strip_removes_packages_block(jq_bin: str) -> None:
    """Nach dem Strip darf in keinem Result mehr ein `Packages`-Key existieren."""
    raw = FIXTURE.read_bytes()
    proc = subprocess.run(
        [jq_bin, "del(.Results[].Packages)"],
        input=raw,
        capture_output=True,
        check=True,
    )
    stripped = json.loads(proc.stdout)
    for r in stripped.get("Results", []):
        assert "Packages" not in r, f"Packages key uebrig: keys={list(r.keys())}"


def test_jq_strip_reduces_size_below_40_percent(jq_bin: str) -> None:
    """DoD-Schwelle aus Block N: stripped < 40% der Original-Bytes."""
    raw = FIXTURE.read_bytes()
    proc = subprocess.run(
        [jq_bin, "del(.Results[].Packages)"],
        input=raw,
        capture_output=True,
        check=True,
    )
    raw_size = len(raw)
    stripped_size = len(proc.stdout)
    ratio = stripped_size / raw_size
    assert ratio < 0.4, (
        f"Strip lieferte nur {ratio:.1%} Reduktion: raw={raw_size} -> stripped={stripped_size}; "
        "DoD verlangt < 40%."
    )


def test_jq_strip_preserves_per_vuln_cause_fields(jq_bin: str) -> None:
    """`PkgIdentifier`/`SeveritySource`/`VendorIDs` muessen pro Vuln erhalten bleiben.

    Wenn die Fixture die Felder nicht hat (alte Trivy-Version), Skip — der
    Test hat dann keine Aussagekraft. Wir akzeptieren das stillschweigend,
    weil die Real-Fixture dynamisch ist.
    """
    raw = FIXTURE.read_bytes()
    raw_doc = json.loads(raw)

    # Suche eine Vuln im Raw mit PkgIdentifier (eine reicht — wir wollen
    # nur sicherstellen, dass der Strip diese Information nicht zerstoert).
    found_raw = False
    for r in raw_doc.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            if v.get("PkgIdentifier") or v.get("SeveritySource") or v.get("VendorIDs"):
                found_raw = True
                break
        if found_raw:
            break

    if not found_raw:
        pytest.skip("fixture has no PkgIdentifier/SeveritySource/VendorIDs to verify")

    proc = subprocess.run(
        [jq_bin, "del(.Results[].Packages)"],
        input=raw,
        capture_output=True,
        check=True,
    )
    stripped = json.loads(proc.stdout)

    # Nach dem Strip muessen *dieselben* Felder noch pro Vuln vorhanden sein.
    found_stripped = False
    for r in stripped.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            if v.get("PkgIdentifier") or v.get("SeveritySource") or v.get("VendorIDs"):
                found_stripped = True
                break
        if found_stripped:
            break
    assert found_stripped, "Strip hat versehentlich PkgIdentifier/SeveritySource/VendorIDs entfernt"


def test_agent_script_uses_correct_jq_filter() -> None:
    """Sanity-Check: das echte Agent-Skript benutzt die `del(.Results[].Packages)`-Form.

    Falls jemand das Skript refactored und versehentlich `.Vulnerabilities`
    statt `.Packages` strippt, ist der CI-Lauf rot.
    """
    agent_sh = Path(__file__).parent.parent.parent / "agent" / "secscan-agent.sh"
    body = agent_sh.read_text()
    assert "del(.Results[].Packages)" in body, (
        "Agent-Skript muss den Packages-Strip-Filter enthalten."
    )
    assert "del(.Results[].Vulnerabilities)" not in body, (
        "Agent-Skript darf NIEMALS .Vulnerabilities strippen — kritischer Datenverlust."
    )
