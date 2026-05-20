"""Service-Layer-Unit-Tests fuer `findings_ingest` ohne DB.

Verifiziert die Pure-Logic-Schicht direkt: Envelope-Parsing, per-Vuln-
Validierung, Class-Verteilung, Disambiguations-Logic, sowie die Resolve-
Logic in einer reinen Python-Form.

Der `ingest_scan`-Wrapper selbst (Bulk-Upsert via `INSERT ... ON CONFLICT`)
ist Postgres-spezifisch (PG-Dialect `pg_insert(...).on_conflict_do_update(
...).returning(...)` + `excluded.<col>`-Attribut-Zugriffe) und nicht
sinnvoll mit `MagicMock` testbar — der Bulk-Insert wird durch die
Acceptance-Suite (`tests/integration/`) abgedeckt. Auf Unit-Ebene testen
wir die Bauschicht (`_build_finding_row`, `_disambiguated_package_name`,
`_safe_vuln`) und die Resolve-Set-Berechnung.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.models import AttackVector, FindingClass, FindingStatus, Severity
from app.schemas.scan_envelope import Envelope, TrivyVulnerability
from app.services.findings_ingest import (
    _CLASS_MAP,
    _SEVERITY_MAP,
    _build_finding_row,
    _disambiguated_package_name,
    _safe_vuln,
)

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "trivy"
REAL = FIXTURE_DIR / "ubuntu-22.04-rke2.json"
ADVERSARIAL = FIXTURE_DIR / "adversarial.json"


def _envelope_dict(scan: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent_version": "0.1.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04 LTS",
            "kernel_version": "5.15.0-100-generic",
            "architecture": "x86_64",
        },
        "scan": scan,
    }


@pytest.fixture(scope="module")
def real_scan() -> dict[str, Any]:
    with REAL.open("rb") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def adversarial_scan() -> dict[str, Any]:
    with ADVERSARIAL.open("rb") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Helper: repliziert die Vuln-Schleife aus `ingest_scan` ohne DB-Seite.
# ---------------------------------------------------------------------------


def _build_rows(env: Envelope, *, server_id: int = 1) -> list[dict[str, Any]]:
    from datetime import UTC, datetime

    now = datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)
    rows: list[dict[str, Any]] = []
    current_keys: set[tuple[str, str]] = set()
    for result in env.scan.results:
        fc = _CLASS_MAP[result.normalized_class()]
        target = result.target
        for raw_vuln in result.vulnerabilities or []:
            vuln = _safe_vuln(raw_vuln, server_name="srv")
            if vuln is None:
                continue
            pkg_disamb = _disambiguated_package_name(vuln.pkg_name, target, fc)
            key = (vuln.vulnerability_id, pkg_disamb)
            if key in current_keys:
                continue
            current_keys.add(key)
            rows.append(
                _build_finding_row(
                    server_id=server_id,
                    vuln=vuln,
                    finding_class=fc,
                    target=target,
                    result=result,
                    now=now,
                )
            )
    return rows


def _count_by_class(rows: list[dict[str, Any]]) -> dict[FindingClass, int]:
    counter: dict[FindingClass, int] = {
        FindingClass.OS_PKGS: 0,
        FindingClass.LANG_PKGS: 0,
        FindingClass.OTHER: 0,
    }
    for row in rows:
        cls = FindingClass(row["finding_class"])
        counter[cls] += 1
    return counter


# ---------------------------------------------------------------------------
# Real-Fixture: Counts und Class-Verteilung
# ---------------------------------------------------------------------------


def test_ingest_real_fixture_counts(real_scan: dict[str, Any]) -> None:
    envelope = Envelope.model_validate(_envelope_dict(real_scan))
    rows = _build_rows(envelope)
    counts = _count_by_class(rows)
    assert len(rows) == 306
    assert counts[FindingClass.LANG_PKGS] == 296
    assert counts[FindingClass.OS_PKGS] == 10
    assert counts[FindingClass.OTHER] == 0


def test_ingest_real_fixture_attack_vectors_and_cvss(real_scan: dict[str, Any]) -> None:
    """Smoke: CVSS-Score und attack_vector werden aus dem CVSS-Vektor abgeleitet."""
    envelope = Envelope.model_validate(_envelope_dict(real_scan))
    rows = _build_rows(envelope)

    # Mindestens eines hat einen abgeleiteten attack_vector != unknown.
    derived = [r for r in rows if r["attack_vector"] != AttackVector.UNKNOWN.value]
    assert derived, "Erwarte mindestens 1 Row mit abgeleitetem attack_vector"

    # Mapping ist konsistent: wenn cvss_v3_vector AV:N enthaelt -> NETWORK.
    for r in rows:
        if r["cvss_v3_vector"] and "AV:N/" in r["cvss_v3_vector"]:
            assert r["attack_vector"] == AttackVector.NETWORK.value, (
                r["identifier_key"],
                r["cvss_v3_vector"],
                r["attack_vector"],
            )

    # KEV nicht in real-fixture: alle is_kev=False.
    for r in rows:
        assert r["is_kev"] is False


def test_ingest_real_fixture_idempotent_at_row_level(real_scan: dict[str, Any]) -> None:
    """Zweimal denselben Envelope durchbauen -> identische Row-Liste.

    Auf Row-Builder-Ebene heisst Idempotenz: dasselbe Envelope liefert immer
    dieselbe deterministische Row-Sequenz. Der DB-seitige Re-Ingest-No-Dup
    haengt von ON-CONFLICT-Semantik ab und wird in der Acceptance-Suite
    (`tests/integration/`) gegen Postgres verifiziert.
    """
    envelope = Envelope.model_validate(_envelope_dict(real_scan))
    rows1 = _build_rows(envelope)
    rows2 = _build_rows(envelope)
    assert len(rows1) == 306
    assert rows1 == rows2


def test_ingest_lang_pkgs_disambiguation_creates_unique_findings(
    real_scan: dict[str, Any],
) -> None:
    """Dieselbe CVE in mehreren Go-Binaries -> separate Rows mit verschiedenen package_names.

    Wir suchen aus der Fixture ein Beispiel: eine CVE-ID die in mehreren
    `lang-pkgs`-Targets vorkommt -> nach dem Build mehrere Rows mit
    identischer `identifier_key` aber unterschiedlichem `package_name`
    (disambiguiert via `pkg@target`).
    """
    envelope = Envelope.model_validate(_envelope_dict(real_scan))
    rows = _build_rows(envelope)
    lang_rows = [r for r in rows if r["finding_class"] == FindingClass.LANG_PKGS.value]

    from collections import Counter

    cve_counts = Counter(r["identifier_key"] for r in lang_rows)
    multi = [k for k, n in cve_counts.items() if n > 1]
    assert multi, "Erwarte mindestens 1 CVE mit Multi-Target-Disambiguation"

    # Innerhalb derselben CVE-Gruppe muessen `package_name`-Werte unique sein.
    for cve in multi[:3]:
        names = {r["package_name"] for r in lang_rows if r["identifier_key"] == cve}
        assert len(names) > 1, (cve, names)
        # Mindestens einer enthaelt das `@target`-Suffix.
        assert any("@" in n for n in names), names


# ---------------------------------------------------------------------------
# Adversarial-Fixture: per-Vuln-Drop vs. Top-Level-Fail
# ---------------------------------------------------------------------------


def test_envelope_validation_rejects_adversarial_on_top_level(
    adversarial_scan: dict[str, Any],
) -> None:
    """Pydantic-Schema validiert strikt pro Vulnerability (z.B. Severity-Literal).

    `Envelope.model_validate` wirft `ValidationError` fuer ungueltige Items.
    Das ist erwartetes Verhalten — die HTTP-Route gibt 422 zurueck.
    """
    with pytest.raises(ValidationError):
        Envelope.model_validate(_envelope_dict(adversarial_scan))


def test_adversarial_fixture_survives_build_when_per_vuln_filtered(
    adversarial_scan: dict[str, Any],
) -> None:
    """Wenn wir nur die validierbaren Vulns aus adversarial filtern, build die rest."""
    keep_ids = {"CVE-2026-00002", "CVE-2026-00009", "CVE-2026-00010"}
    filtered = json.loads(json.dumps(adversarial_scan))
    for result in filtered["Results"]:
        result["Vulnerabilities"] = [
            v for v in result["Vulnerabilities"] if v["VulnerabilityID"] in keep_ids
        ]

    envelope = Envelope.model_validate(_envelope_dict(filtered))
    rows = _build_rows(envelope)

    # Alle 3 IDs durchgekommen.
    persisted_ids = {r["identifier_key"] for r in rows}
    assert keep_ids.issubset(persisted_ids), persisted_ids
    assert len(rows) == 3

    # CWE-Stripping: CVE-2026-00009 hatte [CWE-79, NOT-A-CWE, CWE-12345678]
    cwe_row = next(r for r in rows if r["identifier_key"] == "CVE-2026-00009")
    assert cwe_row["cwe_ids"] == ["CWE-79"], cwe_row["cwe_ids"]

    # Reference-Stripping: nur https-URLs.
    ref_row = next(r for r in rows if r["identifier_key"] == "CVE-2026-00010")
    assert ref_row["references"] == ["https://example.com/ok"], ref_row["references"]


# ---------------------------------------------------------------------------
# Resolve-Set-Berechnung (Python-Logic, ohne SQL).
# ---------------------------------------------------------------------------


def test_resolve_set_with_disjoint_scans() -> None:
    """Scan 1 hat (CVE-1, pkg-a); Scan 2 hat (CVE-2, pkg-b).

    Resolve-Set = OPEN/ACK-Findings deren `(identifier_key, package_name)` NICHT
    im current_keys-Set des aktuellen Scans steckt. Wir replizieren die Logic
    hier in Python ohne `ingest_scan`/SQL.
    """
    # Aktueller Scan: nur pkg-b.
    scan_b = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.70.0"},
        "Results": [
            {
                "Target": "alpine 3.18",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-20002",
                        "PkgName": "pkg-b",
                        "InstalledVersion": "2.0",
                        "Severity": "MEDIUM",
                        "Title": "scan b only",
                    }
                ],
            }
        ],
    }
    env_b = Envelope.model_validate(_envelope_dict(scan_b))
    rows_b = _build_rows(env_b)
    current_keys = {(r["identifier_key"], r["package_name"]) for r in rows_b}
    assert current_keys == {("CVE-2024-20002", "pkg-b")}

    # Bestand vor dem Scan: (CVE-1, pkg-a) ist OPEN.
    existing = [
        ("CVE-2024-10001", "pkg-a", FindingStatus.OPEN),
        ("CVE-2024-20002", "pkg-b", FindingStatus.OPEN),
    ]
    to_resolve = [(cve, pkg) for cve, pkg, _st in existing if (cve, pkg) not in current_keys]
    assert to_resolve == [("CVE-2024-10001", "pkg-a")]


# ---------------------------------------------------------------------------
# Smoke: `_safe_vuln` swallowt kaputtes Per-Vuln-Item ohne zu werfen.
# ---------------------------------------------------------------------------


def test_safe_vuln_returns_none_for_invalid_payload() -> None:
    """Ein offensichtlich kaputtes Vuln-Dict (z.B. fehlende Pflichtfelder) → None."""
    bad = {"VulnerabilityID": "CVE-2024-FOO"}  # PkgName/InstalledVersion fehlen.
    assert _safe_vuln(bad, server_name="srv") is None


def test_safe_vuln_returns_model_for_valid_payload() -> None:
    payload = {
        "VulnerabilityID": "CVE-2024-99999",
        "PkgName": "openssl",
        "InstalledVersion": "1.0",
        "Severity": "HIGH",
    }
    vuln = _safe_vuln(payload, server_name="srv")
    assert isinstance(vuln, TrivyVulnerability)
    assert vuln.vulnerability_id == "CVE-2024-99999"
    assert vuln.severity == "HIGH"


# ---------------------------------------------------------------------------
# Smoke: Severity-Map ist vollstaendig.
# ---------------------------------------------------------------------------


def test_severity_map_covers_all_trivy_levels() -> None:
    """`_SEVERITY_MAP` ist die Single-Source-of-Truth fuer Trivy-Severity-Strings."""
    assert set(_SEVERITY_MAP.keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
    assert _SEVERITY_MAP["CRITICAL"] is Severity.CRITICAL
    assert _SEVERITY_MAP["UNKNOWN"] is Severity.UNKNOWN
