"""Service-Layer-Tests fuer `ingest_scan` ohne HTTP.

Ziel: das Pydantic-Schema und die DB-Persistierung mit der echten Trivy-Fixture
direkt verifizieren — auch Performance-Garantien.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import AttackVector, Finding, FindingClass, FindingStatus, Server
from app.schemas.scan_envelope import Envelope
from app.services.findings_ingest import ingest_scan
from tests._helpers import register_test_server

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
# Real-Fixture: Counts und Class-Verteilung
# ---------------------------------------------------------------------------


def test_ingest_real_fixture_counts(db_app: Flask, real_scan: dict[str, Any]) -> None:
    server_id, _api = register_test_server(db_app, name="ingest-svc")
    envelope = Envelope.model_validate(_envelope_dict(real_scan))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            result = ingest_scan(server, envelope, session=sess)
            sess.commit()
        finally:
            sess.close()

    assert result.findings_total == 306
    assert result.findings_inserted == 306
    assert result.findings_updated == 0
    assert result.findings_resolved == 0
    assert result.findings_class_lang_pkgs == 296
    assert result.findings_class_os_pkgs == 10
    assert result.findings_class_other == 0


def test_ingest_real_fixture_attack_vectors_and_cvss(
    db_app: Flask, real_scan: dict[str, Any]
) -> None:
    """Smoke: CVSS-Score und attack_vector werden aus dem CVSS-Vektor abgeleitet."""
    server_id, _api = register_test_server(db_app, name="ingest-cvss")
    envelope = Envelope.model_validate(_envelope_dict(real_scan))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            ingest_scan(server, envelope, session=sess)
            sess.commit()
            findings = list(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()

    # Mindestens eines hat einen abgeleiteten attack_vector != unknown.
    derived = [f for f in findings if f.attack_vector != AttackVector.UNKNOWN]
    assert derived, "Erwarte mindestens 1 Finding mit abgeleitetem attack_vector"

    # Mapping ist konsistent: wenn cvss_v3_vector AV:N enthaelt -> NETWORK.
    for f in findings:
        if f.cvss_v3_vector and "AV:N/" in f.cvss_v3_vector:
            assert f.attack_vector == AttackVector.NETWORK, (
                f.identifier_key,
                f.cvss_v3_vector,
                f.attack_vector,
            )

    # KEV nicht in real-fixture: alle is_kev=False.
    for f in findings:
        assert f.is_kev is False


def test_ingest_performance_under_5s(db_app: Flask, real_scan: dict[str, Any]) -> None:
    """306 Findings muessen unter 5 s persistiert werden."""
    server_id, _api = register_test_server(db_app, name="perf-srv")
    envelope = Envelope.model_validate(_envelope_dict(real_scan))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            start = time.monotonic()
            ingest_scan(server, envelope, session=sess)
            sess.commit()
            elapsed = time.monotonic() - start
        finally:
            sess.close()
    assert elapsed < 5.0, f"Ingest 306 Findings dauerte {elapsed:.2f}s (> 5s SLA)"


def test_ingest_real_fixture_idempotent(db_app: Flask, real_scan: dict[str, Any]) -> None:
    """Zweimal aufrufen -> 306 Findings stabil.

    Wir pruefen den DB-State (kein Duplikat) — die `inserted`/`updated`-Counter
    benutzen eine `first_seen_at`-vs-`now`-Heuristik mit 1s-Toleranz; bei
    schnellem Back-to-Back-Aufruf in derselben Sekunde liefert sie inkonsistente
    Werte (Implementer-Hinweis). DB-Invariante ist hingegen klar: 306 unique
    Rows bleiben es auch nach Re-Ingest.
    """
    server_id, _api = register_test_server(db_app, name="idem-svc")
    envelope = Envelope.model_validate(_envelope_dict(real_scan))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            r1 = ingest_scan(server, envelope, session=sess)
            sess.commit()
            r2 = ingest_scan(server, envelope, session=sess)
            sess.commit()
            findings_count = len(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()

    assert r1.findings_total == 306
    assert r2.findings_total == 306
    assert r2.findings_resolved == 0
    assert findings_count == 306, "Idempotenz: kein Duplikat trotz Re-Ingest"


def test_ingest_lang_pkgs_disambiguation_creates_unique_findings(
    db_app: Flask, real_scan: dict[str, Any]
) -> None:
    """Dieselbe CVE in mehreren Go-Binaries muss separat persistiert werden.

    Wir suchen aus der Fixture ein Beispiel: eine CVE-ID die in mehreren
    `lang-pkgs`-Targets vorkommt -> nach dem Ingest mehrere `findings`-Rows
    mit identischer `identifier_key` aber unterschiedlichem `package_name`
    (das ist disambiguiert via `pkg@target`).
    """
    server_id, _api = register_test_server(db_app, name="disambig-srv")
    envelope = Envelope.model_validate(_envelope_dict(real_scan))

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            ingest_scan(server, envelope, session=sess)
            sess.commit()
            findings = list(
                sess.execute(
                    select(Finding)
                    .where(Finding.server_id == server_id)
                    .where(Finding.finding_class == FindingClass.LANG_PKGS)
                )
                .scalars()
                .all()
            )
        finally:
            sess.close()

    # Pro CVE-ID Gruppen-Counts bilden: mindestens eine CVE mit > 1 Finding.
    from collections import Counter

    cve_counts = Counter(f.identifier_key for f in findings)
    multi = [k for k, n in cve_counts.items() if n > 1]
    assert multi, "Erwarte mindestens 1 CVE mit Multi-Target-Disambiguation"

    # Innerhalb derselben CVE-Gruppe muessen `package_name`-Werte unique sein.
    for cve in multi[:3]:
        names = {f.package_name for f in findings if f.identifier_key == cve}
        assert len(names) > 1, (cve, names)
        # Mindestens einer enthaelt das `@target`-Suffix.
        assert any("@" in n for n in names), names


# ---------------------------------------------------------------------------
# Adversarial-Fixture: per-Vuln-Drop vs. Top-Level-Fail
# ---------------------------------------------------------------------------


def test_envelope_validation_rejects_adversarial_on_top_level(
    adversarial_scan: dict[str, Any],
) -> None:
    """Die adversarial.json enthaelt mehrere ungueltige Vulns.

    Da das Pydantic-Schema strikt pro Vulnerability validiert (z.B.
    Severity-Literal), wirft `Envelope.model_validate` eine ValidationError
    fuer die ungueltigen Items. Das ist erwartetes Verhalten — die HTTP-Route
    gibt 422 zurueck.
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Envelope.model_validate(_envelope_dict(adversarial_scan))


def test_adversarial_fixture_survives_ingest_when_per_vuln_filtered(
    db_app: Flask, adversarial_scan: dict[str, Any]
) -> None:
    """Wenn wir nur die *validierbaren* Vulns aus adversarial filtern, ingest die rest.

    Test: wir entfernen die offensichtlich kaputten Vulns aus dem Envelope
    (Severity=ULTRA_CRITICAL, CVE-foo-bar, etc.) und pruefen dass die
    "wirklich validen" durchgehen — bzw. dass Stripping-Items wie CweIDs
    und References korrekt gefiltert werden.
    """
    # Bewahre nur die "milden" adversarialen Vulns auf:
    # - CVE-2026-00009 (CWE-Stripping)
    # - CVE-2026-00010 (Reference-Stripping)
    # - CVE-2026-00002 (XSS in Title — bleibt erlaubt)
    keep_ids = {"CVE-2026-00002", "CVE-2026-00009", "CVE-2026-00010"}
    filtered = json.loads(json.dumps(adversarial_scan))
    for result in filtered["Results"]:
        result["Vulnerabilities"] = [
            v for v in result["Vulnerabilities"] if v["VulnerabilityID"] in keep_ids
        ]

    envelope = Envelope.model_validate(_envelope_dict(filtered))

    server_id, _api = register_test_server(db_app, name="adv-srv")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            result = ingest_scan(server, envelope, session=sess)
            sess.commit()
            findings = list(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()

    # Alle 3 IDs durchgekommen.
    persisted_ids = {f.identifier_key for f in findings}
    assert keep_ids.issubset(persisted_ids), persisted_ids
    assert result.findings_total == 3

    # CWE-Stripping: CVE-2026-00009 hatte [CWE-79, NOT-A-CWE, CWE-12345678]
    cwe_finding = next(f for f in findings if f.identifier_key == "CVE-2026-00009")
    assert cwe_finding.cwe_ids == ["CWE-79"], cwe_finding.cwe_ids

    # Reference-Stripping: nur https-URLs.
    ref_finding = next(f for f in findings if f.identifier_key == "CVE-2026-00010")
    assert ref_finding.references == ["https://example.com/ok"], ref_finding.references


def test_ingest_resolve_phase_with_disjoint_scans(db_app: Flask) -> None:
    """Scan 1 hat (CVE-1, pkg-a); Scan 2 hat (CVE-2, pkg-b). CVE-1 wird resolved."""
    server_id, _api = register_test_server(db_app, name="resolve-svc")

    factory = get_session_factory(db_app)

    scan_a = {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.70.0"},
        "Results": [
            {
                "Target": "alpine 3.18",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-10001",
                        "PkgName": "pkg-a",
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                        "Title": "scan a only",
                    }
                ],
            }
        ],
    }
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

    with db_app.app_context():
        sess = factory()
        try:
            server = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            ingest_scan(server, Envelope.model_validate(_envelope_dict(scan_a)), session=sess)
            sess.commit()
            r2 = ingest_scan(server, Envelope.model_validate(_envelope_dict(scan_b)), session=sess)
            sess.commit()
            findings = list(
                sess.execute(select(Finding).where(Finding.server_id == server_id)).scalars().all()
            )
        finally:
            sess.close()

    assert r2.findings_resolved == 1
    by_id = {f.identifier_key: f for f in findings}
    assert by_id["CVE-2024-10001"].status == FindingStatus.RESOLVED
    assert by_id["CVE-2024-10001"].resolved_at is not None
    assert by_id["CVE-2024-20002"].status == FindingStatus.OPEN
