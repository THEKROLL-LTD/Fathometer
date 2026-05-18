"""Block O Phase B (ADR-0022 §Pre-Triage-Algorithmus) — Tabellen-Tests.

~30 Cases via `pytest.mark.parametrize` decken alle Severity x EPSS x KEV-
Kombinationen sowie Snapshot-Fehlt-, Boundary- und max-over-providers-
Faelle ab. Reason-String-Substring-Checks sind separat ausgelagert.

Performance-Bench (`pytest.mark.bench`): 10000 Findings x pretriage < 100 ms.
Wird in der Default-Suite via `-m "not bench"` ausgeschlossen.
"""

from __future__ import annotations

import time

import pytest

from app.models import Finding, FindingClass, FindingType, Server, Severity
from app.services.risk_engine import RiskBand, pretriage


def _f(
    *,
    severity: Severity = Severity.UNKNOWN,
    epss: float | None = None,
    is_kev: bool = False,
    severity_by_provider: dict[str, str] | None = None,
) -> Finding:
    f = Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key="CVE-2024-9999",
        package_name="testpkg",
        severity=severity,
    )
    f.epss_score = epss
    f.is_kev = is_kev
    f.severity_by_provider = severity_by_provider
    return f


def _s() -> Server:
    s = Server(name="test-host", api_key_hash="x" * 64, expected_scan_interval_h=24)
    s.os_family = "ubuntu"
    return s


# ---------------------------------------------------------------------------
# Tabellen-Tests: Severity x EPSS x KEV -> erwarteter Band
# ---------------------------------------------------------------------------


_PRETRIAGE_CASES = [
    # id, severity, epss, kev, expected_band
    ("low+low-epss+no-kev -> noise", Severity.LOW, 0.001, False, RiskBand.NOISE),
    ("unknown+zero-epss+no-kev -> noise", Severity.UNKNOWN, 0.0, False, RiskBand.NOISE),
    ("medium+low-epss+no-kev -> monitor", Severity.MEDIUM, 0.05, False, RiskBand.MONITOR),
    ("medium+high-epss+no-kev -> pending (epss)", Severity.MEDIUM, 0.15, False, RiskBand.PENDING),
    ("medium+low-epss+kev -> pending (kev)", Severity.MEDIUM, 0.001, True, RiskBand.PENDING),
    ("high+low-epss+no-kev -> pending (high)", Severity.HIGH, 0.001, False, RiskBand.PENDING),
    ("high+zero-epss+no-kev -> pending (high)", Severity.HIGH, 0.0, False, RiskBand.PENDING),
    ("critical+any -> pending", Severity.CRITICAL, 0.5, False, RiskBand.PENDING),
    ("critical+high-epss+kev -> pending", Severity.CRITICAL, 0.9, True, RiskBand.PENDING),
    ("low+low-epss+kev -> pending (kev override)", Severity.LOW, 0.001, True, RiskBand.PENDING),
    (
        "unknown+zero-epss+kev -> pending (kev override)",
        Severity.UNKNOWN,
        0.0,
        True,
        RiskBand.PENDING,
    ),
    # EPSS Boundary
    ("medium+epss==0.1 -> pending", Severity.MEDIUM, 0.1, False, RiskBand.PENDING),
    ("medium+epss==0.0999 -> monitor", Severity.MEDIUM, 0.0999, False, RiskBand.MONITOR),
    ("low+epss==0.1 -> pending", Severity.LOW, 0.1, False, RiskBand.PENDING),
    ("low+epss==0.0999 -> noise", Severity.LOW, 0.0999, False, RiskBand.NOISE),
    # epss=None gleichbedeutend zu 0.0
    ("medium+epss==None+no-kev -> monitor", Severity.MEDIUM, None, False, RiskBand.MONITOR),
    ("low+epss==None+no-kev -> noise", Severity.LOW, None, False, RiskBand.NOISE),
    ("low+epss==None+kev -> pending", Severity.LOW, None, True, RiskBand.PENDING),
]


@pytest.mark.parametrize(
    "case_id,severity,epss,kev,expected",
    _PRETRIAGE_CASES,
    ids=[c[0] for c in _PRETRIAGE_CASES],
)
def test_pretriage_table(
    case_id: str,
    severity: Severity,
    epss: float | None,
    kev: bool,
    expected: RiskBand,
) -> None:
    """Decken die Sev x EPSS x KEV-Matrix aus ADR-0022 §Pre-Triage."""
    f = _f(severity=severity, epss=epss, is_kev=kev)
    s = _s()
    result = pretriage(f, s, snapshot_available=True)
    assert result.band is expected, f"{case_id}: got {result.band}, expected {expected}"


# ---------------------------------------------------------------------------
# Snapshot fehlt -> UNKNOWN (egal welche Severity/EPSS/KEV)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity,epss,kev",
    [
        (Severity.CRITICAL, 0.95, True),
        (Severity.HIGH, 0.5, False),
        (Severity.MEDIUM, 0.1, False),
        (Severity.LOW, 0.01, False),
        (Severity.UNKNOWN, 0.0, False),
    ],
)
def test_pretriage_no_snapshot_always_unknown(severity: Severity, epss: float, kev: bool) -> None:
    """Adversarial-Garantie aus ADR-0022 §Risk-Band-Modell: kein Snapshot -> UNKNOWN."""
    f = _f(severity=severity, epss=epss, is_kev=kev)
    s = _s()
    result = pretriage(f, s, snapshot_available=False)
    assert result.band is RiskBand.UNKNOWN
    assert "snapshot" in result.reason.lower()
    assert "0.3.0" in result.reason


# ---------------------------------------------------------------------------
# max-over-providers triggert PENDING wenn EIN Provider HIGH ist
# ---------------------------------------------------------------------------


def test_pretriage_max_over_providers_promotes_to_pending() -> None:
    """NVD=HIGH, Ubuntu=LOW, finding.severity=LOW -> PENDING (max = HIGH)."""
    f = _f(
        severity=Severity.LOW,
        severity_by_provider={"nvd": "high", "ubuntu": "low"},
    )
    s = _s()
    result = pretriage(f, s, snapshot_available=True)
    assert result.band is RiskBand.PENDING
    assert "HIGH" in result.reason


def test_pretriage_max_over_providers_critical_in_one_provider() -> None:
    """Nur ein Provider critical -> PENDING (max trigger)."""
    f = _f(
        severity=Severity.MEDIUM,
        severity_by_provider={"nvd": "critical", "ubuntu": "medium"},
    )
    s = _s()
    result = pretriage(f, s, snapshot_available=True)
    assert result.band is RiskBand.PENDING
    assert "CRITICAL" in result.reason


def test_pretriage_provider_map_all_low_no_trigger() -> None:
    """Alle Provider LOW, finding.severity LOW, kein KEV, low EPSS -> NOISE."""
    f = _f(
        severity=Severity.LOW,
        severity_by_provider={"nvd": "low", "ubuntu": "low"},
        epss=0.001,
    )
    s = _s()
    result = pretriage(f, s, snapshot_available=True)
    assert result.band is RiskBand.NOISE


# ---------------------------------------------------------------------------
# Reason-Strings
# ---------------------------------------------------------------------------


def test_pretriage_noise_reason_substrings() -> None:
    """`noise` Reason enthaelt 'all providers <= LOW' und 'not KEV'."""
    f = _f(severity=Severity.LOW, epss=0.001)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.band is RiskBand.NOISE
    assert "LOW" in result.reason
    assert "not KEV" in result.reason
    assert "EPSS" in result.reason


def test_pretriage_monitor_reason_substrings() -> None:
    """`monitor` Reason erwaehnt MEDIUM und EPSS."""
    f = _f(severity=Severity.MEDIUM, epss=0.05)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.band is RiskBand.MONITOR
    assert "MEDIUM" in result.reason
    assert "EPSS" in result.reason
    assert "not KEV" in result.reason


def test_pretriage_pending_high_reason_substrings() -> None:
    """`pending` (HIGH) enthaelt 'max-severity HIGH' und 'pending LLM review'."""
    f = _f(severity=Severity.HIGH, epss=0.001)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.band is RiskBand.PENDING
    assert "max-severity HIGH" in result.reason
    assert "pending LLM review" in result.reason


def test_pretriage_pending_kev_reason_substrings() -> None:
    """`pending` (KEV) enthaelt 'KEV listed' an erster Stelle."""
    f = _f(severity=Severity.MEDIUM, epss=0.001, is_kev=True)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.band is RiskBand.PENDING
    assert result.reason.startswith("KEV listed")
    assert "pending LLM review" in result.reason


def test_pretriage_pending_epss_reason_substrings() -> None:
    """`pending` (EPSS) enthaelt 'EPSS ... >= 0.1' Format."""
    f = _f(severity=Severity.MEDIUM, epss=0.15)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.band is RiskBand.PENDING
    assert "EPSS 0.15" in result.reason
    assert ">= 0.1" in result.reason


def test_pretriage_pending_kev_combined_with_severity_and_epss() -> None:
    """`pending` mit KEV+HIGH+EPSS -> alle drei Parts plus 'pending LLM review'."""
    f = _f(severity=Severity.CRITICAL, epss=0.5, is_kev=True)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.band is RiskBand.PENDING
    assert "KEV listed" in result.reason
    assert "max-severity CRITICAL" in result.reason
    assert "EPSS 0.50" in result.reason
    assert "pending LLM review" in result.reason


def test_pretriage_reason_length_capped() -> None:
    """Reason-Strings sind hart auf 256 Chars gecapped (DB-Spalte)."""
    f = _f(severity=Severity.CRITICAL, epss=0.99, is_kev=True)
    result = pretriage(f, _s(), snapshot_available=True)
    assert len(result.reason) <= 256


# ---------------------------------------------------------------------------
# RiskEvaluation-Metadaten
# ---------------------------------------------------------------------------


def test_pretriage_result_has_engine_source_and_timestamp() -> None:
    f = _f(severity=Severity.LOW, epss=0.001)
    result = pretriage(f, _s(), snapshot_available=True)
    assert result.source == "engine"
    assert result.computed_at is not None
    assert result.computed_at.tzinfo is not None  # tz-aware


# ---------------------------------------------------------------------------
# Performance-Bench — 10000 Findings < 100 ms
# ---------------------------------------------------------------------------


@pytest.mark.bench
def test_pretriage_performance_10k_findings_under_100ms() -> None:
    """Block-O-Brief DoD: 10000 Findings x pretriage() < 100 ms."""
    findings = [
        _f(
            severity=Severity.MEDIUM,
            epss=0.05,
            is_kev=(i % 50 == 0),
            severity_by_provider={"nvd": "medium", "ubuntu": "low"} if i % 3 == 0 else None,
        )
        for i in range(10_000)
    ]
    server = _s()
    t0 = time.perf_counter()
    for f in findings:
        pretriage(f, server, snapshot_available=True)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert elapsed_ms < 100.0, f"pretriage too slow: {elapsed_ms:.2f} ms for 10k findings"
