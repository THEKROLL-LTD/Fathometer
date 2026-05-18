"""Adversarial: KEV/Severity/EPSS-Kombinationen muessen deterministisch
in PENDING bzw. MONITOR/NOISE landen (Block O, ADR-0022 §Pre-Triage-Algorithmus).

Security-Auditor-Punkt #1 (ADR-0022): „Tabellen-Tests muessen alle
KEV+HIGH+EPSS-Kombinationen abdecken, die in `pending` landen muessen."

Garantie dieses Tests:
  * Kein silent-Demote eines echten Triage-Kandidaten zu MONITOR/NOISE.
  * Kein silent-Promote eines harmlosen Findings zu PENDING.
  * Die Regel-Reihenfolge im `pretriage()`-Code (Snapshot -> KEV -> HIGH+
    -> EPSS >= 0.1 -> MEDIUM -> sonst NOISE) ist die Single-Source-of-
    Truth — dieser Test pruefen die Tabelle gegen das beobachtete Verhalten.

Wenn ein zukuenftiger Refactor die Cuts verschiebt (z.B. EPSS-Schwelle
0.05 statt 0.1), faellt dieser Test auf und der Refactor wird sichtbar.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)
from app.services.risk_engine import RiskBand, pretriage


def _make_finding(severity: Severity, *, epss: float, is_kev: bool) -> Finding:
    """In-Memory-Finding ohne DB."""
    now = datetime.now(tz=UTC)
    return Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key="CVE-2024-91001",
        package_name="combopkg",
        installed_version="1.0",
        severity=severity,
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        epss_score=epss,
        is_kev=is_kev,
        first_seen_at=now,
        last_seen_at=now,
    )


def _make_server() -> Server:
    return Server(
        id=1,
        name="srv-combo-test",
        api_key_hash="x" * 64,
        expected_scan_interval_h=24,
        os_family="ubuntu",
    )


# ---------------------------------------------------------------------------
# Tabelle der erwarteten PENDING-Cases.
#
# Cases die MUESSEN in PENDING landen:
#   * KEV=True x jede Severity x jeder EPSS (KEV-Override schlaegt alles).
#   * HIGH/CRITICAL x KEV=False x jeder EPSS (Severity-Trigger).
#   * MEDIUM/LOW x KEV=False x EPSS >= 0.1 (EPSS-Trigger).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "epss", "is_kev", "trigger_label"),
    [
        # ---- KEV-Override (egal Severity, egal EPSS) ----
        (Severity.CRITICAL, 0.95, True, "KEV+CRITICAL+high-EPSS"),
        (Severity.CRITICAL, 0.0, True, "KEV+CRITICAL+zero-EPSS"),
        (Severity.HIGH, 0.5, True, "KEV+HIGH+mid-EPSS"),
        (Severity.HIGH, 0.0, True, "KEV+HIGH+zero-EPSS"),
        (Severity.MEDIUM, 0.05, True, "KEV+MEDIUM+sub-threshold-EPSS"),
        (Severity.LOW, 0.001, True, "KEV+LOW+near-zero-EPSS"),
        (Severity.UNKNOWN, 0.0, True, "KEV+UNKNOWN+zero-EPSS"),
        # ---- HIGH/CRITICAL ohne KEV ----
        (Severity.CRITICAL, 0.001, False, "CRITICAL+low-EPSS-no-KEV"),
        (Severity.HIGH, 0.001, False, "HIGH+low-EPSS-no-KEV"),
        (Severity.HIGH, 0.99, False, "HIGH+high-EPSS-no-KEV"),
        # ---- EPSS-Trigger ohne KEV und ohne HIGH+ ----
        (Severity.MEDIUM, 0.1, False, "MEDIUM+EPSS-exact-threshold-no-KEV"),
        (Severity.MEDIUM, 0.15, False, "MEDIUM+EPSS-above-threshold-no-KEV"),
        (Severity.LOW, 0.5, False, "LOW+high-EPSS-no-KEV"),
    ],
)
def test_pending_required_combinations(
    severity: Severity, epss: float, is_kev: bool, trigger_label: str
) -> None:
    """Diese Kombinationen MUESSEN in PENDING landen — kein silent-Demote."""
    finding = _make_finding(severity, epss=epss, is_kev=is_kev)
    server = _make_server()

    evaluation = pretriage(finding, server, snapshot_available=True)

    assert evaluation.band is RiskBand.PENDING, (
        f"[{trigger_label}] Erwartet PENDING, got {evaluation.band.value} — "
        f"silent demote eines Triage-Kandidaten."
    )
    assert evaluation.source == "engine"
    # Reason erklaert WARUM pending — wichtig fuer Operator-Diagnose.
    assert "pending LLM review" in evaluation.reason, (
        f"[{trigger_label}] Reason muss 'pending LLM review' enthalten, ist: {evaluation.reason!r}"
    )


# ---------------------------------------------------------------------------
# Tabelle der erwarteten NICHT-PENDING-Cases.
#
# Cases die NICHT in PENDING landen duerfen:
#   * MEDIUM x KEV=False x EPSS < 0.1 -> MONITOR.
#   * LOW x KEV=False x EPSS < 0.1 -> NOISE.
#   * UNKNOWN-Severity x KEV=False x EPSS < 0.1 -> NOISE
#     (UNKNOWN-rank = 0, kleiner als MEDIUM, also NOISE).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "epss", "is_kev", "expected_band", "trigger_label"),
    [
        # MEDIUM mit sub-threshold-EPSS -> MONITOR (nicht NOISE!).
        (Severity.MEDIUM, 0.0, False, RiskBand.MONITOR, "MEDIUM+zero-EPSS-no-KEV"),
        (Severity.MEDIUM, 0.05, False, RiskBand.MONITOR, "MEDIUM+sub-threshold-EPSS-no-KEV"),
        (Severity.MEDIUM, 0.099, False, RiskBand.MONITOR, "MEDIUM+just-below-threshold-no-KEV"),
        # LOW mit sub-threshold-EPSS -> NOISE.
        (Severity.LOW, 0.0, False, RiskBand.NOISE, "LOW+zero-EPSS-no-KEV"),
        (Severity.LOW, 0.001, False, RiskBand.NOISE, "LOW+near-zero-EPSS-no-KEV"),
        (Severity.LOW, 0.099, False, RiskBand.NOISE, "LOW+just-below-threshold-no-KEV"),
        # UNKNOWN-Severity -> NOISE.
        (Severity.UNKNOWN, 0.0, False, RiskBand.NOISE, "UNKNOWN+zero-EPSS-no-KEV"),
    ],
)
def test_non_pending_combinations(
    severity: Severity,
    epss: float,
    is_kev: bool,
    expected_band: RiskBand,
    trigger_label: str,
) -> None:
    """Diese Kombinationen MUESSEN NICHT in PENDING landen — kein silent-Promote."""
    finding = _make_finding(severity, epss=epss, is_kev=is_kev)
    server = _make_server()

    evaluation = pretriage(finding, server, snapshot_available=True)

    assert evaluation.band is expected_band, (
        f"[{trigger_label}] Erwartet {expected_band.value}, got {evaluation.band.value} — "
        f"silent promote oder fehlklassifiziert."
    )
    # Insbesondere darf das nicht PENDING sein (separate Assertion fuer
    # klare Failure-Message).
    assert evaluation.band is not RiskBand.PENDING, (
        f"[{trigger_label}] silent-promote zu PENDING entdeckt — "
        f"defensiver Schutz gegen Cut-Drift in `pretriage()`."
    )


# ---------------------------------------------------------------------------
# Edge: EPSS EXAKT auf der Schwelle. Wir verlassen uns auf das `>=`-Verhalten
# in `pretriage()` (`if epss >= EPSS_PENDING_THRESHOLD`). Wenn jemand das
# auf `>` aendert, faellt dieser Test auf.
# ---------------------------------------------------------------------------


def test_epss_exact_threshold_triggers_pending() -> None:
    """EPSS = 0.1 (genauer Cut-Punkt) loest PENDING aus — `>=` nicht `>`."""
    finding = _make_finding(Severity.LOW, epss=0.1, is_kev=False)
    server = _make_server()
    evaluation = pretriage(finding, server, snapshot_available=True)
    assert evaluation.band is RiskBand.PENDING, (
        "EPSS=0.1 (genauer Cut) sollte PENDING ausloesen; wenn nicht, wurde der "
        "Operator >= zu > geaendert."
    )
    # Reason-Marker: enthaelt `EPSS 0.10`.
    assert "EPSS 0.10" in evaluation.reason


def test_epss_just_below_threshold_no_pending() -> None:
    """EPSS = 0.099 (knapp unter Cut) -> kein PENDING-Trigger."""
    finding = _make_finding(Severity.LOW, epss=0.099, is_kev=False)
    server = _make_server()
    evaluation = pretriage(finding, server, snapshot_available=True)
    assert evaluation.band is RiskBand.NOISE


# ---------------------------------------------------------------------------
# Provider-Map-Variation: ein einzelner HIGH/CRITICAL-Provider muss als
# Trigger reichen — `max_severity_across_providers()` ist das Eingabe-Signal.
# ---------------------------------------------------------------------------


def test_single_critical_provider_triggers_pending() -> None:
    """`severity_by_provider={"nvd":"critical"}` -> PENDING, auch wenn
    Top-Level-Severity LOW ist (Trivy uneinig ueber Provider hinweg)."""
    now = datetime.now(tz=UTC)
    finding = Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key="CVE-2024-91002",
        package_name="multi-prov",
        installed_version="1.0",
        severity=Severity.LOW,  # Top-Level LOW
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        epss_score=0.0,
        is_kev=False,
        first_seen_at=now,
        last_seen_at=now,
        severity_by_provider={"nvd": "critical", "ubuntu": "low"},
    )
    server = _make_server()
    evaluation = pretriage(finding, server, snapshot_available=True)

    assert evaluation.band is RiskBand.PENDING, (
        f"Max-over-providers muss CRITICAL liefern -> PENDING. got {evaluation.band.value}."
    )
    # Reason zeigt `max-severity CRITICAL`.
    assert "CRITICAL" in evaluation.reason.upper()
