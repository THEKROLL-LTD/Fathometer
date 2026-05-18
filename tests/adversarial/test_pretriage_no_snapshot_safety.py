"""Adversarial: Pre-Triage ohne Snapshot landet IMMER in UNKNOWN.

Block O, ADR-0022 §Pre-Triage-Algorithmus, Regel 1:

> Wenn `snapshot_available=False` (Agent < v0.3.0 oder Snapshot-Parse-Fehler):
> Output ist IMMER `UNKNOWN`. Kein silent-Fallback auf Severity-/KEV-/EPSS-
> basierte Klassifikation — der Operator muss sehen dass der Snapshot fehlt.

`UNKNOWN` ist in `ACTION_REQUIRED_MAP` auf `YES` gemappt (konservativer
Default — Security-Auditor-Punkt 2). Diese Eigenschaft testen wir hier in
allen Severity/EPSS/KEV-Variationen, damit ein zukuenftiger Refactor des
Algorithmus diese harte Invariante nicht stillschweigend verletzen kann.
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
from app.services.risk_engine import ACTION_REQUIRED_MAP, ActionRequired, RiskBand, pretriage


def _make_finding(
    *,
    severity: Severity,
    epss: float | None,
    is_kev: bool,
    severity_by_provider: dict[str, str] | None = None,
) -> Finding:
    """In-Memory-Finding ohne DB — Pre-Triage ist pure-function-Code."""
    now = datetime.now(tz=UTC)
    return Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key="CVE-2024-99001",
        package_name="testpkg",
        installed_version="1.0",
        severity=severity,
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        epss_score=epss,
        is_kev=is_kev,
        first_seen_at=now,
        last_seen_at=now,
        severity_by_provider=severity_by_provider,
    )


def _make_server() -> Server:
    """In-Memory-Server ohne DB."""
    return Server(
        id=1,
        name="srv-no-snapshot-test",
        api_key_hash="x" * 64,
        expected_scan_interval_h=24,
        os_family="ubuntu",
    )


# ---------------------------------------------------------------------------
# Tabelle: Severity x EPSS x KEV — alle Eingaben muessen UNKNOWN liefern,
# wenn der Snapshot fehlt.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "epss", "is_kev"),
    [
        # CRITICAL + KEV + hoher EPSS — wuerde mit Snapshot in PENDING landen.
        (Severity.CRITICAL, 0.95, True),
        # HIGH + halber EPSS.
        (Severity.HIGH, 0.5, False),
        # HIGH ohne EPSS-Daten.
        (Severity.HIGH, None, False),
        # MEDIUM + EPSS knapp ueber Schwelle (sonst PENDING).
        (Severity.MEDIUM, 0.15, False),
        # MEDIUM + niedriger EPSS (sonst MONITOR).
        (Severity.MEDIUM, 0.05, False),
        # LOW ohne EPSS, nicht KEV (sonst NOISE).
        (Severity.LOW, 0.001, False),
        # LOW + KEV (sonst PENDING).
        (Severity.LOW, 0.0, True),
        # UNKNOWN-Severity.
        (Severity.UNKNOWN, 0.0, False),
        # CRITICAL ohne KEV, ohne EPSS.
        (Severity.CRITICAL, None, False),
    ],
)
def test_pretriage_without_snapshot_is_always_unknown(
    severity: Severity, epss: float | None, is_kev: bool
) -> None:
    """Egal welche Severity-/EPSS-/KEV-Kombination — ohne Snapshot UNKNOWN.

    Dies ist die maximal konservative Default-Policy: solange wir den Host-
    Kontext nicht kennen, faellen wir die Pre-Triage-Entscheidung nicht.
    """
    finding = _make_finding(severity=severity, epss=epss, is_kev=is_kev)
    server = _make_server()

    evaluation = pretriage(finding, server, snapshot_available=False)

    assert evaluation.band is RiskBand.UNKNOWN, (
        f"Erwartet UNKNOWN bei Severity={severity}, EPSS={epss}, KEV={is_kev}, "
        f"got {evaluation.band}"
    )
    assert evaluation.source == "engine"
    # Reason muss den Snapshot-Mangel erklaeren (Operator-Hint).
    assert "host snapshot missing" in evaluation.reason, (
        f"Reason muss 'host snapshot missing' enthalten, ist: {evaluation.reason!r}"
    )


# ---------------------------------------------------------------------------
# Provider-Map-Variation: ein einzelner CRITICAL-Provider darf ohne Snapshot
# NICHT in PENDING durchsickern. Hier wuerde der Severity-Resolver bei
# vorhandenem Snapshot HIGH/CRITICAL melden — ohne Snapshot ist die Antwort
# trotzdem UNKNOWN.
# ---------------------------------------------------------------------------


def test_pretriage_without_snapshot_ignores_provider_map() -> None:
    """`severity_by_provider={"nvd":"critical"}` ohne Snapshot -> UNKNOWN.

    Garantie: kein silent-Fallback auf den Provider-Resolver-Pfad. Das ist
    eine harte Invariante der Engine — der Snapshot ist Voraussetzung fuer
    JEDE Severity-basierte Entscheidung.
    """
    finding = _make_finding(
        severity=Severity.LOW,
        epss=0.0,
        is_kev=False,
        severity_by_provider={"nvd": "critical", "ubuntu": "high"},
    )
    server = _make_server()
    evaluation = pretriage(finding, server, snapshot_available=False)

    assert evaluation.band is RiskBand.UNKNOWN
    assert "host snapshot missing" in evaluation.reason


# ---------------------------------------------------------------------------
# Action-Required-Konsistenz: UNKNOWN muss `action_required=yes` ergeben.
# Wenn jemand die Map versehentlich aendert, faellt dieser Test auf.
# ---------------------------------------------------------------------------


def test_unknown_band_maps_to_action_required_yes() -> None:
    """UNKNOWN ist Operator-Konservativ: wird in der UI als 'action needed' angezeigt.

    Wenn jemand `ACTION_REQUIRED_MAP[UNKNOWN]` versehentlich auf `NO` aendert,
    wuerde ein Server ohne Snapshot in den 'Safe'-Bucket fallen — exakt das
    Verhalten das ADR-0022 §Risk-Band-Modell verbietet.
    """
    assert ACTION_REQUIRED_MAP[RiskBand.UNKNOWN] is ActionRequired.YES


# ---------------------------------------------------------------------------
# Sanity-Negativ-Test: mit `snapshot_available=True` und gleicher Eingabe
# wuerde die Engine NICHT UNKNOWN melden — dieser Test ist die Brueck-Garantie
# dass die UNKNOWN-Antwort wirklich am `snapshot_available`-Flag haengt und
# nicht etwa an irgendeiner anderen Bedingung.
# ---------------------------------------------------------------------------


def test_pretriage_with_snapshot_does_not_return_unknown_for_low_input() -> None:
    """Sanity: gleiches Finding mit `snapshot_available=True` ist NICHT UNKNOWN."""
    finding = _make_finding(severity=Severity.LOW, epss=0.001, is_kev=False)
    server = _make_server()
    evaluation = pretriage(finding, server, snapshot_available=True)

    assert evaluation.band is not RiskBand.UNKNOWN
    assert evaluation.band is RiskBand.NOISE  # konkrete Klassifikation: LOW/no-EPSS/no-KEV
