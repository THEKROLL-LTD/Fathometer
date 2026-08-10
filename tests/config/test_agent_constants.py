"""Block N (ADR-0021) — Plausibilitaets-Checks fuer die Agent/Trivy-Konstanten.

Die Konstanten leben als `ClassVar` auf `app.config.Settings` (kein
`FM_*`-Env-Override), Begruendung siehe ADR-0021 (Selbstabschaltungs-
Falle vermeiden). Tests stellen sicher, dass die Werte zueinander passen,
nicht versehentlich vertauscht wurden (z.B. `MIN > CURRENT`), und die
URL-Template-Platzhalter unverkennbar sind.
"""

from __future__ import annotations

from app.config import Settings
from app.services.agent_version import version_lt


def test_min_agent_is_below_current_agent() -> None:
    """`MIN_AGENT_VERSION` muss strikt kleiner sein als `CURRENT_AGENT_VERSION`."""
    assert version_lt(Settings.MIN_AGENT_VERSION, Settings.CURRENT_AGENT_VERSION) is True, (
        f"MIN={Settings.MIN_AGENT_VERSION} CURRENT={Settings.CURRENT_AGENT_VERSION}"
    )


def test_min_trivy_le_recommended_trivy() -> None:
    """`MIN_TRIVY_VERSION` <= `RECOMMENDED_TRIVY_VERSION`."""
    # `version_lt(a, b)` ist `a < b`. `<=` heisst `not (b < a)`.
    assert version_lt(Settings.RECOMMENDED_TRIVY_VERSION, Settings.MIN_TRIVY_VERSION) is False, (
        f"MIN={Settings.MIN_TRIVY_VERSION} REC={Settings.RECOMMENDED_TRIVY_VERSION}"
    )


def test_ticket015_version_bump_values() -> None:
    """RECOMMENDED-Trivy on 0.73.0 (TICKET-022); agent on 0.11.0 (TICKET-023
    — reads the Trivy DB metadata after the scan instead of before, bumping
    the agent from 0.10.0). MIN-Trivy stays at 0.70.0 deliberately (no hard
    retirement of 0.70.0 hosts). MIN_AGENT_VERSION stays 0.1.0 — old agents
    keep reporting stale DB metadata, which is the status quo, not a
    breakage."""
    assert Settings.RECOMMENDED_TRIVY_VERSION == "0.73.0"
    assert Settings.CURRENT_AGENT_VERSION == "0.11.0"
    assert Settings.MIN_TRIVY_VERSION == "0.70.0"
    assert Settings.MIN_AGENT_VERSION == "0.1.0"


def test_trivy_db_stale_threshold_positive_int() -> None:
    """`TRIVY_DB_STALE_THRESHOLD_DAYS` ist eine positive Ganzzahl."""
    assert isinstance(Settings.TRIVY_DB_STALE_THRESHOLD_DAYS, int)
    assert Settings.TRIVY_DB_STALE_THRESHOLD_DAYS > 0
    # Block-Brief Default 7 — Bump kommt mit eigenem ADR.
    assert Settings.TRIVY_DB_STALE_THRESHOLD_DAYS == 7


def test_trivy_release_url_template_has_placeholders() -> None:
    """Template enthaelt `{version}` und `{arch}` als Bash-`%s`-Aequivalent."""
    template = Settings.TRIVY_RELEASE_URL_TEMPLATE
    assert "{version}" in template
    assert "{arch}" in template
    assert template.startswith("https://github.com/aquasecurity/trivy/releases/")


def test_trivy_release_url_template_renders_recommended_assets() -> None:
    """TICKET-022: Template loest fuer RECOMMENDED_TRIVY_VERSION beide
    Arch-Werte auf die echten Upstream-Asset-Namen auf (verifiziert gegen
    das reale v0.73.0-Release, kein Netzwerk-Call)."""
    template = Settings.TRIVY_RELEASE_URL_TEMPLATE
    version = Settings.RECOMMENDED_TRIVY_VERSION
    assert template.format(version=version, arch="64bit") == (
        f"https://github.com/aquasecurity/trivy/releases/download/"
        f"v{version}/trivy_{version}_Linux-64bit.tar.gz"
    )
    assert template.format(version=version, arch="ARM64") == (
        f"https://github.com/aquasecurity/trivy/releases/download/"
        f"v{version}/trivy_{version}_Linux-ARM64.tar.gz"
    )
