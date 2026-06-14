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
    """RECOMMENDED-Trivy auf 0.71.0; Agent auf 0.8.0 (Block AL / ADR-0066 —
    os-pkgs-Host-Update-Anker); MIN-Trivy bleibt bewusst 0.70.0 (kein
    Hart-Ausmustern von 0.70.0-Hosts). MIN_AGENT_VERSION bleibt 0.1.0 — alte
    Agenten senden kein host_updates -> NULL -> mitigate, kein Hard-Reject."""
    assert Settings.RECOMMENDED_TRIVY_VERSION == "0.71.0"
    assert Settings.CURRENT_AGENT_VERSION == "0.8.0"
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
