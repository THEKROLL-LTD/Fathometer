"""Tests fuer die Application-Group-Card-Partials (Block P, ADR-0023 §12).

Die Partials selbst werden via `flask.render_template_string` mit einem
`{% include %}`-Wrapper getestet — wir umgehen die volle View und prufen
nur das Card-Markup.

Abgedeckte DoD-Punkte:
  - Group mit `risk_band="act"` -> normales Card-Markup + Pill.
  - Group ohne `risk_band` (NULL) -> Evaluating-Card mit Spinner.
  - `worst_finding_id` gesetzt + worst_finding im Context -> Worst-Block.
  - `<details>` listet alle Findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Flask, render_template

from app.db import get_session_factory
from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    Severity,
)


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _seed_group_with_findings(
    app: Flask,
    *,
    label: str,
    risk_band: str | None = None,
    risk_band_reason: str | None = None,
    worst: bool = False,
    n_findings: int = 3,
) -> tuple[int, list[int]]:
    """Legt einen Server, eine Group, N Findings an. Liefert (group_id,
    finding_ids).

    Wenn `worst=True` wird `worst_finding_id` auf das erste Finding gesetzt.
    """
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=f"srv-{label}", api_key_hash="x" * 64)
            sess.add(srv)
            sess.flush()

            grp = ApplicationGroup(
                label=label,
                explanation=f"{label} explanation",
                path_prefixes=[],
                pkg_name_exact=[],
                pkg_name_glob=[],
                pkg_purl_pattern=[],
                risk_band=risk_band,
                risk_band_reason=risk_band_reason,
            )
            sess.add(grp)
            sess.flush()

            ids: list[int] = []
            for i in range(n_findings):
                f = Finding(
                    server_id=srv.id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"CVE-{label}-{i}",
                    package_name=f"pkg-{i}",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                    application_group_id=grp.id,
                )
                sess.add(f)
                sess.flush()
                ids.append(f.id)

            if worst and ids:
                grp.worst_finding_id = ids[0]

            sess.commit()
            return grp.id, ids
        finally:
            sess.close()


def _render_card(
    app: Flask,
    *,
    template: str,
    group_id: int,
    finding_ids: list[int],
    worst_finding_id: int | None = None,
    open_default: bool = False,
) -> str:
    """Rendert das Card-Partial mit dem geforderten Context. Lasst die View
    aussen vor — wir reinvestigieren das Template direkt."""
    factory = get_session_factory(app)
    with app.app_context(), app.test_request_context("/"):
        sess = factory()
        try:
            grp = sess.get(ApplicationGroup, group_id)
            assert grp is not None
            findings = [sess.get(Finding, fid) for fid in finding_ids]
            findings = [f for f in findings if f is not None]
            worst = sess.get(Finding, worst_finding_id) if worst_finding_id else None
            ctx: dict[str, Any] = {
                "group": grp,
                "findings": findings,
                "worst_finding": worst,
                "open_default": open_default,
            }
            return render_template(template, **ctx)
        finally:
            sess.close()


def test_application_group_card_renders_with_risk_band(db_app: Flask) -> None:
    """Group mit `risk_band='act'` -> Card mit Pill, Reason, Findings-Count."""
    gid, fids = _seed_group_with_findings(
        db_app,
        label="k3s",
        risk_band="act",
        risk_band_reason="patch available in upstream",
        n_findings=3,
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        group_id=gid,
        finding_ids=fids,
    )
    assert f'data-test="group-card-{gid}"' in html
    assert 'data-test="risk-band-pill-act"' in html, html[:500]
    assert "k3s" in html
    assert "3 findings" in html
    assert "patch available in upstream" in html
    assert 'data-test="group-risk-reason"' in html


def test_application_group_card_renders_worst_finding_block(db_app: Flask) -> None:
    """`worst_finding_id` gesetzt + worst_finding im Context -> Worst-Block."""
    gid, fids = _seed_group_with_findings(
        db_app,
        label="openssh-server",
        risk_band="escalate",
        worst=True,
        n_findings=2,
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        group_id=gid,
        finding_ids=fids,
        worst_finding_id=fids[0],
    )
    assert 'data-test="group-worst-finding"' in html
    assert "WORST FINDING" in html
    assert "CVE-openssh-server-0" in html


def test_application_group_card_no_worst_block_when_not_set(db_app: Flask) -> None:
    """Keine `worst_finding_id` -> kein Worst-Block."""
    gid, fids = _seed_group_with_findings(
        db_app, label="nginx", risk_band="monitor", worst=False, n_findings=2
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        group_id=gid,
        finding_ids=fids,
    )
    assert 'data-test="group-worst-finding"' not in html


def test_application_group_card_details_lists_all_findings(db_app: Flask) -> None:
    """`<details>`-Drilldown listet alle Findings."""
    gid, fids = _seed_group_with_findings(db_app, label="bind9", risk_band="mitigate", n_findings=4)
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        group_id=gid,
        finding_ids=fids,
    )
    assert "<details" in html
    assert 'data-test="group-findings-details"' in html
    # Jede Finding-ID muss in der Drilldown-Tabelle vorkommen.
    for fid in fids:
        assert f'id="finding-{fid}"' in html


def test_group_evaluating_card_for_null_risk_band(db_app: Flask) -> None:
    """Group ohne `risk_band` (Worker arbeitet) -> Spinner-Card."""
    gid, fids = _seed_group_with_findings(db_app, label="containerd", risk_band=None, n_findings=2)
    html = _render_card(
        db_app,
        template="_partials/group_evaluating_card.html",
        group_id=gid,
        finding_ids=fids,
    )
    assert f'data-test="group-evaluating-{gid}"' in html
    assert 'data-test="group-evaluating-spinner"' in html
    assert "Evaluating risk for 2 findings" in html
    assert "containerd" in html


def test_application_group_card_open_default_flag(db_app: Flask) -> None:
    """`open_default=true` rendert `<details open>`."""
    gid, fids = _seed_group_with_findings(
        db_app, label="kubelet", risk_band="escalate", n_findings=1
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        group_id=gid,
        finding_ids=fids,
        open_default=True,
    )
    import re

    match = re.search(r"<details\b([^>]*)>", html)
    assert match is not None, "details-Tag fehlt"
    # `open`-Attribut steht im opening-Tag.
    assert "open" in match.group(1), f"open-Attribut fehlt: {match.group(1)!r}"
