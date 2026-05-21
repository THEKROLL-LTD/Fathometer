"""Tests fuer die Application-Group-Card-Partials (Block P, ADR-0023 §12;
Block-Q Phase B, ADR-0025 §2).

Die Partials selbst werden via `flask.render_template` mit dem aus dem
Loader gebauten Render-Vertrag getestet — wir umgehen die volle View und
pruefen nur das Card-Markup.

Render-Vertrag (Block-Q Phase B):
  - `group`         : ApplicationGroup.
  - `count`         : int — Anzahl OPEN-Findings dieser Group.
  - `worst_finding` : Finding | None.
  - `server`        : Server — fuer den HTMX-url_for(group_id, server_id).

Abgedeckte DoD-Punkte:
  - Group mit `risk_band="act"` -> normales Card-Markup + Pill + Count.
  - Group ohne `risk_band` (NULL) -> Evaluating-Card mit Spinner.
  - `worst_finding_id` gesetzt + worst_finding im Context -> Worst-Block.
  - `<details>` rendert IMMER ohne `open`-Attribut (Lazy-Slot, ADR-0025 §2).
  - Lazy-Slot enthaelt den HTMX-Trigger auf
    `server_detail.group_findings_fragment`.
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
) -> tuple[int, int, list[int]]:
    """Legt einen Server, eine Group, N Findings an. Liefert (server_id,
    group_id, finding_ids).

    Wenn `worst=True` wird `worst_finding_id` auf das erste Finding gesetzt.
    """
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=f"srv-{label}", api_key_hash="x" * 64)
            sess.add(srv)
            sess.flush()
            srv_id = srv.id

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
            return srv_id, grp.id, ids
        finally:
            sess.close()


def _render_card(
    app: Flask,
    *,
    template: str,
    server_id: int,
    group_id: int,
    count: int,
    worst_finding_id: int | None = None,
) -> str:
    """Rendert das Card-Partial mit dem aus Block-Q Phase B geforderten
    Context (group/count/worst_finding/server). Lasst die View aussen vor.

    `count` ist die explizit gemeldete Anzahl OPEN-Findings (aus dem
    Aggregat-Loader). Findings selbst werden NICHT mehr durchgereicht
    (Lazy-Slot, ADR-0025 §2).
    """
    factory = get_session_factory(app)
    with app.app_context(), app.test_request_context("/"):
        sess = factory()
        try:
            grp = sess.get(ApplicationGroup, group_id)
            assert grp is not None
            srv = sess.get(Server, server_id)
            assert srv is not None
            worst = sess.get(Finding, worst_finding_id) if worst_finding_id else None
            ctx: dict[str, Any] = {
                "group": grp,
                "count": count,
                "worst_finding": worst,
                "server": srv,
            }
            return render_template(template, **ctx)
        finally:
            sess.close()


def test_application_group_card_renders_with_risk_band(db_app: Flask) -> None:
    """Group mit `risk_band='act'` -> Card mit Pill, Reason, Findings-Count.

    Block-Q Phase B: `count` kommt direkt aus dem Aggregat-Loader und wird
    als Badge gerendert (`group-findings-count`).
    """
    sid, gid, _fids = _seed_group_with_findings(
        db_app,
        label="k3s",
        risk_band="act",
        risk_band_reason="patch available in upstream",
        n_findings=3,
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        server_id=sid,
        group_id=gid,
        count=3,
    )
    assert f'data-test="group-card-{gid}"' in html
    assert 'data-test="risk-band-pill-act"' in html, html[:500]
    assert "k3s" in html
    assert 'data-test="group-findings-count"' in html
    assert "3 findings" in html
    assert "patch available in upstream" in html
    assert 'data-test="group-risk-reason"' in html


def test_application_group_card_renders_worst_finding_block(db_app: Flask) -> None:
    """`worst_finding_id` gesetzt + worst_finding im Context -> Worst-Block."""
    sid, gid, fids = _seed_group_with_findings(
        db_app,
        label="openssh-server",
        risk_band="escalate",
        worst=True,
        n_findings=2,
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        server_id=sid,
        group_id=gid,
        count=2,
        worst_finding_id=fids[0],
    )
    assert 'data-test="group-worst-finding"' in html
    assert "WORST FINDING" in html
    assert "CVE-openssh-server-0" in html


def test_application_group_card_no_worst_block_when_not_set(db_app: Flask) -> None:
    """Keine `worst_finding_id` -> kein Worst-Block."""
    sid, gid, _fids = _seed_group_with_findings(
        db_app, label="nginx", risk_band="monitor", worst=False, n_findings=2
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        server_id=sid,
        group_id=gid,
        count=2,
    )
    assert 'data-test="group-worst-finding"' not in html


def test_application_group_card_details_is_lazy_slot(db_app: Flask) -> None:
    """Block-Q Phase B.3 (ADR-0025 §2): die `<details>`-Section enthaelt
    keinen einzigen Finding-Anchor mehr — stattdessen einen HTMX-Lazy-Slot,
    der erst beim Aufklappen die Findings nachlaedt.

    Verifikation:
      - `data-test="group-findings-details"` rendert.
      - `data-test="group-findings-lazy-slot"` ist im Initial-HTML.
      - Der Slot zeigt einen Loading-Spinner-Hinweis ("Lade Findings").
      - Der HTMX-Trigger zeigt auf
        `server_detail.group_findings_fragment` mit korrekter server_id/
        group_id.
      - Es gibt keine `id="finding-<id>"`-Anchors mehr im Initial-HTML
        (haetten die Findings eagerly mit-gerendert, waeren sie hier).
    """
    sid, gid, _fids = _seed_group_with_findings(
        db_app, label="bind9", risk_band="mitigate", n_findings=4
    )
    html = _render_card(
        db_app,
        template="_partials/application_group_card.html",
        server_id=sid,
        group_id=gid,
        count=4,
    )
    assert "<details" in html
    assert 'data-test="group-findings-details"' in html
    assert 'data-test="group-findings-lazy-slot"' in html
    assert "Lade Findings" in html
    # HTMX-Trigger laedt vom group-findings-Endpoint.
    assert f"/servers/{sid}/groups/{gid}/findings" in html
    assert 'hx-trigger="toggle once' in html
    # KEINE eager-gerenderten Finding-Anchors im Initial-HTML.
    import re

    assert not re.search(r'id="finding-\d+"', html), (
        "Initial-Card-HTML enthaelt Finding-Anchors — Block-Q-Spec verlangt Lazy-Slot."
    )


def test_group_evaluating_card_for_null_risk_band(db_app: Flask) -> None:
    """Group ohne `risk_band` (Worker arbeitet) -> Spinner-Card.

    Render-Vertrag: Evaluating-Card bekommt `group` + `count`, KEINE
    `findings`-Liste (Block-Q Phase B).
    """
    sid, gid, _fids = _seed_group_with_findings(
        db_app, label="containerd", risk_band=None, n_findings=2
    )
    html = _render_card(
        db_app,
        template="_partials/group_evaluating_card.html",
        server_id=sid,
        group_id=gid,
        count=2,
    )
    assert f'data-test="group-evaluating-{gid}"' in html
    assert 'data-test="group-evaluating-spinner"' in html
    assert "Evaluating risk for 2 findings" in html
    assert "containerd" in html


def test_application_group_card_never_renders_open_by_default(db_app: Flask) -> None:
    """Block-Q Phase B.3 (ADR-0025 §2): die `<details>`-Section rendert
    IMMER ohne `open`-Attribut — egal welchen Risk-Band die Group hat.

    Die fruehere `_open_default`-Logik (escalate/act/mitigate/pending/
    unknown auto-expanded) entfaellt ersatzlos; Findings werden via HTMX
    nachgeladen, wenn der Operator das `<summary>` oeffnet.
    """
    import re

    # `pending`/`unknown` sind Pre-Triage-only und dort durch DB-Check-Constraint
    # `ck_application_groups_band` ausgeschlossen — daher hier nicht testbar.
    # Die fruehere `_open_default`-Logik hatte diese beiden Bands ebenfalls
    # eager-expanded; der Regress-Schutz dafuer liegt in
    # `test_group_without_risk_band_renders_evaluating_card` (NULL-Band ->
    # Evaluating-Card statt expanded Card).
    for band in ("escalate", "act", "mitigate", "monitor", "noise"):
        sid, gid, _fids = _seed_group_with_findings(
            db_app, label=f"kubelet-{band}", risk_band=band, n_findings=1
        )
        html = _render_card(
            db_app,
            template="_partials/application_group_card.html",
            server_id=sid,
            group_id=gid,
            count=1,
        )
        match = re.search(r"<details\b([^>]*)>", html)
        assert match is not None, f"details-Tag fehlt fuer band={band}"
        assert "open" not in match.group(1), (
            f"details fuer band={band} darf KEIN 'open'-Attribut haben: {match.group(1)!r}"
        )
        # Doppelt sicher: globaler Check.
        assert "<details open" not in html, (
            f"`<details open` darf fuer band={band} nicht im Markup stehen."
        )
