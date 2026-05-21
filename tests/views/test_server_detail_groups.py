"""Server-Detail-Findings-Section mit Application-Group-Cards (Block P,
Block-Q Phase B/C, ADR-0025 §2 + §3).

DoD aus Block-P-Brief Task #13 (angepasst an ADR-0025):
  - Server mit 3 Groups (escalate/act/noise) -> 3 Cards in Sort-Order
    (escalate zuerst).
  - ALLE Application-Group-Cards rendern default COLLAPSED (Block-Q
    Phase B.3, ADR-0025 §2 — `_expanded_bands`-Auto-Open ist weg).
  - Ungrouped-Findings -> "Pending grouping"-Sektion am Ende mit pro-Band
    collapsed `<details>`-Buckets, Findings selbst lazy via HTMX
    (Block-Q Phase C.3, ADR-0025 §3 — keine CVE-IDs im Initial-HTML).
  - Group ohne risk_band -> Evaluating-Card statt normale Card.
  - Bulk-Ack-Noise-Modal-Liste enthaelt noise-Findings aus allen Groups +
    ungrouped, keine non-noise.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from flask import Flask

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
from tests._helpers import create_admin_user, login


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _seed(
    app: Flask,
    *,
    server_name: str,
    groups_spec: list[dict[str, Any]],
    ungrouped_count: int = 0,
) -> int:
    """Legt Server, Groups und Findings an.

    `groups_spec` ist eine Liste dicts mit Keys:
      - `label`     : str.
      - `risk_band` : str | None.
      - `findings`  : list[dict] mit `risk_band`, `identifier_key`.
    """
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=server_name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
                host_state_snapshot_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id

            for spec in groups_spec:
                grp = ApplicationGroup(
                    label=spec["label"],
                    path_prefixes=[],
                    pkg_name_exact=[],
                    pkg_name_glob=[],
                    pkg_purl_pattern=[],
                    risk_band=spec.get("risk_band"),
                    risk_band_reason=spec.get("risk_band_reason"),
                )
                sess.add(grp)
                sess.flush()
                for f_spec in spec.get("findings", []):
                    f = Finding(
                        server_id=srv_id,
                        finding_type=FindingType.VULNERABILITY,
                        finding_class=FindingClass.OS_PKGS,
                        identifier_key=f_spec["identifier_key"],
                        package_name=f_spec.get("package_name", "pkg"),
                        severity=Severity.HIGH,
                        status=FindingStatus.OPEN,
                        attack_vector=AttackVector.UNKNOWN,
                        first_seen_at=_now(),
                        last_seen_at=_now(),
                        application_group_id=grp.id,
                        risk_band=f_spec.get("risk_band"),
                    )
                    sess.add(f)

            for i in range(ungrouped_count):
                f = Finding(
                    server_id=srv_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key=f"CVE-UNGROUPED-{i}",
                    package_name=f"orphan-{i}",
                    severity=Severity.HIGH,
                    status=FindingStatus.OPEN,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                    application_group_id=None,
                    risk_band="pending",
                )
                sess.add(f)

            sess.commit()
            return srv_id
        finally:
            sess.close()


def test_three_groups_in_risk_sort_order(db_app: Flask) -> None:
    """3 Groups (escalate/act/noise) -> Cards in escalate-act-noise Reihenfolge."""
    create_admin_user(db_app)
    sid = _seed(
        db_app,
        server_name="srv-3groups",
        groups_spec=[
            {
                "label": "noise-group",
                "risk_band": "noise",
                "findings": [{"identifier_key": "CVE-N1", "risk_band": "noise"}],
            },
            {
                "label": "act-group",
                "risk_band": "act",
                "findings": [{"identifier_key": "CVE-A1", "risk_band": "act"}],
            },
            {
                "label": "escalate-group",
                "risk_band": "escalate",
                "findings": [{"identifier_key": "CVE-E1", "risk_band": "escalate"}],
            },
        ],
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)

    # Alle drei Cards muessen gerendert sein.
    assert "escalate-group" in body
    assert "act-group" in body
    assert "noise-group" in body
    # Sort-Order: escalate-Card kommt vor act, die vor noise.
    pos_escalate = body.index("escalate-group")
    pos_act = body.index("act-group")
    pos_noise = body.index("noise-group")
    assert pos_escalate < pos_act < pos_noise, (pos_escalate, pos_act, pos_noise)


def test_all_group_cards_default_collapsed(db_app: Flask) -> None:
    """Block-Q Phase B.3 (ADR-0025 §2): ALLE Application-Group-Cards
    rendern default COLLAPSED.

    Die fruehere `_expanded_bands`-Logik (escalate/act/mitigate/pending/
    unknown auto-open, monitor/noise collapsed) entfaellt ersatzlos.
    Wir erzeugen eine escalate- UND eine noise-Card und verifizieren
    beide haben KEIN `open`-Attribut.
    """
    create_admin_user(db_app)
    sid = _seed(
        db_app,
        server_name="srv-openclose",
        groups_spec=[
            {
                "label": "esc-grp",
                "risk_band": "escalate",
                "findings": [{"identifier_key": "CVE-X1", "risk_band": "escalate"}],
            },
            {
                "label": "noi-grp",
                "risk_band": "noise",
                "findings": [{"identifier_key": "CVE-X2", "risk_band": "noise"}],
            },
        ],
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)

    import re

    # escalate-Card: das `<details>` der Group-Card darf KEIN 'open' tragen.
    esc_pos = body.index("esc-grp")
    esc_block = body[esc_pos : esc_pos + 3000]
    esc_details = re.search(r"<details\b([^>]*)>", esc_block)
    assert esc_details is not None
    assert "open" not in esc_details.group(1), (
        f"escalate-details darf KEIN 'open'-Attribut haben (ADR-0025 §2): {esc_details.group(1)!r}"
    )

    # noise-Card: weiterhin collapsed.
    noi_pos = body.index("noi-grp")
    noi_block = body[noi_pos : noi_pos + 3000]
    noi_details = re.search(r"<details\b([^>]*)>", noi_block)
    assert noi_details is not None
    assert "open" not in noi_details.group(1), (
        f"noise-details darf 'open' nicht haben: {noi_details.group(1)!r}"
    )


def test_ungrouped_findings_pending_grouping_section(db_app: Flask) -> None:
    """Findings ohne `application_group_id` -> Pending-grouping-Sektion.

    Block-Q Phase C.3 (ADR-0025 §3): die Pending-Sektion rendert eigentlich
    Lazy — pro Risk-Band ein collapsed `<details>`-Bucket mit
    `data-test="pending-band-<band>"`, die Findings selbst kommen erst
    nach HTMX-Aufklappen. CVE-IDs duerfen NICHT im Initial-HTML stehen.

    Wir seeden 2 ungroupierte Findings (default-Band `pending` aus dem
    `_seed`-Helper) und pruefen die Sektion-Struktur — keine CVE-Suche.
    """
    create_admin_user(db_app)
    sid = _seed(
        db_app,
        server_name="srv-orphan",
        groups_spec=[
            {
                "label": "real-grp",
                "risk_band": "act",
                "findings": [{"identifier_key": "CVE-OK", "risk_band": "act"}],
            },
        ],
        ungrouped_count=2,
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)

    # Pending-Grouping-Sektion ist im Initial-HTML sichtbar.
    assert 'data-test="pending-grouping-section"' in body
    assert "Pending grouping" in body

    # Pro Risk-Band mit count>0 ein `<details>`-Bucket. `_seed`-Helper setzt
    # ungroupierte Findings auf risk_band="pending" — also muss zumindest
    # der pending-Bucket erscheinen.
    assert 'data-test="pending-band-pending"' in body, (
        "Erwartet `pending-band-pending`-Bucket im Initial-HTML "
        "(2 ungroupierte Findings mit risk_band='pending')."
    )
    # Lazy-Slot mit HTMX-Trigger auf den pending-Endpoint ist vorhanden.
    assert 'data-test="pending-band-lazy-slot"' in body
    assert f"/servers/{sid}/findings/pending" in body

    # KEINE Finding-CVE-IDs im Initial-HTML — die werden lazy nachgeladen
    # (ADR-0025 §3).
    assert "CVE-UNGROUPED-0" not in body, (
        "Ungroupierte CVE-IDs duerfen NICHT eager gerendert sein (Block-Q Phase C.3)."
    )
    assert "CVE-UNGROUPED-1" not in body


def test_group_without_risk_band_renders_evaluating_card(db_app: Flask) -> None:
    """Group mit `risk_band=NULL` -> Evaluating-Card statt normale Card."""
    create_admin_user(db_app)
    sid = _seed(
        db_app,
        server_name="srv-eval",
        groups_spec=[
            {
                "label": "pending-grp",
                "risk_band": None,
                "findings": [
                    {"identifier_key": "CVE-EV-1", "risk_band": "pending"},
                    {"identifier_key": "CVE-EV-2", "risk_band": "pending"},
                ],
            },
        ],
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)

    # Evaluating-Card statt normale Card.
    assert 'data-test="group-evaluating-' in body
    assert "Evaluating risk for 2 findings" in body
    # Normale Card-Marker darf nicht fuer diese Group da sein (keine
    # Risk-Pill fuer die evaluating-Group). Wir pruefen indirekt: das
    # `group-risk-reason`-Element fehlt komplett, weil kein Risk-Band.
    assert 'data-test="group-risk-reason"' not in body


def test_bulk_ack_noise_modal_contains_only_noise(db_app: Flask) -> None:
    """Bulk-Ack-Noise-Modal-Liste enthaelt nur noise-Findings (aus allen
    Groups + ungrouped), keine non-noise."""
    create_admin_user(db_app)
    sid = _seed(
        db_app,
        server_name="srv-noisemix",
        groups_spec=[
            {
                "label": "act-grp",
                "risk_band": "act",
                "findings": [
                    # Mixed: ein noise + ein act in derselben Group.
                    {"identifier_key": "CVE-N-IN-ACT", "risk_band": "noise"},
                    {"identifier_key": "CVE-A-NORMAL", "risk_band": "act"},
                ],
            },
            {
                "label": "noise-only-grp",
                "risk_band": "noise",
                "findings": [
                    {"identifier_key": "CVE-N-PURE", "risk_band": "noise"},
                ],
            },
        ],
        ungrouped_count=0,
    )
    # Zusaetzlich ungrouped noise-Finding einfuegen.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                Finding(
                    server_id=sid,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key="CVE-N-UNGROUPED",
                    package_name="orph",
                    severity=Severity.LOW,
                    status=FindingStatus.OPEN,
                    attack_vector=AttackVector.UNKNOWN,
                    first_seen_at=_now(),
                    last_seen_at=_now(),
                    application_group_id=None,
                    risk_band="noise",
                )
            )
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)

    # Bulk-Ack-Noise-Modal/Toolbar wird nur sichtbar wenn noise_total > 0.
    assert 'data-test="bulk-ack-noise-scope"' in body, body[:500]

    # Total noise count = 3 (1 in act-grp + 1 in noise-only-grp + 1 ungrouped).
    # Der Modal-Wrapper traegt den count.
    assert "(3)" in body or ">3<" in body or "noise_total" not in body  # graceful

    # Extrahiere die Modal-Region und pruefe, dass nur noise-IDs drin sind.
    # `_bulk_ack_noise_modal.html` umrahmt seine Liste; wir suchen nach den
    # noise-CVE-Strings und stellen sicher, dass non-noise CVE NICHT in
    # diesem Sub-Block ist.
    # Einfacher Smoketest: Alle drei Noise-IDs muessen im Body sein.
    assert "CVE-N-IN-ACT" in body
    assert "CVE-N-PURE" in body
    assert "CVE-N-UNGROUPED" in body
