"""View-Tests fuer die "Was zu tun ist"-Aktions-Sektion (v0.9.3, ADR-0023 §c).

Die Sektion sitzt zwischen Header-Sub-Line und Host-Snapshot. Sie zeigt
bis zu fuenf Cards in Operations-Dringlichkeits-Reihenfolge:

* ESCALATE · Distro patchen    (escalate, patch, os_package)
* ESCALATE · App-Update         (escalate, patch, application_bundle)
* ESCALATE · Kein Patch — mitigieren (escalate, mitigate, any)
* ACT · Distro patchen         (act, patch, os_package)
* ACT · App-Update             (act, patch, application_bundle)

Leere Cards werden geskippt; wenn alle leer sind, blendet sich die Sektion
selbst aus. NULL-``action_type``-Groups (Pre-Triage, vor erstem Pass-2)
matchen keine Card.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
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


def _seed_server_with_groups(
    app: Flask,
    *,
    name: str,
    groups: list[dict[str, object]],
) -> int:
    """Erstellt einen Server und fuer jeden Eintrag in ``groups`` eine
    ApplicationGroup mit (``risk_band``, ``action_type``, ``group_kind``,
    ``n_findings``)-Daten. Liefert die Server-ID.
    """
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
                host_state_snapshot_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            for spec in groups:
                grp = ApplicationGroup(
                    label=str(spec["label"]),
                    explanation=None,
                    path_prefixes=[],
                    pkg_name_exact=[],
                    pkg_name_glob=[],
                    pkg_purl_pattern=[],
                    risk_band=spec.get("risk_band"),  # type: ignore[arg-type]
                    risk_band_reason=str(spec.get("reason", "")) or None,
                    risk_band_source="llm",
                    action_type=spec.get("action_type"),  # type: ignore[arg-type]
                    group_kind=spec.get("group_kind"),  # type: ignore[arg-type]
                    source="llm",
                )
                sess.add(grp)
                sess.flush()
                # n_findings OPEN-Findings, an die Group gemappt.
                n = int(spec.get("n_findings", 1))  # type: ignore[arg-type]
                for i in range(n):
                    f = Finding(
                        server_id=srv.id,
                        finding_type=FindingType.VULNERABILITY,
                        finding_class=FindingClass.OS_PKGS,
                        identifier_key=f"CVE-{spec['label']}-{i}",
                        package_name=str(spec["label"]),
                        installed_version="1.0",
                        severity=Severity.HIGH,
                        attack_vector=AttackVector.UNKNOWN,
                        status=FindingStatus.OPEN,
                        is_kev=False,
                        first_seen_at=_now(),
                        last_seen_at=_now(),
                        application_group_id=grp.id,
                    )
                    sess.add(f)
            sess.commit()
            return int(srv.id)
        finally:
            sess.close()


pytestmark = pytest.mark.usefixtures("db_app")


class TestActionNeededSection:
    def test_section_hidden_when_no_escalate_or_act_group(self, db_app: Flask) -> None:
        """Server ohne Cards (nur monitor/noise) → Sektion ist nicht im DOM."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-only-noise",
            groups=[
                {
                    "label": "noise-grp",
                    "risk_band": "noise",
                    "action_type": "none",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
                {
                    "label": "monitor-grp",
                    "risk_band": "monitor",
                    "action_type": "watch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        assert 'data-test="action-needed-section"' not in body, (
            "Sektion sollte ausgeblendet sein wenn keine ESCALATE/ACT-Card matched"
        )

    def test_section_hidden_when_all_groups_null_action_type(self, db_app: Flask) -> None:
        """Pre-Triage (action_type NULL) → keine Card matched → Sektion versteckt."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-pre-triage",
            groups=[
                {
                    "label": "pending-grp",
                    "risk_band": "escalate",
                    "action_type": None,  # noch nicht von Pass-2 gesetzt
                    "group_kind": "os_package",
                    "n_findings": 2,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        assert 'data-test="action-needed-section"' not in body

    def test_section_shows_escalate_distro_patch_card(self, db_app: Flask) -> None:
        """Single escalate+patch+os_package Group → genau eine Card."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-escalate-distro",
            groups=[
                {
                    "label": "openssl",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "reason": "KEV CVE-2024-6387 PUBLIC-EXPOSED",
                    "n_findings": 2,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        assert 'data-test="action-needed-section"' in body
        assert 'data-test="action-card-escalate-distro-patch"' in body
        # Leere Cards nicht im DOM.
        assert 'data-test="action-card-act-distro-patch"' not in body

    def test_card_order_escalate_before_act(self, db_app: Flask) -> None:
        """ESCALATE-Card MUSS vor ACT-Card im HTML stehen."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-mixed",
            groups=[
                {
                    "label": "act-grp",
                    "risk_band": "act",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
                {
                    "label": "esc-grp",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        idx_escalate = body.find('data-test="action-card-escalate-distro-patch"')
        idx_act = body.find('data-test="action-card-act-distro-patch"')
        assert idx_escalate >= 0
        assert idx_act >= 0
        assert idx_escalate < idx_act, "ESCALATE muss vor ACT stehen"

    def test_escalate_card_shows_group_label_in_drilldown_table(self, db_app: Flask) -> None:
        """ESCALATE-Card zeigt Group-Label in der Drilldown-Tabelle (Phase D2).

        Die Sub-Line der Group-Labels (sublist) entfaellt; Group-Name erscheint
        stattdessen in der Group-Spalte der workflow-card__drilldown-Tabelle.
        """
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-esc-drilldown",
            groups=[
                {
                    "label": "openssh-server",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        # sublist-Anker existiert nicht mehr (Phase D2-B).
        assert 'data-test="action-card-escalate-distro-patch-sublist"' not in body
        # Drilldown-Tabelle und Group-Label sind im DOM.
        assert 'data-test="action-card-escalate-distro-patch-table"' in body
        assert "openssh-server" in body

    def test_escalate_card_renders_all_groups_in_drilldown_table(self, db_app: Flask) -> None:
        """Alle Group-Rows erscheinen in der Drilldown-Tabelle (keine Sub-Line-Kuerzung).

        Phase D2-B entfernt die Sub-Line mit ``+N more``-Kuerzung; die Drilldown-Tabelle
        rendert alle Rows (bis Pagination-Stub bei > 25 greift).
        """
        create_admin_user(db_app)
        groups = [
            {
                "label": f"grp-{i}",
                "risk_band": "escalate",
                "action_type": "patch",
                "group_kind": "os_package",
                "n_findings": 1,
            }
            for i in range(7)
        ]
        sid = _seed_server_with_groups(db_app, name="srv-7-escalate", groups=groups)
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        # "+N more"-Suffix gibt es nicht mehr.
        assert "+2 more" not in body
        # Alle 7 Group-Labels rendern als Drilldown-Rows.
        for i in range(7):
            assert f"grp-{i}" in body

    def test_act_card_drilldown_table_rendered_no_sublist(self, db_app: Flask) -> None:
        """ACT-Card hat Drilldown-Tabelle, keinen sublist-Anker (Phase D2)."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-act-drilldown",
            groups=[
                {
                    "label": "act-pkg",
                    "risk_band": "act",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        # Die Card selbst existiert.
        assert 'data-test="action-card-act-distro-patch"' in body
        # Drilldown-Tabelle ist im DOM.
        assert 'data-test="action-card-act-distro-patch-table"' in body
        # sublist-Anker existiert nicht mehr (Phase D2-B).
        assert 'data-test="action-card-act-distro-patch-sublist"' not in body

    def test_details_collapsed_by_default(self, db_app: Flask) -> None:
        """``<details>`` haengt ohne ``open``-Attribut im HTML — Drilldown nur on
        click; kein Mid-Page-Layout-Jitter."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-default-collapsed",
            groups=[
                {
                    "label": "esc-x",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        assert "<details " in body  # Element existiert
        # Heuristik gegen "open"-Attribut: kein "<details open"-Match in der
        # Aktions-Sektion. Wir suchen die Section und das erste <details darin.
        section_idx = body.find('data-test="action-needed-section"')
        assert section_idx >= 0
        section_end = body.find("</section>", section_idx)
        section_html = body[section_idx:section_end]
        assert "<details open" not in section_html, (
            "Aktions-Cards sollen default-collapsed sein, nicht open"
        )

    def test_mitigate_card_shows_when_no_patch_path(self, db_app: Flask) -> None:
        """``(escalate, mitigate)``-Combo zeigt die ``escalate-mitigate``-Card,
        unabhaengig von group_kind (Spec ``group_kind: None``)."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-mitigate",
            groups=[
                {
                    "label": "no-fix-grp",
                    "risk_band": "escalate",
                    "action_type": "mitigate",
                    "group_kind": "application_bundle",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        assert 'data-test="action-card-escalate-mitigate"' in body

    def test_count_badge_matches_group_count(self, db_app: Flask) -> None:
        """Card-Count-Badge zeigt die Anzahl der Groups in der Card."""
        create_admin_user(db_app)
        sid = _seed_server_with_groups(
            db_app,
            name="srv-count",
            groups=[
                {
                    "label": "esc-a",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
                {
                    "label": "esc-b",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
                {
                    "label": "esc-c",
                    "risk_band": "escalate",
                    "action_type": "patch",
                    "group_kind": "os_package",
                    "n_findings": 1,
                },
            ],
        )
        client = db_app.test_client()
        login(client)
        body = client.get(f"/servers/{sid}").get_data(as_text=True)
        # data-test="action-card-escalate-distro-patch-count">3</span>
        idx = body.find('data-test="action-card-escalate-distro-patch-count"')
        assert idx >= 0
        # Schaue im nahen Umfeld nach der Zahl 3.
        chunk = body[idx : idx + 200]
        assert ">3<" in chunk
