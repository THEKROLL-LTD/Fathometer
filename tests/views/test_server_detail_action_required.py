"""Block O (ADR-0022): Server-Detail Action-Required-Pill + Host-Snapshot-
Sektion + Per-Finding-Risk-Band-Reason.

Tests:
  - Server mit `pending`-Finding -> rote Action-Pill mit Sub-Counter.
  - Server ohne Yes-Bands -> gruene Safe-Pill.
  - Server ohne Snapshot -> graue Update-Agent-Pill.
  - Host-Snapshot-Sektion zeigt erste 5 Listener + "+N more"-Toggle.
  - Per-Finding-Detail-Box zeigt `risk_band_reason` in Mono-Font.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask

from app.db import get_session_factory
from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    ServerListener,
    ServerService,
    Severity,
)
from tests._helpers import create_admin_user, login


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _create_server(
    app: Flask,
    *,
    name: str,
    with_snapshot: bool = True,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
                host_state_snapshot_at=(_now() if with_snapshot else None),
            )
            sess.add(srv)
            sess.flush()
            srv_id = srv.id
            sess.commit()
            return srv_id
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    risk_band: str | None = None,
    risk_band_reason: str | None = None,
    severity: Severity = Severity.HIGH,
) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            now = _now()
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key=identifier_key,
                package_name="openssl",
                installed_version="1.0",
                severity=severity,
                status=FindingStatus.OPEN,
                is_kev=False,
                attack_vector=AttackVector.UNKNOWN,
                first_seen_at=now,
                last_seen_at=now,
                risk_band=risk_band,
                risk_band_reason=risk_band_reason,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _add_listeners(app: Flask, server_id: int, count: int) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            for i in range(count):
                sess.add(
                    ServerListener(
                        server_id=server_id,
                        proto="tcp",
                        port=22 + i,
                        addr="0.0.0.0",  # noqa: S104 — test-fixture, kein Bind
                        process=f"proc-{i}",
                        pid=1000 + i,
                    )
                )
            sess.commit()
        finally:
            sess.close()


def _add_service(app: Flask, server_id: int, name: str) -> None:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            sess.add(ServerService(server_id=server_id, name=name))
            sess.commit()
        finally:
            sess.close()


def test_server_detail_action_needed_pill_for_pending_finding(db_app: Flask) -> None:
    """Server mit `pending`-Finding -> rote 'Action needed'-Pill mit Sub-Counter."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-pending")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-PE-1",
        risk_band="pending",
        risk_band_reason="max-severity HIGH · pending LLM review",
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="action-required-pill-needed"' in body
    # Sub-Counter "1 pending" muss im Pill-Label vorkommen.
    assert "1 pending" in body


def test_server_detail_safe_pill_when_only_no_bands(db_app: Flask) -> None:
    """Server mit nur monitor/noise -> gruene Safe-Pill."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-safe")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-M-1", risk_band="monitor")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-N-1", risk_band="noise")
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="action-required-pill-safe"' in body
    # Sub-Counter (1 monitor · 1 noise).
    assert "1 monitor" in body
    assert "1 noise" in body


def test_server_detail_update_agent_pill_when_snapshot_missing(db_app: Flask) -> None:
    """Server ohne host_state_snapshot_at -> graue Update-Agent-Pill."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-no-snapshot", with_snapshot=False)
    # Kein Finding -> safe (aber Snapshot fehlt -> override).
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="action-required-pill-update-agent"' in body
    # Tooltip-Hint enthaelt "Update agent" Sprache.
    assert "Update agent" in body


def test_server_detail_host_snapshot_section_shows_first_5_listeners(db_app: Flask) -> None:
    """Snapshot-Sektion zeigt max 5 Listener inline + "+N more"-Toggle."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-listeners")
    _add_listeners(db_app, sid, count=8)
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)

    assert 'data-test="host-snapshot-section"' in body
    assert 'data-test="host-snapshot-listeners-inline"' in body
    # Toggle fuer die restlichen 3.
    assert 'data-test="host-snapshot-listeners-toggle"' in body
    assert "3 more — show all" in body or "more — show all" in body


def test_server_detail_host_snapshot_empty_state_without_snapshot(db_app: Flask) -> None:
    """Ohne Snapshot -> "Update agent"-Empty-State."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-empty-snap", with_snapshot=False)
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="host-snapshot-missing"' in body


def test_server_detail_finding_row_shows_risk_band_reason(db_app: Flask) -> None:
    """Finding mit `risk_band_reason` rendert das in Mono-Font unter der CVE-ID."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-reason")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-R-1",
        risk_band="pending",
        risk_band_reason="KEV listed · pending LLM review",
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="finding-risk-reason"' in body
    assert "KEV listed" in body
    assert "pending LLM review" in body


def test_server_detail_findings_grouped_by_band_with_section_headers(db_app: Flask) -> None:
    """Findings sind nach `risk_band` gruppiert, eine tbody-Section pro Band."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-grouped")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-P-1", risk_band="pending")
    _add_finding(db_app, server_id=sid, identifier_key="CVE-N-1", risk_band="noise")
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-test="findings-band-group-pending"' in body
    assert 'data-test="findings-band-group-noise"' in body
    # Toggle-Buttons pro Band.
    assert 'data-test="findings-band-toggle-pending"' in body
    assert 'data-test="findings-band-toggle-noise"' in body
