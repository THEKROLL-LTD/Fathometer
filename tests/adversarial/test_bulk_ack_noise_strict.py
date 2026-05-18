"""Adversarial: Bulk-Ack-Noise server-side filter (Block O, ADR-0022).

Sicherheits-Default: wenn der Client `risk_band_filter="noise"` setzt, MUSS
der Server-Side-Filter eingeschleuste non-noise-IDs aus dem Set entfernen
und in `skipped_non_noise_ids` reporten. Selbst wenn der Operator die
Client-Seite umgeht und IDs anderer Baender mitsendet, darf KEIN
non-noise-Finding acknowledged werden.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
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


def _create_server(app: Flask, name: str) -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(
                name=name,
                api_key_hash="x" * 64,
                expected_scan_interval_h=24,
                last_scan_at=_now(),
            )
            sess.add(srv)
            sess.flush()
            sid = srv.id
            sess.commit()
            return sid
        finally:
            sess.close()


def _add_finding(
    app: Flask,
    *,
    server_id: int,
    identifier_key: str,
    risk_band: str,
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
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                is_kev=False,
                attack_vector=AttackVector.UNKNOWN,
                first_seen_at=now,
                last_seen_at=now,
                risk_band=risk_band,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _get_status(app: Flask, fid: int) -> FindingStatus:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            f = sess.execute(select(Finding).where(Finding.id == fid)).scalar_one()
            return f.status
        finally:
            sess.close()


def test_bulk_ack_noise_filter_drops_non_noise_ids(db_app: Flask) -> None:
    """4 IDs (1 noise, 1 monitor, 1 act, 1 pending) -> nur die noise-ID
    wird acked, die drei anderen landen in `skipped_non_noise_ids`."""
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-noise-strict")
    fid_noise = _add_finding(db_app, server_id=sid, identifier_key="CVE-NOISE-1", risk_band="noise")
    fid_monitor = _add_finding(
        db_app, server_id=sid, identifier_key="CVE-MONITOR-1", risk_band="monitor"
    )
    fid_act = _add_finding(db_app, server_id=sid, identifier_key="CVE-ACT-1", risk_band="act")
    fid_pending = _add_finding(
        db_app, server_id=sid, identifier_key="CVE-PENDING-1", risk_band="pending"
    )

    client = db_app.test_client()
    login(client)

    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "finding_ids": [fid_noise, fid_monitor, fid_act, fid_pending],
            "risk_band_filter": "noise",
            "dry_run": False,
        },
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()

    # Genau 1 acked (das noise-Finding).
    assert body["count"] == 1
    assert body["finding_ids"] == [fid_noise]

    # Drei in skipped_non_noise_ids.
    assert "skipped_non_noise_ids" in body
    skipped = set(body["skipped_non_noise_ids"])
    assert skipped == {fid_monitor, fid_act, fid_pending}, (
        f"Erwartet alle drei non-noise-IDs in skipped, got {skipped}"
    )

    # risk_band_filter wird zurueckgespiegelt.
    assert body["risk_band_filter"] == "noise"

    # DB-State: noise ist ACKNOWLEDGED, die anderen drei sind OPEN.
    assert _get_status(db_app, fid_noise) == FindingStatus.ACKNOWLEDGED
    assert _get_status(db_app, fid_monitor) == FindingStatus.OPEN
    assert _get_status(db_app, fid_act) == FindingStatus.OPEN
    assert _get_status(db_app, fid_pending) == FindingStatus.OPEN


def test_bulk_ack_noise_dry_run_also_filters(db_app: Flask) -> None:
    """Dry-Run respektiert `risk_band_filter` ebenfalls (ehrliche Vorschau)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-noise-dryrun")
    fid_noise = _add_finding(db_app, server_id=sid, identifier_key="CVE-NS-DR-N", risk_band="noise")
    fid_monitor = _add_finding(
        db_app, server_id=sid, identifier_key="CVE-NS-DR-M", risk_band="monitor"
    )
    client = db_app.test_client()
    login(client)
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "finding_ids": [fid_noise, fid_monitor],
            "risk_band_filter": "noise",
            "dry_run": True,
        },
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["dry_run"] is True
    assert body["count"] == 1
    assert body["finding_ids"] == [fid_noise]
    assert set(body["skipped_non_noise_ids"]) == {fid_monitor}
    # Beide bleiben OPEN bei dry-run.
    assert _get_status(db_app, fid_noise) == FindingStatus.OPEN
    assert _get_status(db_app, fid_monitor) == FindingStatus.OPEN


def test_bulk_ack_no_risk_band_filter_unchanged(db_app: Flask) -> None:
    """Ohne `risk_band_filter` werden alle uebergebenen IDs acked (Backward-
    Compat fuer den bestehenden Block-F-Workflow)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, "srv-no-rbf")
    fid_noise = _add_finding(db_app, server_id=sid, identifier_key="CVE-NRBF-N", risk_band="noise")
    fid_pending = _add_finding(
        db_app, server_id=sid, identifier_key="CVE-NRBF-P", risk_band="pending"
    )
    client = db_app.test_client()
    login(client)
    resp = client.post(
        "/api/findings/bulk-acknowledge",
        json={
            "finding_ids": [fid_noise, fid_pending],
            "dry_run": False,
        },
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 2
    # Kein risk_band_filter -> leere skipped-Liste.
    assert body["skipped_non_noise_ids"] == []
    # risk_band_filter ist null im Response.
    assert body["risk_band_filter"] is None
    assert _get_status(db_app, fid_noise) == FindingStatus.ACKNOWLEDGED
    assert _get_status(db_app, fid_pending) == FindingStatus.ACKNOWLEDGED
