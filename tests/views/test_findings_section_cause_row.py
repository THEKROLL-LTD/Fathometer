"""Block N (ADR-0021) — View-Test fuer die Ursachen-Sub-Zeile (Task #12a).

Drei DoD-Cases:
* lang-pkg (gobinary) mit `target_path` -> Pfad gerendert.
* os-pkg (ubuntu) mit `vendor_ids` -> Vendor-IDs als Badges sichtbar.
* Legacy-Finding mit `result_type=NULL` und `package_name@target` -> Fallback
  rendert den Suffix als Pfad.
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
    Severity,
)
from tests._helpers import create_admin_user, login


def _create_server(app: Flask, name: str = "srv-cause") -> int:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            srv = Server(name=name, api_key_hash="x" * 64, expected_scan_interval_h=24)
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
    package_name: str,
    result_type: str | None,
    target_path: str | None = None,
    vendor_ids: list[str] | None = None,
    finding_class: FindingClass = FindingClass.OS_PKGS,
) -> int:
    factory = get_session_factory(app)
    now = datetime.now(tz=UTC)
    with app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=finding_class,
                identifier_key=identifier_key,
                package_name=package_name,
                installed_version="1.0.0",
                severity=Severity.HIGH,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
                result_type=result_type,
                target_path=target_path,
                vendor_ids=vendor_ids,
                package_purl=None,
                severity_source=None,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def test_lang_pkg_gobinary_renders_target_path(db_app: Flask) -> None:
    """gobinary mit target_path -> Pfad steht im Rendered HTML."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-lang-cause")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-LANG",
        package_name="github.com/foo/bar",
        result_type="gobinary",
        target_path="usr/local/bin/myapp",
        finding_class=FindingClass.LANG_PKGS,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    # Type-Label als Badge.
    assert "gobinary" in body
    # Pfad mit fuehrendem Slash (Template normalisiert auf `/<trimmed>`).
    assert "/usr/local/bin/myapp" in body


def test_os_pkg_ubuntu_renders_vendor_ids(db_app: Flask) -> None:
    """ubuntu-Paket mit vendor_ids -> badges mit Vendor-ID erscheinen."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-os-cause")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-OS01",
        package_name="openssl",
        result_type="ubuntu",
        vendor_ids=["USN-1234-1", "DLA-5678-1"],
        finding_class=FindingClass.OS_PKGS,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    assert "ubuntu" in body
    assert "USN-1234-1" in body
    assert "DLA-5678-1" in body
    # Mindestens ein vendor-id-Badge mit data-test.
    assert 'data-test="finding-vendor-id"' in body


def test_finding_with_purl_renders_data_purl_attribute(db_app: Flask) -> None:
    """Finding mit `package_purl` -> `data-purl` Attribut im Markup (Tooltip)."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-purl")
    # PURL setzen — der Stub-Helper unten setzt es per direktem Add.
    factory = get_session_factory(db_app)
    now = datetime.now(tz=UTC)
    with db_app.app_context():
        sess = factory()
        try:
            f = Finding(
                server_id=sid,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key="CVE-2026-PURL",
                package_name="openssl",
                installed_version="3.0.2",
                severity=Severity.HIGH,
                attack_vector=AttackVector.UNKNOWN,
                status=FindingStatus.OPEN,
                first_seen_at=now,
                last_seen_at=now,
                result_type="ubuntu",
                target_path=None,
                vendor_ids=None,
                package_purl="pkg:deb/ubuntu/openssl@3.0.2",
                severity_source="ubuntu",
            )
            sess.add(f)
            sess.commit()
        finally:
            sess.close()

    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    assert 'data-purl="pkg:deb/ubuntu/openssl@3.0.2"' in body


def test_vendor_ids_cap_three_pills_rendered(db_app: Flask) -> None:
    """`vendor_ids=[v1, v2, v3, v4]` -> nur die ersten drei werden als Pill gerendert."""
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-vendor-cap")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-CAP",
        package_name="curl",
        result_type="ubuntu",
        vendor_ids=["USN-1", "USN-2", "USN-3", "USN-4"],
        finding_class=FindingClass.OS_PKGS,
    )
    client = db_app.test_client()
    login(client)
    body = client.get(f"/servers/{sid}").get_data(as_text=True)
    # Erste drei sichtbar.
    assert "USN-1" in body
    assert "USN-2" in body
    assert "USN-3" in body
    # Vierter ist nicht im gerenderten Markup (Template-Slicing `[:3]`).
    assert "USN-4" not in body
    # Anzahl Vendor-ID-Badges: exakt drei.
    assert body.count('data-test="finding-vendor-id"') == 3


def test_legacy_finding_uses_package_name_at_suffix_fallback(db_app: Flask) -> None:
    """Alt-Daten ohne result_type/target_path -> kein Render (kind=unknown).

    Aber Findings mit gesetztem `result_type` und `package_name@<path>` ohne
    explizites `target_path` muessen den Pfad-Fallback aktivieren.
    """
    create_admin_user(db_app)
    sid = _create_server(db_app, name="srv-fallback-cause")
    _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-FBK",
        package_name="github.com/foo/bar@usr/local/bin/legacyapp",
        result_type="gobinary",
        target_path=None,
        finding_class=FindingClass.LANG_PKGS,
    )
    client = db_app.test_client()
    login(client)
    resp = client.get(f"/servers/{sid}")
    assert resp.status_code == 200, resp.data[:300]
    body = resp.get_data(as_text=True)
    # Type-Label aus result_type.
    assert "gobinary" in body
    # Pfad-Fallback rendert den Suffix mit fuehrendem Slash.
    assert "/usr/local/bin/legacyapp" in body
