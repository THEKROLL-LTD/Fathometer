"""Block N (ADR-0021) / Block AA (ADR-0041) — Ursachen-Felder-Persistenz.

Block N hatte die Ursachen-Sub-Zeile (`target_path`, `vendor_ids`,
`package_purl`, Type-Badges) ausschliesslich in der flachen Tabelle
(`_view_list.html`) gerendert, erreichbar via `?flat=1`. Block AA (ADR-0041)
entfernt den Flat-Pfad; der neue Single-Source-Inline-Body
(`finding_inline_body.html`) zeigt bewusst KEINE Ursachen-Felder mehr
(Less-is-more, keine Doppel-Daten zur Summary). Damit faellt die
Cause-Row-Anzeige als UI-Surface weg — dokumentiert als Re-Open-Trigger in
ADR-0041 (analog zu den nicht mehr narrowenden URL-Filtern).

Diese Tests sichern daher nur noch, dass die Ursachen-Felder weiterhin
**persistiert** werden (Ingest-/Model-Garantie) — die Daten sind fuer einen
spaeteren Re-Open der Anzeige verfuegbar, auch wenn sie aktuell nicht
gerendert werden.
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
    package_purl: str | None = None,
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
                package_purl=package_purl,
                severity_source=None,
            )
            sess.add(f)
            sess.flush()
            fid = f.id
            sess.commit()
            return fid
        finally:
            sess.close()


def _load(app: Flask, fid: int) -> Finding:
    factory = get_session_factory(app)
    with app.app_context():
        sess = factory()
        try:
            return sess.execute(select(Finding).where(Finding.id == fid)).scalar_one()
        finally:
            sess.close()


def test_lang_pkg_gobinary_target_path_persisted(db_app: Flask) -> None:
    sid = _create_server(db_app, name="srv-lang-cause")
    fid = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-LANG",
        package_name="github.com/foo/bar",
        result_type="gobinary",
        target_path="usr/local/bin/myapp",
        finding_class=FindingClass.LANG_PKGS,
    )
    f = _load(db_app, fid)
    assert f.result_type == "gobinary"
    assert f.target_path == "usr/local/bin/myapp"


def test_os_pkg_ubuntu_vendor_ids_persisted(db_app: Flask) -> None:
    sid = _create_server(db_app, name="srv-os-cause")
    fid = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-OS01",
        package_name="openssl",
        result_type="ubuntu",
        vendor_ids=["USN-1234-1", "DLA-5678-1"],
        finding_class=FindingClass.OS_PKGS,
    )
    f = _load(db_app, fid)
    assert f.result_type == "ubuntu"
    assert f.vendor_ids == ["USN-1234-1", "DLA-5678-1"]


def test_finding_package_purl_persisted(db_app: Flask) -> None:
    sid = _create_server(db_app, name="srv-purl")
    fid = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-PURL",
        package_name="openssl",
        result_type="ubuntu",
        package_purl="pkg:deb/ubuntu/openssl@3.0.2",
    )
    f = _load(db_app, fid)
    assert f.package_purl == "pkg:deb/ubuntu/openssl@3.0.2"


def test_vendor_ids_full_list_persisted(db_app: Flask) -> None:
    """Alle Vendor-IDs werden persistiert (das frueher flat-only `[:3]`-Slicing
    war reine Anzeige-Logik und ist mit dem Flat-Pfad entfallen)."""
    sid = _create_server(db_app, name="srv-vendor-cap")
    fid = _add_finding(
        db_app,
        server_id=sid,
        identifier_key="CVE-2026-CAP",
        package_name="curl",
        result_type="ubuntu",
        vendor_ids=["USN-1", "USN-2", "USN-3", "USN-4"],
        finding_class=FindingClass.OS_PKGS,
    )
    f = _load(db_app, fid)
    assert f.vendor_ids == ["USN-1", "USN-2", "USN-3", "USN-4"]
