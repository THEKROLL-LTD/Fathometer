"""Block P (ADR-0023) — Modell-Tests fuer `application_groups`.

Verifiziert CheckConstraints (band, source), UNIQUE auf `label`, FK auf
`findings.application_group_id` mit `ON DELETE SET NULL`.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

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
from tests._helpers import register_test_server


def _new_group(label: str = "k3s", **overrides: Any) -> ApplicationGroup:
    return ApplicationGroup(
        label=label,
        explanation="Rancher K3s Bundle.",
        path_prefixes=[],
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        **overrides,
    )


def test_insert_valid_group(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_group(label="k3s"))
            sess.commit()
            row = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.label == "k3s")
            ).scalar_one()
            assert row.path_prefixes == []
            assert row.pkg_name_exact == []
            assert row.source == "llm"
            assert row.detected_at is not None
        finally:
            sess.close()


def test_insert_invalid_band_pending_fails(db_app: Flask) -> None:
    """`pending` ist Pre-Triage-only und MUSS auf Group-Ebene rejected werden."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_group(label="bad-pending", risk_band="pending"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_insert_invalid_band_unknown_fails(db_app: Flask) -> None:
    """`unknown` ist ebenfalls Pre-Triage-only."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_group(label="bad-unknown", risk_band="unknown"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_insert_invalid_source_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_group(label="bad-source", source="something"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_duplicate_label_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(_new_group(label="dupe"))
            sess.commit()
            sess.add(_new_group(label="dupe"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_finding_with_nonexistent_group_fk_fails(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="srv-fk")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                Finding(
                    server_id=server_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key="CVE-2099-0001",
                    package_name="openssh-server",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.NETWORK,
                    status=FindingStatus.OPEN,
                    application_group_id=999_999,
                )
            )
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_group_delete_sets_finding_fk_null(db_app: Flask) -> None:
    """ON DELETE SET NULL: gelöschte Group setzt FK auf Finding auf NULL."""
    server_id, _ = register_test_server(db_app, name="srv-setnull")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group(label="will-be-deleted")
            sess.add(grp)
            sess.flush()
            group_id = grp.id

            f = Finding(
                server_id=server_id,
                finding_type=FindingType.VULNERABILITY,
                finding_class=FindingClass.OS_PKGS,
                identifier_key="CVE-2099-0002",
                package_name="openssh-server",
                severity=Severity.HIGH,
                attack_vector=AttackVector.NETWORK,
                status=FindingStatus.OPEN,
                application_group_id=group_id,
            )
            sess.add(f)
            sess.commit()
            finding_id = f.id

            # Group loeschen → FK soll auf NULL fallen.
            sess.delete(grp)
            sess.commit()

            reloaded = sess.execute(select(Finding).where(Finding.id == finding_id)).scalar_one()
            assert reloaded.application_group_id is None
        finally:
            sess.close()


def test_server_delete_does_not_cascade_to_group(db_app: Flask) -> None:
    """Application-Group lebt unabhaengig vom Server-Lifecycle.

    Server-Delete cascadiert auf Findings, aber NICHT auf die Group selber —
    Group ist eine flotten-weite Library-Entitaet.
    """
    server_id, _ = register_test_server(db_app, name="srv-grp-life")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group(label="library-survives")
            sess.add(grp)
            sess.flush()
            group_id = grp.id

            sess.add(
                Finding(
                    server_id=server_id,
                    finding_type=FindingType.VULNERABILITY,
                    finding_class=FindingClass.OS_PKGS,
                    identifier_key="CVE-2099-0003",
                    package_name="openssh-server",
                    severity=Severity.HIGH,
                    attack_vector=AttackVector.NETWORK,
                    status=FindingStatus.OPEN,
                    application_group_id=group_id,
                )
            )
            sess.commit()

            srv = sess.execute(select(Server).where(Server.id == server_id)).scalar_one()
            sess.delete(srv)
            sess.commit()

            still = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.id == group_id)
            ).scalar_one_or_none()
            assert still is not None, "Group sollte Server-Delete ueberleben"
        finally:
            sess.close()
