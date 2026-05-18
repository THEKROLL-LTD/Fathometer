"""Block P (ADR-0023) — Modell-Tests fuer `llm_risk_cache`.

CheckConstraint auf risk_band (nur finale LLM-Bands).
PK-Duplicate via gleichem cache_key.
Group-Delete cascadiert auf Cache-Rows.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db import get_session_factory
from app.models import ApplicationGroup, LLMRiskCache


def _new_group(label: str = "k3s") -> ApplicationGroup:
    return ApplicationGroup(
        label=label,
        explanation="Test-Group.",
        path_prefixes=[],
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
    )


def _new_cache(
    *, group_id: int, cache_key: str, risk_band: str = "act", **overrides: Any
) -> LLMRiskCache:
    defaults: dict[str, Any] = {
        "cache_key": cache_key,
        "group_id": group_id,
        "group_findings_fp": "a" * 16,
        "cve_data_fp": "b" * 16,
        "server_context_fp": "c" * 16,
        "risk_band": risk_band,
        "worst_finding_id": None,
        "reason": "Test reason.",
        "llm_model": "deepseek-v3",
    }
    defaults.update(overrides)
    return LLMRiskCache(**defaults)


def test_insert_valid_cache_row(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group()
            sess.add(grp)
            sess.flush()
            cache = _new_cache(group_id=grp.id, cache_key="d" * 64)
            sess.add(cache)
            sess.commit()
            row = sess.execute(
                select(LLMRiskCache).where(LLMRiskCache.cache_key == "d" * 64)
            ).scalar_one()
            assert row.risk_band == "act"
            assert row.used_count == 1
        finally:
            sess.close()


def test_invalid_band_pending_fails(db_app: Flask) -> None:
    """`pending` ist Pre-Triage-only und im Cache verboten."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group(label="grp-pending")
            sess.add(grp)
            sess.flush()
            sess.add(_new_cache(group_id=grp.id, cache_key="e" * 64, risk_band="pending"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_invalid_band_unknown_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group(label="grp-unknown")
            sess.add(grp)
            sess.flush()
            sess.add(_new_cache(group_id=grp.id, cache_key="f" * 64, risk_band="unknown"))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_pk_duplicate_fails(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group(label="grp-dupe")
            sess.add(grp)
            sess.flush()
            sess.add(_new_cache(group_id=grp.id, cache_key="0" * 64))
            sess.commit()
            sess.add(_new_cache(group_id=grp.id, cache_key="0" * 64))
            with pytest.raises(IntegrityError):
                sess.commit()
        finally:
            sess.rollback()
            sess.close()


def test_group_delete_cascades_to_cache(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _new_group(label="grp-cascade")
            sess.add(grp)
            sess.flush()
            gid = grp.id
            sess.add(_new_cache(group_id=gid, cache_key="1" * 64))
            sess.commit()

            sess.delete(grp)
            sess.commit()

            still = sess.execute(
                select(LLMRiskCache).where(LLMRiskCache.cache_key == "1" * 64)
            ).scalar_one_or_none()
            assert still is None
        finally:
            sess.close()
