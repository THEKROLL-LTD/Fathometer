"""Integration-Smokes fuer `app/services/llm_cache.py` gegen echte Postgres-DB.

Diese Tests wurden aus `tests/services/test_llm_cache.py` ausgelagert
(TICKET-004, Slice 4). Der Service ist ein reiner ORM-Wrapper auf der
``llm_risk_cache``-Tabelle (lookup-Query, store-Insert, record_hit-Update,
lru_evict-Delete); die Tests pruefen genau diese SQL-Operationen mit echter
Postgres-Persistenz. Eine Mock-Variante waere ohne breite Session-Mocks
nicht sinnvoll abbildbar.

Auto-Markierung als ``db_integration`` (und damit ``acceptance``) erfolgt
ueber `tests/conftest.py::_ACCEPTANCE_PATH_PREFIXES`.

Sechs Faelle:

* Cache-Hit mit frischem Eintrag.
* Cache-Miss bei unbekanntem Key.
* TTL-Verfall (Eintrag > ``llm_cache_ttl_days`` alt → None).
* ``record_hit`` erhoeht ``used_count`` und schreibt ``last_used_at``.
* ``store`` legt einen neuen Eintrag korrekt an.
* ``lru_evict_if_needed`` loescht aelteste ``last_used_at`` wenn Tabelle
  ueber ``llm_cache_max_rows`` ist.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from flask import Flask
from sqlalchemy import func, select

from app.config import load_settings
from app.db import get_session_factory
from app.models import ApplicationGroup, LLMRiskCache
from app.services.llm_cache import (
    lookup,
    lru_evict_if_needed,
    record_hit,
    store,
)


def _make_group(sess, label: str) -> ApplicationGroup:
    g = ApplicationGroup(
        label=label,
        explanation=f"test {label}",
        path_prefixes=[],
        pkg_name_exact=[label],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )
    sess.add(g)
    sess.flush()
    return g


def test_lookup_returns_fresh_entry(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _make_group(sess, "alpha")
            store(
                sess,
                cache_key="a" * 64,
                group_id=grp.id,
                group_findings_fp="g" * 16,
                cve_data_fp="c" * 16,
                server_context_fp="s" * 16,
                risk_band="act",
                worst_finding_id=None,
                reason="patch verfuegbar",
                llm_model="test-model-v1",
            )
            sess.commit()

            hit = lookup(sess, "a" * 64)
            assert hit is not None
            assert hit.risk_band == "act"
            assert hit.reason == "patch verfuegbar"
        finally:
            sess.close()


def test_lookup_returns_none_for_unknown_key(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            assert lookup(sess, "f" * 64) is None
        finally:
            sess.close()


def test_lookup_returns_none_for_expired_entry(db_app: Flask) -> None:
    """Eintrag mit ``computed_at`` weiter zurueck als TTL → None."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _make_group(sess, "beta")
            cfg = load_settings()
            ttl = cfg.llm_cache_ttl_days
            entry = LLMRiskCache(
                cache_key="b" * 64,
                group_id=grp.id,
                group_findings_fp="g" * 16,
                cve_data_fp="c" * 16,
                server_context_fp="s" * 16,
                risk_band="monitor",
                worst_finding_id=None,
                reason="stale entry",
                llm_model="m",
                computed_at=datetime.now(UTC) - timedelta(days=ttl + 1),
                last_used_at=datetime.now(UTC) - timedelta(days=ttl + 1),
                used_count=1,
            )
            sess.add(entry)
            sess.commit()
            assert lookup(sess, "b" * 64) is None
        finally:
            sess.close()


def test_record_hit_increments_used_count(db_app: Flask) -> None:
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _make_group(sess, "gamma")
            store(
                sess,
                cache_key="c" * 64,
                group_id=grp.id,
                group_findings_fp="g" * 16,
                cve_data_fp="c" * 16,
                server_context_fp="s" * 16,
                risk_band="noise",
                worst_finding_id=None,
                reason="bluetooth inactive",
                llm_model="m",
            )
            sess.commit()

            cached = lookup(sess, "c" * 64)
            assert cached is not None
            before = cached.used_count or 0
            record_hit(sess, cached)
            sess.commit()
            sess.refresh(cached)
            assert (cached.used_count or 0) == before + 1
            assert cached.last_used_at is not None
        finally:
            sess.close()


def test_store_inserts_row(db_app: Flask) -> None:
    """Block U Phase D: ``store(...)`` returnt ``None`` (PG-INSERT ON CONFLICT
    DO NOTHING statt ORM-``session.add``). Wir verifizieren die Persistenz
    nicht mehr ueber den Return-Wert, sondern via ``lookup``-Roundtrip.
    """
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _make_group(sess, "delta")
            result = store(
                sess,
                cache_key="d" * 64,
                group_id=grp.id,
                group_findings_fp="g" * 16,
                cve_data_fp="c" * 16,
                server_context_fp="s" * 16,
                risk_band="escalate",
                worst_finding_id=42,
                reason="KEV listed",
                llm_model="m",
            )
            sess.commit()
            assert result is None, "store() returnt seit Phase D None"
            persisted = lookup(sess, "d" * 64)
            assert persisted is not None, "Eintrag muss nach store+commit auffindbar sein"
            assert persisted.cache_key == "d" * 64
            assert persisted.risk_band == "escalate"
            assert persisted.worst_finding_id == 42
            count = sess.execute(select(func.count()).select_from(LLMRiskCache)).scalar_one()
            assert count == 1
        finally:
            sess.close()


def test_lru_evict_when_over_limit(db_app: Flask, monkeypatch: pytest.MonkeyPatch) -> None:
    """Wenn Tabelle > ``llm_cache_max_rows``, loescht ``lru_evict_if_needed``
    die aeltesten ``last_used_at``."""
    factory = get_session_factory(db_app)

    # Monkeypatch der Settings-Loader-Funktion, damit wir das Limit klein
    # halten koennen — wir wollen keine 100K Rows in den Tests einlegen.
    import app.services.llm_cache as cache_mod

    real_loader = cache_mod._get_settings

    class _Patched:
        llm_cache_ttl_days = 30
        llm_cache_max_rows = 3

    monkeypatch.setattr(cache_mod, "_get_settings", lambda: _Patched())

    with db_app.app_context():
        sess = factory()
        try:
            grp = _make_group(sess, "epsilon")
            now = datetime.now(UTC)
            # Fuenf Eintraege mit aufsteigender ``last_used_at``.
            for i in range(5):
                entry = LLMRiskCache(
                    cache_key=f"{i:064d}",
                    group_id=grp.id,
                    group_findings_fp="g" * 16,
                    cve_data_fp="c" * 16,
                    server_context_fp="s" * 16,
                    risk_band="monitor",
                    worst_finding_id=None,
                    reason=f"entry {i}",
                    llm_model="m",
                    computed_at=now - timedelta(minutes=10 - i),
                    last_used_at=now - timedelta(minutes=10 - i),
                    used_count=1,
                )
                sess.add(entry)
            sess.commit()
            assert sess.execute(select(func.count()).select_from(LLMRiskCache)).scalar_one() == 5

            deleted = lru_evict_if_needed(sess)
            sess.commit()
            assert deleted == 2

            remaining = sess.execute(select(LLMRiskCache.cache_key)).scalars().all()
            remaining_set = set(remaining)
            # Die aeltesten zwei (i=0,1) sind weg.
            assert f"{0:064d}" not in remaining_set
            assert f"{1:064d}" not in remaining_set
            assert f"{4:064d}" in remaining_set
        finally:
            sess.close()
            monkeypatch.setattr(cache_mod, "_get_settings", real_loader)
