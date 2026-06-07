# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""LLM-Risk-Cache-Helper fuer Block P (ADR-0023) — Pass-2-Cache.

Vier Operationen:

* :func:`lookup` — TTL-aware Cache-Lookup auf ``llm_risk_cache.cache_key``.
* :func:`record_hit` — ``used_count += 1``, ``last_used_at = now()``.
* :func:`store` — Cache-Eintrag persistieren (Caller commitet).
* :func:`lru_evict_if_needed` — Single-Statement-DELETE bei
  Tabellengroesse > ``LLM_CACHE_MAX_ROWS``.

TTL und LRU-Schwelle werden aus :func:`app.config.load_settings()` gelesen
(``llm_cache_ttl_days`` / ``llm_cache_max_rows``). Beide Werte koennen pro
Deploy ueber ``FM_LLM_CACHE_*``-Env-Vars ueberschrieben werden.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.config import Settings, load_settings
from app.models import LLMRiskCache


def _get_settings() -> Settings:
    """Lazy-Loader fuer die Settings-Singleton.

    Pro Call neu geladen, weil die ``Settings``-Klasse keine globalen
    Mutationen erlaubt — pydantic-settings cached die Env intern, der
    Aufruf ist billig.
    """
    return load_settings()


def lookup(session: Session, cache_key: str) -> LLMRiskCache | None:
    """TTL-aware Cache-Lookup. Returns ``None`` bei Miss oder Verfall.

    Eintraege aelter als ``LLM_CACHE_TTL_DAYS`` werden ignoriert (kein
    aktives Loeschen — der naechste LLM-Call schreibt einen frischen
    Eintrag, der alte wird per LRU spaeter verdraengt).
    """
    cached = (
        session.execute(select(LLMRiskCache).where(LLMRiskCache.cache_key == cache_key))
        .scalars()
        .first()
    )
    if cached is None:
        return None
    ttl_days = _get_settings().llm_cache_ttl_days
    computed_at = cached.computed_at
    if computed_at.tzinfo is None:
        computed_at = computed_at.replace(tzinfo=UTC)
    if datetime.now(UTC) - computed_at > timedelta(days=ttl_days):
        return None
    return cached


def record_hit(session: Session, cached: LLMRiskCache) -> None:
    """``used_count += 1``, ``last_used_at = now()``.

    Caller muss commit. Wir nutzen ``func.now()`` statt
    ``datetime.now(UTC)`` damit die DB-eigene Clock-Quelle bestimmt — das
    matched das ``server_default``-Pattern an anderen Spalten.
    """
    cached.used_count = (cached.used_count or 0) + 1
    cached.last_used_at = func.now()


def store(
    session: Session,
    *,
    cache_key: str,
    group_id: int,
    group_findings_fp: str,
    cve_data_fp: str,
    server_context_fp: str,
    risk_band: str,
    worst_finding_id: int | None,
    reason: str,
    llm_model: str | None,
    action_type: str | None = None,
) -> None:
    """Legt einen neuen Cache-Eintrag an. Caller muss commit.

    ``action_type`` ist v0.9.3-Pflichtfeld auf der Group, im Cache aber
    nullable fuer Forward-Compat mit Pre-v0.9.3-Eintraegen (alte Caches
    werden beim Restore mit ``action_type=None`` zurueckgespielt; das
    Worker-``_apply_pass2_to_group`` setzt das Feld dann nicht).

    Block U Phase D (ADR-0029 §Entscheidung Punkt 5): Unter paralleler
    Worker-Concurrency koennen zwei in-flight Pass-2-Jobs denselben
    ``cache_key`` produzieren (gleicher Group-Fingerprint, derselbe
    CVE-Snapshot). Wir nutzen ``INSERT ... ON CONFLICT DO NOTHING`` ueber
    den Primary-Key ``cache_key``: der zweite Insert ist ein No-Op statt
    eines ``IntegrityError``. Der erste persistierte Eintrag gewinnt; das
    ist akzeptabel, weil identische Inputs identische Outputs liefern
    sollten (Cache-Sinn). Vorbild: ADR-0028 §Pass-2-Persistierung mit
    Junction-UPSERT.

    ``cache_key`` ist Primary-Key in :class:`LLMRiskCache` (siehe
    ``app/models.py`` Zeile 1003), damit ist der ON-CONFLICT-Target-Index
    eindeutig.
    """
    stmt = (
        pg_insert(LLMRiskCache)
        .values(
            cache_key=cache_key,
            group_id=group_id,
            group_findings_fp=group_findings_fp,
            cve_data_fp=cve_data_fp,
            server_context_fp=server_context_fp,
            risk_band=risk_band,
            action_type=action_type,
            worst_finding_id=worst_finding_id,
            reason=reason,
            llm_model=llm_model,
        )
        .on_conflict_do_nothing(index_elements=["cache_key"])
    )
    session.execute(stmt)


def lru_evict_if_needed(session: Session) -> int:
    """Single-Statement-DELETE bei Tabellengroesse > ``LLM_CACHE_MAX_ROWS``.

    Strategie: COUNT, dann ein DELETE mit ORDER-BY-Subquery — kein N+1,
    kein Load aller Rows in den ORM-Identity-Map. Returns Anzahl der
    geloeschten Rows.
    """
    max_rows = _get_settings().llm_cache_max_rows
    total = session.execute(select(func.count()).select_from(LLMRiskCache)).scalar_one()
    if total <= max_rows:
        return 0
    excess = int(total) - int(max_rows)
    victims_subq = (
        select(LLMRiskCache.cache_key)
        .order_by(LLMRiskCache.last_used_at.asc())
        .limit(excess)
        .scalar_subquery()
    )
    result = session.execute(delete(LLMRiskCache).where(LLMRiskCache.cache_key.in_(victims_subq)))
    rowcount = getattr(result, "rowcount", None)
    return int(rowcount) if rowcount is not None else 0


__all__ = ["lookup", "lru_evict_if_needed", "record_hit", "store"]
