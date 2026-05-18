"""LLM-Risk-Cache-Helper fuer Block P (ADR-0023) — Pass-2-Cache.

Vier Operationen:

* :func:`lookup` — TTL-aware Cache-Lookup auf ``llm_risk_cache.cache_key``.
* :func:`record_hit` — ``used_count += 1``, ``last_used_at = now()``.
* :func:`store` — Cache-Eintrag persistieren (Caller commitet).
* :func:`lru_evict_if_needed` — Single-Statement-DELETE bei
  Tabellengroesse > ``LLM_CACHE_MAX_ROWS``.

TTL und LRU-Schwelle werden aus :func:`app.config.load_settings()` gelesen
(``llm_cache_ttl_days`` / ``llm_cache_max_rows``). Beide Werte koennen pro
Deploy ueber ``SECSCAN_LLM_CACHE_*``-Env-Vars ueberschrieben werden.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
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
) -> LLMRiskCache:
    """Legt einen neuen Cache-Eintrag an. Caller muss commit."""
    entry = LLMRiskCache(
        cache_key=cache_key,
        group_id=group_id,
        group_findings_fp=group_findings_fp,
        cve_data_fp=cve_data_fp,
        server_context_fp=server_context_fp,
        risk_band=risk_band,
        worst_finding_id=worst_finding_id,
        reason=reason,
        llm_model=llm_model,
    )
    session.add(entry)
    return entry


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
