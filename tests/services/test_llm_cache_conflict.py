"""Pure-Unit-Tests fuer Block U Phase D — Pass-2-Cache-Conflict
(siehe ``docs/blocks/U-worker-concurrency.md`` §Phase D).

Getestet wird ausschliesslich :func:`app.services.llm_cache.store`. Phase D
hat den ORM-``session.add(LLMRiskCache(...))`` durch einen Postgres-
spezifischen ``INSERT ... ON CONFLICT DO NOTHING``-Statement ersetzt, damit
zwei parallele Worker-Tasks denselben ``cache_key`` produzieren koennen
ohne ``IntegrityError``.

Alle Tests verwenden eine ``MagicMock``-Session — keine echte DB. Wir
inspizieren das uebergebene ``stmt`` durch Compile gegen den Postgres-Dialect
(in-memory, kein Roundtrip).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy.dialects import postgresql

from app.services.llm_cache import store


def _store_args() -> dict[str, object]:
    """Vollstaendiges Argument-Set fuer einen ``store(...)``-Call.

    Spiegelt die heutige ``store``-Signatur (cache_key, group_id,
    group_findings_fp, cve_data_fp, server_context_fp, risk_band,
    worst_finding_id, reason, llm_model, action_type).
    """
    return {
        "cache_key": "a" * 64,
        "group_id": 42,
        "group_findings_fp": "g" * 16,
        "cve_data_fp": "c" * 16,
        "server_context_fp": "s" * 16,
        "risk_band": "act",
        "worst_finding_id": 7,
        "reason": "patch verfuegbar",
        "llm_model": "test-model-v1",
        "action_type": "patch",
    }


# ---------------------------------------------------------------------------
# 1) Statement nutzt PG-Insert mit ON CONFLICT DO NOTHING
# ---------------------------------------------------------------------------


def test_store_uses_pg_insert_with_on_conflict_do_nothing() -> None:
    """``store(...)`` muss ein PG-INSERT mit ``ON CONFLICT DO NOTHING`` emit."""
    session = MagicMock()
    result = store(session, **_store_args())  # type: ignore[arg-type]

    assert result is None, "store() soll None zurueckgeben (Phase D)"
    assert session.execute.call_count == 1, (
        f"execute() sollte genau 1x gerufen werden, war {session.execute.call_count}x"
    )

    stmt = session.execute.call_args[0][0]
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    upper = compiled.upper()
    assert "ON CONFLICT" in upper and "DO NOTHING" in upper, (
        f"Compile-String muss 'ON CONFLICT ... DO NOTHING' enthalten, war:\n{compiled}"
    )
    # PG kompiliert mit index_elements=["cache_key"] zu 'ON CONFLICT (cache_key) DO NOTHING'.
    # Wir akzeptieren explicit-Target und ohne-Target — beide Varianten haben dieselbe Semantik.
    on_conflict_idx = upper.find("ON CONFLICT")
    do_nothing_idx = upper.find("DO NOTHING")
    assert do_nothing_idx > on_conflict_idx, (
        f"DO NOTHING muss nach ON CONFLICT erscheinen:\n{compiled}"
    )
    assert "INSERT INTO LLM_RISK_CACHE" in upper, (
        f"Compile-String muss INSERT INTO llm_risk_cache enthalten:\n{compiled}"
    )


# ---------------------------------------------------------------------------
# 2) Alle Spalten landen im VALUES-Clause
# ---------------------------------------------------------------------------


def test_store_passes_all_columns() -> None:
    """Compile-Params enthalten alle Spalten die ``store`` uebergibt."""
    session = MagicMock()
    args = _store_args()
    store(session, **args)  # type: ignore[arg-type]

    stmt = session.execute.call_args[0][0]
    compiled = stmt.compile(dialect=postgresql.dialect())
    params = compiled.params

    expected_columns = {
        "cache_key",
        "group_id",
        "group_findings_fp",
        "cve_data_fp",
        "server_context_fp",
        "risk_band",
        "action_type",
        "worst_finding_id",
        "reason",
        "llm_model",
    }
    actual_keys = set(params.keys())
    missing = expected_columns - actual_keys
    assert not missing, (
        f"Folgende Spalten fehlen in den Compile-Params: {missing}\nActual: {actual_keys}"
    )

    # Werte selbst stimmen mit den Inputs ueberein.
    assert params["cache_key"] == args["cache_key"]
    assert params["group_id"] == args["group_id"]
    assert params["risk_band"] == args["risk_band"]
    assert params["reason"] == args["reason"]
    assert params["llm_model"] == args["llm_model"]
    assert params["action_type"] == args["action_type"]
    assert params["worst_finding_id"] == args["worst_finding_id"]


# ---------------------------------------------------------------------------
# 3) Return-Wert ist None (Signatur-Change Phase D)
# ---------------------------------------------------------------------------


def test_store_returns_none() -> None:
    """``store(...)`` returnt ``None`` — kein ORM-Objekt mehr (Phase D)."""
    session = MagicMock()
    result = store(session, **_store_args())  # type: ignore[arg-type]
    assert result is None, f"store soll None zurueckgeben, war {result!r}"


# ---------------------------------------------------------------------------
# 4) ON-CONFLICT-Target ist ``cache_key`` (Primary-Key)
# ---------------------------------------------------------------------------


def test_store_targets_cache_key_index_element() -> None:
    """ON-CONFLICT-Target-Index muss ``cache_key`` sein (Primary-Key des Models)."""
    session = MagicMock()
    store(session, **_store_args())  # type: ignore[arg-type]

    stmt = session.execute.call_args[0][0]
    compiled = str(stmt.compile(dialect=postgresql.dialect()))
    # PG kompiliert ``index_elements=["cache_key"]`` zu ``ON CONFLICT (cache_key) DO NOTHING``.
    assert "(cache_key)" in compiled.lower() or "cache_key" in compiled.lower(), (
        f"Compile-String muss cache_key als ON-CONFLICT-Index-Element fuehren:\n{compiled}"
    )
    # Defensive: das Wort cache_key tritt im VALUES auf, aber auch im ON-CONFLICT.
    # Wir wollen sicherstellen dass es NACH dem 'ON CONFLICT' vorkommt.
    upper = compiled.upper()
    on_conflict_idx = upper.find("ON CONFLICT")
    assert on_conflict_idx >= 0, "ON CONFLICT muss im Statement vorkommen"
    tail = compiled[on_conflict_idx:].lower()
    assert "cache_key" in tail, (
        f"cache_key muss nach 'ON CONFLICT' erscheinen, ON-CONFLICT-Tail:\n{tail}"
    )


# ---------------------------------------------------------------------------
# 5) Regression-Schutz — kein session.add(...) mehr
# ---------------------------------------------------------------------------


def test_store_no_session_add_call() -> None:
    """``store`` darf nicht zurueck auf ORM-``session.add`` rutschen.

    Regression-Schutz fuer Phase D: der alte Pfad ``session.add(LLMRiskCache(...))``
    ist nicht mehr concurrency-safe (IntegrityError bei Sibling-Insert).
    """
    session = MagicMock()
    store(session, **_store_args())  # type: ignore[arg-type]
    assert session.add.call_count == 0, (
        f"store() darf session.add() NICHT mehr aufrufen "
        f"(Pre-Phase-D-Pfad), war {session.add.call_count}x gerufen"
    )
