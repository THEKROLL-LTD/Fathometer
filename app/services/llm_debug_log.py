"""Operator-Debugging-Log fuer LLM-Calls (Block P, v0.9.3, ADR-0023 §"(e)").

Drei Operationen:

* :func:`record` — schreibt eine Row mit (gecappten) Request/Response-Bodies
  und Reasoning-Feld. Wird vom Worker nach jedem LLM-Call aufgerufen (Erfolg
  wie Fehler).
* :func:`evict_old` — Time-Cap + Count-Cap-DELETEs. Wird vom Worker als
  Sub-Tick alle 10 Minuten aufgerufen.
* :func:`_apply_body_cap` — interner Helper fuer Per-Body-Size-Trimming.

Body-Size-Cap (``llm_debug_log_body_size_cap``, default 64 KB) gilt pro
``request_body`` und ``response_body`` separat. Bei Ueberschreitung wird
das Body-Dict durch ein Stub-Dict ersetzt:

.. code:: json

   {"__truncated": true, "original_size_bytes": 123456, "preview": "..."}
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import load_settings
from app.models import LLMDebugLog, LLMJob


def should_sample_debug_log(
    job_id: int,
    job_type: str,
    status: str,
    sample_rate: int,
) -> bool:
    """Entscheidet, ob eine Debug-Log-Row fuer diesen Call geschrieben werden soll.

    Block U Phase G (ADR-0029): unter N=200-Concurrency wuerde der Worker
    bis zu ~12 Inserts/s in ``llm_debug_log`` erzeugen. Wir samplen
    Success-Calls auf 1:``sample_rate`` herunter und behalten alle
    Fehler-Calls 1:1, damit Forensik (validation_error, timeout, error,
    ...) verlustfrei bleibt.

    Semantik:

    * ``status != "success"`` -> immer True (Errors werden nie gesampelt).
    * ``sample_rate <= 1``    -> immer True (Sampling deaktiviert).
    * sonst                   -> True wenn ``hash((job_id, job_type)) %
      sample_rate == 0``.

    ``hash()`` ist innerhalb desselben Prozesses deterministisch (gleicher
    Input -> gleicher Output), zwischen Prozessen aber via
    ``PYTHONHASHSEED`` randomisiert. Das ist hier kein Problem, weil
    Sampling-Entscheidungen pro Job genau einmal getroffen werden.
    """
    if status != "success":
        return True
    if sample_rate <= 1:
        return True
    h = abs(hash((int(job_id), job_type)))
    return (h % sample_rate) == 0


def _apply_body_cap(body: dict[str, Any] | None, cap_bytes: int) -> dict[str, Any] | None:
    """Trimmt ``body`` falls ``json.dumps(body)`` > ``cap_bytes``.

    Bei Ueberschreitung wird ein Stub-Dict zurueckgegeben mit:

    * ``__truncated``: ``True``
    * ``original_size_bytes``: Original-JSON-Groesse
    * ``preview``: erste ``cap_bytes - 256`` Bytes des Originals als String

    Bei ``None`` als Input bleibt es bei ``None``.
    """
    if body is None:
        return None
    try:
        serialized = json.dumps(body, default=str)
    except (TypeError, ValueError):
        # Nicht-serialisierbarer Inhalt → wir capen aggressiv auf einen
        # repr-String, damit der Insert nicht selbst explodiert.
        repr_str = repr(body)[: max(256, cap_bytes - 256)]
        return {
            "__truncated": True,
            "original_size_bytes": -1,
            "preview": repr_str,
            "note": "body not JSON-serializable; repr() preview only",
        }
    if len(serialized) <= cap_bytes:
        return body
    # Trim: wir nehmen die ersten (cap - 256) Bytes des serialisierten
    # Strings als Preview — das ist nicht zwingend valides JSON, aber
    # menschlich lesbar fuer den Operator.
    preview_len = max(256, cap_bytes - 256)
    return {
        "__truncated": True,
        "original_size_bytes": len(serialized),
        "preview": serialized[:preview_len],
    }


def record(
    session: Session,
    *,
    job: LLMJob | None,
    job_type: str,
    status: str,
    model: str,
    request_body: dict[str, Any],
    response_body: dict[str, Any] | None,
    duration_ms: int,
    server_id: int | None = None,
    group_id: int | None = None,
    error: str | None = None,
) -> LLMDebugLog:
    """Schreibt eine Debug-Log-Row. Caller muss commit.

    ``job`` ist optional — falls vorhanden, wird ``job_id`` daraus gezogen.
    ``server_id``/``group_id`` koennen separat uebergeben werden (Pass-2-
    Caller weiss die Werte ohne Job-Lookup).
    """
    cfg = load_settings()
    cap = cfg.llm_debug_log_body_size_cap
    capped_req = _apply_body_cap(request_body, cap)
    capped_res = _apply_body_cap(response_body, cap)
    if capped_req is None:
        # ``request_body`` ist NOT NULL — defensiv Stub schreiben.
        capped_req = {"__truncated": False, "note": "empty request body"}

    job_id_val: int | None = None
    if job is not None:
        job_id_val = int(job.id) if job.id is not None else None
        if server_id is None:
            server_id = job.server_id

    entry = LLMDebugLog(
        job_type=job_type,
        job_id=job_id_val,
        server_id=server_id,
        group_id=group_id,
        model=model[:64],
        request_body=capped_req,
        response_body=capped_res,
        duration_ms=max(0, int(duration_ms)),
        status=status,
        error=(error[:65536] if error else None),
    )
    session.add(entry)
    return entry


def evict_old(session: Session) -> tuple[int, int]:
    """Eviction-Sub-Tick: Time-Cap + Count-Cap-DELETEs.

    Returns ``(time_evicted, count_evicted)``-Tuple mit den jeweiligen
    Row-Counts. Caller muss commit (oder die Funktion committet selbst —
    wir machen das hier, damit der Worker keine Annahmen treffen muss).
    """
    cfg = load_settings()
    # Step 1: Time-Cap.
    time_result = session.execute(
        text("DELETE FROM llm_debug_log WHERE created_at < now() - make_interval(days => :days)"),
        {"days": cfg.llm_debug_log_max_age_days},
    )
    time_evicted = int(getattr(time_result, "rowcount", 0) or 0)

    # Step 2: Count-Cap.
    # Block U Phase G (ADR-0029): CTE-DELETE statt ``NOT IN`` — der NOT-IN-
    # Plan ist auf grossen Tabellen O(n^2)-haftig und blockt unter N=200-
    # Last den Insert-Strom. ``ORDER BY created_at DESC, id DESC`` mit ``id``
    # als Tie-Breaker, damit Sub-Sekunden-Kollisionen in ``created_at``
    # deterministisch sind.
    count_result = session.execute(
        text(
            "DELETE FROM llm_debug_log USING ("
            "  SELECT id FROM llm_debug_log "
            "  ORDER BY created_at DESC, id DESC "
            "  OFFSET :max_rows"
            ") AS to_evict "
            "WHERE llm_debug_log.id = to_evict.id"
        ),
        {"max_rows": cfg.llm_debug_log_max_rows},
    )
    count_evicted = int(getattr(count_result, "rowcount", 0) or 0)

    session.commit()
    return time_evicted, count_evicted


__all__ = ["evict_old", "record", "should_sample_debug_log"]
