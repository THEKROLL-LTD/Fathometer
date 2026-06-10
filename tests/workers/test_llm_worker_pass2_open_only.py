# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer TICKET-010 Etappe 2 — ``_do_pass2`` bewertet nur OPEN.

Bug-B-Regression (Fingerprint-Domain-Mismatch Enqueue <-> Worker):

* Beide ``select(Finding)``-Loads in ``_do_pass2`` (Fingerprint-Phase und
  Detached-Reload) MUESSEN auf ``Finding.status == FindingStatus.OPEN``
  filtern — identische WHERE-Semantik wie
  ``pass2_enqueue.enqueue_pass2_for_server``.
* Resolved/acknowledged Findings duerfen weder in den Fingerprint noch in
  den LLM-Input gelangen (sonst waere ein geschlossenes Finding als
  ``worst_finding_id`` waehlbar).
* Wenn zwischen Phase 1 und Phase 2 alle Findings der Group geschlossen
  werden (Triage-/Ingest-Race), endet der Job done/skipped mit Reason
  ``"no open findings in group on server"`` — ohne LLM-Call.

Kein DB-Roundtrip: die Fake-Session wertet die WHERE-Klausel der
``select(Finding)``-Statements in-memory aus (eq + in_). Damit testen wir
das *echte* Statement das der Code baut — nicht ein gemocktes Resultat,
das den Status-Filter verschleiern wuerde.
"""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy.sql import operators as sa_operators
from sqlalchemy.sql.selectable import Select

from app.models import (
    ApplicationGroup,
    ApplicationGroupEvaluation,
    Finding,
    FindingStatus,
    LLMJob,
    Server,
)
from app.services.llm_fingerprints import group_findings_fingerprint
from app.services.pass2_enqueue import enqueue_pass2_for_server
from app.workers import llm_worker

JOB_ID = 99
GROUP_ID = 7
SERVER_ID = 3


# ---------------------------------------------------------------------------
# Fakes: In-Memory-WHERE-Evaluation statt gemockter Result-Listen
# ---------------------------------------------------------------------------


def _eval_where(stmt: Select[Any], rows: list[Any]) -> list[Any]:
    """Wertet die WHERE-Klausel eines ``select(Finding)`` in-memory aus.

    Unterstuetzt ``==`` und ``IN`` — genau die Operatoren die beide
    Code-Pfade (Worker + Enqueue) benutzen. Unbekannte Operatoren werfen,
    damit eine WHERE-Aenderung im App-Code den Test sichtbar bricht statt
    still alles durchzulassen.
    """
    where = stmt.whereclause
    if where is None:
        return list(rows)
    conds = list(where.clauses) if hasattr(where, "clauses") else [where]
    out: list[Any] = []
    for row in rows:
        for cond in conds:
            col_name = cond.left.name
            actual = getattr(row, col_name)
            if cond.operator is sa_operators.in_op:
                if actual not in cond.right.value:
                    break
            elif cond.operator is sa_operators.eq:
                if actual != cond.right.value:
                    break
            else:  # pragma: no cover - Schutz gegen WHERE-Drift
                raise AssertionError(f"unsupported operator in WHERE: {cond.operator}")
        else:
            out.append(row)
    return out


def _status_bind_values(stmt: Select[Any]) -> list[Any]:
    """Bind-Werte aller ``findings.status``-Vergleiche der WHERE-Klausel."""
    where = stmt.whereclause
    assert where is not None, "statement has no WHERE clause"
    conds = list(where.clauses) if hasattr(where, "clauses") else [where]
    return [c.right.value for c in conds if getattr(c.left, "name", None) == "status"]


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return self._rows


class _FakeSession:
    """DB-freie Session: ``get`` aus Identity-Map, ``execute`` mit
    In-Memory-WHERE-Evaluation fuer ``select(Finding)``."""

    def __init__(
        self,
        *,
        identity: dict[tuple[type, int], Any] | None = None,
        findings: list[Any] | None = None,
        groups: list[Any] | None = None,
        evals: list[Any] | None = None,
        active_jobs: list[Any] | None = None,
    ) -> None:
        self.identity = identity or {}
        self.findings = findings or []
        self.groups = groups or []
        self.evals = evals or []
        self.active_jobs = active_jobs or []
        self.executed: list[Select[Any]] = []
        self.added: list[Any] = []
        self.committed = 0

    def get(self, model: type, pk: int) -> Any:
        return self.identity.get((model, pk))

    def execute(self, stmt: Select[Any], params: Any = None) -> _Result:
        self.executed.append(stmt)
        entity = stmt.column_descriptions[0]["entity"]
        if entity is Finding:
            return _Result(_eval_where(stmt, self.findings))
        if entity is ApplicationGroup:
            return _Result(self.groups)
        if entity is ApplicationGroupEvaluation:
            return _Result(self.evals)
        if entity is LLMJob:
            return _Result(self.active_jobs)
        raise AssertionError(f"unexpected entity in fake session: {entity}")  # pragma: no cover

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    def flush(self) -> None:
        pass

    def commit(self) -> None:
        self.committed += 1


def _install_sessions(monkeypatch: pytest.MonkeyPatch, sessions: list[_FakeSession]) -> None:
    """``llm_worker.get_session`` liefert die Fake-Sessions in Reihenfolge."""
    it = iter(sessions)

    @contextmanager
    def _get() -> Any:
        yield next(it)

    monkeypatch.setattr(llm_worker, "get_session", _get)


def _mk_finding(fid: int, key: str, purl: str, status: FindingStatus) -> SimpleNamespace:
    return SimpleNamespace(
        id=fid,
        identifier_key=key,
        package_purl=purl,
        package_name="pkg",
        status=status,
        application_group_id=GROUP_ID,
        server_id=SERVER_ID,
    )


def _mixed_store() -> list[SimpleNamespace]:
    """Group mit gemischten Status: 2x open, 1x resolved, 1x acknowledged."""
    return [
        _mk_finding(1, "CVE-2026-0001", "pkg:deb/a@1", FindingStatus.OPEN),
        _mk_finding(2, "CVE-2026-0002", "pkg:deb/b@2", FindingStatus.OPEN),
        _mk_finding(3, "CVE-2026-0003", "pkg:deb/c@3", FindingStatus.RESOLVED),
        _mk_finding(4, "CVE-2026-0004", "pkg:deb/d@4", FindingStatus.ACKNOWLEDGED),
    ]


def _job() -> SimpleNamespace:
    return SimpleNamespace(
        payload={"group_id": GROUP_ID, "server_id": SERVER_ID},
        status="in_progress",
        completed_at=None,
        result=None,
    )


def _phase1_identity(job: SimpleNamespace) -> dict[tuple[type, int], Any]:
    return {
        (LLMJob, JOB_ID): job,
        (ApplicationGroup, GROUP_ID): SimpleNamespace(id=GROUP_ID, label="test-group"),
        (Server, SERVER_ID): SimpleNamespace(id=SERVER_ID),
    }


def _patch_phase1_helpers(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Patcht alle Phase-1-Nebenpfade; spied auf ``group_findings_fingerprint``.

    ``group_findings_fingerprint`` bleibt die ECHTE Funktion (wir wollen den
    realen Fingerprint vergleichen), wird aber gewrappt um den Input zu
    capturen. CVE-/Server-Fingerprints sind fuer die Domain-Frage irrelevant
    und werden auf Konstanten gepatcht.
    """
    captured: dict[str, Any] = {"fp_inputs": []}

    def _spy_fp(findings: list[Any]) -> str:
        captured["fp_inputs"].append(list(findings))
        fp = group_findings_fingerprint(findings)
        captured["fp"] = fp
        return fp

    monkeypatch.setattr(llm_worker, "_audit_pass2_with_failed_siblings", lambda *a, **k: None)
    monkeypatch.setattr(llm_worker, "group_findings_fingerprint", _spy_fp)
    monkeypatch.setattr(llm_worker, "cve_data_fingerprint", lambda f: "c" * 16)
    monkeypatch.setattr(llm_worker, "server_context_fingerprint", lambda s, session=None: "s" * 16)
    monkeypatch.setattr(llm_worker, "make_cache_key", lambda *a: "k" * 64)
    return captured


async def _run_pass2_cache_hit(
    monkeypatch: pytest.MonkeyPatch, store: list[SimpleNamespace]
) -> dict[str, Any]:
    """Treibt ``_do_pass2`` ueber den Cache-Hit-Pfad (kein LLM, keine Phase 2)
    und captured Fingerprint-Input + ``_upsert_evaluation``-Kwargs."""
    job = _job()
    sess = _FakeSession(identity=_phase1_identity(job), findings=store)
    _install_sessions(monkeypatch, [sess])
    captured = _patch_phase1_helpers(monkeypatch)

    cached = SimpleNamespace(risk_band="medium", reason="r", worst_finding_id=1, action_type="fix")
    monkeypatch.setattr(llm_worker, "lookup", lambda s, key: cached)
    monkeypatch.setattr(llm_worker, "record_hit", lambda s, c: None)
    upsert_kwargs: dict[str, Any] = {}
    monkeypatch.setattr(llm_worker, "_upsert_evaluation", lambda s, **kw: upsert_kwargs.update(kw))
    monkeypatch.setattr(llm_worker, "inherit_group_risk_to_findings", lambda s, **kw: 0)
    monkeypatch.setattr(llm_worker, "_audit", lambda *a, **k: None)

    await llm_worker._do_pass2(JOB_ID)
    return {"job": job, "session": sess, "captured": captured, "upsert": upsert_kwargs}


def _run_enqueue(store: list[SimpleNamespace], *, evals: list[Any]) -> tuple[int, _FakeSession]:
    """``enqueue_pass2_for_server`` gegen denselben Finding-Store (echter
    Fingerprint, echte WHERE-Evaluation)."""
    sess = _FakeSession(
        groups=[SimpleNamespace(id=GROUP_ID)],
        evals=evals,
        active_jobs=[],
        findings=store,
    )
    with patch("app.services.pass2_enqueue.log_event"):
        count = enqueue_pass2_for_server(sess, SERVER_ID, trigger="scan_ingest")
    return count, sess


# ---------------------------------------------------------------------------
# Ticket-Fall 2: resolved/acknowledged nicht im Fingerprint-/LLM-Input
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase1_load_excludes_resolved_and_acknowledged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Die Fingerprint-Phase laedt NUR open Findings — resolved/acknowledged
    sind weder im Fingerprint-Input noch (spaeter) als ``worst_finding_id``
    waehlbar, weil sie die geladene Findings-Liste nie erreichen."""
    out = await _run_pass2_cache_hit(monkeypatch, _mixed_store())
    loaded = out["captured"]["fp_inputs"][0]
    loaded_ids = sorted(f.id for f in loaded)
    assert loaded_ids == [1, 2], f"non-open findings leaked into pass2 input: {loaded_ids}"
    assert all(f.status == FindingStatus.OPEN for f in loaded)
    assert out["job"].status == "done"
    assert out["job"].result["cache_hit"] is True


@pytest.mark.asyncio
async def test_phase1_status_filter_is_open_in_where_clause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Das Phase-1-Statement traegt den OPEN-Filter in der WHERE-Klausel —
    nicht nur zufaellig passende Testdaten."""
    out = await _run_pass2_cache_hit(monkeypatch, _mixed_store())
    stmt = out["session"].executed[0]
    assert _status_bind_values(stmt) == [FindingStatus.OPEN], str(stmt)


# ---------------------------------------------------------------------------
# Ticket-Fall 1: Bug-B-Regression — Worker-Fingerprint == Enqueue-Fingerprint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_worker_fingerprint_equals_enqueue_fingerprint_on_mixed_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bug-B-Regression: beide Code-Pfade fingerprinten das OPEN-Subset.

    Der Fingerprint den ``_do_pass2`` persistiert (``_upsert_evaluation``)
    muss exakt dem Fingerprint entsprechen den ``enqueue_pass2_for_server``
    ueber dieselbe gemischte Group berechnet — und NICHT dem ALL-Set-FP.
    """
    store = _mixed_store()
    out = await _run_pass2_cache_hit(monkeypatch, store)
    worker_fp = out["upsert"]["gf_fp"]

    open_subset = [f for f in store if f.status == FindingStatus.OPEN]
    assert worker_fp == group_findings_fingerprint(open_subset)
    # Alter Bug: ALL-Set-Fingerprint — darf NICHT mehr rauskommen.
    assert worker_fp != group_findings_fingerprint(store)


@pytest.mark.asyncio
async def test_no_reenqueue_after_worker_eval_on_mixed_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Konvergenz-Regression (Dauer-Re-Enqueue-Schleife aus Bug B):

    Nachdem der Worker den Fingerprint persistiert hat, darf der naechste
    Ingest dieselbe (unveraenderte) Group NICHT erneut enqueuen — der
    Enqueue-Fingerprint matcht jetzt den gespeicherten Worker-Fingerprint.
    """
    store = _mixed_store()
    out = await _run_pass2_cache_hit(monkeypatch, store)
    worker_fp = out["upsert"]["gf_fp"]

    stored_eval = SimpleNamespace(group_id=GROUP_ID, group_findings_fingerprint=worker_fp)
    count, _ = _run_enqueue(store, evals=[stored_eval])
    assert count == 0, "unchanged OPEN-set re-enqueued: Bug-B loop is back"

    # Gegenprobe: aendert sich das OPEN-Set (ein Finding resolved), wird
    # wieder enqueued — der Gate ist also nicht einfach tot.
    store[0].status = FindingStatus.RESOLVED
    count_changed, _ = _run_enqueue(store, evals=[stored_eval])
    assert count_changed == 1


@pytest.mark.asyncio
async def test_worker_and_enqueue_use_identical_status_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """WHERE-Klauseln beider Code-Pfade binden denselben Status-Wert (OPEN) —
    der „Single-Source"-Querverweis im Code ist damit regressionsgesichert."""
    out = await _run_pass2_cache_hit(monkeypatch, _mixed_store())
    worker_stmt = out["session"].executed[0]

    _, enq_sess = _run_enqueue(_mixed_store(), evals=[])
    finding_stmts = [s for s in enq_sess.executed if s.column_descriptions[0]["entity"] is Finding]
    assert finding_stmts, "enqueue did not load findings"
    enqueue_stmt = finding_stmts[-1]

    assert (
        _status_bind_values(worker_stmt)
        == _status_bind_values(enqueue_stmt)
        == [FindingStatus.OPEN]
    )


# ---------------------------------------------------------------------------
# Leer-Listen-Guard Phase 1: keine offenen Findings -> done/skipped, kein LLM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase1_no_open_findings_job_done_skipped_without_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Group hat nur resolved/acknowledged Findings -> Job endet done/skipped
    BEVOR Fingerprint, Cache-Lookup oder Reviewer-Setup laufen."""
    store = [
        _mk_finding(3, "CVE-2026-0003", "pkg:deb/c@3", FindingStatus.RESOLVED),
        _mk_finding(4, "CVE-2026-0004", "pkg:deb/d@4", FindingStatus.ACKNOWLEDGED),
    ]
    job = _job()
    sess = _FakeSession(identity=_phase1_identity(job), findings=store)
    _install_sessions(monkeypatch, [sess])
    monkeypatch.setattr(llm_worker, "_audit_pass2_with_failed_siblings", lambda *a, **k: None)

    def _boom_fp(findings: list[Any]) -> str:  # pragma: no cover
        raise AssertionError("fingerprint must not run without open findings")

    async def _boom_reviewer(session: Any) -> Any:  # pragma: no cover
        raise AssertionError("reviewer setup must not run without open findings")

    monkeypatch.setattr(llm_worker, "group_findings_fingerprint", _boom_fp)
    monkeypatch.setattr(llm_worker, "_get_reviewer_for_job", _boom_reviewer)

    await llm_worker._do_pass2(JOB_ID)

    assert job.status == "done"
    assert job.completed_at is not None
    assert job.result == {"skipped": True, "reason": "no open findings in group on server"}
    assert sess.committed == 1


# ---------------------------------------------------------------------------
# Ticket-Fall 3: Detached-Reload-Race — alle Findings zwischen Phase 1 und
# Phase 2 geschlossen -> done/skipped ohne LLM-Call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detached_reload_race_all_closed_skips_without_llm_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 1 sieht ein offenes Finding (Cache-Miss); bevor Phase 2 laedt,
    ist es resolved (Triage-/Ingest-Race). Der Reload filtert OPEN, findet
    nichts -> Job done/skipped, Reviewer wird NICHT aufgerufen."""
    open_finding = _mk_finding(1, "CVE-2026-0001", "pkg:deb/a@1", FindingStatus.OPEN)
    job = _job()

    phase1 = _FakeSession(identity=_phase1_identity(job), findings=[open_finding])
    setup = _FakeSession()
    # Detached-Session sieht dasselbe Finding — aber inzwischen RESOLVED.
    closed_finding = _mk_finding(1, "CVE-2026-0001", "pkg:deb/a@1", FindingStatus.RESOLVED)
    detached = _FakeSession(
        identity={
            (ApplicationGroup, GROUP_ID): SimpleNamespace(id=GROUP_ID, label="test-group"),
            (Server, SERVER_ID): SimpleNamespace(id=SERVER_ID),
            (LLMJob, JOB_ID): job,
        },
        findings=[closed_finding],
    )
    _install_sessions(monkeypatch, [phase1, setup, detached])
    _patch_phase1_helpers(monkeypatch)
    monkeypatch.setattr(llm_worker, "lookup", lambda s, key: None)  # Cache-Miss

    llm_calls: list[Any] = []

    class _SpyReviewer:
        async def pass2_evaluate_groups(self, *args: Any, **kwargs: Any) -> Any:
            llm_calls.append((args, kwargs))
            raise AssertionError("LLM must not be called when all findings closed mid-job")

    async def _fake_get_reviewer(session: Any) -> tuple[Any, str, bool]:
        return _SpyReviewer(), "test-model", False

    monkeypatch.setattr(llm_worker, "_get_reviewer_for_job", _fake_get_reviewer)

    def _boom_hydrate(session: Any, server: Any) -> None:  # pragma: no cover
        raise AssertionError("snapshot hydrate must not run without open findings")

    monkeypatch.setattr(llm_worker, "_hydrate_server_snapshot", _boom_hydrate)

    await llm_worker._do_pass2(JOB_ID)

    assert llm_calls == [], "reviewer was called despite empty OPEN-set"
    assert job.status == "done"
    assert job.completed_at is not None
    assert job.result == {"skipped": True, "reason": "no open findings in group on server"}
    assert detached.committed == 1


@pytest.mark.asyncio
async def test_detached_reload_statement_filters_open_and_phase1_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Der Detached-Reload selektiert exakt die Phase-1-IDs UND filtert OPEN —
    ein zwischenzeitlich resolved Finding faellt raus, offene bleiben drin."""
    f_open = _mk_finding(1, "CVE-2026-0001", "pkg:deb/a@1", FindingStatus.OPEN)
    f_racy = _mk_finding(2, "CVE-2026-0002", "pkg:deb/b@2", FindingStatus.OPEN)
    job = _job()

    phase1 = _FakeSession(identity=_phase1_identity(job), findings=[f_open, f_racy])
    setup = _FakeSession()
    # Race: Finding 2 ist beim Reload resolved; Finding 1 weiterhin offen.
    detached = _FakeSession(
        identity={
            (ApplicationGroup, GROUP_ID): SimpleNamespace(id=GROUP_ID, label="test-group"),
            (Server, SERVER_ID): SimpleNamespace(id=SERVER_ID),
            (LLMJob, JOB_ID): job,
        },
        findings=[
            f_open,
            _mk_finding(2, "CVE-2026-0002", "pkg:deb/b@2", FindingStatus.RESOLVED),
        ],
    )
    _install_sessions(monkeypatch, [phase1, setup, detached])
    _patch_phase1_helpers(monkeypatch)
    monkeypatch.setattr(llm_worker, "lookup", lambda s, key: None)
    monkeypatch.setattr(llm_worker, "_hydrate_server_snapshot", lambda s, srv: None)

    llm_inputs: list[Any] = []

    class _CapturingReviewer:
        async def pass2_evaluate_groups(
            self, server: Any, groups: list[Any]
        ) -> tuple[Any, dict[str, Any]]:
            llm_inputs.append(groups)
            evaluation = SimpleNamespace(
                group_id=GROUP_ID,
                risk_band="low",
                reason="r",
                worst_finding_id=1,
                action_type="fix",
            )
            return SimpleNamespace(evaluations=[evaluation]), {"usage": {}}

    async def _fake_get_reviewer(session: Any) -> tuple[Any, str, bool]:
        return _CapturingReviewer(), "test-model", False

    monkeypatch.setattr(llm_worker, "_get_reviewer_for_job", _fake_get_reviewer)

    # Phase 3 (Persistenz nach LLM-Call) braucht eine vierte Session und
    # weitere Helper — fuer diesen Test irrelevant, wir stoppen via Exception
    # sobald der LLM-Input eingesammelt ist (Success-Debug-Log laeuft direkt
    # nach dem LLM-Call und vor der Persistenz).
    class _StopAfterLLMError(Exception):
        pass

    def _stop(*args: Any, **kwargs: Any) -> None:
        raise _StopAfterLLMError()

    monkeypatch.setattr(llm_worker, "_record_pass_debug_log", _stop)

    with pytest.raises(_StopAfterLLMError):
        await llm_worker._do_pass2(JOB_ID)

    # LLM-Input: nur das noch offene Finding 1; das racy-resolved Finding 2
    # ist rausgefiltert obwohl seine ID im Phase-1-Snapshot lag.
    assert len(llm_inputs) == 1
    (_group, findings_re) = llm_inputs[0][0]
    assert [f.id for f in findings_re] == [1]
    assert all(f.status == FindingStatus.OPEN for f in findings_re)

    # Statement-Check: Reload filtert nach id IN (Phase-1-IDs) UND status=OPEN.
    reload_stmt = detached.executed[0]
    assert _status_bind_values(reload_stmt) == [FindingStatus.OPEN], str(reload_stmt)
    where = reload_stmt.whereclause
    assert where is not None
    in_conds = [
        c
        for c in (list(where.clauses) if hasattr(where, "clauses") else [where])
        if c.operator is sa_operators.in_op
    ]
    assert len(in_conds) == 1
    assert sorted(in_conds[0].right.value) == [1, 2]
