# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer TICKET-013 Etappe 5 — Worker-Lane-Pickup + action_type.

Deckt:

* :func:`_derive_action_type` — vollstaendige Ableitungstabelle aus ADR-0053
  (alle sechs gueltigen ``(fix_lane, risk_band)``-Kombinationen) plus das
  defensive Verhalten bei ``(mitigate, act)`` (kommt nicht vor, da der
  Validator es ablehnt — wir fallen auf ``mitigate`` zurueck statt zu crashen).
* ``_do_pass2`` Lane-Wiring: liest ``fix_lane`` aus dem Payload, filtert die
  OPEN-Findings auf die Lane, reicht ``fix_lane`` an ``make_cache_key``,
  ``pass2_evaluate_groups`` (Prompt/Validator) und ``_upsert_evaluation`` durch.
* Fehlende/ungueltige ``fix_lane`` im Payload (Legacy-Job) -> Job done/skipped
  mit Warnung, KEIN Fingerprint, KEIN Cache-Lookup, KEIN LLM-Call.

Kein DB-Roundtrip: Fake-Session wertet die ``select(Finding)``-WHERE-Klausel
in-memory aus (wiederverwendet aus ``test_llm_worker_pass2_open_only``).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.models import ApplicationGroup, FindingStatus, LLMJob, Server
from app.services.llm_fingerprints import group_findings_fingerprint
from app.workers import llm_worker

from .test_llm_worker_pass2_open_only import (
    GROUP_ID,
    JOB_ID,
    SERVER_ID,
    _FakeSession,
    _install_sessions,
    _mk_finding,
)

# ---------------------------------------------------------------------------
# _derive_action_type — vollstaendige Ableitungstabelle (ADR-0053)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fix_lane", "risk_band", "expected"),
    [
        ("patch", "escalate", "patch"),
        ("patch", "act", "patch"),
        ("patch", "monitor", "watch"),
        ("patch", "noise", "none"),
        # ADR-0064: die mitigate-Lane deckt jetzt auch lang-pkgs-mit-Fix ab
        # (die fruehere ``upstream``-Lane ist hierher kollabiert).
        ("mitigate", "escalate", "mitigate"),
        ("mitigate", "monitor", "watch"),
        ("mitigate", "noise", "none"),
    ],
)
def test_derive_action_type_table(fix_lane: str, risk_band: str, expected: str) -> None:
    assert llm_worker._derive_action_type(fix_lane, risk_band) == expected


def test_derive_action_type_unknown_lane_falls_back_without_crash(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Ein unbekannter Lane-Wert (z.B. die seit ADR-0064 entfallene
    ``upstream``-Lane) ist nicht in der Ableitungstabelle. Defensiv: kein
    Crash, Fallback auf ``mitigate``, Log-Warnung."""
    with caplog.at_level("WARNING"):
        result = llm_worker._derive_action_type("upstream", "act")
    assert result == "mitigate"
    assert any("unexpected_lane_band_combo" in r.message for r in caplog.records)


def test_derive_action_type_mitigate_act_falls_back_without_crash(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``(mitigate, act)`` kommt nicht vor (Validator lehnt act im mitigate-Call
    ab). Defensiv: wir crashen nicht, fallen auf ``mitigate`` zurueck und loggen
    den unerwarteten Combo."""
    with caplog.at_level("WARNING"):
        result = llm_worker._derive_action_type("mitigate", "act")
    assert result == "mitigate"
    assert any("unexpected_lane_band_combo" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _do_pass2 — Lane-Wiring (fix_lane aus Payload -> Filter -> Durchreichen)
# ---------------------------------------------------------------------------


def _lane_job(fix_lane: str | Any) -> SimpleNamespace:
    return SimpleNamespace(
        payload={"group_id": GROUP_ID, "server_id": SERVER_ID, "fix_lane": fix_lane},
        status="in_progress",
        completed_at=None,
        result=None,
    )


def _phase1_identity(job: SimpleNamespace) -> dict[tuple[type, int], Any]:
    return {
        (LLMJob, JOB_ID): job,
        (ApplicationGroup, GROUP_ID): SimpleNamespace(id=GROUP_ID, label="g"),
        (Server, SERVER_ID): SimpleNamespace(id=SERVER_ID),
    }


def _mixed_lane_store() -> list[SimpleNamespace]:
    """Gemischte Group: 2 OPEN patchbar (fixed_version), 2 OPEN no-fix."""
    return [
        _mk_finding(1, "CVE-2026-0001", "pkg:deb/a@1", FindingStatus.OPEN, fixed_version="1.1"),
        _mk_finding(2, "CVE-2026-0002", "pkg:deb/b@2", FindingStatus.OPEN, fixed_version="2.2"),
        _mk_finding(3, "CVE-2026-0003", "pkg:deb/c@3", FindingStatus.OPEN, fixed_version=None),
        _mk_finding(4, "CVE-2026-0004", "pkg:deb/d@4", FindingStatus.OPEN, fixed_version=None),
    ]


async def _run_cache_hit_lane(
    monkeypatch: pytest.MonkeyPatch, *, fix_lane: str, store: list[SimpleNamespace]
) -> dict[str, Any]:
    """Treibt ``_do_pass2`` ueber den Cache-Hit-Pfad und captured die durch-
    gereichten ``fix_lane``-Argumente an cache_key + upsert sowie den
    Fingerprint-Input."""
    job = _lane_job(fix_lane)
    sess = _FakeSession(identity=_phase1_identity(job), findings=store)
    _install_sessions(monkeypatch, [sess])

    captured: dict[str, Any] = {}

    def _spy_fp(findings: list[Any]) -> str:
        captured["fp_input_ids"] = sorted(f.id for f in findings)
        return group_findings_fingerprint(findings)

    def _spy_cache_key(*args: Any, **kwargs: Any) -> str:
        captured["cache_key_fix_lane"] = kwargs.get("fix_lane")
        return "k" * 64

    monkeypatch.setattr(llm_worker, "_audit_pass2_with_failed_siblings", lambda *a, **k: None)
    monkeypatch.setattr(llm_worker, "group_findings_fingerprint", _spy_fp)
    monkeypatch.setattr(llm_worker, "cve_data_fingerprint", lambda f: "c" * 16)
    monkeypatch.setattr(llm_worker, "server_context_fingerprint", lambda s, session=None: "s" * 16)
    monkeypatch.setattr(llm_worker, "make_cache_key", _spy_cache_key)

    cached = SimpleNamespace(risk_band="monitor", reason="r", worst_finding_id=1, action_type="x")
    monkeypatch.setattr(llm_worker, "lookup", lambda s, key: cached)
    monkeypatch.setattr(llm_worker, "record_hit", lambda s, c: None)
    upsert_kwargs: dict[str, Any] = {}
    monkeypatch.setattr(llm_worker, "_upsert_evaluation", lambda s, **kw: upsert_kwargs.update(kw))
    monkeypatch.setattr(llm_worker, "inherit_group_risk_to_findings", lambda s, **kw: 0)
    monkeypatch.setattr(llm_worker, "_audit", lambda *a, **k: None)

    await llm_worker._do_pass2(JOB_ID)
    return {"job": job, "captured": captured, "upsert": upsert_kwargs}


@pytest.mark.asyncio
async def test_do_pass2_patch_lane_filters_to_patchable_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = await _run_cache_hit_lane(monkeypatch, fix_lane="patch", store=_mixed_lane_store())
    # Nur die patchbaren Findings (1, 2) gehen in Fingerprint/Selektion.
    assert out["captured"]["fp_input_ids"] == [1, 2]
    assert out["captured"]["cache_key_fix_lane"] == "patch"
    assert out["upsert"]["fix_lane"] == "patch"
    assert out["job"].result["cache_hit"] is True
    # action_type aus (patch, monitor) abgeleitet.
    assert out["job"].result["action_type"] == "watch"


@pytest.mark.asyncio
async def test_do_pass2_mitigate_lane_filters_to_nofix_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = await _run_cache_hit_lane(monkeypatch, fix_lane="mitigate", store=_mixed_lane_store())
    # Nur die no-fix Findings (3, 4).
    assert out["captured"]["fp_input_ids"] == [3, 4]
    assert out["captured"]["cache_key_fix_lane"] == "mitigate"
    assert out["upsert"]["fix_lane"] == "mitigate"


@pytest.mark.asyncio
async def test_do_pass2_passes_fix_lane_to_reviewer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cache-Miss-Pfad: ``fix_lane`` wird an ``pass2_evaluate_groups``
    (Prompt + Validator) durchgereicht."""
    store = _mixed_lane_store()
    job = _lane_job("mitigate")

    phase1 = _FakeSession(identity=_phase1_identity(job), findings=store)
    setup = _FakeSession()
    detached = _FakeSession(
        identity={
            (ApplicationGroup, GROUP_ID): SimpleNamespace(id=GROUP_ID, label="g"),
            (Server, SERVER_ID): SimpleNamespace(id=SERVER_ID),
            (LLMJob, JOB_ID): job,
        },
        findings=store,
    )
    _install_sessions(monkeypatch, [phase1, setup, detached])

    monkeypatch.setattr(llm_worker, "_audit_pass2_with_failed_siblings", lambda *a, **k: None)
    monkeypatch.setattr(llm_worker, "group_findings_fingerprint", lambda f: "g" * 16)
    monkeypatch.setattr(llm_worker, "cve_data_fingerprint", lambda f: "c" * 16)
    monkeypatch.setattr(llm_worker, "server_context_fingerprint", lambda s, session=None: "s" * 16)
    monkeypatch.setattr(llm_worker, "make_cache_key", lambda *a, **k: "k" * 64)
    monkeypatch.setattr(llm_worker, "lookup", lambda s, key: None)  # Cache-Miss
    monkeypatch.setattr(llm_worker, "_hydrate_server_snapshot", lambda s, srv: None)

    seen: dict[str, Any] = {}

    class _StopError(Exception):
        pass

    class _Reviewer:
        async def pass2_evaluate_groups(
            self, server: Any, groups: list[Any], *, fix_lane: str | None = None
        ) -> tuple[Any, dict[str, Any]]:
            seen["fix_lane"] = fix_lane
            seen["finding_ids"] = [f.id for (_g, fs) in groups for f in fs]
            raise _StopError

    async def _fake_get_reviewer(session: Any) -> tuple[Any, str, bool]:
        return _Reviewer(), "m", False

    monkeypatch.setattr(llm_worker, "_get_reviewer_for_job", _fake_get_reviewer)

    with pytest.raises(_StopError):
        await llm_worker._do_pass2(JOB_ID)

    assert seen["fix_lane"] == "mitigate"
    # Reviewer sieht nur die no-fix Findings.
    assert seen["finding_ids"] == [3, 4]


@pytest.mark.asyncio
async def test_do_pass2_empty_lane_skips_without_eval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leere Lane (alle OPEN-Findings sind patchbar, Job will mitigate) -> Job
    done/skipped ohne Cache-Lookup, ohne Eval-Row."""
    store = [
        _mk_finding(1, "CVE-2026-0001", "pkg:deb/a@1", FindingStatus.OPEN, fixed_version="1.1"),
        _mk_finding(2, "CVE-2026-0002", "pkg:deb/b@2", FindingStatus.OPEN, fixed_version="2.2"),
    ]
    job = _lane_job("mitigate")
    sess = _FakeSession(identity=_phase1_identity(job), findings=store)
    _install_sessions(monkeypatch, [sess])
    monkeypatch.setattr(llm_worker, "_audit_pass2_with_failed_siblings", lambda *a, **k: None)

    def _boom(*a: Any, **k: Any) -> None:  # pragma: no cover
        raise AssertionError("must not run for empty lane")

    monkeypatch.setattr(llm_worker, "lookup", _boom)

    await llm_worker._do_pass2(JOB_ID)

    assert job.status == "done"
    assert job.result["skipped"] is True
    assert "mitigate" in job.result["reason"]


# ---------------------------------------------------------------------------
# Legacy-Job: fehlende / ungueltige fix_lane im Payload -> skip mit Warnung
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_lane", [None, "", "bogus", "Patch"])
async def test_do_pass2_missing_or_invalid_fix_lane_skips_with_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    bad_lane: Any,
) -> None:
    """Legacy-/korruptes Payload ohne gueltige ``fix_lane`` -> Job done/skipped
    mit Warnung, BEVOR Findings geladen, Fingerprint berechnet oder Cache
    konsultiert wird."""
    payload = {"group_id": GROUP_ID, "server_id": SERVER_ID}
    if bad_lane is not None:
        payload["fix_lane"] = bad_lane
    job = SimpleNamespace(payload=payload, status="in_progress", completed_at=None, result=None)
    sess = _FakeSession(identity=_phase1_identity(job))
    _install_sessions(monkeypatch, [sess])
    monkeypatch.setattr(llm_worker, "_audit_pass2_with_failed_siblings", lambda *a, **k: None)

    def _boom(*a: Any, **k: Any) -> None:  # pragma: no cover
        raise AssertionError("must not run for legacy job without fix_lane")

    monkeypatch.setattr(llm_worker, "group_findings_fingerprint", _boom)
    monkeypatch.setattr(llm_worker, "lookup", _boom)

    with caplog.at_level("WARNING"):
        await llm_worker._do_pass2(JOB_ID)

    assert job.status == "done"
    assert job.result == {
        "skipped": True,
        "reason": "missing or invalid fix_lane in payload",
    }
    assert any("missing_or_invalid_fix_lane" in r.message for r in caplog.records)
