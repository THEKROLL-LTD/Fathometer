"""Gemeinsame Fixtures fuer Block-P-Integration-Tests.

Stellt einen wiederverwendbaren Mock-Reviewer + Reviewer-Factory bereit der
``_build_reviewer`` im Worker ersetzt, sodass Pass-1 und Pass-2 ohne echten
LLM-Call deterministische Outputs liefern. Die Cache- und DB-Pfade laufen
unveraendert durch.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from flask import Flask

from app.db import get_session_factory
from app.services.llm_risk_reviewer import Pass1Result, Pass2Result
from app.workers import llm_worker


class MockReviewer:
    """Deterministischer Pass-1/Pass-2-Stub fuer Integration-Tests.

    Kann sowohl statisch konfiguriert (`pass1_result`, `pass2_result`) als
    auch dynamisch (`pass1_fn`, `pass2_fn`) genutzt werden, damit komplexere
    Szenarien (Sequenz von Calls, unterschiedliche Antworten pro Group) sich
    sauber ausdruecken lassen.
    """

    def __init__(
        self,
        *,
        pass1_result: Pass1Result | None = None,
        pass2_result: Pass2Result | None = None,
        pass1_fn: Callable[[Any], Pass1Result] | None = None,
        pass2_fn: Callable[[Any, Any], Pass2Result] | None = None,
    ) -> None:
        self._pass1_result = pass1_result
        self._pass2_result = pass2_result
        self._pass1_fn = pass1_fn
        self._pass2_fn = pass2_fn
        self.pass1_call_count = 0
        self.pass2_call_count = 0

    async def pass1_detect_groups(self, findings: Any) -> Pass1Result:
        await asyncio.sleep(0)
        self.pass1_call_count += 1
        if self._pass1_fn is not None:
            return self._pass1_fn(findings)
        if self._pass1_result is None:
            return Pass1Result(groups=[], ungrouped_finding_ids=[int(f.id) for f in findings])
        return self._pass1_result

    async def pass2_evaluate_groups(self, server: Any, groups: Any) -> Pass2Result:
        await asyncio.sleep(0)
        self.pass2_call_count += 1
        if self._pass2_fn is not None:
            return self._pass2_fn(server, groups)
        if self._pass2_result is None:
            return Pass2Result(evaluations=[])
        return self._pass2_result


@pytest.fixture
def worker_session_factory(db_app: Flask) -> Iterator[None]:
    """Routet den Worker auf die `db_app`-Engine und resetted State."""
    factory = get_session_factory(db_app)
    llm_worker.set_session_factory_for_tests(factory)
    llm_worker.reset_shutdown_for_tests()
    llm_worker.set_reviewer_factory_for_tests(None)
    yield
    llm_worker.set_reviewer_factory_for_tests(None)
    llm_worker.reset_shutdown_for_tests()


@pytest.fixture
def install_mock_reviewer() -> Callable[[MockReviewer], MockReviewer]:
    """Returns ein Setter, der einen Mock-Reviewer im Worker installiert.

    Usage::

        reviewer = install_mock_reviewer(MockReviewer(pass1_result=..., pass2_result=...))
        llm_worker._tick()
        assert reviewer.pass2_call_count == 1
    """

    def _install(reviewer: MockReviewer) -> MockReviewer:
        def _factory(_session: Any) -> tuple[Any, str]:
            return reviewer, "mock-model"

        llm_worker.set_reviewer_factory_for_tests(_factory)
        return reviewer

    return _install


__all__ = ["MockReviewer", "install_mock_reviewer", "worker_session_factory"]
