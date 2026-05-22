"""Pure-Unit-Tests fuer ``app.workers.llm_worker._classify_error``.

v0.9.4 Fix 3: OpenAI-SDK-Fehler (``BadRequestError``/``APIStatusError``)
sollen als LLM-Fehler erkannt werden — Audit-Metadata bekommt
``error_class=llm_api_error``.

DB-backed Smokes fuer ``_requeue_or_fail`` (Audit-Roundtrip durch echte
``llm_jobs``/``audit_events``-Persistenz) liegen in
``tests/integration/test_error_classification_db.py``.
"""

from __future__ import annotations

from app.workers.llm_worker import _classify_error


def test_classify_error_recognizes_badrequest() -> None:
    """BadRequestError-Stringification → ``llm_api_error``."""
    err = "BadRequestError(\"Error code: 400 - {'error': {'message': 'too long'}}\")"
    assert _classify_error(err) == "llm_api_error"


def test_classify_error_recognizes_apistatuserror() -> None:
    """APIStatusError → ``llm_api_error``."""
    assert _classify_error("APIStatusError('rate limit')") == "llm_api_error"


def test_classify_error_recognizes_error_code_marker() -> None:
    """Textuelle ``Error code: NNN``-Marker → ``llm_api_error``."""
    assert _classify_error("Error code: 400 - context_window_exceeded") == "llm_api_error"


def test_classify_error_still_handles_timeout() -> None:
    """Regression: Timeout-Markers haben Vorrang vor llm_api_error."""
    assert _classify_error("LLMTimeoutError(asyncio timeout)") == "timeout"
    assert _classify_error("read timeout") == "timeout"


def test_classify_error_still_handles_invalid_response() -> None:
    """Regression: ``llminvalidresponse`` bleibt ``invalid_response``."""
    assert _classify_error("LLMInvalidResponseError('no choices')") == "invalid_response"


def test_classify_error_other_for_unknown() -> None:
    """Fallback bleibt ``other`` fuer Nicht-LLM-Fehler."""
    assert _classify_error("ConnectionRefusedError") == "other"
