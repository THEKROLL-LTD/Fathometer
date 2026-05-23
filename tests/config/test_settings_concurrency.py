"""Block U Phase A (ADR-0029) — Pydantic-Bounds und Env-Var-Override fuer die
zwei neuen Concurrency-/Sampling-Settings plus die angehobene Default-Cap fuer
``llm_debug_log_max_rows``.

Pure-Unit-Tests gegen ``app.config.Settings`` und ``load_settings()`` ohne
DB- oder App-Factory-Kontext.

Gespiegelt werden die DB-CheckConstraints in
``alembic/versions/0012_block_u_worker_concurrency.py``:
- ``llm_worker_job_concurrency`` IN [1, 200]
- ``llm_debug_log_success_sample_rate`` IN [1, 1000]

Bei jedem Test setzen wir einen Pflicht-``SECSCAN_ENCRYPTION_KEY`` (>=32),
damit ``Settings()`` ueberhaupt instantiierbar ist. Andere ``SECSCAN_*``-Vars
werden pro Test bewusst geleert, damit das Host-Environment keine Defaults
overrided.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings, load_settings


@pytest.fixture(autouse=True)
def _clean_secscan_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entfernt alle ``SECSCAN_*``-Vars und setzt einen sauberen Encryption-Key.

    Pydantic-Settings liest case-insensitive — wir entfernen darum alle
    Varianten. Der Encryption-Key wird auf eine 32-Zeichen-Konstante
    gepinnt, damit ``Settings()`` keinen ValidationError wegen fehlender
    Pflicht-Felder wirft. Alle anderen Tests, die echte Env-Overrides
    pruefen, setzen ihre eigenen Vars explizit.
    """
    import os

    for key in list(os.environ.keys()):
        if key.upper().startswith("SECSCAN_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SECSCAN_ENCRYPTION_KEY", "x" * 32)


# ---------------------------------------------------------------------------
# Default-Werte — Block U Phase A.
# ---------------------------------------------------------------------------


def test_default_llm_worker_job_concurrency_is_one() -> None:
    """Backward-Compat: ohne explizite Konfiguration laeuft N=1."""
    s = load_settings()
    assert s.llm_worker_job_concurrency == 1


def test_default_llm_debug_log_success_sample_rate_is_ten() -> None:
    """Sampling 1:10 ist der Default fuer N=200-Skalierung."""
    s = load_settings()
    assert s.llm_debug_log_success_sample_rate == 10


def test_default_llm_debug_log_max_rows_is_2000() -> None:
    """Phase A hebt den Default von 500 auf 2000 an (reine Pydantic-Aenderung).

    Wichtig: das ist KEIN Schema-Touch — die DB-Spalte gibt es bereits aus
    Block P. Aber der Operator bekommt nach v0.11.0 ein groesseres
    Forensik-Fenster ohne manuelles Eingreifen.
    """
    s = load_settings()
    assert s.llm_debug_log_max_rows == 2000, (
        f"Default vor Block U war 500, nach Phase A muss er 2000 sein. "
        f"Aktuell: {s.llm_debug_log_max_rows}"
    )


# ---------------------------------------------------------------------------
# Bounds — gespiegelt zu DB-CheckConstraints.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [1, 2, 50, 199, 200])
def test_llm_worker_job_concurrency_accepts_in_range(value: int) -> None:
    s = Settings(llm_worker_job_concurrency=value)  # type: ignore[call-arg]
    assert s.llm_worker_job_concurrency == value


@pytest.mark.parametrize("value", [0, -1, 201, 1000])
def test_llm_worker_job_concurrency_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(llm_worker_job_concurrency=value)  # type: ignore[call-arg]
    # Sicherstellen dass der ValidationError tatsaechlich auf das richtige
    # Feld zeigt — sonst koennte ein anderer Pflicht-Field-Fehler den Test
    # fluky-PASSen lassen.
    msg = str(exc.value)
    assert "llm_worker_job_concurrency" in msg, msg


@pytest.mark.parametrize("value", [1, 2, 10, 100, 999, 1000])
def test_llm_debug_log_success_sample_rate_accepts_in_range(value: int) -> None:
    s = Settings(llm_debug_log_success_sample_rate=value)  # type: ignore[call-arg]
    assert s.llm_debug_log_success_sample_rate == value


@pytest.mark.parametrize("value", [0, -1, 1001, 10000])
def test_llm_debug_log_success_sample_rate_rejects_out_of_range(value: int) -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(llm_debug_log_success_sample_rate=value)  # type: ignore[call-arg]
    msg = str(exc.value)
    assert "llm_debug_log_success_sample_rate" in msg, msg


# ---------------------------------------------------------------------------
# Env-Var-Override — Prefix SECSCAN_, case-insensitive.
# ---------------------------------------------------------------------------


def test_env_override_llm_worker_job_concurrency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECSCAN_LLM_WORKER_JOB_CONCURRENCY", "5")
    s = load_settings()
    assert s.llm_worker_job_concurrency == 5


def test_env_override_llm_debug_log_success_sample_rate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_SUCCESS_SAMPLE_RATE", "25")
    s = load_settings()
    assert s.llm_debug_log_success_sample_rate == 25


def test_env_override_at_upper_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECSCAN_LLM_WORKER_JOB_CONCURRENCY", "200")
    monkeypatch.setenv("SECSCAN_LLM_DEBUG_LOG_SUCCESS_SAMPLE_RATE", "1000")
    s = load_settings()
    assert s.llm_worker_job_concurrency == 200
    assert s.llm_debug_log_success_sample_rate == 1000


def test_env_override_out_of_range_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """201 ueber die Env-Var muss genauso einen ValidationError werfen wie
    direkt im Konstruktor — sonst koennten Operator-Fehler unbemerkt durch."""
    monkeypatch.setenv("SECSCAN_LLM_WORKER_JOB_CONCURRENCY", "201")
    with pytest.raises(ValidationError) as exc:
        load_settings()
    assert "llm_worker_job_concurrency" in str(exc.value)


def test_env_override_non_integer_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tippfehler wie ``"abc"`` muessen frueh durch Pydantic gefangen werden,
    nicht erst beim DB-CheckConstraint."""
    monkeypatch.setenv("SECSCAN_LLM_WORKER_JOB_CONCURRENCY", "abc")
    with pytest.raises(ValidationError):
        load_settings()
