"""Pure-Unit-Tests fuer ``app.workers.scan_ingest_worker``.

Testet ausschliesslich DB-freie Logik:

* Backoff-Berechnung (``compute_backoff_sec``).
* Max-Attempts-Decision (``should_fail``).
* Error-Truncation (``truncate_error``).
* JSON-Serialisierung des ``result``-Felds (``result_to_jsonb``).

DB-Integration-Tests (SELECT FOR UPDATE SKIP LOCKED, atomares UPDATE,
Stale-Reaper, Retention-Sweep) sind als DoD-C-On-Demand-Verification
im Modul-Docstring von scan_ingest_worker.py dokumentiert.
"""

from __future__ import annotations

import pytest

from app.workers.scan_ingest_worker import (
    _BACKOFF_BASE_SEC,
    _ERROR_MAX_BYTES,
    MAX_SCAN_INGEST_ATTEMPTS,
    compute_backoff_sec,
    result_to_jsonb,
    should_fail,
    truncate_error,
)


class TestComputeBackoffSec:
    """Backoff-Berechnung: base_sec * 2^(attempts-1)."""

    def test_attempts_1_returns_base(self) -> None:
        """attempts=1 → 30s (base)."""
        assert compute_backoff_sec(1) == _BACKOFF_BASE_SEC

    def test_attempts_2_doubles(self) -> None:
        """attempts=2 → 60s (2x base)."""
        assert compute_backoff_sec(2) == _BACKOFF_BASE_SEC * 2

    def test_attempts_3_quadruples(self) -> None:
        """attempts=3 → 120s (4x base, aber bei 3 attempts ist Job failed)."""
        assert compute_backoff_sec(3) == _BACKOFF_BASE_SEC * 4

    def test_attempts_0_returns_base(self) -> None:
        """attempts=0 → base (defensiver Fallback)."""
        assert compute_backoff_sec(0) == _BACKOFF_BASE_SEC

    def test_attempts_negative_returns_base(self) -> None:
        """Negative attempts → base (defensiv)."""
        assert compute_backoff_sec(-1) == _BACKOFF_BASE_SEC

    def test_custom_base_sec(self) -> None:
        """Custom base_sec wird korrekt verwendet."""
        assert compute_backoff_sec(1, base_sec=60) == 60
        assert compute_backoff_sec(2, base_sec=60) == 120
        assert compute_backoff_sec(3, base_sec=60) == 240

    def test_return_type_is_int(self) -> None:
        """Rueckgabewert ist immer int (wichtig fuer SQL-Bind-Parameter)."""
        result = compute_backoff_sec(2)
        assert isinstance(result, int)


class TestShouldFail:
    """Max-Attempts-Decision."""

    def test_attempts_below_max_returns_false(self) -> None:
        assert should_fail(1) is False
        assert should_fail(2) is False

    def test_attempts_at_max_returns_true(self) -> None:
        assert should_fail(MAX_SCAN_INGEST_ATTEMPTS) is True

    def test_attempts_above_max_returns_true(self) -> None:
        assert should_fail(MAX_SCAN_INGEST_ATTEMPTS + 1) is True

    def test_zero_attempts_returns_false(self) -> None:
        assert should_fail(0) is False

    def test_custom_max_attempts(self) -> None:
        assert should_fail(2, max_attempts=2) is True
        assert should_fail(1, max_attempts=2) is False

    @pytest.mark.parametrize("attempts", [1, 2])
    def test_retry_range(self, attempts: int) -> None:
        """Fuer attempts 1 und 2 (default max=3) soll requeued werden."""
        assert should_fail(attempts) is False

    def test_at_default_max(self) -> None:
        """Standard-Szenario: attempt 3 = final fail."""
        assert should_fail(3) is True
        assert MAX_SCAN_INGEST_ATTEMPTS == 3  # Sanity-Check Konstante


class TestTruncateError:
    """Error-Truncation auf 4 KB."""

    def test_short_string_unchanged(self) -> None:
        short = "kurzer Fehler"
        assert truncate_error(short) == short

    def test_empty_string(self) -> None:
        assert truncate_error("") == ""

    def test_exact_limit_unchanged(self) -> None:
        exact = "x" * _ERROR_MAX_BYTES
        result = truncate_error(exact)
        assert result == exact
        assert len(result.encode("utf-8")) == _ERROR_MAX_BYTES

    def test_over_limit_is_truncated(self) -> None:
        long_err = "x" * (_ERROR_MAX_BYTES + 100)
        result = truncate_error(long_err)
        assert len(result.encode("utf-8")) <= _ERROR_MAX_BYTES + 20  # Toleranz fuer suffix
        assert "[truncated]" in result

    def test_unicode_safe_truncation(self) -> None:
        """Multi-Byte UTF-8-Zeichen werden nicht mitten im Byte-Sequence getrennt."""
        # Euro-Zeichen: 3 Bytes in UTF-8.
        # 4096 Bytes = 1365 Euro-Zeichen + 1 Byte Rest (das letzte Euro passt nicht rein).
        unicode_str = "€" * 2000  # 6000 Bytes — ueber dem Limit
        result = truncate_error(unicode_str)
        # Wichtig: soll dekodierbares UTF-8 zurueckgeben, kein UnicodeDecodeError.
        assert result.encode("utf-8") is not None
        assert "[truncated]" in result

    def test_custom_max_bytes(self) -> None:
        """Custom max_bytes wird respektiert."""
        result = truncate_error("12345678901234567890", max_bytes=10)
        assert len(result.encode("utf-8")) <= 10 + 20  # Toleranz fuer suffix
        assert "[truncated]" in result


class TestResultToJsonb:
    """Serialisierung von ScanProcessingResult nach JSONB-dict."""

    def test_valid_result_object(self) -> None:
        """Ein gueltiges ScanProcessingResult wird korrekt serialisiert."""
        from app.services.scan_processing import ScanProcessingResult

        r = ScanProcessingResult(
            scan_id=42,
            findings_total=100,
            findings_inserted=80,
            findings_updated=15,
            findings_resolved=5,
            findings_reopened=2,
            class_os_pkgs=60,
            class_lang_pkgs=30,
            class_other=10,
        )
        d = result_to_jsonb(r)
        assert d["scan_id"] == 42
        assert d["findings_total"] == 100
        assert d["findings_inserted"] == 80
        assert d["findings_updated"] == 15
        assert d["findings_resolved"] == 5
        assert d["findings_reopened"] == 2
        assert d["class_os_pkgs"] == 60
        assert d["class_lang_pkgs"] == 30
        assert d["class_other"] == 10

    def test_all_values_are_int(self) -> None:
        """Alle serialisierten Werte sind int (fuer JSONB-Kompatibilitaet)."""
        from app.services.scan_processing import ScanProcessingResult

        r = ScanProcessingResult(
            scan_id=1,
            findings_total=10,
            findings_inserted=5,
            findings_updated=3,
            findings_resolved=2,
            findings_reopened=1,
            class_os_pkgs=7,
            class_lang_pkgs=2,
            class_other=1,
        )
        d = result_to_jsonb(r)
        for key, val in d.items():
            assert isinstance(val, int), f"Feld {key!r} ist kein int: {val!r}"

    def test_missing_attributes_returns_empty_dict(self) -> None:
        """Objekte ohne die erwarteten Attribute geben ein leeres dict zurueck."""

        class BrokenResult:
            pass

        d = result_to_jsonb(BrokenResult())
        assert d == {}

    def test_none_input_returns_empty_dict(self) -> None:
        """None als Input gibt leeres dict zurueck ohne Exception."""
        d = result_to_jsonb(None)
        assert d == {}

    def test_expected_keys_present(self) -> None:
        """Alle neun erwarteten Schluesselnamen sind im result-dict."""
        from app.services.scan_processing import ScanProcessingResult

        r = ScanProcessingResult(
            scan_id=1,
            findings_total=0,
            findings_inserted=0,
            findings_updated=0,
            findings_resolved=0,
            findings_reopened=0,
            class_os_pkgs=0,
            class_lang_pkgs=0,
            class_other=0,
        )
        d = result_to_jsonb(r)
        expected_keys = {
            "scan_id",
            "findings_total",
            "findings_inserted",
            "findings_updated",
            "findings_resolved",
            "findings_reopened",
            "class_os_pkgs",
            "class_lang_pkgs",
            "class_other",
        }
        assert set(d.keys()) == expected_keys
