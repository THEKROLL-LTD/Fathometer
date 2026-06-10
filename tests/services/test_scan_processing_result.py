"""Pure-Unit-Tests fuer ``ScanProcessingResult`` Pydantic-Validation.

Testet ausschliesslich das Pydantic-Modell, keine DB-Abhaengigkeiten.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.services.scan_processing import ScanProcessingResult


class TestScanProcessingResultValid:
    """Happy-Path: gueltiger Result."""

    def test_all_fields_set(self) -> None:
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
        assert r.scan_id == 42
        assert r.findings_total == 100
        assert r.findings_inserted == 80
        assert r.findings_updated == 15
        assert r.findings_resolved == 5
        assert r.findings_reopened == 2
        assert r.class_os_pkgs == 60
        assert r.class_lang_pkgs == 30
        assert r.class_other == 10

    def test_zeros_allowed(self) -> None:
        """Alle Felder koennen Null sein (leerer Scan)."""
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
        assert r.findings_total == 0

    def test_extra_fields_ignored(self) -> None:
        """extra='ignore' — unbekannte Felder werden verworfen."""
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
            unknown_future_field="ignored",  # type: ignore[call-arg]
        )
        assert not hasattr(r, "unknown_future_field")


class TestScanProcessingResultNegativeCounts:
    """Negative Counts duerfen nicht akzeptiert werden."""

    @pytest.mark.parametrize(
        "field,value",
        [
            ("scan_id", -1),
            ("findings_total", -1),
            ("findings_inserted", -1),
            ("findings_updated", -1),
            ("findings_resolved", -1),
            ("findings_reopened", -1),
            ("class_os_pkgs", -1),
            ("class_lang_pkgs", -1),
            ("class_other", -1),
        ],
    )
    def test_negative_raises_validation_error(self, field: str, value: int) -> None:
        """Negative Werte in jedem Feld fuehren zu ValidationError."""
        kwargs: dict[str, int] = {
            "scan_id": 1,
            "findings_total": 0,
            "findings_inserted": 0,
            "findings_updated": 0,
            "findings_resolved": 0,
            "findings_reopened": 0,
            "class_os_pkgs": 0,
            "class_lang_pkgs": 0,
            "class_other": 0,
        }
        kwargs[field] = value
        with pytest.raises(ValidationError) as exc_info:
            ScanProcessingResult(**kwargs)
        # Stellt sicher dass der Fehler den richtigen Feldnamen enthaelt.
        errors = exc_info.value.errors()
        assert any(e["loc"] == (field,) for e in errors), (
            f"Kein Fehler fuer Feld '{field}' in: {errors}"
        )


class TestScanProcessingResultMissingFields:
    """Fehlende Pflichtfelder fuehren zu ValidationError."""

    def test_missing_scan_id(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ScanProcessingResult(  # type: ignore[call-arg]
                findings_total=0,
                findings_inserted=0,
                findings_updated=0,
                findings_resolved=0,
                findings_reopened=0,
                class_os_pkgs=0,
                class_lang_pkgs=0,
                class_other=0,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("scan_id",) for e in errors)

    def test_missing_class_fields(self) -> None:
        with pytest.raises(ValidationError):
            ScanProcessingResult(  # type: ignore[call-arg]
                scan_id=1,
                findings_total=0,
                findings_inserted=0,
                findings_updated=0,
                findings_resolved=0,
                findings_reopened=0,
            )
