"""Block N (ADR-0021) — Adversarial: VendorIDs mit Control-Chars/NUL/Overlong.

Pydantic-Validator verwirft Items still — bewusst NICHT die ganze Vuln
killen, sondern nur die schaedlichen Items raus. Cap auf 32 Items
(MAX_VENDOR_IDS_PER_VULN) und 128 Chars pro Item (MAX_VENDOR_ID_LENGTH).

Korrespondiert zu `_attack=16` in `tests/fixtures/trivy/adversarial.json`.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.schemas.scan_envelope import (
    MAX_VENDOR_ID_LENGTH,
    MAX_VENDOR_IDS_PER_VULN,
    TrivyVulnerability,
)


def _vuln_with_vendor_ids(items: list[Any]) -> TrivyVulnerability:
    return TrivyVulnerability.model_validate(
        {
            "VulnerabilityID": "CVE-2026-00016",
            "PkgName": "test-pkg",
            "InstalledVersion": "1.0",
            "Severity": "MEDIUM",
            "VendorIDs": items,
        }
    )


def test_vendor_ids_nul_byte_item_dropped() -> None:
    """`_attack=16` aus adversarial.json: NUL-Byte → Item raus, andere bleiben."""
    vuln = _vuln_with_vendor_ids(["USN-1234-1", "USN-with-NUL\x00inside", "RHSA-2024:1234"])
    assert vuln.vendor_ids == ["USN-1234-1", "RHSA-2024:1234"]


def test_vendor_ids_control_chars_dropped() -> None:
    """Newlines/Tabs/etc. → non-ASCII via `_PRINTABLE_ASCII_RE` → drop."""
    vuln = _vuln_with_vendor_ids(["USN-1234-1", "USN\n-injected", "RHSA-2024:1234"])
    assert vuln.vendor_ids == ["USN-1234-1", "RHSA-2024:1234"]


@pytest.mark.parametrize(
    "bad_item",
    [
        pytest.param("USN-é-2024", id="non-ascii"),
        pytest.param("USN-" + "A" * (MAX_VENDOR_ID_LENGTH + 1), id="overlong"),
        pytest.param("USN-\x1b[31mred", id="ansi-escape"),
    ],
)
def test_vendor_ids_bad_string_item_dropped(bad_item: Any) -> None:
    """Schadhafte STRING-Items werden still gedroppt — andere bleiben erhalten."""
    vuln = _vuln_with_vendor_ids(["USN-1234-1", bad_item, "RHSA-2024:1234"])
    assert vuln.vendor_ids == ["USN-1234-1", "RHSA-2024:1234"]


@pytest.mark.parametrize(
    "bad_item",
    [
        pytest.param(12345, id="non-string-int"),
        pytest.param(None, id="non-string-none"),
        pytest.param({"USN": 1}, id="non-string-dict"),
    ],
)
def test_vendor_ids_non_string_item_rejects_whole_vuln(bad_item: Any) -> None:
    """Pydantic v2 erzwingt `list[str]` strikt — non-string-Items killen die Vuln.

    Das ist strenger als nur `_validate_vendor_ids` zu droppen; passt aber
    zur DoS-Mitigation (kein Garbage-Item passiert in den DB-Pfad).
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _vuln_with_vendor_ids(["USN-1234-1", bad_item, "RHSA-2024:1234"])


def test_vendor_ids_cap_at_32_items() -> None:
    """50 valide Items → exakt 32 (MAX_VENDOR_IDS_PER_VULN) bleiben uebrig."""
    items = [f"ADV-{i:04d}" for i in range(50)]
    vuln = _vuln_with_vendor_ids(items)
    assert vuln.vendor_ids is not None
    assert len(vuln.vendor_ids) == MAX_VENDOR_IDS_PER_VULN
    # Reihenfolge: erste 32.
    assert vuln.vendor_ids[0] == "ADV-0000"
    assert vuln.vendor_ids[-1] == f"ADV-{31:04d}"


def test_vendor_ids_no_crash_on_all_invalid_strings() -> None:
    """Alle (STRING-) Items invalid → leere Liste, kein Vuln-Reject."""
    vuln = _vuln_with_vendor_ids(["\x00", "é-only", "\x1b[bad"])
    assert vuln.vendor_ids == []
