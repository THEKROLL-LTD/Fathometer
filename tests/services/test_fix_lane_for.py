# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer `risk_engine.fix_lane_for` + `fix_lane_sql_case`
(Block AG, ADR-0061 — dritte Lane ``upstream``).

Deckt:

* Vollmatrix ``{os-pkgs, lang-pkgs, other} x {has_fix True/False}`` je einmal
  mit ``FindingClass``-Enum-Input und einmal mit rohem ``str``-Input.
* ``has_fix``-Falsy-Werte (leerer String, ``None``, ``0``) -> ``mitigate``.
* CVE-2026-42504-Regression (tailscaled / gobinary stdlib): ``lang-pkgs`` mit
  gesetztem ``fixed_version`` -> ``upstream`` (NICHT ``patch``).
* Struktur des SQL-Spiegels (kompilierte CASE-Form, kein DB-Execute).

Kein DB-Roundtrip — reine Funktions-Aufrufe und ein Compile.
"""

from __future__ import annotations

import pytest

from app.models import Finding, FindingClass
from app.services.risk_engine import FIX_LANES, fix_lane_for, fix_lane_sql_case

# ---------------------------------------------------------------------------
# Vollmatrix: {os-pkgs, lang-pkgs, other} x {has_fix} — Enum- und str-Input
# ---------------------------------------------------------------------------

# (finding_class_value, has_fix, expected_lane) — Wahrheitstabelle ADR-0061.
_MATRIX = [
    pytest.param("os-pkgs", True, "patch", id="os-pkgs+fix=patch"),
    pytest.param("os-pkgs", False, "mitigate", id="os-pkgs+nofix=mitigate"),
    pytest.param("lang-pkgs", True, "upstream", id="lang-pkgs+fix=upstream"),
    pytest.param("lang-pkgs", False, "mitigate", id="lang-pkgs+nofix=mitigate"),
    pytest.param("other", True, "upstream", id="other+fix=upstream"),
    pytest.param("other", False, "mitigate", id="other+nofix=mitigate"),
]


@pytest.mark.parametrize(("klass", "has_fix", "expected"), _MATRIX)
def test_fix_lane_for_matrix_with_str_input(klass: str, has_fix: bool, expected: str) -> None:
    assert fix_lane_for(klass, has_fix) == expected


@pytest.mark.parametrize(("klass", "has_fix", "expected"), _MATRIX)
def test_fix_lane_for_matrix_with_enum_input(klass: str, has_fix: bool, expected: str) -> None:
    enum_klass = FindingClass(klass)
    assert fix_lane_for(enum_klass, has_fix) == expected


def test_fix_lane_for_enum_and_str_agree() -> None:
    """Enum-Input und String-Input liefern fuer jede Klasse dieselbe Lane —
    StrEnum vergleicht gleich mit seinem Wert."""
    for klass in FindingClass:
        for has_fix in (True, False):
            assert fix_lane_for(klass, has_fix) == fix_lane_for(klass.value, has_fix)


# ---------------------------------------------------------------------------
# has_fix als Falsy-Wert -> mitigate (bool(...)-Semantik)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "falsy",
    [
        pytest.param("", id="empty-string"),
        pytest.param(None, id="none"),
        pytest.param(0, id="int-zero"),
        pytest.param(False, id="bool-false"),
    ],
)
def test_fix_lane_for_falsy_has_fix_is_mitigate(falsy: object) -> None:
    """Leerer String / None / 0 / False zaehlen als no-fix -> mitigate,
    unabhaengig von der Finding-Klasse."""
    for klass in ("os-pkgs", "lang-pkgs", "other"):
        assert fix_lane_for(klass, falsy) == "mitigate", (klass, falsy)


@pytest.mark.parametrize(
    "truthy",
    [
        pytest.param("1.2.3", id="version-string"),
        pytest.param("0", id="nonempty-string-zero"),
        pytest.param(1, id="int-one"),
        pytest.param(True, id="bool-true"),
    ],
)
def test_fix_lane_for_truthy_has_fix_os_pkgs_is_patch(truthy: object) -> None:
    """Jeder truthy ``has_fix`` auf os-pkgs -> patch (auch der String ``"0"``,
    der als nicht-leer truthy ist)."""
    assert fix_lane_for("os-pkgs", truthy) == "patch"


def test_fix_lanes_constant_is_three_lanes() -> None:
    assert FIX_LANES == ("patch", "upstream", "mitigate")


# ---------------------------------------------------------------------------
# CVE-2026-42504-Regression (DoD-Kern): tailscaled / gobinary stdlib
# ---------------------------------------------------------------------------


def test_cve_2026_42504_langpkgs_with_fix_is_upstream_not_patch() -> None:
    """Regression: ein gobinary/stdlib-Finding (``lang-pkgs``) mit gesetztem
    ``fixed_version`` darf NICHT als ``patch`` klassifiziert werden — der Fix
    ist eine in das Binary kompilierte Go-Toolchain-Version, kein per
    dnf/apt applizierbares OS-Paket-Update. Erwartung: ``upstream``.

    Das ist genau der tailscaled/CVE-2026-42504-Bug, den ADR-0061 schliesst:
    vorher landete der Fix faelschlich in der patch-Lane und versprach dem
    Operator ein Host-Patch, das die Luecke nicht schliesst."""
    assert fix_lane_for("lang-pkgs", "go1.23.4") == "upstream"
    assert fix_lane_for(FindingClass.LANG_PKGS, "go1.23.4") == "upstream"


def test_cve_2026_42504_langpkgs_without_fix_is_mitigate() -> None:
    """Gleiches gobinary-Finding ohne ``fixed_version`` -> mitigate
    (no-fix-Regel hat Vorrang vor der Klassen-Unterscheidung)."""
    assert fix_lane_for("lang-pkgs", None) == "mitigate"
    assert fix_lane_for("lang-pkgs", "") == "mitigate"


# ---------------------------------------------------------------------------
# SQL-Spiegel: kompilierte CASE-Form spiegelt die Python-Wahrheitstabelle
# ---------------------------------------------------------------------------


def test_fix_lane_sql_case_compiles_to_mirrored_truth_table() -> None:
    """Der SQLAlchemy-``case`` spiegelt :func:`fix_lane_for` Branch-fuer-Branch:
    NOT has_fix -> mitigate; finding_class == 'os-pkgs' -> patch; else upstream.
    Reine Compile-Pruefung (literal_binds), kein DB-Execute."""
    compiled = str(
        fix_lane_sql_case(Finding.finding_class, Finding.has_fix).compile(
            compile_kwargs={"literal_binds": True}
        )
    )
    assert "WHEN NOT findings.has_fix THEN 'mitigate'" in compiled
    assert "WHEN (findings.finding_class = 'os-pkgs') THEN 'patch'" in compiled
    assert "ELSE 'upstream'" in compiled
    # Branch-Reihenfolge muss exakt der Python-Logik entsprechen: no-fix-Veto
    # zuerst, dann os-pkgs, sonst upstream.
    assert compiled.index("'mitigate'") < compiled.index("'patch'") < compiled.index("'upstream'")
