# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pure-Unit-Tests fuer ``app.services.upstream_seed.build_research_seed`` (Block AI, ADR-0063, P3).

DB-frei: Finding wird als ``SimpleNamespace``-Stub gefakt (duck-typed Attribut-
Zugriff). Kein Live-Netz/LLM, keine Session.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.upstream_seed import ResearchSeed, build_research_seed


def _finding(**overrides: object) -> SimpleNamespace:
    """Baut ein researchbares lang-pkgs/gobinary-Finding (CVE-2026-42504-artig)."""
    base: dict[str, object] = {
        "finding_class": "lang-pkgs",
        "fixed_version": "1.25.9, 1.26.2",
        "target_path": "usr/sbin/tailscaled",
        "installed_version": "v1.26.1",
        "package_purl": "pkg:golang/stdlib@v1.26.1",
        "package_name": "stdlib@usr/sbin/tailscaled",
        "identifier_key": "CVE-2026-42504",
        "result_type": "gobinary",
        "title": "stdlib: net/http vulnerability",
        "description": "longer description",
        "owning_package": "tailscale",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# Happy-Path: researchbar -> korrekte Felder
# ---------------------------------------------------------------------------


def test_researchable_lang_pkgs_gobinary_full_seed() -> None:
    seed = build_research_seed(_finding())
    assert isinstance(seed, ResearchSeed)
    assert seed.artifact_module == "tailscaled"
    assert seed.installed_component_version == "v1.26.1"
    assert seed.ecosystem == "gobinary"
    assert seed.finding_class == "lang-pkgs"
    assert seed.binary_path == "usr/sbin/tailscaled"
    assert seed.vulnerable_component == "stdlib"
    assert seed.fixing_component_version == "1.25.9, 1.26.2"
    assert seed.cve == "CVE-2026-42504"
    assert seed.description == "stdlib: net/http vulnerability"
    assert seed.search_hint == "tailscale"


def test_enum_finding_class_value_normalized() -> None:
    """FindingClass-StrEnum-aehnlicher Input (`.value`) wird normalisiert."""
    enum_like = SimpleNamespace(value="lang-pkgs")
    seed = build_research_seed(_finding(finding_class=enum_like))
    assert seed is not None
    assert seed.finding_class == "lang-pkgs"


# ---------------------------------------------------------------------------
# Nicht-researchbar -> None
# ---------------------------------------------------------------------------


def test_os_pkgs_not_researchable() -> None:
    assert build_research_seed(_finding(finding_class="os-pkgs")) is None


@pytest.mark.parametrize("missing_fix", [None, "", "   "])
def test_missing_fixed_version_not_researchable(missing_fix: object) -> None:
    assert build_research_seed(_finding(fixed_version=missing_fix)) is None


@pytest.mark.parametrize("bad_path", [None, "", "   ", "/", "///"])
def test_empty_or_directory_target_path_not_researchable(bad_path: object) -> None:
    assert build_research_seed(_finding(target_path=bad_path)) is None


@pytest.mark.parametrize("missing_installed", [None, "", "   "])
def test_missing_installed_version_not_researchable(missing_installed: object) -> None:
    assert build_research_seed(_finding(installed_version=missing_installed)) is None


def test_missing_component_purl_and_name_not_researchable() -> None:
    assert build_research_seed(_finding(package_purl=None, package_name=None)) is None


def test_missing_identifier_key_not_researchable() -> None:
    assert build_research_seed(_finding(identifier_key=None)) is None


# ---------------------------------------------------------------------------
# artifact_module-Normalisierung (Basename aus target_path)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target_path", "expected_module"),
    [
        ("usr/sbin/tailscaled", "tailscaled"),
        ("/usr/sbin/tailscaled", "tailscaled"),
        ("var/lib/rancher/k3s/data/abc/bin/k3s", "k3s"),
        ("opt/app/bin/server/", "server"),  # trailing slash
        ("standalone-binary", "standalone-binary"),
    ],
)
def test_artifact_module_basename_normalization(target_path: str, expected_module: str) -> None:
    seed = build_research_seed(_finding(target_path=target_path))
    assert seed is not None
    assert seed.artifact_module == expected_module
    # binary_path bleibt der volle (rohe) Pfad.
    assert seed.binary_path == target_path


# ---------------------------------------------------------------------------
# vulnerable_component: PURL-Parsing + package_name-@target-Fallback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        ("pkg:golang/stdlib@v1.26.1", "stdlib"),
        ("pkg:golang/github.com/go-git/go-git/v5@v5.17.2", "github.com/go-git/go-git/v5"),
        ("pkg:golang/golang.org/x/crypto@v0.31.0", "golang.org/x/crypto"),
    ],
)
def test_vulnerable_component_from_purl(purl: str, expected: str) -> None:
    seed = build_research_seed(_finding(package_purl=purl))
    assert seed is not None
    assert seed.vulnerable_component == expected


def test_vulnerable_component_falls_back_to_package_name_without_at_target() -> None:
    """Ohne PURL: package_name ohne ADR-0011-``@<target>``-Suffix."""
    seed = build_research_seed(
        _finding(package_purl=None, package_name="github.com/foo/bar@usr/bin/foo")
    )
    assert seed is not None
    assert seed.vulnerable_component == "github.com/foo/bar"


def test_vulnerable_component_purl_preferred_over_name() -> None:
    seed = build_research_seed(
        _finding(package_purl="pkg:golang/stdlib@v1.26.1", package_name="other@target")
    )
    assert seed is not None
    assert seed.vulnerable_component == "stdlib"


# ---------------------------------------------------------------------------
# search_hint = owning_package, NICHT Teil von (artifact_module, installed_version)
# ---------------------------------------------------------------------------


def test_search_hint_is_owning_package_not_cache_key() -> None:
    seed_a = build_research_seed(_finding(owning_package="tailscale"))
    seed_b = build_research_seed(_finding(owning_package="something-else"))
    assert seed_a is not None and seed_b is not None
    assert seed_a.search_hint == "tailscale"
    assert seed_b.search_hint == "something-else"
    # Cache-Key (artifact_module, installed_component_version) ist
    # owning_package-unabhaengig stabil.
    assert (seed_a.artifact_module, seed_a.installed_component_version) == (
        seed_b.artifact_module,
        seed_b.installed_component_version,
    )


def test_search_hint_none_when_owning_package_absent() -> None:
    seed = build_research_seed(_finding(owning_package=None))
    assert seed is not None
    assert seed.search_hint is None


def test_description_falls_back_to_description_field_when_no_title() -> None:
    seed = build_research_seed(_finding(title=None, description="fallback desc"))
    assert seed is not None
    assert seed.description == "fallback desc"


def test_description_capped_at_600_chars() -> None:
    seed = build_research_seed(_finding(title="x" * 2000))
    assert seed is not None
    assert seed.description is not None
    assert len(seed.description) == 600
