"""Block N (ADR-0021) — Smoke-Tests fuer `format_finding_cause`.

Volle Edge-Case-Sammlung kommt in Phase D durch den test-writer; hier nur
die DoD-Asserts aus Task #12a: drei `kind`-Pfade (os/lang/unknown) plus
der ADR-0011-Fallback aus `package_name@target`.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.services.finding_display import format_finding_cause


def _finding(**kwargs: Any) -> Any:
    """Erzeugt einen Finding-Stub mit den Feldern, die der Helper liest."""
    defaults: dict[str, Any] = {
        "result_type": None,
        "target_path": None,
        "package_name": "",
        "package_purl": None,
        "severity_source": None,
        "vendor_ids": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_kind_lang_gobinary_with_target_path() -> None:
    """gobinary mit gesetztem `target_path` -> kind=lang, Pfad direkt aus dem Feld."""
    cause = format_finding_cause(
        _finding(
            result_type="gobinary",
            target_path="usr/local/bin/myapp",
            package_name="github.com/foo/bar",
            package_purl="pkg:golang/github.com/foo/bar@v1.0.0",
            severity_source="ghsa",
        )
    )
    assert cause["kind"] == "lang"
    assert cause["type_label"] == "gobinary"
    assert cause["path"] == "usr/local/bin/myapp"
    assert cause["purl"] == "pkg:golang/github.com/foo/bar@v1.0.0"
    assert cause["severity_source"] == "ghsa"
    assert cause["vendor_ids"] == []


def test_kind_os_ubuntu_with_vendor_ids() -> None:
    """ubuntu -> kind=os; vendor_ids werden als Liste durchgereicht."""
    cause = format_finding_cause(
        _finding(
            result_type="ubuntu",
            target_path=None,
            package_name="openssl",
            vendor_ids=["USN-1234-1", "DLA-5678-1"],
            severity_source="ubuntu",
        )
    )
    assert cause["kind"] == "os"
    assert cause["type_label"] == "ubuntu"
    assert cause["path"] is None
    assert cause["vendor_ids"] == ["USN-1234-1", "DLA-5678-1"]
    assert cause["severity_source"] == "ubuntu"


def test_kind_unknown_no_result_type() -> None:
    """Legacy-Finding ohne `result_type` -> kind=unknown, kein Pfad-Fallback."""
    cause = format_finding_cause(
        _finding(
            result_type=None,
            target_path=None,
            package_name="legacy@/should/not/leak",
        )
    )
    assert cause["kind"] == "unknown"
    assert cause["type_label"] == ""
    # ADR-0011-Fallback gilt NUR wenn kind=lang. Unknown -> path bleibt None.
    assert cause["path"] is None


def test_lang_fallback_from_package_name_at_suffix() -> None:
    """Lang-Finding ohne `target_path` -> Pfad aus `package_name@<path>` (ADR-0011)."""
    cause = format_finding_cause(
        _finding(
            result_type="gobinary",
            target_path=None,
            package_name="github.com/foo/bar@usr/local/bin/myapp",
        )
    )
    assert cause["kind"] == "lang"
    assert cause["path"] == "usr/local/bin/myapp"


def test_all_distro_result_types_are_os() -> None:
    """Alle in der Allowlist genannten Distros werden als kind=os erkannt."""
    distro_types = (
        "ubuntu",
        "debian",
        "rhel",
        "centos",
        "rocky",
        "alma",
        "fedora",
        "amazon",
        "alpine",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "sles",
        "oracle",
    )
    for dt in distro_types:
        cause = format_finding_cause(_finding(result_type=dt, package_name="pkg"))
        assert cause["kind"] == "os", f"{dt} should be os"
        assert cause["type_label"] == dt


def test_vendor_ids_none_becomes_empty_list() -> None:
    """`vendor_ids = None` muss als leere Liste durchkommen (Template iteriert)."""
    cause = format_finding_cause(_finding(result_type="ubuntu", vendor_ids=None))
    assert cause["vendor_ids"] == []
