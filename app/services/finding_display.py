"""Ursachen-Sub-Zeile pro Finding (Block N, ADR-0021).

Liefert ein strukturiertes Dict, mit dem das Template die zweite Sub-Zeile
unter dem Paket-Namen rendert. Die Logik trennt drei Faelle:

* `kind == "lang"`  — Trivy-Result-Type ist eine Sprach-/Build-Klasse
  (z.B. `gobinary`, `python-pkg`, `npm`). Hier zeigen wir den Pfad zum
  betroffenen Artefakt; bei alten Findings ohne `target_path` faellt
  die Logik auf den ADR-0011-`package_name@target`-Split zurueck.
* `kind == "os"`    — Distro-Paket (z.B. `ubuntu`, `debian`). Hier rendert
  das Template `installed_version` und bis zu drei `vendor_ids` als
  Quellen-Marker (z.B. `USN-1234-1`, `DLA-3456-1`).
* `kind == "unknown"` — `result_type` ist `None` (Legacy-Daten vor
  Block N). Template rendert in dem Fall nichts.

Der Helper wird via Context-Processor als Jinja-Global
`format_finding_cause` exponiert (siehe `app/__init__.py`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from app.models import Finding


# Distro-Trivy-Result-Types laut ADR-0021. Alles andere wird als "lang"
# klassifiziert, solange `result_type` gesetzt ist.
_DISTRO_TYPES: frozenset[str] = frozenset(
    {
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
    }
)


class FindingCause(TypedDict):
    """Strukturierte Ursachen-Anzeige fuer ein Finding (Block N).

    `kind` steuert das Render-Branching im Template:
      * `"os"`      — Distro-Paket; zeige `installed_version` + `vendor_ids`.
      * `"lang"`    — Sprach-Paket; zeige Pfad zum Artefakt.
      * `"unknown"` — Legacy-Finding ohne `result_type`; nichts rendern.
    """

    kind: str
    type_label: str
    path: str | None
    vendor_ids: list[str]
    purl: str | None
    severity_source: str | None


def format_finding_cause(f: Finding) -> FindingCause:
    """Liefert die Ursachen-Anzeige-Daten fuer ein Finding.

    Fallback-Logik fuer den Pfad: wenn `target_path` `None` ist und das
    Finding als lang-Paket klassifiziert wird, versucht der Helper den
    ADR-0011-Split aus `package_name` (`name@path/to/artifact`). So
    laufen alte Findings ohne neuen Pfad weiterhin lesbar durch.
    """
    rt = f.result_type
    if rt in _DISTRO_TYPES:
        kind = "os"
    elif rt:
        kind = "lang"
    else:
        kind = "unknown"

    path = f.target_path
    if path is None and kind == "lang" and "@" in (f.package_name or ""):
        _, _, suffix = f.package_name.partition("@")
        path = suffix or None

    return FindingCause(
        kind=kind,
        type_label=rt or "",
        path=path,
        vendor_ids=list(f.vendor_ids or []),
        purl=f.package_purl,
        severity_source=f.severity_source,
    )


__all__ = ["FindingCause", "format_finding_cause"]
