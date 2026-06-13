# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Seed-Extraktion fuer die agentische Upstream-Update-Suche (Block AI, ADR-0063, P3).

Reine, DB-freie Funktion :func:`build_research_seed`, die aus einem
``Finding`` die :class:`ResearchSeed` ableitet — die Bruecke zwischen dem
Trivy-Finding und den Agent-Instructions (P4). Sie ersetzt die hartcodierten
Spike-Konstanten (``PACKAGE``/``INSTALLED``/``INSTALLED_COMPONENT``/
``FIXING_COMPONENT``/``ECOSYSTEM`` in ``scripts/spikes/test_agent_pydantic.py``).

**Researchbarkeit (ADR-0063 §Mechanik, ADR-0061 ``upstream``-Lane):** nur
``finding_class == "lang-pkgs"`` MIT gesetzter ``fixed_version`` ist researchbar
(das ist die ``upstream``-Lane — der Komponenten-Build-Fix). ``os-pkgs`` hat
einen Host-Patch (Tier 1, ADR-0062); ein no-fix-Finding hat keine fixende
Version. Beides -> ``None``.

**Cache-Key (ADR-0063 §Cache "pro (Modul, installierte Version)"):**

* ``artifact_module`` = normalisierte Binary-**Basename** aus ``target_path``
  (z.B. ``"usr/sbin/tailscaled"`` -> ``"tailscaled"``,
  ``"var/lib/rancher/k3s/.../bin/k3s"`` -> ``"k3s"``). Bewusst **nicht**
  ``package_purl``: die PURL ist die *Komponente* (``stdlib``/Dep) und kollidiert
  ueber verschiedene Binaries. Leerer/None-Pfad -> nicht researchbar (``None``).
* ``installed_component_version`` = ``installed_version`` (z.B. ``"v1.26.1"`` fuer
  stdlib bzw. die Dep-Version fuer Dep-Findings).

``search_hint`` (= ``owning_package``, AH/ADR-0062, kann ``None`` sein) ist ein
zusaetzlicher Suchhinweis fuer den Agenten und **nicht** Teil des Cache-Keys
(AH-unabhaengig stabil).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

# Trivy-gobinary-PURLs sind ``pkg:golang/<modulpfad>@<version>``. Wir strippen
# Prefix + Versions-Suffix, um die verwundbare Komponente lesbar zu machen.
_PURL_GOLANG_PREFIX = "pkg:golang/"
# Beschreibungs-Kappung fuers Prompt (der Service neutralisiert/saeubert den
# String erst beim Einbetten ins Prompt, P4 ``_safe``).
_DESCRIPTION_MAX = 600


@dataclass(frozen=True, slots=True)
class ResearchSeed:
    """DB-freie Eingabe fuer den Research-Agenten (P4).

    Alle Felder sind reine Strings/``None`` — kein ORM-Objekt, kein Session-
    Bezug, damit der Agent-Instructions-Builder und die Tests pure-unit
    bleiben. Die untrusted Scanner-Strings (``description``) werden erst im
    Prompt-Builder (P4) ueber ``_safe`` neutralisiert.
    """

    #: Cache-Key-Teil 1: normalisierter Binary-Basename aus ``target_path``.
    artifact_module: str
    #: Cache-Key-Teil 2: installierte Komponenten-Version (``installed_version``).
    installed_component_version: str
    #: Trivy-``result_type`` (z.B. ``"gobinary"``) — das Oekosystem.
    ecosystem: str
    #: ``finding_class`` (immer ``"lang-pkgs"`` fuer einen gueltigen Seed).
    finding_class: str
    #: Voller Binary-Pfad aus ``target_path`` (z.B. ``"usr/sbin/tailscaled"``).
    binary_path: str
    #: Verwundbare Komponente (aus PURL geparst, z.B. ``"stdlib"``).
    vulnerable_component: str
    #: Fixende Komponenten-Version(en) (``fixed_version``, z.B. ``"1.25.9, 1.26.2"``).
    fixing_component_version: str
    #: CVE-/Vuln-ID (``identifier_key``).
    cve: str
    #: Gekappte Beschreibung (``title``/``description``), untrusted Scanner-Text.
    description: str | None
    #: Zusaetzlicher Suchhinweis (``owning_package``, AH) — NICHT Teil des Cache-Keys.
    search_hint: str | None


def _attr(finding: Any, name: str) -> Any:
    """Liest ein Feld vom ``Finding``-ORM-Objekt (oder duck-typed Stub/Row)."""
    return getattr(finding, name, None)


def _enum_value(raw: Any) -> str | None:
    """Normalisiert ``FindingClass``/StrEnum/str auf den String-Wert (oder None)."""
    if raw is None:
        return None
    value = getattr(raw, "value", raw)
    if not isinstance(value, str):
        return None
    return value


def _normalize_module(target_path: str | None) -> str | None:
    """Leitet den Cache-Key-``artifact_module`` aus ``target_path`` ab.

    Basename-Semantik auf dem (von fuehrenden Slashes befreiten) Pfad. Leere/
    None-Pfade oder ein Pfad, der nur auf ein Verzeichnis zeigt (trailing
    slash), liefern ``None`` -> nicht researchbar. Trivy-``target_path`` ist
    POSIX-formatiert (``usr/sbin/tailscaled``), daher ``PurePosixPath``.
    """
    if not target_path:
        return None
    stripped = target_path.strip()
    if not stripped:
        return None
    # Trailing-Slashes wuerden den Basename leer machen — abschneiden.
    base = PurePosixPath(stripped.rstrip("/")).name.strip()
    return base or None


def _parse_vulnerable_component(package_purl: str | None, package_name: str | None) -> str | None:
    """Leitet die verwundbare Komponente aus PURL (bevorzugt) oder Name ab.

    PURL ``pkg:golang/<modul>@<version>`` -> ``<modul>`` (Prefix + ``@version``
    abgeschnitten, z.B. ``"stdlib"`` oder ``"github.com/go-git/go-git/v5"``).
    Fallback: ``package_name`` ohne das ADR-0011-``@target``-Suffix.
    """
    if package_purl:
        purl = package_purl.strip()
        if purl.startswith(_PURL_GOLANG_PREFIX):
            purl = purl[len(_PURL_GOLANG_PREFIX) :]
        # Versions-Suffix (letztes ``@``) abschneiden — Modulpfade selbst tragen
        # kein ``@``, nur das PURL-Versions-Segment.
        at_idx = purl.rfind("@")
        if at_idx > 0:
            purl = purl[:at_idx]
        purl = purl.strip()
        if purl:
            return purl
    if package_name:
        # ADR-0011: ``package_name`` traegt fuer lang-pkgs ein ``@<target>``-
        # Suffix fuer den UNIQUE-Constraint. Den schneiden wir ab.
        name = package_name.split("@", 1)[0].strip()
        if name:
            return name
    return None


def build_research_seed(finding: Any) -> ResearchSeed | None:
    """Leitet aus einem ``Finding`` den :class:`ResearchSeed` ab (oder ``None``).

    Pure/DB-frei: liest nur Attribute. ``None`` (= nicht researchbar) wenn:

    * ``finding_class != "lang-pkgs"`` (os-pkgs hat Host-Patch, Tier 1),
    * keine ``fixed_version`` (no-fix — keine fixende Komponente),
    * ``target_path`` ergibt keinen Binary-Basename (Cache-Key-Teil 1 fehlt),
    * keine ``installed_version`` (Cache-Key-Teil 2 fehlt),
    * keine verwundbare Komponente aus PURL/Name ableitbar.
    """
    finding_class = _enum_value(_attr(finding, "finding_class"))
    if finding_class != "lang-pkgs":
        return None

    fixed_version = _attr(finding, "fixed_version")
    if not fixed_version or not str(fixed_version).strip():
        return None

    artifact_module = _normalize_module(_attr(finding, "target_path"))
    if artifact_module is None:
        return None

    installed_version = _attr(finding, "installed_version")
    if not installed_version or not str(installed_version).strip():
        return None

    vulnerable_component = _parse_vulnerable_component(
        _attr(finding, "package_purl"), _attr(finding, "package_name")
    )
    if vulnerable_component is None:
        return None

    cve = _attr(finding, "identifier_key")
    if not cve or not str(cve).strip():
        return None

    ecosystem = _attr(finding, "result_type") or "unknown"

    # Beschreibung: ``title`` bevorzugt, sonst ``description`` (gekappt). Bleibt
    # untrusted Scanner-Text; die Marker-Neutralisierung passiert im
    # Prompt-Builder (P4), nicht hier (Seed bleibt rohe Daten).
    raw_desc = _attr(finding, "title") or _attr(finding, "description")
    description: str | None = None
    if raw_desc:
        description = str(raw_desc)[:_DESCRIPTION_MAX]

    owning_package = _attr(finding, "owning_package")
    search_hint = str(owning_package) if owning_package else None

    return ResearchSeed(
        artifact_module=artifact_module,
        installed_component_version=str(installed_version).strip(),
        ecosystem=str(ecosystem),
        finding_class=finding_class,
        binary_path=str(_attr(finding, "target_path")),
        vulnerable_component=vulnerable_component,
        fixing_component_version=str(fixed_version).strip(),
        cve=str(cve).strip(),
        description=description,
        search_hint=search_hint,
    )


__all__ = ["ResearchSeed", "build_research_seed"]
