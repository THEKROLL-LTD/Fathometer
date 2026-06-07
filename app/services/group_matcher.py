# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Pattern-Matcher fuer Block P (ADR-0023) — deterministische Zuordnung.

Implementiert die Match-Logik aus ADR-0023 §"Pattern-Match-Logik":

1. ``path_prefixes`` — laengster Prefix-Match gewinnt (ueber alle Groups).
2. ``pkg_name_exact`` — auf ``finding.package_name.split("@", 1)[0]``
   (ADR-0011-``@target``-Suffix abschneiden).
3. ``pkg_name_glob`` via ``fnmatch.fnmatchcase``.
4. ``pkg_purl_pattern`` — Prefix-Match auf ``finding.package_purl or ""``.

Singleton mit In-Memory-Cache. Concurrency: ``_lock`` schuetzt nur den
In-Memory-State (``_groups``, ``_loaded``). Der Worker und der Ingest-Pfad
rufen :func:`apply_matches_for_server` beide auf — beide rufen vor jedem
Match-Pass :meth:`GroupMatcher.reload` auf, damit die Library frisch ist.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence
from threading import Lock

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import ApplicationGroup, Finding


class GroupMatcher:
    """In-Memory-Singleton mit der ``application_groups``-Library.

    Lazy-init ueber :meth:`get`. Vor jedem Match-Pass MUSS der Caller
    :meth:`reload` aufrufen — der Cache ist nicht selbst-invalidierend.
    """

    _instance: GroupMatcher | None = None
    _class_lock: Lock = Lock()

    def __init__(self) -> None:
        self._lock: Lock = Lock()
        self._groups: list[ApplicationGroup] = []
        self._loaded: bool = False

    @classmethod
    def get(cls) -> GroupMatcher:
        """Lazy Singleton-Zugriff mit double-checked Locking."""
        if cls._instance is None:
            with cls._class_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def _reset_for_tests(cls) -> None:
        """Nur fuer Tests — verwirft den Singleton."""
        with cls._class_lock:
            cls._instance = None

    def reload(self, session: Session) -> None:
        """Laedt die komplette ``application_groups``-Tabelle in den Cache."""
        groups = list(session.execute(select(ApplicationGroup)).scalars().all())
        with self._lock:
            self._groups = groups
            self._loaded = True

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def groups(self) -> list[ApplicationGroup]:
        """Snapshot der aktuell geladenen Groups (Kopie)."""
        with self._lock:
            return list(self._groups)

    def match(self, finding: Finding) -> ApplicationGroup | None:
        """Match-Reihenfolge: path_prefix (laengster Match) > pkg_exact > glob > purl.

        Returns ``None`` wenn kein Pattern greift oder die Library leer ist.
        """
        with self._lock:
            if not self._loaded:
                return None
            groups = list(self._groups)

        # 1) path_prefixes — laengster Match gewinnt.
        # Bugfix 2026-05-24: Slash-insensitive vergleichen. Trivys
        # ``Result.Target``/``PkgPath`` sind bei ``rootfs /``-Scans relativ und
        # tragen keinen Leading-Slash (``AdminLTE-master/...``), waehrend
        # LLM-emittierte Prefixes laut PASS1-Prompt mit ``/`` beginnen
        # (``/AdminLTE-master/``). Der Pass1-Validator normalisiert seit
        # demselben Commit beim Persistieren auf relative Form — der ``lstrip``
        # hier ist defensive Forward-Compat gegen Legacy-Rows in der
        # ``application_groups``-Library.
        target_norm = (finding.target_path or "").lstrip("/")
        best: tuple[int, ApplicationGroup] | None = None
        if target_norm:
            for grp in groups:
                for prefix in grp.path_prefixes or []:
                    if not prefix:
                        continue
                    prefix_norm = prefix.lstrip("/")
                    if prefix_norm and target_norm.startswith(prefix_norm):
                        candidate = (len(prefix_norm), grp)
                        if best is None or candidate[0] > best[0]:
                            best = candidate
        if best is not None:
            return best[1]

        # 2) pkg_name_exact — strippt ADR-0011-`@target`-Suffix.
        pkg_name_raw = finding.package_name or ""
        pkg_name_base = pkg_name_raw.split("@", 1)[0]
        for grp in groups:
            if pkg_name_base and pkg_name_base in (grp.pkg_name_exact or []):
                return grp

        # 3) pkg_name_glob — case-sensitive fnmatch.
        for grp in groups:
            for pattern in grp.pkg_name_glob or []:
                if pattern and fnmatch.fnmatchcase(pkg_name_base, pattern):
                    return grp

        # 4) pkg_purl_pattern — simpler Prefix-Match.
        purl = finding.package_purl or ""
        if purl:
            for grp in groups:
                for pattern in grp.pkg_purl_pattern or []:
                    if pattern and purl.startswith(pattern):
                        return grp

        return None


def apply_matches_for_server(session: Session, server_id: int) -> int:
    """Sucht alle ungroupierten Findings dieses Servers und versucht zu matchen.

    Setzt bei Treffer ``Finding.application_group_id`` und aktualisiert
    ``ApplicationGroup.last_used_at`` auf ``now()``. Caller muss commit
    machen. Returns die Anzahl neu zugeordneter Findings.
    """
    matcher = GroupMatcher.get()
    matcher.reload(session)
    count = 0
    findings = list(
        session.execute(
            select(Finding).where(
                Finding.server_id == server_id,
                Finding.application_group_id.is_(None),
            )
        )
        .scalars()
        .all()
    )
    touched_groups: set[int] = set()
    for finding in findings:
        grp = matcher.match(finding)
        if grp is None:
            continue
        finding.application_group_id = grp.id
        touched_groups.add(grp.id)
        count += 1
    # Group-`last_used_at` einmal pro betroffener Group setzen.
    if touched_groups:
        groups = list(
            session.execute(select(ApplicationGroup).where(ApplicationGroup.id.in_(touched_groups)))
            .scalars()
            .all()
        )
        now_func = func.now()
        for grp in groups:
            grp.last_used_at = now_func
    return count


def derive_group_kind(
    *,
    path_prefixes: list[str],
    pkg_name_exact: list[str],
    pkg_purl_pattern: list[str],
    pkg_name_glob: list[str],
) -> str:
    """Deterministische Ableitung von :attr:`ApplicationGroup.group_kind`.

    Regel laut ADR-0023 §"Update v0.9.3" Punkt (c):

    * ``application_bundle`` — wenn ``path_prefixes`` non-empty
      (Bundle-Identitaet primaer ueber Pfad).
    * ``os_package`` — andernfalls (nur ``pkg_name_exact`` /
      ``pkg_purl_pattern`` / ``pkg_name_glob`` befuellt).

    ``pkg_name_exact``/``pkg_purl_pattern``/``pkg_name_glob`` werden
    erwartet, sind aber fuer die Entscheidung nicht ausschlaggebend —
    die Signatur dokumentiert was der Caller liefern kann.
    """
    if path_prefixes:
        return "application_bundle"
    # Defense-in-Depth: die ungenutzten Parameter halten den Linter
    # bei Laune und dokumentieren das volle Match-Rules-Tupel.
    _ = (pkg_name_exact, pkg_purl_pattern, pkg_name_glob)
    return "os_package"


def affinity_sort_for_pass1(findings: Sequence[Finding]) -> list[Finding]:
    """Sortiert Findings nach (target_path-Top-3-Segments, package_name).

    Ziel: Findings die zur selben Owner-Application gehoeren landen
    benachbart und damit beim Batch-Split im selben Chunk. Das LLM
    sieht dann den Cross-Language-/Multi-Path-Kontext (Pass-1-Regel 6
    und 7) und kann Bundle-Group-Labels konsistent vergeben.

    Sort-Key:
      - primaer: Top-3-Path-Segments des target_path
        (z.B. "/var/lib/rancher" oder "/home/webapp")
      - sekundaer: package_name (haelt gleiche OS-Pakete beieinander)
      - tertiaer: id (deterministischer Tiebreak)
    """

    def _key(f: Finding) -> tuple[str, str, int]:
        path = f.target_path or ""
        parts = path.split("/")
        # parts[0] ist leer wenn path mit / beginnt; nimm die ersten
        # drei nicht-leeren Segments
        segs = [p for p in parts if p]
        bucket = "/" + "/".join(segs[:3]) if segs else ""
        return (bucket, f.package_name or "", int(f.id))

    return sorted(findings, key=_key)


__all__ = [
    "GroupMatcher",
    "affinity_sort_for_pass1",
    "apply_matches_for_server",
    "derive_group_kind",
]
