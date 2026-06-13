"""Pass-2-Input-Selektion — deterministische Worst-Auswahl (TICKET-011).

Ersetzt das zufaellige ``fs[:32]``-Cap in ``_render_pass2_prompt``: die
Findings kommen aus dem Worker ohne ORDER BY, d.h. bei Groups > Budget
lag z.B. ein KEV-Finding beliebig oft ausserhalb des Prompt-Fensters
(Bug A, Befund CVE-2026-31431).

:func:`select_pass2_findings` ist eine reine Funktion ueber eine bereits
geladene Finding-Liste (keine Session, kein Query) und waehlt nach
festen Stufen:

1. Pflicht-Slots: alle KEV, dann alle CRITICAL. Ueberschreiten allein
   diese das Budget, wird innerhalb nach EPSS desc gekuerzt (KEV vor
   CRITICAL).
2. EPSS-Quote: Top-:data:`EPSS_QUOTA` nach EPSS — faengt
   "wahrscheinlich ausgenutzt, aber nur MEDIUM".
3. Pfad-Quote: je distinct ``target_path`` (Fallback ``package_name``)
   das nach Triage-Order schlimmste Finding (Exposure-Breite fuers
   Pfad-Reasoning).
4. Auffuellen des Restbudgets nach Triage-Order.

Triage-Order = ``is_kev DESC, epss DESC NULLS LAST, cvss DESC NULLS
LAST, severity_rank DESC, first_seen ASC``, Tiebreak ``identifier_key``
und zuletzt ``id`` — damit ist die Auswahl total geordnet, also
deterministisch und reproduzierbar. Render-Reihenfolge = Triage-Order.

Fix-Verfuegbarkeit ist bewusst KEIN Selektionskriterium (User-
Entscheidung 1, TICKET-011): ein Fix macht ein Finding nicht schlimmer.
``fixed_version`` bleibt Attribut der Prompt-Zeile (Action-Type-
Entscheidung), fliesst aber nicht in die Auswahl ein.

Invariante: solange die Anzahl KEV-Findings das Budget nicht
ueberschreitet, enthaelt der Rest 0 KEV (``rest_kev_count == 0``). Im
(theoretischen) Overflow-Fall traegt das Aggregat den ehrlichen
KEV-Count statt einer harten 0.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from app.models import Finding, Severity
from app.services.risk_engine import FIX_LANES, FixLane, fix_lane_for

#: Default-Budget — bewusst identisch zum historischen ``fs[:32]``-Cap.
#: Budget-Tuning ist explizit nicht Teil von TICKET-011.
PASS2_FINDINGS_BUDGET = 32

#: ``FixLane``/``FIX_LANES`` leben seit ADR-0061 in :mod:`app.services.risk_engine`
#: (Single-Source ueber drei Lanes: ``patch``/``upstream``/``mitigate``). Hier
#: re-exportiert fuer Back-Compat der Bestands-Importeure (``server_detail``,
#: ``pass2_enqueue``), die ``FixLane``/``FIX_LANES`` aus diesem Modul beziehen.


def fix_lane_of(finding: Finding) -> FixLane:
    """Deterministische Fix-Lane eines Findings (ADR-0061, verfeinert ADR-0062).

    Delegiert an die Single-Source :func:`risk_engine.fix_lane_for` mit
    ``finding.finding_class``, ``bool(finding.fixed_version)`` und dem
    Host-Update-Flag ``finding.host_update_available``. ``bool(fixed_version)``
    ist exakt das Praedikat der generierten DB-Spalte ``Finding.has_fix``
    (``fixed_version IS NOT NULL AND fixed_version <> ''``), damit Enqueue,
    Worker-Persist und der SQL-Lane-CASE der Inheritance **dieselbe**
    Partition sehen. Ein leerer ``fixed_version``-String zaehlt damit als
    ``mitigate``. ``host_update_available=True`` promotet ein lang-pkgs-Finding
    von ``upstream`` nach ``patch`` (ADR-0062); ``False``/``NULL`` bleibt
    ``upstream``.
    """
    return fix_lane_for(
        finding.finding_class,
        bool(finding.fixed_version),
        finding.host_update_available,
    )


def partition_by_lane(findings: Iterable[Finding]) -> dict[FixLane, list[Finding]]:
    """Partitioniert Findings in die drei Fix-Lanes (ADR-0061).

    Liefert immer alle drei Keys (``patch``/``upstream``/``mitigate``); leere
    Lanes haben eine leere Liste. Caller ueberspringen leere Lanes (kein Job,
    keine Eval-Row — ADR-0053/0061).
    """
    buckets: dict[FixLane, list[Finding]] = {lane: [] for lane in FIX_LANES}
    for f in findings:
        buckets[fix_lane_of(f)].append(f)
    return buckets


#: Stufe 2: Anzahl Top-EPSS-Slots (Budget // 4).
EPSS_QUOTA = PASS2_FINDINGS_BUDGET // 4

#: Python-Pendant zu ``findings_query._severity_rank_expr`` (SQL-CASE).
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}

#: Render-Reihenfolge der Severity-Counts im Rest-Aggregat.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.UNKNOWN,
)

_TriageKey = tuple[int, int, float, int, float, int, float, str, int]


def triage_sort_key(f: Finding) -> _TriageKey:
    """Sort-Key fuer die Triage-Order (aufsteigend sortieren).

    ``is_kev DESC, epss DESC NULLS LAST, cvss DESC NULLS LAST,
    severity_rank DESC, first_seen ASC, identifier_key ASC, id ASC``.
    """
    return (
        0 if f.is_kev else 1,
        1 if f.epss_score is None else 0,
        -(f.epss_score or 0.0),
        1 if f.cvss_v3_score is None else 0,
        -(f.cvss_v3_score or 0.0),
        -_SEVERITY_RANK.get(f.severity, 0),
        f.first_seen_at.timestamp(),
        f.identifier_key,
        int(f.id),
    )


def _epss_desc_key(f: Finding) -> tuple[float, _TriageKey]:
    """EPSS desc, NULLS LAST; Tiebreak Triage-Order."""
    epss = f.epss_score if f.epss_score is not None else -1.0
    return (-epss, triage_sort_key(f))


@dataclass(frozen=True)
class SelectionResult:
    """Ergebnis der Pass-2-Input-Selektion inkl. Rest-Aggregat."""

    #: Selektierte Findings in Triage-Order (= Render-Reihenfolge).
    selected: tuple[Finding, ...]
    #: IDs der selektierten Findings — fuer die ``worst_finding_id``-
    #: Validierung (das LLM darf nur gezeigte IDs referenzieren).
    selected_ids: frozenset[int]
    #: Anzahl nicht gezeigter Findings (0 wenn Group <= Budget).
    rest_count: int
    #: ``((severity_value, count), ...)`` in Severity-Order, nur > 0.
    rest_severity_counts: tuple[tuple[str, int], ...]
    rest_max_epss: float | None
    rest_fixable_count: int
    #: 0 solange #KEV <= Budget (Invariante); sonst ehrlicher Count.
    rest_kev_count: int


def select_pass2_findings(
    findings: Sequence[Finding],
    budget: int = PASS2_FINDINGS_BUDGET,
) -> SelectionResult:
    """Waehlt deterministisch die ``budget`` wichtigsten Findings aus.

    Reine Funktion — keine Session, kein Query; O(n log n) ueber die
    bereits geladene Liste. Gleicher Input liefert identische Auswahl
    und Reihenfolge.
    """
    # Dedupe ueber Finding-ID; Triage-Order ist ab hier die kanonische
    # Reihenfolge fuer alle Stufen und das Render.
    ordered: list[Finding] = []
    seen_ids: set[int] = set()
    for f in sorted(findings, key=triage_sort_key):
        fid = int(f.id)
        if fid in seen_ids:
            continue
        seen_ids.add(fid)
        ordered.append(f)

    if len(ordered) <= budget:
        return _build_result(ordered, [])

    selected_ids: set[int] = set()

    def take(candidates: Iterable[Finding]) -> None:
        for f in candidates:
            if len(selected_ids) >= budget:
                return
            selected_ids.add(int(f.id))

    kev = [f for f in ordered if f.is_kev]
    critical = [f for f in ordered if not f.is_kev and f.severity == Severity.CRITICAL]

    if len(kev) + len(critical) > budget:
        # Overflow: Verdikt ist ohnehin klar — innerhalb nach EPSS desc
        # kuerzen (KEV vor CRITICAL), Rest steht im Aggregat.
        take(sorted(kev, key=_epss_desc_key))
        take(sorted(critical, key=_epss_desc_key))
    else:
        # Stufe 1: Pflicht-Slots.
        take(kev)
        take(critical)
        # Stufe 2: EPSS-Quote (Overlap mit Stufe 1 ist via Set-Dedupe
        # gratis — die Quote zaehlt die Top-k insgesamt, nicht k neue).
        with_epss = [f for f in ordered if f.epss_score is not None]
        take(sorted(with_epss, key=_epss_desc_key)[:EPSS_QUOTA])
        # Stufe 3: Pfad-Quote — erstes Vorkommen je Pfad/Paket in
        # Triage-Order ist das jeweils schlimmste Finding.
        seen_paths: set[str] = set()
        for f in ordered:
            path_key = (f.target_path or "").strip() or f.package_name
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            take([f])
        # Stufe 4: Auffuellen nach Triage-Order.
        take(ordered)

    selected = [f for f in ordered if int(f.id) in selected_ids]
    rest = [f for f in ordered if int(f.id) not in selected_ids]
    return _build_result(selected, rest)


def _build_result(selected: list[Finding], rest: list[Finding]) -> SelectionResult:
    severity_counts = tuple(
        (sev.value, count)
        for sev in _SEVERITY_ORDER
        if (count := sum(1 for f in rest if f.severity == sev)) > 0
    )
    epss_values = [f.epss_score for f in rest if f.epss_score is not None]
    return SelectionResult(
        selected=tuple(selected),
        selected_ids=frozenset(int(f.id) for f in selected),
        rest_count=len(rest),
        rest_severity_counts=severity_counts,
        rest_max_epss=max(epss_values) if epss_values else None,
        rest_fixable_count=sum(1 for f in rest if f.fixed_version),
        rest_kev_count=sum(1 for f in rest if f.is_kev),
    )


__all__ = [
    "EPSS_QUOTA",
    "FIX_LANES",
    "PASS2_FINDINGS_BUDGET",
    "FixLane",
    "SelectionResult",
    "fix_lane_for",
    "fix_lane_of",
    "partition_by_lane",
    "select_pass2_findings",
    "triage_sort_key",
]
