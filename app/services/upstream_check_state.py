# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""State-Lookup fuer die agentische Upstream-Update-Suche (Block AI-2, ADR-0063, P1).

Bruecke zwischen dem `(server, group)`-Worst-Upstream-Finding, dem
``upstream_check_results``-Cache-Eintrag und dem UI-State-Kontrakt
(``idle``/``running``/``done``/``cached``/``disabled``). Zwei Aufrufer:

* die Browser-Routen in :mod:`app.api.upstream_check` (POST-Enqueue + GET-Poll),
* der Initial-Render-Pfad der ``escalate-mitigate``-Card in
  :mod:`app.views.server_detail` (Batch-Lookup ohne Extra-Roundtrip).

**Server-seitige Identitaet (IDOR-/Tampering-Schutz, ADR-0063 §Gating).** Das
zu pruefende Finding wird NIE per Client-``finding_id`` uebernommen, sondern
server-seitig als schlimmstes researchbares (has-fix lang-pkgs) Finding einer
konkreten ``(server, group)`` ermittelt (:func:`worst_upstream_finding`; seit
ADR-0064 liegen diese in der ``mitigate``-Lane). Daraus baut
``build_research_seed`` den Cache-Key ``(artifact_module, installed_version)``,
ueber den der ``upstream_check_results``-Eintrag geladen wird.

**Beratend, nie Band-flippend.** Dieses Modul liest nur; es schreibt nie
``Finding.risk_band``/``fix_lane`` — nur der Enqueue-Service beruehrt die
``upstream_check_results``-Zeile.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import nulls_last, select
from sqlalchemy.orm import Session

from app.models import Finding, FindingClass, FindingStatus, UpstreamCheckResult
from app.services.findings_query import _severity_rank_expr
from app.services.upstream_check_enqueue import UPSTREAM_CHECK_TTL_DAYS
from app.services.upstream_seed import ResearchSeed, build_research_seed

# UI-State-Kontrakt (ADR-0063 §UI/UX "Zustaende (pro Row)"). Single Source of
# Truth fuer den State-Key, den P2 auf Markup mappt (Poll-Attribut nur im
# ``running``-State).
STATE_DISABLED = "disabled"
STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_CACHED = "cached"

#: Queue-Status-Werte, die einen laufenden/wartenden Job markieren (Spiegel von
#: ``upstream_check_enqueue._IN_FLIGHT_STATES``).
_IN_FLIGHT_STATES: frozenset[str] = frozenset({"queued", "running"})


@dataclass(frozen=True, slots=True)
class UpstreamCheckState:
    """Abgeleiteter UI-State eines Upstream-Checks fuer eine ``(server, group)``.

    Reine View-Daten — kein ORM-Bezug ueber ``row`` hinaus. P2 liest:

    * ``state``: einer von :data:`STATE_DISABLED`/``IDLE``/``RUNNING``/``DONE``/
      ``CACHED`` — bestimmt das Markup und ob das HTMX-Poll-Attribut gesetzt
      wird (nur ``running``).
    * ``row``: der ``UpstreamCheckResult`` (Verdikt-Felder) oder ``None``
      (idle/disabled).
    * ``seed``: der :class:`ResearchSeed` (Anzeige-Kontext: Modul, Versionen)
      oder ``None`` (kein researchbares Finding / disabled).
    * ``checked_age``: Alter des ``done``-Verdikts (``timedelta``) oder ``None``
      — fuer „checked <relative> ago" im ``cached``-State.
    * ``is_fresh``: ``True`` wenn das ``done``-Verdikt innerhalb der TTL liegt
      (-> ``cached``), sonst ``False`` (-> ``done``, Re-Check empfohlen).
    """

    state: str
    row: UpstreamCheckResult | None
    seed: ResearchSeed | None
    checked_age: timedelta | None
    is_fresh: bool


def worst_upstream_finding(session: Session, server_id: int, group_id: int) -> Finding | None:
    """Schlimmstes researchbares (has-fix lang-pkgs) Finding der Group.

    Anker fuer den on-demand Upstream-Check (ADR-0064: Upstream-Fix ist
    Finding-Level-Enrichment, NICHT mehr eine eigene Lane). Diese Findings
    liegen jetzt in der ``mitigate``-Lane (die ``upstream``-Lane wurde mit
    ADR-0064/Block-AK-P1 kollabiert). Gefiltert auf das, was
    :func:`app.services.upstream_seed.build_research_seed` akzeptiert:
    ``status == OPEN`` UND ``finding_class == 'lang-pkgs'`` UND ``has_fix``
    (≙ ``fixed_version IS NOT NULL AND <> ''``, generierte Spalte
    :attr:`Finding.has_fix`) UND ``host_update_available IS NOT TRUE``. Letzteres
    haelt die Anker-Auswahl deckungsgleich mit der ``mitigate``-Lane: ein
    lang-pkgs-Finding mit ``host_update_available=true`` ist per ADR-0062 in der
    ``patch``-Lane (Host kann es selbst updaten) — fuer das ist ein Upstream-
    Rebuild-Check sinnlos, daher kein Anker. Sortiert nach der §15-Triage-Order (KEV desc,
    EPSS desc nulls last, CVSS desc nulls last, Severity-Rank desc,
    ``first_seen_at`` asc). Liefert das Top-Finding als volles ORM-Objekt
    (``build_research_seed`` liest mehrere Spalten) oder ``None`` (kein
    researchbares Finding).

    KEINE Client-``finding_id``: das Finding wird ausschliesslich server-seitig
    bestimmt (IDOR-/Tampering-Schutz, ADR-0063 §Gating).
    """
    stmt = (
        select(Finding)
        .where(
            Finding.server_id == server_id,
            Finding.application_group_id == group_id,
            Finding.status == FindingStatus.OPEN,
            Finding.finding_class == FindingClass.LANG_PKGS,
            Finding.has_fix,
            # ADR-0064: nur mitigate-Lane-Anker — host-updatebare lang-pkgs
            # (ADR-0062) liegen in der patch-Lane, kein Upstream-Check noetig.
            Finding.host_update_available.isnot(True),
        )
        .order_by(
            Finding.is_kev.desc(),
            nulls_last(Finding.epss_score.desc()),
            nulls_last(Finding.cvss_v3_score.desc()),
            _severity_rank_expr().desc(),
            Finding.first_seen_at.asc(),
        )
        .limit(1)
    )
    return session.execute(stmt).scalars().first()


def _load_result_row(session: Session, seed: ResearchSeed) -> UpstreamCheckResult | None:
    """Laedt die ``upstream_check_results``-Zeile per Cache-Key (oder ``None``)."""
    return session.execute(
        select(UpstreamCheckResult).where(
            UpstreamCheckResult.artifact_module == seed.artifact_module,
            UpstreamCheckResult.installed_version == seed.installed_component_version,
        )
    ).scalar_one_or_none()


def _checked_age(row: UpstreamCheckResult, *, now: datetime) -> timedelta | None:
    """Alter des Verdikts ueber ``checked_at`` (tz-naive defensiv als UTC)."""
    checked_at = row.checked_at
    if checked_at is None:
        return None
    if checked_at.tzinfo is None:
        checked_at = checked_at.replace(tzinfo=UTC)
    return now - checked_at


def derive_state(
    row: UpstreamCheckResult | None,
    seed: ResearchSeed | None,
    *,
    configured: bool,
    ttl_days: int | None = None,
    now: datetime | None = None,
) -> UpstreamCheckState:
    """Leitet den UI-State aus Cache-Zeile + Konfig-Flag ab (ADR-0063 §UI/UX).

    Reine Funktion (pure-unit testbar). Mapping:

    * ``configured`` false -> :data:`STATE_DISABLED` (Button disabled, Hinweis
      auf die Settings). Dominiert alle anderen States.
    * keine Zeile / kein researchbares Finding (``seed is None``) ->
      :data:`STATE_IDLE`.
    * ``status in {queued, running}`` -> :data:`STATE_RUNNING` (Poll-State).
    * ``status == done`` UND ``checked_at`` juenger als TTL -> :data:`STATE_CACHED`
      (Re-Check invalidiert den Cache).
    * ``status == done`` aber TTL ueberschritten -> :data:`STATE_DONE`
      (Ergebnis sichtbar, Re-Check empfohlen).
    * sonst (``status == error`` o.ae.) -> :data:`STATE_DONE` (Verdikt-/Fehler-
      Anzeige + Re-Check, ADR-0063 §"abstain/Fehler").
    """
    effective_now = now if now is not None else datetime.now(UTC)
    effective_ttl = ttl_days if ttl_days is not None else UPSTREAM_CHECK_TTL_DAYS

    if not configured:
        return UpstreamCheckState(
            state=STATE_DISABLED, row=None, seed=seed, checked_age=None, is_fresh=False
        )
    if seed is None or row is None:
        return UpstreamCheckState(
            state=STATE_IDLE, row=None, seed=seed, checked_age=None, is_fresh=False
        )

    status = row.status
    if status in _IN_FLIGHT_STATES:
        return UpstreamCheckState(
            state=STATE_RUNNING, row=row, seed=seed, checked_age=None, is_fresh=False
        )

    if status == "done":
        age = _checked_age(row, now=effective_now)
        is_fresh = age is not None and age < timedelta(days=effective_ttl)
        return UpstreamCheckState(
            state=STATE_CACHED if is_fresh else STATE_DONE,
            row=row,
            seed=seed,
            checked_age=age,
            is_fresh=is_fresh,
        )

    # error / unbekannter Status -> Verdikt-/Fehler-Anzeige (done-Markup),
    # Re-Check anbietbar. Nicht „fresh" (kein gueltiger Cache-Hit).
    return UpstreamCheckState(
        state=STATE_DONE,
        row=row,
        seed=seed,
        checked_age=_checked_age(row, now=effective_now),
        is_fresh=False,
    )


def lookup_state_for_group(
    session: Session,
    server_id: int,
    group_id: int,
    *,
    configured: bool,
    now: datetime | None = None,
) -> UpstreamCheckState:
    """Voller State-Lookup fuer eine ``(server, group)`` (DB + Ableitung).

    1. Worst researchbares Finding server-seitig (:func:`worst_upstream_finding`).
    2. :class:`ResearchSeed` daraus (``None`` = nicht researchbar -> idle).
    3. Cache-Zeile per Seed-Key.
    4. :func:`derive_state`.

    Genutzt vom GET-Poll-Endpoint und vom Card-Initial-Render. ``configured``
    wird vom Aufrufer einmal via ``is_upstream_check_configured`` bestimmt und
    durchgereicht (kein Settings-Roundtrip pro Group).
    """
    if not configured:
        return derive_state(None, None, configured=False, now=now)

    finding = worst_upstream_finding(session, server_id, group_id)
    seed = build_research_seed(finding) if finding is not None else None
    if seed is None:
        return derive_state(None, None, configured=True, now=now)
    row = _load_result_row(session, seed)
    return derive_state(row, seed, configured=True, now=now)


def lookup_state_for_seeds(
    session: Session,
    seeds: list[tuple[Any, ResearchSeed]],
    *,
    configured: bool,
    now: datetime | None = None,
) -> dict[Any, UpstreamCheckState]:
    """Batch-Variante: laedt alle Cache-Zeilen fuer eine Liste von Seeds in EINER
    Query und leitet pro Eintrag den State ab.

    ``seeds`` ist eine Liste ``(key, seed)`` — ``key`` ist ein vom Aufrufer
    gewaehlter Identifikator (z.B. die Group-ID bzw. Card-Entry-Identitaet),
    unter dem das Ergebnis-Dict indiziert wird. Verhindert N+1 ueber die
    ``escalate-mitigate``-Card (P1.3). Researchbare Seeds ohne Cache-Zeile
    werden als ``idle`` abgeleitet.

    Bei nicht-konfiguriertem Feature liefert jede Group ``disabled`` ohne
    DB-Query.
    """
    if not configured or not seeds:
        return {
            key: derive_state(None, seed, configured=configured, now=now) for key, seed in seeds
        }

    # Eine Query ueber alle (artifact_module, installed_version)-Paare.
    pairs = {(s.artifact_module, s.installed_component_version) for _key, s in seeds}
    rows = (
        session.execute(
            select(UpstreamCheckResult).where(
                UpstreamCheckResult.artifact_module.in_({m for m, _v in pairs}),
                UpstreamCheckResult.installed_version.in_({v for _m, v in pairs}),
            )
        )
        .scalars()
        .all()
    )
    by_key: dict[tuple[str, str], UpstreamCheckResult] = {
        (r.artifact_module, r.installed_version): r for r in rows
    }

    out: dict[Any, UpstreamCheckState] = {}
    for key, seed in seeds:
        row = by_key.get((seed.artifact_module, seed.installed_component_version))
        out[key] = derive_state(row, seed, configured=True, now=now)
    return out


__all__ = [
    "STATE_CACHED",
    "STATE_DISABLED",
    "STATE_DONE",
    "STATE_IDLE",
    "STATE_RUNNING",
    "UpstreamCheckState",
    "derive_state",
    "lookup_state_for_group",
    "lookup_state_for_seeds",
    "worst_upstream_finding",
]
