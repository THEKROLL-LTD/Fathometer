# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Risk-Engine — Pre-Triage und gemeinsame Konstanten (Block O, ADR-0022).

Phase A lieferte Konstanten und Enums; Phase B faegt die deterministische
Pre-Triage-Engine plus die zentralisierte `VENDOR_SEVERITY_INT_MAP` hinzu
(Trivys internes Severity-Integer-Mapping, das vom Envelope-Pre-Validator
und potenziell von zukuenftigen LLM-Pfaden konsumiert wird).

Public-API:

* `RiskBand` — sieben Bands aus ADR-0022 §Risk-Band-Modell.
* `ActionRequired` — binaere User-Achse (`yes`/`no`).
* `ACTION_REQUIRED_MAP` — deterministisches Mapping `band -> action`.
* `RISK_BAND_SORT_RANK` — numerisches Mapping fuer die UI-Default-Sortierung.
* `EPSS_PENDING_THRESHOLD` — Cut fuer den Pre-Triage-EPSS-Trigger (0.1).
* `VENDOR_SEVERITY_INT_MAP` — Trivys interner Severity-Code (0..4) -> Label.
* `RiskEvaluation` — Result-Datacontainer der Engine.
* `pretriage(finding, server, snapshot_available) -> RiskEvaluation` —
  deterministische Vor-Klassifikation in `{noise, monitor, pending, unknown}`.
* `normalize_vendor_status(raw)` — Whitelist-Normalisierung des Trivy-Status.

Single-Responsibility: `pretriage()` macht KEINEN DB-Schreibzugriff. Sie
liest nur `finding.epss_score`, `.is_kev`, `.severity_by_provider`,
`.severity` (via `max_severity_across_providers()`) und gibt eine
`RiskEvaluation` zurueck. Der Ingest-Caller (Phase-C-Task #8) entscheidet
ob ein bestehender `risk_band_source == 'llm'` skipped wird — diese
Logik gehoert NICHT in `pretriage()` selbst.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import UTC, datetime

from app.models import Finding, Server, Severity
from app.services.severity_resolver import _SEVERITY_RANK, max_severity_across_providers


class RiskBand(enum.StrEnum):
    """Die sieben Risk-Bands aus ADR-0022.

    Drei Bands sind Block-O-Outputs der deterministischen Pre-Triage
    (`pending`, `monitor`, `noise`), einer ist Block-O-Output ohne
    Snapshot (`unknown`), drei werden vom LLM-Pass in Block P gesetzt
    (`escalate`, `act`, `mitigate`).
    """

    ESCALATE = "escalate"
    ACT = "act"
    MITIGATE = "mitigate"
    PENDING = "pending"
    UNKNOWN = "unknown"
    MONITOR = "monitor"
    NOISE = "noise"


class ActionRequired(enum.StrEnum):
    """Binaere User-Achse (ADR-0022 §Risk-Band-Modell Level 1)."""

    YES = "yes"
    NO = "no"


# Deterministisches Mapping `band -> action_required`. Single-Source-of-Truth
# fuer die UI; `action_required` ist KEINE eigene DB-Spalte sondern wird beim
# Render abgeleitet (siehe ADR-0022).
ACTION_REQUIRED_MAP: dict[RiskBand, ActionRequired] = {
    RiskBand.ESCALATE: ActionRequired.YES,
    RiskBand.ACT: ActionRequired.YES,
    RiskBand.MITIGATE: ActionRequired.YES,
    RiskBand.PENDING: ActionRequired.YES,
    RiskBand.UNKNOWN: ActionRequired.YES,
    RiskBand.MONITOR: ActionRequired.NO,
    RiskBand.NOISE: ActionRequired.NO,
}


def yes_band_values() -> tuple[str, ...]:
    """Liefert die `risk_band`-Werte fuer `action_required="yes"`.

    Abgeleitet aus `ACTION_REQUIRED_MAP`, NICHT hardcoded — wenn ein neuer
    Band hinzukommt oder ein Band die Action-Required-Achse wechselt, bleibt
    dieser Helper konsistent. Reihenfolge entspricht `RISK_BAND_SORT_RANK`
    (escalate first), damit UI-Sub-Counter deterministisch sind.
    """
    return tuple(
        band.value
        for band, action in sorted(
            ACTION_REQUIRED_MAP.items(),
            key=lambda kv: -RISK_BAND_SORT_RANK[kv[0]],
        )
        if action is ActionRequired.YES
    )


def no_band_values() -> tuple[str, ...]:
    """Liefert die `risk_band`-Werte fuer `action_required="no"`."""
    return tuple(
        band.value
        for band, action in sorted(
            ACTION_REQUIRED_MAP.items(),
            key=lambda kv: -RISK_BAND_SORT_RANK[kv[0]],
        )
        if action is ActionRequired.NO
    )


# Numerisches Mapping fuer die UI-Default-Sortierung. Streng monoton fallend
# von ESCALATE (oben) bis NOISE (unten); `NULL`-Band wird im SQL-Coalesce
# unter NOISE einsortiert (`0`), siehe ADR-0022 §Sort-Order.
RISK_BAND_SORT_RANK: dict[RiskBand, int] = {
    RiskBand.ESCALATE: 70,
    RiskBand.ACT: 60,
    RiskBand.MITIGATE: 50,
    RiskBand.PENDING: 40,
    RiskBand.UNKNOWN: 30,
    RiskBand.MONITOR: 20,
    RiskBand.NOISE: 10,
}


# Pre-Triage-Cuts (ADR-0022 §Pre-Triage-Algorithmus). Konstante im Code,
# keine Schema-Migration noetig wenn nachjustiert wird (Re-Open-Trigger).
EPSS_PENDING_THRESHOLD: float = 0.1


# Whitelist-Normalisierung fuer Trivys `Vulnerability.Status`-Feld
# (ADR-0022 §vendor_status). Keys sind die Roh-Werte aus Trivy in
# lower-case; Werte sind die UI-/DB-stabilen Labels.
_VENDOR_STATUS_MAP: dict[str, str] = {
    "affected": "affected",
    "fixed": "fixed",
    "under_investigation": "investigating",
    "will_not_fix": "will_not_fix",
    "end_of_life": "eol",
    "not_affected": "not_affected",
}


# Trivy-internes Severity-Integer-Mapping (Phase B Zentralisierungs-Ziel).
# Quelle: Trivy `dbtypes/Severity` (SeverityUnknown=0 ... SeverityCritical=4).
# Public-API damit der Envelope-Pre-Validator (`scan_envelope.py`) und
# potenzielle Block-P-Pfade die gleiche Tabelle nutzen, ohne dass die
# Konstante an zwei Stellen drifted.
VENDOR_SEVERITY_INT_MAP: dict[int, str] = {
    0: "unknown",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}


def normalize_vendor_status(raw: str | None) -> str | None:
    """Mappt den Trivy-Roh-Status auf die ADR-0022-Whitelist.

    Rueckgaben:

    * `None` falls `raw` `None` oder leer ist (kein Datensatz).
    * Ein bekannter Whitelist-Wert (`affected`/`fixed`/`investigating`/
      `will_not_fix`/`eol`/`not_affected`) falls Trivy einen erkannten
      Status liefert.
    * `"unknown"` falls Trivy einen Wert ausserhalb der Whitelist liefert
      (Forward-Compat — wir verlieren keine Findings, signalisieren aber
      dem Operator dass der Wert nicht klassifizierbar ist).
    """
    if raw is None or raw == "":
        return None
    return _VENDOR_STATUS_MAP.get(raw.strip().lower(), "unknown")


# ---------------------------------------------------------------------------
# Pre-Triage-Engine (Phase B)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RiskEvaluation:
    """Ergebnis eines Pre-Triage-Aufrufs.

    `source` ist immer `"engine"` aus diesem Modul — Block P (LLM) baut
    eigene `RiskEvaluation`-Instanzen mit `source="llm"`. Caller schreibt
    die Felder dann auf das Finding (`risk_band`, `risk_band_source`,
    `risk_band_computed_at`). `reason` wird seit TICKET-012 nicht mehr
    auf Finding-Ebene persistiert (AI-Assessment ist Group-Level).
    """

    band: RiskBand
    reason: str
    computed_at: datetime
    source: str = "engine"


# Max-Laenge fuer den Reason-String (DB-Spalte `String(256)`). Wir cappen
# defensiv am Ende der Format-Funktion damit die Persistenz nie an einem
# zu langen Grund scheitert.
_REASON_MAX_LENGTH = 256


def pretriage(finding: Finding, server: Server, snapshot_available: bool) -> RiskEvaluation:
    """Deterministische Pre-Triage-Klassifikation (ADR-0022).

    Output ist einer aus `{NOISE, MONITOR, PENDING, UNKNOWN}`. Reine
    Vor-Auswertung — kein Host-Kontext-Abgleich, kein DB-Schreibzugriff,
    kein I/O.

    Regeln (in Reihenfolge):

    1. Kein Snapshot -> `UNKNOWN`.
    2. KEV-Flag gesetzt -> `PENDING`.
    3. Max-Severity (ueber alle Provider) >= HIGH -> `PENDING`.
    4. EPSS-Score >= 0.1 -> `PENDING`.
    5. Max-Severity == MEDIUM -> `MONITOR`.
    6. sonst -> `NOISE`.

    `pretriage()` ueberschreibt einen bestehenden `risk_band` mit
    `risk_band_source == 'llm'` NICHT — diese Logik gehoert in den Caller
    (Single-Responsibility, siehe Modul-Docstring).
    """
    now = datetime.now(tz=UTC)

    # Regel 1: Kein Snapshot -> UNKNOWN.
    if not snapshot_available:
        return RiskEvaluation(
            band=RiskBand.UNKNOWN,
            reason=_truncate("host snapshot missing — update agent to >= 0.3.0"),
            computed_at=now,
        )

    max_sev = max_severity_across_providers(finding)
    max_rank = _SEVERITY_RANK[max_sev]
    epss = finding.epss_score or 0.0
    kev = bool(finding.is_kev)

    # Regel 2: KEV first — ueberschreibt alles, auch LOW + EPSS=0.
    if kev:
        return RiskEvaluation(
            band=RiskBand.PENDING,
            reason=_format_pending_reason(max_sev, epss, kev=True),
            computed_at=now,
        )

    # Regel 3: Ein einzelner HIGH/CRITICAL-Provider reicht.
    if max_rank >= _SEVERITY_RANK[Severity.HIGH]:
        return RiskEvaluation(
            band=RiskBand.PENDING,
            reason=_format_pending_reason(max_sev, epss, kev=False),
            computed_at=now,
        )

    # Regel 4: EPSS-Trigger ueber CISA-aehnliche Schwelle.
    if epss >= EPSS_PENDING_THRESHOLD:
        return RiskEvaluation(
            band=RiskBand.PENDING,
            reason=_truncate(f"EPSS {epss:.2f} >= 0.1 · pending LLM review"),
            computed_at=now,
        )

    # Regel 5: MEDIUM-Mittelfeld ohne Exploit-Signal -> MONITOR.
    if max_rank == _SEVERITY_RANK[Severity.MEDIUM]:
        return RiskEvaluation(
            band=RiskBand.MONITOR,
            reason=_truncate(f"max-severity MEDIUM · EPSS {epss:.3f} · not KEV"),
            computed_at=now,
        )

    # Regel 6: alle Provider <= LOW + EPSS < 0.1 + nicht KEV -> NOISE.
    return RiskEvaluation(
        band=RiskBand.NOISE,
        reason=_truncate(f"all providers <= LOW · EPSS {epss:.3f} · not KEV"),
        computed_at=now,
    )


def _format_pending_reason(max_sev: Severity, epss: float, *, kev: bool) -> str:
    """Baut den Reason-String fuer den PENDING-Band.

    Reihenfolge der Parts: KEV first, dann Severity (wenn HIGH+), dann EPSS
    (wenn >= 0.1), immer `"pending LLM review"` als Schluss-Token.
    Cap auf 256 Chars (DB-Spalte).
    """
    parts: list[str] = []
    if kev:
        parts.append("KEV listed")
    if _SEVERITY_RANK[max_sev] >= _SEVERITY_RANK[Severity.HIGH]:
        parts.append(f"max-severity {max_sev.value.upper()}")
    if epss >= EPSS_PENDING_THRESHOLD:
        parts.append(f"EPSS {epss:.2f}")
    parts.append("pending LLM review")
    return _truncate(" · ".join(parts))


def _truncate(reason: str) -> str:
    """Cappt den Reason-String auf die DB-Spalten-Laenge (256 Chars)."""
    if len(reason) <= _REASON_MAX_LENGTH:
        return reason
    return reason[:_REASON_MAX_LENGTH]


__all__ = [
    "ACTION_REQUIRED_MAP",
    "EPSS_PENDING_THRESHOLD",
    "RISK_BAND_SORT_RANK",
    "VENDOR_SEVERITY_INT_MAP",
    "ActionRequired",
    "RiskBand",
    "RiskEvaluation",
    "no_band_values",
    "normalize_vendor_status",
    "pretriage",
    "yes_band_values",
]
