"""Tendenz-Berechnung fuer den Server-Detail-Header (Block K, ADR-0018;
ADR-0038 reduziert das Fenster auf 30 Tage).

Liefert eine grob-granulare Klassifikation, ob die OPEN-Findings eines
Servers in den letzten Tagen steigen, fallen oder stabil bleiben. Speist
das Tendenz-Label in der HeaderStats-Sektion ("ueber 30 tage stabil" etc.).

Heuristik (siehe ADR-0018 §Begruendung):
    avg(Daily-OPEN-Total ueber `days_short` Tage)
    vs avg(Daily-OPEN-Total ueber `days_long` Tage)

    diff = (avg_short - avg_long) / max(avg_long, 1)
    diff >=  +threshold -> RISING
    diff <=  -threshold -> FALLING
    sonst              -> STABLE

Default-Parameter: `days_short=7`, `days_long=30`, `threshold=0.05`. Magic
Numbers stehen NICHT in der Logik, sondern als Default-Werte am Signatur-
Kopf — testbar und sichtbar.

Tagessumme: critical+high+medium+low aus `DailySeverityCount`. UNKNOWN
fliesst absichtlich nicht ein (analog zum Stacked-Chart).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy.orm import Session

from app.services.severity_history import DailySeverityCount, daily_severity_counts_for_server


class Tendency(StrEnum):
    """Klassifizierung der Findings-Entwicklung ueber das Tendency-Fenster."""

    STABLE = "stable"
    RISING = "rising"
    FALLING = "falling"

    @property
    def label(self) -> str:
        """Menschenlesbares Label gemaess Design-Mockup (lowercase).

        Hinweis: das Label ist auf das Default-Fenster (30 Tage, ADR-0038)
        zugeschnitten. Mit einem abweichenden `days_long` weicht der Text
        vom Wahrheitsgehalt ab — fuer den MVP-Scope ist das vertretbar.
        """
        return {
            Tendency.STABLE: "über 30 tage stabil",
            Tendency.RISING: "über 30 tage steigend",
            Tendency.FALLING: "über 30 tage fallend",
        }[self]


def tendency_from_counts(
    counts: list[DailySeverityCount],
    *,
    days_short: int = 7,
    days_long: int = 30,
    threshold: float = 0.05,
) -> Tendency:
    """Berechnet die Tendenz aus einer bereits berechneten Counts-Liste.

    Pure-Funktion ohne Session-Abhaengigkeit. Empfohlene Schnittstelle fuer
    Aufrufer, die bereits `daily_severity_counts_for_server` aufgerufen haben
    (Phase B, ADR-0030 Befund 1) — vermeidet doppelten DB-Call.

    Args:
        counts: Ergebnis von `daily_severity_counts_for_server`. Leere Liste
            liefert STABLE als Default.
        days_short: Kurzfenster fuer den avg-Short-Vergleich (Default 7).
        days_long: Langfenster; sollte `len(counts)` entsprechen (Default 30).
        threshold: Schwelle fuer signifikante Aenderung (Default 5%).

    Returns:
        `Tendency.STABLE` bei leerer History oder Differenz < threshold.
    """
    if not counts:
        return Tendency.STABLE

    # Tagessumme = critical+high+medium+low (UNKNOWN ausserhalb des Stacks).
    totals = [c.critical + c.high + c.medium + c.low for c in counts]

    # Falls die Liste kuerzer als days_short ist (Sanity-Check, sollte
    # praktisch nie passieren weil severity_history immer `days` Eintraege
    # liefert), nehmen wir was da ist.
    short_window = totals[-days_short:] if days_short > 0 else totals
    long_window = totals

    if not short_window or not long_window:
        return Tendency.STABLE

    avg_short = sum(short_window) / len(short_window)
    avg_long = sum(long_window) / len(long_window)

    denom = max(avg_long, 1.0)
    diff = (avg_short - avg_long) / denom

    if diff >= threshold:
        return Tendency.RISING
    if diff <= -threshold:
        return Tendency.FALLING
    return Tendency.STABLE


def compute_tendency(
    session: Session,
    server_id: int,
    *,
    days_short: int = 7,
    days_long: int = 30,
    threshold: float = 0.05,
    now: datetime | None = None,
) -> Tendency:
    """Duenner Wrapper um `tendency_from_counts` fuer Bestands-Aufrufer.

    Laedt die Counts via `daily_severity_counts_for_server` und delegiert
    die Berechnung an die Pure-Funktion `tendency_from_counts`. Neuer Code
    der bereits Counts hat sollte `tendency_from_counts` direkt aufrufen
    (Phase B, ADR-0030 Befund 1).

    Args:
        session: aktive SQLAlchemy-Session.
        server_id: Ziel-Server.
        days_short: Kurzfenster (Default 7 Tage).
        days_long: Langfenster (Default 30 Tage, ADR-0038).
        threshold: Schwelle fuer signifikante Aenderung (Default 5%).
        now: optionaler "Jetzt"-Zeitstempel (fuer Tests).

    Returns:
        `Tendency.STABLE` bei leerer History oder Differenz < threshold.
    """
    counts = daily_severity_counts_for_server(session, server_id, days=days_long, now=now)
    return tendency_from_counts(
        counts, days_short=days_short, days_long=days_long, threshold=threshold
    )


__all__ = ["Tendency", "compute_tendency", "tendency_from_counts"]
