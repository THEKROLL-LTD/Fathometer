"""Tendenz-Berechnung fuer den Server-Detail-Header (Block K, ADR-0018).

Liefert eine grob-granulare Klassifikation, ob die OPEN-Findings eines
Servers in den letzten Tagen steigen, fallen oder stabil bleiben. Speist
das Tendenz-Label in der HeaderStats-Sektion ("ueber 50 tage stabil" etc.).

Heuristik (siehe ADR-0018 §Begruendung):
    avg(Daily-OPEN-Total ueber `days_short` Tage)
    vs avg(Daily-OPEN-Total ueber `days_long` Tage)

    diff = (avg_short - avg_long) / max(avg_long, 1)
    diff >=  +threshold -> RISING
    diff <=  -threshold -> FALLING
    sonst              -> STABLE

Default-Parameter: `days_short=7`, `days_long=50`, `threshold=0.05`. Magic
Numbers stehen NICHT in der Logik, sondern als Default-Werte am Signatur-
Kopf — testbar und sichtbar.

Tagessumme: critical+high+medium+low aus `DailySeverityCount`. UNKNOWN
fliesst absichtlich nicht ein (analog zum Stacked-Chart).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy.orm import Session

from app.services.severity_history import daily_severity_counts_for_server


class Tendency(StrEnum):
    """Klassifizierung der Findings-Entwicklung ueber das Tendency-Fenster."""

    STABLE = "stable"
    RISING = "rising"
    FALLING = "falling"

    @property
    def label(self) -> str:
        """Menschenlesbares Label gemaess Design-Mockup (lowercase).

        Hinweis: das Label ist auf das Default-Fenster (50 Tage) zugeschnitten.
        Mit einem abweichenden `days_long` weicht der Text vom Wahrheits-
        gehalt ab — fuer den MVP-Block-K-Scope ist das vertretbar.
        """
        return {
            Tendency.STABLE: "über 50 tage stabil",
            Tendency.RISING: "über 50 tage steigend",
            Tendency.FALLING: "über 50 tage fallend",
        }[self]


def compute_tendency(
    session: Session,
    server_id: int,
    *,
    days_short: int = 7,
    days_long: int = 50,
    threshold: float = 0.05,
    now: datetime | None = None,
) -> Tendency:
    """Berechnet die Tendenz fuer einen Server.

    Args:
        session: aktive SQLAlchemy-Session.
        server_id: Ziel-Server.
        days_short: Kurzfenster (Default 7 Tage).
        days_long: Langfenster (Default 50 Tage).
        threshold: Schwelle fuer signifikante Aenderung (Default 5%).
        now: optionaler "Jetzt"-Zeitstempel (fuer Tests).

    Returns:
        `Tendency.STABLE` bei leerer History oder Differenz < threshold.
    """
    counts = daily_severity_counts_for_server(session, server_id, days=days_long, now=now)

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


__all__ = ["Tendency", "compute_tendency"]
