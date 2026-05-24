"""Listener-Exposure-Klassifizierung (Block X, ADR-0038 §(3)).

Bestimmt fuer eine bind-Adresse, ob ein Listener nur loopback-erreichbar ist
oder vom Netz exponiert. Pure Function, keine DB, keine Persistenz-Spalte am
ServerListener-Modell — die Klassifizierung ist 100 Prozent aus dem ``addr``-
Feld ableitbar und kann jederzeit ohne Migration veraendert werden.

Klassifizierungen:
- ``"LOOPBACK"``: addr matched 127.0.0.0/8 (IPv4-Loopback) ODER ::1
  (IPv6-Loopback). Beides wird von ``ipaddress.ip_address(...).is_loopback``
  aus der stdlib abgedeckt.
- ``"PUBLIC EXPOSED"``: alles andere (``0.0.0.0``, ``::``, externe
  IPv4/IPv6-Bind-Adressen) sowie ungueltige Eingaben — fail-safe: lieber
  eine Warn-Pille zu viel als einen exponierten Listener als Loopback zu
  maskieren.

Verwendet ``ipaddress.ip_address(...).is_loopback`` aus der stdlib (ein
einheitlicher API-Pfad fuer IPv4 und IPv6, der die CIDR-Semantik korrekt
implementiert).
"""

from __future__ import annotations

import ipaddress
from typing import Literal

ExposureClass = Literal["LOOPBACK", "PUBLIC EXPOSED"]


def classify_exposure(addr: str) -> ExposureClass:
    """Klassifiziert eine bind-Adresse als LOOPBACK oder PUBLIC EXPOSED.

    Fail-safe: ungueltige Eingaben (leerer String, Nicht-IP-Token,
    Whitespace-only, IPv6-Brackets, Port-Suffix, ...) geben
    ``"PUBLIC EXPOSED"`` zurueck.

    Begruendung: lieber eine Warn-Pille zu viel als versehentlich einen
    exponierten Listener als Loopback zu maskieren.

    Beispiele::

        classify_exposure("127.0.0.1")       -> "LOOPBACK"
        classify_exposure("::1")             -> "LOOPBACK"
        classify_exposure("[::1]")           -> "LOOPBACK"
        classify_exposure("[::1]:8000")      -> "LOOPBACK"
        classify_exposure("0.0.0.0")         -> "PUBLIC EXPOSED"
        classify_exposure("::")              -> "PUBLIC EXPOSED"
        classify_exposure("8.8.8.8")         -> "PUBLIC EXPOSED"
        classify_exposure("")                -> "PUBLIC EXPOSED"
        classify_exposure("not-an-ip")       -> "PUBLIC EXPOSED"

    Args:
        addr: Bind-Adresse wie sie im ``ServerListener.addr``-Feld steht.
            Kann IPv4, IPv6 (mit oder ohne eckige Klammern / Port-Suffix)
            oder eine ungueltige Zeichenkette sein.

    Returns:
        ``"LOOPBACK"`` wenn die Adresse ausschliesslich loopback-erreichbar
        ist; ``"PUBLIC EXPOSED"`` in allen anderen Faellen.
    """
    if not addr:
        return "PUBLIC EXPOSED"

    candidate = addr.strip()
    if not candidate:
        return "PUBLIC EXPOSED"

    # IPv6 mit eckigen Klammern (z. B. "[::1]" oder "[::1]:8000") — nur den
    # IP-Teil extrahieren, Port-Suffix wegwerfen.
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return "PUBLIC EXPOSED"

    return "LOOPBACK" if ip.is_loopback else "PUBLIC EXPOSED"


__all__ = ["ExposureClass", "classify_exposure"]
