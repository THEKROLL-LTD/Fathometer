# ruff: noqa: S104
"""Adversarial: ListenerEntry-`addr`-Feld (Block O, ADR-0022 §Host-Snapshot).

Verifiziert die Pydantic-Layer-Validierung von `ListenerEntry.addr`:
ASCII-only via `_PRINTABLE_ASCII_RE`, NUL-frei via `_no_nul_bytes()`, plus
striktes IP-Literal via `ipaddress.ip_address()` (IPv4/IPv6). Reine Schema-
Tests — kein DB-Roundtrip noetig.

Sicherheits-Hintergrund: `addr` landet via `persist_host_state()` in der
`server_listeners`-Tabelle und wird im Server-Detail gerendert. Wenn der
Validator hier lax waere, koennten manipulierte Agents bspw. Cmdlines
oder URL-Fragmente in das Feld schmuggeln (Jinja-Autoescape ist die zweite
Verteidigungslinie — Tests dazu in `test_host_state_xss.py`).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import ListenerEntry

# ---------------------------------------------------------------------------
# Reject-Cases — strukturell ungueltige Adressen muessen ValidationError werfen.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("addr", "expected_substr"),
    [
        # Zu grosse IPv4-Oktette — `ipaddress.ip_address()` lehnt ab.
        ("999.999.999.999", "addr"),
        # NUL-Byte — `_no_nul_bytes()` haut zuerst zu.
        ("0.0.0.0\x00malicious", "addr"),
        # Non-ASCII-Byte — `_PRINTABLE_ASCII_RE` lehnt ab.
        ("0.0.0.0\xff", "addr"),
        # Komplett-Junk.
        ("not-an-ip", "addr"),
        # Leerer String — `ipaddress` lehnt ab und `_PRINTABLE_ASCII_RE` matcht
        # min 1 Char nicht.
        ("", "addr"),
        # IPv4 mit Port-Suffix — keine valide IP-Literal-Form.
        ("127.0.0.1:8080", "addr"),
        # Eckige Klammern um IPv6 (URL-Notation) — `ipaddress` lehnt ab.
        ("[::1]", "addr"),
        # Hostname statt Literal.
        ("localhost", "addr"),
    ],
)
def test_listener_addr_invalid_rejected(addr: str, expected_substr: str) -> None:
    """Validator muss ungueltige `addr`-Werte mit ValidationError ablehnen.

    Wir pruefen nicht die exakte Fehler-Message (Pydantic-Format-Aenderungen
    sind kein semantischer Bruch), aber dass das `addr`-Feld in den errors
    referenziert wird — andernfalls schluesse ein anderer Validator das Item.
    """
    with pytest.raises(ValidationError) as exc_info:
        ListenerEntry(proto="tcp", addr=addr, port=22)

    error_str = str(exc_info.value)
    assert expected_substr in error_str, (
        f"Erwartet '{expected_substr}' im Fehler-Output fuer addr={addr!r}, got: {error_str}"
    )


# ---------------------------------------------------------------------------
# Accept-Cases — valide IP-Literale (IPv4 + IPv6) muessen durchgehen.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [
        "0.0.0.0",
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.255",
        "::1",  # IPv6 loopback
        "::",  # IPv6 unspecified
        "2001:db8::1",  # IPv6 documentation range
        "fe80::1",  # IPv6 link-local ohne Scope
    ],
)
def test_listener_addr_valid_accepted(addr: str) -> None:
    """Standard-Literale (v4/v6) muessen Schema-Pruefung passieren."""
    entry = ListenerEntry(proto="tcp", addr=addr, port=8080)
    assert entry.addr == addr


# ---------------------------------------------------------------------------
# IPv6-Scope-Variation — Python 3.13 akzeptiert `fe80::1%eth0` via
# `ipaddress.ip_address()` (Scope-Suffix). Wir verifizieren den tatsaechlichen
# Validator-Output und dokumentieren ihn als Test-Invariante. ASCII-Validator
# laesst `%` (0x25) und `eth0` durch.
# ---------------------------------------------------------------------------


def test_listener_addr_ipv6_with_scope_accepted() -> None:
    """IPv6 Link-Local mit Scope-Suffix (`fe80::1%eth0`) ist gueltig in
    Python 3.13 — der `ipaddress`-stdlib-Parser akzeptiert das. Damit
    akzeptiert auch der Pydantic-Layer und der String landet unveraendert
    in der `server_listeners.addr`-Spalte (`String(64)`, reicht locker).

    Wenn Python das in Zukunft strikter macht, faellt dieser Test auf und
    der Validator-Code muss explizit eine Policy-Entscheidung treffen.
    """
    entry = ListenerEntry(proto="tcp6", addr="fe80::1%eth0", port=22)
    assert entry.addr == "fe80::1%eth0"


# ---------------------------------------------------------------------------
# Defense-in-depth: NUL-Bytes muessen vor jedem anderen Check fallen
# (Postgres `String` kann sie nicht speichern, und Skript-Engines koennten
# bei `\x00` truncieren). Wir verifizieren das gezielt.
# ---------------------------------------------------------------------------


def test_listener_addr_nul_at_start_rejected() -> None:
    """`\\x00`-Praefix darf nicht akzeptiert werden."""
    with pytest.raises(ValidationError):
        ListenerEntry(proto="tcp", addr="\x000.0.0.0", port=22)


def test_listener_addr_nul_at_end_rejected() -> None:
    """`\\x00`-Suffix darf nicht akzeptiert werden."""
    with pytest.raises(ValidationError):
        ListenerEntry(proto="tcp", addr="0.0.0.0\x00", port=22)
