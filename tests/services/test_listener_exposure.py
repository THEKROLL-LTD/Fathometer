"""Pure-Unit-Tests fuer app/services/listener_exposure.py (Block X Phase C, C10).

Prueft:
  1. Loopback-Klassifizierungen: 127.0.0.0/8, ::1, IPv6-Brackets, IPv4-mapped.
  2. PUBLIC-EXPOSED-Klassifizierungen: 0.0.0.0, ::, externe IPv4/IPv6, RFC1918.
  3. Fail-safe bei ungueltige Eingaben: immer PUBLIC EXPOSED.
  4. Return-Type-Konsistenz: isinstance(str) und genau ein der zwei Literal-Werte.
"""

from __future__ import annotations

import pytest

from app.services.listener_exposure import classify_exposure

# ---------------------------------------------------------------------------
# Test 1 — Loopback-Klassifizierungen
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("127.0.0.1", "LOOPBACK"),
        ("127.0.0.2", "LOOPBACK"),
        ("127.255.255.255", "LOOPBACK"),  # Ende des 127.0.0.0/8-Blocks
        ("127.1.1.1", "LOOPBACK"),
        ("::1", "LOOPBACK"),
        ("[::1]", "LOOPBACK"),  # IPv6 mit Brackets
        ("[::1]:8000", "LOOPBACK"),  # IPv6 + Port
        ("::ffff:127.0.0.1", "LOOPBACK"),  # IPv4-mapped-IPv6 — stdlib-is_loopback bejaht
        ("  127.0.0.1  ", "LOOPBACK"),  # Whitespace wird getrimmt
        ("\t127.0.0.1\n", "LOOPBACK"),  # Tabs + Newline getrimmt
        ("[127.0.0.1]", "LOOPBACK"),  # IPv4 mit Brackets (Jinja-Agent-Edge-Case)
    ],
)
def test_loopback_classifications(addr: str, expected: str) -> None:
    """Alle Loopback-Adressen muessen als 'LOOPBACK' klassifiziert werden."""
    result = classify_exposure(addr)
    assert result == expected, (
        f"classify_exposure({addr!r}) -> {result!r}, erwartet {expected!r}. "
        "127.0.0.0/8 und ::1 sind Loopback per stdlib ip_address.is_loopback."
    )


# ---------------------------------------------------------------------------
# Test 2 — PUBLIC EXPOSED Klassifizierungen
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr,expected",
    [
        ("0.0.0.0", "PUBLIC EXPOSED"),  # noqa: S104
        ("::", "PUBLIC EXPOSED"),
        ("[::]:443", "PUBLIC EXPOSED"),  # Wildcard IPv6 mit Port
        ("8.8.8.8", "PUBLIC EXPOSED"),
        ("1.1.1.1", "PUBLIC EXPOSED"),
        ("10.0.0.1", "PUBLIC EXPOSED"),  # RFC1918 ist NICHT loopback
        ("192.168.1.10", "PUBLIC EXPOSED"),  # RFC1918
        ("172.16.0.1", "PUBLIC EXPOSED"),  # RFC1918
        ("169.254.0.1", "PUBLIC EXPOSED"),  # Link-local IPv4
        ("2001:db8::1", "PUBLIC EXPOSED"),  # IPv6 Documentation
        ("fe80::1", "PUBLIC EXPOSED"),  # Link-local IPv6
        ("100.64.0.1", "PUBLIC EXPOSED"),  # CGNAT-Range
        ("[fe80::1]:9090", "PUBLIC EXPOSED"),  # Link-local IPv6 mit Brackets + Port
    ],
)
def test_public_exposed_classifications(addr: str, expected: str) -> None:
    """Alles ausser Loopback muss als 'PUBLIC EXPOSED' klassifiziert werden.

    RFC1918 (10.x, 192.168.x, 172.16.x) und Link-local sind KEIN Loopback —
    sie koennen von anderen Hosts im Netz erreicht werden.
    """
    result = classify_exposure(addr)
    assert result == expected, (
        f"classify_exposure({addr!r}) -> {result!r}, erwartet {expected!r}. "
        "RFC1918, link-local, wildcard-bindings und externe IPs sind PUBLIC EXPOSED."
    )


# ---------------------------------------------------------------------------
# Test 3 — Fail-safe bei ungueltige Eingaben
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    [
        "",
        "   ",
        "\t",
        "\n",
        "not-an-ip",
        "127.0.0",  # IPv4 unvollstaendig
        "foo.bar",
        "999.999.999.999",  # Out-of-range
        "127.0.0.1 OR 1=1",  # SQL-Injection-Versuch
        "<script>alert(1)</script>",  # XSS-Versuch
        "\x00127.0.0.1",  # NUL-Prefix
        "127.0.0.1\x00",  # NUL-Suffix
        "localhost",  # Hostname, kein IP-Literal
        "::1::1",  # Doppelt-ungueltig
        "256.0.0.1",  # Oktett > 255
        "[",  # Nur oeffnende Bracket
        "[::1",  # Bracket nicht geschlossen
        "127.0.0.1:8080",  # IPv4 mit Port (kein Bracket) — kann nicht geparst werden
        "2001:db8:::1",  # Doppelter Doppelpunkt
    ],
)
def test_invalid_input_fails_safe(addr: str) -> None:
    """Fail-safe: ungueltige Eingaben -> 'PUBLIC EXPOSED'.

    Begruendung ADR-0038 §(3): lieber eine Warn-Pille zu viel als
    versehentlich einen exponierten Listener als Loopback zu maskieren.
    """
    result = classify_exposure(addr)
    assert result == "PUBLIC EXPOSED", (
        f"classify_exposure({addr!r}) -> {result!r}, erwartet 'PUBLIC EXPOSED'. "
        "Ungueltige Eingaben muessen fail-safe auf PUBLIC EXPOSED fallen."
    )


# ---------------------------------------------------------------------------
# Test 4 — Return-Type-Konsistenz
# ---------------------------------------------------------------------------


def test_return_type_is_literal_string() -> None:
    """Return-Typ ist immer str und immer einer der zwei dokumentierten Werte."""
    valid_values = {"LOOPBACK", "PUBLIC EXPOSED"}

    for addr in ("127.0.0.1", "0.0.0.0", "::1", "::", "8.8.8.8", "", "not-an-ip"):  # noqa: S104
        result = classify_exposure(addr)
        assert isinstance(result, str), (
            f"classify_exposure({addr!r}) -> {type(result)}, erwartet str."
        )
        assert result in valid_values, (
            f"classify_exposure({addr!r}) -> {result!r}, erwartet einen der Werte: {valid_values}."
        )
