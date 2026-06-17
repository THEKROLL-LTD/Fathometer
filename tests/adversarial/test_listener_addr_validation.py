# ruff: noqa: S104
"""Adversarial: ListenerEntry-`addr` field (Block O, ADR-0022 §Host-Snapshot).

Verifies the Pydantic-layer validation of `ListenerEntry.addr`: ASCII-only via
`_PRINTABLE_ASCII_RE`, NUL-free via `_no_nul_bytes()`, plus strict IP-literal
validation via `ipaddress.ip_address()` (IPv4/IPv6). Pure schema tests — no DB
roundtrip needed.

TICKET-018: `_validate_addr` now NORMALIZES before validating. Agents in the
field send bracketed and/or zone-suffixed IPv6 literals (`[fe80::1]%tun0`, the
link-local VPN interface). The stdlib `ipaddress.ip_address()` rejects the
bracket form, so the validator strips a surrounding `[ ]` pair and a trailing
`%zone` suffix and stores the bare literal. Two prior reject cases are
intentionally flipped to accept-after-normalization (see the parametrize lists).

Security background: `addr` lands via `persist_host_state()` in the
`server_listeners` table and is rendered on the server-detail page. If this
validator were lax, manipulated agents could smuggle cmdlines or URL fragments
into the field (Jinja autoescape is the second line of defense — tests for that
live in `test_host_state_xss.py`).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import ListenerEntry

# ---------------------------------------------------------------------------
# Reject-Cases — structurally invalid addresses must raise ValidationError.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("addr", "expected_substr"),
    [
        # Oversized IPv4 octets — `ipaddress.ip_address()` rejects.
        ("999.999.999.999", "addr"),
        # NUL byte — `_no_nul_bytes()` strips/normalizes first; remainder is junk.
        ("0.0.0.0\x00malicious", "addr"),
        # Non-ASCII byte — `_PRINTABLE_ASCII_RE` rejects.
        ("0.0.0.0\xff", "addr"),
        # Total junk.
        ("not-an-ip", "addr"),
        # Empty string — `ipaddress` rejects and `_PRINTABLE_ASCII_RE` requires
        # at least one char.
        ("", "addr"),
        # IPv4 with port suffix — not a valid IP literal form.
        ("127.0.0.1:8080", "addr"),
        # Hostname instead of a literal.
        ("localhost", "addr"),
        # Genuine garbage in all-caps — not normalizable to any literal.
        ("TOTAL-GARBAGE", "addr"),
        # Bracketed non-IP — strips to `notanip`, still not a literal.
        ("[notanip]", "addr"),
    ],
)
def test_listener_addr_invalid_rejected(addr: str, expected_substr: str) -> None:
    """The validator must reject invalid `addr` values with a ValidationError.

    We do not check the exact error message (Pydantic format changes are not a
    semantic break), only that the `addr` field is referenced in the errors —
    otherwise a different validator dropped the item.
    """
    with pytest.raises(ValidationError) as exc_info:
        ListenerEntry(proto="tcp", addr=addr, port=22)

    error_str = str(exc_info.value)
    assert expected_substr in error_str, (
        f"Expected '{expected_substr}' in error output for addr={addr!r}, got: {error_str}"
    )


# ---------------------------------------------------------------------------
# Accept-Cases — valid IP literals (IPv4 + IPv6) must pass through unchanged.
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
        "fe80::1",  # IPv6 link-local without scope
    ],
)
def test_listener_addr_valid_accepted(addr: str) -> None:
    """Standard literals (v4/v6) without brackets/zone pass and store verbatim."""
    entry = ListenerEntry(proto="tcp", addr=addr, port=8080)
    assert entry.addr == addr


# ---------------------------------------------------------------------------
# Accept-after-normalization (TICKET-018) — bracketed and/or zoned IPv6 literals
# are normalized to the bare literal and stored normalized. The STORED value
# must be the bare literal (brackets and `%zone` removed).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_addr", "stored_addr"),
    [
        # The exact gitlab02 break case: `[fe80::…]%tun0` (brackets + zone).
        ("[fe80::53a0:796a:5d2:96c1]%tun0", "fe80::53a0:796a:5d2:96c1"),
        # FLIPPED from the prior reject list (was `("[::1]", "addr")`): bracketed
        # loopback now normalizes and is accepted.
        ("[::1]", "::1"),
        # Zone inside the brackets.
        ("[fe80::1%tun0]", "fe80::1"),
        # Bracketed unspecified.
        ("[::]", "::"),
        # Bare zone-suffixed link-local (Python 3.13 accepts the bare form, but
        # the validator still normalizes the zone away for a stable stored form).
        ("fe80::1%eth0", "fe80::1"),
        # Bracketed without zone.
        ("[fe80::1]", "fe80::1"),
        # Bracketed full IPv6.
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_listener_addr_normalized_and_accepted(raw_addr: str, stored_addr: str) -> None:
    """Bracketed/zoned IPv6 literals normalize to the bare literal and store it."""
    entry = ListenerEntry(proto="tcp6", addr=raw_addr, port=22)
    assert entry.addr == stored_addr, (
        f"addr={raw_addr!r} should normalize to {stored_addr!r}, got {entry.addr!r}"
    )


# ---------------------------------------------------------------------------
# IPv6 scope variation (TICKET-018 behavior flip) — previously this stored the
# raw `fe80::1%eth0`; the normalizing validator now strips the zone and stores
# the bare `fe80::1`. Kept as an explicit named test to document the flip.
# ---------------------------------------------------------------------------


def test_listener_addr_ipv6_with_scope_accepted() -> None:
    """IPv6 link-local with a scope suffix (`fe80::1%eth0`) is accepted.

    TICKET-018: the normalizing validator strips the `%eth0` zone and stores the
    bare literal `fe80::1` (was the raw string before the ticket). Zone info is
    not retained — link-local addresses are never publicly exposed, so the
    exposure classifier is unaffected.
    """
    entry = ListenerEntry(proto="tcp6", addr="fe80::1%eth0", port=22)
    assert entry.addr == "fe80::1"


# ---------------------------------------------------------------------------
# Defense-in-depth: NUL bytes must fall before any other check (Postgres
# `String` cannot store them, and script engines may truncate on `\x00`).
# ---------------------------------------------------------------------------


def test_listener_addr_nul_at_start_rejected() -> None:
    """A `\\x00` prefix must not be accepted."""
    with pytest.raises(ValidationError):
        ListenerEntry(proto="tcp", addr="\x000.0.0.0", port=22)


def test_listener_addr_nul_at_end_rejected() -> None:
    """A `\\x00` suffix must not be accepted."""
    with pytest.raises(ValidationError):
        ListenerEntry(proto="tcp", addr="0.0.0.0\x00", port=22)
