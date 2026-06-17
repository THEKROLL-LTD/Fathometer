# ruff: noqa: S104
# 0.0.0.0 as a listener-addr fixture is realistic (sshd default), not an actual
# bind address. Bandit's S104 is a false positive here.
"""TICKET-018 — host_state is advisory/best-effort: a single malformed listener
or process entry must drop only itself, never fail the whole envelope.

Before TICKET-018, `Envelope.host_state.listeners: list[ListenerEntry]` was
validated monolithically, so one invalid `ListenerEntry.addr` (e.g. a bracketed
link-local VPN literal) aggregated into a `ValidationError` over the entire
envelope and discarded ALL vulnerability findings — the product's whole purpose.

These pure-unit tests assert the `mode="before"` per-item leniency on
`HostStateBlock.listeners`/`processes` (the `_filter_entries` helper):
- a malformed entry is dropped, the valid ones are retained;
- a full `Envelope.model_validate` with a bad listener AND vulnerability findings
  still parses, vulns survive, the bad listener is gone;
- an over-long list is silently truncated to the cap (`MAX_LISTENERS`/
  `MAX_PROCESSES`) before per-item validation — the DoS fast-fail guard added by
  the security fix: `_filter_entries` slices the raw list to `cap` BEFORE running
  per-item `model_validate`, bounding the work to O(cap) regardless of how huge
  the attacker-supplied array is. An over-long list is therefore capped, not
  rejected, even when every entry is garbage.
"""

from __future__ import annotations

from typing import Any

from app.schemas.scan_envelope import (
    MAX_LISTENERS,
    MAX_PROCESSES,
    Envelope,
    HostStateBlock,
)

# ---------------------------------------------------------------------------
# Helpers — minimal valid envelope / vuln dicts (no invented Trivy fields).
# Mirrors the shapes in tests/schemas/test_host_state_envelope.py.
# ---------------------------------------------------------------------------


def _minimal_envelope(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "agent_version": "0.3.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15",
            "architecture": "x86_64",
        },
        "scan": {"SchemaVersion": 2, "Results": []},
    }
    base.update(overrides)
    return base


def _minimal_vuln(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "VulnerabilityID": "CVE-2024-12345",
        "PkgName": "openssl",
        "Severity": "HIGH",
    }
    base.update(overrides)
    return base


def _scan_with_one_vuln() -> dict[str, Any]:
    """A Trivy scan block carrying exactly one os-pkg vulnerability finding."""
    return {
        "SchemaVersion": 2,
        "ArtifactName": "testserver",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "ubuntu 22.04",
                "Class": "os-pkgs",
                "Type": "ubuntu",
                "Vulnerabilities": [_minimal_vuln()],
            }
        ],
    }


# ---------------------------------------------------------------------------
# Listener leniency — one bad entry dropped, valid ones (incl. bracketed/zoned)
# retained.
# ---------------------------------------------------------------------------


def test_listeners_bad_entry_dropped_valid_retained() -> None:
    """One malformed listener (garbage addr) is dropped; the rest survive."""
    block = HostStateBlock.model_validate(
        {
            "listeners": [
                {"proto": "tcp", "addr": "TOTAL-GARBAGE", "port": 22, "process": "x"},
                {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"},
                # A bracketed + zoned link-local literal — must survive AND
                # normalize (this is the original gitlab02 break case).
                {
                    "proto": "tcp6",
                    "addr": "[fe80::53a0:796a:5d2:96c1]%tun0",
                    "port": 22,
                    "process": "sshd",
                },
            ]
        }
    )
    addrs = [li.addr for li in block.listeners]
    assert addrs == ["0.0.0.0", "fe80::53a0:796a:5d2:96c1"], addrs
    assert "TOTAL-GARBAGE" not in addrs


def test_listeners_missing_port_entry_dropped() -> None:
    """A listener with no `port` (required field) is dropped, not a hard fail."""
    block = HostStateBlock.model_validate(
        {
            "listeners": [
                {"proto": "tcp", "addr": "0.0.0.0", "process": "broken"},  # no port
                {"proto": "tcp", "addr": "127.0.0.1", "port": 5432, "process": "postgres"},
            ]
        }
    )
    assert len(block.listeners) == 1
    assert block.listeners[0].addr == "127.0.0.1"
    assert block.listeners[0].port == 5432


def test_listeners_all_bad_yields_empty_list() -> None:
    """If every listener is malformed, the block still constructs with []."""
    block = HostStateBlock.model_validate(
        {
            "listeners": [
                {"proto": "tcp", "addr": "not-an-ip", "port": 22},
                {"proto": "icmp", "addr": "0.0.0.0", "port": 22},  # bad proto
            ]
        }
    )
    assert block.listeners == []


# ---------------------------------------------------------------------------
# Process leniency — invalid pid dropped, valid one kept.
# ---------------------------------------------------------------------------


def test_processes_bad_entry_dropped_valid_retained() -> None:
    """A process with an out-of-range pid is dropped; pid=1 is kept."""
    block = HostStateBlock.model_validate(
        {
            "processes": [
                {"pid": -5, "comm": "broken"},  # pid < 0 -> invalid
                {"pid": 1, "user": "root", "comm": "systemd", "args": "/sbin/init"},
            ]
        }
    )
    assert len(block.processes) == 1
    assert block.processes[0].pid == 1
    assert block.processes[0].comm == "systemd"


def test_processes_non_ascii_comm_entry_dropped() -> None:
    """A process whose comm is non-ASCII is dropped item-by-item."""
    block = HostStateBlock.model_validate(
        {
            "processes": [
                {"pid": 10, "comm": "sshdé"},  # non-ASCII -> invalid entry
                {"pid": 20, "comm": "sshd"},
            ]
        }
    )
    assert [p.pid for p in block.processes] == [20]


# ---------------------------------------------------------------------------
# Full envelope regression — the core TICKET-018 fix: a bad listener must NOT
# discard the vulnerability findings.
# ---------------------------------------------------------------------------


def test_envelope_with_bad_listener_keeps_vulns() -> None:
    """A bad listener no longer discards the whole scan: vulns survive."""
    host_state = {
        "tools_available": ["ss", "ps"],
        "gaps": [],
        "listeners": [
            # The exact reported break case — bracketed + zoned link-local.
            {"proto": "tcp6", "addr": "[fe80::53a0:796a:5d2:96c1]%tun0", "port": 22},
            {"proto": "tcp", "addr": "TOTAL-GARBAGE", "port": 22},  # genuinely bad
            {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "process": "sshd"},
        ],
        "processes": [],
        "kernel_modules": [],
        "services": [],
    }
    env = Envelope.model_validate(
        _minimal_envelope(scan=_scan_with_one_vuln(), host_state=host_state)
    )

    # Vulnerability findings — the product's purpose — must survive. The schema
    # exposes the Trivy aliases under snake_case Python attribute names.
    results = env.scan.results
    assert len(results) == 1
    vulns = results[0].vulnerabilities
    assert vulns is not None
    assert len(vulns) == 1
    assert vulns[0].vulnerability_id == "CVE-2024-12345"

    # The genuinely-bad listener is dropped; the valid + normalized ones remain.
    assert env.host_state is not None
    addrs = [li.addr for li in env.host_state.listeners]
    assert "TOTAL-GARBAGE" not in addrs
    assert "fe80::53a0:796a:5d2:96c1" in addrs
    assert "0.0.0.0" in addrs
    assert len(addrs) == 2


# ---------------------------------------------------------------------------
# DoS fast-fail guard — the raw list is sliced to the cap (`items[:cap]`) BEFORE
# any per-item validation runs, so an over-long list of VALID entries is now
# silently TRUNCATED to the cap, not rejected. This bounds the validation work
# to O(cap) regardless of attacker-supplied list size.
# ---------------------------------------------------------------------------


def test_over_long_listeners_list_truncated_to_cap() -> None:
    """An over-long list of valid listeners is truncated to MAX_LISTENERS."""
    listeners = [
        {"proto": "tcp", "addr": "0.0.0.0", "port": 10000 + (i % 5000), "process": "x"}
        for i in range(MAX_LISTENERS + 50)
    ]
    block = HostStateBlock.model_validate({"listeners": listeners})
    assert len(block.listeners) == MAX_LISTENERS, len(block.listeners)


def test_over_long_processes_list_truncated_to_cap() -> None:
    """An over-long list of valid processes is truncated to MAX_PROCESSES."""
    processes = [{"pid": i + 1, "comm": "x"} for i in range(MAX_PROCESSES + 50)]
    block = HostStateBlock.model_validate({"processes": processes})
    assert len(block.processes) == MAX_PROCESSES, len(block.processes)


# ---------------------------------------------------------------------------
# DoS-bound regression — the reason for the security fix. A raw list far larger
# than the cap, with EVERY entry invalid, must validate WITHOUT raising and
# yield a bounded result: the slice-to-cap-before-validate guard means at most
# `cap` items are ever validated (here 0 survive, since all are garbage), so the
# work never scales with the attacker-supplied list length.
# ---------------------------------------------------------------------------


def test_huge_invalid_listeners_list_bounded_no_raise() -> None:
    """A huge all-invalid listeners list validates to a bounded (empty) result."""
    listeners = [{"addr": "TOTAL-GARBAGE"} for _ in range(MAX_LISTENERS * 100)]
    block = HostStateBlock.model_validate({"listeners": listeners})
    # Every entry is invalid (no proto/port, bad addr) -> all dropped item-by-item.
    assert len(block.listeners) <= MAX_LISTENERS, len(block.listeners)
    assert block.listeners == []


def test_huge_invalid_processes_list_bounded_no_raise() -> None:
    """A huge all-invalid processes list validates to a bounded (empty) result."""
    processes = [{"pid": -1} for _ in range(MAX_PROCESSES * 100)]
    block = HostStateBlock.model_validate({"processes": processes})
    # pid < 0 is invalid for every entry -> all dropped item-by-item.
    assert len(block.processes) <= MAX_PROCESSES, len(block.processes)
    assert block.processes == []
