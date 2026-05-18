# ruff: noqa: S104
# 0.0.0.0 ist als Listener-Addr-Fixture realistisch (sshd-Default), nicht eine
# tatsaechliche Bind-Adresse. Bandit's S104 ist hier ein False-Positive.
"""Block O Phase A (ADR-0022) — Envelope-Schema-Erweiterung um `host_state`
plus `TrivyVulnerability.VendorSeverity`.

Erfuellt DoD Task #3 aus dem Block-O-Brief:

- Vollstaendiger `host_state`-Block parst.
- `host_state = None` → Envelope-Parse erfolgreich.
- Listener mit `port=70000` → ValidationError.
- Process mit `args` Laenge 5000 → ValidationError.
- `tools_available` mit non-ASCII-Item → Item verworfen, andere bleiben.
- 5000 Listener → ValidationError (Pydantic Max-Length-Reject).
- `VendorSeverity` mit 20 Providern → Reject.
- Numerische `VendorSeverity`-Values `{"nvd": 3, "ubuntu": 2}` →
  `{"nvd":"high","ubuntu":"medium"}`.
- Malformed IPv4 (`"999.999.999.999"`) → ValidationError fuer den Listener.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import (
    Envelope,
    HostStateBlock,
    ListenerEntry,
    ProcessEntry,
    TrivyVulnerability,
)

# ---------------------------------------------------------------------------
# Helper
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


def _full_host_state() -> dict[str, Any]:
    return {
        "snapshot_at": "2026-05-18T03:14:22Z",
        "tools_available": ["ss", "ps", "lsmod", "systemctl"],
        "gaps": [],
        "listeners": [
            {
                "proto": "tcp",
                "addr": "0.0.0.0",
                "port": 22,
                "process": "sshd",
                "pid": 1234,
            },
            {
                "proto": "tcp",
                "addr": "127.0.0.1",
                "port": 5432,
                "process": "postgres",
                "pid": 5678,
            },
            {
                "proto": "udp",
                "addr": "0.0.0.0",
                "port": 53,
                "process": "named",
                "pid": 901,
            },
        ],
        "processes": [
            {"pid": 1234, "user": "root", "comm": "sshd", "args": "/usr/sbin/sshd -D"},
            {
                "pid": 5678,
                "user": "postgres",
                "comm": "postgres",
                "args": "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main",
            },
        ],
        "kernel_modules": [
            "ext4",
            "nf_conntrack",
            "xt_conntrack",
            "br_netfilter",
            "overlay",
            "bridge",
        ],
        "services": ["sshd.service", "postgresql.service", "nginx.service"],
    }


# ---------------------------------------------------------------------------
# Top-Level-Envelope mit host_state
# ---------------------------------------------------------------------------


def test_full_host_state_parses() -> None:
    """Vollstaendiger `host_state`-Block parst — alle Felder gesetzt."""
    env = Envelope.model_validate(_minimal_envelope(host_state=_full_host_state()))
    assert env.host_state is not None
    assert len(env.host_state.listeners) == 3
    assert env.host_state.listeners[0].proto == "tcp"
    assert env.host_state.listeners[0].addr == "0.0.0.0"
    assert env.host_state.listeners[0].port == 22
    assert env.host_state.listeners[0].process == "sshd"
    assert len(env.host_state.processes) == 2
    assert env.host_state.processes[0].comm == "sshd"
    assert "ext4" in env.host_state.kernel_modules
    assert "sshd.service" in env.host_state.services
    assert env.host_state.tools_available == ["ss", "ps", "lsmod", "systemctl"]
    assert env.host_state.gaps == []


def test_envelope_without_host_state_parses() -> None:
    """Forward-Compat: Agent 0.2.0 sendet kein `host_state` → Envelope ok."""
    env = Envelope.model_validate(_minimal_envelope())
    assert env.host_state is None


def test_envelope_with_explicit_none_host_state_parses() -> None:
    env = Envelope.model_validate(_minimal_envelope(host_state=None))
    assert env.host_state is None


# ---------------------------------------------------------------------------
# Listener-Validatoren
# ---------------------------------------------------------------------------


def test_listener_port_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        ListenerEntry.model_validate(
            {"proto": "tcp", "addr": "0.0.0.0", "port": 70000, "process": "sshd"}
        )


def test_listener_port_negative_rejected() -> None:
    with pytest.raises(ValidationError):
        ListenerEntry.model_validate(
            {"proto": "tcp", "addr": "0.0.0.0", "port": -1, "process": "sshd"}
        )


def test_listener_invalid_proto_rejected() -> None:
    with pytest.raises(ValidationError):
        ListenerEntry.model_validate(
            {"proto": "icmp", "addr": "0.0.0.0", "port": 22, "process": "sshd"}
        )


def test_listener_malformed_ipv4_rejected() -> None:
    """`"999.999.999.999"` ist kein gueltiges IP-Literal."""
    with pytest.raises(ValidationError):
        ListenerEntry.model_validate({"proto": "tcp", "addr": "999.999.999.999", "port": 22})


def test_listener_ipv6_literal_accepted() -> None:
    entry = ListenerEntry.model_validate(
        {"proto": "tcp6", "addr": "::1", "port": 443, "process": "nginx"}
    )
    assert entry.addr == "::1"


def test_listener_non_ascii_addr_rejected() -> None:
    with pytest.raises(ValidationError):
        ListenerEntry.model_validate({"proto": "tcp", "addr": "0.0.0.ÿ", "port": 22})


def test_listener_nul_in_addr_rejected() -> None:
    with pytest.raises(ValidationError):
        ListenerEntry.model_validate({"proto": "tcp", "addr": "0.0.0.0\x00", "port": 22})


# ---------------------------------------------------------------------------
# Process-Validatoren
# ---------------------------------------------------------------------------


def test_process_args_too_long_rejected() -> None:
    """Process `args` Laenge 5000 > MAX_PROCESS_ARGS_LENGTH (4096) → reject."""
    with pytest.raises(ValidationError):
        ProcessEntry.model_validate(
            {"pid": 1234, "user": "root", "comm": "java", "args": "x" * 5000}
        )


def test_process_args_at_max_length_accepted() -> None:
    """Exakt 4096 Zeichen Args — Grenzfall."""
    entry = ProcessEntry.model_validate(
        {"pid": 1234, "user": "root", "comm": "java", "args": "x" * 4096}
    )
    assert entry.args is not None
    assert len(entry.args) == 4096


def test_process_non_ascii_comm_rejected() -> None:
    with pytest.raises(ValidationError):
        ProcessEntry.model_validate({"pid": 1234, "comm": "sshdé"})


def test_process_nul_in_args_rejected() -> None:
    with pytest.raises(ValidationError):
        ProcessEntry.model_validate({"pid": 1234, "args": "ls\x00 -la"})


def test_process_pid_too_large_rejected() -> None:
    with pytest.raises(ValidationError):
        ProcessEntry.model_validate({"pid": 2**31, "comm": "java"})


# ---------------------------------------------------------------------------
# tools_available / gaps — Filter-Logik (per-Item-Drop)
# ---------------------------------------------------------------------------


def test_tools_available_non_ascii_item_dropped_others_kept() -> None:
    """Non-ASCII-Item verworfen, andere bleiben (Item-Drop, kein Reject)."""
    block = HostStateBlock.model_validate({"tools_available": ["ss", "psé", "lsmod"]})
    assert block.tools_available == ["ss", "lsmod"]


def test_tools_available_nul_item_dropped() -> None:
    block = HostStateBlock.model_validate({"tools_available": ["ss", "lsmod\x00", "systemctl"]})
    assert block.tools_available == ["ss", "systemctl"]


def test_tools_available_capped_at_32_items() -> None:
    items = [f"tool{i}" for i in range(50)]
    block = HostStateBlock.model_validate({"tools_available": items})
    assert len(block.tools_available) == 32


def test_tools_available_too_long_item_dropped() -> None:
    block = HostStateBlock.model_validate({"tools_available": ["ss", "x" * 33, "ps"]})
    assert block.tools_available == ["ss", "ps"]


def test_gaps_non_ascii_filtered() -> None:
    block = HostStateBlock.model_validate({"gaps": ["servicesé", "kernel_modules"]})
    assert block.gaps == ["kernel_modules"]


# ---------------------------------------------------------------------------
# kernel_modules / services Filter
# ---------------------------------------------------------------------------


def test_kernel_modules_non_ascii_dropped() -> None:
    block = HostStateBlock.model_validate({"kernel_modules": ["ext4", "br_éfilter", "overlay"]})
    assert block.kernel_modules == ["ext4", "overlay"]


def test_services_capped_at_1024() -> None:
    items = [f"svc{i}.service" for i in range(2000)]
    block = HostStateBlock.model_validate({"services": items})
    assert len(block.services) == 1024


# ---------------------------------------------------------------------------
# Listeners/Processes — Max-Length-Reject (ganze Liste)
# ---------------------------------------------------------------------------


def test_5000_listeners_rejected() -> None:
    """5000 Eintraege > MAX_LISTENERS=4096 → ValidationError (Pydantic-Default)."""
    listeners = [
        {"proto": "tcp", "addr": "0.0.0.0", "port": 10000 + (i % 5000), "process": "x"}
        for i in range(5000)
    ]
    with pytest.raises(ValidationError):
        HostStateBlock.model_validate({"listeners": listeners})


def test_5000_processes_rejected() -> None:
    processes = [{"pid": i + 1, "comm": "x"} for i in range(5000)]
    with pytest.raises(ValidationError):
        HostStateBlock.model_validate({"processes": processes})


# ---------------------------------------------------------------------------
# VendorSeverity (TrivyVulnerability)
# ---------------------------------------------------------------------------


def test_vendor_severity_string_values_lowercase_normalized() -> None:
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(VendorSeverity={"nvd": "High", "ubuntu": "MEDIUM"})
    )
    assert vuln.vendor_severity == {"nvd": "high", "ubuntu": "medium"}


def test_vendor_severity_integer_values_mapped() -> None:
    """Trivy schreibt numerisch (`3`); wir mappen via Tabelle."""
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(VendorSeverity={"nvd": 3, "ubuntu": 2}))
    assert vuln.vendor_severity == {"nvd": "high", "ubuntu": "medium"}


def test_vendor_severity_integer_unknown_value_to_unknown() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(VendorSeverity={"nvd": 99}))
    assert vuln.vendor_severity == {"nvd": "unknown"}


def test_vendor_severity_too_many_providers_rejected() -> None:
    """20 Provider > MAX_VENDOR_SEVERITY_PROVIDERS (16) → reject."""
    map_20: dict[str, str] = {f"provider{i}": "high" for i in range(20)}
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(VendorSeverity=map_20))


def test_vendor_severity_non_ascii_key_rejected() -> None:
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(VendorSeverity={"ubunté": "high"}))


def test_vendor_severity_nul_in_key_rejected() -> None:
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(VendorSeverity={"nv\x00d": "high"}))


def test_vendor_severity_non_ascii_value_item_dropped() -> None:
    """Non-ASCII im Wert → per-Item-Drop, andere bleiben."""
    vuln = TrivyVulnerability.model_validate(
        _minimal_vuln(VendorSeverity={"nvd": "hiégh", "ubuntu": "high"})
    )
    assert vuln.vendor_severity == {"ubuntu": "high"}


def test_vendor_severity_none_default() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln())
    assert vuln.vendor_severity is None


def test_vendor_severity_empty_dict() -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(VendorSeverity={}))
    assert vuln.vendor_severity == {}
