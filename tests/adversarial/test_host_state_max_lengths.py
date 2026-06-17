"""Adversarial: Pydantic-Bounds des `HostStateBlock` (Block O, ADR-0022).

Verifies the max-length bounds in `app/schemas/scan_envelope.py`:

  * Listeners:        `MAX_LISTENERS = 4096`        -> silent truncate (slice-to-cap before validate).
  * Processes:        `MAX_PROCESSES = 4096`        -> silent truncate (slice-to-cap before validate).
  * KernelModules:    `MAX_KERNEL_MODULES = 1024`   -> soft cap in the `mode="before"` validator.
  * Services:         `MAX_SERVICES = 1024`         -> soft cap in the `mode="before"` validator.
  * Tools/Gaps:       `MAX_TOOLS_GAPS_ITEMS = 32`   -> soft cap in the `mode="before"` validator.

Background: `listeners` and `processes` are typed sub-models (`ListenerEntry`,
`ProcessEntry`) carrying per-item leniency (TICKET-018). The security fix for
TICKET-018 slices the raw list to the cap (`items[:cap]`) in the `mode="before"`
`_filter_entries` validator BEFORE per-item validation — bounding the work to
O(cap) regardless of attacker-supplied list size. Consequence: an over-long
`listeners`/`processes` list is now SILENTLY TRUNCATED to the cap, not rejected
with a `ValidationError`. The string lists (`kernel_modules`, `services`,
`tools_available`, `gaps`) run through the `_filter_ascii_strings()` helper with
`mode="before"` and are likewise silently trimmed to the cap maximum.
"""

from __future__ import annotations

from app.schemas.scan_envelope import (
    MAX_KERNEL_MODULES,
    MAX_LISTENERS,
    MAX_PROCESSES,
    MAX_SERVICES,
    MAX_TOOLS_GAPS_ITEMS,
    HostStateBlock,
)

# ---------------------------------------------------------------------------
# Silent-truncate cases: typed sub-model lists are sliced to the cap BEFORE
# per-item validation (TICKET-018 DoS fast-fail guard) -> an over-long list is
# truncated to the cap, not rejected.
# ---------------------------------------------------------------------------


def test_10000_listeners_truncated_to_cap() -> None:
    """10000 listener entries exceed `MAX_LISTENERS=4096` -> truncated to the cap.

    The `mode="before"` `_filter_entries` validator slices the raw list to
    `MAX_LISTENERS` before validating any item, so even syntactically valid
    listeners beyond the cap are silently dropped (best-effort), bounding the
    validation work to O(cap).
    """
    many = [{"proto": "tcp", "addr": "127.0.0.1", "port": 22} for _ in range(10_000)]
    block = HostStateBlock(listeners=many)
    assert len(block.listeners) == MAX_LISTENERS, len(block.listeners)


def test_10000_processes_truncated_to_cap() -> None:
    """10000 process entries exceed `MAX_PROCESSES=4096` -> truncated to the cap."""
    many = [{"pid": i + 1, "user": "root", "comm": "x", "args": "x"} for i in range(10_000)]
    block = HostStateBlock(processes=many)
    assert len(block.processes) == MAX_PROCESSES, len(block.processes)


# ---------------------------------------------------------------------------
# Defensive-Soft-Caps: String-Listen mit `mode="before"`-Filter.
# Diese werden NICHT mit ValidationError abgelehnt — sie capen still auf den
# Maximalwert. Garantie: Memory-/DB-Bound-Sicherheit ohne den ganzen Snapshot
# wegen einzelnem Volume-Spike zu killen.
# ---------------------------------------------------------------------------


def test_2000_kernel_modules_capped_at_max() -> None:
    """2000 Kernel-Module werden silent auf `MAX_KERNEL_MODULES=1024` getrimmt."""
    many = [f"mod_{i}" for i in range(2000)]
    block = HostStateBlock(kernel_modules=many)
    assert len(block.kernel_modules) == MAX_KERNEL_MODULES
    # Die ersten 1024 ueberleben (FIFO-Trim im Helper).
    assert block.kernel_modules[0] == "mod_0"
    assert block.kernel_modules[-1] == f"mod_{MAX_KERNEL_MODULES - 1}"


def test_2000_services_capped_at_max() -> None:
    """2000 Services werden silent auf `MAX_SERVICES=1024` getrimmt."""
    many = [f"svc_{i}.service" for i in range(2000)]
    block = HostStateBlock(services=many)
    assert len(block.services) == MAX_SERVICES
    assert block.services[0] == "svc_0.service"
    assert block.services[-1] == f"svc_{MAX_SERVICES - 1}.service"


def test_100_tools_available_capped_at_32() -> None:
    """100 `tools_available`-Strings werden silent auf `MAX_TOOLS_GAPS_ITEMS=32` getrimmt.

    Dokumentiertes Verhalten: `_filter_ascii_strings()` im
    `field_validator(..., mode="before")` trimmt FIFO. Damit gibt es keinen
    422-Reject — der Snapshot wird ingested, aber nur die ersten 32 Tools
    sind sichtbar.
    """
    many = [f"tool{i}" for i in range(100)]
    block = HostStateBlock(tools_available=many)
    assert len(block.tools_available) == MAX_TOOLS_GAPS_ITEMS
    assert block.tools_available[0] == "tool0"
    assert block.tools_available[-1] == f"tool{MAX_TOOLS_GAPS_ITEMS - 1}"


def test_100_gaps_capped_at_32() -> None:
    """Analog `gaps`: silent-Trim auf 32 Eintraege."""
    many = [f"gap_{i}" for i in range(100)]
    block = HostStateBlock(gaps=many)
    assert len(block.gaps) == MAX_TOOLS_GAPS_ITEMS


# ---------------------------------------------------------------------------
# Soft-Cap-Edge-Cases: ueberlange Items werden per-Item gedroppt, nicht
# silent truncated. Das ist eine andere Sicherheits-Eigenschaft als das
# Listen-Cap und sollte separat verifiziert sein.
# ---------------------------------------------------------------------------


def test_kernel_module_oversized_item_dropped() -> None:
    """Ein einzelnes Modul mit Length > 64 Chars wird per-Item gedroppt.

    Garantie: kein silent-Truncate, der zu kollidierenden Modul-Namen
    fuehren wuerde (z.B. zwei Module die beide bei Zeichen 64 trunciert
    werden und dann identische PKs erzeugen).
    """
    block = HostStateBlock(kernel_modules=["valid_mod", "x" * 65, "another_valid"])
    assert "valid_mod" in block.kernel_modules
    assert "another_valid" in block.kernel_modules
    assert len(block.kernel_modules) == 2  # Oversized-Item gedroppt


def test_service_oversized_item_dropped() -> None:
    """Ein einzelner Service-Name > 128 Chars wird gedroppt."""
    block = HostStateBlock(services=["good.service", "x" * 129, "also.good"])
    assert "good.service" in block.services
    assert "also.good" in block.services
    assert len(block.services) == 2


# ---------------------------------------------------------------------------
# Exakt-am-Bound-Cases: genau MAX-Wert akzeptiert, MAX+1 abgelehnt/gecappt.
# Wichtig damit Off-By-One-Bugs in zukuenftigen Refactors auffallen.
# ---------------------------------------------------------------------------


def test_listeners_at_exact_max_accepted() -> None:
    """Genau `MAX_LISTENERS` Eintraege werden akzeptiert (Off-By-One-Guard)."""
    listeners = [{"proto": "tcp", "addr": "127.0.0.1", "port": 80} for _ in range(MAX_LISTENERS)]
    block = HostStateBlock(listeners=listeners)
    assert len(block.listeners) == MAX_LISTENERS


def test_listeners_one_over_max_truncated() -> None:
    """`MAX_LISTENERS + 1` entries -> truncated to exactly `MAX_LISTENERS`.

    Off-by-one guard for the slice-to-cap truncation: one entry over the cap is
    silently dropped, the result is exactly `MAX_LISTENERS`.
    """
    listeners = [
        {"proto": "tcp", "addr": "127.0.0.1", "port": 80} for _ in range(MAX_LISTENERS + 1)
    ]
    block = HostStateBlock(listeners=listeners)
    assert len(block.listeners) == MAX_LISTENERS, len(block.listeners)
