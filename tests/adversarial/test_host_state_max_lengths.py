"""Adversarial: Pydantic-Bounds des `HostStateBlock` (Block O, ADR-0022).

Verifiziert die Max-Length-Bounds aus `app/schemas/scan_envelope.py`:

  * Listeners:        `MAX_LISTENERS = 4096`        -> hard reject (Field max_length).
  * Processes:        `MAX_PROCESSES = 4096`        -> hard reject (Field max_length).
  * KernelModules:    `MAX_KERNEL_MODULES = 1024`   -> soft cap im `mode="before"`-Validator.
  * Services:         `MAX_SERVICES = 1024`         -> soft cap im `mode="before"`-Validator.
  * Tools/Gaps:       `MAX_TOOLS_GAPS_ITEMS = 32`   -> soft cap im `mode="before"`-Validator.

Hintergrund: `listeners` und `processes` sind typisierte Sub-Modelle
(`ListenerEntry`, `ProcessEntry`) mit `Field(..., max_length=...)` am Field
-> Pydantic feuert einen harten `ValidationError` bei Ueberschreitung.
Die String-Listen (`kernel_modules`, `services`, `tools_available`, `gaps`)
laufen durch den `_filter_ascii_strings()`-Helper mit `mode="before"` und
werden silent auf das Cap-Maximum getrimmt — das ist defensiver weil
einzelne Junk-Items per-Item geworfen werden ohne den ganzen Snapshot
zu killen.

Sicherheits-Aspekt: ValidationError-Output darf keine sensiblen Infos
leaken (z.B. den ganzen 10000-Eintrag-Listener-Block in der Message).
Wir pruefen das defensiv als Hinweis.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import (
    MAX_KERNEL_MODULES,
    MAX_LISTENERS,
    MAX_SERVICES,
    MAX_TOOLS_GAPS_ITEMS,
    HostStateBlock,
)

# ---------------------------------------------------------------------------
# Hard-Reject-Cases: typisierte Sub-Modell-Listen mit `Field(max_length=...)`
# ---------------------------------------------------------------------------


def test_10000_listeners_rejected_with_validation_error() -> None:
    """10000 Listener-Eintraege ueberschreiten `MAX_LISTENERS=4096` -> ValidationError.

    Die Liste selbst (`list[ListenerEntry]`) hat ein hartes Field-`max_length`,
    daher feuert Pydantic den Reject auf Container-Ebene VOR der Item-
    Validation. Selbst syntaktisch valide Listener werden so nicht ingested
    wenn das Volumen den Cap sprengt.
    """
    many = [{"proto": "tcp", "addr": "127.0.0.1", "port": 22} for _ in range(10_000)]
    with pytest.raises(ValidationError) as exc_info:
        HostStateBlock(listeners=many)

    err = exc_info.value
    err_str = str(err)
    # Feld `listeners` muss im Fehler genannt sein.
    assert "listeners" in err_str
    # Hinweis-Check (kein hartes Assert): Fehler-Output sollte nicht den ganzen
    # 10000-Eintrag-Dump enthalten. Pydantic v2 ist typischerweise kompakt,
    # wir bestaetigen das defensiv.
    assert len(err_str) < 50_000, (
        f"ValidationError-Output ist auffaellig gross ({len(err_str)} Bytes) — "
        "moeglicherweise wird die ganze Listener-Liste in die Message gedumped."
    )


def test_10000_processes_rejected_with_validation_error() -> None:
    """10000 Process-Eintraege ueberschreiten `MAX_PROCESSES=4096` -> ValidationError."""
    many = [{"pid": i + 1, "user": "root", "comm": "x", "args": "x"} for i in range(10_000)]
    with pytest.raises(ValidationError) as exc_info:
        HostStateBlock(processes=many)

    assert "processes" in str(exc_info.value)


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


def test_listeners_one_over_max_rejected() -> None:
    """`MAX_LISTENERS + 1` Eintraege -> ValidationError."""
    listeners = [
        {"proto": "tcp", "addr": "127.0.0.1", "port": 80} for _ in range(MAX_LISTENERS + 1)
    ]
    with pytest.raises(ValidationError):
        HostStateBlock(listeners=listeners)
