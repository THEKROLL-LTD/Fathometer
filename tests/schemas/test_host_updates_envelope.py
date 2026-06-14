# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Block AH/AL (ADR-0062/0066) — Envelope `host_updates` + `HostUpdateEntry`.

Pure-Unit-Tests fuer das Pydantic-Modell und das optionale
`Envelope.host_updates`-Feld. Deckt:

- Gueltiger Eintrag parst (alle Felder).
- `path` UND `pkg_name` sind beide optional (ADR-0066: os-pkgs joinen ueber
  `pkg_name`, lang-pkgs ueber `path`); ein Eintrag setzt genau einen Key.
- `update_available` ist Pflicht-bool.
- `owning_package`/`available_version` sind optional (None ok).
- NUL-Byte in `path`/`pkg_name`/`owning_package` -> Reject.
- non-ASCII in `pkg_name`/`owning_package` -> Reject.
- `> MAX_HOST_UPDATES` Eintraege -> Reject (Pydantic max_length).
- Envelope ohne `host_updates` bleibt gueltig (Default None, alter Agent).
- Unbekannte Extra-Keys im Entry werden ignoriert (extra="ignore").

Kein DB-Roundtrip — reine Pydantic-Validierung.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import (
    MAX_HOST_UPDATES,
    Envelope,
    HostUpdateEntry,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _minimal_envelope(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "agent_version": "0.4.0",
        "host": {
            "os_family": "rocky",
            "os_version": "9.3",
            "os_pretty_name": "Rocky Linux 9.3",
            "kernel_version": "5.14.0",
            "architecture": "x86_64",
        },
        "scan": {"SchemaVersion": 2, "Results": []},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# HostUpdateEntry — Happy-Path und Pflichtfelder
# ---------------------------------------------------------------------------


def test_host_update_entry_full_parses() -> None:
    entry = HostUpdateEntry.model_validate(
        {
            "path": "/usr/bin/tailscaled",
            "owning_package": "tailscale",
            "available_version": "1.78.1-1",
            "update_available": True,
        }
    )
    assert entry.path == "/usr/bin/tailscaled"
    assert entry.owning_package == "tailscale"
    assert entry.available_version == "1.78.1-1"
    assert entry.update_available is True


def test_host_update_entry_pkg_name_variant_parses() -> None:
    """ADR-0066: os-pkgs-Eintrag mit `pkg_name`-Join-Key statt `path`."""
    entry = HostUpdateEntry.model_validate(
        {
            "pkg_name": "kernel",
            "owning_package": "kernel",
            "available_version": "5.14.0-687.12.1.el9_8",
            "update_available": False,
        }
    )
    assert entry.pkg_name == "kernel"
    assert entry.path is None
    assert entry.owning_package == "kernel"
    assert entry.update_available is False


def test_host_update_entry_path_and_pkg_name_both_optional() -> None:
    """ADR-0066: weder `path` noch `pkg_name` ist Pflicht — ein Eintrag ohne
    beide parst (degeneriert, aber kein Hard-Reject); nur `update_available`
    ist Pflicht. Der Ingest-Join ignoriert solche Eintraege schlicht."""
    entry = HostUpdateEntry.model_validate({"update_available": False})
    assert entry.path is None
    assert entry.pkg_name is None


def test_host_update_entry_nul_byte_in_pkg_name_rejected() -> None:
    with pytest.raises(ValidationError):
        HostUpdateEntry.model_validate({"pkg_name": "ker\x00nel", "update_available": True})


def test_host_update_entry_non_ascii_pkg_name_rejected() -> None:
    with pytest.raises(ValidationError):
        HostUpdateEntry.model_validate({"pkg_name": "kärnel", "update_available": True})


def test_host_update_entry_update_available_required() -> None:
    with pytest.raises(ValidationError) as exc:
        HostUpdateEntry.model_validate({"path": "/usr/bin/foo"})
    assert "update_available" in str(exc.value), exc.value


def test_host_update_entry_optional_fields_default_none() -> None:
    entry = HostUpdateEntry.model_validate({"path": "/usr/bin/foo", "update_available": False})
    assert entry.owning_package is None
    assert entry.available_version is None
    assert entry.update_available is False


def test_host_update_entry_empty_optional_strings_become_none() -> None:
    """Leere Strings in den ASCII-Optionalfeldern werden auf None normalisiert
    (gleiche Konvention wie die uebrigen ASCII-Validatoren im Schema)."""
    entry = HostUpdateEntry.model_validate(
        {
            "path": "/usr/bin/foo",
            "owning_package": "",
            "available_version": "",
            "update_available": True,
        }
    )
    assert entry.owning_package is None
    assert entry.available_version is None


def test_host_update_entry_ignores_unknown_keys() -> None:
    """extra="ignore": unbekannte Keys aus einer neueren Agent-Version werden
    stillschweigend verworfen, der Entry parst trotzdem."""
    entry = HostUpdateEntry.model_validate(
        {
            "path": "/usr/bin/foo",
            "update_available": True,
            "repo_id": "baseos",  # neues Feld einer zukuenftigen Agent-Version
            "Unknown": {"nested": 1},
        }
    )
    assert entry.path == "/usr/bin/foo"
    assert not hasattr(entry, "repo_id")


# ---------------------------------------------------------------------------
# Adversarial: NUL-Byte / non-ASCII
# ---------------------------------------------------------------------------


def test_host_update_entry_nul_byte_in_path_rejected() -> None:
    with pytest.raises(ValidationError):
        HostUpdateEntry.model_validate({"path": "/usr/bin/foo\x00bar", "update_available": True})


def test_host_update_entry_nul_byte_in_owning_package_rejected() -> None:
    with pytest.raises(ValidationError):
        HostUpdateEntry.model_validate(
            {
                "path": "/usr/bin/foo",
                "owning_package": "tail\x00scale",
                "update_available": True,
            }
        )


@pytest.mark.parametrize(
    "field",
    [
        pytest.param("owning_package", id="owning_package"),
        pytest.param("available_version", id="available_version"),
    ],
)
def test_host_update_entry_non_ascii_optional_field_rejected(field: str) -> None:
    payload: dict[str, Any] = {"path": "/usr/bin/foo", "update_available": True}
    payload[field] = "täilscale"  # non-ASCII Umlaut
    with pytest.raises(ValidationError) as exc:
        HostUpdateEntry.model_validate(payload)
    assert field in str(exc.value) or "ASCII" in str(exc.value), exc.value


def test_host_update_entry_path_over_max_length_rejected() -> None:
    with pytest.raises(ValidationError):
        HostUpdateEntry.model_validate(
            {"path": "/x" * 300, "update_available": True}  # > 512 Zeichen
        )


# ---------------------------------------------------------------------------
# Envelope.host_updates — optionales Feld + Bounds
# ---------------------------------------------------------------------------


def test_envelope_without_host_updates_is_valid() -> None:
    """Alter Agent sendet kein `host_updates` -> Default None, Envelope parst."""
    env = Envelope.model_validate(_minimal_envelope())
    assert env.host_updates is None


def test_envelope_with_host_updates_list_parses() -> None:
    env = Envelope.model_validate(
        _minimal_envelope(
            host_updates=[
                {
                    "path": "/usr/bin/tailscaled",
                    "owning_package": "tailscale",
                    "available_version": "1.78.1-1",
                    "update_available": True,
                },
                {"path": "/usr/bin/curl", "update_available": False},
            ]
        )
    )
    assert env.host_updates is not None
    assert len(env.host_updates) == 2
    assert env.host_updates[0].update_available is True
    assert env.host_updates[1].update_available is False
    assert env.host_updates[1].owning_package is None


def test_envelope_with_mixed_path_and_pkg_name_entries_parses() -> None:
    """ADR-0066: ein Scan enthaelt beide Eintrags-Formen nebeneinander —
    lang-pkgs ueber `path`, os-pkgs ueber `pkg_name`."""
    env = Envelope.model_validate(
        _minimal_envelope(
            host_updates=[
                {"path": "/usr/bin/tailscaled", "update_available": True},
                {"pkg_name": "kernel", "update_available": False},
            ]
        )
    )
    assert env.host_updates is not None
    assert env.host_updates[0].path == "/usr/bin/tailscaled"
    assert env.host_updates[0].pkg_name is None
    assert env.host_updates[1].pkg_name == "kernel"
    assert env.host_updates[1].path is None


def test_envelope_host_updates_empty_list_ok() -> None:
    env = Envelope.model_validate(_minimal_envelope(host_updates=[]))
    assert env.host_updates == []


def test_envelope_host_updates_over_max_rejected() -> None:
    """Mehr als MAX_HOST_UPDATES Eintraege -> Pydantic max_length-Reject."""
    too_many = [
        {"path": f"/usr/bin/p{i}", "update_available": False} for i in range(MAX_HOST_UPDATES + 1)
    ]
    with pytest.raises(ValidationError):
        Envelope.model_validate(_minimal_envelope(host_updates=too_many))


def test_envelope_host_updates_at_max_ok() -> None:
    """Genau MAX_HOST_UPDATES Eintraege duerfen noch durch (Boundary)."""
    exactly = [
        {"path": f"/usr/bin/p{i}", "update_available": False} for i in range(MAX_HOST_UPDATES)
    ]
    env = Envelope.model_validate(_minimal_envelope(host_updates=exactly))
    assert env.host_updates is not None
    assert len(env.host_updates) == MAX_HOST_UPDATES
