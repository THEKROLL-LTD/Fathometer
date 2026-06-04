"""Pure-Unit-Tests fuer `app.schemas.bulk_request` (Pydantic, kein DB-Touch).

Deckt die drei Flavors A (`finding_ids`), B (`match`) und C (`server_scope`,
ADR-0044 / TICKET-009 Etappe 1) ab — XOR-Validierung, Band-Whitelist,
`server_id`-Positiv-Constraint und die Comment-Helper.

Diese Datei ist bewusst DB-frei: sie ruft ausschliesslich
`BulkAckRequest.model_validate(...)` bzw. `BulkAckServerScope(...)` auf.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.bulk_request import (
    BULK_ACK_BANDS,
    BulkAckRequest,
    BulkAckServerScope,
)

# ---------------------------------------------------------------------------
# Flavor C — BulkAckServerScope-Modell direkt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("band", ["escalate", "act", "mitigate", "monitor", "noise"])
def test_server_scope_accepts_each_allowed_band(band: str) -> None:
    """Jeder der fuenf Whitelist-Bands validiert sauber (DoD 2, Test 1)."""
    scope = BulkAckServerScope(server_id=42, risk_band=band)  # type: ignore[arg-type]
    assert scope.server_id == 42
    assert scope.risk_band == band


def test_bulk_ack_bands_constant_is_single_source() -> None:
    """`BULK_ACK_BANDS` deckt sich exakt mit der Literal-Whitelist."""
    assert BULK_ACK_BANDS == ("escalate", "act", "mitigate", "monitor", "noise")


@pytest.mark.parametrize("bad_band", ["pending", "unknown", "", "NOISE", "Noise", "  noise"])
def test_server_scope_rejects_non_whitelist_band(bad_band: str) -> None:
    """`pending`/`unknown`/leer/falsche Schreibweise scheitern an Pydantic.

    Insbesondere `"NOISE"` ist case-sensitiv und muss raus (Test 2).
    """
    with pytest.raises(ValidationError) as exc:
        BulkAckServerScope(server_id=1, risk_band=bad_band)  # type: ignore[arg-type]
    locs = {".".join(str(p) for p in e["loc"]) for e in exc.value.errors()}
    assert "risk_band" in locs, exc.value.errors()


@pytest.mark.parametrize("bad_id", [0, -1, -9999])
def test_server_scope_rejects_non_positive_server_id(bad_id: int) -> None:
    """`server_id=0`/negativ -> ValidationError (Test 3)."""
    with pytest.raises(ValidationError):
        BulkAckServerScope(server_id=bad_id, risk_band="noise")


def test_server_scope_extra_fields_ignored() -> None:
    """`extra="ignore"` -> ein zusaetzliches Feld kippt die Validierung nicht."""
    scope = BulkAckServerScope.model_validate({"server_id": 7, "risk_band": "act", "injected": "x"})
    assert scope.server_id == 7
    assert not hasattr(scope, "injected")


# ---------------------------------------------------------------------------
# Flavor C — eingebettet im BulkAckRequest
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("band", ["escalate", "act", "mitigate", "monitor", "noise"])
def test_request_with_server_scope_validates(band: str) -> None:
    req = BulkAckRequest.model_validate(
        {"server_scope": {"server_id": 5, "risk_band": band}, "dry_run": True}
    )
    assert req.server_scope is not None
    assert req.server_scope.server_id == 5
    assert req.server_scope.risk_band == band
    assert req.finding_ids is None
    assert req.match is None


@pytest.mark.parametrize("bad_band", ["pending", "unknown", "", "NOISE"])
def test_request_with_pending_band_raises(bad_band: str) -> None:
    """`risk_band="pending"` (und Geschwister) -> ValidationError (Test 2)."""
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate({"server_scope": {"server_id": 1, "risk_band": bad_band}})


def test_request_with_zero_server_id_raises() -> None:
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate({"server_scope": {"server_id": 0, "risk_band": "noise"}})


def test_request_dry_run_defaults_to_true() -> None:
    """`dry_run` ist Pflicht-Default `True` — Apply muss explizit `false`."""
    req = BulkAckRequest.model_validate({"server_scope": {"server_id": 9, "risk_band": "monitor"}})
    assert req.dry_run is True


# ---------------------------------------------------------------------------
# XOR — genau einer der drei Flavors
# ---------------------------------------------------------------------------


def test_xor_server_scope_plus_finding_ids_raises() -> None:
    """Flavor C + Flavor A im selben Body -> ValidationError (Test 4)."""
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate(
            {
                "server_scope": {"server_id": 1, "risk_band": "noise"},
                "finding_ids": [1, 2, 3],
            }
        )


def test_xor_server_scope_plus_match_raises() -> None:
    """Flavor C + Flavor B im selben Body -> ValidationError (Test 4)."""
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate(
            {
                "server_scope": {"server_id": 1, "risk_band": "noise"},
                "match": {"cve_id": "CVE-2024-12345"},
            }
        )


def test_xor_all_three_flavors_raises() -> None:
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate(
            {
                "server_scope": {"server_id": 1, "risk_band": "noise"},
                "match": {"cve_id": "CVE-2024-12345"},
                "finding_ids": [1],
            }
        )


def test_xor_none_of_three_raises() -> None:
    """Kein Flavor gesetzt -> ValidationError (Test 4)."""
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate({"dry_run": True})


# ---------------------------------------------------------------------------
# Regression Flavor A / B — bestehende XOR-Pfade unveraendert
# ---------------------------------------------------------------------------


def test_flavor_a_finding_ids_validates() -> None:
    req = BulkAckRequest.model_validate({"finding_ids": [1, 2, 3], "dry_run": True})
    assert req.finding_ids == [1, 2, 3]
    assert req.server_scope is None


def test_flavor_a_rejects_non_positive_id() -> None:
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate({"finding_ids": [1, 0, 3]})


def test_flavor_b_match_validates() -> None:
    req = BulkAckRequest.model_validate({"match": {"cve_id": "CVE-2024-12345"}})
    assert req.match is not None
    assert req.match.cve_id == "CVE-2024-12345"
    assert req.server_scope is None


def test_flavor_b_match_requires_cve_or_package() -> None:
    with pytest.raises(ValidationError):
        BulkAckRequest.model_validate({"match": {"status": "open"}})


# ---------------------------------------------------------------------------
# Comment-Helper
# ---------------------------------------------------------------------------


def test_clean_comment_strips_and_detects() -> None:
    req = BulkAckRequest.model_validate(
        {"server_scope": {"server_id": 1, "risk_band": "noise"}, "comment": "  hallo  "}
    )
    assert req.has_comment is True
    assert req.clean_comment() == "hallo"


def test_blank_comment_is_no_comment() -> None:
    req = BulkAckRequest.model_validate(
        {"server_scope": {"server_id": 1, "risk_band": "noise"}, "comment": "   "}
    )
    assert req.has_comment is False
    assert req.clean_comment() is None


def test_missing_comment_is_no_comment() -> None:
    """ADR-0006: Kommentar ist NIE Pflicht — der Ohne-Kommentar-Pfad gilt."""
    req = BulkAckRequest.model_validate({"server_scope": {"server_id": 1, "risk_band": "noise"}})
    assert req.has_comment is False
    assert req.clean_comment() is None
