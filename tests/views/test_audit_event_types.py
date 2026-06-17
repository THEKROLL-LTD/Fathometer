"""Block Z, Phase E: die neuen Audit-Event-Typen sind im Filter-Whitelist
(`KNOWN_ACTIONS` in `app/views/audit_view.py`) registriert.

Der Audit-View-Filter verwirft unbekannte `action`-Werte still (Bookmarks
duerfen nicht brechen). Damit die neuen Block-Z-Events `/audit?action=...`-
filterbar sind, muessen sie in `KNOWN_ACTIONS` stehen.
"""

from __future__ import annotations

import pytest

from app.views.audit_view import KNOWN_ACTIONS

_BLOCK_Z_ACTIONS = [
    "group.created",
    "group.renamed",
    "group.deleted",
    "group.moved",
    "tag.renamed",
    "tag.color_changed",
]


@pytest.mark.parametrize("action", _BLOCK_Z_ACTIONS)
def test_block_z_action_in_known_actions(action: str) -> None:
    assert action in KNOWN_ACTIONS, (
        f"Block-Z-Audit-Event {action!r} fehlt in KNOWN_ACTIONS — "
        f"der /audit-Filter wuerde ihn still verwerfen."
    )


# TICKET-018 (visibility): a scan whose envelope fails to validate, or whose
# host_state parse fails, must be filterable in /audit — otherwise a silently
# lost scan is invisible to the operator.
_TICKET_018_ACTIONS = [
    "scan.ingest_failed",
    "host_state.parse_failed",
]


@pytest.mark.parametrize("action", _TICKET_018_ACTIONS)
def test_ticket_018_failure_action_in_known_actions(action: str) -> None:
    assert action in KNOWN_ACTIONS, (
        f"TICKET-018 audit event {action!r} is missing from KNOWN_ACTIONS — "
        f"the /audit filter would silently discard it, hiding a lost scan."
    )
