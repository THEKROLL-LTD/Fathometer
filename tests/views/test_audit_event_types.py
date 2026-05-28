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
