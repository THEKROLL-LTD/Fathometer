"""Initial-Backfill fuer Group-Risk-Vererbung.

Aufruf:
    python -m app.cli.inherit_group_risk_backfill
"""

from __future__ import annotations

import sys

from app import create_app
from app.db import session_scope
from app.services.finding_group_inheritance import inherit_group_risk_to_findings


def main() -> int:
    """Fuehrt die idempotente Vererbung ueber alle Findings aus."""
    app = create_app()
    with session_scope(app) as session:
        updated = inherit_group_risk_to_findings(session)
    sys.stdout.write(f"Inherited group risk to {updated} findings.\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - operativer Entrypoint
    raise SystemExit(main())
