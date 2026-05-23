"""DEPRECATED — Block W Addendum 2026-05-23.

Diese Test-Datei deckte die Tailwind-CDN-JIT-Safelist in `base_app.html`
ab (TD-010). Mit der Phase-2-Vorziehung (ADR-0032 Addendum, Tailwind +
DaisyUI komplett aus dem Dual-Stack entfernt) ist die Safelist
ersatzlos weg — der esbuild-Build scannt nichts JIT-mässig, und
`legacy-shim.css` deckt die noch-Tailwind-klassigen Templates statisch
ab.

TD-010 ist mit dem Addendum erledigt. Diese Datei kann beim naechsten
Repo-Cleanup geloescht werden — bis dahin sind alle Tests hier
skipped (kein Coverage-Loch, weil die getesteten Invarianten nicht
mehr existieren).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.skip(
    reason=(
        "Tailwind-Safelist mit Block W Addendum entfernt (ADR-0032 Phase 2). "
        "Test-Datei wird beim naechsten Repo-Cleanup geloescht."
    )
)


def test_deprecated_placeholder() -> None:
    """Platzhalter — wird durch pytestmark skipped."""
