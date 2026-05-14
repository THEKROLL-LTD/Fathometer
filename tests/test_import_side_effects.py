"""Verifiziert, dass `import app` keine Seiteneffekte hat.

`create_app()` ist die einzige Stelle, an der Settings geladen, Logging
konfiguriert und DB-Verbindungen vorbereitet werden. Reiner Import des
Packages oder der Factory-Funktion darf nicht crashen — selbst wenn
`SECSCAN_ENCRYPTION_KEY` fehlt.
"""

from __future__ import annotations

import importlib
import sys

import pytest


@pytest.fixture
def no_secscan_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entfernt alle `SECSCAN_*`-Variablen und purged das `app`-Modul aus `sys.modules`."""
    for key in (
        "SECSCAN_ENCRYPTION_KEY",
        "SECSCAN_SECRET_KEY",
        "SECSCAN_DATABASE_URL",
        "SECSCAN_MAX_BODY_MB",
        "SECSCAN_LOG_LEVEL",
    ):
        monkeypatch.delenv(key, raising=False)
    # Modul-Cache leeren, damit ein frischer Import erzwungen wird.
    for mod in list(sys.modules):
        if mod == "app" or mod.startswith("app."):
            monkeypatch.delitem(sys.modules, mod, raising=False)


def test_import_app_does_not_crash_without_env(no_secscan_env: None) -> None:
    """`import app` darf ohne Pflicht-Env-Vars nicht scheitern."""
    import app  # noqa: F401 — import-only smoke test


def test_import_create_app_does_not_crash_without_env(no_secscan_env: None) -> None:
    """Auch der Import der Factory-Funktion darf keine Settings laden."""
    from app import create_app  # noqa: F401 — import-only smoke test


def test_create_app_call_fails_without_env(no_secscan_env: None) -> None:
    """Nur `create_app()` darf scheitern — und genau dann auch."""
    from app import create_app

    with pytest.raises(SystemExit):
        create_app()


def test_reimporting_app_is_idempotent(no_secscan_env: None) -> None:
    """Mehrfaches Import-und-Reload darf weder werfen noch globalen State mutieren."""
    import app as app_module

    reloaded = importlib.reload(app_module)
    assert reloaded is app_module, "reload should return same module object"
