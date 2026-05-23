"""Pure-Unit-Tests fuer den `_inject_version`-Context-Processor.

Block W Phase B.

Prueft:
- Valides Semver (z.B. "v0.12.0") wird unveraendert durchgereicht.
- Fehlendes SECSCAN_VERSION-Env-Var -> "dev" Default.
- Shell-Injection-Versuch ("$(rm -rf /)") -> "dev" Fallback.
- Leerer String -> "dev".
- Zu langer Wert (> 64 Zeichen) -> "dev".

Pattern:
  `_SECSCAN_VERSION_RE` und die innere `_validated`-Funktion sind nicht
  direkt importierbar (sie ist lokal in `_inject_version` definiert).
  Stattdessen rufen wir den Context-Processor ueber `app.jinja_env.globals`
  und `render_template_string` auf, oder wir testen die Regex-Logik
  indirekt ueber den tatsaechlichen Context-Processor.

  Konkreter Ansatz:
    1. Flask-App mit Test-Request-Context erstellen.
    2. Im Jinja-Kontext ist `_inject_version` als Context-Processor
       registriert — bei `render_template_string("{{ secscan_version }}")`
       wird er aufgerufen.
    3. monkeypatch.setenv / delenv steuert den Env-State.
"""

from __future__ import annotations

import pytest
from flask import Flask

# ---------------------------------------------------------------------------
# Hilfsfunktion: Context-Processor direkt ausfuehren
# ---------------------------------------------------------------------------


def _run_inject_version(app: Flask) -> dict[str, str]:
    """Fuehrt alle registrierten Context-Processors aus und gibt den kombinierten
    dict zurueck. Filtert auf Keys die mit 'secscan' beginnen."""
    with app.test_request_context("/"):
        # Flask ruft Context-Processors automatisch beim Render auf.
        # Wir koennen sie auch direkt aus app.template_context_processors holen.
        result: dict[str, str] = {}
        for func in app.template_context_processors.get(None, []):
            ctx = func()
            for k, v in ctx.items():
                if k.startswith("secscan"):
                    result[k] = v
        return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_inject_version_valid_semver(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SECSCAN_VERSION='v0.12.0' -> secscan_version == 'v0.12.0'."""
    monkeypatch.setenv("SECSCAN_VERSION", "v0.12.0")
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "v0.12.0", (
        f"Valides Semver soll unveraendert durchgereicht werden, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_dev_default(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fehlendes SECSCAN_VERSION-Env-Var -> secscan_version == 'dev'."""
    monkeypatch.delenv("SECSCAN_VERSION", raising=False)
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "dev", (
        f"Fehlendes Env-Var soll 'dev' liefern, aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_invalid_shell_injection(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shell-Injection-Versuch '$(rm -rf /)' -> secscan_version == 'dev'."""
    monkeypatch.setenv("SECSCAN_VERSION", "$(rm -rf /)")
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "dev", (
        f"Invalides Env-Var (Shell-Injection) soll auf 'dev' fallen, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_empty_string(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leerer SECSCAN_VERSION-Wert -> secscan_version == 'dev'."""
    monkeypatch.setenv("SECSCAN_VERSION", "")
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "dev", (
        f"Leerer Env-Var-Wert soll auf 'dev' fallen, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_too_long(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """65-Zeichen-Wert (> max 64) -> secscan_version == 'dev'."""
    monkeypatch.setenv("SECSCAN_VERSION", "a" * 65)
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "dev", (
        f"Zu langer Env-Var-Wert (65 Zeichen) soll auf 'dev' fallen, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_exactly_64_chars_valid(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Genau 64 Zeichen (Grenzwert) mit gueltigem Charset -> bleibt unveraendert."""
    value = "a" * 64
    monkeypatch.setenv("SECSCAN_VERSION", value)
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == value, (
        f"Exakt 64 Zeichen sollen als valide gelten, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_with_xss_tag(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTML/Script-Injection '\"<script>alert(1)</script>' -> secscan_version == 'dev'."""
    monkeypatch.setenv("SECSCAN_VERSION", '"<script>alert(1)</script>')
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "dev", (
        f"XSS-Versuch soll auf 'dev' fallen, aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_build_hash_valid(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Commit-Hash-Format (alphanumerisch, nur erlaubte Zeichen) -> unveraendert."""
    monkeypatch.setenv("SECSCAN_VERSION", "abc123def456")
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "abc123def456", (
        f"Alphanumerischer Commit-Hash soll unveraendert bleiben, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_with_dots_and_dashes(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Version mit Punkten und Bindestrichen -> unveraendert (Charset OK)."""
    monkeypatch.setenv("SECSCAN_VERSION", "v1.2.3-rc.1")
    ctx = _run_inject_version(app)
    assert ctx["secscan_version"] == "v1.2.3-rc.1", (
        f"Version mit erlaubten Sonderzeichen soll unveraendert bleiben, "
        f"aber secscan_version={ctx['secscan_version']!r}"
    )


def test_inject_version_build_revision_also_present(
    app: Flask,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Context-Processor liefert auch secscan_build_revision."""
    monkeypatch.setenv("SECSCAN_VERSION", "v0.12.0")
    monkeypatch.setenv("SECSCAN_BUILD_REVISION", "abc1234")
    ctx = _run_inject_version(app)
    assert "secscan_build_revision" in ctx, (
        "secscan_build_revision muss im Context-Processor-Dict vorhanden sein"
    )
    assert ctx["secscan_build_revision"] == "abc1234", (
        f"Valide Build-Revision soll unveraendert sein, "
        f"aber secscan_build_revision={ctx['secscan_build_revision']!r}"
    )
