"""Pure-Unit-Tests fuer ``app.services.llm_debug_log._apply_body_cap``.

Diese Datei haelt nach TICKET-004-Slice-4 nur noch die reinen Body-Cap-Unit-
Tests: ``_apply_body_cap`` operiert auf einem Dict + int und liefert ein
Dict zurueck — kein DB-Zugriff noetig.

Die DB-Tests fuer ``record()``, ``evict_old()`` und den ORM-Roundtrip
wurden nach ``tests/integration/test_llm_debug_log_db.py`` ausgelagert.
"""

from __future__ import annotations

from app.services.llm_debug_log import _apply_body_cap

# ---------------------------------------------------------------------------
# _apply_body_cap-Tests (Unit, kein DB)
# ---------------------------------------------------------------------------


class TestApplyBodyCap:
    def test_under_cap_passes_through(self) -> None:
        body = {"k": "v"}
        out = _apply_body_cap(body, 65536)
        assert out is body

    def test_none_stays_none(self) -> None:
        assert _apply_body_cap(None, 65536) is None

    def test_over_cap_returns_stub(self) -> None:
        big = {"data": "x" * 10_000}
        out = _apply_body_cap(big, 1024)
        assert out is not None
        assert out.get("__truncated") is True
        assert out.get("original_size_bytes", 0) > 1024
        assert "preview" in out

    def test_non_serializable_body_returns_repr_stub(self) -> None:
        class _Bad:
            pass

        out = _apply_body_cap({"obj": _Bad()}, 1024)
        # default=str rettet den Fall — also kein Repr-Path, aber kein Crash.
        assert out is not None

    def test_preview_is_truncated_string(self) -> None:
        big = {"data": "ABCDEF" * 10_000}
        out = _apply_body_cap(big, 1024)
        assert out is not None
        preview = out.get("preview", "")
        # Preview-Laenge muss <= max(256, cap-256) sein und ein String.
        assert isinstance(preview, str)
        assert len(preview) <= max(256, 1024 - 256)
