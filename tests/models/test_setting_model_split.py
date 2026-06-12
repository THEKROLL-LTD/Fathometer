"""Pure-Unit-Regression: ``Setting`` fuehrt die getrennten Modell-Felder.

Block AF / ADR-0057. Introspektiert ausschliesslich die ORM-Metadata (kein
DB-Fixture, kein Postgres) — liegt unter ``tests/models/`` und ist deshalb in
``tests/conftest.py::_PURE_UNIT_OVERRIDES`` als Pure-Unit-Ausnahme gefuehrt
(sonst wuerde die Prefix-Heuristik es faelschlich als db_integration markieren).

Belegt:
- ``llm_reviewer_model`` + ``llm_chat_model`` existieren als Spalten.
- Das alte ``llm_model`` ist **nicht** mehr Teil von ``Setting`` (Rename, kein
  additives Feld).
- ``llm_reviewer_model`` ist nullable; ``llm_chat_model`` ist NOT NULL mit
  permanentem ``server_default``.
"""

from __future__ import annotations

from app.models import Setting


def _column(name: str) -> object | None:
    return Setting.__table__.columns.get(name)


def test_setting_has_both_model_columns() -> None:
    assert _column("llm_reviewer_model") is not None, "llm_reviewer_model fehlt"
    assert _column("llm_chat_model") is not None, "llm_chat_model fehlt"


def test_setting_has_no_legacy_llm_model_column() -> None:
    """Das ehemalige ``llm_model`` wurde umbenannt, nicht additiv behalten."""
    assert _column("llm_model") is None, (
        "Setting.llm_model existiert noch — ADR-0057 verlangt Rename auf llm_reviewer_model."
    )


def test_reviewer_model_is_nullable() -> None:
    col = Setting.__table__.columns["llm_reviewer_model"]
    assert col.nullable is True, "llm_reviewer_model soll nullable bleiben (System ohne Provider)."


def test_chat_model_is_not_null_with_server_default() -> None:
    col = Setting.__table__.columns["llm_chat_model"]
    assert col.nullable is False, "llm_chat_model muss NOT NULL sein (ADR-0057 §Entscheidung 1)."
    assert col.server_default is not None, "llm_chat_model braucht permanenten server_default."
    default_sql = str(col.server_default.arg)  # type: ignore[union-attr]
    assert "DeepSeek-V4-Flash" in default_sql, default_sql
