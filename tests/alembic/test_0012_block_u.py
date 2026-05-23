"""Pure-Unit-Test fuer Migration ``0012_block_u_worker_concurrency`` (Block U Phase A).

Im Gegensatz zu den anderen Tests unter ``tests/alembic/`` (die echte Postgres-
Reflection brauchen und damit ``db_integration``-Marker tragen) verifiziert
dieser Test das Migration-File rein **statisch**: das Modul wird geladen,
``op.add_column`` und ``op.create_check_constraint`` werden gemockt und die
Aufrufe im ``upgrade()``-/``downgrade()``-Codepfad als Spy erfasst.

Hintergrund: ein echter ``alembic upgrade head`` gegen Postgres ist
``db_integration`` und damit auf User-Anweisung (siehe CLAUDE.md §"Test-
Konvention — Default vs. On-Demand"). Eine statische Verifikation reicht aus
um Tippfehler im Spalten-Namen, falsche Default-Werte oder fehlende
CheckConstraints zu fangen — die echte Postgres-Semantik (NOT NULL,
CHECK rejects, Roundtrip) bleibt der ``db_integration``-Suite vorbehalten.

Hinweis: ``tests/alembic/`` ist im ``_ACCEPTANCE_PATH_PREFIXES`` der globalen
``conftest.py``; dieser Test bekommt damit automatisch ``acceptance``- und
``db_integration``-Marker und laeuft NICHT im Default-Pure-Unit-Pytest-Lauf.
Er ist trotzdem pure-unit (kein DB-Zugriff) und kann jederzeit per
``pytest tests/alembic/test_0012_block_u.py -p no:cacheprovider -o addopts=`` direkt
aufgerufen werden — der Default-Selektor exkludiert ihn aus Ordnungs-Gruenden.

Die DoD-A des Blocks verlangt zusaetzlich einen Postgres-Roundtrip — dafuer
muss der User explizit ``pytest -m db_integration`` triggern (z.B. zusammen
mit ``tests/alembic/test_0010_scan_ingest_jobs.py``-Schema-Reflection-Tests).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "0012_block_u_worker_concurrency.py"
)


def _load_migration_module(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, MagicMock]:
    """Laedt das Migration-File mit einem gemockten ``alembic.op``-Namespace.

    Gibt das geladene Modul und das Mock-``op``-Objekt zurueck, damit Tests
    die Spy-Aufrufe inspizieren koennen.
    """
    import alembic

    mock_op = MagicMock()
    # ``alembic.op`` ist ein Proxy auf den aktuell aktiven MigrationContext.
    # In Pure-Unit-Tests existiert keiner — wir patchen den Namespace, damit
    # ``from alembic import op`` im Migration-File unser Mock zurueckliefert.
    monkeypatch.setattr(alembic, "op", mock_op, raising=False)

    # Modul explizit ueber den Filesystem-Pfad laden, damit jeder Test eine
    # frische Modul-Instanz mit dem aktuellen Mock-``op`` bekommt.
    spec = importlib.util.spec_from_file_location("_block_u_migration_under_test", MIGRATION_PATH)
    assert spec is not None and spec.loader is not None, (
        f"Konnte Migration-Spec fuer {MIGRATION_PATH} nicht laden"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, mock_op


# ---------------------------------------------------------------------------
# Header-Konstanten — Revision-IDs muessen exakt stimmen.
# ---------------------------------------------------------------------------


def test_migration_revision_id_is_block_u(monkeypatch: pytest.MonkeyPatch) -> None:
    module, _ = _load_migration_module(monkeypatch)
    assert module.revision == "0012_block_u_worker", f"revision-ID falsch: {module.revision!r}"


def test_migration_down_revision_links_to_block_t(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _ = _load_migration_module(monkeypatch)
    assert module.down_revision == "0011_app_group_evals", (
        f"down_revision falsch: {module.down_revision!r}"
    )


# ---------------------------------------------------------------------------
# upgrade() — beide add_column + beide create_check_constraint.
# ---------------------------------------------------------------------------


def test_upgrade_adds_both_settings_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    module, mock_op = _load_migration_module(monkeypatch)
    module.upgrade()

    # ``op.add_column("settings", sa.Column(...))`` — zwei Calls, Reihenfolge
    # implementation-defined aber beide muessen passieren.
    add_column_calls = mock_op.add_column.call_args_list
    assert len(add_column_calls) == 2, (
        f"Erwartet 2 add_column-Aufrufe, bekommen {len(add_column_calls)}: {add_column_calls}"
    )
    tables = {call.args[0] for call in add_column_calls}
    assert tables == {"settings"}, f"add_column-Tabellen: {tables}"

    # sa.Column-Namen extrahieren — Position 1 ist das Column-Objekt.
    col_names = {call.args[1].name for call in add_column_calls}
    assert col_names == {
        "llm_worker_job_concurrency",
        "llm_debug_log_success_sample_rate",
    }, f"add_column-Spalten-Namen: {col_names}"


def test_upgrade_columns_are_not_null_with_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, mock_op = _load_migration_module(monkeypatch)
    module.upgrade()

    cols_by_name = {call.args[1].name: call.args[1] for call in mock_op.add_column.call_args_list}

    concurrency_col = cols_by_name["llm_worker_job_concurrency"]
    assert concurrency_col.nullable is False, "llm_worker_job_concurrency muss NOT NULL"
    assert str(concurrency_col.server_default.arg) == "1", (
        f"Default-Server-Default fuer llm_worker_job_concurrency: "
        f"{concurrency_col.server_default.arg!r}"
    )

    sample_col = cols_by_name["llm_debug_log_success_sample_rate"]
    assert sample_col.nullable is False, "llm_debug_log_success_sample_rate muss NOT NULL"
    assert str(sample_col.server_default.arg) == "10", (
        f"Default-Server-Default fuer llm_debug_log_success_sample_rate: "
        f"{sample_col.server_default.arg!r}"
    )


def test_upgrade_creates_both_check_constraints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, mock_op = _load_migration_module(monkeypatch)
    module.upgrade()

    cc_calls = mock_op.create_check_constraint.call_args_list
    assert len(cc_calls) == 2, (
        f"Erwartet 2 create_check_constraint-Aufrufe, bekommen {len(cc_calls)}: {cc_calls}"
    )

    by_name: dict[str, dict[str, str]] = {}
    for call in cc_calls:
        # Signatur: op.create_check_constraint(name, table, condition)
        name = call.args[0]
        table = call.args[1]
        condition = call.args[2]
        by_name[name] = {"table": table, "condition": condition}

    assert "ck_settings_llm_worker_job_concurrency" in by_name, by_name
    assert "ck_settings_llm_debug_log_success_sample_rate" in by_name, by_name

    concurrency_cc = by_name["ck_settings_llm_worker_job_concurrency"]
    assert concurrency_cc["table"] == "settings"
    assert "llm_worker_job_concurrency BETWEEN 1 AND 200" in concurrency_cc["condition"]

    sample_cc = by_name["ck_settings_llm_debug_log_success_sample_rate"]
    assert sample_cc["table"] == "settings"
    assert "llm_debug_log_success_sample_rate BETWEEN 1 AND 1000" in sample_cc["condition"]


# ---------------------------------------------------------------------------
# downgrade() — entfernt beide Constraints und beide Spalten.
# ---------------------------------------------------------------------------


def test_downgrade_drops_both_check_constraints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, mock_op = _load_migration_module(monkeypatch)
    module.downgrade()

    drop_cc_calls = mock_op.drop_constraint.call_args_list
    cc_names = {call.args[0] for call in drop_cc_calls}
    assert cc_names == {
        "ck_settings_llm_worker_job_concurrency",
        "ck_settings_llm_debug_log_success_sample_rate",
    }, f"drop_constraint-Namen: {cc_names}"

    # Beide muessen mit type_='check' gedroppt werden, damit Postgres den
    # CHECK-Namespace verwendet.
    for call in drop_cc_calls:
        assert call.kwargs.get("type_") == "check", f"drop_constraint ohne type_='check': {call}"


def test_downgrade_drops_both_columns(monkeypatch: pytest.MonkeyPatch) -> None:
    module, mock_op = _load_migration_module(monkeypatch)
    module.downgrade()

    drop_col_calls = mock_op.drop_column.call_args_list
    assert len(drop_col_calls) == 2, (
        f"Erwartet 2 drop_column-Aufrufe, bekommen {len(drop_col_calls)}: {drop_col_calls}"
    )
    targets = {(call.args[0], call.args[1]) for call in drop_col_calls}
    assert targets == {
        ("settings", "llm_worker_job_concurrency"),
        ("settings", "llm_debug_log_success_sample_rate"),
    }, f"drop_column-Targets: {targets}"
