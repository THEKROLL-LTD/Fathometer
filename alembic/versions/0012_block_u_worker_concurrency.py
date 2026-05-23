"""block_u_worker_concurrency - ADR-0029 §"Entscheidung" Punkte 1 + 5.

Zwei neue Spalten auf der Settings-Singleton-Row fuer Block U Phase A:

- ``llm_worker_job_concurrency INT NOT NULL DEFAULT 1`` — globaler Cap fuer
  parallele LLM-Jobs im Worker-Prozess. Default 1 ist backward-compatible
  (Verhalten identisch mit Block P / v0.9.x). Operator regelt manuell in
  ``/settings/llm-reviewer`` hoch.
- ``llm_debug_log_success_sample_rate INT NOT NULL DEFAULT 10`` — Sampling-
  Rate fuer ``llm_debug_log``-Inserts bei ``status='success'``. Errors
  laufen weiterhin 1:1. Phase G nutzt den Wert in
  ``_should_sample_debug_log``.

Zwei CheckConstraints schuetzen die Bounds (analog Pydantic-Field-Bounds in
``app/config.py``):

- ``ck_settings_llm_worker_job_concurrency``: BETWEEN 1 AND 200.
- ``ck_settings_llm_debug_log_success_sample_rate``: BETWEEN 1 AND 1000.

Keine neue Tabelle, keine FK-Ziele, keine Index-Aenderungen.

Revision ID: 0012_block_u_worker
Revises: 0011_app_group_evals
Create Date: 2026-05-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012_block_u_worker"
down_revision: str | None = "0011_app_group_evals"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "settings",
        sa.Column(
            "llm_worker_job_concurrency",
            sa.Integer(),
            nullable=False,
            server_default="1",
        ),
    )
    op.add_column(
        "settings",
        sa.Column(
            "llm_debug_log_success_sample_rate",
            sa.Integer(),
            nullable=False,
            server_default="10",
        ),
    )
    op.create_check_constraint(
        "ck_settings_llm_worker_job_concurrency",
        "settings",
        "llm_worker_job_concurrency BETWEEN 1 AND 200",
    )
    op.create_check_constraint(
        "ck_settings_llm_debug_log_success_sample_rate",
        "settings",
        "llm_debug_log_success_sample_rate BETWEEN 1 AND 1000",
    )


def downgrade() -> None:
    # Reihenfolge umgekehrt: erst Constraints, dann Columns.
    op.drop_constraint(
        "ck_settings_llm_debug_log_success_sample_rate",
        "settings",
        type_="check",
    )
    op.drop_constraint(
        "ck_settings_llm_worker_job_concurrency",
        "settings",
        type_="check",
    )
    op.drop_column("settings", "llm_debug_log_success_sample_rate")
    op.drop_column("settings", "llm_worker_job_concurrency")
