# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""reviewer_chat_model_split — getrennte LLM-Modelle (ADR-0057, Block AF).

ADR-0057 trennt das bisher geteilte ``settings.llm_model`` in zwei explizit
benannte Modell-Felder auf der Singleton-``settings``-Row — bei *einem*
geteilten Provider (``llm_base_url``/``llm_api_key_encrypted`` bleiben
unveraendert):

* ``llm_reviewer_model`` — Modell des Risk-Reviewers (Block-P-Worker,
  Pass 1 + Pass 2). Reines Rename von ``llm_model``; behaelt die alte
  ``NULL``-Semantik (System ohne Provider hat hier ``NULL``).
* ``llm_chat_model`` — Modell des Per-Group-Chats (Block AE). NEU, ``NOT NULL``
  mit **permanentem** ``server_default`` ``'deepseek-ai/DeepSeek-V4-Flash'``.
  Das ``ADD COLUMN NOT NULL DEFAULT`` backfillt bestehende Zeilen automatisch
  mit dem Default (kein separates ``UPDATE`` noetig); der ``server_default``
  bleibt auf der Spalte (er schuetzt auch frische ``ensure_settings_row``-
  Inserts, die kein Modell seeden).

``downgrade()`` droppt ``llm_chat_model`` (Daten-Verlust akzeptiert — vorher
gab es das Feld nicht) und benennt ``llm_reviewer_model`` zurueck nach
``llm_model``.

Revision ID: 0024_reviewer_chat_model_split
Revises: 0023_block_ae_group_chat
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0024_reviewer_chat_model_split"
down_revision: str | None = "0023_block_ae_group_chat"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.alter_column("settings", "llm_model", new_column_name="llm_reviewer_model")
    op.add_column(
        "settings",
        sa.Column(
            "llm_chat_model",
            sa.String(128),
            nullable=False,
            server_default="deepseek-ai/DeepSeek-V4-Flash",
        ),
    )


def downgrade() -> None:
    op.drop_column("settings", "llm_chat_model")
    op.alter_column("settings", "llm_reviewer_model", new_column_name="llm_model")
