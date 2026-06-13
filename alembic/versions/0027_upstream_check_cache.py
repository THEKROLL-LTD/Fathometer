"""upstream_check_cache — ADR-0063 (Block AI, P1+P2).

Zwei Teile in einer Migration:

1. **Settings-Spalten (P1):** sieben neue Spalten auf der Singleton-Row
   ``settings`` fuer die optionale, operator-gated agentische Upstream-Update-
   Suche. Das Feature ist **default OFF** (Air-Gap-first): ``upstream_check_enabled``
   traegt ``server_default false``, alle uebrigen Config-Spalten sind nullable
   (unkonfiguriert = aus). Geteilter LLM-Provider wie Reviewer/Chat, aber
   eigenes Modell (``llm_research_model``). Such-Backend-Secrets
   (``*_api_key_encrypted``/``*_password_encrypted``) sind Fernet-verschluesselt
   — gleiche Pipeline wie ``llm_api_key_encrypted``.

2. **Cache-Tabelle (P2) + Queue-State (P5):** ``upstream_check_results`` haelt
   das gecachte Verdikt pro ``(artifact_module, installed_version)`` (UNIQUE =
   Cache-Key) UND ist zugleich die Job-Queue und der Research-Request: eine Zeile
   pro Artefakt@Version = ein In-Flight-Job = ein Cache-Eintrag (ADR-0063, P5).
   Der ``status`` (``queued``/``running``/``done``/``error``) treibt den
   Research-Worker-Claim (``SELECT … FOR UPDATE SKIP LOCKED``); die
   Seed-Snapshot-Spalten (``cve``/``vulnerable_component``/… ) werden beim
   Enqueue gefuellt, damit der Worker ohne das (evtl. geloeschte) Finding
   auskommt. ``checked_at`` ist der TTL-Anker. Beratend — das Verdikt flippt nie
   automatisch einen ``risk_band``/``fix_lane`` (ADR-0063 §Leitplanken).

   Zusaetzlich: eigene Heartbeat-Spalte ``research_worker_heartbeat_at`` auf der
   Singleton-``settings``-Row (analog ``llm_worker_heartbeat_at``) fuer den
   internen Healthcheck des separaten Research-Worker-Containers.

``downgrade`` kehrt beides vollstaendig um (Tabelle + Spalten droppen). Der
Datenverlust ist offensichtlich und akzeptiert: gecachte Verdikte werden bei
Bedarf neu gesucht, die Feature-Config beim Re-Setup neu gesetzt.

Revision ID: 0027_upstream_check_cache
Revises: 0026_host_update_availability
Create Date: 2026-06-13
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0027_upstream_check_cache"
down_revision: str | None = "0026_host_update_availability"
branch_labels: str | None = None
depends_on: str | None = None

_SETTINGS = "settings"
_CACHE = "upstream_check_results"


def upgrade() -> None:
    # --- P1: settings-Spalten -------------------------------------------
    op.add_column(
        _SETTINGS,
        sa.Column(
            "upstream_check_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        _SETTINGS,
        sa.Column("upstream_search_backend", sa.String(length=16), nullable=True),
    )
    op.add_column(
        _SETTINGS,
        sa.Column("upstream_search_base_url", sa.String(length=512), nullable=True),
    )
    op.add_column(
        _SETTINGS,
        sa.Column("upstream_search_api_key_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        _SETTINGS,
        sa.Column("upstream_search_username", sa.String(length=128), nullable=True),
    )
    op.add_column(
        _SETTINGS,
        sa.Column("upstream_search_password_encrypted", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        _SETTINGS,
        sa.Column("llm_research_model", sa.String(length=128), nullable=True),
    )
    # P5: eigener Heartbeat des Research-Worker-Containers (analog
    # ``llm_worker_heartbeat_at``) — der Research-Healthcheck prueft das Alter.
    op.add_column(
        _SETTINGS,
        sa.Column("research_worker_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- P2 + P5: Cache-Tabelle = Queue + Request + Ergebnis-Cache -------
    op.create_table(
        _CACHE,
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("artifact_module", sa.String(length=512), nullable=False),
        sa.Column("installed_version", sa.String(length=256), nullable=False),
        # --- P5: Queue-State (Job-Lebenszyklus, Claim-getrieben) ---------
        # queued/running/done/error — der Research-Worker claimt 'queued'-Zeilen.
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        # Anzahl Worker-Versuche (Backoff/Max-Attempts-Logik).
        sa.Column(
            "attempts",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        # Pickup-Zeitstempel + Worker-ID (Stale-Reaper-Anker).
        sa.Column("picked_up_at", sa.DateTime(timezone=True), nullable=True),
        # Fruehester naechster Claim-Zeitpunkt (Backoff nach Fehler/Reap).
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("picked_up_by", sa.String(length=128), nullable=True),
        # --- P5: Request/Seed-Snapshot (beim Enqueue gefuellt) -----------
        # Damit der Worker den ResearchSeed ohne das (evtl. geloeschte) Finding
        # rekonstruieren kann. ``fixing_component_version`` ist bereits als
        # Verdict-Spalte vorhanden und wird beim Enqueue mit dem Seed-Wert
        # vorbelegt (nicht doppelt angelegt).
        sa.Column("cve", sa.String(length=128), nullable=True),
        sa.Column("vulnerable_component", sa.String(length=256), nullable=True),
        sa.Column("ecosystem", sa.String(length=64), nullable=True),
        sa.Column("binary_path", sa.String(length=512), nullable=True),
        sa.Column("search_hint", sa.String(length=256), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        # Enqueue-Zeitstempel — Claim-Order (FIFO ORDER BY requested_at).
        sa.Column(
            "requested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("delivery", sa.String(length=32), nullable=True),
        sa.Column("fixing_component_version", sa.String(length=256), nullable=True),
        sa.Column("latest_release_component_version", sa.String(length=256), nullable=True),
        sa.Column("fixed_build_release", sa.String(length=256), nullable=True),
        sa.Column("fixed_build_release_date", sa.String(length=64), nullable=True),
        sa.Column("operator_action", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("sources_used", JSONB(), nullable=True),
        sa.Column("reasoning", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column(
            "checked_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "artifact_module",
            "installed_version",
            name="uq_upstream_check_results_module_version",
        ),
    )
    # P5: Claim-Index auf ``status`` — der Worker scannt nach 'queued'.
    op.create_index("ix_upstream_check_results_status", _CACHE, ["status"])


def downgrade() -> None:
    op.drop_index("ix_upstream_check_results_status", table_name=_CACHE)
    op.drop_table(_CACHE)
    op.drop_column(_SETTINGS, "research_worker_heartbeat_at")
    op.drop_column(_SETTINGS, "llm_research_model")
    op.drop_column(_SETTINGS, "upstream_search_password_encrypted")
    op.drop_column(_SETTINGS, "upstream_search_username")
    op.drop_column(_SETTINGS, "upstream_search_api_key_encrypted")
    op.drop_column(_SETTINGS, "upstream_search_base_url")
    op.drop_column(_SETTINGS, "upstream_search_backend")
    op.drop_column(_SETTINGS, "upstream_check_enabled")
