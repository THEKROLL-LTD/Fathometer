"""Alembic-Migration-Environment fuer fathometer.

Konfiguriert SQLAlchemy 2.x async (psycopg-Treiber). In Block A gibt es noch
keine Models — `target_metadata` ist `None`. Block B fuegt die echten Models
hinzu und setzt `target_metadata = Base.metadata`.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Alembic-Config-Objekt aus alembic.ini.
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Models einbinden — Block B liefert die echte `Base.metadata`.
from app.models import Base

target_metadata = Base.metadata


def _get_url() -> str:
    """Liest die DB-URL aus dem Environment.

    Wir bewusst NICHT `app.config.load_settings()` — Alembic muss auch ohne
    `FM_ENCRYPTION_KEY` lauffaehig sein (z.B. im CI).
    """
    url = os.environ.get("FM_DATABASE_URL")
    if not url:
        url = "postgresql+psycopg://fathometer:fathometer@db:5432/fathometer"
    return url


def run_migrations_offline() -> None:
    """Offline-Migration ohne DB-Connection (SQL-Skript-Erzeugung)."""
    context.configure(
        url=_get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Online-Migration gegen die konfigurierte DB."""
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _get_url()

    connectable = async_engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
