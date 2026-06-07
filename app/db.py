"""Synchrone SQLAlchemy-Engine und Session-Factory fuer die Web-Schicht.

Flask laeuft im MVP synchron (Gunicorn-Sync-Worker). Async-SQLAlchemy nutzen
wir nur fuer Alembic. Fuer die Request-Handler reicht eine klassische
`scoped_session`-aehnliche Per-Request-Session.

Die Engine wird lazy beim ersten Zugriff erzeugt — Tests koennen die DB
ueberspringen, wenn sie keine echte Connection ziehen.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast

from flask import Flask, g
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

_ENGINE_KEY = "_fathometer_engine"
_SESSION_FACTORY_KEY = "_fathometer_session_factory"


def _to_sync_url(url: str) -> str:
    """Wandelt eine `postgresql+psycopg`-URL fuer Sync-Nutzung um.

    `psycopg` (v3) bietet sowohl Sync- als auch Async-API ueber denselben
    Treiber-String. Wir lassen den String unveraendert — SQLAlchemy waehlt
    automatisch die Sync-Variante, sobald `create_engine` (statt
    `create_async_engine`) benutzt wird.
    """
    return url


def init_engine(app: Flask) -> None:
    """Registriert die Engine an der App.

    Wird in `create_app()` aufgerufen.
    """
    url = _to_sync_url(app.config["FM_DATABASE_URL"])
    engine = create_engine(url, pool_pre_ping=True, future=True)
    app.extensions[_ENGINE_KEY] = engine
    app.extensions[_SESSION_FACTORY_KEY] = sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False
    )


def get_engine(app: Flask) -> Engine:
    """Liefert die Engine der gegebenen App."""
    return cast(Engine, app.extensions[_ENGINE_KEY])


def get_session_factory(app: Flask) -> sessionmaker[Session]:
    """Liefert die Session-Factory der gegebenen App."""
    return cast("sessionmaker[Session]", app.extensions[_SESSION_FACTORY_KEY])


def get_session() -> Session:
    """Liefert die Per-Request-Session.

    Wird beim ersten Aufruf pro Request lazy erzeugt und am Request-Ende
    via `teardown_request`-Hook geschlossen (siehe `app/__init__.py`).
    """
    from flask import current_app

    if "db_session" not in g:
        factory = get_session_factory(current_app._get_current_object())  # type: ignore[attr-defined]
        g.db_session = factory()
    return cast(Session, g.db_session)


def close_session(exception: BaseException | None = None) -> None:
    """`teardown_request`-Handler — schliesst die Session am Request-Ende."""
    session = g.pop("db_session", None)
    if session is not None:
        if exception is not None:
            session.rollback()
        session.close()


@contextmanager
def session_scope(app: Flask) -> Iterator[Session]:
    """Hilfs-Context-Manager fuer Skripte/CLI ausserhalb der Request-Schleife."""
    factory = get_session_factory(app)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


__all__: list[str] = [
    "close_session",
    "get_engine",
    "get_session",
    "get_session_factory",
    "init_engine",
    "session_scope",
]
