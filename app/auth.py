# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Authentifizierung und Key-Hashing.

Drei verschiedene Geheimnis-Typen mit unterschiedlichen Hash-Strategien:

- **User-Passwoerter**: niedriger Entropie, brute-force-anfaellig — Argon2id.
- **Master-Key**: 256-bit hochentropisch, aber selten benutzt — SHA-256 mit
  `hmac.compare_digest` reicht (siehe ARCHITECTURE.md §8 und CLAUDE.md).
- **Server-Keys**: ebenfalls 256-bit hochentropisch — SHA-256 (im Modul
  `app/security.py` bzw. spaeter im Scan-Ingest aus Block C).

Flask-Login-Integration: `LoginManager` mit `User`-Loader, der die DB
befragt. Der UserMixin-Wrapper liegt in dieser Datei, damit kein zusaetzlicher
ORM-Mapping-Klimbim noetig ist.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from functools import lru_cache
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit, urlunsplit

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, make_response, redirect, request, url_for
from flask_login import LoginManager, UserMixin
from sqlalchemy import select

from app.db import get_session
from app.models import User as UserModel

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

    from app.config import Settings

log = structlog.get_logger(__name__)

# Login-Manager wird in `create_app()` an die App gebunden.
login_manager: LoginManager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.session_protection = "strong"


def safe_next(raw: str | None) -> str | None:
    """Reduziert ein `next`-Ziel auf einen lokalen, relativen Pfad.

    Schutz gegen Open-Redirect: ein vom Client kontrollierter Wert (Query-Param
    `next` oder HTMX-Header `HX-Current-URL`) darf niemals zu einem fremden Host
    fuehren. Wir verwerfen Scheme und Netloc und behalten nur `path?query` —
    absolute oder protokoll-relative URLs (`//evil.example`) werden so entschaerft.

    Gibt `None` zurueck, wenn nichts Brauchbares uebrig bleibt (Caller faellt dann
    auf sein Default-Ziel zurueck).
    """
    if not raw:
        return None
    parts = urlsplit(raw)
    # Nur Pfad + Query behalten; Scheme/Netloc/Fragment wegwerfen.
    path = parts.path or "/"
    # Ein Pfad MUSS mit genau einem "/" beginnen — sonst koennte `urlsplit`
    # bei Eingaben wie "/\evil.example" oder Backslash-Tricks etwas Fremdes
    # durchlassen. Wir normalisieren auf single-leading-slash.
    if not path.startswith("/") or path.startswith("//"):
        return None
    cleaned = urlunsplit(("", "", path, parts.query, ""))
    return cleaned or None


@login_manager.unauthorized_handler
def _unauthorized() -> WerkzeugResponse:
    """Auth-Expiry-Handling fuer Browser- UND HTMX-Requests.

    Default-Flask-Login liefert einen 302 auf die Login-View. Ein HTMX-XHR folgt
    dem 302 transparent und swappt die Login-Seite ins Partial-Target — das
    eingebettete Login-Formular sieht der Operator dann mitten im Layout.

    Stattdessen: bei `HX-Request` einen leeren 204 mit `HX-Redirect`-Header.
    HTMX macht daraufhin einen harten Voll-Seiten-Wechsel auf `/login`. Als
    `next` nehmen wir `HX-Current-URL` (die echte Seite im Browser), nicht den
    Partial-Endpoint.
    """
    if request.headers.get("HX-Request"):
        target = safe_next(request.headers.get("HX-Current-URL"))
        login_url = url_for("auth.login", next=target) if target else url_for("auth.login")
        resp = make_response("", 204)
        resp.headers["HX-Redirect"] = login_url
        return resp
    target = safe_next(request.full_path)
    return redirect(url_for("auth.login", next=target) if target else url_for("auth.login"))


class AuthUser(UserMixin):
    """Flask-Login-View des ORM-`User`.

    Bewusst eine eigene Klasse statt `UserMixin` direkt am ORM-Model — wir
    wollen keine Session-Lifetime der ORM-Instanz an die Flask-Session koppeln.
    """

    def __init__(self, *, id: int, username: str) -> None:
        self.id = id
        self.username = username

    def get_id(self) -> str:
        return str(self.id)


@lru_cache(maxsize=1)
def _hasher_for(time_cost: int, memory_cost: int, parallelism: int) -> PasswordHasher:
    """Cached Argon2-PasswordHasher mit den konfigurierten Cost-Parametern."""
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )


def _settings_from_app() -> Settings:
    from flask import current_app

    return cast("Settings", current_app.config["FM_SETTINGS"])


def _get_hasher() -> PasswordHasher:
    s = _settings_from_app()
    return _hasher_for(s.argon2_time_cost, s.argon2_memory_cost, s.argon2_parallelism)


# ---------------------------------------------------------------------------
# Passwort-Hashing (Argon2id) — fuer Admin-Account.
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hashed ein Klartext-Passwort mit Argon2id.

    Bewusst keine Validierungs-Logik hier — das ist Aufgabe der Forms.
    """
    return _get_hasher().hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verifiziert ein Passwort gegen den gespeicherten Argon2-Hash.

    `argon2.PasswordHasher.verify` wirft bei Mismatch; wir fangen das und
    geben `False` zurueck. Konstantzeit-Verhalten kommt aus argon2-cffi.
    """
    try:
        return _get_hasher().verify(stored_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:
        # z.B. ungueltiges Hash-Format — niemals den Klartext-Hash loggen.
        log.warning("auth.password_verify_error")
        return False


# ---------------------------------------------------------------------------
# Master-Key (256-bit hochentropisch) — SHA-256 + compare_digest.
# ---------------------------------------------------------------------------


def generate_master_key() -> str:
    """Erzeugt einen frischen 32-Byte URL-safe Master-Key (Base64, ~43 Zeichen).

    Wird beim Setup einmal angezeigt und nirgends sonst persistiert.
    """
    return secrets.token_urlsafe(32)


def hash_master_key(key: str) -> str:
    """SHA-256-Hex-Hash eines Master-Keys.

    Argon2id ist hier Over-Kill — der Klartext-Raum ist 256 bit, Brute-Force
    unmoeglich, und der Hash wird auf jedem `/api/register`-Call verifiziert.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_master_key(stored_hash: str, key: str) -> bool:
    """Konstantzeit-Vergleich des Master-Keys gegen seinen Hash."""
    candidate = hash_master_key(key)
    return hmac.compare_digest(stored_hash, candidate)


# ---------------------------------------------------------------------------
# Server-Key (gleiche Strategie wie Master-Key) — Helpers fuer Block C.
# ---------------------------------------------------------------------------


def generate_server_key() -> str:
    """Erzeugt einen frischen 32-Byte URL-safe Server-Key."""
    return secrets.token_urlsafe(32)


def hash_server_key(key: str) -> str:
    """SHA-256-Hex-Hash eines Server-Keys."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_server_key(stored_hash: str, key: str) -> bool:
    """Konstantzeit-Vergleich Server-Key gegen Hash."""
    candidate = hash_server_key(key)
    return hmac.compare_digest(stored_hash, candidate)


# ---------------------------------------------------------------------------
# Flask-Login-User-Loader.
# ---------------------------------------------------------------------------


@login_manager.user_loader
def _load_user(user_id: str) -> AuthUser | None:
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return None
    session = get_session()
    row = session.execute(select(UserModel).where(UserModel.id == uid)).scalar_one_or_none()
    if row is None:
        return None
    return AuthUser(id=row.id, username=row.username)


def init_auth(app: Flask) -> None:
    """Bindet `LoginManager` an die Flask-App."""
    login_manager.init_app(app)


__all__ = [
    "AuthUser",
    "generate_master_key",
    "generate_server_key",
    "hash_master_key",
    "hash_password",
    "hash_server_key",
    "init_auth",
    "login_manager",
    "safe_next",
    "verify_master_key",
    "verify_password",
    "verify_server_key",
]
