"""Konfiguration via pydantic-settings.

Liest alle `SECSCAN_*`-Environment-Variablen ein und validiert sie strikt.
Fehlende Pflichtwerte (vor allem `SECSCAN_ENCRYPTION_KEY`) fuehren in der
App-Factory zu einem Start-Refusal — siehe `app/__init__.py`.
"""

from __future__ import annotations

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Zentrale Settings-Klasse.

    Alle Werte koennen ueber Environment-Variablen mit dem Prefix `SECSCAN_`
    gesetzt werden. Defaults entsprechen ARCHITECTURE.md §9.
    """

    model_config = SettingsConfigDict(
        env_prefix="SECSCAN_",
        env_file=None,  # Container injiziert env direkt; .env wird vom compose geladen.
        case_sensitive=False,
        extra="ignore",
    )

    # ----- Pflicht -----
    encryption_key: SecretStr = Field(
        ...,
        description="Fernet-Key fuer LLM-API-Key-Verschluesselung. Mindestens 32 Zeichen.",
        min_length=32,
    )
    secret_key: SecretStr = Field(
        default=SecretStr(""),
        description="Flask-Session-Cookie-Geheimnis.",
    )
    database_url: str = Field(
        default="postgresql+psycopg://secscan:secscan@db:5432/secscan",
        description="SQLAlchemy-URL mit async-faehigem psycopg-Treiber.",
    )

    # ----- Body- und Decompress-Limits (siehe ARCHITECTURE.md §9) -----
    max_body_mb: int = Field(default=10, ge=1, le=1024)
    max_decompressed_mb: int = Field(default=100, ge=1, le=10240)

    # ----- Rate-Limits (flask-limiter Format) -----
    ratelimit_register: str = Field(default="10/minute")
    ratelimit_login: str = Field(default="5/minute")
    ratelimit_scans_unauth: str = Field(default="20/minute")
    ratelimit_scans_auth: str = Field(default="60/hour")

    # ----- Gunicorn -----
    gunicorn_workers: int = Field(default=2, ge=1, le=64)
    gunicorn_timeout: int = Field(default=120, ge=10, le=600)

    # ----- Logging -----
    log_level: str = Field(default="INFO")

    # ----- Argon2id-Cost-Parameter (siehe ARCHITECTURE.md §8) -----
    # Defaults bewusst auf "~100ms auf moderner CPU" abgestimmt — siehe §9
    # "Login-Brute-Force" — Argon2-Verify ist das natuerliche Rate-Limit.
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost: int = Field(default=65536, ge=8192, le=1048576)
    argon2_parallelism: int = Field(default=4, ge=1, le=16)

    # ----- Session-Konfiguration -----
    session_lifetime_days: int = Field(default=7, ge=1, le=90)

    @property
    def max_body_bytes(self) -> int:
        """Body-Limit in Bytes fuer Flask `MAX_CONTENT_LENGTH`."""
        return self.max_body_mb * 1024 * 1024


def load_settings() -> Settings:
    """Laedt Settings aus dem Environment.

    Wirft `pydantic.ValidationError`, wenn `SECSCAN_ENCRYPTION_KEY` fehlt oder
    zu kurz ist. Die App-Factory faengt das ab und beendet mit `SystemExit`.
    """
    return Settings()  # type: ignore[call-arg]
