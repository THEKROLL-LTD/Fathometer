# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Konfiguration via pydantic-settings.

Liest alle `FM_*`-Environment-Variablen ein und validiert sie strikt.
Fehlende Pflichtwerte (vor allem `FM_ENCRYPTION_KEY`) fuehren in der
App-Factory zu einem Start-Refusal — siehe `app/__init__.py`.
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Zentrale Settings-Klasse.

    Alle Werte koennen ueber Environment-Variablen mit dem Prefix `FM_`
    gesetzt werden. Defaults entsprechen ARCHITECTURE.md §9.
    """

    model_config = SettingsConfigDict(
        env_prefix="FM_",
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
        default="postgresql+psycopg://fathometer:fathometer@db:5432/fathometer",
        description="SQLAlchemy-URL mit async-faehigem psycopg-Treiber.",
    )

    # ----- Public-URL (Block N / v0.7.1) -----
    # Explizite extern sichtbare Base-URL des Backends, inkl. Schema. Wird
    # vom Bootstrap-Installer-Template (`/install.sh`) und vom Context-
    # Processor `external_base_url` bevorzugt vor `request.host_url`
    # verwendet. Ohne diesen Override sieht Flask hinter einem TLS-
    # terminierenden Reverse-Proxy nur das interne `http://`-Schema —
    # das wuerde im gerenderten Installer einen falschen `FM_URL`
    # einbacken und beim ersten `POST /api/register` einen HTTP→HTTPS-
    # 301-Redirect ausloesen (`curl -X POST` verliert dann den POST).
    # Mitigation laeuft zusaetzlich ueber `werkzeug.middleware.proxy_fix.
    # ProxyFix` (siehe `app/__init__.py`), aber `FM_PUBLIC_URL` ist
    # die explizite, deploy-eindeutige Quelle der Wahrheit.
    public_url: str | None = Field(
        default=None,
        description=(
            "Extern sichtbare Backend-URL inkl. Schema, z.B. "
            "'https://fathometer.example.com'. Trailing-Slash wird "
            "abgeschnitten."
        ),
    )

    # ----- Body- und Decompress-Limits (siehe ARCHITECTURE.md §9) -----
    max_body_mb: int = Field(default=64, ge=1, le=1024)
    max_decompressed_mb: int = Field(default=512, ge=1, le=10240)

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

    # ----- Block P (ADR-0023) — LLM-Risk-Reviewer-Settings -----
    # TTL in Tagen fuer `llm_risk_cache`-Eintraege (Read-Side-Check, kein
    # aktives Loeschen). Eintraege aelter als TTL gelten als invalid und
    # triggern einen neuen LLM-Call.
    llm_cache_ttl_days: int = Field(default=30, ge=1, le=3650)
    # LRU-Hard-Limit fuer `llm_risk_cache`. Hintergrund-Job loescht aelteste
    # `last_used_at` wenn die Tabelle die Grenze ueberschreitet.
    llm_cache_max_rows: int = Field(default=100_000, ge=100, le=10_000_000)
    # Max-Token-Budget pro Pass-1- und Pass-2-Call (Out-Token, Defense-in-
    # Depth gegen runaway-Outputs).
    # v0.9.x: Pass-1-Cap auf 16384 angehoben. Heterogene Batches (verschiedene
    # Packages in einem Job) zwingen GPT-OSS-120B zu deutlich mehr Reasoning-
    # Tokens als bei homogenen — beobachtet 2026-05-20: Job 24 mit 5+ Groups
    # vs Jobs 23/22/21 mit 1 Group, Job 24 timed out 3x bei 8192-Cap +120s-
    # Timeout. 16k Tokens kostet nichts wenn ungenutzt (nur tatsaechliche
    # Output-Tokens werden verrechnet).
    llm_pass1_max_tokens: int = Field(default=16384, ge=256, le=32768)
    llm_pass2_max_tokens: int = Field(default=2048, ge=256, le=32768)
    # Pass-1-Batch-Cap. v0.9.x: Default von 100 → 50 reduziert. Bei
    # heterogenen Reste-Batches muss das Modell pro Batch nur ~3-5 Groups
    # erkennen statt potentiell 10+. Erwartete Trade-offs: ~2x mehr Jobs,
    # aber dafuer deterministischere Job-Dauer und kein 120s-Timeout-Hit.
    # Operator kann via FM_LLM_PASS1_FINDINGS_PER_BATCH ueberschreiben.
    llm_pass1_findings_per_batch: int = Field(default=50, ge=5, le=2000)

    # ----- Block P (ADR-0023) — Worker- und Token-Budget-Settings -----
    # DEPRECATED als Laufzeit-Cap (ADR-0056): dieses Env-Field ist seit
    # ADR-0056 NUR noch der Install-Seed fuer ``Setting.llm_daily_token_cap``
    # (gesetzt in ``ensure_settings_row``). Der Worker erzwingt zur Laufzeit
    # den DB-Cap ``llm_daily_token_cap`` (Operator-steuerbar via Provider-Tab),
    # NICHT mehr diesen Wert — siehe ``app/services/llm_budget.py``.
    # Default 2M Tokens: Reasoning-Modelle (z. B. ``openai/gpt-oss-120b``)
    # produzieren ~3x mehr Tokens (Pass-2-Real ~1500 statt 500); bei ~100
    # Calls/Tag bleibt das bei DeepInfra unter $1-2/Monat.
    llm_token_budget_daily: int = Field(default=2_000_000, ge=1000, le=10_000_000_000)
    # Worker-Poll-Intervall (Sekunden). Default 2s — laut ADR irrelevant
    # gegenueber LLM-Latenzen von 30-90s, aber bei `mode=off`/empty-queue
    # die dominante Backoff-Latenz.
    worker_poll_interval_sec: float = Field(default=2.0, ge=0.1, le=60.0)
    # Stale-Timeout fuer `in_progress`-Jobs in Minuten. Nach Ablauf reaped
    # der Stale-Reaper-Sub-Tick die Jobs zurueck in die Queue oder auf
    # `failed` (bei `attempts >= 3`).
    worker_stale_timeout_min: int = Field(default=10, ge=1, le=1440)

    # ----- Block U (ADR-0029) — Parallele LLM-Job-Verarbeitung -----
    # Globaler Cap fuer parallel laufende LLM-Jobs im Worker-Prozess
    # (asyncio-Semaphore, In-Process-Concurrency — kein Multi-Container-
    # Scope, siehe ADR-0029 §Out-of-Scope). Default 1 ist backward-
    # compatible — bestehende Deploys behalten das Block-P-Verhalten,
    # bis der Operator manuell in /settings/llm-reviewer hochregelt.
    # Hot-Reload alle 30 s im Worker via ``_get_concurrency_throttled``.
    # Setzen via FM_LLM_WORKER_JOB_CONCURRENCY.
    llm_worker_job_concurrency: int = Field(default=1, ge=1, le=200)
    # Sampling-Rate fuer ``llm_debug_log``-Inserts bei ``status='success'``.
    # Errors (validation_error/timeout/error) werden weiterhin 1:1 persistiert,
    # Successes nur 1:N. Default 1:10 ist Skalierungs-Mitigation fuer N=200
    # (siehe ADR-0029 §Konsequenzen "Debug-Log-Tabelle explodiert").
    # Setzen via FM_LLM_DEBUG_LOG_SUCCESS_SAMPLE_RATE.
    llm_debug_log_success_sample_rate: int = Field(default=10, ge=1, le=1000)

    # ----- Block P (ADR-0023) — LLM-Debug-Log (v0.9.3) -----
    # Operator-Debugging-Tabelle fuer LLM-Job-Request/Response-Bodies.
    # Eviction laeuft im Worker als Sub-Tick (analog Stale-Reaper).
    # v0.11.0 (Block U Phase A): Default von 500 auf 2000 angehoben — bei
    # N=200 Concurrency und 1:10-Sampling (Phase G) bietet 2000 Rows
    # ein deutlich breiteres Forensik-Fenster, ohne dass die
    # CTE-DELETE-Eviction (Phase G.3) teurer wird.
    llm_debug_log_max_rows: int = Field(default=2000, ge=10, le=100_000)
    llm_debug_log_max_age_days: int = Field(default=14, ge=1, le=365)
    # Per-Body-Size-Cap. Bodies werden bei Ueberschreitung getrimmt mit
    # ``{"__truncated": True, "original_size_bytes": N}`` Marker.
    llm_debug_log_body_size_cap: int = Field(default=65536, ge=1024, le=1_048_576)

    # ----- Agent- und Trivy-Versionen (Block N / ADR-0021) -----
    # Class-Level-Konstanten — NICHT als BaseSettings-Field deklariert, weil
    # sie ausdruecklich NICHT per `FM_*`-Env-Var ueberschrieben werden
    # sollen. Ein User-Setting fuer die Mindest-Version waere eine
    # Selbstabschaltungs-Falle (siehe ADR-0021). Version-Bumps geschehen
    # gemeinsam mit dem Agent-Skript im selben Commit.
    MIN_AGENT_VERSION: ClassVar[str] = "0.1.0"
    CURRENT_AGENT_VERSION: ClassVar[str] = "0.8.0"
    MIN_TRIVY_VERSION: ClassVar[str] = "0.70.0"
    RECOMMENDED_TRIVY_VERSION: ClassVar[str] = "0.71.0"
    TRIVY_RELEASE_URL_TEMPLATE: ClassVar[str] = (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v{version}/trivy_{version}_Linux-{arch}.tar.gz"
    )
    TRIVY_DB_STALE_THRESHOLD_DAYS: ClassVar[int] = 7

    # ----- Block Q (ADR-0024) — External EPSS/KEV Enrichment -----
    # Master-Switch fuer den ``feed_enrichment``-Worker-Sub-Tick. Wenn
    # ``True``, springt der Tick sofort zurueck — kein HTTP, kein Log-Spam.
    # Gedacht fuer Air-Gap-Deploys ohne Outbound-HTTPS.
    feed_pull_disabled: bool = Field(
        default=False,
        description=(
            "Master-Switch fuer den External-Feed-Pull (EPSS/KEV). "
            "True => Worker-Sub-Tick ist no-op (Air-Gap-Setup)."
        ),
    )
    feed_epss_url: str = Field(
        default="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        description="HTTPS-URL des EPSS-Daily-CSV-Snapshots (gzipped).",
    )
    feed_kev_url: str = Field(
        default="https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
        description=(
            "HTTPS-URL des CISA-KEV-JSON-Feeds. Default ist der offizielle "
            "GitHub-Mirror (cisagov/kev-data) — identisches JSON-Schema, "
            "kein Cloudflare-Bot-Block (cisa.gov direkt blockt Hetzner-/"
            "Cloud-IP-Ranges mit 403). Override fuer Air-Gap / interne "
            "Proxies via FM_FEED_KEV_URL."
        ),
    )
    feed_pull_interval_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Mindestabstand zwischen zwei erfolgreichen Pulls pro Feed (Stunden).",
    )
    feed_jitter_max_min: int = Field(
        default=30,
        ge=0,
        le=120,
        description="Max. Jitter (Minuten) auf das Pull-Intervall, ±-symmetrisch.",
    )
    feed_max_decompressed_mb_epss: int = Field(
        default=50,
        ge=1,
        le=500,
        description=(
            "Cap fuer dekomprimierte EPSS-CSV-Groesse in MB "
            "(Gzip-Bomb-Schutz). Realistisch ~25 MB, Default 50 MB."
        ),
    )
    feed_max_bytes_kev_mb: int = Field(
        default=10,
        ge=1,
        le=100,
        description=(
            "Cap fuer das CISA-KEV-JSON-Response in MB. Realistisch ~1 MB, Default 10 MB."
        ),
    )

    # ----- Block R (ADR-0026) — Async-Scan-Ingest -----
    # ENV: FM_MAX_QUEUED_INGEST_JOBS (Prefix FM_ + Field-Name).
    # Das urspruengliche Feature-Flag `SCAN_INGEST_ASYNC` ist seit v0.12.0
    # ersatzlos entfernt — Async ist der einzige Pfad (siehe ADR-0026
    # §Cutover-Abschluss).
    max_queued_ingest_jobs: int = Field(
        default=50,
        ge=1,
        le=10_000,
        description=(
            "Soft-Cap fuer gleichzeitig queued+in_progress Ingest-Jobs pro Server. "
            "Bei Ueberschreitung 429 Too Many Requests. "
            "DoS-Schutz (ADR-0026 §Bedrohungsmodell). "
            "Setzen via FM_MAX_QUEUED_INGEST_JOBS."
        ),
    )
    # Block R Phase C (ADR-0026) — Worker-Parameter.
    # Max-Versuche bevor ein Ingest-Job auf 'failed' gesetzt wird.
    scan_ingest_max_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description=(
            "Max. Pickup-Versuche fuer einen Ingest-Job bevor er auf 'failed' "
            "gesetzt wird. Backoff: 30s * 2^(attempts-1). "
            "Setzen via FM_SCAN_INGEST_MAX_ATTEMPTS."
        ),
    )
    # Stale-Timeout fuer in_progress Ingest-Jobs. Nach Ablauf requeued der
    # Stale-Reaper den Job oder setzt ihn auf 'failed' (bei max attempts).
    scan_ingest_stale_timeout_min: int = Field(
        default=5,
        ge=1,
        le=60,
        description=(
            "Stale-Timeout fuer in_progress Ingest-Jobs in Minuten. "
            "Ingest-Jobs sind reine DB-Arbeit ohne LLM-Calls — 5 Minuten "
            "ist ein realistischer Upper-Bound. "
            "Setzen via FM_SCAN_INGEST_STALE_TIMEOUT_MIN."
        ),
    )
    # Cadence des Retention-Sweeps in Sekunden.
    scan_ingest_retention_interval_sec: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description=(
            "Cadence des Scan-Ingest-Retention-Sweeps in Sekunden (Default 1h). "
            "Loescht payload_gzip bei done-Jobs nach 1h und failed-Zeilen nach 24h. "
            "Setzen via FM_SCAN_INGEST_RETENTION_INTERVAL_SEC."
        ),
    )

    @property
    def max_body_bytes(self) -> int:
        """Body-Limit in Bytes fuer Flask `MAX_CONTENT_LENGTH`."""
        return self.max_body_mb * 1024 * 1024

    @property
    def encryption_key_has_low_entropy(self) -> bool:
        """`True` wenn der Encryption-Key weniger als 16 distinkte Bytes hat.

        Siehe ADR-0013: schwache Trivial-Keys (`aaaa…`, `1234567890…`)
        loesen beim App-Start ein structlog-WARNING aus. Echte
        Zufalls-Keys (`secrets.token_urlsafe(48)`) haben typisch 40+
        distinkte Bytes — das Limit bei 16 ist konservativ.
        """
        raw = self.encryption_key.get_secret_value().encode("utf-8")
        return len(set(raw)) < 16


def load_settings() -> Settings:
    """Laedt Settings aus dem Environment.

    Wirft `pydantic.ValidationError`, wenn `FM_ENCRYPTION_KEY` fehlt oder
    zu kurz ist. Die App-Factory faengt das ab und beendet mit `SystemExit`.
    """
    return Settings()  # type: ignore[call-arg]
