"""SQLAlchemy-Models fuer fathometer.

Enthaelt alle 12 Tabellen aus ARCHITECTURE.md §5 sowie die zugehoerigen
Python-Enums, Constraints, Indizes und die generierte Spalte
`findings.has_fix`.

Konvention: SQLAlchemy 2.x Style mit `DeclarativeBase` und `Mapped[...] /
mapped_column(...)`. Alle Zeitstempel sind `TIMESTAMP WITH TIME ZONE`.
Enums werden als Postgres-`ENUM`-Typen erzeugt (siehe Migration 0002).

Wichtig: Foreign-Keys auf `users.id` sind `nullable=True` mit `ON DELETE SET
NULL`, damit Audit-Eintraege beim (zukuenftigen) Loeschen eines Users nicht
mitgehen — Audit muss erhalten bleiben.
"""

from __future__ import annotations

import enum
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# ---------------------------------------------------------------------------
# Enums — Python-Seitig. Die Postgres-`ENUM`-Typen werden in der Migration
# explizit angelegt; SQLAlchemy bekommt `native_enum=True, create_type=False`
# damit die Migration die Hoheit ueber Lebenszyklus und Werte behaelt.
# ---------------------------------------------------------------------------


class Severity(enum.StrEnum):
    """Severity-Stufen aus dem Trivy-Report (case-folded auf lowercase)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class FindingType(enum.StrEnum):
    """Top-Level-Typ. Im MVP nur `vulnerability` produziert."""

    VULNERABILITY = "vulnerability"
    SECRET = "secret"  # noqa: S105 — Enum-Wert, kein Passwort.
    MISCONFIG = "misconfig"


class FindingClass(enum.StrEnum):
    """Klasse aus dem Trivy-`Class`-Feld pro Result."""

    OS_PKGS = "os-pkgs"
    LANG_PKGS = "lang-pkgs"
    OTHER = "other"


class FindingStatus(enum.StrEnum):
    """Triage-Status pro Finding."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AttackVector(enum.StrEnum):
    """CVSS-v3 Attack-Vector."""

    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"
    UNKNOWN = "unknown"


# Postgres-Enum-Typnamen — exakt so in der Migration erzeugt.
SEVERITY_ENUM_NAME = "severity"
FINDING_TYPE_ENUM_NAME = "finding_type"
FINDING_CLASS_ENUM_NAME = "finding_class"
FINDING_STATUS_ENUM_NAME = "finding_status"
ATTACK_VECTOR_ENUM_NAME = "attack_vector"


def _pg_enum(enum_cls: type[enum.Enum], name: str) -> Any:
    """Erzeugt einen SQLAlchemy-`Enum`-Typ, der den nativen Postgres-Enum nutzt.

    `create_type=False` verhindert Auto-Create durch das ORM — die Migration
    erzeugt und droppt die Typen explizit.
    """
    from sqlalchemy import Enum as SAEnum

    return SAEnum(
        enum_cls,
        name=name,
        native_enum=True,
        create_type=False,
        values_callable=lambda e: [member.value for member in e],
    )


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Gemeinsame Basisklasse aller ORM-Models."""


# ---------------------------------------------------------------------------
# users — genau ein Admin im MVP (siehe ADR-0004).
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    notes: Mapped[list[FindingNote]] = relationship(
        "FindingNote", back_populates="author_user", foreign_keys="FindingNote.author_user_id"
    )


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# server_groups — 1:N-Group fuer Sidebar-Sektionen (ADR-0034, Migration 0014).
# ---------------------------------------------------------------------------


class ServerGroup(Base):
    """Operator-pflegbare Sidebar-Gruppe fuer Server (1:N).

    Ein Server gehoert zu hoechstens einer Gruppe (`Server.group_id` nullable).
    Kein Default-Seed — Tabelle ist nach der Migration leer. CRUD-UI kommt
    in einem spaeteren Block. `position` ist die Sidebar-Sortier-Reihenfolge
    (kleinster Wert zuerst, Ties alphabetisch nach `name`).
    """

    __tablename__ = "server_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    servers: Mapped[list[Server]] = relationship("Server", back_populates="group")

    __table_args__ = (
        CheckConstraint(
            "length(trim(name)) > 0 AND length(name) <= 64",
            name="ck_server_groups_name_length",
        ),
        CheckConstraint(
            "name ~ '^[A-Za-z0-9 _.-]+$'",
            name="ck_server_groups_name_charset",
        ),
    )


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    api_key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_scan_interval_h: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Denormalisierte Host-Info aus dem letzten Scan.
    os_family: Mapped[str | None] = mapped_column(String(32))
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_pretty_name: Mapped[str | None] = mapped_column(String(256))
    kernel_version: Mapped[str | None] = mapped_column(String(128))
    architecture: Mapped[str | None] = mapped_column(String(16))
    agent_version: Mapped[str | None] = mapped_column(String(32))
    # Block N (ADR-0021): zuletzt beobachtete Trivy-Version aus dem Envelope
    # (Agent ab v0.2.0 sendet `host.trivy_version`).
    trivy_version: Mapped[str | None] = mapped_column(String(32))
    # Zeitstempel des letzten Envelope-Empfangs mit `agent_version` — der
    # UI-Indikator fuer "veraltet" soll nicht auf einem 6-Monate-alten Wert
    # haengen, wenn der Server selbst stale ist.
    agent_version_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Block O (ADR-0022): Zeitstempel des zuletzt empfangenen Host-Snapshots.
    # NULL solange noch kein Agent ab v0.3.0 einen `host_state`-Block geliefert
    # hat — die Pre-Triage-Engine setzt das Finding dann in `risk_band=unknown`.
    host_state_snapshot_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Trivy-DB-Frische.
    trivy_db_version: Mapped[str | None] = mapped_column(String(64))
    trivy_db_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Block W (ADR-0034): optionale 1:N-Gruppen-Zuordnung. NULL = ungrouped.
    # ON DELETE SET NULL: Gruppe loeschen setzt dieses Feld zurueck ohne
    # den Server zu loeschen.
    group_id: Mapped[int | None] = mapped_column(
        ForeignKey("server_groups.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    scans: Mapped[list[Scan]] = relationship(
        "Scan", back_populates="server", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="server", cascade="all, delete-orphan"
    )
    tag_links: Mapped[list[ServerTag]] = relationship(
        "ServerTag", back_populates="server", cascade="all, delete-orphan"
    )
    # lazy="selectin" damit Sidebar-Context-Abfragen die Gruppe in einer
    # separaten IN-Query laden statt per JOIN — konsistent mit tag_links.
    group: Mapped[ServerGroup | None] = relationship(
        "ServerGroup", back_populates="servers", lazy="selectin"
    )


# ---------------------------------------------------------------------------
# scans — reine Empfangs-Buchhaltung, kein Roh-JSON (siehe ADR-0005).
# ---------------------------------------------------------------------------


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    agent_version: Mapped[str | None] = mapped_column(String(32))
    trivy_scanner_version: Mapped[str | None] = mapped_column(String(32))
    trivy_db_version: Mapped[str | None] = mapped_column(String(64))
    trivy_db_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Historisierte Host-Felder zum Zeitpunkt des Scans.
    os_family: Mapped[str | None] = mapped_column(String(32))
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_pretty_name: Mapped[str | None] = mapped_column(String(256))
    kernel_version: Mapped[str | None] = mapped_column(String(128))
    architecture: Mapped[str | None] = mapped_column(String(16))

    server: Mapped[Server] = relationship("Server", back_populates="scans")


# ---------------------------------------------------------------------------
# tags und server_tags
# ---------------------------------------------------------------------------


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    color: Mapped[str] = mapped_column(String(7), nullable=False, default="#6b7280")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    server_links: Mapped[list[ServerTag]] = relationship(
        "ServerTag", back_populates="tag", cascade="all, delete-orphan"
    )


class ServerTag(Base):
    __tablename__ = "server_tags"

    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    tag_id: Mapped[int] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)

    server: Mapped[Server] = relationship("Server", back_populates="tag_links")
    tag: Mapped[Tag] = relationship("Tag", back_populates="server_links")


# ---------------------------------------------------------------------------
# findings — Kerntabelle. `has_fix` ist eine generierte Spalte (§5).
# ---------------------------------------------------------------------------


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False
    )

    # Typ und natuerliche ID.
    finding_type: Mapped[FindingType] = mapped_column(
        _pg_enum(FindingType, FINDING_TYPE_ENUM_NAME), nullable=False
    )
    finding_class: Mapped[FindingClass] = mapped_column(
        _pg_enum(FindingClass, FINDING_CLASS_ENUM_NAME), nullable=False
    )
    identifier_key: Mapped[str] = mapped_column(String(128), nullable=False)
    package_name: Mapped[str] = mapped_column(String(256), nullable=False)

    # Vulnerability-Felder.
    installed_version: Mapped[str | None] = mapped_column(String(256))
    fixed_version: Mapped[str | None] = mapped_column(String(256))
    severity: Mapped[Severity] = mapped_column(
        _pg_enum(Severity, SEVERITY_ENUM_NAME), nullable=False
    )
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)

    # Triage-Signale.
    cvss_v3_score: Mapped[float | None] = mapped_column(Float)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(256))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String(16)))
    attack_vector: Mapped[AttackVector] = mapped_column(
        _pg_enum(AttackVector, ATTACK_VECTOR_ENUM_NAME),
        nullable=False,
        default=AttackVector.UNKNOWN,
    )
    references: Mapped[list[str] | None] = mapped_column(ARRAY(Text))

    # Block AA (ADR-0041): Trivy-PrimaryURL (Aquasec-/NVD-/Vendor-Direktlink).
    # Bereits im Envelope-Schema validiert; wird beim Re-Ingest gefuellt
    # (NULL fuer Bestands-Findings bis zum naechsten Scan).
    primary_url: Mapped[str | None] = mapped_column(String(2048))

    # Block N (ADR-0021): Ursachen-Felder pro Finding. Werden bei jedem
    # Re-Ingest geschrieben (auch beim Update — kein historisches Bewahren).
    # `package_name` enthaelt weiterhin das ADR-0011-`@target`-Suffix fuer
    # lang-pkgs, damit der UNIQUE-Constraint nicht bricht; `target_path`
    # ist die strukturierte Form fuer die UI.
    package_purl: Mapped[str | None] = mapped_column(String(512))
    target_path: Mapped[str | None] = mapped_column(String(512))
    result_type: Mapped[str | None] = mapped_column(String(64))
    severity_source: Mapped[str | None] = mapped_column(String(64))
    vendor_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String(128)))

    # Block O (ADR-0022): Risk-Band-Klassifikation der Pre-Triage-Engine
    # (`engine`) oder des LLM-Passes in Block P (`llm`/`manual`).
    # `risk_band` ist nullable bis zur ersten Auswertung; die UI rendert in
    # diesem Fall einen "pending pre-triage"-Hint.
    risk_band: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_band_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    risk_band_source: Mapped[str | None] = mapped_column(
        String(16), nullable=True, default="engine"
    )
    risk_band_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Provider-Map aus Trivys `Vulnerability.VendorSeverity` — Eingabe fuer
    # `max_severity_across_providers()` (Phase B). JSONB damit wir bei
    # spaeteren Use-Cases (Disagreement-Pill, Re-Open-Trigger) GIN-indexieren
    # koennen ohne Schema-Migration.
    severity_by_provider: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Normalisierter Vendor-Status (ADR-0022 §vendor_status, Whitelist:
    # affected/fixed/investigating/will_not_fix/eol/not_affected/unknown).
    vendor_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Generierte Spalte — Postgres berechnet bei jedem Insert/Update.
    has_fix: Mapped[bool] = mapped_column(
        Boolean,
        Computed("fixed_version IS NOT NULL AND fixed_version <> ''", persisted=True),
        nullable=False,
    )

    # Lifecycle.
    status: Mapped[FindingStatus] = mapped_column(
        _pg_enum(FindingStatus, FINDING_STATUS_ENUM_NAME),
        nullable=False,
        default=FindingStatus.OPEN,
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Block P (ADR-0023): Zuordnung zur Application-Group. NULL bedeutet noch
    # nicht durch Pass 1 zugeordnet ("Pending grouping"-Sektion in der UI).
    # ON DELETE SET NULL: bei Group-Loeschung verlieren die Findings nur den
    # Verweis, bleiben aber erhalten.
    application_group_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("application_groups.id", ondelete="SET NULL"),
        nullable=True,
    )

    server: Mapped[Server] = relationship("Server", back_populates="findings")
    notes: Mapped[list[FindingNote]] = relationship(
        "FindingNote", back_populates="finding", cascade="all, delete-orphan"
    )
    application_group: Mapped[ApplicationGroup | None] = relationship(
        "ApplicationGroup", back_populates="findings"
    )

    __table_args__ = (
        UniqueConstraint(
            "server_id",
            "finding_type",
            "identifier_key",
            "package_name",
            name="uq_findings_natural_key",
        ),
        CheckConstraint(
            "cvss_v3_score IS NULL OR (cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0)",
            name="ck_findings_cvss_range",
        ),
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0.0 AND epss_score <= 1.0)",
            name="ck_findings_epss_range",
        ),
        CheckConstraint(
            "epss_percentile IS NULL OR (epss_percentile >= 0.0 AND epss_percentile <= 1.0)",
            name="ck_findings_epss_percentile_range",
        ),
        Index("ix_findings_server_status", "server_id", "status"),
        Index("ix_findings_identifier_key", "identifier_key"),
        # Partial-Indizes — Conditions werden als rohe SQL-Texte uebergeben
        # (sicher: keine User-Eingabe).
        Index(
            "ix_findings_kev_open",
            "is_kev",
            postgresql_where="is_kev = true",
        ),
        Index(
            "ix_findings_epss_open",
            "epss_score",
            postgresql_where="status = 'open'",
            postgresql_ops={"epss_score": "DESC NULLS LAST"},
        ),
        Index(
            "ix_findings_package_open",
            "package_name",
            "server_id",
            postgresql_where="status = 'open'",
        ),
        # Block O (ADR-0022): Risk-Band-Indizes fuer die UI-Filter.
        # Partial-Index auf offene Findings deckt den haeufigsten Dashboard-
        # Filter `?risk_band=...&status=open` ab; `server_risk_band` deckt die
        # Server-Detail-Gruppierung.
        Index(
            "ix_findings_risk_band_open",
            "risk_band",
            postgresql_where="status = 'open'",
        ),
        Index(
            "ix_findings_server_risk_band",
            "server_id",
            "risk_band",
        ),
        # Block P (ADR-0023): Drill-down-Index fuer Application-Group-Filter
        # auf der Server-Detail-View und Dashboard-Filter-Bar.
        Index("ix_findings_application_group", "application_group_id"),
        # Perf (Migration 0018): konsolidierter Partial-Covering-Index fuer die
        # Server-Detail-Aggregate. EXPLAIN-Befund (2026-06-07, sid mit 25.9k
        # offenen Findings): _risk_band_header_counts / _load_server_band_
        # aggregates / _load_application_groups (Count) / _tendency_quick und
        # die triage-COUNT-Query lasen je ~15k Buffer (~118 MB) als Heap-Scan
        # ueber alle offenen Rows, obwohl sie nur 1-2 Spalten zaehlen. Mit
        # diesem Index laufen sie als Index-Only-Scan (~150 Buffer). Die
        # INCLUDE-Spalten decken die Projektion der Aggregate + die
        # Sort-/Filter-Keys der Triage-/Group-Listen ab.
        # `id` als erste INCLUDE-Spalte (Migration 0019): ohne den `id`-WERT im
        # Index fallen `count(id)`-Aggregate und der Two-Step-`select(id)`-Pfad
        # auf Heap-Scans zurueck (B-Tree haelt nur den Heap-TID, nicht den
        # id-Wert). Mit `id` in INCLUDE werden Q1/Q3/Q4/Q5 Index-Only.
        Index(
            "ix_findings_server_open_triage",
            "server_id",
            "risk_band",
            postgresql_include=[
                "id",
                "application_group_id",
                "first_seen_at",
                "is_kev",
                "severity",
                "epss_score",
            ],
            postgresql_where="status = 'open'",
        ),
    )


# ---------------------------------------------------------------------------
# finding_notes — Discussion-Thread mit Soft-Delete.
# ---------------------------------------------------------------------------


class FindingNote(Base):
    __tablename__ = "finding_notes"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(64), nullable=False)
    # Optionale FK auf users.id — `author` bleibt im Soft-Delete-Fall auch
    # erhalten, wenn der User-Datensatz weg ist (Multi-User-Zukunft).
    author_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship("Finding", back_populates="notes")
    author_user: Mapped[User | None] = relationship(
        "User", back_populates="notes", foreign_keys=[author_user_id]
    )


# ---------------------------------------------------------------------------
# audit_events — siehe ARCHITECTURE.md §13.
# ---------------------------------------------------------------------------


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(128))
    comment: Mapped[str | None] = mapped_column(Text)
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSONB)

    __table_args__ = (Index("ix_audit_events_ts_desc", ts.desc()),)


# ---------------------------------------------------------------------------
# settings — Single-Row mit Singleton-Constraint.
# ---------------------------------------------------------------------------


class Setting(Base):
    __tablename__ = "settings"

    # `id` ist immer 1 — Check-Constraint erzwingt Single-Row.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    severity_threshold: Mapped[Severity] = mapped_column(
        _pg_enum(Severity, SEVERITY_ENUM_NAME),
        nullable=False,
        default=Severity.HIGH,
    )
    stale_threshold_h: Mapped[int] = mapped_column(Integer, nullable=False, default=48)
    stale_trivy_db_threshold_h: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    # Master-Key (Argon2id).
    master_key_hash: Mapped[str | None] = mapped_column(String(255))

    # LLM-Provider-Block (Felder fuer Block G — Schema bereits hier).
    llm_provider_name: Mapped[str | None] = mapped_column(String(64))
    llm_base_url: Mapped[str | None] = mapped_column(String(256))
    llm_api_key_encrypted: Mapped[bytes | None] = mapped_column()
    llm_model: Mapped[str | None] = mapped_column(String(128))
    llm_daily_token_cap: Mapped[int] = mapped_column(Integer, nullable=False, default=1_000_000)

    setup_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Block P (ADR-0023): LLM-Risk-Reviewer-Feature-Flag + Worker-Heartbeat +
    # Token-Budget-Tageszaehler. Die drei Felder leben auf der Singleton-Row
    # damit Worker und Web-Container denselben Status sehen.
    block_p_llm_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="off")
    llm_worker_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    llm_token_budget_used_today: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Naechster Token-Budget-Reset (00:00 UTC). Worker setzt das Feld in
    # `maybe_reset_budget`. Default per server_default `now()` damit
    # bestehende Zeilen einen verarbeitbaren (sofort-faelligen) Wert haben.
    llm_token_budget_reset_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Block U (ADR-0029): Globaler Cap fuer parallele LLM-Jobs im Worker-
    # Prozess (in_process-Concurrency via asyncio.Semaphore). Default 1 ist
    # backward-compatible mit Block P. Worker liest den Wert via
    # ``_get_concurrency_throttled`` mit 30-s-Cache-Window (Hot-Reload).
    llm_worker_job_concurrency: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    # Block U (ADR-0029 §Phase G): Sampling-Rate fuer ``llm_debug_log``-
    # Inserts mit ``status='success'``. Errors laufen 1:1, Successes nur
    # wenn ``hash((job_id, job_type)) % sample_rate == 0``.
    llm_debug_log_success_sample_rate: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10, server_default="10"
    )

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_settings_singleton"),
        # Block P: Mode-Whitelist.
        CheckConstraint(
            "block_p_llm_mode IN ('off', 'observation', 'live')",
            name="ck_settings_block_p_llm_mode",
        ),
        CheckConstraint(
            "llm_token_budget_used_today >= 0",
            name="ck_settings_llm_token_budget_used_today_nonneg",
        ),
        # Block U (ADR-0029): Bounds gespiegelt zum Pydantic-Field in
        # ``app/config.py`` (ge=1, le=200 bzw. ge=1, le=1000).
        CheckConstraint(
            "llm_worker_job_concurrency BETWEEN 1 AND 200",
            name="ck_settings_llm_worker_job_concurrency",
        ),
        CheckConstraint(
            "llm_debug_log_success_sample_rate BETWEEN 1 AND 1000",
            name="ck_settings_llm_debug_log_success_sample_rate",
        ),
    )


# ---------------------------------------------------------------------------
# Host-Snapshot-Tabellen (Block O, ADR-0022 §Host-Snapshot-Datenmodell).
#
# Vier Tabellen, eine pro Snapshot-Block. Persistenz-Strategie ist
# truncate+insert pro Server (kein UPSERT) — wir wollen den vollstaendigen
# aktuellen State, kein Merge mit alten Daten. Datensatz-Volumen pro Server:
# bis zu 4096 + 4096 + 1024 + 1024 = 10K Zeilen.
# ---------------------------------------------------------------------------


class ServerListener(Base):
    """Listening-Socket aus `ss` / `netstat` zum Snapshot-Zeitpunkt."""

    __tablename__ = "server_listeners"

    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    # proto in {tcp, udp, tcp6, udp6}
    proto: Mapped[str] = mapped_column(String(8), primary_key=True)
    port: Mapped[int] = mapped_column(Integer, primary_key=True)
    addr: Mapped[str] = mapped_column(String(64), primary_key=True)
    process: Mapped[str | None] = mapped_column(String(64))
    pid: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        Index("ix_server_listeners_port", "server_id", "port"),
        CheckConstraint(
            "port >= 0 AND port <= 65535",
            name="ck_server_listeners_port_range",
        ),
    )


class ServerProcess(Base):
    """Prozess-Eintrag aus `ps` zum Snapshot-Zeitpunkt."""

    __tablename__ = "server_processes"

    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    pid: Mapped[int] = mapped_column(Integer, primary_key=True)
    user: Mapped[str | None] = mapped_column(String(32))
    comm: Mapped[str | None] = mapped_column(String(64))
    args: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_server_processes_comm", "server_id", "comm"),)


class ServerKernelModule(Base):
    """Geladenes Kernel-Modul aus `lsmod` zum Snapshot-Zeitpunkt."""

    __tablename__ = "server_kernel_modules"

    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(64), primary_key=True)


class ServerService(Base):
    """systemd-/Init-Service-Eintrag zum Snapshot-Zeitpunkt."""

    __tablename__ = "server_services"

    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    name: Mapped[str] = mapped_column(String(128), primary_key=True)


# ---------------------------------------------------------------------------
# Block P (ADR-0023) — Application-Groups, LLM-Job-Queue, LLM-Risk-Cache.
#
# Drei neue Tabellen plus FK `findings.application_group_id` (siehe oben in
# der `Finding`-Klasse). Modellierung folgt ADR-0023 §"Application-Group-
# Schicht", §"Asynchroner Worker via llm_jobs" und §"Two-Level-Caching".
#
# - `application_groups` lebt unabhaengig vom Finding-Lifecycle. `risk_band`
#   nur final-LLM-Bands (kein `pending`/`unknown` — die sind Pre-Triage-only).
# - `llm_jobs` ist die Job-Queue mit `SELECT ... FOR UPDATE SKIP LOCKED`-
#   Pickup-Pattern und drei Partial-Indizes (Pickup, Stale, Server-Lookup).
# - `llm_risk_cache` Cache-Key ist SHA256-hex (64 chars), Fingerprint-Felder
#   bleiben 16-char-Truncates fuer Inspection.
# ---------------------------------------------------------------------------


class ApplicationGroup(Base):
    """Owner-Application-Group fuer Findings (k3s, openssh-server, ...).

    Match-Patterns persistieren die Pass-1-LLM-Lernerfahrung. **Bewertung
    wandert ab Block T (ADR-0028) in die Junction-Tabelle
    `application_group_evaluations` mit Composite-PK (group_id, server_id).**
    Diese Klasse haelt nur noch fleet-weite Identitaet + Pattern-Library.

    Pass-2 schreibt seit Block T per UPSERT in die Junction, nicht mehr
    direkt auf diese Zeile. Findings erben ihren Band aus der fuer ihren
    Server zustaendigen Junction-Row (TICKET-002, Composite-Match in
    :mod:`app.services.finding_group_inheritance`).
    """

    __tablename__ = "application_groups"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    label: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    explanation: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Match-Patterns. ARRAY-Felder defaulten zu `[]` damit das Backend immer
    # einen iterierbaren Wert sieht (kein NULL-vs-empty-Edge-Case).
    path_prefixes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    pkg_name_exact: Mapped[list[str]] = mapped_column(
        ARRAY(String(256)), nullable=False, default=list
    )
    pkg_name_glob: Mapped[list[str]] = mapped_column(
        ARRAY(String(256)), nullable=False, default=list
    )
    pkg_purl_pattern: Mapped[list[str]] = mapped_column(
        ARRAY(String(512)), nullable=False, default=list
    )

    # v0.9.3 (ADR-0023 §Update v0.9.3): deterministisches ``group_kind``,
    # wird beim Group-Insert aus den ``match_rules`` abgeleitet (siehe
    # :func:`app.services.group_matcher.derive_group_kind`). Trennt
    # OS-Pakete (``apt``/``dnf upgrade`` reicht) von Application-Bundles
    # (Vendor-Update noetig).
    group_kind: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Lifecycle / Audit.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="llm")
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="application_group")
    evaluations: Mapped[list[ApplicationGroupEvaluation]] = relationship(
        "ApplicationGroupEvaluation",
        back_populates="group",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "source IN ('llm','manual')",
            name="ck_application_groups_source",
        ),
        # v0.9.3: group_kind (deterministisch im Backend aus ``match_rules``
        # abgeleitet). Trennt OS-Pakete (``apt``/``dnf upgrade`` reicht) von
        # Application-Bundles (Vendor-Update noetig).
        CheckConstraint(
            "group_kind IS NULL OR group_kind IN ('application_bundle','os_package')",
            name="ck_application_groups_group_kind",
        ),
    )


class ApplicationGroupEvaluation(Base):
    """Per-(group, server) LLM-Bewertung — Junction-Tabelle (ADR-0028, Block T).

    Loest den last-write-wins-Bug aus ADR-0023: dieselbe Pattern-Group hat
    auf zwei unterschiedlichen Servern unterschiedliche Bewertungen
    (Listener-Profil, Host-Snapshot, Process-Inventar). Composite-PK
    (group_id, server_id) trennt die Bewertungen physisch.

    Pass-2 schreibt hier per UPSERT (``pg_insert().on_conflict_do_update``)
    statt direkt auf ``ApplicationGroup`` zu setzen. Findings erben ihren
    Band aus der fuer ihren Server zustaendigen Junction-Row (Composite-
    Match in :mod:`app.services.finding_group_inheritance`).

    ``worst_finding_id`` ist bewusst KEIN ForeignKey — die Junction-Row
    ueberlebt Finding-Deletes mit stale-Pointer, UI fallback'd auf
    "Worst-Finding nicht mehr vorhanden" (analog der frueheren Logik auf
    ``ApplicationGroup``).
    """

    __tablename__ = "application_group_evaluations"

    group_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("application_groups.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    server_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("servers.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    # Bewertung. ``risk_band`` ist NOT NULL — "Nicht bewertet" wird durch
    # das Fehlen der Zeile ausgedrueckt, nicht durch NULL.
    risk_band: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_band_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    risk_band_source: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'llm'")
    )
    risk_band_computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    worst_finding_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    group_findings_fingerprint: Mapped[str | None] = mapped_column(String(16), nullable=True)
    action_type: Mapped[str | None] = mapped_column(String(16), nullable=True)

    group: Mapped[ApplicationGroup] = relationship("ApplicationGroup", back_populates="evaluations")

    __table_args__ = (
        CheckConstraint(
            "risk_band IN ('escalate','act','mitigate','monitor','noise')",
            name="ck_app_group_evals_band",
        ),
        CheckConstraint(
            "risk_band_source IN ('llm','manual')",
            name="ck_app_group_evals_source",
        ),
        CheckConstraint(
            "action_type IS NULL OR action_type IN "
            "('patch','mitigate','watch','none','investigate')",
            name="ck_app_group_evals_action_type",
        ),
        Index(
            "ix_app_group_evals_server",
            "server_id",
            "risk_band",
        ),
        Index(
            "ix_app_group_evals_worst_finding",
            "worst_finding_id",
            postgresql_where=text("worst_finding_id IS NOT NULL"),
        ),
    )


class LLMJob(Base):
    """Asynchrone LLM-Job-Queue (Pass 1 Group-Detection / Pass 2 Risk-Eval).

    Pickup-Pattern: `SELECT ... FROM llm_jobs WHERE status='queued' AND
    next_attempt_at <= now() ORDER BY created_at LIMIT 1 FOR UPDATE SKIP
    LOCKED`. `depends_on` modelliert Pass-2-wartet-auf-Pass-1 (ON DELETE
    SET NULL — wenn der Parent-Job geloescht wird, bleiben Kinder mit
    `depends_on = NULL` lebend, koennen also direkt picken).
    """

    __tablename__ = "llm_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    server_id: Mapped[int | None] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    depends_on: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("llm_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    picked_up_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    picked_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "job_type IN ('group_detection','risk_evaluation')",
            name="ck_llm_jobs_type",
        ),
        CheckConstraint(
            "status IN ('queued','in_progress','done','failed')",
            name="ck_llm_jobs_status",
        ),
        CheckConstraint("attempts >= 0", name="ck_llm_jobs_attempts"),
        # Pickup-Index — Partial auf `queued`, deckt die heisseste Query.
        Index(
            "ix_llm_jobs_pickup",
            "status",
            "next_attempt_at",
            postgresql_where="status = 'queued'",
        ),
        # Stale-Reaper-Index — Partial auf `in_progress`.
        Index(
            "ix_llm_jobs_stale",
            "status",
            "picked_up_at",
            postgresql_where="status = 'in_progress'",
        ),
        # Server-Aufschluesselung fuer UI-Stats.
        Index("ix_llm_jobs_server", "server_id", "status"),
    )


class LLMRiskCache(Base):
    """Pass-2-Result-Cache mit `(group_id, group_findings_fp, cve_data_fp,
    server_context_fp)`-Key. TTL 30 Tage (Read-Side), LRU bei > 100K Rows.

    `cache_key` ist SHA256-hex (64 chars) ueber die vier Inputs; die drei
    fp-Spalten bleiben truncate-16-chars fuer DB-Inspection.
    """

    __tablename__ = "llm_risk_cache"

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("application_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    group_findings_fp: Mapped[str] = mapped_column(String(16), nullable=False)
    cve_data_fp: Mapped[str] = mapped_column(String(16), nullable=False)
    server_context_fp: Mapped[str] = mapped_column(String(16), nullable=False)

    risk_band: Mapped[str] = mapped_column(String(16), nullable=False)
    # v0.9.3: spiegelt :attr:`ApplicationGroup.action_type` damit der Cache
    # selbsterklaerend ist und ein Restore aus dem Cache das Feld korrekt
    # zurueck-applied. Nullable fuer Forward-Compat mit Pre-v0.9.3-Eintraegen.
    action_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # `worst_finding_id` bewusst kein FK (Finding-Lifecycle entkoppelt).
    worst_finding_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    llm_model: Mapped[str | None] = mapped_column(String(64), nullable=True)

    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    used_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # Auch hier nur die finalen LLM-Bands.
        CheckConstraint(
            "risk_band IN ('escalate','act','mitigate','monitor','noise')",
            name="ck_llm_risk_cache_band",
        ),
        CheckConstraint(
            "action_type IS NULL OR action_type IN ('patch','mitigate','watch','none')",
            name="ck_llm_risk_cache_action_type",
        ),
        Index("ix_llm_risk_cache_lru", "last_used_at"),
        Index("ix_llm_risk_cache_group", "group_id"),
    )


class ScanIngestJob(Base):
    """Transit-Queue fuer asynchronen Scan-Ingest (ADR-0026).

    `payload_gzip` ist reiner Durchlauf-Speicher: der Worker setzt die Spalte
    atomar mit status='done' auf NULL. Bei status='failed' bleibt der Payload
    max. 24h fuer Operator-Debugging erhalten, danach entfernt der Retention-
    Sweep die gesamte Zeile. Langfristige Persistenz des Roh-JSON ist bewusst
    ausgeschlossen (ADR-0005-Transit-Ausnahme, ADR-0026 §Bedrohungsmodell).
    """

    __tablename__ = "scan_ingest_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    server_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("servers.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Gzip-komprimierter Decompressed-Body. NULL nach status='done' (atomar
    # gesetzt) oder nach Retention-Sweep. STORAGE EXTERNAL in der Migration.
    payload_gzip: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    picked_up_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    picked_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )

    server: Mapped[Server] = relationship("Server")
    scan: Mapped[Scan | None] = relationship("Scan")

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','in_progress','done','failed')",
            name="ck_scan_ingest_jobs_status",
        ),
        CheckConstraint(
            "attempts >= 0",
            name="ck_scan_ingest_jobs_attempts",
        ),
        # Pickup-Index — Partial auf queued, deckt die heisseste Worker-Query.
        Index(
            "ix_scan_ingest_jobs_pickup",
            "next_attempt_at",
            "created_at",
            postgresql_where="status = 'queued'",
        ),
        # Stale-Reaper-Index — Partial auf in_progress.
        Index(
            "ix_scan_ingest_jobs_stale",
            "picked_up_at",
            postgresql_where="status = 'in_progress'",
        ),
        # Server-Aufschluesselung fuer Status-Endpoint und Per-Server-Cap-Check.
        Index("ix_scan_ingest_jobs_server", "server_id", "status"),
    )


class LLMDebugLog(Base):
    """Operator-Debugging-Log fuer LLM-Job-Request/Response-Bodies (v0.9.3).

    Pro LLM-Call eine Row mit dem (gecappten) Request- und Response-Body
    plus Reasoning-Feld und Status. Eviction laeuft im Worker als Sub-Tick
    (Count-Cap + Time-Cap, siehe ADR-0023 §"(e) LLM-Debug-Log-Tabelle").

    Alle drei FKs sind ``ON DELETE SET NULL`` — der Debug-Log soll den
    Lifecycle der referenzierten Entitaeten ueberleben (Job-Cleanup,
    Group-Loeschung, Server-Loeschung). FK-NULL ist akzeptabler Datenfall:
    Operator sieht den Debug-Eintrag mit ``-`` als Referenz-Spalte.
    """

    __tablename__ = "llm_debug_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    job_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("llm_jobs.id", ondelete="SET NULL"), nullable=True
    )
    server_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )
    group_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("application_groups.id", ondelete="SET NULL"), nullable=True
    )
    model: Mapped[str] = mapped_column(String(64), nullable=False)
    request_body: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    response_body: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('success','failed','timeout','validation_error')",
            name="ck_llm_debug_log_status",
        ),
        Index("ix_llm_debug_log_created", "created_at"),
        Index("ix_llm_debug_log_job_type", "job_type", "created_at"),
        Index(
            "ix_llm_debug_log_group",
            "group_id",
            postgresql_where=text("group_id IS NOT NULL"),
        ),
    )


# ---------------------------------------------------------------------------
# Block Q (ADR-0024) — External EPSS/KEV Enrichment.
#
# Drei Server-Side-Feed-Tabellen die der ``feed_enrichment``-Worker-Sub-Tick
# einmal taeglich aus den offiziellen Feeds (FIRST.org / CISA) befuellt. Die
# Anreicherung selbst (Ingest-Lookup + Backfill) ist Phase 2/3, hier nur das
# Datenmodell und die UPSERT-Targets.
# ---------------------------------------------------------------------------


class EpssScore(Base):
    """EPSS-Score pro CVE — Daily-Snapshot von FIRST.org.

    ``epss_score`` und ``epss_percentile`` sind beide in [0.0, 1.0] und werden
    per Check-Constraint validiert (Defense-in-Depth gegen einen kaputten
    Feed-Pull). PK ist ``cve_id`` — pro CVE genau ein Score, UPSERT auf
    Konflikt.
    """

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    epss_percentile: Mapped[float] = mapped_column(Float, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "epss_score >= 0.0 AND epss_score <= 1.0 "
            "AND epss_percentile >= 0.0 AND epss_percentile <= 1.0",
            name="ck_epss_scores_range",
        ),
    )


class CisaKevCatalog(Base):
    """CISA-KEV-Eintrag pro CVE.

    Spalten 1:1 nach ADR-0024 §"Neue DB-Tabellen". ``date_added`` ist NOT
    NULL (CISA fuellt das immer), ``due_date`` und alle Vendor-/Text-Felder
    sind nullable damit kuenftige CISA-Schema-Aenderungen (z.B. eine Pflicht-
    Spalte verschwindet) den Pull nicht killen.
    """

    __tablename__ = "cisa_kev_catalog"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor_project: Mapped[str | None] = mapped_column(String(256), nullable=True)
    product: Mapped[str | None] = mapped_column(String(256), nullable=True)
    vulnerability_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    short_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    known_ransomware: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class FeedPullLog(Base):
    """Audit-Eintrag pro Feed-Pull-Attempt (success/failure).

    Wird vom ``feed_enrichment``-Worker pro Pull-Lauf geschrieben. Eviction
    laeuft im selben Sub-Tick (hard-cap 100 Zeilen pro ``feed_name``).
    Status-Whitelist deckt running/success/failed; ``feed_name`` ist
    Whitelist-checked auf die zwei bekannten Feeds.
    """

    __tablename__ = "feed_pull_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    feed_name: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bytes_downloaded: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "feed_name IN ('epss', 'cisa_kev')",
            name="ck_feed_pull_log_name",
        ),
        Index(
            "ix_feed_pull_log_feed_started",
            "feed_name",
            text("started_at DESC"),
        ),
    )


__all__ = [
    "ATTACK_VECTOR_ENUM_NAME",
    "FINDING_CLASS_ENUM_NAME",
    "FINDING_STATUS_ENUM_NAME",
    "FINDING_TYPE_ENUM_NAME",
    "SEVERITY_ENUM_NAME",
    "ApplicationGroup",
    "ApplicationGroupEvaluation",
    "AttackVector",
    "AuditEvent",
    "Base",
    "CisaKevCatalog",
    "EpssScore",
    "FeedPullLog",
    "Finding",
    "FindingClass",
    "FindingNote",
    "FindingStatus",
    "FindingType",
    "LLMDebugLog",
    "LLMJob",
    "LLMRiskCache",
    "Scan",
    "ScanIngestJob",
    "Server",
    "ServerGroup",
    "ServerKernelModule",
    "ServerListener",
    "ServerProcess",
    "ServerService",
    "ServerTag",
    "Setting",
    "Severity",
    "Tag",
    "User",
]
