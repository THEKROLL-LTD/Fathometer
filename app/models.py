"""SQLAlchemy-Models fuer secscan.

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
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
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


class LlmConversationStatus(enum.StrEnum):
    """Lebenszyklus einer LLM-Conversation."""

    ACTIVE = "active"
    ARCHIVED = "archived"


class LlmMessageRole(enum.StrEnum):
    """Chat-Rolle einer LLM-Message."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


# Postgres-Enum-Typnamen — exakt so in der Migration erzeugt.
SEVERITY_ENUM_NAME = "severity"
FINDING_TYPE_ENUM_NAME = "finding_type"
FINDING_CLASS_ENUM_NAME = "finding_class"
FINDING_STATUS_ENUM_NAME = "finding_status"
ATTACK_VECTOR_ENUM_NAME = "attack_vector"
LLM_CONVERSATION_STATUS_ENUM_NAME = "llm_conversation_status"
LLM_MESSAGE_ROLE_ENUM_NAME = "llm_message_role"


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

    # Trivy-DB-Frische.
    trivy_db_version: Mapped[str | None] = mapped_column(String(64))
    trivy_db_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scans: Mapped[list[Scan]] = relationship(
        "Scan", back_populates="server", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding", back_populates="server", cascade="all, delete-orphan"
    )
    tag_links: Mapped[list[ServerTag]] = relationship(
        "ServerTag", back_populates="server", cascade="all, delete-orphan"
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

    server: Mapped[Server] = relationship("Server", back_populates="findings")
    notes: Mapped[list[FindingNote]] = relationship(
        "FindingNote", back_populates="finding", cascade="all, delete-orphan"
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
# LLM-Tabellen — Schema komplett vorhanden, UI/Logik kommt in Block G.
# ---------------------------------------------------------------------------


class LlmConversation(Base):
    __tablename__ = "llm_conversations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_message_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[LlmConversationStatus] = mapped_column(
        _pg_enum(LlmConversationStatus, LLM_CONVERSATION_STATUS_ENUM_NAME),
        nullable=False,
        default=LlmConversationStatus.ACTIVE,
    )
    findings_snapshot_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    messages: Mapped[list[LlmMessage]] = relationship(
        "LlmMessage", back_populates="conversation", cascade="all, delete-orphan"
    )
    finding_links: Mapped[list[LlmConversationFinding]] = relationship(
        "LlmConversationFinding",
        back_populates="conversation",
        cascade="all, delete-orphan",
    )


class LlmMessage(Base):
    __tablename__ = "llm_messages"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    conversation_id: Mapped[int] = mapped_column(
        ForeignKey("llm_conversations.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[LlmMessageRole] = mapped_column(
        _pg_enum(LlmMessageRole, LLM_MESSAGE_ROLE_ENUM_NAME), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)

    conversation: Mapped[LlmConversation] = relationship(
        "LlmConversation", back_populates="messages"
    )


class LlmConversationFinding(Base):
    __tablename__ = "llm_conversation_findings"

    conversation_id: Mapped[int] = mapped_column(
        ForeignKey("llm_conversations.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    severity_at_send: Mapped[Severity] = mapped_column(
        _pg_enum(Severity, SEVERITY_ENUM_NAME), nullable=False
    )
    cvss_v3_score_at_send: Mapped[float | None] = mapped_column(Float)
    epss_score_at_send: Mapped[float | None] = mapped_column(Float)
    is_kev_at_send: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    conversation: Mapped[LlmConversation] = relationship(
        "LlmConversation", back_populates="finding_links"
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
    default_theme: Mapped[str] = mapped_column(String(8), nullable=False, default="auto")

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

    __table_args__ = (
        CheckConstraint("id = 1", name="ck_settings_singleton"),
        CheckConstraint(
            "default_theme IN ('light', 'dark', 'auto')",
            name="ck_settings_theme",
        ),
    )


__all__ = [
    "ATTACK_VECTOR_ENUM_NAME",
    "FINDING_CLASS_ENUM_NAME",
    "FINDING_STATUS_ENUM_NAME",
    "FINDING_TYPE_ENUM_NAME",
    "LLM_CONVERSATION_STATUS_ENUM_NAME",
    "LLM_MESSAGE_ROLE_ENUM_NAME",
    "SEVERITY_ENUM_NAME",
    "AttackVector",
    "AuditEvent",
    "Base",
    "Finding",
    "FindingClass",
    "FindingNote",
    "FindingStatus",
    "FindingType",
    "LlmConversation",
    "LlmConversationFinding",
    "LlmConversationStatus",
    "LlmMessage",
    "LlmMessageRole",
    "Scan",
    "Server",
    "ServerTag",
    "Setting",
    "Severity",
    "Tag",
    "User",
]
