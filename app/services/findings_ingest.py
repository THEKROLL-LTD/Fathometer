"""Findings-Ingest: Pydantic-Envelope -> normalisierte DB-Zeilen.

Aufgaben (siehe ARCHITECTURE.md §5 und §6):

1. Pro Vulnerability im Envelope ein Finding-Row bauen.
2. **Dedup-Upsert** auf `(server_id, finding_type, identifier_key, package_name)`
   via Postgres `INSERT ... ON CONFLICT DO UPDATE`.
3. **Resolve-Phase**: alle OPEN/ACKNOWLEDGED Findings dieses Servers die nicht
   im aktuellen Scan-Set sind -> RESOLVED.
4. Trivy-DB-Frische aus `scan.Metadata.DataSource` und `scan.Metadata.UpdatedAt`
   extrahieren und in `servers` denormalisieren (plus `last_scan_at`).
5. `Scan`-Buchhaltungs-Row anlegen (kein Roh-JSON — ADR-0005).

Performance: bulk-Insert mit ON CONFLICT in EINER Statement-Round. Bei 306
Vulns muss das in <5s durchlaufen (DoD von Block C).

Idempotenz: zweimal denselben Scan -> keine Duplikate (UNIQUE-Constraint).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import (
    AttackVector,
    CisaKevCatalog,
    EpssScore,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Scan,
    Server,
    Severity,
)
from app.schemas.scan_envelope import (
    Envelope,
    TrivyResult,
    TrivyVulnerability,
)
from app.services.risk_engine import normalize_vendor_status

log = structlog.get_logger(__name__)


# Postgres-Hard-Limit fuer Bind-Parameter pro Query: 65535 (uint16). Eine
# Finding-Row bindet ~27 Spalten (nach Block N) — wir batchen daher in
# 1000er-Schritten und haben damit ~27000 Parameter pro Statement, also
# komfortabel unter dem Limit auch wenn weitere Spalten dazukommen.
FINDINGS_INSERT_CHUNK_SIZE = 1000


# ---------------------------------------------------------------------------
# Ergebnis-Datenstruktur
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScanIngestResult:
    """Zusammenfassung eines erfolgreichen Ingest-Laufs."""

    scan_id: int
    received_at: datetime
    findings_total: int
    findings_inserted: int
    findings_updated: int
    findings_resolved: int
    findings_class_os_pkgs: int
    findings_class_lang_pkgs: int
    findings_class_other: int


# ---------------------------------------------------------------------------
# Hilfen
# ---------------------------------------------------------------------------


_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.UNKNOWN,
}

_ATTACK_VECTOR_MAP: dict[str, AttackVector] = {
    "network": AttackVector.NETWORK,
    "adjacent": AttackVector.ADJACENT,
    "local": AttackVector.LOCAL,
    "physical": AttackVector.PHYSICAL,
    "unknown": AttackVector.UNKNOWN,
}

_CLASS_MAP: dict[str, FindingClass] = {
    "os-pkgs": FindingClass.OS_PKGS,
    "lang-pkgs": FindingClass.LANG_PKGS,
    "other": FindingClass.OTHER,
}


def _safe_vuln(raw_vuln: Any, *, server_name: str) -> TrivyVulnerability | None:
    """Versucht einen rohen Vuln-Dict in `TrivyVulnerability` zu parsen.

    Ein einzelner Validation-Fail killt nicht den ganzen Scan — Pro-Vuln-
    Fehler werden geloggt und das Item verworfen. Top-Level-Fehler dagegen
    sind durch das Envelope-Parsing schon abgefangen.
    """
    try:
        return TrivyVulnerability.model_validate(raw_vuln)
    except (ValueError, TypeError) as exc:
        log.info(
            "ingest.vuln_validation_failed",
            server=server_name,
            error=str(exc)[:200],
        )
        return None


def _extract_trivy_db_meta(envelope: Envelope) -> tuple[str | None, datetime | None]:
    """Liest Trivy-DB-Version und UpdatedAt aus Envelope oder Metadata-Fallback.

    Bevorzugt den ``envelope.trivy_db``-Top-Level-Block (Agent >= 0.3.1),
    faellt fuer alte Agents auf ``envelope.scan.metadata.data_source``
    zurueck.

    Hinweis Legacy-Fallback: ``metadata.data_source.name``/``.id`` liefert
    den Vuln-Provider-Namen (z.B. ``"ghsa"``, ``"debian"``), NICHT die
    Trivy-DB-Schema-Version. Das ist ungenau aber besser als NULL —
    sobald der Host auf Agent >= 0.3.1 aktualisiert ist, liefert der Top-
    Level-Block die echte Schema-Version (``"2"``).
    """
    trivy_db_version: str | None = None
    trivy_db_updated_at: datetime | None = None

    if envelope.trivy_db is not None:
        if envelope.trivy_db.version:
            trivy_db_version = envelope.trivy_db.version
        if envelope.trivy_db.updated_at is not None:
            trivy_db_updated_at = envelope.trivy_db.updated_at

    if trivy_db_version is None or trivy_db_updated_at is None:
        metadata = envelope.scan.metadata
        if metadata is not None:
            if trivy_db_version is None and metadata.data_source is not None:
                trivy_db_version = metadata.data_source.name or metadata.data_source.id
            if trivy_db_updated_at is None and metadata.updated_at is not None:
                trivy_db_updated_at = metadata.updated_at

    return trivy_db_version, trivy_db_updated_at


_TARGET_MAX_LEN = 160  # bleibt mit pkg_name unter 256.


def _effective_target_path(vuln: TrivyVulnerability, result: TrivyResult) -> str | None:
    """Bevorzugt ``Vulnerability.PkgPath`` ueber ``Result.Target``.

    Trivy liefert den per-Finding-Pfad an unterschiedlichen Stellen je
    Analyzer-Familie:

    * File-Level-Analyzer (``gobinary``, ``jar``, ``pyinstaller``, alle
      ``os-pkgs``-Typen) tragen den Pfad bzw. den Hostnamen im
      ``Result.Target``-Feld; ``Vulnerability.PkgPath`` ist hier meist leer.
    * Walker-Analyzer fuer Sprach-Paketmanager (``node-pkg``, ``python-pkg``,
      ``gemspec``, ``cargo``, ...) aggregieren alle Funde eines Oekosystems
      in einem einzigen ``Result`` und setzen ``Result.Target`` nur auf den
      Oekosystem-Namen (z.B. ``"Node.js"``). Die echte Per-Paket-Location
      steht dann ausschliesslich in ``Vulnerability.PkgPath``.

    Diese Funktion bevorzugt ``PkgPath`` wann immer Trivy ihn liefert, ohne
    Type-Listen zu pflegen — ``PkgPath`` ist per Konstruktion praeziser als
    ``Target``. Fehlt ``PkgPath``, fallen wir auf ``Result.Target`` zurueck
    (alter Standard).
    """
    pkg_path = (vuln.pkg_path or "").strip()
    if pkg_path:
        return pkg_path
    return result.target


def _extract_cause_fields(vuln: TrivyVulnerability, result: TrivyResult) -> dict[str, Any]:
    """Block N (ADR-0021): zieht die fuenf Ursachen-Felder pro Finding.

    Wird sowohl bei Insert als auch bei Update gesetzt — wenn ein Feld jetzt
    `None` ist und vorher gefuellt war, wird die DB-Spalte auf NULL
    aktualisiert. Bewusst: der aktuelle Scan ist die Quelle der Wahrheit,
    historische Werte werden nicht bewahrt.
    """
    return {
        "package_purl": vuln.package_purl,
        "target_path": _effective_target_path(vuln, result),
        "result_type": result.type_,
        "severity_source": vuln.severity_source,
        "vendor_ids": vuln.vendor_ids,
        # Block O (ADR-0022): Vendor-Status (`will_not_fix`/`eol`/...) und
        # Provider-Severity-Map (`VendorSeverity`). Beide werden bei jedem
        # Re-Ingest geschrieben — fehlende Felder im aktuellen Scan setzen
        # die Spalten auf NULL (Quelle der Wahrheit ist der aktuelle Scan).
        # `vendor_severity` ist im Envelope-Pre-Validator bereits zu
        # lowercase-Strings normalisiert (numerische Trivy-Severities werden
        # ueber `VENDOR_SEVERITY_INT_MAP` aufgeloest), wir schreiben das
        # Dict direkt durch.
        "vendor_status": normalize_vendor_status(vuln.status),
        "severity_by_provider": dict(vuln.vendor_severity) if vuln.vendor_severity else None,
    }


def _disambiguated_package_name(
    pkg_name: str, target: str | None, finding_class: FindingClass
) -> str:
    """Baut den `package_name`-Wert, der den UNIQUE-Constraint disambiguiert.

    Trivy meldet dieselbe `(CVE, PkgName)`-Kombination oft mehrfach auf
    verschiedenen `Target`-Werten (z.B. `stdlib`-CVEs in mehreren Go-Binaries
    auf demselben Server). Wir haengen den `Target` an den `package_name`
    fuer `lang-pkgs`-Findings — bei `os-pkgs` ist `Target` immer der
    Hostname und tragen keine Information, deshalb ohne Suffix.

    Pragmatische Abweichung von §5 — siehe Bericht im Block C.
    Alternative waere eine Schema-Erweiterung mit eigener `target`-Spalte,
    was aber eine Migration ueber den Block-C-Scope hinaus waere.
    """
    if finding_class != FindingClass.LANG_PKGS or not target or target.strip() == "":
        return pkg_name
    target_short = target[:_TARGET_MAX_LEN]
    return f"{pkg_name}@{target_short}"


def _build_finding_row(
    *,
    server_id: int,
    vuln: TrivyVulnerability,
    finding_class: FindingClass,
    target: str | None,
    result: TrivyResult,
    now: datetime,
) -> dict[str, Any]:
    """Erzeugt das dict fuer den Bulk-Insert einer Finding-Zeile."""
    cvss_score, cvss_vector = vuln.best_cvss_v3()
    attack_vector_str = vuln.attack_vector_from_cvss()
    severity = _SEVERITY_MAP[vuln.severity]
    # ADR-0011-Erweiterung (Bugfix 2026-05-24): Disambiguator nutzt denselben
    # bevorzugten Per-Finding-Pfad wie `target_path`, damit `Result.Target=
    # "Node.js"` nicht alle `vite`-Findings derselben Server-Row auf denselben
    # `package_name="vite@Node.js"` kollabiert (UNIQUE-Constraint-Kollision)
    # und die DB-Spalte mit dem Disambiguator drift-frei bleibt.
    effective_target = _effective_target_path(vuln, result) or target
    pkg_disamb = _disambiguated_package_name(vuln.pkg_name, effective_target, finding_class)
    cause = _extract_cause_fields(vuln, result)

    return {
        "server_id": server_id,
        "finding_type": FindingType.VULNERABILITY.value,
        "finding_class": finding_class.value,
        "identifier_key": vuln.vulnerability_id,
        "package_name": pkg_disamb,
        "installed_version": vuln.installed_version,
        "fixed_version": vuln.fixed_version,
        "severity": severity.value,
        "title": vuln.title,
        "description": vuln.description,
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "epss_score": vuln.epss.score if vuln.epss else None,
        "epss_percentile": vuln.epss.percentile if vuln.epss else None,
        "is_kev": bool(vuln.is_kev_hint),
        "kev_added_at": vuln.kev_added_at,
        "cwe_ids": vuln.cwe_ids or None,
        "attack_vector": _ATTACK_VECTOR_MAP[attack_vector_str].value,
        "references": vuln.references or None,
        # Block N (ADR-0021) — Ursachen-Felder.
        "package_purl": cause["package_purl"],
        "target_path": cause["target_path"],
        "result_type": cause["result_type"],
        "severity_source": cause["severity_source"],
        "vendor_ids": cause["vendor_ids"],
        # Block O (ADR-0022) — Vendor-Status + Provider-Severity-Map.
        "vendor_status": cause["vendor_status"],
        "severity_by_provider": cause["severity_by_provider"],
        "status": FindingStatus.OPEN.value,
        "first_seen_at": now,
        "last_seen_at": now,
    }


# ---------------------------------------------------------------------------
# EPSS/KEV-Anreicherung (Block Q, ADR-0024)
# ---------------------------------------------------------------------------


def _enrich_with_feeds(session: Session, rows: list[dict[str, Any]]) -> None:
    """Reichert Findings-Rows in-place mit EPSS- und KEV-Daten an.

    Liest aus den Server-seitigen Feed-Tabellen (``epss_scores``,
    ``cisa_kev_catalog``) per Bulk-IN-Lookup. Felder die im Lookup
    getroffen werden ueberschreiben die vom Scanner gelieferten Werte —
    unsere Feed-Pulls sind die autoritative Quelle (siehe ADR-0024
    §"Geklaerte Design-Entscheidungen" Punkt 2).

    Nicht-CVE-Identifiers (GHSA-, RHSA-, ...) bleiben unberuehrt; fuer
    sie gibt es keine EPSS/KEV-Quellen.
    """
    cve_ids = {
        row["identifier_key"]
        for row in rows
        if isinstance(row.get("identifier_key"), str) and row["identifier_key"].startswith("CVE-")
    }
    if not cve_ids:
        return

    epss_map: dict[str, EpssScore] = {
        r.cve_id: r for r in session.scalars(select(EpssScore).where(EpssScore.cve_id.in_(cve_ids)))
    }
    kev_map: dict[str, CisaKevCatalog] = {
        r.cve_id: r
        for r in session.scalars(select(CisaKevCatalog).where(CisaKevCatalog.cve_id.in_(cve_ids)))
    }

    if not epss_map and not kev_map:
        return

    for row in rows:
        cve = row.get("identifier_key")
        if not isinstance(cve, str) or not cve.startswith("CVE-"):
            continue
        if (e := epss_map.get(cve)) is not None:
            row["epss_score"] = e.epss_score
            row["epss_percentile"] = e.epss_percentile
        if (k := kev_map.get(cve)) is not None:
            row["is_kev"] = True
            # ``kev_added_at`` ist Timestamp tz; CISA liefert nur Date.
            # Auf 00:00 UTC normieren — konsistent mit dem bestehenden
            # ``Finding.kev_added_at``-Spalten-Semantik.
            row["kev_added_at"] = datetime.combine(k.date_added, datetime.min.time(), tzinfo=UTC)


# ---------------------------------------------------------------------------
# Haupt-Entry-Point
# ---------------------------------------------------------------------------


def ingest_scan(
    server: Server,
    envelope: Envelope,
    *,
    session: Session,
    now: datetime | None = None,
) -> ScanIngestResult:
    """Persistiert einen Scan-Envelope: Findings, Resolve, Server-Felder, Scan-Row.

    Wirft `RuntimeError` wenn die Anzahl der eindeutigen `(identifier_key,
    package_name)`-Paare die DoS-Schranke (MAX_VULNS_PER_SCAN) ueberschreitet
    — das passiert in der Praxis nicht, weil das Pydantic-Schema das bereits
    aggregiert. Doppel-Check hier ist Defense-in-Depth.

    Idempotent: zweimal denselben Envelope -> selbe DB-Zustaende.
    """
    now = now or datetime.now(tz=UTC)
    server_id = server.id

    # ---- 1. Findings-Zeilen aus dem Envelope bauen --------------------
    rows: list[dict[str, Any]] = []
    current_keys: set[tuple[str, str]] = set()
    class_counter: dict[FindingClass, int] = {
        FindingClass.OS_PKGS: 0,
        FindingClass.LANG_PKGS: 0,
        FindingClass.OTHER: 0,
    }

    for trivy_result in envelope.scan.results:
        finding_class = _CLASS_MAP[trivy_result.normalized_class()]
        target = trivy_result.target
        for raw_vuln in trivy_result.vulnerabilities or []:
            # `raw_vuln` ist bereits durch Pydantic gelaufen — aber wir
            # verwerfen per-Vuln-Fehler nochmal als Sicherheits-Netz.
            vuln = _safe_vuln(raw_vuln, server_name=server.name)
            if vuln is None:
                continue

            pkg_disamb = _disambiguated_package_name(vuln.pkg_name, target, finding_class)
            key = (vuln.vulnerability_id, pkg_disamb)
            if key in current_keys:
                # Innerhalb eines Scans dieselbe Kombination doppelt -> ignorieren.
                continue
            current_keys.add(key)

            rows.append(
                _build_finding_row(
                    server_id=server_id,
                    vuln=vuln,
                    finding_class=finding_class,
                    target=target,
                    result=trivy_result,
                    now=now,
                )
            )
            class_counter[finding_class] += 1

    findings_total = len(rows)

    # ---- 1b. EPSS/KEV-Anreicherung (Block Q, ADR-0024) ----------------
    # Vor dem Bulk-Upsert die Server-seitigen Feed-Tabellen konsultieren.
    # Trifft pro Scan einen einzelnen IN-Lookup je Feed; bei ~5000 Findings
    # sind das ~5000 CVE-IDs in einer Query, voellig unkritisch.
    _enrich_with_feeds(session, rows)

    # ---- 2. Bulk-Upsert via INSERT ... ON CONFLICT --------------------
    # `ON CONFLICT` auf dem Unique-Constraint `uq_findings_natural_key`.
    # Felder die wir bei Update aktualisieren: alles ausser `status`,
    # `first_seen_at`, `acknowledged_at`, `acknowledged_by`, `resolved_at`.
    inserted_count = 0
    updated_count = 0

    if rows:
        # Postgres-Limit: max 65535 Bind-Parameter pro Query. Bei ~27 Spalten
        # pro Row passt das fuer ~2400 Rows; ein grosser Server-Scan (Ubuntu
        # /-Root) liefert aber leicht 5000+ Findings. Daher in Batches von
        # FINDINGS_INSERT_CHUNK_SIZE Rows upserten und Ergebnisse aggregieren.
        for chunk_start in range(0, len(rows), FINDINGS_INSERT_CHUNK_SIZE):
            chunk = rows[chunk_start : chunk_start + FINDINGS_INSERT_CHUNK_SIZE]
            stmt = pg_insert(Finding).values(chunk)
            update_cols: dict[str, Any] = {
                "installed_version": stmt.excluded.installed_version,
                "fixed_version": stmt.excluded.fixed_version,
                "severity": stmt.excluded.severity,
                "title": stmt.excluded.title,
                "description": stmt.excluded.description,
                "cvss_v3_score": stmt.excluded.cvss_v3_score,
                "cvss_v3_vector": stmt.excluded.cvss_v3_vector,
                "epss_score": stmt.excluded.epss_score,
                "epss_percentile": stmt.excluded.epss_percentile,
                "is_kev": stmt.excluded.is_kev,
                "kev_added_at": stmt.excluded.kev_added_at,
                "cwe_ids": stmt.excluded.cwe_ids,
                "attack_vector": stmt.excluded.attack_vector,
                "references": stmt.excluded.references,
                "last_seen_at": stmt.excluded.last_seen_at,
                "finding_class": stmt.excluded.finding_class,
                # Block N (ADR-0021) — Ursachen-Felder: bei jedem Re-Ingest
                # ueberschreiben (auch auf NULL), aktueller Scan ist Quelle
                # der Wahrheit.
                "package_purl": stmt.excluded.package_purl,
                "target_path": stmt.excluded.target_path,
                "result_type": stmt.excluded.result_type,
                "severity_source": stmt.excluded.severity_source,
                "vendor_ids": stmt.excluded.vendor_ids,
                # Block O (ADR-0022) — Vendor-Status + Provider-Severity-Map.
                # Quelle der Wahrheit ist der aktuelle Scan, fehlende Felder
                # ueberschreiben mit NULL.
                "vendor_status": stmt.excluded.vendor_status,
                "severity_by_provider": stmt.excluded.severity_by_provider,
            }
            upsert = stmt.on_conflict_do_update(
                constraint="uq_findings_natural_key",
                set_=update_cols,
            ).returning(Finding.id, Finding.first_seen_at)

            upsert_result = session.execute(upsert)
            # Heuristik: wenn `first_seen_at == now` ist, war es ein Insert.
            # `now` ist eindeutig (Pydantic gibt einen Mikrosekunden-Stempel)
            # — aber praktischer ist: wir vergleichen `first_seen_at` mit
            # `now` mit Toleranz. Wir benutzen RETURNING-Daten:
            for _row_id, first_seen in upsert_result.all():
                # Wenn first_seen_at innerhalb der letzten Sekunde -> Insert.
                if first_seen and abs((first_seen - now).total_seconds()) < 1.0:
                    inserted_count += 1
                else:
                    updated_count += 1

    # ---- 3. Resolve-Phase: alles was OPEN/ACK aber nicht im Scan war ----
    resolved_count = 0
    if rows:
        # WICHTIG: identifier_key UND package_name muessen matchen (Composite-
        # Key). SQLAlchemy unterstuetzt das via Tuple-IN nicht trivial; wir
        # nutzen NOT EXISTS-Subquery oder bauen einen JSON-Trick. Pragmatisch:
        # SELECT IDs der zu resolvenden Findings via Python-Filter, dann UPDATE.
        existing = session.execute(
            select(
                Finding.id,
                Finding.identifier_key,
                Finding.package_name,
            ).where(
                Finding.server_id == server_id,
                Finding.finding_type == FindingType.VULNERABILITY,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED]),
            )
        ).all()
        ids_to_resolve = [
            row.id for row in existing if (row.identifier_key, row.package_name) not in current_keys
        ]
        if ids_to_resolve:
            session.execute(
                update(Finding)
                .where(Finding.id.in_(ids_to_resolve))
                .values(status=FindingStatus.RESOLVED, resolved_at=now)
            )
            resolved_count = len(ids_to_resolve)

    # ---- 4. Server-Felder denormalisieren -----------------------------
    trivy_version: str | None = None
    if envelope.scan.trivy is not None:
        trivy_version = envelope.scan.trivy.version

    trivy_db_version, trivy_db_updated_at = _extract_trivy_db_meta(envelope)

    server.last_scan_at = now
    server.os_family = envelope.host.os_family
    server.os_version = envelope.host.os_version
    server.os_pretty_name = envelope.host.os_pretty_name
    server.kernel_version = envelope.host.kernel_version
    server.architecture = envelope.host.architecture
    server.agent_version = envelope.agent_version
    # Block N (ADR-0021): zuletzt beobachtete Trivy-CLI-Version aus dem
    # `host`-Block (optional — Agent v0.1.0 sendet das Feld nicht).
    server.trivy_version = envelope.host.trivy_version
    server.agent_version_seen_at = now
    if trivy_db_version is not None:
        server.trivy_db_version = trivy_db_version
    if trivy_db_updated_at is not None:
        server.trivy_db_updated_at = trivy_db_updated_at

    # ---- 5. Scan-Buchhaltungs-Row anlegen -----------------------------
    scan = Scan(
        server_id=server_id,
        received_at=now,
        agent_version=envelope.agent_version,
        trivy_scanner_version=trivy_version,
        trivy_db_version=trivy_db_version,
        trivy_db_updated_at=trivy_db_updated_at,
        os_family=envelope.host.os_family,
        os_version=envelope.host.os_version,
        os_pretty_name=envelope.host.os_pretty_name,
        kernel_version=envelope.host.kernel_version,
        architecture=envelope.host.architecture,
    )
    session.add(scan)
    session.flush()

    return ScanIngestResult(
        scan_id=scan.id,
        received_at=now,
        findings_total=findings_total,
        findings_inserted=inserted_count,
        findings_updated=updated_count,
        findings_resolved=resolved_count,
        findings_class_os_pkgs=class_counter[FindingClass.OS_PKGS],
        findings_class_lang_pkgs=class_counter[FindingClass.LANG_PKGS],
        findings_class_other=class_counter[FindingClass.OTHER],
    )


def server_is_active(server: Server) -> bool:
    """Service-Helper: ist der Server in einem Zustand, der Scans annehmen darf?

    Aktiv = weder `revoked_at` noch `retired_at` gesetzt.
    """
    return server.revoked_at is None and server.retired_at is None


# Unused-Import-Suppression: Wir importieren `TrivyResult` damit die
# `TrivyResult.normalized_class()`-Methode in Type-Checks sichtbar bleibt.
_ = TrivyResult


__all__ = [
    "ScanIngestResult",
    "ingest_scan",
    "server_is_active",
]
