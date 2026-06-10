"""Pure-Unit-Tests fuer die Reopen-Phase in ``ingest_scan`` (TICKET-010, Bug A).

Die Reopen-Logik liegt inline in ``ingest_scan`` (Sektion 1c) — wir testen
sie ohne DB ueber eine Recording-Session, die alle ``execute``-Statements
abfaengt und klassifiziert:

* SELECT der Reopen-Phase (WHERE status = RESOLVED) bekommt konfigurierbare
  Bestands-Rows zurueck.
* UPDATE-Statements werden inkl. kompilierter Bind-Parameter aufgezeichnet
  (welche IDs, welche SET-Werte).
* Der Bulk-Upsert (pg INSERT ... ON CONFLICT) liefert ein leeres
  RETURNING-Set.

Getestete Vertraege (Ticket-Spec Etappe 1):

1. RESOLVED-Finding mit ``(identifier_key, package_name)`` im aktuellen
   Scan-Set → wird reopened (status=open, resolved_at=NULL).
2. RESOLVED-Finding ausserhalb des Sets → nicht reopened.
3. ACK bleibt ACK: die Reopen-SELECT filtert ausschliesslich auf RESOLVED —
   ACKNOWLEDGED kommt im WHERE nicht vor (User-Entscheidung 1, ADR-0052).
4. Leeres Schnittmengen-Set → kein UPDATE.
5. Reopen-UPDATE laeuft VOR dem Bulk-Upsert (sonst wuerde das Upsert den
   ``last_seen_at`` eines noch-RESOLVED-Findings weiterlaufen lassen).
6. ``ScanIngestResult.findings_reopened`` spiegelt die Anzahl reopeneter IDs.

Die echte UPDATE-/Upsert-Semantik gegen Postgres ist db_integration und
steht beim User an (siehe Ticket-DoD).
"""

from __future__ import annotations

from collections import namedtuple
from typing import Any
from unittest.mock import MagicMock

from sqlalchemy import Insert, Select, Update
from sqlalchemy.dialects import postgresql

from app.models import FindingStatus
from app.schemas.scan_envelope import Envelope
from app.services.findings_ingest import ScanIngestResult, ingest_scan

# Row-Shape der Reopen-/Resolve-SELECTs: (id, identifier_key, package_name).
FindingRow = namedtuple("FindingRow", ["id", "identifier_key", "package_name"])


# ---------------------------------------------------------------------------
# Statement-Klassifizierung ueber kompilierte Bind-Parameter (kein Order-
# Coupling — robust gegen zukuenftige zusaetzliche Statements im Service).
# ---------------------------------------------------------------------------


def _compiled_params(stmt: Any) -> dict[str, Any]:
    return dict(stmt.compile(dialect=postgresql.dialect()).params)


def _classify_select(stmt: Any) -> str:
    """Reopen-SELECT filtert status == RESOLVED; Resolve-SELECT status IN (OPEN, ACK)."""
    values = list(_compiled_params(stmt).values())
    for v in values:
        if isinstance(v, (list, tuple)):
            if FindingStatus.OPEN in v or FindingStatus.OPEN.value in v:
                return "select_resolve"
        elif v == FindingStatus.RESOLVED or v == FindingStatus.RESOLVED.value:
            return "select_reopen"
    return "select_other"


def _classify_update(stmt: Any) -> str:
    """Reopen-UPDATE setzt status=open + resolved_at=NULL; Resolve-UPDATE status=resolved."""
    params = _compiled_params(stmt)
    status = params.get("status")
    if status == FindingStatus.OPEN or status == FindingStatus.OPEN.value:
        return "update_reopen"
    if status == FindingStatus.RESOLVED or status == FindingStatus.RESOLVED.value:
        return "update_resolve"
    return "update_other"


def _update_target_ids(stmt: Any) -> list[int]:
    """Extrahiert die ID-Liste aus dem ``WHERE id IN (...)`` eines UPDATEs."""
    for value in _compiled_params(stmt).values():
        if isinstance(value, (list, tuple)):
            return sorted(int(v) for v in value)
    return []


# ---------------------------------------------------------------------------
# Recording-Session
# ---------------------------------------------------------------------------


class RecordingSession:
    """DB-freie Session-Attrappe fuer ``ingest_scan``.

    ``calls`` ist die chronologische Liste ``(kind, stmt)`` aller
    ``execute``-Aufrufe — damit sind sowohl Inhalt (Bind-Parameter) als
    auch Reihenfolge (Reopen vor Upsert) assertierbar.
    """

    def __init__(
        self,
        *,
        resolved_rows: list[FindingRow] | None = None,
        open_ack_rows: list[FindingRow] | None = None,
    ) -> None:
        self._resolved_rows = list(resolved_rows or [])
        self._open_ack_rows = list(open_ack_rows or [])
        self.calls: list[tuple[str, Any]] = []
        self._added: list[Any] = []

    # --- vom Service genutzte API ---------------------------------------

    def scalars(self, stmt: Any) -> list[Any]:
        # Feed-Enrichment (EPSS/KEV): leere Feed-Tabellen.
        return []

    def execute(self, stmt: Any, params: Any = None) -> Any:
        result = MagicMock()
        if isinstance(stmt, Insert):
            self.calls.append(("insert_upsert", stmt))
            result.all.return_value = []  # RETURNING leer → inserted/updated = 0
            return result
        if isinstance(stmt, Update):
            self.calls.append((_classify_update(stmt), stmt))
            return result
        if isinstance(stmt, Select):
            kind = _classify_select(stmt)
            self.calls.append((kind, stmt))
            if kind == "select_reopen":
                result.all.return_value = list(self._resolved_rows)
            elif kind == "select_resolve":
                result.all.return_value = list(self._open_ack_rows)
            else:
                result.all.return_value = []
            return result
        raise AssertionError(f"Unerwartetes Statement an execute(): {stmt!r}")

    def add(self, obj: Any) -> None:
        self._added.append(obj)

    def flush(self) -> None:
        # Simuliert die PK-Vergabe fuer die Scan-Row.
        for obj in self._added:
            if getattr(obj, "id", None) is None:
                obj.id = 4711

    # --- Test-Komfort ----------------------------------------------------

    def kinds(self) -> list[str]:
        return [kind for kind, _stmt in self.calls]

    def updates_of_kind(self, kind: str) -> list[Any]:
        return [stmt for k, stmt in self.calls if k == kind]


# ---------------------------------------------------------------------------
# Envelope-/Server-Fixtures
# ---------------------------------------------------------------------------


def _make_envelope(vulns: list[tuple[str, str]]) -> Envelope:
    """Minimaler Envelope mit os-pkgs-Vulns ``(cve_id, pkg_name)``.

    os-pkgs bewusst: kein ``@target``-Disambiguator im ``package_name``,
    die ``current_keys`` sind damit exakt die uebergebenen Tupel.
    """
    results: list[dict[str, Any]] = []
    if vulns:
        results.append(
            {
                "Target": "testhost",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": cve,
                        "PkgName": pkg,
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                        "Title": f"{cve} in {pkg}",
                    }
                    for cve, pkg in vulns
                ],
            }
        )
    return Envelope.model_validate(
        {
            "agent_version": "0.3.1",
            "host": {
                "os_family": "alpine",
                "os_version": "3.18",
                "os_pretty_name": "Alpine Linux v3.18",
                "kernel_version": "6.1.0",
                "architecture": "x86_64",
            },
            "scan": {"SchemaVersion": 2, "Results": results},
        }
    )


def _make_server() -> MagicMock:
    server = MagicMock()
    server.id = 1
    server.name = "testhost"
    return server


def _run_ingest(session: RecordingSession, vulns: list[tuple[str, str]]) -> ScanIngestResult:
    return ingest_scan(_make_server(), _make_envelope(vulns), session=session)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1+2: Set-Vergleich — Wiedergaenger rein, Nicht-Wiedergaenger draussen
# ---------------------------------------------------------------------------


class TestReopenFilter:
    def test_resolved_finding_in_current_keys_is_reopened(self) -> None:
        """RESOLVED + Key im Scan → genau dieses Finding wird reopened."""
        session = RecordingSession(
            resolved_rows=[FindingRow(101, "CVE-2026-31431", "vsftpd")],
        )
        result = _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        reopen_updates = session.updates_of_kind("update_reopen")
        assert len(reopen_updates) == 1, session.kinds()
        assert _update_target_ids(reopen_updates[0]) == [101]
        assert result.findings_reopened == 1

    def test_resolved_finding_outside_current_keys_stays_resolved(self) -> None:
        """RESOLVED + Key NICHT im Scan → kein Reopen-UPDATE."""
        session = RecordingSession(
            resolved_rows=[FindingRow(102, "CVE-2020-99999", "old-pkg")],
        )
        result = _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        assert session.updates_of_kind("update_reopen") == [], session.kinds()
        assert result.findings_reopened == 0

    def test_mixed_resolved_set_reopens_only_redetected_ids(self) -> None:
        """Gemischter Bestand: nur die Schnittmenge landet im UPDATE."""
        session = RecordingSession(
            resolved_rows=[
                FindingRow(201, "CVE-2026-31431", "vsftpd"),
                FindingRow(202, "CVE-2020-99999", "old-pkg"),
                FindingRow(203, "CVE-2026-11111", "openssl"),
            ],
        )
        result = _run_ingest(
            session,
            [("CVE-2026-31431", "vsftpd"), ("CVE-2026-11111", "openssl")],
        )

        reopen_updates = session.updates_of_kind("update_reopen")
        assert len(reopen_updates) == 1, session.kinds()
        assert _update_target_ids(reopen_updates[0]) == [201, 203]
        assert result.findings_reopened == 2

    def test_composite_key_must_match_both_parts(self) -> None:
        """Gleiche CVE, anderes Paket → KEIN Match (Composite-Key-Vergleich)."""
        session = RecordingSession(
            resolved_rows=[FindingRow(301, "CVE-2026-31431", "proftpd")],
        )
        result = _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        assert session.updates_of_kind("update_reopen") == [], session.kinds()
        assert result.findings_reopened == 0

    def test_reopen_update_sets_status_open_and_clears_resolved_at(self) -> None:
        """SET-Werte des Reopen-UPDATEs: status=open, resolved_at=NULL."""
        session = RecordingSession(
            resolved_rows=[FindingRow(101, "CVE-2026-31431", "vsftpd")],
        )
        _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        (stmt,) = session.updates_of_kind("update_reopen")
        params = _compiled_params(stmt)
        assert params["status"] == FindingStatus.OPEN
        assert params["resolved_at"] is None


# ---------------------------------------------------------------------------
# 3: ACK bleibt ACK
# ---------------------------------------------------------------------------


class TestAckStaysAck:
    def test_reopen_select_filters_resolved_only(self) -> None:
        """Die Reopen-SELECT-WHERE referenziert nur RESOLVED, nie ACKNOWLEDGED.

        Die ACK-Ausgrenzung lebt im SQL-WHERE (status == RESOLVED) — ein
        ACKNOWLEDGED-Finding kann konstruktionsbedingt nie im Reopen-
        Kandidaten-Set landen (User-Entscheidung 1, ADR-0052).
        """
        session = RecordingSession()
        _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        reopen_selects = [stmt for k, stmt in session.calls if k == "select_reopen"]
        assert len(reopen_selects) == 1, session.kinds()
        for value in _compiled_params(reopen_selects[0]).values():
            flat = value if isinstance(value, (list, tuple)) else [value]
            assert FindingStatus.ACKNOWLEDGED not in flat, (
                "Reopen-SELECT darf ACKNOWLEDGED nicht einschliessen"
            )
            assert FindingStatus.ACKNOWLEDGED.value not in flat

    def test_filter_replication_ack_with_key_in_set_not_reopened(self) -> None:
        """Python-Replikation des Gesamt-Filters (SQL-WHERE + Set-Vergleich).

        Stil analog ``test_resolve_set_with_disjoint_scans``: dokumentiert
        den Vertrag als reine Mengen-Logik — ACK mit Key im Set bleibt
        draussen, RESOLVED mit Key im Set kommt rein.
        """
        current_keys = {("CVE-2026-31431", "vsftpd"), ("CVE-2026-11111", "openssl")}
        existing = [
            (1, "CVE-2026-31431", "vsftpd", FindingStatus.RESOLVED),  # → reopen
            (2, "CVE-2026-11111", "openssl", FindingStatus.ACKNOWLEDGED),  # ACK bleibt ACK
            (3, "CVE-2020-99999", "old-pkg", FindingStatus.RESOLVED),  # nicht im Scan
            (4, "CVE-2026-31431", "vsftpd", FindingStatus.OPEN),  # schon offen
        ]
        ids_to_reopen = [
            fid
            for fid, cve, pkg, status in existing
            if status == FindingStatus.RESOLVED and (cve, pkg) in current_keys
        ]
        assert ids_to_reopen == [1]


# ---------------------------------------------------------------------------
# 4: Leeres Set → kein UPDATE
# ---------------------------------------------------------------------------


class TestEmptySets:
    def test_no_resolved_findings_no_update(self) -> None:
        """Kein RESOLVED-Bestand → SELECT laeuft, aber kein UPDATE."""
        session = RecordingSession(resolved_rows=[])
        result = _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        assert "select_reopen" in session.kinds()
        assert session.updates_of_kind("update_reopen") == []
        assert result.findings_reopened == 0

    def test_empty_scan_skips_reopen_phase_entirely(self) -> None:
        """Leerer Scan (rows == []) → weder Reopen-SELECT noch -UPDATE."""
        session = RecordingSession(
            resolved_rows=[FindingRow(101, "CVE-2026-31431", "vsftpd")],
        )
        result = _run_ingest(session, [])

        assert "select_reopen" not in session.kinds(), session.kinds()
        assert session.updates_of_kind("update_reopen") == []
        assert result.findings_reopened == 0
        assert result.findings_total == 0


# ---------------------------------------------------------------------------
# 5: Reihenfolge — Reopen VOR dem Bulk-Upsert
# ---------------------------------------------------------------------------


class TestReopenOrdering:
    def test_reopen_update_runs_before_upsert(self) -> None:
        """Das Reopen-UPDATE muss vor dem ersten Upsert-INSERT laufen."""
        session = RecordingSession(
            resolved_rows=[FindingRow(101, "CVE-2026-31431", "vsftpd")],
        )
        _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        kinds = session.kinds()
        assert "update_reopen" in kinds, kinds
        assert "insert_upsert" in kinds, kinds
        assert kinds.index("update_reopen") < kinds.index("insert_upsert"), kinds

    def test_reopen_select_runs_before_resolve_select(self) -> None:
        """Phasen-Reihenfolge: 1c (Reopen) vor 3 (Resolve)."""
        session = RecordingSession(
            resolved_rows=[FindingRow(101, "CVE-2026-31431", "vsftpd")],
        )
        _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        kinds = session.kinds()
        assert kinds.index("select_reopen") < kinds.index("select_resolve"), kinds


# ---------------------------------------------------------------------------
# 6: Result-Feld + Unabhaengigkeit von der Resolve-Phase
# ---------------------------------------------------------------------------


class TestResultField:
    def test_reopen_and_resolve_counts_are_independent(self) -> None:
        """Reopen- und Resolve-Zaehler beeinflussen sich nicht gegenseitig."""
        session = RecordingSession(
            resolved_rows=[FindingRow(101, "CVE-2026-31431", "vsftpd")],
            open_ack_rows=[FindingRow(501, "CVE-2024-55555", "gone-pkg")],
        )
        result = _run_ingest(session, [("CVE-2026-31431", "vsftpd")])

        assert result.findings_reopened == 1
        assert result.findings_resolved == 1

        resolve_updates = session.updates_of_kind("update_resolve")
        assert len(resolve_updates) == 1, session.kinds()
        assert _update_target_ids(resolve_updates[0]) == [501]
