"""Pure-Unit-Tests fuer ``app.services.scan_processing``.

Testet die Service-Boundary von ``process_scan_envelope`` mit gemockten
Sub-Services (monkeypatch). Kein echter DB-Zugriff, kein Postgres.

Scope:
- ScanProcessingResult Pydantic-Schema (Validierung; Haupttests in
  test_scan_processing_result.py, hier nur Integration in process_scan_envelope).
- Error-Propagation: ValidationError aus ingest_scan propagiert nach oben.
- Aufruf-Reihenfolge der Sub-Services via call-order-Verifizierung.
- gzip-Decompress-Fehler.
- ValueError bei malformiertem JSON.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.services.scan_processing import ScanProcessingResult, process_scan_envelope

# ---------------------------------------------------------------------------
# Test-Fixtures und Helpers
# ---------------------------------------------------------------------------


def _make_minimal_envelope_bytes() -> bytes:
    """Minimaler gueltiger Trivy-Envelope als gzip-komprimierte Bytes.

    Enthaelt alle Pflicht-Felder des Pydantic-Envelope-Schemas.
    """
    envelope = {
        "agent_version": "0.3.1",
        "host": {
            "hostname": "testserver",
            "os_family": "linux",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04 LTS",
            "kernel_version": "5.15.0-91-generic",
            "architecture": "amd64",
        },
        "scan": {
            "SchemaVersion": 2,
            "ArtifactName": "testserver",
            "ArtifactType": "filesystem",
            "Results": [],
            "Metadata": {
                "ImageConfig": {},
                "DataSource": None,
                "UpdatedAt": None,
            },
        },
        "host_state": None,
    }
    return gzip.compress(json.dumps(envelope).encode("utf-8"))


def _make_fake_ingest_result() -> Any:
    """Minimaler ScanIngestResult-Fake."""
    from app.services.findings_ingest import ScanIngestResult

    return ScanIngestResult(
        scan_id=42,
        received_at=datetime.now(UTC),
        findings_total=10,
        findings_inserted=8,
        findings_updated=2,
        findings_resolved=1,
        findings_class_os_pkgs=5,
        findings_class_lang_pkgs=3,
        findings_class_other=2,
    )


def _make_fake_server() -> MagicMock:
    """Fake Server-ORM-Objekt mit Mindest-Attributen."""
    server = MagicMock()
    server.id = 1
    server.name = "testserver"
    server.revoked_at = None
    server.retired_at = None
    return server


# ---------------------------------------------------------------------------
# Basis-Tests fuer process_scan_envelope
# ---------------------------------------------------------------------------


class TestProcessScanEnvelopeGzipDecompress:
    """Decompress- und Parse-Fehler werden korrekt weitergegeben."""

    def test_invalid_gzip_raises_error(self) -> None:
        """Invalides gzip-Byte-Sequence fuehrt zu OSError/EOFError (gzip-Fehler)."""
        import gzip as _gzip

        session = MagicMock()
        server = _make_fake_server()
        # gzip.decompress wirft bei ungueltigen Daten BadGzipFile (Subklasse von OSError)
        # oder EOFError — beide sind konkrete Typen.
        with pytest.raises((OSError, EOFError, _gzip.BadGzipFile)):
            process_scan_envelope(session, server, b"not-gzip-data")

    def test_invalid_json_raises_value_error(self) -> None:
        """Gueltiges gzip aber invalides JSON → ValueError."""
        bad_json_gzip = gzip.compress(b"{invalid json")
        session = MagicMock()
        server = _make_fake_server()
        with pytest.raises(ValueError, match="JSON"):
            process_scan_envelope(session, server, bad_json_gzip)

    def test_non_dict_json_raises_value_error(self) -> None:
        """Top-Level JSON-Array → ValueError."""
        array_gzip = gzip.compress(json.dumps([1, 2, 3]).encode("utf-8"))
        session = MagicMock()
        server = _make_fake_server()
        with pytest.raises(ValueError):
            process_scan_envelope(session, server, array_gzip)


class TestProcessScanEnvelopeValidationError:
    """Pydantic-ValidationError aus Envelope.model_validate propagiert."""

    def test_validation_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ValidationError aus dem Envelope-Parse wird NICHT gecatcht."""
        from pydantic import ValidationError as PydanticValidationError

        # Wir patchen Envelope.model_validate um einen ValidationError zu werfen.
        # Das entspricht einem strukturell ungueltigem Scan-Payload.
        def fake_validate(data: Any) -> Any:
            # Erzeuge einen echten Pydantic-ValidationError via ein kaputtes Modell.
            from pydantic import BaseModel

            class Dummy(BaseModel):
                x: int

            Dummy.model_validate({"x": "not_an_int_abc"})

        monkeypatch.setattr(
            "app.services.scan_processing.Envelope.model_validate",
            fake_validate,
        )

        payload_gzip = gzip.compress(json.dumps({"some": "data"}).encode("utf-8"))
        session = MagicMock()
        server = _make_fake_server()

        with pytest.raises(PydanticValidationError):
            process_scan_envelope(session, server, payload_gzip)


class TestProcessScanEnvelopeCallOrder:
    """Aufruf-Reihenfolge der Sub-Services wird eingehalten."""

    def test_ingest_scan_called_before_persist_host_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ingest_scan wird VOR persist_host_state aufgerufen."""
        call_log: list[str] = []

        fake_result = _make_fake_ingest_result()

        def fake_ingest(server: Any, envelope: Any, *, session: Any) -> Any:
            call_log.append("ingest_scan")
            return fake_result

        def fake_persist(session: Any, server: Any, host_state: Any) -> None:
            call_log.append("persist_host_state")

        def fake_pretriage(finding: Any, server: Any, snapshot: Any) -> Any:
            m = MagicMock()
            m.band.value = "medium"
            m.reason = "test"
            m.computed_at = datetime.now(UTC)
            return m

        # Settings-Row-Mock: LLM-Mode = off (kein Job-Queueing)
        fake_settings_row = MagicMock()
        fake_settings_row.block_p_llm_mode = "off"

        monkeypatch.setattr("app.services.scan_processing.run_ingest", fake_ingest)
        monkeypatch.setattr("app.services.scan_processing.persist_host_state", fake_persist)
        monkeypatch.setattr("app.services.scan_processing.pretriage", fake_pretriage)
        monkeypatch.setattr(
            "app.services.scan_processing.get_settings_row",
            lambda session: fake_settings_row,
        )
        # log_event als No-Op.
        monkeypatch.setattr("app.services.scan_processing.log_event", lambda *a, **kw: None)

        # Minimaler Envelope mit host_state damit persist_host_state aufgerufen wird.
        envelope_with_host = {
            "agent_version": "0.3.1",
            "host": {
                "hostname": "testserver",
                "os_family": "linux",
                "os_version": "22.04",
                "os_pretty_name": "Ubuntu 22.04 LTS",
                "kernel_version": "5.15.0-91-generic",
                "architecture": "amd64",
            },
            "scan": {
                "SchemaVersion": 2,
                "ArtifactName": "testserver",
                "ArtifactType": "filesystem",
                "Results": [],
                "Metadata": {"ImageConfig": {}, "DataSource": None, "UpdatedAt": None},
            },
            "host_state": {
                "tools_available": [],
                "gaps": [],
                "listeners": [],
                "processes": [],
                "kernel_modules": [],
                "services": [],
            },
        }
        payload_gzip = gzip.compress(json.dumps(envelope_with_host).encode("utf-8"))
        session = MagicMock()
        # session.query().filter().all() → leere Liste (kein Pre-Triage-Loop)
        session.query.return_value.filter.return_value.all.return_value = []

        server = _make_fake_server()

        result = process_scan_envelope(session, server, payload_gzip)

        # ingest_scan muss VOR persist_host_state sein.
        assert call_log.index("ingest_scan") < call_log.index("persist_host_state")
        assert isinstance(result, ScanProcessingResult)

    def test_no_commit_called_on_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """process_scan_envelope darf session.commit() NICHT aufrufen (ADR-0026)."""
        fake_result = _make_fake_ingest_result()

        monkeypatch.setattr(
            "app.services.scan_processing.run_ingest",
            lambda *a, **kw: fake_result,
        )
        fake_settings_row = MagicMock()
        fake_settings_row.block_p_llm_mode = "off"
        monkeypatch.setattr(
            "app.services.scan_processing.get_settings_row",
            lambda s: fake_settings_row,
        )
        monkeypatch.setattr("app.services.scan_processing.log_event", lambda *a, **kw: None)
        monkeypatch.setattr(
            "app.services.scan_processing.pretriage",
            lambda f, s, snap: MagicMock(
                band=MagicMock(value="medium"), reason="r", computed_at=datetime.now(UTC)
            ),
        )

        payload_gzip = _make_minimal_envelope_bytes()
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []

        process_scan_envelope(session, _make_fake_server(), payload_gzip)

        # session.commit() darf nicht direkt aufgerufen worden sein.
        session.commit.assert_not_called()


class TestPass2EnqueueDelegation:
    """TICKET-007 Etappe 2: der Block-P-Pfad delegiert das Pass-2-Enqueue an
    ``enqueue_pass2_for_server`` (trigger=``scan_ingest``); kein depends_on,
    kein eigener affected_groups-Loop mehr."""

    def _drive(self, monkeypatch: pytest.MonkeyPatch) -> tuple[MagicMock, MagicMock]:
        fake_result = _make_fake_ingest_result()
        monkeypatch.setattr("app.services.scan_processing.run_ingest", lambda *a, **kw: fake_result)
        monkeypatch.setattr(
            "app.services.scan_processing.pretriage",
            lambda f, s, snap: MagicMock(
                band=MagicMock(value="medium"), reason="r", computed_at=datetime.now(UTC)
            ),
        )
        # LLM-Mode != off, damit der Block-P-Pfad ueberhaupt laeuft.
        fake_settings_row = MagicMock()
        fake_settings_row.block_p_llm_mode = "live"
        monkeypatch.setattr(
            "app.services.scan_processing.get_settings_row", lambda s: fake_settings_row
        )
        monkeypatch.setattr(
            "app.services.scan_processing._get_settings",
            lambda: MagicMock(llm_pass1_findings_per_batch=50),
        )
        monkeypatch.setattr("app.services.scan_processing.GroupMatcher", MagicMock())
        monkeypatch.setattr(
            "app.services.scan_processing.apply_matches_for_server", lambda *a, **kw: None
        )
        monkeypatch.setattr(
            "app.services.scan_processing.inherit_group_risk_to_findings", lambda *a, **kw: 0
        )

        mock_log = MagicMock()
        monkeypatch.setattr("app.services.scan_processing.log_event", mock_log)
        mock_enqueue = MagicMock(return_value=3)
        monkeypatch.setattr("app.services.scan_processing.enqueue_pass2_for_server", mock_enqueue)

        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []
        # Ungrouped-PENDING-Query liefert leer -> keine Pass-1-Jobs.
        session.execute.return_value.scalars.return_value.all.return_value = []

        process_scan_envelope(session, _make_fake_server(), _make_minimal_envelope_bytes())
        return mock_enqueue, mock_log

    def test_delegates_to_helper_with_scan_ingest_trigger(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_enqueue, _ = self._drive(monkeypatch)
        mock_enqueue.assert_called_once()
        args, kwargs = mock_enqueue.call_args
        # (session, server_id) positional, trigger kw.
        assert args[1] == 1
        assert kwargs["trigger"] == "scan_ingest"

    def test_helper_return_flows_into_jobs_queued_audit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, mock_log = self._drive(monkeypatch)
        jobs_queued_calls = [
            c for c in mock_log.call_args_list if c.args and c.args[0] == "llm.jobs_queued"
        ]
        assert len(jobs_queued_calls) == 1
        assert jobs_queued_calls[0].kwargs["metadata"]["pass2_queued"] == 3


class TestProcessScanEnvelopeResult:
    """Ergebnis-Counts sind korrekt gemapt."""

    def test_result_counts_match_ingest_result(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ScanProcessingResult spiegelt die ScanIngestResult-Felder korrekt."""
        fake_ingest_result = _make_fake_ingest_result()

        monkeypatch.setattr(
            "app.services.scan_processing.run_ingest",
            lambda *a, **kw: fake_ingest_result,
        )
        fake_settings_row = MagicMock()
        fake_settings_row.block_p_llm_mode = "off"
        monkeypatch.setattr(
            "app.services.scan_processing.get_settings_row",
            lambda s: fake_settings_row,
        )
        monkeypatch.setattr("app.services.scan_processing.log_event", lambda *a, **kw: None)
        monkeypatch.setattr(
            "app.services.scan_processing.pretriage",
            lambda f, s, snap: MagicMock(
                band=MagicMock(value="medium"), reason="r", computed_at=datetime.now(UTC)
            ),
        )

        payload_gzip = _make_minimal_envelope_bytes()
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []

        result = process_scan_envelope(session, _make_fake_server(), payload_gzip)

        assert result.scan_id == fake_ingest_result.scan_id
        assert result.findings_total == fake_ingest_result.findings_total
        assert result.findings_inserted == fake_ingest_result.findings_inserted
        assert result.findings_updated == fake_ingest_result.findings_updated
        assert result.findings_resolved == fake_ingest_result.findings_resolved
        assert result.class_os_pkgs == fake_ingest_result.findings_class_os_pkgs
        assert result.class_lang_pkgs == fake_ingest_result.findings_class_lang_pkgs
        assert result.class_other == fake_ingest_result.findings_class_other

    def test_host_state_error_does_not_kill_job(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SQLAlchemyError in persist_host_state wird gecatcht, Job laeuft weiter."""
        from sqlalchemy.exc import SQLAlchemyError

        fake_result = _make_fake_ingest_result()

        def fake_persist_failing(session: Any, server: Any, host_state: Any) -> None:
            raise SQLAlchemyError("Simulated DB error")

        monkeypatch.setattr(
            "app.services.scan_processing.run_ingest",
            lambda *a, **kw: fake_result,
        )
        monkeypatch.setattr(
            "app.services.scan_processing.persist_host_state",
            fake_persist_failing,
        )
        fake_settings_row = MagicMock()
        fake_settings_row.block_p_llm_mode = "off"
        monkeypatch.setattr(
            "app.services.scan_processing.get_settings_row",
            lambda s: fake_settings_row,
        )
        monkeypatch.setattr("app.services.scan_processing.log_event", lambda *a, **kw: None)
        monkeypatch.setattr(
            "app.services.scan_processing.pretriage",
            lambda f, s, snap: MagicMock(
                band=MagicMock(value="medium"), reason="r", computed_at=datetime.now(UTC)
            ),
        )

        # Envelope MIT host_state (damit persist_host_state aufgerufen wird)
        envelope_with_host = {
            "agent_version": "0.3.1",
            "host": {
                "hostname": "testserver",
                "os_family": "linux",
                "os_version": "22.04",
                "os_pretty_name": "Ubuntu 22.04 LTS",
                "kernel_version": "5.15.0-91-generic",
                "architecture": "amd64",
            },
            "scan": {
                "SchemaVersion": 2,
                "ArtifactName": "testserver",
                "ArtifactType": "filesystem",
                "Results": [],
                "Metadata": {"ImageConfig": {}, "DataSource": None, "UpdatedAt": None},
            },
            "host_state": {
                "tools_available": [],
                "gaps": [],
                "listeners": [],
                "processes": [],
                "kernel_modules": [],
                "services": [],
            },
        }
        payload_gzip = gzip.compress(json.dumps(envelope_with_host).encode("utf-8"))
        session = MagicMock()
        session.query.return_value.filter.return_value.all.return_value = []

        # Darf KEINE Exception werfen — host_state-Fehler wird gecatcht.
        result = process_scan_envelope(session, _make_fake_server(), payload_gzip)
        assert result.scan_id == fake_result.scan_id
