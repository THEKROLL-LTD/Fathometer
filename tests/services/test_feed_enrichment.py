"""Block Q Phase 1 (ADR-0024) — Tests fuer ``app.workers.feed_enrichment``.

Drei Test-Schichten:

1. **Pydantic-Schemas** (``EpssRow``, ``KevEntry``, ``KevFeed``) — pure,
   kein DB-/HTTP-Setup, getrieben durch parametrisierte Edge-Cases.
2. **Helper-Funktionen** (``_kev_ransomware_flag``, ``_is_pull_due``) —
   pur, ohne DB.
3. **Pull-Worker** (``pull_epss``, ``pull_kev``, ``feed_enrichment_tick``)
   — mit echter Test-DB (``db_app``) und Stub-``httpx.Client``-Mock.
"""

from __future__ import annotations

import gzip
import io
import json
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from flask import Flask
from pydantic import ValidationError
from sqlalchemy import select

from app.db import get_session_factory
from app.models import CisaKevCatalog, EpssScore, FeedPullLog
from app.schemas.feed_enrichment import EpssRow, KevEntry, KevFeed
from app.workers import feed_enrichment
from app.workers.feed_enrichment import (
    _is_pull_due,
    _kev_ransomware_flag,
    feed_enrichment_tick,
    pull_epss,
    pull_kev,
)

# ---------------------------------------------------------------------------
# Pydantic — EpssRow
# ---------------------------------------------------------------------------


def test_epss_row_happy() -> None:
    row = EpssRow(cve="CVE-2024-6387", epss=0.42, percentile=0.97)
    assert row.cve == "CVE-2024-6387"
    assert row.epss == pytest.approx(0.42)
    assert row.percentile == pytest.approx(0.97)


@pytest.mark.parametrize(
    "bad_cve",
    [
        "CVE-foo-bar",
        "cVe-2024-6387",  # lowercase prefix
        "CVE-2024-X",
        "CVE-24-1234",  # nur 2 Jahresziffern
        "CVE-2024-123",  # nur 3 Suffix-Ziffern (< 4)
        "",
        "GHSA-1234-5678-90ab",
    ],
)
def test_epss_row_rejects_bad_cve(bad_cve: str) -> None:
    with pytest.raises(ValidationError):
        EpssRow(cve=bad_cve, epss=0.5, percentile=0.5)


@pytest.mark.parametrize("bad_epss", [-0.1, 1.5, 2.0])
def test_epss_row_rejects_out_of_range_epss(bad_epss: float) -> None:
    with pytest.raises(ValidationError):
        EpssRow(cve="CVE-2024-0001", epss=bad_epss, percentile=0.5)


@pytest.mark.parametrize("bad_pct", [-0.1, 2.0, 1.01])
def test_epss_row_rejects_out_of_range_percentile(bad_pct: float) -> None:
    with pytest.raises(ValidationError):
        EpssRow(cve="CVE-2024-0001", epss=0.5, percentile=bad_pct)


# ---------------------------------------------------------------------------
# Pydantic — KevEntry
# ---------------------------------------------------------------------------


def test_kev_entry_happy_camelcase_alias() -> None:
    """CISA-Originalformat: camelCase-Keys werden via ``alias`` akzeptiert."""
    entry = KevEntry.model_validate(
        {
            "cveID": "CVE-2024-6387",
            "vendorProject": "OpenBSD",
            "product": "OpenSSH",
            "vulnerabilityName": "regreSSHion",
            "dateAdded": "2024-07-01",
            "shortDescription": "Race condition in sshd.",
            "requiredAction": "Patch.",
            "dueDate": "2024-07-22",
            "knownRansomwareCampaignUse": "Unknown",
        }
    )
    assert entry.cve_id == "CVE-2024-6387"
    assert entry.vendor_project == "OpenBSD"
    assert entry.date_added == date(2024, 7, 1)
    assert entry.due_date == date(2024, 7, 22)
    assert entry.known_ransomware_campaign_use == "Unknown"


def test_kev_entry_happy_snake_case_populate_by_name() -> None:
    """snake_case wird ueber ``populate_by_name=True`` ebenso akzeptiert."""
    entry = KevEntry.model_validate(
        {
            "cve_id": "CVE-2024-0001",
            "date_added": "2024-01-15",
            "vendor_project": "Acme",
        }
    )
    assert entry.cve_id == "CVE-2024-0001"
    assert entry.date_added == date(2024, 1, 15)
    assert entry.vendor_project == "Acme"


def test_kev_entry_date_added_required() -> None:
    with pytest.raises(ValidationError):
        KevEntry.model_validate({"cveID": "CVE-2024-0001"})


def test_kev_entry_rejects_bad_cve() -> None:
    with pytest.raises(ValidationError):
        KevEntry.model_validate({"cveID": "CVE-foo-bar", "dateAdded": "2024-01-01"})


def test_kev_entry_extra_fields_ignored() -> None:
    """Zukunfts-tolerant: unbekannte Felder werden geschluckt, nicht rejected."""
    entry = KevEntry.model_validate(
        {
            "cveID": "CVE-2024-0001",
            "dateAdded": "2024-01-01",
            "newFutureField": "irrelevant",
            "nested": {"any": "thing"},
        }
    )
    assert entry.cve_id == "CVE-2024-0001"


def test_kev_entry_known_ransomware_string_kept_raw() -> None:
    """Das String-Mapping auf bool passiert im Worker, nicht im Schema."""
    entry = KevEntry.model_validate(
        {
            "cveID": "CVE-2024-0002",
            "dateAdded": "2024-02-01",
            "knownRansomwareCampaignUse": "Known",
        }
    )
    assert entry.known_ransomware_campaign_use == "Known"


# ---------------------------------------------------------------------------
# Pydantic — KevFeed
# ---------------------------------------------------------------------------


def test_kev_feed_minimal_empty_list() -> None:
    feed = KevFeed.model_validate(
        {
            "catalogVersion": "2026.05.20",
            "dateReleased": "2026-05-20T10:00:00.000Z",
            "count": 0,
            "vulnerabilities": [],
        }
    )
    assert feed.count == 0
    assert feed.vulnerabilities == []


def test_kev_feed_extra_top_level_fields_ignored() -> None:
    feed = KevFeed.model_validate(
        {
            "catalogVersion": "2026.05.20",
            "dateReleased": "2026-05-20T10:00:00.000Z",
            "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-01"}],
            "futureUnknownTopLevel": "ok",
        }
    )
    assert len(feed.vulnerabilities) == 1


# ---------------------------------------------------------------------------
# Helper — _kev_ransomware_flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Known", True),
        ("known", True),
        ("KNOWN", True),
        ("  Known  ", True),
        ("Unknown", False),
        ("unknown", False),
        ("random", False),
        ("", False),
        (None, False),
    ],
)
def test_kev_ransomware_flag(raw: str | None, expected: bool) -> None:
    assert _kev_ransomware_flag(raw) is expected


# ---------------------------------------------------------------------------
# Helper — _is_pull_due
# ---------------------------------------------------------------------------


def test_is_pull_due_first_run_true() -> None:
    """``last_success is None`` → faellig (First-Run-Default)."""
    assert _is_pull_due(None, interval_hours=24, jitter_max_min=30) is True


def test_is_pull_due_too_recent_false() -> None:
    """Vor wenigen Sekunden gepullt → noch lange nicht faellig.

    Auch wenn der Jitter zufaellig negativ ausfaellt: `now - 10s` ist <<
    `24h - 30min`, also deterministisch False.
    """
    last = datetime.now(UTC) - timedelta(seconds=10)
    assert _is_pull_due(last, interval_hours=24, jitter_max_min=30) is False


def test_is_pull_due_way_past_interval_true() -> None:
    """Pull liegt > interval+jitter zurueck → deterministisch faellig."""
    last = datetime.now(UTC) - timedelta(hours=48)
    assert _is_pull_due(last, interval_hours=24, jitter_max_min=30) is True


def test_is_pull_due_naive_last_success_assumed_utc() -> None:
    """tz-naive Werte werden als UTC interpretiert (Defensiv-Pfad)."""
    naive_last = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=48)
    assert naive_last.tzinfo is None
    assert _is_pull_due(naive_last, interval_hours=24, jitter_max_min=30) is True


# ---------------------------------------------------------------------------
# Stub-HTTP-Client fuer Pull-Tests
# ---------------------------------------------------------------------------


class _StubResponse:
    """Imitiert ``httpx.Response`` so weit der Pull-Code es nutzt."""

    def __init__(self, body: bytes, status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=httpx.Request("GET", "https://example/"),
                response=httpx.Response(self.status_code),
            )

    def iter_bytes(self, chunk_size: int = 65536) -> Any:
        # Liefert den Body in einer einzigen Chunk-Iteration; das ist fuer
        # die Caps und Decompress-Logik aequivalent zum Streaming.
        if self._body:
            yield self._body


class _StubStreamCtx:
    """Context-Manager der ``with client.stream(...) as r:`` simuliert."""

    def __init__(self, response: _StubResponse) -> None:
        self._response = response

    def __enter__(self) -> _StubResponse:
        return self._response

    def __exit__(self, *exc: Any) -> None:
        return None


class StubHttpClient:
    """Minimaler ``httpx.Client``-Stub.

    ``response_for_url`` ist ein Mapping URL → (body_bytes, status_code).
    Wenn keine URL gematcht wird, raise'en wir.
    """

    def __init__(self, response_for_url: dict[str, tuple[bytes, int]]) -> None:
        self._map = response_for_url
        self.calls: list[str] = []

    def stream(self, method: str, url: str, **_kwargs: Any) -> _StubStreamCtx:
        self.calls.append(url)
        if url not in self._map:
            raise AssertionError(f"unexpected URL: {url!r}")
        body, status = self._map[url]
        return _StubStreamCtx(_StubResponse(body, status_code=status))


def _gzip_csv(text: str) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(text.encode("utf-8"))
    return buf.getvalue()


def _settings_stub(**overrides: Any) -> SimpleNamespace:
    """Defaults aus app/config.py — Test ueberschreibt einzelne Felder."""
    base = {
        "feed_pull_disabled": False,
        "feed_epss_url": "https://example.invalid/epss.csv.gz",
        "feed_kev_url": "https://example.invalid/kev.json",
        "feed_pull_interval_hours": 24,
        "feed_jitter_max_min": 30,
        "feed_max_decompressed_mb_epss": 50,
        "feed_max_bytes_kev_mb": 10,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------------------------------------------------------------------------
# pull_epss — Happy Path + Failure-Pfade
# ---------------------------------------------------------------------------


def test_pull_epss_happy(db_app: Flask) -> None:
    csv_text = (
        "#model_version:v2024.01,score_date:2026-05-20T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-0001,0.5,0.99\n"
        "CVE-2024-0002,0.01,0.10\n"
    )
    body = _gzip_csv(csv_text)
    client = StubHttpClient({"https://example.invalid/epss.csv.gz": (body, 200)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()):
                row_count, bytes_dl = pull_epss(sess, http_client=client)
            assert row_count == 2
            assert bytes_dl == len(body)

            stored = sess.execute(select(EpssScore).order_by(EpssScore.cve_id)).scalars().all()
            assert [r.cve_id for r in stored] == ["CVE-2024-0001", "CVE-2024-0002"]
            assert stored[0].epss_score == pytest.approx(0.5)

            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "epss")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "success"
            assert log_row.row_count == 2
            assert log_row.bytes_downloaded == len(body)
            assert log_row.completed_at is not None
        finally:
            sess.close()


def test_pull_epss_gzip_bomb_aborts(db_app: Flask) -> None:
    """Decompressed-Size > Cap → ``ValueError`` propagiert, Audit ``failed``."""
    # 64 KB Payload, Cap auf 1 MB ist normal — wir umgehen den ge=1-Schutz
    # des Settings-Models indem wir den Stub direkt setzen.
    big = "cve,epss,percentile\n" + "\n".join(f"CVE-2024-{i:05d},0.1,0.1" for i in range(20_000))
    body = _gzip_csv(big)
    client = StubHttpClient({"https://example.invalid/epss.csv.gz": (body, 200)})

    # 1 MB Cap, aber unkomprimiertes Volumen >> 1 MB → Abort.
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            tiny_cap_settings = _settings_stub(feed_max_decompressed_mb_epss=0)
            # ge=1 verhindert das normalerweise — als SimpleNamespace umgehen wir's:
            tiny_cap_settings.feed_max_decompressed_mb_epss = 0  # 0 MB Cap
            with (
                patch.object(feed_enrichment, "load_settings", lambda: tiny_cap_settings),
                pytest.raises(ValueError, match="decompressed size exceeds"),
            ):
                pull_epss(sess, http_client=client)

            # Keine EPSS-Rows persistiert.
            assert sess.execute(select(EpssScore)).scalars().all() == []
            # Audit: status='failed'.
            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "epss")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "failed"
            assert log_row.error_message is not None
            assert "decompressed size exceeds" in log_row.error_message
        finally:
            sess.close()


def test_pull_epss_header_mismatch_aborts(db_app: Flask) -> None:
    bad_csv = "wrong,header,row\nCVE-2024-0001,0.5,0.99\n"
    body = _gzip_csv(bad_csv)
    client = StubHttpClient({"https://example.invalid/epss.csv.gz": (body, 200)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with (
                patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()),
                pytest.raises(ValueError, match="unexpected EPSS CSV header"),
            ):
                pull_epss(sess, http_client=client)

            assert sess.execute(select(EpssScore)).scalars().all() == []
            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "epss")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "failed"
        finally:
            sess.close()


def test_pull_epss_invalid_ratio_aborts(db_app: Flask) -> None:
    """100 Rows, 2 davon mit epss>1.0 → 2% > 1% Schwelle → Abort."""
    lines = ["cve,epss,percentile"]
    for i in range(98):
        lines.append(f"CVE-2024-{i:05d},0.1,0.1")
    # 2 Rows mit ungueltigem EPSS-Score (>1.0) → Pydantic validiert fail.
    lines.append("CVE-2024-99998,1.5,0.5")
    lines.append("CVE-2024-99999,1.5,0.5")
    body = _gzip_csv("\n".join(lines) + "\n")
    client = StubHttpClient({"https://example.invalid/epss.csv.gz": (body, 200)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with (
                patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()),
                pytest.raises(ValueError, match="EPSS pull aborted"),
            ):
                pull_epss(sess, http_client=client)

            assert sess.execute(select(EpssScore)).scalars().all() == []
            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "epss")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "failed"
        finally:
            sess.close()


def test_pull_epss_upsert_overrides_existing(db_app: Flask) -> None:
    """Bestehende Row wird beim Pull aktualisiert, kein PK-Konflikt."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            # Vor-Befuellung: epss_score=0.1.
            sess.add(EpssScore(cve_id="CVE-2024-0001", epss_score=0.1, epss_percentile=0.1))
            sess.commit()

            csv_text = "cve,epss,percentile\nCVE-2024-0001,0.5,0.95\n"
            body = _gzip_csv(csv_text)
            client = StubHttpClient({"https://example.invalid/epss.csv.gz": (body, 200)})

            with patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()):
                row_count, _bytes = pull_epss(sess, http_client=client)
            assert row_count == 1

            updated = sess.execute(
                select(EpssScore).where(EpssScore.cve_id == "CVE-2024-0001")
            ).scalar_one()
            assert updated.epss_score == pytest.approx(0.5)
            assert updated.epss_percentile == pytest.approx(0.95)
        finally:
            sess.close()


def test_pull_epss_http_error_marks_failed(db_app: Flask) -> None:
    """HTTP 500 propagiert → Audit ``failed``, keine EpssScore-Rows."""
    client = StubHttpClient({"https://example.invalid/epss.csv.gz": (b"", 500)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with (
                patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()),
                pytest.raises(httpx.HTTPStatusError),
            ):
                pull_epss(sess, http_client=client)
            assert sess.execute(select(EpssScore)).scalars().all() == []
            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "epss")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "failed"
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# pull_kev — Happy Path + Caps + UPSERT
# ---------------------------------------------------------------------------


def _kev_feed_json(entries: list[dict[str, Any]]) -> bytes:
    payload = {
        "title": "CISA KEV Catalog",
        "catalogVersion": "2026.05.20",
        "dateReleased": "2026-05-20T10:00:00.000Z",
        "count": len(entries),
        "vulnerabilities": entries,
    }
    return json.dumps(payload).encode("utf-8")


def test_pull_kev_happy(db_app: Flask) -> None:
    body = _kev_feed_json(
        [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Acme",
                "product": "Foo",
                "vulnerabilityName": "Bug",
                "dateAdded": "2024-01-01",
                "shortDescription": "X.",
                "requiredAction": "Patch.",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2024-0002",
                "dateAdded": "2024-02-15",
                "knownRansomwareCampaignUse": "Known",
            },
        ]
    )
    client = StubHttpClient({"https://example.invalid/kev.json": (body, 200)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()):
                row_count, bytes_dl = pull_kev(sess, http_client=client)
            assert row_count == 2
            assert bytes_dl == len(body)

            stored = (
                sess.execute(select(CisaKevCatalog).order_by(CisaKevCatalog.cve_id)).scalars().all()
            )
            assert [r.cve_id for r in stored] == ["CVE-2024-0001", "CVE-2024-0002"]
            assert stored[0].vendor_project == "Acme"
            assert stored[0].known_ransomware is False
            assert stored[1].known_ransomware is True  # "Known" → True

            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "cisa_kev")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "success"
            assert log_row.row_count == 2
        finally:
            sess.close()


def test_pull_kev_body_cap_aborts(db_app: Flask) -> None:
    """Response groesser als ``feed_max_bytes_kev_mb`` → ValueError + failed."""
    # 200 Eintraege, ~50 KB JSON
    body = _kev_feed_json(
        [
            {
                "cveID": f"CVE-2024-{i:05d}",
                "dateAdded": "2024-01-01",
                "shortDescription": "A" * 200,
            }
            for i in range(200)
        ]
    )
    client = StubHttpClient({"https://example.invalid/kev.json": (body, 200)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            tiny = _settings_stub()
            tiny.feed_max_bytes_kev_mb = 0  # 0 MB Cap → garantierter Abort
            with (
                patch.object(feed_enrichment, "load_settings", lambda: tiny),
                pytest.raises(ValueError, match="KEV response exceeds cap"),
            ):
                pull_kev(sess, http_client=client)

            assert sess.execute(select(CisaKevCatalog)).scalars().all() == []
            log_row = (
                sess.execute(
                    select(FeedPullLog)
                    .where(FeedPullLog.feed_name == "cisa_kev")
                    .order_by(FeedPullLog.id.desc())
                )
                .scalars()
                .first()
            )
            assert log_row is not None
            assert log_row.status == "failed"
        finally:
            sess.close()


def test_pull_kev_upsert_with_duplicate_cve_in_feed(db_app: Flask) -> None:
    """Doppelter CVE in derselben Feed-Datei wird dedupliziert (kein Crash)."""
    body = _kev_feed_json(
        [
            {
                "cveID": "CVE-2024-9999",
                "dateAdded": "2024-01-01",
                "vendorProject": "First",
            },
            {
                "cveID": "CVE-2024-9999",
                "dateAdded": "2024-02-01",
                "vendorProject": "Second",  # Last-wins beim Dedupe.
            },
        ]
    )
    client = StubHttpClient({"https://example.invalid/kev.json": (body, 200)})

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()):
                row_count, _bytes = pull_kev(sess, http_client=client)
            assert row_count == 1  # dedupliziert
            stored = sess.execute(select(CisaKevCatalog)).scalars().all()
            assert len(stored) == 1
            assert stored[0].vendor_project == "Second"
        finally:
            sess.close()


def test_pull_kev_upsert_overrides_existing(db_app: Flask) -> None:
    """Bestehende Row wird durch neuere Feed-Daten ueberschrieben."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.add(
                CisaKevCatalog(
                    cve_id="CVE-2024-0001",
                    vendor_project="OldVendor",
                    date_added=date(2023, 12, 31),
                )
            )
            sess.commit()

            body = _kev_feed_json(
                [
                    {
                        "cveID": "CVE-2024-0001",
                        "dateAdded": "2024-01-15",
                        "vendorProject": "NewVendor",
                        "knownRansomwareCampaignUse": "Known",
                    }
                ]
            )
            client = StubHttpClient({"https://example.invalid/kev.json": (body, 200)})
            with patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()):
                pull_kev(sess, http_client=client)

            updated = sess.execute(
                select(CisaKevCatalog).where(CisaKevCatalog.cve_id == "CVE-2024-0001")
            ).scalar_one()
            assert updated.vendor_project == "NewVendor"
            assert updated.date_added == date(2024, 1, 15)
            assert updated.known_ransomware is True
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# feed_enrichment_tick — End-to-End Sub-Tick
# ---------------------------------------------------------------------------


def test_feed_enrichment_tick_disabled_is_noop(db_app: Flask) -> None:
    """``feed_pull_disabled=True`` → kein Audit-Log, kein HTTP."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with patch.object(
                feed_enrichment,
                "load_settings",
                lambda: _settings_stub(feed_pull_disabled=True),
            ):
                feed_enrichment_tick(sess)
            assert sess.execute(select(FeedPullLog)).scalars().all() == []
            assert sess.execute(select(EpssScore)).scalars().all() == []
        finally:
            sess.close()


def test_feed_enrichment_tick_both_pulled_on_first_run(db_app: Flask) -> None:
    """Keine Vor-Pulls → beide Feeds werden gezogen."""
    epss_body = _gzip_csv("cve,epss,percentile\nCVE-2024-0001,0.5,0.99\n")
    kev_body = _kev_feed_json([{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-01"}])
    stub = StubHttpClient(
        {
            "https://example.invalid/epss.csv.gz": (epss_body, 200),
            "https://example.invalid/kev.json": (kev_body, 200),
        }
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with (
                patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()),
                patch.object(feed_enrichment.httpx, "Client", lambda **_kw: _ClientCtx(stub)),
            ):
                feed_enrichment_tick(sess)

            # Beide URLs wurden besucht.
            assert "https://example.invalid/epss.csv.gz" in stub.calls
            assert "https://example.invalid/kev.json" in stub.calls
            # Je ein success-Log pro Feed.
            assert (
                sess.execute(
                    select(FeedPullLog).where(
                        FeedPullLog.feed_name == "epss", FeedPullLog.status == "success"
                    )
                )
                .scalars()
                .first()
                is not None
            )
            assert (
                sess.execute(
                    select(FeedPullLog).where(
                        FeedPullLog.feed_name == "cisa_kev",
                        FeedPullLog.status == "success",
                    )
                )
                .scalars()
                .first()
                is not None
            )
        finally:
            sess.close()


def test_feed_enrichment_tick_kev_runs_when_epss_fails(db_app: Flask) -> None:
    """EPSS-Pull wirft → KEV-Pull laeuft trotzdem (try/except getrennt)."""
    bad_epss = _gzip_csv("wrong,header,row\nCVE-2024-0001,0.5,0.99\n")
    kev_body = _kev_feed_json([{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-01"}])
    stub = StubHttpClient(
        {
            "https://example.invalid/epss.csv.gz": (bad_epss, 200),
            "https://example.invalid/kev.json": (kev_body, 200),
        }
    )

    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            with (
                patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()),
                patch.object(feed_enrichment.httpx, "Client", lambda **_kw: _ClientCtx(stub)),
            ):
                feed_enrichment_tick(sess)

            # EPSS failed, KEV success — beide Logs vorhanden.
            epss_log = (
                sess.execute(select(FeedPullLog).where(FeedPullLog.feed_name == "epss"))
                .scalars()
                .first()
            )
            kev_log = (
                sess.execute(select(FeedPullLog).where(FeedPullLog.feed_name == "cisa_kev"))
                .scalars()
                .first()
            )
            assert epss_log is not None and epss_log.status == "failed"
            assert kev_log is not None and kev_log.status == "success"
            assert sess.execute(select(CisaKevCatalog)).scalars().first() is not None
        finally:
            sess.close()


def test_feed_enrichment_tick_skips_when_not_due(db_app: Flask) -> None:
    """Frischer success-Eintrag → Tick macht keinen HTTP-Call."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            now = datetime.now(UTC)
            sess.add(
                FeedPullLog(
                    feed_name="epss",
                    status="success",
                    started_at=now,
                    completed_at=now,
                    row_count=1,
                    bytes_downloaded=10,
                )
            )
            sess.add(
                FeedPullLog(
                    feed_name="cisa_kev",
                    status="success",
                    started_at=now,
                    completed_at=now,
                    row_count=1,
                    bytes_downloaded=10,
                )
            )
            sess.commit()

            stub = StubHttpClient({})  # leere Map — jeder Call wuerde AssertionError werfen
            with (
                patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()),
                patch.object(feed_enrichment.httpx, "Client", lambda **_kw: _ClientCtx(stub)),
            ):
                feed_enrichment_tick(sess)

            # Nur die zwei vorgewaehlten success-Logs, keine neuen Pull-Eintraege.
            count = sess.execute(select(FeedPullLog)).scalars().all()
            assert len(count) == 2
            assert stub.calls == []
        finally:
            sess.close()


# Helfer fuer das httpx.Client-Context-Manager-Pattern in feed_enrichment_tick.
class _ClientCtx:
    """Wickelt unseren StubHttpClient in ein context-manager-faehiges Objekt."""

    def __init__(self, stub: StubHttpClient) -> None:
        self._stub = stub

    def __enter__(self) -> StubHttpClient:
        return self._stub

    def __exit__(self, *exc: Any) -> None:
        return None


# ---------------------------------------------------------------------------
# feed_pull_log Eviction (hard-cap 100 Zeilen pro feed_name)
# ---------------------------------------------------------------------------


def test_feed_pull_log_eviction_after_101_rows(db_app: Flask) -> None:
    """101 Eintraege pro feed_name → nach erfolgreichem Pull bleiben max 100."""
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            # 101 alte success-Eintraege manuell anlegen — die werden
            # spaeter durch den Pull (der Eviction triggert) reduziert.
            now = datetime.now(UTC)
            for i in range(101):
                sess.add(
                    FeedPullLog(
                        feed_name="epss",
                        status="success",
                        started_at=now - timedelta(days=200 - i),
                        completed_at=now - timedelta(days=200 - i),
                        row_count=1,
                        bytes_downloaded=1,
                    )
                )
            sess.commit()
            before = (
                sess.execute(select(FeedPullLog).where(FeedPullLog.feed_name == "epss"))
                .scalars()
                .all()
            )
            assert len(before) == 101

            # Jetzt einen echten Pull triggern, der nach Erfolg evicted.
            body = _gzip_csv("cve,epss,percentile\nCVE-2024-0001,0.5,0.99\n")
            client = StubHttpClient({"https://example.invalid/epss.csv.gz": (body, 200)})
            with patch.object(feed_enrichment, "load_settings", lambda: _settings_stub()):
                pull_epss(sess, http_client=client)

            after = (
                sess.execute(select(FeedPullLog).where(FeedPullLog.feed_name == "epss"))
                .scalars()
                .all()
            )
            # Wir hatten 101 + 1 (neuer running/success Eintrag) = 102; nach
            # Eviction auf 100 zugeschnitten.
            assert len(after) == 100
        finally:
            sess.close()


# ---------------------------------------------------------------------------
# LLM-Worker-Integration (smoke)
# ---------------------------------------------------------------------------


def _bind_worker_session_factory(db_app: Flask) -> None:
    """Bindet die Worker-Session-Factory an die Test-DB-Engine.

    Der Worker baut sonst lazy eine eigene Engine aus
    ``SECSCAN_DATABASE_URL`` — funktioniert auch, lässt aber modul-globalen
    State zwischen Tests bestehen. Wir verbinden explizit.
    """
    from sqlalchemy.orm import sessionmaker

    from app.db import get_engine
    from app.workers import llm_worker

    factory = sessionmaker(bind=get_engine(db_app), expire_on_commit=False, autoflush=False)
    llm_worker.set_session_factory_for_tests(factory)


def test_llm_worker_runs_feed_enrichment_check_calls_tick(db_app: Flask) -> None:
    """``_run_feed_enrichment_check`` delegiert an ``feed_enrichment_tick``."""
    from app.workers import llm_worker

    _bind_worker_session_factory(db_app)
    called: dict[str, int] = {"count": 0}

    def _spy(session: Any) -> None:
        called["count"] += 1

    with patch.object(llm_worker.feed_enrichment, "feed_enrichment_tick", _spy):
        llm_worker._run_feed_enrichment_check()
    assert called["count"] == 1


def test_llm_worker_run_feed_enrichment_check_swallows_exception(
    db_app: Flask,
) -> None:
    """Exception im Tick wird in ``_run_feed_enrichment_check`` geschluckt."""
    from app.workers import llm_worker

    _bind_worker_session_factory(db_app)

    def _boom(session: Any) -> None:
        raise RuntimeError("simulated tick failure")

    with patch.object(llm_worker.feed_enrichment, "feed_enrichment_tick", _boom):
        # Sollte KEINE Exception werfen — der Worker-Loop muss weiterlaufen.
        llm_worker._run_feed_enrichment_check()
