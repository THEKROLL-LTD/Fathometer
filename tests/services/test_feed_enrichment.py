"""Pure-Unit-Tests fuer ``app.workers.feed_enrichment``.

Diese Datei enthaelt ausschliesslich DB-/HTTP-freie Tests:

1. **Pydantic-Schemas** (``EpssRow``, ``KevEntry``, ``KevFeed``) — pure,
   parametrisierte Edge-Cases.
2. **Helper-Funktionen** (``_kev_ransomware_flag``, ``_is_pull_due``) —
   pure, ohne DB.

Die Pull-Worker-/Audit-Integration-Tests (``pull_epss``, ``pull_kev``,
``feed_enrichment_tick``, ``_evict_old_audit_rows`` und LLM-Worker-Smokes)
laufen mit echter Test-DB und gehoeren in
``tests/integration/test_feed_enrichment_db.py`` (TICKET-004, Slice 5).
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.schemas.feed_enrichment import EpssRow, KevEntry, KevFeed
from app.workers.feed_enrichment import _is_pull_due, _kev_ransomware_flag

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
