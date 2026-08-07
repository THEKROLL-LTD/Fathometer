"""TICKET-021 (ADR-0072) — per-vuln ingest leniency.

A single non-conforming Trivy vulnerability must drop only itself, never the
whole scan (issue #23: a `TEMP-*` identifier or an over-long `Title` on a
Debian host discarded hundreds of valid findings on every timer cycle).

Before TICKET-021, `TrivyResult.vulnerabilities: list[TrivyVulnerability]`
was validated monolithically, so one failing entry aggregated into a
`ValidationError` over the entire envelope and the ingest worker marked the
job `failed` — total data loss for that host. The `_safe_vuln` safety net in
`findings_ingest` could never fire because it only ever received objects
Pydantic had already validated.

These pure-unit tests assert:
- the `mode="before"` per-item filter on `TrivyResult.vulnerabilities`
  (reusing `_filter_entries`, the TICKET-018 host_state pattern): a bad entry
  is dropped, the valid ones survive, drops are counted into the validation
  context with a truncated first-error sample;
- the DoS bound: the raw list is truncated to `MAX_VULNS_PER_SCAN` BEFORE any
  per-item validation, so an over-long list is capped, not rejected — even
  when every entry is garbage;
- the cross-result total cap (`TrivyReport._total_vuln_cap`) still rejects a
  report exceeding `MAX_VULNS_PER_SCAN` across all results;
- the widened identifier whitelist (D1, curated): CVE, GHSA, TEMP, DSA, DLA,
  RUSTSEC, GO, PYSEC — real Debian tracker TEMP names included;
- `title`/`description` trim instead of reject (D2): display-only fields,
  same pattern as `cwe_ids`/`references` (v0.6.1);
- the drop count propagates into `ScanIngestResult` / `ScanProcessingResult`
  and the job `result` JSONB.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from app.schemas.scan_envelope import (
    MAX_STRING_LENGTH,
    MAX_TITLE_LENGTH,
    MAX_VULNS_PER_SCAN,
    VULN_DROP_STATS_CONTEXT_KEY,
    Envelope,
    TrivyVulnerability,
)

# ---------------------------------------------------------------------------
# Helpers — minimal valid envelope / vuln dicts (no invented Trivy fields).
# Mirrors tests/schemas/test_host_state_leniency.py.
# ---------------------------------------------------------------------------


def _minimal_envelope(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "agent_version": "0.1.0",
        "host": {
            "os_family": "ubuntu",
            "os_version": "22.04",
            "os_pretty_name": "Ubuntu 22.04",
            "kernel_version": "5.15",
            "architecture": "x86_64",
        },
        "scan": {"SchemaVersion": 2, "Results": []},
    }
    base.update(overrides)
    return base


def _minimal_vuln(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "VulnerabilityID": "CVE-2024-12345",
        "PkgName": "openssl",
        "Severity": "HIGH",
    }
    base.update(overrides)
    return base


def _result_with_vulns(vulns: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "Target": "debian 13",
        "Class": "os-pkgs",
        "Type": "debian",
        "Vulnerabilities": vulns,
    }
    result.update(overrides)
    return result


def _validate_with_stats(doc: dict[str, Any]) -> tuple[Envelope, dict[str, Any]]:
    stats: dict[str, Any] = {}
    envelope = Envelope.model_validate(doc, context={VULN_DROP_STATS_CONTEXT_KEY: stats})
    return envelope, stats


# ---------------------------------------------------------------------------
# Identifier whitelist (D1) — accepted formats vs. rejected garbage.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "identifier",
    [
        "CVE-2024-12345",
        "CVE-2026-1234567",  # 7-digit tail (upper bound)
        "GHSA-abcd-efgh-ijkl",
        # Real, currently-published Debian Security Tracker TEMP names (D3).
        "TEMP-0000000-E57E4E",  # opensmtpd — unassigned bug number
        "TEMP-1142894-39EC25",  # stack buffer overflow
        "TEMP-0290435-0B57B5",  # tar / rmt
        "TEMP-0517018-A83CE6",  # sysvinit
        "DSA-5815-1",
        "DLA-3842-1",
        "RUSTSEC-2024-0421",
        "GO-2024-2687",
        "PYSEC-2024-1",
    ],
)
def test_identifier_whitelist_accepts_real_formats(identifier: str) -> None:
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(VulnerabilityID=identifier))
    assert vuln.vulnerability_id == identifier


@pytest.mark.parametrize(
    "identifier",
    [
        "CVE-foo-bar",
        "CVE-123",  # year part must be 4 digits
        "cve-2024-12345",  # case-sensitive
        "TEMP-x-y",
        "TEMP-00000-ABCDEF",  # bug number below 6 digits
        "TEMP-0000000-e57e4e",  # hex suffix is uppercase-only
        "TEMP-0000000-E57E4",  # hex suffix must be exactly 6 chars
        "DSA-58-1",  # DSA number below 3 digits
        "DSA-5815-123",  # DSA suffix above 2 digits
        "DLA-38-1",
        "RUSTSEC-2024-421",  # RUSTSEC suffix must be exactly 4 digits
        "GO-2024-1",  # GO suffix min 4 digits
        "PYSEC-2024-123456",  # PYSEC suffix max 5 digits
        "NOT-A-CVE",
        "",
    ],
)
def test_identifier_whitelist_rejects_garbage(identifier: str) -> None:
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(VulnerabilityID=identifier))


# ---------------------------------------------------------------------------
# The core fix — one non-conforming entry drops only itself.
# ---------------------------------------------------------------------------


def test_envelope_with_temp_id_and_valid_vulns_loses_nothing() -> None:
    """The reported issue #23 case: a `TEMP-*` vuln plus several valid ones.

    All entries must survive — `TEMP-*` is legitimate Trivy output on Debian.
    """
    temp_vuln = _minimal_vuln(
        VulnerabilityID="TEMP-0000000-E57E4E",
        PkgName="opensmtpd",
        Title="Remotely triggerable buffer overflow in OpenSMTPD",
    )
    valid = [
        _minimal_vuln(VulnerabilityID="CVE-2024-11111", PkgName="openssl"),
        _minimal_vuln(VulnerabilityID="CVE-2024-22222", PkgName="tar"),
    ]
    envelope, stats = _validate_with_stats(
        _minimal_envelope(
            scan={"SchemaVersion": 2, "Results": [_result_with_vulns([temp_vuln, *valid])]}
        )
    )

    vulns = envelope.scan.results[0].vulnerabilities
    assert vulns is not None
    ids = [v.vulnerability_id for v in vulns]
    assert ids == ["TEMP-0000000-E57E4E", "CVE-2024-11111", "CVE-2024-22222"], ids
    assert stats == {}, stats  # nothing dropped


def test_one_invalid_vuln_dropped_rest_ingest_counted() -> None:
    """A genuinely invalid entry (bad Severity, garbage PkgName) is dropped,
    the valid siblings ingest, and the context counter reports the drop."""
    bad_severity = _minimal_vuln(VulnerabilityID="CVE-2024-33333", Severity="ULTRA_CRITICAL")
    bad_pkg = _minimal_vuln(VulnerabilityID="CVE-2024-44444", PkgName="../../../etc/passwd")
    good = _minimal_vuln(VulnerabilityID="CVE-2024-55555", PkgName="openssl")

    envelope, stats = _validate_with_stats(
        _minimal_envelope(
            scan={
                "SchemaVersion": 2,
                "Results": [_result_with_vulns([good, bad_severity, bad_pkg])],
            }
        )
    )

    vulns = envelope.scan.results[0].vulnerabilities
    assert vulns is not None
    assert [v.vulnerability_id for v in vulns] == ["CVE-2024-55555"]
    assert stats["dropped"] == 2, stats
    # First-error sample: one entry only, `loc: msg` shape, bounded length.
    assert isinstance(stats["first_error"], str)
    assert len(stats["first_error"]) <= 200
    assert ":" in stats["first_error"]


def test_envelope_without_context_still_filters_silently() -> None:
    """Callers that pass no validation context (tests, ad-hoc validation)
    get the same per-item filtering, just without drop statistics."""
    envelope = Envelope.model_validate(
        _minimal_envelope(
            scan={
                "SchemaVersion": 2,
                "Results": [
                    _result_with_vulns(
                        [
                            _minimal_vuln(VulnerabilityID="CVE-foo-bar"),  # dropped
                            _minimal_vuln(VulnerabilityID="CVE-2024-55555"),
                        ]
                    )
                ],
            }
        )
    )
    vulns = envelope.scan.results[0].vulnerabilities
    assert vulns is not None
    assert [v.vulnerability_id for v in vulns] == ["CVE-2024-55555"]


def test_all_vulns_invalid_yields_empty_list_not_error() -> None:
    """If every vulnerability in a result is non-conforming, the result (and
    the scan) still validates — the findings list is simply empty."""
    envelope, stats = _validate_with_stats(
        _minimal_envelope(
            scan={
                "SchemaVersion": 2,
                "Results": [
                    _result_with_vulns(
                        [
                            _minimal_vuln(Severity="NOPE"),
                            _minimal_vuln(VulnerabilityID="garbage"),
                        ]
                    )
                ],
            }
        )
    )
    assert envelope.scan.results[0].vulnerabilities == []
    assert stats["dropped"] == 2, stats


def test_first_error_sample_is_single_line_against_malicious_keys() -> None:
    """Log-forging guard (security-auditor GELB): a CVSS provider key bearing
    newlines/ANSI must not smuggle extra lines into the `first_error` sample —
    `loc` contains attacker-controlled dict keys for nested CVSS failures."""
    bad_cvss = _minimal_vuln(
        CVSS={"nvd\nFORGED-LOG-LINE\x1b[31m": {"V3Score": 99.0}},
    )
    _envelope, stats = _validate_with_stats(
        _minimal_envelope(scan={"SchemaVersion": 2, "Results": [_result_with_vulns([bad_cvss])]})
    )
    assert stats["dropped"] == 1, stats
    sample = stats["first_error"]
    assert "\n" not in sample and "\r" not in sample and "\x1b" not in sample, repr(sample)
    assert "FORGED-LOG-LINE" in sample  # the key is still recognizable


def test_drop_stats_aggregate_across_results() -> None:
    """Drops are counted per result and aggregated across the whole report."""
    doc = _minimal_envelope(
        scan={
            "SchemaVersion": 2,
            "Results": [
                _result_with_vulns(
                    [_minimal_vuln(Severity="NOPE"), _minimal_vuln()],
                    Target="r1",
                ),
                _result_with_vulns(
                    [_minimal_vuln(VulnerabilityID="bad"), _minimal_vuln()],
                    Target="r2",
                ),
            ],
        }
    )
    envelope, stats = _validate_with_stats(doc)
    assert stats["dropped"] == 2, stats
    assert len(envelope.scan.results[0].vulnerabilities or []) == 1
    assert len(envelope.scan.results[1].vulnerabilities or []) == 1


# ---------------------------------------------------------------------------
# DoS bound — truncation BEFORE per-item validation (protected: the
# `MAX_VULNS_PER_SCAN` bound must stay ahead of per-item work).
# ---------------------------------------------------------------------------


def test_over_long_vuln_list_capped_not_rejected() -> None:
    """An over-long list of VALID vulnerabilities is silently truncated to
    `MAX_VULNS_PER_SCAN` before per-item validation — capped, not rejected."""
    vulns = [
        _minimal_vuln(VulnerabilityID=f"CVE-2024-{10000 + (i % 80000)}", PkgName=f"pkg{i}")
        for i in range(MAX_VULNS_PER_SCAN + 50)
    ]
    envelope, stats = _validate_with_stats(
        _minimal_envelope(scan={"SchemaVersion": 2, "Results": [_result_with_vulns(vulns)]})
    )
    kept = envelope.scan.results[0].vulnerabilities
    assert kept is not None
    assert len(kept) == MAX_VULNS_PER_SCAN, len(kept)
    assert stats["dropped"] == 50, stats
    assert "cap" in stats["first_error"]


def test_huge_all_garbage_vuln_list_bounded_no_raise() -> None:
    """DoS-bound regression: a raw list far larger than the cap with EVERY
    entry invalid must validate WITHOUT raising and yield a bounded result —
    at most `cap` items are ever validated (all dropped here)."""
    vulns = [{"VulnerabilityID": "garbage"} for _ in range(MAX_VULNS_PER_SCAN + 1000)]
    envelope, stats = _validate_with_stats(
        _minimal_envelope(scan={"SchemaVersion": 2, "Results": [_result_with_vulns(vulns)]})
    )
    assert envelope.scan.results[0].vulnerabilities == []
    # cap validation failures + 1000 truncation overflow.
    assert stats["dropped"] == MAX_VULNS_PER_SCAN + 1000, stats


def test_cross_result_total_cap_still_enforced() -> None:
    """The `TrivyReport` cross-result cap still rejects a report whose total
    (validated) vulnerability count exceeds `MAX_VULNS_PER_SCAN`."""
    per_result = MAX_VULNS_PER_SCAN // 2 + 1
    vulns = [_minimal_vuln(PkgName=f"pkg{i}") for i in range(per_result)]
    doc = _minimal_envelope(
        scan={
            "SchemaVersion": 2,
            "Results": [
                _result_with_vulns(vulns, Target="r1"),
                _result_with_vulns(list(vulns), Target="r2"),
            ],
        }
    )
    with pytest.raises(ValidationError):
        Envelope.model_validate(doc)


# ---------------------------------------------------------------------------
# Display-field trims (D2) — title/description trim instead of reject.
# ---------------------------------------------------------------------------


def test_overlong_title_trimmed_vuln_survives() -> None:
    """The second reported issue #23 case: a 600-char `Title` is trimmed to
    `MAX_TITLE_LENGTH` and the vulnerability survives."""
    envelope, stats = _validate_with_stats(
        _minimal_envelope(
            scan={
                "SchemaVersion": 2,
                "Results": [_result_with_vulns([_minimal_vuln(Title="T" * 600)])],
            }
        )
    )
    vulns = envelope.scan.results[0].vulnerabilities
    assert vulns is not None and len(vulns) == 1
    assert vulns[0].title is not None
    assert len(vulns[0].title) == MAX_TITLE_LENGTH
    assert stats == {}, stats  # a trim is not a drop


def test_overlong_description_trimmed_vuln_survives() -> None:
    """Same for `Description` against `MAX_STRING_LENGTH` (64 KB)."""
    envelope, _stats = _validate_with_stats(
        _minimal_envelope(
            scan={
                "SchemaVersion": 2,
                "Results": [
                    _result_with_vulns([_minimal_vuln(Description="D" * (MAX_STRING_LENGTH + 1))])
                ],
            }
        )
    )
    vulns = envelope.scan.results[0].vulnerabilities
    assert vulns is not None and len(vulns) == 1
    assert vulns[0].description is not None
    assert len(vulns[0].description) == MAX_STRING_LENGTH


def test_title_at_boundary_kept_verbatim() -> None:
    """Exactly `MAX_TITLE_LENGTH` chars stay untouched."""
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(Title="x" * MAX_TITLE_LENGTH))
    assert vuln.title == "x" * MAX_TITLE_LENGTH


def test_control_char_strip_still_applies_before_trim() -> None:
    """The existing control-char scrub keeps working; NUL still rejects."""
    vuln = TrivyVulnerability.model_validate(_minimal_vuln(Title="a\x01b\x02c"))
    assert vuln.title == "abc"
    with pytest.raises(ValidationError):
        TrivyVulnerability.model_validate(_minimal_vuln(Title="a\x00b"))


# ---------------------------------------------------------------------------
# Observability plumbing — drop count through the result chain.
# ---------------------------------------------------------------------------


def test_scan_processing_result_carries_vulns_dropped() -> None:
    """`ScanProcessingResult` accepts and validates the new counter."""
    from app.services.scan_processing import ScanProcessingResult

    result = ScanProcessingResult(
        scan_id=1,
        findings_total=2,
        findings_inserted=2,
        findings_updated=0,
        findings_resolved=0,
        findings_reopened=0,
        class_os_pkgs=2,
        class_lang_pkgs=0,
        class_other=0,
        vulns_dropped=3,
    )
    assert result.vulns_dropped == 3

    with pytest.raises(ValidationError):
        ScanProcessingResult(
            scan_id=1,
            findings_total=0,
            findings_inserted=0,
            findings_updated=0,
            findings_resolved=0,
            findings_reopened=0,
            class_os_pkgs=0,
            class_lang_pkgs=0,
            class_other=0,
            vulns_dropped=-1,
        )


def test_scan_ingest_result_carries_vulns_dropped() -> None:
    """`ScanIngestResult` carries the counter (default 0)."""
    from app.services.findings_ingest import ScanIngestResult

    result = ScanIngestResult(
        scan_id=1,
        received_at=datetime.now(UTC),
        findings_total=0,
        findings_inserted=0,
        findings_updated=0,
        findings_resolved=0,
        findings_reopened=0,
        findings_class_os_pkgs=0,
        findings_class_lang_pkgs=0,
        findings_class_other=0,
        vulns_dropped=7,
    )
    assert result.vulns_dropped == 7


def test_result_to_jsonb_includes_vulns_dropped() -> None:
    """The worker's JSONB serializer exposes the counter to the job result."""
    from app.services.scan_processing import ScanProcessingResult
    from app.workers.scan_ingest_worker import result_to_jsonb

    result = ScanProcessingResult(
        scan_id=1,
        findings_total=0,
        findings_inserted=0,
        findings_updated=0,
        findings_resolved=0,
        findings_reopened=0,
        class_os_pkgs=0,
        class_lang_pkgs=0,
        class_other=0,
        vulns_dropped=4,
    )
    assert result_to_jsonb(result)["vulns_dropped"] == 4


def test_process_scan_envelope_counts_drops_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drop count from envelope validation reaches `ScanProcessingResult`
    via `run_ingest(vulns_dropped=...)` — the ticket's wiring requirement."""
    from app.services import scan_processing
    from app.services.findings_ingest import ScanIngestResult

    captured: dict[str, Any] = {}

    def fake_ingest(server: Any, envelope: Any, **kwargs: Any) -> ScanIngestResult:
        captured.update(kwargs)
        return ScanIngestResult(
            scan_id=1,
            received_at=datetime.now(UTC),
            findings_total=1,
            findings_inserted=1,
            findings_updated=0,
            findings_resolved=0,
            findings_reopened=0,
            findings_class_os_pkgs=1,
            findings_class_lang_pkgs=0,
            findings_class_other=0,
            vulns_dropped=int(kwargs.get("vulns_dropped", 0)),
        )

    monkeypatch.setattr(scan_processing, "run_ingest", fake_ingest)
    monkeypatch.setattr(scan_processing, "log_event", lambda *a, **kw: None)
    settings_row = MagicMock()
    settings_row.block_p_llm_mode = "off"
    monkeypatch.setattr(scan_processing, "get_settings_row", lambda s: settings_row)

    session = MagicMock()
    session.query.return_value.filter.return_value.all.return_value = []

    doc = _minimal_envelope(
        scan={
            "SchemaVersion": 2,
            "Results": [
                _result_with_vulns(
                    [
                        _minimal_vuln(VulnerabilityID="CVE-foo-bar"),  # dropped
                        _minimal_vuln(VulnerabilityID="CVE-2024-55555"),
                    ]
                )
            ],
        }
    )
    payload = gzip.compress(json.dumps(doc).encode("utf-8"))

    server = MagicMock()
    server.id = 1
    server.name = "testserver"

    result = scan_processing.process_scan_envelope(session, server, payload)

    assert captured["vulns_dropped"] == 1, captured
    assert result.vulns_dropped == 1
