# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Accepted advisory identifier formats (`identifier_key`).

Curated whitelist per ARCHITECTURE.md §9 — every pattern anchored, no generic
fallback. Shared by scan ingest and bulk-acknowledge so the two cannot drift
apart (ADR-0072).
"""

from __future__ import annotations

import re

# CVE and GHSA carry the bulk. The rest is what real Trivy output ships
# verbatim: Debian Security Tracker temporary names (`TEMP-0000000-E57E4E`),
# Debian advisories, and OSV ecosystem identifiers for lang-pkgs.
VULN_ID_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^CVE-\d{4}-\d{4,7}$"),
    re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$"),
    re.compile(r"^TEMP-\d{6,10}-[0-9A-F]{6}$"),
    re.compile(r"^DSA-\d{3,5}-\d{1,2}$"),
    re.compile(r"^DLA-\d{3,5}-\d{1,2}$"),
    re.compile(r"^RUSTSEC-\d{4}-\d{4}$"),
    re.compile(r"^GO-\d{4}-\d{4,}$"),
    re.compile(r"^PYSEC-\d{4}-\d{1,5}$"),
)

VULN_ID_FORMATS = "CVE, GHSA, TEMP, DSA, DLA, RUSTSEC, GO, PYSEC"


def is_known_vuln_id(value: str) -> bool:
    """True if `value` matches one of the accepted identifier formats."""
    return any(pattern.match(value) for pattern in VULN_ID_PATTERNS)


__all__ = ["VULN_ID_FORMATS", "VULN_ID_PATTERNS", "is_known_vuln_id"]
