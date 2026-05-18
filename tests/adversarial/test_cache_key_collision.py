"""Adversarial: `make_cache_key` ist kollisionsfrei (ADR-0023).

Zwei unterschiedliche Inputs MUESSEN unterschiedliche 64-char-SHA-256-Keys
liefern — sonst koennen wir mit dem Cache-Hit eine fremde Group-Bewertung
auf eine andere Group anwenden (Cache-Poisoning).

Probe-Variationen:
* unterschiedliche `group_id`
* unterschiedliche `group_findings_fp`
* unterschiedliche `cve_data_fp`
* unterschiedliche `server_context_fp`
* permutation der drei Fingerprints (Reihenfolge zaehlt!)
"""

from __future__ import annotations

import re

import pytest

from app.services.llm_fingerprints import make_cache_key


def test_cache_key_is_64_char_hex() -> None:
    """Output ist genau 64 hex-chars (voller SHA-256-hex)."""
    key = make_cache_key(1, "a" * 16, "b" * 16, "c" * 16)
    assert len(key) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", key) is not None


def test_cache_key_is_deterministic() -> None:
    """Selber Input → selber Key (kein Salt, kein Timing)."""
    args = (1, "a" * 16, "b" * 16, "c" * 16)
    assert make_cache_key(*args) == make_cache_key(*args)


def test_cache_key_differs_by_group_id() -> None:
    base = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    for gid in (0, 2, 999, 100_000):
        other = make_cache_key(gid, "aa" * 8, "bb" * 8, "cc" * 8)
        assert other != base, f"group_id={gid} kollidierte mit group_id=1"


def test_cache_key_differs_by_group_findings_fp() -> None:
    base = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    for fp in ("ab" * 8, "ba" * 8, "00" * 8, "ff" * 8):
        other = make_cache_key(1, fp, "bb" * 8, "cc" * 8)
        assert other != base, f"group_findings_fp={fp} kollidierte"


def test_cache_key_differs_by_cve_data_fp() -> None:
    base = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    for fp in ("aa" * 8, "ac" * 8, "00" * 8):
        if fp == "bb" * 8:
            continue
        other = make_cache_key(1, "aa" * 8, fp, "cc" * 8)
        assert other != base, f"cve_data_fp={fp} kollidierte"


def test_cache_key_differs_by_server_context_fp() -> None:
    base = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    for fp in ("00" * 8, "dd" * 8, "ee" * 8):
        other = make_cache_key(1, "aa" * 8, "bb" * 8, fp)
        assert other != base, f"server_context_fp={fp} kollidierte"


def test_cache_key_order_of_fingerprints_matters() -> None:
    """`make_cache_key(gf, cve, sv)` darf NICHT denselben Key liefern wie
    `make_cache_key(cve, gf, sv)` — sonst koennte ein Pfad-Vertauscher den
    Cache vergiften."""
    a = make_cache_key(1, "11" * 8, "22" * 8, "33" * 8)
    b = make_cache_key(1, "22" * 8, "11" * 8, "33" * 8)
    c = make_cache_key(1, "11" * 8, "33" * 8, "22" * 8)
    assert a != b
    assert a != c
    assert b != c


def test_cache_key_no_collision_in_pairwise_grid() -> None:
    """Vollstaendige Kreuztabelle: jede unterschiedliche Kombination liefert
    einen unterschiedlichen Key. 4 Variationen pro Dimension = 256 Pairs."""
    gids = [1, 2]
    gf_fps = ["aa" * 8, "ab" * 8]
    cve_fps = ["b1" * 8, "b2" * 8]
    sv_fps = ["c1" * 8, "c2" * 8]
    seen: dict[str, tuple[int, str, str, str]] = {}
    for g in gids:
        for gf in gf_fps:
            for cve in cve_fps:
                for sv in sv_fps:
                    k = make_cache_key(g, gf, cve, sv)
                    assert k not in seen, f"collision: ({g},{gf},{cve},{sv}) == {seen[k]} → {k}"
                    seen[k] = (g, gf, cve, sv)


@pytest.mark.parametrize(
    "fingerprint_value",
    [
        "",
        "0",
        "abcd",
        "1234567890abcdef",
        "ffffffffffffffff",
    ],
)
def test_cache_key_handles_edge_case_fingerprints(fingerprint_value: str) -> None:
    """Auch Edge-Cases (kurz, leer, randvoll) duerfen keine Kollisionen liefern."""
    key1 = make_cache_key(1, fingerprint_value, "bb" * 8, "cc" * 8)
    key2 = make_cache_key(1, "aa" * 8, fingerprint_value, "cc" * 8)
    assert key1 != key2 or fingerprint_value == "aa" * 8
