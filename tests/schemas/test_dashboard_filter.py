"""Tests fuer `app.schemas.dashboard_filter.DashboardFilter` (Block D).

Pure Schema-Tests — kein App- oder DB-Context noetig. Wir bauen
`werkzeug.MultiDict` direkt zusammen, wie ihn `flask.request.args` liefern
wuerde.
"""

from __future__ import annotations

from werkzeug.datastructures import MultiDict

from app.models import Severity
from app.schemas.dashboard_filter import DashboardFilter


def _args(**kwargs: str) -> MultiDict[str, str]:
    md: MultiDict[str, str] = MultiDict()
    for key, value in kwargs.items():
        md.add(key, value)
    return md


# ---------------------------------------------------------------------------
# Tag-Parsing
# ---------------------------------------------------------------------------


def test_tags_comma_separated() -> None:
    filt = DashboardFilter.from_request(_args(tags="prod,web"))
    assert filt.tags == ["prod", "web"]
    assert filt.tags_mode == "or"  # Default


def test_tags_multi_key() -> None:
    md: MultiDict[str, str] = MultiDict()
    md.add("tags", "prod")
    md.add("tags", "web")
    filt = DashboardFilter.from_request(md)
    assert filt.tags == ["prod", "web"]


def test_tags_lowercased_and_deduplicated() -> None:
    filt = DashboardFilter.from_request(_args(tags="PROD,Web,prod"))
    assert filt.tags == ["prod", "web"]


def test_tags_invalid_regex_silently_dropped() -> None:
    """Tag-Names die nicht TAG_NAME_REGEX matchen werden verworfen — keine
    422-Antwort, kein Crash."""
    filt = DashboardFilter.from_request(_args(tags="invalid!tag"))
    assert filt.tags == []


def test_tags_mixed_valid_and_invalid() -> None:
    filt = DashboardFilter.from_request(_args(tags="prod,WAS BAD!,web"))
    assert filt.tags == ["prod", "web"]


def test_tags_triple_dedup() -> None:
    filt = DashboardFilter.from_request(_args(tags="prod,prod,prod"))
    assert filt.tags == ["prod"]


def test_tags_empty_string() -> None:
    filt = DashboardFilter.from_request(_args(tags=""))
    assert filt.tags == []


def test_tags_whitespace_only_ignored() -> None:
    filt = DashboardFilter.from_request(_args(tags="  ,  ,prod  "))
    assert filt.tags == ["prod"]


def test_tags_combined_multi_key_and_comma() -> None:
    md: MultiDict[str, str] = MultiDict()
    md.add("tags", "prod,web")
    md.add("tags", "db")
    filt = DashboardFilter.from_request(md)
    assert set(filt.tags) == {"prod", "web", "db"}


# ---------------------------------------------------------------------------
# Severity-Parsing
# ---------------------------------------------------------------------------


def test_severity_high() -> None:
    filt = DashboardFilter.from_request(_args(severity="high"))
    assert filt.severity == Severity.HIGH


def test_severity_critical_uppercase() -> None:
    filt = DashboardFilter.from_request(_args(severity="CRITICAL"))
    assert filt.severity == Severity.CRITICAL


def test_severity_invalid_returns_none() -> None:
    filt = DashboardFilter.from_request(_args(severity="ULTRA"))
    assert filt.severity is None


def test_severity_unknown_keyword_returns_none() -> None:
    # `unknown` ist zwar Severity-Wert, aber NICHT in den erlaubten Overrides.
    filt = DashboardFilter.from_request(_args(severity="unknown"))
    assert filt.severity is None


def test_severity_missing_returns_none() -> None:
    filt = DashboardFilter.from_request(_args())
    assert filt.severity is None


# ---------------------------------------------------------------------------
# tags_mode-Parsing
# ---------------------------------------------------------------------------


def test_tags_mode_and() -> None:
    filt = DashboardFilter.from_request(_args(tags_mode="and"))
    assert filt.tags_mode == "and"


def test_tags_mode_or_default() -> None:
    filt = DashboardFilter.from_request(_args())
    assert filt.tags_mode == "or"


def test_tags_mode_invalid_falls_back_to_or() -> None:
    filt = DashboardFilter.from_request(_args(tags_mode="foo"))
    assert filt.tags_mode == "or"


def test_tags_mode_case_insensitive() -> None:
    filt = DashboardFilter.from_request(_args(tags_mode="AND"))
    assert filt.tags_mode == "and"


# ---------------------------------------------------------------------------
# Booleans (kev_only, stale_only)
# ---------------------------------------------------------------------------


def test_kev_only_one() -> None:
    filt = DashboardFilter.from_request(_args(kev_only="1"))
    assert filt.kev_only is True


def test_kev_only_true_string() -> None:
    filt = DashboardFilter.from_request(_args(kev_only="true"))
    assert filt.kev_only is True


def test_kev_only_zero_is_false() -> None:
    filt = DashboardFilter.from_request(_args(kev_only="0"))
    assert filt.kev_only is False


def test_kev_only_garbage_is_false() -> None:
    filt = DashboardFilter.from_request(_args(kev_only="foo"))
    assert filt.kev_only is False


def test_kev_only_missing_defaults_false() -> None:
    filt = DashboardFilter.from_request(_args())
    assert filt.kev_only is False


def test_stale_only_one() -> None:
    filt = DashboardFilter.from_request(_args(stale_only="1"))
    assert filt.stale_only is True


def test_stale_only_yes_string() -> None:
    filt = DashboardFilter.from_request(_args(stale_only="yes"))
    assert filt.stale_only is True


# ---------------------------------------------------------------------------
# to_query_string Roundtrip
# ---------------------------------------------------------------------------


def test_to_query_string_empty_for_defaults() -> None:
    filt = DashboardFilter()
    assert filt.to_query_string() == ""


def test_to_query_string_serializes_tags_comma_separated() -> None:
    filt = DashboardFilter(tags=["prod", "web"])
    qs = filt.to_query_string()
    assert "tags=prod%2Cweb" in qs


def test_to_query_string_omits_default_tags_mode() -> None:
    filt = DashboardFilter(tags=["prod"], tags_mode="or")
    qs = filt.to_query_string()
    assert "tags_mode" not in qs


def test_to_query_string_includes_and_mode() -> None:
    filt = DashboardFilter(tags=["prod"], tags_mode="and")
    assert "tags_mode=and" in filt.to_query_string()


def test_to_query_string_full_roundtrip() -> None:
    filt = DashboardFilter(
        tags=["prod", "web"],
        tags_mode="and",
        severity=Severity.CRITICAL,
        kev_only=True,
        stale_only=True,
    )
    qs = filt.to_query_string()
    assert "tags=prod%2Cweb" in qs
    assert "tags_mode=and" in qs
    assert "severity=critical" in qs
    assert "kev_only=1" in qs
    assert "stale_only=1" in qs


# ---------------------------------------------------------------------------
# extra-Felder werden ignoriert (forward-compat).
# ---------------------------------------------------------------------------


def test_unknown_param_is_ignored() -> None:
    md: MultiDict[str, str] = MultiDict()
    md.add("unknown_param", "foo")
    md.add("tags", "prod")
    filt = DashboardFilter.from_request(md)
    assert filt.tags == ["prod"]
    # Kein Attribut `unknown_param` am Model — wir testen nur, dass das
    # Parsing nicht crasht.


# ---------------------------------------------------------------------------
# is_active-Property
# ---------------------------------------------------------------------------


def test_is_active_false_for_defaults() -> None:
    assert DashboardFilter().is_active is False


def test_is_active_true_with_tags() -> None:
    assert DashboardFilter(tags=["prod"]).is_active is True


def test_is_active_true_with_severity_override() -> None:
    assert DashboardFilter(severity=Severity.CRITICAL).is_active is True


def test_is_active_true_with_kev_only() -> None:
    assert DashboardFilter(kev_only=True).is_active is True


def test_is_active_true_with_stale_only() -> None:
    assert DashboardFilter(stale_only=True).is_active is True


# ---------------------------------------------------------------------------
# Block M (ADR-0020) — neue Felder: q, status, sort, dir
# ---------------------------------------------------------------------------


def test_q_empty_string_becomes_none() -> None:
    filt = DashboardFilter.from_request(_args(q=""))
    assert filt.q is None


def test_q_whitespace_only_becomes_none() -> None:
    filt = DashboardFilter.from_request(_args(q="   "))
    assert filt.q is None


def test_q_strip_and_cap_at_128() -> None:
    long = "a" * 200
    filt = DashboardFilter.from_request(_args(q=long))
    assert filt.q is not None
    assert len(filt.q) == 128


def test_q_normal_value_preserved() -> None:
    filt = DashboardFilter.from_request(_args(q="openssh"))
    assert filt.q == "openssh"


def test_status_default_open() -> None:
    assert DashboardFilter.from_request(_args()).status == "open"


def test_status_valid_values() -> None:
    for val in ("open", "acknowledged", "resolved", "all"):
        assert DashboardFilter.from_request(_args(status=val)).status == val


def test_status_invalid_falls_back_to_open() -> None:
    assert DashboardFilter.from_request(_args(status="bogus")).status == "open"


def test_sort_default_sev() -> None:
    assert DashboardFilter.from_request(_args()).sort == "sev"


def test_sort_valid_values() -> None:
    for val in ("server", "cve", "pkg", "epss", "cvss", "sev", "status", "first_seen"):
        assert DashboardFilter.from_request(_args(sort=val)).sort == val


def test_sort_invalid_falls_back_to_sev() -> None:
    assert DashboardFilter.from_request(_args(sort="DROP TABLE")).sort == "sev"


def test_dir_default_desc() -> None:
    assert DashboardFilter.from_request(_args()).dir == "desc"


def test_dir_asc_accepted() -> None:
    assert DashboardFilter.from_request(_args(dir="asc")).dir == "asc"


def test_dir_invalid_falls_back_to_desc() -> None:
    assert DashboardFilter.from_request(_args(dir="sideways")).dir == "desc"


def test_to_query_string_omits_default_status_sort_dir() -> None:
    filt = DashboardFilter(status="open", sort="sev", dir="desc")
    qs = filt.to_query_string()
    assert "status" not in qs
    assert "sort" not in qs
    assert "dir" not in qs


def test_to_query_string_includes_block_m_fields() -> None:
    filt = DashboardFilter(q="openssh", status="acknowledged", sort="cvss", dir="asc")
    qs = filt.to_query_string()
    assert "q=openssh" in qs
    assert "status=acknowledged" in qs
    assert "sort=cvss" in qs
    assert "dir=asc" in qs


def test_to_query_string_override_replaces_existing_key() -> None:
    filt = DashboardFilter(sort="sev", dir="desc")
    qs = filt.to_query_string(override={"sort": "cvss", "dir": "asc"})
    assert "sort=cvss" in qs
    assert "dir=asc" in qs
    # Default `sev/desc` darf nicht auch noch da sein.
    assert "sort=sev" not in qs


def test_to_query_string_override_appends_new_key() -> None:
    filt = DashboardFilter()
    qs = filt.to_query_string(override={"sort": "cvss"})
    assert "sort=cvss" in qs


def test_to_query_string_roundtrip_with_block_m_fields() -> None:
    """parse -> serialize -> parse -> identisch fuer alle relevanten Felder."""
    original = DashboardFilter(
        tags=["prod", "web"],
        tags_mode="and",
        severity=Severity.HIGH,
        kev_only=True,
        stale_only=True,
        q="openssh",
        status="acknowledged",
        sort="cvss",
        dir="asc",
    )
    qs = original.to_query_string()
    # Parse aus dem QueryString reproduzieren.
    from urllib.parse import parse_qsl

    md: MultiDict[str, str] = MultiDict()
    for k, v in parse_qsl(qs, keep_blank_values=False):
        md.add(k, v)
    reparsed = DashboardFilter.from_request(md)

    assert reparsed.tags == original.tags
    assert reparsed.tags_mode == original.tags_mode
    assert reparsed.severity == original.severity
    assert reparsed.kev_only == original.kev_only
    assert reparsed.stale_only == original.stale_only
    assert reparsed.q == original.q
    assert reparsed.status == original.status
    assert reparsed.sort == original.sort
    assert reparsed.dir == original.dir


def test_is_active_true_with_q() -> None:
    assert DashboardFilter(q="openssh").is_active is True


def test_is_active_true_with_status_acknowledged() -> None:
    assert DashboardFilter(status="acknowledged").is_active is True


def test_is_active_false_for_sort_or_dir_only() -> None:
    """Sort/Dir zaehlen NICHT als aktiver Filter (ADR-0020)."""
    assert DashboardFilter(sort="cvss", dir="asc").is_active is False


def test_tag_single_form_accepted_alongside_tags() -> None:
    """Block-M-Filter-Bar nutzt `?tag=` (Single-Form); alte `tags`-Form bleibt."""
    md: MultiDict[str, str] = MultiDict()
    md.add("tag", "prod")
    filt = DashboardFilter.from_request(md)
    assert filt.tags == ["prod"]
