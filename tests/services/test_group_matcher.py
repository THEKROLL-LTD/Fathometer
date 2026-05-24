"""Tests fuer `app.services.group_matcher` — Block P (ADR-0023) Pattern-Match.

Verifiziert die Match-Reihenfolge:
1. ``path_prefixes`` — laengster Match gewinnt.
2. ``pkg_name_exact`` — ADR-0011-``@target``-Suffix wird gestrippt.
3. ``pkg_name_glob`` — fnmatch.
4. ``pkg_purl_pattern`` — Prefix.

Plus Library-Reload und :func:`apply_matches_for_server`.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from flask import Flask
from sqlalchemy import select

from app.db import get_session_factory
from app.models import (
    ApplicationGroup,
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.group_matcher import (
    GroupMatcher,
    affinity_sort_for_pass1,
    apply_matches_for_server,
)
from tests._helpers import register_test_server


@pytest.fixture(autouse=True)
def _reset_singleton() -> None:
    """Vor jedem Test den GroupMatcher-Singleton resetten."""
    GroupMatcher._reset_for_tests()
    yield
    GroupMatcher._reset_for_tests()


def _make_finding(
    server_id: int,
    *,
    cve: str = "CVE-2024-0001",
    package_name: str = "openssl",
    target_path: str | None = None,
    purl: str | None = None,
) -> Finding:
    now = datetime.now(tz=UTC)
    return Finding(
        server_id=server_id,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=cve,
        package_name=package_name,
        installed_version="1.0",
        severity=Severity.HIGH,
        attack_vector=AttackVector.UNKNOWN,
        status=FindingStatus.OPEN,
        is_kev=False,
        first_seen_at=now,
        last_seen_at=now,
        target_path=target_path,
        package_purl=purl,
    )


def _insert_group(
    sess,
    label: str,
    *,
    path_prefixes: list[str] | None = None,
    pkg_name_exact: list[str] | None = None,
    pkg_name_glob: list[str] | None = None,
    pkg_purl_pattern: list[str] | None = None,
) -> ApplicationGroup:
    grp = ApplicationGroup(
        label=label,
        explanation=f"Test group {label}",
        path_prefixes=path_prefixes or [],
        pkg_name_exact=pkg_name_exact or [],
        pkg_name_glob=pkg_name_glob or [],
        pkg_purl_pattern=pkg_purl_pattern or [],
        source="llm",
    )
    sess.add(grp)
    sess.flush()
    return grp


# ---------------------------------------------------------------------------
# Match-Reihenfolge & Edge-Cases
# ---------------------------------------------------------------------------


def test_path_prefix_longest_wins(db_app: Flask) -> None:
    """k3s mit `/var/lib/rancher/k3s/agent/containerd/...` matched k3s (laenger),
    nicht eine hypothetische containerd-Group."""
    server_id, _ = register_test_server(db_app, name="matcher-1")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            k3s = _insert_group(sess, "k3s", path_prefixes=["/var/lib/rancher/k3s/"])
            _insert_group(sess, "containerd", path_prefixes=["/var/lib/"])
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            f = _make_finding(
                server_id,
                target_path="/var/lib/rancher/k3s/agent/containerd/snapshot",
            )
            assert matcher.match(f) is not None
            assert matcher.match(f).label == "k3s"
            assert matcher.match(f).id == k3s.id
        finally:
            sess.close()


def test_pkg_name_exact_when_no_path_match(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="matcher-2")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            _insert_group(sess, "openssh-server", pkg_name_exact=["openssh-server"])
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            f = _make_finding(server_id, package_name="openssh-server")
            grp = matcher.match(f)
            assert grp is not None
            assert grp.label == "openssh-server"
        finally:
            sess.close()


def test_pkg_name_exact_strips_at_target_suffix(db_app: Flask) -> None:
    """ADR-0011: `package_name` enthaelt `@target`-Disambiguation; der Matcher
    muss das vor dem Vergleich abschneiden."""
    server_id, _ = register_test_server(db_app, name="matcher-3")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            _insert_group(sess, "stdlib", pkg_name_exact=["stdlib"])
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            # Trivy persistiert `stdlib@/usr/local/bin/k3s-server`.
            f = _make_finding(server_id, package_name="stdlib@/usr/local/bin/k3s-server")
            grp = matcher.match(f)
            assert grp is not None
            assert grp.label == "stdlib"
        finally:
            sess.close()


def test_pkg_name_glob_when_no_exact_match(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="matcher-4")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            _insert_group(sess, "k3s", pkg_name_glob=["k3s-*"])
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            f = _make_finding(server_id, package_name="k3s-server")
            grp = matcher.match(f)
            assert grp is not None
            assert grp.label == "k3s"
        finally:
            sess.close()


def test_pkg_purl_pattern_as_last_resort(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="matcher-5")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            _insert_group(sess, "golang-stdlib", pkg_purl_pattern=["pkg:golang/stdlib"])
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            f = _make_finding(
                server_id,
                package_name="completely-unrelated",
                purl="pkg:golang/stdlib@1.23.5",
            )
            grp = matcher.match(f)
            assert grp is not None
            assert grp.label == "golang-stdlib"
        finally:
            sess.close()


def test_no_match_returns_none(db_app: Flask) -> None:
    server_id, _ = register_test_server(db_app, name="matcher-6")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            _insert_group(sess, "k3s", pkg_name_exact=["k3s"])
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            f = _make_finding(server_id, package_name="zzz-unknown-pkg")
            assert matcher.match(f) is None
        finally:
            sess.close()


def test_reload_picks_up_new_groups(db_app: Flask) -> None:
    """Library-Reload muss neue Groups sehen."""
    server_id, _ = register_test_server(db_app, name="matcher-7")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            sess.commit()
            matcher = GroupMatcher.get()
            matcher.reload(sess)
            f = _make_finding(server_id, package_name="newpkg")
            assert matcher.match(f) is None

            _insert_group(sess, "newpkg", pkg_name_exact=["newpkg"])
            sess.commit()
            matcher.reload(sess)
            grp = matcher.match(f)
            assert grp is not None
            assert grp.label == "newpkg"
        finally:
            sess.close()


def test_apply_matches_for_server_assigns_and_updates_last_used(
    db_app: Flask,
) -> None:
    server_id, _ = register_test_server(db_app, name="matcher-apply")
    factory = get_session_factory(db_app)
    with db_app.app_context():
        sess = factory()
        try:
            grp = _insert_group(sess, "openssl", pkg_name_exact=["openssl"])
            grp_id = grp.id
            f1 = _make_finding(server_id, cve="CVE-X-1", package_name="openssl")
            f2 = _make_finding(server_id, cve="CVE-X-2", package_name="openssl")
            f3 = _make_finding(server_id, cve="CVE-X-3", package_name="ghost")
            sess.add_all([f1, f2, f3])
            sess.commit()

            count = apply_matches_for_server(sess, server_id)
            sess.commit()
            assert count == 2

            assigned = list(
                sess.execute(
                    select(Finding).where(
                        Finding.server_id == server_id,
                        Finding.application_group_id.is_not(None),
                    )
                )
                .scalars()
                .all()
            )
            assert len(assigned) == 2
            assert all(f.application_group_id == grp_id for f in assigned)

            grp_after = sess.execute(
                select(ApplicationGroup).where(ApplicationGroup.id == grp_id)
            ).scalar_one()
            assert grp_after.last_used_at is not None
        finally:
            sess.close()


def test_empty_library_returns_none_when_unloaded(db_app: Flask) -> None:
    """Matcher ohne `reload()`-Call returnt None — Singleton-Default."""
    server_id, _ = register_test_server(db_app, name="matcher-unloaded")
    matcher = GroupMatcher.get()
    f = _make_finding(server_id, package_name="anything")
    assert matcher.match(f) is None


# ---------------------------------------------------------------------------
# v0.9.4 — affinity_sort_for_pass1 (Pass-1-Batching)
# ---------------------------------------------------------------------------


def _bare_finding(fid: int, *, target_path: str | None, package_name: str = "p") -> Finding:
    """Lightweight Finding ohne DB — affinity_sort_for_pass1 ist rein in-memory."""
    f = _make_finding(server_id=1, target_path=target_path, package_name=package_name)
    f.id = fid
    return f


def test_affinity_sort_groups_same_path_prefix() -> None:
    """Findings mit gleichem Top-3-Pfad-Prefix landen benachbart."""
    findings = [
        _bare_finding(10, target_path="/d/e/f/y.py"),
        _bare_finding(11, target_path="/a/b/c/x.py"),
        _bare_finding(12, target_path="/a/b/c/z.py"),
    ]
    sorted_ = affinity_sort_for_pass1(findings)
    ids = [f.id for f in sorted_]
    # /a/b/c/* kommt vor /d/e/f/* (lexikografisch); beide /a/b/c-Findings
    # liegen benachbart.
    assert ids == [11, 12, 10]


def test_affinity_sort_handles_empty_target_path() -> None:
    """Findings ohne target_path landen in einem eigenen Bucket — kein Crash."""
    findings = [
        _bare_finding(1, target_path="/a/b/c/x"),
        _bare_finding(2, target_path=None),
        _bare_finding(3, target_path=""),
    ]
    sorted_ = affinity_sort_for_pass1(findings)
    # Empty-Path-Bucket "" kommt vor "/a/b/c" (lexikografisch),
    # die beiden empty-path findings liegen aneinander.
    ids = [f.id for f in sorted_]
    assert ids[:2] == [2, 3]
    assert ids[-1] == 1


def test_affinity_sort_deterministic_for_identical_keys() -> None:
    """Identischer Pfad + Package → Tiebreak nach id ASC."""
    findings = [
        _bare_finding(5, target_path="/x/y/z/a", package_name="pkg"),
        _bare_finding(3, target_path="/x/y/z/a", package_name="pkg"),
        _bare_finding(4, target_path="/x/y/z/a", package_name="pkg"),
    ]
    sorted_ = affinity_sort_for_pass1(findings)
    assert [f.id for f in sorted_] == [3, 4, 5]


def test_affinity_sort_secondary_key_is_package_name() -> None:
    """Gleicher Top-3-Pfad-Prefix → Sort innerhalb nach package_name."""
    findings = [
        _bare_finding(1, target_path="/a/b/c/file1", package_name="zlib"),
        _bare_finding(2, target_path="/a/b/c/file2", package_name="alpha"),
    ]
    sorted_ = affinity_sort_for_pass1(findings)
    assert [f.id for f in sorted_] == [2, 1]


# ---------------------------------------------------------------------------
# Bugfix 2026-05-24: Slash-insensitive Path-Prefix-Match.
# ---------------------------------------------------------------------------


def _bare_group(label: str, *, path_prefixes: list[str]) -> ApplicationGroup:
    """Pure-In-Memory-Group ohne DB — fuer Matcher-Unit-Tests."""
    return ApplicationGroup(
        id=hash(label) & 0xFFFF,
        label=label,
        explanation=f"{label} group",
        path_prefixes=path_prefixes,
        pkg_name_exact=[],
        pkg_name_glob=[],
        pkg_purl_pattern=[],
        source="llm",
    )


def _stuff_matcher(groups: list[ApplicationGroup]) -> GroupMatcher:
    """Singleton mit gegebenen Groups bestuecken (kein DB-Reload noetig)."""
    GroupMatcher._reset_for_tests()
    m = GroupMatcher.get()
    # Hand-bestuecken — `reload()` braucht eine echte Session.
    m._groups = groups  # type: ignore[attr-defined]
    m._loaded = True  # type: ignore[attr-defined]
    return m


def test_matcher_slash_insensitive_absolute_prefix_relative_target() -> None:
    """Legacy-Group mit Leading-Slash-Prefix muss relative Trivy-Targets matchen."""
    grp = _bare_group("adminlte-master", path_prefixes=["/AdminLTE-master/"])
    matcher = _stuff_matcher([grp])
    try:
        f = _bare_finding(1, target_path="AdminLTE-master/node_modules/vite/package.json")
        hit = matcher.match(f)
        assert hit is not None
        assert hit.label == "adminlte-master"
    finally:
        GroupMatcher._reset_for_tests()


def test_matcher_slash_insensitive_relative_prefix_absolute_target() -> None:
    """Neue normalisierte Group (ohne Leading-Slash) matched auch Targets mit Leading-Slash."""
    grp = _bare_group("k3s", path_prefixes=["var/lib/rancher/k3s/"])
    matcher = _stuff_matcher([grp])
    try:
        f = _bare_finding(1, target_path="/var/lib/rancher/k3s/data/server")
        hit = matcher.match(f)
        assert hit is not None
        assert hit.label == "k3s"
    finally:
        GroupMatcher._reset_for_tests()


def test_matcher_longest_match_wins_with_mixed_slash_styles() -> None:
    """Wenn zwei Groups matchen, gewinnt die mit dem laengeren normalisierten Prefix —
    auch wenn die Prefixes unterschiedliche Slash-Stile haben."""
    short = _bare_group("var-lib", path_prefixes=["/var/lib/"])
    long_ = _bare_group("k3s", path_prefixes=["var/lib/rancher/k3s/"])
    matcher = _stuff_matcher([short, long_])
    try:
        f = _bare_finding(1, target_path="var/lib/rancher/k3s/data/server")
        hit = matcher.match(f)
        assert hit is not None
        assert hit.label == "k3s"
    finally:
        GroupMatcher._reset_for_tests()


def test_matcher_does_not_match_partial_segment() -> None:
    """`AdminLTE-master/` darf nicht `AdminLTE-master-old/` matchen (Prefix-Kollision)."""
    grp = _bare_group("adminlte-master", path_prefixes=["AdminLTE-master/"])
    matcher = _stuff_matcher([grp])
    try:
        # Trailing-Slash im Prefix zwingt das nachfolgende `/`-Segment.
        f = _bare_finding(1, target_path="AdminLTE-master-old/node_modules/x.json")
        assert matcher.match(f) is None
    finally:
        GroupMatcher._reset_for_tests()


# ---------------------------------------------------------------------------
# Bugfix 2026-05-24: _sanitize_path_prefix normalisiert Leading-Slash.
# ---------------------------------------------------------------------------


def test_sanitize_strips_leading_slash() -> None:
    from app.services.llm_risk_reviewer import _sanitize_path_prefix

    assert _sanitize_path_prefix("/AdminLTE-master/") == "AdminLTE-master/"
    assert _sanitize_path_prefix("/var/lib/rancher/k3s/") == "var/lib/rancher/k3s/"


def test_sanitize_accepts_relative_path_unchanged() -> None:
    from app.services.llm_risk_reviewer import _sanitize_path_prefix

    assert _sanitize_path_prefix("AdminLTE-master/") == "AdminLTE-master/"


def test_sanitize_rejects_root_slash() -> None:
    """`/` allein → nach Strip leer → reject."""
    from app.services.llm_risk_reviewer import _sanitize_path_prefix

    assert _sanitize_path_prefix("/") is None
    assert _sanitize_path_prefix("///") is None


def test_sanitize_rejects_non_ascii_after_strip() -> None:
    from app.services.llm_risk_reviewer import _sanitize_path_prefix

    assert _sanitize_path_prefix("/öäü/path/") is None
    assert _sanitize_path_prefix("öäü/path/") is None
