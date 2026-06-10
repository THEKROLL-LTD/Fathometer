"""Tests fuer `app.services.llm_fingerprints` — Block P (ADR-0023).

Verifiziert:

* Determinismus pro Funktion (gleicher Input → gleicher Hash).
* Canonical-Serialization (Input in anderer Reihenfolge → gleicher Hash).
* PID/args/snapshot_at-Aenderung beeinflussen den Server-Context NICHT.
* Listener-Add / Kernel-Module-Add / Tag-Add aendern den Hash.
* ``make_cache_key`` ist 64-char-Hex.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Server,
    ServerKernelModule,
    ServerListener,
    ServerProcess,
    ServerService,
    ServerTag,
    Severity,
    Tag,
)
from app.services.llm_fingerprints import (
    cve_data_fingerprint,
    group_findings_fingerprint,
    make_cache_key,
    server_context_fingerprint,
)
from app.services.llm_prompts import PASS2_PROMPT_VERSION


def _make_finding(
    *,
    fid: int = 1,
    identifier_key: str = "CVE-2024-0001",
    package_name: str = "openssl",
    purl: str | None = "pkg:deb/ubuntu/openssl@3.0.2",
    severity: Severity = Severity.HIGH,
    epss: float | None = 0.42,
    is_kev: bool = False,
    vendor_status: str | None = "affected",
    severity_by_provider: dict[str, str] | None = None,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    now = datetime.now(tz=UTC)
    return Finding(
        id=fid,
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=identifier_key,
        package_name=package_name,
        installed_version="1.0",
        severity=severity,
        attack_vector=AttackVector.UNKNOWN,
        status=status,
        epss_score=epss,
        is_kev=is_kev,
        first_seen_at=now,
        last_seen_at=now,
        severity_by_provider=severity_by_provider,
        vendor_status=vendor_status,
        package_purl=purl,
    )


def _make_server(
    *,
    os_family: str = "ubuntu",
    os_version: str = "24.04",
    listeners: list[ServerListener] | None = None,
    processes: list[ServerProcess] | None = None,
    modules: list[ServerKernelModule] | None = None,
    services: list[ServerService] | None = None,
    tag_names: list[str] | None = None,
) -> Server:
    srv = Server(
        id=1,
        name="srv-fp-test",
        api_key_hash="x" * 64,
        expected_scan_interval_h=24,
        os_family=os_family,
        os_version=os_version,
    )
    # In-Memory-Attribute, vom Fingerprint per getattr gelesen.
    srv.listeners = listeners or []  # type: ignore[attr-defined]
    srv.processes = processes or []  # type: ignore[attr-defined]
    srv.kernel_modules = modules or []  # type: ignore[attr-defined]
    srv.services = services or []  # type: ignore[attr-defined]
    if tag_names:
        links: list[ServerTag] = []
        for name in tag_names:
            t = Tag(name=name, color="#6b7280")
            link = ServerTag()
            link.tag = t
            links.append(link)
        srv.tag_links = links  # type: ignore[attr-defined]
    else:
        srv.tag_links = []  # type: ignore[attr-defined]
    return srv


# ---------------------------------------------------------------------------
# group_findings_fingerprint
# ---------------------------------------------------------------------------


def test_group_findings_fingerprint_is_deterministic() -> None:
    a = _make_finding(fid=1, identifier_key="CVE-A", purl="pkg:deb/x@1")
    b = _make_finding(fid=2, identifier_key="CVE-B", purl="pkg:deb/x@2")
    fp1 = group_findings_fingerprint([a, b])
    fp2 = group_findings_fingerprint([a, b])
    assert fp1 == fp2
    assert len(fp1) == 16


def test_group_findings_fingerprint_order_independent() -> None:
    a = _make_finding(fid=1, identifier_key="CVE-A", purl="pkg:deb/x@1")
    b = _make_finding(fid=2, identifier_key="CVE-B", purl="pkg:deb/x@2")
    fp_ab = group_findings_fingerprint([a, b])
    fp_ba = group_findings_fingerprint([b, a])
    assert fp_ab == fp_ba


def test_group_findings_fingerprint_changes_when_cve_added() -> None:
    a = _make_finding(fid=1, identifier_key="CVE-A")
    b = _make_finding(fid=2, identifier_key="CVE-B")
    c = _make_finding(fid=3, identifier_key="CVE-C")
    assert group_findings_fingerprint([a, b]) != group_findings_fingerprint([a, b, c])


# ---------------------------------------------------------------------------
# TICKET-010 Etappe 2 (Bug B): Input-Domaene ist das OPEN-Set
# ---------------------------------------------------------------------------


def _mixed_status_group() -> list[Finding]:
    """Group mit gemischten Status: 2x open, 1x resolved, 1x acknowledged."""
    return [
        _make_finding(fid=1, identifier_key="CVE-A", purl="pkg:deb/a@1"),
        _make_finding(fid=2, identifier_key="CVE-B", purl="pkg:deb/b@2"),
        _make_finding(
            fid=3, identifier_key="CVE-C", purl="pkg:deb/c@3", status=FindingStatus.RESOLVED
        ),
        _make_finding(
            fid=4, identifier_key="CVE-D", purl="pkg:deb/d@4", status=FindingStatus.ACKNOWLEDGED
        ),
    ]


def test_group_findings_fingerprint_ignores_status_attribute() -> None:
    """Der Status fliesst NICHT in den Hash ein — die OPEN-Domaene muss
    deshalb zwingend beim Laden gefiltert werden (Bug-B-Wurzel: wer das
    ALL-Set laedt, bekommt einen anderen Fingerprint als das OPEN-Set,
    nicht etwa denselben mit anderem Status-Feld)."""
    f_open = _make_finding(fid=1, identifier_key="CVE-A", purl="pkg:deb/a@1")
    f_resolved = _make_finding(
        fid=1, identifier_key="CVE-A", purl="pkg:deb/a@1", status=FindingStatus.RESOLVED
    )
    assert group_findings_fingerprint([f_open]) == group_findings_fingerprint([f_resolved])


def test_group_findings_fingerprint_open_subset_differs_from_all_set() -> None:
    """Bug-B-Kern: ALL-Set-Fingerprint (alter Worker-Load) != OPEN-Set-
    Fingerprint (Enqueue) sobald die Group non-open Findings enthaelt —
    genau der Mismatch der die Dauer-Re-Enqueue-Schleife ausgeloest hat."""
    mixed = _mixed_status_group()
    open_subset = [f for f in mixed if f.status == FindingStatus.OPEN]
    assert group_findings_fingerprint(mixed) != group_findings_fingerprint(open_subset)


def test_group_findings_fingerprint_open_subset_equal_across_callers() -> None:
    """Bug-B-Regression: Enqueue und Worker filtern beide auf OPEN — ueber
    dieselbe gemischte Group kommt (auch bei anderer Lade-Reihenfolge)
    identischer Fingerprint heraus."""
    mixed = _mixed_status_group()
    enqueue_view = [f for f in mixed if f.status == FindingStatus.OPEN]
    worker_view = [f for f in reversed(mixed) if f.status == FindingStatus.OPEN]
    assert group_findings_fingerprint(enqueue_view) == group_findings_fingerprint(worker_view)


# ---------------------------------------------------------------------------
# cve_data_fingerprint
# ---------------------------------------------------------------------------


def test_cve_data_fingerprint_stable_for_same_input() -> None:
    a = _make_finding(
        identifier_key="CVE-X",
        epss=0.123456,
        is_kev=True,
        vendor_status="affected",
        severity_by_provider={"nvd": "high", "ubuntu": "medium"},
    )
    fp1 = cve_data_fingerprint([a])
    fp2 = cve_data_fingerprint([a])
    assert fp1 == fp2
    assert len(fp1) == 16


def test_cve_data_fingerprint_changes_on_epss_drift_above_precision() -> None:
    base = _make_finding(epss=0.1234)
    drifted = _make_finding(epss=0.5678)
    assert cve_data_fingerprint([base]) != cve_data_fingerprint([drifted])


def test_cve_data_fingerprint_provider_map_order_independent() -> None:
    a = _make_finding(severity_by_provider={"nvd": "high", "ubuntu": "medium"})
    b = _make_finding(severity_by_provider={"ubuntu": "medium", "nvd": "high"})
    assert cve_data_fingerprint([a]) == cve_data_fingerprint([b])


# ---------------------------------------------------------------------------
# server_context_fingerprint — PID/args/snapshot_at/user dürfen NICHT
# einfließen.
# ---------------------------------------------------------------------------


def test_server_context_fingerprint_pid_change_does_not_affect_hash() -> None:
    p1 = ServerProcess(server_id=1, pid=1234, user="root", comm="sshd", args="/usr/sbin/sshd -D")
    p2 = ServerProcess(server_id=1, pid=9999, user="root", comm="sshd", args="/usr/sbin/sshd -D")
    s1 = _make_server(processes=[p1])
    s2 = _make_server(processes=[p2])
    assert server_context_fingerprint(s1) == server_context_fingerprint(s2)


def test_server_context_fingerprint_args_change_does_not_affect_hash() -> None:
    p1 = ServerProcess(server_id=1, pid=10, user="root", comm="nginx", args="nginx: master")
    p2 = ServerProcess(server_id=1, pid=10, user="root", comm="nginx", args="nginx: master alt")
    s1 = _make_server(processes=[p1])
    s2 = _make_server(processes=[p2])
    assert server_context_fingerprint(s1) == server_context_fingerprint(s2)


def test_server_context_fingerprint_user_change_does_not_affect_hash() -> None:
    p1 = ServerProcess(server_id=1, pid=10, user="root", comm="nginx", args="x")
    p2 = ServerProcess(server_id=1, pid=10, user="www-data", comm="nginx", args="x")
    s1 = _make_server(processes=[p1])
    s2 = _make_server(processes=[p2])
    assert server_context_fingerprint(s1) == server_context_fingerprint(s2)


def test_server_context_fingerprint_listener_add_changes_hash() -> None:
    li1 = ServerListener(server_id=1, proto="tcp", port=22, addr="0.0.0.0", process="sshd")  # noqa: S104
    li2 = ServerListener(server_id=1, proto="tcp", port=443, addr="0.0.0.0", process="nginx")  # noqa: S104
    s_one = _make_server(listeners=[li1])
    s_two = _make_server(listeners=[li1, li2])
    assert server_context_fingerprint(s_one) != server_context_fingerprint(s_two)


def test_server_context_fingerprint_kernel_module_add_changes_hash() -> None:
    m1 = ServerKernelModule(server_id=1, name="ext4")
    m2 = ServerKernelModule(server_id=1, name="overlay")
    s_one = _make_server(modules=[m1])
    s_two = _make_server(modules=[m1, m2])
    assert server_context_fingerprint(s_one) != server_context_fingerprint(s_two)


def test_server_context_fingerprint_tag_add_changes_hash() -> None:
    s_one = _make_server(tag_names=["prod"])
    s_two = _make_server(tag_names=["prod", "internet-exposed"])
    assert server_context_fingerprint(s_one) != server_context_fingerprint(s_two)


def test_server_context_fingerprint_service_add_changes_hash() -> None:
    s1 = ServerService(server_id=1, name="nginx")
    s2 = ServerService(server_id=1, name="postgresql")
    s_one = _make_server(services=[s1])
    s_two = _make_server(services=[s1, s2])
    assert server_context_fingerprint(s_one) != server_context_fingerprint(s_two)


def test_server_context_fingerprint_input_order_does_not_matter() -> None:
    li_a = ServerListener(server_id=1, proto="tcp", port=22, addr="0.0.0.0", process="sshd")  # noqa: S104
    li_b = ServerListener(server_id=1, proto="tcp", port=443, addr="0.0.0.0", process="nginx")  # noqa: S104
    m1 = ServerKernelModule(server_id=1, name="ext4")
    m2 = ServerKernelModule(server_id=1, name="overlay")
    s_one = _make_server(listeners=[li_a, li_b], modules=[m1, m2])
    s_two = _make_server(listeners=[li_b, li_a], modules=[m2, m1])
    assert server_context_fingerprint(s_one) == server_context_fingerprint(s_two)


# ---------------------------------------------------------------------------
# make_cache_key
# ---------------------------------------------------------------------------


def test_make_cache_key_is_64_char_hex() -> None:
    key = make_cache_key(42, "a" * 16, "b" * 16, "c" * 16)
    assert len(key) == 64
    assert all(ch in "0123456789abcdef" for ch in key)


def test_make_cache_key_deterministic_and_input_sensitive() -> None:
    k1 = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    k2 = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    assert k1 == k2
    # Group-ID change → andere Key.
    k3 = make_cache_key(2, "aa" * 8, "bb" * 8, "cc" * 8)
    assert k1 != k3
    # FP-change → andere Key.
    k4 = make_cache_key(1, "aa" * 8, "bb" * 8, "dd" * 8)
    assert k1 != k4


# ---------------------------------------------------------------------------
# TICKET-011: Versions-Salt + title/attack_vector im CVE-Fingerprint
# ---------------------------------------------------------------------------


def test_make_cache_key_carries_prompt_version_salt() -> None:
    """Der Key MUSS den Versions-Salt enthalten — eine materielle Prompt-
    Semantik-Aenderung (PASS2_PROMPT_VERSION-Bump) invalidiert den Cache
    einmalig (TICKET-011)."""
    unsalted = hashlib.sha256(f"1|{'aa' * 8}|{'bb' * 8}|{'cc' * 8}".encode()).hexdigest()
    salted = hashlib.sha256(
        f"1|{'aa' * 8}|{'bb' * 8}|{'cc' * 8}|v{PASS2_PROMPT_VERSION}".encode()
    ).hexdigest()
    key = make_cache_key(1, "aa" * 8, "bb" * 8, "cc" * 8)
    assert key == salted
    assert key != unsalted


def test_prompt_version_is_at_least_two() -> None:
    # Version 1 war die Prompt-Semantik vor TICKET-011 (ohne Salt).
    assert PASS2_PROMPT_VERSION >= 2


def test_cve_data_fingerprint_changes_on_title_change() -> None:
    """Title steht seit TICKET-011 in der Pass-2-Prompt-Zeile und muss den
    CVE-Fingerprint mit-invalidieren (z.B. Title-Update durch Enrichment)."""
    f1 = _make_finding()
    f1.title = "old title"
    f2 = _make_finding()
    f2.title = "new title"
    assert cve_data_fingerprint([f1]) != cve_data_fingerprint([f2])


def test_cve_data_fingerprint_changes_on_attack_vector_change() -> None:
    f1 = _make_finding()
    f2 = _make_finding()
    f2.attack_vector = AttackVector.NETWORK
    assert cve_data_fingerprint([f1]) != cve_data_fingerprint([f2])
