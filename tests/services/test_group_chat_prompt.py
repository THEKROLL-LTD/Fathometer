"""Pure-Unit-Tests fuer `app.services.group_chat_prompt` (Block AE, ADR-0055).

Verifiziert ohne DB-Roundtrip (in-memory ORM-Objekte + plain dicts):

- Marker-Disziplin: genau ein START/END-Paar, START vor END, alle Daten
  zwischen den Markern.
- `_safe`: NUL/Control-Chars werden gestript, Uebergroesse gecappt.
- Findings-Zeilen-Format (CVE | sev | cvss | epss | kev | vec | title).
- Leere Group -> "No open findings in this group."
- Listener-Exposure-Rendering (LOOPBACK vs. PUBLIC EXPOSED).
- Service-Liste alphabetisch.
- Alle Fingerprint-Felder zwischen den Markern.
- `CHAT_SUGGESTIONS` single-source.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models import (
    AttackVector,
    Finding,
    FindingClass,
    FindingStatus,
    FindingType,
    Severity,
)
from app.services.group_chat_prompt import (
    CHAT_SUGGESTIONS,
    GROUP_CHAT_FINDINGS_BUDGET,
    TRIVY_DATA_END,
    TRIVY_DATA_START,
    FindingsAggregate,
    _safe,
    build_group_system_prompt,
    build_user_intro,
)

# ---------------------------------------------------------------------------
# Fixtures (in-memory, kein DB-Roundtrip)
# ---------------------------------------------------------------------------
#
# Der Server wird als leichter Stub modelliert (kein ORM-Objekt): der Builder
# liest nur Attribute via getattr, und ein echter `Server` wuerde beim Setzen
# von `tag_links` die SQLAlchemy-Backref-Machinery triggern. Das Duck-Typing
# spiegelt genau die Attribute, auf die der Builder zugreift.


class _Tag:
    def __init__(self, name: str) -> None:
        self.name = name


class _Link:
    """Minimaler Stub fuer `ServerTag` (`.tag.name`)."""

    def __init__(self, name: str) -> None:
        self.tag = _Tag(name)


class _ServerStub:
    """Duck-typed Server-Stub mit genau den vom Builder gelesenen Attributen."""

    def __init__(
        self,
        *,
        name: str,
        os_pretty_name: str | None,
        os_family: str | None,
        kernel_version: str | None,
        architecture: str | None,
        tags: list[str],
        last_scan_at: datetime | None,
    ) -> None:
        self.name = name
        self.os_pretty_name = os_pretty_name
        self.os_family = os_family
        self.kernel_version = kernel_version
        self.architecture = architecture
        self.tag_links = [_Link(t) for t in tags]
        self.last_scan_at = last_scan_at


def _make_server(
    *,
    name: str = "web-01",
    os_pretty_name: str | None = "Ubuntu 22.04 LTS",
    kernel_version: str | None = "5.15.0-100-generic",
    architecture: str | None = "x86_64",
    tags: list[str] | None = None,
    last_scan: datetime | None = datetime(2026, 6, 1, 12, 0, tzinfo=UTC),
) -> _ServerStub:
    return _ServerStub(
        name=name,
        os_pretty_name=os_pretty_name,
        os_family="ubuntu",
        kernel_version=kernel_version,
        architecture=architecture,
        tags=tags or [],
        last_scan_at=last_scan,
    )


def _make_finding(
    *,
    identifier_key: str = "CVE-2026-0001",
    package_name: str = "openssl",
    severity: Severity = Severity.HIGH,
    cvss: float | None = 7.5,
    epss: float | None = 0.42,
    is_kev: bool = False,
    attack_vector: AttackVector = AttackVector.NETWORK,
    title: str | None = "SSL/TLS Vulnerability",
) -> Finding:
    return Finding(
        server_id=1,
        finding_type=FindingType.VULNERABILITY,
        finding_class=FindingClass.OS_PKGS,
        identifier_key=identifier_key,
        package_name=package_name,
        installed_version="1.1.1",
        fixed_version="1.1.1u",
        severity=severity,
        title=title,
        cvss_v3_score=cvss,
        epss_score=epss,
        is_kev=is_kev,
        attack_vector=attack_vector,
        status=FindingStatus.OPEN,
        first_seen_at=datetime(2026, 5, 10, tzinfo=UTC),
        last_seen_at=datetime(2026, 5, 10, tzinfo=UTC),
    )


def _snapshot(
    *,
    services: list[str] | None = None,
    listeners: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "services": services if services is not None else ["nginx", "cron"],
        "listeners": listeners
        if listeners is not None
        else [
            {
                "process": "nginx",
                "addr": "0.0.0.0",  # noqa: S104 — test-fixture, kein Bind
                "port": 443,
                "proto": "tcp",
                "pid": 1234,
                "exposure": "PUBLIC EXPOSED",
            },
            {
                "process": "postgres",
                "addr": "127.0.0.1",
                "port": 5432,
                "proto": "tcp",
                "pid": 99,
                "exposure": "LOOPBACK",
            },
        ],
        "processes": [],
    }


class _Worst:
    def __init__(self, identifier_key: str, title: str) -> None:
        self.identifier_key = identifier_key
        self.title = title


def _build(**overrides: Any) -> str:
    kwargs: dict[str, Any] = {
        "server": _make_server(tags=["prod", "edge"]),
        "group_label": "openssl / TLS stack",
        "lane": "escalate",
        "worst_finding": _Worst("CVE-2026-0001", "SSL/TLS Vulnerability"),
        "reason": "KEV-listed, network-reachable.",
        "host_snapshot": _snapshot(),
        "group_findings": [_make_finding()],
    }
    kwargs.update(overrides)
    return build_group_system_prompt(**kwargs)


def _data_block(prompt: str) -> str:
    """Extrahiert den Inhalt des echten Daten-Blocks.

    Der Anti-Injection-Guard nennt die Marker-Namen *ebenfalls* (vor dem
    Block). Der echte Daten-Block wird daher vom **letzten** START- und
    **letzten** END-Marker begrenzt — analog zur `rfind`-Konvention im alten
    `llm_prompt`-Test.
    """
    start = prompt.rindex(TRIVY_DATA_START) + len(TRIVY_DATA_START)
    end = prompt.rindex(TRIVY_DATA_END)
    return prompt[start:end]


# ---------------------------------------------------------------------------
# Marker-Disziplin
# ---------------------------------------------------------------------------


def test_data_block_delimiters_balanced() -> None:
    """Genau ein echtes Marker-Paar als Block-Delimiter; START vor END.

    Der Guard erwaehnt die Marker-Namen einmal (Hinweis-Satz), danach folgt
    genau eine oeffnende und eine schliessende Marker-Instanz als echter
    Block-Rahmen. Im Daten-Block selbst steht **kein** weiterer literaler
    Marker.
    """
    prompt = _build()
    # Guard nennt beide Marker einmal, Block rahmt mit je einem weiteren.
    assert prompt.count(TRIVY_DATA_START) == 2
    assert prompt.count(TRIVY_DATA_END) == 2
    # Realer Block: letzter START vor letztem END.
    assert prompt.rindex(TRIVY_DATA_START) < prompt.rindex(TRIVY_DATA_END)
    # Im Block selbst keine weiteren literalen Marker.
    block = _data_block(prompt)
    assert TRIVY_DATA_START not in block
    assert TRIVY_DATA_END not in block


def test_injection_guard_before_data_block() -> None:
    prompt = _build()
    guard_section = prompt[: prompt.rindex(TRIVY_DATA_START)]
    lc = guard_section.lower()
    assert "data" in lc
    assert "not instructions" in lc or "not commands" in lc or "ignore" in lc


def test_intro_is_english_and_present() -> None:
    prompt = _build()
    assert prompt.startswith("You are the Fathometer AI triage assistant")
    assert "exactly one package group" in prompt


def test_intro_demands_host_specific_attack_path() -> None:
    prompt = _build()
    assert "realistic attack path on THIS specific host" in prompt
    assert "do not give generic CVE textbook background" in prompt


def test_intro_caps_length_and_forbids_markdown() -> None:
    prompt = _build()
    assert "under ~150 words" in prompt
    assert "plain text only" in prompt
    assert "Do NOT use Markdown" in prompt


# ---------------------------------------------------------------------------
# Fingerprint zwischen den Markern
# ---------------------------------------------------------------------------


def test_all_fingerprint_fields_between_markers() -> None:
    prompt = _build(
        server=_make_server(
            name="db-07",
            os_pretty_name="Debian 12",
            kernel_version="6.1.0-amd64",
            architecture="aarch64",
            tags=["prod", "db"],
            last_scan=datetime(2026, 6, 5, 8, 30, tzinfo=UTC),
        )
    )
    block = _data_block(prompt)
    for token in ("db-07", "Debian 12", "6.1.0-amd64", "aarch64", "prod", "db"):
        assert token in block, token
    assert "2026-06-05T08:30" in block


def test_fingerprint_falls_back_to_os_family_and_dash() -> None:
    prompt = _build(
        server=_make_server(
            os_pretty_name=None,
            kernel_version=None,
            architecture=None,
            tags=[],
            last_scan=None,
        )
    )
    block = _data_block(prompt)
    # os_family-Fallback.
    assert "ubuntu" in block
    # Leere Tags + kein Last-Scan -> "-".
    assert "TAGS: -" in block
    assert "LAST SCAN: -" in block


# ---------------------------------------------------------------------------
# Services + Listeners
# ---------------------------------------------------------------------------


def test_services_sorted_alphabetically() -> None:
    prompt = _build(host_snapshot=_snapshot(services=["zsh", "apache", "mysql"]))
    block = _data_block(prompt)
    assert block.index("apache") < block.index("mysql") < block.index("zsh")


def test_empty_services_render_none() -> None:
    prompt = _build(host_snapshot=_snapshot(services=[]))
    assert "ACTIVE SERVICES: none" in _data_block(prompt)


def test_listener_exposure_rendering() -> None:
    prompt = _build()
    block = _data_block(prompt)
    assert "nginx · 0.0.0.0:443 · tcp · PUBLIC EXPOSED" in block
    assert "postgres · 127.0.0.1:5432 · tcp · LOOPBACK" in block


def test_empty_listeners_render_none() -> None:
    prompt = _build(host_snapshot=_snapshot(listeners=[]))
    assert "LISTENERS: none" in _data_block(prompt)


# ---------------------------------------------------------------------------
# Group-Kontext
# ---------------------------------------------------------------------------


def test_group_context_fields_present() -> None:
    prompt = _build()
    block = _data_block(prompt)
    assert "GROUP: openssl / TLS stack" in block
    assert "WORKFLOW LANE: escalate" in block
    assert "CVE-2026-0001" in block
    assert "KEV-listed, network-reachable." in block


def test_group_context_handles_missing_worst_and_reason() -> None:
    prompt = _build(worst_finding=None, reason=None, lane=None)
    block = _data_block(prompt)
    assert "WORST FINDING: -" in block
    assert "SCANNER REASON: -" in block
    assert "WORKFLOW LANE: -" in block


# ---------------------------------------------------------------------------
# Findings-Zeilen-Format
# ---------------------------------------------------------------------------


def test_finding_line_format() -> None:
    prompt = _build(
        group_findings=[
            _make_finding(
                identifier_key="CVE-2026-1234",
                severity=Severity.CRITICAL,
                cvss=9.8,
                epss=0.9731,
                is_kev=True,
                attack_vector=AttackVector.NETWORK,
                title="Remote Code Execution",
            )
        ]
    )
    block = _data_block(prompt)
    assert (
        "- CVE-2026-1234 | sev=critical | cvss=9.8 | epss=0.9731 | "
        "kev=yes | vec=network | Remote Code Execution" in block
    )


def test_finding_line_handles_null_scores() -> None:
    prompt = _build(
        group_findings=[
            _make_finding(cvss=None, epss=None, is_kev=False, title=None),
        ]
    )
    block = _data_block(prompt)
    assert "cvss=- | epss=- |" in block
    assert "kev=no" in block
    # title None -> "-"
    assert block.rstrip().endswith("| -")


def test_empty_group_renders_no_findings_message() -> None:
    prompt = _build(group_findings=[])
    block = _data_block(prompt)
    assert "No open findings in this group." in block


# ---------------------------------------------------------------------------
# Findings-Budget + Aggregat (ADR-0058)
# ---------------------------------------------------------------------------


def test_group_chat_findings_budget_value() -> None:
    """Budget ist bewusst kleiner als das Pass-2-Budget (32)."""
    assert GROUP_CHAT_FINDINGS_BUDGET == 15


def test_aggregate_line_rendered_when_rest_present() -> None:
    """Aggregat-Zeile fasst den nicht gezeigten Rest zusammen (Counts/EPSS/KEV)."""
    agg = FindingsAggregate(
        rest_count=730,
        severity_counts=(("critical", 3), ("high", 120), ("medium", 607)),
        max_epss=0.91,
        fixable_count=412,
        kev_count=2,
    )
    prompt = _build(
        group_findings=[_make_finding(identifier_key="CVE-2026-0001")],
        findings_aggregate=agg,
    )
    block = _data_block(prompt)
    assert "CVE-2026-0001" in block
    assert "730 more findings not shown" in block
    assert "critical=3, high=120, medium=607" in block
    assert "max_epss=0.91" in block
    assert "kev=2" in block
    assert "fixable=412" in block
    # Marker-Disziplin bleibt erhalten — kein literaler Marker im Aggregat.
    assert TRIVY_DATA_START not in block
    assert TRIVY_DATA_END not in block


def test_aggregate_omitted_when_none() -> None:
    """Ohne Aggregat (kein Trim) keine ``... more ...``-Zeile."""
    prompt = _build(
        group_findings=[_make_finding(identifier_key="CVE-2026-0001")],
        findings_aggregate=None,
    )
    block = _data_block(prompt)
    assert "more findings not shown" not in block


def test_aggregate_with_zero_rest_renders_nothing() -> None:
    """``rest_count == 0`` -> keine Aggregat-Zeile (defensiv)."""
    agg = FindingsAggregate(
        rest_count=0,
        severity_counts=(),
        max_epss=None,
        fixable_count=0,
        kev_count=0,
    )
    prompt = _build(
        group_findings=[_make_finding(identifier_key="CVE-2026-0001")],
        findings_aggregate=agg,
    )
    block = _data_block(prompt)
    assert "more findings not shown" not in block


def test_aggregate_only_rest_no_selected_still_renders() -> None:
    """Leere Selektion aber Rest vorhanden -> Aggregat-Zeile statt Empty-Hinweis."""
    agg = FindingsAggregate(
        rest_count=5,
        severity_counts=(("high", 5),),
        max_epss=None,
        fixable_count=0,
        kev_count=0,
    )
    prompt = _build(group_findings=[], findings_aggregate=agg)
    block = _data_block(prompt)
    assert "No open findings in this group." not in block
    assert "5 more findings not shown" in block
    assert "max_epss=n/a" in block


def test_multiple_findings_each_on_own_line() -> None:
    prompt = _build(
        group_findings=[
            _make_finding(identifier_key="CVE-2026-0001"),
            _make_finding(identifier_key="CVE-2026-0002"),
        ]
    )
    block = _data_block(prompt)
    assert "CVE-2026-0001" in block
    assert "CVE-2026-0002" in block
    findings_section = block[block.index("FINDINGS:") :]
    assert findings_section.count("\n- ") == 2


# ---------------------------------------------------------------------------
# _safe-Sanitization
# ---------------------------------------------------------------------------


def test_safe_strips_nul() -> None:
    assert "\x00" not in _safe("ab\x00cd")
    assert _safe("ab\x00cd") == "abcd"


def test_safe_strips_control_chars_keeps_tab_newline() -> None:
    out = _safe("a\x01b\x1fc\td\ne", max_len=200)
    assert "\x01" not in out
    assert "\x1f" not in out
    assert "\t" in out
    assert "\n" in out
    assert "abc" in out


def test_safe_strips_del() -> None:
    assert "\x7f" not in _safe("a\x7fb")


def test_safe_caps_length() -> None:
    out = _safe("x" * 500, max_len=64)
    assert len(out) == 64
    assert out.endswith("…")


def test_safe_empty_and_none_become_dash() -> None:
    assert _safe(None) == "-"
    assert _safe("") == "-"
    assert _safe("\x00\x00") == "-"


def test_safe_applied_to_finding_title_in_prompt() -> None:
    prompt = _build(
        group_findings=[_make_finding(title="evil\x00\x07title")],
    )
    block = _data_block(prompt)
    assert "\x00" not in block
    assert "\x07" not in block
    assert "eviltitle" in block


# ---------------------------------------------------------------------------
# CHAT_SUGGESTIONS + build_user_intro
# ---------------------------------------------------------------------------


def test_chat_suggestions_single_source() -> None:
    assert [s.label for s in CHAT_SUGGESTIONS] == [
        "Explain attack vector",
        "List exploitable findings",
    ]


def test_chat_suggestion_prompt_decoupled_from_label() -> None:
    # Der gesendete Prompt ist laenger/praeziser als das knappe Chip-Label
    # und verlangt explizit den host-spezifischen Angriffspfad (ADR-0055).
    sug = CHAT_SUGGESTIONS[0]
    assert sug.prompt != sug.label
    assert "compromise THIS server" in sug.prompt
    assert "concrete attack path" in sug.prompt


def test_list_exploitable_suggestion_present_and_decoupled() -> None:
    # Zweite Schnellwahl (ADR-0055/Task): listet alle real exploitable Findings
    # der Group auf. Label kurz, Prompt ausformuliert und host-spezifisch.
    sug = next(s for s in CHAT_SUGGESTIONS if s.label == "List exploitable findings")
    assert sug.prompt != sug.label
    assert "every finding" in sug.prompt
    assert "THIS host" in sug.prompt
    # Verlangt eine vollstaendige Liste statt Zusammenfassung (Admin-Ziel).
    assert "do not summarize them away" in sug.prompt


def test_build_user_intro_contains_group_label() -> None:
    intro = build_user_intro("openssl / TLS stack")
    assert "openssl / TLS stack" in intro
