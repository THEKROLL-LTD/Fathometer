"""Pure-Unit-Tests fuer TICKET-013 / ADR-0053 (Fix-Lane-Evaluation) — die
View-Schicht in `app/views/server_detail.py`.

Deckt:
  * `_load_application_groups_for_server`: gemischte Group liefert zwei
    `lanes`-Eintraege (patch zuerst, dann mitigate); Lane-eigener Count,
    Live-Worst und Drift; Group-Total = Summe ueber Lanes; Group-Sort nach
    Max-Band ueber die Lanes.
  * `_build_action_sections`: flache `(group, lane)`-Eintraege; eine Group
    erscheint in zwei Cards wenn beide Lanes escalate sind; reine patch-Group
    nur in der Patch-Card; kein `act + mitigate`-Match.

Kein DB-Fixture noetig: SessionExecute wird via Fake-Session beantwortet,
Rows sind SimpleNamespace (Attribut-Zugriff wie SQLAlchemy-Row).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.services.llm_fingerprints import group_findings_fingerprint
from app.views.server_detail import (
    _build_action_sections,
    _load_application_groups_for_server,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(**fields: Any) -> SimpleNamespace:
    return SimpleNamespace(**fields)


class _FakeResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def all(self) -> list[Any]:
        return list(self._rows)


class _FakeSession:
    def __init__(self, execute_returns: list[list[Any]]) -> None:
        self._returns = iter(execute_returns)

    def execute(self, _stmt: Any) -> _FakeResult:
        return _FakeResult(next(self._returns))


def _group_row(group_id: int, label: str, group_kind: str = "os_package") -> SimpleNamespace:
    return _row(id=group_id, label=label, group_kind=group_kind, explanation=None)


def _eval_row(
    group_id: int,
    fix_lane: str,
    risk_band: str,
    action_type: str,
    worst_finding_id: int | None = None,
    *,
    fingerprint: str | None = None,
) -> SimpleNamespace:
    return _row(
        group_id=group_id,
        fix_lane=fix_lane,
        risk_band=risk_band,
        risk_band_reason=f"{risk_band} reason",
        worst_finding_id=worst_finding_id,
        action_type=action_type,
        risk_band_computed_at=None,
        group_findings_fingerprint=fingerprint,
    )


def _worst_row(group_id: int, fix_lane: str, finding_id: int) -> SimpleNamespace:
    # ADR-0061: Query (4) projiziert fix_lane direkt (Lane-CASE), nicht has_fix.
    return _row(
        application_group_id=group_id,
        fix_lane=fix_lane,
        id=finding_id,
        identifier_key=f"CVE-2026-{finding_id}",
        package_name="pkg",
        title="bug",
    )


def _open_row(group_id: int, fix_lane: str, finding_id: int) -> SimpleNamespace:
    """Query-(5)-Row (Lane-OPEN-Set-Projektion, TICKET-014; ADR-0061: fix_lane)."""
    return _row(
        application_group_id=group_id,
        fix_lane=fix_lane,
        id=finding_id,
        identifier_key=f"CVE-2026-{finding_id}",
        package_purl="",
    )


def _fp(open_rows: list[Any]) -> str:
    return group_findings_fingerprint(open_rows)


# ---------------------------------------------------------------------------
# _load_application_groups_for_server — Lane-Split
# ---------------------------------------------------------------------------


def test_mixed_group_yields_two_lanes_patch_first() -> None:
    """Eine Group mit patch- und mitigate-Findings liefert zwei Lane-
    Eintraege, patch zuerst; Lane-Counts korrekt, Group-Total = Summe."""
    counts_rows: list[Any] = [(10, "patch", 4), (10, "mitigate", 3)]
    group_rows = [_group_row(10, "kernel")]
    patch_open = [_open_row(10, "patch", 100)]
    mitigate_open = [_open_row(10, "mitigate", 200)]
    eval_rows = [
        _eval_row(
            10, "patch", "escalate", "patch", worst_finding_id=100, fingerprint=_fp(patch_open)
        ),
        _eval_row(
            10, "mitigate", "monitor", "watch", worst_finding_id=200, fingerprint=_fp(mitigate_open)
        ),
    ]
    worst_rows = [
        _worst_row(10, "patch", 100),
        _worst_row(10, "mitigate", 200),
    ]
    open_rows = patch_open + mitigate_open
    sess = _FakeSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)

    assert len(result) == 1
    entry = result[0]
    assert entry["count"] == 7, "Group-Total = Summe ueber Lanes (4 + 3)"
    lanes = entry["lanes"]
    assert [lane["fix_lane"] for lane in lanes] == ["patch", "mitigate"]

    patch_lane = lanes[0]
    assert patch_lane["count"] == 4
    assert patch_lane["evaluation"].risk_band == "escalate"
    assert patch_lane["worst_finding"].id == 100
    assert patch_lane["worst_finding_drift"] is False

    mitigate_lane = lanes[1]
    assert mitigate_lane["count"] == 3
    assert mitigate_lane["evaluation"].risk_band == "monitor"
    assert mitigate_lane["worst_finding"].id == 200
    assert mitigate_lane["worst_finding_drift"] is False


def test_pure_patch_group_has_single_patch_lane() -> None:
    """Reine patch-Group (nur has_fix=True) hat genau eine patch-Lane."""
    counts_rows: list[Any] = [(10, "patch", 2)]
    group_rows = [_group_row(10, "openssl")]
    open_rows = [_open_row(10, "patch", 100)]
    eval_rows = [_eval_row(10, "patch", "act", "patch", fingerprint=_fp(open_rows))]
    worst_rows = [_worst_row(10, "patch", 100)]
    sess = _FakeSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)

    lanes = result[0]["lanes"]
    assert [lane["fix_lane"] for lane in lanes] == ["patch"]
    assert result[0]["count"] == 2


def test_lane_worst_and_drift_are_per_lane() -> None:
    """Drift wird pro Lane berechnet (TICKET-014): die patch-Lane-Eval zeigt
    auf ein nicht mehr offenes Finding (999 ∉ {100}) -> Drift; die
    mitigate-Lane ist in-sync (Fingerprint stimmt, worst offen) -> kein Drift.
    Die Anzeige-Spalte zeigt unabhaengig davon den Triage-Live-Worst."""
    counts_rows: list[Any] = [(10, "patch", 2), (10, "mitigate", 1)]
    group_rows = [_group_row(10, "mixed")]
    patch_open = [_open_row(10, "patch", 100)]
    mitigate_open = [_open_row(10, "mitigate", 200)]
    eval_rows = [
        _eval_row(
            10, "patch", "escalate", "patch", worst_finding_id=999, fingerprint=_fp(patch_open)
        ),
        _eval_row(
            10,
            "mitigate",
            "escalate",
            "mitigate",
            worst_finding_id=200,
            fingerprint=_fp(mitigate_open),
        ),
    ]
    worst_rows = [
        _worst_row(10, "patch", 100),
        _worst_row(10, "mitigate", 200),
    ]
    open_rows = patch_open + mitigate_open
    sess = _FakeSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    lanes = _load_application_groups_for_server(sess, 1)[0]["lanes"]
    by_lane = {lane["fix_lane"]: lane for lane in lanes}
    assert by_lane["patch"]["worst_finding"].id == 100
    assert by_lane["patch"]["worst_finding_drift"] is True
    assert by_lane["mitigate"]["worst_finding_drift"] is False


def test_group_sort_uses_max_band_over_lanes() -> None:
    """Group-Sort richtet sich nach dem Max-Band ueber die Lanes: eine Group
    deren mitigate-Lane escalate ist steht ueber einer reinen act-Group,
    auch wenn ihre patch-Lane nur monitor ist."""
    counts_rows: list[Any] = [
        (10, "patch", 1),
        (10, "mitigate", 1),
        (20, "patch", 1),
    ]
    group_rows = [_group_row(10, "mixed-escalate"), _group_row(20, "pure-act")]
    eval_rows = [
        _eval_row(10, "patch", "monitor", "watch"),
        _eval_row(10, "mitigate", "escalate", "mitigate"),
        _eval_row(20, "patch", "act", "patch"),
    ]
    worst_rows: list[Any] = []
    open_rows: list[Any] = []
    sess = _FakeSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)
    assert [e["group"].label for e in result] == ["mixed-escalate", "pure-act"]


def test_lane_without_eval_counts_as_pending_for_sort() -> None:
    """Eine Lane ohne Eval-Row zaehlt fuer die Group-Sort als PENDING-Rank;
    eine Group mit unbewerteter Lane steht ueber einer reinen act-Group
    (PENDING-Rank 40 < act-Rank 60? — PENDING ist niedriger, also act zuerst).
    """
    counts_rows: list[Any] = [(10, "patch", 1), (20, "patch", 1)]
    group_rows = [_group_row(10, "pending-lane"), _group_row(20, "act-lane")]
    eval_rows = [_eval_row(20, "patch", "act", "patch")]
    worst_rows: list[Any] = []
    open_rows: list[Any] = []
    sess = _FakeSession([counts_rows, group_rows, eval_rows, worst_rows, open_rows])
    result = _load_application_groups_for_server(sess, 1)
    # act-Rank (60) > PENDING-Rank (40) -> act-Lane-Group zuerst.
    assert [e["group"].label for e in result] == ["act-lane", "pending-lane"]
    # Die pending-lane-Group traegt eine Lane mit evaluation=None.
    pending = next(e for e in result if e["group"].label == "pending-lane")
    assert pending["lanes"][0]["evaluation"] is None


# ---------------------------------------------------------------------------
# _build_action_sections — (group, lane)-Eintraege
# ---------------------------------------------------------------------------


def _group_entry(
    group_id: int,
    label: str,
    group_kind: str,
    lanes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Baut den Lane-Kontrakt-Entry wie ihn der Loader ausgibt."""
    return {
        "group": _group_row(group_id, label, group_kind),
        "count": sum(lane["count"] for lane in lanes),
        "lanes": lanes,
    }


def _lane(
    fix_lane: str,
    risk_band: str,
    action_type: str,
    *,
    count: int = 1,
    worst_id: int = 1,
) -> dict[str, Any]:
    return {
        "fix_lane": fix_lane,
        "evaluation": _eval_row(0, fix_lane, risk_band, action_type),
        "count": count,
        "worst_finding": _worst_row(0, fix_lane, worst_id),
        "worst_finding_drift": False,
    }


def _cards_by_id(application_groups: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {card["id"]: card for card in _build_action_sections(application_groups)}


def test_group_in_two_cards_when_both_lanes_escalate() -> None:
    """Eine Group mit escalate-patch UND escalate-mitigate erscheint in zwei
    Cards: ESCALATE-Patch-distro UND ESCALATE-No-patch-mitigate."""
    groups = [
        _group_entry(
            10,
            "kernel",
            "os_package",
            [
                _lane("patch", "escalate", "patch"),
                _lane("mitigate", "escalate", "mitigate"),
            ],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-distro-patch" in cards
    assert "escalate-mitigate" in cards
    # Beide Cards tragen GENAU diese Group als flachen Lane-Eintrag.
    patch_entries = cards["escalate-distro-patch"]["groups"]
    mitigate_entries = cards["escalate-mitigate"]["groups"]
    assert [e["group"].label for e in patch_entries] == ["kernel"]
    assert [e["fix_lane"] for e in patch_entries] == ["patch"]
    assert [e["group"].label for e in mitigate_entries] == ["kernel"]
    assert [e["fix_lane"] for e in mitigate_entries] == ["mitigate"]


def test_pure_patch_group_only_in_patch_card() -> None:
    """Reine patch-Group (escalate) matcht nur die Patch-distro-Card, nicht
    die mitigate-Card."""
    groups = [
        _group_entry(
            10,
            "openssl",
            "os_package",
            [_lane("patch", "escalate", "patch")],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-distro-patch" in cards
    assert "escalate-mitigate" not in cards


def test_flat_entry_contract_keys() -> None:
    """Die flachen Lane-Eintraege tragen die vom Template gelesenen Keys."""
    groups = [
        _group_entry(
            10,
            "openssl",
            "os_package",
            [_lane("patch", "escalate", "patch", count=4, worst_id=42)],
        )
    ]
    entry = _cards_by_id(groups)["escalate-distro-patch"]["groups"][0]
    assert set(entry.keys()) == {
        "group",
        "fix_lane",
        "evaluation",
        "count",
        "worst_finding",
        "worst_finding_drift",
    }
    assert entry["fix_lane"] == "patch"
    assert entry["count"] == 4
    assert entry["evaluation"].risk_band_reason == "escalate reason"
    assert entry["worst_finding"].id == 42
    assert entry["worst_finding_drift"] is False


def test_no_act_mitigate_card() -> None:
    """Es gibt KEINE act+mitigate-Karte: eine mitigate-Lane mit risk_band=act
    (haette es per Band-Whitelist nie geben duerfen) matcht keine Card."""
    groups = [
        _group_entry(
            10,
            "kernel",
            "os_package",
            [_lane("mitigate", "act", "mitigate")],
        )
    ]
    cards = _build_action_sections(groups)
    assert cards == [], "act+mitigate darf in keiner Card landen"


def test_app_bundle_escalate_patch_routes_to_app_card() -> None:
    """escalate-patch auf einer application_bundle-Group landet in der
    App-Update-Card, nicht in der distro-Card."""
    groups = [
        _group_entry(
            10,
            "nginx-bundle",
            "application_bundle",
            [_lane("patch", "escalate", "patch")],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-app-update" in cards
    assert "escalate-distro-patch" not in cards


def test_monitor_lane_matches_no_action_card() -> None:
    """monitor/noise-Lanes sind kein Action-Needed -> keine Card."""
    groups = [
        _group_entry(
            10,
            "quiet",
            "os_package",
            [
                _lane("patch", "monitor", "watch"),
                _lane("mitigate", "noise", "none"),
            ],
        )
    ]
    assert _build_action_sections(groups) == []


def test_lane_without_evaluation_skipped() -> None:
    """Eine Lane ohne Eval-Row (evaluation=None) matcht keine Card."""
    groups = [
        {
            "group": _group_row(10, "half", "os_package"),
            "count": 1,
            "lanes": [
                {
                    "fix_lane": "patch",
                    "evaluation": None,
                    "count": 1,
                    "worst_finding": None,
                    "worst_finding_drift": False,
                }
            ],
        }
    ]
    assert _build_action_sections(groups) == []


# ---------------------------------------------------------------------------
# ADR-0064: upstream-Lane in mitigate kollabiert — nur noch escalate-mitigate
# ---------------------------------------------------------------------------


def test_escalate_mitigate_card_has_no_upstream_sibling() -> None:
    """ADR-0064: die ``upstream``-Lane ist in ``mitigate`` kollabiert; es gibt
    nur noch die ``escalate-mitigate``-Card (keine ``escalate-upstream``).
    Ein has-fix-lang-pkgs-Finding (frueher upstream-Lane) liegt jetzt in der
    ``mitigate``-Lane und landet in ``escalate-mitigate``."""
    groups = [
        _group_entry(
            10,
            "go-toolchain",
            "os_package",
            [_lane("mitigate", "escalate", "mitigate")],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-mitigate" in cards
    assert "escalate-upstream" not in cards
    mitigate_entries = cards["escalate-mitigate"]["groups"]
    assert [e["group"].label for e in mitigate_entries] == ["go-toolchain"]
    assert [e["fix_lane"] for e in mitigate_entries] == ["mitigate"]


def test_escalate_mitigate_label_says_no_host_patch() -> None:
    """ADR-0064: Card-Label ist ``No host patch — mitigate`` (praeziser als
    ``No patch``, weil ein Upstream-Fix pro Row existieren kann)."""
    groups = [
        _group_entry(
            10,
            "no-fix-lib",
            "os_package",
            [_lane("mitigate", "escalate", "mitigate")],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-mitigate" in cards
    assert cards["escalate-mitigate"]["label"] == "ESCALATE · No host patch — mitigate"


def test_group_with_patch_and_mitigate_lanes_appears_in_two_cards() -> None:
    """Eine Group mit BEIDEN Lanes (escalate-patch + escalate-mitigate)
    erscheint in zwei Cards: distro-patch UND mitigate — je mit dem passenden
    Lane-Eintrag (ADR-0064: kein eigener upstream-Eimer mehr)."""
    groups = [
        _group_entry(
            10,
            "mixed-stack",
            "os_package",
            [
                _lane("patch", "escalate", "patch"),
                _lane("mitigate", "escalate", "mitigate"),
            ],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-distro-patch" in cards
    assert "escalate-mitigate" in cards
    assert "escalate-upstream" not in cards
    assert [e["fix_lane"] for e in cards["escalate-distro-patch"]["groups"]] == ["patch"]
    assert [e["fix_lane"] for e in cards["escalate-mitigate"]["groups"]] == ["mitigate"]


def test_cve_2026_42504_lang_pkgs_fix_does_not_emit_app_update_card() -> None:
    """CVE-2026-42504-Regression auf Card-Ebene: ein has-fix-lang-pkgs-Eintrag
    (gobinary/stdlib-Fix, nicht host-applizierbar) erzeugt KEINE
    ``act-app-update``/``escalate-app-update``-Card — er gehoert in die
    ``escalate-mitigate``-Card (ADR-0064: Upstream-Fix ist Finding-Level, der
    Fix landet in der mitigate-Lane). Vor ADR-0061 waere ein solcher Fix
    faelschlich als host-applizierbarer Patch gerendert worden."""
    groups = [
        _group_entry(
            10,
            "tailscaled",
            "application_bundle",
            [_lane("mitigate", "escalate", "mitigate")],
        )
    ]
    cards = _cards_by_id(groups)
    assert "escalate-mitigate" in cards
    assert "escalate-upstream" not in cards
    assert "escalate-app-update" not in cards
    assert "act-app-update" not in cards
    assert "escalate-distro-patch" not in cards
    assert [e["fix_lane"] for e in cards["escalate-mitigate"]["groups"]] == ["mitigate"]
