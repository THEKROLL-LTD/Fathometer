# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 THEKROLL LTD

"""Length budgets for the documentation artifacts (AGENTS.md, "Documentation
hygiene"). Pure-unit: reads files, touches nothing else.

The budgets exist because TICKET-021 shipped a 46-line CHANGELOG block, a
1400-word STATE.md paragraph and an ADR that all re-narrated the same fix.
A rule nobody can fail is a rule nobody follows, so these are tests.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

MAX_CHANGELOG_BLOCK_LINES = 25
MAX_ADR_LINES = 80
# The budget applies from ADR-0072 (when the policy landed) onwards. Older ADRs
# are legacy and are not retrofitted.
FIRST_BUDGETED_ADR = 72

_ADR_FILENAME_RE = re.compile(r"^(\d{4})-.+\.md$")


def _adr_paths() -> list[Path]:
    return sorted(p for p in (REPO_ROOT / "docs" / "decisions").glob("*.md"))


def _unreleased_blocks() -> dict[str, list[str]]:
    """`### ` blocks under `## [Unreleased]`, keyed by their heading."""
    lines = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    blocks: dict[str, list[str]] = {}
    heading: str | None = None
    in_unreleased = False
    for line in lines:
        if line.startswith("## "):
            in_unreleased = line.strip().startswith("## [Unreleased]")
            heading = None
            continue
        if not in_unreleased:
            continue
        if line.startswith("### "):
            heading = line[4:].strip()
            blocks[heading] = []
            continue
        if heading is not None:
            blocks[heading].append(line)
    # Trailing blank lines belong to the separation, not to the block.
    return {h: _rstrip_blank(body) for h, body in blocks.items()}


def _rstrip_blank(lines: list[str]) -> list[str]:
    end = len(lines)
    while end and not lines[end - 1].strip():
        end -= 1
    return lines[:end]


def test_changelog_unreleased_blocks_stay_within_budget() -> None:
    over = {
        heading: len(body)
        for heading, body in _unreleased_blocks().items()
        if len(body) > MAX_CHANGELOG_BLOCK_LINES
    }
    assert not over, (
        f"CHANGELOG [Unreleased] block(s) over {MAX_CHANGELOG_BLOCK_LINES} lines: {over}. "
        "State what changes for the operator; rationale belongs in the ADR."
    )


@pytest.mark.parametrize("path", _adr_paths(), ids=lambda p: p.name)
def test_adr_stays_within_budget(path: Path) -> None:
    match = _ADR_FILENAME_RE.match(path.name)
    if match is None:  # README.md — the index, not an ADR.
        pytest.skip(f"{path.name} is not an ADR")
    if int(match.group(1)) < FIRST_BUDGETED_ADR:
        pytest.skip(f"{path.name} predates the budget (ADR-{FIRST_BUDGETED_ADR:04d})")
    length = len(path.read_text(encoding="utf-8").splitlines())
    assert length <= MAX_ADR_LINES, (
        f"{path.name} is {length} lines, budget {MAX_ADR_LINES}. An ADR records the "
        "decision and the alternative rejected — not the implementation."
    )


_SUBAGENTS = (
    "backend-implementer",
    "frontend-implementer",
    "reviewer",
    "security-auditor",
    "test-writer",
)


def _agent_body(path: Path) -> str:
    """The Markdown below the frontmatter."""
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n.*?\n---\n(.*)$", text, re.S)
    assert match is not None, f"{path} has no frontmatter"
    return match.group(1)


@pytest.mark.parametrize("name", _SUBAGENTS)
def test_subagent_bodies_are_identical_across_tools(name: str) -> None:
    """Claude Code and OpenCode read different frontmatter but the same rules.

    Two copies of a prompt drift; a drifted reviewer prompt stops catching what
    the other one catches. Only the frontmatter may differ.
    """
    claude = _agent_body(REPO_ROOT / ".claude" / "agents" / f"{name}.md")
    opencode = _agent_body(REPO_ROOT / ".opencode" / "agents" / f"{name}.md")
    assert claude == opencode, (
        f"{name}: .claude/agents and .opencode/agents have drifted. "
        "Edit one, port the same text to the other in the same commit."
    )


def test_state_md_status_sections_are_tables() -> None:
    """`## Open` and `## Completed` hold table rows, nothing else.

    The format is the enforcement: a wall of text cannot be written as a row.
    """
    lines = (REPO_ROOT / "docs" / "blocks" / "STATE.md").read_text(encoding="utf-8").splitlines()
    tabled = {"## Open", "## Completed"}
    section: str | None = None
    offenders: list[str] = []
    for line in lines:
        if line.startswith("## "):
            section = line.strip()
            continue
        if section not in tabled or not line.strip():
            continue
        if not line.lstrip().startswith("|"):
            offenders.append(f"{section}: {line[:80]}")
    assert not offenders, (
        f"STATE.md prose outside a table row: {offenders}. "
        "One row per item; detail goes to the ADR, the block file and CHANGELOG.md."
    )
