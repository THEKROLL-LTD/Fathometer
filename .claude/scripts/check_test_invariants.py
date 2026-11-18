"""Structural test invariants for dependency fixes.

Usage: check_test_invariants.py <renovate-head> [--worktree]

Compares every changed Python file under tests/ between the Renovate head and HEAD
(or the working tree). Values inside checks may change; structure may not.
"""

import ast
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

CHECK_CALLS = {"raises", "warns"}
GIT = shutil.which("git") or "git"


def run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed git binary, workflow-controlled arguments
        [GIT, *args], capture_output=True, text=True, check=False
    )


def git(*args: str) -> str:
    result = run_git(*args)
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def old_source(rev: str, path: str) -> str | None:
    result = run_git("show", f"{rev}:{path}")
    return result.stdout if result.returncode == 0 else None


def new_source(path: str, worktree: bool) -> str | None:
    if worktree:
        file = Path(path)
        return file.read_text() if file.exists() else None
    return old_source("HEAD", path)


def is_pytest_check(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in CHECK_CALLS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
    )


def parametrize_cases(func: ast.AST) -> int:
    cases = 0
    for deco in getattr(func, "decorator_list", []):
        if (
            isinstance(deco, ast.Call)
            and isinstance(deco.func, ast.Attribute)
            and deco.func.attr == "parametrize"
            and len(deco.args) >= 2
            and isinstance(deco.args[1], (ast.List, ast.Tuple))
        ):
            cases += len(deco.args[1].elts)
    return cases


def summarize(func: ast.AST) -> dict:
    asserts = 0
    constant_asserts = 0
    exception_types: Counter[str] = Counter()
    for node in ast.walk(func):
        if isinstance(node, ast.Assert):
            asserts += 1
            if isinstance(node.test, ast.Constant):
                constant_asserts += 1
        elif is_pytest_check(node):
            first = ast.unparse(node.args[0]) if node.args else "<none>"
            exception_types[f"{node.func.attr}:{first}"] += 1
    return {
        "asserts": asserts,
        "constant_asserts": constant_asserts,
        "exception_types": exception_types,
        "cases": parametrize_cases(func),
    }


def tests_in(source: str) -> dict[str, dict]:
    tree = ast.parse(source)
    found: dict[str, dict] = {}

    def visit(body: list[ast.stmt], prefix: str) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
                "test_"
            ):
                found[f"{prefix}{node.name}"] = summarize(node)

    visit(tree.body, "")
    return found


def main() -> int:
    base = sys.argv[1]
    worktree = "--worktree" in sys.argv[2:]
    revs = [base] if worktree else [f"{base}..HEAD"]
    changed = git("diff", "--name-only", *revs, "--", "tests/").split()
    failures: list[str] = []

    for path in (p for p in changed if p.endswith(".py")):
        before, after = old_source(base, path), new_source(path, worktree)
        if before is None:
            if Path(path).name.startswith("test_"):
                failures.append(f"{path}: new test module")
            continue
        if after is None:
            failures.append(f"{path}: file deleted")
            continue
        old_tests, new_tests = tests_in(before), tests_in(after)
        for name in sorted(old_tests.keys() - new_tests.keys()):
            failures.append(f"{path}::{name}: test removed or renamed")
        for name in sorted(new_tests.keys() - old_tests.keys()):
            failures.append(f"{path}::{name}: test added")
        for name in sorted(old_tests.keys() & new_tests.keys()):
            old, new = old_tests[name], new_tests[name]
            if new["asserts"] < old["asserts"]:
                failures.append(
                    f"{path}::{name}: fewer asserts ({old['asserts']} -> {new['asserts']})"
                )
            if new["constant_asserts"] > old["constant_asserts"]:
                failures.append(f"{path}::{name}: assert on a constant added")
            if new["exception_types"] != old["exception_types"]:
                failures.append(
                    f"{path}::{name}: checked exception types changed "
                    f"({dict(old['exception_types'])} -> {dict(new['exception_types'])})"
                )
            if new["cases"] < old["cases"]:
                failures.append(
                    f"{path}::{name}: parametrization cases removed "
                    f"({old['cases']} -> {new['cases']})"
                )

    for line in failures:
        print(f"FAIL: {line}")
    if not failures:
        print("OK: test invariants hold")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
