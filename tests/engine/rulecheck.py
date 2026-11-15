"""Which binder rules the code refuses on, and which ones a test claims to trigger."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*(\.[A-Z0-9_]+)+$")
ENFORCING = {"enforce", "refuse", "IssuerError", "_proof_error", "bad", "fail"}
SRC = sorted((ROOT / "src" / "cunho").rglob("*.py"))
TESTS = sorted((ROOT / "tests" / "engine").glob("test_*.py"))
# Milestones whose every rule must have code and a test. A milestone joins FINISHED when it is done; while it
# is BUILDING its rules need a test only for the code that already claims them.
FINISHED = frozenset({"M2", "M3", "M4"})
BUILDING: frozenset[str] = frozenset()


def rule_ids(paths: list[Path], calls: set[str]) -> set[str]:
    """Rule ids passed, as string constants, to calls of the named functions."""
    found: set[str] = set()
    for path in paths:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if name in calls:
                    found |= {
                        a.value
                        for a in ast.walk(node)
                        if isinstance(a, ast.Constant) and isinstance(a.value, str) and RULE_ID.match(a.value)
                    }
    return found


def refused_rules(paths: list[Path]) -> set[str]:
    """Rule ids the code can refuse on: every rule-id literal outside an `implements(...)` decorator.

    Most reach `enforce`/`refuse` directly; a few are handed to a helper that refuses with them (a proof
    `typ` rule, a nonce rule, a body-size rule), so a call-site scan alone would miss them.
    """
    found: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text())
        declared = {
            id(a)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "implements"
            for a in ast.walk(node)
        }
        found |= {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and RULE_ID.match(node.value)
            and id(node) not in declared
        }
    return found


ENFORCED = refused_rules(SRC)


def milestone_rules(registry: dict[str, dict[str, object]], milestones: frozenset[str]) -> set[str]:
    """The registry's rule ids whose milestone is one of `milestones`."""
    return {rule for rule, entry in registry.items() if entry["milestone"] in milestones}
