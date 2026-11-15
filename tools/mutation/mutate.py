"""Mutation run over the engine: break one check at a time and expect a test to fail.

Every mode works on scratch copies of the checkout (the checkout itself is never changed):

- rules (default): `refuse()` is patched to do nothing for one rule id at a time, so every check under
  that id is gone at once (the run from the second M2 review, N-M6). The rules are those of M2 and M3
  that the code refuses on.
- sites (`--sites`): every refusing statement in `src/cunho` is replaced by `pass`, one at a time:
  `enforce(...)`, `refuse(...)`, `_proof_error(...)`, `bad(...)`, `fail(...)`, `problems.append(...)`
  and every `raise` statement, whatever it raises (IssuerError, JoseError, AuditError, ConfigError,
  ValueError...).
- conditions (`--conditions`): every condition that guards a refusal is altered, one change at a time.
  A guard is the test of an `if` whose body refuses (raises, calls a refusing helper, records a rulebook
  problem, returns False, None or a `(False, reason)` result, or skips with `continue`), and the
  condition passed to `enforce`. Each
  guard is negated, each operand of an `and`/`or` in it is dropped, each `not` in it is removed, and
  each comparison in it is moved across its boundary (`<` and `<=`, `>` and `>=`, `==` and `!=`, `in`
  and `not in`, `is` and `is not`). The hand-written patches in `patches.py` are added to this mode:
  semantic changes no automatic rule produces (a replay cache that lives one second, `min` turned into
  `max`, a nonce that is never consumed...).
- all (`--all`): sites and conditions together.

A mutant is KILLED when `pytest tests/engine -x` fails, SURVIVED when the suite stays green. Mutants
that cannot change behaviour are listed, each with its reason, in `equivalent.py`; a listed mutant
that is killed, or that no longer exists, is an error too, so the list stays short and true. The exit
code is 0 only when every other mutant is killed. Usage:

    python tools/mutation/mutate.py [--sites | --conditions | --all] [--jobs 4] [--shard 1/4]
                                    [--only TEXT] [--rules A,B] [--list] [--json out.json]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from equivalent import EQUIVALENT  # noqa: E402 - the tool's own directory
from patches import PATCHES  # noqa: E402

SKIP = {
    ".git",
    ".venv",
    "_work",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".hypothesis",
    "evidence",
    "research",
}
REFUSING = {"enforce", "refuse", "_proof_error", "bad", "fail"}
SWITCH = "CUNHO_MUTATION_DISABLE_RULE"
PATCH = f'''
import os as _mutation_os

_MUTATION_DISABLED = _mutation_os.environ.get("{SWITCH}")
_real_refuse = refuse


def refuse(rule, error, description, status=400, **kwargs):
    if rule == _MUTATION_DISABLED:
        return
    _real_refuse(rule, error, description, status, **kwargs)


def enforce(condition, rule, error, description, status=400, **kwargs):
    if not condition:
        refuse(rule, error, description, status, **kwargs)
'''
FLIP: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
}


@dataclass(frozen=True)
class Mutant:
    label: str
    file: str = ""
    kind: str = ""  # rule | site | negate | drop | not | flip | patch
    index: int = -1  # position of the node in ast.walk order (site and condition mutants)
    detail: int = 0  # which operand or comparison inside the guard
    rule: str = ""
    old: str = ""
    new: str = ""
    lines: tuple[int, int] = (0, 0)  # the source lines the change touches, for test selection


def _copy(target: Path, source: Path = ROOT) -> Path:
    def ignore(_: str, names: list[str]) -> set[str]:
        return {n for n in names if n in SKIP}

    shutil.copytree(source, target, ignore=ignore, symlinks=True)
    return target


# Rules mode switches off the rules of M2 and of M3, which is being built: an M3 rule is mutated as soon as
# code refuses on it, so its first tests are held to the same bar as M2's.
MILESTONES = frozenset({"M2", "M3"})


def milestone_rules(root: Path) -> list[str]:
    sys.path[:0] = [str(root)]
    try:
        from tests.engine.rulecheck import refused_rules  # noqa: PLC0415 - the copy's own definition
    finally:
        sys.path.remove(str(root))
    registry = json.loads((root / "src" / "cunho" / "rules" / "registry.json").read_text())
    enforced = refused_rules(sorted((root / "src" / "cunho").rglob("*.py")))
    return sorted(r for r in enforced if registry.get(r, {}).get("milestone") in MILESTONES)


# finding the nodes -------------------------------------------------------------------------------


def _name(call: ast.Call) -> str:
    return call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")


def _refusing_statement(node: ast.stmt) -> bool:
    """A raise, a call to a refusing helper, or `problems.append(...)` (a rulebook check's refusal)."""
    if isinstance(node, ast.Raise):
        return True
    if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
        return False
    call = node.value
    if isinstance(call.func, ast.Attribute) and call.func.attr == "append":
        return isinstance(call.func.value, ast.Name) and call.func.value.id == "problems"
    return _name(call) in REFUSING


def _refuses(body: list[ast.stmt]) -> bool:
    """A guarded body that refuses: raises, calls a refusing helper, returns a refusal, or skips."""
    for node in body:
        if _refusing_statement(node) or isinstance(node, ast.Continue):
            return True
        if isinstance(node, ast.Return) and node.value is not None:
            value = node.value
            if isinstance(value, ast.Constant) and value.value in (False, None):
                return True
            if isinstance(value, ast.Tuple) and value.elts and isinstance(value.elts[0], ast.Constant):
                if value.elts[0].value is False:
                    return True
    return False


def _qualnames(tree: ast.Module) -> dict[int, str]:
    """The enclosing function or class of every node, for labels that survive line moves."""
    out: dict[int, str] = {}

    def visit(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                inner = f"{scope}.{child.name}" if scope else child.name
            out[id(child)] = inner or "<module>"
            visit(child, inner)

    visit(tree, "")
    return out


def _short(node: ast.AST, limit: int = 90) -> str:
    text = " ".join(ast.unparse(node).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _guard_parts(guard: ast.expr) -> tuple[list[ast.BoolOp], list[ast.UnaryOp], list[ast.Compare]]:
    """BoolOps, `not`s and comparisons inside a guard, not descending into lambdas or comprehensions."""
    bools: list[ast.BoolOp] = []
    nots: list[ast.UnaryOp] = []
    compares: list[ast.Compare] = []
    stack: list[ast.AST] = [guard]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Lambda | ast.GeneratorExp | ast.ListComp | ast.SetComp | ast.DictComp):
            continue
        if isinstance(node, ast.BoolOp):
            bools.append(node)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            nots.append(node)
        elif isinstance(node, ast.Compare):
            compares.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return bools, nots, compares


def _guards(tree: ast.Module) -> list[tuple[int, ast.expr]]:
    """(walk index of the owning node, guard expression) for every guard in the module."""
    out = []
    for index, node in enumerate(ast.walk(tree)):
        if isinstance(node, ast.If) and _refuses(node.body):
            out.append((index, node.test))
        elif isinstance(node, ast.Call) and _name(node) == "enforce" and node.args:
            out.append((index, node.args[0]))
    return out


def discover(root: Path, kinds: set[str]) -> list[Mutant]:
    found: list[Mutant] = []
    for path in sorted((root / "src" / "cunho").rglob("*.py")):
        found += _discover_file(root, path, kinds)
    if "condition" in kinds:
        for label, file, old, new in PATCHES:
            source = (root / "src" / "cunho" / file).read_text()
            start = source[: source.find(old)].count("\n") + 1 if old in source else 0
            span = (start, start + old.count("\n"))
            found.append(Mutant(f"patch: {label}", f"src/cunho/{file}", "patch", old=old, new=new, lines=span))
    return found


def _discover_file(root: Path, path: Path, kinds: set[str]) -> list[Mutant]:
    found: list[Mutant] = []
    relative = str(path.relative_to(root))
    short = relative.removeprefix("src/cunho/")
    tree = ast.parse(path.read_text())
    scope = _qualnames(tree)
    seen: Counter[str] = Counter()

    def add(kind: str, index: int, owner: ast.AST, what: str, detail: int = 0, rule: str = "") -> None:
        base = f"{short}:{scope.get(id(owner), '<module>')}: {kind}: {what}"
        seen[base] += 1
        label = base if seen[base] == 1 else f"{base} #{seen[base]}"
        node = nodes[index]
        target = node.test if kind == "negate" and isinstance(node, ast.If) else node
        span = (getattr(target, "lineno", 0), getattr(target, "end_lineno", 0) or getattr(target, "lineno", 0))
        found.append(Mutant(label, relative, kind, index, detail, rule, lines=span))

    nodes = list(ast.walk(tree))
    if "site" in kinds:
        for index, node in enumerate(nodes):
            if isinstance(node, ast.stmt) and _refusing_statement(node):
                call = node.value if isinstance(node, ast.Expr) else getattr(node, "exc", None)
                rule = ""
                if isinstance(call, ast.Call):
                    rule = next(
                        (a.value for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, str)),
                        "",
                    )
                add("site", index, node, _short(node), rule=rule)
    if "condition" in kinds:
        positions = {id(n): i for i, n in enumerate(nodes)}
        for index, guard in _guards(tree):
            owner = nodes[index]
            add("negate", index, owner, _short(guard))
            bools, nots, compares = _guard_parts(guard)
            for bool_op in bools:
                for position, operand in enumerate(bool_op.values):
                    add(
                        "drop",
                        positions[id(bool_op)],
                        owner,
                        f"{_short(operand, 60)} in {_short(guard, 60)}",
                        position,
                    )
            for unary in nots:
                add("not", positions[id(unary)], owner, f"{_short(unary, 60)} in {_short(guard, 60)}")
            for compare in compares:
                for position, op in enumerate(compare.ops):
                    if type(op) in FLIP:
                        add("flip", positions[id(compare)], owner, f"{_short(compare, 60)} [{position}]", position)
    return found


# applying them -----------------------------------------------------------------------------------


class _Swap(ast.NodeTransformer):
    def __init__(self, target: ast.AST, replacement: ast.AST) -> None:
        self.target = target
        self.replacement = replacement

    def generic_visit(self, node: ast.AST) -> ast.AST:
        if node is self.target:
            return self.replacement
        return super().generic_visit(node)


def mutated_source(source: str, mutant: Mutant) -> str:
    if mutant.kind == "patch":
        count = source.count(mutant.old)
        if count != 1:
            raise ValueError(f"patch {mutant.label!r} matches {count} times; update tools/mutation/patches.py")
        return source.replace(mutant.old, mutant.new)
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    node = nodes[mutant.index]
    replacement: ast.AST
    if mutant.kind == "site":
        replacement = ast.Pass()
    elif mutant.kind == "negate":
        if isinstance(node, ast.If):
            node.test = ast.UnaryOp(ast.Not(), node.test)
        else:
            assert isinstance(node, ast.Call)
            node.args[0] = ast.UnaryOp(ast.Not(), node.args[0])
        replacement = node
    elif mutant.kind == "drop":
        assert isinstance(node, ast.BoolOp)
        rest = [v for i, v in enumerate(node.values) if i != mutant.detail]
        replacement = rest[0] if len(rest) == 1 else ast.BoolOp(node.op, rest)
    elif mutant.kind == "not":
        assert isinstance(node, ast.UnaryOp)
        replacement = node.operand
    elif mutant.kind == "flip":
        assert isinstance(node, ast.Compare)
        ops = list(node.ops)
        ops[mutant.detail] = FLIP[type(ops[mutant.detail])]()
        replacement = ast.Compare(node.left, ops, node.comparators)
    else:
        raise ValueError(mutant.kind)
    if replacement is not node:
        tree = _Swap(node, replacement).visit(tree)
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"


# Tests that run cunho in other processes, where line coverage cannot see: selected for every mutant
# in the files those processes use.
SUBPROCESS_TESTS = {
    "store.py": ["tests/engine/test_review2_fixes.py::test_n_l5_workers_starting_together_on_a_new_store"]
}


def coverage_map(root: Path, env: dict[str, str]) -> dict[str, set[str]]:
    """file:line -> the test functions that run it, from one instrumented run of the suite."""
    out = root / "linecover.json"
    local = {**env, "PYTHONPATH": env["PYTHONPATH"] + ":tools/mutation", "CUNHO_LINECOVER_OUT": str(out)}
    command = [sys.executable, "-m", "pytest", "tests/engine", "-q", "-p", "no:cacheprovider", "-p", "linecover"]
    result = subprocess.run(command, cwd=root, env=local, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"the coverage run failed:\n{result.stdout[-3000:]}")
    by_line: dict[str, set[str]] = {}
    for test, lines in json.loads(out.read_text()).items():
        function = test.split("[", 1)[0]  # every case of a selected function runs, so covers() still holds
        for line in lines:
            by_line.setdefault(line, set()).add(function)
    return by_line


def selected_tests(mutant: Mutant, by_line: dict[str, set[str]]) -> list[str] | None:
    """The test functions that reach the mutant's lines; None means the whole suite."""
    short = mutant.file.removeprefix("src/cunho/")
    tests: set[str] = set()
    for line in range(mutant.lines[0], mutant.lines[1] + 1):
        tests |= by_line.get(f"{short}:{line}", set())
    if "<outside>" in tests or mutant.kind == "rule" or not mutant.lines[0]:
        return None  # module-level code, or a mutant without a place: run everything
    return sorted(tests | set(SUBPROCESS_TESTS.get(short, [])))


def _run(root: Path, env: dict[str, str], timeout: int, tests: list[str] | None = None) -> tuple[bool, float, str]:
    """Run the suite, or the given tests; returns (failed, seconds, the first failing test)."""
    started = time.monotonic()
    if tests is not None and not tests:
        return False, 0.0, "no test reaches this code"
    targets = tests if tests is not None else ["tests/engine"]
    command = [sys.executable, "-m", "pytest", *targets, "-x", "-q", "-p", "no:cacheprovider", "-rfE"]
    try:
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return True, time.monotonic() - started, "timeout"  # a hang is a detected change
    # The short summary's lines, not captured log lines, which start with a level name such as ERROR too.
    summary = ("FAILED tests/", "ERROR tests/")
    first = next((line for line in result.stdout.splitlines() if line.startswith(summary)), "")
    if result.returncode not in (0, 1):
        first = first or f"pytest exit {result.returncode}"  # collection or import error: the change was seen
    return result.returncode != 0, time.monotonic() - started, first


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sites", action="store_true", help="remove each refusing statement and each raise")
    mode.add_argument("--conditions", action="store_true", help="alter each condition that guards a refusal")
    mode.add_argument("--all", action="store_true", help="sites and conditions")
    parser.add_argument("--jobs", type=int, default=max(1, min(8, (os.cpu_count() or 2) - 2)))
    parser.add_argument("--rules", default="", help="comma-separated rule ids (rules mode)")
    parser.add_argument("--only", default="", help="run only mutants whose label contains this text")
    parser.add_argument("--shard", default="1/1", help="run the k-th of n equal slices, e.g. 2/4")
    parser.add_argument("--timeout", type=int, default=0, help="seconds per run (default: 6 x the clean run)")
    parser.add_argument("--list", action="store_true", help="print the mutants and exit")
    parser.add_argument(
        "--select",
        action="store_true",
        help="run each mutant against the tests that reach its lines first; survivors are confirmed on the full suite",
    )
    parser.add_argument("--json", type=Path, help="write the results here as JSON")
    args = parser.parse_args()

    kinds = (
        {"site"} if args.sites else {"condition"} if args.conditions else {"site", "condition"} if args.all else set()
    )
    mode_name = "all" if args.all else "sites" if args.sites else "conditions" if args.conditions else "rules"
    shard, shards = (int(x) for x in args.shard.split("/"))

    with tempfile.TemporaryDirectory(prefix="cunho-mutation-") as scratch:
        base = _copy(Path(scratch) / "base")
        if kinds:
            mutants = discover(base, kinds)
            known = {m.label for m in mutants}
            stale = sorted(label for label in EQUIVALENT if label not in known and _in_mode(label, kinds))
            if stale:
                print(f"equivalent.py lists mutants that no longer exist; remove them: {stale}", file=sys.stderr)
                return 2
        else:
            rules = [r for r in args.rules.split(",") if r] or milestone_rules(base)
            mutants = [Mutant(rule, kind="rule", rule=rule) for rule in rules]
        if args.only:
            mutants = [m for m in mutants if args.only in m.label]
        mutants = mutants[shard - 1 :: shards]
        if args.list:
            for mutant in mutants:
                print(("EQUIV    " if mutant.label in EQUIVALENT else "         ") + mutant.label)
            print(f"{len(mutants)} mutants")
            return 0
        for mutant in mutants:  # every patch must still apply before any time is spent
            if mutant.kind == "patch":
                mutated_source((base / mutant.file).read_text(), mutant)
        # The copies have no git history; the upgrade test reads an older commit from this repository with `git
        # archive`, which writes nothing into it.
        env = {
            **os.environ,
            "PYTHONPATH": "src:probe:.",
            "PYTHONDONTWRITEBYTECODE": "1",
            "CUNHO_SOURCE_REPO": str(ROOT),
        }
        env.pop("CUNHO_MUTATION_DISABLE_RULE", None)
        # The unmutated suite must pass under the same parallel load, or flaky tests would pass as kills.
        with ThreadPoolExecutor(args.jobs) as pool:
            baseline = list(pool.map(lambda _: _run(base, env, 1800), range(args.jobs)))
        broken = [first for failed, _, first in baseline if failed]
        if broken:
            print(f"the unmutated suite fails under load; fix it first: {broken}", file=sys.stderr)
            return 2
        clean = max(seconds for _, seconds, _ in baseline)
        timeout = args.timeout or max(120, int(clean * 6))
        by_line = coverage_map(base, env) if args.select and kinds else None
        print(f"{len(mutants)} mutants ({mode_name}, shard {shard}/{shards}); clean run {clean:.0f} s", flush=True)

        def one(item: tuple[int, Mutant]) -> tuple[Mutant, bool, float, str]:
            index, mutant = item
            work = _copy(Path(scratch) / f"m{index}", base)  # the snapshot taken at the start
            try:
                local = dict(env)
                if mutant.kind == "rule":
                    rules_init = work / "src" / "cunho" / "rules" / "__init__.py"
                    rules_init.write_text(rules_init.read_text() + PATCH)
                    local[SWITCH] = mutant.rule
                else:
                    target = work / mutant.file
                    target.write_text(mutated_source(target.read_text(), mutant))
                if by_line is not None:
                    tests = selected_tests(mutant, by_line)
                    if tests is not None:
                        killed, seconds, first = _run(work, local, timeout, tests)
                        if killed:
                            return mutant, killed, seconds, first
                return (mutant, *_run(work, local, timeout))  # the whole suite decides
            finally:
                shutil.rmtree(work, ignore_errors=True)

        results = []
        with ThreadPoolExecutor(args.jobs) as pool:
            for mutant, was_killed, seconds, first in pool.map(one, enumerate(mutants)):
                verdict = "KILLED  " if was_killed else "EQUIV   " if mutant.label in EQUIVALENT else "SURVIVED"
                print(f"{verdict} {mutant.label} ({seconds:.0f} s) {first}", flush=True)
                results.append(
                    {
                        "mutant": mutant.label,
                        "killed": was_killed,
                        "equivalent": mutant.label in EQUIVALENT,
                        "by": first,
                    }
                )
    survivors = [r["mutant"] for r in results if not r["killed"] and not r["equivalent"]]
    killed_but_listed = [r["mutant"] for r in results if r["killed"] and r["equivalent"]]
    equivalent = sum(1 for r in results if r["equivalent"] and not r["killed"])
    killed = sum(1 for r in results if r["killed"])
    print(
        f"\n{killed}/{len(results)} killed, {equivalent} listed as equivalent; "
        f"survivors: {survivors or 'none'}"
        + (
            f"; listed as equivalent but killed (remove from equivalent.py): {killed_but_listed}"
            if killed_but_listed
            else ""
        )
    )
    if args.json:
        summary = {"killed": killed, "total": len(results), "equivalent": equivalent, "survivors": survivors}
        args.json.write_text(json.dumps({"mode": mode_name, "summary": summary, "results": results}, indent=1))
    return 1 if survivors or killed_but_listed else 0


def _in_mode(label: str, kinds: set[str]) -> bool:
    if label.startswith("patch: "):
        return "condition" in kinds
    kind = label.split(": ", 2)[1] if label.count(": ") >= 2 else ""
    return ("site" in kinds and kind == "site") or ("condition" in kinds and kind in {"negate", "drop", "not", "flip"})


if __name__ == "__main__":
    raise SystemExit(main())
