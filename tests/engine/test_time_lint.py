"""No code in the engine reads the wall clock except the stores and the clock watch.

Everything cunho decides by time goes by the clock watch's time (DESIGN.md, time). The reviews' clock findings
came from places that read the wall clock, or read the time outside the transaction its value was written in,
one caller at a time (research/cunho-m2-fixes.md, CX-15 to CX-29). M3 adds many more lifetimes: the
authorization code, request_uri, the attestation PoP, the trusted list's NextUpdate, CRLs, OCSP responses and
refresh tokens. So a new wall-clock read is refused here, before it reaches a review.

A wall-clock read is `time.time()`, `time.time_ns()`, `datetime.now()`, `datetime.utcnow()`, `datetime.today()`,
`date.today()` or `CLOCK_REALTIME`, however the module or class was imported. A call is allowed only in the
stores (`store.py`) and in the clock watch (`ClockWatch`, `HostClock`). Naming `time.time` without calling it is
allowed only where it is the default wall clock handed to the issuer, the audit log, the status lists and the
stores, which give it to the clock watch.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

import pytest

from .rulecheck import SRC

CLOCK_SCOPES = {("store.py", ""), ("service.py", "ClockWatch"), ("service.py", "HostClock")}
DEFAULT_CLOCKS = {
    ("store.py", ""),
    ("service.py", "Issuer.__init__"),
    ("audit.py", "AuditLog.__init__"),
    ("status.py", "StatusLists.__init__"),
}
READERS = {"time", "time_ns"}
DATE_READERS = {"now", "utcnow", "today"}


@dataclass(frozen=True)
class Read:
    file: str
    scope: str
    line: int
    called: bool


def _allowed(scope: str, file: str, scopes: set[tuple[str, str]]) -> bool:
    return any(file == f and (not s or scope == s or scope.startswith(s + ".")) for f, s in scopes)


def wall_clock_reads(source: str, file: str) -> list[Read]:
    """Every read of the wall clock in `source`, with the class or function it is in."""
    tree = ast.parse(source)
    time_modules: set[str] = set()
    datetime_modules: set[str] = set()
    date_classes: set[str] = set()
    readers: set[str] = set()  # names bound to time.time, time.time_ns or CLOCK_REALTIME by `from time import`
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "time":
                    time_modules.add(alias.asname or "time")
                elif alias.name == "datetime":
                    datetime_modules.add(alias.asname or "datetime")
        elif isinstance(node, ast.ImportFrom) and node.module in ("time", "datetime"):
            for alias in node.names:
                if node.module == "time" and alias.name in READERS | {"CLOCK_REALTIME"}:
                    readers.add(alias.asname or alias.name)
                elif node.module == "datetime" and alias.name in ("datetime", "date"):
                    date_classes.add(alias.asname or alias.name)

    def is_date_class(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in date_classes
        return (
            isinstance(node, ast.Attribute)
            and node.attr in ("datetime", "date")
            and isinstance(node.value, ast.Name)
            and node.value.id in datetime_modules
        )

    def is_read(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in readers
        if not isinstance(node, ast.Attribute):
            return False
        if isinstance(node.value, ast.Name) and node.value.id in time_modules:
            return node.attr in READERS or node.attr == "CLOCK_REALTIME"
        return node.attr in DATE_READERS and is_date_class(node.value)

    found: list[Read] = []

    def visit(node: ast.AST, scope: str) -> None:
        if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            scope = f"{scope}.{node.name}" if scope else node.name
        if isinstance(node, ast.Call) and isinstance(node.func, ast.expr) and is_read(node.func):
            found.append(Read(file, scope, node.lineno, True))
            for child in [*node.args, *(k.value for k in node.keywords)]:
                visit(child, scope)
            return
        if isinstance(node, ast.expr) and is_read(node):
            found.append(Read(file, scope, node.lineno, False))
            return
        for inner in ast.iter_child_nodes(node):
            visit(inner, scope)

    visit(tree, "")
    return found


def refused(reads: list[Read]) -> list[Read]:
    """The reads the rule does not allow."""
    return [
        r
        for r in reads
        if not _allowed(r.scope, r.file, CLOCK_SCOPES) and (r.called or not _allowed(r.scope, r.file, DEFAULT_CLOCKS))
    ]


def test_the_engine_reads_the_wall_clock_only_in_the_stores_and_the_clock_watch() -> None:
    reads = [read for path in SRC for read in wall_clock_reads(path.read_text(), path.name)]
    assert reads, "the lint found no wall clock at all, so it is not looking"
    assert refused(reads) == []


@pytest.mark.parametrize(
    "source",
    [
        "import time\ndef f():\n    return time.time()\n",
        "import time as t\ndef f():\n    return t.time_ns()\n",
        "from time import time\ndef f():\n    return time()\n",
        "from time import time as now\nx = now()\n",
        "import datetime as dt\ndef f():\n    return dt.datetime.now(dt.UTC)\n",
        "import datetime\ndef f():\n    return datetime.date.today()\n",
        "from datetime import datetime\nclass A:\n    def f(self):\n        return datetime.utcnow()\n",
        "from datetime import date as d\nx = d.today()\n",
        "import time\nx = time.clock_gettime(time.CLOCK_REALTIME)\n",
        "import time\ndef f(clock=time.time):\n    return clock()\n",
        "import time\nclock = time.time\n",
    ],
)
def test_a_wall_clock_read_in_engine_code_is_refused(source: str) -> None:
    assert refused(wall_clock_reads(source, "oauth.py")), source


@pytest.mark.parametrize(
    ("source", "file"),
    [
        ("import time\nclass SqliteStore:\n    def f(self):\n        return time.time()\n", "store.py"),
        ("import time\nclass ClockWatch:\n    def now(self):\n        return time.time()\n", "service.py"),
        ("import time\nclass Issuer:\n    def __init__(self, clock=time.time):\n        pass\n", "service.py"),
        ("import time\nx = time.monotonic()\n", "oauth.py"),
        ("import datetime as dt\nx = dt.datetime.fromtimestamp(0, dt.UTC)\n", "oauth.py"),
    ],
)
def test_the_stores_the_clock_watch_and_other_clocks_are_allowed(source: str, file: str) -> None:
    assert refused(wall_clock_reads(source, file)) == []


def test_a_default_clock_is_not_a_licence_to_call_it() -> None:
    """The issuer may take `time.time` as its default wall clock, but may not call it itself."""
    source = "import time\nclass Issuer:\n    def __init__(self, clock=time.time):\n        self.t = time.time()\n"
    assert [r.called for r in refused(wall_clock_reads(source, "service.py"))] == [True]
