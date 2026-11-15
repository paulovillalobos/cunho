"""A pytest plugin that records which lines of src/cunho each test runs (Python 3.12 sys.monitoring).

`mutate.py --select` runs the suite once with it, then runs each mutant against only the tests that
reach the mutated lines. Survivors are run again against the whole suite before they count, so the
selection can only save time, never hide a kill. Lines run outside any test (imports, collection) map
to every test. Output: the JSON file named by CUNHO_LINECOVER_OUT.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from types import CodeType
from typing import Any

import pytest

TOOL = 4  # a free sys.monitoring tool id (0-5); coverage tools use 1
SRC = str(Path("src/cunho").resolve()) + os.sep
_hits: dict[str, set[str]] = {}
_current = "<outside>"


def _line(code: CodeType, line: int) -> Any:
    if not code.co_filename.startswith(SRC):
        return sys.monitoring.DISABLE
    _hits.setdefault(_current, set()).add(f"{code.co_filename[len(SRC) :]}:{line}")
    return None


def pytest_configure(config: pytest.Config) -> None:
    sys.monitoring.use_tool_id(TOOL, "cunho-linecover")
    sys.monitoring.register_callback(TOOL, sys.monitoring.events.LINE, _line)
    sys.monitoring.set_events(TOOL, sys.monitoring.events.LINE)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem: pytest.Item | None) -> Iterator[None]:
    global _current
    _current = item.nodeid
    try:
        return (yield)
    finally:
        _current = "<outside>"


def pytest_unconfigure(config: pytest.Config) -> None:
    sys.monitoring.set_events(TOOL, 0)
    sys.monitoring.free_tool_id(TOOL)
    out = os.environ.get("CUNHO_LINECOVER_OUT")
    if out:
        Path(out).write_text(json.dumps({test: sorted(lines) for test, lines in _hits.items()}))
