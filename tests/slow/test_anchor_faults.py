"""Every pair of cut points in two anchor writes in a row (review 5, N5-M1). Slow, so it runs as its own CI job:
`pytest -m slow tests/slow`. The engine suite runs every single cut point and a slice of the pairs."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.engine.anchorfaults import first_write_size, run

pytestmark = pytest.mark.slow


def _fresh(root: Path) -> Path:
    shutil.rmtree(root, ignore_errors=True)
    return root


@pytest.mark.parametrize("second", [2, 3, 4])
def test_two_writes_in_a_row_cut_at_every_pair_of_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, second: int
) -> None:
    """Write 1 is the second action's own line. After it is torn, the next action writes the missing line
    (write 2), its repair entry's line (write 3) and its own line (write 4); each is cut too, at every byte."""
    with monkeypatch.context() as patch:
        size = first_write_size(tmp_path / "size", patch)
    step = 1 if second == 2 else 4
    for first in range(0, size + 1, step):
        for keep in range(0, 440):
            plan = {1: ("tear", first), second: ("tear", keep)}
            with monkeypatch.context() as patch:
                run(_fresh(tmp_path / "run"), plan, (first + keep) % 3 == 0, patch)


def test_nul_tail_then_a_torn_repair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with monkeypatch.context() as patch:
        size = first_write_size(tmp_path / "size", patch)
    for first in range(1, size + 2, 3):
        for keep in range(0, 440, 2):
            plan = {1: ("nul", first), 2: ("tear", keep), 3: ("nul", keep // 2)}
            with monkeypatch.context() as patch:
                run(_fresh(tmp_path / "run"), plan, keep % 2 == 0, patch)
