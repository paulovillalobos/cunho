"""Regression tests for the fifth M2 review (cunho-m2-review-5.md): the audit anchor and verification."""

from __future__ import annotations

import random
import threading
from pathlib import Path
from typing import Any

import pytest

from cunho.audit import Anchor, AuditLog, Mark
from cunho.keyring import Keyring
from cunho.store import SqliteStore

from .anchorfaults import AnchorFaults, History, first_write_size, run
from .helpers import Clock

# N5-M1: the anchor survives a write cut at any byte, twice, and NUL or garbage tails --------------------


def test_n5_m1_a_write_cut_at_every_byte_is_repaired(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """t1: one tear that left a prefix was repaired; any other stopped all logging for good."""
    with monkeypatch.context() as patch:
        size = first_write_size(tmp_path / "size", patch)
    for keep in range(size + 1):
        with monkeypatch.context() as patch:
            history = run(tmp_path / f"tear{keep}", {1: ("tear", keep)}, False, patch)
        repairs = [e for e in history.log.entries() if e["event"] == "audit.anchor_repaired"]
        assert len(repairs) == (1 if 0 < keep < size else 0), keep  # a write that got through whole is no tear


def test_n5_m1_the_repair_itself_cut_at_every_byte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """t1 (a): the write that repairs a tear is torn too, at every byte, and the next one repairs both."""
    with monkeypatch.context() as patch:
        size = first_write_size(tmp_path / "size", patch)
    for keep in range(0, 420):  # past the end of the repair write, which then reaches the disk whole
        with monkeypatch.context() as patch:
            run(tmp_path / f"second{keep}", {1: ("tear", size // 2), 2: ("tear", keep)}, False, patch)
    for keep in range(size + 1):  # and every first tear, with the repair cut in its middle
        with monkeypatch.context() as patch:
            run(tmp_path / f"first{keep}", {1: ("tear", keep), 2: ("tear", 150)}, keep % 2 == 0, patch)


def test_n5_m1_nul_tails_of_every_length(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """t1 (b): NUL bytes where the line should be, as XFS or ext4 writeback can leave them after a power loss."""
    with monkeypatch.context() as patch:
        size = first_write_size(tmp_path / "size", patch)
    for keep in range(1, size + 2):
        with monkeypatch.context() as patch:
            run(tmp_path / f"nul{keep}", {1: ("nul", keep)}, keep % 2 == 0, patch)


@pytest.mark.parametrize(
    "garbage",
    [
        b"\x00" * 30_000,  # longer than the stretch the tail reads first
        b"\n\n\n",
        b'{"seq": 3, "mac": "x", "time": 0, "prev": "y", "tag": "z"}\n',
        b"\xff\xfe not text \n at all",
        bytes(random.Random(5).randrange(256) for _ in range(5000)),
    ],
)
def test_n5_m1_garbage_after_the_last_line_is_closed_and_declared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, garbage: bytes
) -> None:
    history = History(tmp_path)
    AnchorFaults(monkeypatch, history.path)
    history.act("a")
    size = history.path.stat().st_size
    with history.path.open("ab") as handle:
        handle.write(garbage)
    assert history.log.verify()[0] is False
    history.restart()
    history.act("b")
    history.check_whole()
    repair = next(e for e in history.log.entries() if e["event"] == "audit.anchor_repaired")
    assert repair["data"] == {"torn_bytes": len(garbage), "at": size}
    ok, detail = history.log.verify()
    assert ok and f"1 damaged stretch(es) of the anchor ({len(garbage)} bytes)" in detail, detail


def test_n5_m1_maintenance_repairs_without_waiting_for_an_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_issuer: Any, clock: Clock
) -> None:
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), audit_anchor_path=tmp_path / "anchor")
    faults = AnchorFaults(monkeypatch, tmp_path / "anchor")
    faults.plan = {faults.writes: ("tear", 40)}
    issuer.audit.append("offer.created", "admin")
    ok, detail = issuer.audit.verify()
    assert not ok and "the next logged action, or maintenance within a minute, repairs it" in detail
    issuer.sweep()
    ok, detail = issuer.audit.verify()
    assert ok and "1 damaged stretch(es) of the anchor (40 bytes)" in detail, detail
    assert [e["event"] for e in issuer.audit.entries()] == ["offer.created", "audit.anchor_repaired"]
    issuer.sweep()
    assert len(issuer.audit.entries()) == 2, "nothing to repair, nothing logged"


# N5-L1: the record of a repair survives an action refused inside its transaction ------------------------


def test_n5_l1_the_repair_entry_survives_a_refused_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_issuer: Any, clock: Clock
) -> None:
    """t2: the repair entry was written in the action's transaction, and rolled back with it."""
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), audit_anchor_path=tmp_path / "anchor")
    faults = AnchorFaults(monkeypatch, tmp_path / "anchor")
    faults.plan = {faults.writes: ("tear", 25)}
    issuer.audit.append("offer.created", "admin")
    with pytest.raises(Exception, match="no live offer"):
        issuer.cancel_offer(issuer.new_subject_ref(), "admin")
    assert [e["event"] for e in issuer.audit.entries()] == ["offer.created", "audit.anchor_repaired"]
    assert issuer.audit.verify()[0]


# N5-L2 and the S17 mutant: verify while another worker prunes or appends ------------------------------


def _worker_log(root: Path, clock: Clock, retention: float | None = 86_400) -> AuditLog:
    """What another uvicorn worker holds: its own store connection, anchor handle and locks."""
    keyring = Keyring.from_file(root / "m.key", create=True)
    store = SqliteStore(root / "s.db", clock)
    anchor = Anchor(root / "anchor", keyring)
    return AuditLog(store, keyring, clock, retention=retention, anchor=anchor, create_anchor=True)


def _verify_while_pruning(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    last: int,
    age: float,
    *,
    retention: float | None = 86_400,
    expected: Any = None,
) -> tuple[tuple[bool, str], list[dict[str, Any]]]:
    """1,300 entries a second apart; another worker prunes through entry `last` while verify walks the first
    page, so the next page starts after a hole. `age` is how long after the first entry verify runs."""
    root.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    start = clock()
    log, other = _worker_log(root, clock, retention), _worker_log(root, clock, retention)
    marks = []
    for n in range(1300):
        marks.append(log.append("offer.created", "admin", n=n))
        clock.now += 1
    clock.now = start + age
    real = log._entries  # noqa: SLF001
    pruned: list[int] = []

    def pruning_meanwhile(after: int = 0, upto: int | None = None) -> Any:
        for count, item in enumerate(real(after, upto)):
            if count == 100 and not pruned:
                pruned.append(other.prune_before(start + last, batch=100))
            yield item

    monkeypatch.setattr(log, "_entries", pruning_meanwhile)
    result = log.verify(expected(marks) if expected else None)
    assert pruned == [last]
    return result, marks


def test_n5_l2_pruned_up_to_the_head_meanwhile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (ok, detail), _ = _verify_while_pruning(tmp_path, monkeypatch, 1300, 3 * 86_400)
    assert ok and "pruning went on meanwhile" in detail, detail


def test_n5_l2_a_young_checkpoint_made_meanwhile_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pruning that went on during verification is held to the retention period like pruning before it."""
    result, _ = _verify_while_pruning(tmp_path / "young", monkeypatch, 700, 1300 + 10)
    assert result == (False, "the checkpoint drops entries younger than the retention period")
    (ok, _), _ = _verify_while_pruning(tmp_path / "edge", monkeypatch, 700, 699 + 86_400)
    assert ok, "a checkpoint exactly the retention period old is old enough"
    (ok, detail), _ = _verify_while_pruning(tmp_path / "none", monkeypatch, 700, 1310, retention=None)
    assert ok and "pruning went on meanwhile" in detail, detail


def test_n5_l2_a_signed_head_at_the_checkpoint_made_meanwhile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def right(marks: list[dict[str, Any]]) -> Mark:
        return Mark(700, marks[699]["mac"])

    def wrong(marks: list[dict[str, Any]]) -> Mark:
        return Mark(700, "e" * 64)

    (ok, detail), _ = _verify_while_pruning(tmp_path / "right", monkeypatch, 700, 3 * 86_400, expected=right)
    assert ok, detail
    result, _ = _verify_while_pruning(tmp_path / "wrong", monkeypatch, 700, 3 * 86_400, expected=wrong)
    assert result == (False, "the store diverges from the signed head at sequence 700")

    def passed(marks: list[dict[str, Any]]) -> Mark:
        return Mark(600, marks[599]["mac"])  # pruned away meanwhile, before verify reached it

    (ok, detail), _ = _verify_while_pruning(tmp_path / "passed", monkeypatch, 700, 3 * 86_400, expected=passed)
    assert ok, detail


def test_n5_l2_a_gap_after_a_checkpoint_is_still_a_gap(tmp_path: Path) -> None:
    clock = Clock()
    log = _worker_log(tmp_path, clock)
    start = clock()
    for n in range(400):
        log.append("offer.created", "admin", n=n)
        clock.now += 1
    clock.now += 2 * 86_400
    assert log.prune_before(start + 100) == 100
    for gap in (300, 101):
        log._store.delete("audit", f"{gap:012d}")  # noqa: SLF001
        assert log.verify() == (False, f"gap or reorder at sequence {gap}")


def test_n5_l2_verify_while_another_worker_prunes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """t4: four of six verifications reported a gap while pruning ran. Pruning now moves on in the middle of
    the walk, deterministically, and verify goes on from the new checkpoint."""
    clock = Clock()
    log, other = _worker_log(tmp_path, clock), _worker_log(tmp_path, clock)
    for n in range(1300):
        log.append("offer.created", "admin", n=n)
        clock.now += 1
    clock.now += 2 * 86_400
    real = log._entries  # noqa: SLF001
    pruned: list[int] = []

    def pruning_meanwhile(after: int = 0, upto: int | None = None) -> Any:
        for count, item in enumerate(real(after, upto)):
            if count == 100 and not pruned:  # past the page verify holds, so the next page starts after a hole
                pruned.append(other.prune_before(clock() - 2 * 86_400 - 1300 + 700, batch=100))
            yield item

    monkeypatch.setattr(log, "_entries", pruning_meanwhile)
    ok, detail = log.verify()
    assert ok and detail.endswith("; 1301 anchor lines") and "pruning went on meanwhile" in detail, detail
    assert pruned == [700]
    assert log.verify(Mark(1, "f" * 64))[0], "a signed head pruned away meanwhile is not held against the log"


def test_n5_l2_a_real_gap_is_still_a_gap(tmp_path: Path) -> None:
    clock = Clock()
    log = _worker_log(tmp_path, clock)
    for n in range(5):
        log.append("offer.created", "admin", n=n)
    log._store.delete("audit", f"{3:012d}")  # noqa: SLF001
    assert log.verify() == (False, "gap or reorder at sequence 3")
    log._store.delete("audit", f"{5:012d}")  # noqa: SLF001
    assert log.verify() == (False, "gap or reorder at sequence 3")


def test_s17_verify_holds_the_anchor_lock_against_another_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 5's S17 dropped the anchor `flock` from verify's snapshot and was caught only some of the time:
    another worker does not take this worker's thread lock, only the file lock. Here a second log, with its own
    handle, appends right after verify reads the head; with the file lock held it must wait."""
    clock = Clock()
    log, other = _worker_log(tmp_path, clock), _worker_log(tmp_path, clock)
    log.append("a", "admin")
    real_head = log._head  # noqa: SLF001
    writers: list[threading.Thread] = []
    appended = threading.Event()

    def append() -> None:
        other.append("b", "admin")
        appended.set()

    def head_then_append() -> Any:
        mark = real_head()
        if not writers:
            writers.append(threading.Thread(target=append))
            writers[0].start()
            appended.wait(1.0)  # with the file lock held by verify, the append cannot finish meanwhile
        return mark

    monkeypatch.setattr(log, "_head", head_then_append)
    result = log.verify()
    writers[0].join(10)
    assert result == (True, "1 entries verified; 2 anchor lines"), result
    assert appended.is_set() and log.verify() == (True, "2 entries verified; 3 anchor lines")
