"""Regression tests for the fifth M2 review (cunho-m2-review-5.md): the clock watch."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho.service import CLOCK_TOLERANCE, ClockWatch, Issuer
from cunho.store import MemoryStore, SqliteStore

from .helpers import Clock, Host

# N5-L5 and N5-L8: the host's own clock tells a stop from a step ------------------------------------------


def test_n5_l5_a_planned_stop_is_not_a_clock_fault(
    make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """t8: a restart after three hours down was held back for an interval and logged as a clock fault."""
    host = Host(clock)
    kw = {"secret_key_file": tmp_path / "m.key", "status_decoy_churn_per_day": 0.05}
    first = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
    first.status.allocate()
    assert "decoys_scheduled" in first.maintenance(force=True)
    host.advance(3 * 3600)  # stopped for three hours, then started again
    restarted = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
    with caplog.at_level(logging.WARNING, "cunho.security"):
        done = restarted.maintenance()
    assert done.get("decoys_scheduled", 0) > 0 and "audit_pruning_held" not in done, done
    assert not [r for r in caplog.records if r.name == "cunho.security"], "the host clock counted the stop"


def test_n5_l5_a_step_is_not_followed(clock: Clock, caplog: pytest.LogCaptureFixture) -> None:
    host, store = Host(clock), MemoryStore(clock)
    watch = host.watch(store)
    assert watch.steady()
    true = clock()
    clock.now += 400 * 86_400  # the wall clock jumps; the host clock does not
    with caplog.at_level(logging.ERROR, "cunho.security"):
        assert watch.steady() and watch.now() == true
    assert "cunho goes by the host clock" in caplog.text
    clock.now -= 400 * 86_400
    host.advance(4 * 3600)  # running, then down, but the wall clock went three hours further than time did
    clock.now += 3 * 3600
    restarted = host.watch(store)
    assert restarted.now() == true + 4 * 3600, "a restart does not hide a step made while down"


def test_n5_l5_after_a_host_restart_the_kernel_decides(clock: Clock) -> None:
    host, store = Host(clock), MemoryStore(clock)
    assert host.watch(store).steady()
    clock.now += 3 * 3600
    host.boot, host.elapsed = "boot-2", 40.0  # a new boot: the host clock started again
    for synced, steady in ((None, False), (False, False), (True, True)):
        host.synced = synced
        watch = host.watch(store)
        assert watch.steady() is steady, synced
        assert (watch.now() is not None) is steady
    host.boot, host.elapsed = "boot-3", 40.0
    clock.now -= 10 * 3600
    assert not host.watch(store).steady(), "a clock behind the last trusted time is never trusted at once"


def test_n5_l5_after_a_host_restart_a_reading_that_keeps_pace_is_trusted(clock: Clock) -> None:
    """A new boot with a reading behind the last base, or without word from the kernel, is trusted once the
    reading has kept pace with the host clock for an interval, and never while the kernel says it is not
    synchronised; a reading that creeps ahead of the host clock starts the wait again."""
    host, store = Host(clock), MemoryStore(clock)
    assert host.watch(store).steady()
    host.boot, host.elapsed, host.synced = "boot-2", 40.0, False
    clock.now -= 30 * 86_400
    watch = host.watch(store, 3600)
    assert not watch.steady()
    host.advance(3600)
    assert not watch.steady(), "the kernel says the clock is not synchronised: keep waiting"
    host.synced = None
    for _ in range(59):
        host.advance(60)
        clock.now += CLOCK_TOLERANCE + 1  # creeping: never keeps pace with the host clock
        assert not watch.steady() and watch.now() is None
    host.advance(3599)
    assert not watch.steady(), "the wait began again at the last step"
    host.advance(1)
    assert watch.steady() and watch.now() == clock(), "kept pace for an interval"
    assert not watch.settled(), "and pruning waits an interval more"


def test_n5_l8_a_reading_far_off_does_not_land_in_the_log(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """t12: one entry at +400 days kept 100 later entries past their retention period, for good."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, audit_retention_days=30)
    issuer.maintenance(force=True)
    expected = clock()
    clock.now += 400 * 86_400  # one request reads a wrong clock
    entry = issuer.audit.append("offer.created", "admin")
    assert entry["clock"] == int(clock()) and abs(entry["time"] - expected) <= CLOCK_TOLERANCE
    clock.now -= 400 * 86_400
    for _ in range(100):
        host.advance(10)
        assert "clock" not in issuer.audit.append("offer.created", "admin")
    clock.now -= 3 * 86_400  # and one far behind
    behind = issuer.audit.append("offer.created", "admin")
    assert behind["time"] >= clock() + 3 * 86_400 - CLOCK_TOLERANCE
    clock.now += 3 * 86_400
    for _ in range(60):
        host.advance(86_400)
        issuer.sweep()  # the background tick keeps the watch's trusted reading fresh
    issuer.audit.append("offer.created", "admin")  # pruning goes by the newest entry's time too (N6-M3)
    # 102, and the entry of the first forced run (CX-17)
    assert issuer.maintenance(force=True)["audit_entries_pruned"] == 103
    assert issuer.audit.verify()[0]


def test_n5_l8_an_entry_dated_ahead_does_not_hold_pruning_back(
    make_issuer: Callable[..., Issuer], clock: Clock
) -> None:
    """The same with a clock that has no host clock behind it, as in the review's t12: the entry keeps its wrong
    time, but the entries after it, which the chain says came later, carry it out with them."""
    issuer = make_issuer(audit_retention_days=30)
    issuer.maintenance(force=True)
    clock.now += 400 * 86_400
    issuer.audit.append("offer.created", "admin")
    clock.now -= 400 * 86_400
    for _ in range(100):
        clock.now += 10
        issuer.audit.append("offer.created", "admin")
    clock.now += 31 * 86_400
    young = issuer.audit.append("offer.created", "admin")
    assert issuer.maintenance(force=True)["audit_entries_pruned"] == 101
    assert issuer.audit.entries()[0]["seq"] == young["seq"]
    assert issuer.audit.verify()[0]


@pytest.mark.parametrize(("ahead", "pruned"), [(32 * 86_400, 0), (32 * 86_400 + 1, 11)])
def test_n5_l8_ahead_means_more_than_a_day_after_pruning_runs(
    make_issuer: Callable[..., Issuer], clock: Clock, ahead: int, pruned: int
) -> None:
    issuer = make_issuer(audit_retention_days=30)
    start = clock()
    issuer.maintenance(force=True)
    clock.now = start + ahead
    issuer.audit.append("offer.created", "admin")
    clock.now = start
    for _ in range(10):
        issuer.audit.append("offer.created", "admin")
    clock.now = start + 31 * 86_400  # pruning runs a day before the entry's date at the boundary, or earlier
    issuer.audit.append("offer.created", "admin")  # pruning goes by the newest entry's time too (N6-M3)
    assert issuer.maintenance(force=True)["audit_entries_pruned"] == pruned


def test_n5_l5_what_the_host_clock_cannot_say(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """Without a host clock (a test clock) the wall clock is the time, as it reads. A time kept without the host
    clock, as cunho kept it before, is treated as one from another boot. Without a boot that can be named the
    watch cannot vouch for anything, and an Issuer on such a host goes by the wall clock alone."""
    bare = ClockWatch(MemoryStore(clock), clock, 3600)
    clock.now += 400 * 86_400
    assert bare.steady() and bare.now() == clock() and bare.settled()
    host, store = Host(clock), MemoryStore(clock)
    store.put("maintenance", "clock", clock() - 3 * 3600, None)  # the time alone, as cunho kept it before
    assert not host.watch(store).steady() and host.watch(store).now() is None
    nameless = Host(clock)
    nameless.boot = None  # type: ignore[assignment]
    watch = nameless.watch(MemoryStore(clock))
    assert not watch.steady() and watch.now() is None and not watch.settled()
    watch.trust(clock())
    assert watch.now() is None, "nothing to lay a base for"


def test_n5_l8_the_time_holds_for_as_long_as_the_boot(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """The time comes from the base and the host clock however long ago the base was laid, and a restarted
    worker goes by the base in the store at once."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    issuer.maintenance(force=True)
    host.advance(30 * 86_400)
    true = clock()
    clock.now += 400 * 86_400
    entry = issuer.audit.append("offer.created", "admin")
    assert entry["clock"] == int(clock()) and entry["time"] == int(true)
    clock.now -= 400 * 86_400
    host.advance(60)
    clock.now += 400 * 86_400  # restarted a minute later, with the wall clock stepped meanwhile
    issuer.use_clock_watch(host.watch(issuer.store))  # what a restarted worker builds, from the stored base
    assert issuer.audit.append("offer.created", "admin")["time"] == int(true) + 60
    assert issuer.maintenance()["audit_entries_pruned"] == 0, "maintenance goes on by the host clock's time"


def test_n5_l8_bounds_need_the_same_named_boot(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    for before, after in ((None, None), ("boot-1", None), ("boot-1", "boot-2")):
        host = Host(clock)
        host.boot = before  # type: ignore[assignment]
        issuer = host.issuer(make_issuer, None)
        issuer.maintenance(force=True)
        host.boot = after  # type: ignore[assignment]
        clock.now += 400 * 86_400
        assert "clock" not in issuer.audit.append("offer.created", "admin"), (before, after)
        clock.now -= 400 * 86_400


def test_n5_l8_a_request_and_the_background_tick_do_not_deadlock(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stress soak hung a worker within a minute: a request logging an entry held the store and asked the
    clock watch for its range, while the background tick held the watch and wrote the store. Here the tick
    writes the store just as a request inside its transaction asks for the range; both must finish."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    issuer.maintenance(force=True)
    watch, store = issuer.clock_watch, issuer.store
    ticking, logging_ = threading.Event(), threading.Event()
    real_put, real_now = store.put, watch.now

    def put(ns: str, *args: Any) -> None:
        if ns == "maintenance" and threading.current_thread().name == "tick":
            ticking.set()
            logging_.wait(2)  # the request is inside its transaction, holding the store
        real_put(ns, *args)

    def now() -> float | None:
        logging_.set()
        ticking.wait(2)  # the tick holds the watch and waits for the store
        return real_now()

    monkeypatch.setattr(store, "put", put)
    issuer.audit.now = now
    threads = [
        threading.Thread(target=watch.trust, args=(clock(),), name="tick", daemon=True),
        threading.Thread(target=issuer.audit.append, args=("offer.created", "admin"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not any(thread.is_alive() for thread in threads), "deadlocked"
