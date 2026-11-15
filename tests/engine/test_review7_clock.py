"""Regression tests for the seventh M2 review (cunho-m2-review-7.md) and the second reviewer's findings: one time
base for every decision about time, and pruning that only removes what verifies."""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import sqlite3
import threading
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

import cunho.status as status_module
from cunho.app import create_app
from cunho.audit import CLOCK_TRUSTED, Anchor, AuditError, AuditLog, Mark, _clock_of
from cunho.errors import ConfigError, IssuerError
from cunho.jose import b64u_decode, parse_jws
from cunho.keyring import Keyring
from cunho.oauth import Grant
from cunho.proofs import ProvenKeys
from cunho.service import CLOCK_TOLERANCE, ClockWatch, HostClock, Issuer
from cunho.status import StatusRef
from cunho.store import MemoryStore, SqliteStore

from .helpers import ISSUER, PID_CONFIG, PRE_AUTH, SLOW_IS_FINE, Clock, Host, Pki, Seeded, Wallet

DAY, JITTER, PUBLISH = 86_400, 3600, 60
BOUND = JITTER + CLOCK_TOLERANCE + PUBLISH  # DESIGN §4: a revocation shows within this, measured on the host clock


def _slot(response: Any) -> tuple[str, int]:
    reference = parse_jws(response.json()["credentials"][0]["credential"].split("~")[0]).payload["status"]
    return reference["status_list"]["uri"].rsplit("/", 1)[1], reference["status_list"]["idx"]


def _bits(token: str) -> bytes:
    return zlib.decompress(b64u_decode(parse_jws(token).payload["status_list"]["lst"]))


def _shown(issuer: Issuer, list_id: str, index: int) -> int:
    return _bits(str(issuer.status_token(list_id)))[index // 8] >> (index % 8) & 1


def _pending(issuer: Issuer, list_id: str) -> int:
    return len(issuer.store.items("status-pending", f"{list_id}:"))


@contextmanager
def _running(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, **overrides: Any
) -> Iterator[tuple[Issuer, Host, Wallet]]:
    host = Host(clock)
    store = overrides.pop("store", None)
    kw = {"status_revocation_jitter": JITTER, "status_decoy_churn_per_day": 0, **overrides}
    with mock.patch.object(status_module, "secrets", Seeded(1)):  # the same draws every run (see Seeded)
        issuer = host.issuer(make_issuer, store, **kw)
        issuer.sweep()  # the first background tick lays the base
        with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
            yield issuer, host, Wallet(client, pki, host.true)  # the wallet's own clock reads right


def _first_shown(issuer: Issuer, host: Host, slot: tuple[str, int], limit: float) -> float | None:
    """Seconds of host time until the bit shows, with a background tick every minute, or None within `limit`."""
    start = host.elapsed
    while host.elapsed - start <= limit:
        if _shown(issuer, *slot):
            return host.elapsed - start
        host.advance(60)
        issuer.sweep()
        issuer.maintenance()
    return None


# M1: revocation moments and status publication go by one time ----------------------------------------------


@pytest.mark.parametrize("shape", ["behind", "ahead", "corrected after it was trusted"])
def test_m1_a_revocation_shows_within_its_bound_however_the_clock_reads(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, shape: str
) -> None:
    """p2 and p2c: with the wall clock two days behind, and staying there, a revocation showed after 48 hours;
    with it two days ahead, at once; with a clock three days ahead for 75 minutes and then put right, after 72
    hours. Moments and publications now both go by the time the host clock gives."""
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        wallet.get_token(wallet.offer())
        slot = _slot(wallet.issue())
        offset = {"behind": -2 * DAY, "ahead": 2 * DAY, "corrected after it was trusted": 3 * DAY}[shape]
        clock.now += offset
        for _ in range(75 if shape.startswith("corrected") else 10):
            host.advance(60)
            issuer.sweep()
            issuer.maintenance()
        if shape.startswith("corrected"):
            clock.now -= offset
            host.advance(300)
        true = host.elapsed
        reply = wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"})
        assert reply.json() == {"revoked": 1}
        [(key, _)] = [(k, v) for k, v in issuer.store.items("status-pending", f"{slot[0]}:")]
        moment = int(key.split(":")[1]) / 1000
        start = clock() - offset if not shape.startswith("corrected") else clock()
        assert start - CLOCK_TOLERANCE <= moment < start + JITTER + CLOCK_TOLERANCE, (moment - start, shape)
        host.advance(0)
        seen = _first_shown(issuer, host, slot, 3 * DAY)
        assert seen is not None and host.elapsed - true <= BOUND + 60, (seen, shape)


def test_m1_a_poll_under_a_clock_far_ahead_publishes_nothing_early(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """p2b: one anonymous status GET under a clock 400 days ahead published every queued decoy and revocation at
    once, and a bit shown is never hidden again."""
    with _running(make_issuer, pki, clock, status_decoy_churn_per_day=0.05) as (issuer, host, wallet):
        issuer.maintenance(force=True)
        wallet.get_token(wallet.offer())
        slot = _slot(wallet.issue())
        wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"})
        host.advance(60)
        issuer.sweep()
        hidden = _pending(issuer, slot[0])
        assert hidden > 1
        clock.now += 400 * DAY
        host.advance(5)
        issuer.sweep()
        assert wallet.client.get(f"/status/{slot[0]}").status_code == 200
        assert _pending(issuer, slot[0]) == hidden, "nothing came due by the time the host clock gives"
        assert _shown(issuer, *slot) == 0


def test_m1_without_a_time_only_the_bits_laid_to_show_at_once_are_published(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """After a host restart that the watch cannot vouch for yet, the list goes on showing what it showed, plus
    the revocations made meanwhile, which show at once; nothing scheduled comes due by a clock nobody vouches
    for."""
    with _running(make_issuer, pki, clock, status_decoy_churn_per_day=0.05) as (issuer, host, wallet):
        issuer.maintenance(force=True)
        wallet.get_token(wallet.offer())
        slot = _slot(wallet.issue())
        hidden = _pending(issuer, slot[0])
        host.boot, host.elapsed = "boot-2", 30.0
        clock.now += 400 * DAY
        issuer.use_clock_watch(host.watch(issuer.store))
        assert not issuer.clock_watch.steady() and issuer.clock_watch.now() is None
        with caplog.at_level(logging.WARNING, "cunho.security"):
            assert wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"}).json() == {
                "revoked": 1
            }
        assert "cannot vouch for the clock yet: a revocation shows at once" in caplog.text
        host.advance(PUBLISH)
        assert _shown(issuer, *slot) == 1 and _pending(issuer, slot[0]) == hidden


def test_m1_a_revocation_laid_by_a_time_ahead_shows_once_a_new_base_puts_it_right(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """A store first started with a clock three days ahead lays its base from it, and a revocation is laid three
    days ahead with it. After a host restart the right time, once it has kept pace for an interval, becomes the
    base, behind the old one: the moment that no clock reading right could have laid is laid again within the
    jitter, instead of hiding the bit for three days."""
    clock.now += 3 * DAY
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        wallet.get_token(wallet.offer())
        slot = _slot(wallet.issue())
        wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"})
        host.boot, host.elapsed = "boot-2", 30.0
        clock.now -= 3 * DAY
        issuer.use_clock_watch(host.watch(issuer.store))
        restart = host.elapsed
        with caplog.at_level(logging.WARNING, "cunho.security"):
            seen = _first_shown(issuer, host, slot, 2 * DAY)
        assert seen is not None and host.elapsed - restart <= 3600 + BOUND + 60, host.elapsed - restart
        assert "laid again within the jitter" in caplog.text


def test_m1_a_schedule_a_right_clock_laid_is_left_as_it_is(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, status_decoy_churn_per_day=0.05, status_revocation_jitter=JITTER)
    issuer.sweep()
    issuer.status.allocate()  # opens list 1 with its decoys scheduled two intervals ahead
    queued = issuer.store.items("status-pending", "1:")
    assert max(int(k.split(":")[1]) / 1000 for k, _ in queued) > clock() + JITTER, "some lie beyond the jitter"
    issuer.status.publish()
    assert issuer.store.items("status-pending", "1:") == queued


# M2 and CX-4: a forward move of the wall clock never moves the time ------------------------------------------


def test_m2_a_clock_that_creeps_ahead_prunes_nothing(
    make_issuer: Callable[..., Issuer], clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """p1: a time source that stepped the clock 7,000 s forward at every one-minute tick walked the trusted time a
    month ahead in six hours, without a warning, and maintenance pruned the whole retention period."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, audit_retention_days=30)
    issuer.maintenance(force=True)
    for _ in range(20):
        for _ in range(24):
            host.advance(3600)
            issuer.sweep()
            issuer.maintenance()
        issuer.audit.append("offer.created", "admin")
    entries = len(issuer.audit.entries())
    true = clock()
    with caplog.at_level(logging.ERROR, "cunho.security"):
        for _ in range(400):
            host.advance(60)
            clock.now += 7000
            issuer.sweep()
            issuer.maintenance()
    true += 400 * 60
    assert "cunho goes by the host clock" in caplog.text, "the creep is reported"
    assert issuer.clock_watch.now() == true
    issuer.admin_refused("/admin/offers", "198.51.100.0/24", True)  # an anonymous request: an entry at the time
    issuer._last_maintenance = 0  # noqa: SLF001
    assert issuer.maintenance()["audit_entries_pruned"] == 0
    assert len(issuer.audit.entries()) == entries + 1
    clock.now = true
    assert issuer.audit.verify()[0]


def test_cx4_a_step_inside_the_old_window_is_not_trusted(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """The second reviewer's CX-4, the same as M2: after a trusted reading, both clocks move 60 s, the wall clock
    alone 1,200 s more, and maintenance runs. The step used to be trusted, so once the clock was put right the
    time read 1,080 s ahead and revocations were laid that much late."""
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        wallet.get_token(wallet.offer())
        slot = _slot(wallet.issue())
        issuer.maintenance(force=True)
        host.advance(60)
        clock.now += 1200
        issuer.sweep()
        issuer.maintenance()
        clock.now -= 1200
        assert issuer.clock_watch.now() == clock(), "the time did not follow the step"
        true = clock()
        wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"})
        [(key, _)] = issuer.store.items("status-pending", f"{slot[0]}:")
        assert true <= int(key.split(":")[1]) / 1000 < true + JITTER


def test_l2_an_anonymous_request_does_not_open_the_log_to_pruning(
    make_issuer: Callable[..., Issuer], clock: Clock
) -> None:
    """p5: with a clock two years ahead, held and settled, one request with a wrong admin token logged an entry at
    the wrong time, and the next maintenance pruned every entry. The rule that went by the newest entry is gone:
    the time no longer follows such a clock, so entries are dated right and pruned by the right time."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, audit_retention_days=30)
    issuer.maintenance(force=True)
    for _ in range(10):
        host.advance(DAY)
        issuer.sweep()
        issuer.audit.append("offer.created", "admin")
    clock.now += 2 * 365 * DAY
    for _ in range(200):
        host.advance(60)
        issuer.sweep()
        issuer.maintenance()
    issuer.admin_refused("/admin/revocations", "198.51.100.0/24", True)
    host.advance(60)
    issuer._last_maintenance = 0  # noqa: SLF001
    done = issuer.maintenance()
    assert done["audit_entries_pruned"] == 0 and done["auth_failures_logged"] == 1, done
    assert issuer.audit.entries()[-1]["time"] == int(clock() - 2 * 365 * DAY)


def test_a_subject_revocation_under_a_clock_far_ahead_finds_every_credential(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """The pre-check's note: a revocation by subject read the issued records by the wall clock, so with the clock
    a month ahead it skipped every credential that clock called expired, which are valid once it is put right."""
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        offer = wallet.offer()
        wallet.get_token(offer)
        slot = _slot(wallet.issue())
        host.advance(60)
        clock.now += 30 * DAY  # past the credential's 14 days
        reply = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "compromise"})
        assert reply.json()["revoked"] == 1, reply.text
        assert issuer.status.value(StatusRef(*slot)) == 1


@pytest.mark.parametrize("offset", [-2 * DAY, 2 * DAY])
def test_offers_tokens_proofs_and_credentials_go_by_the_same_time(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, offset: int
) -> None:
    """Under a wall clock days off, a wallet whose own clock reads right redeems its offer, proves its key and gets
    a credential dated by the time, and a subject closed while the wall clock read behind stays closed once it is
    put right: the closing mark expires by the same time the offer and its token do."""
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        host.advance(60)
        clock.now += offset
        offer = wallet.offer()
        host.advance(60)
        wallet.get_token(offer)
        reply = wallet.issue()
        assert reply.status_code == 200, reply.text
        nbf = parse_jws(reply.json()["credentials"][0]["credential"].split("~")[0]).payload["nbf"]
        assert nbf == int(host.true()) // 3600 * 3600, "dated by the time, not by the wall clock"
        later = wallet.offer()
        closed = wallet.admin("revocations", {"subject_ref": later["subject_ref"], "reason": "compromise"})
        assert closed.json() == {"revoked": 0, "offer_cancelled": True}, closed.text
        clock.now -= offset
        host.advance(60)
        code = later["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        assert wallet.token_request(code).status_code == 400, "a closed offer stays closed"


def test_sweeping_goes_by_the_time(make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path) -> None:
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    issuer.sweep()
    issuer.store.put("dpop-jti", "replay", 1, 125)
    host.advance(100)
    clock.now += 400 * DAY
    assert issuer.sweep() == 0, "a clock far ahead deletes no replay entry"
    clock.now -= 400 * DAY
    host.advance(24)
    assert issuer.sweep() == 0, "a second before it expires"
    host.advance(1)
    assert issuer.sweep() == 1


def test_l4_a_restart_behind_and_a_step_hidden_in_a_stop(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """S27 and S24 (review 7, L4) at the watch: a host restart with a reading behind the last base is not trusted
    at once even with NTP in sync, and a step of more than the tolerance hidden in a stop is still a step."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    issuer.sweep()
    host.advance(3 * 3600)
    clock.now += CLOCK_TOLERANCE + 1
    restarted = host.watch(issuer.store)
    assert restarted.now() == clock() - CLOCK_TOLERANCE - 1, "three hours down, and a step the host clock sees"
    restarted.steady()  # the tick keeps the latest time it saw
    host.boot, host.elapsed, host.synced = "boot-2", 10.0, True
    clock.now -= 600
    assert not host.watch(issuer.store).steady(), "behind the last time seen: not at once, even in sync"
    clock.now += 600 + 60
    assert host.watch(issuer.store).steady(), "ahead of it and in sync: at once"


# L4 S32: the DPoP replay cache outlives a proof dated a window ahead ----------------------------------------


def test_l4_a_dpop_proof_dated_ahead_cannot_be_replayed(wallet: Wallet, clock: Clock) -> None:
    """A proof dated a whole window ahead is acceptable for twice the window: its jti must be kept that long."""
    window = 60
    proof = wallet.dpop("POST", f"{ISSUER}/token", iat=int(clock()) + window)
    first = wallet.offer()["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    assert wallet.token_request(first, dpop=proof).status_code == 200
    clock.now += 90
    second = wallet.offer()["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    replay = wallet.token_request(second, dpop=proof)
    assert replay.status_code == 400 and "already used" in replay.json()["error_description"]


# CX-1: pruning removes only what verifies ---------------------------------------------------------------------


def test_cx1_an_entry_dated_back_by_a_database_writer_is_not_pruned(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """p1_prune_forged_times: an entry whose time a database writer moved back past the retention period failed
    verification, as it should; then the next maintenance pruned it, and verify called the log valid for good."""
    kw = {"secret_key_file": tmp_path / "m.key", "audit_retention_days": 3650}
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    for _ in range(3):
        issuer.audit.append("offer.created", "admin")
    db = sqlite3.connect(tmp_path / "s.db", isolation_level=None)
    for key, raw in db.execute("SELECT key, value FROM kv WHERE ns='audit' ORDER BY key").fetchall()[:2]:
        entry = json.loads(raw)
        entry["time"] = int(clock()) - 3650 * DAY - 1
        db.execute("UPDATE kv SET value=? WHERE ns='audit' AND key=?", (json.dumps(entry), key))
    assert issuer.audit.verify() == (False, "entry 1 was altered")
    with caplog.at_level(logging.ERROR, "cunho.security"):
        assert issuer.maintenance(force=True)["audit_entries_pruned"] == 0
    assert "pruning stopped at entry 1, which does not verify in its chain" in caplog.text
    assert issuer.audit.verify() == (False, "entry 1 was altered"), "still reported, after a restart too"
    restarted = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    assert restarted.audit.verify() == (False, "entry 1 was altered")


def test_cx1_pruning_follows_the_chain_from_the_checkpoint(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """Pruning past an entry removed from the front, or past one put back from elsewhere, would tidy up after
    whoever removed it: pruning stops where the chain breaks."""
    issuer = make_issuer(audit_retention_days=30)
    for _ in range(4):
        issuer.audit.append("offer.created", "admin")
        clock.now += DAY
    clock.now += 40 * DAY
    issuer.audit.append("offer.created", "admin")
    first = issuer.store.get("audit", f"{1:012d}")
    issuer.store.delete("audit", f"{1:012d}")
    assert issuer.maintenance(force=True)["audit_entries_pruned"] == 0, "entry 2 does not follow the genesis"
    issuer.store.put("audit", f"{1:012d}", first, None)
    assert issuer.maintenance(force=True)["audit_entries_pruned"] == 4
    assert issuer.audit.verify()[0]
    issuer.audit.append("offer.created", "admin")
    clock.now += 40 * DAY
    issuer.audit.append("offer.created", "admin")
    sixth = issuer.store.get("audit", f"{6:012d}")
    assert isinstance(sixth, dict)
    issuer.store.put("audit", f"{6:012d}", {**sixth, "prev": "0" * 64}, None)
    assert issuer.maintenance(force=True)["audit_entries_pruned"] == 1, "entry 5, and not entry 6 after it"
    assert [e["seq"] for e in issuer.audit.entries()] == [6, 7]


# The invariant, as a property ---------------------------------------------------------------------------------


def _faults() -> Any:
    from hypothesis import strategies as st

    offsets = st.sampled_from([0, 0, 0, 30, -30, 1200, -1200, 7000, 2 * DAY, -2 * DAY, 400 * DAY])
    return st.lists(st.tuples(offsets, st.integers(1, 90), st.booleans()), min_size=1, max_size=12)


def test_for_any_wall_clock_fault_the_host_clock_can_see(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    """Review 7's invariant: for any sequence of wall-clock faults on one boot, a revocation shows within jitter,
    tolerance and interval of host time, no bit shows before its moment in host time, and no entry younger than
    the retention period in host time is pruned."""
    hypothesis = pytest.importorskip("hypothesis")
    from hypothesis import given, settings

    @settings(max_examples=25, deadline=None, suppress_health_check=SLOW_IS_FINE)
    @given(_faults())
    def run(steps: list[tuple[int, int, bool]]) -> None:
        clock = Clock()
        retention = 3
        with _running(lambda **kw: make_issuer_for(clock, **kw), pki, clock, audit_retention_days=retention) as (
            issuer,
            host,
            wallet,
        ):
            base = clock() - (host.elapsed - 5000)  # wall time at host 5000, as the true time goes
            revoked: list[tuple[tuple[str, int], float]] = []
            logged: list[float] = []
            for offset, minutes, revoke in steps:
                clock.now = base + (host.elapsed - 5000) + offset
                if revoke:
                    wallet.get_token(wallet.offer())
                    slot = _slot(wallet.issue())
                    reply = wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"})
                    assert reply.json() == {"revoked": 1}
                    revoked.append((slot, host.elapsed))
                logged.append(host.elapsed)
                issuer.audit.append("offer.created", "admin")
                for _ in range(minutes):
                    host.advance(60)
                    issuer.sweep()
                    issuer.maintenance()
                    for slot, when in revoked:
                        if host.elapsed - when > BOUND + 60:
                            assert _shown(issuer, *slot), "shown within the bound of host time"
                    oldest = min(issuer.audit.entries(), key=lambda e: e["seq"], default=None)
                    young = [t for t in logged if host.elapsed - t < retention * DAY - CLOCK_TOLERANCE]
                    assert oldest is None or len(issuer.audit.entries()) >= len(young), "nothing young pruned"
            for slot, when in revoked:
                for key, _ in issuer.store.items("status-pending", f"{slot[0]}:"):
                    if key.endswith(f":{slot[1]:08d}"):
                        assert int(key.split(":")[1]) / 1000 >= base + (when - 5000) - CLOCK_TOLERANCE

    def make_issuer_for(clock: Clock, **overrides: Any) -> Issuer:
        from cunho.settings import Settings
        from cunho.store import MemoryStore

        from .helpers import settings_kwargs

        store = overrides.pop("store", None) or MemoryStore(clock)
        return Issuer(Settings(**settings_kwargs(pki, **overrides)), store=store, clock=clock)

    del hypothesis
    run()


# What the round's own mutants showed untested -----------------------------------------------------------------


def test_a_clock_that_went_back_never_stalls_maintenance(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """Without a host clock the time is the wall clock, and it can go back; maintenance then runs at once rather
    than waiting for the time to catch up with the last run."""
    issuer = make_issuer()
    issuer.maintenance(force=True)
    clock.now -= DAY
    assert "expired_entries" in issuer.maintenance()


def test_a_worker_goes_by_the_time_from_its_start(pki: Pki, tmp_path: Path) -> None:
    """An issuer on the real host clock reads the clock when it is built, so its first request already goes by
    the watch's time rather than by the wall clock."""
    import time

    from cunho.settings import Settings
    from cunho.store import MemoryStore

    from .helpers import settings_kwargs

    issuer = Issuer(Settings(**settings_kwargs(pki)), store=MemoryStore(time.time), clock=time.time)
    now = issuer.clock_watch.now()
    assert now is not None and abs(now - time.time()) < 5


def test_decoys_are_scheduled_by_the_time(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, status_decoy_churn_per_day=0.05, status_revocation_jitter=JITTER)
    issuer.sweep()
    clock.now += 400 * DAY
    issuer.status.allocate()  # opens list 1, its schedule laid at once
    host.advance(3 * 3600)
    assert issuer.status.churn() > 0
    latest = max(int(k.split(":")[1]) / 1000 for k, _ in issuer.store.items("status-pending", "1:"))
    assert latest <= host.true() + 2 * 3600 + JITTER, "two intervals and the jitter ahead of the time at most"


def test_an_entry_logged_without_a_time_does_not_hold_pruning_back(
    make_issuer: Callable[..., Issuer], clock: Clock
) -> None:
    """An entry logged after a host restart, before the watch could vouch for the time, carries the wall clock as
    it read, here 400 days ahead. Measured against the time, not the wall clock, which still reads ahead, it is
    dated ahead, so the older entries logged after it go with the first older one, as the chain orders them."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, audit_retention_days=30)
    issuer.sweep()
    host.boot, host.elapsed, host.synced = "boot-2", 30.0, None
    clock.now += 400 * DAY
    issuer.use_clock_watch(host.watch(issuer.store))
    issuer.clock_watch.steady()
    ahead = issuer.audit.append("offer.created", "admin")
    assert ahead["time"] == int(clock())
    host.advance(3600)
    assert issuer.clock_watch.steady(), "kept pace with the host clock for an interval: a base at the wrong time"
    issuer.maintenance(force=True)  # an operator who knows better lays the base from a clock put right
    clock.now -= 400 * DAY
    issuer.maintenance(force=True)
    for _ in range(3):
        issuer.audit.append("offer.created", "admin")
    host.advance(31 * DAY)
    clock.now += 400 * DAY  # the wall clock reads far ahead again; the time does not follow it
    issuer.audit.append("offer.created", "admin")
    issuer._last_maintenance = 0  # noqa: SLF001
    done = issuer.maintenance()
    assert done["audit_entries_pruned"] >= 4, done


def test_verify_measures_the_checkpoint_by_the_time(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, audit_retention_days=30)
    issuer.maintenance(force=True)
    issuer.audit.append("offer.created", "admin")
    host.advance(31 * DAY)
    issuer.audit.append("offer.created", "admin")
    issuer.maintenance(force=True)
    assert issuer.audit.verify()[0]
    clock.now -= 400 * DAY
    assert issuer.audit.verify()[0], "a wall clock far behind does not make the checkpoint look young"


def test_a_new_boot_reading_off_by_exactly_the_tolerance_keeps_pace(clock: Clock) -> None:
    host, store = Host(clock), store_for(clock)
    assert host.watch(store).steady()
    host.boot, host.elapsed, host.synced = "boot-2", 30.0, None
    clock.now -= DAY
    watch = host.watch(store, 3600)
    assert not watch.steady()
    host.advance(3600)
    clock.now += CLOCK_TOLERANCE  # off by the tolerance over the interval, and no more
    assert watch.steady()


def test_an_upgrade_that_cannot_be_logged_refuses_to_start(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    kw = {"secret_key_file": tmp_path / "m.key", "audit_anchor_path": tmp_path / "audit.anchor"}
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    issuer.audit.append("offer.created", "admin")
    issuer.store.delete("meta", "schema")
    lines = (tmp_path / "audit.anchor").read_bytes().splitlines(keepends=True)
    with (tmp_path / "audit.anchor").open("ab") as anchor:
        anchor.write(lines[0])  # a copy of the genesis line: nothing can be logged
    with pytest.raises(ConfigError, match="repeats or goes back"):
        make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)


def test_pruning_reports_an_entry_whose_key_is_no_number(
    make_issuer: Callable[..., Issuer], clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """A damaged log whose first key is not a number stops pruning with the alert, and maintenance goes on to its
    other steps (second reviewer)."""
    issuer = make_issuer()
    issuer.audit.append("offer.created", "admin")
    issuer.store.put("audit", "!", {"seq": 1}, None)
    clock.now += 400 * DAY
    with caplog.at_level(logging.ERROR, logger="cunho.security"):
        assert issuer.audit.prune_before(clock.now - DAY) == 0
        assert isinstance(issuer.maintenance(force=True), dict)  # it runs through, without raising
    assert "audit pruning stopped at entry '!'" in caplog.text


@pytest.mark.parametrize("damage", ["surrogate", "long key"])
def test_a_damaged_audit_row_stops_pruning_only(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, caplog: pytest.LogCaptureFixture, damage: str
) -> None:
    """A row a database writer damaged so that checking it could raise (a lone surrogate in its data, a key of
    thousands of digits) is reported as not verifying: verify says so, pruning stops with the alert, and
    maintenance runs its other steps (the second reviewer)."""
    store = SqliteStore(tmp_path / "s.db", clock)
    issuer = make_issuer(store=store)
    issuer.audit.append("offer.created", "admin")
    issuer.audit.append("offer.created", "admin")
    db = sqlite3.connect(tmp_path / "s.db")
    if damage == "surrogate":
        value = db.execute("SELECT value FROM kv WHERE ns='audit' AND key=?", (f"{1:012d}",)).fetchone()[0]
        entry = json.loads(value)
        entry["actor"] = "\ud800"
        db.execute("UPDATE kv SET value=? WHERE ns='audit' AND key=?", (json.dumps(entry), f"{1:012d}"))
    else:
        db.execute("INSERT INTO kv VALUES ('audit', ?, '{}', NULL)", ("0" * 5000,))
    db.commit()
    db.close()
    clock.now += 400 * DAY
    assert issuer.audit.verify()[0] is False
    with caplog.at_level(logging.ERROR, logger="cunho.security"):
        assert issuer.audit.prune_before(clock.now - DAY) == 0
        assert isinstance(issuer.maintenance(force=True), dict)  # it runs through, without raising
    assert "audit pruning stopped at entry" in caplog.text
    assert len(caplog.text) < 20_000, "the alert names a damaged key cut short"


def test_a_clock_base_written_into_the_database_does_not_bring_an_offer_back(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """Whoever can write the database alone moved the base back, and an expired offer was exchanged again with a
    DPoP proof dated at the moved time (the second reviewer). The base and the latest time seen are kept under
    a MAC: a moved one does not verify, the watch takes it for none, and the time stays right."""
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        offer = wallet.offer()
        code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        host.advance(issuer.settings.offer_ttl + 60)
        assert wallet.token_request(code).status_code == 400
        issuer.clock_watch.steady()  # a reading on the base keeps the latest time seen
        for key in (f"clock:{host.boot}", "seen"):
            row: Any = issuer.store.get("maintenance", key)
            back = issuer.settings.offer_ttl + 600
            if isinstance(row, dict):
                row["time"] -= back
            else:
                row -= back  # the latest time seen as it was kept before it carried a MAC
            issuer.store.put("maintenance", key, row, None)
        issuer.clock_watch.steady()
        assert abs(issuer.time() - clock.now) <= CLOCK_TOLERANCE, "the moved base is not gone by"
        wallet.clock.now = issuer.time()  # a proof dated at whatever time the issuer goes by
        assert wallet.token_request(code).status_code == 400
        restarted = host.watch(issuer.store)
        assert restarted.now() is None, "a worker started later does not take the moved base either"


@pytest.mark.parametrize("damage", ["written", "deleted"])
def test_a_latest_time_seen_taken_back_does_not_bring_a_set_back_clock_in(
    make_issuer: Callable[..., Issuer], clock: Clock, damage: str
) -> None:
    """After a host restart the watch trusts a synchronised clock at once only when it is not behind the latest
    time seen. Whoever can write the database alone took that time back to the base, written in or deleted, and a
    clock set back since the base was trusted at once (CX-12). A time seen that does not verify, or none, is a
    wait of an interval."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    assert issuer.clock_watch.steady()  # the base
    host.advance(3 * 3600)
    assert issuer.clock_watch.steady()  # the latest time seen, three hours after it
    base = issuer.store.get("maintenance", f"clock:{host.boot}")
    assert base is not None
    if damage == "written":
        issuer.store.put("maintenance", "seen", {"time": base["time"], "tag": "0" * 64}, None)
    else:
        issuer.store.delete("maintenance", "seen")
    host.boot, host.elapsed, host.synced = "boot-2", 10.0, True
    clock.now -= 600  # behind the time seen, ahead of the base
    restarted = host.watch(issuer.store)
    assert not restarted.steady(), "not at once"
    assert restarted.now() is None


def test_a_watch_with_a_host_clock_needs_a_keyring(clock: Clock) -> None:
    """The base and the latest time seen are kept under a MAC; a watch that could not make one does not start."""
    host = HostClock(elapsed=lambda: 0.0, boot=lambda: "boot-1", synced=lambda: None)
    with pytest.raises(ConfigError, match="keyring"):
        ClockWatch(store_for(clock), clock, 3600, host=host)


def test_a_base_pairs_the_wall_and_host_clock_read_together(clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    """A pause between the wall-clock reading and laying the base (a lock, a busy store) does not leave the time
    behind for the boot (eighth review, CX-5)."""
    host, store = Host(clock), store_for(clock)
    watch = host.watch(store)
    peek = store.peek

    def slow(ns: str, key: str) -> Any:
        if ns == "maintenance" and key.startswith("clock"):
            host.advance(180)  # time really passes while the watch waits
        return peek(ns, key)

    monkeypatch.setattr(store, "peek", slow)
    assert watch.steady()
    monkeypatch.setattr(store, "peek", peek)
    assert watch.steady()
    now = watch.now()
    assert now is not None and abs(now - clock.now) < 1


def test_workers_starting_together_on_a_new_boot_lay_one_base(clock: Clock, tmp_path: Path) -> None:
    """Two workers start on a new boot and the wall clock steps between their readings: the second goes by the
    base the first laid and never replaces it (eighth review, CX-6)."""
    host = Host(clock)
    assert host.watch(SqliteStore(tmp_path / "s.db", clock)).steady()
    host.boot, host.elapsed, host.synced = "boot-2", 30.0, True
    host.advance(600)
    first_store, second_store = SqliteStore(tmp_path / "s.db", clock), SqliteStore(tmp_path / "s.db", clock)
    first, second = host.watch(first_store), host.watch(second_store)
    peek, reads, done = first_store.peek, [0], threading.Event()

    def other_worker() -> None:
        second.steady()
        done.set()

    worker = threading.Thread(target=other_worker)

    def interleaved(ns: str, key: str) -> Any:
        value = peek(ns, key)
        if ns == "maintenance" and key.startswith("clock"):
            reads[0] += 1
            if reads[0] == 2:  # the first worker has read the old boot's base and has not laid its own yet
                clock.now += 100  # the wall clock steps
                worker.start()
                done.wait(1)  # the second worker waits for the first, or (before the fix) lays its own base
        return value

    first_store.peek = interleaved  # type: ignore[method-assign]
    assert first.steady()
    worker.join(10)
    assert done.is_set()
    first_now, second_now = first.now(), second.now()
    assert first_now is not None and second_now is not None
    assert abs(first_now - second_now) < 1
    stored = second_store.get("maintenance", f"clock:{host.boot}")
    assert stored is not None and stored["time"] == pytest.approx(clock.now - 100)  # the first base


def test_a_forced_correction_in_one_worker_is_the_time_of_every_worker(clock: Clock, tmp_path: Path) -> None:
    """The base was laid from a clock a day ahead, and an operator corrected it with a forced run in one worker.
    Another worker kept the old base until its next tick and took a nonce the first had just created as expired,
    which deleted it (the second reviewer, CX-13). Every worker reads the base in the store, inside the
    transaction, so the correction is every worker's time at once."""
    host = Host(clock)
    clock.now += DAY  # the wall clock reads a day ahead when the store starts
    workers = []
    for _ in range(2):
        store = SqliteStore(tmp_path / "s.db", clock)
        watch = host.watch(store)
        store.go_by(functools.partial(_time_of, watch, clock))
        workers.append((store, watch))
    (first_store, first), (second_store, second) = workers
    assert first.steady() and second.steady()
    assert second.now() == pytest.approx(clock.now)
    clock.now -= DAY
    first.trust(clock.now)  # the forced run, in the first worker only
    first_store.put("nonce", "n", "fresh", 300)
    now = second.now()
    assert now is not None and abs(now - clock.now) < 1, "the second worker goes by the corrected base"
    assert second_store.take("nonce", "n") == "fresh", "a fresh nonce is not taken for expired"


def test_no_request_reads_the_store_on_the_event_loop(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """The time reads the clock base in the store, so a time read on the event loop is a store call there, and a
    store transaction of another thread stalled every request in the worker: the cached status token and a
    refused admin request did (the second reviewer, CX-14). No route reads the store on the event loop."""
    with _running(make_issuer, pki, clock) as (issuer, _host, wallet):
        ref = issuer.status.allocate()
        on_loop: list[str] = []
        store = issuer.store
        for name in ("peek", "get", "put", "take", "add", "incr", "delete", "items", "scan", "atomic"):
            method = getattr(store, name)

            def watched(*args: Any, _name: str = name, _method: Any = method, **kwargs: Any) -> Any:
                try:
                    asyncio.get_running_loop()
                    on_loop.append(_name)
                except RuntimeError:
                    pass  # a worker thread of the pool
                return _method(*args, **kwargs)

            setattr(store, name, watched)
        for _ in range(2):  # signed, then the cached token
            assert wallet.client.get(f"/status/{ref.list_id}").status_code == 200
        assert wallet.client.post("/admin/offers", json={}, headers={"Authorization": "Bearer x"}).status_code == 401
        assert wallet.client.get("/.well-known/openid-credential-issuer").status_code == 200
        assert on_loop == []


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_a_sweep_deletes_nothing_stamped_after_a_correction_it_did_not_see(
    clock: Clock, tmp_path: Path, kind: str
) -> None:
    """Maintenance read the time, another worker corrected a base laid a day ahead with a forced run, and the
    sweep went on with the cutoff it had read: a DPoP replay marker of 300 seconds the corrected worker had just
    made was deleted while still live (the second reviewer, CX-15). The sweep reads the time again inside each
    of its transactions and goes by the earlier one."""
    host = Host(clock)
    clock.now += DAY
    shared = MemoryStore(clock) if kind == "memory" else None
    workers = []
    for _ in range(1 if kind == "memory" else 2):
        store = shared if shared is not None else SqliteStore(tmp_path / "s.db", clock)
        watch = host.watch(store)
        store.go_by(functools.partial(_time_of, watch, clock))
        workers.append((store, watch))
    (first_store, first), (second_store, second) = workers[0], workers[-1]
    assert all(watch.steady() for _, watch in workers)
    cutoff = second.now()  # what the sweep of the second worker read
    assert cutoff is not None
    clock.now -= DAY
    first.trust(clock.now)
    first_store.put("dpop", "jti", 1, 300)
    assert second_store.sweep(cutoff) == 0
    assert second_store.get("dpop", "jti") == 1, "a live replay marker is kept"


def test_pruning_goes_by_a_correction_made_while_it_runs(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """Maintenance read the time from a base laid 40 days ahead, another worker corrected it with a forced run,
    and an entry logged by the corrected time was pruned at once by the cutoff read before, with 30 days of
    retention (the second reviewer, CX-16). Every pruning batch reads the time again and moves the cutoff back
    as far as the time went back."""
    host = Host(clock)
    clock.now += 40 * DAY  # the wall clock reads 40 days ahead when the store starts
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), audit_retention_days=30)
    assert issuer.clock_watch.steady()
    stale = issuer.clock_watch.now()  # what maintenance read
    assert stale is not None
    other = host.watch(SqliteStore(tmp_path / "s.db", clock))
    clock.now -= 40 * DAY
    other.trust(clock.now)  # a forced run in the other worker
    issuer.audit.append("offer.created", "admin")  # logged by the corrected time
    kept = len(issuer.audit.entries())
    assert issuer.audit.prune_before(stale - 30 * DAY, now=stale) == 0
    assert len(issuer.audit.entries()) == kept
    assert issuer.audit.verify()[0]


def test_pruning_stops_when_another_worker_lays_the_base_again(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """A forced run lays the base again, and pruning waits an interval after it, in every worker: one that
    started pruning before it stops at its next batch (CX-16)."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), audit_retention_days=30)
    assert issuer.clock_watch.steady()
    issuer.audit.append("offer.created", "admin")
    host.advance(31 * DAY)
    assert issuer.clock_watch.steady() and issuer.clock_watch.settled()
    now = issuer.clock_watch.now()
    assert now is not None
    host.watch(SqliteStore(tmp_path / "s.db", clock)).trust(clock.now)  # a forced run in the other worker
    assert issuer._prune(now) == 0
    assert len(issuer.audit.entries()) == 1


def test_a_clock_base_put_back_after_a_forced_correction_is_not_gone_by(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """The base was laid from a clock an hour behind and an operator put it right with a forced run. Whoever can
    write the database alone put the earlier base back, its MAC still good, and an expired offer was exchanged
    again, while verify still passed (the second reviewer, CX-17). The forced run's entry names the base on its
    anchor line, outside the database: a base laid before it on the same boot is not gone by, in this worker or
    in one started later."""
    clock.now -= 3600  # the wall clock reads an hour behind when the base is laid
    with _running(make_issuer, pki, clock) as (issuer, host, wallet):
        before = issuer.store.peek("maintenance", f"clock:{host.boot}")
        host.advance(1)
        clock.now += 3600  # put right
        issuer.maintenance(force=True)
        offer = wallet.offer()
        code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        host.advance(issuer.settings.offer_ttl + 60)
        issuer.clock_watch.steady()
        assert wallet.token_request(code).status_code == 400
        issuer.store.put("maintenance", f"clock:{host.boot}", before, None)  # the earlier base, with its MAC, put back
        issuer.clock_watch.steady()
        assert abs(issuer.time() - clock.now) <= CLOCK_TOLERANCE, "the earlier base is not gone by"
        wallet.clock.now = issuer.time()  # a proof dated at whatever time the issuer goes by
        assert wallet.token_request(code).status_code == 400
        assert issuer.audit.verify()[0]
        restarted = host.watch(issuer.store, floor=issuer.audit.clock_floor)
        assert restarted.now() is None, "a worker started later refuses it too, by the anchor"


def test_a_worker_that_never_saw_the_corrected_base_refuses_the_earlier_one(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """A second worker read the base before the forced run and nothing since. The earlier base put back is the
    row it read last, and it refused it only at its next tick, up to a minute later (the second reviewer,
    CX-18). Every reading of the time asks the anchor, so it refuses that row at once."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    assert issuer.clock_watch.steady()
    second = host.watch(SqliteStore(tmp_path / "s.db", clock), floor=issuer.audit.clock_floor)
    assert second.now() is not None
    before = issuer.store.peek("maintenance", f"clock:{host.boot}")
    host.advance(60)
    clock.now += 3600
    issuer.maintenance(force=True)
    issuer.store.put("maintenance", f"clock:{host.boot}", before, None)
    assert second.now() is None, "at once, without a tick"


def test_the_anchor_names_a_forced_base_also_when_its_line_was_written_late(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forced run's anchor line names its base, also when the line is written by the next transaction, after
    a crash left it out (CX-17)."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    assert issuer.clock_watch.steady()
    host.advance(60)
    monkeypatch.setattr(issuer.audit, "_anchor_committed", lambda: None)  # the line is not written
    issuer.maintenance(force=True)
    monkeypatch.undo()
    base: Any = issuer.store.peek("maintenance", f"clock:{host.boot}")
    issuer.audit.append("offer.created", "admin")  # the next transaction writes the missing line first
    assert issuer.audit.clock_floor() == (base["boot"], base["elapsed"], base["time"])


def test_a_forced_base_on_an_anchor_line_that_lost_its_newline_still_counts(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """A forced run's anchor line lost only its last byte, the newline. The line is authenticated and the next
    write closes it, but its base was not counted, before the repair or after it, so a copy of the base before
    it was gone by again (the second reviewer, CX-19)."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    assert issuer.clock_watch.steady()
    before = issuer.store.peek("maintenance", f"clock:{host.boot}")
    host.advance(60)
    issuer.maintenance(force=True)
    base: Any = issuer.store.peek("maintenance", f"clock:{host.boot}")
    expected = (base["boot"], base["elapsed"], base["time"])
    path = tmp_path / "s.db.audit-anchor"
    data = path.read_bytes()
    assert data.endswith(b"\n")
    path.write_bytes(data[:-1])  # a torn write: the forced run's line without its newline
    fresh = Anchor(path, issuer.keyring)
    assert fresh.clock() == list(expected), "a worker reading the file now"
    issuer.audit.append("offer.created", "admin")  # the next write closes the line
    assert issuer.audit.verify()[0]
    assert issuer.audit.clock_floor() == expected
    assert Anchor(path, issuer.keyring).clock() == list(expected), "a worker reading it after the repair"
    issuer.store.put("maintenance", f"clock:{host.boot}", before, None)
    assert host.watch(issuer.store, floor=issuer.audit.clock_floor).now() is None


def test_a_failed_forced_run_leaves_the_watch_as_the_store(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forced run could not log its entry, and the store went back to the base before it; the watch had raised
    its floor to the base laid inside, refused the base the store went back to, and went by the wall clock while
    every other worker went by the base (the second reviewer, CX-20). The watch's memory goes back too."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    assert issuer.clock_watch.steady()
    host.advance(60)
    clock.now += 600  # the wall clock steps; a forced run would lay the base by it
    expected = issuer.clock_watch.now()
    real = issuer.audit.append

    def failing(event: str, actor: str, **data: Any) -> dict[str, Any]:
        if event == CLOCK_TRUSTED:
            raise AuditError("the anchor cannot be written")
        return real(event, actor, **data)

    monkeypatch.setattr(issuer.audit, "append", failing)
    with pytest.raises(AuditError):
        issuer.maintenance(force=True)
    assert issuer.clock_watch.now() == expected, "the base before the forced run, as in every other worker"


def test_the_watch_is_put_back_before_the_store_lets_go(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forced run failed, the transaction rolled back and let go of the store, and only then did the watch's
    memory go back: a request in between read the base the store went back to while the floor still named the
    one undone, refused it and went by the wall clock (the second reviewer, CX-30). The watch goes back inside
    the rollback, while the store's lock is still held."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    assert issuer.clock_watch.steady()
    host.advance(60)
    clock.now += 600
    expected = issuer.clock_watch.now()
    seen: list[tuple[int, float | None]] = []
    real_trust, real_append = issuer.clock_watch.trust, issuer.audit.append

    def trust(now: float) -> Any:
        store: Any = issuer.store
        store.on_rollback(lambda: seen.append((store._depth, issuer.clock_watch.now())))  # noqa: SLF001
        return real_trust(now)

    def failing(event: str, actor: str, **data: Any) -> dict[str, Any]:
        if event == CLOCK_TRUSTED:
            raise AuditError("the anchor cannot be written")
        return real_append(event, actor, **data)

    monkeypatch.setattr(issuer.clock_watch, "trust", trust)
    monkeypatch.setattr(issuer.audit, "append", failing)
    with pytest.raises(AuditError):
        issuer.maintenance(force=True)
    assert seen == [(1, expected)], "inside the rollback, still holding the store, the time is the store's"
    assert issuer.clock_watch.now() == expected


def test_a_base_whose_commit_fails_leaves_the_watch_as_the_store(clock: Clock, tmp_path: Path) -> None:
    """A base laid in a transaction whose COMMIT fails is undone with the watch's memory too (CX-30)."""
    host = Host(clock)
    store = SqliteStore(tmp_path / "s.db", clock)
    watch = host.watch(store)
    assert watch.steady()
    host.advance(60)
    expected = watch.now()

    class FailingCommit:
        def __init__(self, db: Any) -> None:
            self._db = db

        def __getattr__(self, name: str) -> Any:
            return getattr(self._db, name)

        def execute(self, sql: str, *args: Any) -> Any:
            if sql == "COMMIT":
                raise sqlite3.OperationalError("disk I/O error")
            return self._db.execute(sql, *args)

    real = store._db  # noqa: SLF001
    store._db = FailingCommit(real)  # type: ignore[assignment]  # noqa: SLF001
    with pytest.raises(sqlite3.OperationalError):
        watch.trust(clock.now + 600)
    store._db = real  # noqa: SLF001
    assert watch.now() == expected


def test_a_correction_forward_while_publishing_does_not_bring_a_revocation_forward(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """One worker started publishing by a time a day behind; another put the time right with a forced run and
    revoked, laying the bit within the jitter of the right time. The first took that moment for one laid too
    late by a clock that read ahead and laid it again by its own time, a day back, so the bit showed at once,
    its jitter lost (the second reviewer, CX-21). The time is read inside the transaction that lays again."""
    host = Host(clock)
    clock.now -= DAY  # the base is laid a day behind
    kw = {"secret_key_file": tmp_path / "m.key", "status_revocation_jitter": JITTER, "status_decoy_churn_per_day": 0}
    with mock.patch.object(status_module, "secrets", Seeded(1)):
        first = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
        second = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
        assert first.clock_watch.steady() and second.clock_watch.steady()
        ref = first.status.allocate()
        host.advance(60)
        clock.now += DAY  # put right
        store, atomic, laid = second.store, second.store.atomic, []

        def corrected_meanwhile() -> Any:
            store.atomic = atomic  # type: ignore[method-assign]
            first.maintenance(force=True)  # the other worker puts the time a day forward
            assert first.status.revoke(ref)  # and revokes, within the jitter of the right time
            laid.extend(store.items("status-pending", f"{ref.list_id}:"))
            return atomic()

        store.atomic = corrected_meanwhile  # type: ignore[method-assign]
        second.status.publish()
        store.atomic = atomic  # type: ignore[method-assign]
        assert laid and store.items("status-pending", f"{ref.list_id}:") == laid, "the moment stays as laid"
        first.status.publish()
        assert _shown(first, ref.list_id, ref.index) == 0, "not before its jitter"


@pytest.mark.parametrize(
    "junk",
    [
        b'{"seq":9,"mac":"\\ud800","prev":"x","time":0,"tag":"t"}\n',  # a lone surrogate, which cannot be MACed
        b"[" * 100_000 + b"\n",  # nesting that exhausts the stack
    ],
)
def test_a_malformed_anchor_line_does_not_stop_the_time(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path, junk: bytes
) -> None:
    """Every reading of the time reads the anchor, so a line appended to it that could not be parsed or tagged
    broke /nonce, /status and a worker's start, not only the audit log (the second reviewer, CX-22). Such a line
    is no line: the reader keeps the newest base it found, and the time goes on."""
    with _running(make_issuer, pki, clock, store=SqliteStore(tmp_path / "s.db", clock)) as (issuer, host, wallet):
        host.advance(60)
        issuer.maintenance(force=True)
        floor = issuer.audit.clock_floor()
        assert floor is not None
        with (tmp_path / "s.db.audit-anchor").open("ab") as anchor_file:
            anchor_file.write(junk)
        host.advance(1)
        assert issuer.audit.clock_floor() == floor
        assert issuer.clock_watch.now() is not None
        assert wallet.client.post("/nonce").status_code == 200
        assert host.watch(issuer.store, floor=issuer.audit.clock_floor).now() is not None, "a worker starting"
        issuer.audit.append("offer.created", "admin")  # the writer takes it for damage and declares it
        assert issuer.audit.verify()[0]


def test_a_clock_reader_that_fails_keeps_the_newest_base_it_found(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever the reader fails with, the floor stays the newest base it found and the time goes on (CX-22)."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    assert issuer.clock_watch.steady()
    host.advance(60)
    issuer.maintenance(force=True)
    floor = issuer.audit.clock_floor()
    assert floor is not None and issuer.audit.anchor is not None
    issuer.audit.append("offer.created", "admin")  # the file grows, so the reader reads again

    def broken(*_: Any, **__: Any) -> Any:
        raise ValueError("a reader that fails in a way nobody foresaw")

    monkeypatch.setattr(issuer.audit.anchor, "_scan", broken)
    assert issuer.audit.clock_floor() == floor
    assert issuer.clock_watch.now() is not None


def test_a_correction_back_while_publishing_does_not_show_a_bit_early(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """One worker read the publication's cutoff by a time a day ahead; another put the time right with a forced
    run and revoked. The first published by the cutoff it had read, and the bit, not due for a while by the
    right time, showed at once, its jitter lost (the second reviewer, CX-23). The cutoff is read again inside the
    transaction that brings bits forward, and the earlier one taken."""
    host = Host(clock)
    clock.now += DAY  # the base is laid a day ahead
    kw = {"secret_key_file": tmp_path / "m.key", "status_revocation_jitter": JITTER, "status_decoy_churn_per_day": 0}
    with mock.patch.object(status_module, "secrets", Seeded(1)):
        first = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
        second = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
        assert first.clock_watch.steady() and second.clock_watch.steady()
        ref = first.status.allocate()
        host.advance(60)
        clock.now -= DAY  # put right
        store, atomic = second.store, second.store.atomic

        def corrected_meanwhile() -> Any:
            store.atomic = atomic  # type: ignore[method-assign]
            first.maintenance(force=True)  # the other worker puts the time a day back
            assert first.status.revoke(ref)  # and revokes, within the jitter of the right time
            return atomic()

        store.atomic = corrected_meanwhile  # type: ignore[method-assign]
        second.status.publish()
        store.atomic = atomic  # type: ignore[method-assign]
        assert _shown(first, ref.list_id, ref.index) == 0, "not before its jitter"
        assert _pending(first, ref.list_id) >= 1


@pytest.mark.parametrize("step", [-DAY, DAY])
def test_an_expiry_is_stamped_by_the_time_in_its_write(clock: Clock, tmp_path: Path, step: int) -> None:
    """A worker read the time for a nonce's expiry and then waited for the write lock while another committed a
    forced run a day back, or a day forward: the nonce of 300 seconds was good for a day more, or expired at once
    (the second reviewer, CX-24). A row that expires is stamped inside its write transaction."""
    host = Host(clock)
    clock.now -= step  # the base is laid off by the step
    workers = []
    for _ in range(2):
        store = SqliteStore(tmp_path / "s.db", clock)
        watch = host.watch(store)
        store.go_by(functools.partial(_time_of, watch, clock))
        workers.append((store, watch))
    (_, first), (second_store, second) = workers
    assert first.steady() and second.steady()
    clock.now += step  # put right
    atomic = second_store.atomic

    def corrected_meanwhile() -> Any:
        second_store.atomic = atomic  # type: ignore[method-assign]
        first.trust(clock.now)  # the forced run, in the other worker
        return atomic()

    second_store.atomic = corrected_meanwhile  # type: ignore[method-assign]
    second_store.put("nonce", "n", 1, 300)
    second_store.atomic = atomic  # type: ignore[method-assign]
    db = sqlite3.connect(tmp_path / "s.db")
    expires = db.execute("SELECT expires FROM kv WHERE ns='nonce' AND key='n'").fetchone()[0]
    db.close()
    assert abs(expires - (clock.now + 300)) < 5, "300 seconds by the corrected time"


def test_decoys_are_scheduled_by_the_time_in_their_transaction(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """A worker read the time to schedule decoys, another put it three days forward with a forced run, and the
    decoys were laid three days in the past, so the next publication showed them together (the second reviewer,
    CX-25). The time is read inside the transaction that lays them."""
    host = Host(clock)
    clock.now -= 3 * DAY  # the base is laid three days behind
    kw = {"secret_key_file": tmp_path / "m.key", "status_decoy_churn_per_day": 0.05, "status_list_size": 131_072}
    with mock.patch.object(status_module, "secrets", Seeded(1)):
        first = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
        second = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
        assert first.clock_watch.steady() and second.clock_watch.steady()
        ref = first.status.allocate()
        laid = {key for key, _ in second.store.items("status-pending", f"{ref.list_id}:")}
        host.advance(60)
        clock.now += 3 * DAY  # put right
        store, atomic = second.store, second.store.atomic

        def corrected_meanwhile() -> Any:
            store.atomic = atomic  # type: ignore[method-assign]
            first.clock_watch.trust(clock.now)  # the forced run, in the other worker
            return atomic()

        store.atomic = corrected_meanwhile  # type: ignore[method-assign]
        assert second.status.churn() > 0
        store.atomic = atomic  # type: ignore[method-assign]
        new = [key for key, _ in second.store.items("status-pending", f"{ref.list_id}:") if key not in laid]
        assert new
        moments = [int(key.split(":")[1]) / 1000 for key in new]
        assert min(moments) >= clock.now - CLOCK_TOLERANCE, "none laid in the past by the time before"


def test_a_claim_after_its_token_expired_is_refused(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """A configuration claimed when the token was new has a marker that expires with the token. A request that
    began a second before the token expired reached its claim a second after, found the marker gone, and was
    issued the configuration again (the second reviewer, CX-26). The claim checks the token again."""
    issuer = make_issuer()
    grant = Grant("g1", "jkt", [PID_CONFIG], "sub", "offer", int(issuer.time()) + issuer.settings.access_token_ttl)
    issuer._claim_grant(grant, PID_CONFIG, ProvenKeys(keys=[]))  # noqa: SLF001
    clock.now = grant.expires  # the second the token expires, as `opened` takes it: no longer good
    with pytest.raises(IssuerError, match="expired access token"):
        issuer._claim_grant(grant, PID_CONFIG, ProvenKeys(keys=[]))  # noqa: SLF001


def test_a_claim_lives_until_its_token_expires(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """A token issued for 600 seconds outlives a restart that set the lifetime to 300; its claim markers lived
    300 seconds, and the same configuration was issued again after 301 (the second reviewer, CX-28). A marker
    lives until the token's own expiry."""
    issuer = make_issuer(access_token_ttl=300)
    grant = Grant("g1", "jkt", [PID_CONFIG], "sub", "offer", int(issuer.time()) + 600)
    issuer._claim_grant(grant, PID_CONFIG, ProvenKeys(keys=[]))  # noqa: SLF001
    clock.now += 301
    with pytest.raises(IssuerError, match="already used for this credential configuration"):
        issuer._claim_grant(grant, PID_CONFIG, ProvenKeys(keys=[]))  # noqa: SLF001


def test_a_clock_number_no_float_can_hold_is_a_row_that_does_not_verify(clock: Clock) -> None:
    """A number written into the clock rows too large for a float raised OverflowError before the MAC was
    checked, and every reading of the time failed with it (the second reviewer, CX-27). It is a row that does
    not verify."""
    host, store = Host(clock), store_for(clock)
    watch = host.watch(store)
    assert watch.steady()
    store.put("maintenance", "clock:boot-1", {"time": 10**400, "elapsed": 1.0, "boot": "boot-1", "tag": "t"}, None)
    store.put("maintenance", "seen", {"time": 10**400, "tag": "t"}, None)
    assert watch.now() is None
    assert watch.steady() is False  # a reading goes on, and waits as after a restart


def _reads(monkeypatch: pytest.MonkeyPatch, owner: Any, name: str, store: Any) -> list[tuple[bool, float]]:
    """Every value `owner.name` gives from now on, with whether a store transaction was open when it was read."""
    calls: list[tuple[bool, float]] = []
    real = getattr(owner, name)

    def watched() -> Any:
        value = real()
        calls.append((store._depth > 0, value))  # noqa: SLF001
        return value

    monkeypatch.setattr(owner, name, watched)
    return calls


def test_an_access_token_expiry_is_read_in_the_transaction_that_stores_it(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep after CX-24: the expiry under an access token's MAC was read before the transaction that stored
    the token, so a forced run committed meanwhile left it stamped by the base before (CX-29)."""
    calls = _reads(monkeypatch, issuer.tokens, "_clock", issuer.store)
    wallet.get_token(wallet.offer())
    (row,) = [value for _, value in issuer.store.items("access-token")]
    assert any(inside for inside, at in calls if int(at) + issuer.settings.access_token_ttl == row["exp"])


def test_a_c_nonce_time_is_read_in_the_transaction_that_stores_it(
    issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The time a c_nonce row keeps is read in the transaction that stores it (CX-29)."""
    calls = _reads(monkeypatch, issuer.nonces, "_clock", issuer.store)
    issuer.nonces.issue_c_nonce()
    assert calls and all(inside for inside, _ in calls)


def test_a_revocation_moment_is_read_in_its_transaction(issuer: Issuer, monkeypatch: pytest.MonkeyPatch) -> None:
    """A revocation laid its moment by a time read before its transaction, so a forced run committed meanwhile
    left the moment by the base before: brought forward, or held back, by the whole correction (CX-29)."""
    ref = issuer.status.allocate()
    calls = _reads(monkeypatch, issuer.status, "now", issuer.store)
    assert issuer.status.revoke(ref)
    assert calls and all(inside for inside, _ in calls)


@pytest.mark.parametrize(
    ("named", "floor"),
    [
        (["boot-1", 5000.0, 1793751634.0], ("boot-1", 5000.0, 1793751634.0)),
        (["boot-1", 5000.0], None),  # two fields, as no line cunho writes
        ([7, 5000.0, 1793751634.0], None),  # a boot that is no name
        (["boot-1", "5000", 1793751634.0], None),  # a reading that is no number
        (["boot-1", True, 1793751634.0], None),  # nor is True
    ],
)
def test_the_clock_floor_takes_only_a_base_of_the_shape_cunho_writes(
    clock: Clock, tmp_path: Path, named: list[Any], floor: Any
) -> None:
    """An anchor line is authenticated, but its base is still taken only in the shape cunho writes: boot,
    host-clock reading and time (CX-17)."""
    keyring = Keyring.ephemeral()
    anchor = Anchor(tmp_path / "anchor", keyring)
    log = AuditLog(MemoryStore(clock), keyring, clock, anchor=anchor, create_anchor=True)
    with anchor.locked():
        anchor.write([(Mark(1, "m"), int(clock()), named)])
    assert log.clock_floor() == floor


def test_only_a_clock_trusted_entry_with_its_fields_names_a_base() -> None:
    """The anchor line of an entry names a base only for a forced run's entry, with its data (CX-17)."""
    assert _clock_of({"event": CLOCK_TRUSTED, "data": {"boot": "b", "elapsed": 1.0, "time": 2.0}}) == ["b", 1.0, 2.0]
    assert _clock_of({"event": "offer.created", "data": {"boot": "b", "elapsed": 1.0, "time": 2.0}}) is None
    assert _clock_of({"event": CLOCK_TRUSTED, "data": "not a mapping"}) is None


def _time_of(watch: ClockWatch, clock: Clock) -> float:
    """The time a worker's store goes by, as Issuer.time gives it."""
    now = watch.now()
    return clock() if now is None else now


def store_for(clock: Clock) -> Any:
    from cunho.store import MemoryStore

    return MemoryStore(clock)


def test_hosts_sharing_one_store_each_keep_their_own_base(clock: Clock) -> None:
    """Workers on two hosts share one PostgreSQL store: each boot lays and goes by its own base, so neither takes the
    other's for a restart of its own and lays it again, which reset the other's time and its wait before pruning
    (the second reviewer). The latest time seen is only ever raised."""
    store = store_for(clock)
    first = Host(clock)
    first_watch = first.watch(store)
    assert first_watch.steady()
    first.advance(4000)
    assert first_watch.steady() and first_watch.settled()
    laid = store.peek("maintenance", "clock:boot-1")
    second = Host(clock)
    second.keyring = first.keyring  # one deployment, one keyring
    second.boot, second.elapsed, second.synced = "boot-2", 77.0, True
    second_watch = second.watch(store)
    assert second_watch.steady(), "a host in sync, not behind the time seen: at once"
    assert store.peek("maintenance", "clock:boot-1") == laid, "the first host's base is untouched"
    assert first_watch.settled() and first_watch.now() == pytest.approx(clock.now)
    assert second_watch.now() == pytest.approx(clock.now)
    first.advance(100)  # time passes on the first host's clock; the second's stands still: their times part
    assert first_watch.steady()
    ahead = store.get("maintenance", "seen")["time"]
    assert ahead == pytest.approx(clock.now)
    assert second_watch.steady() and second_watch.now() == pytest.approx(clock.now - 100)
    assert store.get("maintenance", "seen")["time"] == ahead, "a host behind does not take it back"
    assert first_watch.settled(), "and the first host's wait before pruning was not started again"


def test_a_base_kept_in_the_single_row_of_an_earlier_store_still_counts(clock: Clock) -> None:
    """A store from before bases were kept per boot holds this boot's base in one row: the watch goes by it, and
    the next base it lays goes under the boot, the old row removed."""
    host, store = Host(clock), store_for(clock)
    watch = host.watch(store)
    assert watch.steady()
    store.put("maintenance", "clock", store.peek("maintenance", "clock:boot-1"), None)
    store.delete("maintenance", "clock:boot-1")
    again = host.watch(store)
    assert again.now() == pytest.approx(clock.now)
    host.advance(10)
    assert again.trust(clock.now) is not None
    assert store.peek("maintenance", "clock") is None and store.peek("maintenance", "clock:boot-1") is not None


def test_the_single_row_of_an_earlier_store_from_another_boot_is_no_base(clock: Clock) -> None:
    """The single row of a store from before bases per boot can hold a base laid before a restart: after the
    restart the watch has no base until it lays one, rather than moving the old boot's base on by the new boot's
    host clock."""
    host, store = Host(clock), store_for(clock)
    assert host.watch(store).steady()
    store.put("maintenance", "clock", store.peek("maintenance", "clock:boot-1"), None)
    store.delete("maintenance", "clock:boot-1")
    host.boot, host.elapsed = "boot-2", 5.0
    assert host.watch(store).now() is None


def test_another_hosts_forced_run_does_not_hide_this_boots(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """Host A forces its clock, then host B forces its own on the same store: a worker started later on A still
    refuses A's earlier base put back into the database, by A's line in the anchor, not B's newer one (the second
    reviewer)."""
    first = Host(clock)
    issuer = first.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock))
    assert issuer.clock_watch.steady()
    before = issuer.store.peek("maintenance", "clock:boot-1")
    first.advance(60)
    clock.now += 3600
    issuer.maintenance(force=True)  # A's correction, named in the anchor
    second = Host(clock)
    second.keyring, second.boot, second.elapsed, second.synced = issuer.keyring, "boot-2", 50.0, True
    other = second.watch(issuer.store, floor=issuer.audit.clock_floor)
    assert other.steady()
    issuer.use_clock_watch(other)
    issuer.maintenance(force=True)  # B's correction, the newer line in the anchor
    assert issuer.audit.clock_floor()[0] == "boot-2"  # type: ignore[index]
    assert issuer.audit.clock_floor("boot-1")[0] == "boot-1"  # type: ignore[index]
    issuer.store.put("maintenance", "clock:boot-1", before, None)  # A's earlier base, with its MAC, put back
    restarted = first.watch(issuer.store, floor=issuer.audit.clock_floor)
    assert restarted.now() is None, "refused by A's own line in the anchor"
