"""Regression tests for the sixth M2 review (cunho-m2-review-6.md): revocations and pruning under a wrong clock."""

from __future__ import annotations

import logging
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.jose import b64u_decode, parse_jws
from cunho.service import CLOCK_TOLERANCE, Issuer
from cunho.status import StatusRef
from cunho.store import SqliteStore

from .helpers import ISSUER, Clock, Host, Pki, Wallet

DAY, JITTER, PUBLISH = 86_400, 3600, 60

# N6-M1: a revocation shows within the jitter of the time the host clock says it was made -------------------


def _slot(response: Any) -> tuple[str, int]:
    reference = parse_jws(response.json()["credentials"][0]["credential"].split("~")[0]).payload["status"]
    return reference["status_list"]["uri"].rsplit("/", 1)[1], reference["status_list"]["idx"]


def _shown(issuer: Issuer, list_id: str, index: int) -> int:
    bits = zlib.decompress(b64u_decode(parse_jws(issuer.status_token(list_id)).payload["status_list"]["lst"]))
    return bits[index // 8] >> (index % 8) & 1


def _moment(issuer: Issuer, list_id: str, index: int) -> float:
    [(key, _)] = [(k, v) for k, v in issuer.store.items("status-pending", f"{list_id}:") if k.endswith(f":{index:08d}")]
    return int(key.split(":")[1]) / 1000


def _revoked_under(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, offset: float, *, evidence: bool = True
) -> tuple[Issuer, Host, tuple[str, int], float]:
    """A credential revoked while the wall clock reads `offset` seconds off, the host clock moving on as time
    does. Returns the issuer, the host, the slot and the true time of the revocation."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None, status_revocation_jitter=JITTER, status_decoy_churn_per_day=0)
    if evidence:
        issuer.sweep()  # the background tick: the watch trusts the clock and keeps the host clock with it
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        offer = wallet.offer()
        wallet.get_token(offer)
        slot = _slot(wallet.issue())
        host.advance(30)
        true = clock()
        clock.now += offset
        reply = wallet.admin("revocations", {"list": slot[0], "index": slot[1], "reason": "compromise"})
        assert reply.json() == {"revoked": 1}, reply.text
        clock.now -= offset
    return issuer, host, slot, true


@pytest.mark.parametrize("offset", [2 * DAY, 20 * 60, -2 * DAY, -20 * 60])
def test_n6_m1_a_revocation_under_a_wrong_clock_keeps_its_moment(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, offset: float
) -> None:
    """p1: a revocation made while the clock read two days ahead stayed hidden for two days after the clock was
    put right; one made while it read behind showed at the next publication, its moment with it."""
    issuer, host, slot, true = _revoked_under(make_issuer, pki, clock, offset)
    moment = _moment(issuer, *slot)
    assert true - CLOCK_TOLERANCE <= moment < true + JITTER + CLOCK_TOLERANCE, (moment - true, offset)
    assert issuer.status.value(StatusRef(*slot)) == 1
    host.advance(JITTER + CLOCK_TOLERANCE + PUBLISH)
    assert _shown(issuer, *slot) == 1, "within the jitter of the true time, and a publication"


def test_n6_m1_without_evidence_a_revocation_shows_at_the_next_publication(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """Before the watch trusted any reading in this process, it cannot say how far off the clock is: the bit
    shows at once rather than at a moment that may be days away."""
    with caplog.at_level(logging.WARNING, "cunho.security"):
        issuer, host, slot, _ = _revoked_under(make_issuer, pki, clock, 2 * DAY, evidence=False)
    assert "cannot vouch for the clock yet: a revocation shows at once" in caplog.text
    assert _moment(issuer, *slot) == 0
    host.advance(PUBLISH)
    assert _shown(issuer, *slot) == 1


# N6-M3: pruning waits for a clock that has read steadily for an interval --------------------------------------


def _month(make_issuer: Callable[..., Issuer], root: Path, host: Host) -> Issuer:
    clock = host.clock
    issuer = host.issuer(make_issuer, SqliteStore(root / "s.db", clock), secret_key_file=root / "m.key")
    issuer.maintenance(force=True)
    for hour in range(3 * 24):  # three days, the background tick reading the clock every hour
        host.advance(3600)
        issuer.sweep()
        if hour % 24 == 0:
            issuer.audit.append("offer.created", "admin")
    return issuer


def _restarted(make_issuer: Callable[..., Issuer], root: Path, host: Host, **overrides: Any) -> Issuer:
    return host.issuer(make_issuer, SqliteStore(root / "s.db", host.clock), secret_key_file=root / "m.key", **overrides)


def test_n6_m3_a_wrong_time_source_at_boot_prunes_nothing(
    make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """p3: after a reboot, a time source two years ahead with the kernel reporting sync was trusted at once, and
    the first maintenance run pruned every entry, all well inside a 365-day retention period."""
    host = Host(clock)
    issuer = _month(make_issuer, tmp_path, host)
    entries = len(issuer.audit.entries())
    host.boot, host.elapsed, host.synced = "boot-2", 30.0, True
    clock.now += 2 * 365 * DAY
    restarted = _restarted(make_issuer, tmp_path, host, audit_retention_days=365)
    assert restarted.clock_watch.steady(), "sweeping may go on: the kernel reports its clock synchronised"
    with caplog.at_level(logging.WARNING, "cunho.security"):
        done = restarted.maintenance()
    assert done["audit_pruning_held"] == 1 and done["audit_entries_pruned"] == 0, done
    assert "audit pruning waits" in caplog.text
    clock.now -= 2 * 365 * DAY  # NTP puts it right ten minutes later
    host.advance(600)
    assert len(restarted.audit.entries()) == entries and restarted.audit.verify()[0]


def test_n6_m3_a_host_restart_holds_pruning_for_an_interval(
    make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock
) -> None:
    """A stop on the same boot needs no wait, since the host clock counted it. A host restart lays a new base,
    and pruning waits an interval from it; the wait survives a restart of cunho, since the start of the
    steady stretch is kept with the base."""
    host = Host(clock)
    issuer = _month(make_issuer, tmp_path, host)
    host.advance(40 * DAY)  # stopped for forty days on the same boot: the host clock moved as far
    issuer.audit.append("offer.created", "admin")
    done = issuer.maintenance()
    assert "audit_pruning_held" not in done and "expired_entries" in done, done
    host.boot, host.elapsed, host.synced = "boot-2", 30.0, True
    host.advance(DAY)
    issuer = _restarted(make_issuer, tmp_path, host)
    assert issuer.maintenance()["audit_pruning_held"] == 1
    host.advance(1800)
    restarted = _restarted(make_issuer, tmp_path, host)
    restarted.sweep()
    assert not restarted.clock_watch.settled(), "half an interval after the new base, after a restart"
    for _ in range(31):
        host.advance(60)
        restarted.sweep()
    assert restarted.clock_watch.settled()
    restarted._last_maintenance = 0  # noqa: SLF001
    assert restarted.maintenance()["audit_entries_pruned"] == 0, "nothing older than ten years"
    shorter = _restarted(make_issuer, tmp_path, host, audit_retention_days=30)
    shorter.sweep()
    assert shorter.maintenance()["audit_entries_pruned"] > 0, "a settled clock prunes again"


def test_n6_m3_a_restart_with_a_steady_clock_does_not_hold_pruning(
    make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock
) -> None:
    host = Host(clock)
    issuer = _month(make_issuer, tmp_path, host)
    assert issuer.clock_watch.settled()
    host.advance(1800)  # a deployment: stopped and started again half an hour later
    restarted = _restarted(make_issuer, tmp_path, host)
    assert restarted.clock_watch.steady() and restarted.clock_watch.settled(), "the stretch is kept in the store"
