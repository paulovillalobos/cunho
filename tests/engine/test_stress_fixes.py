"""Regression tests for defects found by the stress harness (tools/stress).

Each test names the suite and the check that found the defect, as they appear in the harness's
SUMMARY.md, so a failure here can be traced back to the stress run that first showed it.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.audit import AuditLog
from cunho.errors import IssuerError
from cunho.keyring import Keyring
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.status import StatusLists
from cunho.store import MemoryStore, SqliteStore

from .helpers import (
    ADMIN_TOKEN,
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    PRE_AUTH,
    Clock,
    EcKey,
    Pki,
    Wallet,
    dpop_proof,
    settings_kwargs,
)

OFFER = {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, "tx_code_length": None}


def test_operator_is_not_throttled_like_anonymous_traffic(make_issuer: Callable[..., Issuer]) -> None:
    """suite1_load / suite2_races, "no 5xx & error_rate<=0.5": offer creation got 429 once wallet
    traffic from the same address used up the per-address budget, so an operator was locked out."""
    issuer = make_issuer(rate_limit_per_minute=3, operator_rate_limit_per_minute=40)
    operator = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        assert [client.post("/nonce").status_code for _ in range(4)] == [200, 200, 200, 429]
        guesses = [client.post("/admin/offers", json=OFFER, headers={"Authorization": "Bearer " + "x" * 40})]
        guesses += [client.post("/admin/offers", json=OFFER) for _ in range(3)]
        assert [r.status_code for r in guesses] == [401, 401, 401, 429], "failed logins keep the anonymous limit"
        offers = [client.post("/admin/offers", json=OFFER, headers=operator).status_code for _ in range(30)]
        assert offers == [201] * 30, "an authenticated operator has its own budget"


def test_operator_limit_is_enforced(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer(operator_rate_limit_per_minute=2)
    operator = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        statuses = [client.post("/admin/offers", json=OFFER, headers=operator).status_code for _ in range(3)]
        assert statuses == [201, 201, 429]


class PausingSqliteStore(SqliteStore):
    """One worker's connection to a shared database file, pausing after it reads a given namespace.

    Two of these on one file stand for two uvicorn workers. The pause holds the first worker between
    its read and its write until the second has made the same read, which is the interleaving the
    stress run hit by chance. When the code under test keeps the read and the write in one
    transaction, the second worker cannot get there: the pause gives up after a second and the
    first worker goes on.
    """

    def __init__(self, path: Path, barrier: threading.Barrier, namespace: str) -> None:
        super().__init__(path)
        self._barrier = barrier
        self._namespace = namespace

    def get(self, ns: str, key: str) -> Any | None:
        value = super().get(ns, key)
        if ns == self._namespace:
            try:
                self._barrier.wait(timeout=1)
            except threading.BrokenBarrierError:
                pass
        return value


def run_together(*calls: Callable[[], Any]) -> list[Any]:
    def guarded(call: Callable[[], Any]) -> Any:
        try:
            return call()
        except Exception as exc:  # noqa: BLE001 - the caller asserts on what came back
            return exc

    with ThreadPoolExecutor(len(calls)) as pool:
        return list(pool.map(guarded, calls))


def test_audit_chain_holds_across_worker_processes(tmp_path: Path) -> None:
    """suite1_load "4w c=50: no 5xx & error_rate<=1%" and suite2_races "concurrent offer creation
    across workers: all 201, no 5xx": two workers read the same audit head and one got
    "audit sequence N already written" (500), or a slower worker moved the head back."""
    keyring = Keyring.ephemeral()
    barrier = threading.Barrier(2)
    path = tmp_path / "store.db"
    workers = [AuditLog(PausingSqliteStore(path, barrier, "audit-meta"), keyring) for _ in range(2)]
    results = run_together(*(lambda log=log: log.append("offer.created", "admin") for log in workers))
    assert not [r for r in results if isinstance(r, Exception)], results
    assert sorted(r["seq"] for r in results) == [1, 2]
    ok, detail = AuditLog(SqliteStore(path), keyring).verify()
    assert ok, detail


def test_one_slot_revoked_once_across_worker_processes(
    tmp_path: Path, make_issuer: Callable[..., Issuer], clock: Clock
) -> None:
    """suite2_races "concurrent revocations: no 5xx" and "reported revoked <= issued slots (no
    inflation)": revocation read a slot as valid and then wrote it, so two workers could both
    count the same credential as revoked."""
    settings = make_issuer().settings
    signer = make_issuer().signers.status
    path = tmp_path / "store.db"
    ref = StatusLists(settings, SqliteStore(path, clock), signer, clock).allocate()
    barrier = threading.Barrier(2)
    workers = [StatusLists(settings, PausingSqliteStore(path, barrier, "status-slot"), signer, clock) for _ in range(2)]
    results = run_together(*(lambda lists=lists: lists.revoke(ref) for lists in workers))
    assert sorted(results) == [False, True]
    assert StatusLists(settings, SqliteStore(path, clock), signer, clock).value(ref) == 1


class PausingMemoryStore(MemoryStore):
    """Once armed, every reader of an offer waits until all the concurrent guesses have read it."""

    def __init__(self, clock: Clock, barrier: threading.Barrier) -> None:
        super().__init__(clock)
        self.armed = False
        self._barrier = barrier

    def get(self, ns: str, key: str) -> Any | None:
        value = super().get(ns, key)
        if ns == "offer" and self.armed:
            try:
                self._barrier.wait(timeout=2)
            except threading.BrokenBarrierError:
                pass
        return value


def test_concurrent_tx_code_guesses_are_capped(pki: Pki, clock: Clock) -> None:
    """suite2_races "tx_code brute force: at most 5 guesses evaluated under concurrency": the attempt
    counter went up only after a wrong guess, so guesses sent at once were all compared (7 of 20)
    before the lockout removed the offer."""
    guesses = 12
    barrier = threading.Barrier(guesses)
    store = PausingMemoryStore(clock, barrier)
    issuer = Issuer(Settings(**settings_kwargs(pki)), store=store, clock=clock)  # an empty store is falsy
    offer = issuer.create_offer(
        {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, "tx_code_length": 6}, "admin"
    )
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    wrong = "000000" if offer["tx_code"] != "000000" else "111111"
    form = parse_qs(f"grant_type={PRE_AUTH}&pre-authorized_code={code}&tx_code={wrong}")
    store.armed = True

    def guess() -> Any:
        proof = dpop_proof(EcKey.generate(), "POST", f"{ISSUER}/token", iat=int(clock()))
        return issuer.token(form, [proof])

    results = run_together(*([guess] * guesses))
    assert all(isinstance(r, IssuerError) and r.error == "invalid_grant" for r in results), results
    compared = [r for r in results if isinstance(r, IssuerError) and r.description == "wrong tx_code"]
    assert len(compared) == issuer.settings.tx_code_max_attempts


def test_workers_starting_together_share_one_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Found reading the multi-worker start-up path while triaging suite2_races (4 workers, one store),
    not seen failing in a run: every worker creates `<store>.keys` when it is missing. With O_EXCL
    the second worker crashed with FileExistsError, and a worker reading between create and write
    saw an empty file."""
    path = tmp_path / "store.db.keys"
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: False if self == path else real_exists(self))
    first = Keyring.from_file(path, create=True)
    second = Keyring.from_file(path, create=True)  # this worker also found the file missing
    assert first.derive("x") == second.derive("x")
    assert [p.name for p in tmp_path.iterdir()] == [path.name], "no temporary file is left behind"
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_wallet_flow_still_issues_with_the_tx_code_counter(wallet: Wallet) -> None:
    offer = wallet.offer(tx=6)
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    wrong = "000000" if offer["tx_code"] != "000000" else "111111"
    for _ in range(4):
        assert wallet.token_request(code, tx_code=wrong).status_code == 400
    assert wallet.token_request(code, tx_code=str(offer["tx_code"])).status_code == 200
