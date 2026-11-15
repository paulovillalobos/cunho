"""Regression tests for the fifth M2 review (cunho-m2-review-5.md): the status list endpoint."""

from __future__ import annotations

import asyncio
import threading
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho import status as status_module
from cunho.app import create_app
from cunho.jose import b64u_decode, parse_jws
from cunho.service import Issuer
from cunho.store import SqliteStore

from .helpers import ISSUER, Clock, Pki

# N5-M3: a status list under a mass revocation ------------------------------------------------------------


class Reads:
    """Counts the rows a store hands out, by namespace."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, store: Any) -> None:
        self.rows: dict[str, int] = {}
        for name in ("get", "items", "scan"):
            real = getattr(store, name)

            def counted(ns: str, *args: Any, _real: Any = real, **named: Any) -> Any:
                result = _real(ns, *args, **named)
                found = len(result) if isinstance(result, list) else int(result is not None)
                self.rows[ns] = self.rows.get(ns, 0) + found
                return result

            monkeypatch.setattr(store, name, counted)

    def total(self) -> int:
        return sum(self.rows.values())


def _hide(issuer: Issuer, count: int, start: float, spread: float) -> None:
    """`count` revoked bits waiting to show between `start` and `start + spread`, as a mass revocation leaves."""
    with issuer.store.atomic():
        for n in range(count):
            issuer.status._show_at("1", n, start + spread * n / count)  # noqa: SLF001


def test_n5_m3_a_poll_costs_nothing_however_many_bits_are_hidden(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """t9: a poll answered from the cache read every pending marker (79 ms with 36,000), and each publication
    read them again. Now a poll between publications reads nothing, and a publication reads the bits that
    came due."""
    issuer = make_issuer(status_list_size=131_072, status_revocation_jitter=3600, status_decoy_churn_per_day=0)
    issuer.status.allocate()
    clock.now = (int(clock()) // 60 + 1) * 60  # the start of a publication
    _hide(issuer, 20_000, clock() + 30, 3600)
    first = issuer.status_token("1")
    reads = Reads(monkeypatch, issuer.store)
    for _ in range(500):
        clock.now += 0.1
        assert issuer.status_token("1") == first
        assert issuer.status.cached("1") == first
    assert reads.total() == 0
    clock.now += 60
    second = issuer.status_token("1")
    due = 20_000 * 30 // 3600 + 1  # the bits due by the second publication, 30 to 60 s after the first
    assert second != first and reads.rows.get("status-pending", 0) <= due + 1, reads.rows
    assert len(issuer.store.items("status-pending", "1:")) == 20_000 - due
    clock.now += 3600
    reads.rows.clear()
    issuer.status.publish()
    assert issuer.store.items("status-pending", "1:") == []
    bits = zlib.decompress(b64u_decode(parse_jws(issuer.status_token("1")).payload["status_list"]["lst"]))
    assert all(bits[n // 8] >> (n % 8) & 1 for n in range(20_000)), "every hidden bit showed in the end"


def test_n5_m3_publications_are_fixed_moments_and_one_signature(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = make_issuer(status_publish_interval=300, status_token_ttl=3600)
    issuer.status.allocate()
    signed: list[int] = []
    real = status_module.sign_jws

    def counting(signer: Any, header: Any, payload: dict[str, Any]) -> str:
        signed.append(payload["iat"])
        time.sleep(0.05)  # every other poll arrives while this one signs
        return real(signer, header, payload)

    monkeypatch.setattr(status_module, "sign_jws", counting)
    threads = [threading.Thread(target=issuer.status_token, args=("1",)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(signed) == 1, "concurrent polls wait for the one that signs"
    assert signed[0] % 300 == 0 and clock() - 300 < signed[0] <= clock()
    assert issuer.status_token("1") is not None and len(signed) == 1


def test_n5_m3_status_is_rate_limited(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    issuer = make_issuer(status_rate_limit_per_minute=3)
    issuer.status.allocate()
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        codes = [client.get("/status/1").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_n5_l3_status_never_touches_the_store_on_the_event_loop(
    make_issuer: Callable[..., Issuer], monkeypatch: pytest.MonkeyPatch, clock: Clock
) -> None:
    """t7: `exists` ran in the async handler, so a store call waiting for another worker's lock froze the
    worker. Every store call of the status route now runs in the thread pool."""
    issuer = make_issuer()
    issuer.status.allocate()
    on_loop: list[str] = []
    for name in ("get", "items", "scan"):
        real = getattr(issuer.store, name)

        def watched(*args: Any, _real: Any = real, _name: str = name, **named: Any) -> Any:
            try:
                asyncio.get_running_loop()
                on_loop.append(_name)
            except RuntimeError:
                pass
            return _real(*args, **named)

        monkeypatch.setattr(issuer.store, name, watched)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        assert [client.get(path).status_code for path in ("/status/1", "/status/1", "/status/2")] == [200, 200, 404]
        clock.now += 60
        assert client.get("/status/1").status_code == 200
    assert on_loop == []


# N5-L4: a list keeps the size it was opened with -------------------------------------------------------


def test_n5_l4_changing_the_list_size_leaves_open_lists_alone(
    make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock
) -> None:
    """t5: restarting with half the size answered 500 to every relying party, and slots past the new size
    could no longer be revoked."""
    store = SqliteStore(tmp_path / "s.db", clock)
    keys = tmp_path / "m.key"
    first = make_issuer(store=store, status_list_size=8192, secret_key_file=keys)
    refs = [first.status.allocate() for _ in range(200)]
    high = next(ref for ref in refs if ref.index >= 4096)
    second = make_issuer(store=store, status_list_size=4096, secret_key_file=keys)
    second.revoke({"list": high.list_id, "index": high.index, "reason": "death"}, "admin")
    assert second.status.value(high) == 1
    clock.now += 60
    raw = zlib.decompress(b64u_decode(parse_jws(second.status_token("1")).payload["status_list"]["lst"]))
    assert len(raw) * 8 == 8192 and raw[high.index // 8] >> (high.index % 8) & 1
    while second.status.allocate().list_id == "1":
        pass
    assert second.status.size_of("2") == 4096 and second.status.size_of("1") == 8192


def test_n5_m3_the_background_tick_brings_lists_forward(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """Bits that came due are applied about once a minute even when nobody polls, so a poll after a quiet
    spell finds little to do and the queue does not grow."""
    issuer = make_issuer(status_decoy_churn_per_day=0)
    issuer.status.allocate()
    _hide(issuer, 50, clock() + 1, 100)
    issuer.sweep()
    assert len(issuer.store.items("status-pending", "1:")) == 50
    clock.now += 200
    issuer.sweep()
    assert issuer.store.items("status-pending", "1:") == []


def test_n5_m3_a_new_list_publishes_exactly_its_decoys(make_issuer: Callable[..., Issuer]) -> None:
    """The decoys a list starts with show at once, each at its own bit (LSB first, as the draft says). CI's
    mutation shard found the bit order of these, unlike that of bits brought forward later, pinned only when
    a misplaced decoy happened to land on a credential a test looked at."""
    issuer = make_issuer(status_decoy_churn_per_day=0)
    issuer.status.allocate()
    bits = zlib.decompress(b64u_decode(parse_jws(issuer.status_token("1")).payload["status_list"]["lst"]))
    shown = {index for index in range(len(bits) * 8) if bits[index // 8] >> (index % 8) & 1}
    decoys = {int(key.split(":")[1]) for key, _ in issuer.store.items("status-decoy", "1:")}
    assert shown == decoys and len(decoys) == int(4096 * issuer.settings.status_decoy_ratio)
