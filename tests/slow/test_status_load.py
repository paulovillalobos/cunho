"""The status endpoint with 100,000 bits waiting to show (review 5, N5-M3), as a mass revocation leaves
them: a poll between publications must stay a dictionary lookup, a publication must cost the bits that
came due and not the bits still hidden, and every hidden bit must show in the end. The latency budgets are
loose enough for a shared CI runner and far below what review 5 measured (79 ms per cached poll with 36,000
markers, 330 ms per rebuild)."""

from __future__ import annotations

import statistics
import time
import zlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.jose import b64u_decode, parse_jws
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import SqliteStore
from tests.engine.helpers import ISSUER, START, Clock, Pki, settings_kwargs

pytestmark = pytest.mark.slow
HIDDEN = 100_000
SIZE = 262_144


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    return Pki.create(tmp_path_factory.mktemp("pki"))


def _bits(token: str) -> bytes:
    return zlib.decompress(b64u_decode(parse_jws(token).payload["status_list"]["lst"]))


def test_status_with_a_hundred_thousand_hidden_bits(pki: Pki, tmp_path: Path) -> None:
    clock = Clock(START)  # the start of a publication
    settings = settings_kwargs(
        pki,
        store_path=tmp_path / "s.db",
        secret_key_file=tmp_path / "m.key",
        status_list_size=SIZE,
        status_revocation_jitter=3600,
        status_decoy_churn_per_day=0,
        status_decoy_ratio=0,
        status_rate_limit_per_minute=10**6,
    )
    issuer = Issuer(Settings(**settings), store=SqliteStore(tmp_path / "s.db", clock), clock=clock)
    issuer.status.allocate()
    with issuer.store.atomic():  # a mass revocation: every bit shows at its own moment within the hour
        for n in range(HIDDEN):
            issuer.store.put("status-slot", f"1:{n:08d}", 1, None)
            issuer.status._show_at("1", n, START + 1 + 3599 * n / HIDDEN)  # noqa: SLF001
    first = issuer.status_token("1")
    assert first is not None and not any(_bits(first)), "nothing shows before its moment"

    polls = []
    for _ in range(20_000):
        started = time.perf_counter()
        assert issuer.status_token("1") == first
        polls.append(time.perf_counter() - started)
    polls.sort()
    assert polls[int(len(polls) * 0.99)] < 0.001, f"p99 of a cached poll: {polls[int(len(polls) * 0.99)]:.6f} s"

    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        started = time.perf_counter()
        for _ in range(2000):
            assert client.get("/status/1").status_code == 200
        per_request = (time.perf_counter() - started) / 2000
        assert per_request < 0.01, f"{per_request * 1000:.1f} ms per HTTP poll between publications"

        rebuilds = []
        for minute in range(1, 61):
            clock.now = START + 60 * minute
            started = time.perf_counter()
            assert client.get("/status/1").status_code == 200
            rebuilds.append(time.perf_counter() - started)
            for _ in range(20):
                client.get("/status/1")
        assert max(rebuilds) < 0.5 and statistics.median(rebuilds) < 0.15, (max(rebuilds), statistics.median(rebuilds))
        bits = _bits(client.get("/status/1").text)
    assert all(bits[n // 8] >> (n % 8) & 1 for n in range(HIDDEN)), "every hidden bit showed within the hour"
    assert issuer.store.items("status-pending", "1:") == []
