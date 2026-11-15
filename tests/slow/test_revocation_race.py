"""A revocation racing the issuance of every configuration of an offer, across worker processes (review 5,
N5-M2). Three workers share one SQLite file: two issue the two configurations of one offer while the third
revokes the person, at a random moment, many times over. Signing is stretched at random in the workers, so
the revocation often lands between a configuration's claim and its commit.

Whatever the order, every credential a wallet received must be revoked once the revocation has answered,
and the revocation must report exactly those credentials.
"""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from cunho.jose import parse_jws
from tests.engine.helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, START, EcKey, Pki, Wallet, settings_kwargs
from tests.engine.test_review5_revocation import NATIONAL, two_configurations

from .workers import RemoteClient, Worker, request, start

pytestmark = pytest.mark.slow
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    return Pki.create(tmp_path_factory.mktemp("pki"))


@pytest.fixture
def workers(pki: Pki, tmp_path: Path) -> Iterator[tuple[list[Worker], Any]]:
    settings = settings_kwargs(
        pki,
        store_path=tmp_path / "s.db",
        secret_key_file=tmp_path / "m.key",
        audit_anchor_path=tmp_path / "audit.anchor",
        metadata_dir=two_configurations(tmp_path),
    )
    running, clock = start(tmp_path, settings, 3, START + 1234, slow_signing=0.02)
    try:
        yield running, clock
    finally:
        for worker in running:
            worker.stop()


def credential_request(wallet: Wallet, config: str) -> tuple[str, str, dict[str, Any]]:
    """The request `Wallet.issue` would send, built here so it can be sent to any worker at any moment."""
    assert wallet.token is not None
    nonce = wallet.c_nonce()
    proof = wallet.proof(EcKey.generate(), nonce)
    headers = [
        ("Authorization", f"DPoP {wallet.token}"),
        ("Content-Type", "application/json"),
        ("DPoP", wallet.dpop("POST", f"{ISSUER}/credential", access_token=wallet.token)),
    ]
    body = json.dumps({"credential_configuration_id": config, "proofs": {"jwt": [proof]}}).encode()
    return request("post", "/credential", content=body, headers=headers)


def slot(reply: Any) -> tuple[str, int]:
    credential = reply.json()["credentials"][0]["credential"]
    ref = parse_jws(credential.split("~")[0]).payload["status"]["status_list"]
    return ref["uri"].rsplit("/", 1)[1], ref["idx"]


def test_a_revocation_racing_both_configurations_never_leaves_a_valid_credential(
    workers: tuple[list[Worker], Any], pki: Pki
) -> None:
    running, clock = workers
    chooser = random.Random()
    wallet = Wallet(RemoteClient(running, lambda: chooser.randrange(3)), pki, clock)  # type: ignore[arg-type]
    outcomes: dict[str, int] = {}
    for _ in range(60):
        offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
        wallet.token = None
        wallet.get_token(offer)
        first, second = credential_request(wallet, PID_CONFIG), credential_request(wallet, NATIONAL)
        revocation = request(
            "post", "/admin/revocations", json={"subject_ref": offer["subject_ref"], "reason": "death"}
        )
        revocation[2]["headers"] = AUTH
        order = chooser.sample(range(3), 3)
        running[order[0]].send("http", first, chooser.random() * 0.01)
        running[order[1]].send("http", second, chooser.random() * 0.01)
        running[order[2]].send("http", revocation, chooser.random() * 0.03)
        replies = [running[order[n]].receive() for n in range(3)]
        issued = [reply for reply in replies[:2] if reply.status_code == 200]
        refused = [reply for reply in replies[:2] if reply.status_code != 200]
        assert all(reply.json()["error"] == "credential_request_denied" for reply in refused), refused
        assert replies[2].status_code == 200, replies[2].text
        assert replies[2].json()["revoked"] == len(issued), (replies[2].json(), len(issued))
        for reply in issued:
            assert running[chooser.randrange(3)].status(*slot(reply)) == 1, "a credential the wallet got stayed valid"
        key = f"{len(issued)} issued, offer cancelled: {replies[2].json().get('offer_cancelled', False)}"
        outcomes[key] = outcomes.get(key, 0) + 1
        clock.now += 1
    ok, detail = running[1].call("audit.verify")
    assert ok, detail
    assert len(outcomes) >= 2, f"the race went one way only: {outcomes}"
