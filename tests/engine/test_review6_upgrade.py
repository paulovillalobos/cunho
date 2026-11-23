"""Regression tests for the sixth M2 review (cunho-m2-review-6.md): upgrading a store written before the schema
version (N6-M2). The store is made by the code of 45ec9be, the tree the fifth review read, checked out into a
temporary git worktree and run in a process of its own."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import zlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho import schema
from cunho.app import create_app
from cunho.errors import ConfigError
from cunho.jose import b64u_decode, parse_jws
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import MemoryStore, SqliteStore

from .helpers import ADMIN_TOKEN, ISSUER, Clock, settings_kwargs

ROOT = Path(__file__).resolve().parents[2]
OLD = "45ec9be"
# What OLD_PHASE wrote when run by the 45ec9be code (old.json, the store, its keyring, anchor and test PKI).
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "store-45ec9be"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
SETTINGS = {"status_revocation_jitter": 3600, "status_decoy_churn_per_day": 0.05}

# Run by the 45ec9be code: three credentials, the first revoked two hours before the upgrade, so its bit shows,
# and the second just before it, so its bit is still hidden; then an offer, not redeemed yet at the upgrade.
OLD_PHASE = r"""
import json, sys, zlib
from pathlib import Path
from fastapi.testclient import TestClient
from cunho.app import create_app
from cunho.jose import b64u_decode, parse_jws
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import MemoryStore, SqliteStore
from tests.engine.helpers import ISSUER, START, Clock, Pki, Wallet, settings_kwargs

work = Path(sys.argv[1])
(work / "pki").mkdir()
pki = Pki.create(work / "pki")
clock = Clock(START)
kw = settings_kwargs(pki, store_path=work / "s.db", secret_key_file=work / "m.key",
                     audit_anchor_path=work / "audit.anchor", **json.loads(sys.argv[2]))
issuer = Issuer(Settings(**kw), clock=clock)
client = TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER)

def slot(response):
    payload = parse_jws(response.json()["credentials"][0]["credential"].split("~")[0]).payload
    reference = payload["status"]["status_list"]
    return reference["uri"].rsplit("/", 1)[1], reference["idx"]

out = {"credentials": []}
for _ in range(3):
    wallet = Wallet(client, pki, clock)
    offer = wallet.offer()
    wallet.get_token(offer)
    response = wallet.issue()
    assert response.status_code == 200, response.text
    out["credentials"].append({"subject_ref": offer["subject_ref"], "slot": slot(response)})
admin = Wallet(client, pki, clock)
for n, later in ((0, 2 * 3600), (1, 1)):  # a second: a jitter shorter than that is unlikely
    list_id, index = out["credentials"][n]["slot"]
    reply = admin.admin("revocations", {"list": list_id, "index": index, "reason": "compromise"})
    assert reply.json() == {"revoked": 1}, reply.text
    clock.now += later
issuer.maintenance(force=True)
out["waiting"] = Wallet(client, pki, clock).offer()["subject_ref"]
token = client.get("/status/1").text
out["published"] = list(zlib.decompress(b64u_decode(parse_jws(token).payload["status_list"]["lst"])))
out["now"] = clock()
out["hidden"] = {k.split(":")[1]: v for k, v in issuer.store.items("status-pending", "1:") if v > clock()}
out["revoked"] = sorted(int(k.split(":")[1]) for k, v in issuer.store.items("status-slot", "1:") if v == 1)
(work / "old.json").write_text(json.dumps(out))
"""


@pytest.fixture(scope="module")
def old_store(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A store, keyring, anchor and PKI written by the 45ec9be code, run from that commit's tree. The tree is
    read with `git archive` into a temporary directory, so nothing is written into the repository. The
    repository is found through CUNHO_SOURCE_REPO when the tests run on a copy (the mutation run). A checkout
    without that history (the public repository is one commit) uses FIXTURE instead: the files the same run
    wrote, kept as they came out."""
    repo = Path(os.environ.get("CUNHO_SOURCE_REPO", ROOT))
    known = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{OLD}^{{commit}}"], capture_output=True)
    if known.returncode != 0:
        # A checkout does not keep file modes, and cunho reads no key that others may read.
        copy = tmp_path_factory.mktemp("upgrade") / "work"
        shutil.copytree(FIXTURE, copy)
        for key in [copy / "m.key", *(copy / "pki").glob("*.key")]:
            key.chmod(0o600)
        return copy
    root = tmp_path_factory.mktemp("upgrade")
    tree, work = root / f"cunho-{OLD}", root / "work"
    tree.mkdir()
    work.mkdir()
    archive = subprocess.run(["git", "-C", str(repo), "archive", OLD], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(tree)], input=archive.stdout, check=True, capture_output=True)
    env = {**os.environ, "PYTHONPATH": f"{tree}/src:{tree}/probe:{tree}"}
    command = [sys.executable, "-c", OLD_PHASE, str(work), json.dumps(SETTINGS)]
    done = subprocess.run(command, cwd=tree, env=env, capture_output=True, text=True, timeout=600)
    assert done.returncode == 0, done.stderr[-3000:]
    return work


def _copy(old_store: Path, target: Path) -> tuple[Path, dict[str, Any]]:
    shutil.copytree(old_store, target)
    return target, json.loads((target / "old.json").read_text())


def _issuer(work: Path, when: float, **overrides: Any) -> Issuer:
    pki: Any = SimpleNamespace(root=work / "pki")
    kw = settings_kwargs(
        pki,
        store_path=work / "s.db",
        secret_key_file=work / "m.key",
        audit_anchor_path=work / "audit.anchor",
        **{**SETTINGS, **overrides},
    )
    return Issuer(Settings(**kw), clock=Clock(when))


def _published(client: TestClient) -> list[int]:
    token = client.get("/status/1").text
    return list(zlib.decompress(b64u_decode(parse_jws(token).payload["status_list"]["lst"])))


def _bits(revoked: list[int]) -> list[int]:
    out = [0] * (4096 // 8)
    for index in revoked:
        out[index // 8] |= 1 << (index % 8)
    return out


def test_n6_m2_an_upgrade_from_45ec9be_publishes_every_bit_it_showed(
    old_store: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """u1: the same store under 382505f published all zeros, revocations and decoys alike, and verify was valid."""
    work, old = _copy(old_store, tmp_path / "work")
    assert old["hidden"], "the old store holds bits still hidden at the upgrade"
    with caplog.at_level(logging.WARNING, "cunho"):
        issuer = _issuer(work, old["now"])
    assert "it is upgraded to 2" in caplog.text and issuer.store.get("meta", "schema") == schema.SCHEMA
    clock: Any = issuer.clock
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        assert _published(client) == old["published"], "the same bits as the old code showed at that moment"
        first, second = (c["slot"][1] for c in old["credentials"][:2])
        assert _bits([first])[first // 8] & old["published"][first // 8]
        assert not old["published"][second // 8] >> (second % 8) & 1, "the second revocation is still hidden"
        clock.now = max(old["hidden"].values()) + 61  # past every moment the old code laid down
        assert _published(client) == _bits(old["revoked"]), "every revoked slot shows, decoys included"
        assert issuer.audit.verify()[0]
    assert issuer.status.size_of("1") == 4096
    assert not schema.upgrade(issuer.store, issuer.settings, clock, issuer._handed_out, []), "only once"  # noqa: SLF001


def test_n6_m2_offers_from_before_the_upgrade_can_still_be_ended(old_store: Path, tmp_path: Path) -> None:
    """References 45ec9be handed out carry no keyed tag; the upgrade records the ones the store names."""
    work, old = _copy(old_store, tmp_path / "work")
    issuer = _issuer(work, old["now"])
    third = old["credentials"][2]
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        reply = client.post(
            "/admin/revocations", json={"subject_ref": third["subject_ref"], "reason": "death"}, headers=AUTH
        )
        assert reply.json() == {"revoked": 1}, reply.text
        reply = client.post(f"/admin/offers/{old['waiting']}/cancel", headers=AUTH)
        assert reply.json() == {"cancelled": True}, reply.text
        reply = client.post(f"/admin/subjects/{old['credentials'][0]['subject_ref']}/erase", headers=AUTH)
        assert reply.status_code == 204, reply.text
        forged = old["waiting"][:-2] + ("AA" if not old["waiting"].endswith("AA") else "BB")
        assert client.post(f"/admin/subjects/{forged}/erase", headers=AUTH).status_code == 400
        assert issuer.audit.verify()[0]


def test_n6_m2_an_upgrade_that_cannot_know_the_size_refuses(old_store: Path, tmp_path: Path) -> None:
    work, old = _copy(old_store, tmp_path / "work")
    with pytest.raises(ConfigError, match="start the upgrade with the list size the earlier version ran with"):
        _issuer(work, old["now"], status_list_size=1024)
    issuer = _issuer(work, old["now"])  # nothing was changed by the refused start
    assert issuer.status.size_of("1") == 4096
    issuer.store.put("meta", "schema", 3, None)
    with pytest.raises(ConfigError, match="schema version 3"):
        _issuer(work, old["now"])


def test_n6_m2_missing_status_state_fails_loudly(
    old_store: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """_unpack answered all zeros for a missing or wrong-sized state; now the list is not served at all."""
    work, old = _copy(old_store, tmp_path / "work")
    issuer = _issuer(work, old["now"])
    with TestClient(
        create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        visible = issuer.store.get("status-visible", "1")
        for broken in (None, "not base64url!", "eJwDAAAAAAE"):
            if broken is None:
                issuer.store.delete("status-visible", "1")
            else:
                issuer.store.put("status-visible", "1", broken, None)
            issuer.clock.now += 60  # type: ignore[attr-defined]
            with caplog.at_level(logging.ERROR, "cunho.security"):
                assert client.get("/status/1").status_code == 500
            assert "has no stored published bits of its size" in caplog.text
        issuer.store.put("status-visible", "1", visible, None)
        meta: Any = issuer.store.get("status-meta", "list:1")
        issuer.store.put("status-meta", "list:1", {"opened": meta["opened"]}, None)
        again = _issuer(work, old["now"] + 120)
        assert again.store.get("meta", "schema") == 2, "a stored version is never upgraded again"
        with pytest.raises(Exception, match="status list 1 has no stored size"):
            again.status.token("1")


def test_n6_m2_a_store_from_382505f_keeps_its_sizes_and_bits(make_issuer: Any, tmp_path: Path, clock: Clock) -> None:
    """382505f stored each list's size and its published bits, but no schema version: the upgrade keeps the
    size whatever the setting says now, and rebuilds the same bits."""
    store = SqliteStore(tmp_path / "s.db", clock)
    keys = {"secret_key_file": tmp_path / "m.key"}
    issuer = make_issuer(store=store, status_list_size=8192, status_revocation_jitter=3600, **keys)
    refs = [issuer.status.allocate() for _ in range(3)]
    issuer.status.revoke(refs[0])
    clock.now += 3 * 3600
    issuer.status.revoke(refs[1])  # still hidden at the upgrade
    before = issuer.status.encoded("1")
    issuer.store.delete("meta", "schema")
    upgraded = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), status_list_size=4096, **keys)
    assert upgraded.status.size_of("1") == 8192 and upgraded.status.encoded("1") == before
    assert upgraded.store.items("status-pending", "1:")
    fresh = MemoryStore(clock)
    assert not schema.upgrade(fresh, upgraded.settings, clock, lambda _: True, [])
    assert fresh.get("meta", "schema") == schema.SCHEMA
