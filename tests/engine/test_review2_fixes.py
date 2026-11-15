"""Regression tests for the second independent M2 review (finding ids from cunho-m2-review-2.md)."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import random
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

import cunho.status as status_module
from cunho.app import RateLimiter, client_bucket, create_app, safe_text
from cunho.audit import Anchor, AuditError, AuditLog
from cunho.errors import ConfigError
from cunho.jose import JoseError, b64u, b64u_decode, b64u_json, parse_jws, sha256_b64u, validate_path
from cunho.keyring import Keyring
from cunho.oauth import seal
from cunho.service import Issuer, Signers
from cunho.settings import DEFAULT_METADATA_DIR, Settings
from cunho.signer import FileSigner, x5c_chain
from cunho.status import StatusRef
from cunho.store import MemoryStore, SqliteStore
from eudi_probe.jose import jws

from .helpers import (
    ADMIN_TOKEN,
    ISSUER,
    KA_POLICY,
    PID_CONFIG,
    PID_SUBJECT,
    PRE_AUTH,
    SLOW_IS_FINE,
    START,
    Clock,
    EcKey,
    Pki,
    Seeded,
    Wallet,
    access_signer,
    certificate,
    der_b64,
    disclosures,
    mdoc_signer,
    production_kwargs,
    settings_kwargs,
)
from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def sqlite_issuer(make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock) -> Issuer:
    """An issuer on SQLite; its anchor file sits next to the database (development default)."""
    return make_issuer(store=SqliteStore(tmp_path / "s.db", clock))


@pytest.fixture
def app_client(sqlite_issuer: Issuer) -> Iterator[TestClient]:
    app = create_app(issuer=sqlite_issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as client:
        yield client


def _db(issuer: Issuer) -> sqlite3.Connection:
    assert isinstance(issuer.store, SqliteStore)
    return sqlite3.connect(issuer.store.path, isolation_level=None)


def _events(issuer: Issuer, count: int, wallet: Wallet) -> None:
    for _ in range(count):
        wallet.offer()


# N-H1: truncation and deletion of the audit log ---------------------------------------------------


def test_n_h1_wiping_the_log_is_detected(sqlite_issuer: Issuer, app_client: TestClient, pki: Pki, clock: Clock) -> None:
    """q2 variant 1: copy the head into the checkpoint and delete every entry."""
    wallet = Wallet(app_client, pki, clock)
    _events(sqlite_issuer, 3, wallet)
    assert sqlite_issuer.audit.verify()[0]
    db = _db(sqlite_issuer)
    head = db.execute("select value from kv where ns='audit-meta' and key='head'").fetchone()[0]
    db.execute("insert or replace into kv values ('audit-meta','checkpoint',?,NULL)", (head,))
    db.execute("delete from kv where ns='audit'")
    assert sqlite_issuer.audit.verify() == (False, "audit checkpoint was altered"), "a head tag is no checkpoint"
    db.execute("delete from kv where ns in ('audit', 'audit-meta')")
    ok, detail = sqlite_issuer.audit.verify()
    assert not ok and "behind the anchor" in detail
    response = wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT})
    assert response.status_code == 500, "nothing is logged on top of a store that fell behind its anchor"


def test_n_h1_truncation_with_an_old_head_is_detected(
    sqlite_issuer: Issuer, app_client: TestClient, pki: Pki, clock: Clock
) -> None:
    """q2 variant 2: keep an old head, log five more events, delete them and restore the old head."""
    wallet = Wallet(app_client, pki, clock)
    _events(sqlite_issuer, 2, wallet)
    db = _db(sqlite_issuer)
    old_head = db.execute("select value from kv where ns='audit-meta' and key='head'").fetchone()[0]
    _events(sqlite_issuer, 5, wallet)
    db.execute("delete from kv where ns='audit' and key > '000000000002'")
    db.execute("update kv set value=? where ns='audit-meta' and key='head'", (old_head,))
    ok, detail = sqlite_issuer.audit.verify()
    assert not ok and detail.startswith("the store (head 2) is behind the anchor")
    verified = app_client.get("/admin/audit/verify", headers=AUTH).json()
    assert verified["valid"] is False


def test_n_h1_anchor_lines_are_chained_and_strictly_increasing(sqlite_issuer: Issuer, tmp_path: Path) -> None:
    anchor = sqlite_issuer.audit.anchor
    assert anchor is not None and anchor.path is not None
    for n in range(4):
        sqlite_issuer.audit.append("event", "admin", n=n)
    lines = anchor.path.read_bytes().splitlines(keepends=True)
    assert [json.loads(line)["seq"] for line in lines] == [0, 1, 2, 3, 4], "a genesis line, then one per entry"
    assert sqlite_issuer.audit.verify()[0]
    anchor.path.write_bytes(b"".join(lines[:2] + lines[3:]))
    assert sqlite_issuer.audit.verify() == (False, "anchor lines were removed or reordered")
    forged = {**json.loads(lines[3]), "seq": 9}
    anchor.path.write_bytes(b"".join(lines) + json.dumps(forged).encode() + b"\n")
    ok, detail = sqlite_issuer.audit.verify()  # bytes no line declares: damage, never a valid anchor
    assert not ok and detail.startswith("the anchor file ends in 257 bytes after its last line"), detail
    anchor.path.write_bytes(b"".join(lines[:3]) + json.dumps(forged).encode() + b"\n" + b"".join(lines[3:]))
    assert not sqlite_issuer.audit.verify()[0]
    with pytest.raises(AuditError, match="the anchor file holds bytes at offset 744 that no anchor line declares"):
        list(anchor.lines())  # bytes between two lines must be declared


def test_n_h1_checkpoint_must_respect_the_retention_period(issuer: Issuer, clock: Clock) -> None:
    """A checkpoint binds the pruned entry's time; pruning entries younger than the retention is refused."""
    for n in range(3):
        issuer.audit.append("event", "admin", n=n)
    clock.now += 10
    issuer.audit.prune_before(clock())  # pruning with the keyring, but inside the retention period
    ok, detail = issuer.audit.verify()
    assert not ok and "younger than the retention period" in detail
    stored: dict[str, Any] = dict(issuer.store.get("audit-meta", "checkpoint") or {})
    issuer.store.put("audit-meta", "checkpoint", {**stored, "time": stored["time"] - 3650 * 86_400 - 1}, None)
    assert issuer.audit.verify() == (False, "audit checkpoint was altered"), "the time is under the MAC"


def test_n_h1_store_ahead_of_the_anchor_is_caught_up(issuer: Issuer, monkeypatch: pytest.MonkeyPatch) -> None:
    """A crash between the commit and the anchor write leaves the store ahead; the next write repairs it.

    The committed action stands: the failed anchor write is logged, not raised (review 4, N4-M4).
    """
    anchor = issuer.audit.anchor
    assert anchor is not None
    issuer.audit.append("first", "admin")
    real_write = anchor.write
    monkeypatch.setattr(anchor, "write", lambda marks: (_ for _ in ()).throw(OSError("crash")) if marks else 0)
    assert issuer.audit.append("second", "admin")["seq"] == 2
    ok, detail = issuer.audit.verify()
    assert not ok and detail.startswith("the 1 newest entries are not anchored yet"), detail  # review 6, N6-H1
    monkeypatch.setattr(anchor, "write", real_write)
    issuer.audit.append("third", "admin")
    assert [line["seq"] for line in anchor.lines()] == [0, 1, 2, 3]
    assert issuer.audit.verify() == (True, "3 entries verified; 4 anchor lines")


def test_n_h1_signed_head_pulled_by_the_operator(
    sqlite_issuer: Issuer, app_client: TestClient, pki: Pki, clock: Clock
) -> None:
    """The operator pulls a signed head and later verifies the store against it."""
    wallet = Wallet(app_client, pki, clock)
    _events(sqlite_issuer, 3, wallet)
    signed = app_client.get("/admin/audit/head", headers=AUTH).text
    assert parse_jws(signed).payload["seq"] == 3
    check = app_client.post("/admin/audit/verify", headers=AUTH, json={"signed_head": signed}).json()
    assert check["valid"] is True, check
    forged = signed[:-4] + ("AAAA" if not signed.endswith("AAAA") else "BBBB")
    assert app_client.post("/admin/audit/verify", headers=AUTH, json={"signed_head": forged}).json()["valid"] is False
    other = AuditLog(MemoryStore(clock), Keyring.ephemeral(), clock)
    for _ in range(3):
        other.append("x", "y")
    assert sqlite_issuer.audit_verify(other.signed_head(sqlite_issuer.audit_signer, ISSUER))[0] is False


def test_n_h1_anchor_orders_appends_from_several_workers(tmp_path: Path) -> None:
    """Two workers (separate connections and file handles) append at once; the anchor stays in order."""
    keyring, path = Keyring.ephemeral(), tmp_path / "s.db"
    anchor_path = tmp_path / "audit.anchor"
    logs = [
        AuditLog(SqliteStore(path), keyring, anchor=Anchor(anchor_path, keyring), create_anchor=True) for _ in range(2)
    ]

    def work(log: AuditLog) -> None:
        for n in range(40):
            log.append("event", "admin", n=n)

    threads = [threading.Thread(target=work, args=(log,)) for log in logs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    seqs = [json.loads(line)["seq"] for line in anchor_path.read_bytes().splitlines()]
    assert seqs == list(range(81))
    assert logs[0].verify() == (True, "80 entries verified; 81 anchor lines")


def test_n_h1_production_needs_an_anchor(pki: Pki, tmp_path: Path) -> None:
    kwargs = production_kwargs(pki, tmp_path)
    with pytest.raises(ConfigError, match="audit_anchor_path"):
        Settings(**{**kwargs, "audit_anchor_path": None})
    with pytest.raises(ConfigError, match="its own file"):
        Settings(**{**kwargs, "audit_anchor_path": kwargs["store_path"]})


# N-H2: failed operator logins ---------------------------------------------------------------------


def test_n_h2_failed_logins_never_write_text_into_the_audit_log(
    issuer: Issuer, caplog: pytest.LogCaptureFixture
) -> None:
    """q3: anonymous requests leave no per-request entry and no chosen text in the chain."""
    app = create_app(issuer=issuer, background_maintenance=False)
    client = TestClient(app, base_url=ISSUER, client=("203.0.113.9", 1234))
    name = "Maria%20Silva%20born%201990-05-17%20NIF%20123456789"
    with caplog.at_level(logging.WARNING, logger="cunho.security"):
        for _ in range(50):
            assert client.post(f"/admin/subjects/{name}/erase").status_code == 401
        client.post("/admin/offers", headers={"Authorization": "Bearer " + "z" * 40}, json={})
    assert issuer.audit.entries() == [], "a failed login writes no audit entry of its own"
    assert all("Maria" not in r.getMessage() for r in caplog.records)
    assert "route=/admin/subjects/{subject_ref}/erase client=203.0.113.0/24" in caplog.records[0].getMessage()
    issuer.maintenance(force=True)
    issuer.maintenance(force=True)
    entries = issuer.audit.entries()
    assert len(entries) == 1, "one aggregate per maintenance run, none when nothing failed"
    assert entries[0]["event"] == "admin.auth_failures"
    assert entries[0]["data"]["count"] == 51 and entries[0]["data"]["with_token"] == 1
    assert entries[0]["data"]["routes"] == {"/admin/offers": 1, "/admin/subjects/{subject_ref}/erase": 50}
    assert "Maria" not in json.dumps(entries)


def test_n_h2_client_buckets() -> None:
    assert client_bucket("203.0.113.9", v4_prefix=24, v6_prefix=48) == "203.0.113.0/24"
    assert client_bucket("2001:db8:1:2:3::9", v4_prefix=24, v6_prefix=48) == "2001:db8:1::/48"
    assert client_bucket("::ffff:198.51.100.7") == "198.51.100.7/32"
    assert client_bucket("testclient") == "unknown" and client_bucket(None) == "unknown"


# N-M1: client text in WWW-Authenticate ------------------------------------------------------------


def _raw_jws(header: dict[str, Any], payload_text: str, key: EcKey) -> str:
    signing_input = f"{b64u_json(header)}.{b64u(payload_text.encode())}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


@pytest.mark.covers("DPOP.SIGNATURE")
def test_n_m1_duplicate_unicode_members_get_a_clean_401(wallet: Wallet) -> None:
    """q7: a repeated member named in any script used to reach the header and end in a 500."""
    wallet.get_token()
    assert wallet.token is not None
    rng = random.Random(1569)
    names = ["€", "ā", "é", " ", '"', "\\", " ", "퟿", "😀"]
    names += ["".join(chr(rng.randrange(0x20, 0x2FFFF)) for _ in range(rng.randrange(1, 6))) for _ in range(60)]
    for name in names:
        if 0xD800 <= ord(name[0]) <= 0xDFFF:
            continue
        member = json.dumps(name)
        payload = (
            f'{{"jti":"{uuid.uuid4().hex}","htm":"POST","htu":"{ISSUER}/credential","iat":{int(wallet.clock())},'
            f'"ath":"{sha256_b64u(wallet.token)}",{member}:1,{member}:2}}'
        )
        proof = _raw_jws(
            {"typ": "dpop+jwt", "alg": "ES256", "jwk": wallet.dpop_key.public_jwk()}, payload, wallet.dpop_key
        )
        response = wallet.credential_request({"credential_configuration_id": PID_CONFIG}, dpop=proof)
        assert response.status_code == 401, (name, response.text)
        challenge = response.headers["www-authenticate"]
        assert challenge.isascii(), name
        assert response.json()["error_description"].endswith("duplicate member name"), "client text is never echoed"


def test_n_m1_error_text_is_header_safe() -> None:
    rng = random.Random(6750)
    for _ in range(2000):
        text = "".join(chr(rng.randrange(0, 0x10FFFF)) for _ in range(rng.randrange(0, 40)))
        safe = safe_text(text)
        assert all(c == "!" or "\x23" <= c <= "\x5b" or "\x5d" <= c <= "\x7e" or c == " " for c in safe), text
        safe.encode("latin-1")


def test_n_m1_hypothesis_over_header_reaching_errors(wallet: Wallet) -> None:
    """Property test with Hypothesis when it is installed (CI installs it)."""
    hypothesis = pytest.importorskip("hypothesis")
    strategies = pytest.importorskip("hypothesis.strategies")
    wallet.get_token()
    assert wallet.token is not None
    token = wallet.token

    @hypothesis.settings(max_examples=150, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(strategies.text(min_size=1, max_size=12), strategies.text(max_size=40))
    def check(name: str, value: str) -> None:
        member = json.dumps(name)
        payload = (
            f'{{"jti":"{uuid.uuid4().hex}","htm":"POST","htu":"{ISSUER}/credential","iat":{int(wallet.clock())},'
            f'"ath":"{sha256_b64u(token)}",{member}:{json.dumps(value)},{member}:2}}'
        )
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": wallet.dpop_key.public_jwk(), "x": value}
        proof = _raw_jws(header, payload, wallet.dpop_key)
        response = wallet.credential_request({"credential_configuration_id": PID_CONFIG}, dpop=proof)
        assert response.status_code == 401
        assert response.headers["www-authenticate"].isascii()

    check()


# N-M2: decoy timing -------------------------------------------------------------------------------


def _bits(client: TestClient, list_id: str) -> set[int]:
    token = client.get(f"/status/{list_id}").text
    raw = zlib.decompress(b64u_decode(parse_jws(token).payload["status_list"]["lst"]))
    return {i for i in range(len(raw) * 8) if raw[i // 8] >> (i % 8) & 1}


def test_n_m2_decoys_arrive_one_at_a_time_at_random_moments(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """q5: poll the list every minute for six hours with maintenance running hourly, as in production."""
    monkeypatch.setattr(status_module, "secrets", Seeded(1))
    issuer = make_issuer(status_list_size=131_072)
    refs = [issuer.status.allocate() for _ in range(50)]
    client = TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER)
    issuer.maintenance()
    previous, new_per_minute = _bits(client, "1"), {}
    revoked_at = {47: refs[3], 130: refs[9], 301: refs[20]}
    for minute in range(1, 361):
        clock.now += 60
        if minute in revoked_at:
            ref = revoked_at[minute]
            body = {"list": ref.list_id, "index": ref.index, "reason": "user_request"}
            assert client.post("/admin/revocations", headers=AUTH, json=body).json() == {"revoked": 1}
        issuer.maintenance()
        current = _bits(client, "1")
        if current - previous:
            new_per_minute[minute] = len(current - previous)
        previous = current
    decoy_minutes = {m: n for m, n in new_per_minute.items() if m not in revoked_at}
    assert len(decoy_minutes) >= 10, new_per_minute
    assert max(new_per_minute.values()) <= 3, "no bursts"
    on_the_hour = sum(n for m, n in decoy_minutes.items() if m % 60 == 0)
    assert on_the_hour * 4 < sum(decoy_minutes.values()), "decoys are not tied to the maintenance tick"
    lone = [m for m, n in decoy_minutes.items() if n == 1]
    assert len(lone) >= 5, "a lone new bit is often a decoy, so it does not single out a revocation"


def test_n_m2_workers_share_one_schedule(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    store = MemoryStore(clock)
    first, second = (make_issuer(store=store, status_list_size=131_072, maintenance_interval=86_400) for _ in "12")
    first.status.allocate()  # opening the list lays down its schedule (review 3, N3-M3)
    assert len(store.items("status-pending")) > 0
    assert first.status.churn() == 0 and second.status.churn() == 0, "a second worker does not add its own decoys"
    clock.now += 86_400
    assert first.status.churn() > 0 and second.status.churn() == 0, "one worker extends it, the other sees that"


# N-M3: PID without key binding --------------------------------------------------------------------


def _metadata_without_binding(tmp_path: Path, vct: str | None = None) -> Path:
    target = tmp_path / "md"
    shutil.copytree(DEFAULT_METADATA_DIR, target)
    path = target / "credentials_supported" / "pid_jwt_vc.json"
    data = json.loads(path.read_text())
    config = data[PID_CONFIG]
    config.pop("cryptographic_binding_methods_supported")
    config.pop("proof_types_supported")
    if vct is not None:
        config["vct"] = vct
    path.write_text(json.dumps(data))
    return target


def test_n_m3_unbound_pid_configuration_refuses_to_start(make_issuer: Callable[..., Issuer], tmp_path: Path) -> None:
    """q6: a PID configuration without key binding, by the PID vct or a national one, never starts."""
    with pytest.raises(ConfigError, match="bound to a key in the wallet's WSCD"):
        make_issuer(metadata_dir=_metadata_without_binding(tmp_path))
    with pytest.raises(ConfigError, match="bound to a key in the wallet's WSCD"):
        make_issuer(metadata_dir=_metadata_without_binding(tmp_path / "pt", "urn:eudi:pid:pt:1"))


@pytest.mark.covers("BIND.DEVICE_BOUND")
def test_n_m3_unbound_pid_is_refused_at_issuance(wallet: Wallet, issuer: Issuer) -> None:
    """Defence in depth: a PID configuration that lost its proof types after startup issues nothing."""
    config = issuer.configs.all[PID_CONFIG]
    config.pop("proof_types_supported")
    wallet.get_token()
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG})
    assert response.status_code == 400 and response.json()["error"] == "credential_request_denied"


# N-M4: revocation and its audit entry -------------------------------------------------------------


def test_n_m4_revocation_is_not_applied_without_its_entry(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """q13: when the log cannot be written, the bit stays as it was and a retry logs the revocation."""
    offer = wallet.offer()
    wallet.get_token(offer)
    status = disclosures(wallet.issue().json()["credentials"][0]["credential"])[1]["status"]["status_list"]
    ref = StatusRef(status["uri"].rsplit("/", 1)[1], status["idx"])
    real = issuer.audit.append

    def failing(event: str, actor: str, **data: Any) -> Any:
        if event in ("credential.revoked", "subject.erased"):
            raise AuditError("database is locked")
        return real(event, actor, **data)

    monkeypatch.setattr(issuer.audit, "append", failing)
    response = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    assert response.status_code == 500 and response.json()["error"] == "server_error"
    assert issuer.status.value(ref) == 0, "not revoked without its audit entry"
    other = wallet.offer()
    erased = wallet.client.post(f"/admin/subjects/{other['subject_ref']}/erase", headers=AUTH)
    assert erased.status_code == 500 and issuer.store.get("vault", other["subject_ref"]) is not None
    monkeypatch.setattr(issuer.audit, "append", real)
    retry = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    assert retry.json() == {"revoked": 1} and issuer.status.value(ref) == 1
    last = issuer.audit.entries()[-1]
    assert (
        last["event"] == "credential.revoked" and last["data"]["count"] == 1 and len(last["data"]["status_refs"]) == 1
    )


def test_n_m4_offer_is_not_created_without_its_entry(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(issuer.audit, "append", lambda *a, **k: (_ for _ in ()).throw(AuditError("full")))
    body = {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT}
    assert wallet.admin("offers", body).status_code == 500
    assert issuer.store.items("offer") == [] and issuer.store.items("vault") == []


# N-M5: rate limiter -------------------------------------------------------------------------------


def test_n_m5_a_full_limiter_evicts_instead_of_refusing() -> None:
    """q4: 100,000 addresses in a minute no longer lock out a new wallet."""
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0], max_clients=1000)
    for i in range(5000):
        limiter.allow(client_bucket(f"2001:db8:{i:x}::1"))
    now[0] = 30.0
    assert len(limiter) == 1000
    assert limiter.allow(client_bucket("198.51.100.7")) is True
    assert limiter.allow(client_bucket("198.51.100.7")) is True
    assert limiter.allow(client_bucket("198.51.100.7")) is False, "the limit itself still holds"


def test_n_m5_ipv6_is_limited_per_64(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer(rate_limit_per_minute=3)
    app = create_app(issuer=issuer, background_maintenance=False)
    statuses = [
        TestClient(app, base_url=ISSUER, client=(f"2001:db8:1:2::{i:x}", 1)).post("/nonce").status_code
        for i in range(5)
    ]
    assert statuses == [200, 200, 200, 429, 429], "one host holds a whole /64"
    other = TestClient(app, base_url=ISSUER, client=("2001:db8:1:3::1", 1))
    assert other.post("/nonce").status_code == 200
    assert other.post("/token").status_code == 400, "each route group has its own table"


# N-M7: maintenance in bounded batches, off the request path --------------------------------------


def test_n_m7_prune_and_verify_read_in_bounded_pages(tmp_path: Path, clock: Clock) -> None:
    store = SqliteStore(tmp_path / "a.db", clock)
    log = AuditLog(store, Keyring.ephemeral(), clock, retention=86_400)
    for n in range(1200):
        log.append("event", "admin", n=n)
    clock.now += 2 * 86_400
    log.append("new", "admin")
    pages: list[int] = []
    real_scan = store.scan

    def scan(ns: str, after: str = "", limit: int = 500, until: str | None = None) -> list[tuple[str, Any]]:
        page = real_scan(ns, after, limit, until)
        pages.append(len(page))
        return page

    store.scan = scan  # type: ignore[method-assign]
    store.items = lambda *a, **k: pytest.fail("the whole log is never loaded")  # type: ignore[method-assign]
    assert log.prune_before(clock() - 86_400) == 1200
    assert max(pages) <= 500 and len(pages) >= 3
    pages.clear()
    assert log.verify() == (
        True,
        "1 entries verified; no anchor configured, so removal of the newest entries is not detectable",
    )
    assert max(pages) <= 500


def test_n_m7_maintenance_never_runs_inside_a_request(issuer: Issuer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(issuer, "maintenance", lambda **_: pytest.fail("maintenance ran in a request"))
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        assert client.post("/nonce").status_code == 200
        assert client.get("/.well-known/openid-credential-issuer").status_code == 200


def test_n_m7_background_maintenance_runs(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer(maintenance_interval=1)
    with TestClient(create_app(issuer=issuer), base_url=ISSUER):
        deadline = time.monotonic() + 5
        while issuer._last_maintenance == 0 and time.monotonic() < deadline:  # noqa: SLF001
            time.sleep(0.05)
    assert issuer._last_maintenance > 0  # noqa: SLF001


# Low findings ----------------------------------------------------------------------------------------


def test_n_l1_x5u_serves_the_signer_certificate(wallet: Wallet, pki: Pki) -> None:
    response = wallet.client.get("/certs/signer.pem")
    assert response.status_code == 200 and response.headers["content-type"] == "application/pem-certificate-chain"
    served = x509.load_pem_x509_certificates(response.content)
    header = disclosures(wallet.issue().json()["credentials"][0]["credential"])[0]
    assert header["x5u"] == f"{ISSUER}/certs/signer.pem"
    der = [c.public_bytes(serialization.Encoding.DER) for c in served]
    assert header["x5t#S256"] == b64u(hashlib.sha256(der[0]).digest())
    assert [base64.b64encode(d).decode() for d in der] == header["x5c"]
    with pytest.raises(ConfigError, match="only at"):
        Settings(**settings_kwargs(pki, signer_certificate_url=f"{ISSUER}/elsewhere.pem"))


@pytest.mark.covers("DPOP.SIGNATURE", "VCI.F4.PROOF_SIGNATURE")
def test_n_l2_crit_is_refused(wallet: Wallet) -> None:
    """q11: RFC 7515 §4.1.11, a crit extension cunho does not understand is refused."""
    offer = wallet.offer()
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    key = wallet.dpop_key
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk(), "crit": ["urn:x"], "urn:x": True}
    claims = {"jti": uuid.uuid4().hex, "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock())}
    response = wallet.token_request(code, dpop=jws(header, claims, key))
    assert response.status_code == 400 and response.json()["error"] == "invalid_dpop_proof"
    wallet.get_token()
    holder = EcKey.generate()
    proof_header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "jwk": holder.public_jwk(),
        "key_attestation": wallet.key_attestation([holder]),
        "crit": ["b64"],
        "b64": False,
    }
    proof = jws(proof_header, {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce()}, holder)
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert response.status_code == 400 and response.json()["error"] == "invalid_proof"
    with pytest.raises(JoseError, match="crit"):
        parse_jws(jws({"alg": "ES256", "crit": []}, {}, key))


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(
    cn: str,
    key: Any,
    issuer: tuple[x509.Certificate, Any] | None = None,
    *,
    ca: bool = False,
    eku: list[x509.ObjectIdentifier] | None = None,
    policy: str | None = None,
    digest: hashes.SHA224 | hashes.SHA256 | None = None,
) -> x509.Certificate:
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer[0].subject if issuer else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if policy:
        builder = builder.add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(policy), None)]), critical=False
        )
    return builder.sign(issuer[1] if issuer else key, digest or hashes.SHA256())


def test_n_l3_key_attestation_signer_profile_and_key_strength() -> None:
    """q10 and H-4: a positive signer profile, and agreed key sizes everywhere in the path."""
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert("WP Root", root_key, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    refused = {
        "any purpose": [
            _cert(
                "a",
                leaf_key,
                (root, root_key),
                eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE],
            )
        ],
        "code signing": [_cert("c", leaf_key, (root, root_key), eku=[ExtendedKeyUsageOID.CODE_SIGNING])],
        "ocsp signing": [_cert("o", leaf_key, (root, root_key), eku=[ExtendedKeyUsageOID.OCSP_SIGNING])],
        "sha-224": [_cert("s", leaf_key, (root, root_key), digest=hashes.SHA224())],
    }
    weak_key = rsa.generate_private_key(65537, 1024)
    weak = _cert("RSA-1024 intermediate", weak_key, (root, root_key), ca=True)
    refused["rsa-1024 intermediate"] = [_cert("l", leaf_key, (weak, weak_key)), weak]
    for label, chain in refused.items():
        with pytest.raises(JoseError):
            validate_path(chain, [root], now)
        assert label
    custom = x509.ObjectIdentifier("1.3.6.1.4.1.99999.2.1")
    validate_path([_cert("k", leaf_key, (root, root_key), eku=[custom])], [root], now)
    with pytest.raises(JoseError, match="policy"):
        validate_path([_cert("k", leaf_key, (root, root_key))], [root], now, frozenset({KA_POLICY}))
    validate_path([_cert("k", leaf_key, (root, root_key), policy=KA_POLICY)], [root], now, frozenset({KA_POLICY}))


def test_n_l4_prefix_lookups_are_case_sensitive(tmp_path: Path) -> None:
    """q14: SQLite LIKE folded ASCII case, so the two stores disagreed."""
    for store in (SqliteStore(tmp_path / "s.db"), MemoryStore()):
        store.put("issued", "sub_AbCdEf:1:00000001", 1, None)
        store.put("issued", "sub_abcdef:1:00000002", 2, None)
        store.put("issued", "sub_abcdeg:1:00000003", 3, None)
        assert store.items("issued", "sub_abcdef:") == [("sub_abcdef:1:00000002", 2)], type(store)


def test_n_l5_workers_starting_together_on_a_new_store(tmp_path: Path) -> None:
    """Switching a new file to WAL raced between workers and killed one with 'database is locked'."""
    script = (
        "import sys, time; sys.path[:0] = [sys.argv[1]]; from pathlib import Path;"
        "from cunho.store import SqliteStore; time.sleep(max(0.0, float(sys.argv[3]) - time.time()));"
        "SqliteStore(Path(sys.argv[2])).put('ns', sys.argv[4], 1, None)"
    )
    for attempt in range(3):
        path = tmp_path / f"cold{attempt}.db"
        start = str(time.time() + 2.0)
        procs = [
            subprocess.Popen([sys.executable, "-c", script, str(ROOT / "src"), str(path), start, str(i)])
            for i in range(6)
        ]
        assert [p.wait(30) for p in procs] == [0] * 6
        assert len(SqliteStore(path).items("ns")) == 6


def test_n_l6_configuration_knobs_are_checked(pki: Pki) -> None:
    for change in (
        {"timestamp_granularity": 0},
        {"timestamp_granularity": 7},
        {"offer_ttl": 0},
        {"dpop_iat_window": 100_000},
        {"status_list_fill_limit": 1.5},
        {"status_decoy_ratio": 0.4},
        {"status_decoy_churn_per_day": -1},
        {"status_token_lifetime": 10, "status_token_ttl": 60},
        {"maintenance_interval": 0},
        {"credential_validity_days": True},
    ):
        with pytest.raises(ConfigError):
            Settings(**settings_kwargs(pki, **change))


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT")
def test_n_l6_erase_takes_only_issued_references(wallet: Wallet, issuer: Issuer) -> None:
    response = wallet.client.post("/admin/subjects/Maria%20Silva/erase", headers=AUTH)
    assert response.status_code == 400
    assert issuer.audit.entries() == []


def test_n_l8_production_mode_starts_with_an_injected_signer(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    """The production guards run end to end with the signer interface an HSM signer will fill in M4."""
    key = tmp_path / "m.key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    settings = Settings(**production_kwargs(pki, tmp_path))
    anchors = pki.root / "issuer-root.pem"
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    status = FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors)
    lists = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    served = ServedStatus({KA_STATUS_LIST: lists.token(KA_STATUS_LIST)})
    issuer = Issuer(
        settings, signers=Signers(signer, status, access_signer(pki), mdoc_signer(pki)), clock=clock, fetcher=served
    )
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        wallet.get_token(wallet.offer(configs=[PID_CONFIG, "eu.europa.ec.eudi.pid_mdoc"]))  # both formats (PID_02)
        assert wallet.issue().status_code == 200
    assert (tmp_path / "audit.anchor").exists() and issuer.audit.verify()[0]
    assert served.asked == [KA_STATUS_LIST], "production checks the key attestation's status"


def test_n_l8_vault_rows_leave_every_file_on_erase(make_issuer: Callable[..., Issuer], tmp_path: Path) -> None:
    """H-3 / N-L8: look for the actual ciphertext and wrapped key bytes, not plaintext that was never stored.

    secure_delete clears the database file at once; the WAL keeps the old pages until maintenance
    checkpoints it, so erasure is complete after the next maintenance run.
    """
    issuer = make_issuer(store=SqliteStore(tmp_path / "v.db"))
    issuer.vault.put("sub_x", {"family_name": "Silva"}, None, "offer")
    sealed = str(issuer.store.get("vault", "sub_x")).encode()
    wrapped = str(issuer.store.get("vault-key", "sub_x")).encode()
    assert any(sealed in path.read_bytes() for path in tmp_path.glob("v.db*")), "the search can find it"
    issuer.vault.erase("sub_x")
    issuer.maintenance(force=True)
    for path in tmp_path.glob("v.db*"):
        content = path.read_bytes()
        assert sealed not in content and wrapped not in content, path.name


def test_l9_response_types_follow_the_authorization_endpoint(client: TestClient) -> None:
    """L-9: no authorization endpoint (M3), so no response type; the two must agree."""
    document = client.get("/.well-known/oauth-authorization-server").json()
    assert ("authorization_endpoint" in document) == bool(document["response_types_supported"])


def test_l12_x5c_never_carries_a_registered_anchor() -> None:
    """A cross-signed root, or an intermediate registered as an anchor, is cut from x5c."""
    root_key, other_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root = certificate("Issuer Root", root_key, ca=True)
    other = certificate("Older Root", other_key, ca=True)
    cross = certificate("Issuer Root", root_key, (other, other_key), ca=True)  # same entity, signed by `other`
    mid_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    mid = certificate("Issuer CA", mid_key, (root, root_key), ca=True)
    leaf = certificate("Issuer Signer", leaf_key, (mid, mid_key), san=["issuer.test"])
    assert x5c_chain([leaf, mid, cross], None) == [leaf, mid, cross], "the old self-signed test keeps it"
    assert x5c_chain([leaf, mid, cross], [root]) == [leaf, mid]
    assert x5c_chain([leaf, mid], [mid]) == [leaf], "an intermediate registered as an anchor is cut too"
    with pytest.raises(ConfigError, match="does not end"):
        x5c_chain([leaf, mid], [other])
    with pytest.raises(ConfigError, match="not in order"):
        x5c_chain([leaf, cross], None)


def test_m1_residual_proofs_capped_by_the_reuse_policy(wallet: Wallet, issuer: Issuer) -> None:
    """Review 2, M-1 residual: a request may not carry more proofs than the reuse policy's batch_size."""
    wallet.get_token()
    nonce = wallet.c_nonce()
    proofs = [wallet.proof(EcKey.generate(), nonce) for _ in range(31)]
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}})
    assert response.status_code == 400 and "at most 30 proofs" in response.json()["error_description"]


# N-M6: each refusing statement, not only each rule, is pinned by a test --------------------------
# `tools/mutation/mutate.py --sites` removes refusing statements one at a time. These cases kill the
# ones that a later check under the same or another rule used to mask.


def _describe(response: Any) -> str:
    return str(response.json().get("error_description", ""))


def test_n_m6_declared_body_size_is_refused_before_reading() -> None:
    import asyncio

    from starlette.requests import Request

    from cunho.app import _body
    from cunho.errors import IssuerError

    async def receive() -> dict[str, Any]:
        raise AssertionError("the body must not be read")

    scope = {"type": "http", "method": "POST", "headers": [(b"content-length", b"999999999")]}
    with pytest.raises(IssuerError, match="request body too large"):
        asyncio.run(_body(Request(scope, receive), "OAUTH.TOKEN_ERROR_BODY"))


def test_n_m6_token_request_shape(wallet: Wallet) -> None:
    from urllib.parse import urlencode

    offer = wallet.offer()
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    form = urlencode({"grant_type": PRE_AUTH, "pre-authorized_code": code})
    as_json = wallet.client.post(
        "/token",
        content=form,
        headers={"Content-Type": "application/json", "DPoP": wallet.dpop("POST", f"{ISSUER}/token")},
    )
    assert as_json.status_code == 400 and "x-www-form-urlencoded" in _describe(as_json)
    twice = wallet.token_request(code, extra={}, dpop="auto")
    assert twice.status_code == 200
    second = wallet.offer()["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    doubled = wallet.client.post(
        "/token",
        content=form.replace(code, second) + "&pre-authorized_code=" + second,
        headers={"Content-Type": "application/x-www-form-urlencoded", "DPoP": wallet.dpop("POST", f"{ISSUER}/token")},
    )
    assert doubled.status_code == 400 and "appears more than once" in _describe(doubled)


def test_n_m6_audit_verify_body(client: TestClient) -> None:
    response = client.post("/admin/audit/verify", headers=AUTH, json={})
    assert response.status_code == 400 and "signed_head" in _describe(response)


def test_n_m6_dpop_with_an_unusable_key(wallet: Wallet) -> None:
    offer = wallet.offer()
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    key = wallet.dpop_key
    header = {"typ": "dpop+jwt", "alg": "ES384", "jwk": key.public_jwk()}
    claims = {"jti": uuid.uuid4().hex, "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock())}
    response = wallet.token_request(code, dpop=jws(header, claims, key))
    assert response.status_code == 400 and "needs curve P-384" in _describe(response)


def _ka_case(wallet: Wallet, holder: EcKey, **claims: Any) -> Any:
    wallet.token = None
    wallet.get_token()
    ka = wallet.key_attestation([holder], **claims)
    return wallet.credential_request(
        {
            "credential_configuration_id": PID_CONFIG,
            "proofs": {"jwt": [wallet.proof(holder, wallet.c_nonce(), key_attestation=ka)]},
        }
    )


def test_n_m6_key_attestation_claims(wallet: Wallet) -> None:
    holder = EcKey.generate()
    future = _ka_case(wallet, holder, iat=int(wallet.clock()) + 3600)
    assert future.status_code == 400 and "iat that is not in the future" in _describe(future)
    listed: list[Any] | None
    for listed in ([], None):
        empty = _ka_case(wallet, holder, attested_keys=listed)
        assert empty.status_code == 400 and "attested_keys must be a non-empty array" in _describe(empty)
    stale = _ka_case(wallet, holder, nonce="made-up")
    assert stale.status_code == 400 and "key attestation nonce is not a valid c_nonce" in _describe(stale)
    wallet.token = None
    wallet.get_token()
    claims = {"iat": int(wallet.clock()), "exp": int(wallet.clock()) + 3600, "attested_keys": [holder.public_jwk()]}
    forged = jws(
        {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [der_b64(wallet.pki.ka_leaf)]}, claims, EcKey.generate()
    )
    response = wallet.credential_request(
        {
            "credential_configuration_id": PID_CONFIG,
            "proofs": {"jwt": [wallet.proof(holder, wallet.c_nonce(), key_attestation=forged)]},
        }
    )
    assert response.status_code == 400 and "key attestation signature does not verify" in _describe(response)


def test_n_m6_jwt_proof_key_references(wallet: Wallet) -> None:
    holder = EcKey.generate()
    wallet.get_token()
    ka = wallet.key_attestation([holder])
    with_kid = jws(
        {"typ": "openid4vci-proof+jwt", "alg": "ES256", "kid": "k1", "key_attestation": ka},
        {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce()},
        holder,
    )
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [with_kid]}})
    assert response.status_code == 400 and "proof key is attested_keys[0]" in _describe(response)
    wrong_curve = wallet.proof(holder, wallet.c_nonce(), alg="ES384")
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [wrong_curve]}})
    assert response.status_code == 400 and "needs curve P-384" in _describe(response)


def test_n_m6_jwt_proof_without_attestation_names_its_key_by_jwk(wallet: Wallet, issuer: Issuer) -> None:
    """A configuration that does not require key attestations still takes the proof key only from jwk."""
    issuer.configs.all[PID_CONFIG]["proof_types_supported"]["jwt"].pop("key_attestations_required")
    wallet.get_token()
    holder = EcKey.generate()
    with_kid = jws(
        {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": holder.public_jwk(), "kid": "k1"},
        {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce()},
        holder,
    )
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [with_kid]}})
    assert response.status_code == 400 and "identify its key with jwk only" in _describe(response)


def test_n_m6_subject_data_gone_before_issuance(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    wallet.get_token(offer)
    assert wallet.issue().status_code == 200  # the only configuration: the data is erased once it is claimed
    issuer.vault.drop_replies(offer["subject_ref"])  # past the reply kept for a repeat (test_repeat_request)
    response = wallet.issue()
    assert response.status_code == 400 and "no longer available" in _describe(response)
    other = wallet.offer()
    wallet.get_token(other)
    assert wallet.client.post(f"/admin/subjects/{other['subject_ref']}/erase", headers=AUTH).status_code == 204
    response = wallet.issue()  # erasure closes the offer too (review 6, N6-L3)
    assert response.status_code == 400 and "subject revoked or erased" in _describe(response)


def test_n_m6_offer_names_only_issued_configurations(wallet: Wallet) -> None:
    for config_id in ("eu.europa.ec.eudi.pid_mdoc", "no.such.configuration"):
        response = wallet.admin("offers", {"credential_configuration_ids": [config_id], "subject": PID_SUBJECT})
        assert response.status_code == 400 and "is not a configuration this deployment issues" in _describe(response)


def test_n_m6_attestation_proof_type_takes_exactly_one(wallet: Wallet) -> None:
    wallet.get_token()
    keys = [EcKey.generate(), EcKey.generate()]
    two = [wallet.key_attestation([k], nonce=wallet.c_nonce()) for k in keys]
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"attestation": two}})
    assert response.status_code == 400 and "exactly one key attestation" in _describe(response)


def test_n_m6_token_scoped_to_its_configurations(wallet: Wallet, issuer: Issuer) -> None:
    token = wallet.get_token()
    key = hashlib.sha256(token.encode()).hexdigest()
    record: dict[str, Any] = dict(issuer.store.get("access-token", key) or {})
    record.pop("mac")
    resealed = seal(issuer.keyring, "token-record", key, {**record, "configuration_ids": ["another.configuration"]})
    issuer.store.put("access-token", key, resealed, 300)
    response = wallet.issue()
    assert response.status_code == 400 and "not issued for this credential configuration" in _describe(response)


def test_n_m6_revocation_reference_format(wallet: Wallet) -> None:
    response = wallet.admin("revocations", {"subject_ref": "Maria Silva", "reason": "death"})
    assert response.status_code == 400 and "not a reference this issuer handed out" in _describe(response)


def test_n_m6_proof_nonce_and_attestation_requirements(wallet: Wallet) -> None:
    wallet.get_token()
    holder = EcKey.generate()
    unknown = wallet.proof(holder, "made-up-nonce")
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [unknown]}})
    assert response.status_code == 400 and "unknown, expired or already used" in _describe(response)
    bare = wallet.proof(holder, wallet.c_nonce(), attest=False)
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [bare]}})
    assert response.status_code == 400 and "requires a key attestation" in _describe(response)


def test_n_m6_dpop_jti_shape(wallet: Wallet) -> None:
    code = wallet.offer()["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    key = wallet.dpop_key
    claims = {"jti": "short", "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock())}
    response = wallet.token_request(
        code, dpop=jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}, claims, key)
    )
    assert response.status_code == 400 and "jti must be a string of 8 to 256 characters" in _describe(response)


def test_pid_values_of_the_wrong_shape_are_problems_not_crashes(wallet: Wallet) -> None:
    """Found by the stress fuzz while checking these fixes: a dict where a code belongs raised TypeError."""
    from cunho.credentials import validate_pid

    today = dt.date(2026, 11, 4)
    for change in (
        {"nationalities": [{"a": 1}]},
        {"issuing_country": {"a": 1}},
        {"sex": {"a": 1}},
        {"sex": True},
        {"place_of_birth": {"country": ["PT"]}},
    ):
        problems = validate_pid({**PID_SUBJECT, **change}, today)
        assert any(p.startswith(next(iter(change))) for p in problems), change
        response = wallet.admin(
            "offers", {"credential_configuration_ids": [PID_CONFIG], "subject": {**PID_SUBJECT, **change}}
        )
        assert response.status_code == 400, change
