"""Regression tests for the seventh M2 review (cunho-m2-review-7.md), its pre-check and the second reviewer's
findings, apart from the clock (test_review7_clock.py)."""

from __future__ import annotations

import datetime as dt
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cunho import audit as audit_module
from cunho import schema
from cunho import service as service_module
from cunho.app import create_app
from cunho.errors import ConfigError
from cunho.jose import JoseError, validate_path
from cunho.service import Issuer, Signers
from cunho.settings import Settings
from cunho.signer import FileSigner
from cunho.store import SqliteStore

from .helpers import (
    ADMIN_TOKEN,
    ISSUER,
    KA_POLICY,
    PID_CONFIG,
    START,
    Clock,
    Host,
    Pki,
    Wallet,
    access_signer,
    certificate,
    mdoc_signer,
    production_kwargs,
    settings_kwargs,
)
from .test_review4_fixes import _env
from .test_review5_revocation import NATIONAL, two_configurations

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
OTHER_POLICY = "1.3.6.1.4.1.99999.1.2"
ANY_POLICY = "2.5.29.32.0"

# CX-2: one allowed policy holds along the whole path ---------------------------------------------------------


def _policies(*oids: str) -> tuple[x509.ExtensionType, bool]:
    return x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(oid), None) for oid in oids]), False


def _path(mid: list[str], leaf: list[str]) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = certificate("WP Root", root_key, ca=True)
    middle = certificate("WP Mid", mid_key, (root, root_key), ca=True, extensions=[_policies(*mid)])
    signer = certificate("KA Signer", leaf_key, (middle, mid_key), extensions=[_policies(*leaf)])
    return [signer, middle], [root]


@pytest.mark.parametrize(
    ("mid", "leaf", "valid"),
    [
        ([KA_POLICY], [OTHER_POLICY], False),  # p3: the intermediate vouches for A, the leaf asserts only B
        ([OTHER_POLICY], [KA_POLICY], False),
        ([KA_POLICY, OTHER_POLICY], [OTHER_POLICY], True),
        ([KA_POLICY], [KA_POLICY, OTHER_POLICY], True),
        ([ANY_POLICY], [OTHER_POLICY], True),  # anyPolicy covers whatever the leaf asserts
        (["1.3.6.1.4.1.99999.1.9"], [KA_POLICY], False),
    ],
)
def test_cx2_one_allowed_policy_must_hold_along_the_whole_path(mid: list[str], leaf: list[str], valid: bool) -> None:
    """The second reviewer's CX-2: with (A, B) allowed, an intermediate asserting A and a leaf asserting only B
    passed, though the valid policy tree of RFC 5280 §6.1 is empty for that path."""
    chain, anchors = _path(mid, leaf)
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    allowed = frozenset({KA_POLICY, OTHER_POLICY})
    if valid:
        validate_path(chain, anchors, now, allowed)
    else:
        with pytest.raises(JoseError, match="does not carry"):
            validate_path(chain, anchors, now, allowed)


# CX-3 and L5: an offer keeps its data until every configuration committed ------------------------------------


def test_cx3_a_claim_given_back_after_the_other_configuration_issued_can_be_issued_again(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """p2_concurrent_vault_loss: A issues configuration 1 while B signs configuration 2; the vault was erased once
    both were claimed, B then failed and gave its claim back, so B's retry could never be issued, and the offer
    was still called live."""
    issuer = make_issuer(metadata_dir=two_configurations(tmp_path))
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
        wallet.get_token(offer)
        real = service_module.sd_jwt_vc
        entered, release = threading.Event(), threading.Event()

        def signing(settings: Any, signer: Any, config: dict[str, Any], *rest: Any) -> str:
            if config["vct"] == "urn:eudi:pid:pt:1" and not release.is_set():
                entered.set()
                assert release.wait(10)
                raise RuntimeError("a transient failure while signing")
            return real(settings, signer, config, *rest)

        monkeypatch.setattr(service_module, "sd_jwt_vc", signing)
        results: dict[str, Any] = {}
        other = TestClient(
            create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
        )
        second = Wallet(other, pki, clock, dpop_key=wallet.dpop_key, token=wallet.token)
        thread = threading.Thread(target=lambda: results.setdefault("b", second.issue(config=NATIONAL)))
        thread.start()
        assert entered.wait(10)
        assert wallet.issue(config=PID_CONFIG).status_code == 200
        assert issuer.store.get("vault-key", offer["subject_ref"]) is not None, "B has not committed"
        release.set()
        thread.join(10)
        assert results["b"].status_code == 500
        retry = second.issue(config=NATIONAL)
        assert retry.status_code == 200, retry.text
        assert issuer.store.get("vault-key", offer["subject_ref"]) is None, "erased once both committed"
        assert not issuer._offer_live(offer["subject_ref"])  # noqa: SLF001


def test_cx3_an_offer_whose_configurations_all_committed_is_not_live_while_its_data_is_still_there(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Between an issuance's commit and the erasure of the vault that follows it, the offer has nothing left to
    issue: liveness goes by what committed, never by whether the data is still there."""
    offer = wallet.offer()
    wallet.get_token(offer)
    seen: list[bool] = []
    real = issuer.status.note_batch

    def between(size: int) -> None:
        assert issuer.store.get("vault-key", offer["subject_ref"]) is not None
        seen.append(issuer._offer_live(offer["subject_ref"]))  # noqa: SLF001
        real(size)

    monkeypatch.setattr(issuer.status, "note_batch", between)
    assert wallet.issue().status_code == 200
    assert seen == [False]


# L1: bytes appended between the read and a write do not leave a worker logging on a wrong position -----------


def test_l1_an_append_during_a_write_is_read_again_and_repaired(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """p3_anchor_append_race: someone who does not take the lock appended a byte just before a worker's write;
    that worker went on logging as if nothing happened, verify failed, and every other worker refused to log."""
    kw = {"secret_key_file": tmp_path / "m.key", "audit_anchor_path": tmp_path / "audit.anchor"}
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    issuer.audit.append("offer.created", "admin")
    real, armed = os.write, [True]

    def racing(fd: int, data: bytes) -> int:
        if armed[0] and data.endswith(b"}\n"):
            armed[0] = False
            with (tmp_path / "audit.anchor").open("ab") as appender:
                appender.write(b"X")
        return real(fd, data)

    monkeypatch.setattr(audit_module.os, "write", racing)
    issuer.audit.append("offer.created", "admin")  # stands, though its anchor line was spoiled
    monkeypatch.setattr(audit_module.os, "write", real)
    issuer.audit.append("offer.created", "admin")
    ok, detail = issuer.audit.verify()
    assert ok and "damaged stretch" in detail, detail
    other = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    other.audit.append("offer.created", "admin")
    assert other.audit.verify()[0]
    assert "audit.anchor_repaired" in [e["event"] for e in issuer.audit.entries()]


# L3 and the pre-check's C1: an upgrade is logged, and production upgrades only when told to ------------------


def test_l3_a_store_without_its_version_row_is_upgraded_in_the_open(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """p4_schema_row_deleted: a database writer removed the version row; the next start upgraded again without
    an audit entry and recorded the offer as live for all 31 configurations of the metadata."""
    kw = {"secret_key_file": tmp_path / "m.key"}
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    issuer.vault.put("sub_legacy000000000000000000", {"family_name": "Silva"}, 600, "offer")
    issuer.store.delete("meta", "schema")
    again = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    events = [e["event"] for e in again.audit.entries()]
    assert events[-1] == "store.upgraded" and again.audit.entries()[-1]["data"] == {"schema": schema.SCHEMA}
    assert again.audit.verify()[0]
    assert again.store.get("subject-open", "sub_legacy000000000000000000") == [PID_CONFIG], "what it issues only"


def test_l3_production_upgrades_only_when_told_to(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    anchors = pki.root / "issuer-root.pem"
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    signers = Signers(
        signer,
        FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors),
        access_signer(pki),
        mdoc_signer(pki),
    )
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    kwargs = production_kwargs(pki, tmp_path)
    issuer = Issuer(Settings(**kwargs), signers=signers, clock=clock)
    issuer.audit.append("offer.created", "admin")
    issuer.store.delete("meta", "schema")
    later = {**kwargs, "audit_anchor_init": False}
    with pytest.raises(ConfigError, match="CUNHO_STORE_UPGRADE=true"):
        Issuer(Settings(**later), signers=signers, clock=clock)
    upgraded = Issuer(Settings(**{**later, "store_upgrade": True}), signers=signers, clock=clock)
    assert upgraded.audit.entries()[-1]["event"] == "store.upgraded"
    assert Settings.from_env(_env(pki, CUNHO_STORE_UPGRADE="true")).store_upgrade


def test_l3_a_store_at_its_version_starts_whatever_its_log_says(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """Only an upgrade needs the log at startup. A store whose newest entries were removed starts as before,
    refuses to log, and verify says why, so the operator can look."""
    kw = {"secret_key_file": tmp_path / "m.key", "audit_anchor_path": tmp_path / "audit.anchor"}
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    issuer.audit.append("offer.created", "admin")
    head = issuer.store.get("audit-meta", "head")
    issuer.audit.append("offer.created", "admin")
    issuer.store.delete("audit", f"{2:012d}")
    issuer.store.put("audit-meta", "head", head, None)
    again = make_issuer(store=SqliteStore(tmp_path / "s.db", clock), **kw)
    assert again.audit.verify() == (False, "the store (head 1) is behind the anchor (sequence 2): entries were removed")


def test_production_refuses_a_host_whose_boot_cannot_be_named(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without a boot to compare the host clock across, the watch could only take the wall clock as it reads, so a
    clock stepped once would prune; production does not start so, and a development run says it goes on."""
    import time

    anchors = pki.root / "issuer-root.pem"
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    signers = Signers(
        signer,
        FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors),
        access_signer(pki),
        mdoc_signer(pki),
    )
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    nameless = service_module.HostClock(boot=lambda: None)
    monkeypatch.setattr(service_module, "HostClock", lambda: nameless)
    with pytest.raises(ConfigError, match="boot cannot be named"):
        Issuer(Settings(**production_kwargs(pki, tmp_path)), signers=signers, clock=time.time)
    development = Issuer(Settings(**settings_kwargs(pki)), clock=time.time)
    assert development.clock_watch.now() == pytest.approx(time.time(), abs=5), "the wall clock alone"


def test_production_starts_on_a_new_store_with_a_host_clock(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The watch's first reading writes the store; a new store is versioned before it, so production does not
    take its own new store for one written before the version (second reviewer)."""
    import time

    anchors = pki.root / "issuer-root.pem"
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    signers = Signers(
        signer,
        FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors),
        access_signer(pki),
        mdoc_signer(pki),
    )
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    named = service_module.HostClock(boot=lambda: "boot-1", synced=lambda: True)
    monkeypatch.setattr(service_module, "HostClock", lambda: named)
    kwargs = production_kwargs(pki, tmp_path)
    issuer = Issuer(Settings(**kwargs), signers=signers, clock=time.time)
    assert issuer.store.get("maintenance", "clock:boot-1") is not None, "the watch laid a base, under its boot"
    again = Issuer(Settings(**{**kwargs, "audit_anchor_init": False}), signers=signers, clock=time.time)
    assert again.clock_watch.now() == pytest.approx(time.time(), abs=5)
    assert not any(e["event"] == "store.upgraded" for e in again.audit.entries())


# L7: the credential endpoint is rate-limited, and no operator takes the admin token's name -------------------


def test_l7_the_credential_endpoint_is_rate_limited(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer(rate_limit_per_minute=3)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        codes = [client.post("/credential", content=b"{}").status_code for _ in range(4)]
    assert codes[:3] == [401, 401, 401] and codes[3] == 429, codes


def test_l7_an_operator_named_admin_is_refused(pki: Pki) -> None:
    with pytest.raises(ConfigError, match="named admin"):
        Settings(**settings_kwargs(pki, operators={"admin": "o" * 40}))


# The pre-check's note, without a time: a subject revocation counts every record still kept -------------------


def test_a_subject_revocation_without_a_time_counts_every_record_kept(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    issuer.sweep()
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        offer = wallet.offer()
        wallet.get_token(offer)
        assert wallet.issue().status_code == 200
        host.boot, host.elapsed = "boot-2", 30.0
        clock.now += 30 * 86_400
        issuer.use_clock_watch(host.watch(issuer.store))
        assert issuer.clock_watch.now() is None
        reply = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "compromise"})
        assert reply.json()["revoked"] == 1, reply.text
