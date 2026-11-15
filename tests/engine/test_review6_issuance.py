"""Regression tests for the sixth M2 review (cunho-m2-review-6.md): erasure and refused claims during issuance,
and the round-5 mutants only the slow suites, or no suite, saw (N6-L1)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from cunho import service as service_module
from cunho.audit import Anchor, AuditLog
from cunho.keyring import Keyring
from cunho.service import Issuer
from cunho.status import StatusRef
from cunho.store import SqliteStore
from eudi_probe.jose import EcKey

from .helpers import ADMIN_TOKEN, PID_CONFIG, Clock, Wallet, disclosures, refused_by
from .test_review5_revocation import NATIONAL, two  # noqa: F401 - the fixture

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _slot(response: Any) -> StatusRef:
    ref = disclosures(response.json()["credentials"][0]["credential"])[1]["status"]["status_list"]
    return StatusRef(ref["uri"].rsplit("/", 1)[1], ref["idx"])


# N6-L3: an erasure stops an issuance that already read the subject's data ----------------------------------


def test_n6_l3_an_erasure_during_signing_stops_the_issuance(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """p5: the erasure answered 204 and the issuance 200, with the person's data, logged after subject.erased."""
    offer = wallet.offer()
    wallet.get_token(offer)
    real = service_module.sd_jwt_vc
    signing, release = threading.Event(), threading.Event()
    slots: list[StatusRef] = []

    def slow(settings: Any, signer: Any, config: Any, subject: Any, key: Any, ref: StatusRef, *rest: Any) -> str:
        slots.append(ref)
        signing.set()
        release.wait(10)
        return real(settings, signer, config, subject, key, ref, *rest)

    monkeypatch.setattr(service_module, "sd_jwt_vc", slow)
    result: dict[str, Any] = {}
    request = threading.Thread(target=lambda: result.setdefault("issued", wallet.issue()))
    request.start()
    assert signing.wait(10)
    erased = wallet.client.post(f"/admin/subjects/{offer['subject_ref']}/erase", headers=AUTH)
    assert erased.status_code == 204
    release.set()
    request.join(10)
    assert result["issued"].status_code == 400 and "revoked or erased" in result["issued"].json()["error_description"]
    assert [e["event"] for e in issuer.audit.entries()] == ["offer.created", "subject.erased"]
    assert issuer.status.value(slots[0]) == 1, "the slot of the refused credential never reads valid"


# N6-L4: a refused claim neither spends the configuration nor leaves the offer live --------------------------


def test_n6_l4_a_key_refused_leaves_the_configuration_to_ask_for_again(
    two: tuple[Wallet, Issuer],  # noqa: F811
) -> None:
    """p6: B was claimed and then refused for a key already bound, so it could never be asked for again, while
    the offer counted as live and kept its data until its window ended."""
    wallet, issuer = two
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    key = EcKey.generate()
    assert wallet.issue([key], config=PID_CONFIG).status_code == 200
    refused_by(lambda: wallet.issue([key], config=NATIONAL), "KA.BIND_TO_ATTESTED_KEY", "already bound")
    assert wallet.issue([EcKey.generate()], config=NATIONAL).status_code == 200, "the claim was not spent"
    assert issuer.store.get("vault-key", offer["subject_ref"]) is None, "every configuration issued: data erased"
    cancelled = wallet.client.post(f"/admin/offers/{offer['subject_ref']}/cancel", headers=AUTH)
    assert cancelled.status_code == 400, "nothing is left to cancel"


def test_n6_l4_a_failure_after_the_claim_gives_it_back(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    offer = wallet.offer()
    wallet.get_token(offer)
    real = service_module.sd_jwt_vc
    slots: list[StatusRef] = []

    def broken(settings: Any, signer: Any, config: Any, subject: Any, key: Any, ref: StatusRef, *rest: Any) -> str:
        slots.append(ref)
        raise RuntimeError("the signer is gone")

    monkeypatch.setattr(service_module, "sd_jwt_vc", broken)
    key = EcKey.generate()
    assert wallet.issue([key]).status_code == 500
    assert issuer.status.value(slots[0]) == 1, "a slot no wallet received never reads valid"
    monkeypatch.setattr(service_module, "sd_jwt_vc", real)
    assert wallet.issue([key]).status_code == 200, "the configuration and the key were given back"
    assert wallet.issue().status_code == 400, "and are claimed once it is issued"


# N6-L1: mutants of round-5 code that only the slow suites, or none, killed ---------------------------------


def test_x11_an_offer_whose_configurations_all_issued_is_not_live(wallet: Wallet, issuer: Issuer, clock: Clock) -> None:
    """X11 let the record of an issued configuration live a second: an offer that had issued everything was called
    live again, so cancellation and `offer_cancelled` reported an offer that could yield nothing."""
    offer = wallet.offer()
    wallet.get_token(offer)
    assert wallet.issue().status_code == 200
    clock.now += issuer.settings.offer_ttl - 5
    assert wallet.client.post(f"/admin/offers/{offer['subject_ref']}/cancel", headers=AUTH).status_code == 400
    revoked = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    assert revoked.json() == {"revoked": 1}, "no offer_cancelled: nothing was left to issue"


def test_x15_a_subject_revoked_after_its_offer_expired_while_its_token_lives(
    wallet: Wallet, issuer: Issuer, clock: Clock
) -> None:
    """X15 let what an offer can yield live only the offer's ttl: revoked after the offer expired, but while a
    token from it was valid, the subject was "nothing to revoke", never closed, and the wallet got its PID."""
    offer = wallet.offer()
    clock.now += issuer.settings.offer_ttl - 10
    wallet.get_token(offer)
    clock.now += 20  # the offer has expired; the access token has not
    revoked = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    assert revoked.json() == {"revoked": 0, "offer_cancelled": True}, revoked.text
    refused_by(lambda: wallet.issue(), "VCI.CRED.ERROR_CODES", "cancelled or its subject revoked")


def test_x17_verify_starts_again_when_pruning_passed_the_head_it_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """X17 went on from a checkpoint past the head verify had read, and reported entries removed: another worker
    logged new entries and pruned through them while verify walked the log."""
    clock = Clock()
    keyring = Keyring.from_file(tmp_path / "m.key", create=True)

    def worker() -> AuditLog:
        anchor = Anchor(tmp_path / "anchor", keyring)
        return AuditLog(SqliteStore(tmp_path / "s.db", clock), keyring, clock, anchor=anchor, create_anchor=True)

    log, other = worker(), worker()
    for n in range(600):
        log.append("offer.created", "admin", n=n)
    real = log._entries  # noqa: SLF001
    moved: list[int] = []

    def pruning_meanwhile(after: int = 0, upto: int | None = None) -> Any:
        for count, item in enumerate(real(after, upto)):
            if count == 100 and not moved:
                for n in range(5):
                    other.append("offer.created", "admin", n=n)
                moved.append(other.prune_before(clock() + 1, batch=1000))
            yield item

    monkeypatch.setattr(log, "_entries", pruning_meanwhile)
    ok, detail = log.verify()
    assert moved == [605] and ok, detail
