"""Regression tests for the fifth M2 review (cunho-m2-review-5.md): revocation, subjects and persons."""

from __future__ import annotations

import json
import shutil
import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho import service as service_module
from cunho.app import create_app
from cunho.service import Issuer
from cunho.settings import DEFAULT_METADATA_DIR
from cunho.status import StatusRef

from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PRE_AUTH, Clock, Pki, Wallet, disclosures, refused_by

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
NATIONAL = "pt.pid_vc_sd_jwt"  # a second SD-JWT PID type, as a national PID would be


def two_configurations(root: Path) -> Path:
    """The EC metadata plus a national PID type with the same claims: an offer can hold both. Once mdoc lands
    (M4) a PID offer holds two configurations as a rule."""
    target = root / "metadata"
    shutil.copytree(DEFAULT_METADATA_DIR, target)
    folder = target / "credentials_supported"
    config = dict(json.loads((folder / "pid_jwt_vc.json").read_text())[PID_CONFIG])
    config["vct"], config["scope"] = "urn:eudi:pid:pt:1", "pt.pid"
    (folder / "pid_pt_jwt_vc.json").write_text(json.dumps({NATIONAL: config}))
    return target


@pytest.fixture
def two(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path) -> Iterator[tuple[Wallet, Issuer]]:
    issuer = make_issuer(metadata_dir=two_configurations(tmp_path))
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        yield Wallet(client, pki, clock), issuer


def _slot(response: Any) -> StatusRef:
    ref = disclosures(response.json()["credentials"][0]["credential"])[1]["status"]["status_list"]
    return StatusRef(ref["uri"].rsplit("/", 1)[1], ref["idx"])


# N5-M2: a revocation while a later configuration of the same offer is being issued -----------------------


def test_n5_m2_a_revocation_between_a_claim_and_its_commit(
    two: tuple[Wallet, Issuer], monkeypatch: pytest.MonkeyPatch
) -> None:
    """t3: B claims its configuration and is signing; A finishes and erases the vault; the operator revokes the
    person; B used to commit a valid PID. The subject is now closed whatever the vault holds, and B, which
    checks the mark in the transaction of its own log entry, is refused."""
    wallet, issuer = two
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    real = service_module.sd_jwt_vc
    signing, release = threading.Event(), threading.Event()

    def slow(settings: Any, signer: Any, config: dict[str, Any], *rest: Any, **named: Any) -> str:
        if config["vct"] == "urn:eudi:pid:pt:1":
            signing.set()
            release.wait(10)
        return real(settings, signer, config, *rest, **named)

    monkeypatch.setattr(service_module, "sd_jwt_vc", slow)
    result: dict[str, Any] = {}
    request_b = threading.Thread(target=lambda: result.setdefault("b", wallet.issue(config=NATIONAL)))
    request_b.start()
    assert signing.wait(10)
    first = wallet.issue(config=PID_CONFIG)
    assert first.status_code == 200
    # B's configuration is claimed but has not committed, so its data stays until it does (review 7, L5).
    assert issuer.store.get("vault-key", offer["subject_ref"]) is not None
    revoked = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "compromise"})
    assert revoked.json() == {"revoked": 1, "offer_cancelled": True}, "B was still on its way"
    release.set()
    request_b.join(10)
    assert result["b"].status_code == 400 and result["b"].json()["error"] == "credential_request_denied"
    assert issuer.status.value(_slot(first)) == 1
    events = [e["event"] for e in issuer.audit.entries()]
    assert events == ["offer.created", "credential.issued", "credential.revoked"]


def test_n5_m2_the_issuance_transaction_checks_the_mark(
    two: tuple[Wallet, Issuer], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check before signing cannot see a revocation that comes while the credential is signed; only the
    check in the transaction of the log entry can, so it is pinned on its own."""
    wallet, issuer = two
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    real = service_module.sd_jwt_vc

    def revoke_while_signing(*args: Any, **named: Any) -> str:
        issuer.revoke({"subject_ref": offer["subject_ref"], "reason": "death"}, "admin")
        return real(*args, **named)

    monkeypatch.setattr(service_module, "sd_jwt_vc", revoke_while_signing)
    response = refused_by(
        lambda: wallet.issue(config=NATIONAL), "VCI.CRED.ERROR_CODES", "this offer was cancelled or its subject revoked"
    )
    assert response.status_code == 400
    assert [e["event"] for e in issuer.audit.entries()] == ["offer.created", "credential.revoked"]


def test_n5_m2_offer_cancelled_says_whether_anything_was_on_its_way(two: tuple[Wallet, Issuer]) -> None:
    wallet, issuer = two
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    assert wallet.issue(config=PID_CONFIG).status_code == 200
    assert wallet.issue(config=NATIONAL).status_code == 200
    revoked = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    assert revoked.json() == {"revoked": 2}, "both committed: nothing was left to cancel"
    assert issuer.store.get("subject-closed", offer["subject_ref"]) == 1, "closed all the same"


def test_s8_the_closed_mark_outlives_the_offer(wallet: Wallet, issuer: Issuer, clock: Clock) -> None:
    """Review 5's S8 let the mark live only the token ttl (300 s): an offer revoked in its first five minutes
    could be redeemed in its second five."""
    offer = wallet.offer()
    wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    clock.now += issuer.settings.offer_ttl - 5
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "this offer was cancelled")


# N5-L11: a revocation erases the subject data, like a cancellation -----------------------------------------


def test_n5_l11_a_subject_revocation_erases_its_data(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    assert issuer.store.get("vault-key", offer["subject_ref"]) is not None
    wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "death"})
    assert issuer.store.get("vault-key", offer["subject_ref"]) is None
    assert issuer.store.get("vault", offer["subject_ref"]) is None


# N5-L6: only references cunho handed out, matched whole; erasure says whether data was held ------------


def test_n5_l6_a_reference_with_a_trailing_newline_is_refused(wallet: Wallet, issuer: Issuer) -> None:
    """t10: `sub_...%0A` passed the `$` check, and its erasure was logged while the data stayed."""
    ref = wallet.offer()["subject_ref"]
    for path in (f"/admin/subjects/{ref}%0A/erase", f"/admin/offers/{ref}%0A/cancel"):

        def post(path: str = path) -> Any:
            return wallet.client.post(path, headers=AUTH)

        response = refused_by(post, "ISS.SUBJECT.ENTITLEMENT", "not a subject reference this issuer handed out")
        assert response.status_code == 400
    refused_by(
        lambda: wallet.admin("revocations", {"subject_ref": ref + "\n", "reason": "death"}),
        "STATUS.MONOTONIC",
        "subject_ref is not a reference this issuer handed out",
    )
    assert issuer.store.get("vault-key", ref) is not None
    assert [e["event"] for e in issuer.audit.entries()] == ["offer.created"]


def test_n5_l6_erasure_of_a_reference_never_handed_out(wallet: Wallet, issuer: Issuer) -> None:
    ref = wallet.offer()["subject_ref"]
    forged = ref[:-3] + ("AAA" if ref[-3:] != "AAA" else "BBB")  # the shape, but not the tag
    refused_by(
        lambda: wallet.client.post(f"/admin/subjects/{forged}/erase", headers=AUTH),
        "ISS.SUBJECT.ENTITLEMENT",
        "not a subject reference this issuer handed out",
    )
    assert wallet.client.post(f"/admin/subjects/{ref}/erase", headers=AUTH).status_code == 204
    assert wallet.client.post(f"/admin/subjects/{ref}/erase", headers=AUTH).status_code == 204
    erased = [e["data"] for e in issuer.audit.entries() if e["event"] == "subject.erased"]
    assert erased == [{"subject_ref": ref, "data_held": True}, {"subject_ref": ref, "data_held": False}]
    assert issuer.store.get("vault-key", ref) is None


# N5-L7: revoking a person, not only one offer ----------------------------------------------------------------


def test_n5_l7_a_person_handle_revokes_every_offer_made_for_that_person(
    wallet: Wallet, issuer: Issuer, clock: Clock
) -> None:
    """t11: revoking the latest reference left the PID issued ten days earlier valid. An operator who gives a
    person handle when creating offers can revoke every credential of that person at once."""
    issued = []
    for _ in range(2):
        response = wallet.admin(
            "offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _pid(), "person": "customer-4711"}
        )
        wallet.token = None
        wallet.get_token(response.json())
        issued.append(wallet.issue())
        clock.now += 5 * 86_400  # the first PID is ten days old at the revocation, and still valid
    other = wallet.admin(
        "offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _pid(), "person": "customer-4712"}
    )
    wallet.token = None
    wallet.get_token(other.json())
    kept = wallet.issue()
    revoked = wallet.admin("revocations", {"person": "customer-4711", "reason": "death"})
    assert revoked.json() == {"revoked": 2, "subjects": 2, "offers_cancelled": 0}
    assert [issuer.status.value(_slot(r)) for r in issued] == [1, 1]
    assert issuer.status.value(_slot(kept)) == 0
    entry = issuer.audit.entries()[-1]
    assert entry["event"] == "credential.revoked" and len(entry["data"]["subject_refs"]) == 2
    everything = json.dumps([issuer.audit.entries(), issuer.store.items("person"), issuer.store.items("person-of")])
    assert "customer-4711" not in everything, "the handle itself is never kept"
    refused_by(
        lambda: wallet.admin("revocations", {"person": "customer-0000", "reason": "death"}),
        "STATUS.MONOTONIC",
        "nothing to revoke for this person",
    )


def test_n5_l7_person_handles_are_checked_and_erased_with_the_subject(wallet: Wallet, issuer: Issuer) -> None:
    bad: Any
    for bad in ("", "has space", "x" * 201, 7, "caf\u00e9"):

        def make_offer(bad: Any = bad) -> Any:
            body = {"credential_configuration_ids": [PID_CONFIG], "subject": _pid(), "person": bad}
            return wallet.admin("offers", body)

        def revoke_person(bad: Any = bad) -> Any:
            return wallet.admin("revocations", {"person": bad, "reason": "death"})

        refused_by(make_offer, "VCI.OFFER.SHAPE", "person must be 1 to 200 printable ASCII characters")
        refused_by(revoke_person, "STATUS.MONOTONIC", "person must be 1 to 200 printable ASCII characters")
    offer = wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _pid(), "person": "p-1"})
    ref = offer.json()["subject_ref"]
    assert len(issuer.store.items("person")) == 1 and issuer.store.get("person-of", ref) is not None
    assert wallet.client.post(f"/admin/subjects/{ref}/erase", headers=AUTH).status_code == 204
    assert issuer.store.items("person") == [] and issuer.store.get("person-of", ref) is None
    lifetime = issuer.settings.offer_ttl + issuer.settings.access_token_ttl + 14 * 86_400 + 3600
    wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _pid(), "person": "p-2"})
    issuer.clock.now += lifetime - 1  # type: ignore[attr-defined]
    assert len(issuer.store.items("person")) == 1, "kept as long as a credential from the offer can be valid"
    issuer.clock.now += 2  # type: ignore[attr-defined]
    assert issuer.store.items("person") == []


def _pid() -> dict[str, Any]:
    from .helpers import PID_SUBJECT

    return dict(PID_SUBJECT)
