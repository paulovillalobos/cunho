"""What the security review found in the issuance state machine (research/cunho-security-review.md): what a refresh
token let a wallet do again, what a login could pile up, what closing a subject left behind, and a document's end
that one format did not read. Each test failed on the code as reviewed and holds its fix."""

from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from cunho import service as service_module
from cunho.jose import thumbprint
from cunho.service import Issuer
from cunho.store import SqliteStore
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet, Pkce, Redirect, pid_scope
from .helpers import ADMIN_TOKEN, PID_CONFIG, PID_SUBJECT, PRE_AUTH, Clock, Pki, Wallet, disclosures, refused_by
from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner
from .test_deferred import decide, deferred, held_login, held_refs, hold
from .test_mdoc import mdoc_settings
from .test_refresh import refreshable

# --- one key, one credential, across the access tokens of a login -----------------------------------------------------


def payload_of(response: Any, index: int = 0) -> dict[str, Any]:
    credential = response.json()["credentials"][index]["credential"]
    return dict(json.loads(base64.urlsafe_b64decode(credential.split("~")[0].split(".")[1] + "==")))


def test_a_refreshed_token_does_not_bind_a_key_that_already_has_a_credential(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    refreshable(code_wallet, code_issuer)
    key = EcKey.generate()
    first = code_wallet.issue([key])
    assert first.status_code == 200, first.text

    renewed = code_wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    code_wallet.token = renewed.json()["access_token"]
    second = code_wallet.issue([key])  # a fresh proof and a fresh key attestation for the very same key

    if second.status_code == 200:
        one, two = payload_of(first), payload_of(second)
        assert one["cnf"] == two["cnf"], "both credentials are bound to the one key"
        assert one["status"] != two["status"], "and they are two credentials, each with its own status entry"
    assert len(code_issuer.store.items("issued")) == 1, "a second credential was made on a key that already had one"
    assert second.status_code == 400 and second.json()["error"] == "invalid_proof", second.text


def test_a_key_stays_claimed_when_the_token_it_was_claimed_under_has_run_out(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    """The claim lives as long as the login can have credentials issued, not as long as one access token."""
    refreshable(code_wallet, code_issuer)
    key = EcKey.generate()
    assert code_wallet.issue([key]).status_code == 200
    for _ in range(2):  # also once the token of the first refresh has ended: a later token shortens no claim
        clock.now += code_issuer.settings.access_token_ttl + 60
        code_wallet.token = code_wallet.refresh_request().json()["access_token"]
        again = code_wallet.issue([key])
        assert again.status_code == 400 and again.json()["error"] == "invalid_proof", again.text
        assert code_wallet.issue([EcKey.generate()]).status_code == 200, "the refusal gave the configuration back"
    assert code_issuer.store.items("grant-key") == [], "no row names a key by its thumbprint"
    rows = [name for name, _ in code_issuer.store.items("subject-key")]
    assert len(rows) == 3, "the key and the two that took its place"
    assert not [name for name in rows if thumbprint(key.public_jwk()) in name], "what is kept is a keyed reference"


DAY = 86_400


def same_store(tmp_path: Path, clock: Clock) -> dict[str, Any]:
    """The settings that make an issuer start on the same database, keys and anchor, as cunho does after a restart."""
    return {
        "store": SqliteStore(tmp_path / "store.db", clock),
        "secret_key_file": tmp_path / "master.key",
        "audit_anchor_path": tmp_path / "audit.anchor",
    }


def test_a_key_stays_claimed_while_a_refresh_token_from_before_a_restart_lives(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Path,
) -> None:
    """The claim goes by the refresh token's own end, under its MAC, not by the lifetimes configured when the key
    is claimed: after a restart with a shorter refresh_token_ttl a claim that went by them ran out weeks before a
    refresh token from before the restart did, and the key got a second credential (the second reviewer)."""
    before = make_code_issuer(**same_store(tmp_path, clock), refresh_token_ttl=30 * DAY)
    wallet = code_wallet_for(before)
    refreshable(wallet, before)
    after = make_code_issuer(**same_store(tmp_path, clock), refresh_token_ttl=3600)
    wallet = replace(wallet, client=code_wallet_for(after).client)
    key = EcKey.generate()
    wallet.token = wallet.refresh_request().json()["access_token"]
    assert wallet.issue([key]).status_code == 200
    clock.now += 20 * DAY  # far past what the lifetimes add up to as they are set now; the refresh token has ten days
    renewed = wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    wallet.token = renewed.json()["access_token"]
    again = wallet.issue([key])
    assert again.status_code == 400 and again.json()["error"] == "invalid_proof", again.text
    assert wallet.issue([EcKey.generate()]).status_code == 200, "the login itself is good, for another key"


def test_a_token_got_with_a_logins_last_refresh_takes_the_claims_along(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], clock: Clock
) -> None:
    """An access token got just before the refresh token ends outlives it. A key claimed long before stays claimed
    for as long as that token can be shown."""
    issuer = make_code_issuer(refresh_token_ttl=600, access_token_ttl=300)
    wallet = code_wallet_for(issuer)
    refreshable(wallet, issuer)
    key = EcKey.generate()
    assert wallet.issue([key]).status_code == 200
    clock.now += 590
    wallet.token = wallet.refresh_request().json()["access_token"]
    clock.now += 200  # the refresh token ended 190 s ago; the token it gave last has 100 s left
    assert wallet.refresh_request().status_code == 400
    again = wallet.issue([key])
    assert again.status_code == 400 and again.json()["error"] == "invalid_proof", again.text
    assert wallet.issue([EcKey.generate()]).status_code == 200, "the token itself is good, for another key"


def test_a_token_from_before_a_restart_that_outlives_its_login_finds_the_key_claimed(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Path,
) -> None:
    """A claim also outlives every token minted before it: here one that lives an hour, from before a restart that
    made new tokens live a minute."""
    before = make_code_issuer(**same_store(tmp_path, clock), refresh_token_ttl=600, access_token_ttl=3600)
    wallet = code_wallet_for(before)
    refreshable(wallet, before)
    early = wallet.token
    after = make_code_issuer(**same_store(tmp_path, clock), refresh_token_ttl=600, access_token_ttl=60)
    wallet = replace(wallet, client=code_wallet_for(after).client)
    clock.now += 10
    wallet.token = wallet.refresh_request().json()["access_token"]
    key = EcKey.generate()
    assert wallet.issue([key]).status_code == 200
    clock.now += 700  # the token the key was claimed under and the refresh token have ended; the early token has not
    wallet.token = early
    again = wallet.issue([key])
    assert again.status_code == 400 and again.json()["error"] == "invalid_proof", again.text
    assert wallet.issue([EcKey.generate()]).status_code == 200, "the early token itself is good, for another key"


def test_a_key_bound_under_a_token_by_the_earlier_version_stays_bound_under_it(wallet: Wallet, issuer: Issuer) -> None:
    """An upgrade while a token lives: the earlier version kept the keys a token had bound under the token's own
    name. Those rows hold for as long as the token does, so the upgrade does not free a key for a second credential."""
    wallet.get_token()
    [(_, row)] = issuer.store.items("access-token")
    bound, free = EcKey.generate(), EcKey.generate()
    issuer.store.put("grant-key", f"{row['grant_id']}:{thumbprint(bound.public_jwk())}", 1, 300)
    refused = wallet.issue([bound])
    assert refused.status_code == 400 and refused.json()["error"] == "invalid_proof", refused.text
    assert "already bound" in refused.json()["error_description"]
    assert wallet.issue([free]).status_code == 200


def test_two_issuances_held_for_review_are_not_both_collected_on_one_key(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    key = EcKey.generate()
    _, first_transaction = hold(code_wallet, code_issuer, [key])
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    again = code_wallet.issue([key])
    # Refusing the second ask at once is the fix that costs least; holding it and refusing one of the two
    # collections would do as well. Either way one key must end with one credential.
    collected = []
    if again.status_code == 202:
        for ref in held_refs(code_wallet):
            assert decide(code_wallet, ref, "release").status_code == 200
        for transaction_id in (first_transaction, again.json()["transaction_id"]):
            answer = deferred(code_wallet, {"transaction_id": transaction_id})
            if answer.status_code == 200:
                collected.append(payload_of(answer))
    else:
        [ref] = held_refs(code_wallet)
        assert decide(code_wallet, ref, "release").status_code == 200
        collected.append(payload_of(deferred(code_wallet, {"transaction_id": first_transaction})))
    assert len(collected) == 1, f"{len(collected)} credentials were collected on one key"


# --- one login and the status entries it can take ---------------------------------------------------------------------


BATCH = 30  # the reference PID configuration's batch_size
ROUNDS = 36


def test_one_login_does_not_open_status_lists_at_will(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    issuer = make_code_issuer(status_list_size=1024)  # 512 usable entries a list, instead of 65,536
    wallet = code_wallet_for(issuer)
    refreshable(wallet, issuer)  # one login: an access token and its refresh token
    keys = [EcKey.generate() for _ in range(BATCH)]
    bound: list[str] = []
    for _ in range(ROUNDS):  # the clock does not move: all of it within the same minute
        renewed = wallet.refresh_request()
        assert renewed.status_code == 200, renewed.text
        wallet.token = renewed.json()["access_token"]
        response = wallet.issue(keys)
        if response.status_code != 200:
            break
        for entry in response.json()["credentials"]:
            bound.append(thumbprint(disclosures(entry["credential"])[1]["cnf"]["jwk"]))
    lists = issuer.status.lists()
    assert len(lists) == 1, (
        f"one login, no time passing: {len(bound)} credentials on {len(set(bound))} keys, "
        f"{len(issuer.store.items('issued'))} live status entries and {len(lists)} status lists opened"
    )


# --- every key attestation of a PID request states its status period --------------------------------------------------


WITHOUT_PERIOD = {"status": {"status_list": {"idx": 9, "uri": KA_STATUS_LIST}}}


def test_every_key_attestation_of_a_pid_batch_states_its_status_period(wallet: Wallet, issuer: Issuer) -> None:
    stated, silent = EcKey.generate(), EcKey.generate()
    attestation_without_period = wallet.key_attestation([silent], key_storage_status=WITHOUT_PERIOD)

    # Alone, the attestation without a period is refused, as the rule says.
    wallet.get_token()
    alone = refused_by(
        lambda: wallet.credential_request(
            {
                "credential_configuration_id": PID_CONFIG,
                "proofs": {"jwt": [wallet.proof(silent, wallet.c_nonce(), key_attestation=attestation_without_period)]},
            }
        ),
        "VALIDITY.PID_LE_STATUS_EXP",
        "key_storage_status.exp",
    )
    assert alone.status_code == 400 and alone.json()["error"] == "invalid_proof"

    # Next to an attestation that states one, it must be refused just the same.
    nonce = wallet.c_nonce()
    proofs = [
        wallet.proof(stated, nonce),  # its own attestation, with key_storage_status.exp
        wallet.proof(silent, nonce, key_attestation=attestation_without_period),
    ]
    batch = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}})
    assert len(issuer.store.items("issued")) == 0, "a PID was issued on a key whose attestation states no status period"
    assert batch.status_code == 400 and batch.json()["error"] == "invalid_proof", batch.text


def test_an_attestation_with_no_status_at_all_is_not_covered_by_another_either(wallet: Wallet, issuer: Issuer) -> None:
    stated, bare = EcKey.generate(), EcKey.generate()
    wallet.get_token()
    nonce = wallet.c_nonce()
    proofs = [
        wallet.proof(stated, nonce),
        wallet.proof(bare, nonce, key_attestation=wallet.key_attestation([bare], key_storage_status=None)),
    ]
    refused_by(
        lambda: wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}}),
        "VALIDITY.PID_LE_STATUS_EXP",
        "key_storage_status.exp",
    )
    assert len(issuer.store.items("issued")) == 0


def test_the_same_holds_when_the_wallet_providers_status_lists_are_read(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Any], pki: Pki
) -> None:
    """As production runs: the key attestations' entries are read from the wallet provider's status list. The
    attestation without a period names a valid entry, so the status check passes it, and nothing else asks for its
    period."""
    served = ServedStatus()
    served.lists[KA_STATUS_LIST] = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key).token(KA_STATUS_LIST)
    issuer = make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=served)
    wallet = wallet_for(issuer)
    wallet.get_token()
    stated, silent = EcKey.generate(), EcKey.generate()
    nonce = wallet.c_nonce()
    proofs = [
        wallet.proof(stated, nonce),
        wallet.proof(
            silent, nonce, key_attestation=wallet.key_attestation([silent], key_storage_status=WITHOUT_PERIOD)
        ),
    ]
    batch = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}})
    assert len(issuer.store.items("issued")) == 0, "a PID was issued on a key whose attestation states no status period"
    assert batch.status_code == 400 and batch.json()["error"] == "invalid_proof", batch.text


# --- a collection that comes while another is at work -----------------------------------------------------------------


def credential_slots(issuer: Issuer) -> dict[str, int]:
    """Every status entry reserved for a credential (the decoys a list starts with left out), with its value."""
    decoys = {key for key, _ in issuer.store.items("status-decoy")}
    return {key: int(value) for key, value in issuer.store.items("status-slot") if key not in decoys}


def test_a_collection_that_loses_the_race_reserves_and_revokes_nothing(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    keys = [EcKey.generate(), EcKey.generate()]
    _, transaction_id = hold(code_wallet, code_issuer, keys)
    [ref] = held_refs(code_wallet)
    assert decide(code_wallet, ref, "release").status_code == 200
    assert credential_slots(code_issuer) == {}, "nothing is reserved while the issuance waits"

    real = service_module.sd_jwt_vc
    signing, go_on = threading.Event(), threading.Event()

    def signer(*args: Any) -> str:
        if not signing.is_set():  # only the first collection waits here, after reserving and before committing
            signing.set()
            go_on.wait(10)
        return real(*args)

    monkeypatch.setattr(service_module, "sd_jwt_vc", signer)
    answers: dict[str, Any] = {}

    def first() -> None:
        answers["first"] = deferred(code_wallet, {"transaction_id": transaction_id})

    thread = threading.Thread(target=first)
    thread.start()
    assert signing.wait(10), "the first collection is signing"
    answers["second"] = deferred(code_wallet, {"transaction_id": transaction_id})
    go_on.set()
    thread.join(10)

    # The one that came while the first was at work is told to ask again, as while the issuance was held; it
    # reserved nothing. The first then gets its credentials, and whoever asks after that is told they were collected.
    assert answers["second"].status_code == 202, answers["second"].text
    assert answers["second"].json() == {
        "transaction_id": transaction_id,
        "interval": code_issuer.settings.deferred_interval,
    }
    assert answers["first"].status_code == 200, answers["first"].text
    assert len(answers["first"].json()["credentials"]) == len(keys)
    late = deferred(code_wallet, {"transaction_id": transaction_id})
    assert late.status_code == 400 and late.json()["error"] == "invalid_transaction_id"
    slots = credential_slots(code_issuer)
    wasted = sorted(key for key, value in slots.items() if value == 1)
    assert len(slots) == len(keys), (
        f"{len(slots)} status entries were reserved for {len(keys)} credentials; {len(wasted)} of them were never "
        "given to a wallet and now read revoked"
    )


def released(wallet: CodeWallet, issuer: Issuer) -> str:
    """An issuance the operator released, not yet collected: its transaction_id."""
    _, transaction_id = hold(wallet, issuer)
    [ref] = held_refs(wallet)
    assert decide(wallet, ref, "release").status_code == 200
    return transaction_id


def killed(*args: Any) -> str:
    raise RuntimeError("the collection ends here")


def test_a_collection_that_fails_gives_its_mark_back_at_once(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction_id = released(code_wallet, code_issuer)
    with monkeypatch.context() as patched:
        patched.setattr(service_module, "sd_jwt_vc", killed)
        assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 500
    assert code_issuer.store.items("collecting") == []
    collected = deferred(code_wallet, {"transaction_id": transaction_id})
    assert collected.status_code == 200, "the wallet's next ask collects, with no minute to wait for"
    assert code_issuer.store.items("collecting") == [], "and gives the mark back too"


def test_a_collection_that_died_holds_the_issuance_for_a_minute_and_no_longer(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A process that is killed gives nothing back. The mark it took then runs out by itself, and the wallet's
    next ask after that collects."""
    transaction_id = released(code_wallet, code_issuer)
    delete, dead = code_issuer.store.delete, [True]

    def as_if_killed(namespace: str, key: str) -> None:
        if not (dead[0] and namespace == "collecting"):
            delete(namespace, key)

    monkeypatch.setattr(code_issuer.store, "delete", as_if_killed)
    with monkeypatch.context() as patched:
        patched.setattr(service_module, "sd_jwt_vc", killed)
        assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 500
    dead[0] = False
    assert len(code_issuer.store.items("collecting")) == 1
    pending = {"transaction_id": transaction_id, "interval": code_issuer.settings.deferred_interval}
    for seconds in (0, 59):
        clock.now += seconds
        waiting = deferred(code_wallet, {"transaction_id": transaction_id})
        assert waiting.status_code == 202 and waiting.json() == pending, waiting.text
    clock.now += 1
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 200


# --- the issuances one login may have waiting for review --------------------------------------------------------------


ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def ask_again(wallet: CodeWallet) -> Any:
    """Another ask under the same login: a refreshed token, new keys."""
    wallet.token = wallet.refresh_request().json()["access_token"]
    return wallet.issue([EcKey.generate()])


def test_a_login_has_three_issuances_of_a_configuration_waiting_and_no_more(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """Every refresh gives a token that may ask again: without a bound one login under review filled the operator's
    list, the store and the audit log, a row and an entry for each ask, for as long as its refresh token lived."""
    subject_ref, _ = hold(code_wallet, code_issuer)
    assert [ask_again(code_wallet).status_code for _ in range(2)] == [202, 202]
    refused = ask_again(code_wallet)
    assert refused.status_code == 400 and refused.json()["error"] == "credential_request_denied", refused.text
    assert "waiting for the issuer's review" in refused.json()["error_description"]
    assert len(held_refs(code_wallet)) == 3
    logged = [e for e in code_issuer.audit.entries() if e["event"] == "credential.deferred"]
    assert len(logged) == 3, "a refused ask leaves no entry"
    assert ask_again(code_wallet).status_code == 400, "and a refused ask took no place: the bound still holds"

    # A hold of another configuration is not counted against this one.
    key = next(k for k, _ in code_issuer.store.items("deferred", f"{subject_ref}:"))
    row = code_issuer._held(key)
    assert row is not None
    code_issuer._keep_held(key, {**row, "config": "another.configuration"})
    assert ask_again(code_wallet).status_code == 202
    assert ask_again(code_wallet).status_code == 400

    # Once the operator has refused one, the wallet learns of it by asking, and the row stays until it runs out:
    # a refused issuance still counts, so refusing does not open the door to the next ask.
    decide(code_wallet, held_refs(code_wallet)[0], "refuse")
    assert ask_again(code_wallet).status_code == 400


# --- what an erasure says it found ------------------------------------------------------------------------------------


def test_an_erasure_says_data_was_held_when_it_removes_an_unswept_vault_entry(
    wallet: Wallet, issuer: Issuer, clock: Clock
) -> None:
    subject_ref = wallet.offer(PID_SUBJECT)["subject_ref"]
    clock.now += issuer.settings.offer_ttl + issuer.settings.access_token_ttl + 1  # the window ended, no sweep yet

    assert issuer.store.peek("vault-key", subject_ref) is not None, "the wrapped key is still in the database"
    assert issuer.store.peek("vault", subject_ref) is not None, "and so is the ciphertext of the person's data"

    erased = wallet.client.post(f"/admin/subjects/{subject_ref}/erase", headers=ADMIN)
    assert erased.status_code == 204, erased.text
    assert issuer.store.peek("vault-key", subject_ref) is None, "the erasure removed it"

    entry = issuer.audit.entries()[-1]
    assert entry["event"] == "subject.erased"
    assert entry["data"]["data_held"] is True, "the log says nothing was held, though the erasure just deleted it"


# --- the rows a login leaves when its subject is closed ---------------------------------------------------------------


@pytest.mark.parametrize("close", ["erase", "revoke", "cancel"])
def test_closing_a_subject_removes_the_rows_of_its_login(
    code_wallet: CodeWallet, code_issuer: Issuer, close: str
) -> None:
    subject_ref = held_login(code_wallet, code_issuer, review=False)
    if close == "erase":
        done = code_wallet.client.post(f"/admin/subjects/{subject_ref}/erase", headers=ADMIN)
    elif close == "revoke":
        body = {"subject_ref": subject_ref, "reason": "user_request"}
        done = code_wallet.client.post("/admin/revocations", json=body, headers=ADMIN)
    else:
        done = code_wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=ADMIN)
    assert done.status_code in (200, 204), done.text
    assert code_wallet.refresh_request().status_code == 400, "the refresh token is of no use any more"

    left = {
        namespace: [json.dumps(row) for _, row in code_issuer.store.items(namespace) if subject_ref in json.dumps(row)]
        for namespace in ("refresh", "code-spent")
    }
    assert not left["refresh"], (
        "the refresh token row is still stored, with the wallet instance's key thumbprint and the status entry of "
        f"its wallet attestation next to the subject reference: {sorted(json.loads(left['refresh'][0]))}"
    )
    assert not left["code-spent"], "and so is the spent-code row of the login"
    assert code_issuer.store.peek("subject-login", subject_ref) is None, "nor the note of where the two were"


# --- an attestation ends with its document, whatever the rulebook calls that day --------------------------------------


HIID = "eu.europa.ec.eudi.hiid_sd_jwt_vc"
HIID_MDOC = "eu.europa.ec.eudi.hiid_mdoc"
HIID_NAMESPACE = "eu.europa.ec.eudi.hiid.1"


def hiid(expiry_date: Any) -> dict[str, Any]:
    return {
        "affiliation_country": "PT",
        "issuance_date": "2026-11-04",
        "expiry_date": expiry_date,
        "issuing_authority": "Autoridade de Teste",
        "issuing_country": "PT",
    }


def test_an_expired_document_is_not_offered_as_sd_jwt_vc(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    issuer = make_issuer(**mdoc_settings(pki, published_configurations=(HIID, HIID_MDOC)))
    wallet = wallet_for(issuer)
    expired = hiid("2020-01-01")
    twin = wallet.admin("offers", {"credential_configuration_ids": [HIID_MDOC], "subject": {HIID_NAMESPACE: expired}})
    assert twin.status_code == 400 and "is in the past" in twin.text, twin.text  # the mdoc of the same rulebook
    offer = wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": expired})
    assert offer.status_code == 400, "cunho offers the SD-JWT VC of a document that expired in 2020"
    assert "expiry_date: is in the past" in offer.json()["error_description"]


def test_an_end_that_is_no_date_is_not_offered_as_sd_jwt_vc(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet]
) -> None:
    """A day cunho cannot read would not end the credential either."""
    wallet = wallet_for(make_issuer(profile="eaa_provider"))
    for end in ("2031-13-01", "soon", 20310101):
        offer = wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": hiid(end)})
        assert offer.status_code == 400, f"{end!r}: {offer.text}"
        assert "expiry_date: must be a calendar date YYYY-MM-DD" in offer.json()["error_description"], end


def test_the_sd_jwt_vc_ends_with_its_document(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], clock: Clock
) -> None:
    issuer = make_issuer(profile="eaa_provider")
    wallet = wallet_for(issuer)
    tomorrow = dt.datetime.fromtimestamp(clock.now, dt.UTC).date() + dt.timedelta(days=1)
    offer = wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": hiid(tomorrow.isoformat())})
    assert offer.status_code == 201, offer.text
    wallet.get_token(offer.json())
    response = wallet.issue(config=HIID)
    assert response.status_code == 200, response.text
    payload = disclosures(response.json()["credentials"][0]["credential"])[1]
    ends = dt.datetime.fromtimestamp(payload["exp"], dt.UTC)
    assert ends.date() <= tomorrow, (
        f"the document ends on {tomorrow}; the credential is technically valid until {ends:%Y-%m-%d %H:%M} UTC"
    )


# --- an offer used up by wrong transaction codes ----------------------------------------------------------------------


def _lock_out(wallet: Wallet, issuer: Issuer) -> dict[str, Any]:
    """An offer with a PIN, and as many wrong guesses as the deployment allows."""
    offer = wallet.offer(tx=6)
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    right = str(offer["tx_code"])
    wrong = "000000" if right != "000000" else "111111"
    for _ in range(issuer.settings.tx_code_max_attempts):
        assert wallet.token_request(code, tx_code=wrong).json()["error"] == "invalid_grant"
    dead = wallet.token_request(code, tx_code=right)
    assert dead.status_code == 400 and dead.json()["error"] == "invalid_grant", "the offer is gone, as designed"
    return offer


def test_a_pin_lockout_is_logged_as_the_end_of_the_offer(
    wallet: Wallet, issuer: Issuer, caplog: pytest.LogCaptureFixture
) -> None:
    """Five wrong PINs ended the offer and neither the audit log nor cunho.security said so: an operator could not
    tell PINs being guessed from an offer nobody used."""
    with caplog.at_level(logging.INFO, logger="cunho.security"):
        offer = _lock_out(wallet, issuer)
    [entry] = [e for e in issuer.audit.entries() if e["event"] == "offer.cancelled"]
    assert entry["actor"] == "cunho"
    assert entry["data"] == {"subject_ref": offer["subject_ref"], "cause": "tx_code_attempts"}
    said = [record.getMessage() for record in caplog.records if record.name == "cunho.security"]
    assert said == ["an offer was ended by wrong transaction codes"], "once, and with nothing of the offer in it"
    assert issuer.audit.verify()[0]
    progress = wallet.client.get(f"/admin/offers/{offer['subject_ref']}", headers=ADMIN).json()
    assert progress["state"] == "expired", "as the operator's pages are told to expect of an offer used up"


def test_a_pin_lockout_erases_the_data_nothing_can_be_issued_from(wallet: Wallet, issuer: Issuer) -> None:
    offer = _lock_out(wallet, issuer)
    assert issuer.store.get("vault-key", offer["subject_ref"]) is None, "the person's data is still in the vault"
    assert issuer.store.items("offer") == [], "the offer's own row, with the MAC of its PIN, is gone"
    assert issuer.store.items("subject-offer") == []


def test_a_lockout_that_comes_after_the_right_code_ends_nothing(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Wallet],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Two token requests read the same offer. The one with the right code takes it and has its token; the other
    then reaches the limit of wrong codes. It ends nothing: the offer is redeemed, and the data its token is to be
    issued from stays where it is (the second reviewer: the lockout erased it)."""
    issuer = make_issuer(tx_code_max_attempts=2)
    wallet = wallet_for(issuer)
    offer = wallet.offer(tx=6)
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    right = str(offer["tx_code"])
    wrong = "000000" if right != "000000" else "111111"
    assert wallet.token_request(code, tx_code=wrong).json()["error_description"] == "wrong tx_code"
    count = issuer.store.incr
    between: list[Any] = []

    def incr(namespace: str, *rest: Any) -> int:
        if namespace == "tx-attempts" and not between:
            between.append(None)  # the request made here counts its own attempt first
            between[0] = wallet.token_request(code, tx_code=right)
        return count(namespace, *rest)

    monkeypatch.setattr(issuer.store, "incr", incr)
    with caplog.at_level(logging.INFO, logger="cunho.security"):
        late = wallet.token_request(
            code, tx_code=wrong
        )  # it has read the offer; the right code comes in before it counts
    [redeemed] = between
    assert redeemed.status_code == 200, redeemed.text
    assert late.status_code == 400 and late.json()["error_description"] == "too many wrong tx_code attempts"
    assert [e for e in issuer.audit.entries() if e["event"] == "offer.cancelled"] == []
    assert "an offer was ended by wrong transaction codes" not in [r.getMessage() for r in caplog.records]
    assert issuer.store.get("vault-key", offer["subject_ref"]) is not None, "the data of a redeemed offer was erased"
    wallet.token = redeemed.json()["access_token"]
    assert wallet.issue().status_code == 200
    progress = wallet.client.get(f"/admin/offers/{offer['subject_ref']}", headers=ADMIN).json()
    assert progress["state"] == "issued"
    assert issuer.audit.verify()[0]


# --- lifetimes that must not shrink with the settings -----------------------------------------------------------------


def test_the_pin_lockout_holds_for_an_offer_that_outlives_a_shorter_offer_ttl(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], clock: Clock, tmp_path: Path
) -> None:
    def start(offer_ttl: int) -> Issuer:
        """cunho on the same database, keys and anchor, as after a restart."""
        return make_issuer(
            store=SqliteStore(tmp_path / "store.db", clock),
            secret_key_file=tmp_path / "master.key",
            audit_anchor_path=tmp_path / "audit.anchor",
            offer_ttl=offer_ttl,
        )

    offer = wallet_for(start(3600)).offer(tx=4)
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    right = str(offer["tx_code"])
    guesses = (f"{n:04d}" for n in range(10_000) if f"{n:04d}" != right)

    issuer = start(60)  # the operator shortened the lifetime of new offers and restarted
    wallet = wallet_for(issuer)
    limit = issuer.settings.tx_code_max_attempts
    answers = []
    for _ in range(3):  # three minutes of an offer that has an hour to live
        for _ in range(limit - 1):
            answers.append(wallet.token_request(code, tx_code=next(guesses)).json()["error_description"])
        clock.now += 61
    compared = answers.count("wrong tx_code")
    assert compared <= limit, f"{compared} wrong PINs were compared against the offer; the limit is {limit}"
    redeemed = wallet.token_request(code, tx_code=right)
    assert redeemed.status_code == 400, "the offer is still redeemed after more wrong PINs than the limit allows"


def test_one_request_uri_completes_one_login_across_a_restart_with_shorter_lifetimes(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Path,
) -> None:
    def start(par_ttl: int, login_ttl: int) -> Issuer:
        return make_code_issuer(
            store=SqliteStore(tmp_path / "store.db", clock),
            secret_key_file=tmp_path / "master.key",
            audit_anchor_path=tmp_path / "audit.anchor",
            par_ttl=par_ttl,
            login_ttl=login_ttl,
        )

    def report(wallet: CodeWallet, login_state: str) -> int:
        answer = wallet.client.post(
            f"/admin/logins/{login_state}",
            json={"subject": PID_SUBJECT, "loa": "high"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        return int(answer.status_code)

    before = start(599, 600)
    wallet = code_wallet_for(before)
    pushed = wallet.par(Pkce.random(), scope=pid_scope(before), state="st")
    assert pushed.status_code == 201, pushed.text
    request_uri = pushed.json()["request_uri"]
    first, second = (
        Redirect(303, wallet.authorize(request_uri).headers["location"]).params["login_state"] for _ in "ab"
    )

    after = code_wallet_for(start(1, 1))  # shorter lifetimes for new requests, and a restart
    assert report(after, first) == 200
    assert report(after, second) == 404, "another login from the same request_uri completed first"
    # The mark, made for par_ttl + login_ttl as they read now, is gone; the second login has minutes left to live.
    clock.now += 3
    assert report(after, second) == 404, "one request_uri completed two logins"


# --- a refresh after a scope of its authorization stopped naming a configuration --------------------------------------


def test_a_refresh_whose_scope_is_no_longer_published_is_answered_not_a_500(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """The token response looked the authorization's scopes up as if each had to be there still: after a restart
    with a configuration published under another scope, every refresh of an earlier login was an internal error."""
    granted = refreshable(code_wallet, code_issuer)
    assert granted["scope"] == pid_scope(code_issuer)
    code_issuer.authorization.scopes = {"renamed_scope": PID_CONFIG}  # as after that restart
    renewed = code_wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    assert "scope" not in renewed.json(), "a scope that names nothing any more is not said to be granted"
    code_wallet.token = renewed.json()["access_token"]
    assert code_wallet.issue([EcKey.generate()]).status_code == 200, "the authorization itself still stands"
