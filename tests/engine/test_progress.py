"""The operator's reads for its own pages (M5 piece A): how far a subject has got (`GET /admin/offers/{subject_ref}`)
and what a pending login is for (`GET /admin/logins/{login_state}`). Both are operator-only and carry no subject
data, code, token or transaction_id."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet, Pkce, Redirect, pushed
from .helpers import ADMIN_TOKEN, PID_CONFIG, PID_SUBJECT, PRE_AUTH, Wallet
from .test_deferred import decide, deferred, held_login, held_refs, hold, notify
from .test_review5_revocation import NATIONAL, two  # noqa: F401 - the fixture

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def progress(wallet: Wallet, subject_ref: str) -> dict[str, Any]:
    response = wallet.client.get(f"/admin/offers/{subject_ref}", headers=ADMIN)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    body: dict[str, Any] = response.json()
    assert set(body) == {"subject_ref", "state", "expires", "configurations", "refusal"}
    assert body["subject_ref"] == subject_ref
    return body


def states(body: dict[str, Any]) -> dict[str, tuple[str, str | None]]:
    return {c["id"]: (c["state"], c["notification"]) for c in body["configurations"]}


def no_subject_data(body: Any) -> None:
    text = json.dumps(body)
    for value in ("Silva", "Ana", "1990", "Porto"):
        assert value not in text, value


def test_a_pre_authorized_offer_from_offered_to_stored(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    subject_ref = offer["subject_ref"]
    first = progress(wallet, subject_ref)
    assert first["state"] == "offered"
    assert first["expires"] == int(wallet.clock()) + issuer.settings.offer_ttl
    assert states(first) == {PID_CONFIG: ("pending", None)}
    wallet.get_token(offer)
    redeemed = progress(wallet, subject_ref)
    assert redeemed["state"] == "redeemed" and redeemed["expires"] is None
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text
    done = progress(wallet, subject_ref)
    assert done["state"] == "issued" and states(done) == {PID_CONFIG: ("issued", None)}
    notification_id = issued.json()["notification_id"]
    assert notify(wallet, {"notification_id": notification_id, "event": "credential_accepted"}).status_code == 204
    assert states(progress(wallet, subject_ref)) == {PID_CONFIG: ("issued", "credential_accepted")}
    assert notify(wallet, {"notification_id": notification_id, "event": "credential_deleted"}).status_code == 204
    assert states(progress(wallet, subject_ref)) == {PID_CONFIG: ("issued", "credential_deleted")}
    # A repeat of an earlier event is not news: the newest one the wallet reported stays.
    assert notify(wallet, {"notification_id": notification_id, "event": "credential_accepted"}).status_code == 204
    final = progress(wallet, subject_ref)
    assert states(final) == {PID_CONFIG: ("issued", "credential_deleted")}
    no_subject_data(final)
    assert notification_id not in json.dumps(final)


def test_one_configuration_of_two_issued(two: tuple[Wallet, Issuer]) -> None:  # noqa: F811
    wallet, _ = two
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    assert wallet.issue(config=NATIONAL).status_code == 200
    body = progress(wallet, offer["subject_ref"])
    assert body["state"] == "redeemed"
    assert states(body) == {PID_CONFIG: ("pending", None), NATIONAL: ("issued", None)}
    assert [c["id"] for c in body["configurations"]] == sorted([PID_CONFIG, NATIONAL])
    assert wallet.issue(config=PID_CONFIG).status_code == 200
    assert progress(wallet, offer["subject_ref"])["state"] == "issued"


def test_an_offer_nobody_scanned_expires(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    wallet.clock.now += issuer.settings.offer_ttl - 1
    assert progress(wallet, offer["subject_ref"])["state"] == "offered"
    wallet.clock.now += 1
    body = progress(wallet, offer["subject_ref"])
    assert body["state"] == "expired" and body["expires"] is None
    assert states(body) == {PID_CONFIG: ("pending", None)}


def test_a_redeemed_offer_does_not_read_expired(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    wallet.get_token(offer)
    wallet.clock.now += issuer.settings.offer_ttl + 1
    assert progress(wallet, offer["subject_ref"])["state"] == "redeemed"


def test_an_offer_burned_by_wrong_tx_codes_reads_expired(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer(tx=6)
    code = offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    wrong = "000000" if offer["tx_code"] != "000000" else "111111"
    for _ in range(issuer.settings.tx_code_max_attempts):
        assert wallet.token_request(code["pre-authorized_code"], tx_code=wrong).status_code == 400
    assert progress(wallet, offer["subject_ref"])["state"] == "expired"


@pytest.mark.parametrize("ending", ["revoke", "cancel", "erase"])
def test_a_closed_subject_reads_closed(wallet: Wallet, ending: str) -> None:
    offer = wallet.offer()
    subject_ref = offer["subject_ref"]
    if ending == "revoke":
        wallet.get_token(offer)
        assert wallet.issue().status_code == 200
        answer = wallet.admin("revocations", {"subject_ref": subject_ref, "reason": "user_request"})
    elif ending == "cancel":
        answer = wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=ADMIN)
    else:
        answer = wallet.client.post(f"/admin/subjects/{subject_ref}/erase", headers=ADMIN)
    assert answer.status_code in (200, 204), answer.text
    body = progress(wallet, subject_ref)
    assert body["state"] == "closed" and body["expires"] is None


def test_a_held_issuance_through_review(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    subject_ref = held_login(code_wallet, code_issuer)
    assert progress(code_wallet, subject_ref)["state"] == "redeemed"
    response = code_wallet.issue([EcKey.generate()])
    assert response.status_code == 202, response.text
    transaction_id = response.json()["transaction_id"]
    held = progress(code_wallet, subject_ref)
    assert held["state"] == "redeemed" and states(held) == {PID_CONFIG: ("held", None)}
    assert transaction_id not in json.dumps(held)
    [ref] = held_refs(code_wallet)
    assert ref not in json.dumps(held), "the operator's reference to the held issuance is the deferred list's"
    decide(code_wallet, ref, "release")
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("released", None)}
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 200
    collected = progress(code_wallet, subject_ref)
    assert collected["state"] == "issued" and states(collected) == {PID_CONFIG: ("issued", None)}


def test_a_refused_review(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    subject_ref, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    decide(code_wallet, ref, "refuse")
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("refused", None)}
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 400
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("refused", None)}, "until the review ends"


def code_login(code_wallet: CodeWallet, code_issuer: Issuer, pkce: Pkce) -> tuple[str, str]:
    """A login reported for the PID; the subject reference and the URL the browser is sent on to."""
    request_uri, _ = pushed(code_wallet, code_issuer, pkce)
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    reported = code_wallet.client.post(
        f"/admin/logins/{login_state}", json={"subject": PID_SUBJECT, "loa": "high"}, headers=ADMIN
    )
    assert reported.status_code == 200, reported.text
    return reported.json()["subject_ref"], reported.json()["continue"]


def test_a_code_flow_login_reads_offered_until_its_code_is_redeemed(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    pkce = Pkce.random()
    subject_ref, resume = code_login(code_wallet, code_issuer, pkce)
    settings = code_issuer.settings
    body = progress(code_wallet, subject_ref)
    assert body["state"] == "offered"
    assert body["expires"] == int(code_wallet.clock()) + settings.login_ttl, "the browser has the login's life"
    code_wallet.clock.now += 5
    back = code_wallet.client.get(resume, follow_redirects=False)
    code = Redirect(303, back.headers["location"]).params["code"]
    after = progress(code_wallet, subject_ref)
    assert after["expires"] == int(code_wallet.clock()) + settings.code_ttl, "then the code's"
    assert code_wallet.code_token_request(code, pkce).status_code == 200
    assert progress(code_wallet, subject_ref)["state"] == "redeemed"


def test_a_code_nobody_redeemed_expires_with_it(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """The second reviewer: the login's deadline went on being shown after the code it led to ran out."""
    subject_ref, resume = code_login(code_wallet, code_issuer, Pkce.random())
    assert code_wallet.client.get(resume, follow_redirects=False).status_code == 303
    code_wallet.clock.now += code_issuer.settings.code_ttl - 1
    assert progress(code_wallet, subject_ref)["state"] == "offered"
    code_wallet.clock.now += 1
    assert progress(code_wallet, subject_ref)["state"] == "expired"


def test_a_login_the_browser_never_came_back_from_expires(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    subject_ref, _ = code_login(code_wallet, code_issuer, Pkce.random())
    code_wallet.clock.now += code_issuer.settings.login_ttl
    assert progress(code_wallet, subject_ref)["state"] == "expired"


def test_completion_is_judged_against_everything_offered(two: tuple[Wallet, Issuer]) -> None:  # noqa: F811
    """The second reviewer: once what the offer could still yield had expired, one configuration of two issued
    read as all of them."""
    wallet, issuer = two
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    assert wallet.issue(config=NATIONAL).status_code == 200
    wallet.clock.now += issuer.settings.offer_ttl + issuer.settings.access_token_ttl + 1
    assert issuer.store.get("subject-open", offer["subject_ref"]) is None, "the case the reviewer named"
    body = progress(wallet, offer["subject_ref"])
    assert body["state"] == "redeemed"
    assert states(body) == {PID_CONFIG: ("pending", None), NATIONAL: ("issued", None)}


def test_a_narrowed_token_is_judged_by_what_it_covers(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], tmp_path: Path
) -> None:
    """A login for two configurations whose token request names one: the one left out can never be issued, so
    issuing the other completes the subject."""
    from .test_authorize_negative import _two_pids, code_of, pid_scope

    issuer = make_code_issuer(metadata_dir=_two_pids(tmp_path), published_configurations=(PID_CONFIG, "x.pid_copy"))
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    code = code_of(wallet, issuer, pkce, scope=f"{pid_scope(issuer)} x.pid_copy")
    subject_ref = issuer.audit.entries()[-1]["data"]["subject_ref"]
    assert {c["id"] for c in progress(wallet, subject_ref)["configurations"]} == {PID_CONFIG, "x.pid_copy"}
    details = json.dumps([{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}])
    body = wallet.code_token_request(code, pkce, extra={"authorization_details": details}).json()
    wallet.token = body["access_token"]
    [identifier] = body["authorization_details"][0]["credential_identifiers"]
    proof = wallet.proof(EcKey.generate(), wallet.c_nonce())
    issued = wallet.credential_request({"credential_identifier": identifier, "proofs": {"jwt": [proof]}})
    assert issued.status_code == 200, issued.text
    done = progress(wallet, subject_ref)
    assert done["state"] == "issued" and states(done) == {PID_CONFIG: ("issued", None)}


def test_only_a_reference_this_issuer_handed_out(wallet: Wallet) -> None:
    for unknown in ("sub_" + "A" * 24, "nothing", "sub_"):
        response = wallet.client.get(f"/admin/offers/{unknown}", headers=ADMIN)
        assert response.status_code == 404 and response.json()["error"] == "invalid_request", unknown


def test_the_reads_need_the_operator_token(wallet: Wallet) -> None:
    subject_ref = wallet.offer()["subject_ref"]
    for path in (f"/admin/offers/{subject_ref}", "/admin/logins/anything"):
        for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"DPoP {ADMIN_TOKEN}"}):
            response = wallet.client.get(path, headers=headers)
            assert response.status_code == 401, (path, headers)
            assert "subject" not in response.text


def test_a_pending_login_says_what_it_is_for(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer, Pkce.random())
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    response = code_wallet.client.get(f"/admin/logins/{login_state}", headers=ADMIN)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "configuration_ids": [PID_CONFIG],
        "client": code_wallet.client_id,
        "wallet_name": "cunho test wallet",
        "wallet_version": "1.0.0",
        "offer_ref": None,
        "expires": int(code_wallet.clock()) + code_issuer.settings.login_ttl,
    }
    reported = code_wallet.client.post(f"/admin/logins/{login_state}", json={"denied": True}, headers=ADMIN)
    assert reported.status_code == 200
    gone = code_wallet.client.get(f"/admin/logins/{login_state}", headers=ADMIN)
    assert gone.status_code == 404 and gone.json()["error"] == "invalid_request"


def test_a_pending_login_without_wallet_name(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """An attestation that names no wallet solution leaves the names out, never guessed."""
    original = code_wallet.attestation

    def unnamed(**claims: Any) -> str:
        return original(**{"wallet_name": ..., "wallet_version": ..., **claims})

    code_wallet.attestation = unnamed  # type: ignore[method-assign]
    request_uri, _ = pushed(code_wallet, code_issuer, Pkce.random())
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    body = code_wallet.client.get(f"/admin/logins/{login_state}", headers=ADMIN).json()
    assert body["wallet_name"] is None and body["wallet_version"] is None


def test_an_expired_login_is_not_found(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer, Pkce.random())
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    code_wallet.clock.now += code_issuer.settings.login_ttl
    assert code_wallet.client.get(f"/admin/logins/{login_state}", headers=ADMIN).status_code == 404
    unknown = code_wallet.client.get("/admin/logins/" + "x" * 43, headers=ADMIN)
    assert unknown.status_code == 404


def test_a_review_held_after_an_earlier_issuance_shows(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """A refresh re-issues a held subject's credential: the new review is newer than the first issuance."""
    subject_ref, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    decide(code_wallet, ref, "release")
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 200
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("issued", None)}
    refreshed = code_wallet.refresh_request()
    assert refreshed.status_code == 200, refreshed.text
    code_wallet.token = refreshed.json()["access_token"]
    again = code_wallet.issue([EcKey.generate()])
    assert again.status_code == 202, again.text
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("held", None)}


def test_an_offer_burned_past_the_limit_reads_expired(wallet: Wallet, issuer: Issuer) -> None:
    """Attempts counted past the limit, as concurrent guesses can leave them, also use the offer up."""
    from cunho.oauth import _hash

    offer = wallet.offer(tx=6)
    code = offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    issuer.store.put("tx-attempts", _hash(code["pre-authorized_code"]), issuer.settings.tx_code_max_attempts, 600)
    assert wallet.token_request(code["pre-authorized_code"], tx_code=offer["tx_code"]).status_code == 400
    assert progress(wallet, offer["subject_ref"])["state"] == "expired"


# The second look: what a subject is for lives as long as its newest mark ------------------------------------


def test_a_late_token_keeps_what_the_subject_is_for(wallet: Wallet, issuer: Issuer) -> None:
    start = wallet.clock()
    offer = wallet.offer()
    wallet.clock.now += issuer.settings.offer_ttl - 1
    wallet.get_token(offer)
    wallet.clock.now = start + issuer.settings.subject_window + 1
    body = progress(wallet, offer["subject_ref"])
    assert body["state"] == "redeemed" and states(body) == {PID_CONFIG: ("pending", None)}


def test_a_late_issuance_keeps_the_subject_issued(wallet: Wallet, issuer: Issuer) -> None:
    """The second reviewer: a subject issued in full went back to redeemed, then expired, while its marks lived."""
    start = wallet.clock()
    offer = wallet.offer()
    wallet.get_token(offer)
    wallet.clock.now += issuer.settings.access_token_ttl - 1
    assert wallet.issue().status_code == 200
    wallet.clock.now = start + issuer.settings.subject_window + 1
    assert issuer.store.get("subject-token", offer["subject_ref"]) is None, "only the issuance's mark is left"
    assert progress(wallet, offer["subject_ref"])["state"] == "issued"


def test_a_late_notification_keeps_what_the_subject_is_for(two: tuple[Wallet, Issuer]) -> None:  # noqa: F811
    wallet, issuer = two
    start = wallet.clock()
    offer = wallet.offer(configs=[PID_CONFIG, NATIONAL])
    wallet.get_token(offer)
    issued = wallet.issue(config=NATIONAL)
    wallet.clock.now += issuer.settings.access_token_ttl - 1
    accepted = {"notification_id": issued.json()["notification_id"], "event": "credential_accepted"}
    assert notify(wallet, accepted).status_code == 204
    wallet.clock.now = start + issuer.settings.subject_window + 1
    body = progress(wallet, offer["subject_ref"])
    assert states(body) == {PID_CONFIG: ("pending", None), NATIONAL: ("pending", "credential_accepted")}


def test_a_login_whose_sibling_completed_is_not_offered_for_consent(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """The second reviewer: a request_uri opened twice gives two logins; once one is reported, the other can no
    longer be, so it is not shown as waiting for consent."""
    request_uri, _ = pushed(code_wallet, code_issuer, Pkce.random())
    first = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    second = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    assert code_wallet.client.get(f"/admin/logins/{second}", headers=ADMIN).status_code == 200
    reported = code_wallet.client.post(
        f"/admin/logins/{first}", json={"subject": PID_SUBJECT, "loa": "high"}, headers=ADMIN
    )
    assert reported.status_code == 200, reported.text
    gone = code_wallet.client.get(f"/admin/logins/{second}", headers=ADMIN)
    assert gone.status_code == 404 and gone.json()["error"] == "invalid_request"
    late = code_wallet.client.post(f"/admin/logins/{second}", json={"denied": True}, headers=ADMIN)
    assert late.status_code == 404, "and its result could not be reported anyway"


# The third look: several reviews of one configuration, in the order they happened ---------------------------


def _ask_again(code_wallet: CodeWallet) -> str:
    """A refresh, and the configuration asked for again: held, as every ask of a subject under review."""
    refreshed = code_wallet.refresh_request()
    assert refreshed.status_code == 200, refreshed.text
    code_wallet.token = refreshed.json()["access_token"]
    again = code_wallet.issue([EcKey.generate()])
    assert again.status_code == 202, again.text
    return str(again.json()["transaction_id"])


def test_a_refused_review_does_not_hide_a_later_one(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """The second reviewer: an older refused review overwrote a newer held one, and later the issuance itself."""
    subject_ref, first = hold(code_wallet, code_issuer)
    [refused] = held_refs(code_wallet)
    decide(code_wallet, refused, "refuse")
    assert deferred(code_wallet, {"transaction_id": first}).status_code == 400
    code_wallet.clock.now += 1
    second = _ask_again(code_wallet)
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("held", None)}
    [newer] = [ref for ref in held_refs(code_wallet) if ref != refused]
    decide(code_wallet, newer, "release")
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("released", None)}
    code_wallet.clock.now += 1
    assert deferred(code_wallet, {"transaction_id": second}).status_code == 200
    done = progress(code_wallet, subject_ref)
    assert done["state"] == "issued" and states(done) == {PID_CONFIG: ("issued", None)}


def test_reviews_and_issuances_within_one_second_keep_their_order(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    code_wallet.clock.now += 0.1
    subject_ref, first = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    decide(code_wallet, ref, "release")
    code_wallet.clock.now += 0.2
    assert deferred(code_wallet, {"transaction_id": first}).status_code == 200
    code_wallet.clock.now += 0.3
    _ask_again(code_wallet)
    assert states(progress(code_wallet, subject_ref)) == {PID_CONFIG: ("held", None)}


def test_a_login_names_the_offer_it_came_from(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """A demo page that showed a code-flow offer finds the login its wallet started, by the offer's reference."""
    made = code_wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "grant": "authorization_code"})
    assert made.status_code == 201, made.text
    issuer_state = made.json()["credential_offer"]["grants"]["authorization_code"]["issuer_state"]
    reference = made.json()["offer_ref"]
    assert len(reference) == 32 and reference not in issuer_state
    request_uri, _ = pushed(code_wallet, code_issuer, Pkce.random(), issuer_state=issuer_state)
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    body = code_wallet.client.get(f"/admin/logins/{login_state}", headers=ADMIN).json()
    assert body["offer_ref"] == reference
    other = code_wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "grant": "authorization_code"})
    assert other.json()["offer_ref"] != reference


def test_a_refused_credential_request_says_why_until_the_credential_is_issued(wallet: Wallet) -> None:
    """While the subject is redeemed, the last credential request refused shows by error code and rule only; the
    description (which may repeat the request) is never kept, and once the credential is issued it is gone."""
    offer = wallet.offer()
    subject_ref = offer["subject_ref"]
    wallet.get_token(offer)
    assert progress(wallet, subject_ref)["refusal"] is None
    holder = EcKey.generate()
    proof = wallet.proof(holder, wallet.c_nonce(), iat=0)
    refused = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert refused.status_code == 400
    body = progress(wallet, subject_ref)
    assert body["state"] == "redeemed"
    assert body["refusal"] == {"error": "invalid_proof", "rule": "VCI.F1.PROOF_IAT"}
    assert refused.json()["error_description"] not in json.dumps(body)
    assert wallet.issue().status_code == 200
    assert progress(wallet, subject_ref)["refusal"] is None


def test_a_token_request_refused_for_a_live_offer_says_why_until_a_token_is_minted(wallet: Wallet) -> None:
    """A wallet that sends no DPoP proof (Sphereon's released client) is refused at the token endpoint; the page
    learns why while the offer still waits, and once a wallet gets a token the old refusal is gone."""
    offer = wallet.offer()
    subject_ref = offer["subject_ref"]
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    refused = wallet.token_request(code, dpop=None)
    assert refused.status_code == 400 and refused.json()["error"] == "invalid_dpop_proof"
    body = progress(wallet, subject_ref)
    assert body["state"] == "offered"
    assert body["refusal"] == {"error": "invalid_dpop_proof", "rule": "OAUTH.DPOP_REQUIRED"}
    assert refused.json()["error_description"] not in json.dumps(body)
    wallet.get_token(offer)
    body = progress(wallet, subject_ref)
    assert body["state"] == "redeemed" and body["refusal"] is None


def test_a_token_request_with_an_unknown_code_notes_nothing(wallet: Wallet) -> None:
    offer = wallet.offer()
    subject_ref = offer["subject_ref"]
    assert wallet.token_request("made-up", dpop=None).status_code == 400
    assert wallet.token_request("made-up").status_code == 400
    assert progress(wallet, subject_ref)["refusal"] is None
