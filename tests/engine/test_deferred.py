"""Deferred issuance held for the operator's review, and the wallet's notifications (OpenID4VCI 1.0 §8.3, §9, §11).

The operator holds a subject's credentials by saying `review` in the login result; the wallet's credential request is
checked in full and answered 202 with a transaction_id; the operator releases or refuses through the admin API; the
wallet collects at the deferred credential endpoint with any token of the same login. Notifications are logged once
per event and never carry the wallet's free text into the log."""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import functools
import json
from typing import Any

import pytest

from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet, Pkce, Redirect, pushed
from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PID_SUBJECT, Clock, Wallet, refused_by

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def held_login(wallet: CodeWallet, issuer: Issuer, *, review: Any = True) -> str:
    """A code-flow login the operator reports with `review`; the wallet ends up holding its tokens. The subject
    reference."""
    pkce = Pkce.random()
    request_uri, _ = pushed(wallet, issuer, pkce)
    location = wallet.authorize(request_uri).headers["location"]
    login_state = Redirect(303, location).params["login_state"]
    reported = wallet.client.post(
        f"/admin/logins/{login_state}", json={"subject": PID_SUBJECT, "loa": "high", "review": review}, headers=ADMIN
    )
    assert reported.status_code == 200, reported.text
    back = wallet.client.get(reported.json()["continue"], follow_redirects=False)
    code = Redirect(303, back.headers["location"]).params["code"]
    tokens = wallet.code_token_request(code, pkce)
    assert tokens.status_code == 200, tokens.text
    wallet.token, wallet.refresh_token = tokens.json()["access_token"], tokens.json()["refresh_token"]
    return str(reported.json()["subject_ref"])


def deferred(wallet: Wallet, body: Any, *, raw: bytes | None = None, token: str | None = None) -> Any:
    token = token or wallet.token
    assert token is not None
    proof = wallet.dpop("POST", f"{ISSUER}/deferred_credential", access_token=token)
    headers = {"Authorization": f"DPoP {token}", "DPoP": proof, "Content-Type": "application/json"}
    return wallet.client.post("/deferred_credential", content=raw or json.dumps(body).encode(), headers=headers)


def notify(wallet: Wallet, body: Any, *, raw: bytes | None = None) -> Any:
    assert wallet.token is not None
    proof = wallet.dpop("POST", f"{ISSUER}/notification", access_token=wallet.token)
    headers = {"Authorization": f"DPoP {wallet.token}", "DPoP": proof, "Content-Type": "application/json"}
    return wallet.client.post("/notification", content=raw or json.dumps(body).encode(), headers=headers)


def held_refs(wallet: Wallet) -> list[str]:
    listed = wallet.client.get("/admin/deferred", headers=ADMIN)
    assert listed.status_code == 200, listed.text
    return [row["ref"] for row in listed.json()["deferred"]]


def decide(wallet: Wallet, ref: str, decision: str) -> Any:
    return wallet.client.post(f"/admin/deferred/{ref}/{decision}", headers=ADMIN)


def events(issuer: Issuer) -> list[str]:
    return [e["event"] for e in issuer.audit.entries()]


def hold(wallet: CodeWallet, issuer: Issuer, keys: list[EcKey] | None = None) -> tuple[str, str]:
    """A held issuance: its subject reference and transaction_id."""
    subject_ref = held_login(wallet, issuer)
    response = wallet.issue(keys)
    assert response.status_code == 202, response.text
    body = response.json()
    assert set(body) == {"transaction_id", "interval"} and body["interval"] == issuer.settings.deferred_interval
    assert response.headers["cache-control"] == "no-store"
    return subject_ref, str(body["transaction_id"])


@pytest.mark.obligation("VCI.DEFER.TRANSACTION_ID")
def test_a_held_issuance_is_released_and_collected_once(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    key = EcKey.generate()
    subject_ref, transaction_id = hold(code_wallet, code_issuer, [key])
    assert code_issuer.store.items("issued") == [], "nothing is signed while it waits"
    waiting = deferred(code_wallet, {"transaction_id": transaction_id})
    assert waiting.status_code == 202 and waiting.json() == {
        "transaction_id": transaction_id,
        "interval": code_issuer.settings.deferred_interval,
    }
    [ref] = held_refs(code_wallet)
    assert decide(code_wallet, ref, "release").json() == {"state": "released"}
    collected = deferred(code_wallet, {"transaction_id": transaction_id})
    assert collected.status_code == 200, collected.text
    body = collected.json()
    assert len(body["credentials"]) == 1 and body["notification_id"]
    payload = json.loads(base64.urlsafe_b64decode(body["credentials"][0]["credential"].split(".")[1] + "=="))
    assert payload["cnf"]["jwk"]["x"] == key.public_jwk()["x"], "bound to the key proven when it was asked for"
    assert events(code_issuer)[-3:] == ["credential.deferred", "credential.released", "credential.issued"]
    issued = code_issuer.audit.entries()[-1]["data"]
    assert issued["subject_ref"] == subject_ref and issued["transaction"] == ref
    again = refused_by(
        lambda: deferred(code_wallet, {"transaction_id": transaction_id}),
        "VCI.DEFER.TRANSACTION_ID",
        "already collected",
    )
    assert again.status_code == 400 and again.json()["error"] == "invalid_transaction_id"
    assert held_refs(code_wallet) == []


def test_the_held_request_was_checked_in_full_first(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """A bad proof is refused at once, not held: what is held is bound to keys already proven."""
    held_login(code_wallet, code_issuer)
    proof = code_wallet.proof(EcKey.generate(), "not-a-nonce-this-issuer-gave")
    refused = code_wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert refused.status_code == 400 and refused.json()["error"] in ("invalid_proof", "invalid_nonce")
    assert held_refs(code_wallet) == []


def test_a_repeated_request_gets_the_same_transaction(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    key = EcKey.generate()
    _, transaction_id = hold(code_wallet, code_issuer, [key])
    again = code_wallet.issue([key])
    assert again.status_code == 202 and again.json()["transaction_id"] == transaction_id
    assert len(held_refs(code_wallet)) == 1
    [ref] = held_refs(code_wallet)
    decide(code_wallet, ref, "release")
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 200
    after = code_wallet.issue([key])
    assert after.status_code == 400 and "already used" in after.json()["error_description"]


@pytest.mark.covers("VCI.DEFER.TRANSACTION_ID")
def test_a_refused_issuance_is_denied(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    assert decide(code_wallet, ref, "refuse").json() == {"state": "refused"}
    assert events(code_issuer)[-1] == "credential.refused"
    for _ in range(2):
        denied = refused_by(
            lambda: deferred(code_wallet, {"transaction_id": transaction_id}),
            "VCI.DEFER.TRANSACTION_ID",
            "refused this issuance",
        )
        assert denied.status_code == 400 and denied.json()["error"] == "credential_request_denied"
    assert code_issuer.store.items("issued") == []


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT")
def test_a_decision_is_taken_once(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    assert decide(code_wallet, ref, "release").status_code == 200
    for decision in ("release", "refuse"):
        again = refused_by(
            functools.partial(decide, code_wallet, ref, decision), "ISS.SUBJECT.ENTITLEMENT", "no issuance held"
        )
        assert again.status_code == 404
    for bad in ("0" * 32, "not-a-ref", ref.upper()):
        assert decide(code_wallet, bad, "release").status_code == 404
    stranger = code_wallet.client.post(f"/admin/deferred/{ref}/refuse")
    assert stranger.status_code == 401


@pytest.mark.covers("VCI.DEFER.TRANSACTION_ID")
def test_an_unknown_or_foreign_transaction_is_invalid(
    code_wallet: CodeWallet, code_issuer: Issuer, code_wallet_for: Any
) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    for body in ({"transaction_id": "nope"}, {"transaction_id": transaction_id + "x"}):
        unknown = refused_by(
            functools.partial(deferred, code_wallet, body), "VCI.DEFER.TRANSACTION_ID", "unknown transaction_id"
        )
        assert unknown.json()["error"] == "invalid_transaction_id"
    other = code_wallet_for(code_issuer)
    held_login(other, code_issuer, review=False)
    foreign = deferred(other, {"transaction_id": transaction_id})
    assert foreign.status_code == 400 and foreign.json()["error"] == "invalid_transaction_id", "another login's"


@pytest.mark.covers("VCI.DEFER.TRANSACTION_ID")
@pytest.mark.parametrize(
    "body",
    [None, [], {}, {"transaction_id": 1}, {"transaction_id": None}],
)
def test_a_malformed_deferred_request_is_refused(code_wallet: CodeWallet, code_issuer: Issuer, body: Any) -> None:
    hold(code_wallet, code_issuer)
    raw = b"{" if body is None else None
    response = refused_by(lambda: deferred(code_wallet, body, raw=raw), "VCI.DEFER.TRANSACTION_ID", "JSON object")
    assert response.status_code == 400 and response.json()["error"] == "invalid_credential_request"


def test_the_deferred_endpoint_needs_its_token(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    bare = code_wallet.client.post("/deferred_credential", json={"transaction_id": transaction_id})
    assert bare.status_code == 401 and "www-authenticate" in bare.headers
    wrong_url = code_wallet.dpop("POST", f"{ISSUER}/credential", access_token=code_wallet.token)
    headers = {"Authorization": f"DPoP {code_wallet.token}", "DPoP": wrong_url}
    bound = code_wallet.client.post("/deferred_credential", json={"transaction_id": transaction_id}, headers=headers)
    assert bound.status_code in (400, 401)
    query = code_wallet.client.post(f"/deferred_credential?access_token={code_wallet.token}", json={})
    assert query.status_code == 400
    proof = code_wallet.dpop("POST", f"{ISSUER}/deferred_credential", access_token=code_wallet.token)
    form = code_wallet.client.post(
        "/deferred_credential",
        content=b"transaction_id=x",
        headers={"Authorization": f"DPoP {code_wallet.token}", "DPoP": proof, "Content-Type": "text/plain"},
    )
    assert form.status_code == 400 and form.json()["error"] == "invalid_credential_request"


def test_a_refreshed_token_collects_after_the_first_expired(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    clock.now += 2 * 86_400  # the review took two days; the access token is long gone
    decide(code_wallet, ref, "release")
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 401
    renewed = code_wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    code_wallet.token = renewed.json()["access_token"]
    collected = deferred(code_wallet, {"transaction_id": transaction_id})
    assert collected.status_code == 200, collected.text


def test_a_held_issuance_ends_with_its_time(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    clock.now += code_issuer.settings.deferred_ttl
    assert decide(code_wallet, ref, "release").status_code == 404
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    gone = deferred(code_wallet, {"transaction_id": transaction_id})
    assert gone.status_code == 400 and gone.json()["error"] == "invalid_transaction_id"


@pytest.mark.parametrize("close", ["revocations", "cancel", "erase"])
def test_closing_the_subject_drops_what_is_held(code_wallet: CodeWallet, code_issuer: Issuer, close: str) -> None:
    subject_ref, transaction_id = hold(code_wallet, code_issuer)
    if close == "revocations":
        body = {"subject_ref": subject_ref, "reason": "user_request"}
        response = code_wallet.client.post("/admin/revocations", json=body, headers=ADMIN)
    elif close == "cancel":
        response = code_wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=ADMIN)
    else:
        response = code_wallet.client.post(f"/admin/subjects/{subject_ref}/erase", headers=ADMIN)
    assert response.status_code in (200, 204), response.text
    assert code_issuer.store.items("deferred") == [] and code_issuer.store.items("transaction") == []
    assert held_refs(code_wallet) == []
    denied = deferred(code_wallet, {"transaction_id": transaction_id})
    assert denied.status_code == 400 and denied.json()["error"] == "credential_request_denied"


def test_a_closure_between_the_read_and_the_entry_stops_the_collection(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two collections at once: the second finds the held row gone in the transaction of its log entry."""
    _, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    decide(code_wallet, ref, "release")
    validity = code_issuer._validity  # noqa: SLF001

    def raced(*args: Any) -> Any:
        for key, _ in code_issuer.store.items("deferred"):
            code_issuer.store.delete("deferred", key)  # another worker collected it meanwhile
        return validity(*args)

    monkeypatch.setattr(code_issuer, "_validity", raced)
    raced_away = deferred(code_wallet, {"transaction_id": transaction_id})
    assert raced_away.status_code == 400 and raced_away.json()["error"] == "invalid_transaction_id"
    assert code_issuer.store.items("issued") == [] and events(code_issuer)[-1] == "credential.released"


def test_a_held_subject_stays_cancellable(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    """Its offer window may have passed while the review goes on: what is held still counts as live."""
    subject_ref, _ = hold(code_wallet, code_issuer)
    clock.now += code_issuer.settings.login_ttl + code_issuer.settings.code_ttl + 3600
    response = code_wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=ADMIN)
    assert response.status_code == 200, response.text


def test_the_subject_data_is_kept_while_the_review_goes_on(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    subject_ref, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    clock.now += code_issuer.settings.deferred_ttl - 60
    assert code_issuer.store.get("vault-key", subject_ref) is not None
    decide(code_wallet, ref, "release")
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    assert deferred(code_wallet, {"transaction_id": transaction_id}).status_code == 200


@pytest.mark.covers("VCI.OFFER.SHAPE")
@pytest.mark.parametrize("review", [True, "yes", 1])
def test_a_pre_authorized_offer_cannot_be_held(wallet: Wallet, review: Any) -> None:
    body = {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, "review": review}
    response = refused_by(lambda: wallet.admin("offers", body), "VCI.OFFER.SHAPE", "review")
    assert response.status_code == 400


def test_an_unheld_offer_may_say_so(wallet: Wallet) -> None:
    body = {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, "review": False}
    assert wallet.admin("offers", body).status_code == 201


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT")
def test_review_in_a_login_result_is_a_boolean(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    request_uri, _ = pushed(code_wallet, code_issuer, pkce)
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    body = {"subject": PID_SUBJECT, "loa": "high", "review": "yes"}
    response = refused_by(
        lambda: code_wallet.client.post(f"/admin/logins/{login_state}", json=body, headers=ADMIN),
        "ISS.SUBJECT.ENTITLEMENT",
        "review must be true or false",
    )
    assert response.status_code == 400


def test_a_code_offer_takes_no_review(wallet: Wallet) -> None:
    body = {"credential_configuration_ids": [PID_CONFIG], "grant": "authorization_code", "review": True}
    response = wallet.admin("offers", body)
    assert response.status_code == 400 and "review" in response.json()["error_description"]


def test_an_unheld_login_issues_at_once(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    held_login(code_wallet, code_issuer, review=False)
    response = code_wallet.issue()
    assert response.status_code == 200 and response.json()["notification_id"]
    assert "credential.deferred" not in events(code_issuer)


def test_the_metadata_names_both_endpoints(wallet: Wallet) -> None:
    document = wallet.client.get("/.well-known/openid-credential-issuer").json()
    assert document["deferred_credential_endpoint"] == f"{ISSUER}/deferred_credential"
    assert document["notification_endpoint"] == f"{ISSUER}/notification"


# notification ------------------------------------------------------------------------------------------------------


@pytest.mark.obligation("VCI.NOTIF.VALIDATION")
def test_each_event_is_logged_once(wallet: Wallet, issuer: Issuer) -> None:
    issued = wallet.issue()
    notification_id = issued.json()["notification_id"]
    for _ in range(2):
        response = notify(wallet, {"notification_id": notification_id, "event": "credential_accepted"})
        assert response.status_code == 204 and response.content == b""
    deleted = {
        "notification_id": notification_id,
        "event": "credential_deleted",
        "event_description": "Zqxv wallet note",
    }
    assert notify(wallet, deleted).status_code == 204
    entries = [e for e in issuer.audit.entries() if e["event"] == "credential.notification"]
    assert [e["data"]["notice"] for e in entries] == ["credential_accepted", "credential_deleted"]
    assert entries[0]["data"]["configuration_id"] == PID_CONFIG
    assert "Zqxv" not in json.dumps(issuer.audit.entries()), "the wallet's free text is never logged"
    assert notification_id not in json.dumps(issuer.audit.entries())


def test_a_repeated_request_gives_the_same_notification_id(wallet: Wallet) -> None:
    key = EcKey.generate()
    first = wallet.issue([key])
    again = wallet.issue([key])
    assert again.json()["notification_id"] == first.json()["notification_id"]


def test_every_issuance_has_its_own_notification_id(wallet: Wallet) -> None:
    first = wallet.issue()
    other = Wallet(wallet.client, wallet.pki, wallet.clock)
    assert other.issue().json()["notification_id"] != first.json()["notification_id"]


@pytest.mark.covers("VCI.NOTIF.VALIDATION")
@pytest.mark.parametrize(
    "change",
    [
        {"event": "credential_lost"},
        {"event": "Credential_Accepted"},
        {"event": None},
        {"event": ["credential_accepted"]},
        {"notification_id": 7},
        {"notification_id": None},
        {"event_description": 'a "quoted" word'},
        {"event_description": "back\\slash"},
        {"event_description": "não"},
        {"event_description": "x" * 1001},
        {"event_description": 5},
    ],
)
def test_a_malformed_notification_is_refused(wallet: Wallet, change: dict[str, Any]) -> None:
    notification_id = wallet.issue().json()["notification_id"]
    body = {"notification_id": notification_id, "event": "credential_accepted", **change}
    body = {k: v for k, v in body.items() if v is not None}
    response = refused_by(lambda: notify(wallet, body), "VCI.NOTIF.VALIDATION", "")
    assert response.status_code == 400 and response.json()["error"] == "invalid_notification_request"


@pytest.mark.covers("VCI.NOTIF.VALIDATION")
def test_a_notification_body_that_is_not_an_object_is_refused(wallet: Wallet) -> None:
    wallet.issue()
    for raw in (b"[]", b"{", b'{"event": "credential_accepted", "event": "credential_failure"}'):
        response = refused_by(functools.partial(notify, wallet, None, raw=raw), "VCI.NOTIF.VALIDATION", "JSON object")
        assert response.json()["error"] == "invalid_notification_request"


def test_the_longest_description_is_accepted(wallet: Wallet) -> None:
    notification_id = wallet.issue().json()["notification_id"]
    body = {"notification_id": notification_id, "event": "credential_failure", "event_description": "x!#[]~ " * 142}
    body["event_description"] = body["event_description"][:1000]
    assert notify(wallet, body).status_code == 204


@pytest.mark.covers("VCI.NOTIF.VALIDATION")
def test_an_unknown_or_foreign_notification_id_is_invalid(wallet: Wallet) -> None:
    notification_id = wallet.issue().json()["notification_id"]
    unknown = refused_by(
        lambda: notify(wallet, {"notification_id": "nope", "event": "credential_accepted"}),
        "VCI.NOTIF.VALIDATION",
        "unknown notification_id",
    )
    assert unknown.json()["error"] == "invalid_notification_id"
    other = Wallet(wallet.client, wallet.pki, wallet.clock)
    other.issue()
    foreign = notify(other, {"notification_id": notification_id, "event": "credential_accepted"})
    assert foreign.status_code == 400 and foreign.json()["error"] == "invalid_notification_id"


def test_the_notification_endpoint_needs_its_token(wallet: Wallet) -> None:
    notification_id = wallet.issue().json()["notification_id"]
    bare = wallet.client.post(
        "/notification", json={"notification_id": notification_id, "event": "credential_accepted"}
    )
    assert bare.status_code == 401
    proof = wallet.dpop("POST", f"{ISSUER}/notification", access_token=wallet.token)
    text = wallet.client.post(
        "/notification",
        content=b"x",
        headers={"Authorization": f"DPoP {wallet.token}", "DPoP": proof, "Content-Type": "text/plain"},
    )
    assert text.status_code == 400 and text.json()["error"] == "invalid_notification_request"


def test_a_deferred_issuance_has_a_notification_id_too(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    [ref] = held_refs(code_wallet)
    decide(code_wallet, ref, "release")
    notification_id = deferred(code_wallet, {"transaction_id": transaction_id}).json()["notification_id"]
    assert notify(code_wallet, {"notification_id": notification_id, "event": "credential_accepted"}).status_code == 204


def test_a_token_that_does_not_cover_the_configuration_collects_nothing(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """A refreshed token narrowed to other configurations (RFC 6749 §6) cannot collect this one."""
    subject_ref, transaction_id = hold(code_wallet, code_issuer)
    [(key, row)] = code_issuer.store.items("deferred")
    held = code_issuer._held(key)  # noqa: SLF001
    assert held is not None
    code_issuer._keep_held(key, {**held, "config": "eu.europa.ec.eudi.iban_sd_jwt_vc"})  # noqa: SLF001
    response = deferred(code_wallet, {"transaction_id": transaction_id})
    assert response.status_code == 400 and response.json()["error"] == "invalid_transaction_id"
    assert key.startswith(f"{subject_ref}:")


def test_a_reply_kept_before_notifications_is_answered_without_one(wallet: Wallet, issuer: Issuer) -> None:
    """A reply an older version kept has no notification_id: a repeated request still gets its credentials."""
    key = EcKey.generate()
    first = wallet.issue([key])
    [(slot_key, _)] = issuer.store.items("vault-reply")
    subject_ref, slot = slot_key.split(":", 1)
    kept = issuer.vault.reply(subject_ref, slot)
    assert kept is not None
    del kept["notification_id"]
    issuer.vault.keep_reply(subject_ref, slot, kept, 60)
    again = wallet.issue([key])
    assert again.status_code == 200, again.text
    assert again.json() == {"credentials": first.json()["credentials"]}


@pytest.mark.parametrize(
    "change",
    [
        {"state": "released"},
        {"keys": [EcKey.generate().public_jwk()]},
        {"key_status": {}},
        {"status_exp": None},
        {"exp": 2_000_000_000},
    ],
)
def test_a_held_row_changed_in_the_database_is_not_trusted(
    code_wallet: CodeWallet, code_issuer: Issuer, change: dict[str, Any]
) -> None:
    """The row decides which keys a credential is bound to and whether the operator released it: one changed by
    whoever can write the database fails its MAC and is taken as gone (the second reviewer)."""
    _, transaction_id = hold(code_wallet, code_issuer)
    [(key, row)] = code_issuer.store.items("deferred")
    code_issuer.store.put("deferred", key, {**row, **change}, 3600)
    response = deferred(code_wallet, {"transaction_id": transaction_id})
    assert response.status_code == 400 and response.json()["error"] == "invalid_transaction_id"
    assert held_refs(code_wallet) == []
    assert decide(code_wallet, key.rsplit(":", 1)[1], "release").status_code == 404
    assert code_issuer.store.items("issued") == []


def test_a_held_row_moved_to_another_subject_is_not_trusted(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    _, transaction_id = hold(code_wallet, code_issuer)
    [(key, row)] = code_issuer.store.items("deferred")
    ref = key.rsplit(":", 1)[1]
    code_issuer.store.delete("deferred", key)
    code_issuer.store.put("deferred", f"sub_{'A' * 24}:{ref}", row, 3600)
    code_issuer.store.put("transaction", ref, f"sub_{'A' * 24}", 3600)
    assert held_refs(code_wallet) == []
    assert decide(code_wallet, ref, "release").status_code == 404


def test_a_notification_row_changed_in_the_database_is_not_trusted(wallet: Wallet, issuer: Issuer) -> None:
    """A row pointed at another login, by whoever can write the database, fails its MAC."""
    notification_id = wallet.issue().json()["notification_id"]
    other = Wallet(wallet.client, wallet.pki, wallet.clock)
    other.issue()
    [(key, row)] = [
        (k, r) for k, r in issuer.store.items("notification") if k == issuer._notification_ref(notification_id)
    ]  # noqa: SLF001
    theirs = next(e for e in reversed(issuer.audit.entries()) if e["event"] == "credential.issued")["data"]
    issuer.store.put("notification", key, {**row, "subject_ref": theirs["subject_ref"]}, 3600)
    moved = notify(other, {"notification_id": notification_id, "event": "credential_accepted"})
    assert moved.status_code == 400 and moved.json()["error"] == "invalid_notification_id"


def test_a_refreshed_token_stays_under_review(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """The review travels with the login through its sealed code, token and refresh rows: a token from the refresh
    token is held too, and nothing in the store outside those rows says so (the second reviewer)."""
    hold(code_wallet, code_issuer)
    renewed = code_wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    code_wallet.token = renewed.json()["access_token"]
    again = code_wallet.issue()
    assert again.status_code == 202, again.text
    assert len(held_refs(code_wallet)) == 2
    assert code_issuer.store.items("subject-review") == []


def test_a_token_whose_review_was_removed_in_the_database_is_not_trusted(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """Taking `review` out of the token row makes its MAC fail: the token is refused, never issued at once."""
    held_login(code_wallet, code_issuer)
    [(key, row)] = code_issuer.store.items("access-token")
    code_issuer.store.put("access-token", key, {k: v for k, v in row.items() if k != "review"}, 300)
    response = code_wallet.issue()
    assert response.status_code == 401
    assert code_issuer.store.items("issued") == []


def test_a_hold_ends_with_the_refresh_token(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    """Asked for a day before the refresh token expires, an issuance waits a day, not deferred_ttl: after that the
    wallet could get no token to collect it with (the second reviewer)."""
    held_login(code_wallet, code_issuer)
    clock.now += code_issuer.settings.refresh_token_ttl - 86_400
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    assert code_wallet.issue().status_code == 202
    [(key, _)] = code_issuer.store.items("deferred")
    row = code_issuer._held(key)  # noqa: SLF001
    assert row is not None and row["exp"] - int(clock()) <= 86_400 < code_issuer.settings.deferred_ttl
    clock.now += 86_400
    assert held_refs(code_wallet) == []
    assert code_wallet.refresh_request().status_code == 400, "and the refresh token is gone with it"


def test_a_hold_keeps_no_data_longer(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    """Asked for near the refresh token's end, a hold keeps the subject's data no longer than the refresh token
    already did (the second reviewer)."""
    subject_ref = held_login(code_wallet, code_issuer)
    clock.now += code_issuer.settings.refresh_token_ttl - 86_400
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    assert code_wallet.issue().status_code == 202
    clock.now += 86_400 + code_issuer.settings.access_token_ttl + 1
    assert code_issuer.store.get("vault-key", subject_ref) is None
    assert code_issuer.store.get("vault", subject_ref) is None


def test_a_closure_while_the_issuance_is_held_stops_it(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The offer is cancelled after the request's checks but before its hold is written: nothing is held, the wallet
    is refused, and the claim is given back."""
    subject_ref = held_login(code_wallet, code_issuer)
    claim = code_issuer._claim_grant  # noqa: SLF001

    def raced(*args: Any) -> None:
        claim(*args)
        code_issuer.cancel_offer(subject_ref, "operator")  # the operator cancels meanwhile

    monkeypatch.setattr(code_issuer, "_claim_grant", raced)
    refused = refused_by(code_wallet.issue, "VCI.CRED.ERROR_CODES", "cancelled")
    assert refused.status_code == 400 and refused.json()["error"] == "credential_request_denied"
    assert held_refs(code_wallet) == [] and code_issuer.store.items("transaction") == []
    assert "credential.deferred" not in events(code_issuer)


def released(wallet: CodeWallet, issuer: Issuer) -> tuple[str, str]:
    subject_ref, transaction_id = hold(wallet, issuer)
    [ref] = held_refs(wallet)
    assert decide(wallet, ref, "release").status_code == 200
    return subject_ref, transaction_id


def test_a_configuration_no_longer_issued_is_not_collected(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issuer was restarted without the configuration while the issuance waited."""
    _, transaction_id = released(code_wallet, code_issuer)
    monkeypatch.setattr(code_issuer, "configs", dataclasses.replace(code_issuer.configs, published=frozenset()))
    denied = refused_by(
        lambda: deferred(code_wallet, {"transaction_id": transaction_id}), "VCI.CRED.ERROR_CODES", "no longer issued"
    )
    assert denied.status_code == 400 and denied.json()["error"] == "credential_request_denied"
    assert code_issuer.store.items("issued") == []


def test_subject_data_gone_is_not_collected(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    subject_ref, transaction_id = released(code_wallet, code_issuer)
    code_issuer.vault.erase(subject_ref)
    denied = refused_by(
        lambda: deferred(code_wallet, {"transaction_id": transaction_id}), "VCI.CRED.ERROR_CODES", "no longer available"
    )
    assert denied.status_code == 400 and denied.json()["error"] == "credential_request_denied"
    assert code_issuer.store.items("issued") == []


@pytest.mark.covers("PID.VALUES.VALID_AT_VALIDITY_START")
def test_the_subject_data_is_checked_again_at_collection(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    """A rule that starts during the review applies: a portrait is required from 11 August 2028."""
    clock.now = dt.datetime(2028, 8, 10, 12, tzinfo=dt.UTC).timestamp()
    _, transaction_id = released(code_wallet, code_issuer)
    clock.now = dt.datetime(2028, 8, 11, 12, tzinfo=dt.UTC).timestamp()
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    denied = refused_by(
        lambda: deferred(code_wallet, {"transaction_id": transaction_id}), "PID.VALUES.VALID_AT_VALIDITY_START", ""
    )
    assert denied.status_code == 400 and "picture" in denied.json()["error_description"]
    assert code_issuer.store.items("issued") == []


@pytest.mark.parametrize("ref", ["G" * 32, "0" * 31, "0" * 33, "A" * 32])
def test_a_decision_on_something_not_a_reference_is_refused(
    code_wallet: CodeWallet, code_issuer: Issuer, ref: str
) -> None:
    hold(code_wallet, code_issuer)
    for decision in ("release", "refuse"):
        response = refused_by(
            functools.partial(decide, code_wallet, ref, decision), "ISS.SUBJECT.ENTITLEMENT", "not a reference"
        )
        assert response.status_code == 404
    assert [row["state"] for row in code_wallet.client.get("/admin/deferred", headers=ADMIN).json()["deferred"]] == [
        "held"
    ]


@pytest.mark.parametrize(("ttl", "interval"), [(3600, 5), (3600, 3600), (30 * 86_400, 86_400), (7 * 86_400, 600)])
def test_the_review_settings_at_their_bounds_are_taken(pki: Any, ttl: int, interval: int) -> None:
    from cunho.settings import Settings

    from .helpers import settings_kwargs

    settings = Settings(**settings_kwargs(pki, deferred_ttl=ttl, deferred_interval=interval))
    assert (settings.deferred_ttl, settings.deferred_interval) == (ttl, interval)


@pytest.mark.parametrize(
    ("ttl", "interval", "message"),
    [
        (3599, 5, "deferred_ttl must be from an hour to 30 days"),
        (30 * 86_400 + 1, 600, "deferred_ttl must be from an hour to 30 days"),
        (7 * 86_400, 4, "deferred_interval must be from 5 s to a day"),
        (7 * 86_400, 86_401, "deferred_interval must be from 5 s to a day"),
        (3600, 3601, "deferred_interval must be from 5 s to a day, and at most deferred_ttl"),
    ],
)
def test_the_review_settings_are_bounded(pki: Any, ttl: int, interval: int, message: str) -> None:
    from cunho.errors import ConfigError
    from cunho.settings import Settings

    from .helpers import settings_kwargs

    with pytest.raises(ConfigError, match=message):
        Settings(**settings_kwargs(pki, deferred_ttl=ttl, deferred_interval=interval))
