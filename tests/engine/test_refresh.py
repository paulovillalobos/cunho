"""Refresh tokens and re-issuance (M3 piece F): RFC 6749 §6, OpenID4VCI §13.5, draft-07 §10.3, ARF ISSU_63 and
ISSU_65, FAPI 2.0 §5.3.2.1 item 9 (no rotation)."""

from __future__ import annotations

import base64
import functools
import json
from collections.abc import Callable
from typing import Any

import pytest

from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet, Pkce, code_of, pid_scope
from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PID_SUBJECT, Clock, refused_by

DAY = 86_400


def refreshable(wallet: CodeWallet, issuer: Issuer, **kwargs: Any) -> dict[str, Any]:
    """A code-flow token response, with the wallet holding its access and refresh tokens."""
    pkce = Pkce.random()
    body: dict[str, Any] = wallet.code_token_request(code_of(wallet, issuer, pkce, **kwargs), pkce).json()
    wallet.token, wallet.refresh_token = body["access_token"], body["refresh_token"]
    return body


def claims_of(response: Any) -> tuple[dict[str, Any], list[Any]]:
    parts = response.json()["credentials"][0]["credential"].split("~")
    payload = json.loads(base64.urlsafe_b64decode(parts[0].split(".")[1] + "=="))
    disclosures = [json.loads(base64.urlsafe_b64decode(d + "==")) for d in parts[1:] if d]
    return payload, disclosures


def subject_of(issuer: Issuer) -> str:
    entry = next(e for e in reversed(issuer.audit.entries()) if e["event"] == "offer.created")
    return str(entry["data"]["subject_ref"])


@pytest.mark.obligation("BATCH.REISSUANCE", "OAUTH.REFRESH_BOUND", "BATCH.REISSUE_SAME_WALLET_UNIT")
def test_a_refresh_token_gets_a_credential_issued_again(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """ARF ISSU_63: re-issuance through the refresh token, to the same wallet unit (ISSU_65), with a new status
    entry and new salts, as every issuance has (Token Status List §13.2, M2's privacy rules)."""
    body = refreshable(code_wallet, code_issuer)
    assert body["refresh_token"] and body["scope"] == pid_scope(code_issuer)
    first = code_wallet.issue()
    assert first.status_code == 200, first.text
    again = code_wallet.refresh_request()
    assert again.status_code == 200 and again.headers["cache-control"] == "no-store", again.text
    renewed = again.json()
    assert renewed["token_type"] == "DPoP" and renewed["access_token"] != body["access_token"]
    assert "refresh_token" not in renewed, "not rotated (FAPI 2.0 §5.3.2.1 item 9)"
    assert renewed["scope"] == pid_scope(code_issuer)
    code_wallet.token = renewed["access_token"]
    second = code_wallet.issue()
    assert second.status_code == 200, second.text
    (one, one_sd), (two, two_sd) = claims_of(first), claims_of(second)
    assert one["status"] != two["status"], "a fresh status entry"
    assert {d[0] for d in one_sd}.isdisjoint({d[0] for d in two_sd}), "fresh salts"
    assert one["cnf"] != two["cnf"], "bound to the key the wallet proved this time"


def test_a_refresh_token_is_used_again_and_again_until_it_expires(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    refreshable(code_wallet, code_issuer)
    for _ in range(3):
        assert code_wallet.refresh_request().status_code == 200
    clock.now += code_issuer.settings.refresh_token_ttl - 1
    assert code_wallet.refresh_request().status_code == 200, "its last second"
    clock.now += 1
    response = refused_by(code_wallet.refresh_request, "VCI.TOKEN.INVALID_GRANT", "unknown or expired refresh token")
    assert response.json()["error"] == "invalid_grant"


@pytest.mark.covers("OAUTH.REFRESH_BOUND", "BATCH.REISSUE_SAME_WALLET_UNIT", "WIA.REQUIRED_AT_PAR_AND_TOKEN")
def test_a_refresh_token_is_bound_to_its_client_and_instance(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """draft-07 §10.3: the same wallet solution and the same instance key. Not the DPoP key (RFC 9449 §5): the
    attestation sender-constrains it, and a wallet may move to a new DPoP key (test below)."""
    refreshable(code_wallet, code_issuer)
    kwargs: dict[str, Any] = {"provider": code_wallet.provider, "refresh_token": code_wallet.refresh_token}
    solution = CodeWallet(
        code_wallet.client,
        code_wallet.pki,
        code_wallet.clock,
        client_id="https://another-wallet-solution.test",
        instance_key=code_wallet.instance_key,
        dpop_key=code_wallet.dpop_key,
        **kwargs,
    )
    instance = CodeWallet(
        code_wallet.client, code_wallet.pki, code_wallet.clock, dpop_key=code_wallet.dpop_key, **kwargs
    )
    for wallet, rule, reason in (
        (solution, "OAUTH.REFRESH_BOUND", "issued to another client"),
        (instance, "BATCH.REISSUE_SAME_WALLET_UNIT", "another wallet instance"),
    ):
        response = refused_by(wallet.refresh_request, rule, reason)
        assert response.status_code == 400 and response.json()["error"] == "invalid_grant"
    unattested = refused_by(
        lambda: code_wallet.refresh_request(attest=False), "WIA.REQUIRED_AT_PAR_AND_TOKEN", "exactly one"
    )
    assert unattested.status_code == 401
    assert code_wallet.refresh_request().status_code == 200, "none of those used it up"


def test_a_refresh_with_a_new_dpop_key_gives_a_token_bound_to_that_key(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """RFC 9449 §5: the refresh token is not bound to a DPoP key, so a wallet can move to a new one; the access
    token it gets is bound to the new key, and the old one is refused with it."""
    refreshable(code_wallet, code_issuer)
    old, code_wallet.dpop_key = code_wallet.dpop_key, EcKey.generate()
    renewed = code_wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    code_wallet.token = renewed.json()["access_token"]
    new, code_wallet.dpop_key = code_wallet.dpop_key, old
    refused = refused_by(code_wallet.issue, "DPOP.KEY_BOUND_TO_TOKEN", "not the key the token is bound to")
    assert refused.status_code == 401
    code_wallet.dpop_key = new
    assert code_wallet.issue().status_code == 200


@pytest.mark.covers("OAUTH.REFRESH_BOUND", "VCI.TOKEN.INVALID_GRANT")
def test_a_refresh_request_needs_a_refresh_token_cunho_issued(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    refreshable(code_wallet, code_issuer)
    refused_by(lambda: code_wallet.refresh_request(extra={"refresh_token": ""}), "OAUTH.REFRESH_BOUND", "is required")
    refused_by(lambda: code_wallet.refresh_request("made-up"), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    access = refused_by(
        lambda: code_wallet.refresh_request(code_wallet.token), "VCI.TOKEN.INVALID_GRANT", "unknown or expired"
    )
    assert access.json()["error"] == "invalid_grant", "an access token is no refresh token"


@pytest.mark.covers("VCI.TOKEN.INVALID_GRANT")
@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("action", ["revoke", "erase", "cancel"])
def test_a_closed_subject_refreshes_nothing(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock, action: str, late: bool
) -> None:
    """Also at the end of the refresh token's life. The refresh token goes with the subject (the security review:
    its row named the subject and the wallet instance for as long as it would have lived), so it is unknown from
    then on; test_a_refresh_token_from_before_is_refused_by_the_closed_mark has the mark's own refusal."""
    refreshable(code_wallet, code_issuer)
    subject_ref = subject_of(code_issuer)
    assert code_wallet.issue().status_code == 200
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    if action == "revoke":
        done = code_wallet.client.post(
            "/admin/revocations", json={"subject_ref": subject_ref, "reason": "user_request"}, headers=headers
        )
    elif action == "erase":
        done = code_wallet.client.post(f"/admin/subjects/{subject_ref}/erase", headers=headers)
    else:
        done = code_wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=headers)
    assert done.status_code in (200, 204), done.text
    if late:
        clock.now += code_issuer.settings.refresh_token_ttl - 10
    refused_by(code_wallet.refresh_request, "VCI.TOKEN.INVALID_GRANT", "unknown or expired refresh token")


@pytest.mark.covers("VCI.TOKEN.INVALID_GRANT")
@pytest.mark.parametrize("late", [False, True])
def test_a_refresh_token_from_before_is_refused_by_the_closed_mark(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock, late: bool
) -> None:
    """A login made before cunho recorded where its rows are keeps its refresh token's row when its subject is
    closed: the closed mark, which lasts as long as the refresh token, refuses it."""
    refreshable(code_wallet, code_issuer)
    subject_ref = subject_of(code_issuer)
    code_issuer.store.delete("subject-login", subject_ref)
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    assert code_wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=headers).status_code == 200
    if late:
        clock.now += code_issuer.settings.refresh_token_ttl - 10
    refused_by(code_wallet.refresh_request, "VCI.TOKEN.INVALID_GRANT", "revoked or erased")


@pytest.mark.covers("VCI.CRED.ERROR_CODES")
def test_a_revocation_after_the_refresh_stops_the_credential(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """A token got by refresh before the revocation gets nothing after it: issuance checks the closed mark."""
    refreshable(code_wallet, code_issuer)
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    revoked = code_wallet.client.post(
        "/admin/revocations", json={"subject_ref": subject_of(code_issuer), "reason": "compromise"}, headers=headers
    )
    assert revoked.status_code == 200 and revoked.json().get("offer_cancelled") is True, revoked.text
    refused_by(code_wallet.issue, "VCI.CRED.ERROR_CODES", "cancelled or its subject revoked or erased")


def test_the_subject_data_stays_for_the_refresh_tokens_life_and_no_longer(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    """Decision 2 (a): the vault entry outlives the first issuance while a refresh token can use it, and goes when
    the refresh token can no longer be used."""
    refreshable(code_wallet, code_issuer)
    subject_ref = subject_of(code_issuer)
    assert code_wallet.issue().status_code == 200
    assert code_issuer.store.get("vault", subject_ref) is not None, "kept for re-issuance"
    clock.now += code_issuer.settings.refresh_token_ttl + code_issuer.settings.access_token_ttl
    assert code_issuer.store.get("vault", subject_ref) is None, "gone with the refresh token"


def test_a_token_got_at_the_end_of_the_refresh_tokens_life_still_gets_its_credential(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    """The data is held until the last access token a refresh can give has expired, not only the refresh token."""
    refreshable(code_wallet, code_issuer)
    assert code_wallet.issue().status_code == 200
    clock.now += code_issuer.settings.refresh_token_ttl - 10
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    clock.now += code_issuer.settings.access_token_ttl - 20
    issued = code_wallet.issue()
    assert issued.status_code == 200, issued.text


def test_a_pre_authorized_token_comes_without_a_refresh_token(wallet: Any) -> None:
    """The pre-authorized flow is anonymous: no attested client to bind a refresh token to (draft-07 §10.3)."""
    offer = wallet.offer()
    code = offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    response = wallet.token_request(code["pre-authorized_code"])
    assert response.status_code == 200 and "refresh_token" not in response.json()


@pytest.mark.covers("VCI.SCOPE_TO_CONFIG", "VCI.AUTHZ_DETAILS")
def test_a_refresh_may_ask_for_part_of_the_authorization_never_more(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    refreshable(code_wallet, code_issuer)
    narrow = code_wallet.refresh_request(extra={"scope": f"unknown {pid_scope(code_issuer)}"})
    assert narrow.status_code == 200 and narrow.json()["scope"] == pid_scope(code_issuer)
    for scope in ("unknown", "x.other"):
        ask = functools.partial(code_wallet.refresh_request, extra={"scope": scope})
        refused_by(ask, "VCI.SCOPE_TO_CONFIG", "more than the authorization covers")
    other = json.dumps([{"type": "openid_credential", "credential_configuration_id": "x.other"}])
    refused_by(
        lambda: code_wallet.refresh_request(extra={"authorization_details": other}),
        "VCI.AUTHZ_DETAILS",
        "names no configuration",
    )
    details = json.dumps([{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}])
    by_details = code_wallet.refresh_request(extra={"authorization_details": details})
    assert by_details.status_code == 200 and by_details.json()["authorization_details"][0]["credential_identifiers"]


def test_credential_identifiers_stay_the_same_across_refreshes(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    details = [{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}]
    body = refreshable(code_wallet, code_issuer, scope=None, authorization_details=details)
    first = body["authorization_details"][0]["credential_identifiers"]
    again = code_wallet.refresh_request().json()["authorization_details"][0]["credential_identifiers"]
    assert again == first
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    proof = code_wallet.proof(EcKey.generate(), code_wallet.c_nonce())
    issued = code_wallet.credential_request({"credential_identifier": first[0], "proofs": {"jwt": [proof]}})
    assert issued.status_code == 200, issued.text


@pytest.mark.obligation("VALIDITY.PID_LE_STATUS_EXP")
def test_a_refresh_goes_by_the_status_period_of_the_attestation_it_shows(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """The wallet attestation shown at refresh decides the cap, as the one shown at PAR and /token did."""
    refreshable(code_wallet, code_issuer)
    code_wallet.client_status_offset = DAY
    code_wallet.token = code_wallet.refresh_request().json()["access_token"]
    issued = code_wallet.issue()
    assert issued.status_code == 200, issued.text
    assert claims_of(issued)[0]["exp"] < int(code_wallet.clock()) + DAY


def test_a_reused_code_also_ends_its_refresh_token(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """RFC 6749 §4.1.2: what the first use yielded is revoked, the refresh token included."""
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce)
    body = code_wallet.code_token_request(code, pkce).json()
    code_wallet.refresh_token = body["refresh_token"]
    refused_by(lambda: code_wallet.code_token_request(code, pkce), "OAUTH.CODE_ONCE_60S", "already used")
    response = refused_by(code_wallet.refresh_request, "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    assert response.json()["error"] == "invalid_grant"
    assert code_issuer.store.items("refresh") == []


def test_a_code_reused_after_its_access_token_expired_still_ends_the_refresh_token(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], clock: Clock
) -> None:
    """The spent-code record lives as long as the refresh token and the last access token it can give."""
    issuer = make_code_issuer()
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    code = code_of(wallet, issuer, pkce)
    wallet.refresh_token = wallet.code_token_request(code, pkce).json()["refresh_token"]
    clock.now += issuer.settings.access_token_ttl + 10
    refused_by(lambda: wallet.code_token_request(code, pkce), "OAUTH.CODE_ONCE_60S", "already used")
    refused_by(wallet.refresh_request, "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    assert issuer.store.items("refresh") == []


def test_revocation_by_person_finds_a_credential_reissued_late(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], clock: Clock
) -> None:
    """The person link lives as long as a credential re-issued at the end of the refresh token's life."""
    from .codewallet import Redirect, pushed

    issuer = make_code_issuer()
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    request_uri, _ = pushed(wallet, issuer, pkce)
    login_state = Redirect(303, wallet.authorize(request_uri).headers["location"]).params["login_state"]
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    body = {"subject": PID_SUBJECT, "loa": "high", "person": "p-9"}
    resume = wallet.client.post(f"/admin/logins/{login_state}", json=body, headers=headers).json()["continue"]
    code = Redirect(303, wallet.client.get(resume, follow_redirects=False).headers["location"]).params["code"]
    wallet.refresh_token = wallet.code_token_request(code, pkce).json()["refresh_token"]
    clock.now += issuer.settings.refresh_token_ttl - 10
    wallet.token = wallet.refresh_request().json()["access_token"]
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text
    clock.now = claims_of(issued)[0]["exp"] - 60
    revoked = wallet.client.post(
        "/admin/revocations", json={"person": "p-9", "reason": "user_request"}, headers=headers
    )
    assert revoked.status_code == 200 and revoked.json()["revoked"] == 1, revoked.text


@pytest.mark.parametrize("value", [0, 365 * DAY + 1, True, 1.5])
def test_the_refresh_token_lifetime_is_bounded(pki: Any, value: Any) -> None:
    from cunho.errors import ConfigError
    from cunho.settings import Settings

    from .helpers import settings_kwargs

    with pytest.raises(ConfigError, match="refresh_token_ttl must be a whole number from 1 to"):
        Settings(**{**settings_kwargs(pki), "refresh_token_ttl": value})


@pytest.mark.parametrize("value", [1, 365 * DAY])
def test_a_refresh_token_may_live_from_a_second_to_a_year(pki: Any, value: int) -> None:
    from cunho.settings import Settings

    from .helpers import settings_kwargs

    assert Settings(**{**settings_kwargs(pki), "refresh_token_ttl": value}).refresh_token_ttl == value


def test_the_as_metadata_offers_the_refresh_grant(code_wallet: CodeWallet) -> None:
    document = code_wallet.client.get("/.well-known/oauth-authorization-server").json()
    assert "refresh_token" in document["grant_types_supported"] and document["issuer"] == ISSUER


def test_a_revocation_racing_a_refresh_leaves_no_credential_after_it(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Any,
) -> None:
    """On one SQLite file, a refresh and a subject revocation at once: whichever commits first, no credential is
    issued once the revocation has committed (the plan's race between revocation and refresh)."""
    import threading

    from cunho.store import SqliteStore

    issuer = make_code_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    wallet = code_wallet_for(issuer)
    refreshable(wallet, issuer)
    subject_ref = subject_of(issuer)
    results: dict[str, Any] = {}
    barrier = threading.Barrier(2)

    def refresh() -> None:
        barrier.wait()
        results["refresh"] = wallet.refresh_request()

    def revoke() -> None:
        barrier.wait()
        results["revoke"] = wallet.client.post(
            "/admin/revocations",
            json={"subject_ref": subject_ref, "reason": "compromise"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

    threads = [threading.Thread(target=refresh), threading.Thread(target=revoke)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results["revoke"].status_code == 200, results["revoke"].text
    assert results["refresh"].status_code in (200, 400)
    if results["refresh"].status_code == 200:
        wallet.token = results["refresh"].json()["access_token"]
    issued = wallet.issue()
    assert issued.status_code == 400 and issued.json()["error"] == "credential_request_denied", issued.text
