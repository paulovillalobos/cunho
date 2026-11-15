"""Every refusal of the authorization code flow, each built so that only its own check can refuse it."""

from __future__ import annotations

import functools
import json
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho.authorize import MAX_OPENS
from cunho.service import Issuer
from cunho.store import SqliteStore
from eudi_probe.jose import EcKey, jwk_thumbprint

from .codewallet import LOGIN, CodeWallet, Pkce, code_of, pid_scope, pushed
from .helpers import ADMIN_TOKEN, Clock, raised_by, refused_by
from .helpers import PID_CONFIG as PID


def error(response: Any) -> str:
    return str(response.json()["error"])


# PAR ------------------------------------------------------------------------------------------------


@pytest.mark.covers("OAUTH.PAR_REQUEST", "OAUTH.RESPONSE_TYPE_CODE", "OAUTH.PKCE_S256", "OAUTH.PKCE_VERIFIER")
@pytest.mark.parametrize(
    ("label", "kwargs", "rule", "reason", "code"),
    [
        (
            "request_uri pushed",
            {"extra": {"request_uri": "urn:x"}},
            "OAUTH.PAR_REQUEST",
            "must not be pushed",
            "invalid_request",
        ),
        ("no client_id", {"drop": ("client_id",)}, "OAUTH.PAR_REQUEST", "client_id is required", "invalid_request"),
        ("long state", {"state": "s" * 2049}, "OAUTH.PAR_REQUEST", "state must be", "invalid_request"),
        (
            "no response_type",
            {"drop": ("response_type",)},
            "OAUTH.RESPONSE_TYPE_CODE",
            "is required",
            "invalid_request",
        ),
        (
            "token",
            {"extra": {"response_type": "token"}},
            "OAUTH.RESPONSE_TYPE_CODE",
            "only response_type=code",
            "unsupported_response_type",
        ),
        (
            "code id_token",
            {"extra": {"response_type": "code id_token"}},
            "OAUTH.RESPONSE_TYPE_CODE",
            "only",
            "unsupported_response_type",
        ),
        (
            "no challenge",
            {"drop": ("code_challenge",)},
            "OAUTH.PKCE_VERIFIER",
            "code_challenge is required",
            "invalid_request",
        ),
        ("plain", {"extra": {"code_challenge_method": "plain"}}, "OAUTH.PKCE_S256", "must be S256", "invalid_request"),
        ("no method", {"drop": ("code_challenge_method",)}, "OAUTH.PKCE_S256", "must be S256", "invalid_request"),
        (
            "short challenge",
            {"extra": {"code_challenge": "abc"}},
            "OAUTH.PKCE_VERIFIER",
            "base64url SHA-256",
            "invalid_request",
        ),
    ],
)
def test_a_pushed_request_is_checked_as_the_authorization_endpoint_would(
    code_wallet: CodeWallet, code_issuer: Issuer, label: str, kwargs: dict[str, Any], rule: str, reason: str, code: str
) -> None:
    kwargs.setdefault("scope", pid_scope(code_issuer))
    response = refused_by(lambda: code_wallet.par(Pkce.random(), **kwargs), rule, reason)
    assert response.status_code == 400 and error(response) == code


@pytest.mark.covers("OAUTH.PAR_REQUEST")
def test_a_parameter_given_twice_is_refused(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    form = (
        f"response_type=code&client_id={code_wallet.client_id}&redirect_uri={code_wallet.redirect_uri}"
        f"&code_challenge={pkce.challenge}&code_challenge_method=S256&scope={pid_scope(code_issuer)}&scope=other"
    )
    headers = [("Content-Type", "application/x-www-form-urlencoded"), *code_wallet.attestation_headers()]
    response = refused_by(
        lambda: code_wallet.client.post("/par", content=form, headers=headers), "OAUTH.PAR_REQUEST", "more than once"
    )
    assert error(response) == "invalid_request"
    wrong_type = refused_by(
        lambda: code_wallet.client.post("/par", content=form, headers=[("Content-Type", "application/json")]),
        "OAUTH.PAR_REQUEST",
        "x-www-form-urlencoded",
    )
    assert wrong_type.status_code == 400


@pytest.mark.covers("OAUTH.REDIRECT_URI_EXACT")
@pytest.mark.parametrize(
    ("redirect_uri", "reason"),
    [
        (None, "redirect_uri is required"),
        ("https://wallet.test/callback/", "not one the operator allows"),
        ("https://WALLET.test/callback", "not one the operator allows"),
        ("https://wallet.test/callback?x=1", "not one the operator allows"),
        ("https://wallet.test:443/callback", "not one the operator allows"),
        ("https://attacker.test/callback", "not one the operator allows"),
    ],
)
def test_the_redirect_uri_is_compared_as_an_exact_string(
    code_wallet: CodeWallet, code_issuer: Issuer, redirect_uri: str | None, reason: str
) -> None:
    """RFC 9700 §2.1: never normalised, so a variant that means the same URL is still another string."""
    kwargs: dict[str, Any] = (
        {"drop": ("redirect_uri",)} if redirect_uri is None else {"extra": {"redirect_uri": redirect_uri}}
    )
    response = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), **kwargs),
        "OAUTH.REDIRECT_URI_EXACT",
        reason,
    )
    assert error(response) == "invalid_request"


@pytest.mark.covers("OAUTH.REDIRECT_URI_EXACT")
def test_the_allow_list_is_per_wallet_solution(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    issuer = make_code_issuer(redirect_uris={"https://another-wallet.test": ("https://wallet.test/callback",)})
    wallet = code_wallet_for(issuer)
    refused_by(lambda: wallet.par(Pkce.random(), scope=pid_scope(issuer)), "OAUTH.REDIRECT_URI_EXACT", "not one")


@pytest.mark.covers("VCI.SCOPE_TO_CONFIG", "VCI.AUTHZ_DETAILS")
@pytest.mark.parametrize(
    ("scope", "details", "rule", "reason", "code"),
    [
        ("unknown", None, "VCI.SCOPE_TO_CONFIG", "names no credential configuration", "invalid_scope"),
        (None, None, "VCI.SCOPE_TO_CONFIG", "names no credential configuration", "invalid_scope"),
        (None, "[]", "VCI.AUTHZ_DETAILS", "JSON array of 1 to 16", "invalid_authorization_details"),
        (None, "{}", "VCI.AUTHZ_DETAILS", "JSON array", "invalid_authorization_details"),
        (None, "[", "VCI.AUTHZ_DETAILS", "JSON array", "invalid_authorization_details"),
        (
            None,
            '[{"type": "payment"}]',
            "VCI.AUTHZ_DETAILS",
            "of type openid_credential",
            "invalid_authorization_details",
        ),
        (
            None,
            '[{"type": "openid_credential"}]',
            "VCI.AUTHZ_DETAILS",
            "names no configuration",
            "invalid_authorization_details",
        ),
        (
            None,
            '[{"type": "openid_credential", "credential_configuration_id": "x"}]',
            "VCI.AUTHZ_DETAILS",
            "names no configuration",
            "invalid_authorization_details",
        ),
        (None, "[1]", "VCI.AUTHZ_DETAILS", "of type openid_credential", "invalid_authorization_details"),
    ],
)
def test_what_is_asked_for_must_name_a_configuration(
    code_wallet: CodeWallet, scope: str | None, details: str | None, rule: str, reason: str, code: str
) -> None:
    extra = {"authorization_details": details} if details is not None else {}
    response = refused_by(lambda: code_wallet.par(Pkce.random(), scope=scope, extra=extra), rule, reason)
    assert error(response) == code


@pytest.mark.covers("VCI.AUTHZ_DETAILS")
def test_locations_must_name_this_issuer(code_wallet: CodeWallet) -> None:
    from .helpers import ISSUER, PID_CONFIG

    item = {"type": "openid_credential", "credential_configuration_id": PID_CONFIG}
    pushed_ok = code_wallet.par(Pkce.random(), authorization_details=[{**item, "locations": [ISSUER]}])
    assert pushed_ok.status_code == 201
    refused_by(
        lambda: code_wallet.par(Pkce.random(), authorization_details=[{**item, "locations": ["https://x.test"]}]),
        "VCI.AUTHZ_DETAILS",
        "locations must name",
    )
    refused_by(
        lambda: code_wallet.par(Pkce.random(), authorization_details=[item] * 17), "VCI.AUTHZ_DETAILS", "1 to 16"
    )


@pytest.mark.covers("OAUTH.CODE_DPOP_BOUND")
def test_dpop_jkt_and_the_par_proof_must_name_one_key(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    other = jwk_thumbprint(EcKey.generate().public_jwk())
    mismatch = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), dpop_jkt=other),
        "OAUTH.CODE_DPOP_BOUND",
        "does not match the DPoP proof key",
    )
    assert error(mismatch) == "invalid_dpop_proof"
    malformed = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), dpop_jkt="not-a-thumbprint", dpop=None),
        "OAUTH.CODE_DPOP_BOUND",
        "JWK SHA-256 thumbprint",
    )
    assert error(malformed) == "invalid_request"
    same = jwk_thumbprint(code_wallet.dpop_key.public_jwk())
    assert code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), dpop_jkt=same).status_code == 201


@pytest.mark.covers("DPOP.HTU")
def test_the_par_proof_is_a_dpop_proof_for_the_par_endpoint(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    proof = code_wallet.dpop("POST", "https://issuer.test/token")
    refused_by(lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), dpop=proof), "DPOP.HTU", "htu")


# the authorization endpoint -------------------------------------------------------------------------


@pytest.mark.covers("OAUTH.PAR_REQUIRED")
@pytest.mark.parametrize(
    "query",
    [
        "response_type=code&client_id=https://wallet-solution.test&redirect_uri=https://wallet.test/callback",
        "client_id=https://wallet-solution.test",
        "",
    ],
)
def test_an_authorization_request_that_was_not_pushed_is_refused(code_wallet: CodeWallet, query: str) -> None:
    response = refused_by(
        lambda: code_wallet.client.get(f"/authorize?{query}", follow_redirects=False),
        "OAUTH.PAR_REQUIRED",
        "pushed first",
    )
    assert response.status_code == 400 and error(response) == "invalid_request" and "location" not in response.headers


@pytest.mark.covers("OAUTH.PAR_REQUIRED")
def test_an_authorization_request_needs_its_client_id_once(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer)
    refused_by(
        lambda: code_wallet.client.get(f"/authorize?request_uri={request_uri}", follow_redirects=False),
        "OAUTH.PAR_REQUIRED",
        "client_id is required",
    )
    twice = f"/authorize?request_uri={request_uri}&client_id=a&client_id=b"
    refused_by(lambda: code_wallet.client.get(twice, follow_redirects=False), "OAUTH.PAR_REQUIRED", "more than once")
    assert code_wallet.authorize(request_uri).status_code == 303, "neither refusal used the request up"


@pytest.mark.covers("OAUTH.PAR_REQUEST_URI_ONCE")
def test_a_request_uri_is_spent_by_the_login_it_starts(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """FAPI 2.0 SP §5.3.2.2 note 3: opened again until a login completes, then spent, for the client that pushed
    it only."""
    request_uri, _ = pushed(code_wallet, code_issuer)
    stranger = refused_by(
        lambda: code_wallet.authorize(request_uri, client_id="https://other-wallet.test"),
        "OAUTH.PAR_REQUEST_URI_ONCE",
        "pushed by another client",
    )
    assert stranger.status_code == 400
    assert code_wallet.authorize(request_uri).status_code == 303, "the stranger did not use it up"
    assert "code" in code_wallet.login(code_wallet.authorize(request_uri), LOGIN).params, "opened again before"
    again = refused_by(lambda: code_wallet.authorize(request_uri), "OAUTH.PAR_REQUEST_URI_ONCE", "already used")
    assert again.status_code == 400 and "location" not in again.headers
    refused_by(
        lambda: code_wallet.authorize("urn:ietf:params:oauth:request_uri:x"), "OAUTH.PAR_REQUEST_URI_ONCE", "unknown"
    )


@pytest.mark.covers("OAUTH.PAR_REQUEST_URI_ONCE")
def test_a_request_uri_expires(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer)
    clock.now += code_issuer.settings.par_ttl
    refused_by(lambda: code_wallet.authorize(request_uri), "OAUTH.PAR_REQUEST_URI_ONCE", "expired")


def test_a_request_uri_lives_its_whole_lifetime(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer)
    clock.now += code_issuer.settings.par_ttl - 1
    assert code_wallet.authorize(request_uri).status_code == 303


# the code exchange ----------------------------------------------------------------------------------


@pytest.fixture
def flow(code_wallet: CodeWallet, code_issuer: Issuer) -> tuple[CodeWallet, Issuer, Pkce, str]:
    pkce = Pkce.random()
    return code_wallet, code_issuer, pkce, code_of(code_wallet, code_issuer, pkce)


@pytest.mark.covers("WIA.REQUIRED_AT_PAR_AND_TOKEN")
def test_the_token_request_needs_the_attestation(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    wallet, _, pkce, code = flow
    response = refused_by(
        lambda: wallet.code_token_request(code, pkce, attest=False), "WIA.REQUIRED_AT_PAR_AND_TOKEN", "exactly one"
    )
    assert response.status_code == 401 and error(response) == "invalid_client"
    assert wallet.code_token_request(code, pkce).status_code == 200, "the refusal did not use the code up"


@pytest.mark.covers("WIA.CLIENT_ID_IS_SUB")
def test_another_instance_of_the_same_wallet_cannot_redeem_the_code(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    wallet, _, pkce, code = flow
    other = CodeWallet(wallet.client, wallet.pki, wallet.clock, provider=wallet.provider, dpop_key=wallet.dpop_key)
    response = refused_by(
        lambda: other.code_token_request(code, pkce), "WIA.CLIENT_ID_IS_SUB", "issued to another client"
    )
    assert error(response) == "invalid_grant"


@pytest.mark.covers("OAUTH.CODE_DPOP_BOUND")
def test_a_code_bound_at_par_needs_the_same_dpop_key(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce)  # the PAR carried a DPoP proof of dpop_key
    other = code_wallet.dpop("POST", "https://issuer.test/token", key=EcKey.generate())
    response = refused_by(
        lambda: code_wallet.code_token_request(code, pkce, dpop=other), "OAUTH.CODE_DPOP_BOUND", "is bound to"
    )
    assert error(response) == "invalid_grant"


def test_a_code_not_bound_at_par_binds_the_token_to_the_proof_key(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce, dpop=None)
    other = EcKey.generate()
    response = code_wallet.code_token_request(
        code, pkce, dpop=code_wallet.dpop("POST", "https://issuer.test/token", key=other)
    )
    assert response.status_code == 200
    code_wallet.token, code_wallet.dpop_key = response.json()["access_token"], other
    assert code_wallet.issue().status_code == 200


@pytest.mark.covers("OAUTH.PKCE_VERIFIER")
@pytest.mark.parametrize(
    ("verifier", "reason", "code"),
    [
        ("A" * 43, "does not match the code_challenge", "invalid_grant"),
        ("A" * 42, "43 to 128 unreserved", "invalid_request"),
        ("A" * 129, "43 to 128 unreserved", "invalid_request"),
        ("A" * 42 + "!", "43 to 128 unreserved", "invalid_request"),
        (None, "the code was issued for a code_challenge", "invalid_grant"),
    ],
)
def test_the_code_verifier_must_match(
    flow: tuple[CodeWallet, Issuer, Pkce, str], verifier: str | None, reason: str, code: str
) -> None:
    wallet, _, pkce, auth_code = flow
    if verifier is None:
        action = functools.partial(wallet.code_token_request, auth_code, pkce, drop=("code_verifier",))
    else:
        action = functools.partial(wallet.code_token_request, auth_code, Pkce(verifier, pkce.challenge))
    response = refused_by(action, "OAUTH.PKCE_VERIFIER", reason)
    assert error(response) == code


@pytest.mark.covers("OAUTH.REDIRECT_URI_EXACT")
def test_the_token_request_repeats_the_redirect_uri(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    wallet, _, pkce, code = flow
    wrong = refused_by(
        lambda: wallet.code_token_request(code, pkce, redirect_uri="https://wallet.test/callback/"),
        "OAUTH.REDIRECT_URI_EXACT",
        "not the one of the authorization request",
    )
    assert error(wrong) == "invalid_grant"
    missing = refused_by(
        lambda: wallet.code_token_request(code, pkce, drop=("redirect_uri",)), "OAUTH.REDIRECT_URI_EXACT", "is required"
    )
    assert error(missing) == "invalid_request"


@pytest.mark.covers("OAUTH.AUTH_CODE_AND_PAR")
def test_the_token_request_needs_the_code(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    wallet, _, pkce, code = flow
    refused_by(
        lambda: wallet.code_token_request(code, pkce, drop=("code",)), "OAUTH.AUTH_CODE_AND_PAR", "code is required"
    )


@pytest.mark.covers("OAUTH.CODE_ONCE_60S")
def test_a_second_use_of_a_code_revokes_the_token_of_the_first(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    """FAPI 2.0 §5.3.2.2 item 9 and RFC 6749 §4.1.2: refused, and the first token is revoked."""
    wallet, _, pkce, code = flow
    first = wallet.code_token_request(code, pkce)
    assert first.status_code == 200
    wallet.token = first.json()["access_token"]
    again = refused_by(lambda: wallet.code_token_request(code, pkce), "OAUTH.CODE_ONCE_60S", "already used")
    assert error(again) == "invalid_grant"
    revoked = wallet.issue()
    assert revoked.status_code == 401 and revoked.json()["error"] == "invalid_token"


@pytest.mark.covers("VCI.TOKEN.INVALID_GRANT")
def test_a_code_lives_at_most_60_seconds(flow: tuple[CodeWallet, Issuer, Pkce, str], clock: Clock) -> None:
    wallet, issuer, pkce, code = flow
    assert issuer.settings.code_ttl == 60
    clock.now += 60
    response = refused_by(
        lambda: wallet.code_token_request(code, pkce), "VCI.TOKEN.INVALID_GRANT", "unknown or expired"
    )
    assert error(response) == "invalid_grant"
    refused_by(lambda: wallet.code_token_request("made-up", pkce), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")


def test_a_code_works_until_its_last_second(flow: tuple[CodeWallet, Issuer, Pkce, str], clock: Clock) -> None:
    wallet, _, pkce, code = flow
    clock.now += 59
    assert wallet.code_token_request(code, pkce).status_code == 200


@pytest.mark.covers("VCI.TOKEN.INVALID_GRANT")
@pytest.mark.parametrize("action", ["revoke", "erase"])
def test_a_code_whose_subject_was_closed_gives_nothing(
    code_wallet: CodeWallet, code_issuer: Issuer, action: str
) -> None:
    """A revocation or erasure between the login and the code exchange (the erasure-during-login case)."""
    pkce = Pkce.random()
    request_uri, _ = pushed(code_wallet, code_issuer, pkce)
    back = code_wallet.login(code_wallet.authorize(request_uri), LOGIN)
    subject_ref = code_issuer.audit.entries()[-1]["data"]["subject_ref"]
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    if action == "revoke":
        done = code_wallet.client.post(
            "/admin/revocations", json={"subject_ref": subject_ref, "reason": "user_request"}, headers=headers
        )
    else:
        done = code_wallet.client.post(f"/admin/subjects/{subject_ref}/erase", headers=headers)
    assert done.status_code in (200, 204), done.text
    refused_by(
        lambda: code_wallet.code_token_request(back.params["code"], pkce),
        "VCI.TOKEN.INVALID_GRANT",
        "revoked or erased",
    )


def test_two_token_requests_with_one_code_yield_one_token(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Path,
) -> None:
    """A race on one SQLite file: the code is taken in the transaction that writes the token, so one request wins,
    the other is refused, and the winner's token is revoked as a reused code's (the plan's risk 1)."""
    issuer = make_code_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    code = code_of(wallet, issuer, pkce)
    results: list[int] = []
    barrier = threading.Barrier(2)

    def redeem() -> None:
        barrier.wait()
        results.append(wallet.code_token_request(code, pkce).status_code)

    threads = [threading.Thread(target=redeem) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == [200, 400]
    assert issuer.store.items("access-token") == [], "the second use revoked the token of the first"


def test_two_logins_from_one_request_uri_completing_at_once_yield_one(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Path,
) -> None:
    issuer = make_code_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    wallet = code_wallet_for(issuer)
    request_uri, _ = pushed(wallet, issuer)
    states = []
    for _ in range(2):
        location = wallet.authorize(request_uri).headers["location"]
        states.append(location.split("login_state=", 1)[1].split("&")[0])
    results: list[str | None] = []
    barrier = threading.Barrier(2)

    def finish(state: str) -> None:
        barrier.wait()
        with issuer.store.atomic():
            results.append(issuer.authorization.finish_login(state, {"denied": True}))

    threads = [threading.Thread(target=finish, args=(state,)) for state in states]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(r is None for r in results) == [False, True]
    assert issuer.store.items("par") == [] and len(issuer.store.items("login-done")) == 1


# the credential endpoint ----------------------------------------------------------------------------


@pytest.mark.covers("OAUTH.NO_TOKEN_IN_QUERY")
def test_an_access_token_in_the_query_is_refused(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    """FAPI 2.0 §5.3.4 item 2 (RFC 6750 §2.3)."""
    wallet, _, pkce, code = flow
    token = wallet.code_token_request(code, pkce).json()["access_token"]
    response = refused_by(
        lambda: wallet.client.post(f"/credential?access_token={token}", json={}),
        "OAUTH.NO_TOKEN_IN_QUERY",
        "Authorization header",
    )
    assert response.status_code == 400 and error(response) == "invalid_request"


def test_a_failure_while_minting_gives_the_code_back(
    flow: tuple[CodeWallet, Issuer, Pkce, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The code is taken, the token written and the spent mark set in one transaction: when the token cannot be
    written, nothing of it stays, and the code still works."""
    wallet, issuer, pkce, code = flow
    real = issuer.tokens.store_token

    def broken(token_key: str, fields: dict[str, Any]) -> None:
        real(token_key, fields)
        raise RuntimeError("disk full")

    monkeypatch.setattr(issuer.tokens, "store_token", broken)
    assert wallet.code_token_request(code, pkce).status_code == 500
    assert issuer.store.items("code-spent") == [] and issuer.store.items("access-token") == []
    monkeypatch.setattr(issuer.tokens, "store_token", real)
    assert wallet.code_token_request(code, pkce).status_code == 200


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT", "OAUTH.ACCESS_DENIED")
def test_a_login_expires_with_its_login_state(code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock) -> None:
    from .codewallet import Redirect
    from .helpers import PID_SUBJECT

    request_uri, _ = pushed(code_wallet, code_issuer)
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    clock.now += code_issuer.settings.login_ttl
    late = code_wallet.client.post(
        f"/admin/logins/{login_state}",
        json={"subject": PID_SUBJECT, "loa": "high"},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert late.status_code == 404
    refused_by(
        lambda: code_wallet.client.get(f"/authorize/continue?login_state={login_state}", follow_redirects=False),
        "OAUTH.ACCESS_DENIED",
        "unknown, expired or used",
    )


@pytest.mark.covers("WIA.POP_FRESH")
def test_a_proof_of_possession_is_remembered_for_its_whole_window(
    code_wallet: CodeWallet, code_issuer: Issuer, clock: Clock
) -> None:
    """A PoP replayed late in its window is still refused: the replay cache lives as long as an iat can pass."""
    pop = code_wallet.attestation_pop(iat=int(clock()) + 50)
    code_issuer.client_auth.authenticate([code_wallet.attestation()], [pop])
    clock.now += 100  # the iat is now 50 s in the past, inside the 60 s window
    raised_by(
        lambda: code_issuer.client_auth.authenticate([code_wallet.attestation()], [pop]),
        "WIA.POP_FRESH",
        "already used",
    )


# the second reviewer's first look at the code flow -------------------------------------------------


@pytest.mark.obligation("VALIDITY.PID_LE_STATUS_EXP", "WIA.STATUS_EXP_NOT_TOKEN_EXP")
def test_a_credential_ends_before_the_wallet_attestations_status_period(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """TS3 v1.5.2 §2.4.3: the PID's technical validity ends before client_status.exp, not 14 days on."""
    import base64
    import json

    code_wallet.client_status_offset = 86_400
    pkce = Pkce.random()
    code_wallet.token = code_wallet.code_token_request(code_of(code_wallet, code_issuer, pkce), pkce).json()[
        "access_token"
    ]
    response = code_wallet.issue()
    assert response.status_code == 200, response.text
    jwt = response.json()["credentials"][0]["credential"].split("~")[0]
    claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
    assert claims["exp"] < int(code_wallet.clock()) + 86_400
    code_wallet.client_status_offset = 10  # less than the timestamp step: nothing can be issued
    pkce = Pkce.random()
    code_wallet.token = code_wallet.code_token_request(code_of(code_wallet, code_issuer, pkce), pkce).json()[
        "access_token"
    ]
    refused_by(code_wallet.issue, "VALIDITY.PID_LE_STATUS_EXP", "revocation maintenance period")


def _two_pids(tmp_path: Path) -> Path:
    """The reference metadata with a second PID configuration, so one login can authorize two of them."""
    import json
    import shutil

    from cunho.settings import DEFAULT_METADATA_DIR

    from .helpers import PID_CONFIG

    target = tmp_path / "md"
    shutil.copytree(DEFAULT_METADATA_DIR, target)
    pid = json.loads((target / "credentials_supported" / "pid_jwt_vc.json").read_text())[PID_CONFIG]
    copy = {**pid, "scope": "x.pid_copy"}
    (target / "credentials_supported" / "zz_copy.json").write_text(json.dumps({"x.pid_copy": copy}))
    return target


@pytest.mark.covers("VCI.AUTHZ_DETAILS")
def test_authorization_details_at_the_token_request_narrow_the_grant(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], tmp_path: Path
) -> None:
    """OpenID4VCI §6.1.1: a scope authorization redeemed with authorization_details gets identifiers, for the
    configurations named, and none beyond what was authorized."""
    from .helpers import PID_CONFIG

    issuer = make_code_issuer(metadata_dir=_two_pids(tmp_path), published_configurations=(PID_CONFIG, "x.pid_copy"))
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    code = code_of(wallet, issuer, pkce, scope=f"{pid_scope(issuer)} x.pid_copy")
    details = json.dumps([{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}])
    body = wallet.code_token_request(code, pkce, extra={"authorization_details": details}).json()
    [detail] = body["authorization_details"]
    assert detail["credential_configuration_id"] == PID_CONFIG and detail["credential_identifiers"]
    assert body["scope"] == pid_scope(issuer), "the granted scope narrowed with it"
    wallet.token = body["access_token"]
    endpoint = issuer.settings.credential_endpoint
    proof = wallet.dpop("POST", endpoint, access_token=wallet.token)
    grant = issuer.tokens.authorize(f"DPoP {wallet.token}", [proof], "POST", endpoint)
    assert grant.configuration_ids == [PID_CONFIG]
    pkce = Pkce.random()
    code = code_of(wallet, issuer, pkce, scope=pid_scope(issuer))
    wider = '[{"type": "openid_credential", "credential_configuration_id": "x.pid_copy"}]'
    response = refused_by(
        lambda: wallet.code_token_request(code, pkce, extra={"authorization_details": wider}),
        "VCI.AUTHZ_DETAILS",
        "does not cover",
    )
    assert response.json()["error"] == "invalid_authorization_details"
    assert wallet.code_token_request(code, pkce).status_code == 200, "the refusal did not use the code up"


@pytest.mark.covers("WIA.CLIENT_ID_IS_SUB", "OAUTH.PKCE_VERIFIER")
def test_a_used_code_in_other_hands_does_not_revoke_the_token(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    """Knowing a used code is not enough to cancel the token it gave: the bindings of its first use are checked
    first, and only the same client that proves them all again triggers the revocation."""
    wallet, _, pkce, code = flow
    token = wallet.code_token_request(code, pkce).json()["access_token"]
    other = CodeWallet(wallet.client, wallet.pki, wallet.clock, provider=wallet.provider)
    refused_by(lambda: other.code_token_request(code, pkce), "WIA.CLIENT_ID_IS_SUB", "issued to another client")
    refused_by(
        lambda: wallet.code_token_request(code, Pkce("B" * 43, pkce.challenge)),
        "OAUTH.PKCE_VERIFIER",
        "does not match",
    )
    wallet.token = token
    assert wallet.issue().status_code == 200, "the token of the first use still works"


def test_the_token_response_says_which_scope_was_granted(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """RFC 6749 §5.1: unknown scopes were ignored, so the granted scope differs and is returned."""
    from .helpers import PID_CONFIG

    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce, scope=f"unknown {pid_scope(code_issuer)} other")
    assert code_wallet.code_token_request(code, pkce).json()["scope"] == pid_scope(code_issuer)
    details = [{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}]
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce, scope=None, authorization_details=details)
    assert "scope" not in code_wallet.code_token_request(code, pkce).json(), "no scope was asked for"


# the second reviewer's second look ------------------------------------------------------------------


def _credential_claims(response: Any) -> dict[str, Any]:
    import base64

    jwt = response.json()["credentials"][0]["credential"].split("~")[0]
    claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
    return claims


@pytest.mark.obligation("VALIDITY.PID_LE_STATUS_EXP")
def test_the_token_requests_own_attestation_caps_validity_too(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """The attestation at /token may carry an earlier client_status.exp than the one at PAR; the earlier wins."""
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce)  # PAR with a 60-day status period
    code_wallet.client_status_offset = 86_400
    code_wallet.token = code_wallet.code_token_request(code, pkce).json()["access_token"]
    response = code_wallet.issue()
    assert response.status_code == 200, response.text
    assert _credential_claims(response)["exp"] < int(code_wallet.clock()) + 86_400


def test_a_person_link_lives_as_long_as_a_credential_from_the_login(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], clock: Clock
) -> None:
    """With a short offer lifetime, revocation by person still finds a credential issued late in a login's life."""
    from .codewallet import Redirect
    from .helpers import PID_SUBJECT

    issuer = make_code_issuer(offer_ttl=1, timestamp_granularity=60)
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    request_uri, _ = pushed(wallet, issuer, pkce)
    login_state = Redirect(303, wallet.authorize(request_uri).headers["location"]).params["login_state"]
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    body = {"subject": PID_SUBJECT, "loa": "high", "person": "p-7"}
    reported = wallet.client.post(f"/admin/logins/{login_state}", json=body, headers=headers)
    assert reported.status_code == 200
    clock.now += 500
    back = wallet.client.get(reported.json()["continue"], follow_redirects=False)
    code = Redirect(303, back.headers["location"]).params["code"]
    wallet.token = wallet.code_token_request(code, pkce).json()["access_token"]
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text
    clock.now = _credential_claims(issued)["exp"] - 60
    revoked = wallet.client.post(
        "/admin/revocations", json={"person": "p-7", "reason": "user_request"}, headers=headers
    )
    assert revoked.status_code == 200 and revoked.json()["revoked"] == 1, revoked.text


@pytest.mark.covers("OAUTH.CODE_DPOP_BOUND")
def test_a_replay_with_another_dpop_key_does_not_revoke_an_unbound_codes_token(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """PAR bound no DPoP key, so the code was redeemed with one; a replay must prove that key before it revokes."""
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce, dpop=None)
    token = code_wallet.code_token_request(code, pkce).json()["access_token"]
    other = code_wallet.dpop("POST", "https://issuer.test/token", key=EcKey.generate())
    refused_by(lambda: code_wallet.code_token_request(code, pkce, dpop=other), "OAUTH.CODE_DPOP_BOUND", "is bound to")
    code_wallet.token = token
    assert code_wallet.issue().status_code == 200, "the token of the first use still works"
    refused_by(lambda: code_wallet.code_token_request(code, pkce), "OAUTH.CODE_ONCE_60S", "already used")
    assert code_wallet.issue().status_code == 401, "the same key, verifier and client do revoke it"


# the second reviewer's third look -------------------------------------------------------------------


@pytest.mark.covers("VCI.TOKEN.INVALID_GRANT")
def test_a_subject_cancelled_at_login_stays_closed_while_its_code_can_come(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], clock: Clock
) -> None:
    """With a short offer lifetime, the closed mark outlives the login and its code, so a cancelled login's code
    is refused late in the login's life too."""
    from .codewallet import Redirect
    from .helpers import PID_SUBJECT

    issuer = make_code_issuer(offer_ttl=1)
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    request_uri, _ = pushed(wallet, issuer, pkce)
    login_state = Redirect(303, wallet.authorize(request_uri).headers["location"]).params["login_state"]
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    reported = wallet.client.post(
        f"/admin/logins/{login_state}", json={"subject": PID_SUBJECT, "loa": "high"}, headers=headers
    )
    subject_ref = reported.json()["subject_ref"]
    assert wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=headers).status_code == 200
    clock.now += 500
    back = wallet.client.get(reported.json()["continue"], follow_redirects=False)
    code = Redirect(303, back.headers["location"]).params["code"]
    refused_by(lambda: wallet.code_token_request(code, pkce), "VCI.TOKEN.INVALID_GRANT", "revoked or erased")


def test_a_narrowed_grant_leaves_nothing_open_once_it_is_issued(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    tmp_path: Path,
    clock: Clock,
) -> None:
    """A login for two configurations whose token request names one: once that one is issued and the refresh
    token has run out, the subject has nothing left to give, so a revocation cancels no live offer; while the
    refresh token lives, it can get only what the narrowed grant covers."""
    from .helpers import PID_CONFIG

    issuer = make_code_issuer(
        metadata_dir=_two_pids(tmp_path), published_configurations=(PID_CONFIG, "x.pid_copy"), refresh_token_ttl=600
    )
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    code = code_of(wallet, issuer, pkce, scope=f"{pid_scope(issuer)} x.pid_copy")
    subject_ref = issuer.audit.entries()[-1]["data"]["subject_ref"]
    details = json.dumps([{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}])
    body = wallet.code_token_request(code, pkce, extra={"authorization_details": details}).json()
    wallet.token = body["access_token"]
    [identifier] = body["authorization_details"][0]["credential_identifiers"]
    proof = wallet.proof(EcKey.generate(), wallet.c_nonce())
    issued = wallet.credential_request({"credential_identifier": identifier, "proofs": {"jwt": [proof]}})
    assert issued.status_code == 200, issued.text
    wallet.refresh_token = body["refresh_token"]
    refused_by(lambda: wallet.refresh_request(extra={"scope": "x.pid_copy"}), "VCI.SCOPE_TO_CONFIG", "more than")
    clock.now += 600 + issuer.settings.access_token_ttl
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    cancel = wallet.client.post(f"/admin/offers/{subject_ref}/cancel", headers=headers)
    assert cancel.status_code == 400 and "no live offer" in cancel.json()["error_description"], cancel.text
    revoked = wallet.client.post(
        "/admin/revocations", json={"subject_ref": subject_ref, "reason": "user_request"}, headers=headers
    )
    assert revoked.json() == {"revoked": 1}, "no offer was left to cancel"


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("https://wallet.test/cb", "https://wallet.test/cb?code=c"),
        ("https://wallet.test/cb?", "https://wallet.test/cb?code=c"),
        ("https://wallet.test/cb?a=1", "https://wallet.test/cb?a=1&code=c"),
        ("https://wallet.test/cb?a=1&", "https://wallet.test/cb?a=1&code=c"),
        ("https://wallet.test/cb?hint=why?", "https://wallet.test/cb?hint=why?&code=c"),
        ("https://wallet.test/cb??", "https://wallet.test/cb??&code=c"),
    ],
)
def test_a_redirect_keeps_the_query_it_has_and_one_delimiter(base: str, expected: str) -> None:
    from cunho.authorize import redirect_to

    assert redirect_to(base, {"code": "c", "state": None}) == expected


def test_a_redirect_uri_ending_in_its_query_delimiter_works(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    from .codewallet import CLIENT_ID

    issuer = make_code_issuer(redirect_uris={CLIENT_ID: ("https://wallet.test/callback?",)})
    wallet = code_wallet_for(issuer)
    wallet.redirect_uri = "https://wallet.test/callback?"
    pkce = Pkce.random()
    request_uri, _ = pushed(wallet, issuer, pkce)
    back = wallet.login(wallet.authorize(request_uri), LOGIN)
    assert back.location.startswith("https://wallet.test/callback?code=") and "??" not in back.location
    assert wallet.code_token_request(back.params["code"], pkce).status_code == 200


# the second reviewer's fourth look ------------------------------------------------------------------


@pytest.mark.covers("VCI.CRED.ERROR_CODES", "OAUTH.CODE_ONCE_60S")
def test_a_code_replayed_during_issuance_stops_that_issuance(
    flow: tuple[CodeWallet, Issuer, Pkce, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The replay closes the login's subject, which the issuance transaction checks, so a credential request that
    passed the token check before the replay hands nothing out."""
    wallet, issuer, pkce, code = flow
    wallet.token = wallet.code_token_request(code, pkce).json()["access_token"]
    real = issuer._validity
    replays: list[int] = []

    def validity_then_replay(*args: Any) -> Any:
        # After the subject data was read from the vault, so only the closed mark, which the issuance transaction
        # checks, can stop it: erasing the data alone would come too late.
        replays.append(wallet.code_token_request(code, pkce).status_code)
        return real(*args)

    monkeypatch.setattr(issuer, "_validity", validity_then_replay)
    response = refused_by(wallet.issue, "OAUTH.CODE_ONCE_60S", "already used")
    assert replays == [400]
    assert response.status_code == 400 and response.json()["error"] == "credential_request_denied", response.text
    events = [e["event"] for e in issuer.audit.entries()]
    assert "credential.issued" not in events and events[-1] == "offer.cancelled"


@pytest.mark.covers("WIA.POP_FRESH")
def test_a_pop_before_its_nbf_is_refused(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    now = int(code_wallet.clock())
    for nbf in (now + 3600, "soon"):
        pop = code_wallet.attestation_pop(nbf=nbf)
        raised_by(
            functools.partial(code_issuer.client_auth.authenticate, [code_wallet.attestation()], [pop]),
            "WIA.POP_FRESH",
            "not valid yet",
        )
    code_issuer.client_auth.authenticate([code_wallet.attestation()], [code_wallet.attestation_pop(nbf=now + 60)])


def test_a_finished_login_does_not_come_back_to_life(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], clock: Clock
) -> None:
    """With a short offer lifetime, the marks of what was issued live as long as the login's open row, so a login
    whose credential was issued stays finished once its refresh token has run out."""
    issuer = make_code_issuer(offer_ttl=1, access_token_ttl=60, refresh_token_ttl=30)
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    wallet.token = wallet.code_token_request(code_of(wallet, issuer, pkce), pkce).json()["access_token"]
    subject_ref = issuer.audit.entries()[-1]["data"]["subject_ref"]
    assert wallet.issue().status_code == 200
    clock.now += 92
    cancel = wallet.client.post(
        f"/admin/offers/{subject_ref}/cancel", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
    )
    assert cancel.status_code == 400 and "no live offer" in cancel.json()["error_description"], cancel.text


def _proof_with_iss(wallet: CodeWallet, holder: EcKey, iss: str) -> str:
    """A jwt key proof (App. F.1) with a key attestation and an iss claim."""
    from eudi_probe.jose import jws

    from .helpers import ISSUER

    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "key_attestation": wallet.key_attestation([holder])}
    claims = {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce(), "iss": iss}
    return jws(header, claims, holder)


@pytest.mark.covers("VCI.F4.PROOF_SIGNATURE")
def test_a_key_proof_may_name_the_attested_client_in_iss(flow: tuple[CodeWallet, Issuer, Pkce, str]) -> None:
    """OpenID4VCI App. F.1: iss, when sent, is the client_id; only the anonymous pre-authorized flow omits it."""
    wallet, _, pkce, code = flow
    wallet.token = wallet.code_token_request(code, pkce).json()["access_token"]
    holder = EcKey.generate()
    named = _proof_with_iss(wallet, holder, wallet.client_id)
    response = wallet.credential_request({"credential_configuration_id": PID, "proofs": {"jwt": [named]}})
    assert response.status_code == 200, response.text
    other = _proof_with_iss(wallet, EcKey.generate(), "https://other-wallet.test")
    refused_by(
        lambda: wallet.credential_request({"credential_configuration_id": PID, "proofs": {"jwt": [other]}}),
        "VCI.F4.PROOF_SIGNATURE",
        "iss must be the client_id",
    )


@pytest.mark.covers("VCI.F1.PROOF_ISS_ANON_PREAUTH")
def test_the_pre_authorized_flow_still_refuses_iss(code_wallet: CodeWallet) -> None:
    code_wallet.get_token()
    proof = _proof_with_iss(code_wallet, EcKey.generate(), code_wallet.client_id)
    refused_by(
        lambda: code_wallet.credential_request({"credential_configuration_id": PID, "proofs": {"jwt": [proof]}}),
        "VCI.F1.PROOF_ISS_ANON_PREAUTH",
        "must be omitted",
    )


@pytest.mark.covers("WIA.POP_FRESH")
def test_a_pop_past_its_exp_is_refused(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    now = int(code_wallet.clock())
    for exp in (now, now - 1, "later"):
        pop = code_wallet.attestation_pop(exp=exp)
        raised_by(
            functools.partial(code_issuer.client_auth.authenticate, [code_wallet.attestation()], [pop]),
            "WIA.POP_FRESH",
            "has expired (exp)",
        )
    code_issuer.client_auth.authenticate([code_wallet.attestation()], [code_wallet.attestation_pop(exp=now + 30)])


@pytest.mark.covers("OAUTH.RESPONSE_TYPE_CODE")
@pytest.mark.parametrize("mode", ["form_post", "fragment", "query.jwt", ""])
def test_a_response_mode_other_than_query_is_refused(code_wallet: CodeWallet, code_issuer: Issuer, mode: str) -> None:
    """The metadata advertises response_modes_supported [query]; another mode is refused at PAR, not answered in the
    query string all the same (the second reviewer)."""
    response = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), extra={"response_mode": mode}),
        "OAUTH.RESPONSE_TYPE_CODE",
        "response_mode=query",
    )
    assert response.status_code == 400 and error(response) == "invalid_request"
    assert (
        code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), extra={"response_mode": "query"}).status_code
        == 201
    )


def test_wallet_attestations_go_by_the_clock_watchs_time(
    make_code_issuer: Callable[..., Issuer], clock: Clock, trust_pki: Any, pki: Any
) -> None:
    """A wall clock stepped two days ahead moves nothing the watch decides by: a wallet whose own clock reads right
    is still authenticated, its attestation and proof judged by the time (DESIGN.md, time)."""
    from fastapi.testclient import TestClient

    from cunho.app import create_app

    from .helpers import ISSUER, Host

    host = Host(clock)
    issuer = host.issuer(make_code_issuer, None)
    issuer.sweep()  # the first background tick lays the base
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = CodeWallet(client, pki, host.true, provider=trust_pki.wallet_provider)
        host.advance(60)
        clock.now += 2 * 86_400
        identity = issuer.client_auth.authenticate([wallet.attestation()], [wallet.attestation_pop()])
        assert identity.status_exp == int(host.true()) + wallet.client_status_offset


# survivors of the full mutation run over the code flow --------------------------------------------


@pytest.mark.covers("OAUTH.PAR_REQUEST")
def test_state_is_one_to_2048_characters(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), extra={"state": ""}),
        "OAUTH.PAR_REQUEST",
        "state must be",
    )
    assert code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), state="s" * 2048).status_code == 201


def test_sixteen_authorization_details_are_accepted(code_wallet: CodeWallet) -> None:
    from .helpers import PID_CONFIG

    item = {"type": "openid_credential", "credential_configuration_id": PID_CONFIG}
    assert code_wallet.par(Pkce.random(), authorization_details=[item] * 16).status_code == 201


@pytest.mark.covers("VCI.AUTHZ_DETAILS")
@pytest.mark.parametrize("config_id", [[], {}, ["x"], 7, None])
def test_a_configuration_id_that_is_not_a_string_is_refused(code_wallet: CodeWallet, config_id: Any) -> None:
    item = {"type": "openid_credential", "credential_configuration_id": config_id}
    response = refused_by(
        lambda: code_wallet.par(Pkce.random(), authorization_details=[item]),
        "VCI.AUTHZ_DETAILS",
        "names no configuration",
    )
    assert response.status_code == 400


@pytest.mark.covers("OAUTH.PAR_REQUEST_URI_ONCE")
def test_a_request_uri_spent_between_the_check_and_the_login_is_refused(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A login from the same request_uri completes after this request checked it: the check inside the transaction
    finds it spent, and no login starts."""
    request_uri, _ = pushed(code_wallet, code_issuer)
    store = code_issuer.store
    real_atomic = store.atomic

    def spent_meanwhile() -> Any:
        for key, _ in store.items("par"):
            store.delete("par", key)  # the other login wins
        return real_atomic()

    monkeypatch.setattr(store, "atomic", spent_meanwhile)
    response = refused_by(lambda: code_wallet.authorize(request_uri), "OAUTH.PAR_REQUEST_URI_ONCE", "already used")
    assert response.status_code == 400 and code_issuer.store.items("login") == []


def test_of_two_logins_from_one_request_uri_the_first_to_complete_wins(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer)
    first, second = code_wallet.authorize(request_uri), code_wallet.authorize(request_uri)
    assert "code" in code_wallet.login(second, LOGIN).params
    with pytest.raises(AssertionError, match="another login from its request completed first"):
        code_wallet.login(first, LOGIN)
    assert code_issuer.store.items("login-done") == [], "the late login yields nothing to resume"


@pytest.mark.covers("OAUTH.PAR_REQUEST_URI_ONCE")
def test_a_request_uri_is_opened_a_bounded_number_of_times(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    request_uri, _ = pushed(code_wallet, code_issuer)
    for _ in range(MAX_OPENS):
        assert code_wallet.authorize(request_uri).status_code == 303
    response = refused_by(lambda: code_wallet.authorize(request_uri), "OAUTH.PAR_REQUEST_URI_ONCE", "too many times")
    assert response.status_code == 400


def test_authorization_details_at_the_token_request_may_name_all_it_covers(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """Naming exactly what the authorization covers is not asking beyond it: the token comes, with identifiers."""
    from .helpers import PID_CONFIG

    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce)
    details = json.dumps([{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}])
    response = code_wallet.code_token_request(code, pkce, extra={"authorization_details": details})
    assert response.status_code == 200, response.text
    assert response.json()["authorization_details"][0]["credential_configuration_id"] == PID_CONFIG


@pytest.mark.covers("WIA.CLIENT_ID_IS_SUB")
def test_another_wallet_solution_with_the_same_instance_key_cannot_redeem_the_code(
    flow: tuple[CodeWallet, Issuer, Pkce, str],
) -> None:
    """The code is bound to the attested sub as well as to the instance key: a second solution's attestation over
    the same key is another client."""
    wallet, _, pkce, code = flow
    other = CodeWallet(
        wallet.client,
        wallet.pki,
        wallet.clock,
        provider=wallet.provider,
        client_id="https://another-wallet-solution.test",
        instance_key=wallet.instance_key,
        dpop_key=wallet.dpop_key,
    )
    response = refused_by(lambda: other.code_token_request(code, pkce), "WIA.CLIENT_ID_IS_SUB", "another client")
    assert error(response) == "invalid_grant"


@pytest.mark.covers("OAUTH.CODE_ONCE_60S")
def test_a_code_redeemed_between_the_check_and_the_take_counts_as_reused(
    flow: tuple[CodeWallet, Issuer, Pkce, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The request saw the code, but another redemption took it first: it is a reuse, refused as one, and the token
    the other redemption got is revoked."""
    from cunho.authorize import _hash

    wallet, issuer, pkce, code = flow
    key = _hash(code)
    raw = issuer.store.get("code", key)
    first = wallet.code_token_request(code, pkce)
    assert first.status_code == 200
    real_get = issuer.store.get

    def seen_before_it_was_taken(ns: str, k: str) -> Any:
        return raw if (ns, k) == ("code", key) else real_get(ns, k)

    monkeypatch.setattr(issuer.store, "get", seen_before_it_was_taken)
    refused_by(lambda: wallet.code_token_request(code, pkce), "OAUTH.CODE_ONCE_60S", "already used")
    monkeypatch.setattr(issuer.store, "get", real_get)
    wallet.token = first.json()["access_token"]
    assert wallet.issue().status_code == 401, "the other redemption's token is revoked"
