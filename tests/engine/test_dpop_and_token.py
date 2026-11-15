"""RFC 9449 checks at the token and credential endpoints, and the pre-authorized grant (OpenID4VCI §6)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.errors import IssuerError
from cunho.service import Issuer
from cunho.store import SqliteStore

from .helpers import ISSUER, PID_SUBJECT, PRE_AUTH, EcKey, Wallet, hs256


def code_of(offer: dict[str, Any]) -> str:
    return str(offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"])


def error(response: Any) -> str:
    return str(response.json()["error"])


BROKEN_PROOFS: list[tuple[str, str, Callable[[Wallet, str], str]]] = [
    ("DPOP.TYP", "wrong typ", lambda w, url: w.dpop("POST", url, typ="JWT")),
    (
        "DPOP.ALG_ASYMMETRIC",
        "HS256",
        lambda w, url: hs256(
            {"jti": "j" * 20, "htm": "POST", "htu": url, "iat": int(w.clock())},
            {"typ": "dpop+jwt", "alg": "HS256", "jwk": w.dpop_key.public_jwk()},
        ),
    ),
    (
        "DPOP.NO_PRIVATE_KEY",
        "private key in jwk",
        lambda w, url: w.dpop("POST", url, header_jwk=w.dpop_key.private_jwk()),
    ),
    ("DPOP.SIGNATURE", "signed by another key", lambda w, url: w.dpop("POST", url, signing_key=EcKey.generate())),
    ("DPOP.SIGNATURE", "not a JWS", lambda w, url: "not.a.jws"),
    ("DPOP.JTI_PRESENT", "no jti", lambda w, url: w.dpop("POST", url, drop=("jti",))),
    ("DPOP.JTI_PRESENT", "no iat", lambda w, url: w.dpop("POST", url, drop=("iat",))),
    ("DPOP.HTM", "wrong method", lambda w, url: w.dpop("GET", url)),
    ("DPOP.HTU", "wrong URI", lambda w, url: w.dpop("POST", "https://other.test/token")),
    ("DPOP.IAT_WINDOW", "stale iat", lambda w, url: w.dpop("POST", url, iat=int(w.clock()) - 3600)),
    ("DPOP.IAT_WINDOW", "future iat", lambda w, url: w.dpop("POST", url, iat=int(w.clock()) + 3600)),
]


@pytest.mark.covers(
    "DPOP.TYP",
    "DPOP.ALG_ASYMMETRIC",
    "DPOP.NO_PRIVATE_KEY",
    "DPOP.SIGNATURE",
    "DPOP.JTI_PRESENT",
    "DPOP.HTM",
    "DPOP.HTU",
    "DPOP.IAT_WINDOW",
)
@pytest.mark.parametrize(("rule", "label", "build"), BROKEN_PROOFS, ids=[b[1] for b in BROKEN_PROOFS])
def test_token_endpoint_refuses_broken_dpop(
    wallet: Wallet, rule: str, label: str, build: Callable[[Wallet, str], str]
) -> None:
    response = wallet.token_request(code_of(wallet.offer()), dpop=build(wallet, f"{ISSUER}/token"))
    assert response.status_code == 400, label
    assert error(response) == "invalid_dpop_proof", label


@pytest.mark.covers("OAUTH.DPOP_REQUIRED", "DPOP.SIGNATURE")
def test_token_needs_exactly_one_dpop_header(wallet: Wallet) -> None:
    code = code_of(wallet.offer())
    assert error(wallet.token_request(code, dpop=None)) == "invalid_dpop_proof"
    two = [wallet.dpop("POST", f"{ISSUER}/token"), wallet.dpop("POST", f"{ISSUER}/token")]
    assert error(wallet.token_request(code, dpop=two)) == "invalid_dpop_proof"


@pytest.mark.covers("DPOP.HTU")
def test_htu_is_normalised(wallet: Wallet) -> None:
    proof = wallet.dpop("POST", "HTTPS://ISSUER.TEST:443/token?ignored=1#frag")
    assert wallet.token_request(code_of(wallet.offer()), dpop=proof).status_code == 200
    other = wallet.dpop("POST", "https://issuer.test/token/other")
    assert error(wallet.token_request(code_of(wallet.offer()), dpop=other)) == "invalid_dpop_proof"


@pytest.mark.obligation("DPOP.TOKEN_TYPE", "OAUTH.TOKEN_ERROR_BODY")
def test_token_response(wallet: Wallet) -> None:
    response = wallet.token_request(code_of(wallet.offer()))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["token_type"] == "DPoP" and body["expires_in"] > 0 and len(body["access_token"]) >= 40


@pytest.mark.covers("OAUTH.TOKEN_ERROR_BODY", "VCI.TOKEN.PREAUTH_REQUEST", "VCI.TOKEN.INVALID_GRANT")
def test_grant_errors(wallet: Wallet) -> None:
    code = code_of(wallet.offer())
    assert error(wallet.token_request(code, extra={"grant_type": "password"})) == "unsupported_grant_type"
    assert error(wallet.token_request("", extra={})) == "invalid_request"
    assert error(wallet.token_request("unknown-code")) == "invalid_grant"
    no_grant = wallet.client.post(
        "/token", content=b"pre-authorized_code=x", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert no_grant.status_code == 400 and error(no_grant) == "invalid_request"


@pytest.mark.covers("VCI.TOKEN.INVALID_GRANT")
def test_pre_authorized_code_is_single_use(wallet: Wallet) -> None:
    code = code_of(wallet.offer())
    assert wallet.token_request(code).status_code == 200
    second = wallet.token_request(code)
    assert second.status_code == 400 and error(second) == "invalid_grant"


@pytest.mark.covers("VCI.TOKEN.PREAUTH_SINGLE_USE")
@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_concurrent_redemption_yields_one_token(
    backend: str, make_issuer: Callable[..., Issuer], wallet: Wallet, clock: Any, tmp_path: Any
) -> None:
    """M-8: real threads call the token logic directly, so the requests truly race (TestClient serializes)."""
    store = SqliteStore(tmp_path / "race.db", clock) if backend == "sqlite" else None
    issuer = make_issuer(store=store) if store is not None else make_issuer()
    offer = issuer.create_offer(
        {"credential_configuration_ids": ["eu.europa.ec.eudi.pid_vc_sd_jwt"], "subject": PID_SUBJECT}, "admin"
    )
    form = {"grant_type": [PRE_AUTH], "pre-authorized_code": [code_of(offer)]}
    proofs = [wallet.dpop("POST", f"{ISSUER}/token") for _ in range(16)]
    barrier = threading.Barrier(len(proofs))
    outcomes: list[str] = []
    # Every thread reads the offer before any of them takes it, so the race happens on every run, not
    # only when the scheduler happens to interleave the threads (review 2, N-M6).
    read_all = threading.Barrier(len(proofs))
    real_get = issuer.store.get

    def get(ns: str, key: str) -> Any:
        value = real_get(ns, key)
        if ns == "offer":
            read_all.wait(timeout=30)
        return value

    issuer.store.get = get  # type: ignore[method-assign]

    def redeem(proof: str) -> None:
        barrier.wait()
        try:
            issuer.token(form, [proof])
            outcomes.append("token")
        except IssuerError as exc:
            outcomes.append(exc.error)

    threads = [threading.Thread(target=redeem, args=(p,)) for p in proofs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["invalid_grant"] * 15 + ["token"]
    issuer.store.get = real_get  # type: ignore[method-assign]


@pytest.mark.covers("VCI.TOKEN.TX_CODE_ERRORS")
def test_tx_code_rules(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer(tx=6)
    code, tx = code_of(offer), str(offer["tx_code"])
    assert len(tx) == 6 and tx.isdigit()
    assert error(wallet.token_request(code)) == "invalid_request", "missing tx_code"
    assert error(wallet.token_request(code, tx_code="000000" if tx != "000000" else "111111")) == "invalid_grant"
    assert wallet.token_request(code, tx_code=tx).status_code == 200, "a wrong attempt does not burn the offer"
    plain = code_of(wallet.offer())
    assert error(wallet.token_request(plain, tx_code="123456")) == "invalid_request", "tx_code not expected"


@pytest.mark.covers("VCI.TOKEN.TX_CODE_ERRORS")
def test_tx_code_lockout(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer(tx=6)
    code, tx = code_of(offer), str(offer["tx_code"])
    wrong = "000000" if tx != "000000" else "111111"
    for _ in range(issuer.settings.tx_code_max_attempts):
        assert error(wallet.token_request(code, tx_code=wrong)) == "invalid_grant"
    assert error(wallet.token_request(code, tx_code=tx)) == "invalid_grant", "offer is burned after the limit"


@pytest.mark.covers("DPOP.JTI_REPLAY")
def test_dpop_proof_replay_is_refused(wallet: Wallet) -> None:
    proof = wallet.dpop("POST", f"{ISSUER}/token")
    assert wallet.token_request(code_of(wallet.offer()), dpop=proof).status_code == 200
    replay = wallet.token_request(code_of(wallet.offer()), dpop=proof)
    assert replay.status_code == 400 and error(replay) == "invalid_dpop_proof"


def credential_body(wallet: Wallet) -> dict[str, Any]:
    holder = EcKey.generate()
    return {
        "credential_configuration_id": "eu.europa.ec.eudi.pid_vc_sd_jwt",
        "proofs": {"jwt": [wallet.proof(holder, wallet.c_nonce())]},
    }


@pytest.mark.covers("OAUTH.RESOURCE_401_CHALLENGE")
def test_credential_endpoint_without_token(wallet: Wallet) -> None:
    response = wallet.client.post("/credential", json={})
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("DPoP ") and "error=" not in challenge and 'algs="ES256 ES384 ES512"' in challenge


@pytest.mark.covers(
    "DPOP.AUTH_SCHEME",
    "DPOP.NO_BEARER_DOWNGRADE",
    "DPOP.ATH",
    "DPOP.KEY_BOUND_TO_TOKEN",
    "OAUTH.RESOURCE_401_CHALLENGE",
)
def test_credential_endpoint_dpop_binding(wallet: Wallet) -> None:
    wallet.get_token()
    url = f"{ISSUER}/credential"
    bearer = wallet.credential_request(credential_body(wallet), scheme="Bearer", dpop=None)
    assert bearer.status_code == 401 and 'error="invalid_token"' in bearer.headers["www-authenticate"]
    no_proof = wallet.credential_request(credential_body(wallet), dpop=None)
    assert no_proof.status_code == 401 and error(no_proof) == "invalid_dpop_proof"
    no_ath = wallet.credential_request(credential_body(wallet), dpop=wallet.dpop("POST", url))
    assert no_ath.status_code == 401 and error(no_ath) == "invalid_dpop_proof"
    other_key = wallet.dpop("POST", url, access_token=wallet.token, key=EcKey.generate())
    stolen = wallet.credential_request(credential_body(wallet), dpop=other_key)
    assert stolen.status_code == 401 and error(stolen) == "invalid_dpop_proof"
    real_token, wallet.token = wallet.token, "forged-token"
    forged = wallet.credential_request(credential_body(wallet))
    assert forged.status_code == 401 and error(forged) == "invalid_token"
    wallet.token = real_token
    basic = wallet.credential_request(credential_body(wallet), scheme="Basic")
    assert basic.status_code == 401 and error(basic) == "invalid_token"


@pytest.mark.covers("DPOP.SERVER_NONCE")
def test_optional_server_nonce(make_issuer: Callable[..., Issuer], pki: Any, clock: Any) -> None:
    issuer = make_issuer(dpop_server_nonce=True)
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        code = code_of(wallet.offer())
        first = wallet.token_request(code)
        assert first.status_code == 400 and error(first) == "use_dpop_nonce"
        nonce = first.headers["dpop-nonce"]
        second = wallet.token_request(code, dpop=wallet.dpop("POST", f"{ISSUER}/token", nonce=nonce))
        assert second.status_code == 200 and "dpop-nonce" in second.headers
