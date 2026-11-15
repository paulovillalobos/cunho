"""The parts of the authorization code wallet that need no endpoint. The full run (PAR, authorize, the test login,
the token request) against cunho is in test_authorize.py."""

from __future__ import annotations

import re
from collections.abc import Iterator
from urllib.parse import parse_qs

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.testclient import TestClient

from cunho.jose import load_x5c, parse_jws, validate_path, verify
from eudi_probe.jose import EcKey

from .codewallet import CLIENT_ID, POP_TYP, REDIRECT_URI, WIA_TYP, CodeWallet, Pkce, Redirect, read_form
from .helpers import ISSUER, Clock, Pki
from .pki import WIA_POLICY, TestPki


@pytest.fixture
def code_wallet(client: TestClient, pki: Pki, clock: Clock, trust_pki: TestPki) -> CodeWallet:
    return CodeWallet(client, pki, clock, provider=trust_pki.wallet_provider)


def test_pkce_matches_the_rfc_7636_vector() -> None:
    vector = Pkce.rfc7636_appendix_b()
    assert Pkce.of(vector.verifier) == vector and vector.method == "S256"


def test_a_random_pkce_verifier_is_43_unreserved_characters() -> None:
    pairs = [Pkce.random() for _ in range(20)]
    assert all(re.fullmatch(r"[A-Za-z0-9._~-]{43}", p.verifier) for p in pairs)
    assert all(Pkce.of(p.verifier) == p for p in pairs) and len({p.verifier for p in pairs}) == 20


def test_the_attestation_is_signed_by_the_wallet_providers_wia_signer(
    code_wallet: CodeWallet, trust_pki: TestPki, clock: Clock
) -> None:
    token = parse_jws(code_wallet.attestation())
    assert token.header["typ"] == WIA_TYP and token.header["alg"] == "ES256"
    chain = load_x5c(token.header["x5c"])
    wp = trust_pki.wallet_provider
    crls = [trust_pki.crls["root"], trust_pki.crls["intermediate"]]
    validate_path(chain, [wp.root.cert], trust_pki.now, frozenset({WIA_POLICY}), crls)
    leaf = chain[0].public_key()
    assert isinstance(leaf, ec.EllipticCurvePublicKey)
    assert verify("ES256", leaf, token.signing_input, token.signature)
    claims = token.payload
    assert claims["sub"] == CLIENT_ID and claims["cnf"]["jwk"] == code_wallet.instance_key.public_jwk()
    assert claims["exp"] > claims["iat"] == int(clock()) and claims["client_status"]["exp"] > claims["exp"]
    assert claims["client_status"]["status"]["status_list"]["uri"].startswith("https://")


def test_an_attestation_claim_can_be_left_out_or_replaced(code_wallet: CodeWallet) -> None:
    claims = parse_jws(code_wallet.attestation(iss=..., wallet_name="other")).payload
    assert "iss" not in claims and claims["wallet_name"] == "other"
    header = parse_jws(code_wallet.attestation(_header={"typ": "jwt", "alg": "ES256"})).header
    assert header == {"typ": "jwt", "alg": "ES256"}


def test_the_pop_is_signed_with_the_attested_key_for_the_issuer(code_wallet: CodeWallet) -> None:
    first, second = parse_jws(code_wallet.attestation_pop()), parse_jws(code_wallet.attestation_pop())
    assert first.header == {"typ": POP_TYP, "alg": "ES256"}
    assert first.payload["aud"] == ISSUER and first.payload["iss"] == CLIENT_ID
    assert first.payload["jti"] != second.payload["jti"]
    key = code_wallet.instance_key.private.public_key()
    assert verify("ES256", key, first.signing_input, first.signature)
    other = EcKey.generate()
    forged = parse_jws(code_wallet.attestation_pop(signing_key=other))
    assert not verify("ES256", key, forged.signing_input, forged.signature)


def test_the_attestation_headers_are_the_two_of_draft_07(code_wallet: CodeWallet) -> None:
    names = [name for name, _ in code_wallet.attestation_headers()]
    assert names == ["OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"]
    assert code_wallet.attestation_headers(attest=False) == []


def test_a_redirect_gives_its_target_and_parameters() -> None:
    back = Redirect(303, f"{REDIRECT_URI}?code=abc&state=xyz&iss=https%3A%2F%2Fissuer.test")
    assert back.target == REDIRECT_URI and back.params == {"code": "abc", "state": "xyz", "iss": ISSUER}
    with pytest.raises(AssertionError, match="more than once"):
        _ = Redirect(303, f"{REDIRECT_URI}?code=a&code=b").params


def test_a_form_is_read_with_its_hidden_inputs() -> None:
    page = (
        '<p>log in</p><form action="/login/done" method="POST"><input type="hidden" name="login_state" value="s1">'
        '<input name="person"><input type="submit" value="go"></form><form action="/other"></form>'
    )
    assert read_form(page) == ("/login/done", "post", {"login_state": "s1", "person": ""})
    with pytest.raises(AssertionError, match="no form"):
        read_form("<p>nothing</p>")


@pytest.fixture
def login_app() -> Iterator[TestClient]:
    """Stands in for the authorization endpoint and a login page, to test the walk the wallet makes."""
    app = FastAPI()

    @app.get("/authorize")
    async def authorize() -> RedirectResponse:
        return RedirectResponse("/login?login_state=s1", status_code=303)

    @app.get("/login")
    async def page(login_state: str) -> HTMLResponse:
        return HTMLResponse(
            f'<form method="post" action="/login"><input type="hidden" name="login_state" value="{login_state}">'
            '<input name="person"></form>'
        )

    @app.post("/login")
    async def done(request: Request) -> RedirectResponse:
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        code = f"code-for-{form['person']}-{form['login_state']}"
        return RedirectResponse(f"{REDIRECT_URI}?code={code}&state=st&iss={ISSUER}", status_code=303)

    with TestClient(app, base_url=ISSUER) as client:
        yield client


def test_the_login_walk_ends_at_the_wallet_with_the_code(
    login_app: TestClient, pki: Pki, clock: Clock, trust_pki: TestPki
) -> None:
    wallet = CodeWallet(login_app, pki, clock, provider=trust_pki.wallet_provider)
    back = wallet.login(wallet.authorize("urn:ietf:params:oauth:request_uri:x"), {"person": "ana"})
    assert back.status == 303 and back.params["code"] == "code-for-ana-s1"
