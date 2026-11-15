"""A pre-authorized token request that carries a wallet attestation (OpenID4VCI 1.0 §6.1): the client is
authenticated with every check the code flow makes, and the token is bound to it, so a key proof may name it in
iss (App. F.1) and its status period caps validity. A request without one stays anonymous; a broken one is refused
and uses nothing up."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import pytest

from cunho.service import Issuer
from eudi_probe.jose import EcKey, jws

from .codewallet import CodeWallet
from .helpers import ISSUER, PID_CONFIG, PRE_AUTH, disclosures, refused_by


def preauth_token(wallet: CodeWallet, offer: dict[str, Any], headers: list[tuple[str, str]]) -> Any:
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    form = {"grant_type": PRE_AUTH, "pre-authorized_code": code, "client_id": wallet.client_id}
    sent = [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("DPoP", wallet.dpop("POST", f"{ISSUER}/token")),
        *headers,
    ]
    return wallet.client.post("/token", content=urlencode(form), headers=sent)


def proof_with_iss(wallet: CodeWallet, holder: EcKey, iss: str) -> str:
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "key_attestation": wallet.key_attestation([holder])}
    claims = {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce(), "iss": iss}
    return jws(header, claims, holder)


def issue_with_iss(wallet: CodeWallet, iss: str) -> Any:
    proof = proof_with_iss(wallet, EcKey.generate(), iss)
    return wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})


@pytest.mark.covers("VCI.F4.PROOF_SIGNATURE")
def test_an_attested_request_binds_the_token_to_its_client(code_wallet: CodeWallet) -> None:
    response = preauth_token(code_wallet, code_wallet.offer(), code_wallet.attestation_headers())
    assert response.status_code == 200, response.text
    code_wallet.token = response.json()["access_token"]
    refused_by(
        lambda: issue_with_iss(code_wallet, "https://other-wallet.test"),
        "VCI.F4.PROOF_SIGNATURE",
        "iss must be the client_id",
    )
    named = issue_with_iss(code_wallet, code_wallet.client_id)
    assert named.status_code == 200, named.text


def test_the_attestation_caps_validity_as_in_the_code_flow(code_wallet: CodeWallet) -> None:
    anonymous = code_wallet.offer()
    code_wallet.get_token(anonymous)
    free = code_wallet.issue()
    code_wallet.client_status_offset = 3 * 86_400  # shorter than the credential validity, so it caps
    response = preauth_token(code_wallet, code_wallet.offer(), code_wallet.attestation_headers())
    code_wallet.token = response.json()["access_token"]
    capped = code_wallet.issue()
    exp = disclosures(capped.json()["credentials"][0]["credential"])[1]["exp"]
    assert exp < disclosures(free.json()["credentials"][0]["credential"])[1]["exp"]
    assert exp <= int(code_wallet.clock()) + 3 * 86_400


@pytest.mark.covers("WIA.REQUIRED_AT_PAR_AND_TOKEN", "WIA.POP_CNF")
def test_a_broken_attestation_is_refused_and_uses_nothing_up(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    offer = code_wallet.offer()
    one_header = refused_by(
        lambda: preauth_token(code_wallet, offer, code_wallet.attestation_headers()[:1]),
        "WIA.REQUIRED_AT_PAR_AND_TOKEN",
        "exactly one",
    )
    assert one_header.status_code == 401 and one_header.json()["error"] == "invalid_client"
    pop_alone = refused_by(
        lambda: preauth_token(code_wallet, offer, code_wallet.attestation_headers()[1:]),
        "WIA.REQUIRED_AT_PAR_AND_TOKEN",
        "exactly one",
    )
    assert pop_alone.status_code == 401 and pop_alone.json()["error"] == "invalid_client"
    stranger = EcKey.generate()
    refused_by(
        lambda: preauth_token(
            code_wallet, offer, code_wallet.attestation_headers(pop=code_wallet.attestation_pop(signing_key=stranger))
        ),
        "WIA.POP_CNF",
        "",
    )
    anonymous = preauth_token(code_wallet, offer, [])
    assert anonymous.status_code == 200, "the refusals left the pre-authorized code unused"
