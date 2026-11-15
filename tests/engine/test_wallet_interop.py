"""What wallets in use need from cunho, each found by running that wallet's code against a local cunho: the EU
reference library (kid "0" beside a key attestation; no attestation proof type without key_attestations_required),
NL Wallet (iat in SD-JWT VCs; mdoc items in ISO key order) and Sphereon's last release (metadata at the appended
well-known path)."""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Any

import cbor2
import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.errors import ConfigError
from cunho.jose import parse_jws
from cunho.service import Issuer
from cunho.settings import Settings
from eudi_probe.jose import EcKey, jws

from .helpers import ISSUER, PID_CONFIG, PRE_AUTH, Wallet, refused_by, settings_kwargs
from .test_mdoc import IBAN, IBAN_SUBJECT, mdoc_settings
from .test_mdoc import issue as issue_mdoc
from .test_qeaa import IBAN_FLAT, IBAN_SDJWT


def _kid_proof(wallet: Wallet, holder: EcKey, nonce: str, kid: str) -> str:
    header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "kid": kid,
        "key_attestation": wallet.key_attestation([holder]),
    }
    return jws(header, {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": nonce}, holder)


def _request(wallet: Wallet, proof: str) -> Any:
    return wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})


def test_kid_0_names_the_first_attested_key(wallet: Wallet) -> None:
    """OpenID4VCI 1.0 App. F.1's own example, which the EU reference library sends."""
    wallet.get_token()
    holder = EcKey.generate()
    response = _request(wallet, _kid_proof(wallet, holder, wallet.c_nonce(), "0"))
    assert response.status_code == 200, response.text


def test_any_other_kid_beside_a_key_attestation_is_refused(wallet: Wallet) -> None:
    for kid in ("1", "00", "key-1", " 0"):
        wallet.token = None
        wallet.get_token()
        proof = _kid_proof(wallet, EcKey.generate(), wallet.c_nonce(), kid)

        def send(p: str = proof) -> Any:
            return _request(wallet, p)

        response = refused_by(send, "VCI.F4.PROOF_SIGNATURE", "attested_keys[0]")
        assert response.status_code == 400, kid


def test_kid_0_signed_by_another_key_is_refused(wallet: Wallet) -> None:
    wallet.get_token()
    holder = EcKey.generate()
    header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "kid": "0",
        "key_attestation": wallet.key_attestation([holder]),
    }
    proof = jws(header, {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce()}, EcKey.generate())
    response = refused_by(lambda: _request(wallet, proof), "VCI.F4.PROOF_SIGNATURE", "does not verify")
    assert response.status_code == 400


def test_sd_jwt_vc_carries_iat_equal_to_nbf(wallet: Wallet) -> None:
    response = wallet.issue()
    assert response.status_code == 200, response.text
    credential = response.json()["credentials"][0]["credential"]
    payload = parse_jws(credential.split("~")[0]).payload
    assert payload["iat"] == payload["nbf"]


def test_mdoc_items_keep_the_iso_key_order(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[..., Wallet], pki: Any
) -> None:
    """A verifier that decodes an item and re-encodes it in the ISO order before hashing gets the digest cunho
    signed."""
    wallet = wallet_for(make_issuer(**mdoc_settings(pki)))
    [credential] = issue_mdoc(wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    document = cbor2.loads(base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4)))
    for items in document["nameSpaces"].values():
        for wrapped in items:
            item = cbor2.loads(wrapped.value)
            assert list(item) == ["digestID", "random", "elementIdentifier", "elementValue"]
            assert cbor2.dumps(item) == wrapped.value


def test_metadata_also_answers_at_the_appended_path(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer(issuer_url=f"{ISSUER}/pid", appended_well_known=True)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        for name in ("openid-credential-issuer", "oauth-authorization-server"):
            inserted = client.get(f"/.well-known/{name}/pid")
            appended = client.get(f"/pid/.well-known/{name}")
            assert inserted.status_code == appended.status_code == 200
            assert inserted.json() == appended.json()
        assert client.get("/pid/.well-known/openid-configuration").status_code == 404


def test_no_appended_path_without_an_issuer_path(client: TestClient) -> None:
    assert client.get("/.well-known/openid-credential-issuer").status_code == 200
    assert client.get("/.well-known/openid-credential-issuer/.well-known/openid-credential-issuer").status_code == 404


def _bearer_issuer(make_issuer: Callable[..., Issuer], pki: Any) -> Issuer:
    return make_issuer(
        profile="eaa_provider",
        metadata_dir=pki.root / "metadata",
        published_configurations=(IBAN_SDJWT,),
        accept_bearer_tokens=True,
    )


def _iban_request(wallet: Wallet) -> dict[str, Any]:
    proof = wallet.proof(EcKey.generate(), wallet.c_nonce())
    return {"credential_configuration_id": IBAN_SDJWT, "proofs": {"jwt": [proof]}}


def test_a_wallet_without_dpop_gets_a_bearer_token_where_allowed(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[..., Wallet], pki: Any
) -> None:
    """Sphereon's released wallet sends no DPoP proof. An eaa_provider with accept_bearer_tokens gives it a plain
    Bearer token, used with the Bearer scheme only."""
    wallet = wallet_for(_bearer_issuer(make_issuer, pki))
    offer = wallet.offer(IBAN_FLAT, configs=[IBAN_SDJWT])
    response = wallet.token_request(offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"], dpop=None)
    assert response.status_code == 200, response.text
    assert response.json()["token_type"] == "Bearer"
    wallet.token = response.json()["access_token"]
    as_dpop = refused_by(
        lambda: wallet.credential_request(_iban_request(wallet)), "DPOP.AUTH_SCHEME", "use the Bearer authorization"
    )
    assert as_dpop.status_code == 401 and as_dpop.headers["www-authenticate"].startswith("Bearer")
    issued = wallet.credential_request(_iban_request(wallet), scheme="Bearer", dpop=None)
    assert issued.status_code == 200, issued.text


def test_a_wallet_with_dpop_still_gets_a_bound_token_where_bearer_is_allowed(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[..., Wallet], pki: Any
) -> None:
    wallet = wallet_for(_bearer_issuer(make_issuer, pki))
    wallet.get_token(wallet.offer(IBAN_FLAT, configs=[IBAN_SDJWT]))
    downgrade = refused_by(
        lambda: wallet.credential_request(_iban_request(wallet), scheme="Bearer", dpop=None),
        "DPOP.NO_BEARER_DOWNGRADE",
        "DPoP-bound",
    )
    assert downgrade.status_code == 401
    assert wallet.credential_request(_iban_request(wallet)).status_code == 200


def test_without_the_option_a_token_request_without_dpop_is_refused(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[..., Wallet], pki: Any
) -> None:
    issuer = make_issuer(
        profile="eaa_provider", metadata_dir=pki.root / "metadata", published_configurations=(IBAN_SDJWT,)
    )
    wallet = wallet_for(issuer)
    offer = wallet.offer(IBAN_FLAT, configs=[IBAN_SDJWT])
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    response = refused_by(
        lambda: wallet.token_request(code, dpop=None), "OAUTH.DPOP_REQUIRED", "DPoP proof is required"
    )
    assert response.status_code == 400


def test_bearer_tokens_are_never_for_a_pid_qeaa_or_pub_eaa(pki: Any) -> None:
    for profile in ("pid_provider", "qeaa_provider", "pub_eaa_provider"):
        with pytest.raises(ConfigError, match="accept_bearer_tokens"):
            Settings(**settings_kwargs(pki, profile=profile, accept_bearer_tokens=True))


def _singular(wallet: Wallet) -> dict[str, Any]:
    proof = wallet.proof(EcKey.generate(), wallet.c_nonce())
    return {"credential_configuration_id": IBAN_SDJWT, "proof": {"proof_type": "jwt", "jwt": proof}}


def test_a_singular_jwt_proof_is_read_as_proofs_where_allowed(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[..., Wallet], pki: Any
) -> None:
    """Sphereon's released wallet, taking cunho for draft 15: no DPoP and a singular proof object."""
    issuer = make_issuer(
        profile="eaa_provider",
        metadata_dir=pki.root / "metadata",
        published_configurations=(IBAN_SDJWT,),
        accept_bearer_tokens=True,
        accept_singular_proof=True,
    )
    wallet = wallet_for(issuer)
    offer = wallet.offer(IBAN_FLAT, configs=[IBAN_SDJWT])
    wallet.token = wallet.token_request(
        offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"], dpop=None
    ).json()["access_token"]
    issued = wallet.credential_request(_singular(wallet), scheme="Bearer", dpop=None)
    assert issued.status_code == 200, issued.text
    assert len(issued.json()["credentials"]) == 1
    for bad in ({"proof_type": "cwt", "cwt": "x"}, {"proof_type": "jwt", "jwt": 5}, "x"):
        body = {"credential_configuration_id": IBAN_SDJWT, "proof": bad}

        def send(b: dict[str, Any] = body) -> Any:
            return wallet.credential_request(b, scheme="Bearer", dpop=None)

        refused = refused_by(
            send,
            "VCI.CRED.PROOFS_SHAPE",
            "proofs is required",
        )
        assert refused.status_code == 400


def test_without_the_option_a_singular_proof_is_no_proof(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[..., Wallet], pki: Any
) -> None:
    issuer = make_issuer(
        profile="eaa_provider", metadata_dir=pki.root / "metadata", published_configurations=(IBAN_SDJWT,)
    )
    wallet = wallet_for(issuer)
    wallet.get_token(wallet.offer(IBAN_FLAT, configs=[IBAN_SDJWT]))
    refused = refused_by(
        lambda: wallet.credential_request(_singular(wallet)), "VCI.CRED.PROOFS_SHAPE", "proofs is required"
    )
    assert refused.status_code == 400


def test_singular_proofs_are_never_for_a_pid_qeaa_or_pub_eaa(pki: Any) -> None:
    for profile in ("pid_provider", "qeaa_provider", "pub_eaa_provider"):
        with pytest.raises(ConfigError, match="accept_singular_proof"):
            Settings(**settings_kwargs(pki, profile=profile, accept_singular_proof=True))


def test_the_status_list_token_names_its_issuer(wallet: Wallet) -> None:
    response = wallet.issue()
    assert response.status_code == 200, response.text
    credential = response.json()["credentials"][0]["credential"]
    uri = parse_jws(credential.split("~")[0]).payload["status"]["status_list"]["uri"]
    token = wallet.client.get(uri.removeprefix(ISSUER), headers={"Accept": "application/statuslist+jwt"})
    assert token.status_code == 200, token.text
    claims = parse_jws(token.text).payload
    assert claims["iss"] == ISSUER and claims["sub"] == uri
