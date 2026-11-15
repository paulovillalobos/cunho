"""Wallet attestation as client authentication (draft-07 §9, TS3 v1.5.2 §2.2.1.2, HAIP 1.0 §4.4.1).

Each negative changes one thing in an otherwise good attestation or proof of possession, so only the check it is
about can refuse it, and asserts that check's rule (review 3, N3-H1)."""

from __future__ import annotations

import base64
import functools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization

from cunho.client_auth import ClientIdentity
from cunho.errors import IssuerError
from cunho.jose import thumbprint
from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .codewallet import CLIENT_ID, CodeWallet, Pkce
from .helpers import ISSUER, raised_by
from .pki import TestPki


def authenticate(
    wallet: CodeWallet, issuer: Issuer, attestation: str | None = None, pop: str | None = None, **kwargs: Any
) -> ClientIdentity:
    return issuer.client_auth.authenticate(
        [attestation or wallet.attestation()], [pop or wallet.attestation_pop()], **kwargs
    )


def refused(rule: str, reason: str, action: Callable[[], Any]) -> IssuerError:
    error = raised_by(action, rule, reason)
    assert error.error == "invalid_client" and error.status == 401
    return error


def test_a_good_attestation_names_the_wallet_solution_and_its_instance(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    identity = authenticate(code_wallet, code_issuer, client_id=CLIENT_ID)
    assert identity.sub == CLIENT_ID and identity.wallet_name == "cunho test wallet"
    assert identity.cnf_jkt == thumbprint(code_wallet.instance_key.public_jwk())
    assert identity.status is not None and identity.status["status_list"]["idx"] == 3
    assert identity.status_exp == int(code_wallet.clock()) + code_wallet.client_status_offset


def test_the_ts3_shape_without_iss_is_accepted(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """Decision 6: TS3 v1.5.2 dropped iss from the WIA, and the later drafts let the PoP leave it out too."""
    identity = authenticate(
        code_wallet, code_issuer, code_wallet.attestation(iss=...), code_wallet.attestation_pop(iss=...)
    )
    assert identity.sub == CLIENT_ID


def test_the_cnf_key_need_not_be_the_dpop_key(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """TS3 v1.5.2 rolled back the rule that the cnf key equals the DPoP key; nothing compares them."""
    assert code_wallet.instance_key.public_jwk() != code_wallet.dpop_key.public_jwk()
    authenticate(code_wallet, code_issuer)


@pytest.mark.covers("WIA.REQUIRED_AT_PAR_AND_TOKEN")
@pytest.mark.parametrize(("attestations", "pops"), [(0, 1), (1, 0), (2, 1), (1, 2), (0, 0)])
def test_exactly_one_of_each_header(code_wallet: CodeWallet, code_issuer: Issuer, attestations: int, pops: int) -> None:
    refused(
        "WIA.REQUIRED_AT_PAR_AND_TOKEN",
        "exactly one",
        lambda: code_issuer.client_auth.authenticate(
            [code_wallet.attestation()] * attestations, [code_wallet.attestation_pop()] * pops
        ),
    )


def _header(token: str) -> dict[str, Any]:
    return json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))


@pytest.mark.covers("WIA.VERIFY")
@pytest.mark.parametrize(
    ("label", "change", "reason"),
    [
        ("typ", {"_header": "typ"}, "typ must be oauth-client-attestation+jwt"),
        ("alg", {"_header": "alg"}, "alg must be one of"),
        ("not a JWT", {"_raw": "not.a jwt"}, "not a compact JWT"),
        ("no sub", {"sub": ...}, "needs a sub"),
        ("empty sub", {"sub": ""}, "needs a sub"),
        ("numeric sub", {"sub": 7}, "needs a sub"),
        ("long sub", {"sub": "x" * 513}, "needs a sub"),
    ],
)
def test_the_attestation_must_be_well_formed(
    code_wallet: CodeWallet, code_issuer: Issuer, label: str, change: dict[str, Any], reason: str
) -> None:
    assert code_wallet.provider is not None
    x5c = code_wallet.provider.wia_x5c()
    if change.get("_header") == "typ":
        token = code_wallet.attestation(_header={"typ": "jwt", "alg": "ES256", "x5c": x5c})
    elif change.get("_header") == "alg":
        token = code_wallet.attestation(_header={"typ": "oauth-client-attestation+jwt", "alg": "HS256", "x5c": x5c})
    elif "_raw" in change:
        token = change["_raw"]
    else:
        token = code_wallet.attestation(**change)
    refused("WIA.VERIFY", reason, lambda: authenticate(code_wallet, code_issuer, token))


@pytest.mark.covers("WIA.CHAIN_TO_WP_LIST")
def test_an_attestation_from_an_untrusted_provider_is_refused(
    code_wallet: CodeWallet, code_issuer: Issuer, trust_pki: TestPki
) -> None:
    other = trust_pki.untrusted
    token = code_wallet.attestation(
        signing_key=EcKey(other.wia_signer.key),
        _header={"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": other.wia_x5c()},
    )
    error = refused(
        "WIA.CHAIN_TO_WP_LIST",
        "not from a trusted wallet provider",
        lambda: authenticate(code_wallet, code_issuer, token),
    )
    assert "anchor" not in error.description, "the error never says which anchor failed"


@pytest.mark.covers("WIA.CHAIN_TO_WP_LIST")
def test_an_attestation_whose_signer_is_revoked_is_refused(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    trust_pki: TestPki,
    tmp_path: Path,
) -> None:
    anchors = tmp_path / "anchors.pem"
    anchors.write_bytes(trust_pki.wallet_provider.root.pem)
    crls = tmp_path / "revoking.crl"
    crls.write_bytes(trust_pki.files["wallet-providers-revoking.crl"].read_bytes())
    issuer = make_code_issuer(wallet_provider_anchors=anchors, wallet_provider_crls=crls)
    wallet = code_wallet_for(issuer)
    refused("WIA.CHAIN_TO_WP_LIST", "not from a trusted wallet provider", lambda: authenticate(wallet, issuer))
    good = tmp_path / "good.crl"
    good.write_bytes(trust_pki.files["wallet-providers.crl"].read_bytes())
    fine = make_code_issuer(wallet_provider_anchors=anchors, wallet_provider_crls=good)
    authenticate(code_wallet_for(fine), fine)


@pytest.mark.covers("WIA.SIGNATURE_X5C")
def test_an_attestation_signed_by_another_key_is_refused(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    token = code_wallet.attestation(signing_key=EcKey.generate())
    refused("WIA.SIGNATURE_X5C", "does not verify under its x5c", lambda: authenticate(code_wallet, code_issuer, token))


@pytest.mark.covers("WIA.NOT_EXPIRED")
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"exp": 0}, "has expired"),
        ({"exp": ...}, "has expired or has no exp"),
        ({"exp": "soon"}, "has expired or has no exp"),
        ({"iat": "+120"}, "iat is in the future"),
        ({"nbf": "+120"}, "nbf is in the future"),
        ({"iat": "x"}, "iat is in the future"),
    ],
)
def test_an_attestation_out_of_its_time_is_refused(
    code_wallet: CodeWallet, code_issuer: Issuer, change: dict[str, Any], reason: str
) -> None:
    now = int(code_wallet.clock())
    claims: dict[str, Any] = {
        k: (now + int(v[1:]) if isinstance(v, str) and v.startswith("+") else v) for k, v in change.items()
    }
    if claims.get("exp") == 0:
        claims["exp"] = now
    token = code_wallet.attestation(**claims)
    refused("WIA.NOT_EXPIRED", reason, lambda: authenticate(code_wallet, code_issuer, token))


def test_an_attestation_a_minute_ahead_is_accepted(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    now = int(code_wallet.clock())
    authenticate(code_wallet, code_issuer, code_wallet.attestation(iat=now + 60, nbf=now + 60))


@pytest.mark.covers("WIA.CNF_PUBLIC")
@pytest.mark.parametrize(
    ("cnf", "reason"),
    [
        ("private", "must hold a public jwk"),
        ({}, "must hold a public jwk"),
        ({"jwk": "x"}, "must hold a public jwk"),
        ({"jwk": {"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}}, "not an accepted public key"),
        ("p384", "not an accepted public key"),
    ],
)
def test_the_cnf_key_must_be_an_accepted_public_key(
    code_wallet: CodeWallet, code_issuer: Issuer, cnf: Any, reason: str
) -> None:
    if cnf == "private":
        cnf = {"jwk": code_wallet.instance_key.private_jwk()}
    elif cnf == "p384":
        from cryptography.hazmat.primitives.asymmetric import ec

        from cunho.jose import jwk_from_public_key

        cnf = {"jwk": jwk_from_public_key(ec.generate_private_key(ec.SECP384R1()).public_key())}
    token = code_wallet.attestation(cnf=cnf)
    refused("WIA.CNF_PUBLIC", reason, lambda: authenticate(code_wallet, code_issuer, token))


@pytest.mark.covers("WIA.POP_CNF")
@pytest.mark.parametrize(
    ("label", "reason"),
    [("other key", "does not verify under the cnf key"), ("typ", "typ must be"), ("alg", "alg must be one of")],
)
def test_the_proof_of_possession_must_be_signed_by_the_cnf_key(
    code_wallet: CodeWallet, code_issuer: Issuer, label: str, reason: str
) -> None:
    if label == "other key":
        pop = code_wallet.attestation_pop(signing_key=EcKey.generate())
    elif label == "typ":
        pop = code_wallet.attestation_pop(_header={"typ": "jwt", "alg": "ES256"})
    else:
        pop = code_wallet.attestation_pop(_header={"typ": "oauth-client-attestation-pop+jwt", "alg": "none"})
    refused("WIA.POP_CNF", reason, lambda: authenticate(code_wallet, code_issuer, pop=pop))


@pytest.mark.covers("WIA.POP_FRESH")
@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"aud": "https://elsewhere.test"}, "aud must be the issuer identifier"),
        ({"aud": [ISSUER]}, "aud must be the issuer identifier"),
        ({"aud": f"{ISSUER}/token"}, "aud must be the issuer identifier"),
        ({"iat": "+61"}, "outside the accepted window"),
        ({"iat": "-61"}, "outside the accepted window"),
        ({"iat": ...}, "outside the accepted window"),
        ({"jti": ...}, "needs a jti"),
        ({"jti": "short"}, "needs a jti"),
    ],
)
def test_the_proof_of_possession_must_be_fresh_and_for_this_issuer(
    code_wallet: CodeWallet, code_issuer: Issuer, change: dict[str, Any], reason: str
) -> None:
    now = int(code_wallet.clock())
    claims: dict[str, Any] = {
        k: (now + int(v) if isinstance(v, str) and v[:1] in "+-" else v) for k, v in change.items()
    }
    pop = code_wallet.attestation_pop(**claims)
    refused("WIA.POP_FRESH", reason, lambda: authenticate(code_wallet, code_issuer, pop=pop))


def test_the_window_edges_are_accepted(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """FAPI 2.0 §5.3.2.1 item 13: up to 10 s ahead must be accepted; cunho takes up to 60 s either way."""
    now = int(code_wallet.clock())
    for iat in (now + 10, now + 60, now - 60):
        authenticate(code_wallet, code_issuer, pop=code_wallet.attestation_pop(iat=iat))


@pytest.mark.covers("WIA.POP_FRESH")
def test_a_proof_of_possession_is_used_once(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pop = code_wallet.attestation_pop()
    authenticate(code_wallet, code_issuer, pop=pop)
    refused("WIA.POP_FRESH", "already used", lambda: authenticate(code_wallet, code_issuer, pop=pop))
    other_instance = CodeWallet(code_wallet.client, code_wallet.pki, code_wallet.clock, provider=code_wallet.provider)
    same_jti = other_instance.attestation_pop(jti=json.loads(base64.urlsafe_b64decode(pop.split(".")[1] + "=="))["jti"])
    authenticate(other_instance, code_issuer, pop=same_jti)  # replay is per instance key


@pytest.mark.covers("WIA.CLIENT_ID_IS_SUB")
@pytest.mark.parametrize(
    ("label", "reason"),
    [("client_id", "client_id is not the sub"), ("pop iss", "iss is not the attestation sub")],
)
def test_the_client_id_and_the_pop_iss_are_the_sub(
    code_wallet: CodeWallet, code_issuer: Issuer, label: str, reason: str
) -> None:
    if label == "client_id":
        action = functools.partial(authenticate, code_wallet, code_issuer, client_id="https://other.test")
    else:
        pop = code_wallet.attestation_pop(iss="https://other.test")
        action = functools.partial(authenticate, code_wallet, code_issuer, pop=pop)
    refused("WIA.CLIENT_ID_IS_SUB", reason, action)


@pytest.mark.covers("WIA.CLIENT_STATUS")
@pytest.mark.parametrize(
    "client_status",
    [
        ...,
        "x",
        {},
        {"status": {}, "exp": "+60"},
        {"status": {"status_list": {"uri": "https://wp.test/s", "idx": "3"}}, "exp": "+60"},
        {"status": {"status_list": {"uri": "https://wp.test/s", "idx": True}}, "exp": "+60"},
        {"status": {"status_list": {"idx": 3}}, "exp": "+60"},
    ],
)
def test_client_status_must_name_a_status_list_entry(
    code_wallet: CodeWallet, code_issuer: Issuer, client_status: Any
) -> None:
    if isinstance(client_status, dict) and client_status.get("exp") == "+60":
        client_status = {**client_status, "exp": int(code_wallet.clock()) + 60}
    token = code_wallet.attestation(client_status=client_status)
    refused("WIA.CLIENT_STATUS", "needs client_status", lambda: authenticate(code_wallet, code_issuer, token))


@pytest.mark.covers("WIA.STATUS_EXP_NOT_TOKEN_EXP")
def test_the_status_period_is_client_status_exp_never_the_attestation_exp(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """CIR 2024/2979 Annex Ib C_WIA-3: a short-lived attestation with a long status period gives the long one, and
    a long-lived one whose status period has passed is refused."""
    now = int(code_wallet.clock())
    listed = {"status_list": {"uri": "https://wp.test/s", "idx": 3}}
    long_status = code_wallet.attestation(exp=now + 30, client_status={"status": listed, "exp": now + 40 * 86_400})
    assert authenticate(code_wallet, code_issuer, long_status).status_exp == now + 40 * 86_400
    for status in ({"status": listed, "exp": now}, {"status": listed}, {"status": listed, "exp": "later"}):
        token = code_wallet.attestation(exp=now + 86_400, client_status=status)
        check = functools.partial(authenticate, code_wallet, code_issuer, token)
        refused("WIA.STATUS_EXP_NOT_TOKEN_EXP", "client_status.exp", check)


def test_a_failed_attestation_at_par_is_a_401_and_writes_nothing(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    before = code_issuer.store.items("par")
    response = code_wallet.par(Pkce.random(), scope="x", attest=False)
    assert response.status_code == 401 and response.json()["error"] == "invalid_client"
    assert code_issuer.store.items("par") == before


def test_the_certificate_in_x5c_is_the_one_that_signs(code_wallet: CodeWallet, trust_pki: TestPki) -> None:
    header = _header(code_wallet.attestation())
    leaf = base64.b64decode(header["x5c"][0])
    assert leaf == trust_pki.wallet_provider.wia_signer.cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.covers("WIA.CHAIN_TO_WP_LIST")
def test_with_wia_policies_a_key_attestation_signer_cannot_sign_a_wallet_attestation(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    trust_pki: TestPki,
) -> None:
    """Both signers sit under the same wallet provider; the policy tells which one may vouch for an instance."""
    from .pki import WIA_POLICY

    issuer = make_code_issuer(wia_signer_policy_oids=(WIA_POLICY,))
    wallet = code_wallet_for(issuer)
    authenticate(wallet, issuer)
    wp = trust_pki.wallet_provider
    token = wallet.attestation(
        signing_key=EcKey(wp.ka_signer.key),
        _header={"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": wp.ka_x5c()},
    )
    refused("WIA.CHAIN_TO_WP_LIST", "not from a trusted wallet provider", lambda: authenticate(wallet, issuer, token))


@pytest.mark.covers("WIA.VERIFY")
@pytest.mark.parametrize("aud", ["https://other-issuer.test", ["https://other-issuer.test"], [ISSUER, 7], 7])
def test_an_attestation_signed_for_another_audience_is_refused(
    code_wallet: CodeWallet, code_issuer: Issuer, aud: Any
) -> None:
    """RFC 7519 §4.1.3: the provider's aud binds the attestation; a PoP made for this issuer does not undo it."""
    token = code_wallet.attestation(aud=aud)
    refused("WIA.VERIFY", "meant for another audience", lambda: authenticate(code_wallet, code_issuer, token))


@pytest.mark.parametrize("aud", [ISSUER, [ISSUER], ["https://other-issuer.test", ISSUER]])
def test_an_attestation_whose_aud_names_this_issuer_is_accepted(
    code_wallet: CodeWallet, code_issuer: Issuer, aud: Any
) -> None:
    authenticate(code_wallet, code_issuer, code_wallet.attestation(aud=aud))


def test_a_sub_of_512_characters_is_accepted(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    code_wallet.client_id = "x" * 512
    assert authenticate(code_wallet, code_issuer).sub == "x" * 512


@pytest.mark.covers("WIA.VERIFY", "WIA.POP_CNF")
@pytest.mark.parametrize("alg", [["ES256"], {"a": 1}, 256, None])
def test_an_alg_that_is_not_a_string_is_refused(code_wallet: CodeWallet, code_issuer: Issuer, alg: Any) -> None:
    assert code_wallet.provider is not None
    header = {"typ": "oauth-client-attestation+jwt", "alg": alg, "x5c": code_wallet.provider.wia_x5c()}
    token = code_wallet.attestation(_header=header)
    refused("WIA.VERIFY", "alg must be one of", lambda: authenticate(code_wallet, code_issuer, token))
    pop = code_wallet.attestation_pop(_header={"typ": "oauth-client-attestation-pop+jwt", "alg": alg})
    refused("WIA.POP_CNF", "alg must be one of", lambda: authenticate(code_wallet, code_issuer, pop=pop))


@pytest.mark.parametrize("length", [16, 256])
def test_a_jti_of_16_to_256_characters_is_accepted(code_wallet: CodeWallet, code_issuer: Issuer, length: int) -> None:
    authenticate(code_wallet, code_issuer, pop=code_wallet.attestation_pop(jti="j" * length))


@pytest.mark.covers("WIA.POP_FRESH")
@pytest.mark.parametrize("length", [15, 257])
def test_a_jti_outside_16_to_256_characters_is_refused(
    code_wallet: CodeWallet, code_issuer: Issuer, length: int
) -> None:
    pop = code_wallet.attestation_pop(jti="j" * length)
    refused("WIA.POP_FRESH", "needs a jti", lambda: authenticate(code_wallet, code_issuer, pop=pop))
