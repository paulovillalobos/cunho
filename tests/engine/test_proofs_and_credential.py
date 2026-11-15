"""Key proofs, key attestations, batch issuance and the credential request (OpenID4VCI §8, App. D and F)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from cunho.service import Issuer
from eudi_probe.jose import jws
from eudi_probe.wallet import key_proof

from .helpers import (
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    START,
    EcKey,
    Wallet,
    certificate,
    der_b64,
    disclosures,
    holder_thumbprint,
    hs256,
    refused_by,
)

PID = PID_CONFIG


def error(response: Any) -> str:
    return str(response.json()["error"])


def request(wallet: Wallet, proofs: list[str], config: str = PID) -> Any:
    if wallet.token is None:
        wallet.get_token()
    return wallet.credential_request({"credential_configuration_id": config, "proofs": {"jwt": proofs}})


@pytest.mark.covers(
    "VCI.F1.PROOF_TYP",
    "VCI.F1.PROOF_AUD",
    "VCI.F1.PROOF_IAT",
    "VCI.F4.PROOF_SIGNATURE",
)
@pytest.mark.parametrize(
    ("label", "build"),
    [
        ("typ", lambda w, h, n: w.proof(h, n, typ="JWT")),
        (
            "aud",
            lambda w, h, n: key_proof(
                h, "https://other.test", nonce=n, iat=int(w.clock()), key_attestation=w.key_attestation([h])
            ),
        ),
        ("stale iat", lambda w, h, n: w.proof(h, n, iat=int(w.clock()) - 86_400)),
        ("signature", lambda w, h, n: w.proof(h, n, signing_key=EcKey.generate())),
        ("not a JWS", lambda w, h, n: "garbage"),
    ],
)
def test_invalid_key_proofs(wallet: Wallet, label: str, build: Any) -> None:
    response = request(wallet, [build(wallet, EcKey.generate(), wallet.c_nonce())])
    assert response.status_code == 400, label
    assert error(response) == "invalid_proof", label


@pytest.mark.covers("VCI.F1.PROOF_ALG_ASYMMETRIC", "VCI.F1.PROOF_ISS_ANON_PREAUTH", "VCI.F4.PROOF_SIGNATURE")
def test_symmetric_iss_and_private_key_proofs(wallet: Wallet) -> None:
    holder = EcKey.generate()
    attestation = wallet.key_attestation([holder])
    symmetric = hs256(
        {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce()},
        {"typ": "openid4vci-proof+jwt", "alg": "HS256", "key_attestation": attestation},
    )
    assert error(request(wallet, [symmetric])) == "invalid_proof"
    with_iss = jws(
        {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": holder.public_jwk(), "key_attestation": attestation},
        {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce(), "iss": "wallet"},
        holder,
    )
    assert error(request(wallet, [with_iss])) == "invalid_proof"
    private = wallet.proof(holder, wallet.c_nonce(), header_jwk=holder.private_jwk())
    assert error(request(wallet, [private])) == "invalid_proof"


@pytest.mark.covers("VCI.NONCE.C_NONCE_VALID")
@pytest.mark.obligation("VCI.NONCE.ENDPOINT", "VCI.NONCE.NO_STORE")
def test_nonce_rules(wallet: Wallet) -> None:
    response = wallet.client.post("/nonce")
    assert response.headers["cache-control"] == "no-store"
    assert wallet.client.post("/nonce").json()["c_nonce"] != response.json()["c_nonce"]
    missing = request(wallet, [wallet.proof(EcKey.generate(), None)])
    assert error(missing) == "invalid_proof"
    unknown = request(wallet, [wallet.proof(EcKey.generate(), "made-up-nonce")])
    assert error(unknown) == "invalid_nonce"
    nonce = wallet.c_nonce()
    assert request(wallet, [wallet.proof(EcKey.generate(), nonce)]).status_code == 200
    reused = request(wallet, [wallet.proof(EcKey.generate(), nonce)])
    assert error(reused) == "invalid_nonce"


@pytest.mark.covers("KA.VERIFY", "KA.CHAIN_TO_WP_LIST", "KA.JWT_PROOF_ATTESTED_KEY0", "KA.PID_KEY_IN_WSCD")
def test_key_attestation_checks(wallet: Wallet) -> None:
    """Each case is refused by the check it names (review 3, N3-H1).

    The "untrusted chain" case used to put a rogue certificate in x5c but sign with the trusted key, so the
    signature check refused it and the anchor check could be deleted with this test green. Each attestation
    is now signed by the key of the certificate it carries; test_review3_fixes has the full table.
    """
    holder = EcKey.generate()
    other_ca_key = ec.generate_private_key(ec.SECP256R1())
    other_ca = certificate("Untrusted WP", other_ca_key, ca=True)
    rogue = EcKey.generate()
    rogue_leaf = certificate("Rogue KA", rogue.private, (other_ca, other_ca_key))
    self_key = EcKey.generate()
    self_signed = certificate("Self Signed KA", self_key.private)

    def attestation(x5c: list[str], key: EcKey, **claims: Any) -> str:
        header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c}
        return wallet.key_attestation([holder], signing_key=key, _header=header, **claims)

    cases: dict[str, tuple[str, str, Any]] = {
        "missing": (
            "KA.VERIFY",
            "requires a key attestation",
            lambda: wallet.proof(holder, wallet.c_nonce(), attest=False),
        ),
        "untrusted chain": (
            "KA.CHAIN_TO_WP_LIST",
            "chain does not end at a trusted anchor",
            lambda: wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation([der_b64(rogue_leaf)], rogue)),
        ),
        "self-signed leaf": (
            "KA.CHAIN_TO_WP_LIST",
            "self-signed",
            lambda: wallet.proof(
                holder, wallet.c_nonce(), key_attestation=attestation([der_b64(self_signed)], self_key)
            ),
        ),
        "expired": (
            "KA.VERIFY",
            "has expired",
            lambda: wallet.proof(
                holder, wallet.c_nonce(), key_attestation=wallet.key_attestation([holder], exp=int(wallet.clock()) - 1)
            ),
        ),
        "no exp with jwt proof": (
            "KA.VERIFY",
            "needs exp",
            lambda: wallet.proof(holder, wallet.c_nonce(), key_attestation=wallet.key_attestation([holder], exp=None)),
        ),
        "weak key storage": (
            "KA.PID_KEY_IN_WSCD",
            "key_storage does not meet",
            lambda: wallet.proof(
                holder,
                wallet.c_nonce(),
                key_attestation=wallet.key_attestation([holder], key_storage=["iso_18045_basic"]),
            ),
        ),
        "weak user auth": (
            "KA.VERIFY",
            "user_authentication does not meet",
            lambda: wallet.proof(
                holder,
                wallet.c_nonce(),
                key_attestation=wallet.key_attestation([holder], user_authentication=["iso_18045_basic"]),
            ),
        ),
        "wrong typ": (
            "KA.VERIFY",
            "typ must be key-attestation+jwt",
            lambda: wallet.proof(
                holder,
                wallet.c_nonce(),
                key_attestation=wallet.key_attestation(
                    [holder], _header={"typ": "JWT", "alg": "ES256", "x5c": [der_b64(wallet.pki.ka_leaf)]}
                ),
            ),
        ),
        "not signed by key 0": (
            "KA.JWT_PROOF_ATTESTED_KEY0",
            "signed with attested_keys[0]",
            lambda: wallet.proof(
                holder, wallet.c_nonce(), key_attestation=wallet.key_attestation([EcKey.generate(), holder])
            ),
        ),
    }

    def send(build: Any) -> Any:
        return lambda: request(wallet, [build()])

    for label, (rule, reason, build) in cases.items():
        response = refused_by(send(build), rule, reason)
        assert response.status_code == 400 and error(response) == "invalid_proof", label


@pytest.mark.covers("VALIDITY.PID_LE_STATUS_EXP")
@pytest.mark.obligation("KA.STATUS_EXP_NOT_TOKEN_EXP", "VALIDITY.PID_LE_STATUS_EXP")
def test_validity_capped_by_key_storage_status(wallet: Wallet) -> None:
    """Review 2, N-M6: every request runs on a fresh token with a key attestation for its own key.

    The earlier version reused a spent token and attested the wrong key, so its refusals came from
    other checks and the rule could be switched off with the test still green.
    """

    def fresh(holder: EcKey, **attestation: Any) -> Any:
        wallet.token = None
        wallet.get_token()
        ka = wallet.key_attestation([holder], **attestation)
        return request(wallet, [wallet.proof(holder, wallet.c_nonce(), key_attestation=ka)])

    wallet.status_exp_offset = 3 * 86_400
    capped = fresh(EcKey.generate())
    assert capped.status_code == 200, capped.text
    payload = disclosures(capped.json()["credentials"][0]["credential"])[1]
    assert payload["exp"] <= wallet.clock() + 3 * 86_400, "capped by key_storage_status.exp, not the KA exp"
    wallet.status_exp_offset = 60
    short = fresh(EcKey.generate())
    assert short.status_code == 400 and error(short) == "credential_request_denied", short.text
    assert "maintenance period" in short.json()["error_description"]
    wallet.status_exp_offset = 30 * 86_400
    no_status = fresh(EcKey.generate(), key_storage_status=None)
    assert no_status.status_code == 400 and error(no_status) == "invalid_proof", no_status.text
    assert "key_storage_status" in no_status.json()["error_description"]


@pytest.mark.covers("KA.BIND_TO_ATTESTED_KEY", "KA.ATTESTATION_PROOF_NONCE")
@pytest.mark.obligation("PRIV.NO_KA_IDX_AS_WALLET_ID", "KA.POP_ALL_KEYS")
def test_attestation_proof_type(wallet: Wallet, issuer: Issuer) -> None:
    wallet.get_token()
    keys = [EcKey.generate(), EcKey.generate()]
    without_nonce = wallet.key_attestation(keys)
    body = {"credential_configuration_id": PID, "proofs": {"attestation": [without_nonce]}}
    assert error(wallet.credential_request(body)) == "invalid_proof"
    two = {"credential_configuration_id": PID, "proofs": {"attestation": [without_nonce, without_nonce]}}
    assert error(wallet.credential_request(two)) == "invalid_proof"
    good = {
        "credential_configuration_id": PID,
        "proofs": {"attestation": [wallet.key_attestation(keys, nonce=wallet.c_nonce())]},
    }
    response = wallet.credential_request(good)
    assert response.status_code == 200, response.text
    bound = {
        holder_thumbprint(
            EcKey.from_private_jwk({**disclosures(c["credential"])[1]["cnf"]["jwk"], "d": k.private_jwk()["d"]})
        )
        for c, k in zip(response.json()["credentials"], keys, strict=True)
    }
    assert bound == {holder_thumbprint(k) for k in keys}, "one credential per attested key"
    stored = str([issuer.store.items(ns) for ns in ("issued", "audit", "access-token", "offer")])
    assert "wallet-provider.test" not in stored, "the KA status reference is never kept as a wallet identifier"
    duplicate = {
        "credential_configuration_id": PID,
        "proofs": {"attestation": [wallet.key_attestation([keys[0], keys[0]], nonce=wallet.c_nonce())]},
    }
    assert error(wallet.credential_request(duplicate)) == "invalid_proof"


@pytest.mark.obligation(
    "BATCH.METHOD_INVISIBLE",
    "BATCH.UNIFORM",
    "PRIV.UNLINKABILITY_BATCH",
    "STATUS.TSL.FRESH_ENTRY_PER_CREDENTIAL",
    "PRIV.TIMESTAMP_COARSENING",
)
def test_batch_issuance(wallet: Wallet) -> None:
    holders = [EcKey.generate() for _ in range(3)]
    nonce = wallet.c_nonce()
    response = request(wallet, [wallet.proof(h, nonce) for h in holders])
    assert response.status_code == 200
    payloads = [disclosures(c["credential"])[1] for c in response.json()["credentials"]]
    assert len({p["status"]["status_list"]["idx"] for p in payloads}) == 3, "a fresh status entry per credential"
    assert len({(p["nbf"], p["exp"]) for p in payloads}) == 1, "same validity, so the batch looks uniform"
    assert len({str(p["_sd"]) for p in payloads}) == 3, "fresh salts: digests differ between copies"


@pytest.mark.covers("BATCH.SUPPORT")
def test_batch_size_is_enforced(make_issuer: Any, pki: Any, clock: Any) -> None:
    from fastapi.testclient import TestClient

    from cunho.app import create_app

    issuer = make_issuer(batch_size=30)
    assert issuer.issuer_metadata()["batch_credential_issuance"] == {"batch_size": 30}
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        nonce = wallet.c_nonce()
        over = request(wallet, [wallet.proof(EcKey.generate(), nonce) for _ in range(31)])
        assert over.status_code == 400 and error(over) == "invalid_credential_request"
        too_many_keys = {
            "credential_configuration_id": PID,
            "proofs": {
                "attestation": [wallet.key_attestation([EcKey.generate() for _ in range(31)], nonce=wallet.c_nonce())]
            },
        }
        assert error(wallet.credential_request(too_many_keys)) == "invalid_proof"


@pytest.mark.covers("VCI.CRED.IDENTIFIER_XOR", "VCI.CRED.ERROR_CODES", "VCI.CRED.PROOFS_SHAPE")
def test_credential_request_shape(wallet: Wallet) -> None:
    wallet.get_token()
    proof = wallet.proof(EcKey.generate(), wallet.c_nonce())
    cases: list[tuple[Any, str]] = [
        ({"proofs": {"jwt": [proof]}}, "invalid_credential_request"),
        (
            {"credential_configuration_id": PID, "credential_identifier": "x", "proofs": {"jwt": [proof]}},
            "invalid_credential_request",
        ),
        ({"credential_identifier": "x", "proofs": {"jwt": [proof]}}, "unknown_credential_identifier"),
        ({"credential_configuration_id": "nope", "proofs": {"jwt": [proof]}}, "unknown_credential_configuration"),
        (
            {"credential_configuration_id": "eu.europa.ec.eudi.pid_mdoc", "proofs": {"jwt": [proof]}},
            "unknown_credential_configuration",
        ),
        (
            {"credential_configuration_id": "eu.europa.ec.eudi.iban_sd_jwt_vc", "proofs": {"jwt": [proof]}},
            "unknown_credential_configuration",
        ),
        ({"credential_configuration_id": 7}, "invalid_credential_request"),
        ({"credential_configuration_id": PID}, "invalid_proof"),
        ({"credential_configuration_id": PID, "proof": {"proof_type": "jwt", "jwt": proof}}, "invalid_proof"),
        (
            {"credential_configuration_id": PID, "proofs": {"jwt": [proof], "attestation": [proof]}},
            "invalid_credential_request",
        ),
        ({"credential_configuration_id": PID, "proofs": {"jwt": []}}, "invalid_credential_request"),
        ({"credential_configuration_id": PID, "proofs": {"jwt": [1, 2]}}, "invalid_credential_request"),
        ({"credential_configuration_id": PID, "proofs": {"di_vp": [proof]}}, "invalid_proof"),
        ({"credential_configuration_id": PID, "proofs": "jwt"}, "invalid_credential_request"),
    ]
    for body, expected in cases:
        response = wallet.credential_request(body)
        assert response.status_code == 400, body
        assert error(response) == expected, (body, response.json())
    wrong_type = wallet.credential_request(None, raw=b"{}", content_type="text/plain")
    assert error(wrong_type) == "invalid_credential_request"


@pytest.mark.covers("PID.VALUES.VALID_AT_VALIDITY_START", "VALIDITY.PID_LE_STATUS_EXP")
def test_subject_data_still_valid_at_issuance(wallet: Wallet) -> None:
    """The data is checked again for the day the credential becomes valid, not only when the offer was made.

    Review 2, N-M6: the expired-document case is refused by the validity cap first, so a second case uses a
    rule that starts between offer and issuance: a portrait is required from 2028-08-11.
    """
    wallet.clock.now = START + 86_400 - 300  # 23:55 UTC
    today = dt.datetime.fromtimestamp(wallet.clock(), dt.UTC).date().isoformat()
    offer = wallet.offer({**PID_SUBJECT, "date_of_expiry": today})
    wallet.clock.now += 240
    wallet.get_token(offer)
    wallet.clock.now += 120  # 00:01 the next day: the document has expired
    response = request(wallet, [wallet.proof(EcKey.generate(), wallet.c_nonce())])
    assert response.status_code == 400
    assert error(response) == "credential_request_denied", "an expired document is never issued (L-4)"

    wallet.clock.now = dt.datetime(2028, 8, 10, 23, 55, tzinfo=dt.UTC).timestamp()
    wallet.token = None
    offer = wallet.offer(PID_SUBJECT)  # no portrait: still allowed on 10 August 2028
    wallet.clock.now += 240
    wallet.get_token(offer)
    wallet.clock.now += 120  # 00:01 on 11 August 2028
    late = request(wallet, [wallet.proof(EcKey.generate(), wallet.c_nonce())])
    assert late.status_code == 400 and error(late) == "credential_request_denied", late.text
    assert "picture" in late.json()["error_description"]


@pytest.mark.covers("VCI.F1.PROOF_ISS_ANON_PREAUTH")
def test_an_iss_in_an_anonymous_proof_is_ignored_only_when_asked(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet]
) -> None:
    """ignore_anonymous_proof_iss (some wallets send iss in the anonymous pre-authorized flow): the proof is taken
    with its iss read as nothing; everything else of it is checked as before."""

    def with_iss(wallet: Wallet, holder: EcKey, **claims: Any) -> str:
        attestation = wallet.key_attestation([holder])
        body = {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce(), "iss": "lissi-wallet", **claims}
        return jws({"typ": "openid4vci-proof+jwt", "alg": "ES256", "key_attestation": attestation}, body, holder)

    strict = wallet_for(make_issuer())
    strict.get_token()
    refused = request(strict, [with_iss(strict, EcKey.generate())])
    assert error(refused) == "invalid_proof" and "must be omitted" in refused.json()["error_description"]

    lenient = wallet_for(make_issuer(ignore_anonymous_proof_iss=True))
    lenient.get_token()
    answer = request(lenient, [with_iss(lenient, EcKey.generate())])
    assert answer.status_code == 200, answer.text
    # nothing else is relaxed: a proof with the wrong audience is still refused
    wrong = request(lenient, [with_iss(lenient, EcKey.generate(), aud="https://elsewhere.test")])
    assert error(wrong) == "invalid_proof"
