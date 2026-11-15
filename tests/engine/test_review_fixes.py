"""Regression tests for the findings of the independent M2 review (research/cunho-m2-review.md ids)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.audit import Vault
from cunho.errors import ConfigError
from cunho.jose import JoseError, b64u, b64u_json, canonical_jwk, jwk_from_public_key, parse_jws, validate_path
from cunho.keyring import Keyring
from cunho.oauth import Grant
from cunho.proofs import ProvenKeys
from cunho.service import Issuer, Signers
from cunho.settings import Settings
from cunho.signer import FileSigner
from cunho.store import MemoryStore, SqliteStore

from .helpers import (
    ADMIN_TOKEN,
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    START,
    Clock,
    EcKey,
    Pki,
    Wallet,
    certificate,
    disclosures,
    settings_kwargs,
)

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def raw_jws(header: dict[str, Any], payload_text: str, key: EcKey) -> str:
    """Sign an arbitrary payload text, including JSON that the standard library would never produce."""
    signing_input = f"{b64u_json(header)}.{b64u(payload_text.encode())}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


def code_of(offer: dict[str, Any]) -> str:
    return str(
        offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
            "pre-authorized_code"
        ]
    )


# H-1 -----------------------------------------------------------------------------------------------


@pytest.mark.covers("DPOP.IAT_WINDOW", "VCI.F1.PROOF_IAT")
@pytest.mark.parametrize("iat", ["NaN", "Infinity", "-Infinity", "true", '"123"'])
def test_non_finite_iat_is_refused(wallet: Wallet, iat: str) -> None:
    """H-1: NaN and Infinity are not JSON, and a boolean or string iat is not a NumericDate."""
    key = wallet.dpop_key
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}
    proof = raw_jws(header, f'{{"jti":"{"j" * 20}","htm":"POST","htu":"{ISSUER}/token","iat":{iat}}}', key)
    response = wallet.token_request(code_of(wallet.offer()), dpop=proof)
    assert response.status_code == 400 and response.json()["error"] == "invalid_dpop_proof"
    holder = EcKey.generate()
    proof_header = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "jwk": holder.public_jwk(),
        "key_attestation": wallet.key_attestation([holder]),
    }
    key_proof = raw_jws(proof_header, f'{{"aud":"{ISSUER}","iat":{iat},"nonce":"{wallet.c_nonce()}"}}', holder)
    wallet.get_token()
    answer = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [key_proof]}})
    assert answer.status_code == 400 and answer.json()["error"] == "invalid_proof"


def test_duplicate_json_members_are_refused() -> None:
    """H-1: duplicate member names would let two parsers read different claims."""
    key = EcKey.generate()
    token = raw_jws({"alg": "ES256"}, '{"iat":1,"iat":2}', key)
    with pytest.raises(JoseError, match="duplicate"):
        parse_jws(token)


# H-2 ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_expired_state_is_swept(backend: str, tmp_path: Path) -> None:
    """H-2: unredeemed nonces and offers do not accumulate."""
    clock = Clock()
    store = MemoryStore(clock) if backend == "memory" else SqliteStore(tmp_path / "s.db", clock)
    for n in range(500):
        store.put("c-nonce", str(n), 1, 300)
    clock.now += 301
    store.put("other", "trigger", 1, None)
    assert store.get("c-nonce", "7") is None, "an expired entry is never read"
    assert store.sweep(clock()) >= 499, "maintenance sweeps them, in the background (review 3, N3-L2)"
    count = len(store) if isinstance(store, MemoryStore) else store.count()
    assert count == 1, "expired entries are gone after the sweep"


def test_nonce_flood_does_not_grow_state(wallet: Wallet, issuer: Issuer, clock: Clock) -> None:
    """H-2: the unauthenticated nonce endpoint cannot grow the store without bound."""
    for _ in range(100):
        assert wallet.client.post("/nonce").status_code == 200
    clock.now += 4000
    issuer.maintenance()
    assert len(issuer.store.items("c-nonce")) == 0 and len(issuer.store) < 20  # type: ignore[arg-type]


# H-3 ----------------------------------------------------------------------------------------------


def test_vault_keys_are_wrapped_outside_the_store(tmp_path: Path) -> None:
    """H-3: the database alone does not decrypt, deleted rows are overwritten, and data expires."""
    clock = Clock()
    store = SqliteStore(tmp_path / "v.db", clock)
    vault = Vault(store, Keyring.ephemeral())
    vault.put("sub_x", {"family_name": "Silva"}, 600, "offer-1")
    assert Vault(store, Keyring.ephemeral()).get("sub_x", "offer-1") is None, "another keyring opens nothing"
    assert vault.get("sub_x", "offer-2") is None, "the data opens only for the offer it was made for"
    assert vault.get("sub_x", "offer-1") == {"family_name": "Silva"}
    assert store._db.execute("PRAGMA secure_delete").fetchone()[0] == 1  # noqa: SLF001
    clock.now += 700
    store.sweep(clock())
    assert store.count() == 0, "expired personal data and its wrapped key are deleted"
    assert b"Silva" not in (tmp_path / "v.db").read_bytes()


def test_vault_is_erased_once_the_grant_is_used(wallet: Wallet, issuer: Issuer) -> None:
    """H-3: personal data is not kept after the last credential of an offer is issued."""
    offer = wallet.offer()
    wallet.get_token(offer)
    assert wallet.issue().status_code == 200
    assert issuer.store.get("vault", offer["subject_ref"]) is None
    assert issuer.store.get("vault-key", offer["subject_ref"]) is None


# H-4 ----------------------------------------------------------------------------------------------


def _path_case(**kind: Any) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = certificate("Root", root_key, ca=True, path_length=kind.get("root_path_length"))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    if kind.get("intermediate"):
        mid_key = ec.generate_private_key(ec.SECP256R1())
        usage = kind.get("intermediate_usage")
        extensions = [(usage, True)] if usage is not None else []
        mid = certificate("Mid", mid_key, (root, root_key), ca=True, extensions=extensions)
        leaf = certificate(
            "Leaf", leaf_key, (mid, mid_key), ca=kind.get("leaf_ca", False), extensions=kind.get("leaf_extensions", [])
        )
        return [leaf, mid], [root]
    leaf = certificate(
        "Leaf", leaf_key, (root, root_key), ca=kind.get("leaf_ca", False), extensions=kind.get("leaf_extensions", [])
    )
    return [leaf], [root]


NO_CERT_SIGN = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
UNKNOWN_CRITICAL = x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00")


@pytest.mark.parametrize(
    "case",
    [
        {"intermediate": True, "root_path_length": 0},
        {"intermediate": True, "intermediate_usage": NO_CERT_SIGN},
        {"leaf_ca": True},
        {"leaf_extensions": [(UNKNOWN_CRITICAL, True)]},
        {"leaf_extensions": [(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)]},
        {"leaf_extensions": [(x509.NameConstraints([x509.DNSName("a.test")], None), True)]},
    ],
    ids=["pathlen", "keycertsign", "leaf-ca", "critical", "tls-eku", "name-constraints"],
)
def test_path_validation_fails_closed(case: dict[str, Any]) -> None:
    """H-4: RFC 5280 §6.1.4 checks on key-attestation certificate paths."""
    chain, anchors = _path_case(**case)
    with pytest.raises(JoseError):
        validate_path(chain, anchors, dt.datetime.fromtimestamp(START, dt.UTC))


def test_path_validation_accepts_a_good_chain() -> None:
    chain, anchors = _path_case(intermediate=True)
    validate_path(chain, anchors, dt.datetime.fromtimestamp(START, dt.UTC))


# H-5 ----------------------------------------------------------------------------------------------


@pytest.mark.covers("DPOP.HTU", "DPOP.ALG_ASYMMETRIC", "VCI.F4.PROOF_SIGNATURE")
def test_former_server_errors(wallet: Wallet) -> None:
    """H-5: each input below used to produce a 500."""
    for htu in (
        "https://issuer.test:abc/token",
        "https://issuer.test:99999/token",
        "https://[::1/token",
        "https://user:pw@issuer.test/token",
    ):
        proof = wallet.dpop("POST", htu)
        response = wallet.token_request(code_of(wallet.offer()), dpop=proof)
        assert response.status_code == 400 and response.json()["error"] == "invalid_dpop_proof", htu
    listed = raw_jws({"typ": "dpop+jwt", "alg": ["ES256"], "jwk": wallet.dpop_key.public_jwk()}, "{}", wallet.dpop_key)
    assert wallet.token_request(code_of(wallet.offer()), dpop=listed).status_code == 400
    wallet.get_token()
    deep = raw_jws({"alg": "ES256", "typ": "openid4vci-proof+jwt"}, "[" * 10_000 + "]" * 10_000, EcKey.generate())
    body = {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [deep]}}
    assert wallet.credential_request(body).status_code == 400
    holder = EcKey.generate()
    for bad_jwk in ("x", {"kty": "RSA"}, {"kty": "EC"}):
        proof = wallet.proof(holder, wallet.c_nonce(), header_jwk=bad_jwk)
        answer = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
        assert answer.status_code == 400 and answer.json()["error"] == "invalid_proof", bad_jwk
    admin = wallet.client.post("/admin/offers", json={}, headers={"Authorization": b"Bearer \xc3\xa9\xc3\xa9"})
    assert admin.status_code == 401


def test_non_ascii_server_nonce(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock) -> None:
    """H-5: a non-ASCII DPoP nonce is refused, not a 500."""
    issuer = make_issuer(dpop_server_nonce=True)
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        response = wallet.token_request(
            code_of(wallet.offer()), dpop=wallet.dpop("POST", f"{ISSUER}/token", nonce="1.é" * 3)
        )
        assert response.status_code == 400 and response.json()["error"] == "use_dpop_nonce"


# H-6 ----------------------------------------------------------------------------------------------


def test_chunked_body_is_refused_early(wallet: Wallet) -> None:
    """H-6: a body without Content-Length is cut off at the limit instead of buffered in full."""
    sent = 0

    def chunks() -> Iterator[bytes]:
        nonlocal sent
        for _ in range(4096):
            sent += 64 * 1024
            yield b"a" * (64 * 1024)

    response = wallet.client.post(
        "/token", content=chunks(), headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 400 and "too large" in response.json()["error_description"]


# M-1 ----------------------------------------------------------------------------------------------


@pytest.mark.covers("VCI.CRED.ERROR_CODES", "KA.BIND_TO_ATTESTED_KEY")
def test_one_credential_request_per_configuration_per_token(wallet: Wallet, issuer: Issuer) -> None:
    """M-1: one offer cannot be turned into unlimited PIDs."""
    offer = wallet.offer()
    token = wallet.get_token(offer)
    offer_id = issuer.tokens.authorize(
        f"DPoP {token}",
        [wallet.dpop("POST", f"{ISSUER}/credential", access_token=token)],
        "POST",
        f"{ISSUER}/credential",
    ).offer_id
    holder = EcKey.generate()
    assert wallet.issue([holder]).status_code == 200
    issuer.vault.put(offer["subject_ref"], PID_SUBJECT, 600, offer_id)  # put the data back after it was erased
    again = wallet.issue([EcKey.generate()])
    assert again.status_code == 400 and again.json()["error"] == "credential_request_denied"
    assert "already used for this credential configuration" in again.json()["error_description"]
    grant = Grant("g1", "jkt", [PID_CONFIG, "other"], "sub", "offer", int(issuer.time()) + 300)
    proven = ProvenKeys(keys=[holder.public_jwk()])
    issuer._claim_grant(grant, PID_CONFIG, proven)  # noqa: SLF001
    with pytest.raises(Exception, match="already bound"):
        issuer._claim_grant(grant, "other", proven)  # noqa: SLF001


# M-2 ----------------------------------------------------------------------------------------------


def test_audit_identity_reasons_and_anchoring(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock) -> None:
    """M-2: named operators, enumerated reasons, logged failures, MACed pointers and a signed head."""
    issuer = make_issuer(operators={"alice": "a" * 40})
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        response = client.post(
            "/admin/offers",
            headers={"Authorization": f"Bearer {'a' * 40}"},
            json={"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT},
        )
        assert response.status_code == 201
        offer = response.json()
        wallet.get_token(offer)
        wallet.issue()
        free_text = client.post(
            "/admin/revocations", headers=AUTH, json={"subject_ref": offer["subject_ref"], "reason": "Ana Silva died"}
        )
        assert free_text.status_code == 400
        client.post("/admin/offers", headers={"Authorization": "Bearer " + "z" * 40}, json={})
        issuer.maintenance(force=True)
        events = [(e["event"], e["actor"]) for e in issuer.audit.entries()]
        assert ("offer.created", "alice") in events and ("admin.auth_failures", "anonymous") in events
        head = client.get("/admin/audit/head", headers=AUTH)
        assert head.status_code == 200 and parse_jws(head.text).payload["seq"] == len(issuer.audit.entries())
    issuer.store.put("audit-meta", "head", {"seq": 1, "mac": "0" * 64, "tag": "0" * 64}, None)
    assert issuer.audit.verify() == (False, "audit head pointer was altered")


def test_retention_prunes_old_entries(issuer: Issuer, clock: Clock) -> None:
    """M-2: the retention period is applied, and what remains still verifies."""
    issuer.audit.append("old", "operator")
    clock.now += (issuer.settings.audit_retention_days + 1) * 86_400
    issuer.audit.append("new", "operator")
    done = issuer.maintenance(force=True)
    assert done["audit_entries_pruned"] == 1 and issuer.audit.verify()[0]


# M-3 ----------------------------------------------------------------------------------------------


@pytest.mark.obligation("KA.JWT_PROOF_ATTESTED_KEY0", "BIND.DEVICE_BOUND", "VCI.F1.PROOF_TYP")
def test_jwt_proof_binds_only_the_signing_key(wallet: Wallet) -> None:
    """M-3: extra attested keys get credentials only through the attestation proof type with a fresh nonce."""
    signer, other = EcKey.generate(), EcKey.generate()
    proof = wallet.proof(signer, wallet.c_nonce(), key_attestation=wallet.key_attestation([signer, other]))
    wallet.get_token()
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    credentials = response.json()["credentials"]
    assert len(credentials) == 1
    assert disclosures(credentials[0]["credential"])[1]["cnf"]["jwk"] == signer.public_jwk()


# M-4 ----------------------------------------------------------------------------------------------


def _p384_proof(wallet: Wallet, nonce: str) -> str:
    key = ec.generate_private_key(ec.SECP384R1())
    jwk = jwk_from_public_key(key.public_key())

    class P384(EcKey):
        def public_jwk(self) -> dict[str, Any]:
            return jwk

    attestation = wallet.key_attestation([P384(key)])
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES384", "jwk": jwk, "key_attestation": attestation}
    signing_input = f"{b64u_json(header)}.{b64u_json({'aud': ISSUER, 'iat': int(wallet.clock()), 'nonce': nonce})}"
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA384())))
    return f"{signing_input}.{b64u(r.to_bytes(48, 'big') + s.to_bytes(48, 'big'))}"


def test_es384_key_proofs_are_accepted(wallet: Wallet) -> None:
    """M-4: CIR 2024/2979 Annex Ib SA-3 requires ES256, ES384 and ES512."""
    wallet.get_token()
    proof = _p384_proof(wallet, wallet.c_nonce())
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert response.status_code == 200, response.text
    assert disclosures(response.json()["credentials"][0]["credential"])[1]["cnf"]["jwk"]["crv"] == "P-384"


# M-5 ----------------------------------------------------------------------------------------------


def test_signer_certificate_must_name_the_issuer(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    """M-5: a verifier matches iss against the signer certificate's SAN."""
    settings = Settings(**settings_kwargs(pki))
    key = ec.generate_private_key(ec.SECP256R1())
    for san in (None, ["other.test"]):
        leaf = certificate("Signer", key, san=san)
        signers = Signers(FileSigner(key, [leaf]), FileSigner(key, [leaf]))
        with pytest.raises(ConfigError, match="subjectAltName"):
            Issuer(settings, store=MemoryStore(clock), signers=signers, clock=clock)


# M-6 ----------------------------------------------------------------------------------------------


def test_status_token_is_cached_until_a_bit_changes(issuer: Issuer, clock: Clock) -> None:
    """M-6: the signed list is not rebuilt on every request."""
    ref = issuer.status.allocate()
    first = issuer.status_token(ref.list_id)
    clock.now += 5
    assert issuer.status_token(ref.list_id) == first
    issuer.status.revoke(ref)
    assert issuer.status_token(ref.list_id) == first, "a revocation changes nothing until the next publication"
    clock.now += issuer.settings.status_publish_interval
    assert issuer.status_token(ref.list_id) != first


# M-8 ----------------------------------------------------------------------------------------------


@pytest.mark.covers("STATUS.MONOTONIC")
def test_revocation_input_is_strict(wallet: Wallet) -> None:
    """M-8: a boolean is not an index; review 2 N-L6: references are bounded and well formed."""
    for body in (
        {"list": "1", "index": True, "reason": "administrative"},
        {"list": "1", "index": 3, "reason": "Ana Silva died"},
        {"subject_ref": "Maria Silva 1990-05-17", "reason": "death"},
        {"subject_ref": "sub_" + "A" * 5000, "reason": "death"},
        {"list": "../1", "index": 3, "reason": "administrative"},
    ):
        response = wallet.client.post("/admin/revocations", headers=AUTH, json=body)
        assert response.status_code == 400, body


# M-9 ----------------------------------------------------------------------------------------------


def test_decoys_keep_appearing(issuer: Issuer, clock: Clock) -> None:
    """M-9: new decoys keep being scheduled over time, so two snapshots do not single out revocations."""
    issuer.status.allocate()
    scheduled = 0
    for _ in range(24 * 30):
        clock.now += 3600
        scheduled += issuer.maintenance(force=True)["decoys_scheduled"]
    expected = issuer.settings.status_list_size * issuer.settings.status_decoy_churn_per_day * 30
    assert 0.5 * expected <= scheduled <= 2 * expected


# M-10 ---------------------------------------------------------------------------------------------


def test_dpop_nonces_survive_restart_and_workers(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    """M-10: the DPoP nonce key comes from the keyring, shared by every worker and kept across restarts."""
    settings = Settings(**settings_kwargs(pki, dpop_server_nonce=True, store_path=tmp_path / "s.db"))
    first = Issuer(settings, clock=clock)
    second = Issuer(settings, clock=clock)
    assert second.nonces.dpop_nonce_valid(first.nonces.issue_dpop_nonce())


def test_issued_records_are_rows(wallet: Wallet, issuer: Issuer) -> None:
    """M-10: one row per issued credential, so concurrent issuance cannot lose a revocation target."""
    offer = wallet.offer()
    wallet.get_token(offer)
    wallet.issue([EcKey.generate(), EcKey.generate()])
    assert len(issuer.store.items("issued", f"{offer['subject_ref']}:")) == 2


# Low ----------------------------------------------------------------------------------------------


@pytest.mark.covers("VCI.OFFER.SHAPE")
def test_offer_shape(wallet: Wallet) -> None:
    for body in (
        {"credential_configuration_ids": "x", "subject": PID_SUBJECT},
        {"credential_configuration_ids": [], "subject": PID_SUBJECT},
        {"credential_configuration_ids": [PID_CONFIG, PID_CONFIG], "subject": PID_SUBJECT},
        {"credential_configuration_ids": ["eu.europa.ec.eudi.pid_mdoc"], "subject": PID_SUBJECT},
        {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, "tx_code_length": 3},
        {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, "tx_code_length": True},
    ):
        response = wallet.admin("offers", body)
        assert response.status_code == 400 and response.json()["error"] == "invalid_request", body
    offer = wallet.offer()
    assert offer["offer_link"].startswith("openid-credential-offer://?credential_offer=")


def test_non_canonical_jwk_is_refused() -> None:
    """L-2: one key has one spelling, so duplicate-key checks cannot be dodged."""
    jwk = EcKey.generate().public_jwk()
    padded = {**jwk, "x": jwk["x"] + "="}
    with pytest.raises(JoseError):
        canonical_jwk(padded)
    assert canonical_jwk(jwk) == jwk


def test_technical_expiry_follows_the_document(wallet: Wallet) -> None:
    """L-4: a PID whose document expires in two days does not get fourteen days of validity."""
    expiry = (dt.datetime.fromtimestamp(wallet.clock(), dt.UTC) + dt.timedelta(days=2)).date()
    wallet.get_token(wallet.offer({**PID_SUBJECT, "date_of_expiry": expiry.isoformat()}))
    payload = disclosures(wallet.issue().json()["credentials"][0]["credential"])[1]
    assert payload["exp"] <= dt.datetime.combine(expiry, dt.time.max, dt.UTC).timestamp()


def test_key_attestation_times_must_be_numbers(wallet: Wallet) -> None:
    """L-7: a future iat or a non-numeric exp is refused."""
    holder = EcKey.generate()
    for claims in ({"iat": int(wallet.clock()) + 3600}, {"exp": "tomorrow"}):
        proof = wallet.proof(holder, wallet.c_nonce(), key_attestation=wallet.key_attestation([holder], **claims))
        wallet.get_token()
        response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
        assert response.status_code == 400 and response.json()["error"] == "invalid_proof", claims


def test_rate_limit(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock) -> None:
    issuer = make_issuer(rate_limit_per_minute=5)
    with TestClient(create_app(issuer=issuer), base_url=ISSUER) as client:
        statuses = [client.post("/nonce").status_code for _ in range(7)]
        assert statuses[:5] == [200] * 5 and statuses[5:] == [429, 429]
