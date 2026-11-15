"""Regression tests for the fourth independent M2 review (finding ids from cunho-m2-review-4.md)."""

from __future__ import annotations

import base64
import datetime as dt
import errno
import hashlib
import json
import logging
import multiprocessing
import os
import sqlite3
import threading
import time
import uuid
import zlib
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cunho import audit as audit_module
from cunho import store as store_module
from cunho.app import create_app
from cunho.audit import Anchor, AuditError, AuditLog
from cunho.errors import ConfigError
from cunho.jose import JoseError, b64u, b64u_decode, b64u_json, load_x5c, parse_jws, strict_json, validate_path
from cunho.keyring import Keyring
from cunho.proofs import CrlFile, parse_crls
from cunho.service import CLOCK_TOLERANCE, Issuer
from cunho.settings import Settings
from cunho.status import StatusRef
from cunho.store import MemoryStore, SqliteStore, Store

from .helpers import (
    ADMIN_TOKEN,
    ISSUER,
    KA_POLICY,
    PID_CONFIG,
    PRE_AUTH,
    SLOW_IS_FINE,
    START,
    Clock,
    EcKey,
    Host,
    Pki,
    Wallet,
    certificate,
    der_b64,
    disclosures,
    pem,
    refused_by,
    settings_kwargs,
)

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
NOW = dt.datetime.fromtimestamp(START, dt.UTC)
STORES = ["memory", "sqlite"]


def raw_jws(header: dict[str, Any], payload_text: str, key: EcKey) -> str:
    """A correctly signed JWS over payload text written by hand, so it can carry any JSON escape."""
    signing_input = f"{b64u_json(header)}.{b64u(payload_text.encode())}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


def store_of(kind: str, tmp_path: Path, clock: Clock) -> Store:
    return MemoryStore(clock) if kind == "memory" else SqliteStore(tmp_path / "s.db", clock)


@pytest.fixture
def wallet_on(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path) -> Iterator[Any]:
    """A wallet against an issuer on the store named by the caller (the production store is SQLite)."""
    clients: list[TestClient] = []

    def build(kind: str, **overrides: Any) -> tuple[Wallet, Issuer]:
        issuer = make_issuer(store=store_of(kind, tmp_path, clock), **overrides)
        client = TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER)
        clients.append(client)
        return Wallet(client, pki, clock), issuer

    yield build
    for client in clients:
        client.close()


# N4-M1: lone UTF-16 surrogates are refused by the parser, for every document ----------------------


@pytest.mark.parametrize(
    "text",
    [
        '"\\ud800"',
        '{"a":"x\\udfff"}',
        '{"\\ud800":1}',
        '[1,["ok","\\udbff"]]',
        '{"a":{"b":[{"c":"\\ude00\\ud83d"}]}}',  # a pair in the wrong order is two lone halves
    ],
)
def test_n4_m1_lone_surrogates_are_refused_when_parsed(text: str) -> None:
    with pytest.raises(ValueError, match="lone surrogate"):
        strict_json(text)
    with pytest.raises(ValueError, match="lone surrogate"):
        strict_json(text.encode())


def test_n4_m1_real_characters_still_parse() -> None:
    assert strict_json('{"a":"\\ud83d\\ude00","b":"ação","c":["ü"]}') == {"a": "😀", "b": "ação", "c": ["ü"]}
    with pytest.raises(ValueError, match="lone surrogate"):
        strict_json('["' + chr(0xD800) + '"]')  # a raw one in text handed over as str


def test_n4_m1_a_jws_with_a_lone_surrogate_is_not_a_jws() -> None:
    key = EcKey.generate()
    token = raw_jws({"alg": "ES256"}, '{"jti":"\\ud800"}', key)
    with pytest.raises(JoseError, match="not valid JSON"):
        parse_jws(token)
    header = b64u(b'{"alg":"ES256","kid":"\\udfff"}')
    with pytest.raises(JoseError, match="not valid JSON"):
        parse_jws(f"{header}.{b64u_json({})}.{b64u(b'x' * 64)}")


@pytest.mark.parametrize("kind", STORES)
def test_n4_m1_dpop_jti_with_a_lone_surrogate_is_a_400(wallet_on: Any, kind: str) -> None:
    """s1: unauthenticated /token on SQLite used to answer 500, as the jti reached the SQLite binding."""
    wallet, _ = wallet_on(kind)
    key = EcKey.generate()
    payload = f'{{"jti":"{uuid.uuid4().hex}\\ud800","htm":"POST","htu":"{ISSUER}/token","iat":{int(wallet.clock())}}}'
    proof = raw_jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}, payload, key)
    response = refused_by(lambda: wallet.token_request("x", dpop=proof), "DPOP.SIGNATURE", "not a valid JWS")
    assert response.status_code == 400 and response.json()["error"] == "invalid_dpop_proof"


@pytest.mark.parametrize("kind", STORES)
@pytest.mark.parametrize("where", ["proof", "attestation"])
def test_n4_m1_key_proof_nonce_with_a_lone_surrogate_is_a_400(wallet_on: Any, kind: str, where: str) -> None:
    """s1: the nonce reached a hash function that encodes to UTF-8, on either store."""
    wallet, _ = wallet_on(kind)
    wallet.get_token()
    holder = EcKey.generate()
    now = int(wallet.clock())
    if where == "proof":
        header = {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": holder.public_jwk(),
            "key_attestation": wallet.key_attestation([holder]),
        }
        proof = raw_jws(header, f'{{"aud":"{ISSUER}","iat":{now},"nonce":"\\udfff"}}', holder)
    else:
        attestation = raw_jws(
            {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [der_b64(wallet.pki.ka_leaf)]},
            f'{{"iat":{now},"exp":{now + 60},"attested_keys":[],"nonce":"\\ud800"}}',
            wallet.pki.ka_key,
        )
        proof = wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)
    body = {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}}
    response = refused_by(lambda: wallet.credential_request(body), "VCI.F4.PROOF_SIGNATURE", "not a valid JWS")
    assert response.status_code == 400 and response.json()["error"] == "invalid_proof"


@pytest.mark.parametrize("kind", STORES)
def test_n4_m1_operator_bodies_with_a_lone_surrogate_are_a_400(wallet_on: Any, kind: str) -> None:
    wallet, issuer = wallet_on(kind)
    text = '{"credential_configuration_ids":["' + PID_CONFIG + '"],"subject":{"family_name":"Silva\\ud800"}}'
    response = wallet.client.post("/admin/offers", content=text, headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 400 and response.json()["error"] == "invalid_request"
    assert issuer.audit.entries() == [], "nothing was logged or stored"


# N4-M2: certificates that cryptography loads but cannot fully read are refused, never a 500 -------


def _patched(cert: x509.Certificate, old: str, new: str) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    assert der.count(bytes.fromhex(old)) >= 1, old
    return base64.b64encode(der.replace(bytes.fromhex(old), bytes.fromhex(new), 1)).decode()


BASIC_OID, POLICIES_OID = "0603551d13", "0603551d20"
P256_OID = "06082a8648ce3d030107"


def malformed(pki: Pki) -> dict[str, str]:
    """s8: byte patches of a real key attestation signer certificate that still load."""
    leaf = pki.ka_leaf
    return {
        "duplicate extension": _patched(leaf, POLICIES_OID, BASIC_OID),
        "basicConstraints value not DER": _patched(leaf, "0603551d130101ff040230", "0603551d130101ff040231"),
        "unknown named curve": _patched(leaf, P256_OID, "06082a8648ce3d03017f"),
    }


def test_n4_m2_load_x5c_refuses_what_it_cannot_fully_read(pki: Pki) -> None:
    for value in malformed(pki).values():
        x509.load_der_x509_certificate(base64.b64decode(value))  # cryptography itself loads each one
        with pytest.raises(JoseError, match="cannot be fully read"):
            load_x5c([value])
        with pytest.raises(JoseError, match="cannot be fully read"):
            load_x5c([der_b64(pki.ka_leaf), value])
    assert load_x5c([der_b64(pki.ka_leaf)])[0] == pki.ka_leaf
    # An unknown version number raises InvalidVersion, which is not a ValueError, while loading.
    with pytest.raises(JoseError, match="not a DER certificate"):
        load_x5c([_patched(pki.ka_leaf, "a003020102", "a003020105")])


@pytest.mark.parametrize("name", ["duplicate extension", "basicConstraints value not DER", "unknown named curve"])
def test_n4_m2_malformed_key_attestation_certificates_are_a_400(wallet: Wallet, pki: Pki, name: str) -> None:
    holder = EcKey.generate()
    header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [malformed(pki)[name]]}
    attestation = wallet.key_attestation([holder], _header=header)
    wallet.get_token()
    body = {
        "credential_configuration_id": PID_CONFIG,
        "proofs": {"jwt": [wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)]},
    }
    response = refused_by(lambda: wallet.credential_request(body), "KA.CHAIN_TO_WP_LIST", "cannot be fully read")
    assert response.status_code == 400 and response.json()["error"] == "invalid_proof"


def test_n4_m2_a_malformed_anchor_or_crl_is_a_refusal(pki: Pki, tmp_path: Path) -> None:
    """Certificates load_x5c never sees (anchors) still give a JoseError, and CRL files are read in full."""
    chain = load_x5c([der_b64(pki.ka_leaf)])
    validate_path(chain, [pki.wallet_ca], NOW)
    duplicate_root = _duplicate_extension_root(pki)
    with pytest.raises(JoseError, match="cannot be processed"):
        validate_path(chain, [duplicate_root], NOW)
    data = _crl_with_duplicate_extension(pki)
    with pytest.raises(ValueError, match="cannot be fully read"):
        parse_crls(data)
    (tmp_path / "wp.crl").write_bytes(data)
    with pytest.raises(ConfigError, match="cannot use the wallet provider CRLs"):
        CrlFile(tmp_path / "wp.crl")


def _duplicate_extension_root(pki: Pki) -> x509.Certificate:
    """The wallet provider root with its key, rebuilt with a subjectKeyIdentifier patched into a second
    basicConstraints: its signature over the chain still verifies, its extensions do not parse."""
    root = certificate(
        "Test Wallet Provider Root",
        pki.wallet_ca_key,
        ca=True,
        extensions=[(x509.SubjectKeyIdentifier.from_public_key(pki.wallet_ca_key.public_key()), False)],
    )
    return x509.load_der_x509_certificate(base64.b64decode(_patched(root, "0603551d0e", BASIC_OID)))


def _crl_with_duplicate_extension(pki: Pki) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.wallet_ca.subject)
        .last_update(NOW - dt.timedelta(days=1))
        .next_update(NOW + dt.timedelta(days=7))
        .add_extension(x509.CRLNumber(1), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pki.wallet_ca_key.public_key()), False)
    )
    der = builder.sign(pki.wallet_ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    return der.replace(bytes.fromhex("0603551d23"), bytes.fromhex("0603551d14"), 1)


# N4-M6: with several current CRLs from one CA, the newest decides and no revocation is taken back ---


def _ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    root = certificate("WP Root", key, ca=True)
    leaf = certificate("KA Signer", ec.generate_private_key(ec.SECP256R1()), (root, key))
    return root, key, leaf


def _crl(
    root: x509.Certificate,
    key: ec.EllipticCurvePrivateKey,
    listed: Sequence[tuple[x509.Certificate, x509.ReasonFlags | None]],
    *,
    age: dt.timedelta,
    number: int | None = None,
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.subject)
        .last_update(NOW - age)
        .next_update(NOW + dt.timedelta(days=7))
    )
    if number is not None:
        builder = builder.add_extension(x509.CRLNumber(number), critical=False)
    for cert, reason in listed:
        entry = x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(NOW - age)
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(key, hashes.SHA256())


def test_n4_m6_the_newest_crl_decides_in_any_order() -> None:
    """s9: an old copy listed first no longer hides a revocation the new CRL carries."""
    root, key, leaf = _ca()
    old = _crl(root, key, [], age=dt.timedelta(days=2))
    new = _crl(root, key, [(leaf, None)], age=dt.timedelta(hours=1))
    for crls in ([new], [old, new], [new, old]):
        with pytest.raises(JoseError, match="the leaf certificate is revoked"):
            validate_path([leaf], [root], NOW, crls=crls)
    validate_path([leaf], [root], NOW, crls=[old])


def test_n4_m6_an_older_crl_cannot_take_a_revocation_back() -> None:
    root, key, leaf = _ca()
    old = _crl(root, key, [(leaf, x509.ReasonFlags.key_compromise)], age=dt.timedelta(days=2))
    new = _crl(root, key, [], age=dt.timedelta(hours=1))
    for crls in ([old, new], [new, old]):
        with pytest.raises(JoseError, match="the leaf certificate is revoked"):
            validate_path([leaf], [root], NOW, crls=crls)


def test_n4_m6_a_hold_is_judged_by_the_newest_crl() -> None:
    root, key, leaf = _ca()
    hold = [(leaf, x509.ReasonFlags.certificate_hold)]
    held = _crl(root, key, hold, age=dt.timedelta(days=2))
    released = _crl(root, key, [], age=dt.timedelta(hours=1))
    for crls in ([held, released], [released, held]):
        validate_path([leaf], [root], NOW, crls=crls)  # the hold was lifted
    newer_hold = _crl(root, key, hold, age=dt.timedelta(hours=1))
    older_clean = _crl(root, key, [], age=dt.timedelta(days=2))
    for crls in ([older_clean, newer_hold], [newer_hold, older_clean]):
        with pytest.raises(JoseError, match="the leaf certificate is revoked"):
            validate_path([leaf], [root], NOW, crls=crls)
    # The CRL number decides before thisUpdate: number 5 is newer than number 4 although it was issued earlier.
    numbered_hold = _crl(root, key, hold, age=dt.timedelta(days=2), number=5)
    numbered_clean = _crl(root, key, [], age=dt.timedelta(hours=1), number=4)
    with pytest.raises(JoseError, match="the leaf certificate is revoked"):
        validate_path([leaf], [root], NOW, crls=[numbered_clean, numbered_hold])
    numbered_clean = _crl(root, key, [], age=dt.timedelta(days=3), number=6)
    validate_path([leaf], [root], NOW, crls=[numbered_hold, numbered_clean])


def test_n4_m6_crl_order_through_the_endpoint(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path
) -> None:
    def pem_crl(listed: list[x509.Certificate], age: dt.timedelta) -> bytes:
        return _crl(pki.wallet_ca, pki.wallet_ca_key, [(c, None) for c in listed], age=age).public_bytes(
            serialization.Encoding.PEM
        )

    old, new = pem_crl([], dt.timedelta(days=2)), pem_crl([pki.ka_leaf], dt.timedelta(hours=1))
    for data in (old + new, new + old):
        (tmp_path / "wp.crl").write_bytes(data)
        issuer = make_issuer(wallet_provider_crls=tmp_path / "wp.crl")
        with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
            wallet = Wallet(client, pki, clock)
            refused_by(wallet.issue, "KA.CHAIN_TO_WP_LIST", "the leaf certificate is revoked")


# N4-L3: inhibitAnyPolicy and policyConstraints marked critical, as RFC 5280 asks ---------------------


def _policy_path(extension: x509.ExtensionType) -> tuple[list[x509.Certificate], x509.Certificate]:
    root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = certificate("R", root_key, ca=True)
    policies = x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(KA_POLICY), None)])
    mid = certificate("M", mid_key, (root, root_key), ca=True, extensions=[(policies, False), (extension, True)])
    leaf = certificate("L", leaf_key, (mid, mid_key), extensions=[(policies, False)])
    return [leaf, mid], root


def test_n4_l3_critical_policy_extensions_are_processed() -> None:
    chain, root = _policy_path(x509.InhibitAnyPolicy(0))
    validate_path(chain, [root], NOW)
    validate_path(chain, [root], NOW, frozenset({KA_POLICY}))
    chain, root = _policy_path(x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None))
    validate_path(chain, [root], NOW, frozenset({KA_POLICY}))
    with pytest.raises(JoseError, match="requires an explicit policy, and none is configured"):
        validate_path(chain, [root], NOW)
    chain, root = _policy_path(x509.PolicyConstraints(require_explicit_policy=None, inhibit_policy_mapping=0))
    validate_path(chain, [root], NOW)  # mappings are refused anyway, so inhibiting them always holds


# N4-L6: a trust anchor rollover does not stop key attestations --------------------------------------


def test_n4_l6_every_anchor_with_the_signing_key_is_tried(pki: Pki) -> None:
    expired = certificate(
        "Test Wallet Provider Root",
        pki.wallet_ca_key,
        ca=True,
        not_before=NOW - dt.timedelta(days=800),
        not_after=NOW - dt.timedelta(days=1),
    )
    chain = [pki.ka_leaf]
    validate_path(chain, [expired, pki.wallet_ca], NOW)
    validate_path(chain, [pki.wallet_ca, expired], NOW)
    with pytest.raises(JoseError, match="trust anchor outside its validity period"):
        validate_path(chain, [expired], NOW)
    other = certificate("Someone Else", ec.generate_private_key(ec.SECP256R1()), ca=True)
    with pytest.raises(JoseError, match="trust anchor outside its validity period"):
        validate_path(chain, [other, expired], NOW)  # the reason of the anchor that held the key


def test_n4_l6_rollover_through_the_endpoint(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path
) -> None:
    """s12: an expired copy of the root listed before its renewed copy used to stop every key attestation."""
    expired = certificate(
        "Test Wallet Provider Root",
        pki.wallet_ca_key,
        ca=True,
        not_before=NOW - dt.timedelta(days=800),
        not_after=NOW - dt.timedelta(days=1),
    )
    (tmp_path / "wp.pem").write_bytes(pem(expired) + pem(pki.wallet_ca))
    issuer = make_issuer(wallet_provider_anchors=tmp_path / "wp.pem")
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        assert Wallet(client, pki, clock).issue().status_code == 200


@pytest.mark.parametrize("kind", STORES)
def test_n4_m1_hypothesis_text_claims_with_surrogates(wallet_on: Any, kind: str) -> None:
    """Every string claim a client signs, filled with text that may hold lone surrogates and control
    characters, on both stores. Hypothesis leaves surrogates out of st.text() unless asked (N4-L7)."""
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")
    odd = st.sampled_from(["\ud800", "\udbff", "\udc00", "\udfff", "\x00", " ", "￾"])
    # st.text() never yields a surrogate, whatever its alphabet, so the strings are joined from characters.
    text = st.lists(st.characters(exclude_categories=()) | odd, min_size=1, max_size=24).map("".join)
    wallet, _ = wallet_on(kind)
    wallet.get_token()

    @hypothesis.settings(max_examples=60, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(st.sampled_from(["jti", "htm", "htu"]), text)
    def dpop(claim: str, value: str) -> None:
        key = EcKey.generate()
        claims = {"jti": uuid.uuid4().hex, "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock())}
        claims[claim] = (uuid.uuid4().hex if claim == "jti" else "") + value
        # json.dumps writes ASCII only, so a surrogate goes out as the JSON escape \udxxx.
        proof = raw_jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}, json.dumps(claims), key)
        assert wallet.token_request("x", dpop=proof).status_code == 400

    @hypothesis.settings(max_examples=60, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(st.sampled_from(["nonce", "aud", "iss"]), text, st.booleans())
    def key_proof(claim: str, value: str, in_attestation: bool) -> None:
        holder = EcKey.generate()
        now = int(wallet.clock())
        if in_attestation:
            attested = {"iat": now, "exp": now + 60, "attested_keys": [holder.public_jwk()], claim: value}
            attestation = raw_jws(
                {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [der_b64(wallet.pki.ka_leaf)]},
                json.dumps(attested),
                wallet.pki.ka_key,
            )
            proof = wallet.proof(holder, "n", key_attestation=attestation)
        else:
            header = {
                "typ": "openid4vci-proof+jwt",
                "alg": "ES256",
                "jwk": holder.public_jwk(),
                "key_attestation": wallet.key_attestation([holder]),
            }
            claims = {"aud": ISSUER, "iat": now, "nonce": "n", claim: value}
            proof = raw_jws(header, json.dumps(claims), holder)
        response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
        assert response.status_code == 400, response.text

    dpop()
    key_proof()


@pytest.mark.filterwarnings("ignore")  # cryptography warns about some of the changed certificates
def test_n4_m2_hypothesis_over_key_attestation_certificate_bytes(wallet: Wallet, pki: Pki) -> None:
    """The key attestation fuzz used to sign over a valid certificate only. Here bytes of the signer
    certificate and of a CA above it are changed, then the attestation is signed, so every path check
    meets certificates that load only in part, or not at all (N4-M2, N4-L7)."""
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")
    leaf = pki.ka_leaf.public_bytes(serialization.Encoding.DER)
    root = pki.wallet_ca.public_bytes(serialization.Encoding.DER)
    wallet.get_token()

    @hypothesis.settings(max_examples=150, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(
        st.booleans(),
        st.lists(st.tuples(st.integers(0, len(leaf) - 1), st.integers(0, 255)), min_size=1, max_size=3),
    )
    def mutated(with_root: bool, changes: list[tuple[int, int]]) -> None:
        der = bytearray(leaf)
        for at, value in changes:
            der[at] = value
        x5c = [base64.b64encode(bytes(der)).decode()]
        if with_root:
            x5c.append(base64.b64encode(root).decode())
        holder = EcKey.generate()
        header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c}
        attestation = wallet.key_attestation([holder], _header=header)
        proof = wallet.proof(holder, "n", key_attestation=attestation)
        response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
        assert response.status_code < 500, response.text

    mutated()


# N4-M3: the published status token never changes at the moment of a revocation ---------------------


def _poll(
    make_issuer: Callable[..., Issuer],
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    event: str | None,
    at_minute: int,
) -> list[tuple[int, int]]:
    """Poll list 1 once a minute for three hours, as a verifier would, and record the iat (in seconds from the
    start) and the number of visible bits of each token. `event` happens at `at_minute`; whatever it hides
    shows at minute 100, whenever it happened."""
    issuer = make_issuer(status_list_size=131_072, status_revocation_jitter=3600, status_decoy_churn_per_day=0)
    start = clock()
    ref = issuer.status.allocate()
    shows = start + 100 * 60
    monkeypatch.setattr("cunho.status._uniform", lambda width: shows - clock())
    seen = []
    for minute in range(180):
        clock.now = start + minute * 60
        if minute == at_minute and event == "revocation":
            issuer.revoke({"list": ref.list_id, "index": ref.index, "reason": "death"}, "admin")
        if minute == at_minute and event == "decoy":
            with issuer.store.atomic():
                issuer.status._decoy(ref.list_id, shows)  # noqa: SLF001 - a decoy that shows with the revoked bit
        payload = parse_jws(issuer.status_token(ref.list_id)).payload
        raw = zlib.decompress(b64u_decode(payload["status_list"]["lst"]))
        seen.append((payload["iat"] - int(start), sum(bin(byte).count("1") for byte in raw)))
    return seen


def test_n4_m3_a_poller_cannot_see_when_a_revocation_happened(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """s4: the token used to be signed again at the revocation, so its iat named the moment.

    Whether the person is revoked at minute 10 or at minute 70, or no one is revoked and a decoy is laid down
    instead, a verifier polling every minute sees the very same sequence of tokens: the bit shows at its own
    moment, and the token is published on fixed moments, whatever happened in between (review 5, N5-M3).
    """
    early = _poll(make_issuer, clock, monkeypatch, "revocation", 10)
    late = _poll(make_issuer, clock, monkeypatch, "revocation", 70)
    decoy = _poll(make_issuer, clock, monkeypatch, "decoy", 40)
    assert early == late == decoy
    counts = [count for _, count in early]
    assert counts[100] == counts[0] and counts[101] == counts[0] + 1, "the bit shows at its own moment, not before"
    offset = int(clock()) % 60
    assert [iat for iat, _ in early] == [60 * minute - offset for minute in range(180)], "the publication moments"
    nothing = _poll(make_issuer, clock, monkeypatch, None, 0)
    assert [iat for iat, _ in nothing] == [iat for iat, _ in early], "no event moves a publication"
    assert [count for _, count in nothing] == [counts[0]] * 180


def test_n4_m3_with_no_jitter_a_revocation_shows_at_once(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """With a jitter of 0 the bit shows at the next publication, and its moment, to within the interval."""
    issuer = make_issuer(status_revocation_jitter=0)
    ref = issuer.status.allocate()
    before = parse_jws(issuer.status_token(ref.list_id)).payload
    clock.now += 7
    issuer.revoke({"list": ref.list_id, "index": ref.index, "reason": "death"}, "admin")
    assert parse_jws(issuer.status_token(ref.list_id)).payload == before
    clock.now += 60
    after = parse_jws(issuer.status_token(ref.list_id)).payload
    assert after["iat"] == before["iat"] + 60 and after["status_list"] != before["status_list"]


# N4-M4: a torn anchor write is repaired, and a committed action is answered as committed ------------


def _audit(tmp_path: Path, clock: Clock, keyring: Keyring | None = None) -> tuple[AuditLog, SqliteStore, Path]:
    keyring = keyring or Keyring.from_file(tmp_path / "m.key", create=True)
    store = SqliteStore(tmp_path / "s.db", clock)
    path = tmp_path / "audit.anchor"
    log = AuditLog(store, keyring, clock, retention=3650 * 86_400, anchor=Anchor(path, keyring), create_anchor=True)
    return log, store, path


class DiskFull:
    """Makes the next anchor write stop after `keep` bytes with ENOSPC, as a full disk does."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, log: AuditLog) -> None:
        self.real = os.write
        self.log = log
        self.left: int | None = None
        monkeypatch.setattr(audit_module.os, "write", self.write)

    def arm(self, keep: int | None = None) -> None:
        self.left = keep if keep is not None else -1

    def write(self, fd: int, data: bytes) -> int:
        anchor = self.log.anchor
        if self.left is None or anchor is None or fd != anchor._fd:  # noqa: SLF001
            return self.real(fd, data)
        keep = len(data) // 2 if self.left < 0 else self.left
        self.left = None
        if keep:
            self.real(fd, data[:keep])
        raise OSError(errno.ENOSPC, "No space left on device")


def test_n4_m4_a_torn_anchor_line_is_closed_written_again_and_logged(
    tmp_path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """s2: the next line used to run into the fragment, and verification failed for good."""
    log, store, path = _audit(tmp_path, clock)
    disk = DiskFull(monkeypatch, log)
    log.append("offer.created", "admin")
    disk.arm()
    with caplog.at_level(logging.ERROR, "cunho.security"):
        entry = log.append("offer.created", "admin")  # committed; its anchor line is torn
    assert entry["seq"] == 2 and "could not be written after a commit" in caplog.text
    assert not path.read_bytes().endswith(b"\n")
    assert not log.verify()[0], "a torn anchor is never reported valid"
    log.append("offer.created", "admin")
    assert path.read_bytes().endswith(b"\n")
    events = [e["event"] for e in log.entries()]
    assert events == ["offer.created", "offer.created", "audit.anchor_repaired", "offer.created"]
    repaired = log.entries()[2]["data"]["torn_bytes"]
    assert repaired > 0 and "after its last line" in caplog.text
    ok, detail = log.verify()
    assert ok and detail.endswith(f"1 damaged stretch(es) of the anchor ({repaired} bytes) were closed and declared")
    restarted, _, _ = _audit(tmp_path, Clock(clock() + 10), Keyring.from_file(tmp_path / "m.key", create=False))
    restarted.append("offer.created", "admin")
    assert restarted.verify()[0]
    assert [line["seq"] for line in restarted.anchor.lines()] == [0, 1, 2, 3, 4, 5]  # type: ignore[union-attr]
    assert store is not None


def test_n4_m4_a_torn_line_already_closed_by_a_newline(
    tmp_path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repair itself can stop right after the newline that closes the fragment; the next one closes both."""
    log, _, path = _audit(tmp_path, clock)
    disk = DiskFull(monkeypatch, log)
    log.append("a", "admin")
    disk.arm()
    log.append("b", "admin")
    disk.arm(keep=1)  # the catch-up writes the closing newline, then stops
    with pytest.raises(AuditError, match="cannot be written"):
        log.append("c", "admin")
    assert path.read_bytes().endswith(b"\n") and [e["event"] for e in log.entries()] == ["a", "b"]
    log.append("c", "admin")
    assert log.verify()[0] and [e["event"] for e in log.entries()] == ["a", "b", "audit.anchor_repaired", "c"]


def test_n4_m4_bytes_no_line_declares_are_refused(tmp_path: Path, clock: Clock) -> None:
    """Damage is skipped only where the next line declares it, so nothing can be slipped in between lines."""
    log, _, path = _audit(tmp_path, clock)
    log.append("a", "admin")
    log.append("b", "admin")
    genesis, first, second = path.read_bytes().splitlines(keepends=True)
    keyring = Keyring.from_file(tmp_path / "m.key", create=False)
    anchor = Anchor(path, keyring)
    for inserted in (first[:10] + b"\n", b"\x00" * 7 + b"\n", b"\n"):
        path.write_bytes(genesis + inserted + first + second)
        with pytest.raises(AuditError, match="that no anchor line declares"):
            list(anchor.lines())
    path.write_bytes(genesis + first + second)
    log.append("c", "admin")  # damage at the end, where a torn write leaves it, is closed and declared
    whole = path.read_bytes()
    path.write_bytes(whole + b"garbage")
    log.append("d", "admin")
    repaired: list[dict[str, Any]] = []
    assert [line["seq"] for line in anchor.lines(repaired)] == [0, 1, 2, 3, 4, 5]  # the repair entry declares it
    assert repaired == [{"at": len(whole), "bytes": 8, "sha256": hashlib.sha256(b"garbage\n").hexdigest()}]
    damaged = path.read_bytes()
    path.write_bytes(damaged.replace(b"garbage", b"garbaGe"))  # a declared stretch changed later
    with pytest.raises(AuditError, match="that no anchor line declares"):
        list(anchor.lines())
    path.write_bytes(damaged)
    assert log.verify()[0]


def test_n4_m4_what_tail_sets_aside_and_what_it_refuses(tmp_path: Path, clock: Clock) -> None:
    log, _, path = _audit(tmp_path, clock)
    log.append("a", "admin")
    genesis, first = path.read_bytes().splitlines(keepends=True)
    keyring = Keyring.from_file(tmp_path / "m.key", create=False)
    path.write_bytes(genesis + first[:10] + b"\n")  # the only line after genesis was torn and closed
    anchor = Anchor(path, keyring)
    assert anchor.tail()["seq"] == 0  # type: ignore[index]
    assert anchor.damaged() == {"at": len(genesis), "bytes": 11}
    path.write_bytes(genesis + first[:-1])  # complete apart from its newline: kept, only the newline added
    assert anchor.tail()["seq"] == 1 and anchor.damaged() == {"at": len(genesis) + len(first) - 1, "bytes": 0}  # type: ignore[index]
    log.append("b", "admin")
    assert log.verify()[0] and [e["event"] for e in log.entries()] == ["a", "audit.anchor_repaired", "b"]
    assert b"\n\n" not in path.read_bytes()
    for content in (b"not an anchor line\n", b"\x00" * 20000):
        path.write_bytes(content)  # nothing valid in the whole file
        with pytest.raises(AuditError, match="holds no valid anchor line"):
            Anchor(path, keyring).tail()
    path.write_bytes(genesis + first + b"\x00" * 20000)  # a long NUL tail is read past to the last line
    assert Anchor(path, keyring).tail()["seq"] == 1  # type: ignore[index]
    with pytest.raises(AuditError, match="the anchor file is missing"):
        next(Anchor(tmp_path / "nowhere", keyring).lines())


def test_n4_m4_a_full_disk_stops_the_next_action_before_it_changes_anything(
    tmp_path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch, pki: Pki
) -> None:
    """At most one committed action is ever missing from the anchor: the next one waits for the disk."""
    clock_ = clock
    issuer = Issuer(
        Settings(
            **settings_kwargs(
                pki, store_path=tmp_path / "s.db", secret_key_file=tmp_path / "m.key", audit_anchor_path=tmp_path / "a"
            )
        ),
        clock=clock_,
    )
    disk = DiskFull(monkeypatch, issuer.audit)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        wallet.offer()
        disk.arm()
        first = wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _subject()})
        assert first.status_code == 201, "the offer was committed, so the answer says so"
        disk.arm(keep=0)
        second = wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _subject()})
        assert second.status_code == 500 and second.json()["error_description"] == "audit log unavailable"
        assert len(issuer.audit.entries()) == 2, "the second offer was refused before anything was written"
        assert (
            wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _subject()}).status_code
            == 201
        )
        assert issuer.audit.verify()[0]


def test_n4_m4_a_store_failure_inside_append_is_an_audit_error(
    tmp_path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    log, store, _ = _audit(tmp_path, clock)

    def full(*_: Any) -> bool:
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(store, "add", full)
    with pytest.raises(AuditError, match="database or disk is full"):
        log.append("a", "admin")


def _subject() -> dict[str, Any]:
    from .helpers import PID_SUBJECT

    return dict(PID_SUBJECT)


# N4-M7: verification under concurrent writers -------------------------------------------------------


def test_n4_m7_verify_while_another_thread_appends(tmp_path: Path) -> None:
    """s3: about half the verifications failed while entries were being appended."""
    log, _, _ = _audit(tmp_path, Clock())
    stop = threading.Event()

    def writer() -> None:
        while not stop.is_set():
            log.append("offer.created", "admin")

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        verdicts = [log.verify() for _ in range(150)]
    finally:
        stop.set()
        thread.join()
    assert all(ok for ok, _ in verdicts), {detail for ok, detail in verdicts if not ok}
    assert len(log.entries()) > 20, "the writer was busy meanwhile"


def _append_in_another_process(root: str, count: int, ready: Any) -> None:
    """A worker process: its own store connection, anchor handle and audit log, as each uvicorn worker has."""
    keyring = Keyring.from_file(Path(root) / "m.key", create=False)
    store = SqliteStore(Path(root) / "s.db")
    log = AuditLog(store, keyring, retention=3650 * 86_400, anchor=Anchor(Path(root) / "audit.anchor", keyring))
    ready.wait()
    for n in range(count):
        log.append("offer.created", "admin", n=n)


def test_n4_m7_verify_while_worker_processes_append(tmp_path: Path) -> None:
    """race4 case 7: four workers on one SQLite file and one anchor; verification never cries wolf."""
    log, _, _ = _audit(tmp_path, Clock())
    log.append("offer.created", "admin")
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    workers = [context.Process(target=_append_in_another_process, args=(str(tmp_path), 150, ready)) for _ in range(3)]
    for worker in workers:
        worker.start()
    ready.set()
    verdicts = []
    try:
        while any(worker.is_alive() for worker in workers):
            verdicts.append(log.verify())
    finally:
        for worker in workers:
            worker.join(60)
    assert all(worker.exitcode == 0 for worker in workers)
    assert len(verdicts) >= 5 and all(ok for ok, _ in verdicts), {detail for ok, detail in verdicts if not ok}
    assert log.verify() == (True, "451 entries verified; 452 anchor lines")


def test_n4_m7_an_append_between_the_head_and_the_anchor_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The same race made deterministic: right after verify reads the head, another thread appends an entry.
    Verify holds the locks every writer takes, so the append waits for it and the snapshot stays whole."""
    log, _, _ = _audit(tmp_path, Clock())
    log.append("a", "admin")
    real_head = log._head  # noqa: SLF001
    writers: list[threading.Thread] = []
    appended = threading.Event()

    def append() -> None:
        log.append("b", "admin")
        appended.set()

    def head_then_append() -> Any:
        mark = real_head()
        if not writers:
            writers.append(threading.Thread(target=append))
            writers[0].start()
            appended.wait(1.0)  # with the locks held by verify, the append cannot finish meanwhile
        return mark

    monkeypatch.setattr(log, "_head", head_then_append)
    result = log.verify()
    writers[0].join(10)
    assert result[0], result
    assert appended.is_set() and log.verify()[0]


def test_n4_m7_a_head_pointer_removed_after_everything_was_pruned(tmp_path: Path, clock: Clock) -> None:
    log, store, _ = _audit(tmp_path, clock)
    log.append("a", "admin")
    log.append("b", "admin")
    clock.now += 4000 * 86_400
    assert log.prune_before(clock() - 3650 * 86_400) == 2 and log.entries() == []
    assert log.verify()[0]
    store.delete("audit-meta", "head")
    assert log.verify() == (False, "the head pointer is missing")


# N4-M5: revoking a person closes their live offer, and an offer can be cancelled --------------------


def test_n4_m5_revoking_a_person_stops_their_live_offer(wallet: Wallet, issuer: Issuer, clock: Clock) -> None:
    """s5: the revocation said "nothing to revoke", and the offer redeemed two minutes later gave a valid PID."""
    offer = wallet.offer()
    response = wallet.admin("revocations", {"reason": "compromise", "subject_ref": offer["subject_ref"]})
    assert response.status_code == 200 and response.json() == {"revoked": 0, "offer_cancelled": True}
    entry = issuer.audit.entries()[-1]
    assert entry["event"] == "credential.revoked" and entry["data"]["offer_cancelled"] is True
    clock.now += 120
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    refused = refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "this offer was cancelled")
    assert refused.status_code == 400 and refused.json()["error"] == "invalid_grant"


def test_n4_m5_revoking_a_person_stops_their_live_token(wallet: Wallet, issuer: Issuer) -> None:
    """A token obtained before the revocation, and a second configuration of the same offer, give nothing."""
    second = "eu.europa.ec.eudi.pid_mdoc" if issuer.configs.get("eu.europa.ec.eudi.pid_mdoc") else None
    configs = [PID_CONFIG, second] if second else [PID_CONFIG]
    offer = wallet.offer(configs=configs)
    wallet.get_token(offer)
    if second:
        assert wallet.issue().status_code == 200
    revoked = wallet.admin("revocations", {"reason": "death", "subject_ref": offer["subject_ref"]})
    assert revoked.json() == {"revoked": 1 if second else 0, "offer_cancelled": True}
    response = refused_by(
        lambda: wallet.issue(config=second or PID_CONFIG),
        "VCI.CRED.ERROR_CODES",
        "this offer was cancelled or its subject revoked",
    )
    assert response.status_code == 400 and response.json()["error"] == "credential_request_denied"


def test_n4_m5_a_revocation_during_an_issuance_sees_its_credentials(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issued rows are written with the issuance's log entry, so a revocation that runs right after it
    finds the new credential; before, it could run in between and miss it."""
    offer = wallet.offer()
    wallet.get_token(offer)
    real = issuer.status.note_batch
    seen: list[dict[str, Any]] = []

    def revoke_now(size: int) -> None:
        seen.append(issuer.revoke({"reason": "death", "subject_ref": offer["subject_ref"]}, "admin"))
        real(size)

    monkeypatch.setattr(issuer.status, "note_batch", revoke_now)
    response = wallet.issue()
    assert response.status_code == 200 and seen[0]["revoked"] == 1
    index = disclosures(response.json()["credentials"][0]["credential"])[1]["status"]["status_list"]["idx"]
    assert issuer.status.value(StatusRef("1", index)) == 1


def test_n4_m5_a_subject_with_nothing_live_is_refused(wallet: Wallet, issuer: Issuer) -> None:
    unknown = issuer.new_subject_ref()  # a reference cunho could have handed out, with nothing behind it
    response = refused_by(
        lambda: wallet.admin("revocations", {"reason": "death", "subject_ref": unknown}),
        "STATUS.MONOTONIC",
        "nothing to revoke for this reference",
    )
    assert response.status_code == 400
    forged = "sub_" + "A" * 24  # the shape, but not a reference cunho handed out (review 5, N5-L6)
    refused_by(
        lambda: wallet.admin("revocations", {"reason": "death", "subject_ref": forged}),
        "STATUS.MONOTONIC",
        "subject_ref is not a reference this issuer handed out",
    )


def test_n4_m5_an_operator_cancels_an_offer(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    ref = offer["subject_ref"]
    assert wallet.client.post(f"/admin/offers/{ref}/cancel").status_code == 401
    response = wallet.client.post(f"/admin/offers/{ref}/cancel", headers=AUTH)
    assert response.status_code == 200 and response.json() == {"cancelled": True}
    entry = issuer.audit.entries()[-1]
    assert entry["event"] == "offer.cancelled" and entry["actor"] == "admin" and entry["data"] == {"subject_ref": ref}
    assert issuer.store.get("vault", ref) is None and issuer.store.get("vault-key", ref) is None
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "this offer was cancelled")
    again = refused_by(
        lambda: wallet.client.post(f"/admin/offers/{ref}/cancel", headers=AUTH),
        "ISS.SUBJECT.ENTITLEMENT",
        "no live offer for this subject reference",
    )
    assert again.status_code == 400 and len(issuer.audit.entries()) == 2
    bad = refused_by(
        lambda: wallet.client.post("/admin/offers/sub_nope/cancel", headers=AUTH),
        "ISS.SUBJECT.ENTITLEMENT",
        "not a subject reference this issuer handed out",
    )
    assert bad.status_code == 400


def test_n4_m5_a_cancelled_offer_keeps_what_it_already_issued(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    wallet.get_token(offer)
    issued = wallet.issue()
    index = disclosures(issued.json()["credentials"][0]["credential"])[1]["status"]["status_list"]["idx"]
    nothing = wallet.client.post(f"/admin/offers/{offer['subject_ref']}/cancel", headers=AUTH)
    assert nothing.status_code == 400, "every credential of the offer was issued: nothing is left to cancel"
    assert issuer.status.value(StatusRef("1", index)) == 0


# N4-L4: a revocation and its log entry stand or fall together -----------------------------------------


@pytest.mark.parametrize("kind", STORES)
@pytest.mark.parametrize("by", ["slot", "subject", "person"])
def test_n4_l4_a_failed_bit_flip_rolls_the_log_entry_back(
    wallet_on: Any, monkeypatch: pytest.MonkeyPatch, by: str, kind: str
) -> None:
    """The memory store now undoes a failed unit as SQLite does, so this holds on both. A revocation by person
    (review 5, N5-L7) too."""
    wallet, issuer = wallet_on(kind)
    response = wallet.admin(
        "offers", {"credential_configuration_ids": [PID_CONFIG], "subject": _subject(), "person": "p-9"}
    )
    offer = response.json()
    wallet.get_token(offer)
    issued = wallet.issue()
    index = disclosures(issued.json()["credentials"][0]["credential"])[1]["status"]["status_list"]["idx"]
    entries = len(issuer.audit.entries())

    def crash(ref: StatusRef) -> bool:
        raise RuntimeError("the worker died between the log entry and the bit")

    monkeypatch.setattr(issuer.status, "revoke", crash)
    target = {
        "slot": {"list": "1", "index": index},
        "subject": {"subject_ref": offer["subject_ref"]},
        "person": {"person": "p-9"},
    }
    body = {"reason": "death", **target[by]}
    with pytest.raises(RuntimeError):
        issuer.revoke(body, "admin")
    assert len(issuer.audit.entries()) == entries, "no entry says revoked while the bit is still 0"
    assert issuer.status.value(StatusRef("1", index)) == 0


# N4-L2: the audit log keeps no personal attribute -------------------------------------------------------


def test_n4_l2_the_exact_expiry_is_not_logged(wallet: Wallet, issuer: Issuer, clock: Clock) -> None:
    """s11: near the end of a document's life the credential's exp is the document's own expiry date."""
    today = dt.datetime.fromtimestamp(clock(), dt.UTC).date()
    expiry = today + dt.timedelta(days=9)
    offer = wallet.offer({**_subject(), "date_of_expiry": expiry.isoformat()})
    wallet.get_token(offer)
    response = wallet.issue()
    exp = disclosures(response.json()["credentials"][0]["credential"])[1]["exp"]
    assert dt.datetime.fromtimestamp(exp, dt.UTC).date() == expiry, "the credential ends with the document"
    entry = next(e for e in issuer.audit.entries() if e["event"] == "credential.issued")
    assert "exp" not in entry["data"] and entry["data"]["validity_days"] == issuer.settings.credential_validity_days
    assert str(exp) not in json.dumps(issuer.audit.entries()) and expiry.isoformat() not in json.dumps(
        issuer.audit.entries()
    )


def test_n4_l4_the_memory_store_undoes_a_failed_unit(clock: Clock) -> None:
    store = MemoryStore(clock)
    store.put("a", "kept", 1, None)
    store.put("a", "changed", 1, None)
    store.put("a", "gone", 1, None)
    with pytest.raises(RuntimeError), store.atomic():
        store.put("a", "changed", 2, None)
        store.delete("a", "gone")
        store.add("a", "new", 1, None)
        store.incr("a", "counter", None)
        with store.atomic():
            store.take("a", "kept")
        raise RuntimeError
    assert store.items("a") == [("changed", 1), ("gone", 1), ("kept", 1)]
    with store.atomic():
        store.put("a", "new", 1, None)
    assert store.get("a", "new") == 1


# N4-M8: a wall clock that jumps does not prune, sweep or stall anything for long -------------------

DAY = 86_400


def test_n4_m8_one_wrong_reading_during_maintenance(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """s6: with the clock 400 days ahead for one run, entries inside the retention period were pruned, verify
    failed afterwards, maintenance stopped in that worker and the decoy schedule stopped for 400 days. Every
    step now goes by the time the host clock gives, so the run goes on as if the clock read right."""
    kw = {
        "secret_key_file": tmp_path / "m.key",
        "audit_anchor_path": tmp_path / "audit.anchor",
        "audit_retention_days": 30,
        "status_decoy_churn_per_day": 0.01,
        "status_list_size": 131_072,
    }
    host = Host(clock)
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
    issuer.status.allocate()
    for _ in range(5):
        issuer.audit.append("offer.created", "admin")
        host.advance(DAY)
    issuer.maintenance(force=True)
    issuer.store.put("dpop-jti", "replay", 1, 7200)  # a replay entry that must outlive the excursion
    host.advance(3600 + CLOCK_TOLERANCE)
    clock.now += 400 * DAY
    with caplog.at_level(logging.ERROR, "cunho.security"):
        done = issuer.maintenance()
        assert issuer.sweep() == 0
    assert done["audit_entries_pruned"] == 0 and done["decoys_scheduled"] > 0, done
    assert "the wall clock reads 34560000 s off the time the host clock gives" in caplog.text
    clock.now -= 400 * DAY
    # the five, and the entry of the forced run (CX-17)
    assert len(issuer.audit.entries()) == 6 and issuer.audit.verify()[0], "nothing was pruned"
    assert issuer.store.get("dpop-jti", "replay") == 1, "nothing was swept"
    host.advance(60)
    assert issuer.maintenance() == {}, "not due yet: a minute after the last run"
    host.advance(3600 + 2 * CLOCK_TOLERANCE)
    done = issuer.maintenance()
    assert done["audit_entries_pruned"] == 0 and done["decoys_scheduled"] > 0, "on time again, with decoys"
    restarted = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
    host.advance(3600)
    assert restarted.maintenance()["decoys_scheduled"] > 0, "a restart keeps scheduling decoys"


def test_n4_m8_the_background_sweep_goes_by_the_time(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    """The store stamps and reads expiries by the time, and the sweep goes by it too: a clock far ahead deletes no
    replay entry early, and one behind keeps nothing late."""
    host = Host(clock)
    store = SqliteStore(tmp_path / "s.db", clock)
    issuer = host.issuer(make_issuer, store)
    store.put("c-nonce", "n", 1, 300)
    assert issuer.sweep() == 0 and issuer.sweep() == 0  # the base, then the latest time seen
    rows = store.count()
    clock.now += 30 * DAY
    assert issuer.sweep() == 0 and store.count() == rows, "a replay entry outlives the excursion"
    assert store.get("c-nonce", "n") == 1, "and is still read"
    clock.now -= 30 * DAY + 3600
    host.advance(300)
    assert issuer.sweep() == 1 and store.count() == rows - 1, "an hour behind: gone when the time says so"


def test_n4_m8_a_clock_that_went_back_does_not_stall_maintenance(
    make_issuer: Callable[..., Issuer], clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """A step back stalls nothing: maintenance goes on by the host clock's time, and only pruning waits, since
    a reading behind the time may mean the time was laid from a clock that read ahead."""
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    issuer.maintenance(force=True)
    host.advance(3600 + CLOCK_TOLERANCE)
    clock.now -= DAY
    with caplog.at_level(logging.ERROR, "cunho.security"):
        done = issuer.maintenance()
    assert "expired_entries" in done and done["audit_pruning_held"] == 1, done
    assert "and audit pruning waits" in caplog.text
    clock.now += DAY
    host.advance(3600)
    assert "audit_pruning_held" not in issuer.maintenance(), "the clock reads right again"


def test_n4_m8_a_restart_goes_by_the_time_kept_in_the_store(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path
) -> None:
    host = Host(clock)
    kw = {"secret_key_file": tmp_path / "m.key"}
    issuer = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
    issuer.maintenance(force=True)
    host.advance(600)
    clock.now -= 7 * DAY
    restarted = host.issuer(make_issuer, SqliteStore(tmp_path / "s.db", clock), **kw)
    assert restarted.clock_watch.now() == clock() + 7 * DAY, "the host clock's time"
    assert restarted.maintenance()["audit_pruning_held"] == 1
    clock.now += 7 * DAY
    host.advance(3600)
    assert "audit_pruning_held" not in restarted.maintenance()


def test_n4_m8_a_forced_run_vouches_for_the_clock(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    host = Host(clock)
    issuer = host.issuer(make_issuer, None)
    assert issuer.sweep() == 0  # the watch trusts the start
    clock.now += 10 * DAY
    issuer.maintenance(force=True)
    assert issuer.clock_watch.now() == clock(), "the forced run laid the time again"
    host.advance(3600)
    done = issuer.maintenance()
    assert "expired_entries" in done and "audit_pruning_held" not in done, done


def test_n4_m8_clock_watch_readings(clock: Clock, caplog: pytest.LogCaptureFixture) -> None:
    """Each reading, at the boundaries: the time is the base moved on by the host clock, whatever the wall clock
    reads; a reading more than the tolerance off is logged, and pruning waits an interval after the base, and
    while the clock reads behind."""
    host, store = Host(clock), MemoryStore(clock)
    watch = host.watch(store, 3600)
    start = clock()
    assert watch.now() is None, "nothing trusted yet"
    assert watch.steady() and watch.now() == start and not watch.settled()

    def at(offset: float) -> float | None:
        clock.now = start + (host.elapsed - 5000) + offset
        watch.steady()
        return watch.now()

    with caplog.at_level(logging.ERROR, "cunho.security"):
        assert at(CLOCK_TOLERANCE) == start and at(-CLOCK_TOLERANCE) == start
        assert not caplog.text, "within the tolerance: nothing to report"
        assert at(CLOCK_TOLERANCE + 1) == start and at(-CLOCK_TOLERANCE - 1) == start
    assert caplog.text.count("the wall clock reads 121 s off") == 1
    assert caplog.text.count("the wall clock reads -121 s off") == 1
    host.elapsed += 3599
    assert at(0) == start + 3599 and not watch.settled(), "an interval since the base was laid, less a second"
    host.elapsed += 1
    assert at(0) == start + 3600 and watch.settled()
    assert at(-CLOCK_TOLERANCE) is not None and watch.settled(), "within the tolerance behind"
    at(-CLOCK_TOLERANCE - 1)
    assert not watch.settled(), "behind: the time may have been laid from a clock that read ahead"
    at(10 * DAY)
    assert watch.settled(), "ahead: the time can only be behind, which prunes less"
    restarted = host.watch(store, 3600)
    assert restarted.now() == start + 3600, "another worker goes by the base in the store"


def test_n4_m8_a_decoy_schedule_set_far_ahead_is_laid_down_again(
    make_issuer: Callable[..., Issuer], clock: Clock
) -> None:
    issuer = make_issuer(status_list_size=131_072, status_decoy_churn_per_day=0.05)
    issuer.status.allocate()
    assert issuer.status.churn() == 0, "scheduled when the list opened"
    issuer.store.put("status-meta", "scheduled_until:1", clock() + 400 * DAY, None)
    assert issuer.status.churn() > 0, "a mark no worker could have set stops nothing"
    issuer.store.put("status-meta", "scheduled_until:1", clock() + 2 * DAY, None)
    assert issuer.status.churn() == 0, "a worker with a one-day interval schedules this far"


# N4-L1: the write-ahead log is cleared once no reader holds it, and nobody waits 30 s meanwhile ---------


def test_n4_l1_a_checkpoint_held_by_a_reader_is_retried(
    make_issuer: Callable[..., Issuer], clock: Clock, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """s10: the checkpoint waited 32 s with the store lock held, failed, and nothing said so."""
    store = SqliteStore(tmp_path / "s.db", clock)
    issuer = make_issuer(store=store)
    issuer.vault.put("sub_x", {"family_name": "Silva"}, None, "offer")
    wrapped = str(store.get("vault-key", "sub_x")).encode()
    reader = sqlite3.connect(tmp_path / "s.db")
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM kv").fetchone()
    issuer.vault.erase("sub_x")
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, "cunho"):
        done = issuer.maintenance(force=True)
    assert time.monotonic() - started < 10 and done["wal_cleared"] == 0
    assert "was not cleared" in caplog.text
    reader.rollback()
    reader.close()
    clock.now += 60
    issuer.sweep()
    assert all(wrapped not in path.read_bytes() for path in tmp_path.glob("s.db*")), "gone from every file"
    assert issuer.maintenance(force=True)["wal_cleared"] == 1


# N4-L5: every setting DESIGN says the operator chooses can be set ---------------------------------------


KNOBS: dict[str, tuple[str, Any]] = {
    "offer_ttl": ("CUNHO_OFFER_TTL", 900),
    "access_token_ttl": ("CUNHO_ACCESS_TOKEN_TTL", 240),
    "c_nonce_ttl": ("CUNHO_C_NONCE_TTL", 120),
    "dpop_iat_window": ("CUNHO_DPOP_IAT_WINDOW", 30),
    "proof_iat_window": ("CUNHO_PROOF_IAT_WINDOW", 600),
    "tx_code_max_attempts": ("CUNHO_TX_CODE_MAX_ATTEMPTS", 3),
    "credential_validity_days": ("CUNHO_CREDENTIAL_VALIDITY_DAYS", 7),
    "timestamp_granularity": ("CUNHO_TIMESTAMP_GRANULARITY", 86_400),
    "status_list_size": ("CUNHO_STATUS_LIST_SIZE", 65_536),
    "status_list_fill_limit": ("CUNHO_STATUS_LIST_FILL_LIMIT", 0.25),
    "status_decoy_ratio": ("CUNHO_STATUS_DECOY_RATIO", 0.05),
    "status_token_ttl": ("CUNHO_STATUS_TOKEN_TTL", 1800),
    "status_token_lifetime": ("CUNHO_STATUS_TOKEN_LIFETIME", 43_200),
    "status_decoy_churn_per_day": ("CUNHO_STATUS_DECOY_CHURN_PER_DAY", 0.004),
    "batch_size": ("CUNHO_BATCH_SIZE", 4),
}


def _env(pki: Pki, **extra: str) -> dict[str, str]:
    return {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": ADMIN_TOKEN,
        "CUNHO_SIGNING_KEY": str(pki.root / "signing.key"),
        "CUNHO_SIGNING_CHAIN": str(pki.root / "signing.pem"),
        "CUNHO_WALLET_PROVIDER_ANCHORS": str(pki.root / "wallet-providers.pem"),
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{ISSUER}/certs/signer.pem",
        **extra,
    }


def test_n4_l5_every_knob_is_read_from_the_environment(pki: Pki) -> None:
    defaults = Settings.from_env(_env(pki))
    chosen = Settings.from_env(_env(pki, **{name: str(value) for name, value in KNOBS.values()}))
    for field, (name, value) in KNOBS.items():
        assert getattr(chosen, field) == value != getattr(defaults, field), name
    assert Settings.from_env(_env(pki, CUNHO_OFFER_TTL="")).offer_ttl == defaults.offer_ttl, "empty is the default"


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("CUNHO_OFFER_TTL", "CUNHO_OFFER_TTL must be a whole number"),
        ("CUNHO_STATUS_LIST_SIZE", "CUNHO_STATUS_LIST_SIZE must be a whole number"),
        ("CUNHO_BATCH_SIZE", "CUNHO_BATCH_SIZE must be a whole number"),
        ("CUNHO_STATUS_DECOY_RATIO", "CUNHO_STATUS_DECOY_RATIO must be a number"),
    ],
)
def test_n4_l5_a_knob_that_is_not_a_number_refuses_to_start(pki: Pki, name: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        Settings.from_env(_env(pki, **{name: "lots"}))


# CI: secure_delete is switched on whatever the SQLite build's default -------------------------------------


def test_secure_delete_is_on_even_where_the_build_leaves_it_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Debian's SQLite turns secure_delete on by default, macOS's does not, so a test that only read the pragma
    could not see it switched off on Linux. Here every connection starts with it off, whatever the build,
    and a deleted row is looked for in the database file itself."""
    real = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        db = real(*args, **kwargs)
        db.execute("PRAGMA secure_delete=OFF")
        return db

    monkeypatch.setattr(store_module.sqlite3, "connect", connect)
    store = SqliteStore(tmp_path / "s.db", Clock())
    assert store._db.execute("PRAGMA secure_delete").fetchone()[0] == 1  # noqa: SLF001
    for n in range(20):
        store.put("filler", str(n), "x" * 60, None)
    store.put("vault", "sub_x", "WRAPPED-KEY-BYTES-0123456789", None)
    assert store.checkpoint()
    store.delete("vault", "sub_x")
    assert store.checkpoint()
    assert b"WRAPPED-KEY-BYTES-0123456789" not in (tmp_path / "s.db").read_bytes()
