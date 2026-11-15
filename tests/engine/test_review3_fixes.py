"""Regression tests for the third independent M2 review (finding ids from cunho-m2-review-3.md)."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import sqlite3
import sys
import uuid
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cunho.app import RateLimiter, create_app
from cunho.audit import GENESIS, Anchor, AuditError, AuditLog, Vault, _canonical, _key
from cunho.errors import ConfigError
from cunho.jose import MAX_NUMERIC, b64u, b64u_decode, b64u_json, is_number, parse_jws, strict_json, thumbprint
from cunho.keyring import Keyring
from cunho.oauth import seal
from cunho.proofs import CrlFile, parse_crls
from cunho.service import Issuer, Signers
from cunho.settings import Settings
from cunho.signer import FileSigner
from cunho.status import StatusRef
from cunho.store import MemoryStore, SqliteStore
from eudi_probe.jose import jws

from .helpers import (
    ADMIN_TOKEN,
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    PRE_AUTH,
    SLOW_IS_FINE,
    START,
    Clock,
    EcKey,
    Pki,
    Wallet,
    access_signer,
    certificate,
    crl,
    der_b64,
    disclosures,
    mdoc_signer,
    production_kwargs,
    refusals,
    refused_by,
    settings_kwargs,
)

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
ROOT = Path(__file__).resolve().parents[2]


def raw_jws(header: dict[str, Any], payload_text: str, key: EcKey) -> str:
    signing_input = f"{b64u_json(header)}.{b64u(payload_text.encode())}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


def code_of(offer: dict[str, Any]) -> str:
    return str(offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"])


def credential(wallet: Wallet, proof: str) -> Any:
    if wallet.token is None:
        wallet.get_token()
    return wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})


# N3-H1: every key attestation case is refused by the check it is about -----------------------------


def _ka_cases(wallet: Wallet) -> dict[str, tuple[str, str, Callable[[EcKey, str], str]]]:
    """label -> (rule, reason, build(holder, nonce) -> jwt proof). Each artefact is correctly signed."""
    pki = wallet.pki
    rogue_ca_key = ec.generate_private_key(ec.SECP256R1())
    rogue_ca = certificate("Rogue WP", rogue_ca_key, ca=True)
    rogue = EcKey.generate()
    rogue_leaf = certificate("Rogue KA", rogue.private, (rogue_ca, rogue_ca_key))
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    copied_name = certificate("WP Intermediate", attacker_key, ca=True)
    forger = EcKey.generate()
    forged_leaf = certificate("Forged KA", forger.private, (copied_name, attacker_key))
    mid_key = ec.generate_private_key(ec.SECP256R1())
    real_mid = certificate("WP Intermediate", mid_key, (pki.wallet_ca, pki.wallet_ca_key), ca=True)
    self_key = EcKey.generate()
    self_signed = certificate("Self Signed KA", self_key.private)
    trusted = [der_b64(pki.ka_leaf)]

    def ka(holder: EcKey, x5c: Any, key: EcKey, **claims: Any) -> str:
        header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c}
        return wallet.key_attestation([holder], signing_key=key, _header=header, **claims)

    def proof(holder: EcKey, nonce: str, attestation: str) -> str:
        return wallet.proof(holder, nonce, key_attestation=attestation)

    return {
        "missing": ("KA.VERIFY", "requires a key attestation", lambda h, n: wallet.proof(h, n, attest=False)),
        "rogue wallet provider": (
            "KA.CHAIN_TO_WP_LIST",
            "chain does not end at a trusted anchor",
            lambda h, n: proof(h, n, ka(h, [der_b64(rogue_leaf)], rogue)),
        ),
        "forged under a copied intermediate": (
            "KA.CHAIN_TO_WP_LIST",
            "broken certificate chain",
            lambda h, n: proof(h, n, ka(h, [der_b64(forged_leaf), der_b64(real_mid)], forger)),
        ),
        "self-signed leaf": (
            "KA.CHAIN_TO_WP_LIST",
            "self-signed",
            lambda h, n: proof(h, n, ka(h, [der_b64(self_signed)], self_key)),
        ),
        "x5c not an array": (
            "KA.CHAIN_TO_WP_LIST",
            "x5c must be an array",
            lambda h, n: proof(h, n, ka(h, "x", pki.ka_key)),
        ),
        "x5c entry not DER": (
            "KA.CHAIN_TO_WP_LIST",
            "not a DER certificate",
            lambda h, n: proof(h, n, ka(h, ["AAAA"], pki.ka_key)),
        ),
        "signed by another key": (
            "KA.VERIFY",
            "signature does not verify",
            lambda h, n: proof(h, n, ka(h, trusted, EcKey.generate())),
        ),
        "wrong typ": (
            "KA.VERIFY",
            "typ must be key-attestation+jwt",
            lambda h, n: proof(
                h, n, wallet.key_attestation([h], _header={"typ": "JWT", "alg": "ES256", "x5c": trusted})
            ),
        ),
        "iat in the future": (
            "KA.VERIFY",
            "iat that is not in the future",
            lambda h, n: proof(h, n, wallet.key_attestation([h], iat=int(wallet.clock()) + 61)),
        ),
        "iat missing": (
            "KA.VERIFY",
            "iat that is not in the future",
            lambda h, n: proof(h, n, wallet.key_attestation([h], iat=...)),
        ),
        "exp not a number": (
            "KA.VERIFY",
            "exp must be a number",
            lambda h, n: proof(h, n, wallet.key_attestation([h], exp="soon")),
        ),
        "no exp with a jwt proof": (
            "KA.VERIFY",
            "needs exp",
            lambda h, n: proof(h, n, wallet.key_attestation([h], exp=None)),
        ),
        "expired": (
            "KA.VERIFY",
            "has expired",
            lambda h, n: proof(h, n, wallet.key_attestation([h], exp=int(wallet.clock()))),
        ),
        "no attested keys": (
            "KA.VERIFY",
            "attested_keys must be a non-empty array",
            lambda h, n: proof(h, n, wallet.key_attestation([h], attested_keys=[])),
        ),
        "attested key unusable": (
            "KA.VERIFY",
            "not a usable public key",
            lambda h, n: proof(h, n, wallet.key_attestation([h], attested_keys=[{"kty": "EC", "crv": "P-256"}])),
        ),
        "weak key storage": (
            "KA.PID_KEY_IN_WSCD",
            "key_storage does not meet",
            lambda h, n: proof(h, n, wallet.key_attestation([h], key_storage=["iso_18045_basic"])),
        ),
        "key storage not a list": (
            "KA.PID_KEY_IN_WSCD",
            "key_storage does not meet",
            lambda h, n: proof(h, n, wallet.key_attestation([h], key_storage="iso_18045_high")),
        ),
        "weak user authentication": (
            "KA.VERIFY",
            "user_authentication does not meet",
            lambda h, n: proof(h, n, wallet.key_attestation([h], user_authentication=["iso_18045_basic"])),
        ),
        "nonce in the attestation unknown": (
            "VCI.NONCE.C_NONCE_VALID",
            "key attestation nonce is not a valid c_nonce",
            lambda h, n: proof(h, n, wallet.key_attestation([h], nonce="made-up")),
        ),
        "not signed with attested key 0": (
            "KA.JWT_PROOF_ATTESTED_KEY0",
            "signed with attested_keys[0]",
            lambda h, n: wallet.proof(h, n, key_attestation=wallet.key_attestation([EcKey.generate(), h])),
        ),
    }


def test_n3_h1_each_key_attestation_case_is_refused_by_its_own_rule(wallet: Wallet) -> None:
    def send(build: Callable[[EcKey, str], str]) -> Callable[[], Any]:
        holder = EcKey.generate()
        return lambda: credential(wallet, build(holder, wallet.c_nonce()))

    for label, (rule, reason, build) in _ka_cases(wallet).items():
        wallet.token = None
        response = refused_by(send(build), rule, reason)
        assert response.status_code == 400, label
    holder = EcKey.generate()
    wallet.token = None
    good = credential(wallet, wallet.proof(holder, wallet.c_nonce()))
    assert good.status_code == 200, good.text


def test_n3_h1_a_rogue_wallet_provider_never_gets_a_wscd_bound_pid(wallet: Wallet) -> None:
    """r6: with the anchor check deleted the old suite stayed green while this got 200."""
    rule, reason, build = _ka_cases(wallet)["rogue wallet provider"]
    response = refused_by(lambda: credential(wallet, build(EcKey.generate(), wallet.c_nonce())), rule, reason)
    assert response.status_code == 400 and response.json()["error"] == "invalid_proof"


def test_n3_h1_attestation_proof_cases_are_refused_by_their_own_rule(wallet: Wallet) -> None:
    wallet.get_token()

    def send(attestation: str) -> Any:
        return wallet.credential_request(
            {"credential_configuration_id": PID_CONFIG, "proofs": {"attestation": [attestation]}}
        )

    keys = [EcKey.generate()]
    refused_by(lambda: send(wallet.key_attestation(keys)), "KA.ATTESTATION_PROOF_NONCE", "must carry a c_nonce")
    refused_by(
        lambda: send(wallet.key_attestation(keys, nonce="")), "KA.ATTESTATION_PROOF_NONCE", "must carry a c_nonce"
    )
    refused_by(
        lambda: send(wallet.key_attestation(keys, nonce="made-up")), "VCI.NONCE.C_NONCE_VALID", "unknown, expired"
    )
    nonce = wallet.c_nonce()
    no_exp = wallet.key_attestation(keys, nonce=nonce, exp=None)
    assert send(no_exp).status_code == 200, "an attestation-type proof needs no exp (only jwt proofs do)"


# N3-M1: a huge number is a 400, never a 500 --------------------------------------------------------

BIG = "1" + "0" * 400


@pytest.mark.parametrize("value", [BIG, "-" + BIG, "1e400", "-1e400", str(MAX_NUMERIC + 1)])
def test_n3_m1_huge_dpop_iat_is_a_clean_400(wallet: Wallet, value: str) -> None:
    """r1: unauthenticated, before the pre-authorized code is even looked up."""
    key = EcKey.generate()
    payload = f'{{"jti":"{uuid.uuid4().hex}","htm":"POST","htu":"{ISSUER}/token","iat":{value}}}'
    proof = raw_jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}, payload, key)
    with refusals() as seen:
        response = wallet.token_request("x", dpop=proof)
    assert response.status_code == 400 and response.json()["error"] == "invalid_dpop_proof"
    assert seen[0][0] in ("DPOP.SIGNATURE", "DPOP.IAT_WINDOW")


@pytest.mark.parametrize("value", [10**400, -(10**400), MAX_NUMERIC + 1, 1e300])
def test_n3_m1_huge_key_proof_and_attestation_numbers_are_clean_400s(wallet: Wallet, value: Any) -> None:
    """A number of more than 20 digits is refused when the JWS is parsed; a smaller one past 2**53 by its check."""
    parsed = isinstance(value, int) and abs(value) > 10**20
    holder = EcKey.generate()

    def expect(rule: str, reason: str) -> tuple[str, str]:
        return ("VCI.F4.PROOF_SIGNATURE", "number too large") if parsed else (rule, reason)

    refused_by(
        lambda: credential(wallet, wallet.proof(holder, wallet.c_nonce(), iat=value)),
        *expect("VCI.F1.PROOF_IAT", "iat is missing, not a finite number"),
    )

    def send(attestation: str) -> Callable[[], Any]:
        return lambda: credential(wallet, wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation))

    for claim, reason in (("iat", "iat that is not in the future"), ("exp", "exp must be a number")):
        wallet.token = None
        refused_by(send(wallet.key_attestation([holder], **{claim: value})), *expect("KA.VERIFY", reason))
    wallet.token = None
    status = {"status": {"status_list": {"idx": 1, "uri": "https://wallet-provider.test/s"}}, "exp": value}
    attestation = wallet.key_attestation([holder], key_storage_status=status)
    refused_by(
        lambda: credential(wallet, wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)),
        *expect("VALIDITY.PID_LE_STATUS_EXP", "key_storage_status.exp"),
    )


def test_n3_m1_number_bounds() -> None:
    assert is_number(MAX_NUMERIC) and is_number(-MAX_NUMERIC) and is_number(float(MAX_NUMERIC))
    assert not is_number(MAX_NUMERIC + 1) and not is_number(-MAX_NUMERIC - 1)
    assert not is_number(float(MAX_NUMERIC) * 2) and not is_number(-float(MAX_NUMERIC) * 2)
    assert not is_number(10**400) and not is_number(True) and not is_number(float("nan")) and not is_number("1")
    assert not is_number(float("inf")) and is_number(0) and is_number(1.5)
    assert strict_json("1" + "0" * 19) == 10**19 and strict_json("-" + "9" * 20) == -int("9" * 20)
    for text in ("1" + "0" * 20, "-" + "1" * 21, "1e400", "-1e309"):
        with pytest.raises(ValueError, match="too large"):
            strict_json(text)
    assert strict_json("1e308") == 1e308


def test_n3_m1_content_length_is_parsed_safely(wallet: Wallet) -> None:
    """Digits other than ASCII, or thousands of them, never reach int() (which raises on both)."""
    import asyncio

    from starlette.requests import Request

    from cunho.app import _body
    from cunho.errors import IssuerError

    async def read(value: bytes) -> None:
        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        scope = {"type": "http", "method": "POST", "headers": [(b"content-length", value)]}
        await _body(Request(scope, receive), "OAUTH.TOKEN_ERROR_BODY")

    for value in ("²".encode(), b"9" * 5000, b"9" * 13, b"-1", str(256 * 1024 + 1).encode()):
        with pytest.raises(IssuerError, match="too large"):
            asyncio.run(read(value))
    for value in (b"0", b"0" * 12, str(256 * 1024).encode()):
        asyncio.run(read(value))


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_n3_m1_hypothesis_over_signed_dpop_and_key_proof_claims(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path, kind: str
) -> None:
    """Claims of every JSON type and size, in proofs that are correctly signed, so they reach the claim checks.

    The second review's fuzzing never signed a proof, so nothing after the signature check was reached. Text
    includes lone surrogates, which Hypothesis leaves out by default, and the run covers the SQLite store,
    which encodes every key it binds (review 4, N4-M1 and N4-L7).
    """
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")
    # st.text() never yields a surrogate, whatever its alphabet, so the strings are joined from characters.
    odd = st.sampled_from(["\ud800", "\udfff", "\x00"])
    text = st.lists(st.characters(exclude_categories=()) | odd, max_size=20).map("".join)
    leaves = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | text
    values = st.recursive(
        leaves,
        lambda inner: st.lists(inner, max_size=3) | st.dictionaries(text, inner, max_size=3),
        max_leaves=6,
    )
    # Numbers written out as text go into the payload as they are; any other string is JSON-encoded, so a lone
    # surrogate drawn as text never reaches the encoder raw.
    raw_numbers = (BIG, "1e400", "-" + BIG)
    numbers = st.integers() | st.floats(allow_nan=False) | st.sampled_from(raw_numbers)
    store = MemoryStore(clock) if kind == "memory" else SqliteStore(tmp_path / "s.db", clock)
    client = TestClient(create_app(issuer=make_issuer(store=store), background_maintenance=False), base_url=ISSUER)
    wallet = Wallet(client, pki, clock)
    wallet.get_token()
    token = wallet.token
    assert token is not None

    @hypothesis.settings(max_examples=120, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(st.sampled_from(["jti", "htm", "htu", "iat", "ath", "nonce"]), values, numbers)
    def dpop(claim: str, value: Any, iat: Any) -> None:
        key = EcKey.generate()
        claims: dict[str, Any] = {"jti": uuid.uuid4().hex, "htm": "POST", "htu": f"{ISSUER}/token"}
        claims[claim] = value
        text = json.dumps(claims)[:-1] + f',"iat":{iat if isinstance(iat, str) else json.dumps(iat)}}}'
        proof = raw_jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}, text, key)
        response = wallet.token_request("x", dpop=proof)
        assert response.status_code == 400, response.text

    @hypothesis.settings(max_examples=120, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(st.sampled_from(["aud", "iat", "nonce", "iss", "exp"]), values | numbers)
    def key_proof(claim: str, value: Any) -> None:
        holder = EcKey.generate()
        claims: dict[str, Any] = {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": "n"}
        text = json.dumps({**claims, claim: "@"}).replace('"@"', value if value in raw_numbers else json.dumps(value))
        header = {
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": holder.public_jwk(),
            "key_attestation": wallet.key_attestation([holder]),
        }
        response = wallet.credential_request(
            {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [raw_jws(header, text, holder)]}}
        )
        assert response.status_code in (400, 401), response.text

    @hypothesis.settings(max_examples=80, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(
        st.sampled_from(["iat", "exp", "attested_keys", "key_storage", "key_storage_status", "nonce"]), values | numbers
    )
    def attestation(claim: str, value: Any) -> None:
        holder = EcKey.generate()
        now = int(wallet.clock())
        claims: dict[str, Any] = {
            "iat": now,
            "exp": now + 3600,
            "attested_keys": [holder.public_jwk()],
            "key_storage": ["iso_18045_high"],
        }
        text = json.dumps({**claims, claim: "@"}).replace('"@"', value if value in raw_numbers else json.dumps(value))
        ka = raw_jws(
            {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [der_b64(wallet.pki.ka_leaf)]},
            text,
            wallet.pki.ka_key,
        )
        response = wallet.credential_request(
            {
                "credential_configuration_id": PID_CONFIG,
                "proofs": {"jwt": [wallet.proof(holder, "n", key_attestation=ka)]},
            }
        )
        assert response.status_code in (400, 401), response.text

    dpop()
    key_proof()
    attestation()


# N3-M2: the whole anchor is compared, and a missing anchor is never started again -------------------


def _log(tmp_path: Path, clock: Clock, keyring: Keyring) -> tuple[AuditLog, SqliteStore, Path]:
    store = SqliteStore(tmp_path / "s.db", clock)
    anchor_path = tmp_path / "audit.anchor"
    log = AuditLog(
        store, keyring, clock, retention=3650 * 86_400, anchor=Anchor(anchor_path, keyring), create_anchor=True
    )
    return log, store, anchor_path


def test_n3_m2_rewritten_history_contradicts_an_older_anchor_line(tmp_path: Path, clock: Clock) -> None:
    """r2 (a): with the keyring, drop the revocation, re-MAC, pad and append one anchor line. The old anchor
    line for sequence 2 still names the revocation's MAC, and verification now reads every line."""
    keyring = Keyring.ephemeral()
    log, store, anchor_path = _log(tmp_path, clock, keyring)
    log.append("offer.created", "admin", subject_ref="sub_A")
    log.append("credential.revoked", "admin", reason="compromise", count=1, status_refs=["deadbeef"])
    log.append("offer.created", "admin", subject_ref="sub_B")
    assert log.verify()[0]
    kept = [e for e in log.entries() if e["event"] != "credential.revoked"]
    kept += [
        {"time": int(clock()), "event": "offer.created", "actor": "admin", "data": {"subject_ref": r}} for r in "CD"
    ]
    db = sqlite3.connect(store.path, isolation_level=None)
    db.execute("DELETE FROM kv WHERE ns='audit'")
    prev = GENESIS
    for seq, entry in enumerate(kept, 1):
        body = {k: v for k, v in entry.items() if k != "mac"} | {"seq": seq, "prev": prev}
        prev = keyring.mac("audit-entry", _canonical(body))
        db.execute("INSERT INTO kv VALUES ('audit',?,?,NULL)", (_key(seq), json.dumps({**body, "mac": prev})))
    head = {"seq": len(kept), "mac": prev, "tag": keyring.mac("audit-head", f"{len(kept)}:{prev}")}
    db.execute("UPDATE kv SET value=? WHERE ns='audit-meta' AND key='head'", (json.dumps(head),))
    lines = [json.loads(line) for line in anchor_path.read_text().splitlines()]
    line: dict[str, Any] = {"seq": len(kept), "mac": prev, "time": int(clock()), "prev": lines[-1]["tag"]}
    line["tag"] = keyring.mac("audit-anchor", _canonical(line))
    with anchor_path.open("a") as handle:
        handle.write(_canonical(line) + "\n")
    assert log.verify() == (False, "the store diverges from the anchor at sequence 2")


def test_n3_m2_a_wiped_log_with_its_anchor_removed_is_not_started_again(tmp_path: Path, clock: Clock) -> None:
    """r2 (b): unlink the anchor and delete every audit row. Before, verify said True and logging restarted."""
    keyring = Keyring.ephemeral()
    log, store, anchor_path = _log(tmp_path, clock, keyring)
    log.append("offer.created", "admin", subject_ref="sub_A")
    anchor_path.unlink()
    store._db.execute("DELETE FROM kv WHERE ns IN ('audit', 'audit-meta')")  # noqa: SLF001
    assert log.verify() == (False, "the anchor file is missing; restore it before anything is logged")
    with pytest.raises(AuditError, match="anchor file is missing"):
        log.append("offer.created", "admin", subject_ref="sub_B")
    assert not anchor_path.exists(), "the anchor file is never created again by a write"
    with pytest.raises(AuditError, match="does not exist"):
        AuditLog(store, keyring, clock, anchor=Anchor(anchor_path, keyring))  # production without the init setting


def test_n3_m2_missing_anchor_over_an_existing_log_refuses_to_start(
    make_issuer: Callable[..., Issuer], tmp_path: Path, clock: Clock
) -> None:
    store = SqliteStore(tmp_path / "s.db", clock)
    issuer = make_issuer(store=store)
    issuer.audit.append("offer.created", "admin")
    anchor = Path(f"{store.path}.audit-anchor")
    assert anchor.exists()
    anchor.unlink()
    with pytest.raises(ConfigError, match="never starts a new anchor over an existing log"):
        make_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    anchor.write_bytes(b"")
    with pytest.raises(ConfigError, match="never starts a new anchor over an existing log"):
        make_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    fresh = make_issuer(store=MemoryStore(clock))
    assert fresh.audit.verify() == (True, "0 entries verified; 1 anchor lines")


def _injected_signers(pki: Pki) -> Signers:
    anchors = pki.root / "issuer-root.pem"
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    return Signers(
        signer,
        FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors),
        access_signer(pki),
        mdoc_signer(pki),
    )


def test_n3_m2_production_starts_a_new_anchor_only_when_told(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    kwargs = production_kwargs(pki, tmp_path, audit_anchor_init=False)
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    with pytest.raises(ConfigError, match="create it once"):
        Issuer(Settings(**kwargs), signers=_injected_signers(pki), clock=clock)
    issuer = Issuer(Settings(**{**kwargs, "audit_anchor_init": True}), signers=_injected_signers(pki), clock=clock)
    assert (tmp_path / "audit.anchor").read_bytes().count(b"\n") == 1
    issuer.audit.append("offer.created", "admin")
    again = Issuer(Settings(**kwargs), signers=_injected_signers(pki), clock=clock)
    assert again.audit.verify()[0], "an existing anchor needs no init setting"


def test_n3_m2_the_anchor_starts_with_its_genesis_line(tmp_path: Path, clock: Clock) -> None:
    keyring = Keyring.ephemeral()
    log, _, anchor_path = _log(tmp_path, clock, keyring)
    log.append("a", "admin")
    lines = anchor_path.read_bytes().splitlines(keepends=True)
    assert json.loads(lines[0])["seq"] == 0 and json.loads(lines[0])["mac"] == GENESIS
    anchor_path.write_bytes(b"".join(lines[1:]))
    assert log.verify() == (False, "anchor lines were removed or reordered")
    other = Anchor(tmp_path / "other.anchor", keyring)
    line = {"seq": 1, "mac": "x" * 64, "time": 0, "prev": GENESIS}
    line["tag"] = keyring.mac("audit-anchor", _canonical(line))
    (tmp_path / "other.anchor").write_text(_canonical(line) + "\n")
    with pytest.raises(AuditError, match="does not start with its genesis line"):
        list(other.lines())
    (tmp_path / "other.anchor").write_text("")
    with pytest.raises(AuditError, match="the anchor file is empty"):
        list(other.lines())


def test_n3_m2_an_anchor_file_replaced_under_an_open_handle_is_noticed(tmp_path: Path, clock: Clock) -> None:
    keyring = Keyring.ephemeral()
    log, _, anchor_path = _log(tmp_path, clock, keyring)
    log.append("a", "admin")
    saved = anchor_path.read_bytes()
    anchor_path.unlink()
    anchor_path.write_bytes(saved)  # same content, new file: the append handle must follow it
    log.append("b", "admin")
    assert anchor_path.read_bytes().count(b"\n") == 3 and log.verify()[0]


def test_n3_m2_pruned_entries_keep_the_anchor_checked(issuer: Issuer, clock: Clock) -> None:
    for n in range(4):
        issuer.audit.append("old", "admin", n=n)
    clock.now += (issuer.settings.audit_retention_days + 1) * 86_400
    issuer.audit.append("new", "admin")
    assert issuer.audit.prune_before(clock() - issuer.settings.audit_retention_days * 86_400) == 4
    assert issuer.audit.verify() == (True, "1 entries verified; 6 anchor lines")
    checkpoint = issuer.store.get("audit-meta", "checkpoint")
    assert checkpoint is not None and checkpoint["seq"] == 4


# N3-M3: a batch revocation looks like a decoy cluster ----------------------------------------------


def _visible(issuer: Issuer, list_id: str = "1") -> set[int]:
    raw = zlib.decompress(b64u_decode(parse_jws(issuer.status.token(list_id)).payload["status_list"]["lst"]))
    return {i for i in range(len(raw) * 8) if raw[i // 8] >> (i % 8) & 1}


def test_n3_m3_a_batch_revocation_is_spread_over_the_window(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """r8: ten credentials of one person no longer flip in the same instant."""
    issuer = make_issuer(status_revocation_jitter=3600, status_decoy_churn_per_day=0, batch_size=30)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        offer = wallet.offer()
        wallet.get_token(offer)
        nonce = wallet.c_nonce()
        issued = credential_batch(wallet, [EcKey.generate() for _ in range(10)], nonce)
        indexes = {disclosures(c["credential"])[1]["status"]["status_list"]["idx"] for c in issued}
        before = _visible(issuer)
        revoked = client.post(
            "/admin/revocations", headers=AUTH, json={"subject_ref": offer["subject_ref"], "reason": "death"}
        )
        assert revoked.json() == {"revoked": 10}
        assert all(issuer.status.value(StatusRef("1", i)) == 1 for i in indexes), "the bits are set at once"
        assert not (_visible(issuer) - before) & indexes, "and shown later, one by one"
        appearances: dict[int, int] = {}
        for minute in range(1, 62):
            clock.now += 60
            for index in (_visible(issuer) - before) & indexes:
                appearances.setdefault(index, minute)
        assert set(appearances) == indexes, "every revoked bit shows within the window"
        assert len(set(appearances.values())) >= 4, "the bits of one batch show at different moments"


def credential_batch(wallet: Wallet, holders: list[EcKey], nonce: str) -> list[dict[str, Any]]:
    body = {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [wallet.proof(h, nonce) for h in holders]}}
    response = wallet.credential_request(body)
    assert response.status_code == 200, response.text
    return list(response.json()["credentials"])


def _waits(monkeypatch: pytest.MonkeyPatch, *seconds: float) -> list[float]:
    """Fix the decoy schedule's waiting times; returns the rates they were asked for."""
    rates: list[float] = []
    queue = list(seconds)

    def wait(rate: float) -> float:
        rates.append(rate)
        return queue.pop(0) if queue else 10**9

    monkeypatch.setattr("cunho.status._exponential", wait)
    return rates


def test_n3_m3_decoys_come_in_clusters_sized_like_real_batches(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = make_issuer(status_list_size=131_072, status_decoy_churn_per_day=0.05, status_revocation_jitter=1800)
    for _ in range(20):
        issuer.status.note_batch(7)
    issuer.status.note_batch(0)
    assert issuer.status._cluster_sizes() == [(7, 20)]  # noqa: SLF001
    rates = _waits(monkeypatch, 100, 200)
    issuer.status.allocate()  # opens list 1 and lays down its schedule
    pending = sorted(float(at) for _, at in issuer.store.items("status-pending", "1:"))
    assert len(pending) == 14, "two clusters, each the size of an issued batch"
    assert clock() + 100 <= pending[0] and pending[-1] < clock() + 300 + 1800
    bits_per_second = 131_072 * 0.05 / 86_400
    assert rates[0] == pytest.approx(bits_per_second / 7), "clusters arrive at the bit rate over the mean size"


def test_n3_m3_cluster_bits_spread_over_the_jitter(
    make_issuer: Callable[..., Issuer], clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = make_issuer(status_list_size=131_072, status_decoy_churn_per_day=0.05, status_revocation_jitter=3600)
    issuer.status.note_batch(30)
    issuer.status.note_batch(30)
    issuer.status.note_batch(1)
    _waits(monkeypatch, 100)
    issuer.status.allocate()
    times = sorted(float(at) for _, at in issuer.store.items("status-pending", "1:"))
    assert len(times) in (1, 30)
    _waits(monkeypatch, 100)
    issuer.store.put("status-meta", "scheduled_until:1", clock(), None)
    while len(times) != 30:  # draw until a 30-cluster comes (two thirds of the draws)
        for key, _ in issuer.store.items("status-pending", "1:"):
            issuer.store.delete("status-pending", key)
        issuer.store.put("status-meta", "scheduled_until:1", clock(), None)
        _waits(monkeypatch, 100)
        issuer.status.churn()
        times = sorted(float(at) for _, at in issuer.store.items("status-pending", "1:"))
    assert times[-1] - times[0] > 600, "a cluster's bits do not show in one instant"
    assert clock() + 100 <= times[0] and times[-1] < clock() + 100 + 3600


def test_n3_m3_each_list_has_its_own_schedule(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """A list opened after the schedule was extended still gets decoys at once (r8: none for two hours)."""
    issuer = make_issuer(
        status_list_size=1024, status_list_fill_limit=0.05, status_decoy_churn_per_day=0.05, maintenance_interval=86_400
    )
    issuer.maintenance(force=True)
    while len(issuer.status.lists()) < 2:
        issuer.status.allocate()
    assert issuer.store.items("status-pending", "2:"), "the second list was scheduled when it opened"
    assert issuer.store.get("status-meta", "scheduled_until:2") is not None
    assert issuer.status.churn() == 0, "both lists are already scheduled to the horizon"


def test_n3_m3_jitter_setting_is_checked(pki: Pki) -> None:
    with pytest.raises(ConfigError, match="status_revocation_jitter must be"):
        Settings(**settings_kwargs(pki, status_revocation_jitter=-1))
    with pytest.raises(ConfigError, match="status_revocation_jitter must be"):
        Settings(**settings_kwargs(pki, status_revocation_jitter=True))
    with pytest.raises(ConfigError, match="at most 86280 s"):
        Settings(**settings_kwargs(pki, status_revocation_jitter=86_400 - 120 - 3600 - 59))
    Settings(**settings_kwargs(pki, status_revocation_jitter=86_400 - 120 - 3600 - 60))
    assert Settings.from_env(_env(pki, CUNHO_STATUS_REVOCATION_JITTER="120")).status_revocation_jitter == 120


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


# N3-M4: revoked key attestation signers ------------------------------------------------------------


def test_n3_m4_a_revoked_key_attestation_signer_is_refused(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path
) -> None:
    crls = tmp_path / "wp.crl"
    crls.write_bytes(crl(pki.wallet_ca, pki.wallet_ca_key))
    issuer = make_issuer(wallet_provider_crls=crls)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        assert credential(wallet, wallet.proof(EcKey.generate(), wallet.c_nonce())).status_code == 200
        crls.write_bytes(crl(pki.wallet_ca, pki.wallet_ca_key, [pki.ka_leaf]))
        os.utime(crls, ns=(1, 2))  # a different stamp even on coarse file systems
        wallet.token = None
        refused_by(
            lambda: credential(wallet, wallet.proof(EcKey.generate(), wallet.c_nonce())),
            "KA.CHAIN_TO_WP_LIST",
            "the leaf certificate is revoked",
        )
        crls.write_bytes(b"not a CRL")
        wallet.token = None
        refused_by(
            lambda: credential(wallet, wallet.proof(EcKey.generate(), wallet.c_nonce())),
            "KA.CHAIN_TO_WP_LIST",
            "no current revocation list",
        )
        crls.unlink()
        wallet.token = None
        refused_by(
            lambda: credential(wallet, wallet.proof(EcKey.generate(), wallet.c_nonce())),
            "KA.CHAIN_TO_WP_LIST",
            "no current revocation list",
        )


def test_n3_m4_crl_files_are_checked_at_startup(pki: Pki, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    good = crl(pki.wallet_ca, pki.wallet_ca_key)
    path = tmp_path / "wp.crl"
    path.write_bytes(good + good)
    assert len(CrlFile(path).current()) == 2
    der = x509.load_pem_x509_crl(good).public_bytes(serialization.Encoding.DER)
    assert len(parse_crls(der)) == 1
    path.write_bytes(b"garbage")
    with pytest.raises(ConfigError, match="cannot use the wallet provider CRLs"):
        CrlFile(path)
    with pytest.raises(ConfigError, match="cannot use the wallet provider CRLs"):
        CrlFile(tmp_path / "missing.crl")
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.wallet_ca.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=1))
    )
    delta = builder.add_extension(x509.DeltaCRLIndicator(1), critical=True).sign(pki.wallet_ca_key, hashes.SHA256())
    with pytest.raises(ValueError, match="only complete CRLs"):
        parse_crls(delta.public_bytes(serialization.Encoding.PEM))
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(5)
        .revocation_date(now)
        .add_extension(x509.CertificateIssuer([x509.DNSName("other.test")]), critical=True)
        .build()
    )
    indirect = builder.add_revoked_certificate(entry).sign(pki.wallet_ca_key, hashes.SHA256())
    with pytest.raises(ValueError, match="CRL entry carries an extension"):
        parse_crls(indirect.public_bytes(serialization.Encoding.PEM))
    reason = x509.RevokedCertificateBuilder().serial_number(6).revocation_date(now)
    reason = reason.add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
    numbered = builder.add_extension(x509.CRLNumber(3), critical=False).add_revoked_certificate(reason.build())
    assert (
        len(parse_crls(numbered.sign(pki.wallet_ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))) == 1
    )
    # M3: production takes revocation from CRL distribution points and OCSP under the list of wallet providers, and
    # the operator's CRL file is pooled in when there is one, so production no longer needs it.
    assert Settings(**{**production_kwargs(pki, tmp_path), "wallet_provider_crls": None}).production
    with caplog.at_level(logging.WARNING, logger="cunho"):
        Issuer(Settings(**settings_kwargs(pki)), store=MemoryStore())
    assert "nor CUNHO_WALLET_PROVIDER_CRLS is set" in caplog.text
    assert Settings.from_env(_env(pki, CUNHO_WALLET_PROVIDER_CRLS=str(path))).wallet_provider_crls == path


# N3-M5: offer and token rows carry a MAC -----------------------------------------------------------


def test_n3_m5_a_forged_access_token_row_gets_nothing(
    make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path, clock: Clock
) -> None:
    """r9: a database writer points a token row at another person's live vault entry."""
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        operator = Wallet(client, pki, clock)
        victim = operator.offer({**PID_SUBJECT, "family_name": "Victim"})
        attacker = Wallet(client, pki, clock)
        token = "attacker-chosen-token-value-0123456789abcdef"
        row = {
            "grant_id": "g" * 24,
            "offer_id": "o" * 24,
            "jkt": thumbprint(attacker.dpop_key.public_jwk()),
            "configuration_ids": [PID_CONFIG],
            "subject_ref": victim["subject_ref"],
            "exp": int(clock()) + 300,
        }
        db = sqlite3.connect(tmp_path / "s.db", isolation_level=None)
        db.execute(
            "INSERT INTO kv VALUES ('access-token',?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), json.dumps(row), clock() + 300),
        )
        attacker.token = token
        response = refused_by(attacker.issue, "OAUTH.RESOURCE_401_CHALLENGE", "unknown or expired access token")
        assert response.status_code == 401
        # Even with a MAC from a stolen keyring, the vault does not open for another offer.
        sealed = seal(issuer.keyring, "token-record", hashlib.sha256(token.encode()).hexdigest(), row)
        db.execute("UPDATE kv SET value=? WHERE ns='access-token'", (json.dumps(sealed),))
        denied = refused_by(attacker.issue, "VCI.CRED.ERROR_CODES", "no longer available")
        assert denied.status_code == 400
        operator.get_token(victim)
        assert operator.issue().status_code == 200, "the victim's own redemption still works"


def test_n3_m5_a_forged_offer_row_gets_no_token(issuer: Issuer, wallet: Wallet, clock: Clock) -> None:
    code = "forged-code-0123456789abcdefghijklmnop"
    key = hashlib.sha256(code.encode()).hexdigest()
    row = {
        "offer_id": "o" * 24,
        "configuration_ids": [PID_CONFIG],
        "subject_ref": "sub_" + "A" * 24,
        "tx_code": None,
        "exp": int(clock()) + 600,
    }
    issuer.store.put("offer", key, row, 600)
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "unknown or expired pre-authorized code")
    issuer.store.put("offer", key, {**seal(issuer.keyring, "offer-record", "other-key", row)}, 600)
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    issuer.store.put("offer", key, seal(issuer.keyring, "offer-record", key, {**row, "exp": int(clock())}), 600)
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    issuer.store.put("offer", key, seal(issuer.keyring, "offer-record", key, {**row, "exp": True}), 600)
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    issuer.store.put("offer", key, ["not", "a", "row"], 600)
    refused_by(lambda: wallet.token_request(code), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    issuer.store.put("offer", key, seal(issuer.keyring, "offer-record", key, {**row, "exp": int(clock()) + 1}), 600)
    assert wallet.token_request(code).status_code == 200, "a correctly sealed row one second before expiry works"


def test_n3_m5_token_rows_expire_by_their_own_time(wallet: Wallet, issuer: Issuer, clock: Clock) -> None:
    token = wallet.get_token()
    key = hashlib.sha256(token.encode()).hexdigest()
    record = dict(issuer.store.get("access-token", key) or {})
    record.pop("mac")
    issuer.store.put(
        "access-token", key, seal(issuer.keyring, "token-record", key, {**record, "exp": int(clock())}), 300
    )
    refused_by(wallet.issue, "OAUTH.RESOURCE_401_CHALLENGE", "unknown or expired access token")


def test_n3_m5_the_grant_links_the_offer_entry_to_the_issuance_entry(wallet: Wallet, issuer: Issuer) -> None:
    first, second = wallet.offer(), wallet.offer()
    wallet.get_token(second)
    assert wallet.issue().status_code == 200
    entries = {e["event"]: e for e in issuer.audit.entries() if e["data"].get("subject_ref") == second["subject_ref"]}
    offered, issued = entries["offer.created"]["data"]["grant"], entries["credential.issued"]["data"]["grant"]
    assert offered == issued and len(offered) == 32
    other = next(e for e in issuer.audit.entries() if e["data"].get("subject_ref") == first["subject_ref"])
    assert other["data"]["grant"] != offered


def test_n3_m5_vault_opens_only_for_its_subject_and_offer(clock: Clock) -> None:
    store = MemoryStore(clock)
    vault = Vault(store, Keyring.ephemeral())
    vault.put("sub_a", {"n": 1}, None, "offer-a")
    store.put("vault", "sub_b", store.get("vault", "sub_a"), None)
    store.put("vault-key", "sub_b", store.get("vault-key", "sub_a"), None)
    assert vault.get("sub_b", "offer-a") is None, "copied rows do not open under another subject"
    assert vault.get("sub_a", "offer-b") is None and vault.get("sub_a", "offer-a") == {"n": 1}
    store.put("vault", "sub_a", "!!", None)
    assert vault.get("sub_a", "offer-a") is None


# Lows ----------------------------------------------------------------------------------------------


def test_n3_l1_malformed_audit_rows_are_a_failed_verification_not_a_500(
    make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path, clock: Clock
) -> None:
    """r5."""
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    db = sqlite3.connect(tmp_path / "s.db", isolation_level=None)
    with TestClient(
        create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        Wallet(client, pki, clock).offer()
        for value in ('{"seq":"x","mac":"m","tag":"t"}', "{}", '{"seq":true,"mac":"m","tag":"t"}', "[1]"):
            db.execute("UPDATE kv SET value=? WHERE ns='audit-meta' AND key='head'", (value,))
            verified = client.get("/admin/audit/verify", headers=AUTH)
            assert verified.status_code == 200 and verified.json() == {
                "valid": False,
                "detail": "audit head pointer was altered",
            }
            head = client.get("/admin/audit/head", headers=AUTH)
            assert head.status_code == 500 and head.json()["error"] == "server_error"
            offer = client.post(
                "/admin/offers",
                headers=AUTH,
                json={"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT},
            )
            assert offer.status_code == 500 and offer.json()["error_description"] == "audit log unavailable"
        db.execute(
            'UPDATE kv SET value=\'{"seq":1,"mac":"m","time":"t","tag":"x"}\' WHERE ns=\'audit-meta\' AND key=\'head\''
        )
        db.execute("INSERT INTO kv VALUES ('audit-meta','checkpoint','{\"seq\":1}',NULL)")
        assert client.get("/admin/audit/verify", headers=AUTH).json()["valid"] is False


def test_n3_l1_a_malformed_entry_stops_pruning_with_an_alert(
    issuer: Issuer, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    for n in range(3):
        issuer.audit.append("old", "admin", n=n)
    entry = dict(issuer.store.get("audit", _key(2)) or {})
    issuer.store.put("audit", _key(2), {**entry, "time": "yesterday"}, None)
    clock.now += (issuer.settings.audit_retention_days + 1) * 86_400
    issuer.audit.append("new", "admin")  # pruning goes by the newest entry's time too (N6-M3)
    with caplog.at_level(logging.ERROR, logger="cunho.security"):
        done = issuer.maintenance(force=True)
    assert done["audit_entries_pruned"] == 1 and "pruning stopped at entry 2, which does not verify" in caplog.text
    assert issuer.audit.verify()[0] is False
    issuer.store.put("audit", _key(2), ["not", "an", "entry"], None)
    assert issuer.audit.verify() == (False, "the audit log holds a malformed record")


def test_n3_l1_a_malformed_entry_stops_catch_up_cleanly(issuer: Issuer, monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = issuer.audit.anchor
    assert anchor is not None
    issuer.audit.append("first", "admin")
    real = anchor.write
    monkeypatch.setattr(anchor, "write", lambda marks: (_ for _ in ()).throw(OSError("crash")) if marks else 0)
    issuer.audit.append("second", "admin")  # committed, not anchored
    monkeypatch.setattr(anchor, "write", real)
    issuer.store.put("audit", _key(2), ["not", "an", "entry"], None)
    with pytest.raises(AuditError, match="malformed record"):
        issuer.audit.append("third", "admin")


def test_n3_l2_requests_never_sweep(tmp_path: Path) -> None:
    """r4: writes no longer delete other expired rows; maintenance does, in the background."""
    for store in (MemoryStore(Clock()), SqliteStore(tmp_path / "s.db", Clock())):
        clock = store._clock  # noqa: SLF001
        assert isinstance(clock, Clock)
        for n in range(50):
            store.put("c-nonce", str(n), 1, 10)
        clock.now += 3600
        store.put("x", "1", 1, None)
        store.add("dpop-jti", "j", 1, 10)
        store.incr("tx-attempts", "k", 10)
        count = len(store._data) if isinstance(store, MemoryStore) else store.count()  # noqa: SLF001
        assert count == 53, type(store)
        assert store.sweep(clock()) == 50


def test_n3_l3_limiter_memory_and_window(clock: Clock) -> None:
    t = [0.0]
    limiter = RateLimiter(3, clock=lambda: t[0], max_clients=2)
    assert [limiter.allow("a") for _ in range(4)] == [True, True, True, False]
    t[0] = 60.0  # the next minute: the previous count still weighs fully at its start
    assert limiter.allow("a") is False
    t[0] = 90.0  # half of it is outside the window: 1.5 of the previous minute's 3 still count
    assert [limiter.allow("a") for _ in range(3)] == [True, True, False]
    t[0] = 240.0  # two minutes later nothing is left
    assert [limiter.allow("a") for _ in range(3)] == [True, True, True]
    limiter.allow("b")
    limiter.allow("c")
    assert len(limiter) == 2, "the least recently seen client was dropped"
    assert limiter.allow("a") is True, "a, dropped, starts a fresh window"
    entry = limiter._hits["a"]  # noqa: SLF001
    assert isinstance(entry, tuple) and len(entry) == 3, "three numbers per client, not one timestamp per request"
    big = RateLimiter(120, clock=lambda: 0.0)
    for _ in range(500):
        big.allow("x")
    assert big._hits["x"] == (0, 120, 0)  # noqa: SLF001


def test_n3_l3_rate_limited_requests_get_no_device_flow_code(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    issuer = make_issuer(rate_limit_per_minute=1)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        assert client.post("/nonce").status_code == 200
        limited = client.post("/nonce")
        assert limited.status_code == 429 and limited.json()["error"] == "invalid_request"
        assert limited.headers["retry-after"] == "60"


def test_n3_l7_the_audit_head_has_its_own_key(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock) -> None:
    issuer = make_issuer()
    signed = issuer.audit_head()
    header = parse_jws(signed).header
    assert header["jwk"] == issuer.audit_signer.public_jwk() != issuer.signers.status.public_jwk()
    assert "x5c" not in header
    assert issuer.audit_verify(signed)[0]
    other = make_issuer()  # another keyring: another head key
    assert issuer.audit_verify(other.audit_head())[0] is False
    status_signed = issuer.audit.signed_head(issuer.signers.status, ISSUER)  # the old key no longer verifies
    assert issuer.audit_verify(status_signed) == (False, "the signed head is not a JWS from this issuer")
    with pytest.raises(ConfigError):
        issuer.audit_signer.certificate_der()
    assert issuer.audit_signer.x5c() == []
    bad = issuer.audit.signed_head(issuer.audit_signer, "https://other.test")
    assert issuer.audit_verify(bad)[0] is False
    forged = jws(
        {"typ": "cunho-audit-head+jwt", "alg": "ES256"}, {"iss": ISSUER, "seq": True, "mac": GENESIS}, EcKey.generate()
    )
    assert issuer.audit_verify(forged)[0] is False


def test_n3_l8_the_documented_recipe_does_not_log_status_fetches() -> None:
    readme = (ROOT / "docs" / "operations.md").read_text()
    assert readme.count("--no-access-log") >= 2, "both uvicorn command lines in the guide turn the access log off"


def test_n3_m1_revocation_index_is_range_checked(wallet: Wallet, issuer: Issuer) -> None:
    def revoke(index: int) -> Callable[[], Any]:
        return lambda: wallet.admin("revocations", {"list": "1", "index": index, "reason": "death"})

    for index in (-1, issuer.settings.status_list_size, 10**19):
        refused_by(revoke(index), "STATUS.MONOTONIC", "nothing to revoke")
    issuer.status.allocate()
    last = issuer.settings.status_list_size - 1
    answer = wallet.admin("revocations", {"list": "1", "index": last, "reason": "death"})
    assert answer.status_code == 200, "the last index is in range"


def test_n3_h1_mutation_tool_covers_every_raise_and_guard() -> None:
    sys.path.insert(0, str(ROOT / "tools" / "mutation"))
    try:
        import mutate
    finally:
        sys.path.remove(str(ROOT / "tools" / "mutation"))
    mutants = mutate.discover(ROOT, {"site", "condition"})
    labels = {m.label for m in mutants}
    for needle in (
        "jose.py:_validate_path: site: raise problem or JoseError('chain does not end at a trusted anchor')",
        "jose.py:_validate_path: site: raise JoseError('broken certificate chain') from exc",
        "audit.py:AuditLog._unanchored_checked: site: "
        "raise AuditError('the audit store diverges from its anchor (head)')",
        "settings.py:Settings._check_knobs: site: "
        "raise ConfigError('status_list_fill_limit must be above 0 and at most 0.9')",
    ):
        assert needle in labels, needle
    kinds = {m.kind for m in mutants}
    assert kinds == {"site", "negate", "drop", "not", "flip", "patch"}
    source = (ROOT / "src" / "cunho" / "jose.py").read_text()
    for mutant in mutants:
        if mutant.file.endswith("jose.py") and mutant.kind != "patch":
            assert mutate.mutated_source(source, mutant) != source


def test_n3_l6_rules_implemented_in_part_are_marked() -> None:
    registry = json.loads((ROOT / "src" / "cunho" / "rules" / "registry.json").read_text())
    partial = {rule for rule, entry in registry.items() if "partial" in entry}
    assert partial == {
        # VCI.PROFILE.OID4VCI_HAIP was partial until M4 ran the OIDF HAIP plans for mdoc too, with their encrypted
        # variants (piece L).
        # PID.RULEBOOK.CONFORMANCE was partial until M4 issued the PID as mdoc too (piece C).
        # META.PREFERRED_STATUS_PERIODS was partial until M3 published preferred_client_status_period (piece G), and
        # KA.CHAIN_TO_WP_LIST until M3 took the anchors from the Commission's list and fetched revocation (piece I).
        "META.EDP_BY_VALUE",  # M3: no metadata member for an embedded disclosure policy is standardised yet
        # M4 piece J: clause 6 holds but for x5chain, which ISO/IEC 18013-5 and the CB-AdES of TS 119 152-1 place apart
        "FMT.ETSI_119472_1",
    }
    assert "uHeaders" in registry["FMT.ETSI_119472_1"]["partial"]
    # It stays partial past M4, the milestone it once named, until a metadata member is standardised.
    edp = registry["META.EDP_BY_VALUE"]
    assert edp["milestone"] == "M3" and "standardised" in edp["partial"] and "M4" not in edp["partial"]
    assert "partial" not in registry["VCI.PROFILE.OID4VCI_HAIP"]


def test_n3_l2_the_background_loop_sweeps_on_every_tick(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    """Without the in-request sweep, the background loop keeps expired state to about a minute of traffic."""
    import time

    issuer = make_issuer(maintenance_interval=1)
    issuer.store.put("c-nonce", "old", 1, 1)
    clock.now += 2
    with TestClient(create_app(issuer=issuer), base_url=ISSUER):
        deadline = time.monotonic() + 5
        while len(issuer.store) > 0 and time.monotonic() < deadline:  # type: ignore[arg-type]
            time.sleep(0.05)
    assert issuer.store.get("c-nonce", "old") is None and ("c-nonce", "old") not in issuer.store._data  # type: ignore[attr-defined]  # noqa: SLF001


def test_n3_l2_sqlite_sweeps_in_short_batches(tmp_path: Path) -> None:
    clock = Clock()
    store = SqliteStore(tmp_path / "s.db", clock)
    for n in range(2500):
        store.put("c-nonce", str(n), 1, 10)
    store.put("keep", "k", 1, None)
    clock.now += 11
    statements: list[str] = []
    store._db.set_trace_callback(statements.append)  # noqa: SLF001
    assert store.sweep(clock(), batch=1000) == 2500 and store.count() == 1
    assert sum(1 for s in statements if s.startswith("BEGIN IMMEDIATE")) == 3, "three transactions of at most 1000 rows"


def test_n3_m2_entries_without_a_head_pointer_fail_verification(clock: Clock) -> None:
    """Found with review 2's q8 script: with the head pointer deleted, entries were never read and verify passed."""
    store, keyring = MemoryStore(clock), Keyring.ephemeral()
    log = AuditLog(store, keyring, clock)
    for n in range(3):
        log.append("e", "admin", n=n)
    store.delete("audit-meta", "head")
    assert log.verify() == (False, "the head pointer is missing")
    empty = AuditLog(MemoryStore(clock), keyring, clock)
    assert empty.verify()[0]
