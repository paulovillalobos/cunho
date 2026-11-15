"""Encrypted credential requests and responses (OpenID4VCI 1.0 §8.2, §8.3, §9, §10, §12.2.4).

The wallet's side of the JWE is written here from the RFCs with `cryptography`'s primitives and a Concat KDF of its
own, not with cunho.jwe, so the two implementations check each other; cunho.jwe's KDF is also held to the known
answer of RFC 7518 Appendix C."""

from __future__ import annotations

import functools
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cunho.errors import ConfigError
from cunho.jose import b64u, b64u_decode
from cunho.jwe import RequestKeys, concat_kdf
from cunho.service import Issuer
from cunho.settings import Settings
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet
from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, Wallet, refused_by, settings_kwargs
from .test_deferred import ADMIN, held_login, held_refs

ENC_BYTES = {"A128GCM": 16, "A256GCM": 32}
CURVES = {"P-256": (ec.SECP256R1(), 32), "P-384": (ec.SECP384R1(), 48), "P-521": (ec.SECP521R1(), 66)}


# ---------------------------------------------------------------- the wallet's side, from the RFCs


def public_jwk(key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    crv = next(name for name, (curve, _) in CURVES.items() if curve.name == key.curve.name)
    size = CURVES[crv][1]
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": crv,
        "x": b64u(numbers.x.to_bytes(size, "big")),
        "y": b64u(numbers.y.to_bytes(size, "big")),
    }


def public_key(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    curve, _ = CURVES[jwk["crv"]]
    x, y = (int.from_bytes(b64u_decode(jwk[c]), "big") for c in ("x", "y"))
    return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()


def kdf(shared: bytes, enc: str, apu: bytes = b"", apv: bytes = b"") -> bytes:
    """RFC 7518 §4.6.2 with NIST SP 800-56A's single-step KDF written out: SHA-256 rounds over a 32-bit counter."""
    length = ENC_BYTES.get(enc, 16)
    other = b"".join(len(part).to_bytes(4, "big") + part for part in (enc.encode(), apu, apv)) + (length * 8).to_bytes(
        4, "big"
    )
    out, counter = b"", 1
    while len(out) < length:
        out += hashlib.sha256(counter.to_bytes(4, "big") + shared + other).digest()
        counter += 1
    return out[:length]


def seal(
    payload: Any, jwk: dict[str, Any], *, enc: str = "A256GCM", header: dict[str, Any] | None = None, raw: bool = False
) -> str:
    """A compact JWE of `payload` (JSON, or bytes with raw) to `jwk`, as a wallet makes it, with `header` on top."""
    peer = public_key(jwk)
    ephemeral = ec.generate_private_key(peer.curve)
    fields: dict[str, Any] = {"alg": "ECDH-ES", "enc": enc, "cty": "json", "epk": public_jwk(ephemeral.public_key())}
    if "kid" in jwk:
        fields["kid"] = jwk["kid"]
    fields = {k: v for k, v in {**fields, **(header or {})}.items() if v is not None}
    protected = b64u(json.dumps(fields).encode())
    apu, apv = (
        b64u_decode(fields[n]) if isinstance(fields.get(n), str) and fields[n] != "*" else b"" for n in ("apu", "apv")
    )
    cek = kdf(ephemeral.exchange(ec.ECDH(), peer), str(fields.get("enc")), apu, apv)
    iv = os.urandom(12)
    data = payload if raw else json.dumps(payload).encode()
    sealed = AESGCM(cek).encrypt(iv, data, protected.encode())
    return ".".join((protected, "", b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])))


def unseal(token: str, key: ec.EllipticCurvePrivateKey) -> tuple[dict[str, Any], Any]:
    """The header and JSON content of a JWE cunho made to `key`."""
    protected, encrypted_key, iv, ciphertext, tag = token.split(".")
    header = json.loads(b64u_decode(protected))
    assert encrypted_key == ""
    cek = kdf(key.exchange(ec.ECDH(), public_key(header["epk"])), header["enc"])
    plain = AESGCM(cek).decrypt(b64u_decode(iv), b64u_decode(ciphertext) + b64u_decode(tag), protected.encode())
    return header, json.loads(plain)


class WalletKey:
    """A wallet's response key and the credential_response_encryption that names it."""

    def __init__(
        self, crv: str = "P-256", enc: str = "A256GCM", kid: str | None = "wallet-1", use: str | None = "enc"
    ) -> None:
        self.private = ec.generate_private_key(CURVES[crv][0])
        self.enc = enc
        self.jwk = {**public_jwk(self.private.public_key()), "alg": "ECDH-ES"}
        if use is not None:
            self.jwk["use"] = use
        if kid is not None:
            self.jwk["kid"] = kid

    def params(self, **changes: Any) -> dict[str, Any]:
        return {"jwk": self.jwk, "enc": self.enc, **changes}


# ---------------------------------------------------------------- fixtures


def text_file(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text)
    path.chmod(0o600)
    return path


def key_file(directory: Path, name: str, key: Any = None, mode: int = 0o600) -> Path:
    key = key or ec.generate_private_key(ec.SECP256R1())
    path = directory / name
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    path.chmod(mode)
    return path


@pytest.fixture
def enc_key(tmp_path: Path) -> Path:
    return key_file(tmp_path, "request-key.pem")


@pytest.fixture
def enc_issuer(make_issuer: Callable[..., Issuer], enc_key: Path) -> Issuer:
    return make_issuer(encryption_keys=(enc_key,))


@pytest.fixture
def enc_wallet(enc_issuer: Issuer, wallet_for: Callable[[Issuer], Wallet]) -> Wallet:
    return wallet_for(enc_issuer)


def issuer_jwk(wallet: Wallet, index: int = 0) -> dict[str, Any]:
    document = wallet.client.get("/.well-known/openid-credential-issuer").json()
    return dict(document["credential_request_encryption"]["jwks"]["keys"][index])


def request_body(wallet: Wallet, key: EcKey | None = None, **extra: Any) -> dict[str, Any]:
    if wallet.token is None:
        wallet.get_token()
    proof = wallet.proof(key or EcKey.generate(), wallet.c_nonce())
    return {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}, **extra}


def send(wallet: Wallet, token: str) -> Any:
    return wallet.credential_request(None, raw=token.encode(), content_type="application/jwt")


def error(response: Any) -> str:
    return str(response.json()["error"])


# ---------------------------------------------------------------- tests


def test_the_kdf_gives_the_known_answer_of_rfc_7518_appendix_c() -> None:
    def private(d: str) -> ec.EllipticCurvePrivateKey:
        return ec.derive_private_key(int.from_bytes(b64u_decode(d), "big"), ec.SECP256R1())

    alice = private("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo")
    bob = private("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")
    shared = alice.exchange(ec.ECDH(), bob.public_key())
    assert list(shared[:4]) == [158, 86, 217, 29]
    assert b64u(concat_kdf(shared, "A128GCM", b"Alice", b"Bob")) == "VqqN6vgjbSBcIijNcacQGg"
    assert kdf(shared, "A128GCM", b"Alice", b"Bob") == concat_kdf(shared, "A128GCM", b"Alice", b"Bob")
    assert kdf(shared, "A256GCM", b"", b"") == concat_kdf(shared, "A256GCM", b"", b"")


@pytest.mark.obligation("VCI.ENC.REQUEST", "VCI.ENC.RESPONSE")
def test_the_metadata_offers_both_blocks_with_request_keys(enc_wallet: Wallet, enc_key: Path) -> None:
    document = enc_wallet.client.get("/.well-known/openid-credential-issuer").json()
    [jwk] = document["credential_request_encryption"]["jwks"]["keys"]
    key = serialization.load_pem_private_key(enc_key.read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    canonical = public_jwk(key.public_key())
    thumbprint = b64u(hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()).digest())
    assert jwk == {**canonical, "use": "enc", "alg": "ECDH-ES", "kid": thumbprint}
    assert document["credential_request_encryption"] == {
        "jwks": {"keys": [jwk]},
        "enc_values_supported": ["A128GCM", "A256GCM"],
        "encryption_required": False,
    }
    assert document["credential_response_encryption"] == {
        "alg_values_supported": ["ECDH-ES"],
        "enc_values_supported": ["A128GCM", "A256GCM"],
        "encryption_required": False,
    }


def test_without_request_keys_neither_block_is_published(wallet: Wallet) -> None:
    document = wallet.client.get("/.well-known/openid-credential-issuer").json()
    assert "credential_request_encryption" not in document and "credential_response_encryption" not in document


def test_an_encrypted_request_gets_a_plain_answer_unless_it_asks(enc_wallet: Wallet) -> None:
    response = send(enc_wallet, seal(request_body(enc_wallet), issuer_jwk(enc_wallet), enc="A128GCM"))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert len(response.json()["credentials"]) == 1


@pytest.mark.obligation("VCI.ENC.RESPONSE")
@pytest.mark.parametrize(
    ("crv", "enc"), [("P-256", "A256GCM"), ("P-256", "A128GCM"), ("P-384", "A256GCM"), ("P-521", "A128GCM")]
)
def test_an_encrypted_response_is_made_to_the_wallets_key(enc_wallet: Wallet, crv: str, enc: str) -> None:
    holder = EcKey.generate()
    mine = WalletKey(crv, enc)
    body = request_body(enc_wallet, holder, credential_response_encryption=mine.params())
    response = send(enc_wallet, seal(body, issuer_jwk(enc_wallet)))
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/jwt" and response.headers["cache-control"] == "no-store"
    header, content = unseal(response.text, mine.private)
    assert header["alg"] == "ECDH-ES" and header["enc"] == enc and header["kid"] == "wallet-1"
    assert header["epk"]["crv"] == crv and set(header) == {"alg", "enc", "epk", "kid"}
    assert len(content["credentials"]) == 1 and content["notification_id"]
    payload = json.loads(b64u_decode(content["credentials"][0]["credential"].split(".")[1]))
    assert payload["cnf"]["jwk"]["x"] == holder.public_jwk()["x"]


@pytest.mark.obligation("VCI.ENC.RESPONSE")
def test_a_compressed_response_asked_for_is_sent_uncompressed(enc_wallet: Wallet) -> None:
    """OpenID4VCI 1.0 §8.2, §12.2.4: cunho publishes no zip_values_supported. A wallet that asks for zip=DEF all the
    same, as the OIDF suite's happy flow does, gets its credential encrypted and uncompressed: the JWE has no zip, so
    the wallet reads it as it is, and no length of the content is given away by compression."""
    mine = WalletKey()
    body = request_body(enc_wallet, credential_response_encryption={**mine.params(), "zip": "DEF"})
    response = send(enc_wallet, seal(body, issuer_jwk(enc_wallet)))
    assert response.status_code == 200, response.text
    header, content = unseal(response.text, mine.private)
    assert "zip" not in header and len(content["credentials"]) == 1
    published = enc_wallet.client.get("/.well-known/openid-credential-issuer").json()
    assert "zip_values_supported" not in published["credential_response_encryption"]


def test_a_wallet_key_without_kid_or_use_gets_a_jwe_without_kid(enc_wallet: Wallet) -> None:
    mine = WalletKey(kid=None, use=None)
    body = request_body(enc_wallet, credential_response_encryption=mine.params())
    response = send(enc_wallet, seal(body, issuer_jwk(enc_wallet)))
    header, _ = unseal(response.text, mine.private)
    assert "kid" not in header


def test_apu_and_apv_go_into_the_key_derivation(enc_wallet: Wallet) -> None:
    header = {"apu": b64u(b"wallet"), "apv": b64u(b"issuer")}
    response = send(enc_wallet, seal(request_body(enc_wallet), issuer_jwk(enc_wallet), header=header))
    assert response.status_code == 200, response.text


@pytest.mark.covers("VCI.ENC.RESPONSE")
def test_response_parameters_in_a_plain_request_are_refused(enc_wallet: Wallet, enc_issuer: Issuer) -> None:
    """§8.2: whoever could change a plain request could put their own key there."""
    body = request_body(enc_wallet, credential_response_encryption=WalletKey().params())
    response = refused_by(lambda: enc_wallet.credential_request(body), "VCI.ENC.RESPONSE", "encrypted request")
    assert response.status_code == 400 and error(response) == "invalid_encryption_parameters"
    assert enc_issuer.store.items("issued") == []


@pytest.mark.covers("VCI.ENC.RESPONSE")
def test_response_parameters_to_an_issuer_without_keys_are_refused(wallet: Wallet) -> None:
    body = request_body(wallet, credential_response_encryption=WalletKey().params())
    response = refused_by(lambda: wallet.credential_request(body), "VCI.ENC.RESPONSE", "does not encrypt")
    assert error(response) == "invalid_encryption_parameters"


@pytest.mark.covers("VCI.ENC.REQUEST")
def test_an_issuer_without_keys_takes_no_encrypted_request(wallet: Wallet) -> None:
    wallet.get_token()
    response = refused_by(
        lambda: wallet.credential_request(None, raw=b"a.b.c.d.e", content_type="application/jwt"),
        "VCI.ENC.REQUEST",
        "no encrypted requests",
    )
    assert response.status_code == 400 and error(response) == "invalid_credential_request"


@pytest.mark.parametrize(
    "change",
    [
        "not-an-object",
        {"zip": 5},
        {"enc": "A192GCM"},
        {"enc": None},
        {"enc": ["A256GCM"]},
        {"jwk": None},
        {"jwk": "a key"},
        {"jwk": {"alg": None}},
        {"jwk": {"alg": "UNSUPPORTED_ALG"}},
        {"jwk": {"alg": "ECDH-ES+A128KW"}},
        {"jwk": {"use": "sig"}},
        {"jwk": {"kid": ""}},
        {"jwk": {"kid": 5}},
        {"jwk": {"d": "AAAA"}},
        {"jwk": {"crv": "P-192"}},
        {"jwk": {"x": "AAAA"}},
        {"jwk": {"y": b64u((5).to_bytes(32, "big"))}},
        {"jwk": {"kty": "RSA"}},
    ],
)
@pytest.mark.covers("VCI.ENC.RESPONSE")
def test_unusable_response_parameters_are_refused_before_anything_is_issued(
    enc_wallet: Wallet, enc_issuer: Issuer, change: Any
) -> None:
    mine = WalletKey()
    if isinstance(change, dict):
        params: Any = mine.params()
        for name, value in change.items():
            if name == "jwk" and isinstance(value, dict):
                params["jwk"] = {k: v for k, v in {**mine.jwk, **value}.items() if v is not None}
            else:
                params[name] = value
        params = {k: v for k, v in params.items() if v is not None}
    else:
        params = change
    body = request_body(enc_wallet, credential_response_encryption=params)
    response = refused_by(
        functools.partial(send, enc_wallet, seal(body, issuer_jwk(enc_wallet))), "VCI.ENC.RESPONSE", ""
    )
    assert response.status_code == 400 and error(response) == "invalid_encryption_parameters", response.text
    assert response.headers["content-type"].startswith("application/json"), "errors are never encrypted"
    assert enc_issuer.store.items("issued") == []
    retry = send(
        enc_wallet, seal(request_body(enc_wallet, credential_response_encryption=mine.params()), issuer_jwk(enc_wallet))
    )
    assert retry.status_code == 200, "nothing was claimed by the refused request"


def test_an_error_answer_is_never_encrypted(enc_wallet: Wallet) -> None:
    mine = WalletKey()
    body = request_body(enc_wallet, credential_response_encryption=mine.params())
    body["proofs"] = {"jwt": ["not.a.proof"]}
    response = send(enc_wallet, seal(body, issuer_jwk(enc_wallet)))
    assert response.status_code == 400 and response.headers["content-type"].startswith("application/json")
    assert error(response) == "invalid_proof"


def mangled(token: str, part: int, value: str) -> str:
    parts = token.split(".")
    parts[part] = value
    return ".".join(parts)


def header_of(fields: dict[str, Any]) -> str:
    return b64u(json.dumps(fields).encode())


BAD_REQUESTS: list[tuple[str, Callable[[str, dict[str, Any]], str], str]] = [
    ("four parts", lambda t, k: t.rsplit(".", 1)[0], "not a compact JWE"),
    ("header not base64url", lambda t, k: mangled(t, 0, "*"), "base64url JSON object"),
    ("header not an object", lambda t, k: mangled(t, 0, header_of([1])), "base64url JSON object"),  # type: ignore[arg-type]
    ("crit", lambda t, k: seal({}, k, header={"crit": ["exp"], "exp": 1}), "crit"),
    ("zip", lambda t, k: seal({}, k, header={"zip": "DEF"}), "no zip"),
    ("alg", lambda t, k: seal({}, k, header={"alg": "ECDH-ES+A256KW"}), "alg must be ECDH-ES"),
    ("enc", lambda t, k: seal({}, k, header={"enc": "A192GCM"}), "enc must be one of"),
    ("enc as a list", lambda t, k: seal({}, k, header={"enc": ["A256GCM"]}), "enc must be one of"),
    ("no kid", lambda t, k: seal({}, k, header={"kid": None}), "kid must name"),
    ("other kid", lambda t, k: seal({}, k, header={"kid": "someone-else"}), "kid must name"),
    ("no epk", lambda t, k: seal({}, k, header={"epk": None}), "epk is not a usable"),
    ("private epk", lambda t, k: seal({}, k, header={"epk": {**k, "d": "AAAA"}}), "epk is not a usable"),
    ("epk off curve", lambda t, k: seal({}, k, header={"epk": {**k, "y": k["x"]}}), "epk is not a usable"),
    (
        "epk on another curve",
        lambda t, k: seal({}, k, header={"epk": public_jwk(ec.generate_private_key(ec.SECP384R1()).public_key())}),
        "curve of the key",
    ),
    ("apu", lambda t, k: seal({}, k, header={"apu": "*"}), "not base64url"),
    ("apv", lambda t, k: seal({}, k, header={"apv": 7}), "not base64url"),
    ("encrypted key", lambda t, k: mangled(t, 1, "AAAA"), "encrypted key must be empty"),
    ("short iv", lambda t, k: mangled(t, 2, b64u(b"\x00" * 8)), "iv must be 12 bytes"),
    ("short tag", lambda t, k: mangled(t, 4, b64u(b"\x00" * 8)), "iv must be 12 bytes and its tag 16"),
    ("tag not base64url", lambda t, k: mangled(t, 4, "*"), "not base64url"),
    ("changed ciphertext", lambda t, k: mangled(t, 3, b64u(b"\x00" * 16)), "does not decrypt"),
    (
        "changed header",
        lambda t, k: mangled(t, 0, header_of({**json.loads(b64u_decode(t.split(".")[0])), "x": 1})),
        "does not decrypt",
    ),
]


@pytest.mark.covers("VCI.ENC.REQUEST")
@pytest.mark.parametrize(("name", "make", "reason"), BAD_REQUESTS, ids=[b[0] for b in BAD_REQUESTS])
def test_a_request_that_does_not_decrypt_is_refused(
    enc_wallet: Wallet, name: str, make: Callable[[str, dict[str, Any]], str], reason: str
) -> None:
    jwk = issuer_jwk(enc_wallet)
    token = make(seal(request_body(enc_wallet), jwk), jwk)
    response = refused_by(functools.partial(send, enc_wallet, token), "VCI.ENC.REQUEST", reason)
    assert response.status_code == 400 and error(response) == "invalid_credential_request", name


@pytest.mark.covers("VCI.ENC.REQUEST")
def test_a_request_in_another_alphabet_is_refused(enc_wallet: Wallet) -> None:
    enc_wallet.get_token()
    response = refused_by(
        lambda: enc_wallet.credential_request(None, raw="é.a.b.c.d".encode(), content_type="application/jwt"),
        "VCI.ENC.REQUEST",
        "in ASCII",
    )
    assert error(response) == "invalid_credential_request"


def test_a_decrypted_request_that_is_not_an_object_is_refused(enc_wallet: Wallet) -> None:
    enc_wallet.get_token()
    jwk = issuer_jwk(enc_wallet)
    for plain in (b"[1]", b"not json"):
        response = refused_by(
            functools.partial(send, enc_wallet, seal(plain, jwk, raw=True)), "VCI.CRED.ERROR_CODES", "JSON object"
        )
        assert error(response) == "invalid_credential_request"


@pytest.fixture
def required_issuer(make_issuer: Callable[..., Issuer], enc_key: Path) -> Issuer:
    return make_issuer(encryption_keys=(enc_key,), encryption_required=True)


@pytest.mark.covers("VCI.ENC.REQUEST", "VCI.ENC.RESPONSE")
def test_when_required_both_ways_a_plain_side_is_refused(
    required_issuer: Issuer, wallet_for: Callable[[Issuer], Wallet]
) -> None:
    wallet = wallet_for(required_issuer)
    document = wallet.client.get("/.well-known/openid-credential-issuer").json()
    assert document["credential_request_encryption"]["encryption_required"] is True
    assert document["credential_response_encryption"]["encryption_required"] is True
    plain = refused_by(lambda: wallet.credential_request(request_body(wallet)), "VCI.ENC.REQUEST", "requires encrypted")
    assert error(plain) == "invalid_encryption_parameters"
    jwk = issuer_jwk(wallet)
    unasked = refused_by(
        functools.partial(send, wallet, seal(request_body(wallet), jwk)), "VCI.ENC.RESPONSE", "requires encrypted"
    )
    assert error(unasked) == "invalid_encryption_parameters"
    mine = WalletKey()
    both = send(wallet, seal(request_body(wallet, credential_response_encryption=mine.params()), jwk))
    assert both.status_code == 200 and unseal(both.text, mine.private)[1]["credentials"]


def test_a_repeated_request_is_answered_to_its_own_key(enc_wallet: Wallet) -> None:
    """The kept reply of a repeated request goes to the key of the request that repeats it."""
    holder = EcKey.generate()
    first, second = WalletKey(kid="first"), WalletKey(kid="second")
    jwk = issuer_jwk(enc_wallet)
    one = send(enc_wallet, seal(request_body(enc_wallet, holder, credential_response_encryption=first.params()), jwk))
    two = send(enc_wallet, seal(request_body(enc_wallet, holder, credential_response_encryption=second.params()), jwk))
    assert one.status_code == two.status_code == 200, two.text
    assert unseal(one.text, first.private)[1] == unseal(two.text, second.private)[1]
    assert unseal(two.text, second.private)[0]["kid"] == "second"


def test_requests_to_any_of_four_keys_decrypt(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], tmp_path: Path
) -> None:
    keys = tuple(key_file(tmp_path, f"key-{i}.pem") for i in range(4))
    wallet = wallet_for(make_issuer(encryption_keys=keys))
    for index in range(4):
        response = send(wallet, seal(request_body(wallet), issuer_jwk(wallet, index)))
        assert response.status_code == 200, response.text
        wallet.token = None


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda d: [d / "missing.pem"], "does not exist"),
        (lambda d: [key_file(d, "open.pem", mode=0o644)], "chmod 600"),
        (lambda d: [text_file(d, "x.pem", "not a key")], "not an unencrypted PEM"),
        (lambda d: [key_file(d, "p384.pem", ec.generate_private_key(ec.SECP384R1()))], "EC P-256"),
        (lambda d: [key_file(d, "rsa.pem", rsa.generate_private_key(65537, 3072))], "EC P-256"),
        (lambda d: [key_file(d, f"k{i}.pem") for i in range(5)], "at most 4"),
    ],
)
def test_unusable_request_keys_stop_the_start(
    make_issuer: Callable[..., Issuer], tmp_path: Path, make: Callable[[Path], list[Path]], message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        make_issuer(encryption_keys=tuple(make(tmp_path)))


def test_the_same_key_twice_stops_the_start(make_issuer: Callable[..., Issuer], tmp_path: Path) -> None:
    first = key_file(tmp_path, "a.pem")
    second = tmp_path / "b.pem"
    second.write_bytes(first.read_bytes())
    second.chmod(0o600)
    with pytest.raises(ConfigError, match="repeats another key"):
        make_issuer(encryption_keys=(first, second))


def test_required_without_keys_stops_the_start(pki: Any) -> None:
    with pytest.raises(ConfigError, match="encryption_required needs encryption_keys"):
        Settings(**settings_kwargs(pki, encryption_required=True))
    assert RequestKeys.load((), False) is None


def test_the_encryption_settings_come_from_the_environment(tmp_path: Path) -> None:
    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": ADMIN_TOKEN,
        "CUNHO_SIGNING_KEY": "k",
        "CUNHO_SIGNING_CHAIN": "c",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "a",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{ISSUER}/certs/signer.pem",
        "CUNHO_ENCRYPTION_KEYS": "/keys/new.pem,/keys/old.pem",
        "CUNHO_ENCRYPTION_REQUIRED": "true",
    }
    settings = Settings.from_env(env)
    assert settings.encryption_keys == (Path("/keys/new.pem"), Path("/keys/old.pem"))
    assert settings.encryption_required is True
    unset = Settings.from_env({k: v for k, v in env.items() if "ENCRYPTION" not in k})
    assert unset.encryption_keys == () and unset.encryption_required is False


@pytest.mark.parametrize("path", ["/credential", "/deferred_credential"])
def test_other_media_types_are_refused(enc_wallet: Wallet, path: str) -> None:
    enc_wallet.get_token()
    assert enc_wallet.token is not None
    proof = enc_wallet.dpop("POST", f"{ISSUER}{path}", access_token=enc_wallet.token)
    headers = {"Authorization": f"DPoP {enc_wallet.token}", "DPoP": proof, "Content-Type": "text/plain"}
    response = enc_wallet.client.post(path, content=b"{}", headers=headers)
    assert response.status_code == 400 and "application/json or application/jwt" in response.json()["error_description"]


def test_the_notification_endpoint_stays_json(enc_wallet: Wallet) -> None:
    enc_wallet.get_token()
    assert enc_wallet.token is not None
    proof = enc_wallet.dpop("POST", f"{ISSUER}/notification", access_token=enc_wallet.token)
    headers = {"Authorization": f"DPoP {enc_wallet.token}", "DPoP": proof, "Content-Type": "application/jwt"}
    response = enc_wallet.client.post("/notification", content=b"a.b.c.d.e", headers=headers)
    assert response.status_code == 400 and response.json()["error_description"] == "use application/json"


# ---------------------------------------------------------------- deferred


@pytest.fixture
def enc_code_issuer(make_code_issuer: Callable[..., Issuer], enc_key: Path) -> Issuer:
    return make_code_issuer(encryption_keys=(enc_key,))


@pytest.fixture
def enc_code_wallet(enc_code_issuer: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]) -> CodeWallet:
    return code_wallet_for(enc_code_issuer)


def deferred_jwe(wallet: CodeWallet, token: str) -> Any:
    assert wallet.token is not None
    proof = wallet.dpop("POST", f"{ISSUER}/deferred_credential", access_token=wallet.token)
    headers = {"Authorization": f"DPoP {wallet.token}", "DPoP": proof, "Content-Type": "application/jwt"}
    return wallet.client.post("/deferred_credential", content=token.encode(), headers=headers)


@pytest.mark.obligation("VCI.ENC.RESPONSE")
def test_a_deferred_issuance_is_answered_to_each_requests_own_key(
    enc_code_wallet: CodeWallet, enc_code_issuer: Issuer
) -> None:
    """§8.3: a 202 is encrypted too; §9.2: the deferred request's own parameters are used."""
    held_login(enc_code_wallet, enc_code_issuer)
    jwk = issuer_jwk(enc_code_wallet)
    first, second, third = WalletKey(kid="1"), WalletKey(kid="2", enc="A128GCM"), WalletKey(kid="3")
    body = request_body(enc_code_wallet, credential_response_encryption=first.params())
    waiting = send(enc_code_wallet, seal(body, jwk))
    assert waiting.status_code == 202 and waiting.headers["content-type"] == "application/jwt"
    transaction_id = unseal(waiting.text, first.private)[1]["transaction_id"]
    again = deferred_jwe(
        enc_code_wallet,
        seal({"transaction_id": transaction_id, "credential_response_encryption": second.params()}, jwk),
    )
    assert again.status_code == 202
    header, content = unseal(again.text, second.private)
    assert header["kid"] == "2" and header["enc"] == "A128GCM" and content["transaction_id"] == transaction_id
    [ref] = held_refs(enc_code_wallet)
    assert enc_code_wallet.client.post(f"/admin/deferred/{ref}/release", headers=ADMIN).status_code == 200
    collected = deferred_jwe(
        enc_code_wallet, seal({"transaction_id": transaction_id, "credential_response_encryption": third.params()}, jwk)
    )
    assert collected.status_code == 200, collected.text
    assert len(unseal(collected.text, third.private)[1]["credentials"]) == 1


@pytest.mark.covers("VCI.ENC.RESPONSE")
def test_a_plain_deferred_request_cannot_ask_for_encryption(
    enc_code_wallet: CodeWallet, enc_code_issuer: Issuer
) -> None:
    held_login(enc_code_wallet, enc_code_issuer)
    waiting = enc_code_wallet.issue()
    assert waiting.status_code == 202
    transaction_id = waiting.json()["transaction_id"]
    assert enc_code_wallet.token is not None
    proof = enc_code_wallet.dpop("POST", f"{ISSUER}/deferred_credential", access_token=enc_code_wallet.token)
    headers = {"Authorization": f"DPoP {enc_code_wallet.token}", "DPoP": proof, "Content-Type": "application/json"}
    body = {"transaction_id": transaction_id, "credential_response_encryption": WalletKey().params()}
    response = refused_by(
        lambda: enc_code_wallet.client.post("/deferred_credential", content=json.dumps(body).encode(), headers=headers),
        "VCI.ENC.RESPONSE",
        "encrypted request",
    )
    assert error(response) == "invalid_encryption_parameters"


def test_an_encrypted_deferred_request_that_does_not_decrypt_is_refused(
    enc_code_wallet: CodeWallet, enc_code_issuer: Issuer
) -> None:
    held_login(enc_code_wallet, enc_code_issuer)
    response = refused_by(lambda: deferred_jwe(enc_code_wallet, "a.b.c.d.e"), "VCI.ENC.REQUEST", "")
    assert error(response) == "invalid_credential_request"
