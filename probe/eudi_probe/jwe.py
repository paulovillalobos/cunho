"""Compact JWE for the probe's encryption checks (OpenID4VCI 1.0 §10): alg ECDH-ES (direct key agreement) with
A128GCM or A256GCM, as RFC 7516 and RFC 7518 §4.6 and §5.3 define them. Written apart from any issuer's code, so a
round trip that works is two implementations agreeing."""

from __future__ import annotations

import hashlib
import json
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .jose import JSON, EcKey, b64u, b64u_decode, b64u_json, ec_public_key_from_jwk

KEY_BITS = {"A128GCM": 128, "A192GCM": 192, "A256GCM": 256}
CURVES: dict[str, Callable[[], ec.EllipticCurve]] = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}


def concat_kdf(shared: bytes, enc: str, apu: bytes, apv: bytes) -> bytes:
    """RFC 7518 §4.6.2: the Concat KDF of NIST SP 800-56A with SHA-256, AlgorithmID the enc value (direct key
    agreement), PartyUInfo and PartyVInfo length-prefixed, SuppPubInfo the key length in bits."""
    bits = KEY_BITS[enc]

    def field(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    other = field(enc.encode("ascii")) + field(apu) + field(apv) + struct.pack(">I", bits)
    out = b""
    counter = 1
    while len(out) * 8 < bits:
        out += hashlib.sha256(struct.pack(">I", counter) + shared + other).digest()
        counter += 1
    return out[: bits // 8]


def _agree(private: ec.EllipticCurvePrivateKey, jwk: JSON) -> bytes:
    return private.exchange(ec.ECDH(), ec_public_key_from_jwk(jwk))


def _public_jwk(key: ec.EllipticCurvePrivateKey) -> JSON:
    numbers = key.public_key().public_numbers()
    size = (key.curve.key_size + 7) // 8
    crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}[key.curve.name]
    return {
        "kty": "EC",
        "crv": crv,
        "x": b64u(numbers.x.to_bytes(size, "big")),
        "y": b64u(numbers.y.to_bytes(size, "big")),
    }


def encrypt(payload: bytes, recipient: JSON, enc: str, **header: Any) -> str:
    """A compact JWE of `payload` to the EC public JWK `recipient`, with the header members given (kid, typ...)."""
    if enc not in KEY_BITS:
        raise ValueError(f"unsupported enc {enc!r}")
    ephemeral = ec.generate_private_key(CURVES[recipient["crv"]]())
    protected = {"alg": "ECDH-ES", "enc": enc, "epk": _public_jwk(ephemeral), **header}
    key = concat_kdf(_agree(ephemeral, recipient), enc, b"", b"")
    encoded = b64u_json(protected)
    iv = os.urandom(12)
    sealed = AESGCM(key).encrypt(iv, payload, encoded.encode("ascii"))
    return ".".join((encoded, "", b64u(iv), b64u(sealed[:-16]), b64u(sealed[-16:])))


@dataclass
class Opened:
    header: JSON
    payload: bytes

    def json(self) -> Any:
        return json.loads(self.payload)


def decrypt(token: str, key: EcKey | ec.EllipticCurvePrivateKey) -> Opened:
    """Open a compact ECDH-ES JWE with our private key. ValueError when it is not one, or does not open."""
    private = key.private if isinstance(key, EcKey) else key
    parts = token.strip().split(".")
    if len(parts) != 5:
        raise ValueError("not a compact JWE (five parts)")
    encoded, wrapped, iv, ciphertext, tag = parts
    header = json.loads(b64u_decode(encoded))
    if not isinstance(header, dict) or header.get("alg") != "ECDH-ES":
        raise ValueError(f"alg is {header.get('alg') if isinstance(header, dict) else None!r}, not ECDH-ES")
    enc = header.get("enc")
    if enc not in KEY_BITS:
        raise ValueError(f"unsupported enc {enc!r}")
    if wrapped:
        raise ValueError("ECDH-ES (direct) has an empty encrypted key")
    if "crit" in header:
        # RFC 7516 §4.1.13 (RFC 7515 §4.1.11): a recipient refuses a JWE whose critical extensions it does not
        # understand, and the probe understands none.
        raise ValueError(f"crit {header['crit']!r} marks extensions critical, which the probe does not understand")
    if "zip" in header:
        raise ValueError("compressed, though no zip was asked for")
    apu = b64u_decode(header["apu"]) if "apu" in header else b""
    apv = b64u_decode(header["apv"]) if "apv" in header else b""
    nonce, sealed, check = b64u_decode(iv), b64u_decode(ciphertext), b64u_decode(tag)
    # RFC 7518 §5.3: a 96-bit IV and a 128-bit tag, each in its own part; a wallet takes no other split of them.
    if len(nonce) != 12 or len(check) != 16:
        raise ValueError(f"the IV is {len(nonce)} bytes and the tag {len(check)}, not 12 and 16")
    cek = concat_kdf(_agree(private, header["epk"]), enc, apu, apv)
    try:
        payload = AESGCM(cek).decrypt(nonce, sealed + check, encoded.encode())
    except Exception as exc:  # noqa: BLE001 - InvalidTag and friends: the JWE does not open
        raise ValueError(f"does not decrypt: {type(exc).__name__}") from exc
    return Opened(header, payload)
