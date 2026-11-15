"""Minimal JOSE helpers for a test wallet. ES256 only on the signing side."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

JSON = dict[str, Any]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def sha256_b64u(value: str) -> str:
    return b64u(hashlib.sha256(value.encode("ascii")).digest())


@dataclass
class EcKey:
    private: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> EcKey:
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_private_jwk(cls, jwk: JSON) -> EcKey:
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" not in jwk:
            raise ValueError("DPoP key must be a private P-256 JWK")
        public = ec_public_key_from_jwk(jwk).public_numbers()
        numbers = ec.EllipticCurvePrivateNumbers(int.from_bytes(b64u_decode(jwk["d"]), "big"), public)
        return cls(numbers.private_key())

    def public_jwk(self) -> JSON:
        numbers = self.private.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def private_jwk(self) -> JSON:
        d = self.private.private_numbers().private_value
        return {**self.public_jwk(), "d": b64u(d.to_bytes(32, "big"))}

    def sign(self, data: bytes) -> bytes:
        r, s = decode_dss_signature(self.private.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk())


def jws(header: JSON, payload: JSON, key: EcKey) -> str:
    signing_input = f"{b64u_json(header)}.{b64u_json(payload)}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


def jws_hs256(header: JSON, payload: JSON, secret: bytes) -> str:
    signing_input = f"{b64u_json(header)}.{b64u_json(payload)}"
    mac = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64u(mac)}"


def jwk_thumbprint(jwk: JSON) -> str:
    """RFC 7638."""
    if jwk.get("kty") == "EC":
        members = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    elif jwk.get("kty") == "RSA":
        members = {k: jwk[k] for k in ("e", "kty", "n")}
    elif jwk.get("kty") == "OKP":
        members = {k: jwk[k] for k in ("crv", "kty", "x")}
    else:
        raise ValueError(f"unsupported kty {jwk.get('kty')!r}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(canonical.encode()).digest())


@dataclass
class ParsedJws:
    header: JSON
    payload: JSON
    signing_input: bytes
    signature: bytes


def parse_jws(token: str) -> ParsedJws:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"expected 3 JWS parts, got {len(parts)}")
    header = json.loads(b64u_decode(parts[0]))
    payload = json.loads(b64u_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWS header and payload must be JSON objects")
    return ParsedJws(header, payload, f"{parts[0]}.{parts[1]}".encode(), b64u_decode(parts[2]))


def load_x5c(x5c: list[str]) -> list[x509.Certificate]:
    # x5c uses standard base64, not base64url (RFC 7515 §4.1.6)
    return [x509.load_der_x509_certificate(base64.b64decode(item)) for item in x5c]


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def verify_with_public_key(alg: str, public_key: Any, signing_input: bytes, signature: bytes) -> bool:
    try:
        if alg.startswith("ES") and isinstance(public_key, ec.EllipticCurvePublicKey):
            size = (public_key.curve.key_size + 7) // 8
            if len(signature) != 2 * size:
                return False
            der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
            digest = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}[alg]
            public_key.verify(der, signing_input, ec.ECDSA(digest))
            return True
        if alg == "EdDSA" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signing_input)
            return True
        if alg[:2] in ("RS", "PS") and isinstance(public_key, rsa.RSAPublicKey):
            digest = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}[alg[2:]]
            pad = (
                padding.PKCS1v15()
                if alg.startswith("RS")
                else padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
            )
            public_key.verify(signature, signing_input, pad, digest)
            return True
    except (InvalidSignature, KeyError, ValueError):
        return False
    return False


def ec_public_key_from_jwk(jwk: JSON) -> ec.EllipticCurvePublicKey:
    curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[jwk["crv"]]
    return ec.EllipticCurvePublicNumbers(
        int.from_bytes(b64u_decode(jwk["x"]), "big"),
        int.from_bytes(b64u_decode(jwk["y"]), "big"),
        curve,
    ).public_key()
