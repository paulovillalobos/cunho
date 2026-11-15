"""Compact JWE for encrypted credential requests and responses (OpenID4VCI 1.0 §10).

One key management algorithm, ECDH-ES in direct key agreement mode, with the Concat KDF of RFC 7518 §4.6.2, and the
two content encryption algorithms HAIP names, A128GCM and A256GCM, all with `cryptography`. No compression: cunho
publishes no zip_values_supported, refuses a compressed request, and answers a wallet that asks for a compressed
response uncompressed, which any wallet reads (the JWE then has no zip), as the OIDF suite expects of an issuer that
does not advertise it. Compressing before encrypting would give away lengths that depend on the credential's content.
A wallet's request is decrypted with one of cunho's request keys; a response is encrypted to the key the wallet sent
in that request.
"""

from __future__ import annotations

import json
import os
import secrets
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

from cunho.errors import ConfigError
from cunho.jose import (
    JoseError,
    alg_for_jwk,
    b64u,
    b64u_decode,
    jwk_from_public_key,
    public_key_from_jwk,
    strict_json,
    thumbprint,
)

ALG = "ECDH-ES"
ENCS = {"A128GCM": 16, "A256GCM": 32}  # the content encryption key's length in bytes
IV_BYTES = 12
TAG_BYTES = 16
MAX_KEYS = 4


class JweError(JoseError):
    pass


def concat_kdf(shared: bytes, enc: str, apu: bytes, apv: bytes) -> bytes:
    """The content encryption key for ECDH-ES in direct mode (RFC 7518 §4.6.2): AlgorithmID is the enc value,
    each of AlgorithmID, PartyUInfo and PartyVInfo is prefixed with its length, and SuppPubInfo is the key's length
    in bits."""
    length = ENCS[enc]

    def prefixed(data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + data

    other = prefixed(enc.encode("ascii")) + prefixed(apu) + prefixed(apv) + struct.pack(">I", length * 8)
    return ConcatKDFHash(hashes.SHA256(), length, other).derive(shared)


def _public(jwk: Any) -> ec.EllipticCurvePublicKey:
    """A public EC key on P-256, P-384 or P-521 whose point is on its curve: anything else, a private key among
    them, raises JoseError."""
    return public_key_from_jwk(jwk, alg_for_jwk(jwk))


@dataclass(frozen=True)
class ResponseKey:
    """The wallet's key and content encryption algorithm for one response (OpenID4VCI 1.0 §8.2)."""

    key: ec.EllipticCurvePublicKey
    enc: str
    kid: str | None

    @classmethod
    def from_params(cls, params: Any) -> ResponseKey:
        """credential_response_encryption as the wallet sent it. Raises JweError, with what is wrong."""
        if not isinstance(params, dict):
            raise JweError("credential_response_encryption must be an object")
        if "zip" in params and not isinstance(params["zip"], str):
            raise JweError("zip, when present, must be a string")
        # A zip asked for is not done: the response goes uncompressed, and its JWE says so by having no zip.
        enc, jwk = params.get("enc"), params.get("jwk")
        if not isinstance(enc, str) or enc not in ENCS:
            raise JweError(f"enc must be one of {', '.join(sorted(ENCS))}")
        if not isinstance(jwk, dict):
            raise JweError("jwk must be a JWK object")
        # §10: "The alg parameter MUST be present. The JWE alg algorithm used MUST be equal to the alg value".
        if jwk.get("alg") != ALG:
            raise JweError(f"the jwk's alg must be {ALG}")
        if "use" in jwk and jwk["use"] != "enc":
            raise JweError("the jwk's use, when present, must be enc")
        kid = jwk.get("kid")
        if kid is not None and (not isinstance(kid, str) or not kid):
            raise JweError("the jwk's kid, when present, must be a non-empty string")
        try:
            key = _public(jwk)
        except JoseError as exc:
            raise JweError(f"the jwk is not a usable public EC key: {exc}") from exc
        return cls(key, enc, kid)

    def encrypt(self, plaintext: bytes) -> str:
        """A compact JWE of `plaintext` to this key, with a fresh ephemeral key, carrying the wallet's kid."""
        ephemeral = ec.generate_private_key(self.key.curve)
        header: dict[str, Any] = {"alg": ALG, "enc": self.enc, "epk": jwk_from_public_key(ephemeral.public_key())}
        if self.kid is not None:
            header["kid"] = self.kid
        protected = b64u(json.dumps(header, separators=(",", ":")).encode())
        cek = concat_kdf(ephemeral.exchange(ec.ECDH(), self.key), self.enc, b"", b"")
        iv = secrets.token_bytes(IV_BYTES)
        sealed = AESGCM(cek).encrypt(iv, plaintext, protected.encode("ascii"))
        ciphertext, tag = sealed[:-TAG_BYTES], sealed[-TAG_BYTES:]
        return ".".join((protected, "", b64u(iv), b64u(ciphertext), b64u(tag)))


@dataclass(frozen=True)
class RequestKeys:
    """cunho's keys for encrypted requests, by kid (the RFC 7638 thumbprint), and whether encryption is required."""

    keys: Mapping[str, ec.EllipticCurvePrivateKey]
    required: bool

    @classmethod
    def load(cls, paths: Sequence[Path], required: bool) -> RequestKeys | None:
        """None without keys. Each file is a PEM EC P-256 private key that only its owner may read."""
        if not paths:
            return None  # the settings refuse encryption_required without keys
        if len(paths) > MAX_KEYS:
            raise ConfigError(f"at most {MAX_KEYS} encryption_keys: the current one and those being retired")
        keys: dict[str, ec.EllipticCurvePrivateKey] = {}
        for path in paths:
            if not path.is_file():
                raise ConfigError(f"encryption key file {path} does not exist")
            if os.stat(path).st_mode & 0o077:
                raise ConfigError(f"encryption key file {path} must not be readable by group or others (chmod 600)")
            try:
                key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            except (ValueError, TypeError) as exc:
                raise ConfigError(f"encryption key file {path} is not an unencrypted PEM private key") from exc
            if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ConfigError(f"encryption key file {path} must hold an EC P-256 key")
            kid = thumbprint(jwk_from_public_key(key.public_key()))
            if kid in keys:
                raise ConfigError(f"encryption key file {path} repeats another key")
            keys[kid] = key
        return cls(keys, required)

    def jwks(self) -> dict[str, Any]:
        """The public keys for credential_request_encryption: each with its kid, use enc and alg ECDH-ES."""
        return {
            "keys": [
                {**jwk_from_public_key(key.public_key()), "use": "enc", "alg": ALG, "kid": kid}
                for kid, key in self.keys.items()
            ]
        }

    def decrypt(self, token: str) -> bytes:
        """The plaintext of a compact JWE made to one of these keys. Raises JweError, with what is wrong."""
        parts = token.split(".")
        if len(parts) != 5:
            raise JweError("not a compact JWE")
        protected, encrypted_key, iv_text, ciphertext_text, tag_text = parts
        try:
            header = strict_json(b64u_decode(protected))
        except (ValueError, UnicodeDecodeError) as exc:
            raise JweError("the JWE header is not a base64url JSON object") from exc
        if not isinstance(header, dict):
            raise JweError("the JWE header is not a base64url JSON object")
        if "crit" in header:
            raise JweError("the JWE header asks for extensions this issuer does not understand (crit)")
        if "zip" in header:
            raise JweError("this issuer does not take compressed requests: send no zip")
        if header.get("alg") != ALG:
            raise JweError(f"the JWE alg must be {ALG}")
        enc = header.get("enc")
        if not isinstance(enc, str) or enc not in ENCS:
            raise JweError(f"the JWE enc must be one of {', '.join(sorted(ENCS))}")
        kid = header.get("kid")
        key = self.keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise JweError("the JWE kid must name one of the keys in credential_request_encryption")
        try:
            epk = _public(header.get("epk"))
        except JoseError as exc:
            raise JweError(f"the JWE epk is not a usable public EC key: {exc}") from exc
        if not isinstance(epk.curve, type(key.curve)):
            raise JweError("the JWE epk must be on the curve of the key it names")
        try:
            apu = b64u_decode(header["apu"]) if "apu" in header else b""
            apv = b64u_decode(header["apv"]) if "apv" in header else b""
            iv, ciphertext, tag = b64u_decode(iv_text), b64u_decode(ciphertext_text), b64u_decode(tag_text)
        except JoseError as exc:
            raise JweError("the JWE has a member that is not base64url") from exc
        if encrypted_key:
            raise JweError("with ECDH-ES the JWE encrypted key must be empty")
        if len(iv) != IV_BYTES or len(tag) != TAG_BYTES:
            raise JweError("the JWE iv must be 12 bytes and its tag 16")
        cek = concat_kdf(key.exchange(ec.ECDH(), epk), enc, apu, apv)
        try:
            return AESGCM(cek).decrypt(iv, ciphertext + tag, protected.encode("ascii"))
        except InvalidTag as exc:
            raise JweError("the JWE does not decrypt with the key it names") from exc
