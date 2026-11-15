"""Test-wallet artefacts: DPoP proofs, key proofs and key attestations."""

from __future__ import annotations

import base64
import datetime as dt
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .jose import JSON, EcKey, b64u, jws, jws_hs256, sha256_b64u


def dpop_proof(
    key: EcKey,
    method: str,
    url: str,
    *,
    access_token: str | None = None,
    nonce: str | None = None,
    iat: int | None = None,
    typ: str = "dpop+jwt",
    alg: str = "ES256",
    header_jwk: JSON | None = None,
    signing_key: EcKey | None = None,
    hs256_secret: bytes | None = None,
    drop: tuple[str, ...] = (),
) -> str:
    """Build a DPoP proof (RFC 9449 §4.2). Keyword overrides exist to build broken proofs."""
    header: JSON = {"typ": typ, "alg": alg, "jwk": header_jwk or key.public_jwk()}
    payload: JSON = {
        "jti": str(uuid.uuid4()),
        "htm": method,
        "htu": url.split("?")[0].split("#")[0],
        "iat": int(time.time()) if iat is None else iat,
    }
    if access_token is not None:
        payload["ath"] = sha256_b64u(access_token)
    if nonce is not None:
        payload["nonce"] = nonce
    for claim in drop:
        payload.pop(claim, None)
    if hs256_secret is not None:
        return jws_hs256(header, payload, hs256_secret)
    return jws(header, payload, signing_key or key)


def key_proof(
    key: EcKey,
    audience: str,
    *,
    nonce: str | None,
    iat: int | None = None,
    typ: str = "openid4vci-proof+jwt",
    alg: str = "ES256",
    header_jwk: JSON | None = None,
    signing_key: EcKey | None = None,
    hs256_secret: bytes | None = None,
    key_attestation: str | None = None,
) -> str:
    """Build a `jwt` key proof (OpenID4VCI 1.0 App. F.1). Anonymous pre-auth, so no `iss`."""
    header: JSON = {"typ": typ, "alg": alg, "jwk": header_jwk or key.public_jwk()}
    if key_attestation is not None:
        header["key_attestation"] = key_attestation
    payload: JSON = {"aud": audience, "iat": int(time.time()) if iat is None else iat}
    if nonce is not None:
        payload["nonce"] = nonce
    if hs256_secret is not None:
        return jws_hs256(header, payload, hs256_secret)
    return jws(header, payload, signing_key or key)


@dataclass
class AttestationIssuer:
    """A wallet-provider CA the issuer under test is configured to trust (optional)."""

    leaf_key: EcKey
    leaf_der_b64: str
    # The status list entry (URI, index) its key attestations name; a placeholder no issuer can resolve without one.
    status: tuple[str, int] | None = None

    @classmethod
    def from_ca_files(cls, ca_cert_path: Path, ca_key_path: Path) -> AttestationIssuer:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
            raise ValueError("key-attestation CA key must be an EC key")
        return cls.under(ca_cert, ca_key)

    @classmethod
    def untrusted(cls) -> AttestationIssuer:
        """A wallet-provider CA no issuer was configured for, made for the run."""
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eudi-probe untrusted wallet provider")])
        now = dt.datetime.now(dt.UTC)
        ca = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cls.under(ca, key)

    @classmethod
    def under(cls, ca_cert: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey) -> AttestationIssuer:
        leaf_key = EcKey.generate()
        now = dt.datetime.now(dt.UTC)
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eudi-probe key attestation")]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        return cls(leaf_key, base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode())

    def key_attestation(
        self,
        attested: list[EcKey],
        *,
        nonce: str | None,
        key_storage: list[str] | None = None,
        user_authentication: list[str] | None = None,
        status_period: int | None = 30 * 86_400,
    ) -> str:
        """Key attestation JWT (OpenID4VCI 1.0 App. D.1); `exp` is set since it is used with jwt proofs."""
        now = int(time.time())
        payload: dict[str, Any] = {
            "iat": now,
            "exp": now + 3600,
            "attested_keys": [k.public_jwk() for k in attested],
            "key_storage": key_storage or ["iso_18045_high"],
            "user_authentication": user_authentication or ["iso_18045_high"],
        }
        if nonce is not None:
            payload["nonce"] = nonce
        uri, index = self.status or ("https://wallet-provider.invalid/status/1", 0)
        if status_period is not None:
            # TS3: the end of the WSCD revocation maintenance period, which PID providers cap validity at.
            payload["key_storage_status"] = {
                "status": {"status_list": {"idx": index, "uri": uri}},
                "exp": now + status_period,
            }
        header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [self.leaf_der_b64]}
        return jws(header, payload, self.leaf_key)


def fresh_secret() -> bytes:
    return uuid.uuid4().bytes + uuid.uuid4().bytes


__all__ = ["AttestationIssuer", "b64u", "dpop_proof", "fresh_secret", "key_proof"]
