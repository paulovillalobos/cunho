"""A wallet provider the issuer under test is configured to trust (fixture mode): it attests wallet instances with
wallet attestations, the OAuth client attestation of HAIP §4.4.1 (draft-ietf-oauth-attestation-based-client-auth),
and each instance proves possession of its key.

The CA is the operator's test wallet-provider CA, given as files. The probe makes a short-lived signer under it for
the run, so the CA key signs one certificate and nothing else. `untrusted()` makes a CA of the same shape that the
issuer has never seen, for the negative checks.
"""

from __future__ import annotations

import base64
import datetime as dt
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .jose import JSON, EcKey, jws

WIA_TYP = "oauth-client-attestation+jwt"
POP_TYP = "oauth-client-attestation-pop+jwt"
ATTESTATION_HEADER = "OAuth-Client-Attestation"
POP_HEADER = "OAuth-Client-Attestation-PoP"


@dataclass
class WalletProvider:
    """A signer of wallet attestations and the chain it sends in x5c, the CA itself left out. `status` is the status
    list entry (URI, index) its attestations name; without one they name a placeholder no issuer can resolve, so a
    deployment that checks wallet attestation status needs one the provider publishes."""

    signer: EcKey
    x5c: list[str]
    status: tuple[str, int] | None = None

    @property
    def policies(self) -> tuple[str, ...]:
        """The certificate policies its signer asserts, which an issuer may require (cunho's wia_signer_policy_oids)."""
        leaf = x509.load_der_x509_certificate(base64.b64decode(self.x5c[0]))
        try:
            held = leaf.extensions.get_extension_for_class(x509.CertificatePolicies).value
        except x509.ExtensionNotFound:
            return ()
        return tuple(p.policy_identifier.dotted_string for p in held)

    @classmethod
    def from_ca_files(cls, cert_path: Path, key_path: Path, policies: tuple[str, ...] = ()) -> WalletProvider:
        ca = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("the wallet-provider CA key must be an EC key")
        return cls.under(ca, key, policies)

    @classmethod
    def from_signer_files(cls, chain_path: Path, key_path: Path) -> WalletProvider:
        """A signer the wallet provider issued for testing: its chain, leaf first and the CA left out, and its key."""
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("the wallet attestation signer key must be a P-256 key: the probe signs with ES256")
        chain = x509.load_pem_x509_certificates(chain_path.read_bytes())
        x5c = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in chain]
        return cls(EcKey(key), x5c)

    @classmethod
    def untrusted(cls, policies: tuple[str, ...] = ()) -> WalletProvider:
        """A provider no issuer was configured for: a fresh self-signed CA with the same kind of signer, asserting
        `policies` (those of the trusted fixture, so only the trust in the CA differs)."""
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
        return cls.under(ca, key, policies)

    @classmethod
    def under(
        cls, ca: x509.Certificate, ca_key: ec.EllipticCurvePrivateKey, policies: tuple[str, ...] = ()
    ) -> WalletProvider:
        signer = EcKey.generate()
        now = dt.datetime.now(dt.UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eudi-probe wallet attestation")]))
            .issuer_name(ca.subject)
            .public_key(signer.private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if policies:
            held = [x509.PolicyInformation(x509.ObjectIdentifier(oid), None) for oid in policies]
            builder = builder.add_extension(x509.CertificatePolicies(held), critical=False)
        leaf = builder.sign(ca_key, hashes.SHA256())
        return cls(signer, [base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()])

    def instance(self, client_id: str) -> Instance:
        return Instance(self, client_id)


@dataclass
class Instance:
    """One wallet instance of a wallet solution (`client_id` is the attestation's sub, the same for every instance),
    with its own key in the attestation's cnf."""

    provider: WalletProvider
    client_id: str
    key: EcKey = field(default_factory=EcKey.generate)
    status_period: int = 60 * 86_400

    def attestation(self, *, signer: EcKey | None = None, header: JSON | None = None, **claims: Any) -> str:
        """The wallet attestation (TS3 §2.3.1). A claim given as `...` is left out."""
        now = int(time.time())
        uri, index = self.provider.status or ("https://wallet-provider.eudi-probe.invalid/status/1", 0)
        payload: JSON = {
            "iss": "https://wallet-provider.eudi-probe.invalid",
            "sub": self.client_id,
            "iat": now,
            "exp": now + 3600,
            "cnf": {"jwk": self.key.public_jwk()},
            "wallet_name": "eudi-probe",
            "wallet_version": "1",
            "client_status": {
                "status": {"status_list": {"idx": index, "uri": uri}},
                "exp": now + self.status_period,
            },
        }
        payload.update(claims)
        sent = header or {"typ": WIA_TYP, "alg": "ES256", "x5c": self.provider.x5c}
        return jws(sent, {k: v for k, v in payload.items() if v is not ...}, signer or self.provider.signer)

    def pop(self, audience: str, *, signer: EcKey | None = None, **claims: Any) -> str:
        """The proof of possession of the attestation's key, for `audience` (the authorization server)."""
        payload: JSON = {"iss": self.client_id, "aud": audience, "jti": str(uuid.uuid4()), "iat": int(time.time())}
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not ...}
        return jws({"typ": POP_TYP, "alg": "ES256"}, payload, signer or self.key)

    def headers(self, audience: str, *, attestation: str | None = None, pop: str | None = None) -> dict[str, str]:
        return {
            ATTESTATION_HEADER: attestation or self.attestation(),
            POP_HEADER: pop or self.pop(audience),
        }
