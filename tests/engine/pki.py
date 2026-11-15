"""A whole test PKI for the M3 trust code, built once per test session with `cryptography`.

- Wallet provider: root -> intermediate -> wallet instance attestation (WIA) signer, and a key attestation (KA)
  signer under the same intermediate, with the certificate policies production asks for (`ka_signer_policy_oids`).
  A second wallet provider has the same names and other keys, and nobody trusts it.
- Revocation: CRLs from each CA (empty, revoking, expired, with an unknown critical extension, a delta CRL), two
  OCSP delegates of the intermediate (id-kp-OCSPSigning, with and without ocsp-nocheck), a rogue delegate issued
  by the other wallet provider, and OCSP responses about the WIA signer: good, revoked, unknown, stale, for
  another certificate, unsigned, with a wrong nonce, from the rogue delegate and with a broken signature.
- Trusted list signer: a self-signed certificate with C=EU and O the scheme operator name, which plays the
  certificate the Commission publishes in the OJEU, and an impostor with the same names and another key.
- Access certificate: a test access certificate authority and the issuer's access certificate (signed metadata).
- Credential and status signers under an issuer root, as in M2.
- mdoc (M4): a document signer under an issuing authority certificate authority (IACA), with the document signer
  purpose of ISO/IEC 18013-5 Annex B (id-mdl-kp-mdlDS, critical) and the issuing country in both names.

Nothing here imports cunho, so `tools/dev_pki.py` builds the same set for local runs. `test_pki.py` checks that
every chain passes `validate_path` and that every broken variant fails for the reason it is built for.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

KA_POLICY = "1.3.6.1.4.1.99999.1.1"  # the test policy of key attestation signers (as in helpers.py)
WIA_POLICY = "1.3.6.1.4.1.99999.1.2"  # the test policy of wallet instance attestation signers (as in helpers.py)
ANY_POLICY = "2.5.29.32.0"
UNKNOWN_EXTENSION = x509.ObjectIdentifier("1.3.6.1.4.1.99999.9.1")
SCHEME_OPERATOR = "cunho test scheme operator"
ISSUER_HOST = "issuer.test"
MDOC_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")  # ISO/IEC 18013-5 Annex B.1.4, id-mdl-kp-mdlDS
MDOC_COUNTRY = "PT"
DAY = dt.timedelta(days=1)


@dataclass(frozen=True)
class Issued:
    """A certificate and its private key."""

    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def der_b64(self) -> str:
        """The form a certificate takes in an `x5c` header."""
        return base64.b64encode(self.cert.public_bytes(serialization.Encoding.DER)).decode()

    @property
    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )


def name(common_name: str, *, country: str | None = None, organization: str | None = None) -> x509.Name:
    attributes = []
    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def _usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


@dataclass(frozen=True)
class Builder:
    """Certificates and CRLs valid around `now`."""

    now: dt.datetime
    days: int = 3650

    def certificate(
        self,
        subject: x509.Name,
        issuer: Issued | None = None,
        *,
        ca: bool = False,
        path_length: int | None = None,
        policies: tuple[str, ...] = (),
        purposes: tuple[x509.ObjectIdentifier, ...] = (),
        san: tuple[str, ...] = (),
        extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    ) -> Issued:
        """A certificate for a new P-256 key, signed by `issuer`, or self-signed without one."""
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.cert.subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(self.now - 30 * DAY)
            .not_valid_after(self.now + self.days * DAY)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
            .add_extension(_usage(ca=ca), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        )
        if issuer:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False
            )
        if policies:
            held = [x509.PolicyInformation(x509.ObjectIdentifier(oid), None) for oid in policies]
            builder = builder.add_extension(x509.CertificatePolicies(held), critical=False)
        if purposes:
            builder = builder.add_extension(x509.ExtendedKeyUsage(list(purposes)), critical=False)
        if san:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical=critical)
        return Issued(builder.sign(issuer.key if issuer else key, hashes.SHA256()), key)

    def crl(
        self,
        issuer: Issued,
        revoked: tuple[x509.Certificate, ...] = (),
        *,
        number: int = 1,
        last_update: dt.datetime | None = None,
        next_update: dt.datetime | None = None,
        extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    ) -> x509.CertificateRevocationList:
        """A CRL from `issuer` listing `revoked`, current from a day ago for 30 days unless told otherwise."""
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer.cert.subject)
            .last_update(last_update or self.now - DAY)
            .next_update(next_update or self.now + 30 * DAY)
            .add_extension(x509.CRLNumber(number), critical=False)
        )
        for cert in revoked:
            entry = x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(self.now - DAY)
            builder = builder.add_revoked_certificate(entry.build())
        for extension, critical in extensions:
            builder = builder.add_extension(extension, critical=critical)
        return builder.sign(issuer.key, hashes.SHA256())


@dataclass(frozen=True)
class WalletProvider:
    root: Issued
    intermediate: Issued
    wia_signer: Issued
    ka_signer: Issued
    ocsp_delegate: Issued  # id-kp-OCSPSigning with ocsp-nocheck
    ocsp_delegate_checked: Issued  # id-kp-OCSPSigning without ocsp-nocheck: its own status needs checking

    @classmethod
    def create(cls, build: Builder, label: str) -> WalletProvider:
        root = build.certificate(name(f"{label} Root"), ca=True, path_length=1, policies=(ANY_POLICY,))
        intermediate = build.certificate(
            name(f"{label} Intermediate"), root, ca=True, path_length=0, policies=(ANY_POLICY,)
        )
        ocsp_purpose = (ExtendedKeyUsageOID.OCSP_SIGNING,)
        return cls(
            root=root,
            intermediate=intermediate,
            wia_signer=build.certificate(name(f"{label} WIA Signer"), intermediate, policies=(WIA_POLICY,)),
            ka_signer=build.certificate(name(f"{label} KA Signer"), intermediate, policies=(KA_POLICY,)),
            ocsp_delegate=build.certificate(
                name(f"{label} OCSP Responder"),
                intermediate,
                purposes=ocsp_purpose,
                extensions=((x509.OCSPNoCheck(), False),),
            ),
            ocsp_delegate_checked=build.certificate(
                name(f"{label} OCSP Responder (checked)"), intermediate, purposes=ocsp_purpose
            ),
        )

    def wia_x5c(self) -> list[str]:
        """The WIA signer and the intermediate, as a wallet sends them (the anchor is left out)."""
        return [self.wia_signer.der_b64, self.intermediate.der_b64]

    def ka_x5c(self) -> list[str]:
        return [self.ka_signer.der_b64, self.intermediate.der_b64]


@dataclass(frozen=True)
class OcspCase:
    """An OCSP exchange about one certificate. `outcome` is what a correct client concludes (RFC 6960 §3.2):
    good, revoked or unknown for a response it may accept, otherwise the check that refuses it."""

    request: bytes
    response: bytes
    nonce: bytes
    outcome: str


OUTCOMES = ("good", "revoked", "unknown", "stale", "certid", "unsigned", "nonce", "responder", "signature")


@dataclass
class TestPki:
    __test__ = False  # a fixture, not a test class

    now: dt.datetime
    wallet_provider: WalletProvider
    untrusted: WalletProvider  # same names, other keys
    crls: dict[str, x509.CertificateRevocationList]
    ocsp: dict[str, OcspCase]
    lote_signer: Issued
    lote_impostor: Issued
    access_ca: Issued
    access_cert: Issued
    issuer_root: Issued
    credential_signer: Issued
    status_signer: Issued
    iaca: Issued
    mdoc_signer: Issued
    files: dict[str, Path] = field(default_factory=dict)

    @classmethod
    def create(cls, now: dt.datetime, days: int = 3650) -> TestPki:
        build = Builder(now, days)
        wp = WalletProvider.create(build, "Test Wallet Provider")
        untrusted = WalletProvider.create(build, "Test Wallet Provider")
        unknown = ((x509.UnrecognizedExtension(UNKNOWN_EXTENSION, b"\x05\x00"), True),)
        crls = {
            "root": build.crl(wp.root),
            "intermediate": build.crl(wp.intermediate),
            "root_revoking": build.crl(wp.root, (wp.intermediate.cert,), number=2),
            "intermediate_revoking": build.crl(wp.intermediate, (wp.wia_signer.cert, wp.ka_signer.cert), number=2),
            "intermediate_expired": build.crl(wp.intermediate, last_update=now - 60 * DAY, next_update=now - 30 * DAY),
            "intermediate_unknown_critical": build.crl(wp.intermediate, number=3, extensions=unknown),
            "intermediate_delta": build.crl(wp.intermediate, number=4, extensions=((x509.DeltaCRLIndicator(1), True),)),
            "untrusted_intermediate": build.crl(untrusted.intermediate),
        }
        lote_name = name("Test LoTE Signer", country="EU", organization=SCHEME_OPERATOR)
        access_ca = build.certificate(name("Test Access Certificate Authority"), ca=True, path_length=0)
        issuer_root = build.certificate(name("Test Issuer Root"), ca=True, path_length=0)
        iaca = build.certificate(name("Test IACA", country=MDOC_COUNTRY), ca=True, path_length=0)
        return cls(
            now=now,
            wallet_provider=wp,
            untrusted=untrusted,
            crls=crls,
            ocsp=_ocsp_cases(wp, untrusted, now),
            lote_signer=build.certificate(lote_name),
            lote_impostor=build.certificate(lote_name),
            access_ca=access_ca,
            access_cert=build.certificate(name("Test Issuer Access Certificate"), access_ca, san=(ISSUER_HOST,)),
            issuer_root=issuer_root,
            credential_signer=build.certificate(name("Test Issuer Signer"), issuer_root, san=(ISSUER_HOST,)),
            status_signer=build.certificate(name("Test Status Signer"), issuer_root),
            iaca=iaca,
            mdoc_signer=build.certificate(
                name("Test Document Signer", country=MDOC_COUNTRY),
                iaca,
                extensions=((x509.ExtendedKeyUsage([MDOC_DS]), True),),
            ),
        )

    def write(self, root: Path) -> dict[str, Path]:
        """The files a deployment points at, under `root`. Keys are written owner-only."""
        root.mkdir(parents=True, exist_ok=True)
        wp = self.wallet_provider
        pem_crls = {k: v.public_bytes(serialization.Encoding.PEM) for k, v in self.crls.items()}
        contents = {
            "wallet-providers.pem": wp.root.pem,
            "wallet-providers.crl": pem_crls["root"] + pem_crls["intermediate"],
            "wallet-providers-revoking.crl": pem_crls["root"] + pem_crls["intermediate_revoking"],
            "untrusted-wallet-provider.pem": self.untrusted.root.pem,
            "wia-signer.pem": wp.wia_signer.pem + wp.intermediate.pem,
            "wia-signer.key": wp.wia_signer.key_pem,
            "ka-signer.pem": wp.ka_signer.pem + wp.intermediate.pem,
            "ka-signer.key": wp.ka_signer.key_pem,
            "lote-signer.pem": self.lote_signer.pem,
            "lote-signer.key": self.lote_signer.key_pem,
            "access.pem": self.access_cert.pem + self.access_ca.pem,
            "access-ca.pem": self.access_ca.pem,
            "access.key": self.access_cert.key_pem,
            "issuer-root.pem": self.issuer_root.pem,
            "signing.pem": self.credential_signer.pem + self.issuer_root.pem,
            "signing.key": self.credential_signer.key_pem,
            "status.pem": self.status_signer.pem + self.issuer_root.pem,
            "status.key": self.status_signer.key_pem,
            "iaca.pem": self.iaca.pem,
            "mdoc-signing.pem": self.mdoc_signer.pem + self.iaca.pem,
            "mdoc-signing.key": self.mdoc_signer.key_pem,
        }
        for file, data in contents.items():
            path = root / file
            if file.endswith(".key"):
                # Owner-only from the moment it exists, not written and then closed (the security review).
                path.unlink(missing_ok=True)
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
                    handle.write(data)
            else:
                path.write_bytes(data)
            self.files[file] = path
        return dict(self.files)


def _ocsp_cases(wp: WalletProvider, untrusted: WalletProvider, now: dt.datetime) -> dict[str, OcspCase]:
    subject, issuer = wp.wia_signer.cert, wp.intermediate.cert
    nonce = os.urandom(16)
    request = (
        ocsp.OCSPRequestBuilder()
        .add_certificate(subject, issuer, hashes.SHA256())
        .add_extension(x509.OCSPNonce(nonce), critical=False)
        .build()
        .public_bytes(serialization.Encoding.DER)
    )

    def response(
        signer: Issued,
        *,
        status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
        about: x509.Certificate = subject,
        this_update: dt.datetime = now - dt.timedelta(minutes=5),
        next_update: dt.datetime = now + DAY,
        reply_nonce: bytes = nonce,
    ) -> bytes:
        revoked = status == ocsp.OCSPCertStatus.REVOKED
        builder = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                about,
                issuer,
                hashes.SHA256(),
                status,
                this_update,
                next_update,
                now - DAY if revoked else None,
                x509.ReasonFlags.key_compromise if revoked else None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, signer.cert)
            .add_extension(x509.OCSPNonce(reply_nonce), critical=False)
        )
        if signer.cert != issuer:
            builder = builder.certificates([signer.cert])
        return builder.sign(signer.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def case(data: bytes, outcome: str) -> OcspCase:
        return OcspCase(request, data, nonce, outcome)

    good = response(wp.ocsp_delegate)
    return {
        "good": case(good, "good"),
        "good_from_ca": case(response(wp.intermediate), "good"),
        "good_from_checked_delegate": case(response(wp.ocsp_delegate_checked), "good"),
        "revoked": case(response(wp.ocsp_delegate, status=ocsp.OCSPCertStatus.REVOKED), "revoked"),
        "unknown": case(response(wp.ocsp_delegate, status=ocsp.OCSPCertStatus.UNKNOWN), "unknown"),
        "stale": case(response(wp.ocsp_delegate, this_update=now - 10 * DAY, next_update=now - 3 * DAY), "stale"),
        "wrong_certid": case(response(wp.ocsp_delegate, about=wp.ka_signer.cert), "certid"),
        "unsigned": case(
            ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(
                serialization.Encoding.DER
            ),
            "unsigned",
        ),
        "wrong_nonce": case(response(wp.ocsp_delegate, reply_nonce=os.urandom(16)), "nonce"),
        "rogue_delegate": case(response(untrusted.ocsp_delegate), "responder"),
        "bad_signature": case(_break_signature(good), "signature"),
    }


def _break_signature(der: bytes) -> bytes:
    """The same response with one byte inside its signature value changed."""
    signature = ocsp.load_der_ocsp_response(der).signature
    at = der.index(signature) + len(signature) // 2
    return der[:at] + bytes([der[at] ^ 0x01]) + der[at + 1 :]
