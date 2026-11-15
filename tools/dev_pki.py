"""Create throwaway keys and certificates for a local development run. Never use them in production.

Usage: python tools/dev_pki.py OUT_DIR [HOST]
HOST, localhost by default, is the issuer host the credential signer names (cunho refuses a signer that does not).
Writes: signing.key/.pem (credential signer + root), status.key/.pem (status-list signer + root),
wallet-providers.pem + wallet-provider.key (a test wallet-provider CA for key attestations),
wallet-providers.crl (that CA's empty CRL, valid for 90 days), iaca.pem, mdoc-signing.key/.pem and iaca.crl (an mdoc
document signer under an IACA, in the certificate profiles of ISO/IEC 18013-5 Annex B, and the IACA's empty CRL),
encryption.key (the key encrypted credential requests are made to),
tls.key/.pem (a self-signed localhost TLS certificate) and admin-token.
Also writes m3/, the test PKI of the authorization code flow (tests/engine/pki.py), valid for 90 days: a wallet
provider root, intermediate, WIA and KA signers (keys included, for a test wallet) and their CRLs, a
trusted list signer, and an access certificate for signed metadata; all-wallet-providers.pem and .crl, both
wallet providers together; test-persons.json, the persons of the built-in test login; and a stand-in registration
certificate and registrar dataset.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


def _cert(
    cn: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None,
    ca: bool,
    san: list[str] | None = None,
    purpose: str | None = None,
    *,
    contact: str | None = None,
    crl: str | None = None,
) -> x509.Certificate:
    """A certificate in the shape ISO/IEC 18013-5 Annex B gives an IACA (Table B.1), a document signer (B.3) and a
    status list signer (B.9), which the other signers take too: countryName, key identifiers, a critical key usage
    (keyCertSign and cRLSign for a CA, digitalSignature for the rest), basicConstraints only on a CA (critical,
    path length 0), and, when given, the issuer's contact as issuerAltName and a CRL distribution point."""
    now = dt.datetime.now(dt.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    signer = issuer[1] if issuer else key
    usage = x509.KeyUsage(
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
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer[0].subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(usage, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if purpose:
        builder = builder.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(purpose)]), critical=True)
    if contact:
        builder = builder.add_extension(
            x509.IssuerAlternativeName([x509.UniformResourceIdentifier(contact)]), critical=False
        )
    if crl:
        point = x509.DistributionPoint([x509.UniformResourceIdentifier(crl)], None, None, None)
        builder = builder.add_extension(x509.CRLDistributionPoints([point]), critical=False)
    return builder.sign(signer, hashes.SHA256())


def _owner_only(path: Path, data: bytes) -> None:
    """Write a file only its owner can read from the moment it exists. Written first and closed afterwards, a key
    was readable by every user of the machine in between (the security review). A file an earlier run left goes."""
    path.unlink(missing_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def _write(path: Path, *items: x509.Certificate | ec.EllipticCurvePrivateKey) -> None:
    data = b""
    for item in items:
        if isinstance(item, x509.Certificate):
            data += item.public_bytes(serialization.Encoding.PEM)
        else:
            data += item.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
    _owner_only(path, data)


def main(out: Path, host: str = "localhost") -> None:
    out.mkdir(parents=True, exist_ok=True)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert("cunho dev root", root_key, None, True)
    _write(out / "issuer-root.pem", root)  # CUNHO_SIGNING_TRUST_ANCHORS: never sent in x5c
    for name in ("signing", "status"):
        key = ec.generate_private_key(ec.SECP256R1())
        _write(out / f"{name}.key", key)
        # The credential signer names the issuer host, so verifiers can match iss (SD-JWT VC §3.5).
        _write(out / f"{name}.pem", _cert(f"cunho dev {name}", key, (root, root_key), False, [host]), root)
    # mdoc (M4): a document signer with the purpose id-mdl-kp-mdlDS under an IACA of its own, which x5chain leaves
    # out (CUNHO_MDOC_TRUST_ANCHORS), and the key encrypted credential requests are made to.
    iaca_key, ds_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    contact = f"https://{host}/"
    iaca = _cert("cunho dev IACA", iaca_key, None, True, contact=contact)
    _write(out / "iaca.pem", iaca)
    _write(out / "mdoc-signing.key", ds_key)
    ds = _cert(
        "cunho dev document signer", ds_key, (iaca, iaca_key), False, None, MDOC_DS, contact=contact, crl=CRL_URL
    )
    _write(out / "mdoc-signing.pem", ds, iaca)
    now = dt.datetime.now(dt.UTC)
    iaca_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(iaca.subject)
        .last_update(now - dt.timedelta(minutes=5))
        .next_update(now + dt.timedelta(days=30))  # within the 90 days the suite allows a document signer's CRL
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(iaca_key.public_key()), critical=False)
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(iaca_key, hashes.SHA256())
    )
    (out / "iaca.crl").write_bytes(iaca_crl.public_bytes(serialization.Encoding.DER))
    _write(out / "encryption.key", ec.generate_private_key(ec.SECP256R1()))
    wp_key = ec.generate_private_key(ec.SECP256R1())
    wp = _cert("cunho dev wallet provider", wp_key, None, True)
    _write(out / "wallet-providers.pem", wp)
    _write(out / "wallet-provider.key", wp_key)
    now = dt.datetime.now(dt.UTC)
    empty = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(wp.subject)
        .last_update(now - dt.timedelta(minutes=5))
        .next_update(now + dt.timedelta(days=90))
        .sign(wp_key, hashes.SHA256())
    )
    (out / "wallet-providers.crl").write_bytes(empty.public_bytes(serialization.Encoding.PEM))
    tls_key = ec.generate_private_key(ec.SECP256R1())
    _write(out / "tls.key", tls_key)
    _write(out / "tls.pem", _cert("localhost", tls_key, None, False, ["localhost"]))
    _owner_only(out / "admin-token", secrets.token_urlsafe(32).encode())
    sys.path.insert(0, str(ROOT))
    from tests.engine.pki import TestPki  # noqa: PLC0415 - the same builder the tests use

    TestPki.create(now, days=90).write(out / "m3")
    # Both wallet providers, for a run with the code flow: the one above signs key attestations, m3/'s wallet
    # attestations. And the persons the built-in test login offers.
    for name in ("wallet-providers.pem", "wallet-providers.crl"):
        (out / f"all-{name}").write_bytes((out / name).read_bytes() + (out / "m3" / name).read_bytes())
    (out / "test-persons.json").write_text(json.dumps({"ana": TEST_PERSON}, indent=2))
    # Stand-ins for what a registrar issues (ETSI TS 119 472-3 §4.2.3), so the issuer metadata carries issuer_info.
    (out / "registration-certificate.jwt").write_text(REGISTRATION_CERTIFICATE)
    (out / "registrar.json").write_text(json.dumps(REGISTRAR_DATASET, indent=2))
    print(f"development PKI written to {out}")


MDOC_DS = "1.0.18013.5.1.2"  # id-mdl-kp-mdlDS, ISO/IEC 18013-5 Annex B
# Where the document signer says its IACA's CRL is: tools/oidf/run.py serves iaca.crl there, on the suite's network.
# A deployment that publishes iaca.crl elsewhere names that place in DEV_PKI_CRL_URL (tools/deploy_init.py).
CRL_URL = os.environ.get("DEV_PKI_CRL_URL") or "http://crl.test:8080/iaca.crl"

# Not a real registration certificate: an unsigned stand-in of its shape, for development only.
REGISTRATION_CERTIFICATE = "eyJ0eXAiOiJyYy1lYWErand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJsb2NhbGhvc3QifQ.ZGV2ZWxvcG1lbnQ"
REGISTRAR_DATASET = {
    "identifier": "XX-DEV-0000",
    "srvDescription": [{"lang": "en", "content": "cunho development run"}],
    "registryURI": "https://registrar.example.test/",
    "providesAttestations": [{"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}}],
}

# A fictitious person for the built-in test login, as a PID login service would report one.
TEST_PERSON = {
    "family_name": "Silva",
    "given_name": "Ana Maria",
    "birthdate": "1990-05-17",
    "place_of_birth": {"locality": "Porto", "country": "PT"},
    "nationalities": ["PT"],
    "address": {"locality": "Braga", "country": "PT", "postal_code": "4700-001"},
    "issuing_authority": "Test Issuing Authority",
    "issuing_country": "PT",
    "issuing_jurisdiction": "PT-03",
    "date_of_expiry": "2031-01-01",
}


if __name__ == "__main__":
    main(Path(sys.argv[1]), *sys.argv[2:3])
