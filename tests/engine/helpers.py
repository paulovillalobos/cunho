"""Test PKI, a controllable clock and a scripted wallet for the engine tests."""

from __future__ import annotations

import base64
import datetime as dt
import json
import random
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from cunho.errors import IssuerError, observers
from cunho.jose import b64u, parse_jws, thumbprint
from cunho.keyring import Keyring
from cunho.service import ClockWatch, HostClock, Issuer
from eudi_probe.jose import EcKey, jws, jws_hs256
from eudi_probe.wallet import dpop_proof, key_proof

try:
    from hypothesis import HealthCheck

    # Hypothesis times its own data generation and fails a test whose examples were merely slow to draw, which
    # happened once under the parallel load of a mutation run (review 5, N5-L9). The examples are unchanged.
    SLOW_IS_FINE: list[Any] = [HealthCheck.too_slow]
except ImportError:  # the tests that need Hypothesis skip without it
    SLOW_IS_FINE = []

ISSUER = "https://issuer.test"
ADMIN_TOKEN = "t" * 40
PID_CONFIG = "eu.europa.ec.eudi.pid_vc_sd_jwt"
PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
KA_POLICY = "1.3.6.1.4.1.99999.1.1"  # a test policy OID marking key attestation signers
WIA_POLICY = "1.3.6.1.4.1.99999.1.2"  # and one marking wallet attestation signers (tests/engine/pki.py)
START = 1_793_750_400  # 2026-11-04T00:00:00Z
MDOC_DS = "1.0.18013.5.1.2"  # id-mdl-kp-mdlDS, ISO/IEC 18013-5 Annex B
# The registration certificate as a registrar would issue it (a compact JWT; its content is not read by cunho) and
# the registrar dataset of TS 119 472-3 §4.2.3.
REGISTRATION_CERTIFICATE = "eyJ0eXAiOiJyYy1lYWErand0IiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJpc3N1ZXIudGVzdCJ9.c2lnbmF0dXJl"
REGISTRAR_DATASET: dict[str, Any] = {
    "identifier": "PT-VAT-500000000",
    "srvDescription": [{"lang": "en", "content": "Test PID issuance"}],
    "registryURI": "https://registrar.example.test/",
    "providesAttestations": [{"format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}}],
}


class Clock:
    def __init__(self, now: float = START + 1234) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Seeded:
    """The CSPRNG's randbelow from a seeded generator, for `cunho.status` in tests of how bits come due: the
    decoys and the jitter of a revocation are random, and a test that waits a little would otherwise see a fair
    coincidence now and then (about one draw in 64 for the decoy spread, one in 100 for an early revocation)."""

    def __init__(self, seed: int) -> None:
        self._random = random.Random(seed)

    def randbelow(self, n: int) -> int:
        return self._random.randrange(n)


class Host:
    """The host's own clock and boot behind a test clock: `advance` is time that really passes, while moving
    `clock.now` alone is a step of the wall clock."""

    def __init__(self, clock: Clock) -> None:
        self.clock, self.elapsed, self.boot, self.synced = clock, 5000.0, "boot-1", cast(bool | None, None)
        self.true = Clock(clock.now)  # the time that really passes, as a wallet with a right clock reads it
        self.keyring = Keyring.ephemeral()  # MACs the base; an issuer built through `issuer` lends its own

    def advance(self, seconds: float) -> None:
        self.clock.now += seconds
        self.true.now += seconds
        self.elapsed += seconds

    def watch(self, store: Any, interval: int = 3600, floor: Any = None) -> ClockWatch:
        host = HostClock(elapsed=lambda: self.elapsed, boot=lambda: self.boot, synced=lambda: self.synced)
        return ClockWatch(store, self.clock, interval, host=host, keyring=self.keyring, floor=floor)

    def issuer(self, make_issuer: Callable[..., Issuer], store: Any, **overrides: Any) -> Issuer:
        issuer = make_issuer(store=store, **overrides)
        self.keyring = issuer.keyring
        watch = self.watch(issuer.store, issuer.settings.maintenance_interval, issuer.audit.clock_floor)
        issuer.use_clock_watch(watch)
        return issuer


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


PROVIDER = "cunho test provider"
PROVIDER_ID = "VATPT-500000000"


def provider_name(cn: str) -> x509.Name:
    """The subject of a qualified provider's certificate: its Member State, name and registration number (eIDAS
    Annex V(b); ETSI EN 319 412-1 §5.1.4)."""
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, PROVIDER),
            x509.NameAttribute(x509.ObjectIdentifier("2.5.4.97"), PROVIDER_ID),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def certificate(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    *,
    ca: bool = False,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    san: list[str] | None = None,
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    path_length: int | None = None,
    name: x509.Name | None = None,
    annex_b: bool = False,
) -> x509.Certificate:
    """A certificate for `key`, by `issuer` or self-signed; `name`, when given, is the whole subject name. `annex_b`
    gives it the form ISO/IEC 18013-5 Annex B asks of mdoc signing certificates: key identifiers, a critical key
    usage (keyCertSign and cRLSign for a CA, digitalSignature otherwise), and basicConstraints on a CA alone."""
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    subject_name = name or _name(subject)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer[0].subject if issuer else subject_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(days=30))
        .not_valid_after(not_after or now + dt.timedelta(days=3650))
    )
    if ca or not annex_b:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True
        )
    if annex_b:
        signer = issuer[1] if issuer else key
        builder = (
            builder.add_extension(ANNEX_B_CA_USAGE if ca else ANNEX_B_SIGNING_USAGE, critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
        )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical=critical)
    return builder.sign(issuer[1] if issuer else key, hashes.SHA256())


def _usage(signing: bool) -> x509.KeyUsage:
    return x509.KeyUsage(signing, False, False, False, False, not signing, not signing, False, False)


ANNEX_B_SIGNING_USAGE, ANNEX_B_CA_USAGE = _usage(True), _usage(False)
# What Annex B asks of an IACA and a document signer beyond annex_b: the issuer's contact, and where the document
# signer's revocation is published.
ANNEX_B_CONTACT = x509.IssuerAlternativeName([x509.UniformResourceIdentifier("https://issuer.test/")])
ANNEX_B_CRL = x509.CRLDistributionPoints(
    [x509.DistributionPoint([x509.UniformResourceIdentifier("https://issuer.test/iaca.crl")], None, None, None)]
)


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def crl(
    issuer: x509.Certificate,
    key: ec.EllipticCurvePrivateKey,
    revoked: list[x509.Certificate] | None = None,
    *,
    last_update: dt.datetime | None = None,
    next_update: dt.datetime | None = None,
) -> bytes:
    """A complete CRL from `issuer`, in PEM, listing `revoked`."""
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(last_update or now - dt.timedelta(days=1))
        .next_update(next_update or now + dt.timedelta(days=3650))
    )
    for cert in revoked or []:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(now).build()
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def der_b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@dataclass
class Pki:
    root: Path
    issuer_ca: x509.Certificate
    issuer_leaf: x509.Certificate
    wallet_ca: x509.Certificate
    wallet_ca_key: ec.EllipticCurvePrivateKey
    ka_leaf: x509.Certificate
    ka_key: EcKey

    @classmethod
    def create(cls, root: Path) -> Pki:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = certificate("Test Issuer Root", ca_key, ca=True)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf = certificate(
            "Test Issuer Signer", leaf_key, (ca, ca_key), san=["issuer.test"], name=provider_name("Test Issuer Signer")
        )
        status_key = ec.generate_private_key(ec.SECP256R1())
        status_leaf = certificate("Test Status Signer", status_key, (ca, ca_key), annex_b=True)
        wp_key = ec.generate_private_key(ec.SECP256R1())
        wp = certificate("Test Wallet Provider Root", wp_key, ca=True)
        ka = EcKey.generate()
        policy = x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(KA_POLICY), None)])
        ka_leaf = certificate("Test Key Attestation Signer", ka.private, (wp, wp_key), extensions=[(policy, False)])
        (root / "signing.key").write_bytes(key_pem(leaf_key))
        (root / "signing.pem").write_bytes(pem(leaf) + pem(ca))
        (root / "status.key").write_bytes(key_pem(status_key))
        (root / "status.pem").write_bytes(pem(status_leaf) + pem(ca))
        (root / "wallet-providers.pem").write_bytes(pem(wp))
        (root / "wallet-providers.crl").write_bytes(crl(wp, wp_key))
        (root / "issuer-root.pem").write_bytes(pem(ca))
        access_key = ec.generate_private_key(ec.SECP256R1())
        access = certificate("Test Issuer Access Certificate", access_key, (ca, ca_key), san=["issuer.test"])
        (root / "access.key").write_bytes(key_pem(access_key))
        (root / "access.pem").write_bytes(pem(access) + pem(ca))
        (root / "registration.jwt").write_text(REGISTRATION_CERTIFICATE)
        (root / "registrar.json").write_text(json.dumps(REGISTRAR_DATASET))
        lote_key = EcKey.generate()
        lote_signer = certificate(
            "Test LoTE Signer",
            lote_key.private,
            name=x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, SCHEME_OPERATOR),
                    x509.NameAttribute(NameOID.COMMON_NAME, "Test LoTE Signer"),
                ]
            ),
        )
        (root / "lote-signer.pem").write_bytes(pem(lote_signer))
        (root / "wallet-providers.lote").write_text(wallet_providers_list(lote_key, lote_signer, wp))
        typed_metadata(root / "metadata")
        # mdoc (M4): a document signer with the purpose id-mdl-kp-mdlDS under an IACA, and one without the purpose.
        iaca_key = ec.generate_private_key(ec.SECP256R1())
        iaca_name = x509.Name(
            [x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"), x509.NameAttribute(NameOID.COMMON_NAME, "Test IACA")]
        )
        iaca = certificate(
            "Test IACA",
            iaca_key,
            ca=True,
            path_length=0,
            name=iaca_name,
            annex_b=True,
            extensions=[(ANNEX_B_CONTACT, False)],
        )
        ds_key = ec.generate_private_key(ec.SECP256R1())
        purpose = x509.ExtendedKeyUsage([x509.ObjectIdentifier(MDOC_DS)])
        ds = certificate(
            "Test Document Signer",
            ds_key,
            (iaca, iaca_key),
            extensions=[(purpose, True), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False)],
            name=provider_name("Test Document Signer"),
            annex_b=True,
        )
        (root / "iaca.pem").write_bytes(pem(iaca))
        (root / "mdoc-signing.key").write_bytes(key_pem(ds_key))
        (root / "mdoc-signing.pem").write_bytes(pem(ds) + pem(iaca))
        plain_key = ec.generate_private_key(ec.SECP256R1())
        plain = certificate("Test Signer Without The mdoc Purpose", plain_key, (iaca, iaca_key))
        (root / "mdoc-plain.key").write_bytes(key_pem(plain_key))
        (root / "mdoc-plain.pem").write_bytes(pem(plain) + pem(iaca))
        tls_key = ec.generate_private_key(ec.SECP256R1())
        tls_purpose = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
        tls = certificate("Test TLS Server", tls_key, (iaca, iaca_key), extensions=[(tls_purpose, False)])
        (root / "mdoc-tls.key").write_bytes(key_pem(tls_key))
        (root / "mdoc-tls.pem").write_bytes(pem(tls) + pem(iaca))
        return cls(root, ca, leaf, wp, wp_key, ka_leaf, ka)


SCHEME_OPERATOR = "cunho test scheme operator"  # as in pki.py


def typed_metadata(target: Path) -> Path:
    """The shipped configurations with an SD-JWT VC Type Metadata document for each SD-JWT VC type, as production
    asks (ETSI TS 119 472-1 EAA-5.2.1.2-03)."""
    import shutil

    from cunho.settings import DEFAULT_METADATA_DIR

    shutil.copytree(DEFAULT_METADATA_DIR, target)
    vcts = set()
    for path in (target / "credentials_supported").glob("*.json"):
        for config in json.loads(path.read_text()).values():
            if config.get("format") == "dc+sd-jwt" and isinstance(config.get("vct"), str):
                vcts.add(config["vct"])
    (target / "type_metadata").mkdir()
    for n, vct in enumerate(sorted(vcts)):
        document = {"vct": vct, "name": f"Test type {n}", "description": "Type Metadata for the tests"}
        (target / "type_metadata" / f"type-{n}.json").write_text(json.dumps(document, indent=2))
    return target


def wallet_providers_list(
    key: EcKey,
    signer: x509.Certificate,
    *providers: x509.Certificate,
    sequence: int = 1,
    now: float = START,
    status: tuple[x509.Certificate, ...] | None = None,
) -> str:
    """The Commission's list of wallet providers (ETSI TS 119 602 Annex E) naming `providers` as the anchors of
    attestation signers and, unless `status` names others, of status list signers, issued a day before `now` and next
    updated thirty days after."""
    stamp = "%Y-%m-%dT%H:%M:%SZ"
    start = dt.datetime.fromtimestamp(now, dt.UTC)

    def service(kind: str) -> dict[str, Any]:
        named = status if kind == "Revocation" and status is not None else providers
        return {
            "ServiceInformation": {
                "ServiceName": [{"lang": "en", "value": "Test Wallet Solution"}],
                "ServiceTypeIdentifier": f"http://uri.etsi.org/19602/SvcType/WalletSolution/{kind}",
                "ServiceDigitalIdentity": {"X509Certificates": [{"val": der_b64(p)} for p in named]},
            }
        }

    payload = {
        "LoTE": {
            "ListAndSchemeInformation": {
                "LoTEVersionIdentifier": 1,
                "LoTESequenceNumber": sequence,
                "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
                "SchemeOperatorName": [{"lang": "en", "value": SCHEME_OPERATOR}],
                "SchemeTerritory": "EU",
                "ListIssueDateTime": (start - dt.timedelta(days=1)).strftime(stamp),
                "NextUpdate": (start + dt.timedelta(days=30)).strftime(stamp),
            },
            "TrustedEntitiesList": [
                {
                    "TrustedEntityInformation": {
                        "TEName": [{"lang": "en", "value": "Test Wallet Provider"}],
                        "TEAddress": {
                            "TEPostalAddress": [{"lang": "en", "StreetAddress": "Rua 1", "Country": "PT"}],
                            "TEElectronicAddress": [{"lang": "en", "uriValue": "mailto:wp@example.test"}],
                        },
                        "TEInformationURI": [{"lang": "en", "uriValue": "https://wp.example.test"}],
                    },
                    "TrustedEntityServices": [service("Issuance"), service("Revocation")],
                }
            ],
        }
    }
    return jws({"alg": "ES256", "x5c": [der_b64(signer)]}, payload, key)


def access_signer(pki: Pki) -> Any:
    """The test issuer's access certificate signer, which signs the issuer metadata."""
    from cunho.signer import FileSigner

    return FileSigner.from_files(pki.root / "access.key", pki.root / "access.pem", pki.root / "issuer-root.pem")


def mdoc_signer(pki: Pki) -> Any:
    """The test mdoc document signer, under the test IACA, which x5chain leaves out."""
    from cunho.signer import FileSigner

    return FileSigner.from_files(pki.root / "mdoc-signing.key", pki.root / "mdoc-signing.pem", pki.root / "iaca.pem")


def settings_kwargs(pki: Pki, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "issuer_url": ISSUER,
        "admin_token": ADMIN_TOKEN,
        "signing_key": pki.root / "signing.key",
        "signing_chain": pki.root / "signing.pem",
        "status_signing_key": pki.root / "status.key",
        "status_signing_chain": pki.root / "status.pem",
        "wallet_provider_anchors": pki.root / "wallet-providers.pem",
        "audit_retention_days": 3650,
        "signer_certificate_url": f"{ISSUER}/certs/signer.pem",
        "status_list_size": 4096,
        "rate_limit_per_minute": 100_000,
        # Revocations show at once in most tests; test_review3_fixes checks the spread on its own.
        "status_revocation_jitter": 0,
    }
    base.update(overrides)
    return base


def production_kwargs(pki: Pki, root: Path, **overrides: Any) -> dict[str, Any]:
    """Everything production mode asks for, apart from a signer (tests inject one)."""
    production: dict[str, Any] = {
        "production": True,
        "store_path": root / "s.db",
        "secret_key_file": root / "m.key",
        "audit_anchor_path": root / "audit.anchor",
        "signing_trust_anchors": pki.root / "issuer-root.pem",
        "ka_signer_policy_oids": (KA_POLICY,),
        "wallet_provider_crls": pki.root / "wallet-providers.crl",
        "audit_anchor_init": True,
        "login_url": "https://login.issuer.test/start",
        "wia_signer_policy_oids": (WIA_POLICY,),
        "lote_path": pki.root / "wallet-providers.lote",
        "lote_signer": pki.root / "lote-signer.pem",
        "fetch_hosts": ("wallet-provider.test",),
        "registration_certificate": pki.root / "registration.jwt",
        "registrar_dataset": pki.root / "registrar.json",
        "metadata_dir": pki.root / "metadata",
        # A PID provider issues the PID in both formats (ARF PID_02): the mdoc PID needs a document signer, and the
        # reference mdoc PID configuration a batch size of 30.
        "mdoc_signing_key": pki.root / "mdoc-signing.key",
        "mdoc_signing_chain": pki.root / "mdoc-signing.pem",
        "mdoc_trust_anchors": pki.root / "iaca.pem",
        "mdoc_signer_certificate_url": f"{ISSUER}/certs/mdoc-signer.pem",
        "batch_size": 30,
    }
    return settings_kwargs(pki, **{**production, **overrides})


PID_SUBJECT: dict[str, Any] = {
    "family_name": "Silva",
    "given_name": "Ana Maria",
    "birthdate": "1990-05-17",
    "place_of_birth": {"locality": "Porto", "country": "PT"},
    "nationalities": ["PT", "ES"],
    "address": {"locality": "Braga", "country": "PT", "postal_code": "4700-001"},
    "issuing_authority": "Instituto dos Registos e do Notariado",
    "issuing_country": "PT",
    "issuing_jurisdiction": "PT-03",
    "date_of_expiry": "2031-11-04",
}


@dataclass
class Wallet:
    """A scripted wallet: builds the requests a real wallet would send."""

    client: TestClient
    pki: Pki
    clock: Clock
    dpop_key: EcKey = field(default_factory=EcKey.generate)
    token: str | None = None
    status_exp_offset: int = 30 * 86_400
    key_status_index: int = 7  # the key attestations' entry on the wallet provider's status list

    def admin(self, path: str, body: Any) -> Any:
        return self.client.post(f"/admin/{path}", json=body, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})

    def offer(
        self, subject: dict[str, Any] | None = None, *, tx: int | None = None, configs: list[str] | None = None
    ) -> dict[str, Any]:
        response = self.admin(
            "offers",
            {
                "credential_configuration_ids": configs or [PID_CONFIG],
                "subject": subject if subject is not None else PID_SUBJECT,
                "tx_code_length": tx,
            },
        )
        assert response.status_code == 201, response.text
        offer: dict[str, Any] = response.json()
        return offer

    def dpop(self, method: str, url: str, **overrides: Any) -> str:
        key = overrides.pop("key", self.dpop_key)
        overrides.setdefault("iat", int(self.clock()))
        return dpop_proof(key, method, url, **overrides)

    def token_request(
        self,
        code: str,
        *,
        tx_code: str | None = None,
        dpop: str | list[str] | None = "auto",
        extra: dict[str, str] | None = None,
    ) -> Any:
        form = {"grant_type": PRE_AUTH, "pre-authorized_code": code}
        if tx_code is not None:
            form["tx_code"] = tx_code
        form.update(extra or {})
        headers: list[tuple[str, str]] = [("Content-Type", "application/x-www-form-urlencoded")]
        proofs = [self.dpop("POST", f"{ISSUER}/token")] if dpop == "auto" else dpop
        for proof in [proofs] if isinstance(proofs, str) else proofs or []:
            headers.append(("DPoP", proof))
        from urllib.parse import urlencode

        return self.client.post("/token", content=urlencode(form), headers=headers)

    def get_token(self, offer: dict[str, Any] | None = None) -> str:
        offer = offer or self.offer()
        code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        response = self.token_request(code, tx_code=offer.get("tx_code"))
        assert response.status_code == 200, response.text
        self.token = response.json()["access_token"]
        return self.token

    def c_nonce(self) -> str:
        response = self.client.post("/nonce")
        assert response.status_code == 200
        return str(response.json()["c_nonce"])

    def key_attestation(
        self, keys: list[EcKey], *, nonce: str | None = None, signing_key: EcKey | None = None, **claims: Any
    ) -> str:
        now = int(self.clock())
        payload: dict[str, Any] = {
            "iat": now,
            "exp": now + 3600,
            "attested_keys": [k.public_jwk() for k in keys],
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_high"],
            "key_storage_status": {
                "status": {
                    "status_list": {"idx": self.key_status_index, "uri": "https://wallet-provider.test/status/1"}
                },
                "exp": now + self.status_exp_offset,
            },
        }
        if nonce is not None:
            payload["nonce"] = nonce
        payload.update(claims)
        header = claims.pop("_header", None) or {
            "typ": "key-attestation+jwt",
            "alg": "ES256",
            "x5c": [der_b64(self.pki.ka_leaf)],
        }
        payload = {k: v for k, v in payload.items() if not k.startswith("_") and v is not ...}
        return jws(header, payload, signing_key or self.pki.ka_key)

    def proof(self, holder: EcKey, nonce: str | None, *, attest: bool = True, **overrides: Any) -> str:
        attestation = overrides.pop("key_attestation", None)
        if attestation is None and attest:
            attestation = self.key_attestation([holder])
        overrides.setdefault("iat", int(self.clock()))
        return key_proof(holder, ISSUER, nonce=nonce, key_attestation=attestation, **overrides)

    def credential_request(
        self,
        body: Any,
        *,
        raw: bytes | None = None,
        scheme: str = "DPoP",
        dpop: str | list[str] | None = "auto",
        content_type: str = "application/json",
    ) -> Any:
        assert self.token is not None
        headers: list[tuple[str, str]] = [("Authorization", f"{scheme} {self.token}"), ("Content-Type", content_type)]
        proofs = [self.dpop("POST", f"{ISSUER}/credential", access_token=self.token)] if dpop == "auto" else dpop
        for proof in [proofs] if isinstance(proofs, str) else proofs or []:
            headers.append(("DPoP", proof))
        content = raw if raw is not None else json.dumps(body).encode()
        return self.client.post("/credential", content=content, headers=headers)

    def issue(self, holders: list[EcKey] | None = None, config: str = PID_CONFIG) -> Any:
        if self.token is None:
            self.get_token()
        holders = holders or [EcKey.generate()]
        nonce = self.c_nonce()
        proofs = [self.proof(h, nonce) for h in holders]
        return self.credential_request({"credential_configuration_id": config, "proofs": {"jwt": proofs}})


@contextmanager
def refusals() -> Iterator[list[tuple[str, str]]]:
    """Record (rule, description) of every refusal raised inside the block, in order."""
    seen: list[tuple[str, str]] = []

    def observe(error: IssuerError) -> None:
        seen.append((error.rule, error.description))

    observers.append(observe)
    try:
        yield seen
    finally:
        observers.remove(observe)


def refused_by(action: Callable[[], Any], rule: str, reason: str) -> Any:
    """Run `action` and assert that its first refusal is `rule`, with `reason` in the description.

    A negative case proves its check only when that check is what refuses it: a case refused by an
    earlier, unrelated check stays green when its own check is deleted (review 3, N3-H1).
    """
    with refusals() as seen:
        result = action()
    assert seen, f"nothing was refused; expected {rule} ({reason})"
    assert seen[0][0] == rule and reason in seen[0][1], f"expected {rule} ({reason}), got {seen[0]}"
    return result


def raised_by(action: Callable[[], Any], rule: str, reason: str) -> IssuerError:
    """As `refused_by`, for a call that raises its refusal instead of answering it over HTTP. The first refusal must
    be `rule` with `reason`: catching any IssuerError would also pass when an earlier, unrelated check refused."""
    with refusals() as seen:
        try:
            action()
        except IssuerError as exc:
            error = exc
        else:
            raise AssertionError(f"nothing was raised; expected {rule} ({reason})")
    assert seen and seen[0][0] == rule and reason in seen[0][1], f"expected {rule} ({reason}), got {seen[:1]}"
    return error


def hs256(payload: dict[str, Any], header: dict[str, Any]) -> str:
    return jws_hs256(header, payload, uuid.uuid4().bytes * 2)


def disclosures(credential: str) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    parts = credential.split("~")
    jwt = parse_jws(parts[0])
    decoded = [json.loads(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))) for d in parts[1:] if d]
    return jwt.header, jwt.payload, decoded


def holder_thumbprint(key: EcKey) -> str:
    return thumbprint(key.public_jwk())


def now_iso() -> str:
    return time.strftime("%Y-%m-%d")


__all__ = ["b64u", "EcKey"]


def _tlv(data: bytes, at: int) -> tuple[int, int, int]:
    """(tag, content start, content end) of the DER element at `at`."""
    length, start = data[at + 1], at + 2
    if length & 0x80:
        count = length & 0x7F
        length, start = int.from_bytes(data[start : start + count], "big"), start + count
    return data[at], start, start + length


def _der(tag: int, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        return bytes([tag, size]) + content
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def crl_without_next_update(issuer: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> bytes:
    """A correctly signed DER CRL with no nextUpdate, which the cryptography builder refuses to make."""
    der = x509.load_pem_x509_crl(crl(issuer, key)).public_bytes(serialization.Encoding.DER)
    _, body, _ = _tlv(der, 0)
    _, tbs_start, tbs_end = _tlv(der, body)
    parts, at = [], tbs_start
    while at < tbs_end:
        tag, _, end = _tlv(der, at)
        parts.append((tag, der[at:end]))
        at = end
    times = [i for i, (tag, _) in enumerate(parts) if tag in (0x17, 0x18)]
    del parts[times[1]]  # thisUpdate stays, nextUpdate goes
    tbs = _der(0x30, b"".join(raw for _, raw in parts))
    _, algorithm_start, algorithm_end = _tlv(der, tbs_end)
    algorithm = der[tbs_end:algorithm_end]
    signature = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    return _der(0x30, tbs + algorithm + _der(0x03, b"\x00" + signature))


def with_database(url: str, name: str) -> str:
    """A PostgreSQL connection URI with its database replaced by `name`."""
    from urllib.parse import urlsplit, urlunsplit

    return urlunsplit(urlsplit(url)._replace(path=f"/{name}"))
