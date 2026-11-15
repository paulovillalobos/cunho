"""ISO/IEC 18013-5 Annex B: the IACA, the document signer and the status list signer of an mdoc issuer fit the
certificate profiles mdoc readers check, or production does not start (piece M; the OIDF suite found the gap)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cunho import annex_b
from cunho.errors import ConfigError
from cunho.service import Issuer, Signers
from cunho.settings import Settings
from cunho.signer import FileSigner

from .helpers import (
    ANNEX_B_CONTACT,
    ANNEX_B_CRL,
    MDOC_DS,
    Clock,
    Pki,
    access_signer,
    certificate,
    key_pem,
    mdoc_signer,
    pem,
    production_kwargs,
    provider_name,
)

PURPOSE = x509.ExtendedKeyUsage([x509.ObjectIdentifier(MDOC_DS)])
IACA_NAME = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"), x509.NameAttribute(NameOID.COMMON_NAME, "IACA")])


def key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def iaca(**changes: Any) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    own = key()
    made = {
        "ca": True,
        "path_length": 0,
        "name": IACA_NAME,
        "annex_b": True,
        "extensions": [(ANNEX_B_CONTACT, False)],
        **changes,
    }
    return certificate("IACA", own, **made), own


def signer(issuer: tuple[x509.Certificate, ec.EllipticCurvePrivateKey], **changes: Any) -> x509.Certificate:
    made = {
        "extensions": [(PURPOSE, True), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False)],
        "name": provider_name("Document Signer"),
        "annex_b": True,
        **changes,
    }
    return certificate("Document Signer", key(), issuer, **made)


def test_certificates_in_the_profiles_have_nothing_wrong() -> None:
    root = iaca()
    assert annex_b.iaca_problems(root[0]) == []
    assert annex_b.document_signer_problems(signer(root), root[0]) == []
    status = certificate("Status", key(), root, annex_b=True)
    assert annex_b.status_signer_problems(status, root[0]) == []
    assert annex_b.issuer_of(signer(root), [iaca()[0], root[0]]) == root[0]
    assert annex_b.issuer_of(signer(root), [iaca()[0]]) is None


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"name": x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IACA")])}, "countryName"),
        ({"annex_b": False}, "subject key identifier"),
        ({"path_length": 1}, "path length 0"),
        ({"extensions": []}, "issuerAltName"),
        (
            {"extensions": [(ANNEX_B_CONTACT, False)], "annex_b": False, "path_length": 0},
            "critical key usage of crl_sign and key_cert_sign alone",
        ),
    ],
)
def test_an_iaca_outside_table_b1_is_named(changes: dict[str, Any], expected: str) -> None:
    root, _ = iaca(**changes)
    problems = annex_b.iaca_problems(root)
    assert any(expected in p and "Table B.1" in p for p in problems), problems


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"name": x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DS")])}, "countryName"),
        ({"annex_b": False}, "subject key identifier"),
        ({"annex_b": False}, "critical key usage of digital_signature alone"),
        ({"annex_b": False}, "2.5.29.19 is critical"),
        ({"extensions": [(PURPOSE, True), (ANNEX_B_CONTACT, False)]}, "CRL distribution point"),
        ({"extensions": [(PURPOSE, True), (ANNEX_B_CRL, False)]}, "issuerAltName"),
        ({"extensions": [(PURPOSE, False), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False)]}, "id-mdl-kp-mdlDS"),
        ({"extensions": [(ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False)]}, "id-mdl-kp-mdlDS"),
        (
            {
                "name": x509.Name(
                    [x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"), x509.NameAttribute(NameOID.COMMON_NAME, "DS")]
                )
            },
            "differs from the IACA's",
        ),
    ],
)
def test_a_document_signer_outside_table_b3_is_named(changes: dict[str, Any], expected: str) -> None:
    root = iaca()
    problems = annex_b.document_signer_problems(signer(root, **changes), root[0])
    assert any(expected in p for p in problems), problems


def test_a_document_signer_names_the_iaca_that_issued_it() -> None:
    """The authority key identifier is the issuing IACA's subject key identifier."""
    root, other = iaca(), iaca()
    problems = annex_b.document_signer_problems(signer(root), other[0])
    assert any("not the issuer's subject key identifier" in p for p in problems), problems


@pytest.mark.parametrize("changes", [{"annex_b": False}])
def test_a_status_signer_outside_table_b9_is_named(changes: dict[str, Any]) -> None:
    root = iaca()
    problems = annex_b.status_signer_problems(certificate("Status", key(), root, **changes), root[0])
    assert any("Table B.9" in p and "subject key identifier" in p for p in problems), problems
    assert any("2.5.29.19 is critical" in p for p in problems), problems


def outside_annex_b(pki: Pki, tmp_path: Path) -> FileSigner:
    """A document signer with the mdoc purpose but nothing else Annex B asks for, under the test IACA's key."""
    ds_key = key()
    plain_iaca_key = key()
    plain_iaca = certificate("Plain IACA", plain_iaca_key, ca=True, path_length=0)
    ds = certificate("Plain Document Signer", ds_key, (plain_iaca, plain_iaca_key), extensions=[(PURPOSE, True)])
    (tmp_path / "ds.key").write_bytes(key_pem(ds_key))
    (tmp_path / "ds.pem").write_bytes(pem(ds) + pem(plain_iaca))
    (tmp_path / "iaca.pem").write_bytes(pem(plain_iaca))
    return FileSigner.from_files(tmp_path / "ds.key", tmp_path / "ds.pem", tmp_path / "iaca.pem")


@pytest.mark.obligation("FMT.MDOC.ISSUERAUTH_X5CHAIN")
def production_settings(pki: Pki, folder: Path, **overrides: Any) -> Settings:
    folder.mkdir(exist_ok=True)
    secret = folder / "m.key"
    secret.write_bytes(b"k" * 32)
    secret.chmod(0o600)
    return Settings(**{**production_kwargs(pki, folder), **overrides})


def test_production_refuses_mdoc_signing_certificates_outside_annex_b(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    settings = production_settings(pki, tmp_path, mdoc_trust_anchors=tmp_path / "iaca.pem")
    anchors = pki.root / "issuer-root.pem"
    credentials = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    status = FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors)
    signers = Signers(credentials, status, access_signer(pki), outside_annex_b(pki, tmp_path))
    with pytest.raises(ConfigError, match="do not fit the profiles mdoc readers check: .*Table B.3.*Table B.1"):
        Issuer(settings, signers=signers, clock=clock)
    # The test PKI's own mdoc signing certificates fit, and production starts with them (test_review2_fixes, N-L8).
    good = Signers(credentials, status, access_signer(pki), mdoc_signer(pki))
    Issuer(production_settings(pki, tmp_path / "again"), signers=good, clock=clock)


def test_a_development_run_says_what_does_not_fit(
    make_issuer: Any, pki: Pki, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    outside_annex_b(pki, tmp_path)
    with caplog.at_level(logging.WARNING, logger="cunho"):
        make_issuer(
            profile="eaa_provider",
            mdoc_signing_key=tmp_path / "ds.key",
            mdoc_signing_chain=tmp_path / "ds.pem",
            mdoc_trust_anchors=tmp_path / "iaca.pem",
            published_configurations=("eu.europa.ec.eudi.iban_mdoc",),
        )
    said = [r.getMessage() for r in caplog.records if "mdoc signing certificates" in r.getMessage()]
    assert any("Table B.3" in m and "CRL distribution point" in m for m in said), said
    assert all("production refuses to start" in m for m in said)


def test_without_mdoc_attestations_the_profiles_are_not_asked(make_issuer: Any, pki: Pki, tmp_path: Path) -> None:
    """A document signer is only read when an mdoc configuration is published."""
    outside_annex_b(pki, tmp_path)
    issuer: Issuer = make_issuer(
        mdoc_signing_key=tmp_path / "ds.key",
        mdoc_signing_chain=tmp_path / "ds.pem",
        mdoc_trust_anchors=tmp_path / "iaca.pem",
        published_configurations=("eu.europa.ec.eudi.pid_vc_sd_jwt",),
        profile="eaa_provider",
    )
    assert issuer.configs.published == {"eu.europa.ec.eudi.pid_vc_sd_jwt"}


def test_a_key_usage_that_is_not_critical_is_named() -> None:
    root, own = iaca()
    usage = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
    loose = certificate(
        "Document Signer",
        key(),
        (root, own),
        extensions=[(PURPOSE, True), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False), (usage, False)],
        name=provider_name("Document Signer"),
    )
    problems = annex_b.document_signer_problems(loose, root)
    assert any("critical key usage of digital_signature alone" in p for p in problems), problems


def test_a_document_signer_whose_iaca_is_not_an_anchor_is_named(
    make_issuer: Any, pki: Pki, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The IACA is the reader's trust anchor (mdoc_trust_anchors): a development run given none, with a chain of the
    document signer alone, cannot check it, and says so."""
    outside_annex_b(pki, tmp_path)
    alone = tmp_path / "alone.pem"
    alone.write_bytes(
        (tmp_path / "ds.pem").read_bytes().split(b"-----END CERTIFICATE-----")[0] + b"-----END CERTIFICATE-----\n"
    )
    with caplog.at_level(logging.WARNING, logger="cunho"):
        make_issuer(
            profile="eaa_provider",
            mdoc_signing_key=tmp_path / "ds.key",
            mdoc_signing_chain=alone,
            mdoc_trust_anchors=None,
            published_configurations=("eu.europa.ec.eudi.iban_mdoc",),
        )
    said = " | ".join(r.getMessage() for r in caplog.records)
    assert "not signed by an IACA among mdoc_trust_anchors" in said, said


def test_a_key_usage_with_more_than_its_role_needs_is_named() -> None:
    root, own = iaca()
    usage = x509.KeyUsage(True, False, False, False, True, False, False, False, False)  # and key agreement
    wider = certificate(
        "Document Signer",
        key(),
        (root, own),
        extensions=[(PURPOSE, True), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False), (usage, True)],
        name=provider_name("Document Signer"),
    )
    problems = annex_b.document_signer_problems(wider, root)
    assert any("critical key usage of digital_signature alone" in p for p in problems), problems


def test_an_issuer_alt_name_without_a_contact_is_named() -> None:
    """Table B.1 and B.3 ask for an rfc822Name or a URI: a DNS name is no way to reach the issuer."""
    dns_only = x509.IssuerAlternativeName([x509.DNSName("issuer.test")])
    root, _ = iaca(extensions=[(dns_only, False)])
    assert any("issuerAltName" in p for p in annex_b.iaca_problems(root))


def test_production_refuses_a_document_signer_under_an_intermediate(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    """The second reviewer: a chain document signer, intermediate, IACA verifies to the IACA, but Annex B has the IACA
    sign the document signer itself. An intermediate sent in the chain is no IACA, however it is made."""
    root, root_key = iaca(path_length=1)
    middle_key = key()
    middle = certificate(
        "Intermediate",
        middle_key,
        (root, root_key),
        ca=True,
        path_length=0,
        name=IACA_NAME,
        annex_b=True,
        extensions=[(ANNEX_B_CONTACT, False)],
    )
    ds_key = key()
    ds = certificate(
        "Document Signer",
        ds_key,
        (middle, middle_key),
        extensions=[(PURPOSE, True), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False)],
        name=provider_name("Document Signer"),
        annex_b=True,
    )
    (tmp_path / "ds.key").write_bytes(key_pem(ds_key))
    (tmp_path / "ds.pem").write_bytes(pem(ds) + pem(middle) + pem(root))
    (tmp_path / "root.pem").write_bytes(pem(root))
    deep = FileSigner.from_files(tmp_path / "ds.key", tmp_path / "ds.pem", tmp_path / "root.pem")
    settings = production_settings(pki, tmp_path, mdoc_trust_anchors=tmp_path / "root.pem")
    anchors = pki.root / "issuer-root.pem"
    credentials = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    status = FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors)
    with pytest.raises(ConfigError, match="not signed by an IACA among mdoc_trust_anchors"):
        Issuer(settings, signers=Signers(credentials, status, access_signer(pki), deep), clock=clock)


def _bare_iaca(constraints: x509.BasicConstraints | None, critical: bool = True) -> x509.Certificate:
    """An IACA in every way Annex B asks but its basicConstraints, which `constraints` gives, or none."""
    import datetime as dt  # noqa: PLC0415

    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415

    from .helpers import ANNEX_B_CA_USAGE  # noqa: PLC0415

    own = key()
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(IACA_NAME)
        .issuer_name(IACA_NAME)
        .public_key(own.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(ANNEX_B_CA_USAGE, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(own.public_key()), critical=False)
        .add_extension(ANNEX_B_CONTACT, critical=False)
    )
    if constraints is not None:
        builder = builder.add_extension(constraints, critical=critical)
    return builder.sign(own, hashes.SHA256())


@pytest.mark.parametrize(
    ("constraints", "critical"),
    [
        (None, True),
        (x509.BasicConstraints(ca=True, path_length=0), False),
        (x509.BasicConstraints(ca=False, path_length=None), True),
    ],
)
def test_an_iaca_whose_basic_constraints_are_wrong_is_named(
    constraints: x509.BasicConstraints | None, critical: bool
) -> None:
    """Table B.1: critical basicConstraints of a CA with path length 0; absent, not critical or not a CA is named."""
    assert annex_b.iaca_problems(_bare_iaca(x509.BasicConstraints(ca=True, path_length=0))) == []
    problems = annex_b.iaca_problems(_bare_iaca(constraints, critical))
    assert any("basicConstraints of a CA with path length 0" in p for p in problems), problems


def test_a_certificate_without_its_authority_key_identifier_is_named() -> None:
    root, own = iaca()
    bare = certificate(
        "Document Signer",
        key(),
        (root, own),
        extensions=[
            (PURPOSE, True),
            (ANNEX_B_CONTACT, False),
            (ANNEX_B_CRL, False),
            (x509.KeyUsage(True, False, False, False, False, False, False, False, False), True),
        ],
        name=provider_name("Document Signer"),
    )
    problems = annex_b.document_signer_problems(bare, root)
    assert any("asks for an authority key identifier" in p for p in problems), problems


def test_a_critical_extended_key_usage_without_the_mdoc_purpose_is_named() -> None:
    root = iaca()
    server = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    problems = annex_b.document_signer_problems(
        signer(root, extensions=[(server, True), (ANNEX_B_CONTACT, False), (ANNEX_B_CRL, False)]), root[0]
    )
    assert any("id-mdl-kp-mdlDS" in p for p in problems), problems


def test_a_status_signer_outside_table_b9_stops_production(pki: Pki, tmp_path: Path, clock: Clock) -> None:
    """The status list signer is checked at start with the document signer, when mdoc attestations are published."""
    own_root_key = key()
    own_root = certificate("Status Root", own_root_key, ca=True, path_length=0)
    status_key = key()
    plain_status = certificate("Plain Status Signer", status_key, (own_root, own_root_key))
    (tmp_path / "status.key").write_bytes(key_pem(status_key))
    (tmp_path / "status.pem").write_bytes(pem(plain_status) + pem(own_root))
    anchors = tmp_path / "anchors.pem"
    anchors.write_bytes((pki.root / "issuer-root.pem").read_bytes() + pem(own_root))
    settings = production_settings(pki, tmp_path, signing_trust_anchors=anchors)
    credentials = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    status = FileSigner.from_files(tmp_path / "status.key", tmp_path / "status.pem", anchors)
    signers = Signers(credentials, status, access_signer(pki), mdoc_signer(pki))
    with pytest.raises(ConfigError, match="Table B.9"):
        Issuer(settings, signers=signers, clock=clock)
