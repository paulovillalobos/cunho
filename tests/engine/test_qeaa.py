"""eIDAS Annex V and VII as ETSI TS 119 472-1 V1.2.1 profiles them: what a qualified or public-body attestation
carries (QEAA.*), and clause 6, what every mdoc attestation that is not an mDL carries (FMT.ETSI_119472_1)."""

from __future__ import annotations

import base64
import datetime as dt
import functools
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cunho import metadata
from cunho.errors import ConfigError
from cunho.jose import b64u
from cunho.qualified import EAA_NAMESPACE, ETSI_NAMESPACE, authority, check_provider
from cunho.service import Issuer
from cunho.settings import Settings
from eudi_probe.jose import EcKey

from .helpers import (
    PID_CONFIG,
    PROVIDER,
    Pki,
    Wallet,
    certificate,
    disclosures,
    key_pem,
    pem,
    refused_by,
    settings_kwargs,
    typed_metadata,
)
from .test_mdoc import IBAN, IBAN_NS, IBAN_SUBJECT, PHOTO, issue, mdoc_settings, read_mdoc

IBAN_SDJWT = "eu.europa.ec.eudi.iban_sd_jwt_vc"
IBAN_FLAT = {**IBAN_SUBJECT[IBAN_NS], "issuance_date": "2026-01-01"}
QUALIFIED = {"qeaa_provider": "urn:etsi:esi:eaa:eu:qualified", "pub_eaa_provider": "urn:etsi:esi:eaa:eu:pub"}
MDOC_URL = "https://issuer.test/certs/mdoc-signer.pem"
ORG_ID = x509.ObjectIdentifier("2.5.4.97")


def der(name: list[tuple[x509.ObjectIdentifier, str]]) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = certificate("x", key, name=x509.Name([x509.NameAttribute(oid, value) for oid, value in name]))
    return cert.public_bytes(serialization.Encoding.DER)


def sdjwt_issuer(make_issuer: Callable[..., Issuer], pki: Pki, profile: str) -> Issuer:
    return make_issuer(profile=profile, metadata_dir=pki.root / "metadata", published_configurations=(IBAN_SDJWT,))


@pytest.mark.parametrize("profile", sorted(QUALIFIED))
@pytest.mark.obligation(
    "QEAA.ANNEX_V",
    "QEAA.QUALIFIED_INDICATOR",
    "QEAA.ATTESTATION_ID_UNIQUE",
    "QEAA.ATTRIBUTES_SCOPE",
    "QEAA.CERT_LOCATION",
)
def test_a_qualified_sd_jwt_vc_carries_annex_v(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, profile: str
) -> None:
    """Annex V, point by point, on two copies of one qualified SD-JWT VC: (a) its category, (b) the provider by its
    certificate, (d) the scheme by vct and the integrity of its Type Metadata, (f) an identity code of its own for
    each copy, (h) where the certificate is, by x5u and x5t#S256 next to x5c, (i) its status."""
    issuer = sdjwt_issuer(make_issuer, pki, profile)
    tokens = issue(wallet_for(issuer), IBAN_SDJWT, IBAN_FLAT, [EcKey.generate(), EcKey.generate()])
    codes = []
    for token in tokens:
        header, payload, disclosed = disclosures(token)
        assert payload["category"] == QUALIFIED[profile]
        leaf = x509.load_der_x509_certificate(base64.b64decode(header["x5c"][0]))
        assert leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == PROVIDER
        assert leaf.subject.get_attributes_for_oid(ORG_ID)[0].value == "VATPT-500000000"
        names = {d[1] for d in disclosed if len(d) == 3} | set(payload)
        assert not names & {"issuing_authority", "issuing_country", "iss_reg_id"}, "named by the certificate alone"
        assert payload["vct"] == "urn:eu.europa.ec.eudi:iban:1" and payload["vct#integrity"].startswith("sha256-")
        assert header["x5u"] == f"{issuer.settings.issuer_url}/certs/signer.pem"
        assert header["x5t#S256"] == b64u(hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).digest())
        assert set(payload["status"]["status_list"]) == {"idx", "uri"}
        assert "shortLived" not in payload
        codes.append(payload["jti"])
    assert len(set(codes)) == 2 and all(len(code) == 32 and int(code, 16) >= 0 for code in codes)


def test_an_attestation_that_is_not_qualified_has_no_category_or_identity_code(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    issuer = sdjwt_issuer(make_issuer, pki, "eaa_provider")
    [token] = issue(wallet_for(issuer), IBAN_SDJWT, IBAN_FLAT, [EcKey.generate()])
    payload = disclosures(token)[1]
    assert "category" not in payload and "jti" not in payload


@pytest.mark.parametrize("profile", [*sorted(QUALIFIED), "eaa_provider"])
@pytest.mark.obligation("FMT.ETSI_119472_1", "QEAA.QUALIFIED_INDICATOR", "QEAA.ATTESTATION_ID_UNIQUE")
def test_an_mdoc_attestation_carries_clause_6_from_cunho(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, profile: str
) -> None:
    """EAA-6.2.4.1-03, EAA-6.2.3-01, EAA-6.2.6-01: the issuing authority, an identity code of each copy's own and the
    issue date, in the ISO/IEC 23220-2 namespace; a qualified or public-body one adds its category (6.2.2.2), and
    the metadata lists them all."""
    issuer = make_issuer(**mdoc_settings(pki, profile=profile, mdoc_signer_certificate_url=MDOC_URL))
    wallet = wallet_for(issuer)
    credentials = issue(wallet, IBAN, IBAN_SUBJECT, [EcKey.generate(), EcKey.generate()])
    codes = []
    for credential in credentials:
        mso, elements, issuer_auth = read_mdoc(credential, pki)
        # EAA-6.6.1-01, CB-AdES-B-B (ETSI TS 119 152-1 Table 14): iat in signed CWT claims, the signer by its x5t
        protected = cbor2.loads(issuer_auth[0])
        signer = issuer_auth[1][33]
        assert protected[34] == [-16, hashlib.sha256(signer).digest()]
        signed = dt.datetime.fromtimestamp(protected[15][6], dt.UTC)
        assert set(protected[15]) == {6} and mso["validityInfo"]["signed"] == signed
        own = elements[EAA_NAMESPACE]
        assert own["issuing_authority_unicode"] == PROVIDER
        assert own["issue_date"] == dt.datetime.fromtimestamp(wallet.clock(), dt.UTC).date()  # tag 1004, decoded
        codes.append(own["document_number"])
        assert elements.get(ETSI_NAMESPACE) == ({"category": QUALIFIED[profile]} if profile in QUALIFIED else None)
        assert elements[IBAN_NS]["iban"] == IBAN_SUBJECT[IBAN_NS]["iban"]
    assert len(set(codes)) == 2 and all(len(code) == 32 for code in codes)
    published = wallet.client.get("/.well-known/openid-credential-issuer").json()
    claims = published["credential_configurations_supported"][IBAN]["credential_metadata"]["claims"]
    paths = {tuple(c["path"]) for c in claims}
    assert {(EAA_NAMESPACE, n) for n in ("issuing_authority_unicode", "document_number", "issue_date")} <= paths
    assert ((ETSI_NAMESPACE, "category") in paths) == (profile in QUALIFIED)


@pytest.mark.parametrize(
    ("element", "value"),
    [
        ((EAA_NAMESPACE, "document_number"), "chosen by the operator"),
        ((EAA_NAMESPACE, "issuing_authority_unicode"), "chosen by the operator"),
        ((EAA_NAMESPACE, "issue_date"), "2020-01-01"),
    ],
)
def test_the_operator_does_not_send_what_cunho_fills_in(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Wallet],
    pki: Pki,
    element: tuple[str, str],
    value: str,
) -> None:
    wallet = wallet_for(make_issuer(**mdoc_settings(pki)))
    subject = {**IBAN_SUBJECT, element[0]: {element[1]: value}}
    response = wallet.admin("offers", {"credential_configuration_ids": [IBAN], "subject": subject})
    assert response.status_code == 400 and "cunho fills it in" in response.text


@pytest.mark.covers("QEAA.SUBJECT_OR_PSEUDONYM")
def test_a_qualified_attestation_refers_every_attribute_to_its_subject(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """QEAA-5.2.5.5-01 and -6.2.5.5-01: no subAttrs in an SD-JWT VC, no SubAttr value in an mdoc."""
    sdjwt = wallet_for(sdjwt_issuer(make_issuer, pki, "qeaa_provider"))
    body = {"credential_configuration_ids": [IBAN_SDJWT], "subject": {**IBAN_FLAT, "subAttrs": []}}
    response = refused_by(lambda: sdjwt.admin("offers", body), "QEAA.SUBJECT_OR_PSEUDONYM", "subAttrs")
    assert response.status_code == 400
    settings = mdoc_settings(pki, profile="pub_eaa_provider", mdoc_signer_certificate_url=MDOC_URL)
    mdoc = wallet_for(make_issuer(**settings))
    other = {"subId": {"family_name": "Silva", "given_name": "Rui", "document_number": "1"}}
    for value in (other, {"subAka": "a pseudonym"}):
        subject = {IBAN_NS: {**IBAN_SUBJECT[IBAN_NS], "account_name": value}}
        body = {"credential_configuration_ids": [IBAN], "subject": subject}
        response = refused_by(functools.partial(mdoc.admin, "offers", body), "QEAA.SUBJECT_OR_PSEUDONYM", "SubAttr")
        assert response.status_code == 400
    # Anything else in that element is for the configuration's own check.
    subject = {IBAN_NS: {**IBAN_SUBJECT[IBAN_NS], "account_name": {"name": "x"}}}
    response = mdoc.admin("offers", {"credential_configuration_ids": [IBAN], "subject": subject})
    assert "SubAttr" not in response.text


@pytest.mark.obligation("QEAA.ISSUER_IDENTITY")
def test_a_qualified_providers_certificate_names_it() -> None:
    """Annex V(b): the Member State, and the name and registration number of a legal person or the name of a natural
    person; ETSI EN 319 412-1 §5.1.4 for the registration number."""
    country, org, cn = NameOID.COUNTRY_NAME, NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME
    good = [
        [(country, "PT"), (org, "A"), (ORG_ID, "VATPT-500000000")],
        [(country, "DE"), (org, "A"), (ORG_ID, "NTRDE-HRB12345")],
        [(country, "BE"), (org, "A"), (ORG_ID, "LEIXG-5299000J2N45DDNE4Y90")],
        [(country, "GR"), (org, "A"), (ORG_ID, "VATEL-123456789")],
        [(country, "FR"), (org, "A"), (ORG_ID, "AB:FR-1234")],
        [(country, "IT"), (cn, "Maria Rossi")],
        [(country, "IT"), (NameOID.GIVEN_NAME, "Maria"), (NameOID.SURNAME, "Rossi")],
    ]
    for name in good:
        check_provider(der(name), "credential signing")
    bad = [
        ([(org, "A"), (ORG_ID, "VATPT-500000000")], "countryName"),
        ([(country, "US"), (org, "A"), (ORG_ID, "VATUS-1")], "countryName"),
        ([(country, "PT"), (country, "ES"), (org, "A"), (ORG_ID, "VATPT-1")], "more than once"),
        ([(country, "PT"), (org, "A")], "organizationIdentifier"),
        ([(country, "PT"), (org, "A"), (ORG_ID, "VAT PT 500000000")], "organizationIdentifier"),
        ([(country, "PT"), (org, "A"), (ORG_ID, "XYZPT-1")], "organizationIdentifier"),
        ([(country, "PT"), (org, "A"), (ORG_ID, "VATPT-")], "organizationIdentifier"),
        ([(country, "PT"), (org, " "), (cn, "x")], None),
        ([(country, "PT")], "the provider's name"),
        ([(country, "PT"), (NameOID.GIVEN_NAME, "Maria")], "the provider's name"),
        ([(country, "PT"), (NameOID.SURNAME, "Rossi")], "the provider's name"),
    ]
    for name, reason in bad:
        if reason is None:  # a blank organizationName is no name: the certificate names a natural person
            check_provider(der(name), "credential signing")
            continue
        with pytest.raises(ConfigError, match=reason):
            check_provider(der(name), "credential signing")


def test_the_issuing_authority_is_the_name_the_certificate_gives() -> None:
    org, cn = NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME
    assert authority(der([(org, "Org"), (cn, "Common")])) == "Org"
    assert authority(der([(cn, "Common")])) == "Common"
    assert authority(der([(NameOID.GIVEN_NAME, "Maria"), (NameOID.SURNAME, "Rossi")])) == "Maria Rossi"
    for name in ([(NameOID.COUNTRY_NAME, "PT")], [(NameOID.GIVEN_NAME, "Maria")], [(NameOID.SURNAME, "Rossi")]):
        with pytest.raises(ConfigError, match="names no issuing authority"):
            authority(der(name))


def _unnamed_signer(tmp_path: Path, pki: Pki, mdoc: bool) -> dict[str, Any]:
    """Settings with a signer whose certificate names only its country: no provider, no issuing authority."""
    root_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root = certificate("Unnamed Root", root_key, ca=True, path_length=0)
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "PT")])
    extensions: list[tuple[x509.ExtensionType, bool]] = []
    if mdoc:
        extensions = [(x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")]), True)]
    leaf = certificate("x", leaf_key, (root, root_key), san=["issuer.test"], extensions=extensions, name=name)
    (tmp_path / "unnamed.key").write_bytes(key_pem(leaf_key))
    (tmp_path / "unnamed.pem").write_bytes(pem(leaf) + pem(root))
    (tmp_path / "unnamed-root.pem").write_bytes(pem(root))
    if mdoc:
        return {
            "mdoc_signing_key": tmp_path / "unnamed.key",
            "mdoc_signing_chain": tmp_path / "unnamed.pem",
            "mdoc_trust_anchors": tmp_path / "unnamed-root.pem",
        }
    return {
        "signing_key": tmp_path / "unnamed.key",
        "signing_chain": tmp_path / "unnamed.pem",
        "signing_trust_anchors": tmp_path / "unnamed-root.pem",
        "status_signing_key": None,  # the status signer chains to the same anchors
        "status_signing_chain": None,
    }


@pytest.mark.parametrize(
    ("profile", "mdoc", "published", "reason"),
    [
        ("qeaa_provider", False, (IBAN_SDJWT,), "credential signing certificate of a qualified"),
        ("pub_eaa_provider", True, (IBAN,), "mdoc document signer certificate of a qualified"),
        ("eaa_provider", True, (IBAN,), "names no issuing authority"),
    ],
)
def test_a_signer_that_does_not_name_the_provider_stops_the_start(
    make_issuer: Callable[..., Issuer],
    pki: Pki,
    tmp_path: Path,
    profile: str,
    mdoc: bool,
    published: tuple[str, ...],
    reason: str,
) -> None:
    settings = mdoc_settings(pki, profile=profile, mdoc_signer_certificate_url=MDOC_URL)
    settings.update(published_configurations=published, **_unnamed_signer(tmp_path, pki, mdoc))
    with pytest.raises(ConfigError, match=reason):
        make_issuer(**settings)


def test_a_document_signer_for_pids_alone_names_no_authority(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    """The PID carries the issuing authority the operator sends: only an mdoc attestation takes it from the
    certificate."""
    issuer = make_issuer(
        **mdoc_settings(
            pki, profile="pid_provider", published_configurations=(PID_CONFIG,), mdoc_signer_certificate_url=MDOC_URL
        )
    )
    assert issuer.configs.published == {PID_CONFIG}


def _metadata_with(tmp_path: Path, file: str, change: Callable[[dict[str, Any]], None]) -> Path:
    folder = typed_metadata(tmp_path / "metadata")
    path = folder / "credentials_supported" / file
    configs = json.loads(path.read_text())
    for config in configs.values():
        change(config)
    path.write_text(json.dumps(configs))
    return folder


def _claims(config: dict[str, Any]) -> list[dict[str, Any]]:
    holder = config["credential_metadata"] if "claims" in config.get("credential_metadata", {}) else config
    claims: list[dict[str, Any]] = holder["claims"]
    return claims


@pytest.mark.obligation("QEAA.ISSUER_IDENTITY", "QEAA.SUBJECT_OR_PSEUDONYM")
@pytest.mark.parametrize(
    ("claim", "reason"),
    [
        ("issuing_authority", "EAA-5.2.4.1-03"),
        ("issuing_country", "EAA-5.2.4.1-07"),
        ("iss_reg_id", "EAA-5.2.4.1-11"),
        ("subAttrs", "QEAA-5.2.5.5-01"),
        ("category", "clash with the category"),
        ("jti", "identity code in jti"),
    ],
)
def test_a_qualified_sd_jwt_vc_configuration_names_the_provider_by_its_certificate(
    pki: Pki, tmp_path: Path, claim: str, reason: str
) -> None:
    folder = _metadata_with(tmp_path, "iban_jwt_vc.json", lambda c: _claims(c).append({"path": [claim]}))
    for profile in QUALIFIED:
        named = Settings(
            **settings_kwargs(pki, profile=profile, metadata_dir=folder, published_configurations=(IBAN_SDJWT,))
        )
        with pytest.raises(ConfigError, match=f"{IBAN_SDJWT}: {claim}: .*{reason}"):
            metadata.load(named)
        default = metadata.load(Settings(**settings_kwargs(pki, profile=profile, metadata_dir=folder)))
        assert IBAN_SDJWT not in default.published and reason in default.findings[IBAN_SDJWT]
    loaded = metadata.load(Settings(**settings_kwargs(pki, profile="eaa_provider", metadata_dir=folder)))
    assert IBAN_SDJWT in loaded.published, "only a qualified or public-body provider is held to it"


def test_a_qualified_provider_publishes_by_default_what_it_may_issue(pki: Pki) -> None:
    """The EC configurations that name the provider in claims are kept out of a qualified provider's metadata; the
    others are published."""
    loaded = metadata.load(
        Settings(**settings_kwargs(pki, profile="qeaa_provider", metadata_dir=pki.root / "metadata"))
    )
    assert IBAN_SDJWT in loaded.published
    assert "eu.europa.ec.eudi.tax_sd_jwt_vc" in loaded.findings and "eu.europa.ec.eudi.tax_sd_jwt_vc" not in (
        loaded.published
    )


@pytest.mark.parametrize(
    ("element", "profiles", "reason"),
    [
        ((ETSI_NAMESPACE, "iss_reg_id"), QUALIFIED, "EAA-6.2.4.1-13"),
        ((EAA_NAMESPACE, "document_number"), (*QUALIFIED, "eaa_provider"), "cunho fills it in"),
        ((EAA_NAMESPACE, "issuing_authority_unicode"), ("eaa_provider",), "cunho fills it in"),
        ((EAA_NAMESPACE, "issue_date"), ("eaa_provider",), "cunho fills it in"),
        ((ETSI_NAMESPACE, "category"), (*QUALIFIED, "eaa_provider"), "cunho fills it in"),
    ],
)
def test_an_mdoc_configuration_lists_none_of_what_cunho_fills_in(
    pki: Pki, tmp_path: Path, element: tuple[str, str], profiles: Any, reason: str
) -> None:
    claim = {"path": list(element), "value_type": "string"}
    folder = _metadata_with(tmp_path, "iban_mdoc.json", lambda c: _claims(c).append(claim))
    for profile in profiles:
        settings = mdoc_settings(pki, profile=profile, mdoc_signer_certificate_url=MDOC_URL)
        named = Settings(**settings_kwargs(pki, metadata_dir=folder, **settings))
        if element[1] == "iss_reg_id":  # a configuration any provider may publish, but not a qualified one
            with pytest.raises(ConfigError, match=f"{IBAN}: .*{reason}"):
                metadata.load(named, mdoc_alg="ES256")
            continue
        default = Settings(
            **settings_kwargs(pki, metadata_dir=folder, **{**settings, "published_configurations": None})
        )
        assert reason in metadata.load(default, mdoc_alg="ES256").findings[IBAN]
    if element[1] == "iss_reg_id":
        settings = mdoc_settings(pki, mdoc_signer_certificate_url=MDOC_URL)
        loaded = metadata.load(Settings(**settings_kwargs(pki, metadata_dir=folder, **settings)), mdoc_alg="ES256")
        assert IBAN in loaded.published


def test_an_mdoc_configuration_keeps_the_elements_cunho_does_not_fill_in(pki: Pki, tmp_path: Path) -> None:
    """Only the elements cunho fills in are refused: others of the ISO/IEC 23220-2 namespace, and a category of the
    configuration's own namespace, are the operator's to send."""
    own = [(EAA_NAMESPACE, "family_name_unicode"), (IBAN_NS, "category")]
    folder = _metadata_with(
        tmp_path, "iban_mdoc.json", lambda c: _claims(c).extend({"path": list(e), "value_type": "string"} for e in own)
    )
    for profile in (*QUALIFIED, "eaa_provider"):
        settings = mdoc_settings(
            pki, profile=profile, published_configurations=(IBAN,), mdoc_signer_certificate_url=MDOC_URL
        )
        loaded = metadata.load(Settings(**settings_kwargs(pki, metadata_dir=folder, **settings)), mdoc_alg="ES256")
        assert IBAN in loaded.published, profile
        paths = {tuple(c["path"]) for c in _claims(loaded.all[IBAN])}
        assert set(own) <= paths and (EAA_NAMESPACE, "document_number") in paths


def test_an_mdl_carries_its_own_issuer_data(pki: Pki, tmp_path: Path) -> None:
    """EAA-6.2.4.1-01, -6.2.3-03, -6.2.6-03: an mDL lists issuing_authority, document_number and issue_date in its own
    namespace, sent by the operator; cunho adds nothing to it."""
    mdl = "eu.europa.ec.eudi.mdl_mdoc"
    loaded = metadata.load(Settings(**settings_kwargs(pki, metadata_dir=pki.root / "metadata")), mdoc_alg="ES256")
    assert mdl not in loaded.findings
    for missing in ("issuing_authority", "document_number", "issue_date"):

        def drop(config: dict[str, Any], name: str = missing) -> None:
            _claims(config)[:] = [c for c in _claims(config) if c["path"] != ["org.iso.18013.5.1", name]]

        folder = _metadata_with(tmp_path / missing, "mdl_mdoc.json", drop)
        loaded = metadata.load(Settings(**settings_kwargs(pki, metadata_dir=folder)), mdoc_alg="ES256")
        assert f"an mDL lists {missing}" in loaded.findings[mdl]
    settings = mdoc_settings(pki, published_configurations=(mdl,))
    loaded = metadata.load(
        Settings(**settings_kwargs(pki, metadata_dir=pki.root / "metadata", **settings)), mdoc_alg="ES256"
    )
    paths = {tuple(c["path"]) for c in _claims(loaded.all[mdl])}
    assert not any(ns in (EAA_NAMESPACE, ETSI_NAMESPACE) for ns, *_ in paths)


def test_the_photo_id_keeps_its_own_elements_beside_cunhos(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    """A configuration with an issuing authority of its own, in its own namespace, gets the ISO/IEC 23220-2 one as
    well: they live in different namespaces."""
    issuer = make_issuer(**mdoc_settings(pki))
    paths = {tuple(c["path"]) for c in _claims(issuer.configs.all[PHOTO])}
    assert ("org.iso.23220.photoid.1", "issuing_authority_unicode") in paths
    assert (EAA_NAMESPACE, "issuing_authority_unicode") in paths
