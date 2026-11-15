"""The PID as mdoc (PID Rulebook v1.7 §3.1; CIR 2024/2977 Annex §4.1; ARF PID_02 to PID_11): one PID, sent in the
SD-JWT VC names, issued in both formats. The mdoc is read back with cbor2 and cryptography alone (test_mdoc.read_mdoc).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cbor2
import pytest

from cunho import cose, metadata
from cunho.credentials import pid_mdoc_elements, validate_pid, validate_pid_mdoc
from cunho.errors import ConfigError
from cunho.mdoc import pid_elements
from cunho.service import Issuer
from cunho.settings import DEFAULT_METADATA_DIR, Settings
from eudi_probe.jose import EcKey

from .helpers import ISSUER, PID_CONFIG, PID_SUBJECT, Pki, Wallet, disclosures, production_kwargs, refused_by
from .test_mdoc import decoded, mdoc_settings, read_mdoc

PID_MDOC = "eu.europa.ec.eudi.pid_mdoc"
NS = "eu.europa.ec.eudi.pid.1"
JPEG = b"\xff\xd8\xff\xe0" + bytes(range(256)) + b"\xff\xd9"  # its data URL is far longer than 150 characters
TODAY = dt.date(2026, 11, 9)
FULL_PID = {
    **PID_SUBJECT,
    "address": {
        "formatted": "Rua do Souto 7, 4700-001 Braga",
        "street_address": "Rua do Souto 7",
        "locality": "Braga",
        "region": "Braga",
        "country": "PT",
        "postal_code": "4700-001",
    },
    "picture": "data:image/jpeg;base64," + base64.b64encode(JPEG).decode(),
    "birth_family_name": "Costa",
    "birth_given_name": "Ana",
    "sex": 2,
    "email": "ana@example.pt",
    "phone_number": "+351912345678",
    "document_number": "PT-0001",
    "personal_administrative_number": "123456789",
}


def pid_settings(pki: Pki, **overrides: Any) -> dict[str, Any]:
    pid = {
        "profile": "pid_provider",
        "mdoc_signer_certificate_url": f"{ISSUER}/certs/mdoc-signer.pem",
        "batch_size": 30,
        "published_configurations": (PID_CONFIG, PID_MDOC),
    }
    return mdoc_settings(pki, **{**pid, **overrides})


@pytest.fixture
def pid_issuer(make_issuer: Callable[..., Issuer], pki: Pki) -> Issuer:
    return make_issuer(**pid_settings(pki))


@pytest.fixture
def pid_wallet(pid_issuer: Issuer, wallet_for: Callable[[Issuer], Wallet]) -> Wallet:
    return wallet_for(pid_issuer)


def offer_both(wallet: Wallet, subject: dict[str, Any]) -> Any:
    return wallet.admin("offers", {"credential_configuration_ids": [PID_MDOC, PID_CONFIG], "subject": subject})


def issue_both(wallet: Wallet, subject: dict[str, Any]) -> tuple[str, str]:
    response = offer_both(wallet, subject)
    assert response.status_code == 201, response.text
    wallet.get_token(response.json())
    mdoc = wallet.issue([EcKey.generate()], config=PID_MDOC)
    sd_jwt = wallet.issue([EcKey.generate()], config=PID_CONFIG)
    assert mdoc.status_code == 200, mdoc.text
    assert sd_jwt.status_code == 200, sd_jwt.text
    return mdoc.json()["credentials"][0]["credential"], sd_jwt.json()["credentials"][0]["credential"]


def _kept(tag: int) -> Callable[[Any, bool], cbor2.CBORTag]:
    return lambda value, _immutable: cbor2.CBORTag(tag, value)


def raw_items(credential: str) -> dict[str, Any]:
    """The data elements with every tag kept as encoded (cbor2 would read tag 1004 as a date)."""
    keep = {0: _kept(0), 1004: _kept(1004)}
    items = decoded(credential)["nameSpaces"][NS]
    out: dict[str, Any] = {}
    for item in items:
        read = cbor2.loads(item.value, semantic_decoders=keep)
        assert read["elementIdentifier"] not in out, "an element twice"
        out[read["elementIdentifier"]] = read["elementValue"]
    return out


@pytest.mark.obligation(
    "PID.MDOC.DOCTYPE_NAMESPACE",
    "PID.MDOC.ENCODING",
    "PID.MDOC.FULL_DATE_TAG1004",
    "PID.MDOC.NO_DUPLICATE_ELEMENTS",
    "PID.ATTRS.MANDATORY_AND_METADATA",
    "PID.MDOC.DOMESTIC_NAMESPACE",
)
def test_one_pid_is_issued_in_both_formats_with_the_rulebook_encoding(pid_wallet: Wallet, pki: Pki) -> None:
    mdoc, sd_jwt = issue_both(pid_wallet, FULL_PID)
    mso, elements, _ = read_mdoc(mdoc, pki)
    assert mso["docType"] == NS and set(elements) == {NS}
    items = raw_items(mdoc)
    issued = dt.datetime.fromtimestamp(int(pid_wallet.clock()), dt.UTC).date().isoformat()
    assert items == {
        "family_name": "Silva",
        "given_name": "Ana Maria",
        "birth_date": cbor2.CBORTag(1004, "1990-05-17"),
        "place_of_birth": {"locality": "Porto", "country": "PT"},
        "nationality": ["PT", "ES"],
        "resident_address": "Rua do Souto 7, 4700-001 Braga",
        "resident_street": "Rua do Souto 7",
        "resident_city": "Braga",
        "resident_state": "Braga",
        "resident_country": "PT",
        "resident_postal_code": "4700-001",
        "portrait": JPEG,
        "family_name_birth": "Costa",
        "given_name_birth": "Ana",
        "sex": 2,
        "email_address": "ana@example.pt",
        "mobile_phone_number": "+351912345678",
        "document_number": "PT-0001",
        "personal_administrative_number": "123456789",
        "issuing_authority": "Instituto dos Registos e do Notariado",
        "issuing_country": "PT",
        "issuing_jurisdiction": "PT-03",
        "expiry_date": cbor2.CBORTag(1004, "2031-11-04"),
        "issuance_date": cbor2.CBORTag(1004, issued),
    }
    # The same PID in SD-JWT VC: the street with its house number, as the Annex's resident_street.
    _, _, revealed = disclosures(sd_jwt)
    assert ["street_address", "Rua do Souto 7"] in [d[1:] for d in revealed if len(d) == 3]


@pytest.mark.obligation("PID.MDOC.X5U_X5T_PROTECTED", "PID.MDOC.CANONICAL_CBOR", "PID.MDOC.TDATE_NO_FRACTION_Z")
def test_the_mdoc_pid_names_its_signer_and_is_deterministic_cbor(pid_wallet: Wallet, pki: Pki) -> None:
    mdoc, _ = issue_both(pid_wallet, PID_SUBJECT)
    _, _, issuer_auth = read_mdoc(mdoc, pki)
    header = cbor2.loads(issuer_auth[0])
    assert header[35] == f"{ISSUER}/certs/mdoc-signer.pem" and header[34][0] == -16
    document = base64.urlsafe_b64decode(mdoc + "=" * (-len(mdoc) % 4))
    # Every structure, read back without interpretation, encodes to the same bytes in the deterministic encoding.
    assert cose.encode(cose.decode(document)) == document
    mso = cose.decode(cose.decode(issuer_auth[2]).value)
    for member in ("signed", "validFrom", "validUntil"):
        text = mso["validityInfo"][member].value
        assert text.endswith("Z") and len(text) == 20


def test_an_attribute_outside_the_annex_is_neither_published_nor_issued(
    make_issuer: Callable[..., Issuer], pki: Pki, caplog: pytest.LogCaptureFixture
) -> None:
    """The reference PID configurations list trust_anchor, the SD-JWT VC address.house_number and the mdoc
    resident_house_number, which the Annex of CIR 2024/2977 as replaced by 2026/1731 does not define (§4.1, §4.2:
    a domestic namespace or type for anything else). They still load; those claims are left out of the metadata."""
    with caplog.at_level(logging.WARNING, logger="cunho"):
        issuer = make_issuer(**pid_settings(pki))
    assert "resident_house_number" in caplog.text and "address/house_number" in caplog.text
    supported = issuer.issuer_metadata()["credential_configurations_supported"]
    mdoc_names = {c["path"][1] for c in supported[PID_MDOC]["credential_metadata"]["claims"]}
    assert not mdoc_names & {"resident_house_number", "trust_anchor"} and "resident_street" in mdoc_names
    sd_jwt_paths = [c["path"] for c in supported[PID_CONFIG]["credential_metadata"]["claims"]]
    assert ["address", "house_number"] not in sd_jwt_paths and ["trust_anchor"] not in sd_jwt_paths
    assert ["address", "street_address"] in sd_jwt_paths


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"trust_anchor": "https://issuer.test/trust"}, "trust_anchor: not in the Annex of CIR 2024/2977"),
        ({"attestation_legal_category": "PID"}, "attestation_legal_category: not in the Annex of CIR 2024/2977"),
        (
            {"address": {"street_address": "Rua do Souto", "house_number": "7"}},
            "address.house_number: not in the Annex of CIR 2024/2977",
        ),
    ],
)
@pytest.mark.parametrize("ids", [[PID_CONFIG], [PID_MDOC, PID_CONFIG]])
def test_a_pid_attribute_outside_the_annex_is_refused_in_both_formats(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Wallet],
    pki: Pki,
    change: dict[str, Any],
    reason: str,
    ids: list[str],
) -> None:
    issuer = make_issuer(**pid_settings(pki)) if len(ids) == 2 else make_issuer()
    wallet = wallet_for(issuer)
    # The SD-JWT VC configuration alone may refuse the claim first, as one it does not list.
    refused_by(
        lambda: wallet.admin("offers", {"credential_configuration_ids": ids, "subject": {**PID_SUBJECT, **change}}),
        "EAA.RULEBOOK.CONFORMANCE",
        reason if len(ids) == 2 else reason.split(":")[0],
    )
    if len(ids) == 1:
        assert any(reason in p for p in validate_pid({**PID_SUBJECT, **change}, TODAY))


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda s: {**s, "family_name": "x" * 151}, "family_name: text longer than 150 characters"),
        (
            lambda s: {**s, "place_of_birth": {"locality": "y" * 151}},
            "place_of_birth: text longer than 150 characters",
        ),
        (lambda s: {**s, "address": {"street_address": "z" * 151}}, "address.street_address: text longer than 150"),
        (lambda s: {k: v for k, v in s.items() if k != "date_of_expiry"}, "date_of_expiry: mandatory in the mdoc PID"),
        (lambda s: {**s, "place_of_birth": {}}, "place_of_birth: needs at least one of"),
        (lambda s: {**s, "family_name": 123}, "family_name: must be a non-empty string"),
        (lambda s: {**s, "issuing_authority": " "}, "issuing_authority: must be a non-empty string"),
        (lambda s: {**s, "document_number": ["PT-1"]}, "document_number: must be a non-empty string"),
        (lambda s: {**s, "date_of_expiry": "nonsense"}, "date_of_expiry: must be a calendar date"),
        (lambda s: {**s, "date_of_issuance": "2026-02-30"}, "date_of_issuance: must be a calendar date"),
        (lambda s: {**s, "date_of_issuance": "2031-11-05"}, "date_of_expiry: is before date_of_issuance"),
        (lambda s: {**s, "date_of_expiry": "2020-01-01"}, "date_of_expiry: is in the past"),
        (lambda s: {**s, "picture": "data:image/jpeg;base64,A"}, "picture: must be a data URL with a base64 JPEG"),
        (lambda s: {**s, "picture": None}, "picture: must be a data URL with a base64 JPEG"),
    ],
)
@pytest.mark.obligation("PID.MDOC.TSTR_MAX150", "PID.MDOC.PLACE_OF_BIRTH_NONEMPTY")
def test_the_mdoc_pid_is_checked_at_the_offer(
    pid_wallet: Wallet, change: Callable[[dict[str, Any]], dict[str, Any]], reason: str
) -> None:
    response = refused_by(lambda: offer_both(pid_wallet, change(PID_SUBJECT)), "EAA.RULEBOOK.CONFORMANCE", reason)
    assert response.status_code == 400


@pytest.mark.parametrize(
    "change",
    [
        {"picture": ""},
        {"date_of_issuance": "2026-11-01"},
        {"date_of_issuance": "2031-11-04"},  # issued and expiring the same day
        {"date_of_expiry": TODAY.isoformat()},  # expiring today
    ],
)
def test_an_mdoc_only_pid_with_valid_values_is_checked_alone(pid_issuer: Issuer, change: dict[str, Any]) -> None:
    """The mdoc may be the only format a wallet asks for: its check stands on its own."""
    config = pid_issuer.configs.get(PID_MDOC)
    assert config is not None
    assert validate_pid_mdoc(config, {**PID_SUBJECT, **change}, TODAY) == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"date_of_expiry": "nonsense"}, "date_of_expiry: must be a calendar date YYYY-MM-DD"),
        ({"date_of_issuance": "2026-02-30"}, "date_of_issuance: must be a calendar date YYYY-MM-DD"),
        ({"picture": None}, "picture: must be a data URL with a base64 JPEG that decodes"),
        ({"date_of_issuance": "2031-11-05"}, "date_of_expiry: is before date_of_issuance"),
        ({"date_of_expiry": "2026-11-08"}, "date_of_expiry: is in the past"),
    ],
)
def test_an_mdoc_only_pid_with_a_bad_value_is_refused_by_its_own_check(
    pid_issuer: Issuer, change: dict[str, Any], problem: str
) -> None:
    config = pid_issuer.configs.get(PID_MDOC)
    assert config is not None
    assert problem in validate_pid_mdoc(config, {**PID_SUBJECT, **change}, TODAY)


def test_150_characters_is_the_limit(pid_wallet: Wallet) -> None:
    assert offer_both(pid_wallet, {**PID_SUBJECT, "family_name": "x" * 150}).status_code == 201


@pytest.mark.obligation("PID.MDOC.UTF8")
def test_mdoc_pid_text_is_valid_unicode(pid_issuer: Issuer) -> None:
    config = pid_issuer.configs.get(PID_MDOC)
    assert config is not None
    assert any("valid Unicode" in p for p in validate_pid_mdoc(config, {**PID_SUBJECT, "given_name": "\ud800"}, TODAY))
    assert validate_pid_mdoc(config, [PID_SUBJECT], TODAY) == ["subject data must be a JSON object"]


@pytest.mark.covers("VCI.FORMATS.ALL_RULEBOOK")
@pytest.mark.parametrize("ids", [[PID_CONFIG], [PID_MDOC]])
def test_a_pid_is_offered_in_both_formats(pid_wallet: Wallet, ids: list[str]) -> None:
    refused_by(
        lambda: pid_wallet.admin("offers", {"credential_configuration_ids": ids, "subject": PID_SUBJECT}),
        "VCI.FORMATS.ALL_RULEBOOK",
        "both formats",
    )


def test_an_sd_jwt_only_deployment_offers_the_pid_alone(wallet: Wallet) -> None:
    assert wallet.offer(configs=[PID_CONFIG])["credential_offer"]


def test_the_mdoc_pid_ends_with_the_document(pid_wallet: Wallet, pki: Pki) -> None:
    soon = (dt.datetime.fromtimestamp(pid_wallet.clock(), dt.UTC) + dt.timedelta(days=3)).date()
    mdoc, _ = issue_both(pid_wallet, {**PID_SUBJECT, "date_of_expiry": soon.isoformat()})
    mso, _, _ = read_mdoc(mdoc, pki)
    assert mso["validityInfo"]["validUntil"] <= dt.datetime.combine(soon, dt.time.max, dt.UTC)


def test_production_issues_the_pid_in_both_formats(pki: Pki, tmp_path: Path) -> None:
    both = Settings(**production_kwargs(pki, tmp_path))
    metadata.load(both, mdoc_alg="ES256")
    with pytest.raises(ConfigError, match="issues the PID in both formats"):
        metadata.load(both, mdoc_alg=None)
    sd_jwt_only = Settings(**production_kwargs(pki, tmp_path, published_configurations=(PID_CONFIG,)))
    with pytest.raises(ConfigError, match="issues the PID in both formats"):
        metadata.load(sd_jwt_only, mdoc_alg="ES256")


def edited(tmp_path: Path, change: Callable[[dict[str, Any]], None]) -> Path:
    folder = tmp_path / "metadata"
    shutil.copytree(DEFAULT_METADATA_DIR, folder)
    path = folder / "credentials_supported" / "pid_mdoc.json"
    configs = json.loads(path.read_text())
    change(configs[PID_MDOC])
    path.write_text(json.dumps(configs))
    return folder


def test_a_domestic_namespace_is_not_issued_yet(make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path) -> None:
    def domestic(config: dict[str, Any]) -> None:
        config["credential_metadata"]["claims"].append({"path": ["pt.gov.pid.1", "tax_id"], "value_type": "string"})

    issuer = make_issuer(**pid_settings(pki, metadata_dir=edited(tmp_path, domestic), published_configurations=None))
    assert "no domestic namespace" in issuer.configs.findings[PID_MDOC]
    assert PID_MDOC not in issuer.configs.published


def test_the_mdoc_pid_has_the_pid_document_type() -> None:
    config = {
        "format": "mso_mdoc",
        "doctype": "org.example.pid",
        "vct": "urn:eudi:pid:1",
        "scope": "pid",
        "cryptographic_binding_methods_supported": ["cose_key"],
        "proof_types_supported": {
            "jwt": {
                "proof_signing_alg_values_supported": ["ES256"],
                "key_attestations_required": {"key_storage": ["iso_18045_high"]},
            }
        },
        "credential_metadata": {"claims": [{"path": [NS, "family_name"]}]},
    }
    with pytest.raises(ConfigError, match="document type is eu.europa.ec.eudi.pid.1"):
        metadata.validate("pid", config, 2)


def test_only_the_elements_the_configuration_lists_are_issued(pid_issuer: Issuer) -> None:
    """Defence in depth behind the offer check: a claim without an element in the configuration never reaches the
    mdoc, nor does the SD-JWT VC house number."""
    config = pid_issuer.configs.get(PID_MDOC)
    assert config is not None
    elements = pid_elements(config, {**FULL_PID, "trust_anchor": "https://issuer.test/trust"})[NS]
    assert "trust_anchor" not in elements and "resident_house_number" not in elements
    assert set(elements) <= set(pid_mdoc_elements(config))


def test_a_configuration_that_does_not_exist_is_not_published(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    with pytest.raises(ConfigError, match="cannot publish"):
        make_issuer(**pid_settings(pki, published_configurations=(PID_CONFIG, PID_MDOC, "org.example.nothing")))


def test_an_offer_without_a_pid_is_not_held_to_both_formats(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    photo = "eu.europa.ec.eudi.photoid"
    issuer = make_issuer(**pid_settings(pki, published_configurations=(PID_CONFIG, PID_MDOC, photo)))
    wallet = wallet_for(issuer)
    from .test_mdoc import PHOTO_SUBJECT

    response = wallet.admin("offers", {"credential_configuration_ids": [photo], "subject": PHOTO_SUBJECT})
    assert response.status_code == 201, response.text


def without_element(config: dict[str, Any], element: str) -> dict[str, Any]:
    trimmed = json.loads(json.dumps(config))
    claims = trimmed["credential_metadata"]["claims"]
    trimmed["credential_metadata"]["claims"] = [c for c in claims if c.get("path") != [NS, element]]
    return trimmed


def test_a_claim_the_mdoc_configuration_has_no_element_for(pid_issuer: Issuer) -> None:
    """A configuration may leave out an optional element of the rulebook: a PID that has it is refused at the offer,
    and the encoder, behind that check, never issues it."""
    config = pid_issuer.configs.get(PID_MDOC)
    assert config is not None
    trimmed = without_element(config, "document_number")
    subject = {**PID_SUBJECT, "document_number": "PT-0001"}
    assert "document_number: the mdoc PID configuration has no data element document_number" in validate_pid_mdoc(
        trimmed, subject, TODAY
    )
    assert "document_number" not in pid_elements(trimmed, subject)[NS]
    assert pid_elements(config, subject)[NS]["document_number"] == "PT-0001"


def test_an_issuance_date_without_an_expiry_is_a_problem_not_an_error(pid_issuer: Issuer) -> None:
    config = pid_issuer.configs.get(PID_MDOC)
    assert config is not None
    subject = {k: v for k, v in PID_SUBJECT.items() if k != "date_of_expiry"} | {"date_of_issuance": "2026-11-01"}
    problems = validate_pid_mdoc(config, subject, TODAY)
    assert problems == ["date_of_expiry: mandatory in the mdoc PID and missing"]
