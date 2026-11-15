"""mdoc issuance (OpenID4VCI 1.0 App. A.2): the IssuerSigned structure, its Mobile Security Object and the status list
in CWT form. Every credential here is read back with cbor2 and cryptography alone, so cunho's own COSE code does not
judge its own output."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import shutil
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cunho import metadata
from cunho.credentials import validate_mdoc_subject
from cunho.errors import ConfigError
from cunho.jose import b64u_decode
from cunho.service import Issuer, check_document_signer, status_list_anchor
from cunho.settings import DEFAULT_METADATA_DIR, Settings
from cunho.signer import FileSigner
from eudi_probe.jose import EcKey

from .helpers import ISSUER, Pki, Wallet, disclosures, production_kwargs, refused_by, settings_kwargs
from .helpers import certificate as helper_certificate
from .helpers import pem as helper_pem

IBAN = "eu.europa.ec.eudi.iban_mdoc"
IBAN_NS = "eu.europa.ec.eudi.iban.1"
PHOTO = "eu.europa.ec.eudi.photoid"
PHOTO_NS = "org.iso.23220.photoid.1"
JPEG = b"\xff\xd8\xff\xe0 a tiny jpeg \xff\xd9"
IBAN_SUBJECT = {
    IBAN_NS: {
        "iban": "PT50000201231234567890154",
        "currency": "EUR",
        "bank_account_status": "active",
        "payment_possibility": True,
        "registered_family_name": "Silva",
        "registered_given_name": "Ana",
        "date_of_birth": "1990-07-04",
        "account_holder_owner": True,
        "coowner": False,
        "issuing_organization": "Banco de Teste",
        "expiry_date": "2030-01-01",
        "credential_type": "iban",
        "business_identifier_code": "TESTPTPL",
    }
}
PHOTO_SUBJECT = {
    PHOTO_NS: {
        "portrait": "data:image/jpeg;base64," + base64.b64encode(JPEG).decode(),
        "family_name_unicode": "Silva",
        "given_name_unicode": "Ana",
        "birth_date": "1990-07-04",
        "age_over_18": True,
        "age_in_years": 36,
        "expiry_date": "2030-01-01",
        "issuing_authority_unicode": "Autoridade de Teste",
        "issuing_country": "PT",
    }
}


def mdoc_settings(pki: Pki, **overrides: Any) -> dict[str, Any]:
    return {
        "profile": "eaa_provider",
        "mdoc_signing_key": pki.root / "mdoc-signing.key",
        "mdoc_signing_chain": pki.root / "mdoc-signing.pem",
        "mdoc_trust_anchors": pki.root / "iaca.pem",
        "published_configurations": (IBAN, PHOTO),
        **overrides,
    }


@pytest.fixture
def mdoc_issuer(make_issuer: Callable[..., Issuer], pki: Pki) -> Issuer:
    return make_issuer(**mdoc_settings(pki))


@pytest.fixture
def mdoc_wallet(mdoc_issuer: Issuer, wallet_for: Callable[[Issuer], Wallet]) -> Wallet:
    return wallet_for(mdoc_issuer)


def iaca(pki: Pki) -> x509.Certificate:
    return x509.load_pem_x509_certificate((pki.root / "iaca.pem").read_bytes())


def ecdsa_verify(key: Any, signature: bytes, data: bytes) -> None:
    half = len(signature) // 2
    der = encode_dss_signature(int.from_bytes(signature[:half]), int.from_bytes(signature[half:]))
    key.verify(der, data, ec.ECDSA(hashes.SHA256()))


def read_mdoc(credential: str, pki: Pki) -> tuple[dict[Any, Any], dict[str, dict[str, Any]], list[Any]]:
    """Verify an mdoc as a relying party would (ISO/IEC 18013-5 §9.3.1): the document signer chains to the IACA, the
    COSE_Sign1 verifies over the MSO, and every item's digest is in the MSO. Returns the MSO, the elements by
    namespace and the issuerAuth."""
    document = decoded(credential)
    assert set(document) == {"nameSpaces", "issuerAuth"}
    protected, unprotected, payload, signature = document["issuerAuth"]
    assert cbor2.loads(protected)[1] == -7
    signer = x509.load_der_x509_certificate(unprotected[33])
    signer.verify_directly_issued_by(iaca(pki))
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload])
    ecdsa_verify(signer.public_key(), signature, to_be_signed)
    wrapped = cbor2.loads(payload)
    assert wrapped.tag == 24
    mso = cbor2.loads(wrapped.value)
    elements: dict[str, dict[str, Any]] = {}
    for ns, items in document["nameSpaces"].items():
        for wrapped_item in items:
            assert wrapped_item.tag == 24
            item = cbor2.loads(wrapped_item.value)
            assert mso["valueDigests"][ns][item["digestID"]] == hashlib.sha256(cbor2.dumps(wrapped_item)).digest()
            assert len(item["random"]) >= 16
            elements.setdefault(ns, {})[item["elementIdentifier"]] = item["elementValue"]
    assert {ns: len(d) for ns, d in mso["valueDigests"].items()} == {ns: len(e) for ns, e in elements.items()}
    return mso, elements, document["issuerAuth"]


def issue(wallet: Wallet, config: str, subject: dict[str, Any], holders: list[EcKey]) -> list[str]:
    offer = wallet.offer(subject, configs=[config])
    wallet.get_token(offer)
    response = wallet.issue(holders, config=config)
    assert response.status_code == 200, response.text
    wallet.subject_ref = offer["subject_ref"]  # type: ignore[attr-defined]
    return [c["credential"] for c in response.json()["credentials"]]


def decoded(credential: str) -> Any:
    return cbor2.loads(base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4)))


@pytest.mark.obligation("FMT.MDOC.MSO_VERIFIES", "FMT.MDOC.ISSUERAUTH_X5CHAIN", "FMT.MDOC.CONFIG_AND_ENCODING")
def test_an_mdoc_verifies_under_its_document_signer(mdoc_wallet: Wallet, pki: Pki) -> None:
    holder = EcKey.generate()
    [credential] = issue(mdoc_wallet, IBAN, IBAN_SUBJECT, [holder])
    mso, elements, issuer_auth = read_mdoc(credential, pki)
    assert mso["version"] == "1.0" and mso["digestAlgorithm"] == "SHA-256"
    assert mso["docType"] == "eu.europa.ec.eudi.iban.1"
    key = mso["deviceKeyInfo"]["deviceKey"]
    jwk = holder.public_jwk()
    assert key == {1: 2, -1: 1, -2: b64u_decode(jwk["x"]), -3: b64u_decode(jwk["y"])}
    # The document signer alone goes in x5chain; the IACA is the verifier's trust anchor.
    assert isinstance(issuer_auth[1][33], bytes)
    sent = IBAN_SUBJECT[IBAN_NS]
    got = elements[IBAN_NS]
    assert got["date_of_birth"] == dt.date(1990, 7, 4)  # tag 1004, read back by cbor2 as a date
    assert {k: v for k, v in got.items() if k not in ("date_of_birth", "issuance_date")} == {
        k: v for k, v in sent.items() if k != "date_of_birth"
    }
    assert got["issuance_date"] == dt.datetime.fromtimestamp(int(mdoc_wallet.clock()), dt.UTC).date().isoformat()


def test_validity_is_whole_seconds_in_utc(mdoc_issuer: Issuer, mdoc_wallet: Wallet, pki: Pki) -> None:
    [credential] = issue(mdoc_wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    document = decoded(credential)
    payload = cbor2.loads(document["issuerAuth"][2])
    raw = cbor2.loads(payload.value, semantic_decoders={0: lambda value, _: value})
    validity = raw["validityInfo"]
    for member in ("signed", "validFrom", "validUntil"):
        assert len(validity[member]) == 20 and validity[member].endswith("Z") and "." not in validity[member]
    assert validity["signed"] == validity["validFrom"] < validity["validUntil"]
    mso, _, _ = read_mdoc(credential, pki)
    days = (mso["validityInfo"]["validUntil"] - mso["validityInfo"]["validFrom"]).days
    assert days == mdoc_issuer.settings.credential_validity_days


@pytest.mark.parametrize("started", [1200, 2400])
def test_an_mdoc_is_never_signed_before_its_signer_certificate(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Wallet],
    pki: Pki,
    clock: Any,
    tmp_path: Path,
    started: int,
) -> None:
    """ISO/IEC 18013-5 §9.3.1: the MSO is signed while the document signer certificate is valid. A certificate put
    in use after the start of the hour the coarse time rounds to gives the mdoc its own start (1200 s); one not
    valid yet (2400 s, after the time of issuance) changes nothing, and is the operator's to replace."""
    hour = int(clock.now) // 3600 * 3600
    clock.now = hour + 1800
    iaca_key, ds_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    iaca = helper_certificate("Fresh IACA", iaca_key, ca=True, path_length=0)
    purpose = x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.0.18013.5.1.2")])
    begins = dt.datetime.fromtimestamp(hour + started, dt.UTC)
    ds = helper_certificate(
        "Fresh Document Signer", ds_key, (iaca, iaca_key), not_before=begins, extensions=[(purpose, True)]
    )
    (tmp_path / "ds.key").write_bytes(
        ds_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (tmp_path / "ds.pem").write_bytes(helper_pem(ds) + helper_pem(iaca))
    (tmp_path / "iaca.pem").write_bytes(helper_pem(iaca))
    issuer = make_issuer(
        **mdoc_settings(
            pki,
            mdoc_signing_key=tmp_path / "ds.key",
            mdoc_signing_chain=tmp_path / "ds.pem",
            mdoc_trust_anchors=tmp_path / "iaca.pem",
        )
    )
    [credential] = issue(wallet_for(issuer), IBAN, IBAN_SUBJECT, [EcKey.generate()])
    payload = cbor2.loads(decoded(credential)["issuerAuth"][2])
    validity = cbor2.loads(payload.value)["validityInfo"]
    expected = hour + started if started <= 1800 else hour
    assert validity["signed"] == validity["validFrom"] == dt.datetime.fromtimestamp(expected, dt.UTC)


@pytest.mark.obligation("STATUS.MDOC_BITS1_UNIQUE_IDX")
def test_a_batch_shares_no_salt_digest_id_or_status_entry(mdoc_wallet: Wallet, pki: Pki) -> None:
    holders = [EcKey.generate(), EcKey.generate()]
    credentials = issue(mdoc_wallet, IBAN, IBAN_SUBJECT, holders)
    read = [read_mdoc(c, pki) for c in credentials]
    assert [m["deviceKeyInfo"]["deviceKey"][-2] for m, _, _ in read] == [
        b64u_decode(h.public_jwk()["x"]) for h in holders
    ]
    statuses = [(m["status"]["status_list"]["uri"], m["status"]["status_list"]["idx"]) for m, _, _ in read]
    assert len(set(statuses)) == 2
    ids = [set(m["valueDigests"][IBAN_NS]) for m, _, _ in read]
    assert ids[0] != ids[1]
    salts = [
        cbor2.loads(item.value)["random"]
        for credential in credentials
        for item in decoded(credential)["nameSpaces"][IBAN_NS]
    ]
    assert len(set(salts)) == len(salts)


@pytest.mark.obligation("STATUS.SHORTLIVED_OR_LIST")
def test_a_credential_that_lives_one_day_still_has_a_status_entry(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """ARF VCR_01 and VCR_01b ask for a status list or a short life; cunho always uses the list, in both formats,
    even for a credential of 24 hours, which EAA-4.2.13-03 would let go without one."""
    mdoc_wallet = wallet_for(make_issuer(**mdoc_settings(pki, credential_validity_days=1)))
    [credential] = issue(mdoc_wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    mso, _, _ = read_mdoc(credential, pki)
    assert mso["validityInfo"]["validUntil"] - mso["validityInfo"]["validFrom"] <= dt.timedelta(days=1)
    assert set(mso["status"]["status_list"]) >= {"idx", "uri"}
    sd_jwt_wallet = wallet_for(make_issuer(credential_validity_days=1))
    response = sd_jwt_wallet.issue()
    assert response.status_code == 200, response.text
    claims = disclosures(response.json()["credentials"][0]["credential"])[1]
    assert claims["exp"] - claims["nbf"] <= 86_400 and set(claims["status"]["status_list"]) == {"idx", "uri"}


@pytest.mark.obligation("STATUS.MDOC_MECHANISM", "STATUS.MDOC_CWT_PROFILE")
def test_the_status_entry_of_an_mdoc_is_read_from_the_cwt_list(
    mdoc_issuer: Issuer, mdoc_wallet: Wallet, pki: Pki
) -> None:
    [credential] = issue(mdoc_wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    mso, _, _ = read_mdoc(credential, pki)
    reference = mso["status"]["status_list"]
    assert set(reference) == {"idx", "uri", "certificate"} and reference["uri"].startswith(f"{ISSUER}/status/")
    # CIR 2024/2979 Annex II EAA-6.2.10.1-06.1: the relying party's trust anchor for the list's x5chain.
    anchor = x509.load_der_x509_certificate(reference["certificate"])

    def bit() -> int:
        response = mdoc_wallet.client.get(reference["uri"], headers={"Accept": "application/statuslist+cwt"})
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/statuslist+cwt"
        assert response.headers["vary"] == "Accept"
        token = cbor2.loads(response.content)
        assert token.tag == 18  # COSE_Sign1_Tagged, not wrapped in the CWT tag (draft-21 §5.2)
        protected, unprotected, payload, signature = token.value
        header = cbor2.loads(protected)
        assert header[1] == -7 and header[16] == "application/statuslist+cwt" and unprotected == {}
        chain = [
            x509.load_der_x509_certificate(c) for c in ([header[33]] if isinstance(header[33], bytes) else header[33])
        ]
        for child, parent in zip(chain, chain[1:], strict=False):
            child.verify_directly_issued_by(parent)
        if chain[-1] != anchor:
            chain[-1].verify_directly_issued_by(anchor)
        ecdsa_verify(chain[0].public_key(), signature, cbor2.dumps(["Signature1", protected, b"", payload]))
        claims = cbor2.loads(payload)
        assert claims[2] == reference["uri"] and claims[4] > claims[6] and claims[65534] > 0
        assert claims[65533]["bits"] == 1
        bits = zlib.decompress(claims[65533]["lst"])
        return (bits[reference["idx"] // 8] >> (reference["idx"] % 8)) & 1

    assert bit() == 0
    subject_ref = mdoc_wallet.subject_ref  # type: ignore[attr-defined]
    assert mdoc_wallet.admin("revocations", {"subject_ref": subject_ref, "reason": "user_request"}).status_code == 200
    mdoc_wallet.clock.now += mdoc_issuer.settings.status_publish_interval
    assert bit() == 1


@pytest.mark.parametrize(
    ("accept", "form"),
    [
        (None, "jwt"),
        ("application/statuslist+jwt", "jwt"),
        ("*/*", "jwt"),
        ("application/statuslist+cwt", "cwt"),
        ("application/statuslist+jwt;q=0.5, application/statuslist+cwt", "cwt"),
        ("application/statuslist+jwt, application/statuslist+cwt;q=0.9", "jwt"),
        ("application/statuslist+cwt;q=0", "jwt"),
        ("application/statuslist+cwt;q=nonsense", "jwt"),
        ("application/statuslist+cwt;q=2", "jwt"),
    ],
)
def test_the_status_list_form_follows_accept(mdoc_wallet: Wallet, accept: str | None, form: str) -> None:
    [credential] = issue(mdoc_wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    document = decoded(credential)
    uri = cbor2.loads(cbor2.loads(document["issuerAuth"][2]).value)["status"]["status_list"]["uri"]
    response = mdoc_wallet.client.get(uri, headers={"Accept": accept} if accept else {})
    assert response.headers["content-type"] == f"application/statuslist+{form}"
    assert (response.content[:1] == b"\xd2") == (form == "cwt")


def test_the_jwt_and_cwt_lists_carry_the_same_bits(mdoc_issuer: Issuer, mdoc_wallet: Wallet) -> None:
    issue(mdoc_wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    [list_id] = mdoc_issuer.status.lists()
    jwt = mdoc_issuer.status_token(list_id)
    cwt = mdoc_issuer.status_cwt(list_id)
    assert isinstance(jwt, str) and isinstance(cwt, bytes)
    payload = json.loads(b64u_decode(jwt.split(".")[1]))
    claims = cbor2.loads(cbor2.loads(cwt).value[2])
    assert b64u_decode(payload["status_list"]["lst"]) == claims[65533]["lst"]
    assert (payload["sub"], payload["iat"], payload["exp"], payload["ttl"]) == (
        claims[2],
        claims[6],
        claims[4],
        claims[65534],
    )
    assert mdoc_issuer.status_cwt(list_id) is cwt  # signed once per publication


def test_a_portrait_and_a_date_take_their_cbor_types(mdoc_wallet: Wallet, pki: Pki) -> None:
    [credential] = issue(mdoc_wallet, PHOTO, PHOTO_SUBJECT, [EcKey.generate()])
    _, elements, _ = read_mdoc(credential, pki)
    got = elements[PHOTO_NS]
    assert got["portrait"] == JPEG and got["birth_date"] == dt.date(1990, 7, 4)
    assert got["age_over_18"] is True and got["age_in_years"] == 36


def test_the_published_mdoc_configuration_is_bound_to_a_cose_key(mdoc_issuer: Issuer) -> None:
    published = mdoc_issuer.issuer_metadata()["credential_configurations_supported"][IBAN]
    assert published["format"] == "mso_mdoc" and published["doctype"] == "eu.europa.ec.eudi.iban.1"
    assert published["cryptographic_binding_methods_supported"] == ["cose_key"]
    assert published["credential_signing_alg_values_supported"] == [-7]
    assert "policy" not in published and "issuer_config" not in published


def test_mdoc_is_published_by_default_only_with_a_document_signer(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    with_signer = make_issuer(**mdoc_settings(pki, published_configurations=None))
    assert IBAN in with_signer.configs.published and PHOTO in with_signer.configs.published
    without = make_issuer(profile="eaa_provider")
    assert not any(c.get("format") == "mso_mdoc" for c in without.configs.issuable().values())
    with pytest.raises(ConfigError, match="mdoc needs a document signer"):
        make_issuer(profile="eaa_provider", published_configurations=(IBAN,))


@pytest.mark.parametrize(
    ("name", "reason"), [("mdoc-plain", "has no extended key usage"), ("mdoc-tls", "lacks id-mdl-kp-mdlDS")]
)
def test_a_document_signer_without_the_mdoc_purpose_does_not_start(
    make_issuer: Callable[..., Issuer], pki: Pki, name: str, reason: str
) -> None:
    with pytest.raises(ConfigError, match=reason):
        make_issuer(
            **mdoc_settings(pki, mdoc_signing_key=pki.root / f"{name}.key", mdoc_signing_chain=pki.root / f"{name}.pem")
        )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"mdoc_signing_chain": None}, "go together"),
        ({"mdoc_signing_key": None}, "go together"),
        ({"profile": "qeaa_provider"}, "mdoc_signer_certificate_url"),
        ({"mdoc_signer_certificate_url": "http://issuer.test/certs/mdoc-signer.pem"}, "must use https"),
        ({"mdoc_signer_certificate_url": f"{ISSUER}/elsewhere.pem"}, "only at"),
    ],
)
def test_document_signer_settings_are_checked(pki: Pki, overrides: dict[str, Any], reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        Settings(**settings_kwargs(pki, **mdoc_settings(pki, **overrides)))


def test_a_qualified_provider_names_its_document_signer_by_x5u_and_x5t(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    url = f"{ISSUER}/certs/mdoc-signer.pem"
    issuer = make_issuer(**mdoc_settings(pki, profile="qeaa_provider", mdoc_signer_certificate_url=url))
    wallet = wallet_for(issuer)
    [credential] = issue(wallet, IBAN, IBAN_SUBJECT, [EcKey.generate()])
    _, _, issuer_auth = read_mdoc(credential, pki)
    header = cbor2.loads(issuer_auth[0])
    signer = issuer_auth[1][33]
    assert header[35] == url and header[34] == [-16, hashlib.sha256(signer).digest()]
    served = x509.load_pem_x509_certificates(wallet.client.get(url).content)
    assert [c.public_bytes(serialization.Encoding.DER) for c in served] == [signer]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda s: {**s, "other.namespace": {}}, "not a namespace of this credential configuration"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "nickname": "x"}}, "not a data element"),
        (lambda s: {IBAN_NS: {k: v for k, v in s[IBAN_NS].items() if k != "iban"}}, "iban: mandatory and missing"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "payment_possibility": "yes"}}, "must be true or false"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "currency": ""}}, "must be a non-empty string"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "date_of_birth": "04/07/1990"}}, "calendar date"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "credential_type": 1.5}}, "numbers must be integers"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "expiry_date": "2020-01-01"}}, "is in the past"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "expiry_date": "yesterday"}}, "expiry_date: must be a calendar date"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "expiry_date": None}}, "expiry_date: must be a calendar date"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "expiry_date": {"y": 2030}}}, "expiry_date: must be a calendar date"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "issuance_date": "2026-13-01"}}, "issuance_date: must be a calendar date"),
        (lambda s: {IBAN_NS: "not an object"}, "must be an object of data elements"),
        (lambda s: [s], "JSON object of namespaces"),
    ],
)
def test_mdoc_subject_data_is_checked_against_the_configuration(
    mdoc_wallet: Wallet, change: Callable[[dict[str, Any]], Any], reason: str
) -> None:
    response = refused_by(
        lambda: mdoc_wallet.admin("offers", {"credential_configuration_ids": [IBAN], "subject": change(IBAN_SUBJECT)}),
        "EAA.RULEBOOK.CONFORMANCE",
        reason,
    )
    assert response.status_code == 400


@pytest.mark.parametrize(
    ("element", "value", "reason"),
    [
        ("portrait", "data:image/png;base64,AAAA", "base64 JPEG"),
        ("portrait", "data:image/jpeg;base64,A", "base64 JPEG"),
        ("portrait", "data:image/jpeg;base64,AAA=AAA=", "base64 JPEG"),
        ("age_in_years", -1, "non-negative integer"),
        ("age_in_years", True, "non-negative integer"),
    ],
)
def test_a_portrait_and_an_unsigned_integer_are_checked(
    mdoc_wallet: Wallet, element: str, value: Any, reason: str
) -> None:
    subject = {PHOTO_NS: {**PHOTO_SUBJECT[PHOTO_NS], element: value}}
    refused_by(
        lambda: mdoc_wallet.admin("offers", {"credential_configuration_ids": [PHOTO], "subject": subject}),
        "EAA.RULEBOOK.CONFORMANCE",
        reason,
    )


def config(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "format": "mso_mdoc",
        "doctype": "org.example.test.1",
        "scope": "org.example.test",
        "cryptographic_binding_methods_supported": ["cose_key"],
        "credential_signing_alg_values_supported": [-7],
        "proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        "credential_metadata": {
            "claims": [{"path": ["org.example.test.1", "name"], "value_type": "string"}],
            "credential_reuse_policy": {
                "id": "arf_annex_ii",
                "options": [{"details": ["limited_time"], "reissue_trigger_lifetime_left": 7_776_000}],
            },
        },
    }
    return {**base, **changes}


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"doctype": None}, "without doctype"),
        ({"doctype": 5}, "without doctype"),
        ({"cryptographic_binding_methods_supported": "cose_key"}, "needs cose_key"),
        ({"credential_signing_alg_values_supported": {}}, "COSE algorithm values"),
        (
            {"credential_metadata": {**config()["credential_metadata"], "claims": {"x": {"path": ["ns", "a"]}}}},
            "lists its data elements",
        ),
        (
            {
                "credential_metadata": {
                    **config()["credential_metadata"],
                    "claims": [["overall_issuer_conditions"], {"path": ["ns", "a"]}],
                }
            },
            "[namespace, data element identifier]",
        ),
        (
            {"credential_metadata": {**config()["credential_metadata"], "claims": [{}, {"path": ["ns", "a"]}]}},
            "[namespace, data element identifier]",
        ),
        (
            {"credential_metadata": {**config()["credential_metadata"], "claims": [{"path": "ab"}]}},
            "[namespace, data element identifier]",
        ),
        ({"doctype": ""}, "without doctype"),
        ({"cryptographic_binding_methods_supported": ["jwk"]}, "needs cose_key"),
        ({"credential_signing_alg_values_supported": ["ES256"]}, "COSE algorithm values"),
        ({"credential_signing_alg_values_supported": [True]}, "COSE algorithm values"),
        ({"credential_metadata": {**config()["credential_metadata"], "claims": []}}, "lists its data elements"),
        (
            {"credential_metadata": {**config()["credential_metadata"], "claims": [{"path": ["name"]}]}},
            "[namespace, data element identifier]",
        ),
        (
            {"credential_metadata": {**config()["credential_metadata"], "claims": [{"path": ["ns", 1]}]}},
            "[namespace, data element identifier]",
        ),
        (
            {
                "credential_metadata": {
                    **config()["credential_metadata"],
                    "claims": [{"path": ["ns", "a"]}, {"path": ["ns", "a"]}],
                }
            },
            "listed twice",
        ),
        (
            {
                "credential_metadata": {
                    **config()["credential_metadata"],
                    "claims": [{"path": ["ns", "a"], "value_type": 3}],
                }
            },
            "value_type must be a string",
        ),
    ],
)
def test_an_mdoc_configuration_is_checked_at_startup(changes: dict[str, Any], reason: str) -> None:
    metadata.validate("test", config(), 2)
    with pytest.raises(ConfigError, match=reason.replace("[", r"\[").replace("]", r"\]")):
        metadata.validate("test", config(**changes), 2)


def test_an_ec_internal_claim_entry_is_not_a_data_element() -> None:
    claims = [{"overall_issuer_conditions": {"at_least_one_of": ["name"]}}, {"path": ["ns", "name"]}]
    metadata.validate("test", config(credential_metadata={**config()["credential_metadata"], "claims": claims}), 2)
    every_internal_key = {key: 1 for key in metadata.INTERNAL_KEYS}
    claims = [every_internal_key, {"path": ["ns", "name"]}]
    metadata.validate("test", config(credential_metadata={**config()["credential_metadata"], "claims": claims}), 2)


def test_an_mdoc_configuration_may_leave_out_its_algorithms(
    make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path
) -> None:
    metadata.validate("test", config(credential_signing_alg_values_supported=None), 2)
    folder = tmp_path / "metadata"
    shutil.copytree(DEFAULT_METADATA_DIR, folder)
    path = folder / "credentials_supported" / "iban_mdoc.json"
    configs = json.loads(path.read_text())
    del configs[IBAN]["credential_signing_alg_values_supported"]
    path.write_text(json.dumps(configs))
    issuer = make_issuer(**mdoc_settings(pki, metadata_dir=folder, published_configurations=(IBAN,)))
    assert (
        "credential_signing_alg_values_supported"
        not in issuer.issuer_metadata()["credential_configurations_supported"][IBAN]
    )


def test_the_document_signer_must_be_in_the_configurations_algorithms(
    make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path
) -> None:
    folder = tmp_path / "metadata"
    shutil.copytree(DEFAULT_METADATA_DIR, folder)
    path = folder / "credentials_supported" / "iban_mdoc.json"
    configs = json.loads(path.read_text())
    configs[IBAN]["credential_signing_alg_values_supported"] = [-35]
    path.write_text(json.dumps(configs))
    with pytest.raises(ConfigError, match=r"document signer \(ES256\) is not in \[-35\]"):
        make_issuer(**mdoc_settings(pki, metadata_dir=folder, published_configurations=(IBAN,)))


@pytest.mark.parametrize(("config", "subject", "ns"), [(IBAN, IBAN_SUBJECT, IBAN_NS), (PHOTO, PHOTO_SUBJECT, PHOTO_NS)])
def test_an_mdoc_does_not_outlive_its_document(
    mdoc_wallet: Wallet, pki: Pki, config: str, subject: dict[str, Any], ns: str
) -> None:
    """The MSO's validUntil ends with the document's expiry_date, as an SD-JWT VC's exp ends with date_of_expiry."""
    soon = (dt.datetime.fromtimestamp(mdoc_wallet.clock(), dt.UTC) + dt.timedelta(days=3)).date()
    [credential] = issue(
        mdoc_wallet, config, {ns: {**subject[ns], "expiry_date": soon.isoformat()}}, [EcKey.generate()]
    )
    mso, _, _ = read_mdoc(credential, pki)
    assert mso["validityInfo"]["validUntil"] <= dt.datetime.combine(soon, dt.time.max, dt.UTC)


def iban_config(issuer: Issuer) -> dict[str, Any]:
    found = issuer.configs.get(IBAN)
    assert found is not None
    return found


TODAY = dt.date(2026, 11, 9)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda s: {IBAN_NS: list(s[IBAN_NS])}, "must be an object of data elements"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "currency": 5}}, "currency: must be a non-empty string"),
        (lambda s: {IBAN_NS: {**s[IBAN_NS], "iban": "PT50\ud800"}}, "valid Unicode"),
    ],
)
def test_mdoc_subject_shapes_are_problems_not_errors(
    mdoc_issuer: Issuer, change: Callable[[dict[str, Any]], Any], reason: str
) -> None:
    problems = validate_mdoc_subject(iban_config(mdoc_issuer), change(IBAN_SUBJECT), TODAY)
    assert any(reason in p for p in problems), problems


def test_a_typed_date_is_reported_once(mdoc_issuer: Issuer) -> None:
    typed = json.loads(json.dumps(iban_config(mdoc_issuer)))
    for claim in typed["credential_metadata"]["claims"]:
        if claim["path"][1] == "expiry_date":
            claim["value_type"] = "full-date"
    problems = validate_mdoc_subject(typed, {IBAN_NS: {**IBAN_SUBJECT[IBAN_NS], "expiry_date": "soon"}}, TODAY)
    assert [p for p in problems if "expiry_date" in p] == [f"{IBAN_NS}/expiry_date: must be a calendar date YYYY-MM-DD"]


def test_a_document_expiring_today_is_still_issued(mdoc_issuer: Issuer) -> None:
    subject = {IBAN_NS: {**IBAN_SUBJECT[IBAN_NS], "expiry_date": TODAY.isoformat()}}
    assert validate_mdoc_subject(iban_config(mdoc_issuer), subject, TODAY) == []


@pytest.mark.parametrize(("value", "valid"), [(0, True), ("5", False), (5.0, False)])
def test_an_unsigned_integer_is_an_integer_from_zero(mdoc_issuer: Issuer, value: Any, valid: bool) -> None:
    photo = mdoc_issuer.configs.get(PHOTO)
    assert photo is not None
    problems = validate_mdoc_subject(photo, {PHOTO_NS: {**PHOTO_SUBJECT[PHOTO_NS], "age_in_years": value}}, TODAY)
    assert (problems == []) == valid, problems


@pytest.mark.parametrize("value", [5, None, ["data:image/jpeg;base64,AAAA"]])
def test_a_portrait_is_text(mdoc_issuer: Issuer, value: Any) -> None:
    photo = mdoc_issuer.configs.get(PHOTO)
    assert photo is not None
    problems = validate_mdoc_subject(photo, {PHOTO_NS: {**PHOTO_SUBJECT[PHOTO_NS], "portrait": value}}, TODAY)
    assert any("base64 JPEG" in p for p in problems), problems


def test_an_empty_portrait_is_issued_as_empty_bytes(mdoc_wallet: Wallet, pki: Pki) -> None:
    """An empty portrait stands for a person who opted out, as in the PID Rulebook; it is not a JPEG to check."""
    [credential] = issue(
        mdoc_wallet, PHOTO, {PHOTO_NS: {**PHOTO_SUBJECT[PHOTO_NS], "portrait": ""}}, [EcKey.generate()]
    )
    _, elements, _ = read_mdoc(credential, pki)
    assert elements[PHOTO_NS]["portrait"] == b""


def test_the_document_signer_needs_a_cose_algorithm(pki: Pki) -> None:
    signer = FileSigner.from_files(pki.root / "mdoc-signing.key", pki.root / "mdoc-signing.pem")
    check_document_signer(signer)

    class Renamed:
        alg = "EdDSA"

        def __getattr__(self, name: str) -> Any:
            return getattr(signer, name)

    with pytest.raises(ConfigError, match="has no COSE value"):
        check_document_signer(Renamed())


def test_a_document_signer_certificate_may_live_elsewhere(pki: Pki) -> None:
    Settings(**settings_kwargs(pki, **mdoc_settings(pki, mdoc_signer_certificate_url="https://certs.example/ds.pem")))


def test_production_keeps_the_iaca_out_of_x5chain(pki: Pki, tmp_path: Path) -> None:
    mdoc = mdoc_settings(pki, mdoc_signer_certificate_url="https://certs.example/ds.pem")
    mdoc.pop("published_configurations")
    without = {**mdoc, "mdoc_trust_anchors": None}
    with pytest.raises(ConfigError, match="production needs mdoc_trust_anchors"):
        Settings(**production_kwargs(pki, tmp_path, **without))
    Settings(**production_kwargs(pki, tmp_path, **mdoc))


def test_the_status_anchor_is_the_issuer_of_the_status_chain(pki: Pki, tmp_path: Path) -> None:
    """With the root left out of the chain, its issuer comes from the signing trust anchors; with none that issued it,
    cunho does not start."""
    anchors = pki.root / "issuer-root.pem"
    status = FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors)
    root = x509.load_pem_x509_certificate(anchors.read_bytes())
    assert status_list_anchor(status, [anchors]) == root.public_bytes(serialization.Encoding.DER)
    assert status_list_anchor(status, [None, anchors]) == root.public_bytes(serialization.Encoding.DER)
    # A certificate with the root's name and another key is not its issuer, even when it comes first.
    impostor_key = ec.generate_private_key(ec.SECP256R1())
    impostor = helper_certificate("Test Issuer Root", impostor_key, ca=True)
    both = tmp_path / "anchors.pem"
    both.write_bytes(helper_pem(impostor) + anchors.read_bytes())
    assert status_list_anchor(status, [both]) == root.public_bytes(serialization.Encoding.DER)
    alone = tmp_path / "impostor.pem"
    alone.write_bytes(helper_pem(impostor))
    with pytest.raises(ConfigError, match="names the issuer of its status list's signing chain"):
        status_list_anchor(status, [alone])
    with pytest.raises(ConfigError, match="names the issuer of its status list's signing chain"):
        status_list_anchor(status, [pki.root / "iaca.pem"])
    with pytest.raises(ConfigError, match="names the issuer of its status list's signing chain"):
        status_list_anchor(status, [None])
