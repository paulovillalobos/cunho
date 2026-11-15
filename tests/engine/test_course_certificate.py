"""The course certificate of the demo (M5 piece B): cunho's own attestation configuration, an SD-JWT VC with its
Type Metadata and an mdoc twin, issued by an attestation provider as a university or a MOOC platform would run it.
The files live in demo/metadata/course; these tests hold them to what cunho checks at start and at issuance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import cbor2
import pytest

from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .helpers import Pki, Wallet, disclosures
from .test_mdoc import decoded, mdoc_settings

COURSE = Path(__file__).resolve().parents[2] / "demo" / "metadata" / "course"
SD_JWT = "app.foaap.course_certificate_sd_jwt"
MDOC = "app.foaap.course_certificate_mdoc"
NAMESPACE = "app.foaap.course_certificate.1"
VCT = "https://foaap.app/vct/course-certificate/1"
COURSE_SUBJECT: dict[str, Any] = {
    "family_name": "Silva",
    "given_name": "Ana Maria",
    "achievement_title": "Introduction to the European Digital Identity Wallet",
    "achievement_description": "What the EU Digital Identity Wallet is and who issues to it.",
    "learning_outcomes": ["Explain the roles of the wallet ecosystem", "Read a credential offer"],
    "assessment_grade": "Passed (92/100)",
    "language_of_classes": ["pt", "en"],
    "expected_study_time": "PT12H",
    "ects_credits": 1,
    "level_of_learning_experience": 5,
    "course_provider": "FOAAP Academy (demo)",
    "course_url": "https://foaap.app/courses/eudi-wallet",
    "date_of_completion": "2026-11-02",
}


def mdoc_subject(subject: dict[str, Any]) -> dict[str, Any]:
    elements = {k: v for k, v in subject.items() if k != "language_of_classes"}
    elements["language_of_classes"] = ", ".join(subject["language_of_classes"])
    return {NAMESPACE: elements}


@pytest.fixture
def course_issuer(make_issuer: Callable[..., Issuer], pki: Pki) -> Issuer:
    return make_issuer(**mdoc_settings(pki, metadata_dir=COURSE, published_configurations=(SD_JWT, MDOC)))


@pytest.fixture
def course_wallet(course_issuer: Issuer, wallet_for: Callable[[Issuer], Wallet]) -> Wallet:
    return wallet_for(course_issuer)


def test_both_configurations_are_published(course_wallet: Wallet) -> None:
    published = course_wallet.client.get("/.well-known/openid-credential-issuer").json()
    configurations = published["credential_configurations_supported"]
    assert set(configurations) == {SD_JWT, MDOC}
    assert configurations[SD_JWT]["vct"] == VCT
    assert configurations[MDOC]["doctype"] == NAMESPACE
    locales = {d["locale"] for d in configurations[SD_JWT]["credential_metadata"]["display"]}
    assert locales == {"en", "pt-PT"}


def test_the_sd_jwt_vc_carries_the_type_metadata_integrity(course_wallet: Wallet) -> None:
    made = course_wallet.offer(COURSE_SUBJECT, configs=[SD_JWT])
    course_wallet.get_token(made)
    response = course_wallet.issue(config=SD_JWT)
    assert response.status_code == 200, response.text
    _, payload, _ = disclosures(response.json()["credentials"][0]["credential"])
    document = (COURSE / "type_metadata" / "course-certificate-1.json").read_bytes()
    import base64

    expected = "sha256-" + base64.b64encode(hashlib.sha256(document).digest()).decode()
    assert payload["vct"] == VCT and payload["vct#integrity"] == expected


def revealed(credential: str) -> dict[str, Any]:
    """The claims an SD-JWT VC discloses, with array elements resolved through their digests (RFC 9901 §4.2)."""
    import base64

    parts = [p for p in credential.split("~")[1:] if p]
    by_digest = {
        base64.urlsafe_b64encode(hashlib.sha256(p.encode()).digest()).decode().rstrip("="): json.loads(
            base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))
        )
        for p in parts
    }

    def resolve(value: Any) -> Any:
        if isinstance(value, list):
            return [resolve(by_digest[v["..."]][1]) if isinstance(v, dict) and "..." in v else v for v in value]
        return value

    return {d[1]: resolve(d[2]) for d in by_digest.values() if len(d) == 3}


def test_the_course_data_comes_back_disclosed(course_wallet: Wallet) -> None:
    course_wallet.get_token(course_wallet.offer(COURSE_SUBJECT, configs=[SD_JWT]))
    response = course_wallet.issue(config=SD_JWT)
    claims = revealed(response.json()["credentials"][0]["credential"])
    for name, value in COURSE_SUBJECT.items():
        assert claims[name] == value, name
    assert "date_of_issuance" in claims, "cunho fills in the day it issues"


def test_the_mdoc_twin_is_issued(course_wallet: Wallet) -> None:
    subject = mdoc_subject(COURSE_SUBJECT)
    course_wallet.get_token(course_wallet.offer(subject, configs=[MDOC]))
    nonce = course_wallet.c_nonce()
    key = EcKey.generate()
    proof = course_wallet.proof(key, nonce, attest=False)
    response = course_wallet.credential_request({"credential_configuration_id": MDOC, "proofs": {"jwt": [proof]}})
    assert response.status_code == 200, response.text
    issuer_signed = decoded(response.json()["credentials"][0]["credential"])
    items = {
        cbor2.loads(item.value)["elementIdentifier"]: cbor2.loads(item.value)["elementValue"]
        for item in issuer_signed["nameSpaces"][NAMESPACE]
    }
    assert items["achievement_title"] == COURSE_SUBJECT["achievement_title"]
    assert "org.iso.23220.1" in issuer_signed["nameSpaces"], "issuing authority, document number, issue date"


def test_subject_data_outside_the_configuration_is_refused(course_wallet: Wallet) -> None:
    response = course_wallet.admin(
        "offers", {"credential_configuration_ids": [SD_JWT], "subject": {**COURSE_SUBJECT, "birthdate": "1990-01-01"}}
    )
    assert response.status_code == 400 and "birthdate" in response.json()["error_description"]
    missing = {k: v for k, v in COURSE_SUBJECT.items() if k != "achievement_title"}
    response = course_wallet.admin("offers", {"credential_configuration_ids": [SD_JWT], "subject": missing})
    assert response.status_code == 400 and "achievement_title" in response.json()["error_description"]


def test_the_type_metadata_matches_the_configuration() -> None:
    """Every claim the configuration lists is described in the Type Metadata, in both languages, and no other."""
    config = json.loads((COURSE / "credentials_supported" / "course_certificate_jwt_vc.json").read_text())[SD_JWT]
    document = json.loads((COURSE / "type_metadata" / "course-certificate-1.json").read_text())
    assert document["vct"] == config["vct"]
    listed = [c["path"] for c in config["credential_metadata"]["claims"]]
    described = [c["path"] for c in document["claims"]]
    assert listed == described
    for claim in document["claims"]:
        assert {d["locale"] for d in claim["display"]} == {"en", "pt-PT"}, claim["path"]
