"""ETSI TS 119 472-1 V1.2.1 clause 5, which CIR 2024/2979 Annex II makes binding (FMT.ETSI_119472_1): the SD-JWT VC
profile of electronic attestations of attributes, PID included. Clause 6 (ISO/IEC mdoc) is in test_qeaa.py."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho import metadata
from cunho.credentials import sd_jwt_vc
from cunho.errors import ConfigError
from cunho.service import Issuer
from cunho.settings import Profile, Settings
from cunho.signer import FileSigner
from cunho.status import StatusRef
from eudi_probe.jose import EcKey

from .helpers import PID_CONFIG, Pki, disclosures, settings_kwargs, typed_metadata

EAA_STATUS_URI = "https://issuer.test/status/1"


def sri(data: bytes) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode()


@pytest.mark.obligation("FMT.ETSI_119472_1")
def test_an_issued_pid_follows_clause_5(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Any], pki: Pki
) -> None:
    """Every requirement of clause 5 an SD-JWT VC PID can be held to, checked on one that cunho issued."""
    issuer = make_issuer(metadata_dir=pki.root / "metadata")
    response = wallet_for(issuer).issue()
    assert response.status_code == 200, response.text
    header, payload, disclosed = disclosures(response.json()["credentials"][0]["credential"])
    config = issuer.configs.all[PID_CONFIG]
    documents = {
        json.loads(p.read_bytes())["vct"]: p.read_bytes() for p in (pki.root / "metadata" / "type_metadata").iterdir()
    }
    # 5.2.1.2: vct, and vct#integrity over the Type Metadata document the vct leads to
    assert payload["vct"] == config["vct"] and payload["vct#integrity"] == sri(documents[config["vct"]])
    # 5.2.2.1: a PID is neither a QEAA nor a PuB-EAA, so no category
    assert "category" not in payload
    # 5.2.7.1: nbf and exp, the technical validity period; 5.2.7.2: no administrative period, or both ends
    assert isinstance(payload["nbf"], int) and isinstance(payload["exp"], int) and payload["nbf"] < payload["exp"]
    assert ("adm_nbf" in payload) == ("adm_exp" in payload)
    # 5.2.8.1: no audience; 5.2.8.2, 5.2.12: oneTime and shortLived, when there, are null; 5.2.11: no renewal
    assert "aud" not in payload
    assert all(payload.get(name, None) is None for name in ("oneTime", "shortLived"))
    # 5.2.10.1 as CIR 2024/2979 Annex II adapts it: the status refers to a Token Status List entry
    assert set(payload["status"]["status_list"]) == {"idx", "uri"} and isinstance(
        payload["status"]["status_list"]["idx"], int
    )
    # 5.4.1: selective disclosure with _sd and _sd_alg whenever there are disclosures
    assert disclosed and payload["_sd_alg"] == "sha-256" and payload["_sd"]
    # 5.5: cnf holds the holder's public key and nothing else
    assert set(payload["cnf"]) == {"jwk"} and "d" not in payload["cnf"]["jwk"]
    # 5.2.4.1: issuing_authority and issuing_country are strings
    named = {d[1]: d[2] for d in disclosed if len(d) == 3}
    assert isinstance(named["issuing_authority"], str) and isinstance(named["issuing_country"], str)
    # 5.6.2-02 and the PID annex: the signer's certificate by x5u and x5t#S256
    assert header["typ"] == "dc+sd-jwt" and header["x5u"] and header["x5t#S256"]


@pytest.mark.parametrize(
    ("profile", "category"),
    [
        (Profile.QEAA_PROVIDER, "urn:etsi:esi:eaa:eu:qualified"),
        (Profile.PUB_EAA_PROVIDER, "urn:etsi:esi:eaa:eu:pub"),
        (Profile.EAA_PROVIDER, None),
        (Profile.PID_PROVIDER, None),
    ],
)
def test_the_category_follows_the_kind_of_provider(pki: Pki, profile: Profile, category: str | None) -> None:
    """5.2.2: a qualified or public-body attestation names its category, any other names none."""
    settings = Settings(**settings_kwargs(pki, profile=profile, published_configurations=()))
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", pki.root / "issuer-root.pem")
    holder = EcKey.generate().public_jwk()
    token = sd_jwt_vc(settings, signer, {"vct": "urn:x"}, {}, holder, StatusRef("1", 0), 0, 60)
    assert disclosures(token)[1].get("category") == category


@pytest.mark.parametrize("profile", [Profile.QEAA_PROVIDER, Profile.PUB_EAA_PROVIDER, Profile.PID_PROVIDER])
def test_qualified_and_public_body_providers_name_their_signer_by_url(pki: Pki, profile: Profile) -> None:
    """QEAA-5.6.2-02 and PuB-EAA-5.6.3-02, as the PID annex: x5u and x5t#S256 in the protected header."""
    with pytest.raises(ConfigError, match="must publish the signer certificate"):
        Settings(**settings_kwargs(pki, profile=profile, signer_certificate_url=None, published_configurations=()))
    Settings(**settings_kwargs(pki, profile=Profile.EAA_PROVIDER, signer_certificate_url=None))


def test_a_claim_named_category_is_refused_where_the_attestation_has_one(pki: Pki, tmp_path: Path) -> None:
    iban = "eu.europa.ec.eudi.iban_sd_jwt_vc"
    folder = typed_metadata(tmp_path / "metadata")
    path = folder / "credentials_supported" / "iban_jwt_vc.json"
    configs = json.loads(path.read_text())
    configs[iban]["credential_metadata"]["claims"].append({"path": ["category"]})
    path.write_text(json.dumps(configs))
    for profile in (Profile.QEAA_PROVIDER, Profile.PUB_EAA_PROVIDER):
        settings = Settings(
            **settings_kwargs(pki, profile=profile, metadata_dir=folder, published_configurations=(iban,))
        )
        with pytest.raises(ConfigError, match="clash with the category"):
            metadata.load(settings)
    metadata.load(Settings(**settings_kwargs(pki, profile=Profile.EAA_PROVIDER, metadata_dir=folder)))
    plain = typed_metadata(tmp_path / "plain")
    for profile in (Profile.QEAA_PROVIDER, Profile.PUB_EAA_PROVIDER):
        settings = Settings(
            **settings_kwargs(pki, profile=profile, metadata_dir=plain, published_configurations=(iban,))
        )
        assert iban in metadata.load(settings).published, "a configuration without such a claim is fine"


def test_type_metadata_documents_are_read_strictly(tmp_path: Path) -> None:
    folder = tmp_path / "type_metadata"
    folder.mkdir()
    assert metadata.load_type_metadata(tmp_path / "absent") == {}
    good = b'{"vct": "urn:eudi:pid:1", "name": "PID"}\n'
    (folder / "a.json").write_bytes(good)
    assert metadata.load_type_metadata(folder) == {"urn:eudi:pid:1": sri(good)}, (
        "the bytes as they are, newline included"
    )
    (folder / "b.json").write_bytes(b'{"vct": "urn:eudi:pid:1"}')
    with pytest.raises(ConfigError, match="two type metadata documents"):
        metadata.load_type_metadata(folder)
    for data, reason in (
        (b"not json", "is not JSON"),
        (b'{"vct": "a", "vct": "b"}', "is not JSON"),
        (b'{"name": "no vct"}', "names no vct"),
        (b'{"vct": ""}', "names no vct"),
        (b'["urn:x"]', "names no vct"),
        (b'{"vct": 5}', "names no vct"),
        (b'{"vct": "urn:y", "pad": "' + b"x" * metadata.MAX_TYPE_METADATA + b'"}', "larger than"),
    ):
        (folder / "b.json").write_bytes(data)
        with pytest.raises(ConfigError, match=reason):
            metadata.load_type_metadata(folder)


def test_a_type_metadata_document_of_exactly_the_cap_is_read(tmp_path: Path) -> None:
    head, tail = b'{"vct": "urn:z", "pad": "', b'"}'
    data = head + b"x" * (metadata.MAX_TYPE_METADATA - len(head) - len(tail)) + tail
    (tmp_path / "a.json").write_bytes(data)
    assert len(data) == metadata.MAX_TYPE_METADATA
    assert metadata.load_type_metadata(tmp_path) == {"urn:z": sri(data)}


def test_production_needs_type_metadata_and_development_warns_without(
    make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from .helpers import production_kwargs

    untyped = tmp_path / "untyped"
    untyped.mkdir()
    import shutil

    shutil.copytree(pki.root / "metadata", untyped / "metadata", ignore=shutil.ignore_patterns("type_metadata"))
    with pytest.raises(ConfigError, match="production needs the SD-JWT VC Type Metadata of"):
        metadata.load(Settings(**production_kwargs(pki, tmp_path, metadata_dir=untyped / "metadata")), mdoc_alg="ES256")
    metadata.load(Settings(**production_kwargs(pki, tmp_path)), mdoc_alg="ES256")
    with caplog.at_level(logging.WARNING, logger="cunho"):
        issuer = make_issuer(metadata_dir=untyped / "metadata")
    assert "no SD-JWT VC Type Metadata for" in caplog.text
    assert issuer.configs.integrity == {}
