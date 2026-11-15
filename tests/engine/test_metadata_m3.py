"""The issuer metadata of M3 (piece G): signed with the access certificate, issuer_info with the registration
certificate, preferred_client_status_period, and the reuse policy of ETSI TS 119 472-3 §4.2.4."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.errors import ConfigError
from cunho.jose import b64u_decode, parse_jws, verify
from cunho.metadata import issuer_info, validate
from cunho.service import Issuer, Signers
from cunho.settings import Settings
from cunho.signed_metadata import METADATA_TYP, check_access_signer, signed_metadata, wants_jwt
from cunho.signer import FileSigner

from .helpers import (
    ISSUER,
    PID_CONFIG,
    REGISTRAR_DATASET,
    REGISTRATION_CERTIFICATE,
    Clock,
    Pki,
    access_signer,
    certificate,
    production_kwargs,
    settings_kwargs,
)

PATH = "/.well-known/openid-credential-issuer"


def access_files(pki: Pki) -> dict[str, Any]:
    return {
        "access_signing_key": pki.root / "access.key",
        "access_signing_chain": pki.root / "access.pem",
        "access_trust_anchors": pki.root / "issuer-root.pem",
    }


def issuer_files(pki: Pki) -> dict[str, Any]:
    return {"registration_certificate": pki.root / "registration.jwt", "registrar_dataset": pki.root / "registrar.json"}


def client_for(issuer: Issuer) -> TestClient:
    return TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER)


def decoded(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    jws = parse_jws(token)
    return jws.header, jws.payload


@pytest.mark.obligation(
    "VCI.META.SIGNED_FORMAT",
    "META.SIGNED_X5C_ACCESS_CERT",
    "META.REGCERT_BY_VALUE",
    "META.PREFERRED_CLIENT_STATUS_PERIOD",
)
def test_the_signed_metadata_is_the_json_metadata_signed_by_the_access_certificate(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    issuer = make_issuer(**access_files(pki), **issuer_files(pki), preferred_client_status_period=31 * 86_400)
    with client_for(issuer) as client:
        plain = client.get(PATH)
        signed = client.get(PATH, headers={"Accept": "application/jwt"})
    assert plain.headers["content-type"] == "application/json" and plain.headers["vary"] == "Accept"
    assert signed.status_code == 200 and signed.headers["content-type"] == "application/jwt"
    header, payload = decoded(signed.text)
    access = x509.load_pem_x509_certificates((pki.root / "access.pem").read_bytes())[0]
    assert header["typ"] == METADATA_TYP and header["alg"] == "ES256"
    assert [base64.b64decode(c) for c in header["x5c"]] == [access.public_bytes(serialization.Encoding.DER)]
    jws = parse_jws(signed.text)
    assert verify("ES256", access.public_key(), jws.signing_input, jws.signature)
    document = plain.json()
    assert {k: v for k, v in payload.items() if k not in ("sub", "iat", "exp")} == document
    assert payload["sub"] == ISSUER == document["credential_issuer"]
    assert payload["iat"] == int(clock.now) and payload["exp"] == payload["iat"] + 86_400
    assert document["preferred_client_status_period"] == 31 * 86_400
    assert document["issuer_info"] == [
        {"format": "registration_cert", "data": REGISTRATION_CERTIFICATE},
        {"format": "registrar_dataset", "data": REGISTRAR_DATASET},
    ]


@pytest.mark.parametrize(
    ("accept", "jwt"),
    [
        (None, False),
        ("", False),
        ("application/json", False),
        ("*/*", False),
        ("application/jwt", True),
        ("APPLICATION/JWT", True),
        ("application/jwt;q=0.9", True),
        ("application/json, application/jwt", False),
        ("application/jwt, application/json;q=0.5", True),
        ("application/jwt;q=0.5, application/json", False),
        ("application/jwt, */*;q=0.1", True),
        ("application/jwt;q=0.2, application/*;q=0.3", False),
        ("application/jwt;q=0", False),
        ("application/jwt;q=nonsense", False),
        ("text/html, application/jwt", True),
        ("application/json;q=0, application/jwt;q=1, */*;q=1", True),
        ("application/json;q=0, */*", True),
        ("application/jwt;q=0, */*", False),
        ("application/*;q=0.5, application/jwt", True),
        ("*/*;q=0.9, application/json", False),
    ],
)
def test_the_signed_form_is_served_only_when_the_client_prefers_it(accept: str | None, jwt: bool) -> None:
    """RFC 9110 §12.5.1: the higher weight wins, and JSON, the form that must always be there, wins a tie."""
    assert wants_jwt(accept) is jwt


def test_without_an_access_signer_the_metadata_is_json_only(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer()
    assert issuer.signed_issuer_metadata() is None
    with client_for(issuer) as client:
        response = client.get(PATH, headers={"Accept": "application/jwt"})
    assert response.headers["content-type"] == "application/json" and "issuer_info" not in response.json()
    assert "preferred_client_status_period" not in response.json()


def test_the_signed_metadata_is_signed_again_each_minute(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    issuer = make_issuer(**access_files(pki))
    clock.now = 60 * (int(clock.now) // 60 + 1)
    first = issuer.signed_issuer_metadata()
    clock.now += 59
    assert issuer.signed_issuer_metadata() == first
    clock.now += 1
    later = issuer.signed_issuer_metadata()
    assert later != first and decoded(str(later))[1]["iat"] == int(clock.now)


def test_the_signed_metadata_lives_as_long_as_set(make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock) -> None:
    issuer = make_issuer(**access_files(pki), signed_metadata_ttl=600)
    _, payload = decoded(str(issuer.signed_issuer_metadata()))
    assert payload["exp"] - payload["iat"] == 600


@pytest.mark.parametrize("ttl", [0, 7 * 86_400 + 1, True, 1.5])
def test_the_signed_metadata_lifetime_is_bounded(pki: Pki, ttl: Any) -> None:
    with pytest.raises(ConfigError, match="signed_metadata_ttl must be a whole number from 1 to"):
        Settings(**settings_kwargs(pki, signed_metadata_ttl=ttl))


class _Stub:
    """A signer whose certificate, x5c and key are set by the test."""

    alg = "ES256"

    def __init__(self, cert: x509.Certificate, x5c: list[x509.Certificate], key: ec.EllipticCurvePrivateKey) -> None:
        self._cert, self._x5c, self._key = cert, x5c, key

    def public_jwk(self) -> dict[str, Any]:
        from cunho.jose import jwk_from_public_key

        return jwk_from_public_key(self._key.public_key())

    def x5c(self) -> list[str]:
        der = serialization.Encoding.DER
        return [base64.b64encode(c.public_bytes(der)).decode() for c in self._x5c]

    def certificate_der(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.DER)

    def sign(self, data: bytes) -> bytes:
        raise NotImplementedError


def test_the_access_signer_is_checked_at_the_start(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    issuer = make_issuer()
    credentials, status = issuer.signers.credentials, issuer.signers.status
    check_access_signer(access_signer(pki), credentials, status)
    key = ec.generate_private_key(ec.SECP256R1())
    lone = certificate("Self-signed Access", key, ca=False)
    with pytest.raises(ConfigError, match="self-signed"):
        check_access_signer(_Stub(lone, [lone], key), credentials, status)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = certificate("Access CA", ca_key, ca=True)
    leaf = certificate("Access", key, (ca, ca_key))
    with pytest.raises(ConfigError, match="leave out the trust anchor"):
        check_access_signer(_Stub(leaf, [leaf, ca], key), credentials, status)
    with pytest.raises(ConfigError, match="start with its certificate"):
        check_access_signer(_Stub(leaf, [], key), credentials, status)
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = certificate("Other", other_key, (ca, ca_key))
    with pytest.raises(ConfigError, match="start with its certificate"):
        check_access_signer(_Stub(leaf, [other], key), credentials, status)
    signing_key = x509.load_pem_x509_certificates((pki.root / "signing.pem").read_bytes())[0]
    reused = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", pki.root / "issuer-root.pem")
    assert reused.certificate_der() == signing_key.public_bytes(serialization.Encoding.DER)
    for same in (credentials, status):
        with pytest.raises(ConfigError, match="must not be the credential or status list signing key"):
            check_access_signer(same, credentials, status)


def test_an_unreadable_access_certificate_stops_the_start(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer()

    class Broken(_Stub):
        def certificate_der(self) -> bytes:
            return b"not der"

    key = ec.generate_private_key(ec.SECP256R1())
    cert = certificate("x", key)
    with pytest.raises(ConfigError, match="cannot be read"):
        check_access_signer(Broken(cert, [cert], key), issuer.signers.credentials, issuer.signers.status)


def test_production_needs_an_access_signer_and_a_registration_certificate(
    pki: Pki, tmp_path: Path, clock: Clock
) -> None:
    from cunho.audit import Anchor  # noqa: F401 - production builds its anchor from the settings

    settings = Settings(**production_kwargs(pki, tmp_path))
    anchors = pki.root / "issuer-root.pem"
    signer = FileSigner.from_files(pki.root / "signing.key", pki.root / "signing.pem", anchors)
    status = FileSigner.from_files(pki.root / "status.key", pki.root / "status.pem", anchors)
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    with pytest.raises(ConfigError, match="production needs an access certificate signer"):
        Issuer(settings, signers=Signers(signer, status), clock=clock)
    for missing in ("registration_certificate", "registrar_dataset"):
        with pytest.raises(ConfigError, match="production needs registration_certificate and registrar_dataset"):
            Settings(**production_kwargs(pki, tmp_path, **{missing: None}))


@pytest.mark.parametrize(
    ("certificate_text", "dataset", "reason"),
    [
        ("", REGISTRAR_DATASET, "registration certificate is empty"),
        ("  \n", REGISTRAR_DATASET, "registration certificate is empty"),
        (None, REGISTRAR_DATASET, "registration certificate is empty"),
        ("café", REGISTRAR_DATASET, "printable ASCII"),
        ("a\x01b", REGISTRAR_DATASET, "printable ASCII"),
        ("a" * (64 * 1024 + 1), REGISTRAR_DATASET, "printable ASCII"),
        (REGISTRATION_CERTIFICATE, [], "non-empty JSON object"),
        (REGISTRATION_CERTIFICATE, {}, "non-empty JSON object"),
        (REGISTRATION_CERTIFICATE, {"identifier": "x"}, "lacks srvDescription, registryURI, providesAttestations"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "identifier": ""}, "identifier must be a non-empty string"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "identifier": 7}, "identifier must be a non-empty string"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "srvDescription": []}, "srvDescription"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "srvDescription": "x"}, "srvDescription"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "srvDescription": [{}]}, "srvDescription"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "registryURI": "http://r.test/"}, "registryURI"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "registryURI": 7}, "registryURI"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "providesAttestations": []}, "providesAttestations"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "providesAttestations": {}}, "providesAttestations"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "providesAttestations": {"a": 1}}, "providesAttestations"),
        (REGISTRATION_CERTIFICATE, {**REGISTRAR_DATASET, "srvDescription": 7}, "srvDescription"),
        (REGISTRATION_CERTIFICATE, list(REGISTRAR_DATASET), "non-empty JSON object"),
    ],
)
def test_issuer_info_out_of_shape_stops_the_start(certificate_text: Any, dataset: Any, reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        issuer_info(certificate_text, dataset)


def test_issuer_info_keeps_the_certificate_as_issued_without_surrounding_space() -> None:
    assert issuer_info(f"\n{REGISTRATION_CERTIFICATE}\n", REGISTRAR_DATASET)[0]["data"] == REGISTRATION_CERTIFICATE
    assert issuer_info("a" * (64 * 1024), REGISTRAR_DATASET)[0]["data"] == "a" * (64 * 1024)


def test_issuer_info_files_must_come_together_and_be_readable(
    make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path
) -> None:
    with pytest.raises(ConfigError, match="set registration_certificate and registrar_dataset together"):
        make_issuer(registration_certificate=pki.root / "registration.jwt")
    with pytest.raises(ConfigError, match="set registration_certificate and registrar_dataset together"):
        make_issuer(registrar_dataset=pki.root / "registrar.json")
    (tmp_path / "bad.json").write_text('{"identifier": "x", "identifier": "y"}')
    with pytest.raises(ConfigError, match="cannot read the registration certificate or registrar dataset"):
        make_issuer(registration_certificate=pki.root / "registration.jwt", registrar_dataset=tmp_path / "bad.json")
    with pytest.raises(ConfigError, match="cannot read the registration certificate or registrar dataset"):
        make_issuer(registration_certificate=tmp_path / "missing", registrar_dataset=pki.root / "registrar.json")


@pytest.mark.parametrize("period", [0, -1, True, 366 * 86_400 + 1, "31", 1.5])
def test_the_preferred_client_status_period_is_a_whole_number_of_seconds_up_to_a_year(pki: Pki, period: Any) -> None:
    with pytest.raises(ConfigError, match="preferred_client_status_period must be a whole number"):
        Settings(**settings_kwargs(pki, preferred_client_status_period=period))


def test_the_preferred_client_status_period_boundaries_are_accepted(pki: Pki) -> None:
    for period in (1, 366 * 86_400):
        assert Settings(**settings_kwargs(pki, preferred_client_status_period=period)).preferred_client_status_period


def test_the_new_settings_come_from_the_environment(pki: Pki) -> None:
    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": "x" * 40,
        "CUNHO_SIGNING_KEY": str(pki.root / "signing.key"),
        "CUNHO_SIGNING_CHAIN": str(pki.root / "signing.pem"),
        "CUNHO_WALLET_PROVIDER_ANCHORS": str(pki.root / "wallet-providers.pem"),
        "CUNHO_AUDIT_RETENTION_DAYS": "3650",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{ISSUER}/certs/signer.pem",
        "CUNHO_ACCESS_SIGNING_KEY": str(pki.root / "access.key"),
        "CUNHO_ACCESS_SIGNING_CHAIN": str(pki.root / "access.pem"),
        "CUNHO_ACCESS_TRUST_ANCHORS": str(pki.root / "issuer-root.pem"),
        "CUNHO_SIGNED_METADATA_TTL": "600",
        "CUNHO_REGISTRATION_CERTIFICATE": str(pki.root / "registration.jwt"),
        "CUNHO_REGISTRAR_DATASET": str(pki.root / "registrar.json"),
        "CUNHO_PREFERRED_CLIENT_STATUS_PERIOD": "2678400",
    }
    settings = Settings.from_env(env)
    assert settings.access_signing_key == pki.root / "access.key" and settings.signed_metadata_ttl == 600
    assert settings.registrar_dataset == pki.root / "registrar.json"
    assert settings.preferred_client_status_period == 2_678_400
    assert (
        Settings.from_env({k: v for k, v in env.items() if "PREFERRED" not in k}).preferred_client_status_period is None
    )
    with pytest.raises(ConfigError, match="preferred_client_status_period"):
        Settings.from_env({**env, "CUNHO_PREFERRED_CLIENT_STATUS_PERIOD": "0"})


@pytest.mark.obligation("META.EDP_BY_VALUE")
def test_no_embedded_disclosure_policy_is_published(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    """META.EDP_BY_VALUE is partial: no metadata member for one is standardised yet, and none is published."""
    document = json.dumps(make_issuer(**access_files(pki), **issuer_files(pki)).issuer_metadata())
    assert "disclosure_policy" not in document and "embedded_disclosure" not in document


# The reuse policy of ETSI TS 119 472-3 V1.1.1 §4.2.4.


def _pid(make_issuer: Callable[..., Issuer]) -> dict[str, Any]:
    return copy.deepcopy(make_issuer().configs.all[PID_CONFIG])


def _with_policy(config: dict[str, Any], policy: Any) -> dict[str, Any]:
    config = copy.deepcopy(config)
    if policy is ...:
        config["credential_metadata"].pop("credential_reuse_policy")
    else:
        config["credential_metadata"]["credential_reuse_policy"] = policy
    return config


def _arf(*options: Any) -> dict[str, Any]:
    return {"id": "arf_annex_ii", "options": list(options)}


A = {"details": ["once_only"], "batch_size": 10, "reissue_trigger_unused": 2}
LIFETIME = {"reissue_trigger_lifetime_left": 1}
B = {"details": ["limited_time"], "reissue_trigger_lifetime_left": 86_400}
C = {"details": ["rotating-batch", "limited_time"], "batch_size": 10, "reissue_trigger_lifetime_left": 86_400}


@pytest.mark.obligation(
    "META.REUSE_POLICY.A_OR_B",
    "META.REUSE_POLICY.CONFORMANCE_472_3",
    "META.REUSE_POLICY.METHOD_B_TRIGGER",
    "META.REUSE_POLICY.METHOD_C_PARAMS",
)
@pytest.mark.parametrize(
    "policy",
    [
        _arf(A),
        _arf(B),
        _arf({**B, "details": ["limited-time"]}),
        _arf(C),
        _arf({**A, "details": ["per-relying-party", "rotating-batch", "once_only"], **LIFETIME}),
        _arf({**A, "batch_size": 2, "reissue_trigger_unused": 1}),
        _arf(A, B),
    ],
)  # fmt: skip
def test_a_reuse_policy_of_method_a_or_b_as_ts_119_472_3_encodes_it_is_accepted(
    make_issuer: Callable[..., Issuer], policy: Any
) -> None:
    validate("pid", _with_policy(_pid(make_issuer), policy), 30)


@pytest.mark.parametrize(
    ("policy", "reason"),
    [
        (..., "no credential_reuse_policy object"),
        ([A], "no credential_reuse_policy object"),
        ({"options": [A]}, "id must be 'arf_annex_ii'"),
        ({"id": "other", "options": [A]}, "id must be 'arf_annex_ii'"),
        ({"id": "arf_annex_ii"}, "needs options"),
        (_arf(), "needs options"),
        ({"id": "arf_annex_ii", "options": A}, "needs options"),
        (_arf("once_only"), "must be an object"),
        (_arf({**A, "details": "once_only"}), "details, an array of strings"),
        (_arf({**A, "details": []}), "details, an array of strings"),
        (_arf({**A, "details": [1]}), "details, an array of strings"),
        (_arf({**A, "details": ["once_only", "twice"]}), "distinct values of"),
        (_arf({**A, "details": ["once_only", "once_only"]}), "distinct values of"),
        (_arf({**A, "details": ["once_only", "limited_time"], "reissue_trigger_lifetime_left": 1}), "one of them"),
        (_arf({**B, "details": ["limited_time", "limited-time"]}), "distinct values of"),
        (_arf({**C, "details": ["rotating-batch"]}), "one of them"),
        (_arf({**A, "batch_size": 1}), "batch_size of 2 or more"),
        (_arf({k: v for k, v in A.items() if k != "batch_size"}), "batch_size of 2 or more"),
        (_arf({**A, "batch_size": True}), "batch_size of 2 or more"),
        (_arf({**A, "batch_size": 31}), "exceeds the issuer batch_size 30"),
        (_arf({k: v for k, v in A.items() if k != "reissue_trigger_unused"}), "reissue_trigger_unused below"),
        (_arf({**A, "reissue_trigger_unused": 10}), "reissue_trigger_unused below"),
        (_arf({**A, "reissue_trigger_unused": -1}), "reissue_trigger_unused below"),
        (_arf({**A, "reissue_trigger_unused": False}), "reissue_trigger_unused below"),
        (_arf({"details": ["limited_time"]}), "reissue_trigger_lifetime_left"),
        (_arf({**B, "reissue_trigger_lifetime_left": 0}), "reissue_trigger_lifetime_left"),
        (_arf({**B, "reissue_trigger_lifetime_left": True}), "reissue_trigger_lifetime_left"),
        (_arf({k: v for k, v in C.items() if k != "batch_size"}), "batch_size of 2 or more"),
        (_arf({k: v for k, v in C.items() if k != "reissue_trigger_lifetime_left"}), "reissue_trigger_lifetime_left"),
        (_arf({**A, "details": ["once_only", "per-relying-party"]}), "reissue_trigger_lifetime_left"),
    ],
)  # fmt: skip
def test_a_reuse_policy_out_of_ts_119_472_3_stops_the_start(
    make_issuer: Callable[..., Issuer], policy: Any, reason: str
) -> None:
    with pytest.raises(ConfigError, match=reason):
        validate("pid", _with_policy(_pid(make_issuer), policy), 30)


def test_the_configurations_cunho_ships_meet_ts_119_472_3(make_issuer: Callable[..., Issuer]) -> None:
    """Every reference configuration with a reuse policy meets §4.2.4; the one without (the AAMVA mDL) was set aside
    before this piece too, as ARF ISSU_39 asks for a policy."""
    configs = make_issuer().configs
    assert configs.findings == {
        "eu.europa.ec.eudi.aamva_mdl_mdoc": "eu.europa.ec.eudi.aamva_mdl_mdoc: no credential_reuse_policy object "
        "(ARF ISSU_39, TS 119 472-3 §4.2.4.1)"
    }
    for config_id, config in configs.issuable().items():
        validate(config_id, config, configs.batch_size)


def test_a_signed_document_is_the_document_with_sub_iat_and_exp(pki: Pki) -> None:
    access = access_signer(pki)
    document = {"credential_issuer": ISSUER, "credential_endpoint": f"{ISSUER}/credential"}
    header, payload = decoded(signed_metadata(document, access, 1000, 60))
    assert payload == {**document, "sub": ISSUER, "iat": 1000, "exp": 1060}
    assert header == {"typ": METADATA_TYP, "x5c": access.x5c(), "alg": "ES256"}
    assert b64u_decode(signed_metadata(document, access, 1000, 60).split(".")[2])


def test_an_issuer_whose_access_key_is_its_credential_key_does_not_start(
    make_issuer: Callable[..., Issuer], pki: Pki
) -> None:
    with pytest.raises(ConfigError, match="must not be the credential or status list signing key"):
        make_issuer(
            access_signing_key=pki.root / "signing.key",
            access_signing_chain=pki.root / "signing.pem",
            access_trust_anchors=pki.root / "issuer-root.pem",
        )


def test_a_signed_document_is_not_served_after_its_exp(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """A lifetime under a minute ends the document before the minute does (the second reviewer)."""
    issuer = make_issuer(**access_files(pki), signed_metadata_ttl=1)
    clock.now = 60 * (int(clock.now) // 60 + 1)
    first = issuer.signed_issuer_metadata()
    assert issuer.signed_issuer_metadata() == first
    clock.now += 1
    later = issuer.signed_issuer_metadata()
    assert later != first and decoded(str(later))[1]["exp"] > int(clock.now)
