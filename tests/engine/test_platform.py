"""Metadata, status lists, the audit log, the store and startup settings."""

from __future__ import annotations

import base64
import copy
import json
import threading
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.audit import AuditLog
from cunho.errors import ConfigError
from cunho.jose import load_x5c, parse_jws, verify
from cunho.keyring import Keyring
from cunho.metadata import load, validate
from cunho.service import Issuer
from cunho.settings import Profile, Settings
from cunho.status import StatusRef
from cunho.store import MemoryStore, SqliteStore, Store

from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PRE_AUTH, Clock, Pki, Wallet, production_kwargs, settings_kwargs


@pytest.mark.obligation(
    "VCI.META.WELL_KNOWN_PATH",
    "VCI.META.FIELDS",
    "VCI.META.NONCE_ENDPOINT_WHEN_BINDING",
    "VCI.META.SCOPE_PER_CONFIG",
    "META.PROOF_TYPES_JWT_AND_ATTESTATION",
    "OAUTH.AS_METADATA",
    "OAUTH.DPOP_REQUIRED",
    "CRYPTO.ES256_384_512",
)
def test_metadata_documents(client: TestClient, issuer: Issuer) -> None:
    document = client.get("/.well-known/openid-credential-issuer").json()
    assert document["credential_issuer"] == ISSUER
    assert document["credential_endpoint"] == f"{ISSUER}/credential"
    assert document["nonce_endpoint"] == f"{ISSUER}/nonce"
    assert document["batch_credential_issuance"] == {"batch_size": 100}
    assert "display" not in document, "no borrowed branding unless the operator sets a display name"
    configs = document["credential_configurations_supported"]
    assert set(configs) == {PID_CONFIG}, "a PID provider publishes PIDs, not the sample attestations"
    assert len(issuer.configs.all) == 31, "all 31 reference configurations load unchanged"
    text = json.dumps(configs)
    for internal in ("issuer_conditions", "issuer_config", "selective_disclosure", '"source"', '"policy"'):
        assert internal not in text, f"{internal} is implementation-internal and is not published"
    pid = configs[PID_CONFIG]
    assert pid["scope"] and set(pid["proof_types_supported"]) == {"jwt", "attestation"}
    for spec in pid["proof_types_supported"].values():
        assert spec["proof_signing_alg_values_supported"] == ["ES256", "ES384", "ES512"]
    assert pid["cryptographic_binding_methods_supported"] == ["jwk"]
    assert pid["credential_signing_alg_values_supported"] == ["ES256"]
    server = client.get("/.well-known/oauth-authorization-server").json()
    assert server["issuer"] == ISSUER and server["token_endpoint"] == f"{ISSUER}/token"
    assert server["dpop_signing_alg_values_supported"] == ["ES256", "ES384", "ES512"]
    assert server["pre-authorized_grant_anonymous_access_supported"] is True


@pytest.mark.obligation("META.PREFERRED_STATUS_PERIODS")
def test_preferred_status_periods_are_published(client: TestClient, issuer: Issuer) -> None:
    """ARF WUA_32: an issuer with a minimum for the remaining status period of the key storage says so, in the
    key attestation requirements of each configuration (registry: META.PREFERRED_STATUS_PERIODS)."""
    published = client.get("/.well-known/openid-credential-issuer").json()["credential_configurations_supported"]
    configured = issuer.configs.all[PID_CONFIG]["proof_types_supported"]
    for proof_type, spec in published[PID_CONFIG]["proof_types_supported"].items():
        period = spec["key_attestations_required"]["preferred_key_storage_status_period"]
        assert period == configured[proof_type]["key_attestations_required"]["preferred_key_storage_status_period"]
        assert isinstance(period, int) and period > 0


@pytest.mark.obligation("CRYPTO.ALG_ALLOWLIST_ACM")
def test_only_agreed_signature_algorithms_verify() -> None:
    """Signatures verify only under ES256, ES384 or ES512 with the curve each names; any other alg, a key of
    another curve, or a signature of the wrong length does not."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    message = b"header.payload"
    for alg, curve, digest, size in (
        ("ES256", ec.SECP256R1(), hashes.SHA256(), 32),
        ("ES384", ec.SECP384R1(), hashes.SHA384(), 48),
        ("ES512", ec.SECP521R1(), hashes.SHA512(), 66),
    ):
        key = ec.generate_private_key(curve)
        r, s_ = decode_dss_signature(key.sign(message, ec.ECDSA(digest)))
        signature = r.to_bytes(size, "big") + s_.to_bytes(size, "big")
        assert verify(alg, key.public_key(), message, signature)
        for other in ("HS256", "RS256", "ES256K", "none", "EdDSA", None):
            assert not verify(other, key.public_key(), message, signature), other
        assert not verify(alg, key.public_key(), message, signature[:-1])
    p384 = ec.generate_private_key(ec.SECP384R1())
    r, s_ = decode_dss_signature(p384.sign(message, ec.ECDSA(hashes.SHA256())))
    assert not verify("ES256", p384.public_key(), message, r.to_bytes(48, "big") + s_.to_bytes(48, "big"))


def test_publication_follows_profile_and_settings(make_issuer: Callable[..., Issuer]) -> None:
    eaa = make_issuer(profile=Profile.EAA_PROVIDER, signer_certificate_url=None)
    published = set(eaa.issuer_metadata()["credential_configurations_supported"])
    assert PID_CONFIG not in published and len(published) == 10
    chosen = make_issuer(published_configurations=("eu.europa.ec.eudi.iban_sd_jwt_vc",), display_name="Banco X")
    assert set(chosen.issuer_metadata()["credential_configurations_supported"]) == {"eu.europa.ec.eudi.iban_sd_jwt_vc"}
    assert chosen.issuer_metadata()["display"] == [{"name": "Banco X"}]
    with pytest.raises(ConfigError, match="cannot publish"):
        make_issuer(published_configurations=("eu.europa.ec.eudi.pid_mdoc",))


@pytest.mark.obligation("VCI.META.WELL_KNOWN_PATH")
def test_well_known_path_insertion(make_issuer: Callable[..., Issuer]) -> None:
    issuer = make_issuer(issuer_url="https://issuer.test/tenant/a")
    with TestClient(create_app(issuer=issuer), base_url="https://issuer.test") as client:
        assert client.get("/.well-known/openid-credential-issuer/tenant/a").status_code == 200
        assert client.get("/tenant/a/.well-known/openid-credential-issuer").status_code == 404
        assert client.post("/tenant/a/nonce").status_code == 200


@pytest.mark.obligation(
    "META.REUSE_POLICY.PRESENT_ORDERED",
    "META.REUSE_POLICY.METHOD_A_PARAMS",
    "META.REUSE_POLICY.REISSUE_TRIGGER_UNUSED",
    "META.KEY_STORAGE_LEVELS",
    "META.NO_KA_FOR_UNBOUND",
    "VCI.META.SCOPE_PER_CONFIG",
    "FMT.SDJWT.VCT_REQUIRED",
    "KA.PID_KEY_IN_WSCD",
)
def test_configuration_validation(issuer: Issuer) -> None:
    good = issuer.configs.all[PID_CONFIG]
    validate("ok", good, 100)

    def broken(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        config = copy.deepcopy(good)
        change(config)
        return config

    jwt = lambda c: c["proof_types_supported"]["jwt"]  # noqa: E731
    reuse = lambda c: c["credential_metadata"]["credential_reuse_policy"]["options"][0]  # noqa: E731
    cases = {
        "no scope": broken(lambda c: c.pop("scope")),
        "no vct": broken(lambda c: c.pop("vct")),
        "symmetric proof alg": broken(lambda c: jwt(c).update(proof_signing_alg_values_supported=["HS256"])),
        "null key attestation": broken(lambda c: jwt(c).update(key_attestations_required=None)),
        "PID without key storage": broken(lambda c: jwt(c)["key_attestations_required"].pop("key_storage")),
        "unknown key storage level": broken(
            lambda c: jwt(c)["key_attestations_required"].update(key_storage=["very_high"])
        ),
        "bad preferred period": broken(
            lambda c: jwt(c)["key_attestations_required"].update(preferred_key_storage_status_period=-1)
        ),
        "binding without proofs": broken(lambda c: c.pop("proof_types_supported")),
        "no reuse policy": broken(lambda c: c["credential_metadata"].pop("credential_reuse_policy")),
        "method A without trigger": broken(lambda c: reuse(c).pop("reissue_trigger_unused")),
        "method A without batch size": broken(lambda c: reuse(c).pop("batch_size")),
    }
    for label, config in cases.items():
        with pytest.raises(ConfigError):
            validate(label, config, 100)
    with pytest.raises(ConfigError, match="exceeds the issuer batch_size"):
        validate("too big", good, 10)
    assert "eu.europa.ec.eudi.aamva_mdl_mdoc" in issuer.configs.findings, "reported, loaded, never published"


@pytest.mark.obligation(
    "STATUS.TSL.TOKEN_CLAIMS",
    "STATUS.TSL.ENCODING",
    "STATUS.TSL.MEDIA_TYPE",
    "STATUS.LIST_SIGNER_AUTHENTICATED",
    "PRIV.STATUS_LIST_UNAUTHENTICATED",
    "STATUS.RETAINED_BEYOND_VALIDITY",
)
def test_status_list_token(client: TestClient, issuer: Issuer, pki: Pki, clock: Clock) -> None:
    ref = issuer.status.allocate()
    assert issuer.status.revoke(ref)
    clock.now += issuer.settings.status_publish_interval  # it shows at the next publication
    response = client.get(f"/status/{ref.list_id}")
    assert response.status_code == 200 and response.headers["content-type"] == "application/statuslist+jwt"
    token = parse_jws(response.text)
    assert token.header["typ"] == "statuslist+jwt"
    leaf = load_x5c(token.header["x5c"])[0]
    assert leaf.subject != pki.issuer_leaf.subject, "status lists use their own key"
    assert verify(token.header["alg"], leaf.public_key(), token.signing_input, token.signature)
    claims = token.payload
    assert claims["sub"] == f"{ISSUER}/status/{ref.list_id}"
    assert claims["exp"] > claims["iat"] and claims["ttl"] > 0
    assert claims["status_list"]["bits"] == 1
    raw = zlib.decompress(base64.urlsafe_b64decode(claims["status_list"]["lst"] + "=="))
    assert len(raw) * 8 == issuer.settings.status_list_size
    assert (raw[ref.index // 8] >> (ref.index % 8)) & 1 == 1
    assert client.get("/status/999").status_code == 404 and client.get("/status/../x").status_code == 404
    clock.now += 365 * 86_400
    assert client.get(f"/status/{ref.list_id}").status_code == 200, "lists outlive the credentials"


@pytest.mark.obligation(
    "PRIV.STATUS_IDX_RANDOM",
    "PRIV.STATUS_LIST_HERD_SIZE",
    "STATUS.TSL.NO_DOUBLE_ALLOCATION",
    "STATUS.MONOTONIC",
    "STATUS.NO_SUSPENSION",
)
def test_status_allocation(issuer: Issuer) -> None:
    refs = [issuer.status.allocate() for _ in range(2100)]
    keys = {(r.list_id, r.index) for r in refs}
    assert len(keys) == len(refs), "no slot is handed out twice"
    indexes = [r.index for r in refs if r.list_id == "1"]
    ascending = sum(1 for a, b in zip(indexes, indexes[1:], strict=False) if b == a + 1)
    assert ascending < 10, "indexes are random, not sequential"
    assert {r.list_id for r in refs} == {"1", "2"}, "a list closes at the fill limit so herds stay large"
    decoys = issuer.store.items("status-decoy", "1:")
    scheduled = issuer.store.items("status-pending", "1:")  # decoys laid down for later when the list opened
    assert len(decoys) - len(scheduled) == int(issuer.settings.status_list_size * issuer.settings.status_decoy_ratio)
    ref = refs[0]
    assert issuer.status.revoke(ref) is True
    assert issuer.status.revoke(ref) is False, "a second revocation is not reported as one (M-8)"
    assert issuer.status.value(ref) == 1, "revocation is permanent and has no suspended state"
    decoy_index = int(decoys[0][0].split(":")[1])
    assert issuer.status.revoke(StatusRef("1", decoy_index)) is False, "decoys are never reported as revocations"
    assert not hasattr(issuer.status, "unrevoke")


def test_audit_chain_detects_tampering(clock: Clock) -> None:
    """M-2: entries and pointers are MACed with a key outside the store.

    No binder rule asks for this technique (DESIGN section 7: "this is our choice"), so the test names none.
    It carried LOG.DISCARD_UNIQUE_VALUES, which is about not keeping salts and credentials (review 3, M-8).
    """
    store, keyring = MemoryStore(clock), Keyring.ephemeral()
    log = AuditLog(store, keyring, clock)
    for n in range(5):
        log.append("event", "operator", n=n)
    assert log.verify()[0]
    entry = store.get("audit", "000000000003")
    assert isinstance(entry, dict)
    store.put("audit", "000000000003", {**entry, "data": {"n": 99}}, None)
    assert log.verify() == (False, "entry 3 was altered")
    store.put("audit", "000000000003", entry, None)
    store.delete("audit", "000000000005")
    assert not log.verify()[0], "removing the newest entry is detected"


def test_vault_erasure_keeps_the_log_valid(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    assert issuer.store.get("vault", offer["subject_ref"]) is not None
    auth = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    erased = wallet.client.post(f"/admin/subjects/{offer['subject_ref']}/erase", headers=auth)
    assert erased.status_code == 204 and issuer.store.get("vault", offer["subject_ref"]) is None
    assert issuer.store.get("vault-key", offer["subject_ref"]) is None
    code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    gone = wallet.token_request(code)  # erasure closes the offer too (review 6, N6-L3)
    assert gone.status_code == 400 and gone.json()["error_description"] == "this offer was cancelled"
    assert wallet.client.get("/admin/audit/verify", headers=auth).json()["valid"]


def test_audit_failure_stops_issuance(wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch) -> None:
    wallet.get_token()

    def broken(*_: Any, **__: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(issuer.audit._store, "add", broken)  # noqa: SLF001
    response = wallet.issue()
    assert response.status_code == 500 and response.json()["error"] == "server_error"
    assert "credentials" not in response.json()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_store_single_use_under_concurrency(backend: str, tmp_path: Path) -> None:
    store: Store = MemoryStore() if backend == "memory" else SqliteStore(tmp_path / "s.db")
    store.put("ns", "code", {"v": 1}, 60)
    winners: list[Any] = []
    threads = [threading.Thread(target=lambda: winners.append(store.take("ns", "code"))) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for w in winners if w is not None) == 1
    assert store.add("ns", "k", 1, None) and not store.add("ns", "k", 2, None)
    assert [store.incr("ns", "n", None) for _ in range(3)] == [1, 2, 3]
    store.put("ns", "a_%", 1, None)
    store.put("ns", "ab", 2, None)
    assert [k for k, _ in store.items("ns", "a_%")] == ["a_%"], "prefixes are literal"


def test_settings_refuse_unsafe_values(pki: Pki) -> None:
    base = settings_kwargs(pki)
    unsafe: list[dict[str, Any]] = [
        {"admin_token": "change-me"},
        {"admin_token": "short"},
        {"operators": {"alice": "change-me"}},
        {"operators": {"alice": "t" * 40}},
        {"issuer_url": "http://issuer.example"},
        {"issuer_url": "https://issuer.test/"},
        {"issuer_url": "https://issuer.test?x=1"},
        {"audit_retention_days": 0},
        {"signer_certificate_url": None},
        {"signer_certificate_url": "http://issuer.test/signer.pem"},
        {"batch_size": 1},
        {"status_list_size": 1000},
        {"production": True, "store_path": None},
    ]
    for change in unsafe:
        with pytest.raises(ConfigError):
            Settings(**{**base, **change})
    assert Settings(**{**base, "profile": Profile.EAA_PROVIDER, "signer_certificate_url": None})
    with pytest.raises(ConfigError):
        Settings(**{**base, "issuer_url": "http://localhost:8000", "production": True})


def test_production_needs_keys_outside_the_store(pki: Pki, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="secret_key_file"):
        Settings(**settings_kwargs(pki, production=True, store_path=tmp_path / "s.db"))
    settings = Settings(**production_kwargs(pki, tmp_path))
    with pytest.raises(ConfigError, match="does not exist"):
        Issuer(settings)
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    with pytest.raises(ConfigError, match="signing_key must be a pkcs11: or aws-kms: key"):
        Issuer(settings)


def test_load_counts(issuer: Issuer) -> None:
    configs = load(issuer.settings)
    assert len(configs.issuable()) == 1 and len(configs.all) == 31
