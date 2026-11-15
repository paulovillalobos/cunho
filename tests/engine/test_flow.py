"""End to end: offer -> DPoP token -> nonce -> PID as SD-JWT VC -> status -> revocation -> audit."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import zlib

import pytest

from cunho.jose import load_x5c, parse_jws, verify
from cunho.service import Issuer

from .helpers import ISSUER, PID_CONFIG, PID_SUBJECT, EcKey, Wallet, disclosures, holder_thumbprint


def _bit(token: str, index: int) -> int:
    claims = parse_jws(token).payload
    raw = zlib.decompress(base64.urlsafe_b64decode(claims["status_list"]["lst"] + "=="))
    return (raw[index // 8] >> (index % 8)) & 1


def _digest(disclosure: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(disclosure.encode()).digest()).rstrip(b"=").decode()


@pytest.mark.obligation(
    "VCI.PROFILE.OID4VCI_HAIP",
    "VCI.OFFER.SHAPE",
    "VCI.CRED.RESPONSE_SHAPE",
    "FMT.SDJWT.CONFIG_AND_ENCODING",
    "FMT.SDJWT.TYP",
    "FMT.SDJWT.VCT_REQUIRED",
    "PID.SDJWT.VCT",
    "FMT.SDJWT.X5C_NO_ANCHOR",
    "PID.SDJWT.X5U_X5TS256",
    "PID.SDJWT.NBF_EXP",
    "FMT.SDJWT.EXP_OR_STATUS",
    "FMT.VALIDATION_INFO_EMBEDDED",
    "BIND.DEVICE_BOUND",
    "STATUS.SDJWT_TSL",
    "STATUS.TSL.REFERENCE",
    "STATUS.REFERENCE_PUBLIC",
    "FMT.SDJWT.NEVER_SD_CLAIMS",
    "PID.SDJWT.RECURSIVE_SD",
    "PID.SD.PER_DATA_IDENTIFIER",
    "PID.SDJWT.CLAIM_MAPPING",
    "PID.RULEBOOK.CONFORMANCE",
    "PRIV.TIMESTAMP_COARSENING",
    "VALIDITY.PID_LE_STATUS_EXP",
    "PID.SDJWT.UTF8",
    "FMT.VALIDITY_PERIOD",
)
def test_pid_issuance_end_to_end(wallet: Wallet, issuer: Issuer) -> None:
    holder = EcKey.generate()
    response = wallet.issue([holder])
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"credentials", "notification_id"} and len(body["credentials"]) == 1
    credential = body["credentials"][0]["credential"]
    assert credential.endswith("~")

    header, payload, decoded = disclosures(credential)
    assert header["typ"] == "dc+sd-jwt" and header["alg"] == "ES256"
    chain = load_x5c(header["x5c"])
    assert len(chain) == 1, "the trust anchor must not be in x5c"
    assert header["x5u"] == f"{ISSUER}/certs/signer.pem"
    leaf_digest = hashlib.sha256(base64.b64decode(header["x5c"][0])).digest()
    assert header["x5t#S256"] == base64.urlsafe_b64encode(leaf_digest).rstrip(b"=").decode()
    jwt = parse_jws(credential.split("~")[0])
    assert verify(header["alg"], chain[0].public_key(), jwt.signing_input, jwt.signature)

    assert payload["iss"] == ISSUER and payload["vct"] == "urn:eudi:pid:1"
    assert payload["_sd_alg"] == "sha-256"
    assert holder_thumbprint(holder) == holder_thumbprint(
        EcKey.from_private_jwk({**payload["cnf"]["jwk"], "d": holder.private_jwk()["d"]})
    )
    assert payload["nbf"] % 3600 == 0 and payload["exp"] % 3600 == 0, "timestamps are rounded"
    assert payload["exp"] <= wallet.clock() + wallet.status_exp_offset, "exp is capped at the KA status period"
    ref = payload["status"]["status_list"]
    assert ref["uri"].startswith(f"{ISSUER}/status/") and isinstance(ref["idx"], int)

    parts = [p for p in credential.split("~")[1:] if p]
    by_digest = {_digest(p): d for p, d in zip(parts, decoded, strict=True)}
    top_level = {by_digest[h][1]: by_digest[h][2] for h in payload["_sd"] if h in by_digest}
    decoys = [h for h in payload["_sd"] if h not in by_digest]
    assert len(decoys) <= 3 and payload["_sd"] == sorted(payload["_sd"]), "decoys hide the claim count (L-3)"
    assert not set(top_level) & {"iss", "nbf", "exp", "cnf", "vct", "status"}
    assert set(top_level) == set(PID_SUBJECT) | {"date_of_issuance", "date_of_expiry"}
    assert top_level["date_of_issuance"] == dt.datetime.fromtimestamp(payload["nbf"], dt.UTC).date().isoformat()
    assert top_level["date_of_expiry"] == PID_SUBJECT["date_of_expiry"], "the administrative date is the document's"
    assert "family_name" not in payload and "birthdate" not in payload
    assert set(top_level["place_of_birth"]) == {"_sd"}, "nested members are disclosable too"
    nested = {by_digest[h][1] for h in top_level["place_of_birth"]["_sd"] if h in by_digest}
    assert nested == {"locality", "country"}
    assert all(set(item) == {"..."} for item in top_level["nationalities"]), "array elements are disclosable"
    countries = sorted(by_digest[item["..."]][1] for item in top_level["nationalities"])
    assert countries == ["ES", "PT"]
    referenced = json.dumps(payload) + json.dumps(decoded)
    assert all(referenced.count(h) == 1 for h in by_digest), "every disclosure is referenced exactly once"

    status = wallet.client.get(ref["uri"].removeprefix(ISSUER))
    assert status.status_code == 200
    assert status.headers["content-type"].startswith("application/statuslist+jwt")
    assert _bit(status.text, ref["idx"]) == 0


@pytest.mark.obligation("STATUS.MONOTONIC", "STATUS.NO_SUSPENSION", "LOG.DISCARD_UNIQUE_VALUES")
def test_revocation_and_audit(wallet: Wallet, issuer: Issuer) -> None:
    offer = wallet.offer()
    wallet.get_token(offer)
    response = wallet.issue()
    credential = response.json()["credentials"][0]["credential"]
    ref = disclosures(credential)[1]["status"]["status_list"]

    revoked = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "user_request"})
    assert revoked.status_code == 200 and revoked.json() == {"revoked": 1}
    assert _bit(wallet.client.get(ref["uri"].removeprefix(ISSUER)).text, ref["idx"]) == 0, "until the next publication"
    wallet.clock.now += issuer.settings.status_publish_interval
    status = wallet.client.get(ref["uri"].removeprefix(ISSUER)).text
    assert _bit(status, ref["idx"]) == 1

    events = [e["event"] for e in issuer.audit.entries()]
    assert events == ["offer.created", "credential.issued", "credential.revoked"]
    assert issuer.audit.verify()[0]
    log = json.dumps(issuer.audit.entries(), ensure_ascii=False)
    for value in ("Silva", "Ana Maria", "1990-05-17", "Porto"):
        assert value not in log, "the audit log holds no personal data"
    issued, revocation = issuer.audit.entries()[1], issuer.audit.entries()[2]
    assert issued["data"]["status_refs"] == revocation["data"]["status_refs"]
    raw = {ref["idx"], f"{ref['uri'].rsplit('/', 1)[1]}:{ref['idx']}"}
    assert not raw & set(issued["data"]["status_refs"]), "status indexes appear only as keyed references"
    assert all(len(r) == 32 for r in issued["data"]["status_refs"])
    stored = json.dumps([issuer.store.items(ns) for ns in ("issued", "audit", "access-token", "grant-config")])
    assert credential.split("~")[0] not in stored and credential.split("~")[1] not in stored, "credentials not kept"
    again = wallet.admin("revocations", {"subject_ref": offer["subject_ref"], "reason": "user_request"})
    assert again.json() == {"revoked": 0}, "only live credentials count"


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT", "EAA.RULEBOOK.CONFORMANCE")
@pytest.mark.obligation("ISS.SUBJECT.ENTITLEMENT", "PID.SDJWT.PICTURE_DATA_URL_JPEG", "PID.PORTRAIT.OPTOUT_EMPTY")
def test_offer_requires_operator_and_valid_portrait(wallet: Wallet) -> None:
    anonymous = wallet.client.post("/admin/offers", json={"credential_configuration_ids": [PID_CONFIG]})
    assert anonymous.status_code == 401
    wrong = wallet.client.post("/admin/offers", json={}, headers={"Authorization": "Bearer " + "x" * 40})
    assert wrong.status_code == 401
    bad_picture = wallet.admin(
        "offers",
        {
            "credential_configuration_ids": [PID_CONFIG],
            "subject": {**PID_SUBJECT, "picture": "https://example.com/me.jpg"},
        },
    )
    assert bad_picture.status_code == 400 and "picture" in bad_picture.json()["error_description"]
    opted_out = wallet.offer({**PID_SUBJECT, "picture": ""})
    assert opted_out["credential_offer"]["credential_configuration_ids"] == [PID_CONFIG]
