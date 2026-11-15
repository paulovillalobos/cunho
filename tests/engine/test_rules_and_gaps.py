"""PID data rules, robustness, the EC reference gaps, and the binder-to-code meta-tests."""

from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.credentials import validate_pid
from cunho.errors import ConfigError
from cunho.rules import REGISTRY
from cunho.service import Issuer

from .codewallet import CodeWallet
from .helpers import (
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    PRE_AUTH,
    Clock,
    EcKey,
    Pki,
    Wallet,
    certificate,
    disclosures,
    hs256,
)
from .rulecheck import BUILDING, ENFORCED, ENFORCING, FINISHED, SRC, TESTS, milestone_rules, rule_ids
from .test_preauth_attested import issue_with_iss, preauth_token

ROOT = Path(__file__).resolve().parents[2]
TODAY = dt.date(2026, 11, 4)


@pytest.mark.obligation(
    "PID.ATTRS.OPTIONAL_SCHEMA",
    "PID.SDJWT.PLACE_OF_BIRTH_NONEMPTY",
    "PID.VALUES.ISSUING_COUNTRY_ALPHA2",
    "PID.VALUES.ISSUING_JURISDICTION_PREFIX",
    "PID.VALUES.NATIONALITY_QU_QS",
    "PID.RULEBOOK.CONFORMANCE",
    "PID.SDJWT.CLAIM_MAPPING",
)
def test_pid_values() -> None:
    assert validate_pid(PID_SUBJECT, TODAY) == []
    assert validate_pid({**PID_SUBJECT, "nationalities": ["QU"]}, TODAY) == []
    assert validate_pid({**PID_SUBJECT, "nationalities": ["QS"]}, TODAY) == []
    bad = {
        "issuing_country": "XX",
        "issuing_jurisdiction": "ES-MD",
        "nationalities": ["Portuguese"],
        "place_of_birth": {"postal_code": "4000"},
        "birthdate": "2030-01-01",
        "sex": 7,
    }
    problems = validate_pid({**PID_SUBJECT, **bad}, TODAY)
    for name in bad:
        assert any(p.startswith(name) for p in problems), name
    assert any("picture" in p for p in validate_pid(PID_SUBJECT, dt.date(2028, 8, 11))), "portrait from 2028"


def offer(wallet: Wallet, subject: Any) -> Any:
    return wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": subject})


class TestReferenceGaps:
    """Behaviours where a reference issuer was seen to fail, which cunho must get right."""

    def test_missing_form_fields_get_400_listing_every_field(self, wallet: Wallet) -> None:
        response = offer(wallet, {"given_name": "Ana"})
        assert response.status_code == 400 and response.json()["error"] == "invalid_request"
        for name in ("family_name", "birthdate", "place_of_birth", "nationalities", "issuing_authority"):
            assert name in response.json()["error_description"]
        assert offer(wallet, None).status_code == 400
        assert offer(wallet, "not an object").status_code == 400
        assert offer(wallet, {**PID_SUBJECT, "unexpected": 1}).status_code == 400

    @pytest.mark.parametrize("value", ["2026-13-45", "31/12/2027", "", "2027-02-30", "tomorrow", 20271231, None])
    def test_malformed_expiry_dates_get_400(self, wallet: Wallet, value: Any) -> None:
        response = offer(wallet, {**PID_SUBJECT, "date_of_expiry": value})
        assert response.status_code == 400
        assert "date_of_expiry" in response.json()["error_description"]

    def test_expiry_before_issuance_or_in_the_past(self, wallet: Wallet) -> None:
        assert (
            offer(wallet, {**PID_SUBJECT, "date_of_issuance": "2026-10-01", "date_of_expiry": "2026-09-01"}).status_code
            == 400
        )
        assert offer(wallet, {**PID_SUBJECT, "date_of_expiry": "2020-01-01"}).status_code == 400

    def test_one_batch_size_from_one_setting(self, make_issuer: Callable[..., Issuer]) -> None:
        issuer = make_issuer()
        assert issuer.issuer_metadata()["batch_credential_issuance"]["batch_size"] == issuer.configs.batch_size
        with pytest.raises(ConfigError, match="exceeds the issuer batch_size"):
            make_issuer(batch_size=15)

    def test_extra_proofs_are_refused_not_truncated(self, wallet: Wallet, issuer: Issuer) -> None:
        wallet.get_token()
        nonce = wallet.c_nonce()
        proofs = [wallet.proof(EcKey.generate(), nonce) for _ in range((issuer.configs.batch_size or 1) + 1)]
        response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}})
        assert response.status_code == 400 and "credentials" not in response.json()

    def test_symmetric_dpop_is_never_advertised_or_accepted(self, wallet: Wallet) -> None:
        algs = wallet.client.get("/.well-known/oauth-authorization-server").json()["dpop_signing_alg_values_supported"]
        assert not [a for a in algs if a.startswith("HS") or a == "none"]
        code = wallet.offer()["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        proof = hs256(
            {"jti": "x" * 20, "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock())},
            {"typ": "dpop+jwt", "alg": "HS256", "jwk": wallet.dpop_key.public_jwk()},
        )
        response = wallet.token_request(code["pre-authorized_code"], dpop=proof)
        assert response.status_code == 400 and response.json()["error"] == "invalid_dpop_proof"


GARBAGE: list[tuple[str, bytes, str]] = [
    ("empty", b"", "application/json"),
    ("invalid json", b"{nope", "application/json"),
    ("array", b"[]", "application/json"),
    ("string", b'"x"', "application/json"),
    ("null", b"null", "application/json"),
    ("deep nesting", b"[" * 100_000 + b"]" * 100_000, "application/json"),
    ("too large", b'{"a":"' + b"A" * 300_000 + b'"}', "application/json"),
    ("invalid utf-8", b"\xff\xfe\xfd", "application/x-www-form-urlencoded"),
    ("form", b"grant_type=x&grant_type=y", "application/x-www-form-urlencoded"),
]


@pytest.mark.covers("OAUTH.TOKEN_ERROR_BODY", "VCI.CRED.ERROR_CODES")
@pytest.mark.parametrize(("label", "body", "content_type"), GARBAGE, ids=[g[0] for g in GARBAGE])
def test_garbage_never_causes_a_server_error(wallet: Wallet, label: str, body: bytes, content_type: str) -> None:
    wallet.get_token()
    targets: list[tuple[str, dict[str, str]]] = [
        ("/token", {}),
        ("/nonce", {}),
        (
            "/credential",
            {
                "Authorization": f"DPoP {wallet.token}",
                "DPoP": wallet.dpop("POST", f"{ISSUER}/credential", access_token=wallet.token),
            },
        ),
        ("/admin/offers", {"Authorization": f"Bearer {'t' * 40}"}),
        ("/admin/revocations", {"Authorization": f"Bearer {'t' * 40}"}),
    ]
    for path, headers in targets:
        response = wallet.client.post(path, content=body, headers={**headers, "Content-Type": content_type})
        assert response.status_code < 500, (label, path, response.text[:200])
        assert isinstance(response.json().get("error" if response.status_code >= 400 else "c_nonce"), str)


@pytest.mark.obligation("HTTP.METHOD_NOT_ALLOWED", "MDOC.NO_SERVER_RETRIEVAL")
def test_routes_and_methods(client: TestClient) -> None:
    response = client.get("/credential")
    assert response.status_code == 405 and "POST" in response.headers["allow"]
    assert response.json()["error"] == "invalid_request"
    assert client.get("/nothing-here").json()["error"] == "not_found"
    paths = {route.path for route in client.app.routes}  # type: ignore[attr-defined]
    assert paths == {
        "/.well-known/openid-credential-issuer",
        "/.well-known/oauth-authorization-server",
        "/token",
        "/par",
        "/authorize",
        "/authorize/continue",
        "/nonce",
        "/credential",
        "/deferred_credential",
        "/notification",
        "/status/{list_id}",
        "/admin/offers",
        "/admin/offers/{subject_ref}",
        "/admin/offers/{subject_ref}/cancel",
        "/admin/revocations",
        "/admin/subjects/{subject_ref}/erase",
        "/admin/audit/verify",
        "/admin/audit/head",
        "/admin/logins/{login_state}",
        "/admin/deferred",
        "/admin/deferred/{ref}/release",
        "/admin/deferred/{ref}/refuse",
        "/certs/signer.pem",
    }, "no ISO 18013-5 server retrieval or other unlisted endpoint exists"


@pytest.mark.obligation("ISS.NO_WALLET_DISCRIMINATION", "PRIV.UNIQUE_ELEMENTS_CSPRNG")
def test_no_wallet_discrimination_and_unique_values(wallet: Wallet, pki: Pki, clock: Clock) -> None:
    """Two different wallet products get the same treatment, and every random value is fresh."""
    first = wallet.issue()
    other_key = EcKey.generate()
    other_leaf = certificate("Another Wallet KA", other_key.private, (pki.wallet_ca, pki.wallet_ca_key))
    other = Wallet(wallet.client, dataclasses.replace(pki, ka_leaf=other_leaf, ka_key=other_key), clock)
    wallet.client.headers["User-Agent"] = "SomeOtherWallet/9.1 (Android)"
    second = other.issue()
    assert first.status_code == second.status_code == 200
    one, two = (disclosures(r.json()["credentials"][0]["credential"]) for r in (first, second))
    assert one[0].keys() == two[0].keys() and one[1].keys() == two[1].keys()
    salts = [d[0] for d in one[2] + two[2]]
    assert len(set(salts)) == len(salts) and all(len(s) >= 22 for s in salts)
    nonces = {wallet.c_nonce() for _ in range(200)}
    assert len(nonces) == 200 and all(len(n) == 43 for n in nonces)
    codes = {
        o["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"] for o in (wallet.offer() for _ in range(20))
    }
    assert len(codes) == 20


_rule_ids = rule_ids


def test_every_rule_in_the_code_is_in_the_binder() -> None:
    used = _rule_ids(SRC, ENFORCING | {"implements"})
    assert used - set(REGISTRY) == set()


def test_every_rule_of_a_finished_milestone_is_enforced_or_proven() -> None:
    """M-7: a decorator alone is not an implementation.

    A rule the code refuses on (enforce/refuse) needs a `covers` test that triggers the refusal. A rule
    that is an obligation (something cunho must produce or do) needs an `obligation` test that checks it.
    Every rule of a finished milestone must have one or the other. A rule of a milestone still being built
    (rulecheck.BUILDING) may have no code yet, but code that claims it needs its test as soon as it lands.
    """
    finished = milestone_rules(REGISTRY, FINISHED)
    started = milestone_rules(REGISTRY, FINISHED | BUILDING)
    enforced = ENFORCED
    declared = _rule_ids(SRC, {"implements"})
    covered = _rule_ids(TESTS, {"covers"})
    proven = _rule_ids(TESTS, {"obligation"})
    assert sorted(finished - enforced - declared) == [], "rules of a finished milestone with no code at all"
    assert sorted((started & enforced) - covered) == [], "enforced rules without a test that triggers them"
    assert sorted((started & declared - enforced) - proven) == [], "obligation rules without an obligation test"
    assert sorted((covered | proven) - set(REGISTRY)) == [], "tests cite unknown rules"


def test_m3_is_finished_with_the_rules_the_owner_put_in_it() -> None:
    """The owner's decisions of 2026-11-05 put these rules in M3, and every rule of M3 has code and a test."""
    m3 = milestone_rules(REGISTRY, frozenset({"M3"}))
    assert "M3" in FINISHED and "M3" not in BUILDING
    # decision 13 (the new rows), decision 11 (ARF-ISSU_65) and decision 3 (status at issuance)
    assert {"OAUTH.PAR_REQUIRED", "ISS.IDPROOF.PLUG_REQUIRED", "BATCH.REISSUE_SAME_WALLET_UNIT"} <= m3
    assert {"WIA.CLIENT_STATUS", "KA.STATUS_AT_ISSUANCE"} <= m3


def test_m4_is_finished_and_what_it_leaves_out_says_why() -> None:
    """Every rule of M4 has code and a test (above); the one whose condition cunho never meets carries its reason
    and belongs to no milestone."""
    assert "M4" in FINISHED and not BUILDING
    left_out = {rule: entry for rule, entry in REGISTRY.items() if entry["milestone"] == "not applicable"}
    assert set(left_out) == {"STATUS.MDOC_ID_UNIQUE_PER_MSO"}
    assert all(len(str(entry.get("not_applicable", ""))) > 40 for entry in left_out.values())
    assert all("not_applicable" not in entry for entry in REGISTRY.values() if entry["milestone"] != "not applicable")


@pytest.mark.obligation("TS3.CONFORMANCE")
def test_every_issuer_requirement_of_ts3_is_enforced_or_proven(code_wallet: CodeWallet) -> None:
    """ARF WUA_36: comply with all relevant requirements of TS3 (wallet unit attestation). Those are the binder rows
    that cite TS3 and bind the issuer's software; each rule they map to has its covers or obligation test. The one
    TS3 row that binds the wallet (KA.REPLAY_DETECTION, its context) is not cunho's to meet. A wallet that sends both
    TS3 attestations, the wallet attestation at the token endpoint and a key attestation in its proof, is served."""
    from_ts3 = {
        rule
        for rule, entry in REGISTRY.items()
        if entry["milestone"] in FINISHED
        and any(str(source["binder_id"]).startswith("TS3-") for source in entry["sources"])
    }
    tested = _rule_ids(TESTS, {"covers", "obligation"})
    assert len(from_ts3) >= 13 and sorted(from_ts3 - tested) == []
    assert REGISTRY["KA.REPLAY_DETECTION"]["milestone"] == "context"
    token = preauth_token(code_wallet, code_wallet.offer(), code_wallet.attestation_headers())
    assert token.status_code == 200, token.text
    code_wallet.token = token.json()["access_token"]
    issued = issue_with_iss(code_wallet, code_wallet.client_id)
    assert issued.status_code == 200, issued.text


def test_registry_matches_the_binder(tmp_path: Path) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "binder" / "src" / "milestones.py"), str(tmp_path)], check=True, capture_output=True
    )
    committed = json.loads((ROOT / "src" / "cunho" / "rules" / "registry.json").read_text())
    assert json.loads((tmp_path / "registry.json").read_text()) == committed
    assert (tmp_path / "MILESTONES.csv").read_text() == (ROOT / "binder" / "MILESTONES.csv").read_text()


def test_binder_files_match_their_sources(tmp_path: Path) -> None:
    """BINDER.csv, BINDER.md and BINDER-PLACEMENT.csv are generated from binder/src: nobody edits them by hand,
    and every row has its strength, quote and source in BINDER-STRENGTH.csv, which is written by hand."""
    binder = ROOT / "binder"
    checks = ROOT / "probe" / "eudi_probe" / "checks.py"
    subprocess.run(
        [sys.executable, str(binder / "src" / "build.py"), str(tmp_path), str(checks)], check=True, capture_output=True
    )
    subprocess.run(
        [sys.executable, str(binder / "src" / "placement.py"), str(tmp_path)], check=True, capture_output=True
    )
    for name in ("BINDER.csv", "BINDER.md", "BINDER-PLACEMENT.csv"):
        assert (tmp_path / name).read_text() == (binder / name).read_text(), name
    rows = [r["binder_id"] for r in csv.DictReader((binder / "BINDER.csv").open(newline=""))]
    strength = list(csv.DictReader((binder / "BINDER-STRENGTH.csv").open(newline="")))
    assert [r["binder_id"] for r in strength] == rows
    for row in strength:
        if row["strength"] not in ("UNVERIFIED", "N/A"):
            assert row["quote"] and row["verified_at"], row["binder_id"]
