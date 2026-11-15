"""The authorization code flow end to end: PAR, the authorization endpoint, the test login, the code exchange and
the credential, with what each step must carry (HAIP 1.0 §4, FAPI 2.0 §5.3.2, OpenID4VCI 1.0 §5, §6, §8)."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.errors import ConfigError
from cunho.jose import thumbprint
from cunho.service import Issuer
from cunho.settings import Settings
from eudi_probe.jose import EcKey

from .codewallet import (
    CANCEL,
    CLIENT_ID,
    IBAN,
    LOGIN,
    REDIRECT_URI,
    CodeWallet,
    Pkce,
    Redirect,
    code_of,
    pid_scope,
    pushed,
)
from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PID_SUBJECT, Pki, refused_by, settings_kwargs


@pytest.mark.obligation(
    "OAUTH.AUTH_CODE_AND_PAR",
    "OAUTH.PAR_REQUEST",
    "OAUTH.PAR_REQUEST_URI_ONCE",
    "OAUTH.PAR_REQUIRED",
    "OAUTH.REDIRECT_URI_EXACT",
    "OAUTH.AUTHZ_RESPONSE_ISS",
    "OAUTH.REDIRECT_303",
    "OAUTH.CODE_ONCE_60S",
    "WIA.VERIFY",
    "WIA.POP_FRESH",
    "WIA.CLIENT_STATUS",
    "WIA.STATUS_EXP_NOT_TOKEN_EXP",
    "ISS.IDPROOF.PLUG_REQUIRED",
)
def test_the_code_flow_issues_a_pid(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    response = code_wallet.par(pkce, scope=pid_scope(code_issuer), state="st-1")
    assert response.status_code == 201 and response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["request_uri"].startswith("urn:ietf:params:oauth:request_uri:") and 0 < body["expires_in"] < 600
    to_login = code_wallet.authorize(body["request_uri"])
    assert to_login.status_code == 303 and to_login.headers["location"].startswith(f"{ISSUER}/test-login?")
    page = code_wallet.client.get(to_login.headers["location"])
    assert page.status_code == 200 and "Test login" in page.text
    back = code_wallet.login(to_login, LOGIN)
    assert back.status == 303 and back.target == REDIRECT_URI
    assert back.params["state"] == "st-1" and back.params["iss"] == ISSUER
    tokens = code_wallet.code_token_request(back.params["code"], pkce)
    assert tokens.status_code == 200 and tokens.headers["cache-control"] == "no-store", tokens.text
    assert tokens.json()["token_type"] == "DPoP" and "authorization_details" not in tokens.json()
    code_wallet.token = tokens.json()["access_token"]
    issued = code_wallet.issue()
    assert issued.status_code == 200, issued.text
    assert len(issued.json()["credentials"]) == 1


def test_every_redirect_of_the_flow_is_a_303(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """FAPI 2.0 §5.3.2.2 items 10-11: never 307, and 303 after the login form's POST."""
    request_uri, _ = pushed(code_wallet, code_issuer)
    first = code_wallet.authorize(request_uri)
    page = code_wallet.client.get(first.headers["location"])
    state = page.text.split('name="login_state" value="')[1].split('"')[0]
    after_form = code_wallet.client.post(
        "/test-login",
        content=f"login_state={state}&person=ana&action=login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )
    back = code_wallet.client.get(after_form.headers["location"], follow_redirects=False)
    assert [first.status_code, after_form.status_code, back.status_code] == [303, 303, 303]


@pytest.mark.parametrize(("review", "status"), [("true", 202), ("yes", 200)])
def test_the_test_login_can_hold_the_credentials_for_review(
    code_wallet: CodeWallet, code_issuer: Issuer, review: str, status: int
) -> None:
    """The test login's box puts the login's credentials on hold, as a login service would with review: true, so a
    probe can try deferred issuance against a development cunho. Only its value true holds."""
    pkce = Pkce.random()
    page = code_wallet.client.get(code_wallet.authorize(pushed(code_wallet, code_issuer, pkce)[0]).headers["location"])
    assert 'type="checkbox" name="review" value="true"' in page.text
    code_wallet.token = code_wallet.code_token_request(
        code_of(code_wallet, code_issuer, pkce, {**LOGIN, "review": review}), pkce
    ).json()["access_token"]
    issued = code_wallet.issue()
    assert issued.status_code == status, issued.text


def test_the_rfc_7636_vector_works_end_to_end(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.rfc7636_appendix_b()
    response = code_wallet.code_token_request(code_of(code_wallet, code_issuer, pkce), pkce)
    assert response.status_code == 200, response.text


@pytest.mark.obligation("VCI.AUTHZ_DETAILS")
def test_authorization_details_give_credential_identifiers(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """OpenID4VCI §5.1.1, §6.2, §8.2: identifiers in the token response, then credential_identifier only."""
    pkce = Pkce.random()
    details = [{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}]
    code = code_of(code_wallet, code_issuer, pkce, scope=None, authorization_details=details)
    body = code_wallet.code_token_request(code, pkce).json()
    [detail] = body["authorization_details"]
    assert detail["type"] == "openid_credential" and detail["credential_configuration_id"] == PID_CONFIG
    [identifier] = detail["credential_identifiers"]
    code_wallet.token = body["access_token"]
    holder = EcKey.generate()
    proof = code_wallet.proof(holder, code_wallet.c_nonce())
    by_id = code_wallet.credential_request({"credential_identifier": identifier, "proofs": {"jwt": [proof]}})
    assert by_id.status_code == 200, by_id.text


@pytest.mark.covers("VCI.AUTHZ_DETAILS", "VCI.CRED.ERROR_CODES")
def test_with_identifiers_only_a_known_identifier_is_taken(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    details = [{"type": "openid_credential", "credential_configuration_id": PID_CONFIG}]
    body = code_wallet.code_token_request(code_of(code_wallet, code_issuer, pkce, authorization_details=details), pkce)
    code_wallet.token = body.json()["access_token"]
    proof = code_wallet.proof(EcKey.generate(), code_wallet.c_nonce())
    by_config = refused_by(
        lambda: code_wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}}),
        "VCI.AUTHZ_DETAILS",
        "send credential_identifier",
    )
    assert by_config.json()["error"] == "invalid_credential_request"
    unknown = refused_by(
        lambda: code_wallet.credential_request({"credential_identifier": "nope", "proofs": {"jwt": [proof]}}),
        "VCI.CRED.ERROR_CODES",
        "unknown credential_identifier",
    )
    assert unknown.json()["error"] == "unknown_credential_identifier"


def test_without_identifiers_a_credential_identifier_is_refused(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    code_wallet.token = code_wallet.code_token_request(code_of(code_wallet, code_issuer, pkce), pkce).json()[
        "access_token"
    ]
    response = refused_by(
        lambda: code_wallet.credential_request({"credential_identifier": "x", "proofs": {"jwt": []}}),
        "VCI.CRED.ERROR_CODES",
        "came with no credential identifiers",
    )
    assert response.json()["error"] == "unknown_credential_identifier"


def test_unknown_scopes_are_ignored_beside_a_known_one(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce, scope=f"openid unknown-scope {pid_scope(code_issuer)}")
    assert code_wallet.code_token_request(code, pkce).status_code == 200


@pytest.mark.obligation("OAUTH.AS_METADATA_M3", "OAUTH.PKCE_S256")
def test_the_as_metadata_advertises_the_code_flow_and_its_routes_exist(code_wallet: CodeWallet) -> None:
    document = code_wallet.client.get("/.well-known/oauth-authorization-server").json()
    assert document["issuer"] == ISSUER
    assert document["authorization_endpoint"] == f"{ISSUER}/authorize"
    assert document["pushed_authorization_request_endpoint"] == f"{ISSUER}/par"
    assert document["require_pushed_authorization_requests"] is True
    assert document["code_challenge_methods_supported"] == ["S256"]
    assert document["response_types_supported"] == ["code"]
    assert set(document["grant_types_supported"]) == {
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
    }
    assert document["token_endpoint_auth_methods_supported"] == ["attest_jwt_client_auth", "none"]
    assert document["client_attestation_signing_alg_values_supported"] == ["ES256", "ES384", "ES512"]
    assert document["client_attestation_pop_signing_alg_values_supported"] == ["ES256", "ES384", "ES512"]
    assert document["authorization_response_iss_parameter_supported"] is True
    paths = {route.path for route in code_wallet.client.app.routes}  # type: ignore[attr-defined]
    for name in ("authorization_endpoint", "pushed_authorization_request_endpoint", "token_endpoint"):
        assert document[name].removeprefix(ISSUER) in paths, name


# the login ----------------------------------------------------------------------------------------


@pytest.mark.obligation("OAUTH.ACCESS_DENIED", "OAUTH.AUTHZ_RESPONSE_ISS")
def test_a_cancelled_login_gives_access_denied_with_state_and_iss(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    request_uri, state = pushed(code_wallet, code_issuer, state="keep-me")
    back = code_wallet.login(code_wallet.authorize(request_uri), CANCEL)
    assert back.status == 303 and back.target == REDIRECT_URI
    assert back.params == {"error": "access_denied", "state": "keep-me", "iss": ISSUER}


def test_a_state_left_out_is_left_out_of_the_answer(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    pkce = Pkce.random()
    response = code_wallet.par(pkce, scope=pid_scope(code_issuer), drop=("state",))
    back = code_wallet.login(code_wallet.authorize(response.json()["request_uri"]), LOGIN)
    assert set(back.params) == {"code", "iss"}


def login_state_of(wallet: CodeWallet, issuer: Issuer, **kwargs: Any) -> str:
    request_uri, _ = pushed(wallet, issuer, **kwargs)
    location = wallet.authorize(request_uri).headers["location"]
    return Redirect(303, location).params["login_state"]


def report(wallet: CodeWallet, login_state: str, body: Any) -> Any:
    return wallet.client.post(
        f"/admin/logins/{login_state}", json=body, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
    )


@pytest.mark.obligation("ISS.SUBJECT.ENTITLEMENT")
def test_the_operator_reports_a_login_and_the_browser_gets_a_code(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """Decision 1: the operator's login service posts the subject to /admin/logins/{login_state}."""
    login_state = login_state_of(code_wallet, code_issuer)
    reported = report(code_wallet, login_state, {"subject": PID_SUBJECT, "loa": "high", "person": "p-1"})
    assert reported.status_code == 200 and reported.json()["subject_ref"].startswith("sub_")
    entry = code_issuer.audit.entries()[-1]
    assert entry["event"] == "offer.created" and entry["actor"] == "admin"
    assert (
        entry["data"]["flow"] == "authorization_code" and entry["data"]["subject_ref"] == reported.json()["subject_ref"]
    )
    assert "p-1" not in json.dumps(entry) and "Silva" not in json.dumps(entry), "no personal data in the log"
    resume = reported.json()["continue"]
    assert resume.startswith(f"{ISSUER}/authorize/continue?login_state={login_state}&completion=")
    back = code_wallet.client.get(resume, follow_redirects=False)
    assert back.status_code == 303 and Redirect(303, back.headers["location"]).params["code"]


@pytest.mark.covers("ISS.IDPROOF.PLUG_REQUIRED")
def test_a_pid_login_needs_assurance_level_high(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    login_state = login_state_of(code_wallet, code_issuer)
    for loa in (None, "substantial"):
        body = {"subject": PID_SUBJECT, "loa": loa}
        response = refused_by(
            functools.partial(report, code_wallet, login_state, body),
            "ISS.IDPROOF.PLUG_REQUIRED",
            "assurance level high",
        )
        assert response.status_code == 400
    assert report(code_wallet, login_state, {"subject": PID_SUBJECT, "loa": "high"}).status_code == 200


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT", "EAA.RULEBOOK.CONFORMANCE")
def test_a_login_report_is_checked_like_an_offer(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    login_state = login_state_of(code_wallet, code_issuer)
    bad_subject = refused_by(
        lambda: report(code_wallet, login_state, {"subject": {"given_name": "Ana"}, "loa": "high"}),
        "EAA.RULEBOOK.CONFORMANCE",
        "family_name",
    )
    assert bad_subject.status_code == 400
    unknown = refused_by(lambda: report(code_wallet, "nope", {"denied": True}), "ISS.SUBJECT.ENTITLEMENT", "unknown")
    assert unknown.status_code == 404
    assert report(code_wallet, login_state, {"denied": True, "subject": PID_SUBJECT}).status_code == 400
    assert report(code_wallet, login_state, {"denied": True}).status_code == 200
    again = refused_by(lambda: report(code_wallet, login_state, {"denied": True}), "ISS.SUBJECT.ENTITLEMENT", "unknown")
    assert again.status_code == 404, "a login is reported once"
    stranger = code_wallet.client.post(f"/admin/logins/{login_state}", json={"denied": True})
    assert stranger.status_code == 401


@pytest.mark.covers("OAUTH.ACCESS_DENIED")
def test_the_browser_cannot_come_back_before_the_login_is_reported(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    login_state = login_state_of(code_wallet, code_issuer)
    early = refused_by(
        lambda: code_wallet.client.get(f"/authorize/continue?login_state={login_state}", follow_redirects=False),
        "OAUTH.ACCESS_DENIED",
        "not finished",
    )
    assert early.status_code == 400 and "location" not in early.headers
    resume = report(code_wallet, login_state, {"subject": PID_SUBJECT, "loa": "high"}).json()["continue"]
    first = code_wallet.client.get(resume, follow_redirects=False)
    assert first.status_code == 303
    second = refused_by(
        lambda: code_wallet.client.get(resume, follow_redirects=False),
        "OAUTH.ACCESS_DENIED",
        "unknown, expired or used",
    )
    assert second.status_code == 400
    missing = refused_by(
        lambda: code_wallet.client.get("/authorize/continue", follow_redirects=False),
        "OAUTH.ACCESS_DENIED",
        "login_state is required",
    )
    assert missing.status_code == 400


# offers for the code flow ---------------------------------------------------------------------------


def code_offer(wallet: CodeWallet, configs: list[str] | None = None, **extra: Any) -> Any:
    return wallet.admin(
        "offers", {"credential_configuration_ids": configs or [PID_CONFIG], "grant": "authorization_code", **extra}
    )


@pytest.mark.obligation("VCI.OFFER.AUTH_CODE_GRANT", "VCI.ISSUER_STATE")
def test_an_issuer_initiated_offer_carries_the_code_grant(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    response = code_offer(code_wallet)
    assert response.status_code == 201, response.text
    offer = response.json()["credential_offer"]
    assert offer["credential_configuration_ids"] == [PID_CONFIG]
    assert set(offer["grants"]) == {"authorization_code"}
    issuer_state = offer["grants"]["authorization_code"]["issuer_state"]
    assert "scope" not in offer["grants"]["authorization_code"], "the scope comes from the metadata (HAIP §4.2)"
    assert response.json()["offer_link"].startswith("openid-credential-offer://?credential_offer=")
    pkce = Pkce.random()
    code = code_of(code_wallet, code_issuer, pkce, issuer_state=issuer_state)
    assert code_wallet.code_token_request(code, pkce).status_code == 200


@pytest.mark.covers("VCI.ISSUER_STATE")
def test_an_issuer_state_is_used_once_and_for_what_it_offered(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    code_issuer = make_code_issuer(published_configurations=(PID_CONFIG, IBAN))
    code_wallet = code_wallet_for(code_issuer)
    issuer_state = code_offer(code_wallet).json()["credential_offer"]["grants"]["authorization_code"]["issuer_state"]
    pushed(code_wallet, code_issuer, issuer_state=issuer_state)
    again = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), issuer_state=issuer_state),
        "VCI.ISSUER_STATE",
        "already used",
    )
    assert again.status_code == 400
    narrow = code_offer(code_wallet, [IBAN]).json()["credential_offer"]["grants"]["authorization_code"]["issuer_state"]
    wider = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), issuer_state=narrow),
        "VCI.ISSUER_STATE",
        "did not offer",
    )
    assert wider.status_code == 400
    forged = refused_by(
        lambda: code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), issuer_state="made-up"),
        "VCI.ISSUER_STATE",
        "unknown",
    )
    assert forged.status_code == 400


@pytest.mark.covers("VCI.OFFER.AUTH_CODE_GRANT", "VCI.OFFER.SHAPE")
def test_a_code_offer_takes_no_subject(code_wallet: CodeWallet) -> None:
    for extra in ({"subject": PID_SUBJECT}, {"tx_code_length": 4}, {"person": "p-1"}):
        offer = functools.partial(code_offer, code_wallet, **extra)
        response = refused_by(offer, "VCI.OFFER.AUTH_CODE_GRANT", "the login says")
        assert response.status_code == 400
    wrong = refused_by(lambda: code_offer(code_wallet, grant="implicit"), "VCI.OFFER.SHAPE", "grant must be")
    assert wrong.status_code == 400


# settings -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"production": True, "test_login_persons": Path("p.json")}, "refuses to start in production"),
        ({"login_url": "http://login.test/start"}, "login_url must be an https URL"),
        ({"login_url": "https://login.test/start", "test_login_persons": Path("p.json")}, "not both"),
        ({"redirect_uris": {CLIENT_ID: ("http://wallet.test/cb",)}}, "not http except on a loopback"),
        ({"redirect_uris": {CLIENT_ID: ("https://wallet.test/cb#frag",)}}, "without a fragment"),
        ({"redirect_uris": {CLIENT_ID: ("https://wallet.test/cb#",)}}, "without a fragment"),
        ({"login_url": "https://login.test/sign-in#"}, "login_url must be an https URL without a fragment"),
        ({"login_url": "https:///sign-in"}, "login_url must be an https URL without a fragment"),
        ({"redirect_uris": {CLIENT_ID: ("/cb",)}}, "must be absolute"),
        ({"redirect_uris": {CLIENT_ID: ("eu.wallet:",)}}, "must be absolute"),
        ({"redirect_uris": {CLIENT_ID: ["https://wallet.test/cb"]}}, "maps each wallet solution"),
        ({"par_ttl": 600}, "par_ttl must be a whole number from 1 to 599"),
        ({"code_ttl": 61}, "code_ttl must be a whole number from 1 to 60"),
        ({"login_ttl": 0}, "login_ttl must be a whole number from 1 to 600"),
        ({"client_attestation_pop_window": 301}, "client_attestation_pop_window must be"),
        ({"code_ttl": True}, "code_ttl must be a whole number"),
        ({"redirect_uris": {CLIENT_ID: (7,)}}, "redirect URI 7"),
        ({"redirect_uris": {7: ("https://wallet.test/cb",)}}, "maps each wallet solution"),
        ({"redirect_uris": {"": ("https://wallet.test/cb",)}}, "maps each wallet solution"),
        ({"par_ttl": 30.5}, "par_ttl must be a whole number"),
        ({"login_ttl": "600"}, "login_ttl must be a whole number"),
    ],
)
def test_code_flow_settings_refuse_what_is_unsafe(
    pki: Pki, tmp_path: Path, change: dict[str, Any], reason: str
) -> None:
    from .helpers import production_kwargs

    base = production_kwargs(pki, tmp_path) if change.get("production") else settings_kwargs(pki)
    with pytest.raises(ConfigError, match=reason):
        Settings(**{**base, **change})


@pytest.mark.parametrize(
    "uri",
    [
        "https://wallet.test/cb",
        "http://127.0.0.1:8123/cb",
        "http://[::1]/cb",
        "eu.wallet://callback",
        "eu.wallet:/callback",
    ],
)
def test_redirect_uris_a_wallet_can_use_are_accepted(pki: Pki, uri: str) -> None:
    Settings(**{**settings_kwargs(pki), "redirect_uris": {CLIENT_ID: (uri,)}})


def test_the_redirect_uris_come_from_the_environment(pki: Pki) -> None:
    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": ADMIN_TOKEN,
        "CUNHO_SIGNING_KEY": "k",
        "CUNHO_SIGNING_CHAIN": "c",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "a",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{ISSUER}/certs/signer.pem",
        "CUNHO_REDIRECT_URIS": json.dumps({CLIENT_ID: [REDIRECT_URI]}),
        "CUNHO_LOGIN_URL": "https://login.test/start",
        "CUNHO_CODE_TTL": "30",
    }
    settings = Settings.from_env(env)
    assert settings.redirect_uris == {CLIENT_ID: (REDIRECT_URI,)} and settings.code_ttl == 30
    for bad in ("[]", "{", '{"a": "https://wallet.test/cb"}'):
        with pytest.raises(ConfigError, match="JSON object of arrays"):
            Settings.from_env({**env, "CUNHO_REDIRECT_URIS": bad})


@pytest.mark.obligation("VCI.SCOPE_TO_CONFIG")
def test_two_configurations_with_one_scope_stop_the_start(make_code_issuer: Callable[..., Issuer]) -> None:
    from cunho.authorize import Authorization

    issuer = make_code_issuer(published_configurations=(PID_CONFIG, IBAN))
    assert set(issuer.authorization.scopes.values()) == {PID_CONFIG, IBAN}
    configs = issuer.configs
    first, second = PID_CONFIG, IBAN
    clash = {**configs.all, second: {**configs.all[second], "scope": configs.all[first]["scope"]}}
    with pytest.raises(ConfigError, match="publish the same scope"):
        Authorization._scope_map(type(configs)(clash, configs.batch_size, configs.findings, configs.published, "ES256"))


def test_the_test_login_page_escapes_what_it_echoes(code_wallet: CodeWallet) -> None:
    page = code_wallet.client.get('/test-login?login_state="><script>x</script>')
    assert page.status_code == 200 and "<script>x" not in page.text


def test_without_test_persons_there_is_no_test_login(client: TestClient) -> None:
    assert client.get("/test-login").status_code == 404


def test_a_thumbprint_names_the_dpop_key(code_wallet: CodeWallet) -> None:
    assert len(thumbprint(code_wallet.dpop_key.public_jwk())) == 43


@pytest.mark.covers("ISS.IDPROOF.PLUG_REQUIRED")
def test_without_a_login_service_no_authorization_starts(
    make_issuer: Callable[..., Issuer], code_files: dict[str, Path], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    issuer = make_issuer(wallet_provider_anchors=code_files["anchors"], redirect_uris={CLIENT_ID: (REDIRECT_URI,)})
    wallet = code_wallet_for(issuer)
    request_uri, _ = pushed(wallet, issuer)
    response = refused_by(lambda: wallet.authorize(request_uri), "ISS.IDPROOF.PLUG_REQUIRED", "no login service")
    assert response.status_code == 503 and "location" not in response.headers


@pytest.mark.parametrize("content", ["{}", "[]", '[{"ana": 1}]', '"ana"', '{"ana": 1}', "{"])
def test_the_test_persons_file_must_hold_persons(
    make_code_issuer: Callable[..., Issuer], tmp_path: Path, content: str
) -> None:
    persons = tmp_path / "persons.json"
    persons.write_text(content)
    with pytest.raises(ConfigError, match="test login persons"):
        make_code_issuer(test_login_persons=persons)


def test_an_operator_login_service_gets_the_browser(
    make_issuer: Callable[..., Issuer], code_files: dict[str, Path], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    issuer = make_issuer(
        wallet_provider_anchors=code_files["anchors"],
        redirect_uris={CLIENT_ID: (REDIRECT_URI,)},
        login_url="https://login.operator.test/start?lang=pt",
    )
    wallet = code_wallet_for(issuer)
    request_uri, _ = pushed(wallet, issuer)
    location = wallet.authorize(request_uri).headers["location"]
    assert location.startswith("https://login.operator.test/start?lang=pt&login_state=")


@pytest.mark.covers("OAUTH.ACCESS_DENIED")
def test_the_wallet_that_started_a_login_cannot_collect_its_code(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """The wallet knows login_state from the redirect it was given; only the person's browser, sent on by the login
    service, has the completion secret. So an attacker who gets someone else to log in on its request gets nothing
    by polling with login_state (the second reviewer)."""
    login_state = login_state_of(code_wallet, code_issuer)
    resume = report(code_wallet, login_state, {"subject": PID_SUBJECT, "loa": "high"}).json()["continue"]
    for query in (f"login_state={login_state}", f"login_state={login_state}&completion=guess"):
        polled = refused_by(
            functools.partial(code_wallet.client.get, f"/authorize/continue?{query}", follow_redirects=False),
            "OAUTH.ACCESS_DENIED",
            "not completed in this browser",
        )
        assert polled.status_code == 400 and "location" not in polled.headers
    back = code_wallet.client.get(resume, follow_redirects=False)
    assert back.status_code == 303 and Redirect(303, back.headers["location"]).params["code"], (
        "the person still gets it"
    )


def test_a_denied_login_also_needs_its_completion_secret(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    login_state = login_state_of(code_wallet, code_issuer)
    resume = report(code_wallet, login_state, {"denied": True}).json()["continue"]
    refused_by(
        lambda: code_wallet.client.get(f"/authorize/continue?login_state={login_state}", follow_redirects=False),
        "OAUTH.ACCESS_DENIED",
        "not completed in this browser",
    )
    back = code_wallet.client.get(resume, follow_redirects=False)
    assert Redirect(303, back.headers["location"]).params["error"] == "access_denied"


def test_the_shortest_code_flow_lifetimes_are_accepted(pki: Pki) -> None:
    settings = Settings(**{**settings_kwargs(pki), "par_ttl": 1, "login_ttl": 1, "code_ttl": 1})
    assert (settings.par_ttl, settings.login_ttl, settings.code_ttl) == (1, 1, 1)
    Settings(
        **{
            **settings_kwargs(pki),
            "par_ttl": 599,
            "login_ttl": 600,
            "code_ttl": 60,
            "client_attestation_pop_window": 300,
        }
    )


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT")
@pytest.mark.parametrize("person", ["has space", "", 7, "x" * 201])
def test_a_login_reports_person_handle_is_checked(code_wallet: CodeWallet, code_issuer: Issuer, person: Any) -> None:
    login_state = login_state_of(code_wallet, code_issuer)
    body = {"subject": PID_SUBJECT, "loa": "high", "person": person}
    response = refused_by(
        functools.partial(report, code_wallet, login_state, body), "ISS.SUBJECT.ENTITLEMENT", "person must be"
    )
    assert response.status_code == 400


@pytest.mark.covers("ISS.SUBJECT.ENTITLEMENT")
@pytest.mark.parametrize("body", [{"denied": True}, {"subject": PID_SUBJECT, "loa": "high"}])
def test_a_login_reported_twice_at_once_is_taken_once(
    code_wallet: CodeWallet, code_issuer: Issuer, monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]
) -> None:
    """Another report takes the login after this one saw it: this one is refused and writes nothing."""
    login_state = login_state_of(code_wallet, code_issuer)
    store = code_issuer.store
    real_take = store.take

    def taken_meanwhile(ns: str, key: str) -> Any:
        if ns == "login":
            real_take(ns, key)
            return None
        return real_take(ns, key)

    entries = len(code_issuer.audit.entries())
    monkeypatch.setattr(store, "take", taken_meanwhile)
    response = refused_by(
        functools.partial(report, code_wallet, login_state, body), "ISS.SUBJECT.ENTITLEMENT", "already reported"
    )
    assert response.status_code == 404
    assert len(code_issuer.audit.entries()) == entries and store.items("login-done") == []
