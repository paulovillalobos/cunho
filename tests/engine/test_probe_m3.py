"""The probe's checks of M3 (piece J) run against cunho itself, in process: every one passes, and each check that
tries a bypass fails once the rule it tests is switched off in cunho, so a pass means the rule held."""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

import cunho.rules
from cunho import app as app_module
from cunho import authorize, client_auth, oauth, proofs, service
from cunho.app import create_app
from cunho.service import Issuer
from eudi_probe.attester import WalletProvider
from eudi_probe.authcode import CodeFlow, FlowFailure
from eudi_probe.checks import ERROR, FAIL, PASS, REGISTRY, SKIP, WARN, Outcome
from eudi_probe.context import CodeTokens, Context, ProbeConfig
from eudi_probe.wallet import AttestationIssuer

from .codewallet import CLIENT_ID, REDIRECT_URI
from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, Clock, EcKey, Pki
from .pki import TestPki

SECOND_CLIENT, SECOND_REDIRECT = "https://other-wallet-solution.test", "https://other-wallet.test/callback"
M3_CHECKS = sorted(c.id for c in REGISTRY if c.group in ("authorization", "attestation")) + [
    "M17",
    "M18",
    "M19",
    "M20",
    "M21",
    "M22",
    "M23",
]
# M20 has nothing to look at: no metadata member for an embedded disclosure policy is standardised yet.
SKIPPED = {"M20"}

# The rule each bypass check tests, which switched off must make the check fail. Where cunho refuses the same request
# by a second rule as well, both are switched off.
BYPASSED: dict[str, str | tuple[str, ...]] = {
    "A04": "OAUTH.PAR_REQUEST_URI_ONCE",
    "A05": "OAUTH.PAR_REQUEST_URI_ONCE",
    "A06": ("OAUTH.PAR_REQUIRED", "OAUTH.PAR_REQUEST_URI_ONCE"),
    "A07": ("OAUTH.PKCE_VERIFIER", "OAUTH.PKCE_S256"),
    "A08": "OAUTH.PKCE_S256",
    "A09": "OAUTH.REDIRECT_URI_EXACT",
    "A10": "OAUTH.RESPONSE_TYPE_CODE",
    "A11": "OAUTH.PKCE_VERIFIER",
    "A12": "OAUTH.REDIRECT_URI_EXACT",
    "A13": ("OAUTH.CODE_ONCE_60S", "VCI.TOKEN.INVALID_GRANT"),
    "A14": "WIA.CLIENT_ID_IS_SUB",
    "A17": "BATCH.REISSUE_SAME_WALLET_UNIT",
    "A18": ("OAUTH.NO_TOKEN_IN_QUERY", "OAUTH.RESOURCE_401_CHALLENGE"),
    "A21": "DPOP.KEY_BOUND_TO_TOKEN",
    "W01": "WIA.REQUIRED_AT_PAR_AND_TOKEN",
    "W02": "WIA.CHAIN_TO_WP_LIST",
    "W03": "WIA.SIGNATURE_X5C",
    "W04": "WIA.POP_CNF",
    "W05": "WIA.NOT_EXPIRED",
    "W06": ("WIA.VERIFY", "WIA.CLIENT_ID_IS_SUB"),
    "W07": "WIA.POP_FRESH",
    "W08": "WIA.POP_FRESH",
    "W09": "WIA.REQUIRED_AT_PAR_AND_TOKEN",
    "W10": "KA.CHAIN_TO_WP_LIST",
}


@pytest.fixture
def probe_issuer(make_code_issuer: Callable[..., Issuer], pki: Pki, clock: Clock) -> Issuer:
    clock.now = time.time()  # the probe signs with the time of the machine it runs on
    return make_code_issuer(
        access_signing_key=pki.root / "access.key",
        access_signing_chain=pki.root / "access.pem",
        access_trust_anchors=pki.root / "issuer-root.pem",
        registration_certificate=pki.root / "registration.jwt",
        registrar_dataset=pki.root / "registrar.json",
        preferred_client_status_period=86_400,
        redirect_uris={CLIENT_ID: (REDIRECT_URI,), SECOND_CLIENT: (SECOND_REDIRECT,)},
    )


@pytest.fixture
def probe(probe_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> Iterator[Callable[[str], Outcome]]:
    """Run one check by id against the issuer, with a fresh context each time, as the probe's CLI would."""
    app = create_app(issuer=probe_issuer, background_maintenance=False)
    # A crash is answered with 500, as a server would, so the probe sees it.
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as client:

        def run(check_id: str) -> Outcome:
            config = config_for(client, pki, trust_pki)
            if check_id == "A20":  # an issuer-initiated offer of the code flow, as an offer command would print
                body = {"credential_configuration_ids": [PID_CONFIG], "grant": "authorization_code"}
                made = client.post("/admin/offers", json=body, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
                config.offer = json.dumps(made.json()["credential_offer"])
            check = next(c for c in REGISTRY if c.id == check_id)
            return check.fn(Context(config))

        yield run


def config_for(client: TestClient, pki: Pki, trust_pki: TestPki) -> ProbeConfig:
    """The probe as the CLI would set it up against cunho's test deployment."""
    provider = trust_pki.wallet_provider.root
    return ProbeConfig(
        issuer=ISSUER,
        client=client,
        attestation_issuer=AttestationIssuer.under(pki.wallet_ca, pki.wallet_ca_key),
        wallet_provider=WalletProvider.under(provider.cert, provider.key),
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        login_fields={"person": "ana", "action": "login"},
        cancel_fields={"person": "ana", "action": "cancel"},
        second_client=(SECOND_CLIENT, SECOND_REDIRECT),
    )


@pytest.mark.parametrize("check_id", M3_CHECKS)
def test_every_m3_check_passes_against_cunho(probe: Callable[[str], Outcome], check_id: str) -> None:
    outcome = probe(check_id)
    assert outcome.status == (SKIP if check_id in SKIPPED else PASS), (outcome.detail, outcome.evidence)


def test_the_m3_checks_pass_one_after_another_in_one_run(probe_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> None:
    """As the probe's command line runs them: in the catalogue's order, in one context, so a check that spends what
    another set up shows (A02 spends the shared token's credential before A18 runs)."""
    app = create_app(issuer=probe_issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as client:
        ctx = Context(config_for(client, pki, trust_pki))
        outcomes = {c.id: c.fn(ctx) for c in REGISTRY if c.id in M3_CHECKS and c.id != "A20"}
    wrong = {i: (o.status, o.detail) for i, o in outcomes.items() if o.status != (SKIP if i in SKIPPED else PASS)}
    assert not wrong, wrong


def switch_off(rules: str | tuple[str, ...], monkeypatch: pytest.MonkeyPatch) -> None:
    """cunho without these rules: their refusals do nothing, wherever they are enforced."""
    real = cunho.rules.refuse
    off = {rules} if isinstance(rules, str) else set(rules)

    def refuse(refused: str, *args: Any, **kwargs: Any) -> Any:
        if refused in off:
            return None
        return real(refused, *args, **kwargs)

    for module in (cunho.rules, service, client_auth, app_module, authorize, oauth, proofs):
        if hasattr(module, "refuse"):
            monkeypatch.setattr(module, "refuse", refuse)


@pytest.mark.parametrize("check_id", sorted(BYPASSED))
def test_each_bypass_check_fails_once_its_rule_is_switched_off(
    probe: Callable[[str], Outcome], monkeypatch: pytest.MonkeyPatch, check_id: str
) -> None:
    switch_off(BYPASSED[check_id], monkeypatch)
    outcome = probe(check_id)
    assert outcome.status in (FAIL, WARN), (BYPASSED[check_id], outcome.status, outcome.detail, outcome.evidence)


def test_every_bypass_check_is_tested_with_its_rule_off() -> None:
    sensitive = {c.id for c in REGISTRY if c.sensitive and c.group in ("authorization", "attestation")}
    assert sensitive == set(BYPASSED)


def test_a_bypass_check_after_a_rotating_refresh_is_not_fooled_by_a_spent_token(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An issuer that rotates refresh tokens spends the one A16 used. A17 and A21 must not take the refusal of that
    spent token for a binding (the second reviewer): with the bindings switched off they fail."""
    real = authorize.Authorization.refresh

    def rotating(self: authorize.Authorization, one: Any, dpop: Any, headers: Any) -> Any:
        answer = real(self, one, dpop, headers)
        self._store.delete("refresh", authorize._hash(str(one("refresh_token"))))
        return answer

    monkeypatch.setattr(authorize.Authorization, "refresh", rotating)
    switch_off(("BATCH.REISSUE_SAME_WALLET_UNIT", "DPOP.KEY_BOUND_TO_TOKEN"), monkeypatch)
    app = create_app(issuer=probe_issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as client:
        ctx = Context(config_for(client, pki, trust_pki))
        by_id = {c.id: c for c in REGISTRY}
        assert by_id["A16"].fn(ctx).status == PASS
        assert by_id["A17"].fn(ctx).status == FAIL
        assert by_id["A21"].fn(ctx).status == FAIL


def test_the_code_flow_answers_a_dpop_nonce_challenge(
    make_code_issuer: Callable[..., Issuer], pki: Pki, trust_pki: TestPki, clock: Clock
) -> None:
    """A server that asks for DPoP nonces (RFC 9449 §8) gets each request again with one (the second reviewer)."""
    clock.now = time.time()
    issuer = make_code_issuer(dpop_server_nonce=True)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        ctx = Context(config_for(client, pki, trust_pki))
        got = ctx.code_tokens()
        assert isinstance(got, CodeTokens), got
        assert got.flow.client.dpop_nonce is not None
        assert next(c for c in REGISTRY if c.id == "A16").fn(ctx).status == PASS


def test_identifiers_count_only_when_there_are_some() -> None:
    """A19 compares credential identifiers only when the token response grants some (the second reviewer)."""
    from eudi_probe.checks import granted_identifiers
    from eudi_probe.context import Exchange

    def answer(details: Any) -> Exchange:
        return Exchange("POST", "/token", 200, {}, json.dumps({"authorization_details": details}))

    config = {"type": "openid_credential", "credential_configuration_id": PID_CONFIG}
    assert granted_identifiers(answer([config]), PID_CONFIG) == []
    assert granted_identifiers(answer([{**config, "credential_identifiers": []}]), PID_CONFIG) == []
    assert granted_identifiers(answer([{**config, "credential_identifiers": [""]}]), PID_CONFIG) == []
    assert granted_identifiers(answer([{**config, "credential_identifiers": ["a"]}]), PID_CONFIG) == ["a"]
    assert granted_identifiers(answer([{**config, "credential_identifiers": ["a"]}]), "other") == []


def test_a_query_token_check_fails_against_an_issuer_that_takes_query_tokens(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """The request A18 sends is valid in every other way, so only the token's place can decide it (the second
    reviewer): an issuer that reads the token from the query, here cunho behind a shim that moves it into the
    header, fails the check."""
    inner = create_app(issuer=probe_issuer, background_maintenance=False)

    async def takes_query_tokens(scope: dict[str, Any], receive: Any, send: Any) -> None:
        query = parse_qs(scope.get("query_string", b"").decode()) if scope["type"] == "http" else {}
        if "access_token" in query:
            headers = [h for h in scope["headers"] if h[0] != b"authorization"]
            headers.append((b"authorization", f"DPoP {query['access_token'][0]}".encode()))
            scope = {**scope, "headers": headers, "query_string": b""}
        await inner(scope, receive, send)

    with TestClient(takes_query_tokens, base_url=ISSUER, raise_server_exceptions=False) as client:  # type: ignore[arg-type]
        outcome = next(c for c in REGISTRY if c.id == "A18").fn(Context(config_for(client, pki, trust_pki)))
    assert outcome.status == FAIL, (outcome.detail, outcome.evidence)


def test_a_token_counts_as_ended_only_when_the_server_says_invalid_token() -> None:
    """A13 passes only on invalid_token; an unrelated refusal shows nothing about the token (the second reviewer)."""
    from eudi_probe.checks import ERROR, token_ended
    from eudi_probe.context import Exchange

    again = Exchange("POST", "/token", 400, {}, '{"error":"invalid_grant"}')

    def credential(status: int, body: str = "", challenge: str = "") -> Exchange:
        return Exchange("POST", "/credential", status, {"www-authenticate": challenge} if challenge else {}, body)

    assert token_ended(again, credential(401, '{"error":"invalid_token"}')).status == PASS
    assert token_ended(again, credential(401, "", 'DPoP error="invalid_token"')).status == PASS
    assert token_ended(again, credential(200)).status == WARN
    assert token_ended(again, credential(400, '{"error":"invalid_proof"}')).status == WARN  # taken, judged on its proof
    assert token_ended(again, credential(400, '{"error":"invalid_request"}')).status == ERROR
    assert token_ended(again, credential(500)).status == ERROR
    assert token_ended(again, credential(0, "transport error")).status == ERROR


def test_a_login_command_opens_the_authorization_request_itself(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki, tmp_path: Path
) -> None:
    """The command gets the whole authorization request, the endpoint's own query kept, and the probe sends nothing
    to the endpoint first, so a session the server keeps in cookies is the command's own (the second reviewer)."""
    seen = tmp_path / "seen"
    command = f"{sys.executable} -c \"import os; open('{seen}', 'w').write(os.environ['EUDI_PROBE_AUTHORIZE_URL'])\""
    app = create_app(issuer=probe_issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER) as client:
        config = config_for(client, pki, trust_pki)
        config.login_fields, config.login_cmd = None, command
        ctx = Context(config)
        client_ = ctx.code_client()
        assert client_ is not None
        failed = CodeFlow(ctx, client_).authorized(scope=ctx.scope_for(PID_CONFIG))
        assert isinstance(failed, FlowFailure), failed  # the command printed nothing to come back with
        query = parse_qs(urlsplit(seen.read_text()).query)
        assert seen.read_text().startswith(f"{ISSUER}/authorize?") and query["client_id"] == [CLIENT_ID]
        opened = client.get(
            f"/authorize?client_id={CLIENT_ID}&request_uri={query['request_uri'][0]}", follow_redirects=False
        )
        assert opened.status_code == 303, "the probe did not use the request_uri itself"


def test_a_code_flow_that_breaks_is_reported_not_skipped(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With everything configured, a server that cannot complete the flow fails A02 and leaves the checks that
    needed the flow with an error; only a missing prerequisite is a skip (the second reviewer)."""

    def broken_par(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("PAR is broken")

    monkeypatch.setattr(authorize.Authorization, "par", broken_par)
    app = create_app(issuer=probe_issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as client:
        by_id = {c.id: c for c in REGISTRY}
        outcomes = {i: by_id[i].fn(Context(config_for(client, pki, trust_pki))).status for i in ("A02", "A11", "A16")}
        config = config_for(client, pki, trust_pki)
        config.wallet_provider = None
        missing = by_id["A02"].fn(Context(config)).status
    assert outcomes == {"A02": FAIL, "A11": ERROR, "A16": ERROR}, outcomes
    assert missing == SKIP


def test_an_offer_without_issuer_state_is_skipped_not_failed(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """issuer_state is optional in an authorization_code grant (OpenID4VCI §4.1.1; the second reviewer)."""
    app = create_app(issuer=probe_issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER) as client:
        config = config_for(client, pki, trust_pki)
        offer = {"credential_issuer": ISSUER, "credential_configuration_ids": [PID_CONFIG]}
        config.offer = json.dumps({**offer, "grants": {"authorization_code": {}}})
        assert next(c for c in REGISTRY if c.id == "A20").fn(Context(config)).status == SKIP
        config.offer = json.dumps({**offer, "grants": {"authorization_code": {"issuer_state": 5}}})
        assert next(c for c in REGISTRY if c.id == "A20").fn(Context(config)).status == FAIL


def test_an_endpoint_with_a_query_keeps_it() -> None:
    """Parameters join a query the endpoint already has (the second reviewer)."""
    from eudi_probe.authcode import with_query

    assert with_query("https://as.example/authorize?tenant=x", {"client_id": "c"}) == (
        "https://as.example/authorize?tenant=x&client_id=c"
    )
    assert with_query("https://as.example/authorize", {"a": "1 2"}) == "https://as.example/authorize?a=1+2"


def test_the_query_token_check_answers_a_dpop_nonce_challenge(
    make_code_issuer: Callable[..., Issuer], pki: Pki, trust_pki: TestPki, clock: Clock
) -> None:
    """A server that asks for a DPoP nonce before it looks at the token gets the query-token request again with one,
    so an issuer that takes query tokens still fails the check (the second reviewer)."""
    clock.now = time.time()
    inner = create_app(issuer=make_code_issuer(dpop_server_nonce=True), background_maintenance=False)

    async def takes_query_tokens(scope: dict[str, Any], receive: Any, send: Any) -> None:
        query = parse_qs(scope.get("query_string", b"").decode()) if scope["type"] == "http" else {}
        if "access_token" in query:
            headers = [h for h in scope["headers"] if h[0] != b"authorization"]
            headers.append((b"authorization", f"DPoP {query['access_token'][0]}".encode()))
            scope = {**scope, "headers": headers, "query_string": b""}
        await inner(scope, receive, send)

    with TestClient(takes_query_tokens, base_url=ISSUER, raise_server_exceptions=False) as client:  # type: ignore[arg-type]
        ctx = Context(config_for(client, pki, trust_pki))
        got = ctx.code_tokens()
        assert isinstance(got, CodeTokens), got
        got.token.dpop_nonce = None  # as when the credential endpoint was never asked before
        outcome = next(c for c in REGISTRY if c.id == "A18").fn(ctx)
    assert outcome.status == FAIL, (outcome.detail, outcome.evidence)


def test_a_login_page_served_by_the_endpoint_counts_as_going_on(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """An authorization server may serve its login form at the endpoint itself (the second reviewer)."""
    from eudi_probe.checks import went_on
    from eudi_probe.context import Exchange

    with TestClient(create_app(issuer=probe_issuer, background_maintenance=False), base_url=ISSUER) as client:
        ctx = Context(config_for(client, pki, trust_pki))
        code_client = ctx.code_client()
        assert code_client is not None
        flow = CodeFlow(ctx, code_client)
    endpoint = f"{ISSUER}/authorize?client_id=c&request_uri=u"
    assert went_on(Exchange("GET", endpoint, 200, {}, "<form>"), flow)
    assert went_on(Exchange("GET", endpoint, 303, {"location": "/login?x=1"}, ""), flow)
    assert not went_on(Exchange("GET", endpoint, 303, {"location": f"{REDIRECT_URI}?error=invalid_request"}, ""), flow)
    assert not went_on(Exchange("GET", endpoint, 400, {}, '{"error":"invalid_request"}'), flow)


@pytest.fixture
def nonce_probe(
    make_code_issuer: Callable[..., Issuer], pki: Pki, trust_pki: TestPki, clock: Clock
) -> Iterator[Callable[[str], Outcome]]:
    """The probe against a cunho that asks for DPoP nonces, which it does after authenticating the wallet."""
    clock.now = time.time()
    app = create_app(issuer=make_code_issuer(dpop_server_nonce=True), background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as client:
        yield lambda check_id: next(c for c in REGISTRY if c.id == check_id).fn(
            Context(config_for(client, pki, trust_pki))
        )


def test_attestation_checks_hold_against_a_server_that_asks_for_nonces(
    nonce_probe: Callable[[str], Outcome], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry after a nonce challenge carries a fresh proof of possession with the same deliberate change, so W08
    gets past its first PAR and a refusal of the retry is never mistaken for the check (the second reviewer)."""
    assert nonce_probe("W08").status == PASS
    assert nonce_probe("W03").status == PASS
    switch_off("WIA.SIGNATURE_X5C", monkeypatch)
    assert nonce_probe("W03").status == FAIL


def test_the_token_check_of_the_code_reuse_spends_nothing(probe_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> None:
    """A13 asks about the token with a request refused for its proof alone, so the token's one credential for the
    configuration is still there afterwards (the second reviewer)."""
    from eudi_probe.checks import accepted, credential_body, token_check

    with TestClient(create_app(issuer=probe_issuer, background_maintenance=False), base_url=ISSUER) as client:
        ctx = Context(config_for(client, pki, trust_pki))
        got = ctx.code_tokens()
        assert isinstance(got, CodeTokens), got
        assert accepted(token_check(ctx, got.token, got.config_id, "check"))
        proof = ctx.proof_for(EcKey.generate(), ctx.c_nonce())
        issued = ctx.credential_request(got.token, credential_body(ctx, got.config_id, [proof]))
    assert issued.status == 200, issued.body


def test_attestation_checks_do_not_pass_when_the_fixture_itself_is_refused(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """A wallet provider the issuer does not trust makes every PAR fail; the checks must not take that for the
    issuer refusing each change (the second reviewer)."""
    with TestClient(create_app(issuer=probe_issuer, background_maintenance=False), base_url=ISSUER) as client:
        config = config_for(client, pki, trust_pki)
        config.wallet_provider = WalletProvider.untrusted()
        statuses = {
            i: next(c for c in REGISTRY if c.id == i).fn(Context(config)).status
            for i in ("W02", "W03", "W04", "W05", "W06", "W07")
        }
    assert set(statuses.values()) == {ERROR}, statuses


def test_a_login_form_answered_with_307_is_sent_again_as_it_was(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """307 and 308 keep the method and the body (RFC 9110 §15.4.8, §15.4.9), as a browser does (the second
    reviewer): a login service that moves its form's target this way still logs the person in."""
    inner = create_app(issuer=probe_issuer, background_maintenance=False)

    async def moved(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["method"] == "POST" and scope["path"] == "/test-login":
            await send({"type": "http.response.start", "status": 307, "headers": [(b"location", b"/moved-login")]})
            await send({"type": "http.response.body", "body": b""})
            return
        if scope["type"] == "http" and scope["path"] == "/moved-login":
            scope = {**scope, "path": "/test-login", "raw_path": b"/test-login"}
        await inner(scope, receive, send)

    with TestClient(moved, base_url=ISSUER, raise_server_exceptions=False) as client:  # type: ignore[arg-type]
        outcome = next(c for c in REGISTRY if c.id == "A02").fn(Context(config_for(client, pki, trust_pki)))
    assert outcome.status == PASS, (outcome.detail, outcome.evidence)


def test_the_code_flow_runs_against_an_issuer_that_checks_attestation_status(
    make_code_issuer: Callable[..., Issuer],
    code_files: dict[str, Path],
    pki: Pki,
    trust_pki: TestPki,
    clock: Clock,
) -> None:
    """With the status list entries the wallet provider publishes (--wia-status, --ka-status), the probe's
    attestations pass an issuer that checks their status; without them they cannot (the second reviewer)."""
    from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner

    clock.now = time.time()
    now = int(clock.now)
    wia = "https://wallet-provider.test/status/probe"
    served = ServedStatus()
    root = trust_pki.wallet_provider.root
    served.lists[wia] = StatusSigner.under(root.cert, root.key).token(wia, iat=now, exp=now + 86_400)
    ka_signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    served.lists[KA_STATUS_LIST] = ka_signer.token(KA_STATUS_LIST, iat=now, exp=now + 86_400)
    issuer = make_code_issuer(wallet_status_anchors=code_files["anchors"], fetcher=served)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        config = config_for(client, pki, trust_pki)
        a02 = next(c for c in REGISTRY if c.id == "A02")
        assert a02.fn(Context(config)).status == FAIL, "the placeholder status entries resolve nowhere"
        assert config.wallet_provider is not None and config.attestation_issuer is not None
        config.wallet_provider.status, config.attestation_issuer.status = (wia, 3), (KA_STATUS_LIST, 7)
        outcome = a02.fn(Context(config))
    assert outcome.status == PASS, (outcome.detail, outcome.evidence)


def test_a_get_form_replaces_the_query_of_its_action() -> None:
    """A browser submits a GET form to its action with the query replaced by the fields (the second reviewer)."""
    from eudi_probe.authcode import form_get

    assert form_get("https://as.example/login?old=1", {"person": "ana"}) == "https://as.example/login?person=ana"
    assert form_get("https://as.example/login", {"a": "1 2", "b": "x"}) == "https://as.example/login?a=1+2&b=x"


def test_the_untrusted_attestation_checks_keep_the_status_entries(
    make_code_issuer: Callable[..., Issuer],
    code_files: dict[str, Path],
    pki: Pki,
    trust_pki: TestPki,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Against an issuer that checks key attestation status, the untrusted attestation names the same, resolvable
    entry, so with chain trust switched off W10 fails instead of passing on a status refusal (the second reviewer)."""
    from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner

    clock.now = time.time()
    now = int(clock.now)
    served = ServedStatus()
    wia = "https://wallet-provider.test/status/probe"
    root = trust_pki.wallet_provider.root
    served.lists[wia] = StatusSigner.under(root.cert, root.key).token(wia, iat=now, exp=now + 86_400)
    ka_signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    served.lists[KA_STATUS_LIST] = ka_signer.token(KA_STATUS_LIST, iat=now, exp=now + 86_400)
    issuer = make_code_issuer(wallet_status_anchors=code_files["anchors"], fetcher=served)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        config = config_for(client, pki, trust_pki)
        assert config.wallet_provider is not None and config.attestation_issuer is not None
        config.wallet_provider.status, config.attestation_issuer.status = (wia, 3), (KA_STATUS_LIST, 7)
        by_id = {c.id: c for c in REGISTRY}
        assert by_id["W10"].fn(Context(config)).status == PASS
        assert by_id["W02"].fn(Context(config)).status == PASS
        switch_off(("KA.CHAIN_TO_WP_LIST", "WIA.CHAIN_TO_WP_LIST"), monkeypatch)
        outcomes = {i: by_id[i].fn(Context(config)) for i in ("W10", "W02")}
    assert {i: o.status for i, o in outcomes.items()} == {"W10": FAIL, "W02": FAIL}, outcomes


def test_a_login_form_is_read_as_a_browser_submits_it() -> None:
    """Selected options, checked boxes only, no buttons (HTML §4.10.21.4; the second reviewer)."""
    from eudi_probe.authcode import _Form

    form = _Form()
    form.feed(
        '<form method="post" action="/login"><input type="hidden" name="state" value="s">'
        '<select name="tenant"><option value="a">A</option><option value="main" selected>Main</option></select>'
        "<select name='lang'><option>en</option><option>pt</option></select>"
        '<input type="checkbox" name="remember" value="yes"><input type="checkbox" name="terms" checked>'
        '<input type="radio" name="mode" value="x"><input type="radio" name="mode" value="y" checked>'
        '<input type="text" name="off" value="z" disabled><textarea name="note">hi</textarea>'
        '<button type="submit" name="action" value="go">Go</button><input type="submit" name="ok" value="OK"></form>'
    )
    assert form.method == "post" and form.action == "/login"
    assert form.fields == {"state": "s", "tenant": "main", "lang": "en", "terms": "on", "mode": "y", "note": "hi"}


def test_login_fields_only_fill_controls_the_form_has() -> None:
    """A password for the login page never reaches a later consent form, nor a GET URL (the second reviewer); a
    field named as a button chooses that button."""
    from eudi_probe.authcode import _Form

    login, consent = _Form(), _Form()
    login.feed(
        '<form method="post"><input name="user"><input type="password" name="password">'
        '<button name="action" value="x">Go</button></form>'
    )
    consent.feed(
        '<form method="get" action="/consent"><input type="hidden" name="flow" value="f">'
        '<input type="checkbox" name="agree" value="1"></form>'
    )
    given = {"user": "ana", "password": "secret", "action": "login", "agree": "1"}
    assert login.submitted(given) == {"user": "ana", "password": "secret", "action": "login"}
    assert consent.submitted(given) == {"flow": "f", "agree": "1"}


def test_options_without_their_end_tags_are_read() -> None:
    """The end tag of an option may be left out (HTML §13.1.2.4; the second reviewer)."""
    from eudi_probe.authcode import _Form

    form = _Form()
    form.feed(
        '<form><select name="person"><option value="ana">Ana<option value="bob">Bob</select>'
        '<select name="lang"><option>en<option selected>pt</select></form>'
    )
    assert form.fields == {"person": "ana", "lang": "pt"}


def test_the_request_uri_binding_needs_a_second_client_the_issuer_allows(
    probe_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """With no second wallet solution configured, A05 cannot show the binding: an unknown client is refused for
    being unknown (the second reviewer)."""
    with TestClient(create_app(issuer=probe_issuer, background_maintenance=False), base_url=ISSUER) as client:
        config = config_for(client, pki, trust_pki)
        config.second_client = None
        assert next(c for c in REGISTRY if c.id == "A05").fn(Context(config)).status == SKIP
