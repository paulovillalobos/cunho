"""Hostile input on every route of the authorization code flow: never a server error.

Attestations and proofs of possession are correctly signed, so their hostile claims reach the checks after the
signature (review 4, N4-M1); text includes lone surrogates and NUL, which st.text() leaves out."""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest

from cunho.jose import b64u, b64u_json
from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet, Pkce, pid_scope
from .helpers import ADMIN_TOKEN, ISSUER, SLOW_IS_FINE

BIG = "1" + "0" * 400


def raw_jws(header: dict[str, Any], payload_text: str, key: EcKey) -> str:
    signing_input = f"{b64u_json(header)}.{b64u(payload_text.encode('utf-8', 'surrogatepass'))}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


GARBAGE: list[tuple[str, bytes, str]] = [
    ("empty", b"", "application/x-www-form-urlencoded"),
    ("invalid utf-8", b"\xff\xfe\xfd", "application/x-www-form-urlencoded"),
    ("repeated", b"client_id=a&client_id=b&scope=x&scope=y", "application/x-www-form-urlencoded"),
    ("percent garbage", b"client_id=%ff%fe&redirect_uri=%00&state=%ed%a0%80", "application/x-www-form-urlencoded"),
    ("details garbage", b"authorization_details=%5B" * 50, "application/x-www-form-urlencoded"),
    ("json", b'{"a": 1}', "application/json"),
    ("too large", b"a=" + b"A" * 300_000, "application/x-www-form-urlencoded"),
]


@pytest.mark.parametrize(("label", "body", "content_type"), GARBAGE, ids=[g[0] for g in GARBAGE])
@pytest.mark.parametrize("attest", [False, True])
def test_garbage_at_par_and_token_never_causes_a_server_error(
    code_wallet: CodeWallet, label: str, body: bytes, content_type: str, attest: bool
) -> None:
    for path in ("/par", "/token"):
        headers = [("Content-Type", content_type), *code_wallet.attestation_headers(attest=attest)]
        if path == "/token":
            body = body + b"&grant_type=authorization_code"
        response = code_wallet.client.post(path, content=body, headers=headers)
        assert 400 <= response.status_code < 500, (label, path, response.text[:200])
        assert isinstance(response.json()["error"], str)


@pytest.mark.parametrize(
    "query",
    [
        "",
        "request_uri=%ff",
        "request_uri=" + "A" * 10_000,
        "client_id=%00&request_uri=%ed%a0%80",
        "login_state=%ff%fe",
        "login_state=" + "A" * 129,
        "login_state=a&login_state=b",
    ],
)
def test_garbage_at_the_authorization_endpoint_never_causes_a_server_error(code_wallet: CodeWallet, query: str) -> None:
    for path in ("/authorize", "/authorize/continue", "/test-login"):
        response = code_wallet.client.get(f"{path}?{query}", follow_redirects=False)
        assert response.status_code < 500, (path, query, response.text[:200])


@pytest.mark.parametrize(
    "body", [b"", b"null", b"[]", b'"x"', b"{nope", b'{"denied": "yes"}', b'{"subject": 1, "loa": ["high"]}']
)
def test_garbage_login_reports_never_cause_a_server_error(
    code_wallet: CodeWallet, code_issuer: Issuer, body: bytes
) -> None:
    from .codewallet import Redirect, pushed

    request_uri, _ = pushed(code_wallet, code_issuer)
    login_state = Redirect(303, code_wallet.authorize(request_uri).headers["location"]).params["login_state"]
    for state in (login_state, "%ff", "x" * 200):
        response = code_wallet.client.post(
            f"/admin/logins/{state}",
            content=body,
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "application/json"},
        )
        assert 400 <= response.status_code < 500, (body, state, response.text[:200])
    for form in (b"", b"login_state=x&person=nobody&action=login", b"login_state=%ff&action=cancel"):
        response = code_wallet.client.post(
            "/test-login", content=form, headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert 400 <= response.status_code < 500, (form, response.text[:200])


def test_signed_attestations_with_hostile_claims_never_cause_a_server_error(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    hypothesis = pytest.importorskip("hypothesis")
    st = pytest.importorskip("hypothesis.strategies")
    # st.text() never yields a surrogate, whatever its alphabet, so the strings are joined from characters.
    odd = st.sampled_from(["\ud800", "\udfff", "\x00"])
    text = st.lists(st.characters(exclude_categories=()) | odd, max_size=20).map("".join)
    leaves = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | text
    values = st.recursive(
        leaves,
        lambda inner: st.lists(inner, max_size=3) | st.dictionaries(text, inner, max_size=3),
        max_leaves=6,
    )
    raw_numbers = st.sampled_from([BIG, "1e400", "-" + BIG])
    provider = code_wallet.provider
    assert provider is not None
    signer = EcKey(provider.wia_signer.key)
    scope = pid_scope(code_issuer)

    def par(attestation: str, pop: str) -> Any:
        headers = [("OAuth-Client-Attestation", attestation), ("OAuth-Client-Attestation-PoP", pop)]
        return code_wallet.par(Pkce.random(), scope=scope, headers=headers, attest=False)

    def payload(claims: dict[str, Any], claim: str, value: Any) -> str:
        """The claims as JSON with `value` under `claim`; a number written out as text goes in as it is."""
        if isinstance(value, str) and value in (BIG, "1e400", "-" + BIG):
            rest = {k: v for k, v in claims.items() if k != claim}
            return json.dumps(rest, ensure_ascii=True)[:-1] + f', "{claim}": {value}}}'
        return json.dumps({**claims, claim: value}, ensure_ascii=True)

    @hypothesis.settings(max_examples=150, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(
        st.sampled_from(["sub", "exp", "iat", "nbf", "cnf", "client_status", "wallet_name", "iss"]),
        values | raw_numbers,
    )
    def attestation(claim: str, value: Any) -> None:
        now = int(code_wallet.clock())
        claims = json.loads(json.dumps(_attestation_claims(code_wallet, now)))
        header = {"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": provider.wia_x5c()}
        token = raw_jws(header, payload(claims, claim, value), signer)
        response = par(token, code_wallet.attestation_pop())
        assert response.status_code in (201, 400, 401), response.text

    @hypothesis.settings(max_examples=150, deadline=None, database=None, suppress_health_check=SLOW_IS_FINE)
    @hypothesis.given(st.sampled_from(["aud", "iat", "jti", "iss"]), values | raw_numbers)
    def pop(claim: str, value: Any) -> None:
        claims = {"iss": code_wallet.client_id, "aud": ISSUER, "jti": uuid.uuid4().hex, "iat": int(code_wallet.clock())}
        token = raw_jws(
            {"typ": "oauth-client-attestation-pop+jwt", "alg": "ES256"},
            payload(claims, claim, value),
            code_wallet.instance_key,
        )
        response = par(code_wallet.attestation(), token)
        assert response.status_code in (201, 400, 401), response.text

    attestation()
    pop()


def _attestation_claims(wallet: CodeWallet, now: int) -> dict[str, Any]:
    return {
        "iss": "https://wallet-provider.test",
        "sub": wallet.client_id,
        "iat": now,
        "exp": now + 3600,
        "cnf": {"jwk": wallet.instance_key.public_jwk()},
        "client_status": {
            "status": {"status_list": {"idx": 3, "uri": "https://wallet-provider.test/status/wia"}},
            "exp": now + 60 * 86_400,
        },
    }
