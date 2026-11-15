"""What the security review found in how cunho reads what it is sent (research/cunho-security-review.md): values
that passed a check they should have failed, and answers the framework gave before cunho's own parsing ran. Each test
failed on the code as reviewed and holds its fix."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.errors import IssuerError
from cunho.jose import MAX_DEPTH, JoseError, JsonRefused, b64u, b64u_decode, parse_jws, strict_json
from cunho.service import Issuer
from eudi_probe.jose import EcKey, jws
from eudi_probe.wallet import dpop_proof

from .codewallet import WALLET_STATUS_LIST, CodeWallet, Pkce, pid_scope
from .helpers import (  # noqa: F811
    ADMIN_TOKEN,
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    PRE_AUTH,
    Clock,
    EcKey,
    Pki,
    Wallet,
    disclosures,
)
from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner
from .test_chaining import (  # noqa: F401 - the fixtures
    WIA_IDX,
    Lists,
    bit,
    chain_rows,
    chained,
    issue,
    ka_lists,
    lists,
    make_chained,
    run,
    served,
    wia_lists,
)
from .test_encryption import WalletKey, issuer_jwk, key_file, request_body, seal, send

# --- a base64url value that ends in a line feed, at the token endpoint and at PAR -------------------------------------


def _b64u_json(value: Any) -> str:
    return b64u(json.dumps(value, separators=(",", ":")).encode())


def _proof_with_jwk(wallet: Wallet, jwk: dict[str, Any]) -> str:
    """A compact JWS shaped as a DPoP proof whose header carries `jwk`. The signature is 64 bytes of nothing: the
    request never gets as far as checking it."""
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    claims = {"jti": "j" * 24, "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock())}
    return f"{_b64u_json(header)}.{_b64u_json(claims)}.{b64u(bytes(64))}"


@pytest.mark.parametrize("value", ["AAA\n", "AA\n", "A\n", "AAAAAAA\n"])
def test_the_base64url_decoder_refuses_a_trailing_line_feed_as_a_jose_error(value: str) -> None:
    """Every malformed value is a JoseError, which is what each caller of the decoder catches."""
    with pytest.raises(JoseError):
        b64u_decode(value)


@pytest.mark.parametrize("member", ["x", "y"])
def test_a_dpop_jwk_coordinate_ending_in_a_line_feed_is_refused_not_a_500(wallet: Wallet, member: str) -> None:
    jwk = EcKey.generate().public_jwk()
    jwk[member] = jwk[member][:-1] + "\n"  # still 43 characters, so the length check passes too
    code = wallet.offer()["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
    response = wallet.token_request(code, dpop=_proof_with_jwk(wallet, jwk))
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_dpop_proof"


def test_a_client_with_no_offer_and_no_token_is_refused_not_answered_500(wallet: Wallet) -> None:
    """The proof is read before the code: any made-up code will do, so the request needs nothing from the issuer."""
    jwk = EcKey.generate().public_jwk()
    jwk["x"] = "AAA\n"
    response = wallet.token_request("no-such-code", dpop=_proof_with_jwk(wallet, jwk))
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_dpop_proof"


def test_a_wallet_attestation_whose_cnf_coordinate_ends_in_a_line_feed_is_refused_not_a_500(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """Needs an attestation signed by a trusted wallet provider, so it is not a path for an outsider."""
    jwk = code_wallet.instance_key.public_jwk()
    jwk["x"] = jwk["x"][:-1] + "\n"
    headers = [
        ("OAuth-Client-Attestation", code_wallet.attestation(cnf={"jwk": jwk})),
        ("OAuth-Client-Attestation-PoP", code_wallet.attestation_pop()),
    ]
    response = code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), headers=headers, attest=False)
    assert response.status_code == 401, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_client"


def test_a_wallet_attestation_whose_identifier_ends_in_a_line_feed_is_refused_not_a_500(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    """As above: the identifier list entry of client_status goes through the same decoder (status_refs.py:61)."""
    status = {
        "status": {"identifier_list": {"id": "AAA\n", "uri": WALLET_STATUS_LIST}},
        "exp": int(code_wallet.clock()) + 86_400,
    }
    headers = [
        ("OAuth-Client-Attestation", code_wallet.attestation(client_status=status)),
        ("OAuth-Client-Attestation-PoP", code_wallet.attestation_pop()),
    ]
    response = code_wallet.par(Pkce.random(), scope=pid_scope(code_issuer), headers=headers, attest=False)
    assert response.status_code == 401, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_client"


# --- the same at the credential endpoint ------------------------------------------------------------------------------


def test_a_proof_whose_signature_ends_in_a_line_feed_is_refused_not_a_500(wallet: Wallet, issuer: Issuer) -> None:
    wallet.get_token()
    header, payload, signature = wallet.proof(EcKey.generate(), wallet.c_nonce()).split(".")
    proof = f"{header}.{payload}.{signature[:-1]}\n"
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_proof"


@pytest.fixture
def encrypting(make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], tmp_path: Path) -> Wallet:
    return wallet_for(make_issuer(encryption_keys=(key_file(tmp_path, "request-key.pem"),)))


def test_an_encrypted_request_that_ends_in_a_line_feed_is_refused_not_a_500(encrypting: Wallet) -> None:
    token = seal(request_body(encrypting), issuer_jwk(encrypting))
    response = send(encrypting, token + "\n")
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_credential_request"


def test_a_response_key_coordinate_that_ends_in_a_line_feed_is_refused_not_a_500(encrypting: Wallet) -> None:
    key = WalletKey()
    jwk: dict[str, Any] = {**key.jwk, "x": key.jwk["x"][:-1] + "\n"}
    body = request_body(encrypting, credential_response_encryption={"jwk": jwk, "enc": "A256GCM"})
    response = send(encrypting, seal(body, issuer_jwk(encrypting)))
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_encryption_parameters"


# --- the same in a wallet provider's status list, and what it did to revocation chaining ------------------------------


def newline_in_x(key: EcKey) -> dict[str, Any]:
    return {**key.public_jwk(), "x": key.public_jwk()["x"] + "\n"}


@pytest.mark.parametrize("size", [64, 32, 16], ids=["an ES256 signature", "a P-256 coordinate", "an AES-GCM tag"])
def test_strict_base64url_refuses_a_trailing_newline_itself(size: int) -> None:
    value = b64u(b"\x01" * size) + "\n"
    try:
        b64u_decode(value)
    except JoseError:
        return
    except binascii.Error as exc:
        pytest.fail(f"b64u_decode lets the decoder's own error out for {len(value)} characters: {exc!r}")
    pytest.fail("a value with a newline is not base64url")


def test_a_jws_followed_by_a_newline_is_not_a_jws() -> None:
    token = jws({"alg": "ES256", "typ": "any"}, {"a": 1}, EcKey.generate()) + "\n"
    with pytest.raises(JoseError):
        parse_jws(token)


def test_a_dpop_key_with_a_newline_is_a_400_at_the_token_endpoint(wallet: Wallet, clock: Clock) -> None:
    """No offer, no token, no secret: any client on the network."""
    key = EcKey.generate()
    proof = dpop_proof(key, "POST", f"{ISSUER}/token", iat=int(clock()), header_jwk=newline_in_x(key))
    response = wallet.token_request("not-a-code", dpop=proof)
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_dpop_proof"


@pytest.mark.parametrize("where", ["after the proof", "in the proof's jwk"])
def test_a_key_proof_with_a_newline_is_a_400(wallet: Wallet, where: str) -> None:
    wallet.get_token()
    holder = EcKey.generate()
    if where == "after the proof":
        proof = wallet.proof(holder, wallet.c_nonce()) + "\n"
    else:
        proof = wallet.proof(holder, wallet.c_nonce(), header_jwk=newline_in_x(holder))
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_proof"


@pytest.mark.parametrize("where", ["after the JWE", "in the response key"])
def test_an_encrypted_request_with_a_newline_is_a_400(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], tmp_path: Path, where: str
) -> None:
    wallet = wallet_for(make_issuer(encryption_keys=(key_file(tmp_path, "request-key.pem"),)))
    if where == "after the JWE":  # a file sent as it is, with the newline at its end
        response = send(wallet, seal(request_body(wallet), issuer_jwk(wallet)) + "\n")
        expected = "invalid_credential_request"
    else:
        mine = {"jwk": {**newline_in_x(EcKey.generate()), "alg": "ECDH-ES"}, "enc": "A256GCM"}
        response = send(wallet, seal(request_body(wallet, credential_response_encryption=mine), issuer_jwk(wallet)))
        expected = "invalid_encryption_parameters"
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == expected


def test_a_status_list_with_a_newline_at_its_end_is_a_refusal_at_issuance(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Wallet],
    pki: Pki,
    served: ServedStatus,  # noqa: F811
) -> None:
    signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    served.lists[KA_STATUS_LIST] = signer.token(KA_STATUS_LIST) + "\n"
    wallet = wallet_for(make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=served))
    response = wallet.issue()
    assert response.status_code == 400, f"{response.status_code}: {response.text}"
    assert response.json()["error"] == "invalid_proof"


def test_one_list_with_a_newline_at_its_end_does_not_stop_revocation_chaining(
    chained: Issuer,  # noqa: F811
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,  # noqa: F811
    served: ServedStatus,  # noqa: F811
    clock: Clock,
) -> None:
    issue(chained, code_wallet_for)
    [(key, _)] = chain_rows(chained)
    assert run(chained, clock) == {"chain_checked": 1, "chain_revoked": 0, "chain_unchecked": 0}
    # The wallet provider revokes the wallet unit: its list of wallet attestations says so, properly served. The
    # list of key attestations, at another URI, now ends with a newline.
    lists.serve(wia={WIA_IDX: 1})
    token = served.lists[KA_STATUS_LIST]
    assert isinstance(token, str)
    served.lists[KA_STATUS_LIST] = token + "\n"
    try:
        done = run(chained, clock)
    except binascii.Error as exc:
        pytest.fail(
            f"the run died on the other list ({exc!r}): the PID of the revoked wallet unit stays valid "
            f"(its bit is {bit(chained, key)}), and nothing is logged in the audit log"
        )
    assert done["chain_revoked"] == 1 and bit(chained, key) == 1


# --- the framework's own redirect, and a query that is not UTF-8 ------------------------------------------------------


FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/token/"),
        ("POST", "/par/"),
        ("POST", "/credential/"),
        ("GET", "/authorize/?client_id=a&request_uri=b"),
        ("GET", "/authorize/continue/?login_state=a&completion=b"),
    ],
)
def test_no_route_answers_with_a_307(code_wallet: CodeWallet, method: str, path: str) -> None:
    response = code_wallet.client.request(method, path, headers=FORM, content=b"a=b", follow_redirects=False)
    assert response.status_code != 307, f"307 to {response.headers.get('location')}"


def test_a_redirect_never_goes_where_the_host_header_says(code_wallet: CodeWallet) -> None:
    """The token request carries the pre-authorized code and the PIN, or the code and its verifier, or the refresh
    token; a 307 asks the client to send them again to the Location."""
    response = code_wallet.client.post(
        "/token/",
        headers={**FORM, "Host": "attacker.example"},
        content=b"grant_type=authorization_code&code=secret&code_verifier=secret",
        follow_redirects=False,
    )
    assert "attacker.example" not in response.headers.get("location", ""), response.headers["location"]


def _call(app: Any, path: str, query: bytes) -> int:
    """One GET straight into the ASGI application, with the query string as the raw bytes a server hands over."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": [(b"host", b"issuer.test")],
        "server": ("issuer.test", 443),
        "client": ("203.0.113.9", 40000),
    }
    statuses: list[int] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])

    async def run() -> None:
        try:
            await app(scope, receive, send)
        except UnicodeDecodeError:
            pass  # the server error middleware raises again after it has answered

    asyncio.run(run())
    assert statuses, "the application did not answer"
    return statuses[0]


@pytest.mark.parametrize(
    ("path", "query"),
    [
        ("/authorize", b"client_id=a&request_uri=\xff"),
        ("/authorize/continue", b"login_state=\xed\xa0\x80"),
    ],
)
def test_query_bytes_that_are_not_utf8_are_refused_not_a_500(code_issuer: Issuer, path: str, query: bytes) -> None:
    app = create_app(issuer=code_issuer, background_maintenance=False)
    status = _call(app, path, query)
    assert 400 <= status < 500, status


# --- a revocation reason that is not a string -------------------------------------------------------------------------


AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.mark.parametrize("reason", [[], ["user_request"], {}, {"user_request": True}])
def test_a_non_string_revocation_reason_is_a_typed_400_not_a_500(client: TestClient, reason: Any) -> None:
    response = client.post(
        "/admin/revocations", json={"reason": reason, "subject_ref": "sub_" + "A" * 24}, headers=AUTH
    )
    assert response.status_code == 400, (
        f"a reason of type {type(reason).__name__} gave {response.status_code}, not a typed 400; body={response.text}"
    )
    assert response.json().get("error") == "invalid_request"


def test_revoke_raises_a_typed_error_for_an_unhashable_reason(issuer: Issuer) -> None:
    # Straight at the engine: the reason check must not raise TypeError before the typed refusal.
    with pytest.raises(IssuerError):
        issuer.revoke({"reason": ["user_request"], "subject_ref": "sub_" + "A" * 24}, "admin")


# --- subject data nested deeper than what walks it can follow ---------------------------------------------------------


HIID = "eu.europa.ec.eudi.hiid_sd_jwt_vc"


def nested(depth: int) -> Any:
    value: Any = "Autoridade de Teste"
    for _ in range(depth):
        value = [value]
    return value


def offer(wallet: Wallet, depth: int) -> Any:
    subject = {
        "affiliation_country": "PT",
        "issuance_date": "2026-11-04",
        "expiry_date": "2030-01-01",
        "issuing_authority": nested(depth),
        "issuing_country": "PT",
    }
    return wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": subject})


def entries_taken(issuer: Issuer) -> int:
    return sum(int(count) for _, count in issuer.store.items("status-count"))


def test_deeply_nested_subject_data_is_refused_with_a_reason(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet]
) -> None:
    wallet = wallet_for(make_issuer(profile="eaa_provider"))
    response = offer(wallet, 2000)  # 4 KiB of brackets
    assert response.status_code == 400, f"the operator's system gets {response.status_code}: {response.text}"


def test_what_the_offer_accepts_can_be_issued(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet]
) -> None:
    issuer = make_issuer(profile="eaa_provider")
    wallet = wallet_for(issuer)
    wallet.get_token(offer(wallet, 1).json())
    assert wallet.issue(config=HIID).status_code == 200  # the first status list is open from here on
    low, high = 1, 2000  # the deepest nesting the offer takes
    while low < high:
        middle = (low + high + 1) // 2
        low, high = (middle, high) if offer(wallet, middle).status_code == 201 else (low, middle - 1)
    failed = []
    for depth in range(low, max(low - 8, 0), -1):
        wallet.token = None
        accepted = offer(wallet, depth)
        assert accepted.status_code == 201, accepted.text
        wallet.get_token(accepted.json())
        before = entries_taken(issuer)
        answers = [wallet.issue(config=HIID).status_code]
        while answers[-1] >= 500 and len(answers) < 4:  # the claim was given back: the wallet just asks again
            answers.append(wallet.issue(config=HIID).status_code)
        if answers[0] != 200:
            failed.append({"levels": depth, "answers": answers, "status entries taken": entries_taken(issuer) - before})
    assert not failed, f"offers cunho accepted, and what the credential endpoint did with them: {failed}"


# --- subject data that uses a name SD-JWT reserves --------------------------------------------------------------------


RESERVED = {"_sd", "..."}


def subject(issuing_authority: Any) -> dict[str, Any]:
    return {
        "affiliation_country": "PT",
        "issuance_date": "2026-11-04",
        "expiry_date": "2030-01-01",
        "issuing_authority": issuing_authority,
        "issuing_country": "PT",
    }


DIGEST = "3q2-7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


@pytest.mark.parametrize(
    "value",
    [
        {"name": "Autoridade de Teste", "_sd": [DIGEST]},
        {"name": "Autoridade de Teste", "...": DIGEST},
        [{"...": DIGEST}],
        [["Autoridade de Teste", {"seat": {"_sd": [DIGEST]}}]],
    ],
    ids=["an _sd member", "a ... member", "an array element that looks like a placeholder", "deeper down"],
)
def test_subject_data_that_uses_a_name_sd_jwt_reserves_is_refused_at_the_offer(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], value: Any
) -> None:
    """Every member of subject data becomes a disclosure under its own name. One named _sd or ... made a credential
    that RFC 9901 section 7.1 has every verifier reject, after a status entry was spent on it and its issuance
    logged. Nothing is signed now: the offer is refused, with the reason."""
    wallet = wallet_for(make_issuer(profile="eaa_provider"))
    offer = wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": subject(value)})
    assert offer.status_code == 400, offer.text
    assert "a member named _sd or ... cannot be issued in an SD-JWT (RFC 9901)" in offer.json()["error_description"]


@pytest.mark.parametrize("name", sorted(RESERVED))
def test_a_reserved_name_at_the_top_of_subject_data_is_refused_too(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], name: str
) -> None:
    wallet = wallet_for(make_issuer(profile="eaa_provider"))
    data = {**subject("Autoridade de Teste"), name: [DIGEST]}
    offer = wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": data})
    assert offer.status_code == 400, offer.text
    assert "a member named _sd or ... cannot be issued in an SD-JWT (RFC 9901)" in offer.json()["error_description"]


def test_names_that_only_look_like_the_reserved_ones_are_issued(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet]
) -> None:
    """The two names themselves, nothing near them, and never a value: a text that reads _sd is a text."""
    wallet = wallet_for(make_issuer(profile="eaa_provider"))
    value = {"name": "_sd", "_sd_alg": "...", "sd": ["...", "_sd"], "....": "Autoridade de Teste"}
    offer = wallet.admin("offers", {"credential_configuration_ids": [HIID], "subject": subject(value)})
    assert offer.status_code == 201, offer.text
    wallet.get_token(offer.json())
    response = wallet.issue(config=HIID)
    assert response.status_code == 200, response.text
    _, _, decoded = disclosures(response.json()["credentials"][0]["credential"])
    assert not [d[1] for d in decoded if len(d) == 3 and d[1] in RESERVED]


# --- the bounds themselves --------------------------------------------------------------------------------------------


def document(levels: int, shape: str) -> str:
    """A JSON document of `levels` containers one inside the other: arrays ("a") and objects ("o"), taken in turn
    from `shape`."""
    kinds = [shape[level % len(shape)] for level in range(levels)]
    opening = "".join("[" if kind == "a" else '{"m":' for kind in kinds)
    return opening + "0" + "".join("]" if kind == "a" else "}" for kind in reversed(kinds))


@pytest.mark.parametrize("shape", ["a", "o", "ao", "oa"], ids=["arrays", "objects", "arrays of objects", "the reverse"])
def test_a_document_nests_as_deep_as_the_bound_and_no_deeper(shape: str) -> None:
    assert strict_json(document(1, shape)) in ([0], {"m": 0})
    strict_json(document(MAX_DEPTH, shape))
    with pytest.raises(JsonRefused, match="JSON nested too deeply"):
        strict_json(document(MAX_DEPTH + 1, shape))


def test_a_wide_document_is_not_a_deep_one() -> None:
    """The bound is on how deep one value lies, not on how many containers a document holds."""
    inner = document(MAX_DEPTH - 1, "ao")
    wide = strict_json("[" + ",".join([inner] * 50) + "]")
    assert len(wide) == 50


def test_a_body_nested_too_deep_is_refused_at_the_admin_api_and_at_the_credential_endpoint(wallet: Wallet) -> None:
    """One level more than the bound, counting the body's own object."""
    deep = document(MAX_DEPTH, "a")
    offer = ('{"credential_configuration_ids":["' + PID_CONFIG + '"],"subject":' + deep + "}").encode()
    refused = wallet.client.post("/admin/offers", content=offer, headers={**AUTH, "Content-Type": "application/json"})
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_request"), refused.text
    wallet.get_token()
    request = ('{"credential_configuration_id":"' + PID_CONFIG + '","proofs":' + deep + "}").encode()
    response = wallet.credential_request(None, raw=request)
    assert (response.status_code, response.json()["error"]) == (400, "invalid_credential_request"), response.text


def test_a_picture_that_ends_in_a_line_feed_is_not_a_data_url(wallet: Wallet) -> None:
    """The same `$` as in the base64url check: it also matches before a final line feed, and a PID in SD-JWT VC
    took its picture as it came."""
    picture = "data:image/jpeg;base64," + base64.b64encode(b"\xff\xd8\xff\xe0 a test picture").decode()

    def offered(value: str) -> Any:
        body = {"credential_configuration_ids": [PID_CONFIG], "subject": {**PID_SUBJECT, "picture": value}}
        return wallet.admin("offers", body)

    assert offered(picture).status_code == 201
    refused = offered(picture + "\n")
    assert refused.status_code == 400, refused.text
    assert "picture: must be a data URL with a base64 JPEG" in refused.json()["error_description"]
