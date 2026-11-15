"""The check catalogue. Each check names the spec section it enforces.

Checks marked sensitive=True test security properties. Their results are written to a
separate private report and must never be published for an unpatched implementation.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import math
import secrets
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature

from . import cose, jwe
from .attester import ATTESTATION_HEADER, POP_HEADER, Instance, WalletProvider
from .authcode import Authorization, Client, CodeFlow, FlowFailure, Pkce, with_query
from .context import PRE_AUTH_GRANT, CodeTokens, Context, Exchange, Offer, Token, with_identifier
from .cose import X5CHAIN, CoseError, IssuerSigned
from .jose import (
    EcKey,
    b64u,
    b64u_decode,
    is_self_signed,
    jwk_thumbprint,
    load_x5c,
    parse_jws,
    verify_with_public_key,
)
from .wallet import AttestationIssuer, dpop_proof, fresh_secret

PASS, WARN, FAIL, SKIP, ERROR = "PASS", "WARN", "FAIL", "SKIP", "ERROR"
SYMMETRIC_OR_NONE = {"none", "HS256", "HS384", "HS512"}
NEVER_DISCLOSED = {"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status"}
TOKEN_ERRORS = {
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_dpop_proof",
    "use_dpop_nonce",
}
CREDENTIAL_ERRORS = {
    "invalid_credential_request",
    "unknown_credential_configuration",
    "unknown_credential_identifier",
    "invalid_proof",
    "invalid_nonce",
    "invalid_encryption_parameters",
    "credential_request_denied",
}


@dataclass
class Outcome:
    status: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Check:
    id: str
    group: str
    source: str
    title: str
    fn: Callable[[Context], Outcome]
    sensitive: bool = False


REGISTRY: list[Check] = []


def check(
    id: str, group: str, source: str, title: str, *, sensitive: bool = False
) -> Callable[[Callable[[Context], Outcome]], Callable[[Context], Outcome]]:
    def register(fn: Callable[[Context], Outcome]) -> Callable[[Context], Outcome]:
        REGISTRY.append(Check(id, group, source, title, fn, sensitive))
        return fn

    return register


def ok(detail: str = "", *ex: Exchange) -> Outcome:
    return Outcome(PASS, detail, [e.evidence() for e in ex])


def fail(detail: str, *ex: Exchange) -> Outcome:
    return Outcome(FAIL, detail, [e.evidence() for e in ex])


def warn(detail: str, *ex: Exchange) -> Outcome:
    return Outcome(WARN, detail, [e.evidence() for e in ex])


def skip(detail: str) -> Outcome:
    return Outcome(SKIP, detail)


def expect_rejected(
    ex: Exchange, *, statuses: set[int], errors: set[str] | None = None, header_error: bool = False
) -> Outcome:
    """Bad input must be refused with the right status and OAuth error code, never a 5xx."""
    if ex.status == 0:
        return Outcome(ERROR, "no HTTP response", [ex.evidence()])
    if ex.status >= 500:
        return fail(f"server error {ex.status} on client mistake", ex)
    if 200 <= ex.status < 300:
        return fail(f"request was accepted ({ex.status})", ex)
    code = ex.error_code()
    if header_error and code is None:
        challenge = ex.header("www-authenticate")
        code = next((e for e in (errors or set()) if f'error="{e}"' in challenge), None)
    if ex.status not in statuses:
        return warn(f"refused with {ex.status}, expected {sorted(statuses)} (error={code})", ex)
    if errors and code not in errors:
        return warn(f"refused, but error={code!r}; expected one of {sorted(errors)}", ex)
    return ok(f"refused with {ex.status} {code}", ex)


# How much an outcome weighs when a check of several requests reports one: an error (a request that got no answer
# proves nothing) outweighs a pass and a warning, and only a failure outweighs it.
GRAVITY = {PASS: 0, SKIP: 0, WARN: 1, ERROR: 2, FAIL: 3}


def gravest(outcomes: list[Outcome]) -> Outcome | None:
    """The outcome a check of several requests reports, or None when every one passed."""
    found = max(outcomes, key=lambda o: GRAVITY[o.status], default=None)
    return found if found is not None and GRAVITY[found.status] > 0 else None


def pre_auth_untestable(ctx: Context) -> Outcome | None:
    """A skip when the authorization server does not advertise the pre-authorized grant and no offer command could
    make one: refusing the grant is then right, and nothing about it can be tested."""
    advertised = ctx.as_metadata.get("grant_types_supported")
    if isinstance(advertised, list) and PRE_AUTH_GRANT not in advertised and not ctx.config.offer_cmd:
        return skip("the pre-authorized code grant is not advertised")
    return None


def need_offer(ctx: Context) -> Offer | None:
    return ctx.fresh_offer() if ctx.can_make_offers() else None


def credential_body(ctx: Context, config_id: str, proofs: list[str]) -> dict[str, Any]:
    return {"credential_configuration_id": config_id, "proofs": {"jwt": proofs}}


def issue_once(ctx: Context) -> tuple[Token, EcKey, Exchange, str] | Outcome:
    """A valid issuance, cached so format checks can inspect the result."""
    if "issued" in ctx.cache:
        return ctx.cache["issued"]
    offer = need_offer(ctx)
    if offer is None:
        return skip("no pre-authorized offer available (pass --offer-cmd)")
    config_id = ctx.target_config_id(offer)
    token = ctx.get_token(offer)
    if token is None or config_id is None:
        return skip("could not obtain an access token; see notes")
    holder = EcKey.generate()
    proof = ctx.proof_for(holder, ctx.c_nonce())
    ex = ctx.credential_request(token, credential_body(ctx, config_id, [proof]), sent="valid request")
    result = (token, holder, ex, config_id)
    ctx.cache["issued"] = result
    return result


def fresh_token(ctx: Context) -> tuple[Token, str] | Outcome:
    offer = need_offer(ctx)
    if offer is None:
        return skip("no pre-authorized offer available (pass --offer-cmd)")
    token = ctx.get_token(offer)
    config_id = ctx.target_config_id(offer)
    if token is None or config_id is None:
        return skip("could not obtain an access token; see notes")
    return token, config_id


# ---------------------------------------------------------------- metadata


@check("M01", "metadata", "OID4VCI 1.0 §12.2.2", "Issuer metadata served at the inserted well-known path")
def m01(ctx: Context) -> Outcome:
    ex = ctx.metadata_exchange
    if ex.status == 200 and isinstance(ex.json(), dict):
        if "application/json" not in ex.header("content-type"):
            return warn("served, but Content-Type is not application/json", ex)
        return ok("", ex)
    if ctx.metadata_fallback is not None:
        return fail("only served at the appended path, not the inserted one", ex, ctx.metadata_fallback)
    return fail("issuer metadata not found", ex)


@check("M02", "metadata", "OID4VCI 1.0 §12.2.4", "credential_issuer equals the issuer identifier")
def m02(ctx: Context) -> Outcome:
    value = ctx.metadata.get("credential_issuer")
    if not ctx.metadata:
        return skip("no metadata")
    if value == ctx.config.issuer:
        return ok(str(value))
    return fail(f"credential_issuer={value!r}, identifier used={ctx.config.issuer!r}")


@check("M03", "metadata", "OID4VCI 1.0 §12.2.4", "credential_endpoint present and https")
def m03(ctx: Context) -> Outcome:
    value = ctx.endpoint("credential_endpoint")
    if not ctx.metadata:
        return skip("no metadata")
    if value and value.startswith("https://"):
        return ok(value)
    return fail(f"credential_endpoint={value!r}")


@check("M04", "metadata", "OID4VCI 1.0 §12.2.4", "Each credential configuration declares its format")
def m04(ctx: Context) -> Outcome:
    if not ctx.configurations:
        return fail("credential_configurations_supported missing or empty")
    missing = [cid for cid, cfg in ctx.configurations.items() if not isinstance(cfg, dict) or "format" not in cfg]
    return fail(f"no format: {missing}") if missing else ok(f"{len(ctx.configurations)} configurations")


@check("M05", "metadata", "HAIP 1.0 §4.1", "nonce_endpoint present when any configuration needs key binding")
def m05(ctx: Context) -> Outcome:
    binding = [cid for cid, cfg in ctx.configurations.items() if cfg.get("cryptographic_binding_methods_supported")]
    if not binding:
        return skip("no configuration requires key binding")
    return (
        ok() if ctx.endpoint("nonce_endpoint") else fail(f"{len(binding)} configurations bind keys, no nonce_endpoint")
    )


@check("M06", "metadata", "HAIP 1.0 §4.1", "Every credential configuration has a scope")
def m06(ctx: Context) -> Outcome:
    missing = [cid for cid, cfg in ctx.configurations.items() if not cfg.get("scope")]
    if not ctx.configurations:
        return skip("no configurations")
    return fail(f"no scope: {missing}") if missing else ok()


@check("M07", "metadata", "OID4VCI 1.0 §12.2.4", "proof_types_supported present iff key binding, with signing algs")
def m07(ctx: Context) -> Outcome:
    problems = []
    for cid, cfg in ctx.configurations.items():
        binding = bool(cfg.get("cryptographic_binding_methods_supported"))
        proofs = cfg.get("proof_types_supported")
        if binding != bool(proofs):
            problems.append(f"{cid}: binding={binding} proof_types={bool(proofs)}")
        for ptype, spec in (proofs or {}).items():
            if not isinstance(spec, dict) or not spec.get("proof_signing_alg_values_supported"):
                problems.append(f"{cid}.{ptype}: no proof_signing_alg_values_supported")
    return fail("; ".join(problems[:10])) if problems else ok()


@check("M08", "metadata", "OID4VCI 1.0 App. F.1", "No none/symmetric proof signing algorithms advertised")
def m08(ctx: Context) -> Outcome:
    bad = sorted(
        {
            f"{cid}:{alg}"
            for cid, cfg in ctx.configurations.items()
            for spec in (cfg.get("proof_types_supported") or {}).values()
            if isinstance(spec, dict)
            for alg in spec.get("proof_signing_alg_values_supported") or []
            if str(alg) in SYMMETRIC_OR_NONE
        }
    )
    return fail(", ".join(bad[:10])) if bad else ok()


@check(
    "M09", "metadata", "OID4VCI 1.0 §12.2.4", "batch_size is an integer of 2 or more when batch issuance is advertised"
)
def m09(ctx: Context) -> Outcome:
    batch = ctx.metadata.get("batch_credential_issuance")
    if batch is None:
        return skip("batch issuance not advertised")
    size = batch.get("batch_size") if isinstance(batch, dict) else None
    return (
        ok(f"batch_size={size}")
        if isinstance(size, int) and size >= 2
        else fail(f"batch_credential_issuance={batch!r}")
    )


@check("M10", "metadata", "OID4VCI 1.0 §12.2.4", "key_attestations_required is an object when present")
def m10(ctx: Context) -> Outcome:
    bad = [
        f"{cid}.{ptype}"
        for cid, cfg in ctx.configurations.items()
        for ptype, spec in (cfg.get("proof_types_supported") or {}).items()
        if isinstance(spec, dict)
        and "key_attestations_required" in spec
        and not isinstance(spec["key_attestations_required"], dict)
    ]
    return fail(f"not an object: {bad[:10]}") if bad else ok()


@check("M11", "metadata", "RFC 8414 §3, §3.3", "AS metadata at the RFC 8414 path, issuer matches")
def m11(ctx: Context) -> Outcome:
    ex = ctx.as_metadata_exchange
    data = ex.json()
    if ex.status != 200 or not isinstance(data, dict):
        if ctx.as_metadata:
            return fail("AS metadata only found at a non-RFC 8414 path", ex)
        return fail("AS metadata not found", ex)
    if data.get("issuer") != ctx.as_identifier:
        return fail(f"issuer={data.get('issuer')!r}, expected {ctx.as_identifier!r}", ex)
    return ok()


@check("M12", "metadata", "RFC 9449 §5.1, §4.2; HAIP 1.0 §4", "DPoP algorithms advertised, asymmetric only")
def m12(ctx: Context) -> Outcome:
    if not ctx.as_metadata:
        return skip("no AS metadata")
    algs = ctx.as_metadata.get("dpop_signing_alg_values_supported")
    if not algs:
        return fail("dpop_signing_alg_values_supported missing (HAIP requires DPoP)")
    bad = sorted({str(a) for a in algs} & SYMMETRIC_OR_NONE)
    return fail(f"symmetric/none DPoP algs advertised: {bad}") if bad else ok(", ".join(map(str, algs)))


@check("M13", "metadata", "HAIP 1.0 §4 (FAPI 2.0, RFC 7636)", "PKCE S256 advertised, plain not offered")
def m13(ctx: Context) -> Outcome:
    if not ctx.as_metadata:
        return skip("no AS metadata")
    methods = ctx.as_metadata.get("code_challenge_methods_supported") or []
    if "S256" not in methods:
        return fail(f"code_challenge_methods_supported={methods!r}")
    return warn("plain is also offered") if "plain" in methods else ok()


@check("M14", "metadata", "HAIP 1.0 §4", "Authorization code flow and PAR available")
def m14(ctx: Context) -> Outcome:
    if not ctx.as_metadata:
        return skip("no AS metadata")
    grants = ctx.as_metadata.get("grant_types_supported") or ["authorization_code", "implicit"]
    problems = []
    if "authorization_code" not in grants:
        problems.append("authorization_code not in grant_types_supported")
    if not ctx.as_metadata.get("authorization_endpoint"):
        problems.append("no authorization_endpoint")
    if not ctx.as_metadata.get("pushed_authorization_request_endpoint"):
        problems.append("no pushed_authorization_request_endpoint")
    return fail("; ".join(problems)) if problems else ok()


@check("M15", "metadata", "OID4VCI 1.0 App. A.2.2, A.3.2", "SD-JWT VC configs carry vct, mdoc configs carry doctype")
def m15(ctx: Context) -> Outcome:
    bad = []
    for cid, cfg in ctx.configurations.items():
        if cfg.get("format") == "dc+sd-jwt" and not cfg.get("vct"):
            bad.append(cid)
        if cfg.get("format") == "mso_mdoc" and not cfg.get("doctype"):
            bad.append(cid)
    return fail(f"missing vct/doctype: {bad}") if bad else ok()


@check("M16", "metadata", "OID4VCI 1.0 §12.2.4", "Only known top-level metadata fields, no leaked internal config")
def m16(ctx: Context) -> Outcome:
    internal = {
        "issuer_conditions",
        "issuer_config",
        "overall_issuer_conditions",
        "source",
        "selective_disclosure",
        "policy",
    }
    leaked = sorted({f"{cid}.{k}" for cid, cfg in ctx.configurations.items() for k in cfg if k in internal})
    return warn(f"implementation-internal fields published: {leaked[:10]}") if leaked else ok()


# ------------------------------------------------------------------- nonce


@check("N01", "nonce", "OID4VCI 1.0 §7.1, §7.2", "POST to the nonce endpoint returns c_nonce")
def n01(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("nonce_endpoint")
    if not endpoint:
        return skip("no nonce_endpoint")
    ex = ctx.http.request("POST", endpoint)
    data = ex.json()
    if ex.status // 100 == 2 and isinstance(data, dict) and isinstance(data.get("c_nonce"), str):
        ctx.cache["nonce_exchange"] = ex
        return ok("", ex)
    return fail("no c_nonce in a 2xx JSON response", ex)


@check("N02", "nonce", "OID4VCI 1.0 §7.2", "Nonce response carries Cache-Control: no-store")
def n02(ctx: Context) -> Outcome:
    ex = ctx.cache.get("nonce_exchange")
    if ex is None:
        return skip("no successful nonce response")
    return (
        ok() if "no-store" in ex.header("cache-control") else fail(f"Cache-Control={ex.header('cache-control')!r}", ex)
    )


@check("N03", "nonce", "OID4VCI 1.0 §7, §13.8", "Each nonce request returns a fresh value")
def n03(ctx: Context) -> Outcome:
    if not ctx.endpoint("nonce_endpoint"):
        return skip("no nonce_endpoint")
    values = {ctx.c_nonce() for _ in range(3)}
    return ok() if len(values) == 3 and None not in values else fail(f"got {len(values)} distinct values")


@check("N04", "nonce", "RFC 9110 §15.5.6", "GET on the nonce endpoint is refused without a server error")
def n04(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("nonce_endpoint")
    if not endpoint:
        return skip("no nonce_endpoint")
    ex = ctx.http.request("GET", endpoint)
    if ex.status >= 500 or ex.status == 0:
        return fail("server error", ex)
    return ok(str(ex.status)) if ex.status in (404, 405) else warn(f"status {ex.status}", ex)


# -------------------------------------------------------------- robustness

TOKEN_GARBAGE: list[tuple[str, dict[str, Any]]] = [
    ("empty body", {"content": b""}),
    ("no grant_type", {"data": {"pre-authorized_code": "x"}}),
    ("unknown grant_type", {"data": {"grant_type": "urn:example:nope"}}),
    ("JSON instead of form", {"json": {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": "x"}}),
    ("100 KB code", {"data": {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": "A" * 100_000}}),
    (
        "invalid UTF-8",
        {
            "content": b"grant_type=\xff\xfe&pre-authorized_code=\xc3",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        },
    ),
    (
        "duplicated params",
        {"content": b"grant_type=a&grant_type=b", "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    ),
]

JSON_GARBAGE: list[tuple[str, bytes]] = [
    ("empty body", b""),
    ("invalid JSON", b"{not json"),
    ("JSON array", b"[]"),
    ("JSON string", b'"hello"'),
    ("JSON null", b"null"),
    ("wrong types", json.dumps({"credential_configuration_id": 7, "proofs": "x"}).encode()),
    ("proofs.jwt numbers", json.dumps({"credential_configuration_id": "x", "proofs": {"jwt": [1, 2]}}).encode()),
    ("deep nesting", b"[" * 5000 + b"]" * 5000),
    ("1 MB string", json.dumps({"credential_configuration_id": "A" * 1_000_000}).encode()),
]


@check(
    "R01", "robustness", "RFC 6749 §5.2", "Token endpoint answers malformed requests with 400 + OAuth error, never 5xx"
)
def r01(ctx: Context) -> Outcome:
    endpoint = ctx.token_endpoint
    if not endpoint:
        return skip("no token_endpoint")
    worst: Outcome = ok()
    evidence = []
    for label, kwargs in TOKEN_GARBAGE:
        ex = ctx.http.request("POST", endpoint, sent=label, **kwargs)
        evidence.append(ex.evidence())
        result = expect_rejected(ex, statuses={400}, errors=TOKEN_ERRORS)
        if ex.status == 401 and ex.error_code() == "invalid_client":
            result = ok("401 invalid_client (RFC 6749 §5.2)", ex)  # an AS that authenticates first may say so
        if GRAVITY[result.status] > GRAVITY[worst.status]:
            worst = Outcome(result.status, f"{label}: {result.detail}")
    worst.evidence = evidence
    return worst


@check("R02", "robustness", "RFC 6750 §3", "Credential endpoint without a token returns 401 with WWW-Authenticate")
def r02(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("credential_endpoint")
    if not endpoint:
        return skip("no credential_endpoint")
    ex = ctx.http.request("POST", endpoint, json={"credential_configuration_id": "x"})
    if ex.status >= 500 or ex.status == 0:
        return fail("server error", ex)
    if ex.status != 401:
        return fail(f"status {ex.status}, expected 401", ex)
    return ok() if ex.header("www-authenticate") else warn("401 without WWW-Authenticate", ex)


@check("R03", "robustness", "RFC 6750 §3.1", "Credential endpoint with a forged token returns 401 invalid_token")
def r03(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("credential_endpoint")
    if not endpoint:
        return skip("no credential_endpoint")
    key = EcKey.generate()
    forged = "forged-" + b64u(fresh_secret())
    headers = {
        "Authorization": f"DPoP {forged}",
        "DPoP": dpop_proof(key, "POST", endpoint, access_token=forged),
    }
    ex = ctx.http.request("POST", endpoint, json={"credential_configuration_id": "x"}, headers=headers)
    return expect_rejected(ex, statuses={401}, errors={"invalid_token"}, header_error=True)


@check(
    "R04",
    "robustness",
    "OID4VCI 1.0 §11.3, RFC 6750 §3",
    "Notification endpoint refuses unauthenticated calls without 5xx",
)
def r04(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("notification_endpoint")
    if not endpoint:
        return skip("no notification_endpoint")
    exchanges = [
        ctx.http.request("POST", endpoint, content=body, headers={"Content-Type": "application/json"}, sent=label)
        for label, body in JSON_GARBAGE[:4]
    ]
    bad = [ex for ex in exchanges if ex.status >= 500 or ex.status == 0 or ex.status // 100 == 2]
    if bad:
        return fail(f"{len(bad)} of {len(exchanges)} answered 2xx/5xx", *bad)
    return ok() if all(ex.status == 401 for ex in exchanges) else warn("refused, not always 401", *exchanges)


@check(
    "R05", "robustness", "OID4VCI 1.0 §9.3, RFC 6750 §3", "Deferred endpoint refuses unauthenticated calls without 5xx"
)
def r05(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("deferred_credential_endpoint")
    if not endpoint:
        return skip("no deferred_credential_endpoint")
    ex = ctx.http.request("POST", endpoint, json={"transaction_id": "nope"})
    if ex.status >= 500 or ex.status == 0 or ex.status // 100 == 2:
        return fail(f"status {ex.status}", ex)
    return ok() if ex.status == 401 else warn(f"status {ex.status}", ex)


@check(
    "R06", "robustness", "OID4VCI 1.0 §8.3.1.2", "Malformed credential request bodies get 400 + OAuth error, never 5xx"
)
def r06(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, _ = got
    worst: Outcome = ok()
    evidence = []
    for label, body in JSON_GARBAGE:
        ex = ctx.credential_request(token, None, raw=body, sent=label)
        evidence.append(ex.evidence())
        result = expect_rejected(ex, statuses={400}, errors=CREDENTIAL_ERRORS)
        if GRAVITY[result.status] > GRAVITY[worst.status]:
            worst = Outcome(result.status, f"{label}: {result.detail}")
    worst.evidence = evidence
    return worst


@check("R07", "robustness", "RFC 9110 §15.5.6", "Wrong HTTP methods are refused without a server error")
def r07(ctx: Context) -> Outcome:
    targets = [ctx.endpoint("credential_endpoint"), ctx.token_endpoint, ctx.endpoint("notification_endpoint")]
    exchanges = [ctx.http.request(m, t) for t in targets if t for m in ("GET", "PUT", "DELETE")]
    bad = [ex for ex in exchanges if ex.status >= 500 or ex.status == 0]
    return fail(f"{len(bad)} server errors", *bad) if bad else ok(f"{len(exchanges)} requests")


# ------------------------------------------------------------------- token


@check("T01", "token", "OID4VCI 1.0 §6; RFC 9449 §5", "Pre-authorized code + DPoP yields a DPoP-bound token")
def t01(ctx: Context) -> Outcome:
    offer = need_offer(ctx)
    if offer is None:
        return skip("no pre-authorized offer available")
    token = ctx.get_token(offer)
    if token is None:
        return fail("no token issued; " + (ctx.notes[-1] if ctx.notes else ""))
    ctx.cache["t01_offer"] = offer
    data = token.exchange.json() or {}
    problems = []
    from_cmd = token.exchange.url == "token-cmd"
    if from_cmd and "token_type" not in data:
        return skip("the token command does not report token_type")
    if str(data.get("token_type", "")).lower() != "dpop":
        problems.append(f"token_type={data.get('token_type')!r}, expected DPoP")
    if not from_cmd and "no-store" not in token.exchange.header("cache-control"):
        problems.append("no Cache-Control: no-store (RFC 6749 §5.1)")
    return fail("; ".join(problems), token.exchange) if problems else ok("", token.exchange)


@check("T02", "token", "OID4VCI 1.0 §6.1, §6.3", "Missing pre-authorized_code -> invalid_request")
def t02(ctx: Context) -> Outcome:
    if not ctx.token_endpoint:
        return skip("no token_endpoint")
    if untestable := pre_auth_untestable(ctx):
        return untestable
    key = EcKey.generate()
    dummy = Offer("", [], None, None, None, {})
    ex = ctx.token_request(dummy, key, form={"grant_type": PRE_AUTH_GRANT})
    return expect_rejected(ex, statuses={400}, errors={"invalid_request"})


@check("T03", "token", "OID4VCI 1.0 §6.3", "Unknown pre-authorized_code -> invalid_grant")
def t03(ctx: Context) -> Outcome:
    if not ctx.token_endpoint:
        return skip("no token_endpoint")
    if untestable := pre_auth_untestable(ctx):
        return untestable
    key = EcKey.generate()
    form = {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": b64u(fresh_secret())}
    ex = ctx.token_request(Offer("", [], None, None, None, {}), key, form=form)
    return expect_rejected(ex, statuses={400}, errors={"invalid_grant"})


@check("T04", "token", "OID4VCI 1.0 §4.1.1", "Pre-authorized code is single use")
def t04(ctx: Context) -> Outcome:
    if untestable := pre_auth_untestable(ctx):
        return untestable
    offer = ctx.cache.get("t01_offer")
    if offer is None:
        return skip("T01 did not redeem an offer")
    ex = ctx.token_request(offer, EcKey.generate())
    return expect_rejected(ex, statuses={400}, errors={"invalid_grant"})


@check("T05", "token", "OID4VCI 1.0 §6.3", "Required tx_code missing -> invalid_request")
def t05(ctx: Context) -> Outcome:
    if untestable := pre_auth_untestable(ctx):
        return untestable
    offer = need_offer(ctx)
    if offer is None or not offer.tx_code_required:
        return skip("no offer with tx_code")
    form = {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": offer.pre_authorized_code or ""}
    ex = ctx.token_request(offer, EcKey.generate(), form=form)
    return expect_rejected(ex, statuses={400}, errors={"invalid_request"})


@check("T06", "token", "OID4VCI 1.0 §6.3", "Wrong tx_code -> invalid_grant")
def t06(ctx: Context) -> Outcome:
    if untestable := pre_auth_untestable(ctx):
        return untestable
    offer = need_offer(ctx)
    if offer is None or not offer.tx_code_required:
        return skip("no offer with tx_code")
    form = {
        "grant_type": PRE_AUTH_GRANT,
        "pre-authorized_code": offer.pre_authorized_code or "",
        "tx_code": "wrong-" + (offer.tx_code_value or "0000"),
    }
    ex = ctx.token_request(offer, EcKey.generate(), form=form)
    return expect_rejected(ex, statuses={400}, errors={"invalid_grant"})


@check("T07", "token", "OID4VCI 1.0 §6.3", "tx_code sent when the offer has none -> invalid_request")
def t07(ctx: Context) -> Outcome:
    if untestable := pre_auth_untestable(ctx):
        return untestable
    offer = need_offer(ctx)
    if offer is None or offer.tx_code_required:
        return skip("no offer without tx_code")
    form = {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": offer.pre_authorized_code or "", "tx_code": "1234"}
    ex = ctx.token_request(offer, EcKey.generate(), form=form)
    return expect_rejected(ex, statuses={400}, errors={"invalid_request"})


def broken_dpop_at_token(ctx: Context, label: str, **overrides: Any) -> Outcome:
    offer = need_offer(ctx)
    if offer is None or not ctx.token_endpoint:
        return skip("no pre-authorized offer available")
    key = EcKey.generate()
    proof = dpop_proof(key, overrides.pop("method", "POST"), overrides.pop("url", ctx.token_endpoint), **overrides)
    ex = ctx.token_request(offer, key, dpop=proof, sent=label)
    return expect_rejected(ex, statuses={400}, errors={"invalid_dpop_proof", "use_dpop_nonce"})


@check("T08", "token", "RFC 9449 §4.2, §4.3(5)", "DPoP proof signed with HS256 is refused", sensitive=True)
def t08(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "HS256 DPoP", alg="HS256", hs256_secret=fresh_secret())


@check("T09", "token", "RFC 9449 §4.3(4), §11.5", "DPoP proof with wrong typ is refused", sensitive=True)
def t09(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "typ=JWT", typ="JWT")


@check("T10", "token", "RFC 9449 §4.3(7)", "DPoP jwk containing a private key is refused", sensitive=True)
def t10(ctx: Context) -> Outcome:
    key = EcKey.generate()
    return broken_dpop_at_token(ctx, "private jwk", header_jwk=key.private_jwk(), signing_key=key)


@check("T11", "token", "RFC 9449 §4.3(8)", "DPoP htm mismatch is refused", sensitive=True)
def t11(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "htm=GET", method="GET")


@check("T12", "token", "RFC 9449 §4.3(9)", "DPoP htu mismatch is refused", sensitive=True)
def t12(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "htu=other", url="https://attacker.example/token")


@check("T13", "token", "RFC 9449 §4.3(11), §11.1", "Stale DPoP proof (iat 1 hour ago) is refused", sensitive=True)
def t13(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "iat-3600", iat=int(time.time()) - 3600)


@check("T14", "token", "RFC 9449 §4.3(6)", "DPoP proof with a bad signature is refused", sensitive=True)
def t14(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "signed by other key", signing_key=EcKey.generate())


@check("T15", "token", "RFC 9449 §4.3(3)", "DPoP proof missing jti is refused", sensitive=True)
def t15(ctx: Context) -> Outcome:
    return broken_dpop_at_token(ctx, "no jti", drop=("jti",))


# -------------------------------------------------------------- credential


@check("C01", "credential", "OID4VCI 1.0 §8.2, §8.3", "Valid request returns 200 with a credentials array")
def c01(ctx: Context) -> Outcome:
    got = issue_once(ctx)
    if isinstance(got, Outcome):
        return got
    _, _, ex, config_id = got
    data = ex.json()
    if ex.status != 200 or not isinstance(data, dict):
        return fail(f"status {ex.status} for {config_id}", ex)
    creds = data.get("credentials")
    if (
        not isinstance(creds, list)
        or not creds
        or not all(isinstance(c, dict) and isinstance(c.get("credential"), str) for c in creds)
    ):
        return fail("credentials is not a non-empty array of {credential: string}", ex)
    if "notification_id" in data and not isinstance(data["notification_id"], str):
        return fail("notification_id is not a string", ex)
    return ok(f"{len(creds)} credential(s) for {config_id}", ex)


def issued_credential(ctx: Context) -> tuple[str, str, EcKey, dict[str, Any]] | Outcome:
    got = issue_once(ctx)
    if isinstance(got, Outcome):
        return got
    _, holder, ex, config_id = got
    data = ex.json()
    if ex.status != 200 or not isinstance(data, dict) or not data.get("credentials"):
        return skip("no credential issued (see C01)")
    return str(data["credentials"][0]["credential"]), config_id, holder, ctx.configurations.get(config_id, {})


def collect_digests(node: Any, into: set[str]) -> None:
    if isinstance(node, dict):
        for digest in node.get("_sd", []) if isinstance(node.get("_sd"), list) else []:
            into.add(str(digest))
        if set(node) == {"..."}:
            into.add(str(node["..."]))
        for value in node.values():
            collect_digests(value, into)
    elif isinstance(node, list):
        for item in node:
            collect_digests(item, into)


@check(
    "C02",
    "credential",
    "SD-JWT VC draft-23 §2.2; HAIP 1.0 §6.1, §6.1.1; RFC 9901",
    "SD-JWT VC is well-formed and bound to the proof key",
)
def c02(ctx: Context) -> Outcome:
    got = issued_credential(ctx)
    if isinstance(got, Outcome):
        return got
    credential, config_id, holder, cfg = got
    if cfg.get("format") != "dc+sd-jwt":
        return skip(f"{config_id} is {cfg.get('format')}")
    parts = credential.split("~")
    try:
        jwt = parse_jws(parts[0])
    except ValueError as exc:
        return fail(f"issuer-signed JWT does not parse: {exc}")
    problems: list[str] = []
    header, payload = jwt.header, jwt.payload
    if header.get("typ") != "dc+sd-jwt":
        problems.append(f"typ={header.get('typ')!r}")
    if payload.get("vct") != cfg.get("vct"):
        problems.append(f"vct={payload.get('vct')!r}, config says {cfg.get('vct')!r}")
    cnf_jwk = (payload.get("cnf") or {}).get("jwk")
    if not isinstance(cnf_jwk, dict) or jwk_thumbprint(cnf_jwk) != holder.thumbprint():
        problems.append("cnf.jwk is not the proof key")
    if "exp" not in payload and "status" not in payload:
        problems.append("neither exp nor status (HAIP 6.1)")
    x5c = header.get("x5c")
    if not isinstance(x5c, list) or not x5c:
        problems.append("no x5c header (HAIP 6.1.1)")
    else:
        certs = load_x5c(x5c)
        if not verify_with_public_key(str(header.get("alg")), certs[0].public_key(), jwt.signing_input, jwt.signature):
            problems.append("signature does not verify with x5c[0]")
        if is_self_signed(certs[-1]) and len(certs) > 1:
            problems.append("x5c includes the trust anchor (HAIP 6.1.1)")
        if len(certs) == 1 and is_self_signed(certs[0]):
            problems.append("x5c is a single self-signed certificate")
    if payload.get("_sd_alg", "sha-256") != "sha-256":
        problems.append(f"_sd_alg={payload.get('_sd_alg')!r} (probe checks sha-256 only)")
    disclosures = [d for d in parts[1:] if d and "." not in d]
    known: set[str] = set()
    collect_digests(payload, known)
    decoded = []
    for disclosure in disclosures:
        try:
            value = json.loads(b64u_decode(disclosure))
        except ValueError:
            problems.append("a disclosure is not base64url JSON")
            continue
        decoded.append(value)
        collect_digests(value, known)
    for disclosure, value in zip(disclosures, decoded, strict=False):
        digest = b64u(hashlib.sha256(disclosure.encode("ascii")).digest())
        if digest not in known:
            problems.append("a disclosure digest is not referenced in the payload")
        if isinstance(value, list) and len(value) == 3 and value[1] in NEVER_DISCLOSED:
            problems.append(f"{value[1]} is selectively disclosable (SD-JWT VC 2.2.2.3)")
    if not credential.endswith("~"):
        problems.append("SD-JWT does not end with '~'")
    return fail("; ".join(problems)) if problems else ok(f"{len(disclosures)} disclosures")


def status_times(iat: Any, exp: Any, ttl: Any, *names: str, whole_ttl: bool = False) -> list[str]:
    """Token Status List §5.1, §5.2: iat required, exp and ttl recommended, and a list past its exp is stale (it may
    hide a revocation); iat not in the future. iat and exp are NumericDates, which may have a fraction (RFC 7519
    §2, RFC 8392 §2); ttl is a positive number in a JWT and an unsigned integer in a CWT (`whole_ttl`)."""

    def number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)

    now, skew, problems = time.time(), 300, []
    if iat is None:
        problems.append(f"no {names[0]}")
    elif not number(iat):
        problems.append(f"{names[0]} {iat!r} is not a NumericDate")
    elif iat > now + skew:
        problems.append(f"{names[0]} is in the future")
    if exp is None:
        problems.append(f"no {names[1]} (RECOMMENDED)")
    elif not number(exp):
        problems.append(f"{names[1]} {exp!r} is not a NumericDate")
    elif exp <= now:
        problems.append(f"the list expired ({names[1]} {exp}, now {int(now)})")
    if ttl is None:
        problems.append(f"no {names[2]} (RECOMMENDED)")
    elif not number(ttl) or ttl <= 0 or (whole_ttl and not isinstance(ttl, int)):
        kind = "an unsigned integer above 0" if whole_ttl else "a positive number"
        problems.append(f"{names[2]} {ttl!r} is not {kind}")
    return problems


@check(
    "C03",
    "credential",
    "Token Status List draft-21 §5.1, §6.2, §8.2, §8.3; HAIP 1.0 §6.1",
    "Status list entry resolves to a valid statuslist+jwt",
)
def c03(ctx: Context) -> Outcome:
    got = issued_credential(ctx)
    if isinstance(got, Outcome):
        return got
    credential, config_id, _, cfg = got
    if cfg.get("format") != "dc+sd-jwt":
        return skip("status check implemented for SD-JWT VC only")
    payload = parse_jws(credential.split("~")[0]).payload
    ref = (payload.get("status") or {}).get("status_list")
    if not isinstance(ref, dict):
        return warn("credential has no status_list reference (no revocation)")
    idx, uri = ref.get("idx"), ref.get("uri")
    if not isinstance(idx, int) or idx < 0 or not isinstance(uri, str):
        return fail(f"bad status_list reference {ref!r}")
    ex = ctx.http.request("GET", uri, headers={"Accept": "application/statuslist+jwt"})
    if ex.status != 200:
        return fail(f"status list fetch returned {ex.status}", ex)
    problems = []
    if not ex.header("content-type").startswith("application/statuslist+jwt"):
        problems.append(f"Content-Type={ex.header('content-type')!r}")
    try:
        token = parse_jws(ex.body.strip())
    except ValueError as exc:
        return fail(f"status list token does not parse: {exc}", ex)
    if token.header.get("typ") != "statuslist+jwt":
        problems.append(f"typ={token.header.get('typ')!r}")
    if token.payload.get("sub") != uri:
        problems.append(f"sub={token.payload.get('sub')!r} != uri")
    payload = token.payload
    problems += status_times(payload.get("iat"), payload.get("exp"), payload.get("ttl"), "iat", "exp", "ttl")
    if not token.header.get("x5c"):
        problems.append("no x5c (HAIP 6.1)")
    status_list = token.payload.get("status_list") or {}
    bits = status_list.get("bits")
    if bits not in (1, 2, 4, 8):
        problems.append(f"bits={bits!r}")
        return fail("; ".join(problems), ex)
    try:
        raw = zlib.decompress(b64u_decode(str(status_list.get("lst", ""))))
    except (zlib.error, ValueError):
        problems.append("lst is not base64url ZLIB data")
        return fail("; ".join(problems), ex)
    per_byte = 8 // bits
    if idx >= len(raw) * per_byte:
        problems.append(f"idx {idx} out of bounds ({len(raw) * per_byte} entries)")
    else:
        value = (raw[idx // per_byte] >> ((idx % per_byte) * bits)) & ((1 << bits) - 1)
        if value != 0:
            problems.append(f"fresh credential has status {value}, expected 0 (VALID)")
    hard = [p for p in problems if "RECOMMENDED" not in p]
    if hard:
        return fail("; ".join(problems), ex)
    return warn("; ".join(problems), ex) if problems else ok(f"{len(raw) * per_byte} entries, idx {idx}", ex)


@check(
    "C04",
    "credential",
    "OID4VCI 1.0 §8.3, §12.2.4; Token Status List §13.2; HAIP 1.0 §6.1",
    "Batch of 2 proofs -> 2 credentials, distinct keys and status indexes",
)
def c04(ctx: Context) -> Outcome:
    if (ctx.batch_size or 0) < 2:
        return skip("batch issuance not advertised")
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    nonce = ctx.c_nonce()
    holders = [EcKey.generate(), EcKey.generate()]
    ex = ctx.credential_request(token, credential_body(ctx, config_id, [ctx.proof_for(h, nonce) for h in holders]))
    data = ex.json()
    if ex.status != 200 or not isinstance(data, dict):
        return fail(f"status {ex.status}", ex)
    creds = data.get("credentials") or []
    if len(creds) != 2:
        return fail(f"{len(creds)} credentials for 2 proofs", ex)
    if ctx.configurations.get(config_id, {}).get("format") != "dc+sd-jwt":
        return ok("2 credentials (format checks are SD-JWT only)", ex)
    payloads = [parse_jws(str(c["credential"]).split("~")[0]).payload for c in creds]
    thumbs = {jwk_thumbprint(p.get("cnf", {}).get("jwk", {})) for p in payloads if p.get("cnf", {}).get("jwk")}
    refs = {json.dumps(p.get("status", {}).get("status_list"), sort_keys=True) for p in payloads}
    problems = []
    if thumbs != {h.thumbprint() for h in holders}:
        problems.append("credentials are not bound one-to-one to the proof keys")
    if any(p.get("status") for p in payloads) and len(refs) != 2:
        problems.append("credentials share a status list entry")
    return fail("; ".join(problems), ex) if problems else ok("", ex)


@check(
    "C05",
    "credential",
    "OID4VCI 1.0 §12.2.4 (batch_size = max proofs array size)",
    "More proofs than batch_size is refused, not silently truncated",
)
def c05(ctx: Context) -> Outcome:
    size = ctx.batch_size or 1
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    nonce = ctx.c_nonce()
    proofs = [ctx.proof_for(EcKey.generate(), nonce) for _ in range(size + 1)]
    ex = ctx.credential_request(token, credential_body(ctx, config_id, proofs), sent=f"{size + 1} proofs")
    if ex.status == 200:
        count = len((ex.json() or {}).get("credentials") or [])
        return warn(f"accepted {size + 1} proofs and issued {count} credentials (silent truncation)", ex)
    return expect_rejected(ex, statuses={400}, errors={"invalid_credential_request", "invalid_proof"})


def bad_credential_request(ctx: Context, build: Callable[[str, str], Any], errors: set[str], label: str) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    proof = ctx.proof_for(EcKey.generate(), ctx.c_nonce())
    ex = ctx.credential_request(token, build(config_id, proof), sent=label)
    return expect_rejected(ex, statuses={400}, errors=errors)


@check("C06", "credential", "OID4VCI 1.0 §8.2", "Draft-era singular `proof` is not accepted in place of `proofs`")
def c06(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx,
        lambda cid, p: {"credential_configuration_id": cid, "proof": {"proof_type": "jwt", "jwt": p}},
        {"invalid_proof", "invalid_credential_request"},
        "singular proof",
    )


@check(
    "C07",
    "credential",
    "OID4VCI 1.0 §8.2",
    "credential_identifier together with credential_configuration_id is refused",
)
def c07(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx,
        lambda cid, p: {"credential_configuration_id": cid, "credential_identifier": "x", "proofs": {"jwt": [p]}},
        {"invalid_credential_request"},
        "both identifiers",
    )


@check(
    "C08", "credential", "OID4VCI 1.0 §8.2", "Neither credential_identifier nor credential_configuration_id is refused"
)
def c08(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx, lambda cid, p: {"proofs": {"jwt": [p]}}, {"invalid_credential_request"}, "no identifier"
    )


@check(
    "C09",
    "credential",
    "OID4VCI 1.0 §8.3.1.2",
    "Unknown credential_configuration_id -> unknown_credential_configuration",
)
def c09(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx,
        lambda cid, p: {"credential_configuration_id": "probe.unknown.config", "proofs": {"jwt": [p]}},
        {"unknown_credential_configuration"},
        "unknown config",
    )


@check("C10", "credential", "OID4VCI 1.0 §8.3.1.2", "Unknown credential_identifier -> unknown_credential_identifier")
def c10(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx,
        lambda cid, p: {"credential_identifier": "probe-unknown-identifier", "proofs": {"jwt": [p]}},
        {"unknown_credential_identifier", "invalid_credential_request"},
        "unknown identifier",
    )


@check(
    "C11",
    "credential",
    "OID4VCI 1.0 §8.2, §8.3.1.2",
    "Missing proofs when the configuration binds keys -> invalid_proof",
)
def c11(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx, lambda cid, p: {"credential_configuration_id": cid}, {"invalid_proof"}, "no proofs"
    )


@check("C12", "credential", "OID4VCI 1.0 §8.2", "proofs with two proof types is refused")
def c12(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx,
        lambda cid, p: {"credential_configuration_id": cid, "proofs": {"jwt": [p], "attestation": [p]}},
        {"invalid_credential_request", "invalid_proof"},
        "two proof types",
    )


@check("C13", "credential", "OID4VCI 1.0 §8.2", "Empty proofs.jwt array is refused")
def c13(ctx: Context) -> Outcome:
    return bad_credential_request(
        ctx,
        lambda cid, p: {"credential_configuration_id": cid, "proofs": {"jwt": []}},
        {"invalid_credential_request", "invalid_proof"},
        "empty proofs",
    )


@check("C14", "credential", "OID4VCI 1.0 §8.3", "Error responses carry no notification_id")
def c14(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, _ = got
    ex = ctx.credential_request(token, {"credential_configuration_id": "probe.unknown.config"})
    data = ex.json()
    if ex.status // 100 == 2:
        return fail("unknown configuration was accepted", ex)
    if isinstance(data, dict) and "notification_id" in data:
        return fail("error response includes notification_id", ex)
    return ok()


@check("C15", "credential", "OID4VCI 1.0 §11.1, §11.3", "Notification endpoint validates notification_id and event")
def c15(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("notification_endpoint")
    if not endpoint:
        return skip("no notification_endpoint")
    got = issue_once(ctx)
    if isinstance(got, Outcome):
        return got
    token, _, issued, _ = got
    notification_id = (issued.json() or {}).get("notification_id")

    def send(body: dict[str, Any], label: str) -> Exchange:
        headers = {
            "Authorization": f"DPoP {token.access_token}",
            "DPoP": dpop_proof(token.key, "POST", endpoint, access_token=token.access_token, nonce=token.dpop_nonce),
        }
        return ctx.http.request("POST", endpoint, json=body, headers=headers, sent=label)

    unknown = send({"notification_id": "probe-unknown", "event": "credential_accepted"}, "unknown id")
    bad_event = send({"notification_id": notification_id or "x", "event": "probe_event"}, "bad event")
    results = [
        expect_rejected(unknown, statuses={400}, errors={"invalid_notification_id"}),
        expect_rejected(bad_event, statuses={400}, errors={"invalid_notification_request", "invalid_notification_id"}),
    ]
    if notification_id:
        good = send({"notification_id": notification_id, "event": "credential_accepted"}, "valid")
        if good.status == 0:
            results.append(Outcome(ERROR, "no HTTP response to the valid notification", [good.evidence()]))
        elif good.status // 100 != 2:
            results.append(fail(f"valid notification refused with {good.status}", good))
        elif good.status != 204:
            results.append(warn(f"valid notification answered {good.status}, 204 RECOMMENDED", good))
    return gravest(results) or ok("", unknown, bad_event)


@check(
    "C16",
    "credential",
    "OID4VCI 1.0 App. A.2.4; ISO/IEC 18013-5 §8.3.2.1.2.2, §9.1.2.4",
    "mdoc credential is base64url CBOR IssuerSigned with x5chain",
)
def c16(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, _, _, _, ex = got
    problems = []
    if X5CHAIN not in signed.auth.unprotected:
        problems.append("no x5chain (label 33) in the issuerAuth unprotected header (§9.1.2.4)")
    short = sorted({f"{i.namespace}/{i.name}" for i in signed.items if len(i.random) < 16})
    if short:
        problems.append(f"random shorter than 16 bytes: {', '.join(short)} (§9.1.2.5)")
    seen: set[tuple[str, int]] = set()
    for item in signed.items:
        if (item.namespace, item.digest_id) in seen:
            problems.append(f"digestID {item.digest_id} used twice in {item.namespace}")
        seen.add((item.namespace, item.digest_id))
    if not signed.items:
        problems.append("no data elements")
    return fail("; ".join(problems), ex) if problems else ok(f"{len(signed.items)} elements", ex)


# --------------------------------------------- security properties (private)


def bad_proof(ctx: Context, label: str, errors: set[str], **overrides: Any) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    holder = EcKey.generate()
    nonce = overrides.pop("nonce_value", ctx.c_nonce())
    proof = ctx.proof_for(holder, nonce, **overrides)
    ex = ctx.credential_request(token, credential_body(ctx, config_id, [proof]), sent=label)
    return expect_rejected(ex, statuses={400}, errors=errors)


@check("S01", "security", "OID4VCI 1.0 App. F.4", "Key proof with a bad signature is refused", sensitive=True)
def s01(ctx: Context) -> Outcome:
    return bad_proof(ctx, "proof signed by other key", {"invalid_proof"}, signing_key=EcKey.generate())


@check("S02", "security", "OID4VCI 1.0 App. F.1", "Key proof with wrong aud is refused", sensitive=True)
def s02(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    from .wallet import key_proof

    proof = key_proof(EcKey.generate(), "https://attacker.example", nonce=ctx.c_nonce())
    ex = ctx.credential_request(token, credential_body(ctx, config_id, [proof]), sent="aud=attacker")
    return expect_rejected(ex, statuses={400}, errors={"invalid_proof"})


@check(
    "S03",
    "security",
    "OID4VCI 1.0 App. F.1, §8.3.1.2",
    "Key proof without nonce is refused (issuer has a nonce endpoint)",
    sensitive=True,
)
def s03(ctx: Context) -> Outcome:
    if not ctx.endpoint("nonce_endpoint"):
        return skip("no nonce_endpoint")
    return bad_proof(ctx, "no nonce", {"invalid_proof", "invalid_nonce"}, nonce_value=None)


@check("S04", "security", "OID4VCI 1.0 §8.3.1.2", "Key proof with an unknown nonce -> invalid_nonce", sensitive=True)
def s04(ctx: Context) -> Outcome:
    if not ctx.endpoint("nonce_endpoint"):
        return skip("no nonce_endpoint")
    return bad_proof(ctx, "forged nonce", {"invalid_nonce"}, nonce_value="probe-" + b64u(fresh_secret()))


@check("S05", "security", "OID4VCI 1.0 App. F.1", "Key proof signed with HS256 is refused", sensitive=True)
def s05(ctx: Context) -> Outcome:
    return bad_proof(ctx, "HS256 proof", {"invalid_proof"}, alg="HS256", hs256_secret=fresh_secret())


@check("S06", "security", "OID4VCI 1.0 App. F.1", "Key proof with wrong typ is refused", sensitive=True)
def s06(ctx: Context) -> Outcome:
    return bad_proof(ctx, "typ=JWT", {"invalid_proof"}, typ="JWT")


@check(
    "S07", "security", "OID4VCI 1.0 App. F.4", "Key proof whose jwk contains a private key is refused", sensitive=True
)
def s07(ctx: Context) -> Outcome:
    key = EcKey.generate()
    return bad_proof(ctx, "private jwk in proof", {"invalid_proof"}, header_jwk=key.private_jwk(), signing_key=key)


@check("S08", "security", "OID4VCI 1.0 App. F.4, §13.8", "Key proof issued a day ago is refused", sensitive=True)
def s08(ctx: Context) -> Outcome:
    return bad_proof(ctx, "iat-86400", {"invalid_proof"}, iat=int(time.time()) - 86_400)


@check("S09", "security", "RFC 9449 §7.2", "DPoP-bound token presented as Bearer is refused", sensitive=True)
def s09(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ex = ctx.credential_request(token, body, scheme="Bearer", dpop=None, sent="Bearer scheme")
    return expect_rejected(ex, statuses={401}, errors={"invalid_token"}, header_error=True)


@check("S10", "security", "RFC 9449 §7.1", "DPoP scheme without a DPoP header is refused", sensitive=True)
def s10(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ex = ctx.credential_request(token, body, dpop=None, sent="no DPoP header")
    return expect_rejected(
        ex, statuses={401, 400}, errors={"invalid_dpop_proof", "invalid_token", "invalid_request"}, header_error=True
    )


@check(
    "S11",
    "security",
    "RFC 9449 §4.3(12), §7",
    "DPoP proof without ath is refused at the credential endpoint",
    sensitive=True,
)
def s11(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    endpoint = ctx.endpoint("credential_endpoint") or ""
    proof = dpop_proof(token.key, "POST", endpoint, nonce=token.dpop_nonce)
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ex = ctx.credential_request(token, body, dpop=proof, sent="no ath")
    return expect_rejected(ex, statuses={401}, errors={"invalid_dpop_proof", "invalid_token"}, header_error=True)


@check(
    "S12",
    "security",
    "RFC 9449 §6, §7.1",
    "DPoP proof from a key other than the token-bound key is refused",
    sensitive=True,
)
def s12(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    endpoint = ctx.endpoint("credential_endpoint") or ""
    proof = dpop_proof(EcKey.generate(), "POST", endpoint, access_token=token.access_token, nonce=token.dpop_nonce)
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ex = ctx.credential_request(token, body, dpop=proof, sent="other DPoP key")
    return expect_rejected(ex, statuses={401}, errors={"invalid_dpop_proof", "invalid_token"}, header_error=True)


@check("S13", "security", "RFC 9449 §11.1", "A replayed DPoP proof (same jti) is refused", sensitive=True)
def s13(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    endpoint = ctx.endpoint("credential_endpoint") or ""
    proof = dpop_proof(token.key, "POST", endpoint, access_token=token.access_token, nonce=token.dpop_nonce)
    first_body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ctx.credential_request(token, first_body, dpop=proof, sent="first use")
    second_body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ex = ctx.credential_request(token, second_body, dpop=proof, sent="replayed DPoP")
    return expect_rejected(ex, statuses={401, 400}, errors={"invalid_dpop_proof"}, header_error=True)


@check(
    "S14",
    "security",
    "OID4VCI 1.0 §12.2.4 (key_attestations_required)",
    "Key attestation is enforced when the configuration requires it",
    sensitive=True,
)
def s14(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    jwt_spec = ((ctx.configurations.get(config_id) or {}).get("proof_types_supported") or {}).get("jwt") or {}
    if "key_attestations_required" not in jwt_spec:
        return skip(f"{config_id} does not require key attestation")
    proof = ctx.proof_for(EcKey.generate(), ctx.c_nonce(), key_attestation=None)
    ex = ctx.credential_request(token, credential_body(ctx, config_id, [proof]), sent="no key attestation")
    return expect_rejected(ex, statuses={400}, errors={"invalid_proof"})


@check("S15", "security", "OID4VCI 1.0 §13.8", "A c_nonce cannot be reused after a successful issuance", sensitive=True)
def s15(ctx: Context) -> Outcome:
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    nonce = ctx.c_nonce()
    if nonce is None:
        return skip("no nonce endpoint")
    first = ctx.credential_request(token, credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), nonce)]))
    if first.status != 200:
        return skip(f"first issuance failed ({first.status})")
    second_token = fresh_token(ctx)
    if isinstance(second_token, Outcome):
        return second_token
    ex = ctx.credential_request(
        second_token[0],
        credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), nonce)]),
        sent="reused c_nonce",
    )
    if ex.status == 200:
        return warn("c_nonce accepted twice (replay window open)", ex)
    return expect_rejected(ex, statuses={400}, errors={"invalid_nonce"})


def b64std(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------- the authorization code flow (HAIP 1.0 §4)

AUTHORIZE_ERRORS = {"invalid_request", "invalid_request_uri", "invalid_client", "unauthorized_client"}


def code_flow(ctx: Context) -> CodeFlow | Outcome:
    client = ctx.code_client()
    if client is None:
        return skip("no wallet provider, client_id or redirect URI configured (--wia-ca, --client-id, --redirect-uri)")
    if not ctx.as_metadata.get("pushed_authorization_request_endpoint"):
        return skip("no pushed_authorization_request_endpoint advertised")
    return CodeFlow(ctx, client)


def target_scope(ctx: Context) -> str | Outcome:
    scope = ctx.scope_for(ctx.target_config_id(None))
    return scope if scope is not None else skip("the target configuration has no scope")


def flow_and_scope(ctx: Context) -> tuple[CodeFlow, str] | Outcome:
    flow = code_flow(ctx)
    if isinstance(flow, Outcome):
        return flow
    scope = target_scope(ctx)
    return scope if isinstance(scope, Outcome) else (flow, scope)


def pushed(flow: CodeFlow, pkce: Pkce, scope: str, **kw: Any) -> str | Outcome:
    """A request_uri from an accepted PAR, or the outcome that says why not."""
    ex = flow.par(pkce, scope=scope, sent="PAR", **kw)
    uri = (ex.json() or {}).get("request_uri") if ex.status == 201 else None
    return uri if isinstance(uri, str) else broken(FlowFailure("PAR was not accepted", [ex]))


def broken(failure: FlowFailure, *, positive: bool = False) -> Outcome:
    """The code flow was tried and stopped. The checks of the flow itself fail; a check that only needed it to get
    to its own question cannot answer it, which is an error, never a skip (a skip is for what was not configured)."""
    return Outcome(
        FAIL if positive else ERROR, f"the code flow stopped: {failure.detail}", [s.evidence() for s in failure.steps]
    )


def code_tokens(ctx: Context, *, positive: bool = False) -> CodeTokens | Outcome:
    got = ctx.code_tokens()
    if isinstance(got, FlowFailure):
        return broken(got, positive=positive)
    return skip(got) if isinstance(got, str) else got


def logged_in(ctx: Context, flow: CodeFlow, scope: str) -> Authorization | Outcome:
    if ctx.config.login_fields is None and not ctx.config.login_cmd:
        return skip("no way to log in configured (--login-field or --login-cmd)")
    got = flow.authorized(scope=scope)
    if isinstance(got, FlowFailure):
        return broken(got)
    return got if got.code is not None else broken(FlowFailure(f"no code came back: {got.params}", got.steps))


def expect_authorize_refused(ex: Exchange, flow: CodeFlow) -> Outcome:
    """A request the authorization endpoint must not act on: refused outright, or sent back to the client with an
    error (RFC 6749 §4.1.2.1); never on to the login."""
    if ex.status == 0:
        return Outcome(ERROR, "no HTTP response", [ex.evidence()])
    if ex.status >= 500:
        return fail(f"server error {ex.status}", ex)
    if ex.status in (301, 302, 303, 307, 308):
        back = flow._back(ex.header("location"))
        if back is not None and "error" in back:
            return ok(f"sent back with error={back['error']}", ex)
        return fail("the request was taken on to the login", ex)
    if 400 <= ex.status < 500:
        return ok(f"refused with {ex.status} {ex.error_code()}", ex)
    return fail(f"answered {ex.status}", ex)


@check(
    "A01",
    "authorization",
    "HAIP 1.0 §4.1, §4.4.1; RFC 9126 §5; RFC 9207 §3",
    "Authorization server metadata advertises PAR (required), S256 only and attestation-based client auth",
)
def a01(ctx: Context) -> Outcome:
    md = ctx.as_metadata
    if "authorization_code" not in (md.get("grant_types_supported") or ["authorization_code"]):
        return skip("the authorization code grant is not advertised")
    problems = []
    if not isinstance(md.get("authorization_endpoint"), str):
        problems.append("no authorization_endpoint")
    if not isinstance(md.get("pushed_authorization_request_endpoint"), str):
        problems.append("no pushed_authorization_request_endpoint")
    if md.get("require_pushed_authorization_requests") is not True:
        problems.append("require_pushed_authorization_requests is not true")
    if md.get("code_challenge_methods_supported") != ["S256"]:
        problems.append(
            f"code_challenge_methods_supported={md.get('code_challenge_methods_supported')!r}, not S256 only"
        )
    if "attest_jwt_client_auth" not in (md.get("token_endpoint_auth_methods_supported") or []):
        problems.append("attest_jwt_client_auth not in token_endpoint_auth_methods_supported")
    if md.get("authorization_response_iss_parameter_supported") is not True:
        problems.append("authorization_response_iss_parameter_supported is not true")
    return fail("; ".join(problems), ctx.as_metadata_exchange) if problems else ok("", ctx.as_metadata_exchange)


@check("A02", "authorization", "HAIP 1.0 §4; OID4VCI 1.0 §5, §6", "The code flow yields a DPoP-bound token that issues")
def a02(ctx: Context) -> Outcome:
    got = code_tokens(ctx, positive=True)
    if isinstance(got, Outcome):
        return got
    data = got.token.exchange.json() or {}
    problems = []
    if str(data.get("token_type", "")).lower() != "dpop":
        problems.append(f"token_type={data.get('token_type')!r}, expected DPoP")
    if "no-store" not in got.token.exchange.header("cache-control"):
        problems.append("no Cache-Control: no-store (RFC 6749 §5.1)")
    proof = ctx.proof_for(EcKey.generate(), ctx.c_nonce())
    issued = ctx.credential_request(got.token, credential_body(ctx, got.config_id, [proof]), sent="code-flow token")
    if issued.status != 200:
        problems.append(f"the credential request with the token answered {issued.status}")
    if problems:
        return fail("; ".join(problems), got.token.exchange, issued)
    return ok("", got.token.exchange, issued)


@check("A03", "authorization", "RFC 9207 §2; RFC 6749 §4.1.2", "The authorization response carries iss and state")
def a03(ctx: Context) -> Outcome:
    got = code_tokens(ctx, positive=True)
    if isinstance(got, Outcome):
        return got
    params, flow = got.authorization.params, got.flow
    problems = []
    if params.get("iss") != flow.as_issuer:
        problems.append(f"iss={params.get('iss')!r}, expected {flow.as_issuer!r}")
    if params.get("state") != got.authorization.state:
        problems.append("state not echoed")
    return fail("; ".join(problems), *got.authorization.steps[-1:]) if problems else ok()


@check(
    "A04",
    "authorization",
    "RFC 9126 §2.2; FAPI 2.0 SP §5.3.2.2",
    "A pushed request_uri is spent once its login completes",
    sensitive=True,
)
def a04(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    if ctx.config.login_fields is None and not ctx.config.login_cmd:
        return skip("no way to log in configured (--login-field or --login-cmd)")
    uri = pushed(flow, Pkce.new(), scope)
    if isinstance(uri, Outcome):
        return uri
    # FAPI 2.0 SP §5.3.2.2 note 3: the request_uri may be opened again until the login completes, so only
    # an opening after that says whether it is spent.
    params, steps = flow.login(uri)
    if params is None or "code" not in params:
        return broken(FlowFailure(f"the login did not come back with a code: {params}", steps))
    return expect_authorize_refused(flow.authorize(uri), flow)


def went_on(ex: Exchange, flow: CodeFlow) -> bool:
    """Whether the authorization endpoint took a request on to the login: a login page served there (200), or a
    redirect anywhere but back to the client with an error."""
    if ex.status == 200:
        return True
    if ex.status in (301, 302, 303, 307, 308):
        back = flow._back(urljoin(ex.url, ex.header("location")))
        return back is None or "error" not in back
    return False


@check("A05", "authorization", "RFC 9126 §4", "A request_uri is refused for another client_id", sensitive=True)
def a05(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    if ctx.config.second_client is None:
        return skip("no second wallet solution the issuer allows (--second-client); an unknown one shows nothing")
    other_id, other_redirect = ctx.config.second_client
    other = ctx.code_client(client_id=other_id, redirect_uri=other_redirect)
    assert other is not None
    second = CodeFlow(ctx, other)
    own = pushed(second, Pkce.new(), scope)  # the second client is accepted on its own
    if isinstance(own, Outcome):
        return own
    opened = second.authorize(own)
    if not went_on(opened, second):
        return broken(FlowFailure("the second client's own request did not lead on to the login", [opened]))
    uri = pushed(flow, Pkce.new(), scope)
    if isinstance(uri, Outcome):
        return uri
    return expect_authorize_refused(flow.authorize(uri, client_id=other_id), flow)


@check(
    "A06",
    "authorization",
    "RFC 9126 §1; HAIP 1.0 §4.1",
    "The authorization endpoint refuses a request that was not pushed",
    sensitive=True,
)
def a06(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    pkce = Pkce.new()
    query = {
        "response_type": "code",
        "client_id": flow.client.client_id,
        "redirect_uri": flow.client.redirect_uri,
        "code_challenge": pkce.challenge,
        "code_challenge_method": "S256",
        "scope": scope,
        "state": "eudi-probe",
    }
    endpoint = flow.endpoint("authorization_endpoint")
    ex = ctx.http.request("GET", with_query(endpoint, query), sent="not pushed")
    return expect_authorize_refused(ex, flow)


@check(
    "A07", "authorization", "RFC 7636 §4.4.1; HAIP 1.0 §4.1", "PAR without a PKCE challenge is refused", sensitive=True
)
def a07(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    ex = flow.par(None, scope=scope, sent="no code_challenge")
    return expect_rejected(ex, statuses={400}, errors={"invalid_request"})


@check(
    "A08",
    "authorization",
    "FAPI 2.0 SP §5.3.2.2; HAIP 1.0 §4.1",
    "PAR with the plain PKCE method is refused",
    sensitive=True,
)
def a08(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    pkce = Pkce.new()
    extra = {"code_challenge": pkce.verifier, "code_challenge_method": "plain"}
    ex = flow.par(None, scope=scope, extra=extra, sent="code_challenge_method=plain")
    return expect_rejected(ex, statuses={400}, errors={"invalid_request"})


@check(
    "A09",
    "authorization",
    "OAuth 2.0 Security BCP §4.1.3; FAPI 2.0 SP §5.3.2.2",
    "PAR with a redirect URI not registered for the client is refused",
    sensitive=True,
)
def a09(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    other = flow.client.redirect_uri.rstrip("/") + "/elsewhere"
    ex = flow.par(Pkce.new(), scope=scope, extra={"redirect_uri": other}, sent="unregistered redirect_uri")
    return expect_rejected(ex, statuses={400}, errors={"invalid_request"})


@check(
    "A10",
    "authorization",
    "RFC 6749 §3.1.1; HAIP 1.0 §4",
    "PAR with response_type other than code is refused",
    sensitive=True,
)
def a10(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    ex = flow.par(Pkce.new(), scope=scope, extra={"response_type": "token"}, sent="response_type=token")
    return expect_rejected(ex, statuses={400}, errors={"invalid_request", "unsupported_response_type"})


@check("A11", "authorization", "RFC 7636 §4.6", "A wrong code_verifier is refused", sensitive=True)
def a11(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    got = logged_in(ctx, flow, scope)
    if isinstance(got, Outcome):
        return got
    assert got.code is not None
    ex = flow.token(got.code, Pkce.new(), sent="another code_verifier")
    return expect_rejected(ex, statuses={400}, errors={"invalid_grant"})


@check(
    "A12",
    "authorization",
    "RFC 6749 §4.1.3",
    "A redirect_uri at the token endpoint other than the authorized one is refused",
    sensitive=True,
)
def a12(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    got = logged_in(ctx, flow, scope)
    if isinstance(got, Outcome):
        return got
    assert got.code is not None
    other = flow.client.redirect_uri.rstrip("/") + "/elsewhere"
    ex = flow.token(got.code, got.pkce, redirect_uri=other, sent="another redirect_uri")
    return expect_rejected(ex, statuses={400}, errors={"invalid_grant", "invalid_request"})


@check(
    "A13",
    "authorization",
    "RFC 6749 §4.1.2, §10.5; FAPI 2.0 SP §5.3.2.1",
    "An authorization code is good once, and its use again ends the token it gave",
    sensitive=True,
)
def a13(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    got = logged_in(ctx, flow, scope)
    if isinstance(got, Outcome):
        return got
    assert got.code is not None
    first = flow.token(got.code, got.pkce, sent="first use")
    data = first.json() or {}
    if first.status != 200 or "access_token" not in data:
        return broken(FlowFailure("the code exchange was not accepted", [first]))
    token = Token(str(data["access_token"]), flow.client.dpop, first)
    config_id = ctx.target_config_id(None) or ""
    before = token_check(ctx, token, config_id, "the token before the reuse")
    if not accepted(before):
        return broken(FlowFailure("the token was not accepted before the code was used again", [before]))
    again = flow.token(got.code, got.pkce, sent="second use")
    refused = expect_rejected(again, statuses={400}, errors={"invalid_grant"})
    if refused.status != PASS:
        return refused
    return token_ended(again, token_check(ctx, token, config_id, "token of a reused code"))


def token_check(ctx: Context, token: Token, config_id: str, sent: str) -> Exchange:
    """A credential request that is refused for its proof alone, so it spends nothing: a server takes the token
    first (RFC 6750 §3.1), answering invalid_token for one it no longer accepts and a request error otherwise."""
    return ctx.credential_request(token, credential_body(ctx, config_id, ["eudi-probe.not-a.proof"]), sent=sent)


def accepted(ex: Exchange) -> bool:
    """Whether the token was taken: the request was answered on its own merits, not refused for the token."""
    return ex.status == 200 or (ex.status == 400 and ex.error_code() in CREDENTIAL_ERRORS)


def token_ended(again: Exchange, after: Exchange) -> Outcome:
    """What the credential endpoint says about a token whose code was used again: ended only when it answers
    invalid_token (RFC 6750 §3.1); still taken when it judges the request itself; anything else shows nothing."""
    if accepted(after):
        return warn(
            "the reuse was refused, but the token it had given is still taken (RFC 6749 §4.1.2 SHOULD)", again, after
        )
    challenge = after.header("www-authenticate")
    if after.status == 401 and (after.error_code() == "invalid_token" or 'error="invalid_token"' in challenge):
        return ok("refused, and the first token is no longer taken", again, after)
    return Outcome(
        ERROR,
        f"the token's fate is unknown: the credential endpoint answered {after.status} {after.error_code()}",
        [again.evidence(), after.evidence()],
    )


@check(
    "A14",
    "authorization",
    "WIA.CLIENT_ID_IS_SUB; draft-ietf-oauth-attestation-based-client-auth §5",
    "A code is refused when another wallet instance presents it",
    sensitive=True,
)
def a14(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    got = logged_in(ctx, flow, scope)
    if isinstance(got, Outcome):
        return got
    assert got.code is not None
    other = ctx.code_client()
    assert other is not None
    other.dpop = flow.client.dpop
    ex = CodeFlow(ctx, other).token(got.code, got.pkce, sent="another wallet instance")
    return expect_rejected(ex, statuses={400, 401}, errors={"invalid_grant", "invalid_client"})


@check(
    "A15",
    "authorization",
    "RFC 6749 §4.1.2.1; OID4VCI 1.0 §5.2",
    "A login the person cancels comes back as access_denied",
)
def a15(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    if ctx.config.cancel_fields is None and not ctx.config.login_cmd:
        return skip("no way to cancel a login configured (--cancel-field or --login-cmd)")
    got = flow.authorized(scope=scope, cancel=True)
    if isinstance(got, FlowFailure):
        return broken(got, positive=True)
    problems = []
    if got.params.get("error") != "access_denied":
        problems.append(f"error={got.params.get('error')!r}, expected access_denied")
    if "code" in got.params:
        problems.append("a code came back")
    if got.params.get("state") != got.state:
        problems.append("state not echoed")
    if got.params.get("iss") != flow.as_issuer:
        problems.append("no iss, or another one")
    return fail("; ".join(problems), *got.steps[-1:]) if problems else ok(str(got.params.get("error")))


@check(
    "A16",
    "authorization",
    "ARF ISSU_63; OID4VCI 1.0 §6.1; RFC 6749 §6",
    "A refresh token gives a new access token that issues",
)
def a16(ctx: Context) -> Outcome:
    got = code_tokens(ctx)
    if isinstance(got, Outcome):
        return got
    if got.refresh_token is None:
        return fail("the code exchange gave no refresh token", got.token.exchange)
    ex = got.flow.refresh(got.refresh_token, sent="refresh")
    data = ex.json() or {}
    if ex.status != 200 or "access_token" not in data:
        return fail(f"refresh answered {ex.status}", ex)
    if isinstance(data.get("refresh_token"), str):
        got.refresh_token = data["refresh_token"]  # an issuer that rotates them has spent the one before
    token = Token(str(data["access_token"]), got.flow.client.dpop, ex)
    proof = ctx.proof_for(EcKey.generate(), ctx.c_nonce())
    issued = ctx.credential_request(token, credential_body(ctx, got.config_id, [proof]), sent="refreshed token")
    return ok("", ex, issued) if issued.status == 200 else fail(f"the refreshed token answered {issued.status}", issued)


@check(
    "A17",
    "authorization",
    "ARF ISSU_65; draft-ietf-oauth-attestation-based-client-auth §10.3",
    "A refresh token is refused for another wallet instance",
    sensitive=True,
)
def a17(ctx: Context) -> Outcome:
    got = own_refresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    other = ctx.code_client()
    assert other is not None
    other.dpop, other.dpop_nonce = got.flow.client.dpop, got.flow.client.dpop_nonce
    ex = CodeFlow(ctx, other).refresh(str(got.refresh_token), sent="another wallet instance")
    return refused_then_good(got, expect_rejected(ex, statuses={400, 401}, errors={"invalid_grant", "invalid_client"}))


def own_code_tokens(ctx: Context) -> CodeTokens | Outcome:
    """A login of its own, so its tokens are unspent whatever ran before: an access token gives one credential per
    configuration, and an issuer may rotate refresh tokens."""
    client = ctx.code_client()
    if client is None:
        return skip("no wallet provider, client_id or redirect URI configured (--wia-ca, --client-id, --redirect-uri)")
    got = ctx.code_tokens(client)
    if isinstance(got, FlowFailure):
        return broken(got)
    return skip(got) if isinstance(got, str) else got


def own_refresh_token(ctx: Context) -> CodeTokens | Outcome:
    got = own_code_tokens(ctx)
    if isinstance(got, Outcome):
        return got
    return got if got.refresh_token is not None else skip("no refresh token")


def refused_then_good(got: CodeTokens, refused: Outcome) -> Outcome:
    """A refusal shows a binding only if the refresh token was good: the wallet it was given to uses it after."""
    if refused.status != PASS:
        return refused
    control = got.flow.refresh(str(got.refresh_token), sent="the wallet's own refresh")
    if control.status != 200:
        return broken(FlowFailure("the refresh token did not work for its own wallet either", [control]))
    return Outcome(PASS, refused.detail, [*refused.evidence, control.evidence()])


@check(
    "A18",
    "authorization",
    "RFC 6750 §2.3; FAPI 2.0 SP §5.3.3",
    "An access token in the query string is refused",
    sensitive=True,
)
def a18(ctx: Context) -> Outcome:
    got = own_code_tokens(ctx)
    token: Token | None = got.token if not isinstance(got, Outcome) else None
    config_id = got.config_id if not isinstance(got, Outcome) else None
    if token is None:
        fresh = fresh_token(ctx)
        if isinstance(fresh, Outcome):
            return fresh
        token, config_id = fresh
    # A request valid in every other way (a DPoP proof bound to the token, the server's nonce, the token's credential
    # identifiers): only the token's place differs.
    endpoint = ctx.endpoint("credential_endpoint") or ""
    proofs = [ctx.proof_for(EcKey.generate(), ctx.c_nonce())]
    body = with_identifier(token, credential_body(ctx, config_id or "", proofs))

    def send() -> Exchange:
        dpop = dpop_proof(token.key, "POST", endpoint, access_token=token.access_token, nonce=token.dpop_nonce)
        return ctx.http.request(
            "POST",
            with_query(endpoint, {"access_token": token.access_token}),
            content=json.dumps(body),
            headers={"Content-Type": "application/json", "DPoP": dpop},
            sent="token in the query",
        )

    ex = send()
    challenged = ex.error_code() == "use_dpop_nonce" or "use_dpop_nonce" in ex.header("www-authenticate")
    if ex.status in (400, 401) and challenged:
        token.dpop_nonce = ex.header("dpop-nonce") or None  # the server's nonce, then the same request again
        ex = send()
    refused = expect_rejected(ex, statuses={400, 401}, errors={"invalid_token", "invalid_request"}, header_error=True)
    if refused.status != PASS:
        return refused
    # The refusal shows something only if the token works where it belongs.
    body = credential_body(ctx, config_id or "", [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    control = ctx.credential_request(token, body, sent="the token in the Authorization header")
    if control.status != 200:
        return broken(FlowFailure("the token did not issue from the Authorization header either", [control]))
    return Outcome(PASS, refused.detail, [*refused.evidence, control.evidence()])


@check(
    "A19",
    "authorization",
    "OID4VCI 1.0 §6.2",
    "credential_identifiers granted by authorization_details stay the same after a refresh",
)
def a19(ctx: Context) -> Outcome:
    flow = code_flow(ctx)
    if isinstance(flow, Outcome):
        return flow
    if ctx.config.login_fields is None and not ctx.config.login_cmd:
        return skip("no way to log in configured (--login-field or --login-cmd)")
    config_id = ctx.target_config_id(None)
    if config_id is None:
        return skip("no credential configuration")
    details = [{"type": "openid_credential", "credential_configuration_id": config_id}]
    got = flow.authorized(details=details)
    if isinstance(got, FlowFailure):
        return broken(got)
    if got.code is None:
        return broken(FlowFailure(f"no code came back: {got.params}", got.steps))
    first = flow.token(got.code, got.pkce, sent="code exchange with authorization_details")
    refresh = (first.json() or {}).get("refresh_token")
    if first.status != 200 or not isinstance(refresh, str):
        return broken(FlowFailure("the code exchange gave no refresh token", [first]))
    again = flow.refresh(refresh, sent="refresh")
    before, after = granted_identifiers(first, config_id), granted_identifiers(again, config_id)
    if not before:
        return fail(f"the token response gives no credential_identifiers for {config_id}", first)
    return ok("", first, again) if before == after else fail(f"{before} became {after}", first, again)


def granted_identifiers(ex: Exchange, config_id: str) -> list[str]:
    """The credential identifiers a token response grants for `config_id`: non-empty strings, or none."""
    details = (ex.json() or {}).get("authorization_details")
    for detail in details if isinstance(details, list) else []:
        if isinstance(detail, dict) and detail.get("credential_configuration_id") == config_id:
            identifiers = detail.get("credential_identifiers")
            if isinstance(identifiers, list) and identifiers and all(isinstance(i, str) and i for i in identifiers):
                return list(identifiers)
    return []


# ---------------------------------------------------------------- wallet attestations (HAIP 1.0 §4.4.1)


def expect_client_refused(ex: Exchange) -> Outcome:
    return expect_rejected(ex, statuses={400, 401}, errors={"invalid_client", "invalid_client_attestation"})


def par_with(ctx: Context, sent: str, make: Callable[[Instance, str], dict[str, str]]) -> Exchange | Outcome:
    """A PAR from a fresh instance of the configured client, with the attestation headers `make` gives for that
    instance and the authorization server's identifier, so each check changes one thing and nothing else."""
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    if isinstance(refused := fixture_refused(flow, scope), Outcome):
        return refused
    # Made for each attempt: a retry after a DPoP nonce challenge brings a fresh proof with the same change.
    return flow.par(
        Pkce.new(), scope=scope, attest=False, headers=lambda: make(flow.client.instance, flow.as_issuer), sent=sent
    )


def fixture_refused(flow: CodeFlow, scope: str) -> Outcome | None:
    """The same wallet's own valid PAR first: a refusal of a changed attestation shows something only if the
    unchanged one is accepted."""
    control = flow.par(Pkce.new(), scope=scope, sent="control: the wallet's own valid attestation")
    if control.status != 201:
        return broken(FlowFailure("the wallet attestation fixture itself is not accepted", [control]))
    return None


@check(
    "W01", "attestation", "HAIP 1.0 §4.4.1; ARF WUA_25", "PAR without a wallet attestation is refused", sensitive=True
)
def w01(ctx: Context) -> Outcome:
    ex = par_with(ctx, "no wallet attestation", lambda instance, audience: {})
    return ex if isinstance(ex, Outcome) else expect_client_refused(ex)


@check(
    "W02",
    "attestation",
    "ARF ISSU_19, ISSU_28, ISSU_30a; ETSI TS 119 602 Annex E",
    "A wallet attestation from a wallet provider the issuer does not trust is refused",
    sensitive=True,
)
def w02(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    # The same in every way but its CA: the configured status entry and the signer's certificate policies included.
    trusted = ctx.config.wallet_provider
    untrusted = WalletProvider.untrusted(trusted.policies if trusted else ())
    untrusted.status = trusted.status if trusted else None
    client = ctx.code_client(provider=untrusted)
    if isinstance(got_flow, Outcome) or client is None:
        return got_flow if isinstance(got_flow, Outcome) else skip("no client configured")
    if isinstance(refused := fixture_refused(*got_flow), Outcome):
        return refused
    ex = CodeFlow(ctx, client).par(Pkce.new(), scope=got_flow[1], sent="untrusted wallet provider")
    return expect_client_refused(ex)


@check(
    "W03",
    "attestation",
    "draft-ietf-oauth-attestation-based-client-auth §5.1",
    "A wallet attestation with a bad signature is refused",
    sensitive=True,
)
def w03(ctx: Context) -> Outcome:
    def make(instance: Instance, audience: str) -> dict[str, str]:
        return instance.headers(audience, attestation=instance.attestation(signer=EcKey.generate()))

    ex = par_with(ctx, "attestation signed by another key", make)
    return ex if isinstance(ex, Outcome) else expect_client_refused(ex)


@check(
    "W04",
    "attestation",
    "draft-ietf-oauth-attestation-based-client-auth §5.2",
    "A proof of possession not signed by the attested key is refused",
    sensitive=True,
)
def w04(ctx: Context) -> Outcome:
    def make(instance: Instance, audience: str) -> dict[str, str]:
        return instance.headers(audience, pop=instance.pop(audience, signer=EcKey.generate()))

    ex = par_with(ctx, "PoP signed by another key", make)
    return ex if isinstance(ex, Outcome) else expect_client_refused(ex)


@check(
    "W05",
    "attestation",
    "draft-ietf-oauth-attestation-based-client-auth §5.1",
    "An expired wallet attestation is refused",
    sensitive=True,
)
def w05(ctx: Context) -> Outcome:
    def make(instance: Instance, audience: str) -> dict[str, str]:
        now = int(time.time())
        return instance.headers(audience, attestation=instance.attestation(iat=now - 7200, exp=now - 3600))

    ex = par_with(ctx, "expired attestation", make)
    return ex if isinstance(ex, Outcome) else expect_client_refused(ex)


@check(
    "W06",
    "attestation",
    "draft-ietf-oauth-attestation-based-client-auth §5.1",
    "A wallet attestation without sub is refused",
    sensitive=True,
)
def w06(ctx: Context) -> Outcome:
    def make(instance: Instance, audience: str) -> dict[str, str]:
        return instance.headers(audience, attestation=instance.attestation(sub=...))

    ex = par_with(ctx, "attestation without sub", make)
    return ex if isinstance(ex, Outcome) else expect_client_refused(ex)


@check(
    "W07",
    "attestation",
    "draft-ietf-oauth-attestation-based-client-auth §5.2",
    "A proof of possession for another audience is refused",
    sensitive=True,
)
def w07(ctx: Context) -> Outcome:
    def make(instance: Instance, audience: str) -> dict[str, str]:
        return instance.headers(audience, pop=instance.pop("https://another-server.eudi-probe.invalid"))

    ex = par_with(ctx, "PoP for another audience", make)
    return ex if isinstance(ex, Outcome) else expect_client_refused(ex)


@check(
    "W08",
    "attestation",
    "draft-ietf-oauth-attestation-based-client-auth §12.1",
    "A proof of possession sent twice is refused the second time",
    sensitive=True,
)
def w08(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    first = flow.par(Pkce.new(), scope=scope, sent="first use")
    if first.status != 201:
        return broken(FlowFailure("the first PAR was not accepted", [first]))
    accepted = {k: v for k, v in flow.last_headers.items() if k in (ATTESTATION_HEADER, POP_HEADER)}
    again = flow.par(Pkce.new(), scope=scope, attest=False, headers=accepted, sent="the same PoP again")
    return expect_client_refused(again)


@check(
    "W09",
    "attestation",
    "HAIP 1.0 §4.4.1; draft-ietf-oauth-attestation-based-client-auth §6",
    "The token endpoint requires the wallet attestation too",
    sensitive=True,
)
def w09(ctx: Context) -> Outcome:
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    got = logged_in(ctx, flow, scope)
    if isinstance(got, Outcome):
        return got
    assert got.code is not None
    return expect_client_refused(flow.token(got.code, got.pkce, attest=False, sent="no wallet attestation"))


@check(
    "W10",
    "attestation",
    "ARF ISSU_21, ISSU_30, WUA_11a; TS3 §2.3.2",
    "A key attestation from a wallet provider the issuer does not trust is refused",
    sensitive=True,
)
def w10(ctx: Context) -> Outcome:
    got = own_code_tokens(ctx)
    token = got.token if not isinstance(got, Outcome) else None
    config_id = got.config_id if not isinstance(got, Outcome) else None
    if token is None:
        fresh = fresh_token(ctx)
        if isinstance(fresh, Outcome):
            return fresh
        token, config_id = fresh
    jwt_spec = ((ctx.configurations.get(config_id or "") or {}).get("proof_types_supported") or {}).get("jwt") or {}
    if "key_attestations_required" not in jwt_spec:
        return skip(f"{config_id} does not require key attestation")
    # The same key attestation in every way but its signer's CA, the configured status entry included, so only the
    # trust in the CA can decide; then the trusted one must be taken, or the refusal shows nothing.
    issuer = AttestationIssuer.untrusted()
    issuer.status = ctx.config.attestation_issuer.status if ctx.config.attestation_issuer else None
    holder, nonce = EcKey.generate(), ctx.c_nonce()
    proof = ctx.proof_for(holder, nonce, key_attestation=issuer.key_attestation([holder], nonce=nonce))
    ex = ctx.credential_request(token, credential_body(ctx, config_id or "", [proof]), sent="untrusted key attestation")
    refused = expect_rejected(ex, statuses={400}, errors={"invalid_proof"})
    if refused.status != PASS:
        return refused
    trusted = ctx.proof_for(EcKey.generate(), ctx.c_nonce())
    control = ctx.credential_request(token, credential_body(ctx, config_id or "", [trusted]), sent="trusted control")
    if control.status != 200:
        return broken(FlowFailure("a key attestation from the trusted provider was not taken either", [control]))
    return Outcome(PASS, refused.detail, [*refused.evidence, control.evidence()])


# ---------------------------------------------------------------- metadata of M3 (ETSI TS 119 472-3)


@check(
    "M17",
    "metadata",
    "OID4VCI 1.0 §12.2.3; ETSI TS 119 472-3 §4.2.1, §4.2.2; ARF ISSU_22",
    "Signed metadata: a JWT with x5c, typ, sub and the same content as the JSON",
)
def m17(ctx: Context) -> Outcome:
    url = ctx.metadata_exchange.url
    ex = ctx.http.request("GET", url, headers={"Accept": "application/jwt"}, sent="Accept: application/jwt")
    if ex.status != 200 or ex.header("content-type").split(";")[0].strip() != "application/jwt":
        return fail(f"no signed metadata: {ex.status} {ex.header('content-type')}", ex)
    try:
        signed = parse_jws(ex.body.strip())
        chain = load_x5c(signed.header.get("x5c") or [])
    except (ValueError, TypeError) as exc:
        return fail(f"not a JWS with an x5c chain: {exc}", ex)
    problems = []
    if signed.header.get("typ") != "openidvci-issuer-metadata+jwt":
        problems.append(f"typ={signed.header.get('typ')!r}")
    if not chain:
        problems.append("no x5c")
    elif not verify_with_public_key(
        str(signed.header.get("alg")), chain[0].public_key(), signed.signing_input, signed.signature
    ):
        problems.append("the signature does not verify under x5c[0]")
    elif any(is_self_signed(c) for c in chain):
        problems.append("x5c carries a self-signed certificate (the trust anchor is never sent)")
    payload = dict(signed.payload)
    if payload.get("sub") != ctx.metadata.get("credential_issuer"):
        problems.append(f"sub={payload.get('sub')!r}, expected the credential issuer")
    now = time.time()
    if not isinstance(payload.get("iat"), int) or payload["iat"] > now + 60:
        problems.append("no iat, or ahead")
    if isinstance(payload.get("exp"), int) and payload["exp"] <= now:
        problems.append("exp has passed")
    for member in ("sub", "iat", "exp", "iss"):
        payload.pop(member, None)
    unsigned = {k: v for k, v in ctx.metadata.items() if k not in ("sub", "iat", "exp", "iss")}
    if payload != unsigned:
        problems.append("the signed content differs from the JSON metadata")
    return fail("; ".join(problems), ex) if problems else ok("", ex)


@check(
    "M18",
    "metadata",
    "ETSI TS 119 472-3 §4.2.3; ARF RPRC_22",
    "issuer_info carries the registration certificate by value and the registrar dataset",
)
def m18(ctx: Context) -> Outcome:
    info = ctx.metadata.get("issuer_info")
    if not isinstance(info, list):
        return fail("no issuer_info array", ctx.metadata_exchange)
    formats = {e.get("format"): e.get("data") for e in info if isinstance(e, dict)}
    problems = []
    certificate = formats.get("registration_cert")
    if not isinstance(certificate, str) or not certificate.strip():
        problems.append("no registration_cert by value")
    dataset = formats.get("registrar_dataset")
    if not isinstance(dataset, dict):
        problems.append("no registrar_dataset object")
    else:
        missing = [
            m for m in ("identifier", "srvDescription", "registryURI", "providesAttestations") if m not in dataset
        ]
        if missing:
            problems.append(f"registrar_dataset lacks {', '.join(missing)}")
    return fail("; ".join(problems), ctx.metadata_exchange) if problems else ok()


REUSE_METHODS = {"once_only", "limited_time", "limited-time", "rotating-batch", "per-relying-party"}


@check(
    "M19",
    "metadata",
    "ETSI TS 119 472-3 §4.2.4; ARF ISSU_39, ISSU_40, ISSU_45, ISSU_50, ISSU_54",
    "Each configuration states its credential reuse policy as TS 119 472-3 encodes it",
)
def m19(ctx: Context) -> Outcome:
    problems = []
    for config_id, config in ctx.configurations.items():
        policy = ((config or {}).get("credential_metadata") or {}).get("credential_reuse_policy")
        problems += [f"{config_id}: {p}" for p in reuse_policy_problems(policy)]
    return fail("; ".join(problems[:5]), ctx.metadata_exchange) if problems else ok()


def reuse_policy_problems(policy: Any) -> list[str]:
    if not isinstance(policy, dict):
        return ["no credential_reuse_policy"]
    options = policy.get("options")
    if not isinstance(policy.get("id"), str) or not isinstance(options, list) or not options:
        return ["credential_reuse_policy needs an id and options"]
    problems = []
    for option in options:
        details = option.get("details") if isinstance(option, dict) else None
        if not isinstance(details, list) or not details or any(d not in REUSE_METHODS for d in details):
            problems.append(f"details {details!r} are not reuse methods")
            continue
        named = set(details)
        if bool(named & {"once_only"}) + bool(named & {"limited_time", "limited-time"}) != 1:
            problems.append("an option names neither or both of methods A and B")
        size = option.get("batch_size")
        if named & {"once_only", "rotating-batch", "per-relying-party"} and not (isinstance(size, int) and size >= 2):
            problems.append("batch_size missing or below 2")
        unused = option.get("reissue_trigger_unused")
        if "once_only" in named and not (isinstance(unused, int) and isinstance(size, int) and 0 <= unused < size):
            problems.append("reissue_trigger_unused missing or not below batch_size")
        left = option.get("reissue_trigger_lifetime_left")
        timed = named & {"limited_time", "limited-time", "rotating-batch", "per-relying-party"}
        if timed and not (isinstance(left, int) and left >= 1):
            problems.append("reissue_trigger_lifetime_left missing")
    return problems


@check(
    "M20",
    "metadata",
    "ARF EDP_09; ETSI TS 119 472-3 §4.2.5",
    "An embedded disclosure policy, if any, is carried by value",
)
def m20(ctx: Context) -> Outcome:
    return skip("no metadata member for an embedded disclosure policy is standardised yet (TS 119 472-3 §4.2.5)")


@check(
    "M21",
    "metadata",
    "TS3 v1.5.2 §2.4",
    "preferred_client_status_period, when published, is a whole number of seconds",
)
def m21(ctx: Context) -> Outcome:
    if "preferred_client_status_period" not in ctx.metadata:
        return skip("not published")
    value = ctx.metadata["preferred_client_status_period"]
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return fail(f"preferred_client_status_period={value!r}", ctx.metadata_exchange)
    return ok(f"{value} s")


@check(
    "A20",
    "authorization",
    "OID4VCI 1.0 §4.1.1, §5.1.1",
    "An offer for the code flow carries issuer_state, which PAR accepts",
)
def a20(ctx: Context) -> Outcome:
    offer = ctx.fresh_offer() if ctx.can_make_offers() else None
    grant = ((offer.raw if offer else {}).get("grants") or {}).get("authorization_code")
    if not isinstance(grant, dict):
        return skip("no offer with an authorization_code grant (pass an offer command that makes one)")
    if "issuer_state" not in grant:
        return skip("the offer has no issuer_state, which is optional (OpenID4VCI §4.1.1)")
    issuer_state = grant["issuer_state"]
    if not isinstance(issuer_state, str) or not issuer_state:
        return fail(f"issuer_state is not a non-empty string: {grant}")
    got_flow = flow_and_scope(ctx)
    if isinstance(got_flow, Outcome):
        return got_flow
    flow, scope = got_flow
    ids = offer.configuration_ids if offer else []
    scope = (ctx.scope_for(ids[0]) or scope) if ids else scope
    ex = flow.par(Pkce.new(), scope=scope, extra={"issuer_state": issuer_state}, sent="PAR with issuer_state")
    return ok("", ex) if ex.status == 201 else fail(f"PAR with the offer's issuer_state answered {ex.status}", ex)


@check(
    "A21",
    "authorization",
    "RFC 9449 §5; OID4VCI 1.0 §6.1",
    "A refresh with a new DPoP key gives an access token bound to that key, not the old one",
    sensitive=True,
)
def a21(ctx: Context) -> Outcome:
    got = own_refresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    other = Client(got.flow.client.instance, got.flow.client.redirect_uri)  # same instance, a new DPoP key
    ex = CodeFlow(ctx, other).refresh(str(got.refresh_token), sent="refresh with a new DPoP key")
    data = ex.json() or {}
    if ex.status != 200 or not isinstance(data.get("access_token"), str):
        # RFC 9449 §5: an authenticated client's refresh token is not bound to the DPoP key, so a wallet can move
        # to a new one; an issuer that binds it anyway leaves nothing here to test.
        return skip(f"the refresh with a new DPoP key answered {ex.status}")
    body = credential_body(ctx, got.config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    old = ctx.credential_request(Token(data["access_token"], got.flow.client.dpop, ex), body, sent="the old DPoP key")
    refused = expect_rejected(old, statuses={400, 401}, errors={"invalid_dpop_proof", "invalid_token"})
    if refused.status != PASS:
        return refused
    body = credential_body(ctx, got.config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    new = ctx.credential_request(Token(data["access_token"], other.dpop, ex), body, sent="the new DPoP key")
    if new.status != 200:
        return broken(FlowFailure("the refreshed token did not work with its own DPoP key either", [new]))
    return Outcome(PASS, refused.detail, [ex.evidence(), *refused.evidence, new.evidence()])


@check("M22", "metadata", "OID4VCI 1.0 §12.2.4; HAIP 1.0 §4.1", "Each configuration's scope is its own")
def m22(ctx: Context) -> Outcome:
    scopes: dict[str, list[str]] = {}
    for config_id, config in ctx.configurations.items():
        scope = (config or {}).get("scope")
        if isinstance(scope, str):
            scopes.setdefault(scope, []).append(config_id)
    shared = {s: ids for s, ids in scopes.items() if len(ids) > 1}
    return fail(f"scopes shared by several configurations: {shared}", ctx.metadata_exchange) if shared else ok()


@check(
    "M23",
    "metadata",
    "OID4VCI 1.0 §12.2.2; RFC 9110 §12.5.1",
    "Metadata is JSON unless JWT is asked for, and the answer says it varies by Accept",
)
def m23(ctx: Context) -> Outcome:
    url = ctx.metadata_exchange.url
    plain = ctx.http.request("GET", url, sent="no Accept")
    signed = ctx.http.request("GET", url, headers={"Accept": "application/jwt"}, sent="Accept: application/jwt")
    problems = []
    if plain.status != 200 or not plain.header("content-type").startswith("application/json"):
        problems.append(f"without Accept: {plain.status} {plain.header('content-type')}")
    if signed.status == 200 and signed.header("content-type").startswith("application/jwt"):
        for ex in (plain, signed):
            if "accept" not in ex.header("vary").lower():
                problems.append(f"no Vary: Accept on the {'JSON' if ex is plain else 'JWT'} answer")
    else:
        return skip("no signed metadata served")
    return fail("; ".join(problems), plain, signed) if problems else ok("", plain, signed)


# ------------------------------------------------------------------ mdoc (M4)


def issue_mdoc(ctx: Context) -> tuple[bytes, str, EcKey, dict[str, Any], Exchange] | Outcome:
    """One mso_mdoc issuance, cached apart from the SD-JWT VC one: the configuration --mdoc-config-id names, or the
    first mso_mdoc one the offer names."""
    if "mdoc" in ctx.cache:
        return ctx.cache["mdoc"]
    result: tuple[bytes, str, EcKey, dict[str, Any], Exchange] | Outcome
    cached = ctx.cache.get("issued")
    if isinstance(cached, tuple) and ctx.configurations.get(cached[3], {}).get("format") == "mso_mdoc":
        # The run's issuance is an mdoc already (--config-id, or a single offer for one): it is the one to inspect,
        # and a single static offer cannot give a second.
        _, holder, ex, config_id = cached
        if ctx.config.mdoc_config_id in (None, config_id):
            data = ex.json()
            credentials = data.get("credentials") if isinstance(data, dict) else None
            if ex.status != 200 or not isinstance(credentials, list) or not credentials:
                result = skip("no credential issued (see C01)")
            else:
                result = (_mdoc_bytes(credentials[0]), config_id, holder, ctx.configurations.get(config_id, {}), ex)
            ctx.cache["mdoc"] = result
            return result
    offer = need_offer(ctx)
    config_id = ctx.mdoc_config_id(offer) if offer is not None else None
    if offer is None:
        result = skip("no pre-authorized offer available (pass --offer-cmd)")
    elif config_id is None:
        result = skip("the offer names no mso_mdoc configuration (pass --mdoc-config-id)")
    else:
        token = ctx.get_token(offer)
        holder = EcKey.generate()
        if token is None:
            result = skip("could not obtain an access token; see notes")
        else:
            body = credential_body(ctx, config_id, [ctx.proof_for(holder, ctx.c_nonce())])
            ex = ctx.credential_request(token, body, sent="mdoc request")
            data = ex.json()
            credentials = data.get("credentials") if isinstance(data, dict) else None
            if ex.status != 200 or not isinstance(credentials, list) or not credentials:
                result = fail(f"the mdoc request for {config_id} answered {ex.status}", ex)
            else:
                result = (_mdoc_bytes(credentials[0]), config_id, holder, ctx.configurations.get(config_id, {}), ex)
    ctx.cache["mdoc"] = result
    return result


def _mdoc_bytes(entry: Any) -> bytes:
    try:
        return b64u_decode(str(entry.get("credential")))
    except (ValueError, AttributeError):
        return b""


def read_mdoc(ctx: Context) -> tuple[IssuerSigned, str, EcKey, dict[str, Any], Exchange] | Outcome:
    got = issue_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    raw, config_id, holder, config, ex = got
    try:
        return cose.issuer_signed(raw), config_id, holder, config, ex
    except CoseError as exc:
        return fail(f"not a base64url CBOR IssuerSigned: {exc}", ex)


@check(
    "I01",
    "mdoc",
    "ISO/IEC 18013-5 §9.1.2.4, §9.3.1, Annex B.1.4; RFC 9052 §4.4; RFC 9360",
    "issuerAuth is signed by the document signer its x5chain names",
)
def i01(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, _, _, _, ex = got
    try:
        chain = signed.auth.chain()
        signed.auth.verify(chain[0].public_key())
    except CoseError as exc:
        return fail(str(exc), ex)
    problems = cose.chain_problems(chain, dt.datetime.now(dt.UTC))
    if not cose.has_purpose(chain[0], cose.MDOC_DS):
        problems.append("the document signer certificate lacks the purpose id-mdl-kp-mdlDS (1.0.18013.5.1.2)")
    leaf = chain[0].subject.rfc4514_string()
    return fail("; ".join(problems), ex) if problems else ok(f"{cose.ALGS[signed.auth.protected[1]]} by {leaf}", ex)


@check(
    "I02",
    "mdoc",
    "ISO/IEC 18013-5 §9.1.2.4, §9.3.1; OID4VCI 1.0 App. A.2.2",
    "The MSO names the configuration's docType and digests every data element",
)
def i02(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, config_id, _, config, ex = got
    mso, problems = signed.mso, []
    if mso.get("version") != "1.0":
        problems.append(f"version {mso.get('version')!r}, not 1.0")
    if mso.get("docType") != config.get("doctype"):
        problems.append(f"docType {mso.get('docType')!r}, but {config_id} names {config.get('doctype')!r}")
    digests = mso.get("valueDigests")
    algorithm = mso.get("digestAlgorithm")
    if not isinstance(digests, dict):
        return fail("; ".join([*problems, "no valueDigests map"]), ex)
    for item in signed.items:
        listed = digests.get(item.namespace, {})
        expected = listed.get(item.digest_id) if isinstance(listed, dict) else None
        try:
            computed = cose.digest(str(algorithm), item.encoded)
        except CoseError as exc:
            return fail("; ".join([*problems, str(exc)]), ex)
        if expected != computed:
            problems.append(f"{item.namespace}/{item.name}: digest {item.digest_id} does not match")
    return fail("; ".join(problems), ex) if problems else ok(f"{len(signed.items)} digests by {algorithm}", ex)


@check(
    "I03",
    "mdoc",
    "ISO/IEC 18013-5 §9.1.2.4 (deviceKeyInfo); OID4VCI 1.0 §8.2, App. A.2",
    "The mdoc is bound to the key of the proof",
)
def i03(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, _, holder, _, ex = got
    info = signed.mso.get("deviceKeyInfo")
    try:
        device = cose.cose_key_public(info.get("deviceKey") if isinstance(info, dict) else None)
    except CoseError as exc:
        return fail(str(exc), ex)
    if device.public_numbers() != holder.private.public_key().public_numbers():
        return fail("deviceKey is not the key of the proof", ex)
    return ok("", ex)


@check(
    "I04",
    "mdoc",
    "ISO/IEC 18013-5 §9.1.2.4 (validityInfo), §9.3.1",
    "validityInfo is tdate without fractions, in order, and inside the signer's validity",
)
def i04(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, _, _, _, ex = got
    info = signed.mso.get("validityInfo")
    if not isinstance(info, dict):
        return fail("no validityInfo map", ex)
    try:
        when = {name: cose.tdate(info.get(name), name) for name in ("signed", "validFrom", "validUntil")}
        chain = signed.auth.chain()
    except CoseError as exc:
        return fail(str(exc), ex)
    now, skew, problems = dt.datetime.now(dt.UTC), dt.timedelta(minutes=5), []
    if when["signed"] > now + skew:
        problems.append(f"signed {when['signed']:%Y-%m-%dT%H:%M:%SZ} is in the future")
    if when["validFrom"] < when["signed"]:
        problems.append("validFrom is before signed")
    if when["validUntil"] <= when["validFrom"]:
        problems.append("validUntil is not after validFrom")
    if not when["validFrom"] - skew <= now < when["validUntil"]:
        problems.append("a fresh mdoc is not valid now")
    leaf = chain[0]
    if not leaf.not_valid_before_utc <= when["signed"] <= leaf.not_valid_after_utc:
        problems.append("signed falls outside the document signer certificate's validity")
    days = (when["validUntil"] - when["validFrom"]).days
    return fail("; ".join(problems), ex) if problems else ok(f"valid {days} days", ex)


def _bad_dates(value: Any, where: str) -> list[str]:
    """Every tag 0 a tdate and every tag 1004 a full-date, as their text is sent (ISO/IEC 18013-5 §7.2.1)."""
    if isinstance(value, cbor2.CBORTag):
        if value.tag == cose.TDATE:
            try:
                cose.tdate(value, where)
            except CoseError as exc:
                return [str(exc)]
        elif value.tag == cose.FULL_DATE and not cose.is_full_date(value):
            return [f"{where}: full-date {value.value!r} is not YYYY-MM-DD"]
        return _bad_dates(value.value, where)
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _bad_dates(v, f"{where}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _bad_dates(v, f"{where}[{i}]")]
    return []


@check(
    "I05",
    "mdoc",
    "OID4VCI 1.0 App. B.2 (claims, mandatory); ISO/IEC 18013-5 §7.2.1; RFC 8943",
    "Every mandatory element is issued, and dates are well-formed tdate or full-date",
)
def i05(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, config_id, _, config, ex = got
    holder = config.get("credential_metadata") if isinstance(config.get("credential_metadata"), dict) else config
    claims = holder.get("claims") if isinstance(holder, dict) else None
    paths = [c for c in claims if isinstance(c, dict) and isinstance(c.get("path"), list)] if claims else []
    issued = {(i.namespace, i.name) for i in signed.items}
    listed = {tuple(c["path"][:2]) for c in paths if len(c["path"]) >= 2}
    problems = [
        f"mandatory {c['path'][0]}/{c['path'][1]} not issued"
        for c in paths
        if c.get("mandatory") is True and len(c["path"]) >= 2 and tuple(c["path"][:2]) not in issued
    ]
    for item in signed.items:
        problems += _bad_dates(item.value, f"{item.namespace}/{item.name}")
    if problems:
        return fail("; ".join(problems), ex)
    extra = sorted(f"{ns}/{name}" for ns, name in issued - listed) if listed else []
    if extra:
        return warn(f"elements the metadata of {config_id} does not describe: {', '.join(extra)}", ex)
    return ok(f"{len(issued)} elements", ex)


def _status_entry(raw: bytes, idx: int, bits: int) -> int | None:
    per_byte = 8 // bits
    if idx >= len(raw) * per_byte:
        return None
    return (raw[idx // per_byte] >> ((idx % per_byte) * bits)) & ((1 << bits) - 1)


@check(
    "I06",
    "mdoc",
    "Token Status List draft-21 §5.2, §6.3, §8; CIR (EU) 2024/2979 Annex II EAA-6.2.10.1",
    "The MSO's status list entry resolves to a valid statuslist+cwt",
)
def i06(ctx: Context) -> Outcome:
    got = read_mdoc(ctx)
    if isinstance(got, Outcome):
        return got
    signed, _, _, _, issued = got
    status = signed.mso.get("status")
    ref = status.get("status_list") if isinstance(status, dict) else None
    if not isinstance(ref, dict):
        return warn("the MSO has no status_list reference (no revocation)", issued)
    idx, uri, anchor = ref.get("idx"), ref.get("uri"), ref.get("certificate")
    if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0 or not isinstance(uri, str):
        return fail(f"bad status_list reference {ref!r}", issued)
    if "certificate" in ref and not isinstance(anchor, bytes):
        # EAA-6.2.10.1-13.1: a bstr of the certificate. One of another type is no reference to tie the chain to.
        return fail(f"the status_list reference's certificate is not a bstr: {anchor!r}", issued)
    ex = ctx.http.request("GET", uri, headers={"Accept": "application/statuslist+cwt"})
    if ex.status != 200:
        return fail(f"status list fetch returned {ex.status}", ex)
    problems = []
    if not ex.header("content-type").startswith("application/statuslist+cwt"):
        problems.append(f"Content-Type={ex.header('content-type')!r}")
    try:
        token = cose.sign1(cose.decode_raw(ex.content))
        chain = token.chain()
        token.verify(chain[0].public_key())
        claims = cose.decode_raw(token.payload)
    except CoseError as exc:
        return fail("; ".join([*problems, str(exc)]), ex)
    if not token.tagged:
        problems.append("not COSE_Sign1_Tagged (18)")
    if token.protected.get(cose.TYP) != "application/statuslist+cwt":
        problems.append(f"protected type (16) is {token.protected.get(cose.TYP)!r}")
    if not isinstance(claims, dict):
        return fail("; ".join([*problems, "the CWT claims are not a map"]), ex)
    if claims.get(2) != uri:
        problems.append(f"sub (2) {claims.get(2)!r} != uri")
    problems += status_times(
        claims.get(6), claims.get(4), claims.get(65534), "iat (6)", "exp (4)", "ttl (65534)", whole_ttl=True
    )
    # The signer is the first certificate of the x5chain: each one signed by the next and valid now, up to the top one,
    # which the reference's certificate signed (CIR 2024/2979 Annex II EAA-6.2.10.1-06.1, -13.1), or the chain
    # proves nothing about who signed the list.
    now = dt.datetime.now(dt.UTC)
    trusted: x509.Certificate | None = None
    if isinstance(anchor, bytes):
        try:
            trusted = x509.load_der_x509_certificate(anchor)
        except ValueError:
            problems.append("the reference's certificate does not parse")
    # Sent in the chain, at its top or below, the reference's certificate ends the path: it is checked there as the
    # issuer of the one under it, and what the chain sends above it is not needed. Sent apart, it must sign the top
    # certificate, as a CA allowed to.
    path = chain[: chain.index(trusted) + 1] if trusted is not None and trusted in chain else chain
    if trusted is not None and trusted == chain[0]:
        # The reference names the certificate that issued the list's signing chain (EAA-6.2.10.1-06.1), a CA above
        # the signer, never the signer itself, which would vouch for its own list.
        problems.append("the reference's certificate is the list's signer itself, not a CA above it")
    problems += [f"list x5chain: {p}" for p in cose.chain_problems(path, now)]
    if trusted is not None:
        if not trusted.not_valid_before_utc <= now <= trusted.not_valid_after_utc:
            problems.append("the reference's certificate is not valid now")
        if trusted not in chain:
            try:
                path[-1].verify_directly_issued_by(trusted)
            except (ValueError, TypeError, InvalidSignature):
                problems.append("the reference's certificate did not sign the top certificate of the list's chain")
            below = len(path) - 1  # the CA certificates under it: every one of the path but the signer's
            problems += [f"the reference's certificate: {p}" for p in cose.issuer_problems(trusted, below)]
    lst = claims.get(65533)
    bits = lst.get("bits") if isinstance(lst, dict) else None
    if bits not in (1, 2, 4, 8) or not isinstance(lst, dict) or not isinstance(lst.get("lst"), bytes):
        return fail("; ".join([*problems, f"status_list (65533) is not {{bits, lst}}: {lst!r}"]), ex)
    try:
        raw = zlib.decompress(lst["lst"])
    except zlib.error:
        return fail("; ".join([*problems, "lst is not ZLIB data"]), ex)
    value = _status_entry(raw, idx, bits)
    if value is None:
        problems.append(f"idx {idx} out of bounds")
    elif value != 0:
        problems.append(f"fresh mdoc has status {value}, expected 0 (VALID)")
    hard = [p for p in problems if "RECOMMENDED" not in p]
    if hard:
        return fail("; ".join(problems), ex)
    # Without a certificate in the reference the list's chain goes up to the IACA (EAA-6.2.10.1-06.2), which the
    # probe is not given: the chain is checked, but not tied to a trust anchor.
    tied = "tied to the reference's certificate" if isinstance(anchor, bytes) else "no certificate to tie the chain to"
    return warn("; ".join(problems), ex) if problems else ok(f"idx {idx}, {bits} bit(s), {tied}", ex)


# -------------------------------------------------------------- deferred (M4)


def deferred_body(transaction_id: str) -> dict[str, Any]:
    return {"transaction_id": transaction_id}


def hold(ctx: Context) -> tuple[Token, str, Exchange] | Outcome:
    """A credential request the issuer holds: 202 with a transaction_id (OID4VCI 1.0 §8.3). The issuance is held by
    a login with the hold fields (the code flow), or by an offer the deferred offer command prints."""
    if not ctx.endpoint("deferred_credential_endpoint"):
        return skip("no deferred_credential_endpoint")
    token: Token | None
    config_id: str | None
    if ctx.config.hold_fields:
        tokens = ctx.code_tokens(extra=ctx.config.hold_fields)
        if isinstance(tokens, FlowFailure):
            return fail(f"the login that holds the issuance: {tokens.reason}", *tokens.steps)
        if isinstance(tokens, str):
            return skip(tokens)
        token, config_id = tokens.token, tokens.config_id
    elif ctx.config.deferred_offer_cmd:
        offer = ctx.fresh_offer(ctx.config.deferred_offer_cmd)
        config_id = ctx.target_config_id(offer)
        token = ctx.get_token(offer) if offer is not None else None
        if token is None or config_id is None:
            return skip("could not obtain an access token for the held offer; see notes")
    else:
        return skip("no way to have an issuance held (pass --hold-field or --deferred-offer-cmd)")
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    ex = ctx.credential_request(token, body, sent="held request")
    data = ex.json()
    if ex.status != 202 or not isinstance(data, dict) or not isinstance(data.get("transaction_id"), str):
        return fail(f"a held request answered {ex.status}, not 202 with a transaction_id", ex)
    return token, str(data["transaction_id"]), ex


def positive_number(value: Any) -> bool:
    """OID4VCI 1.0 §8.3: interval is a positive number of seconds, which may have a fraction."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value > 0


def wait_interval(ctx: Context, answer: Exchange, early: list[str]) -> None:
    """OID4VCI 1.0 §8.3: the wallet waits the interval of a 202 before it asks the deferred endpoint again. One
    longer than --deferred-wait-max is not waited out: the poll goes early, and the outcome says so."""
    data = answer.json()
    interval = data.get("interval") if isinstance(data, dict) else None
    if not positive_number(interval):
        return
    assert isinstance(interval, (int, float))
    if interval <= ctx.config.deferred_wait_max:
        ctx.sleep(interval)
    else:
        early.append(f"polled before the {interval} s interval (longer than --deferred-wait-max)")


def refused_early(early: list[str], detail: str, *ex: Exchange) -> Outcome:
    """A refusal of a poll sent before the interval is the probe's doing as much as the issuer's: a warning."""
    if early:
        return warn(f"{detail}; {'; '.join(early)}", *ex)
    return fail(detail, *ex)


@check("D01", "deferred", "OID4VCI 1.0 §9, §11, §12.2.4", "Deferred and notification endpoints, when listed, use https")
def d01(ctx: Context) -> Outcome:
    listed = {n: ctx.metadata.get(n) for n in ("deferred_credential_endpoint", "notification_endpoint")}
    present = {n: v for n, v in listed.items() if v is not None}
    if not present:
        return skip("neither endpoint is listed")
    bad = [f"{n}={v!r}" for n, v in present.items() if not isinstance(v, str) or not v.startswith("https://")]
    return fail("; ".join(bad), ctx.metadata_exchange) if bad else ok(", ".join(sorted(present)))


@check("D02", "deferred", "OID4VCI 1.0 §9.3", "Unknown transaction_id -> invalid_transaction_id")
def d02(ctx: Context) -> Outcome:
    if not ctx.endpoint("deferred_credential_endpoint"):
        return skip("no deferred_credential_endpoint")
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, _ = got
    unknown = deferred_body(f"probe-unknown-{secrets.token_hex(8)}")
    ex = ctx.credential_request(token, unknown, at="deferred_credential_endpoint", sent="unknown transaction_id")
    return expect_rejected(ex, statuses={400}, errors={"invalid_transaction_id"})


@check("D03", "deferred", "OID4VCI 1.0 §9; RFC 6750 §3", "Deferred endpoint without a token returns 401")
def d03(ctx: Context) -> Outcome:
    endpoint = ctx.endpoint("deferred_credential_endpoint")
    if not endpoint:
        return skip("no deferred_credential_endpoint")
    ex = ctx.http.request("POST", endpoint, json=deferred_body("probe"), sent="no token")
    if ex.status >= 500 or ex.status == 0:
        return fail("server error", ex)
    if ex.status != 401:
        return fail(f"status {ex.status}, expected 401", ex)
    return ok() if ex.header("www-authenticate") else warn("401 without WWW-Authenticate", ex)


@check(
    "D04",
    "deferred",
    "OID4VCI 1.0 §8.3, §9.1, §9.2",
    "A held issuance answers 202, stays pending, is collected once released, then the id is spent",
)
def d04(ctx: Context) -> Outcome:
    got = hold(ctx)
    if isinstance(got, Outcome):
        return got
    token, transaction_id, held = got
    first = held.json()
    problems = []
    interval = first.get("interval")
    if not positive_number(interval):
        problems.append(f"interval {interval!r} is not a positive number")
    if "credentials" in first:
        problems.append("the 202 answer carries credentials")
    if problems:
        return fail("; ".join(problems), held)
    early: list[str] = []
    wait_interval(ctx, held, early)
    pending = ctx.credential_request(
        token, deferred_body(transaction_id), at="deferred_credential_endpoint", sent="still held"
    )
    again = pending.json()
    if pending.status != 202 or not isinstance(again, dict) or again.get("transaction_id") != transaction_id:
        return refused_early(
            early, f"while held: {pending.status}, not 202 with the same transaction_id", held, pending
        )
    if not ctx.config.release_cmd:
        return ok("held and pending; collection not tried (pass --release-cmd)", held, pending)
    if not ctx.release_held():
        return Outcome(ERROR, "the release command failed; see notes")
    wait_interval(ctx, pending, early)  # the interval the last answer gave, which may have changed
    collected = ctx.credential_request(
        token, deferred_body(transaction_id), at="deferred_credential_endpoint", sent="released"
    )
    data = collected.json()
    if collected.status != 200 or not isinstance(data, dict) or not data.get("credentials"):
        detail = f"once released: {collected.status}, not 200 with credentials"
        return refused_early(early, detail, held, pending, collected)
    if "notification_id" in data and not isinstance(data["notification_id"], str):
        return fail("notification_id is not a string", collected)
    spent = ctx.credential_request(
        token, deferred_body(transaction_id), at="deferred_credential_endpoint", sent="collected already"
    )
    reuse = expect_rejected(spent, statuses={400}, errors={"invalid_transaction_id"})
    if reuse.status != PASS:
        return Outcome(reuse.status, f"after collection: {reuse.detail}", reuse.evidence)
    return ok(f"{len(data['credentials'])} credential(s) after release", held, collected, spent)


@check(
    "D05",
    "deferred",
    "OID4VCI 1.0 §9, §9.3",
    "A held issuance cannot be collected with another wallet's token",
    sensitive=True,
)
def d05(ctx: Context) -> Outcome:
    got = hold(ctx)
    if isinstance(got, Outcome):
        return got
    token, transaction_id, held = got
    other = fresh_token(ctx)
    if isinstance(other, Outcome):
        return other
    released = ctx.release_held()
    early: list[str] = []
    wait_interval(ctx, held, early)
    stranger = ctx.credential_request(
        other[0], deferred_body(transaction_id), at="deferred_credential_endpoint", sent="another wallet's token"
    )
    refused = expect_rejected(stranger, statuses={400}, errors={"invalid_transaction_id"})
    if refused.status == FAIL or stranger.status == 202:
        return fail(f"another wallet's token: {stranger.status}", held, stranger)
    if not released:
        return refused
    owner = ctx.credential_request(
        token, deferred_body(transaction_id), at="deferred_credential_endpoint", sent="the holder's token"
    )
    if owner.status != 200:
        detail = f"the holder could not collect after release ({owner.status})"
        return Outcome(ERROR, "; ".join([detail, *early]), [owner.evidence()])
    return refused


# ---------------------------------------------------------- notification (M4)


def fresh_notification(ctx: Context) -> tuple[Token, str] | Outcome:
    """A notification_id of an issuance of its own: the run's shared one may be spent by C15's notification, and an
    issuer may answer a spent id before it looks at the rest of the request."""
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    issued = ctx.credential_request(token, body, sent="issuance to notify about")
    data = issued.json()
    if issued.status != 200 or not isinstance(data, dict):
        return skip(f"no credential issued to notify about ({issued.status})")
    notification_id = data.get("notification_id")
    if not isinstance(notification_id, str):
        return skip("the issuance gave no notification_id")
    return token, notification_id


def notify(ctx: Context, token: Token, body: Any, label: str) -> Exchange:
    return ctx.credential_request(token, body, at="notification_endpoint", sent=label)


@check(
    "C17",
    "credential",
    "OID4VCI 1.0 §11, §11.3",
    "A notification_id cannot be used with another wallet's token",
    sensitive=True,
)
def c17(ctx: Context) -> Outcome:
    if not ctx.endpoint("notification_endpoint"):
        return skip("no notification_endpoint")
    got = fresh_notification(ctx)
    if isinstance(got, Outcome):
        return got
    token, notification_id = got
    other = fresh_token(ctx)
    if isinstance(other, Outcome):
        return other
    event = {"notification_id": notification_id, "event": "credential_accepted"}
    stranger = notify(ctx, other[0], event, "another wallet's token")
    refused = expect_rejected(stranger, statuses={400}, errors={"invalid_notification_id"})
    if refused.status == FAIL:  # the bypass is established: the holder's own notification changes nothing of it
        return refused
    owner = notify(ctx, token, event, "the holder's token")
    if owner.status // 100 != 2:
        return Outcome(ERROR, f"the holder's own notification was refused ({owner.status})", [owner.evidence()])
    return refused


@check(
    "C18",
    "credential",
    "OID4VCI 1.0 §11.1, §11.3",
    "Malformed notification requests -> invalid_notification_request",
)
def c18(ctx: Context) -> Outcome:
    if not ctx.endpoint("notification_endpoint"):
        return skip("no notification_endpoint")
    got = fresh_notification(ctx)
    if isinstance(got, Outcome):
        return got
    token, notification_id = got
    bodies = {
        "no event": {"notification_id": notification_id},
        'event_description with "': {
            "notification_id": notification_id,
            "event": "credential_failure",
            "event_description": 'quote " inside',
        },
        "event_description not ASCII": {
            "notification_id": notification_id,
            "event": "credential_failure",
            "event_description": "não guardada",
        },
        "event_description not a string": {
            "notification_id": notification_id,
            "event": "credential_failure",
            "event_description": 7,
        },
    }
    exchanges = [notify(ctx, token, body, label) for label, body in bodies.items()]
    outcomes = [expect_rejected(ex, statuses={400}, errors={"invalid_notification_request"}) for ex in exchanges]
    return gravest(outcomes) or ok(f"{len(bodies)} malformed requests refused", *exchanges)


# ------------------------------------------------------------ encryption (M4)

ENC_OURS = ("A128GCM", "A256GCM")


def encryption_blocks(ctx: Context) -> tuple[dict[str, Any], dict[str, Any]] | Outcome:
    request, response = (
        ctx.metadata.get(n) for n in ("credential_request_encryption", "credential_response_encryption")
    )
    if not isinstance(request, dict) or not isinstance(response, dict):
        return skip("the issuer does not take encrypted requests and send encrypted responses")
    return request, response


def issuer_key(request: dict[str, Any]) -> dict[str, Any] | None:
    """The first ECDH-ES EC key of credential_request_encryption.jwks the probe can encrypt to."""
    keys = (request.get("jwks") or {}).get("keys") if isinstance(request.get("jwks"), dict) else None
    for key in keys if isinstance(keys, list) else []:
        if isinstance(key, dict) and key.get("alg") == "ECDH-ES" and key.get("crv") in jwe.CURVES:
            return key
    return None


class Sealed:
    """An encrypted credential request (OID4VCI 1.0 §10) that asks for an encrypted response to a key of ours."""

    def __init__(self, ctx: Context, request: dict[str, Any], response: dict[str, Any], enc: str | None = None):
        self.key = EcKey.generate()
        self.kid = f"probe-{secrets.token_hex(4)}"
        self.target = issuer_key(request)
        self.request_enc = next((e for e in ENC_OURS if e in (request.get("enc_values_supported") or [])), None)
        self.response_enc = enc or next(
            (e for e in ENC_OURS if e in (response.get("enc_values_supported") or [])), None
        )

    def problem(self, response: dict[str, Any]) -> str | None:
        if self.target is None:
            return "credential_request_encryption lists no ECDH-ES EC key"
        if self.request_enc is None or self.response_enc is None:
            return f"none of {', '.join(ENC_OURS)} is supported both ways"
        if "ECDH-ES" not in (response.get("alg_values_supported") or []):
            return "ECDH-ES is not in alg_values_supported for responses"
        return None

    def params(self) -> dict[str, Any]:
        return {
            "jwk": {**self.key.public_jwk(), "alg": "ECDH-ES", "use": "enc", "kid": self.kid},
            "enc": self.response_enc,
        }

    def seal(self, body: dict[str, Any]) -> bytes:
        assert self.target is not None and self.request_enc is not None
        plain = json.dumps(body).encode()
        return jwe.encrypt(plain, self.target, self.request_enc, kid=self.target.get("kid")).encode("ascii")


@check(
    "E01",
    "encryption",
    "OID4VCI 1.0 §10, §12.2.4",
    "credential_request_encryption and credential_response_encryption are well-formed",
)
def e01(ctx: Context) -> Outcome:
    request, response = (
        ctx.metadata.get(n) for n in ("credential_request_encryption", "credential_response_encryption")
    )
    if request is None and response is None:
        return skip("no encryption advertised")
    problems = []

    def strings(block: dict[str, Any], name: str) -> None:
        value = block.get(name)
        if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
            problems.append(f"{name} is not a non-empty array of strings")

    for name, block in (("credential_request_encryption", request), ("credential_response_encryption", response)):
        if block is None:
            continue
        if not isinstance(block, dict):
            problems.append(f"{name} is not an object")
            continue
        if not isinstance(block.get("encryption_required"), bool):
            problems.append(f"{name}.encryption_required is not a boolean")
        strings(block, "enc_values_supported")
        if "zip_values_supported" in block:
            strings(block, "zip_values_supported")
    if isinstance(response, dict):
        strings(response, "alg_values_supported")
    if isinstance(request, dict):
        keys = (request.get("jwks") or {}).get("keys") if isinstance(request.get("jwks"), dict) else None
        if not isinstance(keys, list) or not keys:
            problems.append("credential_request_encryption.jwks has no keys")
        else:
            kids = [k.get("kid") if isinstance(k, dict) else None for k in keys]
            if not all(isinstance(k, str) and k for k in kids) or len(set(kids)) != len(kids):
                problems.append("each key of jwks needs a kid of its own (§12.2.4)")
            if not all(isinstance(k, dict) and isinstance(k.get("alg"), str) for k in keys):
                problems.append("each key of jwks needs alg (§10)")
            if any(isinstance(k, dict) and "d" in k for k in keys):
                problems.append("jwks carries a private key")
    if response is not None and request is None:
        problems.append("encrypted responses without encrypted requests: §8.2 lets no wallet ask for one")
    return fail("; ".join(problems), ctx.metadata_exchange) if problems else ok()


@check(
    "E02",
    "encryption",
    "OID4VCI 1.0 §8.2, §8.3, §10",
    "An encrypted request gets an encrypted response to the wallet's key",
)
def e02(ctx: Context) -> Outcome:
    blocks = encryption_blocks(ctx)
    if isinstance(blocks, Outcome):
        return blocks
    request, response = blocks
    sealed = Sealed(ctx, request, response)
    if (reason := sealed.problem(response)) is not None:
        return skip(reason)
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = with_identifier(token, credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())]))
    body["credential_response_encryption"] = sealed.params()
    ex = ctx.credential_request(token, None, raw=sealed.seal(body), content_type="application/jwt", sent="encrypted")
    if ex.status != 200:
        return fail(f"encrypted request answered {ex.status}", ex)
    problems = []
    if not ex.header("content-type").startswith("application/jwt"):
        problems.append(f"Content-Type={ex.header('content-type')!r}, not application/jwt")
    try:
        opened = jwe.decrypt(ex.body, sealed.key)
        data = opened.json()
    except (ValueError, KeyError) as exc:
        return fail("; ".join([*problems, f"the response does not open with our key: {exc}"]), ex)
    if opened.header.get("kid") != sealed.kid:
        problems.append(f"kid {opened.header.get('kid')!r}, not the one our jwk named (§10)")
    if opened.header.get("enc") != sealed.response_enc:
        problems.append(f"enc {opened.header.get('enc')!r}, not the {sealed.response_enc} asked for")
    if not isinstance(data, dict) or not data.get("credentials"):
        problems.append("the decrypted response has no credentials")
    return fail("; ".join(problems), ex) if problems else ok(f"{sealed.request_enc} in, {sealed.response_enc} out", ex)


@check(
    "E03",
    "encryption",
    "OID4VCI 1.0 §8.2, §8.3.1.2",
    "An enc the issuer does not support -> invalid_encryption_parameters",
)
def e03(ctx: Context) -> Outcome:
    blocks = encryption_blocks(ctx)
    if isinstance(blocks, Outcome):
        return blocks
    request, response = blocks
    supported = response.get("enc_values_supported") or []
    unsupported = next(e for e in ("A128CBC-HS256", "A192GCM", "A256CBC-HS512", "probe-enc") if e not in supported)
    sealed = Sealed(ctx, request, response)
    if (reason := sealed.problem(response)) is not None:
        return skip(reason)
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = with_identifier(token, credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())]))
    body["credential_response_encryption"] = {**sealed.params(), "enc": unsupported}
    ex = ctx.credential_request(token, None, raw=sealed.seal(body), content_type="application/jwt", sent=unsupported)
    return expect_rejected(ex, statuses={400}, errors={"invalid_encryption_parameters"})


@check(
    "E04",
    "encryption",
    "OID4VCI 1.0 §8.2 (request encryption MUST be used with credential_response_encryption)",
    "credential_response_encryption in a plain request is refused",
    sensitive=True,
)
def e04(ctx: Context) -> Outcome:
    blocks = encryption_blocks(ctx)
    if isinstance(blocks, Outcome):
        return blocks
    request, response = blocks
    sealed = Sealed(ctx, request, response)
    if (reason := sealed.problem(response)) is not None:
        return skip(reason)
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())])
    body["credential_response_encryption"] = sealed.params()
    ex = ctx.credential_request(token, body, sent="an attacker's key in a plain request", plain=True)
    return expect_rejected(ex, statuses={400}, errors={"invalid_encryption_parameters"})


@check(
    "E05",
    "encryption",
    "OID4VCI 1.0 §10; RFC 7516 §5.2",
    "An encrypted request that does not decrypt is refused",
    sensitive=True,
)
def e05(ctx: Context) -> Outcome:
    blocks = encryption_blocks(ctx)
    if isinstance(blocks, Outcome):
        return blocks
    request, response = blocks
    sealed = Sealed(ctx, request, response)
    if (reason := sealed.problem(response)) is not None:
        return skip(reason)
    got = fresh_token(ctx)
    if isinstance(got, Outcome):
        return got
    token, config_id = got
    body = with_identifier(token, credential_body(ctx, config_id, [ctx.proof_for(EcKey.generate(), ctx.c_nonce())]))
    # The request E02 sends: only its changed tag is wrong, so no other refusal can hide a JWE taken unopened.
    body["credential_response_encryption"] = sealed.params()
    parts = sealed.seal(body).decode("ascii").split(".")
    tag = b64u_decode(parts[4])
    parts[4] = b64u(bytes([tag[0] ^ 1]) + tag[1:])
    ex = ctx.credential_request(
        token, None, raw=".".join(parts).encode("ascii"), content_type="application/jwt", sent="tag changed"
    )
    return expect_rejected(ex, statuses={400}, errors={"invalid_credential_request", "invalid_encryption_parameters"})
