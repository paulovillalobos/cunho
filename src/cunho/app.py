"""HTTP layer. Requests are parsed by hand so that no client input can reach an unhandled exception."""

from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import logging
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, TypeVar
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from cunho import metadata
from cunho.authorize import LOGIN_STATE
from cunho.errors import IssuerError
from cunho.jose import strict_json
from cunho.oauth import DPOP_ALGS
from cunho.rules import implements, refuse
from cunho.service import ADMIN_ROUTES, Issuer, Reply
from cunho.settings import Settings
from cunho.signed_metadata import wants_jwt

MAX_BODY = 256 * 1024
CONTENT_LENGTH = re.compile(r"[0-9]{1,12}")
NO_STORE = {"Cache-Control": "no-store"}
SIGNER_CERTIFICATE_PATH = "/certs/signer.pem"
MDOC_SIGNER_CERTIFICATE_PATH = "/certs/mdoc-signer.pem"
log = logging.getLogger("cunho")
refusals = logging.getLogger("cunho.refusals")
# The discovery documents a wallet may look for (RFC 8414, RFC 9728, OpenID Connect, OpenID4VCI, SD-JWT VC).
_DISCOVERY = frozenset(
    {
        "openid-credential-issuer",
        "oauth-authorization-server",
        "openid-configuration",
        "oauth-protected-resource",
        "jwt-vc-issuer",
    }
)


def _printable(text: str, limit: int = 300) -> str:
    """A value from a request, fit for one log line: no control characters (no forged lines), and bounded."""
    clean = "".join(c if c.isprintable() else "?" for c in text)
    return clean if len(clean) <= limit else clean[:limit] + "…"


T = TypeVar("T")
# RFC 6749 §5.2 and RFC 6750 §3: error_description is limited to %x20-21 / %x23-5B / %x5D-7E.
SAFE_TEXT = frozenset(chr(c) for c in range(0x20, 0x7F)) - {'"', "\\"}


def safe_text(value: str, limit: int = 300) -> str:
    """Error text as RFC 6750 allows it, so no client input can make a response header unencodable."""
    return "".join(c if c in SAFE_TEXT else "?" for c in value[:limit])


def error_response(exc: IssuerError) -> JSONResponse:
    headers = {**NO_STORE, **exc.headers}
    description = safe_text(exc.description)
    if exc.scheme:
        parts = [] if exc.bare_challenge else [f'error="{safe_text(exc.error)}"', f'error_description="{description}"']
        if exc.scheme == "DPoP":
            parts.append(f'algs="{DPOP_ALGS}"')
        headers["WWW-Authenticate"] = f"{exc.scheme} " + ", ".join(parts) if parts else exc.scheme
    return JSONResponse({"error": exc.error, "error_description": description}, exc.status, headers)


def client_bucket(host: str | None, *, v4_prefix: int = 32, v6_prefix: int = 64) -> str:
    """The client's network: one IPv4 address, or one IPv6 /64, which a single host usually holds whole."""
    try:
        address = ipaddress.ip_address(host or "")
    except ValueError:
        return "unknown"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    prefix = v4_prefix if address.version == 4 else v6_prefix
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


class RateLimiter:
    """A sliding one-minute window per client, kept in memory and bounded in size.

    Each client costs three numbers, not one timestamp per request (review 3, N3-L3): the count in the
    current minute, the count in the minute before, and which minute that is. The window estimate is the
    current count plus the previous count weighted by how much of the previous minute is still inside
    the last 60 seconds. When the table is full, the client seen least recently is dropped to make room,
    so a full table never refuses a newcomer (review 2, N-M5).
    """

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic, max_clients: int = 100_000):
        self._per_minute = per_minute
        self._clock = clock
        self._max_clients = max_clients
        self._hits: OrderedDict[str, tuple[int, int, int]] = OrderedDict()  # minute, count, previous count
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        minute = int(now // 60)
        with self._lock:
            entry = self._hits.get(key)
            if entry is None:
                while len(self._hits) >= self._max_clients:
                    self._hits.popitem(last=False)
                count, previous = 0, 0
            else:
                self._hits.move_to_end(key)
                seen, count, previous = entry
                if seen != minute:
                    count, previous = 0, (count if seen == minute - 1 else 0)
            weight = 1 - (now - minute * 60) / 60
            allowed = count + previous * weight < self._per_minute
            self._hits[key] = (minute, count + allowed, previous)
            return allowed

    def __len__(self) -> int:
        return len(self._hits)


async def _body(request: Request, rule: str, error: str = "invalid_request") -> bytes:
    """Read the body, refusing once it passes MAX_BODY, whether or not Content-Length was sent."""
    declared = request.headers.get("content-length")
    # At most 12 ASCII digits before int(): a digit like "²" or a 5000-digit value would otherwise raise
    # inside int() (review 3, N3-M1).
    if declared is not None and (not CONTENT_LENGTH.fullmatch(declared) or int(declared) > MAX_BODY):
        refuse(rule, error, "request body too large")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY:
            refuse(rule, error, "request body too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _media_type(request: Request) -> str:
    return request.headers.get("content-type", "").split(";", 1)[0].strip().lower()


# The credential and deferred credential endpoints take a request as JSON or, encrypted, as a JWE (OpenID4VCI 1.0
# §10); the notification endpoint as JSON only.
ENCRYPTABLE = frozenset({"application/json", "application/jwt"})
JSON_ONLY = frozenset({"application/json"})
STATUS_FORMS = {"application/statuslist+jwt": "jwt", "application/statuslist+cwt": "cwt"}


def _status_form(accept: str | None) -> str:
    """The status list form a client asks for in Accept (draft-ietf-oauth-status-list-21 §8.1): the CWT when it
    weighs application/statuslist+cwt above application/statuslist+jwt, the JWT otherwise, as before there was a
    choice."""
    weights = {"jwt": 0.0, "cwt": 0.0}
    for part in (accept or "").split(","):
        media, *params = (piece.strip() for piece in part.split(";"))
        form = STATUS_FORMS.get(media.lower())
        if form is None:
            continue
        weight = 1.0
        for param in params:
            name, _, value = param.partition("=")
            if name.strip().lower() == "q":
                try:
                    weight = float(value)
                except ValueError:
                    weight = 0.0
        weights[form] = max(weights[form], weight if 0.0 <= weight <= 1.0 else 0.0)
    return "cwt" if weights["cwt"] > weights["jwt"] else "jwt"


def _json(raw: bytes) -> Any:
    try:
        return strict_json(raw)
    except (ValueError, UnicodeDecodeError):
        return None


@implements(
    "MDOC.NO_SERVER_RETRIEVAL",
    "PRIV.STATUS_LIST_UNAUTHENTICATED",
    "HTTP.METHOD_NOT_ALLOWED",
    "VCI.META.WELL_KNOWN_PATH",
    "STATUS.TSL.MEDIA_TYPE",
)
def create_app(
    settings: Settings | None = None, *, issuer: Issuer | None = None, background_maintenance: bool = True
) -> FastAPI:
    """Routes are exactly those below; there is no ISO 18013-5 server-retrieval endpoint."""
    issuer = issuer or Issuer(settings or Settings.from_env())
    settings = issuer.settings
    base = metadata.base_path(settings)

    async def maintenance_loop() -> None:
        """Maintenance off the request path (review 2, N-M7): checked about once a minute, run per interval.

        Expired state is swept on every tick, in short batches, so it stays bounded by about a minute of
        traffic without any request paying for the sweep (review 3, N3-L2).
        """
        tick = min(60, settings.maintenance_interval)
        while True:
            await asyncio.sleep(tick * (0.5 + secrets.randbelow(1000) / 2000))
            try:
                await run_in_threadpool(issuer.sweep)
                await run_in_threadpool(issuer.maintenance)
                # On its own interval, not maintenance's: the check must never be more than a day apart (LC_GEN-4).
                await run_in_threadpool(issuer.chain)
            except Exception:  # noqa: BLE001 - keep the loop alive; the next run retries
                log.exception("maintenance failed")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(maintenance_loop()) if background_maintenance else None
        try:
            yield
        finally:
            if task is not None:
                task.cancel()

    # No redirect of the framework's own: by default a path with a slash too many is answered 307 to the path
    # without it, at a Location made from the request's Host header, which tells a client to send its token request
    # again, body and all (OAUTH.REDIRECT_303: never a 307). Such a path is not found (the security review).
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan, redirect_slashes=False)
    # Anonymous traffic is limited per client network and route group, each group in its own table; an
    # authenticated operator by name, with its own budget, so a burst of wallet traffic from one address
    # (or a proxy) never locks the operator out.
    groups = ("token", "nonce", "credential", "admin", "par", "authorize")
    limiters = {group: RateLimiter(settings.rate_limit_per_minute) for group in groups}
    # Relying parties poll status lists; a verifier behind one address may check many credentials, so the
    # group has its own, larger budget (review 5, N5-M3).
    limiters["status"] = RateLimiter(settings.status_rate_limit_per_minute)
    operator_limiter = RateLimiter(settings.operator_rate_limit_per_minute)

    async def work(fn: Callable[..., T], *args: Any) -> T:
        return await run_in_threadpool(fn, *args)

    def too_many() -> StarletteHTTPException:
        return StarletteHTTPException(429, "too many requests", headers={"Retry-After": "60"})

    def limit(request: Request, group: str) -> None:
        if not limiters[group].allow(client_bucket(request.client.host if request.client else None)):
            raise too_many()

    def refused(request: Request, status: int, error: str, rule: str) -> None:
        """With log_refusals on, why a request was refused, and nothing of who sent it: the route as cunho declares
        it (an unknown path only by the name of a discovery document), the status, the error code and the rule.
        Never the address, a header, a token, the body, or the error's description, which may repeat what the
        request sent (the second reviewer). The path is read from the scope: request.url decodes the query, which
        may not be UTF-8 (the second reviewer)."""
        if not settings.log_refusals:
            return
        route = getattr(request.scope.get("route"), "path", None)
        if route is None:
            # A path no route matched may carry a login state or a subject reference (the second reviewer); only the
            # name of a known discovery document is kept, without what follows it, as it tells what a wallet looked for.
            route = "(no route)"
            parts = str(request.scope.get("path", "")).split("/")
            if len(parts) > 2 and parts[1] == ".well-known" and parts[2] in _DISCOVERY:
                route = f"/.well-known/{parts[2]}" + ("/…" if len(parts) > 3 else "")
        refusals.warning(
            "refused %s %s: %d %s [%s]",
            request.method,
            _printable(route, 120),
            status,
            _printable(error, 60),
            _printable(rule, 120),
        )

    @app.exception_handler(IssuerError)
    async def on_issuer_error(request: Request, exc: IssuerError) -> JSONResponse:
        refused(request, exc.status, exc.error, exc.rule)
        return error_response(exc)

    @app.exception_handler(StarletteHTTPException)
    async def on_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        refused(request, exc.status_code, {404: "not_found"}.get(exc.status_code, "invalid_request"), "http")
        # 429 has no OAuth error code of its own; "slow_down" belongs to the device flow (review 3, N3-L3).
        error = {404: "not_found"}.get(exc.status_code, "invalid_request")
        headers = {**NO_STORE, **(exc.headers or {})}
        return JSONResponse({"error": error, "error_description": str(exc.detail)}, exc.status_code, headers)

    @app.exception_handler(Exception)
    async def on_bug(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return JSONResponse({"error": "server_error", "error_description": "internal error"}, 500, NO_STORE)

    @app.get(metadata.well_known_path(settings, "openid-credential-issuer"), response_model=None)
    async def issuer_metadata(request: Request) -> Response:
        """JSON, always; the signed form when the client prefers application/jwt and an access signer is configured,
        which production requires (OpenID4VCI §12.2.2, §12.2.3)."""
        if wants_jwt(request.headers.get("accept")):
            signed = await work(issuer.signed_issuer_metadata)
            if signed is not None:
                return Response(signed, media_type="application/jwt", headers={"Vary": "Accept"})
        return JSONResponse(issuer.issuer_metadata(), headers={"Vary": "Accept"})

    @app.get(metadata.well_known_path(settings, "oauth-authorization-server"))
    async def as_metadata() -> JSONResponse:
        return JSONResponse(issuer.as_metadata())

    if settings.appended_well_known and metadata.base_path(settings).strip("/"):
        # Wallets that append the well-known segment to the issuer's path instead of inserting it (§12.2.2) find the
        # same documents there (docs/operations.md).
        appended = f"{metadata.base_path(settings).rstrip('/')}/.well-known"
        app.add_api_route(f"{appended}/openid-credential-issuer", issuer_metadata, methods=["GET"], response_model=None)
        app.add_api_route(f"{appended}/oauth-authorization-server", as_metadata, methods=["GET"])

    async def form_of(request: Request, rule: str) -> dict[str, list[str]]:
        raw = await _body(request, rule)
        if _media_type(request) != "application/x-www-form-urlencoded":
            refuse(rule, "invalid_request", "use application/x-www-form-urlencoded")
        try:
            return parse_qs(raw.decode("utf-8", errors="strict"), keep_blank_values=True, strict_parsing=False)
        except UnicodeDecodeError:
            refuse(rule, "invalid_request", "the form is not UTF-8")

    def query_of(request: Request) -> dict[str, list[str]]:
        """The query as the server handed it over, a byte a character: `request.url` reads it as UTF-8 and raises
        on bytes that are not, before any of cunho's own checks (the security review). A value no route expects is
        then refused by that route."""
        raw: bytes = request.scope.get("query_string", b"")
        return parse_qs(raw.decode("latin-1"), keep_blank_values=True, strict_parsing=False)

    def see_other(location: str) -> RedirectResponse:
        """FAPI 2.0 §5.3.2.2: never 307, which would forward a login form's fields; 303 after a form POST."""
        return RedirectResponse(location, 303, headers=NO_STORE)

    @app.post(f"{base}/token")
    async def token(request: Request) -> JSONResponse:
        limit(request, "token")
        form = await form_of(request, "OAUTH.TOKEN_ERROR_BODY")
        body, headers = await work(issuer.token, form, request.headers.getlist("dpop"), request.headers.getlist)
        return JSONResponse(body, headers=headers)

    @app.post(f"{base}/par")
    async def par(request: Request) -> JSONResponse:
        limit(request, "par")
        form = await form_of(request, "OAUTH.PAR_REQUEST")
        body, headers = await work(issuer.par, form, request.headers.getlist)
        return JSONResponse(body, 201, headers)

    @app.get(f"{base}/authorize")
    async def authorize(request: Request) -> RedirectResponse:
        limit(request, "authorize")
        return see_other(await work(issuer.authorize, query_of(request)))

    @app.get(f"{base}/authorize/continue")
    async def resume(request: Request) -> RedirectResponse:
        limit(request, "authorize")
        return see_other(await work(issuer.resume, query_of(request)))

    @app.post(f"{base}/nonce")
    async def nonce(request: Request) -> JSONResponse:
        limit(request, "nonce")
        body, headers = await work(issuer.nonce)
        return JSONResponse(body, headers=headers)

    @app.post(f"{base}/credential")
    async def credential(request: Request) -> Response:
        """Rate-limited like the other public routes: a request may carry 256 KiB and, with a token, costs a
        certificate path and CRL check per proof (review 7, L7)."""
        limit(request, "credential")
        if "access_token" in request.query_params:
            refuse("OAUTH.NO_TOKEN_IN_QUERY", "invalid_request", "send the access token in the Authorization header")
        raw = await _body(request, "VCI.CRED.ERROR_CODES", "invalid_credential_request")
        authorization = request.headers.get("authorization")
        dpop = request.headers.getlist("dpop")
        media = _media_type(request)
        if media not in ENCRYPTABLE:
            await work(issuer.tokens.authorize, authorization, dpop, "POST", settings.credential_endpoint)
            refuse("VCI.CRED.ERROR_CODES", "invalid_credential_request", "use application/json or application/jwt")
        return _answer(await work(issuer.credential, authorization, dpop, raw, media))

    def _answer(reply: Reply) -> Response:
        """200 with credentials, or 202 with a transaction_id while the issuance waits (OpenID4VCI 1.0 §8.3, §9.2):
        as JSON, or as the JWE of it when the wallet asked for an encrypted response (§10)."""
        if reply.jwe is not None:
            return Response(reply.jwe, reply.status, NO_STORE, media_type="application/jwt")
        return JSONResponse(reply.body, reply.status, NO_STORE)

    async def _wallet_post(
        request: Request, rule: str, error: str, url: str, media_types: frozenset[str]
    ) -> tuple[str | None, list[str], bytes, str]:
        """What the deferred and notification endpoints read, checked as the credential endpoint checks it."""
        limit(request, "credential")
        if "access_token" in request.query_params:
            refuse("OAUTH.NO_TOKEN_IN_QUERY", "invalid_request", "send the access token in the Authorization header")
        raw = await _body(request, rule, error)
        authorization = request.headers.get("authorization")
        dpop = request.headers.getlist("dpop")
        media = _media_type(request)
        if media not in media_types:
            await work(issuer.tokens.authorize, authorization, dpop, "POST", url)
            refuse(rule, error, f"use {' or '.join(sorted(media_types))}")
        return authorization, dpop, raw, media

    @app.post(f"{base}/deferred_credential")
    async def deferred_credential(request: Request) -> Response:
        url = settings.deferred_credential_endpoint
        authorization, dpop, raw, media = await _wallet_post(
            request, "VCI.DEFER.TRANSACTION_ID", "invalid_credential_request", url, ENCRYPTABLE
        )
        return _answer(await work(issuer.deferred_credential, authorization, dpop, raw, media))

    @app.post(f"{base}/notification")
    async def notification(request: Request) -> Response:
        url = settings.notification_endpoint
        authorization, dpop, raw, _ = await _wallet_post(
            request, "VCI.NOTIF.VALIDATION", "invalid_notification_request", url, JSON_ONLY
        )
        await work(issuer.notification, authorization, dpop, raw)
        return Response(status_code=204, headers=NO_STORE)

    @app.get(f"{base}/status/{{list_id}}")
    async def status(request: Request, list_id: str) -> Response:
        """Rate-limited like every public route. A token this worker already signed for the current publication
        is answered without signing again. All of it runs in the thread pool, never on the event loop, where a
        store call waiting for another worker's lock would stall every request (review 5, N5-L3): even the
        cached token, since the publication goes by the time, which reads the clock base in the store (the
        second reviewer, CX-14).
        """
        limit(request, "status")
        if not list_id.isdecimal() or not list_id.isascii():
            raise StarletteHTTPException(404, "unknown status list")
        form = _status_form(request.headers.get("accept"))
        token = await work(issuer.status_cwt if form == "cwt" else issuer.status_token, list_id)
        if token is None:
            raise StarletteHTTPException(404, "unknown status list")
        return Response(
            token,
            media_type=f"application/statuslist+{form}",
            # One URI, two forms: a cache keeps them apart by Accept (RFC 9110 §12.5.5).
            headers={"Cache-Control": f"max-age={settings.status_token_ttl}", "Vary": "Accept"},
        )

    async def admin(request: Request) -> str:
        """Authenticate first: operators get their own limit, failed attempts the anonymous one."""
        authorization = request.headers.get("authorization")
        operator = issuer.operator(authorization)
        if operator is not None:
            if not operator_limiter.allow(f"operator:{operator}"):
                raise too_many()
        else:
            limit(request, "admin")
            route = getattr(request.scope.get("route"), "path", "")
            route = route[len(base) :] if base and route.startswith(base) else route
            host = request.client.host if request.client else None
            await work(  # it counts by the time, which reads the store (CX-14)
                issuer.admin_refused,
                route if route in ADMIN_ROUTES else "other",
                client_bucket(host, v4_prefix=24, v6_prefix=48),
                bool(authorization),
            )
            raise IssuerError(
                "ISS.SUBJECT.ENTITLEMENT",
                "invalid_token",
                "operator authentication required",
                401,
                scheme="Bearer",
                bare_challenge=not authorization,
            )
        return operator

    @app.post(f"{base}/admin/offers")
    async def create_offer(request: Request) -> JSONResponse:
        operator = await admin(request)
        body = _json(await _body(request, "ISS.SUBJECT.ENTITLEMENT"))
        return JSONResponse(await work(issuer.create_offer, body, operator), 201, NO_STORE)

    @app.get(f"{base}/admin/offers/{{subject_ref}}")
    async def offer_progress(request: Request, subject_ref: str) -> JSONResponse:
        """How far a subject has got, for the operator's own pages; no subject data."""
        await admin(request)
        return JSONResponse(await work(issuer.subject_progress, subject_ref), headers=NO_STORE)

    @app.get(f"{base}/admin/logins/{{login_state}}")
    async def pending_login(request: Request, login_state: str) -> JSONResponse:
        """What a login waiting for its result is for, so the login service can ask the person's consent."""
        await admin(request)
        return JSONResponse(await work(issuer.pending_login, login_state), headers=NO_STORE)

    @app.post(f"{base}/admin/logins/{{login_state}}")
    async def login_result(request: Request, login_state: str) -> JSONResponse:
        """The operator's login service reports who logged in, or that the login was denied."""
        operator = await admin(request)
        body = _json(await _body(request, "ISS.SUBJECT.ENTITLEMENT"))
        return JSONResponse(await work(issuer.complete_login, login_state, body, operator), headers=NO_STORE)

    if issuer.test_persons:

        @app.get(f"{base}/test-login")
        async def test_login_page(request: Request) -> HTMLResponse:
            """A login for tests only: pick a fixture person, or cancel. Production refuses to start with it."""
            limit(request, "authorize")
            state = html.escape(query_of(request).get(LOGIN_STATE, [""])[0])
            options = "".join(
                f'<option value="{html.escape(p)}">{html.escape(p)}</option>' for p in sorted(issuer.test_persons)
            )
            page = (
                "<!doctype html><title>cunho test login</title><h1>Test login</h1>"
                f'<form method="post" action="{base}/test-login">'
                f'<input type="hidden" name="{LOGIN_STATE}" value="{state}">'
                f'<select name="person">{options}</select>'
                '<label><input type="checkbox" name="review" value="true"> hold for review</label>'
                '<button type="submit" id="login" name="action" value="login">Log in</button>'
                '<button type="submit" id="cancel" name="action" value="cancel">Cancel</button></form>'
            )
            return HTMLResponse(page, headers=NO_STORE)

        @app.post(f"{base}/test-login")
        async def test_login(request: Request) -> RedirectResponse:
            limit(request, "authorize")
            form = await form_of(request, "ISS.SUBJECT.ENTITLEMENT")

            def value(name: str) -> str:
                return (form.get(name) or [""])[0]

            login_state, person = value(LOGIN_STATE), value("person")
            if value("action") == "cancel":
                body: dict[str, Any] = {"denied": True}
            elif person in issuer.test_persons:
                body = {"subject": issuer.test_persons[person], "loa": "high"}
                if value("review") == "true":  # the operator holds the credentials for review (deferred issuance)
                    body["review"] = True
            else:
                refuse("ISS.SUBJECT.ENTITLEMENT", "invalid_request", "pick one of the test persons")
            result = await work(issuer.complete_login, login_state, body, "test-login")
            return see_other(result["continue"])

    @app.get(f"{base}/admin/deferred")
    async def deferred_issuances(request: Request) -> JSONResponse:
        await admin(request)
        return JSONResponse(await work(issuer.deferred_issuances), headers=NO_STORE)

    @app.post(f"{base}/admin/deferred/{{ref}}/release")
    async def release_deferred(request: Request, ref: str) -> JSONResponse:
        operator = await admin(request)
        return JSONResponse(await work(issuer.decide_deferred, ref, "release", operator), headers=NO_STORE)

    @app.post(f"{base}/admin/deferred/{{ref}}/refuse")
    async def refuse_deferred(request: Request, ref: str) -> JSONResponse:
        operator = await admin(request)
        return JSONResponse(await work(issuer.decide_deferred, ref, "refuse", operator), headers=NO_STORE)

    @app.post(f"{base}/admin/offers/{{subject_ref}}/cancel")
    async def cancel_offer(request: Request, subject_ref: str) -> JSONResponse:
        operator = await admin(request)
        return JSONResponse(await work(issuer.cancel_offer, subject_ref, operator), headers=NO_STORE)

    @app.post(f"{base}/admin/revocations")
    async def revoke(request: Request) -> JSONResponse:
        operator = await admin(request)
        body = _json(await _body(request, "STATUS.MONOTONIC"))
        return JSONResponse(await work(issuer.revoke, body, operator), headers=NO_STORE)

    @app.post(f"{base}/admin/subjects/{{subject_ref}}/erase")
    async def erase(request: Request, subject_ref: str) -> Response:
        operator = await admin(request)
        await work(issuer.erase_subject, subject_ref, operator)
        return Response(status_code=204)

    @app.api_route(f"{base}/admin/audit/verify", methods=["GET", "POST"])
    async def audit_verify(request: Request) -> JSONResponse:
        """GET checks the chain against the anchor; POST {"signed_head": ...} also against a pulled head."""
        await admin(request)
        signed_head = None
        if request.method == "POST":
            body = _json(await _body(request, "ISS.SUBJECT.ENTITLEMENT"))
            if not isinstance(body, dict) or not isinstance(body.get("signed_head"), str):
                refuse("ISS.SUBJECT.ENTITLEMENT", "invalid_request", "send {signed_head: <JWS from /admin/audit/head>}")
            signed_head = body["signed_head"]
        ok, detail = await work(issuer.audit_verify, signed_head)
        return JSONResponse({"valid": ok, "detail": detail}, headers=NO_STORE)

    @app.get(f"{base}/admin/audit/head")
    async def audit_head(request: Request) -> Response:
        await admin(request)
        return Response(await work(issuer.audit_head), media_type="application/jwt", headers=NO_STORE)

    if issuer.signers.mdoc is not None and (
        settings.mdoc_signer_certificate_url == f"{settings.issuer_url}{MDOC_SIGNER_CERTIFICATE_PATH}"
    ):
        mdoc_chain_pem = "".join(_pem(der) for der in issuer.signers.mdoc.x5c())

        @app.get(f"{base}{MDOC_SIGNER_CERTIFICATE_PATH}")
        async def mdoc_signer_certificate() -> Response:
            """The x5u resource of the mdoc issuerAuth (RFC 9360 §2): the document signer certificate x5t names."""
            return Response(mdoc_chain_pem, media_type="application/pem-certificate-chain")

    if settings.signer_certificate_url == f"{settings.issuer_url}{SIGNER_CERTIFICATE_PATH}":
        chain_pem = "".join(_pem(der) for der in issuer.signers.credentials.x5c())

        @app.get(f"{base}{SIGNER_CERTIFICATE_PATH}")
        async def signer_certificate() -> Response:
            """The x5u resource (RFC 7515 §4.1.5): the signer certificate chain the x5t#S256 header names."""
            return Response(chain_pem, media_type="application/pem-certificate-chain")

    return app


def _pem(der_b64: str) -> str:
    body = base64.b64encode(base64.b64decode(der_b64)).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
