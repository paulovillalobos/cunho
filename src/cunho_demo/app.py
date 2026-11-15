"""The demo service: the page's API, the login screens of the authorization code flow, and the operator console.

Run with `uvicorn --factory cunho_demo.app:create_app`. The visitor's browser talks only to this service; this
service talks to the two cunho instances through their admin APIs."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import logging
import random
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import segno
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from cunho.app import RateLimiter, client_bucket
from cunho_demo.client import Cunho, CunhoError
from cunho_demo.console import console_routes
from cunho_demo.offers import CREDENTIALS, FLOWS, FORMATS, card, configurations, load_personas, step, subject
from cunho_demo.screens import login_routes
from cunho_demo.sessions import Session, Sessions
from cunho_demo.settings import DemoSettings, IssuerLink
from cunho_demo.wallet import Activity, DemoWallet, KeyAttester, Route

log = logging.getLogger("cunho_demo")
STATIC = Path(__file__).with_name("static")
MAX_BODY = 4096
MAX_WALLETS = 8  # demo wallet runs at once; past that a visitor is asked to try again in a minute
NO_STORE = {"Cache-Control": "no-store"}
# The page loads nothing from anywhere else, and no other site may frame it.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
        "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    # same-origin, not no-referrer: under no-referrer browsers send "Origin: null" with a form's POST, which the
    # origin checks then refuse; same-origin still keeps the login's URL from every other site.
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


class DemoError(Exception):
    def __init__(self, status: int, error: str, message: str) -> None:
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


def qr_svg(text: str) -> str:
    """The QR code of an offer as inline SVG, sized by the page (a viewBox only), with a quiet zone of four."""
    code = segno.make(text, error="m", micro=False)
    return str(code.svg_inline(scale=1, border=4, dark="#000", light="#fff", omitsize=True, title="QR code"))


def offer_in(link: str) -> dict[str, Any]:
    """The credential offer a by-value link (openid-credential-offer://?credential_offer=...) carries."""
    offer: dict[str, Any] = json.loads(parse_qs(urlsplit(link).query)["credential_offer"][0])
    return offer


def route(link: IssuerLink, transport: httpx.AsyncBaseTransport | None) -> Route:
    verify: Any = ssl.create_default_context(cafile=str(link.ca_file)) if link.ca_file else True
    return Route(link.url.rstrip("/"), transport, verify)


def create_app(
    settings: DemoSettings | None = None,
    *,
    transports: dict[str, httpx.AsyncBaseTransport] | None = None,
    clock: Callable[[], float] | None = None,
    today: Callable[[], dt.date] = lambda: dt.datetime.now(dt.UTC).date(),
) -> FastAPI:
    settings = settings or DemoSettings.from_env()
    transports = transports or {}
    personas = load_personas(settings.personas)
    clock = clock or time.monotonic
    sessions = Sessions(
        settings.session_ttl, settings.max_sessions, settings.offer_ttl, clock, settings.sessions_per_client
    )
    issuers = {
        "pid": Cunho(settings.pid, transports.get("pid")),
        "course": Cunho(settings.course, transports.get("course")),
    }
    new_sessions = RateLimiter(settings.sessions_per_minute, clock)
    polls = RateLimiter(settings.polls_per_minute, clock)
    logins = RateLimiter(settings.logins_per_minute, clock)
    # Progress reads per issuer, for all visitors together: see DemoSettings.progress_per_minute.
    reads = {name: RateLimiter(settings.progress_per_minute, clock) for name in issuers}
    pid_configurations = settings.pid_configurations
    wallet = None
    if settings.wallet_ka_chain is not None and settings.wallet_ka_key is not None:
        attester = KeyAttester.from_files(settings.wallet_ka_chain, settings.wallet_ka_key)
        routes = {
            "pid": route(settings.pid, transports.get("pid")),
            "course": route(settings.course, transports.get("course")),
        }
        wallet = DemoWallet(attester, routes)
    running: set[asyncio.Task[None]] = set()  # the demo wallet's runs, kept until they end

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            for task in list(running):
                task.cancel()
            for cunho in issuers.values():
                await cunho.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.sessions = sessions
    app.state.issuers = issuers
    app.state.wallet = wallet

    @app.middleware("http")
    async def headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 - whatever no handler expected is answered here, with the headers below
            # Left to the framework's outermost layer, the answer would carry none of them (the security review).
            log.exception("unhandled error")
            response = JSONResponse({"error": "server_error"}, 500, NO_STORE)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if settings.origin.startswith("https://"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        # The page and its files are asked for again each time (their ETag makes that cheap), so a page from one
        # release never runs with a script from another. The API's answers already say no-store.
        response.headers.setdefault("Cache-Control", "no-cache")
        return response

    @app.exception_handler(DemoError)
    async def on_demo_error(_: Request, exc: DemoError) -> JSONResponse:
        extra = {"Retry-After": "60"} if exc.status == 429 else {}
        return JSONResponse({"error": exc.error, "message": exc.message}, exc.status, {**NO_STORE, **extra})

    @app.exception_handler(StarletteHTTPException)
    async def on_http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse({"error": "not_found" if exc.status_code == 404 else "invalid_request"}, exc.status_code)

    def client_of(request: Request) -> str:
        """The visitor's network: an IPv4 address, or an IPv6 /56, the smallest block a home connection is usually
        given. Counted by /64, one such connection would be 256 clients to every limit here."""
        return client_bucket(request.client.host if request.client else None, v6_prefix=56)

    def visitor_of(request: Request) -> str | None:
        """The visitor's address, for the issuer to count the demo wallet's requests by (DemoWallet); None when the
        connection gives none."""
        try:
            return str(ipaddress.ip_address(request.client.host if request.client else ""))
        except ValueError:
            return None

    def limit(request: Request, limiter: RateLimiter) -> None:
        if not limiter.allow(client_of(request)):
            raise DemoError(429, "too_many_requests", "Too many requests from your network. Try again in a minute.")

    async def json_body(request: Request) -> dict[str, Any]:
        """Same-origin JSON only: a cross-site form cannot send application/json without a preflight, which this
        service never answers, and an Origin header, when the browser sends one, must be the page's own."""
        origin = request.headers.get("origin")
        if origin is not None and origin not in settings.origins:
            raise DemoError(403, "forbidden", "Requests come from the demo page only.")
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            raise DemoError(415, "invalid_request", "Send application/json.")
        raw = b""
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > MAX_BODY:
                raise DemoError(413, "invalid_request", "The request is too large.")
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            raise DemoError(400, "invalid_request", "The request is not JSON.") from None
        if not isinstance(body, dict):
            raise DemoError(400, "invalid_request", "The request must be a JSON object.")
        return body

    def session_of(session_id: str) -> Session:
        session = sessions.get(session_id)
        if session is None:
            raise DemoError(404, "not_found", "This demo session has ended. Start a new one.")
        return session

    def unavailable(exc: CunhoError) -> DemoError:
        log.warning("cunho answered %s %s", exc.status, exc.error)
        if exc.status in (429, 503) or exc.status >= 500:
            return DemoError(503, "unavailable", "The issuer is not reachable right now. Try again in a minute.")
        return DemoError(502, "issuer_refused", "The issuer refused the request.")

    # the visitor's API ---------------------------------------------------------------------------------------

    @app.post("/api/sessions")
    async def new_session(request: Request) -> JSONResponse:
        body = await json_body(request)
        limit(request, new_sessions)
        credential = body.get("credential")
        if credential not in CREDENTIALS:
            raise DemoError(400, "invalid_request", "credential is pid or course.")
        fmt = body.get("format", FORMATS[credential][0])
        if fmt not in FORMATS[credential]:
            raise DemoError(400, "invalid_request", f"format is one of {', '.join(FORMATS[credential])}.")
        flow = body.get("flow", FLOWS[0])
        if flow not in FLOWS:
            raise DemoError(400, "invalid_request", "flow is pre-authorized_code or authorization_code.")
        pin = body.get("pin", False)
        if not isinstance(pin, bool) or (pin and flow != FLOWS[0]):
            raise DemoError(400, "invalid_request", "pin is true or false, and only for a pre-authorized offer.")
        persona_id = body.get("persona")
        if persona_id is None:
            persona_id = random.choice(sorted(personas))  # which fictional person: nothing secret
        if not isinstance(persona_id, str) or persona_id not in personas:
            raise DemoError(400, "invalid_request", "persona is one of the demo's people.")
        persona = personas[persona_id]
        ids = configurations(credential, fmt, pid_configurations)
        offer: dict[str, Any] = {"credential_configuration_ids": ids}
        if flow == FLOWS[0]:
            offer["subject"] = subject(persona, credential, fmt, today(), settings.pid_validity_days)
            if pin:
                offer["tx_code_length"] = 4
        else:
            offer["grant"] = "authorization_code"
        session = Session(
            credential=credential,
            format=fmt,
            flow=flow,
            persona=persona.id,
            configurations=ids,
            client=client_of(request),
        )
        # Its place is taken before the offer is made, so the bound holds for the work sent to cunho as well.
        if not sessions.add(session):
            raise DemoError(503, "busy", "The demo is busy. Try again in a few minutes.")
        try:
            made = await issuers[credential].create_offer(offer)
        except CunhoError as exc:
            sessions.remove(session.id)
            raise unavailable(exc) from exc
        session.subject_ref = made.get("subject_ref")
        session.offer_ref = made.get("offer_ref")
        try:
            session.offer = offer_in(made["offer_link"])
        except (KeyError, IndexError, TypeError, ValueError):
            sessions.remove(session.id)
            raise DemoError(502, "issuer_refused", "The issuer's offer could not be read.") from None
        session.tx_code = made.get("tx_code")
        links = links_of(session)
        answer = {
            "id": session.id,
            "credential": credential,
            "format": fmt,
            "flow": flow,
            "persona": {"id": persona.id, "name": persona.name},
            "card": card(persona, credential, today(), settings.pid_validity_days),
            "offer_link": made["offer_link"],
            **links,
            # Two QR codes of the same offer: one a wallet app scans, short since it names the offer by reference;
            # one a phone's camera opens, which brings the offer to the phone page.
            "qr_svg": qr_svg(links["wallet_link"]),
            "qr_svg_phone": qr_svg(links["phone_link"]),
            "tx_code": made.get("tx_code"),
            "expires_in": settings.offer_ttl,
            "demo_wallet": wallet is not None and flow == FLOWS[0],
        }
        return JSONResponse(answer, 201, NO_STORE)

    def links_of(session: Session) -> dict[str, str]:
        """A wallet's link to the offer, by reference (credential_offer_uri, OpenID4VCI 1.0 section 4.1.3), and
        the phone page's, both on the demo's public origin."""
        offer_uri = f"{settings.origin}/offers/{session.token}"
        return {
            "wallet_link": f"openid-credential-offer://?credential_offer_uri={quote(offer_uri, safe='')}",
            "phone_link": f"{settings.origin}/o/{session.token}",
            "phone_path": f"/o/{session.token}",
        }

    async def view(session: Session, *, poll: bool = False) -> dict[str, Any]:
        """What the page shows of a session. A poll asks the issuer only while the visitors together are within
        this minute's share of the operator API (DemoSettings.progress_per_minute); past it, it is answered with
        what the issuer said last, so polling can make a page lag but never takes the operator API from the offers,
        the logins and the console. An answer to something the visitor did always asks."""
        progress = None
        if session.subject_ref is not None:
            if not poll or session.progress is None or reads[session.credential].allow("visitors"):
                try:
                    session.progress = await issuers[session.credential].progress(session.subject_ref)
                except CunhoError as exc:
                    raise unavailable(exc) from exc
            progress = session.progress
        offer_open = sessions.clock() < session.offer_expires
        persona = personas[session.persona]
        return {
            "id": session.id,
            # Who it is for: the person chosen on the login screen of a code-flow offer may not be the one first shown.
            "persona": {"id": persona.id, "name": persona.name},
            "card": card(persona, session.credential, today(), settings.pid_validity_days),
            "step": step(progress, session.signing_in, offer_open, session.revoked, session.cancelled),
            "configurations": progress["configurations"] if progress else [],
            # Why the issuer refused the wallet's last credential request, by error code and rule only.
            "refusal": progress.get("refusal") if progress else None,
            "wallet": session.wallet.view() if session.wallet else None,
        }

    def by_token(token: str) -> Session:
        session = sessions.by_token(token)
        if session is None or session.offer is None:
            raise DemoError(404, "not_found", "This offer has ended. Start a new one on the demo page.")
        return session

    async def phone_view(session: Session, *, poll: bool = False) -> dict[str, Any]:
        """What the phone page shows: the session's view without its id, which acts on it, and without the PIN,
        which the QR code must not give whoever scans it."""
        answer = await view(session, poll=poll)
        del answer["id"]
        return {
            **answer,
            "credential": session.credential,
            "flow": session.flow,
            "pin": session.tx_code is not None,
            "wallet_link": links_of(session)["wallet_link"],
            "demo_wallet": wallet is not None and session.flow == FLOWS[0],
        }

    def start_wallet(session: Session, pin: str | None, visitor: str | None) -> None:
        if wallet is None:
            raise DemoError(404, "not_available", "This demo has no demo wallet.")
        if session.flow != FLOWS[0] or session.offer is None:
            raise DemoError(409, "wallet_flow", "The demo wallet takes offers made straight away, without sign-in.")
        # A failed run is tried again only if it never redeemed the offer: past the token, the pre-authorized code
        # is spent, and the run keeps whatever it was issued.
        if session.wallet is not None and (session.wallet.state != "failed" or session.wallet.redeemed):
            raise DemoError(409, "wallet_started", "The demo wallet already took this offer.")
        if session.revoked or sessions.clock() >= session.offer_expires:
            raise DemoError(409, "offer_ended", "This offer has ended. Start a new one.")
        if len(running) >= MAX_WALLETS:
            raise DemoError(503, "busy", "The demo wallet is busy. Try again in a minute.")
        activity = Activity()
        session.wallet = activity
        task = asyncio.create_task(
            wallet.run(
                session.credential,
                session.offer,
                pin,
                activity,
                visitor,
            )
        )
        running.add(task)
        task.add_done_callback(running.discard)

    async def check_status(session: Session, visitor: str | None) -> None:
        if wallet is None or session.wallet is None or not session.wallet.credentials or session.offer is None:
            raise DemoError(409, "nothing_held", "The demo wallet holds no credential from this offer.")
        try:
            await wallet.check_status(session.credential, session.offer["credential_issuer"], session.wallet, visitor)
        except Exception as exc:  # noqa: BLE001 - whatever went wrong, the visitor is told the issuer is unreachable
            log.warning("status check failed: %s", type(exc).__name__)
            raise DemoError(503, "unavailable", "The status list could not be read. Try again in a minute.") from None

    @app.post("/api/sessions/{session_id}/demo-wallet")
    async def demo_wallet(request: Request, session_id: str) -> JSONResponse:
        await json_body(request)
        limit(request, polls)
        session = session_of(session_id)
        start_wallet(session, session.tx_code, visitor_of(request))  # the page shows the PIN; its wallet types it
        return JSONResponse(await view(session), 202, NO_STORE)

    @app.post("/api/sessions/{session_id}/status")
    async def session_status(request: Request, session_id: str) -> JSONResponse:
        await json_body(request)
        limit(request, polls)
        session = session_of(session_id)
        await check_status(session, visitor_of(request))
        return JSONResponse(await view(session), headers=NO_STORE)

    # the offer by reference, and the phone page a camera opens -------------------------------------------------

    @app.get("/offers/{token}")
    async def offer_by_reference(request: Request, token: str) -> JSONResponse:
        limit(request, polls)
        session = by_token(token)
        if sessions.clock() >= session.offer_expires:
            raise DemoError(404, "not_found", "This offer has ended.")
        return JSONResponse(session.offer, headers=NO_STORE)

    @app.get("/o/{token}")
    async def phone_page(token: str) -> FileResponse:
        # The page itself; app.js reads the token from the address and asks /api/offers/{token}.
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/api/offers/{token}")
    async def offer_progress(request: Request, token: str) -> JSONResponse:
        limit(request, polls)
        return JSONResponse(await phone_view(by_token(token), poll=True), headers=NO_STORE)

    @app.post("/api/offers/{token}/demo-wallet")
    async def offer_demo_wallet(request: Request, token: str) -> JSONResponse:
        body = await json_body(request)
        limit(request, polls)
        session = by_token(token)
        pin = body.get("pin")
        if session.tx_code is not None and not (isinstance(pin, str) and pin.isdigit() and len(pin) <= 8):
            raise DemoError(400, "invalid_request", "Type the PIN shown on the page where you made the offer.")
        # The phone page never sees the PIN: the visitor types it, and cunho checks it as it checks a wallet's.
        start_wallet(session, pin if session.tx_code is not None else None, visitor_of(request))
        return JSONResponse(await phone_view(session), 202, NO_STORE)

    @app.post("/api/offers/{token}/status")
    async def offer_status(request: Request, token: str) -> JSONResponse:
        await json_body(request)
        limit(request, polls)
        session = by_token(token)
        await check_status(session, visitor_of(request))
        return JSONResponse(await phone_view(session), headers=NO_STORE)

    @app.get("/api/sessions/{session_id}")
    async def session_progress(request: Request, session_id: str) -> JSONResponse:
        limit(request, polls)
        return JSONResponse(await view(session_of(session_id), poll=True), headers=NO_STORE)

    @app.post("/api/sessions/{session_id}/revoke")
    async def revoke(request: Request, session_id: str) -> JSONResponse:
        await json_body(request)
        limit(request, polls)
        session = session_of(session_id)
        if session.subject_ref is None or session.revoked:
            raise DemoError(409, "nothing_to_revoke", "Nothing in this session can be revoked.")
        try:
            await issuers[session.credential].revoke(session.subject_ref)
        except CunhoError as exc:
            if exc.status == 400:
                raise DemoError(409, "nothing_to_revoke", "Nothing in this session can be revoked.") from exc
            raise unavailable(exc) from exc
        session.revoked = True
        return JSONResponse(await view(session), headers=NO_STORE)

    async def decide(request: Request, session_id: str, decision: str) -> JSONResponse:
        await json_body(request)
        limit(request, polls)
        session = session_of(session_id)
        cunho = issuers[session.credential]
        try:
            held = [
                row["ref"]
                for row in await cunho.deferred()
                if row["subject_ref"] == session.subject_ref and row["state"] == "held"
            ]
            if session.subject_ref is None or not held:
                raise DemoError(409, "nothing_held", "Nothing in this session waits for review.")
            for ref in held:
                await cunho.decide(ref, decision)
        except CunhoError as exc:
            raise unavailable(exc) from exc
        return JSONResponse(await view(session), headers=NO_STORE)

    @app.post("/api/sessions/{session_id}/release")
    async def release(request: Request, session_id: str) -> JSONResponse:
        return await decide(request, session_id, "release")

    @app.post("/api/sessions/{session_id}/refuse")
    async def refuse(request: Request, session_id: str) -> JSONResponse:
        return await decide(request, session_id, "refuse")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True}, headers=NO_STORE)

    login_routes(app, settings, issuers, sessions, personas, today, lambda request: logins.allow(client_of(request)))
    console_routes(
        app,
        password_hash=settings.operator_password_hash,
        secret_key=settings.secret_key,
        origins=settings.origins,
        secure=settings.origin.startswith("https://"),
        issuers=issuers,
        sessions=sessions,
        clock=clock,
    )

    if STATIC.is_dir():
        app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
    return app
