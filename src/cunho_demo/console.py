"""The operator console of the demo: what an operator of the two cunho instances sees and decides, behind a password.

It shows whether each issuer's audit log verifies, the issuances held for review (release or refuse), the demo
sessions under way, and revokes by subject reference. It talks to cunho through the same admin API as the page,
so it can do nothing an operator token could not. Off unless DEMO_OPERATOR_PASSWORD_FILE is set.

The password is kept only as an scrypt hash (`python -m cunho_demo.console` makes one). A signed-in operator holds
a random session in an HttpOnly, SameSite=Strict cookie, kept in this process's memory for eight hours; every form
carries a token derived from it, so no other site can make the console act."""

from __future__ import annotations

import asyncio
import base64
import getpass
import hashlib
import hmac
import html
import re
import secrets
import sys
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.concurrency import run_in_threadpool

from cunho.app import client_bucket
from cunho.keyring import same
from cunho_demo.client import Cunho, CunhoError
from cunho_demo.sessions import Sessions

COOKIE = "demo_operator"
SESSION_TTL = 8 * 3600
FAILED_LOGINS = 5  # wrong passwords per network in a window, after which no password is even checked
FAILED_WINDOW = 60
SUBJECT_REF = re.compile(r"sub_[A-Za-z0-9_-]{8,64}")
HELD_REF = re.compile(r"[0-9a-f]{32}")
MAX_FORM = 4096
NO_STORE = {"Cache-Control": "no-store"}
SCRYPT = {"n": 2**15, "r": 8, "p": 1}
TITLES = {"pid": "PID issuer", "course": "Course certificate issuer"}


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, maxmem=64 * 1024 * 1024, dklen=32, **SCRYPT)
    encode = base64.urlsafe_b64encode
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${encode(salt).decode()}${encode(digest).decode()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt, digest = stored.split("$")
        if kind != "scrypt":
            return False
        expected = base64.urlsafe_b64decode(digest)
        derived = hashlib.scrypt(
            password.encode(),
            salt=base64.urlsafe_b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            maxmem=64 * 1024 * 1024,
            dklen=len(expected),
        )
    except ValueError:
        return False
    return hmac.compare_digest(derived, expected)


class FailedLogins:
    """Sign-in attempts per client network. Each attempt takes its place before its password is checked, so
    attempts sent all at once count as they arrive (the second reviewer), and gives it back when the password was
    right. Once a network has used FAILED_LOGINS in the current window, its attempts are refused before any password
    is checked, the right one included."""

    def __init__(self, clock: Callable[[], float], max_networks: int = 10_000) -> None:
        self._clock = clock
        self._max = max_networks
        self._failures: dict[str, tuple[float, int]] = {}  # network -> (window start, count)
        self._lock = threading.Lock()

    def begin(self, network: str) -> bool:
        """Take a place for one attempt; False when the network has none left in this window."""
        with self._lock:
            now = self._clock()
            start, count = self._failures.get(network, (now, 0))
            if now - start >= FAILED_WINDOW:
                start, count = now, 0
            if count >= FAILED_LOGINS:
                return False
            if network not in self._failures and len(self._failures) >= self._max:
                self._failures = {k: v for k, v in self._failures.items() if now - v[0] < FAILED_WINDOW}
                if len(self._failures) >= self._max:
                    return False  # still full of live windows: no new network until one ends (the second reviewer)
            self._failures[network] = (start, count + 1)
            return True

    def succeeded(self, network: str) -> None:
        """The password was right: the attempt's place is given back."""
        with self._lock:
            if network in self._failures:
                start, count = self._failures[network]
                self._failures[network] = (start, max(0, count - 1))


class OperatorSessions:
    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def open(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            now = self._clock()
            self._sessions = {k: v for k, v in self._sessions.items() if v > now}
            self._sessions[token] = now + SESSION_TTL
        return token

    def valid(self, token: str | None) -> bool:
        with self._lock:
            return token is not None and self._sessions.get(token, 0) > self._clock()

    def close(self, token: str | None) -> None:
        with self._lock:
            self._sessions.pop(token or "", None)


def console_routes(
    app: FastAPI,
    *,
    password_hash: str | None,
    secret_key: bytes,
    origins: frozenset[str],
    secure: bool,
    issuers: dict[str, Cunho],
    sessions: Sessions,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    if not password_hash:
        return  # no console without a password
    operators = OperatorSessions(clock)
    failures = FailedLogins(clock)
    # With the __Host- prefix a browser takes the cookie only from this very host, over https, for the whole site:
    # another site under the same domain cannot plant one in the operator's browser. The prefix needs Secure, which
    # a local run over plain http cannot set, so that one keeps the plain name.
    cookie = f"__Host-{COOKIE}" if secure else COOKIE
    checking = asyncio.Semaphore(2)  # scrypt checks at once, whatever the number of networks asking

    def csrf(token: str) -> str:
        return hmac.new(secret_key, f"operator:{token}".encode(), hashlib.sha256).hexdigest()

    def page(title: str, body: str, status: int = 200) -> HTMLResponse:
        document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<meta name="robots" content="noindex">
<title>{html.escape(title)} · demo operator</title>
<link rel="stylesheet" href="/styles.css">
</head>
<body class="screen">
<header class="topbar"><div class="shell topbar-inner">
<span class="brand"><span class="brand-mark" aria-hidden="true"></span>Demo operator</span>
</div></header>
<main class="shell">
{body}
</main>
</body>
</html>
"""
        return HTMLResponse(document, status, headers=NO_STORE)

    async def form(request: Request) -> dict[str, str] | None:
        request_origin = request.headers.get("origin")
        if request_origin is not None and request_origin not in origins:
            return None
        if request.headers.get("content-type", "").split(";")[0].strip().lower() != (
            "application/x-www-form-urlencoded"
        ):
            return None
        raw = b""
        async for chunk in request.stream():
            raw += chunk
            if len(raw) > MAX_FORM:
                return None
        try:
            fields = parse_qs(raw.decode("utf-8"))
        except UnicodeDecodeError:
            return None
        return {name: values[0] for name, values in fields.items() if len(values) == 1}

    def signed_in(request: Request) -> str | None:
        token = request.cookies.get(cookie)
        return token if operators.valid(token) else None

    def login_page(message: str = "", status: int = 200) -> HTMLResponse:
        note = f'<p class="error" role="alert">{html.escape(message)}</p>' if message else ""
        body = f"""<section class="card narrow-card">
<h1>Sign in</h1>
<p>The console of the demo's two issuers.</p>
{note}
<form method="post" action="/operator/login">
<label class="field"><span>Password</span>
<input type="password" name="password" autocomplete="current-password" required></label>
<div class="actions"><button class="button primary" type="submit">Sign in</button></div>
</form>
</section>"""
        return page("Sign in", body, status)

    @app.get("/operator")
    async def console(request: Request) -> Response:
        token = signed_in(request)
        if token is None:
            return login_page()
        return page("Console", await overview(token, request.query_params.get("done", "")))

    @app.post("/operator/login")
    async def login(request: Request) -> Response:
        fields = await form(request)
        if fields is None:
            return login_page("This form must be sent from the console.", 400)
        network = client_bucket(request.client.host if request.client else None)
        if not failures.begin(network):
            return login_page("Too many wrong passwords. Wait a minute.", 429)
        # scrypt takes a moment on purpose: off the event loop, so the page and the API keep answering.
        async with checking:
            right = await run_in_threadpool(password_matches, fields.get("password", ""), password_hash)
        if not right:
            return login_page("Wrong password.", 401)
        failures.succeeded(network)
        response = RedirectResponse("/operator", 303, headers=NO_STORE)
        response.set_cookie(
            cookie, operators.open(), max_age=SESSION_TTL, httponly=True, secure=secure, samesite="strict", path="/"
        )
        return response

    @app.post("/operator/logout")
    async def logout(request: Request) -> Response:
        token = signed_in(request)
        fields = await form(request)
        if token is not None and fields is not None and same(fields.get("csrf", ""), csrf(token)):
            operators.close(token)
        response = RedirectResponse("/operator", 303, headers=NO_STORE)
        response.delete_cookie(cookie, path="/", secure=secure, httponly=True, samesite="strict")
        return response

    @app.post("/operator/action")
    async def action(request: Request) -> Response:
        token = signed_in(request)
        if token is None:
            return login_page("Sign in first.", 401)
        fields = await form(request)
        if fields is None or not same(fields.get("csrf", ""), csrf(token)):
            return page("Refused", '<p class="error">This form must be sent from the console.</p>', 400)
        issuer, what = fields.get("issuer", ""), fields.get("action", "")
        if issuer not in issuers:
            return page("Refused", '<p class="error">Unknown issuer.</p>', 400)
        try:
            if what in ("release", "refuse") and HELD_REF.fullmatch(fields.get("ref", "")):
                await issuers[issuer].decide(fields["ref"], what)
                done = "released" if what == "release" else "refused"
            elif what == "revoke" and SUBJECT_REF.fullmatch(fields.get("subject_ref", "").strip()):
                subject_ref = fields["subject_ref"].strip()
                answer = await issuers[issuer].revoke(subject_ref)
                for session in sessions.with_subject(subject_ref):
                    session.revoked = True  # the visitor's page says revoked, as when they revoke it themselves
                done = f"revoked {answer.get('revoked', 0)}"
            else:
                return page("Refused", '<p class="error">That action is not one the console takes.</p>', 400)
        except CunhoError as exc:
            reason = exc.description or exc.error
            body = f'<p class="error">The issuer refused: {html.escape(reason)}</p><p><a href="/operator">Back</a></p>'
            return page("Refused", body, 409 if exc.status < 500 else 503)
        return RedirectResponse(f"/operator?done={quote(done)}", 303, headers=NO_STORE)

    async def overview(token: str, done: str) -> str:
        parts = []
        if done:
            parts.append(f'<p class="notice" role="status">Done: {html.escape(done[:40])}</p>')
        form_token = html.escape(csrf(token))
        for name, cunho in issuers.items():
            try:
                audit: dict[str, Any] = await cunho.audit_verify()
                held = [row for row in await cunho.deferred() if row["state"] == "held"]
                verified = "verifies" if audit.get("valid") else f"does NOT verify: {audit.get('detail', '')}"
            except CunhoError as exc:
                parts.append(f'<section class="panel"><h2>{TITLES.get(name, name)}</h2>')
                parts.append(f'<p class="error">Not reachable ({exc.status}).</p></section>')
                continue
            rows = "".join(
                f"""<tr><td><code>{html.escape(row["ref"][:12])}</code></td><td><code>{html.escape(row["subject_ref"])}</code></td>
<td>{html.escape(row["configuration_id"])}</td><td>
<form method="post" action="/operator/action" class="inline">
<input type="hidden" name="csrf" value="{form_token}"><input type="hidden" name="issuer" value="{name}">
<input type="hidden" name="ref" value="{html.escape(row["ref"])}">
<button class="button primary" name="action" value="release">Release</button>
<button class="button" name="action" value="refuse">Refuse</button></form></td></tr>"""
                for row in held
            )
            table = (
                f'<table class="table"><thead><tr><th>Held</th><th>Subject</th><th>Configuration</th><th></th></tr>'
                f"</thead><tbody>{rows}</tbody></table>"
                if held
                else "<p>Nothing held for review.</p>"
            )
            parts.append(
                f"""<section class="panel"><h2>{TITLES.get(name, name)}</h2>
<p>Audit log: <strong>{html.escape(verified)}</strong></p>
{table}
<form method="post" action="/operator/action" class="revoke-form">
<input type="hidden" name="csrf" value="{form_token}"><input type="hidden" name="issuer" value="{name}">
<label class="field"><span>Revoke by subject reference</span>
<input name="subject_ref" pattern="sub_[A-Za-z0-9_-]{{8,64}}" required placeholder="sub_..."></label>
<button class="button danger" name="action" value="revoke">Revoke</button></form>
</section>"""
            )
        recent = sessions.recent(20)
        listed = "".join(
            f"<tr><td>{html.escape(s.credential)}</td><td>{html.escape(s.flow)}</td><td>{html.escape(s.persona)}</td>"
            f"<td><code>{html.escape(s.subject_ref or '-')}</code></td></tr>"
            for s in recent
        )
        parts.append(
            '<section class="panel"><h2>Demo sessions under way</h2>'
            + (
                f'<table class="table"><thead><tr><th>Credential</th><th>Flow</th><th>Person</th><th>Subject</th></tr>'
                f"</thead><tbody>{listed}</tbody></table>"
                if recent
                else "<p>None.</p>"
            )
            + "</section>"
        )
        parts.append(
            f"""<form method="post" action="/operator/logout">
<input type="hidden" name="csrf" value="{form_token}"><button class="link-button">Sign out</button></form>"""
        )
        return "<h1>Demo operator</h1>" + "".join(parts)


def main() -> None:
    """Print the scrypt hash of a password read from the terminal, for DEMO_OPERATOR_PASSWORD_FILE."""
    password = getpass.getpass("Operator password: ")
    if len(password) < 12:
        sys.exit("use at least 12 characters")
    if getpass.getpass("Again: ") != password:
        sys.exit("the two do not match")
    print(hash_password(password))


if __name__ == "__main__":
    main()
