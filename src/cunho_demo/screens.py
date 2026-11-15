"""The login service of the demo's authorization code flow: the screens a wallet sends the person's browser to.

Each cunho's CUNHO_LOGIN_URL points here (`/login/pid`, `/login/course`). The person picks one of the demo's
fictional people, sees what will be issued and to which wallet, and agrees or cancels; the demo then reports the
login to cunho with the operator token and sends the browser on. No identity is checked: it says so on every
screen. Server-rendered, no script: the screens work in any wallet's browser."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import html
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from cunho.keyring import same
from cunho_demo.client import Cunho, CunhoError
from cunho_demo.offers import COURSE_MDOC, COURSE_SD_JWT, Persona, subject
from cunho_demo.sessions import Session, Sessions
from cunho_demo.settings import DemoSettings
from cunho_demo.texts import LABELS, TEXT, language, shown

LOGIN_STATE = re.compile(r"[A-Za-z0-9_-]{16,200}")
MAX_FORM = 4096
NO_STORE = {"Cache-Control": "no-store"}


def page(lang: str, title: str, body: str, status: int = 200, head: str = "") -> HTMLResponse:
    t = TEXT[lang]
    document = f"""<!doctype html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>{html.escape(title)} · {html.escape(t["brand"])}</title>
<link rel="stylesheet" href="/styles.css">
{head}</head>
<body class="screen">
<header class="topbar"><div class="shell topbar-inner">
<span class="brand"><span class="brand-mark" aria-hidden="true"></span>{html.escape(t["brand"])}</span>
</div></header>
<main class="shell narrow">
<p class="notice" role="note">{html.escape(t["demo_notice"])}</p>
{body}
</main>
</body>
</html>
"""
    return HTMLResponse(document, status, headers=NO_STORE)


def login_routes(
    app: FastAPI,
    settings: DemoSettings,
    issuers: dict[str, Cunho],
    sessions: Sessions,
    personas: dict[str, Persona],
    today: Callable[[], dt.date],
    allow: Callable[[Request], bool],
) -> None:
    """`allow` says whether the client of a request is within its limit for these screens. Every one of them asks the
    issuer something with the operator token, so each is counted before it does (the security review)."""

    def token(issuer: str, login_state: str) -> str:
        """Binds a form to its login: a page on another site cannot post one, since it never saw login_state."""
        message = f"login:{issuer}:{login_state}".encode()
        return hmac.new(settings.secret_key, message, hashlib.sha256).hexdigest()

    def onward(lang: str, url: str) -> HTMLResponse:
        """On to cunho, and from there to the wallet. Not a 303 from the form: a browser checks a form's redirects
        against the CSP's form-action, which allows this site alone, and the wallet's redirect URI is another
        app's. A new navigation, by refresh or by the link, is not a form's (the second reviewer)."""
        t = TEXT[lang]
        target = html.escape(url)
        body = f"""<section class="card">
<h1>{html.escape(t["onward_title"])}</h1>
<p><a class="button primary" href="{target}">{html.escape(t["onward"])}</a></p>
</section>"""
        return page(lang, t["onward_title"], body, head=f'<meta http-equiv="refresh" content="0; url={target}">\n')

    def failure(lang: str, key: str, status: int) -> HTMLResponse:
        t = TEXT[lang]
        body = f'<section class="card"><h1>{html.escape(t["error_title"])}</h1><p>{html.escape(t[key])}</p></section>'
        return page(lang, t["error_title"], body, status)

    def too_many(request: Request) -> HTMLResponse:
        lang = language(request.query_params.get("lang"), request.headers.get("accept-language"))
        answer = failure(lang, "error_busy", 429)
        answer.headers["Retry-After"] = "60"
        return answer

    def credentials_text(lang: str, issuer: str) -> str:
        return TEXT[lang][issuer]

    def issuer_text(lang: str, issuer: str) -> str:
        return TEXT[lang][f"{issuer}_issuer"]

    async def form(request: Request) -> dict[str, str] | None:
        """The posted form, or None when it does not come from this site's own page."""
        origin = request.headers.get("origin")
        if origin is not None and origin not in settings.origins:
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
            fields = parse_qs(raw.decode("ascii"), strict_parsing=False)
        except UnicodeDecodeError:
            return None
        return {name: values[0] for name, values in fields.items() if len(values) == 1}

    async def pending(issuer: str, login_state: str) -> dict[str, Any] | None:
        try:
            return await issuers[issuer].pending_login(login_state)
        except CunhoError as exc:
            if exc.status == 404:
                return None
            raise

    def session_for(issuer: str, login: dict[str, Any]) -> Session | None:
        reference = login.get("offer_ref")
        session = sessions.by_offer(reference) if isinstance(reference, str) else None
        return session if session is not None and session.credential == issuer else None

    def format_of(issuer: str, configuration_ids: list[str]) -> str | None:
        if issuer == "pid":
            return "both"
        wanted = {COURSE_SD_JWT, COURSE_MDOC} & set(configuration_ids)
        if len(wanted) != 1:
            return None  # one subject cannot be both an SD-JWT VC's claims and an mdoc's namespaces
        return "mdoc" if COURSE_MDOC in wanted else "sd_jwt"

    def persona_choice(lang: str, chosen: str) -> str:
        items = []
        for persona in personas.values():
            checked = " checked" if persona.id == chosen else ""
            items.append(
                f'<label class="persona"><input type="radio" name="persona" value="{persona.id}"{checked} required>'
                f'<span class="persona-name">{html.escape(persona.name)}</span></label>'
            )
        return "".join(items)

    def hidden(fields: dict[str, str]) -> str:
        return "".join(
            f'<input type="hidden" name="{name}" value="{html.escape(value)}">' for name, value in fields.items()
        )

    @app.get("/login/{issuer}")
    async def login(request: Request, issuer: str) -> Response:
        if not allow(request):
            return too_many(request)
        lang = language(request.query_params.get("lang"), request.headers.get("accept-language"))
        login_state = request.query_params.get("login_state", "")
        if issuer not in issuers or not LOGIN_STATE.fullmatch(login_state):
            return failure(lang, "error_request", 400)
        try:
            found = await pending(issuer, login_state)
        except CunhoError:
            return failure(lang, "error_unavailable", 503)
        if found is None:
            return failure(lang, "error_gone", 410)
        session = session_for(issuer, found)
        if session is not None and not session.signing_in:
            # The offer has been used: the page waits as long as this login can still be reported, from the first
            # visit, which is moments after cunho made the login; a reload does not move it (the second reviewer).
            session.signing_in = True
            session.offer_expires = max(session.offer_expires, sessions.clock() + settings.login_ttl)
        t = TEXT[lang]
        intro = t["login_intro"].format(issuer=issuer_text(lang, issuer), credentials=credentials_text(lang, issuer))
        chosen = session.persona if session is not None else next(iter(personas))
        fields = {"login_state": login_state, "token": token(issuer, login_state), "lang": lang}
        other = "en" if lang == "pt" else "pt"
        body = f"""<section class="card">
<h1>{html.escape(t["login_title"])}</h1>
<p>{html.escape(intro)}</p>
<form method="post" action="/login/{issuer}">
{hidden(fields)}
<fieldset class="personas"><legend>{html.escape(t["login_persona"])}</legend>{persona_choice(lang, chosen)}</fieldset>
<div class="actions">
<button class="button primary" type="submit">{html.escape(t["continue"])}</button>
<button class="button" type="submit" name="action" value="cancel" formaction="/consent/{issuer}"
 formnovalidate>{html.escape(t["cancel"])}</button>
</div>
</form>
<p class="language"><a href="/login/{issuer}?login_state={html.escape(login_state)}&amp;lang={other}"
 hreflang="{other}">{html.escape(t["language"])}</a></p>
</section>"""
        return page(lang, t["login_title"], body)

    @app.post("/login/{issuer}")
    async def chosen(request: Request, issuer: str) -> Response:
        if not allow(request):
            return too_many(request)
        fields = await form(request)
        lang = language((fields or {}).get("lang"), request.headers.get("accept-language"))
        login_state = (fields or {}).get("login_state", "")
        if (
            fields is None
            or issuer not in issuers
            or not LOGIN_STATE.fullmatch(login_state)
            or not same(fields.get("token", ""), token(issuer, login_state))
            or fields.get("persona") not in personas
        ):
            return failure(lang, "error_request", 400)
        try:
            found = await pending(issuer, login_state)
        except CunhoError:
            return failure(lang, "error_unavailable", 503)
        if found is None:
            return failure(lang, "error_gone", 410)
        fmt = format_of(issuer, list(found["configuration_ids"]))
        if fmt is None:
            return failure(lang, "error_formats", 400)
        persona = personas[fields["persona"]]
        data = subject(persona, issuer, "sd_jwt" if issuer == "course" else fmt, today(), settings.pid_validity_days)
        labels = LABELS[lang]
        rows = "".join(
            f"<div><dt>{html.escape(labels.get(name, name))}</dt><dd>{html.escape(shown(value))}</dd></div>"
            for name, value in data.items()
        )
        t = TEXT[lang]
        wallet = found.get("wallet_name") or t["your_wallet"]
        intro = t["consent_intro"].format(
            issuer=issuer_text(lang, issuer), credentials=credentials_text(lang, issuer), wallet=wallet
        )
        intro = intro[:1].upper() + intro[1:]  # it starts with the issuer's name, written to fit mid-sentence
        hidden_fields = {
            "login_state": login_state,
            "token": token(issuer, login_state),
            "lang": lang,
            "persona": persona.id,
        }
        body = f"""<section class="card">
<h1>{html.escape(t["consent_title"])}</h1>
<p>{html.escape(intro)}</p>
<dl class="claims">{rows}</dl>
<form method="post" action="/consent/{issuer}">
{hidden(hidden_fields)}
<label class="check"><input type="checkbox" name="review" value="true">
<span>{html.escape(t["consent_hold"])}<small>{html.escape(t["consent_hold_hint"])}</small></span></label>
<div class="actions">
<button class="button primary" type="submit" name="action" value="issue">{html.escape(t["issue"])}</button>
<button class="button" type="submit" name="action" value="cancel">{html.escape(t["cancel"])}</button>
</div>
</form>
</section>"""
        return page(lang, t["consent_title"], body)

    @app.post("/consent/{issuer}")
    async def consent(request: Request, issuer: str) -> Response:
        if not allow(request):
            return too_many(request)
        fields = await form(request)
        lang = language((fields or {}).get("lang"), request.headers.get("accept-language"))
        login_state = (fields or {}).get("login_state", "")
        if (
            fields is None
            or issuer not in issuers
            or not LOGIN_STATE.fullmatch(login_state)
            or not same(fields.get("token", ""), token(issuer, login_state))
        ):
            return failure(lang, "error_request", 400)
        try:
            found = await pending(issuer, login_state)
            if found is None:
                return failure(lang, "error_gone", 410)
            if fields.get("action") == "cancel":
                result = await issuers[issuer].report_login(login_state, {"denied": True})
                cancelled = session_for(issuer, found)
                if cancelled is not None:
                    cancelled.cancelled = True
                return onward(lang, result["continue"])
            if fields.get("action") != "issue" or fields.get("persona") not in personas:
                return failure(lang, "error_request", 400)
            fmt = format_of(issuer, list(found["configuration_ids"]))
            if fmt is None:
                return failure(lang, "error_formats", 400)
            persona = personas[fields["persona"]]
            report: dict[str, Any] = {
                "subject": subject(persona, issuer, fmt, today(), settings.pid_validity_days),
                # No identity is checked: these are fictional people, and the screens say so. cunho asks a PID
                # login to state its level, which a real deployment's identity proofing sets.
                "loa": "high",
            }
            if fields.get("review") == "true":
                report["review"] = True
            result = await issuers[issuer].report_login(login_state, report)
        except CunhoError as exc:
            if exc.status == 404:
                return failure(lang, "error_gone", 410)
            if exc.status == 400:
                return failure(lang, "error_request", 400)
            return failure(lang, "error_unavailable", 503)
        session = session_for(issuer, found)
        if session is not None:
            session.subject_ref = result["subject_ref"]
            session.persona = persona.id
        return onward(lang, result["continue"])
