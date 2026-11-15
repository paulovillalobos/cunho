"""The authorization code flow as HAIP 1.0 §4 profiles it: PAR (RFC 9126) authenticated by a wallet attestation,
PKCE with S256 (RFC 7636), the browser's visit to the authorization endpoint and the login behind it, and the token
request with DPoP; then refresh tokens.

The login is the issuer's own: the probe either fills the forms it is shown with the fields the operator gave
(`--login-field`, as a person would type them), or runs a command that does the login and prints the URL the
browser was finally sent to (`--login-cmd`, for logins a form cannot drive).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

from .attester import Instance
from .jose import EcKey, b64u
from .wallet import dpop_proof

if TYPE_CHECKING:
    from .context import Context, Exchange

CODE_GRANT = "authorization_code"
REFRESH_GRANT = "refresh_token"
MAX_STEPS = 10
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@dataclass(frozen=True)
class Pkce:
    verifier: str
    challenge: str

    @classmethod
    def new(cls) -> Pkce:
        verifier = b64u(secrets.token_bytes(32))
        return cls(verifier, b64u(hashlib.sha256(verifier.encode("ascii")).digest()))


@dataclass
class Client:
    """A wallet instance as an OAuth client: its attestation, its redirect URI and its DPoP key."""

    instance: Instance
    redirect_uri: str
    dpop: EcKey = field(default_factory=EcKey.generate)
    dpop_nonce: str | None = None  # the authorization server's latest DPoP nonce, when it asks for them

    @property
    def client_id(self) -> str:
        return self.instance.client_id


@dataclass
class Authorization:
    """What came back to the redirect URI, and how."""

    params: dict[str, str]
    pkce: Pkce
    state: str
    steps: list[Exchange]

    @property
    def code(self) -> str | None:
        return self.params.get("code")


class _Form(HTMLParser):
    """The first form of a page and the values a browser would submit from it unchanged (HTML §4.10.21.4): text and
    hidden inputs, checked checkboxes and radio buttons ("on" without a value), the selected option of each select
    (the first one when none is marked), and textareas; never buttons, nor unchecked or disabled controls."""

    SKIPPED = {"submit", "button", "image", "reset", "file"}

    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.method = "get"
        self.refresh: str | None = None  # where a <meta http-equiv="refresh"> sends the browser, as browsers follow
        self.fields: dict[str, str] = {}
        self.controls: set[str] = set()  # every named control, buttons and unchecked ones included
        self._inside = False
        self._select: str | None = None  # the name of the select being read
        self._first: str | None = None  # its first option's value, the one sent when none is selected
        self._option: dict[str, str] | None = None  # the option being read, for an option without a value
        self._textarea: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k: v or "" for k, v in attrs}
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh" and self.refresh is None:
            _, _, target = values.get("content", "").partition(";")
            key, _, url = target.strip().partition("=")
            if key.strip().lower() == "url" and url.strip():
                self.refresh = url.strip().strip("'\"")
            return
        if tag == "form" and self.action is None:
            self.action, self.method, self._inside = values.get("action", ""), values.get("method", "get"), True
            return
        if not self._inside:
            return
        name = values.get("name")
        if tag in ("input", "select", "textarea", "button") and name and "disabled" not in values:
            self.controls.add(name)
        if tag == "input" and name and "disabled" not in values:
            kind = values.get("type", "text").lower()
            if kind in self.SKIPPED:
                return
            if kind in ("checkbox", "radio"):
                if "checked" in values:
                    self.fields[name] = values.get("value", "on")
                return
            self.fields.setdefault(name, values.get("value", ""))
        elif tag == "select" and name and "disabled" not in values:
            self._select, self._first = name, None
        elif tag == "option" and self._select is not None:
            self._close_option()  # the end tag of an option may be left out (HTML §13.1.2.4)
            self._option = values
        elif tag == "textarea" and name and "disabled" not in values:
            self._textarea = name
            self.fields.setdefault(name, "")

    def _close_option(self) -> None:
        if self._select is not None and self._option is not None:
            value = self._option.get("value", "")
            if self._first is None:
                self._first = value
            if "selected" in self._option:
                self.fields[self._select] = value
        self._option = None

    def submitted(self, given: dict[str, str]) -> dict[str, str]:
        """What to send: the form's own values, with the operator's fields only for controls this form has (a
        button's name chooses that button), so a secret for one page never reaches another page's form or URL."""
        return {**self.fields, **{name: value for name, value in given.items() if name in self.controls}}

    def handle_data(self, data: str) -> None:
        if self._option is not None and "value" not in self._option:
            self._option["value"] = data.strip()
        if self._textarea is not None:
            self.fields[self._textarea] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "option":
            self._close_option()
        elif tag == "select" and self._select is not None:
            self._close_option()
            if self._select not in self.fields and self._first is not None:
                self.fields[self._select] = self._first
            self._select = None
        elif tag == "textarea":
            self._textarea = None
        elif tag == "form":
            self._inside = False


@dataclass(frozen=True)
class FlowFailure:
    """The flow was tried and stopped, which a check reports; not a missing prerequisite, which it skips."""

    reason: str
    steps: list[Exchange] = field(default_factory=list)

    @property
    def detail(self) -> str:
        return f"{self.reason}: {self.steps[-1].evidence()}" if self.steps else self.reason


def form_get(action: str, values: dict[str, str]) -> str:
    """Where a GET form goes: its action with the query replaced by the form's fields (HTML §4.10.21.3, as a browser
    builds it)."""
    parts = urlsplit(action)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(values), ""))


def with_query(url: str, params: dict[str, str]) -> str:
    """`url` with `params` added to the query it may already have (RFC 6749 §3.1 lets an endpoint carry one)."""
    parts = urlsplit(url)
    query = "&".join(q for q in (parts.query, urlencode(params)) if q)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


class CodeFlow:
    def __init__(self, ctx: Context, client: Client) -> None:
        self.ctx = ctx
        self.client = client
        self.last_headers: dict[str, str] = {}  # the headers of the last request sent, for a check that replays them

    @property
    def as_issuer(self) -> str:
        return str(self.ctx.as_metadata.get("issuer") or self.ctx.as_identifier)

    def endpoint(self, name: str) -> str:
        value = self.ctx.as_metadata.get(name)
        return value if isinstance(value, str) else ""

    def attestation_headers(self, *, attest: bool = True, **given: str) -> dict[str, str]:
        return self.client.instance.headers(self.as_issuer, **given) if attest else {}

    def _post(
        self,
        endpoint: str,
        form: dict[str, str],
        headers: Callable[[], dict[str, str]],
        sent: str,
        *,
        dpop: bool = True,
    ) -> Exchange:
        """POST a form, with a DPoP proof when `dpop`. A server that asks for a DPoP nonce (RFC 9449 §8) gets the
        request again once, with a proof carrying it and the headers made again (a proof of possession of the
        attestation is good once); the nonce is kept for the requests after."""

        def send() -> Exchange:
            sent_headers = {"Content-Type": "application/x-www-form-urlencoded", **headers()}
            self.last_headers = sent_headers
            if dpop:
                sent_headers["DPoP"] = dpop_proof(self.client.dpop, "POST", endpoint, nonce=self.client.dpop_nonce)
            return self.ctx.http.request("POST", endpoint, content=urlencode(form), headers=sent_headers, sent=sent)

        exchange = send()
        if dpop and exchange.status in (400, 401) and exchange.error_code() == "use_dpop_nonce":
            self.client.dpop_nonce = exchange.header("dpop-nonce") or None
            exchange = send()
        elif exchange.header("dpop-nonce"):
            self.client.dpop_nonce = exchange.header("dpop-nonce")
        return exchange

    def par(
        self,
        pkce: Pkce | None,
        *,
        scope: str | None = None,
        details: list[dict[str, Any]] | None = None,
        state: str = "eudi-probe",
        attest: bool = True,
        headers: dict[str, str] | Callable[[], dict[str, str]] | None = None,
        extra: dict[str, str] | None = None,
        drop: tuple[str, ...] = (),
        dpop: bool = True,
        sent: str = "",
    ) -> Exchange:
        """A pushed authorization request. `headers` replace the attestation headers: a function is called for each
        attempt, so a retry after a DPoP nonce challenge carries a fresh proof of possession with the same deliberate
        change; a dict is sent as it is, retry included (a replay)."""
        endpoint = self.endpoint("pushed_authorization_request_endpoint")
        form: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client.client_id,
            "redirect_uri": self.client.redirect_uri,
            "state": state,
        }
        if pkce is not None:
            form.update(code_challenge=pkce.challenge, code_challenge_method="S256")
        if scope is not None:
            form["scope"] = scope
        if details is not None:
            form["authorization_details"] = json.dumps(details)
        form.update(extra or {})
        form = {k: v for k, v in form.items() if k not in drop}
        if callable(headers):
            made = headers
            return self._post(
                endpoint, form, lambda: {**self.attestation_headers(attest=attest), **made()}, sent, dpop=dpop
            )
        if headers is not None:
            given = dict(headers)
            return self._post(
                endpoint, form, lambda: {**self.attestation_headers(attest=attest), **given}, sent, dpop=dpop
            )
        return self._post(endpoint, form, lambda: self.attestation_headers(attest=attest), sent, dpop=dpop)

    def authorize_url(self, request_uri: str, *, client_id: str | None = None) -> str:
        """The authorization request for a pushed request (RFC 9126 §4), as a browser opens it."""
        query = {"client_id": client_id or self.client.client_id, "request_uri": request_uri}
        return with_query(self.endpoint("authorization_endpoint"), query)

    def authorize(self, request_uri: str, *, client_id: str | None = None) -> Exchange:
        return self.ctx.http.request("GET", self.authorize_url(request_uri, client_id=client_id))

    def login(
        self, request_uri: str, *, cancel: bool = False, extra: dict[str, str] | None = None
    ) -> tuple[dict[str, str] | None, list[Exchange]]:
        """From the authorization request to the redirect back to the wallet: its query parameters, or None when
        the walk did not get there. The redirect is not opened.

        A login command starts at the authorization request itself (`$EUDI_PROBE_AUTHORIZE_URL`), as a browser
        would, so any session the server keeps in cookies is its own; the probe sends nothing to the endpoint."""
        config = self.ctx.config
        if config.login_cmd:
            env = dict(
                os.environ,
                EUDI_PROBE_AUTHORIZE_URL=self.authorize_url(request_uri),
                EUDI_PROBE_LOGIN_CANCEL="1" if cancel else "0",
            )
            done = subprocess.run(config.login_cmd, shell=True, capture_output=True, text=True, timeout=180, env=env)
            lines = [line for line in done.stdout.splitlines() if line.strip()]
            if done.returncode != 0 or not lines:
                self.ctx.notes.append(f"login command failed: rc={done.returncode} {done.stderr[-300:]}")
                return None, []
            return self._back(lines[-1].strip()), []
        fields = config.cancel_fields if cancel else config.login_fields
        if extra and fields is not None and not cancel:  # fields of one login only, such as a hold for review
            fields = {**fields, **extra}
        current = self.authorize(request_uri)
        steps = [current]
        method, body = "GET", ""  # of the request that got `current`: 307 and 308 send them again, as a browser does
        for _ in range(MAX_STEPS):
            if current.status in (301, 302, 303, 307, 308):
                location = urljoin(current.url, current.header("location"))
                back = self._back(location)
                if back is not None:
                    return back, steps
                if current.status in (307, 308) and method == "POST":
                    current = self.ctx.http.request("POST", location, content=body, headers=FORM)
                else:
                    method, body = "GET", ""
                    current = self.ctx.http.request("GET", location)
                steps.append(current)
                continue
            if current.status != 200 or fields is None:
                return None, steps
            form = _Form()
            form.feed(current.body)
            if form.action is None and form.refresh is not None:
                # A page that moves on by itself, as a login service may answer a form with (a new navigation, so the
                # form's CSP form-action does not govern where it goes).
                location = urljoin(current.url, form.refresh)
                back = self._back(location)
                if back is not None:
                    return back, steps
                method, body = "GET", ""
                current = self.ctx.http.request("GET", location)
                steps.append(current)
                continue
            if form.action is None:
                return None, steps
            target = urljoin(current.url, form.action)
            values = form.submitted(fields)
            if form.method.lower() == "post":
                method, body = "POST", urlencode(values)
                current = self.ctx.http.request("POST", target, content=body, headers=FORM)
            else:
                method, body = "GET", ""
                current = self.ctx.http.request("GET", form_get(target, values))
            steps.append(current)
        return None, steps

    def _back(self, location: str) -> dict[str, str] | None:
        parts, mine = urlsplit(location), urlsplit(self.client.redirect_uri)
        if (parts.scheme, parts.netloc, parts.path) != (mine.scheme, mine.netloc, mine.path):
            return None
        return {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}

    def authorized(
        self,
        *,
        scope: str | None = None,
        details: list[dict[str, Any]] | None = None,
        cancel: bool = False,
        extra: dict[str, str] | None = None,
    ) -> Authorization | FlowFailure:
        """PAR, authorize and the login, up to the redirect back, or where the flow stopped."""
        pkce = Pkce.new()
        state = b64u(secrets.token_bytes(12))
        pushed = self.par(pkce, scope=scope, details=details, state=state, sent="PAR")
        uri = (pushed.json() or {}).get("request_uri") if pushed.status == 201 else None
        if not isinstance(uri, str):
            return FlowFailure("PAR was not accepted", [pushed])
        params, steps = self.login(uri, cancel=cancel, extra=extra)
        if params is None:
            return FlowFailure("the login did not lead back to the redirect URI", [pushed, *steps])
        return Authorization(params, pkce, state, [pushed, *steps])

    def token(
        self,
        code: str,
        pkce: Pkce | None,
        *,
        redirect_uri: str | None = None,
        attest: bool = True,
        dpop: bool = True,
        extra: dict[str, str] | None = None,
        drop: tuple[str, ...] = (),
        sent: str = "",
    ) -> Exchange:
        endpoint = self.endpoint("token_endpoint")
        form = {
            "grant_type": CODE_GRANT,
            "code": code,
            "redirect_uri": redirect_uri or self.client.redirect_uri,
            "client_id": self.client.client_id,
        }
        if pkce is not None:
            form["code_verifier"] = pkce.verifier
        form.update(extra or {})
        form = {k: v for k, v in form.items() if k not in drop}
        return self._post(endpoint, form, lambda: self.attestation_headers(attest=attest), sent, dpop=dpop)

    def refresh(self, refresh_token: str, *, attest: bool = True, sent: str = "") -> Exchange:
        endpoint = self.endpoint("token_endpoint")
        form = {"grant_type": REFRESH_GRANT, "refresh_token": refresh_token, "client_id": self.client.client_id}
        return self._post(endpoint, form, lambda: self.attestation_headers(attest=attest), sent)
