"""A scripted wallet for the authorization code flow: wallet attestation, PAR, authorize, the test login and the
token request, with PKCE and DPoP.

Its parts that need no endpoint (PKCE, the attestation and its proof of possession, reading the redirect back to
the wallet, filling in a login form) are tested in `test_codewallet.py`; the full run against cunho in
`test_authorize.py`.

Every request can be broken on purpose through keyword overrides, as the M2 helpers allow, so a negative test
changes one thing and nothing else.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from cunho.jose import b64u
from cunho.service import Issuer
from eudi_probe.jose import EcKey, jws

from .helpers import ISSUER, PID_CONFIG, Wallet
from .pki import WalletProvider

PAR_PATH = "/par"
AUTHORIZE_PATH = "/authorize"
TOKEN_PATH = "/token"
CODE_GRANT = "authorization_code"
REFRESH_GRANT = "refresh_token"
WIA_TYP = "oauth-client-attestation+jwt"
POP_TYP = "oauth-client-attestation-pop+jwt"
CLIENT_ID = "https://wallet-solution.test"  # the WIA sub: one value for every instance of a wallet solution
REDIRECT_URI = "https://wallet.test/callback"
WALLET_STATUS_LIST = "https://wallet-provider.test/status/wia"
MAX_REDIRECTS = 10


@dataclass(frozen=True)
class Pkce:
    """A PKCE pair (RFC 7636 §4.1, §4.2), S256 only."""

    verifier: str
    challenge: str
    method: str = "S256"

    @classmethod
    def random(cls) -> Pkce:
        return cls.of(b64u(secrets.token_bytes(32)))

    @classmethod
    def of(cls, verifier: str) -> Pkce:
        return cls(verifier, b64u(hashlib.sha256(verifier.encode("ascii")).digest()))

    @classmethod
    def rfc7636_appendix_b(cls) -> Pkce:
        """The example of RFC 7636 Appendix B, so a test can check the server against a published vector."""
        return cls("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")


@dataclass(frozen=True)
class Redirect:
    """Where a redirect sends the browser, and its query parameters (each given once)."""

    status: int
    location: str

    @property
    def target(self) -> str:
        parts = urlsplit(self.location)
        return f"{parts.scheme}://{parts.netloc}{parts.path}"

    @property
    def params(self) -> dict[str, str]:
        query = parse_qs(urlsplit(self.location).query, keep_blank_values=True, strict_parsing=False)
        repeated = sorted(k for k, v in query.items() if len(v) != 1)
        if repeated:
            raise AssertionError(f"parameters given more than once: {repeated}")
        return {k: v[0] for k, v in query.items()}


class _Form(HTMLParser):
    """The first form of a page: its action, method and the values of its inputs."""

    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.method = "get"
        self.fields: dict[str, str] = {}
        self._inside = False
        self._done = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k: v or "" for k, v in attrs}
        if tag == "form" and not self._done and self.action is None:
            self.action, self.method, self._inside = values.get("action", ""), values.get("method", "get"), True
        elif tag == "input" and self._inside and values.get("name"):
            if values.get("type") in ("checkbox", "radio") and "checked" not in values:
                return  # as a browser submits the form: an unticked box sends nothing
            self.fields[values["name"]] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._inside:
            self._inside, self._done = False, True


def read_form(html: str) -> tuple[str, str, dict[str, str]]:
    """(action, method, fields) of the first form in `html`. Raises AssertionError when there is none."""
    form = _Form()
    form.feed(html)
    if form.action is None:
        raise AssertionError("the page has no form")
    return form.action, form.method.lower(), form.fields


@dataclass
class CodeWallet(Wallet):
    """A wallet that authenticates with a wallet attestation and runs the authorization code flow."""

    provider: WalletProvider | None = None
    client_id: str = CLIENT_ID
    redirect_uri: str = REDIRECT_URI
    instance_key: EcKey = field(default_factory=EcKey.generate)  # the cnf key of the attestation
    refresh_token: str | None = None
    attestation_ttl: int = 3600
    client_status_offset: int = 60 * 86_400

    # wallet attestation ------------------------------------------------------------------------

    def attestation(self, *, signing_key: EcKey | None = None, **claims: Any) -> str:
        """A wallet instance attestation (OpenID4VCI App. E, draft-07 §5.1, TS3 §2.3.1), signed by the provider's
        WIA signer with its chain in x5c. A claim given as `...` is left out; `_header` replaces the header."""
        assert self.provider is not None, "a CodeWallet needs a wallet provider from the test PKI"
        now = int(self.clock())
        payload: dict[str, Any] = {
            "iss": "https://wallet-provider.test",
            "sub": self.client_id,
            "iat": now,
            "exp": now + self.attestation_ttl,
            "cnf": {"jwk": self.instance_key.public_jwk()},
            "wallet_name": "cunho test wallet",
            "wallet_version": "1.0.0",
            "client_status": {
                "status": {"status_list": {"idx": 3, "uri": WALLET_STATUS_LIST}},
                "exp": now + self.client_status_offset,
            },
        }
        header = claims.pop("_header", None) or {"typ": WIA_TYP, "alg": "ES256", "x5c": self.provider.wia_x5c()}
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not ...}
        return jws(header, payload, signing_key or EcKey(self.provider.wia_signer.key))

    def attestation_pop(self, *, audience: str = ISSUER, signing_key: EcKey | None = None, **claims: Any) -> str:
        """The proof of possession of the attestation's cnf key (draft-07 §5.2)."""
        payload: dict[str, Any] = {
            "iss": self.client_id,
            "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": int(self.clock()),
        }
        header = claims.pop("_header", None) or {"typ": POP_TYP, "alg": "ES256"}
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not ...}
        return jws(header, payload, signing_key or self.instance_key)

    def attestation_headers(
        self, attestation: str | None = None, pop: str | None = None, *, attest: bool = True
    ) -> list[tuple[str, str]]:
        """The two client attestation headers (draft-07 §6.1), or none when `attest` is False."""
        if not attest:
            return []
        return [
            ("OAuth-Client-Attestation", attestation or self.attestation()),
            ("OAuth-Client-Attestation-PoP", pop or self.attestation_pop()),
        ]

    # requests ----------------------------------------------------------------------------------

    def _post_form(
        self,
        path: str,
        form: Mapping[str, str],
        *,
        dpop: str | list[str] | None,
        headers: list[tuple[str, str]],
    ) -> Any:
        sent: list[tuple[str, str]] = [("Content-Type", "application/x-www-form-urlencoded"), *headers]
        for proof in [dpop] if isinstance(dpop, str) else dpop or []:
            sent.append(("DPoP", proof))
        return self.client.post(path, content=urlencode(dict(form)), headers=sent)

    def par(
        self,
        pkce: Pkce,
        *,
        scope: str | None = None,
        authorization_details: list[dict[str, Any]] | None = None,
        state: str | None = None,
        issuer_state: str | None = None,
        dpop: str | list[str] | None = "auto",
        dpop_jkt: str | None = None,
        attest: bool = True,
        headers: list[tuple[str, str]] | None = None,
        extra: dict[str, str] | None = None,
        drop: tuple[str, ...] = (),
    ) -> Any:
        """A pushed authorization request (RFC 9126 §2.1), client-authenticated by the attestation."""
        form: dict[str, str] = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "code_challenge": pkce.challenge,
            "code_challenge_method": pkce.method,
            "state": state or secrets.token_urlsafe(16),
        }
        if scope is not None:
            form["scope"] = scope
        if authorization_details is not None:
            form["authorization_details"] = json.dumps(authorization_details)
        if issuer_state is not None:
            form["issuer_state"] = issuer_state
        if dpop_jkt is not None:
            form["dpop_jkt"] = dpop_jkt
        form.update(extra or {})
        form = {k: v for k, v in form.items() if k not in drop}
        proof = self.dpop("POST", f"{ISSUER}{PAR_PATH}") if dpop == "auto" else dpop
        sent = [*self.attestation_headers(attest=attest), *(headers or [])]
        return self._post_form(PAR_PATH, form, dpop=proof, headers=sent)

    def authorize(self, request_uri: str, *, client_id: str | None = None, extra: dict[str, str] | None = None) -> Any:
        """The browser's visit to the authorization endpoint with a pushed request (RFC 9126 §4)."""
        query = {"client_id": client_id or self.client_id, "request_uri": request_uri, **(extra or {})}
        return self.client.get(f"{AUTHORIZE_PATH}?{urlencode(query)}", follow_redirects=False)

    def login(self, response: Any, fields: Mapping[str, str]) -> Redirect:
        """Follow the browser from the authorization endpoint through the test login back to the wallet.

        Every redirect is followed by hand, so its status code is seen (FAPI 2.0 §5.3.2.2: never 307). A page
        with a form is filled in with `fields` on top of the form's own inputs and submitted. The walk ends at
        the first redirect to the wallet's redirect_uri, which is returned unopened."""
        for _ in range(MAX_REDIRECTS):
            if response.status_code in (301, 302, 303, 307, 308):
                redirect = Redirect(response.status_code, response.headers["location"])
                if redirect.target == Redirect(0, self.redirect_uri).target:
                    return redirect
                response = self.client.get(urljoin(str(response.url), redirect.location), follow_redirects=False)
                continue
            assert response.status_code == 200, f"the login stopped at {response.status_code}: {response.text}"
            action, method, form = read_form(response.text)
            target = urljoin(str(response.url), action)
            values = {**form, **fields}
            if method == "post":
                response = self.client.post(
                    target,
                    content=urlencode(values),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    follow_redirects=False,
                )
            else:
                response = self.client.get(f"{target}?{urlencode(values)}", follow_redirects=False)
        raise AssertionError(f"no redirect to {self.redirect_uri} after {MAX_REDIRECTS} steps")

    def code_token_request(
        self,
        code: str,
        pkce: Pkce,
        *,
        redirect_uri: str | None = None,
        dpop: str | list[str] | None = "auto",
        attest: bool = True,
        extra: dict[str, str] | None = None,
        drop: tuple[str, ...] = (),
    ) -> Any:
        """The token request of the authorization code grant (RFC 6749 §4.1.3, RFC 7636 §4.5)."""
        form = {
            "grant_type": CODE_GRANT,
            "code": code,
            "code_verifier": pkce.verifier,
            "redirect_uri": redirect_uri or self.redirect_uri,
            "client_id": self.client_id,
            **(extra or {}),
        }
        form = {k: v for k, v in form.items() if k not in drop}
        proof = self.dpop("POST", f"{ISSUER}{TOKEN_PATH}") if dpop == "auto" else dpop
        return self._post_form(TOKEN_PATH, form, dpop=proof, headers=self.attestation_headers(attest=attest))

    def refresh_request(
        self,
        refresh_token: str | None = None,
        *,
        dpop: str | list[str] | None = "auto",
        attest: bool = True,
        extra: dict[str, str] | None = None,
    ) -> Any:
        """A refresh token request (RFC 6749 §6), with the attestation (draft-07 §10.3) and DPoP."""
        token = refresh_token or self.refresh_token
        assert token is not None, "no refresh token yet"
        form = {"grant_type": REFRESH_GRANT, "refresh_token": token, "client_id": self.client_id, **(extra or {})}
        proof = self.dpop("POST", f"{ISSUER}{TOKEN_PATH}") if dpop == "auto" else dpop
        return self._post_form(TOKEN_PATH, form, dpop=proof, headers=self.attestation_headers(attest=attest))

    # the whole flow ----------------------------------------------------------------------------

    def get_code_token(
        self, login_fields: Mapping[str, str], *, scope: str | None = None, pkce: Pkce | None = None
    ) -> dict[str, Any]:
        """PAR, authorize, the test login and the token request; keeps the access and refresh tokens."""
        pkce = pkce or Pkce.random()
        state = secrets.token_urlsafe(16)
        pushed = self.par(pkce, scope=scope, state=state)
        assert pushed.status_code == 201, pushed.text
        back = self.login(self.authorize(pushed.json()["request_uri"]), login_fields)
        params = back.params
        assert params.get("state") == state and params.get("iss") == ISSUER, params
        tokens = self.code_token_request(params["code"], pkce)
        assert tokens.status_code == 200, tokens.text
        body: dict[str, Any] = tokens.json()
        self.token = body["access_token"]
        self.refresh_token = body.get("refresh_token")
        return body


# helpers for tests of the flow ---------------------------------------------------------------------

LOGIN = {"person": "ana", "action": "login"}
IBAN = "eu.europa.ec.eudi.iban_sd_jwt_vc"
CANCEL = {"person": "ana", "action": "cancel"}


def pid_scope(issuer: Issuer) -> str:
    config = issuer.configs.get(PID_CONFIG)
    assert config is not None
    return str(config["scope"])


def pushed(wallet: CodeWallet, issuer: Issuer, pkce: Pkce | None = None, **kwargs: Any) -> tuple[str, str]:
    """A successful PAR: its request_uri and the state it carried."""
    kwargs.setdefault("scope", pid_scope(issuer))
    state = kwargs.pop("state", "st-1")
    response = wallet.par(pkce or Pkce.random(), state=state, **kwargs)
    assert response.status_code == 201, response.text
    return str(response.json()["request_uri"]), state


def code_of(wallet: CodeWallet, issuer: Issuer, pkce: Pkce, fields: dict[str, str] = LOGIN, **kwargs: Any) -> str:
    request_uri, _ = pushed(wallet, issuer, pkce, **kwargs)
    back = wallet.login(wallet.authorize(request_uri), fields)
    return back.params["code"]
