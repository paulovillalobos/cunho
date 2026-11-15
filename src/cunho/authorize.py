"""The authorization code flow (HAIP 1.0 §4, FAPI 2.0 §5.3.2): pushed requests, the authorization endpoint, the
operator's login, and the exchange of the code for an access token.

The steps, each a sealed store row taken once (the M3 plan's rule: single use is one transaction):

1. `POST /par`: the wallet authenticates with its attestation, and cunho checks the request as the
   authorization endpoint would (RFC 9126 §2.1). It answers with a `request_uri` that lives under 600 s.
2. `GET /authorize?client_id&request_uri`: the pushed request is taken, and the browser is sent to the
   operator's login with a single-use `login_state`.
3. `POST /admin/logins/{login_state}`: the operator's login service reports who logged in, with the same
   `subject` body as an offer, or that the login was denied. cunho creates the subject as it does for an offer
   (`Issuer.complete_login`), and answers with the URL to send the browser back to, which carries a fresh
   completion secret: the wallet knows login_state, so login_state alone must not yield the code.
4. `GET /authorize/continue?login_state&completion`: the browser comes back, and is sent to the wallet's
   `redirect_uri` with `code`, `state` and `iss`, or with `error=access_denied`, `state` and `iss`. Always 303.
5. `POST /token` with `grant_type=authorization_code`: the attestation again, the same wallet solution and
   instance key, DPoP (with the key bound at PAR when there was one), PKCE and the same `redirect_uri`. The code
   is taken in the transaction that writes the access token; a second use finds the "spent" row written there
   and revokes the token the first use yielded.

Errors before the wallet's redirect URI is known and trusted are answered to the browser as JSON, never
redirected (RFC 6749 §4.1.2.1).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NoReturn
from urllib.parse import quote, urlencode

from cunho.client_auth import ATTESTATION_HEADER, POP_HEADER, ClientAuth, ClientIdentity
from cunho.errors import ConfigError
from cunho.jose import ALGORITHMS, b64u, sha256_b64u, strict_json
from cunho.keyring import Keyring, same
from cunho.metadata import PRE_AUTH_GRANT, Configurations
from cunho.oauth import Dpop, Tokens, opened, seal
from cunho.rules import enforce, implements, refuse
from cunho.settings import MAX_LOGIN_TTL, MAX_PAR_TTL, Settings
from cunho.store import Store

CODE_GRANT = "authorization_code"
REFRESH_GRANT = "refresh_token"
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"
OPENID_CREDENTIAL = "openid_credential"
CODE_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")  # BASE64URL(SHA-256(...)) is always 43 characters
CODE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")  # RFC 7636 §4.1
JKT = re.compile(r"[A-Za-z0-9_-]{43}")
MAX_STATE = 2048  # FAPI 2.0 §5.3.2.2 note 4: a state that carries a JWT can pass 1000 characters
MAX_DETAILS = 16
MAX_OPENS = 8  # logins one request_uri can start before one completes (FAPI 2.0 SP §5.3.2.2 note 3)
LOGIN_STATE = "login_state"
COMPLETION = "completion"


def offer_ref(issuer_state: str) -> str:
    """The reference of a code-flow offer by its issuer_state, as create_offer returns it and a login names it."""
    return _hash(issuer_state)[:32]


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def fail(rule: str, reason: str) -> NoReturn:
    refuse(rule, "invalid_request", reason)


def redirect_to(base: str, params: Mapping[str, str | None]) -> str:
    """`base` with `params` added to its query, keeping a query it already has (RFC 6749 §3.1.2)."""
    query = urlencode({k: v for k, v in params.items() if v is not None}, quote_via=quote)
    if "?" not in base:
        return f"{base}?{query}"
    # After the first "?" is the query. An empty one (`...callback?`) or one that ends with "&" takes the parameters
    # as they are; any other, also one whose last value ends in "?", takes an "&" first (the second reviewer).
    existing = base.split("?", 1)[1]
    return f"{base}{'' if existing == '' or existing.endswith('&') else '&'}{query}"


class Authorization:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        keyring: Keyring,
        configs: Configurations,
        client_auth: ClientAuth,
        dpop: Dpop,
        tokens: Tokens,
        clock: Callable[[], float],
        on_code_reuse: Callable[[str, str, str], None],
        on_refresh_granted: Callable[[str, str, int], None],
    ) -> None:
        self._settings = settings
        self._store = store
        self._keyring = keyring
        self._configs = configs
        self._client_auth = client_auth
        self._dpop = dpop
        self._tokens = tokens
        self._clock = clock
        self._on_code_reuse = on_code_reuse  # (subject_ref, token key, refresh key): revoke what a reused code yielded
        self._on_refresh_granted = on_refresh_granted  # (subject_ref, offer_id, ttl): keep the subject for refresh
        self.scopes = self._scope_map(configs)
        self.test_login = False  # set by the issuer when the built-in test login serves fixture persons

    @staticmethod
    @implements("VCI.SCOPE_TO_CONFIG")
    def _scope_map(configs: Configurations) -> dict[str, str]:
        """One scope names one configuration (HAIP 1.0 §4.3), so a scope request is never ambiguous."""
        scopes: dict[str, str] = {}
        for config_id, config in configs.issuable().items():
            scope = config.get("scope")
            if scope in scopes:
                raise ConfigError(f"{config_id} and {scopes[scope]} publish the same scope {scope!r}")
            scopes[str(scope)] = config_id
        return scopes

    # metadata ----------------------------------------------------------------------------------

    @implements("OAUTH.AS_METADATA_M3", "OAUTH.AUTH_CODE_AND_PAR", "OAUTH.PKCE_S256")
    def metadata(self, settings: Settings) -> dict[str, Any]:
        """The authorization server metadata of the code flow (RFC 8414 §2, RFC 9126 §5, RFC 9207 §3,
        draft-07 §10.1). Pre-authorized offers stay anonymous, so `none` stays beside the attestation."""
        algs = sorted(ALGORITHMS)
        return {
            "authorization_endpoint": settings.authorization_endpoint,
            "pushed_authorization_request_endpoint": settings.par_endpoint,
            "require_pushed_authorization_requests": True,
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": [CODE_GRANT, REFRESH_GRANT, PRE_AUTH_GRANT],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth", "none"],
            "client_attestation_signing_alg_values_supported": algs,
            "client_attestation_pop_signing_alg_values_supported": algs,
            "authorization_response_iss_parameter_supported": True,
        }

    # offers ------------------------------------------------------------------------------------

    @implements("VCI.OFFER.AUTH_CODE_GRANT", "VCI.ISSUER_STATE")
    def code_offer(self, configuration_ids: list[str]) -> dict[str, Any]:
        """An issuer-initiated offer for the code flow (OpenID4VCI §4.1.1). Its `issuer_state` is single use and
        bound to the configurations offered; it never says who the user is, which the login decides."""
        issuer_state = b64u(secrets.token_bytes(32))
        with self._store.atomic():  # the expiry under the MAC is read in the transaction that stores it (CX-29)
            key = _hash(issuer_state)
            record = {"configuration_ids": configuration_ids, "exp": int(self._clock()) + self._settings.offer_ttl}
            self._store.put(
                "issuer-state", key, seal(self._keyring, "issuer-state", key, record), self._settings.offer_ttl
            )
        offer = {
            "credential_issuer": self._settings.issuer_url,
            "credential_configuration_ids": configuration_ids,
            "grants": {CODE_GRANT: {"issuer_state": issuer_state}},
        }
        link = "openid-credential-offer://?credential_offer=" + quote(json.dumps(offer, separators=(",", ":")), safe="")
        # The login a wallet starts from this offer names it by this reference (GET /admin/logins/{login_state}),
        # so the operator's pages can tell which of their offers a login came from.
        return {"credential_offer": offer, "offer_link": link, "offer_ref": offer_ref(issuer_state)}

    # PAR ---------------------------------------------------------------------------------------

    @implements("OAUTH.PAR_REQUEST", "OAUTH.PAR_REQUEST_URI_ONCE", "PRIV.UNIQUE_ELEMENTS_CSPRNG")
    def par(
        self, form: Mapping[str, list[str]], headers: Callable[[str], list[str]]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """A pushed authorization request (RFC 9126 §2). The client is authenticated before anything is read
        beyond its client_id, and nothing is written for a client that fails (the plan's R7)."""
        one = _one_of(form, "OAUTH.PAR_REQUEST")
        client_id = one("client_id")
        identity = self._client_auth.authenticate(headers(ATTESTATION_HEADER), headers(POP_HEADER), client_id)
        enforce(client_id is not None, "OAUTH.PAR_REQUEST", "invalid_request", "client_id is required")
        if "request_uri" in form:
            fail("OAUTH.PAR_REQUEST", "request_uri must not be pushed (RFC 9126 §2.1)")
        response_type = one("response_type")
        enforce(response_type is not None, "OAUTH.RESPONSE_TYPE_CODE", "invalid_request", "response_type is required")
        enforce(
            response_type == "code",
            "OAUTH.RESPONSE_TYPE_CODE",
            "unsupported_response_type",
            "only response_type=code is supported",
        )
        enforce(
            one("response_mode") in (None, "query"),
            "OAUTH.RESPONSE_TYPE_CODE",
            "invalid_request",
            "only response_mode=query is supported",
        )  # the metadata says query only; another mode is refused, never answered as query (the second reviewer)
        redirect_uri = self._redirect_uri(identity, one("redirect_uri"))
        challenge = self._challenge(one("code_challenge"), one("code_challenge_method"))
        state = one("state")
        if state is not None and not 0 < len(state) <= MAX_STATE:
            fail("OAUTH.PAR_REQUEST", f"state must be 1 to {MAX_STATE} characters")
        scope = one("scope")
        configuration_ids, details = self._requested(scope, one("authorization_details"))
        scopes = [s for s in dict.fromkeys((scope or "").split(" ")) if s in self.scopes] if scope is not None else None
        issuer_state = one("issuer_state")
        dpop_jkt = self._dpop_binding(one("dpop_jkt"), headers("dpop"))
        request_uri = REQUEST_URI_PREFIX + b64u(secrets.token_bytes(32))
        ttl = self._settings.par_ttl
        with self._store.atomic():
            if issuer_state is not None:
                self._take_issuer_state(issuer_state, configuration_ids)
            key = _hash(request_uri)
            record = {
                "client": identity.sub,
                "cnf": identity.cnf_jkt,
                "client_status_exp": identity.status_exp,
                "client_status": identity.status,
                "wallet": identity.wallet,  # for the login service's consent screen (GET /admin/logins/{login_state})
                "offer_ref": offer_ref(issuer_state) if issuer_state is not None else None,
                "redirect_uri": redirect_uri,
                "state": state,
                "challenge": challenge,
                "dpop_jkt": dpop_jkt,
                "configuration_ids": configuration_ids,
                "details": details,
                "scopes": scopes,
                "exp": int(self._clock()) + ttl,
            }
            self._store.put("par", key, seal(self._keyring, "par-record", key, record), ttl)
        return {"request_uri": request_uri, "expires_in": ttl}, {"Cache-Control": "no-store"}

    @implements("OAUTH.REDIRECT_URI_EXACT")
    def _redirect_uri(self, identity: ClientIdentity, value: str | None) -> str:
        """Required, and one of the URIs the operator allows for this wallet solution, compared as exact strings
        (RFC 9700 §2.1). Wallets are not registered one by one: the attested `sub` names the solution."""
        enforce(value is not None, "OAUTH.REDIRECT_URI_EXACT", "invalid_request", "redirect_uri is required")
        allowed = self._settings.redirect_uris.get(identity.sub, ())
        enforce(
            value in allowed,
            "OAUTH.REDIRECT_URI_EXACT",
            "invalid_request",
            "redirect_uri is not one the operator allows for this wallet",
        )
        return str(value)

    def _challenge(self, challenge: str | None, method: str | None) -> str:
        enforce(
            challenge is not None,
            "OAUTH.PKCE_VERIFIER",
            "invalid_request",
            "code_challenge is required (RFC 7636 §4.4.1)",
        )
        enforce(
            method == "S256",
            "OAUTH.PKCE_S256",
            "invalid_request",
            "code_challenge_method must be S256",
        )
        enforce(
            bool(CODE_CHALLENGE.fullmatch(str(challenge))),
            "OAUTH.PKCE_VERIFIER",
            "invalid_request",
            "code_challenge must be a base64url SHA-256 value",
        )
        return str(challenge)

    @implements("VCI.AUTHZ_DETAILS")
    def _requested(self, scope: str | None, details: str | None) -> tuple[list[str], list[str]]:
        """The configurations asked for, by scope (unknown scopes ignored, OpenID4VCI §5.1.2) and by
        authorization_details (§5.1.1). Returns them all, and those asked for by authorization_details."""
        by_details = self._details(details) if details is not None else []
        by_scope = [self.scopes[s] for s in (scope or "").split(" ") if s in self.scopes]
        requested = list(dict.fromkeys([*by_details, *by_scope]))
        enforce(
            bool(requested),
            "VCI.SCOPE_TO_CONFIG",
            "invalid_scope",
            "the request names no credential configuration this issuer offers",
        )
        return requested, list(dict.fromkeys(by_details))

    def _details(self, details: str) -> list[str]:
        """The configurations an authorization_details parameter names (OpenID4VCI §5.1.1), each once."""
        try:
            parsed = strict_json(details)
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if not isinstance(parsed, list) or not 0 < len(parsed) <= MAX_DETAILS:
            refuse(
                "VCI.AUTHZ_DETAILS",
                "invalid_authorization_details",
                f"authorization_details must be a JSON array of 1 to {MAX_DETAILS} objects",
            )
        return list(dict.fromkeys(self._detail(item) for item in parsed))

    def _detail(self, item: Any) -> str:
        def bad(reason: str) -> NoReturn:
            refuse("VCI.AUTHZ_DETAILS", "invalid_authorization_details", reason)

        if not isinstance(item, dict) or item.get("type") != OPENID_CREDENTIAL:
            bad(f"each authorization_details entry must be an object of type {OPENID_CREDENTIAL}")
        config_id = item.get("credential_configuration_id")
        if not isinstance(config_id, str) or self._configs.get(config_id) is None:
            bad("credential_configuration_id names no configuration this issuer offers")
        locations = item.get("locations")
        if locations is not None and locations != [self._settings.issuer_url]:
            bad("locations must name this credential issuer only")
        return config_id

    @implements("OAUTH.CODE_DPOP_BOUND")
    def _dpop_binding(self, dpop_jkt: str | None, proofs: list[str]) -> str | None:
        """RFC 9449 §10.1: a dpop_jkt parameter, or a DPoP proof on the PAR request, binds the code to that key;
        when both are sent they must name the same key."""
        if dpop_jkt is not None and not JKT.fullmatch(dpop_jkt):
            refuse("OAUTH.CODE_DPOP_BOUND", "invalid_request", "dpop_jkt must be a JWK SHA-256 thumbprint")
        if not proofs:
            return dpop_jkt
        jkt = self._dpop.verify(proofs, "POST", self._settings.par_endpoint, resource=False)
        if dpop_jkt is not None and not same(dpop_jkt, jkt):
            refuse("OAUTH.CODE_DPOP_BOUND", "invalid_dpop_proof", "dpop_jkt does not match the DPoP proof key")
        return jkt

    def _take_issuer_state(self, issuer_state: str, configuration_ids: list[str]) -> None:
        """Inside the PAR transaction: an issuer_state from cunho's own offer, used once, for what it offered.
        It may have been injected by an attacker (OpenID4VCI §5.1.3), so it decides only what may be asked for."""
        key = _hash(issuer_state)
        offer = opened(self._keyring, "issuer-state", key, self._store.take("issuer-state", key), self._clock())
        enforce(
            offer is not None,
            "VCI.ISSUER_STATE",
            "invalid_request",
            "issuer_state is unknown, expired or already used",
        )
        assert offer is not None
        enforce(
            set(configuration_ids) <= set(offer["configuration_ids"]),
            "VCI.ISSUER_STATE",
            "invalid_request",
            "the request asks for a configuration its offer did not offer",
        )

    # authorization endpoint ------------------------------------------------------------------

    @implements("OAUTH.PAR_REQUIRED")
    def authorize(self, query: Mapping[str, list[str]]) -> str:
        """The authorization endpoint (RFC 9126 §4): only a pushed request, by its request_uri, from the client that
        pushed it. Returns where to send the browser: the login, with a fresh login_state.

        The request_uri can be opened again until a login it started completes, which spends it (FAPI 2.0 SP
        §5.3.2.2 note 3: a person who reloads the page, or comes back to it, is not turned away), at most
        MAX_OPENS times."""
        one = _one_of(query, "OAUTH.PAR_REQUIRED")
        request_uri = one("request_uri")
        enforce(
            request_uri is not None,
            "OAUTH.PAR_REQUIRED",
            "invalid_request",
            "authorization requests must be pushed first (RFC 9126); send client_id and request_uri",
        )
        client_id = one("client_id")
        enforce(client_id is not None, "OAUTH.PAR_REQUIRED", "invalid_request", "client_id is required")
        key = _hash(str(request_uri))
        pushed = opened(self._keyring, "par-record", key, self._store.get("par", key), self._clock())
        enforce(
            pushed is not None,
            "OAUTH.PAR_REQUEST_URI_ONCE",
            "invalid_request",
            "request_uri is unknown, expired or already used",
        )
        assert pushed is not None
        # Checked before anything is counted, so a client that is not the one who pushed it cannot use it up.
        enforce(
            same(str(client_id), pushed["client"]),
            "OAUTH.PAR_REQUEST_URI_ONCE",
            "invalid_request",
            "request_uri was pushed by another client",
        )
        login = self._settings.login_url or (self._settings.test_login_endpoint if self.test_login else None)
        enforce(
            login is not None,
            "ISS.IDPROOF.PLUG_REQUIRED",
            "temporarily_unavailable",
            "this deployment has no login service configured",
            503,
        )
        assert login is not None
        login_state = b64u(secrets.token_bytes(32))
        with self._store.atomic():
            enforce(
                self._store.get("par", key) is not None,
                "OAUTH.PAR_REQUEST_URI_ONCE",
                "invalid_request",
                "request_uri is unknown, expired or already used",
            )  # again inside the transaction: a login that completed meanwhile spent it
            enforce(
                self._store.incr("par-opens", key, self._settings.par_ttl) <= MAX_OPENS,
                "OAUTH.PAR_REQUEST_URI_ONCE",
                "invalid_request",
                "request_uri was opened too many times",
            )
            login_key = _hash(login_state)
            ttl = self._settings.login_ttl
            record = {**{k: v for k, v in pushed.items() if k != "exp"}, "par": key, "exp": int(self._clock()) + ttl}
            self._store.put("login", login_key, seal(self._keyring, "login-record", login_key, record), ttl)
        return redirect_to(login, {LOGIN_STATE: login_state})

    # the login ---------------------------------------------------------------------------------

    def pending_login(self, login_state: str) -> dict[str, Any] | None:
        """The pushed request a login_state stands for, while its login is not reported yet. Any string is looked up
        by its hash, so one cunho did not hand out finds nothing."""
        key = _hash(login_state)
        return opened(self._keyring, "login-record", key, self._store.get("login", key), self._clock())

    def reportable_login(self, login_state: str) -> dict[str, Any] | None:
        """The pending login, unless another login started from the same pushed request completed first, after
        which its result can no longer be reported (finish_login): nobody is asked to agree to it (the second
        reviewer)."""
        pending = self.pending_login(login_state)
        if pending is None:
            return None
        # A login started before request_uris could be opened again names none: "None" is never a key.
        if self._store.get("par-done", str(pending.get("par"))) is not None:
            return None
        return pending

    def finish_login(self, login_state: str, result: dict[str, Any]) -> str | None:
        """Inside the caller's transaction: take the pending login and keep its result for the browser's return.
        Returns the URL the login service sends the browser to, with a fresh completion secret that only the login
        service learns; None when another report took the login first, or another login started from the same
        request_uri completed first. Completing, by a login or a denial, spends the request_uri (FAPI 2.0 SP
        §5.3.2.2 note 3)."""
        key = _hash(login_state)
        pending = opened(self._keyring, "login-record", key, self._store.take("login", key), self._clock())
        if pending is None:
            return None
        par = pending.pop("par", None)  # None for a login started before request_uris could be opened again
        if par is not None:
            # Marked as long as a login started from it can live: its last opening, then a login's life. By the
            # longest both may be set to, not by their settings now: after a restart with shorter ones the mark ran
            # out while another login from the same request_uri still lived, and that one completed too (the
            # security review; as CX-28 for claims).
            if not self._store.add("par-done", par, 1, MAX_PAR_TTL + MAX_LOGIN_TTL):
                return None
            self._store.delete("par", par)
        completion = b64u(secrets.token_bytes(32))
        ttl = self._settings.login_ttl
        record = {
            **{k: v for k, v in pending.items() if k != "exp"},
            **result,
            "completion": _hash(completion),
            "exp": int(self._clock()) + ttl,
        }
        self._store.put("login-done", key, seal(self._keyring, "login-done", key, record), ttl)
        return redirect_to(self._settings.continue_endpoint, {LOGIN_STATE: login_state, COMPLETION: completion})

    @implements("OAUTH.AUTHZ_RESPONSE_ISS", "OAUTH.ACCESS_DENIED", "OAUTH.REDIRECT_303")
    def resume(self, query: Mapping[str, list[str]]) -> str:
        """The browser's return from the login (`/authorize/continue`). Returns the wallet's redirect URI with a
        code, or with access_denied, always with state and iss (RFC 9207 §2, RFC 6749 §4.1.2.1)."""
        one = _one_of(query, "OAUTH.ACCESS_DENIED")
        login_state, completion = one(LOGIN_STATE), one(COMPLETION)
        enforce(
            login_state is not None,
            "OAUTH.ACCESS_DENIED",
            "invalid_request",
            "login_state is required",
        )
        assert login_state is not None
        key = _hash(login_state)
        code = b64u(secrets.token_bytes(32))
        with self._store.atomic():
            done = opened(self._keyring, "login-done", key, self._store.get("login-done", key), self._clock())
            if done is None:
                pending = self.pending_login(login_state) is not None
                refuse(
                    "OAUTH.ACCESS_DENIED",
                    "invalid_request",
                    "the login is not finished yet" if pending else "login_state is unknown, expired or used",
                )
            # The wallet that pushed the request knows login_state, so it is not enough to collect the code: the
            # browser must bring the secret the login service received when it reported the login, which only the
            # person's browser is sent on to (the second reviewer).
            enforce(
                isinstance(completion, str) and same(_hash(completion), done["completion"]),
                "OAUTH.ACCESS_DENIED",
                "invalid_request",
                "this login was not completed in this browser",
            )
            self._store.delete("login-done", key)
            params: dict[str, str | None] = {"state": done["state"], "iss": self._settings.issuer_url}
            if done.get("denied"):
                return redirect_to(done["redirect_uri"], {"error": "access_denied", **params})
            code_key = _hash(code)
            ttl = self._settings.code_ttl
            record = {
                **{k: v for k, v in done.items() if k not in ("exp", "state", "denied", "completion")},
                "exp": int(self._clock()) + ttl,
            }
            self._store.put("code", code_key, seal(self._keyring, "code-record", code_key, record), ttl)
            # A token can now be got only with this code, for as long as it lives (GET /admin/offers/{subject_ref}).
            self._store.put("subject-offer", done["subject_ref"], record["exp"], ttl)
        return redirect_to(done["redirect_uri"], {"code": code, **params})

    # the code exchange -------------------------------------------------------------------------

    @implements("OAUTH.CODE_ONCE_60S", "VCI.AUTHZ_DETAILS")
    def exchange(
        self, one: Callable[[str], str | None], dpop: Sequence[str], headers: Callable[[str], list[str]]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """The token request of the code grant (RFC 6749 §4.1.3, RFC 7636 §4.6, RFC 9449 §10)."""
        client_id = one("client_id")
        identity = self._client_auth.authenticate(headers(ATTESTATION_HEADER), headers(POP_HEADER), client_id)
        code = one("code")
        enforce(bool(code), "OAUTH.AUTH_CODE_AND_PAR", "invalid_request", "code is required")
        verifier = one("code_verifier")
        # Every code was issued against a code_challenge, so a request without the verifier cannot redeem it: the
        # grant does not verify (RFC 7636 §4.6; the OIDF suite asks for invalid_grant). One sent malformed is a
        # bad request (RFC 6749 §5.2).
        enforce(
            verifier is not None,
            "OAUTH.PKCE_VERIFIER",
            "invalid_grant",
            "code_verifier is required: the code was issued for a code_challenge",
        )
        assert verifier is not None
        enforce(
            bool(CODE_VERIFIER.fullmatch(verifier)),
            "OAUTH.PKCE_VERIFIER",
            "invalid_request",
            "code_verifier must be 43 to 128 unreserved characters (RFC 7636 §4.1)",
        )
        redirect_uri = one("redirect_uri")
        enforce(redirect_uri is not None, "OAUTH.REDIRECT_URI_EXACT", "invalid_request", "redirect_uri is required")
        jkt = self._dpop.verify(dpop, "POST", self._settings.token_endpoint, resource=False)
        key = _hash(str(code))
        row = opened(self._keyring, "code-record", key, self._store.get("code", key), self._clock())
        # A code used before is refused, and revokes what its first use yielded, only when the request carries
        # what that use proved: the client, its instance key, the DPoP key, the verifier and the redirect URI.
        # Knowing a used code alone must not let another wallet cancel the token (the second reviewer).
        spent = None if row is not None else self._spent(key)
        bound = row if row is not None else spent
        if bound is not None:
            self._check(bound, identity, jkt, str(verifier), str(redirect_uri))
        narrowed = self._narrowed(one("authorization_details"), row)
        token, token_key = self._tokens.new_token()
        refresh, refresh_key = self._tokens.new_token()
        identifiers: dict[str, str] = {}
        configuration_ids: list[str] = []
        reused: dict[str, Any] | None = None
        with self._store.atomic():
            taken = None
            if row is not None:
                taken = opened(self._keyring, "code-record", key, self._store.take("code", key), self._clock())
            if taken is None:
                again = self._spent(key)
                if again is not None:
                    # A redemption that ran alongside this one wrote it: its bindings, the DPoP key it used
                    # included, are checked before its token is revoked, as the spent row's are above.
                    self._check(again, identity, jkt, str(verifier), str(redirect_uri))
                    reused = again
            else:
                configuration_ids = narrowed or taken["configuration_ids"]
                if narrowed:
                    # What the subject can still yield is what this token covers: the code is spent, so the
                    # configurations left out can no longer be issued (the second reviewer).
                    self._store.put(
                        "subject-open", taken["subject_ref"], configuration_ids, self._settings.access_token_ttl
                    )
                    self._store.put(
                        "subject-configs", taken["subject_ref"], configuration_ids, self._settings.subject_window
                    )
                if taken["details"] or narrowed:
                    identifiers = {b64u(secrets.token_bytes(16)): c for c in configuration_ids}
                grant = {
                    "offer_id": taken["offer_id"],
                    "jkt": jkt,
                    "configuration_ids": configuration_ids,
                    "subject_ref": taken["subject_ref"],
                    "client": identity.sub,
                    # The earlier end of the two attestations' status periods: the one at PAR and the one that
                    # authenticates this request (TS3 v1.5.2 §2.4.3).
                    "client_status_exp": _earlier(taken["client_status_exp"], identity.status_exp),
                    # Both attestations' references: either one revoked revokes what this token yields (LC_GEN-4).
                    "client_status": _distinct(taken.get("client_status"), identity.status),
                    # The wallet that redeems the code; the one at PAR is the same client (same sub and key).
                    "wallet": identity.wallet,
                    "identifiers": identifiers,
                    "review": taken.get("review") is True,
                    "refresh_exp": int(self._clock()) + self._settings.refresh_token_ttl,
                }
                self._tokens.store_token(token_key, grant)
                # Not the DPoP key: a refreshed access token is bound to the key shown at the refresh (RFC 9449 §5).
                bound = {k: v for k, v in grant.items() if k != "jkt"}
                self._store_refresh(refresh_key, {**bound, "cnf": identity.cnf_jkt, "scopes": taken.get("scopes")})
                # The record outlives what the code yielded: a replay while the refresh token or the last token
                # it gives is alive still ends them (the second reviewer).
                ttl = max(self._settings.code_ttl, self._settings.refresh_token_ttl + self._settings.access_token_ttl)
                kept = {k: taken[k] for k in ("client", "cnf", "challenge", "redirect_uri", "subject_ref")}
                # The DPoP key the token is bound to, whether or not PAR bound the code to one: a replay must
                # prove it too before it revokes that token (the second reviewer).
                record = {
                    **kept,
                    "dpop_jkt": jkt,
                    "token": token_key,
                    "refresh": refresh_key,
                    "exp": int(self._clock()) + ttl,
                }
                self._store.put("code-spent", key, seal(self._keyring, "code-spent", key, record), ttl)
                # Where the login's two long-lived rows are, for the day its subject is closed (Issuer._close_subject):
                # they name the subject and the wallet instance that logged in, and nothing can use them after that.
                self._store.put("subject-login", taken["subject_ref"], {"refresh": refresh_key, "code": key}, ttl)
        if reused is not None:
            # RFC 6749 §4.1.2: revoke what the first use yielded. The token row goes, and the subject of the login
            # is closed, which the issuance transaction checks, so a credential request already under way with
            # that token is stopped too (the second reviewer).
            self._on_code_reuse(reused["subject_ref"], reused["token"], reused["refresh"])
        if taken is None:
            enforce(
                spent is None and row is None,
                "OAUTH.CODE_ONCE_60S",
                "invalid_grant",
                "the authorization code was already used",
            )
            refuse("VCI.TOKEN.INVALID_GRANT", "invalid_grant", "unknown or expired authorization code")
        extra = self._granted(identifiers, taken.get("scopes"), configuration_ids)
        extra["refresh_token"] = refresh
        return self._tokens.response(token, extra)

    def _granted(
        self, identifiers: dict[str, str], scopes: list[str] | None, configuration_ids: list[str]
    ) -> dict[str, Any]:
        """What a token response says the token covers: authorization_details with credential identifiers, and the
        scope granted (RFC 6749 §5.1), which differs from the one asked for when unknown scopes were ignored or
        the request was narrowed."""
        extra: dict[str, Any] = {}
        if identifiers:
            extra["authorization_details"] = [
                {
                    "type": OPENID_CREDENTIAL,
                    "credential_configuration_id": config_id,
                    "credential_identifiers": [identifier],
                }
                for identifier, config_id in identifiers.items()
            ]
        if scopes is not None:
            # A scope of the authorization that names no configuration any more (one unpublished since the login)
            # is granted nothing, not looked up as if it had to be there (the security review).
            granted = [s for s in scopes if self.scopes.get(s) in configuration_ids]
            if granted:
                extra["scope"] = " ".join(granted)
        return extra

    # refresh tokens ------------------------------------------------------------------------------

    def _store_refresh(self, refresh_key: str, grant: dict[str, Any]) -> None:
        """Inside the code exchange's transaction: the refresh token's row, sealed, with its own exp, and the
        subject kept for it (decision 2: the data stays in the vault for the refresh token's life)."""
        ttl = self._settings.refresh_token_ttl
        record = {**grant, "exp": grant["refresh_exp"]}
        self._store.put("refresh", refresh_key, seal(self._keyring, "refresh-record", refresh_key, record), ttl)
        self._on_refresh_granted(grant["subject_ref"], grant["offer_id"], ttl)

    @implements("BATCH.REISSUANCE", "OAUTH.REFRESH_BOUND", "BATCH.REISSUE_SAME_WALLET_UNIT", "BATCH.SILENT_REISSUANCE")
    def refresh(
        self, one: Callable[[str], str | None], dpop: Sequence[str], headers: Callable[[str], list[str]]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """The refresh token grant (RFC 6749 §6), for re-issuance (OpenID4VCI §13.5, ARF ISSU_63). The refresh
        token is bound to the attested client and its instance key (draft-07 §10.3), so a re-issued credential
        goes to the same wallet unit (ARF ISSU_65). It is not bound to a DPoP key: an authenticated client's refresh
        token is sender-constrained by that authentication (RFC 9449 §5), and the new access token is bound to the
        DPoP key shown now. It is not rotated (FAPI 2.0 §5.3.2.1 item 9): each use gives a new access token for
        what the authorization covered, with no login and nothing asked of the user (ARF ISSU_42)."""
        client_id = one("client_id")
        identity = self._client_auth.authenticate(headers(ATTESTATION_HEADER), headers(POP_HEADER), client_id)
        refresh = one("refresh_token")
        enforce(bool(refresh), "OAUTH.REFRESH_BOUND", "invalid_request", "refresh_token is required")
        jkt = self._dpop.verify(dpop, "POST", self._settings.token_endpoint, resource=False)
        key = _hash(str(refresh))
        row = opened(self._keyring, "refresh-record", key, self._store.get("refresh", key), self._clock())
        enforce(row is not None, "VCI.TOKEN.INVALID_GRANT", "invalid_grant", "unknown or expired refresh token")
        assert row is not None
        enforce(
            same(identity.sub, row["client"]),
            "OAUTH.REFRESH_BOUND",
            "invalid_grant",
            "the refresh token was issued to another client",
        )
        enforce(
            same(identity.cnf_jkt, row["cnf"]),
            "BATCH.REISSUE_SAME_WALLET_UNIT",
            "invalid_grant",
            "the refresh token was issued to another wallet instance",
        )
        enforce(
            self._store.get("subject-closed", row["subject_ref"]) is None,
            "VCI.TOKEN.INVALID_GRANT",
            "invalid_grant",
            "this login's subject was revoked or erased",
        )  # checked again in the issuance transaction, as for every token
        configuration_ids = self._refreshed(one("scope"), one("authorization_details"), row)
        known = dict(row["identifiers"]) if row["identifiers"] else {}
        identifiers: dict[str, str] = {}
        if known or one("authorization_details") is not None:
            by_config = {c: i for i, c in known.items()}
            identifiers = {by_config.get(c) or b64u(secrets.token_bytes(16)): c for c in configuration_ids}
        token, token_key = self._tokens.new_token()
        self._tokens.store_token(
            token_key,
            {
                "offer_id": row["offer_id"],
                "jkt": jkt,
                "configuration_ids": configuration_ids,
                "subject_ref": row["subject_ref"],
                "client": identity.sub,
                # The attestation shown now decides how long the wallet provider keeps this instance's status.
                "client_status_exp": identity.status_exp,
                "client_status": _distinct(identity.status),
                # The wallet as it is now: a refresh by a version taken off a configuration's list gets nothing of it.
                "wallet": identity.wallet,
                "identifiers": identifiers,
                "review": row.get("review") is True,
                "refresh_exp": row["exp"],
            },
        )
        return self._tokens.response(token, self._granted(identifiers, row.get("scopes"), configuration_ids))

    def _refreshed(self, scope: str | None, details: str | None, row: dict[str, Any]) -> list[str]:
        """What a refresh asks for (RFC 6749 §6): all the authorization covered, or a part of it named by scope or
        authorization_details, never more."""
        if details is not None:
            return self._narrowed(details, row)
        if scope is None:
            return list(row["configuration_ids"])
        wanted = list(dict.fromkeys(self.scopes[s] for s in scope.split(" ") if s in self.scopes))
        enforce(
            bool(wanted) and set(wanted) <= set(row["configuration_ids"]),
            "VCI.SCOPE_TO_CONFIG",
            "invalid_scope",
            "the scope asks for nothing, or for more than the authorization covers",
        )
        return wanted

    def _spent(self, key: str) -> dict[str, Any] | None:
        return opened(self._keyring, "code-spent", key, self._store.get("code-spent", key), self._clock())

    def _narrowed(self, details: str | None, row: dict[str, Any] | None) -> list[str]:
        """authorization_details in the token request (OpenID4VCI §6.1.1): configurations the authorization
        covers, for which the token is issued, with credential identifiers; none of them beyond it."""
        if details is None or row is None:
            return []
        wanted = self._details(details)
        enforce(
            set(wanted) <= set(row["configuration_ids"]),
            "VCI.AUTHZ_DETAILS",
            "invalid_authorization_details",
            "authorization_details asks for a configuration the authorization does not cover",
        )
        return wanted

    def _check(self, row: dict[str, Any], identity: ClientIdentity, jkt: str, verifier: str, redirect_uri: str) -> None:
        enforce(
            same(identity.sub, row["client"]) and same(identity.cnf_jkt, row["cnf"]),
            "WIA.CLIENT_ID_IS_SUB",
            "invalid_grant",
            "the authorization code was issued to another client",
        )
        enforce(
            row["dpop_jkt"] is None or same(jkt, row["dpop_jkt"]),
            "OAUTH.CODE_DPOP_BOUND",
            "invalid_grant",
            "the DPoP key is not the key the authorization code is bound to",
        )
        enforce(
            same(sha256_b64u(verifier), row["challenge"]),
            "OAUTH.PKCE_VERIFIER",
            "invalid_grant",
            "code_verifier does not match the code_challenge",
        )
        enforce(
            redirect_uri == row["redirect_uri"],
            "OAUTH.REDIRECT_URI_EXACT",
            "invalid_grant",
            "redirect_uri is not the one of the authorization request",
        )
        enforce(
            self._store.get("subject-closed", row["subject_ref"]) is None,
            "VCI.TOKEN.INVALID_GRANT",
            "invalid_grant",
            "this login's subject was revoked or erased",
        )


def _distinct(*statuses: Any) -> list[dict[str, Any]]:
    """The wallet attestation status references given, each once, leaving out none or an empty one."""
    found: list[dict[str, Any]] = []
    for status in statuses:
        if isinstance(status, dict) and status and status not in found:
            found.append(status)
    return found


def _earlier(first: int | None, second: int | None) -> int | None:
    """The earlier of two status period ends, either of which a conformance run may leave out."""
    return min((t for t in (first, second) if t is not None), default=None)


def _one_of(form: Mapping[str, list[str]], rule: str) -> Callable[[str], str | None]:
    """Each parameter at most once (RFC 6749 §3.1: parameters MUST NOT be included more than once)."""

    def one(name: str) -> str | None:
        values = form.get(name) or []
        enforce(len(values) <= 1, rule, "invalid_request", f"{name} appears more than once")
        return values[0] if values else None

    return one
