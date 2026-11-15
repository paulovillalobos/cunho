"""Shared state for one probe run: HTTP transport, discovery, offers, tokens."""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx

from . import jwe
from .attester import WalletProvider
from .authcode import Authorization, Client, CodeFlow, FlowFailure
from .jose import EcKey
from .wallet import AttestationIssuer, dpop_proof, key_proof

PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
BODY_LIMIT = 600


@dataclass
class Exchange:
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body: str
    sent: str = ""
    content: bytes = b""  # the body as sent, for binary media types (a CWT status list)

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    def error_code(self) -> str | None:
        data = self.json()
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            return data["error"]
        return None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def evidence(self) -> str:
        sent = f" [{self.sent}]" if self.sent else ""
        body = self.body if len(self.body) <= BODY_LIMIT else self.body[:BODY_LIMIT] + "...(truncated)"
        return f"{self.method} {self.url}{sent} -> {self.status} {body}"


class Http:
    """httpx wrapper that never raises and can rewrite advertised URLs to reachable ones."""

    def __init__(
        self, *, verify: bool, rewrites: list[tuple[str, str]], timeout: float, client: httpx.Client | None = None
    ) -> None:
        self.rewrites = rewrites
        self.client = client or httpx.Client(verify=verify, timeout=timeout, follow_redirects=False)

    def transport_url(self, url: str) -> str:
        for advertised, reachable in self.rewrites:
            if url.startswith(advertised):
                return reachable + url[len(advertised) :]
        return url

    def request(self, method: str, url: str, *, sent: str = "", **kwargs: Any) -> Exchange:
        try:
            response = self.client.request(method, self.transport_url(url), follow_redirects=False, **kwargs)
        except httpx.HTTPError as exc:
            return Exchange(method, url, 0, {}, f"transport error: {exc!r}", sent)
        headers = {k.lower(): v for k, v in response.headers.items()}
        return Exchange(method, url, response.status_code, headers, response.text, sent, response.content)


@dataclass
class Offer:
    credential_issuer: str
    configuration_ids: list[str]
    pre_authorized_code: str | None
    tx_code_spec: dict[str, Any] | None
    tx_code_value: str | None
    raw: dict[str, Any]

    @property
    def tx_code_required(self) -> bool:
        return self.tx_code_spec is not None


@dataclass
class Token:
    access_token: str
    key: EcKey
    exchange: Exchange
    dpop_nonce: str | None = None


@dataclass
class ProbeConfig:
    issuer: str
    offer: str | None = None
    offer_cmd: str | None = None
    token_cmd: str | None = None
    tx_code: str | None = None
    config_id: str | None = None
    insecure: bool = False
    rewrites: list[tuple[str, str]] = field(default_factory=list)
    timeout: float = 20.0
    attestation_issuer: AttestationIssuer | None = None
    # The authorization code flow: a wallet provider the issuer trusts, the wallet solution's client_id (the sub of
    # its attestations) and a redirect URI the issuer allows for it, and how to log in (authcode.py).
    wallet_provider: WalletProvider | None = None
    client_id: str | None = None
    redirect_uri: str | None = None
    login_fields: dict[str, str] | None = None
    cancel_fields: dict[str, str] | None = None
    login_cmd: str | None = None
    # A second wallet solution the issuer allows, for the checks that need two clients.
    second_client: tuple[str, str] | None = None
    # A client_id for the pre-authorized token request, for servers that want one although the grant is anonymous.
    token_client_id: str | None = None
    # M4: the mso_mdoc configuration the mdoc checks ask for (else the first one an offer names); a command that
    # prints an offer the issuer holds for review (deferred issuance) and one that releases what it holds.
    mdoc_config_id: str | None = None
    deferred_offer_cmd: str | None = None
    release_cmd: str | None = None
    # Login fields with which the issuer holds the issuance for review (the code flow's way to deferred issuance).
    hold_fields: dict[str, str] | None = None
    # The longest deferred polling interval the probe waits out; a longer one is polled early, and said so.
    deferred_wait_max: float = 60.0
    client: httpx.Client | None = None  # for tests: an in-process transport


def insert_well_known(identifier: str, suffix: str) -> str:
    """RFC 8414 §3 / OpenID4VCI §12.2.2: insert the well-known segment between host and path."""
    parts = urlsplit(identifier)
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, f"/.well-known/{suffix}{path}", "", ""))


def append_well_known(identifier: str, suffix: str) -> str:
    return identifier.rstrip("/") + f"/.well-known/{suffix}"


class Context:
    def __init__(self, config: ProbeConfig) -> None:
        self.config = config
        self.http = Http(
            verify=not config.insecure, rewrites=config.rewrites, timeout=config.timeout, client=config.client
        )
        self.notes: list[str] = []
        self.sleep: Callable[[float], None] = time.sleep  # tests wait without the wall clock
        self.cache: dict[str, Any] = {}
        self.metadata_fallback: Exchange | None = None
        self._static_offer_used = False

    # discovery -----------------------------------------------------------

    @cached_property
    def metadata_exchange(self) -> Exchange:
        spec_url = insert_well_known(self.config.issuer, "openid-credential-issuer")
        exchange = self.http.request("GET", spec_url, headers={"Accept": "application/json"})
        if exchange.status == 200 and isinstance(exchange.json(), dict):
            return exchange
        fallback = append_well_known(self.config.issuer, "openid-credential-issuer")
        if fallback != spec_url:
            alt = self.http.request("GET", fallback, headers={"Accept": "application/json"})
            if alt.status == 200 and isinstance(alt.json(), dict):
                self.notes.append(f"issuer metadata only found at non-spec path {fallback}")
                self.metadata_fallback = alt
        return exchange

    @cached_property
    def metadata(self) -> dict[str, Any]:
        data = self.metadata_exchange.json()
        if isinstance(data, dict) and self.metadata_exchange.status == 200:
            return data
        fallback = self.metadata_fallback
        if fallback is not None:
            data = fallback.json()
            if isinstance(data, dict):
                return data
        return {}

    @cached_property
    def as_identifier(self) -> str:
        servers = self.metadata.get("authorization_servers")
        if isinstance(servers, list) and servers and isinstance(servers[0], str):
            return servers[0]
        return str(self.metadata.get("credential_issuer") or self.config.issuer)

    @cached_property
    def as_metadata_exchange(self) -> Exchange:
        return self.http.request(
            "GET",
            insert_well_known(self.as_identifier, "oauth-authorization-server"),
            headers={"Accept": "application/json"},
        )

    @cached_property
    def as_metadata(self) -> dict[str, Any]:
        candidates = [
            self.as_metadata_exchange,
            self.http.request("GET", append_well_known(self.as_identifier, "oauth-authorization-server")),
            self.http.request("GET", append_well_known(self.as_identifier, "openid-configuration")),
        ]
        for index, exchange in enumerate(candidates):
            data = exchange.json()
            if exchange.status == 200 and isinstance(data, dict):
                if index:
                    self.notes.append(f"AS metadata only found at non-RFC-8414 path {exchange.url}")
                return data
        return {}

    def endpoint(self, name: str) -> str | None:
        value = self.metadata.get(name)
        return value if isinstance(value, str) else None

    @property
    def token_endpoint(self) -> str | None:
        value = self.as_metadata.get("token_endpoint")
        return value if isinstance(value, str) else None

    @property
    def configurations(self) -> dict[str, Any]:
        value = self.metadata.get("credential_configurations_supported")
        return value if isinstance(value, dict) else {}

    @property
    def batch_size(self) -> int | None:
        batch = self.metadata.get("batch_credential_issuance")
        if isinstance(batch, dict) and isinstance(batch.get("batch_size"), int):
            return int(batch["batch_size"])
        return None

    # offers ----------------------------------------------------------------

    def can_make_offers(self) -> bool:
        return bool(
            self.config.offer_cmd or self.config.token_cmd or (self.config.offer and not self._static_offer_used)
        )

    def fresh_offer(self, command: str | None = None) -> Offer | None:
        """A new offer: from `command` when given (the deferred offer command), else as the run is set up."""
        tx_code = self.config.tx_code
        if command is not None:
            return self._offer_from(command, tx_code)
        if self.config.token_cmd and not self.config.offer_cmd:
            # Authorization-code issuers: the token command does the whole grant itself.
            return Offer(str(self.config.issuer), [], None, None, None, {"via": "token_cmd"})
        if self.config.offer_cmd:
            return self._offer_from(self.config.offer_cmd, tx_code)
        if self.config.offer and not self._static_offer_used:
            self._static_offer_used = True
            return self.parse_offer(self.config.offer, tx_code)
        return None

    def _offer_from(self, command: str, tx_code: str | None) -> Offer | None:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if result.returncode != 0 or not lines:
            self.notes.append(f"offer command failed: rc={result.returncode} {result.stderr[-300:]}")
            return None
        text = lines[-1].strip()
        try:
            wrapped = json.loads(text)
        except ValueError:
            wrapped = None
        if isinstance(wrapped, dict) and "offer" in wrapped:
            text = str(wrapped["offer"])
            tx_code = wrapped.get("tx_code") or tx_code
        return self.parse_offer(text, tx_code)

    def release_held(self) -> bool:
        """Run the release command: the operator releases what the issuer holds for review."""
        if not self.config.release_cmd:
            return False
        result = subprocess.run(self.config.release_cmd, shell=True, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            self.notes.append(f"release command failed: rc={result.returncode} {result.stderr[-300:]}")
        return result.returncode == 0

    def mdoc_config_id(self, offer: Offer | None) -> str | None:
        """The mso_mdoc configuration the mdoc checks ask for."""
        if self.config.mdoc_config_id:
            return self.config.mdoc_config_id
        if self.configurations.get(self.config.config_id or "", {}).get("format") == "mso_mdoc":
            return self.config.config_id  # --config-id names an mdoc configuration: the one the run asks for
        # A token command's offer names no configuration: the metadata's are the ones its token may cover.
        ids = offer.configuration_ids if offer and offer.configuration_ids else list(self.configurations)
        return next((i for i in ids if self.configurations.get(i, {}).get("format") == "mso_mdoc"), None)

    def parse_offer(self, text: str, tx_code: str | None) -> Offer | None:
        data: Any
        if text.lstrip().startswith("{"):
            data = json.loads(text)
        else:
            query = parse_qs(urlsplit(text).query)
            if "credential_offer" in query:
                data = json.loads(query["credential_offer"][0])
            elif "credential_offer_uri" in query:
                exchange = self.http.request("GET", query["credential_offer_uri"][0])
                data = exchange.json()
            else:
                self.notes.append(f"could not parse credential offer: {text[:200]}")
                return None
        if not isinstance(data, dict):
            return None
        grant = (data.get("grants") or {}).get(PRE_AUTH_GRANT) or {}
        return Offer(
            credential_issuer=str(data.get("credential_issuer", "")),
            configuration_ids=list(data.get("credential_configuration_ids") or []),
            pre_authorized_code=grant.get("pre-authorized_code"),
            tx_code_spec=grant.get("tx_code") if "tx_code" in grant else None,
            tx_code_value=tx_code,
            raw=data,
        )

    def target_config_id(self, offer: Offer | None) -> str | None:
        if self.config.config_id:
            return self.config.config_id
        ids = offer.configuration_ids if offer else list(self.configurations)
        for config_id in ids:
            if self.configurations.get(config_id, {}).get("format") == "dc+sd-jwt":
                return config_id
        return ids[0] if ids else None

    # protocol helpers ---------------------------------------------------------

    def token_request(
        self,
        offer: Offer,
        key: EcKey,
        *,
        form: dict[str, str] | None = None,
        dpop: str | None | bool = True,
        nonce: str | None = None,
        sent: str = "",
    ) -> Exchange:
        endpoint = self.token_endpoint or ""
        if form is None:
            form = {"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": offer.pre_authorized_code or ""}
            if offer.tx_code_required and offer.tx_code_value is not None:
                form["tx_code"] = offer.tx_code_value
        if self.config.token_client_id and "client_id" not in form:
            # Every form a check builds too, so a server that wants it reaches the condition being tested.
            form = {**form, "client_id": self.config.token_client_id}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if dpop is True:
            headers["DPoP"] = dpop_proof(key, "POST", endpoint, nonce=nonce)
        elif isinstance(dpop, str):
            headers["DPoP"] = dpop
        return self.http.request("POST", endpoint, data=form, headers=headers, sent=sent)

    def token_from_cmd(self) -> Token | None:
        """Run --token-cmd; it prints JSON {access_token, dpop_jwk (private), dpop_nonce?}."""
        result = subprocess.run(self.config.token_cmd or "", shell=True, capture_output=True, text=True, timeout=180)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        try:
            data = json.loads(lines[-1]) if lines else None
        except ValueError:
            data = None
        if result.returncode != 0 or not isinstance(data, dict) or "access_token" not in data:
            self.notes.append(f"token command failed: rc={result.returncode} {result.stderr[-300:]}")
            return None
        key = EcKey.from_private_jwk(data["dpop_jwk"])
        exchange = Exchange("POST", "token-cmd", 200, {}, lines[-1])  # whole: T01 reads token_type from it
        return Token(str(data["access_token"]), key, exchange, data.get("dpop_nonce"))

    def get_token(self, offer: Offer | None = None) -> Token | None:
        """A token for `offer`, or for a fresh one. An offer with a pre-authorized code is exchanged itself, even in a
        token-command run: the deferred offer command's held offer is not the token command's grant."""
        given_code = offer is not None and bool(offer.pre_authorized_code)
        if self.config.token_cmd and not self.config.offer_cmd and not given_code:
            return self.token_from_cmd()
        offer = offer or self.fresh_offer()
        if offer is None or not offer.pre_authorized_code or not self.token_endpoint:
            return None
        key = EcKey.generate()
        exchange = self.token_request(offer, key)
        nonce = None
        if exchange.status in (400, 401) and exchange.error_code() == "use_dpop_nonce":
            nonce = exchange.header("dpop-nonce") or None
            exchange = self.token_request(offer, key, nonce=nonce)
        data = exchange.json()
        if exchange.status != 200 or not isinstance(data, dict) or "access_token" not in data:
            self.notes.append(f"token request failed: {exchange.evidence()}")
            return None
        return Token(str(data["access_token"]), key, exchange, exchange.header("dpop-nonce") or nonce)

    def c_nonce(self) -> str | None:
        endpoint = self.endpoint("nonce_endpoint")
        if not endpoint:
            return None
        data = self.http.request("POST", endpoint).json()
        if isinstance(data, dict) and isinstance(data.get("c_nonce"), str):
            return str(data["c_nonce"])
        return None

    def proof_for(self, holder: EcKey, nonce: str | None, **overrides: Any) -> str:
        attestation = None
        if self.config.attestation_issuer is not None and "key_attestation" not in overrides:
            attestation = self.config.attestation_issuer.key_attestation([holder], nonce=nonce)
        return key_proof(
            holder,
            str(self.metadata.get("credential_issuer") or self.config.issuer),
            nonce=nonce,
            key_attestation=overrides.pop("key_attestation", attestation),
            **overrides,
        )

    def credential_request(
        self,
        token: Token,
        body: Any,
        *,
        scheme: str = "DPoP",
        dpop: str | None | bool = True,
        raw: bytes | None = None,
        content_type: str = "application/json",
        sent: str = "",
        at: str = "credential_endpoint",
        plain: bool = False,
    ) -> Exchange:
        """A request to the credential endpoint, or to the one `at` names (deferred_credential_endpoint,
        notification_endpoint), with the token and its DPoP proof, answering a DPoP nonce challenge.

        Against an issuer that requires encryption (OID4VCI 1.0 §8.2, §9.1, §10), a request the probe builds itself
        is sent as a wallet sends it: sealed to the issuer's key, asking for a response encrypted to a key of the
        probe's, whose answer is opened before a check reads it. `raw` bodies, `plain` ones and notifications go as
        they are."""
        endpoint = self.endpoint(at) or ""
        if at == "credential_endpoint":
            body = with_identifier(token, body)
        response_key: EcKey | None = None
        if raw is None and not plain and at != "notification_endpoint" and self.encryption_required():
            sealed = self.sealed(body)
            if sealed is not None:
                raw, response_key = sealed
                content_type, sent = "application/jwt", f"{sent} (encrypted)".strip()

        def send(nonce: str | None) -> Exchange:
            headers = {"Authorization": f"{scheme} {token.access_token}", "Content-Type": content_type}
            if dpop is True:
                headers["DPoP"] = dpop_proof(token.key, "POST", endpoint, access_token=token.access_token, nonce=nonce)
            elif isinstance(dpop, str):
                headers["DPoP"] = dpop
            content = raw if raw is not None else json.dumps(body).encode()
            return self.http.request("POST", endpoint, content=content, headers=headers, sent=sent)

        exchange = send(token.dpop_nonce)
        if dpop is True and exchange.status == 401 and "use_dpop_nonce" in exchange.header("www-authenticate"):
            token.dpop_nonce = exchange.header("dpop-nonce") or None
            exchange = send(token.dpop_nonce)
        if response_key is not None and exchange.header("content-type").startswith("application/jwt"):
            try:
                opened = jwe.decrypt(exchange.body, response_key)
            except (ValueError, KeyError) as exc:
                self.notes.append(f"an encrypted response did not open: {exc}")
                return exchange
            headers = {**exchange.headers, "content-type": "application/json"}
            body_text = opened.payload.decode("utf-8", "replace")
            return Exchange(exchange.method, exchange.url, exchange.status, headers, body_text, exchange.sent)
        return exchange

    def encryption_required(self) -> bool:
        """Whether the issuer requires encrypted requests or responses (OID4VCI 1.0 §12.2.4)."""
        blocks = (self.metadata.get(n) for n in ("credential_request_encryption", "credential_response_encryption"))
        return any(isinstance(b, dict) and b.get("encryption_required") is True for b in blocks)

    def sealed(self, body: Any) -> tuple[bytes, EcKey | None] | None:
        """`body` sealed to the issuer's first ECDH-ES key, asking for a response encrypted to a new key of the
        probe's when the issuer encrypts responses, and that key (None when it does not); None when the issuer
        offers no request encryption the probe can do. Request encryption stands on its own (§8.2: the response
        parameters need an encrypted request, not the other way round)."""
        request = self.metadata.get("credential_request_encryption")
        response = self.metadata.get("credential_response_encryption")
        if not isinstance(request, dict) or not isinstance(body, dict):
            return None
        keys = request.get("jwks", {}).get("keys") if isinstance(request.get("jwks"), dict) else None
        target = next(
            (k for k in keys or [] if isinstance(k, dict) and k.get("alg") == "ECDH-ES" and k.get("crv") in jwe.CURVES),
            None,
        )
        ours = ("A128GCM", "A256GCM")
        request_enc = next((e for e in ours if e in (request.get("enc_values_supported") or [])), None)
        if target is None or request_enc is None:
            self.notes.append("the issuer requires encryption the probe cannot do (ECDH-ES with A128GCM or A256GCM)")
            return None
        key: EcKey | None = None
        asked = dict(body)
        if isinstance(response, dict) and "ECDH-ES" in (response.get("alg_values_supported") or []):
            response_enc = next((e for e in ours if e in (response.get("enc_values_supported") or [])), None)
            if response_enc is not None:
                key = EcKey.generate()
                jwk = {**key.public_jwk(), "alg": "ECDH-ES", "use": "enc", "kid": "probe-response"}
                asked["credential_response_encryption"] = {"jwk": jwk, "enc": response_enc}
            elif response.get("encryption_required") is True:
                self.notes.append("the issuer requires encrypted responses in an enc the probe cannot open")
        token = jwe.encrypt(json.dumps(asked).encode(), target, request_enc, kid=target.get("kid"))
        return token.encode("ascii"), key

    # the authorization code flow ------------------------------------------------

    def code_client(
        self, *, provider: WalletProvider | None = None, client_id: str | None = None, redirect_uri: str | None = None
    ) -> Client | None:
        """A fresh wallet instance of the configured wallet solution (or of the one given), or None when the run
        has no wallet provider, client_id or redirect URI."""
        provider = provider or self.config.wallet_provider
        client_id = client_id or self.config.client_id
        redirect_uri = redirect_uri or self.config.redirect_uri
        if provider is None or not client_id or not redirect_uri:
            return None
        return Client(provider.instance(client_id), redirect_uri)

    def scope_for(self, config_id: str | None) -> str | None:
        scope = (self.configurations.get(config_id or "") or {}).get("scope")
        return scope if isinstance(scope, str) else None

    def code_tokens(
        self, client: Client | None = None, *, extra: dict[str, str] | None = None
    ) -> CodeTokens | FlowFailure | str:
        """A token from the code flow for the target configuration, by scope; cached for the configured client. A
        string names a missing prerequisite; a FlowFailure says where the flow, tried, stopped. `extra` login fields
        make a login of its own, never cached."""
        cache = client is None and not extra  # the shared login; a check with a client or fields gets its own
        if cache and self.cache.get("code_tokens"):
            return self.cache["code_tokens"]
        client = client or self.code_client()
        if client is None:
            return "no wallet provider, client_id or redirect URI configured (--wia-ca, --client-id, --redirect-uri)"
        if self.config.login_fields is None and not self.config.login_cmd:
            return "no way to log in configured (--login-field or --login-cmd)"
        config_id = self.target_config_id(None)
        scope = self.scope_for(config_id)
        if config_id is None or scope is None:
            return "no credential configuration with a scope"
        flow = CodeFlow(self, client)
        authorization = flow.authorized(scope=scope, extra=extra)
        if isinstance(authorization, FlowFailure):
            return authorization
        if authorization.code is None:
            return FlowFailure(f"no code came back: {authorization.params}", authorization.steps)
        exchange = flow.token(authorization.code, authorization.pkce, sent="code exchange")
        data = exchange.json()
        if exchange.status != 200 or not isinstance(data, dict) or "access_token" not in data:
            return FlowFailure("the code exchange failed", [exchange])
        refresh = data.get("refresh_token")
        token = Token(str(data["access_token"]), client.dpop, exchange, exchange.header("dpop-nonce") or None)
        got = CodeTokens(flow, authorization, token, refresh if isinstance(refresh, str) else None, config_id)
        if cache:
            self.cache["code_tokens"] = got
        return got


def with_identifier(token: Token, body: Any) -> Any:
    """OpenID4VCI §8.2: a token whose response gave credential_identifiers is used with credential_identifier. A body
    naming a configuration the token has an identifier for is sent with that identifier instead."""
    if not isinstance(body, dict) or not isinstance(body.get("credential_configuration_id"), str):
        return body
    if "credential_identifier" in body:  # a request that names both on purpose (C07) is sent as it is
        return body
    details = (token.exchange.json() or {}).get("authorization_details") if token.exchange.body else None
    for detail in details if isinstance(details, list) else []:
        if not isinstance(detail, dict):
            continue
        identifiers = detail.get("credential_identifiers")
        if detail.get("credential_configuration_id") == body["credential_configuration_id"] and identifiers:
            rest = {k: v for k, v in body.items() if k != "credential_configuration_id"}
            return {"credential_identifier": identifiers[0], **rest}
    return body


@dataclass
class CodeTokens:
    flow: CodeFlow
    authorization: Authorization
    token: Token
    refresh_token: str | None
    config_id: str
