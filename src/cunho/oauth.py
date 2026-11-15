"""Pre-authorized offers, the token endpoint, DPoP and nonces."""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, NoReturn
from urllib.parse import quote, urlsplit

from cunho.jose import (
    ALGORITHMS,
    JoseError,
    b64u,
    has_private_members,
    is_number,
    parse_jws,
    public_key_from_jwk,
    sha256_b64u,
    thumbprint,
    verify,
)
from cunho.keyring import Keyring, same
from cunho.metadata import PRE_AUTH_GRANT
from cunho.rules import enforce, implements, refuse
from cunho.settings import Settings
from cunho.store import Store

DPOP_ALGS = " ".join(sorted(ALGORITHMS))
# Another grant of the token endpoint: given the form (one value per name) and the DPoP proofs, it answers.
TokenGrant = Callable[[Callable[[str], str | None], Sequence[str]], tuple[dict[str, Any], dict[str, str]]]
security_log = logging.getLogger("cunho.security")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _record_text(key: str, record: dict[str, Any]) -> str:
    return json.dumps({"key": key, "record": record}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def seal(keyring: Keyring, purpose: str, key: str, record: dict[str, Any]) -> dict[str, Any]:
    """A store row that carries a keyring MAC over its key and content (review 3, N3-M5).

    Offer and access-token rows decide whose data a wallet receives. Whoever can write the database
    could otherwise insert a row that points at another person's vault entry.
    """
    return {**record, "mac": keyring.mac(purpose, _record_text(key, record))}


def offer_key(code: str) -> str:
    """The key an offer's record is stored under, from its pre-authorized code."""
    return _hash(code)


def opened(keyring: Keyring, purpose: str, key: str, value: Any, now: float) -> dict[str, Any] | None:
    """The row's content when its MAC verifies and its own expiry has not passed; None otherwise."""
    if not isinstance(value, dict):
        return None
    record = {k: v for k, v in value.items() if k != "mac"}
    if not same(keyring.mac(purpose, _record_text(key, record)), str(value.get("mac", ""))):
        security_log.warning("a %s row failed its MAC check and was ignored", purpose)
        return None
    expires = record.get("exp")
    if not isinstance(expires, int) or expires <= now:  # True is 1, long past
        return None
    return record


def _whole(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _wallet(value: Any) -> tuple[str | None, str | None] | None:
    """The wallet solution and version a token row keeps; None for a row without an attestation, or a malformed one."""
    if not isinstance(value, list) or len(value) != 2 or not all(v is None or isinstance(v, str) for v in value):
        return None
    return value[0], value[1]


def normalize_url(url: str) -> str | None:
    """RFC 9449 §4.3: compare htu without query and fragment, after RFC 3986 normalisation.

    Returns None for anything that is not a plain absolute URI (bad port, userinfo, no host), which
    never matches. Percent-encoding and dot segments are compared as sent, which can only refuse.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if not parts.hostname or "@" in parts.netloc:
        return None
    default = {"https": 443, "http": 80}.get(parts.scheme.lower())
    host = parts.hostname.lower()
    netloc = host if port in (None, default) else f"{host}:{port}"
    return f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}"


@dataclass(frozen=True)
class Grant:
    grant_id: str
    jkt: str | None  # None for a Bearer token (accept_bearer_tokens)
    configuration_ids: list[str]
    subject_ref: str
    offer_id: str
    expires: int  # when the access token expires, under its MAC
    # credential_identifier -> configuration, when the token response returned authorization_details (§6.2)
    identifiers: dict[str, str] = field(default_factory=dict)
    # the end of the wallet attestation's status maintenance period, which caps a credential's validity
    client_status_exp: int | None = None
    # the attested client (the wallet attestation's sub) of a code-flow token; None for an anonymous one
    client: str | None = None
    # the status references of the wallet attestations that authenticated it, for revocation chaining (LC_GEN-4)
    client_status: tuple[dict[str, Any], ...] = ()
    # the operator holds what this token yields for review (OpenID4VCI §9): carried from the login result through the
    # sealed code, token and refresh rows, so no row whose absence would mean "issue at once" decides it
    review: bool = False
    # when the refresh token that came with the login, or that gave this token, expires: how long the wallet can still
    # get a token for this login, so how long an issuance held for review can wait to be collected
    refresh_exp: int | None = None
    # the wallet solution and version of the wallet attestation that got this token, None for an anonymous one: some
    # configurations are issued only to the solutions they name (ARF SUA_03)
    wallet: tuple[str | None, str | None] | None = None


class Nonces:
    """c_nonce values (single use, stored) and optional DPoP server nonces (stateless, HMAC-bound)."""

    def __init__(self, settings: Settings, store: Store, keyring: Keyring, clock: Callable[[], float]) -> None:
        self._settings = settings
        self._store = store
        self._clock = clock
        self._keyring = keyring

    @implements("VCI.NONCE.ENDPOINT", "PRIV.UNIQUE_ELEMENTS_CSPRNG")
    def issue_c_nonce(self) -> str:
        value = b64u(secrets.token_bytes(32))
        with self._store.atomic():  # the time stored is read in the transaction that stores it (CX-29)
            self._store.put("c-nonce", _hash(value), {"issued": self._clock()}, self._settings.c_nonce_ttl)
        return value

    def c_nonce_valid(self, value: Any) -> bool:
        return isinstance(value, str) and self._store.get("c-nonce", _hash(value)) is not None

    def consume_c_nonce(self, value: str) -> bool:
        return self._store.take("c-nonce", _hash(value)) is not None

    def _dpop_mac(self, stamp: str) -> str:
        return self._keyring.mac("dpop-nonce", stamp)[:32]

    def issue_dpop_nonce(self) -> str:
        stamp = str(int(self._clock()))
        return f"{stamp}.{self._dpop_mac(stamp)}"

    def dpop_nonce_valid(self, value: Any) -> bool:
        """Only a stamp cunho issued carries a valid MAC, so int() never sees anything but its own digits."""
        if not isinstance(value, str) or "." not in value:
            return False
        stamp, mac = value.split(".", 1)
        if not stamp.isascii() or not same(mac, self._dpop_mac(stamp)):  # ASCII: a lone surrogate cannot be MACed
            return False
        return 0 <= self._clock() - int(stamp) <= self._settings.dpop_iat_window * 5


class Dpop:
    def __init__(self, settings: Settings, store: Store, nonces: Nonces, clock: Callable[[], float]) -> None:
        self._settings = settings
        self._store = store
        self._nonces = nonces
        self._clock = clock

    def verify(
        self,
        headers: Sequence[str],
        method: str,
        url: str,
        *,
        resource: bool,
        access_token: str | None = None,
    ) -> str:
        """Run the RFC 9449 §4.3 checks and return the JWK thumbprint of the proof key."""
        status, scheme = (401, "DPoP") if resource else (400, None)

        def bad(rule: str, reason: str) -> NoReturn:
            refuse(rule, "invalid_dpop_proof", reason, status, scheme=scheme)

        enforce(
            len(headers) <= 1,
            "DPOP.SIGNATURE",
            "invalid_dpop_proof",
            "more than one DPoP header",
            status,
            scheme=scheme,
        )
        enforce(
            len(headers) == 1,
            "OAUTH.DPOP_REQUIRED",
            "invalid_dpop_proof",
            "a DPoP proof is required",
            status,
            scheme=scheme,
        )
        try:
            proof = parse_jws(headers[0])
        except JoseError as exc:
            bad("DPOP.SIGNATURE", f"DPoP proof is not a valid JWS: {exc}")
        header, claims = proof.header, proof.payload
        if header.get("typ") != "dpop+jwt":
            bad("DPOP.TYP", "typ must be dpop+jwt")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in ALGORITHMS:
            bad("DPOP.ALG_ASYMMETRIC", f"alg must be one of {DPOP_ALGS}")
        jwk = header.get("jwk")
        if not isinstance(jwk, dict) or has_private_members(jwk):
            bad("DPOP.NO_PRIVATE_KEY", "jwk must be a public key")
        try:
            key = public_key_from_jwk(jwk, alg)
        except JoseError as exc:
            bad("DPOP.SIGNATURE", str(exc))
        if not verify(alg, key, proof.signing_input, proof.signature):
            bad("DPOP.SIGNATURE", "signature does not verify")
        for claim in ("jti", "htm", "htu", "iat"):
            if claim not in claims:
                bad("DPOP.JTI_PRESENT", f"missing {claim}")
        # RFC 9449 §4.2 asks for enough entropy and sets no length; the replay cache is what refuses a jti seen
        # before. The bounds only refuse a degenerate one and keep the cache's keys small.
        if not isinstance(claims["jti"], str) or not 8 <= len(claims["jti"]) <= 256:
            bad("DPOP.JTI_PRESENT", "jti must be a string of 8 to 256 characters")
        if claims["htm"] != method:
            bad("DPOP.HTM", "htm does not match the request method")
        htu = normalize_url(claims["htu"]) if isinstance(claims["htu"], str) else None
        if htu != normalize_url(url):  # our own URL always normalises, so None never matches
            bad("DPOP.HTU", "htu does not match the request URI")
        iat = claims["iat"]
        if not is_number(iat) or abs(self._clock() - iat) > self._settings.dpop_iat_window:
            bad("DPOP.IAT_WINDOW", "iat is missing, not a finite number, or outside the accepted window")
        if self._settings.dpop_server_nonce and not self._nonces.dpop_nonce_valid(claims.get("nonce")):
            refuse(
                "DPOP.SERVER_NONCE",
                "use_dpop_nonce",
                "a fresh server nonce is required",
                status,
                scheme=scheme,
                headers={"DPoP-Nonce": self._nonces.issue_dpop_nonce()},
            )
        if access_token is not None and claims.get("ath") != sha256_b64u(access_token):
            bad("DPOP.ATH", "ath does not match the access token")
        jkt = thumbprint(jwk)
        if not self._store.add("dpop-jti", f"{jkt}:{claims['jti']}", 1, self._settings.dpop_iat_window * 2 + 5):
            bad("DPOP.JTI_REPLAY", "this DPoP proof was already used")
        return jkt


class Offers:
    def __init__(self, settings: Settings, store: Store, keyring: Keyring, clock: Callable[[], float]) -> None:
        self._settings = settings
        self._store = store
        self._keyring = keyring
        self._clock = clock

    @implements("VCI.OFFER.SHAPE", "PRIV.UNIQUE_ELEMENTS_CSPRNG")
    def create(
        self, configuration_ids: list[str], subject_ref: str, tx_code_length: int | None, offer_id: str
    ) -> dict[str, Any]:
        code = b64u(secrets.token_bytes(32))
        tx_code = None
        if tx_code_length:
            tx_code = "".join(str(secrets.randbelow(10)) for _ in range(tx_code_length))
        record = {
            "offer_id": offer_id,
            "configuration_ids": configuration_ids,
            "subject_ref": subject_ref,
            "tx_code": self._keyring.mac("tx-code", f"{code}:{tx_code}") if tx_code else None,
            "exp": int(self._clock()) + self._settings.offer_ttl,
        }
        key = _hash(code)
        self._store.put("offer", key, seal(self._keyring, "offer-record", key, record), self._settings.offer_ttl)
        grant: dict[str, Any] = {"pre-authorized_code": code}
        if tx_code_length:
            grant["tx_code"] = {
                "input_mode": "numeric",
                "length": tx_code_length,
                "description": "Enter the code you received separately.",
            }
        offer = {
            "credential_issuer": self._settings.issuer_url,
            "credential_configuration_ids": configuration_ids,
            "grants": {PRE_AUTH_GRANT: grant},
        }
        link = "openid-credential-offer://?credential_offer=" + quote(_compact(offer), safe="")
        # A by-value deep link (OpenID4VCI §4.1); `credential_offer_uri` would mean a by-reference URL.
        return {"credential_offer": offer, "offer_link": link, "tx_code": tx_code}


def _compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))


class Tokens:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        dpop: Dpop,
        nonces: Nonces,
        keyring: Keyring,
        clock: Callable[[], float],
        used_up: Callable[[str, str], None],
        minted: Callable[[str, int], None] | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        self._dpop = dpop
        self._nonces = nonces
        self._keyring = keyring
        self._clock = clock
        # Told the offer's row and its subject when wrong transaction codes have used an offer up: the issuer ends
        # the offer as it ends every other, in one logged transaction (Issuer._offer_used_up).
        self._used_up = used_up
        # Told of every token minted, inside the transaction that stores it: its subject, and when it expires.
        self._minted = minted

    @implements("DPOP.TOKEN_TYPE", "OAUTH.TOKEN_ERROR_BODY", "VCI.TOKEN.PREAUTH_SINGLE_USE")
    def exchange(
        self,
        form: Mapping[str, list[str]],
        dpop_headers: Sequence[str],
        grants: Mapping[str, TokenGrant] | None = None,
        client: Callable[[Callable[[str], str | None]], Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """The token endpoint. The pre-authorized code grant is handled here; another grant in `grants` (the
        authorization code grant) gets the parsed form and the DPoP proofs, and mints with `store_token`.

        `client` authenticates a pre-authorized request that carries a wallet attestation and returns who the client
        is, or None for a request without one, which stays anonymous (OpenID4VCI 1.0 §6.1). A token obtained with
        one is bound to that client: a proof may name it in iss (App. F.1), and its status period caps validity as
        in the code flow."""

        def one(name: str) -> str | None:
            values = form.get(name) or []
            enforce(len(values) <= 1, "OAUTH.TOKEN_ERROR_BODY", "invalid_request", f"{name} appears more than once")
            return values[0] if values else None

        grant_type = one("grant_type")
        enforce(grant_type is not None, "OAUTH.TOKEN_ERROR_BODY", "invalid_request", "grant_type is required")
        handler = (grants or {}).get(str(grant_type))
        if handler is not None:
            return handler(one, dpop_headers)
        enforce(
            grant_type == PRE_AUTH_GRANT,
            "OAUTH.TOKEN_ERROR_BODY",
            "unsupported_grant_type",
            "only the pre-authorized code and authorization code grants are offered",
        )
        code = one("pre-authorized_code")
        enforce(bool(code), "VCI.TOKEN.PREAUTH_REQUEST", "invalid_request", "pre-authorized_code is required")
        tx_code = one("tx_code")
        identity = client(one) if client is not None else None
        if not dpop_headers and self._settings.accept_bearer_tokens:
            jkt = None  # a plain Bearer token for a wallet that sends no DPoP proof
        else:
            jkt = self._dpop.verify(dpop_headers, "POST", self._settings.token_endpoint, resource=False)
        key = _hash(str(code))
        offer = opened(self._keyring, "offer-record", key, self._store.get("offer", key), self._clock())
        enforce(offer is not None, "VCI.TOKEN.INVALID_GRANT", "invalid_grant", "unknown or expired pre-authorized code")
        assert offer is not None
        enforce(
            self._store.get("subject-closed", offer["subject_ref"]) is None,
            "VCI.TOKEN.INVALID_GRANT",
            "invalid_grant",
            "this offer was cancelled",
        )  # revoked or cancelled by the operator (review 4, N4-M5)
        if offer["tx_code"] is None:
            enforce(tx_code is None, "VCI.TOKEN.TX_CODE_ERRORS", "invalid_request", "this offer has no tx_code")
        else:
            enforce(tx_code is not None, "VCI.TOKEN.TX_CODE_ERRORS", "invalid_request", "tx_code is required")
            # Count the attempt before comparing, so concurrent guesses cannot all slip in before the lockout. The
            # count lives as long as the offer itself, by the expiry under the offer's MAC, not for the lifetime
            # configured now: after a restart with a shorter offer_ttl the count of an offer made before it ran
            # out and began again, as often as the offer still lived (the security review; as CX-28 for claims).
            attempts = self._store.incr("tx-attempts", key, max(offer["exp"] - self._clock(), 1))
            if attempts > self._settings.tx_code_max_attempts:
                self._used_up(key, offer["subject_ref"])
                refuse("VCI.TOKEN.TX_CODE_ERRORS", "invalid_grant", "too many wrong tx_code attempts")
            if not same(self._keyring.mac("tx-code", f"{code}:{tx_code}"), offer["tx_code"]):
                if attempts >= self._settings.tx_code_max_attempts:
                    self._used_up(key, offer["subject_ref"])
                refuse("VCI.TOKEN.TX_CODE_ERRORS", "invalid_grant", "wrong tx_code")
        offer = opened(self._keyring, "offer-record", key, self._store.take("offer", key), self._clock())
        enforce(offer is not None, "VCI.TOKEN.PREAUTH_SINGLE_USE", "invalid_grant", "pre-authorized code already used")
        assert offer is not None
        token, token_key = self.new_token()
        self.store_token(
            token_key,
            {
                "offer_id": offer["offer_id"],
                "jkt": jkt,
                "configuration_ids": offer["configuration_ids"],
                "subject_ref": offer["subject_ref"],
                **(
                    {
                        "client": identity.sub,
                        "client_status_exp": identity.status_exp,
                        "client_status": [identity.status] if identity.status else [],
                        "wallet": identity.wallet,
                    }
                    if identity
                    else {}
                ),
            },
        )
        return self.response(token, token_type="DPoP" if jkt is not None else "Bearer")

    @staticmethod
    def new_token() -> tuple[str, str]:
        """A new access token and the key its row is stored under."""
        token = b64u(secrets.token_bytes(32))
        return token, _hash(token)

    def store_token(self, token_key: str, fields: dict[str, Any]) -> None:
        """Store an access token's row, sealed. Joins the caller's transaction when there is one."""
        # The expiry under the token's MAC is read in the transaction that stores it, as the store's own is: a
        # forced run another worker commits meanwhile would leave the token stamped by the base before (CX-29).
        with self._store.atomic():
            record = {
                "grant_id": b64u(secrets.token_bytes(18)),
                **fields,
                "exp": int(self._clock()) + self._settings.access_token_ttl,
            }
            self._store.put(
                "access-token",
                token_key,
                seal(self._keyring, "token-record", token_key, record),
                self._settings.access_token_ttl,
            )
            if self._minted is not None and isinstance(fields.get("subject_ref"), str):
                self._minted(fields["subject_ref"], record["exp"])

    def response(
        self, token: str, extra: dict[str, Any] | None = None, *, token_type: str = "DPoP"
    ) -> tuple[dict[str, Any], dict[str, str]]:
        headers = {"Cache-Control": "no-store"}
        if self._settings.dpop_server_nonce:
            headers["DPoP-Nonce"] = self._nonces.issue_dpop_nonce()
        body = {"access_token": token, "token_type": token_type, "expires_in": self._settings.access_token_ttl}
        return {**body, **(extra or {})}, headers

    @implements("OAUTH.RESOURCE_401_CHALLENGE")
    def authorize(self, authorization: str | None, dpop_headers: Sequence[str], method: str, url: str) -> Grant:
        """Protected-resource access (RFC 9449 §7): DPoP scheme, valid token, proof bound to the token key."""
        enforce(
            bool(authorization),
            "OAUTH.RESOURCE_401_CHALLENGE",
            "invalid_token",
            "an access token is required",
            401,
            scheme="DPoP",
            bare_challenge=True,
        )
        assert authorization is not None
        scheme, _, token = authorization.partition(" ")
        token = token.strip()
        record = None
        if token:
            key = _hash(token)
            record = opened(self._keyring, "token-record", key, self._store.get("access-token", key), self._clock())
        if record is not None and record["jkt"] is None:
            # A Bearer token (accept_bearer_tokens): RFC 6750, with no DPoP proof to check.
            enforce(
                scheme.lower() == "bearer",
                "DPOP.AUTH_SCHEME",
                "invalid_token",
                "use the Bearer authorization scheme for this access token",
                401,
                scheme="Bearer",
            )
            return self._grant(record)
        if scheme.lower() == "bearer" and record is not None:
            refuse("DPOP.NO_BEARER_DOWNGRADE", "invalid_token", "this access token is DPoP-bound", 401, scheme="DPoP")
        enforce(
            scheme.lower() == "dpop" and bool(token),
            "DPOP.AUTH_SCHEME",
            "invalid_token",
            "use the DPoP authorization scheme",
            401,
            scheme="DPoP",
        )
        enforce(
            record is not None,
            "OAUTH.RESOURCE_401_CHALLENGE",
            "invalid_token",
            "unknown or expired access token",
            401,
            scheme="DPoP",
        )
        assert record is not None
        jkt = self._dpop.verify(dpop_headers, method, url, resource=True, access_token=token)
        enforce(
            same(jkt, record["jkt"]),
            "DPOP.KEY_BOUND_TO_TOKEN",
            "invalid_dpop_proof",
            "the DPoP key is not the key the token is bound to",
            401,
            scheme="DPoP",
        )
        return self._grant(record)

    @staticmethod
    def _grant(record: dict[str, Any]) -> Grant:
        return Grant(
            record["grant_id"],
            record["jkt"],
            list(record["configuration_ids"]),
            record["subject_ref"],
            record["offer_id"],
            record["exp"],
            dict(record.get("identifiers") or {}),
            record.get("client_status_exp"),
            record.get("client"),
            tuple(s for s in record.get("client_status") or () if isinstance(s, dict)),
            record.get("review") is True,
            _whole(record.get("refresh_exp")),
            _wallet(record.get("wallet")),
        )
