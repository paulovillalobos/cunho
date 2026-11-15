"""Wallet attestation as client authentication (OpenID4VCI 1.0 App. E, HAIP 1.0 §4.4.1).

The wallet sends two headers at the PAR and token endpoints (draft-ietf-oauth-attestation-based-client-auth-07
§6): `OAuth-Client-Attestation`, a JWT the wallet provider signed for this wallet instance, and
`OAuth-Client-Attestation-PoP`, a JWT the instance signs with the key the attestation names in `cnf`. Both the
-07 shape and the later one TS3 v1.5.2 follows are accepted: `iss` may be left out of either JWT, and nothing
requires the `cnf` key to be the DPoP key (TS3 v1.5.2 dropped that).

Every check refuses with its own rule, as `invalid_client` with 401 and fixed text: no error says which anchor
or which claim of the wallet's failed beyond the rule's own words, and none echoes what the wallet sent.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn

from cunho.jose import (
    ALGORITHMS,
    JoseError,
    Jws,
    has_private_members,
    is_number,
    load_x5c,
    parse_jws,
    public_key_from_jwk,
    thumbprint,
    validate_path,
    verify,
)
from cunho.rules import enforce, implements, refuse
from cunho.settings import Settings
from cunho.status_refs import references
from cunho.store import Store

if TYPE_CHECKING:
    from cunho.trust import Trust
    from cunho.wallet_status import WalletStatus

WIA_TYP = "oauth-client-attestation+jwt"
POP_TYP = "oauth-client-attestation-pop+jwt"
ATTESTATION_HEADER = "oauth-client-attestation"
POP_HEADER = "oauth-client-attestation-pop"
# FAPI 2.0 §5.3.2.1: accept up to 10 s in the future, refuse more than 60 s. cunho takes the 60 s.
FUTURE_SKEW = 60
MAX_CLIENT_ID = 512


@dataclass(frozen=True)
class ClientIdentity:
    """Who authenticated: the wallet solution (`sub`), the instance key, and what the attestation says about the
    instance's status. Later steps compare against this, never derive it again."""

    sub: str
    cnf_jkt: str
    status_exp: int | None  # None only in a conformance run, for an attestation without client_status
    status: dict[str, Any] | None
    wallet_name: str | None = None  # the wallet solution, as on the list of wallet providers (TS3 v1.5 §2.3.1)
    wallet_version: str | None = None

    @property
    def wallet(self) -> list[str | None]:
        """The wallet solution and its version, as a token row keeps them for the gate of ARF SUA_03."""
        return [self.wallet_name, self.wallet_version]


def _wallet(claims: dict[str, Any]) -> tuple[str | None, str | None]:
    """wallet_name and wallet_version of a wallet attestation, each when it is a string (OpenID4VCI App. E)."""
    name, version = claims.get("wallet_name"), claims.get("wallet_version")
    return (name if isinstance(name, str) else None, version if isinstance(version, str) else None)


def fail(rule: str, reason: str) -> NoReturn:
    refuse(rule, "invalid_client", reason, 401)


class ClientAuth:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        trust: Trust,
        clock: Callable[[], float],
        wallet_status: WalletStatus | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        self._trust = trust
        self._clock = clock
        self._wallet_status = wallet_status

    @implements("WIA.VERIFY", "WIA.STATUS_EXP_NOT_TOKEN_EXP", "TS3.CONFORMANCE")
    def authenticate(
        self, attestations: Sequence[str], pops: Sequence[str], client_id: str | None = None
    ) -> ClientIdentity:
        """Run every check of draft-07 §9 that applies, in order, and return who the client is."""
        enforce(
            len(attestations) == 1 and len(pops) == 1,
            "WIA.REQUIRED_AT_PAR_AND_TOKEN",
            "invalid_client",
            "send exactly one OAuth-Client-Attestation and one OAuth-Client-Attestation-PoP header",
            401,
        )
        attestation = self._signed(attestations[0], WIA_TYP, "WIA.VERIFY")
        pop = self._signed(pops[0], POP_TYP, "WIA.POP_CNF")
        now = self._clock()
        try:
            chain = load_x5c(attestation.header.get("x5c"))
        except JoseError:
            fail("WIA.CHAIN_TO_WP_LIST", "the wallet attestation is not from a trusted wallet provider")
        # The signature before the path. A wallet provider's chain is public, every attestation carries it, and the
        # path check asks for the chain's revocation, which may fetch a CRL or ask an OCSP responder: checked the
        # other way round, anyone could have cunho fetch for a chain they signed nothing under (the security review).
        signer = chain[0].public_key()
        if not verify(attestation.header["alg"], signer, attestation.signing_input, attestation.signature):
            fail("WIA.SIGNATURE_X5C", "the wallet attestation signature does not verify under its x5c certificate")
        try:
            validate_path(
                chain,
                self._trust.issuance(),
                dt.datetime.fromtimestamp(now, dt.UTC),
                frozenset(self._settings.wia_signer_policy_oids),
                revocation=self._trust.revocation(),
            )
        except JoseError:
            fail("WIA.CHAIN_TO_WP_LIST", "the wallet attestation is not from a trusted wallet provider")
        claims = attestation.payload
        sub = claims.get("sub")
        if not isinstance(sub, str) or not 0 < len(sub) <= MAX_CLIENT_ID:
            fail("WIA.VERIFY", "the wallet attestation needs a sub")
        if "aud" in claims and not self._for_us(claims["aud"]):
            # RFC 7519 §4.1.3: an attestation the provider signed for other audiences is not for this issuer, even
            # with a proof of possession made for it (the second reviewer).
            fail("WIA.VERIFY", "the wallet attestation is meant for another audience")
        exp = claims.get("exp")
        if not is_number(exp) or exp <= now:
            fail("WIA.NOT_EXPIRED", "the wallet attestation has expired or has no exp")
        for name in ("iat", "nbf"):
            if name in claims and (not is_number(claims[name]) or claims[name] > now + FUTURE_SKEW):
                fail("WIA.NOT_EXPIRED", f"the wallet attestation {name} is in the future")
        cnf = claims.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not isinstance(jwk, dict) or has_private_members(jwk):
            fail("WIA.CNF_PUBLIC", "the wallet attestation cnf must hold a public jwk")
        try:
            jkt = thumbprint(jwk)
            instance_key = public_key_from_jwk(jwk, pop.header["alg"])
        except JoseError:
            fail("WIA.CNF_PUBLIC", "the wallet attestation cnf key is not an accepted public key")
        if not verify(pop.header["alg"], instance_key, pop.signing_input, pop.signature):
            fail("WIA.POP_CNF", "the attestation proof of possession does not verify under the cnf key")
        self._fresh(pop.payload, now, jkt)
        if "iss" in pop.payload and pop.payload["iss"] != sub:
            fail("WIA.CLIENT_ID_IS_SUB", "the attestation proof of possession iss is not the attestation sub")
        if client_id is not None and client_id != sub:
            fail("WIA.CLIENT_ID_IS_SUB", "client_id is not the sub of the wallet attestation")
        if "client_status" not in claims and self._settings.conformance_mode:
            return ClientIdentity(sub, jkt, None, None, *_wallet(claims))
        status_exp, status = self._client_status(claims, now)
        if self._wallet_status is not None:
            # Last, so a request that fails a check that costs nothing never makes cunho fetch.
            try:
                self._wallet_status.check(claims["client_status"])
            except JoseError as exc:
                fail("WIA.CLIENT_STATUS", str(exc))
        return ClientIdentity(sub, jkt, status_exp, status, *_wallet(claims))

    def _for_us(self, aud: Any) -> bool:
        """An aud claim names this issuer: as the string, or as one of the strings of an array."""
        issuer = self._settings.issuer_url
        return aud == issuer or (isinstance(aud, list) and issuer in aud and all(isinstance(a, str) for a in aud))

    def _signed(self, token: str, typ: str, rule: str) -> Jws:
        try:  # strict base64url in three parts, which is within the token68 syntax of draft-07 §6.1
            jws = parse_jws(token)
        except JoseError:
            fail(rule, "a client attestation header is not a compact JWT")
        if jws.header.get("typ") != typ:
            fail(rule, f"typ must be {typ}")
        alg = jws.header.get("alg")
        if not isinstance(alg, str) or alg not in ALGORITHMS:
            fail(rule, f"alg must be one of {' '.join(sorted(ALGORITHMS))}")
        return jws

    @implements("WIA.POP_FRESH")
    def _fresh(self, claims: dict[str, Any], now: float, jkt: str) -> None:
        """aud is the issuer identifier and nothing else (FAPI 2.0 §5.3.2.1 item 8), iat lies in the window, and
        each jti is accepted once per instance key for as long as its iat could pass (draft-07 §12.1)."""
        if claims.get("aud") != self._settings.issuer_url:
            fail("WIA.POP_FRESH", "the attestation proof of possession aud must be the issuer identifier")
        iat = claims.get("iat")
        window = self._settings.client_attestation_pop_window
        if not is_number(iat) or iat > now + FUTURE_SKEW or iat < now - window:
            fail("WIA.POP_FRESH", "the attestation proof of possession iat is outside the accepted window")
        nbf = claims.get("nbf")
        if nbf is not None and (not is_number(nbf) or nbf > now + FUTURE_SKEW):
            # draft-07 §5.2: not accepted for processing before nbf (the second reviewer).
            fail("WIA.POP_FRESH", "the attestation proof of possession is not valid yet (nbf)")
        exp = claims.get("exp")
        if exp is not None and (not is_number(exp) or exp <= now):
            # draft-07 §5.2: valid in all other respects per RFC 7519, so an exp it carries must not have passed.
            fail("WIA.POP_FRESH", "the attestation proof of possession has expired (exp)")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not 16 <= len(jti) <= 256:
            fail("WIA.POP_FRESH", "the attestation proof of possession needs a jti of 16 to 256 characters")
        if not self._store.add("wia-pop-jti", f"{jkt}:{jti}", 1, window + FUTURE_SKEW + 5):
            fail("WIA.POP_FRESH", "this attestation proof of possession was already used")

    @implements("WIA.CLIENT_STATUS")
    def _client_status(self, claims: dict[str, Any], now: float) -> tuple[int, dict[str, Any]]:
        """TS3 v1.5.2 §2.3.1: client_status with a status list reference and the end of its maintenance period.
        That end, never the attestation's own exp, caps what is issued (CIR 2024/2979 Annex Ib C_WIA-3). Whether
        the entry says VALID is read from the wallet provider's list in `authenticate`."""
        status = claims.get("client_status")
        try:
            found = references(status)
        except JoseError:
            found = []
        enforce(
            bool(found),
            "WIA.CLIENT_STATUS",
            "invalid_client",
            "the wallet attestation needs client_status with a status list or identifier list reference",
            401,
        )
        assert isinstance(status, dict)
        exp = status.get("exp")
        if not is_number(exp) or exp <= now:
            fail("WIA.STATUS_EXP_NOT_TOKEN_EXP", "client_status.exp is missing or has passed")
        # Either mechanism (CIR 2024/2979 Annex II EAA-6.2.10.1-14, -16), kept as the attestation names it.
        member: dict[str, Any] = {}
        for each in found:
            member |= each.member()
        return int(exp), member
