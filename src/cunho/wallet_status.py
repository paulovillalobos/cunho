"""Wallet providers' status lists: whether a wallet attestation or a key attestation is still valid when cunho
issues (WIA.CLIENT_STATUS, KA.STATUS_AT_ISSUANCE; ARF WUA_25, TS3 v1.5.2 §2.4.3).

Both attestations point at an entry of a Token Status List (draft-ietf-oauth-status-list) that their wallet
provider publishes. `WalletStatus.check` fetches the list through the safe fetcher and accepts the attestation only
if its entry says VALID (0). The list is held to what its draft asks of a relying party, and more:

- a compact JWS with `typ` statuslist+jwt, signed under an `x5c` chain to the anchors for wallet providers'
  status lists (the Commission's list in production, cunho.trust), the signer's own revocation checked as for
  wallet attestations;
- `sub` the URI the attestation names, `iat` not ahead of now, and `exp`, which must be there and still ahead;
- `status_list` with `bits` 1, 2, 4 or 8 and `lst` a zlib stream of at most MAX_LIST bytes when inflated, so a
  small list cannot unfold into a large one; the entry read least significant bit first, as the draft lays out;
- a list older than one already seen at the same URI, by `iat`, is refused, so one replayed over the network cannot
  bring back an attestation that was revoked meanwhile. The newest `iat` seen is kept in the store for
  WATERMARK_TTL, apart from the lists in hand, so neither the bounded cache dropping a list, nor a restart, nor
  another worker forgets it.

A list is kept until its `exp`, its `ttl` or LIFETIME, whichever comes first. Whatever cannot be fetched, read or
checked refuses: the status is unknown. Refusals are StatusError with fixed text; the callers turn them into the
refusal of their own rule.
"""

from __future__ import annotations

import datetime as dt
import logging
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from cunho import cose
from cunho.fetch import Fetcher, FetchError
from cunho.jose import (
    ALGORITHMS,
    JoseError,
    b64u_decode,
    is_number,
    load_der_chain,
    load_x5c,
    parse_jws,
    sha256_b64u,
    validate_path,
    verify,
)
from cunho.revocation import _Bounded
from cunho.rules import implements
from cunho.status import CWT_EXP, CWT_IAT, CWT_SUB, CWT_TTL
from cunho.status_refs import Reference, Revoked, StatusError, references
from cunho.store import Store

if TYPE_CHECKING:
    from cunho.trust import Trust

log = logging.getLogger("cunho")
STATUS_TYP = "statuslist+jwt"
TYPES = frozenset({"application/statuslist+jwt"})
# The attestation revocation list mechanism (CIR 2024/2979 Annex II EAA-6.2.10.1-09, -10): a CWT of this type, whose
# claim IDENTIFIER_LIST holds the identifiers of the revoked attestations.
IDENTIFIER_TYP = "application/identifierlist+cwt"
IDENTIFIER_TYPES = frozenset({IDENTIFIER_TYP})
IDENTIFIER_LIST = 65530
MAX_TOKEN = 1024 * 1024
MAX_LIST = 16 * 1024 * 1024  # bytes of statuses once inflated
BUDGET = 2.0
SKEW = 60
LIFETIME = 3600  # the longest a list is kept, whatever its exp and ttl allow
# A list may live at most MAX_LIFETIME from its iat, and the newest iat seen at a URI is kept a day longer than
# that, from when it was seen: any older list has expired before the mark could, so it can never be replayed past
# it (the second reviewer). Wallet providers' lists live hours.
MAX_LIFETIME = 30 * 86_400
WATERMARK_TTL = MAX_LIFETIME + 86_400
VALID = 0


@dataclass(frozen=True)
class _List:
    statuses: bytes  # a status list's entries, or empty for an identifier list
    bits: int
    iat: int
    exp: float
    until: float  # when it must be fetched again
    chain: list[x509.Certificate]  # the signer's, judged again at every use
    ids: frozenset[bytes] = frozenset()  # an identifier list's revoked identifiers; none on a status list


class WalletStatus:
    def __init__(
        self,
        fetcher: Fetcher,
        trust: Trust,
        clock: Callable[[], float],
        store: Store,
        *,
        budget: float = BUDGET,
        entries: int = 1000,
    ) -> None:
        self._fetcher = fetcher
        self._trust = trust
        self._clock = clock
        self._store = store
        self._budget = budget
        self._lists = _Bounded(entries)

    @implements("STATUS.CLIENT_TSL")
    def check(self, status: Any) -> None:
        """Raise StatusError unless every entry an attestation's status member names says VALID now: Revoked when a
        list says otherwise, another StatusError when the status cannot be known. Both mechanisms are read (CIR
        2024/2979 Annex II EAA-6.2.10.1-16)."""
        for found in references(status):
            self.check_reference(found)

    def check_reference(self, found: Reference) -> None:
        """Raise unless the entry says VALID now."""
        listed = self._usable_now(self._list(found.uri, identifiers=found.id is not None))
        self._judge(listed, found)

    def verdicts(self, found: list[Reference]) -> dict[Reference, str]:
        """Revocation chaining's reading of one list, every entry it names at once: the list is fetched once, fresh,
        never one kept from before (the second reviewer), and each entry is "valid", "revoked" or "unknown". A list
        that cannot be used leaves every entry of it unknown, at the cost of one fetch."""
        if not found:
            return {}
        try:
            # The job can wait for its place in the host's minute, which a request cannot (Fetcher.wait_for).
            self._fetcher.wait_for(found[0].uri)
            listed = self._usable_now(self._list(found[0].uri, identifiers=found[0].id is not None, fresh=True))
        except StatusError:
            return {each: "unknown" for each in found}
        verdict: dict[Reference, str] = {}
        for each in found:
            try:
                self._judge(listed, each)
                verdict[each] = "valid"
            except Revoked:
                verdict[each] = "revoked"
            except StatusError:
                verdict[each] = "unknown"
        return verdict

    def _usable_now(self, listed: _List) -> _List:
        # Judged by the time it is used, read after any wait and fetch: a list that ran out meanwhile is refused,
        # and a list in hand is only as good as its signer is now, so a CRL that revokes the signer, or that or the
        # signer's certificate running out, ends it too (the second reviewer).
        now = self._clock()
        if now >= listed.exp:
            raise StatusError("the wallet provider's status list has no exp or has expired")
        self._trusted(listed.chain, now)
        return listed

    def _judge(self, listed: _List, found: Reference) -> None:
        """An entry against the list of its own kind: an identifier against an identifier list's identifiers, an
        index against a status list's entries (_list fetches each kind apart)."""
        if found.idx is not None:
            if _entry(listed, found.idx) != VALID:
                raise Revoked("the attestation is revoked or suspended on its wallet provider's status list")
            return
        if found.id in listed.ids:
            raise Revoked("the attestation is revoked on its wallet provider's identifier list")

    def _list(self, uri: str, *, identifiers: bool = False, fresh: bool = False) -> _List:
        key = ("identifiers" if identifiers else "statuses", uri)
        held: _List | None = self._lists.get(key)
        if held is not None and not fresh and self._usable(uri, held):
            return held
        with self._lists.flight(key):
            held = self._lists.get(key)
            if held is not None and not fresh and self._usable(uri, held):
                return held
            types = IDENTIFIER_TYPES if identifiers else TYPES
            try:
                data = self._fetcher.get(uri, types=types, max_bytes=MAX_TOKEN, budget=self._budget)
            except FetchError as exc:
                raise StatusError("the wallet provider's status list cannot be fetched") from exc
            now = self._clock()  # the time after the wait and the fetch
            try:
                fetched = self._verified_identifiers(data, uri, now) if identifiers else self._verified(data, uri, now)
            except StatusError:
                raise
            except Exception as exc:  # noqa: BLE001 - whatever a reply makes the reading raise, the status is unknown
                # Never an error of another kind: issuance would answer it 500, and one such list would end a run
                # of revocation chaining before any credential was judged (the security review).
                log.exception("a wallet provider's list could not be read")
                raise StatusError("the wallet provider's status list cannot be read") from exc
            self._raise_watermark(uri, fetched.iat)
            self._lists.put(key, fetched)
            return fetched

    def _usable(self, uri: str, held: _List) -> bool:
        """A list in hand stands in for a fetch until it is due again, and only while no newer list has been seen at
        its URI, by this worker or another: a worker's cache must not outlast a revocation another saw (the second
        reviewer)."""
        seen = self._store.get("wallet-status-iat", sha256_b64u(uri))
        return self._clock() < held.until and not (isinstance(seen, int) and held.iat < seen)

    def _raise_watermark(self, uri: str, iat: int) -> None:
        """Refuse a list older than the newest seen at `uri`, and keep the newer mark, in one transaction."""
        key = sha256_b64u(uri)
        with self._store.atomic():
            seen = self._store.get("wallet-status-iat", key)
            if isinstance(seen, int) and iat < seen:
                raise StatusError("the wallet provider's status list is older than one already seen")
            if not isinstance(seen, int) or iat > seen:
                self._store.put("wallet-status-iat", key, iat, WATERMARK_TTL)

    def _verified(self, data: bytes, uri: str, now: float) -> _List:
        try:
            token = parse_jws(data.decode("ascii"), MAX_TOKEN)
        except (JoseError, UnicodeDecodeError) as exc:
            raise StatusError("the wallet provider's status list is not a compact JWS") from exc
        header, claims = token.header, token.payload
        if header.get("typ") != STATUS_TYP:
            raise StatusError("the wallet provider's status list has the wrong typ")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in ALGORITHMS:
            raise StatusError("the wallet provider's status list is signed with an algorithm cunho does not accept")
        try:
            chain = load_x5c(header.get("x5c"))
        except JoseError as exc:
            raise StatusError("the wallet provider's status list is not signed by a trusted signer") from exc
        # The signature first: checking the path asks for the chain's revocation, which may fetch.
        if not verify(alg, chain[0].public_key(), token.signing_input, token.signature):
            raise StatusError("the wallet provider's status list signature does not verify")
        self._trusted(chain, now)
        if claims.get("sub") != uri:
            raise StatusError("the wallet provider's status list is not the one the attestation names")
        iat, exp, ttl = claims.get("iat"), claims.get("exp"), claims.get("ttl", None)
        if not isinstance(iat, int) or isinstance(iat, bool) or iat > now + SKEW:
            raise StatusError("the wallet provider's status list needs an iat that is not in the future")
        if not is_number(exp):  # whether it has passed is judged when the list is used, in `check`
            raise StatusError("the wallet provider's status list has no exp or has expired")
        if exp > iat + MAX_LIFETIME:
            raise StatusError("the wallet provider's status list lives longer than cunho accepts")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
            raise StatusError("the wallet provider's status list ttl is not a positive whole number")
        listed = claims.get("status_list")
        bits = listed.get("bits") if isinstance(listed, dict) else None
        lst = listed.get("lst") if isinstance(listed, dict) else None
        if bits not in (1, 2, 4, 8) or isinstance(bits, bool) or not isinstance(lst, str):
            raise StatusError("the wallet provider's status list needs bits of 1, 2, 4 or 8 and an lst")
        until = min(float(exp), now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)
        return _List(_inflated(lst), int(bits), iat, float(exp), until, chain)

    def _verified_identifiers(self, data: bytes, uri: str, now: float) -> _List:
        """An identifier list (CIR 2024/2979 Annex II EAA-6.2.10.1-08 to -10): a COSE_Sign1_Tagged CWT of type
        application/identifierlist+cwt, signed with ES256, ES384 or ES512 under the x5chain of its protected header
        to the anchors for wallet providers' status lists, with sub, iat, exp, an optional ttl and the IdentifierList
        claim, held to the same bounds as a status list."""
        try:
            message = cose.decode(data)
            if not isinstance(message, cbor2.CBORTag) or message.tag != cose.SIGN1:
                raise cose.CoseError("not a COSE_Sign1_Tagged")
            header = cose.decode(message.value[0]) if isinstance(message.value, list) and message.value else None
            if not isinstance(header, dict):
                raise cose.CoseError("no protected header")
        except (cose.CoseError, IndexError) as exc:
            raise StatusError("the wallet provider's identifier list is not a COSE_Sign1_Tagged CWT") from exc
        if header.get(cose.TYP) != IDENTIFIER_TYP:
            raise StatusError("the wallet provider's identifier list has the wrong type")
        try:
            chain = load_der_chain(cose.x5chain_certificates(header.get(cose.X5CHAIN)))
        except (cose.CoseError, JoseError) as exc:
            raise StatusError("the wallet provider's identifier list is not signed by a trusted signer") from exc
        key = chain[0].public_key()
        try:
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise cose.CoseError("not an EC key")
            _, _, payload = cose.verify1(message, key)
            claims = cose.decode(payload)
        except cose.CoseError as exc:
            raise StatusError("the wallet provider's identifier list signature does not verify") from exc
        self._trusted(chain, now)  # after the signature: checking the path may fetch the chain's revocation
        if not isinstance(claims, dict) or claims.get(CWT_SUB) != uri:
            raise StatusError("the wallet provider's identifier list is not the one the attestation names")
        iat, exp, ttl = claims.get(CWT_IAT), claims.get(CWT_EXP), claims.get(CWT_TTL)
        if not isinstance(iat, int) or isinstance(iat, bool) or iat > now + SKEW:
            raise StatusError("the wallet provider's identifier list needs an iat that is not in the future")
        if not isinstance(exp, int) or isinstance(exp, bool):
            raise StatusError("the wallet provider's identifier list has no exp or has expired")
        if exp > iat + MAX_LIFETIME:
            raise StatusError("the wallet provider's identifier list lives longer than cunho accepts")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
            raise StatusError("the wallet provider's identifier list ttl is not a positive whole number")
        listed = claims.get(IDENTIFIER_LIST)
        identifiers = listed.get("identifiers") if isinstance(listed, dict) else None
        if not isinstance(identifiers, dict) or not all(isinstance(i, bytes) for i in identifiers):
            raise StatusError("the wallet provider's identifier list needs identifiers, a map keyed by byte strings")
        until = min(float(exp), now + (ttl if ttl is not None else LIFETIME), now + LIFETIME)
        return _List(b"", 1, iat, float(exp), until, chain, frozenset(identifiers))

    def _trusted(self, chain: list[x509.Certificate], now: float) -> None:
        try:
            validate_path(
                chain,
                self._trust.status(),
                dt.datetime.fromtimestamp(now, dt.UTC),
                revocation=self._trust.revocation(),
            )
        except JoseError as exc:
            raise StatusError("the wallet provider's status list is not signed by a trusted signer") from exc


def _inflated(lst: str) -> bytes:
    """The statuses of `lst`: a zlib stream (RFC 1950) of at most MAX_LIST bytes once inflated, complete, with
    nothing after it."""
    try:
        packed = b64u_decode(lst)
        inflater = zlib.decompressobj()
        statuses = inflater.decompress(packed, MAX_LIST + 1)
    except (JoseError, ValueError, zlib.error) as exc:
        raise StatusError("the wallet provider's status list lst cannot be read") from exc
    if len(statuses) > MAX_LIST:  # the inflater stops one byte past the cap, so more is left in it
        raise StatusError("the wallet provider's status list is larger than allowed once inflated")
    if not inflater.eof or inflater.unused_data:
        raise StatusError("the wallet provider's status list lst is cut short or has data after it")
    return statuses


def _entry(listed: _List, idx: int) -> int:
    """Entry `idx`: `bits` bits, the first entry in the least significant bits of the first byte."""
    at = idx * listed.bits
    if at // 8 >= len(listed.statuses):
        raise StatusError("the attestation's status list entry is outside the list")
    return (listed.statuses[at // 8] >> (at % 8)) & ((1 << listed.bits) - 1)
