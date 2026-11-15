"""Token Status List (draft-ietf-oauth-status-list-21) for revocation.

One bit per credential: 0 valid, 1 revoked (CIR 2024/2979 Annex II allows no other value). Indexes are
drawn at random and reserved atomically. Each list starts with revoked decoys, and `churn` keeps adding
decoys over time.

Revocations and decoys have the same shape (review 3, N3-M3). Revoking a person flips every credential
of their batch, so each revoked bit becomes visible at its own random moment within
`status_revocation_jitter` seconds instead of all at once. Decoys arrive as clusters at Poisson moments;
a cluster's size is drawn from the sizes of the batches this issuer actually handed out, and each of its
bits becomes visible at its own random moment within the same window. A poller therefore sees k bits
appear within one window in both cases, and cannot tell a revocation from a decoy cluster by its timing
or its size; only by the rate, in the proportion of the decoy rate to the revocation rate. What decoys
cannot hide is the overall trend in the count, and they hide little when revocations far outnumber them.

Lists are published on fixed moments, every `status_publish_interval` seconds (a minute by default): the
token's `iat` is that moment and it shows the bits due by then. A revoked bit that is still hidden changes
nothing a poller can see, and the moments do not depend on any revocation, so `iat` does not give one away
(review 4, N4-M3). The published bits are kept in the store and brought forward from a queue keyed by the
moment each bit shows, so a publication costs the number of bits that came due, and a poll between two
publications costs a dictionary lookup, however many bits are hidden (review 5, N5-M3). With a jitter of 0 a
revocation shows at the next publication, by choice, and its moment, to within the interval, with it.
"""

from __future__ import annotations

import base64
import logging
import math
import secrets
import threading
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass

import cbor2

from cunho import cose
from cunho.jose import b64u, b64u_decode
from cunho.rules import implements
from cunho.settings import CLOCK_TOLERANCE, Settings
from cunho.signer import Signer, sign_jws
from cunho.store import Store

VALID, REVOKED = 0, 1
JWT, CWT = "jwt", "cwt"
# CWT claim keys (RFC 8392 §3.1.2, §3.1.4, §3.1.6; draft-ietf-oauth-status-list-21 §5.2, §14.2)
CWT_SUB, CWT_EXP, CWT_IAT, CWT_TTL, CWT_STATUS_LIST = 2, 4, 6, 65534, 65533
DAY = 86_400
FULL = 0.9  # decoys never push a list past this share of its slots
PAGE = 1000  # queued bits applied per store read
security_log = logging.getLogger("cunho.security")


class StatusError(Exception):
    """The stored state of a list is missing or does not fit it. Never answered with a list of zeros."""


@dataclass(frozen=True)
class StatusRef:
    list_id: str
    index: int

    def claim(self, base: str) -> dict[str, dict[str, object]]:
        return {"status_list": {"idx": self.index, "uri": f"{base}/status/{self.list_id}"}}


class StatusLists:
    def __init__(self, settings: Settings, store: Store, signer: Signer, clock: Callable[[], float] = time.time):
        self._settings = settings
        self._store = store
        self._signer = signer
        self._clock = clock
        self._interval = settings.status_publish_interval
        # (list id, form) -> (publication, token): the JWT form as text, the CWT form as bytes
        self._cache: dict[tuple[str, str], tuple[tuple[int, bool], str | bytes]] = {}
        self._sizes: dict[str, int] = {}  # a list's size never changes once it is open
        self._lock = threading.Lock()
        self._builds: dict[str, threading.Lock] = {}
        # The time revocations and publications go by: the clock watch's in an Issuer (ClockWatch.now), None
        # while it cannot vouch for the time.
        self.now: Callable[[], float | None] = clock

    def _key(self, list_id: str, index: int) -> str:
        return f"{list_id}:{index:08d}"

    def size_of(self, list_id: str) -> int | None:
        """The size the list was opened with, or None when there is no such list. Changing the setting later
        applies to new lists only, so lists already published keep their length and every slot in them stays
        revocable (review 5, N5-L4). A list without a stored size is never given the setting's instead: the
        schema upgrade stores one for every list (review 6, N6-M2)."""
        size = self._sizes.get(list_id)
        if size is not None:
            return size
        meta = self._store.get("status-meta", f"list:{list_id}")
        if meta is None:
            return None
        size = meta.get("size") if isinstance(meta, dict) else None
        if not isinstance(size, int):
            raise _missing(f"status list {list_id} has no stored size")
        with self._lock:
            self._sizes[list_id] = size
        return size

    def _size(self, list_id: str) -> int:
        """The size of a list this code just found or opened, so one that exists."""
        size = self.size_of(list_id)
        assert size is not None
        return size

    def _current_list(self) -> str:
        current = self._store.get("status-meta", "current")
        if current is None:
            current = self._open_list(1)
        return str(current)

    def _open_list(self, number: int) -> str:
        list_id = str(number)
        size = self._settings.status_list_size
        now = self.now()
        opened = int(self._clock() if now is None else now)
        if self._store.add("status-meta", f"list:{list_id}", {"opened": opened, "size": size}, None):
            bits = bytearray(size // 8)
            for _ in range(int(size * self._settings.status_decoy_ratio)):
                index = self._reserve(list_id, REVOKED)
                self._store.put("status-decoy", self._key(list_id, index), 1, None)
                bits[index // 8] |= 1 << (index % 8)  # the decoys a list starts with show at once
            self._store.put("status-visible", list_id, _pack(bits), None)
            # A new list gets its decoy schedule at once, not at the next maintenance run (review 3, N3-M3), when
            # there is a time to lay it from.
            if now is not None:
                self._schedule(list_id, now)
        self._store.put("status-meta", "current", list_id, None)
        return list_id

    def _reserve(self, list_id: str, value: int) -> int:
        size = self._size(list_id)
        while True:
            index = secrets.randbelow(size)
            if self._store.add("status-slot", self._key(list_id, index), value, None):
                self._store.incr("status-count", list_id, None)
                return index

    def _decoy(self, list_id: str, at: float) -> None:
        """A revoked decoy slot whose bit stays hidden until `at`."""
        index = self._reserve(list_id, REVOKED)
        self._store.put("status-decoy", self._key(list_id, index), 1, None)
        self._show_at(list_id, index, at)

    def lists(self) -> list[str]:
        return [key.split(":", 1)[1] for key, _ in self._store.items("status-meta", "list:")]

    @implements(
        "PRIV.STATUS_IDX_RANDOM",
        "PRIV.STATUS_LIST_HERD_SIZE",
        "STATUS.TSL.NO_DOUBLE_ALLOCATION",
        "STATUS.TSL.FRESH_ENTRY_PER_CREDENTIAL",
    )
    def allocate(self) -> StatusRef:
        """A fresh, random, never reused slot. Lists close at the fill limit to keep herds large."""
        with self._store.atomic():
            list_id = self._current_list()
            used = int(self._store.get("status-count", list_id) or 0)
            if used >= self._size(list_id) * self._settings.status_list_fill_limit:
                list_id = self._open_list(int(list_id) + 1)
            return StatusRef(list_id, self._reserve(list_id, VALID))

    def revocable(self, ref: StatusRef) -> bool:
        """True when the slot holds a real credential that is still valid (a decoy is revoked from the start)."""
        return self._store.get("status-slot", self._key(ref.list_id, ref.index)) == VALID

    @implements("STATUS.MONOTONIC", "STATUS.NO_SUSPENSION")
    def revoke(self, ref: StatusRef) -> bool:
        """Set a live credential's bit to 1. There is no way back to 0.

        Returns True only when a real, still valid credential was revoked now: never for decoys,
        unknown slots or slots that were already revoked. The bit is set at once and shows in the
        published list at a random moment within `status_revocation_jitter` seconds, the same spread a
        decoy cluster has, so the bits of one person's batch do not appear together (review 3, N3-M3).
        Nothing a poller can see changes before then (review 4, N4-M3); with a jitter of 0 the bit shows
        at the next publication.

        The moment is laid on the clock watch's time, which lists are published by too, so a wall clock that
        reads ahead or behind moves neither the moment nor the publication (review 6, N6-M1; review 7, M1).
        When the watch cannot vouch for the time yet, the bit shows at the next publication, without its
        jitter: later would be a guess.
        """
        key = self._key(ref.list_id, ref.index)
        # Check and set in one transaction: two concurrent revocations of one slot report it once. The moment is
        # laid by the time read inside it, as every moment is (CX-29).
        with self._store.atomic():
            now = self.now()
            if now is None:
                security_log.warning("the clock watch cannot vouch for the clock yet: a revocation shows at once")
            if not self.revocable(ref):
                return False
            self._store.put("status-slot", key, REVOKED, None)
            at = 0.0 if now is None else now + _uniform(self._settings.status_revocation_jitter)
            self._show_at(ref.list_id, ref.index, at)
            return True

    def _show_at(self, list_id: str, index: int, at: float) -> None:
        """Queue a revoked bit to show at `at`. The queue is keyed by that moment, so a publication reads only
        the bits that came due, however many are still hidden (review 5, N5-M3)."""
        self._store.put("status-pending", f"{list_id}:{int(at * 1000):016d}:{index:08d}", at, None)

    def note_batch(self, size: int) -> None:
        """Count one issued batch of `size` credentials: decoy clusters draw their sizes from these counts."""
        if size > 0:
            self._store.incr("status-batch", str(size), None)

    def _cluster_sizes(self) -> list[tuple[int, int]]:
        counts = [(int(k), int(v)) for k, v in self._store.items("status-batch") if k.isdecimal() and int(v) > 0]
        return counts or [(1, 1)]

    def value(self, ref: StatusRef) -> int | None:
        value = self._store.get("status-slot", self._key(ref.list_id, ref.index))
        return None if value is None else int(value)

    def exists(self, list_id: str) -> bool:
        return self.size_of(list_id) is not None

    def churn(self) -> int:
        """Schedule decoy clusters for the coming window on every list; returns how many decoys.

        The rate is `status_decoy_churn_per_day` of the list size per day, in bits. The schedule is kept
        per list in the store, so several workers running maintenance extend one schedule instead of each
        adding their own, a list opened later gets its own schedule from its first moment, and time spent
        stopped is not made up in a burst.
        """
        with self._store.atomic():
            # Read inside the transaction, as every expiry is: a forced run in another worker may move the time
            # meanwhile, and decoys laid by the time before would come due together (the second reviewer, CX-25).
            now = self.now()
            if now is None:
                return 0
            return sum(self._schedule(list_id, now) for list_id in self.lists())

    def _schedule(self, list_id: str, now: float) -> int:
        """Extend one list's schedule to two maintenance intervals ahead. Call inside a transaction."""
        size = self._size(list_id)
        rate = size * self._settings.status_decoy_churn_per_day / DAY
        if rate <= 0:
            return 0
        horizon = now + 2 * self._settings.maintenance_interval
        mark = f"scheduled_until:{list_id}"
        stored = float(self._store.get("status-meta", mark) or now)
        if stored > now + 2 * max(self._settings.maintenance_interval, DAY):
            # No worker schedules that far ahead, whatever its interval: the mark was set while the clock was
            # far ahead, and would stop decoys until that time came round. Lay the schedule down again from
            # now (review 4, N4-M8).
            stored = now
        start = max(stored, now)
        # Never shrink the schedule; when it already reaches the horizon the loop below adds nothing.
        self._store.put("status-meta", mark, max(start, horizon), None)
        sizes = self._cluster_sizes()
        mean = sum(k * n for k, n in sizes) / sum(n for _, n in sizes)
        spread = self._settings.status_revocation_jitter
        room = int(size * FULL) - int(self._store.get("status-count", list_id) or 0)
        added = 0
        moment = start + _exponential(rate / mean)
        while moment < horizon and room > 0:
            for _ in range(min(_weighted(sizes), room)):
                self._decoy(list_id, moment + _uniform(spread))
                added, room = added + 1, room - 1
            moment += _exponential(rate / mean)
        return added

    def _publication(self) -> tuple[tuple[int, bool], float]:
        """The current publication, by the clock watch's time, and the moment its bits are due by. While the
        watch cannot vouch for the time, the publication is the wall clock's and brings forward only the bits
        laid to show at once: a list then shows what it showed, and the revocations made meanwhile."""
        now = self.now()
        if now is None:
            return (int(self._clock() // self._interval), False), 0.0
        epoch = int(now // self._interval)
        return (epoch, True), float(epoch * self._interval)

    def _advance(self, list_id: str, upto: float) -> str:
        """The published bits of a list as of `upto`: the stored visible state, with the bits that came due by
        then applied and taken off the queue in one transaction. The work is the number of bits that came due,
        never the number still hidden or the number of slots in use (review 5, N5-M3)."""
        prefix, limit = f"{list_id}:", f"{list_id}:{int(upto * 1000):016d}:~"
        if self._store.scan("status-pending", prefix, 1, limit):
            with self._store.atomic():
                # The cutoff read again inside the transaction, and the earlier one taken: a forced run in another
                # worker may have moved the time back since `upto` was read, and queued a bit that is not due by
                # the time it set (the second reviewer, CX-23).
                upto = min(upto, self._publication()[1])
                limit = f"{list_id}:{int(upto * 1000):016d}:~"
                bits = bytearray(_unpack(self._visible(list_id)))
                cursor = prefix
                while True:
                    due = [key for key, _ in self._store.scan("status-pending", cursor, PAGE, limit)]
                    for key in due:
                        index = int(key.rsplit(":", 1)[1])
                        bits[index // 8] |= 1 << (index % 8)
                        self._store.delete("status-pending", key)
                    if len(due) < PAGE:
                        break
                    cursor = due[-1]
                visible = _pack(bits)
                self._store.put("status-visible", list_id, visible, None)
                return visible
        return self._visible(list_id)

    def _visible(self, list_id: str) -> str:
        """The published bits of a list as stored. A list that has none, or bits of another length, fails
        loudly: answering with zeros would take back every bit it ever showed (review 6, N6-M2)."""
        stored = self._store.get("status-visible", list_id)
        try:
            length = len(_unpack(stored)) if isinstance(stored, str) else -1
        except (ValueError, zlib.error):
            length = -1
        if length != self._size(list_id) // 8:
            raise _missing(f"status list {list_id} has no stored published bits of its size")
        return str(stored)

    def publish(self) -> int:
        """Bring every list's published bits up to the current publication; maintenance runs it about once a
        minute, so requests seldom find more than a minute's worth of bits to apply. Returns how many lists."""
        _, upto = self._publication()
        lists = self.lists()
        for list_id in lists:
            self._relay(list_id)
            self._advance(list_id, upto)
        return len(lists)

    def _relay(self, list_id: str) -> None:
        """Lay again, within the jitter of the time, every queued moment later than any a clock that read right
        could have laid: decoys are scheduled two maintenance intervals ahead at most, each within the jitter of
        its moment, and revocations within the jitter. Such a moment was laid by a time that read ahead, before a
        host restart laid the clock watch's base behind it, and would hide its bit for as long (review 7, M1).
        Normally there is none, and finding none costs one read of the queue's far end.

        The time is read inside each transaction that lays moments again, never before it: a forced run in
        another worker may move it forward meanwhile, and a moment rightly laid by the new time would be taken
        for one too late and brought forward, its jitter lost (the second reviewer, CX-21). While the clock
        watch cannot vouch for the time, nothing is laid again."""
        settings = self._settings
        while True:
            with self._store.atomic():
                now = self.now()
                if now is None:
                    return
                horizon = now + 2 * settings.maintenance_interval + settings.status_revocation_jitter + CLOCK_TOLERANCE
                after, end = f"{list_id}:{int(horizon * 1000):016d}:~", f"{list_id}:~"
                late = self._store.scan("status-pending", after, PAGE, end)
                if not late:
                    return
                for key, _ in late:
                    self._store.delete("status-pending", key)
                    self._show_at(
                        list_id, int(key.rsplit(":", 1)[1]), now + _uniform(settings.status_revocation_jitter)
                    )
            security_log.warning(
                "%d bits of status list %s were queued later than a clock that reads right lays any; they are laid "
                "again within the jitter",
                len(late),
                list_id,
            )

    def encoded(self, list_id: str) -> str:
        return self._advance(list_id, self._publication()[1])

    def cached(self, list_id: str, form: str = JWT) -> str | bytes | None:
        """The token of the current publication when this worker already signed it: no store access at all,
        so a poller costs a dictionary lookup (review 5, N5-M3)."""
        entry = self._cache.get((list_id, form))
        return entry[1] if entry is not None and entry[0] == self._publication()[0] else None

    @implements(
        "STATUS.TSL.ENCODING",
        "STATUS.TSL.TOKEN_CLAIMS",
        "STATUS.LIST_SIGNER_AUTHENTICATED",
        "STATUS.RETAINED_BEYOND_VALIDITY",
        "STATUS.REFERENCE_PUBLIC",
    )
    def token(self, list_id: str) -> str:
        """The signed list of the current publication as a JWT (draft-ietf-oauth-status-list-21 §5.1)."""
        token = self._signed(list_id, JWT)
        assert isinstance(token, str)
        return token

    def cwt(self, list_id: str) -> bytes:
        """The same list as a CWT (§5.2), for mdoc: the same bits, `sub`, `iat`, `exp` and `ttl`."""
        token = self._signed(list_id, CWT)
        assert isinstance(token, bytes)
        return token

    def _signed(self, list_id: str, form: str) -> str | bytes:
        """Lists are published on fixed moments, every `status_publish_interval` seconds, with `iat` at that moment
        and the bits due by then, so neither the token nor its `iat` changes at the moment of a revocation (review 4,
        N4-M3). Each worker signs a list at most once per publication and form; concurrent requests wait for the one
        that signs."""
        token = self.cached(list_id, form)
        if token is not None:
            return token
        with self._lock:
            build = self._builds.setdefault(list_id, threading.Lock())
        with build:
            publication, upto = self._publication()
            entry = self._cache.get((list_id, form))
            if entry is not None and entry[0] == publication:
                return entry[1]
            start = publication[0] * self._interval
            uri = f"{self._settings.issuer_url}/status/{list_id}"
            lst = self._advance(list_id, upto)
            exp = start + self._settings.status_token_lifetime
            token = self._cwt(uri, start, exp, b64u_decode(lst)) if form == CWT else self._jwt(uri, start, exp, lst)
            self._cache[(list_id, form)] = (publication, token)
            return token

    def _jwt(self, uri: str, iat: int, exp: int, lst: str) -> str:
        header = {"typ": "statuslist+jwt", "x5c": self._signer.x5c()}
        payload = {
            # iss is optional in the Token Status List (draft-21 §5.1); some wallets verify the token as they verify
            # an SD-JWT VC and require it (Sphereon).
            "iss": self._settings.issuer_url,
            "sub": uri,
            "iat": iat,
            "exp": exp,
            "ttl": self._settings.status_token_ttl,
            "status_list": {"bits": 1, "lst": lst},
        }
        return sign_jws(self._signer, header, payload)

    @implements("STATUS.MDOC_CWT_PROFILE")
    def _cwt(self, uri: str, iat: int, exp: int, lst: bytes) -> bytes:
        """draft-ietf-oauth-status-list-21 §5.2: a COSE_Sign1_Tagged CWT, not tagged as a CWT, with its type in the
        protected header; CIR 2024/2979 Annex II EAA-6.2.10.1-07 and -08 ask for exp and for the signer's x5chain in
        the protected header."""
        chain = [base64.b64decode(der) for der in self._signer.x5c()]
        claims = {
            CWT_SUB: uri,
            CWT_IAT: iat,
            CWT_EXP: exp,
            CWT_TTL: self._settings.status_token_ttl,
            CWT_STATUS_LIST: {"bits": 1, "lst": lst},
        }
        protected = {cose.TYP: "application/statuslist+cwt", cose.X5CHAIN: cose.x5chain(chain)}
        return cose.encode(cbor2.CBORTag(cose.SIGN1, cose.sign1(self._signer, cose.encode(claims), protected, {})))


def _pack(bits: bytearray) -> str:
    return b64u(zlib.compress(bytes(bits), 9))


def _unpack(stored: str) -> bytes:
    return zlib.decompress(b64u_decode(stored))


def _missing(problem: str) -> StatusError:
    security_log.error("%s; the store needs the schema upgrade, or was changed by hand", problem)
    return StatusError(problem)


def _exponential(rate: float) -> float:
    """An exponential waiting time from the CSPRNG, so the decoy schedule cannot be predicted."""
    uniform = (secrets.randbelow(2**53) + 1) / 2**53
    return -math.log(uniform) / rate


def _uniform(width: float) -> float:
    """A uniform delay in [0, width) from the CSPRNG."""
    return secrets.randbelow(2**53) / 2**53 * width if width > 0 else 0.0


def _weighted(sizes: list[tuple[int, int]]) -> int:
    """A cluster size drawn in proportion to how often batches of that size were issued."""
    pick = secrets.randbelow(sum(n for _, n in sizes))
    for size, count in sizes[:-1]:
        if pick < count:
            return size
        pick -= count
    return sizes[-1][0]
