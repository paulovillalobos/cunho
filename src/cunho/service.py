"""The issuer: wires the components together and runs the issuance flow."""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import datetime as dt
import functools
import json
import logging
import math
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from cunho import annex_b, cose, mdoc, metadata, schema
from cunho.audit import CLOCK_TRUSTED, Anchor, AuditError, AuditLog, Mark, Vault
from cunho.authorize import CODE_GRANT, REFRESH_GRANT, Authorization
from cunho.client_auth import ATTESTATION_HEADER, POP_HEADER, ClientAuth, ClientIdentity
from cunho.credentials import (
    EXPIRY_CLAIMS,
    MDOC_ISSUANCE_DATES,
    ClaimsError,
    check_subject,
    config_claims,
    parse_date,
    pid_mdoc_elements,
    sd_jwt_vc,
)
from cunho.errors import ConfigError, IssuerError
from cunho.fetch import Fetcher
from cunho.jose import (
    JoseError,
    b64u,
    b64u_decode,
    parse_jws,
    public_key_from_jwk,
    sha256_b64u,
    strict_json,
    thumbprint,
)
from cunho.jose import verify as verify_signature
from cunho.jwe import JweError, RequestKeys, ResponseKey
from cunho.keyring import Keyring, same
from cunho.oauth import Dpop, Grant, Nonces, Offers, Tokens, offer_key, opened, seal
from cunho.proofs import ProofVerifier, ProvenKeys
from cunho.qualified import CATEGORIES, FILLED, authority, check_provider, names_another_subject
from cunho.rules import enforce, implements, refuse
from cunho.settings import CLOCK_TOLERANCE, Profile, Settings
from cunho.signed_metadata import check_access_signer, signed_metadata
from cunho.signer import KeyringSigner, Signer, load_signer
from cunho.status import StatusLists, StatusRef
from cunho.status_refs import Reference, Revoked, references
from cunho.store import MemoryStore, PostgresStore, SqliteStore, Store
from cunho.trust import Trust
from cunho.wallet_status import WalletStatus

DAY = 86_400
SUBJECT_REF = re.compile(r"sub_[A-Za-z0-9_-]{24}")  # always with fullmatch: `$` also matches before a newline
PERSON_HANDLE = re.compile(r"[\x21-\x7e]{1,200}")
LOGIN_GONE = "login already reported, or another login from its request completed first"
# The only route names that failed operator logins are counted under; never the raw path (review 2, N-H2).
ADMIN_ROUTES = frozenset(
    {
        "/admin/offers",
        "/admin/offers/{subject_ref}",
        "/admin/offers/{subject_ref}/cancel",
        "/admin/revocations",
        "/admin/subjects/{subject_ref}/erase",
        "/admin/audit/verify",
        "/admin/audit/head",
        "/admin/logins/{login_state}",
        "/admin/deferred",
        "/admin/deferred/{ref}/release",
        "/admin/deferred/{ref}/refuse",
    }
)
security_log = logging.getLogger("cunho.security")
log = logging.getLogger("cunho")
# ARF revocation triggers (REVOC.ON_*). A closed list keeps free text, and so personal data, out of the log.
PAGE = 500  # rows revocation chaining reads at a time
# Issuances of one configuration that one login may have waiting for the operator's review, decided or not, at a
# time: a wallet whose first ask was lost may ask again, and no wallet fills the operator's list.
HELD_PER_CONFIGURATION = 3
COLLECTING = 60  # seconds one request has to collect a released issuance before another may try
# Notification events (OpenID4VCI 1.0 §11.1), and the characters an event_description may hold: printable ASCII
# without the double quote and the backslash.
EVENTS = frozenset({"credential_accepted", "credential_failure", "credential_deleted"})
EVENT_DESCRIPTION = re.compile(r"[\x20\x21\x23-\x5b\x5d-\x7e]{0,1000}")
TRANSACTION_REF = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class Reply:
    """A credential or deferred credential response: its content, and the compact JWE of it when the wallet asked
    for an encrypted response (OpenID4VCI 1.0 §8.3, §9.2)."""

    body: dict[str, Any]
    jwe: str | None = None

    @property
    def status(self) -> int:
        """200 with credentials, or 202 with a transaction_id while the issuance waits."""
        return 202 if "transaction_id" in self.body else 200


class LeaseLost(Exception):
    """A revocation chaining run no longer holds the lease: another worker runs it now."""


REVOCATION_REASONS = frozenset(
    {"user_request", "death", "compromise", "attribute_change", "wallet_revoked", "administrative"}
)


@dataclass(frozen=True)
class Signers:
    credentials: Signer
    status: Signer
    access: Signer | None = None  # the access certificate, which signs the issuer metadata (M3)
    mdoc: Signer | None = None  # the mdoc document signer (M4)


def default_signers(settings: Settings) -> Signers:
    """The signers the settings name. Production keeps every signing key in an HSM or KMS: a PEM file is refused."""
    signer = functools.partial(
        load_signer,
        production=settings.production,
        pkcs11_module=settings.pkcs11_module,
        pkcs11_pin_file=settings.pkcs11_pin_file,
    )
    anchors = settings.signing_trust_anchors
    credentials = signer(settings.signing_key, settings.signing_chain, anchors)
    status = credentials
    if settings.status_signing_key and settings.status_signing_chain:
        status = signer(settings.status_signing_key, settings.status_signing_chain, anchors, name="status_signing_key")
    access = None
    if settings.access_signing_key and settings.access_signing_chain:
        access = signer(
            settings.access_signing_key,
            settings.access_signing_chain,
            settings.access_trust_anchors,
            name="access_signing_key",
        )
    mdoc = None
    if settings.mdoc_signing_key and settings.mdoc_signing_chain:
        mdoc = signer(
            settings.mdoc_signing_key,
            settings.mdoc_signing_chain,
            settings.mdoc_trust_anchors,
            name="mdoc_signing_key",
        )
    return Signers(credentials, status, access, mdoc)


def _issuer_info(settings: Settings) -> list[dict[str, Any]] | None:
    """issuer_info from the registration certificate and registrar dataset files, when the deployment has them."""
    if settings.registration_certificate is None and settings.registrar_dataset is None:
        return None
    if settings.registration_certificate is None or settings.registrar_dataset is None:
        raise ConfigError("set registration_certificate and registrar_dataset together")
    try:
        certificate = settings.registration_certificate.read_text(encoding="ascii")
        dataset = strict_json(settings.registrar_dataset.read_bytes())
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read the registration certificate or registrar dataset: {exc}") from exc
    return metadata.issuer_info(certificate, dataset)


def default_store(settings: Settings, clock: Callable[[], float]) -> Store:
    if settings.store_url is not None:
        return PostgresStore(settings.store_url, clock)
    if settings.store_path is None:
        return MemoryStore(clock)
    return SqliteStore(Path(settings.store_path), clock)


def default_anchor(settings: Settings, store: Store, keyring: Keyring) -> Anchor:
    """The configured anchor file; in development a file next to the SQLite store, or memory."""
    if settings.audit_anchor_path is not None:
        return Anchor(settings.audit_anchor_path, keyring)
    if isinstance(store, SqliteStore):
        return Anchor(Path(f"{store.path}.audit-anchor"), keyring)
    return Anchor(None, keyring)


class AuthFailures:
    """Failed operator logins, counted per fixed route name and flushed to the audit log as one entry.

    Each failure goes to the operational log (`cunho.security`). The audit chain gets at most one
    aggregate entry per maintenance run per worker, holding only counts, route names from a fixed list
    and times, so anonymous clients can neither grow the log at will nor write text into it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._routes: dict[str, int] = {}
        self._with_token = 0
        self._first: int | None = None
        self._last: int | None = None

    def record(self, route: str, with_token: bool, now: float) -> None:
        with self._lock:
            name = route if route in ADMIN_ROUTES else "other"
            self._routes[name] = self._routes.get(name, 0) + 1
            self._with_token += int(with_token)
            self._first = int(now) if self._first is None else self._first
            self._last = int(now)

    def drain(self) -> dict[str, Any] | None:
        with self._lock:
            if not self._routes:
                return None
            summary = {
                "count": sum(self._routes.values()),
                "routes": dict(sorted(self._routes.items())),
                "with_token": self._with_token,
                "first": self._first,
                "last": self._last,
            }
            self._routes, self._with_token, self._first, self._last = {}, 0, None, None
            return summary


def host_elapsed() -> float:
    """Seconds on the host's own clock, which wall-clock steps do not move and which keeps counting while the
    host sleeps: CLOCK_BOOTTIME on Linux, CLOCK_MONOTONIC on macOS (which counts sleep there)."""
    return time.clock_gettime(getattr(time, "CLOCK_BOOTTIME", time.CLOCK_MONOTONIC))


@functools.cache
def host_boot() -> str | None:
    """An identifier of the current boot of the host, or None where there is none to read. A process never
    outlives the boot it started in, so it is read once."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() or None
    except OSError:
        pass
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        size, value = ctypes.c_size_t(64), ctypes.create_string_buffer(64)
        if libc.sysctlbyname(b"kern.bootsessionuuid", value, ctypes.byref(size), None, ctypes.c_size_t(0)) == 0:
            return value.value.decode() or None
    except (OSError, AttributeError, UnicodeDecodeError):
        pass
    return None


def kernel_clock_synced() -> bool | None:
    """Whether the kernel says NTP keeps its clock in sync. `ntp_adjtime` with no change asked for only
    reads the state, and TIME_ERROR (5) means unsynchronised. None where that cannot be asked."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"))
        state = int(libc.ntp_adjtime(ctypes.create_string_buffer(1024)))  # larger than any struct timex
    except (OSError, AttributeError, TypeError):
        return None
    return None if state < 0 else state != 5


@dataclass(frozen=True)
class HostClock:
    """What the host can say about time besides the wall clock: its own clock, which steps do not move, the
    boot that clock counts from, and whether the kernel reports NTP sync (None when it cannot say)."""

    elapsed: Callable[[], float] = host_elapsed
    boot: Callable[[], str | None] = host_boot
    synced: Callable[[], bool | None] = kernel_clock_synced


@dataclass(frozen=True)
class Base:
    """A wall-clock reading the watch trusted, with the host clock and boot at that moment."""

    time: float
    elapsed: float
    boot: str


def _finite(value: int | float) -> float | None:
    """`value` as a float, or None: a number written into the database too large for a float is a row that does
    not verify, never an error at a reading of the time (the second reviewer, CX-27)."""
    try:
        return float(value)
    except OverflowError:
        return None


def _base_of(stored: dict[str, Any]) -> Base | None:
    """The base a stored row of the right shape names, or None when a number in it is too large for a float."""
    time, elapsed = _finite(stored["time"]), _finite(stored["elapsed"])
    return None if time is None or elapsed is None else Base(time, elapsed, stored["boot"])


class ClockWatch:
    """The one time base: every decision about time goes by `now` (reviews 4 to 7: N4-M8, N5-L5, N6-M1, N6-M3,
    and review 7's M1 and M2).

    The wall clock can be stepped, by a wrong or hostile time source, and every round of reviews found one more
    place where a step did lasting damage. The host's own clock cannot be stepped: it counts the time that
    really passed, sleep included, from the start of each boot. So the watch keeps one base per boot, a
    wall-clock reading it trusted and the host clock at that moment, and the time is the base moved on by the
    host clock. The wall clock is read only to be compared with it: a reading more than CLOCK_TOLERANCE off is
    logged, every minute while it lasts. On one boot the time therefore moves exactly as far as the host clock
    does, whatever the wall clock reads: a clock stepped a little at every reading moves it no more than one
    stepped once, or not at all (review 7, M2). It never goes back, and every worker reads the same.

    Workers on several hosts may share one store (PostgreSQL): each boot keeps its own base, under its boot
    identifier, so one host's base is never taken for another's restart (the second reviewer), and the hosts' times
    differ by no more than their clocks did when each laid its base. Workers on one host, and containers on one
    kernel, share a boot and go by one base.

    The base is laid once per boot, never moved afterwards except by a forced run, whose caller vouches for the
    clock: on the first start of a store; after a host restart, at once when the reading is not behind the
    last base and the kernel reports its clock synchronised by NTP, otherwise once the reading has kept pace
    with the host clock for a whole interval and the kernel does not say it is unsynchronised. Until then the
    watch cannot vouch for the time and `now` is None. The base is kept in the store, so every worker on the
    boot, and a worker started again, goes by the same one.

    Pruning, which cannot be undone, waits for more (`settled`): an interval since the base was laid, and a wall
    clock that does not read behind the time. A reading behind it may mean the base was laid from a clock that
    read ahead and was put right since, so the time may be ahead too; a reading ahead of it can only make the
    time behind, which prunes less.

    A clock passed in for tests has no host clock behind it: the wall clock is then the time, as it reads.
    """

    def __init__(
        self,
        store: Store,
        clock: Callable[[], float],
        interval: int,
        *,
        host: HostClock | None = None,
        keyring: Keyring | None = None,
        floor: Callable[[str | None], tuple[str, float, float] | None] | None = None,
    ) -> None:
        if host is not None and keyring is None:
            raise ConfigError("a clock watch with a host clock needs the keyring to MAC the base it keeps")
        self._store = store
        self._keyring = keyring
        self._clock = clock
        self._host = host
        self._settle = interval
        self._lock = threading.Lock()
        # The base row last read from the store and the base it verified to, replaced whole: `now` reads the
        # row at every call and checks its MAC only when the row changed.
        self._kept: tuple[Any, Base | None] = (None, None)
        self._new: tuple[float, float] | None = None  # a reading on a new boot, waiting: wall and host clock
        self._behind = False  # the last reading `steady` took was behind the time
        # The boot, host-clock reading and time of the newest base this worker knows was laid, from the bases it
        # went by and from the anchor (`floor`), where a forced run leaves one: a base laid before it on the same
        # boot is a copy put back, and is gone by no more (the second reviewer, CX-17).
        self._anchored = floor
        self._floor: tuple[str, float, float] | None = None
        self._refused: Any = None  # the last row refused as a copy, logged once

    def _boot(self) -> str | None:
        assert self._host is not None
        return self._host.boot()

    def _stored(self) -> Any:
        """This boot's base row: under its boot identifier, or the single row a store kept before bases were kept
        per boot, when that one is this boot's (`_expected` goes by no other boot's base)."""
        boot = self._boot()
        stored = None if boot is None else self._store.peek("maintenance", f"clock:{boot}")
        return self._store.peek("maintenance", "clock") if stored is None else stored

    def _raise_floor(self, seen: tuple[str, float, float] | None = None) -> None:
        """Raise the floor to `seen`, or to what the anchor names when `seen` is None; only this boot counts."""
        if seen is None and self._anchored is not None:
            seen = self._anchored(self._boot())
        floor = self._floor
        if seen is None or seen[0] != self._boot():
            return
        if floor is None or floor[0] != seen[0] or seen[1] > floor[1]:
            self._floor = seen

    def _before(self, base: Base) -> bool:
        """Whether `base` was laid before the floor on its boot, at an earlier host-clock reading. Two bases of one
        boot are never laid at the same reading: the host clock counts in nanoseconds, and time passes between."""
        floor = self._floor
        return floor is not None and floor[0] == base.boot and base.elapsed < floor[1]

    def _tag(self, purpose: str, *values: float | str) -> str:
        assert self._keyring is not None  # every watch with a host clock has one
        return self._keyring.mac(purpose, ":".join(repr(v) for v in values))

    def _load(self) -> Base | None:
        """The base kept in the store, for this boot or another; None when there is none, or when its MAC does
        not verify. Every expiry goes by the base, so whoever can write the database alone must not be able to
        move it: an offer or token past its time would be good again (the second reviewer). A base that does not
        verify is taken for none, as after a host restart, with an alert."""
        stored = self._stored()
        base = self._adopt(stored)
        if stored is not None and base is None:
            security_log.error("the clock base in the store does not verify; the watch lays a new one")
        return base

    def _adopt(self, stored: Any) -> Base | None:
        """The base a row read from the store verifies to, None when it does not; the MAC is checked again only
        when the row is not the one read last. A base laid before one this worker knows of on the same boot (see
        `_floor`) is refused whether it was read before or not, by what the anchor names at this very reading
        (the second reviewer, CX-18): a worker that has not ticked since another forced a base is no exception."""
        self._raise_floor()
        kept = self._kept
        if stored == kept[0]:
            base = kept[1]
        else:
            base = self._verified(stored)
            self._kept = (stored, base)
        if base is not None and self._before(base):
            if stored != self._refused:
                self._refused = stored
                security_log.error(
                    "the clock base in the store was laid before one this worker knows of on the same boot: a "
                    "copy put back into the database; it is not gone by"
                )
            return None
        if base is not None:
            self._raise_floor((base.boot, base.elapsed, base.time))
        return base

    def _verified(self, stored: Any) -> Base | None:
        """The base a row verifies to under its MAC, or None; nothing else is kept or raised by it."""
        if (
            isinstance(stored, dict)
            and all(isinstance(stored.get(k), int | float) for k in ("time", "elapsed"))
            and isinstance(stored.get("boot"), str)
            and isinstance(stored.get("tag"), str)
        ):
            candidate = _base_of(stored)
            if candidate is not None and same(
                self._tag("clock-base", candidate.time, candidate.elapsed, candidate.boot), stored["tag"]
            ):
                return candidate
        return None

    def _latest(self) -> Base | None:
        """The newest base that verifies among every boot's, and the single row of a store from before bases per
        boot: what a new boot compares its first reading with."""
        rows = [row for _, row in self._store.items("maintenance", "clock:", at=-math.inf)]
        bases = [b for b in map(self._verified, [*rows, self._store.peek("maintenance", "clock")]) if b is not None]
        return max(bases, key=lambda b: b.time, default=None)

    def _current(self) -> Base | None:
        """The base in the store now. Every worker reads it at every call, inside the store transaction when
        there is one: a base laid again by a forced run in one worker is the base of every other at once, so
        none stamps or reads an expiry by the time it had before (the second reviewer, CX-13). The read does
        not go by the clock, since the store's expiries go by this one."""
        assert self._host is not None
        return self._adopt(self._stored())

    def _seen(self) -> float | None:
        """The latest time seen, kept in the store under its MAC; None when there is none or it does not verify."""
        stored = self._store.get("maintenance", "seen")
        if (
            isinstance(stored, dict)
            and isinstance(stored.get("time"), int | float)
            and isinstance(stored.get("tag"), str)
        ):
            seen = _finite(stored["time"])
            if seen is not None and same(self._tag("clock-seen", seen), stored["tag"]):
                return seen
        return None

    def _lay(self, now: float, elapsed: float) -> Base | None:
        """Trust `now`, read together with the host clock's `elapsed`, from here on, on this boot. A pair read
        apart would leave the base behind or ahead by whatever ran between them, for the whole boot."""
        assert self._host is not None
        boot = self._boot()
        if boot is None:
            return None
        base = Base(float(now), float(elapsed), boot)
        # When the transaction this base is laid in rolls back, what the watch keeps in memory goes back with the
        # store, before the store's lock is released: a worker that raised its floor to a base the store undid
        # would refuse the base the store went back to (the second reviewer, CX-20 and CX-30).
        saved = (self._kept, self._floor, self._new, self._behind)
        self._store.on_rollback(lambda: self._put_back(saved))
        tag = self._tag("clock-base", base.time, base.elapsed, base.boot)
        row = {"time": base.time, "elapsed": base.elapsed, "boot": base.boot, "tag": tag}
        self._store.put("maintenance", f"clock:{base.boot}", row, None)
        self._store.delete("maintenance", "clock")  # the single row of a store from before bases per boot
        self._store.put("maintenance", "seen", {"time": base.time, "tag": self._tag("clock-seen", base.time)}, None)
        self._kept, self._new, self._behind = (row, base), None, False
        self._floor = (base.boot, base.elapsed, base.time)  # the newest base, whatever the floor said before
        return base

    def _put_back(self, saved: tuple[tuple[Any, Base | None], tuple[str, float, float] | None, Any, bool]) -> None:
        self._kept, self._floor, self._new, self._behind = saved

    def _expected(self, base: Base | None, elapsed: float | None = None) -> float | None:
        """Where the base and the host clock put the time at `elapsed` (now when None), or None on another boot
        or without a base."""
        if base is None or base.boot != self._boot():
            return None
        assert self._host is not None  # a base is only laid with a host clock
        return base.time + (self._host.elapsed() if elapsed is None else elapsed) - base.elapsed

    def now(self) -> float | None:
        """The time every decision goes by: the base moved on by the host clock; the wall clock as it reads
        without a host clock (a test clock); None when there is a host clock but no base for this boot yet. It
        never goes back on one boot, and every worker on the boot reads the same, the base in the store (see
        `_current`). It does not take the lock: the store reads its expiries by it from inside its transactions,
        while `steady` writes the store holding the lock."""
        if self._host is None:
            return self._clock()
        return self._expected(self._current())

    def trust(self, now: float) -> Base | None:
        """Take `now` as right: a forced run, whose caller vouches for the clock. Pruning waits an interval again.
        The base laid is returned, for the caller to log; the store comes before the lock, as in `steady`, so a
        caller may run this inside an audit transaction."""
        if self._host is None:
            return None
        elapsed = self._host.elapsed()
        with self._store.atomic(), self._lock:
            return self._lay(now, elapsed)

    def settled(self) -> bool:
        """Whether pruning may go by the time: an interval since the base was laid, and a wall clock that did
        not read behind the time at the last reading (review 6, N6-M3; review 7, M2). The base is kept in the
        store, so a restart does not cut the wait short."""
        if self._host is None:
            return True
        base = self._current()
        expected = self._expected(base)
        return base is not None and expected is not None and not self._behind and expected - base.time >= self._settle

    def steady(self) -> bool:
        """Read the clock, as the background tick does about once a minute: lay a base when this boot has none
        yet, log a reading far from the time, and say whether the watch can vouch for the time now."""
        if self._host is None:
            return True
        # One pair, read before waiting for anything; and one store transaction, so that workers starting
        # together on a new boot lay one base between them and none replaces a base another already goes by.
        # The store comes before the lock, as in `trust`, which may run inside an audit transaction.
        reading, elapsed = self._clock(), self._host.elapsed()
        with self._store.atomic(), self._lock:
            # Whether any boot, on any host, laid a base: only a store that never had one is on its first start.
            had = bool(self._store.items("maintenance", "clock:", at=-math.inf)) or (
                self._store.peek("maintenance", "clock") is not None
            )
            base = self._load()
            expected = self._expected(base, elapsed)
            if expected is not None:
                # The latest time seen, for a host restart to be compared with: the base alone may be long ago.
                # Only ever raised: another host whose clock runs a little behind must not take it back.
                latest = max(expected, self._seen() or expected)
                self._store.put("maintenance", "seen", {"time": latest, "tag": self._tag("clock-seen", latest)}, None)
                self._behind = reading < expected - CLOCK_TOLERANCE
                if abs(reading - expected) > CLOCK_TOLERANCE:
                    security_log.error(
                        "the wall clock reads %d s off the time the host clock gives since the watch trusted it; "
                        "cunho goes by the host clock%s",
                        int(reading - expected),
                        ", and audit pruning waits" if self._behind else "",
                    )
                return True
            if self._boot() is None:
                security_log.error("the host's boot cannot be named; the clock watch cannot vouch for the time")
                return False
            if not had:
                self._lay(reading, elapsed)  # the first start of a store: nothing to go by but the clock
                return True
            synced = self._host.synced()
            # The latest time seen must verify: one deleted or written into the database would take the time
            # back to the base, which may be long ago, and a clock set back since would be trusted at once.
            seen = self._seen()
            # The newest base any boot laid, on this host or another: this boot's own is not there yet.
            last = self._latest()
            if last is not None and seen is not None and reading >= max(seen, last.time) and synced is True:
                security_log.warning(
                    "the host restarted since the watch last trusted the clock, and the kernel reports its clock "
                    "synchronised; audit pruning waits until it has read steadily for an interval"
                )
                self._lay(reading, elapsed)
                return True
            new = self._new
            if new is None or abs((reading - new[0]) - (elapsed - new[1])) > CLOCK_TOLERANCE:
                self._new = (reading, elapsed)
                security_log.error(
                    "the host restarted since the watch last trusted the clock; pruning, sweeping, decoys and "
                    "status publication wait until the clock has kept pace with the host clock for an interval"
                )
                return False
            if elapsed - new[1] < self._settle:
                return False
            if synced is False:
                security_log.error(
                    "the wall clock keeps pace with the host clock, but the kernel says it is not synchronised"
                )
                return False
            security_log.warning("the wall clock kept pace with the host clock for an interval; trusting it")
            self._lay(reading, elapsed)
            return True


def load_test_persons(path: Path | None) -> dict[str, dict[str, Any]]:
    """The fixture persons of the built-in test login: a JSON object from a person id to its subject data."""
    if path is None:
        return {}
    try:
        persons = strict_json(path.read_bytes())
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise ConfigError(f"cannot read the test login persons in {path}: {exc}") from exc
    if not isinstance(persons, dict) or not persons or not all(isinstance(v, dict) for v in persons.values()):
        raise ConfigError("the test login persons file must be a non-empty JSON object of objects")
    return persons


def default_keyring(settings: Settings) -> Keyring:
    """Keys outside the store: the configured file, a file next to a development database, or memory."""
    if settings.secret_key_file is not None:
        return Keyring.from_file(settings.secret_key_file, create=not settings.production)
    if settings.store_path is not None:
        return Keyring.from_file(Path(f"{settings.store_path}.keys"), create=True)
    return Keyring.ephemeral()


MDOC_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")  # id-mdl-kp-mdlDS


def status_list_anchor(signer: Signer, sources: Sequence[Path | None]) -> bytes:
    """The certificate whose key signed the top certificate of the status list's x5chain, which an mdoc names in
    its status_list as the relying party's trust anchor for the list (CIR 2024/2979 Annex II EAA-6.2.10.1-06.1,
    -13.1): the root itself when the chain ends self-signed, otherwise its issuer among the PEM files given (the
    signing trust anchors, and the status signer's chain file, which may hold the root x5c leaves out)."""
    top = x509.load_der_x509_certificate(base64.b64decode(signer.x5c()[-1]))
    candidates = [top] + [c for path in sources if path for c in x509.load_pem_x509_certificates(path.read_bytes())]
    for candidate in candidates:
        if candidate.subject != top.issuer:
            continue
        try:
            top.verify_directly_issued_by(candidate)
        except (ValueError, TypeError, InvalidSignature):
            continue
        return candidate.public_bytes(serialization.Encoding.DER)
    raise ConfigError(
        "an mdoc names the issuer of its status list's signing chain: the status list chain must end self-signed, "
        "or signing_trust_anchors must hold the certificate that issued its top certificate"
    )


def check_document_signer(signer: Signer) -> None:
    """A verifier of an mdoc takes only a document signer certificate with the purpose id-mdl-kp-mdlDS (ISO/IEC
    18013-5 Annex B), and an mdoc carries its signer's certificate in x5chain."""
    leaf = x509.load_der_x509_certificate(signer.certificate_der())
    try:
        purposes = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ConfigError("the mdoc document signer certificate has no extended key usage id-mdl-kp-mdlDS") from exc
    if MDOC_DS not in purposes:
        raise ConfigError("the mdoc document signer certificate's extended key usage lacks id-mdl-kp-mdlDS")
    if signer.alg not in cose.ALGORITHMS:
        raise ConfigError(f"the mdoc document signer's algorithm {signer.alg} has no COSE value")


@implements("FMT.SDJWT.X5C_NO_ANCHOR")
def check_signer_identity(signer: Signer, issuer_url: str) -> None:
    """SD-JWT VC draft-23 §3.5: a verifier matches `iss` against the signer certificate's SAN."""
    leaf = x509.load_der_x509_certificate(signer.certificate_der())
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ConfigError("the credential signing certificate has no subjectAltName for the issuer") from exc
    host = (urlsplit(issuer_url).hostname or "").lower()
    uris = names.get_values_for_type(x509.UniformResourceIdentifier)
    dns = [name.lower() for name in names.get_values_for_type(x509.DNSName)]
    if issuer_url not in uris and host not in dns:
        raise ConfigError(f"the credential signing certificate's subjectAltName does not name {issuer_url}")


class Issuer:
    def __init__(
        self,
        settings: Settings,
        *,
        store: Store | None = None,
        signers: Signers | None = None,
        keyring: Keyring | None = None,
        clock: Callable[[], float] = time.time,
        fetcher: Fetcher | None = None,
    ) -> None:
        self.settings = settings
        self.clock = clock  # the wall clock: only the clock watch reads it for what it says (see `time`)
        self.store = store if store is not None else default_store(settings, self.time)
        self.store.go_by(self.time)
        self.keyring = keyring or default_keyring(settings)
        self.signers = signers or default_signers(settings)
        check_signer_identity(self.signers.credentials, settings.issuer_url)
        if self.signers.access is not None:
            check_access_signer(self.signers.access, self.signers.credentials, self.signers.status)
        elif settings.production:
            raise ConfigError(
                "production needs an access certificate signer: the issuer metadata is signed with it (ARF ISSU_22, "
                "ETSI TS 119 472-3 §4.2.1)"
            )
        else:
            log.warning("no access certificate signer: the issuer metadata is served as JSON only. Development only.")
        if self.signers.mdoc is not None:
            check_document_signer(self.signers.mdoc)
        self.configs = metadata.load(
            settings, self.signers.credentials.alg, self.signers.mdoc.alg if self.signers.mdoc else None
        )
        self._check_annex_b()
        self._check_provider_names()
        self.request_keys = RequestKeys.load(settings.encryption_keys, settings.encryption_required)
        untyped = sorted(
            metadata.missing_type_metadata(self.configs.all, self.configs.published, self.configs.integrity)
        )
        if untyped:
            log.warning(
                "no SD-JWT VC Type Metadata for %s: their credentials carry no vct#integrity (ETSI TS 119 472-1 "
                "EAA-5.2.1.2-03). Development only; production refuses to start without it.",
                untyped,
            )
        self.issuer_info = _issuer_info(settings)
        self._signed_metadata: tuple[int, str, int] | None = None  # (minute, token, its exp)
        self._as_metadata_hooks: list[metadata.AsMetadataHook] = []
        try:
            self.audit = AuditLog(
                self.store,
                self.keyring,
                clock,
                retention=settings.audit_retention_days * DAY,
                anchor=default_anchor(settings, self.store, self.keyring),
                # Production starts a new anchor only when told to, on a new deployment (review 3, N3-M2).
                create_anchor=settings.audit_anchor_init or not settings.production,
            )
        except AuditError as exc:
            raise ConfigError(str(exc)) from exc
        self.audit_signer = KeyringSigner(self.keyring.derive("audit-head-signing"))
        self.auth_failures = AuthFailures()
        self.vault = Vault(self.store, self.keyring)
        self.status = StatusLists(settings, self.store, self.signers.status, clock)
        self.status_anchor = (
            status_list_anchor(
                self.signers.status,
                [settings.signing_trust_anchors, settings.status_signing_chain or settings.signing_chain],
            )
            if self.signers.mdoc
            else None
        )
        self.nonces = Nonces(settings, self.store, self.keyring, self.time)
        self.dpop = Dpop(settings, self.store, self.nonces, self.time)
        self.offers = Offers(settings, self.store, self.keyring, self.time)
        self.tokens = Tokens(
            settings,
            self.store,
            self.dpop,
            self.nonces,
            self.keyring,
            self.time,
            self._offer_used_up,
            self._token_minted,
        )
        # `fetcher` is for tests, which serve from 127.0.0.1; a deployment fetches only from its fetch_hosts.
        self.fetcher = fetcher or Fetcher(settings.fetch_hosts)
        self.trust = Trust.from_settings(settings, self.store, self.time, self.fetcher)
        if self.trust.revocation() is None:
            log.warning(
                "neither the list of wallet providers nor CUNHO_WALLET_PROVIDER_CRLS is set: revoked wallet provider "
                "certificates are not refused. Development only; production refuses to start without the list."
            )
        self.wallet_status: WalletStatus | None = None
        if self.trust.checks_status():
            self.wallet_status = WalletStatus(self.fetcher, self.trust, self.time, self.store)
        else:
            log.warning(
                "no anchors for wallet providers' status lists: revoked wallet and key attestations are not refused. "
                "Development only; production refuses to start without the list."
            )
        self.proofs = ProofVerifier(settings, self.nonces, self.trust, self.time, self.wallet_status)
        # Wallet attestations chain to the same wallet providers' anchors and revocation as key attestations do.
        self.client_auth = ClientAuth(settings, self.store, self.trust, self.time, self.wallet_status)
        self.authorization = Authorization(
            settings,
            self.store,
            self.keyring,
            self.configs,
            self.client_auth,
            self.dpop,
            self.tokens,
            self.time,
            self._code_reused,
            self._hold_for_refresh,
        )
        self.test_persons = load_test_persons(settings.test_login_persons)
        self.authorization.test_login = bool(self.test_persons)
        if not settings.login_url and not self.test_persons:
            log.warning("no login service is configured: the authorization code flow refuses every authorization")
        # A clock passed in (tests, simulations) has no host clock behind it: the watch then goes by the wall
        # clock alone, as it does on a host whose boot cannot be named, since a restart cannot be told apart
        # from a stop there.
        host = HostClock() if clock is time.time else None
        if host is not None and host.boot() is None:
            if settings.production:
                raise ConfigError("the host's boot cannot be named, so the clock watch has no time to go by")
            log.error("the host's boot cannot be named: the clock watch goes by the wall clock alone")
            host = None
        self.use_clock_watch(
            ClockWatch(
                self.store,
                clock,
                settings.maintenance_interval,
                host=host,
                keyring=self.keyring,
                floor=self.audit.clock_floor,
            )
        )
        # The version comes before the watch's first reading, which writes the store: a new store must still look
        # empty to the upgrade, or production would take it for one written before the version (second reviewer).
        if self.store.get("meta", "schema") != schema.SCHEMA:
            # The upgrade and its log entry stand or fall together, so a store whose version row was removed by
            # hand is not upgraded again unseen (review 7, L3). A store at the version starts without the log:
            # one whose log fails its checks starts, refuses to log, and says why when verified.
            try:
                with self.audit.transaction():
                    if schema.upgrade(self.store, settings, clock, self._handed_out, list(self.configs.issuable())):
                        self.audit.append("store.upgraded", "cunho", schema=schema.SCHEMA)
                        log.warning("the store carried no schema version; it is upgraded to %d", schema.SCHEMA)
            except AuditError as exc:
                raise ConfigError(str(exc)) from exc
        self.trust.start()  # after the version, since reading the list records its sequence number in the store
        self.clock_watch.steady()  # the first reading: a worker goes by the time from its first request
        self._last_maintenance = 0.0
        self._wal_dirty = False
        self.extend_as_metadata(self.authorization.metadata)

    def use_clock_watch(self, watch: ClockWatch) -> None:
        """Every decision about time goes by this watch (see `time`)."""
        self.clock_watch = watch
        self.audit.now = watch.now
        self.status.now = watch.now

    def time(self) -> float:
        """The one time cunho goes by (review 7, M1 and M2): the clock watch's, which is the base it trusted moved
        on by the host clock, or the wall clock while the watch cannot vouch for it. The store's expiries, the
        lifetimes of offers, tokens, nonces and proofs, a credential's validity, the moments of revocations, the
        publication of status lists, the audit entry times, sweeping and pruning all read it, so a wall clock
        that is stepped moves none of them, and none moves apart from the others."""
        watch: ClockWatch | None = getattr(self, "clock_watch", None)  # None while the issuer is being built
        now = watch.now() if watch is not None else None
        return self.clock() if now is None else now

    # metadata ------------------------------------------------------------------------------

    def issuer_metadata(self) -> dict[str, Any]:
        return metadata.issuer_metadata(self.settings, self.configs, self.issuer_info, self.request_keys)

    def signed_issuer_metadata(self) -> str | None:
        """The issuer metadata as a signed JWT, or None without an access signer. Signed again each minute of issuer
        time, so a run of requests costs one signature, and `iat` is never more than a minute old."""
        if self.signers.access is None:
            return None
        now = int(self.time())
        held = self._signed_metadata
        # Within the minute, and before the token's own exp: a lifetime under a minute ends it sooner (the second
        # reviewer).
        if held is not None and held[0] == now // 60 and now < held[2]:
            return held[1]
        ttl = self.settings.signed_metadata_ttl
        token = signed_metadata(self.issuer_metadata(), self.signers.access, now, ttl)
        self._signed_metadata = (now // 60, token, now + ttl)
        return token

    def as_metadata(self) -> dict[str, Any]:
        return metadata.authorization_server_metadata(self.settings, self._as_metadata_hooks)

    def extend_as_metadata(self, hook: metadata.AsMetadataHook) -> None:
        """Add fields to the authorization server metadata. The document is built at once, so a hook that clashes
        with another, or sets the issuer identifier, stops cunho from starting rather than failing a request."""
        hooks = [*self._as_metadata_hooks, hook]
        metadata.authorization_server_metadata(self.settings, hooks)
        self._as_metadata_hooks = hooks

    # operator side ---------------------------------------------------------------------------

    def _today(self) -> dt.date:
        return dt.datetime.fromtimestamp(self.time(), dt.UTC).date()

    def operator(self, authorization: str | None) -> str | None:
        """The name of the operator whose token this is, or None."""
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer":
            return None  # an empty token matches no operator below
        for name, expected in {"admin": self.settings.admin_token, **self.settings.operators}.items():
            if same(token.strip(), expected):
                return name
        return None

    def admin_refused(self, route: str, client: str, had_token: bool) -> None:
        """A failed operator login: one operational log line and a count, never an audit entry of its own."""
        name = route if route in ADMIN_ROUTES else "other"
        security_log.warning("admin authentication failed: route=%s client=%s token_sent=%s", name, client, had_token)
        self.auth_failures.record(name, had_token, self.time())

    @implements("ISS.SUBJECT.ENTITLEMENT")
    def create_offer(self, body: Any, operator: str) -> dict[str, Any]:
        """The operator decides who is entitled to which credential; cunho checks the data against the rulebook."""
        enforce(isinstance(body, dict), "ISS.SUBJECT.ENTITLEMENT", "invalid_request", "body must be a JSON object")
        ids = body.get("credential_configuration_ids")
        enforce(
            isinstance(ids, list) and bool(ids) and all(isinstance(i, str) for i in ids) and len(set(ids)) == len(ids),
            "VCI.OFFER.SHAPE",
            "invalid_request",
            "credential_configuration_ids must be a non-empty array of distinct strings",
        )
        for config_id in ids:
            enforce(
                self.configs.get(config_id) is not None,
                "VCI.OFFER.SHAPE",
                "invalid_request",
                f"{config_id} is not a configuration this deployment issues",
            )
        published = {
            self.configs.all[c].get("format") for c in self.configs.published if metadata.is_pid(self.configs.all[c])
        }
        offered = {self.configs.all[c].get("format") for c in ids if metadata.is_pid(self.configs.all[c])}
        enforce(
            not offered or offered == published,
            "VCI.FORMATS.ALL_RULEBOOK",
            "invalid_request",
            "a PID is offered in both formats this deployment publishes, SD-JWT VC and mdoc (ARF PID_02)",
        )
        grant = body.get("grant", "pre-authorized_code")
        enforce(
            grant in ("pre-authorized_code", CODE_GRANT),
            "VCI.OFFER.SHAPE",
            "invalid_request",
            "grant must be pre-authorized_code or authorization_code",
        )
        if grant == CODE_GRANT:
            return self._code_offer(body, list(ids), operator)
        subject = body.get("subject")
        for config_id in ids:
            self._own_subject(self.configs.all[config_id], subject)
            try:
                check_subject(self.configs.all[config_id], subject, self._today())
            except ClaimsError as exc:
                refuse("EAA.RULEBOOK.CONFORMANCE", "invalid_request", "; ".join(exc.problems))
        length = body.get("tx_code_length")
        enforce(
            length is None or (isinstance(length, int) and 4 <= length <= 10),  # True is 1, below the range
            "VCI.OFFER.SHAPE",
            "invalid_request",
            "tx_code_length must be an integer from 4 to 10",
        )
        person = body.get("person")
        enforce(
            person is None or (isinstance(person, str) and bool(PERSON_HANDLE.fullmatch(person))),
            "VCI.OFFER.SHAPE",
            "invalid_request",
            "person must be 1 to 200 printable ASCII characters without spaces",
        )
        enforce(
            body.get("review", False) is False,
            "VCI.OFFER.SHAPE",
            "invalid_request",
            "review is for the authorization code flow: give it with the login result, whose refresh token lets "
            "the wallet collect a held credential later",
        )
        subject_ref = self.new_subject_ref()
        offer_id = b64u(secrets.token_bytes(18))
        settings = self.settings
        window = settings.offer_ttl + settings.access_token_ttl
        with self._logged():
            # Logged first and in one transaction with the writes: no offer exists without its entry. The keyed
            # grant reference ties this entry to the issuance it leads to (review 3, N3-M5). The person handle
            # is never logged.
            self.audit.append(
                "offer.created",
                operator,
                subject_ref=subject_ref,
                grant=self._grant_ref(offer_id),
                configuration_ids=ids,
                tx_code=length is not None,
            )
            self.vault.put(subject_ref, subject, window, offer_id)
            # What the offer can still yield, apart from the vault, which issuance erases early (review 5, N5-M2).
            self.store.put("subject-open", subject_ref, list(ids), window)
            # For GET /admin/offers/{subject_ref}: what the offer was for, as long as anything about it is kept,
            # and until when a token can be got from it.
            self.store.put("subject-configs", subject_ref, list(ids), self._subject_window())
            self.store.put("subject-offer", subject_ref, int(self.time()) + settings.offer_ttl, settings.offer_ttl)
            if person is not None:
                self._link_person(subject_ref, str(person))
            offer = self.offers.create(list(ids), subject_ref, length, offer_id)
        return {**offer, "subject_ref": subject_ref}

    def _code_offer(self, body: dict[str, Any], ids: list[str], operator: str) -> dict[str, Any]:
        """An issuer-initiated offer for the authorization code flow: who the person is comes from the login, so
        the offer carries no subject data and no tx_code (OpenID4VCI §4.1.1)."""
        for name in ("subject", "tx_code_length", "person", "review"):
            enforce(
                body.get(name) is None,
                "VCI.OFFER.AUTH_CODE_GRANT",
                "invalid_request",
                f"an authorization_code offer takes no {name}: the login says who the person is",
            )
        with self._logged():
            self.audit.append("offer.created", operator, grant=CODE_GRANT, configuration_ids=ids)
            offer = self.authorization.code_offer(ids)
        return offer

    @implements("ISS.SUBJECT.ENTITLEMENT", "ISS.IDPROOF.PLUG_REQUIRED")
    def complete_login(self, login_state: str, body: Any, operator: str) -> dict[str, Any]:
        """The operator's login service reports the result of a login (`POST /admin/logins/{login_state}`).

        A successful login is an offer created at that moment, as `create_offer` makes one: a new subject
        reference, the subject data in the vault, its log entry, all in one transaction, so revocation, erasure
        and the closed mark work on it unchanged. A PID needs a login at assurance level high (CIR 2024/2977
        Art. 3(7), ARF ISSU_18), which the login service states in `loa`. `{"denied": true}` reports a user who
        cancelled or failed, and the wallet gets access_denied. Either way the answer carries `continue`, the URL to
        send the person's browser to: it holds a completion secret only this answer gives out, so the wallet that
        started the login, which knows login_state, cannot collect the code itself."""
        enforce(isinstance(body, dict), "ISS.SUBJECT.ENTITLEMENT", "invalid_request", "body must be a JSON object")
        assert isinstance(body, dict)
        pending = self.authorization.pending_login(login_state)
        enforce(
            pending is not None,
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "login_state is unknown, expired or already reported",
            404,
        )
        assert pending is not None
        if body.get("denied") is True:
            enforce(
                set(body) == {"denied"},
                "ISS.SUBJECT.ENTITLEMENT",
                "invalid_request",
                "a denied login carries nothing but denied",
            )
            with self.store.atomic():
                resume = self.authorization.finish_login(login_state, {"denied": True})
                enforce(resume is not None, "ISS.SUBJECT.ENTITLEMENT", "invalid_request", LOGIN_GONE, 404)
            return {"denied": True, "continue": resume}
        ids = list(pending["configuration_ids"])
        if any(metadata.is_pid(self.configs.all[c]) for c in ids):
            enforce(
                body.get("loa") == "high",
                "ISS.IDPROOF.PLUG_REQUIRED",
                "invalid_request",
                "a PID needs a login at assurance level high: send loa=high",
            )
        subject = body.get("subject")
        for config_id in ids:
            self._own_subject(self.configs.all[config_id], subject)
            try:
                check_subject(self.configs.all[config_id], subject, self._today())
            except ClaimsError as exc:
                refuse("EAA.RULEBOOK.CONFORMANCE", "invalid_request", "; ".join(exc.problems))
        assert isinstance(subject, dict)  # check_subject refuses anything else
        person = body.get("person")
        enforce(
            person is None or (isinstance(person, str) and bool(PERSON_HANDLE.fullmatch(person))),
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "person must be 1 to 200 printable ASCII characters without spaces",
        )
        review = self._review(body, "ISS.SUBJECT.ENTITLEMENT")
        subject_ref = self.new_subject_ref()
        offer_id = b64u(secrets.token_bytes(18))
        settings = self.settings
        window = settings.login_ttl + settings.code_ttl + settings.access_token_ttl
        with self._logged():
            outcome = {"subject_ref": subject_ref, "offer_id": offer_id, **({"review": True} if review else {})}
            resume = self.authorization.finish_login(login_state, outcome)
            enforce(resume is not None, "ISS.SUBJECT.ENTITLEMENT", "invalid_request", LOGIN_GONE, 404)
            self.audit.append(
                "offer.created",
                operator,
                subject_ref=subject_ref,
                grant=self._grant_ref(offer_id),
                configuration_ids=ids,
                flow=CODE_GRANT,
                **({"review": True} if review else {}),
            )
            self.vault.put(subject_ref, subject, window, offer_id)
            self.store.put("subject-open", subject_ref, ids, window)
            # The browser has the login's life to come back; the code it then gets moves this (Authorization.resume).
            self.store.put("subject-configs", subject_ref, ids, self._subject_window())
            self.store.put("subject-offer", subject_ref, int(self.time()) + settings.login_ttl, settings.login_ttl)
            if person is not None:
                self._link_person(subject_ref, str(person), window)
        return {"subject_ref": subject_ref, "continue": resume}

    @staticmethod
    def _review(body: dict[str, Any], rule: str) -> bool:
        """Whether the operator holds this subject's credentials for review: the credential endpoint then answers
        with a transaction_id, and the operator releases or refuses each issuance (OpenID4VCI 1.0 §9)."""
        review = body.get("review", False)
        enforce(isinstance(review, bool), rule, "invalid_request", "review must be true or false")
        return bool(review)

    def new_subject_ref(self) -> str:
        """A fresh pseudonymous reference that carries a keyed tag, so cunho can tell one it handed out from any
        other string of the same shape without keeping a row for every reference forever (review 5, N5-L6)."""
        random = secrets.token_bytes(10)
        return "sub_" + b64u(random + bytes.fromhex(self.keyring.mac("subject-ref", random))[:8])

    def _handed_out(self, subject_ref: Any) -> bool:
        """A reference with cunho's keyed tag, or one the schema upgrade found in use from before the tag."""
        if not isinstance(subject_ref, str) or not SUBJECT_REF.fullmatch(subject_ref):
            return False
        raw = b64u_decode(subject_ref[4:])
        if len(raw) == 18 and same(raw[10:], bytes.fromhex(self.keyring.mac("subject-ref", raw[:10]))[:8]):
            return True
        return self.store.get("subject-legacy", subject_ref) is not None

    def _person_ref(self, person: str) -> str:
        """The keyed reference of an operator's person handle. Only this is stored, and never in the log."""
        return self.keyring.mac("person", person)[:32]

    def _link_person(self, subject_ref: str, person: str, window: int | None = None) -> None:
        """Remember which person an offer was for, for as long as a credential from it can be valid. `window` is
        how long the offer or login can still lead to an issuance: an offer's own lifetime and its token's by
        default."""
        settings = self.settings
        window = settings.offer_ttl + settings.access_token_ttl if window is None else window
        ttl = window + settings.credential_validity_days * DAY
        ttl += settings.timestamp_granularity
        self._link_person_ref(subject_ref, self._person_ref(person), ttl)

    def _link_person_ref(self, subject_ref: str, reference: str, ttl: float) -> None:
        self.store.put("person", f"{reference}:{subject_ref}", 1, ttl)
        self.store.put("person-of", subject_ref, reference, ttl)

    @implements("STATUS.MONOTONIC")
    def revoke(self, body: Any, operator: str) -> dict[str, Any]:
        """Revoke by status slot, or every live credential of a subject reference.

        Revoking a subject also closes its offer, when one is still live: neither the pre-authorized code nor
        an access token obtained with it yields another credential (review 4, N4-M5). The issued rows are read,
        and the subject closed, in the same transaction as the log entry, and issuance writes its issued rows
        in the transaction of its own entry, so a revocation that runs alongside an issuance either sees that
        issuance's credentials or stops it.
        """
        enforce(isinstance(body, dict), "STATUS.MONOTONIC", "invalid_request", "body must be a JSON object")
        reason = body.get("reason")
        enforce(
            isinstance(reason, str) and reason in REVOCATION_REASONS,
            "STATUS.MONOTONIC",
            "invalid_request",
            f"reason must be one of {sorted(REVOCATION_REASONS)}",
        )
        refs: list[StatusRef] = []
        subject_ref = body.get("subject_ref")
        person = body.get("person")
        index = body.get("index")
        list_id = body.get("list")
        if subject_ref is not None:
            enforce(
                self._handed_out(subject_ref),
                "STATUS.MONOTONIC",
                "invalid_request",
                "subject_ref is not a reference this issuer handed out",
            )
            with self._logged():
                return self._revoke_subjects([subject_ref], reason, operator)
        if person is not None:
            enforce(
                isinstance(person, str) and bool(PERSON_HANDLE.fullmatch(person)),
                "STATUS.MONOTONIC",
                "invalid_request",
                "person must be 1 to 200 printable ASCII characters without spaces",
            )
            prefix = f"{self._person_ref(str(person))}:"
            with self._logged():
                subjects = [key[len(prefix) :] for key, _ in self.store.items("person", prefix)]
                return self._revoke_subjects(subjects, reason, operator, person=True)
        if (
            isinstance(list_id, str)
            and list_id.isdecimal()
            and list_id.isascii()
            and len(list_id) <= 9
            and isinstance(index, int)
            and not isinstance(index, bool)
            and 0 <= index < (self.status.size_of(list_id) or 0)  # no such list: nothing to revoke
        ):
            refs = [StatusRef(list_id, index)]
        enforce(bool(refs), "STATUS.MONOTONIC", "invalid_request", "nothing to revoke for this reference")
        with self._logged():
            return {"revoked": self._revoke_slots(refs, reason, operator, None)}

    def _revoke_subjects(
        self, subject_refs: list[str], reason: str, operator: str, *, person: bool = False
    ) -> dict[str, Any]:
        """Inside an audit transaction: every issued credential of the subjects, and their offers.

        Every subject revoked is closed, whether or not its vault entry is still there: an issuance that read
        the data before the vault was erased could still be on its way (review 5, N5-M2). Its issuance checks
        the mark in the transaction of its own log entry, so it is refused. The subject data goes too: nothing
        more is issued from it (review 5, N5-L11). `offer_cancelled` says whether anything could still have
        been issued.
        """
        refs: list[StatusRef] = []
        live = []
        # Which credentials are still valid goes by the time, not by the wall clock as it reads, so a clock that
        # reads far ahead does not make a revocation miss them; without a time, every record still kept counts.
        now = self.clock_watch.now()
        at = -math.inf if now is None else now
        for subject_ref in subject_refs:
            issued = self.store.items("issued", f"{subject_ref}:", at=at)
            refs += [StatusRef(r["list"], int(r["idx"])) for _, r in issued]
            if self._offer_live(subject_ref):
                live.append(subject_ref)
        enforce(
            bool(refs) or bool(live),
            "STATUS.MONOTONIC",
            "invalid_request",
            "nothing to revoke for this person" if person else "nothing to revoke for this reference",
        )
        for subject_ref in subject_refs:
            self._close_subject(subject_ref)
            self.vault.erase(subject_ref)
            # Its credentials are revoked: nothing is left to chain, so their attestations' references go.
            for key, _ in self.store.items("chain", f"{subject_ref}:", at=0):
                self.store.delete("chain", key)
        if person:
            count = self._revoke_slots(refs, reason, operator, None, len(live), subject_refs)
            return {"revoked": count, "subjects": len(subject_refs), "offers_cancelled": len(live)}
        result: dict[str, Any] = {"revoked": self._revoke_slots(refs, reason, operator, subject_refs[0], len(live))}
        if live:
            result["offer_cancelled"] = True
        return result

    def _revoke_slots(
        self,
        refs: list[StatusRef],
        reason: str,
        operator: str,
        subject_ref: str | None,
        closed: int = 0,
        subject_refs: list[str] | None = None,
    ) -> int:
        """Log first, in the same transaction as the bit flips: a revocation never takes effect unlogged, and
        a failed log write leaves every bit as it was (review 2, N-M4). Call inside an audit transaction."""
        revoked = [ref for ref in refs if self.status.revocable(ref)]
        data: dict[str, Any] = {"count": len(revoked), "reason": reason, "subject_ref": subject_ref}
        if subject_refs is not None:
            data["subject_refs"] = subject_refs  # a revocation by person: every offer made for that person
            data["offers_cancelled"] = closed
        elif closed:
            data["offer_cancelled"] = True
        self.audit.append("credential.revoked", operator, **data, status_refs=[self._ref(r) for r in revoked])
        for ref in revoked:
            self.status.revoke(ref)
        return len(revoked)

    def _offer_live(self, subject_ref: str) -> bool:
        """An offer can still yield a credential while it is open and one of its configurations has not been
        issued. A configuration counts as issued only once its issuance committed, not when it was claimed."""
        if self.store.get("subject-closed", subject_ref) is not None:
            return False
        if self.store.get("subject-refresh", subject_ref) is not None:
            # A refresh token can still get credentials issued again, or collect one held for review: only the code
            # flow is held, and no hold outlasts the login's refresh token, so this mark covers it too.
            return True
        configurations = self.store.get("subject-open", subject_ref)
        if not isinstance(configurations, list):
            return False
        return any(self.store.get("subject-done", f"{subject_ref}:{c}") is None for c in configurations)

    def _close_subject(self, subject_ref: str) -> None:
        """No further token or credential for this subject: the token and credential endpoints check the mark.
        It lives as long as an offer, or a login with its code, and a token obtained at the very end of their
        lives could (the second reviewer: a login's subject outlived an offer's lifetime)."""
        self.store.put("subject-closed", subject_ref, 1, self._subject_window())
        self.vault.drop_replies(subject_ref)
        for key, _ in self.store.items("deferred", f"{subject_ref}:", at=0):  # nothing held is issued any more
            self.store.delete("deferred", key)
            self.store.delete("transaction", key.rsplit(":", 1)[1])
        # The refresh token of its login and the record of the login's spent code: neither can be used once the
        # subject is closed, and they name the subject beside the wallet instance that logged in, for as long as the
        # refresh token would have lived (the security review).
        login = self.store.peek("subject-login", subject_ref)
        if isinstance(login, dict):
            self.store.delete("refresh", str(login.get("refresh")))
            self.store.delete("code-spent", str(login.get("code")))
            self.store.delete("subject-login", subject_ref)

    def _offer_used_up(self, offer_key: str, subject_ref: str) -> None:
        """Wrong transaction codes have used an offer up (Tokens.exchange): its code gets no token any more. It ends
        as every other offer that ends before its time, in one logged transaction, and the subject's data goes with
        it, since nothing can be issued from it. Before, the offer went without a trace in any log, so an operator
        could not tell codes being guessed from an offer nobody used, and its data stayed in the vault until the
        offer would have run out (the security review). The subject is not marked closed: its progress still reads
        as an offer that ran out, as the operator's pages are told to expect.

        The offer is taken here, as a request with the right code takes it, so whichever of the two comes first has
        it. When a request with the right code got there first it has its token, and nothing is ended, logged or
        erased: the data that token is to be issued from must stay (the second reviewer)."""
        with self._logged():
            ended = self.store.take("offer", offer_key) is not None
            if ended:
                self.store.delete("subject-offer", subject_ref)
                self.audit.append("offer.cancelled", "cunho", subject_ref=subject_ref, cause="tx_code_attempts")
                self.vault.erase(subject_ref)
        if ended:
            security_log.warning("an offer was ended by wrong transaction codes")

    def _subject_window(self) -> int:
        return self.settings.subject_window

    def _token_minted(self, subject_ref: str, expires: int) -> None:
        """Inside the transaction that stores an access token: the subject has reached a wallet."""
        self.store.put("subject-token", subject_ref, 1, self._subject_window())
        self.store.delete("subject-refused", subject_ref)  # a refusal before this token is behind the wallet now
        self._keep_configs(subject_ref)
        self._keep_keys(subject_ref, expires)

    def _keep_keys(self, subject_ref: str, expires: int) -> None:
        """A token of this subject was minted that ends at `expires`. The latest end among the subject's tokens is
        kept (`subject-reach`), and the keys the subject has credentials on stay claimed at least that long: a key
        is claimed until the end of its login's refresh token and of every token minted so far (_claim_grant), and
        a token minted later that ends after that takes the claims along with it. Each end is the token's own,
        under its MAC. The lifetimes configured now do not come into it: after a restart with a shorter
        refresh_token_ttl a claim that went by them ran out while a refresh token from before the restart still
        lived, and its key was bound again (the second reviewer)."""
        known = self.store.get("subject-reach", subject_ref)
        if isinstance(known, int) and known >= expires:
            return
        left = max(expires - self.time(), 1)
        self.store.put("subject-reach", subject_ref, expires, left)
        for key, until in self.store.items("subject-key", f"{subject_ref}:"):
            if not isinstance(until, int) or until < expires:  # never shortened: most reach to the refresh token's end
                self.store.put("subject-key", key, expires, left)

    def _keep_configs(self, subject_ref: str) -> None:
        """Beside every later mark of a subject's progress, in its transaction: what the subject is for lives as
        long as the newest mark, so completion is never judged without it (the second reviewer)."""
        listed = self.store.get("subject-configs", subject_ref)
        if isinstance(listed, list):
            self.store.put("subject-configs", subject_ref, listed, self._subject_window())

    def subject_progress(self, subject_ref: str) -> dict[str, Any]:
        """How far one subject has got (`GET /admin/offers/{subject_ref}`), for the operator's own pages: a demo
        that follows a QR code, a console. Built from what cunho keeps anyway to decide issuance, and never the
        subject data, a code, a token, a transaction_id or the person handle.

        `state` is the furthest the subject got: `closed` (revoked, cancelled or erased), `issued` (every
        configuration), `redeemed` (a wallet got a token), `offered` (a token can still be got, until `expires`)
        or `expired`. Each configuration is `pending`, `held`, `released` or `refused` (a review), or `issued`,
        with the newest event the wallet reported for it at the notification endpoint. While the subject is
        `redeemed`, `refusal` is the error code and rule of the last credential request refused, if any: what a
        wallet that does not get its credential did not pass."""
        enforce(
            self._handed_out(subject_ref),
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "not a subject reference this issuer handed out",
            404,
        )
        configurations: dict[str, dict[str, Any]] = {}
        # Per configuration, the newest of its issuance and its reviews: a refresh can ask for a configuration
        # again, and each ask held for review leaves a row of its own until it ends (the second reviewer). At the
        # same moment a review is the newer: a review collected is gone, so one left came after the issuance.
        newest: dict[str, tuple[float, int]] = {}

        def of(config_id: str) -> dict[str, Any]:
            return configurations.setdefault(config_id, {"state": "pending", "notification": None})

        def step(config_id: str, at: float, rank: int, state: str) -> None:
            if (at, rank) > newest.get(config_id, (-math.inf, 0)):
                newest[config_id] = (at, rank)
                of(config_id)["state"] = state

        with self.store.atomic():  # one reading: an issuance committing meanwhile is seen whole or not at all
            # What the subject is for: kept as long as any mark below, so completion is judged against all of it
            # (the second reviewer); a subject from before M5 has only what it can still yield.
            listed = self.store.get("subject-configs", subject_ref)
            if not isinstance(listed, list):
                listed = self.store.get("subject-open", subject_ref)
            listed = [str(c) for c in listed] if isinstance(listed, list) else []
            for config_id in listed:
                of(config_id)
            for key, _ in self.store.items("subject-done", f"{subject_ref}:"):
                at = self.store.get("subject-issued", key)
                step(key.split(":", 1)[1], float(at) if isinstance(at, int | float) else 0.0, 0, "issued")
            for key, _ in self.store.items("deferred", f"{subject_ref}:"):
                row = self._held(key)
                if row is not None:
                    step(row["config"], float(row.get("at", row["created"])), 1, row["state"])
            for key, event in self.store.items("subject-event", f"{subject_ref}:"):
                of(key.split(":", 1)[1])["notification"] = event
            expires = self.store.get("subject-offer", subject_ref)
            refused = self.store.get("subject-refused", subject_ref)
            if self.store.get("subject-closed", subject_ref) is not None:
                state = "closed"
            elif listed and all(configurations[c]["state"] == "issued" for c in listed):
                state = "issued"
            elif self.store.get("subject-token", subject_ref) is not None:
                state = "redeemed"
            elif expires is not None:
                state = "offered"
            else:
                state = "expired"
        return {
            "subject_ref": subject_ref,
            "state": state,
            "expires": expires if state == "offered" else None,
            "configurations": [{"id": c, **configurations[c]} for c in sorted(configurations)],
            "refusal": refused if state in ("offered", "redeemed") and isinstance(refused, dict) else None,
        }

    def pending_login(self, login_state: str) -> dict[str, Any]:
        """What a login the login service has yet to report is for (`GET /admin/logins/{login_state}`), so it can
        show the person what they are about to agree to: the configurations the wallet asked for, the wallet
        solution that asked (the `sub` of its attestation, and the name and version it gives), and until when the
        login can be reported."""
        pending = self.authorization.reportable_login(login_state)
        enforce(
            pending is not None,
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "login_state is unknown, expired or already reported",
            404,
        )
        assert pending is not None
        name, version = pending.get("wallet") or (None, None)
        return {
            "configuration_ids": list(pending["configuration_ids"]),
            "client": pending["client"],
            "wallet_name": name,
            "wallet_version": version,
            "offer_ref": pending.get("offer_ref"),
            "expires": pending["exp"],
        }

    def _hold_for_refresh(self, subject_ref: str, offer_id: str, ttl: int) -> None:
        """Inside the code exchange's transaction: a refresh token now lets the wallet get credentials again for
        `ttl`, so the subject's data stays in the vault that long (decision 2, option a), crypto-shredded on
        revocation, erasure or cancellation as before, and the link to its person handle lives as long as a
        credential re-issued at the very end could."""
        hold = ttl + self.settings.access_token_ttl
        data = self.vault.get(subject_ref, offer_id)
        if data is not None:
            self.vault.put(subject_ref, data, hold, offer_id)
        self.store.put("subject-refresh", subject_ref, 1, hold)
        reference = self.store.get("person-of", subject_ref)
        if isinstance(reference, str):
            settings = self.settings
            linked = hold + settings.credential_validity_days * DAY + settings.timestamp_granularity
            self._link_person_ref(subject_ref, reference, linked)

    def _code_reused(self, subject_ref: str, token_key: str, refresh_key: str) -> None:
        """An authorization code used again by the client that used it: its token and refresh token go, and its
        login's subject is closed and its data erased, in one logged transaction, as a cancellation does."""
        with self._logged():
            self.store.delete("access-token", token_key)
            self.store.delete("refresh", refresh_key)
            self.audit.append("offer.cancelled", "cunho", subject_ref=subject_ref, cause="authorization_code_reused")
            self._close_subject(subject_ref)
            self.vault.erase(subject_ref)

    def cancel_offer(self, subject_ref: str, operator: str) -> dict[str, Any]:
        """Cancel an offer that has not yielded all its credentials, named by the subject reference that
        `create_offer` returned. Credentials already issued stay valid; revoke them to end them."""
        enforce(
            self._handed_out(subject_ref),
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "not a subject reference this issuer handed out",
        )
        with self._logged():
            enforce(
                self._offer_live(subject_ref),
                "ISS.SUBJECT.ENTITLEMENT",
                "invalid_request",
                "no live offer for this subject reference",
            )
            self.audit.append("offer.cancelled", operator, subject_ref=subject_ref)
            self._close_subject(subject_ref)
            self.vault.erase(subject_ref)  # nothing is left to issue from it (data minimisation)
        return {"cancelled": True}

    def erase_subject(self, subject_ref: str, operator: str) -> dict[str, Any]:
        """Erase what cunho holds about a subject: its data in the vault and the link to the operator's person
        handle. Only a reference cunho handed out is accepted, and the log says whether there was data left to
        erase, so an erasure record is never untrue (review 5, N5-L6). Its credentials stay revocable by the
        subject reference.

        The subject is closed too, as a revocation closes it: an issuance that read the data before the erasure
        is refused in the transaction of its own log entry, so no credential with the data is handed out after
        `subject.erased` (review 6, N6-L3)."""
        enforce(
            self._handed_out(subject_ref),
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "not a subject reference this issuer handed out",
        )
        with self._logged():
            held = self.vault.data_held(subject_ref) or self.vault.replies_held(subject_ref)
            person = self.store.get("person-of", subject_ref)
            self.audit.append("subject.erased", operator, subject_ref=subject_ref, data_held=held)
            self._close_subject(subject_ref)
            self.vault.erase(subject_ref)
            if isinstance(person, str):
                self.store.delete("person", f"{person}:{subject_ref}")
                self.store.delete("person-of", subject_ref)
        return {"erased": True, "data_held": held}

    def audit_head(self) -> str:
        try:
            return self.audit.signed_head(self.audit_signer, self.settings.issuer_url)
        except AuditError as exc:
            security_log.error("audit head unavailable: %s", exc)
            raise IssuerError(
                "LOG.ISSUANCE_AUDIT", "server_error", "the audit log failed its checks; run /admin/audit/verify", 500
            ) from exc

    def audit_verify(self, signed_head: Any = None) -> tuple[bool, str]:
        """Verify the chain, also against a signed head the operator pulled earlier and kept elsewhere."""
        if signed_head is None:
            return self.audit.verify()
        try:
            jws = parse_jws(signed_head)
            key = public_key_from_jwk(self.audit_signer.public_jwk(), jws.header.get("alg"))
        except JoseError:
            return False, "the signed head is not a JWS from this issuer"
        claims = jws.payload
        if (
            jws.header.get("typ") != "cunho-audit-head+jwt"
            or not verify_signature(jws.header.get("alg"), key, jws.signing_input, jws.signature)
            or claims.get("iss") != self.settings.issuer_url
            or not isinstance(claims.get("seq"), int)
            or isinstance(claims.get("seq"), bool)
            or not isinstance(claims.get("mac"), str)
        ):
            return False, "the signed head is not a JWS from this issuer"
        return self.audit.verify(Mark(claims["seq"], claims["mac"]))

    def sweep(self) -> int:
        """The background sweep of expired rows, about once a minute (`app.py`), with a retry of a WAL
        checkpoint that could not finish, and the publication of status lists.

        It first anchors what a crash left out and closes a damaged anchor, so that waits for no logged
        action (review 5, N5-M1). Nothing is swept or published while the clock watch cannot vouch for the time.
        """
        try:
            self.audit.repair()
        except AuditError as exc:
            security_log.error("the audit anchor could not be repaired: %s", exc)
        self.clock_watch.steady()
        now = self.clock_watch.now()
        if now is None:
            return 0
        removed = self._sweep(now)
        self.status.publish()
        if self._wal_dirty:
            self._checkpoint()
        return removed

    def _sweep(self, now: float) -> int:
        """Delete the rows that expired by the time `now`, which the store stamps and reads expiries by, so a wall
        clock that reads ahead deletes no replay entry early."""
        return self.store.sweep(now)

    def _checkpoint(self) -> bool:
        """Clear the SQLite write-ahead log; until that succeeds, erased rows may still be in it (N4-L1)."""
        self._wal_dirty = not self.store.checkpoint()
        if self._wal_dirty:
            log.warning(
                "the write-ahead log is held by a reader and was not cleared; erased data may stay in it until "
                "a later try succeeds, about once a minute"
            )
        return not self._wal_dirty

    def maintenance(self, *, force: bool = False) -> dict[str, int]:
        """Sweep expired state, apply the audit retention period, schedule decoys and log login failures.

        It runs from a background task (`app.py`), never inside a request, and every step works in short
        bounded transactions, so it is safe in several workers at once. Every step goes by the clock watch's
        time, and waits while the watch cannot vouch for it; pruning waits longer, until the watch has settled
        (ClockWatch). `force`, for tests and the operator's own scripts, runs it now and takes the clock as right.
        """
        watch = self.clock_watch
        now = watch.now()
        due = now is None or not 0 <= now - self._last_maintenance < self.settings.maintenance_interval
        if not force and not due:
            return {}
        if force:
            # The base and its entry stand or fall together, and the entry's anchor line names the base, outside
            # the database, so a copy of the base before it cannot be put back unseen (CX-17).
            with self.audit.transaction():
                base = watch.trust(self.clock())
                if base is not None:
                    self.audit.append(CLOCK_TRUSTED, "cunho", boot=base.boot, elapsed=base.elapsed, time=base.time)
        elif not watch.steady():
            return {"clock_not_steady": 1}
        now = watch.now()
        if now is None:  # a forced run on a host whose boot cannot be named
            return {"clock_not_steady": 1}
        self._last_maintenance = now
        failures = self.auth_failures.drain()
        if failures is not None:
            try:
                self.audit.append("admin.auth_failures", "anonymous", **failures)
            except AuditError:
                security_log.exception("could not log the failed operator logins")
        settled = force or watch.settled()
        if not settled:
            security_log.warning("the clock watch has not settled; audit pruning waits")
        done = {
            "expired_entries": self._sweep(now),
            "audit_entries_pruned": self._prune(now, force) if settled else 0,
            "decoys_scheduled": self.status.churn(),
            "auth_failures_logged": failures["count"] if failures else 0,
        }
        done.update(self.chain(force=force))
        if not settled:
            done["audit_pruning_held"] = 1
        done["wal_cleared"] = int(self._checkpoint())
        return done

    @implements("REVOC.CHAIN_WIA_KA", "VALIDITY.EAA_LE_STATUS_EXP")
    def chain(self, *, force: bool = False) -> dict[str, int]:
        """Revocation chaining (CIR 2024/2979 Annex Ib LC_GEN-4, CIR 2024/2977 Art. 5(4)(b), ARF WUA_29, VCR_07c,
        TS3 §2.3.1): at least every chain_interval, the status of the wallet attestations and key attestations behind
        every credential that lives more than a day is read again from their wallet providers' lists, each list
        once, and every credential whose wallet unit or key storage is revoked is revoked, logged as wallet_revoked.

        A list that cannot be read leaves its credentials as they are: cunho alerts and logs every missed check and
        tries again at the next run, since revoking on a wallet provider's outage could not be undone (CIR 2024/2977
        Art. 5(5)); the credentials end by the attestations' status periods in any case (LC_GEN-3). Only with
        chain_revoke_after_days set does it revoke a credential left unchecked that long. One worker runs it per
        interval; every revocation is its own logged transaction, so a run that stops halfway loses nothing."""
        now = self.clock_watch.now()
        if now is None:
            return {}
        interval = self.settings.chain_interval
        with self.store.atomic():
            # One run at a time across workers: whether a run is due and the lease are read and taken together, and
            # the lease does not depend on the interval, so a long run that crosses into the next interval keeps it
            # (the second reviewer). It lasts at most an interval, so a worker that dies holding it delays the next
            # run by no more than that. A forced run, by an operator or a test, does not wait for it.
            last = self.store.get("chain-last", "run")
            if not force and isinstance(last, int | float) and 0 <= now - last < interval:
                return {}
            lease = b64u(secrets.token_bytes(12))
            if not self.store.add("chain-run", "lease", lease, interval):
                if not force:
                    return {}
                self.store.put("chain-run", "lease", lease, interval)  # a forced run takes it; the other one stops
            self.store.put("chain-last", "run", now, None)  # runs are timed from start to start
        try:
            return self._chain_run(now, lease)
        except LeaseLost:
            security_log.warning("a revocation chaining run lost its lease to another and stopped")
            return {"chain_lease_lost": 1}
        finally:
            with self.store.atomic():
                if self.store.get("chain-run", "lease") == lease:
                    self.store.delete("chain-run", "lease")

    def _keep_lease(self, lease: str) -> None:
        """Renew this run's lease for another interval, and only this run's. A run that lost it (a pause longer than an
        interval, and another worker took it) stops here: it writes nothing more (the second reviewer)."""
        with self.store.atomic():
            if self.store.get("chain-run", "lease") != lease:
                raise LeaseLost
            self.store.put("chain-run", "lease", lease, self.settings.chain_interval)

    def _chain_run(self, now: float, lease: str) -> dict[str, int]:
        """One run, holding `lease`: its own token, passed down rather than kept on the issuer, so two runs in one
        process never share one (the second reviewer)."""
        if not self.store.scan("chain", limit=1):
            return {}
        if self.wallet_status is None:
            security_log.error(
                "revocation chaining cannot run: no wallet provider's status lists are read (set the list of wallet "
                "providers, or wallet_status_anchors in development)"
            )
            return {"chain_unavailable": 1}
        # Each list once (the second reviewer): first the entries the live credentials name, by list, which are
        # small; then each list fetched fresh and judged for all its entries, one list in memory at a time; then the
        # credentials, by those verdicts.
        by_list: dict[tuple[str, bool], set[Reference]] = {}
        for _, row in self._chain_rows():
            for each in self._chain_refs(row):
                by_list.setdefault((each.uri, each.id is not None), set()).add(each)
        states: dict[Reference, str] = {}
        for entries in by_list.values():
            states.update(self.wallet_status.verdicts(sorted(entries, key=lambda r: (r.idx or 0, r.id or b""))))
            self._keep_lease(lease)
        counts = {"chain_checked": 0, "chain_revoked": 0, "chain_unchecked": 0}
        for done, (key, row) in enumerate(self._chain_rows(), 1):
            counts[f"chain_{self._chain_row(key, row, now, states, lease)}"] += 1
            if done % PAGE == 0:
                self._keep_lease(lease)
        unknown = sorted({sha256_b64u(ref.uri)[:16] for ref, state in states.items() if state == "unknown"})
        if counts["chain_unchecked"]:
            security_log.error(
                "revocation chaining could not read %d wallet provider list(s) for %d credential(s); it tries again "
                "at the next run",
                len(unknown),
                counts["chain_unchecked"],
            )
            with self._logged():
                self.audit.append("chain.unchecked", "cunho", credentials=counts["chain_unchecked"], lists=unknown)
        return counts

    def _chain_rows(self) -> Iterator[tuple[str, Any]]:
        after = ""
        while page := self.store.scan("chain", after=after, limit=PAGE):
            after = page[-1][0]
            yield from page

    @staticmethod
    def _chain_refs(row: Any) -> list[Reference]:
        found: list[Reference] = []
        for member in row.get("watch", []) if isinstance(row, dict) else []:
            try:
                found += references({"status": member})
            except JoseError:
                continue
        return found

    def _chain_row(self, key: str, row: Any, now: float, states: dict[Reference, str], lease: str) -> str:
        """One credential's check: "revoked", "checked" when every attestation is VALID, "unchecked" otherwise. An
        entry not read this run (a credential issued meanwhile) is read on its own."""
        subject_ref, list_id, index = key.rsplit(":", 2)
        ref = StatusRef(list_id, int(index))
        found = self._chain_refs(row)
        assert self.wallet_status is not None
        for each in found:
            if each not in states:
                states.update(self.wallet_status.verdicts([each]))
        verdicts = {states[each] for each in found}
        stale = self.settings.chain_revoke_after_days
        if "revoked" in verdicts or ("unknown" in verdicts and stale is not None):
            with self._logged():
                # Fenced: only while this run holds the lease, and by the row as it is now, not as the run read it,
                # so a newer run's later check counts (the second reviewer).
                self._keep_lease(lease)
                current = self.store.get("chain", key)
                if not isinstance(current, dict):
                    return "revoked"  # a revocation of the subject meanwhile took it
                overdue = stale is not None and now - float(current.get("ok", now)) > stale * DAY
                if "revoked" not in verdicts and not overdue:
                    return "unchecked"
                if self.status.revocable(ref):
                    reason = "wallet_revoked" if "revoked" in verdicts else "wallet_unchecked"
                    self._revoke_slots([ref], reason, "cunho", subject_ref)
                self.store.delete("chain", key)
            return "revoked"
        if "unknown" in verdicts or not found:
            return "unchecked"
        ttl = max(float(row["exp"]) - self.time(), 60)
        with self.store.atomic():
            self._keep_lease(lease)
            # Only if the row is still there, a revocation of the subject meanwhile having deleted it, and only
            # forward: an older check never writes over a newer one (the second reviewer).
            current = self.store.get("chain", key)
            if isinstance(current, dict) and float(current.get("ok", 0)) < now:
                self.store.put("chain", key, {**current, "ok": int(now)}, ttl)
        return "checked"

    def _chains(self, nbf: int, exp: int) -> bool:
        """Whether credentials issued now are chained: a PID provider's, or an attestation provider's that chains (ARF
        VCR_07d), that live more than a day (LC_GEN-4; a short-lived one needs no revocation, EAA-6.2.10.1-02.1)."""
        chains = self.settings.profile is Profile.PID_PROVIDER or self.settings.chain_attestations
        return chains and exp - nbf > DAY

    @implements("REVOC.STORE_WIA_CLIENT_STATUS")
    def _chain_watch(self, proven: ProvenKeys, grant: Grant, key: dict[str, Any] | None) -> list[dict[str, Any]]:
        """The status references to check again while one credential lives: the wallet attestations' behind its
        token, and the key attestation's of its own key (the second reviewer: never another key's of the batch)."""
        own = proven.key_status.get(thumbprint(key), []) if key is not None else []
        found: list[dict[str, Any]] = []
        for member in (*grant.client_status, *own):
            if member not in found:
                found.append(member)
        return found

    def _prune(self, now: float, force: bool = False) -> int:
        """Prune what the time says is older than the retention period. Only entries that verify are pruned, in
        their chain from the checkpoint, so whoever can write the database cannot make an entry look old (the
        second reviewer's CX-1). Every batch reads the time and asks the clock watch again whether it has settled,
        so a forced run in another worker meanwhile holds pruning back (CX-16); a forced run here prunes now."""
        try:
            still = None if force else self.clock_watch.settled
            return self.audit.prune_before(now - self.settings.audit_retention_days * DAY, now=now, still=still)
        except AuditError as exc:
            security_log.error("audit pruning stopped: %s", exc)
            return 0
        except Exception:  # damaged rows a check did not foresee stop pruning only, never the steps after it
            security_log.exception("audit pruning stopped on an error; run /admin/audit/verify")
            return 0

    # wallet side -------------------------------------------------------------------------------

    def token(
        self,
        form: Mapping[str, list[str]],
        dpop: Sequence[str],
        headers: Callable[[str], list[str]] = lambda _: [],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """The token endpoint; `headers` gives the request's values of a header, for the wallet attestation."""

        def code_grant(one: Callable[[str], str | None], proofs: Sequence[str]) -> tuple[Any, dict[str, str]]:
            return self.authorization.exchange(one, proofs, headers)

        def refresh_grant(one: Callable[[str], str | None], proofs: Sequence[str]) -> tuple[Any, dict[str, str]]:
            return self.authorization.refresh(one, proofs, headers)

        def attested(one: Callable[[str], str | None]) -> ClientIdentity | None:
            attestations, pops = headers(ATTESTATION_HEADER), headers(POP_HEADER)
            if not attestations and not pops:
                return None  # anonymous, as the pre-authorized flow allows
            return self.client_auth.authenticate(attestations, pops, one("client_id"))

        try:
            return self.tokens.exchange(form, dpop, {CODE_GRANT: code_grant, REFRESH_GRANT: refresh_grant}, attested)
        except IssuerError as exc:
            self._token_refused(form, exc)
            raise

    def _token_refused(self, form: Mapping[str, list[str]], exc: IssuerError) -> None:
        """For GET /admin/offers/{subject_ref}: a wallet holding a live offer's pre-authorized code was refused at
        the token endpoint (no DPoP proof, say), by error code and rule only. Nothing is noted for a code that names
        no live offer, nor for invalid_grant, which is about the code itself (unknown, used, cancelled, wrong
        tx_code), not about how the wallet asked."""
        codes = form.get("pre-authorized_code") or []
        if exc.error == "invalid_grant" or form.get("grant_type") != [metadata.PRE_AUTH_GRANT] or len(codes) != 1:
            return
        if not codes[0]:
            return
        key = offer_key(codes[0])
        # One transaction: a redemption either takes the offer before this reads it (nothing is noted) or mints its
        # token after this writes (and clears the note), never in between (the second reviewer).
        with self.store.atomic():
            offer = opened(self.keyring, "offer-record", key, self.store.get("offer", key), self.time())
            if offer is not None:
                refusal = {"error": exc.error, "rule": exc.rule}
                self.store.put("subject-refused", offer["subject_ref"], refusal, self._subject_window())

    def par(
        self, form: Mapping[str, list[str]], headers: Callable[[str], list[str]]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        return self.authorization.par(form, headers)

    def authorize(self, query: Mapping[str, list[str]]) -> str:
        return self.authorization.authorize(query)

    def resume(self, query: Mapping[str, list[str]]) -> str:
        return self.authorization.resume(query)

    @implements("VCI.NONCE.NO_STORE")
    def nonce(self) -> tuple[dict[str, Any], dict[str, str]]:
        headers = {"Cache-Control": "no-store"}
        if self.settings.dpop_server_nonce:
            headers["DPoP-Nonce"] = self.nonces.issue_dpop_nonce()
        return {"c_nonce": self.nonces.issue_c_nonce()}, headers

    @implements(
        "VCI.CRED.RESPONSE_SHAPE",
        "VCI.CRED.ERROR_CODES",
        "VCI.PROFILE.OID4VCI_HAIP",
        "BATCH.SUPPORT",
        "BATCH.UNIFORM",
        "BATCH.METHOD_INVISIBLE",
        "PRIV.TIMESTAMP_COARSENING",
        "PRIV.UNLINKABILITY_BATCH",
        "LOG.DISCARD_UNIQUE_VALUES",
        "ISS.NO_WALLET_DISCRIMINATION",
        "VALIDITY.PID_LE_STATUS_EXP",
    )
    def credential(
        self, authorization: str | None, dpop: Sequence[str], raw: bytes, media_type: str = "application/json"
    ) -> Reply:
        """The credential endpoint (OpenID4VCI 1.0 §8). Issued credentials and their salts are never stored.

        Nothing here looks at which wallet product is asking: every wallet that passes the same checks
        gets the same answer.
        """
        grant = self.tokens.authorize(authorization, dpop, "POST", self.settings.credential_endpoint)
        try:
            body, encrypted = self._wallet_request(raw, media_type, "invalid_credential_request")
            enforce(
                isinstance(body, dict),
                "VCI.CRED.ERROR_CODES",
                "invalid_credential_request",
                "the request body must be a JSON object",
            )
            assert isinstance(body, dict)
            # Before anything is claimed or signed: parameters that cannot be used are refused, not found out after.
            response_key = self._response_key(body, encrypted)
            return self._reply(self._credential_response(grant, body), response_key)
        except IssuerError as exc:
            # For GET /admin/offers/{subject_ref}: why the wallet holding this subject's token was last refused, by
            # error code and rule only (a description may repeat what the request sent).
            self.store.put(
                "subject-refused", grant.subject_ref, {"error": exc.error, "rule": exc.rule}, self._subject_window()
            )
            raise

    def _credential_response(self, grant: Grant, body: dict[str, Any]) -> dict[str, Any]:
        """The credential endpoint's answer to a request whose token and encryption were checked."""
        enforce(
            ("credential_identifier" in body) != ("credential_configuration_id" in body),
            "VCI.CRED.IDENTIFIER_XOR",
            "invalid_credential_request",
            "send exactly one of credential_identifier and credential_configuration_id",
        )
        config_id = self._requested_configuration(grant, body)
        config = self.configs.get(config_id)
        if config is None:
            refuse("VCI.CRED.ERROR_CODES", "unknown_credential_configuration", "unknown credential configuration")
        enforce(
            config_id in grant.configuration_ids,
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "the access token was not issued for this credential configuration",
        )
        self._wallet_gate(config, grant)
        proofs = body.get("proofs")
        if proofs is None and self.settings.accept_singular_proof:
            proofs = _singular_proof(body.get("proof"))
        proven = self._proofs(config, proofs, grant.client)
        for value in sorted(proven.nonces):
            enforce(
                self.nonces.consume_c_nonce(value), "VCI.NONCE.C_NONCE_VALID", "invalid_nonce", "c_nonce already used"
            )
        enforce(
            self.store.get("subject-closed", grant.subject_ref) is None,
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "this offer was cancelled or its subject revoked or erased",
        )  # checked again in the transaction of the log entry, below
        kept = self.vault.reply(grant.subject_ref, f"{grant.grant_id}:{config_id}")
        if kept is not None:
            return self._repeated(kept, proven)
        subject = self.vault.get(grant.subject_ref, grant.offer_id)
        enforce(
            subject is not None,
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "the subject data for this offer is no longer available",
        )
        assert subject is not None
        nbf, exp = self._validity(proven, config, subject, grant)
        chained = self._chains(nbf, exp)
        subject = self._with_issuance_date(config, subject, nbf)
        try:
            check_subject(config, subject, dt.datetime.fromtimestamp(nbf, dt.UTC).date())
        except ClaimsError as exc:
            refuse("PID.VALUES.VALID_AT_VALIDITY_START", "credential_request_denied", "; ".join(exc.problems))
        self._claim_grant(grant, config_id, proven)
        if grant.review:
            return self._defer(grant, config_id, proven)
        return self._issue(grant, config_id, config, proven, subject, nbf, exp, chained)

    @implements("STATUS.SHORTLIVED_OR_LIST")
    def _issue(
        self,
        grant: Grant,
        config_id: str,
        config: dict[str, Any],
        proven: ProvenKeys,
        subject: dict[str, Any],
        nbf: int,
        exp: int,
        chained: bool,
        transaction: str | None = None,
    ) -> dict[str, Any]:
        """Sign, log and record one credential response. `transaction` is the reference of a deferred issuance being
        collected: its row is taken in the transaction of the log entry, so it yields its credentials once. Every
        credential gets an entry in a status list, however short it lives: cunho never relies on a short validity in
        place of revocation, which the law allows but does not require (EAA-4.2.13-03)."""
        keys: list[dict[str, Any] | None] = list(proven.keys) or [None]
        refs: list[StatusRef] = []
        notification_id = b64u(secrets.token_bytes(18))
        try:
            refs = [self.status.allocate() for _ in keys]
            credentials = [
                self._credential(config, subject, key, ref, nbf, exp) for key, ref in zip(keys, refs, strict=True)
            ]
            with self._logged():
                # In the transaction of the log entry: a revocation of this subject either committed first, and
                # stops this issuance here, or comes after and finds these issued rows (review 4, N4-M5).
                enforce(
                    self.store.get("subject-closed", grant.subject_ref) is None,
                    "VCI.CRED.ERROR_CODES",
                    "credential_request_denied",
                    "this offer was cancelled or its subject revoked or erased",
                )
                if transaction is not None:
                    # Taken here, with the entry: a second collection of the same transaction finds it gone.
                    held = f"{grant.subject_ref}:{transaction}"
                    enforce(
                        self._held(held) is not None,
                        "VCI.DEFER.TRANSACTION_ID",
                        "invalid_transaction_id",
                        "unknown transaction_id, or its credentials were already collected",
                    )
                    self.store.delete("deferred", held)
                    self.store.delete("transaction", transaction)
                # The exact exp is not logged: near the end of a document's life it is the document's own
                # expiry date, a personal attribute (review 4, N4-L2). The configured period is.
                self.audit.append(
                    "credential.issued",
                    "wallet",
                    subject_ref=grant.subject_ref,
                    grant=self._grant_ref(grant.offer_id),
                    configuration_id=config_id,
                    count=len(credentials),
                    status_refs=[self._ref(r) for r in refs],
                    nbf=nbf,
                    validity_days=self.settings.credential_validity_days,
                    **({"transaction": transaction} if transaction is not None else {}),
                )
                # A repeated request gets the same response (§8.3); after a deferred issuance, the transaction_id
                # it kept is spent, so its kept answer goes and a repeat is refused as a second use of the token.
                slot = f"{grant.grant_id}:{config_id}"
                if transaction is None:
                    reply = {
                        "keys": sorted(thumbprint(k) for k in proven.keys),
                        "credentials": credentials,
                        "notification_id": notification_id,
                    }
                    self.vault.keep_reply(grant.subject_ref, slot, reply, max(grant.expires - self.time(), 1))
                else:
                    self.vault.drop_reply(grant.subject_ref, slot)
                # What the wallet's notifications name (§11): the issuance, never a credential or a key. Sealed, as
                # the rows that say whose issuance something is are.
                window = self._subject_window()
                about = self._notification_ref(notification_id)
                notice = {
                    "subject_ref": grant.subject_ref,
                    "config": config_id,
                    "grant": self._grant_ref(grant.offer_id),
                    "exp": int(self.time() + window),
                }
                self.store.put("notification", about, seal(self.keyring, "notification", about, notice), window)
                for key, ref in zip(keys, refs, strict=True):
                    self.store.put(
                        "issued",
                        f"{grant.subject_ref}:{ref.list_id}:{ref.index}",
                        {"list": ref.list_id, "idx": ref.index},
                        max(exp - self.time(), 60),
                    )
                    watch = self._chain_watch(proven, grant, key) if chained else []
                    if watch:
                        # What revocation chaining checks again for this credential while it lives (LC_GEN-4).
                        self.store.put(
                            "chain",
                            f"{grant.subject_ref}:{ref.list_id}:{ref.index}",
                            {"watch": watch, "exp": exp, "ok": int(self.time())},
                            max(exp - self.time(), 60),
                        )
                # As long as the subject's open row can live, for an offer or a login (the second reviewer).
                self.store.put("subject-done", f"{grant.subject_ref}:{config_id}", 1, self._subject_window())
                # When, for GET /admin/offers/{subject_ref}: a review asked for later is newer than this issuance.
                issued_at = f"{grant.subject_ref}:{config_id}"
                self.store.put("subject-issued", issued_at, self.time(), self._subject_window())
                self._keep_configs(grant.subject_ref)
        except BaseException:
            # Nothing was handed out: its slots never reach a wallet, and the claim is given back, so
            # the offer is not live for a configuration it can no longer issue (review 6, N6-L4).
            for ref in refs:
                self.status.revoke(ref)
            if transaction is None:
                self._release_grant(grant, config_id, proven)
            raise
        self.status.note_batch(len(refs))
        done = all(self.store.get("subject-done", f"{grant.subject_ref}:{c}") for c in grant.configuration_ids)
        if done and self.store.get("subject-refresh", grant.subject_ref) is None:
            # Data minimisation (ARF ISSU_35b, GDPR Art. 5(1)(c)): nothing is left to issue from this offer. Only
            # once every configuration committed: one merely claimed may still fail and be given back, and its
            # data must then still be there (review 7, L5; the second reviewer's CX-3).
            self.vault.erase(grant.subject_ref)
        return {"credentials": [{"credential": c} for c in credentials], "notification_id": notification_id}

    def _credential(
        self,
        config: dict[str, Any],
        subject: dict[str, Any],
        key: dict[str, Any] | None,
        ref: StatusRef,
        nbf: int,
        exp: int,
    ) -> str:
        """One credential in the configuration's format."""
        if config.get("format") == metadata.MDOC:
            # An mdoc configuration is published only with a document signer, and only bound to a key.
            assert self.signers.mdoc is not None and self.status_anchor is not None and key is not None
            return mdoc.issuer_signed(
                self.settings, self.signers.mdoc, config, subject, key, ref, nbf, exp, self.status_anchor
            )
        return sd_jwt_vc(
            self.settings,
            self.signers.credentials,
            config,
            subject,
            key,
            ref,
            nbf,
            exp,
            self.configs.integrity.get(config["vct"]),
        )

    def _repeated(self, kept: dict[str, Any], proven: ProvenKeys) -> dict[str, Any]:
        """A request repeated under the same access token for the same configuration, with fresh proofs for the
        same keys, gets the credentials the first one got (OpenID4VCI 1.0 §8.3; the conformance suite asks a
        token more than once). A new credential is never made: a second one on the same key would share it
        (ARF ISSU_35), and the token's one batch is all it can yield (M-1). The reply goes when the token
        expires or the subject is closed."""
        enforce(
            sorted(thumbprint(k) for k in proven.keys) == kept["keys"],
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "this access token was already used for this credential configuration with other keys",
        )
        if "transaction_id" in kept:
            return {"transaction_id": kept["transaction_id"], "interval": self.settings.deferred_interval}
        answer: dict[str, Any] = {"credentials": [{"credential": c} for c in kept["credentials"]]}
        if "notification_id" in kept:  # a reply kept before notifications came has none, and needs none (§8.3)
            answer["notification_id"] = kept["notification_id"]
        return answer

    def _defer(self, grant: Grant, config_id: str, proven: ProvenKeys) -> dict[str, Any]:
        """Hold the issuance for the operator's review (OpenID4VCI 1.0 §8.3, §9): every check of the request has
        passed and the keys are proven, so what is kept is what the credentials will be bound to and capped by. Only the
        code flow is held, and its refresh token already keeps the subject's data and the link to its person handle
        until it expires and a token after it could, which a hold never outlasts: nothing is kept longer for it (the
        second reviewer)."""
        transaction_id = b64u(secrets.token_bytes(32))
        ref = self._transaction_ref(transaction_id)
        now = self.time()
        # Never longer than the wallet can still get a token for this login: past its refresh token's expiry a
        # released issuance could not be collected (the second reviewer).
        reach = max(grant.expires, grant.refresh_exp or 0) - int(now)
        hold = max(min(self.settings.deferred_ttl, reach), 1)
        row = {
            "state": "held",
            "config": config_id,
            "offer": grant.offer_id,
            "grant": grant.grant_id,
            "keys": proven.keys,
            "status_exp": proven.status_exp,
            "key_status": proven.key_status,
            "created": int(now),
            "at": now,  # ordered against the subject's issuances by GET /admin/offers/{subject_ref}
            "exp": int(now + hold),
        }
        try:
            with self._logged():
                enforce(
                    self.store.get("subject-closed", grant.subject_ref) is None,
                    "VCI.CRED.ERROR_CODES",
                    "credential_request_denied",
                    "this offer was cancelled or its subject revoked or erased",
                )
                # Every refresh gives a token that may ask again, so nothing but this bounds what one login puts
                # before the operator, into the store and into the log (the security review).
                waiting = [self._held(key) for key, _ in self.store.items("deferred", f"{grant.subject_ref}:")]
                enforce(
                    sum(1 for held in waiting if held is not None and held["config"] == config_id)
                    < HELD_PER_CONFIGURATION,
                    "VCI.CRED.ERROR_CODES",
                    "credential_request_denied",
                    "this login already has issuances of this configuration waiting for the issuer's review",
                )
                self.audit.append(
                    "credential.deferred",
                    "wallet",
                    subject_ref=grant.subject_ref,
                    grant=self._grant_ref(grant.offer_id),
                    configuration_id=config_id,
                    count=max(len(proven.keys), 1),
                    transaction=ref,
                )
                self._keep_held(f"{grant.subject_ref}:{ref}", row)
                self.store.put("transaction", ref, grant.subject_ref, hold)
                self.vault.keep_reply(
                    grant.subject_ref,
                    f"{grant.grant_id}:{config_id}",
                    {"keys": sorted(thumbprint(k) for k in proven.keys), "transaction_id": transaction_id},
                    max(grant.expires - now, 1),
                )
        except BaseException:
            self._release_grant(grant, config_id, proven)
            raise
        return {"transaction_id": transaction_id, "interval": self.settings.deferred_interval}

    @implements("VCI.DEFER.TRANSACTION_ID")
    def deferred_credential(
        self, authorization: str | None, dpop: Sequence[str], raw: bytes, media_type: str = "application/json"
    ) -> Reply:
        """The deferred credential endpoint (OpenID4VCI 1.0 §9). Any access token of the same login that may ask for
        the configuration collects it, so a wallet whose token expired during the review uses a refreshed one, which
        only the attested wallet that logged in can get (the refresh token is bound to it)."""
        grant = self.tokens.authorize(authorization, dpop, "POST", self.settings.deferred_credential_endpoint)
        body, encrypted = self._wallet_request(raw, media_type, "invalid_credential_request")
        enforce(
            isinstance(body, dict) and isinstance(body.get("transaction_id"), str),
            "VCI.DEFER.TRANSACTION_ID",
            "invalid_credential_request",
            "the request body must be a JSON object with a transaction_id string",
        )
        assert isinstance(body, dict)
        # The parameters of this request, not of the first one: the wallet's key may have changed meanwhile (§9.2).
        response_key = self._response_key(body, encrypted)
        return self._reply(self._collect(grant, str(body["transaction_id"])), response_key)

    def _collect(self, grant: Grant, transaction_id: str) -> dict[str, Any]:
        """The deferred credential endpoint's answer to a request whose token and encryption were checked."""
        # A closed subject's held issuances are gone with it: the wallet learns it can stop asking (§9.3).
        enforce(
            self.store.get("subject-closed", grant.subject_ref) is None,
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "this offer was cancelled or its subject revoked or erased",
        )
        ref = self._transaction_ref(transaction_id)
        row = self._held(f"{grant.subject_ref}:{ref}")
        enforce(
            isinstance(row, dict) and row["config"] in grant.configuration_ids,
            "VCI.DEFER.TRANSACTION_ID",
            "invalid_transaction_id",
            "unknown transaction_id, or its credentials were already collected",
        )
        assert isinstance(row, dict)
        enforce(
            row["state"] != "refused",
            "VCI.DEFER.TRANSACTION_ID",
            "credential_request_denied",
            "the issuer refused this issuance",
        )
        if row["state"] == "held":
            return {"transaction_id": transaction_id, "interval": self.settings.deferred_interval}
        # One request collects at a time. The row is taken in the transaction of the log entry, after the status
        # entries are reserved and the credentials signed: every collection that came at once did that work, and
        # all but one then revoked the entries they had taken (the security review). Another request asks again,
        # as while the issuance was held; a request that dies leaves the mark to run out.
        if not self.store.add("collecting", f"{grant.subject_ref}:{ref}", 1, COLLECTING):
            return {"transaction_id": transaction_id, "interval": self.settings.deferred_interval}
        try:
            return self._collect_released(grant, transaction_id, ref, row)
        finally:
            self.store.delete("collecting", f"{grant.subject_ref}:{ref}")

    def _collect_released(self, grant: Grant, transaction_id: str, ref: str, row: dict[str, Any]) -> dict[str, Any]:
        """The credentials of a released issuance, for the one request that holds its collecting mark."""
        if self.wallet_status is not None:
            # The keys' attestations were checked when the issuance was asked for, which may be weeks ago, and
            # revocation chaining watches only issued credentials: read their status again now. A revocation ends the
            # issuance; a list that cannot be read keeps it waiting, as the wallet may ask again (OpenID4VCI §9.2).
            members = [m for found in row["key_status"].values() for m in found]
            for member in [m for i, m in enumerate(members) if m not in members[:i]]:
                try:
                    self.wallet_status.check({"status": member})
                except Revoked:
                    refuse(
                        "KA.STATUS_AT_ISSUANCE",
                        "credential_request_denied",
                        "a key attestation behind this issuance was revoked",
                    )
                except JoseError:
                    return {"transaction_id": transaction_id, "interval": self.settings.deferred_interval}
        config_id = str(row["config"])
        config = self.configs.get(config_id)
        enforce(
            config is not None,
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "this credential configuration is no longer issued",
        )
        assert config is not None
        # The wallet that collects is the one behind the token used now, as at a refresh (ARF SUA_03).
        self._wallet_gate(config, grant)
        subject = self.vault.get(grant.subject_ref, str(row["offer"]))
        enforce(
            subject is not None,
            "VCI.CRED.ERROR_CODES",
            "credential_request_denied",
            "the subject data for this offer is no longer available",
        )
        assert subject is not None
        proven = ProvenKeys(keys=list(row["keys"]), status_exp=row["status_exp"], key_status=dict(row["key_status"]))
        # The keys and their attestations are those proven when the issuance was asked for; the wallet attestation
        # is the one behind the token used now, as at a refresh, which decides how long the wallet's status is kept.
        held = Grant(
            grant_id=str(row["grant"]),
            jkt=grant.jkt,
            configuration_ids=grant.configuration_ids,
            subject_ref=grant.subject_ref,
            offer_id=str(row["offer"]),
            expires=grant.expires,
            client_status_exp=grant.client_status_exp,
            client=grant.client,
            client_status=grant.client_status,
            wallet=grant.wallet,
        )
        nbf, exp = self._validity(proven, config, subject, held)
        chained = self._chains(nbf, exp)
        subject = self._with_issuance_date(config, subject, nbf)
        try:
            check_subject(config, subject, dt.datetime.fromtimestamp(nbf, dt.UTC).date())
        except ClaimsError as exc:
            refuse("PID.VALUES.VALID_AT_VALIDITY_START", "credential_request_denied", "; ".join(exc.problems))
        return self._issue(held, config_id, config, proven, subject, nbf, exp, chained, transaction=ref)

    def deferred_issuances(self) -> dict[str, Any]:
        """What the operator has to decide: every issuance held or released and not collected yet."""
        held = [(key, self._held(key)) for key, _ in self.store.items("deferred")]
        rows = [
            {
                "ref": key.rsplit(":", 1)[1],
                "subject_ref": key.rsplit(":", 1)[0],
                "configuration_id": row["config"],
                "state": row["state"],
                "created": row["created"],
            }
            for key, row in held
            if row is not None
        ]
        return {"deferred": sorted(rows, key=lambda r: (r["created"], r["ref"]))}

    def decide_deferred(self, ref: str, decision: str, operator: str) -> dict[str, Any]:
        """Release or refuse an issuance held for review. The decision is taken and logged in one transaction, and
        only from held: a released issuance is not refused afterwards, nor a refused one released."""
        assert decision in ("release", "refuse")
        enforce(
            bool(TRANSACTION_REF.fullmatch(ref)),
            "ISS.SUBJECT.ENTITLEMENT",
            "invalid_request",
            "not a reference of a held issuance",
            404,
        )
        with self._logged():
            subject_ref = self.store.get("transaction", ref)
            key = f"{subject_ref}:{ref}"
            row = self._held(key) if isinstance(subject_ref, str) else None
            enforce(
                isinstance(row, dict) and row["state"] == "held",
                "ISS.SUBJECT.ENTITLEMENT",
                "invalid_request",
                "no issuance held for review with this reference",
                404,
            )
            assert isinstance(row, dict)
            state = "released" if decision == "release" else "refused"
            self.audit.append(
                f"credential.{state}",
                operator,
                subject_ref=subject_ref,
                configuration_id=row["config"],
                transaction=ref,
            )
            self._keep_held(key, {**row, "state": state})
        return {"state": state}

    @implements("VCI.NOTIF.VALIDATION")
    def notification(self, authorization: str | None, dpop: Sequence[str], raw: bytes) -> None:
        """The notification endpoint (OpenID4VCI 1.0 §11). Each event of an issuance is logged once, however often
        the wallet sends it. The wallet's event_description is checked and never kept: it is free text."""
        grant = self.tokens.authorize(authorization, dpop, "POST", self.settings.notification_endpoint)
        try:
            body = strict_json(raw)
        except (ValueError, UnicodeDecodeError):
            body = None
        enforce(
            isinstance(body, dict),
            "VCI.NOTIF.VALIDATION",
            "invalid_notification_request",
            "the request body must be a JSON object",
        )
        assert isinstance(body, dict)
        notification_id, event = body.get("notification_id"), body.get("event")
        description = body.get("event_description")
        enforce(
            isinstance(notification_id, str) and isinstance(event, str) and event in EVENTS,
            "VCI.NOTIF.VALIDATION",
            "invalid_notification_request",
            "send a notification_id string and an event of credential_accepted, credential_failure or "
            "credential_deleted",
        )
        enforce(
            description is None or (isinstance(description, str) and bool(EVENT_DESCRIPTION.fullmatch(description))),
            "VCI.NOTIF.VALIDATION",
            "invalid_notification_request",
            'event_description must be at most 1000 printable ASCII characters without " and \\',
        )
        ref = self._notification_ref(str(notification_id))
        row = opened(self.keyring, "notification", ref, self.store.get("notification", ref), self.time())
        enforce(
            isinstance(row, dict) and row["subject_ref"] == grant.subject_ref,
            "VCI.NOTIF.VALIDATION",
            "invalid_notification_id",
            "unknown notification_id",
        )
        assert isinstance(row, dict)
        with self._logged():
            if self.store.add("notified", f"{ref}:{event}", 1, self._subject_window()):
                self.audit.append(
                    "credential.notification",
                    "wallet",
                    subject_ref=row["subject_ref"],
                    grant=row["grant"],
                    configuration_id=row["config"],
                    notice=str(event),
                )
                # The newest event the wallet reported for the configuration, for GET /admin/offers/{subject_ref}.
                about = f"{row['subject_ref']}:{row['config']}"
                self.store.put("subject-event", about, str(event), self._subject_window())
                self._keep_configs(row["subject_ref"])

    def _wallet_request(self, raw: bytes, media_type: str, error: str) -> tuple[Any, bool]:
        """The parsed body of a credential or deferred credential request, decrypted when it came as application/jwt
        (OpenID4VCI 1.0 §10), and whether it was encrypted. None when it is not JSON: the endpoint refuses that."""
        encrypted = media_type == "application/jwt"
        if encrypted:
            keys = self.request_keys
            enforce(
                keys is not None,
                "VCI.ENC.REQUEST",
                error,
                "this issuer takes no encrypted requests: send application/json",
            )
            assert keys is not None
            try:
                raw = keys.decrypt(raw.decode("ascii"))
            except UnicodeDecodeError:
                refuse("VCI.ENC.REQUEST", error, "an encrypted request is a compact JWE in ASCII")
            except JweError as exc:
                refuse("VCI.ENC.REQUEST", error, str(exc))
        else:
            # §10: "When encryption of a message was required but the received message is unencrypted, it SHOULD be
            # rejected."
            enforce(
                self.request_keys is None or not self.request_keys.required,
                "VCI.ENC.REQUEST",
                "invalid_encryption_parameters",
                "this issuer requires encrypted requests: see credential_request_encryption",
            )
        try:
            return strict_json(raw), encrypted
        except (ValueError, UnicodeDecodeError):
            return None, encrypted

    def _response_key(self, body: dict[str, Any], encrypted: bool) -> ResponseKey | None:
        """The wallet's key for an encrypted response, from credential_response_encryption (OpenID4VCI 1.0 §8.2), or
        None for a plain one. The parameters must come in an encrypted request: in a plain one, whoever can change
        the request could put their own key there and read the credentials."""
        keys = self.request_keys
        if "credential_response_encryption" not in body:
            enforce(
                keys is None or not keys.required,
                "VCI.ENC.RESPONSE",
                "invalid_encryption_parameters",
                "this issuer requires encrypted responses: send credential_response_encryption",
            )
            return None
        enforce(
            keys is not None,
            "VCI.ENC.RESPONSE",
            "invalid_encryption_parameters",
            "this issuer does not encrypt responses: send no credential_response_encryption",
        )
        enforce(
            encrypted,
            "VCI.ENC.RESPONSE",
            "invalid_encryption_parameters",
            "credential_response_encryption must come in an encrypted request (OpenID4VCI 1.0 section 8.2)",
        )
        try:
            return ResponseKey.from_params(body["credential_response_encryption"])
        except JweError as exc:
            refuse("VCI.ENC.RESPONSE", "invalid_encryption_parameters", str(exc))

    @implements("VCI.ENC.RESPONSE")
    def _reply(self, body: dict[str, Any], key: ResponseKey | None) -> Reply:
        """The response, encrypted to the wallet's key when it asked: whatever it holds, credentials or a
        transaction_id (OpenID4VCI 1.0 §8.3 "regardless of the content"). Errors are raised, never encrypted."""
        if key is None:
            return Reply(body)
        return Reply(body, key.encrypt(json.dumps(body, separators=(",", ":")).encode()))

    def _held(self, key: str) -> dict[str, Any] | None:
        """A deferred issuance's row, `{subject_ref}:{transaction ref}`, when its MAC verifies over the key and the
        content and it has not expired. It decides which keys a credential is bound to and whether the operator
        released it, so whoever can write the database must not be able to change either (the second reviewer)."""
        return opened(self.keyring, "deferred", key, self.store.get("deferred", key), self.time())

    def _keep_held(self, key: str, row: dict[str, Any]) -> None:
        self.store.put("deferred", key, seal(self.keyring, "deferred", key, row), max(row["exp"] - self.time(), 1))

    def _transaction_ref(self, transaction_id: str) -> str:
        return self.keyring.mac("transaction", transaction_id)[:32]

    def _notification_ref(self, notification_id: str) -> str:
        return self.keyring.mac("notification", notification_id)[:32]

    def _requested_configuration(self, grant: Grant, body: dict[str, Any]) -> str:
        """OpenID4VCI §8.2: a token whose response returned credential_identifiers is used with
        credential_identifier only; any other with credential_configuration_id only."""
        if grant.identifiers:
            enforce(
                "credential_identifier" in body,
                "VCI.AUTHZ_DETAILS",
                "invalid_credential_request",
                "this access token came with credential_identifiers: send credential_identifier",
            )
            identifier = body["credential_identifier"]
            config_id = grant.identifiers.get(identifier) if isinstance(identifier, str) else None
            if config_id is None:
                refuse("VCI.CRED.ERROR_CODES", "unknown_credential_identifier", "unknown credential_identifier")
            return config_id
        if "credential_identifier" in body:
            refuse(
                "VCI.CRED.ERROR_CODES",
                "unknown_credential_identifier",
                "this access token came with no credential identifiers",
            )
        config_id = body["credential_configuration_id"]
        enforce(
            isinstance(config_id, str),
            "VCI.CRED.ERROR_CODES",
            "invalid_credential_request",
            "credential_configuration_id must be a string",
        )
        return str(config_id)

    def status_token(self, list_id: str) -> str | None:
        """The signed status list as a JWT, or None for a list that does not exist. A token this worker already
        signed for the current publication is answered before the store is asked whether the list exists."""
        cached = self.status.cached(list_id, "jwt")
        if isinstance(cached, str):
            return cached
        return self.status.token(list_id) if self.status.exists(list_id) else None

    def status_cwt(self, list_id: str) -> bytes | None:
        """The same list as a CWT, for mdoc, or None for a list that does not exist."""
        cached = self.status.cached(list_id, "cwt")
        if isinstance(cached, bytes):
            return cached
        return self.status.cwt(list_id) if self.status.exists(list_id) else None

    # helpers -------------------------------------------------------------------------------------

    def _claim_grant(self, grant: Grant, config_id: str, proven: ProvenKeys) -> None:
        """One credential request per configuration per access token, and no key bound twice for one subject.

        The configuration and the keys are claimed in one transaction, so a key refused leaves the
        configuration unclaimed and the wallet can ask again with another (review 6, N6-L4).

        A key is claimed for the subject, for as long as a token of the subject can be shown (_keep_keys), not for
        the one access token: every refresh gives a new token, and a key claimed per token was bound to a second,
        different credential at the next one (ARF ISSU_35; the security review). What is kept is a keyed
        reference of the key, never the key.

        A claim is made only while the token lives, which is checked again here, inside the transaction: a request
        that began just before the token expired could otherwise reach this after an earlier claim's marker,
        made when the token was new, had expired with it, and claim the same configuration again (the second
        reviewer, CX-26). Each marker lives until the token's own expiry, under its MAC, not for the lifetime
        configured now, which may be shorter than the one the token was issued with (CX-28)."""
        with self.store.atomic():
            now = self.time()
            enforce(
                now < grant.expires,
                "OAUTH.RESOURCE_401_CHALLENGE",
                "invalid_token",
                "unknown or expired access token",
                401,
                scheme="DPoP",
            )
            ttl = grant.expires - now
            enforce(
                self.store.add("grant-config", f"{grant.grant_id}:{config_id}", 1, ttl),
                "VCI.CRED.ERROR_CODES",
                "credential_request_denied",
                "this access token was already used for this credential configuration",
            )
            # Until no token of the subject can be shown any more, as far as is known now: the end of the login's
            # refresh token, of this token and of every token minted before it (_keep_keys).
            known = self.store.get("subject-reach", grant.subject_ref)
            reach = max(known if isinstance(known, int) else 0, grant.expires, grant.refresh_exp or 0)
            for key in proven.keys:
                enforce(
                    # A token from before keys were claimed for the subject left its claims under its own name
                    # (grant-key): they hold for as long as that token lives, also across the upgrade.
                    self.store.get("grant-key", f"{grant.grant_id}:{thumbprint(key)}") is None
                    and self.store.add(
                        "subject-key", self._key_ref(grant.subject_ref, key), reach, max(reach - now, 1)
                    ),
                    "KA.BIND_TO_ATTESTED_KEY",
                    "invalid_proof",
                    "this key is already bound to a credential issued from this offer or login",
                )

    def _release_grant(self, grant: Grant, config_id: str, proven: ProvenKeys) -> None:
        """Give back what `_claim_grant` took, for an issuance that did not commit."""
        with self.store.atomic():
            self.store.delete("grant-config", f"{grant.grant_id}:{config_id}")
            for key in proven.keys:
                self.store.delete("subject-key", self._key_ref(grant.subject_ref, key))

    def _key_ref(self, subject_ref: str, key: dict[str, Any]) -> str:
        """The row that says a subject has a credential on this key: the subject, and a keyed reference of the key."""
        return f"{subject_ref}:{self.keyring.mac('subject-key', thumbprint(key))[:32]}"

    def _proofs(self, config: dict[str, Any], proofs: Any, client: str | None = None) -> ProvenKeys:
        types = (
            metadata.published_config(config, self.configs.signer_alg, self.configs.mdoc_alg).get(
                "proof_types_supported"
            )
            or {}
        )
        if not types:
            # Startup already refuses such a configuration; this keeps an unbound PID impossible (review 2, N-M3).
            enforce(
                not metadata.is_pid(config) and self.settings.profile is not Profile.PID_PROVIDER,
                "BIND.DEVICE_BOUND",
                "credential_request_denied",
                "a PID is only issued bound to a key the wallet proves it holds",
            )
            return ProvenKeys()
        enforce(
            proofs is not None,
            "VCI.CRED.PROOFS_SHAPE",
            "invalid_proof",
            "proofs is required for this credential configuration",
        )
        enforce(
            isinstance(proofs, dict) and len(proofs) == 1,
            "VCI.CRED.PROOFS_SHAPE",
            "invalid_credential_request",
            "proofs must contain exactly one proof type",
        )
        assert isinstance(proofs, dict)
        proof_type, items = next(iter(proofs.items()))
        enforce(
            isinstance(items, list) and bool(items) and all(isinstance(i, str) for i in items),
            "VCI.CRED.PROOFS_SHAPE",
            "invalid_credential_request",
            "the proofs array must hold strings",
        )
        enforce(
            proof_type in types,
            "VCI.CRED.PROOFS_SHAPE",
            "invalid_proof",
            "this proof type is not supported for this configuration",
        )
        limit = metadata.batch_limit(config, self.configs.batch_size)
        enforce(
            len(items) <= limit,
            "BATCH.SUPPORT",
            "invalid_credential_request",
            f"at most {limit} proofs per request (batch_size)",
        )
        spec = types[proof_type]
        proven = (
            self.proofs.jwt_proofs(items, spec, client)
            if proof_type == "jwt"
            else self.proofs.attestation_proofs(items, spec)
        )
        enforce(
            len(proven.keys) <= limit,
            "BATCH.SUPPORT",
            "invalid_proof",
            f"the key attestation lists more than {limit} keys (batch_size)",
        )
        self.proofs.require_status_period(proven, config)
        return proven

    def _validity(
        self, proven: ProvenKeys, config: dict[str, Any], subject: dict[str, Any], grant: Grant
    ) -> tuple[int, int]:
        """nbf and exp. The technical validity ends before the key attestation's key_storage_status.exp and the
        wallet attestation's client_status.exp (TS3 v1.5.2 §2.4.3, ARF ISSU_12c), so revocation chaining can rely
        on both for as long as the credential lives."""
        step = self.settings.timestamp_granularity
        now = int(self.time())
        nbf = now // step * step
        if config.get("format") == metadata.MDOC and self.signers.mdoc is not None:
            # ISO/IEC 18013-5 §9.3.1: a reader checks that the MSO was signed while the document signer certificate
            # was valid. The coarse time can fall before the start of a certificate put in use since: the mdoc then
            # starts with the certificate, a time every mdoc it signs that hour shares, so it tells nothing more.
            started = int(
                x509.load_der_x509_certificate(self.signers.mdoc.certificate_der()).not_valid_before_utc.timestamp()
            )
            if nbf < started <= now:
                nbf = started
        exp = nbf + self.settings.credential_validity_days * DAY
        for status_exp in (proven.status_exp, grant.client_status_exp):
            if status_exp is not None:
                exp = min(exp, status_exp - 1)
        if config.get("format") == metadata.MDOC and not metadata.is_pid(config):
            # An mdoc's administrative validity ends at the expiry_date of its namespace (ETSI TS 119 472-1
            # EAA-6.2.7.2-02). The PID comes in the SD-JWT VC names in either format, with date_of_expiry.
            ends = [parse_date(members.get("expiry_date")) for members in subject.values() if isinstance(members, dict)]
        else:
            # Whichever name the rulebook gives the document's end (the security review: only date_of_expiry was
            # read, so an attestation whose rulebook says expiry_date outlived its document).
            ends = [parse_date(subject.get(name)) for name in EXPIRY_CLAIMS]
        for document_end in ends:
            if document_end is not None:
                # The technical validity never outlasts the document itself.
                end_of_day = dt.datetime.combine(document_end, dt.time.max, dt.UTC).timestamp()
                exp = min(exp, int(end_of_day))
        exp = exp // step * step
        enforce(
            exp > nbf,
            "VALIDITY.PID_LE_STATUS_EXP",
            "credential_request_denied",
            "the wallet's revocation maintenance period or the document ends too soon to issue a credential",
        )
        return nbf, exp

    @staticmethod
    def _with_issuance_date(config: dict[str, Any], subject: dict[str, Any], nbf: int) -> dict[str, Any]:
        day = dt.datetime.fromtimestamp(nbf, dt.UTC).date().isoformat()
        if config.get("format") == metadata.MDOC and metadata.is_pid(config):
            # The PID in the SD-JWT VC names: its issuance_date element is issued from date_of_issuance.
            listed = pid_mdoc_elements(config)
            out = dict(subject)
            if "issuance_date" in listed and "date_of_issuance" not in out:
                out["date_of_issuance"] = day
            return out
        if config.get("format") == metadata.MDOC:
            spaces: dict[str, Any] = {ns: dict(members) for ns, members in subject.items()}
            for claim in config_claims(config):
                ns, name = (str(p) for p in claim["path"][:2])
                if name in MDOC_ISSUANCE_DATES and name not in spaces.get(ns, {}) and (ns, name) not in FILLED:
                    spaces.setdefault(ns, {})[name] = day
            return spaces
        names = {str(c["path"][0]) for c in config_claims(config) if len(c["path"]) == 1}
        out = dict(subject)
        if "date_of_issuance" in names and "date_of_issuance" not in out:
            out["date_of_issuance"] = day
        return out

    @implements("FMT.MDOC.ISSUERAUTH_X5CHAIN")
    def _check_annex_b(self) -> None:
        """When mdoc attestations are published, the document signer, its IACA and the status list signer fit the
        certificate profiles of ISO/IEC 18013-5 Annex B, which mdoc readers hold to: production refuses to start
        otherwise, and a development run says what does not fit."""
        mdocs = any(c.get("format") == metadata.MDOC for c in self.configs.issuable().values())
        if self.signers.mdoc is None or not mdocs:
            return
        signer = x509.load_der_x509_certificate(self.signers.mdoc.certificate_der())
        anchors = (
            x509.load_pem_x509_certificates(self.settings.mdoc_trust_anchors.read_bytes())
            if self.settings.mdoc_trust_anchors
            else []
        )
        # Annex B has the IACA, the reader's trust anchor, sign the document signer itself: no intermediate between.
        iaca = annex_b.issuer_of(signer, anchors)
        problems = annex_b.document_signer_problems(signer, iaca)
        if iaca is None:
            problems.append(
                "the document signer is not signed by an IACA among mdoc_trust_anchors: Annex B has the IACA, the "
                "reader's trust anchor, sign it directly, with no intermediate certificate between"
            )
        else:
            problems += annex_b.iaca_problems(iaca)
        status = x509.load_der_x509_certificate(self.signers.status.certificate_der())
        status_chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in self.signers.status.x5c()[1:]]
        status_anchors = (
            x509.load_pem_x509_certificates(self.settings.signing_trust_anchors.read_bytes())
            if self.settings.signing_trust_anchors
            else []
        )
        problems += annex_b.status_signer_problems(status, annex_b.issuer_of(status, [*status_chain, *status_anchors]))
        if problems and self.settings.production:
            raise ConfigError(
                "the mdoc signing certificates do not fit the profiles mdoc readers check: " + "; ".join(problems)
            )
        for problem in problems:
            log.warning("mdoc signing certificates: %s. Development only; production refuses to start.", problem)

    def _check_provider_names(self) -> None:
        """At start: the certificates a qualified or public-body provider signs with name it as Annex V(b) asks, and
        a document signer that signs mdoc attestations names the issuing authority they carry."""
        mdocs = [c for c in self.configs.issuable().values() if c.get("format") == metadata.MDOC]
        if self.settings.profile in CATEGORIES:
            check_provider(self.signers.credentials.certificate_der(), "credential signing")
            if self.signers.mdoc is not None and mdocs:
                check_provider(self.signers.mdoc.certificate_der(), "mdoc document signer")
        if self.signers.mdoc is not None and any(not metadata.is_pid(c) for c in mdocs):
            authority(self.signers.mdoc.certificate_der())

    @staticmethod
    def _wallet_gate(config: dict[str, Any], grant: Grant) -> None:
        """ARF SUA_03: a configuration that names wallet solutions, such as a SUA attestation whose rulebook asks
        what wallets do with it, is issued only to those solutions, in the versions named, as the wallet attestation
        that got the access token says. A token got without one gets none of it."""
        allowed = config.get("wallet_solutions")
        if allowed is None:
            return
        enforce(
            grant.wallet is not None,
            "ISS.SUA.WALLET_GATE",
            "credential_request_denied",
            "this credential is issued only to the wallet solutions it names: authenticate with a wallet attestation",
        )
        assert grant.wallet is not None
        name, version = grant.wallet
        enforce(
            any(
                entry["wallet_name"] == name and ("wallet_versions" not in entry or version in entry["wallet_versions"])
                for entry in allowed
            ),
            "ISS.SUA.WALLET_GATE",
            "credential_request_denied",
            "this credential is not issued to this wallet solution or version",
        )

    def _own_subject(self, config: dict[str, Any], subject: Any) -> None:
        """A qualified or public-body attestation refers every attribute to its subject (Annex V(c))."""
        if self.settings.profile in CATEGORIES:
            other = names_another_subject(config, subject)
            enforce(other is None, "QEAA.SUBJECT_OR_PSEUDONYM", "invalid_request", f"{other}")

    def _ref(self, ref: StatusRef) -> str:
        return self.keyring.mac("status-ref", f"{ref.list_id}:{ref.index}")[:32]

    def _grant_ref(self, offer_id: str) -> str:
        return self.keyring.mac("grant-ref", offer_id)[:32]

    @contextmanager
    def _logged(self) -> Iterator[None]:
        """An audit transaction: a log failure is a clean 500, and any failure rolls the whole action back."""
        try:
            with self.audit.transaction():
                yield
        except AuditError as exc:
            security_log.error("audit log unavailable: %s", exc)
            raise IssuerError("LOG.ISSUANCE_AUDIT", "server_error", "audit log unavailable", 500) from exc


def _singular_proof(proof: Any) -> dict[str, list[str]] | None:
    """An earlier draft's `proof` object of type jwt, as OpenID4VCI 1.0 `proofs` (accept_singular_proof); anything
    else is no proof at all, and refused as such."""
    if isinstance(proof, dict) and proof.get("proof_type") == "jwt" and isinstance(proof.get("jwt"), str):
        return {"jwt": [proof["jwt"]]}
    return None
