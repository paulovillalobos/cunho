"""Tamper-evident event log and the personal-data vault (DESIGN.md section 7).

The log holds events and pseudonymous references only. Each entry carries a MAC over its content
and over the previous entry's MAC, keyed with a secret that lives outside the data store, so
whoever can write the database cannot rewrite or reorder entries without `verify` noticing.

Deleting entries from the end, or the whole log, cannot be caught from inside the database: an old
head can always be restored. So every new head is also appended, MACed, to an anchor file that the
operator keeps outside the database, on append-only (WORM) storage. The anchor lines form their own
MAC chain that starts with the log itself (a genesis line at sequence 0) and grows by exactly one per
entry, and `verify` compares every line with the store: it fails when the store is behind the anchor or
disagrees with any line still covered by the store. A missing anchor is never started again over an
existing log. `signed_head` produces a signed statement of the newest entry for operators who also want to
keep the head somewhere else.

A write to the anchor can stop part-way (a full disk, a crash), or leave NUL bytes after a power loss. The
next write closes whatever follows the last valid line and declares it in its first line, which `lines`
checks and skips, and the log gets an entry of its own saying so.

Personal data lives in the vault, encrypted per subject; the per-subject keys are wrapped with a
key-encryption key from the keyring, so the database alone does not decrypt anything, and erasing
a subject deletes its wrapped key.
"""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cunho.jose import b64u, b64u_decode
from cunho.keyring import Keyring, same
from cunho.settings import CLOCK_TOLERANCE
from cunho.signer import Signer, sign_jws
from cunho.store import Store

GENESIS = "0" * 64
PAGE = 500
LINE_MAX = 65_536  # cunho writes no line near this long; longer runs of bytes are read in pieces
VERIFY_TRIES = 10
FUTURE_SLACK = 86_400  # an entry dated more than a day after the moment pruning runs was logged by a wrong clock
security_log = logging.getLogger("cunho.security")


def _canonical(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


CLOCK_TRUSTED = "clock.trusted"


def _clock_of(entry: dict[str, Any]) -> list[Any] | None:
    """The boot, host-clock reading and time of the base a forced run laid, for the anchor line of its entry."""
    data = entry.get("data")
    if entry.get("event") != CLOCK_TRUSTED or not isinstance(data, dict):
        return None
    return [data.get("boot"), data.get("elapsed"), data.get("time")]


def _key(seq: int) -> str:
    return f"{seq:012d}"


class AuditError(Exception):
    """Writing the log failed. Callers must not complete the action they were logging."""


@dataclass(frozen=True)
class Mark:
    """One position in the chain: an entry's sequence number and MAC."""

    seq: int
    mac: str


@dataclass
class _Read:
    """How far a reader got through the anchor file: the offset just past the last complete line and that
    line, then what follows it: how many bytes are not a line, their SHA-256, and a line at the very end
    that is complete apart from its newline."""

    end: int = 0
    last: dict[str, Any] | None = None
    clock: list[Any] | None = None  # the newest base a forced run laid, from the newest line that names one
    # The same for each boot: hosts sharing a store each force their own bases (the second reviewer).
    clocks: dict[str, list[Any]] = field(default_factory=dict)
    loose: int = 0
    digest: Any = field(default_factory=hashlib.sha256)
    trailing: dict[str, Any] | None = None


class Anchor:
    """The append-only anchor file: one MACed line per audit head, outside the database.

    Each line is `{"seq", "mac", "time", "prev", "tag"}`: `prev` is the previous line's tag (GENESIS on
    the first line) and `tag` is a keyring MAC over the rest, under its own purpose, so a line can be
    neither forged nor taken for a head pointer or a checkpoint. The first line is the genesis line
    (`seq` 0, `mac` GENESIS), written once when the file is created for an empty log, and `seq` grows by
    exactly one per line after it. Appends from several worker processes are ordered with an exclusive
    `flock` on the file. cunho never creates the file again once a log exists (review 3, N3-M2).

    The file is only ever read forwards, from its start, and every line must follow the one before it. A
    valid line that does not, such as a copy of an earlier line appended to the file, is refused wherever
    it is: it cannot be cunho's, and taking the last valid line as the end, as the reader once did, let a
    copy move the end back (review 6, N6-H1). Each worker remembers how far it read, so a write reads only
    what other workers appended since; the first write of a worker reads the whole file.

    A write can stop part-way (a full disk, a crash), and after a power loss some file systems leave the
    end of the file as NUL bytes instead of what was written. Every writer holds the lock, so whatever
    follows the last line, found under the lock, is damage, never a line still being written. The next
    write closes it with a newline and writes its lines after it; its first line declares the damage it
    closes, by offset, length and SHA-256, under the line's tag. The reader skips bytes that are not a line
    only when the next line declares exactly those bytes, so damage of any shape, or a repair that was
    itself cut short, is repaired by the next write that gets through, while bytes that no tagged line
    accounts for, or a declared stretch changed later, fail verification (review 5, N5-M1). A line that is
    complete apart from its newline is kept, and only the newline is written.
    """

    def __init__(self, path: Path | None, keyring: Keyring) -> None:
        """`path=None` keeps the lines in memory, for tests and in-memory development runs only."""
        self.path = path
        self._keyring = keyring
        self._fd: int | None = None
        self._pid = 0
        self._read = _Read()  # how far this worker has read the file
        self._size = -1  # the file size `_tail` and the fields below describe
        self._tail: dict[str, Any] | None = None
        # What `tail` found after the last line: the bytes to write first, and the damage to declare.
        self._prefix = b""
        self._damage: dict[str, Any] | None = None
        self._open: dict[str, int] | None = None  # offset and length of what `tail` found unclosed
        self._memory: list[bytes] = []
        self._memory_lock = threading.Lock()
        self._clock_read = _Read()  # where `clock` got to, apart from the writer's place
        self._clock_size = -1
        self._clock_lock = threading.Lock()  # held only while `clock` reads, and around no other lock

    def _tag(self, line: dict[str, Any]) -> str:
        return self._keyring.mac("audit-anchor", _canonical({k: v for k, v in line.items() if k != "tag"}))

    def _line(
        self,
        seq: int,
        mac: str,
        when: int,
        prev: str,
        damage: dict[str, Any] | None = None,
        clock: list[Any] | None = None,
    ) -> dict[str, Any]:
        line: dict[str, Any] = {"seq": seq, "mac": mac, "time": when, "prev": prev}
        if damage is not None:
            line["damage"] = damage
        if clock is not None:
            line["clock"] = clock
        line["tag"] = self._tag(line)
        return line

    def present(self) -> bool:
        """True when the anchor holds at least its genesis line."""
        if self.path is None:
            return bool(self._memory)
        try:
            return self.path.stat().st_size > 0
        except OSError:
            return False

    def create(self, when: int) -> None:
        """Start a new anchor with its genesis line. Several workers may race: exactly one file results."""
        data = (_canonical(self._line(0, GENESIS, when, GENESIS)) + "\n").encode()
        if self.path is None:
            with self._memory_lock:
                if not self._memory:
                    self._memory.append(data)
            return
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.{secrets.token_hex(4)}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, self.path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    def _handle(self) -> int:
        """The append handle. The file is never created here, and a removed or replaced file is noticed."""
        assert self.path is not None
        try:
            current = os.stat(self.path)
            if self._fd is not None and self._pid == os.getpid():
                held = os.fstat(self._fd)
                if (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino):
                    return self._fd
                os.close(self._fd)
            self._fd, self._pid = os.open(self.path, os.O_WRONLY | os.O_APPEND), os.getpid()
            self._read, self._size = _Read(), -1  # another file: read it from its start
        except FileNotFoundError as exc:
            self._fd = None
            raise AuditError("the anchor file is missing; restore it before anything is logged") from exc
        return self._fd

    def close(self) -> None:
        """Close the append handle; the next write opens it again and reads the file from its start."""
        if self._fd is not None and self._pid == os.getpid():
            os.close(self._fd)
        self._fd = None

    @contextmanager
    def locked(self) -> Iterator[None]:
        if self.path is None:
            with self._memory_lock:
                yield
            return
        fd = self._handle()
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)

    def size(self) -> int:
        """The length of the file now. Call with the lock held to know what `lines(upto=...)` may read."""
        if self.path is None:
            return sum(len(line) for line in self._memory)
        return os.fstat(self._handle()).st_size

    @contextmanager
    def _reader(self) -> Iterator[Any]:
        if self.path is None:
            yield io.BytesIO(b"".join(self._memory))
            return
        try:
            handle = open(self.path, "rb")  # noqa: SIM115 - closed below, after the caller is done
        except FileNotFoundError as exc:
            raise AuditError("the anchor file is missing") from exc
        with handle:
            yield handle

    def _valid(self, raw: bytes) -> dict[str, Any] | None:
        """The line `raw` (without its newline) holds, or None when it is not a line cunho wrote. Whatever cannot
        be parsed or tagged (a lone surrogate, which cannot be encoded for the MAC; nesting deep enough to exhaust
        the stack) is not a line either: every reading of the time reads the anchor (the second reviewer,
        CX-22)."""
        try:
            line = json.loads(raw)
            valid = (
                isinstance(line, dict)
                and isinstance(line.get("seq"), int)
                and not isinstance(line.get("seq"), bool)
                and isinstance(line.get("mac"), str)
                and isinstance(line.get("prev"), str)
                and same(self._tag(line), str(line.get("tag", "")))
            )
        except (ValueError, UnicodeError, TypeError, RecursionError):
            return None
        return dict(line) if valid else None

    def _scan(
        self, handle: Any, at: _Read, size: int, repaired: list[dict[str, Any]] | None = None
    ) -> Iterator[dict[str, Any]]:
        """Read forwards from `at.end` up to `size` bytes, yield every complete line after checking it, and
        move `at` past it. What follows the last complete line is left in `at` for `tail`.

        A piece is a line only when it starts a line, so bytes a newline does not close are read in pieces of
        at most LINE_MAX bytes, whatever their length."""
        handle.seek(at.end)
        offset, whole, loose, digest = at.end, True, 0, hashlib.sha256()
        at.trailing = None
        while offset < size:
            raw = handle.readline(min(size - offset, LINE_MAX))
            if not raw:
                raise AuditError("the anchor file got shorter while it was read")
            complete = raw.endswith(b"\n")
            line = self._valid(raw[:-1] if complete else raw) if whole else None
            if line is not None:
                self._follows(line, at.last, offset, loose, digest)
                if isinstance(line.get("clock"), list):
                    # Also from a line complete apart from its newline: it is authenticated, and the next write
                    # closes it rather than declaring it damage (the second reviewer, CX-19).
                    at.clock = line["clock"]
                    if line["clock"] and isinstance(line["clock"][0], str):
                        at.clocks[line["clock"][0]] = line["clock"]
                if complete:
                    if loose and repaired is not None:
                        repaired.append(line["damage"])
                    at.end, at.last = offset + len(raw), line
                    offset, loose, digest = at.end, 0, hashlib.sha256()
                    yield line
                    continue
                at.trailing = line  # complete apart from its newline, so at the very end
            loose += len(raw)
            digest.update(raw)
            offset, whole = offset + len(raw), complete
        at.loose, at.digest = loose, digest

    @staticmethod
    def _follows(line: dict[str, Any], last: dict[str, Any] | None, offset: int, loose: int, digest: Any) -> None:
        """Refuse a line that does not follow `last` in one unbroken chain from the genesis line, or that does
        not declare exactly the `loose` bytes before it."""
        if last is not None and line["seq"] <= last["seq"]:
            raise AuditError(
                f"the anchor line at offset {offset} repeats or goes back (sequence {line['seq']} after "
                f"{last['seq']}): cunho never writes such a line, so it was copied there; logging stops until an "
                "operator removes it (see DESIGN.md section 7)"
            )
        if line["prev"] != (last["tag"] if last else GENESIS):
            raise AuditError("anchor lines were removed or reordered")
        if last is None and (line["seq"] != 0 or line["mac"] != GENESIS):
            raise AuditError("the anchor file does not start with its genesis line")
        if last is not None and line["seq"] != last["seq"] + 1:
            raise AuditError(f"the anchor sequence jumps from {last['seq']} to {line['seq']}")
        expected = {"at": offset - loose, "bytes": loose, "sha256": digest.hexdigest()} if loose else None
        if line.get("damage") != expected:
            raise AuditError(f"the anchor file holds bytes at offset {offset - loose} that no anchor line declares")

    def damaged(self) -> dict[str, int] | None:
        """What the last `tail` found after the last valid line and no write has closed yet: its offset and
        length (0 for a line complete apart from its newline). Call with the lock held."""
        return dict(self._open) if self._open is not None else None

    def tail(self) -> dict[str, Any] | None:
        """The last line, after reading forwards what was appended since this worker last read the file. Call
        with the lock held. Any line that does not follow the one before it is refused (AuditError).

        Whatever follows the last line is set aside for `write` to close and declare. A file that is empty
        gives None; one that holds no valid line at all is not one of cunho's anchors, and that is refused.
        """
        size = self.size()
        if size == self._size:
            return self._tail
        if size == 0:
            return None
        if size < self._read.end:
            security_log.error("the audit anchor is shorter than when this worker last read it; reading it again")
            self._read = _Read()
        self._size, self._prefix, self._damage, self._open = -1, b"", None, None
        at = self._read
        with self._reader() as handle:
            for _ in self._scan(handle, at, size):
                pass
        last = at.trailing or at.last
        if last is None:
            raise AuditError("the anchor file holds no valid anchor line")
        if at.trailing is not None:
            self._prefix, self._open = b"\n", {"at": size, "bytes": 0}
        elif at.loose:
            digest = at.digest.copy()
            digest.update(b"\n")
            self._prefix, self._open = b"\n", {"at": at.end, "bytes": at.loose}
            self._damage = {"at": at.end, "bytes": at.loose + 1, "sha256": digest.hexdigest()}
        self._size, self._tail = size, last
        return last

    def clock(self, boot: str | None = None) -> list[Any] | None:
        """The boot, host-clock reading and time of the newest base a forced run laid, on `boot` when given, from
        the newest line that names one, or None. Lines are appended only, outside the database, so whoever can
        write the database cannot take this back (the second reviewer, CX-17).

        It takes neither the anchor's lock nor any other, and keeps a place of its own in the file, apart from
        the writer's: the clock watch asks at every reading of the time, from inside store transactions, so a
        base put back is refused at once in every worker (CX-18). Lines are only ever appended, so a reader that
        reads only up to the size it saw, and starts again when the file got shorter, sees each line whole or
        not yet. A file it cannot read or whose lines do not check keeps the newest base it found before."""
        with self._clock_lock:
            try:
                size = sum(len(line) for line in self._memory) if self.path is None else self.path.stat().st_size
                if size != self._clock_size:
                    if size < self._clock_read.end:
                        self._clock_read = _Read()
                    with self._reader() as handle:
                        for _ in self._scan(handle, self._clock_read, size):
                            pass
                    self._clock_size = size
            except Exception as exc:  # noqa: BLE001 - the time must not fail with the anchor (CX-22)
                security_log.error("the audit anchor cannot be read for the clock base (%s)", type(exc).__name__)
            return self._clock_read.clock if boot is None else self._clock_read.clocks.get(boot)

    def write(self, marks: list[tuple[Mark, int, list[Any] | None]]) -> dict[str, int] | None:
        """Append one line per mark, chained to the current tail, and flush it to disk. Lock held.

        Damage after the tail is closed with a newline first, and the first line written declares it.
        Returns the offset and length of what was closed, or None when there was nothing to close. Without
        marks nothing is written, and damage waits for the next line.
        """
        last = self.tail()
        if last is None:
            raise AuditError("the anchor file is empty; restore it before anything is logged")
        if not marks:
            return None
        prev, out, damage = last["tag"], [], self._damage
        for mark, when, clock in marks:
            line = self._line(mark.seq, mark.mac, when, prev, damage, clock)
            out.append(_canonical(line) + "\n")
            prev, last, damage = line["tag"], line, None
        data = self._prefix + "".join(out).encode()
        closed = self._open
        if self.path is None:
            self._memory.extend(line.encode() for line in out)
        else:
            fd = self._handle()
            rest = data
            while rest:
                rest = rest[os.write(fd, rest) :]
            os.fsync(fd)
        # Our own lines, under the lock: the next read starts after them.
        end = self._size + len(data)
        if self.path is not None and os.fstat(fd).st_size != end:
            # Bytes landed in the file between the read and this write, by someone who does not take the lock:
            # these lines do not follow the ones this worker read. The worker does not move where it reads on
            # from, so its next write reads what landed, declares it and repairs it, as any other worker would,
            # instead of logging on as if nothing happened while verify fails (review 7, L1).
            raise AuditError("the anchor file grew while this worker wrote to it; its next write reads what landed")
        self._read = _Read(end, last)
        self._size, self._tail, self._prefix, self._damage, self._open = end, last, b"", None, None
        if closed is not None and self.path is not None:
            security_log.error(
                "the audit anchor held %d bytes after its last line (a torn or lost write); they were closed and "
                "declared by the next line",
                closed["bytes"],
            )
        return closed if self.path is not None else None

    def lines(self, repaired: list[dict[str, Any]] | None = None, upto: int | None = None) -> Iterator[dict[str, Any]]:
        """Every complete line of the file, or of its first `upto` bytes, read from the start and checked as
        `tail` checks them: tags, one unbroken chain from the genesis line, and every byte between two lines
        declared by the second one. Raises AuditError when the file is missing or fails a check.

        Damage a line declares is skipped, and its declaration goes into `repaired` when a list is given.
        Undeclared bytes at the very end are left alone: they are damage the next write declares, which
        `damaged` reports.
        """
        at = _Read()
        with self._reader() as handle:
            size = upto if upto is not None else handle.seek(0, io.SEEK_END)
            yield from self._scan(handle, at, size, repaired)
        if at.last is None:
            raise AuditError("the anchor file holds no valid anchor line" if size else "the anchor file is empty")


class AuditLog:
    def __init__(
        self,
        store: Store,
        keyring: Keyring,
        clock: Callable[[], float] = time.time,
        *,
        retention: float | None = None,
        anchor: Anchor | None = None,
        create_anchor: bool = False,
    ) -> None:
        """With an anchor, check it is there before anything else (review 3, N3-M2).

        A missing or empty anchor is created only for a log that has never written anything, and only
        when `create_anchor` allows it; over an existing log it is an AuditError, never a fresh start.
        """
        self._store = store
        self._keyring = keyring
        self._clock = clock
        self._retention = retention
        self.anchor = anchor
        self._lock = threading.RLock()
        self._depth = 0
        self._pending: list[tuple[Mark, int, list[Any] | None]] = []
        # The time entries and checks go by: the clock watch's in an Issuer (ClockWatch.now), None while it
        # cannot vouch for the time.
        self.now: Callable[[], float | None] = clock
        if anchor is not None and not anchor.present():
            if self._has_history():
                raise AuditError(
                    "the audit anchor is missing or empty but the audit log has entries: restore the anchor "
                    "from its append-only storage; cunho never starts a new anchor over an existing log"
                )
            if not create_anchor:
                raise AuditError("the audit anchor does not exist; create it once, on a new deployment")
            anchor.create(int(clock()))

    def _has_history(self) -> bool:
        meta = self._store.get("audit-meta", "head") or self._store.get("audit-meta", "checkpoint")
        return meta is not None or bool(self._store.scan("audit", "", 1))

    def _mac(self, body: dict[str, Any]) -> str:
        return self._keyring.mac("audit-entry", _canonical(body))

    def _verifies(self, entry: dict[str, Any]) -> bool:
        """Whether a stored entry carries its right MAC. One that cannot even be put in canonical form (a lone
        surrogate written into the database by hand) does not verify, and is reported as altered rather than
        raising out of verify or maintenance (the second reviewer)."""
        try:
            expected = self._mac({k: v for k, v in entry.items() if k != "mac"})
        except (UnicodeError, ValueError, TypeError, RecursionError):
            return False
        return same(expected, str(entry.get("mac", "")))

    # The head pointer and the pruning checkpoint use different MAC purposes, so one can never be
    # passed off as the other (review 2, N-H1). The checkpoint also binds the time of the pruned entry.

    def _head_tag(self, seq: int, mac: str) -> str:
        return self._keyring.mac("audit-head", f"{seq}:{mac}")

    def _checkpoint_tag(self, seq: int, mac: str, when: int) -> str:
        return self._keyring.mac("audit-checkpoint", f"{seq}:{mac}:{when}")

    def _head(self) -> Mark | None:
        value = self._store.get("audit-meta", "head")
        if value is None:
            return None
        if not _shaped(value, seq=int, mac=str, tag=str) or not same(
            self._head_tag(value["seq"], value["mac"]), value["tag"]
        ):
            raise AuditError("audit head pointer was altered")
        return Mark(value["seq"], value["mac"])

    def _checkpoint(self) -> tuple[Mark, int] | None:
        value = self._store.get("audit-meta", "checkpoint")
        if value is None:
            return None
        if not _shaped(value, seq=int, mac=str, time=int, tag=str) or not same(
            self._checkpoint_tag(value["seq"], value["mac"], value["time"]), value["tag"]
        ):
            raise AuditError("audit checkpoint was altered")
        return Mark(value["seq"], value["mac"]), value["time"]

    # writing ------------------------------------------------------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One store transaction for the enclosed writes and the audit entries they log.

        Use it when an action and its log entry must stand or fall together. Lock order is always this
        log's lock, then the anchor file lock, then the store, so workers cannot deadlock.

        The anchor lines are written after the commit. When that write fails (a full disk, a crash), the
        action stands, since it was committed, and the store is ahead of the anchor. The next transaction
        first writes the lines still missing, before it changes anything, and refuses to go on when it
        cannot; so at most one committed transaction is ever missing from the anchor (review 4, N4-M4). The
        entries are MACed, so only real entries can be caught up.
        """
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            anchor_lock = self.anchor.locked() if self.anchor else _nothing()
            with anchor_lock:
                self._depth, self._pending = 1, []
                try:
                    self._catch_up()
                    with self._store.atomic():
                        yield
                    if self.anchor is not None:
                        self._anchor_committed()
                finally:
                    self._depth, self._pending = 0, []

    def repair(self) -> None:
        """Anchor what a crash left out and close a damaged anchor now, without waiting for the next logged
        action. The background task calls it about once a minute, so `verify` reports damage for about that
        long at most. Raises AuditError as a logged action would."""
        if self.anchor is None:
            return
        with self.transaction():
            pass

    def _anchor_committed(self) -> None:
        """Anchor the entries of a committed transaction. A failure cannot undo the action, so it is logged."""
        assert self.anchor is not None
        try:
            self.anchor.write(self._pending)
        except (OSError, AuditError) as exc:
            security_log.error(
                "the audit anchor could not be written after a commit (%s); the action stands, and the next "
                "write anchors it first",
                exc,
            )

    def _catch_up(self) -> None:
        """Compare the anchor with the store before writing: refuse to extend a store that fell behind, write
        the lines of entries that were committed but never anchored, and close damage after the last line.

        A repair is logged as `audit.anchor_repaired` in a transaction of its own, before the action's, so an
        action refused inside its transaction cannot take the record of the repair with it (review 5, N5-L1).
        When no committed entry was missing, that entry's own line is the one that declares the damage.
        """
        anchor = self.anchor
        if anchor is None:
            return
        backlog = self._unanchored(anchor)
        try:
            damage = anchor.write(backlog) or anchor.damaged()
            if damage is None:
                return
            with self._store.atomic():
                self._append("audit.anchor_repaired", "cunho", {"torn_bytes": damage["bytes"], "at": damage["at"]})
            anchor.write(self._pending)
        except OSError as exc:
            raise AuditError(f"the audit anchor cannot be written: {exc.strerror or exc}") from exc
        finally:
            self._pending = []

    def _unanchored(self, anchor: Anchor) -> list[tuple[Mark, int, list[Any] | None]]:
        """The entries committed but not anchored yet (a crash after the commit), once the anchor's last line
        and the store are found to agree. Raises AuditError when they do not. Writers and `verify` both ask
        this, so verify fails whenever cunho refuses to log (review 6, N6-H1)."""
        try:
            return self._unanchored_checked(anchor)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise AuditError("the audit store holds a malformed record") from exc  # review 3, N3-L1

    def _unanchored_checked(self, anchor: Anchor) -> list[tuple[Mark, int, list[Any] | None]]:
        head = self._head() or Mark(0, GENESIS)
        tail = anchor.tail()
        if tail is None:
            raise AuditError("the anchor file is empty; restore it before anything is logged")
        anchored = Mark(int(tail["seq"]), str(tail["mac"]))
        if anchored.seq > head.seq:
            raise AuditError(
                f"the store (head {head.seq}) is behind the anchor (sequence {anchored.seq}): entries were removed"
            )
        if anchored.seq == head.seq:
            if anchored != head:
                raise AuditError("the audit store diverges from its anchor (head)")
            return []
        # The store is ahead: entries were committed but not anchored (a crash after the commit). Pruning
        # never passes the anchor, so the anchored entry is still there, or is the checkpoint.
        checkpoint = self._checkpoint()
        if checkpoint is not None and checkpoint[0].seq > anchored.seq:
            raise AuditError("entries were pruned before they were anchored")
        if checkpoint is not None and checkpoint[0].seq == anchored.seq:
            if checkpoint[0] != anchored:
                raise AuditError("the audit store diverges from its anchor (checkpoint)")
        elif anchored.seq > 0:
            entry = self._store.get("audit", _key(anchored.seq))
            if not isinstance(entry, dict) or entry.get("mac") != anchored.mac:
                raise AuditError("the audit store diverges from its anchor (anchored entry)")
        previous, backlog = anchored, []
        for _, entry in self._entries(after=anchored.seq, upto=head.seq):
            if entry.get("seq") != previous.seq + 1 or entry.get("prev") != previous.mac:
                raise AuditError("the audit store diverges from its anchor (broken link)")
            if not self._verifies(entry):
                raise AuditError(f"entry {entry.get('seq')} was altered")
            previous = Mark(int(entry["seq"]), str(entry["mac"]))
            backlog.append((previous, int(entry["time"]), _clock_of(entry)))
        if previous != head:
            raise AuditError("the audit store diverges from its anchor (head)")
        return backlog

    def clock_floor(self, boot: str | None = None) -> tuple[str, float, float] | None:
        """The boot, host-clock reading and time of the newest base a forced run laid, on `boot` when given, as the
        anchor names it, or None without an anchor or without such a line. It takes no lock (see Anchor.clock).
        A worker asks for its own boot: with hosts sharing a store, another host's newer forced run must not hide
        this boot's (the second reviewer)."""
        if self.anchor is None:
            return None
        clock = self.anchor.clock(boot)
        if clock is None or len(clock) != 3 or not isinstance(clock[0], str):
            return None
        if not all(isinstance(v, int | float) and not isinstance(v, bool) for v in clock[1:]):
            return None
        return clock[0], float(clock[1]), float(clock[2])

    def append(self, event: str, actor: str, **data: Any) -> dict[str, Any]:
        """Read the head, write the entry and move the head in one store transaction.

        Worker processes that share the store would otherwise read the same head, so one of them
        would fail to write its entry, or a slower one would move the head back over a newer entry.
        """
        try:
            with self.transaction():
                return self._append(event, actor, data)
        except AuditError:
            raise
        except Exception as exc:  # noqa: BLE001 - any storage failure must stop the logged action
            raise AuditError(str(exc)) from exc

    def _append(self, event: str, actor: str, data: dict[str, Any]) -> dict[str, Any]:
        head = self._head() or Mark(0, GENESIS)
        reading, now = int(self._clock()), self.now()
        body: dict[str, Any] = {
            "seq": head.seq + 1,
            "time": reading if now is None else int(now),
            "event": event,
            "actor": actor,
            "data": data,
            "prev": head.mac,
        }
        if now is not None and abs(reading - now) > CLOCK_TOLERANCE:
            # A reading far from the time the clock watch gives: the entry gets that time, and keeps the reading,
            # so one wrong reading neither blocks pruning for good nor gets an entry pruned early (review 5,
            # N5-L8).
            body["clock"] = reading
        entry: dict[str, Any] = {**body, "mac": self._mac(body)}
        if not self._store.add("audit", _key(entry["seq"]), entry, None):
            raise AuditError(f"audit sequence {entry['seq']} already written")
        self._store.put(
            "audit-meta",
            "head",
            {"seq": entry["seq"], "mac": entry["mac"], "tag": self._head_tag(entry["seq"], entry["mac"])},
            None,
        )
        self._pending.append((Mark(entry["seq"], entry["mac"]), entry["time"], _clock_of(entry)))
        return entry

    # reading ------------------------------------------------------------------------------------------

    def _entries(self, after: int = 0, upto: int | None = None) -> Iterator[tuple[str, dict[str, Any]]]:
        """Stream entries in pages, never the whole log at once."""
        cursor = _key(after) if after else ""
        while True:
            page = self._store.scan("audit", cursor, PAGE)
            for key, entry in page:
                if upto is not None and int(entry.get("seq", 0)) > upto:
                    return
                yield key, entry
            if len(page) < PAGE:
                return
            cursor = page[-1][0]

    def entries(self) -> list[dict[str, Any]]:
        return [entry for _, entry in self._entries()]

    def verify(self, expected: Mark | None = None) -> tuple[bool, str]:
        """Check the chain from the checkpoint to the head, against every anchor line and an optional known head.

        Any record that cannot be read is a failed verification, never an exception (review 3, N3-L1).
        """
        for _ in range(VERIFY_TRIES):
            try:
                result = self._verify(expected)
            except AuditError as exc:
                return False, str(exc)
            except Exception:  # noqa: BLE001 - a malformed row written by someone else must not become a 500
                return False, "the audit log holds a malformed record"
            if result is not None:
                return result
        return False, "the log kept changing under verification; try again"

    def _verify(self, expected: Mark | None) -> tuple[bool, str] | None:
        # The checkpoint, the head and the anchor are read together, under the locks every writer holds, so they
        # describe one moment; the anchor is then read up to the size it had at that moment. Entries and anchor
        # lines added while the rest is read come after that moment and are not looked at: without this, an
        # entry appended between reading the head and reading the anchor looked like an entry that had been
        # removed (review 4, N4-M7). Under the same locks the anchor's last line is checked against the store
        # exactly as a writer checks it before it logs, so verify can never pass while logging is refused, and
        # never while an entry is not anchored yet (review 6, N6-H1).
        size, damage, backlog = 0, None, []
        with self._lock, self.anchor.locked() if self.anchor else _nothing():
            start = self._checkpoint()
            head = self._head()
            if head is None and (start is not None or self._store.scan("audit", "", 1)):
                return False, "the head pointer is missing"
            if self.anchor is not None:
                backlog = self._unanchored(self.anchor)
                size, damage = self.anchor.size(), self.anchor.damaged()
        if damage is not None:
            # A damaged anchor is never reported valid, even though nothing was lost yet (review 5, N5-M1).
            return False, (
                f"the anchor file ends in {damage['bytes']} bytes after its last line, at offset {damage['at']} "
                "(a torn or lost write); the next logged action, or maintenance within a minute, repairs it"
            )
        if backlog:
            return False, (
                f"the {len(backlog)} newest entries are not anchored yet (a write stopped after its commit); the "
                "next logged action, or maintenance within a minute, anchors them"
            )
        if start is not None and self._retention is not None:
            if start[1] > self._time() - self._retention:
                return False, "the checkpoint drops entries younger than the retention period"
        first = start[0] if start else Mark(0, GENESIS)
        repaired: list[dict[str, Any]] = []
        lines = self.anchor.lines(repaired, upto=size) if self.anchor else iter(())
        line: dict[str, Any] | None = next(lines, None)
        count = 1 if line is not None else 0

        def advance_to(seq: int, mark: Mark) -> str | None:
            """Move through the anchor up to `seq`; a line at `seq` must name `mark` (review 3, N3-M2)."""
            nonlocal line, count
            while line is not None and line["seq"] <= seq:
                if line["seq"] == seq and line["mac"] != mark.mac:
                    return f"the store diverges from the anchor at sequence {seq}"
                line = next(lines, None)
                count += line is not None
            return None

        while line is not None and line["seq"] < first.seq:  # pruned from the store; the anchor chain still checks
            line = next(lines, None)
            count += line is not None
        problem = advance_to(first.seq, first)
        if problem:
            return False, problem
        previous = first
        upto = head.seq if head else 0
        signed_seen = expected is None or expected.seq < first.seq
        if expected is not None and expected.seq == first.seq:
            if expected.mac != first.mac:
                return False, f"the store diverges from the signed head at sequence {expected.seq}"
            signed_seen = True
        entries = self._entries(after=first.seq, upto=upto)
        checked, hopped = 0, False
        while True:
            item = next(entries, None)
            if item is None or item[1].get("seq") != previous.seq + 1:
                # A gap, or the end before the head: pruning may have moved past us while we read, in this
                # worker or another. Then go on from the new checkpoint, which is MACed like an entry and
                # must match its anchor line, instead of reporting a gap (review 5, N5-L2).
                if item is None and previous.seq == upto:
                    break
                moved = self._checkpoint()
                if moved is None or moved[0].seq <= previous.seq:
                    if item is None:
                        break
                    return False, f"gap or reorder at sequence {previous.seq + 1}"
                if moved[0].seq > upto:
                    return None  # everything we were reading was pruned; start again
                if self._retention is not None and moved[1] > self._time() - self._retention:
                    return False, "the checkpoint drops entries younger than the retention period"
                if expected is not None and previous.seq < expected.seq <= moved[0].seq:
                    if expected.seq == moved[0].seq and expected.mac != moved[0].mac:
                        return False, f"the store diverges from the signed head at sequence {expected.seq}"
                    signed_seen = True
                previous, hopped = moved[0], True
                problem = advance_to(previous.seq, previous)
                if problem:
                    return False, problem
                entries = self._entries(after=previous.seq, upto=upto)
                continue
            entry = item[1]
            if entry.get("prev") != previous.mac or not self._verifies(entry):
                return False, f"entry {entry.get('seq')} was altered"
            previous, checked = Mark(int(entry["seq"]), str(entry["mac"])), checked + 1
            problem = advance_to(previous.seq, previous)
            if problem:
                return False, problem
            if expected is not None and previous.seq == expected.seq:
                if expected.mac != previous.mac:
                    return False, f"the store diverges from the signed head at sequence {expected.seq}"
                signed_seen = True
        if head is not None and head != previous:
            return False, "entries after the last one were removed"
        if not signed_seen:
            assert expected is not None
            return (
                False,
                f"the store (head {previous.seq}) is behind the signed head ({expected.seq}): entries were removed",
            )
        detail = f"{checked} entries verified" + ("; pruning went on meanwhile" if hopped else "")
        if self.anchor is None:
            return True, detail + "; no anchor configured, so removal of the newest entries is not detectable"
        detail += f"; {count} anchor lines"
        if repaired:
            size = sum(int(r["bytes"]) - 1 for r in repaired)
            detail += f"; {len(repaired)} damaged stretch(es) of the anchor ({size} bytes) were closed and declared"
        return True, detail

    def head(self) -> Mark:
        return self._head() or Mark(0, GENESIS)

    def _time(self) -> float:
        """The clock watch's time, or the wall clock while it cannot vouch: for an entry or a check, never for
        pruning, which waits instead."""
        now = self.now()
        return self._clock() if now is None else now

    def signed_head(self, signer: Signer, issuer: str) -> str:
        """A signed statement of the newest entry, for the operator to pull and keep outside cunho.

        `signer` is the audit head key, used for nothing else (review 3, N3-L7).
        """
        head = self.head()
        return sign_jws(
            signer,
            {"typ": "cunho-audit-head+jwt", "jwk": signer.public_jwk()},
            {"iss": issuer, "iat": int(self._time()), "seq": head.seq, "mac": head.mac},
        )

    def prune_before(
        self, cutoff: float, batch: int = PAGE, *, now: float | None = None, still: Callable[[], bool] | None = None
    ) -> int:
        """Drop entries older than `cutoff` in short batches, each behind a MACed checkpoint. `now` is the time
        pruning runs at, the clock watch's when not given; `still`, when given, says whether pruning may go on.

        Both are checked again inside every batch's transaction. A forced run in another worker may correct the
        time back meanwhile: the batch goes by the earlier of `now` and the time read inside it, with the cutoff
        moved back as far, so an entry logged by the corrected time is never pruned by the old one; and pruning
        stops once `still` says no, as the clock watch does for an interval after a base is laid again (the
        second reviewer, CX-16).

        Every batch is its own short transaction and reads at most `batch` entries, so pruning a large log holds
        the write lock only briefly and never loads the log into memory (review 2, N-M7). Pruning never passes
        the last anchored entry, and it removes only entries that verify, in their chain from the checkpoint:
        each one MACed, the first one following the checkpoint and each later one the entry before it. An
        entry's age is its own time, which is under its MAC, so whoever can write the database cannot make an
        entry look old, nor remove entries from the front and have pruning tidy up after them: pruning stops at
        the first entry that does not verify, with an alert, and verify reports it (review 3, N3-L1; the second
        reviewer's CX-1).
        """
        removed, now = 0, self._time() if now is None else now
        while True:
            anchor_lock = self.anchor.locked() if self.anchor else _nothing()
            with self._lock, anchor_lock, self._store.atomic():
                at = min(now, self._time())
                if still is not None and not still():
                    return removed
                before = cutoff - (now - at)
                # Never past the anchor: an entry committed but not yet anchored must stay until the next
                # write anchors it, or the anchor could never be caught up without a gap.
                tail = self.anchor.tail() if self.anchor else None
                limit = int(tail["seq"]) if tail is not None else None
                checkpoint = self._checkpoint()
                previous = checkpoint[0] if checkpoint is not None else Mark(0, GENESIS)
                old: list[tuple[str, dict[str, Any]]] = []
                ahead: list[tuple[str, dict[str, Any]]] = []
                broken: str | None = None
                for key, entry in self._store.scan("audit", "", batch):
                    if limit is not None and _shaped(entry, seq=int) and entry["seq"] > limit:
                        break
                    if not self._follows(entry, previous):
                        broken = key
                        break
                    previous = Mark(entry["seq"], entry["mac"])
                    if entry["time"] > at + FUTURE_SLACK:
                        # Dated after the moment pruning runs: logged while the clock watch could not vouch for a
                        # clock that read far ahead. It does not hold back the entries after it, and goes with the
                        # first older one that follows, since the chain orders them (review 5, N5-L8).
                        ahead.append((key, entry))
                        continue
                    if entry["time"] >= before:
                        break
                    old += [*ahead, (key, entry)]
                    ahead = []
                if old:
                    key, last = old[-1]
                    when = last["time"]
                    self._store.put(
                        "audit-meta",
                        "checkpoint",
                        {
                            "seq": last["seq"],
                            "mac": last["mac"],
                            "time": when,
                            "tag": self._checkpoint_tag(last["seq"], last["mac"], when),
                        },
                        None,
                    )
                    removed += self._store.delete_through("audit", key)
            if broken is not None:
                security_log.error(
                    "audit pruning stopped at entry %s, which does not verify in its chain; run /admin/audit/verify",
                    _label(broken),
                )
                return removed
            if len(old) < batch:
                return removed

    def _follows(self, entry: Any, previous: Mark) -> bool:
        """Whether `entry` is a well-formed entry, MACed, and the one right after `previous` in the chain."""
        if not _shaped(entry, seq=int, mac=str, time=int, prev=str):
            return False
        # The MAC binds `prev`, and cunho writes each entry after the one whose MAC it names, so an entry that
        # verifies and names `previous` is the one after it: its sequence needs no check of its own.
        return entry["prev"] == previous.mac and self._verifies(entry)


def _label(key: str) -> str:
    """An audit key as an alert names it: its sequence number, or a damaged key quoted and cut short. Nothing here
    parses the key, so no key a database writer chose can raise (the second reviewer)."""
    if len(key) == len(_key(0)) and key.isascii() and key.isdecimal():
        return key.lstrip("0") or "0"
    return repr(key[:40]) + ("..." if len(key) > 40 else "")


def _shaped(value: Any, **fields: type) -> bool:
    """A dict whose named members have the given types (a bool is never taken for an int)."""
    if not isinstance(value, dict):
        return False
    return all(
        isinstance(value.get(name), kind) and not isinstance(value.get(name), bool) for name, kind in fields.items()
    )


@contextmanager
def _nothing() -> Iterator[None]:
    yield


class Vault:
    """Personal data, encrypted with one AES-256-GCM key per subject, the key wrapped by the keyring."""

    def __init__(self, store: Store, keyring: Keyring) -> None:
        self._store = store
        self._kek = AESGCM(keyring.derive("vault-kek"))

    @staticmethod
    def _aad(subject_ref: str, binding: str) -> bytes:
        """The ciphertext names its subject and the offer it was created for (review 3, N3-M5)."""
        return f"{subject_ref}|{binding}".encode()

    def put(self, subject_ref: str, data: dict[str, Any], ttl: float | None, binding: str) -> None:
        key = AESGCM.generate_key(bit_length=256)
        nonce, wrap_nonce = os.urandom(12), os.urandom(12)
        aad = self._aad(subject_ref, binding)
        sealed = AESGCM(key).encrypt(nonce, json.dumps(data, ensure_ascii=False).encode(), aad)
        self._store.put("vault-key", subject_ref, b64u(wrap_nonce + self._kek.encrypt(wrap_nonce, key, aad)), ttl)
        self._store.put("vault", subject_ref, b64u(nonce + sealed), ttl)

    def get(self, subject_ref: str, binding: str) -> dict[str, Any] | None:
        """The subject's data, or None when it is gone or does not open under this subject and offer."""
        wrapped, sealed = self._store.get("vault-key", subject_ref), self._store.get("vault", subject_ref)
        if wrapped is None or sealed is None:
            return None  # erased or expired: not worth an alert
        aad = self._aad(subject_ref, binding)
        try:
            raw_key, raw = b64u_decode(wrapped), b64u_decode(sealed)
            key = self._kek.decrypt(raw_key[:12], raw_key[12:], aad)
            data = json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], aad))
        except (InvalidTag, ValueError):
            security_log.warning("a vault entry did not open for its subject and offer")
            return None
        return data if isinstance(data, dict) else None

    def erase(self, subject_ref: str) -> None:
        self._store.delete("vault-key", subject_ref)
        self._store.delete("vault", subject_ref)

    def data_held(self, subject_ref: str) -> bool:
        """Whether the subject's data is still stored, expired or not: a store keeps an expired row until its sweep,
        and the data with it (the security review: an erasure that removed such a row logged that none was held)."""
        return self._store.peek("vault-key", subject_ref) is not None

    def keep_reply(self, subject_ref: str, slot: str, reply: dict[str, Any], ttl: float) -> None:
        """A credential response, sealed until `ttl`, so a request repeated under the same access token gets
        the same credentials and no new one is made (OpenID4VCI 1.0 §8.3 with ARF ISSU_35)."""
        nonce = os.urandom(12)
        aad = self._aad(subject_ref, slot)
        sealed = self._kek.encrypt(nonce, json.dumps(reply, ensure_ascii=False).encode(), aad)
        self._store.put("vault-reply", f"{subject_ref}:{slot}", b64u(nonce + sealed), ttl)

    def reply(self, subject_ref: str, slot: str) -> dict[str, Any] | None:
        sealed = self._store.get("vault-reply", f"{subject_ref}:{slot}")
        if sealed is None:
            return None
        try:
            raw = b64u_decode(sealed)
            reply = json.loads(self._kek.decrypt(raw[:12], raw[12:], self._aad(subject_ref, slot)))
        except (InvalidTag, ValueError):
            security_log.warning("a kept reply did not open for its subject and slot")
            return None
        return reply if isinstance(reply, dict) else None

    def replies_held(self, subject_ref: str) -> bool:
        """Whether a reply of the subject's is still stored, expired or not: a store may keep an expired row until
        its sweep, and that row still opens under the keyring (the second reviewer)."""
        return bool(self._store.items("vault-reply", f"{subject_ref}:", at=0))

    def drop_reply(self, subject_ref: str, slot: str) -> None:
        self._store.delete("vault-reply", f"{subject_ref}:{slot}")

    def drop_replies(self, subject_ref: str) -> None:
        for key, _ in self._store.items("vault-reply", f"{subject_ref}:", at=0):  # expired rows too
            self._store.delete("vault-reply", key)
