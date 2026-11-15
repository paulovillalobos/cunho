"""State with expiry and atomic single-use operations.

Everything that must be used once (pre-authorized codes, nonces, DPoP jti values) goes through
`take` or `add`, which are atomic in both backends, so concurrent requests cannot both succeed.
A read-check-write sequence that spans several calls (the audit chain head, a status-list bit) runs
inside `atomic()`, which in SQLite is one `BEGIN IMMEDIATE` transaction, so it also holds when
several worker processes share one database file. Reads never return an expired entry. Expired rows are
deleted by `sweep`, which the background task calls about once a minute, never inside a request (review
3, N3-L2), so state stays bounded and personal data does not outlive its time to live by much.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any, Protocol

from cunho.errors import ConfigError

Clock = Callable[[], float]
BUSY_TIMEOUT = 30.0
CHECKPOINT_WAIT_MS = 1000  # how long a checkpoint waits for readers, holding this worker's store lock


class Store(Protocol):
    def put(self, ns: str, key: str, value: Any, ttl: float | None) -> None: ...

    def get(self, ns: str, key: str) -> Any | None: ...

    def peek(self, ns: str, key: str) -> Any | None:
        """The value as stored, whatever its expiry, without reading the clock: for the clock watch, whose time
        the expiries themselves go by."""
        ...

    def take(self, ns: str, key: str) -> Any | None:
        """Return and delete in one step."""
        ...

    def add(self, ns: str, key: str, value: Any, ttl: float | None) -> bool:
        """Insert only if absent; False when the key already exists."""
        ...

    def incr(self, ns: str, key: str, ttl: float | None) -> int: ...

    def delete(self, ns: str, key: str) -> None: ...

    def items(self, ns: str, prefix: str = "", *, at: float | None = None) -> list[tuple[str, Any]]:
        """Every entry whose key starts with `prefix`, in key order, that is live at `at` (now when None)."""
        ...

    def scan(self, ns: str, after: str = "", limit: int = 500, until: str | None = None) -> list[tuple[str, Any]]:
        """Up to `limit` live entries whose key sorts after `after`, and at or before `until` when given, in key
        order (bounded memory)."""
        ...

    def delete_through(self, ns: str, last: str) -> int:
        """Delete every entry whose key sorts at or before `last`; returns how many were removed."""
        ...

    def sweep(self, now: float) -> int:
        """Delete every entry expired by `now`, and by the store's own time read inside the transaction, whichever
        is earlier; returns how many were removed. A time corrected back after `now` was read (a forced run in
        another worker) deletes nothing stamped by the corrected one (the second reviewer, CX-15)."""
        ...

    def checkpoint(self) -> bool:
        """Clear copies of deleted rows that a write-ahead log may still hold. False when it could not."""
        ...

    def empty(self) -> bool:
        """True when the store holds no row at all, expired or not."""
        ...

    def atomic(self) -> AbstractContextManager[None]:
        """Run the enclosed calls as one unit: no other thread or process writes in between, and an exception
        undoes every write made inside."""
        ...

    def go_by(self, clock: Clock) -> None:
        """Stamp and read expiries by `clock` from now on: the Issuer's time (Issuer.time)."""
        ...

    def on_rollback(self, undo: Callable[[], None]) -> None:
        """Call `undo` when the transaction open now rolls back, before its lock is released, so no one sees the
        store undone while what was kept in memory beside it is not (the second reviewer, CX-30)."""
        ...


def _prefix_end(prefix: str) -> str | None:
    """The smallest string greater than every string that starts with `prefix`, or None if unbounded."""
    for position in range(len(prefix) - 1, -1, -1):
        if ord(prefix[position]) < 0x10FFFF:
            return prefix[:position] + chr(ord(prefix[position]) + 1)
    return None


class MemoryStore:
    def __init__(self, clock: Clock = time.time) -> None:
        self._clock = clock
        self._data: dict[tuple[str, str], tuple[Any, float | None]] = {}
        self._lock = threading.RLock()
        self._depth = 0
        # Inside atomic(): the entries as they were before the unit changed them, so an exception can undo
        # it as a SQLite rollback would. Without it the memory store kept half of a failed unit, and tests
        # on it could not show that an action and its log entry fall together (review 4, N4-L4).
        self._journal: dict[tuple[str, str], tuple[Any, float | None] | None] | None = None
        self._undo: list[Callable[[], None]] = []  # what `on_rollback` asked for, in the open transaction

    def go_by(self, clock: Clock) -> None:
        self._clock = clock

    def _keep(self, key: tuple[str, str]) -> None:
        if self._journal is not None and key not in self._journal:
            self._journal[key] = self._data.get(key)

    def _live(self, ns: str, key: str, *, purge: bool = False) -> tuple[Any, float | None] | None:
        """The entry unless it expired. A read leaves an expired entry in place for sweep, as SQLite's do, so peek
        and items at an earlier time still find it; take, add and incr purge it first, as SQLite's _purge does."""
        entry = self._data.get((ns, key))
        if entry is not None and entry[1] is not None and entry[1] <= self._clock():
            if purge:
                self._keep((ns, key))
                del self._data[(ns, key)]
            return None
        return entry

    def _expiry(self, ttl: float | None) -> float | None:
        return None if ttl is None else self._clock() + ttl

    def sweep(self, now: float) -> int:
        with self._lock:
            cutoff = min(now, self._clock())
            expired = [k for k, (_, exp) in self._data.items() if exp is not None and exp <= cutoff]
            for key in expired:
                self._keep(key)
                del self._data[key]
            return len(expired)

    def checkpoint(self) -> bool:
        return True

    def empty(self) -> bool:
        with self._lock:
            return not self._data

    @contextmanager
    def atomic(self) -> Iterator[None]:
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self._depth, self._journal, self._undo = 1, {}, []
            try:
                yield
            except BaseException:
                for key, entry in self._journal.items():
                    if entry is None:
                        self._data.pop(key, None)
                    else:
                        self._data[key] = entry
                for undo in reversed(self._undo):
                    undo()
                raise
            finally:
                self._depth, self._journal, self._undo = 0, None, []

    def on_rollback(self, undo: Callable[[], None]) -> None:
        if self._depth:
            self._undo.append(undo)

    def put(self, ns: str, key: str, value: Any, ttl: float | None) -> None:
        with self._lock:
            self._keep((ns, key))
            self._data[(ns, key)] = (json.loads(json.dumps(value)), self._expiry(ttl))

    def get(self, ns: str, key: str) -> Any | None:
        with self._lock:
            entry = self._live(ns, key)
            return None if entry is None else json.loads(json.dumps(entry[0]))

    def peek(self, ns: str, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get((ns, key))
            return None if entry is None else json.loads(json.dumps(entry[0]))

    def take(self, ns: str, key: str) -> Any | None:
        with self._lock:
            entry = self._live(ns, key, purge=True)
            if entry is None:
                return None
            self._keep((ns, key))
            del self._data[(ns, key)]
            return entry[0]

    def add(self, ns: str, key: str, value: Any, ttl: float | None) -> bool:
        with self._lock:
            if self._live(ns, key, purge=True) is not None:
                return False
            self._keep((ns, key))
            self._data[(ns, key)] = (json.loads(json.dumps(value)), self._expiry(ttl))
            return True

    def incr(self, ns: str, key: str, ttl: float | None) -> int:
        with self._lock:
            entry = self._live(ns, key, purge=True)
            value = (int(entry[0]) if entry else 0) + 1
            self._keep((ns, key))
            self._data[(ns, key)] = (value, entry[1] if entry else self._expiry(ttl))
            return value

    def delete(self, ns: str, key: str) -> None:
        with self._lock:
            self._keep((ns, key))
            self._data.pop((ns, key), None)

    def items(self, ns: str, prefix: str = "", *, at: float | None = None) -> list[tuple[str, Any]]:
        with self._lock:
            keys = sorted(k for (n, k) in self._data if n == ns and k.startswith(prefix))
            if at is None:
                return [(k, entry[0]) for k in keys if (entry := self._live(ns, k)) is not None]
            entries = [(k, self._data[(ns, k)]) for k in keys]
            return [(k, value) for k, (value, expires) in entries if expires is None or expires > at]

    def scan(self, ns: str, after: str = "", limit: int = 500, until: str | None = None) -> list[tuple[str, Any]]:
        with self._lock:
            keys = sorted(k for (n, k) in self._data if n == ns and k > after and (until is None or k <= until))
            out: list[tuple[str, Any]] = []
            for key in keys:
                entry = self._live(ns, key)
                if entry is not None:
                    out.append((key, json.loads(json.dumps(entry[0]))))
                    if len(out) >= limit:
                        break
            return out

    def delete_through(self, ns: str, last: str) -> int:
        with self._lock:
            doomed = [k for k in self._data if k[0] == ns and k[1] <= last]
            for key in doomed:
                self._keep(key)
                del self._data[key]
            return len(doomed)

    def __len__(self) -> int:
        return len(self._data)


class SqliteStore:
    """Single-host persistent store. For several hosts, PostgresStore."""

    def __init__(self, path: Path, clock: Clock = time.time) -> None:
        self.path = path
        self._clock = clock
        self._lock = threading.RLock()
        self._depth = 0
        self._undo: list[Callable[[], None]] = []  # what `on_rollback` asked for, in the open transaction
        # Several worker processes may share the file: every write waits up to BUSY_TIMEOUT for the lock.
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=BUSY_TIMEOUT)
        self._wal()
        # Deleted rows (personal data, vault keys) are overwritten, not left in free pages.
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS kv (ns TEXT, key TEXT, value TEXT, expires REAL, PRIMARY KEY (ns, key))"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS kv_expires ON kv (expires) WHERE expires IS NOT NULL")

    def go_by(self, clock: Clock) -> None:
        self._clock = clock

    def _wal(self) -> None:
        """Switch to WAL once. Workers that start together on a new file may find it locked: retry with backoff.

        Changing the journal mode needs an exclusive lock that the busy timeout does not wait for, so a
        worker that lost the race used to die with `database is locked` (review 2, N-L5).
        """
        delay = 0.01
        for _ in range(12):
            try:
                if str(self._db.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal":
                    return
                self._db.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc):
                    raise
            time.sleep(delay)
            delay = min(delay * 2, 1.0)
        raise sqlite3.OperationalError("could not switch the store to WAL mode")

    def _expiry(self, ttl: float | None) -> float | None:
        return None if ttl is None else self._clock() + ttl

    @contextmanager
    def atomic(self) -> Iterator[None]:
        """One write transaction, taken up front (BEGIN IMMEDIATE); nested calls join the outer one."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self._db.execute("BEGIN IMMEDIATE")
            self._depth, self._undo = 1, []
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                try:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                finally:
                    for undo in reversed(self._undo):
                        undo()
                raise
            finally:
                self._depth, self._undo = 0, []

    def on_rollback(self, undo: Callable[[], None]) -> None:
        if self._depth:
            self._undo.append(undo)

    def _purge(self, ns: str, key: str) -> None:
        self._db.execute(
            "DELETE FROM kv WHERE ns=? AND key=? AND expires IS NOT NULL AND expires<=?", (ns, key, self._clock())
        )

    def sweep(self, now: float, batch: int = 1000) -> int:
        """Delete rows expired by `now` in short transactions of at most `batch` rows, so writers never wait
        long."""
        removed = 0
        while True:
            with self.atomic():
                cutoff = min(now, self._clock())  # read inside the transaction, as every other expiry (CX-15)
                deleted = self._db.execute(
                    "DELETE FROM kv WHERE rowid IN "
                    "(SELECT rowid FROM kv WHERE expires IS NOT NULL AND expires<=? LIMIT ?)",
                    (cutoff, batch),
                ).rowcount
            removed += deleted
            if deleted < batch:
                return removed

    def checkpoint(self) -> bool:
        """Copy the WAL into the database and truncate it, so erased vault rows leave the WAL file too.

        secure_delete overwrites deleted rows in the database file at once, but the write-ahead log keeps
        the old pages until a checkpoint resets it. A reader in another worker can hold the WAL: the
        checkpoint then waits at most CHECKPOINT_WAIT_MS, not the 30 s every request in this worker would
        wait behind its lock, and returns False, so maintenance tries again (review 4, N4-L1).
        """
        with self._lock:
            self._db.execute(f"PRAGMA busy_timeout={CHECKPOINT_WAIT_MS}")
            try:
                busy, _, _ = self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            finally:
                self._db.execute(f"PRAGMA busy_timeout={int(BUSY_TIMEOUT * 1000)}")
            return int(busy) == 0

    def put(self, ns: str, key: str, value: Any, ttl: float | None) -> None:
        # A row that expires is written in a transaction, with its expiry stamped inside it: the time reads the
        # clock base in the store, and a forced run that another worker commits while this one waits for the
        # write lock would leave the row stamped by the base before (the second reviewer, CX-24).
        with self.atomic() if ttl is not None else self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO kv VALUES (?,?,?,?)", (ns, key, json.dumps(value), self._expiry(ttl))
            )

    def get(self, ns: str, key: str) -> Any | None:
        with self._lock:
            row = self._db.execute(
                "SELECT value FROM kv WHERE ns=? AND key=? AND (expires IS NULL OR expires>?)",
                (ns, key, self._clock()),
            ).fetchone()
            return None if row is None else json.loads(row[0])

    def peek(self, ns: str, key: str) -> Any | None:
        with self._lock:
            row = self._db.execute("SELECT value FROM kv WHERE ns=? AND key=?", (ns, key)).fetchone()
            return None if row is None else json.loads(row[0])

    def take(self, ns: str, key: str) -> Any | None:
        with self.atomic():
            self._purge(ns, key)
            row = self._db.execute("SELECT value FROM kv WHERE ns=? AND key=?", (ns, key)).fetchone()
            if row is not None:
                self._db.execute("DELETE FROM kv WHERE ns=? AND key=?", (ns, key))
        return None if row is None else json.loads(row[0])

    def add(self, ns: str, key: str, value: Any, ttl: float | None) -> bool:
        with self.atomic():
            self._purge(ns, key)
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO kv VALUES (?,?,?,?)", (ns, key, json.dumps(value), self._expiry(ttl))
            )
            return cursor.rowcount == 1

    def incr(self, ns: str, key: str, ttl: float | None) -> int:
        with self.atomic():
            self._purge(ns, key)
            row = self._db.execute("SELECT value FROM kv WHERE ns=? AND key=?", (ns, key)).fetchone()
            value = (int(json.loads(row[0])) if row else 0) + 1
            if row:
                self._db.execute("UPDATE kv SET value=? WHERE ns=? AND key=?", (json.dumps(value), ns, key))
            else:
                self._db.execute("INSERT INTO kv VALUES (?,?,?,?)", (ns, key, json.dumps(value), self._expiry(ttl)))
            return value

    def delete(self, ns: str, key: str) -> None:
        with self._lock:
            self._db.execute("DELETE FROM kv WHERE ns=? AND key=?", (ns, key))

    def items(self, ns: str, prefix: str = "", *, at: float | None = None) -> list[tuple[str, Any]]:
        """A key range rather than LIKE, which folds ASCII case (review 2, N-L4); keys compare as bytes."""
        query = "SELECT key, value FROM kv WHERE ns=? AND key>=? AND (expires IS NULL OR expires>?)"
        args: list[Any] = [ns, prefix, self._clock() if at is None else at]
        upper = _prefix_end(prefix)
        if upper is not None:
            query += " AND key<?"
            args.append(upper)
        with self._lock:
            rows = self._db.execute(query + " ORDER BY key", args).fetchall()
            return [(k, json.loads(v)) for k, v in rows]

    def scan(self, ns: str, after: str = "", limit: int = 500, until: str | None = None) -> list[tuple[str, Any]]:
        query = "SELECT key, value FROM kv WHERE ns=? AND key>? AND (expires IS NULL OR expires>?)"
        args: list[Any] = [ns, after, self._clock()]
        if until is not None:
            query += " AND key<=?"
            args.append(until)
        with self._lock:
            rows = self._db.execute(query + " ORDER BY key LIMIT ?", [*args, limit]).fetchall()
            return [(k, json.loads(v)) for k, v in rows]

    def delete_through(self, ns: str, last: str) -> int:
        with self._lock:
            return self._db.execute("DELETE FROM kv WHERE ns=? AND key<=?", (ns, last)).rowcount

    def empty(self) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM kv LIMIT 1").fetchone() is None

    def count(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM kv").fetchone()[0])


# The transaction-level advisory lock every write transaction takes first, so writers go one at a time across every
# worker and host, as SQLite's BEGIN IMMEDIATE has them on one host: "cunho" in ASCII.
WRITE_LOCK = 0x63756E686F
SCHEMA_LOCK = WRITE_LOCK + 1


class PostgresStore:
    """A store in PostgreSQL, through psycopg 3 (the `postgres` extra), for workers on several hosts.

    It keeps SQLite's contract: every write runs in a transaction that first takes one advisory lock, so `atomic()`
    holds across every worker as BEGIN IMMEDIATE does on one host, and a single write outside it waits for it too.
    Reads see what is committed (READ COMMITTED; with writers one at a time, inside `atomic()` that is also what
    the transaction last read). Keys are kept as UTF-8 bytes, so they sort as SQLite's do and may hold any character
    a string can, NUL included, which a Postgres text column refuses. One connection per worker process, used by one
    thread at a time; it is opened again before a call when the server dropped it between calls.
    """

    def __init__(self, url: str, clock: Clock = time.time, lock_timeout: float = BUSY_TIMEOUT) -> None:
        try:
            import psycopg
        except ImportError as exc:
            raise ConfigError("a Postgres store needs the postgres extra: pip install 'cunho[postgres]'") from exc
        self._psycopg = psycopg
        self._url = url
        self._clock = clock
        self._lock_timeout = f"{int(lock_timeout * 1000)}ms"
        self._lock = threading.RLock()
        self._depth = 0
        self._undo: list[Callable[[], None]] = []
        self._db = self._connect()
        with self._lock:
            self._db.execute("BEGIN")
            try:
                # Workers that start together on a new database would race to create the table.
                self._db.execute("SELECT pg_advisory_xact_lock(%s)", (SCHEMA_LOCK,))
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS kv (ns text NOT NULL, key bytea NOT NULL, value text NOT NULL, "
                    "expires double precision, PRIMARY KEY (ns, key))"
                )
                self._db.execute("CREATE INDEX IF NOT EXISTS kv_expires ON kv (expires) WHERE expires IS NOT NULL")
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _connect(self) -> Any:
        try:
            return self._psycopg.connect(self._url, autocommit=True)
        except self._psycopg.Error as exc:
            raise ConfigError(f"cannot connect to the Postgres store: {exc}") from exc

    def _ready(self) -> Any:
        """The connection, opened again when the server dropped it between calls (never inside a transaction)."""
        if self._depth == 0 and (self._db.closed or self._db.broken):
            self._db = self._connect()
        return self._db

    def go_by(self, clock: Clock) -> None:
        self._clock = clock

    def _expiry(self, ttl: float | None) -> float | None:
        return None if ttl is None else self._clock() + ttl

    @contextmanager
    def atomic(self) -> Iterator[None]:
        """One write transaction that takes the write lock first; nested calls join the outer one."""
        with self._lock:
            if self._depth:
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            db = self._ready()
            db.execute("BEGIN")
            self._depth, self._undo = 1, []
            try:
                # A writer that never lets go fails this request after the wait SQLite's busy timeout allows,
                # instead of holding this worker's store lock, and every request behind it, for good (the second
                # reviewer). Only for this transaction.
                db.execute("SELECT set_config('lock_timeout', %s, true)", (self._lock_timeout,))
                db.execute("SELECT pg_advisory_xact_lock(%s)", (WRITE_LOCK,))
                yield
                db.execute("COMMIT")
            except BaseException:
                try:
                    if not db.broken and db.info.transaction_status != self._psycopg.pq.TransactionStatus.IDLE:
                        db.execute("ROLLBACK")
                except self._psycopg.Error:
                    pass  # the connection went down with the transaction: the server dropped it, and it is raised
                finally:
                    # Whatever the rollback did, what was kept in memory beside the store goes back with it
                    # (the second reviewer): a failed ROLLBACK used to skip these.
                    for undo in reversed(self._undo):
                        undo()
                raise
            finally:
                self._depth, self._undo = 0, []

    def on_rollback(self, undo: Callable[[], None]) -> None:
        if self._depth:
            self._undo.append(undo)

    def _purge(self, ns: str, key: bytes) -> None:
        self._db.execute(
            "DELETE FROM kv WHERE ns=%s AND key=%s AND expires IS NOT NULL AND expires<=%s", (ns, key, self._clock())
        )

    def _read(self, query: str, args: list[Any] | tuple[Any, ...]) -> list[Any]:
        with self._lock:
            return list(self._ready().execute(query, args).fetchall())

    def sweep(self, now: float, batch: int = 1000) -> int:
        """Delete rows expired by `now` in short transactions of at most `batch` rows."""
        removed = 0
        while True:
            with self.atomic():
                cutoff = min(now, self._clock())  # read under the write lock, as SQLite's sweep (CX-15)
                deleted = self._db.execute(
                    "DELETE FROM kv WHERE (ns, key) IN "
                    "(SELECT ns, key FROM kv WHERE expires IS NOT NULL AND expires<=%s LIMIT %s)",
                    (cutoff, batch),
                ).rowcount
            removed += deleted
            if deleted < batch:
                return removed

    def checkpoint(self) -> bool:
        """VACUUM the table, so the space of deleted rows (erased vault keys among them) is reclaimed for reuse. It
        cannot reach the server's write-ahead log, its archives or backups: their retention is the operator's."""
        with self._lock:
            if self._depth:
                return False
            try:
                self._ready().execute("VACUUM kv")
            except self._psycopg.Error:
                return False
            return True

    def put(self, ns: str, key: str, value: Any, ttl: float | None) -> None:
        with self.atomic():
            self._db.execute(
                "INSERT INTO kv VALUES (%s,%s,%s,%s) "
                "ON CONFLICT (ns, key) DO UPDATE SET value=EXCLUDED.value, expires=EXCLUDED.expires",
                (ns, key.encode(), json.dumps(value), self._expiry(ttl)),
            )

    def get(self, ns: str, key: str) -> Any | None:
        # The time is read under the lock, as SQLite's get reads it: a reading taken before waiting for another
        # thread's transaction would let a row that expired meanwhile through (the second reviewer).
        with self._lock:
            rows = self._read(
                "SELECT value FROM kv WHERE ns=%s AND key=%s AND (expires IS NULL OR expires>%s)",
                (ns, key.encode(), self._clock()),
            )
        return json.loads(rows[0][0]) if rows else None

    def peek(self, ns: str, key: str) -> Any | None:
        rows = self._read("SELECT value FROM kv WHERE ns=%s AND key=%s", (ns, key.encode()))
        return json.loads(rows[0][0]) if rows else None

    def take(self, ns: str, key: str) -> Any | None:
        with self.atomic():
            self._purge(ns, key.encode())
            row = self._db.execute(
                "DELETE FROM kv WHERE ns=%s AND key=%s RETURNING value", (ns, key.encode())
            ).fetchone()
        return None if row is None else json.loads(row[0])

    def add(self, ns: str, key: str, value: Any, ttl: float | None) -> bool:
        with self.atomic():
            self._purge(ns, key.encode())
            cursor = self._db.execute(
                "INSERT INTO kv VALUES (%s,%s,%s,%s) ON CONFLICT (ns, key) DO NOTHING",
                (ns, key.encode(), json.dumps(value), self._expiry(ttl)),
            )
            return bool(cursor.rowcount == 1)

    def incr(self, ns: str, key: str, ttl: float | None) -> int:
        with self.atomic():
            self._purge(ns, key.encode())
            row = self._db.execute("SELECT value FROM kv WHERE ns=%s AND key=%s", (ns, key.encode())).fetchone()
            value = (int(json.loads(row[0])) if row else 0) + 1
            if row:
                self._db.execute("UPDATE kv SET value=%s WHERE ns=%s AND key=%s", (json.dumps(value), ns, key.encode()))
            else:
                self._db.execute(
                    "INSERT INTO kv VALUES (%s,%s,%s,%s)", (ns, key.encode(), json.dumps(value), self._expiry(ttl))
                )
            return value

    def delete(self, ns: str, key: str) -> None:
        with self.atomic():
            self._db.execute("DELETE FROM kv WHERE ns=%s AND key=%s", (ns, key.encode()))

    def items(self, ns: str, prefix: str = "", *, at: float | None = None) -> list[tuple[str, Any]]:
        """A key range over the UTF-8 bytes, which sort in code point order as SQLite's keys do."""
        query = "SELECT key, value FROM kv WHERE ns=%s AND key>=%s AND (expires IS NULL OR expires>%s)"
        upper = _prefix_end(prefix)
        if upper is not None:
            query += " AND key<%s"
        with self._lock:
            args: list[Any] = [ns, prefix.encode(), self._clock() if at is None else at]
            if upper is not None:
                args.append(upper.encode())
            rows = self._read(query + " ORDER BY key", args)
        return [(bytes(k).decode(), json.loads(v)) for k, v in rows]

    def scan(self, ns: str, after: str = "", limit: int = 500, until: str | None = None) -> list[tuple[str, Any]]:
        query = "SELECT key, value FROM kv WHERE ns=%s AND key>%s AND (expires IS NULL OR expires>%s)"
        if until is not None:
            query += " AND key<=%s"
        with self._lock:
            args: list[Any] = [ns, after.encode(), self._clock()]
            if until is not None:
                args.append(until.encode())
            rows = self._read(query + " ORDER BY key LIMIT %s", [*args, limit])
        return [(bytes(k).decode(), json.loads(v)) for k, v in rows]

    def delete_through(self, ns: str, last: str) -> int:
        with self.atomic():
            return int(self._db.execute("DELETE FROM kv WHERE ns=%s AND key<=%s", (ns, last.encode())).rowcount)

    def empty(self) -> bool:
        return not self._read("SELECT 1 FROM kv LIMIT 1", ())

    def count(self) -> int:
        return int(self._read("SELECT COUNT(*) FROM kv", ())[0][0])

    def close(self) -> None:
        with self._lock:
            self._db.close()
