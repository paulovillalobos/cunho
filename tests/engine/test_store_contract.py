"""The store contract, the same for every store (memory, SQLite, PostgreSQL), and what only PostgreSQL adds: writers on
several processes one at a time, a write that waits for another worker's transaction, a connection the server
dropped, and the issuer running on it."""

from __future__ import annotations

import multiprocessing
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from cunho.errors import ConfigError
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import MemoryStore, PostgresStore, SqliteStore, Store
from eudi_probe.jose import EcKey

from . import store_workers
from .helpers import Clock, Pki, Wallet, settings_kwargs, with_database

psycopg = pytest.importorskip("psycopg")


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def made(request: pytest.FixtureRequest, tmp_path: Path, clock: Clock) -> Iterator[Store]:
    if request.param == "memory":
        yield MemoryStore(clock)
    elif request.param == "sqlite":
        yield SqliteStore(tmp_path / "s.db", clock)
    else:
        store = PostgresStore(request.getfixturevalue("pg_url"), clock)
        yield store
        store.close()


def test_put_get_and_expiry(made: Store, clock: Clock) -> None:
    made.put("ns", "a", {"x": [1, "é", None]}, 10)
    made.put("ns", "forever", 1, None)
    assert made.get("ns", "a") == {"x": [1, "é", None]} and made.get("other", "a") is None
    clock.now += 10
    assert made.get("ns", "a") is None, "expired at its expiry"
    assert made.peek("ns", "a") == {"x": [1, "é", None]}, "peek ignores the expiry"
    assert made.get("ns", "forever") == 1
    made.put("ns", "forever", 2, None)
    assert made.get("ns", "forever") == 2, "put replaces"


def test_take_once(made: Store, clock: Clock) -> None:
    made.put("ns", "code", "v", 5)
    assert made.take("ns", "code") == "v" and made.take("ns", "code") is None
    made.put("ns", "late", "v", 5)
    clock.now += 5
    assert made.take("ns", "late") is None


def test_add_only_when_absent(made: Store, clock: Clock) -> None:
    assert made.add("jti", "j", 1, 5) and not made.add("jti", "j", 2, 5)
    assert made.get("jti", "j") == 1
    clock.now += 5
    assert made.add("jti", "j", 3, 5), "an expired entry does not count"
    assert made.get("jti", "j") == 3


def test_incr_counts_and_keeps_its_first_expiry(made: Store, clock: Clock) -> None:
    assert [made.incr("n", "k", 10) for _ in range(3)] == [1, 2, 3]
    clock.now += 9
    assert made.incr("n", "k", 10) == 4
    clock.now += 1
    assert made.incr("n", "k", 10) == 1, "counted again once the first expiry passed"


def test_delete(made: Store) -> None:
    made.put("ns", "a", 1, None)
    made.delete("ns", "a")
    made.delete("ns", "never")
    assert made.get("ns", "a") is None


KEYS = ["a", "B", "b", "ab", "a:1", "a:2", "a\x00z", "aé", "a\U0001f600", "b:1"]


def test_items_and_scan_go_by_code_point_order(made: Store, clock: Clock) -> None:
    for key in KEYS:
        made.put("ns", key, key, None)
    made.put("ns", "a:old", "x", 1)
    assert [k for k, _ in made.items("ns")] == sorted(KEYS + ["a:old"])
    assert [k for k, _ in made.items("ns", "a")] == sorted(k for k in KEYS + ["a:old"] if k.startswith("a"))
    assert [k for k, _ in made.items("ns", "a:")] == ["a:1", "a:2", "a:old"], "a key range, not a case-folding LIKE"
    clock.now += 1
    assert [k for k, _ in made.items("ns", "a:")] == ["a:1", "a:2"]
    assert [k for k, _ in made.items("ns", "a:", at=clock.now - 2)] == ["a:1", "a:2", "a:old"]
    assert made.items("ns", "\U0010ffff") == []
    assert [k for k, _ in made.scan("ns", limit=3)] == sorted(KEYS)[:3]
    assert [k for k, _ in made.scan("ns", after="a:2", until="b")] == [k for k in sorted(KEYS) if "a:2" < k <= "b"]


def test_delete_through(made: Store) -> None:
    for key in ("0001", "0002", "0003"):
        made.put("log", key, key, None)
    assert made.delete_through("log", "0002") == 2
    assert [k for k, _ in made.items("log")] == ["0003"]


def test_sweep_removes_only_what_expired(made: Store, clock: Clock) -> None:
    for i in range(5):
        made.put("ns", f"short{i}", i, 1)
    made.put("ns", "long", 1, 100)
    made.put("ns", "forever", 1, None)
    assert made.sweep(clock.now) == 0
    clock.now += 1
    assert made.sweep(clock.now) == 5
    assert made.peek("ns", "short0") is None and made.peek("ns", "long") == 1
    assert made.peek("ns", "forever") == 1


def test_atomic_commits_or_undoes_everything(made: Store) -> None:
    undone: list[str] = []
    with made.atomic():
        made.put("ns", "a", 1, None)
        with made.atomic():
            made.put("ns", "b", 2, None)
    assert made.get("ns", "a") == 1 and made.get("ns", "b") == 2
    with pytest.raises(RuntimeError), made.atomic():
        made.put("ns", "a", 10, None)
        made.delete("ns", "b")
        made.on_rollback(lambda: undone.append("first"))
        made.on_rollback(lambda: undone.append("second"))
        raise RuntimeError
    assert made.get("ns", "a") == 1 and made.get("ns", "b") == 2
    assert undone == ["second", "first"], "in reverse, once"
    made.on_rollback(lambda: undone.append("outside"))
    assert undone == ["second", "first"], "outside a transaction nothing is kept to undo"


def test_empty_and_checkpoint(made: Store) -> None:
    assert made.empty()
    made.put("ns", "a", 1, 1)
    assert not made.empty()
    assert made.checkpoint() is True


def test_go_by_another_clock(made: Store, clock: Clock) -> None:
    other = Clock()
    other.now = clock.now + 1000
    made.go_by(other)
    made.put("ns", "a", 1, 10)
    assert made.get("ns", "a") == 1
    made.go_by(clock)
    assert made.get("ns", "a") == 1, "stamped by the other clock: lives until its 1010"


# ---------------------------------------------------------------- PostgreSQL only


def run_in_processes(target: Callable[..., Any], args: list[tuple[Any, ...]]) -> list[Any]:
    context = multiprocessing.get_context("spawn")
    with context.Pool(len(args)) as pool:
        return pool.starmap(target, args)


def test_one_add_wins_across_processes(pg_url: str) -> None:
    won = run_in_processes(store_workers.adds, [(pg_url, 40)] * 4)
    assert sorted(k for keys in won for k in keys) == sorted(f"k{i}" for i in range(40))


def test_writers_go_one_at_a_time_across_processes(pg_url: str) -> None:
    run_in_processes(store_workers.increments, [(pg_url, 25)] * 4)
    store = PostgresStore(pg_url)
    assert store.get("count", "n") == 100
    assert store.get("count", "rmw") == 100, "no update lost between a read and its write"
    store.close()


def test_workers_starting_together_create_the_table_once(pg_url: str) -> None:
    assert run_in_processes(store_workers.opens, [(pg_url,)] * 6) == [True] * 6


def test_a_write_waits_for_another_workers_transaction(pg_url: str, clock: Clock) -> None:
    first, second = PostgresStore(pg_url, clock), PostgresStore(pg_url, clock)
    order: list[str] = []
    inside = threading.Event()

    def other() -> None:
        inside.wait()
        second.delete("ns", "a")  # a single write, outside any atomic()
        order.append("deleted")

    thread = threading.Thread(target=other)
    thread.start()
    with first.atomic():
        first.put("ns", "a", 1, None)
        inside.set()
        time.sleep(0.3)
        order.append("committing")
    thread.join(5)
    assert order == ["committing", "deleted"] and first.get("ns", "a") is None
    first.close()
    second.close()


def test_a_dropped_connection_is_opened_again(pg_url: str, postgres: str, clock: Clock) -> None:
    store = PostgresStore(pg_url, clock)
    store.put("ns", "a", 1, None)
    pid = store._db.info.backend_pid  # noqa: SLF001
    with psycopg.connect(postgres, autocommit=True) as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (pid,))
    with pytest.raises(psycopg.OperationalError):
        store.get("ns", "a")  # the call that finds it gone fails
    assert store.get("ns", "a") == 1, "the next one opens it again"
    with store.atomic():
        store.put("ns", "b", 2, None)
    store.close()


def test_checkpoint_waits_outside_a_transaction(pg_url: str, clock: Clock) -> None:
    store = PostgresStore(pg_url, clock)
    with store.atomic():
        assert store.checkpoint() is False, "VACUUM cannot run inside a transaction"
    store.close()


def test_a_store_that_cannot_be_reached_stops_the_start(postgres: str) -> None:
    with pytest.raises(ConfigError, match="cannot connect to the Postgres store"):
        PostgresStore(with_database(postgres, "no_such_database"))


def test_a_postgres_store_without_the_extra_says_what_to_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "psycopg", None)  # what an import finds when the package is not installed
    with pytest.raises(ConfigError, match=r"pip install 'cunho\[postgres\]'"):
        PostgresStore("postgresql:///unused")


def test_a_table_in_the_way_stops_the_start(pg_url: str) -> None:
    """A `kv` table that is not the store's own makes laying the schema fail: the start stops on it rather than
    running on a table it cannot use."""
    with psycopg.connect(pg_url, autocommit=True) as db:
        db.execute("CREATE TABLE kv (other integer)")
    with pytest.raises(psycopg.Error, match="expires"):
        PostgresStore(pg_url)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"store_path": Path("/tmp/x.db")}, "not both"),
        ({"store_url": "mysql://host/db"}, "postgresql:// connection URI"),
        ({"secret_key_file": None}, "needs secret_key_file and audit_anchor_path"),
        ({"audit_anchor_path": None}, "needs secret_key_file and audit_anchor_path"),
    ],
)
def test_a_postgres_store_is_set_with_its_keys_outside(
    pki: Pki, tmp_path: Path, change: dict[str, Any], message: str
) -> None:
    base = {
        "store_url": "postgresql://cunho@db.internal/cunho",
        "secret_key_file": tmp_path / "m.key",
        "audit_anchor_path": tmp_path / "audit.anchor",
    }
    assert Settings(**settings_kwargs(pki, **base)).store_url == base["store_url"]
    with pytest.raises(ConfigError, match=message):
        Settings(**settings_kwargs(pki, **{**base, **change}))


def test_the_store_url_comes_from_the_environment(tmp_path: Path) -> None:
    from .helpers import ADMIN_TOKEN, ISSUER

    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": ADMIN_TOKEN,
        "CUNHO_SIGNING_KEY": "k",
        "CUNHO_SIGNING_CHAIN": "c",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "a",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{ISSUER}/certs/signer.pem",
        "CUNHO_SECRET_KEY_FILE": str(tmp_path / "m.key"),
        "CUNHO_AUDIT_ANCHOR_PATH": str(tmp_path / "a"),
        "CUNHO_STORE_URL": "postgresql://cunho@db.internal/cunho",
    }
    assert Settings.from_env(env).store_url == "postgresql://cunho@db.internal/cunho"
    assert Settings.from_env({k: v for k, v in env.items() if k != "CUNHO_STORE_URL"}).store_url is None


def test_the_issuer_runs_on_postgres(
    pki: Pki, tmp_path: Path, pg_url: str, clock: Clock, wallet_for: Callable[[Issuer], Wallet]
) -> None:
    """Issue, repeat, revoke and verify the audit log with the store named by store_url, then start again on it."""
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    kwargs = settings_kwargs(
        pki,
        store_url=pg_url,
        secret_key_file=tmp_path / "m.key",
        audit_anchor_path=tmp_path / "audit.anchor",
    )
    issuer = Issuer(Settings(**kwargs), clock=clock)
    assert isinstance(issuer.store, PostgresStore)
    wallet = wallet_for(issuer)
    offer = wallet.offer()
    wallet.get_token(offer)
    key = EcKey.generate()
    issued = wallet.issue([key])
    assert issued.status_code == 200, issued.text
    assert wallet.issue([key]).json() == issued.json(), "a repeated request gets the reply kept for it"
    admin = {"Authorization": f"Bearer {kwargs['admin_token']}"}
    revoked = wallet.client.post(
        "/admin/revocations", json={"subject_ref": offer["subject_ref"], "reason": "user_request"}, headers=admin
    )
    assert revoked.status_code == 200 and revoked.json()["revoked"] >= 1, revoked.text
    verified = wallet.client.get("/admin/audit/verify", headers=admin)
    assert verified.status_code == 200 and verified.json()["valid"] is True, verified.text
    again = Issuer(Settings(**kwargs), clock=clock)
    assert again.store.get("meta", "schema") is not None, "the second start finds the first one's database"


def test_a_writer_that_never_lets_go_fails_the_wait(pg_url: str, clock: Clock) -> None:
    """The writer lock is waited for as long as SQLite's busy timeout lets a write wait, then the call fails,
    leaving this worker free (the second reviewer)."""
    holder, waiter = PostgresStore(pg_url, clock), PostgresStore(pg_url, clock, lock_timeout=0.2)
    with holder.atomic():
        holder.put("ns", "a", 1, None)
        started = time.monotonic()
        with pytest.raises(psycopg.errors.LockNotAvailable):
            waiter.put("ns", "b", 2, None)
        assert time.monotonic() - started < 5
        assert waiter.get("ns", "b") is None, "the worker reads on, its transaction rolled back"
    waiter.put("ns", "b", 2, None)
    assert waiter.get("ns", "b") == 2
    holder.close()
    waiter.close()


def test_a_rollback_that_fails_with_the_connection_still_undoes_what_was_kept(
    pg_url: str, postgres: str, clock: Clock
) -> None:
    """The server drops the connection inside a transaction that then fails: ROLLBACK raises in turn, and the
    undo callbacks ran all the same (the second reviewer); the caller sees its own error."""
    store = PostgresStore(pg_url, clock)
    undone: list[bool] = []
    with pytest.raises(RuntimeError, match="the unit failed"), store.atomic():
        store.put("ns", "a", 1, None)
        store.on_rollback(lambda: undone.append(True))
        with psycopg.connect(postgres, autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(%s)", (store._db.info.backend_pid,))  # noqa: SLF001
        raise RuntimeError("the unit failed")
    assert undone == [True]
    assert store.get("ns", "a") is None, "a new connection, and nothing of the unit committed"
    store.close()
