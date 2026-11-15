"""What the Postgres store's multi-process tests run in each worker process (importable, for spawn)."""

from __future__ import annotations

from cunho.store import PostgresStore


def adds(url: str, keys: int) -> list[str]:
    store = PostgresStore(url)
    won = [f"k{i}" for i in range(keys) if store.add("once", f"k{i}", 1, None)]
    store.close()
    return won


def increments(url: str, times: int) -> None:
    store = PostgresStore(url)
    for _ in range(times):
        store.incr("count", "n", None)
        with store.atomic():  # a read-modify-write that only holds if no other worker writes in between
            value = store.get("count", "rmw") or 0
            store.put("count", "rmw", value + 1, None)
    store.close()


def opens(url: str) -> bool:
    PostgresStore(url).close()
    return True
