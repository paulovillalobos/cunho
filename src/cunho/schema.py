"""The version of what cunho keeps in its store, and the upgrade from the versions before it had one.

Every store carries `SCHEMA` under ("meta", "schema"). A new store gets it on its first start. A store without
it was written by cunho before the version existed, at 45ec9be (review 5) or at 382505f (review 6), and is
upgraded once, in one transaction, before anything else runs; a store with a version this code does not know
refuses to start. Until this existed, a store written by 45ec9be started fine under 382505f and published every
one of its status lists as zeros, revocations and decoys alike (review 6, N6-M2).

The upgrade rebuilds what a status list shows from its slots, which hold every bit ever set:
- the size each list was opened with, which 45ec9be did not store: it took the setting, so the upgrade does too,
  and refuses when a slot lies beyond it, since the setting then cannot be the size the list was opened with;
- the queue of bits still hidden, which 45ec9be kept one row per slot with the moment as the value: a bit whose
  moment is still to come goes into the queue keyed by its moment, and one whose moment passed already showed;
- the published bits: every revoked slot, decoys included, except the ones still in the queue.

It also lets operators go on revoking, cancelling and erasing the offers made before the upgrade: subject
references 45ec9be handed out carry no keyed tag, so each one the store still names is recorded as handed out,
and an offer whose data is still in the vault counts as live, for every configuration the deployment issues,
until its window ends.

A store without a version is also what a database writer leaves who removes the version row, so the upgrade is
logged (`store.upgraded`, in the transaction of the upgrade), and production upgrades only when told to
(`store_upgrade`), as it starts a new anchor only when told to (review 7, L3).
"""

from __future__ import annotations

import zlib
from collections.abc import Callable

from cunho.errors import ConfigError
from cunho.jose import b64u
from cunho.settings import Settings
from cunho.store import Store

SCHEMA = 2
REVOKED = 1
# Where a subject reference shows up in a store written before the schema version.
SUBJECT_NAMESPACES = ("vault-key", "issued", "subject-open", "subject-closed", "subject-done", "person-of")


def upgrade(
    store: Store,
    settings: Settings,
    clock: Callable[[], float],
    handed_out: Callable[[str], bool],
    configuration_ids: list[str],
) -> bool:
    """Bring the store to SCHEMA. Returns True when it upgraded a store written before the version existed."""
    with store.atomic():
        version = store.get("meta", "schema")
        if version == SCHEMA:
            return False
        if version is not None:
            raise ConfigError(f"the store has schema version {version!r}; this cunho reads version {SCHEMA} only")
        earlier = not store.empty()
        if earlier and settings.production and not settings.store_upgrade:
            # A store with no version is one written before it, or one whose version row was removed by hand: in
            # production the operator says which, as for a new anchor (review 7, L3).
            raise ConfigError(
                "the store carries no schema version: set CUNHO_STORE_UPGRADE=true once to upgrade a store written "
                "before the version existed, or find out who removed the version row"
            )
        if earlier:
            _status(store, settings, clock())
            _subjects(store, settings, handed_out, configuration_ids)
        store.put("meta", "schema", SCHEMA, None)
        return earlier


def _status(store: Store, settings: Settings, now: float) -> None:
    for key, meta in store.items("status-meta", "list:"):
        list_id = key.split(":", 1)[1]
        size = meta.get("size") if isinstance(meta, dict) else None
        if not isinstance(size, int) or isinstance(size, bool):
            size = settings.status_list_size
        slots = {int(k.split(":", 1)[1]): v for k, v in store.items("status-slot", f"{list_id}:")}
        beyond = [index for index in slots if index >= size]
        if beyond:
            raise ConfigError(
                f"status list {list_id} has a slot at {max(beyond)}, beyond the {size} of CUNHO_STATUS_LIST_SIZE: "
                "start the upgrade with the list size the earlier version ran with"
            )
        store.put("status-meta", key, {**(meta if isinstance(meta, dict) else {}), "size": size}, None)
        hidden = set()
        for pending, at in store.items("status-pending", f"{list_id}:"):
            parts = pending.split(":")
            if len(parts) == 3:  # already keyed by its moment
                hidden.add(int(parts[2]))
                continue
            store.delete("status-pending", pending)
            if float(at) > now:
                index = int(parts[1])
                store.put("status-pending", f"{list_id}:{int(float(at) * 1000):016d}:{index:08d}", at, None)
                hidden.add(index)
        bits = bytearray(size // 8)
        for index, value in slots.items():
            if value == REVOKED and index not in hidden:
                bits[index // 8] |= 1 << (index % 8)
        store.put("status-visible", list_id, b64u(zlib.compress(bytes(bits), 9)), None)
        store.delete("status-rev", list_id)


def _subjects(
    store: Store, settings: Settings, handed_out: Callable[[str], bool], configuration_ids: list[str]
) -> None:
    references: set[str] = set()
    for namespace in SUBJECT_NAMESPACES:
        references |= {key.split(":", 1)[0] for key, _ in store.items(namespace)}
    for reference in sorted(references):
        if not handed_out(reference):
            store.put("subject-legacy", reference, 1, None)
    window = settings.offer_ttl + settings.access_token_ttl
    for reference, _ in store.items("vault-key"):
        if store.get("subject-open", reference) is None:
            store.put("subject-open", reference, list(configuration_ids), window)


__all__ = ["SCHEMA", "upgrade"]
