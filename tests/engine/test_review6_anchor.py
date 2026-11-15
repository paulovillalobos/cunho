"""Regression tests for the sixth M2 review (cunho-m2-review-6.md): replayed and reordered anchor lines."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.audit import LINE_MAX, Anchor, AuditError, AuditLog
from cunho.keyring import Keyring
from cunho.service import Issuer
from cunho.store import MemoryStore, SqliteStore

from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PID_SUBJECT, Clock, Pki, Wallet

DAY = 86_400
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

# N6-H1: a copy of a genuine anchor line never moves the end back ---------------------------------------


def _log(root: Path, clock: Clock, store: Any = None) -> AuditLog:
    keyring = Keyring.from_file(root / "m.key", create=True)
    store = store if store is not None else MemoryStore(clock)
    return AuditLog(
        store, keyring, clock, retention=30 * DAY, anchor=Anchor(root / "anchor", keyring), create_anchor=True
    )


def _history(root: Path, *, pruned: bool) -> tuple[AuditLog, Clock, list[bytes]]:
    """Six entries, a day apart; with `pruned`, the first four are pruned by a run forty days later."""
    root.mkdir(parents=True, exist_ok=True)
    clock = Clock()
    log = _log(root, clock)
    for n in range(4):
        log.append("offer.created", "admin", n=n)
        clock.now += DAY
    if pruned:
        clock.now += 40 * DAY
    for n in range(4, 6):
        log.append("offer.created", "admin", n=n)
    if pruned:
        assert log.prune_before(clock() - 30 * DAY) == 4
    assert log.verify()[0]
    return log, clock, (root / "anchor").read_bytes().splitlines(keepends=True)


def _truncate(log: AuditLog, keep: int, heads: dict[int, Any]) -> None:
    """What a database writer can do: remove the newest entries and put back the head row as it once was."""
    store = log._store  # noqa: SLF001
    for seq in range(keep + 1, 7):
        store.delete("audit", f"{seq:012d}")
    store.put("audit-meta", "head", heads[keep], None)


def _heads(root: Path, lines: list[bytes]) -> dict[int, Any]:
    """The head row of every anchored entry as cunho wrote it when that entry was the newest, which any reader
    of the database saw at the time."""
    keyring = Keyring.from_file(root / "m.key", create=False)
    heads = {}
    for raw in lines[1:]:
        line = json.loads(raw)
        tag = keyring.mac("audit-head", f"{line['seq']}:{line['mac']}")
        heads[line["seq"]] = {"seq": line["seq"], "mac": line["mac"], "tag": tag}
    return heads


@pytest.mark.parametrize("pruned", [False, True])
def test_n6_h1_a_copy_of_any_earlier_line_is_refused(tmp_path: Path, pruned: bool) -> None:
    """p2, p2b and p4: the reader took the last valid line as the end, so a copy moved it back; verify read the
    file only up to the copy's sequence and called a truncated store valid, or stayed valid while every logged
    action failed. Here a copy of every earlier line, the genesis line included, before and after pruning,
    with the store left alone or cut back to every entry it still holds."""
    for index in range(7):
        for keep in [None, *range(4 if pruned else 1, 6)]:
            root = tmp_path / f"line{index}-keep{keep}"
            log, _, lines = _history(root, pruned=pruned)
            if keep is not None:
                _truncate(log, keep, _heads(root, lines))
            with (root / "anchor").open("ab") as handle:
                handle.write(lines[index])
            before = (root / "anchor").read_bytes()
            for reader in (log, _log(root, Clock(log._clock()), log._store)):  # noqa: SLF001 - and after a restart
                ok, detail = reader.verify()
                assert not ok and f"repeats or goes back (sequence {index} after 6)" in detail, (index, keep, detail)
                with pytest.raises(AuditError, match=f"sequence {index} after 6"):
                    reader.append("offer.created", "admin")
                assert (root / "anchor").read_bytes() == before, "nothing is ever chained onto the copy"


def test_n6_h1_a_copy_without_its_newline_and_two_copies_in_a_row(tmp_path: Path) -> None:
    log, _, lines = _history(tmp_path, pruned=False)
    anchor = tmp_path / "anchor"
    whole = anchor.read_bytes()
    for appended in (lines[3][:-1], lines[2] + lines[3], b"\x00" * 9 + b"\n" + lines[6]):
        anchor.write_bytes(whole + appended)
        ok, detail = log.verify()
        assert not ok and "repeats or goes back" in detail, detail
        with pytest.raises(AuditError, match="repeats or goes back"):
            log.append("offer.created", "admin")
    anchor.write_bytes(whole)  # the operator removes what was appended
    log.append("offer.created", "admin")
    assert log.verify()[0]


def test_n6_h1_reordered_and_removed_lines(tmp_path: Path) -> None:
    log, clock, lines = _history(tmp_path, pruned=False)
    anchor = tmp_path / "anchor"
    for content, message in (
        (lines[:3] + [lines[4], lines[3]] + lines[5:], "anchor lines were removed or reordered"),
        (lines[:3] + lines[4:], "anchor lines were removed or reordered"),
        (lines[1:], "anchor lines were removed or reordered"),
        ([lines[0], lines[0], *lines[1:]], "repeats or goes back"),
    ):
        anchor.write_bytes(b"".join(content))
        restarted = _log(tmp_path, clock, log._store)  # noqa: SLF001 - a worker that reads the file from its start
        ok, detail = restarted.verify()
        assert not ok and message in detail, detail
        with pytest.raises(AuditError, match=message):
            restarted.append("offer.created", "admin")


def test_n6_h1_the_end_is_never_behind_the_head_a_worker_saw(tmp_path: Path, clock: Clock) -> None:
    """A worker reads on from where it stopped; a copy appended by anyone else is caught there too."""
    log = _log(tmp_path, clock, SqliteStore(tmp_path / "s.db", clock))
    other = _log(tmp_path, clock, SqliteStore(tmp_path / "s.db", clock))
    log.append("a", "admin")
    other.append("b", "admin")
    lines = (tmp_path / "anchor").read_bytes().splitlines(keepends=True)
    with (tmp_path / "anchor").open("ab") as handle:
        handle.write(lines[1])
    for worker in (log, other):
        with pytest.raises(AuditError, match="sequence 1 after 2"):
            worker.append("c", "admin")
        assert not worker.verify()[0]


def test_n6_h1_verify_and_logging_never_disagree(
    tmp_path: Path, make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock
) -> None:
    """p2b: after pruning, a copy of the genesis line stopped every logged action while verify stayed valid."""
    store = SqliteStore(tmp_path / "s.db", clock)
    issuer = make_issuer(store=store, audit_anchor_path=tmp_path / "anchor", audit_retention_days=30)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        for _ in range(3):
            wallet.offer()
        clock.now += 40 * DAY
        wallet.offer()
        assert issuer.maintenance(force=True)["audit_entries_pruned"] == 3
        genesis = (tmp_path / "anchor").read_bytes().splitlines(keepends=True)[0]
        with (tmp_path / "anchor").open("ab") as handle:
            handle.write(genesis)
        body = {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT}
        assert client.post("/admin/offers", json=body, headers=AUTH).status_code == 500
        verified = client.get("/admin/audit/verify", headers=AUTH).json()
        assert verified["valid"] is False and "repeats or goes back" in verified["detail"], verified
        issuer.sweep()  # the background repair cannot get past it either
        assert client.post("/admin/offers", json=body, headers=AUTH).status_code == 500
        assert issuer.audit.verify()[0] is False


def test_n6_h1_a_store_ahead_of_its_anchor_is_never_valid(tmp_path: Path, clock: Clock) -> None:
    """verify used to call a store seven entries ahead of its anchor valid ("7 newest not anchored yet")."""
    log = _log(tmp_path, clock)
    log.append("a", "admin")
    anchor = tmp_path / "anchor"
    saved = anchor.read_bytes()
    log.append("b", "admin")
    log.append("c", "admin")
    anchor.write_bytes(saved)  # as if both anchor writes were lost after their commits
    restarted = _log(tmp_path, clock, log._store)  # noqa: SLF001
    ok, detail = restarted.verify()
    assert not ok and detail.startswith("the 2 newest entries are not anchored yet"), detail
    restarted.repair()
    assert restarted.verify() == (True, "3 entries verified; 4 anchor lines")


def test_n6_h1_a_line_after_a_long_run_of_bytes_is_not_a_line(tmp_path: Path) -> None:
    """Bytes a newline does not close are read in pieces; a piece is a line only when it starts one, so a copy
    run on after LINE_MAX bytes without a newline is part of the damage, as a whole-line reader would see it."""
    log, _, lines = _history(tmp_path, pruned=False)
    anchor = tmp_path / "anchor"
    whole = anchor.read_bytes()
    anchor.write_bytes(whole + b"\x00" * LINE_MAX + lines[-1])
    ok, detail = log.verify()
    assert not ok and f"ends in {LINE_MAX + len(lines[-1])} bytes after its last line" in detail, detail
    log.append("offer.created", "admin")
    assert log.verify()[0]
    with pytest.raises(AuditError, match="got shorter while it was read"):
        list(Anchor(anchor, Keyring.from_file(tmp_path / "m.key", create=False)).lines(upto=anchor.stat().st_size + 1))


def test_n6_h1_a_worker_reads_a_shorter_anchor_again_from_its_start(
    tmp_path: Path, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """An anchor put back to an earlier copy of itself is read again whole, never from where a worker stopped."""
    log = _log(tmp_path, clock)
    log.append("a", "admin")
    saved = (tmp_path / "anchor").read_bytes()
    log.append("b", "admin")
    (tmp_path / "anchor").write_bytes(saved)
    with caplog.at_level(logging.ERROR, "cunho.security"):
        log.append("c", "admin")  # entry b is caught up, then c is anchored after it
    assert "shorter than when this worker last read it" in caplog.text
    assert log.verify() == (True, "3 entries verified; 4 anchor lines")


def test_n6_h1_verify_reads_the_anchor_only_up_to_its_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Lines another worker appends after verify took its snapshot are not read: they belong to entries verify
    did not read either."""
    clock = Clock()
    log = _log(tmp_path, clock, SqliteStore(tmp_path / "s.db", clock))
    other = _log(tmp_path, clock, SqliteStore(tmp_path / "s.db", clock))
    log.append("a", "admin")
    anchor = log.anchor
    assert anchor is not None
    real = anchor.lines

    def appended_meanwhile(*args: Any, **named: Any) -> Any:
        other.append("b", "admin")
        return real(*args, **named)

    monkeypatch.setattr(anchor, "lines", appended_meanwhile)
    assert log.verify() == (True, "1 entries verified; 2 anchor lines")
    monkeypatch.setattr(anchor, "lines", real)
    assert log.verify() == (True, "2 entries verified; 3 anchor lines")
