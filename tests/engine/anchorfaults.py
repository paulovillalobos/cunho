"""Fault injection for the audit anchor file: writes cut short at any byte, NUL tails and garbage.

Used by the review 5 tests in this directory and by the exhaustive run under `tests/slow`.
"""

from __future__ import annotations

import errno
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from cunho import audit as audit_module
from cunho.audit import Anchor, AuditError, AuditLog
from cunho.keyring import Keyring
from cunho.store import MemoryStore

from .helpers import Clock

KEY = b"k" * 32


class AnchorFaults:
    """Stands in for `os.write` on one anchor file. A planned fault applies to one write to that file, counted
    from 0 across every handle that opens it, so a restarted log is counted on. A fault is ("tear", n): the
    first n bytes reach the file, then the disk is full; or ("nul", n): n NUL bytes reach the file instead of
    the data, as a file system can leave them after a power loss, and the writer never learns otherwise."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
        self.path = path
        self.real = os.write
        self.writes = 0
        self.plan: dict[int, tuple[str, int]] = {}
        self.sizes: list[int] = []  # the length of every write, as it was asked for
        monkeypatch.setattr(audit_module.os, "write", self.write)
        monkeypatch.setattr(audit_module.os, "fsync", lambda fd: None)  # not under test here; keeps it fast

    def _ours(self, fd: int) -> bool:
        try:
            held, current = os.fstat(fd), os.stat(self.path)
        except OSError:
            return False
        return (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino)

    def write(self, fd: int, data: bytes) -> int:
        if not self._ours(fd):
            return self.real(fd, data)
        number, self.writes = self.writes, self.writes + 1
        self.sizes.append(len(data))
        fault = self.plan.pop(number, None)
        if fault is None:
            return self.real(fd, data)
        kind, keep = fault
        written = data[:keep] if kind == "tear" else b"\x00" * keep
        if written:
            self.real(fd, written)
        raise OSError(errno.ENOSPC if kind == "tear" else errno.EIO, "injected anchor fault")


@dataclass
class History:
    """One audit log on a memory store (the database) and an anchor file, driven through faults."""

    root: Path
    clock: Clock = field(default_factory=Clock)
    store: MemoryStore = field(init=False)
    log: AuditLog = field(init=False)
    committed: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.store = MemoryStore(self.clock)
        self.log = self._open(create=True)

    @property
    def path(self) -> Path:
        return self.root / "audit.anchor"

    def _open(self, *, create: bool = False) -> AuditLog:
        keyring = Keyring(KEY)
        anchor = Anchor(self.path, keyring)
        return AuditLog(self.store, keyring, self.clock, retention=3650 * 86_400, anchor=anchor, create_anchor=create)

    def restart(self) -> None:
        """A crash and a restart: a new process opens the same database and anchor."""
        self.close()
        self.log = self._open()

    def close(self) -> None:
        if self.log.anchor is not None:
            self.log.anchor.close()

    def act(self, event: str) -> bool:
        """One logged action. True when it was committed (a failed anchor write after the commit included)."""
        try:
            self.log.append(event, "admin")
        except AuditError:
            return False
        self.committed.append(event)
        return True

    def damaged(self) -> bool:
        """An oracle apart from cunho's own reader: the file does not end in a complete JSON line."""
        content = self.path.read_bytes()
        if not content.endswith(b"\n"):
            return True
        try:
            return "tag" not in json.loads(content.splitlines()[-1])
        except ValueError:
            return True

    def check_whole(self) -> None:
        """After the faults: valid, every committed action logged in order, every entry anchored once."""
        ok, detail = self.log.verify()
        assert ok, detail
        entries = self.log.entries()
        assert [e["event"] for e in entries if e["event"] != "audit.anchor_repaired"] == self.committed
        lines = list(self.log.anchor.lines())  # type: ignore[union-attr]
        assert [line["seq"] for line in lines] == list(range(len(entries) + 1))
        assert [line["mac"] for line in lines[1:]] == [e["mac"] for e in entries]
        assert not self.damaged()


def run(root: Path, faults: dict[int, tuple[str, int]], restart: bool, monkeypatch: pytest.MonkeyPatch) -> History:
    """Log until the planned faults have all struck and three actions went through after them. After every
    step, `verify` must not call a damaged anchor valid."""
    root.mkdir(parents=True, exist_ok=True)
    history = History(root)
    injector = AnchorFaults(monkeypatch, history.path)
    injector.plan = dict(faults)
    clean, step = 0, 0
    while injector.plan or clean < 3:
        committed = history.act(f"e{step}")
        step += 1
        assert step < 40, "the faults never stopped striking"
        damaged = history.damaged()
        if damaged:
            assert not history.log.verify()[0], "verify called a damaged anchor valid"
            if restart:
                history.restart()
        clean = clean + 1 if committed and not damaged and not injector.plan else 0
    history.check_whole()
    history.close()
    return history


def first_write_size(root: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    """How long the anchor write of the second action is, so a test can cut it at every byte."""
    root.mkdir(parents=True, exist_ok=True)
    history = History(root)
    injector = AnchorFaults(monkeypatch, history.path)
    history.act("e0")
    history.act("e1")
    history.close()
    return injector.sizes[1]


__all__ = ["AnchorFaults", "History", "run", "first_write_size", "AuditError"]
