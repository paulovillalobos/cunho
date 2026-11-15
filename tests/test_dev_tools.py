"""The development tools (tools/dev_pki.py, tools/demo_local.py, and tests/engine/pki.py, which dev_pki.py and the
demo stack's image use): a private key or a token is readable by its owner alone from the moment the file exists.

The security review found each of them written first and closed afterwards: with the usual umask the file was 0644
in a 0755 directory in between, readable by every other user of a developer's or a build machine."""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
OTHERS = stat.S_IRWXG | stat.S_IRWXO


def tool(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"{name}_under_test", TOOLS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def mode_when_written(monkeypatch: pytest.MonkeyPatch) -> dict[Path, int]:
    """The mode of each file written through pathlib, read the moment its content is in it: what another user of
    the machine finds until a later chmod. A file made owner-only (os.open with a mode) is not in it."""
    seen: dict[Path, int] = {}

    def watch(name: str) -> None:
        real = getattr(Path, name)

        def write(self: Path, *args: Any, **kwargs: Any) -> Any:
            result = real(self, *args, **kwargs)
            seen.setdefault(self, stat.S_IMODE(self.stat().st_mode))
            return result

        monkeypatch.setattr(Path, name, write)

    watch("write_bytes")
    watch("write_text")
    return seen


@pytest.fixture
def usual_umask() -> Iterator[None]:
    previous = os.umask(0o022)  # what a login shell gives on most systems, whatever this machine's is
    yield
    os.umask(previous)


def test_dev_pki_never_writes_a_secret_that_others_can_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode_when_written: dict[Path, int], usual_umask: None
) -> None:
    monkeypatch.setattr(sys, "path", list(sys.path))  # the tool adds to it; the next test gets it back as it was
    out = tmp_path / "dev"
    dev_pki = tool("dev_pki")
    dev_pki.main(out)
    secret = [p for p in out.rglob("*") if p.is_file() and (p.suffix == ".key" or p.name == "admin-token")]
    assert {p.name for p in secret} >= {"signing.key", "wallet-provider.key", "ka-signer.key", "admin-token"}
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in secret)
    exposed = sorted(str(p.relative_to(out)) for p in secret if mode_when_written.get(p, 0) & OTHERS)
    assert not exposed, f"written readable by every user of the machine, closed only afterwards: {exposed}"
    # Made again over what a run left, as the tool is used: the files are replaced, and owner-only still.
    (out / "signing.key").chmod(0o644)
    before = (out / "signing.key").read_bytes()
    dev_pki.main(out)
    assert (out / "signing.key").read_bytes() != before
    assert stat.S_IMODE((out / "signing.key").stat().st_mode) == 0o600


def test_demo_local_never_writes_a_secret_that_others_can_read(
    tmp_path: Path, mode_when_written: dict[Path, int], usual_umask: None
) -> None:
    """The demo's secret key, the console's password hash and both operator tokens go through this function."""
    private = tool("demo_local").private
    path = private(tmp_path / "pid-admin-token", b"not a real token")
    assert path.read_bytes() == b"not a real token" and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not mode_when_written.get(path, 0) & OTHERS
    path.chmod(0o644)
    assert private(path, b"another run's").read_bytes() == b"another run's"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, "a file an earlier run left is replaced, not written into"
