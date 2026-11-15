"""Fixtures every suite shares: a PostgreSQL server for the store (M4 piece I)."""

from __future__ import annotations

import glob
import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.engine.helpers import with_database


def _postgres_bin() -> Path | None:
    """The directory of initdb and pg_ctl: CUNHO_TEST_PG_BIN, the PATH, Homebrew's or Debian's."""
    candidates = [os.environ.get("CUNHO_TEST_PG_BIN"), os.path.dirname(shutil.which("initdb") or "")]
    candidates += sorted(glob.glob("/opt/homebrew/opt/postgresql@*/bin"), reverse=True)
    candidates += sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True)
    for candidate in filter(None, candidates):
        if (Path(candidate) / "initdb").exists() and (Path(candidate) / "pg_ctl").exists():
            return Path(candidate)
    return None


@pytest.fixture(scope="session")
def postgres() -> Iterator[str]:
    """A PostgreSQL server for the store's tests: CUNHO_TEST_POSTGRES_URL when CI gives one, otherwise a throwaway
    cluster on a Unix socket in a short directory under /tmp (socket paths are limited to about 100 bytes)."""
    given = os.environ.get("CUNHO_TEST_POSTGRES_URL")
    if given:
        yield given
        return
    binaries = _postgres_bin()
    if binaries is None:
        pytest.skip("PostgreSQL is not installed")
    root = Path(tempfile.mkdtemp(prefix="cpg", dir="/tmp"))
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    run = lambda *args: subprocess.run([str(a) for a in args], check=True, capture_output=True, env=env)  # noqa: E731
    run(binaries / "initdb", "-D", root / "data", "-A", "trust", "-U", "cunho", "--no-sync", "-E", "UTF8", "--locale=C")
    options = f"-k {root} -c listen_addresses='' -p 5433 -F"
    run(binaries / "pg_ctl", "-D", root / "data", "-o", options, "-l", root / "log", "-w", "start")
    try:
        yield f"postgresql://cunho@/postgres?host={root}&port=5433"
    finally:
        subprocess.run([str(binaries / "pg_ctl"), "-D", str(root / "data"), "-m", "immediate", "stop"], env=env)
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def pg_url(postgres: str) -> Iterator[str]:
    """A new, empty database on the test server, dropped afterwards."""
    psycopg = pytest.importorskip("psycopg")
    name = f"cunho_{secrets.token_hex(6)}"
    with psycopg.connect(postgres, autocommit=True) as admin:
        admin.execute(f"CREATE DATABASE {name}")
    try:
        yield with_database(postgres, name)
    finally:
        with psycopg.connect(postgres, autocommit=True) as admin:
            admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
