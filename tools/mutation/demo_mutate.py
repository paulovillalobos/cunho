"""Mutation run over the demo service (src/cunho_demo): break one guard at a time and expect tests/demo to fail.

The engine's run (mutate.py) covers src/cunho; the demo service is a front end beside it, with guards of its own:
same-origin forms and JSON, rate limits, the session table's bounds, the visitor's scope, the console's password
and tokens, the steps the page shows. Each mutant in DEMO_PATCHES is a hand-written change to one of them, applied
to a scratch copy of the checkout (the checkout itself is never changed); it is KILLED when `pytest tests/demo -x`
fails there. A patch whose old text does not occur exactly once stops the run: it has to follow the code.

Usage: python tools/mutation/demo_mutate.py [--jobs 3] [--only TEXT] [--list]
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from demo_patches import DEMO_PATCHES  # noqa: E402

COPY = ("src", "probe", "tests", "demo", "pyproject.toml")


def check(patches: list[tuple[str, str, str, str]]) -> None:
    for label, file, old, _ in patches:
        count = (ROOT / "src" / "cunho_demo" / file).read_text().count(old)
        if count != 1:
            raise SystemExit(f"{label}: its old text occurs {count} times in {file}; update the patch with the code")


def run(label: str, file: str, old: str, new: str, timeout: int) -> tuple[str, bool, float, str]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cunho-demo-mutation-") as scratch:
        root = Path(scratch)
        for name in COPY:
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, root / name, ignore=shutil.ignore_patterns("__pycache__", "_work", "_suite"))
            else:
                shutil.copy(source, root / name)
        target = root / "src" / "cunho_demo" / file
        target.write_text(target.read_text().replace(old, new, 1))
        command = [sys.executable, "-m", "pytest", "tests/demo", "-x", "-q", "-p", "no:cacheprovider", "-rfE"]
        try:
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return label, True, time.monotonic() - started, "timeout"
    first = next((line for line in result.stdout.splitlines() if line.startswith(("FAILED", "ERROR"))), "")
    return label, result.returncode != 0, time.monotonic() - started, first or f"pytest exit {result.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jobs", type=int, default=3)
    parser.add_argument("--only", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    check(DEMO_PATCHES)
    chosen = [p for p in DEMO_PATCHES if args.only in p[0]]
    if args.list:
        for label, file, _, _ in chosen:
            print(f"{file}: {label}")
        print(f"{len(chosen)} mutants")
        return 0
    clean = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/demo", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if clean.returncode != 0:
        raise SystemExit("tests/demo fails before any mutation:\n" + clean.stdout[-2000:])
    survivors = []
    with ThreadPoolExecutor(args.jobs) as pool:
        for label, killed, seconds, first in pool.map(lambda p: run(p[0], p[1], p[2], p[3], 300), chosen):
            print(f"{'KILLED  ' if killed else 'SURVIVED'} {label} ({seconds:.0f} s) {first}", flush=True)
            if not killed:
                survivors.append(label)
    print(f"{len(chosen) - len(survivors)}/{len(chosen)} killed; survivors: {survivors or 'none'}")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
