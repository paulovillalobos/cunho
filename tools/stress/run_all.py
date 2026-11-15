#!/usr/bin/env python3
"""cunho stress & security harness - one runner for all six suites.

Usage:
    run_all.py SOURCE_DIR [--quick] [--out DIR] [--soak-seconds N] [--suites 1,2,4]

SOURCE_DIR is a cunho checkout (its src/cunho and tools/dev_pki.py). The runner:
  1. generates a throwaway dev PKI with SOURCE_DIR/tools/dev_pki.py,
  2. sanity-starts cunho from SOURCE_DIR on a free port over TLS (uvicorn) and stops it,
  3. runs each suite (each manages its own 1- or 4-worker TLS server as it needs),
  4. writes per-suite JSON + a markdown summary into the output directory.

Scratch files go to $CUNHO_STRESS_WORK (default tools/stress/_work); results to --out
(default $CUNHO_STRESS_WORK/out).
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

HARNESS = Path(__file__).resolve().parent
SUITES = {
    1: "suite1_load.py",
    2: "suite2_races.py",
    3: "suite3_fuzz.py",
    4: "suite4_attack.py",
    5: "suite5_chaos.py",
    6: "suite6_soak.py",
}


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("--"):
        print(__doc__)
        return 2
    source = Path(argv[0]).resolve()
    quick = "--quick" in argv
    work = Path(os.environ.get("CUNHO_STRESS_WORK") or HARNESS / "_work").resolve()
    out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else work / "out"
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    soak_seconds = argv[argv.index("--soak-seconds") + 1] if "--soak-seconds" in argv else None
    which = [int(x) for x in argv[argv.index("--suites") + 1].split(",")] if "--suites" in argv else list(SUITES)

    env = dict(
        os.environ,
        CUNHO_SRC=str(source),
        CUNHO_STRESS_WORK=str(work),
        PYTHONPATH=os.pathsep.join([str(source / "src"), str(source / "probe")]),
    )

    print(
        f"== cunho stress harness ==\n  source : {source}\n  out    : {out}\n  mode   : "
        f"{'quick' if quick else 'full'}\n  suites : {which}\n"
    )

    # 1 + 2: generate a dev PKI and sanity-start/stop cunho over TLS, from the given source dir.
    sys.path.insert(0, str(HARNESS))
    os.environ["CUNHO_SRC"] = str(source)
    os.environ["CUNHO_STRESS_WORK"] = str(work)
    import common  # noqa: E402  (imported after CUNHO_SRC is set)

    pki = common.gen_pki(work / "runall")
    print("  dev PKI generated.")
    srv = common.Server(pki=pki, workers=1, rate_limit=common.HIGH_RATE_LIMIT).start()
    ok, detail = common.new_wallet(srv).full_flow()
    print(f"  sanity server at {srv.issuer_url}: full flow -> {ok} ({detail})")
    srv.stop()
    if not ok:
        print("  WARNING: sanity flow failed; suites may not run meaningfully.")

    # 3: run the suites as isolated subprocesses.
    results = {}
    for n in which:
        script = SUITES[n]
        cmd = [sys.executable, str(HARNESS / script), str(out)]
        if quick:
            cmd.append("--quick")
        if n == 6 and soak_seconds:
            cmd += ["--seconds", str(soak_seconds)]
        print(f"\n----- running {script} -----", flush=True)
        t0 = time.time()
        rc = subprocess.run(cmd, env=env).returncode
        jpath = out / f"{Path(script).stem}.json"
        if jpath.exists():
            results[script] = json.loads(jpath.read_text())
        else:
            results[script] = {
                "suite": Path(script).stem,
                "ok": False,
                "error": f"no output (rc={rc})",
                "passed": 0,
                "total": 0,
                "duration_s": round(time.time() - t0, 1),
                "checks": [],
            }

    write_summary(out, source, quick, results)
    overall_ok = all(r.get("ok") for r in results.values())
    print(f"\n===== OVERALL: {'PASS' if overall_ok else 'FAIL'} =====")
    return 0 if overall_ok else 1


def source_commit(source: Path) -> str:
    try:
        rev = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return rev + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def write_summary(out: Path, source: Path, quick: bool, results: dict) -> None:
    summary = {
        "source": str(source),
        "commit": source_commit(source),
        "mode": "quick" if quick else "full",
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "suites": {
            k: {kk: v[kk] for kk in ("passed", "failed", "total", "ok", "duration_s") if kk in v}
            for k, v in results.items()
        },
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2))

    lines = [
        "# cunho stress & security harness - results",
        "",
        f"- source: `{source}` at commit `{summary['commit']}`",
        f"- mode: **{summary['mode']}**",
        f"- python {summary['python']} on {summary['platform']}",
        f"- generated: {summary['generated']}",
        "",
        "| suite | pass | fail | total | verdict | seconds |",
        "|---|---|---|---|---|---|",
    ]
    for script, r in results.items():
        verdict = "PASS" if r.get("ok") else "FAIL"
        lines.append(
            f"| {script} | {r.get('passed', 0)} | {r.get('failed', 0)} | "
            f"{r.get('total', 0)} | {verdict} | {r.get('duration_s', '?')} |"
        )
    lines += ["", "## Failed checks (findings)", ""]
    any_fail = False
    for script, r in results.items():
        fails = [c for c in r.get("checks", []) if not c.get("pass")]
        if r.get("error"):
            lines.append(f"- **{script}**: {r['error']}")
            any_fail = True
        for c in fails:
            any_fail = True
            detail = {k: v for k, v in c.items() if k not in ("check", "pass")}
            lines.append(f"- **{script}** - {c['check']}  `{json.dumps(detail, default=str)}`")
    if not any_fail:
        lines.append("_None - every check passed._")
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n")
    print(f"\n  wrote {out / 'SUMMARY.md'} and {out / 'summary.json'}")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
