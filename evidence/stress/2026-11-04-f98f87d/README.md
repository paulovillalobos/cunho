# Stress run, 2026-11-04, after the second review

Full run of `tools/stress` (all six suites, 30-minute soak) against commit `f98f87d`, every suite
PASS. Same machine and method as `../2026-11-04/` (Apple Silicon, macOS 26.5, Python 3.12.15,
everything on localhost, the harness from a fresh clone of that commit). Scratch paths are shown as
`/tmp/cunho-under-test` and `/tmp/cunho-stress-work`.

| suite | checks | verdict |
|---|---|---|
| suite1_load | 10 | PASS |
| suite2_races | 11 | PASS |
| suite3_fuzz | 13 | PASS |
| suite4_attack | 23 | PASS |
| suite5_chaos | 20 | PASS |
| suite6_soak | 7 | PASS |

What changed since the earlier run, and what this run shows:

- Every audit entry is now also appended, with an fsync, to the anchor file. 1 worker: about 470 to
  490 flows/s from 50 to 200 concurrent wallets (p95 121 ms at 50, 396 ms at 200). 4 workers on one
  SQLite file: about 260 to 280 flows/s (p95 991 ms at 200). Several workers are still correct but
  not faster on SQLite.
- The soak ran cunho with a 60-second maintenance interval: 20 background maintenance runs were seen,
  349,691 full flows with no error and no 5xx, RSS flat (83 MB early, 76 MB late), and at the end the
  audit chain of 778,920 entries verified against 778,920 anchor lines.
- The first full run of these changes, against `c7c8021`, failed one fuzz check: `validate_pid`
  raised `TypeError` on an object where a code belongs. That run was stopped, the defect fixed in
  `f98f87d` with a regression test, and this run started from a fresh clone.
