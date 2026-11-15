# Stress run, 2026-11-04, after the sixth review

Full run of `tools/stress` (all six suites, 30-minute soak) against commit `8684b1b`, every suite
PASS, 101 checks. Same machine and method as `../2026-11-04-709a9a4/` (Apple Silicon, macOS 26.5,
Python 3.12.15, everything on localhost, the harness from a fresh clone of that commit). Scratch
paths are shown as `/tmp/cunho-under-test` and `/tmp/cunho-stress-work`.

| suite | checks | verdict |
|---|---|---|
| suite1_load | 11 | PASS |
| suite2_races | 12 | PASS |
| suite3_fuzz | 19 | PASS |
| suite4_attack | 23 | PASS |
| suite5_chaos | 28 | PASS |
| suite6_soak | 8 | PASS |

The full mode was used because the sixth round changed the audit anchor reader (forwards only, every
line on one chain, a worker reading on from where it stopped), verify (the writer's own check under
the locks, the file read up to its size), the moments of revocations and pruning under the clock
watch, the store (a schema version and the upgrade, strict readers of a list's stored state), and
issuance (claims in one transaction, given back on failure; erasure closing the subject).

An earlier full run, against `fd87094`, failed two checks, and both were right:
- the clock-jump check of the chaos suite: under a clock 400 days ahead the background tick, which
  `6064610` had made publish whatever the clock read, published every bit that clock called due, and
  a bit once shown cannot be hidden again. `085d8e5` reverts that change; the tick publishes only
  while the clock reads steadily, as before, and DESIGN says so.
- the status fuzz target: it built a list by writing a list row without a size or published bits into
  the store, which cunho now refuses rather than answering with zeros. `8684b1b` opens the list as an
  issuance does.

What this run shows:

- 1 worker: about 180 to 296 flows/s from 10 to 200 concurrent wallets (p95 219 ms at 50, 850 ms at
  200). 4 workers on one SQLite file: about 92 to 200 flows/s (p95 1,365 ms at 200). These are lower
  than in the fifth round's run because the machine was busier this time: suite 1 run back to back
  against `382505f` and against `8684b1b` gave the same rates within a few percent (for 1 worker at
  200 wallets, 187 and 184 flows/s against 185 and 195).
- A status list with 100,000 hidden bits, polled by eight clients on one worker: 2,970 answers a
  second, with the metadata endpoint of the same worker at p50 3.0 ms and p95 5.4 ms meanwhile.
- The chaos suite tore an anchor write, then the repair too, then closed and declared both when there
  was room; left 4 KiB of NULs at the end of the file, which a restarted issuer repaired on its first
  action; and jumped the clock 400 days ahead, with nothing pruned, swept or published meanwhile.
- The soak ran with a 60-second maintenance interval: 19 background maintenance runs seen, 234,542
  full flows and 20,161 revocations with no error and no 5xx, RSS flat (79 MB early, 70 MB late), the
  oldest expired row never older than 52 s, and short-lived state levelling off. The audit log was
  verified 27 times while the traffic ran, valid every time, and at the end its 535,855 entries
  verified against all 535,856 anchor lines.
- The harness publishes revocations at the next publication (`CUNHO_STATUS_REVOCATION_JITTER=0`,
  `CUNHO_STATUS_PUBLISH_INTERVAL=1`), because its suites read a status bit right after revoking it;
  the moments of revocations under a wrong clock are tested in `tests/engine/test_review6_clock.py`
  and `tests/slow/test_model.py`.
