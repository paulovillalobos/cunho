# Stress run, 2026-11-04, after the fifth review

Full run of `tools/stress` (all six suites, 30-minute soak) against commit `709a9a4`, every suite
PASS, 101 checks. Same machine and method as `../2026-11-04-e7f52ab/` (Apple Silicon, macOS 26.5,
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

The full mode was used because the fifth round changed the audit anchor (damage of any shape closed
and declared, the repair entry in its own transaction, verify going on from a checkpoint pruning
made meanwhile), the status list (fixed publications from a queue of due bits, a rate limit, off the
event loop), revocation (the subject closed whatever the vault holds, person handles), the clock watch
(the host's own clock) and the audit entry times, and because the review found blind spots in the
harness itself (N5-L9).

An earlier full run, against `31615bf`, failed: its soak server stopped answering within a minute,
and the last verification timed out. A request logging an entry held the store and asked the clock
watch for the range a reading should fall in, while the background tick held the watch's lock and
wrote the store. `fe0761c` reads that range without the lock, with a test that deadlocked every time
on the old code, and `709a9a4` gives the soak's last verification the ten minutes the others already
had: at about 13 microseconds an entry, the default ten seconds no longer fit the log a full soak
leaves.

What this run shows:

- 1 worker: about 427 to 447 flows/s from 50 to 200 concurrent wallets (p95 118 ms at 50, 444 ms
  at 200). 4 workers on one SQLite file: about 246 to 259 flows/s (p95 1,015 ms at 200). Several
  workers are still correct but not faster on SQLite.
- New this round, and passing: a status list with 100,000 hidden bits, as a mass revocation leaves
  it, polled by eight clients on one worker: 5,207 answers a second, with the metadata endpoint of
  the same worker at p50 1.7 ms and p95 2.8 ms meanwhile (review 5 measured 4 answers a second and
  metadata up to 2 s). The chaos suite tore an anchor write, then tore the repair too (a clean 500,
  nothing changed), then closed and declared both tears when there was room; verify did not call
  the torn anchor valid; and after 4 KiB of NULs were left at the end of the file, as a power loss
  can, a restarted issuer repaired it on its first action.
- The soak ran with a 60-second maintenance interval: 20 background maintenance runs seen, 329,354
  full flows and 28,038 revocations with no error and no 5xx, RSS flat (70 MB early, 68 MB late), the
  oldest expired row never older than 54 s, and short-lived state levelling off. The audit log was
  verified 26 times while the traffic ran, valid every time, and at the end its 752,689 entries
  verified against all 752,690 anchor lines (the genesis line and one per entry).
- The harness publishes revocations at the next publication (`CUNHO_STATUS_REVOCATION_JITTER=0`,
  `CUNHO_STATUS_PUBLISH_INTERVAL=1`), because its suites read a status bit right after revoking it;
  the fixed publications, the spread over time and the cost under 100,000 hidden bits are tested in
  `tests/engine/test_review4_fixes.py`, `tests/engine/test_review5_status.py` and
  `tests/slow/test_status_load.py`.
