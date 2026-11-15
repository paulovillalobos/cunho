# Stress run, 2026-11-05, at the end of M2

Full run of `tools/stress` (all six suites, full durations, the 30-minute soak) against commit `8a17f3c`,
every suite PASS, 101 checks. Same machine and method as `../2026-11-04-709a9a4/` (Apple Silicon, macOS
26.5, Python 3.12.15, everything on localhost, the harness run from a fresh clone of that commit). Scratch
paths are shown as `/tmp/cunho-under-test`, `/tmp/cunho-stress-out` and `/tmp/cunho-stress-work`.

| suite | checks | verdict | seconds |
|---|---|---|---|
| suite1_load | 11 | PASS | 45.1 |
| suite2_races | 12 | PASS | 7.3 |
| suite3_fuzz | 19 | PASS | 99.5 |
| suite4_attack | 23 | PASS | 4.8 |
| suite5_chaos | 28 | PASS | 51.0 |
| suite6_soak | 8 | PASS | 1820.3 |

`8a17f3c` is the commit two reviews in a row found nothing in (the second reviewer's nineteenth and
twentieth looks), after the fixes for CX-5 to CX-30 (`research/cunho-m2-fixes.md`): the clock base kept
under a MAC and anchored outside the database for a forced run, read from the store at every reading of
the time, and read inside every transaction whose writes it decides.

What this run shows:
- Load: full flows with no 5xx and no errors at 10 to 200 clients, on one worker and on four sharing one
  SQLite file. One worker issued 107 to 182 a second; four issued fewer, 46 to 119, since SQLite takes one
  writer at a time, as `DESIGN.md` says.
- A status list with 100,000 hidden bits, polled by eight clients on one worker: about 2,030 answers a
  second, with the metadata endpoint of the same worker at p50 2.9 ms and p95 4.1 ms meanwhile. Since
  CX-14 the status route runs in the thread pool, cached tokens too.
- The race, fuzz and attack suites: every single-use operation once, no input reaching a 5xx, every attack
  refused.
- The chaos suite: kill and restart, a locked database, a full disk, a torn and a NUL-tailed anchor, each
  repaired and declared, and a 400-day wall-clock jump that the maintenance run goes through on the host
  clock, pruning and sweeping nothing.
- The soak, 30 minutes with a 60-second maintenance interval: 124,771 full flows with no error and no 5xx,
  RSS flat (67 MB early, 65 MB late, peak 76 MB), no expired row older than 56 seconds left behind,
  maintenance seen 20 times off the request path, the log verified 26 times under load, and at the end its
  285,031 entries against all 285,032 anchor lines.
- As before, the harness publishes revocations at the next publication (`CUNHO_STATUS_REVOCATION_JITTER=0`,
  `CUNHO_STATUS_PUBLISH_INTERVAL=1`), because its suites read a status bit right after revoking it; the
  moments of revocations are tested in `tests/engine/test_review7_clock.py` and `tests/slow/test_model.py`.
