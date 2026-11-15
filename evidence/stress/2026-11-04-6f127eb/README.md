# Stress run, 2026-11-04, after the third review

Full run of `tools/stress` (all six suites, 30-minute soak) against commit `6f127eb`, every suite
PASS, 86 checks. Same machine and method as `../2026-11-04-f98f87d/` (Apple Silicon, macOS 26.5,
Python 3.12.15, everything on localhost, the harness from a fresh clone of that commit). Scratch
paths are shown as `/tmp/cunho-under-test` and `/tmp/cunho-stress-work`.

| suite | checks | verdict |
|---|---|---|
| suite1_load | 10 | PASS |
| suite2_races | 11 | PASS |
| suite3_fuzz | 15 | PASS |
| suite4_attack | 23 | PASS |
| suite5_chaos | 20 | PASS |
| suite6_soak | 7 | PASS |

The full mode was used because the third round changed the store (no sweep inside requests,
batched background sweeps), the rate limiter (three numbers per client) and the audit paths
(whole-anchor verification, no anchor created over an existing log, pruning stopped at the anchor).

What this run shows:

- 1 worker: about 460 to 470 flows/s from 50 to 200 concurrent wallets (p95 139 ms at 50, 416 ms
  at 200). 4 workers on one SQLite file: about 240 to 250 flows/s (p95 1,025 ms at 200). Several
  workers are still correct but not faster on SQLite.
- The fuzz suite now signs DPoP proofs and key proofs whose claims carry arbitrary values (huge
  integers included), so the checks after the signature are reached; no 5xx (N3-M1, N3-L4).
- The soak ran with a 60-second maintenance interval: 20 background maintenance runs seen, 331,093
  full flows with no error and no 5xx, RSS flat (86 MB early, 88 MB late), the oldest expired row
  never older than 54 s although requests no longer sweep, and at the end the audit chain of 738,183
  entries verified against all 738,184 anchor lines (the genesis line and one per entry).
- The harness publishes revocations at once (`CUNHO_STATUS_REVOCATION_JITTER=0`), because its
  suites read a status bit right after revoking it; the spread over time is tested in
  `tests/engine/test_review3_fixes.py`.
- The first full run of this round, against `463d533`, passed every check but one: the soak still
  looked for the single `scheduled_until` key that each status list now keeps for itself, so it saw
  no maintenance runs. The harness was fixed in `6f127eb` and this run started from a fresh clone.
