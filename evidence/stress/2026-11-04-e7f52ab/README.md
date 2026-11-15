# Stress run, 2026-11-04, after the fourth review

Full run of `tools/stress` (all six suites, 30-minute soak) against commit `e7f52ab`, every suite
PASS, 97 checks. Same machine and method as `../2026-11-04-6f127eb/` (Apple Silicon, macOS 26.5,
Python 3.12.15, everything on localhost, the harness from a fresh clone of that commit). Scratch
paths are shown as `/tmp/cunho-under-test` and `/tmp/cunho-stress-work`.

| suite | checks | verdict |
|---|---|---|
| suite1_load | 10 | PASS |
| suite2_races | 12 | PASS |
| suite3_fuzz | 19 | PASS |
| suite4_attack | 23 | PASS |
| suite5_chaos | 25 | PASS |
| suite6_soak | 8 | PASS |

The full mode was used because the fourth round changed the audit anchor (torn-line repair, the
missing lines written before the next change, verification against one snapshot), the status token's
schedule, revocation and issuance transactions, the memory and SQLite stores (rollback, a bounded WAL
checkpoint) and maintenance (the clock watch), and because the review found blind spots in the
harness itself (N4-L7).

What this run shows:

- 1 worker: about 466 to 472 flows/s from 50 to 200 concurrent wallets (p95 139 ms at 50, 412 ms
  at 200). 4 workers on one SQLite file: about 240 to 266 flows/s (p95 923 ms at 200). Several
  workers are still correct but not faster on SQLite.
- New this round, and passing: `/admin/audit/verify` answered valid 50 times out of 50 while four
  threads created 1,486 offers on four workers (N4-M7); the fuzz suite drew text with lone surrogates
  and NUL, fuzzed `strict_json` and JWS payloads, and changed bytes of a key attestation signer
  certificate in-process and signed over HTTP, with no unhandled exception and no 5xx (N4-M1, N4-M2);
  a full disk under the anchor file gave 201 for the committed offer, a clean refusal while there was
  no room, then a repaired, logged torn line and a valid chain (N4-M4); maintenance during a 400-day
  clock jump pruned and swept nothing and ran again once the clock was back (N4-M8).
- The soak ran with a 60-second maintenance interval: 23 background maintenance runs seen, 315,334
  full flows with no error and no 5xx, RSS flat (84 MB early, 74 MB late), the oldest expired row
  never older than 46 s, and short-lived state levelling off. The audit log was verified 27 times
  while the traffic ran, valid every time, and at the end its 720,864 entries verified against all
  720,865 anchor lines (the genesis line and one per entry).
- The harness publishes revocations at once (`CUNHO_STATUS_REVOCATION_JITTER=0`), because its
  suites read a status bit right after revoking it; the token schedule and the spread over time are
  tested in `tests/engine/test_review3_fixes.py` and `tests/engine/test_review4_fixes.py`.
