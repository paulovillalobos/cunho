# Stress run, 2026-11-04

Full run of `tools/stress` (all six suites, 30-minute soak) against commit `c306b09`, every suite
PASS. Produced on one laptop (Apple Silicon, macOS 26.5, Python 3.12.15), everything on localhost:

```bash
git clone <cunho repository> /tmp/cunho-under-test
CUNHO_STRESS_PYTHON=<python with cunho's dependencies, hypothesis and psutil> \
  /tmp/cunho-under-test/tools/stress/run_all.sh /tmp/cunho-under-test --out out
```

The harness used is the one inside that clone, so the results match the code and the harness at
the same commit. The clone lived in a scratch directory; its path is shown as
`/tmp/cunho-under-test` in these files. Nothing else was edited.

| suite | checks | verdict |
|---|---|---|
| suite1_load | 10 | PASS |
| suite2_races | 11 | PASS |
| suite3_fuzz | 13 | PASS |
| suite4_attack | 23 | PASS |
| suite5_chaos | 20 | PASS |
| suite6_soak | 5 | PASS |

Headline numbers (a flow is offer, token, nonce and credential: four requests and one signed
SD-JWT VC; the load client runs on the same machine):

- 1 worker: about 390 flows/s from 50 to 200 concurrent wallets; p95 137 ms at 50, 495 ms at 200.
- 4 workers on one SQLite file: about 340 flows/s at 100 to 200 wallets; p95 740 ms at 200.
  Correct, but not faster: SQLite takes one writer at a time.
- Server RSS: peak 145 MB (1 worker), 387 MB (4 workers together); soak 80 MB early, 69 MB late.
- Soak: 263,545 flows, 301,490 nonces, 112,836 status-list reads, 22,451 revocations, no error.
  No expired row was older than 60 s; short-lived rows levelled off at about 420,000.
- Floods from one address with the default limit (120 per minute): 3,885 of 4,000 nonce requests
  and every failed operator login past the limit got 429 with `Retry-After`, none got 5xx.

What the soak also shows: the store grew to 1.5 million rows and 867 MB in 30 minutes. Audit
entries (kept for `CUNHO_AUDIT_RETENTION_DAYS`), status-list slots and issued-credential records
grow with issuance by design; size the disk for the expected issuance volume and retention.

The defects this harness found, and their regression tests, are in
`tests/engine/test_stress_fixes.py`.
