# Stress run, 2026-11-05, after the seventh review

Quick run of `tools/stress` (all six suites, short durations, a 26-second soak) against commit `71043d2`,
every suite PASS, 96 checks. Same machine and method as `../2026-11-04-8684b1b/` (Apple Silicon, macOS
26.5, Python 3.12.15, everything on localhost, the harness from a fresh clone of that commit), but in
quick mode: the full run with the 30-minute soak is left for the end of the milestone. Scratch paths are
shown as `/tmp/cunho-under-test` and `/tmp/cunho-stress-work`.

| suite | checks | verdict |
|---|---|---|
| suite1_load | 7 | PASS |
| suite2_races | 12 | PASS |
| suite3_fuzz | 19 | PASS |
| suite4_attack | 23 | PASS |
| suite5_chaos | 28 | PASS |
| suite6_soak | 7 | PASS |

The seventh round changed what cunho goes by for time (one time, the clock watch's base moved on by the
host clock, for every decision), pruning (only entries that verify in their chain), the vault's erasure,
the certificate policy check, the anchor writer, the schema upgrade and the rate limits.

The quick run before this one, against `9bc5498`, failed three checks of the chaos suite's clock jump,
and rightly for how that check was built: it ran an in-process cunho on a test clock, which has no host
clock behind it and so is the time as it reads, and a 400-day jump of it was taken for time that passed.
`71043d2` gives that check a host clock behind the clock watch, as every deployment has, jumps the wall
clock alone, and lets the ten days before the expired-code request pass on both clocks. With that, the
maintenance run during the jump prunes and sweeps nothing, runs on time once the clock is back, and the
log verifies.

What this run shows, in quick mode:
- A status list with 100,000 hidden bits, polled by eight clients on one worker: about 1,960 answers a
  second, with the metadata endpoint of the same worker at p50 4.1 ms and p95 6.8 ms meanwhile.
- The race, fuzz and attack suites: every single-use operation once, no input reaching a 5xx, every
  attack refused.
- The chaos suite: kill and restart, a locked database, a full disk, an anchor torn twice and a NUL tail,
  each repaired and declared, and the clock jumps above.
- The soak (26 seconds, a 5-second maintenance interval): 2,190 flows with no error and no 5xx, RSS flat
  (74 MB early, 75 MB late), no expired row left behind, the log verified 9 times under load, and at the
  end its 4,980 entries against all 4,981 anchor lines.
- The harness publishes revocations at the next publication (`CUNHO_STATUS_REVOCATION_JITTER=0`,
  `CUNHO_STATUS_PUBLISH_INTERVAL=1`), because its suites read a status bit right after revoking it; the
  moments of revocations under a wrong clock are tested in `tests/engine/test_review7_clock.py` and
  `tests/slow/test_model.py`.
