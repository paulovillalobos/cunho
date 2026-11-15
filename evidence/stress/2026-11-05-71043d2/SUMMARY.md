# cunho stress & security harness - results

- source: `/tmp/cunho-under-test` at commit `71043d2`
- mode: **quick**
- python 3.12.15 on macOS-26.5.1-arm64-arm-64bit
- generated: 2026-11-05 03:01:22

| suite | pass | fail | total | verdict | seconds |
|---|---|---|---|---|---|
| suite1_load.py | 7 | 0 | 7 | PASS | 14.4 |
| suite2_races.py | 12 | 0 | 12 | PASS | 6.7 |
| suite3_fuzz.py | 19 | 0 | 19 | PASS | 25.4 |
| suite4_attack.py | 23 | 0 | 23 | PASS | 4.1 |
| suite5_chaos.py | 28 | 0 | 28 | PASS | 50.8 |
| suite6_soak.py | 7 | 0 | 7 | PASS | 26.0 |

## Failed checks (findings)

_None - every check passed._
