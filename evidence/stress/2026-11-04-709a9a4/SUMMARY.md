# cunho stress & security harness - results

- source: `/tmp/cunho-under-test` at commit `709a9a4`
- mode: **full**
- python 3.12.15 on macOS-26.5.1-arm64-arm-64bit
- generated: 2026-11-04 15:30:30

| suite | pass | fail | total | verdict | seconds |
|---|---|---|---|---|---|
| suite1_load.py | 11 | 0 | 11 | PASS | 37.3 |
| suite2_races.py | 12 | 0 | 12 | PASS | 6.1 |
| suite3_fuzz.py | 19 | 0 | 19 | PASS | 25.5 |
| suite4_attack.py | 23 | 0 | 23 | PASS | 3.2 |
| suite5_chaos.py | 28 | 0 | 28 | PASS | 49.9 |
| suite6_soak.py | 8 | 0 | 8 | PASS | 1822.6 |

## Failed checks (findings)

_None - every check passed._
