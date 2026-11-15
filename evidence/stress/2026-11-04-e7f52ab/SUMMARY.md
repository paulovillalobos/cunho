# cunho stress & security harness - results

- source: `/tmp/cunho-under-test` at commit `e7f52ab`
- mode: **full**
- python 3.12.15 on macOS-26.5.1-arm64-arm-64bit
- generated: 2026-11-04 10:13:55

| suite | pass | fail | total | verdict | seconds |
|---|---|---|---|---|---|
| suite1_load.py | 10 | 0 | 10 | PASS | 5.7 |
| suite2_races.py | 12 | 0 | 12 | PASS | 6.3 |
| suite3_fuzz.py | 19 | 0 | 19 | PASS | 24.3 |
| suite4_attack.py | 23 | 0 | 23 | PASS | 3.0 |
| suite5_chaos.py | 25 | 0 | 25 | PASS | 47.7 |
| suite6_soak.py | 8 | 0 | 8 | PASS | 1818.2 |

## Failed checks (findings)

_None - every check passed._
