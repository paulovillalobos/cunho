# cunho stress & security harness - results

- source: `/tmp/cunho-under-test` at commit `f98f87d`
- mode: **full**
- python 3.12.15 on macOS-26.5.1-arm64-arm-64bit
- generated: 2026-11-04 04:35:14

| suite | pass | fail | total | verdict | seconds |
|---|---|---|---|---|---|
| suite1_load.py | 10 | 0 | 10 | PASS | 5.2 |
| suite2_races.py | 11 | 0 | 11 | PASS | 5.7 |
| suite3_fuzz.py | 13 | 0 | 13 | PASS | 19.3 |
| suite4_attack.py | 23 | 0 | 23 | PASS | 3.2 |
| suite5_chaos.py | 20 | 0 | 20 | PASS | 47.6 |
| suite6_soak.py | 7 | 0 | 7 | PASS | 1824.8 |

## Failed checks (findings)

_None - every check passed._
