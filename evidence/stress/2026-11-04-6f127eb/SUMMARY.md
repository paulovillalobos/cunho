# cunho stress & security harness - results

- source: `/tmp/cunho-under-test` at commit `6f127eb`
- mode: **full**
- python 3.12.15 on macOS-26.5.1-arm64-arm-64bit
- generated: 2026-11-04 07:48:36

| suite | pass | fail | total | verdict | seconds |
|---|---|---|---|---|---|
| suite1_load.py | 10 | 0 | 10 | PASS | 6.7 |
| suite2_races.py | 11 | 0 | 11 | PASS | 6.1 |
| suite3_fuzz.py | 15 | 0 | 15 | PASS | 20.6 |
| suite4_attack.py | 23 | 0 | 23 | PASS | 3.4 |
| suite5_chaos.py | 20 | 0 | 20 | PASS | 48.3 |
| suite6_soak.py | 7 | 0 | 7 | PASS | 1819.4 |

## Failed checks (findings)

_None - every check passed._
