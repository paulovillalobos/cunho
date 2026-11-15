# cunho stress and security harness

A load, race, fuzz, attack, chaos and soak harness for cunho. It starts a throwaway cunho from a
given checkout on a free local port over TLS with uvicorn, drives it like a wallet and an operator,
and writes a PASS/FAIL summary with JSON. Everything runs on localhost; nothing leaves the machine.

Run it after every round of fixes, against a fresh clone of the branch under test.

## Setup

The harness needs cunho's runtime dependencies plus `hypothesis` and `psutil` (the `stress`
dependency group in `pyproject.toml`):

```bash
uv pip install --python .venv hypothesis psutil     # or a separate venv in tools/stress/.venv
```

`run_all.sh` uses `$CUNHO_STRESS_PYTHON` if set, else `tools/stress/.venv`, else the repo's `.venv`.
cunho and the probe are imported from the checkout under test through `PYTHONPATH`, so the same
Python can test any checkout without reinstalling.

## How to run

```bash
# Everything, full durations (the soak runs 30 minutes), against a fresh clone:
git clone . /tmp/cunho-under-test
tools/stress/run_all.sh /tmp/cunho-under-test --out /tmp/stress-out

# Fast self-test (short durations, about 2 minutes):
tools/stress/run_all.sh /tmp/cunho-under-test --quick --out /tmp/stress-quick

# A subset, custom soak length:
tools/stress/run_all.sh /tmp/cunho-under-test --suites 1,2,4 --soak-seconds 600
```

A single suite runs on its own with `CUNHO_SRC` set to the checkout:

```bash
CUNHO_SRC=/tmp/cunho-under-test .venv/bin/python tools/stress/suite2_races.py /tmp/stress-out --quick
```

The runner makes a dev PKI with the checkout's own `tools/dev_pki.py`, starts cunho once over TLS
for a sanity flow, then runs each suite as its own process, because the suites need different
worker counts (1 or 4), stores and rate limits. Results: `SUMMARY.md`, `summary.json` and one
`suiteN_*.json` per suite in `--out`, with the commit under test. Scratch files (PKI, SQLite
stores, server logs) go to `$CUNHO_STRESS_WORK`, by default `tools/stress/_work`, which git
ignores. The exit code is 0 only if every suite passes.

With `CUNHO_STRESS_STORE_URL` set to an empty PostgreSQL database, the servers of a suite use it
instead of a SQLite file (suites 2 and 3; give each run a fresh database).

## Rate limits

cunho limits `/token`, `/nonce` and failed operator logins per client address
(`CUNHO_RATE_LIMIT_PER_MINUTE`, default 120). All harness traffic comes from 127.0.0.1, but the load,
race, fuzz, chaos and soak suites stand for many different wallets, so they start cunho with a very
high limit (`common.HIGH_RATE_LIMIT`). The attack suite keeps the default and checks that the
limiter answers floods with 429 and never with 5xx.

## What each suite checks

**suite1_load**: concurrent wallets (10, 50, 100, 200; quick: 10, 50) doing full flows (offer, token,
nonce, credential) against 1 worker and against 4 workers sharing one SQLite store. Reports
throughput, p50/p95/p99 latency, error rate, the first error and server RSS. PASS per level: no 5xx
or transport error and at most 1% failed flows; RSS peak under 1500 MB.

**suite2_races** (4 workers, one SQLite store): fires N requests at once and asserts the exact number
of successes. Same pre-authorized code: 1. Same c_nonce: 1. Same DPoP proof: 1. One access token
for one configuration: 1. tx_code brute force: 0, at most `tx_code_max_attempts` guesses compared
however many arrive together, and the lockout holds. Concurrent revocations of one subject: no 5xx,
no double counting. Concurrent offer creation: all 201. `/admin/audit/verify` while four threads create
offers on the four workers: valid every time, since nothing was tampered with. The authorization code
flow, each race sent by one wallet: the same pushed `request_uri` at `/authorize`: 1 login. The same
`login_state` reported by the login service: 1. The same wallet attestation proof of possession at PAR: 1.
The same authorization code redeemed: 1 token, and the uses after it end that token and its refresh token.
Refreshes of one login racing the revocation of its subject: no 5xx, and no token works once the
revocation has answered. Afterwards the audit chain verifies.

**suite3_fuzz**: Hypothesis over every endpoint (no 5xx, no answer slower than 2 s) and over
`jose.parse_jws`, `jose.public_key_from_jwk`, `jose.load_x5c` and `validate_path`,
`credentials.validate_subject` and `validate_pid`, `metadata.validate`, `jose.strict_json` and the
status-list encoding: each returns or raises its declared exception, never crashes or hangs, and
traced memory stays bounded. Text includes lone UTF-16 surrogates, NUL and other characters that cannot
be encoded: Hypothesis never puts a surrogate in `st.text()`, whatever its alphabet, so the suite joins
strings from single characters. A real key attestation signer certificate is fuzzed byte by byte, in
`load_x5c` and `validate_path` and as a correctly signed key attestation over HTTP. The Commission's list
of wallet providers goes through `lote.read_lote` as raw bytes and as lists the pinned signer signed with
one member changed to an arbitrary value. The authorization code flow: PAR with arbitrary forms and bodies,
with wallet attestations and their proofs of possession correctly signed but carrying arbitrary claims,
and with the wallet attestation signer's certificate changed byte by byte; `/authorize` with arbitrary
queries; and the code grant at `/token` with arbitrary fields. An unaltered PAR is checked to be accepted
first, so the fuzz is known to reach past the attestation checks.

**suite4_attack**: alg confusion (`none`, HS256 keyed with the public key, an ES256 signature over a
P-384 key), oversized and duplicated headers, unicode and control characters in every field, very
long URLs, path traversal on `/status` and `/admin`, timing of the operator token comparison,
slowloris, a 20-certificate key-attestation chain, expired and not-yet-valid certificates, a CA
certificate as the key-attestation signer, JWKs with huge coordinates, a credential request with
10,000 proofs. Each is refused cleanly: 4xx, no 5xx, no hang, nothing issued. Last come floods on
`/nonce`, `/token` and failed operator logins: 429 with `Retry-After` once over the limit, never
5xx, bounded memory, and an authenticated operator is still served.

**suite5_chaos**: `kill -9` mid-flow and restart on the same SQLite store (revocations, tokens, the
audit chain survive); the store locked by another connection for longer than cunho's 30-second busy
timeout (issuance fails closed with a JSON error, then recovers with a valid audit chain); disk full
through a fault-injecting store wrapper, on every write and on the audit writes only (no credential
without its audit entry, no valid status slot left behind, chain valid, recovery); a full disk under
the audit anchor file (a line torn half-way after a commit, which is answered as done; the next action
refused while there is no room; then the torn line repaired, logged, and the chain valid); clock jumps
of 400 days forward during maintenance (nothing pruned or swept, and maintenance runs again once the
clock is back), 10 days forward and 20 back (expired artefacts refused cleanly, chain valid). The chaos
parts log tracebacks for the injected faults; that is expected.

**suite6_soak**: mixed traffic (full flows, nonces, status lists, offers, revocations) for 30 minutes
(quick: 20 s), sampling RSS and the SQLite store. cunho runs with `CUNHO_MAINTENANCE_INTERVAL=60`
(quick: 5), so the soak covers many background maintenance runs; the suite checks that they happened
and that the audit chain verifies against its anchor file while the traffic runs (every 60 s; quick:
2 s), with no false alarm, and at the end. PASS: no 5xx, at most 1% failed flows, RSS late
median under twice the early median and peak under 1500 MB, no expired row older than 180 s
(cunho sweeps at least every 60 s), and short-lived protocol state levelling off in the second
half of a long run. Audit entries, status slots and issued-credential records grow with issuance by
design.
