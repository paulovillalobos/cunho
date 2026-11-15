# cunho M2: red-team review

Repo: `~/Downloads/cunho` @ `9ea6289` ("Add the issuer engine for the pre-authorized flow").
Scope: the OpenID4VCI 1.0 pre-authorized flow, DPoP, nonce, the credential endpoint (jwt and attestation proofs), key attestations, PID as an SD-JWT VC, Token Status List draft-21, and the audit log. M3/M4 items are not reported as missing.

All 81 tests pass (`pytest tests/engine`). Every reproduction below is a script in `<scratch>/`. Each script uses `harness.py`, which builds an `Issuer` and a `TestClient` the same way `tests/engine/conftest.py` does. Run them with `~/Downloads/cunho/.venv/bin/python pN.py` from that directory.

Severity scale: **Critical** means a credential bound to a key the holder does not hold, or a forged credential. **High** means a MUST bypass, an unauthenticated denial of service, or a personal-data breach of a stated guarantee. **Medium** means a conformance gap or hardening a national PID provider would block release on. **Low** means hygiene.

No Critical finding. I found no path to a credential bound to a key whose possession was never checked, other than the trust-the-wallet-provider case in M-3.

---

## High

### H-1. A DPoP proof with `iat: NaN` passes the freshness check, so it never expires and can be replayed once the jti cache entry ages out
- **Where:** `src/cunho/oauth.py:155-157` (DPoP) and `src/cunho/proofs.py:208-210` (key proof). The root cause is `json.loads` in `src/cunho/jose.py:74-75`, which accepts `NaN` and `Infinity`.
- **Why it is wrong:** RFC 9449 §4.3 check 11 says the proof's creation time MUST be within an acceptable window. `isinstance(float('nan'), float)` is true, and `abs(now - nan) > window` is **False**, so a NaN `iat` always passes. The jti replay entry lives for `2*dpop_iat_window+5` = 125 s (`oauth.py:170`). After that, the same proof is accepted again. RFC 9449 §11.1 relies on the iat window to make a jti cache sufficient, and NaN removes that window. §11.2 (pre-generated proofs) is exactly the attack the iat window exists to stop: anyone with brief access to the key can pre-sign proofs that stay valid indefinitely.
- **Repro (`p1.py`, `p2.py`):** sign a DPoP proof whose payload text is `{"jti":"…","htm":"POST","htu":"https://issuer.test/token","iat":NaN}`. The first use returns 200. An immediate replay returns 400 (jti). After advancing the clock 10 days, a replay on a new pre-authorized code returns **200**. At the credential endpoint, the same trick yields a DPoP proof with `ath` that stays valid for the access token's whole life after the jti TTL.
- **Impact limits:** key proofs still need a single-use c_nonce, so this does not by itself mint credentials for a stolen key. It defeats a MUST and the DPoP replay model.
- **Fix:** parse every JOSE header and payload with `json.loads(..., parse_constant=_reject)` and reject duplicate member names (`object_pairs_hook`). Require `iat` to be an `int` that is not a `bool` (or a finite float), using `math.isfinite`. Add NaN, Infinity and boolean `iat` cases to the DPoP and key-proof tests.

### H-2. Unauthenticated, unbounded state growth: expired entries are never removed (memory or disk exhaustion)
- **Where:** `src/cunho/store.py:46-51`: `MemoryStore._live` deletes an expired entry only when that exact key is read again. `src/cunho/store.py:112-115`: `SqliteStore._purge` is also per key. Nothing ever sweeps either store. The writers are `oauth.py:63-67` (every `POST /nonce` stores a c_nonce), `oauth.py:170` (every DPoP jti), and `oauth.py:187` (offers).
- **Why it is wrong:** DESIGN §3 says that nothing a client sends can hurt the service, and OpenID4VCI §7 puts the nonce endpoint outside authentication. A c_nonce that nobody redeems is never read again, so it is never deleted.
- **Repro (`p6.py`):** 3,000 `POST /nonce` calls followed by a 30-day clock advance leave **3,001** live entries in `MemoryStore._data`. With SQLite, 2,000 calls leave 2,000 `c-nonce` rows after 30 days. One attacker loop on `/nonce`, with no token needed, grows memory or the database file without bound.
- **Fix:** add a periodic sweep (`DELETE FROM kv WHERE expires<=?`, plus a timed sweep in `MemoryStore`), and index `expires`. Put a global and per-IP rate limit on `/nonce` and `/token`. Alternatively, make c_nonce stateless: an HMAC'd timestamp plus a short-lived replay set bounded by the TTL.

### H-3. Personal data in the "vault" outlives its TTL indefinitely, and the crypto-shredding is illusory
- **Where:** `src/cunho/audit.py:106-123` (`Vault.put/erase`), `src/cunho/service.py:128-129`, and the same lazy expiry as H-2.
- **Why it is wrong:**
  1. An offer that is never redeemed leaves its full PID data set (name, birth date, address, portrait) in the store **forever**. The TTL is only checked if someone reads that `subject_ref` again. That breaks GDPR Art. 5(1)(e) and ARF ISSU_35b data minimisation, and it contradicts DESIGN §7.
  2. The per-subject AES key is stored in the same table, the same file, and the same backup as the ciphertext (`vault-key` beside `vault`). Deleting the key is therefore no stronger than deleting the row. SQLite runs without `secure_delete`, so the deleted rows, key included, stay readable in free pages and the WAL. The DESIGN's claim that "deleting the key erases the person" gives no security beyond a plain `DELETE`.
- **Repro (`p10.py` part 1):** create an offer and never redeem it. Advance the clock one year. Read `vault` and `vault-key` straight from the SQLite file and decrypt: the output is `Silva`.
- **Fix:** sweep expired rows (H-2). Keep vault keys in a separate key store (the KMS/HSM interface, or at least a separate file with its own lifecycle and no backups). Turn on `PRAGMA secure_delete=ON`. Add a test that inspects the SQLite file after expiry and after erase.

### H-4. Certificate path validation for key attestations is a partial RFC 5280 check
- **Where:** `src/cunho/jose.py:157-187` (`validate_path`), used for every KA in `src/cunho/proofs.py:119-123`.
- **Why it is wrong:** this check decides whether a PID is bound to a WSCD key (`KA.CHAIN_TO_WP_LIST`: ARF ISSU_21, 2979 Annex Ib TR_KA-5). The code checks the basicConstraints `cA` flag and the signature or name link, and nothing else:
  - **pathLenConstraint is ignored** (RFC 5280 §6.1.4(l)-(m)).
  - **keyUsage is ignored.** An intermediate without `keyCertSign` is accepted (§6.1.4(n)), and so is a leaf without `digitalSignature`.
  - **Unknown critical extensions are accepted** (§6.1.4(o)), and name constraints are not processed.
  - **No EKU or certificate-policy check.** Any end-entity certificate under a wallet-provider root can sign KAs, including a TLS server certificate or a WIA signer.
  - **A CA certificate is accepted as the KA signer** (the leaf's `cA=TRUE` is never rejected).
  - Expiry of the anchor is checked only on the `verify_directly_issued_by(anchor)` branch.
- **Repro (`p9.py`):** each of the following is ACCEPTED:
  - a root with `pathLen=0` that issued another CA, which issued the leaf;
  - an intermediate whose keyUsage forbids certificate signing;
  - a leaf that is a CA, carries only a serverAuth EKU, and has an unknown critical extension.
- **Fix:** replace the hand-rolled walk with `cryptography.x509.verification.PolicyBuilder` (RFC 5280 and CABF profile engine, with a custom extension policy), or a vetted validator. Require `digitalSignature` on the leaf and `cA=FALSE`, and pin the KA signer by EKU or policy OID when TS3 defines one. Add negative tests for each RFC 5280 §6.1.4 step.

### H-5. Five client-reachable inputs produce HTTP 500, against the design's "nothing a client sends can produce a 500"
All five are confirmed (`p1.py`, `p3.py`, `p4.py`, `p10.py`):

| # | Input | Where | Auth needed |
|---|---|---|---|
| a | DPoP `htu` with a bad port (`https://issuer.test:abc/token`, `:99999`, `https://[::1/token`): `urlsplit().port` raises `ValueError` | `oauth.py:41` | none (`/token`) |
| b | DPoP or proof header `"alg": ["ES256"]`: `in frozenset` raises `TypeError: unhashable` | `oauth.py:135`, `proofs.py:86`, `jose.py:125` | none (`/token`) |
| c | JWS payload nested about 10,000 levels deep: `RecursionError` is not caught | `jose.py:74-77` (catches only `ValueError` and `UnicodeDecodeError`) | an access token (proof in the body); the DPoP header too, if the front end allows headers over about 27 KB |
| d | jwt proof with a valid KA but header `jwk` set to `"x"`, `{"kty":"RSA"}` or `{"kty":"EC"}`: `AttributeError`, `JoseError` or `KeyError` from `thumbprint()` | `proofs.py:192`; also `proofs.py:51-58` for any non-EC entry in `attested_keys[1:]` | any wallet holding a valid KA |
| e | Non-ASCII bytes in `Authorization: Bearer …` to admin routes, or a non-ASCII MAC part in the DPoP `nonce` when server nonces are on: `hmac.compare_digest` raises `TypeError` | `service.py:373`, `oauth.py:85` | none |

The garbage-input test (`tests/engine/test_rules_and_gaps.py`, `GARBAGE`) only fuzzes the outer HTTP body, so it misses all five.

**Fix:**
- Wrap `normalize_url` in `try/except ValueError`.
- Check `isinstance(alg, str)` before any membership test.
- Catch `RecursionError` in `parse_jws`, and cap the length of each JWS segment.
- Validate every JWK through `public_key_from_jwk` before calling `thumbprint`, including all `attested_keys`.
- Compare bytes in `compare_digest` (`.encode()`), or hash both sides first.
- Add a property-based fuzz test (Hypothesis) over the JOSE headers and claims.

### H-6. Request bodies are buffered in full before the size limit applies
- **Where:** `src/cunho/app.py:40-48`. `MAX_BODY` is checked against `Content-Length`, but a chunked request has no `Content-Length`. `await request.body()` then reads the whole stream into memory before `len(body) > MAX_BODY` runs.
- **Repro (`p8.py`):** a chunked 64 MiB POST to `/token` is answered with 400 "request body too large", but only after it has been fully buffered: about 129 MiB peak in-process, client included. The endpoint is unauthenticated.
- **Fix:** stream with `async for chunk in request.stream()` and abort once the running total exceeds `MAX_BODY`. Also document a front-end limit.

---

## Medium

### M-1. An access token can be redeemed without limit, so one offer yields unlimited PIDs, many bound to the same key
- **Where:** `src/cunho/oauth.py:277-321` and `src/cunho/service.py:187-280`. Nothing counts or consumes uses of the token.
- **Repro (`p5.py`):** with one token, four requests using the **same holder key** return `[200, 200, 200, 200]`, which is four PIDs bound to one key. A single request with 100 proofs returns 100 PIDs. Within the 300 s token life, one offer can produce thousands of PIDs.
- **Why it matters:** DESIGN says "each key in a batch gets at most one credential", but that holds only within one request. ARF ISSU_43 (Method A, once-only) and the advertised reuse policy (`batch_size: 30`) assume the provider controls how many credentials exist per issuance. Multiple PIDs on one key also make presentations linkable, against 2977 Art. 5(8) and ARF ISSU_35.
- **Fix:** record the thumbprints already bound under each grant and refuse repeats. Put a cap per grant (for example, one credential request per configuration per token, or `reuse_policy.batch_size` in total) and invalidate the token after the cap.

### M-2. The audit hash chain is not tamper-evident against the people who can tamper with it
- **Where:** `src/cunho/audit.py:43-93`.
- **Why it is wrong:** the chain is an unkeyed SHA-256 chain. Its head pointer and the pruning checkpoint live in the same store as the entries, and `verify()` trusts both. Anyone with write access to the store can rewrite entries, cut entries off the end, or delete entries from the start and set a `checkpoint`, and `verify()` still returns `True`. ETSI EN 319 401 REQ-7.10 ("cannot be easily deleted or destroyed") is not met against the realistic threat, an insider or a compromised host.
- **Repro (`p8.py`):** after a full recompute of the chain, `verify()` returns `(True, '2 entries verified')`. After truncating the tail and moving the head it returns `(True, '1 entries verified')`. After deleting the first entry and adding a forged checkpoint it returns `(True, '0 entries verified')`.
- **Also:**
  - The actor is always the literal string `"operator"`. DESIGN §7 promises "the operator identity", and there is none, so no accountability.
  - The operator's free-text `reason` (`service.py:151`) is logged verbatim, so personal data can enter the log, against DESIGN §7's "never names or other personal data".
  - Failed admin authentications are not logged.
  - `audit_retention_days` is required at startup (`settings.py:67`) but never used, and `prune_before` (`audit.py:83`) is never called. The retention promise in DESIGN §7 is not implemented.
- **Fix:**
  - Sign or HMAC each entry with a key outside the store (the signer interface).
  - Anchor the head periodically outside the store, for example in a signed checkpoint written to WORM storage or an RFC 3161 timestamp.
  - Make the checkpoint signed.
  - Log an authenticated operator identity (per-operator tokens).
  - Constrain `reason` to an enumeration.
  - Wire up a retention job.

### M-3. `KA.POP_ALL_KEYS` is claimed, but the jwt+KA path issues for keys whose possession was never proven
- **Where:** `src/cunho/proofs.py:216-219`, marked `@implements("KA.POP_ALL_KEYS")` at `proofs.py:163-169`.
- **Why it is wrong:** the rule's own quote (ARF WUA_12) is "SHALL receive a proof that the Wallet Unit possesses the private keys corresponding to all public keys…". In a jwt proof carrying a KA, only `attested_keys[0]` signs. The KA itself needs no nonce (`nonce_rule=None`) and may be hours old, yet every `attested_keys[i]` gets a credential. For keys 1 to n, the only evidence is a stale wallet-provider statement. TS3 and OpenID4VCI App. D may permit this, but then the binder claim is false, and the conflict between WUA_12 and TS3 should be resolved in the binder rather than hidden.
- **Fix:** do one of the following:
  - Issue only for keys that signed a fresh jwt proof.
  - Accept extra attested keys only when the KA carries this issuer's fresh c_nonce (as the attestation proof type does).
  - Drop the `@implements` claim and record the deviation.

### M-4. `CRYPTO.ES256_384_512` is claimed but not met: key proofs accept ES256 only
- **Where:** `src/cunho/jose.py:123` claims the rule. `src/cunho/proofs.py:171` intersects the accepted algorithms with the config's `proof_signing_alg_values_supported`, which is `["ES256"]` in every shipped config.
- **Why it is wrong:** CIR 2024/2979 Annex Ib SA-3 says the credential issuer "shall support all of the algorithms mentioned in SA-1", and TS3 §2.6 says PID providers SHALL support ES256, ES384 and ES512. A conformant wallet using a P-384 WSCD key is refused.
- **Repro (`p11.py`):** an ES384 jwt proof with a valid KA gets `400 invalid_proof "alg must be one of ['ES256']"`.
- **Fix:** have `metadata.validate` refuse to start when a device-bound configuration does not list all three, or add them when publishing. Also check `credential_signing_alg_values_supported` against `signer.alg`; it is never compared today.

### M-5. The SD-JWT VC is signed with `x5c` and `iss` set to an https URL, but the signer certificate's SAN is never checked against `iss`
- **Where:** `src/cunho/credentials.py:241-252`, `src/cunho/signer.py:42-53`, `src/cunho/settings.py:58-79`.
- **Why it is wrong:** SD-JWT VC (draft-23), in the section on validating the issuer-signed JWT key with X.509, requires that when `iss` is a URI, it match a `uniformResourceIdentifier` (or DNS) SAN in the leaf certificate. HAIP §6.1.1 makes `x5c` mandatory. cunho will happily issue credentials that strict verifiers must reject, and the test PKI certificates have no SAN at all.
- **Related:** `x5u` (`signer_certificate_url`) is neither required to be https (RFC 7515 §4.1.5 requires integrity protection) nor served by cunho. Nothing checks that the resource at `x5u` matches `x5t#S256`.
- **Fix:** at startup, refuse a signer whose leaf has no SAN matching `issuer_url`, and require `https` for `signer_certificate_url`. Ship the test PKI with SANs.

### M-6. The status list token is rebuilt from scratch on every unauthenticated GET, on the event loop
- **Where:** `src/cunho/status.py:98-124` and `src/cunho/app.py:127-135`. Every route is `async def`, but the work inside (ECDSA signing, zlib, SQLite reads) is blocking.
- **Repro (`p6.py`, `p7.py`):** about 15 ms per GET at 7.6k slots. **About 76 ms per GET with a full list** (65k slots, SQLite). Each GET reads every slot row, decodes it from JSON, compresses, and signs. About 13 req/s saturates a worker, and while it does, `/token` and `/credential` stall, because the blocking code runs on the event loop.
- **Fix:** cache the signed token per list and rebuild it only when a slot changes or on a `ttl` cadence. Keep the bitstring as one blob rather than one row per slot. Make the handlers `def` (threadpool), or move CPU work to `run_in_threadpool`.

### M-7. Rule claims that nothing enforces (`@implements` as a rubber stamp), and a meta-test that counts decorators as implementations
`tests/engine/test_rules_and_gaps.py:198-204` counts a rule as "implemented" if its id appears in any `implements(...)` call. As a result:

| Rule | Where | What the code actually does |
|---|---|---|
| `BATCH.METHOD_INVISIBLE` (ISSU_41) | `service.py:179` | nothing |
| `ISS.NO_WALLET_DISCRIMINATION` | `service.py:183` | nothing; the test greps for the absence of the string `wallet_allowlist` |
| `META.REUSE_POLICY.A_OR_B`, `METHOD_B_TRIGGER`, `METHOD_C_PARAMS` | `metadata.py:95-98` | `validate()` (`metadata.py:130-140`) only checks `once_only` (method A); B and C parameters, and "A or B is present", are never checked |
| `TRUST.WP_ANCHORS_FROM_LIST` ("as published by the Commission … and only those", ISSU_28) | `proofs.py:109` | a PEM file path; no LoTE parsing or signature check |
| `VALIDITY.EAA_LE_STATUS_EXP` | `service.py:185` | conditional on revocation chaining, which does not exist in M2 |
| `PID.SDJWT.CLAIM_MAPPING` | `credentials.py:130` | nothing maps or checks claim names against Table 7; names come straight from the EC JSON, which also carries `value_type: "test"` for `address` |
| `KA.POP_ALL_KEYS` | M-3 | contradicted by the code |
| `CRYPTO.ES256_384_512` | M-4 | not met for key proofs |
| `KA.PID_KEY_IN_WSCD` | `proofs.py:139-143` | enforced only if the operator's config sets `key_attestations_required.key_storage`; `metadata.validate` does not require it for `urn:eudi:pid:1` |

DESIGN §8's "117 binder rules, each implemented and tested" is therefore overstated.

**Fix:** make the meta-test require at least one `enforce`/`refuse` call or a named obligation test per rule. Downgrade the rules above to "documented gap", or implement them.

### M-8. Test-suite defects
- **Flaky test:** `tests/engine/test_flow.py:126` asserts `str(ref["idx"]) not in log`, a substring test of a decimal index against a JSON log full of hex hashes and Unix timestamps. Measured **13 failures in 300 runs (4.3%)** (`flaky.py`). The check is also meaningless: a keyed reference would not contain the index anyway.
- **Tautology:** `tests/engine/test_platform.py:169`: `assert not revoke(x) or value(x) == 1` is always true.
- **Asserts the wrong behaviour:** `test_platform.py:166` asserts that revoking twice returns `True` both times. The admin API therefore reports `{"revoked": 1}` for already-revoked slots and for **decoy** slots (`p10.py`), which inflates revocation reports. A boolean `"index": true` is accepted as index 1.
- **Mislabelled:** `test_audit_chain_detects_tampering` claims `LOG.DISCARD_UNIQUE_VALUES`, which it has nothing to do with.
- **Not actually concurrent:** `test_concurrent_redemption_yields_one_token` runs threads through `TestClient`, but the app runs every request on one event loop with synchronous handlers, so the requests are serialized. It proves nothing about concurrency.
- **Fix:** compare against a set of parsed `status_refs` instead of substrings. Delete or rewrite the tautology. Make `revoke` return whether the slot was a live, unrevoked, real credential. Test concurrency at the store level (already done) and with a multi-process server.

### M-9. Status-list decoys do not hide revocations from anyone who fetches the list twice
- **Where:** `src/cunho/status.py:51-58`. Decoys are set once, when a list opens.
- **Why it matters:** an observer diffing two successive tokens sees exactly which bits flipped and when. DESIGN §4 claims the decoys stop "the number of set bits" revealing revocations. That is true for one snapshot only. ARF VCR_18 and 1569 Art. 4(4) (privacy-preserving revocation) are not served by this.
- **Fix:** add decoy flips over time (a Poisson process on unused slots), or document the limit honestly.

### M-10. A different DPoP nonce secret in every process, so multi-worker deployments randomly fail
- **Where:** `src/cunho/oauth.py:61`. `secrets.token_bytes(32)` is generated per process and lost on restart.
- **Why it matters:** with `dpop_server_nonce=True` and more than one uvicorn worker on the shared SqliteStore, a nonce issued by worker A fails on worker B (`use_dpop_nonce` loops), and every restart invalidates all nonces. The same multi-worker setup has a lost-update race on the `issued` record (`service.py:277-279`, read-modify-write), so revoking by `subject_ref` can miss credentials.
- **Fix:** persist the nonce key in the store, as `ref-secret` already is. Make `issued` an append (one row per ref, keyed `subject_ref:list:idx`).

---

## Low

- **L-1. htu normalisation accepts userinfo.** `normalize_url` (`oauth.py:37-44`) drops `user:pass@`, so `https://attacker:pw@ISSUER.test:443/token?x#y` matches (`p10.py`). RFC 9449 §4.3 (check 9) compares the URI without query and fragment; userinfo is part of the authority and should cause a mismatch. Percent-encoding and dot segments are not normalised either; that error is on the safe side, but it is undocumented.
- **L-2. Lax base64url.** `b64u_decode` (`jose.py:43-49`) is non-validating. It accepts characters from both alphabets, silently drops characters outside the alphabet, and ignores non-zero padding bits. One key therefore has many JWK spellings and many thumbprints, which defeats the per-request duplicate-key check in `ProvenKeys.add_key` for configurations without a KA. It also lets malformed `x` and `y` values (lists, ints) flow into `cnf.jwk`. Fix: strict decoding (`validate=True` on the translated string, then re-encode and compare), and reject non-string coordinates.
- **L-3. No decoy digests.** `_conceal` (`credentials.py:193-209`) adds none, so `len(_sd)` tells every verifier how many top-level claims the PID has (for example, whether there is an address). RFC 9901 §4.2.5 decoys are optional, but this is a PID.
- **L-4. Technical `exp` is not capped at the administrative `date_of_expiry`.** In `service.py:338-350` a PID whose document expires tomorrow still gets a 14-day `exp`.
- **L-5. `date_of_issuance` and `date_of_expiry` are derived from the rounded `nbf` and `exp`.** Combined with L-4, a verifier can read `date_of_expiry` as a technical value.
- **L-6. tx_code lockout burns the offer.** `oauth.py:256-260` deletes the offer after `tx_code_max_attempts`, but DESIGN §4 says the counter "does not burn the offer". Either behaviour is defensible; the document and the code disagree. The `tx_code` is also stored as an unsalted SHA-256 of a 4 to 10 digit string, which is trivially reversible from a database dump. That is low risk because the pre-authorized code is a 256-bit value stored hashed.
- **L-7. KA freshness.** `iat` is never checked for freshness (`proofs.py:127-128`). A non-integer `exp` (for example a float) skips the expiry check entirely on the attestation path (`proofs.py:132`). `key_storage_status.status` is collected and then thrown away (`proofs.py:158-160`), although the comment says it is kept to re-check revocation later. `KA.STATUS_AT_ISSUANCE` is placed in M4, which means M2 issues PIDs from KAs that may already be revoked. That makes M2 unsafe to deploy on its own.
- **L-8. Dead branch.** `service.py:334` checks `vct == PID or profile == PID`, but `proofs.py:239` then re-checks only the profile. An `eaa_provider` deployment issuing `urn:eudi:pid:1` skips the status-period cap.
- **L-9. Metadata hygiene.**
  - `cryptographic_binding_methods_supported` advertises `cose_key` for `dc+sd-jwt`, which can never be honoured.
  - The issuer `display` is copied from the EC sample (`dev.issuer.eudiw.dev` logo), and the configurations use `examplestate.com` logos.
  - A PID-provider deployment advertises 11 EC sample EAAs (IBAN, tax, and others) by default.
  - `credential_signing_alg_values_supported` is static.
  - `response_types_supported: []` meets RFC 8414 §2 in form only.
- **L-10. Error codes and labels.**
  - A request for a configuration that exists but is not published (mdoc) gets `credential_request_denied` (`service.py:220-227`). That leaks unpublished configuration ids; per §8.3.1.2 the answer should be `unknown_credential_configuration`.
  - The body-size refusal on `/credential` is labelled `OAUTH.TOKEN_ERROR_BODY` (`app.py:43-47`).
  - The 404 for an unknown status list is labelled `STATUS.TSL.TOKEN_CLAIMS`.
  - Admin authentication failures are labelled `ISS.SUBJECT.ENTITLEMENT` with `invalid_token`, even when no token was sent (RFC 6750 §3.1).
  - The content-type checks use `startswith` (`app.py:94,117`), so `application/jsonx` passes.
- **L-11. Misnamed offer field.** `credential_offer_uri` in the admin offer response (`oauth.py:209-210`) holds the by-value deep link (`openid-credential-offer://?credential_offer=…`). In OpenID4VCI §4.1, `credential_offer_uri` is the by-reference HTTPS URL. This misleads integrators.
- **L-12. Dead code.** `Pkcs11Signer` and `KmsSigner` stubs, `StatusLists.base`, `AuditLog.prune_before`, `Settings.extra`, `ProvenKeys.key_storage_status`. `x5c` "no anchor" relies only on the self-signed test (`signer.py:53`), so a cross-signed root or an intermediate registered as an anchor is still sent.
- **L-13. SQLite contention.** Every `SqliteStore.get` performs a write (`_purge`). The default 5 s busy timeout yields `database is locked` 500s under multi-process contention.

---

## What is done well (for calibration only; no points awarded)
- Pre-authorized codes and c_nonces are single-use through an atomic `take`, and the DPoP jti cache is keyed per key.
- Bearer downgrade is refused.
- `ath` and the key binding to the token are checked.
- Symmetric algorithms and `none` are impossible.
- Curve and algorithm confusion are blocked.
- Signatures must be exactly `2*size` bytes.
- Protocol claims are written after the subject claims, so subject data cannot override them.
- Disclosures are recursive, with digests sorted.
- Status-list bit order matches draft-21 §4.1 (LSB first), compression is ZLIB/DEFLATE, the media type is correct, and indexes are random with no double allocation.
- RFC 6749 and OpenID4VCI §6.3 and §8.3.1.2 error codes are mostly right.

---

## Grade: **4 / 10**

On the given scale, "works, is structured, and has basic safety checks" is a 2-3. cunho is above that: the DPoP/token/nonce core, the SD-JWT builder and the status list are mostly careful. It falls well short of what a national PID provider's review would pass:
- a freshness MUST that NaN bypasses;
- unauthenticated storage, body and CPU denial of service;
- PII retained without bound behind a crypto-shredding claim that adds nothing;
- a partial RFC 5280 path check guarding the WSCD binding;
- five client-reachable 500s against an explicit design promise;
- a tamper-evident log that the operator can silently rewrite;
- a rule registry in which about 10 of the "117 implemented" rules are decorators without enforcement, and a 4%-flaky test asserting the wrong property.

## What 10/10 within M2 would take
1. Strict JOSE parsing: no NaN or Infinity, no duplicate keys, a recursion cap, type checks on every header member, strict base64url, and JWK validation before any thumbprint. Add a Hypothesis fuzz suite asserting no 5xx on every endpoint, including the JWS internals.
2. Real RFC 5280 path validation (`cryptography.x509.verification`), with keyUsage, EKU/policy, pathLen and critical-extension handling, plus negative tests per step.
3. A store with active expiry sweeps, rate limits on `/nonce` and `/token`, streamed body limits, and non-blocking handlers. Add a load test asserting bounded memory under `/nonce` flooding.
4. A vault key held outside the data store, `secure_delete`, and a test proving that personal data is unreadable after expiry and after erasure.
5. An audit log with entries signed or MAC'd by a key outside the store, externally anchored checkpoints, an authenticated operator identity, an enumerated `reason`, and an actual retention job.
6. Per-grant issuance accounting: one credential per key, a cap per offer, and invalidation of the token.
7. Conformance closures: ES384 and ES512 key proofs, a startup check that the signer SAN matches `iss`, https for `x5u`, KA freshness checks, and the method A/B/C reuse-policy checks.
8. A meta-test that requires real enforcement or obligation tests per rule. Remove false `@implements` claims, and fix the flaky, tautological and mislabelled tests.
9. Cached status-list tokens, revocation-masking decoy churn, and `revoke` reporting only real, newly revoked slots.
