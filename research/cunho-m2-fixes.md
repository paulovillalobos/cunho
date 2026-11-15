# cunho M2: fixes for the independent review

Review: cunho-m2-review.md (graded the first cut 4/10). The fixes below answered every High and Medium finding at the time; a second review found nine of them only partly fixed, and those are finished in the second section; a third review (6/10) found six partly fixed and eight new findings, all in the third section. Tests live in tests/engine.

| Finding | What changed | Test |
|---|---|---|
| H-1 NaN/Infinity iat | Strict JSON (no NaN, Infinity or duplicate members); NumericDate must be a finite non-boolean number | test_review_fixes::test_non_finite_iat_is_refused, test_duplicate_json_members_are_refused |
| H-2 unbounded state | Both stores sweep expired entries at least every 60 s; hourly maintenance; per-client rate limits on /token, /nonce and admin | test_expired_state_is_swept, test_nonce_flood_does_not_grow_state, test_rate_limit |
| H-3 PII outlives TTL, illusory shredding | Per-subject keys wrapped by a key-encryption key from the keyring (outside the store); SQLite secure_delete; vault erased once an offer is fully issued; expired rows swept | test_vault_keys_are_wrapped_outside_the_store, test_vault_is_erased_once_the_grant_is_used |
| H-4 partial RFC 5280 | Path length cap, pathLenConstraint, keyCertSign, leaf not a CA, leaf digitalSignature, no TLS-only leaf, unknown critical extensions and name constraints refused | test_path_validation_fails_closed (6 cases), test_path_validation_accepts_a_good_chain |
| H-5 five 500s | htu bad port/userinfo, non-string alg, recursion, malformed proof JWK, non-ASCII compare all refused cleanly | test_former_server_errors, test_non_ascii_server_nonce |
| H-6 chunked body buffered | Body streamed with a running limit | test_chunked_body_is_refused_early |
| M-1 unlimited token reuse | One credential request per configuration per token (atomic), no key bound twice per grant | test_one_credential_request_per_configuration_per_token |
| M-2 rewritable audit chain | Entries and pointers MACed with the keyring; signed head for external anchoring; named operator tokens; reason enum; failed admin auth logged; retention pruning wired | test_audit_chain_detects_tampering, test_audit_identity_reasons_and_anchoring, test_retention_prunes_old_entries |
| M-3 KA.POP_ALL_KEYS contradicted | jwt proofs bind only the key that signed them; all attested keys only via the attestation proof type with a fresh c_nonce | test_jwt_proof_binds_only_the_signing_key |
| M-4 ES384/ES512 refused | Proofs and key attestations accept and publish ES256/384/512; signer alg checked against credential_signing_alg_values_supported | test_es384_key_proofs_are_accepted |
| M-5 SAN vs iss | Startup refuses a signer certificate whose SAN does not name the issuer; signer_certificate_url must be https; test and dev PKI carry SANs | test_signer_certificate_must_name_the_issuer |
| M-6 status list rebuilt per GET | Signed token cached per list, rebuilt on change or half ttl; blocking work in a thread pool | test_status_token_is_cached_until_a_bit_changes |
| M-7 decorators as implementations | Meta-test now needs an enforcing call plus a triggering test, or an obligation test; reuse methods A/B/C and LoTE moved to M3, EAA chaining to M4, each with a note; claim names enforced | test_every_m2_rule_is_enforced_or_proven, test_pid_values |
| M-8 test defects | Flaky substring check replaced with parsed refs; tautology removed; revoke reports only live real slots; boolean index refused; race test uses real threads | test_revocation_and_audit, test_status_allocation, test_revocation_input_is_strict, test_concurrent_redemption_yields_one_token |
| M-9 decoys static | Decoys added over time by maintenance; limit documented in DESIGN.md | test_decoys_keep_appearing |
| M-10 per-process nonce key, read-modify-write | DPoP nonce key from the keyring; issued records are one row per credential | test_dpop_nonces_survive_restart_and_workers, test_issued_records_are_rows |
| L-1 htu userinfo | Refused | test_former_server_errors |
| L-2 lax base64url | Strict canonical base64url; JWKs canonicalised before use | test_non_canonical_jwk_is_refused |
| L-3 no decoy digests | 0 to 3 decoy digests per _sd array | test_pid_issuance_end_to_end |
| L-4, L-5 exp vs document | exp capped at the end of date_of_expiry; date_of_expiry is the operator's administrative date, never derived | test_technical_expiry_follows_the_document |
| L-6 tx_code lockout docs, reversible hash | DESIGN.md matches the code; tx_codes stored as keyed hashes | test_tx_code_lockout |
| L-7 KA freshness | iat not in the future, exp must be a number; KA status at issuance stays M4 and DESIGN.md says M2 is not for real PIDs | test_key_attestation_times_must_be_numbers |
| L-8 profile-only check | Status-period cap applies to any PID configuration | test_validity_capped_by_key_storage_status |
| L-9 metadata hygiene | Only jwk binding for SD-JWT; no EC branding (operator display_name); publication by profile or setting; signing alg published as the signer's | test_metadata_documents, test_publication_follows_profile_and_settings |
| L-10 labels and leaks | Unpublished configurations get unknown_credential_configuration; exact content types; bare Bearer challenge without a token | test_credential_request_shape |
| L-11 offer field name | offer_link instead of credential_offer_uri | test_offer_shape |
| L-12 dead code | Removed StatusLists.base, ProvenKeys.key_storage_status, Settings.extra; PKCS#11 and KMS stubs kept on purpose (interface for M4) | n/a |
| L-13 SQLite writes on read | get() no longer writes; 30 s busy timeout | test_store_single_use_under_concurrency |

Not fixed, and why:
- KA status at issuance and the 24-hour chaining job (L-7, part of M-9 context): milestone M4. DESIGN.md and README say M2 must not issue real PIDs.
- External anchoring of the audit head is provided as a signed statement; storing it in WORM storage is the operator's job.
- No Hypothesis property-based fuzzing yet; the garbage table and the review repros cover the known cases.

---

## Second review (cunho-m2-review-2.md): fixes

Tests are in `tests/engine/test_review2_fixes.py` unless another file is named. Each test name carries the finding id.

| Finding | Change | Test |
|---|---|---|
| N-H1 audit truncation and deletion | Every new head is appended, MACed under its own purpose, to an anchor file outside the database (`audit_anchor_path`; production refuses to start without it; README documents append-only/WORM storage). Anchor lines chain by MAC and their sequence grows by exactly one; `verify()` fails when the store is behind or diverges from the anchor, and new entries are refused on a store that fell behind. Head pointer, checkpoint and anchor use distinct MAC purposes; the checkpoint binds the pruned entry's time and is refused when younger than the retention period. Appends from several workers are ordered with `flock`; a crash between commit and anchor write is caught up on the next write. `POST /admin/audit/verify` checks the log against a signed head pulled from `GET /admin/audit/head`. | test_n_h1_wiping_the_log_is_detected, test_n_h1_truncation_with_an_old_head_is_detected, test_n_h1_anchor_lines_are_chained_and_strictly_increasing, test_n_h1_checkpoint_must_respect_the_retention_period, test_n_h1_store_ahead_of_the_anchor_is_caught_up, test_n_h1_signed_head_pulled_by_the_operator, test_n_h1_anchor_orders_appends_from_several_workers, test_n_h1_production_needs_an_anchor |
| N-H2 failed logins in the audit chain | No audit entry per failed login. Each failure goes to the `cunho.security` operational log with a route name from a fixed list and the client network (IPv4 /24, IPv6 /48). Maintenance writes one aggregate `admin.auth_failures` entry per run: counts per fixed route, with-token count, first and last time; no free text. | test_n_h2_failed_logins_never_write_text_into_the_audit_log, test_n_h2_client_buckets; test_audit_identity_reasons_and_anchoring (test_review_fixes.py) |
| N-M1 500 via WWW-Authenticate | Duplicate-member errors no longer echo the name; the proof-type error no longer echoes the type. Every error description is cut to the RFC 6750 character set in the header and the body. | test_n_m1_duplicate_unicode_members_get_a_clean_401, test_n_m1_error_text_is_header_safe, test_n_m1_hypothesis_over_header_reaching_errors (runs where Hypothesis is installed; CI installs it) |
| N-M2 decoys in hourly bursts | Decoys are scheduled as a Poisson process over a window ahead (shared through the store, so workers do not add their own) and each becomes visible at its own random moment; the cached status token is rebuilt when the next one comes due. DESIGN states the remaining limit (ratio of decoy to revocation rate, overall trend). | test_n_m2_decoys_arrive_one_at_a_time_at_random_moments, test_n_m2_workers_share_one_schedule, test_decoys_keep_appearing (test_review_fixes.py) |
| N-M3 PID without key binding | One `is_pid` test (vct family `urn:eudi:pid:`), used everywhere. Startup refuses a PID configuration, and any configuration a PID provider publishes, without binding and a KA with `key_storage`. `_proofs` refuses a PID with no proof types (`BIND.DEVICE_BOUND`). | test_n_m3_unbound_pid_configuration_refuses_to_start, test_n_m3_unbound_pid_is_refused_at_issuance |
| N-M4 revocation applied unlogged | Revocation, erasure and offer creation log first and write in one audit transaction; a failed log write changes nothing. | test_n_m4_revocation_is_not_applied_without_its_entry, test_n_m4_offer_is_not_created_without_its_entry |
| N-M5 limiter locks out new clients | LRU eviction instead of refusal when full; IPv6 keyed per /64; one table per route group. | test_n_m5_a_full_limiter_evicts_instead_of_refusing, test_n_m5_ipv6_is_limited_per_64 |
| N-M6 coverage not proven; hollow test | Every refusal reports its rule id to observers; a `covers` test fails unless each rule it names refused something while it ran (summed over parametrized cases). Rules passed to helpers count as refused rules. Wrong `covers` claims were removed or fixed; the hollow validity test uses fresh tokens and matching KAs; the concurrent-redemption race is forced so it fires every run. `tools/mutation/mutate.py` (rules mode and per-statement `--sites` mode) is a separate CI job. | conftest `_covered_rules_fire`, test_validity_capped_by_key_storage_status, test_subject_data_still_valid_at_issuance, test_concurrent_redemption_yields_one_token, test_n_m6_* (one per statement the per-statement run first found unpinned) |
| N-M7 prune loads the whole log | Pruning works in batches of 500, each its own short transaction, reading only the batch; verify and catch-up stream pages. Maintenance runs in a background task, never in a request. | test_n_m7_prune_and_verify_read_in_bounded_pages, test_n_m7_maintenance_never_runs_inside_a_request, test_n_m7_background_maintenance_runs |
| N-L1 x5u points nowhere | cunho serves the signer chain at `/certs/signer.pem`; a `signer_certificate_url` on cunho's own origin must be that path. | test_n_l1_x5u_serves_the_signer_certificate |
| N-L2 crit ignored | Any JWS with `crit` is refused. | test_n_l2_crit_is_refused |
| N-L3 no KA signer profile, no key floor | See H-4. | test_n_l3_key_attestation_signer_profile_and_key_strength |
| N-L4 LIKE folds case | Prefix lookups are key ranges. | test_n_l4_prefix_lookups_are_case_sensitive |
| N-L5 WAL cold start | WAL is switched once, with retry and backoff on a lock. | test_n_l5_workers_starting_together_on_a_new_store |
| N-L6 knobs not validated | TTLs, iat windows, granularity, fill limit, decoy ratio and churn, token lifetime and maintenance interval are checked at startup; revocation and erasure references must have the form cunho hands out. | test_n_l6_configuration_knobs_are_checked, test_n_l6_erase_takes_only_issued_references, test_revocation_input_is_strict |
| N-L7 M3/M4 in present tense | DESIGN component list says what is M3/M4; the M2 summary no longer says every finding was fixed. | n/a |
| N-L8 evidence gaps | Production mode starts and issues with an injected signer. The vault test looks for the stored ciphertext and wrapped key, and erasure now also checkpoints the SQLite WAL (it held erased rows). The soak runs maintenance every 60 s and checks it ran and that the chain verifies against its anchor. | test_n_l8_production_mode_starts_with_an_injected_signer, test_n_l8_vault_rows_leave_every_file_on_erase |
| H-4 / N-L3 partial RFC 5280 | KA signer profile: no `anyExtendedKeyUsage`, not an EKU of only TLS/code/e-mail/time-stamping/OCSP purposes, a required policy OID when `ka_signer_policy_oids` is set (production must). Every path certificate and the anchor: agreed curves or RSA of at least 3072 bits, SHA-256 or stronger. | test_n_l3_key_attestation_signer_profile_and_key_strength, test_path_validation_fails_closed (test_review_fixes.py) |
| H-5 client-reachable 500s | Closed with N-M1 (fixed text, charset backstop, fuzz and Hypothesis tests). | as N-M1 |
| M-2 audit chain | Closed with N-H1, N-H2 and N-M7. | as those |
| M-5 SAN vs iss; x5u | Closed with N-L1. | test_n_l1_x5u_serves_the_signer_certificate |
| M-7 decorators as implementations | Closed with N-M6; mutation: 45/45 rules and 100/100 refusing statements killed. | conftest, tools/mutation |
| M-8 test defects | Hollow validity test fixed (N-M6); vacuous vault test replaced (N-L8). | as those |
| M-9 static decoys | Closed with N-M2. | as N-M2 |
| L-9 metadata hygiene | `response_types_supported` stays `[]`: with no authorization endpoint before M3 it is the only true value; a test ties it to the endpoint and DESIGN says so. | test_l9_response_types_follow_the_authorization_endpoint |
| L-12 x5c anchor heuristic | `x5c` is cut before the first certificate that is one of `signing_trust_anchors` (same subject and key, so a cross-signed copy too); the chain must be in order. Production requires the setting. | test_l12_x5c_never_carries_a_registered_anchor |
| M-1 residual (batch 100 vs policy 30) | A request carries at most the smaller of the issuer batch_size and the reuse policy's batch_size. | test_m1_residual_proofs_capped_by_the_reuse_policy |
| Stress fuzz (found while checking these fixes) | `validate_pid` raised TypeError on an object where a country, nationality or sex code belongs (an operator request then got a 500); such values are now problems, and a boolean is not taken for sex 1. | test_pid_values_of_the_wrong_shape_are_problems_not_crashes |

Not fixed, and why:
- H-3 residual, the vault key-encryption key does not rotate. A backup taken while an offer is live, plus the master secret, still decrypts that offer's data. Rotating it needs a key store that can destroy old keys, which is the HSM/KMS work of M4; DESIGN states the limit.
- Production still cannot start with the file signer; the production guards are tested with an injected signer until the M4 signers exist.
- Revocations are not batched into publication epochs: decoys now hide them by timing, at the ratio the operator sets, as DESIGN states.

---

## Third review (cunho-m2-review-3.md): fixes

Tests are in `tests/engine/test_review3_fixes.py` (one or more per finding, named with its id), `tests/engine/test_review3_paths.py` (certificate paths, one check per case) and `tests/engine/test_review3_units.py` (the checks the extended mutation run found unpinned). The reviewers' scripts from all three rounds were run again against the result; see "Re-running the reproductions" below.

| Finding | Change | Test |
|---|---|---|
| N3-H1 test strength | `tools/mutation/mutate.py` now has `--sites` (every refusing call, every `problems.append` of the rulebook checks and every `raise` in `src/cunho`, whatever it raises), `--conditions` (each guard of a refusal negated, each `and`/`or` operand dropped, each `not` removed, each comparison moved across its boundary, plus the hand-written semantic mutants of `tools/mutation/patches.py`, which take over the reviewer's `condmut.py` list) and `--all`. Equivalent mutants are listed with a reason in `tools/mutation/equivalent.py`; the run fails on any other survivor, on a listed mutant that is killed and on a listed mutant that no longer exists. `--select` runs each mutant first against the tests that reach its lines (a `sys.monitoring` line-coverage pass, `tools/mutation/linecover.py`) and confirms every survivor on the whole suite. CI runs rules mode and the full run in four shards, and the multi-process race suite. Refusals now hand the error itself to `errors.observers`; `helpers.refused_by` asserts the rule and the reason of the first refusal, and every negative key attestation case is built so that only its own check can refuse it (the "untrusted chain" KA is signed by the rogue leaf's key, the "broken link" one by a forger under a copied intermediate). Path validation has one test per check, each with the case on the other side of its boundary. Result on the final tree: 1,289 of 1,289 mutants killed (273 removed refusals and raises, 953 altered conditions, 63 hand-written), none listed as equivalent; rules mode 45 of 45. Checks that could never decide anything were removed instead of listed (see below). | test_n3_h1_* in all three files; tools/mutation |
| N3-M1 huge integer iat | `is_number` compares integers and never passes them to `math.isfinite`; a NumericDate must lie within ±2^53. `strict_json` refuses integers of more than 20 digits and floats that overflow. `Content-Length` must be 1 to 12 ASCII digits before `int()`. A revocation index must lie inside the list. Hypothesis fuzzes correctly signed DPoP proofs, key proofs and key attestations over arbitrary claim values in the suite, and the stress fuzz suite does the same over HTTP. | test_n3_m1_* |
| N3-M2 anchor history | The anchor file starts with a genesis line and is checked whole: `verify` streams every line and compares each one still covered by the store with the entry of the same sequence. A missing or empty anchor is never started again over a log that has entries: cunho refuses to start, and a running cunho refuses to log (the append handle no longer creates the file, and notices a removed or replaced file). Production creates a new anchor only with `CUNHO_AUDIT_ANCHOR_INIT=true`, on a new deployment. Pruning never removes an entry that is not yet anchored (found while pinning the catch-up checks: such a prune left a gap the anchor could never fill). README no longer suggests object-lock storage for the file itself. | test_n3_m2_*; test_pruning_stops_at_the_anchor |
| N3-M3 batch revocations vs decoys | Each revoked bit becomes visible at its own random moment within `status_revocation_jitter` (default 3600 s; jitter plus token ttl at most 24 h). Decoys arrive as clusters at Poisson moments; the cluster size is drawn from the sizes of the batches cunho actually issued, and each bit of a cluster shows at its own moment within the same window. Every list has its own schedule, laid down when the list opens. DESIGN states what remains: the trend in the count, and the case where a person's credentials came from several requests. | test_n3_m3_* |
| N3-M4 certificate revocation for the KA path | Implemented with local CRLs: `CUNHO_WALLET_PROVIDER_CRLS` names a PEM or DER file, re-read whenever it changes. Every certificate below the anchor must be covered by a current, correctly signed, complete CRL from its own issuer (whose key usage allows CRL signing) and must not be listed in it; a missing, stale or unusable CRL fails closed. Delta, partitioned and indirect CRLs, and CRLs without nextUpdate, are refused when loaded. Production refuses to start without the setting, and a development run logs that revocation is not checked. Fetching from distribution points and OCSP stay with the trusted lists in M3 (`KA.CHAIN_TO_WP_LIST` is marked partial in the registry). `tools/dev_pki.py` writes the CRL. | test_n3_m4_*; test_review3_paths CRL cases |
| N3-M5 database writer redirects issuance | Offer and access-token rows carry a keyring MAC over their key and content, including their own expiry, and are ignored when it does not verify. The vault ciphertext and wrapped key are bound to the subject and to the offer they were created for. `offer.created` and `credential.issued` both log a keyed reference to the grant. | test_n3_m5_* |
| H-4 partial RFC 5280 | Revocation (N3-M4); policies required on intermediates too, anyPolicy refused below inhibitAnyPolicy, policy mappings refused; intermediates limited to foreign purposes refused (N3-L9). | test_review3_paths |
| H-5 client-reachable 500s | N3-M1, N3-L1 and the signed-claim fuzzing. | as those |
| M-2 audit chain | N3-M2. | as N3-M2 |
| M-7 decorators as implementations | N3-H1 and N3-L6. | as those |
| M-8 test defects | `test_audit_chain_detects_tampering` no longer claims `LOG.DISCARD_UNIQUE_VALUES` (no binder rule asks for this technique). The conftest `make_issuer` fixture replaced an empty `MemoryStore` passed to it with a new one (an empty store is falsy), which made `test_n_m2_workers_share_one_schedule` hollow; fixed, and the test now checks a second worker against the same store. | test_platform.py, test_review2_fixes.py |
| N-M6 coverage not proven | N3-H1: rule and reason asserted per case, every `raise` and guard mutated. | as N3-H1 |
| N3-L1 verify 500 | Any record that cannot be read fails verification instead of raising; `GET /admin/audit/head` answers a clean 500 with fixed text; a malformed entry stops pruning with an alert instead of crashing every run; catch-up turns malformed rows into an AuditError. | test_n3_l1_* |
| N3-L2 sweeping in requests | Requests never sweep; reads never return expired entries; maintenance sweeps. | test_n3_l2_requests_never_sweep |
| N3-L3 limiter memory, slow_down | Three numbers per client (sliding-window counter) instead of one timestamp per request; 429 carries `invalid_request` and `Retry-After`. | test_n3_l3_* |
| N3-L4 shallow stress evidence | The fuzz suite signs DPoP proofs and key proofs with fuzzed claims; the race suite runs in CI; this round's stress run is the full one (all six suites, 30-minute soak) from a fresh clone of `6f127eb`: 86 of 86 checks pass (`evidence/stress/2026-11-04-6f127eb/`). The first full run, against `463d533`, failed one soak check because the soak still read the global decoy schedule key; the harness was fixed and the run repeated. | tools/stress, evidence/stress |
| N3-L5 false DESIGN sentences | §3.3 states how numbers are bounded and that only wallet-facing errors are fixed text; §10 says what the mutation run covers; §6 places the 24-hour notice with the operator (`REVOC.USER_NOTICE_24H`); §5 says mdoc and chaining are M4. Path errors no longer echo an OID from the client's certificate. | test_n3_h1_critical_extensions_and_name_constraints |
| N3-L6 partial rules | `registry.json` marks `VCI.PROFILE.OID4VCI_HAIP`, `VALIDITY.PID_LE_STATUS_EXP`, `PID.RULEBOOK.CONFORMANCE` and `KA.CHAIN_TO_WP_LIST` as `partial`, with the missing part and its milestone. | test_n3_l6_rules_implemented_in_part_are_marked |
| N3-L7 audit head key | The head statement is signed with a P-256 key derived from the keyring for that purpose only, published in the JWS header; the status-list key is no longer used for it. | test_n3_l7_the_audit_head_has_its_own_key |
| N3-L8 status fetches logged | Both uvicorn command lines in README use `--no-access-log`, and README says why; DESIGN §7 says so too. The stress harness runs uvicorn the same way. | test_n3_l8_the_documented_recipe_does_not_log_status_fetches |
| N3-L9 path profile gaps | See H-4; a leaf whose extended key usage names any TLS, code, e-mail, time-stamping or OCSP purpose is refused, even next to another purpose. | test_n3_l9_* |

Found while pinning checks, beyond the review:
- Pruning could remove committed entries that were not yet anchored (above, N3-M2).
- `metadata.validate` and `_require_device_binding` crashed at startup on proof type entries of the wrong JSON type; they now refuse them with a ConfigError.
- With its head pointer deleted, a log that still had entries verified as empty and valid (seen with review 2's `q8` script); entries without a head pointer now fail verification.
- Requests no longer sweep (N3-L2), so the background task now sweeps expired state on every tick, about once a minute, in batches of 1,000 rows; full maintenance still runs per interval.
- Several checks that could never decide anything were removed rather than listed as equivalent: a decode error after the base64url alphabet and length were already checked, an empty anchor list from a loader that refuses empty files, a decoy test in `revocable` (a decoy slot is revoked from the start), a length and digit test on server nonces whose MAC already decides, a `htu is None` test, a boolean test where `True` already fails the range, an unreachable assertion in the cluster-size draw, and the upper bound on `timestamp_granularity` that the "divides a day" test already enforces.

Not fixed, and why:
- Anchor lines are MACed, not signed. Someone who holds the keyring and can replace the anchor file (it is not on append-only storage) can still rewrite history; signing the lines with a key that is not on the database host needs the HSM signer of M4. Append-only storage remains the operator's job.
- A database wiped together with its anchor file looks like a new deployment when `CUNHO_AUDIT_ANCHOR_INIT` is set, or in a development run; production without that setting refuses to start.
- Status bits, issued-credential records and nonces are not MACed: a database writer can still change a status bit. Every revocation is in the audit log with a keyed status reference, so an operator can compare; cunho does not.
- CRLs are read from a file the operator keeps current; cunho fetches nothing (no distribution points, no OCSP) until the trusted lists of M3.
- The decoy cluster sizes follow issuance requests; a person whose credentials came from several requests is revoked as one larger cluster.

Re-running the reproductions:
| Script | Result now |
|---|---|
| review 3 `r1_bigint_iat` | all three 400 (`invalid_dpop_proof`, `invalid_proof`: number too large) |
| review 3 `r2_anchor_history` (constructor given `create_anchor=True`, the new API; restart without it) | (a) `(False, 'the store diverges from the anchor at sequence 2')`; (b) the running process: `(False, 'the anchor file is missing')` and refuses to log; a restart without the init setting refuses to start |
| review 3 `r3_limiter_memory` | 18 MiB per full table (was about 185 MiB) |
| review 3 `r4_inrequest_sweep` | the next wallet's `add()` takes 0 ms: no sweep in the request |
| review 3 `r5_verify_crash` | `/admin/audit/verify` answers 200 `{"valid": false}`, `/admin/audit/head` a clean 500 with fixed text |
| review 3 `r6_rogue_wp_hollow`, `r7_broken_link_hollow` | 400 on the real tree; on a tree with either check deleted the suite now fails (both mutants killed) |
| review 3 `r8_batch_revocation_burst` (with the default jitter of 3600 s; the test helper sets 0) | the ten revoked bits appear one or two at a time over the next hour, between decoys of the same shape |
| review 3 `r9_db_writer_redirect` | the forged token row gets 401 `invalid_token` |
| review 3 `race.py` (4 workers, one SQLite file) | 1×200 for every single-use race, 5 tx_code comparisons, audit verifies (47 entries, 48 anchor lines), 0 tracebacks |
| review 3 `mut/raisemut.py`, `mut/condmut.py` | taken over by `tools/mutation` (`--sites`, `--conditions`, `patches.py`) |
| review 2 `q1`-`q14` | every attack refused as in review 3. `q2`: wipe and truncation fail verification; `q3`: no audit entry for a failed login; `q8`: verification now also fails for entries without a head pointer; `q9`: H-2 shows expired nonce rows until the background sweep runs (the script starts no background task); `q12` (real 4-worker server): 400 after the limit, RSS flat |
| review 1 `p1`-`p11` | every attack refused as in review 3; `p8` and `p10` stop where review 2 said their internals changed |

## Fourth review (cunho-m2-review-4.md): fixes

Tests are in `tests/engine/test_review4_fixes.py`, named with the finding id, with a few changes to earlier tests where the behaviour changed on purpose (listed below). The reviewers' scripts from rounds two, three and four were run again against the result; see "Re-running the reproductions" below.

| Finding | Commit | Change | Test |
|---|---|---|---|
| N4-M1 lone surrogates give 500 | `b7fd8d1` | `strict_json` refuses any string, member names included, that holds a lone UTF-16 surrogate, once, for every document it parses: request bodies, JWS headers and payloads, operator bodies. The walk uses its own stack. The Hypothesis test over signed claims draws text with surrogates (joined from single characters: `st.text()` never yields one, whatever its alphabet) and runs on SQLite as well as memory; a second test fills every string claim of DPoP proofs, key proofs and key attestations with such text. | test_n4_m1_*; test_n3_m1_hypothesis_over_signed_dpop_and_key_proof_claims[memory, sqlite] |
| N4-M2 malformed X.509 gives 500 | `b7fd8d1` | `load_x5c` reads every part of each certificate the path checks use (extensions, key, signature hash, validity, names, serial) and turns whatever cryptography raises into a JoseError; loading itself catches everything too (a fuzzed version number raises `InvalidVersion`, found by the new fuzz test). `validate_path` turns any exception into a refusal, which covers anchors and CRLs the loader never sees; the CRL loader reads each CRL in full; the anchor loader turns any exception into a ConfigError. A Hypothesis test changes bytes of the KA signer certificate and signs the attestation over it. | test_n4_m2_* |
| N4-M3 status token re-signed at a revocation | `7deb484` | A revocation with a jitter no longer moves the list's revision, and neither does a decoy laid down hidden. The token is signed again when a hidden bit comes due (pending markers now outlive their moment by one token ttl, so a token signed before can tell), on half its ttl, or for a change that shows at once (a jitter of 0, decoys laid down when a list opens). The test polls a list every minute for three hours and gets the very same tokens whether the person is revoked at minute 10, at minute 70, or not at all with a decoy showing instead. The review's `s4` simulation: 0 quiet rebuilds, 0 of 400 revoked bits flagged. | test_n4_m3_* |
| N4-M4 torn anchor write; 500 after a commit | `795b86e` | A torn last line found under the lock is closed with a newline (unless a repair already closed it) and its line written again in full; the reader skips a line that is the start of the next one, which is exactly what a repaired tear looks like, since a line depends only on its entry and the line before it. A torn line that is not the start of what cunho writes next is refused. The repair is audited (`audit.anchor_repaired`, with the torn length), logged to `cunho.security`, and reported by verify. The lines a crash left out are written before the next transaction changes anything, which is refused when they cannot be, so at most one committed action is missing from the anchor; a failed anchor write after a commit is logged and the action answered as done. Recovery after restoring the database from an older backup is documented as not available in M2 (see below). | test_n4_m4_*; test_n_h1_store_ahead_of_the_anchor_is_caught_up |
| N4-M5 revoking a person leaves their offer and token live | `cfdf492` | A subject revocation closes the subject's offer when it can still yield a credential (`offer_cancelled` in the answer and in the log entry); the token endpoint and the credential endpoint refuse a closed subject. `POST /admin/offers/{subject_ref}/cancel` cancels an offer on its own, logged as `offer.cancelled`, and erases the subject data it held. Issuance writes its issued rows and checks the closed mark in the transaction of its own log entry; a subject revocation reads the rows and sets the mark in its own, so the two cannot miss each other. | test_n4_m5_* |
| N4-M6 several CRLs from one CA | `b7fd8d1` | Every usable current CRL from the issuer is collected. The newest, by CRL number and then by thisUpdate, decides, so a certificate it lists is refused whatever the reason; and since an older CRL cannot take a revocation back, a certificate any current CRL lists is refused too, except a certificateHold that the newest CRL no longer lists. | test_n4_m6_* |
| N4-M7 verify false alarms under load | `795b86e`, `8853531` | `verify` read the head pointer first and the anchor last, so an entry appended in between looked removed. It now reads the checkpoint, the head and the anchor's last line together, under the audit lock and the anchor `flock` that every writer holds, and reads anchor lines only up to that last line. A pytest test runs three worker processes appending to one SQLite file and one anchor while the parent verifies (all valid); another appends from a thread right after verify reads the head, which kills the mutant that drops the locks every time (the full mutation run found the threaded tests catch it only sometimes). The race suite and the soak now verify under load too. | test_n4_m7_*; suite2 `sc_verify_under_load`; suite6 |
| N4-M8 wall-clock excursions | `c3ad3e5`, `41b9b21` | A clock watch compares each reading with the last one maintenance trusted. Behind it by more than two minutes, or ahead by more than two maintenance intervals, and pruning, the background sweep and decoy scheduling wait, with an error in `cunho.security`, until a reading agrees again, or the new time has held for a whole interval (then it is trusted, with a warning). The trusted time is kept in the store for restarts. A clock that went back no longer stalls the interval check, and a decoy schedule mark further ahead than any worker could set is laid down again. `force=True` (tests, the operator's own scripts) vouches for the clock. | test_n4_m8_* |
| N4-L1 WAL checkpoint result ignored, 30 s stall | `c3ad3e5` | The checkpoint waits at most a second for readers, then restores the 30 s busy timeout, returns whether the WAL was emptied, and is tried again on every background tick until it is, with a warning meanwhile; maintenance reports `wal_cleared`. | test_n4_l1_* |
| N4-L2 exp in the audit log | `cfdf492` | `credential.issued` no longer records `exp`; it records the configured `validity_days`. | test_n4_l2_* |
| N4-L3 critical inhibitAnyPolicy refused | `b7fd8d1` | inhibitAnyPolicy and policyConstraints are known critical extensions. A policyConstraints that requires an explicit policy is honoured when the deployment names its policies and refused when it does not; inhibitPolicyMapping always holds, since mappings are refused. The earlier test now uses a critical inhibitAnyPolicy, as a conforming CA would. | test_n4_l3_*; test_n3_l9_policies_on_intermediates |
| N4-L4 revocation and its entry not pinned | `cfdf492` | A test makes the bit flip fail after the log entry and checks that the entry is gone and the bit still 0, by slot and by subject, on both stores. The memory store did not roll back a failed `atomic()` unit at all, so this could only hold on SQLite; it now keeps a journal and undoes the unit as SQLite does. Mutants R1a and R1b move the flips out of the transaction. | test_n4_l4_* |
| N4-L5 settings that cannot be set | `89ec6a8` | `Settings.from_env` reads every tuning setting (the list in README), and a value that is not a number refuses to start with the variable's name. | test_n4_l5_* |
| N4-L6 anchor rollover | `b7fd8d1` | Every anchor whose key verifies the top of the chain is tried; the path is refused, with the first such anchor's reason, only when none passes. | test_n4_l6_* |
| N4-L7 fuzz and chaos blind spots | `25ea352` | The stress fuzz suite joins text from single characters, surrogates and NUL included, fuzzes `strict_json` and JWS payloads, and changes bytes of a KA signer certificate, in-process and signed over HTTP. The chaos suite fills the disk under the anchor (torn write after a commit, then no room, then room) and runs maintenance during a 400-day clock jump. The race suite and the soak verify the audit log under load. | tools/stress |
| N4-L8 false DESIGN sentences | `e7f52ab` | §3.3 says how each class of client input is refused where it is parsed, and that the absence of 500s is what the fuzzing shows, not a proof; §4 status says the token changes only when a bit shows and on its cadence, names the decoy rate setting, and says a revocation closes a live offer; §7 describes the torn-line repair, at most one unanchored action, and the restore limit; §7 says erasure is complete after the next checkpoint no reader holds up; §7 says the exact expiry is not logged; §4 trust and maintenance describe the CRL choice, rollover, policy extensions and the clock watch. | DESIGN.md |
| CI mutation shard 1/4: ST2 survives on Linux | `c3f9399` | The ST2 mutant (`PRAGMA secure_delete=ON` left out) survived on the Ubuntu runner and was killed on macOS. The only test of it read the pragma back, and Debian's libsqlite3, which the runner's Python links, is built with secure_delete on by default, so leaving the pragma out changed nothing there. The new test starts every connection with secure_delete off, whatever the build, checks the store turns it on, and looks for a deleted row in the database file after a checkpoint. | test_secure_delete_is_on_even_where_the_build_leaves_it_off |

Earlier tests changed on purpose:
- `test_n_h1_store_ahead_of_the_anchor_is_caught_up` and `test_n3_l1_a_malformed_entry_stops_catch_up_cleanly`: a failed anchor write after the commit no longer fails the append.
- `_crash_once` in `test_review3_units.py` models a crash as an anchor write that never happens, since a raised error no longer leaves the entry unanchored.
- `test_n3_m2_a_wiped_log_with_its_anchor_removed_is_not_started_again`: verify now takes the anchor lock first, so it reports the missing file in the words the writers use.
- `test_routes_and_methods`: the cancel route.

Mutation run: 1,392 of 1,392 mutants killed in `--all --select` mode (292 removed refusals and raises, 1,005 altered conditions, 95 hand-written changes, of which 32 are new this round), none listed as equivalent; rules mode 45 of 45. The run before the last commit left one survivor, a boundary of the clock watch, which `41b9b21` pins; an earlier run found the verify locks killed only some of the time, which `8853531` pins. The same run on CI (four shards and rules mode, Ubuntu) passed on `e7f52ab`, ST2 included. Review 4's `mut/semmut.py`, run again: R1 no longer applies (the code it patched moved; it is carried over as R1a and R1b and killed), R2 to R8, R13 and R14 are killed, and R9, R10 and R12 survive as before, the three the review itself judged equivalent or out of reach of a unit suite.

Not fixed, and why:
- A database restored from an older backup cannot be told from one whose newest entries were removed, so cunho stops logging on top of it, as before. M2 has no step that re-bases the anchor on a restored database, because such a step would let a deletion through as well; a re-base that cannot be abused needs the anchor signed by a key off the database host (M4). DESIGN §7 and README say so, and what to do meanwhile.
- A clock that is wrong from the moment cunho starts, and stays wrong, cannot be told from a long stop; the watch only catches a clock that moves. DESIGN says NTP must be in sync before cunho starts.
- A clock that jumps ahead and holds its wrong time for a whole maintenance interval is trusted after that interval, so a long excursion can still prune early; a shorter one cannot.
- While a reader holds the write-ahead log, erased data stays in it until a checkpoint succeeds; cunho retries about once a minute and warns, but cannot force a reader off.
- With a jitter of 0 a revocation is published at once, and its moment with it, by choice; the stress harness runs that way.
- From review 4's semantic mutants, R9 (anchor without `fsync`) and R12 (maintenance without its own sweep, which the background task does anyway) remain without a unit test, as the review judged them untestable in a unit suite or equivalent; R10 is stricter, not weaker.

Stress run: all six suites, full mode with the 30-minute soak, from a fresh clone of `e7f52ab`: 97 of 97 checks pass (`evidence/stress/2026-11-04-e7f52ab/`).

Re-running the reproductions:
| Script | Result now |
|---|---|
| review 4 `s1_lone_surrogate` | 400 on both stores, `/token` and `/credential` (was 500 on SQLite, and on `/credential` everywhere) |
| review 4 `s2_anchor_torn_write` | offer during the full disk 201, next offer 201, verify `(True, '... 1 torn anchor line(s) were closed and written again')`, also after a restart |
| review 4 `s3_verify_false_alarm` | 200 of 200 verifications valid during appends (was 102 of 200 failing) |
| review 4 `s4_status_iat_leak` | 0 quiet rebuilds, 0 of 40 revocation moments revealed; 0 of 400 revoked bits and 0 of 836 decoy bits flagged (was 35 of 40, 362 of 400) |
| review 4 `s5_revoke_then_issue` | the revocation answers `{'revoked': 0, 'offer_cancelled': True}`; redeeming the offer two minutes later gets 400 `invalid_grant` "this offer was cancelled" (the script stops there, as it expected a token) |
| review 4 `s6_clock_excursion` | maintenance at +400 days answers `{'clock_not_steady': 1}`; 5 entries and verify valid after the correction; maintenance two hours later runs and schedules decoys; 30 days later decoys are still scheduled |
| review 4 `s7_list_open_cost` | 63 ms to open a list, 96 ms to rebuild a 62k-slot token (unchanged, not a finding) |
| review 4 `s8_x509_exceptions` | all five certificates 400 `invalid_proof` (was 500 for three) |
| review 4 `s9_crl_order` | 400 in all three orders (was 200 with the old CRL first) |
| review 4 `s10_checkpoint_ignored` | maintenance with a reader open takes 1.1 s (was 32 s with the store lock held) and logs that the WAL was not cleared; the script keeps its reader open, so the key stays in the WAL until a later try; the script's own direct `wal_checkpoint` call still waits its 30 s |
| review 4 `s11_audit_exp_attribute` | `credential.issued` has no `exp` (the script stops with KeyError looking for it) |
| review 4 `s12_anchor_rollover` | PID issued in all three orders (was 400 with the expired copy first) |
| review 4 `race/race4.py` (4 workers) | 1×200 for every single-use race, 5 tx_code comparisons; case 6 (surrogate jti) 400; case 7, 60 verifications under load: 60 valid (was 53 of 60 failing); 0 tracebacks |
| review 4 `rerun3/r2_anchor_history`, `r2b`, `r8` | (a) `the store diverges from the anchor at sequence 2`; (b) a running process refuses to log after unlink and wipe, a restart without the init flag refuses to start (the script's own constructor sets the flag, which is the documented way to start a new deployment); r8 with a 3600 s jitter: the ten bits show over the next hour |
| review 3 `r1`, `r3`, `r4`, `r5`, `r9` | as in review 4: 400 for huge iat; 18 MiB per limiter table; no sweep in requests; verify `{"valid": false}` and a clean 500 for the head; the forged token row 401 (the script stops there) |
| review 3 `r6`, `r7` (given the real tree) | 400 |
| review 3 `r2` | needs `create_anchor=True` since review 3 (the adapted copy is review 4's `rerun3`) |
| review 3 `race/race.py` (4 workers) | 1×200 for every single-use race, 5 tx_code comparisons, audit verifies, no 5xx |
| review 2 `q1`, `q2`, `q4`, `q5`, `q7`-`q10`, `q13`, `q14` | refused or correct as in review 4 (`q2`: wipe and truncation fail verification; `q13`: a failed log write leaves the bit at 0) |
| review 2 `q3`, `q6`, `q11` | stop with an exception on purpose: no audit entry for a failed login, startup refuses an unbound PID, the DPoP proof with `crit` is refused (400) so no token is issued for the second half |
| review 2 `q12` (real 4-worker server) | 400 for a 200 MiB chunked body, RSS 62 to 63 MiB, no traceback |

## Fifth review (cunho-m2-review-5.md): fixes

The review graded M2 8/10 and listed what a 9 and a 10 would need. All of it is done here except the pre-authorized part of the OIDF test plan in CI, which needs the suite's code and network access and moves to M3 with the rest of the OIDF work. Tests are in `tests/engine/test_review5_anchor.py`, `test_review5_revocation.py`, `test_review5_status.py`, `test_review5_clock.py` and `test_review5_input.py`, named with the finding id, and the slow suites in `tests/slow` run as their own CI job (`pytest -m slow`).

| Finding | Commit | Change | Test |
|---|---|---|---|
| N5-M1 anchor repair handles one shape of damage | `956878d`, `0453e3b` | Whatever follows the last valid line, found under the lock, is damage. The next write closes it with a newline and its first line declares it, by offset, length and SHA-256, under the line's tag; the reader skips bytes only where the next line declares exactly those bytes. So a repair cut short, a NUL tail, garbage or a line missing only its newline are all repaired by the next write that gets through, while bytes no line accounts for, or a declared stretch changed later, fail verification. The tail is read backwards in growing stretches until a valid line, so a long NUL tail is read past. Verify reports undeclared damage at the end as invalid ("the next logged action, or maintenance within a minute, repairs it"); the background tick repairs it. | test_n5_m1_* (every cut point of the write, every cut point of the repair, NUL tails of every length, five garbage tails, the background repair); test_n4_m4_* (rewritten); tests/slow/test_anchor_faults.py (every pair of cut points in two writes in a row, writes 1 and 2, 1 and 3, 1 and 4, with and without a restart, NUL tails then a torn repair) |
| N5-M2 revocation misses a second configuration in flight | `cd60181` | A subject revocation always sets the closed mark, whatever the vault holds; issuance checks it before signing and again in the transaction of its own log entry. Whether an offer is live is read from what it can still yield (configurations whose issuance committed are recorded in that transaction), not from the vault. `offer_cancelled` says whether anything could still have been issued. | test_n5_m2_a_revocation_between_a_claim_and_its_commit (the review's t3, deterministic), test_n5_m2_the_issuance_transaction_checks_the_mark, test_n5_m2_offer_cancelled_says_whether_anything_was_on_its_way; tests/slow/test_revocation_race.py (three worker processes, 60 rounds); tests/slow/test_model.py |
| N5-M3 status endpoint cost under mass revocation | `5847b9a` | Lists are published on fixed moments, every `status_publish_interval` seconds (60 by default), with `iat` at that moment and the bits due by then. The published bits are kept in the store; hidden bits wait in a queue keyed by the moment each shows (`Store.scan` takes an upper key), so a publication reads only the bits that came due and a poll between publications is a dictionary lookup in the worker, with no store access. Each worker signs a list once per publication, concurrent polls waiting for the one that signs, and the background tick brings every list forward. `/status` is rate-limited per client (`status_rate_limit_per_minute`, 600 by default). | test_n5_m3_* (20,000 hidden bits: 500 polls read no row, a publication reads only the bits due; one signature for eight concurrent polls; the rate limit; the background tick); tests/slow/test_status_load.py (100,000 hidden bits: p99 of a cached poll under 1 ms, HTTP polls under 10 ms, the slowest of 60 publications under 0.5 s, every bit shown within the hour); stress suite1 |
| N5-L1 repair entry rolled back with a refused action | `956878d` | `audit.anchor_repaired`, with the offset and length, is written in a transaction of its own before the action's, and anchored at once; when no committed entry was missing, its own line is the one that declares the damage. | test_n5_l1_the_repair_entry_survives_a_refused_action |
| N5-L2 verify reports a gap while pruning runs | `956878d`, `0453e3b`, `8af3c2f` | On a gap, or at the end before the head, verify reads the checkpoint again; when pruning moved past it, it goes on from the new checkpoint (MACed like an entry, matched against its anchor line, held to the retention period and to a signed head), and starts over only when everything it was reading was pruned. | test_n5_l2_* (pruning from another worker during the walk: past the page, up to the head, a young checkpoint, the retention boundary, no retention, a signed head at the new checkpoint; real gaps after a checkpoint) |
| N5-L3 a store call on the event loop | `5847b9a` | The status route answers from the worker's cache without touching the store, and everything else runs in the thread pool. | test_n5_l3_status_never_touches_the_store_on_the_event_loop |
| N5-L4 changing the list size breaks a deployment | `5847b9a` | Each list stores the size it was opened with, and every use of a list (reservation, the fill limit, decoys, the published length, the revocation index check) takes it from there. | test_n5_l4_changing_the_list_size_leaves_open_lists_alone |
| N5-L5 a planned stop treated as a clock fault | `2cc084a`, `492dfd0`, `fe0761c`, `80e20a4` | The clock watch keeps the host's own clock (CLOCK_BOOTTIME on Linux, CLOCK_MONOTONIC on macOS, both counting sleep) and boot id with the time it trusts, in memory and in the store. A reading far from the last trusted one is trusted at once when the wall clock moved as far as the host's clock on the same boot (a stop or a pause), or, after a host restart, when it is forward and the kernel reports NTP sync (`ntp_adjtime`). A new time held for an interval is no longer trusted while the kernel says the clock is unsynchronised. | test_n5_l5_* |
| N5-L6 trailing newline; erasure of unknown references | `cd60181` | Subject references carry a keyed tag (10 random bytes and 8 bytes of MAC) and are matched whole, so a reference cunho never handed out, or one with a trailing newline, is refused by erasure, cancellation and revocation alike; `subject.erased` records `data_held`. | test_n5_l6_* |
| N5-L7 revoking a person revokes one offer | `cd60181` | An operator may give an opaque person handle when creating an offer; only its keyed reference is stored, never logged, for as long as a credential from the offer can be valid, and `{"person": ...}` revokes every offer made for it, in one transaction and one log entry naming the subject references. Erasing a subject removes the link. README says plainly what a revocation by subject reference covers, and that an operator who gives no handle must map persons to references. | test_n5_l7_*; test_n4_l4_a_failed_bit_flip_rolls_the_log_entry_back[person]; tests/slow/test_model.py |
| N5-L8 one future-dated entry blocks pruning | `2cc084a`, `41b409e`, `8af3c2f`, `492dfd0`, `fe0761c` | From the same host clock evidence, the watch tells the audit log the range a reading should fall in, read without the watch's lock (see the stress run below); an entry outside it gets the time it should have read and keeps the reading as `clock`. Independently of that, pruning passes over an entry dated more than a day after the moment it runs and removes it with the first older entry after it, which the chain orders after it. | test_n5_l8_* |
| N5-L9 test gaps | `956878d`, `cd60181`, `4744d72`, `efbde7c`, `3b70fe9` | S8 (the closed mark living 300 s) is killed by redeeming an offer revoked at once near the end of its life; S17 (verify without the anchor `flock`) by a second log with its own file handle that appends right after verify reads the head, every time. The load-sensitive Hypothesis failure was its health check timing data generation; the engine's Hypothesis tests now leave that check out. The stress chaos suite tears the repair and leaves a NUL tail; the load suite polls `/status` with 100,000 hidden bits. | test_s8_the_closed_mark_outlives_the_offer, test_s17_verify_holds_the_anchor_lock_against_another_worker; tools/stress |
| N5-L10 false DESIGN sentences | `31615bf` | §7 describes the declared-damage repair, that verify never reports damaged anchors valid, and the repair entry in its own transaction; §7 says how a revocation and the issuance of any configuration cannot miss each other; §4 maintenance describes the host clock evidence and what still cannot be told apart; §4 status and README say what a subject reference and a person handle cover. | DESIGN.md, README.md |
| N5-L11 parser and configuration hygiene | `89ec6a8`, `cd60181` | `strict_json` decodes bytes as UTF-8 before parsing; a JWS that does not parse answers fixed text, except cunho's own refusals; boolean settings take true/1/yes/on and false/0/no/off and refuse anything else; a subject revocation erases the subject data. | test_n5_l11_* |

From review 4's partly fixed findings, as review 5 listed them:
- **N4-M4** (torn anchor write): see N5-M1 and N5-L1.
- **N4-M5** (revocation and live offers): see N5-M2 and N5-L7.
- **N4-M7** (verify false alarms): see N5-L2.
- **N4-M8** (wall-clock faults): an excursion held for a full interval is now trusted only when the kernel does not say the clock is unsynchronised; a restart after a stop is told from a step (N5-L5); a request-time reading no longer damages retention (N5-L8).
- **N4-L7** (fuzz and chaos blind spots): see N5-M1, N5-M3 and N5-L9.
- **N4-L8** (false DESIGN sentences): see N5-L10.

The review's 10-bar items:
- **Model-based concurrency test** (`580ff67`): `tests/slow/test_model.py`, a Hypothesis state machine across four worker processes on one SQLite file, one anchor and one key, with one test clock the parent moves. Rules: offers with one or two configurations, with or without a person handle, redeemed at once or later; token exchanges; credential requests; a race of an offer's remaining configurations against the revocation of its subject on other workers; revocation by subject and by person; cancellation; erasure; time moving on by a second to two days; forced maintenance (with pruning, the retention period being a day) and the background tick. A plain model gives the expected answer of every request. After each step: the audit log verifies from a random worker; every credential whose subject or person was revoked is revoked in the store, and in the published list once its publication came; every other credential handed out is valid. 30 examples of up to 40 steps per run; it killed the vault-only closing mutant and a status cache mutant when tried by hand.
- **Fault injection for the anchor and the store, in CI**: the engine suite cuts the anchor write at every byte, the repair at every byte, and leaves NUL and garbage tails; the slow job cuts every pair of points in two writes in a row, with restarts. Crashes between commit and anchor were already covered (`_crash_once`, the chaos suite); I/O errors on the store are the chaos suite's disk-full part.
- **Clock handling that tells a stop from a step**: N5-L5 and N5-L8.
- **Person-level revocation**: N5-L7.
- **The OIDF test plan**: not done, moved to M3 (see below).

Earlier tests changed on purpose:
- The N4-M4 tests (`test_review4_fixes.py`) are rewritten for declared damage: a fragment is no longer recognised by being the start of the next line, so the tests now check that undeclared bytes are refused and that a declared stretch cannot be changed. `test_n_h1_anchor_lines_are_chained_and_strictly_increasing` and `test_anchor_file_damage` expect the new messages.
- The N4-M3 tests: the token now changes on every publication, at fixed moments, whatever happens; the test checks the very same tokens come out whether the person is revoked at minute 10, 70 or not at all, and that the moments are the publication moments.
- Tests that read a published bit right after a revocation with a jitter of 0 move the clock one publication on (`test_revocation_and_audit`, `test_status_list_token`, `test_status_token_is_cached_until_a_bit_changes`, `test_n4_m3_with_no_jitter_a_revocation_shows_at_once`); the jitter bound test allows for the publication interval.
- `test_n4_m5_a_subject_with_nothing_live_is_refused` uses a reference cunho could have handed out, and checks a forged one is refused as not handed out.
- `test_n_m1_duplicate_unicode_members_get_a_clean_401` and two N3-M1 tests still see cunho's own refusal text; only the decoder's text is no longer echoed.

Mutation run: 1,482 mutants in `--all --select` mode (296 removed refusals and raises, 1,062 altered conditions, 124 hand-written changes), none listed as equivalent; rules mode 45 of 45. Of the hand-written changes, 35 are new this round, 12 were carried over to the code they used to patch, and 6 were dropped with the code they patched (the old torn-line repair, the pending markers and the revision counter), each replaced by a new one on the new code. The full run on `0453e3b` killed 1,468 of 1,479. The 11 survivors were two branches of verify's checkpoint hop, the edge of "ahead" in pruning, eight clock watch checks that were redundant with another or never reached by a test, and the publication interval's bound; `8af3c2f` and `492dfd0` pin them (the second also gives the host clock evidence one object, so no check is redundant). After the deadlock fix below, the clock watch mutants ran again (37, one survivor about a nameless boot, pinned in `80e20a4`, then the 11 of its range all killed), as did every verify (54), prune (2) and settings-check (46) mutant and the twelve W patches: all killed on the final tree. Every other mutant is on code the full run saw unchanged. The same run on CI then kept T1b alive in shard 2 of 4 (a new list's decoy bits written MSB first): locally it had been killed only because a misplaced decoy happened to land on a credential a test looked at. A test now checks that a new list publishes exactly its decoys, each at its own bit, which kills it every time. Earlier, a first pass over the hand-written mutants found R1c and T23 alive (pinned in `4744d72`), and the first part of a full run on `3b70fe9` found the anchor's own line check, which could no longer refuse anything, and a status id length limit that decided nothing (both removed in `0453e3b`). Review 5's `mut/semmut5.py`, run again: S5, S7 to S10 and S13 to S18 are killed, S8 and S17 now every time (S8 by `test_s8_the_closed_mark_outlives_the_offer`, S17 by `test_s17_verify_holds_the_anchor_lock_against_another_worker`, a deterministic test rather than a race that is won some of the time). S1 to S4, S6, S11 and S12 no longer apply: they patched the pending markers, the revision counter, the token cadence and the torn-line repair, which are gone; their counterparts on the new code are T2, T3, T8, T11, T17, A13 and A19 in `patches.py`, all killed, and S4's (a revocation that shows exactly `jitter` seconds later) applied by hand is killed by `test_n3_m3_a_batch_revocation_is_spread_over_the_window`.

Every new concurrency test ran 20 times in a row on the final code, all passing: the engine's interleavings (S17, the N5-L2 pruning tests, the N5-M2 interleaving, concurrent signing, the cached poll, the tick and a request that must not deadlock) and the slow race and model tests across worker processes.

Not fixed, and why:
- **The OIDF test plan in CI.** It needs the OpenID Foundation's suite and network access, so it moves to M3 with the authorization code flow, as DESIGN §10 already planned for the full plan.
- **A wrong clock at a host restart.** When the host restarted and the kernel does not report NTP sync, a clock that is wrong from the start still cannot be told from a long stop; the watch then waits for the clock to read steadily for an interval, as before. DESIGN and README say to start cunho after NTP sync (`After=time-sync.target`).
- **Test clocks.** A clock passed in for tests or simulations has no host clock behind it, so the watch goes by the wall clock alone. The review's t8 passes one, and still shows a stop held back for an interval; the same stop with the host clock behind it is trusted at once (test_n5_l5_a_planned_stop_is_not_a_clock_fault). Its t12 passes one too, and now prunes all 100 entries through the second change (pruning past an entry dated ahead), which needs no host clock.
- **Bits due during a stop.** Decoys and revocations that came due while cunho was stopped all show at the first publication after it starts; they are indistinguishable from each other, but their number shows. Re-spreading them would hide revocations later than the jitter promises.
- **Revocation by person after erasure.** Erasing a subject removes its link to the person handle (it is personal data under GDPR), so a later revocation by person no longer covers that subject; its credentials stay revocable by `subject_ref`. README says so.
- **The status cost per publication** still grows with the size of the list (decompressing and compressing its bits, about a millisecond for 131,072 bits), once per publication per worker and list, never with the number of hidden bits or of polls.

Stress run: all six suites, full mode with the 30-minute soak, from a fresh clone of `709a9a4`: 101 of 101 checks pass (`evidence/stress/2026-11-04-709a9a4/`). The first full run, against `31615bf`, did not: its soak server stopped answering within a minute. A request logging an entry held the store and asked the clock watch for its range while the background tick held the watch's lock and wrote the store, a deadlock between the N5-L8 change and the clock watch that no engine test could see, since none runs a request and the tick in two threads of one worker. `fe0761c` reads the range without the lock and adds a test that deadlocked every time on the old code; `709a9a4` gives the soak's last verification the ten minutes the others had (the default ten seconds no longer fit 752,689 entries). In the passing run, a status list with 100,000 hidden bits answered eight pollers 5,207 times a second with metadata at p95 2.8 ms; the soak ran 329,354 flows and 28,038 revocations with no error, verified the log 26 times under load and its 752,689 entries at the end.

Re-running the reproductions:
| Script | Result now |
|---|---|
| review 5 `t1_anchor_second_tear` | (a) offers after the second tear: 201, 201, 201; verify `(True, '... 1 damaged stretch(es) of the anchor (200 bytes) were closed and declared')`, also after a restart; (b) after the NUL tail: 201, 201, 201, verify valid with the stretch declared (was 500 for good, and verify valid over the NULs) |
| review 5 `t2_repair_entry_rolled_back` | `audit.anchor_repaired logged: True` though the first action after the tear was refused |
| review 5 `t3_revoke_race_two_configs` | the revocation answers `{'revoked': 1, 'offer_cancelled': True}` and request B gets 400 (was 200 with a valid PID) |
| review 5 `t4_verify_during_prune` | 6 of 6 verifications valid while pruning (was 4 of 6 false) |
| review 5 `t5_list_size_change` | `GET /status/1` 200 after the restart with half the size (was 500); a slot past the new size is accepted for revocation |
| review 5 `t8_restart_after_stop` | unchanged: 60 ticks held, because the script passes a test clock with no host clock behind it (see "Not fixed") |
| review 5 `t9_status_rebuild_storm` | 1,201 polls in 60 s, 1 rebuild, 0.0 CPU-seconds (was 469 rebuilds and 352% of a core); the script then stops looking for `_moments`, which is gone |
| review 5 `t9b_status_http` | 8 pollers: 1,625 responses/s (was 4/s); metadata 13 to 32 ms while they poll, one first request at 370 ms (was up to 2,073 ms) |
| review 5 `t7_event_loop_block` | with one status GET waiting on the lock, metadata answers in 0.01 s (was 4.44 s) |
| review 5 `t10_erase_newline` | 400 for `<ref>%0A` and for a reference never handed out, nothing logged, data kept |
| review 5 `t11_person_vs_offer` | unchanged by design: revoking the latest `subject_ref` covers that offer; the person handle covers both (test_n5_l7_*) |
| review 5 `t12_future_entry_blocks_pruning` | `pruned: 106 | entries kept although past retention: 0` (was 100 kept) |
| review 5 `t13_hygiene` | (a) `strict_json` refuses the UTF-16LE body (the script stops there, expecting it parsed); (b) run on its own: 400 "DPoP proof is not a valid JWS: header or payload is not valid JSON", no byte echoed |
| review 5 `race4_rerun` | 1×200 for every single-use race, 5 tx_code comparisons, the surrogate jti 400, 60 of 60 verifications valid, 0 tracebacks |
| review 4 `s1` to `s3`, `s5` to `s12` | as in the fourth round's table; `s2` now reports the declared stretch, `s3` 200 of 200 valid |
| review 4 `s4_status_iat_leak` | its classifier flags a bit as a revocation when the token changed without a new bit in the hour before. Lists are now published every minute whatever happens, so every bit, revoked and decoy alike, is flagged (400 of 400 and 760 of 760): it can no longer tell them apart, which is the property; the engine's N4-M3 test shows the tokens are identical whether a person is revoked at minute 10, at minute 70 or not at all |
| review 4 `race/race4.py`, `rerun3/*` | as before: 1×200 per single-use race, 60 of 60 verifications valid, 0 tracebacks; `r2` and `r2b` as in round four; `r8` shows the ten bits over the next hour |
| review 3 `r1`, `r3` to `r5`, `r8`, `r9`, `race/race.py`; `r6` and `r7` given the real tree | refused or correct as in round four; `r8` with a jitter of 0 shows the ten bits at the next publication, a minute later |
| review 2 `q1`, `q2`, `q4`, `q5`, `q7` to `q10`, `q12` (a real 4-worker server), `q13`, `q14`; `q3`, `q6`, `q11` | as in round four: `q12` 400 for a 200 MiB chunked body with RSS 63 to 64 MiB and no traceback; `q3`, `q6` and `q11` stop on purpose as before |

---

## Sixth review (cunho-m2-review-6.md): fixes

The review graded M2 7/10: one High finding, the audit anchor made to lie by a copy of one of its own lines, three Medium ones about time and upgrades, five Low ones, and three of review 5's items partly fixed. Every round so far had added new robustness bugs in the code it added, so this one removes and simplifies where it can, picks the plainest rule that is obviously correct for each subtle mechanism, and says in DESIGN what that rule gives up. Tests are in `tests/engine/test_review6_anchor.py`, `test_review6_clock.py`, `test_review6_upgrade.py` and `test_review6_issuance.py`, named with the finding id, and in `tests/slow/test_model.py`.

| Finding | Commit | Change | Test |
|---|---|---|---|
| N6-H1 a copied anchor line makes verify call a truncated store valid, and stops logging while verify stays green | `8605f1a` | Removed: the backward reader that took the last valid line as the end, the tail cache keyed by size, `_through` and verify's own "behind" check. The anchor is now read only forwards from its first line, by one reader that writers and verify share: every line must follow the one before it (genesis first, `prev` the tag of that line, sequence one more), and bytes between lines must be declared by the next one, as before. A valid line that repeats or goes back is refused wherever it is ("repeats or goes back (sequence s after t)"), so the end is always the last line of one unbroken chain, which is the highest. Logging stops until an operator removes the copy (DESIGN §7 and README say how). Each worker remembers how far it read and reads on from there, and from the start again when the file is shorter. Verify takes the size under the locks, runs the writer's own check of the anchor's last line against the store, so it fails whenever cunho refuses to log, fails while any entry is not anchored yet (it used to report "7 newest not anchored yet" as valid), and reads the file up to that size, never up to a sequence. | test_n6_h1_a_copy_of_any_earlier_line_is_refused (every earlier line, genesis included, before and after pruning, with the store left alone or cut back to every entry it holds, by the running worker and after a restart), test_n6_h1_a_copy_without_its_newline_and_two_copies_in_a_row, test_n6_h1_reordered_and_removed_lines, test_n6_h1_the_end_is_never_behind_the_head_a_worker_saw, test_n6_h1_verify_and_logging_never_disagree, test_n6_h1_a_store_ahead_of_its_anchor_is_never_valid, test_n6_h1_a_line_after_a_long_run_of_bytes_is_not_a_line, test_n6_h1_a_worker_reads_a_shorter_anchor_again_from_its_start; tests/slow/test_model.py (`anchor_line_copied`) |
| N6-M1 a revocation made while the clock reads ahead stays hidden after the clock is put right | `8f20918` | The moment of a revocation is laid from `ClockWatch.request_time`: the reading kept within the range the host clock gives (the last trusted reading moved on by the host's own clock, give or take two minutes), the same evidence the audit entry times already used. So the bound is measured on the host clock, which steps do not move. When the watch has no trusted reading to go by yet, the bit shows at the next publication, without its jitter, with a warning. The settings check for the 24-hour bound now counts the two minutes. | test_n6_m1_a_revocation_under_a_wrong_clock_keeps_its_moment (two days and twenty minutes, ahead and behind), test_n6_m1_without_evidence_a_revocation_shows_at_the_next_publication, test_n3_m3_jitter_setting_is_checked; tests/slow/test_model.py (`revoke_under_a_wrong_clock`, up to two days either way, with the visibility bound checked on the time that really passed) |
| N6-M2 an upgrade from 45ec9be un-publishes every revocation and decoy | `62c0257` | The store carries a schema version (`src/cunho/schema.py`). A store without one is upgraded once, in one `BEGIN IMMEDIATE` transaction, before anything else runs: each list gets a stored size (45ec9be had none and took the setting, so the upgrade takes the setting and refuses to start when a slot lies beyond it), bits still hidden are queued by their moments and the old queue rows go, the published bits are rebuilt from the slots, subject references from before the keyed tag are recorded as handed out, and offers whose data is still in the vault stay live until their window ends. A version it does not know refuses to start. `_unpack` no longer answers zeros: a list without a stored size, or without published bits of its size, is a 500 and an error in `cunho.security`. | test_n6_m2_an_upgrade_from_45ec9be_publishes_every_bit_it_showed (the store is made by the 45ec9be code, checked out into a temporary git worktree and run in its own process), test_n6_m2_offers_from_before_the_upgrade_can_still_be_ended, test_n6_m2_an_upgrade_that_cannot_know_the_size_refuses, test_n6_m2_missing_status_state_fails_loudly, test_n6_m2_a_store_from_382505f_keeps_its_sizes_and_bits |
| N6-M3 after a reboot, one wrong time source prunes the whole log | `8f20918` | Pruning, the one irreversible action, waits until the clock has read steadily for an interval since the last reading that moved too far, whatever explained it: a stop the host clock explains and a restart with NTP in sync now hold it too (sweeping still trusts them). The start of that steady stretch is kept in the store with the trusted time, so a restart does not cut the wait short. And maintenance never prunes an entry younger than the retention period measured against the newest entry's own time. DESIGN and README recommend an authenticated time source (NTS). | test_n6_m3_a_wrong_time_source_at_boot_prunes_nothing (the review's p3), test_n6_m3_every_explained_jump_holds_pruning_for_an_interval, test_n6_m3_pruning_goes_by_the_newest_entry_too, test_n6_m3_a_new_time_held_for_an_interval_still_waits_one_for_pruning, test_n6_m3_a_restart_with_a_steady_clock_does_not_hold_pruning |
| N6-L1 round-5 mutants only the slow suites, or none, killed | `1b76414`, `0c3438c`, `2e7b076` | Engine tests kill X11 (an issued configuration recorded for a second), X15 (what an offer can yield living only the offer ttl) and X17 (verify going on from a checkpoint past the head it read); all three are hand-written mutants now, so every CI mutation run checks them. X2 (the reader ignoring the offset of a declared stretch) cannot be killed on the new reader, or the old one: a stretch always starts where the line before it ends, the lines before it are fixed by the chain, and every stretch before it by its own length and hash, so the offset in a declaration is implied by what the reader already checks. It stays in the declaration for whoever reads the file, and is not listed as a mutant. The slow suites stay outside the mutation run: each mutant only they killed now has an engine test. | test_x11_an_offer_whose_configurations_all_issued_is_not_live, test_x15_a_subject_revoked_after_its_offer_expired_while_its_token_lives, test_x17_verify_starts_again_when_pruning_passed_the_head_it_read |
| N6-L2 the model test does not exercise the round-5 code | `de01ad0` | Each worker's clock watch has a host clock behind it, counting the time the parent moves, and the parent can put the wall clock off without moving it. Lists carry a jitter and decoys from the start and over time. New steps revoke a fresh PID while the wall clock reads up to two days off either way, damage the anchor (torn, NUL, garbage) before the background repair, append a copy of one of its lines and check that verify fails and nothing is logged until the operator removes it, and run pruning alongside verify and a new offer on three workers. The published list is checked on the time that really passed: every revoked credential shows once the jitter and the tolerance have passed, only revoked slots and decoys ever show, and none before the moment it was queued for. 150 examples of up to 60 steps (was 30 of 40). | tests/slow/test_model.py |
| N6-L3 erasure does not stop an issuance in flight | `1b76414` | Erasure closes the subject, as a revocation does; the issuance transaction refuses it and revokes its slots. | test_n6_l3_an_erasure_during_signing_stops_the_issuance (the review's p5, deterministic) |
| N6-L4 a refused claim keeps the offer live, the claim spent and the data held | `1b76414` | A configuration and its keys are claimed in one transaction, so a key already bound leaves the configuration unclaimed; an issuance that fails or is refused before it commits gives the claim back and revokes its slots. | test_n6_l4_a_key_refused_leaves_the_configuration_to_ask_for_again (the review's p6), test_n6_l4_a_failure_after_the_claim_gives_it_back |
| N6-L5 false DESIGN sentences | `e7dc2f8`, `085d8e5` | §7 "fails when the store is behind the anchor" and "at most one committed action is ever missing" are true now (N6-H1). §4 status says the moment is laid on the clock watch's time and what happens without evidence. §10 no longer gives mutant counts or review grades, which go stale every round. The slow anchor test is described as it runs (every byte of the second write, and every byte or every fourth byte of the first). For "maintenance brings every list forward about once a minute", `6064610` first made the tick publish whatever the clock read; the stress run's clock-jump check then showed what that gave up (under a clock 400 days ahead the tick published every bit that clock called due, and a bit shown cannot be hidden again), so `085d8e5` reverts it and the sentence now says what the code does: about once a minute while the clock reads steadily, and whenever a poll comes. | DESIGN.md, README.md |

Review 5's partly fixed items:
- **N5-L4** (changing the list size): lists opened before the size was stored get one from the upgrade (N6-M2), and a list without one is never given the setting's.
- **N5-L5** (a planned stop treated as a clock fault): still trusted at once for sweeping; pruning waits an interval (N6-M3).
- **N5-L10** (false DESIGN sentences): see N6-L5.

Earlier tests changed on purpose:
- `test_n_h1_anchor_lines_are_chained_and_strictly_increasing` rewrote the anchor in place to a file of the same length with a line inserted in the middle. A worker now reads on from where it stopped, so only a full read sees such a rewrite, which is not possible on append-only storage; the test checks that verify fails and that the full read names the undeclared bytes.
- `test_n_h1_store_ahead_of_the_anchor_is_caught_up` expected verify to be valid with "1 newest not anchored yet"; it is now invalid until the next write anchors the entry.
- `test_catch_up_refuses_a_store_that_fell_behind_or_diverged` and `test_n3_h1_mutation_tool_covers_every_raise_and_guard` follow a new message and a renamed function.
- `test_n3_m3_jitter_setting_is_checked`: the bound is two minutes lower.
- `test_n3_l1_a_malformed_entry_stops_pruning_with_an_alert`, `test_n5_l8_a_reading_far_off_does_not_land_in_the_log` and `test_n5_l8_ahead_means_more_than_a_day_after_pruning_runs` pruned an idle log by the clock alone; they log an entry at the new time first.
- `test_vault_erasure_keeps_the_log_valid` and `test_n_m6_subject_data_gone_before_issuance`: an erased subject's offer is closed, so the token and the credential are refused as cancelled; "no longer available" is checked on an offer whose configurations were all claimed.
- In the model test, a race step after a revocation by slot expects the subject revocation to succeed, since the issued rows are still there.

Mutation run: 1,545 mutants in `--all --select` mode on `0c3438c` (303 removed refusals and raises, 1,082 altered conditions, 160 hand-written changes, 36 of them new this round and 15 carried over to the code they used to patch). 1,540 were killed and five survived:
- three parts of the new size and published-bits checks of a status list that could never decide anything: a size stored as `true`, a row that is not an object, and published state that is not text, each refused already by the check beside it;
- the refusal of a list that does not exist on a path that only ever sees lists it has just read;
- A18, verify reading the anchor past its snapshot: the test that covered it appended from another worker only when that worker won a race.

`2e7b076` removes the first four (the last one is now an assertion: the case cannot arise) and pins A18 with a test that appends just before verify reads the lines, every time. Every `status.py` mutant ran again on the result (12 of 12 killed), and so did A18 and every hand-written status mutant (25 of 25 killed). The tree now has 1,535 mutants (302 removed refusals and raises, 1,073 altered conditions, 160 hand-written changes), none listed as equivalent. Rules mode: 45 of 45 killed. The first try at rules mode stopped at its baseline: a Hypothesis test in `test_review3_fixes.py` had drawn a string beginning with "1" that held a lone surrogate, and wrote it into a payload unencoded; 2 runs in 320 failed so. `fd87094` encodes every string but the three numbers written out as text, and 320 runs pass. X2 is not among the hand-written mutants, for the reason under N6-L1.

Every new concurrency test ran 20 times in a row on the final code, all passing: the engine's interleavings (N6-L3's erasure during signing, X17's pruning past the head during verify, a copy appended after another worker read the anchor, verify's snapshot, every test in `test_review5_anchor.py`, the N5-M2 interleaving, the tick and a request that must not deadlock, appends from two workers) and the slow model and race tests across worker processes.

Not fixed, and why:
- **A time source wrong for a whole interval while cunho keeps logging.** It is taken as right, as before: nothing on the host can tell it from a step NTP made, and the entries logged meanwhile carry its time, so the newest-entry rule no longer protects. DESIGN and README recommend NTS.
- **Other request-time checks under a wrong clock.** The lifetimes of offers, tokens, nonces and DPoP proofs, credential validity and the issued records a revocation by subject or person finds still go by the wall clock as it reads; a revocation by subject while the clock reads far ahead misses a credential whose record that clock already calls expired. Taking all of them from the clock watch is a larger change than M2's scope; DESIGN says so, and the clock watch logs an error every minute while the clock is off.
- **Test clocks.** A clock passed in for tests has no host clock behind it, and the watch goes by the wall clock alone. The review's `p1` passes one, so it still shows the bit hidden for two days; the same revocation with a host clock behind the watch, as every real deployment has, is laid within two minutes of the true time (test_n6_m1_*).
- **A copied anchor line stops logging until an operator acts.** Anyone who can append to the anchor can do it, as anyone who can write the database can stop cunho. Taking the copy for damage and repairing it automatically would let the reader guess which line is the real end, which is the bug this round fixes.
- **Anchor files repaired by 45ec9be.** Its torn-line repair left the fragment before the whole line, with no declaration; the reader refuses it, as the 382505f reader already did. The upgrade does not rewrite anchors; DESIGN says so.
- **The upgrade cannot know a list's size** when 45ec9be ran with a different setting from the one the upgrade starts with; it refuses when a slot lies beyond the setting, and README says to start the upgrade with the old size.
- **A worker's first write reads the whole anchor**, a few seconds per million lines. A MACed position in the store would save it, at the price of more code to get right; not now.
- **The OIDF test plan in CI** stays with M3.

Stress run: all six suites, full mode with the 30-minute soak, from a fresh clone of `8684b1b`: 101 of 101 checks pass (`evidence/stress/2026-11-04-8684b1b/`). The run before it, against `fd87094`, failed two checks, both rightly: under a clock 400 days ahead the background tick, which `6064610` had made publish whatever the clock read, published every bit that clock called due (reverted in `085d8e5`), and the status fuzz target built a list by hand without a size or published bits, which cunho now refuses (`8684b1b` opens the list as an issuance does). In the passing run the soak ran 234,542 flows and 20,161 revocations with no error, verified the log 27 times under load and its 535,855 entries at the end. The load rates are lower than in the fifth round because the machine was busier; suite 1 run back to back against `382505f` and `8684b1b` gave the same rates.

Gates on the final code: ruff and ruff format clean, mypy clean on 74 files, `pytest` 576 passed, `pytest -m slow` 7 passed, `verify_evidence.py` OK. CI on `8684b1b` passed every job, its four mutation shards running all 1,535 mutants with no survivor.

Re-running the reproductions:
| Script | Result now |
|---|---|
| review 6 `p1_revoke_while_clock_ahead` | unchanged: the script passes a test clock with no host clock behind the watch (see "Not fixed"), so the bit stays hidden until the wrong clock's moment. The same script with a host clock behind the watch, as every deployment has: bit 0 at 1 and 30 minutes, 1 at 61 minutes after the revocation, measured on the host clock (was hidden for two days) |
| review 6 `p2_anchor_replayed_line` | the next offer is 500 and verify says `the anchor line at offset 1240 repeats or goes back (sequence 2 after 4)`; nothing is chained onto the copy (the script then stops, expecting offers to succeed) |
| review 6 `p2b_anchor_replayed_genesis` | offers 500, 500, 500 and after the background repair still 500, and verify is false with `repeats or goes back (sequence 0 after 6)` (was valid while every action failed); the revocation by slot is a 400, since list 1 does not exist |
| review 6 `p3_restart_ntp_prunes_log` | `steady at once: True`, maintenance `audit_entries_pruned: 0, audit_pruning_held: 1`, all 30 entries left, and verify valid after the correction (was every entry pruned and verify failing for good) |
| review 6 `p4_anchor_verify_false_valid` | A: after the copy, verify and `GET /admin/audit/verify` are false with `repeats or goes back (sequence 4 after 6)` (was valid); B is not reached, as the next offer of A is refused |
| review 6 `p5_erase_during_issuance` | erasure 204, issuance 400, log `['offer.created', 'subject.erased']` (was 200 with the person's data after `subject.erased`) |
| review 6 `p6_claimed_never_issued_is_live` | B with the reused key 400, B with a fresh key 200 (was refused, the claim spent), the vault erased, cancel 400 "no live offer" |
| review 6 `u1_upgrade` | `published bit of the same PID = 1; 1-bits in list = 83` after the upgrade (was 0 and 0), and still 1 an hour and a maintenance run later; the one more bit is a decoy that came due in the two hours between the phases |
| review 5 `t1`, `t2`, `t3`, `t4`, `t10`, `t12`, `race4_rerun`, `t9b` | as in the fifth round's table: both tears repaired and declared; the repair entry kept; request B refused with `offer_cancelled`; 6 of 6 verifications valid while pruning; erasure of `<ref>%0A` and of a reference never handed out refused; nothing kept past retention; 1x200 per single-use race and 60 of 60 verifications valid; 8 pollers 1,922 responses a second with metadata at 13 to 24 ms. In `t9b` each revocation the script makes before the server's first tick logs that the clock watch cannot vouch for the clock yet, and shows at once |
| review 5 `t5_list_size_change` | 200 after the restart with half the size, as before |
| review 5 `t7_event_loop_block` | metadata 0.01 s while the status GET waits, as before; that GET is now a 500, since the script opens list 1 by writing a row without a size into the store by hand, which is refused rather than served as zeros |
| review 5 `t8_restart_after_stop` | unchanged (a test clock with no host clock), and its maintenance runs now also report `audit_pruning_held` |
| review 5 `t9_status_rebuild_storm`, `t11_person_vs_offer`, `t13_hygiene` | as before: 1,201 polls with one rebuild; the latest reference covers its own offer; UTF-16 refused (both scripts stop where they did) |
| review 4 `s1` to `s12`, `race4`, `rerun3` | as before: every input refused cleanly; `s2` reports the declared stretch; `s3` 200 of 200 valid; `s4` flags every bit, revoked and decoy alike (400 of 400 and 627 of 627); `s5` the token refused for a revoked subject (the script stops there); `s10` the checkpoint gives up and maintenance answers; `s11` no `exp` in the log (the script stops there); `s12` the three rollover orders issue; `race4` 1x200 per single-use race, 60 of 60 verifications valid, 0 tracebacks |
| review 3 `r1`, `r3` to `r9`, `race`; `r2` given `create_anchor=True` | as before: `r2` (a) `the store diverges from the anchor at sequence 2`; `r6`, `r7` refused against the real tree; `r9` the redirected token row is ignored; `race` 1x200 per single-use race and the log valid |
| review 2 `q1` to `q14` | as before: `q2` wipe and truncation fail verification, now with `the store (head 2) is behind the anchor (sequence 7)`; `q8` verification fails for entries without a head pointer; `q12` against a real 4-worker server: 400 for a 200 MiB chunked body, RSS 63 to 65 MiB, no traceback; `q3`, `q6` and `q11` stop on purpose as before |

## Seventh review (cunho-m2-review-7.md): fixes

The review graded M2 7.5/10: no High, two Medium findings, both about time, and seven Low ones, with four of review 6's items partly fixed. The developers' pre-check (`cunho-precheck-7.md`) found C1, the same as the review's L3, and noted that a subject revocation under a clock far ahead missed credentials. The second reviewer's findings, read with the round, are CX-1 (High: a database writer could have maintenance prune entries whose time it moved back), CX-2 (Medium: certificate policies were not processed along the path), CX-3 (Low/Medium: a transient failure could lose an offer's configuration for good, the same defect as review 7's L5) and CX-4 (the same defect as review 7's M2, from a code review of `ac2ea49..db9b9a0`). One more item came in during the round: the registry claimed META.PREFERRED_STATUS_PERIODS was implemented, and nothing published or handled `preferred_client_status_period`.

Most findings of the last four rounds were about time, and pruning, the irreversible step, kept being attacked (N4-M8, N6-M3, CX-1, M2). So this round does not add one more special case. Every decision about time now reads one source, the clock watch's time, which is a base laid once per boot moved on by the host clock, and pruning removes only what verifies. What that gives up is written in DESIGN §4 (time). Tests are in `tests/engine/test_review7_clock.py` and `test_review7_fixes.py`, named with the finding id, and in `tests/slow/test_model.py`.

| Finding | Commit | Change | Test |
|---|---|---|---|
| M1 revocation moments go by the clock watch, status lists by the raw wall clock | `6f48874`, `1e13a04`, `d18fb18` | Publication (`StatusLists._publication`), the poll path and the background tick go by the clock watch's time, the same time revocation moments are laid on, so a clock that stays behind, stays ahead, or is put right after it was trusted moves neither. The time is the base moved on by the host clock, not the wall clock held within two minutes of it: with a range, the published moment of a list could go back by twice the tolerance when the clock stepped from ahead to behind, and the model test caught a bit shown before its moment. While the watch cannot vouch for the time (after a host restart, until it is trusted), a list brings forward only the bits laid to show at once, so nothing scheduled comes due by a clock nobody vouches for. The background tick's hold on publication (`085d8e5`) is gone: it guarded against the raw clock, which publication no longer reads. On one boot the watch never accepts a new time. When a host restart lays the base behind the time before it, because that time read ahead, the background publication lays every queued moment later than any a clock reading right lays (two maintenance intervals and the jitter ahead, decoys included) again within the jitter, as the review suggested; normally there is none, and finding none is one read of the far end of the queue. | test_m1_a_revocation_shows_within_its_bound_however_the_clock_reads (behind, ahead, corrected after it was trusted: the review's p2 and p2c), test_m1_a_poll_under_a_clock_far_ahead_publishes_nothing_early (p2b), test_m1_without_a_time_only_the_bits_laid_to_show_at_once_are_published, test_m1_a_revocation_laid_by_a_time_ahead_shows_once_a_new_base_puts_it_right, test_m1_a_schedule_a_right_clock_laid_is_left_as_it_is, test_decoys_are_scheduled_by_the_time, test_for_any_wall_clock_fault_the_host_clock_can_see (the review's invariant as a Hypothesis property); tests/slow/test_model.py (`wall_clock_steps`, `wall_clock_put_right`) |
| M2 forward moves under two intervals trusted without the host clock (and the second reviewer's CX-4, the same defect) | `6f48874`, `1e13a04` | Removed: the window of two maintenance intervals, the trusted reading moved on at every tick, the steady stretch kept apart from the base, `bounds` and `request_time`. The watch keeps one base per boot, a wall-clock reading it trusted with the host clock at that moment, and the time is that base moved on by the host clock. The base is laid on the first start of a store, and after a host restart at once when the kernel reports sync and the reading is not behind the latest time seen, otherwise once the reading has kept pace with the host clock for an interval. On the same boot the wall clock is only compared with the time, and a reading more than the tolerance off is logged every minute; nothing follows it, so a clock stepped a little at every tick, or once, moves nothing. `maintenance_interval` needs no cap: no window depends on it. | test_m2_a_clock_that_creeps_ahead_prunes_nothing (the review's p1: 400 ticks of 7,000 s), test_cx4_a_step_inside_the_old_window_is_not_trusted (the second reviewer's scenario), test_n4_m8_clock_watch_readings, test_n5_l5_a_step_is_not_followed, test_n5_l5_after_a_host_restart_a_reading_that_keeps_pace_is_trusted, test_a_worker_goes_by_the_time_from_its_start, test_a_clock_that_went_back_never_stalls_maintenance |
| CX-1 a database writer has maintenance prune entries whose time it moved back | `6f48874`, `7b85554` | `prune_before` checks, in the transaction that removes them, that each entry is well formed, MACed, and names the checkpoint or the entry before it as its `prev` (which the MAC binds, so the sequence needs no check of its own), and stops at the first one that does not, with an alert. An entry's age is its own time, under its MAC; removing entries from the front, or putting an older one back, breaks the chain and stops pruning there. | test_cx1_an_entry_dated_back_by_a_database_writer_is_not_pruned (the second reviewer's p1, after a restart too), test_cx1_pruning_follows_the_chain_from_the_checkpoint, test_an_entry_logged_without_a_time_does_not_hold_pruning_back, test_verify_measures_the_checkpoint_by_the_time, test_n3_l1_a_malformed_entry_stops_pruning_with_an_alert |
| CX-2 certificate policies checked certificate by certificate | `33c864f` | One allowed policy must hold along the whole path: the set the path is valid for starts as the deployment's, each intermediate narrows it to what it asserts unless it asserts anyPolicy where that is not inhibited, and the leaf must assert one of what is left. Without policy mappings, which stay refused, this is the valid policy tree of RFC 5280 §6.1; DESIGN §4 trust says so. | test_cx2_one_allowed_policy_must_hold_along_the_whole_path (six paths, the second reviewer's p3 among them), test_n3_h1_leaf_signer_profile |
| CX-3 and L5 an offer called live for a configuration it can no longer issue | `dbdaa7b`, `7b85554` | The vault is erased once every configuration is in `subject-done`, not once every one is claimed, so a claim given back after a failure can be issued again; revocation, cancellation and erasure still close the offer whatever the vault holds. | test_cx3_a_claim_given_back_after_the_other_configuration_issued_can_be_issued_again (the second reviewer's p2, deterministic), test_cx3_an_offer_whose_configurations_all_committed_is_not_live_while_its_data_is_still_there, test_n5_m2_a_revocation_between_a_claim_and_its_commit |
| L1 an append racing a write leaves the writer on a wrong position | `82e8bd2`, `7b85554` | After a write, the file's size is compared with the end the writer expects; when they differ, the write is reported as failed (the action stands, as for any anchor write after a commit) and the worker does not move where it reads on from, so its next write reads what landed, declares it and repairs it, as any other worker would. | test_l1_an_append_during_a_write_is_read_again_and_repaired (the review's p3) |
| L2 the newest-entry rule undone by one anonymous request | `6f48874` | Removed: `newest_time` and the cutoff that went by it. The time no longer follows a clock that jumped, so the rule protects nothing the time does not, and anyone could undo it. | test_l2_an_anonymous_request_does_not_open_the_log_to_pruning (the review's p5) |
| L3 and the pre-check's C1 the upgrade re-run silently | `5c459e6`, `7b85554` | The upgrade runs in an audit transaction and writes `store.upgraded` with it. Production upgrades a store without a version only with `store_upgrade` (`CUNHO_STORE_UPGRADE=true`), as it starts a new anchor only with `audit_anchor_init`. An offer from before the upgrade is live for the configurations the deployment issues, not all 31 it loads. | test_l3_a_store_without_its_version_row_is_upgraded_in_the_open (the review's p4), test_l3_production_upgrades_only_when_told_to, test_an_upgrade_that_cannot_be_logged_refuses_to_start, test_n6_m2_* |
| L4 engine-test gaps | `6f48874`, `1e13a04` | S32 (the DPoP replay cache living only the iat window), S27 (a host restart behind the last time trusted at once with NTP in sync) and S24 (a wider tolerance) are pinned and are hand-written mutants now (R7O1, R7C7, R7C2). S31 was equivalent, as the review said: the claim's `* 2` is gone. | test_l4_a_dpop_proof_dated_ahead_cannot_be_replayed, test_l4_a_restart_behind_and_a_step_hidden_in_a_stop, test_n4_m8_clock_watch_readings, test_a_new_boot_reading_off_by_exactly_the_tolerance_keeps_pace |
| L6 false DESIGN and README sentences | `f94e900` | Each sentence the review lists is rewritten to what the code does: the moment and the publications go by one time; what a wrong reading can and cannot prune; the newest-entry rule is gone; "the offer is never called live for something it can no longer issue" is true now (L5); the mutation sentence; "every configuration" in the upgrade is the issuable ones (L3). | DESIGN.md, README.md |
| L7 hygiene | `ea7f033` | The credential endpoint has its own rate-limit table. An operator named `admin` in `CUNHO_OPERATORS` is refused at startup. The upgrade test reads `45ec9be` with `git archive` into a temporary directory, writes nothing into `.git`, and skips, saying why, without the history; the mutation tool needs no worktree either. | test_l7_the_credential_endpoint_is_rate_limited, test_l7_an_operator_named_admin_is_refused, test_n6_m2_an_upgrade_from_45ec9be_publishes_every_bit_it_showed |
| The pre-check's note: a subject revocation under a clock far ahead missed credentials | `6f48874`, `1e13a04` | The issued records are read by the time; while the watch cannot vouch for it, every record still kept counts. | test_a_subject_revocation_under_a_clock_far_ahead_finds_every_credential, test_a_subject_revocation_without_a_time_counts_every_record_kept |
| registry: META.PREFERRED_STATUS_PERIODS | `fb64e01` | The rule was claimed by the configuration validator, which refuses a malformed period and communicates nothing, and the meta-test accepted it because a test carried the rule in its `obligation` marker: it never checked that the test ran the code claiming the rule, let alone what it asserted. Every `implements` function now reports its rules each time it runs, and an `obligation` test fails unless code claiming its rule ran during it, as a `covers` test fails unless its rule refused something. That check found four more claims of the same kind, each moved to the code and the test that do the work (STATUS.TSL.ENCODING, PID.ATTRS.OPTIONAL_SCHEMA, KA.ATTESTATION_PROOF_NONCE with KA.POP_ALL_KEYS, CRYPTO.ALG_ALLOWLIST_ACM). The rule is now claimed by the issuer metadata, which publishes each configuration's `preferred_key_storage_status_period`, and is marked partial: `preferred_client_status_period` for wallet instance attestations comes with wallet attestation in M3 (`binder/src/milestones.py`, registry regenerated). What the reach check cannot see is whether a test asserts the right thing once the code ran; that stays a matter of review. | test_preferred_status_periods_are_published, test_only_agreed_signature_algorithms_verify, test_n3_l6_rules_implemented_in_part_are_marked; the check itself in `tests/engine/conftest.py` |

Review 6's partly fixed items:
- **N6-M1** (revocation under a wrong clock): see M1. Moments and publications go by one time, and so do offers, tokens, nonces, proofs and the store's expiries (`1e13a04`): the model test, once the wall clock could stay off for many steps, showed that a subject closed while the clock read two days behind got a closing mark that expired early once the clock was put right, and its offer could be redeemed again.
- **N6-M3** (a wrong time source at boot prunes the log): see M2 and L2. Pruning waits an interval after a new base and while the wall clock reads behind the time, and removes only what verifies.
- **N6-L2** (the model test does not exercise the clock watch's holds): maintenance runs unforced, in both of its steps; a new step steps the wall clock and leaves it off for every kind of step that follows, polls and issuance included, until another puts it right; the wallets keep their own clock right. The maintenance step checks that pruning waits while the clock reads behind.
- **N6-L5** (false DESIGN sentences): see L6.

Earlier tests changed on purpose:
- The N4-M8, N5-L5 and N6-M3 tests of the watch's window, of a stop the host clock explains holding pruning, and of a new time held for an interval on the same boot are rewritten for the base: a step on the same boot is never followed, a stop on the same boot needs no wait, and a new boot waits until the clock keeps pace for an interval (`test_n4_m8_*`, `test_n5_l5_*`, `test_n6_m3_a_host_restart_holds_pruning_for_an_interval`). `test_n6_m3_pruning_goes_by_the_newest_entry_too` and `test_n6_m3_a_new_time_held_for_an_interval_still_waits_one_for_pruning` are removed with the rule and the behaviour they pinned.
- `test_n5_l8_bounds_only_from_a_recent_trusted_reading` becomes `test_n5_l8_the_time_holds_for_as_long_as_the_boot`: the base needs no recent reading. The deadlock test now pits a forced run against a request asking the time.
- `store.sweep()` takes the time to sweep by. `test_n3_l1_a_malformed_entry_stops_pruning_with_an_alert` expects the new alert.
- `test_n5_m2_a_revocation_between_a_claim_and_its_commit` expects the vault kept while B has not committed (L5).
- `test_n3_h1_leaf_signer_profile` checks the leaf's policy on a path whose intermediate carries it, since an intermediate without it is now refused first (CX-2).
- `test_n6_m2_a_store_from_382505f_keeps_its_sizes_and_bits` keeps its keyring across the restart, as the upgrade now logs; the 45ec9be phase revokes its second credential a second before the store is read, not a minute, which a jitter shorter than a minute failed once in about sixty runs.
- `test_jwt_proof_binds_only_the_signing_key`, `test_metadata_documents` and `test_configuration_validation` no longer claim obligations whose code they do not run (registry item).

Mutation run: this round's process runs the tool locally for the modules the round changed and leaves the full run to CI's four shards. The tree has 1,562 mutants in `--all --select` mode (307 removed refusals and raises, 1,062 altered conditions, 193 hand-written changes: 50 new this round, some of them earlier ones renamed for the new code, 8 rewritten for it, and 17 removed with the code they patched). The first local run over the round's code left twelve survivors. Four came from three checks that could never decide anything, which `7b85554` removes: pruning's sequence check beside `prev`, which the MAC binds (each of the two survived its own removal); the overtaken writer's reset of a position it had not moved yet; the watch's second check for a host clock. The other eight were behaviours no test pinned, each with a test in `7b85554`: liveness while the data is still there (S15c), a time that goes back without a host clock, a worker reading the clock as it is built, decoys scheduled by the time, an entry logged without a time measured against the time, verify's checkpoint age, a new boot's reading off by exactly the tolerance, and an upgrade that cannot be logged. `29efdfa`, which the reproductions led to, has its own test and mutant (R7S16). On the final code every mutant of the changed modules is killed: the hand-written ones 193 of 193, `service.py` 183 of 183, `audit.py` 180 of 180, `jose.py` 222 of 222, `settings.py` 160 of 160, `app.py` 41 of 41, `store.py` 20 of 20, `schema.py` 15 of 15, `status.py` 14 of 14 and `rules/__init__.py` 7 of 7, 1,035 in all, none listed as equivalent. Rules mode: 45 of 45 killed. The other 527 (`oauth.py`, `proofs.py`, `credentials.py`, `metadata.py`, `signer.py`, `keyring.py`) run in CI's shards.

Every new and changed concurrency test ran five times in a row on the final code, all passing: the CX-3 interleaving (B's claim given back after A committed), the N5-M2 interleavings, the erasure during signing (N6-L3), the anchor interleavings of `test_review5_anchor.py`, the tick and a request that must not deadlock, and the slow model and race tests across worker processes. The slow suite as a whole passed on the final code (7 tests, 9 minutes).

Not fixed, and why:
- **A clock wrong when the watch laid its base.** On one boot cunho does not follow a correction of the clock its base was laid from: a host restarted with a wrong clock while the kernel reported sync, or whose wrong clock kept pace with the host clock for an interval, keeps that time until the host restarts again or an operator runs a forced maintenance. An error says every minute that the wall clock reads off, and pruning waits while it reads behind. This is the price of a time that never moves further than the host clock: any rule that follows the wall clock on the same boot is the one M2 walked forward. NTP in sync before cunho starts, and an authenticated time source (NTS), are what close it; DESIGN and README say so.
- **A virtual machine paused.** A guest whose clocks stop while it is paused comes back with a time behind by the pause, reported the same way, until the host restarts or a forced run.
- **A host clock NTP does not steer** drifts from the wall clock by its own error; after enough days the difference passes two minutes and is reported. On Linux NTP steers CLOCK_BOOTTIME with the wall clock.
- **A clock with no host clock behind it.** A clock passed in for tests is the time as it reads, so a step of it is taken for time that passed: review 4's `s6`, which passes one, prunes again under its 400-day excursion, as in review 4, since the window that held such a jump went with the rest of the old watch. Every deployment has a host clock; production refuses one whose boot cannot be named (`9bc5498`), where the host clock could not be compared across restarts, and a development run there goes by the wall clock alone, with an error. The same script with a host clock behind the watch prunes nothing.
- **What a test asserts once its code ran.** The new reach check makes an `obligation` test run the code that claims the rule; it cannot tell whether the test's assertions are the right ones.
- **Earlier items still open:** the anchor signed off the database host (M4), the database restored from a backup (M4), a worker's first write reading the whole anchor, and the OIDF test plan in CI (M3), as in the sixth round.

Stress run: all six suites in quick mode, as this round's process asks (the full run with the 30-minute soak is left for the end of the milestone), from a fresh clone of `71043d2`: 96 of 96 checks pass (`evidence/stress/2026-11-05-71043d2/`). The quick run before it, against `9bc5498`, failed three checks of the chaos suite's clock jump, rightly for how that check was built: it jumped a test clock with no host clock behind the watch, which is the time as it reads. `71043d2` gives it a host clock, as every deployment has.

Gates on the final code: ruff and ruff format clean, mypy clean on 76 files, `pytest` 618 passed, `pytest -m slow` 7 passed, `verify_evidence.py` OK. CI on `71043d2` passed every job: check, slow, races, rules mode (45 of 45 killed) and the four mutation shards, which ran all 1,562 mutants and killed every one.

Re-running the reproductions (each from a copy of its directory; scripts that call an interface this round removed were adapted in the copy, as said):
| Script | Result now |
|---|---|
| review 7 `p1_clock_creep_prunes_log` (its `bounds()` line read through `now()`) | 383 ticks of 7,000 s each: the wall clock reads 31 days ahead, the time does not follow it, an error every tick says so, maintenance prunes 0 of 21 entries after an anonymous failed login, and verify is valid after the correction (was 20 of 21 pruned, silently, and verify failing) |
| review 7 `p2_revoke_clock_behind` | the bit shows after 18 minutes with the clock two days behind and 13 with it two days ahead (was 2,900 minutes, and one) |
| review 7 `p2b_poll_publishes_queue` | the queue keeps its 9 bits through the background tick and one anonymous GET under a clock 400 days ahead (was emptied by the GET), and the revoked bit is not shown early |
| review 7 `p2c_correction_after_trusted_wrong_clock` | the bit shows half an hour after a revocation made after the correction (was 72.6 hours): the time never followed the clock three days ahead |
| review 7 `p3_anchor_append_race` | the overtaken write is reported, the stray byte and the line behind it are declared and repaired by the next write, the same worker and a second one log on, and verify is valid with the damaged stretch named (was verify failing and every other worker refusing to log) |
| review 7 `p4_schema_row_deleted` | the upgrade is logged (`store.upgraded`) and the offer is live for the one configuration the deployment issues (was unlogged, for 31) |
| review 7 `p5_newest_entry_rule_anonymous` | maintenance after the anonymous request prunes 0 of 11 (was 10 of 10) |
| review 7 `p6_dpop_future_iat_replay` | unchanged: the replay 90 s later is refused |
| the second reviewer's `p1_prune_forged_times` | pruned 0, verify still reports "entry 1 was altered" (was 2 pruned and verify valid for good); the script stops at its own assertion |
| the second reviewer's `p2_concurrent_vault_loss` | B's retry is issued (200) and the offer is no longer live afterwards (was 400 "no longer available" and the offer live); the script stops at its own assertion |
| the second reviewer's `p3_policy_path` | the PID issuance is refused, 400 (was 200); the script stops at its own assertion |
| review 6 `p1_revoke_while_clock_ahead` | with its test clock, which has no host clock behind it, the time is the wall clock as it reads: the bit was laid two days ahead, and the background publication lays it again within the jitter, so it shows two hours after the correction (was hidden for two days) |
| review 6 `p2_anchor_replayed_line`, `p2b_anchor_replayed_genesis`, `p4_anchor_verify_false_valid` | as in the sixth round: every copy refused with "repeats or goes back", logging stops, verify false. p4 first stopped at the constructor, since the upgrade took the log on every start; `29efdfa` takes it only when an upgrade is due, and p4 runs as before |
| review 6 `p3_restart_ntp_prunes_log` (its `time_bounds` line replaced by `use_clock_watch`, which passes the time itself now) | steady at once, maintenance prunes 0 and holds pruning, all 30 entries kept, verify valid after the correction |
| review 6 `p5_erase_during_issuance`, `p6_claimed_never_issued_is_live`, `u1_upgrade` | as before: the issuance after the erasure 400; B with a fresh key 200, cancel "no live offer"; 82 bits before and after the upgrade, and an hour later |
| review 5 `t1`, `t2`, `t3`, `t4`, `t5`, `t10`, `t11`, `t12`, `race4_rerun`, `t7_event_loop_block`, `t9b_status_http` | as in the sixth round: both tears repaired and declared; B refused after the revocation; 6 of 6 verifications valid while pruning; 200 after the restart with half the size; erasure of a reference never handed out refused; nothing kept past retention (106 pruned); 1x200 per single-use race and 60 of 60 verifications valid; metadata at 0.01 s while the status GET waits (a 500, as the script opens a list by hand); 8 pollers about 2,600 responses a second with metadata at 11 to 18 ms |
| review 5 `t8_restart_after_stop` | the first maintenance after the restart runs, schedules decoys and is never refused as "clock not steady" |
| review 5 `t9_status_rebuild_storm`, `t13_hygiene` | as before: 1,201 polls with one rebuild, then the script stops at an attribute removed in the sixth round; UTF-16 refused |
| review 4 `s6_clock_excursion` | with its test clock the time is the wall clock as it reads, so the run 400 days ahead prunes the five entries, as in review 4: the window that held a test clock's jump was removed with the rest of the old watch. The same script with a host clock behind the watch, as every deployment has (`s6_host.py` in the copy): nothing pruned, verify valid after the correction, maintenance on time two hours later and decoys scheduled after a restart. See "Not fixed" |
| review 4 `s1`, `s2`, `s3`, `s5`, `s7` to `s12`, `race4`; `s4` with `store.sweep(clock())` | as before: every input refused cleanly; the torn write declared; 200 of 200 verifications valid; the token refused for a revoked subject; the checkpoint gives up and maintenance answers; no `exp` in the log; the three rollover orders issue; 1x200 per single-use race and 60 of 60 valid; `s4` flags every bit, revoked and decoy alike (400 of 400 and 701 of 701) |
| review 3 `r1`, `r3` to `r5`, `r8`, `r9`, `race`; `r2` with `create_anchor=True`; `r6`, `r7` given the tree | as before: `r2` (a) "the store diverges from the anchor at sequence 2"; `r6`, `r7` refused (400); `r9` the redirected token row ignored; `race` 1x200 per single-use race and the log valid |
| review 2 `q1` to `q14`; `q12` against a real 4-worker server on localhost | as before: `q2` wipe and truncation fail verification; `q8` prunes nothing of its unMACed entries, now stopping at the first, which does not verify; `q12` 400 for a 200 MiB chunked body, RSS 64 to 65 MiB, no traceback; `q3`, `q6` and `q11` stop on purpose as before |

## Second reviewer on the seventh review fixes (c8a5193): fixes

The second reviewer read the diff from db9b9a0 to c8a5193 and found two defects, both in the new time base. Its
three earlier repro scripts (CX-1 to CX-3) stop at their own assertions on c8a5193: the defects are gone.

- **CX-5, Medium: a base paired a wall-clock reading with a later host-clock reading.** `steady` read the wall
  clock, then waited for its lock and the store, and `_lay` read the host clock only then. A pause between the
  two (a busy store, a worker held up) left the base, and so the time, behind by the pause for the whole boot:
  180 s behind is past the 60 s DPoP window, and correctly timed wallets were refused. Fixed: `steady` reads
  both clocks together before it waits for anything, and the pair is what is laid; a forced run does the same.
  Test: `test_a_base_pairs_the_wall_and_host_clock_read_together` (360 s behind before the fix). Mutant R8C1.
- **CX-6, Medium: workers starting together on a new boot could each lay a base.** The lock was per process and
  the read, check and write of the base was not one store transaction, so two workers could both read the old
  boot's base and each lay their own; with the wall clock stepped between their readings, they disagreed on the
  time, and the overwritten one's time went back at its next tick. Fixed: `steady` and a forced run hold one
  store transaction (BEGIN IMMEDIATE in SQLite) from reading the base to laying it, so the second worker finds
  the base the first laid and goes by it. Test: `test_workers_starting_together_on_a_new_boot_lay_one_base`
  (100 s apart before the fix). Mutant R8C2.

### Second look at 53f0230

The second reviewer read the diff from db9b9a0 to 53f0230 again and found two more, both reproduced.

- **CX-7, High: production could not start on a new store.** The watch's first reading at startup laid its base
  in the store before the version check ran, so a new store no longer looked empty and production took it for
  one written before the version, refusing to start without `CUNHO_STORE_UPGRADE=true`. Tests with a clock passed
  in have no host clock and write no base, so none saw it. Fixed: the version comes first, then the watch's first
  reading. Test: `test_production_starts_on_a_new_store_with_a_host_clock` (the startup error before the fix).
- **CX-8, Medium: a damaged audit key stopped maintenance.** Pruning marked an entry whose key is not a number as
  broken, as it should, then raised `ValueError` turning the key into a number for its alert, which escaped
  maintenance before decoys and the checkpoint. Fixed: the alert names the key as stored. Test:
  `test_pruning_reports_an_entry_whose_key_is_no_number` (ValueError before the fix).

### Third look at 4360429

Two more of the same kind as CX-8, both reproduced: a row damaged so that checking it raises stopped maintenance.

- **CX-9, Medium: a lone surrogate in an audit entry's data.** `_shaped` passed it, and its MAC raised
  `UnicodeEncodeError` in pruning, verify and the anchor check, so maintenance stopped before decoys and the
  checkpoint at every run. Fixed: one `_verifies` check for every stored entry, where an entry that cannot be put
  in canonical form does not verify and is reported as altered.
- **CX-10, Medium: an audit key of 5,000 digits.** It passed the "is a number" check of the CX-8 fix and then
  hit Python's limit on integer conversion. Fixed: the alert never parses a key; a sequence key of the stored
  width is shown as its number, any other key quoted and cut to 40 characters.
- **The class, closed in depth:** pruning's caller now catches any error, logs it with an alert and returns, so a
  damaged row no check foresaw stops pruning only, never the maintenance steps after it.
- Test: `test_a_damaged_audit_row_stops_pruning_only`, for both damages (the two errors above before the fix).

### Fourth look at 7831f50

- **CX-11, High: the clock base in the database was not authenticated.** Since round 7 every expiry goes by the
  base, and the base was a plain store row. Whoever can write the database alone (the threat the audit MACs and
  the vault's crypto-shredding are built for) moved its time back, kept its boot and host-clock fields, and an
  expired offer was exchanged again with a DPoP proof dated at the moved time. Before round 7 those expiries went
  by the wall clock, which the database cannot move, so round 7 opened this. Reproduced: the time went 1,200 s
  back. Fixed: the base and the latest time seen carry a MAC from the keyring (purposes `clock-base` and
  `clock-seen`); a row that does not verify is taken for none, with an alert, so the watch lays a new base as
  after a host restart, and until then goes by the wall clock. A watch with a host clock refuses to be built
  without the keyring. A store from before this change carries an untagged base, which the first reading takes
  for none, once. Test: `test_a_clock_base_written_into_the_database_does_not_bring_an_offer_back`. Mutants
  R8C3 and R8C4.
- **CX-12, found by the mutation run on the CX-11 fix (mutant R8C4 survived).** The MAC on the latest time seen
  changed nothing: a row that did not verify was dropped, and the restart check then fell back to the base's own
  time, which is what a deleted row gave too. So a database writer could still take the comparison back to the
  base, hours ago, and a synchronised clock set back since was trusted at once. Fixed: after a host restart the
  quick way needs a base and a latest time seen that both verify; without either, the watch waits an interval.
  Laying a base also writes its time as the latest seen, so a store is never without one. What is left: a
  writer who kept an older seen row can put it back, which moves the comparison back to that older reading,
  never behind the base. Tests: `test_a_latest_time_seen_taken_back_does_not_bring_a_set_back_clock_in`
  (written and deleted, both fail on the CX-11 code), `test_a_watch_with_a_host_clock_needs_a_keyring`.

### Fifth and sixth looks at be4df81

The fifth look found nothing. The sixth found one Medium:

- **CX-13, Medium: a forced correction in one worker left the others on the old time.** Each worker kept the
  base in memory and read the store again only at its next tick, about a minute later. When an operator
  corrected a base laid from a clock that read ahead with a forced run (`maintenance(force=True)`), the other
  workers kept stamping and reading expiries by the old time until then. Reproduced with two SQLite connections
  and a one-day correction: a nonce of 300 seconds the corrected worker had just created was taken for expired by
  the other, and `take()` deleted it. Fixed: the watch reads the base row at every reading of the time, through
  a store read that does not go by the clock (`peek`), inside the store transaction when there is one, and
  checks its MAC again only when the row changed. The forced run is a write transaction too, so it falls wholly
  before or wholly after every other one. Test: `test_a_forced_correction_in_one_worker_is_the_time_of_every_worker`.
  Mutants R8C5 (a worker goes by the base it read last) and R8C6 (a worker keeps the first base it read); R7C10,
  for the read at a worker's start, went with that read.

### Seventh look at 9970433

Both findings came from the CX-13 fix, which made reading the time a store read:

- **CX-14, High: time reads on the event loop became store calls.** The status route answered a cached token
  on the event loop, and its publication goes by the time; a refused admin request was counted there by the
  time too. Both now reached `peek` and the store's lock, so a store transaction of another thread, which can
  wait 30 seconds for SQLite's lock, stalled every request of the worker. Reproduced: a store lock held 400 ms
  stalled a cached status lookup 400 ms. Fixed: the status route, cached token included, and the count of a
  refused admin request run in the thread pool. Test: `test_no_request_reads_the_store_on_the_event_loop`,
  which watches every store call and fails on one made with an event loop running; it drives the status
  route twice, a refused admin request and the metadata. Mutants R8A1, R8A2 and AP6.
- **CX-15, Medium: a sweep went on with a cutoff from before a correction.** Maintenance read the time and
  then swept in batches of 1,000 rows by it. A forced run in another worker that corrected a base laid ahead
  could come in between, and the sweep deleted rows the corrected worker had just stamped: reproduced with two
  SQLite connections, a DPoP replay marker of 300 seconds was deleted while live. Fixed: both stores read the
  time again inside each sweep transaction and delete by the earlier of it and the cutoff given. Test:
  `test_a_sweep_deletes_nothing_stamped_after_a_correction_it_did_not_see`, for both stores. Mutants R8S1
  and R8S2.

One run of the mutation tool's baseline (five copies of the suite at once, on the CX-13 code) timed out while
other heavy jobs ran on the machine; six copies at once then passed in under three minutes, and the same
mutation run passed its baseline when run again.

### Eighth look at d945a98

- **CX-16, Medium: pruning went on with a cutoff from before a correction.** Pruning is the same pattern as
  CX-15, and cannot be undone. Maintenance read the time and whether the watch had settled, then pruned in
  batches by them. A forced run in another worker that corrected a base laid ahead could come in between:
  with 30 days of retention and a 40-day correction, an entry logged by the corrected time was pruned at once,
  and verification failed. Fixed: every pruning batch reads the time again inside its transaction, goes by the
  earlier of it and the time pruning started with, moves its cutoff back as far, and asks the watch again
  whether it has settled, so pruning stops in every worker for an interval after a forced run in any of them.
  A forced run's own pruning goes on, as before. Tests: `test_pruning_goes_by_a_correction_made_while_it_runs`
  and `test_pruning_stops_when_another_worker_lays_the_base_again`, both failing on the CX-15 code. Mutants
  R8P1, R8P2 and R8P3.

### Ninth and tenth looks at bcd7b88

Both found nothing: two clean reviews in a row.

One test failed once in the gates that followed, under the mutation tool's baseline for `audit.py`:
`test_n_m2_decoys_arrive_one_at_a_time_at_random_moments`. It polls a status list every minute for six hours
and checks how the decoys spread, and the decoys come from the CSPRNG, so every run drew a new sample. It
passed 150 runs in a row; a sweep of 64 seeded draws found one that fails, seed 32, where a revocation and three
decoys fell into one publication and the burst check (at most 3 new bits a minute) saw 4. That is a fair
coincidence of independent moments, not the hourly burst the test was written against, which added dozens at
the maintenance tick. The test now draws from a seeded generator in place of the CSPRNG, so it checks the
same properties on the same sample every run; cunho itself still draws from the CSPRNG.

### Eleventh look at d420f29

- **CX-17, Medium: an earlier clock base, with its MAC, put back after a forced run.** CX-11 put the base
  under a MAC, and CX-12 already named what was left: a writer who kept an older row can put it back. After an
  operator corrects a base laid from a clock running behind with a forced run on the same boot, the earlier
  base still verifies. The second reviewer put it back by replacing only that row: an expired pre-authorized
  code went from 400 to 200, and verify still passed. The database cannot stop this, since the writer is the
  database; the one thing cunho keeps outside it is the audit anchor, append-only. Fixed: a forced run lays
  its base and logs `clock.trusted` in one audit transaction, and that entry's anchor line names the base:
  boot, host-clock reading and time. The line is written also when the next transaction writes it late, after
  a crash. Every worker keeps the newest base it knows of on the boot, from the bases it went by and from the
  anchor, which it reads when it starts and at every tick (before the store, in the lock order), and refuses
  a base laid before it, at an earlier host-clock reading (two bases of one boot are never laid at the same
  one: the host clock counts in nanoseconds, and time passes between); such a base is
  taken for none, as one that does not verify, so the wall clock, which the operator just put right, is the
  time until the watch lays a new base. The check runs on every reading, also of a row read before: a worker
  that never saw the corrected base would otherwise go by its cached copy. `steady` and `trust` now take the
  store before the watch's lock, so a forced run can lay its base inside the audit transaction. Tests:
  `test_a_clock_base_put_back_after_a_forced_correction_is_not_gone_by` (the reviewer's case, and a worker
  started after it), `test_a_worker_that_never_saw_the_corrected_base_refuses_the_earlier_one`, `test_the_anchor_names_a_forced_base_also_when_its_line_was_written_late`. Mutants
  R8R1 to R8R7 and R8R10. Two older tests count one more entry, the forced run's own.

A second test failed once under load in the mutation tool's baseline, while the second reviewer ran the suite
too: `test_m1_a_poll_under_a_clock_far_ahead_publishes_nothing_early`. Load was not the cause. A sweep of 200
seeded draws found two that fail: a revocation shows after a random delay of up to an hour, and the test lets
65 seconds of host time pass, so about one draw in 60 made the revocation come due in them, rightly, while the
test said it must not. Every test that runs through `_running` now draws from a seeded generator, as the decoy
test does (`Seeded` in the test helpers); cunho itself still draws from the CSPRNG.

### Twelfth look at a3c04b7

- **CX-18, Medium: a worker that had not ticked went by a base put back.** The floor from the anchor was read
  when a worker started and at every tick. A worker that read the base before another forced a new one, and
  had not ticked since, still went by the earlier base put back, for up to a minute. Fixed: the floor is read
  from the anchor at every reading of the time. That read takes no lock: the anchor has a reader of its own for
  it, with its own place in the file, apart from the writer's, which reads only up to the size it saw and
  starts again when the file got shorter. Lines are only ever appended, so it sees each one whole or not yet,
  and it can run from inside a store transaction without breaking the lock order. A file it cannot read keeps
  the newest base it found before, with an alert. The writer's own tracking of the newest base, added for
  CX-17, is gone with it. Test: `test_a_worker_that_never_saw_the_corrected_base_refuses_the_earlier_one`
  now refuses the copy at once, without a tick. Mutant R8R2.
- **CX-19, Medium: a forced base on a line that lost its newline did not count.** A torn write that loses
  only the final newline leaves a line the reader accepts and the next write closes, but its base was not
  taken, before the repair or after it. Fixed: the reader takes the base from such a line too. Test:
  `test_a_forced_base_on_an_anchor_line_that_lost_its_newline_still_counts`, which checks a worker reading
  the file before the repair and one after it. Mutant R8R6.

### Thirteenth look at c30f8c6

- **CX-20, Medium: a failed forced run left the floor raised.** A forced run lays its base and logs its entry
  in one audit transaction. When the entry could not be logged, the store went back to the base before it,
  but the worker had already raised its floor to the base laid inside, refused the base the store went back
  to as one laid before, and went by the wall clock while every other worker went by the base. Fixed: the
  forced run runs inside `ClockWatch.undone_on_error`, which puts the watch's memory back (the base it read
  last, the floor, the reading waiting on a new boot, whether the clock read behind) when the transaction
  fails. Test: `test_a_failed_forced_run_leaves_the_watch_as_the_store`. Mutants R8U1 and R8U2.
- **CX-21, Medium: status publication laid moments again by a time read before.** `publish` read the time,
  then laid again every queued moment later than a clock that reads right could lay. A forced run in another
  worker that moved the time forward in between made a revocation, rightly laid within the jitter of the new
  time, look too late; it was laid again by the old time, a day back, and showed at once, its jitter lost.
  Fixed: the time is read inside each transaction that lays moments again, as sweeping and pruning do (CX-15,
  CX-16); while the watch cannot vouch for the time, nothing is laid again. Test:
  `test_a_correction_forward_while_publishing_does_not_bring_a_revocation_forward`, which makes the other
  worker correct and revoke as the publishing worker opens that transaction. Mutant R8T1 reads the time just
  before it.

### Fourteenth look at 5cefb4c

- **CX-22, Medium: a malformed anchor line stopped the time.** Since CX-18 every reading of the time reads the
  anchor. A line appended to it with a lone surrogate raised `UnicodeEncodeError` while its tag was computed,
  and one nested deep enough raised `RecursionError`; neither was caught, so `/nonce`, `/status` (cached
  answers too) and a worker's start failed with the anchor. Fixed: whatever cannot be parsed or tagged is no
  line, for the writer too, and the clock reader catches anything else and keeps the newest base it found,
  with an alert. Test: `test_a_malformed_anchor_line_does_not_stop_the_time`, for both lines. Mutants R8R11
  and R8R12.
- **CX-23, Medium: bits came due by a cutoff read before their transaction.** `publish` read the publication's
  cutoff, then brought forward every bit due by it. A forced run in another worker that moved the time back
  in between, and a revocation queued by the corrected time, made that bit show at once, about 930 seconds
  early in the reviewer's case, its jitter lost. Fixed: the transaction that brings bits forward reads the
  cutoff again and takes the earlier one; the status token goes through the same code. Test:
  `test_a_correction_back_while_publishing_does_not_show_a_bit_early`. Mutant R8T2.

The two CX-22 mutants (R8R11, R8R12) each survived at first, since each protection covered for the other: a
parser that catches more makes the reader's catch-all unreachable, and the reverse. The malformed-line test now
also logs and verifies afterwards, which the writer cannot do when the parser lets `RecursionError` through,
and `test_a_clock_reader_that_fails_keeps_the_newest_base_it_found` makes the reader fail in a way the parser
does not cover.

### Fifteenth look at d58a157

- **CX-24, Medium: a SQLite row's expiry was stamped before its write lock.** `SqliteStore.put` worked out the
  expiry, then waited for the write lock to insert. A forced run another worker committed meanwhile left a
  300-second nonce good for a day more after a correction back, or expired at once after one forward. Fixed:
  a row that expires is written in a transaction of its own, with its expiry stamped inside it (`add`,
  `incr` and `take` already were). Test: `test_an_expiry_is_stamped_by_the_time_in_its_write`, both ways.
  Mutant R8S3.
- **CX-25, Medium: decoys were scheduled by a time read before their transaction.** `churn` read the time, then
  opened the transaction that lays decoys. A forced run three days forward in between laid them three days in
  the past, so the next publication showed them together. Fixed: the time is read inside that transaction.
  Test: `test_decoys_are_scheduled_by_the_time_in_their_transaction`. Mutant R8T3.

The reads of the time moved inside the transaction they decide, so far: the store's own expiries (CX-13,
CX-24), sweeping (CX-15), pruning (CX-16), laying status moments again (CX-21), bringing bits forward (CX-23)
and scheduling decoys (CX-25).

### Sixteenth look at f47698c

- **CX-26, Medium: a claim after its token expired.** The marker that says a configuration was claimed under a
  token lives as long as the token. A request that began a second before the token expired, with another
  configuration of the offer still to issue, reached its claim a second after: the marker made when the token
  was new had expired with it, and the same configuration was issued again. Fixed: the claim checks again,
  inside its transaction, that the token has not expired, by the expiry the token row carries under its MAC
  (now part of `Grant`), so every marker outlives the token it guards. Test:
  `test_a_claim_after_its_token_expired_is_refused`. Mutant R8V1.
- **CX-27, Medium: a clock number too large for a float stopped the time.** A clock row with `time` set to
  10**400 passed the shape checks and raised `OverflowError` before its MAC was checked, and since every
  reading of the time reads that row, every request that goes by the time failed. Fixed: such a number makes
  the row one that does not verify, in the base and in the latest time seen. Test:
  `test_a_clock_number_no_float_can_hold_is_a_row_that_does_not_verify`. Mutant R8V2.

### Seventeenth look at 12f3ff8

- **CX-28, Medium: a claim's marker lived for the lifetime configured now.** CX-26 made markers live for the
  configured token lifetime from the claim. A token issued for 600 seconds outlives a restart that set the
  lifetime to 300, so its markers lived 300 seconds, and the same configuration was issued again after 301.
  Fixed: a marker lives until the token's own expiry, which the token row carries under its MAC, measured by
  the time read inside the claim's transaction. Test: `test_a_claim_lives_until_its_token_expires`. Mutant
  R8V3.

### CX-29: a sweep of every read of the time

Six of the second reviewer's findings (CX-15, CX-16, CX-21, CX-23, CX-24, CX-25) were one class, found one place
per review: a time read before the store transaction that writes a value derived from it. A forced run another
worker commits in the gap leaves that value by the base before, for as long as the value lives. With the
owner's approval we swept the class ourselves rather than wait for the reviewer to find each place.

Every read of the time in `src/cunho` was listed (`now()`, `time()`, `_time()`, `_clock()` and the store's
expiries) and each sorted by one question: is a value derived from it written to the store, or used as the
cutoff of something that cannot be undone, outside the transaction that writes it? A read that only decides
(is this token still good, is this proof fresh) is not the class: deciding a moment before a correction commits
is the same as a request that came a moment earlier. Three more were found and moved inside their transaction:

- the expiry under an access token's MAC, read before the transaction that stored the token;
- the time a c_nonce row keeps;
- the moment a revocation is laid to show at, read before the revocation's transaction (the CX-21 class, in
  `revoke` itself).

The rest were already inside their transaction (offer creation, issuance and its issued rows, revocation by
subject, audit entries, list opening, the vault, the DPoP replay cache, the claim markers), or only decide
(proof and DPoP checks, token and offer lookups), or never reach the store (the DPoP server nonce, which is
stateless, and a credential's own `nbf` and `exp`, which are what it was issued with; its issued row lives
until that same `exp`). Tests: `test_an_access_token_expiry_is_read_in_the_transaction_that_stores_it`,
`test_a_c_nonce_time_is_read_in_the_transaction_that_stores_it` and
`test_a_revocation_moment_is_read_in_its_transaction`, each of which checks that the time it stored was read
while a store transaction was open. Mutants R8W1 to R8W3.

### Eighteenth look at 062edac

- **CX-30, Medium: the watch went back after the store let go.** CX-20 put the watch's memory back when a
  forced run failed, from a wrapper around the audit transaction, so after the transaction had rolled back and
  released the store. A request in between read the base the store went back to while the floor still named
  the one undone, refused it, and went by the wall clock; with that clock ahead, `consume_c_nonce` deleted live
  nonces. A COMMIT that failed was not covered at all. Fixed: both stores take `on_rollback(undo)`, which runs
  inside the rollback of the open transaction, before its lock is released, whether the body or the COMMIT
  failed; the watch registers its own undo whenever it lays a base, in `trust` and in `steady` alike, and the
  wrapper is gone. Tests: `test_the_watch_is_put_back_before_the_store_lets_go` (it checks the time from inside
  the rollback, with the lock held) and `test_a_base_whose_commit_fails_leaves_the_watch_as_the_store`. Mutants
  R8U1 to R8U3.

### End of M2: two clean looks, and the checks after them

The second reviewer's nineteenth and twentieth looks, at `8a17f3c`, found nothing: two in a row.

The full stress run against a fresh clone of `8a17f3c`, all six suites with the 30-minute soak, passed every one
of its 101 checks (`evidence/stress/2026-11-05-8a17f3c/`).

CI's mutation shards at `8a17f3c` found five mutants no test killed, all in checks added today: the second at
which a token expires (`now < grant.expires` against `<=`), the shape of the base an anchor line names (three
fields, a boot that is a name), a forced run's entry whose data is not a mapping, and T2, which since CX-23
changed the check before the transaction, which decides nothing any more, instead of the cutoff inside it. No
code changed: `test_a_claim_after_its_token_expired_is_refused` now claims at the very second the token
expires, `test_the_clock_floor_takes_only_a_base_of_the_shape_cunho_writes` and
`test_only_a_clock_trusted_entry_with_its_fields_names_a_base` are new, and T2 changes the cutoff inside the
transaction.

### M2 accepted

At `14c7930`, the code of `8a17f3c` with the tests above:
- **The second reviewer:** the nineteenth, twentieth and twenty-first looks found nothing.
- **CI:** green in every job, its four mutation shards included.
- **The stress run:** 101 of 101 checks.
- **The clock and concurrency tests** (`test_review5_clock.py`, `test_review6_clock.py`, `test_review7_clock.py`, 88 tests): passed 20 times in a row.
- **The full local mutation run** (`tools/mutation/mutate.py --all`): killed 1,628 of 1,628 mutants. Eight of them were first killed by timeout while the machine was overloaded and its disk full, so each was run again on its own. Five failed a test. The other three hang for good, so a hang is what kills them:
  - removing the "got shorter" check in `Anchor._scan` leaves the reader looping on the same offset;
  - the two mutants of `moved[0].seq <= previous.seq` in `_verify` make it go back to the same checkpoint forever.
