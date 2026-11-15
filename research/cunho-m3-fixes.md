# cunho M3: fixes for the reviews

What the second reviewer found in the M3 pieces, and what changed. Tests live in tests/engine; each one fails on the
code the review read.

## The authorization code flow and wallet attestation, first look at d320743

| Finding | What changed | Test |
|---|---|---|
| P1: a credential outlived the wallet attestation's status period | The access token's `client_status.exp` reaches the grant, and a credential's validity ends before it as it ends before the key attestation's `key_storage_status.exp` (TS3 v1.5.2 §2.4.3). VALIDITY.PID_LE_STATUS_EXP is no longer marked partial. | test_a_credential_ends_before_the_wallet_attestations_status_period |
| P2: authorization_details in the token request were ignored | They are read (OpenID4VCI §6.1.1): the token covers the configurations they name, with credential identifiers, and a configuration the authorization does not cover is refused as invalid_authorization_details. | test_authorization_details_at_the_token_request_narrow_the_grant |
| P2: anyone who knew a used code could revoke its token | The "spent" row keeps the bindings of the first use, under a MAC, and a second use is checked against them first: only the same client, instance key, DPoP key, verifier and redirect URI trigger the revocation. | test_a_used_code_in_other_hands_does_not_revoke_the_token |
| P2: the token response did not say which scope was granted | When the request used `scope`, the response carries the scope granted: the known scopes it asked for, narrowed by authorization_details in the token request (RFC 6749 §5.1). | test_the_token_response_says_which_scope_was_granted |

## Second look at 1010e54

| Finding | What changed | Test |
|---|---|---|
| P1: the token request's own attestation did not cap validity | The token keeps the earlier of the two `client_status.exp` values: the attestation at PAR and the one that authenticates the token request. | test_the_token_requests_own_attestation_caps_validity_too |
| P2: a person link from a login expired before its credentials | The link lives for the login's own window (login, code and access token lifetimes) plus the credential validity, not an offer's. | test_a_person_link_lives_as_long_as_a_credential_from_the_login |
| P2: a code that PAR bound to no DPoP key could be replayed with any key to revoke its token | The spent row keeps the DPoP key the code was redeemed with, and a redemption racing the first is checked against the spent row too before it revokes. | test_a_replay_with_another_dpop_key_does_not_revoke_an_unbound_codes_token |

## Third look at bc7c2a0

| Finding | What changed | Test |
|---|---|---|
| P2: a closed mark could expire while a login's code was still to come | The mark lives as long as an offer or a login with its code, whichever is longer, and a token after it. | test_a_subject_cancelled_at_login_stays_closed_while_its_code_can_come |
| P2: narrowing a grant left the other configurations open | A token request that narrows the grant narrows what the subject can still yield, in the transaction that spends the code. | test_a_narrowed_grant_leaves_nothing_open_once_it_is_issued |
| P2: a redirect URI ending in `?` got a second `?` | The parameters join an existing query, empty or not, with one delimiter. | test_a_redirect_keeps_the_query_it_has_and_one_delimiter, test_a_redirect_uri_ending_in_its_query_delimiter_works |

## Fourth look at 9cbcfc8

| Finding | What changed | Test |
|---|---|---|
| P2: a code replayed while a credential request was under way did not stop it | A replay that proves the first use's bindings now deletes the token and closes the login's subject, with its data erased and an `offer.cancelled` entry, in one logged transaction; the issuance transaction checks the closed mark, so a request already past the token check hands nothing out. | test_a_code_replayed_during_issuance_stops_that_issuance |
| P2: the PoP's nbf was not checked | A PoP whose nbf is not a number, or lies more than the allowed skew ahead, is refused (draft-07 §5.2). | test_a_pop_before_its_nbf_is_refused |
| P2: a finished login could look live again | The marks of what was issued live as long as an offer's or a login's open row can. | test_a_finished_login_does_not_come_back_to_life |

The hand-written mutants that the code flow's changes to `service.py` had moved (S2, S13, S14, S15d, S17, S17b, X11, R7S13) were found not to match once: `--list` does not check that. They now name the new code, and E14 to E19 cover this round's fixes.

## Fifth look at 887dbe9

| Finding | What changed | Test |
|---|---|---|
| P1: the wallet that started a login could collect the code with login_state | A login report's answer gives the URL to send the browser back to, with a fresh completion secret that only the login service learns; `/authorize/continue` needs it, for a denied login too. | test_the_wallet_that_started_a_login_cannot_collect_its_code, test_a_denied_login_also_needs_its_completion_secret |
| P2: a key proof naming the client in iss was refused in the code flow | A code-flow token carries its attested client to the proof checks: iss may name that client_id (App. F.1), and anything else in iss is refused; the anonymous pre-authorized flow still refuses iss. | test_a_key_proof_may_name_the_attested_client_in_iss, test_the_pre_authorized_flow_still_refuses_iss |
| P2: the PoP's exp was not checked | A PoP whose exp is not a number or has passed is refused. | test_a_pop_past_its_exp_is_refused |

## Sixth look at 49a7fee

| Finding | What changed | Test |
|---|---|---|
| P2: an unsupported response_mode was accepted and answered as query | PAR refuses any response_mode but query, which is all the metadata advertises. | test_a_response_mode_other_than_query_is_refused |

## Seventh look at fc7e9f1

| Finding | What changed | Test |
|---|---|---|
| P2: a redirect URI whose last query value ends in `?` lost the code into that value | The parameters join without an "&" only when the query after the first "?" is empty or ends with "&". | test_a_redirect_keeps_the_query_it_has_and_one_delimiter |

Also from the mutation run of the round before: two hand-written mutants survived. A test now steps the wall clock two days ahead under a host clock and shows wallet attestations go by the clock watch's time (E16), and the code-replay test replays after the subject data was read, so only the closed mark can stop the issuance (E17).

## Eighth look at 23bc537

| Finding | What changed | Test |
|---|---|---|
| P2: a wallet attestation signed for another audience was accepted | An attestation with an aud claim must name this issuer, as the string or in an array of strings (RFC 7519 §4.1.3); one without aud is accepted as before. | test_an_attestation_signed_for_another_audience_is_refused, test_an_attestation_whose_aud_names_this_issuer_is_accepted |
| P2: a login URL or redirect URI ending in an empty "#" passed | Any "#" in them refuses the start, an empty fragment too. | test_code_flow_settings_refuse_what_is_unsafe |

## The full mutation run over the code flow

Every refusing statement, `raise` and guarded condition of the new code was switched off or altered, one at a
time, and every M3 rule the code refuses on was switched off in turn. The rule run killed 28 of 28. The site and
condition run left 34 survivors in `authorize.py`, `client_auth.py`, the code-flow settings and the login report;
after the changes below a second run killed every mutant there (159, 124, 46, 16, 28 and 9).

- **A test helper that let the wrong refusal pass.** The wallet attestation tests caught any IssuerError, so a
  case refused by an earlier check passed for the check it was about. `raised_by` now asserts the first refusal's
  rule and reason, as `refused_by` does over HTTP; every attestation case still passed under it.
- **Checks that could never decide anything were removed:** the shape check of a login_state (any string is looked
  up by its hash) and the token68 check of the attestation headers (the strict JWS parser refuses the same
  strings with the same words).
- **Tests added** for each boundary and type the run could move: state of 0 and of 2048 characters, 16
  authorization_details, a configuration id or alg that is not a string, a sub of 512 and 513 characters, a jti of
  15, 16, 256 and 257, the code-flow lifetimes at 1 and at their caps, settings given a boolean, a float or text,
  redirect allow-list entries and keys of the wrong type, a scheme-only redirect URI, a login URL without a host,
  a redirect allow-list that is not JSON, a persons file holding a list, a person handle out of shape, another
  wallet solution over the same instance key, authorization_details naming all the grant covers, and the races
  where a request_uri, a code or a login is taken by another request between the check and the take.

## Refresh tokens, first look at 4678743

| Finding | What changed | Test |
|---|---|---|
| P2: a code replayed after its access token expired no longer ended the refresh token | The spent-code record lives as long as the refresh token plus the last access token it can give, so a replay within that time still revokes both and closes the subject (RFC 6749 §4.1.2). | test_a_code_reused_after_its_access_token_expired_still_ends_the_refresh_token |

## Second look at 4ec8f55

| Finding | What changed | Test |
|---|---|---|
| P2: spent-code rows written before refresh tokens have no `refresh` field, so an upgraded store would fail on a replay | Nothing. No release has the code flow: `main` writes no `code-spent` rows, and the earlier rows only ever lived on this branch. M3 ships its store rows in one format. | none |

## The full mutation run over the refresh tokens

Two clean reviews in a row (the third and fourth looks, at 63a70b9), then the run. Every refusing statement and
guarded condition in `refresh`, `_refreshed`, the code exchange and `_offer_live` was switched off or altered:
14, 5, 19 and 4 mutants, all killed. OAUTH.REFRESH_BOUND and BATCH.REISSUE_SAME_WALLET_UNIT were switched off in
turn and both killed; BATCH.REISSUANCE is an obligation nothing refuses on, so switching it off changes nothing,
and its tests are the re-issuance ones below. The hand-written patches F1 to F19 break what no automatic change
reaches: the bindings, the vault hold, the closed mark, the spent-code record, the lifetimes, the identifiers and
the scope. Three survived, and a test was added for each; the re-run killed all 19.

- **The cap of a year itself.** Only values past the cap were tested; a refresh token of exactly a year (and of a
  second) is now accepted by a test.
- **The closed mark for the refresh token's whole life.** Closed subjects were tested right after the revocation,
  erasure or cancellation; each case now also tries a refresh ten seconds before the refresh token ends.
- **The data held for the last access token a refresh gives.** A token got ten seconds before the refresh token
  ends now gets its credential just before that token expires.

## The safe fetcher and revocation from the network, first look at bb2206c

| Finding | What changed | Test |
|---|---|---|
| P1: over HTTPS the deadline cut the plain socket, which the TLS socket had detached, so a dripping server held the request | The deadline cuts whichever socket is live; the TLS socket takes its place before the handshake, which then runs under the deadline too. | test_a_slow_server_over_tls_is_cut_off_when_the_budget_runs_out, test_a_handshake_that_never_comes_is_cut_off_when_the_budget_runs_out |
| P1: a delegated OCSP responder was trusted on its issuer's signature, its purpose and its dates alone | It is held to the path's profile as well: no unknown critical extension or name constraints, agreed key sizes and hashes, a key usage that allows signatures, and not a CA. | test_a_delegate_out_of_profile_is_refused |
| P2: the DNS lookup and the connection were outside the time budget | The lookup runs in a thread the request stops waiting for when the budget runs out, and the connection gets what is left. | test_a_dns_lookup_that_hangs_is_cut_off_when_the_budget_runs_out, test_the_time_spent_resolving_comes_out_of_the_budget |
| P2: a failed check left its key's lock in the registry, so failing certificates piled up | The lock leaves the registry when its last user leaves, returned or raised; a count of users keeps a waiting caller on the same lock. | test_a_failing_key_leaves_no_lock_behind, test_a_caller_waiting_on_a_key_shares_the_lock_of_the_one_holding_it, test_failed_ocsp_checks_leave_no_lock_behind |

## Second look at f666ed2

| Finding | What changed | Test |
|---|---|---|
| P1: an OCSP answer in hand was used again without its responder's checks, so it outlived a delegate that expired or was revoked | The answer keeps the delegate that signed it; each use checks the delegate's certificate is valid now and, without ocsp-nocheck, its status by the CRLs of now. An expired delegate sends the request to the responder again; a revoked one refuses. | test_an_answer_in_hand_is_dropped_once_its_responder_certificate_expires, test_an_answer_in_hand_is_refused_once_its_responder_is_revoked |
| P2: a fetched CRL was kept before its signature was checked, so a forged one with far-off dates stopped every later fetch | Only CRLs the certificate's issuer signed are kept; a fetch that brings none leaves the copy in hand. | test_a_forged_crl_with_far_off_dates_does_not_stop_the_next_fetch |

## Third look at 92e27c7

| Finding | What changed | Test |
|---|---|---|
| P1: an OCSP answer in hand was found by the issuer's key and the serial, so a CA sharing another's key under another name got its answer | Answers are kept by the whole CertID: the issuer's name, its key and the serial. | test_an_answer_about_one_issuer_is_not_used_for_another_that_shares_its_key |
| P2: CRLs were kept by URL alone, so a second issuer at the same URL was given the first one's lists | CRLs are kept by URL and issuer. | test_two_issuers_whose_crls_share_one_url_each_get_their_own |

## Fourth look at d244220

| Finding | What changed | Test |
|---|---|---|
| P1: a bundle stayed in hand while any of its CRLs was current, so an older clean CRL that lived longer kept it after the newer, revoking one expired, and the revoked certificate passed | The copy in hand stands in for a fetch only while its newest CRL, by number and then thisUpdate, is current. | test_a_bundle_is_fetched_again_once_its_newest_crl_expires |

## Fifth look at 403d370

| Finding | What changed | Test |
|---|---|---|
| P1: a refetch that failed after the newest CRL expired handed on the stale bundle, whose older clean CRL then vouched for a revoked certificate | A fetch that fails, or brings no CRL the issuer signed, gives nothing. The CRL check itself also treats a newer CRL from the issuer that has expired as leaving the status unknown, so the same bundle in the operator's file is refused too. | test_a_failed_fetch_after_the_newest_crl_expires_hands_on_nothing, test_an_expired_newer_crl_leaves_the_status_unknown, test_a_newer_crl_not_yet_current_leaves_the_current_one_in_charge |


## Sixth look at 411538b

| Finding | What changed | Test |
|---|---|---|
| P1: a failed refetch gave nothing, so an older clean CRL in the operator's file vouched for a certificate the expired fetched CRL had revoked | A failed refetch hands on the copy in hand as evidence, never as proof. The CRL check sees the expired newer CRL and leaves the status unknown unless something newer covers it, whichever source each CRL came from. | test_a_failed_fetch_keeps_the_newer_crl_as_evidence_against_an_older_one_in_the_operator_file, test_an_operator_file_newer_than_the_expired_fetched_crl_still_decides |

The evidence lives in worker memory. After a restart, or once the bounded cache drops the entry, only the
operator's file is left when the fetch fails, as in M2; an operator who keeps that file must keep it current.

## Seventh look at b5f6251

| Finding | What changed | Test |
|---|---|---|
| P1: a fetch that brought an older CRL, replayed over plain http, replaced a newer revoking one in hand, so the revoked certificate passed once the newer one expired | A CRL in hand newer than everything fetched is kept beside what came, so the CRL check still sees it expire and leaves the status unknown until a newer CRL arrives. | test_a_replayed_older_crl_does_not_wipe_out_the_newer_one_in_hand |

## Eighth look at 031bb86

| Finding | What changed | Test |
|---|---|---|
| P1: a fetch that brought an older clean CRL beside a newer one dated after now replaced the expired revoking CRL in hand, and the older one vouched for the revoked certificate until the newer one took effect | A CRL in hand is dropped only when a newer CRL that came is already in force. | test_a_crl_in_hand_stays_until_a_newer_one_is_in_force |

## Ninth look at d8b1ca2

| Finding | What changed | Test |
|---|---|---|
| P2: an endpoint serving the same CRL dated after now again and again made the copy in hand grow by one CRL per fetch, inside a cache bounded only in entries | What came and what is kept are merged with each CRL once, by its bytes, and at most the newest sixteen are kept. | test_a_crl_served_again_and_again_is_kept_once, test_the_crls_kept_for_one_entry_are_capped |


## Tenth look at ea94cf1

Four looks in a row found a way the CRLs in hand lost something the CRL check needed. The rule for keeping them
is now stated from what that check reads, not from the case at hand, and each earlier case keeps its test.

| Finding | What changed | Test |
|---|---|---|
| P1: the cap of sixteen cut the newest CRLs, so seventeen dated after now pushed out the expired revoking CRL, or the only current one | Nothing is cut. Past sixteen, what came and what was in hand are judged in full for the check at hand, and the copy in hand stays as it was. | test_crls_dated_after_now_do_not_push_out_the_evidence_or_the_coverage, test_the_crls_kept_for_one_entry_are_capped_and_more_are_judged_but_not_kept |
| P2: a newer clean CRL in force dropped every older CRL in hand, among them a current one whose revocation still stands | A CRL is dropped only when it has expired and a newer one is in force, which is when nothing the CRL check decides depends on it. | test_a_current_crl_that_revoked_stays_when_a_newer_clean_one_takes_over, test_an_expired_crl_goes_once_a_newer_one_is_in_force |

## Eleventh look at 71183d8

The sixth finding on the CRLs in hand, and the one the tenth fix left open: judging an overflow in full for one
check, then going back to the copy from before, forgets what the overflow showed. An overflow is no longer
judged at all.

| Finding | What changed | Test |
|---|---|---|
| P1: past sixteen CRLs the revoking one was judged once and not kept, so when the next fetch failed the clean copy from before vouched for the revoked certificate | More than sixteen CRLs the check can still use is not what a CA publishes. The source is refused from then on, a failed fetch included, until a fetch brings few enough with a CRL in force at least as new as every CRL seen meanwhile. | test_a_revocation_seen_when_the_crls_overflow_is_not_forgotten_when_the_next_fetch_fails, test_an_overflowed_source_recovers_only_with_a_crl_in_force_as_new_as_every_one_seen, test_more_crls_than_are_kept_refuse_the_source, test_crls_dated_after_now_cannot_push_out_the_evidence |

The overflow mark lives with the copy in hand, so a restart or the cache dropping the entry forgets it, as with
the evidence above.

## Twelfth look at 6e23767, and a simpler design for the CRLs in hand

The seventh finding on the CRLs in hand: recovering from an overflow by a CRL number alone dropped an older
revoking CRL that was still current. Seven findings on one mechanism said the mechanism was wrong, so it was
replaced rather than patched again.

What cunho remembers of a distribution point is now the CRLs of its last fetch that the issuer signed, and the
newest CRL it has seen in force there. The newest CRL in force decides (RFC 5280 §6.3.3): a complete CRL lists
every unexpired certificate its issuer revoked, and a revocation other than certificateHold never leaves it (RFC
5280 §5, §5.3.1), so an older CRL adds nothing a newer one in force does not say. When no CRL in force now, from
the fetch or the operator's file, is as new as the newest seen, the status is unknown. That one rule covers what
the earlier fixes covered one by one: an older list replayed over plain http, a fetch that fails after the newest
CRL expired, an older clean CRL in the operator's file, a CRL dated after now, and a fetch with more than sixteen
CRLs, which is refused while its newest CRL in force is still remembered. Nothing is merged, so nothing piles up.

M2's rule that a revocation in any current CRL stands still holds within what one check sees (one fetch and the
operator's file). Across fetches the newest complete CRL decides, as RFC 5280 says; a newer complete CRL in force
that no longer lists a certificate is taken at its word. Every test of the eleven earlier looks still passes.

| Finding | What changed | Test |
|---|---|---|
| P1: recovery from an overflow by CRL number alone dropped a still-current revoking CRL | The design above. After an overflow, older CRLs replayed are refused, and one in force as new as the newest seen decides as the newest complete CRL. | test_after_an_overflow_only_a_crl_in_force_as_new_as_the_newest_seen_decides, test_a_revocation_seen_when_the_crls_overflow_is_not_forgotten_when_the_next_fetch_fails, test_a_fetch_with_more_crls_than_are_kept_is_refused, test_a_crl_that_comes_into_force_while_in_hand_becomes_the_newest_seen, test_only_the_crls_the_issuer_signed_are_kept, test_the_crls_of_the_last_fetch_are_kept_and_not_fetched_again_while_they_decide |

## Thirteenth look at 6d94289

| Finding | What changed | Test |
|---|---|---|
| P1: a CRL counted as seen only if a check ran while it was in force, so a revoking CRL that took effect and expired between two checks was forgotten when an older one replayed replaced it | A CRL counts as seen once its thisUpdate has passed, in force or expired. What was in hand counts before a fetch replaces it, and what a check sees counts at the check. | test_a_crl_that_took_effect_and_expired_between_two_checks_still_counts_as_seen, test_a_newer_crl_seen_in_the_operator_file_counts_as_seen |

## Fourteenth look at 7397cd8

| Finding | What changed | Test |
|---|---|---|
| P1: a check refused before it remembered the newest CRL it saw, so an expired revoking CRL in the operator's file was forgotten when the file went back | The newest CRL seen is remembered before the check can refuse. | test_a_newer_crl_seen_by_a_refused_check_is_remembered |

## Fifteenth look at 1a0e726

| Finding | What changed | Test |
|---|---|---|
| P1: two checks at once could write the newest CRL seen out of order, so one that saw #2 rolled back the #5 another had remembered | Every write of what a distribution point gave goes through one lock and keeps the higher of the newest seen and what is written; a fetch replaces the CRLs and keeps the higher mark. | test_a_check_that_saw_less_cannot_roll_back_the_newest_seen |

## Sixteenth look at 9714401

| Finding | What changed | Test |
|---|---|---|
| P1: a check stored the higher mark but decided by its own, older view, so one that started before another check remembered #5 still accepted on #2 | Every check merges its view into what is stored, under the lock, and decides by the result. | test_a_check_decides_by_the_newest_seen_once_its_view_is_merged_in |


## The full mutation run over the fetcher and revocation

Two clean looks in a row (the seventeenth and eighteenth, at 1bab7d8), then the run. WIA.CHAIN_TO_WP_LIST and
KA.CHAIN_TO_WP_LIST were switched off in turn and both killed; TRUST.REVOCATION_FETCHED is an obligation nothing
refuses on, and its tests are the agreement with the reference OCSP checker and the fetched-CRL tests. Every
refusing statement and guarded condition in `fetch.py` (86), `revocation.py` (97) and the revocation parts of
`jose.py` (32) was switched off or altered, and the hand-written patches C1 to C33 were applied. The first run left
25 survivors; after the changes below a second run killed every mutant but the three listed as equivalent in
`tools/mutation/equivalent.py`, each with its reason.

- **Edges tested exactly:** a URL of 2048 characters and of 2049; an OCSP answer used again at thisUpdate less the
  skew and at nextUpdate; a delegate whose validity starts or ends exactly at the check; an answer, a failed
  connection and a failed exchange landing exactly on the deadline (a clock that gives set readings).
- **Inputs no test sent:** a server that declares a million bytes and sends ten, one whose length is not a
  number, one that closes without answering; a responder ID that names no certificate sent or two; a response
  signed with Ed25519, which has no hash; delegates without basic constraints or key usage; a resolver answer
  that is not an address; `validate_path` given the CRL file and another source at once.
- **Code that could not decide anything:** the password half of the user-info check (a password comes only with
  a user name) was removed; a resolver failure is now a FetchError where it happens, and the catch-all for
  malformed answers that hid it was narrowed.

## Wallet providers' status lists, first look at 8edaf8f

| Finding | What changed | Test |
|---|---|---|
| P1: a list in hand was used for up to an hour without judging its signer again, so a CRL that revoked the signer, or the signer's certificate or covering CRL running out, did not end it | The list keeps its signer's chain, and every use judges that path again by the anchors and CRLs of now. | test_a_list_in_hand_is_dropped_once_its_signer_is_revoked_or_runs_out |
| P2: an `alg` that is a list or an object raised a TypeError, a 500 instead of a refusal | `alg` must be a string before it is looked up. | test_a_list_cunho_cannot_trust_or_read_refuses |

## Second look at d17a89a

| Finding | What changed | Test |
|---|---|---|
| P2: the newest iat seen lived with the list in the bounded cache, so a list dropped from it, or a restart, forgot it and an older list replayed was accepted | The mark is kept in the store for 31 days, apart from the lists in hand, raised in one transaction and shared by every worker. | test_the_newest_list_seen_outlives_the_cache_and_a_restart |
| P2: a list was judged by the time read before the wait for the lock and the fetch, so one that ran out meanwhile was accepted | The list is checked by the time read after the fetch, and its exp and signer again by the time it is used. | test_a_list_is_judged_by_the_time_after_the_fetch |

## Third look at 990ac96

| Finding | What changed | Test |
|---|---|---|
| P2: a worker's list in hand did not look at the shared mark, so it went on accepting an entry another worker had seen revoked, for up to an hour | A list in hand stands in for a fetch only while no newer list has been seen at its URI; otherwise it is fetched again and the mark applies. | test_a_newer_list_another_worker_saw_ends_this_workers_list_in_hand |
| P2: the mark was kept 31 days while a list could live longer, so an older list could be replayed once the mark was gone | A list may live at most 30 days from its iat, and the mark is kept a day longer from when it was seen, so every older list has expired first. | test_a_list_may_live_thirty_days_and_no_longer |


## The full mutation run over the wallet providers' status lists

Two clean looks in a row (the fourth and fifth, at 8e19617), then the run. WIA.CLIENT_STATUS and
KA.STATUS_AT_ISSUANCE were switched off in turn and both killed. Every refusing statement and guarded condition in
`wallet_status.py` (86), in `ClientAuth.authenticate` (61), `ProofVerifier.key_attestation` (45) and the settings
checks (126) was switched off or altered, and the hand-written patches H1 to H12 were applied. Five survived in
`wallet_status.py`, and none was a missing test: each was one of two checks of the same thing. Whether a list's exp
has passed was asked when it was verified and again when it was used; it is now asked only when it is used, by the
time read then. An inflater that stopped at the cap was asked both whether its output passed the cap and whether
input was left over, which only happens when it did; the second question is gone. The re-run killed all 81.

## The list of wallet providers, first look at 2026e4f

| Finding | What changed | Test |
|---|---|---|
| P2: at the start the file's stamp was taken after the read, so a list replaced during the read stood under the new stamp and was never read again | The stamp is taken before the read; a file that changed during it is read again at the next use. | test_a_list_replaced_while_it_is_read_at_the_start_is_read_again |
| P2: six months were taken as 184 days, which lets a list issued on 1 January run to 4 July | The limit is six calendar months, on the same day, or the last day of a shorter month. | test_the_next_update_is_at_most_six_calendar_months_after_the_issue |

## Second look at 353f2d1

| Finding | What changed | Test |
|---|---|---|
| P2: the list file was read whole before its size was judged, so a huge file could exhaust memory at the start or a refresh | At most the cap and one byte are read; anything longer is refused. | test_a_huge_list_file_is_refused_without_being_read_whole |

## Third look at 9f10899

| Finding | What changed | Test |
|---|---|---|
| P2: a worker checked the shared highest sequence number only when it read the file, so with list 1 put back under its old stamp it went on giving the anchors list 2 had withdrawn | Every use compares the list in hand with the highest sequence number in the store; a superseded list gives no anchors, and the file is read again at the next use. | test_a_list_another_worker_superseded_gives_no_anchors_though_its_file_looks_unchanged |

## Fourth look at 6f72601

| Finding | What changed | Test |
|---|---|---|
| P2: a certificate of an unknown X.509 version made the library raise InvalidVersion, which was not caught; during a refresh it escaped after the stamp had changed, so the previous list's anchors stayed in use | Whatever the library raises while loading a certificate is a refusal, and whatever stops a read of the file, at the start or a refresh, leaves no list in hand. | test_a_certificate_of_an_unknown_version_is_refused_and_leaves_no_anchors_behind |

## Fifth look at efbb8b9

| Finding | What changed | Test |
|---|---|---|
| P2: a refresh that failed for a passing reason kept the new file's stamp, so the worker never read the unchanged file again and stayed without anchors until it changed or restarted | A read that failed is tried again a minute later, the file unchanged, and gives no anchors meanwhile. | test_a_read_that_failed_is_tried_again_a_minute_later |


## The full mutation run over the list of wallet providers

Two clean looks in a row (the sixth and seventh, at 5861eec), then the run over every refusing statement and
guarded condition of `lote.py` (141) and of `parse_jws` (28), and the hand-written patches B2 to B15. The three
rules are obligations nothing refuses on; their tests are the ones above. Fourteen survived. Eleven were edges and
shapes no test sent: a list of exactly the cap; the pinned signer at the first and last second of its validity,
when read and at a later use; a date with a one-digit day, which the date parser takes and §6.1.3 does not;
a language tag that is not a string; `x5c` as an object or an empty array, and `crit` as an object or an empty
array, the first of each a crash before; `b64` true, which is no reason to refuse; and the stored sequence number
gone. One clause of `parse_jws` could decide nothing (with nothing understood, no name passes anyway) and is gone.
The re-run killed all 141 and 26.

## Signed metadata, first look at eca5c43

| Finding | What changed | Test |
|---|---|---|
| P2: the signed document was kept for the minute whatever its lifetime, so a lifetime under a minute served it after its exp | The document in hand is used only within its minute and before its own exp. | test_a_signed_document_is_not_served_after_its_exp |
| P2: each form took the highest weight of every range that matched it, so `application/json;q=0, */*` still gave JSON | Each form takes the weight of the most specific range that matches it (RFC 9110 §12.5.1). | test_the_signed_form_is_served_only_when_the_client_prefers_it |


## The full mutation run over the signed metadata

Two clean looks in a row (the second and third, at 025862e), then the run over every refusing statement and guarded
condition of `signed_metadata.py` (15), the reuse policy check (51), `issuer_info` (48), its loader (12), the
signed document in hand (2), the access signer at the start (6) and the settings checks (146), and the hand-written
patches G1 to G9. Four survived, each a shape no test sent: a registrar dataset given as a non-empty array (a crash
before), `srvDescription` as a number (a crash before), `providesAttestations` as a non-empty object (accepted
before), and a check of the reuse methods written as a subset test, which a duplicate check hid; it now names each
method that is not one. The re-run killed all 49 and 48.

## Trust wired to the list, first look at 757050c

Clean. With the list configured, the anchors of each purpose come from its services and revocation from the network,
the operator's CRL file pooled in; without it, a development run, from the PEM files of M2. The patches written for
it, I1 to I9, left three standing: a swap of the issuance and revocation services' anchors in either direction, which
no test told apart because every test list named the same provider in both, and a list read by the wall clock. A
list naming different providers in each service, and a wall clock stepped past the list's next update, now kill them.

The slow model found one thing in cunho, in a test of its own making: the list file and the CRL file were told
changed by their time and size, so a file renamed over the old one within one tick of a coarse file system clock
(ext4 counts in jiffies), and of the same size, went unread. Both stamps now carry the inode too, and the CRL file's
stamp is taken before its first read, as the list's is (P11, P12, I10).

| Finding | What changed | Test |
|---|---|---|
| A list or CRL file renamed over the old one in the same clock tick, same size, was not read | The stamp is the inode, the time and the size. | test_a_list_renamed_over_the_old_one_is_read_though_its_time_and_size_are_the_same, test_a_crl_file_renamed_over_the_old_one_is_read_though_its_time_and_size_are_the_same |
| The CRL file's stamp was taken after its first read, so a file replaced during it stood under the new stamp | Taken before, as for the list. | test_a_crl_file_replaced_while_it_is_read_at_the_start_is_read_again |

The slow model now runs the code flow across its four workers (PAR with the wallet attestation, the login reported
through the operator API, the code exchange, refreshes and a refresh from another wallet instance) with trust from
the list, which the operator's job renews whenever time moves on, or withdraws, or rolls back to an older one. The
race suite sends the code flow's single-use values N times at once, and the fuzz suite the list parser and the code
flow's signed inputs; CI runs the fuzz suite as its own job.

## The probe for M3, first look at 133edc3

| Finding | What changed | Test |
|---|---|---|
| P2: A17 and A21 used the refresh token A16 had used; an issuer that rotates them would refuse it as spent, which the checks took for a binding | Each takes a login of its own, and a refusal counts only if the rightful wallet's refresh with the same token then works. A16 keeps a rotated token. | test_a_bypass_check_after_a_rotating_refresh_is_not_fooled_by_a_spent_token |
| P2: the code flow never answered a DPoP nonce challenge, so a server that asks for nonces could not be tested | A request answered use_dpop_nonce is sent again once, with the nonce and the attestation headers made again; the nonce is kept. | test_the_code_flow_answers_a_dpop_nonce_challenge |
| P2: A19 compared the identifiers of two answers that granted none, and passed | Only non-empty strings granted for the configuration asked for count. | test_identifiers_count_only_when_there_are_some |

## Second look at a0af1bc

| Finding | What changed | Test |
|---|---|---|
| P2: A18 sent the query token without a DPoP proof, so an issuer that reads query tokens could still refuse it for the missing proof | The request is valid in every other way (DPoP bound to the token, the server's nonce, the token's identifiers), and the refusal counts only if the same token then issues from the header. | test_a_query_token_check_fails_against_an_issuer_that_takes_query_tokens |
| P2: A13 took any answer but 200 as the token ended | The token must issue before the reuse, and only invalid_token after it shows it ended; anything else is an error, not a pass. | test_a_token_counts_as_ended_only_when_the_server_says_invalid_token |

## Third look at 67de1d4

| Finding | What changed | Test |
|---|---|---|
| P2: `--login-cmd` got a relative Location as it was, and an empty string when the endpoint served the login page itself | The command gets the redirect resolved against the endpoint, or the endpoint's own URL. | test_a_login_command_gets_a_url_it_can_open |
| P2: A20 failed an authorization_code offer without issuer_state, which is optional | Absent, the check skips; present, it must be a non-empty string that PAR accepts. | test_an_offer_without_issuer_state_is_skipped_not_failed |

## Fourth look at fb2db6e

| Finding | What changed | Test |
|---|---|---|
| P2: an authorization endpoint that already carries a query got a second `?` | Parameters join the endpoint's own query (authorize and A06). | test_an_endpoint_with_a_query_keeps_it |
| P2: A18's own request did not answer a DPoP nonce challenge, so a server that asks for one first was misjudged | The query-token request is sent again once with the server's nonce. | test_the_query_token_check_answers_a_dpop_nonce_challenge |

The mutation run over piece I left one survivor: `Trust.from_settings` refused a run with neither the list nor PEM
anchors, which `Settings` already refuses, so the check could never decide anything. It is an assertion now.

## Fifth look at bc21f09

| Finding | What changed | Test |
|---|---|---|
| P2: a code flow that was tried and broke (a 500 at PAR, a refused exchange) was a skip, so a broken flow left the scored results | A skip is only for what was not configured. The checks of the flow itself (A02, A03, A15) fail; a check that needed the flow, or whose control request failed, reports an error. | test_a_code_flow_that_breaks_is_reported_not_skipped |
| P2: the login command was handed a session the probe had started, without its cookies | The command opens the authorization request itself (`$EUDI_PROBE_AUTHORIZE_URL`); the probe sends nothing to the endpoint first. | test_a_login_command_opens_the_authorization_request_itself |

Found while checking those against a live cunho: A18 and W10 used the token A02 had already spent on the
configuration, which the in-process tests, one context per check, did not see. Each takes a login of its own, and a
test now runs every M3 check in one context, as the command line does
(test_the_m3_checks_pass_one_after_another_in_one_run).

## Sixth look at a7c5b05

| Finding | What changed | Test |
|---|---|---|
| P2: A04 took only a redirect as the first use going on to the login, so a server that serves its login form at the endpoint got an error | A login page served there (200), or a redirect anywhere but back to the client with an error, counts as going on. | test_a_login_page_served_by_the_endpoint_counts_as_going_on |

## Seventh look at ca13ef2

| Finding | What changed | Test |
|---|---|---|
| P2: the retry after a DPoP nonce challenge sent the same attestation proof of possession, which cunho had already taken before asking for the nonce: W08's first PAR broke, and a negative check could be refused for the replay instead of its own change | A check's deliberate headers are made again for each attempt, with a fresh proof and the same change; W08 replays exactly the proof its accepted request carried. | test_attestation_checks_hold_against_a_server_that_asks_for_nonces |
| P2: A13's control request spent the token's one credential, so the request after the code's reuse could not show the token still worked | The token is checked with a request refused for its proof alone, which spends nothing: invalid_token means ended, a request error means still taken. | test_the_token_check_of_the_code_reuse_spends_nothing |

## The TS 119 472-1 profile (piece L)

ETSI TS 119 472-1 V1.2.1, clauses 2 to 6, is binding through CIR 2024/2979 Annex II. Clause 5 is the SD-JWT VC
profile, read requirement by requirement against what cunho issues. Most of it held by construction: nbf and exp,
no audience, `_sd_alg`, a `cnf` with the public key only, the Token Status List reference (as the Annex adapts
§5.2.10.1). What did not: `vct#integrity` (EAA-5.2.1.2-03, a "shall"), now the SRI digest of the Type Metadata
document the operator supplies per type, which production requires; the `category` of a qualified or public-body
attestation (§5.2.2), now set by the provider profile, with a configuration claim of that name refused; and x5u with
x5t#S256 for those two profiles (QEAA-5.6.2-02, PuB-EAA-5.6.3-02), now required as for PID providers. Clause 6 is
mdoc, which comes in M4, so the rule is marked partial for it. With L, every rule of M3 has code and a test, and the
meta-test holds M3 to that as a finished milestone.

## Eighth look at 83ee243

| Finding | What changed | Test |
|---|---|---|
| P2: W02 to W07 passed when the fixture itself was not accepted, every PAR then failing with invalid_client | Each sends the wallet's own valid PAR first; if that is refused the check is an error. | test_attestation_checks_do_not_pass_when_the_fixture_itself_is_refused |
| P2: the login walker followed a 307 or 308 with a GET, dropping the submitted form | 307 and 308 send the same method and body again, as a browser does. | test_a_login_form_answered_with_307_is_sent_again_as_it_was |

The first look at piece L (d0b91b4, base 83ee243) was clean.

## Ninth look at 6cec3fa

| Finding | What changed | Test |
|---|---|---|
| P2: `--wia-signer` took a P-384 or P-521 key that the ES256 signer cannot use, so every code-flow check errored | Only a P-256 key is accepted, with a clear error, before anything else is read. | test_a_wallet_attestation_signer_must_be_p256 |

The second look at piece L (6cec3fa) was clean: two clean looks in a row.

## Tenth look at 51ee04d

| Finding | What changed | Test |
|---|---|---|
| P2: the probe's attestations named a status list on a `.invalid` host, so an issuer that checks attestation status refused every one | `--wia-status` and `--ka-status` give the entries the wallet provider publishes. | test_the_code_flow_runs_against_an_issuer_that_checks_attestation_status |

The mutation run over the Type Metadata loader left two survivors, shapes no test sent: a document of exactly the
cap, and a `vct` that is a number. Both are tested now.

## Eleventh look at 2f296d7

| Finding | What changed | Test |
|---|---|---|
| P2: W10's untrusted key attestation named the placeholder status entry, so against an issuer that checks status it could be refused for the status alone | It carries the configured entry, the same in every way but its CA, and a trusted one must be taken after it. | test_the_untrusted_key_attestation_check_keeps_the_status_entry |
| P2: a GET login form whose action had a query got a second `?` | The action's query is replaced by the fields, as a browser does. | test_a_get_form_replaces_the_query_of_its_action |

## Twelfth look at 07ec9cc

| Finding | What changed | Test |
|---|---|---|
| P2: W02's untrusted wallet provider named the placeholder status entry, so a status check could refuse it with chain trust broken | It carries the configured entry, the same in every way but its CA. | test_the_untrusted_attestation_checks_keep_the_status_entries |

The mutation run over the configuration loader left one survivor: no test loaded a qualified-provider configuration
without a category claim, so refusing every one went unnoticed. Tested now.

## Thirteenth look at b4aae8b

| Finding | What changed | Test |
|---|---|---|
| P2: the login-form reader sent an empty value for a select and sent unchecked checkboxes | Forms are read as a browser submits them: the selected option (the first when none is), checked boxes and radios only, textareas, no buttons or disabled controls. | test_a_login_form_is_read_as_a_browser_submits_it |

## Fourteenth look at 18242cb

| Finding | What changed | Test |
|---|---|---|
| P1: every configured login field went into every form along the login, so a password for the login page could reach a later consent form, or a GET URL and the probe's evidence | A field fills only a control the form has; a field named as a button chooses that button. | test_login_fields_only_fill_controls_the_form_has |

## Fifteenth look at d8f98ca

| Finding | What changed | Test |
|---|---|---|
| P2: `--token-client-id` went only into the token forms the probe built itself, not into those T02, T03 and T05 to T07 build | Every token form gets it, unless the form sets its own client_id. | test_the_token_client_id_goes_into_every_token_form |

## Sixteenth and seventeenth looks at 67019dd

The sixteenth was clean. The seventeenth found one more:

| Finding | What changed | Test |
|---|---|---|
| P2: an option without its end tag, which HTML allows, was never recorded, so such a select sent nothing | An option is closed when the next one starts or its select ends. | test_options_without_their_end_tags_are_read |

## Eighteenth and nineteenth looks at 8ff09e2

The eighteenth was clean. The nineteenth found one more:

| Finding | What changed | Test |
|---|---|---|
| P2: W02's untrusted provider asserted no certificate policy, so an issuer that requires one could refuse it for the policy alone | It asserts the trusted fixture's policies, so only the CA differs. | test_the_untrusted_wallet_provider_asserts_the_trusted_ones_policies |

The re-run of piece L's loaders killed every mutant: 13 of 13 in the Type Metadata loader, 22 of 22 in the
configuration loader.

## Twentieth look at a81c114

| Finding | What changed | Test |
|---|---|---|
| P2: the rewrite to the token's credential identifiers also rewrote C07, which names a configuration and an identifier on purpose | A request that already names an identifier is sent as it is. | test_a_request_naming_both_identifiers_is_sent_as_it_is |

## Twenty-first look at 8c52a04

| Finding | What changed | Test |
|---|---|---|
| P2: A05 presented the request_uri under a made-up client, which an issuer refuses for being unknown whether or not it binds the request to its client | A05 uses `--second-client`, shows that client is accepted on its own, then presents the first client's request_uri under it; without one it skips. | test_the_request_uri_binding_needs_a_second_client_the_issuer_allows |

## Twenty-second and twenty-third looks at eb5705a

Both clean: two clean looks in a row, which closes the probe for M3. The mutation tool mutates the engine
(src/cunho), not the probe; the probe's own counterpart is tests/engine/test_probe_m3.py, which shows each bypass
check failing against a cunho with the rule it tests switched off, and the review findings above, each fixed with a
test that fails on the code reviewed.

## The OIDF conformance suite, run locally (piece K)

tools/oidf/run.py runs the OpenID Foundation suite (its images and source pinned by digest and commit) against the
checkout, in docker on the build machine. The first full run of the HAIP plan passed most modules, every client
attestation and DPoP negative among them, and showed four places where cunho, not the harness, had to move:

| What the suite showed | What changed | Test |
|---|---|---|
| A token answered one credential request per configuration; the suite asks the same token again (the happy flow's second call, the DPoP negatives' good calls, the additional-requests module), as OpenID4VCI 1.0 §8.3 allows | A request repeated under the same token for the same configuration, with fresh proofs for the same keys, gets the credentials the first one got. No credential is made twice, so M-1 and ARF ISSU_35 hold: one batch per token, never two credentials on one key. The reply is kept sealed until the token expires, goes when the subject is closed, and an erasure counts it as data held. Other keys are still refused. | test_repeat_request.py |
| The refresh token was bound to the DPoP key; the suite refreshes with a new one | RFC 9449 §5: an authenticated client's refresh token is sender-constrained by that authentication. It stays bound to the attested client and instance key (draft-07 §10.3, ARF ISSU_65); the new access token is bound to the DPoP key shown at the refresh. Probe A21 now checks that binding and that the old key is refused. | test_a_refresh_with_a_new_dpop_key_gives_a_token_bound_to_that_key |
| A request_uri was spent at the first visit to the authorization endpoint | FAPI 2.0 SP §5.3.2.2 note 3: it is spent when a login it started completes, by a login or a cancel, and can be opened again until then, at most eight times. Of two logins from one request_uri, the first to complete wins. Probe A04 now checks the request_uri is refused after its login. | test_a_request_uri_is_spent_by_the_login_it_starts and three more |
| A token request without code_verifier was refused as invalid_request; the suite expects invalid_grant | Every code was issued against a code_challenge, so a request without the verifier cannot redeem it: invalid_grant (RFC 7636 §4.6). A malformed verifier stays invalid_request (RFC 6749 §5.2). | test_the_code_verifier_must_match |
| A DPoP jti of 15 characters was refused (cunho asked for 16) | RFC 9449 §4.2 sets no length; the replay cache refuses a jti seen before. The floor is now 8 characters, which refuses only a degenerate one. | test_dpop_claim_boundaries |
| The suite's pre-authorized wallet authenticates with a wallet attestation and names itself in the proof's iss; cunho ignored the attestation, kept the token anonymous and refused the iss | A pre-authorized token request that carries a wallet attestation is authenticated with every check the code flow makes, and the token is bound to the client: a proof may name it in iss (App. F.1) and its status period caps validity. Without one the flow stays anonymous; a broken one is refused and uses nothing up. | test_preauth_attested.py |
| TLS 1.2 offered ciphers outside BCP 195 | The conformance image serves only the ECDHE-ECDSA AES-GCM suites (RFC 9325 §4.2). A deployment's proxy sets its own; the README says which suites. | the suite's TLS modules |

One place stays as it was: the batch module signs proof i with attested_keys[i] of one shared key attestation.
OpenID4VCI 1.0 App. F allows any attested key to sign; TS3 §2.2.2.2 and CIR 2024/2979 Annex Ib TR_KA-6.1 require
attested_keys[0], and the Regulation is binding. The harness asks that module for the attestation proof type, one
key attestation for every key, which both allow.

What the plan reports beyond that is listed with its reason: the metadata modules warn about what the EUDI rules
add (`credential_reuse_policy`, `issuer_info`, the claims' `value_type`), and since the suite's schema closes
credential_metadata the warning names the standard members beside them too (tools/oidf/expected-failures.json); the
encrypted variants are skipped because cunho offers no credential encryption, which OpenID4VCI and HAIP leave
optional (tools/oidf/expected-skips.json). The pre-authorized flow has no HAIP plan in the suite, so it runs under the
suite's plain OpenID4VCI profile, which checks a status list token's signature only against an embedded jwk or the
authorization server's jwks; cunho signs those tokens with an x5c chain, which the HAIP plans check and pass, so that
one check is listed as expected for that plan alone. The modules that expect an error page at the authorization endpoint end as
REVIEW: run.py checks the page and stands in for the screenshot a person sends in a certification run.

## First look at af81164

| Finding | What changed | Test |
|---|---|---|
| P2: with SQLite an expired reply stays on disk until the sweep, and `items()` skips expired rows, so an erasure in between left it there, still readable under the keyring, and reported no data held | Replies are dropped and counted whatever their expiry. | test_an_erasure_drops_a_reply_the_sweep_has_not_reached_yet |

## Second and third looks at 0305b56

Both clean: two clean looks in a row, which closes piece K. Mutation killed every patch written for it: R1 to R9 (the
repeated request and its kept reply), U1 to U4 (the request_uri), K1 to K5 (the verifier, the DPoP jti, the attested
pre-authorized request), and S14, E13 and E18 after their text moved.
