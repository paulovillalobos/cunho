# cunho M4: fixes for the reviews

What the second reviewer found in the M4 pieces, and what changed. Tests live in tests/engine; each one fails on the
code the review read.

## CBOR and COSE for mdoc (piece A)

`src/cunho/cose.py` holds what mdoc is built from: the deterministic CBOR encoding of RFC 8949 §4.2.1, the tags mdoc
uses (24, 0 and 1004), COSE_Key, the x5chain and x5t header values of RFC 9360, and COSE_Sign1 signed through the
existing signers and verified with ES256, ES384 and ES512 only. Decoding is strict: one item and nothing after it, no
duplicate map keys, no indefinite lengths, a depth limit, and every tag kept as encoded, so a date reads back as the
text that was signed.

The tests check the RFC 9052 Appendix C.2.1 signature with its published key, build the signed bytes a second time
from RFC 9052 §4.4 with cbor2 and cryptography alone, check the key order against the example of RFC 8949 §4.2.1,
and read random values back through the encoder. The test PKI gains an IACA and a document signer with the
ISO/IEC 18013-5 Annex B purpose.

Found while building: a protected `alg` that was an array made verification raise TypeError instead of refusing,
and an `alg` of -7.0 read as ES256. Only an integer `alg` is looked up now
(test_a_changed_rfc_example_is_refused).

## First look at 8df9610

| Finding | What changed | Test |
|---|---|---|
| P2: tag 55799 (self-described CBOR) was dropped on decoding | Every tag cbor2 would turn into a Python object is kept as a tag: 55799, and also 52, 54 and 43000, which the same scan found. A test scans every tag up to 70000 and checks that decoding keeps it and re-encoding gives the same bytes. | test_decode_keeps_every_tag_cbor2_would_interpret |
| P2: a COSE_Key whose `crv` was an array raised TypeError, and a boolean or float `kty` or `crv` could pass as its integer | `kty` and `crv`, like a protected `alg`, must be integers that are not booleans before they are compared or looked up. | test_only_public_ec2_cose_keys_on_the_curve_load |

## Second look at 12fbfe1

| Finding | What changed | Test |
|---|---|---|
| P2: a tagged array or map used as a map key could not be encoded again after decoding (RuntimeError) | A map key keeps its contents hashable through tags as well as through arrays and maps. The property test now draws map keys that are arrays, maps and tags, nested. | test_a_tagged_container_can_be_a_map_key, test_encoding_is_deterministic_and_reads_back |

## Third look at 5499f13

| Finding | What changed | Test |
|---|---|---|
| P2: a protected header `{True: -7}` or `{1.0: -7}` read as having `alg`, since Python compares True and 1.0 equal to 1 | Every label of both headers and of a COSE_Key must be an integer that is not a boolean, or a text string (RFC 9052 §1.5), before anything is looked up. | test_a_changed_rfc_example_is_refused, test_only_public_ec2_cose_keys_on_the_curve_load |
| P2: a JWK whose `crv` was an array raised TypeError | The JWK must be an object, `crv` a string and `x` and `y` base64url before conversion; anything else is refused as CoseError. | test_only_public_ec_jwks_convert |

## Fourth look at 41a8d3b

Clean. Mutation found that MA3 changed nothing (`strftime` drops fractions anyway), so it now writes the fractions
it is named after.

## Mutation at 7f5a4e3

All 21 hand-written mutants were killed; 15 of the 139 site and condition mutants of cose.py survived. Each now has a
test, or a reason:

- A COSE_Sign1 as a tuple, a signature as a list of numbers, an unprotected header as a list, a protected header that
  is not a byte string, and `crit` in the unprotected header are refused with their own reason
  (test_a_changed_rfc_example_is_refused). The signature case verified before the type check was tested: a list of
  numbers slices and converts like bytes.
- A COSE_Key coordinate padded with a zero byte names the same point; only the curve's exact size is read
  (test_a_cose_key_coordinate_is_a_byte_string_of_the_curves_size). A COSE_Key that is not a map, a JWK `y` of the
  wrong size and non-bytes input to `decode` are refused (test_a_cose_key_is_a_map,
  test_a_jwk_coordinate_of_the_wrong_size_does_not_convert, test_decode_takes_bytes_only). An x5chain given as a
  tuple is refused (test_x5chain_and_x5t).
- The check for two map keys with one encoding was dropped as unreachable. That was wrong, and the sixth look
  showed why (below); it is back with a test.
- `set(protected) <= KNOWN_HEADERS` turned into a proper subset is equivalent: the protected labels equal the whole
  set only when they include `crit`, which is refused first (tools/mutation/equivalent.py).

## Sixth look at ef416d2

| Finding | What changed | Test |
|---|---|---|
| P2: two distinct map keys could share an encoding, `2**64` and `#6.2(h'010000000000000000')`, and the map came out with a duplicate key | The check for keys with one encoding, dropped after the mutation run as unreachable, is back. | test_two_keys_with_one_encoding_are_refused |

## Seventh and eighth looks at 0268abf

Both clean. Piece A is closed on two clean looks in a row.

Mutation at 0268abf: 138 of the 139 site and condition mutants of cose.py killed, the last one listed as equivalent
with its reason, and the 21 hand-written ones (MA1 to MA21) killed.

## mdoc issuance and the CWT status list (piece B)

`src/cunho/mdoc.py` issues an mso_mdoc configuration as OpenID4VCI 1.0 App. A.2 asks: the base64url of the CBOR
IssuerSigned structure, its MSO signed by a document signer of its own (`mdoc_signing_key`), whose certificate
startup checks for id-mdl-kp-mdlDS. The MSO carries the status reference in its `status` member (ETSI TS 119 472-1
EAA-6.2.10.1-01 to -03), and the status list is served at the same URI as a CWT on Accept
`application/statuslist+cwt` (draft-ietf-oauth-status-list-21 §5.2; CIR 2024/2979 Annex II EAA-6.2.10.1-07, -08:
exp, and x5chain in the protected header). Piece D of the plan is folded in here, so no mdoc is issued without its
status list. The EC reference mdoc files load as before; those that pass the checks are published when a document
signer is configured. The PID as mdoc is neither published nor issued until its rulebook check exists.

The tests read every credential back with cbor2 and cryptography alone: the signer chains to the IACA, the
COSE_Sign1 verifies over the tagged MSO, each item's digest is in the MSO, the device key is the proven key, a batch
shares no salt, digest id set or status entry, and the CWT list flips its bit on a revocation.

## First look at e209869

| Finding | What changed | Test |
|---|---|---|
| P2: an mdoc's validUntil could outlast the document, since only the SD-JWT `date_of_expiry` capped validity | For an mdoc configuration the `expiry_date` of each namespace caps the validity, to the end of that day (ETSI TS 119 472-1 EAA-6.2.7.2-02). | test_an_mdoc_does_not_outlive_its_document |
| P2: a portrait such as `data:image/jpeg;base64,A` passed the offer and failed at issuance with a 500 | The base64 of a portrait is decoded when the offer is checked, and one that does not decode is refused with the rulebook problem. | test_a_portrait_and_an_unsigned_integer_are_checked |

## Second look at 331dbb6

| Finding | What changed | Test |
|---|---|---|
| P2: a PID provider with a document signer and a batch size of 30 published the PID mdoc configurations, and then refused every offer for them | The PID as mdoc is set aside as a finding at startup, never published by default, and naming it in published_configurations is refused, until its PID Rulebook check exists. The refusal at the offer, which could no longer be reached, is gone. | test_the_pid_as_mdoc_is_not_published_before_its_rulebook_check |

Mutation at e209869: MB24 (a document signer without the mdoc purpose is taken) survived, since the test's signer had
no extended key usage at all and was refused before the purpose was looked at. A signer whose only purpose is TLS
server authentication is now refused too (test_a_document_signer_without_the_mdoc_purpose_does_not_start).

## Third look at a964c07

| Finding | What changed | Test |
|---|---|---|
| P2: an `expiry_date` the configuration gives no value_type (the IBAN one) took any value, and an unreadable one capped nothing | `expiry_date`, `issuance_date` and `issue_date` must be calendar dates whatever the configuration says of their type, as `date_of_expiry` and `date_of_issuance` are for SD-JWT VC. | test_mdoc_subject_data_is_checked_against_the_configuration |

## Fourth and fifth looks at 952e666

Both clean. Piece B is closed on two clean looks in a row.

Mutation at 6c15449, over every function piece B added or changed: the 28 hand-written mutants were killed, and 22
of the site and condition mutants survived. Each was an input shape or a boundary no test reached, and each now has a
test: a namespace given as a list, a string, unsigned integer or portrait of another type, text that is not valid
Unicode, an expiry date of today, an age of 0, an empty portrait (issued as empty bytes, as a person who opted out),
a doctype, binding list, algorithm list, claims list or claim path of the wrong type, an empty or non-object claim
entry next to the EC-internal ones, an mdoc configuration without algorithms, a document signer whose algorithm has
no COSE value, a document signer certificate hosted elsewhere, and production without mdoc_trust_anchors
(tests/engine/test_mdoc.py).

Mutation at 253bddd, over the same functions: every mutant killed (validate_mdoc_subject 73, _jpeg_data_url 10,
_check_mdoc 49, load 30, check_document_signer 7, and the mdoc settings checks). Piece B is closed.

## The PID as mdoc (piece C)

The operator sends one PID, in the SD-JWT VC names, and cunho issues it as mdoc too: each claim becomes its data
element of the PID Rulebook §3.1.2 table in eu.europa.ec.eudi.pid.1, with the dates as full-date whatever type the
configuration gives them, the portrait as JPEG bytes, nationality as an array and place_of_birth as a map. The offer
checks what only the mdoc asks for: text of at most 150 characters and valid Unicode, a data element in the
configuration for every claim sent, and the configuration's mandatory elements. `address.house_number` stays SD-JWT
VC only (research/arf-issuer-requirements.md, F3). An element a configuration lists in the PID namespace outside the
rulebook is neither published nor issued, with a warning (ARF PID_06); a domestic namespace sets the configuration
aside. A PID provider publishing both formats offers the PID in both (ARF PID_02), and production refuses one that
publishes only one; the production test fixtures now carry a document signer. PID.RULEBOOK.CONFORMANCE is no longer
partial.

## First look at f99b786

| Finding | What changed | Test |
|---|---|---|
| P1: with only the mdoc PID asked for, nothing checked a text element's type or the administrative dates: `family_name: 123` passed, and `date_of_expiry: "nonsense"` failed at issuance | The mdoc PID's check stands on its own: every text element is a non-empty string, date_of_issuance and date_of_expiry are calendar dates, the expiry is not before the issuance nor in the past. | test_the_mdoc_pid_is_checked_at_the_offer, test_an_mdoc_only_pid_with_valid_values_is_checked_alone |
| P2: a PID portrait whose base64 does not decode passed, and the mdoc failed at issuance | A non-empty picture must decode, as for any mdoc portrait. | test_the_mdoc_pid_is_checked_at_the_offer |

Mutation at f99b786: MC3, MC6 and MC9 survived. The mdoc PID's portrait in the tests was short enough to pass the
text limit either way, a missing date_of_expiry was matched by the SD-JWT VC check's words, and nothing called the
encoder with a claim the configuration does not list. The test portrait is now longer than 150 characters as a data
URL, the missing expiry must be refused by the mdoc check, and the encoder is called directly
(test_only_the_elements_the_configuration_lists_are_issued).

## Second and third looks at da462cb, fourth look at a0a1933

The second and third were clean; the fourth found one more.

| Finding | What changed | Test |
|---|---|---|
| P2: `picture: null` passed as the person's opt-out, and the mdoc carried it as empty bytes, also once the portrait is mandatory | A picture that is sent is either the empty string, the opt-out (ARF PID_03), or a JPEG data URL, in both formats. The check of validate_pid, which an earlier test took null through as if it were absent, changes for SD-JWT VC too. | test_the_mdoc_pid_is_checked_at_the_offer, test_pid_checks_accept_their_boundaries |

## Fifth and sixth looks at 307e54a

Both clean. Piece C is closed on two clean looks in a row.

Mutation at a0a1933: MC19 (the mdoc PID's administrative dates are not read) survived, since the offer test listed both
formats and the SD-JWT VC check refused the same date with the same words. The mdoc PID check is now tested on its
own (test_an_mdoc_only_pid_with_a_bad_value_is_refused_by_its_own_check).

## Attributes outside the Annex (piece C, from the law)

Checking the PID against the consolidated Annex of CIR 2024/2977 as replaced by 2026/1731 (EUR-Lex, 11 August 2026)
showed that `trust_anchor`, `attestation_legal_category` and `address.house_number`, which the PID Rulebook v1.7 still
lists, are not among its data identifiers; §4.1 and §4.2 put anything outside the Annex in a domestic namespace or
type, and its resident_street already includes the house number. cunho issued all three in the PID. It now refuses
them in either format, with the reason (the house number goes in `street_address`), and leaves them out of the
published metadata of the reference configurations with a warning. The earlier choice to keep `house_number` in
SD-JWT VC only (research F3) is superseded.

The mutation run at a0a1933 also left nine survivors: the mdoc PID's date order and past-expiry checks, with their
boundaries, were only reached with both formats offered; publishing a configuration that does not exist had no test;
and the both-formats rule had a clause that could not change its outcome, now removed, while an offer without a PID in
a deployment publishing both formats had no test. Each has a test now (test_mdoc_pid.py).

## Seventh and eighth looks at b6ded55

Both clean. Piece C is closed on two clean looks in a row.

Mutation at 7022c3c: MC3 and MC8 survived, since once the Annex fix took attestation_legal_category out of the PID no
claim lacked an element in the reference configuration; and dropping `expires` from the date order check survived,
since no test sent an issuance date without an expiry. Both are tested now
(test_a_claim_the_mdoc_configuration_has_no_element_for,
test_an_issuance_date_without_an_expiry_is_a_problem_not_an_error).

Mutation at 29c75c8: MC3, MC8 and every mutant of validate_pid_mdoc (42) killed. Piece C is closed.

## The status list's trust anchor in the MSO (piece B, from the law)

Reading CIR 2024/2979 Annex II for piece E showed a gap in piece B. EAA-6.2.10.1-06 and -13.1: the MSO's status_list
may name a `certificate`, the one whose key signed the top certificate of the list's x5chain, which the relying party
then takes as trust anchor for the list; without it, the list must be signed under the certificate that signed the
document signer, the IACA. cunho signs its lists with the status signer under the issuer root and named nothing, so a
relying party following the law could not authenticate an mdoc's status list. Every mdoc now names that certificate:
the root itself when the status chain ends self-signed, otherwise its issuer among the signing trust anchors (or the
status chain file), and cunho does not start with a document signer when there is none. The test verifies the list
from the MSO's certificate down to the signature (test_the_status_entry_of_an_mdoc_is_read_from_the_cwt_list,
test_the_status_anchor_is_the_issuer_of_the_status_chain).

Looks at 29b5c08 (base 1555c78): two clean in a row. Mutation: MD2 (any certificate with the right name is taken as
the anchor) survived, since no test offered one with the root's name and another key; one now comes first in the
anchors file and is passed over (test_the_status_anchor_is_the_issuer_of_the_status_chain). MD1, MD3, MB6 and every
mutant of status_list_anchor killed.

## Revocation chaining (piece E)

Each credential that lives more than a day keeps, in the store and never in the logs, the status references of the
wallet attestations and key attestations it was issued against (ARF WURevocation_11): in the code flow both the one at
PAR and the one at the token request, the one shown at a refresh for what the refresh yields, and those of a
pre-authorized request that carried one. A job in the maintenance loop, at most every chain_interval and never more
than a day apart, reads each wallet provider's list once and revokes every credential whose wallet unit or key storage
is revoked, logged as wallet_revoked (CIR 2024/2979 Annex Ib LC_GEN-4; CIR 2024/2977 Art. 5(4)(b); ARF WUA_29, VCR_07c,
WURevocation_18; TS3 §2.3.1). One worker runs it per interval.

cunho now reads identifier lists as well as status lists, for wallet and key attestations, at issuance and in the job
(CIR 2024/2979 Annex II EAA-6.2.10.1-09 to -11, -14, -16), and tells a revocation (Revoked) from a status it cannot
know. A list that cannot be read revokes nothing: cunho alerts in cunho.security and logs chain.unchecked, and tries
again (Paulo, 2026-11-09: alert only); chain_revoke_after_days lets an operator revoke after that many days unchecked,
logged as wallet_unchecked. An attestation provider chains with chain_attestations (ARF VCR_07d); a credential of a day
or less is not chained (EAA-6.2.10.1-02.1). Revoking a subject drops its references; erasing it keeps them while its
credentials live. Reference parsing moved to cunho.status_refs so the modules that only read references do not import
the fetching code.

## First look at 258b50e

| Finding | What changed | Test |
|---|---|---|
| P2: chaining ran inside maintenance, so a maintenance interval of two days stretched the daily check to two days | The background loop runs the job on every tick, gated by chain_interval alone. | test_the_background_loop_runs_the_job_whatever_the_maintenance_interval |
| P2: an outage at one wallet provider cost a fetch, and its timeout, per wallet, which could stall maintenance for hours | A list that cannot be fetched, verified, trusted or is out of date fails as ListUnavailable, and the run asks for it once: every other entry of it is unknown at once. An entry past the end of a readable list stays that entry's own. | test_an_outage_costs_one_fetch_per_list_not_one_per_wallet, test_an_entry_past_the_end_of_a_readable_list_leaves_the_others_checked |

## Second look at 2c23c93

| Finding | What changed | Test |
|---|---|---|
| P2: in a batch whose keys come with different key attestations, every credential watched every attestation, so revoking one key storage entry revoked credentials of other, valid keys | Each attested key keeps its own references, by thumbprint, and a credential watches the wallet attestations of its token and the key attestation of its own key. | test_a_credential_is_chained_to_its_own_key_attestation_only |
| P2: a check that read a row before the subject was revoked wrote it back afterwards, and the references were kept until expiry | The row is updated only if it is still there, read and written in one transaction. | test_a_check_does_not_bring_back_a_row_a_revocation_deleted |

## Third look at 56b82d8

| Finding | What changed | Test |
|---|---|---|
| P2: a run could count a list issuance had fetched up to an hour before as a fresh check, so with a one-day interval a revocation could stay unseen for nearly 25 hours | Each run takes only lists fetched since it started: the first entry of a list fetches it again, and the rest of the run reads that one. | test_a_run_reads_lists_fresh_never_one_kept_from_before_it |

Mutation at 258b50e: ME1 (an identifier list kept past its exp), ME5 (an identifier list's signer not checked before it is
kept) and ME15 (the interval ignored) survived. A list past its exp is fetched again, an untrusted list with a later iat
cannot make the genuine one look older, and a run just before a new interval period is not followed by another just
after it (test_an_identifier_list_past_its_exp_is_fetched_again,
test_an_untrusted_identifier_list_cannot_raise_the_newest_seen, test_a_new_interval_period_does_not_start_a_run_early).

## Fourth look at ac5b858

| Finding | What changed | Test |
|---|---|---|
| P2: the run still went entry by entry, so a list with a short ttl, or more lists than the worker's cache holds, was fetched again for later entries | The run collects the entries the live credentials name, by list (small references only); fetches each list once, fresh, and judges all its entries at once, one list in memory at a time; then acts on the verdicts. An entry it did not collect, of a credential issued meanwhile, is read on its own. | test_each_list_is_fetched_once_per_run_even_when_its_ttl_runs_out_meanwhile, test_an_entry_not_read_at_the_start_of_a_run_is_read_on_its_own |

## Fifth look at 98a5f7a (clean), sixth look at 98a5f7a

| Finding | What changed | Test |
|---|---|---|
| P2: the lock between workers was named after the interval, so a run still going when the clock crossed into the next interval let another worker start one beside it, and the older run could write older timestamps over newer ones | One lease, whatever the interval, taken in the same transaction as the check that a run is due, which records the run's start; the run renews its own lease, and only its own, after each list and each page, and gives it back at the end only if it is still its own. A worker that dies holding it delays the next run by at most an interval. | test_a_second_worker_waits_for_a_run_in_progress_even_across_intervals, test_a_run_longer_than_an_interval_keeps_its_lease, test_a_run_renews_only_its_own_lease, test_a_run_that_lost_its_lease_leaves_the_new_one_alone |

## Seventh look at e5a87d8

| Finding | What changed | Test |
|---|---|---|
| P2: a run that lost its lease, after a pause longer than an interval, went on writing: an older check's time over a newer one, which with chain_revoke_after_days could revoke too early | Renewing a lease the run no longer holds stops the run. Every write it makes, a revocation or a check, renews the lease first in the same transaction; a check moves the time forward only, and the unchecked period is judged from the row as it is now. A forced run takes the lease, so the other one stops. | test_a_run_that_lost_its_lease_writes_nothing_more, test_an_older_check_never_writes_over_a_newer_one, test_overdue_goes_by_the_row_as_it_is_not_as_the_run_read_it, test_a_forced_run_takes_the_lease |

## Eighth look at f38ed72

| Finding | What changed | Test |
|---|---|---|
| P2: an interval of a second, which settings took, let a run's lease run out during one list's fetch, so every run stopped and nothing was ever revoked | chain_interval is from ten minutes to a day: the lease lasts an interval and is renewed after each list, and one fetch has a budget of seconds. | test_chaining_settings_are_checked, test_the_shortest_and_longest_intervals_are_taken |

## Ninth and tenth looks at 913e2c3

Both clean. Piece E is closed on two clean looks in a row.

Mutation at 913e2c3: ME27 survived because, once the job judges each list as a whole in `verdicts`, nothing told a list's
failure from an entry's any more: ListUnavailable and the wrapper that raised it are gone. ME28 survived because the
write-back test's check came out unchecked, so it never reached the write it guards; the lists are served now and
the test asserts the check succeeds (test_a_check_does_not_bring_back_a_row_a_revocation_deleted).

## Eleventh look at 57eb62d (clean), twelfth look at 57eb62d

| Finding | What changed | Test |
|---|---|---|
| P2: the lease token was kept on the issuer, so a forced run in the same process overwrote it and the older run went on renewing the newer run's lease and writing | Each run's token is passed down through its steps; nothing about a run is kept on the issuer. | test_a_run_with_a_stale_token_stops_at_its_first_write |

## Thirteenth and fourteenth looks at bcfe4b5

Both clean. Piece E is closed on two clean looks in a row.

Mutation at bcfe4b5: 14 site mutants survived in `status_refs.py`, `WalletStatus._judge` and
`WalletStatus._verified_identifiers`. Two were dead code: the `reference()` helper nothing called any more, and a
branch of `_judge` no input could reach; both are gone (0205d6b). The rest were untested edges of identifier lists,
now tested: a tag other than COSE_Sign1, a protected header or payload that is not a map, `iat` or `exp` given as a
boolean, a non-integer `ttl`, `iat` just past the clock skew and exactly at it, `exp` at the longest allowed
lifetime, an identifier of the longest allowed length, and a trusted RSA signer, which reaches the EC-only signature
check. ME2 now points at the simpler check in `_judge`.

Mutation at 5eaaeab: `status_refs.py` and ME2 clean; three survived. Two were fallbacks in `_judge` no input could
reach (an index of 0 for an entry with none, no identifiers for a list with none): `_judge` now picks the status-list
branch by the index and an identifier list's identifiers default to none, so neither fallback exists. The third
showed that a list whose `exp` is a boolean would, without that check, pass verification and set the newest-seen
mark before being refused as expired, so a later genuine list with an older `iat` would be refused
(test_a_list_refused_for_its_exp_leaves_no_mark). ME2 follows the new line.

Mutation at ca0439a: `WalletStatus._judge` 6/6, `WalletStatus._verified_identifiers` 55/55 and ME2 killed;
`status_refs.py` 23/23 at 5eaaeab. Piece E is closed: two clean looks in a row (bcfe4b5) and mutation clean.

## Piece F: deferred issuance and notification (OpenID4VCI 1.0 §8.3, §9, §11)

Built at the commit after c049cee. The operator holds a login's credentials with `"review": true` in the login
result; a pre-authorized offer with `review` is refused, since its token cannot outlive a review and it has no
refresh token. The credential request is checked in full, the grant claimed, and the answer is 202 with a
`transaction_id` (a keyed reference of it is stored, never the id). The operator lists, releases or refuses through
the admin API, once per issuance. The wallet collects with any token of the same login that covers the
configuration; the credentials are signed then, bound to the keys proven at the request, with the wallet attestation
of the token used now, and the held row is taken in the transaction of the log entry so a transaction yields once.
Closure drops held issuance; the subject's data and person link are kept for as long as it can be collected.
Every credential response carries a `notification_id`; notifications are logged once per event, their free text
never kept. Patches MF1 to MF13. Seven older patches (S9, S12, S14, R6S3, R7L1, E15, R4) follow the code they
target, which moved into `_issue`.

## First look at 0a322a4

| Finding | What changed | Test |
|---|---|---|
| P1: a key attestation revoked while an issuance waits for review did not stop its collection: its status was read when the issuance was asked for, and chaining watches only issued credentials | At collection, the held keys' status references are read again: a revocation answers credential_request_denied, a list that cannot be read keeps the issuance waiting (202) | test_a_key_attestation_revoked_during_review_stops_the_collection, test_a_key_attestation_that_cannot_be_read_keeps_the_collection_waiting |
| P2: a reply kept by the previous version has no notification_id, and a repeated request raised KeyError | Such a reply is answered without one, which §8.3 allows | test_a_reply_kept_before_notifications_is_answered_without_one |

## Second look at 91adebf

| Finding | What changed | Test |
|---|---|---|
| P1: a held issuance's row was trusted as stored: whoever can write the database could change the keys it binds, clear their status references, or mark it released without the operator | The row is sealed with the keyring MAC over its key (subject and transaction reference) and content, with its own expiry, as offer, token and refresh rows are; every read opens it, and a decision seals it again. A row that fails is taken as gone | test_a_held_row_changed_in_the_database_is_not_trusted, test_a_held_row_moved_to_another_subject_is_not_trusted |

Found while fixing it: the notification row, which says whose issuance a notification_id names, was unsealed too;
a changed row could let another login's notifications into the log under the first one's issuance. Sealed the same
way (test_a_notification_row_changed_in_the_database_is_not_trusted).

## Third look at 8dd4d8b

| Finding | What changed | Test |
|---|---|---|
| P1: the review was a store row whose absence meant "issue at once", so deleting it skipped the operator | The review travels in the login result, which the sealed login-done, code, access-token and refresh rows carry, and a token says it as `Grant.review`; nothing outside those rows decides it, and a token row changed to drop it fails its MAC | test_a_refreshed_token_stays_under_review, test_a_token_whose_review_was_removed_in_the_database_is_not_trusted |

## Fourth look at 81fa043

| Finding | What changed | Test |
|---|---|---|
| P2: an issuance asked for near the end of the refresh token's life was held for the full deferred_ttl, though after the refresh token expired no token could collect it | Tokens carry the expiry of the refresh token of their login (sealed with them); a hold lasts deferred_ttl or until the later of the token's and the refresh token's expiry, whichever comes first | test_a_hold_ends_with_the_refresh_token |

## Fifth look at baff5d9

| Finding | What changed | Test |
|---|---|---|
| P2: a hold re-kept the subject's data and person link for a fresh subject window, so a request near the refresh token's end kept personal data a month longer than anything could use it | Nothing is re-kept: only the code flow is held, its refresh token already keeps the data and the link until it ends and a token after it could, and a hold never outlasts that. MF8 goes with the code it broke | test_a_hold_keeps_no_data_longer |

## Sixth and seventh looks at 2397d82

Both clean. Piece F is closed on two clean looks in a row.

### Mutation at 61ee771 (piece F)

Sixteen areas: F's new code in service.py, the two settings, `_whole`, and the MF patches. Fourteen survivors, all
fixed:

- `_defer`'s check of a closed subject inside its transaction, and the `raise` after giving the claim back: no test
  closed the subject between the request's checks and the hold. A new test cancels the offer right after the claim:
  the wallet is refused, nothing is held, no transaction is indexed.
- The deferred endpoint's refusals of a configuration no longer issued, of subject data that is gone, and of data
  that no longer passes the PID rules on the day of collection: each now has a test (the last one holds across
  11 August 2028, when a portrait becomes required).
- `decide_deferred`'s check of the reference's shape: a test now sends references that are not 32 lower-case hex.
- The notification's `isinstance(event, str)`: an event given as a list now has a case (it would raise TypeError
  in the set lookup).
- `deferred_ttl` and `deferred_interval` bounds: tests at each bound, taken and refused, including an interval
  longer than a short `deferred_ttl`. The `deferred_ttl` message no longer says the subject's data is kept that
  long, which stopped being true when holds stopped extending anything.
- MF7, a held issuance making the offer live: the branch was dead. Only the code flow is held and no hold outlasts
  the login's refresh token, whose mark already makes the offer live. Branch and patch removed; the comment on the
  refresh mark says it covers holds, and F10 now flips that mark's check.

Rerun at 0506673 on the nine areas touched (`_defer`, `deferred_credential`, `decide_deferred`, `notification`,
`_offer_live`, both settings, the MF patches and F10): 85 of 85 killed, none listed as equivalent.

**Piece F is closed**: two clean looks in a row at 2397d82, and mutation clean.

## Piece G: encrypted requests and responses (built at this commit)

OpenID4VCI 1.0 §8.2, §8.3, §9.1, §9.2, §10 and §12.2.4. Two new binder rows, VCI.ENC.REQUEST and VCI.ENC.RESPONSE
(M4_ROWS in binder/src/rows_spec.py), with their quotes in BINDER-STRENGTH.csv.

- `jwe.py`: compact JWE with ECDH-ES in direct mode, A128GCM and A256GCM, the Concat KDF of RFC 7518 §4.6.2, all
  with `cryptography`. The KDF gives RFC 7518 Appendix C's known answer; the tests' wallet side is written apart from
  it, with its own KDF, and the two decrypt each other.
- `CUNHO_ENCRYPTION_KEYS` (up to four PEM EC P-256 keys, chmod 600) and `CUNHO_ENCRYPTION_REQUIRED`. With keys the
  metadata carries both blocks, each key with its RFC 7638 thumbprint as kid, use enc, alg ECDH-ES; no
  zip_values_supported.
- The credential and deferred credential endpoints take application/jwt. The JWE's alg, enc, kid (required, one of
  cunho's keys), epk (on that key's curve), empty encrypted key, iv and tag lengths are checked; apu and apv go into
  the KDF; crit and zip are refused. credential_response_encryption is taken only from an encrypted request (§8.2),
  with a public EC key whose alg is ECDH-ES, and is checked before anything is claimed or signed. 200 and 202
  answers are encrypted when asked; errors never are. A deferred request's own parameters are used (§9.2).

### First and second looks at 0f2289e (piece G)

Both clean: no findings, the full suite green. Piece G is closed on reviews. Seven patches (MG1 to MG7) added for
what the generated mutants do not reach: the reply never encrypted, the app serving the JWE's content as JSON, apu
and apv left out of the KDF, the key length given in bytes, the protected header not authenticated, the wallet's kid
not echoed, and the metadata without the request keys.

### Mutation at 95bb9f8 (piece G)

Thirteen areas: jwe.py, the request and response checks, both endpoints, the metadata, the settings check, the app
routes, and MG1 to MG7. Everything outside jwe.py was killed (57 of 57, and all seven patches). Six survivors in
jwe.py:

- `_public`'s own refusal of a non-object or private key: `public_key_from_jwk` already refuses both, with the same
  effect. The check is gone.
- `isinstance(enc, str)` in the response parameters and in the request header: an enc sent as a list now has a case
  in each (it would raise TypeError in the dict lookup).
- `"use" in jwk`: every test key carried use. A wallet key with neither kid nor use now has a test.
- `len(paths) > MAX_KEYS` as `>=`: a test now runs with exactly four request keys.

Rerun at 0c77884 on jwe.py and the MG patches: 93 of 93 and 7 of 7 killed, none listed as equivalent.

**Piece G is closed**: two clean looks in a row at 0f2289e, and mutation clean.

## Piece H: signing keys in an HSM or KMS (built at this commit)

No binder rows: decision 1 holds signers to engineering tests. A key setting takes a PEM file, a `pkcs11:` URI
(RFC 7512: token, object, id, type=private; no query, the PIN comes from `CUNHO_PKCS11_PIN_FILE`, chmod 600, the
library from `CUNHO_PKCS11_MODULE`) or `aws-kms:` and a key id, ARN or alias. Production refuses a file for every
signing key (credential, status, mdoc, access), where it refused the file signer outright before. The `pkcs11` and
`kms` extras bring python-pkcs11 and boto3.

- Both hash the input and have the device sign the digest (CKM_ECDSA; KMS MessageType DIGEST, since a JWS signing
  input can pass the 4096 bytes KMS takes as a message). Every signature is checked against the leaf certificate's
  key before use, and each signer signs once at the start.
- PKCS#11: one session per signer behind a lock, opened again once when the token drops it. Found while testing: a
  PKCS#11 login belongs to the process, so the second signer on a token (status or mdoc beside the credential key)
  got UserAlreadyLoggedIn and production with several keys in one HSM would not have started; such a session now
  opens without logging in again.
- KMS: the key is pinned to the ARN GetPublicKey returns; the region comes from an ARN; KeyUsage SIGN_VERIFY and
  ECC_NIST_P256/P384/P521 only.
- Tests: SoftHSM2 with the test PKI's own keys imported, end to end through a production issuer with all four keys
  in the HSM. KMS through a fake client that signs the digest as the API reference describes and checks every
  request against botocore's KMS model; moto 5.2 hashes a DIGEST message a second time, so it could not stand in.
  CI installs softhsm2 and the extras in the check and mutation jobs, so the tests do not skip there.

### First look at e3cbf37 (piece H)

A first run of the look reviewed a working tree from which macOS's daily /tmp cleanup had removed 217 files, and
reported them deleted; that run does not count, and every look now resets the review checkout and checks it is
complete before it starts. The look on the restored tree found one thing:

- [P2] When a signature failed with the session still open, the retry opened a new session without closing the old
  one, so transient failures could use up the token's sessions. The old session is now closed first; when it was
  the process's only session on the token, the token logs the process out and the new session logs in again. Two
  tests: a failure that leaves the session open (the old one is closed after), and the same on a token where the
  signer holds the only session. The wrong-PIN test now has a token of its own, so its outcome does not depend on
  which test logged in first.

### Second look (at 373b3f7, piece H)

Two findings, both checked in python-pkcs11 0.10.1's source (`Token.open` logs in after opening the session and
does not close it when the login fails; `Session.close` calls C_Logout before C_CloseSession):

- [P2] The second signer on a token opened a session, failed its login with UserAlreadyLoggedIn and left that
  session open, at every start and every recovery while another signer was logged in.
- [P2] Recovering the signer whose session had logged in closed that session, which logged the whole process out
  and broke the other signers' key handles.

Login is now per token (`_Token`, one per library and token in the process): one session logs in, once, and stays
open; every signer signs on a session of its own that never logs in, so closing it logs nobody out. A recovery
replaces only the failing signer's session, and logs the process in again only when a probe on the login session
(C_GenerateRandom) shows it is gone with the token's other sessions. Tests: signers after the first open no session
with a PIN; one signer's recovery leaves another's session and key working; after a logout the next signature logs
in again (the login session is a new one). A failed first login still leaves its session to the library, but the
start stops there.

### Third look (at 6be07ec, piece H)

- [P2] The login probe dropped the login session on any error, so a token without a random generator, or a passing
  device error, made the next login fail with UserAlreadyLoggedIn for good. The login session is now dropped only on
  errors that say it is gone (SessionHandleInvalid, SessionClosed, DeviceRemoved, TokenNotPresent,
  UserNotLoggedIn); any other answer keeps it. A test per kind of answer (RandomNoRNG, FunctionNotSupported,
  DeviceError): the failing signer recovers, the login is kept, and a new signer on the token starts.

### Fourth and fifth looks (at bb694be, piece H)

The fourth was clean. The fifth:

- [P2] The login probe (C_GenerateRandom) told a live session from a dead one, not a logged-in one from a public
  one: a token that logs the process out and keeps its sessions answered the probe, so cunho never logged in again
  and every signature failed until a restart. Reproduced with C_Logout on the live login session.

python-pkcs11 0.10 offers neither C_GetSessionInfo nor C_Login on an open session, so cunho now calls the module's
own (from C_GetFunctionList, the library python-pkcs11 loaded). Every session cunho opens is public, which
python-pkcs11 closes without C_Logout; the process logs in with C_Login on one of them, kept for that, and
CKR_USER_ALREADY_LOGGED_IN counts as logged in. Before logging in it reads the session's state: logged in, public
(log in again) or gone (open another, then look). This also ends the session a failed login left behind before.
Tests: a logout that keeps the sessions (the key comes back into view, on the same login session), a login session
that is gone, and a wrong PIN three times over (refused with CKR 0xa0 each time, one public login session reused).
The probe tests went with the probe.

### Sixth and seventh looks at cb8b0ff (piece H)

Both clean. Piece H is closed on reviews. Five patches (MH1 to MH5) for what the generated mutants do not reach: an
HSM or KMS signature used unchecked, no signature at the start, KMS sent the message instead of its digest, the
KMS key following the alias instead of the ARN found at the start, and a failing HSM session not given back.

### Mutation at 8079207 (piece H)

signer.py (110 mutants), default_signers and MH1 to MH5. All five patches killed; seven survivors in signer.py, each
now with a test:

- `_Module`'s refusals (a file ctypes cannot load or without C_GetFunctionList, a function list answered with an
  error or not filled in): python-pkcs11 refuses such a file first, so `_Module` is now tested on its own, with a
  stand-in for the loaded library.
- The two messages that name a missing extra (pkcs11, kms): tested with the module made unimportable.
- A pkcs11: URI attribute without `=`: `type` alone now has a case.

Rerun at 9246695 on signer.py: 109 of 110 killed. The survivor is `_Chained`'s refusal of a certificate whose key is
not EC: the file and KMS signers refuse such a key before, so only an HSM key with an RSA certificate reaches it. A
test now does.

Rerun at b3f4248 on `_Chained`: 17 of 17 killed. With the earlier runs (signer.py, default_signers, MH1 to MH5),
nothing survives.

**Piece H is closed**: two clean looks in a row at cb8b0ff, and mutation clean.

## Piece I: a PostgreSQL store (built at this commit)

No binder row (decision 1). `PostgresStore` (psycopg 3, the `postgres` extra), chosen by `CUNHO_STORE_URL`, a
postgresql:// URI, in place of `CUNHO_STORE_PATH`; it needs `secret_key_file` and `audit_anchor_path`, since
neither lives in the database, and is refused together with a store path.

- Every write transaction takes one advisory lock first (`pg_advisory_xact_lock`), single writes outside `atomic()`
  included, so writers go one at a time across workers and hosts as BEGIN IMMEDIATE has them on one SQLite file;
  reads see what is committed. The table is created under a second advisory lock, for workers that start together.
- Keys are UTF-8 bytes (bytea): they sort in code point order as SQLite's do, and may hold NUL, which a Postgres
  text column refuses. A connection the server dropped between calls is opened again on the next call.
- `checkpoint` runs VACUUM; the README says what it cannot reach (the server's WAL, archives, backups).
- One contract test file runs the same tests on the memory, SQLite and PostgreSQL stores. It found that the memory
  store deleted an expired entry on any read, while SQLite leaves it for sweep, so a later `peek` or `items(at=...)`
  in the past missed it on memory alone; the memory store now purges only in take, add and incr, as SQLite does.
- PostgreSQL only: four processes adding the same keys (one wins each), four processes counting and doing a
  read-modify-write in `atomic()` (no update lost), six processes creating the table at once, a single write
  waiting for another connection's transaction, a connection the server terminated, VACUUM refused inside a
  transaction, an unreachable database, the settings, and the issuer issuing, repeating, revoking and verifying its
  log on PostgreSQL, then starting again on the same database.
- The slow model test (four worker processes) now runs on SQLite and on PostgreSQL, a new database per example;
  both pass.
- Tests start a throwaway cluster on a Unix socket under /tmp (initdb, pg_ctl) when no CUNHO_TEST_POSTGRES_URL is
  given; the CI runner image carries PostgreSQL, and the check, slow and mutation jobs install psycopg.
- ST1, ST4 and R8S1 match their SQLite and memory lines again, which the new store's text had made ambiguous.

### First look at f4fb77b (piece I)

- [P1] The clock watch kept one base for the store, named by the boot it was laid on. With hosts sharing a
  PostgreSQL store, each took the other's base for a restart of its own and laid it again, so every host kept
  losing its trusted time and starting its wait before pruning over. Each boot now keeps its own base, under
  `clock:<boot>`; a new boot compares its first reading with the newest base any boot laid (checked under its MAC,
  without touching what the watch keeps), a store that never had any base is a first start, and the latest time
  seen is only raised by a tick, so a host whose time runs behind does not take it back. Workers on one host, and
  containers on one kernel, share a boot and one base, as before. A store's single `clock` row from before is still
  this boot's base, and the next base laid replaces it. The clock tests now read the per-boot row; two new tests:
  two hosts on one store (each keeps its base; the first host's wait is not started again; the time seen stays at
  the host ahead), and a base kept in the single row of an earlier store.
- [P2] Waiting for the PostgreSQL writer lock had no bound and held the worker's store lock meanwhile. Each write
  transaction now sets `lock_timeout` to SQLite's busy timeout (30 s) for itself; a test holds the lock and sees a
  second connection fail after its timeout and write afterwards.
- W5, W8, W9, R7C7, R7C8, R8C2, R8C3 and R8C5 repointed to the lines that now do what they break.

### Second look (at 6888780, piece I)

- [P1] The anchor gave the newest forced base of any boot, so with hosts sharing a store, host B's newer forced
  run hid host A's: a worker started later on A no longer refused A's earlier base put back into the database. The
  anchor reader now keeps the newest forced base per boot too, `clock_floor(boot)` gives that boot's, and the watch
  asks for its own. A test forces A, then B, puts A's earlier base back, and a new worker on A refuses it; it fails
  with the watch asking for the newest of any boot.
- [P2] PostgresStore's get, items and scan read the time before taking the worker's lock, so a row could expire
  while the call waited for another thread's transaction and still be returned. They now read it under the lock, as
  SQLite's do.

### Third look (at b9dc54b, piece I)

- [P2] The README let hosts sharing a store do without shared locking of the anchor if they did not run
  maintenance at once. Every logged action, issuance and revocation included, appends to the anchor after its
  transaction, so hosts that cannot lock it against each other break its chain. The README now requires one anchor
  file with working `flock` across hosts and names no alternative.

### Fourth and fifth looks (at 6414641, piece I)

The fourth was clean. The fifth:

- [P2] When the server dropped the connection inside a transaction that then failed, ROLLBACK raised in turn and
  the undo callbacks were skipped, so the clock watch kept a floor at a base the database never committed. The
  callbacks now run in a `finally` around the rollback, under the store lock, in both SQLite and PostgreSQL; in
  PostgreSQL a failed ROLLBACK means the connection, and the transaction with it, is gone, so the caller's own error
  is raised. A test terminates the backend inside a failing unit: the callback runs, the caller sees its error, and
  the next call reconnects and finds nothing of the unit. R8U2 repointed to the new SQLite rollback.

### Sixth and seventh looks at c6c45e3 (piece I)

Both clean. Piece I is closed on reviews. Eight patches (MI1 to MI8) for what the generated mutants do not reach:
the writer lock, its timeout and the schema lock in PostgreSQL; the clock base read from the single row only; a new
boot compared with its own base; the latest time seen taken back by a host behind; the newest forced base of any
boot as the floor; and a failed PostgreSQL rollback skipping the undo callbacks.

### Mutation at 687090f (piece I)

Three survivors of 99, all fixed with tests:

- The Postgres store's message when psycopg is missing was marked as never run. A test hides the package and checks
  the message names the extra to install; the coverage exclusion is gone.
- Dropping the `raise` after a failed schema setup let the store start on a table it cannot use. A test puts a `kv`
  table of another shape in the database and checks the start stops on it.
- R7C3, the boot check in `_expected`: since bases are kept per boot it is reached only through the single row of an
  older store, which may hold a base from before a restart. A test leaves such a row and restarts the host: the
  watch has no base, instead of moving the old boot's base on by the new host clock.

### Mutation at 2c58b2c (piece I)

PostgresStore 5 of 5 and the R7C patches 10 of 10 killed. Piece I is closed.

## Piece J: qualified attestations, the wallet-solution gate, silent re-issuance

Built from ETSI TS 119 472-1 V1.2.1 (clauses 4.2, 5.2, 5.6, 6, Annex A), ETSI TS 119 152-1 V1.1.1 (CB-AdES), ARF SUA_01
to SUA_07 and TS3 v1.5 (wallet_name, wallet_version).

- Qualified and public-body providers (QEAA.*): the provider is named by its signing certificate, which every
  credential carries, so its configurations list no issuing_authority, issuing_country or iss_reg_id (EAA-5.2.4.1-03,
  -07, -11; EAA-6.2.4.1-13). At start, the credential signer's and the document signer's certificates must give the
  Member State, and the name and an EN 319 412-1 §5.1.4 organizationIdentifier of a legal person or the name of a
  natural person. Each SD-JWT VC gets a jti of 128 random bits; subAttrs, and SubAttr values in an mdoc, are refused
  (QEAA-5.2.5.5-01, -6.2.5.5-01). By default such a provider publishes only what it may issue; naming another
  configuration stops the start.
- Clause 6 for every mdoc attestation that is not a PID or an mDL: cunho fills in issuing_authority_unicode (from the
  certificate), document_number (an identity code per credential) and issue_date in org.iso.23220.1, and the category
  of a qualified or public-body attestation in org.etsi.01947201.010101; the metadata lists them and neither the
  configuration nor the operator's data may. An mDL lists its own. The issuerAuth carries iat in signed CWT claims
  and x5t, as the CB-AdES baseline asks; x5chain stays a bare unprotected header as ISO/IEC 18013-5 asks, which TS 119
  152-1 §4.4 contradicts, so FMT.ETSI_119472_1 keeps a partial mark naming that point.
- ISS.SUA.WALLET_GATE: a configuration may list wallet_solutions (wallet_name, optional wallet_versions); each token
  row keeps the wallet of the attestation that got it (the newest one on a refresh), and the credential endpoint
  refuses a gated configuration to any other wallet, or to a token got without an attestation.
- BATCH.SILENT_REISSUANCE: the refresh grant, proven with a test where nobody can log in any more.
- L2 and L7 repointed to the moved code.

### First look at c888047 (piece J)

- A wallet_solutions entry with `"wallet_versions": null` passed the start-up check, and the gate then raised a
  TypeError at the credential endpoint. The check now refuses wallet_versions whenever the key is there and is not a
  non-empty list of version strings; a test covers null.

### Second look at 9250513 (piece J)

- The deferred credential endpoint issued a released credential without the wallet-solution gate: a wallet could ask
  with a listed version, refresh with an attestation of a version off the list, and collect. The collection now runs
  the gate on the grant it collects with (the newest attestation, as at a refresh), and the grant it issues under
  keeps that wallet. A test holds, releases, refreshes with a version off the list (refused), then with a listed one
  (collected).

### Third look at 363df10 (piece J)

- The issue date in org.iso.23220.1 was filled in only when the operator left it out, so an operator could give an
  mdoc attestation any issue date, though the README says cunho fills it in. It is now among the elements cunho fills
  at signing (the day the credential's validity starts) and refused in the operator's data, and the issuance-date
  fill-in of the other namespaces leaves it alone. MB22 repointed.

### Fourth and fifth looks at d88f69a (piece J)

Both clean. Piece J is closed on reviews. Thirteen patches (MJ1 to MJ13) for what the generated mutants do not reach:
the version check of the wallet gate; the gate at the credential and deferred endpoints; the wallet kept in pre-
authorized, code-flow and refreshed tokens; a refused configuration published by default; the issuing authority's
name; the mdoc category's namespace; the signed signing time; the Member State and organizationIdentifier checks;
and the document signer's check for a qualified provider.

### Mutation at 4e8b298 (piece J)

All sites, conditions and the MJ, L and MB22 patches over piece J's code. Eight survivors, each killed by a test:

- `_check_mdoc_eaa`: no test listed an element of org.iso.23220.1 that cunho does not fill in, or a `category` in
  another namespace, so refusing every element of that namespace, or every `category`, went unseen. A test now
  publishes an mdoc attestation with family_name_unicode in org.iso.23220.1 and a category of its own namespace,
  under each profile.
- `authority`: a certificate with a surname and no given name was not tried; it now raises.
- `_check_wallet_solutions`: an entry that is a list or a number was not tried, so the dict check could go and the
  start would crash with an AttributeError or TypeError instead. Both are now in the start-up cases.
- `oauth._wallet`: rows of the wrong length, or with a name or version that is not a string, were not tried; a unit
  test now gives it broken rows.
- MJ6: no test redeemed a pre-authorized code with a wallet attestation for a gated configuration. One does now, and
  gets the credential.

### Rerun at bc8513b (piece J)

The five areas again: `_check_mdoc_eaa` 14/14, `authority` 6/6, `_check_wallet_solutions` 28/28, `oauth._wallet`
7/7, MJ6 1/1. No survivors. Piece J is closed.

## Piece K: the probe for M4

Eighteen new checks, written against the specifications and apart from cunho's code (the probe has its own COSE,
CBOR and JWE code, `probe/eudi_probe/cose.py` and `jwe.py`):

- mdoc (I01 to I06, and C16 now on the mdoc issuance): the IssuerSigned structure, issuerAuth signed by the
  document signer its x5chain names with the id-mdl-kp-mdlDS purpose, the MSO's docType and every element's digest,
  the device key against the proof key, validityInfo (tdate without fractions, in order, inside the signer's
  validity), every mandatory element issued and every date well-formed, and the status list entry fetched and
  verified as a `statuslist+cwt`, with the reference's `certificate` checked to sign the list's chain.
- Deferred issuance (D01 to D05): endpoints, an unknown transaction_id, no token, a held issuance from 202 to
  collection and the id spent after, and another wallet's token refused.
- Notification (C17, C18): another wallet's token refused, malformed requests refused.
- Encryption (E01 to E05): the metadata blocks, an encrypted round trip, an unsupported enc, response encryption
  asked for in a plain request, and a request that does not decrypt.

`tools/probe_local.py` now runs cunho with a document signer and a request encryption key, offers the PID in both
formats, holds an issuance through the test login and releases it with `tools/dev_release.py`, and fails unless every
check of M3 and M4 passes; it passes. An engine test runs every M4 check in process, shows each of the four that try
a bypass failing once cunho's rule is switched off, and feeds the mdoc checks mdocs broken where each looks.

What the probe found in cunho:

- An mdoc started at the coarse time, rounded down to the hour, and its MSO said it was signed then. Against a
  document signer certificate that started within that hour, `signed` came before the certificate's validity, and a
  reader that checks it (ISO/IEC 18013-5 §9.3.1) refuses every mdoc of that hour. An mdoc now starts at the
  certificate's start when that is later than the coarse time and not later than now; a test covers a certificate
  that started within the hour and one not valid yet. MK1 and MK2 patch it; S5 and R7S14 repointed.

Other changes: the test login has a box that holds the login's credentials for review, so deferred issuance can be
tried against a development cunho; the test wallet's form filler leaves unticked boxes out, as a browser does. The
binder links the new checks to the rows that asked for them (mdoc device key, MSO verification, CWT status list,
deferred, notification, request and response encryption).

### Mutation at b1f0997 (piece K)

`_validity` 3/3, the test login 1/1, MK1 to MK4 4/4, S5 and R7S14 1/1 each. No survivors. MK3 and MK4 cover the
test login's hold box, which the generator does not reach.

### First look at b1f0997 (piece K)

- D04 polled the deferred endpoint at once after a 202, though the wallet waits its interval (OpenID4VCI 1.0 §8.3), so
  an issuer that enforces it would fail. The probe now waits each 202's interval, the latest one given, up to
  `--deferred-wait-max` (60 s); a longer one is polled early and said so, and a refusal of such a poll is a warning.
  `probe_local` runs cunho with the least interval, 5 s, so the waits are real; a test counts them.
- I06 checked that the status list had an exp, not that it was still valid, so a stale list that hides a revocation
  passed. I06 and C03 (the JWT list, which had the same gap) now fail a list past its exp or with an iat in the
  future, and a ttl that is not a positive number; tests read both lists thirty days on.
- A full-date was checked for its shape only, so 2026-02-30 passed, and a tdate of that day stopped I04 with an
  error instead of a finding. Both are now read as days of the calendar.

### Second look at 78640ea (piece K)

- I06 verified the status list with the first certificate of its x5chain and checked only that the last one was
  signed by the reference's certificate, so a signer prepended to a real chain passed. It now checks every link of
  the chain and that each certificate, and the reference's certificate, is valid now. Without a certificate in the
  reference the chain goes up to the IACA, which the probe is not given: the outcome says it is not tied to an
  anchor. Tests serve the probe a list signed by a certificate prepended to the real chain, and one signed by an
  expired certificate under a chain the reference names.

### Third look at 950c83b (piece K)

- With one static offer and `--config-id` an mdoc configuration, C01 spent the offer and C16 then skipped, as the
  mdoc checks asked for an offer of their own; before piece K, C16 read C01's credential. The mdoc checks now inspect
  the run's issuance when it is already an mdoc of the configuration they want; a test runs C01, C16 and I01 to I03
  on one offer.
- The status list times took only integers, but a NumericDate may have a fraction (RFC 7519 §2, RFC 8392 §2), so a
  current list with a fractional iat or exp failed. They now take any finite number; ttl stays a positive number,
  and an unsigned integer in a CWT.

### Fourth look at c687328 (piece K)

- C18 took the gravest of its four outcomes from failures and warnings only, so four requests that got no answer
  passed as "4 malformed requests refused". C15, R01 and R04 had the same gap: an error never outweighed a pass. They
  now report the gravest outcome by one ranking (failure, error, warning, pass), and C15 calls a valid notification
  that got no answer an error, not a refusal. A test makes the notification and token endpoints time out.

### Fifth look at 2d67741 (piece K)

- The probe's chain check took a signature by the next certificate as enough, so a status list signed under an
  end-entity certificate posing as an intermediate passed I06. Every certificate that signs another, and the
  reference's certificate, must now be a CA, with keyCertSign when it states its key usage and no more CA
  certificates under it than its path length allows (RFC 5280 §4.2.1.3, §4.2.1.9). A test serves such a list.
- C17 checked the holder's own notification after the stranger's, and a refusal of it, which follows when the
  stranger's notification was taken, turned the established failure into an error. A failure now stands.

### Sixth look at 38204db (piece K)

- C17 and C18 used the notification_id of the run's shared issuance, which C15 had already notified: against an
  issuer that spends an id once the credential is accepted, C17 erred and C18 got the wrong error, whatever the
  issuer did right. Each now notifies an issuance of its own; a test runs C15, C17 and C18 in a row and shows their
  ids apart.
- When the list's x5chain sent the certificate the reference names as its top, I06 counted it as a CA under itself,
  so a [signer, root] chain with a path length of 0 failed. It is now checked once, in the chain; a test serves such a
  list.

### Seventh look at 1328aab (piece K)

- I02 hashed a new encoding of each IssuerSignedItemBytes, not the bytes the issuer sent, so an item sent with a
  longer encoding of its tag or length failed against a right digest, and passed against a digest of the shorter
  form. The probe's CBOR reader now keeps the bytes each tag came in, and I02 hashes those (ISO/IEC 18013-5
  §9.1.2.5). A test sends an item with its tag and length each in two bytes, against both digests.

### Eighth look at 7b1cce5 (piece K)

- E05's tampered request asked for no encrypted response, so on an issuer that requires one it was wrong twice: an
  issuer that took the JWE unopened would still refuse it, with invalid_encryption_parameters, and E05 would pass.
  It now carries credential_response_encryption as E02's request does, so the changed tag is all that is wrong; a
  test puts the tag back, opens the request with the issuer's key and finds it whole.

### Ninth look at 9698709 (piece K)

- When the reference named an intermediate CA and the list's chain sent it at its top, I06 checked it as its own
  issuer and failed a right chain. The reference's certificate, wherever the chain sends it, now ends the path there:
  the certificates under it are checked up to it, and what the chain sends above it is not needed. Sent apart, it
  must still sign the top certificate as a CA allowed to. A test serves [signer, root], [signer, intermediate] and
  [signer, intermediate, expired root] with the reference naming the root or the intermediate.

### Tenth look at 6c3289f (piece K)

- A reference that named the list's signing certificate itself cut the path to that one certificate, so no CA check
  ran and I06 passed a list that vouched for itself. The reference names the certificate that issued the signing
  chain (EAA-6.2.10.1-06.1): naming the signer is now a failure. A test serves such a list.

### Eleventh look at bce27e1 (piece K)

Clean.

### Twelfth look at bce27e1 (piece K)

- A status_list reference whose certificate was a text, a number or null was read as having none, so I06 passed
  without tying the list to it. A certificate member that is not a bstr now fails.
- The probe's CBOR reader took an indefinite length on an integer or a tag (additional information 31), and read
  `1f` as null, where a conforming decoder refuses it. Only strings, arrays and maps may be indefinite (RFC 8949
  §3.2.4); the others now fail. Tests for both.

### Thirteenth look at 37a859b (piece K)

- The probe's CBOR reader took an indefinite string nested in another as a chunk, and read `5f5f4161ffff` as `a`,
  where a conforming decoder refuses it. Each chunk must be a definite-length string of the same major type (RFC 8949
  §3.2.3); a nested indefinite one, or one of the other type, now fails. Tests for both.

### Fourteenth look at 9c55258 (piece K)

- With `--token-cmd` and `--config-id` an mdoc configuration, the mdoc checks skipped: a token command's offer names
  no configuration, and the selector neither read `--config-id` nor fell back to the metadata. Before piece K, C16
  read the run's issuance, which honoured `--config-id`. The selector now takes `--mdoc-config-id`, then
  `--config-id` when it names an mdoc configuration, then the offer's configurations or, when it names none, the
  metadata's. A test runs C16, I01 and I03 with a token command.
- One run of the whole suite here had one failure, whose name the gate did not print; six runs since, the whole
  suite and the affected files repeated, passed. The gate now prints the names of failed tests, so it can be named
  if it comes again.

### Fifteenth look at 05a14a1 (piece K)

Clean.

### Sixteenth look at 05a14a1 (piece K)

- The probe's COSE reader never read crit (2), so an issuerAuth or status list rightly signed but marking critical a
  header the probe does not understand passed I01 and I06, where a conforming recipient refuses it (RFC 9052 §3.1).
  crit must now be a non-empty array in the protected header, naming labels present there, all of them among those
  the probe understands (alg, content type, kid, CWT claims, typ, x5chain, x5t, x5u). Tests re-sign an issuerAuth
  with crit [999], and read each malformed crit.

### Seventeenth look at 91ff5e0 (piece K)

- In a run with `--token-cmd` and `--deferred-offer-cmd` and no offer command, the probe fetched a token for the held
  offer by running the token command, so D04 and D05 asked under another grant and failed on a 200. An offer that
  carries a pre-authorized code is now exchanged itself; the token command serves only the run's own offers. A test
  checks both in one token-command run.

### Eighteenth look at 3abaaf4 (piece K)

- The probe's JWE reader joined ciphertext and tag before decrypting, so a response with the last ciphertext byte
  moved into a 17-byte tag opened and E02 passed, where a wallet refuses it. The IV must be 12 bytes and the tag 16
  (RFC 7518 §5.3).
- The probe's COSE reader took a label sent in both the protected and the unprotected header, and verified by the
  protected one; a recipient refuses such a message (RFC 9052 §3). It now does too. Tests for both.

### Nineteenth look at 35ad779 (piece K)

- The probe's JWE reader ignored crit, so an encrypted response marking an unknown extension critical opened and
  E02 passed it, where a wallet refuses it (RFC 7516 §4.1.13). The probe understands no extension: a JWE with crit
  is refused. A test for it.

### Twentieth look at 7afeb15 (piece K)

- D04 called an interval of 0.5 or 5.0 a failure and the waits skipped it, though OpenID4VCI 1.0 §8.3 asks for a
  positive number, not an integer. Both now take any finite positive number; a test waits 0.5 and 5.0 and none of
  0, true, infinity or a string.

### Twenty-first look at 7b7164c (piece K)

- Against an issuer that requires encrypted requests or responses, the probe sent the requests it builds in plain
  JSON, so C16, I01 to I06 and the deferred checks failed without inspecting anything, as did the M2 issuance checks.
  The probe now sends them as a wallet does there: sealed to the issuer's first ECDH-ES key, asking for a response
  encrypted to a key of its own, and opens the answer before a check reads it. Bodies a check sends as they are
  (`raw`, E04's plain request) and notifications stay plain. A test runs C01 and every M4 check against such an
  issuer.

### Twenty-second look at 0a0ee3a (piece K)

- Against an issuer that requires encrypted requests and publishes no response encryption, the probe found nothing
  to seal with and sent plain JSON. Request encryption now stands on its own: the request is sealed, and asks for an
  encrypted response only when the issuer encrypts responses with something the probe can open. A test seals for both
  kinds of issuer.

### Twenty-third look at 04a658b (piece K)

Clean.

### Twenty-fourth look at 04a658b (piece K)

- The protected header was read with cbor2, which takes a repeated label and data after the map, so a rightly signed
  issuerAuth or status list with either passed I01 and I06. It is now read with the probe's strict reader, as the
  rest of the message is; no other part of a received message is read with cbor2. Tests for both.

### Twenty-fifth look at e2fd0ed (piece K)

- A header label of true or 1.0 passed as alg, Python taking both for 1. Labels in either header must now be integers
  (not booleans) or text strings (RFC 9052 §3).
- The device key took crv true or 1.0, and coordinates with zeros in front, since the point stayed the same. kty and
  crv must now be integers, and x and y bstr of the curve's length (RFC 9053 §7.1.1), on the curve. Tests for both.

### Twenty-sixth and twenty-seventh looks at 77fbda5 (piece K)

Both clean. Piece K is closed. The mutation run at b1f0997 stands for it: cunho's code has not changed since (every
fix after it is in the probe and its tests), and it ran MK1 to MK4 with S5 and R7S14, all killed. The probe passes
against a local cunho with every check of M3 and M4.

## Piece L: the OIDF suite for mdoc and encryption

tools/oidf/run.py runs two more plans, the HAIP plan for mdoc wallet- and issuer-initiated (`haip-wallet-mdoc`,
`haip-issuer-mdoc`), against an mdoc configuration made for the run, and turns request and response encryption on,
so every HAIP plan's encrypted variant runs. Each format gets a cunho of its own, publishing its configuration
alone, since a login's subject data has the shape of one format. expected-skips.json is empty. All five plans pass;
the encrypted modules (happy flow, unknown configuration, unsupported encryption algorithm) pass in all four HAIP
plans. VCI.PROFILE.OID4VCI_HAIP is no longer partial.

What the runs found:

- cunho refused credential_response_encryption with zip, as it publishes no zip_values_supported; the suite's
  encrypted happy flow always asks for zip=DEF and expects an issuer that does not advertise compression to answer
  uncompressed. cunho now does: a zip asked for is not done, and the JWE says so by having none, which any wallet
  reads. A zip that is not a string is refused, and a compressed request still is. Compressing before encrypting
  would give away lengths that depend on the credential's content. A test asks for zip=DEF.
- The development PKI's IACA, document signer and status signer were outside the certificate profiles of ISO/IEC
  18013-5 Annex B (Tables B.1, B.3, B.9): no countryName, key identifiers, critical key usage, issuer contact or CRL
  distribution point, and a critical basicConstraints on end-entity certificates. tools/dev_pki.py now makes every
  certificate in those profiles and an IACA CRL (next update within 30 days), which run.py serves on the suite's
  network, as application/pkix-crl, at the point the document signer names. cunho itself does not yet check an
  operator's document signer against Annex B: that is for piece M.
- The suite expects the mdocs of a batch to carry the same data elements; cunho gives each its own document_number
  (the attestation's unique identifier, EAA-6.2.3-01, drawn at random), so batch copies cannot be linked by it. It is
  listed in expected-failures.json with that reason; the subject's elements are the same in every copy.

### First and second looks at 427c617 (piece L)

Both clean. Mutation over ResponseKey.from_params, the one function of cunho piece L changed: 37/37 killed. Piece L is
closed.

## Piece M: integration, hardening and docs

### The certificate profiles of ISO/IEC 18013-5 Annex B

The OIDF suite's mdoc plans (piece L) check the IACA, the document signer and the status list signer against the
profiles of Annex B, as strict mdoc readers do, and cunho started with any certificate that had the mdoc purpose.
`cunho/annex_b.py` now lists what does not fit Table B.1 (IACA), B.3 (document signer, and its binding to the IACA:
authority key identifier, countryName) and B.9 (status list signer); when an mdoc configuration is published,
production refuses to start with anything listed, and a development run warns. The test PKI's IACA, document signer
and status signer are made in those profiles (`annex_b=True` in tests/engine/helpers.py); tests name each
departure, and production refuses certificates outside them. MM1 to MM14 patch what the generator does not reach.

Production already refused to start without the other M4 items: an HSM or KMS key for every signer, a PID provider
publishing the PID in both formats, x5u for mdoc PIDs and qualified providers, mdoc_trust_anchors, the wallet
providers' status list anchors that revocation chaining reads, and the clock watch; the chaining job runs in every
worker's maintenance loop under a lease, every chain_interval (10 minutes to a day).

### First look at 8cd917e (piece M)

- The IACA was looked for among the certificates the chain sends as well as the trust anchors, so a document signer
  under an intermediate, itself under a configured root, passed with the intermediate taken for its IACA. Annex B
  has the IACA, the reader's trust anchor, sign the document signer itself: it is now looked for among
  mdoc_trust_anchors alone. A test refuses such a chain in production.

### Second and third looks at a6d4feb (piece M)

Both clean.

### Mutation at 8cd917e (piece M, the Annex B check)

`_check_annex_b` 7/7. Seven survivors, each now killed by a test: a certificate without its authority key
identifier; an IACA without basicConstraints, with them not critical, or not a CA; a critical extended key usage
without id-mdl-kp-mdlDS; and MM11, a status list signer outside Table B.9 stopping production. One condition, an
isinstance the type of the extension always met, is gone rather than listed as equivalent. MM8 repointed.

### Rerun at d47fc99 (piece M, the Annex B check)

`_check_annex_b` 7/7, MM 14/14, `annex_b.py` 40/41: dropping `not constraints.ca` survived, since a certificate that
is no CA has no path length (RFC 5280 §4.2.1.9; cryptography refuses to read one that has), so the path length test
already names it. The condition is gone, with that reason beside the test; MM8 repointed.

### The slow model test for M4

The model test (tests/slow/test_model.py), four worker processes on one SQLite file or one Postgres database, now
also runs: offers of an mdoc attestation (the IBAN mdoc, its validity and status entry read from the MSO); logins the
operator holds for review, decided at /admin/deferred and collected at the deferred endpoint with whatever token the
wallet holds then; one rule that takes a held issuance from login to a collected credential, so every run sees one;
notifications, and a stranger's token refused one; a wallet provider revoking one wallet's key attestations (each
wallet now has an entry of its own on the list), which refuses that wallet's next requests; and the chaining job,
from the background loop or from maintenance, which also runs it. New invariants: no held issuance outlives its
subject's closing; a chaining run due by cunho's own record runs when there are live credentials to watch, and
revokes exactly those whose key attestation was revoked, and none while the list of wallet providers is not
trusted. Wallet attestation revocation by chaining stays with the engine tests (test_chaining.py).

Building it found nothing wrong in cunho; it did correct the model twice: maintenance runs the chaining job too, and
a refused issuance answers credential_request_denied each time it is asked, as the README says. The slow suite
passes on SQLite and Postgres (150 examples each).

DESIGN: M3 marked done, M4 described as it stands, the rest of clause 6 and revocation chaining no longer called
future work, and the anchor signed off the database host no longer promised for M4, which does not plan it.

### Stress suites 2 and 3 for M4

Suite 2 (races, four workers): a released issuance collected N times at once gives one credential and
invalid_transaction_id to the rest; N decisions on one held issuance take one; collections racing the subject's
erasure give no 5xx and nothing once the erasure has answered; one notification sent N times is 204 each time; one
c_nonce in N encrypted requests gives one credential. Suite 3 (fuzz): cunho's JWE request decryption over arbitrary
text and five-part tokens with arbitrary headers, credential_response_encryption parameters, mdoc subject data
against the IBAN mdoc configuration in process; the deferred and notification endpoints and application/jwt bodies
at the credential endpoint over HTTP. The stress server offers encryption (CUNHO_ENCRYPTION_KEYS).

One older check of suite 2 had gone stale in M3: it took the same request_uri at /authorize to start exactly one
login, but since M3 a request_uri starts up to MAX_OPENS (8) logins until one completes (FAPI 2.0 SP §5.3.2.2 note
3). It failed against M3 too; it now expects that limit, counted across workers. Both suites pass, quick and full.

### Full mutation over M4 (piece M)

Every mode over the whole engine at the end of M4: 3,902 site, condition and patch mutants, then the 76 rules.
Three survived, each a gap in the tests, none in cunho:

- A pre-authorized token request with the attestation proof of possession but no attestation was tested only the
  other way round (attestation without its proof). With the check on the proof header gone, such a request went
  through as anonymous. It is now sent and must be refused with invalid_client (WIA.REQUIRED_AT_PAR_AND_TOKEN).
- chain_revoke_after_days was tested with 0 and True only, so neither the whole-number check nor the boundary
  was held: 1.5 and "2" are now refused, and 1 day is accepted.

Everything else was killed, the rules included.

### The slow model and a held issuance's end (second reviewer)

A held issuance lasts deferred_ttl but never past the refresh token of its login (_defer). The model did not know
it: after two days had passed twice it still expected the operator's list to show the hold, a false failure on
right behaviour that random runs reach only rarely. The model now records when each hold ends, from the same
inputs cunho uses, and treats a hold past its end as dropped, for the operator and for the wallet. A new rule
reaches that end on every run: a released issuance, a refresh just before the refresh token expires, then the
hold gone from the list and invalid_transaction_id for the wallet, whose access token still works.

### M4 joins the finished milestones

With M4 moved from building to finished, the meta-test asks every M4 rule for code and a test. Three had neither:

- STATUS.SHORTLIVED_OR_LIST (ARF VCR_01, VCR_01b): cunho gives every credential a status list entry, in both
  formats, however short it lives, so the rule held without being claimed. The issuance code now claims it, and a
  test issues a one-day mdoc and a one-day SD-JWT VC and finds a status entry in each.
- TS3.CONFORMANCE (ARF WUA_36, comply with TS3): the attestation checks claim it, and a test holds every finished
  rule from a TS3 row to its covers or obligation test, then serves a wallet that sends both TS3 attestations.
  KA.REPLAY_DETECTION, the one TS3 row on the wallet's side, stays a context rule.
- STATUS.MDOC_ID_UNIQUE_PER_MSO is not applicable, as the plan said: it is about the identifier of an identifier
  list, which cunho never issues. The binder now has a not-applicable list with the reason, and the registry carries
  it; a test checks that it is the only one and that its reason is there.

The note on META.EDP_BY_VALUE no longer promises M4: it stays partial until a metadata member for an embedded
disclosure policy is standardised. The stress suites can run on PostgreSQL (CUNHO_STRESS_STORE_URL).

### Stress suites 2 and 3 on PostgreSQL

With CUNHO_STRESS_STORE_URL the stress servers use a PostgreSQL database instead of a SQLite file, with the secret
key and the audit anchor outside it, as cunho asks there (one pair per database). On a throwaway local cluster,
suite 3 passed (35/35) and suite 2 passed 22/22 in four full runs, two of them beside a full test run.

The first full run of suite 2 had one failure: in the scenario where a released issuance is collected 50 times at
once, one request got no answer within the client's 30 seconds. The other 21 checks passed, and the audit chain
verified. It did not come back: the scenario alone, four rounds of 50, takes under a second each, with exactly one
credential and invalid_transaction_id for the rest. At the time, stress servers left from an earlier, failed start
were still running on the machine, beside the second reviewer's own test run. The cause is not known. So that the
next one shows where its time went, suite 2 now records how long each scenario took, and every suite exits non-zero
when a check fails (the runner already read their JSON; a suite run alone used to exit 0 either way).

## M4 done (2026-11-10)

What section 7 of the plan asks, checked at 995bbfb:

1. Every M4 rule has code and a covers or obligation test (the meta-test now counts M4 as finished), but
   STATUS.MDOC_ID_UNIQUE_PER_MSO, marked not applicable with its reason. The partials left are two, each with its
   reason: FMT.ETSI_119472_1 (x5chain, where ISO/IEC 18013-5 and CB-AdES disagree) and META.EDP_BY_VALUE (no
   metadata member is standardised).
2. Mutation over the whole engine, rules, sites, conditions and the 541 hand-written patches: three survivors, all
   test gaps, now killed; none listed as equivalent.
3. The slow suites pass on SQLite and Postgres (8 passed). Stress suites 2 and 3 pass on both stores.
4. The probe passes against a local cunho, every M3 and M4 check.
5. OIDF, run locally with tools/oidf/run.py: the HAIP plan for mdoc, plain and encrypted (64 modules each, one
   failure each, the batch document_number); the OpenID4VCI plan for SD-JWT VC (21 modules, every failure listed);
   the HAIP plan for SD-JWT VC, plain and encrypted (64 modules each, no failure). Every failure and warning is in
   tools/oidf/expected-failures.json with its reason.
6. The second reviewer found nothing in two looks in a row at 995bbfb.
7. The README and DESIGN say what the code does; production refuses to start without the HSM or KMS key, the mdoc
   trust anchors and Annex B profiles, the status list anchors and the other M4 settings it needs.
