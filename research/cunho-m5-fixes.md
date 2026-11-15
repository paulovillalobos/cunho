# cunho M5: fixes for the reviews

What the second reviewer found in the M5 pieces, and what changed. Tests live in tests/engine; each one fails on the
code the review read.

## Reads for an operator's own pages (piece A)

A demo page that shows a QR code has to say when the wallet has the credential, and a login service has to show
the person what they are agreeing to before it reports the login. Both are things any operator's front end needs,
so they are two operator-only reads in the engine, built from what cunho keeps anyway, and the demo talks to cunho
through them as any operator's code would.

- `GET /admin/offers/{subject_ref}`: the subject's `state` (`offered`, `redeemed`, `issued`, `closed`, `expired`),
  until when a token can be got (`expires`), and each configuration's state (`pending`, `issued`, or `held`,
  `released`, `refused` while a review is open) with the newest event the wallet reported for it. Three small rows
  carry what cunho did not keep before: the configurations the subject is for (`subject-configs`), the moment a
  token can no longer be got (`subject-offer`: the offer's end; for a login, the login's end, then the code's) and
  that a wallet got a token (`subject-token`); and one per configuration for the newest notification event
  (`subject-event`), written only when an event is new, so a repeat of an older event does not hide a newer one.
  The answer is read under the store's write lock, so it is one moment's state.
- `GET /admin/logins/{login_state}`: the configurations a pending login is for, the wallet solution (`client`, and
  `wallet_name` and `wallet_version` from its attestation, which the pushed request now keeps) and the login's end.

Neither answer carries the subject data, a code, a token, a transaction_id or the person handle (tests check the
PID's values and the transaction references are absent). `complete_login` already answered with the
`subject_ref`.

The mutation tool's automatic modes see only the two refusals of these reads, so the state logic has hand-written
mutants of its own (`P5A*` in tools/mutation/patches.py). The subject window moved into `Settings.subject_window`
so the token module can use it too; the hand-written mutant F13 follows it to settings.py.

### First look at 7b5bbc9

| Finding | What changed | Test |
|---|---|---|
| P2: completion was judged against `subject-open`, which lives only an offer and a token's life; after it expired, one configuration of two issued read as `issued` | The configurations a subject is for are kept in `subject-configs` for the subject window, as long as the other marks, and `issued` means every one of them was issued. A token request narrowed by authorization_details narrows it too, since what it left out can never be issued. A subject from before M5 falls back to what it can still yield, and is never called `issued` from its marks alone. | test_completion_is_judged_against_everything_offered, test_a_narrowed_token_is_judged_by_what_it_covers |
| P2: a login's subject read `offered` for the login's life and the code's together, so a code nobody redeemed was shown as still usable long after it ran out | The login sets the deadline to the login's end; the browser's return, which makes the code, moves it to the code's end. | test_a_code_nobody_redeemed_expires_with_it, test_a_login_the_browser_never_came_back_from_expires, test_a_code_flow_login_reads_offered_until_its_code_is_redeemed |

Mutation at 152bc42 over the P5A mutants and the reads' own refusals: two survivors, both test gaps, now killed. A
review held again after an earlier issuance (a refresh re-issues a held subject) was never shown, so hiding it
behind the issuance went unseen (test_a_review_held_after_an_earlier_issuance_shows); and the tx_code lockout past
the limit, reached only when concurrent guesses overshoot it, was never run (test_an_offer_burned_past_the_limit_reads_expired).

### Second look at 152bc42

| Finding | What changed | Test |
|---|---|---|
| P2: `subject-configs` lived a subject window from the offer or login, while a later token, issuance or notification mark lived one from its own moment; once the list expired, a subject issued in full went back to `redeemed`, then `expired` | Every later mark renews the list in its own transaction, for the same window, so the list lives as long as the newest mark. | test_a_late_token_keeps_what_the_subject_is_for, test_a_late_issuance_keeps_the_subject_issued, test_a_late_notification_keeps_what_the_subject_is_for |
| P2: a request_uri opened twice gives two logins; once one was reported, the other could no longer be (its request is spent), yet the read showed it as waiting for consent | The read answers 404 for a login whose pushed request another login already completed (`Authorization.reportable_login`). | test_a_login_whose_sibling_completed_is_not_offered_for_consent |

### Third look at cd9168b

| Finding | What changed | Test |
|---|---|---|
| P2: a refresh can ask for a configuration again, and under review each ask leaves a row of its own; the rows were read in the order of their random references, so an older refused review could hide a newer held one, and, once the newer one was collected, overwrite the issuance | Each configuration takes the newest of its issuance and its reviews. A review row keeps the moment it was made to the fraction of a second (`at`), and an issuance its own (`subject-issued`); at the same moment the review is the newer, since a review that was collected is gone. | test_a_refused_review_does_not_hide_a_later_one, test_reviews_and_issuances_within_one_second_keep_their_order |

### Fourth and fifth looks at 51e4479

Nothing found in either.

### Mutation at 51e4479 (piece A)

The P5A mutants (27), the reads' refusals and F13: every one killed but one, `reportable_login`'s guard
`par is not None`, which could not change what it answers: a login started before request_uris could be opened
again names no request, and no request is stored under an empty or missing key. The line now reads the mark under
`str(pending.get("par"))`, which no such login can match, with no guard left to drop; its mutants are all killed.
P5A15 (a repeated notification event overwrites a newer one) was first killed by an indentation error of its own
making; it now leaves valid code and is killed by a test.

### Sixth and seventh looks at 510422f

Nothing found in either. Piece A is done.

## The course certificate (piece B)

`demo/metadata/course` is the metadata directory of the demo's second cunho, an attestation provider that issues a
course certificate, the case a university or a MOOC platform such as NAU would run: an SD-JWT VC of type
`https://foaap.app/vct/course-certificate/1`, with its Type Metadata, and an mdoc twin. demo/README.md says what
each claim is and why. The PID instance needs no directory of its own: it runs on the shipped one.

The tests start a cunho on the directory, check that both configurations are published with labels in both
languages, that the SD-JWT VC's `vct#integrity` is the digest of the Type Metadata file's bytes, that every claim
comes back as given (array elements resolved through their digests), that the mdoc carries the data elements and
the ones cunho adds in `org.iso.23220.1`, that data outside the configuration or missing a mandatory claim is
refused, and that the Type Metadata describes exactly the configuration's claims, in both languages.

### First and second looks at 7501d0d (piece B)

Nothing found in either. The piece changes no engine code, so it has no mutants of its own; the full suite passes
with its tests (2385).

## A login names the offer it came from (piece A2)

A demo page that shows an authorization code offer has to know which login the wallet then starts, so that what
the person agrees to on the login screen ends up in the page that showed the QR code. Creating such an offer now
answers an `offer_ref` (the first 32 hex characters of the SHA-256 of its issuer_state), the pushed request keeps
it, and `GET /admin/logins/{login_state}` names it. Mutants P5A22 and P5A23.

Mutation at 2de741f over P5A22, P5A23 and the patches near them: all killed. Two clean looks at 2de741f.

## The demo service (piece C)

`src/cunho_demo` is the demo's own service, an operator's front end written as any operator would write one: it
talks to cunho only through the admin API, with the operator token, and holds no key and no credential. It offers
a PID (both formats) and a course certificate (SD-JWT VC or mdoc), by the pre-authorized or the authorization
code flow, for one of three fictional people; nothing a visitor sends ends up in a credential, since the API takes
only choices from a fixed menu. A session lives half an hour in memory and holds cunho's pseudonymous reference,
never personal data. The page polls the session and gets one step: waiting, signing in, connected, held, released,
refused, issued, stored, failed, deleted, revoked, closed or expired, read from piece A's progress.

What a public endpoint in front of two issuers needs: POSTs are JSON from the page's own origin (a cross-site
form cannot send JSON without a preflight, which is never answered, and a foreign Origin header is refused), 4 KiB
at most; new sessions and polls are rate-limited per client network with cunho's own limiter; a full table refuses
new sessions instead of dropping those under way, and checks before an offer is made at cunho; cunho's own error
text stays in the log; the operator token never leaves the server. Every answer carries a strict CSP (nothing
from another origin, no inline script, no framing), nosniff, no referrer, and HSTS on https. QR codes are made on
the server (segno, BSD), as SVG with a viewBox and a quiet zone of four modules.

Tests in tests/demo run the service against two cunho instances in the same process (a PID provider with the mdoc
signer, and the course provider) and a scripted wallet that scans the QR code, gets the credentials and notifies.

### First look at a2a5fad (piece C)

| Finding | What changed | Test |
|---|---|---|
| P1: an authorization code session could never learn its subject: nothing reported the login | The login and consent screens (piece E) report it and attach the subject to the session the offer belongs to, by `offer_ref`. | tests/demo/test_screens.py |
| P2: several requests could pass the check for room at once while cunho made their offers, then be refused, leaving offers made for nothing | A session takes its place in the table before cunho is asked, and gives it back when cunho refuses. | test_the_table_bounds_sessions_and_ends_them_in_order, test_an_issuer_that_refuses |
| P2: a session's end was set before cunho was asked, so sessions finishing out of order sat out of order in the table, and the purge, which stops at the first live one, missed ended ones | The end is set when the session is added, under the table's lock: every session lives the same time from then, so the table's order is the order they end in. | test_the_table_bounds_sessions_and_ends_them_in_order |

## The page, and the login and consent screens (pieces D and E)

The page (src/cunho_demo/static) is HTML, CSS and plain JavaScript, no framework, no build step, nothing from
another origin, no inline script or style, so the CSP stays `script-src 'self'`. The visitor picks the PID or the
course certificate, and in the options the flow, the format of the course certificate and a PIN. The page shows
the QR code (with the "Open in a wallet on this device" button first on a phone), the PIN, the fictional person,
how long the code works, and the steps as they happen, polling every second, slowing to three; a step that ends
badly says what happened (revoked, refused, not stored, expired). After issuance it offers the revocation, and
while an issuance is held, Release and Refuse. English and Portuguese, light and dark, reduced motion respected.

The login service of the authorization code flow is the demo service itself (src/cunho_demo/screens.py): each
cunho's `CUNHO_LOGIN_URL` points at `/login/pid` or `/login/course`. The person picks a fictional person, sees
what will be issued, to which wallet (its name from the wallet attestation, escaped like everything shown), with
the values, may ask to hold it for review, and agrees or cancels; the demo reports the login to cunho and sends
the browser on with 303. Server-rendered, without script, so they work in any wallet's browser. Each form is bound
to its issuer and login_state by an HMAC under the demo's secret key; forms from another origin or not
urlencoded are refused. A login whose wallet asks for both formats of the course certificate is refused with a
plain message: one subject cannot be an SD-JWT VC's claims and an mdoc's namespaces at once.

tools/demo_local.py runs the whole demo here (two cunho instances over TLS with the development certificate, the
demo service, and with `--view-port` a plain-http copy for a browser that does not trust that certificate), and
tools/demo_wallet.py is a scripted wallet that takes a pre-authorized offer through token, credentials and
notifications. With both, the page was checked at 375 and 1280 pixels, light and dark, in both languages, through
waiting, connected, stored and revoked for both credentials, and the login and consent screens at both widths.

### Second look at 569021a (pieces C to E)

| Finding | What changed | Test |
|---|---|---|
| P1: the CSP's `form-action 'self'` blocked the 303 from the login screens to cunho in Chromium, which checks a form's redirects too, so no code-flow login could finish in it | The screens answer a form with a short page that moves on by a refresh and a link, a new navigation that form-action does not govern; the strict CSP stays. | test_the_way_back_is_a_new_navigation_not_a_form_redirect |
| P2: a login cancelled on the screens left its session showing "signing in" | The session records the cancellation, and the page shows "sign-in cancelled". | test_a_cancelled_login_shows_on_the_page |
| P2: a login abandoned on its screen showed "signing in" until the session ended | Without a subject yet, an ended offer reads expired before anything else. A login opened on the screens keeps the page waiting for `DEMO_LOGIN_TTL` (cunho's login lifetime) from then, since cunho takes its result that long. | test_an_abandoned_login_ends_with_its_login, test_steps |

### Third look at e34aad2 (pieces C to E)

| Finding | What changed | Test |
|---|---|---|
| P2: a person chosen on the login screen other than the one the page first showed was never shown: the page kept the first name | Each progress answer carries the session's person, and the page shows it. | test_a_code_flow_offer_from_qr_code_to_issued |
| P2: an answer about a session the visitor had already left, still on its way, was drawn over the new session | The page notes which session it asked about and drops answers, and errors, about any other. | checked in the browser pane |

## The operator console (piece G)

`/operator`, off unless `DEMO_OPERATOR_PASSWORD_FILE` holds an scrypt hash (`python -m cunho_demo.console` makes
one from a password typed twice, at least 12 characters). It shows, for each issuer, whether its audit log
verifies, the issuances held for review with Release and Refuse, and a form to revoke by subject reference, and
lists the demo sessions under way. It acts through the same admin API as the page. A signed-in operator holds a
random session kept in memory for eight hours, in an HttpOnly, SameSite=Strict cookie (Secure on https); every
form carries an HMAC of that session under the demo's secret key, and forms from another origin are refused;
five wrong passwords a minute per network, then 429. Nothing but the two actions and the two kinds of reference
it knows the shape of reaches cunho.

### Fourth look at 915ef49 (pieces C to G)

| Finding | What changed | Test |
|---|---|---|
| P1: past the limit of wrong passwords the console still checked each one, so a right guess still signed in, and every check ran scrypt on the event loop | A network that reached five wrong passwords in the window is refused before any password is checked, the right one included; scrypt runs in a worker thread. | test_wrong_passwords_are_limited |
| P2: reloading the login screen, or switching its language, gave the page another full login lifetime to wait | The deadline is set at the first visit only. | test_an_abandoned_login_ends_with_its_login |

Found in the browser pane while taking the console's screenshots: under `Referrer-Policy: no-referrer` a browser
sends `Origin: null` with a form's POST, so the origin checks refused every form of the console and, in a real
browser, of the login and consent screens; the tests had set the header by hand. The policy is now `same-origin`,
which still keeps the login's URL, with its login_state, from every other site. The console then signed in and
showed both issuers' audit status, held issuances and the sessions under way.

### Fifth look at d4a1951 (pieces C to G)

| Finding | What changed | Test |
|---|---|---|
| P1: attempts sent all at once from one network all passed the check before any of them was counted, so a burst could still guess, and queue scrypt work without bound | Each attempt takes its place before its password is checked and gives it back when the password was right; at most two scrypt checks run at once, whoever asks. | test_attempts_take_their_place_before_the_password_is_checked, test_wrong_passwords_are_limited |

### Sixth look at 7d888d4 (pieces C to G)

| Finding | What changed | Test |
|---|---|---|
| P2: the table of networks with failed sign-ins could grow past its bound when every place held a live window, rebuilt on every new network | When it is still full after expired windows are dropped, a new network is refused until a window ends. | test_the_table_of_networks_stays_bounded |
| P2: a subject revoked from the console showed as "closed" on the visitor's page, not "revoked" | The console marks the sessions of that subject revoked, as the page's own revocation does. | test_revoking_from_the_console |

Seventh and eighth looks at baf80a5 (pieces C to G): nothing found in either.

## The container kit (piece H)

deploy/ holds one image for the three services (python 3.13-slim and caddy 2.10.2 pinned by digest; a build stage
for the wheels; SoftHSM2; an unprivileged user), compose.yaml and the Caddyfile; tools/deploy_init.py prepares the
secrets once; docs/DEMO.md says how to run it here, on a server, and what to renew every month. Each cunho signs
through PKCS#11 with keys imported into a SoftHSM token of its own and deleted from disk.

Found while bringing it up here (colima, compose from the docker CLI image): dev_pki.py imports the tests' PKI
builder, which the image now carries; a first run cut short left a PKI and a token half made, which the next run
took as done, so the PKI is made aside and renamed into place and a token that fails to fill is deleted; the
credential signer must name the issuers' host, which init now passes to dev_pki; Caddy refuses an empty `email`,
and runs `respond` before `reverse_proxy` whatever the order in the file, so the catch-all 404 answered everything
until the routes became exclusive `handle` blocks. Then, through Caddy at issuer.localhost and demo.localhost: the
metadata of both issuers, 404 for the operator API from outside, the Type Metadata at its vct path, and a PID in
both formats with a PIN, issued to tools/demo_wallet.py and followed by the page's API to "stored".

### First look at 241111d (piece H)

| Finding | What changed | Test |
|---|---|---|
| P2: with `DEMO_PUBLIC_URL` set to another site, as docs/DEMO.md says to, the issuers still sent the browser to login screens on `DEMO_HOST`, whose forms the demo then refused as coming from another origin | Both `CUNHO_LOGIN_URL` follow `DEMO_PUBLIC_URL` when it is set. | compose config |
| P2: a token made but not filled when init was killed (no handler runs then) was taken as done, so the issuer could never start | A token counts as filled only with its PIN file, written last; one without is deleted and made again, the keys being still on disk until every token is filled. | a token made by hand without a PIN, then init: both tokens made, the stack starts |

## The probe and the OIDF suite on the course certificate (piece J)

`tools/probe_local.py --course` runs the probe against the course provider: every check against the SD-JWT VC,
the mdoc checks and C16 against the mdoc in a run of its own (one subject cannot be both), and the code-flow
offer. Every M3 and M4 check passes but W10, which skips: the course certificate asks for no key attestation, so
there is no untrusted one to refuse. The PID run passes as before. `tools/dev_offer.py --course [--mdoc]` makes the
offers, and `tools/oidf/run.py --course` runs the suite's plans with the course certificate's configurations as the
demo publishes them, in place of the run's own.

### Second look at 4ab7644 (pieces H and J)

| Finding | What changed | Test |
|---|---|---|
| P2: the mdoc document signer of the deployed demo named the conformance suite's CRL address, which nothing serves there, so a wallet that checks revocation could not accept its mdocs | dev_pki.py takes the CRL address from `DEV_PKI_CRL_URL`; init sets it to `https://ISSUER_HOST/crl/iaca.crl`, copies the CRL into a volume of its own, and Caddy serves it there; the monthly renewal refreshes it. | the signer names `https://issuer.localhost:8443/crl/iaca.crl`; init writes the CRL to the public volume |

Third look at 2c94085 (pieces H and J): nothing found.

## Mutation of the demo service (piece K)

`tools/mutation/demo_mutate.py` runs the hand-written mutants of `tools/mutation/demo_patches.py` (60: the page's
API, the session table, the steps, the login and consent screens, the console and the settings), each on a scratch
copy, and expects `tests/demo` to fail. Three survived the first run, all test gaps, now killed: a QR code without
its quiet zone (test_the_qr_code_keeps_its_quiet_zone, against segno's own symbol size), a consent form sent as
text/plain, and a consent for a person who is not in the demo (both in test_forms_from_elsewhere_are_refused).

Fourth look at b82cbf3 (pieces H to K): nothing found.

### The wallet-initiated flow through the demo's screens, over the network

The probe's code-flow checks (group `authorization`) ran against the PID issuer of `tools/demo_local.py`, through
the demo's own login and consent screens over TLS (`--login-field persona=ana --login-field action=issue
--cancel-field action=cancel`): every check passed but A05 and A20, which skip as they always do without a second
wallet solution and an offer. For that, the probe's browser walk now follows a page that moves on by itself
(`<meta http-equiv="refresh">`), as browsers do and as the screens answer a form
(test_the_browser_walk_follows_a_page_that_moves_on_by_itself).

### The OIDF plans on the course certificate

`tools/oidf/run.py --course`, the four HAIP plans: both mdoc plans passed with only the failures already listed. In
both SD-JWT VC plans the one unexpected failure was the suite fetching the Type Metadata of an https vct (SD-JWT VC
§6.3) from foaap.app, where nothing is published yet. The runner now serves the file, byte for byte, at the vct's
URL under that host's name on the suite's own network, as it serves the IACA's CRL.

## The milestone's own looks

### First look at 951e46a (all of M5, from e6c03a7)

| Finding | What changed | Test |
|---|---|---|
| P1: the demo's tests import segno, which ci.yml did not install, so the fast job would fail to collect them | The fast job installs segno and runs the demo's mutants after the tests. | ci.yml |
| P2: with `--view-port`, tools/demo_local.py ran a second demo process with sessions of its own, so a code-flow login, which cunho sends to the TLS one, never reached the page opened over http | One process listens on both ports, and takes forms and JSON from both origins (`DEMO_EXTRA_ORIGINS`, which also lets one service answer to a second name). | test_a_second_origin_of_the_same_service, test_extra_origins_from_the_environment; a session made over http read over https on a running stack |

The demo's 60 mutants run again after the change: all killed.

### Second look at d5068eb (all of M5): nothing found.

### Third look at cb589f7 (all of M5)

| Finding | What changed | Test |
|---|---|---|
| P2: the course certificate's vct names foaap.app, but the stack answers its Type Metadata on `DEMO_HOST`, and the rewrite docs/DEMO.md asked of the front site left `/vct` out, so wallets could not fetch it | docs/DEMO.md: the front site rewrites `/vct/*` too, or serves the file itself; Caddy's answer is enough when `DEMO_HOST` is foaap.app; a demo under another domain changes the vct in both files of demo/metadata/course. | docs only |

### Fourth and fifth looks at 0816de6 (all of M5): nothing found.

## The full mutation run at the end of M5

`tools/mutation/mutate.py --all` (sites and conditions, with the hand-written patches) over the engine at 0816de6:
3935 of 3940 mutants killed, 4 listed as equivalent, one survivor, a test gap in code from before M5. A wallet
providers list whose SchemeOperatorName was a string or an object instead of a sequence was still refused, but
only by the check of each item further on, so dropping `not isinstance(value, list)` in `lote._texts` changed
nothing the tests saw. Two cases of test_a_list_cunho_cannot_take_anchors_from_is_refused now give it a string and
an object; the ten mutants of `_texts` run again, all killed. Rules mode (`mutate.py`): 76 of 76 killed.

The slow suites (`pytest -m slow tests/slow`) on the same code: 8 of 8 passed, the model test on SQLite and on
Postgres.

### Sixth and seventh looks at 1badce2 (all of M5): nothing found.

M5 is done locally: every piece and the whole milestone reviewed to two clean looks in a row, the engine's
mutants, its rules and the demo's mutants all killed, the slow suites green. What is left needs the demo online:
a real wallet from the EU's reference apps scanning the page's QR code.

## The page, redesigned (after M5 was done locally)

The first page worked but read like a tool for developers: dark, dense, every option and the protocol's steps on
the first screen. It is now built around the credentials as cards, the way a wallet shows them: a light page, the
PID and the course certificate as two cards to pick from, the fields each holds, the options as switches, and
the offer in a panel beside them, where the QR code gives way to the credential's card, filled with the
fictional person's data, and to the steps as the wallet goes through them. The protocol's steps moved under
"How it works". The login, consent and console screens share the stylesheet and changed with it.

- The session's answers carry the card's face: [claim, value] for a few fields of the person it is for, the
  same data the offer holds (offers.CARD, offers.card), so a code-flow login that picks another person changes
  the card too (test_a_pid_from_qr_code_to_stored, the Eleni case in test_screens).
- The page's files are served with `Cache-Control: no-cache`: without it, browsers kept the old script and
  stylesheet beside the new page (seen in the browser pane), which after a release would break the page.
- `tools/demo_local.py --view-port` takes requests named 127.0.0.1 as well as localhost: the page refused every
  request when opened at 127.0.0.1, where it listens.

Three new demo mutants (A23 the card shows another person, A24 no `no-cache`, O9 a card with every field): 63
of 63 killed. Screenshots at 375 and 1280 px, light and dark, English and Portuguese, through waiting,
connected, stored and revoked, with a PIN and with the course certificate.

### Every control of the page, clicked (Paulo: "none of the buttons work")

The redesign locked the choices while an offer was open, without showing it, and kept "Start again" at the foot
of the offer panel: a visitor who clicked a card or an option after making an offer saw nothing happen. Now any
change of a choice leaves the open offer (it expires on its own) and the page is ready to make a new one. On a
computer with no wallet app, "Open in a wallet on this device" does nothing, which a browser cannot detect: it
now says it opens a wallet app if one is installed, and a "Copy offer link" button sits under it. The tab's title
follows the language. Each control clicked in the browser: both cards, both flows, both formats, the PIN switch,
Create offer, Copy offer link, a card changed with an offer open, Start again, the language, How it works.

Looks 3 and 4 at 455e6a2 (the redesign and the controls, from 769dcbd): nothing found.
