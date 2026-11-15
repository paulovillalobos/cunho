# The demo's whole flow: fixes log

Branch `demo-flow`, from `m5` at 1811145. What changed after M5 so that a visitor sees an issuance through to
the end, whatever they scan with, and what each look by the second reviewer found.

## Why

Scanned with a phone's camera, the page's QR code gave "No usable data found": it held an
`openid-credential-offer://` link, which only a wallet app reads, and most visitors have no wallet that takes an
issuer it does not know (the EU reference wallet takes only the issuers built into it). The demo stopped at
"Waiting for your wallet".

## What the demo does now

- **The demo wallet** (`src/cunho_demo/wallet.py`). "No wallet? Try it with the demo wallet" hands a
  pre-authorized offer to a wallet the demo service runs: it reads the metadata, gets a DPoP-bound token (typing
  the PIN), makes a holder key per credential, has it attested by a wallet provider's key-attestation signer,
  proves possession on the issuer's nonce, takes each credential and notifies the issuer. It then checks what it
  got, and the page shows it under "Inside the credential": the signature with the certificate the credential
  carries (and that each certificate of the chain signs the one below), every disclosure (SD-JWT VC) or data
  element (mdoc) against the digests the issuer signed, the holder binding, the validity and the status list
  entry, and the claims. "Check the status as a verifier would" reads the status list token (its signature, its
  `sub`, its expiry) and the bits at the credential's index: Valid, then Revoked once the visitor revokes it and
  the list is published again.
- **The wallet only reaches the two issuers.** Every URL it is given must be on the public origin of the issuer
  that made the offer; it is sent to that issuer's internal address (the operator API's), while the proofs name
  the public URL as cunho checks them. Anything else is refused unsent.
- **No code-flow offers, no held issuances.** cunho refuses `review` on a pre-authorized offer (a held one could
  never be collected without a refresh token), so the demo wallet takes pre-authorized offers only, and a 202
  ends its run as a refusal.
- **Offers by reference** (`credential_offer_uri`, OpenID4VCI 1.0 section 4.1.3): the demo serves each offer at
  `/offers/{reference}` while it can be used, so the wallet app's QR code is a short link instead of the whole
  offer.
- **The phone page.** The phone camera's QR code is `https://<demo>/o/{reference}`: the page opens on the phone
  with the offer's card, "Open in a wallet on this device", and the demo wallet. The reference gives the offer,
  its progress, the demo wallet and the status check, never the session id (which acts on the session) or the
  PIN (which the QR code must not give whoever scans it): the visitor types the PIN on the phone, and cunho checks
  it as it checks a wallet's.
- The page explains which QR code to use for what, and lists no wallet it has not been tested with.

## Checks

- tests/demo/test_wallet.py: the demo wallet takes a PID (both formats) and a course certificate (mdoc, with the
  PIN) from offer to stored against two cunho instances in the process; a second run of the same offer is
  refused; a refused run can be tried again; code-flow offers and a demo without a key-attestation signer are
  refused; a revocation reads Valid then Revoked on the status list; the offer by reference equals the offer by
  value and ends with the offer; the phone page carries neither the session id nor the PIN, refuses to start
  without the PIN, fails on a wrong PIN and succeeds on the right one; a changed signature, an extra disclosure
  and a changed mdoc element are seen; a status list signed by another key reads unknown; the wallet never asks a
  host other than the issuer's internal address.
- The page in the browser pane, against tools/demo_local.py on its own ports (8200 to 8202, page on 8299): the
  demo wallet through to stored, the credentials inside, the status Valid, revoked, then Revoked about a minute
  later; the phone page at phone width with a PIN typed; tools/demo_wallet.py with a by-reference link.
- Demo mutants (`tools/mutation/demo_mutate.py`): 80, with 20 new ones for the demo wallet, the offer by
  reference and the phone page. The first run left two survivors, both test gaps: a forged status list was also
  malformed, so it read unknown without the signature check (the test now forges a well-formed list, and checks a
  list naming another list and one past its expiry), and nothing refused a credential request (a scripted issuer
  now does, and the run must end as a refusal with no notification sent). The wallet's mutants run again: all
  killed.
- Gates: ruff, ruff format, mypy, the full suite (2485 passed).

## The second reviewer's looks

### First and second looks at 5dbf3c3 (from 1811145)

| Finding | What changed | Test |
|---|---|---|
| P2: every poll rebuilt "Inside the credential", so a credential opened to read closed again every ten seconds | The section is rebuilt only when what it shows changes (the credentials, the time of the last status check, the language). | in the browser pane |
| P2: "Bound to a key only the wallet holds" only checked that the credential named some key | The SD-JWT VC's `cnf.jwk` and the mdoc's device key (COSE_Key, P-256) must be the very key the wallet made for that credential. | test_a_changed_signature_or_claim_is_seen (a stranger's key reads unbound) |
| P2: a run that failed after the token (at the notification, say) could be started again, which threw away what it had been issued and then failed on the spent code | A failed run is started again only if it never redeemed the offer; the view says whether it can be (`retry`), and the page offers the button only then. | test_a_run_that_redeemed_the_offer_is_not_started_again |

Mutants for the three fixes (W9, W10, A33) and the two whose guard moved (A29, A30): all killed; 83 in all.

## Simple and Advanced (Paulo: "it should be simple: name, age, place, issuer")

The page opens in **Simple**: the two credentials, one button, the QR code a phone's camera reads, "Open in a
wallet" and the demo wallet, the four steps, and then what the wallet received as anyone reads it: the name, the
age (from the birth date), the place of birth and who issued it (for the course certificate: the course, the
grade and the course provider), one line saying the issuer's signature and every claim checked, and the status
after "Check its status". Simple makes every offer with the defaults (straight away, no PIN, the course
certificate as SD-JWT VC). **Advanced**, one switch away in the top bar, is everything else: the flow, the format
and the PIN, both QR codes, the copy link and the phone page here, the demo wallet's steps, and "Inside the
credential" with each check and the credential as issued. The choice is kept in the browser (localStorage), and
the page works the same without it. A place is written from the town to the country ("Porto, PT").

Checked in the browser pane at 1280 and 375 px: Simple through to the result and the status, then Advanced on
the same offer. The wallet's mutants run again after the change to how a place is written: all killed.

### Third and fourth looks at 389f987 (from 1811145)

Third: nothing found. Fourth:

| Finding | What changed | Test |
|---|---|---|
| P2: in Simple, a failed demo wallet's error stayed on the page after "Start again" and a new offer | Leaving an offer clears it, and a view with no wallet run hides it. | in the browser pane: an error left on the page is gone on the next offer |

### Fifth and sixth looks at efb90c0 (from 1811145)

Sixth: nothing found. Fifth:

| Finding | What changed | Test |
|---|---|---|
| P2: with `CUNHO_DPOP_SERVER_NONCE` the issuer challenges the first DPoP proof with `use_dpop_nonce`, which ended the demo wallet's run | Every DPoP request answers a challenge once with the nonce given (in the body at the token endpoint, in WWW-Authenticate at a resource) and keeps the latest nonce for the next. | test_the_demo_wallet_answers_the_issuers_dpop_nonce; mutant W11 |

## The phone on the same Wi-Fi

Scanned with a phone, the phone camera's QR code named `https://localhost:...`, which on a phone is the phone. A
local run can now be reached from a phone on the same Wi-Fi: `tools/demo_local.py --lan ADDRESS` serves the page's
port on this machine's private address too and makes the QR codes point there. The demo allows plain http for a
private address as it did for localhost, and still refuses it for any other (test_settings_refuse_what_would_be_unsafe
with a public IP). Checked over the Wi-Fi address: the phone page, the demo wallet started from it, both formats
stored.

### Seventh and eighth looks at d0952cd (all of demo-flow, from 1811145): nothing found.

## The phone page as a wallet (Paulo: "it should open the wallet and show the credential")

Under the ARF it is the wallet that shows an offer: who issues it, which credential, which attributes, and asks
the person to accept before it stores anything. A phone with an EUDI wallet app does that when it is handed the
offer (the "Wallet app" QR code, or "Open in a wallet on this device"). For a phone without one, the phone page
now behaves the same way with the demo wallet: "FOAAP demo issuer wants to add this credential to your wallet",
the credential and its attributes, **Add to wallet** or **Decline**. Declining issues nothing and can be undone
before the offer ends; adding runs the issuance and ends on the card "In your wallet" with the name, age, place
and issuer and the genuine check. Nothing is shown as under way (steps, card, "Start again") before the person
accepts. A link still opens the offer in a real wallet app on the phone. Checked at phone width: decline, show
again, add, through to the card in the wallet.

### Ninth and tenth looks at 7a814c6 (from 1811145)

| Finding | What changed | Test |
|---|---|---|
| P1 (both looks): with no demo wallet for the offer (a code-flow offer, or a demo without a key-attestation signer) the phone page hid every link to a real wallet | The page's own "Open in a wallet on this device" stays whenever the consent screen (which carries its own link) is not shown. | in the browser pane: a code-flow offer's phone page shows the link and the steps |
| P2: an offer taken by a real wallet left the phone page's progress hidden, since only the demo wallet's acceptance showed it | The consent screen shows only while the offer waits for a wallet; as soon as the issuer reports progress, from any wallet, the page shows it. | in the browser pane: an offer taken by tools/demo_wallet.py reaches "Done" on the open phone page |

### Eleventh and twelfth looks at f2ccec0 (all of demo-flow, from 1811145): nothing found.

### Thirteenth and fourteenth looks at 3d15e32 (the fictional people made Portuguese): nothing found.

## The phone page drawn as a wallet (Paulo: "clean white, look at the cards")

Taking the structure of a wallet's credential screen, not anyone's branding (no EU emblem): the phone page is now
always white and shows one large card (the credential's colour, the demo's seal), who offers it, an **Info**
section (the credential, the issuer, then the person's attributes; once stored also the date of issuance, the
validity and the age), a **History** section (offer received, declined, added to the wallet, status checked,
revoked by the issuer, with the time), and pill buttons: Add to wallet and Decline. Adding shows "Adding to your
wallet…", then a toast "Added to your wallet", the heading "In your wallet", the genuine check and "Check its
status". With no demo wallet for the offer, "Open in my wallet app" leads; progress from a real wallet shows as
it comes. Checked at phone width in English and Portuguese: offer, add, the toast, the status, the history.

### Fifteenth and sixteenth looks at d037ca3 (from 1811145)

| Finding | What changed | Test |
|---|---|---|
| P2 (both looks): the phone page's History list was named `history`, which hid `window.history` from the language switch: switching language threw on both pages | Renamed (`happened`). | in the browser pane: the language switches with no error |
| P2 (both): the phone page hid the request errors (`#issue-error`): an ended reference opened an empty page, an empty PIN or a failed status check said nothing | Those errors show in the wallet screen; an ended reference shows only its message. | in the browser pane: an unknown reference says the offer has ended |
| P2 (both): when a real wallet app stored the credential, the phone page went on showing the offer | It says "In your wallet app" and History records it, without suggesting the demo wallet holds it. | in the browser pane: an offer taken by tools/demo_wallet.py |

### Seventeenth and eighteenth looks at 39a86b4 (all of demo-flow, from 1811145): nothing found.

## The card (Paulo: "all black, only the coin; when it is verified the lines appear")

The phone page's card is now drawn by `static/card.js`: a black card with a coin in the middle (the twelve EU stars
around the arms of Portugal for the PID; around a laurel wreath and an open book for the course certificate), the
person's name as the largest line, FOAAP and "Demo issuer" smaller, and the rest in one small grey size (the
credential, the country or the credits and level, the validity or the course, the formats or the grade). When the
wallet has found the credential genuine, the coin flares, light sweeps across and the lines of a nautical chart
draw out from the coin to the edges, and stay; a revoked credential loses them. With reduced motion the lines simply
appear. A line too long for its place is made smaller until it fits.

New files, all served by the demo itself: `card.js`; `arms.svg` (the arms from Flag_of_Portugal.svg on Wikimedia
Commons, public domain, recoloured black and white); `fonts.css` and `fonts/SpaceGrotesk.ttf` with its `OFL.txt`
(SIL Open Font License 1.1). NOTICE names both. test_page checks they are served with no-cache, that the only url()
in a stylesheet is the font's own path, and that the arms carry no script and name nothing elsewhere.

Checked at phone width (390 px) in a separate headless Chrome, English and Portuguese: the offer (plain black card),
"Add to wallet" (the flare and the lines), the stored PID and course certificate. The mutant T1 followed the code it
patches (settings.py's private-address check), and is killed.

### Nineteenth and twentieth looks at b3ad2a1 (from b6593af)

| Finding | What changed | Test |
|---|---|---|
| P2 (both looks): when a real wallet app stored the PID, the card still said "Not yet in your wallet" under the heading "In your wallet app" | The card says "In your wallet app" then (without the chart lines, which mean the demo wallet checked it). | in a headless Chrome: an offer taken by tools/demo_wallet.py while its phone page is open |

### Twenty-first and twenty-second looks at f24041f (from b6593af): nothing found.

## The main page (Paulo: "pure black, the white and the buttons of Revolut, the AIP type, the real FOAAP logo")

The main page is now black (#000) with white text, Space Grotesk for its headings and the system sans for the rest,
and two kinds of buttons only: a white pill for the step forward, outlined white pills for everything else (the
choice of credential, Simple and Advanced, the scan switch, the language). The FOAAP "F" (redrawn from the company's
logo, measured from it) is the mark in the top bar and the tab's icon. In place of two coloured cards and an empty QR
panel, the right of the page is the black card itself: it shows the credential chosen (the arms or the laurel), turns
over to its QR code when the offer is made, and turns back once a wallet has taken it; with the demo wallet it then
flares and draws its chart lines, as on the phone. Under it, the steps are a line of dots, then the status and, while
the offer waits, the demo wallet and "Open in a wallet on this device". On a phone the card comes first. Advanced
keeps every option and check, restyled. The phone page keeps its white wallet screen, with the logo and without the
coloured demo badge.

Fixed on the way: card.js's phone-page function shared its name with the main page's renderCard, so every poll drew
the card from the session (a course offer read as a PID) and could replay the glow; the two are now one cardFace()
used by both pages, and each card names its SVG definitions apart. Checked in a separate headless Chrome: the
course card stays verified through thirty seconds of polls.

Checked at 1280 px and 390 px, English and Portuguese, Simple and Advanced: the choice, the card turned over to the
QR code, the demo wallet through to stored, the course certificate; the phone page with both credentials.

### Twenty-third and twenty-fourth looks at 4198886 (from 590ef64)

| Finding | What changed | Test |
|---|---|---|
| P2: the session's polled view carries no `credential` or `format`, so a course offer's card turned into a PID card after the first poll | The card reads what was offered from the offer itself (`withOffer`), and only the progress from each view. | in a headless Chrome: a course offer stays a course card after polls, and through the demo wallet to stored |
| P2: on narrow screens in Advanced the card's back (scan switch, hint, PIN, expiry) could not grow and ran over the steps | Both sides share one grid cell; the back, once turned to, grows with what it holds, stacked on phones, and the cell keeps to the card's width. | at 390 px in Portuguese, with a PIN and "Wallet app": no overlap, no sideways scroll |

### Twenty-fifth and twenty-sixth looks at 695f24d (from 590ef64): nothing found.

## The page said what it was about, not what a visitor could do (13 November 2026)

A reading of the live page by someone who does not work on wallets: it looked right, but it asked a visitor to
understand too much before trying anything. "Create offer" is the issuer's word; the first instruction was to scan
with a phone, before saying that nothing had to be installed; Simple named OpenID4VCI, SD-JWT VC and mdoc; the grey
small print, the demo notice among it, was hard to read on black, though the card carries the country's arms; and
after the demo wallet the page said "in your wallet", which a visitor could look for in an app on their phone.

What changed:

- Two buttons in place of "Create offer": **Try it now**, which makes the offer and has the demo wallet take it at
  once (the card stays face up, the first step reads "Offer made", the status "Working…"), and **Use my wallet app
  (QR code)**, the offer as before. In Advanced with "After signing in", Try it now is not there: the demo wallet
  takes only offers made straight away.
- Simple says it plainly: "Live demo · no app needed"; a new lead; the credentials without their formats; "How it
  works" as Choose, Request, Sign, Store, Check. Advanced keeps the protocol words and the formats.
- The demo notice is a framed line that starts "Demo only." and says the card is not an official document; the
  card's corner says "Demo · not a real ID" (the course card its grade, or "Demo · not a real certificate") where it
  showed the formats; the page's grey text is lighter.
- Stored by the demo wallet, the last step reads "In the demo wallet", and a framed answer names the person and says
  the demo wallet is one the page runs and forgets after 30 minutes, not an app on the phone, and how to get one into
  a real wallet app. Stored by a real wallet app, the page says "Stored in your wallet" as before.

Checked in a separate headless Chrome against the local stack, at 1440 px and 390 px, English and Portuguese, Simple
and Advanced: Try it now through to stored with both credentials, the QR path, Try it now hidden with sign-in, no
errors in the console. A test holds the order of the two buttons, the notice and the card's corner words.

### Twenty-seventh and twenty-eighth looks at b6395a5 (from 8e5275d)

| Finding | What changed | Test |
|---|---|---|
| P2 (both looks): while an offer was being made only the button pressed was disabled, so the other made a second offer, and the later answer took the page over | While one is being made, both buttons are disabled and a press of either does nothing. | in a headless Chrome: both buttons pressed in one go make one offer, carried to stored |
| P2 (both looks): Try it now followed the offer only once the demo wallet's start was answered, so a lost or refused answer left the page at "Working…" for good | The page follows the offer from the moment it is made, whatever the answer; if the demo wallet did not start, the offer shows as any other, with its QR code and the demo wallet's button. | in a headless Chrome: an answer lost on the way (the wallet started) still reaches "In the demo wallet"; a refused start turns the card to its QR code |

### Twenty-ninth and thirtieth looks at a6e417c (from 8e5275d): nothing found.

## Try it now shows the code; the demo wallet waits to be asked (13 November 2026)

Paulo, trying real wallet apps on the live demo: Try it now ran the whole flow by itself, so there was no QR code to
scan, and the switch to the wallet app's code was only in Advanced, where on his screen it ran past the card's edge.
Now there is one button again, Try it now, which makes the offer and turns the card over to its QR code; the demo
wallet runs only when "No wallet? Try it with the demo wallet" is pressed. Simple shows the switch between the phone
camera's code and the wallet app's, and the switch wraps rather than run past the card. The lead says both ways. The
words that say where a demo-wallet credential is stay.

Checked in a headless Chrome against the local stack at 1440, 1180 and 390 px: the card turns to its QR code, the
"Wallet app" switch is inside the card and changes the code, the demo wallet carries the offer to "In the demo
wallet", no console errors.

### Thirty-first and thirty-second looks at db90106 (from d4b99db): nothing found.

## Why a wallet app is refused: an optional log of the reason (13 November 2026)

The first real wallet apps on the live demo: Paradym took the offer and was issued the course certificate (both
formats), then failed on its side; Lissi got its token and was refused at the credential; Sphereon stopped too.
cunho keeps no access log, and an error answer goes only to the wallet, so the reason was nowhere to read.

`CUNHO_LOG_REFUSALS=1` (in the stack, `LOG_REFUSALS=1` in `deploy/.env`) logs to `cunho.refusals`, for each refused
request, the method, the route as cunho declares it (an unknown path only by the name of a known discovery document), the status, the
error code, the rule and the description, each made printable and bounded so a request cannot forge a line. Never
the address, a header, the query, a token or the body. Off by default; it is for finding out what a wallet expects,
then off again.

Tests: off by default nothing is logged; on, a refused token request and an unknown path are logged with their
route, status and error, and a query value, a DPoP header, a forwarded address and the client's own address are in
no line; control characters are replaced and a long value cut; the setting reads from the environment. The mutation
tool has no mutant on these lines (they refuse nothing); removing the guard, the call in either handler, or the
cleaning each fails one of these tests.

### Thirty-third and thirty-fourth looks at d297170 (from f72de78)

| Finding | What changed | Test |
|---|---|---|
| P2 (both looks): an unknown path's fallback read `request.url`, which decodes the query; a query that is not UTF-8 turned the 404 into a 500 inside the handler | The path is read from the scope. | an ASGI request to an unknown path with the query `\xff\xfe`: 404, and the line logged |
| P2 (one look): the error's description can repeat what the request sent (an unknown configuration id, for one) | The line has the method, the route, the status, the error code and the rule, all from cunho's own code; no description. | the description of a refused token request is in no line |

## Paradym's own words: the status list is checked against the credential's chain (13 November 2026)

With Paradym's development mode on, the failure after "Credential signed" reads: "Status List JWT verification
failed: The status list certificate chain could not be validated against the trusted status certificates …
X509ValidationError: No trusted certificate was found". In Credo (the library under Paradym), a wallet that trusts an
issuer it does not know on the chain the credential carries checks the status list against that same trust, and,
with no certificate named for status lists, asks that the status list carry exactly the credential's chain. The demo
signed its status lists with a status key of its own (production requires one; a trusted list would then name it).

The demo stack now signs status lists with the credentials' own key and chain: `CUNHO_STATUS_SIGNING_KEY` and
`CUNHO_STATUS_SIGNING_CHAIN` are no longer set in `deploy/compose.yaml`, which cunho allows outside production.
mdoc credentials are signed by the document signer, a key of their own, so for an mdoc this does not yet line up.

### Thirty-fifth and thirty-sixth looks at 52084c5 (from f72de78)

| Finding | What changed | Test |
|---|---|---|
| P2 (both looks): a path no route matched was logged as asked, and a mistyped route may carry a login state or a subject reference | Such a path is logged as "(no route)", unless it is a `/.well-known/` one, which carries nothing of anyone and tells which document a wallet looked for. | `/admin/logins/<state>/` logs "(no route)"; `/.well-known/openid-configuration` logs its path |

### Thirty-seventh and thirty-eighth looks at 7a1da38 (from f72de78)

| Finding | What changed | Test |
|---|---|---|
| P2 (one look; the other clean): any `/.well-known/` path was logged whole, and what follows the prefix may carry anything | Only a known discovery document's name is logged (`openid-credential-issuer`, `oauth-authorization-server`, `openid-configuration`, `oauth-protected-resource`, `jwt-vc-issuer`), with "/…" for whatever follows; any other path is "(no route)". | `/.well-known/jwt-vc-issuer/<state>` logs `/.well-known/jwt-vc-issuer/…`; `/.well-known/<state>` logs "(no route)" |

### Thirty-ninth and fortieth looks at 9996f39 (from f72de78): nothing found.

## What the refusal log said about Lissi and Sphereon (13 November 2026)

- **Lissi** got its token and was refused at the credential: `refused POST /course/credential: 400 invalid_proof
  [VCI.F1.PROOF_ISS_ANON_PREAUTH]`. Its key proof carries `iss` in the anonymous pre-authorized flow, where
  OpenID4VCI 1.0 App. F.1 says the wallet MUST omit it. The rule binds nothing there (there is no client), so
  `CUNHO_IGNORE_ANONYMOUS_PROOF_ISS=1` now reads such an `iss` as nothing and checks the rest of the proof as before;
  off by default, on in the demo stack. Test: refused without the setting, issued with it, and a wrong `aud` still
  refused with it. Mutation over `jwt_proofs`: 39 of 39 killed.
- **Sphereon** stops before asking for anything: "openID4VCIClient has no types". Its client reads the offer of an
  earlier draft of OpenID4VCI (a `types` list); cunho's offer is the 1.0 one (`credential_configuration_ids`).
  Speaking that draft is another protocol, not a variant of this one: not done.

### Forty-first and forty-second looks at 3a15baa (from 975417e): nothing found.

## Lissi, a step further: one course certificate per offer (13 November 2026)

With `iss` read as nothing, Lissi's credential request was refused under `KA.BIND_TO_ATTESTED_KEY`, at "Wallet
connected": the course issuer's metadata offered a batch of three (`batch_size`), and the refusal is the one for a
key that appears twice in one request, a wallet that answers a batch with the same key each time. A batch is for
credentials on different keys, which a verifier cannot link; three on one key would be three copies of one. The
course certificate in the demo is now offered one at a time (`demo/metadata/course/metadata_config.json` names no
batch); the PID keeps its batch. The full suite passes.

Two looks at bcdcf41 (from e7944a7): nothing found.

## The page says why a real wallet was refused (13 November 2026)

Trying real wallets, the page stood at "Wallet connected" with nothing said when the issuer refused the wallet's
credential request; the reason was only in the refusal log on the server. Now:

- cunho keeps, per subject, the error code and rule of the last credential request it refused (never the
  description, which may repeat the request), for as long as the subject's other marks, and
  `GET /admin/offers/{subject_ref}` gives it as `refusal` while the subject is `redeemed`; once the credential is
  issued it is no longer given.
- The demo's step is `rejected` then: the third dot reads "Refused by the issuer" and the status says why in words
  (the same key twice, an iss where it must not be, no fresh nonce, another audience, a date out of range, the wrong
  type, a signature that does not verify, no trusted key attestation; otherwise the error code), and in Advanced the
  code and rule. The page keeps following the offer: the wallet may try again.

Tests: the engine's progress shows the refusal of a proof dated 1970 by code and rule, not its description, and none
once the credential is issued; the demo's step is `rejected` for a redeemed subject with a refusal and `issued` for
an issued one. Mutation over `Issuer.credential`: 3 of 3 killed. Checked in a headless Chrome with the API's answer
made a refusal, Simple and Advanced: the dot and the words, no console errors.

Two looks at 5e7e8bd (from aa5ce91): nothing found.

## Lissi holds a cunho credential (13 November 2026)

With the batch gone, Lissi took the course certificate (SD-JWT VC): "Credential offer accepted successfully", the
card in its wallet, no refusal in the log. The page stayed at "Waiting for your wallet to confirm it stored it":
Lissi does not call the notification endpoint, which a wallet may leave out. "Credential signed" now reads as done,
and the status says the credential was issued and that some wallet apps do not report back; the last dot still turns
when a wallet does.

Paradym took the course certificate as well (SD-JWT VC), once its cached status list from before the change had
expired; like Lissi it does not call the notification endpoint. So for a wallet app the page now ends where the
issuer's knowledge ends: once the credential is issued and there is no demo wallet, the card lights up and draws its
lines as for the demo wallet, its line reads "In your wallet app", the steps end at "Credential signed" (the dot only
a report could fill is not shown), and the status reads "Done: issued to your wallet app". Checked in a headless
Chrome with the API's answer made such an issuance, and the demo wallet through to "In the demo wallet" unchanged.

## Wallet interop from running wallets' own code (branch wallet-interop)

The EU reference OpenID4VCI library, NL Wallet's issuance code and Sphereon's released client were run against a
local cunho. What failed on cunho's side, and what changed:

- The course issuer published the `attestation` proof type without `key_attestations_required`; the EU library then
  refused the whole metadata. The attestation type is now offered only where a key attestation is required (an
  empty requirement still counts).
- The EU library names the attested key with `kid: "0"` beside a key attestation, as OpenID4VCI 1.0 App. F.1's own
  example does; cunho refused it. `kid` "0" is now read as attested key 0, which alone may sign (Annex Ib TR_KA-6.1);
  any other `kid` is still refused.
- NL Wallet requires `iat` in an SD-JWT VC; it now carries one, equal to `nbf`.
- NL Wallet re-encodes each mdoc item before hashing it, in ISO key order; cunho wrote length-first order (valid, and
  its digests matched what it sent). Items are now written in the ISO order.
- Sphereon's last release looks for the metadata after the issuer's path. `CUNHO_APPENDED_WELL_KNOWN=1` answers
  there too; off by default, on in the demo.

Second reviewer: look 43 clean; look 44 found that `key_attestations_required: {}` lost the attestation proof type
(fixed, with a test); looks 45 and 46 clean.

## A wallet refused at the token endpoint (branch token-refusal)

After the interop deploy Sphereon's released wallet found the metadata and was then refused at the token endpoint:
it sends no DPoP proof, which cunho requires (HAIP), and the page kept waiting. A refusal for a live offer's code is
now noted by error code and rule only, shown while the offer waits ("rejected", with "the wallet did not bind its
access token to its key (DPoP)"), and cleared when a token is minted; invalid_grant, which is about the code itself,
is not noted. DPoP stays required.

Second reviewer: looks 47 and 48 both found that a refusal could be written after a successful redemption cleared
it; the live-offer check and the write are now one transaction. Looks 49 and 50 clean.

## Bearer tokens for wallets without DPoP (branch sphereon-bearer)

Sphereon's released wallet sends no DPoP proof. `CUNHO_ACCEPT_BEARER_TOKENS=1`, allowed only for an eaa_provider,
gives such a pre-authorized token request a Bearer token usable only with the Bearer scheme; a request with a DPoP
proof still gets a bound token. On in the demo for the course certificate; the PID keeps DPoP. A wallet refused at
the token endpoint now shows at "Wallet connected" instead of after it. Second reviewer: looks 51 and 52 clean.

## A singular proof from an earlier draft (branch sphereon-proof)

With a Bearer token, Sphereon's released wallet reached the credential endpoint and was refused for having no
proofs: it takes cunho for draft 15 (its version detection reads batch_credential_issuance that way) and sends one
jwt proof in a singular `proof` object. `CUNHO_ACCEPT_SINGULAR_PROOF=1`, only for an eaa_provider, reads it as
`proofs: {jwt: [...]}`, checked like any other. On in the demo for the course. Second reviewer: looks 53 and 54
clean.

## iss in the status list token (branch status-iss)

Sphereon's released wallet then took the course certificate and refused it as "Invalid SD-JWT VC". Running its own
pinned libraries here showed why: its x509 chain check treats the leaf as self-signed and never checks it against
an anchor, so a HAIP chain (leaf only, no trust anchor in x5c) fails whatever the wallet trusts; that is Sphereon's
to fix. Past that, it verifies the status list token as an SD-JWT VC and requires iss, which the Token Status List
leaves optional: the JWT status token now carries iss. Second reviewer: looks 55 and 56 clean.

## Licence: AGPL-3.0-only plus a commercial licence (branch eupl-licence)

cunho moves from Apache-2.0 to AGPL-3.0-only, and FOAAP also offers it under a commercial licence. The files copied
from the EU reference issuer keep their Apache-2.0 licence, with a copy of it beside them. The demo page names the new
licence. Outside contributions need a contributor licence agreement. Second reviewer: look 57 clean; look 58 found the
missing Apache copy and the demo text (both fixed); looks 59 and 60 clean.

## The OpenID Foundation suite, run again (13 November 2026)

The suite's server image pinned in `tools/oidf/run.py` (sha256:db966f36…, built from 1e6f543) is no longer in the
OpenID Foundation's registry, so the run stopped at the start. The pins now name the suite's `latest` images as of
13 November 2026 (server sha256:06db5442…, nginx sha256:5ed25320…), built from master at daca6ad, and the runner is
checked out at that commit. All five plans ran against demo-flow at f72de78…+: 277 modules, 0 failures beyond those
listed with their reason in `expected-failures.json` (the mdoc batch datasets, and the status list token checked with
an embedded JWK where cunho's carries x5c), and the expected warnings for the EUDI metadata OpenID4VCI does not define.
