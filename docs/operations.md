# Operating cunho

How to run cunho, configure it for production, and test it. For what cunho is and why, see the [README](../README.md); for how it is built, [DESIGN.md](../DESIGN.md).

## Running cunho locally

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python tools/dev_pki.py dev
export CUNHO_ISSUER_URL=https://localhost:8443 CUNHO_ADMIN_TOKEN="$(cat dev/admin-token)" \
  CUNHO_SIGNING_KEY=dev/signing.key CUNHO_SIGNING_CHAIN=dev/signing.pem \
  CUNHO_STATUS_SIGNING_KEY=dev/status.key CUNHO_STATUS_SIGNING_CHAIN=dev/status.pem \
  CUNHO_WALLET_PROVIDER_ANCHORS=dev/all-wallet-providers.pem CUNHO_AUDIT_RETENTION_DAYS=365 \
  CUNHO_SIGNER_CERTIFICATE_URL=https://localhost:8443/certs/signer.pem CUNHO_STORE_PATH=dev/store.db \
  CUNHO_SECRET_KEY_FILE=dev/master.key CUNHO_AUDIT_ANCHOR_PATH=dev/audit.anchor \
  CUNHO_SIGNING_TRUST_ANCHORS=dev/issuer-root.pem CUNHO_WALLET_PROVIDER_CRLS=dev/all-wallet-providers.crl \
  CUNHO_TEST_LOGIN_PERSONS=dev/test-persons.json CUNHO_ACCESS_SIGNING_KEY=dev/m3/access.key \
  CUNHO_ACCESS_SIGNING_CHAIN=dev/m3/access.pem CUNHO_ACCESS_TRUST_ANCHORS=dev/m3/access-ca.pem \
  CUNHO_REGISTRATION_CERTIFICATE=dev/registration-certificate.jwt CUNHO_REGISTRAR_DATASET=dev/registrar.json \
  CUNHO_REDIRECT_URIS='{"https://wallet-solution.test": ["https://wallet.test/callback"]}'
.venv/bin/uvicorn --factory cunho.app:create_app --port 8443 --ssl-keyfile dev/tls.key --ssl-certfile dev/tls.pem \
  --no-access-log
.venv/bin/python tools/dev_offer.py https://localhost:8443 dev/admin-token
```

To issue the PID as mdoc too, add `CUNHO_MDOC_SIGNING_KEY=dev/mdoc-signing.key CUNHO_MDOC_SIGNING_CHAIN=dev/mdoc-signing.pem CUNHO_MDOC_TRUST_ANCHORS=dev/iaca.pem CUNHO_MDOC_SIGNER_CERTIFICATE_URL=https://localhost:8443/certs/mdoc-signer.pem` and offer both formats with `tools/dev_offer.py ... --mdoc` (a PID provider offers the PID in both, ARF PID_02); for encrypted requests and responses, add `CUNHO_ENCRYPTION_KEYS=dev/encryption.key`. `tools/probe_local.py` starts cunho with all of it and runs the probe.

The development keys are throwaway. cunho refuses to start in production mode with a file key, an example admin token, an `http` issuer URL, no audit retention period, no secret key file, no audit anchor file, no `CUNHO_SIGNING_TRUST_ANCHORS`, no `CUNHO_KA_SIGNER_POLICY_OIDS` or `CUNHO_WIA_SIGNER_POLICY_OIDS`, no Commission list of wallet providers (`CUNHO_LOTE_PATH` and `CUNHO_LOTE_SIGNER`), no `CUNHO_FETCH_HOSTS`, no login service (`CUNHO_LOGIN_URL`), no access certificate signer, no registration certificate or registrar dataset, no Type Metadata for a published SD-JWT VC type, or on a host whose boot cannot be named (Linux and macOS name theirs). Keep the secret key file out of database backups: it holds the keys that protect the vault and the audit log.

`--no-access-log` keeps uvicorn from writing the client address of every request, status-list fetches included, to its log; cunho promises never to record who fetched a status list (910/2014 Art. 5a(16)). If you need access logs for operations, drop the address and the `/status/` paths before they are stored.

### Trust in wallet providers

In production the wallet providers cunho trusts are the ones on the Commission's list of wallet providers (ETSI TS 119 602, Annex E). `CUNHO_LOTE_PATH` names the list as the Commission publishes it, a signed JSON file, and `CUNHO_LOTE_SIGNER` the one certificate that signs it, as the Official Journal publishes it. cunho never fetches the list: run a job that downloads it and replaces the file (write a new file and rename it over the old one) well before its `NextUpdate`. cunho reads the file again whenever it changes, so a wallet solution taken off the list is refused at the next request, with no restart. A list that does not verify under the pinned certificate, is not the wallet providers list, is past its `NextUpdate` or has a lower sequence number than one cunho has already seen stops the start; once running, such a list leaves cunho trusting no wallet provider, and so issuing nothing, until a good one is in place. The certificates of each wallet solution's issuance service are the anchors for wallet and key attestation signers, and those of its revocation service the anchors for the signers of the wallet provider's status lists.

Without the list, a development run reads `CUNHO_WALLET_PROVIDER_ANCHORS` (and, if set, `CUNHO_WALLET_STATUS_ANCHORS`) from PEM files, and starts with warnings about what is not checked.

### Revoked wallet-provider certificates

With the list, the revocation of every certificate in a wallet or key attestation's path, and in a status list signer's, comes from the network: the CRL at the certificate's distribution point, or its OCSP responder when it names only that, fetched as it is needed and kept until the CRL's `nextUpdate` or the response's. A certificate that names neither is judged by `CUNHO_WALLET_PROVIDER_CRLS`, a file with the current CRLs (PEM, one or more, or a single DER CRL) of the CAs concerned; CRLs in that file are also pooled with the fetched ones. Keep the file fresh with a job, as for the list. Whatever cannot be fetched or checked refuses: an attestation whose revocation status is unknown is not accepted. cunho remembers the newest CRL it has seen at each distribution point, so an older one sent again cannot undo a revocation, but only in each worker's memory: after a restart, a worker can be shown an older CRL that is still before its `nextUpdate`. Only complete CRLs are accepted (no delta, partitioned or indirect CRLs). Without the list, a development run checks the file alone, and without the file it starts with a warning that revocation is not checked.

### What cunho fetches

cunho fetches CRLs, OCSP responses and wallet providers' status lists, and nothing else. `CUNHO_FETCH_HOSTS` is a comma-separated list of the host names it may fetch them from; production refuses to start without it. Every address a host resolves to must be public, the connection goes to the address that was checked, redirects are not followed, and each fetch has a size cap and a time budget of about two seconds, so a slow or hostile server cannot hold a request. A URL whose fetch failed is not tried again for five seconds: the requests that waited for it share the one failure. cunho sends one host at most 60 requests a minute; a request that finds no place left is refused, and revocation chaining waits for its place. A host that is not on the list, or cannot be reached, leaves the status unknown, and the attestation is refused. The failures go to the log with the host name.

### The authorization code flow

A wallet starts with a pushed authorization request (`/par`) that carries its wallet attestation and a proof of possession (`attest_jwt_client_auth`), and PKCE with S256. Its redirect URI must be one of those `CUNHO_REDIRECT_URIS` allows for its wallet solution: a JSON object from the `sub` of the wallet solution's attestation to an array of exact URIs. `/authorize` then sends the person's browser to your login service, `CUNHO_LOGIN_URL`, with a `login_state` parameter. The login service proves who the person is (at assurance level high for a PID) and reports the result with the operator token:

```
POST /admin/logins/{login_state}
{"subject": {...the claims, as for an offer...}, "loa": "high", "person": "optional handle for revocation by person"}
```

or `{"denied": true}` when the person cancelled or failed. The answer carries `continue`, the URL to send the browser to next; only this answer gives it out, so a wallet that knows the `login_state` cannot finish the login for itself. A login must be reported within `CUNHO_LOGIN_TTL` seconds (600 by default), and the code it leads to is good once, for `CUNHO_CODE_TTL` seconds (60). The wallet attestation is checked at PAR and again at the token request: its chain to the list's anchors, its signer's certificate policy (`CUNHO_WIA_SIGNER_POLICY_OIDS`) and its entry on the wallet provider's status list. The code flow gives a refresh token, bound to the wallet solution and to the wallet instance (the key in its wallet attestation, which the refresh request presents again), not to a DPoP key (RFC 9449 §5: the attestation already ties it to the wallet), so the wallet may move to a new DPoP key and the access token it gets is bound to that one. The wallet can get fresh credentials for `CUNHO_REFRESH_TOKEN_TTL` seconds (30 days by default) without a new login; the subject's data stays in the vault that long, and revoking or erasing the subject ends it. `CUNHO_TEST_LOGIN_PERSONS` turns on a built-in login that offers fixture persons from a JSON file, for tests and the OIDF suite; production refuses to start with it. Without a login service a development run refuses every authorization with `temporarily_unavailable`.

### Following an offer, and asking for consent

The operator's own pages can follow a subject and show a person what a login is for, with the operator token, as
every admin route. `GET /admin/offers/{subject_ref}` answers how far the subject got: its `state`, the furthest it
reached, is `offered` (a wallet can still get a token from the offer or login, until `expires`, in seconds since
the epoch), `redeemed` (a wallet got a token), `issued` (every configuration was issued), `closed` (revoked,
cancelled or erased) or `expired` (no token was got in time, or wrong transaction codes used the offer up); each
configuration in `configurations` is `pending`, `issued`, or, while a review is open, `held`, `released` or
`refused`, with `notification`, the newest event the wallet reported for it at `/notification` (an event sent
again after a newer one does not count). A demo page that shows a QR code polls it to say when the wallet has
the credential. It never carries the subject data, a code, a token, a `transaction_id` or the person handle, and a
reference cunho did not hand out answers 404. It reads under the store's write lock, so every answer is one
moment's state; poll it every second or so, not in a tight loop. An offer for the authorization code flow made
with `create_offer` has no `subject_ref` until the login: follow the one the login result returns.

`GET /admin/logins/{login_state}`, while a login waits for its result, answers what the wallet asked for: the
`configuration_ids`, the wallet solution (`client`, the `sub` of its wallet attestation, and the `wallet_name`
and `wallet_version` the attestation gives, or null), the `offer_ref` of the offer it came from, when the wallet
started from an authorization code offer, and when the login runs out (`expires`). Creating such an offer answers
its `offer_ref` too, so a page that showed the offer's QR code knows which login is its own. A login service
shows it on its consent screen before it reports the login; once reported, or after `CUNHO_LOGIN_TTL`, the
answer is 404.

### Review before issuance, and notifications

To check a person's credentials before they are issued, report the login with `"review": true` next to the subject. The wallet's credential request is then checked in full (token, proofs, nonces, keys, the subject data) and answered with HTTP 202 and a `transaction_id`; nothing is signed yet. `GET /admin/deferred` lists what waits, by a reference, the `subject_ref` and the configuration; `POST /admin/deferred/{ref}/release` or `/refuse` decides it, once, and each decision is logged. The wallet asks again at `/deferred_credential` with the `transaction_id` and any access token of the same login (a refreshed one, when the first ran out during the review): it gets 202 while the issuance waits, the credentials once released, bound to the keys it proved at the first request and valid from the moment it collects them, and `credential_request_denied` once refused. A `transaction_id` yields its credentials once, to one request: another that comes while the first is collecting gets 202 and asks again. One login can have three issuances of a configuration waiting or refused at a time; a further ask gets `credential_request_denied` until one of them is collected or runs out. `CUNHO_DEFERRED_TTL` is how long an issuance can wait to be decided and collected (a week by default, from an hour to 30 days), and never longer than the login's refresh token, which keeps the subject's data in the vault anyway; nothing is kept longer for a review. `CUNHO_DEFERRED_INTERVAL` is how long a wallet is told to wait between asks (600 s by default). Revoking, cancelling or erasing the subject drops what waits. Review is for the authorization code flow only: a pre-authorized offer has no refresh token, and its access token would run out before anyone decided, so an offer with `review` is refused.

Every credential response carries a `notification_id`. The wallet reports at `/notification` whether it stored the credentials (`credential_accepted`), failed to (`credential_failure`) or the person deleted them (`credential_deleted`); each event is logged once as `credential.notification`, however often the wallet sends it. The wallet's `event_description` is checked and never kept. Nothing else follows from a notification: a deleted credential stays valid until you revoke it.

### Encrypted requests and responses

A wallet can encrypt its credential and deferred credential requests to cunho, and ask for the answers encrypted to its own key (OpenID4VCI 1.0 §10), on top of TLS. Give cunho its request keys in `CUNHO_ENCRYPTION_KEYS`: paths, separated by commas, to PEM files that each hold an EC P-256 private key and that only cunho's user can read (`chmod 600`), at most four. The metadata then publishes all of them, each with its RFC 7638 thumbprint as `kid`, in `credential_request_encryption`, and `credential_response_encryption` beside it. To rotate, add the new key, and remove the old one once every copy of the metadata wallets may hold has expired. With `CUNHO_ENCRYPTION_REQUIRED=true`, a wallet must encrypt both ways; it cannot be set without keys. The algorithms are ECDH-ES with A128GCM or A256GCM, and nothing is compressed. A wallet asks for an encrypted answer only inside an encrypted request: in a plain one, whoever could change the request could put their own key in it. Error answers are never encrypted. The notification endpoint takes JSON only. Make these keys for this use alone; a signing key does not belong here.

### Signing keys in an HSM or KMS

Each signing key setting (`CUNHO_SIGNING_KEY`, `CUNHO_STATUS_SIGNING_KEY`, `CUNHO_MDOC_SIGNING_KEY`, `CUNHO_ACCESS_SIGNING_KEY`) takes one of three things, with its certificate chain in the matching `_CHAIN` setting as before:

- a PEM file, for development only: production refuses to start with one;
- a key in an HSM, by a PKCS#11 URI (RFC 7512) that names the token and the key by its label, its id or both, such as `pkcs11:token=cunho;object=issuer` or `pkcs11:token=cunho;id=%01`. Install the `pkcs11` extra (`pip install 'cunho[pkcs11]'`), set `CUNHO_PKCS11_MODULE` to the token's PKCS#11 library and `CUNHO_PKCS11_PIN_FILE` to a file holding the user PIN, readable by cunho's user only (`chmod 600`). The URI takes no query: the PIN never goes in it;
- a key in AWS KMS, by `aws-kms:` and its key id, ARN or alias, such as `aws-kms:alias/cunho-issuer`. Install the `kms` extra (`pip install 'cunho[kms]'`); credentials and region come from the usual AWS settings, and from the ARN when you give one. The key must be an ECC_NIST_P256, P384 or P521 signing key.

When mdoc attestations are published, the document signer's certificate, the IACA that issued it (in `CUNHO_MDOC_TRUST_ANCHORS`) and the status list signer's certificate must fit the certificate profiles of ISO/IEC 18013-5 Annex B (Tables B.1, B.3 and B.9), which mdoc readers check: `countryName` in the subject (the document signer's the same as its IACA's), subject and authority key identifiers, a critical key usage of exactly `keyCertSign` and `cRLSign` for the IACA and `digitalSignature` for the others, a critical extended key usage id-mdl-kp-mdlDS, the issuer's contact as `issuerAltName` (an email address or a URI), a CRL distribution point for the document signer, basicConstraints of a CA with path length 0 for the IACA, and no other critical extension in the others. Production refuses to start with one that does not fit and says what is missing; a development run warns. `tools/dev_pki.py` makes certificates in those profiles.

cunho signs once with each key when it starts and checks the signature against the certificate's key, so a wrong key, PIN or permission stops the start instead of the first issuance. Every later signature is checked the same way before it is used. A KMS key is pinned to the ARN KMS gives at the start, so moving an alias takes effect at the next start. When the HSM drops cunho's session, cunho opens it again once before a signature counts as failed. To rotate a key, put the new key and its certificate in place and restart.

### Type Metadata of the credentials

Every SD-JWT VC carries `vct#integrity`, the digest of the Type Metadata document its `vct` leads to (SD-JWT VC §6 and §7, ETSI TS 119 472-1 EAA-5.2.1.2-03, which CIR 2024/2979 Annex II makes binding). Put each document in `type_metadata/` under the metadata directory (`CUNHO_METADATA_DIR`), one JSON file per type, naming its `vct`; cunho hashes the file's bytes as they are, so publish exactly that file where the `vct` points. Production refuses to start while a published SD-JWT VC configuration has none; a development run warns and issues without `vct#integrity`. A qualified or public-body attestation provider (`CUNHO_PROFILE=qeaa_provider` or `pub_eaa_provider`) also gets the `category` of TS 119 472-1 §5.2.2 in every credential, and, like a PID provider, must publish its signer's certificate (`CUNHO_SIGNER_CERTIFICATE_URL`, for `x5u` and `x5t#S256`).

### Qualified and public-body attestations

With `CUNHO_PROFILE=qeaa_provider` or `pub_eaa_provider`, every credential carries what eIDAS Annex V or VII asks, as ETSI TS 119 472-1 V1.2.1 profiles it. The provider is named by its signing certificate, which every credential carries: the subject of each signing certificate (and of the mdoc document signer's) must give the Member State as `countryName` and, for a legal person, `organizationName` and the registration number as `organizationIdentifier` in the form of ETSI EN 319 412-1 §5.1.4 (`VATPT-500000000`), or the person's name for a natural person. cunho checks this at start. So a configuration of such a provider lists no `issuing_authority`, `issuing_country` or `iss_reg_id` (TS 119 472-1 forbids them next to the qualified certificate), no `subAttrs` (every attribute refers to the subject), and no `category` or `jti`, which cunho fills in: each credential gets an identity code of its own in `jti`, 128 random bits. By default such a provider publishes only the configurations it may issue; naming another one in `CUNHO_PUBLISHED_CONFIGURATIONS` stops the start with the reason. Subject data that gives attributes of someone else (`subAttrs`, or an mdoc `subId` or `subAka` value) is refused.

Every mdoc attestation that is not a PID or an mDL gets from cunho, in the ISO/IEC 23220-2 namespace `org.iso.23220.1`, the issuing authority (`issuing_authority_unicode`, the certificate's `organizationName`), an identity code of its own (`document_number`) and the issue date, and, from a qualified or public-body provider, the `category` in `org.etsi.01947201.010101` (TS 119 472-1 clause 6). The metadata lists them; the configuration and the operator's data do not. An mDL lists its own `issuing_authority`, `document_number` and `issue_date`. The mdoc signature is a CB-AdES baseline signature (ETSI TS 119 152-1): its signing time and the signer's `x5t` are in the protected header. One point differs: `x5chain` stays a bare unprotected header, where ISO/IEC 18013-5 puts it and mdoc verifiers read it, rather than inside the `uHeaders` array of TS 119 152-1 §4.4.

### Credentials for some wallet solutions only

A configuration may name the wallet solutions it is issued to, as `"wallet_solutions": [{"wallet_name": "...", "wallet_versions": ["..."]}]` in its file (`wallet_versions` is optional; without it every version is allowed). This is for an attestation whose rulebook asks things of the wallet, such as a SUA attestation (ARF SUA_03). The `wallet_name` and `wallet_version` are those of the wallet attestation that got the access token, as the list of wallet providers names the solution; a token got without a wallet attestation, or by a solution or version not named, gets `credential_request_denied` for that configuration. A refresh goes by the attestation shown at the refresh. The list is never published.

### Signed metadata and the registration certificate

A client that asks for `application/jwt` gets the issuer metadata as a JWT signed with the issuer's access certificate (OpenID4VCI §12.2.3, ETSI TS 119 472-3 §4.2.1). Its key is set like the others (see Signing keys in an HSM or KMS): `CUNHO_ACCESS_SIGNING_KEY`, `CUNHO_ACCESS_SIGNING_CHAIN` and `CUNHO_ACCESS_TRUST_ANCHORS`, the access certificate authority's anchors, which never go into `x5c`. The access certificate must not be self-signed and its key must be neither the credential nor the status list signing key. A signed document lives `CUNHO_SIGNED_METADATA_TTL` seconds (a day by default, at most a week). The metadata carries the registration certificate the registrar issued (`CUNHO_REGISTRATION_CERTIFICATE`, the file as issued) and the registrar dataset (`CUNHO_REGISTRAR_DATASET`, a JSON object with `identifier`, `srvDescription`, `registryURI` and `providesAttestations`); production refuses to start without them. `CUNHO_PREFERRED_CLIENT_STATUS_PERIOD`, in seconds, is published for wallets that choose how long their attestation's status stays maintained.

cunho serves the signer certificate chain at `/certs/signer.pem`, the `x5u` URL above. Set `CUNHO_SIGNER_CERTIFICATE_URL` to that path, or to a URL you host yourself that serves the same chain; cunho does not fetch it to check.

### A PostgreSQL store

Workers on more than one host share a PostgreSQL database instead of a SQLite file: install the `postgres` extra (`pip install 'cunho[postgres]'`) and set `CUNHO_STORE_URL` to a `postgresql://` connection URI, in place of `CUNHO_STORE_PATH`. cunho creates its one table on the first start. The secret key file and the audit anchor never live in the database, so a Postgres store needs `CUNHO_SECRET_KEY_FILE` and `CUNHO_AUDIT_ANCHOR_PATH` even in development; with workers on several hosts, the anchor file must be one file on storage they all append to and lock with working `flock` across hosts, such as an NFSv4 export with locking. Every logged action, every issuance and revocation among them, appends to it after its database transaction, and hosts that cannot lock it against each other break its chain and stop issuing: there is no other way to run several hosts. Every write takes one advisory lock first, so writers go one at a time, as on SQLite, and a write waits at most 30 seconds for it before the request fails: what this buys is several hosts, not more writes per second. Each host keeps its own clock base (see the time rules below), laid from its own clock when it boots, so run every host on NTP: their times differ by as much as their clocks did then. Maintenance runs `VACUUM` on the table where SQLite empties its write-ahead log; the server's own write-ahead log, its archives and backups keep deleted rows for as long as you keep them, so set their retention with erasure in mind.

### The audit anchor file

`CUNHO_AUDIT_ANCHOR_PATH` names a file outside the database. It starts with a genesis line and gets one MACed line for every audit entry, and `GET /admin/audit/verify` compares every line with the database: deleting or rewriting entries, or restoring an older copy of the database, makes verification fail, and cunho stops logging, and so stops issuing, until someone looks. cunho never creates the anchor again over an existing log: if the file is missing or empty while the database has entries, cunho refuses to start, and a running cunho refuses to log. In production the file is created only on the first start of a new deployment, with `CUNHO_AUDIT_ANCHOR_INIT=true`; remove the setting afterwards. This only helps if the file itself cannot be cut short or removed: keep it on append-only storage (on Linux `chattr +a` on a local file system), apart from the database and its backups, and give cunho's user no right to truncate, rename or delete it. Object stores cannot hold the file itself, because cunho appends to it and locks it with `flock`; ship a copy there instead. Several workers on one host share the file. Without the setting, a development run keeps the anchor next to the SQLite file, or in memory, and creates it for a new database.

A write to the anchor can stop part-way, when the disk fills up or the machine stops, and after a power loss some file systems leave NUL bytes at the end of the file instead of what was written. The action that was being anchored stands, since it was committed, and is answered as done; `cunho.security` logs that the anchor is behind. The next action first closes whatever follows the last valid line with a newline and writes the missing lines, the first of which declares the bytes it closed, and is refused until it can (an HTTP 500, "audit log unavailable"), so free space and nothing more is needed, however often a write is cut short: the repair only appends, which append-only storage allows, and the log gets an `audit.anchor_repaired` entry of its own. The background task does the same about once a minute when no action comes. Until then verification reports the damage and does not call the log valid; afterwards it reports the stretches that were closed and declared. Bytes between two lines that no line declares, or a declared stretch changed later, fail verification. So does a copy of one of the file's own lines appended to it, which anyone who can append to the file can add: every line must follow the one before it, and cunho logs nothing until the copy is gone. Keep a copy of the file as evidence, lift the append-only flag, cut the file back to the end of the line before the copy (`truncate -s <offset>`, with the offset verify names) and set the flag again; if verify then says the database is behind the anchor, entries were removed, and the way back is a new deployment, as after a restore. A database restored from an older backup cannot be told from one whose newest entries were removed, so cunho stops logging on top of it; there is no step that re-bases the anchor in M2. Keep the database on storage that survives a crash instead of planning to restore it; after a restore, start a new deployment with a new anchor and keep the old database and anchor as the record.

Operators who also want a copy of the head elsewhere can pull `GET /admin/audit/head` on a schedule and later check the log against it with `POST /admin/audit/verify` and `{"signed_head": "<that JWS>"}`. The statement is signed by a key derived from the secret key file for this purpose only; its public key is in the JWS header (`jwk`), and you should pin it the first time.

Maintenance (audit pruning, decoy scheduling) runs in the background every `CUNHO_MAINTENANCE_INTERVAL` seconds, an hour by default, never inside a request. Revocation chaining runs with it, at most every `CUNHO_CHAIN_INTERVAL` seconds (six hours by default; from ten minutes to a day): for every credential that lives more than a day, it reads the wallet providers' lists again, status lists and identifier lists alike, and revokes the credential when the wallet attestation or the key attestation it was issued against is revoked. A PID provider always chains; an attestation provider does with `CUNHO_CHAIN_ATTESTATIONS=1`. A list that cannot be read is logged to `cunho.security` and to the audit log as `chain.unchecked`, and nothing is revoked for it: revocation cannot be undone, and an outage at a wallet provider should not cost every holder their PID. To revoke credentials whose attestations could not be checked for some days, set `CUNHO_CHAIN_REVOKE_AFTER_DAYS`. Expired state is never read, and the same background task deletes it about once a minute, in short batches. Everything cunho decides by time goes by one time: the wall clock as cunho trusted it once per boot, moved on by the host's own clock, which counts the time that really passed and which wall-clock steps do not move. On one boot cunho then never follows the wall clock again: a reading more than two minutes off is logged to `cunho.security` every minute, and offers, tokens, revocations, status lists, sweeping and pruning all go on by the host's clock. After a host restart cunho trusts the wall clock at once when the kernel reports it synchronised by NTP, and otherwise once it has kept pace with the host's clock for an interval. Audit pruning, which cannot be undone, waits an interval after that, and while the wall clock reads behind cunho's time; it removes only entries whose MAC and chain verify. If the wall clock was wrong when cunho trusted it and is put right later on the same boot, cunho keeps its time until the host restarts or you run a forced maintenance once the clock is right (`python -c 'from cunho.service import Issuer; from cunho.settings import Settings; Issuer(Settings.from_env()).maintenance(force=True)'` with cunho's environment), and says so every minute. Start cunho after NTP has synchronised the clock (with systemd, `After=time-sync.target`), or a reboot with a wrong clock is taken as right, and use an authenticated time source (NTS, which chrony supports). The SQLite write-ahead log is emptied after each run, so erased data leaves every file; when a reader in another worker holds it, cunho logs a warning and tries again about once a minute.

In the anonymous pre-authorized flow a wallet must omit `iss` from its key proof (OpenID4VCI 1.0 App. F.1), and cunho refuses a proof that has one. Some wallets send it all the same; with `CUNHO_IGNORE_ANONYMOUS_PROOF_ISS=1` such an `iss` is ignored, binding the proof to no client (there is none), and nothing else of the proof is relaxed.

The issuer metadata of an issuer with a path lives at `/.well-known/openid-credential-issuer/<path>` (OpenID4VCI 1.0 §12.2.2). Some wallets still look for it at `/<path>/.well-known/openid-credential-issuer` and, finding nothing, go on as if the issuer offered no credentials; with `CUNHO_APPENDED_WELL_KNOWN=1` both that document and the authorization server metadata also answer there. Off by default.

cunho binds every access token to the wallet's key with DPoP (RFC 9449), as HAIP requires. Some wallets send no DPoP proof. An attestation provider that is neither qualified nor public (`CUNHO_PROFILE=eaa_provider`) can set `CUNHO_ACCEPT_BEARER_TOKENS=1`: a pre-authorized token request without a DPoP proof then gets a plain Bearer token (RFC 6750), which works only with the `Bearer` scheme, while a request with a DPoP proof still gets a DPoP-bound token that a `Bearer` request cannot use. A Bearer token is only as safe as the channel and the hands it passes through, so it is off by default, and a PID, QEAA or PuB-EAA provider refuses to start with it.

OpenID4VCI 1.0 takes key proofs in `proofs`; earlier drafts had a single `proof` object, and some wallets still send it. With `CUNHO_ACCEPT_SINGULAR_PROOF=1`, again only for an `eaa_provider`, a credential request without `proofs` whose `proof` is of type `jwt` is read as `proofs: {"jwt": [...]}` and checked exactly like one sent that way. Off by default.

With `CUNHO_LOG_REFUSALS=1` cunho logs to `cunho.refusals`, for each request it refuses, the route, the status, the error code and the rule, and nothing of who asked: no address, header, query, token or body, and not the error's description, which may repeat what the request sent. It is off by default; turn it on to find out what a wallet that does not get through expects, then off again.

Every tuning setting can be set from the environment: `CUNHO_OFFER_TTL`, `CUNHO_ACCESS_TOKEN_TTL`, `CUNHO_C_NONCE_TTL`, `CUNHO_DPOP_IAT_WINDOW`, `CUNHO_PROOF_IAT_WINDOW`, `CUNHO_TX_CODE_MAX_ATTEMPTS`, `CUNHO_CREDENTIAL_VALIDITY_DAYS`, `CUNHO_TIMESTAMP_GRANULARITY`, `CUNHO_STATUS_LIST_SIZE`, `CUNHO_STATUS_LIST_FILL_LIMIT`, `CUNHO_STATUS_DECOY_RATIO`, `CUNHO_STATUS_DECOY_CHURN_PER_DAY`, `CUNHO_STATUS_TOKEN_TTL`, `CUNHO_STATUS_TOKEN_LIFETIME`, `CUNHO_STATUS_PUBLISH_INTERVAL` and `CUNHO_STATUS_RATE_LIMIT_PER_MINUTE`, besides those above. cunho refuses to start on a value that is not a number or that would defeat a protection. `CUNHO_STATUS_LIST_SIZE` applies to lists opened after it changes; lists already published keep their size.

The database carries a schema version. A database written by an earlier cunho without one is upgraded on the first start: the status lists keep every bit they showed, and offers made before it can still be revoked, cancelled and erased. Run that first start with the `CUNHO_STATUS_LIST_SIZE` the earlier version used, which it never stored; cunho refuses to start when a slot lies beyond it. In production, also set `CUNHO_STORE_UPGRADE=true` for that one start, and remove it afterwards: a database without a version is also what someone who removed the version row leaves, so cunho asks. The upgrade is logged as `store.upgraded`. A database with a version this cunho does not know refuses to start. Switches (`CUNHO_PRODUCTION`, `CUNHO_AUDIT_ANCHOR_INIT`, `CUNHO_STORE_UPGRADE`, `CUNHO_DPOP_SERVER_NONCE`, `CUNHO_ENCRYPTION_REQUIRED`) take `true`, `1`, `yes` or `on`, and `false`, `0`, `no` or `off`; anything else refuses to start.

### Status lists and revocation timing

Revoking a subject flips the status bit of every credential issued from its offer. So that a poller cannot see k bits change at once and know it was a revocation, each bit shows at its own random moment within `CUNHO_STATUS_REVOCATION_JITTER` seconds (an hour by default), and decoys arrive as clusters whose sizes follow the batch sizes cunho actually issued, spread over the same window. Lists are published on fixed moments, every `CUNHO_STATUS_PUBLISH_INTERVAL` seconds (a minute by default), with the bits due by then, so the signed list never changes at the revocation itself. Set the jitter to 0 to publish revocations at the next publication, moment included. The jitter, the publication interval and `status_token_ttl` together may not exceed 24 hours less a margin of two minutes. A revocation's moment and the publications go by the same time, cunho's, so a wall clock that reads ahead or behind, for a moment or for days, cannot hide a revocation for longer or show it, or any decoy, early; when cunho cannot vouch for the time yet (after a host restart until the clock is trusted), the bit shows at the next publication. The background task publishes every list about once a minute, and a poll whenever it comes. A poll between two publications is answered from the worker's memory, so a mass revocation does not make `/status` expensive; it is still rate-limited per client (`CUNHO_STATUS_RATE_LIMIT_PER_MINUTE`, default 600), and a CDN or reverse-proxy cache in front of it, honouring the `Cache-Control` it sends, takes the load off cunho entirely.

**What a revocation covers.** cunho holds no person identifier: every offer gets its own `subject_ref`, and a person who was issued credentials twice, say a PID renewed after ten days, has two. `POST /admin/revocations` with `{"subject_ref": ..., "reason": ...}` revokes every live credential issued from that one offer and closes the offer whatever state it is in: the pre-authorized code and any access token obtained with it are refused from then on, a configuration still being issued is refused, the subject data is erased, and when the offer could still have yielded a credential the answer carries `"offer_cancelled": true`. To revoke a person, either keep your own mapping from the person to every `subject_ref` you were given and revoke each, or give an opaque handle of your choosing when creating the offer, `"person": "<1 to 200 printable ASCII characters>"` (your customer number, never the person's name or national identifier), and revoke with `{"person": ..., "reason": ...}`: that covers every offer made with the handle while a credential from it can be valid, and answers how many credentials, subjects and live offers it covered. cunho keeps only a keyed reference of the handle, never logs it, and drops it with the subject when the subject is erased (`POST /admin/subjects/{subject_ref}/erase`); revoke such a subject by its `subject_ref`. Erasure is refused for a reference cunho never handed out, and the log says whether there was data left to erase. To stop an offer without revoking anything, `POST /admin/offers/{subject_ref}/cancel`, with the `subject_ref` that creating the offer returned; it is logged as `offer.cancelled`, and the subject data the offer held is erased.

### One token per system: operator scopes

Every system that calls the admin API (a learning platform, an operator's front end, a script) should have a token of its own, in `CUNHO_OPERATORS` (`name=token,name=token`; each at least 32 characters, all different). `CUNHO_OPERATOR_SCOPES` then limits what each one may do: a JSON object from the operator's name to its permissions, the credential configurations it may act on, and its own requests per minute:

```json
{"lms": {"permissions": ["offers", "offers.read", "offers.cancel", "revoke"],
         "configurations": ["app.foaap.course_certificate_sd_jwt", "app.foaap.student_card_sd_jwt"],
         "rate_limit_per_minute": 6000}}
```

The permissions are `offers`, `offers.read`, `offers.cancel`, `logins`, `revoke`, `revoke.slot`, `erase`, `deferred` and `audit`. A token without a scope, the admin's included, has every permission but `revoke.slot`: revoking by status list slot names no person and no configuration, so it can revoke anyone's credential, and only a scope that names it may do it: the admin's, or another with no `configurations` and neither `offers` nor `logins`. To give it to the admin token, name all nine permissions in the admin's scope (`{"admin": {"permissions": [...]}}`).

A token whose scope can make offers or report logins acts only on the subjects it made itself, so one learning platform that is compromised cannot follow, cancel, revoke or erase what another one issued: another system's subject reference is refused (403, `insufficient_scope`), its reviews cannot be decided and are left out of the list, and a revocation by person reaches only the subjects this token made. A login that has not been reported yet belongs to no one, so any token with `logins` for its configurations can read or report it; its `login_state` reaches only `CUNHO_LOGIN_URL`. The start stops, with the reason, on an unknown permission or key, an empty permission list, a scope for an operator that does not exist, a configuration this deployment does not publish, or a rate limit that is not a positive number.

The course provider's example metadata (`demo/metadata/course`) holds a course certificate (`app.foaap.course_certificate_sd_jwt`, and an mdoc) and a student card (`app.foaap.student_card_sd_jwt`), each with its Type Metadata. The container kit publishes the two course certificates; to issue the student card too, add `app.foaap.student_card_sd_jwt` to `CUNHO_PUBLISHED_CONFIGURATIONS` and serve `type_metadata/student-card-1.json` where its `vct` points, as `deploy/Caddyfile` serves the course certificate's. The Moodle connector (`local_eudiwallet`) issues both with a token scoped as above.

## The demo

`src/cunho_demo` is an operator's front end, written as any operator would write one: it talks to cunho only through the admin API, with the operator token. It offers a PID (both formats) or the course certificate of `demo/metadata/course` (SD-JWT VC or mdoc), for one of three fictional people, by the pre-authorized or the authorization code flow, shows the offer as a QR code and follows the issuance step by step through `GET /admin/offers/{subject_ref}`. For the code flow it is the login service of both cunho instances (`CUNHO_LOGIN_URL`), with a login and a consent screen that shows what will be issued to which wallet; a visitor can hold an issuance for review and release or refuse it, and revoke what they were issued. A visitor with no wallet can let the demo wallet (`src/cunho_demo/wallet.py`) take a pre-authorized offer: it does what a wallet does (DPoP, key proofs with key attestation, notification), then checks what it got (the issuer's signature, every claim against the digests the issuer signed) and reads its status as a verifier would, so the page shows the whole issuance and what was issued, and a revocation showing on the status list. Each offer is also given by reference (`credential_offer_uri`, a short QR code) and as a phone page a phone's camera opens, which hands the offer to a wallet app or to the demo wallet and never shows the PIN. `/operator` is a console for the person running it. docs/DEMO.md runs it on this machine (`tools/demo_local.py`, and `tools/demo_wallet.py` to play a wallet) and in containers (`deploy/`), with keys in SoftHSM behind Caddy. `tools/probe_local.py --course` and `tools/oidf/run.py --course` check the course provider as the probe and the conformance suite check the PID. `tools/mutation/demo_mutate.py` breaks each of the demo's guards in turn and expects `tests/demo` to notice.

## Rate limits and running behind a reverse proxy

cunho limits requests per client on `/token`, `/nonce`, `/credential` (with `/deferred_credential` and `/notification`) and failed operator logins (`CUNHO_RATE_LIMIT_PER_MINUTE`, default 120), and on `/status` (`CUNHO_STATUS_RATE_LIMIT_PER_MINUTE`, default 600), with one table per route group. A client is one IPv4 address or one IPv6 /64, and costs three numbers (this minute's count, the last minute's count and which minute it is), so a full table of 100,000 clients takes a few tens of megabytes. When a table is full, the client seen least recently is dropped, so a flood of new addresses never locks new wallets out. A refused request gets HTTP 429 with `Retry-After: 60`. An authenticated operator is checked first and gets its own, larger budget per operator name (`CUNHO_OPERATOR_RATE_LIMIT_PER_MINUTE`, default 6000), so wallet traffic from one address never locks the operator out. The counters live in each worker's memory: with several workers the effective limit is the configured one times the number of workers, and the counters reset on restart.

Failed operator logins are written to the `cunho.security` log with the route name and the client's network (IPv4 /24, IPv6 /48), never the requested path. The audit log gets one entry per maintenance run with the counts.

This limiter is a backstop, not the first line of defence. Put a reverse proxy or WAF in front of cunho and rate-limit there, per address and per route, before traffic reaches the issuer; the proxy can also drop slow or oversized requests that cunho would otherwise have to read.

Behind a proxy every request arrives from the proxy's address, so the per-address limit would throttle all wallets together. Tell uvicorn to take the client address from the proxy's `X-Forwarded-For` header, and only from the proxy itself:

```bash
.venv/bin/uvicorn --factory cunho.app:create_app --host 127.0.0.1 --port 8000 \
  --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-access-log
```

Set `--forwarded-allow-ips` to the proxy's address, never to `*` on a port that clients can reach directly: anyone could then choose their own address and escape the limit. Make sure the proxy overwrites `X-Forwarded-For` and `X-Forwarded-Proto` rather than appending to what the client sent. The proxy terminates TLS; `CUNHO_ISSUER_URL` stays the public `https` URL. HAIP and FAPI 2.0 (§5.2.2) take TLS 1.2 only with the cipher suites BCP 195 recommends (RFC 9325 §4.2): `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384` and their RSA twins, or TLS 1.3 alone. tools/oidf/Dockerfile shows the setting for uvicorn serving TLS itself.

## Mutation testing

```bash
.venv/bin/python tools/mutation/mutate.py                # switch off each M2 rule in turn
.venv/bin/python tools/mutation/mutate.py --sites        # remove each refusing statement and each raise
.venv/bin/python tools/mutation/mutate.py --conditions   # alter each condition that guards a refusal
.venv/bin/python tools/mutation/mutate.py --all --list   # see what would run
```

Each mutant runs on a scratch copy of the checkout and must make the engine test suite fail. `--sites` removes every `raise` in `src/cunho` and every call that refuses (`enforce`, `refuse`, rulebook problems...). `--conditions` negates each guard of a refusal, drops each operand of its `and`/`or`, removes each `not` and moves each comparison across its boundary, and adds the hand-written semantic mutants in `tools/mutation/patches.py`. Mutants that cannot change behaviour are listed with a reason in `tools/mutation/equivalent.py`; the run fails on any other survivor, and on a listed mutant that is killed or gone. CI runs rules mode and the full `--all` run, in shards, as separate jobs.

## Slow suites

```bash
.venv/bin/python -m pytest -m slow tests/slow
```

`pytest` alone leaves them out. They cut two anchor writes in a row at every byte of the second and of the first, or at every fourth byte of the first when the second is not the write right after it, race a revocation against the issuance of both configurations of an offer on three worker processes, poll a status list with 100,000 hidden bits, and run a Hypothesis state machine of offers, tokens, logins of the authorization code flow, refreshes (and a refresh from another wallet instance), issuance, revocation, cancellation, erasure, maintenance and verify across four worker processes on one SQLite file, with trust in wallet providers from the Commission's list, which the operator's job renews, withdraws or rolls back, wallet providers' status lists fetched, revocation jitter and decoys, maintenance unforced, the wall clock stepped for one request or for many steps, and damaged and copied anchor lines, checking the invariants after every step. CI runs them as their own job.

## The OIDF conformance suite

```bash
.venv/bin/python tools/oidf/run.py haip-wallet          # or haip-issuer, preauth, haip-wallet-mdoc, haip-issuer-mdoc
```

This runs the OpenID Foundation's conformance suite against the checkout, on this machine, in docker: the suite's
server, database and proxy from images pinned by digest, its runner from its source at a pinned commit, and cunho
built from the working tree and served on `cunho.test`. It needs docker and about 3 GB of images. Results go to
`tools/oidf/_work/results/<plan>`; `--keep` leaves the containers up, with the suite's pages at
`https://localhost.emobix.co.uk:8443`. The run's docstring says how cunho is set up for it and why.

The two HAIP plans run once for an SD-JWT VC and once for an mdoc (`-mdoc`), each format against a cunho of its own,
and with request and response encryption on, so each plan's encrypted variant runs too; no module is expected to be
skipped. The mdoc's document signer and IACA follow the certificate profiles of ISO/IEC 18013-5 Annex B, and the
IACA's CRL is served on the suite's network at the distribution point the signer names. What cunho does differently
from what a module expects is in `tools/oidf/expected-failures.json`, each with its reason.

A few modules expect cunho to refuse with an error page and ask a person for a screenshot. run.py checks the page
the suite's browser got (a 400 from the authorization endpoint) and sends a 1x1 placeholder, so those modules end as
REVIEW; a certification submission needs real screenshots instead.

CI runs all five plans in its oidf job, nightly, on main and on pull requests, with the other heavy jobs; a push
to a working branch runs the fast checks and the probe only.

## Running the probe

```bash
PYTHONPATH=probe .venv/bin/python -m eudi_probe \
  --issuer https://issuer.example --name my-issuer@commit \
  --offer-cmd ./make-offer.sh --out out/my-issuer
```

`--offer-cmd` prints a fresh pre-authorized credential offer. Issuers that only support the authorization code flow use `--token-cmd` instead. `--help` lists the rest.

The checks of the authorization code flow and of wallet attestations need a wallet provider the issuer trusts: `--wia-signer CHAIN KEY` (a wallet attestation signer the provider issued for testing) or `--wia-ca CERT KEY` (a test wallet-provider CA, under which the probe makes its own short-lived signer), `--client-id` (the wallet solution, the `sub` of its attestations) and a `--redirect-uri` the issuer allows for it. The probe logs in by filling the issuer's login forms with `--login-field NAME=VALUE` (and `--cancel-field` for the cancelled login), or through `--login-cmd`, a command that opens the authorization request `$EUDI_PROBE_AUTHORIZE_URL` itself, as a browser would (so any session the server keeps in cookies is its own), logs in, and prints where the browser was sent last. Against a local cunho with its test login:

```bash
PYTHONPATH=probe .venv/bin/python -m eudi_probe --issuer https://localhost:8443 --name cunho@local --insecure \
  --ka-ca dev/wallet-providers.pem dev/wallet-provider.key --wia-signer dev/m3/wia-signer.pem dev/m3/wia-signer.key \
  --client-id https://wallet-solution.test --redirect-uri https://wallet.test/callback \
  --login-field person=ana --login-field action=login --cancel-field action=cancel \
  --only authorization,attestation --out out/cunho
```

The mdoc checks (group `mdoc`) ask for the first `mso_mdoc` configuration the offer names, or `--mdoc-config-id`, and verify what comes back on their own, without the issuer's code: the IssuerSigned structure, the signature by the document signer its x5chain names, every element's digest, the device key against the proof key, validityInfo inside the signer certificate's validity, and the status list entry as a `statuslist+cwt`. The deferred checks need an issuance the issuer holds: `--hold-field NAME=VALUE` for a login that holds it (cunho's test login has a box for that, `--hold-field review=true`) or `--deferred-offer-cmd` for an offer that does, and `--release-cmd` for a command that releases what is held, as the operator would (`tools/dev_release.py` for a local cunho). The encryption checks send encrypted requests to the first `ECDH-ES` key of `credential_request_encryption` and decrypt the response with a key of their own. `tools/probe_local.py OUT_DIR` runs every check against a local cunho with all of this set up, and fails unless every check of M3 and M4 passes.

The check that a pushed request belongs to the client that pushed it needs a second wallet solution the issuer allows, `--second-client CLIENT_ID=REDIRECT_URI`; without one it skips. Against an issuer that checks the status of wallet and key attestations, give the status list entries the wallet provider publishes for them with `--wia-status URI INDEX` and `--ka-status URI INDEX`; otherwise the attestations name a placeholder that resolves nowhere. The checks that try a bypass (`sensitive` in `checks.py`) go to the private report, as the security checks do.
