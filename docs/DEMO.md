# Running the demo

The demo is a page where someone picks a credential, scans a QR code with an EU wallet and watches the issuance
happen. It runs two cunho instances, as the law has two roles: a PID provider (`/pid`) and an attestation
provider that issues a course certificate (`/course`), and the demo service (`src/cunho_demo`): the page, its API,
the login and consent screens of the authorization code flow, and an operator console. Everything it issues is
about fictional people. demo/README.md describes the course certificate.

## On this machine, without containers

```bash
.venv/bin/pip install -e '.[demo]'
.venv/bin/python tools/demo_local.py out/demo --view-port 8099
```

The demo is at `https://localhost:8100` and, for a browser that does not trust the development certificate, at
`http://localhost:8099`; the operator console's password for the run is printed. The page's demo wallet ("No
wallet? Try it with the demo wallet") takes any offer made straight away and shows what it was issued; "Open the
phone page on this computer" opens the page a phone's camera opens from the QR code. To try the phone page on a
phone on the same Wi-Fi, add `--lan` with this machine's address there (`ipconfig getifaddr en0` on a Mac): the
page's port listens on it too and the QR codes point to it. That is plain http on the local network, which the
demo allows for private addresses only; a real wallet app still needs the demo online over https. `tools/demo_wallet.py` plays a
wallet from the command line: give it the link of the page's "Open in a wallet" button.

```bash
.venv/bin/python tools/demo_wallet.py 'openid-credential-offer://?credential_offer_uri=...' \
  --ka-ca out/demo/dev/wallet-providers.pem out/demo/dev/wallet-provider.key --ca-file out/demo/dev/tls.pem
```

### What a visitor sees

- Two QR codes of each offer, picked with "Scan with": the phone camera's is a short https link to the phone page
  (`/o/{reference}`), which opens the offer in a wallet app on the phone or hands it to the demo wallet; the wallet
  app's is the offer by reference (`openid-credential-offer://?credential_offer_uri=.../offers/{reference}`). The
  reference gives the offer and its progress only: the phone page never shows the PIN (the visitor types it there)
  and cannot revoke.
- The demo wallet (`src/cunho_demo/wallet.py`) runs in the demo service, with keys that live in its memory for the
  session. It reaches the issuers by their internal address, signing its proofs for their public URLs, and attests
  its keys with the key-attestation signer in `DEMO_WALLET_KA_CHAIN_FILE` and `DEMO_WALLET_KA_KEY_FILE` (the
  development PKI's `m3/ka-signer.pem` and `.key`), whose wallet provider the issuers must trust: when
  `WALLET_PROVIDER_ANCHORS` names real wallets' providers, add that one's root to the file, or remove the two
  settings and the page offers no demo wallet. It takes pre-authorized offers only: cunho holds code-flow issuances
  for review, and a held pre-authorized offer could never be collected.
- Real wallets: the page lists none it has not been tested with. A wallet takes the offer only if it accepts any
  issuer (the EU reference wallet takes only the issuers built into it) and cunho trusts its provider.

## The container stack

`deploy/` holds one image for all three services (cunho with SoftHSM2, so the keys are used through PKCS#11 and
never read from a file once imported), a compose file and a Caddyfile:

```bash
cp deploy/.env.example deploy/.env      # ISSUER_HOST, DEMO_HOST and the ports
docker compose -f deploy/compose.yaml up -d --build
```

The first start runs `init` once (`tools/deploy_init.py`): a PKI for the demo, a SoftHSM token per instance with
every signing key imported, each instance's operator token and secret key, the demo's secret key, and the operator
console's password, printed once and kept only as an scrypt hash. The PKI is made in the init container's own
memory and its signing keys go from there into the tokens, so they are never files on the volume the services
read; of its other private keys the volume gets only the two a service reads from a file (the key encrypted
requests are made to, and the demo wallet's key-attestation signer).

Read the password with `docker compose -f deploy/compose.yaml logs init`, then remove the container that printed
it, which takes its log with it: `docker compose -f deploy/compose.yaml rm -f init`. Until then whoever can read
Docker's logs on the host can read the password. Locally, with `ISSUER_HOST=issuer.localhost:8443` and `DEMO_HOST=demo.localhost:8443`, Caddy makes its
own certificates; its root is in the `caddy-data` volume (`/data/caddy/pki/authorities/local/root.crt`).

What the stack does:

- Caddy terminates TLS (1.3, or 1.2 with the suites BCP 195 recommends), routes `/pid` and `/course` and their
  well-known documents to each instance, answers 404 for the operator API, which only the demo service reaches,
  on the internal network, serves the IACA's CRL at `/crl/iaca.crl` on the issuer host, the distribution point
  the mdoc document signer names, and the course certificate's Type Metadata at `/vct/course-certificate/1` on
  the demo host. It keeps no access log, and leaves out of its log the lines it would otherwise write, with the
  client's address and the address asked for, when a request cannot be passed on or an answer is cut short: cunho
  promises never to record who fetched a status list. A service that is away therefore shows in
  `docker compose ps` and in its own log, not in Caddy's. It sets `Strict-Transport-Security` and
  `X-Content-Type-Options` on everything either host answers, its own files, 404s and errors included, offers
  HTTP/1.1 and HTTP/2 only (the compose file publishes no UDP port, which HTTP/3 needs), and closes a request
  whose headers or body do not arrive in time.
- The three services run as an unprivileged user on a read-only file system, with no capabilities, on a network
  that has no route out, and Docker keeps the newest 30 MB of what each prints. Only Caddy is on the outside
  network; it runs as root inside its container, as its image is made, with every capability dropped but the one
  to bind ports 80 and 443. That network carries IPv6 as well as IPv4, so a
  visitor's own address reaches Caddy whichever way they come: on a network without IPv6, Docker hands every
  IPv6 connection on from one internal address, and all IPv6 visitors then share one rate limit and one
  wrong-password lockout. It needs Docker Engine 27 or later, which gives the network its IPv6 subnet.
- The image takes its base by digest and every Python package by version and hash (`deploy/requirements.txt`),
  so a build is the same whenever it is made. cunho and the demo service run from their source in the image; no
  build tool is fetched to package them.
- Revocations show at the next status list publication (no jitter, a minute apart) and a demo credential lives
  30 days at most. Both are demo settings, not advice for a deployment.
- cunho runs in development mode, and says so in its log: it trusts wallet providers from a PEM file, which
  production refuses by design. For real wallets, put their providers' attestation signer certificates in a PEM
  file and set `WALLET_PROVIDER_ANCHORS` (and `WALLET_PROVIDER_CRLS`), and set `REDIRECT_URIS` to the redirect
  URIs those wallets register, as JSON from each wallet solution's identifier to its URIs. To check the status of
  those wallets' attestations too, the issuers need a route out to their providers' status lists: put them on the
  outside network and set `CUNHO_FETCH_HOSTS` and `CUNHO_WALLET_STATUS_ANCHORS` (docs/operations.md, "What cunho fetches").

### Every month

The demo PKI's certificates last 90 days and its CRLs 30. Renew both, then restart the three services: the
issuers for their new certificates, and the demo service for the demo wallet's new key-attestation signer (with the
old one in its memory every run of the demo wallet is refused):

```bash
docker compose -f deploy/compose.yaml run --rm init python tools/deploy_init.py /secrets /softhsm --renew \
  --public /public
docker compose -f deploy/compose.yaml restart cunho-pid cunho-course demo
```

Credentials issued before then no longer verify, which a demo can live with. Operator tokens, secret keys, the
stores and the audit logs are kept.

A job on the first of each month is not quite enough by itself. A CRL made on the 1st ends thirty days later: in a
month of 31 days that is a day before the next run, and with a CRL out of date the issuers refuse the demo wallet's
attestations. Renew every four weeks, or have a daily check renew when a CRL that ends first has less than two days
left: `pki/m3/wallet-providers.crl` and `pki/iaca.crl` last 30 days, while the first CRL in
`pki/all-wallet-providers.crl` lasts 90, so a check that reads only that file's first CRL never acts.

### Keeping the image current

Nothing in the image moves by itself: the base images and the Python packages are the ones the files name. To
take newer ones, make `deploy/requirements.txt` again (the command is at its top), check it
(`uvx pip-audit -r deploy/requirements.txt --require-hashes`), put the current digests of `python:3.13-slim` in
`deploy/Dockerfile` and of `caddy` in `deploy/compose.yaml`
(`docker buildx imagetools inspect python:3.13-slim` prints one), and build again:

```bash
docker compose -f deploy/compose.yaml up -d --build
```

Do it when a dependency or Caddy publishes a security fix, and otherwise with the monthly renewal.

A newer Caddy, or a change to `deploy/Caddyfile`, is tried before it is deployed. What Caddy answers and what it
writes to its log cannot be read off `deploy/Caddyfile` and `deploy/compose.yaml`. So a test holds by digest what
the Caddyfile says, its comments aside, and the lines of the `caddy` service, and fails when either changes. `python
tools/try_caddy.py` then starts that Caddy on that Caddyfile on this machine, with Docker (`--pull` fetches a Caddy
that is not on the machine yet). It reads what Caddy itself makes of the file, asks it what a client asks and what
one should not, and sees that every answer of the two hosts still carries the two headers and that Caddy wrote
nothing while it was asked. When that holds it prints the digests to put into `tests/test_deploy.py`. It prints none
when Caddy's reading holds something the tool has no rule for (a matcher or a handler it does not know, another line
for one of the two headers, another way of speaking to a service), nor when one of its fixed requests is no longer
answered as the stack answers today. It says which, and the tool or its cases are brought in line by hand before it
vouches for the change.

### Backups

The `pid-data` and `course-data` volumes hold each issuer's store and audit anchor; `secrets` and `softhsm` hold
the keys. A demo can be started again from nothing, so the simplest backup is none: `docker compose down -v` and
`up` give a fresh demo. Keep the audit anchors if you want the record.

## On a server

One small VM is enough (one vCPU, 2 GB of memory): cunho is a long-running server with a database, keys and a
background task, so it cannot run on a serverless platform. Point `ISSUER_HOST` and `DEMO_HOST` at it in DNS, set
them in `deploy/.env` without ports, and start the stack: Caddy gets certificates from Let's Encrypt. To serve the
page from another site, have that site rewrite `/api/*`, `/login/*`, `/consent/*`, `/operator*`, `/o/*`,
`/offers/*` and `/vct/*` to `DEMO_HOST` and set `DEMO_PUBLIC_URL` to its origin, so the demo accepts its forms and
its QR codes point there. Two things then need care, because every request reaches Caddy from that site and not
from the visitor. The limits below count by the address Caddy passes on: unless Caddy is told to trust that site
as a proxy (`trusted_proxies`) and to pass on the one address it gives (`header_up X-Forwarded-For {client_ip}` in
each `reverse_proxy`), all visitors count as one client, and five wrong passwords a minute from anyone keep the
operator out of the console. And the page's files are then served by that site, which has to send the page's
security headers itself (`SECURITY_HEADERS` in `src/cunho_demo/app.py`).

### What a visitor can use

The demo is open to anyone, so each client network gets a share and no more. A network is one IPv4 address or
one IPv6 /56, the block a home connection is usually given.

- 12 new offers a minute (`DEMO_SESSIONS_PER_MINUTE`) and 40 live sessions (`DEMO_SESSIONS_PER_CLIENT`): a
  network's own oldest session gives way to its new one. The demo holds 2000 sessions in all
  (`DEMO_MAX_SESSIONS`), each for half an hour; a new one is refused when it is full.
- 240 progress reads and actions a minute (`DEMO_POLLS_PER_MINUTE`), and 60 requests a minute to the login and
  consent screens (`DEMO_LOGINS_PER_MINUTE`).
- All visitors together get `DEMO_PROGRESS_PER_MINUTE` progress reads a minute of each issuer (3000, half of what
  cunho allows the operator token by default): past that a page is shown what was read last, so polling can make
  pages lag but cannot take the operator API from the offers, the logins and the console.
- The demo wallet runs for a visitor are counted by each issuer as that visitor's own, as a wallet app's requests
  are: the demo service names the visitor's address to the issuer, which takes it because the issuers trust the
  services on the internal network (`--forwarded-allow-ips` in the compose file).

A client with many networks can still fill the session table or slow the pages down for others; what stops that
is a limit in front of the stack (a firewall or a CDN that rate-limits), not the demo itself.

The course certificate's type is `https://foaap.app/vct/course-certificate/1`, and every credential carries the
digest of its Type Metadata, which wallets may fetch from that URL: the site at foaap.app must answer it, by the
`/vct/*` rewrite above or with the file itself (`demo/metadata/course/type_metadata/course-certificate-1.json`,
byte for byte, as `application/json`). Caddy answers it on `DEMO_HOST`, which is enough when `DEMO_HOST` is
foaap.app. A demo under another domain changes the `vct` in both files of `demo/metadata/course` (the SD-JWT VC
configuration and the Type Metadata) to a URL on that domain.
