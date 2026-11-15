# cunho

**The production credential issuer for the EU Digital Identity Wallet.**

From 24 December 2026 every EU Member State must offer its citizens a European Digital Identity Wallet, and every
organisation that puts credentials into those wallets must speak the same protocols, prove which wallet it is talking
to, and keep each credential revocable for as long as it lives (Regulation (EU) 2024/1183 and its implementing acts).

In practice the wallets do not yet speak the same language. Each one reads the specifications its own way, and an
issuer that works with one is refused by the next. We read and ran the code of the wallets and libraries people
actually use, found where each one breaks, and made cunho work with them without lowering its guard where the law
does not allow it. Most open-source issuers today are reference implementations, marked by their own authors as not
meant for production.

cunho is built to run in production, and built from the law down: every rule it enforces is traced to the article,
specification or standard it comes from, and to the test that proves it.

[Live demo](https://demo.foaap.app) · [Operating guide](docs/operations.md) · [Design](DESIGN.md) ·
[Security](SECURITY.md) · [Commercial licence](#use-cunho-in-production)

## Where it stands

| | |
|---|---|
| **Wallets** | Lissi and Paradym store cunho's credentials in their released apps. The EU reference OpenID4VCI library receives both the PID and the course certificate, in both formats. For each wallet we tested, we know where it departs from the specifications and how cunho meets it. |
| **Conformance** | All five OpenID Foundation conformance plans pass as expected: HAIP issuer and wallet, pre-authorized, and their mdoc variants. |
| **Tests** | 3,410 tests, written rule by rule, that run on every change. Then every refusal in the engine is removed or altered in turn, and the tests must catch each one. |
| **Rules** | 416 requirements from EU law, the Architecture and Reference Framework, HAIP, OpenID4VCI and the IETF drafts, each with its source, its strength, the component that enforces it, and its test (`binder/`). |
| **Security** | A line-by-line security review of the engine, the demo and the live service in November 2026: no critical finding; all three high findings fixed. |
| **Live** | [issuer.foaap.app](https://issuer.foaap.app) issues a PID and a course certificate to real wallets. |

## What it does

- **Protocols.** OpenID4VCI 1.0 with the HAIP 1.0 profile: pre-authorized code with transaction codes, authorization
  code with PAR and PKCE, DPoP-bound tokens with server nonces, nonce endpoint, batch, deferred issuance and
  notifications, encrypted requests and responses, signed metadata.
- **Credentials.** SD-JWT VC and ISO/IEC 18013-5 mdoc. The PID to the PID rulebook, and attestations of any kind,
  including qualified (QEAA) and public-body (PuB-EAA) attestations in the ETSI TS 119 472-1 profile.
- **Wallet trust.** Wallet and key attestations checked against the Commission's list of wallet providers (ETSI TS
  119 602), with revocation by CRL, OCSP and status list; a PID is only issued to a key whose attestation shows it is held
  in the wallet's secure cryptographic device, at the required level.
- **Revocation.** Token Status Lists in JWT and CWT form, signed by their own key, with a fresh index for every
  credential; revoking a wallet revokes what was issued to it.
- **Keys.** HSM through PKCS#11, or a cloud KMS. Production refuses to start with a key in a file.
- **Audit.** A tamper-evident log, chained and anchored outside the database, that the operator can verify at any
  time.
- **Privacy.** No access log of who fetches a status list, data minimisation in what is stored, erasure on request.
- **Operations.** SQLite for one host, PostgreSQL for several. One container stack for the whole service
  (`deploy/`).
- **Real wallets.** Options for wallets that do not follow the specification to the letter, each off by default,
  each documented, and never for the PID.

## Try it

Scan a QR code at [demo.foaap.app](https://demo.foaap.app) with an EU wallet app, or run everything on your machine:

```bash
python3.12 -m venv .venv && .venv/bin/pip install -e '.[demo]'
.venv/bin/python tools/demo_local.py out/demo --view-port 8099
```

Then open `https://localhost:8100`. It runs a PID provider, a course certificate provider and the demo page, with
a throwaway development PKI, and nothing leaves your machine. [docs/DEMO.md](docs/DEMO.md) has the details, and
[docs/operations.md](docs/operations.md) shows how to run cunho on its own and configure it for production.

## How it is built

Rules reach developers as lists of sentences, and so they end up in the wrong place, or nowhere. cunho gives every
rule three things: its strength, checked against the original text; the component that enforces it; and a test
that proves it. Every refusal names its rule, so an operator can tell why a wallet was turned away and a reviewer
can find the line of law behind it. [DESIGN.md](DESIGN.md) describes the issuer component by component.

`probe/` is `eudi-probe`, a test client that behaves like a wallet and holds any running issuer to the same rules:
129 checks, each written from the specification it tests.

## Work upstream

We read the code the wallets run, run it against cunho, and fix what we find at its source:

- EU reference OpenID4VCI library: refuse a batch whose proofs share a key
  ([eudi-lib-jvm-openid4vci-kt#633](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt/pull/633)).
- Credo, OpenWallet Foundation: honour `verifyCredentialStatus` for received SD-JWT VCs
  ([credo-ts#3262](https://github.com/openwallet-foundation/credo-ts/pull/3262)).
- Italy's IO wallet: proof audience, tested against cunho
  ([io-react-native-wallet#390](https://github.com/pagopa/io-react-native-wallet/pull/390)).
- Sphereon SSI-SDK: X.509 chain validation of HAIP credentials
  ([SSI-SDK#404](https://github.com/Sphereon-Opensource/SSI-SDK/issues/404)).

## Where it is going

- **Certification-ready evidence.** A report that maps each obligation of the implementing acts to the code and the
  test that meets it, in the form a conformity assessment body reads.
- **Qualified attestations for trust service providers.** cunho as the issuance engine behind a QTSP's QEAA service,
  in its own infrastructure and HSM.
- **Education.** Course certificates and diplomas from Moodle and Open edX straight into the wallet, through plugins
  that call cunho.
- **Interoperability.** Every major wallet tested against cunho as it changes, with where it breaks and why.

## Use cunho in production

cunho is open source under the GNU Affero General Public License v3 (`AGPL-3.0-only`). You can use, study, change and
share it; if you change it and offer it to others over a network, you share your changes under the same licence.

FOAAP, Lda also licenses cunho commercially, for organisations that build it into their own products or services
without the AGPL's obligations, with support, maintenance, security updates and help with certification. Write to
[paulo@foaap.app](mailto:paulo@foaap.app).

## Contributing and security

Contributions are welcome under a contributor licence agreement: see [CONTRIBUTING.md](CONTRIBUTING.md). Report
vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes; please do not open public issues for them.

## Licence

AGPL-3.0-only, with a commercial licence available from FOAAP, Lda. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The
files in `src/cunho/metadata_config/` are copied unchanged from the EU Digital Identity Wallet issuer reference
implementation and remain under the Apache License 2.0 (see `LICENSE` and `NOTICE` there).

---

Built by [FOAAP, Lda](https://tecnologia.foaap.app), Porto, Portugal.
