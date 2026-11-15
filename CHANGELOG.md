# Changelog

## 0.1.0 (2026-11-15)

First public release.

- OpenID4VCI 1.0 issuer with the HAIP 1.0 profile: pre-authorized code with transaction codes, authorization code
  with PAR and PKCE, DPoP-bound tokens and server nonces, nonce endpoint, batch, deferred issuance, notifications,
  encrypted requests and responses, signed metadata.
- SD-JWT VC and ISO/IEC 18013-5 mdoc; the PID, and attestations including QEAA and PuB-EAA in the ETSI TS 119 472-1
  profile.
- Wallet and key attestations checked against the Commission's list of wallet providers, with revocation by CRL,
  OCSP and status list, and revocation chaining.
- Token Status Lists (JWT and CWT) signed by their own key, with a fresh index per credential.
- Signing keys in an HSM (PKCS#11) or a cloud KMS; tamper-evident audit log anchored outside the database; SQLite or
  PostgreSQL storage.
- The binder: 416 requirements traced to their source, component and test. `eudi-probe`, a wallet-like test client
  with 129 checks.
- Compatibility options for wallets in use (appended well-known path, Bearer tokens and a singular proof for plain
  attestation providers), each off by default and never for the PID.
- Demo service and container kit; live at demo.foaap.app.
- Licence: AGPL-3.0-only, with a commercial licence from FOAAP, Lda.
