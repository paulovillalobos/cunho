# Changelog

## 0.2.0 (2026-11-23)

- Operator scopes (`CUNHO_OPERATOR_SCOPES`): each operator token may be limited to some admin actions and some
  credential configurations, with its own rate limit.
- A token that makes offers or reports logins acts only on the subjects it made: reading, cancelling, revoking or
  erasing another system's subject, or deciding its review, is refused (403, `insufficient_scope`); the review list
  and revocation by person leave out what others made.
- Example metadata for a student card (`app.foaap.student_card_sd_jwt`, SD-JWT VC with Type Metadata) beside the
  course certificate, as the Moodle connector issues them.

Breaking changes, when upgrading from 0.1.0:

- Revoking by status list slot (`POST /admin/revocations` with `list` and `index`), which names no person and can
  revoke anyone's credential, is now a permission no token has unless its scope names it, the admin's included.
  To keep it for the admin token: `CUNHO_OPERATOR_SCOPES={"admin": {"permissions": ["offers", "offers.read",
  "offers.cancel", "logins", "revoke", "revoke.slot", "erase", "deferred", "audit"]}}`. Revocation by
  `subject_ref` or `person` is unchanged.
- A request with two `Authorization` headers is refused (401); 0.1.0 used the first.

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
