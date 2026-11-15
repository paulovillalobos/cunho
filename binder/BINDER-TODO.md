# Binder rows to add (failures seen in real issuers that no row covers yet)

From FAILURES-PLAIN-ENGLISH.md (2026-11-03). Each needs a source (spec section or engineering rule) before it becomes a row.
- Credential request/response encryption: OID4VCI 1.0 §8.2 / §8.3 (credential_request_encryption, credential_response_encryption, invalid_encryption_parameters). Seen: NL Wallet, Inji, Multipaz.
- Status list lifetime and rollover: Token Status List §5.1 exp/ttl, §13.7. Seen: swiyu 365-day exp, manual rollover.
- Absent PID values sent as empty strings: PID rulebook / 2977 annex (attribute present only if known). Seen: Bundesdruckerei.
- Certificate expiry monitoring for published signer/encryption certs: engineering rule (operational). Seen: EC Kotlin, EC age verification.
- Cache-Control: no-store on the token response: RFC 6749 §5.1. Seen: EC Python.
- Token response status 200: RFC 6749 §5.1. Seen: pyeudiw (201).
- Separate signing key for status-list tokens: engineering rule, key separation (ETSI 119 412-6 profile check). Seen: EC status list.
- Access-token signing algorithm in the HAIP set (ES256 minimum): HAIP §7. Seen: credo (Ed25519 default).
- Deployment bundle in step with service config: engineering rule (release integrity). Seen: walt.id.
- No release-candidate crypto libraries pinned in production: engineering rule. Seen: A-SIT.

Now rows: metadata content negotiation (OID4VCI §12.2.2) is `SPEC-OID4VCI-12.2.2-signed-format` (VCI.META.SIGNED_FORMAT, M3).
