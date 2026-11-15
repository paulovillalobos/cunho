# Protocol-spec items from CHECKLIST.md not already carried by an ARF/eIDAS row (S_ROWS), and the rows M3 and M4 add
# (M3_ROWS, M4_ROWS).
# (binder_id, source_ref, binds, testability, probes, new, rule, depends, topic, notes)

V = "OpenID4VCI 1.0 Final (16 Sep 2025) "
D = "RFC 9449 (DPoP) "
H = "OpenID4VC HAIP 1.0 Final "
T = "draft-ietf-oauth-status-list-21 "
S = "SD-JWT VC draft-23 "
I = "ISO/IEC 18013-5 "

S_ROWS = [
    # OpenID4VCI
    ("SPEC-OID4VCI-4.1.1-offer", V + "§4.1.1", "PP;AP", "blackbox", "T01", "offer_shape", "VCI.OFFER.SHAPE", "ARF-ISSU_01a", "ISS",
     "Credential offer with pre-authorized_code grant and tx_code object well-formed. T01 only redeems it."),
    ("SPEC-OID4VCI-4.1.1-preauth-single-use", V + "§4.1.1", "PP;AP", "blackbox", "T04", "", "VCI.TOKEN.PREAUTH_SINGLE_USE", "ARF-ISSU_01a", "ISS",
     "Pre-authorized code redeemable once."),
    ("SPEC-OID4VCI-6.1-token-preauth", V + "§6, §6.1", "PP;AP", "blackbox", "T01;T02", "", "VCI.TOKEN.PREAUTH_REQUEST", "ARF-ISSU_01a", "ISS",
     "Token request with pre-authorized_code; missing code -> invalid_request."),
    ("SPEC-OID4VCI-6.3-unknown-code", V + "§6.3", "PP;AP", "blackbox", "T03", "", "VCI.TOKEN.INVALID_GRANT", "ARF-ISSU_01a", "ISS",
     "Unknown pre-authorized_code -> invalid_grant."),
    ("SPEC-OID4VCI-6.3-tx_code", V + "§6.3", "PP;AP", "blackbox", "T05;T06;T07", "", "VCI.TOKEN.TX_CODE_ERRORS", "ARF-ISSU_01a", "ISS",
     "tx_code missing -> invalid_request; wrong -> invalid_grant; unexpected -> invalid_request."),
    ("SPEC-OID4VCI-7.1-nonce-endpoint", V + "§7, §7.1", "PP;AP", "blackbox", "N01;N03;N04", "", "VCI.NONCE.ENDPOINT", "TS3-§2.2.2.2d", "PROOF",
     "POST nonce endpoint returns fresh c_nonce; wrong method refused without 5xx."),
    ("SPEC-OID4VCI-7.2-no-store", V + "§7.2", "PP;AP", "blackbox", "N02", "", "VCI.NONCE.NO_STORE", "SPEC-OID4VCI-7.1-nonce-endpoint", "PROOF",
     "Nonce response Cache-Control: no-store."),
    ("SPEC-OID4VCI-8.2-identifier-xor", V + "§8.2", "PP;AP", "blackbox", "C07;C08", "", "VCI.CRED.IDENTIFIER_XOR", "ARF-ISSU_01a", "ISS",
     "credential_identifier XOR credential_configuration_id."),
    ("SPEC-OID4VCI-8.2-proofs-only", V + "§8.2", "PP;AP", "blackbox", "C06;C11;C12;C13", "", "VCI.CRED.PROOFS_SHAPE", "ARF-ISSU_01a", "PROOF",
     "Only `proofs` (singular `proof` gone); one proof type; non-empty; required when binding."),
    ("SPEC-OID4VCI-8.3-response", V + "§8.3", "PP;AP", "blackbox", "C01;C14", "", "VCI.CRED.RESPONSE_SHAPE", "ARF-ISSU_01a", "ISS",
     "200 with credentials array (or 202 deferred); notification_id string; none on errors."),
    ("SPEC-OID4VCI-8.3.1.2-error-codes", V + "§8.3.1.2", "PP;AP", "blackbox", "C09;C10;R06", "", "VCI.CRED.ERROR_CODES", "ARF-ISSU_01a", "ISS",
     "Credential error codes (unknown_credential_configuration, unknown_credential_identifier, invalid_proof, invalid_nonce, ...); malformed bodies 400 not 5xx."),
    ("SPEC-OID4VCI-9-deferred", V + "§9", "PP;AP", "blackbox", "R05;D01;D02;D03;D04;D05", "", "VCI.DEFER.TRANSACTION_ID", "ARF-ISSU_01a", "ISS",
     "Deferred endpoint: unknown transaction_id -> invalid_transaction_id. R05 checks only unauthenticated calls."),
    ("SPEC-OID4VCI-11-notification", V + "§11.1, §11.3", "PP;AP", "blackbox", "C15;R04;D01;C17;C18", "", "VCI.NOTIF.VALIDATION", "ARF-ISSU_01a", "ISS",
     "Notification events credential_accepted/failure/deleted; 204; invalid_notification_id."),
    ("SPEC-OID4VCI-12.2.2-well-known", V + "§12.2.2", "PP;AP", "blackbox", "M01", "", "VCI.META.WELL_KNOWN_PATH", "ARF-ISSU_01a", "META",
     "Metadata at the path-inserted well-known URL."),
    ("SPEC-OID4VCI-12.2.4-metadata", V + "§12.2.4", "PP;AP", "blackbox", "M02;M03;M04;M07;M16", "", "VCI.META.FIELDS", "ARF-ISSU_01a", "META",
     "credential_issuer, credential_endpoint (https), format per config, proof types iff binding, no leaked internal config."),
    ("SPEC-OID4VCI-12.2.4-batch_size", V + "§12.2.4", "PP;AP", "blackbox", "M09;C04;C05", "", "BATCH.SUPPORT", "ARF-ISSU_64", "BATCH",
     "batch_credential_issuance.batch_size >= 2; proofs > batch_size refused, not truncated."),
    ("SPEC-OID4VCI-12.2.4-key_attestations_required", V + "§12.2.4", "PP;AP", "blackbox", "M10;S14", "", "META.KEY_STORAGE_LEVELS", "ARF-ISSU_27d", "META",
     "key_attestations_required is an object and is enforced."),
    ("SPEC-OID4VCI-A.2-mso_mdoc", V + "App. A.2 (A.2.2, A.2.4)", "PP;AP", "blackbox", "M15;C16;I02;I05", "", "FMT.MDOC.CONFIG_AND_ENCODING", "ARF-ISSU_12", "FMT",
     "mso_mdoc config carries doctype; credential is base64url CBOR IssuerSigned."),
    ("SPEC-OID4VCI-A.3-dc+sd-jwt", V + "App. A.3 (A.3.2)", "PP;AP", "blackbox", "M15;C02", "", "FMT.SDJWT.CONFIG_AND_ENCODING", "ARF-ISSU_12", "FMT",
     "dc+sd-jwt config carries vct; credential is a well-formed SD-JWT VC."),
    ("SPEC-OID4VCI-D-key-attestation", V + "App. D", "PP;AP", "fixture", "", "", "KA.VERIFY", "ARF-WUA_11a", "PROOF",
     "KA shape: typ key-attestation+jwt, attested_keys, exp required with jwt proof. Needs a KA fixture."),
    ("SPEC-OID4VCI-F.1-typ", V + "App. F.1", "PP;AP", "blackbox", "S06", "", "VCI.F1.PROOF_TYP", "", "PROOF",
     "typ openid4vci-proof+jwt."),
    ("SPEC-OID4VCI-F.1-alg", V + "App. F.1", "PP;AP", "blackbox", "S05;M08", "", "VCI.F1.PROOF_ALG_ASYMMETRIC", "ARF-OIA_03", "PROOF",
     "alg not none/symmetric (advertised and accepted)."),
    ("SPEC-OID4VCI-F.1-key-header", V + "App. F.1", "PP;AP", "blackbox", "", "proof_key_header_exclusive", "VCI.F1.KEY_HEADER_EXCLUSIVE", "", "PROOF",
     "kid / jwk / x5c mutually exclusive in the proof header."),
    ("SPEC-OID4VCI-F.1-aud", V + "App. F.1", "PP;AP", "blackbox", "S02", "", "VCI.F1.PROOF_AUD", "", "PROOF",
     "aud = Credential Issuer identifier."),
    ("SPEC-OID4VCI-F.1-iat", V + "App. F.1, F.4, §13.8", "PP;AP", "blackbox", "S08", "", "VCI.F1.PROOF_IAT", "", "PROOF",
     "iat present and fresh."),
    ("SPEC-OID4VCI-F.1-nonce", V + "App. F.1, §8.3.1.2, §13.8", "PP;AP", "blackbox", "S03;S04;S15", "", "VCI.NONCE.C_NONCE_VALID", "TS3-§2.2.2.2d", "PROOF",
     "nonce required when a nonce endpoint exists; unknown -> invalid_nonce; no reuse."),
    ("SPEC-OID4VCI-F.1-iss-anon", V + "App. F.1", "PP;AP", "blackbox", "", "proof_iss_omitted_preauth_accepted", "VCI.F1.PROOF_ISS_ANON_PREAUTH", "", "PROOF",
     "iss omitted for anonymous pre-authorized flow must be accepted."),
    ("SPEC-OID4VCI-F.4-verification", V + "App. F.4", "PP;AP", "blackbox", "S01;S07", "", "VCI.F4.PROOF_SIGNATURE", "", "PROOF",
     "Proof signature verifies; no private key in jwk."),
    # DPoP
    ("SPEC-RFC9449-4.3-3", D + "§4.3(3)", "PP;AP (AS + CI)", "blackbox", "T15", "", "DPOP.JTI_PRESENT", "SPEC-HAIP-4-dpop", "OAUTH", "jti present."),
    ("SPEC-RFC9449-4.3-4", D + "§4.3(4), §11.5", "PP;AP (AS + CI)", "blackbox", "T09", "", "DPOP.TYP", "SPEC-HAIP-4-dpop", "OAUTH", "typ dpop+jwt."),
    ("SPEC-RFC9449-4.3-5", D + "§4.2, §4.3(5)", "PP;AP (AS + CI)", "blackbox", "T08", "", "DPOP.ALG_ASYMMETRIC", "SPEC-HAIP-4-dpop", "OAUTH", "Asymmetric alg only."),
    ("SPEC-RFC9449-4.3-6", D + "§4.3(6)", "PP;AP (AS + CI)", "blackbox", "T14", "", "DPOP.SIGNATURE", "SPEC-HAIP-4-dpop", "OAUTH", "Signature verifies with header jwk."),
    ("SPEC-RFC9449-4.3-7", D + "§4.3(7)", "PP;AP (AS + CI)", "blackbox", "T10", "", "DPOP.NO_PRIVATE_KEY", "SPEC-HAIP-4-dpop", "OAUTH", "jwk has no private key."),
    ("SPEC-RFC9449-4.3-8", D + "§4.3(8)", "PP;AP (AS + CI)", "blackbox", "T11", "", "DPOP.HTM", "SPEC-HAIP-4-dpop", "OAUTH", "htm matches."),
    ("SPEC-RFC9449-4.3-9", D + "§4.3(9)", "PP;AP (AS + CI)", "blackbox", "T12", "", "DPOP.HTU", "SPEC-HAIP-4-dpop", "OAUTH", "htu matches."),
    ("SPEC-RFC9449-4.3-11", D + "§4.3(11), §11.1", "PP;AP (AS + CI)", "blackbox", "T13", "", "DPOP.IAT_WINDOW", "SPEC-HAIP-4-dpop", "OAUTH", "iat within window."),
    ("SPEC-RFC9449-4.3-12", D + "§4.3(12), §7", "PP;AP (CI)", "blackbox", "S11", "", "DPOP.ATH", "SPEC-HAIP-4-dpop", "OAUTH", "ath required at resource (credential) endpoint."),
    ("SPEC-RFC9449-11.1-jti-replay", D + "§11.1", "PP;AP (AS + CI)", "blackbox", "S13", "", "DPOP.JTI_REPLAY", "SPEC-HAIP-4-dpop", "OAUTH", "Replayed jti refused."),
    ("SPEC-RFC9449-7.1-key-binding", D + "§6, §7.1", "PP;AP (CI)", "blackbox", "S12;A21", "", "DPOP.KEY_BOUND_TO_TOKEN", "SPEC-HAIP-4-dpop", "OAUTH", "Proof key = token-bound key (cnf.jkt)."),
    ("SPEC-RFC9449-5-token-type", D + "§5", "PP;AP (AS)", "blackbox", "T01", "", "DPOP.TOKEN_TYPE", "SPEC-HAIP-4-dpop", "OAUTH", "token_type DPoP."),
    ("SPEC-RFC9449-7.1-scheme", D + "§7.1", "PP;AP (CI)", "blackbox", "S10", "", "DPOP.AUTH_SCHEME", "SPEC-HAIP-4-dpop", "OAUTH", "Authorization: DPoP scheme requires a DPoP header."),
    ("SPEC-RFC9449-7.2-no-bearer-downgrade", D + "§7.2", "PP;AP (CI)", "blackbox", "S09", "", "DPOP.NO_BEARER_DOWNGRADE", "SPEC-HAIP-4-dpop", "OAUTH", "DPoP-bound token sent as Bearer refused."),
    ("SPEC-RFC9449-8-9-nonces", D + "§8, §9", "PP;AP (AS + CI)", "blackbox", "", "dpop_nonce_supported", "DPOP.SERVER_NONCE", "SPEC-HAIP-4-dpop", "OAUTH",
     "Server-provided DPoP nonce (use_dpop_nonce) handled correctly. Optional in RFC 9449; grade as hardening."),
    # HAIP
    ("SPEC-HAIP-4-auth-code-par", H + "§4", "PP;AP (AS)", "blackbox", "M14;A02", "", "OAUTH.AUTH_CODE_AND_PAR", "ARF-ISSU_01a", "OAUTH",
     "Authorization code flow MUST; PAR when the authorization endpoint is used."),
    ("SPEC-HAIP-4-pkce", H + "§4 (RFC 7636)", "PP;AP (AS)", "blackbox", "M13;A07;A08", "", "OAUTH.PKCE_S256", "ARF-ISSU_01a", "OAUTH", "PKCE S256; plain not offered."),
    ("SPEC-HAIP-4-dpop", H + "§4", "PP;AP (AS + CI)", "blackbox", "M12;T01", "", "OAUTH.DPOP_REQUIRED", "ARF-ISSU_01a", "OAUTH", "DPoP MUST; asymmetric algs advertised."),
    ("SPEC-HAIP-4-batch-metadata", H + "§4", "PP;AP", "blackbox", "M09", "", "BATCH.SUPPORT", "ARF-ISSU_64", "BATCH", "Batch issuance metadata."),
    ("SPEC-HAIP-4.1-scope", H + "§4.1", "PP;AP", "blackbox", "M06", "", "VCI.META.SCOPE_PER_CONFIG", "ARF-ISSU_01a", "META", "scope for every credential configuration."),
    ("SPEC-HAIP-4.1-nonce-endpoint", H + "§4.1", "PP;AP", "blackbox", "M05", "", "VCI.META.NONCE_ENDPOINT_WHEN_BINDING", "ARF-ISSU_01a", "META", "nonce_endpoint when any config needs key binding."),
    ("SPEC-HAIP-4.5.1-ka-x5c", H + "§4.5.1", "PP;AP", "blackbox", "W10", "", "KA.CHAIN_TO_WP_LIST", "ARF-WUA_11a", "PROOF",
     "KA carries x5c; signing cert not self-signed (self-signed KA must be refused)."),
    ("SPEC-HAIP-6.1-exp-or-status", H + "§6.1", "PP;AP", "blackbox", "C02", "", "FMT.SDJWT.EXP_OR_STATUS", "ARF-ARB_01b", "FMT",
     "SD-JWT VC has exp and/or status. Weaker than PID rule nbf+exp (PIDRB-§4.1.1d)."),
    ("SPEC-HAIP-6.1-cnf-jwk", H + "§6.1", "PP;AP", "blackbox", "C02", "", "BIND.DEVICE_BOUND", "ARF-ISSU_17", "PROOF", "cnf.jwk holds the holder key."),
    ("SPEC-HAIP-6.1.1-x5c", H + "§6.1.1", "PP;AP", "blackbox", "C02", "", "FMT.SDJWT.X5C_NO_ANCHOR", "ARF-ARB_01b", "FMT",
     "INCONSISTENCY with EIDAS-2977-Annex§4.2-x5u-x5tS256: HAIP wants x5c (issuer chain, trust anchor excluded); the 2026/1731 PID annex wants x5u + x5t#S256. Emit both."),
    # Token Status List
    ("SPEC-TSL-4.1-encoding", T + "§4.1", "PP;AP", "blackbox", "C03", "", "STATUS.TSL.ENCODING", "ARF-VCR_11a", "STAT", "bits 1/2/4/8; ZLIB/DEFLATE lst."),
    ("SPEC-TSL-5.1-token-claims", T + "§5.1", "PP;AP", "blackbox", "C03", "", "STATUS.TSL.TOKEN_CLAIMS", "ARF-VCR_11a", "STAT", "typ statuslist+jwt; sub = uri; iat; exp and ttl."),
    ("SPEC-TSL-6.2-reference", T + "§6.2", "PP;AP", "blackbox", "C03", "", "STATUS.TSL.REFERENCE", "ARF-VCR_11a;EIDAS-2979-AnnexII-EAA-5.2.10.1-06", "STAT", "status.status_list.idx/uri in the credential."),
    ("SPEC-TSL-8.2-media-type", T + "§8.2", "PP;AP", "blackbox", "C03", "", "STATUS.TSL.MEDIA_TYPE", "ARF-VCR_11a", "STAT", "Content-Type application/statuslist+jwt."),
    ("SPEC-TSL-13.2-fresh-entry", T + "§13.2", "PP;AP", "blackbox", "C04", "", "STATUS.TSL.FRESH_ENTRY_PER_CREDENTIAL", "ARF-ISSU_35", "PRIV", "Fresh status entry per (batch) credential."),
    ("SPEC-TSL-13.3-no-double-allocation", T + "§13.3", "PP;AP", "blackbox", "C04", "status_idx_random", "STATUS.TSL.NO_DOUBLE_ALLOCATION", "ARF-VCR_17", "PRIV",
     "No index allocated twice (across issuances, not just within a batch)."),
    # SD-JWT VC
    ("SPEC-SDJWTVC-typ", S + "§2.2", "PP;AP", "blackbox", "C02", "", "FMT.SDJWT.TYP", "ARF-ARB_01b", "FMT", "typ dc+sd-jwt."),
    ("SPEC-SDJWTVC-vct", S + "§2.2", "PP;AP", "blackbox", "C02;M15", "", "FMT.SDJWT.VCT_REQUIRED", "ARF-ARB_01b", "FMT", "vct required and equal to the configuration's."),
    ("SPEC-SDJWTVC-never-sd", S + "§2.2.2.3", "PP;AP", "blackbox", "C02", "", "FMT.SDJWT.NEVER_SD_CLAIMS", "EIDAS-2977-Annex§4.2-SD", "FMT",
     "iss/nbf/exp/cnf/vct/status never selectively disclosable. Bounds PID_21 'all claims SD'."),
    # ISO mdoc
    ("SPEC-ISO18013-5-issuerauth-x5chain", I + "§9.1.2; OID4VCI App. A.2.4", "PP;AP", "blackbox", "C16;I01", "", "FMT.MDOC.ISSUERAUTH_X5CHAIN", "ARF-ISSU_12", "FMT",
     "INCONSISTENCY with EIDAS-2977-Annex§4.1-x5u-x5t: ISO/probe expect x5chain (label 33) in issuerAuth; 2026/1731 PID annex wants x5u + x5t in the protected header. Emit both."),
    ("SPEC-ISO18013-5-mso-verify", I + "MSO / COSE_Sign1 (CHECKLIST)", "PP;AP", "blackbox", "C16;I01;I02;I04", "", "FMT.MDOC.MSO_VERIFIES", "ARF-ISSU_12", "FMT",
     "COSE_Sign1 ES256 (-7) verifies; validityInfo present; digest per element matches; deviceKeyInfo present."),
    # generic HTTP / OAuth robustness
    ("SPEC-RFC8414-3-as-metadata", "RFC 8414 §3, §3.3", "PP;AP (AS)", "blackbox", "M11", "", "OAUTH.AS_METADATA", "ARF-ISSU_01a", "OAUTH", "AS metadata at RFC 8414 path; issuer matches."),
    ("SPEC-RFC6749-5.2-token-errors", "RFC 6749 §5.2", "PP;AP (AS)", "blackbox", "R01", "", "OAUTH.TOKEN_ERROR_BODY", "ARF-ISSU_01a", "OAUTH", "Malformed token requests -> 400 + OAuth error, never 5xx."),
    ("SPEC-RFC6750-3-bearer-challenge", "RFC 6750 §3, §3.1", "PP;AP (CI)", "blackbox", "R02;R03;R04;R05;D03", "", "OAUTH.RESOURCE_401_CHALLENGE", "ARF-ISSU_01a", "OAUTH",
     "Missing/forged token -> 401 with WWW-Authenticate (invalid_token) on credential, notification, deferred endpoints."),
    ("SPEC-RFC9110-15.5.6-methods", "RFC 9110 §15.5.6", "PP;AP", "blackbox", "N04;R07", "", "HTTP.METHOD_NOT_ALLOWED", "ARF-ISSU_01a", "ISS", "Wrong HTTP methods refused without 5xx."),
]

# Rules the M3 plan (authorization code flow, wallet attestation, trusted lists, signed metadata, refresh
# tokens) needs and the rows above do not carry, accepted as binder rows by the owner on 2026-11-05. HAIP §4
# asks for "the provisions of [FAPI2_Security_Profile] that are applicable"; without these rows
# OAUTH.AUTH_CODE_AND_PAR would stand for about 30 checks behind one rule id. They are not from CHECKLIST.md,
# so each names its own layer.
# (binder_id, layer, source_ref, binds, testability, probes, new, rule, depends, topic, notes)
F = "FAPI 2.0 Security Profile Final (Feb 2025) "
A7 = "draft-ietf-oauth-attestation-based-client-auth-07 "

M3_ROWS = [
    # authorization endpoint, PAR and PKCE
    ("SPEC-FAPI2-5.3.2.2-par-required", "spec", F + "§5.3.2.2 items 2-4; RFC 9126 §4, §5", "PP;AP (AS)", "blackbox", "M14;A06",
     "", "OAUTH.PAR_REQUIRED", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "Authorization requests without a pushed request_uri are refused (invalid_request); "
     "require_pushed_authorization_requests is true."),
    ("SPEC-RFC9126-2-par-request", "spec", "RFC 9126 §2, §2.1, §2.2, §2.3", "PP;AP (AS)", "fixture", "", "",
     "OAUTH.PAR_REQUEST", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "PAR is a form-encoded POST with client authentication; request_uri inside the push is refused; the push is "
     "validated as the authorization endpoint would validate it; the answer is 201 with request_uri and expires_in."),
    ("SPEC-RFC9126-2.2-request-uri-once", "spec", "RFC 9126 §2.2, §4, §7.3; " + F + "§5.3.2.2 item 12", "PP;AP (AS)",
     "fixture", "A04;A05", "", "OAUTH.PAR_REQUEST_URI_ONCE", "SPEC-RFC9126-2-par-request", "OAUTH",
     "request_uri is unguessable, bound to the client_id that pushed it, spent when a login it started completes "
     "(FAPI 2.0 SP §5.3.2.2 note 3; it can be opened again until then, a bounded number of times), and expires in "
     "under 600 s."),
    ("SPEC-RFC7636-4-pkce-verifier", "spec", "RFC 7636 §4.1, §4.4.1, §4.6", "PP;AP (AS)", "fixture", "A07;A11", "",
     "OAUTH.PKCE_VERIFIER", "SPEC-HAIP-4-pkce", "OAUTH",
     "code_verifier is 43-128 unreserved characters; a missing code_challenge gives invalid_request; a verifier that "
     "is missing or does not match gives invalid_grant."),
    ("SPEC-FAPI2-5.3.2.1-code-once-60s", "spec", F + "§5.3.2.1 item 11, §5.3.2.2 item 9; RFC 6749 §4.1.2",
     "PP;AP (AS)", "fixture", "A13", "", "OAUTH.CODE_ONCE_60S", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "The authorization code is single use and lives at most 60 s; a second use revokes what the first use yielded."),
    ("SPEC-RFC9449-10-code-dpop-bound", "spec", "RFC 9449 §10, §10.1; " + F + "§5.3.2.1 item 12", "PP;AP (AS)",
     "fixture", "", "", "OAUTH.CODE_DPOP_BOUND", "SPEC-HAIP-4-dpop", "OAUTH",
     "The code is bound to dpop_jkt or to the DPoP key shown at PAR; a token request with another key is refused, "
     "and so is a PAR whose dpop_jkt and DPoP proof name different keys."),
    ("SPEC-RFC9700-2.1-redirect-exact", "spec", "RFC 9700 §2.1; " + F + "§5.3.2.2 items 6, 8; RFC 6749 §4.1.3",
     "PP;AP (AS)", "fixture", "A09;A12", "", "OAUTH.REDIRECT_URI_EXACT", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "redirect_uri is required in PAR and compared as an exact string; the token request repeats it exactly; no "
     "http except loopback. Wallets are not pre-registered: what it is matched against is owner decision 5."),
    ("SPEC-RFC9207-2-iss", "spec", "RFC 9207 §2, §2.3, §3; " + F + "§5.3.2.2 item 7", "PP;AP (AS)", "fixture", "A03", "",
     "OAUTH.AUTHZ_RESPONSE_ISS", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "iss is in every authorization response, error responses included; the AS metadata says "
     "authorization_response_iss_parameter_supported: true."),
    ("SPEC-FAPI2-5.3.2.2-response-type-code", "spec", F + "§5.3.2.2 item 1", "PP;AP (AS)", "fixture", "A10", "",
     "OAUTH.RESPONSE_TYPE_CODE", "SPEC-HAIP-4-auth-code-par", "OAUTH", "Only response_type=code."),
    ("SPEC-FAPI2-5.3.2.2-no-307", "spec", F + "§5.3.2.2 items 10-11", "PP;AP (AS)", "fixture", "", "",
     "OAUTH.REDIRECT_303", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "Never redirect with 307; answer a form POST with 303."),
    ("SPEC-FAPI2-5.3.4-no-token-in-query", "spec", F + "§5.3.4 item 2; RFC 6750 §2.3", "PP;AP (CI)", "blackbox", "A18",
     "", "OAUTH.NO_TOKEN_IN_QUERY", "SPEC-HAIP-4-dpop", "OAUTH",
     "An access token in the query string is refused."),
    ("SPEC-RFC6749-4.1.2.1-access-denied", "spec", "RFC 6749 §4.1.2.1", "PP;AP (AS)", "fixture", "A15", "",
     "OAUTH.ACCESS_DENIED", "SPEC-HAIP-4-auth-code-par", "OAUTH",
     "A user who cancels or fails the login gets an access_denied redirect with state and iss, never a 500."),
    # wallet attestation as client authentication
    ("SPEC-HAIP-4.4.1-wia-required", "spec", "OpenID4VC HAIP 1.0 Final §4.4.1; " + A7 + "§6.3, §6.4, §10.3",
     "PP;AP (AS)", "blackbox", "W01;W09", "", "WIA.REQUIRED_AT_PAR_AND_TOKEN",
     "EIDAS-2979-AnnexIb-TR-WIA-3;ARF-WUA_25", "WIA",
     "Client attestation at PAR and at every token request (code and refresh). The issuer side of "
     "EIDAS-2979-AnnexIb-TR-WIA-3, which binds the wallet."),
    ("SPEC-HAIP-4.4.1-client-id-sub", "spec", "OpenID4VC HAIP 1.0 Final §4.4.1; " + A7 + "§6.3, §6.4, §9 step 13",
     "PP;AP (AS)", "fixture", "A14;W06", "", "WIA.CLIENT_ID_IS_SUB", "SPEC-HAIP-4.4.1-wia-required", "WIA",
     "client_id equals the attestation sub, and the PoP iss."),
    ("SPEC-ABCA07-9-pop-fresh", "spec", A7 + "§5.2, §9 steps 9-10, §12.1; " + F + "§5.3.2.1 items 8, 13",
     "PP;AP (AS)", "fixture", "W07;W08", "", "WIA.POP_FRESH", "SPEC-HAIP-4.4.1-wia-required", "WIA",
     "PoP aud is the issuer identifier only; iat up to 10 s ahead is accepted and more than 60 s ahead refused; "
     "jti is single use."),
    ("SPEC-ABCA07-9-cnf-public", "spec", A7 + "§5.1, §9 step 6", "PP;AP (AS)", "fixture", "", "", "WIA.CNF_PUBLIC",
     "SPEC-HAIP-4.4.1-wia-required", "WIA", "cnf.jwk is a public key on an allowed curve."),
    ("ARF-WUA_25-not-revoked", "arf", "ARF 3.0.0 HLR WUA_25 (second sentence); TS3 v1.5.2 §2.3.1, §2.4.3", "PP;AP",
     "fixture", "", "", "WIA.CLIENT_STATUS", "ARF-WUA_25;EIDAS-1569-AnnexI-REQ-EAASP-4.2.2.3-03", "WIA",
     "client_status is present and its Token Status List entry is VALID at issuance. The 24-hour re-check of live "
     "PIDs stays with revocation chaining (M4)."),
    # OpenID4VCI on the authorization code flow
    ("SPEC-OID4VCI-6.2-authz-details", "spec", "OpenID4VCI 1.0 Final (16 Sep 2025) §5.1.1, §6.1.1, §6.2, §8.2",
     "PP;AP (AS + CI)", "fixture", "A19", "", "VCI.AUTHZ_DETAILS", "SPEC-OID4VCI-8.2-identifier-xor", "ISS",
     "authorization_details of type openid_credential with credential_configuration_id; the token response returns "
     "credential_identifiers, and the credential request then uses credential_identifier (M2 refuses every "
     "credential_identifier, so that refusal changes)."),
    ("SPEC-OID4VCI-5.1.2-scope", "spec", "OpenID4VCI 1.0 Final (16 Sep 2025) §5.1.2; OpenID4VC HAIP 1.0 Final §4.1, §4.3",
     "PP;AP (AS)", "blackbox", "M06;M22", "", "VCI.SCOPE_TO_CONFIG", "SPEC-HAIP-4.1-scope", "ISS",
     "Scope-only requests work; unknown scopes are ignored; authorization_details wins over a scope for the same "
     "configuration; every configuration's scope is unique, checked at startup."),
    ("SPEC-OID4VCI-5.1.3-issuer-state", "spec", "OpenID4VCI 1.0 Final (16 Sep 2025) §4.1.1, §5.1.3", "PP;AP (AS)",
     "fixture", "A20", "", "VCI.ISSUER_STATE", "SPEC-HAIP-4.2-offer-auth-code", "ISS",
     "issuer_state from an issuer-initiated offer is single use, bound to its offer, and never trusted to identify "
     "the user."),
    ("SPEC-HAIP-4.2-offer-auth-code", "spec", "OpenID4VC HAIP 1.0 Final §4.2; OpenID4VCI 1.0 Final §4.1.1", "PP;AP",
     "blackbox", "A20", "", "VCI.OFFER.AUTH_CODE_GRANT", "SPEC-OID4VCI-4.1.1-offer", "ISS",
     "Offers can carry the authorization_code grant."),
    ("SPEC-ABCA07-10.3-refresh-bound", "spec", A7 + "§10.3; RFC 9449 §5; " + F + "§5.3.2.1 item 9", "PP;AP (AS)",
     "fixture", "A17", "", "OAUTH.REFRESH_BOUND", "ARF-ISSU_65", "OAUTH",
     "A refresh token is bound to the attested client (same sub, same cnf), not to a DPoP key: the attestation "
     "sender-constrains it (RFC 9449 §5) and the new access token is bound to the DPoP key shown at the refresh. "
     "It is not rotated. A closed subject kills it."),
    # metadata
    ("SPEC-RFC8414-2-as-metadata-m3", "spec", "RFC 8414 §2; RFC 9126 §5; RFC 9207 §3; " + A7 + "§10.1", "PP;AP (AS)",
     "blackbox", "M13;M14;A01", "", "OAUTH.AS_METADATA_M3", "SPEC-RFC8414-3-as-metadata", "META",
     "AS metadata gains authorization_endpoint, pushed_authorization_request_endpoint, "
     "require_pushed_authorization_requests, code_challenge_methods_supported [S256], attest_jwt_client_auth (plus "
     "none while pre-auth stays anonymous), the client attestation alg lists, "
     "authorization_response_iss_parameter_supported, response_types_supported [code], and grant_types_supported "
     "with authorization_code and refresh_token. The contract test covers every field."),
    ("SPEC-OID4VCI-12.2.2-signed-format", "spec",
     "OpenID4VCI 1.0 Final (16 Sep 2025) §12.2.2, §12.2.3; OpenID4VC HAIP 1.0 Final §4.1", "PP;AP", "blackbox", "M23;M17",
     "", "VCI.META.SIGNED_FORMAT", "ARF-ISSU_22", "META",
     "JSON is always served; the JWT only for Accept: application/jwt, with typ openidvci-issuer-metadata+jwt, sub the "
     "issuer identifier, iat, a short exp, and no trust anchor in x5c. HAIP §4.1 cites Section 11.2.3 of OID4VCI, "
     "which is §12.2.3 in 1.0 Final. Closes the metadata content negotiation item of BINDER-TODO.md."),
    ("ARF-WUA_32-client-status-period", "arf", "ARF 3.0.0 HLR WUA_32; TS3 v1.5.2 §2.4, §2.4.2", "PP;AP", "blackbox", "M21",
     "", "META.PREFERRED_CLIENT_STATUS_PERIOD", "ARF-WUA_32", "META",
     "Advertise preferred_client_status_period when the operator sets one, and refuse a WIA whose remaining "
     "client_status.exp is shorter."),
    # trust
    ("ETSI-119602-6.3.15-lote-authentic", "ts",
     "ETSI TS 119 602 V1.1.1 §6.3.2, §6.3.15, §6.8, Annex E.2, E.4; ETSI TS 119 182-1 V1.2.1; ARF 3.0.0 TLPub_06, TLPub_07",
     "PP;AP", "unit", "", "", "TRUST.LOTE_AUTHENTIC", "ARF-ISSU_19b", "WIA",
     "The LoTE's compact JAdES signature verifies under the signer pinned from the OJEU; the signer's C and O match "
     "the scheme territory and operator; NextUpdate has not passed; LoTESequenceNumber never goes back; LoTEType "
     "is the wallet providers type."),
    ("SPEC-RFC6960-3.2-revocation-fetched", "spec", "RFC 5280 §4.2.1.13, §6.1.3(a)(3); RFC 6960 §3.2, §4.2.2.2",
     "PP;AP", "unit", "", "", "TRUST.REVOCATION_FETCHED", "ARF-ISSU_21", "WIA",
     "CRLs fetched from distribution points; OCSP responses fully verified (CertID, authorised responder, signature, "
     "thisUpdate and nextUpdate, nonce if sent); UNKNOWN fails. The part of KA.CHAIN_TO_WP_LIST and "
     "WIA.CHAIN_TO_WP_LIST that M2 leaves partial."),
    # subject
    ("ARF-ISSU_18-plug-required", "arf", "ARF 3.0.0 HLR ISSU_18; CIR 2024/2977 Art. 3(7); DESIGN.md §3 point 5", "PP",
     "unit", "", "", "ISS.IDPROOF.PLUG_REQUIRED", "ARF-ISSU_18;EIDAS-2977-Art3(7)", "ISS",
     "Production refuses to start without a login plug that declares LoA high for PID; the built-in test login "
     "refuses to start in production. The startup check for the operator rule ISS.IDPROOF.LOA_HIGH."),
]

# The rows M4 adds: credential request and response encryption (M4 plan section 1.3, decision 1). They are not from
# CHECKLIST.md, so each names its own layer, as the M3 rows do.
# (binder_id, layer, source_ref, binds, testability, probes, new, rule, depends, topic, notes)
M4_ROWS = [
    ("SPEC-OID4VCI-10-request-encryption", "spec", V + "§8.2, §9.1, §10, §12.2.4", "PP;AP", "blackbox", "E01;E02;E05",
     "", "VCI.ENC.REQUEST", "SPEC-OID4VCI-12.2.4-metadata", "ISS",
     "credential_request_encryption publishes each request key with its kid, alg ECDH-ES and use enc, the enc values "
     "and encryption_required. The credential and deferred endpoints take a compact JWE as application/jwt; its "
     "kid names the key; a request that is not encrypted while encryption is required is refused."),
    ("SPEC-OID4VCI-10-response-encryption", "spec", V + "§8.2, §8.3, §9.2, §10, §12.2.4", "PP;AP", "blackbox", "E01;E02;E03;E04",
     "", "VCI.ENC.RESPONSE", "SPEC-OID4VCI-8.3-response", "ISS",
     "credential_response_encryption in an encrypted request: the 200 or 202 answer is a JWE to the wallet's key with "
     "its alg and kid, as application/jwt; error answers never are. Parameters that are wrong or missing while "
     "required, or sent in a request that is not encrypted, give invalid_encryption_parameters."),
]
