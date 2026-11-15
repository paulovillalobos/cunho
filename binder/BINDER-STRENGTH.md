# Binder strength re-check (BINDER-STRENGTH)

Date: 2026-11-03. Input: BINDER.csv (386 rows, not edited). Output: BINDER-STRENGTH.csv (one row per binder_id). Every quote was checked programmatically to occur verbatim (whitespace-normalised; "..." marks omissions; OJ footnote markers removed) in the source text listed in `verified_at`, and is at most 34 words.

## Sources actually read

| Source | Version used |
|---|---|
| ARF high-level requirements | v3.0.0 tag (c64f2cb, released 2026-07-23), hltr/high-level-requirements.csv. Local clone @f5789a7 differs from v3.0.0 only in ISSU_33b (not in the binder). |
| TS3 (WUA) | v1.5.2 (2026-05-26), eudi-doc-standards-and-technical-specifications @365f734 |
| PID Rulebook | v1.7 (2026-07-17), eudi-doc-attestation-rulebooks-catalog @36f8adc |
| Reg. (EU) 910/2014 | Consolidated 18.10.2024 (02014R0910-20241018; includes 2024/1183 and corrigendum C1 "unlinkability"); newest consolidation listed by the Cellar SPARQL endpoint |
| CIR 2024/2977, 2979, 2980, 2982 | Consolidated 11.08.2026 (incl. CIR 2026/1731) |
| CIR 2025/848 | Consolidated 11.08.2026 (incl. CIR 2026/1730); applies from 24.12.2026 |
| CIR 2025/1569 | Consolidated 11.08.2026 (incl. CIR 2026/1735) |
| CIR 2025/1566, 2025/2160, 2025/2530, 2026/798 | OJ texts (no consolidated version exists); 1566 applies from 19.08.2027 |
| OpenID4VCI | 1.0 Final, 16 Sep 2025 |
| HAIP | 1.0, 24 Dec 2025 |
| RFCs | 9449, 6749, 6750, 8414, 9110 (rfc-editor.org text) |
| Token Status List | draft-ietf-oauth-status-list-21 |
| SD-JWT VC | draft-ietf-oauth-sd-jwt-vc-23 |
| ISO/IEC 18013-5 | Not accessible (paywalled): 2 rows marked UNVERIFIED |

All EU texts came from the Publications Office Cellar (`https://publications.europa.eu/resource/celex/<CELEX>`), since eur-lex.europa.eu serves a bot challenge.

## Labels

- **strength**: the keyword in the quoted sentence. MUST = shall/must/required/shall not; CONDITIONAL-MUST = a MUST that applies only if a feature is offered or a situation exists (the trigger is in `condition`); SHOULD; MAY (incl. relief clauses such as "revocation shall not be required"); UNVERIFIED = source not reachable; N/A = the marker row.
- **binds_software_or_operator**: SOFTWARE = behaviour of issuer software that a test can observe; OPERATOR = a duty of the organisation (policy, registration, identity proofing, certificates, record-keeping, notifications, incident and revocation decisions); **NONE (party)** = the sentence binds someone other than the issuer (wallet, Member State, Commission, registrar, CA, rulebook author). A third value was needed because 48 rows bind no issuer at all.
- **issuer_types**: PP = PID provider, QEAA = qualified EAA provider (a QTSP), PuB-EAA = public-body EAA provider, nqEAA = non-qualified EAA provider.
- ARF, TS3 and the PID Rulebook are not law. Their SHALL is a MUST inside that framework only; legal force exists only where an implementing act points to them.

## Counts

Totals: MUST 273, CONDITIONAL-MUST 101, SHOULD 1, MAY 8, UNVERIFIED 2, N/A 1. Binds: SOFTWARE 261, OPERATOR 77, NONE 48.

| layer | binds | MUST | CONDITIONAL-MUST | SHOULD | MAY | UNVERIFIED | N/A | total |
|---|---|---|---|---|---|---|---|---|
| law | SOFTWARE | 61 | 18 | 0 | 3 | 0 | 0 | 82 |
| law | OPERATOR | 32 | 8 | 0 | 2 | 0 | 0 | 42 |
| law | NONE | 22 | 0 | 0 | 0 | 0 | 1 | 23 |
| arf | SOFTWARE | 64 | 23 | 0 | 1 | 0 | 0 | 88 |
| arf | OPERATOR | 18 | 16 | 1 | 0 | 0 | 0 | 35 |
| arf | NONE | 18 | 4 | 0 | 0 | 0 | 0 | 22 |
| ts | SOFTWARE | 8 | 5 | 0 | 0 | 0 | 0 | 13 |
| ts | NONE | 1 | 0 | 0 | 0 | 0 | 0 | 1 |
| rulebook | SOFTWARE | 10 | 2 | 0 | 0 | 0 | 0 | 12 |
| spec | SOFTWARE | 38 | 24 | 0 | 2 | 2 | 0 | 66 |
| spec | NONE | 1 | 1 | 0 | 0 | 0 | 0 | 2 |
| **all** | | 273 | 101 | 1 | 8 | 2 | 1 | 386 |

So 181 rows are an unconditional MUST on issuer software (61 of them law). Another 72 are conditional software MUSTs, 77 rows are operator duties, and 48 bind no issuer.

Of the 79 law MUST or CONDITIONAL-MUST rows labelled SOFTWARE, 17 rest on an indirect legal hook. They come from CIR 2024/2979 Annex Ib or CIR 2024/2982 Annexes I and II, which the enacting articles (2979 Art. 6(2), 2982 Art. 4(1) and 5(1)) address to **wallet providers**. The text names the authorisation server or credential issuer, but issuer-side force comes only through 2977 Art. 3(9) (PP) or 1569 REQ-EAASP-4.2.2.3-03 (QEAA/PuB-EAA). There is no hook for nqEAA.

## Structural corrections (affect many rows)

1. **Record-keeping is an operator duty for trust service providers only.** 910/2014 Art. 24(2)(h) binds QTSPs. 2025/2160 Art. 4(3)(b) binds non-qualified TSPs, and QTSPs through 2025/2530 Art. 2. Neither binds PID providers, which are not trust service providers. The 2160 records are onboarding/identity-verification data, user authentication data and status changes of the TSP's own certificates and keys. They are not an issuance audit log.
2. **Optional OpenID4VCI endpoints.** OID4VCI §9 and §11 each say "Support for this endpoint is OPTIONAL". batch_credential_issuance, nonce_endpoint, the pre-authorized grant and tx_code are OPTIONAL as well. HAIP only requires the issuer to *signal* batch support. These rows are now CONDITIONAL-MUST: an issuer breaks them only by offering the feature and implementing it wrongly.
3. **The law does not oblige PID providers to implement OpenID4VCI or TS 119 472-3 directly.** 910 Art. 5a(5)(a) binds wallets. 2982 Art. 4(1) binds wallet providers. 2977 Art. 3(8) and 3(9) each allow "another authentication mechanism ... notified at assurance level high" as an alternative to the access certificate and WUA validation.
4. **Wallet-only rows used against issuers.** ARF-DASH_05 (wallet log content), ISSU_06/07/11/24*, WUA_05a, Mig_* and 2979 TR-WIA-3 bind wallets. DASH_05 says nothing about issuer error codes; that duty is OID4VCI §8.3.1.2.
5. **Rulebook and certificate-content rows.** ARB_01b, ARB_25, ARB_30, ARB_34, ARB_24a and VCR_02 bind rulebook authors. Reg_31/32 and RPRC_02/05/06/07/07a/15 bind CAs or registration-certificate providers. 848 Annexes III–V bind registrars and CAs. ISSU_68/70/71/73 and 45f(1)(b) are certificate profiles the operator obtains; you can see them from outside, but they are not software behaviour.
6. **Dates.** CIR 2025/848 (registration, entitlements) applies from 24.12.2026, so no registration certificates exist yet. Wallet validation of registration certificates starts 11.08.2028 (2982 Art. 3(4)). The PID portrait becomes mandatory on 11.08.2028. CIR 2025/1566 applies from 19.08.2027.
7. **Words the notes add that the source lacks.** Examples: "refuse over-size batches" (§8.3 lets an issuer "issue fewer", and F.1 says it SHOULD issue one credential per attested key); "nonce no reuse" (§13.8: a nonce stays usable until the issuer rejects it); "jti replay" (RFC 9449 §11.1 "can"); "exp and ttl" (TSL: RECOMMENDED); "refuse legacy proof" (OID4VCI: additional parameters MAY be defined); "both formats" (2977 Annex §4 says "as applicable"; only ARF PID_02 says both); "atomic publication" (Art. 24(3) only states legal effect).
8. **Keywords inside notes.** TS3 §2.3.2 and 2979 C_KA-1 place "shall not use the KA idx as a Wallet Unit identifier" inside a NOTE. PID Rulebook §4.1.1 "nbf and exp" is a non-normative Note; the binding text is 2977 Annex §4.2. Rulebook §2.2 and §3.1.2c are keyword-less definitions; their force comes from 2977 Art. 3(3)/Annex and ARF PID_09/PID_18.
9. **Side finding (not top-10).** NL Wallet's "metadata says ESP256 (-9) but signs ES256 (-7)" is explicitly allowed: OID4VCI A.2.2 says an IssuerAuth alg -7 on P-256 "matches both -7 and -9".

## All corrections, by row

| binder_id | strength | binds | correction |
|---|---|---|---|
| ARF-ISSU_18 | MUST | OPERATOR | Overstated as software/fixture: this is an operator identity-proofing procedure (eID-scheme defined); software only integrates an IdP. |
| ARF-ISSU_19a | MUST | OPERATOR | Duty is met by configuration of accepted Wallet Providers, not by issuer code; software only needs a configurable allowlist. |
| ARF-ISSU_27a | CONDITIONAL-MUST | OPERATOR | Conditional (natural-person subject only) and procedural (identity verification), not a software/fixture test. |
| ARF-ISSU_27b | CONDITIONAL-MUST | OPERATOR | Data-correctness duty of the provider (authentic-source process); "unit" testability overstated. |
| ARF-SUA_03 | MUST | SOFTWARE | Notes misstate scope: the rule covers SUA attestations other than those specified in TS12 and refers to the SUA Attestation Rulebook, not "meeting TS12". |
| ARF-PID_13 | CONDITIONAL-MUST | OPERATOR | The SHALL is to have a policy (operator); a consistency unit test is our hardening, not the requirement. |
| ARF-PID_19 | CONDITIONAL-MUST | SOFTWARE | "Always emit nbf" does not follow from PID_19 (which is conditional on nbf being present); it follows from the 2026 PID Annex §4.2 (nbf and exp "shall be used"). |
| ARF-PID_20 | CONDITIONAL-MUST | OPERATOR | Policy duty (operator), not a unit-testable software property. |
| ARF-ARB_01b | MUST | NONE (Scheme Provider) | binds "Scheme Provider;AP" overstated: the HLR addresses only the Scheme Provider; AP duty is indirect via ISSU_25. |
| ARF-ARB_25 | MUST | NONE (Attribute Schema Provider) | Notes overstate: the HLR requires the rulebook to include attestation_legal_category; it says nothing about issued attestations carrying it. |
| ARF-ARB_30 | CONDITIONAL-MUST | NONE (Scheme Provider) | Binds the rulebook author, not the issuer; issuer duty only via ISSU_25. |
| ARF-ARB_34 | MUST | NONE (Scheme Provider) | Binds the rulebook author, not the issuer. |
| PIDRB-§3.1.2c | MUST | SOFTWARE | Cited sentence carries no RFC 2119 keyword; cite 2977 Annex §4.1(e) as the binding text. |
| PIDRB-§2.2 | MUST | SOFTWARE | Rulebook §2.2 is a definition table without a keyword; source_ref should point to the 2977 Annex §1 notes (addressed to Member States, implemented by the PP). |
| PIDRB-§2.5 | CONDITIONAL-MUST | SOFTWARE | issuing_jurisdiction is optional metadata, so the rule is conditional; the rulebook "shall" is lower-case (copied from law; §1.3 reserves capitalised keywords). |
| PIDRB-§4.1.1c | CONDITIONAL-MUST | SOFTWARE | Table cell without keyword; binding via PID_18 / 2977 Table 7. Conditional until 2028-08-11. |
| PIDRB-§4.1.1d | MUST | SOFTWARE | Rulebook text is a non-normative "Note:" without keyword; the binding source is 2977 Annex §4.2 ("shall be used"). source_ref should cite the law. |
| ARF-WUA_32 | CONDITIONAL-MUST | SOFTWARE | Notes call it an ARF SHALL vs optional law; the ARF SHALL is itself conditional on the issuer having minimum requirements, so it is consistent with law (LC_WIA-1/LC_KA-1 "may"). |
| ARF-WURevocation_11 | CONDITIONAL-MUST | SOFTWARE | Main addressee is the Wallet Provider; PP duty is only the identifier choice in the death flow. |
| TS3-§2.3.2b | MUST | SOFTWARE | The SHALL NOT sits inside a "Note on the idx value" blockquote; normative weight is doubtful (2979 Annex Ib C_KA-1 also puts it in a NOTE). |
| ARF-VCR_02 | MUST | NONE (Rulebook) | Not an issuer duty; the rulebook decides revocability for nqEAA. |
| ARF-VCR_06 | CONDITIONAL-MUST | OPERATOR | Operator incident duty; software only needs a revoke capability (covered by VCR_11/11a). |
| ARF-VCR_07a | CONDITIONAL-MUST | OPERATOR | Operator process (request channel + revoke), not a unit-testable software property. |
| ARF-VCR_07b | SHOULD | OPERATOR | Operator process (request intake + revoke) at SHOULD level; "unit" testability overstated. |
| ARF-VCR_08 | CONDITIONAL-MUST | OPERATOR | Operator process (death-registry feed); "unit" testability overstated. |
| ARF-VCR_09 | CONDITIONAL-MUST | OPERATOR | Operator process triggered by attribute changes at the source. |
| ARF-EDP_11 | CONDITIONAL-MUST | OPERATOR | Operator process triggered by policy changes; "unit" testability overstated. |
| ARF-RP_02 | CONDITIONAL-MUST | OPERATOR | Operator design/process choice (short-lived vs revocable by entitled parties); "unit" testability overstated. |
| ARF-ARB_24a | CONDITIONAL-MUST | NONE (Rulebook) | Binds the rulebook, not the AP. |
| ARF-ISSU_68 | MUST | OPERATOR | Blackbox-observable, but a certificate-procurement duty of the operator, not software behaviour. |
| ARF-ISSU_70 | MUST | OPERATOR | Certificate-procurement duty, not software behaviour. |
| ARF-ISSU_71 | MUST | OPERATOR | Certificate-procurement duty, not software behaviour. |
| ARF-ISSU_73 | MUST | OPERATOR | Certificate-procurement duty, not software behaviour. |
| ARF-PPNot_03 | MUST | OPERATOR | Achieved by notification/certificate set-up (operator); software only signs. |
| ARF-PPNot_04 | MUST | OPERATOR | Certificate-procurement duty, not software behaviour. |
| ARF-PuBPNot_04 | MUST | OPERATOR | Operator set-up, not software behaviour. |
| ARF-Reg_31 | MUST | NONE (Access CA / certificate content) | Not an issuer software duty; at most an operator self-check of the certificate it obtained. |
| ARF-Reg_32 | MUST | NONE (Access CA / certificate content) | Not an issuer software duty. |
| ARF-RPRC_14 | MUST | OPERATOR | Deployment/operations duty; blackbox check only sees one supply point. |
| ARF-RPRC_15 | MUST | NONE (registration-certificate content) | Not an issuer software duty. |
| ARF-RPRC_05 | CONDITIONAL-MUST | NONE (registration-certificate content) | Not an issuer software duty. |
| ARF-RPRC_06 | MUST | NONE (registration-certificate content) | Not an issuer software duty. |
| ARF-RPRC_07 | MUST | NONE (registration-certificate content) | Not an issuer software duty. |
| ARF-RPRC_07a | MUST | NONE (registration-certificate content) | Not an issuer software duty. |
| ARF-RPRC_02 | MUST | NONE (provider of registration certificates) | Binds the provider of registration certificates, not the issuer. |
| ARF-ISSU_06+ISSU_11a | MUST | NONE (Wallet) | Wallet duty; issuer is only the counterpart. |
| ARF-ISSU_07+ISSU_09+ISSU_08 | MUST | NONE (Wallet) | Wallet duty. |
| ARF-ISSU_11 | MUST | NONE (Wallet) | Wallet duty. |
| ARF-ISSU_24+ISSU_34+CT_05 | MUST | NONE (Wallet) | Wallet duty. |
| ARF-ISSU_24a+ISSU_24b+ISSU_34a+ISSU_34b+RPRC_22a+RPRC_22b+RPRC_23 | CONDITIONAL-MUST | NONE (Wallet) | Wallet duty with a 2028 start date. |
| ARF-WUA_05a | MUST | NONE (Wallet) | Wallet duty. |
| TS3-§2.2.2.1+§2.4.2 | MUST | NONE (Wallet / Wallet Provider) | Wallet duty; not an issuer requirement. |
| ARF-Mig_07+Mig_11 | MUST | NONE (Wallet) | Wallet-driven; for the issuer it is ordinary issuance. |
| ARF-DASH_05 | MUST | NONE (Wallet) | Overstated: DASH_05 binds only the Wallet Unit log. It imposes no duty on issuers; specific error codes are an OID4VCI §8.3.1.2 duty. No issuer can break this row. |
| EIDAS-910-Art5a(5)(a)(i) | MUST | NONE (Wallet) | Addressee is the Wallet ("European Digital Identity Wallets shall"); blackbox issuer testing of this row is a proxy, not the legal duty. |
| EIDAS-910-Art24(1) | MUST | OPERATOR | Identity verification is an operator procedure (conformity-assessed), not a software fixture test. |
| EIDAS-910-Art24(1a)(a) | MAY | OPERATOR | Overstated as a requirement to implement Wallet-based (OpenID4VP) identity verification: it is one optional method among four. |
| EIDAS-910-Art24(2)(g) | MUST | OPERATOR | Organisational security duty of the QTSP; an HSM option in software helps but its absence is not a breach by the software. |
| EIDAS-910-Art24(2)(h) | MUST | OPERATOR | Overstated: binds only qualified trust service providers as an organisational record-keeping duty ("Such recording may be done electronically"). It is not a requirement on issuer software, and does not bind PID providers or non-qualified EAA providers. |
| EIDAS-910-Art24(3)-publish24h | MUST | OPERATOR | Service-level duty of the QTSP (process + publication interval). |
| EIDAS-910-Art24(3)-effective | MUST | NONE (legal effect) | Describes legal effect, not a software duty; "publish atomically" is our engineering inference. |
| EIDAS-910-Art45d(3) | MUST | NONE (legislators / relying parties) | Not an issuer duty. |
| EIDAS-910-Art45f(1)(b) | MUST | OPERATOR | Certificate content (operator/CA), not issuer software behaviour. |
| EIDAS-910-Art45h(1) | MUST | OPERATOR | Organisational data-governance duty; "unit" testability overstated. |
| EIDAS-910-Art45h(2) | MUST | OPERATOR | Data-architecture duty of the provider; testability "unit" overstated. |
| EIDAS-910-AnnexV-VII(g) | MUST | OPERATOR | Requires a qualified certificate and QSCD (operator); software only applies the signature. |
| EIDAS-910-AnnexV-VII(i) | MUST | SOFTWARE | Annex V/VII (i) has no short-lived exception; the <=24 h relief (2979 EAA-4.2.13-03) only waives revocation, so the notes' "unless short-lived" is an interpretation. |
| EIDAS-2977-Art3(7) | MUST | OPERATOR | Procedural identity proofing (operator), not a fixture-testable software property. |
| EIDAS-2977-Art3(8) | MUST | SOFTWARE | Overstated: law allows an alternative to the access certificate ("or by using another authentication mechanism ... notified at assurance level high"); signed metadata is not named. |
| EIDAS-2977-Art3(9) | MUST | SOFTWARE | Law offers an alternative ("or use another authentication mechanism ... assurance level high"); WUA validation is not the only compliant path. |
| EIDAS-2977-Art5(2) | MUST | OPERATOR | Legal allocation of who may revoke; "status-list write authorisation" test is our proxy. |
| EIDAS-2977-Art5(3) | CONDITIONAL-MUST | OPERATOR | Operator communication duty; "unit" testability overstated. |
| EIDAS-2977-Art5(4)(a) | CONDITIONAL-MUST | OPERATOR | Conditional on the PP revoking at all; operator process. |
| EIDAS-2977-Art5(6) | MUST | OPERATOR | Retention duty of the operator; "unit" testability overstated. |
| EIDAS-2977-Art5(7) | CONDITIONAL-MUST | SOFTWARE | Binds only PID providers and is conditional on revocation; it cannot be broken by EAA issuers or generic products not acting as PP. |
| EIDAS-2977-Art5(8) | MUST | SOFTWARE | Notes over-read the text: it names no technique (no batch issuance, no status-index rule). |
| EIDAS-2977-Annex§4 | MUST | SOFTWARE | Law says clauses 5 and 6 "as applicable"; reading it as "both formats" is not supported by the text. |
| EIDAS-2977-Annex§5 | MUST | NONE (Commission list) | Sentence addresses the Commission's list; no issuer software duty. Blackbox testability overstated. |
| EIDAS-2979-AnnexIb-TR-WIA-3 | MUST | NONE (Wallet) | Wallet duty; issuer acceptance is implied, not stated. |
| EIDAS-2979-AnnexIb-C_KA-1 | MUST | SOFTWARE | The cited C_KA-1 body governs KA content (wallet provider); the issuer rule is inside a NOTE, so its normative weight is doubtful. |
| EIDAS-2979-AnnexII-EAA-4.2.13-03 | MAY | SOFTWARE | An exemption ("shall not be required"), not a duty. |
| EIDAS-2979-AnnexII-PuB-EAA-4.6.3-04 | MUST | OPERATOR | Certificate content (operator/CA), not software behaviour. |
| EIDAS-2982-Art4(3)(c) | MUST | NONE (Wallet) | Binds wallet solutions; PP use is optional, fixture testing of the issuer overstated. |
| EIDAS-2982-AnnexI-intro | MUST | NONE (Wallet provider; issuer indirect) | Law does not directly oblige PP/AP to implement TS 119 472-3: 2982 Art. 4(1) says "Wallet providers shall ensure that wallet solutions support" it. |
| EIDAS-2980-AnnexII-§3(1)(h) | MUST | NONE (Member States; PP obtains certificate) | Member State notification duty; PP role is operator (obtaining a compliant certificate), not software. |
| EIDAS-848-AnnexI-pt12(b)-(e) | MUST | OPERATOR | Registration content (operator), visible in certificates issued by CAs; not software behaviour. |
| EIDAS-848-AnnexIV-pt3 | MUST | NONE (Access CA) | Binds the access-certificate provider's policy; blackbox issuer testing overstated. |
| EIDAS-848-AnnexV-pt3 | MUST | NONE (Registration-certificate provider) | Binds the registration-certificate provider; not an issuer duty. |
| EIDAS-1569-Art4(2) | MUST | OPERATOR | Legal allocation; "unit" testability is a proxy. |
| EIDAS-1569-Art4(3) | CONDITIONAL-MUST | OPERATOR | Conditional (> 24 h validity) operator process; "unit" testability overstated. |
| EIDAS-1569-AnnexI-REQ-EAASP-7.5.3-02 | MUST | OPERATOR | Hardware procurement/certification duty of the operator; an issuer product without an HSM option does not itself break it. |
| EIDAS-1569-AnnexI-REQ-EAASP-7.9-02 | MUST | OPERATOR | "No attribute values in logs" is our interpretation. |
| EIDAS-798-OVR-7.10-01 | MAY | OPERATOR | Optional allocation ("can"), operator duty; "unit" testability overstated. |
| EIDAS-2160-Art4(3)(b) | MUST | OPERATOR | Overstated: an organisational record-keeping duty of non-qualified trust service providers (and QTSPs via 2025/2530). Its three items are onboarding/identity data, authentication data and key/certificate status changes, NOT an issuance audit log; it does not bind PID providers. |
| EIDAS-2530-Art3(7)(d) | MUST | OPERATOR | Termination-plan procedure (operator); "unit" testability overstated. |
| SPEC-OID4VCI-4.1.1-offer | CONDITIONAL-MUST | SOFTWARE | Pre-authorized grant is optional; HAIP §4.2 mandates Credential Offer support (same- and cross-device) but only the authorization_code grant. |
| SPEC-OID4VCI-6.3-unknown-code | CONDITIONAL-MUST | SOFTWARE | §6.3 lists clarifications (no keyword); the MUST-level duty is RFC 6749 §5.2. |
| SPEC-OID4VCI-6.3-tx_code | CONDITIONAL-MUST | SOFTWARE | §6.3 mapping is a clarification without keyword; tx_code itself is OPTIONAL. |
| SPEC-OID4VCI-7.1-nonce-endpoint | CONDITIONAL-MUST | SOFTWARE | "Wrong method refused without 5xx" is not in §7 (it is our RFC 9110 hardening). |
| SPEC-OID4VCI-8.2-identifier-xor | MUST | SOFTWARE | Request-construction rule for Wallets; rejecting violations is implied by §8.3.1.2, not stated in §8.2. |
| SPEC-OID4VCI-8.2-proofs-only | CONDITIONAL-MUST | SOFTWARE | Refusing the legacy singular "proof" is not mandated: OID4VCI says "Additional Credential Request parameters MAY be defined and used"; a missing "proofs" maps to invalid_proof. |
| SPEC-OID4VCI-9-deferred | CONDITIONAL-MUST | SOFTWARE | Overstated in the failures sheet: not offering a deferred endpoint breaks nothing; only a broken advertised endpoint does. |
| SPEC-OID4VCI-11-notification | CONDITIONAL-MUST | SOFTWARE | Overstated in the failures sheet: absence of a notification endpoint is compliant; only an offered-but-wrong endpoint breaks §11. |
| SPEC-OID4VCI-12.2.4-metadata | MUST | SOFTWARE | "No leaked internal config" is not an OID4VCI requirement (hardening). |
| SPEC-OID4VCI-12.2.4-batch_size | CONDITIONAL-MUST | SOFTWARE | Overstated: no MUST requires refusing over-size requests, and §8.3 allows issuing fewer ("unless the Issuer decides to issue fewer Credentials"); F.1 even says the issuer SHOULD issue one credential per attested key. |
| SPEC-OID4VCI-D-key-attestation | CONDITIONAL-MUST | SOFTWARE | KA shape (typ, attested_keys, exp) binds the Wallet Provider; the issuer duty is validation. |
| SPEC-OID4VCI-F.1-key-header | MUST | NONE (Wallet) | Issuer rejection of kid+jwk combinations is not mandated (F.4 checks only required claims, typing, alg, signature, no private key, nonce, time). |
| SPEC-OID4VCI-F.1-nonce | CONDITIONAL-MUST | SOFTWARE | "No reuse" is not mandated: §13.8 "A Wallet can continue using a given nonce until it is rejected"; nonce lifetime is issuer policy. |
| SPEC-OID4VCI-F.1-iss-anon | CONDITIONAL-MUST | SOFTWARE | Acceptance by the issuer is implied, not stated. |
| SPEC-RFC9449-11.1-jti-replay | MAY | SOFTWARE | Overstated as a check: jti replay storage is optional ("can"); the §11.1 MUST is only the limited acceptance window (row 4.3-11). |
| SPEC-HAIP-4-batch-metadata | MUST | SOFTWARE | Omitting batch_credential_issuance is a valid "not supported" signal; only issuers that accept multiple proofs without advertising it break this. |
| SPEC-HAIP-4.5.1-ka-x5c | CONDITIONAL-MUST | NONE (KA producer / Wallet Provider) | Constrains the KA; issuer refusal of self-signed KAs follows from TS3/2979 trust-anchor validation, not from HAIP §4.5.1. |
| SPEC-TSL-5.1-token-claims | MUST | SOFTWARE | Notes require "exp and ttl"; draft-21 makes both RECOMMENDED, not required. |
| SPEC-ISO18013-5-issuerauth-x5chain | UNVERIFIED | SOFTWARE | Could not verify against ISO/IEC 18013-5 text; OID4VCI A.2.4 only requires the base64url IssuerSigned structure. |
| SPEC-ISO18013-5-mso-verify | UNVERIFIED | SOFTWARE | Could not verify against ISO/IEC 18013-5 text. |
| SPEC-RFC6750-3-bearer-challenge | CONDITIONAL-MUST | SOFTWARE | Overstated for HAIP/DPoP issuers: the MUST is the Bearer challenge header; the 401 status is SHOULD, and DPoP challenges are optional. |
| SPEC-RFC9110-15.5.6-methods | CONDITIONAL-MUST | SOFTWARE | RFC 9110 does not mandate 405 for wrong methods; "refused without 5xx" is hardening. |
## Re-scoring the "most broken rules" (FAILURES-PLAIN-ENGLISH.md, top 10)

Issuer roles used below. Real PID-provider software: NL Wallet, Bundesdruckerei, EC Kotlin, and the PID parts of EC Python and pyeudiw. The rest are generic products, pilots or frameworks (EUDIPLO, Procivis, Keycloak, walt.id, credo, A-SIT, MOSIP, Multipaz, wwWallet, bedrock, SUNET), plus out-of-scope stacks (swiyu is Swiss; Yivi does not use OID4VCI). None of the 21 is a QTSP or a TSP running a supervised service. Law therefore reaches them only as software someone might deploy, never as the operator the law addresses.

| # | Row | Counted | What the source really is | Issuers that truly break a binding software rule |
|---|---|---|---|---|
| 1 | EIDAS-2160-Art4(3)(b) | 19/21 | MUST, **OPERATOR**, non-qualified TSPs (nqEAA; QTSPs via 2530 Art. 2). Not PPs. Content is onboarding data, authentication data and key/certificate status changes, not an issuance log. | **0/19**. An operator record-keeping duty, not a software rule. Three of the 19 are pure PID issuers (NL Wallet, Bundesdruckerei, EC Kotlin), which this act does not cover at all. |
| 2 | EIDAS-910-Art24(2)(h) | 19/21 | MUST, **OPERATOR**, QTSPs only (QEAA). "Such recording may be done electronically." | **0/19**. Operator duty of a QTSP; no counted issuer is one. A built-in audit log is a good feature for QTSP customers, not a legal requirement on the product. |
| 3 | ARF-DASH_05 | 15/21 | MUST on the **Wallet** log (NONE for issuers). | **0/15**. The error-handling faults behind these entries are already counted under row 5 / RFC 6749 §5.2. |
| 4 | SPEC-OID4VCI-11-notification | 14/21 | **CONDITIONAL-MUST**: "Support for this endpoint is OPTIONAL". If offered: 2xx on success, 400 + `error` (REQUIRED) for an invalid id. | **4/14**: EUDIPLO (bad id gets no error code), SUNET (stub accepts anything and never issues ids), EC Python issuer (refuses DPoP tokens although HAIP mandates DPoP, and never checks the body), pyeudiw (endpoint advertised but switched off). The other 10 simply do not offer it, which complies. |
| 5 | SPEC-OID4VCI-8.3.1.2-error-codes | 14/21 | **MUST** on software for all issuer types: specific codes MUST replace generic `invalid_request`, and 400 MUST be used for unsupported credentials. The exact code value is SHOULD. | **11/14** at MUST level (500s on client mistakes, a missing `error` field, or generic invalid_request/server_error): EUDIPLO, Bundesdruckerei, SUNET, EC Kotlin, Keycloak, walt.id, Multipaz, EC Python, pyeudiw, wwWallet, bedrock. **SHOULD level only**: Procivis (old-draft code names), credo (wrong code name; its 500s are real internal errors), MOSIP (wrong code name; dropping one invalid proof is tolerated by §8.3 "issue fewer"). |
| 6 | SPEC-OID4VCI-9-deferred | 11/21 | **CONDITIONAL-MUST**: "Support for this endpoint is OPTIONAL". | **1 confirmed (pyeudiw: advertised, broken), 1 possible (SUNET stub, if advertised)** of 11. The rest do not offer it, which complies. |
| 7 | ARF-ISSU_64 | 10/21 | **MUST on software, ARF only** (not law). OID4VCI and HAIP leave batch support optional. | **1–3/10**: pyeudiw (no batch at all); A-SIT and wwWallet accept several proofs but never advertise batch support (this also breaks the HAIP §4 MUST to signal it). The other 7 do support batch; their failure is limit enforcement, which is not what ISSU_64 says. |
| 8 | EIDAS-2977-Art5(7) | 9/21 | **CONDITIONAL-MUST on PID providers only**, and only "where" they revoke. | **1/9**: EC Kotlin PID issuer issues PIDs with no status entry, so a PP running it could not publish status as required. EC status-list server: publishing via another web server satisfies the law. The other 7 are not PP software; their gap maps to ARF VCR_11/11a and TSL rows, not to this article. |
| 9 | SPEC-OID4VCI-12.2.4-batch_size | 9/21 | **CONDITIONAL-MUST** (batch_size REQUIRED, >= 2, only when batch_credential_issuance is advertised). No sentence requires refusing over-size requests. §8.3 allows issuing fewer, and F.1 says the issuer SHOULD issue one per attested key. | **0/9** against this row. Silent truncation (Keycloak, EC Python) is explicitly allowed. Exceeding one's own advertised maximum (EUDIPLO, EC Kotlin, Multipaz, Bundesdruckerei) contradicts the parameter's meaning but breaks no stated MUST. Accepting several proofs without advertising batch (A-SIT, wwWallet, perhaps MOSIP) breaks HAIP §4, a different row. |
| 10 | SPEC-RFC6750-3-bearer-challenge | 9/21 | **CONDITIONAL-MUST**: WWW-Authenticate is MUST only for Bearer-protected resources. A 401 for invalid_token is SHOULD. For DPoP tokens RFC 9449 says the server "can" send a challenge. OID4VCI cites RFC 6750 §3 only "such as". | **1 confirmed (EC Python issuer: Bearer-only, 401 without challenge), up to 3** (EC Kotlin, A-SIT, if they accept Bearer). The rest return 400/403/404 instead of 401, which is a SHOULD-level deviation. |

**Net:** the top 10 count 129 issuer-row failures. Only **19 confirmed (at most 25)** are breaches of a binding rule on issuer software, and 11 of those are row 5. Rows 1–3 (53 counted failures) contain **none**. They are operator duties of trust service providers, or a wallet rule. Rows 4, 6 and 9 mostly count issuers for not offering optional features.

**Suggested fixes to FAILURES-PLAIN-ENGLISH.md:**
- Move the audit-trail items to a separate "operator readiness" list. Do not present them as rule breaks.
- Drop the ARF-DASH_05 tags.
- Count deferred and notification only where the endpoint is advertised but broken.
- Re-tag batch-limit items to SPEC-HAIP-4-batch-metadata where batch is unadvertised, and to "inconsistent with advertised batch_size (no MUST)" elsewhere.
- Split RFC 6750 items into MUST (missing header on Bearer) and SHOULD (status code).

## M3 rows (added 2026-11-05)

28 rows from `M3_ROWS` in `binder/src/rows_spec.py`, accepted by the owner on 2026-11-05. The input above (386 rows) is unchanged; BINDER.csv now has 414. Each quote was checked by script against the source text named in `verified_at`, on the same rules: verbatim after normalising whitespace and page furniture, "..." for omissions, in order, at most 34 words. Every passage cited inside a `correction` was checked the same way.

| Source | Version read |
|---|---|
| FAPI 2.0 Security Profile | Final, February 2025 (openid.net) |
| RFC 9126, 7636, 9207, 6749, 9449, 9700, 8414, 5280, 6960 | rfc-editor.org text |
| draft-ietf-oauth-attestation-based-client-auth | -07, 15 September 2025 |
| OpenID4VCI | 1.0 Final, 16 Sep 2025 |
| HAIP | 1.0 Final, 24 Dec 2025 |
| ETSI TS 119 602 | V1.1.1 (2025-11), etsi.org PDF |
| ETSI TS 119 182-1 | V1.2.1, etsi.org PDF (read for the JAdES baseline levels and serialisations) |
| ARF high-level requirements | v3.0.0, as above |
| TS3 | v1.5.2, as above |

All 28 bind issuer software. 24 are MUST and 4 CONDITIONAL-MUST. One is MUST for the PID provider only (`ARF-ISSU_18-plug-required`); the rest apply to every issuer type.

What checking the texts changed or settled:

1. **`ARF-WUA_25-not-revoked` (WIA.CLIENT_STATUS) is MUST for every issuer type, not MAY for attestation providers.** ARF 3.0.0 WUA_25 has a second sentence, "In addition, the PID Provider or Attestation Provider SHALL validate that the WIA is not revoked." CIR 2025/1569 REQ-EAASP-4.2.2.3-03 says the same for QEAA and PuB-EAA providers. The MAY in TS3 §2.3.1 is about repeating the check during the PID's life.
2. **HAIP's "Section 11.2.3" is OID4VCI §12.2.3.** HAIP 1.0 §4.1 cites Section 11.2.3 of OpenID4VCI for signed metadata. In OpenID4VCI 1.0 Final, signed metadata is §12.2.3 and §11.2 is the Successful Notification Response. Recorded on `SPEC-OID4VCI-12.2.2-signed-format`.
3. **draft-07 numbering.** The checks the plan cited as "§6.2 steps" are §9 in -07: step 6 is the private key in `cnf`, step 9 the PoP time window, step 10 the audience, step 13 the client_id. §6.2 has three header checks. The rows cite §9.
4. **No token in the query** is FAPI 2.0 Final §5.3.4 (requirements for resource servers), second item.
5. **The offer's scope.** HAIP §4.2 asks the issuer to "include a scope value" for the authorization_code grant. OpenID4VCI §4.1.1 gives that grant no scope member, so the Wallet takes the scope from the metadata entry of each offered configuration, which VCI.META.SCOPE_PER_CONFIG already requires.
6. **Keywords weaker than the check.** RFC 9126 makes single-use request_uri a SHOULD, draft-07 makes jti replay detection a SHOULD, and RFC 6749 makes revoking the tokens of a reused code a SHOULD. RFC 9449 §5 does not bind an authenticated client's refresh token to the DPoP key. cunho does all four, as the plan proposes; each row's `correction` says so.
