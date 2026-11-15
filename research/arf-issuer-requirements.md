# ARF issuer-side requirements checklist (PID Provider / Attestation Provider)

Prepared 2026-11-03 for an Apache-2.0 EUDI Wallet credential issuer. Every quoted excerpt below was checked by script against the source text (verbatim fragments joined by "…", under 30 words each). Treat quotes as excerpts and use the source files as authoritative.

## Sources (pinned)

| Source | Repo / file | Commit | Version stated in the source |
|---|---|---|---|
| ARF | `eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework`, `hltr/high-level-requirements.csv` (normative; Annex 2.01 says the CSV wins over the .md renderings) | `f5789a77dfc6d5a85834c431465afbe543d0141a` (main, 2026-10-02) | **ARF 3.0.0** (`Makefile VERSION := 3.0.0`, CHANGELOG `[3.0.0] - 2026-07-21`; tag `v3.0.0` = `c64f2cbb19aee37c571c58af66d359c4d5be29c8`). Between the tag and HEAD the CSV changed in only one row, ISSU_33b, which binds the Wallet. |
| Technical Specifications | `eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications` | `365f734ac95b858343b09aaf56a80f3e1d684119` (2026-10-27) | TS3 (WUA) **v1.5.2** (2026-05-26); TS2 v1.0.1; TS5 v1.6; TS6 v1.2.2; TS11 v1.0.1 |
| PID Rulebook | `eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog`, `rulebooks/pid/pid-rulebook.md` (ARF Annex 3.01 is now only a pointer to this file) | `36f8adcf914ac06cac18d685add04e0a8a06d685` | PID Rulebook **v1.7** (2026-07-17) |

Local clones: `<scratch>/arf/{arf,ts,rb}`.

## Legend

- **ID**: the ARF HLR identifier (the `Index` column of the CSV). Each one also has a harmonised ID (e.g. `AS-AP-10-001`) in the CSV. Rows named `TS3-§x` or `PIDRB-§x` are normative statements from TS3 or the PID Rulebook that have no HLR ID.
- **Binds**: PP = PID Provider; AP = Attestation Provider (QEAA, PuB-EAA or non-qualified EAA Provider); QEAA / PuB-EAA / EAA = that provider type only; WP = Wallet Provider; Wallet = Wallet Unit; Scheme Provider = author of the Attestation Rulebook. "Issuer self-check" means the requirement binds another party (Access CA or registration-certificate provider), but your issuer should still validate the artefact it was given before serving it.
- **Testable**: *Yes* = can be a deterministic automated check against issuer output or behaviour. *Partly* = needs an integration or fixture, a policy configuration, or covers only the technical half. *Organisational* = a policy or document obligation that code cannot test.
- **Spec mapping**: protocol sections are given **only when the ARF/TS text cites them** (e.g. OID4VCI §12.2.3, App. D/E/F.4, §14.5; HAIP §4/§6/§6.1; ISO 18013-5 §9.1.2.4; SD-JWT VC §3.2.2.2; ETSI TS 119 472-3 §4.2.3/§4.2.4.2). Feature names without a section number (e.g. "batch issuance", "Nonce Endpoint", "refresh token") are the analyst's mapping and should be confirmed against the spec.
- Reminder: HLRs that are "Empty" in 3.0.0 (e.g. ISSU_04, ISSU_16, ISSU_18a, ISSU_22a/b, ISSU_31, ISSU_32a, ISSU_66, PID_15, WUA_13–16, WUA_18–21, WUA_23) were deleted. Do not implement checks for them.

## Count of issuer-binding ARF HLRs per topic

Counted once per HLR ID, under its primary topic. The TS3 rows (13) and PID Rulebook rows (12) are listed separately and are **not** included in these counts.

| Topic | Yes | Partly | Organisational only | Listed, binds someone else (Scheme Provider, Access CA, reg-cert provider: issuer self-checks) |
|---|---|---|---|---|
| 1. Issuance protocol (OpenID4VCI / HAIP / general issuance duties) | 7 | 9 | 1 | 0 |
| 2. PID rulebook / data model (attributes, encodings, validity) | 18 | 2 | 2 | 4 |
| 3. Wallet Unit Attestation (WIA) and Key Attestation (KA) checks | 26 | 1 | 2 | 0 |
| 4. Revocation and status (time limits, validity, short-lived credentials) | 10 | 6 | 2 | 2 |
| 5. Issuer authentication (signing certificates, access certificates, trusted lists / LoTEs, x5c) | 9 | 1 | 5 | 2 |
| 6. Registration certificates in Credential Issuer metadata (incl. "issuer_info") | 1 | 1 | 0 | 6 |
| 7. Batch issuance, one-time-use (Methods A-D) and re-issuance | 11 | 2 | 1 | 0 |
| 8. Logging / audit | 0 | 1 | 0 | 1 |
| 9. Data minimisation and privacy (unlinkability, status-index privacy) | 4 | 1 | 0 | 0 |
| **Total ARF HLRs binding PP/AP** | **86** | **24** | **13** | |


## 1. Issuance protocol (OpenID4VCI / HAIP / general issuance duties)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| ISSU_01a | PP, AP | Yes | OID4VCI 1.0 profiled by HAIP 1.0 §4 and §6 (OID4VCI Annex A.2 mdoc, A.3 SD-JWT VC), plus TS3 | "PID Providers and Attestation Providers SHALL support the OpenID4VCI protocol specified in [OpenID4VCI], as profiled in Sections 4 and 6 of [HAIP]" | `issu_01a_oid4vci_haip_profile` |
| ISSU_15 | PP | Yes | OID4VCI 1.0 | "A PID Provider SHALL support the OpenID4VCI protocol referenced in ISSU_01 for issuing PIDs." | `issu_15_pid_via_oid4vci` |
| ISSU_26 | AP | Yes | OID4VCI 1.0 | "An Attestation Provider SHALL support the OpenID4VCI protocol referenced in ISSU_01 for issuing attestations." | `issu_26_eaa_via_oid4vci` |
| ISSU_03 | PP, AP, Wallet | Partly (conditional: the HLR note says it applies once the DC API is a W3C Recommendation and OID4VCI defines a DC API binding) | W3C Digital Credentials API | "Wallet Units, PID Providers, and Attestation Providers SHALL support the [W3C Digital Credentials API]…for the issuance of PIDs and attestations." | `issu_03_dc_api_issuance (feature-flag)` |
| ISSU_12 | PP, AP | Yes | ISO/IEC 18013-5 mdoc and SD-JWT VC (per rulebook) | "A PID Provider or Attestation Provider SHALL offer its PIDs or attestations in all formats required in the PID Rulebook or the applicable Attestation Rulebook" | `issu_12_all_rulebook_formats_offered` |
| OIA_03 | all (incl. PP, AP) | Yes | ECCG Agreed Cryptographic Mechanisms v2.0; TS3 §2.6 | "PID Providers, Attestation Providers…SHALL only use cryptographic algorithms included in the [ECCG Agreed Cryptographic Mechanisms v2.0]." | `oia_03_alg_allowlist_eccg` |
| ProxId_02 | all (incl. PP, AP) | Yes (negative test) | ISO/IEC 18013-5 server retrieval | "Wallet Units, PID Providers, Attestation Providers, Wallet Providers, and Relying Parties SHALL NOT support server retrieval as specified in ISO/IEC 18013-5" | `proxid_02_no_server_retrieval_endpoint` |
| ISSU_18 | PP | Partly (identity-proofing integration; LoA High per eID scheme) | CIR 2015/1502 (LoA High) | "A PID Provider SHALL verify the identity of the subject of the PID in compliance with Level of Assurance (LoA) High requirements." | `issu_18_loa_high_idp_gate` |
| ISSU_19a | PP | Partly | — | "A PID Provider SHALL support all Wallet Solutions recognised under the corresponding notified eID scheme" | `issu_19a_wallet_solution_allowlist_complete` |
| ISSU_20 | PP | Organisational | — | "a PID Provider SHALL publish a list of supported Wallet Solutions in such a way that it can be easily found" | — |
| ISSU_27a | AP | Partly | — | "If the subject of the attestation is a natural person, an Attestation Provider SHALL verify the identity of the subject of the attestation" | `issu_27a_subject_identity_verified` |
| ISSU_27b | AP | Partly | — | "If applicable, an Attestation Provider SHALL ensure that the attributes attested in the attestation issued are valid for the identified attestation subject." | `issu_27b_attr_source_binding` |
| ISSU_27c | AP | Partly | — | "The Attestation Provider SHALL verify that the User requesting the attestation has the right to receive it." | `issu_27c_entitlement_check` |
| ISSU_29 | QEAA, PuB-EAA | Partly (no wallet-solution discrimination in code paths) | — | "a QEAA Provider or PuB-EAA Provider SHALL NOT discriminate between Wallet Solutions when processing a request for the issuance of an attestation." | `issu_29_no_wallet_discrimination` |
| SUA_03 | AP (SUA attestations) | Partly | TS12 | "The Attestation Provider of a SUA attestation…SHALL NOT issue such an attestation to a Wallet Unit that does not comply with all relevant requirements" | `sua_03_sua_wallet_gate` |
| ACP_07 | AP | Partly | (OID4VCI extension, not yet specified) | "Before making a request according to ACP_05, an Attestation Provider SHALL verify that the new attestation indeed belongs to the User of the existing PID or attestation." | `acp_07_binding_subject_match` |
| EDP_09 | AP | Yes | OID4VCI Credential Issuer metadata + ETSI TS 119 472-3 | "An Attestation Provider SHALL include an embedded disclosure policy (if any) by value in the Issuer metadata related to the attestation" | `edp_09_edp_by_value_in_metadata` |


## 2. PID rulebook / data model (attributes, encodings, validity)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| PID_01 | PP | Yes | PID Rulebook | "PIDs and PID Providers SHALL comply with all requirements in [PID Rulebook]" | `pid_01_rulebook_conformance (umbrella)` |
| ISSU_14 | PP | Yes | PID Rulebook | "A PID Provider SHALL ensure that all PIDs it issues to Wallet Units comply with the requirements specified in [PID Rulebook]" | `issu_14_rulebook_conformance` |
| PID_02 | PP | Yes | ISO/IEC 18013-5 + SD-JWT VC | "A PID Provider SHALL issue any PID in both the format specified in ISO/IEC 18013-5 [ISO/IEC 18013-5] and the format specified in [SD-JWT VC]." | `pid_02_dual_format` |
| PID_03 | PP | Yes | SD-JWT VC / ISO 18013-5 | "If the User opts out, the PID Provider SHALL include the `portrait` attribute in the PID as an empty JSON `string` or CBOR `bstr`" | `pid_03_portrait_optout_empty` |
| PID_04 | PP | Yes | ISO/IEC 18013-5 docType | "PID Providers SHALL use "eu.europa.ec.eudi.pid.1" as the attestation type for ISO/IEC 18013-5-compliant PIDs." | `pid_04_doctype` |
| PID_05 | PP | Yes | ISO/IEC 18013-5 namespace | "a PID Provider SHALL use the value "eu.europa.ec.eudi.pid.1" for the identifier of the namespace for the PID attributes" | `pid_05_namespace` |
| PID_06 | PP | Yes | ISO/IEC 18013-5 namespaces | "If so, these attributes SHALL be defined within a domestic PID namespace as meant in requirement ARB_10" | `pid_06_domestic_ns_format (eu.europa.ec.eudi.pid.<cc>[.n])` |
| PID_07 | PP | Organisational | Attestation Rulebook | "A PID Provider that defines a domestic namespace SHALL publish the namespace…in an Attestation Rulebook" | — |
| PID_08 | PP | Yes | ISO/IEC 18013-5 IssuerSigned | "a PID Provider SHALL include both the attributes and the metadata specified in [CIR 2024/2977] in the PID as issuer-signed data elements." | `pid_08_metadata_issuer_signed` |
| PID_09 | PP | Yes | PID Rulebook §3.1.2 (ARF text cites stale "Section 4.2.1") | "a PID Provider SHALL encode each attribute or metadata in the PID as specified in the third column of the tables" | `pid_09_mdoc_encoding_table` |
| PID_10 | PP | Yes | RFC 8949 CBOR | "a PID Provider SHALL encode each attribute or metadata in the PID in Concise Binary Object Representation (CBOR) according to [RFC 8949]." | `pid_10_cbor` |
| PID_11 | PP | Yes | ISO/IEC 18013-5 | "a PID Provider SHALL ensure that each PID contains at most one attribute with the same attribute identifier." | `pid_11_no_duplicate_elements` |
| PID_12 | PP | Yes | ISO/IEC 18013-5 §9.1.2.4 (MSO validFrom) | "SHALL ensure that the value of all attributes and metadata in the PID is valid at…the validFrom element in the MSO" | `pid_12_values_valid_at_validFrom (e.g. age_over_*)` |
| PID_13 | PP | Partly (policy + consistency test) | ISO/IEC 18013-5 §9.1.2.4 | "the PID Provider SHALL have a policy for determining the value of these attributes relative to the `validFrom` and `validUntil` elements in the MSO" | `pid_13_admin_vs_technical_validity_mdoc` |
| PID_14 | PP | Yes | SD-JWT VC `vct` | "The type indicated by the vct claim SHALL be `urn:eudi:pid:1` for the type defined in this document or a domestic type that extends it." | `pid_14_vct_urn_eudi_pid` |
| PID_16 | PP | Organisational | Attestation Rulebook / SD-JWT VC Type Metadata | "A PID Provider that defines a domestic type SHALL publish information about the type" | — |
| PID_17 | PP | Yes | SD-JWT VC | "a PID Provider SHALL include both the attributes and the metadata specified in [CIR 2024/2977] in the PID as claims." | `pid_17_metadata_as_claims` |
| PID_18 | PP | Yes | PID Rulebook §4.1.1 (ARF text cites stale "Section 5.2") | "a PID Provider SHALL encode each attribute or metadata in the PID as specified in the tables in [Section 5.2 of the PID Rulebook]" | `pid_18_sdjwt_claim_mapping` |
| PID_19 | PP | Yes | SD-JWT VC `nbf` | "SHALL ensure that the value of all attributes and metadata in the PID is valid at the value of the timestamp in the nbf claim, if present." | `pid_19_values_valid_at_nbf` |
| PID_20 | PP | Partly (policy + consistency test) | SD-JWT VC §3.2.2.2 (nbf/exp) | "the PID Provider SHALL have a policy for determining the value of these claims relative to the `nbf` and `exp` claims in the SD-JWT VC" | `pid_20_admin_vs_technical_validity_sdjwt` |
| PID_21 | PP | Yes | SD-JWT / SD-JWT VC (non-SD claims per SD-JWT VC) | "a PID Provider SHALL make all claims (i.e., all top-level properties, all nested properties, and all array entries) selectively disclosable individually" | `pid_21_recursive_sd (address.*, nationalities[i], place_of_birth.*)` |
| ISSU_25 | AP | Yes | Attestation Rulebook | "An Attestation Provider SHALL ensure all attestations issued to Wallet Units comply with the requirements specified in the applicable Attestation Rulebook" | `issu_25_rulebook_conformance` |
| ARB_01b | Scheme Provider (AP inherits via ISSU_25) | Yes | HAIP 1.0 §6.1 (IETF SD-JWT VC profile) | "SHALL ensure that these attestations comply with the 'IETF SD-JWT VC Profile' specified in [HAIP] Section 6.1." | `arb_01b_haip_sdjwtvc_profile` |
| ARB_25 | Scheme Provider (AP inherits) | Yes | Attestation Rulebook template | "An Attribute Schema Provider SHALL include in its Attestation Rulebook the attribute `attestation_legal_category`" | `arb_25_attestation_legal_category_present` |
| ARB_30 | Scheme Provider (AP inherits) | Yes | SD-JWT VC | "SHALL specify for all claims…whether an Attestation Provider MUST, MAY, or MUST NOT make that claim selectively disclosable." | `arb_30_sd_policy_per_claim` |
| ARB_34 | Scheme Provider (AP inherits) | Yes | — | "The Scheme Provider for an Attestation Rulebook SHALL specify whether that attestation is device-bound or not." | `arb_34_device_binding_per_type` |

### 2a. PID Rulebook encoding rules (not HLRs; normative text of the PID Rulebook v1.7)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| PIDRB-§3.1.2a | PP | Yes | ISO/IEC 18013-5 (CBOR tstr) | "All attributes having encoding type `tstr` SHALL have a maximum length of 150 characters." | `pidrb_mdoc_tstr_max150` |
| PIDRB-§3.1.2b | PP | Yes | RFC 8949 | "a `tstr` SHALL be encoded in UTF-8 and SHALL support the full Unicode range." | `pidrb_mdoc_utf8_full_unicode` |
| PIDRB-§3.1.2c | PP | Yes | RFC 8943 tag 1004 | "This document specifies `full-date` as `full-date = #6.1004(tstr)`, where tag 1004 is specified in [RFC 8943]." | `pidrb_mdoc_full_date_tag1004` |
| PIDRB-§3.1.2d | PP | Yes | RFC 3339 | "Fractions of seconds SHALL NOT be used;…the time-offset defined in [RFC 3339] SHALL be set to "Z"." | `pidrb_mdoc_tdate_no_fraction_utc_z` |
| PIDRB-§3.1.2e | PP | Yes | RFC 8949 §4.2 (3 of 4 canonical rules) | "integers (major types 0 and 1) SHALL be as small as possible;…indefinite-length items SHALL be made into definite-length items." | `pidrb_mdoc_canonical_cbor` |
| PIDRB-§3.1.4 | PP | Yes | CDDL (RFC 8610) | "place_of_birth SHALL contain at least one of the following key-value pairs: `"country"`, `"region"`, or `"locality"`." | `pidrb_mdoc_place_of_birth_nonempty` |
| PIDRB-§2.2 | PP | Yes | ISO 3166-1 | "If unknown, value `QU`. If the user does not hold a nationality, value `QS`." | `pidrb_nationality_alpha2_qu_qs` |
| PIDRB-§2.5 | PP | Yes | ISO 3166-2 | "The first part of the code shall be the same as the value for the issuing country." | `pidrb_issuing_jurisdiction_prefix` |
| PIDRB-§4.1.1a | PP | Yes | SD-JWT VC (JSON) | "A JSON string used in an SD-JWT VC-encoded PID SHALL be encoded in UTF-8 and SHALL support the full Unicode range" | `pidrb_sdjwt_utf8` |
| PIDRB-§4.1.1b | PP | Yes | OIDC4IDA eKYC §4.1 | "At least one of the members (country, region or locality) SHALL be present in the JSON structure" | `pidrb_sdjwt_place_of_birth_nonempty` |
| PIDRB-§4.1.1c | PP | Yes | OIDC Core §5.1 `picture` | "data URL containing the base64-encoded portrait in JPEG format" | `pidrb_sdjwt_picture_data_url_jpeg` |
| PIDRB-§4.1.1d | PP | Yes | JWT nbf/exp | "The standard JWT claims nbf and exp are used to express the technical validity period of a SD-JWT VC-compliant PID." | `pidrb_sdjwt_nbf_exp_present` |


## 3. Wallet Unit Attestation (WIA) and Key Attestation (KA) checks

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| ISSU_17 | PP | Yes | ISO 18013-5 mdoc authentication (MSO device key); SD-JWT VC key binding (`cnf`) | "A PID Provider SHALL implement device binding for all PIDs it issues" | `issu_17_pid_device_bound` |
| ISSU_27 | AP | Yes | ISO 18013-5 / SD-JWT VC key binding | "If an issued attestation is device-bound, the Attestation Provider SHALL ensure that the attestation is cryptographically bound to a WSCA/WSCD or a keystore" | `issu_27_eaa_device_binding` |
| WUA_09a | PP, AP | Yes | OID4VCI App. D (`attested_keys`) | "the PID Provider or Attestation Provider SHALL bind the issued PID(s) or attestation(s) to one of the public keys attested in the KA" | `wua_09a_bind_to_attested_key` |
| WUA_11a | PP, AP | Yes | OID4VCI App. F.4; TS3 §2.2.2.2, §2.4.3 | "the PID Provider or Attestation Provider SHALL verify the KA in accordance with the requirements in [OpenID4VCI] Appendix F.4…SHALL validate that the KA is not revoked." | `wua_11a_ka_verify_and_status` |
| WUA_12 | PP, AP | Yes | OID4VCI proof types `jwt` / `attestation` (c_nonce) | "the PID Provider or Attestation Provider SHALL receive a proof that the Wallet Unit possesses the private keys corresponding to all public keys in the KA." | `wua_12_ka_pop` |
| WUA_25 | PP, AP | Yes | OID4VCI App. E (wallet attestation at PAR + token endpoint); TS3 §2.2.1.2 | "the PID Provider or Attestation Provider SHALL verify the WIA in accordance with the requirements in [OpenID4VCI] Appendix E…SHALL validate that the WIA is not revoked." | `wua_25_wia_verify_and_status` |
| WUA_34 | PP | Yes | OID4VCI App. D `key_storage` (iso_18045_high); TS3 §2.3.2 | "During issuance of a PID, a PID Provider SHALL verify that the keys attested in the KA are stored in the WSCA/WSCD described in the KA." | `wua_34_pid_key_in_wscd` |
| WUA_10a | AP (non-device-bound) | Yes | OID4VCI §12.2.4 metadata; TS3 §2.2.2.2 | "An Attestation Provider issuing non-device-bound attestations SHALL indicate in its Credential Issuer metadata that it does not need a KA" | `wua_10a_no_ka_metadata` |
| WUA_04 | PP, AP (and WP, Wallet) | Yes | ECCG ACM v2.0; TS3 §2.6 (ES256/384/512) | "When issuing, presenting, or verifying a WIA or KA…PID Providers, and Attestation Providers SHALL only use cryptographic algorithms included in the [ECCG Agreed Cryptographic Mechanisms v2.0]." | `wua_04_wua_alg_allowlist` |
| WUA_32 | PP, AP | Yes | TS3 §2.4 (`preferred_client_status_period`, `preferred_key_storage_status_period`) | "SHALL communicate these requirements to the Wallet Unit at the time of PID or attestation issuance" | `wua_32_preferred_status_period_metadata` |
| WUA_36 | PP, AP | Yes | TS3 (all) | "A PID Provider or Attestation Provider SHALL comply with all relevant requirements specified in [Technical Specification 3]" | `wua_36_ts3_conformance (umbrella)` |
| WUA_29 | PP | Yes | Token Status List; TS3 §2.3.1, §2.4.3 (check every 24h) | "Throughout the entire validity period of an issued PID, the PID Provider SHALL verify the revocation status of both the Wallet Instance and WSCD…SHALL revoke the PID." | `wua_29_revocation_chaining_job` |
| WUA_30 | PP | Yes | TS3 §2.4.3 | "The technical validity period of a PID SHALL be consistent with the period during which the Wallet Provider has committed to maintaining the revocation status" | `wua_30_pid_validity_within_status_maintenance` |
| ISSU_12c | PP | Yes | TS3 §2.4.3 (`client_status.exp`, `key_storage_status.exp`) | "The expiration date of a PID SHALL be no later than the end of the revocation maintenance periods of the WIA and the KA" | `issu_12c_pid_exp_le_status_exp` |
| ISSU_12d | AP (if chaining) | Yes | TS3 §2.4.3 | "the expiration date of an attestation SHALL be no later than the end of the revocation maintenance periods of the WIA and the KA (if applicable)" | `issu_12d_eaa_exp_le_status_exp` |
| ISSU_19 | PP | Yes | Wallet Provider LoTE (ETSI TS 119 602) | "a PID Provider SHALL accept the Wallet Provider trust anchors it needs, as published by the Commission in the Wallet Provider LoTE." | `issu_19_wp_trust_anchors_from_lote` |
| ISSU_19b | PP | Yes | ETSI TS 119 602 LoTE | "For the retrieval and management of trust anchors, PID Providers SHALL support LoTEs complying with [ETSI TS 119 602]." | `issu_19b_lote_parser` |
| ISSU_21 | PP | Yes | OID4VCI App. D/E; TS3 | "Before issuing a PID, a PID Provider SHALL verify the Wallet Unit's WIA and KA using a trust anchor registered in the Wallet Provider LoTE." | `issu_21_wia_ka_chain_to_lote` |
| ISSU_27d | AP (device-bound) | Yes | OID4VCI §12.2.4 + App. D.2 (`key_storage`, `user_authentication`) | "An Attestation Provider issuing device-bound attestations SHALL indicate the desired level of security for the private key storage and for User authentication in its Credential Issuer metadata" | `issu_27d_key_attestations_required_levels` |
| ISSU_28 | AP | Yes | Wallet Provider LoTE | "an Attestation Provider SHALL accept all Wallet Provider trust anchors published by the Commission in the relevant LoTE, and only those." | `issu_28_all_and_only_wp_anchors` |
| ISSU_28a | AP | Yes | ETSI TS 119 602 | "For the retrieval and management of trust anchors, Attestation Providers SHALL support LoTEs complying with [ETSI TS 119 602]." | `issu_28a_lote_parser` |
| ISSU_30 | AP | Yes | OID4VCI App. D; TS3 §2.4.3 | "Before issuing a device-bound attestation, an Attestation Provider SHALL verify the Wallet Unit's key attestation using a trust anchor registered in the Wallet Provider LoTE." | `issu_30_ka_chain_and_status` |
| ISSU_30a | AP | Yes | OID4VCI App. E | "verify that the Wallet Provider mentioned in the Wallet Unit's WIA is present in the Wallet Provider LoTE." | `issu_30a_wia_provider_in_lote` |
| VCR_12a | PP, AP | Yes | Token Status List (TS3 §2.5) | "A PID Provider or Attestation Provider SHALL support the mechanism specified per VCR_01a for verifying the revocation status of a WIA or KA." | `vcr_12a_tsl_client` |
| WPNot_04 | PP, AP | Yes | Wallet Provider LoTE (sealed by Commission) | "PID Providers, Attestation Providers, and other relevant actors SHALL accept Wallet Provider trust anchors and the trust anchors for WIA and KA revocation lists" | `wpnot_04_status_list_signer_anchor` |
| WURevocation_18 | PP | Yes | TS3 §2.4.3 | "A PID Provider issuing revocable PIDs SHALL, for each of its valid PIDs, regularly verify whether the Wallet Instance on which that PID is residing has been revoked" | `wurev_18_chain_revoke_immediately` |
| WURevocation_11 | PP (and WP) | Partly (outbound revocation request on death) | TS3 (WIA `client_status`) | "the PID Provider SHALL use a Wallet Instance identifier provided by the Wallet Provider in the WIA during PID issuance." | `wurev_11_store_wia_client_status_for_death_flow` |
| WURevocation_13 | PP | Organisational | — | "the PID Provider SHALL ensure that the revocation does not harm the interests of any of the stakeholders." | — |
| WURevocation_19 | AP | Organisational | — | "An Attestation Provider SHALL publish its policy in this regard." | — |

### 3a. TS3 v1.5.2 issuer-side requirements (not HLRs; pulled in by WUA_36 / ISSU_01a)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| TS3-§2.2.1.2a | PP, AP | Yes | OID4VCI App. E; JWS `x5c` | "they SHALL verify that the signature of the WIA verifies under the public key in the signing certificate included in the `x5c` parameter" | `ts3_wia_sig_x5c` |
| TS3-§2.2.1.2b | PP, AP | Yes | JWT `exp` | "When a PID Provider or Attestation Provider receives a WIA, then they SHALL check that it has not expired." | `ts3_wia_not_expired` |
| TS3-§2.2.1.2c | PP, AP | Yes | OID4VCI App. E PoP | "they SHALL check the signature of the PoP verifies under the public key present in the `cnf`." | `ts3_wia_pop_cnf` |
| TS3-§2.2.2.2a | PP, AP (device-bound) | Yes | OID4VCI §12.2.4 `proof_types_supported` | "it supports both the `jwt` and the `attestation` proof types for KAs" | `ts3_meta_both_proof_types` |
| TS3-§2.2.2.2b | AP (non-device-bound) | Yes | OID4VCI §12.2.4 | "An Attestation Provider issuing non-device-bound attestations SHALL omit the `proof_types_supported` and the `cryptographic_binding_methods_supported` parameters" | `ts3_meta_omit_binding_for_nonbound` |
| TS3-§2.2.2.2c | PP, AP | Yes | OID4VCI `jwt` proof | "they SHALL verify that the signature of the `jwt` element verifies under the key at index 0 of the `attested_keys` array" | `ts3_jwt_proof_signed_by_attested_keys0` |
| TS3-§2.2.2.2d | PP, AP | Yes | OID4VCI Nonce Endpoint `c_nonce` | "they SHALL verify that the `jwt` element includes a valid `c_nonce` from their `nonce_endpoint` in the `nonce` field" | `ts3_c_nonce_valid` |
| TS3-§2.3.1 | PP | Yes | Token Status List | "A PID Provider that has issued a PID to this Wallet Unit SHALL check this `client_status.status` entry at least once every 24 hours" | `ts3_wia_status_poll_24h` |
| TS3-§2.3.2a | PP | Yes | OID4VCI App. D `key_storage` | "During PID issuance, the PID Provider SHALL ensure that the PID they issue is bound to a key originating from a KA whose key storage is a WSCD." | `ts3_pid_key_from_wscd_ka` |
| TS3-§2.4.3a | PP | Yes | `client_status.exp`, `key_storage_status.exp` | "The technical validity period of a PID SHALL end before the `client_status.exp` of the WIA and the `key_storage_status.exp` of the KA" | `ts3_pid_validity_lt_status_exp` |
| TS3-§2.4.3b | AP (device-bound) | Yes | Token Status List | "Before issuing a device-bound attestation, an Attestation Provider SHALL verify the revocation status of the KA received during issuance." | `ts3_ap_ka_status_at_issuance` |
| TS3-§2.6 | PP, AP | Yes | JWA ES256/ES384/ES512 | "PID Providers and Attestation Providers SHALL support all of these" | `ts3_support_es256_es384_es512` |

**Implementation notes (TS3 v1.5.2):**
- The WIA is an OID4VCI App. E client attestation, sent to the **Authorization Server** at both PAR and the Token Request. The KA is a `key_attestation` sent in the **Credential Request** inside a `jwt` proof (header) or an `attestation` proof. TS3 §2.4.3 notes that the AS must hand the WIA's `client_status` to the Credential Issuer, for example inside the access token. Without that hand-off, WUA_29 and WURevocation_18 cannot be met.
- Field names are new in TS3 1.5: `client_status{status,exp}` in the WIA, `key_storage_status{status,exp}` in the KA, plus `wallet_name`, `wallet_version`, `wallet_solution_certification_information`, and the App. D `certification`. `iss` is gone, and the Wallet Provider is identified from the `x5c` signing certificate. The token-level `exp` is **not** the revocation-maintenance end.
- TS3 §2.4.2 binds Wallet Providers to always be able to present WIAs and KAs whose `*_status.exp` is ≥ 31 days in the future. A PID Provider can therefore request ≥ 1 month through `preferred_key_storage_status_period` / `preferred_client_status_period`.
- With the "per-issuer reuse" option (TS3 §2.5.1), the WIA `client_status.status` index stays stable across one wallet's interactions with your issuer. That makes it a pseudonymous per-issuer wallet identifier, and per ISSU_35b it must not be shared.
- TS3 §2.2.2.2 writes `key_attestation_required`, while TS3 §2.4 and OID4VCI use `key_attestations_required`. Implement the OID4VCI name.
- The ARF repo bundles an older TS3 copy (v1.5.1), which still requires the WIA `cnf` key to be the DPoP key. v1.5.2 in the TS repo rolled that back. Pin v1.5.2.

## 4. Revocation and status (time limits, validity, short-lived credentials)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| VCR_01 | PP, QEAA, PuB-EAA (mdoc) | Yes | CIR 2024/2979 Annex 2 (ISO/IEC 18013-5 2nd ed. status/identifier lists) | "Only issue short-lived attestations having a validity period of 24 hours or less…Use an Attestation Status List mechanism specified per VCR_11" | `vcr_01_mdoc_shortlived_or_list` |
| VCR_01b | PP, QEAA, PuB-EAA (SD-JWT VC) | Yes | Token Status List | "Only issue short-lived attestations having a validity period of 24 hours or less…Use an Attestation Status List mechanism specified per VCR_11." | `vcr_01b_sdjwt_shortlived_or_tsl` |
| VCR_11 | PP, AP (mdoc) | Yes | CIR 2024/2979 Annex 2 | "the PID Provider or Attestation Provider SHALL implement the Attestation Status List or Attestation Revocation List mechanism as specified in Annex 2" | `vcr_11_mdoc_status_mechanism` |
| VCR_11a | PP, AP (SD-JWT VC) | Yes | IETF Token Status List | "the PID Provider or Attestation Provider SHALL implement the Attestation Status List mechanism as specified in [Token Status List]." | `vcr_11a_sdjwt_status_list` |
| VCR_02 | Scheme Provider / EAA Provider | Partly | Attestation Rulebook | "the relevant Rulebook SHALL specify whether that type of EAA must be revocable." | `vcr_02_rulebook_revocability_config` |
| VCR_03 | PP, AP | Organisational | — | "SHALL be the only party in the EUDI Wallet ecosystem responsible for executing the revocation of that PID or attestation." | — |
| VCR_04 | PP, AP, WP | Yes | Token Status List / ARL | "A PID Provider, Attestation Provider, or Wallet Provider that revoked a PID, attestation, WIA, or KA SHALL NOT reverse the revocation." | `vcr_04_revocation_irreversible` |
| VCR_05 | PP, AP, WP | Organisational | — | "the PID Provider, Attestation Provider, or Wallet Provider SHALL have a policy specifying under which conditions a PID, attestation, WIA, or KA it issued will be revoked." | — |
| VCR_06 | PP, AP | Partly | — | "the PID Provider or Attestation Provider SHALL revoke a PID or attestation when its security has been compromised." | `vcr_06_compromise_bulk_revoke` |
| VCR_07a | PP | Partly (needs user revocation-request channel) | — | "If a PID is revocable, the PID Provider SHALL revoke that PID upon the explicit request of the User to whom the PID was issued." | `vcr_07a_user_request_revoke` |
| VCR_07b | AP | Partly (SHOULD) | — | "If an attestation is revocable, the Attestation Provider SHOULD revoke that attestation upon the explicit request of the User" | `vcr_07b_user_request_revoke` |
| VCR_07c | PP | Yes | TS3 / Token Status List | "If a PID is revocable, the PID Provider SHALL revoke that PID if the Wallet Unit on which it resides is revoked" | `vcr_07c_chain_revoke` |
| VCR_07d | AP | Partly (MAY) | TS3 | "If an attestation is revocable, the Attestation Provider MAY revoke that attestation if the Wallet Unit on which it resides is revoked" | `vcr_07d_optional_chain_revoke` |
| VCR_08 | PP | Partly (death-registry feed) | — | "If a PID is revocable, the PID Provider SHALL revoke a PID upon the death of the natural person who is the subject of the PID." | `vcr_08_death_revoke` |
| VCR_09 | PP, AP | Yes | — | "revoke that PID or attestation if the value of one or more of the attributes…was changed…and the technical PID…is still valid for at least 24 hours." | `vcr_09_attr_change_revoke_if_ge_24h` |
| EDP_11 | AP | Yes | ETSI TS 119 472-3 EDP | "An Attestation Provider SHALL revoke an attestation if a corresponding embedded disclosure policy is added, changed, or deleted." | `edp_11_edp_change_revoke` |
| PPNot_03a | PP | Yes | PID Provider LoTE (ETSI TS 119 602 Annex D) | "PID Providers SHALL ensure that all Attestation Status Lists or Attestation Revocation Lists used to revoke their PIDs can be authenticated" | `ppnot_03a_status_list_signer_notified` |
| PuBPNot_05 | PuB-EAA | Yes | PuB-EAA LoTE (ETSI TS 119 602 Annex H) | "PuB-EAA Providers SHALL ensure that all Attestation Status Lists and Attestation Revocation Lists used to revoke their PuB-EAAs can be authenticated" | `pubpnot_05_status_list_signer_notified` |
| RP_02 | AP (representation attestations) | Partly | — | "SHALL ensure that either the attestations are short-lived or that all entities which, according to applicable law, must have the ability to request revocation" | `rp_02_representation_shortlived_or_revocable` |
| ARB_24a | Scheme Provider (AP inherits) | Yes | Token Status List `uri` / ARL URL | "If an attestation is revocable, the relevant Attestation Rulebook SHALL specify the URL at which Relying Parties and other entities can retrieve the relevant Attestation Status Lists" | `arb_24a_status_host_matches_rulebook` |

**Time limits and validity rules collected from the sources:**

| Rule | Value | Source |
|---|---|---|
| Short-lived attestations may skip revocation | technical validity ≤ 24 h | VCR_01, VCR_01b (from ETSI EN 319 411-1 REV-6.2.4-03A) |
| Revoke on attribute change | only if the technical PID/attestation is still valid ≥ 24 h | VCR_09 |
| PID Provider polling of WIA + KA status | at least once every 24 h for the PID's validity; at issuance only if the PID is valid < 24 h | TS3 §2.3.1, §2.4.3 |
| PID technical validity upper bound | ends before `client_status.exp` (WIA) **and** `key_storage_status.exp` (KA) | ISSU_12c, WUA_30, TS3 §2.4.3 |
| EAA technical validity upper bound | the same, but only if the AP chooses revocation chaining | ISSU_12d, TS3 §2.4.3 |
| WIA TTL (Wallet Provider) | < 24 h | TS3 §2.2.1.1, WUA_33 |
| Revocation is final | no un-revoke (no "valid" after "invalid" in a status list) | VCR_04 |
| Mechanism by format | mdoc: short-lived, ASL or ARL (CIR 2024/2979 Annex 2). SD-JWT VC: short-lived or Token Status List only | VCR_01, VCR_01b, VCR_11, VCR_11a |
| Status list access | no RP authentication | VCR_16 |

## 5. Issuer authentication (signing certificates, access certificates, trusted lists / LoTEs, x5c)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| ISSU_22 | PP | Yes | OID4VCI §12.2.3 signed metadata; JWS `x5c` (RFC 7515) | "A PID Provider SHALL sign its Credential Issuer metadata as specified in section 12.2.3 of [OpenID4VCI]…include its access certificate…in the `x5c` parameter" | `issu_22_signed_metadata_x5c_access_cert_chain` |
| ISSU_32 | AP | Yes | OID4VCI §12.2.3; JWS `x5c` | "An Attestation Provider SHALL sign its Credential Issuer metadata as specified in section 12.2.3 of [OpenID4VCI]…in the `x5c` parameter" | `issu_32_signed_metadata_x5c_access_cert_chain` |
| ISSU_68 | PP | Yes (certificate profile lint) | ETSI TS 119 412-6 Clause 4 | "PID Providers SHALL ensure that the certificates they use for signing PIDs comply with all applicable requirements in [ETSI TS 119 412-6], in particular Clause 4." | `issu_68_pid_signer_cert_profile` |
| ISSU_70 | QEAA | Yes (cert lint) | ETSI TS 119 412-6 Clause 7 | "QEAA Providers SHALL ensure that the certificates they use for signing QEAAs comply with all applicable requirements in [ETSI TS 119 412-6], in particular Clause 7." | `issu_70_qeaa_signer_cert_profile` |
| ISSU_71 | EAA | Yes (cert lint) | ETSI TS 119 412-6 Clause 6 | "Providers of non-qualified EAAs SHALL ensure that the certificates they use for signing EAAs comply with all applicable requirements in [ETSI TS 119 412-6], in particular Clause 6." | `issu_71_eaa_signer_cert_profile` |
| ISSU_73 | PuB-EAA | Yes (cert lint) | ETSI TS 119 412-6 Clause 8 | "PuB-EAAs Providers SHALL ensure that the certificates they use for signing PuB-EAAs comply with all applicable requirements in [ETSI TS 119 412-6], in particular Clause 8." | `issu_73_pubeaa_signer_cert_profile` |
| ISSU_67 | PP | Organisational | ETSI TS 119 471 cl. 6-7; ETSI EN 319 411-1 NCP+ | "A PID Provider SHALL have a policy governing all aspects of PID issuance and management, in line with clauses 6 and 7 of [ETSI TS 119 471]" | — |
| ISSU_69 | QEAA | Organisational | ETSI TS 119 471; ETSI EN 319 411-2 QCP-n-qscd / QCP-l-qscd | "A QEAA Provider SHALL have a policy governing all aspects of QEAA issuance and management, in line with clauses 6 and 7 of [ETSI TS 119 471]" | — |
| ISSU_72 | PuB-EAA | Organisational | ETSI TS 119 471; ETSI EN 319 411-1 NCP+ | "A PuB-EAA Provider SHALL have a policy governing all aspects of PuB-EAA issuance and management, in line with clauses 6 and 7 of [ETSI TS 119 471]" | — |
| PPNot_03 | PP | Yes | PID Provider LoTE (ETSI TS 119 602 Annex D, per PPNot_07) | "PID Providers SHALL ensure that all PIDs they issue can be authenticated using the PID Provider trust anchors notified to the Commission." | `ppnot_03_pid_chain_to_notified_anchor` |
| PPNot_04 | PP | Yes | Access CA LoTE | "PID Providers SHALL ensure that their access certificates can be authenticated using the applicable Access Certificate Authority trust anchors notified to the Commission." | `ppnot_04_access_cert_chain_to_access_ca` |
| PuBPNot_04 | PuB-EAA | Yes | PuB-EAA LoTE (ETSI TS 119 602 Annex H) | "PuB-EAA Providers SHALL ensure that all PuB-EAAs they issue can be authenticated using the trust anchors notified to the Commission." | `pubpnot_04_chain_to_notified_anchor` |
| Reg_10a | PP, AP (as registering entity) | Partly | TS5 / TS6 | "A registering entity SHALL register one or more Services, and SHALL receive at least one access certificate for each registered Service" | `reg_10a_access_cert_per_service` |
| Reg_10e | PP, AP | Organisational | TS6 | "A PID Provider or Attestation Provider SHALL register which type(s) of attestation each of its registered Services intends to issue to Wallet Units." | — |
| Reg_08 | PP, AP | Organisational | TS5 / TS6 | "SHALL make any updates necessary to ensure the continued correctness of the registered information without undue delay." | — |
| Reg_31 | Access CA (issuer self-check) | Yes | access certificate profile (ETSI TS 119 411-8) | "An access certificate SHALL contain a trade name for the entity" | `reg_31_access_cert_trade_name_matches_regcert` |
| Reg_32 | Access CA (issuer self-check) | Yes | access certificate profile | "An access certificate SHALL contain an EU-wide unique identifier for the entity" | `reg_32_access_cert_identifier_matches_regcert` |


## 6. Registration certificates in Credential Issuer metadata (incl. "issuer_info")

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| RPRC_22 | PP, AP | Yes | OID4VCI Credential Issuer metadata + ETSI TS 119 472-3 (§4.2.3 per ISSU_24a) | "A PID Provider or Attestation Provider SHALL include the registration certificate of the applicable Service in its Credential Issuer metadata…by value, not by reference." | `rprc_22_regcert_by_value_in_metadata` |
| RPRC_14 | PP, AP | Partly (deployment config) | — | "SHALL distribute the registration certificates it received during registration to all service supply points having an access certificate containing the same Service identifier." | `rprc_14_regcert_service_id_matches_access_cert` |
| RPRC_15 | Provider of registration certificates (issuer self-check) | Yes | TS5 `providesAttestations` | "SHALL contain the type(s) of attestation that the applicable Service of this entity intends to issue to Wallet Units." | `rprc_15_regcert_lists_offered_types` |
| RPRC_05 | Provider of registration certificates (issuer self-check) | Yes | TS5 `intendedUse` | "the certificate SHALL NOT contain the intended use as meant in Annex I (9) and (10) of CIR 2025/848." | `rprc_05_no_intended_use_unless_also_rp` |
| RPRC_06 | reg-cert content (issuer self-check) | Yes | ETSI TS 119 475 | "which SHALL be identical to the trade name in the access certificates of the entity" | `rprc_06_trade_name_equal` |
| RPRC_07 | reg-cert content (issuer self-check) | Yes | ETSI TS 119 475 | "which SHALL be identical to the identifier in the access certificates of that entity" | `rprc_07_identifier_equal` |
| RPRC_07a | reg-cert content (issuer self-check) | Yes | ETSI TS 119 475 | "which SHALL be identical to the Service identifier and trade name in one or more of the access certificates of that entity" | `rprc_07a_service_id_equal` |
| RPRC_02 | Provider of registration certificates (issuer self-check) | Yes | JWS `x5c` | "the Provider of registration certificates SHALL include the signing certificate and…any intermediate certificate(s)…in the `x5c` parameter in the JOSE header" | `rprc_02_regcert_x5c_chain` |

**About `issuer_info`:** the string `issuer_info` does not appear anywhere in the ARF, TS or rulebook repositories at the pinned commits. The ARF only says that the access certificate and registration certificate are carried in Credential Issuer metadata "per [OpenID4VCI] and [ETSI TS 119 472-3]" (ARF main §6, and ISSU_24a/ISSU_34a cite ETSI TS 119 472-3 **§4.2.3**). The exact metadata parameter name and encoding must be taken from ETSI TS 119 472-3, which is not in these repos and was not verified here. TS5 v1.6 gives the content model a Wallet will inspect: `entitlements` URIs such as `https://uri.etsi.org/19475/Entitlement/PID_Provider`, `.../QEAA_Provider`, `.../PUB_EAA_Provider` and `.../Non_Q_EAA_Provider`, and `providesAttestations`, which must be non-empty for provider entitlements. These are exactly the fields that ISSU_24a/24b/34a/34b and RPRC_23 make the Wallet check. Note that those wallet-side checks apply only **24 months after** entry into force of the Regulation amending CIR 2024/2982, while RPRC_22 (the issuer must publish) has no such delay.

## 7. Batch issuance, one-time-use (Methods A-D) and re-issuance

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| ISSU_64 | PP, AP, Wallet | Yes | OID4VCI batch issuance (multiple proofs / `batch_credential_issuance` metadata) | "PID Providers, Attestation Providers, and Wallet Units SHALL support the features of [OpenID4VCI] enabling the batch issuance of technical PIDs or attestations." | `issu_64_batch_issuance` |
| ISSU_63 | PP, AP, Wallet | Yes | OID4VCI refresh-token based re-issuance | "PID Providers and Attestation Providers, and Wallet Units SHALL support the features of [OpenID4VCI] enabling the re-issuance of PIDs and attestations." | `issu_63_reissuance` |
| ISSU_65 | PP, AP (device-bound) | Yes | OID4VCI §14.5 (cited in HLR note; device-bound refresh token) | "SHALL verify that a re-issued technical PID or device-bound attestation is issued to the same Wallet Unit as the existing PID or attestation." | `issu_65_reissue_same_wallet_unit` |
| ISSU_43 | PP, AP (batch content) | Yes | OID4VCI batch | "All PIDs or attestations in a batch SHALL have the same attribute values and the same technical validity period." | `issu_43_batch_uniform (Method A)` |
| ISSU_51 | PP, AP (batch content) | Yes | OID4VCI batch | "All PIDs or attestations in a batch SHALL have the same attribute values and the same technical validity period." | `issu_51_batch_uniform (Method C)` |
| ISSU_38 | PP, AP | Organisational (risk analysis + parameter policy) | — | "A PID Provider or Attestation Provider SHALL have a policy describing which method(s) (i.e, A, B, C, and/or D) it will use" | — |
| ISSU_39 | PP, AP | Yes | ETSI TS 119 472-3 §4.2.4.2 `credential_reuse_policy` | "PID Providers and Attestation Providers SHALL include the `credential_reuse_policy` parameter…in their Credential Issuer Metadata…Indicated methods SHALL be ordered by preference." | `issu_39_credential_reuse_policy_present_ordered` |
| ISSU_40 | PP, AP | Yes | ETSI TS 119 472-3 §4.2.4.2 | "A PID Provider or Attestation Provider SHALL indicate in their OpenID4VCI Issuer metadata that either method A or method B must be used" | `issu_40_exactly_one_of_A_B` |
| ISSU_40a | PP, AP, Wallet | Yes | ETSI TS 119 472-3 §4.2.4 | "a Wallet Unit, PID Provider, or Attestation Provider SHALL comply with the applicable requirements in [ETSI TS 119 472-3], section 4.2.4." | `issu_40a_472_3_reuse_conformance` |
| ISSU_45 | PP, AP | Yes | ETSI TS 119 472-3 §4.2.4.2 (`batch_size`, lower limit) | "The PID Provider or Attestation Provider SHALL inform the Wallet Unit about the value of the lower limit and the size of the batch to be requested" | `issu_45_method_a_params` |
| ISSU_50 | PP, AP | Yes | ETSI TS 119 472-3 §4.2.4.2 | "The PID Provider or Attestation Provider SHALL inform the Wallet Unit about the moment at which the Wallet Unit must request the re-issuance" | `issu_50_method_b_reissue_trigger` |
| ISSU_54 | PP, AP | Yes | ETSI TS 119 472-3 §4.2.4.2 | "The PID Provider or Attestation Provider SHALL inform the Wallet Unit about the size of the batch and about the moment at which the Wallet Unit must request" | `issu_54_method_c_params` |
| ISSU_41 | PP, AP, WP | Partly | — | "Wallet Providers, PID Providers, and Attestation Providers SHALL ensure that Users do not notice which of the methods A, B, C, or D is used" | `issu_41_no_user_visible_method` |
| ISSU_42 | PP, AP, WP | Partly (refresh-token reissuance without user auth) | OID4VCI refresh token | "SHALL ensure that no User action is needed for the re-issuance of WIAs or KAs, PIDs, or attestations." | `issu_42_silent_reissuance` |


## 8. Logging / audit

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| ISSU_35b | PP, AP, WP | Partly (retention design + log redaction test) | — | "SHALL discard the values of all unique elements…as well as any timestamps, as soon as they are no longer needed." | `issu_35b_logs_redact_unique_values` |
| ISSU_67 / ISSU_69 / ISSU_72 | cross-ref (see section 5): PP / QEAA / PuB-EAA | Organisational (audit/event-logging duties inherited from ETSI TS 119 471 cl. 6-7 and EN 319 411-1/-2; those standards are not in the repo and were not verified) | ETSI TS 119 471; EN 319 411-1/-2 | "SHALL have a policy governing all aspects of PID issuance and management" | — |

**Gap:** no ARF 3.0.0 HLR directly requires a PID or Attestation Provider to keep an event log or audit trail. Topic 19 logging (DASH_*) binds the Wallet Unit, and Reg_09 binds the Member State. Issuer audit duties come only indirectly: ISSU_67/69/72 policies follow ETSI TS 119 471 cl. 6–7 and EN 319 411-1/-2 (NCP+/QCP), and VCR_05, ISSU_38, WURevocation_13 and WURevocation_19 require documented policies or risk analyses. Design tensions to settle explicitly:
- ISSU_35b requires discarding unique values (salts, digests, status indices, device keys, signatures) and timestamps "as soon as they are no longer needed". Yet WUA_29, WURevocation_11/18 and VCR_07a/09 require retaining the WIA `client_status` reference, the KA `key_storage_status` reference and the status index for each issued PID until it expires. Keep those in a minimal, access-controlled revocation store, and keep them **out of** application logs.
- DASH_05 makes the Wallet log the issuer's trade name, identifier, Service id, attestation type requested and issued, batch size, and the reason for any failed issuance. Return specific, non-PII OID4VCI error codes and descriptions so wallets can record a meaningful reason.

## 9. Data minimisation and privacy (unlinkability, status-index privacy)

| ID | Binds | Testable in issuer software | Protocol / spec mapping | Normative text (quoted excerpt) | Suggested check |
|---|---|---|---|---|---|
| ISSU_35 | PP, AP | Yes | ISO 18013-5 / SD-JWT VC (salts, digests, status idx, device key, signature) | "SHALL ensure that all unique elements in a PID or attestation have a negligible chance of having the same value across all PIDs or attestations issued by that Provider." | `issu_35_csprng_unique_elements` |
| ISSU_36 | PP, AP, WP | Yes | JWT iat/nbf/exp; MSO validityInfo | "SHALL ensure that the timestamps in these PIDs, attestations, or WIAs and KAs do not enable Relying Parties to conclude that they are part of the same batch" | `issu_36_timestamp_coarsening` |
| VCR_17 | PP, AP, WP | Yes | Token Status List / CIR 2024/2979 Annex 2 | "SHALL randomly assign the index for each PID or attestation, to prevent this index from becoming a correlator." | `vcr_17_random_status_index_no_dupes` |
| VCR_18 | PP, AP, WP | Partly (list sizing / decoys) | Token Status List | "SHALL represent a sufficiently large number of PIDs, attestations, WIAs, or KAs on each Attestation Status List to ensure herd privacy." | `vcr_18_min_list_size_decoys` |
| VCR_16 | PP, AP, WP | Yes | Token Status List endpoint | "SHALL NOT require the Relying Party or Relying Party Instance to authenticate itself before downloading an Attestation Status List" | `vcr_16_status_list_unauthenticated` |
| TS3-§2.3.2b | PP, AP | Yes (code review / negative test) | TS3 KA `key_storage_status.status.idx` | "PID Providers or Attestation Providers SHALL NOT use the KA `idx` as a Wallet Unit identifier." | `ts3_no_ka_idx_as_wallet_id` |

**Cross-references in other sections:** PID_21 (recursive selective disclosure), PID_03 (portrait opt-out), ISSU_43/51 (a batch must be uniform, so coarsen timestamps identically within a batch), and VCR_04 (the status list never moves back to valid). ISSU_36a puts precise timestamps that a use case needs into a selectively disclosable attribute defined by the rulebook. PAD_03 says the Wallet will **not** notify the issuer when a PID is deleted, so do not design flows that depend on such a notification.

## 10. PID attributes: data identifier vs mdoc vs SD-JWT VC

Source: `rulebooks/pid/pid-rulebook.md` v1.7 (commit `36f8adc`): §2.2 and §2.4 (presence), §3.1.2 (mdoc), §4.1.1 (SD-JWT VC). The mdoc docType and namespace are both `eu.europa.ec.eudi.pid.1` (PID_04, PID_05). The SD-JWT VC `vct` is `urn:eudi:pid:1` or a domestic type under `urn:eudi:pid:` (PID_14).

### 10a. Mandatory attributes (CIR 2024/2977 Table 1) and mandatory metadata (Table 5)

| Data identifier (CIR) | Presence | mdoc element identifier | mdoc encoding | SD-JWT VC claim | SD-JWT VC encoding |
|---|---|---|---|---|---|
| family_name | M | `family_name` | `tstr` | `family_name` | string (OIDC §5.1) |
| given_name | M | `given_name` | `tstr` | `given_name` | string (OIDC §5.1) |
| birth_date | M | `birth_date` | `full-date` (tag 1004) | **`birthdate`** | string `YYYY-MM-DD` (OIDC §5.1) |
| birth_place | M | **`place_of_birth`** | map `{? country, ? region, ? locality}`, at least one present | **`place_of_birth`** | JSON object (eKYC §4.1), at least one of country/region/locality |
| nationality | M | **`nationality`** | array of alpha-2 `tstr` (`nationalities`); `QU` = unknown, `QS` = stateless | **`nationalities`** | array of alpha-2 strings |
| portrait | M (only **24 months after** the amending CIR enters into force; may be empty on user opt-out, PID_03) | `portrait` | `bstr` (JPEG, ISO/IEC 39794-5 / 19794-5) | **`picture`** | string: data URL, base64 JPEG |
| issuing_authority | M (metadata) | `issuing_authority` | `tstr` | `issuing_authority` | string |
| issuing_country | M (metadata) | `issuing_country` | `tstr` (alpha-2) | `issuing_country` | string |

### 10b. Optional attributes and metadata (the name differences that most often break interop)

| Data identifier | mdoc element / encoding | SD-JWT VC claim / encoding |
|---|---|---|
| resident_address | `resident_address` / `tstr` | `address.formatted` / string |
| resident_country | `resident_country` / `tstr` | `address.country` / string |
| resident_state | `resident_state` / `tstr` | `address.region` / string |
| resident_city | `resident_city` / `tstr` | `address.locality` / string |
| resident_postal_code | `resident_postal_code` / `tstr` | `address.postal_code` / string |
| resident_street | `resident_street` / `tstr` | `address.street_address` / string |
| (resident_house_number; see inconsistency F3) | none | `address.house_number` / string |
| personal_administrative_number | `personal_administrative_number` / `tstr` | `personal_administrative_number` / string |
| family_name_birth | `family_name_birth` / `tstr` | `birth_family_name` / string |
| given_name_birth | `given_name_birth` / `tstr` | `birth_given_name` / string |
| sex | `sex` / `uint` (0,1,2,3,4,5,6,9) | `sex` / number (not OIDC `gender`) |
| email_address | `email_address` / `tstr` | `email` / string |
| mobile_phone_number | `mobile_phone_number` / `tstr` | `phone_number` / string |
| expiry_date (metadata) | `expiry_date` / `tdate` or `full-date` | `date_of_expiry` / string `YYYY-MM-DD` |
| issuance_date (metadata) | `issuance_date` / `tdate` or `full-date` | `date_of_issuance` / string `YYYY-MM-DD` |
| document_number (metadata) | `document_number` / `tstr` | `document_number` / string |
| issuing_jurisdiction (metadata) | `issuing_jurisdiction` / `tstr` (ISO 3166-2, prefix = issuing_country) | `issuing_jurisdiction` / string |
| trust_anchor (rulebook-only) | `trust_anchor` / `tstr` | `trust_anchor` / string |
| attestation_legal_category (rulebook-only) | `attestation_legal_category` / `tstr` | `attestation_legal_category` / string |

The technical validity period is the MSO `validFrom`/`validUntil` for mdoc and `nbf`/`exp` for SD-JWT VC. It is distinct from `issuance_date`/`expiry_date` (or `date_of_issuance`/`date_of_expiry`), which carry the administrative validity (PID_13, PID_20, rulebook §2.5). Key binding uses `cnf` in SD-JWT VC and the MSO device key in mdoc. The rulebook does not specify `iss`, `status` or other technical claims ("not shown here", rulebook §4.3).

## 11. Wallet-side checks your issuer's output must pass (wallet-binding; paraphrased)

| ID | What the Wallet verifies against your issuer |
|---|---|
| ISSU_06 / ISSU_11a | The received credential matches what was requested, and every member of a batch has identical attribute values and technical validity. |
| ISSU_07 / ISSU_09 / ISSU_08 | The PID signature chains to a PID Provider LoTE anchor; PuB-EAA chains to the PuB-EAA LoTE; QEAA is validated as a qualified signature against the QEAA Trusted List (ETSI TS 119 612). |
| ISSU_11 | The Wallet shows the issuer's identity using the subject of your **access certificate**, so the subject DN and trade name must be presentable to users. |
| ISSU_24 / ISSU_34 / CT_05 | The access certificate is authentic, currently valid, chains to the Access CA LoTE, and carries at least one valid SCT. |
| ISSU_24a/24b, ISSU_34a/34b, RPRC_22a/22b, RPRC_23 | The registration certificate in metadata is valid, its `entitlement` / `providesAttestations` covers the requested type, and its identifier equals the access certificate's. Mandatory from 24 months after the amending CIR 2024/2982. |
| ISSU_11b | On any failed check the Wallet deletes the credential and tells the user why. |
| WUA_05a / WUA_10a | The Wallet reads key-storage requirements from your metadata (ISSU_27d) and does not send a KA for non-device-bound types. |
| TS3 §2.2.2.1, §2.4.2 | A KA is used at most once, and re-issuance always carries a fresh KA. Issuers MAY detect KA replay (optional hardening). |
| Mig_07 / Mig_11 | After migration the Wallet asks for a fresh issuance (no refresh token), so the full user authentication path runs. |
| DASH_05 | The Wallet logs your identifiers, the types requested and issued, the batch size, and failure reasons. |

## 12. Inconsistencies and gaps found in the sources (verify before coding)

| # | Finding | Impact on issuer |
|---|---|---|
| F1 | PID_09 cites "Section 4.2.1 of the PID Rulebook" and PID_18 cites "Section 5.2". Rulebook v1.7 numbers these §3.1.2 and §4.1.1, and the ARF links point at Annex 3.01, which is now only a pointer file. | Cite the rulebook by version and section in test names, not the ARF link. |
| F2 | Rulebook §4.2 says "Requirement PID_15 … requires that the information on the common EU-wide type as well as on any domestic types is published", but PID_15 is **Empty** in ARF 3.0.0. | Publishing Type Metadata is not a current HLR; PID_16 still needs a rulebook for domestic types. |
| F3 | The SD-JWT VC table defines `address.house_number` (data identifier `resident_house_number`), which is absent from §2 (CIR) and from the mdoc table. | Do not emit it in mdoc. Treat it as optional SD-JWT-only. (Superseded in M4: the Annex of CIR 2024/2977 as replaced by 2026/1731 has no house number and puts it in resident_street, so cunho refuses it in either format, with trust_anchor and attestation_legal_category.) |
| F4 | Rulebook §6 says PID trust anchors are in a "Trusted List", and TS3 says "Trusted List for Wallet Providers". The ARF HLRs (OIA_12, PPNot_05/07, ISSU_19/19b) say **LoTE per ETSI TS 119 602** (Annex D for PID Providers). | Implement a LoTE (119 602) parser for Wallet Provider anchors, and publish PID anchors through the PID Provider LoTE. Use TS 119 612 only for QEAA. |
| F5 | TS3 §2.2.2.2 writes `key_attestation_required`; TS3 §2.4 and OID4VCI write `key_attestations_required`. | Use `key_attestations_required`. |
| F6 | The ARF repo bundles TS3 v1.5.1 (WIA `cnf` must equal the DPoP key); the TS repo has v1.5.2, which rolled that back. | Pin TS3 v1.5.2. Do not hard-fail on a DPoP key that differs from the WIA `cnf`. |
| F7 | `issuer_info` appears nowhere in the ARF, TS or rulebook repos; the carriage of access and registration certificates is delegated to ETSI TS 119 472-3 §4.2.3. | Take the parameter names from 472-3 itself. |
| F8 | ISSU_19 lets a PP accept the Wallet Provider anchors "it needs"; ISSU_28 requires an AP to accept "all … and only those"; ISSU_19a requires a PP to support all Wallet Solutions recognised under its eID scheme. | Make the WP-anchor allowlist configurable for PP and complete-by-default for AP. |
| F9 | PID_19 says attribute values must be valid "at … nbf, if present", but the rulebook uses `nbf`/`exp` as the technical validity. | Always emit `nbf` and `exp`. |
| F10 | ISSU_35b (discard unique values and timestamps) conflicts with WUA_29 / WURevocation_11/18 / VCR_07a/09 (which need stored references) and with audit policy obligations. | Define a retention matrix (see §8). |
| F11 | ISSU_43/51 require the same technical validity across a batch, while ISSU_36 requires timestamps that do not reveal a batch. | Coarsen `iat`/`nbf`/`exp` and MSO `signed`/`validFrom`/`validUntil` to a shared bucket, identical within the batch. |
| F12 | The portrait is mandatory only 24 months after the amending CIR enters into force; PID_03 opt-out produces an empty `""` or `bstr`. | Validators must accept an empty portrait. Do not omit the element. |

## 13. Top 10 requirements most likely to be failed by reference or sample issuers

This ranking is the analyst's judgement, based on how new each requirement is (ARF 2.9–3.0, TS3 1.5.x, ETSI 472-3) and how much non-protocol state it needs. It was **not** measured against any specific codebase.

1. **ISSU_22 / ISSU_32**: signed Credential Issuer metadata (OID4VCI §12.2.3) signed with the **access-certificate** key, with the full `x5c` chain up to the Access CA LoTE anchor. Samples typically serve unsigned JSON.
2. **RPRC_22** (with RPRC_06/07/07a): the registration certificate embedded **by value** in metadata, with identifier, trade name and Service id equal to the access certificate's.
3. **ISSU_39 / ISSU_40 / ISSU_45 / ISSU_50**: the `credential_reuse_policy` metadata (ETSI TS 119 472-3 §4.2.4.2), ordered by preference, containing exactly one of Method A or B, with batch size, lower limit and re-issue trigger.
4. **WUA_25 / ISSU_30a / TS3 §2.2.1.2**: WIA verification per OID4VCI App. E: `x5c` chain to the Wallet Provider **LoTE**, expiry, PoP under `cnf`, and `client_status` revocation.
5. **WUA_11a / WUA_34 / TS3 §2.2.2.2 / TS3 §2.3.2a**: KA verification per OID4VCI App. F.4: both `jwt` and `attestation` proof types advertised, `jwt` signed by `attested_keys[0]`, `c_nonce` check, `key_storage` = WSCD (iso_18045_high) for PID, and KA status check.
6. **WUA_29 / WURevocation_18 / TS3 §2.3.1 (+VCR_07c)**: a background job that re-checks the WIA and KA status at least every 24 h for every live PID and revokes immediately. This needs `client_status` carried from the AS to the Credential Issuer.
7. **ISSU_12c / WUA_30 / TS3 §2.4.3a**: PID `exp` / `validUntil` clamped below min(`client_status.exp`, `key_storage_status.exp`), not the token-level `exp`.
8. **VCR_17 / VCR_18**: random, collision-free status-list indices on lists large enough for herd privacy (decoys if needed). Samples allocate indices sequentially.
9. **ISSU_36 / ISSU_35 (+ISSU_35b)**: timestamp coarsening shared across a batch, CSPRNG salts and identifiers, and no unique values in logs.
10. **PID_21 (+PID_03, PID_14)**: every nested property and array element individually selectively disclosable (`address.*`, each `nationalities[i]`, `place_of_birth.*`), an empty portrait on opt-out, and `vct` = `urn:eudi:pid:1`.

Runners-up: ISSU_65 (re-issuance bound to the same Wallet Unit), VCR_09 (revoke on attribute change when ≥ 24 h of validity remain), ISSU_68 (signer certificate profile per ETSI TS 119 412-6 cl. 4), and the PIDRB-§3.1.2 rules (canonical CBOR, tag 1004 `full-date`, `Z` with no fractional seconds, `tstr` ≤ 150 characters).
