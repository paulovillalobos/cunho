# eIDAS 2.0: issuer-side obligations checklist (PID provider / attestation provider)

Compiled 2026-11-03 from the Official Journal texts. Every quote is from the act's English OJ text and is 30 words or fewer; "..." marks an omission. Where an obligation was later amended, the **text in force today** is quoted, with the amending act named.

## How the texts were obtained (read this first)

- `eur-lex.europa.eu` (including the ELI URL given in the brief) returned **HTTP 202 with an empty body** to automated clients (a bot challenge). The texts were therefore fetched from the **Publications Office Cellar** (`publications.europa.eu/resource/celex/<CELEX>`). That is the official repository EUR-Lex renders, and it serves the same OJ XHTML.
- Numbers, titles and dates were checked against the Publications Office SPARQL endpoint (CELEX number, `work_date_document`, English title) and against the OJ header of each downloaded text.
- **Coverage limit:** the search looked for 2024–2026 acts whose titles mention 910/2014, the Wallet, attestations of attributes, trusted lists, or "applicable standards and specifications". An act published in the last weeks may not be indexed yet.
- **Consolidation:** no consolidated versions were used. Amendments were applied by hand from the amending acts listed below. Before relying on any row in an audit, re-check it against the EUR-Lex consolidated version.

## 1. Acts verified, and whether they bind issuers

| CELEX | Act (number, title, date of adoption; OJ date) | Binds issuers? |
|---|---|---|
| 32024R1183 | Regulation (EU) 2024/1183 of 11 April 2024 amending Regulation (EU) No 910/2014 as regards establishing the European Digital Identity Framework (OJ L 30.4.2024). Corrigendum 32024R1183R(02), OJ 9.4.2025, fixes "unlikeability" to **"unlinkability"** in Art. 5a(16)(b). | **Yes**: Art. 5a(16), 19a, 24, 45d–45h, Annexes V–VII |
| 32014R0910 | Regulation (EU) No 910/2014, original text (used only for Art. 24(3)–(4), which Art. 24(4a) applies to QEAA) | Yes (QEAA) |
| 32024R2977 | Commission Implementing Regulation (EU) 2024/2977 of 28 Nov 2024 ... as regards person identification data and electronic attestations of attributes issued to European Digital Identity Wallets (OJ 4.12.2024) | **Yes, the core act** |
| 32024R2979 | CIR (EU) 2024/2979 of 28 Nov 2024 ... integrity and core functionalities of European Digital Identity Wallets (OJ 4.12.2024) | Indirectly. Its Annex II (formats and revocation, = ETSI TS 119 472-1) binds PID providers through 2024/2977 and QEAA/PuB-EAA providers through 2025/1569. Annex III covers embedded disclosure policies. |
| 32024R2980 | CIR (EU) 2024/2980 of 28 Nov 2024 ... notifications to the Commission concerning the European Digital Identity Wallet ecosystem (OJ 4.12.2024) | Indirectly. Member States notify PID providers and their signing certificates; this list is the PID trust anchor. |
| 32024R2981 | CIR (EU) 2024/2981 of 28 Nov 2024 ... certification of European Digital Identity Wallets (OJ 4.12.2024) | **No**: binds wallets and conformity assessment bodies |
| 32024R2982 | CIR (EU) 2024/2982 of 28 Nov 2024 ... protocols and interfaces to be supported by the European Digital Identity Framework (OJ 4.12.2024) | **Yes, in practice.** Annex I (issuance = ETSI TS 119 472-3) and Annex II (presentation) were inserted by 2026/1731. |
| 32025R0846 | CIR (EU) 2025/846 of 6 May 2025 ... cross-border identity matching of natural persons (OJ 7.5.2025; applies 24.12.2026) | No: binds Member States acting as relying parties |
| 32025R0847 | CIR (EU) 2025/847 of 6 May 2025 ... reactions to security breaches of European Digital Identity Wallets (OJ 7.5.2025) | No (Member States and wallets). It reaches issuers only through wallet unit attestation revocation, see 2977 Art. 5(4)(b). |
| 32025R0848 | CIR (EU) 2025/848 of 6 May 2025 ... registration of wallet-relying parties (OJ 7.5.2025; **applies 24.12.2026**) | **Yes**: PID and EAA providers register as wallet-relying parties with an issuer entitlement |
| 32025R0849 | CIR (EU) 2025/849 of 6 May 2025 ... submission of information ... for the list of certified European Digital Identity Wallets (OJ 7.5.2025) | No (Member States) |
| 32025R1566 | CIR (EU) 2025/1566 of 29 July 2025 ... reference standards for the verification of the identity and attributes of the person to whom the qualified certificate or the qualified electronic attestation of attributes is to be issued (OJ 30.7.2025; **applies 19.8.2027**) | **Yes (QEAA)** |
| 32025R1569 | CIR (EU) 2025/1569 of 29 July 2025 ... qualified electronic attestations of attributes and electronic attestations of attributes provided by or on behalf of a public sector body responsible for an authentic source (OJ 30.7.2025; Arts 6–9 apply 19.8.2026) | **Yes (QEAA, PuB-EAA)** |
| 32025R2160 | CIR (EU) 2025/2160 of 27 Oct 2025 ... management of risks to the provision of non-qualified trust services (OJ 28.10.2025) | **Yes (non-qualified EAA providers)** |
| 32025R2530 | CIR (EU) 2025/2530 of 16 Dec 2025 ... requirements for qualified trust service providers providing qualified trust services (OJ 17.12.2025) | **Yes (QEAA)** |
| 32025D2164 | Commission Implementing **Decision** (EU) 2025/2164 of 27 Oct 2025 amending Implementing Decision (EU) 2015/1505 (trusted list template, now based on ETSI TS 119 612 v2.4.1; applies 29.4.2026) | Indirectly. QEAA trust anchors are in national trusted lists. |
| 32026R0798 | CIR (EU) 2026/798 of 7 April 2026 ... remote onboarding of users to the European Digital Identity Wallets by eID means at level substantial plus additional remote onboarding procedures (OJ 8.4.2026) | **Yes (PID provider identity proofing)** |
| 32026R1730 | CIR (EU) 2026/1730 of 15 July 2026 amending CIR (EU) 2025/848 as regards applicable standards and specifications (OJ 22.7.2026) | Yes (access and registration certificate profiles) |
| 32026R1731 | CIR (EU) 2026/1731 of 15 July 2026 amending CIRs (EU) 2024/2977, 2024/2979, 2024/2980 and 2024/2982 as regards applicable standards and specifications (OJ 22.7.2026; in force 11.8.2026; some points apply from 11.8.2028) | **Yes: replaces the 2977 PID Annex and adds the wallet unit attestation / key attestation annex (2979 Annex Ib) and the issuance protocol annex (2982 Annex I)** |
| 32026R1735 | CIR (EU) 2026/1735 of 15 July 2026 amending CIR (EU) 2025/1569 as regards applicable standards and specifications (OJ 22.7.2026) | **Yes (QEAA / PuB-EAA: ETSI TS 119 471)** |

Other acts found in the search (2025/1567, 1568, 1570, 1571, 1572, 1929, 1942–1946, 2162, 2527, 2531, 2532; 2026/248) cover QSCDs, peer review, supervisory reports, the procedure for starting a qualified trust service, timestamps, validation, preservation, CAB accreditation, website certificates, ledgers, archiving and AdES formats. None of them adds an issuer-software duty, apart from **2025/1572**, which is the notification procedure a QEAA provider follows when it starts a service (organisational). Not tabulated.

**Expected acts, confirmed:** 2024/2977, 2024/2979, 2024/2980, 2024/2982 and 2025/848 all exist with the expected titles. The brief left the 2025 EAA / trusted-list / certification acts open. They are **2025/1569** (+ 2026/1735) for QEAA and PuB-EAA, **2025/1566** for QEAA identity verification, **2025/2160** for non-qualified TSPs, **2025/2530** for QTSPs, Decision **2025/2164** for trusted lists, and **2024/2981** for wallet certification (not an issuer act).

**Standards named in the brief:**

| Spec | Referenced by an act? | Where |
|---|---|---|
| OpenID4VCI 1.0 | Yes, directly | 2979 Annex Ib (inserted by 2026/1731 Annex III): Appendices D, E, F.3; §12.2.2 and §12.2.4 |
| HAIP 1.0 ("OpenID4VC-HAIP") | Yes, **presentation only** | 2982 Annex II (2026/1731 Annex XII) via ETSI TS 119 472-2. For **issuance** it applies only as far as ETSI TS 119 472-3 profiles it; the acts do not name HAIP for issuance. |
| ISO/IEC 18013-5 | Yes | 2982 Annex II; the PID mdoc encoding in the 2977 Annex §4.1 (mdoc format via ETSI TS 119 472-1 cl. 6) |
| ISO/IEC 18013-7:2025 Annex C | Yes | 2982 Annex II |
| SD-JWT VC | Yes | 2977 Annex §4.2; ETSI TS 119 472-1 cl. 5 |
| IETF Token Status List (draft-ietf-oauth-status-list-20) | Yes | 2979 Annex II (2026/1731 Annex IV), ref [25]; Annex Ib R_GEN-1 |
| ETSI TS 119 472-1 V1.2.1 | Yes | 2979 Annex II (the EAA/PID formats and revocation profile) |
| ETSI TS 119 472-2 V1.2.1 | Yes | 2982 Annex II (presentation) |
| ETSI TS 119 472-3 V1.1.1 | Yes | 2982 Annex I (**issuance**); 2979 Annex III (embedded disclosure, cl. 4.2.5) |
| ETSI TS 119 471 V1.1.1 | Yes | 2025/1569 Annex I as replaced by 2026/1735 (QEAA / PuB-EAA providers) |
| ETSI TS 119 475 V1.2.1 | Yes | 2025/848 Annex V (registration certificates, via 2026/1730); 2982 Annex II RO-23 (RP access certificate) |
| ETSI TS 119 602 | **Not found** in any of the acts listed above | n/a |
| Also mandated | | ETSI TS 119 412-6 (PID/EAA provider certificate profile) and EN 319 412-1/-2/-3/-5; ETSI TS 119 411-8 (access certificate policy); ETSI EN 319 401; ETSI TS 119 461 (identity proofing); ETSI TS 119 478 (authentic-source interface); ETSI TS 119 612 (trusted lists); ENISA "Agreed Cryptographic Mechanisms"; RFC 7515/7519/7800/9360/8610/8943/8949/3339 |

## 2. Obligations table

Key: **Testable?** `yes` = can be a deterministic check in issuer code or CI. `partly` = code supports it, but evidence or policy is also needed. `organisational` = process, policy or legal duty. **PID** = PID provider; **QEAA** = qualified EAA provider (QTSP); **PuB** = public-sector-body EAA provider (Art. 45f); **nqEAA** = non-qualified EAA provider; **EAA** = all attestation providers; **WP** = wallet provider; **MS** = Member State.

### 2.1 Regulation (EU) No 910/2014 as amended by 2024/1183

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check / duty |
|---|---|---|---|---|---|---|
| 1 | 910/2014 Art. 5a(16)(a) (2024/1183 Art. 1(5)) | "not allow providers of electronic attestations of attributes or any other party, after the issuance ... to obtain data that allows transactions or user behaviour to be tracked" | Wallet framework (WP/MS); constrains EAA and PID design | partly | Token Status List (privacy) | `no_phone_home`: no callback, no per-holder status URL, no presentation telemetry |
| 2 | Art. 5a(16)(b) as corrected by 32024R1183R(02) | "enable privacy preserving techniques which ensure unlinkability, where the attestation of attributes does not require the identification of the user" | Wallet framework; mirrored for PID in 2977 Art. 5(8) | partly | SD-JWT VC / mdoc batch issuance | `batch_issuance_unlinkable` |
| 3 | Art. 5a(5)(b) | "not provide any information to trust service providers of electronic attestations of attributes about the use of those electronic attestations" | WP | no (wallet side) | n/a | Issuer must not *require* usage signals |
| 4 | Art. 5a(5)(a)(i) | "support common protocols and interfaces: (i) for issuance of person identification data, qualified and non-qualified electronic attestations of attributes ... to the European Digital Identity Wallet" | WP (counterpart for issuers) | yes (interop) | OpenID4VCI / ETSI TS 119 472-3 | `oid4vci_conformance` |
| 5 | Art. 5a(5)(f) | "ensure that the person identification data ... uniquely represents the natural person, legal person or the natural person representing ... and is associated with that ... Wallet" | Wallet / MS; executed by PID provider | partly | n/a | `pid_subject_uniqueness` + binding (see 2977 Art. 3(4)–(5)) |
| 6 | Art. 5a(11) | "European Digital Identity Wallets shall be provided under an electronic identification scheme with assurance level high." | MS / WP; PID issuance must meet LoA high | organisational | CIR 2015/1502 | LoA-high scheme evidence |
| 7 | Art. 5a(18)(c)–(d) | MS notify "the bodies responsible for ensuring that the person identification data is associated with the ... Wallet" and "the mechanism allowing for the validation of the person identification data" | MS | organisational | ETSI TS 119 412-6 certificates in the Commission list (2980) | Provide data for MS notification |
| 8 | Art. 5b(1) | "Where a relying party intends to rely upon European Digital Identity Wallets ... the relying party shall register in the Member State where it is established." | Issuers acting as wallet-relying parties (see 2025/848 Annex I pt 12) | organisational | n/a | Register with the PID_Provider / QEAA_Provider / etc. entitlement |
| 9 | Art. 19a(1)(a) | nqTSP "shall ... have appropriate policies and take corresponding measures to manage legal, business, operational and other direct or indirect risks" | nqEAA | organisational | ETSI EN 319 401 (via 2025/2160) | Risk register |
| 10 | Art. 19a(1)(b) | notify breaches "without undue delay and in any case no later than 24 hours of having become aware of any security breaches or disruptions" | nqEAA | partly | n/a | Incident runbook; alerting SLO of 24 h or less |
| 11 | Art. 24(1) | "When issuing ... a qualified electronic attestation of attributes, a qualified trust service provider shall verify the identity and, if applicable, any specific attributes" | QEAA | partly | ETSI TS 119 461 (via 2025/1566) | `subject_identity_verified` gate before issuance |
| 12 | Art. 24(1a)(a) | Identity verification "by means of the European Digital Identity Wallet or a notified electronic identification means which meets ... assurance level high" (one of four methods) | QEAA | yes | OpenID4VP + HAIP (PID presentation to the issuer) | `pid_presentation_for_issuance` |
| 13 | Art. 24(2)(fb) | Notify supervisory body and affected individuals of significant breaches "without undue delay and in any event within 24 hours of the incident" | QEAA | organisational | n/a | IR runbook |
| 14 | Art. 24(2)(g) | "take appropriate measures against forgery, theft or misappropriation of data or, without right, deleting, altering or rendering data inaccessible" | QEAA | partly | ETSI EN 319 401 / TS 119 471 | HSM/QSCD keys; tamper-evident logs |
| 15 | Art. 24(2)(h) | "record and keep accessible ... all relevant information concerning data issued and received by the qualified trust service provider, for the purpose of providing evidence in legal proceedings" | QEAA | partly | ETSI EN 319 401 cl. 7.10 | `issuance_audit_log` (append-only, retention policy) |
| 16 | Art. 24(2)(i) | "have an up-to-date termination plan to ensure the continuity of service" | QEAA | organisational | 2025/2530 Art. 3 | Termination plan |
| 17 | Art. 24(4a) + 910/2014 Art. 24(3) | Art. 24(3) applies to QEAA: "register such revocation ... and publish the revocation status ... in any event within 24 hours after the receipt of the request" | QEAA | **yes** | Token Status List | `revocation_publish_latency <= 24h` |
| 18 | Art. 24(4a) + 910/2014 Art. 24(3) | "The revocation shall become effective immediately upon its publication." | QEAA | yes | Token Status List | Status list published atomically |
| 19 | Art. 24(4a) + 910/2014 Art. 24(4) | Status info "available at least on a per certificate basis at any time and beyond the validity period ... in an automated manner that is reliable, free of charge and efficient" | QEAA | yes | Token Status List (`exp`/`ttl`) | `status_list_retained_beyond_validity`; status endpoint needs no authentication |
| 20 | Art. 45d(1) | "Qualified electronic attestation of attributes shall meet the requirements laid down in Annex V." | QEAA | yes | SD-JWT VC / mdoc via ETSI TS 119 472-1 | See rows 31–39 |
| 21 | Art. 45d(3) | QEAA "shall not be subject to any mandatory requirement in addition to the requirements laid down in Annex V" | QEAA (and MS) | n/a | n/a | Do not hard-fail on non-Annex-V fields |
| 22 | Art. 45d(4) | Revoked QEAA "shall lose its validity from the moment of its revocation and its status shall not in any circumstances be reverted" | QEAA | **yes** | Token Status List (no suspension) | `status_monotonic` (no 1 to 0 transition) |
| 23 | Art. 45f(1)(b) | PuB-EAA signing qualified certificate must contain certified attributes "indicating that the issuing body is established in accordance with Union or national law as the responsible for the authentic source" | PuB | yes | ETSI TS 119 412-6 cl. 8; EN 319 412-5 QcType `id-etsi-qct-eidaspsbeaa` | `pub_eaa_cert_profile` |
| 24 | Art. 45f(4) | Revoked PuB-EAA "shall lose its validity from the moment of its revocation and its status shall not be reverted" | PuB | yes | Token Status List | `status_monotonic` |
| 25 | Art. 45f(8) | PuB bodies "shall provide an interface with European Digital Identity Wallets" | PuB | yes | OpenID4VCI / ETSI TS 119 472-3 | `oid4vci_endpoint_available` |
| 26 | Art. 45g(1) | Users can "request, obtain, store and manage the electronic attestation of attributes irrespective of the Member State where the ... Wallet is provided" | All EAA | yes | OpenID4VCI | `wallet_trust_list_cross_border` (accept any listed wallet provider) |
| 27 | Art. 45g(2) | "Providers of qualified electronic attestations of attributes shall provide an interface with European Digital Identity Wallets" | QEAA | yes | OpenID4VCI / ETSI TS 119 472-3 | `oid4vci_endpoint_available` |
| 28 | Art. 45h(1) | EAA providers "shall not combine personal data relating to the provision of those services with personal data from any other services offered by them or their commercial partners" | QEAA, nqEAA | partly | n/a | Separate DB/schema; no shared user IDs |
| 29 | Art. 45h(2) | "Personal data relating to the provision of electronic attestation of attributes services shall be kept logically separate from other data" | QEAA, nqEAA | partly | n/a | `data_store_isolation` |
| 30 | Art. 45h(3) | QEAA "in a manner that is functionally separate from other services provided by them" | QEAA | organisational | ETSI TS 119 471 | Deployment/role separation |

### 2.2 Annex V (QEAA content) and Annex VII (PuB-EAA content) of 910/2014

Annex VII points (a)–(i) mirror Annex V for PuB-EAA, with "public body" in place of QTSP. Both bind the issued artefact, so all rows are `yes`.

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 31 | Annex V(a) / VII(a) | "an indication, at least in a form suitable for automated processing, that the attestation has been issued as a qualified electronic attestation of attributes" | QEAA / PuB | yes | ETSI TS 119 472-1 (QEAA/PuB-EAA type indicators) | `qualified_indicator_present` |
| 32 | Annex V(b) / VII(b) | Issuer data "including at least, the Member State in which that provider is established" and name, "where applicable, registration number as stated in the official records" | QEAA / PuB | yes | ETSI TS 119 472-1; TS 119 412-6 | `issuer_identity_fields` |
| 33 | Annex V(c) / VII(c) | "a set of data unambiguously representing the entity to which the attested attributes refer; if a pseudonym is used, it shall be clearly indicated" | QEAA / PuB | yes | SD-JWT VC / mdoc | `subject_or_pseudonym_flag` |
| 34 | Annex V(d) / VII(d) | "the attested attribute or attributes, including, where applicable, the information necessary to identify the scope of those attributes" | QEAA / PuB | yes | Scheme in the 2025/1569 catalogue | `scheme_conformant_claims` |
| 35 | Annex V(e) / VII(e) | "details of the beginning and end of the attestation's period of validity" | QEAA / PuB | yes | SD-JWT VC `nbf`/`exp`; mdoc `validityInfo` | `validity_period_present` |
| 36 | Annex V(f) / VII(f) | "the attestation identity code, which must be unique for the qualified trust service provider and ... the indication of the scheme" | QEAA / PuB | yes | ETSI TS 119 472-1 | `attestation_id_unique` (uniqueness DB constraint) |
| 37 | Annex V(g) / VII(g) | "the qualified electronic signature or qualified electronic seal of the issuing qualified trust service provider" | QEAA / PuB | yes | JAdES/COSE; QSCD | `signed_with_qualified_seal` (certificate QC statements) |
| 38 | Annex V(h) / VII(h) | "the location where the certificate supporting the qualified electronic signature or qualified electronic seal ... is available free of charge" | QEAA / PuB | yes | `x5u` / `x5chain` | `cert_location_resolvable` |
| 39 | Annex V(i) / VII(i) | "the information or location of the services that can be used to enquire about the validity status of the qualified attestation" | QEAA / PuB | yes | Token Status List `status.status_list.uri` | `status_reference_present` (unless short-lived, see row 101) |

### 2.3 CIR (EU) 2024/2977 (PID and EAA to wallets) as amended by 2026/1731

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 40 | 2977 Art. 3(1) | "Providers of person identification data shall issue person identification data to wallet units in accordance with the electronic identification schemes under which wallet solutions are provided." | PID | organisational | n/a | Scheme config |
| 41 | 2977 Art. 3(2) | PID must contain "the information necessary for authentication and validation of the person identification data" | PID | yes | `x5u`/`x5t`; trusted list (2980) | `pid_validatable_offline` |
| 42 | 2977 Art. 3(3) | PID must "comply with the technical specifications set out in the Annex" | PID | yes | Annex (rows 60–79) | `pid_annex_conformance` |
| 43 | 2977 Art. 3(4) | "Member States shall ensure that the person identification data issued to a given wallet user is unique for the Member State." | MS (PID provider implements) | partly | n/a | `subject_dedup` |
| 44 | 2977 Art. 3(5) | PID must be "cryptographically bound to the wallet unit to which it is issued" | PID | **yes** | SD-JWT VC `cnf` (RFC 7800); mdoc `deviceKeyInfo` | `holder_binding_required` |
| 45 | 2977 Art. 3(7) | PID providers "shall perform identity verification of the wallet user ... before issuing the person identification data" | PID (MS enrol at LoA high) | partly | ETSI TS 119 461 (via 2026/798) | `identity_proofing_gate` |
| 46 | 2977 Art. 3(8) | PID providers "shall identify themselves to wallet units using their wallet-relying party access certificate" (or another LoA-high mechanism) | PID | **yes** | ETSI TS 119 411-8 / 119 475 access cert; OpenID4VCI signed metadata | `issuer_access_cert_configured` |
| 47 | 2977 Art. 3(9) | "Before issuing ... shall authenticate and validate the wallet unit attestation ... and verify that the wallet unit belongs to a wallet solution the provider ... accepts" | PID | **yes** | OpenID4VCI App. E (WIA), App. D (KA) | `wua_required`, `wallet_solution_allowlist` |
| 48 | 2977 Art. 4(1) as replaced by 2026/1731 Art. 1(2) | "Electronic attestations of attributes issued to wallet units shall comply with at least one of the standards set out in Annex II of Implementing Regulation (EU) 2024/2979." | EAA (all) | yes | ETSI TS 119 472-1 (SD-JWT VC, mdoc) | `eaa_format_conformance` |
| 49 | 2977 Art. 4(2) | "Providers of electronic attestations of attributes shall identify themselves to wallet units using their wallet-relying party access certificate." | EAA (all) | yes | Access cert (TS 119 411-8) | `issuer_access_cert_configured` |
| 50 | 2977 Art. 4(3) | EAA must "contain the information necessary for authentication and validation of those electronic attestations of attributes" | EAA (all) | yes | `x5c`/`x5chain` | `eaa_validatable` |
| 51 | 2977 Art. 5(1) | "written and publicly accessible policies relating to validity status management, including ... conditions under which such person identification data can be revoked without delay" | PID | organisational | n/a | Published revocation policy URL |
| 52 | 2977 Art. 5(2) | "Only providers of person identification data or electronic attestation of attributes can revoke the person identification data or electronic attestations of attributes issued by them." | PID, EAA | yes | Token Status List signing key | `status_list_write_authz` |
| 53 | 2977 Art. 5(3) | Inform users of revocation "through dedicated and secure channels ... within 24 hours of the revocation and of the reasons for the revocation" | PID | partly | n/a | `revocation_user_notice <= 24h` |
| 54 | 2977 Art. 5(4)(a) | Revoke "upon the explicit request of the wallet user" | PID | yes | n/a | `user_revocation_endpoint` |
| 55 | 2977 Art. 5(4)(b) as replaced by 2026/1731 Art. 1(3) | Revoke "where the wallet unit attestation of the wallet unit to which the person identification data was issued to has been revoked" | PID | **yes** | Token Status List (WIA `client_status`, KA `key_storage_status`) | `revocation_chaining` job (see row 95) |
| 56 | 2977 Art. 5(5) | "shall ensure that revocations cannot be reverted" | PID | **yes** | Token Status List | `status_monotonic` |
| 57 | 2977 Art. 5(6) | "The revoked person identification data shall remain accessible for as long as required by Union law or national law." | PID | partly | n/a | Retention config |
| 58 | 2977 Art. 5(7) | Make "publicly available the validity status ... in a privacy preserving manner, and indicate the location of that information in the person identification data" | PID | **yes** | Token Status List; mdoc `status` | `status_reference_present`, `status_list_public` |
| 59 | 2977 Art. 5(8) | "enable privacy preserving techniques which ensure unlinkability where the electronic attestations of attributes do not require the identification of the user" | PID | partly | Batch issuance; unique status index per credential | `batch_issuance_unlinkable` |

**2977 Annex (PID technical specifications), as replaced by 2026/1731 Annex I**

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 60 | Annex §1 Table 1 | Mandatory natural-person PID: `family_name`, `given_name`, `birth_date`, `birth_place`, `nationality`, plus `portrait` (portrait requirement "shall apply from 11 August 2028") | PID | **yes** | SD-JWT VC / mdoc | `pid_mandatory_attrs` (portrait conditional on date) |
| 61 | Annex §1 notes | "Where the nationality of the natural person is unknown, Member States shall use the value 'QU'." / stateless: "'QS'" / portrait opt-out: "set the value empty" | MS / PID | yes | ISO 3166-1 | `nationality_sentinels` |
| 62 | Annex §1 notes | "Member States shall ensure that the selective disclosure applies to each data identifier, including the portrait." | MS / PID | **yes** | SD-JWT `_sd`; mdoc per-element digests | `per_claim_selective_disclosure` |
| 63 | Annex §1 Table 2 | Optional natural-person PID: `resident_*`, `personal_administrative_number`, `family_name_birth`, `given_name_birth`, `sex`, `email_address`, `mobile_phone_number` | PID | yes | n/a | `pid_optional_attrs_schema` |
| 64 | Annex §2 Tables 3–4 | Legal-person PID mandatory: "current legal name" and "a unique identifier constructed by the sending Member State ... as persistent as possible in time" | PID (legal-person) | yes | n/a | `lpid_mandatory_attrs` |
| 65 | Annex §3 Table 5 | Metadata **mandatory**: `issuing_authority`, `issuing_country`. **Optional**: `expiry_date`, `document_number`, `issuing_jurisdiction`, `issuance_date`. (`location_status` from the 2024 Annex is **not** in the replaced Annex.) | PID | **yes** | n/a | `pid_metadata` |
| 66 | Annex §3 Table 5 | `issuing_country`: "Alpha-2 country code, as specified in ISO 3166-1, of the country or territory of the provider" | PID | yes | ISO 3166-1 | `iso3166_alpha2` |
| 67 | Annex §4 | PID "issued in accordance with ... Annex II to Implementing Regulation (EU) 2024/2979, clauses 5 (SD-JWT VC format) and 6 (ISO/IEC-mdoc format)". The 2024 text said "issued in two formats". The 2026 wording does not say "both" explicitly; read it as both formats being expected, and check national guidance. | PID | yes | ETSI TS 119 472-1 cl. 5/6 | `pid_formats_offered` |
| 68 | Annex §4.1 | mdoc: "The attestation type ... shall be 'eu.europa.ec.eudi.pid.1'" and the namespace is the same | PID | yes | ISO/IEC 18013-5 | `mdoc_doctype` |
| 69 | Annex §4.1 | mdoc device key: "That public key shall correspond to a private key that is stored in the wallet secure cryptographic device ('WSCD')" | PID | yes (via the key attestation) | ISO/IEC 18013-5 MSO | `device_key_from_wscd_ka` |
| 70 | Annex §4.1 | mdoc protected header "shall contain the x5u and the x5t header parameters, both specified in RFC 9360"; "digest algorithm ... x5t ... shall be SHA-256" | PID | **yes** | COSE RFC 9360 | `mdoc_cose_x5u_x5t` |
| 71 | Annex §4.1(c),(h) | "a tstr shall have a maximum length of 150 characters"; dates "not use fractions of seconds" and offset "set to 'Z'" | PID | yes | CBOR (RFC 8949/8943/3339) | `mdoc_encoding_rules` (Table 6, items (a)–(l)) |
| 72 | Annex §4.2 | SD-JWT VC: "All claims ... shall be selectively disclosable individually, except those claims defined as non-selectively disclosable in SD-JWT VC format." | PID | **yes** | SD-JWT VC | `sdjwt_all_claims_sd` |
| 73 | Annex §4.2 | "The JWT claims nbf and exp as defined in RFC 7519 shall be used to express the technical validity period" | PID | yes | RFC 7519 | `sdjwt_nbf_exp` |
| 74 | Annex §4.2 | PID "shall incorporate the cnf claim ... which shall be a public key generated from a private key stored in the WSCD" | PID | yes | RFC 7800 | `sdjwt_cnf_from_wscd` |
| 75 | Annex §4.2 | SD-JWT VC protected header "shall contain the x5u and the x5t#S256 header parameters" | PID | **yes** | RFC 7515 | `sdjwt_header_x5u_x5tS256` |
| 76 | Annex §4.2 Tables 7–8 | Claim-name mapping (e.g. `birth_date` to `birthdate`; `expiry_date` to `date_of_expiry`; `portrait` to `picture` as a JPEG data URL) | PID | yes | SD-JWT VC | `sdjwt_claim_mapping` |
| 77 | Annex §4.2 | "The base type of person identification data shall be 'urn:eudi:pid:1', included in the vct claim." | PID | yes | SD-JWT VC `vct` | `sdjwt_vct` |
| 78 | Annex §4.1 / §4.2 | Domestic extensions: the scheme must be "published in accordance with Article 8 of Commission Implementing Regulation (EU) 2025/1569" | PID / MS | partly | 2025/1569 catalogue | `domestic_ns_registered` |
| 79 | Annex §5 | "The list of providers of person identification data made available by the Commission in accordance with Implementing Regulation (EU) 2024/2980 shall enable the authentication of person identification data." | Commission / PID | yes | 2980 list (TS 119 412-6 certs) | `signing_cert_in_commission_list` |

### 2.4 CIR 2024/2979 Annex Ib: wallet unit attestation / key attestation (inserted by 2026/1731 Annex III)

These are the clauses where the *issuer's authorisation server or credential issuer* is the subject.

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 80 | 2979 Annex Ib TR-WIA-3 | Wallet sends the WIA "to the authorisation server in the pushed authorisation request and the token request, as specified in OID4VCI" | WP (issuer AS must accept it) | yes | OpenID4VCI App. E; PAR | `wia_on_par_and_token` |
| 81 | TR-WIA-4 | AS "shall verify the signature of the wallet instance attestation using the public key in the signing certificate included in the 'x5c' parameter" | Issuer AS (PID/EAA) | **yes** | OpenID4VCI App. E | `wia_sig_verify` |
| 82 | TR-WIA-4.1 | AS "shall also verify that this signing certificate can be verified with a trust anchor on the list of wallet providers referred to in Article 5 of ... 2024/2980" | Issuer AS | **yes** | 2980 list | `wia_chain_to_wp_list` |
| 83 | TR-WIA-4.2 / 4.3 | AS "shall verify that the wallet instance attestation has not expired" and "verify the signature of the PoP under the public key present in the 'cnf' claim" | Issuer AS | **yes** | OpenID4VCI App. E | `wia_exp`, `wia_pop` |
| 84 | C_WIA-3 / LC_WIA_2 | AS "shall not interpret the 'exp' parameter in the top level of a wallet instance attestation as the end of the revocation maintenance period" | Issuer AS | yes | n/a | Use `client_status.exp` |
| 85 | TR_KA-4 | For device-bound credentials the issuer "shall indicate in the 'proof_types_supported' ... that it supports both the 'jwt' and the 'attestation' proof type ... 'key_attestations_required'" | Credential issuer | **yes** | OpenID4VCI §12.2.4 | `metadata_proof_types` |
| 86 | TR_KA-4.1 | Non-device-bound: "shall omit the 'proof_types_supported' and the 'cryptographic_binding_methods_supported' parameters" | Credential issuer | yes | OpenID4VCI §12.2.4 | `metadata_unbound_omits` |
| 87 | TR_KA-5 | Verify key-attestation signature from `x5c` and its chain "with a trust anchor on the list for wallet providers referred to in Article 5 of ... 2024/2980" | Credential issuer | **yes** | OpenID4VCI App. D | `ka_chain_to_wp_list` |
| 88 | TR_KA-6 / 6.1 | Verify the `jwt` proof "under the key at index 0 of the 'attested_keys' array" and that "'nonce' ... includes a valid c_nonce from their nonce_endpoint" | Credential issuer | **yes** | OpenID4VCI §7, App. D, F | `jwt_proof_attested_key0`, `c_nonce_valid` |
| 89 | TR_KA-7 | For the `attestation` proof type, verify "that the 'key_attestation' object includes a valid c_nonce from their nonce_endpoint" | Credential issuer | yes | OpenID4VCI App. F.3 | `attestation_proof_nonce` |
| 90 | TR_KA-8 | "A provider of person identification data shall ensure that person identification data is bound to a public key that originates from a key attestation mentioning a WSCD." | PID | **yes** | OpenID4VCI App. D (`key_storage` = `iso_18045_high`) | `pid_key_from_wscd` |
| 91 | C_KA-1 note | Credential issuer "shall not use the 'idx' value in a key attestation as a wallet unit identifier, but shall instead use the 'idx' value in a wallet instance attestation" | Credential issuer | yes | Token Status List | `no_ka_idx_as_id` |
| 92 | C_KA-3 | Credential issuer "shall not interpret the 'exp' parameter in the top level of a key attestation as the end of the revocation maintenance period" | Credential issuer | yes | n/a | Use `key_storage_status.exp` |
| 93 | LC_WIA-1/1.1; LC_KA-1/1.1 | Optional metadata `preferred_client_status_period` ("placed at the top level") and `preferred_key_storage_status_period` (inside `key_attestations_required`) | Issuer (optional) | yes | OpenID4VCI §12.2.2/12.2.4 | `metadata_status_period_placement` |
| 94 | LC_GEN-3 | "The technical validity period of person identification data shall end before both the 'client_status.exp' ... and the 'key_storage_status.exp'" | PID | **yes** | n/a | `pid_exp_lt_wia_ka_status_exp` |
| 95 | LC_GEN-4 | A PID with validity over 24 h "shall check the revocation status of both the wallet instance attestation and the key attestation ... at least once every 24 hours"; if revoked, revoke the PID | PID | **yes** | Token Status List | `revocation_chaining` cron (24 h or less) |
| 96 | SA-3 | "An authorization server or a credential issuer ... shall support all of the algorithms mentioned in SA-1" (ES256, ES384, ES512) | Issuer AS / CI | **yes** | JOSE | `alg_support_es256_384_512` |
| 97 | 2979 Annex II EAA-6.2.10.1-16 (2026/1731 Annex IV) | PID and EAA providers "shall support both the attestation status list mechanism and the attestation revocation list mechanism ... for verifying the revocation status of a wallet instance attestation (WIA)" and of a KA | PID, EAA | **yes** | Token Status List + identifier list (CWT) | `wia_ka_status_both_mechanisms` |

### 2.5 CIR 2024/2979 Annex II: formats and revocation (= ETSI TS 119 472-1 V1.2.1 with adaptations; 2026/1731 Annex IV)

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 98 | 2979 Annex II (intro) | "The technical specifications set out in clauses 2 to 6 of ETSI TS 119 472-1 V1.2.1 (2026-02) apply." | PID (via 2977 Annex §4), all EAA (via 2977 Art. 4(1)), QEAA/PuB (via 2025/1569) | yes | ETSI TS 119 472-1 | `etsi_119472_1_profile` |
| 99 | Adaptation 4.2.11.1, EAA-4.2.11.1-06 | For PID, QEAA, PuB-EAA the status "shall only indicate whether the attestation is revoked or not revoked and shall not support any other status values, such as suspension" | PID, QEAA, PuB | **yes** | Token Status List (`bits` = 1) | `no_suspension_status` |
| 100 | EAA-4.2.11.1-06.1 | "Where an attestation is revoked, it shall be permanently revoked." | PID, QEAA, PuB | yes | n/a | `status_monotonic` |
| 101 | 4.2.13, EAA-4.2.13-03; EAA-6.2.10.1-02.1 | "Where short-lived electronic attestations of attributes with a validity period of 24 hours or less are issued, revocation shall not be required." | EAA, PID | yes | n/a | `short_lived_no_status_ok` (24 h or less) |
| 102 | 4.6.3, PuB-EAA-4.6.3-04 | PuB-EAA qualified certificate "shall meet the requirements of clause 8 of ETSI TS 119 412-6 ... and shall contain the QcType ... id-etsi-qct-eidaspsbeaa" | PuB | yes | ETSI TS 119 412-6; EN 319 412-5 | `pub_eaa_qctype` |
| 103 | 5.2.10.1, EAA-5.2.10.1-06 | SD-JWT VC: "The status member may contain the status_list member as specified in clause 6.2 of ... draft-ietf-oauth-status-list-20" | EAA, PID (SD-JWT VC) | yes | Token Status List | `sdjwt_status_list_ref` |
| 104 | EAA-6.2.10.1-02 | mdoc revocation: use a status list "or" an identifier list (unless short-lived) | PID, QEAA, PuB | yes | Token Status List; identifier list | `mdoc_revocation_mechanism` |
| 105 | EAA-6.2.10.1-03.1 | "only values 'valid' and 'invalid' ... shall be used" | PID, QEAA, PuB | yes | Token Status List | `status_values_valid_invalid_only` |
| 106 | EAA-6.2.10.1-07 / -08 | "An MSO revocation list shall be implemented ... as a status list token in CWT format"; "the exp claim shall be present"; algorithms ES256/384/512 or ESB256/384/512; "x5chain in the protected header" | PID, QEAA, PuB (mdoc) | **yes** | Token Status List (CWT), COSE | `mdoc_status_cwt_profile` |
| 107 | EAA-6.2.10.1-11.2 | Identifier list: "To prevent the identifier from being used as a correlation across presentations, it shall be unique per MSO." | Issuer (mdoc) | yes | n/a | `revocation_id_unique_per_mso` |
| 108 | EAA-6.2.10.1-12.1 / 13.2 | Status list: "The bits element ... shall be set to 1"; "the combination of status index and URI shall be unique per MSO" | Issuer (mdoc) | **yes** | Token Status List | `status_bits_1`, `status_idx_unique_per_mso` |

### 2.6 CIR 2024/2982 Annexes I and II (protocols; inserted by 2026/1731 Annexes XI–XII)

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 109 | 2982 Art. 4(2) | Wallets "request issuance ... only from parties having an authentic and valid wallet-relying party access certificate attesting them as" a PID / QEAA / PuB-EAA / nqEAA provider | WP (issuer precondition) | yes | Access cert (TS 119 411-8), 848 Annex I pt 12 | `access_cert_entitlement_matches_role` |
| 110 | 2982 Art. 4(3)(c) | Wallets support "mechanisms that enable providers of person identification data to verify issuance, delivery and activation in compliance with assurance level high" | WP / PID | partly | CIR 2015/1502 | `pid_activation_check` |
| 111 | 2982 Annex I (intro) | "The technical specification ETSI TS 119 472-3 V1.1.1 (2026-03) shall apply with the following adaptations" (Annex A of the TS excluded) | PID, EAA (issuance interface) | **yes** | ETSI TS 119 472-3 (OpenID4VCI profile) | `etsi_119472_3_conformance` |
| 112 | Annex I, ISS-MDATA-REG_CERT-4.2.3-04 | "One of the elements in the issuer_info array parameter shall contain the PID/EAA Provider's registration certificate." | PID, EAA | **yes** | ETSI TS 119 472-3; TS 119 475 | `metadata_issuer_info_reg_cert` |
| 113 | Annex I, ISS-MDATA-EAA-REUSE-POL-4.2.4.2-09 | If the reuse policy is `arf_annex_ii` with "'once_only' or ... 'per-relying-party'", the object "shall also contain a JSON number mapped to the label 'reissue_trigger_unused'" | PID, EAA | yes | ETSI TS 119 472-3 | `metadata_reuse_policy` |
| 114 | 2982 Annex II, ISO/IEC 18013-SUPPORT-01 | "Wallet Units, PID Providers, Attestation Providers ... shall not support server retrieval as specified in ISO/IEC 18013-5" | PID, EAA | **yes** | ISO/IEC 18013-5 | `no_mdoc_server_retrieval` |
| 115 | 2982 Annex II (intro) | Presentation: "Annex C to ISO/IEC 18013-7:2025" and ETSI TS 119 472-2 (HAIP-based). Applies to wallets and RPs. It affects issuers only through the `vct`/doctype and SD design. | WP, RP | no (issuer) | HAIP 1.0, ISO/IEC 18013-5/-7 | n/a (interop test only) |

### 2.7 CIR 2024/2980 (notifications) as amended by 2026/1731 Annex X

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 116 | 2980 Annex II §3(1)(h) as replaced | MS notify PID-provider certificates "compliant with standard ETSI EN 319 412-2 V2.4.1 (2025-06) or ... EN 319 412-3 V1.3.1 (2023-09)" that verify the PID signature | MS (PID provides certs) | yes | EN 319 412-2/-3; TS 119 412-6 | `pid_signer_cert_profile` |
| 117 | 2980 Annex II §3(1)(g) | Notify "the URL of the webpage that contains the policies, terms and conditions of the provider of person identification data" | MS / PID | organisational | n/a | Publish T&Cs URL |
| 118 | 2980 Annex II §2(1)(h) as replaced | Wallet-provider certificates (EN 319 412-2/-3) "can be used to authenticate and validate wallet unit attestations" | MS / WP. The issuer consumes these as the WIA/KA trust anchors. | yes | Commission list | `wp_trust_list_loader` (signed list, pinned certificates per 2980 Art. 5(4)) |

### 2.8 CIR 2025/848 (RP registration) as amended by 2026/1730

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 119 | 848 Annex I pt 12(b)–(e) | Entitlements "'QEAA_Provider'", "'Non_Q_EAA_Provider'", "'PUB_EAA_Provider'", "'PID_Provider'" | Issuer as wallet-relying party | partly | Access cert / registration cert | `entitlement_in_certs` |
| 120 | 848 Art. 5(2)–(3) | Wallet-relying parties "shall ensure that the information provided is accurate" and "update any information previously registered ... without undue delay" | Issuer as wallet-relying party | organisational | n/a | Registration ops |
| 121 | 848 Annex III pt 3 | PID entitlement verified against "the list of providers of person identification data published by the Commission in accordance with Article 5a(18)" | Registrar (issuer precondition) | organisational | n/a | n/a |
| 122 | 848 Annex IV pt 3 as amended by 2026/1730 | Access-certificate policy "shall, as applicable, comply with standard ETSI TS 119 411-8 V1.1.1 (2025-10)" | Access-cert CA (issuer holds the cert) | yes | ETSI TS 119 411-8 | `access_cert_profile_119411_8` |
| 123 | 848 Annex V pt 3 as amended by 2026/1730 | Registration-certificate policy "shall comply with ETSI TS 119 475 V1.2.1 (2026-03)" | Registration-cert CA | yes | ETSI TS 119 475 | `reg_cert_profile_119475` |
| 124 | 848 Art. 6(7) | When it no longer relies on wallets, the wallet-relying party "shall notify the relevant registrar without undue delay and request the cancellation" | Issuer as wallet-relying party | organisational | n/a | Decommission runbook |

### 2.9 CIR 2025/1569 (QEAA / PuB-EAA) as amended by 2026/1735

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 125 | 1569 Art. 3(1) | Providers "shall comply with the list of reference standards and specifications set out in Annex I and shall ensure that the electronic attestations ... comply with ... Annex II" | QEAA, PuB | partly | ETSI TS 119 471; TS 119 472-1 | `etsi_119471_controls` |
| 126 | 1569 Art. 3(2) (2026/1735 text) | Where the EAA belongs to a catalogued scheme, providers "shall comply with the requirements of the corresponding scheme for the attestation of attributes" | QEAA, PuB | yes | Catalogue of schemes (Art. 8) | `scheme_schema_validation` |
| 127 | 1569 Art. 4(2) | Providers "shall be the only entities able to revoke the electronic attestations of attributes they issue" | QEAA, PuB | yes | Token Status List | `status_list_write_authz` |
| 128 | 1569 Art. 4(3) (2026/1735) | For validity over 24 h, revoke "(a) upon the request of the person to whom the electronic attestation of attributes was issued", or (b) on known compromise, or (c) as law requires | QEAA, PuB | yes | n/a | `revocation_triggers` |
| 129 | 1569 Art. 4(4) (2026/1735) | Revocation "privacy preserving and hindering linkability or traceability. The revocation techniques shall comply with the requirements set out in Annex II" | QEAA, PuB | **yes** | Token Status List (via 2979 Annex II) | `status_privacy` (unique index per credential, large lists) |
| 130 | 1569 Art. 4(5) | Status information to relying parties "in a manner that ensures the integrity and authenticity of that information" | QEAA, PuB | **yes** | Signed status list token (JWT/CWT) | `status_list_signed` |
| 131 | 1569 Annex I pt (3), REQ-EAASP-4.2.2.3-02 (2026/1735) | "The EAASP shall authenticate to the EUDIW instance implementing mutual authentication mechanisms that use a valid access certificate." | QEAA, PuB | **yes** | Access cert; OpenID4VCI | `issuer_access_cert_configured` |
| 132 | REQ-EAASP-4.2.2.3-03 | "The EAASP shall validate the EUDIW unit, and whether the EUDIW instance is revoked." | QEAA, PuB | **yes** | OpenID4VCI App. E + status | `wia_status_check` |
| 133 | REQ-EAASP-6.1-02 | "EAASP shall document the revocation mechanism in the EAAS practice statement" | QEAA, PuB | organisational | ETSI TS 119 471 | Practice statement |
| 134 | REQ-EAASP-6.3-02 | Notify the supervisory body "one month before implementing any change" and "three months before the planned cessation" | QEAA, PuB | organisational | n/a | Change management |
| 135 | REQ-EAASP-7.5.3-01B | "select and use suitable cryptographic techniques compliant with the Agreed Cryptographic Mechanisms endorsed by the European Cybersecurity Certification Group and published by ENISA" | QEAA, PuB | **yes** | ENISA ACM | `crypto_policy_enisa_acm` (alg/curve allowlist) |
| 136 | REQ-EAASP-7.5.3-02 | The EAA signing device "is a qualified signature or seal creation device"; other signatures use CC EAL4+, EUCC EAL4+, or FIPS 140-3 L3 devices | QEAA, PuB | partly | QSCD; CC/EUCC/FIPS | `signer_backend_is_qscd` (configuration attestation) |
| 137 | REQ-EAASP-7.9-02 | "Monitoring activities shall take account of the sensitivity of any information collected or analysed." | QEAA, PuB | partly | n/a | Log redaction (no attribute values in logs) |
| 138 | 1569 Annex II (2026/1735) | Issue "in compliance with at least one of the standards set out in Annex II to ... 2024/2979 and apply the relevant revocation techniques" | QEAA, PuB | yes | ETSI TS 119 472-1 | `eaa_format_conformance` |

*Superseded (2025/1569 original Annex II, replaced by 2026/1735 on 11.8.2026):* "process only the minimum set of attributes necessary for the issuance and management of the attestation", "authenticate to the wallet unit", and "verify that the wallet unit is not revoked or suspended". The last two now sit in ETSI TS 119 471 (rows 131–132). Data minimisation now rests on GDPR, eIDAS Art. 45h and Art. 5a(16), and the per-claim selective disclosure in rows 62/72. **No specific minimisation clause aimed at issuers was found in the current implementing acts.**

### 2.10 Identity verification, risk and QTSP acts

| # | Source | Obligation (quote) | Binds | Testable? | Spec | Suggested check |
|---|---|---|---|---|---|---|
| 139 | 2025/1566 Annex (applies 19.8.2027) | "The standard ETSI TS 119 461 V2.1.1 (2025-02) for conformance with Annex C clause C.3 applies" to identity verification for QEAA | QEAA | partly | ETSI TS 119 461 | Identity-proofing provider evidence |
| 140 | 2026/798 Annex §1–2 | PID remote onboarding at substantial-plus: conformance with ETSI TS 119 461 cl. 5–9.5. Note: "the risk assessment of the provider of person identification data can cover the identity proofing" | PID (onboarding) | partly | ETSI TS 119 461; EN 319 401 | `onboarding_ipsp_conformance` |
| 141 | 2026/798, OVR-7.10-01 Note 1 | "Long-term requirements for retention of evidence can be fulfilled by the provider of person identification data requesting the identity proofing" | PID | partly | EN 319 401 cl. 7.10 | Evidence store with retention |
| 142 | 2025/2160 Art. 4(3)(b) | Record and retain "all relevant information collected in the process of registration and onboarding ...", "authentication data assigned", and "any change of the status of public key certificates or other cryptographic material" | nqEAA (QEAA via 2025/2530 Art. 2) | partly | EN 319 401 | `audit_log_onboarding_and_key_events` |
| 143 | 2025/2160 Art. 4(3)(a) | "verify, where applicable, the identity of the users ... and publish information on the identity verification methods used" | nqEAA | organisational | n/a | Published identity-verification method |
| 144 | 2025/2160 Art. 4(6) | Review the risk evaluation "at least annually" | nqEAA (QEAA via 2530) | organisational | EN 319 401 cl. 5 | Annual review |
| 145 | 2025/2530 Art. 1(1)(d) | Notify the supervisory body of significant changes to "the use of cryptographic techniques or cryptographic materials in the provision of the qualified trust services" | QEAA | organisational | n/a | Key-rotation change notice |
| 146 | 2025/2530 Art. 3(7)(d) | Termination: "no further qualified trust service output can be created or enabled through the use of the signature or seal creation data" | QEAA | partly | QSCD | Key destruction procedure |
| 147 | 2024/2977 and 2026/1731 (searched) | No PID-provider-specific **logging** clause found in 2977 or 2026/1731. Transaction logging (2979 Art. 9) binds **wallet instances**, not issuers. | n/a | n/a | n/a | **not found** for PID; use rows 15/142 |

## 3. Counts

- Rows: 147 (one is a "not found" marker).
- **Issuer-testable `yes`: 100.** Of these, 36 are marked **yes** in bold as high priority. Some rows describe the same check, e.g. `status_monotonic`; after de-duplication, 91 distinct check-name sets remain.
- `partly`: 25. `organisational`: 18. `no`: 2. `n/a`: 2.

## 4. Gaps and caveats

- **ETSI TS 119 602 is not referenced** by any act found. Trust lists for PID providers and wallet providers come from 2024/2980 (format left to the Commission's published specs, Art. 5(4)(a)); QTSP lists use ETSI TS 119 612 (Decision 2025/2164).
- **HAIP 1.0** is mandated only for **presentation** (2982 Annex II). Issuance is mandated through ETSI TS 119 472-3 and OpenID4VCI 1.0 (named directly in 2979 Annex Ib).
- **PID metadata changed in 2026:** `expiry_date` is now optional (administrative validity), `issuance_date` was added (optional), and `location_status` was dropped from the table. Technical validity is `nbf`/`exp` (SD-JWT VC). Art. 5(7), which requires the status location to be indicated in the PID, still applies.
- The **portrait** becomes mandatory (unless the user opts out) from **11.8.2028**.
- **Revocation time limits:** PID user notice within 24 h (2977 Art. 5(3)). QEAA status published within 24 h of the request (910/2014 Art. 24(3) via 24(4a)). WIA/KA status polled every 24 h or less for PID valid over 24 h (Annex Ib LC_GEN-4). Short-lived (24 h or less) attestations are exempt from revocation (EAA-4.2.13-03). Access and registration certificates are revoked within 24 h (848 Annex IV(3)(h), V(3)(g)).
- **Non-qualified EAA providers** have the lightest regime: 2977 Art. 4, 45g(1), 45h(1)–(2), 19a and 2025/2160. 2025/1569 does **not** apply to them.
