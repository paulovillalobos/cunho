# What the law says an EUDI Wallet credential issuer must log

Status: research memo, not legal advice. Prepared 3 November 2026.
Every finding below comes from the official text named next to it. Quotes are verbatim and kept short. Where a passage is cut, "…" marks the cut.

---

## 0. Sources read, with versions

| # | Instrument | Version read | Where it came from |
|---|---|---|---|
| A | Reg. (EU) 910/2014 (eIDAS) | Consolidated text **02014R0910-20241018**, which includes amendment M2 = Reg. 2024/1183 and corrigendum C1 (OJ 9.4.2025) | Publications Office Cellar, `resource/celex/02014R0910-20241018` (XHTML) |
| B | Reg. (EU) 2024/1183 | OJ L 30.4.2024 (used for recitals only) | Cellar `32024R1183` |
| C | CIR (EU) 2025/2160 (risk management for non-qualified TSPs) | OJ L 28.10.2025, in force 17.11.2025; no amendments found | Cellar `32025R2160` |
| D | CIR (EU) 2024/2977 (PID and EAA issued to wallets) | Consolidated **02024R2977-20260811**, which includes CIR 2026/1731 | Cellar; checked against the 2026/1731 OJ text |
| E | CIR (EU) 2024/2979 (wallet integrity and core functions) | Consolidated **02024R2979-20260811**, which includes 2026/1731 (new Annex Ib, Annex II) | Cellar; checked against 2026/1731 |
| F | CIR (EU) 2025/1569 (QEAA and PuB-EAA) | Consolidated **02025R1569-20260811**, which includes CIR 2026/1735 (OJ 22.7.2026, in force 11.8.2026; its Art 1(3) applies from 1.1.2027) | Cellar; checked against 2026/1735 |
| G | CIR (EU) 2025/2530 (requirements for QTSPs) | OJ L 17.12.2025 | Cellar `32025R2530` |
| H | GDPR (EU) 2016/679 | OJ L 4.5.2016 | Cellar `32016R0679` |
| I | CIR (EU) 2015/1502 (assurance levels) | OJ text of 8.9.2015. Later amendments **not checked** | Cellar `32015R1502` |
| J | Directive (EU) 2022/2555 (NIS2) and CIR (EU) 2024/2690 | OJ texts | Cellar |
| K | ETSI EN 319 401 **V3.1.1 (2024-06)** and **V3.2.1 (2026-01)** | etsi.org PDFs | etsi.org/deliver |
| L | ETSI TS 119 471 **V1.1.1 (2025-05)** | etsi.org PDF | etsi.org/deliver |
| M | ARF **v3.0.0** (tag `v3.0.0`, commit c64f2cb, 21.7.2026), `hltr/high-level-requirements.csv` | Local clone `<scratch>/arf/arf` | git |

**Corrections to the earlier summary**

1. **Art 5a(4)(a) is not the transaction-log provision.** The wallet transaction log is **Art 5a(4)(d)**.
2. **Art 19 no longer exists.** NIS2 Art 42 deleted it: "In Regulation (EU) No 910/2014, Article 19 is deleted with effect from 18 October 2024." The security rules for non-qualified TSPs are now in **Art 19a**.
3. **Art 24(2)(h) does not bind every issuer.** It binds QTSPs, which includes QEAA providers, and wallet providers through Art 5a(20). It reaches public-body EAA providers only indirectly. It does **not** bind PID providers or non-qualified EAA providers. See §1.
4. **CIR 2025/2160 Art 4(3)(b) does not bind every issuer.** It binds *non-qualified* TSPs, and CIR 2025/2530 Art 2 extends it to QTSPs. It does **not** bind PID providers. Whether it reaches a given non-qualified EAA provider depends on the definitions; see §2.
5. **The ARF is not law.** CIR 2024/2977 Art 1 only says the rules are "to be updated … in line with … the architecture and reference framework". ARF HLRs bind only where a CIR copies them. Otherwise they are certification and interoperability expectations.

---

## 1. Who is who (definitions, Reg. 910/2014 consolidated 18.10.2024)

| Citation | Operative text (quoted) | Consequence |
|---|---|---|
| Art 3(3) | "'person identification data' means a set of data that is issued in accordance with Union or national law and that enables the establishment of the identity of a natural or legal person…" | PID is **not** in the Art 3(16) list of trust services. A PID provider is therefore not a "trust service provider" just by issuing PID. It works under the eID scheme (Art 5a(11)) and CIR 2024/2977. |
| Art 3(16), point (g) | "'trust service' means an electronic service normally provided for remuneration which consists of any of the following: … (g) the issuance of electronic attestations of attributes" | Issuing EAA is a trust service, subject to "normally provided for remuneration". |
| Art 3(19) | "'trust service provider' means a natural or a legal person who provides one or more trust services either as a qualified or as a non-qualified trust service provider" | **A non-qualified EAA provider is a non-qualified TSP.** Art 19a and CIR 2025/2160 therefore reach it, subject to two limits: the remuneration qualifier above, and the closed-system exclusion below. |
| Art 2(2) | "This Regulation does not apply to the provision of trust services that are used exclusively within closed systems resulting from national law or from agreements between a defined set of participants." | A closed-ecosystem EAA issuer may fall outside eIDAS altogether. |
| Art 3(44) / (45) | EAA: "an attestation in electronic form that allows attributes to be authenticated". QEAA: "…issued by a qualified trust service provider and meets the requirements laid down in Annex V" | A QEAA provider is a QTSP, so Art 24 applies. |
| Art 3(46) | PuB-EAA: "…issued by a public sector body that is responsible for an authentic source or by a public sector body that is designated by the Member State…" | PuB-EAA has its own regime (Art 45f). Whether Art 19a *also* applies to public bodies is **not settled by the text** (see the remuneration qualifier). |

---

## 2. Source-by-source table

Strength codes: **SHALL** = binding obligation; **SHALL NOT** = binding prohibition; **SHOULD** = recommendation or recital; **MAY** = permission. "ARF-SHALL" is a non-binding framework requirement.

### 2.1 Reg. 910/2014 (consolidated 18.10.2024)

| Citation | Quote (≤40 words) | Binds | Strength |
|---|---|---|---|
| Art 5a(4)(d) | wallets shall enable the user to "access a log of all transactions carried out through the European Digital Identity Wallet via a common dashboard…" | Wallet provider / Member State (wallet-side log) | SHALL |
| Art 5a(5)(b) | wallets shall "not provide any information to trust service providers of electronic attestations of attributes about the use of those electronic attestations" | Wallet provider. Effect: issuers must not receive usage data from the wallet | SHALL NOT |
| Art 5a(14) | "The provider of the European Digital Identity Wallet shall neither collect information about the use of the European Digital Identity Wallet which is not necessary for the provision of European Digital Identity Wallet services…" | Wallet provider only | SHALL NOT |
| Art 5a(16)(a) | the technical framework shall "not allow providers of electronic attestations of attributes or any other party, after the issuance of the attestation of attributes, to obtain data that allows transactions or user behaviour to be tracked, linked or correlated… unless explicitly authorised by the user" | Addressed to the "technical framework"; aimed at all EAA providers | SHALL NOT |
| Art 5a(16)(b) | "enable privacy preserving techniques which ensure unlinkability, where the attestation of attributes does not require the identification of the user" | Technical framework | SHALL |
| Art 5a(20) | "Article 24(2), points (b), and (d) to (h), shall apply mutatis mutandis to providers of European Digital Identity Wallets." | Wallet providers (this is why 24(2)(h) reaches *them*) | SHALL |
| Art 5f(1) | "…they shall also accept European Digital Identity Wallets that are provided in accordance with this Regulation." | Public-sector relying parties. **Nothing on logging** | n/a |
| Art 19a(1)(a) | a non-qualified TSP shall "have appropriate policies and take corresponding measures to manage legal, business, operational and other direct or indirect risks to the provision of the non-qualified trust service…" | Non-qualified TSPs, including non-qualified EAA providers | SHALL |
| Art 19a(2) | "Compliance with the requirements laid down in this Article shall be presumed where those standards, specifications and procedures are met." | Same. CIR 2025/2160 is a presumption-of-conformity route | n/a |
| Art 24(2)(e) | "use trustworthy systems and products that are protected against modification and ensure the technical security and reliability of the processes supported by them…" | QTSPs (incl. QEAA); wallet providers via 5a(20) | SHALL |
| Art 24(2)(f) | "use trustworthy systems to store data provided to it, in a verifiable form so that: … (ii) only authorised persons can make entries and changes to the stored data, (iii) the data can be checked for authenticity" | Same | SHALL |
| Art 24(2)(f)(i) | data are "publicly available for retrieval only where the consent of the person to whom the data relates has been obtained" | Same | SHALL |
| Art 24(2)(g) | "take appropriate measures against forgery, theft or misappropriation of data or, without right, deleting, altering or rendering data inaccessible" | Same | SHALL |
| **Art 24(2)(h)** | "record and keep accessible for as long as necessary after the activities of the qualified trust service provider have ceased, all relevant information concerning data issued and received… for the purpose of providing evidence in legal proceedings…" | **QTSPs only** (incl. QEAA providers), plus wallet providers via 5a(20). Not PID providers. Not non-qualified EAA providers | SHALL |
| Art 24(3) | a QTSP revoking a certificate "shall register such revocation in its certificate database and publish the revocation status… within 24 hours after the receipt of the request" | QTSPs issuing qualified certificates; extended to QEAA by 24(4a) | SHALL |
| Art 24(4) | status information "shall be made available at least on a per certificate basis at any time and beyond the validity period of the certificate…" | Same, extended to QEAA by 24(4a) | SHALL |
| **Art 24(4a)** | "Paragraphs 3 and 4 shall apply accordingly to the revocation of qualified electronic attestations of attributes." | **QEAA providers only** | SHALL |
| Art 45d(4) | a revoked QEAA "shall lose its validity from the moment of its revocation and its status shall not in any circumstances be reverted" | QEAA providers | SHALL |
| Art 45f(2) | Member State "shall ensure that the public sector bodies that issue electronic attestations of attributes meet a level of reliability and trustworthiness equivalent to qualified trust service providers in accordance with Article 24" | Member States. This is an *indirect* route for Art 24 to reach PuB-EAA providers | SHALL |
| Art 45f(4) | a revoked PuB-EAA "shall lose its validity from the moment of its revocation and its status shall not be reverted" | PuB-EAA providers | SHALL |
| Art 45h(1) | "Providers of qualified and non-qualified electronic attestation of attributes services shall not combine personal data relating to the provision of those services with personal data from any other services…" | All EAA providers (not PID) | SHALL NOT |
| Art 45h(2) | "Personal data relating to the provision of electronic attestation of attributes services shall be kept logically separate from other data held by the provider…" | All EAA providers | SHALL |
| Art 3(52), Art 45l(1)(c)-(d) | Ledger: "ensuring the integrity of those records and the accuracy of the chronological ordering"; qualified ledgers "ensure the unique sequential chronological ordering" and changes are "immediately detectable" | Only qualified-ledger QTSPs. It is a **separate trust service, not an issuer duty** | n/a for issuers |
| Annex V (c), (f), (i); Annex VII same | QEAA/PuB-EAA contains subject data ("if a pseudonym is used, it shall be clearly indicated"), an "attestation identity code, which must be unique for the qualified trust service provider", and status-service location | QEAA / PuB-EAA content | SHALL |
| Annex VI | List of attributes to be verifiable against authentic sources | Nothing on logging | n/a |

### 2.2 CIR 2025/2160: risk management for non-qualified trust services

**Scope.** Art 1 refers to "the reference standards referred to in Article 19a(2)". Art 2(1) applies to "the non-qualified trust service provider".

**Who it binds.** Non-qualified TSPs, which includes non-qualified EAA providers (see §1). CIR 2025/2530 Art 2 extends Arts 2-4 to QTSPs. It does **not** bind PID providers.

**How strong it is.** The articles say "shall", and the CIR is "binding in its entirety". However, recital 4 says it works as the presumption-of-conformity route: "a non-qualified trust services provider may still rely on other practices to demonstrate compliance". In other words, Art 4(3)(b) is the default way to meet Art 19a(1)(a) but not the only lawful way.

| Citation | Quote | Strength |
|---|---|---|
| **Art 4(3)(b)** | "record and securely retain for as long as necessary in accordance with Union or national laws, including after the activities of the non-qualified trust service provider have ceased, the following information:" | SHALL |
| — 1st indent | "all relevant information collected in the process of registration and onboarding of the trust service users, including, where applicable, the identity verification of the users" | SHALL |
| — 2nd indent | "authentication data assigned to the user of the trust service, where applicable" | SHALL |
| — 3rd indent | "any change of the status of public key certificates or other cryptographic material used in the provision of the trust service" | SHALL. *Whether a per-EAA revocation counts as "cryptographic material" is an interpretation, not settled* |
| Art 4(3)(a) | "verify, where applicable, the identity of the users of the trust service… and publish information on the identity verification methods used" | SHALL |
| **Art 4(7)** | "Non-qualified trust service providers shall ensure the availability, integrity and confidentiality of the information referred to in paragraph 3, point (b)." | SHALL |
| Recital 5 | "non-qualified trust service providers should ensure the integrity and confidentiality of such data" | SHOULD (recital) |
| Annex | Applies ETSI EN 319 401 V3.1.1 clauses "5. Risk Assessment; 6. Policies and practices; 7.1 … 7.2 … 7.3 … 7.4 … 7.6" | SHALL (presumption route) |

**Clauses the Annex leaves out.** It does **not** list EN 319 401 clause 7.10 (Collection of evidence) or 7.9 (Monitoring and logging). For a non-qualified EAA provider, then, the ETSI record-keeping and "cannot be easily deleted" rules are **not** imported by this CIR. Clause 6, which is imported, does contain REQ-6.2-02(e): the terms and conditions must state "the period of time during which TSP's event logs are retained".

### 2.3 CIR 2024/2977: PID and EAA issued to wallets (consolidated 11.8.2026)

| Citation | Quote | Binds | Strength |
|---|---|---|---|
| Art 2(4) | PID provider "means a natural or legal person responsible for issuing and revoking the person identification data and ensuring that the person identification data of a user is cryptographically bound to a wallet unit" | PID provider | definition |
| Art 3(7) | "…providers of person identification data shall perform identity verification of the wallet user in accordance with the requirements related to identity proofing and verification before issuing…" | PID provider | SHALL |
| Art 5(1) | PID providers "shall have written and publicly accessible policies relating to validity status management…" | PID provider | SHALL |
| Art 5(2) | "Only providers of person identification data or electronic attestation of attributes can revoke the person identification data or electronic attestations of attributes issued by them." | PID and all EAA providers | SHALL (exclusive) |
| **Art 5(3)** | revoking PID providers "shall, through dedicated and secure channels, inform wallet users… within 24 hours of the revocation and of the reasons for the revocation" | PID provider | SHALL |
| **Art 5(4)** | PID providers shall revoke "(a) upon the explicit request of the wallet user…; (b) where the wallet unit attestation… has been revoked; (c) in other situations determined… in their policies" | PID provider | SHALL |
| Art 5(5) | "Providers of person identification data issued to a wallet unit shall ensure that revocations cannot be reverted." | PID provider | SHALL |
| **Art 5(6)** | "The revoked person identification data shall remain accessible for as long as required by Union law or national law." | PID provider. *Unclear whether "accessible" means the status or the data* | SHALL |
| Art 5(7) | PID providers "shall make publicly available the validity status… in a privacy preserving manner" | PID provider | SHALL |
| Art 5(8) | PID providers "shall enable privacy preserving techniques which ensure unlinkability where the electronic attestations of attributes do not require the identification of the user" | PID provider | SHALL |
| Annex (replaced by 2026/1731) | PID data set, metadata (e.g. optional `document_number`), encoding. **No logging or record-keeping text** | PID provider | n/a |

The CIR contains **no article on issuer logs or records**, apart from Art 5(6).

### 2.4 CIR 2024/2979: wallet integrity (consolidated 11.8.2026)

| Citation | Quote | Binds | Strength |
|---|---|---|---|
| Art 9(1) | "Irrespective of whether or not a transaction is successfully completed, wallet instances shall log all transactions with wallet-relying parties and other wallet units…" | Wallet provider / wallet instance | SHALL |
| Art 9(2) | log "shall at least contain: (a) the time and date… (b) the name, contact details, and the unique identifier of the corresponding wallet-relying party… (c) the type or types of data requested and presented…" (9(2)(b) as amended by 2026/1731) | Wallet | SHALL |
| **Art 9(3)** | "Wallet providers shall ensure integrity, authenticity and confidentiality of the logged information." | Wallet provider | SHALL |
| Art 9(5) | logs "shall be accessible to the wallet provider, where it is necessary… on the basis of explicit prior consent by the wallet user" | Wallet provider | SHALL (limit) |
| Art 9(6) | "The logs… shall remain accessible for as long as they are required by Union law or national law." | Wallet | SHALL |
| Recital 11 | "Logging transactions is an important tool to provide transparency, in the form of providing an overview of the transactions to the wallet user." | — | recital |
| **Annex Ib, LC_GEN-4** (inserted by 2026/1731) | "A provider of person identification data having a technical validity period of more than 24 hours shall check the revocation status of both the wallet instance attestation and the key attestation received during issuance at least once every 24 hours…" | **PID provider** | SHALL |
| Annex Ib, LC_GEN-3 | "The technical validity period of person identification data shall end before both the 'client_status.exp'… and the 'key_storage_status.exp'…" | PID provider | SHALL |
| Annex Ib, R_WIA-5 | status lists must be "sufficiently large to prevent correlation… at least 10 000 attestations" | Wallet provider (WIA lists) | SHALL |
| Annex II (replaced by 2026/1731), EAA-4.2.11.1-06.1 | "Where an attestation is revoked, it shall be permanently revoked." | PID, QEAA and PuB-EAA providers | SHALL |
| Annex II, EAA-6.2.10.1-02.1 | for attestations valid "equal to or less than 24 hours, then revocation shall not be required" | Same | MAY skip revocation |

**Practical effect of LC_GEN-4.** A PID provider **must keep**, for each PID it issued, the status references (status-list URI and index) of the WIA and KA it received at issuance. It needs them for the PID's whole validity period, because it has to re-check them every 24 hours.

**What the CIR does not do.** It puts **no logging duty on issuers**. Art 9 is the *wallet's* log only.

### 2.5 CIR 2025/1569: QEAA and PuB-EAA (consolidated 11.8.2026, i.e. as amended by 2026/1735)

| Citation | Quote | Binds | Strength |
|---|---|---|---|
| Art 3(1) | providers "shall comply with the list of reference standards and specifications set out in Annex I…" | QEAA and PuB-EAA providers | SHALL |
| Art 4(1) | **Deleted** by 2026/1735 (it was the revocation-policy duty) | — | — |
| Art 4(3) | for attestations valid >24 h, providers "shall revoke them in at least the following circumstances: (a) upon the request of the person to whom the electronic attestation of attributes was issued or… of the subject…" | QEAA and PuB-EAA providers | SHALL |
| **Art 4(4)** | providers "shall set up revocation techniques and management methods that are privacy preserving and hindering linkability or traceability." | QEAA and PuB-EAA providers | SHALL |
| Art 4(5) | status information must be made available "in a manner that ensures the integrity and authenticity of that information" | QEAA and PuB-EAA providers | SHALL |
| **Annex I** (since 11.8.2026) | "ETSI TS 119 471 V1.1.1 (2025-05) shall apply with the following adaptations:" and the normative reference becomes "ETSI EN 319 401 V3.2.1 (2026-01)" | QEAA and PuB-EAA providers | SHALL |
| Annex I (original, until 10.8.2026) | providers "shall issue their attestations… according to the specifications for trust service providers established in standard ETSI EN 319 401 v3.1.1" | QEAA and PuB-EAA providers | SHALL |
| Annex II(2)(c) (original, **removed** 11.8.2026) | "process only the minimum set of attributes necessary for the issuance and management of the attestation" | Was binding on QEAA and PuB-EAA providers; minimisation now rests on GDPR | — |
| Annex I adaptation, REQ-EAASP-7.9-02 | "Monitoring activities shall take account of the sensitivity of any information collected or analysed." | QEAA and PuB-EAA providers | SHALL |
| Annex I adaptation, REQ-EAASP-7.12-04 | termination plan "shall comply with the requirements set out in the implementing acts adopted pursuant to Article 24(5)" (i.e. CIR 2025/2530) | QEAA and PuB-EAA providers | SHALL |

**Why this matters most for QEAA and PuB-EAA providers.** Because Annex I makes **TS 119 471** binding, the ETSI logging clauses in §2.9 below are binding law for these providers. The 2026/1735 adaptations do **not** change TS 119 471 clauses 7.10 or 7.13.

### 2.6 CIR 2025/2530: QTSP requirements (implements Art 24(5))

| Citation | Quote | Binds | Strength |
|---|---|---|---|
| **Art 2** | "The requirements laid down in Article 2, Article 3 and Article 4 of Commission Implementing Regulation 2025/2160 shall apply mutatis mutandis to qualified trust service providers…" | QTSPs (incl. QEAA providers) | SHALL |
| Art 3(1) | termination plan must cover "how information is kept accessible in accordance with Article 24(2), point (h)" | QTSPs | SHALL |
| Art 3(7)(e) | plan must ensure "the accessibility and usability of all relevant records held by the qualified trust service provider" | QTSPs | SHALL |
| Art 3(8)(a) | those records must "provide evidence in relation to the compliance of the qualified trust services with Regulation (EU) No 910/2014 and Regulation (EU) 2016/679" | QTSPs | SHALL |
| Annex point 13 | for QEAA: "the standard referenced in Annex I to Commission Implementing Regulation (EU) 2025/1569" | QEAA providers | SHALL |

This is the only CIR that gives detail on **how** Art 24(2)(h) is to be implemented. It does so through the termination plan and by importing 2160 Art 4(3)(b). It sets **no** retention number.

### 2.7 GDPR (OJ 4.5.2016): limits on any log that contains personal data

| Citation | Quote | Binds | Strength |
|---|---|---|---|
| Art 5(1)(c) | "adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed ('data minimisation')" | Every controller (every issuer) | SHALL |
| Art 5(1)(e) | "kept in a form which permits identification of data subjects for no longer than is necessary for the purposes…" | Every controller | SHALL |
| Art 5(1)(f) | "processed in a manner that ensures appropriate security… including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage" | Every controller | SHALL |
| Art 25(2) | "only personal data which are necessary for each specific purpose… are processed. That obligation applies to the amount of personal data collected, the extent of their processing, the period of their storage and their accessibility." | Every controller | SHALL |
| Art 30(1)(f) | the record of processing must contain "where possible, the envisaged time limits for erasure of the different categories of data" | Controllers (with the Art 30(5) exemption below 250 staff, unless the processing is not occasional) | SHALL |
| Art 32(1)(b) | "the ability to ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services" | Controllers and processors | SHALL (as appropriate to risk) |
| Art 17(3)(b), (e) | erasure does not apply where processing is necessary "for compliance with a legal obligation…" or "for the establishment, exercise or defence of legal claims" | Every controller | exemption |
| Art 15(1) | data subject's right to "access to the personal data" | Every controller | SHALL |

### 2.8 Other binding instruments that reach issuers

| Citation | Quote | Binds | Strength |
|---|---|---|---|
| CIR 2015/1502 Annex 2.4.4(1) | "Record and maintain relevant information using an effective record-management system, taking into account applicable legislation and good practice in relation to data protection and data retention." | "providers" in an eID scheme (2.4: "All participants providing a service related to electronic identification in a cross-border context"). **PID providers**, because PID sits under an LoA-high eID scheme (eIDAS Art 5a(11); CIR 2024/2977 Art 3(1), 3(7)). The link is an interpretation | SHALL |
| CIR 2015/1502 Annex 2.4.4(2) | "Retain… and protect records for as long as they are required for the purpose of auditing and investigation of security breaches, and retention, after which the records shall be securely destroyed." | Same | SHALL |
| CIR 2015/1502 Annex 2.4.1(2) | providers comply with legal requirements on "what information may be retained and for how long" | Same | SHALL |
| NIS2 Art 2(2)(a)(ii) | "Regardless of their size, this Directive also applies to entities… where: (a) services are provided by: … (ii) trust service providers" | All TSPs (qualified and non-qualified) | scope |
| CIR 2024/2690 Annex 3.2.3(e) | logs shall include, where appropriate, "all privileged access to systems and applications, and activities performed by administrative accounts" | All TSPs ("relevant entities", Art 1) | SHALL |
| **CIR 2024/2690 Annex 3.2.5** | "The relevant entities shall maintain and back up logs for a predefined period and shall protect them from unauthorised access or changes." | All TSPs, including non-qualified EAA providers | SHALL |
| CIR 2024/2690 Annex 3.2.6 | "…ensure that all systems have synchronised time sources to be able to correlate logs between systems…" | All TSPs | SHALL (to the extent feasible) |

### 2.9 ETSI EN 319 401 and TS 119 471 (the texts auditors apply)

**Legal status of these clauses**

- EN 319 401 V3.1.1 clause 7.10 bound QEAA and PuB-EAA providers through CIR 2025/1569 Annex I (original version) until 10.8.2026.
- From 11.8.2026, TS 119 471 V1.1.1 binds them; its REQ-EAASP-7.10-01 pulls in EN 319 401 clause 7.10.
- For non-qualified TSPs, only EN 319 401 clauses 5, 6, 7.1-7.4 and 7.6 are imported (through 2160). Clauses 7.9 and 7.10 are **best practice, not law**, for them.

| Clause | Quote | Strength |
|---|---|---|
| EN 319 401 V3.1.1 / V3.2.1 REQ-7.10-01 | "The TSP shall record and keep accessible for an appropriate period of time, including after the activities of the TSP have ceased, all relevant information concerning data issued and received by the TSP…" | SHALL |
| REQ-7.10-02 | "The confidentiality and integrity of current and archived records concerning operation of services shall be maintained." | SHALL |
| REQ-7.10-04 | records "shall be made available if required for the purposes of providing evidence of the correct operation of the services for the purpose of legal proceedings" | SHALL |
| REQ-7.10-05 | "The precise time of significant TSP's environmental, key management and clock synchronization events shall be recorded." | SHALL |
| REQ-7.10-06 | "The time used to record events as required in the audit log shall be synchronized with UTC at least once a day." | SHALL |
| REQ-7.10-07 | records held "for a period of time as appropriate for providing necessary legal evidence and as notified in the TSP's terms and conditions" | SHALL |
| **REQ-7.10-08** | "The events shall be logged in a way that they cannot be easily deleted or destroyed (except if reliably transferred to long-term media) within the period of time that they are required to be held." | SHALL |
| REQ-7.10-08 EXAMPLE | "…write-only media, a record of each removable storage media used and the use of off-site backup or by parallel storage… at several (e.g. 2 or 3) independent sites" | informative |
| REQ-6.2-02(e) | T&Cs specify "the period of time during which TSP's event logs are retained" | SHALL |
| REQ-7.4-12X (V3.1.1) | "TSP's personnel shall be accountable for their activities. EXAMPLE: By retaining event logs." | SHALL |
| V3.2.1 REQ-7.9.1-14 | "The TSP shall maintain and back up logs for a predefined period and shall protect them from unauthorised access or changes." | SHALL |
| TS 119 471 REQ-EAASP-7.10-02 | "Evidence of the EAA issuance process shall be collected and securely archived." | SHALL (binding on QEAA and PuB-EAA providers) |
| REQ-EAASP-7.10-04 | "All events related to registration including requests for EAA renewal shall be logged." | SHALL |
| REQ-EAASP-7.10-06 | "The EAASP shall log all events relating to the EAA life-cycle." | SHALL |
| **REQ-EAASP-7.10-07** | "The EAASP shall log all requests and reports relating to revocation, as well as the resulting action." | SHALL |
| REQ-EAASP-7.10-08 | "The EAASP shall precisely document the period of retention of the information mentioned above in its practices statements and shall indicate which information is subject to be handed-over through its termination plan." | SHALL |
| REQ-EAASP-7.12-02 | "The EAASP shall retain the following records after any EAA based on these records ceases to be valid: a) log of all events relating to the EAA life cycle; and b) attributes attestations data issuance evidence." | SHALL |
| REQ-EAASP-7.12-03 | "The retention period shall be defined by the EAASP in accordance with national legislation." | SHALL |
| REQ-EAASP-7.4-04 | "The EAASP shall monitor and log all authentication attempts and failures in order to detect potential malicious activities." | SHALL |
| REQ-EAASP-6.2.4-03 / -06 | "The EAASP shall record the agreement with the EAA Subscriber." Records are "retained for the period of time as indicated to the EAA Subscriber as part of the terms and conditions." | SHALL |
| REQ-EAASP-7.13-03 | "The EAASP shall protect confidentiality and integrity of registration data…" | SHALL |
| **REQ-EAASP-7.13-05** | "The EAASP shall not track, link, correlate, or otherwise obtain knowledge of transactions or EAA Subject behaviour post-issuance of the EAA unless explicitly authorized by the EAA Subject." | SHALL NOT |
| REQ-EAASP-7.13-06 | "The EAASP shall keep logically separate attributes and metadata related to EAA Subject and/or EAA Subscribers… from other data held." | SHALL |
| **REQ-EAASP-7.13-08** | "The EAASP shall ensure that its systems are designed to log minimal information about EAA issuance and usage, sufficient for security and management purposes… but not enabling tracking of user activities." | SHALL |

### 2.10 ARF 3.0.0 HLRs (not law; certification and interoperability expectations)

| HLR | Quote | Addressee | Strength |
|---|---|---|---|
| ISSU_35 | unique elements must have "a negligible chance of having the same value"; includes "a) the salt… b) the hash values of all attributes, c) the attestation identifier or index used for revocation… d) the attestation public key… e) the value of the Attestation Provider signature" | PID and Attestation Providers | ARF-SHALL |
| **ISSU_35b** | "…SHALL discard the values of all unique elements, including at least the ones mentioned in requirement ISSU_35… as well as any timestamps, as soon as they are no longer needed. The Provider SHALL NOT communicate these values to any other party…" | PID, Attestation and Wallet Providers | ARF-SHALL / SHALL NOT |
| ISSU_36 | timestamps in batch-issued credentials must "not enable Relying Parties to conclude that they are part of the same batch" | Same | ARF-SHALL |
| VCR_17 | "SHALL randomly assign the index for each PID or attestation, to prevent this index from becoming a correlator" | Same | ARF-SHALL |
| VCR_18 | "SHALL represent a sufficiently large number of PIDs, attestations… on each Attestation Status List to ensure herd privacy" | Same | ARF-SHALL |
| VCR_16 | "SHALL NOT require the Relying Party… to authenticate itself before downloading an Attestation Status List" | Same | ARF-SHALL NOT |
| VCR_03 (note) | "A PID Provider or Attestation Provider MAY outsource the operation of the revocation process to a third party." | Same | ARF-MAY |
| VCR_07a / 07b | PID: "SHALL revoke that PID upon the explicit request of the User". Attestation: "SHOULD revoke… upon the explicit request" | PID / Attestation Providers | ARF-SHALL / SHOULD |
| VCR_02 | for non-qualified EAA, "the relevant Rulebook SHALL specify whether that type of EAA must be revocable" | Rulebook authors | ARF-SHALL |
| **WURevocation_11** | "To identify the Wallet Unit that is to be revoked, the PID Provider SHALL use a Wallet Instance identifier provided by the Wallet Provider in the WIA during PID issuance." | PID Provider (death case) | ARF-SHALL |
| **WURevocation_18 / WUA_29** | PID Provider "SHALL, for each of its valid PIDs, regularly verify whether the Wallet Instance… has been revoked… using the WIA and KA received during issuance of that PID" | PID Provider | ARF-SHALL; the legal basis is CIR 2979 Annex Ib LC_GEN-4 |
| WURevocation_19 | Attestation Provider "MAY decide to revoke an attestation if the Wallet Provider revoked the Wallet Unit… SHALL publish its policy" | Attestation Providers | ARF-MAY / SHALL |
| WUA_08 | "The Wallet Provider SHALL ensure that this Wallet Instance identifier does not enable tracking of the User." Note: the identifier is "the URI and index to the Attestation Status List for WIAs" | Wallet Provider | ARF-SHALL |
| DASH_02 / DASH_05 | the wallet log includes issuance transactions, with "the trade name… unique identifier… of the corresponding PID Provider or Attestation Provider" | Wallet | ARF-SHALL |
| DASH_06 / 06b | "The Wallet Provider SHALL ensure the confidentiality, integrity, and authenticity of all transactions included in the log." "…no entity other than the User can delete transactions from the log" | Wallet | ARF-SHALL |
| Reg_09 | "Member States SHALL log all changes made on the information registered regarding a PID Provider…" | Member State registrars (not issuers) | ARF-SHALL |

**Missing HLR.** I found no ARF HLR that tells a PID or Attestation Provider to keep an audit or issuance log. The only issuer-side "record" HLRs are the WIA/KA retention for revocation chaining (above) and the policy HLRs.

---

## 3. Plain answers

### Q1. Must an issuer record that it ISSUED a credential? Identity or pseudonymous reference? Which issuer types?

- **QEAA provider: yes, explicitly.**
  - eIDAS Art 24(2)(h) requires "all relevant information concerning data issued" to be recorded.
  - TS 119 471 REQ-EAASP-7.10-02 requires "Evidence of the EAA issuance process" and 7.10-06 requires all EAA life-cycle events. TS 119 471 is binding through CIR 2025/1569 Art 3(1) and Annex I.
  - CIR 2025/2160 Art 4(3)(b), applied through 2530 Art 2, covers onboarding and identity-verification information.
- **PuB-EAA provider: yes.** The same TS 119 471 clauses bind it through CIR 2025/1569 Annex I. Art 24 also reaches it indirectly through eIDAS Art 45f(2).
- **Non-qualified EAA provider: partly, and only by the presumption route.**
  - CIR 2025/2160 Art 4(3)(b) requires recording **onboarding and identity-verification information, assigned authentication data, and status changes of cryptographic material**.
  - It does **not** say "each attestation issued". EN 319 401 clause 7.10 is not imported.
  - Recital 4 allows "other practices".
  - All TSPs must also keep NIS2 security logs (CIR 2024/2690 Annex 3.2).
- **PID provider: no explicit "issuance log" duty in any eIDAS-family text.**
  - The general record-keeping rule in CIR 2015/1502 Annex 2.4.4 applies, on the reading that PID providers are eID-scheme "providers".
  - It **must retain** the WIA/KA status references received at issuance, to re-check them every 24 hours (CIR 2024/2979 Annex Ib LC_GEN-4; ARF WURevocation_18).
- **To whom (identity or pseudonym).**
  - The *identity* must be recorded in the **onboarding/identity-verification** records: 2160 Art 4(3)(b), first indent; for QTSPs, Art 24(1).
  - Nothing requires the *issuance event* itself to carry the real identity.
  - Annex V(c) and Annex VII(c) allow a pseudonymous subject ("if a pseudonym is used, it shall be clearly indicated").
  - GDPR Art 5(1)(c), Art 25(2), eIDAS Art 45h(2) and TS 119 471 REQ-EAASP-7.13-06/-08 all push towards an internal pseudonymous account reference in the event log, with identity data kept logically separate.

### Q2. Must it record REVOCATION events, and who requested and performed them?

- **QEAA:**
  - eIDAS Art 24(3) with 24(4a): "register such revocation… and publish the revocation status… within 24 hours after the receipt of the request". The 24-hour clock means the time the request was received has to be evidenced.
  - TS 119 471 REQ-EAASP-7.10-07: "log all requests and reports relating to revocation, as well as the resulting action".
  - Revocation is irreversible (Art 45d(4)).
- **PuB-EAA:** TS 119 471 REQ-EAASP-7.10-07 applies through CIR 2025/1569. Revocation is irreversible (Art 45f(4)). CIR 2025/1569 Art 4(3) lists the triggers, starting with a request by the holder or subject.
- **PID provider:**
  - No text says "log revocations".
  - CIR 2024/2977 Art 5(3) requires the user to be told the "reasons for the revocation" within 24 hours.
  - Art 5(4) lists the triggers: user request, WUA revoked, or policy.
  - Art 5(5) requires irreversibility.
  - Demonstrating compliance with these rules in practice needs a record of the trigger, the time and the reason. That record is **implied, not stated**.
- **Non-qualified EAA:** only CIR 2025/2160 Art 4(3)(b), third indent ("any change of the status of… cryptographic material"), and whether that covers an attestation revocation is an interpretation. Whether such an EAA must be revocable at all is left to the rulebook (ARF VCR_02).
- **Who performed it (the operator):**
  - EN 319 401 REQ-7.4-12X ("personnel shall be accountable… By retaining event logs") applies to non-qualified TSPs too, since clause 7.4 is in the 2160 Annex.
  - CIR 2024/2690 Annex 3.2.3(e) covers administrator activity for all TSPs.
- **Who requested it:** explicit only in TS 119 471 7.10-07 ("requests and reports"), so only for QEAA and PuB-EAA providers.

### Q3. What must it NOT record or retain?

- **Usage, presentation or post-issuance tracking data.**
  - eIDAS Art 5a(16)(a) and 5a(5)(b).
  - TS 119 471 REQ-EAASP-7.13-05 (SHALL NOT, binding on QEAA and PuB-EAA providers).
  - REQ-EAASP-7.13-08 ("log minimal information… not enabling tracking of user activities").
  - CIR 2025/1569 Art 4(4): revocation must be "privacy preserving and hindering linkability or traceability". In practice, **do not log status-list fetches with requester IP or identity alongside the list or index**.
- **Unique credential values once no longer needed** (ARF ISSU_35b, not law): salts, attribute digests, revocation index or identifier, device public key, signature value and credential timestamps. ISSU_35b also says "SHALL NOT communicate these values to any other party".
- **Data combined with other services:** eIDAS Art 45h(1); keep it logically separate under Art 45h(2).
- **PID or attribute data beyond need:** GDPR Art 5(1)(c), Art 25(2) and TS 119 471 REQ-EAASP-7.13-04. The explicit 1569 Annex II(2)(c) minimisation clause was removed on 11.8.2026, so minimisation now rests on GDPR. No issuer-side text bans attribute *values* in logs outright; for the wallet log, ARF DASH_03a does. Minimisation still points to logging attribute *types*, not values.

### Q4. How long (retention), and who may access?

**No EU text sets a number of years.** Each formula defers elsewhere:

- eIDAS Art 24(2)(h): "for as long as necessary after the activities… have ceased" (QTSP).
- CIR 2025/2160 Art 4(3)(b): "for as long as necessary in accordance with Union or national laws, including after… ceased".
- CIR 2024/2977 Art 5(6): "as long as required by Union law or national law".
- CIR 2015/1502 2.4.4(2): as long as needed "for the purpose of auditing and investigation of security breaches… after which the records shall be securely destroyed".
- TS 119 471 REQ-EAASP-7.12-02/-03: retained after the EAA ceases to be valid; the period is "defined… in accordance with national legislation".
- The retention period must be **published or documented**:
  - EN 319 401 REQ-6.2-02(e), in the terms and conditions;
  - TS 119 471 REQ-EAASP-7.10-08, in the practice statement;
  - GDPR Art 30(1)(f), in the record of processing.
- The GDPR ceiling: Art 5(1)(e), "no longer than is necessary".

**Access:**

- Entries and changes by "only authorised persons"; "publicly available for retrieval only where the consent" is given (eIDAS Art 24(2)(f)).
- Archives kept confidential: EN 319 401 REQ-7.10-02 and -03; CIR 2025/2160 Art 4(7).
- Records made available "for the purpose of legal proceedings" (REQ-7.10-04).
- For QTSPs, records stay accessible after termination as evidence of compliance with eIDAS and GDPR (CIR 2025/2530 Art 3(7)(e) and 3(8)(a)).
- For QTSPs, conformity assessment audits every 24 months (eIDAS Art 20(1)).
- Data subjects have the GDPR Art 15 right of access.
- NIS2 logs must be protected "from unauthorised access or changes" (CIR 2024/2690 Annex 3.2.5).

### Q5. Does any text require tamper-evidence (immutable, append-only, hash chain, timestamps)?

**No text requires a hash chain, append-only storage, immutability or cryptographic timestamping of issuer logs.** The closest provisions, from strongest to weakest:

1. **EN 319 401 REQ-7.10-08**: events logged "in a way that they cannot be easily deleted or destroyed". The example given is write-only media and off-site or parallel storage. Binding on **QEAA and PuB-EAA** providers through CIR 2025/1569 and TS 119 471; best practice for others.
2. **Integrity duties.**
   - eIDAS Art 24(2)(f)(ii)-(iii): authorised-only entries and changes, authenticity checkable.
   - eIDAS Art 24(2)(g): measures against data being, "without right, deleting, altering".
   - Both apply to QTSPs and to wallet providers.
3. **CIR 2025/2160 Art 4(7)**: "integrity and confidentiality" of the Art 4(3)(b) records. Applies to non-qualified TSPs, and to QTSPs through 2530 Art 2.
4. **CIR 2024/2690 Annex 3.2.5**: protect logs "from unauthorised access or changes". Applies to all TSPs. EN 319 401 V3.2.1 REQ-7.9.1-14 says the same.
5. **Time.** EN 319 401 REQ-7.10-05 requires precise time for key-management events; REQ-7.10-06 requires the audit log clock to sync with UTC daily; CIR 2024/2690 Annex 3.2.6 requires synchronised time sources.
6. **GDPR Art 5(1)(f) and 32(1)(b)**: integrity as part of security, scaled to risk.
7. **eIDAS Art 3(52) and 45l** define what a tamper-evident chronological ledger is. A hash chain approximates 45l(1)(c)-(d). However, only a QTSP-provided ledger is a "qualified electronic ledger", so **do not market the log as one**.

**Conclusion.** A hash-chained, append-only log is a strong way to meet these integrity and "cannot be easily deleted" duties, but it is a design choice, not a legal requirement. eIDAS Art 24(2)(f)(ii) actually contemplates *authorised* "entries and changes", so the law asks for controlled, attributable changes rather than absolute immutability.

### Q6. Conflicts

1. **ISSU_35b (discard unique values) vs revocation.**
   - Revocation needs the index or identifier: CIR 2025/1569 Art 4, eIDAS Art 24(3)/(4a), CIR 2024/2977 Art 5.
   - PID providers must keep the WIA/KA status references (CIR 2024/2979 Annex Ib LC_GEN-4).
   - ISSU_35b's own words, "as soon as they are no longer needed", resolve this up to credential expiry: keep the index-to-account mapping while the credential is valid and revocable, then drop it.
   - After expiry, the status list itself must still answer "beyond the validity period" (eIDAS Art 24(4) via 24(4a), QEAA). That requires keeping the status bit, **not** the index-to-person mapping.
2. **ISSU_35b vs "retain after validity".** TS 119 471 REQ-EAASP-7.12-02 requires keeping the "log of all events relating to the EAA life cycle" and "issuance evidence" after the EAA expires.
   - For QEAA and PuB-EAA providers the binding CIR-imported standard prevails over the non-binding ARF.
   - Reconcile them by keeping events keyed to an internal record ID, and removing credential-level unique values (signature, salts, digests, index) once revocation is no longer possible.
   - Whether a *keyed* digest of the credential, kept as evidence, counts as a "value" under ISSU_35b is **a judgement call that no text answers**.
3. **Append-only vs GDPR erasure and storage limitation** (GDPR Art 5(1)(e), Art 17).
   - GDPR Art 17(3)(b) and (e) cover retention during the legally required period.
   - After that period, personal data must go. An immutable log that holds personal data in its entries will breach Art 5(1)(e).
   - The design implication: chain the *hashes* of entries, keep personal payloads separately deletable or crypto-shreddable, and never put credential unique values or attribute values into the chained part.
4. **Precise event timestamps vs ISSU_35b/ISSU_36 timestamp hygiene.**
   - EN 319 401 requires precise time for key-management events.
   - The ARF targets timestamps *inside credentials*.
   - Log event times are service records, not credential elements. However, do not copy the credential's own `iat`/`exp`/validity values into the log.
5. **ISSU_35b "SHALL NOT communicate… to any other party" vs external log shipping or anchoring.**
   - Shipping entries that contain unique values to a third-party SIEM, or anchoring them publicly, would breach ISSU_35b.
   - Anchoring only a chain-head hash computed over value-free entries does not.
   - Outsourcing is foreseen for revocation (VCR_03 note) but not expressly for logs.

---

## 4. What our audit log must, should and must not contain

**MUST**, scoped by issuer type. "QEAA/PuB" means the line is binding law for those providers; for non-qualified EAA providers it is best practice unless marked otherwise.

| # | Line | Basis |
|---|---|---|
| M1 | An issuance event per credential, or per batch, with time, credential type, internal pseudonymous account or record ID, and the issuer key/certificate used. No credential unique values | TS 119 471 REQ-EAASP-7.10-02/-06 (QEAA/PuB); eIDAS Art 24(2)(h) (QEAA) |
| M2 | Onboarding and identity-verification records (method, result, evidence reference), in a **separate store** linked by the internal ID | CIR 2025/2160 Art 4(3)(b), 1st indent (non-qualified EAA, and QTSPs via 2530 Art 2); eIDAS Art 45h(2); TS 119 471 REQ-EAASP-7.13-06 |
| M3 | Authentication data assigned to users, and every authentication attempt and failure | CIR 2025/2160 Art 4(3)(b), 2nd indent; TS 119 471 REQ-EAASP-7.4-04 (QEAA/PuB) |
| M4 | Revocation events: time the request was received, who requested it (holder, subject, issuer policy, compromise, or WUA-revoked), the reason, the action taken and its time, the operator, and the status-publication time | TS 119 471 REQ-EAASP-7.10-07 (QEAA/PuB); eIDAS Art 24(3)+(4a) 24-hour clock (QEAA); CIR 2024/2977 Art 5(3)-(4) reason and trigger (PID) |
| M5 | Every status change of issuer keys, certificates or other cryptographic material, with precise UTC time | CIR 2025/2160 Art 4(3)(b), 3rd indent; EN 319 401 REQ-7.10-05/-06 |
| M6 | (PID providers) the WIA and KA status references received at issuance, retained for the PID's validity, plus each 24-hour re-check and its result | CIR 2024/2979 Annex Ib LC_GEN-4; ARF WURevocation_18 / WUA_29 / WURevocation_11 |
| M7 | Privileged and administrator actions, configuration changes, and log start/stop | CIR 2024/2690 Annex 3.2.3(e), (f), (k) (all TSPs); EN 319 401 REQ-7.4-12X |
| M8 | Integrity protection, access control limited to authorised roles, backups, and a stated retention period | CIR 2025/2160 Art 4(7); CIR 2024/2690 Annex 3.2.5; eIDAS Art 24(2)(f)-(g) (QEAA); EN 319 401 REQ-7.10-02/-08 (QEAA/PuB) |
| M9 | A documented retention period and handover-on-termination list | TS 119 471 REQ-EAASP-7.10-08 (QEAA/PuB); EN 319 401 REQ-6.2-02(e) (non-qualified EAA via 2160 Annex); GDPR Art 30(1)(f); CIR 2025/2530 Art 3(1), 3(8) (QTSP) |
| M10 | The subscriber terms-acceptance record | TS 119 471 REQ-EAASP-6.2.4-03 (QEAA/PuB) |

**SHOULD** (supported by the texts, not required):

| # | Line | Basis |
|---|---|---|
| S1 | Hash-chain the entries, sign or seal the chain head periodically, and keep 2-3 independent copies | Implements EN 319 401 REQ-7.10-08 and its example; eIDAS Art 24(2)(f)(iii) "checked for authenticity"; CIR 2024/2690 Annex 3.2.5 |
| S2 | Synchronise the log clock to UTC at least daily, and record clock-sync events | EN 319 401 REQ-7.10-05/-06; CIR 2024/2690 Annex 3.2.6 |
| S3 | Keep payloads separately deletable or crypto-shreddable, with the chain committing to their hashes, so expiry under GDPR Art 5(1)(e) does not break the chain | GDPR Art 5(1)(e), 17, 25(2); eIDAS Art 24(2)(f)(ii) (authorised changes) |
| S4 | Provide an export or evidence bundle for legal proceedings and supervisors | EN 319 401 REQ-7.10-04; CIR 2025/2530 Art 3(8)(a) |
| S5 | Monitor the logging system independently of the systems it logs | CIR 2024/2690 Annex 3.2.6 |

**MUST NOT:**

| # | Line | Basis |
|---|---|---|
| N1 | Any post-issuance usage or presentation data, or relying-party identities tied to a holder | eIDAS Art 5a(16)(a), 5a(5)(b); TS 119 471 REQ-EAASP-7.13-05/-08 (binding on QEAA/PuB) |
| N2 | Status-list or revocation-check requests tied to requester IP or identity and to the list/index | CIR 2025/1569 Art 4(4) (QEAA/PuB); ARF VCR_16/VCR_18 |
| N3 | Credential unique values beyond need: salts, disclosure digests, signature value, device public key, credential timestamps, and the revocation index after the credential can no longer be revoked. Never ship these to third parties | ARF ISSU_35/ISSU_35b (non-binding); GDPR Art 5(1)(c) |
| N4 | Attribute values or PID data, unless required as issuance evidence and then kept minimised and in the separate store | GDPR Art 5(1)(c), 25(2); TS 119 471 REQ-EAASP-7.13-04/-08 |
| N5 | Combined data from the issuer's other services | eIDAS Art 45h(1) |
| N6 | Personal data kept indefinitely "because the log is immutable" | GDPR Art 5(1)(e); CIR 2015/1502 2.4.4(2) ("securely destroyed") |
| N7 | Any marketing claim that the log is a "qualified electronic ledger" or required by eIDAS | eIDAS Art 3(53), 45l |

---

## 5. Not verified

1. **National retention periods.** No EU text sets years. Member-State QTSP or eID laws (e.g. 10-30 year rules in some States) were not read.
2. **Whether Art 19a and CIR 2025/2160 apply to public-sector PuB-EAA bodies.** This depends on the "normally provided for remuneration" qualifier in Art 3(16) and has not been tested in case law or guidance.
3. **Whether a per-attestation revocation is "a change of the status of… other cryptographic material"** under CIR 2025/2160 Art 4(3)(b). This is an interpretation.
4. **CIR 2015/1502**: read in its 2015 OJ form; later amendments not checked. Its application to PID providers is through the LoA-high eID scheme (eIDAS Art 5a(11); CIR 2024/2977 Art 3(7)). This link is a reading, not an explicit statement.
5. **The meaning of "revoked person identification data shall remain accessible"** (CIR 2024/2977 Art 5(6)): status only, or the data itself.
6. **The ARF's legal weight.** Treated as non-binding apart from CIR-copied text. Whether national certification schemes or conformity assessment bodies treat ISSU_35b as mandatory was not checked.
7. **ETSI TS 119 472-1 V1.2.1 and EN 319 401 V3.2.1** were not read clause by clause. Only the clauses quoted above were checked (7.9.1-14, 7.10, 6.2-02).
8. **Supervisory-body access powers** (eIDAS Art 46b) and CAB audit scope (Art 20) beyond the sentences quoted.
9. **EDPB or national DPA guidance** on immutable logs, blockchain and erasure was not consulted.
10. **Consolidated eIDAS text.** The 18.10.2024 consolidation was the one available. Any later corrigendum or amendment after the C1 corrigendum (9.4.2025) was not checked.
