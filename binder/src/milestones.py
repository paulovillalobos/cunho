"""Assign every software rule id to the milestone that implements it, and build the code registry.

Usage: python binder/src/milestones.py [OUT_DIR]   (run from the repo root)
Writes binder/MILESTONES.csv and src/cunho/rules/registry.json, or both files into OUT_DIR.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

M2 = {
    # oauth: pre-authorized flow, DPoP, nonce
    "DPOP.ALG_ASYMMETRIC", "DPOP.ATH", "DPOP.AUTH_SCHEME", "DPOP.HTM", "DPOP.HTU", "DPOP.IAT_WINDOW",
    "DPOP.JTI_PRESENT", "DPOP.JTI_REPLAY", "DPOP.KEY_BOUND_TO_TOKEN", "DPOP.NO_BEARER_DOWNGRADE",
    "DPOP.NO_PRIVATE_KEY", "DPOP.SERVER_NONCE", "DPOP.SIGNATURE", "DPOP.TOKEN_TYPE", "DPOP.TYP",
    "OAUTH.DPOP_REQUIRED", "OAUTH.RESOURCE_401_CHALLENGE", "OAUTH.TOKEN_ERROR_BODY",
    "VCI.NONCE.C_NONCE_VALID", "VCI.NONCE.ENDPOINT", "VCI.NONCE.NO_STORE", "VCI.OFFER.SHAPE",
    "VCI.TOKEN.INVALID_GRANT", "VCI.TOKEN.PREAUTH_REQUEST", "VCI.TOKEN.PREAUTH_SINGLE_USE",
    "VCI.TOKEN.TX_CODE_ERRORS",
    # proofs
    "BIND.DEVICE_BOUND", "KA.ATTESTATION_PROOF_NONCE", "KA.BIND_TO_ATTESTED_KEY", "KA.CHAIN_TO_WP_LIST",
    "KA.JWT_PROOF_ATTESTED_KEY0", "KA.PID_KEY_IN_WSCD", "KA.POP_ALL_KEYS", "KA.STATUS_EXP_NOT_TOKEN_EXP",
    "KA.VERIFY", "VCI.F1.PROOF_ALG_ASYMMETRIC", "VCI.F1.PROOF_AUD", "VCI.F1.PROOF_IAT",
    "VCI.F1.PROOF_ISS_ANON_PREAUTH", "VCI.F1.PROOF_TYP", "VCI.F4.PROOF_SIGNATURE",
    # issuance
    "BATCH.METHOD_INVISIBLE", "BATCH.SUPPORT", "BATCH.UNIFORM", "HTTP.METHOD_NOT_ALLOWED",
    "VCI.CRED.ERROR_CODES", "VCI.CRED.IDENTIFIER_XOR", "VCI.CRED.PROOFS_SHAPE", "VCI.CRED.RESPONSE_SHAPE",
    "VCI.PROFILE.OID4VCI_HAIP",
    # metadata
    "META.KEY_STORAGE_LEVELS", "META.NO_KA_FOR_UNBOUND", "META.PREFERRED_STATUS_PERIODS",
    "META.PROOF_TYPES_JWT_AND_ATTESTATION", "META.REUSE_POLICY.METHOD_A_PARAMS",
    "META.REUSE_POLICY.PRESENT_ORDERED", "META.REUSE_POLICY.REISSUE_TRIGGER_UNUSED", "OAUTH.AS_METADATA",
    "VCI.META.FIELDS", "VCI.META.NONCE_ENDPOINT_WHEN_BINDING", "VCI.META.SCOPE_PER_CONFIG",
    "VCI.META.WELL_KNOWN_PATH",
    # status
    "STATUS.LIST_SIGNER_AUTHENTICATED", "STATUS.MONOTONIC", "STATUS.NO_SUSPENSION", "STATUS.REFERENCE_PUBLIC",
    "STATUS.RETAINED_BEYOND_VALIDITY", "STATUS.SDJWT_TSL", "STATUS.TSL.ENCODING",
    "STATUS.TSL.FRESH_ENTRY_PER_CREDENTIAL", "STATUS.TSL.MEDIA_TYPE", "STATUS.TSL.NO_DOUBLE_ALLOCATION",
    "STATUS.TSL.REFERENCE", "STATUS.TSL.TOKEN_CLAIMS",
    # audit, signer, privacy, subject
    "LOG.DISCARD_UNIQUE_VALUES", "CRYPTO.ALG_ALLOWLIST_ACM", "CRYPTO.ES256_384_512",
    "PRIV.NO_KA_IDX_AS_WALLET_ID", "PRIV.STATUS_IDX_RANDOM", "PRIV.STATUS_LIST_HERD_SIZE",
    "PRIV.STATUS_LIST_UNAUTHENTICATED", "PRIV.TIMESTAMP_COARSENING", "PRIV.UNIQUE_ELEMENTS_CSPRNG",
    "PRIV.UNLINKABILITY_BATCH", "ISS.SUBJECT.ENTITLEMENT", "ISS.NO_WALLET_DISCRIMINATION",
    # credentials: SD-JWT VC and the PID in SD-JWT VC
    "EAA.RULEBOOK.CONFORMANCE", "FMT.SDJWT.CONFIG_AND_ENCODING", "FMT.SDJWT.EXP_OR_STATUS",
    "FMT.SDJWT.NEVER_SD_CLAIMS", "FMT.SDJWT.TYP", "FMT.SDJWT.VCT_REQUIRED", "FMT.SDJWT.X5C_NO_ANCHOR",
    "FMT.VALIDATION_INFO_EMBEDDED", "FMT.VALIDITY_PERIOD", "MDOC.NO_SERVER_RETRIEVAL",
    "PID.ATTRS.OPTIONAL_SCHEMA", "PID.PORTRAIT.OPTOUT_EMPTY", "PID.RULEBOOK.CONFORMANCE",
    "PID.SD.PER_DATA_IDENTIFIER", "PID.SDJWT.CLAIM_MAPPING", "PID.SDJWT.NBF_EXP",
    "PID.SDJWT.PICTURE_DATA_URL_JPEG", "PID.SDJWT.PLACE_OF_BIRTH_NONEMPTY", "PID.SDJWT.RECURSIVE_SD",
    "PID.SDJWT.UTF8", "PID.SDJWT.VCT", "PID.SDJWT.X5U_X5TS256", "PID.VALUES.ISSUING_COUNTRY_ALPHA2",
    "PID.VALUES.ISSUING_JURISDICTION_PREFIX", "PID.VALUES.NATIONALITY_QU_QS",
    "PID.VALUES.VALID_AT_VALIDITY_START", "VALIDITY.PID_LE_STATUS_EXP",
}

M3 = {
    "OAUTH.AUTH_CODE_AND_PAR", "OAUTH.PKCE_S256", "META.SIGNED_X5C_ACCESS_CERT", "META.REGCERT_BY_VALUE",
    "META.EDP_BY_VALUE", "META.REUSE_POLICY.CONFORMANCE_472_3", "TRUST.LOTE_PARSER_119602",
    "WIA.CHAIN_TO_WP_LIST", "WIA.NOT_EXPIRED", "WIA.POP_CNF", "WIA.SIGNATURE_X5C", "WIA.STATUS_EXP_NOT_TOKEN_EXP",
    "WIA.VERIFY", "BATCH.REISSUANCE", "FMT.ETSI_119472_1",
    "META.REUSE_POLICY.A_OR_B", "META.REUSE_POLICY.METHOD_B_TRIGGER", "META.REUSE_POLICY.METHOD_C_PARAMS",
    "TRUST.WP_ANCHORS_FROM_LIST",
    # Owner decisions of 2026-11-05: refresh tokens come in M3, and so does the refresh-token binding (decision
    # 11); the status of the WIA and of the KA is checked at issuance in M3 (decision 3).
    "BATCH.REISSUE_SAME_WALLET_UNIT", "KA.STATUS_AT_ISSUANCE",
    # The rows M3 adds to the binder (binder/src/rows_spec.py, M3_ROWS; decision 13)
    "OAUTH.PAR_REQUIRED", "OAUTH.PAR_REQUEST", "OAUTH.PAR_REQUEST_URI_ONCE", "OAUTH.PKCE_VERIFIER",
    "OAUTH.CODE_ONCE_60S", "OAUTH.CODE_DPOP_BOUND", "OAUTH.REDIRECT_URI_EXACT", "OAUTH.AUTHZ_RESPONSE_ISS",
    "OAUTH.RESPONSE_TYPE_CODE", "OAUTH.REDIRECT_303", "OAUTH.NO_TOKEN_IN_QUERY", "OAUTH.ACCESS_DENIED",
    "OAUTH.REFRESH_BOUND", "OAUTH.AS_METADATA_M3", "WIA.REQUIRED_AT_PAR_AND_TOKEN", "WIA.CLIENT_ID_IS_SUB",
    "WIA.POP_FRESH", "WIA.CNF_PUBLIC", "WIA.CLIENT_STATUS", "VCI.AUTHZ_DETAILS", "VCI.SCOPE_TO_CONFIG",
    "VCI.ISSUER_STATE", "VCI.OFFER.AUTH_CODE_GRANT", "VCI.META.SIGNED_FORMAT", "META.PREFERRED_CLIENT_STATUS_PERIOD",
    "TRUST.LOTE_AUTHENTIC", "TRUST.REVOCATION_FETCHED", "ISS.IDPROOF.PLUG_REQUIRED",
}

# Why a rule sits where it does when it is not obvious from its component.
NOTES = {
    "META.REUSE_POLICY.A_OR_B": "needs the ETSI TS 119 472-3 encoding of reuse methods B and C; M2 checks method A only",
    "META.REUSE_POLICY.METHOD_B_TRIGGER": "needs the ETSI TS 119 472-3 encoding of method B",
    "META.REUSE_POLICY.METHOD_C_PARAMS": "needs the ETSI TS 119 472-3 encoding of method C",
    "TRUST.WP_ANCHORS_FROM_LIST": "M2 trusted a configured PEM file; M3 reads the Commission LoTE (ETSI TS 119 602) "
    "and production requires it, the PEM file staying for development",
    "VALIDITY.EAA_LE_STATUS_EXP": "applies to an attestation provider that chains revocation (chain_attestations, "
    "ARF VCR_07d); a PID provider always does",
    "KA.STATUS_AT_ISSUANCE": "checked at issuance from M3, with WIA.CLIENT_STATUS (owner decision 3), and again at "
    "least every day while a credential lives, by revocation chaining (M4)",
    "WIA.CLIENT_STATUS": "checked at issuance (M3), and again at least every day while a credential lives, by "
    "revocation chaining (M4)",
}

FUTURE = {"VCI.DCAPI.ISSUANCE", "PID.LPID.MANDATORY", "ISS.ACP.SUBJECT_MATCH"}

# Rules whose condition cunho never meets, with the reason. They have no milestone and need no code.
NOT_APPLICABLE = {
    "STATUS.MDOC_ID_UNIQUE_PER_MSO": "the identifier of an identifier list is never issued: cunho gives every mdoc "
    "a Token Status List entry, one of the two mechanisms the law allows (EAA-6.2.10.1-02), and that entry is unique "
    "per MSO (STATUS.MDOC_BITS1_UNIQUE_IDX)",
}

# Rules M2 implements only in part: the part that is missing, and the milestone that adds it (review 3, N3-L6).
# The registry marks them "partial", so an M2 rule count never reads as complete coverage.
PARTIAL = {
    "FMT.ETSI_119472_1": "clauses 5 (SD-JWT VC) and 6 (ISO/IEC mdoc) hold for every credential cunho issues, "
    "vct#integrity from the operator's Type Metadata included, but for one point of the CB-AdES signature of EAA-6.6.1-01 "
    "that ISO/IEC 18013-5 §9.1.2.4 contradicts: x5chain is a bare unprotected header, where mdoc verifiers read it, "
    "not inside the uHeaders array of ETSI TS 119 152-1 §4.4",
    "META.EDP_BY_VALUE": "no embedded disclosure policy is published: none is configured, and no metadata member for "
    "one is standardised yet (ETSI TS 119 472-3 V1.1.1 §4.2.5 gives its data model only); cunho carries one by value "
    "once a member is named",
}


def milestone_for(rule_id: str, component: str, binds: str) -> str:
    ids = set(rule_id.split(";"))
    if component in ("operator", "context") or not binds.startswith("SOFTWARE"):
        return "operator" if component != "context" else "context"
    if ids & M2:
        return "M2"
    if ids & M3:
        return "M3"
    if ids & FUTURE:
        return "future"
    if ids <= set(NOT_APPLICABLE):
        return "not applicable"
    return "M4"


def main(out_dir: Path | None = None) -> None:
    binder = {r["binder_id"]: r for r in csv.DictReader((ROOT / "binder/BINDER.csv").open(newline=""))}
    strength = {r["binder_id"]: r for r in csv.DictReader((ROOT / "binder/BINDER-STRENGTH.csv").open(newline=""))}
    placement = list(csv.DictReader((ROOT / "binder/BINDER-PLACEMENT.csv").open(newline="")))
    registry: dict[str, dict[str, object]] = {}
    milestones_path = (out_dir or ROOT / "binder") / "MILESTONES.csv"
    with milestones_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["binder_id", "our_rule_id", "component", "strength", "binds", "milestone"])
        for row in placement:
            milestone = milestone_for(row["our_rule_id"], row["component"], row["binds"])
            writer.writerow([row["binder_id"], row["our_rule_id"], row["component"], row["strength"], row["binds"],
                             milestone])
            for rule_id in row["our_rule_id"].split(";"):
                own = milestone_for(rule_id, row["component"], row["binds"])
                entry = registry.setdefault(rule_id, {
                    "component": row["component"], "milestone": own, "strengths": [], "sources": []})
                if rule_id in NOTES:
                    entry["note"] = NOTES[rule_id]
                if rule_id in PARTIAL:
                    entry["partial"] = PARTIAL[rule_id]
                if rule_id in NOT_APPLICABLE:
                    entry["not_applicable"] = NOT_APPLICABLE[rule_id]
                entry["strengths"].append(row["strength"])  # type: ignore[union-attr]
                entry["sources"].append({  # type: ignore[union-attr]
                    "binder_id": row["binder_id"],
                    "source": binder[row["binder_id"]]["source_ref"],
                    "strength": row["strength"],
                    "binds": row["binds"],
                    "quote": strength[row["binder_id"]]["quote"],
                })
    missing = sorted((M2 | M3) - set(registry))
    if missing:
        raise SystemExit(f"milestone ids not in binder: {missing}")
    moved = sorted(rule for rule in M3 if registry[rule]["milestone"] != "M3")
    if moved:
        raise SystemExit(f"M3 ids that land elsewhere (operator or context rows only, or also in M2): {moved}")
    out = (out_dir or ROOT / "src/cunho/rules") / "registry.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(sorted(registry.items())), indent=1, ensure_ascii=False) + "\n")
    counts: dict[str, int] = {}
    for entry in registry.values():
        counts[str(entry["milestone"])] = counts.get(str(entry["milestone"]), 0) + 1
    print(len(registry), "rule ids", counts)


if __name__ == "__main__":
    import sys

    main(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
