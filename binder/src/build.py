import csv
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from rows_arf import ROWS as ARF_ROWS  # noqa: E402
from rows_eidas import E  # noqa: E402
from rows_spec import M3_ROWS, M4_ROWS, S_ROWS  # noqa: E402

OUT = Path(sys.argv[1])
CHECKS = Path(sys.argv[2]).read_text()
PROBE_IDS = re.findall(r'@check\(\s*"([A-Z]\d\d)"', CHECKS)
PROBE_TITLES = dict(re.findall(r'@check\(\s*"([A-Z]\d\d)",\s*"[a-z]+",\s*"[^"]*",\s*"([^"]*)"', CHECKS))

ACTS = [
    (1, 39, "Reg. (EU) No 910/2014 as amended by Reg. (EU) 2024/1183"),
    (40, 59, "CIR (EU) 2024/2977 as amended by CIR (EU) 2026/1731"),
    (60, 79, "CIR (EU) 2024/2977 Annex as replaced by CIR (EU) 2026/1731 Annex I"),
    (80, 96, "CIR (EU) 2024/2979 Annex Ib (inserted by CIR (EU) 2026/1731 Annex III)"),
    (97, 108, "CIR (EU) 2024/2979 Annex II (CIR (EU) 2026/1731 Annex IV; = ETSI TS 119 472-1 V1.2.1)"),
    (109, 115, "CIR (EU) 2024/2982 (Annexes I-II inserted by CIR (EU) 2026/1731 Annexes XI-XII)"),
    (116, 118, "CIR (EU) 2024/2980 as amended by CIR (EU) 2026/1731 Annex X"),
    (119, 124, "CIR (EU) 2025/848 as amended by CIR (EU) 2026/1730"),
    (125, 138, "CIR (EU) 2025/1569 as amended by CIR (EU) 2026/1735"),
    (139, 147, "identity-verification, risk and QTSP acts"),
]


def act(n):
    return next(a for lo, hi, a in ACTS if lo <= n <= hi)


COLS = ["binder_id", "layer", "source_ref", "binds", "testability", "probe_checks", "new_check_needed",
        "our_rule_id", "depends_on", "notes"]
rows = []
for r in ARF_ROWS:
    bid, layer, src, binds, test, probes, new, rule, deps, topic, notes = r
    rows.append(dict(zip(COLS, [bid, layer, src, binds, test, probes, new, rule, deps, notes]), topic=topic))
for r in E:
    n, bid, src, binds, test, probes, new, rule, deps, topic, notes = r
    rows.append(dict(zip(COLS, [bid, "law", f"{src}; {act(n)}; eidas-issuer-obligations.md row {n}", binds, test,
                                probes, new, rule, deps, notes]), topic=topic))
for r in S_ROWS:
    bid, src, binds, test, probes, new, rule, deps, topic, notes = r
    rows.append(dict(zip(COLS, [bid, "spec", src + "; CHECKLIST.md", binds, test, probes, new, rule, deps, notes]),
                     topic=topic))
for r in M3_ROWS + M4_ROWS:
    bid, layer, src, binds, test, probes, new, rule, deps, topic, notes = r
    rows.append(dict(zip(COLS, [bid, layer, src, binds, test, probes, new, rule, deps, notes]), topic=topic))

# ---------------------------------------------------------------- validation
ids = [r["binder_id"] for r in rows]
dup = [i for i, c in Counter(ids).items() if c > 1]
assert not dup, dup
idset = set(ids)
errors = []
for r in rows:
    assert r["testability"] in {"blackbox", "unit", "fixture", "organisational"}, r
    assert r["layer"] in {"law", "arf", "ts", "rulebook", "spec"}, r
    for d in filter(None, r["depends_on"].split(";")):
        if d not in idset:
            errors.append(f"{r['binder_id']}: depends_on {d} missing")
    for p in filter(None, r["probe_checks"].split(";")):
        if p not in PROBE_IDS:
            errors.append(f"{r['binder_id']}: unknown probe {p}")
    if r["testability"] == "blackbox" and not (r["probe_checks"] or r["new_check_needed"]):
        errors.append(f"{r['binder_id']}: blackbox without probe or new check")
    if r["testability"] != "blackbox" and r["new_check_needed"]:
        errors.append(f"{r['binder_id']}: new check on non-blackbox row")
assert not errors, "\n".join(errors)
assert len(E) == 147 and [e[0] for e in E] == list(range(1, 148))
used = {p for r in rows for p in r["probe_checks"].split(";") if p}
unused = [p for p in PROBE_IDS if p not in used]

# ---------------------------------------------------------------- CSV
with open(OUT / "BINDER.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)

# ---------------------------------------------------------------- stats
LAYERS = ["law", "arf", "ts", "rulebook", "spec"]
TESTS = ["blackbox", "fixture", "unit", "organisational"]
grid = Counter((r["layer"], r["testability"]) for r in rows)
bb = [r for r in rows if r["testability"] == "blackbox"]
full = [r for r in bb if r["probe_checks"] and not r["new_check_needed"]]
part = [r for r in bb if r["probe_checks"] and r["new_check_needed"]]
newonly = [r for r in bb if not r["probe_checks"] and r["new_check_needed"]]
newc = Counter(n for r in rows for n in r["new_check_needed"].split(";") if n)
newrows = {n: [r["binder_id"] for r in rows if n in r["new_check_needed"].split(";")] for n in newc}
newonly_c = Counter(n for r in newonly for n in r["new_check_needed"].split(";") if n)
rules = {r["our_rule_id"] for r in rows}
rule_count = len({x for r in rows for x in r["our_rule_id"].split(";")})

TOPICS = OrderedDict([
    ("ISS", "Issuance protocol"),
    ("OAUTH", "DPoP / OAuth"),
    ("PROOF", "Proofs + key attestation"),
    ("WIA", "Wallet attestation + trust lists (incl. signer certificates)"),
    ("FMT", "Formats: SD-JWT VC / mdoc (incl. QEAA Annex V content)"),
    ("PID", "PID data model"),
    ("STAT", "Status / revocation + time limits"),
    ("BATCH", "Batch / one-time use"),
    ("META", "Metadata incl. issuer_info / registration certificate / access certificate"),
    ("LOG", "Logging / audit (incl. governance duties)"),
    ("PRIV", "Privacy"),
])
LAYER_ORDER = {l: i for i, l in enumerate(LAYERS)}


def cell(s):
    return s.replace("|", "\\|").replace("\n", " ")


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "n/a"


md = []
md.append("# The binder: EUDI issuer requirements -> tests\n")
md.append(
    "One traceability matrix from every issuer requirement in EU law, the ARF and the protocol specs to the test that "
    "proves it. It is the core spec for our Apache-2.0 EUDI credential issuer (each row proposes an `our_rule_id` for the "
    "rule registry) and the yardstick for grading public issuers (each blackbox row names the probe check that grades it, "
    "or the check we still have to write).\n")
md.append(
    "**Inputs** (all in this folder unless noted): `arf-issuer-requirements.md` (ARF 3.0.0 HLRs @f5789a7, TS3 v1.5.2, "
    "PID Rulebook v1.7), `eidas-issuer-obligations.md` (147 rows from 910/2014 as amended and the implementing acts up to "
    "2026/1731, 2026/1735), `CHECKLIST.md` (OpenID4VCI 1.0, RFC 9449, HAIP 1.0, Token Status List draft-21, SD-JWT VC "
    "draft-23, ISO/IEC 18013-5) and the probe catalogue `~/Downloads/eudi-issuer-pro/probe/eudi_probe/checks.py` "
    f"({len(PROBE_IDS)} checks). Machine-readable copy: `BINDER.csv`.\n")
md.append(
    f"**M3 rows** ({len(M3_ROWS)}, added 2026-11-05): the rules the authorization code flow, wallet attestation, trusted "
    "lists, signed metadata and refresh tokens need and no row above carried, from FAPI 2.0 (which HAIP §4 pulls in), "
    "RFC 9126, 7636, 9207, 9449, 9700, 8414, 5280 and 6960, draft-ietf-oauth-attestation-based-client-auth-07, "
    "OpenID4VCI 1.0, ETSI TS 119 602, ARF 3.0.0 and TS3. Each gives its own layer and source, and its strength and "
    "quote are in `BINDER-STRENGTH.csv`.\n")
md.append(
    f"**M4 rows** ({len(M4_ROWS)}, added 2026-11-09): encrypted credential requests and responses, from OpenID4VCI 1.0 "
    "§8.2, §8.3, §9, §10 and §12.2.4, with their strengths and quotes in `BINDER-STRENGTH.csv`.\n")
md.append("**How to read a row**\n")
md.append(
    "- `layer`: law (eIDAS + implementing acts), arf (ARF HLR), ts (TS3; ETSI TS for the M3 rows), rulebook (PID Rulebook), spec (protocol items "
    "from CHECKLIST.md that no ARF/eIDAS row carries, and most M3 rows).\n"
    "- `testability`: **blackbox** = gradable from outside over HTTP against any issuer (the probe); **fixture** = needs "
    "a controlled environment the public issuer will not give us (a Wallet Provider CA the issuer trusts, a revocable WIA/KA, a "
    "rulebook schema, an opt-out user); **unit** = internal behaviour we prove with unit/integration tests in our own "
    "code; **organisational** = policy, registration or notification duty.\n"
    "- `probe_checks` + `new_check_needed` on the same row = the probe covers part, the new check closes the rest.\n"
    "- Deduplication: where an ARF/TS/rulebook row and a law row require the same thing, both rows stay (different "
    "layers), the narrower one points to the other in `depends_on`, and both carry the same `our_rule_id`. A few rows "
    "carry two rule ids separated by `;` because the source text bundles two checks.\n"
    "- Wallet-side ARF HLRs (arf-issuer-requirements.md §11) are included as `binds = Wallet` rows because the issuer's "
    "output must pass them; their text is paraphrased in the input, so those rows group the IDs exactly as the input does.\n"
    "- Not included: HLRs marked Empty in ARF 3.0.0 (ISSU_04, ISSU_16, ISSU_18a, ISSU_22a/b, ISSU_31, ISSU_32a, ISSU_66, "
    "PID_15, WUA_13-16, WUA_18-21, WUA_23) and the ISSU_67/69/72 cross-reference line in ARF §8 (already rows).\n")

md.append("## Counts\n")
md.append(f"**{len(rows)} rows**, {rule_count} distinct proposed rule ids, {len(newc)} new probe checks proposed.\n")
md.append("| layer | " + " | ".join(TESTS) + " | total |")
md.append("|---|" + "---|" * (len(TESTS) + 1))
for l in LAYERS:
    vals = [grid[(l, t)] for t in TESTS]
    md.append(f"| {l} | " + " | ".join(map(str, vals)) + f" | {sum(vals)} |")
tot = [sum(grid[(l, t)] for l in LAYERS) for t in TESTS]
md.append("| **total** | " + " | ".join(f"**{v}**" for v in tot) + f" | **{len(rows)}** |\n")

md.append("**Probe coverage of the blackbox rows**\n")
md.append("| | rows | share of blackbox |")
md.append("|---|---|---|")
md.append(f"| fully covered by existing probe checks | {len(full)} | {pct(len(full), len(bb))} |")
md.append(f"| partly covered (existing check + new check needed) | {len(part)} | {pct(len(part), len(bb))} |")
md.append(f"| not covered (new check needed) | {len(newonly)} | {pct(len(newonly), len(bb))} |")
md.append(f"| **blackbox total** | **{len(bb)}** | touched by at least one probe check: **{pct(len(full) + len(part), len(bb))}** |\n")
by_layer = []
for l in LAYERS:
    b = [r for r in bb if r["layer"] == l]
    f = [r for r in b if r["probe_checks"] and not r["new_check_needed"]]
    p_ = [r for r in b if r["probe_checks"] and r["new_check_needed"]]
    by_layer.append(f"{l} {len(f)}/{len(p_)}/{len(b) - len(f) - len(p_)}")
md.append("Per layer (fully / partly / not covered): " + "; ".join(by_layer) + ".\n")
md.append(
    "Reading: the current probe is strong where the spec layer is (OpenID4VCI request/response shapes, DPoP, proof "
    "validation, Token Status List) and blind where EU law and the ARF add issuer duties: signed metadata with the access "
    "certificate, the registration certificate in `issuer_info`, the credential reuse policy, WIA/KA trust, the PID data "
    "model, mdoc status, and the privacy properties of timestamps and status indices.\n")
if unused:
    md.append(f"Probe checks not mapped to any row: {', '.join(unused)}.\n")
else:
    md.append(f"Every one of the {len(PROBE_IDS)} probe checks maps to at least one binder row.\n")

md.append("## Inconsistencies carried into the binder\n")
md.append(
    "| Where | Conflict | Binder handling |\n|---|---|---|\n"
    "| SD-JWT VC issuer key header | 2026/1731 PID annex (law row 75): protected header SHALL contain `x5u` and `x5t#S256`. HAIP 1.0 §6.1.1: `x5c` chain without trust anchor (probe C02 FAILs without `x5c`). | Two rows: `EIDAS-2977-Annex§4.2-x5u-x5tS256` (new check `sdjwt_header_x5u_x5tS256`) and `SPEC-HAIP-6.1.1-x5c` (C02). Our issuer emits `x5c` + `x5u` + `x5t#S256`. |\n"
    "| mdoc issuer key header | 2026/1731 PID annex (law row 70): protected header SHALL contain `x5u` and `x5t` (RFC 9360, SHA-256). ISO/IEC 18013-5 / OID4VCI A.2.4 / probe C16: `x5chain` (label 33) in issuerAuth. | Two rows: `EIDAS-2977-Annex§4.1-x5u-x5t` and `SPEC-ISO18013-5-issuerauth-x5chain`. Emit both. |\n"
    "| Trust-list format | ARF ISSU_19b/28a, WPNot_04: LoTE per ETSI TS 119 602. eIDAS input: TS 119 602 is not referenced by any act; law uses the 2024/2980 Commission list (F4). | `TRUST.LOTE_PARSER_119602` and `TRUST.WP_ANCHORS_FROM_LIST` kept separate; loader must accept the Commission-published format. |\n"
    "| WIA/KA status mechanism | ARF VCR_12a: the VCR_01a mechanism. Law row 97: BOTH status list and revocation (identifier) list. | `STATUS.CLIENT_TSL` covers both; law is stricter. |\n"
    "| Selective disclosure scope | ARF PID_21: all claims SD. Law row 72 and SD-JWT VC: except iss/nbf/exp/cnf/vct/status. | `PID.SDJWT.RECURSIVE_SD` bounded by `FMT.SDJWT.NEVER_SD_CLAIMS`. |\n"
    "| Status-period metadata | ARF WUA_32: SHALL communicate status periods. Law rows 93: optional metadata. | Treat as SHALL (`META.PREFERRED_STATUS_PERIODS`). |\n"
    "| Validity claims | HAIP 6.1: `exp` and/or `status`. PID rulebook + law row 73: `nbf` and `exp`. ARF PID_19 'nbf, if present' (F9). | Always emit `nbf` + `exp`; new check `validity_period_present`. |\n"
    "| `key_attestation(s)_required` | TS3 §2.2.2.2 vs TS3 §2.4/OID4VCI spelling (F5). | Use `key_attestations_required`. |\n"
    "| WIA `cnf` vs DPoP key | TS3 v1.5.1 (bundled in ARF repo) requires equality; v1.5.2 rolled it back (F6). | Do not hard-fail; pin v1.5.2. |\n"
    "| `issuer_info` | Absent from ARF/TS/rulebook repos (F7); law row 112 (2982 Annex I, ETSI TS 119 472-3 §4.2.3) names it. | `META.REGCERT_BY_VALUE` uses `issuer_info`. |\n"
    "| Rulebook section numbers | ARF PID_09/PID_18 cite stale §4.2.1/§5.2; v1.7 numbers are §3.1.2/§4.1.1 (F1). | Rulebook rows cite v1.7 numbers. |\n"
    "| Unique values vs revocation store | ISSU_35b (discard) vs WUA_29, WURevocation_11/18, VCR_07a/09 and audit duties (F10). | Retention matrix: minimal revocation store, nothing unique in logs. |\n"
    "| Batch uniformity vs unlinkability | ISSU_43/51 (same validity) vs ISSU_36 (timestamps must not reveal batch) (F11). | Coarsen to a shared bucket, identical within the batch. |\n"
    "| Status List draft | Law row 103 pins draft-ietf-oauth-status-list-20; CHECKLIST and probe grade draft-21. | Noted on the row. |\n")

md.append("## Full table by topic\n")
md.append("Columns: id, layer, source, binds, test (bb = blackbox, fx = fixture, unit, org), probe, new check, rule id, depends on, notes.\n")
ABBR = {"blackbox": "bb", "fixture": "fx", "unit": "unit", "organisational": "org"}
for key, title in TOPICS.items():
    tr = [r for r in rows if r["topic"] == key]
    tr.sort(key=lambda r: (LAYER_ORDER[r["layer"]], r["binder_id"]))
    tb = [r for r in tr if r["testability"] == "blackbox"]
    tf = [r for r in tb if r["probe_checks"] and not r["new_check_needed"]]
    md.append(f"### {title} ({len(tr)} rows; {len(tb)} blackbox, {len(tf)} fully probe-covered)\n")
    md.append("| id | layer | source | binds | test | probe | new check | rule id | depends on | notes |")
    md.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in tr:
        md.append("| " + " | ".join(cell(x) for x in [
            f"`{r['binder_id']}`", r["layer"], r["source_ref"], r["binds"], ABBR[r["testability"]],
            r["probe_checks"].replace(";", " "), r["new_check_needed"].replace(";", " "),
            f"`{r['our_rule_id']}`", r["depends_on"].replace(";", " "), r["notes"]]) + " |")
    md.append("")

md.append("## New probe checks to add, by binder rows closed\n")
md.append(
    "`rows` = binder rows that name the check; `uncovered` = of those, rows the current probe does not touch at all. "
    "Ties are broken by uncovered rows, then name.\n")
md.append("| # | new check | rows | uncovered | binder rows |")
md.append("|---|---|---|---|---|")
order = sorted(newc, key=lambda n: (-newc[n], -newonly_c[n], n))
for i, n in enumerate(order, 1):
    md.append(f"| {i} | `{n}` | {newc[n]} | {newonly_c[n]} | {' '.join(newrows[n])} |")
md.append("")
md.append(
    "Fixture-only checks (not blackbox, so not in this list) worth building into our own integration suite with a test "
    "Wallet Provider CA: WIA expiry/PoP/status (TS3-§2.2.1.2a-c, law rows 81, 83), KA `attested_keys[0]` signature and "
    "WSCD key storage (TS3-§2.2.2.2c, TS3-§2.3.2a, WUA_34, law rows 88-90), revocation chaining every 24 h (WUA_29, "
    "WURevocation_18, TS3-§2.3.1, law rows 55/95), PID validity clamped below `client_status.exp`/`key_storage_status.exp` "
    "(ISSU_12c, WUA_30, TS3-§2.4.3a, law row 94).\n")
(OUT / "BINDER.md").write_text("\n".join(md))

print("rows", len(rows), dict(Counter(r["layer"] for r in rows)))
print("grid", {f"{l}/{t}": grid[(l, t)] for l in LAYERS for t in TESTS})
print("blackbox", len(bb), "full", len(full), "part", len(part), "new-only", len(newonly))
print("rules", rule_count, "new checks", len(newc), "unused probes", unused)
for n in order[:15]:
    print(newc[n], newonly_c[n], n)
