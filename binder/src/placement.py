"""Place every binder row in the cunho component that will enforce it.

Usage: python binder/src/placement.py [OUT_DIR]   (run from the repo root)
Writes binder/BINDER-PLACEMENT.csv, or that file into OUT_DIR, and prints a per-component summary.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Most specific prefix wins.
COMPONENTS = {
    "OAUTH.AS_METADATA": "metadata",
    "OAUTH.AS_METADATA_M3": "metadata",
    "OAUTH.NO_TOKEN_IN_QUERY": "issuance",
    "VCI.META": "metadata",
    "META": "metadata",
    "VCI.OFFER": "oauth",
    "VCI.TOKEN": "oauth",
    "VCI.NONCE": "oauth",
    "VCI.DCAPI": "oauth",
    "VCI.AUTHZ_DETAILS": "oauth",
    "VCI.SCOPE_TO_CONFIG": "oauth",
    "VCI.ISSUER_STATE": "oauth",
    "OAUTH": "oauth",
    "DPOP": "oauth",
    "VCI.F1": "proofs",
    "VCI.F4": "proofs",
    "KA": "proofs",
    "BIND": "proofs",
    "WIA": "trust",
    "TRUST": "trust",
    "TS3": "trust",
    "VCI.CRED": "issuance",
    "VCI.DEFER": "issuance",
    "VCI.ENC": "issuance",
    "VCI.NOTIF": "issuance",
    "VCI.PROFILE": "issuance",
    "VCI.FORMATS": "issuance",
    "BATCH": "issuance",
    "HTTP": "issuance",
    "INTEROP": "issuance",
    "PID": "credentials",
    "EAA": "credentials",
    "QEAA": "credentials",
    "FMT": "credentials",
    "MDOC": "credentials",
    "VALIDITY": "credentials",
    "STATUS": "status",
    "REVOC": "status",
    "LOG": "audit",
    "PRIV": "privacy",
    "CRYPTO": "signer",
    "KEY": "signer",
    "ISS": "subject",
    "ORG": "operator",
    "REG": "operator",
}


def component_for(rule_id: str) -> str:
    parts = rule_id.split(".")
    for depth in range(len(parts), 0, -1):
        prefix = ".".join(parts[:depth])
        if prefix in COMPONENTS:
            return COMPONENTS[prefix]
    raise SystemExit(f"no component for rule id {rule_id!r}")


def main(out_dir: Path | None = None) -> None:
    binder = list(csv.DictReader((ROOT / "binder/BINDER.csv").open(newline="")))
    strength = {r["binder_id"]: r for r in csv.DictReader((ROOT / "binder/BINDER-STRENGTH.csv").open(newline=""))}
    out = (out_dir or ROOT / "binder") / "BINDER-PLACEMENT.csv"
    summary: Counter[tuple[str, str, str]] = Counter()
    with out.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["binder_id", "our_rule_id", "component", "strength", "binds", "condition", "probe_checks"])
        for row in binder:
            s = strength[row["binder_id"]]
            binds = s["binds_software_or_operator"]
            component = "context" if binds.startswith("NONE") else component_for(row["our_rule_id"])
            writer.writerow(
                [row["binder_id"], row["our_rule_id"], component, s["strength"], binds, s["condition"], row["probe_checks"]]
            )
            summary[(component, s["strength"], binds.split(" ")[0])] += 1
    per_component: Counter[str] = Counter()
    for (component, _, _), count in summary.items():
        per_component[component] += count
    for component, count in per_component.most_common():
        detail = ", ".join(f"{st}/{b}={n}" for (c, st, b), n in sorted(summary.items()) if c == component)
        print(f"{component:12} {count:4}  {detail}")


if __name__ == "__main__":
    import sys

    main(Path(sys.argv[1]) if len(sys.argv) > 1 else None)
