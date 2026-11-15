"""Build the failure ledger: every probe result of every run, with evidence hash, root cause and binder rows.

Usage: python -m eudi_probe.ledger RUNS_DIR BINDER_CSV OUT_DIR

RUNS_DIR holds one folder per issuer run with results.json and optionally rootcause.json /
rootcause-PRIVATE.json (written by the runner). Sensitive checks only ever go to the PRIVATE outputs.
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def evidence_hash(evidence: list[str]) -> str:
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class Row:
    run: str
    issuer: str
    check_id: str
    status: str
    sensitive: bool
    source: str
    title: str
    detail: str
    evidence_sha256: str
    hash_verified: str
    observed: str
    expected: str
    root_cause: str
    binder_ids: str


def load_rootcauses(run_dir: Path) -> dict[str, dict[str, Any]]:
    causes: dict[str, dict[str, Any]] = {}
    for name in ("rootcause.json", "rootcause-PRIVATE.json"):
        path = run_dir / name
        if path.exists():
            for entry in json.loads(path.read_text()):
                causes[str(entry.get("check_id"))] = entry
    return causes


def load_binder(path: Path) -> dict[str, list[str]]:
    by_check: dict[str, list[str]] = defaultdict(list)
    if not path.exists():
        return by_check
    with path.open(newline="") as handle:
        for record in csv.DictReader(handle):
            for check_id in (record.get("probe_checks") or "").split(";"):
                if check_id.strip():
                    by_check[check_id.strip()].append(record["binder_id"])
    return by_check


def build(runs_dir: Path, binder_csv: Path) -> tuple[list[Row], list[str]]:
    binder = load_binder(binder_csv)
    rows: list[Row] = []
    manifest: list[str] = []
    for results_path in sorted(runs_dir.glob("*/results.json")):
        run_dir = results_path.parent
        data = json.loads(results_path.read_text())
        manifest.append(f"{run_dir.name}/results.json sha256={file_hash(results_path)}")
        causes = load_rootcauses(run_dir)
        # Runners may write a root cause against a variant run kept in a subfolder.
        variants: dict[tuple[str, str], str] = {}
        for variant_path in sorted(run_dir.glob("*/results.json")):
            manifest.append(f"{run_dir.name}/{variant_path.parent.name}/results.json sha256={file_hash(variant_path)}")
            for item in json.loads(variant_path.read_text())["results"]:
                variants[(item["id"], evidence_hash(item.get("evidence") or []))] = variant_path.parent.name
        for result in data["results"]:
            digest = evidence_hash(result.get("evidence") or [])
            cause = causes.get(result["id"], {})
            claimed = cause.get("evidence_sha256")
            if not claimed:
                verified = "n/a"
            elif claimed == digest:
                verified = "yes"
            elif (result["id"], claimed) in variants:
                verified = f"yes ({variants[(result['id'], claimed)]})"
            else:
                verified = "MISMATCH"
            rows.append(
                Row(
                    run=run_dir.name,
                    issuer=data.get("name", run_dir.name),
                    check_id=result["id"],
                    status=result["status"],
                    sensitive=bool(result.get("sensitive")),
                    source=result.get("source", ""),
                    title=result.get("title", ""),
                    detail=result.get("detail", ""),
                    evidence_sha256=digest,
                    hash_verified=verified,
                    observed=str(cause.get("observed", "")),
                    expected=str(cause.get("expected", "")),
                    root_cause=str(cause.get("root_cause", "")),
                    binder_ids=";".join(binder.get(result["id"], [])),
                )
            )
    return rows, manifest


def cell(value: str, limit: int = 220) -> str:
    value = value.replace("|", "\\|").replace("\n", " ")
    return value if len(value) <= limit else value[: limit - 3] + "..."


def write_outputs(rows: list[Row], manifest: list[str], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for private in (False, True):
        subset = [r for r in rows if r.sensitive == private]
        suffix = "-PRIVATE" if private else ""
        with (out_dir / f"LEDGER{suffix}.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(Row.__dataclass_fields__.keys())
            for r in subset:
                writer.writerow([getattr(r, f) for f in Row.__dataclass_fields__])
        issuers = sorted({r.issuer for r in subset})
        checks = sorted({(r.check_id, r.title, r.source) for r in subset})
        grid = {(r.check_id, r.issuer): r.status for r in subset}
        lines = [f"# Failure ledger{' (PRIVATE: security checks)' if private else ''}", "", "## Runs", ""]
        lines += [f"- {m}" for m in manifest]
        lines += ["", "## Matrix", "", "| check | source | " + " | ".join(issuers) + " |"]
        lines.append("|---|---|" + "---|" * len(issuers))
        for check_id, title, source in checks:
            marks = [grid.get((check_id, issuer), "") for issuer in issuers]
            lines.append(f"| {check_id} {cell(title, 70)} | {cell(source, 60)} | " + " | ".join(marks) + " |")
        lines += ["", "## Failures and why", ""]
        lines.append("| issuer | check | status | observed | root cause | binder rows | evidence sha256 | hash ok |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for r in subset:
            if r.status in ("FAIL", "WARN", "ERROR"):
                lines.append(
                    f"| {r.issuer} | {r.check_id} | {r.status} | {cell(r.observed or r.detail)} | "
                    f"{cell(r.root_cause) or 'TODO'} | {cell(r.binder_ids, 80)} | "
                    f"`{r.evidence_sha256[:16]}` | {r.hash_verified} |"
                )
        (out_dir / f"LEDGER{suffix}.md").write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    rows, manifest = build(Path(args[0]), Path(args[1]))
    write_outputs(rows, manifest, Path(args[2]))
    print(f"{len(rows)} results, {len(manifest)} result files", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
