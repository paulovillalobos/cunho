"""Release every issuance a local cunho holds for review, as its operator would (eudi-probe --release-cmd).

Usage: python tools/dev_release.py ISSUER_URL ADMIN_TOKEN_FILE
Development only: it releases whatever is held, without looking.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx


def main(argv: list[str]) -> None:
    issuer, token_file = argv[0], Path(argv[1])
    headers = {"Authorization": f"Bearer {token_file.read_text().strip()}"}
    listed = httpx.get(f"{issuer}/admin/deferred", headers=headers, verify=False)
    listed.raise_for_status()
    for row in listed.json()["deferred"]:
        if row["state"] == "held":
            httpx.post(
                f"{issuer}/admin/deferred/{row['ref']}/release", headers=headers, verify=False
            ).raise_for_status()


if __name__ == "__main__":
    main(sys.argv[1:])
