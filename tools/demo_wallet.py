"""A scripted wallet for a local demo run: take a pre-authorized credential offer, as the demo page's QR code holds
it, and collect every credential it offers, the way a wallet does (OpenID4VCI 1.0 with DPoP and key proofs), then
report each as stored. For checking the demo without a phone; not a wallet anyone should keep credentials in.

Usage: python tools/demo_wallet.py OFFER_LINK --ka-ca CERT KEY [--tx-code CODE] [--until token|issue|notify]
                                   [--ca-file PEM | --insecure]
OFFER_LINK is the openid-credential-offer:// link (the page's "Open in a wallet" button). --ka-ca names a wallet
provider CA the issuer trusts, under which this wallet attests its keys (dev/wallet-providers.pem and
dev/wallet-provider.key from tools/dev_pki.py). Each step is printed as it happens.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "probe"))

from eudi_probe.jose import EcKey  # noqa: E402 - the probe of this checkout
from eudi_probe.wallet import AttestationIssuer, dpop_proof, key_proof  # noqa: E402

PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


def well_known(issuer: str, suffix: str) -> str:
    parts = urlsplit(issuer)
    return f"{parts.scheme}://{parts.netloc}/.well-known/{suffix}{parts.path}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("offer_link")
    parser.add_argument("--ka-ca", nargs=2, metavar=("CERT", "KEY"), type=Path, required=True)
    parser.add_argument("--tx-code")
    parser.add_argument("--until", choices=("token", "issue", "notify"), default="notify")
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument("--ca-file", type=Path, help="the CA of the issuer's TLS certificate")
    trust.add_argument("--insecure", action="store_true", help="do not check the issuer's TLS certificate")
    args = parser.parse_args()

    verify: Any = False if args.insecure else (str(args.ca_file) if args.ca_file else True)
    query = parse_qs(urlsplit(args.offer_link).query)
    if "credential_offer_uri" in query:  # by reference, as the demo page's links are: fetch it first
        offer: dict[str, Any] = httpx.get(query["credential_offer_uri"][0], verify=verify, timeout=10).json()
    else:
        offer = json.loads(query["credential_offer"][0])
    issuer = offer["credential_issuer"]
    attester = AttestationIssuer.from_ca_files(*args.ka_ca)
    dpop_key = EcKey.generate()
    with httpx.Client(verify=verify, timeout=10) as client:
        metadata = client.get(well_known(issuer, "openid-credential-issuer")).json()
        servers = metadata.get("authorization_servers") or [issuer]
        token_endpoint = client.get(well_known(servers[0], "oauth-authorization-server")).json()["token_endpoint"]
        grant = offer["grants"][PRE_AUTH]
        form = {"grant_type": PRE_AUTH, "pre-authorized_code": grant["pre-authorized_code"]}
        if args.tx_code:
            form["tx_code"] = args.tx_code
        answer = client.post(token_endpoint, data=form, headers={"DPoP": dpop_proof(dpop_key, "POST", token_endpoint)})
        if answer.status_code != 200:
            print(f"token refused: {answer.status_code} {answer.text}")
            return 1
        token = answer.json()["access_token"]
        print("token: got one, bound to this wallet's DPoP key")
        if args.until == "token":
            return 0

        def authorized(url: str) -> dict[str, str]:
            proof = dpop_proof(dpop_key, "POST", url, access_token=token)
            return {"Authorization": f"DPoP {token}", "DPoP": proof}

        notices = []
        for config_id in offer["credential_configuration_ids"]:
            nonce = client.post(metadata["nonce_endpoint"]).json()["c_nonce"]
            holder = EcKey.generate()
            attestation = attester.key_attestation([holder], nonce=None)
            proof = key_proof(holder, issuer, nonce=nonce, key_attestation=attestation)
            body = {"credential_configuration_id": config_id, "proofs": {"jwt": [proof]}}
            endpoint = metadata["credential_endpoint"]
            answer = client.post(endpoint, json=body, headers=authorized(endpoint))
            if answer.status_code not in (200, 202):
                print(f"{config_id}: refused: {answer.status_code} {answer.text}")
                return 1
            if answer.status_code == 202:
                print(f"{config_id}: held for review, transaction {answer.json()['transaction_id'][:8]}...")
                continue
            print(f"{config_id}: issued ({len(answer.json()['credentials'])} credential)")
            notices.append(answer.json()["notification_id"])
        if args.until == "issue":
            return 0
        endpoint = metadata["notification_endpoint"]
        for notice in notices:
            body = {"notification_id": notice, "event": "credential_accepted"}
            answer = client.post(endpoint, json=body, headers=authorized(endpoint))
            print(f"notification: {answer.status_code}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
