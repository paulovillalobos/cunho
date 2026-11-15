"""Command line: run the check catalogue against one issuer and write the reports."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import traceback
from pathlib import Path

from .attester import WalletProvider
from .checks import ERROR, FAIL, PASS, REGISTRY, SKIP, WARN, Check, Outcome
from .context import Context, ProbeConfig
from .wallet import AttestationIssuer

ORDER = {PASS: 0, WARN: 1, FAIL: 2, ERROR: 3, SKIP: 4}


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="eudi-probe", description=__doc__)
    parser.add_argument("--issuer", required=True, help="Credential Issuer Identifier (https URL)")
    parser.add_argument("--name", required=True, help="label for the report, e.g. ec-python-issuer@73de7df")
    parser.add_argument("--offer", help="one credential offer (openid-credential-offer:// URI or JSON)")
    parser.add_argument("--offer-cmd", help="shell command that prints a fresh offer (or JSON {offer, tx_code})")
    parser.add_argument(
        "--token-cmd",
        help="shell command that prints JSON {access_token, dpop_jwk, dpop_nonce?}; "
        "for issuers without pre-authorized code",
    )
    parser.add_argument("--tx-code", help="transaction code for offers that require one")
    parser.add_argument("--config-id", help="credential configuration to request")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification (local self-signed certs)")
    parser.add_argument(
        "--rewrite",
        action="append",
        default=[],
        metavar="ADVERTISED=REACHABLE",
        help="send requests for an advertised URL prefix to a reachable one",
    )
    parser.add_argument(
        "--ka-ca",
        nargs=2,
        metavar=("CERT_PEM", "KEY_PEM"),
        help="wallet-provider CA trusted by the issuer, used to sign key attestations",
    )
    parser.add_argument(
        "--wia-ca",
        nargs=2,
        metavar=("CERT_PEM", "KEY_PEM"),
        help="wallet-provider CA trusted by the issuer, used to sign wallet attestations (the code flow)",
    )
    parser.add_argument(
        "--wia-signer",
        nargs=2,
        metavar=("CHAIN_PEM", "KEY_PEM"),
        help="a wallet attestation signer the issuer trusts, its chain without the CA (instead of --wia-ca)",
    )
    parser.add_argument(
        "--wia-status",
        nargs=2,
        metavar=("URI", "INDEX"),
        help="the status list entry the wallet attestations name, for an issuer that checks their status",
    )
    parser.add_argument(
        "--ka-status",
        nargs=2,
        metavar=("URI", "INDEX"),
        help="the status list entry the key attestations name, for an issuer that checks their status",
    )
    parser.add_argument("--wia-policy", action="append", default=[], help="certificate policy OID of WIA signers")
    parser.add_argument("--client-id", help="the wallet solution's client_id: the sub of its wallet attestations")
    parser.add_argument("--redirect-uri", help="a redirect URI the issuer allows for --client-id")
    parser.add_argument(
        "--second-client",
        metavar="CLIENT_ID=REDIRECT_URI",
        help="a second wallet solution the issuer allows, for the checks that need two clients",
    )
    parser.add_argument(
        "--login-field",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="a field to fill in the issuer's login forms, as a person would",
    )
    parser.add_argument(
        "--cancel-field", action="append", default=[], metavar="NAME=VALUE", help="the fields that cancel the login"
    )
    parser.add_argument(
        "--login-cmd",
        help="shell command that opens $EUDI_PROBE_AUTHORIZE_URL as a browser would, logs in (cancels when "
        "$EUDI_PROBE_LOGIN_CANCEL is 1) and "
        "prints the URL the browser was finally sent to",
    )
    parser.add_argument(
        "--token-client-id", help="client_id to send on pre-authorized token requests, for servers that require one"
    )
    parser.add_argument("--mdoc-config-id", help="mso_mdoc configuration for the mdoc checks (default: from the offer)")
    parser.add_argument(
        "--deferred-offer-cmd",
        help="shell command that prints an offer the issuer holds for review (deferred issuance)",
    )
    parser.add_argument(
        "--hold-field",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="a login field with which the issuer holds the issuance for review (deferred issuance by the code flow)",
    )
    parser.add_argument(
        "--deferred-wait-max",
        type=float,
        default=60.0,
        help="the longest deferred polling interval to wait out before polling (seconds; default 60)",
    )
    parser.add_argument("--release-cmd", help="shell command with which the operator releases what the issuer holds")
    parser.add_argument("--only", help="comma-separated check ids or groups")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    return parser.parse_args(argv)


def _pair(text: str) -> tuple[str, str]:
    name, sep, value = text.partition("=")
    if not sep:
        raise SystemExit(f"expected NAME=VALUE, got {text!r}")
    return name, value


def selected(only: str | None) -> list[Check]:
    if not only:
        return REGISTRY
    wanted = {item.strip() for item in only.split(",")}
    return [c for c in REGISTRY if c.id in wanted or c.group in wanted]


def run_check(ctx: Context, item: Check) -> Outcome:
    try:
        return item.fn(ctx)
    except Exception as exc:  # noqa: BLE001 - a crashing check must not stop the run
        return Outcome(ERROR, f"probe error: {exc!r}", [traceback.format_exc(limit=3)])


def render(name: str, issuer: str, results: list[tuple[Check, Outcome]], notes: list[str], private: bool) -> str:
    counts = {s: sum(1 for _, o in results if o.status == s) for s in ORDER}
    scored = counts[PASS] + counts[WARN] + counts[FAIL]
    score = (counts[PASS] + 0.5 * counts[WARN]) / scored * 100 if scored else 0.0
    lines = [
        f"# eudi-probe: {name}{' (PRIVATE: security checks)' if private else ''}",
        "",
        f"Issuer: `{issuer}`  ",
        f"Run: {dt.datetime.now(dt.UTC).isoformat(timespec='seconds')}  ",
        f"Result: {counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail, "
        f"{counts[ERROR]} error, {counts[SKIP]} skipped; score {score:.0f}% of applicable checks",
        "",
        "| id | status | check | source | detail |",
        "|---|---|---|---|---|",
    ]
    for item, outcome in results:
        detail = outcome.detail.replace("|", "\\|").replace("\n", " ")[:300]
        lines.append(f"| {item.id} | {outcome.status} | {item.title} | {item.source} | {detail} |")
    if notes:
        lines += ["", "## Notes", *[f"- {n}" for n in notes]]
    lines += ["", "## Evidence"]
    for item, outcome in results:
        if outcome.status in (FAIL, WARN, ERROR) and outcome.evidence:
            lines += ["", f"### {item.id} {outcome.status}", "```", *[e[:1500] for e in outcome.evidence[:6]], "```"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rewrites = [tuple(r.split("=", 1)) for r in args.rewrite]
    config = ProbeConfig(
        issuer=args.issuer,
        offer=args.offer,
        offer_cmd=args.offer_cmd,
        token_cmd=args.token_cmd,
        tx_code=args.tx_code,
        config_id=args.config_id,
        insecure=args.insecure,
        rewrites=[(a, b) for a, b in rewrites],
        attestation_issuer=AttestationIssuer.from_ca_files(Path(args.ka_ca[0]), Path(args.ka_ca[1]))
        if args.ka_ca
        else None,
        wallet_provider=WalletProvider.from_ca_files(Path(args.wia_ca[0]), Path(args.wia_ca[1]), tuple(args.wia_policy))
        if args.wia_ca
        else WalletProvider.from_signer_files(Path(args.wia_signer[0]), Path(args.wia_signer[1]))
        if args.wia_signer
        else None,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        second_client=_pair(args.second_client) if args.second_client else None,
        login_fields=dict(_pair(f) for f in args.login_field) if args.login_field else None,
        cancel_fields=dict(_pair(f) for f in args.cancel_field) if args.cancel_field else None,
        login_cmd=args.login_cmd,
        token_client_id=args.token_client_id,
        mdoc_config_id=args.mdoc_config_id,
        deferred_offer_cmd=args.deferred_offer_cmd,
        release_cmd=args.release_cmd,
        deferred_wait_max=args.deferred_wait_max,
        hold_fields=dict(_pair(f) for f in args.hold_field) if args.hold_field else None,
    )
    if args.wia_status and config.wallet_provider is not None:
        config.wallet_provider.status = (args.wia_status[0], int(args.wia_status[1]))
    if args.ka_status and config.attestation_issuer is not None:
        config.attestation_issuer.status = (args.ka_status[0], int(args.ka_status[1]))
    ctx = Context(config)
    results = []
    for item in selected(args.only):
        outcome = run_check(ctx, item)
        results.append((item, outcome))
        print(f"{item.id:4} {outcome.status:5} {item.title}  {outcome.detail[:120]}", file=sys.stderr)

    args.out.mkdir(parents=True, exist_ok=True)
    public = [(c, o) for c, o in results if not c.sensitive]
    private = [(c, o) for c, o in results if c.sensitive]
    (args.out / "report.md").write_text(render(args.name, args.issuer, public, ctx.notes, private=False))
    (args.out / "report-PRIVATE-security.md").write_text(render(args.name, args.issuer, private, [], private=True))
    raw = [
        {
            "id": c.id,
            "group": c.group,
            "source": c.source,
            "title": c.title,
            "sensitive": c.sensitive,
            "status": o.status,
            "detail": o.detail,
            "evidence": o.evidence,
        }
        for c, o in results
    ]
    (args.out / "results.json").write_text(
        json.dumps({"name": args.name, "issuer": args.issuer, "results": raw}, indent=2)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
