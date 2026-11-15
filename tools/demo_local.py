"""Run the demo on this machine: two cunho instances (the PID provider and the course provider) and the demo service,
with a throwaway development PKI.

Usage: python tools/demo_local.py OUT_DIR [--port 8100]
The page is then at https://localhost:8100; the PID issuer at https://localhost:8101/pid and the course issuer at
https://localhost:8102/course, over TLS with the development certificate (cunho's x5u URLs must be https), which the
demo service trusts through DEMO_ISSUER_CA_FILE; the demo serves TLS too, since cunho takes only an https login
service. Ctrl-C stops all three. Nothing leaves 127.0.0.1. A wallet on
another device cannot reach these addresses: for a real wallet, run the container kit (deploy/) behind TLS.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
CLIENT_ID = "https://wallet-solution.test"
REDIRECT_URI = "https://wallet.test/callback"


def private(path: Path, data: bytes) -> Path:
    """Write a file only its owner can read from the moment it exists: written first and closed afterwards, a secret
    was readable by every user of the machine in between (the security review). A file an earlier run left goes."""
    path.unlink(missing_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(data)
    return path


def cunho_env(dev: Path, state: Path, issuer: str, login: str, token: str) -> dict[str, str]:
    """A development cunho as the demo runs it: every M4 item that works without a deployment, revocations
    published within a minute (no jitter), and the demo's login screens as its login service."""
    state.mkdir(parents=True, exist_ok=True)
    return {
        "CUNHO_ISSUER_URL": issuer,
        "CUNHO_ADMIN_TOKEN": token,
        "CUNHO_SIGNING_KEY": str(dev / "signing.key"),
        "CUNHO_SIGNING_CHAIN": str(dev / "signing.pem"),
        "CUNHO_STATUS_SIGNING_KEY": str(dev / "status.key"),
        "CUNHO_STATUS_SIGNING_CHAIN": str(dev / "status.pem"),
        "CUNHO_SIGNING_TRUST_ANCHORS": str(dev / "issuer-root.pem"),
        "CUNHO_MDOC_SIGNING_KEY": str(dev / "mdoc-signing.key"),
        "CUNHO_MDOC_SIGNING_CHAIN": str(dev / "mdoc-signing.pem"),
        "CUNHO_MDOC_TRUST_ANCHORS": str(dev / "iaca.pem"),
        "CUNHO_MDOC_SIGNER_CERTIFICATE_URL": f"{issuer}/certs/mdoc-signer.pem",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{issuer}/certs/signer.pem",
        "CUNHO_WALLET_PROVIDER_ANCHORS": str(dev / "all-wallet-providers.pem"),
        "CUNHO_WALLET_PROVIDER_CRLS": str(dev / "all-wallet-providers.crl"),
        "CUNHO_ACCESS_SIGNING_KEY": str(dev / "m3" / "access.key"),
        "CUNHO_ACCESS_SIGNING_CHAIN": str(dev / "m3" / "access.pem"),
        "CUNHO_ACCESS_TRUST_ANCHORS": str(dev / "m3" / "access-ca.pem"),
        "CUNHO_REGISTRATION_CERTIFICATE": str(dev / "registration-certificate.jwt"),
        "CUNHO_REGISTRAR_DATASET": str(dev / "registrar.json"),
        "CUNHO_ENCRYPTION_KEYS": str(dev / "encryption.key"),
        "CUNHO_AUDIT_RETENTION_DAYS": "365",
        "CUNHO_STORE_PATH": str(state / "store.db"),
        "CUNHO_SECRET_KEY_FILE": str(state / "master.key"),
        "CUNHO_AUDIT_ANCHOR_PATH": str(state / "audit.anchor"),
        "CUNHO_LOGIN_URL": login,
        "CUNHO_REDIRECT_URIS": json.dumps({CLIENT_ID: [REDIRECT_URI]}),
        "CUNHO_STATUS_REVOCATION_JITTER": "0",
        "CUNHO_STATUS_PUBLISH_INTERVAL": "60",
        "CUNHO_CREDENTIAL_VALIDITY_DAYS": "30",
        "CUNHO_DEFERRED_INTERVAL": "5",
        "CUNHO_DISPLAY_NAME": "FOAAP demo issuer",
    }


def ready(url: str, process: subprocess.Popen[bytes], name: str) -> None:
    deadline = time.time() + 40
    while time.time() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"{name} exited before it was ready; see its log")
        try:
            if httpx.get(url, verify=False).status_code == 200:  # the development certificate, on localhost
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise SystemExit(f"{name} did not become ready in time")


def serve_demo(port: int, view_port: int, key: str, cert: str, lan: str | None = None) -> None:
    """The demo service on two ports in one process: TLS on `port`, plain http on `view_port`, and with `lan` the
    view port on that private-network address too, for a phone on the same Wi-Fi."""
    import asyncio  # noqa: PLC0415 - only this mode needs them

    import uvicorn  # noqa: PLC0415

    from cunho_demo.app import create_app  # noqa: PLC0415

    app = create_app()

    def config(on: int, host: str = "127.0.0.1", **tls: str) -> uvicorn.Config:
        return uvicorn.Config(app, host=host, port=on, log_level="warning", access_log=False, **tls)  # type: ignore[arg-type]

    servers = [uvicorn.Server(config(port, ssl_keyfile=key, ssl_certfile=cert)), uvicorn.Server(config(view_port))]
    if lan:
        servers.append(uvicorn.Server(config(view_port, lan)))

    async def both() -> None:
        await asyncio.gather(*(server.serve() for server in servers))

    asyncio.run(both())


def main() -> int:
    if sys.argv[1:2] == ["--serve-demo"]:
        port, view_port, key, cert = sys.argv[2:6]
        serve_demo(int(port), int(view_port), key, cert, sys.argv[6] if len(sys.argv) > 6 else None)
        return 0
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument(
        "--view-port",
        type=int,
        help="also serve the demo over plain http on this port, for a browser that does not trust the development "
        "certificate: the same process, so both share their sessions",
    )
    parser.add_argument(
        "--lan",
        metavar="ADDRESS",
        help="this machine's address on its Wi-Fi (a private address): the view port listens there too and the "
        "page's QR codes point there, so a phone on the same network opens the phone page; needs --view-port",
    )
    args = parser.parse_args()
    if args.lan and not args.view_port:
        parser.error("--lan needs --view-port")
    out: Path = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    dev = out / "dev"
    base = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]))
    if not (dev / "signing.key").exists():
        subprocess.run([sys.executable, str(ROOT / "tools" / "dev_pki.py"), str(dev)], check=True, env=base)
    demo_url = f"https://localhost:{args.port}"
    pid_url, course_url = f"https://localhost:{args.port + 1}/pid", f"https://localhost:{args.port + 2}/course"
    tokens = {name: secrets.token_urlsafe(32) for name in ("pid", "course")}
    secret = private(out / "demo-secret.key", secrets.token_bytes(32))
    # The operator console, with a password made for this run; it is printed below and kept nowhere else.
    sys.path.insert(0, str(ROOT / "src"))
    from cunho_demo.console import hash_password  # noqa: PLC0415 - the checkout's demo package

    password = secrets.token_urlsafe(12)
    operator = private(out / "operator-password", hash_password(password).encode())
    token_files = {name: private(out / f"{name}-admin-token", token.encode()) for name, token in tokens.items()}
    pid = dict(base, **cunho_env(dev, out / "pid", pid_url, f"{demo_url}/login/pid", tokens["pid"]))
    pid["CUNHO_PROFILE"] = "pid_provider"
    course = dict(base, **cunho_env(dev, out / "course", course_url, f"{demo_url}/login/course", tokens["course"]))
    course.update(
        CUNHO_PROFILE="eaa_provider",
        CUNHO_METADATA_DIR=str(ROOT / "demo" / "metadata" / "course"),
        CUNHO_PUBLISHED_CONFIGURATIONS="app.foaap.course_certificate_sd_jwt,app.foaap.course_certificate_mdoc",
    )
    demo = dict(
        base,
        DEMO_PUBLIC_URL=demo_url,
        DEMO_PID_ADMIN_URL=pid_url,
        DEMO_PID_ADMIN_TOKEN_FILE=str(token_files["pid"]),
        DEMO_COURSE_ADMIN_URL=course_url,
        DEMO_COURSE_ADMIN_TOKEN_FILE=str(token_files["course"]),
        DEMO_SECRET_KEY_FILE=str(secret),
        DEMO_ISSUER_CA_FILE=str(dev / "tls.pem"),
        DEMO_OPERATOR_PASSWORD_FILE=str(operator),
        # The demo wallet attests its keys with the development PKI's second wallet provider (m3/), which
        # all-wallet-providers.pem makes both issuers trust.
        DEMO_WALLET_KA_CHAIN_FILE=str(dev / "m3" / "ka-signer.pem"),
        DEMO_WALLET_KA_KEY_FILE=str(dev / "m3" / "ka-signer.key"),
    )
    (dev / "m3" / "ka-signer.key").chmod(0o600)
    plan = [
        (
            "cunho-pid",
            pid,
            "cunho.app:create_app",
            args.port + 1,
            f"https://localhost:{args.port + 1}/.well-known/openid-credential-issuer/pid",
        ),
        (
            "cunho-course",
            course,
            "cunho.app:create_app",
            args.port + 2,
            f"https://localhost:{args.port + 2}/.well-known/openid-credential-issuer/course",
        ),
        ("demo", demo, "cunho_demo.app:create_app", args.port, f"{demo_url}/healthz"),
    ]
    tls = ["--ssl-keyfile", str(dev / "tls.key"), "--ssl-certfile", str(dev / "tls.pem")]
    if args.view_port:
        # One process on both ports, so a page opened over http and the login screens cunho sends the wallet's
        # browser to over https see the same sessions; it takes forms and JSON from both origins.
        # The view port listens on 127.0.0.1, so a browser can name it either way.
        demo["DEMO_EXTRA_ORIGINS"] = f"http://localhost:{args.view_port},http://127.0.0.1:{args.view_port}"
    if args.lan:
        # The phone page's links name the Wi-Fi address; the TLS origin stays for the login screens.
        demo["DEMO_PUBLIC_URL"] = f"http://{args.lan}:{args.view_port}"
        demo["DEMO_EXTRA_ORIGINS"] += f",{demo_url}"
    processes: list[subprocess.Popen[bytes]] = []
    try:
        for name, env, factory, port, check in plan:
            log = (out / f"{name}.log").open("wb")
            command = [
                sys.executable,
                "-m",
                "uvicorn",
                "--factory",
                factory,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ]
            command += ["--no-access-log", "--log-level", "warning", *tls]
            if name == "demo" and args.view_port:
                command = [sys.executable, str(Path(__file__).resolve()), "--serve-demo", str(port)]
                command += [str(args.view_port), str(dev / "tls.key"), str(dev / "tls.pem")]
                command += [args.lan] if args.lan else []
            process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            ready(check, process, name)
        print(f"demo at {demo_url} (logs in {out}); operator console password: {password}", flush=True)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        while all(process.poll() is None for process in processes):
            time.sleep(1)
        print("a process stopped; see its log", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
