"""Run eudi-probe against a local cunho: a development PKI, cunho over TLS with the code flow's test login, and every
check of the probe. Exits non-zero when a check fails or errs, or when a check of M3 or M4 does not pass.

Usage: python tools/probe_local.py OUT_DIR [--course]
With --course the issuer is the demo's course provider (demo/metadata/course, an attestation provider) and every
check runs against the course certificate: the SD-JWT VC, and the mdoc in a run of its own.
Everything stays on 127.0.0.1. The reports land in OUT_DIR/pre-authorized and OUT_DIR/code-flow-offer.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
CLIENT_ID = "https://wallet-solution.test"
REDIRECT_URI = "https://wallet.test/callback"
SECOND_CLIENT, SECOND_REDIRECT = "https://other-wallet-solution.test", "https://other-wallet.test/callback"
# The checks of M3 that may skip: M20 has no metadata member to look at yet (ETSI TS 119 472-3 §4.2.5), and A20
# needs an offer for the code flow, which only the second run makes.
MAY_SKIP = {"M20", "A20"}
# The course certificate asks for no key attestation (demo/README.md), so the check that an untrusted one is refused
# has nothing to look at.
MAY_SKIP_COURSE = MAY_SKIP | {"W10"}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main(out: Path, course: bool = False) -> int:
    out.mkdir(parents=True, exist_ok=True)
    dev, port = out / "dev", free_port()
    issuer = f"https://localhost:{port}"
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT / "probe"), str(ROOT)]))
    subprocess.run([sys.executable, str(ROOT / "tools" / "dev_pki.py"), str(dev)], check=True, env=env)
    env.update(
        CUNHO_ISSUER_URL=issuer,
        CUNHO_ADMIN_TOKEN=(dev / "admin-token").read_text().strip(),
        CUNHO_SIGNING_KEY=str(dev / "signing.key"),
        CUNHO_SIGNING_CHAIN=str(dev / "signing.pem"),
        CUNHO_STATUS_SIGNING_KEY=str(dev / "status.key"),
        CUNHO_STATUS_SIGNING_CHAIN=str(dev / "status.pem"),
        CUNHO_WALLET_PROVIDER_ANCHORS=str(dev / "all-wallet-providers.pem"),
        CUNHO_WALLET_PROVIDER_CRLS=str(dev / "all-wallet-providers.crl"),
        CUNHO_AUDIT_RETENTION_DAYS="365",
        CUNHO_SIGNER_CERTIFICATE_URL=f"{issuer}/certs/signer.pem",
        CUNHO_SIGNING_TRUST_ANCHORS=str(dev / "issuer-root.pem"),
        CUNHO_STORE_PATH=str(out / "store.db"),
        CUNHO_SECRET_KEY_FILE=str(out / "master.key"),
        CUNHO_AUDIT_ANCHOR_PATH=str(out / "audit.anchor"),
        CUNHO_TEST_LOGIN_PERSONS=str(dev / "test-persons.json"),
        CUNHO_REDIRECT_URIS=json.dumps({CLIENT_ID: [REDIRECT_URI], SECOND_CLIENT: [SECOND_REDIRECT]}),
        CUNHO_ACCESS_SIGNING_KEY=str(dev / "m3" / "access.key"),
        CUNHO_ACCESS_SIGNING_CHAIN=str(dev / "m3" / "access.pem"),
        CUNHO_ACCESS_TRUST_ANCHORS=str(dev / "m3" / "access-ca.pem"),
        CUNHO_REGISTRATION_CERTIFICATE=str(dev / "registration-certificate.jwt"),
        CUNHO_REGISTRAR_DATASET=str(dev / "registrar.json"),
        CUNHO_PREFERRED_CLIENT_STATUS_PERIOD="86400",
        CUNHO_MDOC_SIGNING_KEY=str(dev / "mdoc-signing.key"),
        CUNHO_MDOC_SIGNING_CHAIN=str(dev / "mdoc-signing.pem"),
        CUNHO_MDOC_TRUST_ANCHORS=str(dev / "iaca.pem"),
        CUNHO_MDOC_SIGNER_CERTIFICATE_URL=f"{issuer}/certs/mdoc-signer.pem",
        CUNHO_ENCRYPTION_KEYS=str(dev / "encryption.key"),
        CUNHO_DEFERRED_INTERVAL="5",  # the least it may be, so the probe waits it out between polls
    )
    if course:
        sys.path.insert(0, str(ROOT / "tools"))
        from dev_offer import SAMPLE_COURSE  # noqa: PLC0415 - the same sample the offers carry

        persons = out / "course-persons.json"
        persons.write_text(json.dumps({"ana": SAMPLE_COURSE}))
        env.update(
            CUNHO_PROFILE="eaa_provider",
            CUNHO_METADATA_DIR=str(ROOT / "demo" / "metadata" / "course"),
            CUNHO_PUBLISHED_CONFIGURATIONS="app.foaap.course_certificate_sd_jwt,app.foaap.course_certificate_mdoc",
            CUNHO_TEST_LOGIN_PERSONS=str(persons),
        )
    server_log = (out / "server.log").open("wb")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "--factory", "cunho.app:create_app", "--host", "127.0.0.1"]
        + ["--port", str(port), "--ssl-keyfile", str(dev / "tls.key"), "--ssl-certfile", str(dev / "tls.pem")]
        + ["--no-access-log", "--log-level", "warning"],
        env=env,
        stdout=server_log,
        stderr=subprocess.STDOUT,
    )
    try:
        ready(issuer, server)
        offer = f"{sys.executable} {ROOT / 'tools' / 'dev_offer.py'} {issuer} {dev / 'admin-token'}"
        release = f"{sys.executable} {ROOT / 'tools' / 'dev_release.py'} {issuer} {dev / 'admin-token'}"
        common = [
            "--issuer",
            issuer,
            "--insecure",
            "--ka-ca",
            str(dev / "wallet-providers.pem"),
            str(dev / "wallet-provider.key"),
            "--wia-signer",
            str(dev / "m3" / "wia-signer.pem"),
            str(dev / "m3" / "wia-signer.key"),
            "--client-id",
            CLIENT_ID,
            "--redirect-uri",
            REDIRECT_URI,
            "--second-client",
            f"{SECOND_CLIENT}={SECOND_REDIRECT}",
            "--login-field",
            "person=ana",
            "--login-field",
            "action=login",
            "--cancel-field",
            "action=cancel",
            "--hold-field",
            "review=true",
            "--release-cmd",
            release,
        ]
        runs = {
            "pre-authorized": ["--name", "cunho@local", "--offer-cmd", f"{offer} --mdoc"],
            "code-flow-offer": [
                "--name",
                "cunho@local-code-offer",
                "--offer-cmd",
                f"{offer} --code-flow --mdoc",
                "--only",
                "A20",
            ],
        }
        if course:
            runs = {
                "course": ["--name", "cunho@local-course", "--offer-cmd", f"{offer} --course"],
                "course-mdoc": ["--name", "cunho@local-course-mdoc", "--offer-cmd", f"{offer} --course --mdoc"]
                + ["--only", "mdoc,C16"],
                "course-code-flow-offer": ["--name", "cunho@local-course-code-offer"]
                + ["--offer-cmd", f"{offer} --course --code-flow", "--only", "A20"],
            }
        results: dict[str, str] = {}
        for name, extra in runs.items():
            target = out / name
            subprocess.run(
                [sys.executable, "-m", "eudi_probe", *common, *extra, "--out", str(target)], env=env, check=True
            )
            for result in json.loads((target / "results.json").read_text())["results"]:
                if result["status"] != "SKIP" or result["id"] not in results:  # a skip never hides a result
                    results[result["id"]] = result["status"]
    finally:
        server.terminate()
        server.wait(10)
        server_log.close()
    return verdict(results, MAY_SKIP_COURSE if course else MAY_SKIP)


def ready(issuer: str, server: subprocess.Popen[bytes]) -> None:
    deadline = time.time() + 30
    while time.time() < deadline:
        if server.poll() is not None:
            raise SystemExit("cunho exited before it was ready; see server.log")
        try:
            if httpx.get(f"{issuer}/.well-known/openid-credential-issuer", verify=False).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise SystemExit("cunho did not become ready in time")


def verdict(results: dict[str, str], may_skip: set[str] = MAY_SKIP) -> int:
    sys.path.insert(0, str(ROOT / "probe"))
    from eudi_probe.checks import REGISTRY  # noqa: PLC0415 - the probe of this checkout

    m3 = {c.id for c in REGISTRY if c.group in ("authorization", "attestation")} | {f"M{n}" for n in range(17, 24)}
    m4 = {c.id for c in REGISTRY if c.group in ("mdoc", "deferred", "encryption")} | {"C15", "C16", "C17", "C18"}
    bad = sorted(i for i, s in results.items() if s in ("FAIL", "ERROR"))
    unproven = sorted(i for i in m3 | m4 if results.get(i) != "PASS" and i not in may_skip)
    if results.get("A20") != "PASS":
        unproven.append("A20")
    for label, ids in (("failed or erred", bad), ("M3 or M4 checks that did not pass", unproven)):
        if ids:
            print(f"{label}: {', '.join(ids)}")
    print("probe against local cunho:", "PASS" if not bad and not unproven else "FAIL")
    return 1 if bad or unproven else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), "--course" in sys.argv[2:]))
