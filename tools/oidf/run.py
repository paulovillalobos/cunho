"""Run the OpenID Foundation conformance suite against cunho, on this machine, in docker.

Usage: python tools/oidf/run.py [PLAN ...] [--keep]
PLAN is preauth, haip-wallet, haip-issuer, haip-wallet-mdoc or haip-issuer-mdoc; all five without one. Results go to
tools/oidf/_work/results/<plan>, as the suite exports them. The exit code is 0 only when every module passes, apart
from the ones listed with their reason in expected-failures.json and expected-skips.json.

The suite tests HAIP alone, so cunho runs in its conformance setting (CUNHO_CONFORMANCE_MODE): the suite's wallet
attestations carry no client_status, which the EUDI rules (TS3, the ARF) ask for and production requires. cunho runs as
an attestation provider issuing one SD-JWT VC type, or one mdoc document type, made for the run, whose key attestation
asks for nothing beyond the attested key, since the suite's key attestations state no key storage either. A plan of
each format runs against a cunho of its own, publishing that configuration alone, since a login's subject data has the
shape of one format. Request and response encryption are on, so the plans' encrypted variants run. What the PID and the
EUDI attestation claims need is tested by cunho's own suites and by eudi-probe.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = Path(os.environ.get("OIDF_WORK", HERE / "_work")).resolve()
SUITE_SOURCE = "https://gitlab.com/openid/conformance-suite.git"
SUITE_COMMIT = "daca6ad2068468d42557ea1152f899cc3ac01a10"  # the source of the images compose.yml pins
SUITE = "https://localhost.emobix.co.uk:8443"  # its own name, 127.0.0.1 from this machine
ISSUER = "https://cunho.test"
ALIAS = "cunho"
CLIENTS = ("https://wallet-solution.test", "https://wallet-solution-2.test")
CONFIG_ID = "cunho.conformance.sd_jwt_vc"
VCT = "urn:cunho:conformance:1"
MDOC_CONFIG_ID = "cunho.conformance.mdoc"
MDOC_DOCTYPE = "org.cunho.conformance.1"  # its namespace too
PLANS = {
    "preauth": "oid4vci-1_0-issuer-test-plan[authorization_request_type=simple][client_auth_type=client_attestation]"
    "[fapi_request_method=unsigned][sender_constrain=dpop][vci_authorization_code_flow_variant=issuer_initiated]"
    "[vci_grant_type=pre_authorization_code][fapi_profile=vci][credential_format=sd_jwt_vc]"
    "[vci_credential_encryption=plain][fapi_response_mode=plain_response]",
    "haip-wallet": "oid4vci-1_0-issuer-haip-test-plan[vci_authorization_code_flow_variant=wallet_initiated]"
    "[credential_format=sd_jwt_vc]",
    "haip-issuer": "oid4vci-1_0-issuer-haip-test-plan[vci_authorization_code_flow_variant=issuer_initiated]"
    "[credential_format=sd_jwt_vc]",
    "haip-wallet-mdoc": "oid4vci-1_0-issuer-haip-test-plan[vci_authorization_code_flow_variant=wallet_initiated]"
    "[credential_format=mdoc]",
    "haip-issuer-mdoc": "oid4vci-1_0-issuer-haip-test-plan[vci_authorization_code_flow_variant=issuer_initiated]"
    "[credential_format=mdoc]",
}
PERSON = {"given_name": "Ana", "family_name": "Silva"}
# Per format: the configuration a plan asks for, the subject data of the test login's person and of an offer (an mdoc
# takes its data elements by namespace), and the anchor the suite verifies the credential's signer to (the IACA for an
# mdoc, whose x5chain leaves it out).
FORMATS: dict[str, dict[str, Any]] = {
    "sd_jwt_vc": {"config": CONFIG_ID, "scope": "cunho.conformance", "person": PERSON, "anchor": "issuer-root.pem"},
    "mdoc": {
        "config": MDOC_CONFIG_ID,
        "scope": "cunho.conformance.mdoc",
        "person": {MDOC_DOCTYPE: PERSON},
        "anchor": "iaca.pem",
    },
}
# With --course, the demo's course certificate (demo/metadata/course) as it is published, in place of the run's own
# configurations: the plans then check what the demo issues.
COURSE_PERSON = {
    "family_name": "Silva",
    "given_name": "Ana",
    "achievement_title": "Introduction to the European Digital Identity Wallet",
    "language_of_classes": ["pt", "en"],
    "expected_study_time": "PT12H",
    "course_provider": "FOAAP Academy (demo)",
    "date_of_completion": "2026-11-02",
}
COURSE_FORMATS: dict[str, dict[str, Any]] = {
    "sd_jwt_vc": {
        "config": "app.foaap.course_certificate_sd_jwt",
        "scope": "app.foaap.course_certificate_sd_jwt",
        "person": COURSE_PERSON,
        "anchor": "issuer-root.pem",
    },
    "mdoc": {
        "config": "app.foaap.course_certificate_mdoc",
        "scope": "app.foaap.course_certificate_mdoc",
        "person": {"app.foaap.course_certificate.1": {**COURSE_PERSON, "language_of_classes": "pt, en"}},
        "anchor": "iaca.pem",
    },
}


def plan_format(plan: str) -> str:
    return "mdoc" if plan.endswith("-mdoc") else "sd_jwt_vc"


FAPI = "fapi2-security-profile-final"
ADMIN_PORT = 8445


def main(argv: list[str]) -> int:
    if "--course" in argv:
        FORMATS.update(COURSE_FORMATS)
    plans = [a for a in argv if not a.startswith("--")] or list(PLANS)
    unknown = [p for p in plans if p not in PLANS]
    if unknown:
        raise SystemExit(f"unknown plans {unknown}; choose from {sorted(PLANS)}")
    prepare()
    up()
    try:
        wait_for(f"{SUITE}/api/server", "the suite")
        runner = suite_runner()
        failed, running = 0, None
        for plan in sorted(plans, key=plan_format):  # one cunho per format, started once
            if plan_format(plan) != running:
                running = plan_format(plan)
                start_cunho(running)
            failed |= run_plan(runner, plan)
        return failed
    finally:
        if "--keep" not in argv:
            down()


def prepare() -> None:
    """A fresh work folder: the test PKI, cunho's metadata and environment, and the suite's configuration."""
    if WORK.exists():
        shutil.rmtree(WORK)
    dev = WORK / "dev"
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT / "probe"), str(ROOT)]))
    subprocess.run([sys.executable, str(ROOT / "tools" / "dev_pki.py"), str(dev), "cunho.test"], check=True, env=env)
    tls_certificate(dev)
    # The IACA's CRL, alone in a folder of its own: what the CRL server below serves, and nothing else of dev/.
    (WORK / "crl").mkdir()
    shutil.copy(dev / "iaca.crl", WORK / "crl" / "iaca.crl")
    if FORMATS["sd_jwt_vc"]["config"] == CONFIG_ID:
        metadata = conformance_metadata(WORK / "metadata")
    else:
        metadata = WORK / "metadata"
        shutil.copytree(ROOT / "demo" / "metadata" / "course", metadata)
        # The suite fetches an https vct's Type Metadata (SD-JWT VC §6.3): served at the vct's own URL, under
        # its host's name on the suite's network, byte for byte the file the credentials' vct#integrity digests.
        served = WORK / "vct" / "vct" / "course-certificate"
        served.mkdir(parents=True)
        shutil.copy(metadata / "type_metadata" / "course-certificate-1.json", served / "1")
        tls_certificate(dev, VCT_HOST, "vct-tls")
    redirect = f"{SUITE}/test/a/{ALIAS}/callback"
    settings = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": (dev / "admin-token").read_text().strip(),
        "CUNHO_PROFILE": "eaa_provider",
        "CUNHO_METADATA_DIR": f"/work/{metadata.name}",
        "CUNHO_SIGNING_KEY": "/work/dev/signing.key",
        "CUNHO_SIGNING_CHAIN": "/work/dev/signing.pem",
        "CUNHO_SIGNING_TRUST_ANCHORS": "/work/dev/issuer-root.pem",
        "CUNHO_STATUS_SIGNING_KEY": "/work/dev/status.key",
        "CUNHO_STATUS_SIGNING_CHAIN": "/work/dev/status.pem",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "/work/dev/all-wallet-providers.pem",
        "CUNHO_WALLET_PROVIDER_CRLS": "/work/dev/all-wallet-providers.crl",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_STORE_PATH": "/work/store.db",
        "CUNHO_SECRET_KEY_FILE": "/work/master.key",
        "CUNHO_AUDIT_ANCHOR_PATH": "/work/audit.anchor",
        "CUNHO_MDOC_SIGNING_KEY": "/work/dev/mdoc-signing.key",
        "CUNHO_MDOC_SIGNING_CHAIN": "/work/dev/mdoc-signing.pem",
        "CUNHO_MDOC_TRUST_ANCHORS": "/work/dev/iaca.pem",
        # Request and response encryption, offered and not required: the plans' encrypted variants use them.
        "CUNHO_ENCRYPTION_KEYS": "/work/dev/encryption.key",
        # The suite's second client keeps a query on its redirect URI, which must come back with the code.
        "CUNHO_REDIRECT_URIS": json.dumps(
            {CLIENTS[0]: [redirect], CLIENTS[1]: [f"{redirect}?dummy1=lorem&dummy2=ipsum"]}
        ),
        "CUNHO_ACCESS_SIGNING_KEY": "/work/dev/m3/access.key",
        "CUNHO_ACCESS_SIGNING_CHAIN": "/work/dev/m3/access.pem",
        "CUNHO_ACCESS_TRUST_ANCHORS": "/work/dev/m3/access-ca.pem",
        "CUNHO_REGISTRATION_CERTIFICATE": "/work/dev/registration-certificate.jwt",
        "CUNHO_REGISTRAR_DATASET": "/work/dev/registrar.json",
        "CUNHO_CONFORMANCE_MODE": "true",
        "CUNHO_RATE_LIMIT_PER_MINUTE": "100000",
    }
    for name, fmt in FORMATS.items():
        (WORK / f"persons-{name}.json").write_text(json.dumps({"ana": fmt["person"]}))
        own = {
            **settings,
            "CUNHO_PUBLISHED_CONFIGURATIONS": fmt["config"],
            "CUNHO_TEST_LOGIN_PERSONS": f"/work/persons-{name}.json",
        }
        (WORK / f"cunho-{name}.env").write_text("".join(f"{k}={v}\n" for k, v in own.items()))
        (WORK / f"suite-config-{name}.json").write_text(json.dumps(suite_config(dev, fmt), indent=2))


def tls_certificate(dev: Path, host: str = "cunho.test", stem: str = "cunho-tls") -> None:
    """A self-signed certificate for `host`; the suite does not check the server's certificate in a local run."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = serialization.PrivateFormat.PKCS8
    (dev / f"{stem}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, pem, serialization.NoEncryption()))
    (dev / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def conformance_metadata(target: Path) -> Path:
    """The shipped configurations and one more for the run: an SD-JWT VC with two claims whose key attestation asks
    for no key storage, and its Type Metadata."""
    shutil.copytree(ROOT / "src" / "cunho" / "metadata_config", target)
    shipped = json.loads((target / "credentials_supported" / "pid_jwt_vc.json").read_text())
    config = json.loads(json.dumps(next(iter(shipped.values()))))
    config.update(scope="cunho.conformance", vct=VCT)
    for proof in config["proof_types_supported"].values():
        proof["key_attestations_required"] = {}
    claims = config["credential_metadata"]["claims"]
    config["credential_metadata"]["claims"] = [c for c in claims if c["path"] in (["given_name"], ["family_name"])]
    config["credential_metadata"]["display"] = [{"name": "cunho conformance run", "locale": "en"}]
    config.pop("issuer_config", None)
    (target / "credentials_supported" / "conformance.json").write_text(json.dumps({CONFIG_ID: config}, indent=2))
    shipped = json.loads((target / "credentials_supported" / "iban_mdoc.json").read_text())
    mdoc = json.loads(json.dumps(next(iter(shipped.values()))))
    mdoc.update(scope="cunho.conformance.mdoc", doctype=MDOC_DOCTYPE)
    for proof in mdoc["proof_types_supported"].values():
        proof["key_attestations_required"] = {}
    mdoc["credential_metadata"].update(  # its credential reuse policy kept
        display=[{"name": "cunho conformance run, mdoc", "locale": "en"}],
        claims=[{"path": [MDOC_DOCTYPE, name], "mandatory": True} for name in ("given_name", "family_name")],
    )
    mdoc.pop("issuer_config", None)
    (target / "credentials_supported" / "conformance_mdoc.json").write_text(
        json.dumps({MDOC_CONFIG_ID: mdoc}, indent=2)
    )
    (target / "type_metadata").mkdir()
    (target / "type_metadata" / "conformance.json").write_text(
        json.dumps({"vct": VCT, "name": "cunho conformance run"})
    )
    return target


def suite_config(dev: Path, fmt: dict[str, Any]) -> dict[str, Any]:
    """The suite's test configuration: the issuer, two attested clients, the keys it attests with, which cunho trusts
    through the development wallet provider (dev/m3), the anchors of cunho's credential and status signers, and the
    browser steps through cunho's test login."""
    m3 = dev / "m3"
    scope = fmt["scope"]
    callback = f"{SUITE}/test/a/{ALIAS}/callback*"
    vci = {"credential_issuer_url": ISSUER, "credential_configuration_id": fmt["config"]}
    return {
        "alias": ALIAS,
        "description": "cunho, local conformance run",
        "vci": vci,
        "client": {"client_id": CLIENTS[0], "scope": scope},
        "client2": {"client_id": CLIENTS[1], "scope": scope},
        "client_attestation": {
            "issuer": "https://wallet-provider.test",
            "attester_jwks": {"keys": [signing_jwk(m3 / "wia-signer.key", m3 / "wia-signer.pem", "wia")]},
            "key_attestation_jwks": {"keys": [signing_jwk(m3 / "ka-signer.key", m3 / "ka-signer.pem", "ka")]},
        },
        "credential": {
            "trust_anchor_pem": (dev / fmt["anchor"]).read_text(),
            "status_list_trust_anchor_pem": (dev / "issuer-root.pem").read_text(),
        },
        "browser": [login("login", callback)],
        "override": {
            # The person cancels, and the wallet gets access_denied.
            f"{FAPI}-user-rejects-authentication": {"browser": [login("cancel", callback)]},
            # FAPI 2.0 SP §5.3.2.2 note 3: the request_uri is opened once with no login, then again to log in.
            f"{FAPI}-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
                "browser": [
                    {
                        "match": f"{ISSUER}/authorize*",
                        "match-limit": 1,
                        "tasks": [{"task": "First visit", "match": f"{ISSUER}/test-login*"}],
                    },
                    login("login", callback),
                ]
            },
            # The suite signs proof i of a batch with attested_keys[i] of one key attestation; TS3 §2.2.2.2 and
            # CIR 2024/2979 Annex Ib TR_KA-6.1 have each jwt proof verify under attested_keys[0], so cunho refuses
            # it. The batch is asked with the attestation proof type, one key attestation for every key (OID4VCI
            # 1.0 App. F.3), which both allow.
            "oid4vci-1_0-issuer-batch-issuance": {"vci": {**vci, "credential_proof_type_hint": "attestation"}},
        },
    }


def login(button: str, callback: str) -> dict[str, Any]:
    """The browser through cunho's test login: the first person is chosen, and `button` (login or cancel) pressed.
    Both steps are optional: a request cunho refuses ends on its error page at the authorization endpoint, which the
    module then asks a screenshot of."""
    return {
        "match": f"{ISSUER}/authorize*",
        "tasks": [
            {
                "task": "Log in",
                "match": f"{ISSUER}/test-login*",
                "optional": True,
                "commands": [["click", "id", button]],
            },
            {
                "task": "Verify Complete",
                "match": callback,
                "optional": True,
                "commands": [["wait", "id", "submission_complete", 10]],
            },
        ],
    }


def signing_jwk(key_path: Path, chain_path: Path, kid: str) -> dict[str, Any]:
    """A private JWK with its x5c, the anchor left out, as the suite signs attestations with."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    numbers = key.private_numbers()

    def b64u(value: int) -> str:
        return base64.urlsafe_b64encode(value.to_bytes(32, "big")).rstrip(b"=").decode()

    chain = x509.load_pem_x509_certificates(chain_path.read_bytes())
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
        "x": b64u(numbers.public_numbers.x),
        "y": b64u(numbers.public_numbers.y),
        "d": b64u(numbers.private_value),
        "x5c": [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in chain],
    }


# The suite's images, pinned by digest so an upstream change cannot alter a run without this file changing; bump them
# on purpose, with SUITE_COMMIT, the source they were built from.
MONGO = "mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070"  # 6.0.13
REGISTRY = "registry.gitlab.com/openid/conformance-suite"
NGINX = f"{REGISTRY}/nginx@sha256:5ed25320272bb4d686f29b26d7d928cc1a22da8e2afc11e88c6758d95df492ba"
SERVER = f"{REGISTRY}@sha256:06db5442303151f392f82a378089941348535619a1fca3c6c3197a9eb9ccff63"
NETWORK = "cunho-oidf"


def up() -> None:
    """The suite (mongo, its server, its nginx under its own name) on one network, and cunho's image."""
    down()
    docker("network", "create", NETWORK)
    docker("build", "-q", "-t", "cunho-oidf", "-f", str(HERE / "Dockerfile"), str(ROOT))
    docker("run", "-d", "--name", "oidf-mongodb", "--network", NETWORK, "--network-alias", "mongodb", MONGO)
    suite_env = ["-e", f"BASE_URL={SUITE}", "-e", "MONGODB_HOST=mongodb", "-e", "SPRING_PROFILES_ACTIVE=dev"]
    for name in ("GOOGLE", "GITLAB"):  # the server will not start without them, though the dev profile never logs in
        suite_env += [
            "-e",
            f"OIDC_{name}_CLIENTID={name.lower()}-client",
            "-e",
            f"OIDC_{name}_SECRET={name.lower()}-secret",
        ]
    docker("run", "-d", "--name", "oidf-server", "--network", NETWORK, "--network-alias", "server", *suite_env, SERVER)
    # The CRL distribution point the document signer names (tools/dev_pki.py CRL_URL), which the suite fetches.
    docker(
        "run",
        "-d",
        "--name",
        "oidf-crl",
        "--network",
        NETWORK,
        "--network-alias",
        "crl.test",
        "-v",
        f"{WORK / 'crl'}:/srv:ro",
        "cunho-oidf",
        "python",
        "-c",
        CRL_SERVER,
    )
    if (WORK / "vct").is_dir():
        docker(
            "run",
            "-d",
            "--name",
            "oidf-vct",
            "--network",
            NETWORK,
            "--network-alias",
            VCT_HOST,
            "-v",
            f"{WORK / 'vct'}:/srv:ro",
            "-v",
            f"{WORK / 'dev'}:/tls:ro",
            "cunho-oidf",
            "python",
            "-c",
            VCT_SERVER,
        )
    docker(
        "run",
        "-d",
        "--name",
        "oidf-nginx",
        "--network",
        NETWORK,
        "--network-alias",
        "localhost.emobix.co.uk",
        "-p",
        "127.0.0.1:8443:8443",
        NGINX,
    )


def start_cunho(fmt: str) -> None:
    """cunho for the plans of one format, on the suite's network under its name, in place of the one before."""
    subprocess.run(["docker", "rm", "-f", "oidf-cunho"], capture_output=True)
    docker(
        "run",
        "-d",
        "--name",
        "oidf-cunho",
        "--network",
        NETWORK,
        "--network-alias",
        "cunho.test",
        "-p",
        f"127.0.0.1:{ADMIN_PORT}:443",  # the operator's side, for offers: this machine only
        "--env-file",
        str(WORK / f"cunho-{fmt}.env"),
        "-v",
        f"{WORK}:/work",
        "cunho-oidf",
    )
    wait_for(f"https://127.0.0.1:{ADMIN_PORT}/.well-known/openid-credential-issuer", f"cunho ({fmt})")


# The course certificate's Type Metadata at https://foaap.app/vct/course-certificate/1, as application/json.
VCT_HOST = "foaap.app"
VCT_SERVER = (
    "import functools, ssl, http.server as h; "
    "h.SimpleHTTPRequestHandler.extensions_map[''] = 'application/json'; "
    "s = h.ThreadingHTTPServer(('', 443), functools.partial(h.SimpleHTTPRequestHandler, directory='/srv')); "
    "c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain('/tls/vct-tls.pem', '/tls/vct-tls.key'); "
    "s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()"
)
# A file server for /srv on port 8080 that names a CRL application/pkix-crl (RFC 5280 §4.2.1.13), which the slim image's
# own table of media types does not.
CRL_SERVER = (
    "import functools, http.server as h; "
    "h.SimpleHTTPRequestHandler.extensions_map['.crl'] = 'application/pkix-crl'; "
    "h.ThreadingHTTPServer(('', 8080), functools.partial(h.SimpleHTTPRequestHandler, directory='/srv')).serve_forever()"
)


def down() -> None:
    for name in ("oidf-cunho", "oidf-crl", "oidf-vct", "oidf-nginx", "oidf-server", "oidf-mongodb"):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "network", "rm", NETWORK], capture_output=True)


def docker(*args: str) -> None:
    subprocess.run(["docker", *args], check=True, env=dict(os.environ, DOCKER_BUILDKIT="0"))


def wait_for(url: str, what: str, seconds: float = 300) -> None:
    context = ssl._create_unverified_context()  # noqa: S323 - the suite's local certificate is self-signed
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, context=context, timeout=5):  # noqa: S310 - a local URL
                return
        except OSError:
            time.sleep(3)
    raise SystemExit(f"{what} did not come up in {seconds:.0f} s")


def suite_runner() -> list[str]:
    """The suite's own runner, from its source at the pinned commit, in a virtual environment of its own."""
    source = WORK.parent / "_suite"
    if not (source / ".git").exists():
        subprocess.run(["git", "clone", "-q", SUITE_SOURCE, str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "fetch", "-q", "origin", SUITE_COMMIT], check=False)
    subprocess.run(["git", "-C", str(source), "checkout", "-q", SUITE_COMMIT], check=True)
    venv = WORK.parent / "_venv"
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        subprocess.run(
            [str(venv / "bin" / "pip"), "install", "-q", "-r", str(source / "scripts" / "requirements.txt")], check=True
        )
    return [str(venv / "bin" / "python"), str(source / "scripts" / "run-test-plan.py")]


def run_plan(runner: list[str], plan: str) -> int:
    results = WORK / "results" / plan
    results.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CONFORMANCE_SERVER=SUITE + "/", CONFORMANCE_DEV_MODE="1", DISABLE_SSL_VERIFY="1")
    command = [*runner, "--no-parallel", "--export-dir", str(results), "--verbose"]
    for name, flag in (
        ("expected-failures.json", "--expected-failures-file"),
        ("expected-skips.json", "--expected-skips-file"),
    ):
        # An entry names the plans it is expected in; the suite's runner fails a run where an entry matches nothing.
        entries = [e for e in json.loads((HERE / name).read_text()) if plan in e.pop("plans")]
        (results / name).write_text(json.dumps(entries, indent=2))
        command += [flag, str(results / name)]
    fmt = plan_format(plan)
    command += [PLANS[plan], str(WORK / f"suite-config-{fmt}.json")]
    print(f"== {plan}", flush=True)
    stop = threading.Event()
    watcher = threading.Thread(target=answer_error_pages, args=(stop, FORMATS[fmt]), daemon=True)
    watcher.start()
    try:
        return subprocess.run(command, env=env).returncode
    finally:
        stop.set()
        watcher.join()


# A 1x1 PNG: the stand-in for a screenshot, never a picture of anything.
PLACEHOLDER = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def answer_error_pages(stop: threading.Event, fmt: dict[str, Any]) -> None:
    """Play the people a run needs, for the modules waiting on them.

    The operator: a module of the issuer-initiated or pre-authorized flows waits for a credential offer at its
    credential_offer_endpoint. run.py makes one with cunho's admin API, as an operator would, and sends it there.

    The tester: a module that expects cunho to refuse at the authorization endpoint with an error page asks a person
    for a screenshot of it and waits. run.py checks the page instead: when the suite's browser was answered 400 by
    cunho's authorization endpoint after the module asked, it fills the module's placeholder with a 1x1 image, so the
    module ends as REVIEW. A certification run needs real screenshots in their place."""
    answered: set[tuple[str, str]] = set()
    offered: dict[str, int] = {}
    while not stop.wait(5):
        try:
            running = suite_get("/api/runner/running")
            for module_id in running if isinstance(running, list) else []:
                info = suite_get(f"/api/info/{module_id}")
                if info.get("status") != "WAITING":
                    continue
                log = suite_get(f"/api/log/{module_id}")
                waits = sum(str(e.get("msg", "")).startswith("Waiting for call to credential offer") for e in log)
                if waits > offered.get(module_id, 0):
                    endpoint = (suite_get(f"/api/runner/{module_id}").get("exposed") or {}).get(
                        "credential_offer_endpoint"
                    )
                    if isinstance(endpoint, str):
                        code_flow = (info.get("variant") or {}).get("vci_grant_type") == "authorization_code"
                        send_offer(endpoint, code_flow, fmt)
                        offered[module_id] = waits
                        print(f"   {module_id}: offer made by cunho's admin API and sent to the wallet", flush=True)
                for placeholder in refused_after(log):
                    if (module_id, placeholder) not in answered:
                        suite_post(f"/api/log/{module_id}/images/{placeholder}", PLACEHOLDER)
                        answered.add((module_id, placeholder))
                        print(f"   {module_id}: cunho refused with an error page; placeholder image sent", flush=True)
        except (OSError, ValueError) as exc:
            print(f"   (watcher: {exc})", flush=True)


def send_offer(endpoint: str, code_flow: bool, fmt: dict[str, Any]) -> None:
    """An offer from cunho's admin API, sent to the wallet's credential offer endpoint (OpenID4VCI 1.0 §4.1): for the
    code flow with an issuer_state and no subject data, since the login says who the person is."""
    body: dict[str, Any] = {"credential_configuration_ids": [fmt["config"]]}
    # A pre-authorized offer with a tx_code, which the suite's wallet waits for in that flow (§3.5).
    body.update({"grant": "authorization_code"} if code_flow else {"subject": fmt["person"], "tx_code_length": 6})
    token = (WORK / "dev" / "admin-token").read_text().strip()
    request = urllib.request.Request(
        f"https://127.0.0.1:{ADMIN_PORT}/admin/offers",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    context = ssl._create_unverified_context()  # noqa: S323 - cunho's local certificate is self-signed
    with urllib.request.urlopen(request, context=context, timeout=10) as response:  # noqa: S310 - a local URL
        made = json.load(response)
    query = str(made["offer_link"]).split("?", 1)[1]  # credential_offer=... as cunho encoded it
    with urllib.request.urlopen(f"{endpoint}?{query}", context=context, timeout=10):  # noqa: S310
        pass
    if made.get("tx_code"):
        # The tx_code reaches the person apart from the offer (OpenID4VCI 1.0 §4.1.1); the module takes it at
        # its tx_code endpoint, next to the offer endpoint.
        base = endpoint.rsplit("/", 1)[0]
        code = urllib.parse.quote(str(made["tx_code"]))
        with urllib.request.urlopen(f"{base}/tx_code?code={code}", context=context, timeout=10):  # noqa: S310
            pass


def refused_after(log: list[dict[str, Any]]) -> list[str]:
    """The placeholders after which the browser got a 400 from cunho's authorization endpoint and stayed there."""
    found = []
    for i, entry in enumerate(log):
        placeholder = entry.get("upload")
        if not isinstance(placeholder, str):
            continue
        after = log[i + 1 :]
        status = next((e.get("response_status_code") for e in after if "response_status_code" in e), None)
        url = next((str(e["url"]) for e in after if isinstance(e.get("url"), str)), "")
        if str(status) == "400" and url.startswith(f"{ISSUER}/authorize"):
            found.append(placeholder)
    return found


def suite_get(path: str) -> Any:
    context = ssl._create_unverified_context()  # noqa: S323 - the suite's local certificate is self-signed
    with urllib.request.urlopen(SUITE + path, context=context, timeout=10) as response:  # noqa: S310
        return json.load(response)


def suite_post(path: str, body: str) -> None:
    context = ssl._create_unverified_context()  # noqa: S323
    request = urllib.request.Request(
        SUITE + path, data=body.encode(), headers={"Content-Type": "text/plain"}, method="POST"
    )
    with urllib.request.urlopen(request, context=context, timeout=10):  # noqa: S310
        pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
