"""Shared harness plumbing: source-dir wiring, dev PKI, a TLS uvicorn server and an HTTP wallet.

Every suite imports this module first. It reads the cunho source directory from the environment
variable CUNHO_SRC (set by run_all; it defaults to the cunho checkout this file lives in) and puts
<src>/src and <src>/probe on sys.path, so the harness can be pointed at any checkout without
reinstalling. Scratch files (dev PKI, SQLite stores, server logs) go to CUNHO_STRESS_WORK, by
default tools/stress/_work, which git ignores.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

HARNESS_DIR = Path(__file__).resolve().parent
WORK_DIR = Path(os.environ.get("CUNHO_STRESS_WORK") or HARNESS_DIR / "_work").resolve()

# Load, race, chaos and soak traffic stands for many distinct wallets, but it all comes from 127.0.0.1.
# Those suites raise cunho's per-address limit out of the way; the attack suite keeps the default.
HIGH_RATE_LIMIT = 10_000_000


def source_dir() -> Path:
    src = os.environ.get("CUNHO_SRC")
    path = Path(src).resolve() if src else HARNESS_DIR.parents[1]
    if not (path / "src" / "cunho").is_dir():
        raise SystemExit(f"cunho source not found under {path} (set CUNHO_SRC)")
    return path


SRC = source_dir()
for p in (str(SRC / "src"), str(SRC / "probe")):
    if p not in sys.path:
        sys.path.insert(0, p)

# Third-party / cunho / probe imports (available once sys.path is wired).
import httpx  # noqa: E402

from eudi_probe.jose import EcKey, jws  # noqa: E402
from eudi_probe.wallet import AttestationIssuer, dpop_proof, key_proof  # noqa: E402

PID_CONFIG = "eu.europa.ec.eudi.pid_vc_sd_jwt"
PID_SCOPE = "eu.europa.ec.eudi.pid_vc_sd_jwt"
PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
# The authorization code flow: the wallet solution the dev PKI's m3/ wallet provider attests, its redirect URI,
# and a login service the harness never visits: it reports each login through the operator API, as a login
# service does.
CLIENT_ID = "https://wallet-solution.test"
REDIRECT_URI = "https://wallet.test/callback"
LOGIN_URL = "https://login.test/start"

PID_SUBJECT: dict[str, Any] = {
    "family_name": "Silva",
    "given_name": "Ana Maria",
    "birthdate": "1990-05-17",
    "place_of_birth": {"locality": "Porto", "country": "PT"},
    "nationalities": ["PT", "ES"],
    "address": {"locality": "Braga", "country": "PT", "postal_code": "4700-001"},
    "issuing_authority": "Instituto dos Registos e do Notariado",
    "issuing_country": "PT",
    "issuing_jurisdiction": "PT-03",
    "date_of_expiry": (dt.date.today() + dt.timedelta(days=5 * 365)).isoformat(),
}


class FlowError(Exception):
    """A step of the wallet flow got an unexpected HTTP answer; str() is 'step:status:body'."""

    def __init__(self, step: str, response: httpx.Response) -> None:
        self.status = response.status_code
        super().__init__(f"{step}:{response.status_code}:{response.text[:120]}")


# --------------------------------------------------------------------------- PKI / server


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def gen_pki(out: Path) -> Path:
    """Run the repo's own tools/dev_pki.py to produce a throwaway dev PKI."""
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(SRC / "src"), str(SRC / "probe")]))
    subprocess.run(
        [sys.executable, str(SRC / "tools" / "dev_pki.py"), str(out)],
        check=True,
        env=env,
        capture_output=True,
    )
    # Both wallet providers: the M2 one for key attestations, m3/'s for wallet attestations.
    for name in ("wallet-providers.pem", "wallet-providers.crl"):
        (out / f"all-{name}").write_bytes((out / name).read_bytes() + (out / "m3" / name).read_bytes())
    return out


def env_for(
    pki: Path,
    issuer_url: str,
    store_path: Path | None,
    *,
    dpop_nonce: bool = False,
    rate_limit: int | None = None,
    maintenance_interval: int | None = None,
) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(SRC / "src"), str(SRC / "probe")])
    env.update(
        CUNHO_ISSUER_URL=issuer_url,
        CUNHO_ADMIN_TOKEN=(pki / "admin-token").read_text().strip(),
        CUNHO_SIGNING_KEY=str(pki / "signing.key"),
        CUNHO_SIGNING_CHAIN=str(pki / "signing.pem"),
        CUNHO_STATUS_SIGNING_KEY=str(pki / "status.key"),
        CUNHO_STATUS_SIGNING_CHAIN=str(pki / "status.pem"),
        CUNHO_WALLET_PROVIDER_ANCHORS=str(pki / "all-wallet-providers.pem"),
        CUNHO_AUDIT_RETENTION_DAYS="365",
        CUNHO_SIGNER_CERTIFICATE_URL=f"{issuer_url}/certs/signer.pem",
        CUNHO_WALLET_PROVIDER_CRLS=str(pki / "all-wallet-providers.crl"),
        # M4: encrypted requests and responses offered, not required, so a suite may send either.
        CUNHO_ENCRYPTION_KEYS=str(pki / "encryption.key"),
        CUNHO_LOGIN_URL=LOGIN_URL,
        CUNHO_REDIRECT_URIS=json.dumps({CLIENT_ID: [REDIRECT_URI]}),
        # The suites read a status bit right after revoking it; the spread of revocations over time is
        # checked by the engine tests (test_review3_fixes, N3-M3). Lists are published every second, so a
        # revoked bit shows a second later at most (review 5, N5-M3).
        CUNHO_STATUS_REVOCATION_JITTER="0",
        CUNHO_STATUS_PUBLISH_INTERVAL="1",
    )
    if os.environ.get("CUNHO_STRESS_STORE_URL"):
        # The suites on PostgreSQL: every server of the run uses this database, as it would use its SQLite file.
        # cunho keeps its secret key and the audit anchor outside the database there; one pair per database.
        url = os.environ["CUNHO_STRESS_STORE_URL"]
        tag = hashlib.sha256(url.encode()).hexdigest()[:12]
        env["CUNHO_STORE_URL"] = url
        env["CUNHO_SECRET_KEY_FILE"] = str(pki / f"pg-{tag}.key")
        env["CUNHO_AUDIT_ANCHOR_PATH"] = str(pki / f"pg-{tag}.anchor")
        env.pop("CUNHO_STORE_PATH", None)
    elif store_path is not None:
        env["CUNHO_STORE_PATH"] = str(store_path)
    if dpop_nonce:
        env["CUNHO_DPOP_SERVER_NONCE"] = "true"
    if rate_limit is not None:
        env["CUNHO_RATE_LIMIT_PER_MINUTE"] = str(rate_limit)
        env["CUNHO_OPERATOR_RATE_LIMIT_PER_MINUTE"] = str(rate_limit)
        env["CUNHO_STATUS_RATE_LIMIT_PER_MINUTE"] = str(rate_limit)
    if maintenance_interval is not None:
        env["CUNHO_MAINTENANCE_INTERVAL"] = str(maintenance_interval)
    return env


@dataclass
class Server:
    pki: Path
    workers: int = 1
    store_path: Path | None = None
    dpop_nonce: bool = False
    rate_limit: int | None = None  # None keeps cunho's default
    maintenance_interval: int | None = None  # None keeps cunho's default (one hour)
    port: int = 0
    proc: subprocess.Popen | None = None
    issuer_url: str = ""
    _rss_samples: list[tuple[float, float]] = field(default_factory=list)
    _rss_stop: threading.Event = field(default_factory=threading.Event)
    _rss_thread: threading.Thread | None = None
    log_path: Path | None = None

    def start(self, timeout: float = 30.0) -> Server:
        self.port = self.port or free_port()
        self.issuer_url = f"https://localhost:{self.port}"
        env = env_for(
            self.pki,
            self.issuer_url,
            self.store_path,
            dpop_nonce=self.dpop_nonce,
            rate_limit=self.rate_limit,
            maintenance_interval=self.maintenance_interval,
        )
        cmd = [
            sys.executable,
            "-m",
            "uvicorn",
            "--factory",
            "cunho.app:create_app",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--ssl-keyfile",
            str(self.pki / "tls.key"),
            "--ssl-certfile",
            str(self.pki / "tls.pem"),
            "--log-level",
            "warning",
            "--no-access-log",
        ]
        if self.workers > 1:
            cmd += ["--workers", str(self.workers)]
        self.log_path = self.pki / f"uvicorn-{self.port}.log"
        logf = open(self.log_path, "wb")
        self.proc = subprocess.Popen(cmd, env=env, stdout=logf, stderr=subprocess.STDOUT)
        self._await_ready(timeout)
        self._start_rss()
        return self

    def _await_ready(self, timeout: float) -> None:
        deadline = time.time() + timeout
        url = f"{self.issuer_url}/.well-known/openid-credential-issuer"
        with httpx.Client(verify=False, timeout=3.0) as c:
            while time.time() < deadline:
                if self.proc and self.proc.poll() is not None:
                    log = self.log_path.read_text() if self.log_path else ""
                    raise SystemExit(f"server exited early (rc={self.proc.returncode}):\n{log[-2000:]}")
                try:
                    if c.get(url).status_code == 200:
                        return
                except Exception:
                    time.sleep(0.15)
        raise SystemExit("server did not become ready in time")

    # RSS of the whole process tree (master + workers) sampled on a background thread.
    def _start_rss(self) -> None:
        import psutil

        assert self.proc is not None
        root = psutil.Process(self.proc.pid)

        def loop() -> None:
            t0 = time.time()
            while not self._rss_stop.wait(0.5):
                try:
                    procs = [root, *root.children(recursive=True)]
                    rss = sum(p.memory_info().rss for p in procs if p.is_running())
                    self._rss_samples.append((round(time.time() - t0, 1), rss / 1_048_576))
                except Exception:
                    pass

        self._rss_thread = threading.Thread(target=loop, daemon=True)
        self._rss_thread.start()

    def rss_mb(self) -> list[tuple[float, float]]:
        return list(self._rss_samples)

    def admin_token(self) -> str:
        return (self.pki / "admin-token").read_text().strip()

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()

    def stop(self) -> None:
        self._rss_stop.set()
        if self._rss_thread:
            self._rss_thread.join(timeout=2)
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def __enter__(self) -> Server:
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


# --------------------------------------------------------------------------- HTTP wallet


def client(issuer_url: str, timeout: float = 10.0) -> httpx.Client:
    return httpx.Client(base_url=issuer_url, verify=False, timeout=timeout)


@dataclass
class Wallet:
    """A scripted wallet over real HTTP. Builds the artefacts a real wallet would send."""

    issuer_url: str
    pki: Path
    admin_token: str
    http: httpx.Client
    dpop_key: EcKey = field(default_factory=EcKey.generate)
    token: str | None = None
    last_subject_ref: str | None = None
    _attn: AttestationIssuer | None = None

    def attestation_issuer(self) -> AttestationIssuer:
        if self._attn is None:
            self._attn = AttestationIssuer.from_ca_files(
                self.pki / "wallet-providers.pem", self.pki / "wallet-provider.key"
            )
        return self._attn

    def create_offer(
        self, subject: dict | None = None, *, tx: int | None = None, configs: list[str] | None = None
    ) -> httpx.Response:
        return self.http.post(
            "/admin/offers",
            json={
                "credential_configuration_ids": configs or [PID_CONFIG],
                "subject": subject if subject is not None else PID_SUBJECT,
                "tx_code_length": tx,
            },
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )

    def dpop(self, method: str, path: str, **kw: Any) -> str:
        return dpop_proof(self.dpop_key, method, f"{self.issuer_url}{path}", **kw)

    def token_request(self, code: str, *, tx_code: str | None = None, dpop: str | None = "auto") -> httpx.Response:
        from urllib.parse import urlencode

        form = {"grant_type": PRE_AUTH, "pre-authorized_code": code}
        if tx_code is not None:
            form["tx_code"] = tx_code
        headers = [("Content-Type", "application/x-www-form-urlencoded")]
        proof = self.dpop("POST", "/token") if dpop == "auto" else dpop
        if proof:
            headers.append(("DPoP", proof))
        return self.http.post("/token", content=urlencode(form), headers=headers)

    def get_token(self, offer: dict | None = None) -> str:
        if offer is None:
            offer = self.offer()
        self.last_subject_ref = offer.get("subject_ref")
        r = self.token_request(offer_code(offer), tx_code=offer.get("tx_code"))
        if r.status_code != 200:
            raise FlowError("token", r)
        self.token = str(r.json()["access_token"])
        return self.token

    def offer(self, subject: dict | None = None, *, tx: int | None = None) -> dict:
        """Create an offer and return its JSON, or raise FlowError (e.g. 'offer:429:...')."""
        r = self.create_offer(subject, tx=tx)
        if r.status_code != 201:
            raise FlowError("offer", r)
        return dict(r.json())

    def nonce(self) -> str:
        r = self.http.post("/nonce")
        if r.status_code != 200:
            raise FlowError("nonce", r)
        return str(r.json()["c_nonce"])

    def proof(self, holder: EcKey, nonce: str) -> str:
        ka = self.attestation_issuer().key_attestation([holder], nonce=None)
        return key_proof(holder, self.issuer_url, nonce=nonce, key_attestation=ka)

    def credential_request(
        self, body: Any, *, dpop: str | None = "auto", content_type: str = "application/json", raw: bytes | None = None
    ) -> httpx.Response:
        assert self.token is not None
        headers = [("Authorization", f"DPoP {self.token}"), ("Content-Type", content_type)]
        proof = self.dpop("POST", "/credential", access_token=self.token) if dpop == "auto" else dpop
        if proof:
            headers.append(("DPoP", proof))
        content = raw if raw is not None else json.dumps(body).encode()
        return self.http.post("/credential", content=content, headers=headers)

    def full_flow(self) -> tuple[bool, str]:
        """Offer -> token -> nonce -> credential with a fresh holder key. Returns (ok, detail)."""
        try:
            self.get_token()
            nonce = self.nonce()
            holder = EcKey.generate()
            r = self.credential_request(
                {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [self.proof(holder, nonce)]}}
            )
            if r.status_code == 200 and "credentials" in r.json():
                return True, "issued"
            return False, f"credential:{r.status_code}:{r.text[:120]}"
        except FlowError as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001
            return False, f"exc:{type(exc).__name__}:{exc}"


@dataclass
class CodeWallet:
    """A wallet of the authorization code flow over real HTTP: a wallet attestation from the dev PKI's m3/ wallet
    provider and its proof of possession, PAR with PKCE and DPoP, the login reported through the operator API, and
    the code exchanged for an access token and a refresh token."""

    issuer_url: str
    pki: Path
    admin_token: str
    http: httpx.Client
    dpop_key: EcKey = field(default_factory=EcKey.generate)
    instance_key: EcKey = field(default_factory=EcKey.generate)
    token: str | None = None
    refresh_token: str | None = None
    subject_ref: str | None = None  # of the last login, as the login service's report returns it

    def attestation(self, **claims: Any) -> str:
        """A wallet instance attestation; a claim given as `...` is left out."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        chain = x509.load_pem_x509_certificates((self.pki / "m3" / "wia-signer.pem").read_bytes())
        key = serialization.load_pem_private_key((self.pki / "m3" / "wia-signer.key").read_bytes(), None)
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": "https://wallet-provider.test",
            "sub": CLIENT_ID,
            "iat": now,
            "exp": now + 3600,
            "cnf": {"jwk": self.instance_key.public_jwk()},
            "wallet_name": "cunho stress wallet",
            "wallet_version": "1.0.0",
            "client_status": {
                "status": {"status_list": {"idx": 3, "uri": "https://wallet-provider.test/status/wia"}},
                "exp": now + 60 * 86_400,
            },
        }
        payload.update(claims)
        x5c = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in chain]
        header = {"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": x5c}
        return jws(header, {k: v for k, v in payload.items() if v is not ...}, EcKey(key))  # type: ignore[arg-type]

    def pop(self, **claims: Any) -> str:
        payload = {"iss": CLIENT_ID, "aud": self.issuer_url, "jti": secrets.token_urlsafe(16), "iat": int(time.time())}
        payload.update(claims)
        return jws({"typ": "oauth-client-attestation-pop+jwt", "alg": "ES256"}, payload, self.instance_key)

    def attested(self, attestation: str | None = None, pop: str | None = None) -> list[tuple[str, str]]:
        return [
            ("OAuth-Client-Attestation", attestation or self.attestation()),
            ("OAuth-Client-Attestation-PoP", pop or self.pop()),
        ]

    def _form(self, path: str, form: dict[str, str], headers: list[tuple[str, str]]) -> httpx.Response:
        sent = [("Content-Type", "application/x-www-form-urlencoded"), ("DPoP", self.dpop("POST", path)), *headers]
        return self.http.post(path, content=urlencode(form), headers=sent)

    def dpop(self, method: str, path: str, **kw: Any) -> str:
        return dpop_proof(self.dpop_key, method, f"{self.issuer_url}{path}", **kw)

    def par(
        self, challenge: str, *, scope: str = PID_SCOPE, headers: list[tuple[str, str]] | None = None
    ) -> httpx.Response:
        form = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "stress",
            "scope": scope,
        }
        return self._form("/par", form, headers if headers is not None else self.attested())

    def authorize(self, request_uri: str) -> httpx.Response:
        query = urlencode({"client_id": CLIENT_ID, "request_uri": request_uri})
        return self.http.get(f"/authorize?{query}", follow_redirects=False)

    def report(self, login_state: str, body: dict[str, Any] | None = None) -> httpx.Response:
        """The login service's report: the person, at assurance level high."""
        sent = body if body is not None else {"subject": PID_SUBJECT, "loa": "high"}
        return self.http.post(
            f"/admin/logins/{login_state}", json=sent, headers={"Authorization": f"Bearer {self.admin_token}"}
        )

    def code_token(self, code: str, verifier: str) -> httpx.Response:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
        }
        return self._form("/token", form, self.attested())

    def refresh(self) -> httpx.Response:
        assert self.refresh_token is not None
        form = {"grant_type": "refresh_token", "refresh_token": self.refresh_token, "client_id": CLIENT_ID}
        return self._form("/token", form, self.attested())

    def login_state(self) -> tuple[str, str]:
        """PAR and the browser's visit to /authorize: the login_state the login service gets, and the verifier."""
        verifier = secrets.token_urlsafe(32)
        pushed = self.par(pkce_challenge(verifier))
        if pushed.status_code != 201:
            raise FlowError("par", pushed)
        sent = self.authorize(pushed.json()["request_uri"])
        if sent.status_code != 303:
            raise FlowError("authorize", sent)
        return parse_qs(urlsplit(sent.headers["location"]).query)["login_state"][0], verifier

    def code(self, *, review: bool = False) -> tuple[str, str]:
        """A login run to its end: the code the wallet's redirect URI receives, and the verifier. With `review`
        the operator holds what the login yields until it decides (deferred issuance, M4)."""
        login_state, verifier = self.login_state()
        reported = self.report(login_state, {"subject": PID_SUBJECT, "loa": "high", "review": True} if review else None)
        if reported.status_code != 200:
            raise FlowError("login", reported)
        self.subject_ref = reported.json()["subject_ref"]
        back = self.http.get(reported.json()["continue"], follow_redirects=False)
        if back.status_code != 303:
            raise FlowError("continue", back)
        return parse_qs(urlsplit(back.headers["location"]).query)["code"][0], verifier

    def get_token(self, *, review: bool = False) -> str:
        code, verifier = self.code(review=review)
        tokens = self.code_token(code, verifier)
        if tokens.status_code != 200:
            raise FlowError("token", tokens)
        self.token, self.refresh_token = tokens.json()["access_token"], tokens.json()["refresh_token"]
        return str(self.token)

    def deferred(self, transaction_id: str) -> httpx.Response:
        """The deferred credential endpoint, with the access token the wallet holds (OpenID4VCI 1.0 §9)."""
        headers = [
            ("Authorization", f"DPoP {self.token}"),
            ("DPoP", self.dpop("POST", "/deferred_credential", access_token=self.token)),
        ]
        return self.http.post("/deferred_credential", json={"transaction_id": transaction_id}, headers=headers)

    def notify(self, body: Any) -> httpx.Response:
        """The notification endpoint (OpenID4VCI 1.0 §11)."""
        headers = [
            ("Authorization", f"DPoP {self.token}"),
            ("DPoP", self.dpop("POST", "/notification", access_token=self.token)),
        ]
        return self.http.post("/notification", json=body, headers=headers)


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def new_code_wallet(server: Server, http: httpx.Client | None = None) -> CodeWallet:
    return CodeWallet(server.issuer_url, server.pki, server.admin_token(), http or client(server.issuer_url))


def offer_code(offer: dict) -> str:
    return str(offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"])


def is_server_error(detail: str) -> bool:
    """True for a full_flow detail that shows a 5xx answer or a transport failure."""
    parts = detail.split(":", 2)
    if parts[0] == "exc":
        return True
    return len(parts) > 1 and parts[1].isdigit() and int(parts[1]) >= 500


def new_wallet(server: Server, http: httpx.Client | None = None) -> Wallet:
    return Wallet(server.issuer_url, server.pki, server.admin_token(), http or client(server.issuer_url))


# --------------------------------------------------------------------------- result reporting


@dataclass
class Suite:
    name: str
    started: float = field(default_factory=time.time)
    checks: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def record(self, name: str, passed: bool, **detail: Any) -> bool:
        self.checks.append({"check": name, "pass": bool(passed), **detail})
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}" + (f"  {detail}" if detail else ""), flush=True)
        return passed

    def summary(self) -> dict:
        passed = sum(1 for c in self.checks if c["pass"])
        return {
            "suite": self.name,
            "passed": passed,
            "failed": len(self.checks) - passed,
            "total": len(self.checks),
            "ok": passed == len(self.checks),
            "duration_s": round(time.time() - self.started, 1),
            "meta": self.meta,
            "checks": self.checks,
        }

    def write(self, out_dir: Path) -> dict:
        out_dir.mkdir(parents=True, exist_ok=True)
        s = self.summary()
        (out_dir / f"{self.name}.json").write_text(json.dumps(s, indent=2, default=str))
        verdict = "PASS" if s["ok"] else "FAIL"
        print(f"\n=== {self.name}: {verdict} ({s['passed']}/{s['total']}) in {s['duration_s']}s ===", flush=True)
        return s


def percentiles(values: list[float], ps: tuple[int, ...] = (50, 95, 99)) -> dict[str, float]:
    if not values:
        return {f"p{p}": 0.0 for p in ps}
    s = sorted(values)
    out = {}
    for p in ps:
        k = min(len(s) - 1, int(round((p / 100) * (len(s) - 1))))
        out[f"p{p}"] = round(s[k] * 1000, 2)  # ms
    return out
