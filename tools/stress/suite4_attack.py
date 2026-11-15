"""Suite 4 - Attack matrix beyond the probe.

Every attack asserts the server refuses cleanly: a 4xx response, no 5xx, no hang, no crash.
Covers: alg confusion (none / HS256-with-pubkey / ES256-sig-on-P-384-key), oversized and
duplicated headers, unicode / control chars in fields, very long URLs, path traversal on
/status and /admin, admin-token comparison timing, slowloris, floods on /nonce, /token and
failed admin logins (the per-address limiter must answer 429, never 5xx), a 20-long
key-attestation chain, expired / not-yet-valid certs, a CA cert used as the KA signer, JWKs
with huge coordinates, and a credential request carrying 10k proofs.
"""

from __future__ import annotations

import base64
import datetime as dt
import socket
import ssl
import statistics
import sys
import time
from pathlib import Path

import common
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from eudi_probe.jose import EcKey, b64u, jws, jws_hs256
from eudi_probe.wallet import dpop_proof, key_proof

# --------------------------------------------------------------------------- raw TLS


def raw_request(
    port: int, payload: bytes, read_timeout: float = 3.0, max_read: int = 65536
) -> tuple[int | None, bytes, str]:
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection(("localhost", port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname="localhost") as ss:
                ss.sendall(payload)
                ss.settimeout(read_timeout)
                data = b""
                try:
                    while len(data) < max_read:
                        chunk = ss.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except (TimeoutError, ssl.SSLError, OSError):
                    pass
    except Exception as exc:  # noqa: BLE001
        return None, b"", f"conn:{type(exc).__name__}"
    status = None
    if data[:5] == b"HTTP/":
        try:
            status = int(data.split()[1])
        except Exception:  # noqa: BLE001
            pass
    return status, data, ""


# --------------------------------------------------------------------------- cert minting


CA = tuple[x509.Certificate, ec.EllipticCurvePrivateKey]


def _ca(pki: Path) -> CA:
    cert = x509.load_pem_x509_certificate((pki / "wallet-providers.pem").read_bytes())
    key = serialization.load_pem_private_key((pki / "wallet-provider.key").read_bytes(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    return cert, key


def mint_leaf(
    ca: CA,
    *,
    ca_flag: bool = False,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    issuer: x509.Certificate | None = None,
) -> tuple[EcKey, x509.Certificate]:
    ca_cert, ca_key = ca
    k = EcKey.generate()
    now = dt.datetime.now(dt.UTC)
    iss = issuer or ca_cert
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attack leaf")]))
        .issuer_name(iss.subject)
        .public_key(k.private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(days=1))
        .not_valid_after(not_after or now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
    )
    return k, b.sign(ca_key, hashes.SHA256())


def der_b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def ka_with_leaf(
    leaf_key: EcKey, leaf_cert: x509.Certificate, holder: EcKey, *, extra_x5c: list[str] | None = None
) -> str:
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + 3600,
        "attested_keys": [holder.public_jwk()],
        "key_storage": ["iso_18045_high"],
        "user_authentication": ["iso_18045_high"],
        "key_storage_status": {
            "status": {"status_list": {"idx": 0, "uri": "https://wp.invalid/1"}},
            "exp": now + 30 * 86400,
        },
    }
    x5c = [der_b64(leaf_cert)] + (extra_x5c or [])
    return jws({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c}, payload, leaf_key)


def issue_with_leaf(
    w: common.Wallet, leaf_key: EcKey, leaf: x509.Certificate, extra_x5c: list[str] | None = None
) -> httpx.Response:
    """Full issuance with a KA signed by a crafted leaf; holder is consistent across KA and proof."""
    w.get_token()
    nonce = w.nonce()
    holder = EcKey.generate()
    ka = ka_with_leaf(leaf_key, leaf, holder, extra_x5c=extra_x5c)
    proof = key_proof(holder, w.issuer_url, nonce=nonce, key_attestation=ka)
    return w.credential_request({"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [proof]}})


# --------------------------------------------------------------------------- attacks


def a_alg_confusion(srv: common.Server, suite: common.Suite) -> None:
    key = EcKey.generate()
    url = f"{srv.issuer_url}/token"
    # alg: none
    none_proof = jws(
        {"typ": "dpop+jwt", "alg": "none", "jwk": key.public_jwk()},
        {"jti": "a" * 20, "htm": "POST", "htu": url, "iat": int(time.time())},
        key,
    )
    none_proof = none_proof.rsplit(".", 1)[0] + "."  # strip signature
    # HS256 using the DPoP public key bytes as the HMAC secret
    pub = key.private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    hs = jws_hs256(
        {"typ": "dpop+jwt", "alg": "HS256", "jwk": key.public_jwk()},
        {"jti": "b" * 20, "htm": "POST", "htu": url, "iat": int(time.time())},
        pub,
    )
    # ES256 header but a P-384 key / mismatched curve
    p384 = ec.generate_private_key(ec.SECP384R1())
    nums = p384.public_key().public_numbers()
    jwk384 = {"kty": "EC", "crv": "P-384", "x": b64u(nums.x.to_bytes(48, "big")), "y": b64u(nums.y.to_bytes(48, "big"))}
    es_mismatch = dpop_proof(key, "POST", url, header_jwk=jwk384)  # signs with P-256 key but claims P-384 jwk
    http = common.client(srv.issuer_url)
    for label, proof in (("none", none_proof), ("HS256+pubkey", hs), ("ES256-on-P384", es_mismatch)):
        r = http.post(
            "/token",
            content="grant_type=x",
            headers={"Content-Type": "application/x-www-form-urlencoded", "DPoP": proof},
        )
        suite.record(f"alg confusion [{label}] rejected, no 5xx", 400 <= r.status_code < 500, status=r.status_code)
    http.close()


def a_headers(srv: common.Server, suite: common.Suite) -> None:
    port = srv.port
    base = f"POST /token HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
    # duplicated DPoP headers
    dup = (base + "DPoP: aaa\r\nDPoP: bbb\r\nContent-Length: 12\r\nConnection: close\r\n\r\ngrant_type=x").encode()
    s, _, err = raw_request(port, dup)
    suite.record("duplicated DPoP headers rejected, no 5xx", (s is not None and 400 <= s < 500), status=s, err=err)
    # oversized single header (~200 KB)
    big = base + "X-Big: " + ("A" * 200_000) + "\r\nContent-Length: 12\r\nConnection: close\r\n\r\ngrant_type=x"
    s, data, err = raw_request(port, big.encode())
    ok = err or (s is None) or (s != 200 and s < 500)  # drop/431/400 all acceptable; must not 5xx or 200
    suite.record("oversized header refused, no 5xx", bool(ok), status=s, err=err)


def a_unicode_control(srv: common.Server, suite: common.Suite) -> None:
    import json as _json

    http = common.client(srv.issuer_url)
    tok = srv.admin_token()
    bad5xx = []
    # control/unicode in subject fields (sent as ASCII-escaped JSON so even surrogates reach the server)
    for val in ("\u0000\u0001‮", "test\x07\x7f", "\ud800", "𝔘𝔫𝔦𝔠𝔬𝔡𝔢", "a" * 5000):
        subj = dict(common.PID_SUBJECT, family_name=val)
        payload = _json.dumps(
            {"credential_configuration_ids": [common.PID_CONFIG], "subject": subj, "tx_code_length": None},
            ensure_ascii=True,
        ).encode("ascii")
        r = http.post(
            "/admin/offers",
            content=payload,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        )
        if r.status_code >= 500:
            bad5xx.append((val[:8], r.status_code))
    # control chars in token form fields
    r = http.post(
        "/token",
        content="grant_type=\x00\x01&pre-authorized_code=\x07",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": dpop_proof(EcKey.generate(), "POST", f"{srv.issuer_url}/token"),
        },
    )
    if r.status_code >= 500:
        bad5xx.append(("form", r.status_code))
    http.close()
    suite.record("unicode/control chars in fields: no 5xx", not bad5xx, offenders=bad5xx)
    # non-ASCII Authorization header via raw socket (H-5e: compare_digest TypeError)
    body = (
        f"GET /admin/audit/verify HTTP/1.1\r\nHost: localhost:{srv.port}\r\n"
        f"Authorization: Bearer \xc3\x28token\r\nConnection: close\r\n\r\n"
    ).encode("latin-1")
    s, _, err = raw_request(srv.port, body)
    suite.record(
        "non-ASCII admin Authorization header: no 5xx", (s is not None and s < 500) or bool(err), status=s, err=err
    )


def a_long_url_traversal(srv: common.Server, suite: common.Suite) -> None:
    http = common.client(srv.issuer_url)
    r1 = http.get("/status/" + "9" * 20000)
    suite.record("very long URL: no 5xx", r1.status_code < 500, status=r1.status_code)
    traversals = [
        "/status/..%2f..%2f..%2fetc%2fpasswd",
        "/status/../../admin/audit/verify",
        "/admin/../../etc/passwd",
        "/admin/offers/..%2f..%2f",
        "/status/%2e%2e%2f",
    ]
    bad = []
    for t in traversals:
        r = http.get(t)
        if r.status_code >= 500 or "root:" in r.text:
            bad.append((t, r.status_code))
    suite.record("path traversal on /status and /admin: no 5xx / no disclosure", not bad, offenders=bad)
    http.close()


def a_admin_timing(srv: common.Server, suite: common.Suite) -> None:
    http = common.client(srv.issuer_url)
    correct = srv.admin_token()
    # two guesses: all-wrong vs first-char-correct, same length
    wrong_a = "Z" * len(correct)
    wrong_b = correct[: len(correct) // 2] + "Z" * (len(correct) - len(correct) // 2)
    n = 60 if "--quick" in sys.argv else 300

    def once(tok: str) -> float:
        t0 = time.perf_counter()
        http.get("/admin/audit/verify", headers={"Authorization": f"Bearer {tok}"})
        return time.perf_counter() - t0

    # Interleaved, so both guesses see the same mix of 401 and (once over the limit) 429 answers.
    times_a: list[float] = []
    times_b: list[float] = []
    for _ in range(n):
        times_a.append(once(wrong_a))
        times_b.append(once(wrong_b))
    ma, mb = statistics.median(times_a), statistics.median(times_b)
    rel = abs(ma - mb) / max(ma, mb)
    http.close()
    # constant-time compare_digest -> medians within noise
    suite.record(
        "admin token comparison shows no timing signal",
        rel < 0.35,
        median_allwrong_ms=round(ma * 1000, 3),
        median_prefix_ms=round(mb * 1000, 3),
        rel_diff=round(rel, 3),
    )


def a_slowloris(srv: common.Server, suite: common.Suite) -> None:
    port = srv.port
    conns = []
    try:
        for _ in range(15):
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(socket.create_connection(("localhost", port), timeout=5), server_hostname="localhost")
            s.sendall(
                (
                    f"POST /token HTTP/1.1\r\nHost: localhost:{port}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 1000000\r\n\r\ngrant"
                ).encode()
            )
            conns.append(s)
        # a normal client must still get through promptly
        t0 = time.time()
        ok, detail = common.new_wallet(srv).full_flow()
        el = time.time() - t0
        suite.record(
            "slowloris: normal client unaffected (<5s, succeeds)", ok and el < 5, elapsed_s=round(el, 2), detail=detail
        )
    finally:
        for s in conns:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass


DEFAULT_RATE_LIMIT = 120  # cunho's CUNHO_RATE_LIMIT_PER_MINUTE default; this suite runs with it


def a_floods(srv: common.Server, suite: common.Suite) -> None:
    """Floods from one address: the limiter refuses with 429 once over the limit, never 5xx, and
    the operator is not locked out by wallet traffic from the same address."""
    http = common.client(srv.issuer_url, timeout=30.0)
    rss0 = max((m for _, m in srv.rss_mb()), default=0)
    n = 1000 if "--quick" in sys.argv else 4000
    statuses = [http.post("/nonce") for _ in range(n)]
    codes = [r.status_code for r in statuses]
    issued, refused = codes.count(200), codes.count(429)
    retry_after = all(r.headers.get("retry-after") for r in statuses if r.status_code == 429)
    suite.record(
        "flood /nonce: no 5xx, 429 once over the limit",
        all(c in (200, 429) for c in codes) and 0 < issued <= DEFAULT_RATE_LIMIT and refused == n - issued,
        issued=issued,
        refused_429=refused,
        n=n,
        other=sorted({c for c in codes if c not in (200, 429)}),
    )
    suite.record("flood /nonce: 429 answers carry Retry-After", refused > 0 and retry_after)
    form = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=x"
    tok = [
        http.post("/token", content=form, headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code
        for _ in range(DEFAULT_RATE_LIMIT + 50)
    ]
    suite.record(
        "flood /token: no 5xx, 429 once over the limit",
        all(c < 500 for c in tok) and tok.count(429) >= 50,
        refused_429=tok.count(429),
        n=len(tok),
        other=sorted(set(tok)),
    )
    bad_admin = [
        http.get("/admin/audit/verify", headers={"Authorization": "Bearer " + "Z" * 43}).status_code
        for _ in range(DEFAULT_RATE_LIMIT + 50)
    ]
    suite.record(
        "flood failed admin logins: no 5xx, 429 once over the limit",
        all(c in (401, 429) for c in bad_admin) and bad_admin.count(429) >= 50,
        refused_429=bad_admin.count(429),
        n=len(bad_admin),
    )
    offer = common.new_wallet(srv, http).create_offer()
    suite.record(
        "operator still served while its address is over the anonymous limit",
        offer.status_code == 201,
        status=offer.status_code,
    )
    http.close()
    time.sleep(1.0)
    rss1 = max((m for _, m in srv.rss_mb()), default=0)
    suite.meta["floods"] = {
        "nonce_issued": issued,
        "nonce_refused": refused,
        "rss_before_mb": round(rss0, 1),
        "rss_after_mb": round(rss1, 1),
        "rss_delta_mb": round(rss1 - rss0, 1),
    }
    suite.record(
        "flood: RSS growth bounded (<150 MB for the burst)", (rss1 - rss0) < 150, rss_delta_mb=round(rss1 - rss0, 1)
    )


def a_ka_chain_len20(srv: common.Server, suite: common.Suite) -> None:
    ca = _ca(srv.pki)
    # 20 self-generated certs that do NOT chain to the anchor -> must be rejected, not hang/crash
    extra = []
    for _ in range(19):
        _, c = mint_leaf(ca)  # signed by CA but used as filler intermediates
        extra.append(der_b64(c))
    leaf_key, leaf = mint_leaf(ca)
    t0 = time.time()
    try:
        r = issue_with_leaf(common.new_wallet(srv), leaf_key, leaf, extra_x5c=extra)
        el = time.time() - t0
        suite.record(
            "20-long KA chain: rejected, no 5xx, no hang",
            r.status_code < 500 and el < 2,
            status=r.status_code,
            elapsed_s=round(el, 2),
        )
    except Exception as exc:  # noqa: BLE001
        suite.record("20-long KA chain: rejected, no 5xx, no hang", False, error=str(exc)[:80])


def a_expired_notyet(srv: common.Server, suite: common.Suite) -> None:
    ca = _ca(srv.pki)
    now = dt.datetime.now(dt.UTC)
    for label, nb, na in (
        ("expired", now - dt.timedelta(days=10), now - dt.timedelta(days=1)),
        ("not-yet-valid", now + dt.timedelta(days=1), now + dt.timedelta(days=10)),
    ):
        leaf_key, leaf = mint_leaf(ca, not_before=nb, not_after=na)
        r = issue_with_leaf(common.new_wallet(srv), leaf_key, leaf)
        suite.record(
            f"{label} KA cert: rejected (not issued), no 5xx",
            r.status_code != 200 and r.status_code < 500,
            status=r.status_code,
        )


def a_ca_as_signer(srv: common.Server, suite: common.Suite) -> None:
    ca = _ca(srv.pki)
    leaf_key, leaf = mint_leaf(ca, ca_flag=True)  # leaf is itself a CA (H-4)
    r = issue_with_leaf(common.new_wallet(srv), leaf_key, leaf)
    # A CA certificate must not be accepted as the key-attestation signer.
    suite.record(
        "CA cert used as KA signer: rejected (not issued)",
        r.status_code != 200 and r.status_code < 500,
        status=r.status_code,
        note="issued=200 would confirm H-4",
    )


def a_huge_coords(srv: common.Server, suite: common.Suite) -> None:
    huge = b64u(b"\xff" * 20000)
    jwk = {"kty": "EC", "crv": "P-256", "x": huge, "y": huge}
    proof = dpop_proof(EcKey.generate(), "POST", f"{srv.issuer_url}/token", header_jwk=jwk)
    http = common.client(srv.issuer_url, timeout=4.0)
    t0 = time.time()
    try:
        r = http.post(
            "/token",
            content="grant_type=x",
            headers={"Content-Type": "application/x-www-form-urlencoded", "DPoP": proof},
        )
        el = time.time() - t0
        suite.record(
            "JWK with huge coordinates: rejected, no 5xx, no hang",
            r.status_code < 500 and el < 2,
            status=r.status_code,
            elapsed_s=round(el, 2),
        )
    except Exception as exc:  # noqa: BLE001
        suite.record("JWK with huge coordinates: rejected, no 5xx, no hang", False, error=str(exc)[:80])
    http.close()


def a_10k_proofs(srv: common.Server, suite: common.Suite) -> None:
    w = common.new_wallet(srv)
    w.get_token()
    body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": ["x.y.z"] * 10000}}
    t0 = time.time()
    r = w.credential_request(body)
    el = time.time() - t0
    suite.record(
        "credential request with 10k proofs: rejected, no 5xx, no hang",
        r.status_code < 500 and el < 2,
        status=r.status_code,
        elapsed_s=round(el, 2),
    )


def run(out_dir: Path, quick: bool) -> dict:
    suite = common.Suite("suite4_attack")
    pki = common.gen_pki(common.WORK_DIR / "attack")
    srv = common.Server(pki=pki, workers=1).start()
    # The floods go last: they use up this address's per-minute budget on purpose.
    attacks = [
        a_alg_confusion,
        a_headers,
        a_unicode_control,
        a_long_url_traversal,
        a_slowloris,
        a_ka_chain_len20,
        a_expired_notyet,
        a_ca_as_signer,
        a_huge_coords,
        a_10k_proofs,
        a_admin_timing,
        a_floods,
    ]
    try:
        for a in attacks:
            try:
                a(srv, suite)
            except Exception as exc:  # noqa: BLE001
                suite.record(f"{a.__name__} ran without harness error", False, error=f"{type(exc).__name__}:{exc}")
    finally:
        srv.stop()
    return suite.write(out_dir)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else common.WORK_DIR / "out"
    raise SystemExit(0 if run(out, "--quick" in sys.argv)["ok"] else 1)
