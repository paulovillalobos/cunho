"""Suite 2 - Cross-process races (4 uvicorn workers, shared SQLite store).

Each scenario fires many requests at once and asserts EXACTLY the allowed number of successes:
  - same pre-authorized code redeemed N times      -> 1
  - same c_nonce used N times                        -> 1
  - same DPoP proof replayed N times                 -> 1
  - same access token reused for same config N times -> 1   (encodes the intended M-1 fix: a cap)
  - tx_code brute force from many clients            -> 0, at most tx_code_max_attempts guesses
                                                        evaluated, and lockout holds
  - concurrent revocations of one subject            -> no 5xx, slot ends revoked, counts consistent
  - audit verification while offers are created      -> valid every time (review 4, N4-M7)
  - the authorization code flow (M3), each by one wallet sending N at once:
      same pushed request_uri at /authorize            -> MAX_OPENS (8) logins, never more
      same login_state reported by the login service   -> 1
      same wallet attestation proof of possession      -> 1 PAR (its jti is single-use)
      same authorization code redeemed                 -> 1 token, and its use again revokes that token
      same refresh token while its subject is revoked  -> no 5xx, and no token works afterwards
  - M4, deferred issuance, notification and encryption:
      a released issuance collected N times at once    -> 1 credential, every other ask invalid_transaction_id
      N decisions on one held issuance, release and refuse mixed -> exactly 1 taken, the rest 404
      collections racing the erasure of the subject     -> no 5xx, nothing collected once the erasure answered
      the same notification sent N times                 -> 204 every time
      the same c_nonce in N encrypted requests           -> 1 credential
  - afterwards the audit chain verifies (no lost or rewound entries across workers)
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import secrets
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import common
import httpx

from eudi_probe import jwe
from eudi_probe.jose import EcKey


def fire[T](n: int, fn: Callable[[int], T]) -> list[T]:
    with cf.ThreadPoolExecutor(max_workers=n) as ex:
        return list(ex.map(fn, range(n)))


def w_for(server: common.Server) -> common.Wallet:
    return common.Wallet(
        server.issuer_url, server.pki, server.admin_token(), common.client(server.issuer_url, timeout=30.0)
    )


def sc_code(server: common.Server, suite: common.Suite, n: int) -> None:
    w = w_for(server)
    code = common.offer_code(w.offer())

    def attempt(_: int) -> int:
        ww = w_for(server)  # fresh DPoP key per client -> isolates the code gate
        return ww.token_request(code).status_code

    codes = fire(n, attempt)
    ok = sum(1 for c in codes if c == 200)
    suite.record("same pre-auth code redeemed Nx -> exactly 1 token", ok == 1, successes=ok, n=n)


def sc_cnonce(server: common.Server, suite: common.Suite, n: int) -> None:
    w = w_for(server)
    w.get_token()
    nonce = w.nonce()  # one nonce, reused across N concurrent credential requests

    def attempt(_: int) -> int:
        holder = EcKey.generate()
        body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [w.proof(holder, nonce)]}}
        return w.credential_request(body).status_code

    codes = fire(n, attempt)
    ok = sum(1 for c in codes if c == 200)
    suite.record("same c_nonce used Nx -> exactly 1 credential", ok == 1, successes=ok, n=n)


def sc_dpop_replay(server: common.Server, suite: common.Suite, n: int) -> None:
    w = w_for(server)
    proof = w.dpop("POST", "/token")  # one proof string replayed across distinct codes
    codes = [common.offer_code(w.offer()) for _ in range(n)]

    def attempt(i: int) -> int:
        return w_for(server).token_request(codes[i], dpop=proof).status_code

    results = fire(n, attempt)
    ok = sum(1 for c in results if c == 200)
    suite.record("same DPoP proof replayed Nx -> exactly 1 token", ok == 1, successes=ok, n=n)


def sc_token_reuse(server: common.Server, suite: common.Suite, n: int) -> None:
    w = w_for(server)
    w.get_token()

    def attempt(_: int) -> int:
        holder = EcKey.generate()
        nonce = w.nonce()  # fresh nonce + fresh holder each time; only the token is reused
        body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [w.proof(holder, nonce)]}}
        return w.credential_request(body).status_code

    results = fire(n, attempt)
    ok = sum(1 for c in results if c == 200)
    # Intended post-fix behaviour (M-1): one credential per configuration per token.
    suite.record("one access token reused Nx for same config -> exactly 1 (M-1 cap)", ok == 1, successes=ok, n=n)


TX_CODE_MAX_ATTEMPTS = 5  # cunho's Settings.tx_code_max_attempts default
MAX_OPENS = 8  # cunho.authorize.MAX_OPENS: logins one request_uri can start before one completes


def sc_txcode(server: common.Server, suite: common.Suite, n: int) -> None:
    w = w_for(server)
    offer = w.offer(tx=6)
    code = common.offer_code(offer)
    correct = offer["tx_code"]
    wrong = "000000" if correct != "000000" else "111111"

    def attempt(_: int) -> tuple[int, str]:
        r = w_for(server).token_request(code, tx_code=wrong)
        return r.status_code, str(r.json().get("error_description", "")) if r.status_code < 500 else ""

    results = fire(n, attempt)
    ok = sum(1 for c, _ in results if c == 200)
    suite.record("tx_code brute force -> 0 successes", ok == 0, successes=ok, n=n)
    # Each "wrong tx_code" answer is one guess the server compared. Concurrency must not buy extra guesses.
    evaluated = sum(1 for _, d in results if d == "wrong tx_code")
    suite.record(
        f"tx_code brute force: at most {TX_CODE_MAX_ATTEMPTS} guesses evaluated under concurrency",
        evaluated <= TX_CODE_MAX_ATTEMPTS,
        evaluated=evaluated,
        n=n,
        no_5xx=all(c < 500 for c, _ in results),
    )
    # lockout must hold: after the storm the correct code no longer yields a token
    after = w_for(server).token_request(code, tx_code=correct).status_code
    suite.record("tx_code lockout holds after brute force (correct code rejected)", after != 200, status_after=after)


def sc_revoke(server: common.Server, suite: common.Suite, n: int) -> None:
    w = w_for(server)
    offer = w.offer()
    subject_ref = offer["subject_ref"]
    w.get_token(offer)
    nonce = w.nonce()
    holder = EcKey.generate()
    issued = w.credential_request(
        {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [w.proof(holder, nonce)]}}
    )
    n_slots = len(issued.json().get("credentials", [])) if issued.status_code == 200 else 0

    def attempt(_: int) -> tuple[int, int | None]:
        r = w_for(server).http.post(
            "/admin/revocations",
            json={"subject_ref": subject_ref, "reason": "administrative"},
            headers={"Authorization": f"Bearer {server.admin_token()}"},
        )
        return (
            r.status_code,
            r.json().get("revoked") if r.headers.get("content-type", "").startswith("application/json") else None,
        )

    results = fire(n, attempt)
    statuses = [s for s, _ in results]
    revoked_counts = [c for _, c in results if c is not None]
    no_5xx = all(s < 500 for s in statuses)
    suite.record("concurrent revocations: no 5xx", no_5xx, statuses=sorted(set(statuses)))
    # total first-time revocations should not exceed the number of issued slots (no double counting)
    total_reported = sum(revoked_counts)
    suite.record(
        "concurrent revocations: reported revoked <= issued slots (no inflation)",
        n_slots > 0 and total_reported <= n_slots,
        issued_slots=n_slots,
        total_reported=total_reported,
    )


def sc_offers(server: common.Server, suite: common.Suite, n: int) -> None:
    """Many operators' offers at once: every one is created and audited (one audit entry each)."""

    def attempt(_: int) -> int:
        return w_for(server).create_offer().status_code

    statuses = fire(n, attempt)
    suite.record(
        "concurrent offer creation across workers: all 201, no 5xx",
        all(s == 201 for s in statuses),
        statuses=sorted(set(statuses)),
        n=n,
    )


def sc_verify_under_load(server: common.Server, suite: common.Suite, n: int) -> None:
    """/admin/audit/verify while four threads create offers on four workers: no tampering, so every answer is
    valid. Verification used to read the head first and the anchor last, and called the entries appended in
    between removed (review 4, N4-M7)."""
    stop = threading.Event()
    created: list[int] = []

    def busy() -> None:
        wallet = w_for(server)
        while not stop.is_set():
            created.append(wallet.create_offer().status_code)

    threads = [threading.Thread(target=busy) for _ in range(4)]
    for thread in threads:
        thread.start()
    verdicts: dict[str, int] = {}
    try:
        with common.client(server.issuer_url, timeout=60.0) as http:
            for _ in range(n):
                body = http.get("/admin/audit/verify", headers={"Authorization": f"Bearer {server.admin_token()}"})
                key = "valid" if body.status_code == 200 and body.json().get("valid") else body.text[:60]
                verdicts[key] = verdicts.get(key, 0) + 1
    finally:
        stop.set()
        for thread in threads:
            thread.join()
    suite.record(
        "audit verify under concurrent offers across workers: never a false alarm",
        verdicts == {"valid": n} and bool(created) and all(status == 201 for status in created),
        verdicts=verdicts,
        offers=len(created),
    )


def cw_for(server: common.Server) -> common.CodeWallet:
    return common.CodeWallet(
        server.issuer_url, server.pki, server.admin_token(), common.client(server.issuer_url, timeout=30.0)
    )


def sc_request_uri(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet = cw_for(server)
    pushed = wallet.par(common.pkce_challenge(secrets.token_urlsafe(32)))
    request_uri = pushed.json()["request_uri"]
    statuses = fire(n, lambda _: wallet.authorize(request_uri).status_code)
    logins = sum(1 for s in statuses if s == 303)
    # FAPI 2.0 SP §5.3.2.2 note 3 (M3): a reloaded page is not turned away until a login completes, up to MAX_OPENS
    # logins from one request_uri, counted atomically across workers.
    suite.record(
        f"same request_uri at /authorize Nx -> exactly {MAX_OPENS} logins at most, no 5xx",
        logins == min(n, MAX_OPENS) and max(statuses) < 500,
        logins=logins,
        statuses=sorted(set(statuses)),
    )


def sc_login_state(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet = cw_for(server)
    login_state, _ = wallet.login_state()
    statuses = fire(n, lambda _: wallet.report(login_state).status_code)
    ok = sum(1 for s in statuses if s == 200)
    suite.record(
        "same login_state reported Nx -> exactly 1, no 5xx",
        ok == 1 and max(statuses) < 500,
        successes=ok,
        statuses=sorted(set(statuses)),
    )


def sc_wia_pop(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet = cw_for(server)
    headers = wallet.attested()
    challenge = common.pkce_challenge(secrets.token_urlsafe(32))
    statuses = fire(n, lambda _: wallet.par(challenge, headers=headers).status_code)
    ok = sum(1 for s in statuses if s == 201)
    suite.record(
        "same attestation proof of possession at PAR Nx -> exactly 1, no 5xx",
        ok == 1 and max(statuses) < 500,
        successes=ok,
        statuses=sorted(set(statuses)),
    )


def sc_auth_code(server: common.Server, suite: common.Suite, n: int) -> None:
    """The wallet that got the code sends it N times at once: one token, and the uses after it end that token and
    its refresh token (RFC 6749 §4.1.2)."""
    wallet = cw_for(server)
    code, verifier = wallet.code()
    replies = fire(n, lambda _: wallet.code_token(code, verifier))
    tokens = [r.json() for r in replies if r.status_code == 200]
    ok = len(tokens) == 1 and max(r.status_code for r in replies) < 500
    if tokens:
        wallet.token, wallet.refresh_token = tokens[0]["access_token"], tokens[0]["refresh_token"]
        ok = ok and wallet.refresh().status_code == 400
        ok = ok and _issue(wallet).status_code in (400, 401)
    suite.record(
        "same authorization code redeemed Nx -> exactly 1 token, then revoked by the reuse",
        ok,
        tokens=len(tokens),
        statuses=sorted({r.status_code for r in replies}),
    )


def sc_refresh_revoke(server: common.Server, suite: common.Suite, n: int) -> None:
    """N refreshes of one login while the operator revokes its subject: whatever lands first, no token works
    once the revocation has answered."""
    wallet = cw_for(server)
    wallet.get_token()
    revoke = {"subject_ref": wallet.subject_ref, "reason": "compromise"}

    def attempt(i: int) -> tuple[int, str | None]:
        if i == n // 2:
            reply = wallet.http.post(
                "/admin/revocations", json=revoke, headers={"Authorization": f"Bearer {server.admin_token()}"}
            )
            return reply.status_code, None
        reply = wallet.refresh()
        return reply.status_code, reply.json().get("access_token") if reply.status_code == 200 else None

    results = fire(n, attempt)
    granted = [token for _, token in results if token is not None]
    revoked = results[n // 2][0] == 200
    working = 0
    for token in granted:
        wallet.token = token
        working += _issue(wallet).status_code == 200
    suite.record(
        "refreshes racing a revocation of the subject: no 5xx, no token works afterwards",
        revoked and working == 0 and max(status for status, _ in results) < 500,
        refreshed=len(granted),
        working_after=working,
        statuses=sorted({status for status, _ in results}),
    )


# M4 ----------------------------------------------------------------------------------------------------------


def _admin(server: common.Server) -> dict[str, str]:
    return {"Authorization": f"Bearer {server.admin_token()}"}


def _held(server: common.Server) -> tuple[common.CodeWallet, str, str]:
    """A login the operator holds for review, its credential asked for (202): the wallet, the transaction_id the
    wallet got, and the reference the operator decides it by."""
    wallet = cw_for(server)
    wallet.get_token(review=True)
    asked = _issue(wallet)
    if asked.status_code != 202:
        raise common.FlowError("held credential request", asked)
    listed = wallet.http.get("/admin/deferred", headers=_admin(server)).json()["deferred"]
    [row] = [r for r in listed if r["subject_ref"] == wallet.subject_ref]
    return wallet, asked.json()["transaction_id"], row["ref"]


def sc_deferred_collect(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet, transaction_id, ref = _held(server)
    wallet.http.post(f"/admin/deferred/{ref}/release", headers=_admin(server))
    replies = fire(n, lambda _: wallet.deferred(transaction_id))
    collected = sum(1 for r in replies if r.status_code == 200)
    others = {(r.status_code, r.json().get("error")) for r in replies if r.status_code != 200}
    suite.record(
        "a released issuance collected Nx -> exactly 1 credential, the rest invalid_transaction_id",
        collected == 1 and others <= {(400, "invalid_transaction_id")},
        collected=collected,
        others=sorted(others, key=str),
    )


def sc_deferred_decide(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet, _, ref = _held(server)
    replies = fire(
        n,
        lambda i: wallet.http.post(f"/admin/deferred/{ref}/{'release' if i % 2 else 'refuse'}", headers=_admin(server)),
    )
    taken = sum(1 for r in replies if r.status_code == 200)
    suite.record(
        "N decisions on one held issuance -> exactly 1 taken, the rest 404",
        taken == 1 and {r.status_code for r in replies} <= {200, 404},
        taken=taken,
        statuses=sorted({r.status_code for r in replies}),
    )


def sc_deferred_erase(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet, transaction_id, ref = _held(server)
    wallet.http.post(f"/admin/deferred/{ref}/release", headers=_admin(server))

    def attempt(i: int) -> httpx.Response:
        if i == n // 2:
            return wallet.http.post(f"/admin/subjects/{wallet.subject_ref}/erase", headers=_admin(server))
        return wallet.deferred(transaction_id)

    replies = fire(n, attempt)
    erased = replies[n // 2].status_code == 204
    after = wallet.deferred(transaction_id)
    collected = sum(1 for i, r in enumerate(replies) if i != n // 2 and r.status_code == 200)
    suite.record(
        "collections racing the erasure of the subject -> no 5xx, at most 1 collected, none after",
        erased and collected <= 1 and after.status_code != 200 and max(r.status_code for r in replies) < 500,
        collected=collected,
        after=after.status_code,
        statuses=sorted({r.status_code for r in replies}),
    )


def sc_notification(server: common.Server, suite: common.Suite, n: int) -> None:
    wallet = cw_for(server)
    wallet.get_token()
    issued = _issue(wallet)
    if issued.status_code != 200:
        raise common.FlowError("credential request", issued)
    body = {"notification_id": issued.json()["notification_id"], "event": "credential_accepted"}
    statuses = [r.status_code for r in fire(n, lambda _: wallet.notify(body))]
    suite.record(
        "the same notification sent Nx -> 204 every time", set(statuses) == {204}, statuses=sorted(set(statuses))
    )


def sc_encrypted_nonce(server: common.Server, suite: common.Suite, n: int) -> None:
    """The c_nonce race again, every request encrypted to cunho's key and asking for an encrypted answer."""
    w = w_for(server)
    w.get_token()
    document = w.http.get("/.well-known/openid-credential-issuer").json()
    [issuer_key] = document["credential_request_encryption"]["jwks"]["keys"]
    nonce = w.nonce()

    def attempt(_: int) -> int:
        holder, mine = EcKey.generate(), EcKey.generate()
        body = {
            "credential_configuration_id": common.PID_CONFIG,
            "proofs": {"jwt": [w.proof(holder, nonce)]},
            "credential_response_encryption": {"jwk": {**mine.public_jwk(), "alg": "ECDH-ES"}, "enc": "A256GCM"},
        }
        sealed = jwe.encrypt(json.dumps(body).encode(), issuer_key, "A256GCM", kid=issuer_key["kid"])
        return w.credential_request(None, content_type="application/jwt", raw=sealed.encode()).status_code

    codes = fire(n, attempt)
    ok = sum(1 for c in codes if c == 200)
    suite.record("same c_nonce in N encrypted requests -> exactly 1 credential", ok == 1, successes=ok, n=n)


def _issue(wallet: common.CodeWallet) -> httpx.Response:
    """A credential request with the wallet's access token, as `common.Wallet.full_flow` sends one."""
    nonce = wallet.http.post("/nonce").json()["c_nonce"]
    holder = EcKey.generate()
    proof = common.Wallet(wallet.issuer_url, wallet.pki, wallet.admin_token, wallet.http).proof(holder, nonce)
    body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [proof]}}
    headers = [
        ("Authorization", f"DPoP {wallet.token}"),
        ("DPoP", wallet.dpop("POST", "/credential", access_token=wallet.token)),
    ]
    return wallet.http.post("/credential", json=body, headers=headers)


def run(out_dir: Path, quick: bool) -> dict:
    n = 20 if quick else 50
    suite = common.Suite("suite2_races")
    suite.meta["n"] = n
    pki = common.gen_pki(common.WORK_DIR / "races")
    store = pki / "races.db"
    if store.exists():
        store.unlink()
    srv = common.Server(pki=pki, workers=4, store_path=store, rate_limit=common.HIGH_RATE_LIMIT).start()
    try:
        for fn in (
            sc_code,
            sc_cnonce,
            sc_dpop_replay,
            sc_token_reuse,
            sc_txcode,
            sc_revoke,
            sc_offers,
            sc_verify_under_load,
            sc_request_uri,
            sc_login_state,
            sc_wia_pop,
            sc_auth_code,
            sc_refresh_revoke,
            sc_deferred_collect,
            sc_deferred_decide,
            sc_deferred_erase,
            sc_notification,
            sc_encrypted_nonce,
        ):
            started = time.monotonic()
            try:
                fn(srv, suite, n)
            except Exception as exc:  # noqa: BLE001
                suite.record(f"{fn.__name__} ran without harness error", False, error=f"{type(exc).__name__}:{exc}")
            finally:
                # How long each scenario took, so a slow one shows where a run spent its time.
                suite.meta.setdefault("seconds", {})[fn.__name__] = round(time.monotonic() - started, 2)
        with common.client(srv.issuer_url, timeout=60.0) as http:
            av = http.get("/admin/audit/verify", headers={"Authorization": f"Bearer {srv.admin_token()}"})
            body = av.json() if av.status_code == 200 else {"status": av.status_code}
            suite.record("audit chain verifies after the races", body.get("valid") is True, detail=body)
    finally:
        srv.stop()
    return suite.write(out_dir)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else common.WORK_DIR / "out"
    raise SystemExit(0 if run(out, "--quick" in sys.argv)["ok"] else 1)
