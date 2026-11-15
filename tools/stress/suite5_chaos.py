"""Suite 5 - Chaos.

A. Kill -9 the server mid-flow and restart on the same SQLite store: offers, tokens, status
   lists and the audit chain must survive or fail cleanly.
B. SQLite locked (a second connection holds BEGIN EXCLUSIVE for longer than cunho's busy
   timeout): issuance must fail closed (no credential handed out, a clean JSON error), and once
   the lock clears the audit chain is valid and a fresh flow works.
C. Disk full / write failure (fault-injecting store wrapper, in-process): issuance fails
   closed and audit.verify() stays valid. The wrapper delegates every method it does not
   intercept, so it keeps working as the Store protocol grows. The audit anchor file gets its own
   full disk: a write torn half-way after the commit, then no room at all, then room again
   (review 4, N4-M4).
D. Clock jumps (controllable clock, in-process): jump forward past every TTL and backward;
   expired artefacts are rejected cleanly (no 5xx) and the audit chain stays valid. Maintenance
   runs during the jumps too: nothing is pruned or swept while the clock is off, and it runs
   again once the clock is back (review 4, N4-M8).
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import sys
import threading
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import common
import httpx
from suite4_attack import _ca, der_b64, mint_leaf  # reuse crafted-cert minting

from eudi_probe.jose import EcKey, b64u_decode, jws, parse_jws
from eudi_probe.wallet import dpop_proof, key_proof


def build_ka(pki: Path, holder: EcKey, now: int) -> str:
    """A valid key attestation minted at clock time `now` (so it survives clock jumps)."""
    base = dt.datetime.fromtimestamp(now, dt.UTC)
    leaf_key, leaf = mint_leaf(
        _ca(pki), not_before=base - dt.timedelta(days=1), not_after=base + dt.timedelta(days=365)
    )
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
    return jws({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [der_b64(leaf)]}, payload, leaf_key)


def status_bit(http: httpx.Client, status_claim: dict) -> int:
    """The published bit, read after the next publication (every second in the stress servers)."""
    time.sleep(1.1)
    uri = status_claim["status_list"]["uri"]
    idx = status_claim["status_list"]["idx"]
    list_id = uri.rsplit("/", 1)[1]
    token = http.get(f"/status/{list_id}").text
    payload = parse_jws(token).payload
    bits = zlib.decompress(b64u_decode(payload["status_list"]["lst"]))
    return (bits[idx // 8] >> (idx % 8)) & 1


# --------------------------------------------------------------------------- A. kill / restart


def part_kill_restart(suite: common.Suite, pki: Path) -> None:
    store = pki / "chaos-kill.db"
    for ext in ("", "-wal", "-shm"):
        (store.parent / (store.name + ext)).unlink(missing_ok=True)
    srv = common.Server(
        pki=pki, workers=1, store_path=store, port=common.free_port(), rate_limit=common.HIGH_RATE_LIMIT
    ).start()
    http = common.client(srv.issuer_url, timeout=20.0)
    w = common.Wallet(srv.issuer_url, pki, srv.admin_token(), http)

    # issue a credential and revoke it
    offer = w.offer()
    subject_ref = offer["subject_ref"]
    w.get_token(offer)
    nonce = w.nonce()
    holder = EcKey.generate()
    cred = w.credential_request(
        {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [w.proof(holder, nonce)]}}
    ).json()["credentials"][0]["credential"]
    status_claim = parse_jws(cred.split("~")[0]).payload["status"]
    rv = http.post(
        "/admin/revocations",
        json={"subject_ref": subject_ref, "reason": "administrative"},
        headers={"Authorization": f"Bearer {srv.admin_token()}"},
    )
    suite.record("kill/restart: revocation before the crash accepted", rv.status_code == 200, status=rv.status_code)
    bit_before = status_bit(http, status_claim)

    # a second token obtained but not yet used (mid-flow)
    w2 = common.Wallet(srv.issuer_url, pki, srv.admin_token(), common.client(srv.issuer_url, timeout=20.0))
    w2.get_token()

    srv.kill()  # SIGKILL mid-flow
    time.sleep(1.0)
    srv2 = common.Server(pki=pki, workers=1, store_path=store, rate_limit=common.HIGH_RATE_LIMIT).start()
    http2 = common.client(srv2.issuer_url, timeout=20.0)
    try:
        av = http2.get("/admin/audit/verify", headers={"Authorization": f"Bearer {srv2.admin_token()}"})
        suite.record(
            "kill/restart: audit chain still valid",
            av.status_code == 200 and av.json().get("valid") is True,
            detail=av.json() if av.status_code == 200 else av.status_code,
        )
        bit_after = status_bit(http2, status_claim)
        suite.record(
            "kill/restart: revoked status survived",
            bit_before == 1 and bit_after == 1,
            before=bit_before,
            after=bit_after,
        )
        # token obtained before the crash still works afterwards (reuse the SAME DPoP key the
        # token is bound to; only repoint transport + endpoints at the restarted server)
        w2.http = common.client(srv2.issuer_url, timeout=20.0)
        w2.issuer_url = srv2.issuer_url
        n2 = w2.nonce()
        h2 = EcKey.generate()
        r2 = w2.credential_request(
            {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [w2.proof(h2, n2)]}}
        )
        suite.record("kill/restart: pre-crash token still issues", r2.status_code == 200, status=r2.status_code)
        # server is healthy for a fresh flow
        ok, detail = common.new_wallet(srv2).full_flow()
        suite.record("kill/restart: fresh flow works after restart", ok, detail=detail)
    finally:
        http.close()
        http2.close()
        srv2.stop()


# --------------------------------------------------------------------------- B. SQLite locked

LOCK_HOLD_S = 35.0  # longer than cunho's SQLite busy timeout (store.BUSY_TIMEOUT, 30 s)


def part_locked(suite: common.Suite, pki: Path) -> None:
    store = pki / "chaos-lock.db"
    for ext in ("", "-wal", "-shm"):
        (store.parent / (store.name + ext)).unlink(missing_ok=True)
    srv = common.Server(pki=pki, workers=1, store_path=store, rate_limit=common.HIGH_RATE_LIMIT).start()
    http = common.client(srv.issuer_url, timeout=LOCK_HOLD_S + 30)
    w = common.Wallet(srv.issuer_url, pki, srv.admin_token(), http)
    try:
        w.get_token()
        nonce = w.nonce()
        holder = EcKey.generate()
        body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [w.proof(holder, nonce)]}}

        locked = threading.Event()

        def hold_lock() -> None:
            conn = sqlite3.connect(str(store), isolation_level=None, timeout=5.0)
            conn.execute("BEGIN EXCLUSIVE")  # blocks every writer
            locked.set()
            time.sleep(LOCK_HOLD_S)
            conn.execute("COMMIT")
            conn.close()

        holder_thread = threading.Thread(target=hold_lock)
        holder_thread.start()
        locked.wait(10)
        t0 = time.time()
        r = w.credential_request(body)
        elapsed = time.time() - t0
        holder_thread.join()
        clean = r.headers.get("content-type", "").startswith("application/json") and "error" in r.json()
        suite.record(
            "sqlite locked: issuance fails closed (no credential, clean JSON error)",
            r.status_code != 200 and clean,
            status=r.status_code,
            elapsed_s=round(elapsed, 1),
            body=r.text[:160],
        )
        with common.client(srv.issuer_url, timeout=20.0) as c2:
            av = c2.get("/admin/audit/verify", headers={"Authorization": f"Bearer {srv.admin_token()}"})
            detail = av.json() if av.status_code == 200 else av.status_code
            suite.record(
                "sqlite locked: audit chain valid after lock clears",
                av.status_code == 200 and av.json().get("valid") is True,
                detail=detail,
            )
        ok, flow = common.new_wallet(srv).full_flow()
        suite.record("sqlite locked: fresh flow works after lock clears", ok, detail=flow)
    finally:
        http.close()
        srv.stop()


# --------------------------------------------------------------------------- in-process harness


class ManualClock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def inproc(
    pki: Path, store_path: Path, store_wrapper: Callable[[Any], Any] | None = None
) -> tuple[Any, Any, ManualClock, str, Path]:
    from fastapi.testclient import TestClient

    from cunho.app import create_app
    from cunho.service import Issuer
    from cunho.settings import Settings
    from cunho.store import SqliteStore

    ISSUER = "https://localhost"
    clock = ManualClock(time.time())
    settings = Settings(
        issuer_url=ISSUER,
        admin_token="x" * 40,
        signing_key=pki / "signing.key",
        signing_chain=pki / "signing.pem",
        status_signing_key=pki / "status.key",
        status_signing_chain=pki / "status.pem",
        wallet_provider_anchors=pki / "wallet-providers.pem",
        audit_retention_days=365,
        signer_certificate_url=f"{ISSUER}/certs/signer.pem",
        rate_limit_per_minute=common.HIGH_RATE_LIMIT,
    )
    store: Any = SqliteStore(store_path, clock)
    if store_wrapper:
        store = store_wrapper(store)
    issuer = Issuer(settings, store=store, clock=clock)
    client = TestClient(create_app(issuer=issuer), base_url=ISSUER, raise_server_exceptions=False)
    return issuer, client, clock, ISSUER, pki


def token_inproc(client: Any, clock: ManualClock, issuer_url: str) -> tuple[str | None, EcKey, Any]:
    from urllib.parse import urlencode

    dk = EcKey.generate()
    now = int(clock.now)
    ofr = client.post(
        "/admin/offers",
        json={
            "credential_configuration_ids": [common.PID_CONFIG],
            "subject": common.PID_SUBJECT,
            "tx_code_length": None,
        },
        headers={"Authorization": "Bearer " + "x" * 40},
    )
    if ofr.status_code != 201:
        return None, dk, ofr
    code = ofr.json()["credential_offer"]["grants"][common.PRE_AUTH]["pre-authorized_code"]
    tr = client.post(
        "/token",
        content=urlencode({"grant_type": common.PRE_AUTH, "pre-authorized_code": code}),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": dpop_proof(dk, "POST", f"{issuer_url}/token", iat=now),
        },
    )
    if tr.status_code != 200:
        return None, dk, tr
    return tr.json()["access_token"], dk, tr


def credential_inproc(
    client: Any, clock: ManualClock, issuer_url: str, pki: Path, token: str | None, dk: EcKey, nonce: str
) -> Any:
    now = int(clock.now)
    holder = EcKey.generate()
    ka = build_ka(pki, holder, now)
    proof = key_proof(holder, issuer_url, nonce=nonce, key_attestation=ka, iat=now)
    return client.post(
        "/credential",
        json={"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [proof]}},
        headers={
            "Authorization": f"DPoP {token}",
            "DPoP": dpop_proof(dk, "POST", f"{issuer_url}/credential", access_token=token, iat=now),
        },
    )


def inproc_flow(client: Any, clock: ManualClock, issuer_url: str, pki: Path) -> tuple[Any, EcKey]:
    token, dk, resp = token_inproc(client, clock, issuer_url)
    if token is None:
        return resp, dk
    nonce = client.post("/nonce").json()["c_nonce"]
    return credential_inproc(client, clock, issuer_url, pki, token, dk, nonce), dk


# --------------------------------------------------------------------------- C. disk full


def part_disk_full(suite: common.Suite, pki: Path) -> None:
    store_path = pki / "chaos-diskfull.db"
    for ext in ("", "-wal", "-shm"):
        (store_path.parent / (store_path.name + ext)).unlink(missing_ok=True)

    class FaultStore:
        """Wraps a Store; raises 'database or disk is full' on writes once armed (simulates disk full).

        Reads, and any method this wrapper does not know about, go straight to the real store.
        """

        def __init__(self, inner: Any) -> None:
            self._inner = inner
            self.armed = False
            self.only_ns: set[str] | None = None  # None: every namespace fails once armed

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

        def _guard(self, ns: str) -> None:
            if self.armed and (self.only_ns is None or ns in self.only_ns):
                raise sqlite3.OperationalError("database or disk is full")

        def put(self, ns: str, *a: Any) -> Any:
            self._guard(ns)
            return self._inner.put(ns, *a)

        def take(self, ns: str, *a: Any) -> Any:
            self._guard(ns)
            return self._inner.take(ns, *a)

        def add(self, ns: str, *a: Any) -> Any:
            self._guard(ns)
            return self._inner.add(ns, *a)

        def incr(self, ns: str, *a: Any) -> Any:
            self._guard(ns)
            return self._inner.incr(ns, *a)

        def delete(self, ns: str, *a: Any) -> Any:
            self._guard(ns)
            return self._inner.delete(ns, *a)

    holder: dict[str, Any] = {}

    def wrap(inner: Any) -> Any:
        fs = FaultStore(inner)
        holder["fs"] = fs
        return fs

    issuer, client, clock, issuer_url, pki = inproc(pki, store_path, store_wrapper=wrap)
    # warm a clean flow first
    r0, _ = inproc_flow(client, clock, issuer_url, pki)
    suite.record("disk full: baseline flow issues before fault", r0.status_code == 200, status=r0.status_code)
    valid_before = issuer.audit.verify()[0]
    # stage a token + nonce while storage works, then arm the fault for the credential write
    token, dk, _ = token_inproc(client, clock, issuer_url)
    nonce = client.post("/nonce").json()["c_nonce"]
    holder["fs"].armed = True
    r1 = credential_inproc(client, clock, issuer_url, pki, token, dk, nonce)
    suite.record(
        "disk full: issuance fails closed during credential write (no 200)",
        r1.status_code != 200,
        status=r1.status_code,
    )
    holder["fs"].armed = False
    valid_after = issuer.audit.verify()[0]
    suite.record(
        "disk full: audit chain stays valid across the fault",
        valid_before and valid_after,
        before=valid_before,
        after=valid_after,
    )

    # Only the audit log's writes fail: the credential is built and signed, but must not be handed out
    # without its audit entry, and its status slot must not stay valid.
    token, dk, _ = token_inproc(client, clock, issuer_url)
    nonce = client.post("/nonce").json()["c_nonce"]
    slots_before = {k for k, v in issuer.store.items("status-slot") if v == 0}
    holder["fs"].only_ns = {"audit", "audit-meta"}
    holder["fs"].armed = True
    r2 = credential_inproc(client, clock, issuer_url, pki, token, dk, nonce)
    holder["fs"].armed = False
    holder["fs"].only_ns = None
    slots_after = {k for k, v in issuer.store.items("status-slot") if v == 0}
    suite.record(
        "disk full on the audit write: no credential, clean JSON error",
        r2.status_code != 200 and "error" in r2.json(),
        status=r2.status_code,
        body=r2.text[:120],
    )
    suite.record(
        "disk full on the audit write: no new valid status slot left behind",
        not (slots_after - slots_before),
        leaked=len(slots_after - slots_before),
    )
    suite.record("disk full on the audit write: audit chain still valid", issuer.audit.verify()[0] is True)
    r3, _ = inproc_flow(client, clock, issuer_url, pki)
    suite.record("disk full: flow works again once space is back", r3.status_code == 200, status=r3.status_code)


def part_anchor_full(suite: common.Suite, pki: Path) -> None:
    """The anchor file's disk fills up: half a line is written, then nothing, then there is room again."""
    import errno
    import os

    from cunho import audit

    store_path = pki / "chaos-anchorfull.db"
    for ext in ("", "-wal", "-shm", ".audit-anchor"):
        (store_path.parent / (store_path.name + ext)).unlink(missing_ok=True)
    issuer, client, _, _, _ = inproc(pki, store_path)  # a plain SQLite store, so its anchor is a file
    if issuer.audit.anchor is None or issuer.audit.anchor.path is None:
        suite.record("anchor disk full: the anchor is a file", False)
        return

    real = os.write
    left: list[int | None] = [None]

    def write(fd: int, data: Any) -> int:
        anchor = issuer.audit.anchor
        if left[0] is None or anchor is None or fd != anchor._fd:  # noqa: SLF001
            return real(fd, data)
        keep, left[0] = (len(data) // 2 if left[0] < 0 else left[0]), None
        if keep:
            real(fd, data[:keep])
        raise OSError(errno.ENOSPC, "No space left on device")

    def offer() -> Any:
        return client.post(
            "/admin/offers",
            json={"credential_configuration_ids": [common.PID_CONFIG], "subject": common.PID_SUBJECT},
            headers={"Authorization": "Bearer " + "x" * 40},
        )

    audit.os.write = write
    try:
        entries = len(issuer.audit.entries())
        left[0] = -1
        torn = offer()
        suite.record(
            "anchor disk full after the commit: the committed offer is answered as created",
            torn.status_code == 201 and len(issuer.audit.entries()) == entries + 1,
            status=torn.status_code,
        )
        left[0] = 0
        refused = offer()
        suite.record(
            "anchor disk still full: the next action is refused before it changes anything, clean JSON",
            refused.status_code == 500 and "error" in refused.json() and len(issuer.audit.entries()) == entries + 1,
            status=refused.status_code,
        )
        damaged = issuer.audit.verify()
        suite.record("anchor torn: verify does not call it valid", damaged[0] is False, verify=damaged)
        left[0] = 37  # the repair itself is torn too (review 5, N5-M1)
        second = offer()
        suite.record(
            "the repair is torn too: refused cleanly, nothing changed",
            second.status_code == 500 and len(issuer.audit.entries()) == entries + 1,
            status=second.status_code,
        )
        again = offer()
        verdict = issuer.audit.verify()
        suite.record(
            "anchor disk has room again: both tears are closed, declared and logged, and the log verifies",
            again.status_code == 201
            and verdict[0] is True
            and "damaged stretch" in verdict[1]
            and any(e["event"] == "audit.anchor_repaired" for e in issuer.audit.entries()),
            status=again.status_code,
            verify=verdict,
        )
        path = issuer.audit.anchor.path
        with path.open("ab") as handle:  # a power loss leaves NULs where the last write should be
            handle.write(b"\x00" * 4096)
        nul = issuer.audit.verify()
        from fastapi.testclient import TestClient

        from cunho.app import create_app
        from cunho.service import Issuer
        from cunho.store import SqliteStore

        clock = issuer.clock
        restarted = Issuer(issuer.settings, store=SqliteStore(store_path, clock), keyring=issuer.keyring, clock=clock)
        client2 = TestClient(create_app(issuer=restarted), base_url=issuer.settings.issuer_url)
        after = client2.post(
            "/admin/offers",
            json={"credential_configuration_ids": [common.PID_CONFIG], "subject": common.PID_SUBJECT},
            headers={"Authorization": "Bearer " + "x" * 40},
        )
        verdict = restarted.audit.verify()
        suite.record(
            "a NUL tail: verify says damaged, and after a restart the next action repairs it",
            nul[0] is False and after.status_code == 201 and verdict[0] is True,
            nul=nul,
            status=after.status_code,
            verify=verdict,
        )
    finally:
        audit.os.write = real


# --------------------------------------------------------------------------- D. clock jumps


def part_clock_jumps(suite: common.Suite, pki: Path) -> None:
    """The wall clock jumps while the host's own clock, which a deployment has behind the clock watch, counts only
    the time that really passes. cunho goes by the host clock: a jump prunes and sweeps nothing, and time that
    really passes ages offers and tokens as it should."""
    from cunho.service import ClockWatch, HostClock

    store_path = pki / "chaos-clock.db"
    for ext in ("", "-wal", "-shm"):
        (store_path.parent / (store_path.name + ext)).unlink(missing_ok=True)
    issuer, client, clock, issuer_url, pki = inproc(pki, store_path)
    elapsed = [1000.0]

    def passes(seconds: float) -> None:  # time that really passes: both clocks move
        clock.now += seconds
        elapsed[0] += seconds

    host = HostClock(elapsed=lambda: elapsed[0], boot=lambda: "stress-host", synced=lambda: None)
    issuer.use_clock_watch(
        ClockWatch(
            issuer.store,
            clock,
            issuer.settings.maintenance_interval,
            host=host,
            keyring=issuer.keyring,
            floor=issuer.audit.clock_floor,
        )
    )
    issuer.sweep()  # the background task's first reading lays the clock watch's base

    r0, _ = inproc_flow(client, clock, issuer_url, pki)
    suite.record("clock jumps: baseline flow issues", r0.status_code == 200, status=r0.status_code)
    entries, rows = len(issuer.audit.entries()), issuer.store.count()
    clock.now += 400 * 86400  # the wall clock alone jumps past the 365-day retention, for one maintenance run
    during = issuer.maintenance()
    swept = issuer.sweep()
    clock.now -= 400 * 86400
    suite.record(
        "clock jumps: maintenance during a 400-day jump goes by the host clock and prunes and sweeps nothing",
        during.get("audit_entries_pruned") == 0
        and during.get("expired_entries") == 0
        and swept == 0
        and len(issuer.audit.entries()) == entries
        and issuer.store.count() >= rows,
        maintenance=during,
        entries_before=entries,
        entries_after=len(issuer.audit.entries()),
    )
    passes(3600 + 1)
    after = issuer.maintenance()
    suite.record(
        "clock jumps: maintenance runs on time once the clock is back, and the log verifies",
        "expired_entries" in after and after.get("audit_entries_pruned") == 0 and issuer.audit.verify()[0] is True,
        maintenance=after,
    )

    # obtain an offer, then let ten days pass so every TTL has expired
    offer = client.post(
        "/admin/offers",
        json={
            "credential_configuration_ids": [common.PID_CONFIG],
            "subject": common.PID_SUBJECT,
            "tx_code_length": None,
        },
        headers={"Authorization": "Bearer " + "x" * 40},
    ).json()
    code = offer["credential_offer"]["grants"][common.PRE_AUTH]["pre-authorized_code"]
    passes(10 * 86400)  # ten days really pass
    from urllib.parse import urlencode

    tr = client.post(
        "/token",
        content=urlencode({"grant_type": common.PRE_AUTH, "pre-authorized_code": code}),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": dpop_proof(EcKey.generate(), "POST", f"{issuer_url}/token", iat=int(clock.now)),
        },
    )
    suite.record(
        "clock jumps: expired pre-auth code rejected cleanly (no 5xx)",
        tr.status_code != 200 and tr.status_code < 500,
        status=tr.status_code,
    )

    # a fresh flow ten days later works
    rf, _ = inproc_flow(client, clock, issuer_url, pki)
    suite.record("clock jumps: fresh flow works at the new time", rf.status_code == 200, status=rf.status_code)

    # the wall clock alone jumps back: no crash
    clock.now -= 20 * 86400
    rb = client.post("/nonce")
    suite.record("clock jumps: backward jump does not 5xx", rb.status_code < 500, status=rb.status_code)
    suite.record("clock jumps: audit chain valid after jumps", issuer.audit.verify()[0] is True)


def run(out_dir: Path, quick: bool) -> dict:
    suite = common.Suite("suite5_chaos")
    pki = common.gen_pki(common.WORK_DIR / "chaos")
    for part in (part_kill_restart, part_locked, part_disk_full, part_anchor_full, part_clock_jumps):
        try:
            part(suite, pki)
        except Exception as exc:  # noqa: BLE001
            suite.record(f"{part.__name__} ran without harness error", False, error=f"{type(exc).__name__}:{exc}")
    return suite.write(out_dir)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else common.WORK_DIR / "out"
    raise SystemExit(0 if run(out, "--quick" in sys.argv)["ok"] else 1)
