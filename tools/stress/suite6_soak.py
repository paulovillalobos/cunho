"""Suite 6 - Soak.

Mixed traffic (full flows, nonce, status GETs, offers, revocations) for a configurable duration
(default 30 minutes; --quick = 20 s). Samples server RSS and the SQLite store size / row counts
over time. Checks: no 5xx anywhere, RSS bounded, expired entries purged within a few sweep
intervals (the oldest expired row is never older than STALE_AGE_LIMIT_S), and short-lived state
levels off instead of growing with traffic (the H-2 unbounded-growth check). Long-lived rows
(audit entries, status slots, issued-credential records) grow with issuance by design. The audit log
is verified against its anchor while the traffic runs, not only at rest, and every answer must be
valid (review 4, N4-M7).

Usage: suite6_soak.py OUT_DIR [--quick] [--seconds N]
"""

from __future__ import annotations

import concurrent.futures as cf
import random
import sqlite3
import sys
import threading
import time
from pathlib import Path

import common

STALE_AGE_LIMIT_S = 180.0  # the soak runs maintenance, which sweeps expired rows, about every 60 s
SHORT_LIVED_S = 3600.0  # rows due to expire within this horizon are short-lived protocol state


def store_stats(store_path: Path, now: float) -> dict:
    total = 0
    stale = 0
    stale_age = 0.0
    short_lived = 0
    scheduled_until = 0.0
    per_ns: dict[str, int] = {}
    size = 0
    for ext in ("", "-wal", "-shm"):
        p = store_path.parent / (store_path.name + ext)
        if p.exists():
            size += p.stat().st_size
    try:
        conn = sqlite3.connect(f"file:{store_path}?mode=ro", uri=True, timeout=2.0)
        for ns, cnt in conn.execute("SELECT ns, COUNT(*) FROM kv GROUP BY ns"):
            per_ns[ns] = cnt
            total += cnt
        row = conn.execute(
            "SELECT COUNT(*), MIN(expires) FROM kv WHERE expires IS NOT NULL AND expires<=?", (now,)
        ).fetchone()
        stale = row[0] if row else 0
        stale_age = round(now - row[1], 1) if row and row[1] is not None else 0.0
        row = conn.execute(
            "SELECT COUNT(*) FROM kv WHERE expires IS NOT NULL AND expires<=?", (now + SHORT_LIVED_S,)
        ).fetchone()
        short_lived = row[0] if row else 0
        # Each status list keeps its own decoy schedule (review 3, N3-M3); every maintenance run extends it.
        row = conn.execute(
            "SELECT MAX(CAST(value AS REAL)) FROM kv WHERE ns='status-meta' AND key LIKE 'scheduled_until%'"
        ).fetchone()
        scheduled_until = float(row[0]) if row and row[0] is not None else 0.0
        conn.close()
    except Exception:  # noqa: BLE001
        pass
    return {
        "bytes": size,
        "rows": total,
        "stale_rows": stale,
        "stale_age_s": stale_age,
        "short_lived_rows": short_lived,
        "scheduled_until": scheduled_until,
        "per_ns": per_ns,
    }


def soak(server: common.Server, store_path: Path, seconds: float, workers: int, verify_every: float) -> dict:
    stop = threading.Event()
    verdicts: dict[str, int] = {}
    counters = {"full": 0, "nonce": 0, "status": 0, "offer": 0, "revoke": 0, "errors": 0, "err5xx": 0}
    lock = threading.Lock()
    subjects: list[str] = []
    first_errors: dict[str, str] = {}

    def bump(k: str, n: int = 1) -> None:
        with lock:
            counters[k] += n

    def worker() -> None:
        http = common.client(server.issuer_url, timeout=30.0)
        w = common.Wallet(server.issuer_url, pki=server.pki, admin_token=server.admin_token(), http=http)
        while not stop.is_set():
            action = random.choices(["full", "nonce", "status", "offer", "revoke"], weights=[35, 40, 15, 7, 3])[0]
            try:
                if action == "full":
                    ok, detail = w.full_flow()
                    bump("full")
                    if ok and w.last_subject_ref and random.random() < 0.1:
                        with lock:
                            subjects.append(w.last_subject_ref)
                    if not ok:
                        bump("errors")
                        if common.is_server_error(detail):
                            bump("err5xx")
                        with lock:
                            first_errors.setdefault(detail[:40], detail)
                elif action == "nonce":
                    r = http.post("/nonce")
                    bump("nonce")
                    if r.status_code != 200:
                        bump("errors")
                    if r.status_code >= 500:
                        bump("err5xx")
                elif action == "status":
                    r = http.get("/status/1")
                    bump("status")
                    if r.status_code >= 500:
                        bump("err5xx")
                elif action == "offer":
                    r = w.create_offer()
                    bump("offer")
                    if r.status_code == 201:
                        with lock:
                            subjects.append(r.json()["subject_ref"])
                    else:
                        bump("errors")
                        if r.status_code >= 500:
                            bump("err5xx")
                elif action == "revoke":
                    ref = None
                    with lock:
                        if subjects:
                            ref = subjects.pop()
                    if ref:
                        # A subject whose offer is still live gets it closed (review 4, N4-M5).
                        r = http.post(
                            "/admin/revocations",
                            json={"subject_ref": ref, "reason": "administrative"},
                            headers={"Authorization": f"Bearer {server.admin_token()}"},
                        )
                        bump("revoke")
                        if r.status_code >= 500:
                            bump("err5xx")
            except Exception as exc:  # noqa: BLE001
                bump("errors")
                bump("err5xx")
                with lock:
                    first_errors.setdefault(type(exc).__name__, f"exc:{type(exc).__name__}:{exc}")
        http.close()

    def verifier() -> None:
        http = common.client(server.issuer_url, timeout=600.0)
        while not stop.wait(verify_every):
            try:
                r = http.get("/admin/audit/verify", headers={"Authorization": f"Bearer {server.admin_token()}"})
                key = "valid" if r.status_code == 200 and r.json().get("valid") else r.text[:80]
            except Exception as exc:  # noqa: BLE001
                key = f"exc:{type(exc).__name__}"
            with lock:
                verdicts[key] = verdicts.get(key, 0) + 1
        http.close()

    checker = threading.Thread(target=verifier)
    checker.start()
    samples = []
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(worker) for _ in range(workers)]
        while time.time() - t0 < seconds:
            time.sleep(max(1.0, seconds / 30))
            rss = max((m for _, m in server.rss_mb()[-3:]), default=0)
            st = store_stats(store_path, time.time())
            samples.append({"t": round(time.time() - t0, 1), "rss_mb": round(rss, 1), **st})
        stop.set()
        for f in futs:
            f.result()
    checker.join()
    return {
        "counters": counters,
        "samples": samples,
        "errors": list(first_errors.values())[:10],
        "verdicts": verdicts,
    }


def run(out_dir: Path, quick: bool) -> dict:
    seconds = 20.0 if quick else 1800.0
    if "--seconds" in sys.argv:
        seconds = float(sys.argv[sys.argv.index("--seconds") + 1])
    suite = common.Suite("suite6_soak")
    suite.meta["seconds"] = seconds
    pki = common.gen_pki(common.WORK_DIR / "soak")
    store = pki / "soak.db"
    for ext in ("", "-wal", "-shm"):
        (store.parent / (store.name + ext)).unlink(missing_ok=True)
    # Maintenance runs in the background every `interval` seconds, so a soak covers many runs of it
    # (review 2, N-L8: the earlier soak never reached a second hourly run).
    interval = 5 if quick else 60
    suite.meta["maintenance_interval"] = interval
    srv = common.Server(
        pki=pki, workers=1, store_path=store, rate_limit=common.HIGH_RATE_LIMIT, maintenance_interval=interval
    ).start()
    try:
        # Verification streams the whole log, which grows to hundreds of thousands of entries in a full run.
        data = soak(srv, store, seconds, workers=8, verify_every=2.0 if quick else 60.0)
        # The same patience as the verifications during the run: at the end of a full run the log holds
        # hundreds of thousands of entries, and the default 10 s were only just enough for 720,864.
        verified = common.client(srv.issuer_url, timeout=600.0).get(
            "/admin/audit/verify", headers={"Authorization": f"Bearer {srv.admin_token()}"}
        )
        audit = verified.json() if verified.status_code == 200 else {"status": verified.status_code}
    finally:
        srv.stop()

    samples = data["samples"]
    suite.meta["counters"] = data["counters"]
    suite.meta["samples"] = samples
    suite.meta["errors"] = data["errors"]
    c = data["counters"]
    suite.record("soak: no 5xx or transport errors", c["err5xx"] == 0, err5xx=c["err5xx"], first=data["errors"][:3])
    suite.record(
        "soak: full flows succeed (<= 1% failed)",
        c["full"] > 0 and c["errors"] <= 0.01 * (c["full"] + c["nonce"] + c["offer"]),
        flows=c["full"],
        errors=c["errors"],
    )
    if len(samples) >= 4:
        rss = [s["rss_mb"] for s in samples if s["rss_mb"] > 0]
        third = max(1, len(samples) // 3)
        rss_early = sorted(rss[:third])[len(rss[:third]) // 2] if rss[:third] else 0
        rss_late = sorted(rss[-third:])[len(rss[-third:]) // 2] if rss[-third:] else 0
        growth = (rss_late / rss_early) if rss_early else 1.0
        suite.record(
            "soak: RSS bounded (late/early median < 2x and peak < 1500 MB)",
            growth < 2.0 and max(rss, default=0) < 1500,
            rss_early_mb=round(rss_early, 1),
            rss_late_mb=round(rss_late, 1),
            peak_mb=round(max(rss, default=0), 1),
            growth=round(growth, 2),
        )
        max_age = max(s["stale_age_s"] for s in samples)
        suite.record(
            f"soak: expired entries purged (oldest expired row < {STALE_AGE_LIMIT_S:.0f} s, H-2)",
            max_age < STALE_AGE_LIMIT_S,
            max_stale_age_s=max_age,
            max_stale_rows=max(s["stale_rows"] for s in samples),
            final_rows=samples[-1]["rows"],
        )
        # Short-lived state levels off once traffic is steady: the last third holds no more than the middle one
        # (+50% for noise). In a short run the TTLs never elapse, so only the purge check above is meaningful.
        if seconds >= 1200:
            mid = sorted(s["short_lived_rows"] for s in samples[third : 2 * third])
            late = sorted(s["short_lived_rows"] for s in samples[-third:])
            mid_m, late_m = mid[len(mid) // 2], late[len(late) // 2]
            suite.record(
                "soak: short-lived state levels off (late median <= 1.5x middle median)",
                late_m <= 1.5 * mid_m + 100,
                middle=mid_m,
                late=late_m,
            )
        runs = len({s["scheduled_until"] for s in samples if s["scheduled_until"]})
        suite.record(
            "soak: maintenance ran in the background, off the request path (N-M7)",
            runs >= max(2, int(seconds / interval / 3)),
            distinct_runs_seen=runs,
            interval_s=interval,
        )
    else:
        suite.record("soak: collected enough samples", False, samples=len(samples))
    verdicts = data["verdicts"]
    suite.record(
        "soak: audit verify under load is valid every time (N4-M7)",
        bool(verdicts) and set(verdicts) == {"valid"},
        verdicts=verdicts,
    )
    suite.record("soak: audit chain verifies against its anchor at the end", audit.get("valid") is True, audit=audit)
    return suite.write(out_dir)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else common.WORK_DIR / "out"
    raise SystemExit(0 if run(out, "--quick" in sys.argv)["ok"] else 1)
