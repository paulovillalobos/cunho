"""Suite 1 - Load to the breaking point.

Ramps concurrent wallets doing full flows (offer -> token -> nonce -> credential) against the
server with 1 uvicorn worker and with 4 workers sharing one SQLite store. Reports throughput,
p50/p95/p99 latency, error rate, first error type and server RSS over time per level.

Then polls a status list that has 100,000 revoked bits waiting to show, as a mass revocation leaves it,
from eight clients at once, while timing the metadata endpoint of the same worker (review 5, N5-M3: four
answers a second and metadata taking up to two seconds before the fix).

PASS for a level = no 5xx or transport errors and at most 1% failed flows. The metrics are always written.
"""

from __future__ import annotations

import concurrent.futures as cf
import sys
import threading
import time
from pathlib import Path

import common


def run_level(server: common.Server, concurrency: int, iters: int) -> dict:
    latencies: list[float] = []
    errors: list[str] = []
    first_error: str | None = None
    server_errors = 0
    lock = threading.Lock()

    def worker() -> None:
        nonlocal first_error, server_errors
        http = common.client(server.issuer_url, timeout=30.0)
        w = common.Wallet(server.issuer_url, server.pki, server.admin_token(), http)
        for _ in range(iters):
            t0 = time.time()
            ok, detail = w.full_flow()
            dt = time.time() - t0
            with lock:
                latencies.append(dt)
                if not ok:
                    errors.append(detail)
                    if first_error is None:
                        first_error = detail
                    if common.is_server_error(detail):
                        server_errors += 1
        http.close()

    start = time.time()
    with cf.ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(lambda _: worker(), range(concurrency)))
    elapsed = time.time() - start
    total = len(latencies)
    ok = total - len(errors)
    http5xx = sum(1 for e in errors if common.is_server_error(e))
    return {
        "concurrency": concurrency,
        "flows": total,
        "succeeded": ok,
        "error_rate": round(len(errors) / total, 3) if total else 0,
        "throughput_rps": round(total / elapsed, 2) if elapsed else 0,
        "elapsed_s": round(elapsed, 2),
        "latency_ms": common.percentiles(latencies),
        "server_5xx_or_exc": http5xx,
        "first_error": first_error,
    }


def prepare_mass_revocation(pki: Path, store: Path, hidden: int) -> None:
    """A store whose list 1 has `hidden` revoked bits that show one by one over the coming hour."""
    from cunho.service import Issuer
    from cunho.settings import Settings

    env = common.env_for(pki, "https://localhost:1", store)
    settings = Settings.from_env({k: v for k, v in env.items() if k.startswith("CUNHO_")})
    issuer = Issuer(settings)
    issuer.status.allocate()
    now = time.time()
    with issuer.store.atomic():
        for n in range(hidden):
            issuer.store.put("status-slot", f"1:{n:08d}", 1, None)
            issuer.status._show_at("1", n, now + 2 + 3600 * n / hidden)  # noqa: SLF001


def status_under_mass_revocation(suite: common.Suite, pki: Path, seconds: float) -> None:
    store = pki / "status-load.db"
    for ext in ("", "-wal", "-shm", ".keys", ".audit-anchor"):
        Path(f"{store}{ext}").unlink(missing_ok=True)
    prepare_mass_revocation(pki, store, 100_000)
    srv = common.Server(pki=pki, workers=1, store_path=store, rate_limit=common.HIGH_RATE_LIMIT).start()
    stop = threading.Event()
    polls: list[int] = []
    failures: list[int] = []

    def poller() -> None:
        http = common.client(srv.issuer_url, timeout=30.0)
        while not stop.is_set():
            code = http.get("/status/1").status_code
            (polls if code == 200 else failures).append(code)
        http.close()

    try:
        threads = [threading.Thread(target=poller) for _ in range(8)]
        for thread in threads:
            thread.start()
        http = common.client(srv.issuer_url, timeout=30.0)
        latencies = []
        deadline = time.time() + seconds
        while time.time() < deadline:
            started = time.time()
            http.get("/.well-known/openid-credential-issuer")
            latencies.append(time.time() - started)
            time.sleep(0.1)
        http.close()
    finally:
        stop.set()
        for thread in threads:
            thread.join(30)
        srv.stop()
    rate = len(polls) / seconds
    timing = common.percentiles(latencies)
    suite.meta["status_mass_revocation"] = {"polls_per_s": round(rate, 1), "metadata_ms": timing}
    suite.record(
        "status with 100,000 hidden bits, 8 pollers: no failure, over 100 polls/s, metadata p95 < 250 ms",
        not failures and rate > 100 and timing["p95"] < 250,
        polls_per_s=round(rate, 1),
        metadata_ms=timing,
        failures=len(failures),
    )


def run(out_dir: Path, quick: bool) -> dict:
    levels = [10, 50] if quick else [10, 50, 100, 200]
    iters = 1 if quick else 2
    suite = common.Suite("suite1_load")
    pki = common.gen_pki(common.WORK_DIR / "load")

    for workers in (1, 4):
        store = (pki / f"load-{workers}.db") if workers > 1 else None
        if store and store.exists():
            store.unlink()
        label = f"{workers}w"
        srv = common.Server(pki=pki, workers=workers, store_path=store, rate_limit=common.HIGH_RATE_LIMIT).start()
        try:
            results = []
            for c in levels:
                res = run_level(srv, c, iters)
                results.append(res)
                passed = res["server_5xx_or_exc"] == 0 and res["error_rate"] <= 0.01
                suite.record(
                    f"{label} c={c}: no 5xx & error_rate<=1%",
                    passed,
                    rps=res["throughput_rps"],
                    p95_ms=res["latency_ms"]["p95"],
                    err_rate=res["error_rate"],
                    first_error=res["first_error"],
                )
            rss = srv.rss_mb()
            peak = max((m for _, m in rss), default=0)
            suite.meta[label] = {"levels": results, "rss_peak_mb": round(peak, 1), "rss_samples": rss}
            # memory must not grow without bound across the ramp
            suite.record(f"{label}: RSS peak < 1500 MB", peak < 1500, peak_mb=round(peak, 1))
        finally:
            srv.stop()
    status_under_mass_revocation(suite, pki, 10.0 if quick else 30.0)
    return suite.write(out_dir)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else common.WORK_DIR / "out"
    quick = "--quick" in sys.argv
    raise SystemExit(0 if run(out, quick)["ok"] else 1)
