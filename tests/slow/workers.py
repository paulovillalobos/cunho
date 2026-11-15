"""Worker processes on one SQLite file, one anchor and one key, as several uvicorn workers run cunho.

Each worker holds its own Issuer and an in-process client of the app, and runs what the parent sends it:
HTTP requests, which the parent builds with the scripted wallet of the engine tests, or calls on the issuer
itself (maintenance, verify, a status bit). All workers read one clock the parent sets, so the parent can
move time for all of them at once. Requests can be sent to several workers before any reply is read, which
is how the tests make actions race across processes.

Behind each worker's clock watch is a host clock that counts the time the parent moves, as the host's own clock
counts real time. The parent can also put the wall clock off by a skew, without moving that host clock, as a
wrong time source does.

Settings may carry `_wallet_status`, the PEM certificate and key of a CA the wallet providers list trusts: each
worker then answers its fetches of wallet providers' status lists with a list signed under that CA at the time that
really passed, every entry VALID, as a wallet provider's server would.
"""

from __future__ import annotations

import json
import multiprocessing
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

from tests.engine.helpers import ISSUER


class SharedClock:
    """A test clock all workers read: `now`, the time that really passes, and `skew`, how far the wall clock reads
    off it, are doubles in shared memory. Calling it reads the wall clock."""

    def __init__(self, value: Any, skew: Any) -> None:
        self.value = value
        self.off = skew

    @property
    def now(self) -> float:
        return float(self.value.value)

    @now.setter
    def now(self, when: float) -> None:
        self.value.value = when

    @property
    def skew(self) -> float:
        return float(self.off.value)

    @skew.setter
    def skew(self, seconds: float) -> None:
        self.off.value = seconds

    def __call__(self) -> float:
        return float(self.value.value) + float(self.off.value)


@dataclass
class Reply:
    """What a worker answered: enough of an HTTP response for the wallet and the tests."""

    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        return json.loads(self.text)


def _status_fetcher(clock: SharedClock, pems: dict[str, bytes]) -> Any:
    """A fetcher that signs a fresh status list for whatever URL it is asked for (see the module docstring)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from cunho.fetch import Fetcher
    from tests.engine.statuslists import StatusSigner

    key = serialization.load_pem_private_key(pems["key"], None)
    signer = StatusSigner.under(x509.load_pem_x509_certificate(pems["certificate"]), key)  # type: ignore[arg-type]

    named = pems.get("revoked")
    revoked = Path(named.decode() if isinstance(named, bytes) else str(named)) if named else None

    class LiveStatus(Fetcher):
        """Every entry VALID but those the model's wallet providers revoked, which `revoked` lists by list URI."""

        def get(self, url: str, *, types: Any, max_bytes: int, budget: float) -> bytes:
            iat = int(clock.now)
            listed = json.loads(revoked.read_text()) if revoked is not None and revoked.exists() else {}
            entries = dict.fromkeys(listed.get(url, []), 1)
            return signer.token(url, entries, size=4096, iat=iat, exp=iat + 86_400).encode()

    return LiveStatus(None)


def _serve(pipe: Connection, value: Any, skew: Any, settings: dict[str, Any], slow_signing: float) -> None:
    """The worker's loop. `slow_signing` stretches credential signing by up to that many seconds, at random,
    so that a claim and its commit are far enough apart for other workers to act in between."""
    from fastapi.testclient import TestClient

    from cunho import service
    from cunho.app import create_app
    from cunho.service import ClockWatch, HostClock, Issuer
    from cunho.settings import Settings
    from cunho.status import StatusRef

    clock = SharedClock(value, skew)
    host = HostClock(elapsed=lambda: clock.now, boot=lambda: "the-model-host", synced=lambda: True)
    if slow_signing:
        real = service.sd_jwt_vc

        def slow(*args: Any, **named: Any) -> str:
            time.sleep(random.random() * slow_signing)
            return real(*args, **named)

        service.sd_jwt_vc = slow
    state: dict[str, Any] = {}

    def build(settings: dict[str, Any]) -> None:
        """A fresh issuer on the files `settings` names; the one before is closed first."""
        if state:
            state["client"].__exit__(None, None, None)
            state["issuer"].store._db.close()  # noqa: SLF001 - a worker that starts over closes what it held
            if state["issuer"].audit.anchor is not None:
                state["issuer"].audit.anchor.close()
        settings = dict(settings)
        pems = settings.pop("_wallet_status", None)
        fetcher = _status_fetcher(clock, pems) if pems is not None else None
        issuer = Issuer(Settings(**settings), clock=clock, fetcher=fetcher)
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
        issuer.clock_watch.steady()  # as a worker with the real host clock reads it when it starts
        client = TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER)
        client.__enter__()
        state.update(issuer=issuer, client=client)

    build(settings)
    while True:
        message = pipe.recv()
        if message is None:
            return
        kind, delay, payload = message
        if delay:
            time.sleep(delay)
        issuer, client = state["issuer"], state["client"]
        try:
            if kind == "reset":
                build(payload)
                pipe.send(True)
            elif kind == "http":
                method, path, named = payload
                response = getattr(client, method)(path, **named)
                pipe.send(Reply(response.status_code, response.text, dict(response.headers)))
            elif kind == "status":
                pipe.send(issuer.status.value(StatusRef(*payload)))
            else:
                target: Any = issuer
                for part in kind.split("."):
                    target = getattr(target, part)
                args, named = payload
                pipe.send(target(*args, **named))
        except Exception as exc:  # noqa: BLE001 - the parent decides what an error means
            pipe.send(exc)


class Worker:
    def __init__(
        self, context: Any, value: Any, skew: Any, settings: dict[str, Any], slow_signing: float = 0.0
    ) -> None:
        self._pipe, child = context.Pipe()
        self.process = context.Process(target=_serve, args=(child, value, skew, settings, slow_signing), daemon=True)
        self.process.start()

    def send(self, kind: str, payload: Any, delay: float = 0.0) -> None:
        self._pipe.send((kind, delay, payload))

    def receive(self, timeout: float = 120.0) -> Any:
        if not self._pipe.poll(timeout):
            raise TimeoutError("a worker did not answer")
        reply = self._pipe.recv()
        if isinstance(reply, Exception):
            raise reply
        return reply

    def call(self, kind: str, *args: Any, **named: Any) -> Any:
        self.send(kind, (args, named))
        return self.receive()

    def status(self, list_id: str, index: int) -> int | None:
        """The stored bit of a status slot (set at once, whatever the jitter)."""
        self.send("status", (list_id, index))
        bit: int | None = self.receive()
        return bit

    def stop(self) -> None:
        try:
            self._pipe.send(None)
        except OSError:
            pass
        self.process.join(10)
        if self.process.is_alive():
            self.process.kill()


class RemoteClient:
    """The wallet's HTTP client, served by the worker `pick()` names for each request."""

    def __init__(self, workers: list[Worker], pick: Callable[[], int]) -> None:
        self.workers = workers
        self.pick = pick

    def _do(self, method: str, path: str, **named: Any) -> Reply:
        worker = self.workers[self.pick()]
        worker.send("http", (method, path, named))
        reply: Reply = worker.receive()
        return reply

    def post(self, path: str, **named: Any) -> Reply:
        return self._do("post", path, **named)

    def get(self, path: str, **named: Any) -> Reply:
        return self._do("get", path, **named)


def start(root: Path, settings: dict[str, Any], count: int, now: float, slow_signing: float = 0.0) -> Any:
    """`count` workers on the files `settings` names, all reading one clock that starts at `now`."""
    context = multiprocessing.get_context("spawn")
    value, skew = context.Value("d", now), context.Value("d", 0.0)
    workers = [Worker(context, value, skew, settings, slow_signing) for _ in range(count)]
    return workers, SharedClock(value, skew)


def request(method: str, path: str, **named: Any) -> tuple[str, str, dict[str, Any]]:
    return method, path, named


__all__ = ["Reply", "RemoteClient", "SharedClock", "Worker", "request", "start"]
