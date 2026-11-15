"""The demo service against two cunho instances in this process: a PID provider and the course provider."""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app as cunho_app
from cunho.service import Issuer
from cunho_demo.app import create_app
from cunho_demo.settings import DemoSettings, IssuerLink
from tests.engine.conftest import (  # noqa: F401 - the engine's fixtures
    clock,
    code_files,
    code_wallet_for,
    make_issuer,
    pki,
    trust_pki,
    wallet_for,
)
from tests.engine.helpers import ADMIN_TOKEN, ISSUER, Pki, Wallet
from tests.engine.test_course_certificate import COURSE, MDOC, SD_JWT
from tests.engine.test_mdoc import mdoc_settings
from tests.engine.test_mdoc_pid import pid_settings

ORIGIN = "https://demo.test"
TODAY = dt.date(2026, 11, 5)  # the engine tests' clock starts on 2026-11-04


@dataclass
class Ticker:
    """The demo's own clock, for its sessions and rate limits."""

    now: float = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Demo:
    client: TestClient
    ticker: Ticker
    pid: Issuer
    course: Issuer
    wallets: dict[str, Wallet] = field(default_factory=dict)

    def start(self, **body: Any) -> Any:
        return self.client.post("/api/sessions", json=body, headers={"Origin": ORIGIN})

    def started(self, **body: Any) -> dict[str, Any]:
        response = self.start(**body)
        assert response.status_code == 201, response.text
        made: dict[str, Any] = response.json()
        return made

    def step(self, session_id: str) -> str:
        response = self.client.get(f"/api/sessions/{session_id}")
        assert response.status_code == 200, response.text
        return str(response.json()["step"])

    def act(self, session_id: str, action: str) -> Any:
        return self.client.post(f"/api/sessions/{session_id}/{action}", json={}, headers={"Origin": ORIGIN})


def offer_of(link: str) -> dict[str, Any]:
    """The credential offer a wallet reads from the QR code."""
    query = parse_qs(urlsplit(link).query)
    offer: dict[str, Any] = json.loads(query["credential_offer"][0])
    return offer


def scan(wallet: Wallet, made: dict[str, Any]) -> None:
    """What a wallet does with a pre-authorized QR code: get a token."""
    wallet.get_token({"credential_offer": offer_of(made["offer_link"]), "tx_code": made.get("tx_code")})


@pytest.fixture
def demo_settings(tmp_path: Path) -> DemoSettings:
    return DemoSettings(
        public_url=ORIGIN,
        pid=IssuerLink(f"{ISSUER}", ADMIN_TOKEN),
        course=IssuerLink(f"{ISSUER}", ADMIN_TOKEN),
        secret_key=b"s" * 32,
        sessions_per_minute=1000,
        polls_per_minute=100_000,
    )


@pytest.fixture
def make_demo(
    make_issuer: Callable[..., Issuer],  # noqa: F811
    pki: Pki,  # noqa: F811
    wallet_for: Callable[[Issuer], Wallet],  # noqa: F811
    demo_settings: DemoSettings,
) -> Iterator[Callable[..., Demo]]:
    clients: list[TestClient] = []

    def build(
        settings: DemoSettings | None = None,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        issuer: Callable[..., Issuer] | None = None,
        front: Callable[[Any], Any] | None = None,
    ) -> Demo:
        """`front` wraps the demo's application, as the stack puts uvicorn's handling of proxy headers in front of
        it; the client then talks to what it returns."""
        made = issuer or make_issuer
        pid = made(**pid_settings(pki, login_url=f"{ORIGIN}/login/pid"))
        course = made(
            **mdoc_settings(
                pki, metadata_dir=COURSE, published_configurations=(SD_JWT, MDOC), login_url=f"{ORIGIN}/login/course"
            )
        )
        ticker = Ticker()
        apps: dict[str, httpx.AsyncBaseTransport] = {
            "pid": httpx.ASGITransport(app=cunho_app(issuer=pid, background_maintenance=False)),
            "course": httpx.ASGITransport(app=cunho_app(issuer=course, background_maintenance=False)),
        }
        app = create_app(settings or demo_settings, transports=transports or apps, clock=ticker, today=lambda: TODAY)
        client = TestClient(front(app) if front else app, base_url=ORIGIN, raise_server_exceptions=False).__enter__()
        clients.append(client)
        return Demo(client, ticker, pid, course, {"pid": wallet_for(pid), "course": wallet_for(course)})

    yield build
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def demo(make_demo: Callable[..., Demo]) -> Demo:
    return make_demo()


@pytest.fixture
def make_code_issuer(
    make_issuer: Callable[..., Issuer],  # noqa: F811
    code_files: Any,  # noqa: F811
) -> Callable[..., Issuer]:
    """An issuer that runs the authorization code flow: wallet providers of both test PKIs, the test wallet's
    redirect URI."""
    from tests.engine.codewallet import CLIENT_ID, REDIRECT_URI

    def build(**overrides: Any) -> Issuer:
        return make_issuer(
            **{"wallet_provider_anchors": code_files["anchors"], "redirect_uris": {CLIENT_ID: (REDIRECT_URI,)}},
            **overrides,
        )

    return build
