"""The refusal log: with CUNHO_LOG_REFUSALS on, why a wallet's request was refused, and nothing of who sent it."""

from __future__ import annotations

import logging
from collections.abc import Callable, MutableMapping
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import _printable, create_app
from cunho.service import Issuer
from cunho.settings import Settings

from .helpers import ADMIN_TOKEN, ISSUER


def _client(issuer: Issuer) -> TestClient:
    return TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER)


def _lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.name == "cunho.refusals"]


def test_off_by_default_nothing_is_logged(make_issuer: Callable[..., Issuer], caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="cunho.refusals")
    with _client(make_issuer()) as client:
        assert client.post("/token", data={"grant_type": "nothing"}).status_code == 400
        assert client.get("/nowhere").status_code == 404
    assert _lines(caplog) == []


def test_on_it_says_why_and_nothing_of_who(
    make_issuer: Callable[..., Issuer], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="cunho.refusals")
    with _client(make_issuer(log_refusals=True)) as client:
        answer = client.post(
            "/token?secret=in-the-query",
            data={"grant_type": "nothing"},
            headers={"Authorization": "DPoP header-token", "X-Forwarded-For": "203.0.113.9"},
        )
        assert answer.status_code == 400
        assert client.get("/nowhere?secret=in-the-query").status_code == 404
    lines = _lines(caplog)
    assert len(lines) == 2
    token, unknown = lines
    body = answer.json()
    assert token.startswith(f"refused POST /token: 400 {body['error']} ["), token
    assert body["error_description"] not in token, "a description may repeat what the request sent"
    assert unknown == "refused GET (no route): 404 not_found [http]", unknown
    for line in lines:
        for private in ("in-the-query", "header-token", "203.0.113.9", "testclient"):
            assert private not in line, (private, line)


def test_a_logged_value_cannot_forge_a_line_and_is_bounded() -> None:
    assert _printable("one\ntwo\rthree\x1b[31m") == "one?two?three?[31m"
    long = _printable("x" * 1000)
    assert len(long) == 301 and long.endswith("…")
    assert _printable("short") == "short"


def test_the_setting_reads_from_the_environment() -> None:
    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": ADMIN_TOKEN,
        "CUNHO_SIGNING_KEY": "k",
        "CUNHO_SIGNING_CHAIN": "c",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "a",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_SIGNER_CERTIFICATE_URL": f"{ISSUER}/certs/signer.pem",
    }
    assert Settings.from_env(env).log_refusals is False
    assert Settings.from_env({**env, "CUNHO_LOG_REFUSALS": "1"}).log_refusals is True


def test_an_unknown_path_with_a_query_that_is_not_utf8_is_still_a_404(
    make_issuer: Callable[..., Issuer], caplog: pytest.LogCaptureFixture
) -> None:
    """The path is read from the scope, so a query cunho cannot decode does not turn the 404 into a 500."""
    caplog.set_level(logging.WARNING, logger="cunho.refusals")
    app = create_app(issuer=make_issuer(log_refusals=True), background_maintenance=False)
    sent: list[MutableMapping[str, Any]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: MutableMapping[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/nowhere",
        "raw_path": b"/nowhere",
        "query_string": b"q=\xff\xfe",
        "headers": [(b"host", b"issuer.test")],
        "server": ("issuer.test", 443),
        "client": ("203.0.113.9", 4000),
    }
    import asyncio

    asyncio.run(app(scope, receive, send))
    assert sent[0]["status"] == 404
    assert _lines(caplog) == ["refused GET (no route): 404 not_found [http]"]


def test_an_unknown_path_is_named_only_when_it_is_a_discovery_one(
    make_issuer: Callable[..., Issuer], caplog: pytest.LogCaptureFixture
) -> None:
    """A mistyped route may carry a login state; a /.well-known/ path tells which document a wallet looked for."""
    caplog.set_level(logging.WARNING, logger="cunho.refusals")
    with _client(make_issuer(log_refusals=True)) as client:
        assert client.get("/admin/logins/the-login-state/").status_code == 404
        assert client.get("/.well-known/openid-configuration").status_code == 404
        assert client.get("/.well-known/jwt-vc-issuer/the-login-state").status_code == 404
        assert client.get("/.well-known/the-login-state").status_code == 404
    assert _lines(caplog) == [
        "refused GET (no route): 404 not_found [http]",
        "refused GET /.well-known/openid-configuration: 404 not_found [http]",
        "refused GET /.well-known/jwt-vc-issuer/…: 404 not_found [http]",
        "refused GET (no route): 404 not_found [http]",
    ]
