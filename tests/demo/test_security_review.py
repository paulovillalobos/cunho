"""What the security review of the demo service found (research/cunho-security-review.md): each test failed on the
code as reviewed and holds the fix."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from cunho.app import create_app as cunho_app
from cunho.service import Issuer
from cunho_demo.app import SECURITY_HEADERS
from cunho_demo.sessions import Session, Sessions
from cunho_demo.settings import DemoConfigError, DemoSettings
from tests.engine.helpers import ADMIN_TOKEN

from .conftest import ORIGIN, Demo
from .test_console import PASSWORD, STORED, console, sign_in
from .test_wallet import ka_files  # noqa: F401 - the wallet tests' fixture

FORM = {"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"}
# A well-formed login_state that names no login, and a token with one character that is not ASCII (an e acute).
NOT_ASCII = b"login_state=AAAAAAAAAAAAAAAA&token=%C3%A9&persona=ana&action=issue"
EVERY_ANSWER = (*SECURITY_HEADERS, "Strict-Transport-Security", "Cache-Control")
PENDING = "/login/pid?login_state=AAAAAAAAAAAAAAAAAAAAAAAA"  # well formed; the issuer knows no such login (410)
COOKIE = "__Host-demo_operator"


def missing_headers(response: Any) -> list[str]:
    return [name for name in EVERY_ANSWER if name.lower() not in response.headers]


@pytest.fixture
def console_demo(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings, make_code_issuer: Callable[..., Issuer]
) -> Demo:
    return make_demo(replace(demo_settings, operator_password_hash=STORED), issuer=make_code_issuer)


# --- text that is not ASCII where a token is compared -------------------------------------------------------------


@pytest.mark.parametrize("path", ["/login/pid", "/login/course", "/consent/pid", "/consent/course"])
def test_a_form_token_that_is_not_ascii_is_a_wrong_token(demo: Demo, path: str) -> None:
    """The comparison raised on such text: anyone could have the service answer 500 and write a traceback, with
    one request that needs no session and no login."""
    answer = demo.client.post(path, content=NOT_ASCII, headers=FORM)
    assert answer.status_code == 400, answer.text
    assert not missing_headers(answer)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/offers/%C3%A9"),
        ("GET", "/api/offers/%C3%A9"),
        ("POST", "/api/offers/%C3%A9/demo-wallet"),
        ("POST", "/api/offers/%C3%A9/status"),
    ],
)
def test_an_offer_reference_that_is_not_ascii_is_not_found(demo: Demo, method: str, path: str) -> None:
    """It is compared with every live session's reference, so one live session, anyone's, was enough."""
    demo.started(credential="pid")
    if method == "GET":
        answer = demo.client.get(path)
    else:
        answer = demo.client.post(path, json={}, headers={"Origin": ORIGIN})
    assert answer.status_code == 404, answer.text
    assert not missing_headers(answer)


def test_a_console_form_token_that_is_not_ascii_is_a_wrong_token(console_demo: Demo) -> None:
    sign_in(console_demo)
    cookie = console_demo.client.cookies.get(COOKIE)
    refused = console_demo.client.post(
        "/operator/action",
        content=b"csrf=%C3%A9&issuer=pid&action=revoke&subject_ref=sub_AAAAAAAAAAAAAAAAAAAAAAAA",
        headers=FORM,
        follow_redirects=False,
    )
    assert refused.status_code == 400, refused.text
    out = console_demo.client.post("/operator/logout", content=b"csrf=%C3%A9", headers=FORM, follow_redirects=False)
    assert out.status_code == 303
    console_demo.client.cookies.set(COOKIE, cookie or "")
    assert "Sign out" in console(console_demo)[0], "a sign-out without the session's token ends nothing"


# --- an answer to an error nobody planned for -----------------------------------------------------------------------


def test_an_unexpected_error_is_answered_with_the_security_headers(demo: Demo) -> None:
    """Whatever goes wrong inside a handler, the answer is the service's own, with every header: the outermost
    layer's plain 500 carried none of them."""
    made = demo.started(credential="pid")

    async def broken(subject_ref: str) -> dict[str, Any]:
        raise RuntimeError("something nobody planned for")

    demo.client.app.state.issuers["pid"].progress = broken  # type: ignore[attr-defined]
    answer = demo.client.get(f"/api/sessions/{made['id']}")
    assert answer.status_code == 500
    assert answer.json() == {"error": "server_error"}
    assert not missing_headers(answer), f"a 500 is sent without {missing_headers(answer)}"
    assert answer.headers["cache-control"] == "no-store"


# --- the login screens are limited per client ------------------------------------------------------------------------


def screen(demo: Demo, which: str) -> Any:
    if which == "login page":
        return demo.client.get(PENDING)
    path = "/login/pid" if which == "login form" else "/consent/pid"
    return demo.client.post(path, content=b"login_state=AAAAAAAAAAAAAAAAAAAAAAAA&token=x", headers=FORM)


@pytest.mark.parametrize("which", ["login page", "login form", "consent form"])
def test_the_login_screens_are_limited_per_client(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings, which: str
) -> None:
    """Each of them asks the issuer something with the operator token, so without a limit one client could spend
    the whole of the operator's allowance at the issuer, and with it every visitor's demo."""
    demo = make_demo(replace(demo_settings, logins_per_minute=3))
    allowed = 410 if which == "login page" else 400
    codes = [screen(demo, which).status_code for _ in range(5)]
    assert codes == [allowed] * 3 + [429, 429]
    refused = screen(demo, which)
    assert refused.headers["retry-after"] == "60" and "text/html" in refused.headers["content-type"]
    assert not missing_headers(refused)
    demo.ticker.now += 120
    assert screen(demo, which).status_code == allowed


def test_the_login_screens_have_their_own_allowance(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    """A page that polls from the same network does not use up the logins, nor the logins the polls."""
    demo = make_demo(replace(demo_settings, logins_per_minute=2, polls_per_minute=2))
    made = demo.started(credential="pid")
    assert [demo.client.get(f"/api/sessions/{made['id']}").status_code for _ in range(3)] == [200, 200, 429]
    assert [screen(demo, "login page").status_code for _ in range(3)] == [410, 410, 429]


def test_the_limit_on_logins_is_a_setting(demo_settings: DemoSettings, tmp_path: Path) -> None:
    assert demo_settings.logins_per_minute == 60
    token, key = tmp_path / "token", tmp_path / "key"
    token.write_text(ADMIN_TOKEN + "\n")
    key.write_bytes(os.urandom(32))
    for path in (token, key):
        path.chmod(0o600)
    env = {
        "DEMO_PUBLIC_URL": ORIGIN,
        "DEMO_PID_ADMIN_URL": "http://cunho-pid:8000/pid",
        "DEMO_PID_ADMIN_TOKEN_FILE": str(token),
        "DEMO_COURSE_ADMIN_URL": "http://cunho-course:8000/course",
        "DEMO_COURSE_ADMIN_TOKEN_FILE": str(token),
        "DEMO_SECRET_KEY_FILE": str(key),
    }
    assert DemoSettings.from_env(env).logins_per_minute == 60
    assert DemoSettings.from_env({**env, "DEMO_LOGINS_PER_MINUTE": "7"}).logins_per_minute == 7
    shipped = DemoSettings.from_env(env)
    assert (shipped.sessions_per_client, shipped.progress_per_minute) == (40, 3000)
    changed = DemoSettings.from_env({**env, "DEMO_SESSIONS_PER_CLIENT": "9", "DEMO_PROGRESS_PER_MINUTE": "11"})
    assert (changed.sessions_per_client, changed.progress_per_minute) == (9, 11)
    with pytest.raises(DemoConfigError, match="logins_per_minute must be positive"):
        replace(demo_settings, logins_per_minute=0)


# --- the console's cookie -----------------------------------------------------------------------------------------


def test_the_console_cookie_can_only_be_set_by_this_host(console_demo: Demo) -> None:
    """With the __Host- prefix a browser takes the cookie only from this host, over https, for the whole site and
    with no Domain: another site under the same domain cannot plant one of its own in the operator's browser."""
    cookie = sign_in(console_demo).headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    assert "Secure" in cookie and "Path=/" in cookie and "domain" not in cookie.lower()
    text, token = console(console_demo)
    assert "Sign out" in text, "the session is found by the cookie under its new name"
    out = console_demo.client.post(
        "/operator/logout", data={"csrf": token}, headers={"Origin": ORIGIN}, follow_redirects=False
    )
    gone = out.headers["set-cookie"]
    assert gone.startswith(f'{COOKIE}="";') and "Secure" in gone and "Path=/" in gone, (
        "a browser lets a __Host- cookie be replaced only by one that is Secure with Path=/"
    )


def test_a_local_http_run_keeps_a_plain_cookie_name(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    """A browser refuses a __Host- cookie that is not Secure, and a local run over plain http cannot set Secure."""
    local = "http://localhost:8099"
    demo = make_demo(replace(demo_settings, public_url=local, operator_password_hash=STORED))
    answer = demo.client.post(
        "/operator/login", data={"password": PASSWORD}, headers={"Origin": local}, follow_redirects=False
    )
    assert answer.status_code == 303
    assert answer.headers["set-cookie"].startswith("demo_operator=") and "Secure" not in answer.headers["set-cookie"]


# --- what one client network can hold, and what counts as one ---------------------------------------------------------


def visitor(demo: Demo, address: str) -> TestClient:
    """The demo as a visitor at this address reaches it."""
    return TestClient(demo.client.app, base_url=ORIGIN, raise_server_exceptions=False, client=(address, 50000))


def offer(client: TestClient, **body: Any) -> Any:
    return client.post("/api/sessions", json={"credential": "pid", **body}, headers={"Origin": ORIGIN})


def test_a_network_holds_only_so_many_sessions_and_its_own_oldest_gives_way() -> None:
    """Without the bound, seven networks making ten offers a minute held all 2000 places for the half hour a
    session lives, and every other visitor was told the demo is busy."""
    table = Sessions(ttl=1800, max_sessions=10, offer_ttl=600, clock=lambda: 1000.0, per_client=2)

    def made(client: str) -> Session:
        session = Session("pid", "both", "pre-authorized_code", "ana", [], client=client)
        assert table.add(session)
        return session

    first, other, second, third = made("198.51.100.7/32"), made("203.0.113.9/32"), made("198.51.100.7/32"), None
    assert len(table) == 3
    third = made("198.51.100.7/32")
    assert table.get(first.id) is None, "the network's oldest gave way"
    assert table.get(second.id) is second and table.get(third.id) is third
    assert table.get(other.id) is other, "another network's session is never touched"
    assert len(Sessions(1800, 10, 600, lambda: 1000.0)._sessions) == 0  # no bound unless one is given: nothing to count


def test_the_bound_on_a_network_is_a_setting_and_the_page_keeps_working(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    demo = make_demo(replace(demo_settings, sessions_per_client=2))
    here, elsewhere = visitor(demo, "198.51.100.7"), visitor(demo, "203.0.113.9")
    theirs = offer(elsewhere).json()["id"]
    mine = [offer(here).json()["id"] for _ in range(3)]
    assert [here.get(f"/api/sessions/{each}").status_code for each in mine] == [404, 200, 200]
    assert elsewhere.get(f"/api/sessions/{theirs}").status_code == 200
    with pytest.raises(DemoConfigError, match="sessions_per_client must be positive"):
        replace(demo_settings, sessions_per_client=0)


def test_one_home_connection_is_one_client_whatever_its_ipv6_addresses(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    """A home connection is usually given a /56: 256 networks of /64. Counted by /64, it was 256 clients to every
    limit of the demo."""
    demo = make_demo(replace(demo_settings, sessions_per_minute=1))
    assert offer(visitor(demo, "2001:db8:0:100::1")).status_code == 201
    assert offer(visitor(demo, "2001:db8:0:1ff::99")).status_code == 429, "another /64 of the same /56"
    assert offer(visitor(demo, "2001:db8:0:200::1")).status_code == 201, "the next /56 is another client"
    assert offer(visitor(demo, "198.51.100.7")).status_code == 201


# --- the visitors' polling and the operator API ---------------------------------------------------------------------


def test_polling_past_the_visitors_share_is_answered_with_what_was_read_last(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    """Every poll was one call of the operator API with the one operator token: twenty-five networks polling as
    fast as the demo let each of them used up what the issuer allows that token, and offers, logins and the
    console's own actions were turned away with them."""
    demo = make_demo(replace(demo_settings, progress_per_minute=3))
    made = demo.started(credential="pid")
    asked: list[str] = []
    issuer = demo.client.app.state.issuers["pid"]  # type: ignore[attr-defined]
    read = issuer.progress

    async def counted(subject_ref: str) -> dict[str, Any]:
        asked.append(subject_ref)
        answer: dict[str, Any] = await read(subject_ref)
        return answer

    issuer.progress = counted
    steps = [demo.step(made["id"]) for _ in range(8)]
    assert steps == ["waiting"] * 8
    assert len(asked) == 4, "the first read of a session, then this minute's share of three"
    phone = demo.client.get(f"/api/offers/{made['phone_path'].rsplit('/', 1)[1]}")
    assert phone.status_code == 200 and phone.json()["step"] == "waiting" and len(asked) == 4
    # What the visitor does is always asked of the issuer, and answered by what it says now.
    assert demo.act(made["id"], "revoke").json()["step"] == "revoked"
    assert len(asked) == 5
    assert demo.step(made["id"]) == "revoked", "a poll shows what the last read showed"
    another = demo.started(credential="pid")
    assert demo.step(another["id"]) == "waiting" and len(asked) == 6, "a session never read is read once"
    demo.ticker.now += 120
    demo.step(made["id"])
    assert len(asked) == 7, "and in the next minute the polls ask again"
    with pytest.raises(DemoConfigError, match="progress_per_minute must be positive"):
        replace(demo_settings, progress_per_minute=0)


# --- the demo wallet and the issuers' limits per client -------------------------------------------------------------


class Fronted(httpx.AsyncBaseTransport):
    """An issuer as the stack runs it (deploy/compose.yaml): uvicorn takes the client's address from the
    X-Forwarded-For header of whoever calls it, the proxy in front or the demo service."""

    def __init__(self) -> None:
        self.inner: httpx.AsyncBaseTransport | None = None
        self.named: list[str | None] = []  # the address each wallet request named, None for none

    def serve(self, issuer: Issuer) -> None:
        served: Any = cunho_app(issuer=issuer, background_maintenance=False)
        self.inner = httpx.ASGITransport(app=ProxyHeadersMiddleware(served, trusted_hosts="*"))  # type: ignore[arg-type]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert self.inner is not None
        if "/admin/" not in request.url.path:
            self.named.append(request.headers.get("x-forwarded-for"))
        return await self.inner.handle_async_request(request)


def run_of(demo: Demo, address: str | None) -> dict[str, Any]:
    """One visitor's demo wallet, from a new PID offer to the end of its run. `address` is the visitor's, as the
    proxy in front of the demo names it; None for a connection that names none."""
    headers = {"Origin": ORIGIN, **({"X-Forwarded-For": address} if address else {})}
    made = demo.client.post("/api/sessions", json={"credential": "pid"}, headers=headers).json()
    started = demo.client.post(f"/api/sessions/{made['id']}/demo-wallet", json={}, headers=headers)
    assert started.status_code == 202, started.text
    end = time.monotonic() + 20
    while time.monotonic() < end:
        run: dict[str, Any] = demo.client.get(f"/api/sessions/{made['id']}", headers=headers).json()["wallet"]
        if run["state"] != "running":
            demo.client.post(f"/api/sessions/{made['id']}/status", json={}, headers=headers)
            return run
        time.sleep(0.02)
    raise AssertionError("the demo wallet did not end")


def test_the_demo_wallet_is_counted_at_the_issuer_as_the_visitor_it_acts_for(
    make_demo: Callable[..., Demo],
    make_issuer: Callable[..., Issuer],
    demo_settings: DemoSettings,
    ka_files: tuple[Path, Path],  # noqa: F811 - the fixture imported above
    clock: Any,
) -> None:
    """To an issuer every request of the demo wallet came from one address, the demo service's, so all visitors
    shared the one allowance an issuer gives a client: thirty PID runs a minute for the whole demo with the
    shipped limit, and the thirty-first visitor's run cut short with its offer spent."""
    fronts = {"pid": Fronted(), "course": Fronted()}
    settings = replace(demo_settings, wallet_ka_chain=ka_files[0], wallet_ka_key=ka_files[1])
    demo = make_demo(
        settings,
        transports=fronts,
        # Four requests a minute for each group of routes: what one PID run takes of the credential group.
        issuer=lambda **kw: make_issuer(**{**kw, "rate_limit_per_minute": 4}),
        # The demo itself as the stack runs it: the visitor's address comes from the proxy in front.
        front=lambda app: ProxyHeadersMiddleware(app, trusted_hosts="*"),
    )
    fronts["pid"].serve(demo.pid)
    fronts["course"].serve(demo.course)
    demo.client.app.app.state.wallet.clock = clock  # type: ignore[attr-defined]  # as cunho reads proofs by it
    assert run_of(demo, "198.51.100.7")["state"] == "done"
    again = run_of(demo, "198.51.100.7")
    assert again["state"] == "failed" and again["error"] == "wallet_refused", "the first visitor's own allowance"
    assert run_of(demo, "2001:db8::7")["state"] == "done", "another visitor's run does not pay for it"
    assert set(fronts["pid"].named) == {"198.51.100.7", "2001:db8::7"}, "every request names its visitor"
    # The phone page's demo wallet and status check name the visitor on the phone, not the one who made the offer.
    made = demo.client.post(
        "/api/sessions", json={"credential": "pid"}, headers={"Origin": ORIGIN, "X-Forwarded-For": "203.0.113.50"}
    ).json()
    by_reference = f"/api/offers/{made['phone_path'].rsplit('/', 1)[1]}"
    phone = {"Origin": ORIGIN, "X-Forwarded-For": "203.0.113.99"}
    fronts["pid"].named.clear()
    assert demo.client.post(f"{by_reference}/demo-wallet", json={}, headers=phone).status_code == 202
    end = time.monotonic() + 20
    while demo.client.get(f"/api/sessions/{made['id']}").json()["wallet"]["state"] == "running":
        assert time.monotonic() < end, "the demo wallet did not end"
        time.sleep(0.02)
    assert set(fronts["pid"].named) == {"203.0.113.99"}
    for path, address in (
        (f"/api/sessions/{made['id']}/status", "203.0.113.50"),
        (f"{by_reference}/status", "203.0.113.99"),
    ):
        fronts["pid"].named.clear()
        checked = demo.client.post(path, json={}, headers={"Origin": ORIGIN, "X-Forwarded-For": address})
        assert checked.status_code == 200 and set(fronts["pid"].named) == {address}, path
    # A connection that gives no address names nobody: the issuer then counts the demo service, as before.
    fronts["pid"].named.clear()
    run_of(demo, None)
    assert set(fronts["pid"].named) == {None}
