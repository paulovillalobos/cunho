"""The operator console: a password, a session in a strict cookie, a token in every form, and what an operator does
with held issuances and revocations, through the same admin API as the page."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from cunho.service import Issuer
from cunho_demo.console import hash_password, password_matches
from cunho_demo.offers import COURSE_SD_JWT
from cunho_demo.settings import DemoConfigError, DemoSettings
from eudi_probe.jose import EcKey
from tests.engine.codewallet import CodeWallet

from .conftest import ORIGIN, Demo, offer_of, scan
from .test_screens import Browser, scope_of

PASSWORD = "correct horse battery staple"
STORED = hash_password(PASSWORD)
CSRF = re.compile(r'name="csrf" value="([0-9a-f]{64})"')


@pytest.fixture
def console_demo(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings, make_code_issuer: Callable[..., Issuer]
) -> Demo:
    return make_demo(replace(demo_settings, operator_password_hash=STORED), issuer=make_code_issuer)


def sign_in(demo: Demo, password: str = PASSWORD) -> Any:
    return demo.client.post(
        "/operator/login", data={"password": password}, headers={"Origin": ORIGIN}, follow_redirects=False
    )


def console(demo: Demo) -> tuple[str, str]:
    page = demo.client.get("/operator")
    assert page.status_code == 200
    [token] = set(CSRF.findall(page.text))
    return page.text, token


def act(demo: Demo, token: str, **fields: str) -> Any:
    return demo.client.post(
        "/operator/action", data={"csrf": token, **fields}, headers={"Origin": ORIGIN}, follow_redirects=False
    )


def test_passwords_are_kept_as_scrypt() -> None:
    assert STORED.startswith("scrypt$32768$8$1$") and PASSWORD not in STORED
    assert password_matches(PASSWORD, STORED)
    assert not password_matches(PASSWORD + "!", STORED)
    assert hash_password(PASSWORD) != STORED, "a salt of its own each time"
    for broken in ("", "plain", "bcrypt$1$2$3$4$5", "scrypt$x$8$1$AA$AA"):
        assert not password_matches(PASSWORD, broken)


def test_no_console_without_a_password(demo: Demo) -> None:
    assert demo.client.get("/operator").status_code == 404
    assert sign_in(demo).status_code in (404, 405), "no such route: the static files answer"


def test_a_password_that_is_not_a_hash_is_refused(demo_settings: DemoSettings) -> None:
    with pytest.raises(DemoConfigError, match="hash"):
        replace(demo_settings, operator_password_hash=PASSWORD)


def test_signing_in_and_out(console_demo: Demo) -> None:
    page = console_demo.client.get("/operator")
    assert page.status_code == 200 and 'type="password"' in page.text and "Held" not in page.text
    wrong = sign_in(console_demo, "guess")
    assert wrong.status_code == 401 and "set-cookie" not in wrong.headers
    right = sign_in(console_demo)
    assert right.status_code == 303 and right.headers["location"] == "/operator"
    cookie = right.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie and "Secure" in cookie and "Path=/" in cookie
    text, token = console(console_demo)
    assert "Audit log: <strong>verifies</strong>" in text and text.count("Nothing held for review.") == 2
    out = console_demo.client.post(
        "/operator/logout", data={"csrf": token}, headers={"Origin": ORIGIN}, follow_redirects=False
    )
    assert out.status_code == 303
    console_demo.client.cookies.clear()
    assert 'type="password"' in console_demo.client.get("/operator").text


def test_a_signed_out_session_is_dead(console_demo: Demo) -> None:
    sign_in(console_demo)
    cookie = console_demo.client.cookies.get("__Host-demo_operator")
    _, token = console(console_demo)
    console_demo.client.post("/operator/logout", data={"csrf": token}, headers={"Origin": ORIGIN})
    console_demo.client.cookies.set("__Host-demo_operator", cookie or "")
    assert 'type="password"' in console_demo.client.get("/operator").text


def test_wrong_passwords_are_limited(console_demo: Demo) -> None:
    """The second reviewer: past the limit even the right password is refused, so guessing gets nowhere."""
    codes = [sign_in(console_demo, f"guess {n}").status_code for n in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert sign_in(console_demo).status_code == 429, "not checked at all until the window ends"
    console_demo.ticker.now += 60
    assert sign_in(console_demo).status_code == 303
    for n in range(4):
        assert sign_in(console_demo, f"again {n}").status_code == 401
    assert sign_in(console_demo).status_code == 303, "under the limit the right password works"


def test_a_session_lasts_eight_hours(console_demo: Demo) -> None:
    sign_in(console_demo)
    console_demo.ticker.now += 8 * 3600
    assert 'type="password"' in console_demo.client.get("/operator").text


def test_forms_need_the_session_and_its_token(console_demo: Demo) -> None:
    signed_out = act(console_demo, "0" * 64, issuer="course", action="revoke", subject_ref="sub_" + "A" * 24)
    assert signed_out.status_code == 401
    sign_in(console_demo)
    _, token = console(console_demo)
    forged = act(console_demo, "0" * 64, issuer="course", action="revoke", subject_ref="sub_" + "A" * 24)
    assert forged.status_code == 400
    elsewhere = console_demo.client.post(
        "/operator/action",
        data={"csrf": token, "issuer": "course", "action": "revoke", "subject_ref": "sub_" + "A" * 24},
        headers={"Origin": "https://evil.test"},
    )
    assert elsewhere.status_code == 400
    for fields in (
        {"issuer": "bank", "action": "revoke", "subject_ref": "sub_" + "A" * 24},
        {"issuer": "course", "action": "erase", "subject_ref": "sub_" + "A" * 24},
        {"issuer": "course", "action": "revoke", "subject_ref": "../admin"},
        {"issuer": "course", "action": "release", "ref": "../../x"},
    ):
        assert act(console_demo, token, **fields).status_code == 400, fields


def test_revoking_from_the_console(console_demo: Demo) -> None:
    made = console_demo.started(credential="course")
    scan(console_demo.wallets["course"], made)
    assert console_demo.wallets["course"].issue(config=COURSE_SD_JWT).status_code == 200
    sign_in(console_demo)
    text, token = console(console_demo)
    session = console_demo.client.app.state.sessions.get(made["id"])  # type: ignore[attr-defined]
    assert session.subject_ref in text, "the demo sessions under way are listed"
    done = act(console_demo, token, issuer="course", action="revoke", subject_ref=session.subject_ref)
    assert done.status_code == 303 and done.headers["location"] == "/operator?done=revoked%201"
    assert "Done: revoked 1" in console_demo.client.get(done.headers["location"]).text
    assert console_demo.step(made["id"]) == "revoked", "the visitor's page says so (the second reviewer)"
    again = act(console_demo, token, issuer="course", action="revoke", subject_ref="sub_" + "A" * 24)
    assert again.status_code == 409 and "The issuer refused" in again.text


def test_releasing_a_held_issuance_from_the_console(
    console_demo: Demo, code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    from tests.engine.test_deferred import deferred

    wallet = code_wallet_for(console_demo.course)
    made = console_demo.started(credential="course", flow="authorization_code")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    browser = Browser(console_demo, wallet)
    location, pkce = browser.start("course", scope_of(console_demo.course, COURSE_SD_JWT), issuer_state=issuer_state)
    browser.back_to_wallet(browser.through(location, review="true"), pkce)
    held = wallet.issue([EcKey.generate()], config=COURSE_SD_JWT)
    assert held.status_code == 202
    sign_in(console_demo)
    text, token = console(console_demo)
    [ref] = re.findall(r'name="ref" value="([0-9a-f]{32})"', text)
    assert act(console_demo, token, issuer="course", action="release", ref=ref).status_code == 303
    assert console_demo.step(made["id"]) == "released"
    assert deferred(wallet, {"transaction_id": held.json()["transaction_id"]}).status_code == 200
    assert act(console_demo, token, issuer="course", action="refuse", ref=ref).status_code == 409


def test_an_issuer_that_cannot_be_reached_from_the_console(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    import httpx

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(down)
    demo = make_demo(
        replace(demo_settings, operator_password_hash=STORED), transports={"pid": transport, "course": transport}
    )
    sign_in(demo)
    page = demo.client.get("/operator")
    assert page.status_code == 200 and page.text.count("Not reachable (503)") == 2


def test_attempts_take_their_place_before_the_password_is_checked() -> None:
    """The second reviewer: attempts sent at once all passed the check before any of them failed. Each now takes
    its place first, and a right password gives its place back."""
    from cunho_demo.console import FailedLogins

    now = [0.0]
    attempts = FailedLogins(lambda: now[0])
    assert all(attempts.begin("net") for _ in range(5)), "five at once, none checked yet"
    assert not attempts.begin("net"), "the sixth is refused before its password is checked"
    attempts.succeeded("net")
    assert attempts.begin("net") and not attempts.begin("net")
    assert attempts.begin("other"), "networks are counted apart"
    now[0] = 60
    assert attempts.begin("net"), "a new window"
    attempts.succeeded("unknown")


def test_the_table_of_networks_stays_bounded() -> None:
    """The second reviewer: when every place holds a live window, a new network is refused, not added."""
    from cunho_demo.console import FailedLogins

    now = [0.0]
    attempts = FailedLogins(lambda: now[0], max_networks=2)
    assert attempts.begin("a") and attempts.begin("b")
    assert not attempts.begin("c"), "full of live windows"
    assert attempts.begin("a"), "a network already counted goes on"
    now[0] = 60
    assert attempts.begin("c"), "room once the windows end"
