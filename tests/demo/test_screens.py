"""The demo's login and consent screens, driven the way a wallet's browser drives them: the wallet pushes its
request, the browser lands on the demo's login, picks a fictional person, agrees, and goes back through cunho to
the wallet, which collects the credential. A held issuance is released or refused from the page."""

from __future__ import annotations

import html
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode, urlsplit

import pytest

from cunho.service import Issuer
from cunho_demo.offers import CARD, COURSE_MDOC, COURSE_SD_JWT, PID_SD_JWT
from eudi_probe.jose import EcKey
from tests.engine.codewallet import CodeWallet, Pkce, Redirect

from .conftest import ORIGIN, Demo, offer_of

HIDDEN = re.compile(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)">')
ONWARD = re.compile(r'<a class="button primary" href="([^"]+)">')

INES_COURSE = "Privacidade desde a conceção"  # her course in personas.json


def onward(answer: Any) -> str:
    """Where the page after a login sends the browser: by refresh and by link, to the same place."""
    assert answer.status_code == 200, answer.text
    [link] = ONWARD.findall(answer.text)
    target = html.unescape(link)
    assert f'<meta http-equiv="refresh" content="0; url={link}">' in answer.text
    return target


@pytest.fixture
def code_demo(
    make_demo: Callable[..., Demo],
    make_code_issuer: Callable[..., Issuer],
) -> Demo:
    return make_demo(issuer=make_code_issuer)


@pytest.fixture
def wallets(code_demo: Demo, code_wallet_for: Callable[[Issuer], CodeWallet]) -> dict[str, CodeWallet]:
    return {"pid": code_wallet_for(code_demo.pid), "course": code_wallet_for(code_demo.course)}


def hidden(page: str) -> dict[str, str]:
    return {name: html.unescape(value) for name, value in HIDDEN.findall(page)}


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.path}?{parts.query}" if parts.query else parts.path


class Browser:
    """The person's browser between the wallet, cunho and the demo's screens."""

    def __init__(self, demo: Demo, wallet: CodeWallet) -> None:
        self.demo, self.wallet = demo, wallet

    def start(self, issuer: str, scope: str, *, issuer_state: str | None = None) -> tuple[str, Pkce]:
        """The wallet pushes its request and opens the authorization endpoint; returns where cunho sends the
        browser, the demo's login."""
        pkce = Pkce.random()
        pushed = self.wallet.par(pkce, scope=scope, state="st", issuer_state=issuer_state)
        assert pushed.status_code == 201, pushed.text
        location = self.wallet.authorize(pushed.json()["request_uri"]).headers["location"]
        assert location.startswith(f"{ORIGIN}/login/{issuer}?login_state="), location
        return location, pkce

    def post(self, path: str, fields: dict[str, str], **headers: str) -> Any:
        return self.demo.client.post(path, data=fields, headers={"Origin": ORIGIN, **headers}, follow_redirects=False)

    def through(self, location: str, persona: str = "ana", **extra: str) -> Any:
        """The login and the consent; returns the consent's answer."""
        login = self.demo.client.get(path_of(location))
        assert login.status_code == 200, login.text
        issuer = urlsplit(location).path.rsplit("/", 1)[1]
        consent = self.post(f"/login/{issuer}", {**hidden(login.text), "persona": persona})
        assert consent.status_code == 200, consent.text
        fields = {**hidden(consent.text), "action": "issue", **extra}
        return self.post(f"/consent/{issuer}", fields)

    def back_to_wallet(self, answer: Any, pkce: Pkce) -> None:
        """cunho's continue URL, then the wallet's redirect with the code, then the token."""
        back = self.wallet.client.get(onward(answer), follow_redirects=False)
        code = Redirect(303, back.headers["location"]).params["code"]
        tokens = self.wallet.code_token_request(code, pkce)
        assert tokens.status_code == 200, tokens.text
        self.wallet.token = tokens.json()["access_token"]


def scope_of(issuer: Issuer, config: str) -> str:
    found = issuer.configs.get(config)
    assert found is not None
    return str(found["scope"])


# the wallet starts from the page's QR code -----------------------------------------------------------------------


def test_a_code_flow_offer_from_qr_code_to_issued(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    made = code_demo.started(credential="course", flow="authorization_code", persona="joao")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    browser = Browser(code_demo, wallets["course"])
    location, pkce = browser.start("course", scope_of(code_demo.course, COURSE_SD_JWT), issuer_state=issuer_state)
    assert code_demo.step(made["id"]) == "waiting"
    login = code_demo.client.get(path_of(location))
    assert code_demo.step(made["id"]) == "signing_in", "the page sees the wallet's browser arrive"
    assert 'value="joao" checked' in login.text, "the person the page showed is chosen already"
    consent = browser.post("/login/course", {**hidden(login.text), "persona": "ines"})
    assert "Privacidade desde a conceção" in consent.text and "cunho test wallet" in consent.text
    answer = browser.post("/consent/course", {**hidden(consent.text), "action": "issue"})
    browser.back_to_wallet(answer, pkce)
    assert code_demo.step(made["id"]) == "connected"
    assert wallets["course"].issue([EcKey.generate()], config=COURSE_SD_JWT).status_code == 200
    assert code_demo.step(made["id"]) == "issued"
    session = code_demo.client.app.state.sessions.get(made["id"])  # type: ignore[attr-defined]
    assert session.persona == "ines"
    view = code_demo.client.get(f"/api/sessions/{made['id']}").json()
    assert view["persona"] == {"id": "ines", "name": "Inês Gonçalves Rodrigues"}, "the page shows who it was issued to"
    shown = dict(view["card"])
    assert list(shown) == list(CARD["course"]), "the course card shows the course, not the person's identity"
    assert shown["achievement_title"] == INES_COURSE and made["card"][0][1] != INES_COURSE, "and the course is hers"


def test_a_held_issuance_released_from_the_page(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    from tests.engine.test_deferred import deferred

    made = code_demo.started(credential="pid", flow="authorization_code")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    wallet = wallets["pid"]
    browser = Browser(code_demo, wallet)
    location, pkce = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT), issuer_state=issuer_state)
    browser.back_to_wallet(browser.through(location, review="true"), pkce)
    held = wallet.issue([EcKey.generate()], config=PID_SD_JWT)
    assert held.status_code == 202, held.text
    assert code_demo.step(made["id"]) == "held"
    released = code_demo.act(made["id"], "release")
    assert released.status_code == 200 and released.json()["step"] == "released"
    assert code_demo.act(made["id"], "release").status_code == 409, "nothing held any more"
    collected = deferred(wallet, {"transaction_id": held.json()["transaction_id"]})
    assert collected.status_code == 200, collected.text
    assert code_demo.step(made["id"]) == "issued", "the wallet asked for the SD-JWT VC alone"


def test_a_held_issuance_refused_from_the_page(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    made = code_demo.started(credential="course", flow="authorization_code")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    wallet = wallets["course"]
    browser = Browser(code_demo, wallet)
    location, pkce = browser.start("course", scope_of(code_demo.course, COURSE_SD_JWT), issuer_state=issuer_state)
    browser.back_to_wallet(browser.through(location, review="true"), pkce)
    assert wallet.issue([EcKey.generate()], config=COURSE_SD_JWT).status_code == 202
    assert code_demo.act(made["id"], "refuse").json()["step"] == "refused"


def test_one_session_cannot_release_another_sessions_issuance(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    made = code_demo.started(credential="course", flow="authorization_code")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    browser = Browser(code_demo, wallets["course"])
    location, pkce = browser.start("course", scope_of(code_demo.course, COURSE_SD_JWT), issuer_state=issuer_state)
    browser.back_to_wallet(browser.through(location, review="true"), pkce)
    assert wallets["course"].issue([EcKey.generate()], config=COURSE_SD_JWT).status_code == 202
    other = code_demo.started(credential="course")
    assert code_demo.act(other["id"], "release").status_code == 409
    assert code_demo.step(made["id"]) == "held"


# the wallet starts on its own ------------------------------------------------------------------------------------


def test_a_wallet_initiated_login_needs_no_page(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    browser = Browser(code_demo, wallets["pid"])
    location, pkce = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
    browser.back_to_wallet(browser.through(location), pkce)
    assert wallets["pid"].issue([EcKey.generate()], config=PID_SD_JWT).status_code == 200


def test_cancel_sends_the_wallet_access_denied(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    browser = Browser(code_demo, wallets["pid"])
    for at in ("login", "consent"):
        location, _ = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
        login = code_demo.client.get(path_of(location))
        fields = hidden(login.text)
        if at == "consent":
            fields = hidden(browser.post("/login/pid", {**fields, "persona": "ana"}).text)
        answer = browser.post("/consent/pid", {**fields, "action": "cancel"})
        back = wallets["pid"].client.get(onward(answer), follow_redirects=False)
        assert Redirect(303, back.headers["location"]).params["error"] == "access_denied"


def test_one_format_of_the_course_certificate_at_a_time(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    scopes = f"{scope_of(code_demo.course, COURSE_SD_JWT)} {scope_of(code_demo.course, COURSE_MDOC)}"
    location, _ = Browser(code_demo, wallets["course"]).start("course", scopes)
    login = code_demo.client.get(path_of(location))
    refused = Browser(code_demo, wallets["course"]).post("/login/course", {**hidden(login.text), "persona": "ana"})
    assert refused.status_code == 400 and "one format" in refused.text


def test_the_mdoc_course_certificate_by_the_code_flow(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    browser = Browser(code_demo, wallets["course"])
    location, pkce = browser.start("course", scope_of(code_demo.course, COURSE_MDOC))
    browser.back_to_wallet(browser.through(location), pkce)
    proof = wallets["course"].proof(EcKey.generate(), wallets["course"].c_nonce(), attest=False)
    issued = wallets["course"].credential_request(
        {"credential_configuration_id": COURSE_MDOC, "proofs": {"jwt": [proof]}}
    )
    assert issued.status_code == 200, issued.text


# what the screens refuse ---------------------------------------------------------------------------------------


def test_a_login_the_issuer_does_not_know(code_demo: Demo) -> None:
    gone = code_demo.client.get("/login/pid?login_state=" + "x" * 43)
    assert gone.status_code == 410 and "expired or was already used" in gone.text
    for path in ("/login/pid?login_state=short", "/login/pid", "/login/bank?login_state=" + "x" * 43):
        assert code_demo.client.get(path).status_code == 400, path


def test_forms_from_elsewhere_are_refused(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    browser = Browser(code_demo, wallets["pid"])
    location, _ = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
    fields = hidden(code_demo.client.get(path_of(location)).text)
    forged = {**fields, "token": "0" * 64}
    assert browser.post("/login/pid", {**forged, "persona": "ana"}).status_code == 400
    assert browser.post("/consent/pid", {**forged, "action": "issue", "persona": "ana"}).status_code == 400
    other_site = code_demo.client.post(
        "/consent/pid",
        data={**fields, "action": "issue", "persona": "ana"},
        headers={"Origin": "https://evil.test"},
        follow_redirects=False,
    )
    assert other_site.status_code == 400
    as_json = code_demo.client.post("/consent/pid", json={**fields, "action": "issue", "persona": "ana"})
    assert as_json.status_code == 400
    other_issuer = browser.post("/consent/course", {**fields, "action": "issue", "persona": "ana"})
    assert other_issuer.status_code == 400, "a form is bound to its issuer too"
    assert browser.post("/login/pid", {**fields, "persona": "mallory"}).status_code == 400
    assert browser.post("/consent/pid", {**fields, "action": "issue", "persona": "mallory"}).status_code == 400
    plain = code_demo.client.post(
        "/consent/pid",
        content=urlencode({**fields, "action": "issue", "persona": "ana"}).encode(),
        headers={"Origin": ORIGIN, "Content-Type": "text/plain"},
    )
    assert plain.status_code == 400, "a form is application/x-www-form-urlencoded, nothing else"
    assert browser.post("/consent/pid", {**fields, "action": "steal", "persona": "ana"}).status_code == 400
    assert code_demo.client.get(path_of(location)).status_code == 200, "nothing was reported"


def test_a_login_reported_twice(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    browser = Browser(code_demo, wallets["pid"])
    location, _ = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
    login = code_demo.client.get(path_of(location))
    consent = hidden(browser.post("/login/pid", {**hidden(login.text), "persona": "ana"}).text)
    assert browser.post("/consent/pid", {**consent, "action": "issue"}).status_code == 200
    again = browser.post("/consent/pid", {**consent, "action": "issue"})
    assert again.status_code == 410


def test_what_the_wallet_names_itself_is_shown_as_text(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    wallet = wallets["pid"]
    original = wallet.attestation

    def named(**claims: Any) -> str:
        return original(**{"wallet_name": '<img src=x onerror="alert(1)">', **claims})

    wallet.attestation = named  # type: ignore[method-assign]
    browser = Browser(code_demo, wallet)
    location, _ = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
    login = code_demo.client.get(path_of(location))
    consent = browser.post("/login/pid", {**hidden(login.text), "persona": "ana"})
    assert "<img" not in consent.text and "&lt;img src=x" in consent.text


def test_screens_in_portuguese(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    browser = Browser(code_demo, wallets["pid"])
    location, _ = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
    by_header = code_demo.client.get(path_of(location), headers={"Accept-Language": "pt-PT,pt;q=0.9,en;q=0.5"})
    assert '<html lang="pt">' in by_header.text and "Entrar como" in by_header.text
    consent = browser.post("/login/pid", {**hidden(by_header.text), "persona": "ines"})
    assert "Emitir para a sua carteira?" in consent.text and "Data de nascimento" in consent.text
    assert "Braga" in consent.text and "Gonçalves Rodrigues" in consent.text
    english = code_demo.client.get(path_of(location) + "&lang=en", headers={"Accept-Language": "pt"})
    assert '<html lang="en">' in english.text


def test_an_issuer_that_cannot_be_reached_from_the_screens(code_demo: Demo) -> None:
    import httpx

    from cunho_demo.client import Cunho
    from cunho_demo.settings import IssuerLink

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    code_demo.client.app.state.issuers["pid"]._client = Cunho(  # type: ignore[attr-defined]
        IssuerLink("https://issuer.test", "t" * 40), httpx.MockTransport(down)
    )._client
    response = code_demo.client.get("/login/pid?login_state=" + "x" * 43)
    assert response.status_code == 503 and "not reachable" in response.text


def test_the_screens_carry_the_security_headers(code_demo: Demo) -> None:
    response = code_demo.client.get("/login/pid?login_state=" + "x" * 43)
    assert "script-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "same-origin"


# the second look: cancelled and abandoned logins, and the way back to the wallet --------------------------------


def test_a_cancelled_login_shows_on_the_page(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    made = code_demo.started(credential="course", flow="authorization_code")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    browser = Browser(code_demo, wallets["course"])
    location, _ = browser.start("course", scope_of(code_demo.course, COURSE_SD_JWT), issuer_state=issuer_state)
    login = code_demo.client.get(path_of(location))
    assert code_demo.step(made["id"]) == "signing_in"
    answer = browser.post("/consent/course", {**hidden(login.text), "action": "cancel"})
    assert answer.status_code == 200
    assert code_demo.step(made["id"]) == "cancelled"


def test_an_abandoned_login_ends_with_its_login(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    made = code_demo.started(credential="course", flow="authorization_code")
    issuer_state = offer_of(made["offer_link"])["grants"]["authorization_code"]["issuer_state"]
    location, _ = Browser(code_demo, wallets["course"]).start(
        "course", scope_of(code_demo.course, COURSE_SD_JWT), issuer_state=issuer_state
    )
    code_demo.ticker.now += 590
    code_demo.client.get(path_of(location))
    code_demo.ticker.now += 20
    assert code_demo.step(made["id"]) == "signing_in", "a login opened late keeps the page waiting for it"
    code_demo.ticker.now += 570
    code_demo.client.get(path_of(location))  # a reload, or the other language, does not move the deadline
    code_demo.ticker.now += 30
    assert code_demo.step(made["id"]) == "expired"


def test_the_way_back_is_a_new_navigation_not_a_form_redirect(code_demo: Demo, wallets: dict[str, CodeWallet]) -> None:
    """The second reviewer: the CSP's form-action allows only this site, and browsers check a form's redirects
    against it, so the screens never answer a form with a redirect to cunho."""
    browser = Browser(code_demo, wallets["pid"])
    location, _ = browser.start("pid", scope_of(code_demo.pid, PID_SD_JWT))
    answer = browser.through(location)
    assert answer.status_code == 200 and "location" not in answer.headers
    assert "form-action 'self'" in answer.headers["content-security-policy"]
    assert onward(answer).startswith("https://issuer.test/authorize/continue?")
