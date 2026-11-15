"""The demo service's API: offers for fictional people, the QR code, the live steps, revocation, and the limits that
keep a public page from being turned against the issuers behind it."""

from __future__ import annotations

import datetime as dt
import json
import os
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from cunho_demo.offers import COURSE_MDOC, COURSE_SD_JWT, DEMO_AUTHORITY, PID_MDOC, PID_SD_JWT, step
from cunho_demo.settings import DemoConfigError, DemoSettings, IssuerLink
from eudi_probe.jose import EcKey
from tests.engine.helpers import ADMIN_TOKEN, ISSUER, disclosures
from tests.engine.test_course_certificate import revealed

from .conftest import TODAY, Demo, offer_of, scan


def notify(wallet: Any, notification_id: str, event: str = "credential_accepted") -> None:
    """The wallet's notification (OpenID4VCI 1.0 §11), as a wallet sends it."""
    proof = wallet.dpop("POST", f"{ISSUER}/notification", access_token=wallet.token)
    headers = {"Authorization": f"DPoP {wallet.token}", "DPoP": proof}
    body = {"notification_id": notification_id, "event": event}
    assert wallet.client.post("/notification", json=body, headers=headers).status_code == 204


# the steps of a pre-authorized offer ---------------------------------------------------------------------------


def test_a_pid_from_qr_code_to_stored(demo: Demo) -> None:
    made = demo.started(credential="pid", persona="ana")
    assert made["persona"] == {"id": "ana", "name": "Ana Maria Silva"}
    assert made["card"] == [
        ["given_name", "Ana Maria"],
        ["family_name", "Silva"],
        ["birthdate", "1994-03-12"],
        ["place_of_birth", "Porto, PT"],
        ["nationalities", "PT"],
    ], "the face of the card is the data the offer holds"
    assert demo.client.get(f"/api/sessions/{made['id']}").json()["card"] == made["card"]
    assert made["qr_svg"].startswith("<svg") and "viewBox" in made["qr_svg"] and "width=" not in made["qr_svg"]
    assert made["offer_link"].startswith("openid-credential-offer://")
    assert made["tx_code"] is None and made["flow"] == "pre-authorized_code"
    assert offer_of(made["offer_link"])["credential_configuration_ids"] == [PID_SD_JWT, PID_MDOC]
    assert demo.step(made["id"]) == "waiting"
    wallet = demo.wallets["pid"]
    scan(wallet, made)
    assert demo.step(made["id"]) == "connected"
    sd_jwt = wallet.issue([EcKey.generate()], config=PID_SD_JWT)
    assert sd_jwt.status_code == 200, sd_jwt.text
    assert demo.step(made["id"]) == "connected", "one format of two"
    mdoc = wallet.issue([EcKey.generate()], config=PID_MDOC)
    assert mdoc.status_code == 200, mdoc.text
    assert demo.step(made["id"]) == "issued"
    notify(wallet, sd_jwt.json()["notification_id"])
    assert demo.step(made["id"]) == "issued", "until the wallet says it stored both"
    notify(wallet, mdoc.json()["notification_id"])
    assert demo.step(made["id"]) == "stored"
    _, payload, _ = disclosures(sd_jwt.json()["credentials"][0]["credential"])
    claims = revealed(sd_jwt.json()["credentials"][0]["credential"])
    assert claims["issuing_authority"] == DEMO_AUTHORITY and claims["given_name"] == "Ana Maria"
    assert claims["date_of_expiry"] == (TODAY + dt.timedelta(days=30)).isoformat()
    assert payload["vct"]


def test_a_course_certificate_in_each_format(demo: Demo) -> None:
    wallet = demo.wallets["course"]
    for fmt, config in (("sd_jwt", COURSE_SD_JWT), ("mdoc", COURSE_MDOC)):
        made = demo.started(credential="course", format=fmt, persona="ines")
        assert offer_of(made["offer_link"])["credential_configuration_ids"] == [config]
        scan(wallet, made)
        issued = wallet.issue([EcKey.generate()], config=config)
        assert issued.status_code == 200, issued.text
        assert demo.step(made["id"]) == "issued"
        wallet.token = None


def test_a_failed_or_deleted_credential_shows(demo: Demo) -> None:
    wallet = demo.wallets["course"]
    made = demo.started(credential="course")
    scan(wallet, made)
    issued = wallet.issue(config=COURSE_SD_JWT)
    notify(wallet, issued.json()["notification_id"], "credential_failure")
    assert demo.step(made["id"]) == "failed"
    notify(wallet, issued.json()["notification_id"], "credential_deleted")
    assert demo.step(made["id"]) == "deleted"


def test_a_pin_is_shown_beside_the_qr_code(demo: Demo) -> None:
    made = demo.started(credential="course", pin=True)
    assert isinstance(made["tx_code"], str) and len(made["tx_code"]) == 4 and made["tx_code"].isdigit()
    grant = offer_of(made["offer_link"])["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    assert grant["tx_code"]["length"] == 4
    scan(demo.wallets["course"], made)
    assert demo.step(made["id"]) == "connected"


def test_an_offer_nobody_scans_expires(demo: Demo) -> None:
    made = demo.started(credential="course")
    demo.wallets["course"].clock.now += demo.course.settings.offer_ttl
    assert demo.step(made["id"]) == "expired"


def test_revoking_from_the_page(demo: Demo) -> None:
    made = demo.started(credential="course")
    refused = demo.act(made["id"], "revoke")
    assert refused.status_code == 200, "an offer not yet scanned is cancelled, which a revocation does too"
    assert refused.json()["step"] == "revoked"
    made = demo.started(credential="course")
    wallet = demo.wallets["course"]
    scan(wallet, made)
    assert wallet.issue(config=COURSE_SD_JWT).status_code == 200
    revoked = demo.act(made["id"], "revoke")
    assert revoked.status_code == 200 and revoked.json()["step"] == "revoked"
    again = demo.act(made["id"], "revoke")
    assert again.status_code == 409 and again.json()["error"] == "nothing_to_revoke"
    assert demo.step(made["id"]) == "revoked"


def test_nothing_held_to_release(demo: Demo) -> None:
    made = demo.started(credential="course")
    for action in ("release", "refuse"):
        response = demo.act(made["id"], action)
        assert response.status_code == 409 and response.json()["error"] == "nothing_held"


# code-flow offers before their login ----------------------------------------------------------------------------


def test_a_code_flow_offer_waits_for_its_login(demo: Demo) -> None:
    made = demo.started(credential="pid", flow="authorization_code")
    offer = offer_of(made["offer_link"])
    assert set(offer["grants"]) == {"authorization_code"}
    session = demo.client.app.state.sessions.get(made["id"])  # type: ignore[attr-defined]
    assert session.subject_ref is None and session.offer_ref and len(session.offer_ref) == 32
    assert demo.step(made["id"]) == "waiting"
    demo.ticker.now += 600
    assert demo.step(made["id"]) == "expired"
    for action in ("revoke", "release"):
        assert demo.act(made["id"], action).status_code == 409


# what the API refuses -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"credential": "passport"},
        {},
        {"credential": "pid", "format": "mdoc"},
        {"credential": "course", "format": "both"},
        {"credential": "course", "flow": "implicit"},
        {"credential": "course", "pin": "yes"},
        {"credential": "course", "pin": True, "flow": "authorization_code"},
        {"credential": "course", "persona": "someone"},
        {"credential": "course", "persona": ["ana"]},
    ],
)
def test_requests_outside_the_menu_are_refused(demo: Demo, body: dict[str, Any]) -> None:
    response = demo.start(**body)
    assert response.status_code == 400 and response.json()["error"] == "invalid_request"
    assert response.headers["cache-control"] == "no-store"
    assert len(demo.client.app.state.sessions) == 0  # type: ignore[attr-defined]


def test_visitor_input_never_reaches_a_credential(demo: Demo) -> None:
    """A field the API does not know is ignored: there is no way to put text of one's own into a credential."""
    made = demo.started(credential="course", persona="joao", family_name="Hacker", subject={"x": 1})
    scan(demo.wallets["course"], made)
    issued = demo.wallets["course"].issue(config=COURSE_SD_JWT)
    claims = revealed(issued.json()["credentials"][0]["credential"])
    assert claims["family_name"] == "Ferreira" and "x" not in claims


def test_only_the_page_may_post(demo: Demo) -> None:
    other = demo.client.post("/api/sessions", json={"credential": "pid"}, headers={"Origin": "https://evil.test"})
    assert other.status_code == 403
    form = demo.client.post(
        "/api/sessions", content=b"credential=pid", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert form.status_code == 415
    text = demo.client.post("/api/sessions", content=b'{"credential":"pid"}', headers={"Content-Type": "text/plain"})
    assert text.status_code == 415
    big = demo.client.post(
        "/api/sessions", content=json.dumps({"x": "a" * 5000}).encode(), headers={"Content-Type": "application/json"}
    )
    assert big.status_code == 413
    broken = demo.client.post("/api/sessions", content=b"{", headers={"Content-Type": "application/json"})
    assert broken.status_code == 400
    array = demo.client.post("/api/sessions", content=b"[]", headers={"Content-Type": "application/json"})
    assert array.status_code == 400
    session = demo.started(credential="course")
    cross = demo.client.post(f"/api/sessions/{session['id']}/revoke", json={}, headers={"Origin": "https://x.test"})
    assert cross.status_code == 403
    assert demo.step(session["id"]) == "waiting"


def test_an_unknown_or_ended_session(demo: Demo) -> None:
    for session_id in ("A" * 22, "short", "../admin", "A" * 22 + "B"):
        response = demo.client.get(f"/api/sessions/{session_id}")
        assert response.status_code == 404, session_id
    made = demo.started(credential="course")
    demo.ticker.now += 1800
    assert demo.client.get(f"/api/sessions/{made['id']}").status_code == 404


def test_new_sessions_are_rate_limited_per_network(make_demo: Callable[..., Demo], demo_settings: DemoSettings) -> None:
    demo = make_demo(replace(demo_settings, sessions_per_minute=3))
    for _ in range(3):
        demo.started(credential="course")
    refused = demo.start(credential="course")
    assert refused.status_code == 429 and refused.headers["retry-after"] == "60"
    demo.ticker.now += 120
    assert demo.start(credential="course").status_code == 201


def test_polling_is_rate_limited(make_demo: Callable[..., Demo], demo_settings: DemoSettings) -> None:
    demo = make_demo(replace(demo_settings, polls_per_minute=5))
    made = demo.started(credential="course")
    codes = [demo.client.get(f"/api/sessions/{made['id']}").status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]


def test_a_full_table_refuses_new_sessions_and_keeps_old_ones(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings
) -> None:
    demo = make_demo(replace(demo_settings, max_sessions=2))
    first = demo.started(credential="course")
    demo.started(credential="course")
    busy = demo.start(credential="course")
    assert busy.status_code == 503 and busy.json()["error"] == "busy"
    assert demo.step(first["id"]) == "waiting", "a demo under way is never dropped"
    demo.ticker.now += 1800
    assert demo.start(credential="course").status_code == 201, "room again once old sessions end"


def test_an_issuer_that_cannot_be_reached(make_demo: Callable[..., Demo]) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(down)
    demo = make_demo(transports={"pid": transport, "course": transport})
    response = demo.start(credential="pid")
    assert response.status_code == 503 and response.json()["error"] == "unavailable"


def test_an_issuer_that_refuses(make_demo: Callable[..., Demo]) -> None:
    def refuses(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_request", "error_description": "no"})

    transport = httpx.MockTransport(refuses)
    demo = make_demo(transports={"pid": transport, "course": transport})
    response = demo.start(credential="course")
    assert response.status_code == 502 and response.json()["error"] == "issuer_refused"
    assert len(demo.client.app.state.sessions) == 0, "the place it took is given back"  # type: ignore[attr-defined]
    assert "no" not in response.json()["message"], "cunho's own words stay in the log"


def test_the_operator_token_goes_to_the_issuer_only(make_demo: Callable[..., Demo]) -> None:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        link = "openid-credential-offer://?credential_offer=%7B%7D"
        return httpx.Response(201, json={"offer_link": link, "subject_ref": "sub_x"})

    transport = httpx.MockTransport(record)
    demo = make_demo(transports={"pid": transport, "course": transport})
    made = demo.started(credential="course")
    assert seen[0].headers["authorization"] == f"Bearer {ADMIN_TOKEN}"
    assert seen[0].url.path == "/admin/offers"
    assert ADMIN_TOKEN not in json.dumps(made)


def test_an_offer_cunho_answers_unreadable_is_refused(make_demo: Callable[..., Demo]) -> None:
    def broken(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"offer_link": "openid-credential-offer://?x", "subject_ref": "sub_x"})

    transport = httpx.MockTransport(broken)
    demo = make_demo(transports={"pid": transport, "course": transport})
    answer = demo.start(credential="pid")
    assert answer.status_code == 502 and len(demo.client.app.state.sessions) == 0  # type: ignore[attr-defined]


def test_security_headers_everywhere(demo: Demo) -> None:
    for response in (demo.client.get("/api/sessions/" + "A" * 22), demo.client.get("/healthz")):
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "same-origin"
        assert response.headers["strict-transport-security"].startswith("max-age=")


# the steps, one by one -------------------------------------------------------------------------------------------


def progress(state: str, *configs: tuple[str, str | None]) -> dict[str, Any]:
    return {
        "state": state,
        "configurations": [{"id": str(i), "state": s, "notification": n} for i, (s, n) in enumerate(configs)],
    }


@pytest.mark.parametrize(
    ("given", "signing_in", "offer_open", "revoked", "expected"),
    [
        (None, False, True, False, "waiting"),
        (None, True, True, False, "signing_in"),
        (None, False, False, False, "expired"),
        (None, True, False, False, "expired"),
        (progress("offered", ("pending", None)), False, True, False, "waiting"),
        (progress("offered", ("pending", None)), True, True, False, "signing_in"),
        (progress("redeemed", ("pending", None)), True, True, False, "connected"),
        (
            {**progress("offered", ("pending", None)), "refusal": {"error": "invalid_dpop_proof", "rule": "X"}},
            False,
            True,
            False,
            "token_rejected",
        ),
        (
            {**progress("redeemed", ("pending", None)), "refusal": {"error": "invalid_proof", "rule": "X"}},
            False,
            True,
            False,
            "rejected",
        ),
        (
            {**progress("issued", ("issued", None)), "refusal": {"error": "invalid_proof", "rule": "X"}},
            False,
            True,
            False,
            "issued",
        ),
        (progress("redeemed", ("held", None)), False, True, False, "held"),
        (progress("redeemed", ("released", None)), False, True, False, "released"),
        (progress("redeemed", ("refused", None)), False, True, False, "refused"),
        (progress("issued", ("issued", None), ("issued", "credential_accepted")), False, True, False, "issued"),
        (progress("issued", ("issued", "credential_accepted")), False, True, False, "stored"),
        (progress("issued", ("issued", "credential_failure")), False, True, False, "failed"),
        (progress("issued", ("issued", "credential_deleted")), False, True, False, "deleted"),
        (progress("closed", ("issued", None)), False, True, True, "revoked"),
        (progress("closed", ("issued", None)), False, True, False, "closed"),
        (progress("expired", ("pending", None)), False, True, False, "expired"),
    ],
)
def test_steps(given: Any, signing_in: bool, offer_open: bool, revoked: bool, expected: str) -> None:
    assert step(given, signing_in, offer_open, revoked) == expected
    if given is None:
        assert step(given, signing_in, offer_open, revoked, cancelled=True) == "cancelled"


# settings ----------------------------------------------------------------------------------------------------------


def test_settings_refuse_what_would_be_unsafe(demo_settings: DemoSettings) -> None:
    for change in (
        {"public_url": "http://demo.example"},
        {"public_url": "http://8.8.8.8:8299"},  # plain http on a public address
        {"public_url": "https://demo.example/path"},
        {"pid": IssuerLink("ftp://x", ADMIN_TOKEN)},
        {"course": IssuerLink("https://x", "short")},
        {"secret_key": b"short"},
        {"session_ttl": 0},
        {"pid_validity_days": 400},
        {"pid_configurations": ()},
    ):
        with pytest.raises(DemoConfigError):
            replace(demo_settings, **change)
    assert replace(demo_settings, public_url="http://localhost:8000").origin == "http://localhost:8000"
    # A phone on the same Wi-Fi as a local run: plain http on a private address only.
    assert replace(demo_settings, public_url="http://192.168.0.200:8299").origin == "http://192.168.0.200:8299"


def test_settings_from_the_environment(tmp_path: Path) -> None:
    token, key = tmp_path / "token", tmp_path / "key"
    token.write_text(ADMIN_TOKEN + "\n")
    key.write_bytes(os.urandom(32))
    for path in (token, key):
        path.chmod(0o600)
    env = {
        "DEMO_PUBLIC_URL": "https://foaap.test",
        "DEMO_PID_ADMIN_URL": "http://cunho-pid:8000/pid",
        "DEMO_PID_ADMIN_TOKEN_FILE": str(token),
        "DEMO_COURSE_ADMIN_URL": "http://cunho-course:8000/course",
        "DEMO_COURSE_ADMIN_TOKEN_FILE": str(token),
        "DEMO_SECRET_KEY_FILE": str(key),
        "DEMO_PID_CONFIGURATIONS": PID_SD_JWT,
        "DEMO_SESSION_TTL": "900",
    }
    settings = DemoSettings.from_env(env)
    assert settings.pid.token == ADMIN_TOKEN and settings.session_ttl == 900
    assert settings.pid_configurations == (PID_SD_JWT,)
    token.chmod(0o640)
    with pytest.raises(DemoConfigError, match="chmod 600"):
        DemoSettings.from_env(env)
    token.chmod(0o600)
    with pytest.raises(DemoConfigError, match="whole number"):
        DemoSettings.from_env({**env, "DEMO_SESSION_TTL": "soon"})
    with pytest.raises(DemoConfigError, match="DEMO_PUBLIC_URL"):
        DemoSettings.from_env({k: v for k, v in env.items() if k != "DEMO_PUBLIC_URL"})


# the session table ---------------------------------------------------------------------------------------------


def test_the_table_bounds_sessions_and_ends_them_in_order() -> None:
    """The second reviewer: places are taken before cunho is asked, and sessions end in the order they began."""
    from cunho_demo.sessions import Session, Sessions

    now = [0.0]
    table = Sessions(ttl=100, max_sessions=2, offer_ttl=10, clock=lambda: now[0])
    first, second, third = (Session("pid", "both", "pre-authorized_code", "ana", []) for _ in range(3))
    assert table.add(first) and first.expires == 100 and first.offer_expires == 10
    now[0] = 50
    assert table.add(second) and second.expires == 150
    assert not table.add(third), "full: the place is refused before any work is sent to cunho"
    table.remove(second.id)
    assert table.add(third)
    now[0] = 100
    assert table.get(first.id) is None and table.get(third.id) is third and len(table) == 1
    table.remove("not-there")


def test_the_qr_code_keeps_its_quiet_zone(demo: Demo) -> None:
    """Four light modules around the symbol (ISO/IEC 18004), which phone cameras need to find it."""
    import re

    import segno

    made = demo.started(credential="pid")
    for svg, text in ((made["qr_svg"], made["wallet_link"]), (made["qr_svg_phone"], made["phone_link"])):
        found = re.search(r'viewBox="0 0 (\d+) (\d+)"', svg)
        assert found is not None
        width, height = map(int, found.groups())
        symbol, _ = segno.make(text, error="m", micro=False).symbol_size(scale=1, border=0)
        assert width == height == symbol + 8


def test_a_second_origin_of_the_same_service(make_demo: Callable[..., Demo], demo_settings: DemoSettings) -> None:
    """The final look: the plain-http view of tools/demo_local.py is the same process on another origin; its forms
    and JSON are taken, any other origin's still not."""
    demo = make_demo(replace(demo_settings, extra_origins=("http://localhost:8099",)))
    view = demo.client.post("/api/sessions", json={"credential": "course"}, headers={"Origin": "http://localhost:8099"})
    assert view.status_code == 201
    other = demo.client.post(
        "/api/sessions", json={"credential": "course"}, headers={"Origin": "http://localhost:8098"}
    )
    assert other.status_code == 403
    assert demo.client.app.state.sessions.get(view.json()["id"]) is not None  # type: ignore[attr-defined]
    for bad in ("http://example.org", "https://x.test/path", "https://"):
        with pytest.raises(DemoConfigError, match="DEMO_EXTRA_ORIGINS"):
            replace(demo_settings, extra_origins=(bad,))


def test_extra_origins_from_the_environment(tmp_path: Path) -> None:
    token, key = tmp_path / "token", tmp_path / "key"
    token.write_text(ADMIN_TOKEN)
    key.write_bytes(os.urandom(32))
    for path in (token, key):
        path.chmod(0o600)
    env = {
        "DEMO_PUBLIC_URL": "https://foaap.test",
        "DEMO_PID_ADMIN_URL": "http://cunho-pid:8000/pid",
        "DEMO_PID_ADMIN_TOKEN_FILE": str(token),
        "DEMO_COURSE_ADMIN_URL": "http://cunho-course:8000/course",
        "DEMO_COURSE_ADMIN_TOKEN_FILE": str(token),
        "DEMO_SECRET_KEY_FILE": str(key),
        "DEMO_EXTRA_ORIGINS": "https://demo.foaap.test, http://localhost:8099",
    }
    settings = DemoSettings.from_env(env)
    assert settings.origins == {"https://foaap.test", "https://demo.foaap.test", "http://localhost:8099"}
