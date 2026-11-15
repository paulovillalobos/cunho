"""The demo wallet, the offer by reference and the phone page's API: a visitor with no wallet watches the whole
issuance, looks inside what was issued, and sees a revocation as a verifier would."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import cbor2
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from cunho_demo.settings import DemoSettings
from cunho_demo.wallet import (
    Activity,
    DemoWallet,
    Key,
    KeyAttester,
    Route,
    WalletError,
    inspect,
    jws,
    read_status,
)
from tests.engine.helpers import Pki

from .conftest import ORIGIN, Demo, offer_of


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.fixture
def ka_files(tmp_path: Path, pki: Pki) -> tuple[Path, Path]:
    """The test wallet provider's key-attestation signer, as the demo is given it."""
    chain, key = tmp_path / "ka-signer.pem", tmp_path / "ka-signer.key"
    chain.write_bytes(pki.ka_leaf.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(
        pki.ka_key.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    key.chmod(0o600)
    return chain, key


@pytest.fixture
def wallet_demo(
    make_demo: Callable[..., Demo], demo_settings: DemoSettings, ka_files: tuple[Path, Path], clock: Any
) -> Demo:
    settings = DemoSettings(**{**demo_settings.__dict__, "wallet_ka_chain": ka_files[0], "wallet_ka_key": ka_files[1]})
    demo = make_demo(settings)
    wallet = demo.client.app.state.wallet  # type: ignore[attr-defined]
    wallet.clock = clock  # the engine's clock, as cunho reads proofs by it
    return demo


def run_wallet(demo: Demo, session_id: str, path: str | None = None, body: dict[str, Any] | None = None) -> Any:
    answer = demo.client.post(
        path or f"/api/sessions/{session_id}/demo-wallet", json=body or {}, headers={"Origin": ORIGIN}
    )
    assert answer.status_code == 202, answer.text
    return answer.json()


def until(demo: Demo, session_id: str, states: set[str], seconds: float = 20) -> dict[str, Any]:
    """The session's view once its demo wallet is in one of these states."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        view: dict[str, Any] = demo.client.get(f"/api/sessions/{session_id}").json()
        if view["wallet"] and view["wallet"]["state"] in states:
            return view
        time.sleep(0.05)
    raise AssertionError(f"the demo wallet did not reach {states}: {view['wallet']}")


def test_the_demo_wallet_takes_a_pid_from_offer_to_stored(wallet_demo: Demo) -> None:
    made = wallet_demo.started(credential="pid", persona="ana")
    assert made["demo_wallet"] is True
    run_wallet(wallet_demo, made["id"])
    view = until(wallet_demo, made["id"], {"done", "failed"})
    assert view["wallet"]["state"] == "done", view["wallet"]
    assert view["step"] == "stored", "cunho saw the wallet store both formats"
    assert view["wallet"]["steps"][:2] == ["wallet_metadata", "wallet_token"]
    assert view["wallet"]["steps"][-1] == "wallet_stored"
    sd_jwt, mdoc = view["wallet"]["credentials"]
    assert sd_jwt["format"] == "dc+sd-jwt" and mdoc["format"] == "mso_mdoc"
    for credential in (sd_jwt, mdoc):
        assert credential["signature"] is True and credential["digests"] is True, credential
        assert credential["holder_bound"] is True and credential["status"] is not None
        assert credential["signer"], "the certificate it was signed with is named"
    assert dict(sd_jwt["claims"])["given_name"] == "Ana Maria"
    assert dict(sd_jwt["claims"])["place_of_birth"] == "Porto, PT", "the country last, as people write a place"
    assert dict(mdoc["claims"])["family_name"] == "Silva"
    assert "_sd" not in dict(sd_jwt["claims"]) and "cnf" not in dict(sd_jwt["claims"])


def test_the_demo_wallet_answers_the_issuers_dpop_nonce(
    make_demo: Callable[..., Demo],
    make_issuer: Callable[..., Any],
    demo_settings: DemoSettings,
    ka_files: tuple[Path, Path],
    clock: Any,
) -> None:
    """The second reviewer: an issuer with CUNHO_DPOP_SERVER_NONCE challenges the first proof at every endpoint;
    the wallet takes the nonce it is given and goes on."""
    settings = DemoSettings(**{**demo_settings.__dict__, "wallet_ka_chain": ka_files[0], "wallet_ka_key": ka_files[1]})
    demo = make_demo(settings, issuer=lambda **kw: make_issuer(**{**kw, "dpop_server_nonce": True}))
    demo.client.app.state.wallet.clock = clock  # type: ignore[attr-defined]
    made = demo.started(credential="pid")
    run_wallet(demo, made["id"])
    view = until(demo, made["id"], {"done", "failed"})
    assert view["wallet"]["state"] == "done", view["wallet"]
    assert view["step"] == "stored"


def test_the_demo_wallet_types_the_pin_and_cannot_take_an_offer_twice(wallet_demo: Demo) -> None:
    made = wallet_demo.started(credential="course", format="mdoc", pin=True, persona="joao")
    run_wallet(wallet_demo, made["id"])
    view = until(wallet_demo, made["id"], {"done", "failed"})
    assert view["wallet"]["state"] == "done" and "wallet_pin" in view["wallet"]["steps"]
    assert view["wallet"]["credentials"][0]["type"] == "app.foaap.course_certificate.1"
    again = wallet_demo.client.post(f"/api/sessions/{made['id']}/demo-wallet", json={}, headers={"Origin": ORIGIN})
    assert again.status_code == 409 and again.json()["error"] == "wallet_started"


def test_a_revocation_shows_on_the_status_list_as_a_verifier_reads_it(wallet_demo: Demo, clock: Any) -> None:
    made = wallet_demo.started(credential="pid")
    run_wallet(wallet_demo, made["id"])
    until(wallet_demo, made["id"], {"done"})
    checked = wallet_demo.client.post(f"/api/sessions/{made['id']}/status", json={}, headers={"Origin": ORIGIN})
    assert checked.status_code == 200, checked.text
    assert [c["status_value"] for c in checked.json()["wallet"]["credentials"]] == ["valid", "valid"]
    assert wallet_demo.act(made["id"], "revoke").status_code == 200
    clock.now += 7 * 86_400  # past any revocation jitter: the next publication carries it
    wallet_demo.pid.clock_watch.trust(wallet_demo.pid.clock())
    wallet_demo.pid.status.publish()
    checked = wallet_demo.client.post(f"/api/sessions/{made['id']}/status", json={}, headers={"Origin": ORIGIN})
    assert [c["status_value"] for c in checked.json()["wallet"]["credentials"]] == ["invalid", "invalid"]
    assert checked.json()["wallet"]["checked_at"]


def test_a_run_that_redeemed_the_offer_is_not_started_again(wallet_demo: Demo) -> None:
    """The second reviewer: a run that failed after the token (at the notification, say) spent the offer's code
    and keeps what it was issued; starting it again would lose that and fail."""
    made = wallet_demo.started(credential="pid")
    session = wallet_demo.client.app.state.sessions.get(made["id"])  # type: ignore[attr-defined]
    held = {"format": "dc+sd-jwt", "claims": [], "raw": "x"}
    session.wallet = Activity(state="failed", steps=["wallet_metadata", "wallet_token"], credentials=[held])
    assert wallet_demo.client.get(f"/api/sessions/{made['id']}").json()["wallet"]["retry"] is False
    again = wallet_demo.client.post(f"/api/sessions/{made['id']}/demo-wallet", json={}, headers={"Origin": ORIGIN})
    assert again.status_code == 409 and session.wallet.credentials == [held]


def test_the_demo_wallet_only_takes_what_it_can(wallet_demo: Demo, demo: Demo) -> None:
    code = wallet_demo.started(credential="pid", flow="authorization_code")
    assert code["demo_wallet"] is False
    refused = wallet_demo.client.post(f"/api/sessions/{code['id']}/demo-wallet", json={}, headers={"Origin": ORIGIN})
    assert refused.status_code == 409 and refused.json()["error"] == "wallet_flow"
    plain = demo.started(credential="pid")
    assert plain["demo_wallet"] is False, "no demo wallet without a key-attestation signer"
    refused = demo.client.post(f"/api/sessions/{plain['id']}/demo-wallet", json={}, headers={"Origin": ORIGIN})
    assert refused.status_code == 404
    other = wallet_demo.client.post(
        f"/api/sessions/{code['id']}/demo-wallet", json={}, headers={"Origin": "https://evil.test"}
    )
    assert other.status_code == 403
    nothing = wallet_demo.client.post(f"/api/sessions/{code['id']}/status", json={}, headers={"Origin": ORIGIN})
    assert nothing.status_code == 409


# the offer by reference and the phone page ------------------------------------------------------------------


def test_the_offer_by_reference_is_the_offer_a_wallet_would_read_by_value(wallet_demo: Demo) -> None:
    made = wallet_demo.started(credential="pid", pin=True)
    query = parse_qs(urlsplit(made["wallet_link"]).query)
    assert made["wallet_link"].startswith("openid-credential-offer://?credential_offer_uri=")
    uri = unquote(query["credential_offer_uri"][0])
    assert uri.startswith(f"{ORIGIN}/offers/") and made["phone_link"] == f"{ORIGIN}/o/{uri.rsplit('/', 1)[1]}"
    answer = wallet_demo.client.get(urlsplit(uri).path)
    assert answer.status_code == 200 and answer.headers["cache-control"] == "no-store"
    assert answer.json() == offer_of(made["offer_link"])
    assert len(made["wallet_link"]) < len(made["offer_link"]) / 2, "a QR code a phone reads easily"
    assert wallet_demo.client.get("/offers/" + "x" * 24).status_code == 404
    wallet_demo.ticker.now += 601  # past the offer's lifetime
    assert wallet_demo.client.get(urlsplit(uri).path).status_code == 404


def test_the_phone_page_never_gives_the_pin_or_the_session(wallet_demo: Demo) -> None:
    made = wallet_demo.started(credential="pid", pin=True, persona="ines")
    token = made["phone_path"].rsplit("/", 1)[1]
    page = wallet_demo.client.get(made["phone_path"])
    assert (
        page.status_code == 200
        and "<title>" in page.text
        and "script-src 'self'" in page.headers["content-security-policy"]
    )
    view = wallet_demo.client.get(f"/api/offers/{token}").json()
    assert "id" not in view and made["tx_code"] not in json.dumps(view)
    assert view["pin"] is True and view["persona"]["id"] == "ines" and view["wallet_link"] == made["wallet_link"]
    no_pin = wallet_demo.client.post(f"/api/offers/{token}/demo-wallet", json={}, headers={"Origin": ORIGIN})
    assert no_pin.status_code == 400, "the phone's visitor types the PIN"
    wrong = "0000" if made["tx_code"] != "0000" else "1111"
    run_wallet(wallet_demo, made["id"], f"/api/offers/{token}/demo-wallet", {"pin": wrong})
    view = until(wallet_demo, made["id"], {"done", "failed"})
    assert view["wallet"]["state"] == "failed" and view["wallet"]["error"] == "wallet_token"
    run_wallet(wallet_demo, made["id"], f"/api/offers/{token}/demo-wallet", {"pin": made["tx_code"]})
    view = until(wallet_demo, made["id"], {"done", "failed"})
    assert view["wallet"]["state"] == "done", "a failed run can be tried again"
    phone = wallet_demo.client.post(f"/api/offers/{token}/status", json={}, headers={"Origin": ORIGIN})
    assert phone.status_code == 200 and phone.json()["wallet"]["credentials"][0]["status_value"] == "valid"
    revoke = wallet_demo.client.post(f"/api/offers/{token}/revoke", json={}, headers={"Origin": ORIGIN})
    assert revoke.status_code in (404, 405), "the QR code cannot revoke"


# what the wallet checks in a credential -------------------------------------------------------------------------


@pytest.fixture
def issued(wallet_demo: Demo) -> list[dict[str, Any]]:
    made = wallet_demo.started(credential="pid")
    run_wallet(wallet_demo, made["id"])
    until(wallet_demo, made["id"], {"done"})
    session = wallet_demo.client.app.state.sessions.get(made["id"])  # type: ignore[attr-defined]
    credentials: list[dict[str, Any]] = session.wallet.credentials
    return credentials


def test_a_changed_signature_or_claim_is_seen(issued: list[dict[str, Any]]) -> None:
    sd_jwt = issued[0]["raw"]
    head, body, signature = sd_jwt.split("~")[0].split(".")
    flipped = signature[:-2] + ("AA" if signature[-2:] != "AA" else "BB")
    stranger = Key.generate().jwk()
    assert inspect("dc+sd-jwt", sd_jwt.replace(signature, flipped, 1), stranger)["signature"] is False
    extra = b64u(json.dumps(["salt", "given_name", "Mallory"]).encode())
    assert inspect("dc+sd-jwt", sd_jwt + extra + "~", stranger)["digests"] is False, "a disclosure nobody signed"
    # The same credentials read for a wallet whose key they are not bound to (the second reviewer).
    assert inspect("dc+sd-jwt", sd_jwt, stranger)["holder_bound"] is False
    assert inspect("mso_mdoc", issued[1]["raw"], stranger)["holder_bound"] is False
    mdoc = cbor2.loads(base64.urlsafe_b64decode(issued[1]["raw"] + "=" * (-len(issued[1]["raw"]) % 4)))
    namespace = next(iter(mdoc["nameSpaces"]))
    item = cbor2.loads(mdoc["nameSpaces"][namespace][0].value)
    item["elementValue"] = "Mallory"
    mdoc["nameSpaces"][namespace][0] = cbor2.CBORTag(24, cbor2.dumps(item))
    assert inspect("mso_mdoc", b64u(cbor2.dumps(mdoc)), stranger)["digests"] is False


def test_a_status_list_that_does_not_check_out_reads_unknown(tmp_path: Path) -> None:
    """A well-formed list reads valid or revoked; the same list signed by another key, or naming another list,
    or past its expiry, reads unknown."""
    key = Key.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "status signer")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key.private, hashes.SHA256())
    )
    x5c = [base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode()]
    uri = "https://issuer.test/status/1"
    bits = b64u(zlib.compress(bytes([0b00000010])))  # index 0 valid, index 1 revoked
    payload = {"sub": uri, "exp": 2_000, "status_list": {"bits": 1, "lst": bits}}
    header = {"typ": "statuslist+jwt", "alg": "ES256", "x5c": x5c}
    good = jws(header, payload, key)
    assert read_status(good, uri, 0, 1_000) == "valid" and read_status(good, uri, 1, 1_000) == "invalid"
    assert read_status(jws(header, payload, Key.generate()), uri, 1, 1_000) == "unknown", "signed by another key"
    assert read_status(good, "https://issuer.test/status/2", 1, 1_000) == "unknown", "another list's token"
    assert read_status(good, uri, 1, 3_000) == "unknown", "past its expiry"
    assert read_status("not.a.token", uri, 0, 0) == "unknown"


def scripted(*answers: httpx.Response) -> tuple[httpx.MockTransport, list[str]]:
    """An issuer that answers each request with the next answer, and the paths it was asked."""
    asked: list[str] = []
    queue = list(answers)

    def answer(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        return queue.pop(0)

    return httpx.MockTransport(answer), asked


def test_an_issuer_that_refuses_the_credential_ends_the_run(ka_files: tuple[Path, Path]) -> None:
    public = "https://issuer.test/pid"
    config = "eu.europa.ec.eudi.pid_vc_sd_jwt"
    metadata = {
        "credential_issuer": public,
        "nonce_endpoint": f"{public}/nonce",
        "credential_endpoint": f"{public}/credential",
        "notification_endpoint": f"{public}/notification",
        "credential_configurations_supported": {config: {"format": "dc+sd-jwt"}},
    }
    transport, asked = scripted(
        httpx.Response(200, json=metadata),
        httpx.Response(200, json={"token_endpoint": f"{public}/token"}),
        httpx.Response(200, json={"access_token": "t", "token_type": "DPoP"}),
        httpx.Response(200, json={"c_nonce": "n"}),
        httpx.Response(400, json={"error": "credential_request_denied"}),
    )
    wallet = DemoWallet(KeyAttester.from_files(*ka_files), {"pid": Route("http://cunho-pid:8000/pid", transport)})
    grant = {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "x"}}
    offer = {"credential_issuer": public, "grants": grant, "credential_configuration_ids": [config]}
    activity = Activity()
    asyncio.run(wallet.run("pid", offer, None, activity))
    assert activity.state == "failed" and activity.error == "wallet_refused"
    assert asked[-1] == "/pid/credential" and "/pid/notification" not in asked


def test_the_wallet_never_follows_a_url_off_the_issuer(ka_files: tuple[Path, Path]) -> None:
    """Every request goes to the issuer's internal address; a URL on any other origin is refused unsent."""
    seen: list[str] = []
    public = "https://issuer.test/pid"
    metadata = {
        "credential_issuer": public,
        "authorization_servers": ["https://evil.test/pid"],
        "credential_configurations_supported": {},
    }

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=metadata)

    route = Route("http://cunho-pid:8000/pid", httpx.MockTransport(answer))
    wallet = DemoWallet(KeyAttester.from_files(*ka_files), {"pid": route})
    assert wallet._internal("pid", public, f"{public}/token") == "http://cunho-pid:8000/pid/token"
    for elsewhere in ("https://evil.test/pid/token", "http://issuer.test/pid/token", "https://issuer.test:444/pid"):
        with pytest.raises(WalletError):
            wallet._internal("pid", public, elsewhere)
    grant = {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "x"}}
    activity = Activity()
    asyncio.run(wallet.run("pid", {"credential_issuer": public, "grants": grant}, None, activity))
    assert activity.state == "failed" and activity.error == "wallet_unreachable"
    assert seen == ["http://cunho-pid:8000/.well-known/openid-credential-issuer/pid"], "evil.test was never asked"
