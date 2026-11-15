"""Wallet providers' status lists (piece H): a wallet attestation or a key attestation whose entry is not VALID is
refused at issuance (WIA.CLIENT_STATUS, KA.STATUS_AT_ISSUANCE)."""

from __future__ import annotations

import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.errors import ConfigError
from cunho.jose import JoseError
from cunho.proofs import CrlFile
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import MemoryStore
from cunho.trust import Trust
from cunho.wallet_status import LIFETIME, MAX_LIFETIME, MAX_LIST, MAX_TOKEN, WATERMARK_TTL, StatusError, WalletStatus
from eudi_probe.jose import EcKey, b64u

from .codewallet import WALLET_STATUS_LIST, CodeWallet, Pkce, code_of, pushed
from .helpers import ISSUER, PID_CONFIG, START, Clock, Pki, certificate, production_kwargs, refused_by, settings_kwargs
from .pki import TestPki
from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner, packed

URI = "https://wallet-provider.test/status/w"
NOW = START + 1234  # the test clock's reading


def member(idx: Any = 0, uri: Any = URI) -> dict[str, Any]:
    return {"status": {"status_list": {"uri": uri, "idx": idx}}, "exp": NOW + 86_400}


@pytest.fixture
def signer(pki: Pki) -> StatusSigner:
    return StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)


@pytest.fixture
def served() -> ServedStatus:
    return ServedStatus()


@pytest.fixture
def status(pki: Pki, served: ServedStatus, clock: Clock) -> WalletStatus:
    return WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))


def refused(status: WalletStatus, reason: str, idx: Any = 0, uri: Any = URI) -> None:
    with pytest.raises(StatusError, match=reason):
        status.check(member(idx, uri))


def test_a_valid_entry_passes_and_any_other_value_refuses(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner
) -> None:
    served.lists[URI] = signer.token(URI, {1: 1})
    status.check(member(0))
    status.check(member(2))
    refused(status, "revoked or suspended", 1)


@pytest.mark.parametrize("bits", [2, 4, 8])
def test_entries_of_several_bits_are_read_least_significant_first(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, bits: int
) -> None:
    """Draft-ietf-oauth-status-list §4.1: entry 0 in the lowest bits of byte 0. SUSPENDED (2) and the application
    values refuse like INVALID (1)."""
    values = {3: 1, 4: 2, 5: (1 << bits) - 1}
    served.lists[URI] = signer.token(URI, values, bits=bits)
    for idx in (0, 1, 2, 6):
        status.check(member(idx))
    for idx in values:
        refused(status, "revoked or suspended", idx)


def test_an_index_past_the_end_of_the_list_is_refused(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner
) -> None:
    served.lists[URI] = signer.token(URI, size=64)
    status.check(member(63))
    refused(status, "outside the list", 64)


@pytest.mark.parametrize(
    "reference",
    [
        None,
        {},
        {"status": {}},
        {"status": {"status_list": "x"}},
        {"status": {"status_list": {"uri": 7, "idx": 0}}},
        {"status": {"status_list": {"uri": URI}}},
        {"status": {"status_list": {"uri": URI, "idx": "0"}}},
        {"status": {"status_list": {"uri": URI, "idx": True}}},
        {"status": {"status_list": {"uri": URI, "idx": -1}}},
        {"status": {"status_list": {"uri": URI, "idx": 1.0}}},
    ],
)
def test_an_attestation_without_an_entry_to_check_is_refused(status: WalletStatus, reference: Any) -> None:
    with pytest.raises(
        StatusError, match="names no status list or identifier list entry|status list entry is malformed"
    ):
        status.check(reference)


def test_a_list_that_cannot_be_fetched_refuses(status: WalletStatus) -> None:
    refused(status, "cannot be fetched")


def _forged(pki: Pki) -> StatusSigner:
    key = ec.generate_private_key(ec.SECP256R1())
    other = certificate("Other Wallet Provider", key, ca=True)
    return StatusSigner.under(other, key)


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda s, p: "not a jws", "not a compact JWS"),
        (lambda s, p: s.token(URI) + "\xff", "not a compact JWS"),
        (lambda s, p: s.token(URI, header={"typ": "JWT"}), "wrong typ"),
        (lambda s, p: s.token(URI, header={"typ": ...}), "wrong typ"),
        (lambda s, p: s.token(URI, header={"alg": "HS256"}), "algorithm cunho does not accept"),
        (lambda s, p: s.token(URI, header={"alg": []}), "algorithm cunho does not accept"),
        (lambda s, p: s.token(URI, header={"alg": {}}), "algorithm cunho does not accept"),
        (lambda s, p: s.token(URI, header={"x5c": ...}), "not signed by a trusted signer"),
        (lambda s, p: _forged(p).token(URI), "not signed by a trusted signer"),
        (lambda s, p: s.token(URI)[:-4] + ("AAAA" if not s.token(URI).endswith("AAAA") else "BBBB"), "does not verify"),
        (lambda s, p: s.token("https://wallet-provider.test/status/other"), "not the one the attestation names"),
        (lambda s, p: s.token(URI, sub=...), "not the one the attestation names"),
        (lambda s, p: s.token(URI, iat=NOW + 61), "iat that is not in the future"),
        (lambda s, p: s.token(URI, iat=...), "iat that is not in the future"),
        (lambda s, p: s.token(URI, iat=float(START)), "iat that is not in the future"),
        (lambda s, p: s.token(URI, iat=True), "iat that is not in the future"),
        (lambda s, p: s.token(URI, exp=...), "no exp or has expired"),
        (lambda s, p: s.token(URI, exp=NOW), "no exp or has expired"),
        (lambda s, p: s.token(URI, exp="later"), "no exp or has expired"),
        (lambda s, p: s.token(URI, ttl=0), "ttl is not a positive whole number"),
        (lambda s, p: s.token(URI, ttl=-5), "ttl is not a positive whole number"),
        (lambda s, p: s.token(URI, ttl=True), "ttl is not a positive whole number"),
        (lambda s, p: s.token(URI, ttl=1.5), "ttl is not a positive whole number"),
        (lambda s, p: s.token(URI, bits=3), "bits of 1, 2, 4 or 8"),
        (lambda s, p: s.token(URI, status_list={"bits": True, "lst": packed({})}), "bits of 1, 2, 4 or 8"),
        (lambda s, p: s.token(URI, status_list={"bits": 1}), "bits of 1, 2, 4 or 8"),
        (lambda s, p: s.token(URI, status_list="all valid"), "bits of 1, 2, 4 or 8"),
        (lambda s, p: s.token(URI, status_list={"bits": 1, "lst": "a+b/"}), "lst cannot be read"),
        (lambda s, p: s.token(URI, status_list={"bits": 1, "lst": b64u(b"not zlib")}), "lst cannot be read"),
        (
            lambda s, p: s.token(URI, status_list={"bits": 1, "lst": b64u(zlib.compress(bytes(64))[:-6])}),
            "cut short or has data after it",
        ),
        (
            lambda s, p: s.token(URI, status_list={"bits": 1, "lst": b64u(zlib.compress(bytes(64)) + b"x")}),
            "cut short or has data after it",
        ),
    ],
)
def test_a_list_cunho_cannot_trust_or_read_refuses(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, pki: Pki, build: Any, reason: str
) -> None:
    served.lists[URI] = build(signer, pki)
    refused(status, reason)


def test_the_boundaries_of_the_list_dates_are_kept(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    """iat up to a minute ahead, exp at least a second ahead, ttl from one second: all accepted."""
    served.lists[URI] = signer.token(URI, iat=NOW + 60, exp=NOW + 1, ttl=1)
    status.check(member())


def test_a_list_that_inflates_past_the_cap_is_refused_and_one_at_the_cap_is_not(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner
) -> None:
    """A zlib stream of a few kilobytes that inflates to more than MAX_LIST bytes is refused before it is all
    inflated; one that inflates to exactly MAX_LIST is read."""
    at_cap = b64u(zlib.compress(bytes(MAX_LIST), 9))
    served.lists[URI] = signer.token(URI, status_list={"bits": 1, "lst": at_cap})
    status.check(member(MAX_LIST * 8 - 1))
    bomb = b64u(zlib.compress(bytes(MAX_LIST + 1), 9))
    assert len(bomb) < MAX_TOKEN // 20
    served.lists["https://wallet-provider.test/status/bomb"] = signer.token(
        "https://wallet-provider.test/status/bomb", status_list={"bits": 1, "lst": bomb}
    )
    refused(status, "larger than allowed once inflated", uri="https://wallet-provider.test/status/bomb")


def test_a_list_is_kept_until_its_ttl_its_exp_or_an_hour_whichever_comes_first(
    pki: Pki, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    def fetches(token: str, until: int) -> None:
        served.asked.clear()
        served.lists[URI] = token
        status = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))
        clock.now = NOW
        status.check(member())
        clock.now = until - 1
        status.check(member())
        assert served.asked == [URI], "kept"
        served.lists[URI] = signer.token(URI, iat=until, exp=until + 86_400)
        clock.now = until
        status.check(member())
        assert served.asked == [URI] * 2, "fetched again"

    fetches(signer.token(URI, ttl=600, exp=NOW + 86_400), NOW + 600)
    fetches(signer.token(URI, ttl=86_400, exp=NOW + 300), NOW + 300)
    fetches(signer.token(URI, exp=NOW + 86_400), NOW + LIFETIME)


def test_a_list_older_than_one_already_seen_is_refused(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    """A list replayed over the network cannot bring back an attestation revoked meanwhile."""
    served.lists[URI] = signer.token(URI, {0: 1}, iat=START + 100, ttl=60)
    refused(status, "revoked or suspended")
    clock.now += 60
    served.lists[URI] = signer.token(URI, iat=START, ttl=60)
    refused(status, "older than one already seen")
    served.lists[URI] = signer.token(URI, {0: 1}, iat=START + 100, ttl=60)
    refused(status, "revoked or suspended")
    served.lists[URI] = signer.token(URI, iat=START + 200, ttl=60)
    clock.now += 60
    status.check(member())


def test_lists_at_two_uris_are_kept_apart(status: WalletStatus, served: ServedStatus, signer: StatusSigner) -> None:
    other = "https://wallet-provider.test/status/x"
    served.lists[URI] = signer.token(URI, {0: 1})
    served.lists[other] = signer.token(other)
    refused(status, "revoked or suspended")
    status.check(member(0, other))


def test_a_list_signer_the_operator_file_revokes_is_refused(
    pki: Pki, served: ServedStatus, signer: StatusSigner, clock: Clock, tmp_path: Path
) -> None:
    import datetime as dt

    leaf = x509.load_der_x509_certificate(__import__("base64").b64decode(signer.x5c[0]))
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    revoked = x509.RevokedCertificateBuilder().serial_number(leaf.serial_number).revocation_date(now).build()
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.wallet_ca.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=30))
        .add_revoked_certificate(revoked)
        .sign(pki.wallet_ca_key, hashes.SHA256())
    )
    file = tmp_path / "wp.crl"
    file.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    served.lists[URI] = signer.token(URI)
    checked = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca], crls=CrlFile(file)), clock, MemoryStore(clock))
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        checked.check(member())


def test_a_status_error_is_a_jose_error() -> None:
    """The callers handle it where they handle the attestation's other failures."""
    assert issubclass(StatusError, JoseError)


# Wired in: the wallet attestation at PAR, token and refresh; the key attestation at the credential request.


@pytest.fixture
def wia_lists(trust_pki: TestPki) -> StatusSigner:
    wp = trust_pki.wallet_provider
    return StatusSigner.under(wp.intermediate.cert, wp.intermediate.key, wp.intermediate.cert)


@pytest.fixture
def watched(
    make_code_issuer: Callable[..., Issuer],
    code_files: dict[str, Path],
    wia_lists: StatusSigner,
    pki: Pki,
    served: ServedStatus,
) -> Issuer:
    """A code-flow issuer that checks both attestations' status, and both lists VALID."""
    served.lists[WALLET_STATUS_LIST] = wia_lists.token(WALLET_STATUS_LIST)
    served.lists[KA_STATUS_LIST] = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key).token(KA_STATUS_LIST)
    return make_code_issuer(wallet_status_anchors=code_files["anchors"], fetcher=served)


@pytest.mark.covers("WIA.CLIENT_STATUS")
def test_a_wallet_attestation_its_provider_revoked_is_refused_at_par(
    watched: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], served: ServedStatus, wia_lists: StatusSigner
) -> None:
    wallet = code_wallet_for(watched)
    served.lists[WALLET_STATUS_LIST] = wia_lists.token(WALLET_STATUS_LIST, {3: 1})
    response = refused_by(lambda: wallet.par(Pkce.random()), "WIA.CLIENT_STATUS", "revoked or suspended")
    assert response.status_code == 401 and response.json()["error"] == "invalid_client"


def test_a_wallet_attestation_revoked_after_par_is_refused_at_the_token_endpoint_and_at_refresh(
    watched: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    served: ServedStatus,
    wia_lists: StatusSigner,
    clock: Clock,
) -> None:
    """Lists that live a second, so each step reads a fresh one while the code and the tokens still live."""

    def serve(entries: dict[int, int], iat: int) -> None:
        served.lists[WALLET_STATUS_LIST] = wia_lists.token(WALLET_STATUS_LIST, entries, iat=iat, ttl=1)
        clock.now += 2

    serve({}, START + 1000)
    wallet = code_wallet_for(watched)
    pkce = Pkce.random()
    code = code_of(wallet, watched, pkce)
    serve({3: 1}, START + 1100)
    refused_by(lambda: wallet.code_token_request(code, pkce), "WIA.CLIENT_STATUS", "revoked or suspended")

    serve({}, START + 1200)
    other = code_wallet_for(watched)
    pkce = Pkce.random()
    other.refresh_token = other.code_token_request(code_of(other, watched, pkce), pkce).json()["refresh_token"]
    serve({3: 1}, START + 1300)
    refused_by(other.refresh_request, "WIA.CLIENT_STATUS", "revoked or suspended")


WIA_IDENTIFIERS = "https://wallet-provider.test/identifiers/wia"


def identifier_status(ident: bytes, clock: Clock) -> dict[str, Any]:
    return {
        "status": {"identifier_list": {"id": b64u(ident), "uri": WIA_IDENTIFIERS}},
        "exp": int(clock()) + 60 * 86_400,
    }


@pytest.mark.covers("WIA.CLIENT_STATUS")
def test_a_wallet_attestation_on_an_identifier_list_is_read_like_one_on_a_status_list(
    watched: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    served: ServedStatus,
    wia_lists: StatusSigner,
    clock: Clock,
) -> None:
    """A wallet provider may revoke wallet attestations by identifier list (CIR 2024/2979 Annex II EAA-6.2.10.1-14):
    cunho takes the attestation while its identifier is not listed and refuses it once it is (-16)."""
    served.lists[WIA_IDENTIFIERS] = wia_lists.identifiers(WIA_IDENTIFIERS, [b"another wallet"])
    wallet = code_wallet_for(watched)
    pkce = Pkce.random()
    attestation = wallet.attestation(client_status=identifier_status(b"this wallet", clock))
    pushed(wallet, watched, pkce, attest=False, headers=wallet.attestation_headers(attestation))
    revoked = wallet.attestation(client_status=identifier_status(b"another wallet", clock))
    response = refused_by(
        lambda: wallet.par(Pkce.random(), attest=False, headers=wallet.attestation_headers(revoked)),
        "WIA.CLIENT_STATUS",
        "revoked on its wallet provider's identifier list",
    )
    assert response.status_code == 401


@pytest.mark.obligation("WIA.CLIENT_STATUS", "KA.STATUS_AT_ISSUANCE")
def test_a_valid_wallet_and_key_attestation_get_their_credential(
    watched: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], served: ServedStatus
) -> None:
    wallet = code_wallet_for(watched)
    pkce = Pkce.random()
    wallet.token = wallet.code_token_request(code_of(wallet, watched, pkce), pkce).json()["access_token"]
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text
    assert set(served.asked) == {WALLET_STATUS_LIST, KA_STATUS_LIST}


@pytest.mark.covers("KA.STATUS_AT_ISSUANCE")
def test_a_key_attestation_its_provider_revoked_is_refused_at_the_credential_request(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Any], pki: Pki, served: ServedStatus
) -> None:
    lists = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    served.lists[KA_STATUS_LIST] = lists.token(KA_STATUS_LIST, {7: 1})
    issuer = make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=served)
    wallet = wallet_for(issuer)
    response = refused_by(wallet.issue, "KA.STATUS_AT_ISSUANCE", "revoked or suspended")
    assert response.json()["error"] == "invalid_proof"
    served.lists[KA_STATUS_LIST] = lists.token(KA_STATUS_LIST)
    assert (
        wallet_for(make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=served))
        .issue()
        .status_code
        == 200
    )


def test_a_key_attestation_without_a_status_entry_is_refused_when_status_is_checked(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Any], pki: Pki, served: ServedStatus
) -> None:
    issuer = make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=served)
    wallet = wallet_for(issuer)
    wallet.get_token()
    holder = EcKey.generate()
    nonce = wallet.c_nonce()
    attestation = wallet.key_attestation([holder], key_storage_status={"exp": NOW + 86_400})
    proof = wallet.proof(holder, nonce, key_attestation=attestation)
    body = {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}}
    refused_by(
        lambda: wallet.credential_request(body),
        "KA.STATUS_AT_ISSUANCE",
        "names no status list or identifier list entry",
    )


def test_without_status_anchors_nothing_is_fetched(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Any], served: ServedStatus
) -> None:
    assert wallet_for(make_issuer(fetcher=served)).issue().status_code == 200
    assert served.asked == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"lote_path": None, "lote_signer": None}, "production needs lote_path and lote_signer"),
        ({"fetch_hosts": None}, "production needs fetch_hosts"),
        ({"fetch_hosts": ()}, "production needs fetch_hosts"),
    ],
)
def test_production_checks_wallet_status_and_fetches_only_from_named_hosts(
    pki: Pki, tmp_path: Path, change: dict[str, Any], message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        Settings(**production_kwargs(pki, tmp_path, **change))


@pytest.mark.parametrize("hosts", [("",), ("https://wallet-provider.test/",), (7,)])
def test_fetch_hosts_must_be_host_names(pki: Pki, hosts: Any) -> None:
    with pytest.raises(ConfigError, match="fetch_hosts must be host names"):
        Settings(**settings_kwargs(pki, fetch_hosts=hosts))


def test_a_list_is_inflated_no_further_than_the_cap(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The cap bounds what the inflater may produce, so a bomb is stopped while it unfolds, not measured after."""
    import cunho.wallet_status as module

    asked: list[int] = []
    real = zlib.decompressobj

    class Watched:
        def __init__(self) -> None:
            self._inner = real()

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            asked.append(max_length)
            return self._inner.decompress(data, max_length)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    monkeypatch.setattr(module.zlib, "decompressobj", Watched)
    served.lists[URI] = signer.token(URI)
    status.check(member())
    assert asked == [MAX_LIST + 1]


def test_status_lists_go_by_the_clock_watchs_time(
    make_code_issuer: Callable[..., Issuer],
    code_files: dict[str, Path],
    clock: Clock,
    trust_pki: TestPki,
    pki: Pki,
    served: ServedStatus,
    wia_lists: StatusSigner,
) -> None:
    """A wall clock stepped two days ahead moves nothing the watch decides by: a list good for one more day is still
    good (DESIGN.md, time)."""
    from .helpers import Host

    host = Host(clock)
    issuer = host.issuer(make_code_issuer, None, wallet_status_anchors=code_files["anchors"], fetcher=served)
    issuer.sweep()  # the first background tick lays the base
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = CodeWallet(client, pki, host.true, provider=trust_pki.wallet_provider)
        host.advance(60)
        served.lists[WALLET_STATUS_LIST] = wia_lists.token(
            WALLET_STATUS_LIST, iat=int(host.true()), exp=int(host.true()) + 86_400
        )
        clock.now += 2 * 86_400
        issuer.client_auth.authenticate([wallet.attestation()], [wallet.attestation_pop()])
        assert served.asked == [WALLET_STATUS_LIST]


def _crl(pki: Pki, revoked: list[x509.Certificate], until: Any) -> bytes:
    import datetime as dt

    now = dt.datetime.fromtimestamp(START, dt.UTC)
    builder = x509.CertificateRevocationListBuilder().issuer_name(pki.wallet_ca.subject).last_update(now)
    builder = builder.next_update(until)
    for cert in revoked:
        entry = x509.RevokedCertificateBuilder().serial_number(cert.serial_number).revocation_date(now).build()
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(pki.wallet_ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def test_a_list_in_hand_is_dropped_once_its_signer_is_revoked_or_runs_out(
    pki: Pki, served: ServedStatus, clock: Clock, tmp_path: Path
) -> None:
    """The signer's path is judged again at every use of a list in hand: a CRL that now revokes the signer, the
    signer's certificate running out, or the covering CRL running out each end the list (the second reviewer)."""
    import base64
    import datetime as dt

    at = dt.datetime.fromtimestamp(NOW, dt.UTC)
    file = tmp_path / "wp.crl"

    def fresh(**signer: Any) -> tuple[WalletStatus, x509.Certificate]:
        made = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key, **signer)
        served.lists[URI] = made.token(URI)
        served.asked.clear()
        clock.now = NOW
        checked = WalletStatus(
            served, Trust.fixed(status=[pki.wallet_ca], crls=CrlFile(file)), clock, MemoryStore(clock)
        )
        checked.check(member())
        return checked, x509.load_der_x509_certificate(base64.b64decode(made.x5c[0]))

    file.write_bytes(_crl(pki, [], at + dt.timedelta(days=30)))
    checked, leaf = fresh()
    file.write_bytes(_crl(pki, [leaf], at + dt.timedelta(days=30)))
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        checked.check(member())

    file.write_bytes(_crl(pki, [], at + dt.timedelta(days=30)))
    checked, _ = fresh(not_after=at + dt.timedelta(minutes=10))
    clock.now = NOW + 11 * 60
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        checked.check(member())

    file.write_bytes(_crl(pki, [], at + dt.timedelta(minutes=10)))
    checked, _ = fresh()
    clock.now = NOW + 11 * 60
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        checked.check(member())
    assert served.asked == [URI], "refused from the list in hand, not fetched again"


def test_the_newest_list_seen_outlives_the_cache_and_a_restart(
    pki: Pki, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    """A list dropped from the bounded cache, or a worker started again, still refuses an older list replayed at its
    URI: the newest iat seen is kept in the store (the second reviewer)."""
    store = MemoryStore(clock)
    other = "https://wallet-provider.test/status/x"
    status = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, store, entries=1)
    served.lists[URI] = signer.token(URI, {0: 1}, iat=START + 200, ttl=60)
    refused(status, "revoked or suspended")
    served.lists[other] = signer.token(other)
    status.check(member(0, other))  # pushes the first list out of the one-entry cache
    clock.now += 60
    served.lists[URI] = signer.token(URI, iat=START + 100, ttl=60)
    refused(status, "older than one already seen")
    restarted = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, store)
    refused(restarted, "older than one already seen")
    served.lists[URI] = signer.token(URI, iat=START + 300, ttl=60)
    restarted.check(member())


class SlowServed(ServedStatus):
    """Served after the clock has moved on by `delay`, as after a wait for the lock and a slow fetch."""

    clock: Clock | None = None
    delay: float = 0.0

    def get(self, url: str, *, types: Any, max_bytes: int, budget: float) -> bytes:
        assert self.clock is not None
        self.clock.now += self.delay
        return super().get(url, types=types, max_bytes=max_bytes, budget=budget)


def test_a_list_is_judged_by_the_time_after_the_fetch(pki: Pki, signer: StatusSigner, clock: Clock) -> None:
    """A list that runs out while it is being fetched is refused (the second reviewer)."""
    served = SlowServed()
    served.clock, served.delay = clock, 1.5
    served.lists[URI] = signer.token(URI, exp=NOW + 1)
    status = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))
    refused(status, "no exp or has expired")
    served.lists[URI] = signer.token(URI, exp=int(clock.now) + 5, iat=START + 1)
    status.check(member())


def test_a_newer_list_another_worker_saw_ends_this_workers_list_in_hand(
    pki: Pki, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    """Two workers on one store: once one sees a newer list that revokes the entry, the other's list in hand no longer
    stands in for a fetch (the second reviewer)."""
    store = MemoryStore(clock)
    first = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, store)
    second = WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, store)
    served.lists[URI] = signer.token(URI, iat=START + 100)
    first.check(member())
    served.lists[URI] = signer.token(URI, {0: 1}, iat=START + 200)
    refused(second, "revoked or suspended")
    refused(first, "revoked or suspended")
    assert served.asked == [URI] * 3


def test_a_list_may_live_thirty_days_and_no_longer(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner
) -> None:
    """So every list older than the newest seen has expired before the mark of the newest is let go."""
    served.lists[URI] = signer.token(URI, iat=START, exp=START + MAX_LIFETIME)
    status.check(member())
    other = "https://wallet-provider.test/status/x"
    served.lists[other] = signer.token(other, iat=START, exp=START + MAX_LIFETIME + 1)
    refused(status, "lives longer than cunho accepts", uri=other)
    assert WATERMARK_TTL > MAX_LIFETIME + 60
