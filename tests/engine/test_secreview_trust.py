"""What the security review found in trust and in what cunho fetches (research/cunho-security-review.md): fetches
anyone could cause, a failure every waiting request repeated, lists that revocation chaining never read or that
ended its run, and two lists of what is refused that had to be lists of what is accepted. Each test failed on the
code as reviewed and holds its fix."""

from __future__ import annotations

import base64
import datetime as dt
import http.server
import logging
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from cunho.errors import IssuerError
from cunho.fetch import RETRY_AFTER, WAITS, Busy, Fetcher, FetchError, is_public
from cunho.jose import MAX_CHAIN, JoseError, load_der_chain, validate_path
from cunho.revocation import FetchedRevocation
from cunho.service import Issuer
from cunho.store import MemoryStore
from cunho.trust import Trust
from cunho.wallet_status import StatusError, WalletStatus
from eudi_probe.jose import EcKey, b64u, jws

from . import test_client_auth as client_tests
from .codewallet import WALLET_STATUS_LIST, CodeWallet, Pkce, pid_scope
from .helpers import PID_CONFIG, PRE_AUTH, START, Clock, Pki, Wallet, certificate, der_b64
from .pki import TestPki
from .statuslists import ServedStatus, StatusSigner
from .test_chaining import (  # noqa: F401 - the chaining tests' fixtures and steps
    DAY,
    WIA_IDENTIFIERS,
    WIA_IDX,
    Lists,
    bit,
    chain_rows,
    chained,
    issue,
    ka_lists,
    lists,
    make_chained,
    run,
    served,
    wia_lists,
)
from .test_fetch import local
from .test_revocation import (  # noqa: F401 - with their fixtures
    Answer,
    Chain,
    accept,
    chain,
    judge,
    port,
    refuse,
    source,
)

# --- the signature before the path, and a failed fetch shared by those who waited for it ------------------------------


CRL_URL = "http://crl.wallet-provider.test/attestation-signers.crl"
STATUS_URL = "https://wallet-provider.test/status/1"
WAITING = 6  # requests sent while the endpoint does not answer


class Unanswered(Fetcher):
    """Every request ends as one to a server that does not answer: held, then refused. Nothing is sent."""

    def __init__(self, hold: threading.Event | None = None) -> None:
        super().__init__(None)
        self.asked: list[str] = []
        self.hold = hold
        self.lock = threading.Lock()

    def _refuse(self, url: str) -> bytes:
        with self.lock:
            self.asked.append(url)
        if self.hold is not None:
            self.hold.wait(20)
        raise FetchError("the server did not answer within the time budget")

    def _exchange(self, method: str, where: Any, *rest: Any) -> bytes:
        """In place of the exchange with the server: what the fetcher does around it stays as it is."""
        return self._refuse(f"{where.scheme}://{where.host}{where.path}")


def listed_issuer(make_issuer: Callable[..., Issuer], pki: Pki, fetcher: Fetcher) -> Issuer:
    """An issuer that takes its anchors from the list of wallet providers, as production does, so revocation comes
    from distribution points and OCSP."""
    issuer = make_issuer(
        lote_path=pki.root / "wallet-providers.lote",
        lote_signer=pki.root / "lote-signer.pem",
        wallet_provider_anchors=None,
        fetcher=fetcher,
    )
    assert isinstance(issuer.trust.revocation(), FetchedRevocation)
    return issuer


def public_chain(pki: Pki) -> str:
    """A genuine attestation signer certificate of the trusted wallet provider, as anyone reads it from the x5c of
    an attestation: it names where its CRL is. Its private key is thrown away: the stranger never has it."""
    point = x509.DistributionPoint([x509.UniformResourceIdentifier(CRL_URL)], None, None, None)
    signer = certificate(
        "Wallet Attestation Signer",
        EcKey.generate().private,
        (pki.wallet_ca, pki.wallet_ca_key),
        extensions=[(x509.CRLDistributionPoints([point]), False)],
    )
    return der_b64(signer)


def strangers_request(x5c: str) -> tuple[dict[str, list[str]], Callable[[str], list[str]]]:
    """A token request from a client that holds nothing: a made-up pre-authorized code, and a wallet attestation
    that names the provider's public chain but is signed with the stranger's own key."""
    own = EcKey.generate()
    attestation = jws({"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": [x5c]}, {"sub": "x"}, own)
    pop = jws({"typ": "oauth-client-attestation-pop+jwt", "alg": "ES256"}, {}, own)
    headers = {"oauth-client-attestation": [attestation], "oauth-client-attestation-pop": [pop]}
    form = {"grant_type": [PRE_AUTH], "pre-authorized_code": ["no-such-code"]}
    return form, lambda name: headers.get(name, [])


def test_a_wallet_attestation_signed_by_a_stranger_makes_cunho_fetch_nothing(
    make_issuer: Callable[..., Issuer], pki: Pki
) -> None:
    """Nothing the request carries is the wallet provider's own: the signature is the stranger's. It is refused
    for that, before cunho goes out to the provider's distribution point for the chain."""
    fetcher = Unanswered()
    issuer = listed_issuer(make_issuer, pki, fetcher)
    form, headers = strangers_request(public_chain(pki))
    with pytest.raises(IssuerError) as refused:
        issuer.token(form, [], headers)
    assert refused.value.status == 401 and refused.value.error == "invalid_client"
    assert fetcher.asked == [], (
        f"a request signed by nobody cunho knows made it fetch {fetcher.asked}: the path, revocation included, "
        "is checked before the attestation's signature"
    )


def test_requests_behind_a_fetch_that_fails_share_its_failure(make_issuer: Callable[..., Issuer], pki: Pki) -> None:
    """Six such requests while the distribution point does not answer. Whichever of them fetches is held until the
    others wait behind it, then fails, as a fetch cut off at its budget does. None of the others makes the same
    fetch again: on the code as reviewed each did, one after another, so the last was held for six budgets."""
    release = threading.Event()
    fetcher = Unanswered(release)
    issuer = listed_issuer(make_issuer, pki, fetcher)
    public = public_chain(pki)
    refusals: list[int] = []

    def ask() -> None:
        form, headers = strangers_request(public)
        try:
            issuer.token(form, [], headers)
        except IssuerError as exc:
            refusals.append(exc.status)

    threads = [threading.Thread(target=ask, daemon=True) for _ in range(WAITING)]
    for thread in threads:
        thread.start()
    revocation = issuer.trust.revocation()
    assert isinstance(revocation, FetchedRevocation)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        queued = [entry[1] for entry in list(revocation._crls._locks.values())]  # noqa: SLF001 - who waits
        if queued == [WAITING] or len(refusals) == WAITING:  # all wait on the one fetch, or none ever fetched
            break
        time.sleep(0.01)
    assert len(fetcher.asked) <= 1, "one fetch at a time"
    release.set()  # the fetch fails; from here no fetch is held any more
    for thread in threads:
        thread.join(20)
    assert refusals == [401] * WAITING, "every request is refused"
    assert len(fetcher.asked) <= 1, (
        f"{len(fetcher.asked)} fetches of one list for {WAITING} requests that waited on the same failure: each "
        "request behind a failed fetch makes it again, so the last one is held for that many time budgets"
    )


def test_checks_queued_behind_a_fetch_that_times_out_make_no_fetch_of_their_own(pki: Pki) -> None:
    """The same with the real fetcher and real time, against a socket on 127.0.0.1 that takes connections and
    never answers. The budget is 0.3 s here (2 s in a deployment). Five path checks at once: one connection is
    made, and the four checks behind it share its failure. On the code as reviewed each made its own, one after
    another, so the last check was held for five budgets."""
    import socket

    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(64)
    checks = 5
    try:
        url = f"http://crl.wallet-provider.test:{silent.getsockname()[1]}/attestation-signers.crl"
        point = x509.DistributionPoint([x509.UniformResourceIdentifier(url)], None, None, None)
        signer = certificate(
            "Wallet Attestation Signer",
            EcKey.generate().private,
            (pki.wallet_ca, pki.wallet_ca_key),
            extensions=[(x509.CRLDistributionPoints([point]), False)],
        )
        revocation = FetchedRevocation(Fetcher(None, resolve=local, loopback_for_tests=True), budget=0.3)
        now = dt.datetime.fromtimestamp(START + 1234, dt.UTC)
        refused: list[str] = []

        def check() -> None:
            with pytest.raises(JoseError, match="no current revocation list") as refusal:
                validate_path([signer], [pki.wallet_ca], now, revocation=revocation)
            refused.append(str(refusal.value))

        threads = [threading.Thread(target=check, daemon=True) for _ in range(checks)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        silent.setblocking(False)
        connections = 0
        while True:
            try:
                silent.accept()[0].close()
            except BlockingIOError:
                break
            connections += 1
    finally:
        silent.close()
    assert len(refused) == checks, "every check is refused"
    assert connections == 1, f"{connections} connections to a server that does not answer, for {checks} checks at once"


def test_one_client_with_a_public_chain_holds_no_thread_of_the_issuer(
    make_issuer: Callable[..., Issuer], pki: Pki
) -> None:
    """Over HTTP. One client posts eighty token requests like the one above: twice the forty worker threads that
    every route of the application shares (starlette's thread pool). None of them has cunho fetch, so none holds a
    thread for a fetch's time budget, and a wallet's request for a nonce is answered among them. On the code as
    reviewed each waited its turn at a distribution point that does not answer: the nonce request got a thread only
    after forty of them, each for a whole budget, and without end while the client kept sending more than one
    request per budget (the default rate limit lets one address send 120 a minute)."""
    from urllib.parse import urlencode

    from fastapi.testclient import TestClient

    from cunho.app import create_app

    from .helpers import ISSUER

    sent_by_client = 80
    fetcher = Unanswered()
    issuer = listed_issuer(make_issuer, pki, fetcher)
    public = public_chain(pki)
    done: list[int] = []
    app = create_app(issuer=issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as http:

        def flood() -> None:
            form, headers = strangers_request(public)
            sent = [("Content-Type", "application/x-www-form-urlencoded")]
            sent += [(name, headers(name)[0]) for name in ("oauth-client-attestation", "oauth-client-attestation-pop")]
            done.append(
                http.post("/token", content=urlencode({k: v[0] for k, v in form.items()}), headers=sent).status_code
            )

        threads = [threading.Thread(target=flood, daemon=True) for _ in range(sent_by_client)]
        for thread in threads:
            thread.start()
        answered = http.post("/nonce")
        for thread in threads:
            thread.join(60)
    assert answered.status_code == 200 and done == [401] * sent_by_client
    assert fetcher.asked == [], "a request signed by nobody cunho knows had it fetch, and held a thread for it"


def test_checks_behind_a_status_list_that_cannot_be_fetched_share_its_failure(pki: Pki, clock: Clock) -> None:
    """The same queue in front of a wallet provider's status list (wallet_status.py), which every credential
    request with a key attestation of that provider waits on: one fetch for all who waited."""
    release = threading.Event()
    fetcher = Unanswered(release)
    status = WalletStatus(fetcher, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))
    member = {"status": {"status_list": {"idx": 3, "uri": STATUS_URL}}}
    unknown: list[str] = []

    def check() -> None:
        try:
            status.check(member)
        except StatusError as exc:
            unknown.append(str(exc))

    threads = [threading.Thread(target=check, daemon=True) for _ in range(WAITING)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        queued = [entry[1] for entry in list(status._lists._locks.values())]  # noqa: SLF001 - who waits
        if queued == [WAITING]:
            break
        time.sleep(0.01)
    assert queued == [WAITING]
    release.set()
    for thread in threads:
        thread.join(20)
    assert len(unknown) == WAITING
    assert len(fetcher.asked) == 1, (
        f"{len(fetcher.asked)} fetches of one status list for {WAITING} checks that waited on the same failure"
    )


# --- a stranger and a wallet provider's fetch budget ------------------------------------------------------------------


class ProviderHost(http.server.BaseHTTPRequestHandler):
    """One host of a wallet provider: its OCSP responder and its status list."""

    answer: Callable[[bytes], bytes] | None = None
    status_list = ""
    asked: list[str] = []

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, body: bytes, kind: str) -> None:
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        self.asked.append("ocsp")
        request = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        answer: Any = type(self).answer
        self._send(answer(request) if answer else b"", "application/ocsp-response")

    def do_GET(self) -> None:
        self.asked.append(self.path)
        self._send(self.status_list.encode() if self.path == "/status/1" else b"", "application/statuslist+jwt")


@pytest.fixture
def host() -> Iterator[str]:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProviderHost)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    ProviderHost.asked = []
    yield f"http://pki.wallet-provider.test:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def test_a_stranger_cannot_use_up_a_providers_fetch_budget(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock, host: str
) -> None:
    # A wallet attestation signer the provider revoked. Its certificate names the provider's OCSP responder.
    aia = x509.AuthorityInformationAccess(
        [x509.AccessDescription(x509.OID_OCSP, x509.UniformResourceIdentifier(f"{host}/ocsp"))]
    )
    revoked = certificate(
        "Revoked Attestation Signer",
        EcKey.generate().private,
        (pki.wallet_ca, pki.wallet_ca_key),
        extensions=[(aia, False)],
    )
    now = dt.datetime.fromtimestamp(clock(), dt.UTC)

    def answer(data: bytes) -> bytes:
        """The provider's responder: the certificate is revoked. Signed by the CA itself."""
        nonce = ocsp.load_der_ocsp_request(data).extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        return (
            ocsp.OCSPResponseBuilder()
            .add_response(
                revoked,
                pki.wallet_ca,
                hashes.SHA256(),
                ocsp.OCSPCertStatus.REVOKED,
                now - dt.timedelta(minutes=5),
                now + dt.timedelta(days=1),
                now - dt.timedelta(days=1),
                x509.ReasonFlags.key_compromise,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, pki.wallet_ca)
            .add_extension(x509.OCSPNonce(nonce), critical=False)
            .sign(pki.wallet_ca_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

    ProviderHost.answer = staticmethod(answer)
    uri = f"{host}/status/1"
    stamp = int(clock())
    ProviderHost.status_list = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key).token(
        uri, {}, iat=stamp, exp=stamp + 2 * DAY
    )

    # The issuer, as production has it: anchors from the list, revocation fetched. One minute on its fetcher's clock.
    fetcher = Fetcher(None, resolve=local, loopback_for_tests=True, monotonic=lambda: 1000.0)
    issuer = make_issuer(
        lote_path=pki.root / "wallet-providers.lote",
        lote_signer=pki.root / "lote-signer.pem",
        wallet_provider_anchors=None,
        wallet_provider_crls=pki.root / "wallet-providers.crl",
        fetcher=fetcher,
    )
    assert isinstance(issuer.trust.revocation(), FetchedRevocation)

    # The stranger: sixty token requests with the revoked signer's public chain, signed with a key of its own.
    own = EcKey.generate()
    headers = {
        "oauth-client-attestation": [
            jws({"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": [der_b64(revoked)]}, {"sub": "x"}, own)
        ],
        "oauth-client-attestation-pop": [jws({"typ": "oauth-client-attestation-pop+jwt", "alg": "ES256"}, {}, own)],
    }
    form = {"grant_type": [PRE_AUTH], "pre-authorized_code": ["no-such-code"]}
    for _ in range(60):
        with pytest.raises(IssuerError) as refused:
            issuer.token(form, [], lambda name: headers.get(name, []))
        assert refused.value.status == 401
    asked_for_the_stranger = len(ProviderHost.asked)

    # In the same minute, a wallet of that provider in good standing asks for its PID. Its key attestation names an
    # entry of the provider's status list, which is there to read and says the entry is valid.
    wallet = wallet_for(issuer)
    wallet.get_token()
    holder = EcKey.generate()
    status = {"status": {"status_list": {"idx": 1, "uri": uri}}, "exp": stamp + 30 * DAY}
    attestation = wallet.key_attestation([holder], key_storage_status=status)
    proof = wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert response.status_code == 200, (
        f"the wallet was refused ({response.json().get('error_description')}): cunho had asked the provider's host "
        f"{asked_for_the_stranger} times for requests signed by nobody it knows, and refused itself the fetch of "
        "the status list"
    )


# --- a status list that does not answer, asked for by many requests ---------------------------------------------------


class Silent(Fetcher):
    """A wallet provider's host that does not answer: every fetch ends when its time budget does."""

    def __init__(self) -> None:
        super().__init__(None)
        self.asked: list[str] = []

    def _exchange(self, method: str, where: Any, *rest: Any) -> bytes:
        """In place of the exchange with the server: what the fetcher does around it stays as it is."""
        self.asked.append(f"{where.scheme}://{where.host}{where.path}")
        raise FetchError("the server did not answer within the time budget")


def test_a_status_list_that_does_not_answer_is_not_fetched_for_every_request(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Any], pki: Pki
) -> None:
    silent = Silent()
    issuer = make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=silent)
    wallet = wallet_for(issuer)
    wallet.get_token()
    requests = 6
    for _ in range(requests):
        refused = wallet.issue()
        assert refused.status_code == 400 and refused.json()["error"] == "invalid_proof", refused.text
    assert len(silent.asked) <= 2, (
        f"{requests} requests in the same second made {len(silent.asked)} fetches of a list that does not answer; in "
        "production each one holds a worker thread for up to two seconds, queued behind the one before it"
    )


# --- an identifier list whose certificate cannot be read --------------------------------------------------------------


URI = "https://wallet-provider.test/identifiers/1"


def unsigned_reply(any_certificate: str) -> bytes:
    """What the URL answers: the shape of an identifier list, with no signature worth the name, whose x5chain holds
    a certificate that says it is X.509 version 8. Made from any certificate at hand; no key is used."""
    der = base64.b64decode(any_certificate)
    at = der.index(b"\xa0\x03\x02\x01\x02")  # [0] EXPLICIT INTEGER 2: version 3
    version_8 = der[: at + 4] + b"\x07" + der[at + 5 :]
    protected = cbor2.dumps({1: -7, 16: "application/identifierlist+cwt", 33: version_8})
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, b"", b""]))


def test_an_identifier_list_with_a_certificate_of_no_version_is_a_status_error(pki: Pki, clock: Clock) -> None:
    signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    fetcher = ServedStatus({URI: unsigned_reply(signer.x5c[0])})
    status = WalletStatus(fetcher, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))
    member = {"status": {"identifier_list": {"id": b64u(b"my wallet"), "uri": URI}}}
    raised: BaseException | None = None
    try:
        status.check(member)
    except StatusError as exc:
        raised = exc
    except Exception as exc:  # noqa: BLE001 - shown below
        raised = exc
    assert isinstance(raised, StatusError), f"the check raised {raised!r}, which no caller takes for a refusal"


def test_a_wallet_whose_identifier_list_answers_so_is_refused_not_answered_500(
    chained: Issuer,  # noqa: F811
    code_wallet_for: Callable[[Issuer], CodeWallet],
    served: ServedStatus,  # noqa: F811
    wia_lists: StatusSigner,  # noqa: F811
    lists: Lists,  # noqa: F811
) -> None:
    """At the pushed authorization request, with a genuine wallet attestation that names the list."""
    served.lists[WIA_IDENTIFIERS] = unsigned_reply(wia_lists.x5c[0])
    wallet = code_wallet_for(chained)
    status = {
        "status": {"identifier_list": {"id": b64u(b"this wallet"), "uri": WIA_IDENTIFIERS}},
        "exp": START + 60 * DAY,
    }
    headers = wallet.attestation_headers(wallet.attestation(client_status=status))
    response = wallet.par(Pkce.random(), scope=pid_scope(chained), attest=False, headers=headers)
    assert (response.status_code, response.json()["error"]) == (401, "invalid_client"), response.text


def test_one_such_reply_does_not_stop_chaining_for_the_other_lists(
    chained: Issuer,  # noqa: F811
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,  # noqa: F811
    served: ServedStatus,  # noqa: F811
    wia_lists: StatusSigner,  # noqa: F811
    clock: Clock,
) -> None:
    """Two PIDs. The first wallet's attestation names an identifier list; the second's names entry 11 of the
    provider's status list, which now says that wallet is revoked. The identifier list URL answers with the
    unsigned reply. The second PID must be revoked whatever happens to the first one's list."""
    assert WIA_IDX != 11
    ident = b"first wallet"
    status = {"status": {"identifier_list": {"id": b64u(ident), "uri": WIA_IDENTIFIERS}}, "exp": START + 60 * DAY}
    served.lists[WIA_IDENTIFIERS] = wia_lists.identifiers(WIA_IDENTIFIERS, [], iat=int(clock()), ttl=1)
    issue(chained, code_wallet_for, client_status=status)
    [(first, _)] = chain_rows(chained)
    entry = {"status": {"status_list": {"idx": 11, "uri": WALLET_STATUS_LIST}}, "exp": START + 60 * DAY}
    issue(chained, code_wallet_for, client_status=entry)
    [second] = [key for key, _ in chain_rows(chained) if key != first]

    lists.serve(wia={11: 1})  # the second wallet is revoked by its provider
    served.lists[WIA_IDENTIFIERS] = unsigned_reply(wia_lists.x5c[0])
    outcome: Any
    try:
        outcome = run(chained, clock)
    except Exception as exc:  # noqa: BLE001 - shown below
        outcome = exc
    assert bit(chained, second) == 1, (
        f"the PID of the revoked wallet is still valid: the run ended with {outcome!r} before it looked at any "
        "credential"
    )
    assert outcome == {"chain_checked": 0, "chain_revoked": 1, "chain_unchecked": 1}


# --- more lists on one host than a minute allows ----------------------------------------------------------------------


LISTS = 61  # one more than a host is asked for in a minute


class ListHandler(http.server.BaseHTTPRequestHandler):
    lists: dict[str, str] = {}
    asked: list[str] = []

    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        self.asked.append(self.path)
        body = self.lists.get(self.path, "").encode()
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "application/statuslist+jwt")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def list_host() -> Iterator[str]:
    """A wallet provider's list host, on 127.0.0.1."""
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ListHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    ListHandler.lists, ListHandler.asked = {}, []
    yield f"http://lists.wallet-provider.test:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


class Deployment:
    """An issuer in front of that host through the real fetcher, with the fetcher's own clock in hand: the tests
    move it on between issuances, so that issuing never comes near the limit and only the run itself is measured."""

    def __init__(
        self,
        make_issuer: Callable[..., Issuer],
        wallet_for: Callable[[Issuer], Wallet],
        pki: Pki,
        clock: Clock,
        host: str,
        **settings: Any,
    ) -> None:
        self.elapsed = [1000.0]
        self.waits: list[float] = []  # each wait of the fetcher for a place in the host's minute, in seconds

        def wait(seconds: float) -> None:
            self.waits.append(seconds)
            self.elapsed[0] += seconds

        fetcher = Fetcher(None, resolve=local, loopback_for_tests=True, monotonic=lambda: self.elapsed[0], sleep=wait)
        self.issuer = make_issuer(wallet_status_anchors=pki.root / "wallet-providers.pem", fetcher=fetcher, **settings)
        self.wallet = wallet_for(self.issuer)
        self.signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
        self.clock, self.host = clock, host

    def uri(self, number: int) -> str:
        return f"{self.host}/status/{number}"

    def serve(self) -> None:
        """Every list, valid, saying every wallet is valid, as the wallet provider publishes them now."""
        now = int(self.clock())
        for number in range(LISTS):
            ListHandler.lists[f"/status/{number}"] = self.signer.token(self.uri(number), {}, iat=now, exp=now + 2 * DAY)

    def issue(self) -> None:
        """One PID per list: each wallet's key attestation names an entry of a list of its own."""
        for number in range(LISTS):
            self.elapsed[0] += 61  # a minute and more between issuances
            holder = EcKey.generate()
            self.wallet.get_token()
            status = {
                "status": {"status_list": {"idx": 1, "uri": self.uri(number)}},
                "exp": int(self.clock()) + 30 * DAY,
            }
            attestation = self.wallet.key_attestation([holder], key_storage_status=status)
            proof = self.wallet.proof(holder, self.wallet.c_nonce(), key_attestation=attestation)
            response = self.wallet.credential_request(
                {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}}
            )
            assert response.status_code == 200, response.text

    def run(self) -> dict[str, int]:
        """One run of the job, more than a minute after the last issuance."""
        self.elapsed[0] += 3600
        ListHandler.asked.clear()
        self.issuer.clock_watch.trust(self.issuer.clock())
        self.issuer.status.publish()
        return self.issuer.chain(force=True)


def test_a_run_reads_every_list_a_host_serves(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock, list_host: str
) -> None:
    deployment = Deployment(make_issuer, wallet_for, pki, clock, list_host)
    deployment.serve()
    deployment.issue()
    assert len(deployment.issuer.store.items("chain", "", at=0)) == LISTS
    done = deployment.run()
    assert done == {"chain_checked": LISTS, "chain_revoked": 0, "chain_unchecked": 0}, (
        f"{done}: the host was asked for {len(ListHandler.asked)} of its {LISTS} lists, all of them there to read; "
        "the fetcher's own limit refused the rest"
    )
    assert len(ListHandler.asked) == LISTS
    assert deployment.waits and all(0 < seconds <= 60 for seconds in deployment.waits), (
        "the run waited for the host's minute, a minute at most each time, instead of taking the limit for an outage"
    )


def test_no_pid_is_revoked_as_unchecked_while_its_list_is_there_to_read(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock, list_host: str
) -> None:
    """With `chain_revoke_after_days`, a day and an hour after issuance: every list is served, fresh and valid."""
    deployment = Deployment(make_issuer, wallet_for, pki, clock, list_host, chain_revoke_after_days=1)
    deployment.serve()
    deployment.issue()
    clock.now += DAY + 3600
    deployment.serve()
    done = deployment.run()
    reasons = [
        entry["data"]["reason"] for entry in deployment.issuer.audit.entries() if entry["event"] == "credential.revoked"
    ]
    assert done["chain_revoked"] == 0 and reasons == [], (
        f"{done}, revoked for {reasons}: a PID was revoked because its wallet's list 'could not be read', and the "
        f"host was never asked for it ({len(ListHandler.asked)} of {LISTS} lists fetched)"
    )


# --- hashes and addresses: lists of what is accepted ------------------------------------------------------------------


NOW = dt.datetime.fromtimestamp(START, dt.UTC)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: tuple[str, ec.EllipticCurvePrivateKey] | None = None,
    digest: Any = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer[0] if issuer else subject))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True)
    )
    return builder.sign(issuer[1] if issuer else key, digest or hashes.SHA256())


@pytest.mark.parametrize("digest", [hashes.SHA224(), hashes.SHA3_224()], ids=["sha224", "sha3-224"])
def test_a_certificate_signed_with_a_224_bit_hash_is_refused(digest: hashes.HashAlgorithm) -> None:
    """SHA-224 was refused by name; SHA3-224, the same length, was not on the list of what is refused."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _certificate("Wallet Provider CA", ca_key)
    signer_key = ec.generate_private_key(ec.SECP256R1())
    signer = _certificate("Attestation Signer", signer_key, ("Wallet Provider CA", ca_key), digest)
    with pytest.raises(JoseError, match="hash outside the agreed mechanisms"):
        validate_path([signer], [ca], NOW)


@pytest.mark.parametrize("digest", [hashes.SHA224(), hashes.SHA3_224()], ids=["sha224", "sha3-224"])
def test_a_crl_signed_with_a_224_bit_hash_does_not_show_a_certificate_is_not_revoked(digest: Any) -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _certificate("Wallet Provider CA", ca_key)
    signer = _certificate("Attestation Signer", ec.generate_private_key(ec.SECP256R1()), ("Wallet Provider CA", ca_key))
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(NOW - dt.timedelta(days=1))
        .next_update(NOW + dt.timedelta(days=5))
        .sign(ca_key, digest)
    )
    with pytest.raises(JoseError):
        validate_path([signer], [ca], NOW, crls=[crl])


@pytest.mark.parametrize("digest", [hashes.SHA224(), hashes.SHA3_224()], ids=["sha224", "sha3-224"])
def test_a_fetched_crl_signed_with_a_224_bit_hash_says_nothing_of_a_certificate(
    chain: Chain,  # noqa: F811
    digest: Any,
) -> None:
    """The same for a list fetched from where the certificate says: such a list was read whatever its hash."""
    now = chain.build.now
    weak = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(chain.mid.cert.subject)
        .last_update(now - dt.timedelta(days=1))
        .next_update(now + dt.timedelta(days=30))
        .add_extension(x509.CRLNumber(1), critical=False)
        .sign(chain.mid.key, digest)
    )
    chain.served.files["/mid.crl"] = weak.public_bytes(serialization.Encoding.DER)
    refuse(chain, chain.by_crl, source(), "no current revocation list")


def test_a_crl_signed_with_a_224_bit_hash_is_not_remembered_as_the_newest_seen(
    chain: Chain,  # noqa: F811
) -> None:
    """Nor does such a list count against the good ones: a list nobody may go by must not make the issuer's real
    list, with a lower number, look like a replay of an older one."""
    revocation = source()
    now = chain.build.now
    weak = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(chain.mid.cert.subject)
        .last_update(now - dt.timedelta(days=1))
        .next_update(now + dt.timedelta(days=30))
        .add_extension(x509.CRLNumber(5), critical=False)
        .sign(chain.mid.key, hashes.SHA224())
    )
    chain.served.files["/mid.crl"] = weak.public_bytes(serialization.Encoding.DER)
    refuse(chain, chain.by_crl, revocation, "no current revocation list")
    chain.served.files["/mid.crl"] = chain.build.crl(chain.mid, number=4).public_bytes(serialization.Encoding.DER)
    accept(chain, chain.by_crl, revocation)


def test_an_ocsp_response_signed_with_sha3_224_is_refused_as_one_signed_with_sha_224(trust_pki: TestPki) -> None:
    with pytest.raises(JoseError, match="signature does not verify"):
        judge(trust_pki, Answer(digest=hashes.SHA3_224()))


@pytest.mark.parametrize(
    "address",
    [
        "fec0::1",  # site-local (RFC 3879 deprecated it; hosts still route it)
        "::127.0.0.1",  # IPv4-compatible: loopback
        "::10.0.0.1",  # IPv4-compatible: private
        "::169.254.169.254",  # IPv4-compatible: cloud metadata
        "::ffff:0:10.0.0.1",  # IPv4-translated (RFC 2765): private
    ],
)
def test_an_address_inside_the_deployment_is_not_public(address: str) -> None:
    assert not is_public(address)


# --- the signature before the path, wherever checking the path may fetch ----------------------------------------------


def provider_signer(pki: Pki) -> StatusSigner:
    """A status list signer of the wallet provider whose certificate names where its CRL is."""
    key = EcKey.generate()
    point = x509.DistributionPoint([x509.UniformResourceIdentifier(CRL_URL)], None, None, None)
    signer = certificate(
        "Wallet Provider Status Signer",
        key.private,
        (pki.wallet_ca, pki.wallet_ca_key),
        extensions=[(x509.CRLDistributionPoints([point]), False)],
    )
    return StatusSigner(key, [der_b64(signer)])


def fetching_status(pki: Pki, clock: Clock, source: Fetcher, revocation: Fetcher) -> WalletStatus:
    """Wallet status as production has it: a list signer's revocation comes from where its certificate says."""
    trust = Trust(lambda: [], lambda: [pki.wallet_ca], FetchedRevocation(revocation))
    return WalletStatus(source, trust, clock, MemoryStore(clock))


def test_a_key_attestation_signed_by_a_stranger_makes_cunho_fetch_nothing(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """At the credential endpoint, which anyone who holds an offer reaches: a key attestation that names the
    provider's public chain and is signed with another key is refused before anything is fetched for it."""
    fetcher = Unanswered()
    issuer = listed_issuer(make_issuer, pki, fetcher)
    wallet = wallet_for(issuer)
    wallet.get_token()
    holder = EcKey.generate()
    header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [public_chain(pki)]}
    attestation = wallet.key_attestation([holder], signing_key=EcKey.generate(), _header=header)
    proof = wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert (response.status_code, response.json()["error"]) == (400, "invalid_proof"), response.text
    assert response.json()["error_description"] == "key attestation signature does not verify"
    assert fetcher.asked == []


NO_CHAIN = [
    ...,
    "MIIB",
    [],
    [7],
    ["not base64 at all!"],
    [base64.b64encode(b"not a certificate").decode()],
]


@pytest.mark.parametrize(
    "x5c", NO_CHAIN, ids=["absent", "a string", "empty", "a number", "not base64", "not a certificate"]
)
def test_a_wallet_attestation_whose_chain_cannot_be_read_is_refused_as_untrusted(
    code_wallet: CodeWallet, code_issuer: Issuer, x5c: Any
) -> None:
    """With the signature checked before the path, the chain is read on its own, ahead of both: one that cannot be
    read is the refusal an untrusted chain gets, never an error."""
    header = {"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": x5c}
    token = code_wallet.attestation(_header={name: value for name, value in header.items() if value is not ...})
    client_tests.refused(
        "WIA.CHAIN_TO_WP_LIST",
        "the wallet attestation is not from a trusted wallet provider",
        lambda: client_tests.authenticate(code_wallet, code_issuer, token),
    )


def test_a_wallet_attestation_with_a_chain_too_long_is_refused_as_untrusted(
    code_wallet: CodeWallet, code_issuer: Issuer
) -> None:
    assert code_wallet.provider is not None
    x5c = code_wallet.provider.wia_x5c()
    header = {"typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": [x5c[0]] * (MAX_CHAIN + 1)}
    client_tests.refused(
        "WIA.CHAIN_TO_WP_LIST",
        "the wallet attestation is not from a trusted wallet provider",
        lambda: client_tests.authenticate(code_wallet, code_issuer, code_wallet.attestation(_header=header)),
    )


@pytest.mark.parametrize(
    "x5c", NO_CHAIN, ids=["absent", "a string", "empty", "a number", "not base64", "not a certificate"]
)
def test_a_key_attestation_whose_chain_cannot_be_read_is_refused_as_untrusted(wallet: Wallet, x5c: Any) -> None:
    wallet.get_token()
    holder = EcKey.generate()
    header = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c}
    attestation = wallet.key_attestation(
        [holder], _header={name: value for name, value in header.items() if value is not ...}
    )
    proof = wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})
    assert (response.status_code, response.json()["error"]) == (400, "invalid_proof"), response.text
    assert response.json()["error_description"].startswith("key attestation is not from a trusted wallet provider: "), (
        response.text
    )


@pytest.mark.parametrize("kind", ["status list", "identifier list"])
def test_a_list_signed_by_a_stranger_makes_cunho_fetch_nothing_more(pki: Pki, clock: Clock, kind: str) -> None:
    """A wallet provider's list that names the provider's public chain and is signed with another key: refused for
    its signature, and the chain's revocation is not asked for."""
    stranger = StatusSigner(EcKey.generate(), provider_signer(pki).x5c)
    now = int(clock())
    if kind == "status list":
        source = ServedStatus({STATUS_URL: stranger.token(STATUS_URL, {}, iat=now, exp=now + DAY)})
        member: dict[str, Any] = {"status": {"status_list": {"idx": 3, "uri": STATUS_URL}}}
    else:
        source = ServedStatus({URI: stranger.identifiers(URI, [], iat=now, exp=now + DAY)})
        member = {"status": {"identifier_list": {"id": b64u(b"my wallet"), "uri": URI}}}
    revocation = Unanswered()
    with pytest.raises(StatusError, match="signature does not verify"):
        fetching_status(pki, clock, source, revocation).check(member)
    assert revocation.asked == []


@pytest.mark.parametrize("kind", ["status list", "identifier list"])
def test_a_list_its_own_signer_signed_has_its_path_checked_revocation_and_all(
    pki: Pki, clock: Clock, kind: str
) -> None:
    """What the test above leaves out on purpose: once the signature is the signer's own, the path is checked, and
    with it where the certificate says its revocation is. Nothing answers there, so the list is not trusted."""
    signer = provider_signer(pki)
    now = int(clock())
    if kind == "status list":
        source = ServedStatus({STATUS_URL: signer.token(STATUS_URL, {}, iat=now, exp=now + DAY)})
        member: dict[str, Any] = {"status": {"status_list": {"idx": 3, "uri": STATUS_URL}}}
    else:
        source = ServedStatus({URI: signer.identifiers(URI, [], iat=now, exp=now + DAY)})
        member = {"status": {"identifier_list": {"id": b64u(b"my wallet"), "uri": URI}}}
    revocation = Unanswered()
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        fetching_status(pki, clock, source, revocation).check(member)
    assert revocation.asked == [CRL_URL]


def test_a_chain_given_as_der_holds_one_to_five_certificates_each_readable(pki: Pki) -> None:
    der = pki.wallet_ca.public_bytes(serialization.Encoding.DER)
    assert load_der_chain([der]) == [pki.wallet_ca]
    assert len(load_der_chain([der] * MAX_CHAIN)) == MAX_CHAIN
    for ders in ([], [der] * (MAX_CHAIN + 1)):
        with pytest.raises(JoseError, match="a certificate chain holds 1 to 5 certificates"):
            load_der_chain(ders)
    with pytest.raises(JoseError, match="x5c entry is not a DER certificate"):
        load_der_chain([der, der[:-1]])


def test_an_identifier_list_with_a_chain_too_long_is_a_status_error(pki: Pki, clock: Clock) -> None:
    signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    signer.x5c = signer.x5c * (MAX_CHAIN + 1)
    now = int(clock())
    fetcher = ServedStatus({URI: signer.identifiers(URI, [], iat=now, exp=now + DAY)})
    status = WalletStatus(fetcher, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))
    with pytest.raises(StatusError, match="identifier list is not signed by a trusted signer"):
        status.check({"status": {"identifier_list": {"id": b64u(b"my wallet"), "uri": URI}}})


@pytest.mark.parametrize("kind", ["status list", "identifier list"])
def test_whatever_reading_a_list_raises_the_status_is_unknown_and_it_is_logged(
    pki: Pki, clock: Clock, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, kind: str
) -> None:
    """The reading of a reply is held to one kind of refusal whatever goes wrong inside it: an error of another
    kind would be a 500 at issuance and the end of a run of revocation chaining."""
    signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    now = int(clock())
    if kind == "status list":
        source = ServedStatus({STATUS_URL: signer.token(STATUS_URL, {}, iat=now, exp=now + DAY)})
        member: dict[str, Any] = {"status": {"status_list": {"idx": 3, "uri": STATUS_URL}}}
        reader = "_verified"
    else:
        source = ServedStatus({URI: signer.identifiers(URI, [], iat=now, exp=now + DAY)})
        member = {"status": {"identifier_list": {"id": b64u(b"my wallet"), "uri": URI}}}
        reader = "_verified_identifiers"
    trust = Trust.fixed(status=[pki.wallet_ca])
    WalletStatus(source, trust, clock, MemoryStore(clock)).check(member)  # readable as it is

    def broken(*args: Any) -> Any:
        raise RuntimeError("something no reply should be able to cause")

    status = WalletStatus(source, trust, clock, MemoryStore(clock))
    monkeypatch.setattr(status, reader, broken)
    with caplog.at_level(logging.ERROR, logger="cunho"), pytest.raises(StatusError) as unknown:
        status.check(member)
    assert str(unknown.value) == "the wallet provider's status list cannot be read"
    assert [record.getMessage() for record in caplog.records] == ["a wallet provider's list could not be read"]
    assert caplog.records[0].exc_info is not None, "the cause is in the log, for the operator"


def test_a_refusal_of_the_reading_itself_is_passed_on_as_it_is_and_not_logged(
    pki: Pki, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    """A list that is merely wrong keeps the reason it was refused for, and is no error to log."""
    signer = StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)
    now = int(clock())
    source = ServedStatus({STATUS_URL: signer.token(STATUS_URL, {}, iat=now, exp=now + DAY, sub="another list")})
    status = WalletStatus(source, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))
    with caplog.at_level(logging.ERROR, logger="cunho"), pytest.raises(StatusError) as refused:
        status.check({"status": {"status_list": {"idx": 3, "uri": STATUS_URL}}})
    assert str(refused.value) == "the wallet provider's status list is not the one the attestation names"
    assert caplog.records == []


# --- the fetcher's memory of a failure, and its wait for a host's minute ----------------------------------------------


STATUS_TYPE = {"application/statuslist+jwt"}


def limited(elapsed: list[float], **kwargs: Any) -> Fetcher:
    return Fetcher(None, resolve=local, loopback_for_tests=True, monotonic=lambda: elapsed[0], **kwargs)


def read(fetcher: Fetcher, url: str) -> bytes:
    return fetcher.get(url, types=STATUS_TYPE, max_bytes=4096, budget=2.0)


def test_a_fetch_that_failed_is_not_made_again_until_a_few_seconds_have_passed(list_host: str) -> None:
    elapsed = [1000.0]
    fetcher = limited(elapsed)
    ListHandler.lists["/status/here"] = "a list"
    gone, here = f"{list_host}/status/gone", f"{list_host}/status/here"
    with pytest.raises(FetchError, match="a status other than 200"):
        read(fetcher, gone)
    assert ListHandler.asked == ["/status/gone"]
    elapsed[0] += RETRY_AFTER - 0.001
    with pytest.raises(FetchError, match="could not be fetched a moment ago and is not tried again yet"):
        read(fetcher, gone)
    assert ListHandler.asked == ["/status/gone"], "the failure stands in for the fetch"
    assert read(fetcher, here) == b"a list", "another URL of the same host is fetched as ever"
    elapsed[0] += 0.001
    ListHandler.lists["/status/gone"] = "back again"
    assert read(fetcher, gone) == b"back again", "once the few seconds have passed the fetch is made again"
    assert ListHandler.asked == ["/status/gone", "/status/here", "/status/gone"]


def test_a_fetch_that_fails_again_is_remembered_from_then(list_host: str) -> None:
    elapsed = [1000.0]
    fetcher = limited(elapsed)
    gone = f"{list_host}/status/gone"
    for _ in range(2):
        with pytest.raises(FetchError, match="a status other than 200"):
            read(fetcher, gone)
        elapsed[0] += RETRY_AFTER
    elapsed[0] -= 0.001  # a moment before the second failure is forgotten, long after the first one was
    with pytest.raises(FetchError, match="not tried again yet"):
        read(fetcher, gone)
    assert ListHandler.asked == ["/status/gone"] * 2


def test_a_fetch_that_succeeded_is_made_again_at_once(list_host: str) -> None:
    fetcher = limited([1000.0])
    ListHandler.lists["/status/here"] = "a list"
    for _ in range(3):
        assert read(fetcher, f"{list_host}/status/here") == b"a list"
    assert ListHandler.asked == ["/status/here"] * 3


def test_cunhos_own_limit_is_not_remembered_as_a_failure_of_the_host(list_host: str) -> None:
    """The limit says nothing was sent, so nothing is known of the URL: the moment the host's minute has a place
    again it is fetched, where a remembered failure would still have refused it for seconds."""
    elapsed = [1000.0]
    fetcher = limited(elapsed, per_host_per_minute=1)
    ListHandler.lists.update({"/status/1": "one", "/status/2": "two"})
    assert read(fetcher, f"{list_host}/status/1") == b"one"
    elapsed[0] = 1057.0
    with pytest.raises(Busy, match="too many requests to this host"):
        read(fetcher, f"{list_host}/status/2")
    elapsed[0] = 1060.0  # the first request is a minute old
    assert read(fetcher, f"{list_host}/status/2") == b"two"
    assert ListHandler.asked == ["/status/1", "/status/2"]


def waiting(elapsed: list[float], waits: list[float], *, moves: bool = True, per_minute: int = 2) -> Fetcher:
    """A fetcher whose waits are recorded; `moves` says whether its clock goes on while it waits."""

    def wait(seconds: float) -> None:
        waits.append(seconds)
        if moves:
            elapsed[0] += seconds

    return limited(elapsed, per_host_per_minute=per_minute, sleep=wait)


def test_a_caller_that_can_wait_waits_until_the_oldest_request_is_a_minute_old(list_host: str) -> None:
    elapsed: list[float] = [1000.0]
    waits: list[float] = []
    fetcher = waiting(elapsed, waits)
    ListHandler.lists["/status/1"] = "one"
    url = f"{list_host}/status/1"
    fetcher.wait_for(url)
    assert waits == [], "no request sent yet: nothing to wait for"
    read(fetcher, url)
    fetcher.wait_for(url)
    assert waits == [], "one place of two is taken"
    elapsed[0] = 1010.0
    read(fetcher, url)
    elapsed[0] = 1020.0
    fetcher.wait_for(url)
    assert waits == [40.0], "until the request sent at 1000 is a minute old"
    assert elapsed[0] == 1060.0
    assert read(fetcher, url) == b"one", "and then the place is there"
    fetcher.wait_for(f"http://another.wallet-provider.test:{url.rsplit(':', 1)[1]}")
    assert waits == [40.0], "the minute is each host's own"


def test_a_wait_is_for_the_place_and_ends_when_it_is_free(list_host: str) -> None:
    """A request sent exactly a minute ago has left the minute, as it has for the fetch itself."""
    elapsed: list[float] = [1000.0]
    waits: list[float] = []
    fetcher = waiting(elapsed, waits, per_minute=1)
    ListHandler.lists["/status/1"] = "one"
    url = f"{list_host}/status/1"
    read(fetcher, url)
    elapsed[0] = 1059.5
    fetcher.wait_for(url)
    assert waits == [0.5] and elapsed[0] == 1060.0
    fetcher.wait_for(url)
    assert waits == [0.5], "at the minute exactly the place is free"
    assert read(fetcher, url) == b"one"


def test_a_wait_ends_after_a_few_turns_whatever_the_clock_does(list_host: str) -> None:
    """A clock that stands still, or other callers that take every place as it frees: the caller does not wait for
    ever, it goes on to the fetch, which is then refused by the limit as it would have been."""
    elapsed: list[float] = [1000.0]
    waits: list[float] = []
    fetcher = waiting(elapsed, waits, moves=False, per_minute=1)
    ListHandler.lists["/status/1"] = "one"
    url = f"{list_host}/status/1"
    read(fetcher, url)
    elapsed[0] = 1030.0
    fetcher.wait_for(url)
    assert waits == [30.0] * WAITS
    with pytest.raises(Busy):
        read(fetcher, url)


def test_waiting_for_a_url_that_is_none_leaves_the_refusal_to_the_fetch() -> None:
    waits: list[float] = []
    fetcher = waiting([1000.0], waits)
    fetcher.wait_for("ftp://wallet-provider.test/status/1")
    fetcher.wait_for("not a URL")
    assert waits == []
    with pytest.raises(FetchError, match="only http and https URLs are fetched"):
        read(fetcher, "ftp://wallet-provider.test/status/1")


def test_the_memory_of_failures_does_not_grow_without_end() -> None:
    """Ten thousand URLs that failed are remembered at most; past that, those whose few seconds are over go."""
    elapsed = [1000.0]

    class Failing(Fetcher):
        def _exchange(self, method: str, where: Any, *rest: Any) -> bytes:
            raise FetchError("cannot connect")

    fetcher = Failing(None, monotonic=lambda: elapsed[0])
    for number in range(10_000):
        with pytest.raises(FetchError, match="cannot connect"):
            read(fetcher, f"http://lists.wallet-provider.test/status/{number}")
    assert len(fetcher._failed) == 10_000  # noqa: SLF001 - what it remembers
    elapsed[0] += RETRY_AFTER
    with pytest.raises(FetchError, match="cannot connect"):
        read(fetcher, "http://lists.wallet-provider.test/status/one-more")
    assert list(fetcher._failed) == ["http://lists.wallet-provider.test/status/one-more"]  # noqa: SLF001
