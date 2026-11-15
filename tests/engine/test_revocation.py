"""Revocation from the network (piece C): OCSP checked in full, CRLs from distribution points, and the source
`validate_path` asks, against a server on 127.0.0.1."""

from __future__ import annotations

import datetime as dt
import http.server
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from cunho.fetch import RETRY_AFTER, Fetcher
from cunho.jose import CrlSet, JoseError, validate_path
from cunho.proofs import CrlFile
from cunho.revocation import FetchedRevocation, _Bounded, _issuer_id, check_ocsp, crl_url, ocsp_request, ocsp_url

from .pki import DAY, UNKNOWN_EXTENSION, Builder, Issued, TestPki, name
from .test_fetch import local

REFUSALS = {
    "revoked": "the certificate is revoked",
    "unknown": "does not know the certificate",
    "stale": "not current",
    "certid": "about another certificate",
    "unsigned": "not a successful one",
    "nonce": "does not answer this request",
    "responder": "not authorised",
    "signature": "signature does not verify",
}


def crl_status(trust_pki: TestPki, *crls: x509.CertificateRevocationList) -> Any:
    def status(delegate: x509.Certificate, issuer: x509.Certificate) -> None:
        CrlSet(list(crls) or [trust_pki.crls["intermediate"]]).check(delegate, issuer, trust_pki.now, "responder")

    return status


@pytest.mark.obligation("TRUST.REVOCATION_FETCHED")
@pytest.mark.parametrize("label", ["good", "good_from_ca", "good_from_checked_delegate", "revoked", "unknown",
                                   "stale", "wrong_certid", "unsigned", "wrong_nonce", "rogue_delegate",
                                   "bad_signature"])  # fmt: skip
def test_the_ocsp_client_agrees_with_the_reference_checker(trust_pki: TestPki, label: str) -> None:
    wp, case = trust_pki.wallet_provider, trust_pki.ocsp[label]

    def check() -> Any:
        return check_ocsp(
            case.response, wp.wia_signer.cert, wp.intermediate.cert, case.nonce, trust_pki.now, crl_status(trust_pki)
        )

    if case.outcome == "good":
        answer = check()
        assert answer.this_update <= trust_pki.now <= answer.next_update
    else:
        with pytest.raises(JoseError, match=REFUSALS[case.outcome]):
            check()


@dataclass
class Answer:
    """What a test responder puts in an OCSP response about the WIA signer."""

    signer: str = "delegate"
    status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD
    this_update: dt.timedelta = -dt.timedelta(minutes=5)
    next_update: dt.timedelta | None = DAY
    nonce: str = "echo"
    by_name: bool = False
    digest: hashes.HashAlgorithm = field(default_factory=hashes.SHA256)
    extension: tuple[x509.ExtensionType, bool] | None = None


def respond(
    trust_pki: TestPki,
    answer: Answer,
    nonce: bytes,
    signers: dict[str, Issued] | None = None,
    at: dt.datetime | None = None,
) -> bytes:
    """A response about the WIA signer, its dates around `at` (the test PKI's now by default)."""
    wp = trust_pki.wallet_provider
    signers = {
        "ca": wp.intermediate,
        "delegate": wp.ocsp_delegate,
        "checked": wp.ocsp_delegate_checked,
        "wia": wp.wia_signer,
        **(signers or {}),
    }
    signer, now = signers[answer.signer], at or trust_pki.now
    revoked = answer.status == ocsp.OCSPCertStatus.REVOKED
    builder = ocsp.OCSPResponseBuilder().add_response(
        wp.wia_signer.cert,
        wp.intermediate.cert,
        hashes.SHA256(),
        answer.status,
        now + answer.this_update,
        None if answer.next_update is None else now + answer.next_update,
        now - DAY if revoked else None,
        x509.ReasonFlags.key_compromise if revoked else None,
    )
    encoding = ocsp.OCSPResponderEncoding.NAME if answer.by_name else ocsp.OCSPResponderEncoding.HASH
    builder = builder.responder_id(encoding, signer.cert)
    if answer.nonce != "none":
        builder = builder.add_extension(
            x509.OCSPNonce(nonce if answer.nonce == "echo" else os.urandom(16)), critical=False
        )
    if answer.extension is not None:
        builder = builder.add_extension(*answer.extension)
    if signer.cert != wp.intermediate.cert:
        builder = builder.certificates([signer.cert])
    return builder.sign(signer.key, answer.digest).public_bytes(serialization.Encoding.DER)


def judge(trust_pki: TestPki, answer: Answer, status: Any = "crl", **signers: Issued) -> Any:
    wp, nonce = trust_pki.wallet_provider, os.urandom(16)
    der = respond(trust_pki, answer, nonce, signers)
    delegate = crl_status(trust_pki) if status == "crl" else status
    return check_ocsp(der, wp.wia_signer.cert, wp.intermediate.cert, nonce, trust_pki.now, delegate)


def test_a_response_without_a_nonce_is_accepted_and_one_with_another_nonce_is_not(trust_pki: TestPki) -> None:
    judge(trust_pki, Answer(nonce="none"))
    with pytest.raises(JoseError, match="does not answer this request"):
        judge(trust_pki, Answer(nonce="other"))


@pytest.mark.parametrize("signer", ["ca", "delegate", "checked"])
def test_a_responder_named_by_name_is_found_as_one_named_by_key(trust_pki: TestPki, signer: str) -> None:
    judge(trust_pki, Answer(signer=signer, by_name=True))


def test_a_certificate_without_the_ocsp_purpose_cannot_answer_for_its_issuer(trust_pki: TestPki) -> None:
    with pytest.raises(JoseError, match="not authorised"):
        judge(trust_pki, Answer(signer="wia"))


@pytest.mark.parametrize(
    ("starts", "days", "checked", "accepted"),
    [
        (0, 10, 2, True),  # valid when the response was produced and at the check
        (0, 1, 2, False),  # valid when it was produced, expired at the check
        (40, 1, 20, False),  # valid at the check, not yet when it was produced
    ],
)
def test_a_delegate_must_be_valid_when_the_response_was_produced_and_now(
    trust_pki: TestPki, starts: int, days: int, checked: int, accepted: bool
) -> None:
    """The library stamps producedAt with the real time, so the dates here are built around it."""
    wp, purpose = trust_pki.wallet_provider, (ExtendedKeyUsageOID.OCSP_SIGNING,)
    produced = dt.datetime.now(dt.UTC)
    delegate = Builder(produced + starts * DAY, days).certificate(
        name("Dated Responder"), wp.intermediate, purposes=purpose, extensions=((x509.OCSPNoCheck(), False),)
    )
    now, nonce = produced + checked * DAY, os.urandom(16)
    der = respond(trust_pki, Answer(signer="other"), nonce, {"other": delegate}, at=now)

    def check() -> Any:
        return check_ocsp(der, wp.wia_signer.cert, wp.intermediate.cert, nonce, now, None)

    if accepted:
        check()
    else:
        with pytest.raises(JoseError, match="outside its validity period"):
            check()


def test_a_delegate_without_ocsp_nocheck_has_its_own_status_checked(trust_pki: TestPki) -> None:
    wp = trust_pki.wallet_provider
    judge(trust_pki, Answer(signer="checked"))
    with pytest.raises(JoseError, match="own status cannot be checked"):
        judge(trust_pki, Answer(signer="checked"), status=None)
    revoking = Builder(trust_pki.now).crl(wp.intermediate, (wp.ocsp_delegate_checked.cert,), number=9)
    with pytest.raises(JoseError, match="revoked"):
        judge(trust_pki, Answer(signer="checked"), status=crl_status(trust_pki, revoking))
    judge(trust_pki, Answer(signer="delegate"), status=None), "ocsp-nocheck: no status needed"
    judge(trust_pki, Answer(signer="ca"), status=None), "the issuer itself: no status needed"


def _responder(
    trust_pki: TestPki,
    *,
    curve: ec.EllipticCurve | None = None,
    signs: bool = True,
    ca: bool = False,
    extra: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    basic: bool = True,
    usage_extension: bool = True,
) -> Issued:
    """A delegated responder built by hand, so its key usage, curve and extensions can be out of profile, or
    missing."""
    wp, now = trust_pki.wallet_provider, trust_pki.now
    key = ec.generate_private_key(curve or ec.SECP256R1())
    usage = x509.KeyUsage(signs, False, False, False, False, ca, False, False, False)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name("Hand-made Responder"))
        .issuer_name(wp.intermediate.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - 30 * DAY)
        .not_valid_after(now + 3650 * DAY)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
        .add_extension(x509.OCSPNoCheck(), critical=False)
    )
    if basic:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    if usage_extension:
        builder = builder.add_extension(usage, critical=True)
    for extension, critical in extra:
        builder = builder.add_extension(extension, critical=critical)
    return Issued(builder.sign(wp.intermediate.key, hashes.SHA256()), key)


@pytest.mark.parametrize(
    ("built", "reason"),
    [
        ({"signs": False}, "key usage does not allow digital signatures"),
        ({"ca": True}, "is a CA certificate"),
        ({"curve": ec.SECP224R1()}, "curve outside the agreed mechanisms"),
        (
            {"extra": ((x509.UnrecognizedExtension(UNKNOWN_EXTENSION, b"\x05\x00"), True),)},
            "unsupported critical extension",
        ),
        ({"extra": ((x509.NameConstraints([x509.DNSName("x.example")], None), False),)}, "name constraints"),
    ],
)
def test_a_delegate_out_of_profile_is_refused(trust_pki: TestPki, built: dict[str, Any], reason: str) -> None:
    """Issued by the CA for OCSP signing is not enough: the certificate is held to the path's profile (the
    second reviewer)."""
    judge(trust_pki, Answer(signer="other"), other=_responder(trust_pki))
    with pytest.raises(JoseError, match=reason):
        judge(trust_pki, Answer(signer="other"), other=_responder(trust_pki, **built))


def test_a_failing_key_leaves_no_lock_behind() -> None:
    """The second reviewer: a check that raises gave its lock back to nobody, so failing keys piled up."""
    cache = _Bounded(10)
    for key in range(5):
        with pytest.raises(RuntimeError), cache.flight(key):
            raise RuntimeError("failed")
    with cache.flight("ok"):
        pass
    assert cache._locks == {}


def test_a_caller_waiting_on_a_key_shares_the_lock_of_the_one_holding_it() -> None:
    cache = _Bounded(10)
    inside, release, order = threading.Event(), threading.Event(), []

    def first() -> None:
        with pytest.raises(RuntimeError), cache.flight("k"):
            inside.set()
            release.wait(2)
            order.append("first")
            raise RuntimeError("failed")

    def second() -> None:
        with cache.flight("k"):
            order.append("second")

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    threads[0].start()
    inside.wait(2)
    threads[1].start()
    time.sleep(0.1)
    assert order == [] and cache._locks["k"][1] == 2, "the second waits on the first one's lock"
    release.set()
    for thread in threads:
        thread.join()
    assert order == ["first", "second"] and cache._locks == {}


def test_a_responder_certified_by_another_ca_is_refused(trust_pki: TestPki) -> None:
    with pytest.raises(JoseError, match="not authorised"):
        judge(trust_pki, Answer(signer="other"), other=trust_pki.untrusted.ocsp_delegate)


@pytest.mark.parametrize("digest", [hashes.SHA224()])  # the library will not sign with SHA-1 at all
def test_a_response_signed_with_a_weak_hash_is_refused(trust_pki: TestPki, digest: hashes.HashAlgorithm) -> None:
    with pytest.raises(JoseError, match="signature does not verify"):
        judge(trust_pki, Answer(digest=digest))


@pytest.mark.parametrize("digest", [hashes.SHA384(), hashes.SHA512()])
def test_a_response_signed_with_a_strong_hash_is_accepted(trust_pki: TestPki, digest: hashes.HashAlgorithm) -> None:
    judge(trust_pki, Answer(digest=digest))


def test_an_unknown_critical_extension_is_refused_and_a_non_critical_one_ignored(trust_pki: TestPki) -> None:
    unknown = x509.UnrecognizedExtension(UNKNOWN_EXTENSION, b"\x05\x00")
    judge(trust_pki, Answer(extension=(unknown, False)))
    with pytest.raises(JoseError, match="critical extension"):
        judge(trust_pki, Answer(extension=(unknown, True)))


@pytest.mark.parametrize(
    ("this_update", "next_update", "accepted"),
    [
        (dt.timedelta(seconds=60), DAY, True),
        (dt.timedelta(seconds=61), DAY, False),
        (-DAY, dt.timedelta(0), True),
        (-DAY, -dt.timedelta(seconds=1), False),
        (-DAY, None, False),
    ],
)
def test_a_response_is_used_only_while_it_is_current(
    trust_pki: TestPki, this_update: dt.timedelta, next_update: dt.timedelta | None, accepted: bool
) -> None:
    answer = Answer(this_update=this_update, next_update=next_update)
    if accepted:
        judge(trust_pki, answer)
    else:
        with pytest.raises(JoseError, match="not current"):
            judge(trust_pki, answer)


@pytest.mark.parametrize("data", [b"", b"\x30\x03\x0a\x01\x00", b"not der", os.urandom(200)])
def test_a_response_that_cannot_be_read_is_refused(trust_pki: TestPki, data: bytes) -> None:
    wp = trust_pki.wallet_provider
    with pytest.raises(JoseError, match="cannot be read|not a successful one"):
        check_ocsp(data, wp.wia_signer.cert, wp.intermediate.cert, b"n" * 16, trust_pki.now, None)


def test_a_response_cut_short_is_refused_and_never_raises_anything_else(trust_pki: TestPki) -> None:
    wp, nonce = trust_pki.wallet_provider, os.urandom(16)
    der = respond(trust_pki, Answer(), nonce)
    for size in range(0, len(der), 7):
        with pytest.raises(JoseError):
            check_ocsp(der[:size], wp.wia_signer.cert, wp.intermediate.cert, nonce, trust_pki.now, None)


def test_the_request_asks_about_the_certificate_with_a_nonce(trust_pki: TestPki) -> None:
    wp, nonce = trust_pki.wallet_provider, os.urandom(16)
    request = ocsp.load_der_ocsp_request(ocsp_request(wp.wia_signer.cert, wp.intermediate.cert, nonce))
    assert request.serial_number == wp.wia_signer.cert.serial_number
    assert request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce == nonce


# The fetched source, against a server that holds CRLs and answers OCSP.


@dataclass
class Served:
    files: dict[str, bytes] = field(default_factory=dict)
    gets: list[str] = field(default_factory=list)
    posts: int = 0
    delay: float = 0.0
    ocsp: Any = None  # a function from a DER request to a DER response, or None for a 404


class RevocationHandler(http.server.BaseHTTPRequestHandler):
    served = Served()

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes, kind: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.served.gets.append(self.path)
        time.sleep(self.served.delay)
        data = self.served.files.get(self.path)
        self._send(200 if data is not None else 404, data or b"", "application/pkix-crl")

    def do_POST(self) -> None:
        self.served.posts += 1
        request = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.served.ocsp is None:
            self._send(404, b"", "text/plain")
        else:
            self._send(200, self.served.ocsp(request), "application/ocsp-response")


@pytest.fixture(scope="module")
def port() -> Iterator[int]:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RevocationHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


@dataclass
class Chain:
    """root -> intermediate -> leaves, where each certificate below the root names where its status is."""

    build: Builder
    root: Issued
    mid: Issued
    by_crl: Issued
    by_ocsp: Issued
    by_neither: Issued
    responder: Issued
    served: Served
    answering: dt.datetime | None = None  # the time the responder dates its answers by, if not build.now


def _points(url: str) -> tuple[x509.ExtensionType, bool]:
    uri = x509.UniformResourceIdentifier(url)
    return x509.CRLDistributionPoints([x509.DistributionPoint([uri], None, None, None)]), False


def _aia(url: str) -> tuple[x509.ExtensionType, bool]:
    uri = x509.UniformResourceIdentifier(url)
    return x509.AuthorityInformationAccess([x509.AccessDescription(x509.OID_OCSP, uri)]), False


@pytest.fixture
def chain(trust_pki: TestPki, port: int) -> Chain:
    base = f"http://revocation.example:{port}"
    build = Builder(trust_pki.now)
    root = build.certificate(name("Fetched Root"), ca=True, path_length=1)
    mid = build.certificate(
        name("Fetched Intermediate"), root, ca=True, path_length=0, extensions=(_points(f"{base}/root.crl"),)
    )
    served = Served()
    served.files = {"/root.crl": build.crl(root).public_bytes(serialization.Encoding.DER)}
    served.files["/mid.crl"] = build.crl(mid).public_bytes(serialization.Encoding.DER)
    RevocationHandler.served = served
    responder = build.certificate(
        name("Fetched Responder"),
        mid,
        purposes=(ExtendedKeyUsageOID.OCSP_SIGNING,),
        extensions=((x509.OCSPNoCheck(), False),),
    )
    return Chain(
        build,
        root,
        mid,
        build.certificate(name("By CRL"), mid, extensions=(_points(f"{base}/mid.crl"),)),
        build.certificate(name("By OCSP"), mid, extensions=(_aia(f"{base}/ocsp"),)),
        build.certificate(name("By Neither"), mid),
        responder,
        served,
    )


def responder(
    chain: Chain, status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD, hours: int = 24, by: Issued | None = None
) -> Any:
    signer = by or chain.responder

    def answer(data: bytes) -> bytes:
        request = ocsp.load_der_ocsp_request(data)
        nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        assert request.serial_number == chain.by_ocsp.cert.serial_number
        now, revoked = chain.answering or chain.build.now, status == ocsp.OCSPCertStatus.REVOKED
        return (
            ocsp.OCSPResponseBuilder()
            .add_response(
                chain.by_ocsp.cert,
                chain.mid.cert,
                hashes.SHA256(),
                status,
                now - dt.timedelta(minutes=5),
                now + dt.timedelta(hours=hours),
                now - DAY if revoked else None,
                x509.ReasonFlags.key_compromise if revoked else None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, signer.cert)
            .certificates([signer.cert])
            .add_extension(x509.OCSPNonce(nonce), critical=False)
            .sign(signer.key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

    return answer


def source(local_crls: CrlFile | None = None, **kwargs: Any) -> FetchedRevocation:
    return FetchedRevocation(Fetcher(None, resolve=local, loopback_for_tests=True), local_crls, **kwargs)


def accept(chain: Chain, leaf: Issued, revocation: FetchedRevocation, now: dt.datetime | None = None) -> None:
    validate_path([leaf.cert, chain.mid.cert], [chain.root.cert], now or chain.build.now, revocation=revocation)


def refuse(chain: Chain, leaf: Issued, revocation: FetchedRevocation, reason: str, now: Any = None) -> None:
    with pytest.raises(JoseError, match=reason):
        accept(chain, leaf, revocation, now)


def test_the_urls_are_read_from_the_certificates(chain: Chain, port: int) -> None:
    base = f"http://revocation.example:{port}"
    assert crl_url(chain.by_crl.cert) == f"{base}/mid.crl" and ocsp_url(chain.by_crl.cert) is None
    assert ocsp_url(chain.by_ocsp.cert) == f"{base}/ocsp" and crl_url(chain.by_ocsp.cert) is None
    assert crl_url(chain.by_neither.cert) is None and ocsp_url(chain.by_neither.cert) is None


@pytest.mark.parametrize(
    "point",
    [
        x509.DistributionPoint([x509.UniformResourceIdentifier("ldap://x/cn=crl")], None, None, None),
        x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://x/a.crl")], None, frozenset({x509.ReasonFlags.key_compromise}), None
        ),
        x509.DistributionPoint(
            [x509.UniformResourceIdentifier("http://x/b.crl")], None, None, [x509.DNSName("other.example")]
        ),
        x509.DistributionPoint(
            None, x509.RelativeDistinguishedName([x509.NameAttribute(x509.OID_COMMON_NAME, "c")]), None, None
        ),
    ],
)
def test_a_distribution_point_this_validator_cannot_use_is_passed_over(chain: Chain, point: Any) -> None:
    cert = chain.build.certificate(name("Odd"), chain.mid, extensions=((x509.CRLDistributionPoints([point]), False),))
    assert crl_url(cert.cert) is None


def test_an_ocsp_location_that_is_not_http_is_passed_over(chain: Chain) -> None:
    ldap = x509.AccessDescription(x509.OID_OCSP, x509.UniformResourceIdentifier("ldap://x/ocsp"))
    issuers = x509.AccessDescription(x509.OID_CA_ISSUERS, x509.UniformResourceIdentifier("http://x/ca.cer"))
    cert = chain.build.certificate(
        name("Odd"), chain.mid, extensions=((x509.AuthorityInformationAccess([ldap, issuers]), False),)
    )
    assert ocsp_url(cert.cert) is None


@pytest.mark.obligation("TRUST.REVOCATION_FETCHED")
def test_a_crl_is_fetched_once_and_kept_until_its_next_update(chain: Chain) -> None:
    revocation = source()
    accept(chain, chain.by_crl, revocation)
    accept(chain, chain.by_crl, revocation)
    assert sorted(chain.served.gets) == ["/mid.crl", "/root.crl"], "each list once"
    later = Builder(chain.build.now + 31 * DAY)
    for path, ca in (("/root.crl", chain.root), ("/mid.crl", chain.mid)):
        chain.served.files[path] = later.crl(ca, number=2).public_bytes(serialization.Encoding.DER)
    accept(chain, chain.by_crl, revocation, later.now)
    assert len(chain.served.gets) == 4, "fetched again once the copy in hand is no longer current"


def test_a_certificate_a_fetched_crl_lists_is_refused(chain: Chain) -> None:
    chain.served.files["/mid.crl"] = chain.build.crl(chain.mid, (chain.by_crl.cert,)).public_bytes(
        serialization.Encoding.DER
    )
    refuse(chain, chain.by_crl, source(), "the leaf certificate is revoked")


def test_an_intermediate_its_root_crl_lists_is_refused(chain: Chain) -> None:
    chain.served.files["/root.crl"] = chain.build.crl(chain.root, (chain.mid.cert,)).public_bytes(
        serialization.Encoding.PEM
    )
    refuse(chain, chain.by_crl, source(), "the intermediate certificate is revoked")


@pytest.mark.parametrize("trouble", ["missing", "garbage", "delta"])
def test_a_crl_that_cannot_be_had_fails_closed(chain: Chain, trouble: str) -> None:
    if trouble == "missing":
        del chain.served.files["/mid.crl"]
    elif trouble == "garbage":
        chain.served.files["/mid.crl"] = b"not a crl"
    else:
        delta = chain.build.crl(chain.mid, extensions=((x509.DeltaCRLIndicator(1), True),))
        chain.served.files["/mid.crl"] = delta.public_bytes(serialization.Encoding.DER)
    refuse(chain, chain.by_crl, source(), "no current revocation list covers the leaf")


def test_a_failed_refetch_keeps_the_copy_in_hand_which_its_dates_then_judge(chain: Chain) -> None:
    revocation = source()
    accept(chain, chain.by_crl, revocation)
    del chain.served.files["/mid.crl"]
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", chain.build.now + 31 * DAY)


def test_concurrent_first_checks_of_one_list_fetch_it_once(chain: Chain) -> None:
    revocation = source()
    chain.served.delay = 0.3
    errors: list[BaseException] = []

    def check() -> None:
        try:
            accept(chain, chain.by_crl, revocation)
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=check) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert sorted(chain.served.gets) == ["/mid.crl", "/root.crl"]


def test_the_cache_is_bounded_and_drops_the_least_recently_used_list(chain: Chain) -> None:
    revocation = source(entries=1)
    accept(chain, chain.by_crl, revocation)
    accept(chain, chain.by_crl, revocation)
    assert len(chain.served.gets) == 4, "one entry: the two lists keep pushing each other out"


@pytest.mark.obligation("TRUST.REVOCATION_FETCHED")
def test_ocsp_is_asked_when_the_certificate_names_only_a_responder_and_the_answer_kept(chain: Chain) -> None:
    chain.served.ocsp = responder(chain, hours=2)
    revocation = source()
    accept(chain, chain.by_ocsp, revocation)
    accept(chain, chain.by_ocsp, revocation)
    assert chain.served.posts == 1
    chain.answering = chain.build.now + dt.timedelta(hours=3)
    accept(chain, chain.by_ocsp, revocation, chain.answering)
    assert chain.served.posts == 2, "asked again once the answer in hand has expired"


def test_a_certificate_ocsp_says_is_revoked_is_refused(chain: Chain) -> None:
    chain.served.ocsp = responder(chain, ocsp.OCSPCertStatus.REVOKED)
    refuse(chain, chain.by_ocsp, source(), "the certificate is revoked")
    chain.served.ocsp = responder(chain, ocsp.OCSPCertStatus.UNKNOWN)
    refuse(chain, chain.by_ocsp, source(), "does not know the certificate")


def test_a_refused_answer_is_not_kept(chain: Chain) -> None:
    revocation = source()
    chain.served.ocsp = responder(chain, ocsp.OCSPCertStatus.REVOKED)
    refuse(chain, chain.by_ocsp, revocation, "revoked")
    refuse(chain, chain.by_ocsp, revocation, "revoked")
    assert chain.served.posts == 2


def test_a_responder_that_cannot_be_reached_fails_closed(chain: Chain) -> None:
    refuse(chain, chain.by_ocsp, source(), "the status of the leaf certificate cannot be fetched")


def test_failed_ocsp_checks_leave_no_lock_behind(chain: Chain) -> None:
    later = [0.0]  # the fetcher's clock, moved on: a URL that just failed is not asked again for a few seconds
    fetcher = Fetcher(None, resolve=local, loopback_for_tests=True, monotonic=lambda: time.monotonic() + later[0])
    revocation = FetchedRevocation(fetcher)
    refuse(chain, chain.by_ocsp, revocation, "cannot be fetched")
    chain.served.ocsp = responder(chain, ocsp.OCSPCertStatus.REVOKED)
    later[0] += RETRY_AFTER
    refuse(chain, chain.by_ocsp, revocation, "revoked")
    assert revocation._answers._locks == {} and revocation._crls._locks == {}


def test_a_certificate_that_names_neither_is_judged_by_the_operator_file(chain: Chain, tmp_path: Path) -> None:
    refuse(chain, chain.by_neither, source(), "no current revocation list covers the leaf")
    file = tmp_path / "local.crl"
    file.write_bytes(chain.build.crl(chain.mid).public_bytes(serialization.Encoding.PEM))
    accept(chain, chain.by_neither, source(CrlFile(file)))
    file.write_bytes(
        chain.build.crl(chain.mid, (chain.by_neither.cert,), number=2).public_bytes(serialization.Encoding.PEM)
    )
    refuse(chain, chain.by_neither, source(CrlFile(file)), "the leaf certificate is revoked")


def test_a_revocation_in_the_operator_file_stands_beside_a_clean_fetched_crl(chain: Chain, tmp_path: Path) -> None:
    file = tmp_path / "local.crl"
    revoking = chain.build.crl(chain.mid, (chain.by_crl.cert,), number=1)
    file.write_bytes(revoking.public_bytes(serialization.Encoding.PEM))
    refuse(chain, chain.by_crl, source(CrlFile(file)), "the leaf certificate is revoked")


def test_a_forged_crl_with_far_off_dates_does_not_stop_the_next_fetch(chain: Chain) -> None:
    """A CRL is kept only once the issuer's signature on it verifies; a forged one served while the endpoint
    was taken over must not keep the real one out after it recovers (the second reviewer)."""
    impostor = chain.build.certificate(chain.mid.cert.subject, ca=True, path_length=0)
    forged = chain.build.crl(impostor, next_update=chain.build.now + 3650 * DAY)
    real = chain.served.files["/mid.crl"]
    chain.served.files["/mid.crl"] = forged.public_bytes(serialization.Encoding.DER)
    revocation = source()
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf")
    chain.served.files["/mid.crl"] = real
    accept(chain, chain.by_crl, revocation)


def _dated_responder(chain: Chain, days: int, nocheck: bool = True) -> tuple[Issued, dt.datetime]:
    """A responder valid from 30 days before the real time to `days` after it, since the library stamps
    producedAt with the real time; and that time."""
    produced = dt.datetime.now(dt.UTC)
    extensions = ((x509.OCSPNoCheck(), False),) if nocheck else ()
    built = Builder(produced, days).certificate(
        name("Dated Responder"), chain.mid, purposes=(ExtendedKeyUsageOID.OCSP_SIGNING,), extensions=extensions
    )
    return built, produced


def test_an_answer_in_hand_is_dropped_once_its_responder_certificate_expires(chain: Chain) -> None:
    """The answer would still be current, but its responder no longer is: it is asked again, and the new answer
    from the expired responder is refused (the second reviewer)."""
    ending, produced = _dated_responder(chain, 1)
    chain.answering = produced
    chain.served.ocsp = responder(chain, hours=5 * 24, by=ending)
    revocation = source()
    accept(chain, chain.by_ocsp, revocation, produced)
    accept(chain, chain.by_ocsp, revocation, produced + dt.timedelta(hours=12))
    assert chain.served.posts == 1
    chain.answering = produced + 2 * DAY
    refuse(chain, chain.by_ocsp, revocation, "outside its validity period", produced + 2 * DAY)
    assert chain.served.posts == 2


def test_an_answer_in_hand_is_refused_once_its_responder_is_revoked(chain: Chain, tmp_path: Path) -> None:
    """A delegate without ocsp-nocheck is checked again at each use of its answer, by the CRLs of now."""
    checked, produced = _dated_responder(chain, 10, nocheck=False)
    file = tmp_path / "local.crl"
    file.write_bytes(chain.build.crl(chain.mid).public_bytes(serialization.Encoding.PEM))
    chain.answering = produced
    chain.served.ocsp = responder(chain, by=checked)
    revocation = source(CrlFile(file))
    accept(chain, chain.by_ocsp, revocation, produced)
    file.write_bytes(chain.build.crl(chain.mid, (checked.cert,), number=2).public_bytes(serialization.Encoding.PEM))
    refuse(chain, chain.by_ocsp, revocation, "OCSP responder certificate is revoked", produced)
    assert chain.served.posts == 1, "refused from the answer in hand"


def _hand_made(
    subject: str,
    issuer: Issued,
    *,
    key: ec.EllipticCurvePrivateKey | None = None,
    ca: bool = False,
    serial: int | None = None,
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    now: dt.datetime,
) -> Issued:
    """A certificate whose key and serial the test chooses, so two can share them."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    usage = x509.KeyUsage(not ca, False, False, False, False, ca, ca, False, False)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(serial or x509.random_serial_number())
        .not_valid_before(now - 30 * DAY)
        .not_valid_after(now + 3650 * DAY)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(usage, critical=True)
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return Issued(builder.sign(issuer.key, hashes.SHA256()), key)


def test_two_issuers_whose_crls_share_one_url_each_get_their_own(chain: Chain, port: int) -> None:
    """The cache holds what one issuer signed; the other issuer, at the same URL, is not given it (the second
    reviewer)."""
    now, base = chain.build.now, f"http://revocation.example:{port}"
    other = _hand_made("Other Intermediate", chain.root, ca=True, now=now, extensions=(_points(f"{base}/root.crl"),))
    leaves = [
        _hand_made(f"Leaf {n}", ca_, now=now, extensions=(_points(f"{base}/both.crl"),))
        for n, ca_ in (("mid", chain.mid), ("other", other))
    ]
    pem = serialization.Encoding.PEM
    chain.served.files["/both.crl"] = chain.build.crl(chain.mid).public_bytes(pem) + chain.build.crl(
        other
    ).public_bytes(pem)
    revocation = source()
    validate_path([leaves[0].cert, chain.mid.cert], [chain.root.cert], now, revocation=revocation)
    validate_path([leaves[1].cert, other.cert], [chain.root.cert], now, revocation=revocation)


def test_an_answer_about_one_issuer_is_not_used_for_another_that_shares_its_key(chain: Chain, port: int) -> None:
    """Two CAs with one key and two names, each with a certificate of the same serial: the answer in hand for
    one is not the answer for the other (the second reviewer)."""
    now, base = chain.build.now, f"http://revocation.example:{port}"
    shared = ec.generate_private_key(ec.SECP256R1())
    cas = {
        label: _hand_made(label, chain.root, key=shared, ca=True, now=now, extensions=(_points(f"{base}/root.crl"),))
        for label in ("Shared A", "Shared B")
    }
    leaves = {
        label: _hand_made(f"Leaf {label}", ca_, serial=4242, now=now, extensions=(_aia(f"{base}/ocsp"),))
        for label, ca_ in cas.items()
    }

    def answer(data: bytes) -> bytes:
        request = ocsp.load_der_ocsp_request(data)
        nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
        label = next(
            label
            for label, ca_ in cas.items()
            if ocsp.load_der_ocsp_request(ocsp_request(leaves[label].cert, ca_.cert, nonce)).issuer_name_hash
            == request.issuer_name_hash
        )
        status = ocsp.OCSPCertStatus.GOOD if label == "Shared A" else ocsp.OCSPCertStatus.REVOKED
        return (
            ocsp.OCSPResponseBuilder()
            .add_response(
                leaves[label].cert,
                cas[label].cert,
                hashes.SHA256(),
                status,
                now - dt.timedelta(minutes=5),
                now + DAY,
                now - DAY if status == ocsp.OCSPCertStatus.REVOKED else None,
                x509.ReasonFlags.key_compromise if status == ocsp.OCSPCertStatus.REVOKED else None,
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, cas[label].cert)
            .add_extension(x509.OCSPNonce(nonce), critical=False)
            .sign(shared, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER)
        )

    chain.served.ocsp = answer
    revocation = source()
    validate_path([leaves["Shared A"].cert, cas["Shared A"].cert], [chain.root.cert], now, revocation=revocation)
    with pytest.raises(JoseError, match="the certificate is revoked"):
        validate_path([leaves["Shared B"].cert, cas["Shared B"].cert], [chain.root.cert], now, revocation=revocation)
    assert chain.served.posts == 2


def test_a_bundle_is_fetched_again_once_its_newest_crl_expires(chain: Chain) -> None:
    """An older clean CRL that lives longer must not keep a bundle whose newer, revoking CRL has expired: the
    copy in hand is judged by its newest CRL (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    older = build.crl(chain.mid, number=1, next_update=build.now + 30 * DAY)
    newer = build.crl(chain.mid, (chain.by_crl.cert,), number=2, next_update=build.now + DAY)
    chain.served.files["/mid.crl"] = older.public_bytes(pem) + newer.public_bytes(pem)
    revocation = source()
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    later = Builder(build.now + 2 * DAY)
    renewed = later.crl(chain.mid, (chain.by_crl.cert,), number=3)
    chain.served.files["/mid.crl"] = older.public_bytes(pem) + renewed.public_bytes(pem)
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked", later.now)
    assert chain.served.gets.count("/mid.crl") == 2


def test_a_failed_fetch_after_the_newest_crl_expires_hands_on_nothing(chain: Chain) -> None:
    """The stale bundle is not handed on when the refetch fails: its older clean CRL would vouch for a
    certificate the newer, expired one revoked (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    older = build.crl(chain.mid, number=1, next_update=build.now + 30 * DAY)
    newer = build.crl(chain.mid, (chain.by_crl.cert,), number=2, next_update=build.now + DAY)
    chain.served.files["/mid.crl"] = older.public_bytes(pem) + newer.public_bytes(pem)
    revocation = source()
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    impostor = build.certificate(chain.mid.cert.subject, ca=True, path_length=0)
    forged = build.crl(impostor, number=9, next_update=build.now + 30 * DAY).public_bytes(pem)
    for trouble in (None, b"not a crl", forged):
        if trouble is None:
            del chain.served.files["/mid.crl"]
        else:
            chain.served.files["/mid.crl"] = trouble
        refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", build.now + 2 * DAY)


@pytest.mark.parametrize(
    ("older_days", "newer_days", "newer_lists", "accepted"),
    [
        (30, -1, True, False),  # a newer revoking CRL expired: the older clean one cannot vouch
        (30, -1, False, False),  # a newer clean one expired: still unknown, it may have been replaced
        (-1, 30, False, True),  # an older CRL that expired does not matter next to a current newer one
    ],
)
def test_an_expired_newer_crl_leaves_the_status_unknown(
    chain: Chain, older_days: int, newer_days: int, newer_lists: bool, accepted: bool
) -> None:
    """The same rule in the CRL check itself, so a bundle in the operator's file is judged alike."""
    build = chain.build
    older = Builder(build.now - 2 * DAY).crl(chain.mid, number=1, next_update=build.now + older_days * DAY)
    newer = Builder(build.now - DAY).crl(
        chain.mid, (chain.by_crl.cert,) if newer_lists else (), number=2, next_update=build.now + newer_days * DAY
    )
    crls = CrlSet([older, newer])
    if accepted:
        crls.check(chain.by_crl.cert, chain.mid.cert, build.now, "leaf")
    else:
        with pytest.raises(JoseError, match="no current revocation list covers the leaf"):
            crls.check(chain.by_crl.cert, chain.mid.cert, build.now, "leaf")


def test_a_newer_crl_not_yet_current_leaves_the_current_one_in_charge(chain: Chain) -> None:
    """A CRL dated after now (a clock behind the CA's) is neither current nor expired: the current one decides."""
    build = chain.build
    current = build.crl(chain.mid, number=1)
    ahead = build.crl(chain.mid, number=2, last_update=build.now + DAY, next_update=build.now + 30 * DAY)
    CrlSet([current, ahead]).check(chain.by_crl.cert, chain.mid.cert, build.now, "leaf")


def test_a_failed_fetch_keeps_the_newer_crl_as_evidence_against_an_older_one_in_the_operator_file(
    chain: Chain, tmp_path: Path
) -> None:
    """The fetched CRL revokes the certificate and expires; the refetch fails; the operator's file holds an older
    clean CRL that is still current. The expired newer CRL is handed on, so the older one cannot vouch for the
    certificate (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    file = tmp_path / "local.crl"
    file.write_bytes(build.crl(chain.mid, number=1, next_update=build.now + 30 * DAY).public_bytes(pem))
    fetched = build.crl(chain.mid, (chain.by_crl.cert,), number=2, next_update=build.now + DAY)
    impostor = build.certificate(chain.mid.cert.subject, ca=True, path_length=0)
    forged = build.crl(impostor, number=9).public_bytes(pem)
    for trouble in (None, b"not a crl", forged):
        chain.served.files["/mid.crl"] = fetched.public_bytes(pem)
        revocation = source(CrlFile(file))
        refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
        if trouble is None:
            del chain.served.files["/mid.crl"]
        else:
            chain.served.files["/mid.crl"] = trouble
        refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", build.now + 2 * DAY)


def test_an_operator_file_newer_than_the_expired_fetched_crl_still_decides(chain: Chain, tmp_path: Path) -> None:
    """The evidence rule refuses only what nothing newer covers: a newer CRL in the operator's file decides."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=1, next_update=build.now + DAY).public_bytes(pem)
    file = tmp_path / "local.crl"
    later = Builder(build.now + 2 * DAY)
    file.write_bytes(later.crl(chain.mid, number=2).public_bytes(pem))
    revocation = source(CrlFile(file))
    accept(chain, chain.by_crl, revocation)
    del chain.served.files["/mid.crl"]
    accept(chain, chain.by_crl, revocation, later.now)


def test_a_replayed_older_crl_does_not_wipe_out_the_newer_one_in_hand(chain: Chain) -> None:
    """CRL #2 revokes the leaf and expires; the endpoint then serves #1, clean and current for another month,
    as anyone on the path can over plain http. #2 stays as evidence, so #1 cannot vouch for the leaf; a newer
    #3 decides again (the second reviewer)."""
    build, der = chain.build, serialization.Encoding.DER
    older = Builder(build.now - 2 * DAY).crl(chain.mid, number=1, next_update=build.now + 30 * DAY)
    newer = build.crl(chain.mid, (chain.by_crl.cert,), number=2, next_update=build.now + DAY)
    chain.served.files["/mid.crl"] = newer.public_bytes(der)
    revocation = source()
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    chain.served.files["/mid.crl"] = older.public_bytes(der)
    later = Builder(build.now + 2 * DAY)
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", later.now)
    chain.served.files["/mid.crl"] = later.crl(chain.mid, number=3).public_bytes(der)
    accept(chain, chain.by_crl, revocation, later.now)


def test_a_crl_in_hand_stays_until_a_newer_one_is_in_force(chain: Chain) -> None:
    """#2 revokes the leaf and expires; the endpoint then serves #1, clean and current, beside #3, published
    ahead and dated after now. #2 stays until #3 is in force, so #1 cannot vouch for the leaf meanwhile (the
    second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    older = Builder(build.now - 2 * DAY).crl(chain.mid, number=1, next_update=build.now + 30 * DAY)
    newer = build.crl(chain.mid, (chain.by_crl.cert,), number=2, next_update=build.now + DAY)
    ahead = Builder(build.now + 4 * DAY).crl(chain.mid, number=3)
    chain.served.files["/mid.crl"] = newer.public_bytes(pem)
    revocation = source()
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    chain.served.files["/mid.crl"] = older.public_bytes(pem) + ahead.public_bytes(pem)
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", build.now + 2 * DAY)
    accept(chain, chain.by_crl, revocation, build.now + 4 * DAY)


def test_the_crls_of_the_last_fetch_are_kept_and_not_fetched_again_while_they_decide(chain: Chain) -> None:
    """A CRL in force as new as any seen decides, so it is not fetched again, and a CRL dated after now beside it
    is kept with it; each fetch replaces what the last one gave, so nothing piles up (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    current = build.crl(chain.mid, number=1)
    ahead = Builder(build.now + 4 * DAY).crl(chain.mid, number=2)
    chain.served.files["/mid.crl"] = current.public_bytes(pem) + ahead.public_bytes(pem)
    revocation = source()
    for _ in range(5):
        accept(chain, chain.by_crl, revocation)
    assert chain.served.gets.count("/mid.crl") == 1
    key = (crl_url(chain.by_crl.cert), *_issuer_id(chain.mid.cert))
    assert len(revocation._crls.get(key).crls) == 2


def test_a_fetch_with_more_crls_than_are_kept_is_refused(chain: Chain) -> None:
    """Seventeen CRLs from one distribution point is not what a CA publishes: the fetch is refused, and the
    newest CRL in force in it is still remembered (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    revocation, url = source(), crl_url(chain.by_crl.cert) or ""
    chain.served.files["/mid.crl"] = b"".join(build.crl(chain.mid, number=n).public_bytes(pem) for n in range(1, 17))
    assert len(revocation.crls(url, chain.mid.cert, build.now)) == 16
    later = Builder(build.now + DAY)
    chain.served.files["/mid.crl"] = b"".join(later.crl(chain.mid, number=n).public_bytes(pem) for n in range(20, 37))
    with pytest.raises(JoseError, match="more revocation lists than this validator keeps"):
        revocation.crls(url, chain.mid.cert, build.now + 31 * DAY)
    [held] = revocation._crls._entries.values()
    assert held.newest is not None and held.newest[0] == 36 and len(held.crls) == 16


def test_crls_dated_after_now_cannot_push_out_the_evidence(chain: Chain, tmp_path: Path) -> None:
    """Seventeen CRLs dated after now, served after the revoking #2 has expired, beside an older clean CRL in the
    operator's file: the fetch is refused, and when the next one fails the older CRL still cannot vouch for the
    leaf, since #2 was seen in force (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    file = tmp_path / "local.crl"
    older = Builder(build.now - 2 * DAY).crl(chain.mid, number=1, next_update=build.now + 30 * DAY)
    file.write_bytes(older.public_bytes(pem))
    revoking = build.crl(chain.mid, (chain.by_crl.cert,), number=2, next_update=build.now + DAY)
    chain.served.files["/mid.crl"] = revoking.public_bytes(pem)
    revocation = source(CrlFile(file))
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    ahead = b"".join(Builder(build.now + 10 * DAY).crl(chain.mid, number=n).public_bytes(pem) for n in range(3, 20))
    chain.served.files["/mid.crl"] = ahead
    refuse(chain, chain.by_crl, revocation, "more revocation lists than this validator keeps", build.now + 2 * DAY)
    del chain.served.files["/mid.crl"]
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", build.now + 2 * DAY)


def test_a_current_crl_that_revoked_stays_when_a_newer_clean_one_takes_over(chain: Chain) -> None:
    """#1 revokes the leaf and stays current; #2, dated after now, makes the copy in hand call for fetches; a
    fetch then brings #3, clean and in force, alone. A revocation in a CRL that is still current stands even when
    a newer CRL no longer lists it, so #3 taking over must not drop #1 (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    revoking = build.crl(chain.mid, (chain.by_crl.cert,), number=1)
    ahead = Builder(build.now + 3 * DAY).crl(chain.mid, number=2)
    chain.served.files["/mid.crl"] = revoking.public_bytes(pem) + ahead.public_bytes(pem)
    revocation = source()
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    later = build.now + dt.timedelta(hours=12)
    chain.served.files["/mid.crl"] = Builder(later).crl(chain.mid, number=3).public_bytes(pem)
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked", later)


def test_an_expired_crl_goes_once_a_newer_one_is_in_force(chain: Chain) -> None:
    """What nothing depends on is dropped, so the copy in hand does not keep every CRL it ever saw."""
    build, der = chain.build, serialization.Encoding.DER
    revocation, url = source(), crl_url(chain.by_crl.cert) or ""
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=1, next_update=build.now + DAY).public_bytes(der)
    revocation.crls(url, chain.mid.cert, build.now)
    later = Builder(build.now + 2 * DAY)
    chain.served.files["/mid.crl"] = later.crl(chain.mid, number=2).public_bytes(der)
    held = revocation.crls(url, chain.mid.cert, later.now)
    assert [c.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number for c in held] == [2]


def _overflowing(chain: Chain, revocation: FetchedRevocation, clean: x509.CertificateRevocationList) -> None:
    """The copy in hand holds `clean`, which expires within the hour; then a fetch brings a current CRL that
    revokes the leaf, beside sixteen dated after now, one too many to keep."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = clean.public_bytes(pem)
    accept(chain, chain.by_crl, revocation)
    revoking = build.crl(chain.mid, (chain.by_crl.cert,), number=5)
    ahead = b"".join(Builder(build.now + 10 * DAY).crl(chain.mid, number=n).public_bytes(pem) for n in range(10, 26))
    chain.served.files["/mid.crl"] = revoking.public_bytes(pem) + ahead
    refuse(
        chain,
        chain.by_crl,
        revocation,
        "more revocation lists than this validator keeps",
        build.now + dt.timedelta(hours=2),
    )


def test_a_revocation_seen_when_the_crls_overflow_is_not_forgotten_when_the_next_fetch_fails(chain: Chain) -> None:
    """The fetch that overflows brings the CRL that revokes the leaf; the next fetch fails. The newest CRL in force
    it held is remembered, so the clean copy from before cannot vouch for the leaf (the second reviewer)."""
    revocation = source()
    _overflowing(
        chain, revocation, chain.build.crl(chain.mid, number=1, next_update=chain.build.now + dt.timedelta(hours=1))
    )
    later = chain.build.now + dt.timedelta(hours=2)
    del chain.served.files["/mid.crl"]
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", later)
    chain.served.files["/mid.crl"] = b"not a crl"
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", later)


def test_after_an_overflow_only_a_crl_in_force_as_new_as_the_newest_seen_decides(chain: Chain) -> None:
    """Older CRLs replayed after the overflow are refused; one as new as the revoking CRL seen in it decides, and
    as the newest complete CRL it is the one that says whether the leaf is revoked (RFC 5280 §6.3.3)."""
    build, pem = chain.build, serialization.Encoding.PEM
    revocation = source()
    _overflowing(chain, revocation, build.crl(chain.mid, number=1, next_update=build.now + dt.timedelta(hours=1)))
    later = build.now + dt.timedelta(hours=2)
    for number in (3, 4):
        chain.served.files["/mid.crl"] = build.crl(chain.mid, number=number).public_bytes(pem)
        refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", later)
    chain.served.files["/mid.crl"] = build.crl(chain.mid, (chain.by_crl.cert,), number=5).public_bytes(pem)
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked", later)
    del chain.served.files["/mid.crl"]
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked", later)


def test_only_the_crls_the_issuer_signed_are_kept(chain: Chain) -> None:
    build, pem = chain.build, serialization.Encoding.PEM
    impostor = build.certificate(chain.mid.cert.subject, ca=True, path_length=0)
    real = build.crl(chain.mid, number=1)
    chain.served.files["/mid.crl"] = build.crl(impostor, number=2).public_bytes(pem) + real.public_bytes(pem)
    held = source().crls(crl_url(chain.by_crl.cert) or "", chain.mid.cert, build.now)
    assert [c.public_bytes(pem) for c in held] == [real.public_bytes(pem)]


def test_a_crl_that_comes_into_force_while_in_hand_becomes_the_newest_seen(chain: Chain) -> None:
    """#1 is clean and short-lived; #3, fetched beside it before it was in force, revokes the leaf. Once #3 has been
    in force, a later fetch that brings only #2, clean and current, cannot vouch for the leaf: #3 was seen."""
    build, pem = chain.build, serialization.Encoding.PEM
    clean = build.crl(chain.mid, number=1, next_update=build.now + 5 * DAY)
    revoking = Builder(build.now + 2 * DAY).crl(
        chain.mid, (chain.by_crl.cert,), number=3, next_update=build.now + 3 * DAY
    )
    chain.served.files["/mid.crl"] = clean.public_bytes(pem) + revoking.public_bytes(pem)
    revocation = source()
    accept(chain, chain.by_crl, revocation)
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked", build.now + 2 * DAY)
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=2, next_update=build.now + 30 * DAY).public_bytes(pem)
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", build.now + 6 * DAY)


def test_a_crl_that_took_effect_and_expired_between_two_checks_still_counts_as_seen(chain: Chain) -> None:
    """#1 is clean; #3, fetched beside it before it was in force, revokes the leaf, and both expire before the next
    check. A fetch that then brings #2, clean and current, cannot vouch for the leaf: #3 was held and issued, even
    though no check ran while it was in force (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    clean = build.crl(chain.mid, number=1, next_update=build.now + 2 * DAY)
    revoking = Builder(build.now + 4 * DAY).crl(
        chain.mid, (chain.by_crl.cert,), number=3, next_update=build.now + 4 * DAY
    )
    chain.served.files["/mid.crl"] = clean.public_bytes(pem) + revoking.public_bytes(pem)
    revocation = source()
    accept(chain, chain.by_crl, revocation)
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=2, next_update=build.now + 30 * DAY).public_bytes(pem)
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf", build.now + 5 * DAY)


def test_a_newer_crl_seen_in_the_operator_file_counts_as_seen(chain: Chain, tmp_path: Path) -> None:
    """The operator's file held #5, which revokes the leaf, then went back to an older copy. A fetched #2 in force
    cannot vouch for the leaf: #5 was seen at a check."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=2).public_bytes(pem)
    file = tmp_path / "local.crl"
    file.write_bytes(build.crl(chain.mid, (chain.by_crl.cert,), number=5).public_bytes(pem))
    revocation = source(CrlFile(file))
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    file.write_bytes(build.crl(chain.mid, number=1).public_bytes(pem))
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf")


def test_a_newer_crl_seen_by_a_refused_check_is_remembered(chain: Chain, tmp_path: Path) -> None:
    """The operator's file holds #5, which revokes the leaf and has expired, beside a fetched #1 in force: the
    check refuses, and when the file then goes away #1 still cannot vouch for the leaf (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=1).public_bytes(pem)
    file = tmp_path / "local.crl"
    expired = Builder(build.now - 10 * DAY).crl(chain.mid, (chain.by_crl.cert,), number=5, next_update=build.now - DAY)
    file.write_bytes(expired.public_bytes(pem))
    revocation = source(CrlFile(file))
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf")
    file.write_bytes(build.crl(chain.mid, number=1).public_bytes(pem))
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf")


def test_a_check_that_saw_less_cannot_roll_back_the_newest_seen(chain: Chain, tmp_path: Path) -> None:
    """Two checks at once, one seeing #2 in the operator's file and one #5: whichever finishes last, #5 stays the
    newest seen, so a replayed #2 is refused (the second reviewer). The interleaving the reviewer found, the
    check that saw #2 writing after the one that saw #5, is played here in that order."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=1).public_bytes(pem)
    file = tmp_path / "local.crl"
    revoking = build.crl(chain.mid, (chain.by_crl.cert,), number=5)
    file.write_bytes(revoking.public_bytes(pem))
    revocation = source(CrlFile(file))
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    key = (crl_url(chain.by_crl.cert), *_issuer_id(chain.mid.cert))
    older = build.crl(chain.mid, number=2)
    stored = revocation._remember(key, None, (2, older.last_update_utc))
    assert stored.newest is not None and stored.newest[0] == 5
    stored = revocation._remember(key, [older], (2, older.last_update_utc))
    assert stored.newest is not None and stored.newest[0] == 5 and stored.crls == [older]
    file.write_bytes(older.public_bytes(pem))
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf")


def test_a_check_decides_by_the_newest_seen_once_its_view_is_merged_in(chain: Chain, tmp_path: Path) -> None:
    """Another check remembers #5 after this one read what the distribution point gave and before it decides: the
    decision goes by #5, not by the #2 this check saw (the second reviewer)."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = build.crl(chain.mid, number=1).public_bytes(pem)
    file = tmp_path / "local.crl"
    file.write_bytes(build.crl(chain.mid, number=2).public_bytes(pem))
    revocation = source(CrlFile(file))
    accept(chain, chain.by_crl, revocation)
    key = (crl_url(chain.by_crl.cert), *_issuer_id(chain.mid.cert))
    newer = build.crl(chain.mid, (chain.by_crl.cert,), number=5)
    read = revocation._source

    def read_then_another_check_remembers(*args: Any) -> Any:
        stale = read(*args)
        revocation._remember(key, None, (5, newer.last_update_utc))
        return stale

    revocation._source = read_then_another_check_remembers  # type: ignore[method-assign, assignment]
    refuse(chain, chain.by_crl, revocation, "no current revocation list covers the leaf")


def test_after_a_failed_fetch_the_crls_of_the_last_fetch_are_still_judged(chain: Chain, tmp_path: Path) -> None:
    """The last fetch gave #3, current and revoking the leaf; the operator's file then gains #6, newer and clean, so
    #3 no longer stands in for a fetch, and the fetch fails. #3 is still among what the check sees, and a
    revocation in a current CRL it sees stands."""
    build, pem = chain.build, serialization.Encoding.PEM
    chain.served.files["/mid.crl"] = build.crl(chain.mid, (chain.by_crl.cert,), number=3).public_bytes(pem)
    file = tmp_path / "local.crl"
    file.write_bytes(build.crl(chain.mid, number=1).public_bytes(pem))
    revocation = source(CrlFile(file))
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    file.write_bytes(build.crl(chain.mid, number=6).public_bytes(pem))
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")
    del chain.served.files["/mid.crl"]
    refuse(chain, chain.by_crl, revocation, "the leaf certificate is revoked")


@pytest.mark.parametrize("left_out", ["basic", "usage_extension"])
def test_a_delegate_without_basic_constraints_or_key_usage_is_judged_without_them(
    trust_pki: TestPki, left_out: str
) -> None:
    """Both extensions are optional for an end entity: without them nothing forbids the signature."""
    built = _responder(trust_pki, basic=False) if left_out == "basic" else _responder(trust_pki, usage_extension=False)
    judge(trust_pki, Answer(signer="other"), other=built)


@pytest.mark.parametrize("copies", [0, 2])
def test_a_responder_named_by_none_or_by_two_of_the_certificates_sent_is_refused(
    trust_pki: TestPki, copies: int
) -> None:
    """The responder ID must name exactly one certificate in the response, or the issuer itself."""
    wp, nonce = trust_pki.wallet_provider, os.urandom(16)
    now = trust_pki.now
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            wp.wia_signer.cert,
            wp.intermediate.cert,
            hashes.SHA256(),
            ocsp.OCSPCertStatus.GOOD,
            now - dt.timedelta(minutes=5),
            now + DAY,
            None,
            None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, wp.ocsp_delegate.cert)
        .add_extension(x509.OCSPNonce(nonce), critical=False)
    )
    if copies:
        builder = builder.certificates([wp.ocsp_delegate.cert] * copies)
    der = builder.sign(wp.ocsp_delegate.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    with pytest.raises(JoseError, match="not authorised"):
        check_ocsp(der, wp.wia_signer.cert, wp.intermediate.cert, nonce, now, None)


def test_a_response_signed_without_a_hash_is_refused(trust_pki: TestPki) -> None:
    """Ed25519 signs without a separate hash: not an agreed mechanism here, and refused, not an error."""
    now = trust_pki.now
    key = ed25519.Ed25519PrivateKey.generate()
    ca_name = name("Ed25519 CA")
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + DAY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("Ed25519 leaf"))
        .issuer_name(ca_name)
        .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + DAY)
        .sign(key, None)
    )
    nonce = os.urandom(16)
    der = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            leaf, ca, hashes.SHA256(), ocsp.OCSPCertStatus.GOOD, now - dt.timedelta(minutes=5), now + DAY, None, None
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, ca)
        .add_extension(x509.OCSPNonce(nonce), critical=False)
        .sign(key, None)
        .public_bytes(serialization.Encoding.DER)
    )
    with pytest.raises(JoseError, match="signature does not verify"):
        check_ocsp(der, leaf, ca, nonce, now, None)


def test_an_answer_in_hand_is_used_up_to_its_dates_exactly(chain: Chain) -> None:
    """Reused from thisUpdate less the allowed skew to nextUpdate, both included: no fetch at either edge."""
    chain.served.ocsp = responder(chain)
    revocation, at = source(), chain.build.now
    accept(chain, chain.by_ocsp, revocation, at)
    accept(chain, chain.by_ocsp, revocation, at - dt.timedelta(minutes=5) - dt.timedelta(seconds=60))
    accept(chain, chain.by_ocsp, revocation, at + DAY)
    assert chain.served.posts == 1


def test_a_delegate_is_used_up_to_its_validity_exactly(chain: Chain) -> None:
    """A delegate valid from an hour before the real time to two hours after it (the library dates producedAt
    with the real time): its answer is accepted and reused at both edges of that validity."""
    produced = dt.datetime.now(dt.UTC).replace(microsecond=0)
    key = ec.generate_private_key(ec.SECP256R1())
    starts, ends = produced - dt.timedelta(hours=1), produced + dt.timedelta(hours=2)
    dated = Issued(
        x509.CertificateBuilder()
        .subject_name(name("Edge Responder"))
        .issuer_name(chain.mid.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(starts)
        .not_valid_after(ends)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
        .add_extension(x509.OCSPNoCheck(), critical=False)
        .sign(chain.mid.key, hashes.SHA256()),
        key,
    )
    chain.answering = starts + dt.timedelta(minutes=5)
    chain.served.ocsp = responder(chain, by=dated)
    revocation = source()
    accept(chain, chain.by_ocsp, revocation, starts)
    accept(chain, chain.by_ocsp, revocation, starts)
    accept(chain, chain.by_ocsp, revocation, ends)
    assert chain.served.posts == 1
    accept(chain, chain.by_ocsp, source(), ends)
    assert chain.served.posts == 2


def test_the_crl_file_and_another_revocation_source_are_not_given_together(chain: Chain) -> None:
    with pytest.raises(ValueError, match="not both"):
        validate_path(
            [chain.by_crl.cert, chain.mid.cert], [chain.root.cert], chain.build.now, crls=[], revocation=source()
        )
