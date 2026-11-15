"""The safe fetcher (M3 plan section 2 item 6, R8), against a server on 127.0.0.1 that misbehaves on purpose."""

from __future__ import annotations

import datetime as dt
import http.server
import logging
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cunho.fetch import Fetcher, FetchError, Target, is_public, target

CRL = "application/pkix-crl"
# A budget of 0.5 s must cut a server that would take 8 s or more well before that; the margin is for a loaded
# machine (mutation runs share it with three jobs), so the tests prove the cut and do not race the scheduler.
CUT_OFF = 3.0
BODY = b"0" * 1000


class Handler(http.server.BaseHTTPRequestHandler):
    seen: list[tuple[str, str, dict[str, str], bytes]] = []

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, status: int, body: bytes, kind: str = CRL, **extra: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.seen.append(("POST", self.path, dict(self.headers), body))
        self._send(200, body[::-1], "application/ocsp-response")

    def do_GET(self) -> None:
        self.seen.append(("GET", self.path, dict(self.headers), b""))
        path = self.path.split("?", 1)[0]
        if path == "/crl":
            self._send(200, BODY)
        elif path == "/crl-with-parameters":
            self._send(200, BODY, CRL + "; charset=binary")
        elif path == "/redirect":
            self._send(302, b"", Location="http://127.0.0.1/crl")
        elif path == "/error":
            self._send(500, b"")
        elif path == "/html":
            self._send(200, BODY, "text/html")
        elif path == "/gzip":
            self._send(200, BODY, Content_Encoding="gzip")
        elif path == "/streamed":
            self.send_response(200)
            self.send_header("Content-Type", CRL)
            self.end_headers()
            self.wfile.write(b"0" * 5000)
        elif path == "/drip":
            self.send_response(200)
            self.send_header("Content-Type", CRL)
            self.send_header("Content-Length", "200")
            self.end_headers()
            for _ in range(200):
                self.wfile.write(b"0")
                self.wfile.flush()
                time.sleep(0.05)
        elif path == "/liar":
            self.send_response(200)
            self.send_header("Content-Type", CRL)
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            self.wfile.write(b"0" * 10)
        elif path == "/nan-length":
            self.send_response(200)
            self.send_header("Content-Type", CRL)
            self.send_header("Content-Length", "ten")
            self.end_headers()
            self.wfile.write(b"0" * 10)
        elif path == "/close":
            self.close_connection = True
        elif path == "/late":
            time.sleep(8)
            self._send(200, BODY)
        else:
            self._send(404, b"")


@pytest.fixture(scope="module")
def server() -> Iterator[int]:
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def local(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]


def fetcher(**kwargs: Any) -> Fetcher:
    return Fetcher(None, resolve=kwargs.pop("resolve", local), loopback_for_tests=True, **kwargs)


def get(f: Fetcher, url: str, max_bytes: int = 4096, budget: float = 2.0) -> bytes:
    return f.get(url, types={CRL}, max_bytes=max_bytes, budget=budget)


def test_a_crl_is_fetched_from_the_checked_address_with_its_host_name(server: int) -> None:
    calls: list[str] = []

    def resolve(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        calls.append(host)
        return local(host, port)

    Handler.seen.clear()
    assert get(fetcher(resolve=resolve), f"http://crl.example:{server}/crl?x=1") == BODY
    assert calls == ["crl.example"]
    method, path, headers, _ = Handler.seen[-1]
    assert (method, path) == ("GET", "/crl?x=1")
    assert headers["Host"] == f"crl.example:{server}"
    assert headers["Accept-Encoding"] == "identity" and headers["Accept"] == CRL


def test_an_ocsp_request_is_posted_with_its_content_type(server: int) -> None:
    Handler.seen.clear()
    reply = fetcher().post(
        f"http://ocsp.example:{server}/",
        b"request",
        content_type="application/ocsp-request",
        types={"application/ocsp-response"},
        max_bytes=100,
        budget=2,
    )
    assert reply == b"tseuqer"
    _, _, headers, body = Handler.seen[-1]
    assert headers["Content-Type"] == "application/ocsp-request" and body == b"request"


def test_a_content_type_with_parameters_is_its_type(server: int) -> None:
    assert get(fetcher(), f"http://crl.example:{server}/crl-with-parameters") == BODY


def test_loopback_is_refused_without_the_test_hook(server: int) -> None:
    Handler.seen.clear()
    with pytest.raises(FetchError, match="not public"):
        get(Fetcher(None, resolve=local), f"http://crl.example:{server}/crl")
    with pytest.raises(FetchError, match="not public"):
        get(Fetcher(None), f"http://127.0.0.1:{server}/crl")
    assert Handler.seen == [], "nothing was sent"


def test_the_test_hook_lets_loopback_through_and_nothing_else() -> None:
    def private(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))]

    with pytest.raises(FetchError, match="not public"):
        get(fetcher(resolve=private), "http://crl.example/crl")


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.0.8",
        "198.18.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "fd00::1",
        "fe80::1%en0",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "2002:7f00:1::1",
        "2002:a9fe:a9fe::1",
        "64:ff9b::a00:1",
        "64:ff9b::7f00:1",
        "2001:0:4136:e378:8000:63bf:f5ff:fffe",
    ],
)
def test_an_address_inside_the_deployment_is_not_public(address: str) -> None:
    assert not is_public(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808", "::ffff:8.8.8.8"])
def test_a_public_address_is_public(address: str) -> None:
    assert is_public(address)


def test_a_host_with_one_private_address_among_public_ones_is_refused() -> None:
    def mixed(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port)),
        ]

    with pytest.raises(FetchError, match="not public"):
        get(Fetcher(None, resolve=mixed), "http://crl.example/crl")


def test_a_dns_answer_that_changes_after_the_check_does_not_move_the_connection(server: int) -> None:
    answers = iter(["127.0.0.1", "10.0.0.1"])

    def rebinding(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers), port))]

    assert get(fetcher(resolve=rebinding), f"http://crl.example:{server}/crl") == BODY
    assert next(answers) == "10.0.0.1", "resolved once"


def test_only_the_hosts_the_operator_allows_are_fetched(server: int) -> None:
    calls: list[str] = []

    def resolve(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        calls.append(host)
        return local(host, port)

    allowed = Fetcher({"CRL.Example"}, resolve=resolve, loopback_for_tests=True)
    assert get(allowed, f"http://crl.example:{server}/crl") == BODY
    with pytest.raises(FetchError, match="not one the operator allows"):
        get(allowed, f"http://other.example:{server}/crl")
    assert calls == ["crl.example"], "a host that is not allowed is not even resolved"


@pytest.mark.parametrize(
    "url",
    [
        None,
        "",
        "ftp://crl.example/crl",
        "ldap://crl.example/cn=ca?certificateRevocationList",
        "file:///etc/passwd",
        "gopher://crl.example/",
        "http://user:secret@crl.example/crl",
        "http://user@crl.example/crl",
        "http:///crl",
        "http://crl.exämple/crl",
        "http://crl.example/a b",
        "http://crl.example/\x00",
        "http://crl.example/\t",
        "http://crl.example:99999/crl",
        "http://crl.example:port/crl",
        "http://[::1/crl",
        "http://crl.example/" + "a" * 2048,
    ],
)
def test_a_url_out_of_shape_is_refused(url: Any) -> None:
    with pytest.raises(FetchError):
        target(url)
    with pytest.raises(FetchError):
        get(fetcher(), url)


def test_a_url_is_split_into_what_the_request_needs() -> None:
    assert target("https://CRL.example/x?y") == Target("https", "crl.example", 443, "/x?y")
    assert target("http://crl.example") == Target("http", "crl.example", 80, "/")
    assert target("http://[2001:db8::1]:8080/a") == Target("http", "2001:db8::1", 8080, "/a")
    assert target("http://crl.example:/a").port == 80
    assert len(target("http://crl.example/" + "a" * 2028).path) == 2029


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("/redirect", "redirects are not followed"),
        ("/error", "status other than 200"),
        ("/missing", "status other than 200"),
        ("/html", "expected content type"),
        ("/gzip", "encoded"),
    ],
)
def test_a_reply_cunho_cannot_use_is_refused(server: int, path: str, reason: str) -> None:
    with pytest.raises(FetchError, match=reason):
        get(fetcher(), f"http://crl.example:{server}{path}")


def test_a_reply_larger_than_allowed_is_refused_with_or_without_a_length(server: int) -> None:
    assert get(fetcher(), f"http://crl.example:{server}/crl", max_bytes=len(BODY)) == BODY
    with pytest.raises(FetchError, match="larger than allowed"):
        get(fetcher(), f"http://crl.example:{server}/crl", max_bytes=len(BODY) - 1)
    assert len(get(fetcher(), f"http://crl.example:{server}/streamed", max_bytes=5000)) == 5000
    with pytest.raises(FetchError, match="larger than allowed"):
        get(fetcher(), f"http://crl.example:{server}/streamed", max_bytes=4999)


@pytest.mark.parametrize("path", ["/drip", "/late"])
def test_a_slow_server_is_cut_off_when_the_budget_runs_out(server: int, path: str) -> None:
    started = time.monotonic()
    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(), f"http://crl.example:{server}{path}", budget=0.5)
    assert time.monotonic() - started < CUT_OFF


def test_a_host_gets_a_limited_number_of_requests_a_minute(server: int) -> None:
    now = [1000.0]
    limited = fetcher(per_host_per_minute=2, monotonic=lambda: now[0])
    url = f"http://crl.example:{server}/crl"
    get(limited, url)
    get(limited, url)
    with pytest.raises(FetchError, match="too many requests"):
        get(limited, url)
    assert get(limited, f"http://other.example:{server}/crl") == BODY, "the limit is per host"
    now[0] += 60
    assert get(limited, url) == BODY


def test_a_host_that_cannot_be_reached_or_resolved_is_a_refusal() -> None:
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    with pytest.raises(FetchError, match="cannot connect"):
        get(fetcher(), f"http://crl.example:{port}/crl")

    def failing(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        raise socket.gaierror("no such host")

    def empty(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        return []

    for resolve in (failing, empty):
        with pytest.raises(FetchError, match="cannot be resolved"):
            get(fetcher(resolve=resolve), "http://crl.example/crl")


def test_a_refusal_is_logged_with_the_host_and_never_the_url(server: int, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="cunho"), pytest.raises(FetchError):
        get(fetcher(), f"http://crl.example:{server}/html?secret=1")
    assert "crl.example" in caplog.text and "secret" not in caplog.text and "/html" not in caplog.text


def _tls_files(tmp: Path, name: str) -> tuple[Path, Path, Path]:
    """A test CA and a server certificate for `name`, as PEM files."""
    now = dt.datetime.now(dt.UTC)

    def cert(subject: str, key: Any, issuer: str, signer: Any, ca: bool) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        if not ca:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        return builder.sign(signer, hashes.SHA256())

    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = cert("test CA", ca_key, "test CA", ca_key, True)
    leaf = cert(name, key, "test CA", ca_key, False)
    pem = serialization.Encoding.PEM
    (tmp / "ca.pem").write_bytes(ca.public_bytes(pem))
    (tmp / "leaf.pem").write_bytes(leaf.public_bytes(pem))
    (tmp / "key.pem").write_bytes(
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return tmp / "ca.pem", tmp / "leaf.pem", tmp / "key.pem"


def test_https_checks_the_certificate_against_the_host_name_not_the_address(tmp_path: Path) -> None:
    ca, leaf, key = _tls_files(tmp_path, "crl.example")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    serving = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    serving.load_cert_chain(leaf, key)
    httpd.socket = serving.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        trusting = ssl.create_default_context(cafile=str(ca))
        assert get(fetcher(tls=trusting), f"https://crl.example:{port}/crl") == BODY
        with pytest.raises(FetchError, match="exchange failed"):
            get(fetcher(tls=ssl.create_default_context(cafile=str(ca))), f"https://other.example:{port}/crl")
        with pytest.raises(FetchError, match="exchange failed"):
            get(fetcher(), f"https://crl.example:{port}/crl")
    finally:
        httpd.shutdown()


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[tuple[int, ssl.SSLContext]]:
    """The misbehaving server over TLS, as crl.example, and a client context that trusts it."""
    ca, leaf, key = _tls_files(tmp_path, "crl.example")
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    serving = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    serving.load_cert_chain(leaf, key)
    httpd.socket = serving.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], ssl.create_default_context(cafile=str(ca))
    httpd.shutdown()


@pytest.mark.parametrize("path", ["/drip", "/late"])
def test_a_slow_server_over_tls_is_cut_off_when_the_budget_runs_out(
    tls_server: tuple[int, ssl.SSLContext], path: str
) -> None:
    """Wrapping detaches the plain socket, so the deadline must cut the TLS one (the second reviewer)."""
    port, trusting = tls_server
    assert get(fetcher(tls=trusting), f"https://crl.example:{port}/crl") == BODY
    started = time.monotonic()
    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(tls=trusting), f"https://crl.example:{port}{path}", budget=0.5)
    assert time.monotonic() - started < CUT_OFF


def test_a_handshake_that_never_comes_is_cut_off_when_the_budget_runs_out() -> None:
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen()
    try:
        started = time.monotonic()
        with pytest.raises(FetchError, match="time budget"):
            get(fetcher(), f"https://crl.example:{silent.getsockname()[1]}/crl", budget=0.5)
        assert time.monotonic() - started < CUT_OFF
    finally:
        silent.close()


def test_a_dns_lookup_that_hangs_is_cut_off_when_the_budget_runs_out() -> None:
    """The resolver has no timeout of its own; the budget covers it too (the second reviewer)."""

    def hanging(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        time.sleep(8)
        return local(host, port)

    started = time.monotonic()
    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(resolve=hanging), "http://crl.example/crl", budget=0.5)
    assert time.monotonic() - started < CUT_OFF


def test_the_time_spent_resolving_comes_out_of_the_budget(server: int) -> None:
    now = [0.0]

    def slow(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        now[0] += 5  # the lookup used the whole budget
        return local(host, port)

    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(resolve=slow, monotonic=lambda: now[0]), f"http://crl.example:{server}/crl", budget=2)


def test_a_declared_length_past_the_cap_is_refused_before_the_body_is_read(server: int) -> None:
    """The server says a million bytes and sends ten: refused on the header, not by a read that never ends."""
    with pytest.raises(FetchError, match="larger than allowed"):
        get(fetcher(), f"http://crl.example:{server}/liar")
    with pytest.raises(FetchError, match="length is not a number"):
        get(fetcher(), f"http://crl.example:{server}/nan-length")


def test_the_url_cap_is_2048_characters() -> None:
    base = "http://crl.example/"
    assert target(base + "a" * (2048 - len(base))).path == "/" + "a" * (2048 - len(base))
    with pytest.raises(FetchError, match="short printable"):
        target(base + "a" * (2049 - len(base)))
    with pytest.raises(FetchError, match="short printable"):
        target("")


def clock(*readings: float) -> Any:
    """A monotonic clock that gives `readings` in turn, then the last one for ever."""
    given = list(readings)

    def read() -> float:
        return given.pop(0) if len(given) > 1 else given[0]

    return read


# The fetcher reads its clock for the deadline, the per-host limit, the connection's budget and the timer's, in that
# order, and then once more at the end of the exchange or when it fails. The readings below land the last one exactly
# on the deadline: at the deadline the time is up.


def test_an_answer_that_ends_exactly_at_the_deadline_is_refused(server: int) -> None:
    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(monotonic=clock(0, 0, 0, 0, 2.0)), f"http://crl.example:{server}/crl", budget=2.0)


def test_a_connection_that_fails_exactly_at_the_deadline_is_put_down_to_the_budget() -> None:
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    port = free.getsockname()[1]
    free.close()
    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(monotonic=clock(0, 0, 1.0, 2.0)), f"http://crl.example:{port}/crl", budget=2.0)
    with pytest.raises(FetchError, match="cannot connect"):
        get(fetcher(monotonic=clock(0, 0, 1.0, 1.9)), f"http://crl.example:{port}/crl", budget=2.0)


def test_an_exchange_that_fails_exactly_at_the_deadline_is_put_down_to_the_budget(server: int) -> None:
    with pytest.raises(FetchError, match="time budget"):
        get(fetcher(monotonic=clock(0, 0, 0, 0, 2.0)), f"http://crl.example:{server}/close", budget=2.0)
    with pytest.raises(FetchError, match="exchange failed"):
        get(fetcher(monotonic=clock(0, 0, 0, 0, 1.9)), f"http://crl.example:{server}/close", budget=2.0)


def test_a_resolver_answer_that_is_not_an_address_is_a_refusal() -> None:
    def garbled(host: str, port: int, type: int = 0) -> list[tuple[Any, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-address", port))]

    with pytest.raises(FetchError, match="cannot be resolved"):
        get(fetcher(resolve=garbled), "http://crl.example/crl")
