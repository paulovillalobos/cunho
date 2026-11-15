"""The safe fetcher: every request cunho sends out goes through `Fetcher`: CRLs, OCSP and the wallet
providers' status lists. The Commission's list is a file an operator job keeps current, never fetched by cunho.

A URL that reaches it comes from a certificate or a list someone else signed, so it is treated as hostile
(RFC 5280 §4.2.1.13 lets a CRL distribution point name any host; OWASP SSRF prevention):

- http and https only, no user info, ASCII only, at most 2048 characters;
- in production only the hosts the operator allows;
- the host is resolved once, every address it resolves to must be public (no loopback, private, link-local,
  shared, reserved, multicast or cloud metadata address, also when embedded in IPv6), and the connection goes
  to the address that was checked, so a DNS answer that changes in between cannot move it;
- no redirects, no content encoding, the content type the caller expects;
- a size cap read as the body arrives, and one time budget for the whole exchange, enforced by closing the
  socket when it runs out, so a server that drips bytes cannot hold a request;
- a limit per host per minute, which a background job may wait for and a request never does;
- a URL whose fetch failed is not tried again for a few seconds: everyone who waited for that fetch shares its
  failure, instead of each making it again in turn.

Every refusal is a FetchError with fixed text. Failures are logged with the host, never the URL, whose path may
carry whatever the certificate's author put there.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import ssl
import threading
import time
from collections import deque
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

log = logging.getLogger("cunho")
MAX_URL = 2048
CHUNK = 65_536
NAT64 = ipaddress.ip_network("64:ff9b::/96")
# IPv6 forms that carry an IPv4 address in their last 32 bits and that the address library does not unwrap: the
# IPv4-compatible addresses (::a.b.c.d, RFC 4291 §2.5.5.1) and the IPv4-translated ones (::ffff:0:a.b.c.d, RFC 2765).
EMBEDDING = (ipaddress.ip_network("::/96"), ipaddress.ip_network("::ffff:0:0:0/96"))
SITE_LOCAL = ipaddress.ip_network("fec0::/10")  # deprecated (RFC 3879), and never a public address
RETRY_AFTER = 5.0  # seconds a URL whose fetch failed is not tried again
WAITS = 3  # how often a caller that may wait asks again for a place in a host's minute
Resolver = Callable[..., list[tuple[Any, ...]]]


class FetchError(Exception):
    """A request cunho refused to send, or a reply it refused to use."""


class Busy(FetchError):
    """cunho's own limit of requests to one host is reached: nothing was sent, and nothing is known of the host."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str


def target(url: Any) -> Target:
    """The parts of a URL the fetcher may use. Raises FetchError for anything else."""
    if not isinstance(url, str) or not 0 < len(url) <= MAX_URL or not url.isascii() or not url.isprintable():
        raise FetchError("the URL is not a short printable ASCII string")
    if any(c.isspace() for c in url):
        raise FetchError("the URL is not a short printable ASCII string")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise FetchError("the URL cannot be parsed") from exc
    if parts.scheme not in ("http", "https"):
        raise FetchError("only http and https URLs are fetched")
    if parts.username is not None:  # a password comes only with a user name, empty or not
        raise FetchError("a URL with user info is not fetched")
    if not parts.hostname:
        raise FetchError("the URL names no host")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(parts.scheme, parts.hostname, port or (443 if parts.scheme == "https" else 80), path)


def is_public(address: str) -> bool:
    """Whether a connection to `address` leaves the deployment's own networks."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in SITE_LOCAL:
            return False
        embedded = [ip.ipv4_mapped, ip.sixtofour, ip.teredo[1] if ip.teredo else None]
        if ip in NAT64 or any(ip in network for network in EMBEDDING):
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if any(inner is not None and not is_public(str(inner)) for inner in embedded):
            return False
    return ip.is_global and not ip.is_multicast


def _cut(live: list[socket.socket]) -> None:
    """The budget ran out: whatever the exchange is waiting for, it stops now. `live` holds the socket in use,
    the TLS socket once the plain one is wrapped, since wrapping detaches the plain one (the second reviewer)."""
    try:
        live[0].shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _resolve_within(resolve: Resolver, host: str, port: int, budget: float) -> list[tuple[Any, ...]]:
    """The resolver has no timeout of its own, so it runs in a thread the request stops waiting for when the
    budget runs out (the second reviewer). A thread left behind ends with the resolver's own timeout."""
    result: list[Any] = []

    def run() -> None:
        try:
            result.append(resolve(host, port, type=socket.SOCK_STREAM))
        except BaseException as exc:  # noqa: BLE001 - handed to the waiting request
            result.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(budget)
    if not result:
        raise FetchError("the server did not answer within the time budget")
    if isinstance(result[0], BaseException):
        raise FetchError("the host cannot be resolved") from result[0]
    answers: list[tuple[Any, ...]] = result[0]
    return answers


class Fetcher:
    """GET and POST under the rules above.

    `allowed_hosts`: the hosts that may be fetched; None allows any host whose addresses are public, which only a
    deployment that is not production may choose. `loopback_for_tests` lets loopback addresses through, and
    nothing else; it exists so the tests can serve from 127.0.0.1, and no setting reaches it.
    """

    def __init__(
        self,
        allowed_hosts: Collection[str] | None,
        *,
        per_host_per_minute: int = 60,
        resolve: Resolver = socket.getaddrinfo,
        monotonic: Callable[[], float] = time.monotonic,
        tls: ssl.SSLContext | None = None,
        loopback_for_tests: bool = False,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._allowed = None if allowed_hosts is None else frozenset(h.lower() for h in allowed_hosts)
        self._per_minute = per_host_per_minute
        self._resolve = resolve
        self._monotonic = monotonic
        self._sleep = sleep
        self._failed: dict[str, float] = {}  # URL -> until when its last failure stands in for a fetch
        self._tls = tls or ssl.create_default_context()
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self._loopback = loopback_for_tests
        self._lock = threading.Lock()
        self._sent: dict[str, deque[float]] = {}

    def get(self, url: str, *, types: Collection[str], max_bytes: int, budget: float) -> bytes:
        return self._fetch("GET", url, None, None, types, max_bytes, budget)

    def post(
        self, url: str, body: bytes, *, content_type: str, types: Collection[str], max_bytes: int, budget: float
    ) -> bytes:
        return self._fetch("POST", url, body, content_type, types, max_bytes, budget)

    def _fetch(
        self,
        method: str,
        url: str,
        body: bytes | None,
        content_type: str | None,
        types: Collection[str],
        max_bytes: int,
        budget: float,
    ) -> bytes:
        where = target(url)
        with self._lock:
            until = self._failed.get(url)
        if until is not None and self._monotonic() < until:
            # A caller that waited for the one fetch of this URL shares its failure. Each making the same fetch
            # again in turn held a thread for a whole budget apiece, and the last of them for all the budgets before
            # it (the security review).
            raise FetchError("this URL could not be fetched a moment ago and is not tried again yet")
        try:
            return self._exchange(method, where, body, content_type, types, max_bytes, budget)
        except Busy as exc:
            log.warning("fetch from %s refused: %s", where.host, exc)
            raise
        except FetchError as exc:
            log.warning("fetch from %s refused: %s", where.host, exc)
            now = self._monotonic()
            with self._lock:
                self._failed[url] = now + RETRY_AFTER
                if len(self._failed) > 10_000:
                    for past in [u for u, end in self._failed.items() if end <= now]:
                        del self._failed[past]
            raise

    def wait_for(self, url: str) -> None:
        """Wait until the host of `url` has a place left in this minute, for a caller that can: revocation chaining
        reads every list of every wallet provider in one run, and a provider may serve more lists from one host than
        a minute allows. Refused instead, those lists read as unreachable at every run, in the same order: their
        wallets were never checked again, or were revoked as unchecked (the security review). A request never waits."""
        try:
            host = target(url).host
        except FetchError:
            return  # the fetch that follows says what is wrong with the URL
        for _ in range(WAITS):
            now = self._monotonic()
            with self._lock:
                sent = self._sent.get(host)
                while sent and sent[0] <= now - 60:
                    sent.popleft()
                if not sent or len(sent) < self._per_minute:
                    return
                free_in = sent[0] + 60 - now
            self._sleep(free_in)

    def _exchange(
        self,
        method: str,
        where: Target,
        body: bytes | None,
        content_type: str | None,
        types: Collection[str],
        max_bytes: int,
        budget: float,
    ) -> bytes:
        if self._allowed is not None and where.host not in self._allowed:
            raise FetchError("the host is not one the operator allows")
        deadline = self._monotonic() + budget
        address = self._address(where, budget)
        self._count(where.host)
        try:
            sock = socket.create_connection((address, where.port), timeout=self._left(deadline))
        except OSError as exc:
            if self._monotonic() >= deadline:
                raise FetchError("the server did not answer within the time budget") from exc
            raise FetchError("cannot connect") from exc
        live = [sock]
        timer = threading.Timer(self._left(deadline), _cut, (live,))
        timer.daemon = True
        timer.start()
        try:
            return self._talk(live, method, where, body, content_type, types, max_bytes, deadline)
        except FetchError:
            raise
        except (OSError, http.client.HTTPException, ValueError) as exc:
            if self._monotonic() >= deadline:
                raise FetchError("the server did not answer within the time budget") from exc
            raise FetchError("the exchange failed") from exc
        finally:
            timer.cancel()
            for each in {id(s): s for s in (sock, *live)}.values():
                each.close()

    def _left(self, deadline: float) -> float:
        """What is left of the budget; nothing left refuses."""
        left = deadline - self._monotonic()
        if left <= 0:
            raise FetchError("the server did not answer within the time budget")
        return left

    def _address(self, where: Target, budget: float) -> str:
        """Resolve once, within the budget; every answer must be public, and the first is the one connected to."""
        try:
            answers = _resolve_within(self._resolve, where.host, where.port, budget)
            addresses = [str(answer[4][0]) for answer in answers]
            judged = [self._may_connect(a) for a in addresses]
        except (UnicodeError, ValueError) as exc:
            raise FetchError("the host cannot be resolved") from exc
        if not addresses:
            raise FetchError("the host cannot be resolved")
        if not all(judged):
            raise FetchError("the host resolves to an address that is not public")
        return addresses[0]

    def _may_connect(self, address: str) -> bool:
        if self._loopback and ipaddress.ip_address(address.split("%", 1)[0]).is_loopback:
            return True
        return is_public(address)

    def _count(self, host: str) -> None:
        """At most `per_host_per_minute` requests to one host in any minute; more fail closed."""
        now = self._monotonic()
        with self._lock:
            sent = self._sent.setdefault(host, deque())
            while sent and sent[0] <= now - 60:
                sent.popleft()
            if len(sent) >= self._per_minute:
                raise Busy("too many requests to this host")
            sent.append(now)
            if len(self._sent) > 10_000:
                for idle in [h for h, s in self._sent.items() if not s or s[-1] <= now - 60]:
                    del self._sent[idle]

    def _talk(
        self,
        live: list[socket.socket],
        method: str,
        where: Target,
        body: bytes | None,
        content_type: str | None,
        types: Collection[str],
        max_bytes: int,
        deadline: float,
    ) -> bytes:
        connection: http.client.HTTPConnection
        if where.scheme == "https":
            # The handshake runs after the TLS socket takes the deadline's place, so a server that stalls or
            # drips during it is cut too.
            live[0] = self._tls.wrap_socket(live[0], server_hostname=where.host, do_handshake_on_connect=False)
            self._left(deadline)
            live[0].do_handshake()  # type: ignore[attr-defined]
            connection = http.client.HTTPSConnection(where.host, where.port)
        else:
            connection = http.client.HTTPConnection(where.host, where.port)
        connection.sock = live[0]  # already connected to the address that was checked
        headers = {"Accept": ", ".join(types), "Accept-Encoding": "identity", "Connection": "close"}
        if content_type is not None:
            headers["Content-Type"] = content_type
        connection.request(method, where.path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise FetchError("the server answered with a status other than 200; redirects are not followed")
        if response.getheader("Content-Encoding", "identity").strip().lower() != "identity":
            raise FetchError("the reply is encoded")
        kind = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if kind not in types:
            raise FetchError("the reply is not of the expected content type")
        length = response.getheader("Content-Length")
        if length is not None and not length.strip().isdigit():
            raise FetchError("the reply's length is not a number")
        if length is not None and int(length) > max_bytes:
            raise FetchError("the reply is larger than allowed")  # refused before a byte of the body is read
        data = bytearray()
        while chunk := response.read(min(CHUNK, max_bytes + 1 - len(data))):
            data += chunk
            if len(data) > max_bytes:
                raise FetchError("the reply is larger than allowed")
        if self._monotonic() >= deadline:
            raise FetchError("the server did not answer within the time budget")
        return bytes(data)
