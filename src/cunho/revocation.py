"""Revocation status from the network: CRLs fetched from distribution points, and OCSP (TRUST.REVOCATION_FETCHED).

`FetchedRevocation` is a `jose.Revocation`, so `validate_path` asks it about every certificate below the anchor:

- a certificate that names a CRL distribution point is judged by that CRL, fetched once and kept until its
  nextUpdate, with M2's rules for which CRL decides (`jose._check_revocation`), the operator's CRL file pooled in;
- one that names only an OCSP responder is judged by an OCSP response, checked in full (RFC 6960 §3.2, §4.2.2.2),
  because the `cryptography` library parses a response and checks nothing in it;
- one that names neither is judged by the operator's CRL file, as in M2.

Whatever cannot be fetched, read or checked fails closed: the status is unknown, and the path is refused. A fetch
runs under the fetcher's time budget; one URL is fetched by one request at a time, and the others wait for its
result (single flight). Caches are bounded, and the least recently used entry goes first.
"""

from __future__ import annotations

import datetime as dt
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

from cunho.fetch import Fetcher, FetchError
from cunho.jose import (
    CrlSet,
    JoseError,
    _check_extensions,
    _check_strength,
    _crl_order,
    _extension,
    agreed_hash,
)
from cunho.proofs import CrlFile, parse_crls
from cunho.rules import implements

CRL_TYPES = frozenset({"application/pkix-crl", "application/x-pkcs7-crl", "application/octet-stream"})
OCSP_TYPES = frozenset({"application/ocsp-response"})
MAX_CRL = 10 * 1024 * 1024
MAX_OCSP = 64 * 1024
MAX_HELD = 16  # CRLs kept from one fetch of a distribution point; a fetch with more is refused
OVERFLOW = "the distribution point served more revocation lists than this validator keeps"
BUDGET = 2.0
SKEW = dt.timedelta(seconds=60)
# Response extensions an OCSP client must understand when they are critical: only the nonce here.
KNOWN_OCSP_EXTENSIONS = {x509.OCSPNonce.oid}


def crl_url(cert: x509.Certificate) -> str | None:
    """The first http(s) URL of a full CRL distribution point: none for reasons or for a CRL issuer, which would
    point at a partitioned or indirect CRL that the CRL loader refuses anyway."""
    try:
        points = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return None
    for point in points:
        if point.reasons is not None or point.crl_issuer is not None or point.full_name is None:
            continue
        for name in point.full_name:
            if isinstance(name, x509.UniformResourceIdentifier) and name.value.startswith(("http://", "https://")):
                return name.value
    return None


def ocsp_url(cert: x509.Certificate) -> str | None:
    """The first http(s) OCSP responder in the authority information access extension."""
    try:
        access = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for description in access:
        location = description.access_location
        if (
            description.access_method == AuthorityInformationAccessOID.OCSP
            and isinstance(location, x509.UniformResourceIdentifier)
            and location.value.startswith(("http://", "https://"))
        ):
            return location.value
    return None


def _key_hash(cert: x509.Certificate) -> bytes:
    """SHA-1 of the subject public key bit string, as a responder ID by key carries it (RFC 6960 §4.2.1); the
    same digest as a key identifier of RFC 5280 §4.2.1.2 method (1)."""
    return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


@dataclass(frozen=True)
class OcspAnswer:
    """What an accepted response says about the certificate, until when it may be relied on, and the delegated
    responder that signed it, if the issuer did not."""

    this_update: dt.datetime
    next_update: dt.datetime
    responder: x509.Certificate | None = None


def ocsp_request(cert: x509.Certificate, issuer: x509.Certificate, nonce: bytes) -> bytes:
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256())
    builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


@dataclass(frozen=True)
class _Response:
    """Every part of a successful response this client uses, read at once (lesson N4-M2: the library parses
    lazily, so a broken part would otherwise raise later, from wherever it is first read)."""

    serial: int
    issuer_key_hash: bytes
    issuer_name_hash: bytes
    hash_name: str
    responder_key_hash: bytes | None
    responder_name: x509.Name | None
    certificates: list[x509.Certificate]
    signature: bytes
    tbs: bytes
    signature_hash: hashes.HashAlgorithm | None
    produced_at: dt.datetime
    this_update: dt.datetime
    next_update: dt.datetime | None
    status: ocsp.OCSPCertStatus
    nonce: bytes | None
    critical: list[x509.ObjectIdentifier]


def _read(der: bytes) -> _Response:
    try:
        response = ocsp.load_der_ocsp_response(der)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise JoseError("the OCSP response is not a successful one")
        if sum(1 for _ in response.responses) != 1:
            raise JoseError("the OCSP response does not hold exactly one answer")
        extensions = list(response.extensions) + list(response.single_extensions)
        nonces = [e.value.nonce for e in extensions if isinstance(e.value, x509.OCSPNonce)]
        return _Response(
            serial=response.serial_number,
            issuer_key_hash=response.issuer_key_hash,
            issuer_name_hash=response.issuer_name_hash,
            hash_name=response.hash_algorithm.name,
            responder_key_hash=response.responder_key_hash,
            responder_name=response.responder_name,
            certificates=list(response.certificates),
            signature=response.signature,
            tbs=response.tbs_response_bytes,
            signature_hash=response.signature_hash_algorithm,
            produced_at=response.produced_at_utc,
            this_update=response.this_update_utc,
            next_update=response.next_update_utc,
            status=response.certificate_status,
            nonce=nonces[0] if len(nonces) == 1 else None,
            critical=[e.oid for e in extensions if e.critical and e.oid not in KNOWN_OCSP_EXTENSIONS],
        )
    except JoseError:
        raise
    except Exception as exc:  # noqa: BLE001 - a response that cannot be fully read is not used
        raise JoseError("the OCSP response cannot be read") from exc


def _signed_by(response: _Response, key: Any) -> bool:
    digest = response.signature_hash
    if not agreed_hash(digest):
        return False
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(response.signature, response.tbs, ec.ECDSA(digest))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(response.signature, response.tbs, padding.PKCS1v15(), digest)
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _names(cert: x509.Certificate, response: _Response) -> bool:
    """Whether the responder ID of `response` names `cert`, by key hash or by name."""
    if response.responder_key_hash is not None:
        return response.responder_key_hash == _key_hash(cert)
    return response.responder_name == cert.subject


def _ocsp_purpose(cert: x509.Certificate) -> bool:
    try:
        purposes = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in purposes


def _check_responder(cert: x509.Certificate) -> None:
    """A delegated responder is held to what a path holds its certificates to: no critical extension this
    validator does not know, agreed key sizes and hashes, and a key usage that allows the signature it makes;
    and it is an end entity (the second reviewer)."""
    role = "the OCSP responder"
    _check_extensions(cert, role)
    _check_strength(cert, role)
    constraints = _extension(cert, x509.BasicConstraints)
    if constraints is not None and constraints.ca:
        raise JoseError("the OCSP responder is a CA certificate")
    usage = _extension(cert, x509.KeyUsage)
    if usage is not None and not usage.digital_signature:
        raise JoseError("the OCSP responder's key usage does not allow digital signatures")


def _no_check(cert: x509.Certificate) -> bool:
    return any(e.oid == x509.OCSPNoCheck.oid for e in cert.extensions)


@implements("TRUST.REVOCATION_FETCHED")
def check_ocsp(
    der: bytes,
    cert: x509.Certificate,
    issuer: x509.Certificate,
    nonce: bytes,
    now: dt.datetime,
    delegate_status: Callable[[x509.Certificate, x509.Certificate], None] | None,
) -> OcspAnswer:
    """Accept an OCSP response only if it says `cert` is good, now (RFC 6960 §3.2, §4.2.2.2). Raises JoseError.

    The response must be successful and hold one answer, for the CertID the request asked about; it must be signed
    by the issuer, or by a responder the issuer certified for OCSP signing and that is valid at producedAt and now;
    it must be current; a nonce in it must be the one sent; and the certificate must be good. A delegated
    responder without id-pkix-ocsp-nocheck has its own status checked by `delegate_status` (RFC 6960
    §4.2.2.2.1), which is refused when there is none. A response without a nonce is accepted, as RFC 8954 §2.1
    lets responders that pre-produce answers do, and its validity period then bounds a replay.
    """
    response = _read(der)
    asked = ocsp.load_der_ocsp_request(ocsp_request(cert, issuer, nonce))
    if (response.serial, response.issuer_key_hash, response.issuer_name_hash, response.hash_name) != (
        asked.serial_number,
        asked.issuer_key_hash,
        asked.issuer_name_hash,
        asked.hash_algorithm.name,
    ):
        raise JoseError("the OCSP response is about another certificate")
    if response.critical:
        raise JoseError("the OCSP response carries a critical extension this client does not process")
    signer = issuer
    if not _names(issuer, response):
        named = [c for c in response.certificates if _names(c, response)]
        if len(named) != 1:
            raise JoseError("the OCSP responder is not authorised for this certificate")
        signer = named[0]
        try:
            signer.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise JoseError("the OCSP responder is not authorised for this certificate") from exc
        if not _ocsp_purpose(signer):
            raise JoseError("the OCSP responder is not authorised for this certificate")
        _check_responder(signer)
        for moment in (response.produced_at, now):
            if not signer.not_valid_before_utc <= moment <= signer.not_valid_after_utc:
                raise JoseError("the OCSP responder certificate is outside its validity period")
    if not _signed_by(response, signer.public_key()):
        raise JoseError("the OCSP response signature does not verify")
    if signer is not issuer and not _no_check(signer):
        if delegate_status is None:
            raise JoseError("the OCSP responder's own status cannot be checked")
        delegate_status(signer, issuer)
    if response.next_update is None or not response.this_update - SKEW <= now <= response.next_update:
        raise JoseError("the OCSP response is not current")
    if response.nonce is not None and response.nonce != nonce:
        raise JoseError("the OCSP response does not answer this request")
    if response.status == ocsp.OCSPCertStatus.REVOKED:
        raise JoseError("the certificate is revoked")
    if response.status != ocsp.OCSPCertStatus.GOOD:
        raise JoseError("the OCSP responder does not know the certificate")
    return OcspAnswer(response.this_update, response.next_update, None if signer is issuer else signer)


class _Bounded:
    """A cache with at most `size` entries, least recently used first out, and one lock per key so a key is
    fetched by one caller at a time."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._entries: OrderedDict[Any, Any] = OrderedDict()
        self._locks: dict[Any, list[Any]] = {}  # key -> [its lock, how many callers hold or wait for it]
        self._lock = threading.Lock()

    def get(self, key: Any) -> Any:
        with self._lock:
            if key not in self._entries:
                return None
            self._entries.move_to_end(key)
            return self._entries[key]

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            self._entries[key] = value
            self._entries.move_to_end(key)
            while len(self._entries) > self._size:
                self._entries.popitem(last=False)

    @contextmanager
    def flight(self, key: Any) -> Iterator[None]:
        """The key's lock, held for the body. The lock goes from the registry when its last user leaves, whether
        the body returned or raised, so failing keys do not pile up (the second reviewer)."""
        with self._lock:
            entry = self._locks.setdefault(key, [threading.Lock(), 0])
            entry[1] += 1
        try:
            with entry[0]:
                yield
        finally:
            with self._lock:
                entry[1] -= 1
                if entry[1] == 0:
                    del self._locks[key]


class FetchedRevocation:
    """The status of each certificate in a path, from its CRL distribution point, its OCSP responder or the
    operator's CRL file, in that order (see the module docstring)."""

    def __init__(
        self, fetcher: Fetcher, local: CrlFile | None = None, *, budget: float = BUDGET, entries: int = 1000
    ) -> None:
        self._fetcher = fetcher
        self._local = local
        self._budget = budget
        self._crls = _Bounded(entries)
        self._answers = _Bounded(entries)
        self._remembering = threading.Lock()

    def _local_crls(self) -> list[x509.CertificateRevocationList]:
        return self._local.current() if self._local is not None else []

    @implements("TRUST.REVOCATION_FETCHED")
    def check(self, cert: x509.Certificate, issuer: x509.Certificate, now: dt.datetime, role: str) -> None:
        url = crl_url(cert)
        if url is not None:
            self._by_crl(cert, issuer, url, now, role)
            return
        url = ocsp_url(cert)
        if url is not None:
            self._ocsp(cert, issuer, url, now, role)
            return
        CrlSet(self._local_crls()).check(cert, issuer, now, role)

    def _by_crl(self, cert: x509.Certificate, issuer: x509.Certificate, url: str, now: dt.datetime, role: str) -> None:
        """Judge `cert` by the CRLs of its distribution point and the operator's file (RFC 5280 §6.3.3).

        The newest CRL in force decides: a complete CRL lists every unexpired certificate its issuer revoked, and
        a revocation other than certificateHold never leaves it (RFC 5280 §5, §5.3.1), so an older CRL adds
        nothing a newer one in force does not say. What cunho remembers of a distribution point is the CRLs of
        its last fetch and the newest CRL it has seen in force there. When no CRL in force now is as new as that
        one, the status is unknown and the certificate is refused: an older list replayed over plain http, a
        fetch that fails after the newest CRL expired, an older clean CRL in the operator's file, or a fetch
        that brought more CRLs than are kept, all end there (the second reviewer). A CRL counts as seen once its
        thisUpdate has passed, whether or not a check ran while it was in force (the second reviewer).
        """
        key = (url, *_issuer_id(issuer))  # one URL may serve several issuers' CRLs (the second reviewer)
        source = self._source(key, url, issuer, now)
        crls = [*source.crls, *self._local_crls()]
        newest = _newest_in_force(crls, issuer, now)
        # Remembered before any refusal, so a refused check keeps it too; and the decision goes by what is stored
        # once this check's view is merged in, so a newer CRL another check saw meanwhile counts (the second
        # reviewer).
        seen = self._remember(key, None, _latest(source.newest, _newest_issued(crls, issuer, now))).newest
        if seen is not None and (newest is None or newest < seen):
            raise JoseError(f"no current revocation list covers the {role} certificate")
        CrlSet(crls).check(cert, issuer, now, role)

    def _source(self, key: Any, url: str, issuer: x509.Certificate, now: dt.datetime) -> _Source:
        """What the distribution point gave, fetched again unless the CRLs of the last fetch still decide. A
        forged CRL is never kept. A fetch that fails, or brings no CRL `issuer` signed, leaves what was there;
        one that brings more than MAX_HELD CRLs is refused, and only the newest of them in force is remembered."""
        source: _Source | None = self._crls.get(key)
        if source is not None and _decides(source, issuer, now):
            return source
        with self._crls.flight(key):
            source = self._crls.get(key) or _Source([], None)
            if _decides(source, issuer, now):
                return source
            try:
                data = self._fetcher.get(url, types=CRL_TYPES, max_bytes=MAX_CRL, budget=self._budget)
                fetched = [crl for crl in parse_crls(data) if _signed(crl, issuer)]
            except (FetchError, ValueError):
                return source
            if not fetched:
                return source
            # What was in hand counts before it is replaced: a CRL that took effect and expired between two checks
            # is seen too, so an older one replayed now cannot wipe it out (the second reviewer). `_remember` keeps
            # the higher of this and the newest seen before.
            newest = _latest(_newest_issued(source.crls, issuer, now), _newest_issued(fetched, issuer, now))
            if len(fetched) > MAX_HELD:
                self._remember(key, None, newest)
                raise JoseError(OVERFLOW)
            return self._remember(key, fetched, newest)

    def _remember(
        self, key: Any, crls: list[x509.CertificateRevocationList] | None, seen: tuple[int, dt.datetime] | None
    ) -> _Source:
        """Store what a fetch brought (`crls`, or None to keep what is there) and the newest CRL seen, under one
        lock and never lowering it: a check that saw less, finishing after one that saw more, cannot roll it back
        (the second reviewer)."""
        with self._remembering:
            current: _Source | None = self._crls.get(key)
            kept = current.crls if current is not None and crls is None else crls or []
            stored = _Source(kept, _latest(current.newest if current is not None else None, seen))
            self._crls.put(key, stored)
            return stored

    def crls(self, url: str, issuer: x509.Certificate, now: dt.datetime) -> list[x509.CertificateRevocationList]:
        """The CRLs of the distribution point's last fetch that `issuer` signed, fetched again if they no longer
        decide."""
        return self._source((url, *_issuer_id(issuer)), url, issuer, now).crls

    def _ocsp(self, cert: x509.Certificate, issuer: x509.Certificate, url: str, now: dt.datetime, role: str) -> None:
        key = (*_issuer_id(issuer), cert.serial_number)  # the whole CertID (the second reviewer)
        held: OcspAnswer | None = self._answers.get(key)
        if held is not None and self._reusable(held, issuer, now):
            return
        with self._answers.flight(key):
            held = self._answers.get(key)
            if held is not None and self._reusable(held, issuer, now):
                return
            nonce = secrets.token_bytes(16)
            try:
                der = self._fetcher.post(
                    url,
                    ocsp_request(cert, issuer, nonce),
                    content_type="application/ocsp-request",
                    types=OCSP_TYPES,
                    max_bytes=MAX_OCSP,
                    budget=self._budget,
                )
            except FetchError as exc:
                raise JoseError(f"the status of the {role} certificate cannot be fetched") from exc
            answer = check_ocsp(der, cert, issuer, nonce, now, self._delegate(now))
            self._answers.put(key, answer)

    def _reusable(self, held: OcspAnswer, issuer: x509.Certificate, now: dt.datetime) -> bool:
        """An answer in hand is used again while it is current and its responder would still be accepted: a
        delegate's certificate valid now and, without ocsp-nocheck, not revoked, by the CRLs of now (the second
        reviewer). A revoked delegate refuses."""
        if not held.this_update - SKEW <= now <= held.next_update:
            return False
        responder = held.responder
        if responder is None:
            return True
        if not responder.not_valid_before_utc <= now <= responder.not_valid_after_utc:
            return False
        if not _no_check(responder):
            self._delegate(now)(responder, issuer)
        return True

    def _delegate(self, now: dt.datetime) -> Callable[[x509.Certificate, x509.Certificate], None]:
        """A delegated responder's own status, from a CRL only: asking OCSP about the OCSP responder could loop."""

        def status(delegate: x509.Certificate, issuer: x509.Certificate) -> None:
            url = crl_url(delegate)
            if url is not None:
                self._by_crl(delegate, issuer, url, now, "OCSP responder")
            else:
                CrlSet(self._local_crls()).check(delegate, issuer, now, "OCSP responder")

        return status


@dataclass(frozen=True)
class _Source:
    """What one distribution point gave for one issuer: the CRLs of its last fetch that the issuer signed, and the
    newest CRL seen in force there, by CRL number and thisUpdate."""

    crls: list[x509.CertificateRevocationList]
    newest: tuple[int, dt.datetime] | None


def _newest_in_force(
    crls: list[x509.CertificateRevocationList], issuer: x509.Certificate, now: dt.datetime
) -> tuple[int, dt.datetime] | None:
    return max((_crl_order(crl) for crl in crls if _in_force(crl, now) and _signed(crl, issuer)), default=None)


def _newest_issued(
    crls: list[x509.CertificateRevocationList], issuer: x509.Certificate, now: dt.datetime
) -> tuple[int, dt.datetime] | None:
    """The newest CRL whose thisUpdate has passed, in force or expired: one that has been issued."""
    return max((_crl_order(crl) for crl in crls if crl.last_update_utc <= now and _signed(crl, issuer)), default=None)


def _latest(*orders: tuple[int, dt.datetime] | None) -> tuple[int, dt.datetime] | None:
    return max((order for order in orders if order is not None), default=None)


def _decides(source: _Source, issuer: x509.Certificate, now: dt.datetime) -> bool:
    """Whether the CRLs in hand can stand in for a fetch: one of them is in force and as new as any seen."""
    newest = _newest_in_force(source.crls, issuer, now)
    seen = _latest(source.newest, _newest_issued(source.crls, issuer, now))
    return newest is not None and (seen is None or newest >= seen)


def _in_force(crl: x509.CertificateRevocationList, now: dt.datetime) -> bool:
    return crl.next_update_utc is not None and crl.last_update_utc <= now <= crl.next_update_utc


def _issuer_id(issuer: x509.Certificate) -> tuple[bytes, bytes]:
    """An issuer as a CertID names it: by its name and its key, since two CAs may share either."""
    return issuer.subject.public_bytes(), _key_hash(issuer)


def _signed(crl: x509.CertificateRevocationList, issuer: x509.Certificate) -> bool:
    if not agreed_hash(crl.signature_hash_algorithm):
        return False
    try:
        return crl.issuer == issuer.subject and crl.is_signature_valid(issuer.public_key())  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
