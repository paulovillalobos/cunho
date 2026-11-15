"""COSE and mdoc reading for the probe's mdoc checks: COSE_Sign1 verified by its Sig_structure (RFC 9052 §4.4),
x5chain (RFC 9360), COSE_Key (RFC 9053 §7.1), the tdate and full-date encodings (RFC 8949 §3.4.1, RFC 8943) and
the IssuerSigned structure of ISO/IEC 18013-5 §8.3.2.1.2.2 and §9.1.2. Written apart from any issuer's code."""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from .jose import verify_with_public_key

ALG, TYP, X5CHAIN = 1, 16, 33
ALGS = {-7: "ES256", -35: "ES384", -36: "ES512"}
DIGESTS = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512}
MDOC_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")  # id-mdl-kp-mdlDS, ISO/IEC 18013-5 Annex B
SIGN1_TAG, ENCODED_CBOR, TDATE, FULL_DATE = 18, 24, 0, 1004
# ISO/IEC 18013-5 §9.1.2.4 (as the PID rulebook repeats it): a tdate has no fraction of a second and ends in Z.
TDATE_FORM = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
FULL_DATE_FORM = re.compile(r"\d{4}-\d{2}-\d{2}")


class CoseError(ValueError):
    pass


CRIT = 2
# The header parameters the probe understands (RFC 9052 §3.1, RFC 9360, RFC 9597, RFC 9596): alg, content type, kid,
# CWT claims, typ, x5chain, x5t and x5u. A message that marks any other critical is refused.
UNDERSTOOD = frozenset({ALG, 3, 4, 15, TYP, X5CHAIN, 34, 35})


@dataclass
class Sign1:
    protected_bytes: bytes
    protected: dict[Any, Any]
    unprotected: dict[Any, Any]
    payload: bytes
    signature: bytes
    tagged: bool

    def header(self, label: int) -> Any:
        return self.protected.get(label, self.unprotected.get(label))

    def chain(self) -> list[x509.Certificate]:
        """The x5chain (label 33), leaf first: one bstr, or an array of them (RFC 9360 §2)."""
        value = self.header(X5CHAIN)
        items = [value] if isinstance(value, bytes) else value
        if not isinstance(items, list) or not items or not all(isinstance(i, bytes) for i in items):
            raise CoseError("no x5chain (label 33) of DER certificates")
        try:
            return [x509.load_der_x509_certificate(i) for i in items]
        except ValueError as exc:
            raise CoseError(f"x5chain does not parse: {exc}") from exc

    def crit_problem(self) -> str | None:
        """Why the critical header parameters (RFC 9052 §3.1) refuse the message, or None."""
        if CRIT in self.unprotected:
            return "crit (2) is in the unprotected header; it belongs in the protected one (RFC 9052 §3.1)"
        if CRIT not in self.protected:
            return None
        listed = self.protected[CRIT]
        if not isinstance(listed, list) or not listed or not all(isinstance(x, (int, str)) for x in listed):
            return f"crit (2) {listed!r} is not a non-empty array of labels"
        missing = [x for x in listed if x not in self.protected]
        if missing:
            return f"crit (2) names {missing!r}, absent from the protected header"
        unknown = [x for x in listed if x not in UNDERSTOOD]
        if unknown:
            return f"crit (2) marks {unknown!r} critical, which the probe does not understand: a recipient refuses it"
        return None

    def verify(self, key: Any) -> None:
        """RFC 9052 §4.4: the signature over ["Signature1", protected, external_aad b"", payload], after the critical
        header parameters (§3.1): a recipient that does not understand one must refuse the message."""
        crit_problem = self.crit_problem()
        if crit_problem is not None:
            raise CoseError(crit_problem)
        label = self.protected.get(ALG)
        alg = ALGS.get(label) if isinstance(label, int) else None
        if alg is None:
            raise CoseError(f"protected alg {self.protected.get(ALG)!r} is not ES256, ES384 or ES512")
        structure = cbor2.dumps(["Signature1", self.protected_bytes, b"", self.payload])
        if not verify_with_public_key(alg, key, structure, self.signature):
            raise CoseError(f"the {alg} signature does not verify")


def sign1(value: Any) -> Sign1:
    tagged = isinstance(value, cbor2.CBORTag)
    if tagged:
        if value.tag != SIGN1_TAG:
            raise CoseError(f"tagged {value.tag}, not COSE_Sign1 (18)")
        value = value.value
    if not isinstance(value, list) or len(value) != 4:
        raise CoseError("not a COSE_Sign1 array of four")
    protected_bytes, unprotected, payload, signature = value
    if not isinstance(protected_bytes, bytes) or not isinstance(unprotected, dict):
        raise CoseError("COSE_Sign1 headers are not a bstr and a map")
    if not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise CoseError("COSE_Sign1 payload or signature is not a bstr (detached payloads are not used here)")
    # The strict reader: a protected header with a repeated label or data after its map is refused (RFC 8949 §5.6).
    protected = decode_raw(protected_bytes) if protected_bytes else {}
    if not isinstance(protected, dict):
        raise CoseError("the protected header is not a map")
    # RFC 9052 §3: a label is an int or a tstr. Python takes true and 1.0 for 1, so they are refused here, before any
    # lookup could read them as alg.
    for bucket, header in (("protected", protected), ("unprotected", unprotected)):
        odd = [label for label in header if not _label(label)]
        if odd:
            raise CoseError(f"{bucket} header labels {odd!r} are not integers or text strings")
    both = sorted(set(protected) & set(unprotected), key=str)
    if both:  # RFC 9052 §3: a label is in one bucket or the other, and a recipient refuses it in both
        raise CoseError(f"header label(s) {both!r} in both the protected and the unprotected header")
    return Sign1(protected_bytes, protected, unprotected, payload, signature, tagged)


def issuer_problems(cert: x509.Certificate, below: int) -> list[str]:
    """RFC 5280 §4.2.1.9, §4.2.1.3, §6.1.4: a certificate that signs another is a CA, may sign certificates when it
    states its key usage, and has no more CA certificates under it than its path length allows (`below`: the CA
    certificates between it and the end-entity one)."""
    name, problems = cert.subject.rfc4514_string(), []
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return [f"{name} signs certificates without basicConstraints"]
    if not constraints.ca:
        return [f"{name} signs certificates but is not a CA"]
    if constraints.path_length is not None and below > constraints.path_length:
        problems.append(f"{name} has {below} CA certificate(s) under it, more than its path length allows")
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        usage = None
    if usage is not None and not usage.key_cert_sign:
        problems.append(f"{name} signs certificates but its key usage lacks keyCertSign")
    return problems


def chain_problems(chain: list[x509.Certificate], at: dt.datetime) -> list[str]:
    """Each certificate signed by the next, which is a CA allowed to sign it, and all valid at `at`."""
    problems = []
    for index, (child, parent) in enumerate(zip(chain, chain[1:], strict=False)):
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature):
            problems.append(f"{child.subject.rfc4514_string()} is not signed by the next certificate")
        problems += issuer_problems(parent, index)
    for cert in chain:
        if not cert.not_valid_before_utc <= at <= cert.not_valid_after_utc:
            problems.append(f"{cert.subject.rfc4514_string()} is not valid now")
    return problems


def has_purpose(cert: x509.Certificate, purpose: x509.ObjectIdentifier) -> bool:
    try:
        usage = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return purpose in usage


def _label(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)) or isinstance(value, str)


def _whole(value: Any, wanted: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == wanted


def cose_key_public(key: Any) -> ec.EllipticCurvePublicKey:
    """An EC2 COSE_Key (RFC 9053 §7.1.1: kty 2, crv 1 to 3, x and y as bstr of the curve's length, leading zeros
    kept) as a public key."""
    curves = {1: (ec.SECP256R1(), 32), 2: (ec.SECP384R1(), 48), 3: (ec.SECP521R1(), 66)}
    if not isinstance(key, dict) or not all(_label(k) for k in key):
        raise CoseError(f"deviceKey is not a COSE_Key map of int or text labels: {key!r}")
    crv = key.get(-1)
    if not _whole(key.get(1), 2) or not any(_whole(crv, c) for c in curves):
        raise CoseError(f"deviceKey is not an EC2 COSE_Key on P-256, P-384 or P-521: {key!r}")
    assert isinstance(crv, int)
    curve, size = curves[crv]
    x, y = key.get(-2), key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != size or len(y) != size:
        raise CoseError(f"deviceKey x and y must be bstr of {size} bytes")
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve).public_key()
    except ValueError as exc:
        raise CoseError(f"deviceKey is not a point of its curve: {exc}") from exc


def tdate(value: Any, name: str) -> dt.datetime:
    """A tdate: tag 0 over the text form, no fraction of a second, Z."""
    if not isinstance(value, cbor2.CBORTag) or value.tag != TDATE:
        raise CoseError(f"{name} is not a tdate (tag 0)")
    if not isinstance(value.value, str) or not TDATE_FORM.fullmatch(value.value):
        raise CoseError(f"{name} {value.value!r} is not YYYY-MM-DDThh:mm:ssZ")
    try:
        return dt.datetime.strptime(value.value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError as exc:
        raise CoseError(f"{name} {value.value!r} is no time of the calendar") from exc


def decode_raw(data: bytes, spans: dict[int, bytes] | None = None) -> Any:
    """CBOR (RFC 8949) with every tag kept as a CBORTag, so tdate, full-date and tag 24 are seen as sent: cbor2's
    own decoder turns tags 0 and 1004 into Python dates and loses their text. One data item, nothing after it."""
    value, end = _item(data, 0, 0, spans)
    if end != len(data):
        raise CoseError("data after the CBOR item")
    return value


BREAK = object()


def _argument(data: bytes, at: int, info: int) -> tuple[int | None, int]:
    if info < 24:
        return info, at
    if info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if at + size > len(data):
            raise CoseError("truncated CBOR")
        return int.from_bytes(data[at : at + size], "big"), at + size
    if info == 31:
        return None, at  # indefinite length
    raise CoseError(f"reserved CBOR additional information {info}")


def _item(data: bytes, at: int, depth: int = 0, spans: dict[int, bytes] | None = None) -> tuple[Any, int]:
    """One data item from `at`, and where it ends. `spans`, when given, gets the bytes each tag came in, by the id
    of its CBORTag: what was sent, not a new encoding of it."""
    begin = at
    if depth > 64:
        raise CoseError("CBOR nested too deep")
    if at >= len(data):
        raise CoseError("truncated CBOR")
    major, info = data[at] >> 5, data[at] & 0x1F
    if major == 7:
        return _simple(data, at + 1, info)
    arg, at = _argument(data, at + 1, info)
    if arg is None and major not in (2, 3, 4, 5):  # RFC 8949 §3.2.4: only strings, arrays and maps go indefinite
        raise CoseError(f"an indefinite length for CBOR major type {major}")
    if major == 0:
        return arg, at
    if major == 1:
        assert arg is not None
        return -1 - arg, at
    if major in (2, 3):
        if arg is None:
            chunks: list[Any] = []
            while data[at : at + 1] != b"\xff":
                # RFC 8949 §3.2.3: each chunk a definite-length string of the same major type.
                if at >= len(data) or data[at] >> 5 != major or data[at] & 0x1F == 31:
                    raise CoseError("a chunk of an indefinite string is not a definite string of its type")
                chunk, at = _item(data, at, depth + 1, spans)
                chunks.append(chunk)
            return (b"".join(chunks) if major == 2 else "".join(chunks)), at + 1
        if at + arg > len(data):
            raise CoseError("truncated CBOR string")
        raw = data[at : at + arg]
        try:
            return (raw if major == 2 else raw.decode("utf-8")), at + arg
        except UnicodeDecodeError as exc:
            raise CoseError("a text string is not UTF-8") from exc
    if major in (4, 5):
        out: Any = [] if major == 4 else {}
        count = 0
        while arg is None or count < arg:
            if arg is None and data[at : at + 1] == b"\xff":
                at += 1
                break
            first, at = _item(data, at, depth + 1, spans)
            if major == 4:
                out.append(first)
            else:
                second, at = _item(data, at, depth + 1, spans)
                try:
                    if first in out:
                        raise CoseError(f"map key {first!r} repeated")
                    out[first] = second
                except TypeError as exc:
                    raise CoseError(f"map key {first!r} cannot be compared") from exc
            count += 1
        return out, at
    assert arg is not None
    inner, at = _item(data, at, depth + 1, spans)
    tag = cbor2.CBORTag(arg, inner)
    if spans is not None:
        spans[id(tag)] = data[begin:at]
    return tag, at


def _simple(data: bytes, at: int, info: int) -> tuple[Any, int]:
    fixed = {20: False, 21: True, 22: None}
    if info in fixed:
        return fixed[info], at
    sizes = {25: ">e", 26: ">f", 27: ">d"}
    if info in sizes:
        size = struct.calcsize(sizes[info])
        if at + size > len(data):
            raise CoseError("truncated CBOR float")
        return struct.unpack(sizes[info], data[at : at + size])[0], at + size
    if info == 31:
        raise CoseError("a break outside an indefinite item")
    raise CoseError(f"CBOR simple value {info} is not used here")


def is_full_date(value: Any) -> bool:
    """RFC 8943: tag 1004 over a YYYY-MM-DD text string that names a day of the calendar."""
    if not isinstance(value, cbor2.CBORTag) or value.tag != FULL_DATE or not isinstance(value.value, str):
        return False
    if FULL_DATE_FORM.fullmatch(value.value) is None:
        return False
    try:
        dt.date.fromisoformat(value.value)
    except ValueError:
        return False
    return True


@dataclass
class Item:
    namespace: str
    encoded: bytes  # the tag-24 data item as sent: what the MSO digests
    digest_id: int
    random: bytes
    name: str
    value: Any


@dataclass
class IssuerSigned:
    items: list[Item]
    auth: Sign1
    mso: dict[Any, Any]


def issuer_signed(data: bytes) -> IssuerSigned:
    """ISO/IEC 18013-5 §8.3.2.1.2.2 IssuerSigned: nameSpaces of tag-24 IssuerSignedItems, and issuerAuth, whose
    payload is the tag-24 MobileSecurityObject (§9.1.2.4)."""
    spans: dict[int, bytes] = {}  # each item's tag 24 as sent: the MSO digests those bytes (§9.1.2.5)
    top = decode_raw(data, spans)
    if not isinstance(top, dict) or set(top) - {"nameSpaces", "issuerAuth"} or "issuerAuth" not in top:
        raise CoseError("not an IssuerSigned map of nameSpaces and issuerAuth")
    spaces = top.get("nameSpaces", {})
    if not isinstance(spaces, dict):
        raise CoseError("nameSpaces is not a map")
    items = []
    for namespace, entries in spaces.items():
        if not isinstance(namespace, str) or not isinstance(entries, list) or not entries:
            raise CoseError(f"nameSpaces[{namespace!r}] is not a non-empty array")
        for entry in entries:
            if not isinstance(entry, cbor2.CBORTag) or entry.tag != ENCODED_CBOR or not isinstance(entry.value, bytes):
                raise CoseError(f"an item of {namespace} is not tag 24 over a bstr")
            item = decode_raw(entry.value)
            if not isinstance(item, dict) or set(item) != {"digestID", "random", "elementIdentifier", "elementValue"}:
                raise CoseError(f"an item of {namespace} is not digestID, random, elementIdentifier, elementValue")
            digest_id, random, name = item["digestID"], item["random"], item["elementIdentifier"]
            if not isinstance(digest_id, int) or digest_id < 0 or isinstance(digest_id, bool):
                raise CoseError(f"{namespace}: digestID {digest_id!r} is not an unsigned integer")
            if not isinstance(random, bytes) or not isinstance(name, str):
                raise CoseError(f"{namespace}: random is not a bstr or elementIdentifier not a tstr")
            items.append(Item(namespace, spans[id(entry)], digest_id, random, name, item["elementValue"]))
    auth = sign1(top["issuerAuth"])
    wrapped = decode_raw(auth.payload)
    if not isinstance(wrapped, cbor2.CBORTag) or wrapped.tag != ENCODED_CBOR or not isinstance(wrapped.value, bytes):
        raise CoseError("the issuerAuth payload is not tag 24 over the MobileSecurityObject")
    mso = decode_raw(wrapped.value)
    if not isinstance(mso, dict):
        raise CoseError("the MobileSecurityObject is not a map")
    return IssuerSigned(items, auth, mso)


def digest(algorithm: str, encoded: bytes) -> bytes:
    if algorithm not in DIGESTS:
        raise CoseError(f"digestAlgorithm {algorithm!r} is not SHA-256, SHA-384 or SHA-512")
    return DIGESTS[algorithm](encoded).digest()
