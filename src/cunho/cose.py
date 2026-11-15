"""Strict CBOR and COSE helpers for mdoc: deterministic encoding, the tags mdoc uses, COSE_Sign1 and COSE_Key.

Encoding follows the core deterministic rules of RFC 8949 §4.2.1: preferred serialisation (cbor2 always writes the
shortest integer and definite lengths), and map keys sorted by the bytewise order of their encodings. Floats and
Python dates are refused, so every date goes through `tdate` or `full_date` and its exact text is the one signed.

COSE_Sign1 (RFC 9052 §4.2) is signed through a `Signer`, whose ECDSA signatures are already the raw r || s COSE
wants (RFC 9053 §2.1). Only ES256, ES384 and ES512 verify, as for JOSE.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import re
from collections.abc import Callable
from typing import Any, TypeGuard

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from cunho.jose import CURVES, JSON, JoseError, b64u_decode
from cunho.signer import Signer

# COSE algorithm values (RFC 9053 §2.1) for the JOSE names the signers use.
ALGORITHMS = {"ES256": -7, "ES384": -35, "ES512": -36}
ALGORITHM_NAMES = {value: name for name, value in ALGORITHMS.items()}
SHA256 = -16  # RFC 9054 §2.1

# Header labels: RFC 9052 §3.1 and RFC 9360 §2.
ALG = 1
CRIT = 2
KID = 4
TYP = 16  # RFC 9596 §2
X5CHAIN = 33
X5T = 34
X5U = 35
CWT_CLAIMS = 15  # RFC 9597 §2
IAT = 6  # RFC 8392 §3.1.6, inside CWT_CLAIMS
KNOWN_HEADERS = frozenset({ALG, CRIT, KID, TYP, X5CHAIN, X5T, X5U})

# COSE_Key (RFC 9052 §7.1, RFC 9053 §7.1.1).
KTY, KTY_EC2, CRV, X, Y, D = 1, 2, -1, -2, -3, -4
COSE_CURVES = {"P-256": 1, "P-384": 2, "P-521": 3}
CURVE_NAMES = {value: name for name, value in COSE_CURVES.items()}

TDATE = 0  # RFC 8949 §3.4.1, date/time string
ENCODED_CBOR = 24  # RFC 8949 §3.4.5.1
FULL_DATE = 1004  # RFC 8943 §3
SIGN1 = 18  # RFC 9052 §2
FULL_DATE_TEXT = re.compile(r"\d{4}-\d{2}-\d{2}")


class CoseError(ValueError):
    """CBOR or COSE input that is not what this module accepts."""


def encode(value: Any) -> bytes:
    """The deterministic encoding of `value` (RFC 8949 §4.2.1)."""
    return cbor2.dumps(_ordered(value))


def _ordered(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, int | str | bytes):
        return value
    if isinstance(value, list | tuple):
        return [_ordered(item) for item in value]
    if isinstance(value, dict | cbor2.frozendict):
        items = [(cbor2.dumps(_ordered(key)), _hashable(_ordered(key)), _ordered(item)) for key, item in value.items()]
        # Distinct keys can share an encoding: 2**64 is written as the bignum #6.2(h'010000000000000000').
        if len({encoded for encoded, _, _ in items}) != len(items):
            raise CoseError("a map has two keys with the same encoding")
        return {key: item for _, key, item in sorted(items, key=lambda entry: entry[0])}
    if isinstance(value, cbor2.CBORTag):
        return cbor2.CBORTag(value.tag, _ordered(value.value))
    raise CoseError(f"{type(value).__name__} has no deterministic encoding here")


def _hashable(key: Any) -> Any:
    # An array or a map as a map key, tagged or not, stays a tuple or a frozendict, which cbor2 writes as the same
    # array or map.
    if isinstance(key, list):
        return tuple(_hashable(item) for item in key)
    if isinstance(key, dict):
        return cbor2.frozendict({k: _hashable(v) for k, v in key.items()})
    if isinstance(key, cbor2.CBORTag):
        return cbor2.CBORTag(key.tag, _hashable(key.value))
    return key


def embed(value: Any) -> cbor2.CBORTag:
    """`#6.24(bstr .cbor value)`: the encoded value inside a byte string, as mdoc signs and digests it."""
    return cbor2.CBORTag(ENCODED_CBOR, encode(value))


def issuer_signed_item(digest_id: int, random: bytes, name: str, value: Any) -> cbor2.CBORTag:
    """IssuerSignedItemBytes with its four keys in the order ISO/IEC 18013-5 §8.3.2.1.2.2 lists them (digestID,
    random, elementIdentifier, elementValue) and the value itself deterministic. Length-first order is valid CBOR too,
    but verifiers that re-encode the decoded item before hashing (NL Wallet) only match the ISO order."""
    item = {"digestID": digest_id, "random": random, "elementIdentifier": name, "elementValue": _ordered(value)}
    return cbor2.CBORTag(ENCODED_CBOR, cbor2.dumps(item))


def tdate(at: float) -> cbor2.CBORTag:
    """`#6.0(tstr)` for a whole second in UTC, without fractions and with the offset `Z`."""
    moment = dt.datetime.fromtimestamp(int(at), dt.UTC)
    return cbor2.CBORTag(TDATE, moment.strftime("%Y-%m-%dT%H:%M:%SZ"))


def full_date(text: str) -> cbor2.CBORTag:
    """`#6.1004(tstr)` for a calendar date `YYYY-MM-DD` (RFC 8943)."""
    if not isinstance(text, str) or not FULL_DATE_TEXT.fullmatch(text):
        raise CoseError("a full-date is YYYY-MM-DD")
    try:
        dt.date.fromisoformat(text)
    except ValueError as exc:
        raise CoseError(f"{text!r} is not a calendar date") from exc
    return cbor2.CBORTag(FULL_DATE, text)


def cose_key(jwk: JSON) -> dict[int, Any]:
    """The COSE_Key of a public EC JWK."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or not isinstance(jwk.get("crv"), str) or "d" in jwk:
        raise CoseError("only public EC keys on P-256, P-384 or P-521 convert")
    if jwk["crv"] not in COSE_CURVES:
        raise CoseError("only public EC keys on P-256, P-384 or P-521 convert")
    size = _coordinate_size(jwk["crv"])
    try:
        x, y = (b64u_decode(jwk.get(member)) for member in ("x", "y"))
    except JoseError as exc:
        raise CoseError("the key's coordinates are not base64url") from exc
    if len(x) != size or len(y) != size:
        raise CoseError("the key's coordinates have the wrong length")
    return {KTY: KTY_EC2, CRV: COSE_CURVES[jwk["crv"]], X: x, Y: y}


def public_key(key: Any) -> ec.EllipticCurvePublicKey:
    """The public key of an EC2 COSE_Key; a private key, compressed point or other shape is refused."""
    if not isinstance(key, dict) or not _labels(key) or not _integer(key.get(KTY)) or not _integer(key.get(CRV)):
        raise CoseError("not a public EC2 COSE_Key on P-256, P-384 or P-521")
    if D in key:
        raise CoseError("not a public EC2 COSE_Key on P-256, P-384 or P-521")
    if key[KTY] != KTY_EC2 or key[CRV] not in CURVE_NAMES:
        raise CoseError("not a public EC2 COSE_Key on P-256, P-384 or P-521")
    curve = CURVE_NAMES[key[CRV]]
    size = _coordinate_size(curve)
    x, y = key.get(X), key.get(Y)
    if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != size or len(y) != size:
        raise CoseError("the key's coordinates are not byte strings of the curve's size")
    numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(x), int.from_bytes(y), _curve(curve))
    try:
        return numbers.public_key()
    except ValueError as exc:
        raise CoseError("the point is not on the curve") from exc


def x5chain(certificates: list[bytes]) -> bytes | list[bytes]:
    """The x5chain value: one certificate as a byte string, more as an array, leaf first (RFC 9360 §2)."""
    if not certificates:
        raise CoseError("an x5chain needs a certificate")
    return certificates[0] if len(certificates) == 1 else list(certificates)


def x5chain_certificates(value: Any) -> list[bytes]:
    """The DER certificates of an x5chain value, leaf first."""
    chain = [value] if isinstance(value, bytes) else value
    if not isinstance(chain, list) or not chain or not all(isinstance(der, bytes) and der for der in chain):
        raise CoseError("x5chain is a byte string or a non-empty array of byte strings")
    return chain


def x5t(certificate: bytes) -> list[Any]:
    """The x5t value: the SHA-256 thumbprint of the DER certificate (RFC 9360 §2)."""
    return [SHA256, hashlib.sha256(certificate).digest()]


def sign1(signer: Signer, payload: bytes, protected: dict[int, Any], unprotected: dict[int, Any]) -> list[Any]:
    """An untagged COSE_Sign1 over `payload`, with `alg` in the protected header taken from the signer."""
    if signer.alg not in ALGORITHMS:
        raise CoseError(f"{signer.alg} has no COSE value here")
    if ALG in protected or ALG in unprotected:
        raise CoseError("alg comes from the signer")
    header = encode({ALG: ALGORITHMS[signer.alg], **protected})
    return [header, dict(unprotected), payload, signer.sign(_to_be_signed(header, payload))]


def verify1(message: Any, key: ec.EllipticCurvePublicKey) -> tuple[dict[Any, Any], dict[Any, Any], bytes]:
    """Check a COSE_Sign1 (tagged or not) under `key`: its protected header, unprotected header and payload.

    `alg` must be in the protected header, name ES256, ES384 or ES512 and match the key's curve. A header label in
    both buckets, `crit`, or any label this module does not know in the protected header is refused, since a
    verifier must understand what is integrity-protected (RFC 9052 §3).
    """
    if isinstance(message, cbor2.CBORTag):
        if message.tag != SIGN1:
            raise CoseError(f"tag {message.tag} is not COSE_Sign1")
        message = message.value
    if not isinstance(message, list) or len(message) != 4:
        raise CoseError("a COSE_Sign1 is an array of four")
    header, unprotected, payload, signature = message
    if not isinstance(header, bytes) or not isinstance(unprotected, dict):
        raise CoseError("the protected header is a byte string and the unprotected one a map")
    if not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise CoseError("the payload and the signature are byte strings")
    protected = decode(header) if header else {}
    if not isinstance(protected, dict):
        raise CoseError("the protected header is a map")
    if not _labels(protected) or not _labels(unprotected):
        raise CoseError("a header label is not an integer or a text string")
    if set(protected) & set(unprotected):
        raise CoseError("a header label is in both buckets")
    if CRIT in protected or CRIT in unprotected or not set(protected) <= KNOWN_HEADERS:
        raise CoseError("the protected header has a parameter this verifier does not understand")
    alg = protected.get(ALG)
    name = ALGORITHM_NAMES.get(alg) if _integer(alg) else None
    if name is None:
        raise CoseError("alg is not ES256, ES384 or ES512 in the protected header")
    _, curve, digest, size = CURVES[name]
    if key.curve.name != curve.name:
        raise CoseError(f"{name} does not match the key's curve")
    if len(signature) != 2 * size:
        raise CoseError("the signature has the wrong length")
    der = encode_dss_signature(int.from_bytes(signature[:size]), int.from_bytes(signature[size:]))
    try:
        key.verify(der, _to_be_signed(header, payload), ec.ECDSA(digest))
    except InvalidSignature as exc:
        raise CoseError("the signature does not verify") from exc
    return protected, unprotected, payload


def decode(data: bytes) -> Any:
    """One well-formed CBOR item and nothing after it: no duplicate map keys, no indefinite lengths, at most
    MAX_DEPTH levels. Every tag stays a CBORTag with its value as encoded, so a date reads back as the text that
    was signed, never as a Python date."""
    if not isinstance(data, bytes):
        raise CoseError("CBOR comes as bytes")
    stream = io.BytesIO(data)
    decoder = cbor2.CBORDecoder(
        stream,
        semantic_decoders=RAW_TAGS,
        max_depth=MAX_DEPTH,
        allow_indefinite=False,
        allow_duplicate_keys=False,
    )
    try:
        value = decoder.decode()
    except (cbor2.CBORDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise CoseError(f"not CBOR: {exc}") from exc
    if stream.tell() != len(data):
        raise CoseError("bytes follow the CBOR item")
    return _thaw(value)


def _thaw(value: Any) -> Any:
    # cbor2 decodes inside a tag, and map keys, as immutable tuples and frozendicts; lists and dicts read the same
    # everywhere. Map keys stay as decoded, since they must stay hashable.
    if isinstance(value, list | tuple):
        return [_thaw(item) for item in value]
    if isinstance(value, dict | cbor2.frozendict):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, cbor2.CBORTag):
        return cbor2.CBORTag(value.tag, _thaw(value.value))
    return value


def _raw(tag: int) -> Callable[[Any, bool], cbor2.CBORTag]:
    return lambda value, _immutable: cbor2.CBORTag(tag, value)


# The tags cbor2 would turn into Python objects (dates, numbers, sets, ...), kept as tags instead.
RAW_TAGS = {
    tag: _raw(tag)
    for tag in (0, 1, 2, 3, 4, 5, 25, 28, 29, 30, 35, 36, 37, 52, 54, 100, 256, 258, 260, 261, 1004, 43000, 55799)
}
MAX_DEPTH = 32


def _integer(value: Any) -> TypeGuard[int]:
    # A COSE discriminator is an integer; True and -7.0 compare equal to 1 and -7 in Python and must not pass.
    return isinstance(value, int) and not isinstance(value, bool)


def _labels(entries: dict[Any, Any]) -> bool:
    # COSE labels are integers or text strings (RFC 9052 §1.5). A boolean or float key compares equal to an integer
    # in Python, so {True: -7} would otherwise read as an alg.
    return all(_integer(label) or isinstance(label, str) for label in entries)


def _to_be_signed(header: bytes, payload: bytes) -> bytes:
    # Sig_structure (RFC 9052 §4.4), with no external data.
    return encode(["Signature1", header, b"", payload])


def _coordinate_size(curve: str) -> int:
    return next(size for name, _, _, size in CURVES.values() if name == curve)


def _curve(curve: str) -> ec.EllipticCurve:
    return next(c for name, c, _, _ in CURVES.values() if name == curve)
