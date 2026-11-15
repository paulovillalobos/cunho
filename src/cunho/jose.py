"""Strict JOSE helpers: compact JWS parsing, JWK handling, signature checks, X.509 paths.

Only the ECDSA algorithms of the ECCG Agreed Cryptographic Mechanisms used by HAIP are accepted
(ES256, ES384, ES512). Symmetric algorithms and `none` can never verify.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, TypeGuard

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from cunho.rules import implements

JSON = dict[str, Any]

CURVES: dict[str, tuple[str, ec.EllipticCurve, hashes.HashAlgorithm, int]] = {
    "ES256": ("P-256", ec.SECP256R1(), hashes.SHA256(), 32),
    "ES384": ("P-384", ec.SECP384R1(), hashes.SHA384(), 48),
    "ES512": ("P-521", ec.SECP521R1(), hashes.SHA512(), 66),
}
ALGORITHMS = frozenset(CURVES)
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
MAX_JWS = 64 * 1024
MAX_CHAIN = 5
B64U = re.compile(r"[A-Za-z0-9_-]*")
# Extensions this validator understands; any other critical extension makes a certificate unusable
# (RFC 5280 §6.1.4(o)).
KNOWN_CRITICAL = {
    x509.BasicConstraints.oid,
    x509.KeyUsage.oid,
    x509.ExtendedKeyUsage.oid,
    x509.SubjectAlternativeName.oid,
    x509.CertificatePolicies.oid,
    # RFC 5280 §4.2.1.14 and §4.2.1.11: conforming CAs MUST mark these critical (review 4, N4-L3).
    x509.InhibitAnyPolicy.oid,
    x509.PolicyConstraints.oid,
}
# Purposes that belong to other certificate types. A key attestation signer whose extended key usage
# lists only these is some other kind of certificate (review 2, N-L3).
FOREIGN_PURPOSES = {
    ExtendedKeyUsageOID.SERVER_AUTH,
    ExtendedKeyUsageOID.CLIENT_AUTH,
    ExtendedKeyUsageOID.CODE_SIGNING,
    ExtendedKeyUsageOID.EMAIL_PROTECTION,
    ExtendedKeyUsageOID.TIME_STAMPING,
    ExtendedKeyUsageOID.OCSP_SIGNING,
}
# ECCG Agreed Cryptographic Mechanisms v2: the curves and the RSA floor accepted anywhere in a path.
PATH_CURVES = {"secp256r1", "secp384r1", "secp521r1", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"}
RSA_MIN_BITS = 3072
# The hashes a signature in a path, on a CRL or on an OCSP response may use: SHA-256 or stronger, by name. A list
# of the hashes refused let through whatever it did not name, SHA3-224 for one (the security review).
PATH_HASHES = frozenset({"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"})
# A NumericDate cunho accepts lies within +/- 2**53 seconds (the integers a JSON double holds exactly), and a
# JSON integer has at most 20 digits: anything larger is refused before any arithmetic (review 3, N3-M1).
MAX_NUMERIC = 2**53
MAX_INT_DIGITS = 20
# How deep the objects and arrays of a JSON document may nest. Nothing cunho is sent comes near it (the list of
# wallet providers has a lower bound of its own, cunho.lote), and what walks a document afterwards (the checks of
# subject data, the builder of disclosures) recurses a level at a time: a document the parser took at thousands of
# levels ended in a RecursionError far from it (the security review).
MAX_DEPTH = 64
ANY_POLICY = "2.5.29.32.0"


class JoseError(ValueError):
    pass


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: Any) -> bytes:
    """Strict base64url: one alphabet, no padding, no stray bits, so every value has one spelling.

    The whole value is matched: `$` also matches before a final line feed, and a value that ended in one passed the
    check and then failed in the decoder with an error no caller expects (the security review)."""
    if not isinstance(value, str) or not B64U.fullmatch(value) or len(value) % 4 == 1:
        raise JoseError("not base64url")
    # The alphabet and the length are checked, so decoding cannot fail.
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64u(data) != value:
        raise JoseError("non-canonical base64url")
    return data


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())


def sha256_b64u(value: str | bytes) -> str:
    data = value.encode("ascii") if isinstance(value, str) else value
    return b64u(hashlib.sha256(data).digest())


class JsonRefused(ValueError):
    """A document cunho refuses on its own rules. The text is cunho's, never the client's, so it can be shown."""


def _no_constants(name: str) -> Any:
    raise JsonRefused(f"{name} is not valid JSON")  # one of NaN, Infinity and -Infinity


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise JsonRefused("duplicate member name")  # never echo client text (review 2, N-M1)
        out[key] = value
    return out


def _bounded_int(text: str) -> int:
    if len(text.lstrip("-")) > MAX_INT_DIGITS:
        raise JsonRefused("number too large")
    return int(text)


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise JsonRefused("number too large")
    return value


def strict_json(data: bytes | str) -> Any:
    """RFC 8259 JSON without NaN, Infinity, duplicate member names, numbers too large to use or text that is not
    Unicode. Bytes must be UTF-8 (RFC 8259 §8.1): `json.loads` would also take UTF-16 and UTF-32, which no
    system exchanging JSON may send (review 5, N5-L11). Raises ValueError."""
    if isinstance(data, bytes | bytearray):
        data = bytes(data).decode("utf-8")  # strict: UnicodeDecodeError is a ValueError
    try:
        value = json.loads(
            data,
            parse_constant=_no_constants,
            object_pairs_hook=_no_duplicates,
            parse_int=_bounded_int,
            parse_float=_finite_float,
        )
    except RecursionError as exc:
        raise JsonRefused("JSON nested too deeply") from exc
    _no_lone_surrogates(value)
    return value


def _no_lone_surrogates(value: Any) -> None:
    """Every string in a parsed document, member names included, must be encodable as UTF-8, and its objects and
    arrays nest no deeper than MAX_DEPTH.

    The escape `\\ud800` is legal JSON syntax but decodes to a lone UTF-16 surrogate, which is not a Unicode
    character: hashing it, binding it in SQLite or signing it raises later, far from the parser, and every
    caller would have to guard each field on its own (review 4, N4-M1). So the parser refuses it, once, for
    every document a client sends. The walk uses its own stack, so depth cannot exhaust Python's.
    """
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, str):
            if not item.isascii():
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError:
                    raise JsonRefused("a string holds a lone surrogate, which is not Unicode text") from None
        elif isinstance(item, dict | list):
            if depth > MAX_DEPTH:
                raise JsonRefused("JSON nested too deeply")
            inside = [*item, *item.values()] if isinstance(item, dict) else item
            stack.extend((each, depth + 1) for each in inside)


def is_number(value: Any) -> TypeGuard[int | float]:
    """A JSON number usable as a NumericDate (RFC 7519): not a boolean, finite and within +/- 2**53.

    Integers are compared, never passed to `math.isfinite`, which raises OverflowError on a huge integer
    (review 3, N3-M1).
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -MAX_NUMERIC <= value <= MAX_NUMERIC
    return isinstance(value, float) and math.isfinite(value) and -MAX_NUMERIC <= value <= MAX_NUMERIC


@dataclass(frozen=True)
class Jws:
    header: JSON
    payload: JSON
    signing_input: bytes
    signature: bytes


def parse_jws(token: Any, max_size: int = MAX_JWS, understood: frozenset[str] = frozenset()) -> Jws:
    """A compact JWS with JSON header and payload. `understood`: header parameters the caller processes itself, which
    `crit` may name; any other in `crit` is refused (RFC 7515 §4.1.11)."""
    if not isinstance(token, str) or len(token) > max_size or token.count(".") != 2:
        raise JoseError("not a compact JWS")
    head, body, sig = token.split(".")
    try:
        header = strict_json(b64u_decode(head))
        payload = strict_json(b64u_decode(body))
    except JsonRefused as exc:
        raise JoseError(f"header or payload is not valid JSON: {exc}") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        # Fixed text: the decoder's own message quotes bytes and positions of the input (review 5, N5-L11).
        raise JoseError("header or payload is not valid JSON") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JoseError("header and payload must be JSON objects")
    if "crit" in header:
        # RFC 7515 §4.1.11: extensions named in crit must be understood, and be present; a caller names the ones it
        # processes, and by default cunho understands none (review 2, N-L2).
        crit = header["crit"]
        if (
            not isinstance(crit, list)
            or not crit
            or len(set(map(str, crit))) != len(crit)
            or not all(isinstance(name, str) and name in understood and name in header for name in crit)
        ):
            raise JoseError("the crit header is not supported")
    return Jws(header, payload, f"{head}.{body}".encode("ascii"), b64u_decode(sig))


def has_private_members(jwk: JSON) -> bool:
    return bool(PRIVATE_JWK_MEMBERS & set(jwk))


def public_key_from_jwk(jwk: Any, alg: Any) -> ec.EllipticCurvePublicKey:
    if not isinstance(alg, str) or alg not in CURVES:
        raise JoseError("alg must be ES256, ES384 or ES512")
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or has_private_members(jwk):
        raise JoseError("only public EC keys are accepted")
    crv, curve, _, size = CURVES[alg]
    if jwk.get("crv") != crv:
        raise JoseError(f"{alg} needs curve {crv}")
    x, y = b64u_decode(jwk.get("x")), b64u_decode(jwk.get("y"))
    if len(x) != size or len(y) != size:
        raise JoseError("bad coordinate length")
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve).public_key()
    except ValueError as exc:
        raise JoseError("point is not on the curve") from exc


def alg_for_jwk(jwk: Any) -> str:
    """The ES algorithm that matches a JWK's curve."""
    crv = jwk.get("crv") if isinstance(jwk, dict) else None
    for alg, (name, _, _, _) in CURVES.items():
        if name == crv:
            return alg
    raise JoseError("only P-256, P-384 and P-521 keys are accepted")


def canonical_jwk(jwk: Any) -> JSON:
    """Validate a public EC JWK and return it with only kty, crv, x and y, in canonical form."""
    return jwk_from_public_key(public_key_from_jwk(jwk, alg_for_jwk(jwk)))


def jwk_from_public_key(key: ec.EllipticCurvePublicKey) -> JSON:
    for crv, curve, _, size in CURVES.values():
        if key.curve.name == curve.name:
            numbers = key.public_numbers()
            return {
                "kty": "EC",
                "crv": crv,
                "x": b64u(numbers.x.to_bytes(size, "big")),
                "y": b64u(numbers.y.to_bytes(size, "big")),
            }
    raise JoseError("unsupported curve")


def thumbprint(jwk: Any) -> str:
    """RFC 7638 JWK thumbprint of a validated EC public key."""
    members = canonical_jwk(jwk)
    return sha256_b64u(json.dumps(members, separators=(",", ":"), sort_keys=True).encode())


@implements("CRYPTO.ALG_ALLOWLIST_ACM", "CRYPTO.ES256_384_512")
def verify(alg: Any, key: Any, signing_input: bytes, signature: bytes) -> bool:
    if not isinstance(alg, str) or alg not in CURVES or not isinstance(key, ec.EllipticCurvePublicKey):
        return False
    _, curve, digest, size = CURVES[alg]
    if key.curve.name != curve.name or len(signature) != 2 * size:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
    try:
        key.verify(der, signing_input, ec.ECDSA(digest))
    except InvalidSignature:
        return False
    return True


def load_x5c(x5c: Any) -> list[x509.Certificate]:
    if not isinstance(x5c, list) or not x5c or len(x5c) > MAX_CHAIN or not all(isinstance(c, str) for c in x5c):
        raise JoseError(f"x5c must be an array of 1 to {MAX_CHAIN} strings")
    try:
        ders = [base64.b64decode(c, validate=True) for c in x5c]
    except ValueError as exc:  # binascii.Error
        raise JoseError("x5c entry is not a DER certificate") from exc
    return load_der_chain(ders)


def load_der_chain(ders: Sequence[bytes]) -> list[x509.Certificate]:
    """The certificates of a chain given as DER, leaf first: 1 to MAX_CHAIN of them, each read in full. Whatever is
    wrong with one, and whatever the certificate library raises on it, is a JoseError: an x5c header and the x5chain
    of a COSE message are read alike (the security review: the latter caught ValueError alone, and a certificate of
    an invalid version raised past it)."""
    if not 0 < len(ders) <= MAX_CHAIN:
        raise JoseError(f"a certificate chain holds 1 to {MAX_CHAIN} certificates")
    try:
        chain = [x509.load_der_x509_certificate(der) for der in ders]
    except Exception as exc:  # noqa: BLE001 - ValueError, InvalidVersion...: not a certificate
        raise JoseError("x5c entry is not a DER certificate") from exc
    for cert in chain:
        _readable(cert)
    return chain


def _readable(cert: x509.Certificate) -> None:
    """Read every part of a certificate that the path checks use, so one cryptography loads but cannot fully
    parse is refused here as a JoseError instead of raising in the middle of the checks.

    cryptography parses lazily: a duplicate extension raises DuplicateExtension, an extension value that is
    not DER raises ValueError and a key on a curve it does not know raises UnsupportedAlgorithm, none of them
    a JoseError, when the path code first touches that part (review 4, N4-M2).
    """
    try:
        for extension in cert.extensions:
            _ = extension.value
        cert.public_key()
        _ = (cert.signature_hash_algorithm, cert.not_valid_before_utc, cert.not_valid_after_utc)
        _ = (cert.issuer, cert.subject, cert.serial_number)
    except Exception as exc:  # noqa: BLE001 - whatever the library raises, the certificate is unusable
        raise JoseError("x5c entry is a certificate that cannot be fully read") from exc


def is_self_signed(cert: x509.Certificate) -> bool:
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _extension(cert: x509.Certificate, kind: type[x509.ExtensionType]) -> Any:
    try:
        return cert.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


def _check_strength(cert: x509.Certificate, role: str) -> None:
    """Every certificate in the path, the anchor included, uses agreed key sizes and hashes."""
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.name not in PATH_CURVES:
            raise JoseError(f"{role} uses a curve outside the agreed mechanisms")
    elif isinstance(key, rsa.RSAPublicKey):
        if key.key_size < RSA_MIN_BITS:
            raise JoseError(f"{role} has an RSA key shorter than {RSA_MIN_BITS} bits")
    else:
        raise JoseError(f"{role} uses a key type outside the agreed mechanisms")
    if not agreed_hash(cert.signature_hash_algorithm):
        raise JoseError(f"{role} is signed with a hash outside the agreed mechanisms")


def agreed_hash(digest: hashes.HashAlgorithm | None) -> TypeGuard[hashes.HashAlgorithm]:
    """Whether a signature's hash is one of PATH_HASHES; None is a signature with no hash of its own to name."""
    return digest is not None and digest.name in PATH_HASHES


def _check_extensions(cert: x509.Certificate, role: str) -> None:
    for extension in cert.extensions:
        if extension.critical and extension.oid not in KNOWN_CRITICAL:
            # Fixed text: the OID comes from the client's certificate (review 3, N3-L5).
            raise JoseError(f"{role} has an unsupported critical extension")
    if _extension(cert, x509.NameConstraints) is not None:
        raise JoseError(f"{role} carries name constraints, which this validator does not process")


def _check_ca(cert: x509.Certificate, below: int, role: str) -> None:
    """A certificate that signs others: CA flag, keyCertSign and pathLen (RFC 5280 §6.1.4(k)-(n))."""
    constraints = _extension(cert, x509.BasicConstraints)
    if constraints is None or not constraints.ca:
        raise JoseError(f"{role} is not a CA")
    if constraints.path_length is not None and below > constraints.path_length:
        raise JoseError(f"{role} pathLenConstraint is exceeded")
    usage = _extension(cert, x509.KeyUsage)
    if usage is not None and not usage.key_cert_sign:
        raise JoseError(f"{role} key usage does not allow certificate signing")
    purposes = _extension(cert, x509.ExtendedKeyUsage)
    if purposes is not None and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in set(purposes):
        if set(purposes) <= FOREIGN_PURPOSES:
            # An intermediate limited to TLS, code signing and the like cannot vouch for attestation signers
            # (review 3, N3-L9).
            raise JoseError(f"{role} is limited to purposes that do not include attestation signing")


def _check_leaf(cert: x509.Certificate) -> None:
    """The signer profile: an end entity for digital signatures, not a CA, TLS, code or OCSP certificate."""
    constraints = _extension(cert, x509.BasicConstraints)
    if constraints is not None and constraints.ca:
        raise JoseError("the signing certificate is a CA certificate")
    if is_self_signed(cert):
        raise JoseError("leaf certificate is self-signed")
    usage = _extension(cert, x509.KeyUsage)
    if usage is not None and not usage.digital_signature:
        raise JoseError("leaf key usage does not allow digital signatures")
    purposes = _extension(cert, x509.ExtendedKeyUsage)
    if purposes is not None:
        if ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in set(purposes):
            raise JoseError("a certificate for any purpose cannot sign attestations")
        if set(purposes) & FOREIGN_PURPOSES:
            # Any TLS, code, e-mail, time-stamping or OCSP purpose, even next to another one (review 3, N3-L9).
            raise JoseError("a TLS, code, e-mail, time-stamping or OCSP certificate cannot sign attestations")


def _policies(cert: x509.Certificate) -> set[str]:
    held = _extension(cert, x509.CertificatePolicies)
    return {p.policy_identifier.dotted_string for p in held} if held is not None else set()


def _check_policies(chain: list[x509.Certificate], anchor: x509.Certificate, policies: frozenset[str]) -> None:
    """RFC 5280 §6.1.3(d)-(f) with an explicit policy required, kept simple and strict (review 3, N3-L9).

    One of `policies` must hold along the whole path: asserted by every intermediate, or covered by its anyPolicy
    where anyPolicy is not inhibited, and asserted by the leaf itself. For a path without policy mappings this is
    the valid policy tree of §6.1: each certificate can only narrow the policies the path is valid for, and the
    path is refused when none is left. Policy mappings are not processed, so they are refused, and anyPolicy is
    not accepted below a certificate that carries inhibitAnyPolicy. Each certificate used to be checked against
    the deployment's set on its own, so an intermediate for one policy could vouch for a leaf of another (the
    second reviewer's CX-2).
    """
    inhibited = _extension(anchor, x509.InhibitAnyPolicy) is not None
    valid = set(policies)
    for cert in reversed(chain[1:]):  # from the anchor down
        if any(extension.oid == ExtensionOID.POLICY_MAPPINGS for extension in cert.extensions):
            raise JoseError("intermediate maps certificate policies, which this validator does not process")
        names = _policies(cert)
        if ANY_POLICY not in names or inhibited:
            valid &= names
        if not valid:
            raise JoseError("intermediate does not carry the key attestation signer policy")
        inhibited = inhibited or _extension(cert, x509.InhibitAnyPolicy) is not None
    if not valid & _policies(chain[0]):
        raise JoseError("the signer certificate does not carry a key attestation signer policy its path allows")


def _check_revocation(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    crls: Sequence[x509.CertificateRevocationList],
    now: dt.datetime,
    role: str,
) -> None:
    """RFC 5280 §6.1.3(a)(3) with the deployment's CRLs: a current CRL from the issuer must not list `cert`.

    Only complete CRLs signed by the certificate's own issuer are used (no delta or partitioned CRLs, no
    indirect CRLs); the loader refuses the others. Without a usable CRL the status is unknown, which fails
    closed (review 3, N3-M4).

    A file may hold several current CRLs from one issuer, an old copy next to a new one. The newest, by CRL
    number and then by thisUpdate, decides (RFC 5280 §6.3.3), so a certificate it lists is refused whatever
    the reason. An older CRL cannot take a revocation back, so a certificate any current CRL lists as revoked
    is refused too; only a certificateHold that the newest CRL no longer lists is let go (review 4, N4-M6).

    A newer CRL from the issuer that has expired leaves the status unknown: the older ones that are still
    current may say less than it did, so they cannot stand in for it (the second reviewer).
    """
    usage = _extension(issuer, x509.KeyUsage)
    usable: list[x509.CertificateRevocationList] = []
    expired: list[x509.CertificateRevocationList] = []
    for crl in crls:
        if crl.issuer != cert.issuer or (usage is not None and not usage.crl_sign):
            continue
        if not agreed_hash(crl.signature_hash_algorithm):
            continue  # a list signed with a hash a certificate may not use says nothing either
        try:
            if not crl.is_signature_valid(issuer.public_key()):  # type: ignore[arg-type]
                continue
        except (TypeError, ValueError):
            continue
        if crl.next_update_utc is not None and crl.next_update_utc < now:
            expired.append(crl)
        elif crl.next_update_utc is not None and crl.last_update_utc <= now:
            usable.append(crl)
    if not usable:
        raise JoseError(f"no current revocation list covers the {role} certificate")
    newest = max(usable, key=_crl_order)
    if any(_crl_order(crl) > _crl_order(newest) for crl in expired):
        raise JoseError(f"no current revocation list covers the {role} certificate")
    for crl in usable:
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if entry is not None and (crl is newest or _revocation_reason(entry) != x509.ReasonFlags.certificate_hold):
            raise JoseError(f"the {role} certificate is revoked")


class Revocation(Protocol):
    """Where the status of a certificate in a path comes from: the deployment's CRL file (`CrlSet`), or CRLs
    fetched from distribution points and OCSP (`cunho.revocation`). `check` raises JoseError unless `cert`,
    issued by `issuer`, is known not to be revoked at `now`."""

    def check(self, cert: x509.Certificate, issuer: x509.Certificate, now: dt.datetime, role: str) -> None: ...


@dataclass(frozen=True)
class CrlSet:
    """A set of CRLs held in hand, judged as `_check_revocation` does."""

    crls: Sequence[x509.CertificateRevocationList]

    def check(self, cert: x509.Certificate, issuer: x509.Certificate, now: dt.datetime, role: str) -> None:
        _check_revocation(cert, issuer, self.crls, now, role)


def _crl_order(crl: x509.CertificateRevocationList) -> tuple[int, dt.datetime]:
    """Newer CRLs sort higher: by CRL number when the CRL has one, then by thisUpdate."""
    try:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        number = -1
    return number, crl.last_update_utc


def _revocation_reason(entry: x509.RevokedCertificate) -> x509.ReasonFlags | None:
    try:
        return entry.extensions.get_extension_for_class(x509.CRLReason).value.reason
    except x509.ExtensionNotFound:
        return None


def validate_path(
    chain: list[x509.Certificate],
    anchors: list[x509.Certificate],
    now: dt.datetime,
    policies: frozenset[str] = frozenset(),
    crls: Sequence[x509.CertificateRevocationList] | None = None,
    revocation: Revocation | None = None,
) -> None:
    """Check leaf -> intermediates -> one of `anchors` (RFC 5280 §6.1, fail closed). Raises JoseError.

    `policies`: certificate policy OIDs of which the leaf, and every intermediate, must carry one, when the
    deployment sets them. `crls`: the deployment's revocation lists; when given, every certificate below
    the anchor must be covered by a current one. `revocation`: another source of that status, in place of
    `crls`. With neither, revocation is not checked (startup warns).

    Any exception the certificate library raises on the way, for a certificate or CRL that `load_x5c` and the
    CRL loader did not see (an anchor, say), is a refusal too, never an error of its own (review 4, N4-M2).
    """
    if crls is not None and revocation is not None:
        raise ValueError("give the CRLs or another revocation source, not both")
    try:
        _validate_path(chain, anchors, now, policies, CrlSet(crls) if crls is not None else revocation)
    except JoseError:
        raise
    except Exception as exc:  # noqa: BLE001 - a certificate that cannot be processed is not a trusted one
        raise JoseError("a certificate in the path cannot be processed") from exc


def _validate_path(
    chain: list[x509.Certificate],
    anchors: list[x509.Certificate],
    now: dt.datetime,
    policies: frozenset[str],
    revocation: Revocation | None,
) -> None:
    if not anchors:
        raise JoseError("no trust anchors configured")
    if not chain or len(chain) > MAX_CHAIN:
        raise JoseError("certificate chain is empty or too long")
    if len(chain) > 1 and any(chain[-1] == anchor for anchor in anchors):
        chain = chain[:-1]  # a sender may include the anchor; it is matched below, not trusted from the chain
    for index, cert in enumerate(chain):
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise JoseError("certificate outside its validity period")
        _check_extensions(cert, "leaf" if index == 0 else "intermediate")
        _check_strength(cert, "leaf" if index == 0 else "intermediate")
    _check_leaf(chain[0])
    for position, (child, parent) in enumerate(zip(chain, chain[1:], strict=False)):
        _check_ca(parent, position, "intermediate")
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise JoseError("broken certificate chain") from exc
    # Several anchors may hold the key that signed the top of the chain: an expired root listed next to its
    # renewed copy during a rollover, for example. Each is tried in turn; the path is refused, with the first
    # anchor's reason, only when none of them passes (review 4, N4-L6).
    problem: JoseError | None = None
    for anchor in anchors:
        try:
            chain[-1].verify_directly_issued_by(anchor)
        except (ValueError, TypeError, InvalidSignature):
            continue
        try:
            _check_anchor(chain, anchor, now, policies, revocation)
        except JoseError as exc:
            problem = problem or exc
            continue
        return
    raise problem or JoseError("chain does not end at a trusted anchor")


def _check_anchor(
    chain: list[x509.Certificate],
    anchor: x509.Certificate,
    now: dt.datetime,
    policies: frozenset[str],
    revocation: Revocation | None,
) -> None:
    """The checks that depend on which anchor the chain ends at: the anchor itself, policies and revocation."""
    if not anchor.not_valid_before_utc <= now <= anchor.not_valid_after_utc:
        raise JoseError("trust anchor outside its validity period")
    _check_extensions(anchor, "trust anchor")
    _check_strength(anchor, "trust anchor")
    _check_ca(anchor, len(chain) - 1, "trust anchor")
    for cert in [*chain, anchor]:
        constraints = _extension(cert, x509.PolicyConstraints)
        if constraints is not None and constraints.require_explicit_policy is not None and not policies:
            # Policy mappings are refused anyway, so inhibitPolicyMapping always holds; an explicit policy can
            # only be required when the deployment names the policies it accepts (review 4, N4-L3).
            raise JoseError("a certificate in the path requires an explicit policy, and none is configured")
    if policies:
        _check_policies(chain, anchor, policies)
    if revocation is not None:
        issuers = [*chain[1:], anchor]
        for index, (cert, issuer) in enumerate(zip(chain, issuers, strict=True)):
            revocation.check(cert, issuer, now, "leaf" if index == 0 else "intermediate")
