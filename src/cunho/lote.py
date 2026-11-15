"""The Commission's list of wallet providers (ETSI TS 119 602 V1.1.1, Annex E), read as the source of the wallet
providers' trust anchors (TRUST.LOTE_PARSER_119602, TRUST.LOTE_AUTHENTIC, TRUST.WP_ANCHORS_FROM_LIST; ARF ISSU_19,
ISSU_19b, ISSU_28, ISSU_28a).

The list is the JSON binding of TS 119 602 Annex A (`{"LoTE": {"ListAndSchemeInformation": ..., "TrustedEntitiesList":
...}}`), signed as a compact JAdES baseline B signature that carries it as its payload (Annex E.4). `read_lote`
accepts it only if:

- the signature verifies under the signer certificate the operator pinned (the one the Commission publishes in the
  Official Journal), named by `x5c` or `x5t#S256` byte for byte, with no chain built; the certificate is valid now, and
  its subject's country and organisation are the scheme territory and one of the scheme operator's names (§6.8.0);
- `crit` names only `sigT`, a signing time not ahead of now, and the payload is attached (no `b64` false);
- it is version 1 of the wallet providers list type, for territory EU, its issue time not ahead of now, its next update
  still ahead (§6.3.15: a list past it is discarded) and at most six months after its issue (Annex E.2);
- it is strict JSON within MAX_LOTE bytes and MAX_DEPTH levels, every member the schema closes is known, and every
  certificate in it can be read in full.

A WalletSolution/Issuance service's certificates become anchors for wallet and key attestation signers, a
WalletSolution/Revocation service's for wallet providers' status list signers (Annex E.3). A service with any other
type, or with a ServiceStatus, which the profile forbids, is trusted for nothing. `LoteFile` reads the list from a file
the operator keeps current, again whenever it changes, and refuses a list whose sequence number is lower than the
highest seen, kept in the store, so an older list put back cannot bring back a withdrawn wallet solution.
"""

from __future__ import annotations

import base64
import binascii
import calendar
import datetime as dt
import hashlib
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from cunho.errors import ConfigError
from cunho.jose import ALGORITHMS, JoseError, _readable, b64u, parse_jws, verify
from cunho.rules import implements
from cunho.store import Store

LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"
ISSUANCE = "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance"
REVOCATION = "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation"
MAX_LOTE = 4 * 1024 * 1024
MAX_DEPTH = 32
SKEW = dt.timedelta(seconds=60)
RETRY = 60  # seconds before a read of the list file that failed is tried again
DATE_TIME = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")  # §6.1.3: UTC, whole seconds, "Z"


class LoteError(Exception):
    """A list cunho will not take its anchors from. Fixed text: the list comes from outside."""


@dataclass(frozen=True)
class TrustedList:
    sequence: int
    next_update: dt.datetime
    issuance: list[x509.Certificate]  # anchors of wallet and key attestation signers
    revocation: list[x509.Certificate]  # anchors of wallet providers' status list signers


def _depth(value: Any) -> int:
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if level > MAX_DEPTH:
            break
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        stack.extend((child, level + 1) for child in children)
    return deepest


def _time(value: Any, name: str) -> dt.datetime:
    if not isinstance(value, str) or not DATE_TIME.match(value):
        raise LoteError(f"the list's {name} is not a UTC date-time in whole seconds")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError as exc:
        raise LoteError(f"the list's {name} is not a UTC date-time in whole seconds") from exc


def six_months_after(at: dt.datetime) -> dt.datetime:
    """The same day and time six calendar months on, or the last day of that month when it is shorter (Annex E.2:
    the next update is at most six months after the issue; the second reviewer)."""
    month = at.month + 6
    year, month = at.year + (month - 1) // 12, (month - 1) % 12 + 1
    return at.replace(year=year, month=month, day=min(at.day, calendar.monthrange(year, month)[1]))


def _object(value: Any, name: str, known: set[str]) -> dict[str, Any]:
    """A JSON object whose members are all ones the schema names (it closes every object cunho reads)."""
    if not isinstance(value, dict):
        raise LoteError(f"the list's {name} is not an object")
    if not set(value) <= known:
        raise LoteError(f"the list's {name} has a member the schema does not allow")
    return value


def _texts(value: Any, name: str) -> list[str]:
    """The texts of a sequence of multilingual strings (§6.1.4): `[{"lang": ..., "value": ...}]`."""
    if not isinstance(value, list) or not value:
        raise LoteError(f"the list's {name} is not a sequence of multilingual strings")
    texts = []
    for item in value:
        entry = _object(item, name, {"lang", "value"})
        if not isinstance(entry.get("lang"), str) or not isinstance(entry.get("value"), str):
            raise LoteError(f"the list's {name} is not a sequence of multilingual strings")
        texts.append(entry["value"])
    return texts


def _certificates(identity: Any) -> list[x509.Certificate]:
    """The certificates of a ServiceDigitalIdentity: `{"X509Certificates": [{"val": <base64 DER>}]}`, each read in
    full. Other identifiers (subject names, key identifiers) give no anchor."""
    known = {"X509Certificates", "X509SubjectNames", "PublicKeyValues", "X509SKIs", "OtherIds"}
    listed = _object(identity, "ServiceDigitalIdentity", known).get("X509Certificates", [])
    if not isinstance(listed, list):
        raise LoteError("the list's X509Certificates is not a sequence")
    certificates = []
    for item in listed:
        entry = _object(item, "X509Certificates entry", {"val", "encoding", "specRef"})
        try:
            der = base64.b64decode(entry.get("val"), validate=True)  # type: ignore[arg-type]
            certificate = x509.load_der_x509_certificate(der)
            _readable(certificate)
        except Exception as exc:  # noqa: BLE001 - InvalidVersion and the like: whatever the library raises (N4-M2)
            raise LoteError("the list holds a certificate that cannot be read") from exc
        certificates.append(certificate)
    return certificates


def _signer_names(signer: x509.Certificate, attribute: x509.ObjectIdentifier) -> list[str]:
    return [str(a.value) for a in signer.subject.get_attributes_for_oid(attribute)]


@implements("TRUST.LOTE_PARSER_119602", "TRUST.LOTE_AUTHENTIC", "TRUST.WP_ANCHORS_FROM_LIST")
def read_lote(data: bytes, signer: x509.Certificate, now: dt.datetime) -> TrustedList:
    """The anchors of a signed wallet providers list, or LoteError (see the module docstring)."""
    if len(data) > MAX_LOTE:
        raise LoteError("the list is larger than allowed")
    try:
        token = parse_jws(data.decode("ascii").strip(), MAX_LOTE, frozenset({"sigT"}))
    except (JoseError, UnicodeDecodeError) as exc:
        raise LoteError("the list is not a compact JWS cunho can read") from exc
    header, payload = token.header, token.payload
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in ALGORITHMS:
        raise LoteError("the list is signed with an algorithm cunho does not accept")
    if "b64" in header and header["b64"] is not True:
        raise LoteError("the list's payload is not attached")
    pinned = signer.public_bytes(serialization.Encoding.DER)
    named = False
    if "x5c" in header:
        x5c = header["x5c"]
        if not isinstance(x5c, list) or not x5c or not isinstance(x5c[0], str):
            raise LoteError("the list is not signed by the pinned signer")
        try:
            sent = base64.b64decode(x5c[0], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise LoteError("the list is not signed by the pinned signer") from exc
        if sent != pinned:
            raise LoteError("the list is not signed by the pinned signer")
        named = True
    if "x5t#S256" in header:
        if header["x5t#S256"] != b64u(hashlib.sha256(pinned).digest()):
            raise LoteError("the list is not signed by the pinned signer")
        named = True
    if not named:
        raise LoteError("the list names no signer certificate")
    if not signer.not_valid_before_utc <= now <= signer.not_valid_after_utc:
        raise LoteError("the pinned signer certificate is outside its validity period")
    if not verify(alg, signer.public_key(), token.signing_input, token.signature):
        raise LoteError("the list's signature does not verify under the pinned signer")
    if "sigT" in header and _time(header["sigT"], "signing time") > now + SKEW:
        raise LoteError("the list's signing time is in the future")
    if _depth(payload) > MAX_DEPTH:
        raise LoteError("the list is nested too deeply")
    return _content(payload, signer, now)


def _content(payload: dict[str, Any], signer: x509.Certificate, now: dt.datetime) -> TrustedList:
    lote = _object(
        _object(payload, "root", {"LoTE"}).get("LoTE"), "LoTE", {"ListAndSchemeInformation", "TrustedEntitiesList"}
    )
    scheme_members = {
        "LoTEVersionIdentifier", "LoTESequenceNumber", "LoTEType", "SchemeOperatorName", "SchemeOperatorAddress",
        "SchemeName", "SchemeInformationURI", "StatusDeterminationApproach", "SchemeTypeCommunityRules",
        "SchemeTerritory", "PolicyOrLegalNotice", "HistoricalInformationPeriod", "PointersToOtherLoTE",
        "ListIssueDateTime", "NextUpdate", "DistributionPoints", "SchemeExtensions",
    }  # fmt: skip
    scheme = _object(lote.get("ListAndSchemeInformation"), "ListAndSchemeInformation", scheme_members)
    version, sequence = scheme.get("LoTEVersionIdentifier"), scheme.get("LoTESequenceNumber")
    if version != 1 or isinstance(version, bool):
        raise LoteError("the list is not version 1 of a list of trusted entities")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise LoteError("the list's sequence number is not a whole number from 1")
    if scheme.get("LoTEType") != LOTE_TYPE:
        raise LoteError("the list is not the wallet providers list")
    if scheme.get("SchemeTerritory") != "EU":
        raise LoteError("the list's scheme territory is not EU")
    operators = _texts(scheme.get("SchemeOperatorName"), "SchemeOperatorName")
    if _signer_names(signer, NameOID.COUNTRY_NAME) != ["EU"] or not (
        set(_signer_names(signer, NameOID.ORGANIZATION_NAME)) & set(operators)
    ):
        raise LoteError("the pinned signer is not the scheme operator of this list")
    issued = _time(scheme.get("ListIssueDateTime"), "issue date-time")
    next_update = _time(scheme.get("NextUpdate"), "next update")
    if issued > now + SKEW:
        raise LoteError("the list's issue date-time is in the future")
    if next_update <= now:
        raise LoteError("the list's next update has passed: the list is discarded as expired")
    if next_update > six_months_after(issued):
        raise LoteError("the list's next update is more than six months after its issue")
    issuance: list[x509.Certificate] = []
    revocation: list[x509.Certificate] = []
    entities = lote.get("TrustedEntitiesList", [])
    if not isinstance(entities, list):
        raise LoteError("the list's TrustedEntitiesList is not a sequence")
    for entity in entities:
        services = _object(entity, "TrustedEntity", {"TrustedEntityInformation", "TrustedEntityServices"})
        listed = services.get("TrustedEntityServices")
        if not isinstance(listed, list):
            raise LoteError("the list's TrustedEntityServices is not a sequence")
        for service in listed:
            entry = _object(service, "TrustedEntityService", {"ServiceInformation", "ServiceHistory"})
            information = _object(
                entry.get("ServiceInformation"),
                "ServiceInformation",
                {
                    "ServiceName", "ServiceDigitalIdentity", "ServiceTypeIdentifier", "ServiceStatus",
                    "StatusStartingTime", "SchemeServiceDefinitionURI", "ServiceSupplyPoints",
                    "ServiceDefinitionURI", "ServiceInformationExtensions",
                },
            )  # fmt: skip
            certificates = _certificates(information.get("ServiceDigitalIdentity"))
            if "ServiceStatus" in information:
                continue  # Annex E.3: the profile does not use it, so a service that has one is trusted for nothing
            kind = information.get("ServiceTypeIdentifier")
            if kind == ISSUANCE:
                issuance.extend(certificates)
            elif kind == REVOCATION:
                revocation.extend(certificates)
    return TrustedList(sequence, next_update, issuance, revocation)


class LoteFile:
    """The wallet providers list in a file the operator keeps current (decision 4: an operator job fetches it, as
    for the CRLs). Read again whenever the file changes. `current` gives the list in force, or None: a list that
    cannot be used, or whose next update has passed since it was read, leaves no anchors, so trust fails closed."""

    def __init__(self, path: Path, signer: x509.Certificate, store: Store, clock: Callable[[], float]) -> None:
        self._path = path
        self._signer = signer
        self._store = store
        self._clock = clock
        self._lock = threading.Lock()
        self._retry_at: float | None = None  # when a read that failed is tried again, the file unchanged
        self._list: TrustedList | None = None
        # The stamp is taken before the read, so a file replaced during it is read again at the next use instead of
        # its old content standing under the new stamp (the second reviewer).
        self._stamp = self._current_stamp()
        try:
            self._list = self._read()
        except Exception as exc:  # noqa: BLE001 - whatever stops the read, the list cannot be used
            raise ConfigError(f"cannot use the wallet providers list in {path}: {exc}") from exc

    def _current_stamp(self) -> tuple[int, int, int] | None:
        """The file's inode, modification time and size, as for the CRL file (cunho.proofs.CrlFile)."""
        try:
            status = self._path.stat()
        except OSError:
            return None
        return status.st_ino, status.st_mtime_ns, status.st_size

    def _read(self) -> TrustedList:
        now = dt.datetime.fromtimestamp(self._clock(), dt.UTC)
        # No more than the cap and one byte, however large the file (the second reviewer).
        with self._path.open("rb") as file:
            data = file.read(MAX_LOTE + 1)
        read = read_lote(data, self._signer, now)
        with self._store.atomic():
            highest = self._store.get("lote-sequence", "wallet-providers")
            if isinstance(highest, int) and read.sequence < highest:
                raise LoteError("the list's sequence number is lower than one already seen")
            if not isinstance(highest, int) or read.sequence > highest:
                self._store.put("lote-sequence", "wallet-providers", read.sequence, None)
        return read

    def current(self) -> TrustedList | None:
        stamp = self._current_stamp()
        with self._lock:
            retry = self._retry_at is not None and self._clock() >= self._retry_at
            if stamp != self._stamp or retry:
                self._stamp = stamp
                try:
                    self._list = self._read()
                    self._retry_at = None
                except Exception:  # noqa: BLE001 - whatever stops the read leaves no list in hand (the second reviewer)
                    # A failure may pass (a store lock that timed out), so the same file is tried again, at most once
                    # a RETRY, and gives no anchors meanwhile (the second reviewer).
                    self._list = None
                    self._retry_at = self._clock() + RETRY
            listed = self._list
        now = dt.datetime.fromtimestamp(self._clock(), dt.UTC)
        if listed is None or listed.next_update <= now:
            return None
        if not self._signer.not_valid_before_utc <= now <= self._signer.not_valid_after_utc:
            return None
        highest = self._store.get("lote-sequence", "wallet-providers")
        if isinstance(highest, int) and listed.sequence < highest:
            # Another worker took a newer list: this one's is superseded, whatever its file's stamp says, so it gives
            # no anchors until the file is read again (the second reviewer).
            with self._lock:
                self._stamp = None
            return None
        return listed
