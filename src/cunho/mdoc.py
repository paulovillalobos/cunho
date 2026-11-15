"""ISO/IEC mdoc credentials (OpenID4VCI 1.0 App. A.2): an IssuerSigned structure with its Mobile Security Object,
signed by the document signer.

Subject data for an mdoc configuration is a JSON object of namespaces, each an object of data elements named by the
configuration's claim paths, `[namespace, element]`. Each element becomes an IssuerSignedItem with its own random salt
and a digest id drawn at random, so neither the order nor the number of elements can be read from the ids; the MSO
holds the SHA-256 digest of each item, the holder's device key, the document type, the validity and the status list
reference (ETSI TS 119 472-1 EAA-6.2.10.1-01 to -03), and the document signer signs it as a COSE_Sign1 with its
certificate in x5chain. Issuers that must name their signer's certificate (PID, QEAA and PuB-EAA providers) add x5u
and x5t to the protected header.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import secrets
from typing import Any

from cunho import cose
from cunho.credentials import PID_MDOC_DATES, config_claims, pid_mdoc_elements, pid_mdoc_names
from cunho.jose import b64u
from cunho.metadata import PID_NAMESPACE, is_pid
from cunho.qualified import CATEGORIES, EAA_NAMESPACE, ETSI_NAMESPACE, MDL_DOCTYPE, attestation_id, authority
from cunho.rules import implements
from cunho.settings import Settings
from cunho.signer import Signer
from cunho.status import StatusRef

SALT_BYTES = 32  # ISO/IEC 18013-5 asks for at least 16 random bytes per item
DIGEST_IDS = 2**31  # digest ids are drawn from [0, 2^31), distinct within one MSO
DATE_TYPES = frozenset({"full-date", "full_date"})


def element_types(config: dict[str, Any]) -> dict[tuple[str, str], str | None]:
    """The value type of each data element of an mdoc configuration, by (namespace, identifier)."""
    return {(str(c["path"][0]), str(c["path"][1])): c.get("value_type") for c in config_claims(config)}


def element_value(kind: str | None, value: Any) -> Any:
    """The CBOR value of one data element: a full-date as tag 1004, a JPEG data URL as its bytes, the rest as the JSON
    the operator sent (the subject check has refused floats and anything else CBOR cannot carry deterministically)."""
    if kind in DATE_TYPES:
        return cose.full_date(value)
    if kind == "jpeg":
        return base64.b64decode(value.split(",", 1)[1], validate=True) if value else b""
    return value


@implements(
    "PID.MDOC.DOCTYPE_NAMESPACE", "PID.MDOC.ENCODING", "PID.MDOC.FULL_DATE_TAG1004", "PID.MDOC.DOMESTIC_NAMESPACE"
)
def pid_elements(config: dict[str, Any], subject: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The PID's data elements in the PID namespace (PID Rulebook §3.1), from the one PID in the SD-JWT VC names: the
    dates as full-date (tag 1004), whatever type the configuration gives them, the portrait as the bytes of its JPEG
    (empty for a person who opted out), nationality as an array and place_of_birth as a map of text. Only elements of
    the rulebook that the configuration lists are issued, so nothing outside the rulebook enters the PID namespace."""
    listed = pid_mdoc_elements(config)
    elements: dict[str, Any] = {}
    for name, value in pid_mdoc_names(subject).items():
        if name not in listed:
            continue
        if name in PID_MDOC_DATES:
            elements[name] = cose.full_date(value)
        elif name == "portrait":
            elements[name] = element_value("jpeg", value)
        else:
            elements[name] = value
    return {PID_NAMESPACE: elements}


def data_elements(
    settings: Settings, signer: Signer, config: dict[str, Any], subject: dict[str, Any], nbf: int
) -> dict[str, dict[str, Any]]:
    """The CBOR value of every data element to issue, by namespace."""
    if is_pid(config):
        return pid_elements(config, subject)
    types = element_types(config)
    elements = {
        ns: {name: element_value(types[(ns, name)], value) for name, value in members.items()}
        for ns, members in subject.items()
    }
    if config.get("doctype") != MDL_DOCTYPE:
        _fill(settings, signer, elements, nbf)
    return elements


@implements("FMT.ETSI_119472_1", "QEAA.QUALIFIED_INDICATOR", "QEAA.ATTESTATION_ID_UNIQUE")
def _fill(settings: Settings, signer: Signer, elements: dict[str, dict[str, Any]], nbf: int) -> None:
    """What every mdoc attestation that is not an mDL carries from cunho (ETSI TS 119 472-1 clause 6.2): the issuer's
    name from its certificate, an identity code of its own, the day it is issued (the start of its validity), and the
    category of a qualified or public-body attestation."""
    own = elements.setdefault(EAA_NAMESPACE, {})
    own["issuing_authority_unicode"] = authority(signer.certificate_der())
    own["document_number"] = attestation_id()
    own["issue_date"] = cose.full_date(dt.datetime.fromtimestamp(nbf, dt.UTC).date().isoformat())
    if settings.profile in CATEGORIES:
        elements.setdefault(ETSI_NAMESPACE, {})["category"] = CATEGORIES[settings.profile]


@implements(
    "FMT.MDOC.CONFIG_AND_ENCODING",
    "FMT.MDOC.ISSUERAUTH_X5CHAIN",
    "FMT.MDOC.MSO_VERIFIES",
    "STATUS.MDOC_MECHANISM",
    "STATUS.MDOC_BITS1_UNIQUE_IDX",
    "PID.MDOC.X5U_X5T_PROTECTED",
    "PID.MDOC.CANONICAL_CBOR",
    "PID.MDOC.TDATE_NO_FRACTION_Z",
    "QEAA.ANNEX_V",
    "QEAA.ATTRIBUTES_SCOPE",
    "QEAA.CERT_LOCATION",
)
def issuer_signed(
    settings: Settings,
    signer: Signer,
    config: dict[str, Any],
    subject: dict[str, Any],
    holder_jwk: dict[str, Any],
    status: StatusRef,
    nbf: int,
    exp: int,
    status_anchor: bytes,
) -> str:
    """One mdoc, as the credential response carries it: the base64url of the CBOR IssuerSigned structure. Its
    status_list names `status_anchor`, the certificate a relying party verifies the status list's x5chain to (CIR
    2024/2979 Annex II EAA-6.2.10.1-06.1, -13.1), since the status list is not signed under the IACA."""
    elements = [
        (ns, name, value)
        for ns, members in data_elements(settings, signer, config, subject, nbf).items()
        for name, value in members.items()
    ]
    ids = secrets.SystemRandom().sample(range(DIGEST_IDS), len(elements))
    name_spaces: dict[str, list[Any]] = {}
    digests: dict[str, dict[int, bytes]] = {}
    for digest_id, (ns, name, value) in zip(ids, elements, strict=True):
        item = cose.issuer_signed_item(digest_id, secrets.token_bytes(SALT_BYTES), name, value)
        name_spaces.setdefault(ns, []).append(item)
        digests.setdefault(ns, {})[digest_id] = hashlib.sha256(cose.encode(item)).digest()
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "valueDigests": digests,
        "deviceKeyInfo": {"deviceKey": cose.cose_key(holder_jwk)},
        "docType": config["doctype"],
        "validityInfo": {"signed": cose.tdate(nbf), "validFrom": cose.tdate(nbf), "validUntil": cose.tdate(exp)},
        "status": {"status_list": {**status.claim(settings.issuer_url)["status_list"], "certificate": status_anchor}},
    }
    # ETSI TS 119 472-1 EAA-6.6.1-01, a CB-AdES baseline signature (ETSI TS 119 152-1 V1.1.1 Table 14): the signing
    # time as iat in signed CWT claims (5.1.9), the same coarse time validityInfo gives, and the signing certificate
    # protected by its x5t (5.2.2). x5chain stays a bare unprotected header, where ISO/IEC 18013-5 §9.1.2.4 puts it
    # and verifiers look for it, not in the uHeaders array CB-AdES asks for (4.4).
    protected: dict[int, Any] = {cose.CWT_CLAIMS: {cose.IAT: nbf}, cose.X5T: cose.x5t(signer.certificate_der())}
    if settings.mdoc_signer_certificate_url:
        protected[cose.X5U] = settings.mdoc_signer_certificate_url
    chain = [base64.b64decode(der) for der in signer.x5c()]
    issuer_auth = cose.sign1(signer, cose.encode(cose.embed(mso)), protected, {cose.X5CHAIN: cose.x5chain(chain)})
    return b64u(cose.encode({"nameSpaces": name_spaces, "issuerAuth": issuer_auth}))
