"""Credential content: rulebook validation and the SD-JWT VC formatter.

Subject data arrives with the claim names of the credential configuration (for the PID, the SD-JWT VC
names of the PID Rulebook: birthdate, place_of_birth, nationalities, picture...).
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import re
import secrets
from collections.abc import Collection
from typing import Any

from cunho.jose import b64u
from cunho.metadata import (
    CATEGORIES,
    MDOC,
    PID_MDOC_ADDRESS,
    PID_MDOC_ELEMENTS,
    PID_MDOC_RULEBOOK,
    PID_NAMESPACE,
    is_pid,
)
from cunho.qualified import FILLED, attestation_id
from cunho.rules import implements
from cunho.settings import Settings
from cunho.signer import Signer, certificate_thumbprint_s256, sign_jws
from cunho.status import StatusRef

# SD-JWT VC draft-23 §2.2.2.3: these never go into disclosures.
NEVER_DISCLOSED = frozenset(
    {"iss", "iat", "nbf", "exp", "cnf", "vct", "vct#integrity", "aka_vcts", "status", "_sd", "_sd_alg"}
)
PID_MANDATORY = (
    "family_name",
    "given_name",
    "birthdate",
    "place_of_birth",
    "nationalities",
    "issuing_authority",
    "issuing_country",
)
PORTRAIT_MANDATORY_FROM = dt.date(2028, 8, 11)  # 24 months after CIR 2026/1731 enters into force
SEX_VALUES = {0, 1, 2, 3, 4, 5, 6, 9}
ISO_3166_ALPHA2 = frozenset(
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY "
    "BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM "
    "FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT "
    "JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN "
    "MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT "
    "PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL "
    "TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split()
)
# PID Rulebook v1.7 §4.1.1 (CIR 2024/2977 Annex as amended by 2026/1731): SD-JWT VC claim names.
PID_CLAIMS = frozenset(
    {
        "family_name",
        "given_name",
        "birthdate",
        "place_of_birth",
        "nationalities",
        "address",
        "personal_administrative_number",
        "picture",
        "birth_family_name",
        "birth_given_name",
        "sex",
        "email",
        "phone_number",
        "date_of_expiry",
        "issuing_authority",
        "issuing_country",
        "document_number",
        "issuing_jurisdiction",
        "date_of_issuance",
    }
)
PID_MEMBERS = {
    "place_of_birth": frozenset({"country", "region", "locality"}),
    "address": frozenset({"formatted", "country", "region", "locality", "postal_code", "street_address"}),
}
# Claims the PID Rulebook v1.7 lists and the Annex of CIR 2024/2977 as replaced by 2026/1731 does not (metadata
# SDJWT_OUTSIDE_ANNEX): refused with the reason, in both formats.
OUTSIDE_ANNEX = {
    "trust_anchor": "trust_anchor: not in the Annex of CIR 2024/2977; an attribute outside it belongs in a domestic "
    "type (§4.2), and the PID is authenticated through the list of PID providers (§5) and x5u",
    "attestation_legal_category": "attestation_legal_category: not in the Annex of CIR 2024/2977; an attribute outside "
    "it belongs in a domestic type (§4.2)",
    "address.house_number": "address.house_number: not in the Annex of CIR 2024/2977, whose resident_street includes "
    "the house number: send it in address.street_address",
}
PID_MDOC_DATES = frozenset({"birth_date", "expiry_date", "issuance_date"})
# The PID's data elements of type tstr (PID Rulebook §3.1.2); the others are dates, structures, the portrait and sex.
PID_MDOC_TEXT = PID_MDOC_RULEBOOK - PID_MDOC_DATES - {"place_of_birth", "nationality", "portrait", "sex"}
TSTR_MAX = 150  # PID Rulebook §3.1.2, CIR 2024/2977 Annex §4.1(c)
DECOYS_MAX = 3
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# The claim that says when the attested document ends, as an SD-JWT VC rulebook names it: date_of_expiry in the PID
# and some attestations, expiry_date in the others (six of the reference configurations).
EXPIRY_CLAIMS = ("date_of_expiry", "expiry_date")
# The names RFC 9901 keeps for itself: a disclosure that carries one makes a verifier reject the whole SD-JWT (§7.1).
RESERVED_NAMES = frozenset({"_sd", "..."})
JPEG_DATA_URL = re.compile(r"data:image/jpeg;base64,[A-Za-z0-9+/]+={0,2}")


class ClaimsError(ValueError):
    """Subject data does not satisfy the rulebook. `problems` lists every defect, not just the first."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def parse_date(value: Any) -> dt.date | None:
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _utf8_ok(value: Any) -> bool:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, dict):
        return all(_utf8_ok(k) and _utf8_ok(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_utf8_ok(v) for v in value)
    return True


def config_claims(config: dict[str, Any]) -> list[dict[str, Any]]:
    claims = (config.get("credential_metadata") or {}).get("claims") or config.get("claims") or []
    return [c for c in claims if isinstance(c, dict) and isinstance(c.get("path"), list) and c["path"]]


@implements("EAA.RULEBOOK.CONFORMANCE", "PID.ATTRS.OPTIONAL_SCHEMA", "PID.SDJWT.UTF8", "FMT.VALIDITY_PERIOD")
def validate_subject(config: dict[str, Any], data: Any, today: dt.date) -> list[str]:
    """Generic check against the configuration's claim list. Returns problems; empty means valid."""
    if not isinstance(data, dict):
        return ["subject data must be a JSON object"]
    problems: list[str] = []
    claims = config_claims(config)
    top_level = {str(c["path"][0]) for c in claims}
    for name in sorted(set(data) - top_level):
        problems.append(f"{name}: not defined by this credential configuration")
    for claim in claims:
        path = [str(p) for p in claim["path"] if p is not None]
        if len(path) != 1:
            continue
        name = path[0]
        if name not in data:
            # date_of_issuance is the day cunho issues; every other mandatory claim comes from the operator.
            if claim.get("mandatory") and name != "date_of_issuance":
                problems.append(f"{name}: mandatory and missing")
            continue
        value, kind = data[name], claim.get("value_type")
        if kind == "string" and (not isinstance(value, str) or not value.strip()):
            problems.append(f"{name}: must be a non-empty string")
        elif kind == "full-date" and parse_date(value) is None:
            problems.append(f"{name}: must be a calendar date YYYY-MM-DD")
        elif kind == "list" and not isinstance(value, list | dict):
            problems.append(f"{name}: must be a list or object")
        elif kind == "uint" and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            problems.append(f"{name}: must be a non-negative integer")
    if not _utf8_ok(data):
        problems.append("text values must be valid Unicode (UTF-8 encodable)")
    if _reserved_name(data):
        problems.append("a member named _sd or ... cannot be issued in an SD-JWT (RFC 9901)")
    for name in ("date_of_issuance", *EXPIRY_CLAIMS):
        if name in data and parse_date(data[name]) is None:
            problems.append(f"{name}: must be a calendar date YYYY-MM-DD")
    issued = parse_date(data.get("date_of_issuance"))
    for name in EXPIRY_CLAIMS:
        expires = parse_date(data.get(name))
        if issued and expires and expires < issued:
            problems.append(f"{name}: is before date_of_issuance")
        if expires and expires < today:
            problems.append(f"{name}: is in the past")
    return problems


def _reserved_name(value: Any) -> bool:
    """Whether subject data uses a name SD-JWT reserves, at any depth: every member becomes a disclosure under its
    own name, and one named _sd or ... is a credential every verifier must reject (the security review)."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if RESERVED_NAMES & set(item):
                return True
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


@implements(
    "PID.RULEBOOK.CONFORMANCE",
    "PID.ATTRS.OPTIONAL_SCHEMA",
    "PID.SDJWT.CLAIM_MAPPING",
    "PID.SDJWT.PLACE_OF_BIRTH_NONEMPTY",
    "PID.SDJWT.PICTURE_DATA_URL_JPEG",
    "PID.PORTRAIT.OPTOUT_EMPTY",
    "PID.VALUES.ISSUING_COUNTRY_ALPHA2",
    "PID.VALUES.ISSUING_JURISDICTION_PREFIX",
    "PID.VALUES.NATIONALITY_QU_QS",
    "PID.VALUES.VALID_AT_VALIDITY_START",
)
def validate_pid(data: dict[str, Any], today: dt.date) -> list[str]:
    """PID-specific rules of CIR 2024/2977 (Annex as amended by 2026/1731) and the PID Rulebook v1.7."""
    problems = [
        OUTSIDE_ANNEX.get(name, f"{name}: not a PID claim name (PID Rulebook §4.1.1)")
        for name in sorted(set(data) - PID_CLAIMS)
    ]
    for name, members in PID_MEMBERS.items():
        if isinstance(data.get(name), dict):
            problems += [
                OUTSIDE_ANNEX.get(f"{name}.{m}", f"{name}.{m}: not a PID member name")
                for m in sorted(set(data[name]) - members)
            ]
            problems += [
                f"{name}.{m}: must be a non-empty string"
                for m, v in data[name].items()
                if m in members and (not isinstance(v, str) or not v.strip())
            ]
    problems += [f"{name}: mandatory and missing" for name in PID_MANDATORY if name not in data]
    if today >= PORTRAIT_MANDATORY_FROM and "picture" not in data:
        problems.append("picture: mandatory from 2028-08-11 (send an empty string if the person opted out)")
    birth = parse_date(data.get("birthdate"))
    if "birthdate" in data and (birth is None or birth > today):
        problems.append("birthdate: must be a past calendar date YYYY-MM-DD")
    place = data.get("place_of_birth")
    if "place_of_birth" in data:
        if not isinstance(place, dict) or not any(
            isinstance(place.get(k), str) and place[k].strip() for k in ("country", "region", "locality")
        ):
            problems.append("place_of_birth: needs at least one of country, region, locality")
        elif "country" in place and not _code(place["country"], ISO_3166_ALPHA2):
            problems.append("place_of_birth.country: must be an ISO 3166-1 alpha-2 code")
    nationalities = data.get("nationalities")
    if "nationalities" in data:
        allowed = ISO_3166_ALPHA2 | {"QU", "QS"}
        if (
            not isinstance(nationalities, list)
            or not nationalities
            or not all(_code(n, allowed) for n in nationalities)
        ):
            problems.append(
                "nationalities: a non-empty list of ISO 3166-1 alpha-2 codes, QU if unknown, QS if stateless"
            )
    country = data.get("issuing_country")
    if "issuing_country" in data and not _code(country, ISO_3166_ALPHA2):
        problems.append("issuing_country: must be an ISO 3166-1 alpha-2 code")
    jurisdiction = data.get("issuing_jurisdiction")
    if jurisdiction is not None and (not isinstance(jurisdiction, str) or not jurisdiction.startswith(f"{country}-")):
        problems.append("issuing_jurisdiction: must be an ISO 3166-2 code starting with issuing_country")
    picture = data.get("picture")
    # An empty string is the person's opt-out (ARF PID_03); anything else sent, null included, is a JPEG data URL.
    if "picture" in data and picture != "" and (not isinstance(picture, str) or not JPEG_DATA_URL.fullmatch(picture)):
        problems.append("picture: must be a data URL with a base64 JPEG, or empty if the person opted out")
    if "sex" in data and (isinstance(data["sex"], bool) or not _code(data["sex"], SEX_VALUES)):
        problems.append("sex: must be one of 0, 1, 2, 3, 4, 5, 6, 9")
    address = data.get("address")
    if address is not None and not isinstance(address, dict):
        problems.append("address: must be an object")
    return problems


def _code(value: object, allowed: Collection[object]) -> bool:
    """Membership for client-shaped values: a list or object is never a code (and never unhashable)."""
    return isinstance(value, str | int) and value in allowed


# The issuance date elements of mdoc rulebooks (PID Rulebook issuance_date, ISO/IEC 23220-2 issue_date): the day
# cunho issues, filled in when the operator leaves them out, as date_of_issuance is for SD-JWT VC.
MDOC_ISSUANCE_DATES = frozenset({"issuance_date", "issue_date"})
MDOC_DATES = MDOC_ISSUANCE_DATES | {"expiry_date"}


def _jpeg_data_url(value: Any) -> bool:
    """A data URL of a JPEG whose base64 decodes: an mdoc carries the bytes, so they are decoded at issuance."""
    if not isinstance(value, str) or not JPEG_DATA_URL.fullmatch(value):
        return False
    try:
        base64.b64decode(value.split(",", 1)[1], validate=True)
    except binascii.Error:
        return False
    return True


def _no_floats(value: Any) -> bool:
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(_no_floats(v) for v in value.values())
    if isinstance(value, list):
        return all(_no_floats(v) for v in value)
    return True


@implements("EAA.RULEBOOK.CONFORMANCE", "FMT.VALIDITY_PERIOD")
def validate_mdoc_subject(config: dict[str, Any], data: Any, today: dt.date) -> list[str]:
    """The data of an mdoc: an object of namespaces, each an object of the configuration's data elements, with the
    value each element's type asks for. Returns problems; empty means valid."""
    if not isinstance(data, dict):
        return ["subject data must be a JSON object of namespaces"]
    elements = {(str(c["path"][0]), str(c["path"][1])): c for c in config_claims(config) if len(c["path"]) == 2}
    namespaces = {ns for ns, _ in elements}
    problems: list[str] = []
    for ns in sorted(set(data) - namespaces):
        problems.append(f"{ns}: not a namespace of this credential configuration")
    for ns in sorted(set(data) & namespaces):
        if not isinstance(data[ns], dict):
            problems.append(f"{ns}: must be an object of data elements")
            continue
        problems += [
            f"{ns}/{name}: not a data element of {ns}"
            for name in sorted(set(data[ns]) - {name for space, name in elements if space == ns})
        ]
    for ns, name in sorted(
        FILLED & {(ns, name) for ns, members in data.items() if isinstance(members, dict) for name in members}
    ):
        problems.append(f"{ns}/{name}: cunho fills it in; the operator does not send it")
    for (ns, name), claim in elements.items():
        members = data.get(ns)
        if not isinstance(members, dict) or name not in members:
            if claim.get("mandatory") and name not in MDOC_ISSUANCE_DATES and (ns, name) not in FILLED:
                problems.append(f"{ns}/{name}: mandatory and missing")
            continue
        value, kind = members[name], claim.get("value_type")
        where = f"{ns}/{name}"
        if kind == "string" and (not isinstance(value, str) or not value.strip()):
            problems.append(f"{where}: must be a non-empty string")
        elif kind in ("full-date", "full_date") and parse_date(value) is None:
            problems.append(f"{where}: must be a calendar date YYYY-MM-DD")
        elif kind == "uint" and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            problems.append(f"{where}: must be a non-negative integer")
        elif kind == "bool" and not isinstance(value, bool):
            problems.append(f"{where}: must be true or false")
        elif kind == "jpeg" and value != "" and not _jpeg_data_url(value):
            problems.append(f"{where}: must be a data URL with a base64 JPEG")
        if name in MDOC_DATES and kind not in ("full-date", "full_date") and parse_date(value) is None:
            # Whatever the configuration says of its type: the expiry caps the validity, and both are dates.
            problems.append(f"{where}: must be a calendar date YYYY-MM-DD")
        expires = parse_date(value) if name == "expiry_date" else None
        if expires is not None and expires < today:
            problems.append(f"{where}: is in the past")
    if not _no_floats(data):
        problems.append("numbers must be integers: an mdoc has no deterministic encoding for fractions here")
    if not _utf8_ok(data):
        problems.append("text values must be valid Unicode (UTF-8 encodable)")
    return problems


def pid_mdoc_names(data: dict[str, Any]) -> dict[str, Any]:
    """The PID's SD-JWT VC claims under their mdoc data element identifiers, values as sent (PID Rulebook §3.1.2).
    Each claim maps to one element and no two claims to the same one, so no element can appear twice."""
    elements = {PID_MDOC_ELEMENTS[name]: value for name, value in data.items() if name in PID_MDOC_ELEMENTS}
    address = data.get("address")
    if isinstance(address, dict):
        elements |= {PID_MDOC_ADDRESS[m]: v for m, v in address.items() if m in PID_MDOC_ADDRESS}
    return elements


def pid_mdoc_elements(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The rulebook data elements an mdoc PID configuration lists in the PID namespace. Any other element it lists
    there is never issued (ARF PID_06: attributes outside the rulebook go in a domestic namespace)."""
    return {
        str(c["path"][1]): c
        for c in config_claims(config)
        if len(c["path"]) == 2 and c["path"][0] == PID_NAMESPACE and c["path"][1] in PID_MDOC_RULEBOOK
    }


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


@implements(
    "PID.ATTRS.MANDATORY_AND_METADATA",
    "PID.MDOC.TSTR_MAX150",
    "PID.MDOC.UTF8",
    "PID.MDOC.PLACE_OF_BIRTH_NONEMPTY",
    "PID.MDOC.NO_DUPLICATE_ELEMENTS",
)
def validate_pid_mdoc(config: dict[str, Any], data: Any, today: dt.date) -> list[str]:
    """The PID as mdoc, from the one PID the operator sends in the SD-JWT VC names: the PID rules of validate_pid
    (place_of_birth with a member among them), every claim sent has a data element in the configuration, the
    configuration's mandatory elements are there, and every text is valid Unicode of at most 150 characters."""
    if not isinstance(data, dict):
        return ["subject data must be a JSON object"]
    problems = validate_pid(data, today)
    listed = pid_mdoc_elements(config)
    names = pid_mdoc_names(data)
    claims = {v: k for k, v in PID_MDOC_ELEMENTS.items()} | {v: f"address.{k}" for k, v in PID_MDOC_ADDRESS.items()}
    problems += [
        f"{claims[e]}: the mdoc PID configuration has no data element {e}" for e in sorted(set(names) - set(listed))
    ]
    problems += [
        f"{claims[e]}: mandatory in the mdoc PID and missing"
        for e, claim in sorted(listed.items())
        if claim.get("mandatory") and e not in names and e != "issuance_date"
    ]
    for element, value in sorted(names.items()):
        if element in PID_MDOC_TEXT and (not isinstance(value, str) or not value.strip()):
            problems.append(f"{claims[element]}: must be a non-empty string")
        if element != "portrait" and any(len(s) > TSTR_MAX for s in _strings(value)):
            problems.append(f"{claims[element]}: text longer than {TSTR_MAX} characters (PID Rulebook §3.1.2)")
    # The checks the SD-JWT VC configuration makes of the same PID, made here too: the mdoc may be the only format
    # asked for, and the mdoc carries these as full-date and JPEG bytes.
    for name in ("date_of_issuance", "date_of_expiry"):
        if name in data and parse_date(data[name]) is None:
            problems.append(f"{name}: must be a calendar date YYYY-MM-DD")
    issued, expires = parse_date(data.get("date_of_issuance")), parse_date(data.get("date_of_expiry"))
    if issued and expires and expires < issued:
        problems.append("date_of_expiry: is before date_of_issuance")
    if expires and expires < today:
        problems.append("date_of_expiry: is in the past")
    if "picture" in data and data["picture"] != "" and not _jpeg_data_url(data["picture"]):
        problems.append("picture: must be a data URL with a base64 JPEG that decodes")
    if not _utf8_ok(data):
        problems.append("text values must be valid Unicode (UTF-8 encodable)")
    return problems


def check_subject(config: dict[str, Any], data: Any, today: dt.date) -> None:
    if config.get("format") == MDOC:
        problems = (
            validate_pid_mdoc(config, data, today) if is_pid(config) else validate_mdoc_subject(config, data, today)
        )
        if problems:
            raise ClaimsError(problems)
        return
    problems = validate_subject(config, data, today)
    if not problems and is_pid(config):
        problems = validate_pid(data, today)
    if problems:
        raise ClaimsError(problems)


def _disclosure(*items: Any) -> tuple[str, str]:
    encoded = b64u(json.dumps([b64u(secrets.token_bytes(16)), *items], ensure_ascii=False).encode("utf-8"))
    return encoded, b64u(hashlib.sha256(encoded.encode("ascii")).digest())


def _decoys() -> list[str]:
    """RFC 9901 §4.2.5 decoy digests, so the size of _sd does not reveal how many claims there are."""
    return [b64u(hashlib.sha256(secrets.token_bytes(32)).digest()) for _ in range(secrets.randbelow(DECOYS_MAX + 1))]


@implements("PID.SDJWT.RECURSIVE_SD", "PID.SD.PER_DATA_IDENTIFIER", "PRIV.UNIQUE_ELEMENTS_CSPRNG")
def _conceal(value: Any, disclosures: list[str]) -> Any:
    """Make every member and every array element selectively disclosable, recursively (RFC 9901)."""
    if isinstance(value, dict):
        digests = []
        for name, child in value.items():
            encoded, digest = _disclosure(name, _conceal(child, disclosures))
            disclosures.append(encoded)
            digests.append(digest)
        return {"_sd": sorted(digests + _decoys())} if digests else {}
    if isinstance(value, list):
        out = []
        for child in value:
            encoded, digest = _disclosure(_conceal(child, disclosures))
            disclosures.append(encoded)
            out.append({"...": digest})
        return out
    return value


@implements(
    "FMT.SDJWT.CONFIG_AND_ENCODING",
    "FMT.SDJWT.TYP",
    "FMT.SDJWT.NEVER_SD_CLAIMS",
    "FMT.SDJWT.EXP_OR_STATUS",
    "FMT.SDJWT.X5C_NO_ANCHOR",
    "FMT.ETSI_119472_1",
    "FMT.VALIDATION_INFO_EMBEDDED",
    "PID.SDJWT.NBF_EXP",
    "PID.SDJWT.VCT",
    "PID.SDJWT.X5U_X5TS256",
    "STATUS.SDJWT_TSL",
    "STATUS.TSL.REFERENCE",
    "QEAA.ANNEX_V",
    "QEAA.QUALIFIED_INDICATOR",
    "QEAA.ATTESTATION_ID_UNIQUE",
    "QEAA.ATTRIBUTES_SCOPE",
    "QEAA.CERT_LOCATION",
)
def sd_jwt_vc(
    settings: Settings,
    signer: Signer,
    config: dict[str, Any],
    subject: dict[str, Any],
    holder_jwk: dict[str, Any] | None,
    status: StatusRef,
    nbf: int,
    exp: int,
    integrity: str | None = None,
) -> str:
    """One SD-JWT VC in compact form, ending with '~' (no key binding JWT at issuance), in the profile of ETSI TS 119
    472-1 clause 5: vct with the vct#integrity of its Type Metadata when there is one, nbf and exp, the category and
    identity code (jti) of a qualified or public-body attestation, a cnf with the holder's public key only, the status
    reference, _sd_alg, and no audience, renewal or other usage component."""
    disclosures: list[str] = []
    concealed = _conceal({k: v for k, v in subject.items() if k not in NEVER_DISCLOSED}, disclosures)
    payload: dict[str, Any] = {
        **concealed,
        "_sd_alg": "sha-256",
        "iss": settings.issuer_url,
        "vct": config["vct"],
        **({"vct#integrity": integrity} if integrity is not None else {}),
        **(
            {"category": CATEGORIES[settings.profile], "jti": attestation_id()}
            if settings.profile in CATEGORIES
            else {}
        ),
        # iat is the same coarse time as nbf, so it reveals nothing more; SD-JWT VC lets it in and verifiers such
        # as NL Wallet require it.
        "iat": nbf,
        "nbf": nbf,
        "exp": exp,
        "status": status.claim(settings.issuer_url),
    }
    if holder_jwk is not None:
        payload["cnf"] = {"jwk": holder_jwk}
    header: dict[str, Any] = {"typ": "dc+sd-jwt", "x5c": signer.x5c()}
    if settings.signer_certificate_url:
        header["x5u"] = settings.signer_certificate_url
        header["x5t#S256"] = certificate_thumbprint_s256(signer)
    jwt = sign_jws(signer, header, payload)
    return "~".join([jwt, *disclosures]) + "~"
