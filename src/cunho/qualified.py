"""What a qualified or public-body attestation carries beyond any other (eIDAS Annex V and VII; ETSI TS 119 472-1
V1.2.1), and the data elements every mdoc attestation carries (clause 6), filled in by cunho rather than sent by the
operator.

The provider is named by its signing certificate, which every credential cunho issues carries (x5c, x5chain): clause
5 forbids issuing_authority, issuing_country and iss_reg_id in an attestation that incorporates the qualified
certificate (EAA-5.2.4.1-03, -07, -11; EAA-6.2.4.1-13), and QEAA-5.2.4.2-01 to -03 let the certificate carry them.
So the certificate of a qualified or public-body provider must hold them, and cunho checks that at start.
"""

from __future__ import annotations

import re
import secrets
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from cunho.errors import ConfigError
from cunho.rules import implements
from cunho.settings import Profile

# ETSI TS 119 472-1 EAA-6.1-04: the namespace of the data elements the document defines for mdoc.
ETSI_NAMESPACE = "org.etsi.01947201.010101"
MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
MDL_NAMESPACE = "org.iso.18013.5.1"
EAA_NAMESPACE = "org.iso.23220.1"  # ISO/IEC 23220-2 §6.3, for an mdoc attestation that is not an mDL (EAA-6.1-03)

# 4.2.2.2-02 and 4.2.2.3-02: the category of a qualified or public-body attestation.
CATEGORIES = {
    Profile.QEAA_PROVIDER: "urn:etsi:esi:eaa:eu:qualified",
    Profile.PUB_EAA_PROVIDER: "urn:etsi:esi:eaa:eu:pub",
}
# The claims a qualified or public-body SD-JWT VC never lists: the provider's identity is in its certificate (above),
# and every attribute refers to the subject (QEAA-5.2.5.5-01, PuB-EAA-5.2.5.6-01), so no subAttrs (EAA-5.3-02).
SDJWT_REFUSED = {
    "issuing_authority": "the provider is named by its qualified certificate (ETSI TS 119 472-1 EAA-5.2.4.1-03)",
    "issuing_country": "the provider's country is in its qualified certificate (ETSI TS 119 472-1 EAA-5.2.4.1-07)",
    "iss_reg_id": "the provider's registration number is in its qualified certificate (EAA-5.2.4.1-11)",
    "subAttrs": "every attribute of a qualified or public-body attestation refers to its subject (QEAA-5.2.5.5-01)",
    "category": "a claim named category would clash with the category of the attestation (EAA-5.2.2)",
    "jti": "cunho gives each attestation its own identity code in jti (Annex V(f), EAA-5.2.3-01)",
}
MDOC_REFUSED = {
    (ETSI_NAMESPACE, "iss_reg_id"): "the provider's registration number is in its qualified certificate "
    "(ETSI TS 119 472-1 EAA-6.2.4.1-13)",
}
# EU Member States by their ISO 3166-1 alpha-2 codes (EAA-4.2.4.1-05).
MEMBER_STATES = frozenset("AT BE BG CY CZ DE DK EE ES FI FR GR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK".split())
# ETSI EN 319 412-1 §5.1.4: a legal person's identity type (VAT, NTR, PSD, LEI, or two letters of a national scheme
# and a colon), the country (EL for Greek VAT numbers, XG for an LEI with no country), a hyphen, the identifier.
ORGANIZATION_IDENTIFIER = re.compile(r"(?:VAT|NTR|PSD|LEI|[A-Z]{2}:)[A-Z]{2}-\S.*")
ORGANIZATION_IDENTIFIER_OID = x509.ObjectIdentifier("2.5.4.97")
ID_BYTES = 16


def _one(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = [a.value for a in name.get_attributes_for_oid(oid)]
    if len(values) > 1:
        raise ConfigError(f"the signer certificate's subject names {oid.dotted_string} more than once")
    value = values[0] if values else None
    return value if isinstance(value, str) and value.strip() else None


@implements("QEAA.ISSUER_IDENTITY")
def check_provider(certificate: bytes, which: str) -> None:
    """A qualified or public-body provider's certificate names it as Annex V(b) and VII(b) ask: the Member State it
    is established in, and its name and registration number when a legal person, its name when a natural person."""
    subject = x509.load_der_x509_certificate(certificate).subject
    where = f"the {which} certificate of a qualified or public-body provider"
    country = _one(subject, NameOID.COUNTRY_NAME)
    if country not in MEMBER_STATES:
        raise ConfigError(f"{where} needs the EU Member State it is established in as countryName (Annex V(b))")
    organization = _one(subject, NameOID.ORGANIZATION_NAME)
    if organization is not None:
        identifier = _one(subject, ORGANIZATION_IDENTIFIER_OID)
        if identifier is None or not ORGANIZATION_IDENTIFIER.fullmatch(identifier):
            raise ConfigError(
                f"{where} names a legal person, so it needs its registration number as organizationIdentifier in the "
                "form of ETSI EN 319 412-1 §5.1.4, such as VATPT-500000000 (Annex V(b)(i); QEAA-4.2.4.2-05)"
            )
        return
    given, family = _one(subject, NameOID.GIVEN_NAME), _one(subject, NameOID.SURNAME)
    if _one(subject, NameOID.COMMON_NAME) is None and (given is None or family is None):
        raise ConfigError(f"{where} needs the provider's name: organizationName, or the person's name (Annex V(b))")


def authority(certificate: bytes) -> str:
    """The provider's name for issuing_authority_unicode (EAA-6.2.4.1-03): its organizationName, or the name the
    certificate gives it."""
    subject = x509.load_der_x509_certificate(certificate).subject
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        name = _one(subject, oid)
        if name is not None:
            return name
    given, family = _one(subject, NameOID.GIVEN_NAME), _one(subject, NameOID.SURNAME)
    if given is None or family is None:
        raise ConfigError("the mdoc document signer certificate names no issuing authority (organizationName)")
    return f"{given} {family}"


@implements("QEAA.ATTESTATION_ID_UNIQUE", "PRIV.UNIQUE_ELEMENTS_CSPRNG")
def attestation_id() -> str:
    """An attestation identity code: 128 bits from the CSPRNG, so unique for the provider without a register of the
    ones given, and telling nothing about the subject or the order of issuance (Annex V(f))."""
    return secrets.token_hex(ID_BYTES)


def filled_elements(config: dict[str, Any], profile: Profile) -> list[dict[str, Any]]:
    """The data elements cunho adds to an mdoc attestation that is not a PID or an mDL: the issuer's name, the
    attestation's identity code and its issue date in the ISO/IEC 23220-2 namespace (EAA-6.2.4.1-03, EAA-6.2.3-01,
    EAA-6.2.6-01), and the category of a qualified or public-body attestation (QEAA-6.2.2.2-01, PuB-EAA-6.2.2.3-01).
    An mDL carries its own (ISO/IEC 18013-5 Table 5), sent by the operator."""
    if config.get("doctype") == MDL_DOCTYPE:
        return []
    claims: list[dict[str, Any]] = [
        {"path": [EAA_NAMESPACE, "issuing_authority_unicode"], "mandatory": True, "value_type": "string"},
        {"path": [EAA_NAMESPACE, "document_number"], "mandatory": True, "value_type": "string"},
        {"path": [EAA_NAMESPACE, "issue_date"], "mandatory": True, "value_type": "full-date"},
    ]
    if profile in CATEGORIES:
        claims.append({"path": [ETSI_NAMESPACE, "category"], "mandatory": True, "value_type": "string"})
    return claims


FILLED = frozenset(
    {
        (EAA_NAMESPACE, "issuing_authority_unicode"),
        (EAA_NAMESPACE, "document_number"),
        (EAA_NAMESPACE, "issue_date"),
        (ETSI_NAMESPACE, "category"),
    }
)
# What an mDL must carry of these, as the operator sends it (EAA-6.2.4.1-01, EAA-6.2.3-03, EAA-6.2.6-03).
MDL_REQUIRED = ("issuing_authority", "document_number", "issue_date")


@implements("QEAA.SUBJECT_OR_PSEUDONYM")
def names_another_subject(config: dict[str, Any], data: Any) -> str | None:
    """Why this subject data would attest attributes of someone other than the subject, or None: a subAttrs claim
    in an SD-JWT VC (EAA-5.3-02), a SubAttr value in an mdoc (EAA-6.3-02). A qualified or public-body attestation
    refers every attribute to its subject (QEAA-5.2.5.5-01, -6.2.5.5-01; PuB-EAA-5.2.5.6-01, -6.2.5.6-01)."""
    if not isinstance(data, dict):
        return None
    if config.get("format") != "mso_mdoc":
        return "subAttrs: attributes of another subject" if "subAttrs" in data else None
    for ns, members in data.items():
        for name, value in members.items() if isinstance(members, dict) else ():
            if isinstance(value, dict) and ("subId" in value or "subAka" in value):
                return f"{ns}/{name}: a SubAttr names another subject"
    return None
