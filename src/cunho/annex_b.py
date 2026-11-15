"""The certificate profiles of ISO/IEC 18013-5 Annex B that mdoc readers check: the IACA (Table B.1), the document
signer (Table B.3) and the signer of an MSO revocation list (Table B.9). A reader that holds to them refuses an mdoc
whose chain does not fit, so production refuses to start with one (the OIDF suite checks the same).

Each function gives what is wrong, in words an operator can act on; an empty list when the certificate fits. What is
checked is what the profiles ask of the certificate's form: countryName in the subject, key identifiers, a critical
key usage of exactly the bits the role needs, the issuer's contact as issuerAltName, a CRL distribution point for a
document signer, a CA with path length 0 for an IACA, and no other critical extension in an end-entity certificate.
"""

from __future__ import annotations

from typing import cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID

MDOC_DS = x509.ObjectIdentifier("1.0.18013.5.1.2")  # id-mdl-kp-mdlDS
KEY_USAGE_BITS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
)


def _extension(cert: x509.Certificate, kind: type[x509.ExtensionType]) -> x509.Extension[x509.ExtensionType] | None:
    try:
        return cert.extensions.get_extension_for_class(kind)
    except x509.ExtensionNotFound:
        return None


def _usage(cert: x509.Certificate, wanted: set[str], table: str) -> list[str]:
    found = _extension(cert, x509.KeyUsage)
    bits = set()
    if found is not None:
        usage = found.value
        assert isinstance(usage, x509.KeyUsage)
        bits = {bit for bit in KEY_USAGE_BITS if getattr(usage, bit)}
    if found is None or not found.critical or bits != wanted:
        names = " and ".join(sorted(wanted))
        return [f"{table} asks for a critical key usage of {names} alone"]
    return []


def _common(cert: x509.Certificate, table: str, issuer: x509.Certificate | None) -> list[str]:
    problems = []
    if not cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME):
        problems.append(f"{table} asks for countryName in the subject")
    if _extension(cert, x509.SubjectKeyIdentifier) is None:
        problems.append(f"{table} asks for a subject key identifier")
    if issuer is not None and issuer is not cert:
        found = _extension(cert, x509.AuthorityKeyIdentifier)
        own = _extension(issuer, x509.SubjectKeyIdentifier)
        if found is None:
            problems.append(f"{table} asks for an authority key identifier")
        elif own is not None:
            aki, ski = found.value, own.value
            assert isinstance(aki, x509.AuthorityKeyIdentifier) and isinstance(ski, x509.SubjectKeyIdentifier)
            if aki.key_identifier != ski.digest:
                problems.append("the authority key identifier is not the issuer's subject key identifier")
    return problems


def _contact(cert: x509.Certificate, table: str) -> list[str]:
    found = _extension(cert, x509.IssuerAlternativeName)
    if found is not None:
        names = found.value
        assert isinstance(names, x509.IssuerAlternativeName)
        if names.get_values_for_type(x509.RFC822Name) or names.get_values_for_type(x509.UniformResourceIdentifier):
            return []
    return [f"{table} asks for the issuer's contact as issuerAltName (an rfc822Name or a URI)"]


def _end_entity_criticals(cert: x509.Certificate, table: str, allowed: set[x509.ObjectIdentifier]) -> list[str]:
    extra = sorted(e.oid.dotted_string for e in cert.extensions if e.critical and e.oid not in allowed)
    return [f"{table} allows no other critical extension, but {', '.join(extra)} is critical"] if extra else []


def iaca_problems(iaca: x509.Certificate) -> list[str]:
    """Table B.1: an IACA root."""
    table = "ISO/IEC 18013-5 Table B.1 (IACA)"
    problems = _common(iaca, table, None)
    problems += _usage(iaca, {"key_cert_sign", "crl_sign"}, table)
    found = _extension(iaca, x509.BasicConstraints)
    none = x509.BasicConstraints(ca=False, path_length=None)
    constraints = cast(x509.BasicConstraints, found.value) if found is not None else none
    # A path length is a CA's alone: one that is no CA has none (RFC 5280 §4.2.1.9, which cryptography holds to when it
    # reads the certificate), so a path length of 0 says a CA.
    if found is None or not found.critical or constraints.path_length != 0:
        problems.append(f"{table} asks for critical basicConstraints of a CA with path length 0")
    return problems + _contact(iaca, table)


def document_signer_problems(signer: x509.Certificate, iaca: x509.Certificate | None) -> list[str]:
    """Table B.3: a document signer, and how it binds to the IACA that issued it when that is known."""
    table = "ISO/IEC 18013-5 Table B.3 (document signer)"
    problems = _common(signer, table, iaca)
    problems += _usage(signer, {"digital_signature"}, table)
    found = _extension(signer, x509.ExtendedKeyUsage)
    if found is None or not found.critical or MDOC_DS not in found.value:  # type: ignore[operator]
        problems.append(f"{table} asks for a critical extended key usage id-mdl-kp-mdlDS")
    points = _extension(signer, x509.CRLDistributionPoints)
    uris = []
    if points is not None:
        distribution = points.value
        assert isinstance(distribution, x509.CRLDistributionPoints)
        uris = [
            name
            for point in distribution
            for name in point.full_name or []
            if isinstance(name, x509.UniformResourceIdentifier)
        ]
    if not uris:
        problems.append(f"{table} asks for a CRL distribution point with a URI, where readers check revocation")
    problems += _contact(signer, table)
    problems += _end_entity_criticals(signer, table, {x509.KeyUsage.oid, x509.ExtendedKeyUsage.oid})
    if iaca is not None:
        country = signer.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        theirs = iaca.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        if country and theirs and country[0].value != theirs[0].value:
            problems.append(f"{table}: the countryName differs from the IACA's")
    return problems


def status_signer_problems(signer: x509.Certificate, issuer: x509.Certificate | None) -> list[str]:
    """Table B.9: the signer of an MSO revocation list, here the status list token in CWT form."""
    table = "ISO/IEC 18013-5 Table B.9 (MSO revocation list signer)"
    problems = [p for p in _common(signer, table, issuer) if "countryName" not in p]
    problems += _usage(signer, {"digital_signature"}, table)
    allowed = {x509.KeyUsage.oid, x509.ExtendedKeyUsage.oid}
    return problems + _end_entity_criticals(signer, table, allowed)


def issuer_of(cert: x509.Certificate, candidates: list[x509.Certificate]) -> x509.Certificate | None:
    """The certificate among `candidates` that signed `cert`, if any."""
    for candidate in candidates:
        if candidate.subject != cert.issuer:
            continue
        try:
            cert.verify_directly_issued_by(candidate)
        except (InvalidSignature, ValueError, TypeError):
            continue
        return candidate
    return None
