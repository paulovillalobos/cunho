"""The M3 test PKI checks itself: every chain it builds is valid, and every broken variant is broken in exactly
the way it is named for, so a test that uses one proves the check it targets (review 3, N3-H1)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cunho.jose import JoseError, validate_path
from cunho.proofs import parse_crls
from cunho.service import Issuer
from eudi_probe.jose import EcKey

from .helpers import KA_POLICY, PID_CONFIG, Wallet, refused_by
from .pki import MDOC_COUNTRY, MDOC_DS, OUTCOMES, SCHEME_OPERATOR, WIA_POLICY, Issued, OcspCase, TestPki


def crls(pki: TestPki, *names: str) -> list[x509.CertificateRevocationList]:
    return [pki.crls[n] for n in names]


def chains(pki: TestPki) -> dict[str, tuple[list[x509.Certificate], x509.Certificate, frozenset[str]]]:
    """Each chain the PKI builds: leaf first, the anchor it ends at, and the policies it is checked with."""
    wp = pki.wallet_provider
    return {
        "wia": ([wp.wia_signer.cert, wp.intermediate.cert], wp.root.cert, frozenset({WIA_POLICY})),
        "ka": ([wp.ka_signer.cert, wp.intermediate.cert], wp.root.cert, frozenset({KA_POLICY})),
        "untrusted wia": (
            [pki.untrusted.wia_signer.cert, pki.untrusted.intermediate.cert],
            pki.untrusted.root.cert,
            frozenset({WIA_POLICY}),
        ),
        "access": ([pki.access_cert.cert], pki.access_ca.cert, frozenset()),
        "credential": ([pki.credential_signer.cert], pki.issuer_root.cert, frozenset()),
        "status": ([pki.status_signer.cert], pki.issuer_root.cert, frozenset()),
        "mdoc": ([pki.mdoc_signer.cert], pki.iaca.cert, frozenset()),
    }


@pytest.mark.parametrize("label", ["wia", "ka", "untrusted wia", "access", "credential", "status", "mdoc"])
def test_every_chain_is_valid(trust_pki: TestPki, label: str) -> None:
    chain, anchor, policies = chains(trust_pki)[label]
    revocation = crls(trust_pki, "root", "intermediate") if label in ("wia", "ka") else None
    validate_path(chain, [anchor], trust_pki.now, policies, revocation)


BROKEN: dict[str, tuple[Callable[[TestPki], dict[str, Any]], str]] = {
    "another provider's chain": (
        lambda p: {"chain": [p.untrusted.wia_signer.cert, p.untrusted.intermediate.cert]},
        "chain does not end at a trusted anchor",
    ),
    "another provider's leaf under ours": (
        lambda p: {"chain": [p.untrusted.wia_signer.cert, p.wallet_provider.intermediate.cert]},
        "broken certificate chain",
    ),
    "the WIA signer revoked": (
        lambda p: {"crls": crls(p, "root", "intermediate_revoking")},
        "leaf certificate is revoked",
    ),
    "the KA signer revoked": (
        lambda p: {
            "chain": [p.wallet_provider.ka_signer.cert, p.wallet_provider.intermediate.cert],
            "policies": frozenset({KA_POLICY}),
            "crls": crls(p, "root", "intermediate_revoking"),
        },
        "leaf certificate is revoked",
    ),
    "the intermediate revoked": (
        lambda p: {"crls": crls(p, "root_revoking", "intermediate")},
        "intermediate certificate is revoked",
    ),
    "only an expired CRL": (
        lambda p: {"crls": crls(p, "root", "intermediate_expired")},
        "no current revocation list covers the leaf certificate",
    ),
    "no CRL from the root": (
        lambda p: {"crls": crls(p, "intermediate")},
        "no current revocation list covers the intermediate certificate",
    ),
    "a WIA signer checked as a KA signer": (
        lambda p: {"policies": frozenset({KA_POLICY})},
        "does not carry a key attestation signer policy its path allows",
    ),
    "an OCSP delegate as a signer": (
        lambda p: {"chain": [p.wallet_provider.ocsp_delegate.cert, p.wallet_provider.intermediate.cert]},
        "OCSP certificate cannot sign attestations",
    ),
    "the access certificate under the wallet provider": (
        lambda p: {"chain": [p.access_cert.cert]},
        "chain does not end at a trusted anchor",
    ),
    "the trusted list signer as a chain": (
        lambda p: {"chain": [p.lote_signer.cert]},
        "leaf certificate is self-signed",
    ),
    "after the certificates expire": (
        lambda p: {"now": p.wallet_provider.wia_signer.cert.not_valid_after_utc + dt.timedelta(days=1)},
        "certificate outside its validity period",
    ),
}


@pytest.mark.parametrize("label", sorted(BROKEN))
def test_every_broken_variant_fails_for_its_reason(trust_pki: TestPki, label: str) -> None:
    make, reason = BROKEN[label]
    wp = trust_pki.wallet_provider
    case: dict[str, Any] = {
        "chain": [wp.wia_signer.cert, wp.intermediate.cert],
        "anchors": [wp.root.cert],
        "now": trust_pki.now,
        "policies": frozenset({WIA_POLICY}),
        "crls": crls(trust_pki, "root", "intermediate"),
        **make(trust_pki),
    }
    with pytest.raises(JoseError, match=reason):
        validate_path(case["chain"], case["anchors"], case["now"], case["policies"], case["crls"])


@pytest.mark.parametrize("label", ["intermediate_unknown_critical", "intermediate_delta"])
def test_crls_this_validator_cannot_process_are_refused_when_loaded(trust_pki: TestPki, label: str) -> None:
    data = trust_pki.crls[label].public_bytes(serialization.Encoding.PEM)
    with pytest.raises(ValueError, match="only complete CRLs are supported"):
        parse_crls(data)
    assert parse_crls(trust_pki.crls["intermediate"].public_bytes(serialization.Encoding.PEM))


def test_the_untrusted_provider_copies_every_name_and_no_key(trust_pki: TestPki) -> None:
    ours, theirs = trust_pki.wallet_provider, trust_pki.untrusted
    for mine, other in zip(
        (ours.root, ours.intermediate, ours.wia_signer, ours.ka_signer),
        (theirs.root, theirs.intermediate, theirs.wia_signer, theirs.ka_signer),
        strict=True,
    ):
        assert mine.cert.subject == other.cert.subject
        assert mine.cert.public_key() != other.cert.public_key()


def test_the_trusted_list_signer_names_the_scheme_operator(trust_pki: TestPki) -> None:
    """ETSI TS 119 602 §6.8.0: C and O of the signer match the scheme territory (EU) and operator name."""
    for signer in (trust_pki.lote_signer, trust_pki.lote_impostor):
        subject = signer.cert.subject
        assert subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "EU"
        assert subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == SCHEME_OPERATOR
        signer.cert.verify_directly_issued_by(signer.cert)
    assert trust_pki.lote_signer.cert.public_key() != trust_pki.lote_impostor.cert.public_key()


def test_the_written_files_are_what_a_deployment_reads(trust_pki: TestPki) -> None:
    files = trust_pki.files
    assert x509.load_pem_x509_certificates(files["wallet-providers.pem"].read_bytes()) == [
        trust_pki.wallet_provider.root.cert
    ]
    assert len(parse_crls(files["wallet-providers.crl"].read_bytes())) == 2
    assert files["signing.key"].stat().st_mode & 0o777 == 0o600
    assert x509.load_pem_x509_certificates(files["access.pem"].read_bytes())[0] == trust_pki.access_cert.cert
    assert files["mdoc-signing.key"].stat().st_mode & 0o777 == 0o600
    assert x509.load_pem_x509_certificates(files["mdoc-signing.pem"].read_bytes()) == [
        trust_pki.mdoc_signer.cert,
        trust_pki.iaca.cert,
    ]


def test_the_document_signer_has_the_mdoc_profile(trust_pki: TestPki) -> None:
    """ISO/IEC 18013-5 Annex B.1.4: the document signer purpose, critical, and the IACA's country in both names."""
    signer, iaca = trust_pki.mdoc_signer.cert, trust_pki.iaca.cert
    purposes = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert purposes.critical and list(purposes.value) == [MDOC_DS]
    country = [n.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value for n in (signer.subject, iaca.subject)]
    assert country == [MDOC_COUNTRY, MDOC_COUNTRY] and signer.issuer == iaca.subject


def _key_hash(cert: x509.Certificate) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


def ocsp_outcome(case: OcspCase, issuer: Issued, now: Any) -> str:
    """What a client that follows RFC 6960 §3.2 and §4.2.2.2 concludes. Piece C's client must agree."""
    response = ocsp.load_der_ocsp_response(case.response)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "unsigned"
    request = ocsp.load_der_ocsp_request(case.request)
    asked = (request.serial_number, request.issuer_key_hash, request.issuer_name_hash, request.hash_algorithm.name)
    if (
        response.serial_number,
        response.issuer_key_hash,
        response.issuer_name_hash,
        response.hash_algorithm.name,
    ) != asked:
        return "certid"
    signer = issuer.cert
    if response.responder_key_hash != _key_hash(issuer.cert):
        named = [c for c in response.certificates if _key_hash(c) == response.responder_key_hash]
        if not named:
            return "responder"
        signer = named[0]
        try:
            signer.verify_directly_issued_by(issuer.cert)
        except (ValueError, TypeError, InvalidSignature):
            return "responder"
        purposes = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.OCSP_SIGNING not in purposes:
            return "responder"
    key = signer.public_key()
    assert isinstance(key, ec.EllipticCurvePublicKey) and response.signature_hash_algorithm is not None
    try:
        key.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(response.signature_hash_algorithm))
    except InvalidSignature:
        return "signature"
    if response.next_update_utc is None or not response.this_update_utc <= now <= response.next_update_utc:
        return "stale"
    nonce = response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    if nonce != case.nonce:
        return "nonce"
    return {
        ocsp.OCSPCertStatus.GOOD: "good",
        ocsp.OCSPCertStatus.REVOKED: "revoked",
        ocsp.OCSPCertStatus.UNKNOWN: "unknown",
    }[response.certificate_status]


def test_every_ocsp_response_is_broken_only_as_named(trust_pki: TestPki) -> None:
    outcomes = {
        label: ocsp_outcome(case, trust_pki.wallet_provider.intermediate, trust_pki.now)
        for label, case in trust_pki.ocsp.items()
    }
    assert outcomes == {label: case.outcome for label, case in trust_pki.ocsp.items()}
    assert set(outcomes.values()) == set(OUTCOMES)


def test_the_two_ocsp_delegates_differ_only_in_ocsp_nocheck(trust_pki: TestPki) -> None:
    wp = trust_pki.wallet_provider

    def nocheck(issued: Issued) -> bool:
        return any(e.oid == x509.OCSPNoCheck.oid for e in issued.cert.extensions)

    assert nocheck(wp.ocsp_delegate) and not nocheck(wp.ocsp_delegate_checked)
    for delegate in (wp.ocsp_delegate, wp.ocsp_delegate_checked):
        delegate.cert.verify_directly_issued_by(wp.intermediate.cert)
    trust_pki.untrusted.ocsp_delegate.cert.verify_directly_issued_by(trust_pki.untrusted.intermediate.cert)


def _issuer_for(make_issuer: Callable[..., Issuer], pki: TestPki, crl_file: str) -> Issuer:
    return make_issuer(
        wallet_provider_anchors=pki.files["wallet-providers.pem"],
        wallet_provider_crls=pki.files[crl_file],
        ka_signer_policy_oids=(KA_POLICY,),
    )


def _ka_wallet(wallet: Wallet, pki: TestPki, provider_ka: Issued, x5c: list[str]) -> Callable[[], Any]:
    holder = EcKey.generate()

    def issue() -> Any:
        wallet.get_token()
        nonce = wallet.c_nonce()
        attestation = wallet.key_attestation(
            [holder],
            signing_key=EcKey(provider_ka.key),
            _header={"typ": "key-attestation+jwt", "alg": "ES256", "x5c": x5c},
        )
        proof = wallet.proof(holder, nonce, key_attestation=attestation)
        return wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})

    return issue


def test_a_key_attestation_from_the_pki_is_accepted_by_the_issuer(
    make_issuer: Callable[..., Issuer], trust_pki: TestPki, wallet_for: Callable[[Issuer], Wallet]
) -> None:
    wallet = wallet_for(_issuer_for(make_issuer, trust_pki, "wallet-providers.crl"))
    wp = trust_pki.wallet_provider
    response = _ka_wallet(wallet, trust_pki, wp.ka_signer, wp.ka_x5c())()
    assert response.status_code == 200, response.text


@pytest.mark.covers("KA.CHAIN_TO_WP_LIST")
@pytest.mark.parametrize(
    ("label", "reason"),
    [("untrusted", "chain does not end at a trusted anchor"), ("revoked", "leaf certificate is revoked")],
)
def test_a_broken_key_attestation_chain_is_refused_with_its_rule(
    make_issuer: Callable[..., Issuer],
    trust_pki: TestPki,
    wallet_for: Callable[[Issuer], Wallet],
    label: str,
    reason: str,
) -> None:
    crl_file = "wallet-providers-revoking.crl" if label == "revoked" else "wallet-providers.crl"
    wallet = wallet_for(_issuer_for(make_issuer, trust_pki, crl_file))
    provider = trust_pki.untrusted if label == "untrusted" else trust_pki.wallet_provider
    response = refused_by(
        _ka_wallet(wallet, trust_pki, provider.ka_signer, provider.ka_x5c()), "KA.CHAIN_TO_WP_LIST", reason
    )
    assert response.status_code == 400 and response.json()["error"] == "invalid_proof"
