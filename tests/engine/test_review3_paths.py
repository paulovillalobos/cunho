"""Certificate path validation, one check per case, each refused for its own reason (review 3, N3-H1, N3-M4, N3-L9).

The second review's path tests only asked for some JoseError. A case built so that an earlier check
refuses it keeps passing when its own check is deleted, which is how the trust-anchor and chain-link
checks could be removed with the suite green. Here every negative case is built to pass every check but
one, the message names that one, and a matching positive case sits on the other side of each boundary.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from cunho.jose import ANY_POLICY, MAX_CHAIN, JoseError, validate_path

from .helpers import KA_POLICY, START

NOW = dt.datetime.fromtimestamp(START, dt.UTC)
POLICY = frozenset({KA_POLICY})
Key = Any


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(
    cn: str,
    key: Key,
    issuer: tuple[x509.Certificate, Key] | None = None,
    *,
    ca: bool = False,
    path_length: int | None = None,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    usage: x509.KeyUsage | None = None,
    eku: list[ObjectIdentifier] | None = None,
    policies: list[str] | None = None,
    extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
    digest: hashes.SHA224 | hashes.SHA256 | None = None,
    issuer_name: str | None = None,
    basic: bool = True,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(issuer_name) if issuer_name else issuer[0].subject if issuer else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - dt.timedelta(days=30))
        .not_valid_after(not_after or NOW + dt.timedelta(days=365))
    )
    if basic:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), True)
    if usage is not None:
        builder = builder.add_extension(usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if policies is not None:
        info = [x509.PolicyInformation(ObjectIdentifier(p), None) for p in policies]
        builder = builder.add_extension(x509.CertificatePolicies(info), critical=False)
    for extension, critical in extensions or []:
        builder = builder.add_extension(extension, critical=critical)
    signer = issuer[1] if issuer else key
    return builder.sign(signer, None if isinstance(signer, ed25519.Ed25519PrivateKey) else digest or hashes.SHA256())


def p256() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def usage(*, signature: bool = False, cert_sign: bool = False, crl_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(signature, False, False, False, False, cert_sign, crl_sign, False, False)


class Path3:
    """root -> mid -> leaf, all valid, the leaf carrying the KA signer policy; tests replace one part."""

    def __init__(self, **mid: Any) -> None:
        self.root_key, self.mid_key, self.leaf_key = p256(), p256(), p256()
        self.root = cert("WP Root", self.root_key, ca=True)
        self.mid = cert("WP Mid", self.mid_key, (self.root, self.root_key), ca=True, **mid)
        self.leaf = cert("KA Signer", self.leaf_key, (self.mid, self.mid_key), policies=[KA_POLICY])

    def leaf_with(self, **kind: Any) -> x509.Certificate:
        kind.setdefault("policies", [KA_POLICY])
        return cert("KA Signer", self.leaf_key, (self.mid, self.mid_key), **kind)


def refuses(chain: list[x509.Certificate], anchors: list[x509.Certificate], reason: str, **kwargs: Any) -> None:
    with pytest.raises(JoseError) as caught:
        validate_path(chain, anchors, kwargs.pop("now", NOW), **kwargs)
    assert reason in str(caught.value), f"expected {reason!r}, got {caught.value}"


def accepts(chain: list[x509.Certificate], anchors: list[x509.Certificate], **kwargs: Any) -> None:
    validate_path(chain, anchors, kwargs.pop("now", NOW), **kwargs)


def test_n3_h1_a_good_path_with_policies_and_crls_is_accepted() -> None:
    path = Path3(policies=[KA_POLICY])
    accepts([path.leaf, path.mid], [path.root], policies=POLICY)
    accepts([path.leaf, path.mid, path.root], [path.root], policies=POLICY)  # the anchor may be sent along
    crls = [crl(path.mid, path.mid_key), crl(path.root, path.root_key)]
    accepts([path.leaf, path.mid], [path.root], policies=POLICY, crls=crls)


def test_n3_h1_anchors_and_chain_shape() -> None:
    path = Path3()
    refuses([path.leaf, path.mid], [], "no trust anchors configured")
    refuses([], [path.root], "empty or too long")
    keys = [p256() for _ in range(MAX_CHAIN + 1)]
    certs = [cert("C0", keys[0], ca=True)]
    for n in range(1, MAX_CHAIN + 1):
        certs.append(cert(f"C{n}", keys[n], (certs[-1], keys[n - 1]), ca=n < MAX_CHAIN))
    chain = list(reversed(certs))  # leaf first: C5 (leaf), C4 ... C0
    accepts(chain[:MAX_CHAIN], [certs[0]])  # five certificates and the anchor C0 itself
    refuses(chain[:MAX_CHAIN] + [certs[0]], [cert("Other", p256(), ca=True)], "empty or too long")
    refuses([path.root], [path.root], "is a CA certificate")  # the anchor alone is never stripped to nothing


def test_n3_h1_untrusted_and_broken_chains_are_refused_by_their_own_checks() -> None:
    """r6 and r7: a rogue wallet provider, and a forged signer under a copied public intermediate."""
    path = Path3()
    rogue_key = p256()
    rogue_root = cert("Rogue WP", rogue_key, ca=True)
    rogue_leaf = cert("Rogue KA", p256(), (rogue_root, rogue_key))
    refuses([rogue_leaf], [path.root], "chain does not end at a trusted anchor")
    attacker_key = p256()
    fake_mid = cert("WP Mid", attacker_key, ca=True)  # same name as the real intermediate, the attacker's key
    forged = cert("Forged KA", p256(), (fake_mid, attacker_key))
    refuses([forged, path.mid], [path.root], "broken certificate chain")
    accepts([path.leaf, path.mid], [cert("Unrelated", p256(), ca=True), path.root])  # the second anchor matches


@pytest.mark.parametrize("who", ["leaf", "intermediate", "trust anchor"])
def test_n3_h1_validity_periods_and_their_boundaries(who: str) -> None:
    def build(**period: Any) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
        root_key, mid_key, leaf_key = p256(), p256(), p256()
        root = cert("R", root_key, ca=True, **(period if who == "trust anchor" else {}))
        mid = cert("M", mid_key, (root, root_key), ca=True, **(period if who == "intermediate" else {}))
        leaf = cert("L", leaf_key, (mid, mid_key), **(period if who == "leaf" else {}))
        return [leaf, mid], [root]

    reason = "trust anchor outside its validity period" if who == "trust anchor" else "outside its validity period"
    second = dt.timedelta(seconds=1)
    refuses(*build(not_after=NOW - second), reason)
    refuses(*build(not_before=NOW + second), reason)
    accepts(*build(not_after=NOW))
    accepts(*build(not_before=NOW))


def test_n3_h1_critical_extensions_and_name_constraints() -> None:
    path = Path3()
    unknown = x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.99999.7"), b"\x05\x00")
    # Not marked critical, so the name-constraints check itself is reached (critical ones are unknown-critical).
    constraints = x509.NameConstraints([x509.DNSName("wallet.test")], None)
    with pytest.raises(JoseError) as caught:
        validate_path([path.leaf_with(extensions=[(unknown, True)]), path.mid], [path.root], NOW)
    assert str(caught.value) == "leaf has an unsupported critical extension", "the client's OID is not echoed (N3-L5)"
    accepts([path.leaf_with(extensions=[(unknown, False)]), path.mid], [path.root])
    refuses([path.leaf_with(extensions=[(constraints, False)]), path.mid], [path.root], "leaf carries name constraints")
    mid = Path3(extensions=[(constraints, False)])
    refuses([mid.leaf, mid.mid], [mid.root], "intermediate carries name constraints")
    mid = Path3(extensions=[(unknown, True)])
    refuses([mid.leaf, mid.mid], [mid.root], "intermediate has an unsupported critical extension")
    root_key = p256()
    root = cert("R", root_key, ca=True, extensions=[(unknown, True)])
    refuses([cert("L", p256(), (root, root_key))], [root], "trust anchor has an unsupported critical extension")
    root = cert("R", root_key, ca=True, extensions=[(constraints, False)])
    refuses([cert("L", p256(), (root, root_key))], [root], "trust anchor carries name constraints")


def test_n3_h1_key_strength_everywhere_in_the_path() -> None:
    root_key = p256()
    root = cert("R", root_key, ca=True)
    refuses([cert("L", ec.generate_private_key(ec.SECP224R1()), (root, root_key))], [root], "leaf uses a curve outside")
    refuses([cert("L", rsa.generate_private_key(65537, 2048), (root, root_key))], [root], "leaf has an RSA key shorter")
    accepts([cert("L", rsa.generate_private_key(65537, 3072), (root, root_key))], [root])
    refuses([cert("L", ed25519.Ed25519PrivateKey.generate(), (root, root_key))], [root], "leaf uses a key type outside")
    refuses([cert("L", p256(), (root, root_key), digest=hashes.SHA224())], [root], "leaf is signed with a hash outside")
    accepts([cert("L", ec.generate_private_key(ec.BrainpoolP256R1()), (root, root_key))], [root])
    weak_key = rsa.generate_private_key(65537, 2048)
    weak = cert("Weak", weak_key, (root, root_key), ca=True)
    refuses([cert("L", p256(), (weak, weak_key)), weak], [root], "intermediate has an RSA key shorter")
    weak_root = cert("Weak root", weak_key, ca=True)
    refuses([cert("L", p256(), (weak_root, weak_key))], [weak_root], "trust anchor has an RSA key shorter")
    dsa_key = dsa.generate_private_key(2048)  # signs with SHA-256, so only the anchor's key type is wrong
    dsa_root = cert("DSA root", dsa_key, ca=True)
    refuses([cert("L", p256(), (dsa_root, dsa_key))], [dsa_root], "trust anchor uses a key type outside")
    ed_root_key = ed25519.Ed25519PrivateKey.generate()
    ed_root = cert("Ed root", ed_root_key, ca=True)
    refuses([cert("L", p256(), (ed_root, ed_root_key))], [ed_root], "leaf is signed with a hash outside")
    sha224_root = cert("R224", root_key, ca=True, digest=hashes.SHA224())
    refuses([cert("L", p256(), (sha224_root, root_key))], [sha224_root], "trust anchor is signed with a hash outside")


def test_n3_h1_ca_flags_path_length_and_key_usage() -> None:
    root_key, a_key, b_key = p256(), p256(), p256()
    root = cert("R", root_key, ca=True)
    not_ca = cert("NotCA", a_key, (root, root_key))
    refuses([cert("L", b_key, (not_ca, a_key)), not_ca], [root], "intermediate is not a CA")
    no_basic = cert("NoBasic", a_key, (root, root_key), basic=False)
    refuses([cert("L", b_key, (no_basic, a_key)), no_basic], [root], "intermediate is not a CA")
    accepts([cert("L", b_key, (root, root_key), basic=False)], [root])  # a leaf may omit basicConstraints
    leaf_root = cert("LeafRoot", root_key)  # an anchor that is not a CA
    refuses([cert("L", b_key, (leaf_root, root_key))], [leaf_root], "trust anchor is not a CA")
    # pathLenConstraint: 0 allows no intermediate below; the boundary itself is accepted.
    zero_root = cert("R0", root_key, ca=True, path_length=0)
    mid = cert("M", a_key, (zero_root, root_key), ca=True)
    refuses([cert("L", b_key, (mid, a_key)), mid], [zero_root], "trust anchor pathLenConstraint is exceeded")
    accepts([cert("L", b_key, (zero_root, root_key))], [zero_root])
    upper = cert("Upper", a_key, (root, root_key), ca=True, path_length=0)
    lower = cert("Lower", b_key, (upper, a_key), ca=True)
    refuses([cert("L", p256(), (lower, b_key)), lower, upper], [root], "intermediate pathLenConstraint is exceeded")
    accepts([cert("L", p256(), (upper, a_key)), upper], [root])
    one = cert("One", a_key, (root, root_key), ca=True, path_length=1)
    lower = cert("Lower", b_key, (one, a_key), ca=True)
    accepts([cert("L", p256(), (lower, b_key)), lower, one], [root])
    # keyCertSign
    no_sign = Path3(usage=usage(crl_sign=True))
    refuses([no_sign.leaf, no_sign.mid], [no_sign.root], "intermediate key usage does not allow certificate signing")
    ok = Path3(usage=usage(cert_sign=True))
    accepts([ok.leaf, ok.mid], [ok.root])
    no_sign_root = cert("R", root_key, ca=True, usage=usage(crl_sign=True))
    refuses(
        [cert("L", b_key, (no_sign_root, root_key))],
        [no_sign_root],
        "trust anchor key usage does not allow certificate signing",
    )


def test_n3_l9_intermediate_purposes() -> None:
    tls_only = Path3(eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
    refuses([tls_only.leaf, tls_only.mid], [tls_only.root], "intermediate is limited to purposes")
    every_foreign = Path3(
        eku=[
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.CODE_SIGNING,
            ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ExtendedKeyUsageOID.TIME_STAMPING,
            ExtendedKeyUsageOID.OCSP_SIGNING,
        ]
    )
    refuses([every_foreign.leaf, every_foreign.mid], [every_foreign.root], "intermediate is limited to purposes")
    with_any = Path3(eku=[ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE])
    accepts([with_any.leaf, with_any.mid], [with_any.root])
    mixed = Path3(eku=[ExtendedKeyUsageOID.SERVER_AUTH, ObjectIdentifier("1.3.6.1.4.1.99999.2.1")])
    accepts([mixed.leaf, mixed.mid], [mixed.root])


def test_n3_h1_leaf_signer_profile() -> None:
    path = Path3()
    chain = [path.mid]
    custom = ObjectIdentifier("1.3.6.1.4.1.99999.2.1")
    refuses([path.leaf_with(ca=True), *chain], [path.root], "the signing certificate is a CA certificate")
    self_signed = cert("KA Signer", path.leaf_key)
    refuses([self_signed], [self_signed], "leaf certificate is self-signed")
    refuses([path.leaf_with(usage=usage(crl_sign=True)), *chain], [path.root], "leaf key usage does not allow digital")
    accepts([path.leaf_with(usage=usage(signature=True)), *chain], [path.root])
    refuses(
        [path.leaf_with(eku=[custom, ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]), *chain],
        [path.root],
        "a certificate for any purpose cannot sign attestations",
    )
    for foreign in (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.OCSP_SIGNING):
        # A foreign purpose refuses the leaf even next to another one (N3-L9).
        refuses([path.leaf_with(eku=[foreign, custom]), *chain], [path.root], "TLS, code, e-mail")
    accepts([path.leaf_with(eku=[custom]), *chain], [path.root])
    held = Path3(policies=[KA_POLICY])  # the intermediate carries the policy, so the leaf decides
    accepts([held.leaf, held.mid], [held.root], policies=POLICY)
    refuses(
        [held.leaf_with(policies=None), held.mid],
        [held.root],
        "does not carry a key attestation signer policy",
        policies=POLICY,
    )
    refuses(
        [held.leaf_with(policies=["1.3.6.1.4.1.99999.1.9"]), held.mid],
        [held.root],
        "does not carry a key attestation signer policy",
        policies=POLICY,
    )
    accepts([path.leaf_with(policies=None), *chain], [path.root])  # no policy required without the setting


def test_n3_l9_policies_on_intermediates() -> None:
    plain = Path3()  # the intermediate asserts no policy at all
    refuses([plain.leaf, plain.mid], [plain.root], "intermediate does not carry", policies=POLICY)
    other = Path3(policies=["1.3.6.1.4.1.99999.1.9"])
    refuses([other.leaf, other.mid], [other.root], "intermediate does not carry", policies=POLICY)
    anything = Path3(policies=[ANY_POLICY])
    accepts([anything.leaf, anything.mid], [anything.root], policies=POLICY)
    inhibit = (x509.InhibitAnyPolicy(0), True)  # critical, as RFC 5280 §4.2.1.14 asks of CAs (review 4, N4-L3)
    root_key, mid_key = p256(), p256()
    root = cert("R", root_key, ca=True, extensions=[inhibit])
    mid = cert("M", mid_key, (root, root_key), ca=True, policies=[ANY_POLICY])
    leaf = cert("L", p256(), (mid, mid_key), policies=[KA_POLICY])
    refuses([leaf, mid], [root], "intermediate does not carry", policies=POLICY)
    upper_key = p256()
    upper = cert("U", upper_key, (root, root_key), ca=True, policies=[KA_POLICY])
    clean_root_key = p256()
    clean_root = cert("CR", clean_root_key, ca=True)
    upper = cert("U", upper_key, (clean_root, clean_root_key), ca=True, policies=[KA_POLICY], extensions=[inhibit])
    lower = cert("Lo", mid_key, (upper, upper_key), ca=True, policies=[ANY_POLICY])
    leaf = cert("L", p256(), (lower, mid_key), policies=[KA_POLICY])
    refuses([leaf, lower, upper], [clean_root], "intermediate does not carry", policies=POLICY)
    lower = cert("Lo", mid_key, (upper, upper_key), ca=True, policies=[KA_POLICY])
    leaf = cert("L", p256(), (lower, mid_key), policies=[KA_POLICY])
    accepts([leaf, lower, upper], [clean_root], policies=POLICY)
    # policyMappings, DER: SEQUENCE { SEQUENCE { OID 1.2.3, OID 1.2.4 } }
    mapping = x509.UnrecognizedExtension(ObjectIdentifier("2.5.29.33"), bytes.fromhex("300a300806022a0306022a04"))
    mapped = Path3(policies=[KA_POLICY], extensions=[(mapping, False)])
    refuses([mapped.leaf, mapped.mid], [mapped.root], "maps certificate policies", policies=POLICY)
    accepts([mapped.leaf, mapped.mid], [mapped.root])  # not looked at when no policy is required


# CRLs (N3-M4) -------------------------------------------------------------------------------------


def crl(
    issuer: x509.Certificate,
    key: Key,
    revoked: list[x509.Certificate] | None = None,
    *,
    last: dt.datetime | None = None,
    next_: dt.datetime | None = None,
    name: x509.Name | None = None,
) -> x509.CertificateRevocationList:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name or issuer.subject)
        .last_update(last or NOW - dt.timedelta(days=1))
        .next_update(next_ or NOW + dt.timedelta(days=7))
    )
    for item in revoked or []:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(item.serial_number).revocation_date(NOW).build()
        )
    return builder.sign(key, hashes.SHA256())


def test_n3_m4_revoked_certificates_are_refused() -> None:
    path = Path3()
    chain, anchors = [path.leaf, path.mid], [path.root]
    good_mid, good_root = crl(path.mid, path.mid_key), crl(path.root, path.root_key)
    refuses(
        chain, anchors, "the leaf certificate is revoked", crls=[crl(path.mid, path.mid_key, [path.leaf]), good_root]
    )
    refuses(
        chain,
        anchors,
        "the intermediate certificate is revoked",
        crls=[good_mid, crl(path.root, path.root_key, [path.mid])],
    )
    accepts(chain, anchors, crls=[crl(path.mid, path.mid_key, [path.mid]), good_root])  # a serial from another CA
    accepts(chain, anchors)  # None: revocation not checked (startup warns)


def test_n3_m4_revocation_status_unknown_fails_closed() -> None:
    path = Path3()
    chain, anchors = [path.leaf, path.mid], [path.root]
    good_root = crl(path.root, path.root_key)
    unknown = "no current revocation list covers the leaf certificate"
    refuses(chain, anchors, unknown, crls=[])
    refuses(chain, anchors, unknown, crls=[good_root])
    refuses(chain, anchors, "no current revocation list covers the intermediate", crls=[crl(path.mid, path.mid_key)])
    second = dt.timedelta(seconds=1)
    refuses(chain, anchors, unknown, crls=[crl(path.mid, path.mid_key, next_=NOW - second), good_root])
    refuses(chain, anchors, unknown, crls=[crl(path.mid, path.mid_key, last=NOW + second), good_root])
    accepts(chain, anchors, crls=[crl(path.mid, path.mid_key, next_=NOW), good_root])
    accepts(chain, anchors, crls=[crl(path.mid, path.mid_key, last=NOW), good_root])
    renamed = crl(path.mid, path.mid_key, [path.leaf], name=_name("Someone Else"))  # the right key, another name
    refuses(chain, anchors, unknown, crls=[renamed, good_root])
    forged = crl(path.mid, p256())  # right issuer name, wrong key
    refuses(chain, anchors, unknown, crls=[forged, good_root])
    accepts(chain, anchors, crls=[forged, crl(path.mid, path.mid_key), good_root])  # a valid one further on
    no_crl_sign = Path3(usage=usage(cert_sign=True))
    crls = [crl(no_crl_sign.mid, no_crl_sign.mid_key), crl(no_crl_sign.root, no_crl_sign.root_key)]
    refuses([no_crl_sign.leaf, no_crl_sign.mid], [no_crl_sign.root], unknown, crls=crls)
    with_crl_sign = Path3(usage=usage(cert_sign=True, crl_sign=True))
    crls = [crl(with_crl_sign.mid, with_crl_sign.mid_key), crl(with_crl_sign.root, with_crl_sign.root_key)]
    accepts([with_crl_sign.leaf, with_crl_sign.mid], [with_crl_sign.root], crls=crls)
