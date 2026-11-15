"""Wallet providers' identifier lists (CIR 2024/2979 Annex II EAA-6.2.10.1-02.3, -08 to -11, -14, -16): cunho reads
them as it reads status lists, for wallet and key attestations, and tells a revocation (Revoked) from a status it
cannot know (any other StatusError)."""

from __future__ import annotations

from typing import Any

import cbor2
import pytest

from cunho.store import MemoryStore
from cunho.trust import Trust
from cunho.wallet_status import Reference, Revoked, StatusError, WalletStatus, references
from eudi_probe.jose import EcKey, b64u

from .helpers import START, Clock, Pki
from .statuslists import ServedStatus, StatusSigner

URI = "https://wallet-provider.test/identifiers/1"
LISTED = b"\x01revoked-wallet"
MINE = b"\x02my-wallet"


def member(ident: bytes = MINE, uri: Any = URI) -> dict[str, Any]:
    return {"status": {"identifier_list": {"id": b64u(ident), "uri": uri}}}


@pytest.fixture
def signer(pki: Pki) -> StatusSigner:
    return StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)


@pytest.fixture
def served() -> ServedStatus:
    return ServedStatus()


@pytest.fixture
def status(pki: Pki, served: ServedStatus, clock: Clock) -> WalletStatus:
    return WalletStatus(served, Trust.fixed(status=[pki.wallet_ca]), clock, MemoryStore(clock))


@pytest.mark.obligation("STATUS.CLIENT_TSL")
def test_an_identifier_not_on_the_list_is_valid_and_one_on_it_is_revoked(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner
) -> None:
    served.lists[URI] = signer.identifiers(URI, [LISTED])
    status.check(member(MINE))
    with pytest.raises(Revoked, match="revoked on its wallet provider's identifier list"):
        status.check(member(LISTED))


@pytest.mark.obligation("STATUS.CLIENT_TSL")
def test_both_mechanisms_named_are_both_read(status: WalletStatus, served: ServedStatus, signer: StatusSigner) -> None:
    listed = "https://wallet-provider.test/status/9"
    served.lists[listed] = signer.token(listed, {3: 1})
    served.lists[URI] = signer.identifiers(URI, [LISTED])
    both = {"status": {"status_list": {"idx": 0, "uri": listed}, "identifier_list": {"id": b64u(MINE), "uri": URI}}}
    status.check(both)
    with pytest.raises(Revoked):
        status.check({"status": {**both["status"], "identifier_list": {"id": b64u(LISTED), "uri": URI}}})
    with pytest.raises(Revoked):
        status.check({"status": {**both["status"], "status_list": {"idx": 3, "uri": listed}}})
    assert [r.member() for r in references(both)] == [
        {"status_list": {"idx": 0, "uri": listed}},
        {"identifier_list": {"id": b64u(MINE), "uri": URI}},
    ]


def test_a_list_that_cannot_be_read_leaves_the_status_unknown(status: WalletStatus, served: ServedStatus) -> None:
    """Not served, or not a CWT: a StatusError, never Revoked, so chaining alerts and does not revoke."""
    with pytest.raises(StatusError) as caught:
        status.check(member())
    assert not isinstance(caught.value, Revoked) and "cannot be fetched" in str(caught.value)
    served.lists[URI] = b"\x01not cbor at all"
    with pytest.raises(StatusError) as caught:
        status.check(member())
    assert not isinstance(caught.value, Revoked)


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda s: s.identifiers(URI, tagged=False), "not a COSE_Sign1_Tagged CWT"),
        (lambda s: cbor2.dumps(cbor2.CBORTag(18, [b"", {}, b"", b""])), "not a COSE_Sign1_Tagged CWT"),
        (lambda s: s.identifiers(URI, protected={16: "application/statuslist+cwt"}), "wrong type"),
        (lambda s: s.identifiers(URI, protected={33: ...}), "not signed by a trusted signer"),
        (lambda s: s.identifiers(URI, protected={33: b"not a certificate"}), "not signed by a trusted signer"),
        (lambda s: s.identifiers(URI, key=EcKey.generate()), "signature does not verify"),
        (lambda s: s.identifiers("https://wallet-provider.test/identifiers/2"), "not the one the attestation names"),
        (lambda s: s.identifiers(URI, iat=START + 1234 + 600), "iat that is not in the future"),
        (lambda s: s.identifiers(URI, iat="now"), "iat that is not in the future"),
        (lambda s: s.identifiers(URI, exp=...), "no exp or has expired"),
        (lambda s: s.identifiers(URI, exp=float(START + 86_400)), "no exp or has expired"),
        (lambda s: s.identifiers(URI, exp=START + 40 * 86_400), "lives longer than cunho accepts"),
        (lambda s: s.identifiers(URI, ttl=0), "ttl is not a positive whole number"),
        (lambda s: s.identifiers(URI, ttl=True), "ttl is not a positive whole number"),
        (lambda s: s.identifiers(URI, claims={65530: {"identifiers": ["x"]}}), "map keyed by byte strings"),
        (lambda s: s.identifiers(URI, claims={65530: {"identifiers": {"text": {}}}}), "map keyed by byte strings"),
        (lambda s: s.identifiers(URI, claims={65530: ...}), "map keyed by byte strings"),
        (lambda s: s.identifiers(URI, tag=17), "not a COSE_Sign1_Tagged CWT"),
        (lambda s: s.identifiers(URI, raw_protected=cbor2.dumps([1, -7])), "not a COSE_Sign1_Tagged CWT"),
        (lambda s: s.identifiers(URI, raw_payload=cbor2.dumps([URI])), "not the one the attestation names"),
        (lambda s: s.identifiers(URI, iat=True), "iat that is not in the future"),
        (lambda s: s.identifiers(URI, iat=START + 1234 + 61), "iat that is not in the future"),
        (lambda s: s.identifiers(URI, exp=True), "no exp or has expired"),
        (lambda s: s.identifiers(URI, ttl=1.5), "ttl is not a positive whole number"),
    ],
)
def test_a_malformed_identifier_list_leaves_the_status_unknown(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, build: Any, reason: str
) -> None:
    served.lists[URI] = build(signer)
    with pytest.raises(StatusError, match=reason) as caught:
        status.check(member())
    assert not isinstance(caught.value, Revoked)


def test_an_untrusted_signer_is_refused(status: WalletStatus, served: ServedStatus, pki: Pki, clock: Clock) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    from .helpers import certificate

    other_key = ec.generate_private_key(ec.SECP256R1())
    other = certificate("Another Wallet Provider", other_key, ca=True)
    served.lists[URI] = StatusSigner.under(other, other_key).identifiers(URI)
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        status.check(member())


def test_an_identifier_list_is_judged_when_it_is_used(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    served.lists[URI] = signer.identifiers(URI, exp=START + 2000)
    status.check(member())
    clock.now = START + 2000
    with pytest.raises(StatusError, match="has no exp or has expired"):
        status.check(member())


def test_an_older_identifier_list_cannot_bring_back_a_revoked_wallet(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    served.lists[URI] = signer.identifiers(URI, [LISTED], iat=START + 1000)
    with pytest.raises(Revoked):
        status.check(member(LISTED))
    clock.now += 7200  # past the cache
    served.lists[URI] = signer.identifiers(URI, [], iat=START + 500)
    with pytest.raises(StatusError, match="older than one already seen"):
        status.check(member(LISTED))


@pytest.mark.parametrize(
    "member_value",
    [
        {"status": {"identifier_list": {"id": "not base64url!", "uri": URI}}},
        {"status": {"identifier_list": {"id": "", "uri": URI}}},
        {"status": {"identifier_list": {"id": b64u(b"x" * 65), "uri": URI}}},
        {"status": {"identifier_list": {"id": b64u(MINE), "uri": 7}}},
        {"status": {"identifier_list": {"id": b64u(MINE)}}},
        {"status": {"identifier_list": "x"}},
    ],
)
def test_a_malformed_identifier_reference_names_nothing(status: WalletStatus, member_value: Any) -> None:
    with pytest.raises(StatusError, match="identifier list entry is malformed"):
        status.check(member_value)


def test_a_reference_keeps_its_mechanism() -> None:
    assert Reference(URI, id=MINE).member() == {"identifier_list": {"id": b64u(MINE), "uri": URI}}
    assert Reference(URI, idx=4).member() == {"status_list": {"idx": 4, "uri": URI}}
    assert references(member())[0] == Reference(URI, id=MINE)


def test_an_identifier_list_past_its_exp_is_fetched_again(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    """A list is kept no longer than its exp: once it has passed, the next check fetches the current one."""
    served.lists[URI] = signer.identifiers(URI, exp=START + 1300)
    status.check(member())
    clock.now = START + 1300
    served.lists[URI] = signer.identifiers(URI, iat=START + 1290, exp=START + 90_000)
    status.check(member())


def test_an_untrusted_identifier_list_cannot_raise_the_newest_seen(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, pki: Pki, clock: Clock
) -> None:
    """A list from a signer nobody trusts is refused before its iat is kept: it cannot make the genuine lists look
    older than one seen, and lock the wallet provider out."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from .helpers import certificate

    other_key = ec.generate_private_key(ec.SECP256R1())
    other = certificate("Another Wallet Provider", other_key, ca=True)
    served.lists[URI] = StatusSigner.under(other, other_key).identifiers(URI, iat=int(clock()) + 30)
    with pytest.raises(StatusError, match="not signed by a trusted signer"):
        status.check(member())
    served.lists[URI] = signer.identifiers(URI, iat=int(clock()))
    status.check(member())


@pytest.mark.parametrize(
    ("build", "check"),
    [
        (lambda s: s.identifiers(URI, iat=START + 1234 + 60), "an iat at the clock skew allowed"),
        (lambda s: s.identifiers(URI, iat=START, exp=START + 30 * 86_400), "a list living the longest allowed"),
    ],
)
def test_an_identifier_list_at_its_limits_is_read(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, build: Any, check: str
) -> None:
    served.lists[URI] = build(signer)
    status.check(member())


def test_a_list_refused_for_its_exp_leaves_no_mark(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner, clock: Clock
) -> None:
    """A list whose exp is a boolean is refused before its iat counts as the newest seen, so a later list with an
    older iat is still read."""
    served.lists[URI] = signer.identifiers(URI, iat=START + 1000, exp=True)
    with pytest.raises(StatusError, match="no exp or has expired"):
        status.check(member())
    clock.now += 7200
    served.lists[URI] = signer.identifiers(URI, [MINE], iat=START + 500)
    with pytest.raises(Revoked):
        status.check(member())


def test_an_identifier_of_the_longest_length_is_read(
    status: WalletStatus, served: ServedStatus, signer: StatusSigner
) -> None:
    longest = b"x" * 64
    served.lists[URI] = signer.identifiers(URI, [longest])
    with pytest.raises(Revoked):
        status.check(member(longest))


def test_a_signer_without_an_ec_key_is_refused(status: WalletStatus, served: ServedStatus, pki: Pki) -> None:
    """A trusted chain whose leaf holds an RSA key, which certificate paths allow: the list cannot be verified as
    ES256, ES384 or ES512, and is refused as a status error, not a crash."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from .helpers import certificate, der_b64

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    leaf = certificate("RSA Status Signer", leaf_key, (pki.wallet_ca, pki.wallet_ca_key))  # type: ignore[arg-type]
    served.lists[URI] = StatusSigner(EcKey.generate(), [der_b64(leaf)]).identifiers(URI)
    with pytest.raises(StatusError, match="signature does not verify"):
        status.check(member())
