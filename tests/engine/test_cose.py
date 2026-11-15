"""cunho.cose: deterministic CBOR, the mdoc tags, COSE_Key and COSE_Sign1, against the RFC examples and against
a second construction of the signed bytes written here with cbor2 and cryptography alone."""

from __future__ import annotations

import hashlib
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from hypothesis import given
from hypothesis import strategies as st

from cunho import cose
from cunho.jose import b64u, jwk_from_public_key

# RFC 9052 Appendix C.2.1 (Single ECDSA Signature) and the key with kid "11" of Appendix C.7.1.
RFC_X = bytes.fromhex("bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff")
RFC_Y = bytes.fromhex("20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")
RFC_SIGNATURE = bytes.fromhex(
    "8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4d25a91aef0b0117e"
    "2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36"
)
RFC_MESSAGE = cbor2.dumps(
    cbor2.CBORTag(18, [bytes.fromhex("a10126"), {4: b"11"}, b"This is the content.", RFC_SIGNATURE])
)


class Signer:
    """A test signer with the cunho Signer interface: raw r || s signatures."""

    def __init__(self, alg: str = "ES256") -> None:
        curve, digest, size = {
            "ES256": (ec.SECP256R1(), hashes.SHA256(), 32),
            "ES384": (ec.SECP384R1(), hashes.SHA384(), 48),
            "ES512": (ec.SECP521R1(), hashes.SHA512(), 66),
        }[alg]
        self.alg, self.key, self.digest, self.size = alg, ec.generate_private_key(curve), digest, size

    def sign(self, data: bytes) -> bytes:
        r, s = decode_dss_signature(self.key.sign(data, ec.ECDSA(self.digest)))
        return r.to_bytes(self.size) + s.to_bytes(self.size)


def rfc_key() -> ec.EllipticCurvePublicKey:
    return cose.public_key({1: 2, -1: 1, -2: RFC_X, -3: RFC_Y})


def test_the_rfc_9052_example_verifies() -> None:
    assert len(RFC_MESSAGE) == 98  # "Size of binary file is 98 bytes"
    protected, unprotected, payload = cose.verify1(cose.decode(RFC_MESSAGE), rfc_key())
    assert protected == {1: -7} and unprotected == {4: b"11"} and payload == b"This is the content."


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda m: [m[0], m[1], b"This is the content!", m[3]], "does not verify"),
        (lambda m: [m[0], m[1], m[2], m[3][:-1] + bytes([m[3][-1] ^ 1])], "does not verify"),
        (lambda m: [m[0], m[1], m[2], m[3][:-1]], "wrong length"),
        (lambda m: [b"", {1: -7, 4: b"11"}, m[2], m[3]], "alg is not"),
        (lambda m: [m[0], {1: -7}, m[2], m[3]], "both buckets"),
        (lambda m: [cbor2.dumps({1: -7, 2: [99]}), m[1], m[2], m[3]], "does not understand"),
        (lambda m: [cbor2.dumps({1: -7, 99: 1}), m[1], m[2], m[3]], "does not understand"),
        (lambda m: [cbor2.dumps({1: -8}), m[1], m[2], m[3]], "alg is not"),
        (lambda m: [cbor2.dumps({1: -7.0}), m[1], m[2], m[3]], "alg is not"),
        (lambda m: [cbor2.dumps({1: [-7]}), m[1], m[2], m[3]], "alg is not"),
        (lambda m: [cbor2.dumps({1: "ES256"}), m[1], m[2], m[3]], "alg is not"),
        (lambda m: [cbor2.dumps({True: -7}), m[1], m[2], m[3]], "not an integer or a text string"),
        (lambda m: [cbor2.dumps({1.0: -7}), m[1], m[2], m[3]], "not an integer or a text string"),
        (lambda m: [m[0], {4.0: b"11"}, m[2], m[3]], "not an integer or a text string"),
        (lambda m: [m[0], {False: b"11"}, m[2], m[3]], "not an integer or a text string"),
        (lambda m: [cbor2.dumps({1: -35}), m[1], m[2], m[3]], "does not match the key's curve"),
        (lambda m: [cbor2.dumps([1, -7]), m[1], m[2], m[3]], "protected header is a map"),
        (lambda m: [m[0], m[1], None, m[3]], "byte strings"),
        (lambda m: [m[0], m[1], m[2], list(m[3])], "byte strings"),
        (lambda m: [bytearray(m[0]), m[1], m[2], m[3]], "protected header is a byte string"),
        (lambda m: [5, m[1], m[2], m[3]], "protected header is a byte string"),
        (lambda m: [m[0], [], m[2], m[3]], "unprotected one a map"),
        (lambda m: [m[0], {2: [4]}, m[2], m[3]], "does not understand"),
        (lambda m: tuple(m), "array of four"),
        (lambda m: m[:3], "array of four"),
    ],
)
def test_a_changed_rfc_example_is_refused(change: Any, reason: str) -> None:
    message = cose.decode(RFC_MESSAGE).value
    with pytest.raises(cose.CoseError, match=reason):
        cose.verify1(change(message), rfc_key())


def test_another_tag_is_not_a_sign1() -> None:
    with pytest.raises(cose.CoseError, match="not COSE_Sign1"):
        cose.verify1(cbor2.CBORTag(98, cose.decode(RFC_MESSAGE).value), rfc_key())


@pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
def test_sign1_signs_the_sig_structure_of_rfc_9052(alg: str) -> None:
    signer = Signer(alg)
    message = cose.sign1(signer, b"payload", {cose.X5T: [-16, b"t" * 32]}, {cose.X5CHAIN: b"cert"})  # type: ignore[arg-type]
    header, unprotected, payload, signature = message
    assert cbor2.loads(header) == {1: cose.ALGORITHMS[alg], 34: [-16, b"t" * 32]} and unprotected == {33: b"cert"}
    # Built again here from RFC 9052 §4.4, without cunho.cose.
    to_be_signed = cbor2.dumps(["Signature1", header, b"", b"payload"])
    half = len(signature) // 2
    der = encode_dss_signature(int.from_bytes(signature[:half]), int.from_bytes(signature[half:]))
    signer.key.public_key().verify(der, to_be_signed, ec.ECDSA(signer.digest))
    assert cose.verify1(message, signer.key.public_key())[2] == b"payload"
    assert cose.verify1(cose.decode(cose.encode(cbor2.CBORTag(18, message))), signer.key.public_key())[2] == b"payload"


def test_sign1_takes_alg_from_the_signer_only() -> None:
    with pytest.raises(cose.CoseError, match="alg comes from the signer"):
        cose.sign1(Signer(), b"", {1: -35}, {})  # type: ignore[arg-type]
    with pytest.raises(cose.CoseError, match="alg comes from the signer"):
        cose.sign1(Signer(), b"", {}, {1: -7})  # type: ignore[arg-type]
    other = Signer()
    other.alg = "EdDSA"
    with pytest.raises(cose.CoseError, match="no COSE value"):
        cose.sign1(other, b"", {}, {})  # type: ignore[arg-type]


def test_a_signature_under_another_key_is_refused() -> None:
    message = cose.sign1(Signer(), b"payload", {}, {})  # type: ignore[arg-type]
    with pytest.raises(cose.CoseError, match="does not verify"):
        cose.verify1(message, Signer().key.public_key())


def test_map_keys_are_in_the_bytewise_order_of_their_encodings() -> None:
    # The example order of RFC 8949 §4.2.1 (without its array keys, which Python cannot hash).
    keys: list[Any] = [False, "aa", "z", -1, 100, 10]
    encoded = cose.encode({key: 0 for key in keys})
    assert encoded == bytes.fromhex("a60a001864002000617a0062616100f400")
    assert cose.encode({"b": {"d": 1, "c": 2}, "a": [{"f": 1, "e": 2}]}) == cbor2.dumps(
        {"a": [{"e": 2, "f": 1}], "b": {"c": 2, "d": 1}}
    )


def test_two_keys_with_one_encoding_are_refused() -> None:
    with pytest.raises(cose.CoseError, match="two keys with the same encoding"):
        cose.encode({2**64: 1, cbor2.CBORTag(2, b"\x01" + bytes(8)): 2})


def test_integers_take_their_shortest_form() -> None:
    assert [cose.encode(n).hex() for n in (23, 24, 255, 256, 65536, -25)] == [
        "17",
        "1818",
        "18ff",
        "190100",
        "1a00010000",
        "3818",
    ]


@pytest.mark.parametrize("value", [1.5, float("nan"), __import__("datetime").date(2020, 1, 1), {1, 2}, bytearray(b"x")])
def test_values_without_a_deterministic_encoding_here_are_refused(value: Any) -> None:
    with pytest.raises(cose.CoseError, match="no deterministic encoding"):
        cose.encode({"v": [value]})


def test_tdate_is_whole_seconds_in_utc_with_z() -> None:
    assert cose.tdate(1_700_000_000.9) == cbor2.CBORTag(0, "2023-11-14T22:13:20Z")
    assert cose.encode(cose.tdate(0)).hex() == "c074" + b"1970-01-01T00:00:00Z".hex()


@pytest.mark.parametrize("text", ["2020-02-30", "2020-1-01", "20200101", "2020-01-01T00:00:00Z", 20200101])
def test_full_date_takes_a_calendar_date_only(text: Any) -> None:
    with pytest.raises(cose.CoseError):
        cose.full_date(text)


def test_full_date_is_tag_1004() -> None:
    assert cose.encode(cose.full_date("1990-07-04")).hex() == "d903ec6a" + b"1990-07-04".hex()


def test_embed_is_tag_24_around_the_deterministic_encoding() -> None:
    assert cose.embed({"b": 1, "a": 2}) == cbor2.CBORTag(24, bytes.fromhex("a2616102616201"))


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"\x01\x02", "bytes follow"),
        (b"\xa2\x01\x01\x01\x02", "Duplicate"),
        (b"\x5f\x41a\xff", "indefinite"),
        (b"\x81" * 40 + b"\x01", "depth"),
        (b"\x1b\x00", "not CBOR"),
        (b"", "not CBOR"),
    ],
)
def test_decode_is_strict(data: bytes, reason: str) -> None:
    with pytest.raises(cose.CoseError, match=reason):
        cose.decode(data)


def test_decode_keeps_every_tag_cbor2_would_interpret() -> None:
    """cbor2 turns some tags into Python objects (dates, decimals, sets, the self-described CBOR mark ...); decode
    keeps every one of them, up to tag 70000, as the tag that was encoded."""
    values: tuple[Any, ...] = (0, b"", "", [])
    for tag in range(70000):
        for value in values:
            try:
                encoded = cbor2.dumps(cbor2.CBORTag(tag, value))
            except (cbor2.CBOREncodeError, TypeError, ValueError):
                continue
            assert cose.decode(encoded) == cbor2.CBORTag(tag, value), tag
            assert cose.encode(cose.decode(encoded)) == encoded, tag


def test_decode_keeps_tags_as_signed() -> None:
    for hexed, tag in (("d903ec6a323032302d30312d3031", 1004), ("c11a5e0be100", 1), ("c249010000000000000000", 2)):
        assert cose.decode(bytes.fromhex(hexed)).tag == tag
    assert cose.decode(cose.encode(cose.tdate(0))) == cose.tdate(0)


@pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512"])
def test_a_jwk_converts_to_a_cose_key_and_back(alg: str) -> None:
    key = Signer(alg).key.public_key()
    converted = cose.cose_key(jwk_from_public_key(key))
    assert converted[1] == 2 and converted[-1] == {"ES256": 1, "ES384": 2, "ES512": 3}[alg]
    assert cose.public_key(converted).public_numbers() == key.public_numbers()


@pytest.mark.parametrize(
    "change",
    [
        lambda j: {**j, "d": b64u(b"\x01" * 32)},
        lambda j: {**j, "kty": "OKP"},
        lambda j: {**j, "crv": "secp256k1"},
        lambda j: {**j, "x": b64u(b"\x01" * 31)},
        lambda j: {k: v for k, v in j.items() if k != "y"},
        lambda j: {**j, "crv": []},
        lambda j: {**j, "crv": {"P-256": 1}},
        lambda j: {**j, "x": 7},
        lambda j: {**j, "x": "not base64url!"},
        lambda j: [j],
    ],
)
def test_only_public_ec_jwks_convert(change: Any) -> None:
    with pytest.raises(cose.CoseError):
        cose.cose_key(change(jwk_from_public_key(Signer().key.public_key())))


@pytest.mark.parametrize(
    "change",
    [
        lambda k: {**k, -4: b"\x01" * 32},
        lambda k: {**k, 1: 1},
        lambda k: {**k, -1: 6},
        lambda k: {**k, -3: True},
        lambda k: {**k, -2: k[-2][:-1]},
        lambda k: {**k, -3: bytes(32)},
        lambda k: {**k, -1: [1]},
        lambda k: {**k, -1: {1: 1}},
        lambda k: {**k, -1: True},
        lambda k: {**k, -1: 1.0},
        lambda k: {**k, 1: 2.0},
        lambda k: {**k, 1: [2]},
        lambda k: {k: v for k, v in k.items() if k != 1},
        lambda k: {True: 2, **{k: v for k, v in k.items() if k != 1}},
        lambda k: {1.0: 2, **{k: v for k, v in k.items() if k != 1}},
        lambda k: {**{k: v for k, v in k.items() if k != -1}, -1.0: 1},
        lambda k: [k],
    ],
)
def test_only_public_ec2_cose_keys_on_the_curve_load(change: Any) -> None:
    good = cose.cose_key(jwk_from_public_key(Signer().key.public_key()))
    with pytest.raises(cose.CoseError):
        cose.public_key(change(good))


@pytest.mark.parametrize(
    "change",
    [
        lambda k: {**k, -2: b"\x00" + k[-2]},
        lambda k: {**k, -3: b"\x00" + k[-3]},
        lambda k: {**k, -2: k[-2][1:]},
        lambda k: {**k, -3: k[-3][1:]},
        lambda k: {**k, -2: "a" * 32},
        lambda k: {**k, -3: list(k[-3])},
    ],
)
def test_a_cose_key_coordinate_is_a_byte_string_of_the_curves_size(change: Any) -> None:
    """A zero-padded coordinate names the same point, so only the exact size reads as that point."""
    good = cose.cose_key(jwk_from_public_key(Signer().key.public_key()))
    with pytest.raises(cose.CoseError, match="coordinates are not byte strings of the curve's size"):
        cose.public_key(change(good))


@pytest.mark.parametrize("key", ["key", b"\x01\x02", 5, None, (1, 2)])
def test_a_cose_key_is_a_map(key: Any) -> None:
    with pytest.raises(cose.CoseError, match="not a public EC2 COSE_Key"):
        cose.public_key(key)


@pytest.mark.parametrize("coordinate", ["x", "y"])
def test_a_jwk_coordinate_of_the_wrong_size_does_not_convert(coordinate: str) -> None:
    jwk = {**jwk_from_public_key(Signer().key.public_key()), coordinate: b64u(b"\x01" * 33)}
    with pytest.raises(cose.CoseError, match="wrong length"):
        cose.cose_key(jwk)


def test_decode_takes_bytes_only() -> None:
    for data in ("01", bytearray(b"\x01"), None, 1):
        with pytest.raises(cose.CoseError, match="CBOR comes as bytes"):
            cose.decode(data)  # type: ignore[arg-type]


def test_x5chain_and_x5t() -> None:
    assert cose.x5chain([b"leaf"]) == b"leaf" and cose.x5chain([b"leaf", b"ca"]) == [b"leaf", b"ca"]
    assert cose.x5chain_certificates(b"leaf") == [b"leaf"]
    assert cose.x5chain_certificates([b"leaf", b"ca"]) == [b"leaf", b"ca"]
    for bad in ([], [b""], [b"leaf", 1], "leaf", None, (b"leaf",)):
        with pytest.raises(cose.CoseError):
            cose.x5chain_certificates(bad)
    with pytest.raises(cose.CoseError):
        cose.x5chain([])
    assert cose.x5t(b"leaf") == [-16, hashlib.sha256(b"leaf").digest()]


keys: st.SearchStrategy[Any] = st.recursive(
    st.integers(-1000, 1000) | st.text(max_size=8) | st.binary(max_size=4),
    lambda inner: (
        st.lists(inner, max_size=3).map(tuple)
        | st.dictionaries(st.integers(-10, 10), inner, max_size=2).map(cbor2.frozendict)
        | st.builds(cbor2.CBORTag, st.sampled_from([24, 4000]), inner)
    ),
    max_leaves=4,
)
values = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**64), 2**64 - 1) | st.text(max_size=20) | st.binary(max_size=20),
    lambda inner: (
        st.lists(inner, max_size=4)
        | st.dictionaries(keys, inner, max_size=4)
        | st.builds(cbor2.CBORTag, st.sampled_from([24, 1004, 4000]), inner)
    ),
    max_leaves=12,
)


@given(values)
def test_encoding_is_deterministic_and_reads_back(value: Any) -> None:
    encoded = cose.encode(value)
    assert cose.encode(cose.decode(encoded)) == encoded
    reordered = cose.decode(cbor2.dumps(value))  # the same value in the caller's key order
    assert cose.encode(reordered) == encoded


def test_a_tagged_container_can_be_a_map_key() -> None:
    for hexed in ("a1d90fa0810102", "a1d90fa0a1010202", "a1d818a10102f5"):
        assert cose.encode(cose.decode(bytes.fromhex(hexed))).hex() == hexed
