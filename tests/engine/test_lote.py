"""The Commission's list of wallet providers (piece B): ETSI TS 119 602 Annex E, read as the source of the wallet
providers' trust anchors."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cunho.errors import ConfigError
from cunho.lote import (
    ISSUANCE,
    LOTE_TYPE,
    MAX_DEPTH,
    MAX_LOTE,
    REVOCATION,
    LoteError,
    LoteFile,
    TrustedList,
    read_lote,
    six_months_after,
)
from cunho.store import MemoryStore
from eudi_probe.jose import EcKey, b64u, jws

from .helpers import START, Clock
from .pki import DAY, SCHEME_OPERATOR, Builder, Issued, TestPki, name

NOW = dt.datetime.fromtimestamp(START, dt.UTC)
PID_LIST = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"
PLACES = [
    "root",
    "LoTE",
    "scheme",
    "entities",
    "entity",
    "services",
    "information",
    "identity",
    "certificates",
    "operator",
]


def stamp(at: dt.datetime) -> str:
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def der64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def service(kind: Any, *certs: x509.Certificate, **extra: Any) -> dict[str, Any]:
    information: dict[str, Any] = {
        "ServiceName": [{"lang": "en", "value": "Test Wallet Solution"}],
        "ServiceDigitalIdentity": {"X509Certificates": [{"val": der64(c)} for c in certs]},
        "ServiceTypeIdentifier": kind,
        **extra,
    }
    return {"ServiceInformation": {k: v for k, v in information.items() if v is not ...}}


def entity(*services: dict[str, Any]) -> dict[str, Any]:
    return {
        "TrustedEntityInformation": {
            "TEName": [{"lang": "en", "value": "Test Wallet Provider"}],
            "TEAddress": {
                "TEPostalAddress": [{"lang": "en", "StreetAddress": "Rue 1", "Country": "PT"}],
                "TEElectronicAddress": [{"lang": "en", "uriValue": "mailto:wp@example.test"}],
            },
            "TEInformationURI": [{"lang": "en", "uriValue": "https://wp.example.test"}],
        },
        "TrustedEntityServices": list(services),
    }


def lote(trust_pki: TestPki, *, entities: Any = None, **scheme: Any) -> dict[str, Any]:
    wp = trust_pki.wallet_provider
    information: dict[str, Any] = {
        "LoTEVersionIdentifier": 1,
        "LoTESequenceNumber": 1,
        "LoTEType": LOTE_TYPE,
        "SchemeOperatorName": [{"lang": "en", "value": SCHEME_OPERATOR}],
        "SchemeTerritory": "EU",
        "ListIssueDateTime": stamp(NOW - DAY),
        "NextUpdate": stamp(NOW + 30 * DAY),
        **scheme,
    }
    if entities is None:
        entities = [entity(service(ISSUANCE, wp.root.cert), service(REVOCATION, trust_pki.issuer_root.cert))]
    body: dict[str, Any] = {"ListAndSchemeInformation": {k: v for k, v in information.items() if v is not ...}}
    if entities is not ...:
        body["TrustedEntitiesList"] = entities
    return {"LoTE": body}


def sign(payload: Any, signer: Issued, **header: Any) -> bytes:
    pinned = signer.cert.public_bytes(serialization.Encoding.DER)
    head: dict[str, Any] = {
        "alg": "ES256",
        "x5c": [base64.b64encode(pinned).decode()],
        "x5t#S256": b64u(hashlib.sha256(pinned).digest()),
        "sigT": stamp(NOW - dt.timedelta(minutes=5)),
        "crit": ["sigT"],
        **header,
    }
    head = {k: v for k, v in head.items() if v is not ...}
    if isinstance(payload, bytes):
        signing_input = f"{b64u(json.dumps(head).encode())}.{b64u(payload)}"
        key = EcKey(signer.key)
        return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}".encode()
    return jws(head, payload, EcKey(signer.key)).encode()


def scheme(t: TestPki, **members: Any) -> bytes:
    """A list signed by the pinned signer, with `members` of its scheme information changed."""
    return sign(lote(t, **members), t.lote_signer)


def listing(t: TestPki, *entities: Any) -> bytes:
    return sign(lote(t, entities=list(entities)), t.lote_signer)


def identified(t: TestPki, identity: Any) -> bytes:
    """A list whose one service has `identity` as its ServiceDigitalIdentity."""
    return listing(t, entity(service(ISSUANCE, ServiceDigitalIdentity=identity)))


def read(trust_pki: TestPki, data: bytes, now: dt.datetime = NOW) -> TrustedList:
    return read_lote(data, trust_pki.lote_signer.cert, now)


def refused(trust_pki: TestPki, data: bytes, reason: str, now: dt.datetime = NOW) -> None:
    with pytest.raises(LoteError, match=reason):
        read(trust_pki, data, now)


@pytest.mark.obligation("TRUST.LOTE_PARSER_119602", "TRUST.LOTE_AUTHENTIC", "TRUST.WP_ANCHORS_FROM_LIST")
def test_a_signed_list_gives_the_wallet_providers_anchors_by_service_type(trust_pki: TestPki) -> None:
    listed = read(trust_pki, sign(lote(trust_pki, LoTESequenceNumber=7), trust_pki.lote_signer))
    assert listed.sequence == 7 and listed.next_update == NOW + 30 * DAY
    assert listed.issuance == [trust_pki.wallet_provider.root.cert]
    assert listed.revocation == [trust_pki.issuer_root.cert]


def test_a_list_with_only_x5c_or_only_x5t_naming_the_pinned_signer_is_read(trust_pki: TestPki) -> None:
    read(trust_pki, sign(lote(trust_pki), trust_pki.lote_signer, **{"x5t#S256": ...}))
    read(trust_pki, sign(lote(trust_pki), trust_pki.lote_signer, x5c=...))
    read(trust_pki, sign(lote(trust_pki), trust_pki.lote_signer, sigT=..., crit=...))


def _names_pinned(trust_pki: TestPki) -> dict[str, Any]:
    """Header members that name the pinned signer, whoever signs."""
    pinned = trust_pki.lote_signer.cert.public_bytes(serialization.Encoding.DER)
    return {"x5c": [der64(trust_pki.lote_signer.cert)], "x5t#S256": b64u(hashlib.sha256(pinned).digest())}


def _impostor_x5c(trust_pki: TestPki) -> list[str]:
    return [der64(trust_pki.lote_impostor.cert)]


@pytest.mark.parametrize(
    ("build", "reason"),
    [
        (lambda t: sign(lote(t), t.lote_impostor), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_impostor, x5c=..., **{"x5t#S256": ...}), "names no signer"),
        (lambda t: sign(lote(t), t.lote_signer, x5c=_impostor_x5c(t)), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_signer, x5c="MIIB"), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_signer, x5c=["not base64!"]), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_signer, x5c=[7]), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_signer, x5c={"k": 1}), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_signer, x5c=[]), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_signer, crit={"sigT": 1}), "not a compact JWS"),
        (lambda t: sign(lote(t), t.lote_signer, crit=[]), "not a compact JWS"),
        (lambda t: scheme(t, SchemeOperatorName=[{"lang": 7, "value": SCHEME_OPERATOR}]), "multilingual"),
        (lambda t: scheme(t, NextUpdate="2026-12-1T00:00:00Z"), "next update"),
        (lambda t: sign(lote(t), t.lote_signer, **{"x5t#S256": b64u(b"x" * 32)}), "pinned signer"),
        (lambda t: sign(lote(t), t.lote_impostor, **_names_pinned(t)), "does not verify"),
        (lambda t: sign(lote(t), t.lote_signer, alg="HS256"), "algorithm"),
        (lambda t: sign(lote(t), t.lote_signer, alg=[]), "algorithm"),
        (lambda t: sign(lote(t), t.lote_signer, b64=False, crit=["sigT", "b64"]), "not a compact JWS"),
        (lambda t: sign(lote(t), t.lote_signer, b64=False), "not attached"),
        (lambda t: sign(lote(t), t.lote_signer, crit=["sigD"], sigD={}), "not a compact JWS"),
        (lambda t: sign(lote(t), t.lote_signer, crit=["sigT", "sigT"]), "not a compact JWS"),
        (lambda t: sign(lote(t), t.lote_signer, crit=["sigT"], sigT=...), "not a compact JWS"),
        (lambda t: sign(lote(t), t.lote_signer, sigT=stamp(NOW + dt.timedelta(seconds=61))), "signing time"),
        (lambda t: sign(lote(t), t.lote_signer, sigT="2026-11-04T00:00:00.5Z"), "signing time"),
        (lambda t: b"not a jws", "not a compact JWS"),
        (lambda t: sign(lote(t), t.lote_signer) + b"\xff", "not a compact JWS"),
        (lambda t: sign(b'{"LoTE": {}, "LoTE": {}}', t.lote_signer), "not a compact JWS"),
        (lambda t: sign(b'{"LoTE": "\\ud800"}', t.lote_signer), "not a compact JWS"),
        (lambda t: sign(b'{"LoTE": 123456789012345678901}', t.lote_signer), "not a compact JWS"),
        (lambda t: sign(b"[1]", t.lote_signer), "not a compact JWS"),
        (lambda t: scheme(t, LoTEType=PID_LIST), "not the wallet providers list"),
        (lambda t: scheme(t, LoTEType=...), "not the wallet providers list"),
        (lambda t: scheme(t, LoTEVersionIdentifier=2), "not version 1"),
        (lambda t: scheme(t, LoTEVersionIdentifier="1"), "not version 1"),
        (lambda t: scheme(t, LoTEVersionIdentifier=True), "not version 1"),
        (lambda t: scheme(t, LoTESequenceNumber=0), "sequence number"),
        (lambda t: scheme(t, LoTESequenceNumber="2"), "sequence number"),
        (lambda t: scheme(t, LoTESequenceNumber=True), "sequence number"),
        (lambda t: scheme(t, SchemeTerritory="PT"), "territory"),
        (lambda t: scheme(t, SchemeOperatorName=[{"lang": "en", "value": "Someone Else"}]), "scheme operator"),
        (lambda t: scheme(t, SchemeOperatorName=[]), "multilingual"),
        (lambda t: scheme(t, SchemeOperatorName=SCHEME_OPERATOR), "multilingual"),
        (lambda t: scheme(t, SchemeOperatorName={"lang": "en", "value": SCHEME_OPERATOR}), "multilingual"),
        (lambda t: scheme(t, SchemeOperatorName=[{"lang": "en"}]), "multilingual"),
        (lambda t: scheme(t, SchemeOperatorName=[{"lang": "en", "value": SCHEME_OPERATOR, "x": 1}]), "does not allow"),
        (lambda t: scheme(t, ListIssueDateTime=stamp(NOW + dt.timedelta(seconds=61))), "issue date-time is in the"),
        (lambda t: scheme(t, NextUpdate=stamp(NOW)), "discarded as expired"),
        (lambda t: scheme(t, NextUpdate=stamp(six_months_after(NOW - DAY) + dt.timedelta(seconds=1))), "six months"),
        (lambda t: scheme(t, NextUpdate="2026-12-01T00:00:00"), "next update"),
        (lambda t: scheme(t, NextUpdate="2026-12-01T00:00:00.000Z"), "next update"),
        (lambda t: scheme(t, NextUpdate="2026-13-01T00:00:00Z"), "next update"),
        (lambda t: scheme(t, NextUpdate=...), "next update"),
        (lambda t: scheme(t, ListIssueDateTime=1793750400), "issue date-time"),
        (lambda t: scheme(t, Signature="x"), "does not allow"),
        (lambda t: sign({**lote(t), "Other": 1}, t.lote_signer), "does not allow"),
        (lambda t: sign({"LoTE": {**lote(t)["LoTE"], "Other": 1}}, t.lote_signer), "does not allow"),
        (lambda t: sign({"LoTE": []}, t.lote_signer), "is not an object"),
        (lambda t: sign(lote(t, entities={}), t.lote_signer), "not a sequence"),
        (lambda t: sign(lote(t, entities=[7]), t.lote_signer), "not an object"),
        (lambda t: sign(lote(t, entities=[{"TrustedEntityServices": {}}]), t.lote_signer), "not a sequence"),
        (lambda t: listing(t, entity({"ServiceInformation": {}, "Other": 1})), "does not allow"),
        (lambda t: listing(t, entity(service(ISSUANCE, Other=1))), "does not allow"),
        (
            lambda t: identified(t, {"X509Certificates": [{"val": "%%"}]}),
            "cannot be read",
        ),
        (
            lambda t: identified(t, {"X509Certificates": [{"val": "MIIB"}]}),
            "cannot be read",
        ),
        (
            lambda t: identified(t, {"X509Certificates": [{"val": 7}]}),
            "cannot be read",
        ),
        (
            lambda t: identified(t, {"X509Certificates": "x"}),
            "not a sequence",
        ),
        (
            lambda t: identified(t, {"Other": []}),
            "does not allow",
        ),
        (
            lambda t: identified(t, []),
            "not an object",
        ),
    ],
)  # fmt: skip
def test_a_list_cunho_cannot_take_anchors_from_is_refused(
    trust_pki: TestPki, build: Callable[[TestPki], bytes], reason: str
) -> None:
    refused(trust_pki, build(trust_pki), reason)


def test_the_list_dates_are_kept_to_the_second(trust_pki: TestPki) -> None:
    """Issued up to a minute ahead, next update at least a second ahead and at most 184 days after the issue."""
    issued = NOW + dt.timedelta(seconds=60)
    read(
        trust_pki,
        sign(
            lote(trust_pki, ListIssueDateTime=stamp(issued), NextUpdate=stamp(NOW + dt.timedelta(seconds=61))),
            trust_pki.lote_signer,
        ),
    )
    read(trust_pki, sign(lote(trust_pki, NextUpdate=stamp(six_months_after(NOW - DAY))), trust_pki.lote_signer))
    read(trust_pki, sign(lote(trust_pki), trust_pki.lote_signer, sigT=stamp(NOW + dt.timedelta(seconds=60))))


def test_a_pinned_signer_outside_its_validity_period_is_refused(trust_pki: TestPki) -> None:
    built = Builder(NOW - 40 * DAY, 1)
    lapsed = built.certificate(name("Test LoTE Signer", country="EU", organization=SCHEME_OPERATOR))
    data = sign(lote(trust_pki), lapsed)
    with pytest.raises(LoteError, match="outside its validity period"):
        read_lote(data, lapsed.cert, NOW)


def test_the_signer_must_be_of_the_eu_and_of_the_scheme_operator(trust_pki: TestPki) -> None:
    for country, organization in (("PT", SCHEME_OPERATOR), ("EU", "Someone Else"), (None, SCHEME_OPERATOR)):
        signer = Builder(NOW).certificate(name("Test LoTE Signer", country=country, organization=organization))
        with pytest.raises(LoteError, match="not the scheme operator"):
            read_lote(sign(lote(trust_pki), signer), signer.cert, NOW)


def test_a_list_too_large_or_too_deep_is_refused(trust_pki: TestPki) -> None:
    refused(trust_pki, b"x" * (MAX_LOTE + 1), "larger than allowed")
    deep: Any = 1
    for _ in range(MAX_DEPTH):
        deep = [deep]
    refused(trust_pki, sign(lote(trust_pki, SchemeExtensions=deep), trust_pki.lote_signer), "nested too deeply")
    shallow: Any = 1
    for _ in range(MAX_DEPTH - 4):
        shallow = [shallow]
    read(trust_pki, sign(lote(trust_pki, SchemeExtensions=shallow), trust_pki.lote_signer))


def test_services_the_profile_does_not_use_are_trusted_for_nothing(trust_pki: TestPki) -> None:
    """A service with a ServiceStatus, which Annex E forbids, or of another type, gives no anchor; one listed with
    subject key identifiers only gives none either, and a list without entities gives no anchors at all."""
    root = trust_pki.wallet_provider.root.cert
    granted = "http://uri.etsi.org/19602/Status/granted"
    entities = [
        entity(
            service(ISSUANCE, root, ServiceStatus=granted),
            service("http://uri.etsi.org/19602/SvcType/PID/Issuance", root),
            service(..., root),
            service(ISSUANCE, ServiceDigitalIdentity={"X509SKIs": ["AAAA"]}),
        )
    ]  # fmt: skip
    listed = read(trust_pki, sign(lote(trust_pki, entities=entities), trust_pki.lote_signer))
    assert listed.issuance == [] and listed.revocation == []
    empty = read(trust_pki, sign(lote(trust_pki, entities=...), trust_pki.lote_signer))
    assert empty.issuance == [] and empty.revocation == []


def test_a_list_with_a_trailing_newline_is_read(trust_pki: TestPki) -> None:
    read(trust_pki, sign(lote(trust_pki), trust_pki.lote_signer) + b"\n")


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    hostile=st.recursive(
        st.none()
        | st.booleans()
        | st.integers(-(2**60), 2**60)
        | st.text(max_size=12)
        | st.floats(allow_nan=False, allow_infinity=False),
        lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=8), inner, max_size=4),
        max_leaves=20,
    ),
    where=st.sampled_from(PLACES),
)  # fmt: skip
def test_a_correctly_signed_list_with_hostile_content_is_read_or_refused_never_more(
    trust_pki: TestPki, hostile: Any, where: str
) -> None:
    """Lesson N4-M1: fuzzing starts after the signature, so the checks behind it are reached."""
    wp = trust_pki.wallet_provider
    body = lote(trust_pki)
    information = body["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]["ServiceInformation"]
    places: dict[str, Callable[[], Any]] = {
        "root": lambda: hostile,
        "LoTE": lambda: {"LoTE": hostile},
        "scheme": lambda: body["LoTE"].__setitem__("ListAndSchemeInformation", hostile),
        "entities": lambda: body["LoTE"].__setitem__("TrustedEntitiesList", hostile),
        "entity": lambda: body["LoTE"]["TrustedEntitiesList"].append(hostile),
        "services": lambda: body["LoTE"]["TrustedEntitiesList"][0].__setitem__("TrustedEntityServices", hostile),
        "information": lambda: information.__setitem__("ServiceTypeIdentifier", hostile),
        "identity": lambda: information.__setitem__("ServiceDigitalIdentity", hostile),
        "certificates": lambda: information["ServiceDigitalIdentity"].__setitem__("X509Certificates", hostile),
        "operator": lambda: body["LoTE"]["ListAndSchemeInformation"].__setitem__("SchemeOperatorName", hostile),
    }
    changed = places[where]()
    payload = changed if where in ("root", "LoTE") else body
    try:
        listed = read(trust_pki, sign(payload, trust_pki.lote_signer))
    except LoteError:
        return
    assert set(listed.issuance) <= {wp.root.cert} and set(listed.revocation) <= {trust_pki.issuer_root.cert}


# The file the operator keeps current.


@pytest.fixture
def written(tmp_path: Path) -> Path:
    return tmp_path / "wallet-providers.lote"


def test_the_list_file_is_read_again_when_it_changes(trust_pki: TestPki, written: Path, clock: Clock) -> None:
    clock.now = START
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=1), trust_pki.lote_signer))
    held = LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    assert held.current() is not None and held.current().sequence == 1  # type: ignore[union-attr]
    root2 = Builder(NOW).certificate(name("Second Provider Root"), ca=True).cert
    entities = [entity(service(ISSUANCE, root2))]
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=2, entities=entities), trust_pki.lote_signer) + b"\n")
    current = held.current()
    assert current is not None and current.sequence == 2 and current.issuance == [root2]


def test_an_older_list_put_back_leaves_no_anchors_even_after_a_restart(
    trust_pki: TestPki, written: Path, clock: Clock
) -> None:
    """A list whose sequence number is lower than one seen cannot bring back a withdrawn wallet solution."""
    clock.now = START
    store = MemoryStore(clock)
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=5), trust_pki.lote_signer))
    held = LoteFile(written, trust_pki.lote_signer.cert, store, clock)
    older = sign(lote(trust_pki, LoTESequenceNumber=4), trust_pki.lote_signer)
    written.write_bytes(older + b"\n")
    assert held.current() is None
    with pytest.raises(ConfigError, match="lower than one already seen"):
        LoteFile(written, trust_pki.lote_signer.cert, store, clock)
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=5), trust_pki.lote_signer))
    current = held.current()
    assert current is not None and current.sequence == 5, "the same sequence number is the same list"


def test_a_list_file_that_goes_bad_or_runs_out_leaves_no_anchors(
    trust_pki: TestPki, written: Path, clock: Clock
) -> None:
    clock.now = START
    written.write_bytes(sign(lote(trust_pki, NextUpdate=stamp(NOW + DAY)), trust_pki.lote_signer))
    held = LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    clock.now = START + 86_399
    assert held.current() is not None
    clock.now = START + 86_400
    assert held.current() is None, "past its next update"
    clock.now = START
    written.write_bytes(b"garbage")
    assert held.current() is None
    written.unlink()
    assert held.current() is None


def test_a_list_file_that_cannot_be_used_stops_the_start(trust_pki: TestPki, written: Path, clock: Clock) -> None:
    clock.now = START
    with pytest.raises(ConfigError, match="cannot use the wallet providers list"):
        LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    written.write_bytes(sign(lote(trust_pki), trust_pki.lote_impostor))
    with pytest.raises(ConfigError, match="cannot use the wallet providers list"):
        LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)


def test_the_list_file_goes_by_the_clock_it_is_given(trust_pki: TestPki, written: Path, clock: Clock) -> None:
    """The time comes from the issuer's clock watch, never the wall clock (DESIGN.md, time)."""
    clock.now = START + 40 * 86_400
    written.write_bytes(sign(lote(trust_pki), trust_pki.lote_signer))
    with pytest.raises(ConfigError, match="discarded as expired"):
        LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)


@pytest.mark.parametrize(
    ("issued", "deadline"),
    [
        ("2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z"),
        ("2026-08-31T12:30:00Z", "2027-02-28T12:30:00Z"),
        ("2027-08-31T00:00:00Z", "2028-02-29T00:00:00Z"),
        ("2026-12-15T08:00:00Z", "2027-06-15T08:00:00Z"),
        ("2026-06-30T23:59:59Z", "2026-12-30T23:59:59Z"),
    ],
)
def test_the_next_update_is_at_most_six_calendar_months_after_the_issue(
    trust_pki: TestPki, issued: str, deadline: str
) -> None:
    """Annex E.2 counts months, not days: from 1 January the limit is 1 July, and from 31 August the end of
    February (the second reviewer)."""
    at = dt.datetime.strptime(issued, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    signer = Builder(at).certificate(name("Test LoTE Signer", country="EU", organization=SCHEME_OPERATOR))
    limit = dt.datetime.strptime(deadline, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    assert six_months_after(at) == limit
    read_lote(
        sign(lote(trust_pki, ListIssueDateTime=issued, NextUpdate=deadline), signer, sigT=issued), signer.cert, at
    )
    late = stamp(limit + dt.timedelta(seconds=1))
    with pytest.raises(LoteError, match="six months"):
        read_lote(
            sign(lote(trust_pki, ListIssueDateTime=issued, NextUpdate=late), signer, sigT=issued), signer.cert, at
        )


def test_a_list_replaced_while_it_is_read_at_the_start_is_read_again(
    trust_pki: TestPki, written: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file changes during the read at the start: the list in hand must not stand under the new stamp (the
    second reviewer)."""
    clock.now = START
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=1), trust_pki.lote_signer))
    newer = sign(lote(trust_pki, LoTESequenceNumber=2), trust_pki.lote_signer) + b"\n"
    read_file = LoteFile._read

    def read_then_replace(self: LoteFile) -> TrustedList:
        listed = read_file(self)
        written.write_bytes(newer)
        return listed

    monkeypatch.setattr(LoteFile, "_read", read_then_replace)
    held = LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    monkeypatch.setattr(LoteFile, "_read", read_file)
    current = held.current()
    assert current is not None and current.sequence == 2


def test_a_huge_list_file_is_refused_without_being_read_whole(trust_pki: TestPki, written: Path, clock: Clock) -> None:
    """A file far past the cap is refused after reading the cap and a byte, not loaded whole (the second reviewer)."""
    import tracemalloc

    clock.now = START
    with written.open("wb") as file:
        file.truncate(512 * 1024 * 1024)  # sparse: costs no disk
    tracemalloc.start()
    try:
        with pytest.raises(ConfigError, match="larger than allowed"):
            LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * MAX_LOTE


def test_a_list_another_worker_superseded_gives_no_anchors_though_its_file_looks_unchanged(
    trust_pki: TestPki, written: Path, clock: Clock
) -> None:
    """Worker A holds list 1; worker B takes list 2; list 1 is put back with its old stamp. A must not go on giving
    list 1's anchors: the highest sequence number seen is shared in the store (the second reviewer)."""
    import os

    clock.now = START
    store = MemoryStore(clock)
    first = sign(lote(trust_pki, LoTESequenceNumber=1), trust_pki.lote_signer)
    written.write_bytes(first)
    stamp_ns = written.stat().st_mtime_ns
    worker_a = LoteFile(written, trust_pki.lote_signer.cert, store, clock)
    second = sign(lote(trust_pki, LoTESequenceNumber=2, entities=...), trust_pki.lote_signer) + b"\n"
    written.write_bytes(second)
    worker_b = LoteFile(written, trust_pki.lote_signer.cert, store, clock)
    assert worker_b.current() is not None and worker_b.current().sequence == 2  # type: ignore[union-attr]
    written.write_bytes(first)
    os.utime(written, ns=(stamp_ns, stamp_ns))
    assert worker_a.current() is None
    written.write_bytes(second)
    current = worker_a.current()
    assert current is not None and current.sequence == 2


def _version_three(cert: x509.Certificate) -> x509.Certificate | bytes:
    """The certificate's DER with its version field changed from v3 (2) to an unknown 3."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return der.replace(b"\xa0\x03\x02\x01\x02", b"\xa0\x03\x02\x01\x03", 1)


def test_a_certificate_of_an_unknown_version_is_refused_and_leaves_no_anchors_behind(
    trust_pki: TestPki, written: Path, clock: Clock
) -> None:
    """The library raises InvalidVersion for it, which must be a refusal like any other, and a refresh that meets it
    must leave no list in hand (the second reviewer)."""
    bad = base64.b64encode(_version_three(trust_pki.wallet_provider.root.cert)).decode()  # type: ignore[arg-type]
    with pytest.raises(x509.InvalidVersion):
        x509.load_der_x509_certificate(base64.b64decode(bad))
    entities = [entity(service(ISSUANCE, ServiceDigitalIdentity={"X509Certificates": [{"val": bad}]}))]
    data = sign(lote(trust_pki, LoTESequenceNumber=2, entities=entities), trust_pki.lote_signer)
    refused(trust_pki, data, "cannot be read")
    clock.now = START
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=1), trust_pki.lote_signer))
    held = LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    assert held.current() is not None
    written.write_bytes(data + b"\n")
    assert held.current() is None
    assert held.current() is None, "and stays so"


def test_a_read_that_failed_is_tried_again_a_minute_later(
    trust_pki: TestPki, written: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refresh that fails for a passing reason, such as a store lock that timed out, leaves no anchors until the same
    file is read again a minute later, and then gives them back (the second reviewer)."""
    from cunho.lote import RETRY

    clock.now = START
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=1), trust_pki.lote_signer))
    held = LoteFile(written, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    written.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=2), trust_pki.lote_signer) + b"\n")
    read_file = LoteFile._read
    attempts: list[int] = []

    def locked(self: LoteFile) -> TrustedList:
        attempts.append(1)
        raise TimeoutError("database is locked")

    monkeypatch.setattr(LoteFile, "_read", locked)
    assert held.current() is None
    assert held.current() is None
    clock.now = START + RETRY - 1
    assert held.current() is None
    assert len(attempts) == 1, "not tried again within the minute"
    monkeypatch.setattr(LoteFile, "_read", read_file)
    clock.now = START + RETRY
    current = held.current()
    assert current is not None and current.sequence == 2


def test_a_list_of_exactly_the_cap_is_read_and_b64_true_is_no_reason_to_refuse(trust_pki: TestPki) -> None:
    token = sign(lote(trust_pki), trust_pki.lote_signer)
    read(trust_pki, token + b"\n" * (MAX_LOTE - len(token)))
    read(trust_pki, sign(lote(trust_pki), trust_pki.lote_signer, b64=True))


def _signer_valid(starts: dt.datetime, ends: dt.datetime) -> Issued:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    subject = name("Test LoTE Signer", country="EU", organization=SCHEME_OPERATOR)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(starts)
        .not_valid_after(ends)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return Issued(cert, key)


def test_the_pinned_signer_is_used_from_and_to_the_second_of_its_validity(
    trust_pki: TestPki, written: Path, clock: Clock
) -> None:
    """Valid from notBefore to notAfter, both included, when the list is read and at every use after."""
    signer = _signer_valid(NOW, NOW + DAY)
    data = sign(lote(trust_pki), signer, sigT=stamp(NOW))
    read_lote(data, signer.cert, NOW)
    read_lote(data, signer.cert, NOW + DAY)
    written.write_bytes(data)
    clock.now = START
    held = LoteFile(written, signer.cert, MemoryStore(clock), clock)
    assert held.current() is not None
    clock.now = START + 86_400
    assert held.current() is not None
    clock.now = START + 86_401
    assert held.current() is None


def test_a_list_in_hand_stands_when_the_stored_sequence_is_gone(
    trust_pki: TestPki, written: Path, clock: Clock
) -> None:
    """The mark is only a floor: with none in the store the list in hand is not judged by it."""
    clock.now = START
    store = MemoryStore(clock)
    written.write_bytes(sign(lote(trust_pki), trust_pki.lote_signer))
    held = LoteFile(written, trust_pki.lote_signer.cert, store, clock)
    store.delete("lote-sequence", "wallet-providers")
    assert held.current() is not None
