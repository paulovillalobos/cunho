"""The probe's checks of M4 (piece K) run against cunho itself, in process: the mdoc, deferred, notification and
encryption checks all pass, and each check that tries a bypass fails once the rule it tests is switched off in cunho,
so a pass means the rule held. Offers and releases go through cunho's admin API, as the probe's offer and release
commands do against a running cunho (tools/probe_local.py)."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import cbor2
import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.service import Issuer
from eudi_probe import checks, cose, jwe
from eudi_probe.checks import FAIL, PASS, REGISTRY, WARN, Outcome, issue_mdoc
from eudi_probe.context import Context, Offer, ProbeConfig
from eudi_probe.jose import EcKey, b64u, b64u_decode

from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PID_SUBJECT, Clock, Pki
from .pki import TestPki
from .test_encryption import key_file
from .test_mdoc_pid import PID_MDOC, pid_settings
from .test_probe_m3 import config_for, switch_off

ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
M4_CHECKS = sorted(c.id for c in REGISTRY if c.group in ("mdoc", "deferred", "encryption")) + ["C16", "C17", "C18"]
BYPASSED: dict[str, str | tuple[str, ...]] = {
    "D05": "VCI.DEFER.TRANSACTION_ID",
    "C17": "VCI.NOTIF.VALIDATION",
    "E04": "VCI.ENC.RESPONSE",
    # A JWE that does not open is left as it came, and refused again as no JSON object: both are switched off.
    "E05": ("VCI.ENC.REQUEST", "VCI.CRED.ERROR_CODES"),
}


class AdminContext(Context):
    """The probe's context with offers and releases made through cunho's admin API: the offer command makes an offer
    of both PID configurations, and the release command releases every held issuance. A held issuance comes from a
    login with the test login's hold for review (--hold-field review=true)."""

    def __init__(self, config: ProbeConfig, client: TestClient) -> None:
        super().__init__(config)
        self.admin = client
        self.slept: list[float] = []
        self.sleep = self.slept.append  # the waits the probe makes, without the wall clock

    def _offer_from(self, command: str, tx_code: str | None) -> Offer | None:
        body: dict[str, Any] = {"credential_configuration_ids": [PID_CONFIG, PID_MDOC], "subject": PID_SUBJECT}
        made = self.admin.post("/admin/offers", json=body, headers=ADMIN)
        assert made.status_code == 201, made.text
        return self.parse_offer(json.dumps(made.json()["credential_offer"]), tx_code)

    def release_held(self) -> bool:
        for row in self.admin.get("/admin/deferred", headers=ADMIN).json()["deferred"]:
            if row["state"] == "held":
                released = self.admin.post(f"/admin/deferred/{row['ref']}/release", headers=ADMIN)
                assert released.status_code == 200, released.text
        return True


@pytest.fixture
def m4_issuer(make_code_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path) -> Issuer:
    clock.now = time.time()  # the probe signs with the time of the machine it runs on
    keys = (key_file(tmp_path, "request.key"),)
    return make_code_issuer(**pid_settings(pki, encryption_keys=keys, deferred_interval=5))


def config(client: TestClient, pki: Pki, trust_pki: TestPki) -> ProbeConfig:
    probe = config_for(client, pki, trust_pki)
    probe.offer_cmd, probe.release_cmd, probe.hold_fields = "offer", "release", {"review": "true"}
    return probe


@pytest.fixture
def probe(m4_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> Iterator[Callable[[str], Outcome]]:
    """Run one check by id against the issuer, with a fresh context each time, as the probe's CLI would."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        yield lambda check_id: next(c for c in REGISTRY if c.id == check_id).fn(
            AdminContext(config(client, pki, trust_pki), client)
        )


@pytest.mark.parametrize("check_id", M4_CHECKS)
def test_every_m4_check_passes_against_cunho(probe: Callable[[str], Outcome], check_id: str) -> None:
    outcome = probe(check_id)
    assert outcome.status == PASS, (outcome.detail, outcome.evidence)


def test_the_m4_checks_pass_one_after_another_in_one_run(m4_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> None:
    """As the probe's command line runs them: in the catalogue's order, in one context, sharing the issuance."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        outcomes = {c.id: c.fn(ctx) for c in REGISTRY if c.id in M4_CHECKS}
    wrong = {i: (o.status, o.detail) for i, o in outcomes.items() if o.status != PASS}
    assert not wrong, wrong


@pytest.mark.parametrize("check_id", sorted(BYPASSED))
def test_each_bypass_check_fails_once_its_rule_is_switched_off(
    probe: Callable[[str], Outcome], monkeypatch: pytest.MonkeyPatch, check_id: str
) -> None:
    switch_off(BYPASSED[check_id], monkeypatch)
    outcome = probe(check_id)
    assert outcome.status in (FAIL, WARN), (BYPASSED[check_id], outcome.status, outcome.detail, outcome.evidence)


def test_every_m4_bypass_check_is_tested_with_its_rule_off() -> None:
    sensitive = {c.id for c in REGISTRY if c.sensitive and c.id in M4_CHECKS}
    assert sensitive == set(BYPASSED)


# ---------------------------------------------------------------- the probe's own COSE and JWE


def test_the_probe_kdf_gives_the_known_answer_of_rfc_7518_appendix_c() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    def private(d: str) -> ec.EllipticCurvePrivateKey:
        return ec.derive_private_key(int.from_bytes(b64u_decode(d), "big"), ec.SECP256R1())

    alice = private("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo")
    bob = private("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")
    shared = alice.exchange(ec.ECDH(), bob.public_key())
    assert b64u(jwe.concat_kdf(shared, "A128GCM", b"Alice", b"Bob")) == "VqqN6vgjbSBcIijNcacQGg"


@pytest.mark.parametrize("enc", ["A128GCM", "A256GCM"])
def test_the_probe_jwe_opens_what_it_seals_and_nothing_changed(enc: str) -> None:
    key = EcKey.generate()
    token = jwe.encrypt(b'{"a":1}', key.public_jwk(), enc, kid="k")
    opened = jwe.decrypt(token, key)
    assert opened.json() == {"a": 1} and opened.header["kid"] == "k" and opened.header["enc"] == enc
    parts = token.split(".")
    for index in (0, 2, 3, 4):
        changed = list(parts)
        raw = b64u_decode(changed[index])
        changed[index] = b64u(bytes([raw[0] ^ 1]) + raw[1:]) if index else b64u(raw.replace(b"ECDH-ES", b"ECDH-XX"))
        with pytest.raises((ValueError, KeyError)):
            jwe.decrypt(".".join(changed), key)
    with pytest.raises(ValueError, match="does not decrypt"):
        jwe.decrypt(token, EcKey.generate())
    # RFC 7518 §5.3 (the second reviewer): the last ciphertext byte moved into the tag still decrypts, unless the
    # lengths are checked; so does nothing with an IV of another length.
    moved = token.split(".")
    sealed, tag = b64u_decode(moved[3]), b64u_decode(moved[4])
    moved[3], moved[4] = b64u(sealed[:-1]), b64u(sealed[-1:] + tag)
    with pytest.raises(ValueError, match="not 12 and 16"):
        jwe.decrypt(".".join(moved), key)
    # RFC 7516 §4.1.13 (the second reviewer): a critical extension the probe does not understand refuses the JWE.
    with pytest.raises(ValueError, match="does not understand"):
        jwe.decrypt(jwe.encrypt(b"{}", key.public_jwk(), enc, crit=["unknown"], unknown=1), key)
    short = token.split(".")
    short[2] = b64u(b64u_decode(short[2])[:11])
    with pytest.raises(ValueError, match="not 12 and 16"):
        jwe.decrypt(".".join(short), key)
    with pytest.raises(ValueError, match="five parts"):
        jwe.decrypt(token.rsplit(".", 1)[0], key)
    with pytest.raises(ValueError, match="empty encrypted key"):
        jwe.decrypt(token.replace("..", ".AA.", 1), key)


def test_the_probe_reads_cbor_tags_as_sent() -> None:
    data = cbor2.dumps({"d": cbor2.CBORTag(1004, "2026-11-10"), "t": cbor2.CBORTag(0, "2026-11-10T10:00:00Z")})
    raw = cose.decode_raw(data)
    assert cose.is_full_date(raw["d"]) and cose.tdate(raw["t"], "t").year == 2026
    for bad in ("2026-11-10T10:00:00.5Z", "2026-11-10T10:00:00+01:00"):
        with pytest.raises(cose.CoseError, match="not YYYY"):
            cose.tdate(cose.decode_raw(cbor2.dumps(cbor2.CBORTag(0, bad))), "t")
    for not_a_day in ("10/11/2026", "2026-02-30", "2026-99-99"):
        assert not cose.is_full_date(cose.decode_raw(cbor2.dumps(cbor2.CBORTag(1004, not_a_day)))), not_a_day
    with pytest.raises(cose.CoseError, match="no time of the calendar"):
        cose.tdate(cose.decode_raw(cbor2.dumps(cbor2.CBORTag(0, "2026-02-30T10:00:00Z"))), "t")
    assert cose.decode_raw(bytes.fromhex("5f42010243030405ff")) == b"\x01\x02\x03\x04\x05"  # indefinite bstr
    assert cose.decode_raw(bytes.fromhex("9f0102ff")) == [1, 2]
    assert cose.decode_raw(bytes.fromhex("f93c00")) == 1.0
    for broken, reason in (
        ("a20101 01 02".replace(" ", ""), "repeated"),
        ("0000", "after"),
        ("5803", "truncated"),
        ("62c328", "UTF-8"),
        ("ff", "break"),
        ("1c", "reserved"),
        ("f0", "simple"),
        ("5f5f4161ffff", "not a definite string"),
        ("5f6161ff", "not a definite string"),
        ("5f41", "truncated"),
        ("1f", "indefinite length for CBOR major type 0"),
        ("3f", "indefinite length for CBOR major type 1"),
        ("df00", "indefinite length for CBOR major type 6"),
    ):
        with pytest.raises(cose.CoseError, match=reason):
            cose.decode_raw(bytes.fromhex(broken))


# ---------------------------------------------------------------- the mdoc checks see what is broken


def _mso(top: dict[Any, Any], change: Callable[[dict[Any, Any]], None]) -> None:
    auth = top["issuerAuth"]
    payload = cose.decode_raw(auth[2])
    mso = cose.decode_raw(payload.value)
    change(mso)
    auth[2] = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))


def _first_item(top: dict[Any, Any], change: Callable[[dict[Any, Any]], None]) -> None:
    space = next(iter(top["nameSpaces"].values()))
    item = cose.decode_raw(space[0].value)
    change(item)
    space[0] = cbor2.CBORTag(24, cbor2.dumps(item))


def _other_certificate(pki: Pki) -> bytes:
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    return x509.load_pem_x509_certificate((pki.root / "iaca.pem").read_bytes()).public_bytes(serialization.Encoding.DER)


def _flip(data: bytes) -> bytes:
    return bytes([data[0] ^ 1]) + data[1:]


BROKEN: dict[str, tuple[str, Callable[[dict[Any, Any], Pki], None]]] = {
    "short random": ("C16", lambda t, _: _first_item(t, lambda i: i.__setitem__("random", b"x"))),
    "x5chain protected": ("C16", lambda t, _: t["issuerAuth"].__setitem__(1, {})),
    "bad signature": ("I01", lambda t, _: t["issuerAuth"].__setitem__(3, _flip(t["issuerAuth"][3]))),
    "another docType": ("I02", lambda t, _: _mso(t, lambda m: m.__setitem__("docType", "org.example.other"))),
    "changed element": ("I02", lambda t, _: _first_item(t, lambda i: i.__setitem__("elementValue", "changed"))),
    "fraction of a second": (
        "I04",
        lambda t, _: _mso(
            t, lambda m: m["validityInfo"].__setitem__("validFrom", cbor2.CBORTag(0, "2026-01-01T00:00:00.5Z"))
        ),
    ),
    "ends before it starts": (
        "I04",
        lambda t, _: _mso(t, lambda m: m["validityInfo"].__setitem__("validUntil", m["validityInfo"]["validFrom"])),
    ),
    "a date not YYYY-MM-DD": (
        "I05",
        lambda t, _: _first_item(t, lambda i: i.__setitem__("elementValue", cbor2.CBORTag(1004, "10/11/2026"))),
    ),
    "status anchor of another chain": (
        "I06",
        lambda t, pki: _mso(
            t, lambda m: m["status"]["status_list"].__setitem__("certificate", _other_certificate(pki))
        ),
    ),
    "status certificate not a bstr": (
        "I06",
        lambda t, _: _mso(t, lambda m: m["status"]["status_list"].__setitem__("certificate", "MIIB...")),
    ),
    "status certificate null": (
        "I06",
        lambda t, _: _mso(t, lambda m: m["status"]["status_list"].__setitem__("certificate", None)),
    ),
    "status index not a number": (
        "I06",
        lambda t, _: _mso(t, lambda m: m["status"]["status_list"].__setitem__("idx", "1")),
    ),
}


@pytest.mark.parametrize("case", sorted(BROKEN))
def test_each_mdoc_check_fails_on_a_broken_mdoc(m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, case: str) -> None:
    """The mdoc checks verify, not only read: each fails on an mdoc broken where it looks, which the probe is given in
    place of the one cunho issued."""
    check_id, breaking = BROKEN[case]
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        raw, config_id, holder, configuration, ex = issue_mdoc(ctx)  # type: ignore[misc]
        check = next(c for c in REGISTRY if c.id == check_id)
        assert check.fn(ctx).status == PASS
        top = cose.decode_raw(raw)
        breaking(top, pki)
        ctx.cache["mdoc"] = (cbor2.dumps(top), config_id, holder, configuration, ex)
        outcome = check.fn(ctx)
    assert outcome.status == FAIL, (case, outcome.status, outcome.detail)


def test_the_mdoc_checks_fail_on_another_key_or_a_mandatory_element_left_out(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        raw, config_id, _, configuration, ex = issue_mdoc(ctx)  # type: ignore[misc]
        ctx.cache["mdoc"] = (raw, config_id, EcKey.generate(), configuration, ex)
        assert by_id("I03").fn(ctx).status == FAIL
        claims = [*configuration["credential_metadata"]["claims"], {"path": ["org.example", "x"], "mandatory": True}]
        wanting = {**configuration, "credential_metadata": {**configuration["credential_metadata"], "claims": claims}}
        ctx.cache["mdoc"] = (raw, config_id, EcKey.generate(), wanting, ex)
        outcome = by_id("I05").fn(ctx)
        assert outcome.status == FAIL and "mandatory org.example/x not issued" in outcome.detail


def by_id(check_id: str) -> Any:
    return next(c for c in REGISTRY if c.id == check_id)


def test_the_deferred_checks_wait_out_the_interval(m4_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> None:
    """OID4VCI 1.0 §8.3 (the second reviewer): the probe waits the interval of each 202 before it polls again, up to
    --deferred-wait-max; a longer one is polled early, and a refusal of such a poll is only a warning."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        assert by_id("D04").fn(ctx).status == PASS and ctx.slept == [5, 5]
        ctx = AdminContext(config(client, pki, trust_pki), client)
        ctx.config.deferred_wait_max = 1
        assert by_id("D04").fn(ctx).status == PASS and ctx.slept == []
    # OID4VCI 1.0 §8.3 (the second reviewer): a positive number, which may have a fraction, is waited out.
    ctx.config.deferred_wait_max = 60
    for interval, waited in ((0.5, [0.5]), (5.0, [5.0]), (0, []), (True, []), (float("inf"), []), ("5", [])):
        assert checks.positive_number(interval) == bool(waited), interval
        ctx.slept.clear()
        held = checks.Exchange("POST", "x", 202, {}, json.dumps({"transaction_id": "t", "interval": interval}))
        checks.wait_interval(ctx, held, [])
        assert ctx.slept == waited, interval
    early = ["polled before the 600 s interval"]
    assert checks.refused_early(early, "refused").status == WARN
    assert checks.refused_early([], "refused").status == FAIL


@pytest.mark.parametrize("check_id", ["I06", "C03"])
def test_a_status_list_past_its_exp_fails(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch, check_id: str
) -> None:
    """Token Status List §5.1, §5.2 (the second reviewer): a list read after its exp may hide a revocation."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        assert by_id(check_id).fn(ctx).status == PASS
        later = time.time() + 30 * 86_400
        monkeypatch.setattr(checks, "time", SimpleNamespace(time=lambda: later))
        outcome = by_id(check_id).fn(ctx)
    assert outcome.status == FAIL and "the list expired" in outcome.detail, outcome.detail


def test_the_status_list_times_are_read_as_the_draft_asks() -> None:
    now = int(time.time())
    assert checks.status_times(now, now + 60, 300, "iat", "exp", "ttl") == []
    assert checks.status_times(now, None, None, "iat", "exp", "ttl") == ["no exp (RECOMMENDED)", "no ttl (RECOMMENDED)"]
    problems = checks.status_times(now + 3600, now - 1, 0, "iat", "exp", "ttl")
    assert problems[0] == "iat is in the future" and problems[2] == "ttl 0 is not a positive number"
    assert problems[1].startswith(f"the list expired (exp {now - 1}, now ")
    assert checks.status_times(None, True, 1.5, "iat", "exp", "ttl") == ["no iat", "exp True is not a NumericDate"]
    # RFC 7519 §2, RFC 8392 §2 (the second reviewer): a NumericDate may have a fraction; a CWT's ttl is an integer.
    assert checks.status_times(now - 0.5, now + 60.25, 1.5, "iat", "exp", "ttl") == []
    assert checks.status_times(now, now + 60, 1.5, "iat", "exp", "ttl", whole_ttl=True) == [
        "ttl 1.5 is not an unsigned integer above 0"
    ]
    assert checks.status_times("now", float("nan"), -1, "iat", "exp", "ttl") == [
        "iat 'now' is not a NumericDate",
        "exp nan is not a NumericDate",
        "ttl -1 is not a positive number",
    ]


def _signed_list(payload: bytes, key: Any, chain: list[bytes]) -> bytes:
    """A statuslist+cwt of `payload`, signed by `key` and sending `chain` as its x5chain."""
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: PLC0415

    protected = cbor2.dumps({1: -7, 16: "application/statuslist+cwt", 33: chain})
    r, s = decode_dss_signature(
        key.sign(cbor2.dumps(["Signature1", protected, b"", payload]), ec.ECDSA(hashes.SHA256()))
    )
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, r.to_bytes(32, "big") + s.to_bytes(32, "big")]))


@pytest.mark.parametrize(
    "forgery",
    [
        "a signer prepended to the real chain",
        "a signer whose certificate expired",
        "a signer under an intermediate that is no CA",
        "a signer the reference names itself",
    ],
)
def test_a_status_list_signed_outside_its_chain_fails(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch, forgery: str
) -> None:
    """CIR 2024/2979 Annex II EAA-6.2.10.1-06.1, -13.1 (the second reviewer): the list's signer is the first
    certificate of a chain whose links all hold and are valid now, up to the reference's certificate."""
    import datetime as dt  # noqa: PLC0415

    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    from .helpers import certificate  # noqa: PLC0415

    def der(cert: Any) -> bytes:
        return bytes(cert.public_bytes(serialization.Encoding.DER))

    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        assert by_id("I06").fn(ctx).status == PASS
        raw, config_id, holder, configuration, ex = issue_mdoc(ctx)  # type: ignore[misc]
        mso = cose.issuer_signed(raw).mso
        uri = mso["status"]["status_list"]["uri"]
        real = cose.sign1(
            cose.decode_raw(ctx.http.request("GET", uri, headers={"Accept": "application/statuslist+cwt"}).content)
        )
        now = dt.datetime.now(dt.UTC)
        key = ec.generate_private_key(ec.SECP256R1())
        if forgery.startswith("a signer prepended"):
            rogue = certificate("Rogue List Signer", key)
            forged = _signed_list(real.payload, key, [der(rogue), *(der(c) for c in real.chain())])
        else:
            ca_key = ec.generate_private_key(ec.SECP256R1())
            ca = certificate("Own List CA", ca_key, ca=True)
            if forgery.endswith("names itself"):  # the second reviewer: the reference names no CA above the signer
                leaf = certificate("Self-Named List Signer", key, (ca, ca_key))
                forged = _signed_list(real.payload, key, [der(leaf)])
                anchor = der(leaf)
            elif forgery.endswith("expired"):
                leaf = certificate(
                    "Expired List Signer",
                    key,
                    (ca, ca_key),
                    not_before=now - dt.timedelta(days=10),
                    not_after=now - dt.timedelta(days=1),
                )
                forged = _signed_list(real.payload, key, [der(leaf), der(ca)])
            else:  # an end-entity certificate signing as if it were an intermediate CA (the second reviewer)
                middle_key = ec.generate_private_key(ec.SECP256R1())
                middle = certificate("Not A CA", middle_key, (ca, ca_key))
                leaf = certificate("List Signer Under It", key, (middle, middle_key))
                forged = _signed_list(real.payload, key, [der(leaf), der(middle), der(ca)])
            top = cose.decode_raw(raw)
            named = anchor if forgery.endswith("names itself") else der(ca)
            _mso(top, lambda m: m["status"]["status_list"].__setitem__("certificate", named))
            ctx.cache["mdoc"] = (cbor2.dumps(top), config_id, holder, configuration, ex)
        sent = ctx.http.request

        def serve(method: str, url: str, **kwargs: Any) -> Any:
            if url == uri:
                headers = {"content-type": "application/statuslist+cwt"}
                return checks.Exchange(method, url, 200, headers, "", kwargs.get("sent", ""), forged)
            return sent(method, url, **kwargs)

        monkeypatch.setattr(ctx.http, "request", serve)
        outcome = by_id("I06").fn(ctx)
    expected = "the list's signer itself" if forgery.endswith("names itself") else "list x5chain"
    assert outcome.status == FAIL and expected in outcome.detail, outcome.detail


def test_a_single_offer_for_an_mdoc_is_inspected_where_it_was_issued(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """A run with one static offer and --config-id an mdoc configuration (the second reviewer): C16 and the mdoc
    checks inspect the credential C01 got, since the offer cannot give a second."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        probe = config(client, pki, trust_pki)
        made = client.post(
            "/admin/offers",
            json={"credential_configuration_ids": [PID_CONFIG, PID_MDOC], "subject": PID_SUBJECT},
            headers=ADMIN,
        )
        probe.offer, probe.offer_cmd, probe.config_id = json.dumps(made.json()["credential_offer"]), None, PID_MDOC
        ctx = AdminContext(probe, client)
        outcomes = {i: by_id(i).fn(ctx).status for i in ("C01", "C16", "I01", "I02", "I03")}
    assert outcomes == dict.fromkeys(outcomes, PASS), outcomes


@pytest.mark.parametrize(("check_id", "path"), [("C18", "/notification"), ("C15", "/notification"), ("R01", "/token")])
def test_a_check_of_several_requests_errs_when_they_get_no_answer(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch, check_id: str, path: str
) -> None:
    """The second reviewer: requests that time out prove nothing, so the check errs instead of passing on them."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        sent = ctx.http.request

        def timing_out(method: str, url: str, **kwargs: Any) -> Any:
            if url == f"{ISSUER}{path}" and kwargs.get("sent") not in ("valid request", "pre-authorized code"):
                return checks.Exchange(method, url, 0, {}, "transport error: ReadTimeout()", kwargs.get("sent", ""))
            return sent(method, url, **kwargs)

        monkeypatch.setattr(ctx.http, "request", timing_out)
        outcome = by_id(check_id).fn(ctx)
    assert outcome.status == checks.ERROR, (outcome.status, outcome.detail)


def test_the_gravest_outcome_is_reported() -> None:
    passed, warned, erred, failed = (Outcome(s) for s in (PASS, WARN, checks.ERROR, FAIL))
    assert checks.gravest([passed, passed]) is None
    assert checks.gravest([passed, warned, erred]) is erred
    assert checks.gravest([erred, failed, warned]) is failed


def test_a_certificate_signs_others_only_as_a_ca_its_constraints_allow() -> None:
    """RFC 5280 §4.2.1.3, §4.2.1.9 (the second reviewer): verify_directly_issued_by checks the signature alone."""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    from .helpers import certificate  # noqa: PLC0415

    def key() -> ec.EllipticCurvePrivateKey:
        return ec.generate_private_key(ec.SECP256R1())

    signing_only = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
    assert cose.issuer_problems(certificate("CA", key(), ca=True, path_length=1), 1) == []
    assert "not a CA" in cose.issuer_problems(certificate("Leaf", key()), 0)[0]
    assert "path length" in cose.issuer_problems(certificate("CA", key(), ca=True, path_length=0), 1)[0]
    assert (
        "keyCertSign"
        in cose.issuer_problems(certificate("CA", key(), ca=True, extensions=[(signing_only, True)]), 0)[0]
    )


def test_a_confirmed_notification_bypass_stays_a_failure(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second reviewer: when the stranger's notification is taken, a refusal of the holder's own one afterwards
    (its id spent by the stranger) does not turn the bypass into an error."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        sent = ctx.http.request

        def taken_by_the_stranger(method: str, url: str, **kwargs: Any) -> Any:
            label = kwargs.get("sent", "")
            if url == f"{ISSUER}/notification" and label in ("another wallet's token", "the holder's token"):
                status, body = (
                    (204, "") if label.startswith("another") else (400, '{"error":"invalid_notification_id"}')
                )
                return checks.Exchange(method, url, status, {}, body, label)
            return sent(method, url, **kwargs)

        monkeypatch.setattr(ctx.http, "request", taken_by_the_stranger)
        outcome = by_id("C17").fn(ctx)
    assert outcome.status == FAIL and "accepted" in outcome.detail, (outcome.status, outcome.detail)


@pytest.mark.parametrize("shape", ["signer, root", "signer, intermediate", "signer, intermediate, expired root"])
def test_an_anchor_sent_in_the_list_chain_ends_its_path(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    """The second reviewer: the certificate the reference names, sent in the list's chain, ends the path there. A
    root with pathLenConstraint 0 is no CA under itself; an intermediate is not checked as its own issuer; and what
    the chain sends above it is not needed, so an expired root there changes nothing."""
    import datetime as dt  # noqa: PLC0415

    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    from .helpers import certificate  # noqa: PLC0415

    def der(cert: Any) -> bytes:
        return bytes(cert.public_bytes(serialization.Encoding.DER))

    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        raw, config_id, holder, configuration, ex = issue_mdoc(ctx)  # type: ignore[misc]
        uri = cose.issuer_signed(raw).mso["status"]["status_list"]["uri"]
        real = cose.sign1(
            cose.decode_raw(ctx.http.request("GET", uri, headers={"Accept": "application/statuslist+cwt"}).content)
        )
        root_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.UTC)
        if shape == "signer, root":
            root = certificate("List Root", root_key, ca=True, path_length=0)
            leaf = certificate("List Signer", key, (root, root_key))
            chain, named = [leaf, root], root
        else:
            ended = shape.endswith("expired root")
            span = {"not_before": now - dt.timedelta(days=10), "not_after": now - dt.timedelta(days=1)} if ended else {}
            root = certificate("List Root", root_key, ca=True, **span)  # type: ignore[arg-type]
            middle_key = ec.generate_private_key(ec.SECP256R1())
            middle = certificate("List Intermediate", middle_key, (root, root_key), ca=True, path_length=0)
            leaf = certificate("List Signer", key, (middle, middle_key))
            chain, named = ([leaf, middle, root] if ended else [leaf, middle]), middle
        forged = _signed_list(real.payload, key, [der(c) for c in chain])
        top = cose.decode_raw(raw)
        _mso(top, lambda m: m["status"]["status_list"].__setitem__("certificate", der(named)))
        ctx.cache["mdoc"] = (cbor2.dumps(top), config_id, holder, configuration, ex)
        sent = ctx.http.request

        def serve(method: str, url: str, **kwargs: Any) -> Any:
            if url == uri:
                headers = {"content-type": "application/statuslist+cwt"}
                return checks.Exchange(method, url, 200, headers, "", kwargs.get("sent", ""), forged)
            return sent(method, url, **kwargs)

        monkeypatch.setattr(ctx.http, "request", serve)
        outcome = by_id("I06").fn(ctx)
    assert outcome.status == PASS, outcome.detail


def test_the_notification_checks_use_ids_of_their_own(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second reviewer: C15 notifies the run's shared issuance, which an issuer may then spend; C17 and C18 get
    issuances of their own, so they test what they say whatever ran before."""
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        sent = ctx.http.request
        ids: dict[str, set[str]] = {}

        def recording(method: str, url: str, **kwargs: Any) -> Any:
            if url == f"{ISSUER}/notification":
                body = kwargs.get("json") or json.loads(kwargs.get("content") or b"{}")
                ids.setdefault(running[0], set()).add(str(body.get("notification_id")))
            return sent(method, url, **kwargs)

        monkeypatch.setattr(ctx.http, "request", recording)
        outcomes, running = {}, [""]
        for check_id in ("C15", "C17", "C18"):
            running[0] = check_id
            outcomes[check_id] = by_id(check_id).fn(ctx).status
    assert outcomes == dict.fromkeys(outcomes, PASS), outcomes
    assert not ids["C15"] & (ids["C17"] | ids["C18"]) and not ids["C17"] & ids["C18"], ids


@pytest.mark.parametrize("digest_of", ["the bytes sent", "a minimal encoding of them"])
def test_the_digest_is_of_the_item_bytes_as_sent(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, digest_of: str
) -> None:
    """ISO/IEC 18013-5 §9.1.2.5 (the second reviewer): the MSO digests IssuerSignedItemBytes as the issuer sent them.
    An item sent with a longer encoding of its tag and length matches a digest of those bytes only."""
    import hashlib  # noqa: PLC0415

    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        raw, config_id, holder, configuration, ex = issue_mdoc(ctx)  # type: ignore[misc]
        top = cose.decode_raw(raw)
        namespace, entries = next(iter(top["nameSpaces"].items()))
        item = cose.decode_raw(entries[0].value)
        minimal = cbor2.dumps(entries[0])
        payload = entries[0].value
        longer = b"\xd9\x00\x18\x59" + len(payload).to_bytes(2, "big") + payload  # tag 24 and length, each in 2 bytes
        digest = hashlib.sha256(longer if digest_of == "the bytes sent" else minimal).digest()
        _mso(top, lambda m: m["valueDigests"][namespace].__setitem__(item["digestID"], digest))
        sent = cbor2.dumps(top)
        assert sent.count(minimal) == 1
        ctx.cache["mdoc"] = (sent.replace(minimal, longer), config_id, holder, configuration, ex)
        outcome = by_id("I02").fn(ctx)
    assert outcome.status == (PASS if digest_of == "the bytes sent" else FAIL), outcome.detail


def test_the_tampered_request_is_wrong_in_its_tag_alone(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second reviewer: E05's request, with its tag put back, is a whole request that asks for an encrypted
    response, as E02's does; on an issuer that requires one, a request without it would be refused for that and hide
    a JWE taken unopened."""
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        sent, seen = ctx.http.request, []

        def recording(method: str, url: str, **kwargs: Any) -> Any:
            if kwargs.get("sent") == "tag changed":
                seen.append(kwargs["content"].decode("ascii"))
            return sent(method, url, **kwargs)

        monkeypatch.setattr(ctx.http, "request", recording)
        assert by_id("E05").fn(ctx).status == PASS
    [token] = seen
    parts = token.split(".")
    tag = b64u_decode(parts[4])
    parts[4] = b64u(bytes([tag[0] ^ 1]) + tag[1:])
    issuer_key = serialization.load_pem_private_key((tmp_path / "request.key").read_bytes(), None)
    body = jwe.decrypt(".".join(parts), issuer_key).json()  # type: ignore[arg-type]
    assert set(body["credential_response_encryption"]) == {"jwk", "enc"} and body["proofs"]["jwt"]


def test_a_token_command_run_inspects_the_mdoc_config_id_names(m4_issuer: Issuer, pki: Pki, trust_pki: TestPki) -> None:
    """The second reviewer: with --token-cmd the offer names no configuration, so `--config-id` an mdoc configuration
    is the one the mdoc checks ask for, as C16 did before piece K."""
    import dataclasses  # noqa: PLC0415

    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        plain = AdminContext(config(client, pki, trust_pki), client)
        offer = plain.fresh_offer()
        token = plain.get_token(offer)
        assert token is not None
        probe = dataclasses.replace(
            config(client, pki, trust_pki), offer_cmd=None, token_cmd="token", config_id=PID_MDOC
        )
        ctx = AdminContext(probe, client)
        ctx.token_from_cmd = lambda: token  # type: ignore[method-assign]
        outcomes = {i: by_id(i).fn(ctx).status for i in ("C16", "I01", "I03")}
    assert outcomes == dict.fromkeys(outcomes, PASS), outcomes


def test_a_critical_header_the_probe_does_not_understand_refuses_the_message(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """RFC 9052 §3.1 (the second reviewer): an issuerAuth rightly signed but marking a header critical that the
    probe does not understand is refused, as a conforming recipient refuses it."""
    from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: PLC0415

    signer = serialization.load_pem_private_key((pki.root / "mdoc-signing.key").read_bytes(), None)
    assert isinstance(signer, ec.EllipticCurvePrivateKey)
    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        raw, config_id, holder, configuration, ex = issue_mdoc(ctx)  # type: ignore[misc]
        top = cose.decode_raw(raw)
        auth = top["issuerAuth"]
        protected = cbor2.dumps({**cose.decode_raw(auth[0]), 2: [999], 999: "unknown semantics"})
        structure = cbor2.dumps(["Signature1", protected, b"", auth[2]])
        r, s = decode_dss_signature(signer.sign(structure, ec.ECDSA(hashes.SHA256())))
        top["issuerAuth"] = [protected, auth[1], auth[2], r.to_bytes(32, "big") + s.to_bytes(32, "big")]
        ctx.cache["mdoc"] = (cbor2.dumps(top), config_id, holder, configuration, ex)
        outcome = by_id("I01").fn(ctx)
    assert outcome.status == FAIL and "does not understand" in outcome.detail, outcome.detail


def test_the_critical_header_list_is_read_as_rfc_9052_says() -> None:
    def message(protected: dict[int, Any], unprotected: dict[int, Any] | None = None) -> cose.Sign1:
        return cose.sign1([cbor2.dumps(protected), unprotected or {}, b"", b""])

    assert message({1: -7, 16: "t", 2: [16]}).crit_problem() is None
    assert message({1: -7}).crit_problem() is None
    for sent, reason in (
        (message({1: -7}, {2: [16]}), "unprotected"),
        (message({1: -7, 2: []}), "non-empty array"),
        (message({1: -7, 2: 16}), "non-empty array"),
        (message({1: -7, 2: [16]}), "absent from the protected header"),
        (message({1: -7, 2: [999], 999: 1}), "does not understand"),
    ):
        assert reason in str(sent.crit_problem()), (sent.protected, sent.unprotected)


def test_an_offer_with_a_code_is_exchanged_even_in_a_token_command_run(
    m4_issuer: Issuer, pki: Pki, trust_pki: TestPki
) -> None:
    """The second reviewer: with --token-cmd and --deferred-offer-cmd, the held offer's pre-authorized code is
    exchanged, not replaced by the token command's grant; the token command still serves the run's own offers."""
    import dataclasses  # noqa: PLC0415

    with TestClient(
        create_app(issuer=m4_issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        probe = dataclasses.replace(config(client, pki, trust_pki), offer_cmd=None, token_cmd="token")
        ctx = AdminContext(probe, client)
        commands: list[str] = []
        ctx.token_from_cmd = lambda: commands.append("token") or None  # type: ignore[method-assign, func-returns-value]
        held = ctx.fresh_offer("held")  # as --deferred-offer-cmd prints it
        assert held is not None and held.pre_authorized_code
        token = ctx.get_token(held)
        assert token is not None and commands == []
        assert ctx.get_token(ctx.fresh_offer()) is None and commands == ["token"]


def test_a_label_in_both_header_buckets_refuses_the_message() -> None:
    """RFC 9052 §3 (the second reviewer): an alg sent again unprotected is refused, not overridden."""
    with pytest.raises(cose.CoseError, match="in both the protected and the unprotected header"):
        cose.sign1([cbor2.dumps({1: -7}), {1: -7, 33: b"x"}, b"", b""])
    assert cose.sign1([cbor2.dumps({1: -7}), {33: b"x"}, b"", b""]).unprotected == {33: b"x"}


def test_the_checks_hold_against_an_issuer_that_requires_encryption(
    make_code_issuer: Callable[..., Issuer], pki: Pki, trust_pki: TestPki, clock: Clock, tmp_path: Path
) -> None:
    """The second reviewer: against an issuer that requires encrypted requests and responses, the probe sends the
    requests it builds as a wallet would, sealed and asking for an encrypted answer, and reads the answer opened, so
    the M4 checks and C01 pass; E04 still sends its plain request, which is refused."""
    clock.now = time.time()
    keys = (key_file(tmp_path, "request.key"),)
    issuer = make_code_issuer(**pid_settings(pki, encryption_keys=keys, encryption_required=True, deferred_interval=5))
    with TestClient(
        create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER, raise_server_exceptions=False
    ) as client:
        ctx = AdminContext(config(client, pki, trust_pki), client)
        assert ctx.encryption_required()
        outcomes = {c.id: c.fn(ctx) for c in REGISTRY if c.id in [*M4_CHECKS, "C01"]}
    wrong = {i: (o.status, o.detail) for i, o in outcomes.items() if o.status != PASS}
    assert not wrong, wrong


def test_request_encryption_stands_without_response_encryption() -> None:
    """The second reviewer: an issuer that requires encrypted requests and encrypts no responses gets its requests
    sealed, without credential_response_encryption; one that encrypts responses is asked for one."""
    issuer_key = EcKey.generate()
    jwk = {**issuer_key.public_jwk(), "alg": "ECDH-ES", "kid": "issuer-1"}
    request = {"jwks": {"keys": [jwk]}, "enc_values_supported": ["A256GCM"], "encryption_required": True}
    response = {"alg_values_supported": ["ECDH-ES"], "enc_values_supported": ["A128GCM"], "encryption_required": False}
    ctx = Context(ProbeConfig(issuer=ISSUER))
    ctx.__dict__["metadata"] = {"credential_request_encryption": request}
    assert ctx.encryption_required()
    sealed = ctx.sealed({"credential_configuration_id": "x"})
    assert sealed is not None and sealed[1] is None
    opened = jwe.decrypt(sealed[0].decode(), issuer_key)
    assert opened.json() == {"credential_configuration_id": "x"} and opened.header["kid"] == "issuer-1"
    ctx.__dict__["metadata"] = {"credential_request_encryption": request, "credential_response_encryption": response}
    sealed = ctx.sealed({"credential_configuration_id": "x"})
    assert sealed is not None and sealed[1] is not None
    asked = jwe.decrypt(sealed[0].decode(), issuer_key).json()["credential_response_encryption"]
    assert asked["enc"] == "A128GCM" and asked["jwk"]["x"] == sealed[1].public_jwk()["x"]


@pytest.mark.parametrize(("header", "reason"), [("a201260126", "repeated"), ("a1012600", "after")])
def test_a_protected_header_is_read_strictly(header: str, reason: str) -> None:
    """The second reviewer: a protected header with a repeated label or trailing data is refused, as the rest of
    the message is."""
    with pytest.raises(cose.CoseError, match=reason):
        cose.sign1([bytes.fromhex(header), {}, b"", b""])


def test_header_labels_and_device_keys_are_read_by_their_types() -> None:
    """The second reviewer: true and 1.0 are no COSE labels, though Python takes them for 1; a device key names its
    curve by an integer and gives coordinates of the curve's length."""
    for protected in ({True: -7}, {1.0: -7}):
        with pytest.raises(cose.CoseError, match="not integers or text strings"):
            cose.sign1([cbor2.dumps(protected), {}, b"", b""])
    with pytest.raises(cose.CoseError, match="not integers or text strings"):
        cose.sign1([cbor2.dumps({1: -7}), {False: b"x"}, b"", b""])
    holder = EcKey.generate()
    jwk = holder.public_jwk()
    x, y = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
    good = {1: 2, -1: 1, -2: x, -3: y}
    assert cose.cose_key_public(good).public_numbers() == holder.private.public_key().public_numbers()
    for broken, reason in (
        ({**good, -1: True}, "EC2 COSE_Key"),
        ({**good, -1: 1.0}, "EC2 COSE_Key"),
        ({**good, 1: 2.0}, "EC2 COSE_Key"),
        ({**good, -2: b"\x00" + x}, "32 bytes"),
        ({**good, -3: y[1:]}, "32 bytes"),
        ({**good, -3: bytes(32)}, "not a point"),
    ):
        with pytest.raises(cose.CoseError, match=reason):
            cose.cose_key_public(broken)
