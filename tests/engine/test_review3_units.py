"""Checks pinned one at a time, found by the extended mutation run (review 3, N3-H1).

Each test names the check it pins. Where a check has a boundary, both sides are tested.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.audit import GENESIS, Anchor, AuditError, AuditLog, Mark, Vault, _canonical, _key
from cunho.credentials import parse_date, validate_pid, validate_subject
from cunho.jose import (
    MAX_CHAIN,
    MAX_JWS,
    JoseError,
    alg_for_jwk,
    b64u,
    b64u_decode,
    is_self_signed,
    jwk_from_public_key,
    load_x5c,
    parse_jws,
    public_key_from_jwk,
    strict_json,
    verify,
)
from cunho.keyring import Keyring
from cunho.service import Issuer
from cunho.store import MemoryStore, SqliteStore

from .helpers import ADMIN_TOKEN, ISSUER, PID_CONFIG, PID_SUBJECT, Clock, EcKey, Pki, Wallet, certificate, der_b64

AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
TODAY = dt.date(2026, 11, 4)


# jose primitives ----------------------------------------------------------------------------------


def test_b64u_decode_is_strict() -> None:
    assert b64u_decode("") == b"" and b64u_decode("AQ") == b"\x01" and b64u_decode("AQI") == b"\x01\x02"
    for value, reason in (
        (1, "not base64url"),
        ("A+", "not base64url"),
        ("AQ==", "not base64url"),
        ("A", "not base64url"),
        ("AQIDB", "not base64url"),
        ("AR", "non-canonical base64url"),  # stray bits after the last byte
        ("AQJ", "non-canonical base64url"),
    ):
        with pytest.raises(JoseError) as caught:
            b64u_decode(value)
        assert str(caught.value) == reason, value


def test_strict_json_refuses_constants_duplicates_and_depth() -> None:
    for text, reason in (
        ("NaN", "NaN is not valid JSON"),
        ("[Infinity]", "Infinity is not valid JSON"),
        ("-Infinity", "-Infinity is not valid JSON"),
        ('{"a":1,"a":2}', "duplicate member name"),
        ("[" * 100_000 + "]" * 100_000, "JSON nested too deeply"),
    ):
        with pytest.raises(ValueError) as caught:
            strict_json(text)
        assert str(caught.value) == reason, text


def _jws(header: Any, payload: Any, signature: bytes = b"\x00" * 64) -> str:
    def part(value: Any) -> str:
        return b64u(value if isinstance(value, bytes) else json.dumps(value).encode())

    return f"{part(header)}.{part(payload)}.{b64u(signature)}"


def _token_of_length(length: int) -> str:
    """A compact JWS of exactly `length` characters, padding the header JSON with spaces as needed."""
    signature = b64u(b"\x00" * 64)
    for spaces in range(8):
        header = b64u(("{" + " " * spaces + '"alg":"ES256"}').encode())
        room = length - len(header) - len(signature) - 2
        if room % 4 == 1:
            continue
        payload = b64u(('{"p":"' + "x" * ((3 * room) // 4 - 8) + '"}').encode())
        token = f"{header}.{payload}.{signature}"
        if len(token) == length:
            return token
    raise AssertionError("no token of that length")


def test_parse_jws_shapes_and_size() -> None:
    for token, reason in (
        (7, "not a compact JWS"),
        ("a.b", "not a compact JWS"),
        ("a.b.c.d", "not a compact JWS"),
        (_jws([], {}), "header and payload must be JSON objects"),
        (_jws({}, [1]), "header and payload must be JSON objects"),
        (_jws(b"\xff", {}), "header or payload is not valid JSON"),
        (_jws({"crit": []}, {}), "the crit header is not supported"),
    ):
        with pytest.raises(JoseError) as caught:
            parse_jws(token)
        assert reason in str(caught.value), token
    assert parse_jws(_token_of_length(MAX_JWS)).header == {"alg": "ES256"}
    with pytest.raises(JoseError, match="not a compact JWS"):
        parse_jws(_token_of_length(MAX_JWS + 1))


def test_public_key_from_jwk_table() -> None:
    key = EcKey.generate()
    jwk = key.public_jwk()
    assert public_key_from_jwk(jwk, "ES256").public_numbers() == key.private.public_key().public_numbers()
    for candidate, alg, reason in (
        (jwk, None, "alg must be ES256, ES384 or ES512"),
        (jwk, ["ES256"], "alg must be ES256, ES384 or ES512"),
        (jwk, "HS256", "alg must be ES256, ES384 or ES512"),
        ("jwk", "ES256", "only public EC keys are accepted"),
        ({**jwk, "kty": "RSA"}, "ES256", "only public EC keys are accepted"),
        (key.private_jwk(), "ES256", "only public EC keys are accepted"),
        (jwk, "ES384", "ES384 needs curve P-384"),
        ({**jwk, "x": b64u(b"\x01" * 31)}, "ES256", "bad coordinate length"),
        ({**jwk, "y": b64u(b"\x01" * 33)}, "ES256", "bad coordinate length"),
        ({**jwk, "y": jwk["x"]}, "ES256", "point is not on the curve"),
    ):
        with pytest.raises(JoseError) as caught:
            public_key_from_jwk(candidate, alg)
        assert str(caught.value) == reason, (candidate, alg)


def test_alg_and_jwk_for_curves() -> None:
    assert alg_for_jwk({"crv": "P-384"}) == "ES384" and alg_for_jwk({"crv": "P-521"}) == "ES512"
    for value in ({"crv": "secp256k1"}, "P-256", None):
        with pytest.raises(JoseError, match="only P-256, P-384 and P-521 keys are accepted"):
            alg_for_jwk(value)
    with pytest.raises(JoseError, match="unsupported curve"):
        jwk_from_public_key(ec.generate_private_key(ec.SECP256K1()).public_key())


def test_signature_verification_edges() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = EcKey.generate()
    public = key.private.public_key()
    signature = key.sign(b"data")
    assert verify("ES256", public, b"data", signature)
    assert not verify("ES256", public, b"data", signature[:-1])
    assert not verify("ES256", public, b"data", signature + b"\0")
    padded = signature[:32] + b"\x00" + signature[32:]  # the same s, one byte longer
    assert not verify("ES256", public, b"data", padded), "the signature has exactly twice the curve size"
    r, s = decode_dss_signature(key.private.sign(b"data", ec.ECDSA(hashes.SHA384())))
    confused = r.to_bytes(48, "big") + s.to_bytes(48, "big")  # a valid P-256 signature over SHA-384, sized for ES384
    assert not verify("ES384", public, b"data", confused), "ES384 needs a P-384 key"
    assert not verify("ES256", "not a key", b"data", signature) and not verify(None, public, b"data", signature)
    assert not verify("HS256", public, b"data", signature) and not verify(["ES256"], public, b"data", signature)
    assert not verify("ES256", public, b"other", signature)


def test_x5c_shape_and_self_signed_detection(pki: Pki) -> None:
    entry = der_b64(pki.ka_leaf)
    assert len(load_x5c([entry] * MAX_CHAIN)) == MAX_CHAIN
    for value in ([], [entry] * (MAX_CHAIN + 1), "x", [entry, 7], None):
        with pytest.raises(JoseError, match="x5c must be an array of 1 to 5 strings"):
            load_x5c(value)
    for value in (["AAAA"], ["***"]):
        with pytest.raises(JoseError, match="not a DER certificate"):
            load_x5c(value)
    key = ec.generate_private_key(ec.SECP256R1())
    assert is_self_signed(certificate("Self", key))
    assert not is_self_signed(pki.ka_leaf)
    impostor = certificate("Self", ec.generate_private_key(ec.SECP256R1()), (certificate("Self", key), key))
    assert not is_self_signed(impostor), "issuer name equals subject, but another key signed it"


# rulebook validation ------------------------------------------------------------------------------

CONFIG: dict[str, Any] = {
    "credential_metadata": {
        "claims": [
            {"path": ["s"], "value_type": "string", "mandatory": True},
            {"path": ["d"], "value_type": "full-date"},
            {"path": ["l"], "value_type": "list"},
            {"path": ["u"], "value_type": "uint"},
            {"path": ["date_of_issuance"], "mandatory": True},
            {"path": ["date_of_expiry"]},
            {"path": ["n", "inner"], "value_type": "string", "mandatory": True},
            {"path": ["n"]},
        ]
    }
}


@pytest.mark.parametrize(
    ("data", "problem"),
    [
        ({"s": "x", "other": 1}, "other: not defined by this credential configuration"),
        ({}, "s: mandatory and missing"),
        ({"s": "   "}, "s: must be a non-empty string"),
        ({"s": 5}, "s: must be a non-empty string"),
        ({"s": "x", "d": "2026-02-30"}, "d: must be a calendar date YYYY-MM-DD"),
        ({"s": "x", "l": "abc"}, "l: must be a list or object"),
        ({"s": "x", "u": -1}, "u: must be a non-negative integer"),
        ({"s": "x", "u": True}, "u: must be a non-negative integer"),
        ({"s": "x", "u": "1"}, "u: must be a non-negative integer"),
        ({"s": "x\udc80"}, "text values must be valid Unicode (UTF-8 encodable)"),
        ({"s": "x", "n": {"inner": "\udc80"}}, "text values must be valid Unicode (UTF-8 encodable)"),
        ({"s": "x", "l": ["\udc80"]}, "text values must be valid Unicode (UTF-8 encodable)"),
        ({"s": "x", "date_of_issuance": "soon"}, "date_of_issuance: must be a calendar date YYYY-MM-DD"),
        ({"s": "x", "date_of_expiry": "2026-11-03"}, "date_of_expiry: is in the past"),
        (
            {"s": "x", "date_of_issuance": "2026-12-02", "date_of_expiry": "2026-12-01"},
            "date_of_expiry: is before date_of_issuance",
        ),
    ],
)
def test_generic_subject_checks(data: dict[str, Any], problem: str) -> None:
    assert problem in validate_subject(CONFIG, data, TODAY)


def test_generic_subject_checks_accept_the_boundaries() -> None:
    assert validate_subject(CONFIG, {"s": "x", "u": 0, "l": {}, "d": "2026-02-28"}, TODAY) == []
    assert validate_subject(CONFIG, {"s": "x", "date_of_expiry": "2026-11-04"}, TODAY) == [], "today is not past"
    same_day = {"s": "x", "date_of_issuance": "2026-12-01", "date_of_expiry": "2026-12-01"}
    assert validate_subject(CONFIG, same_day, TODAY) == []
    assert validate_subject(CONFIG, "not an object", TODAY) == ["subject data must be a JSON object"]
    assert parse_date("2026-11-04") == TODAY and parse_date("2026-11-4") is None and parse_date(20261104) is None
    assert parse_date("x2026-11-04") is None
    assert parse_date("20261104") is None, "fromisoformat would take the basic format; the rulebook wants YYYY-MM-DD"
    issued_only = {"s": "x", "date_of_issuance": "2026-12-01"}
    assert validate_subject(CONFIG, issued_only, TODAY) == [], "no expiry date to compare with"


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        ({"nickname": "x"}, "nickname: not a PID claim name"),
        ({"place_of_birth": {"locality": "Porto", "planet": "Earth"}}, "place_of_birth.planet: not a PID member name"),
        ({"place_of_birth": {"locality": "Porto", "region": " "}}, "place_of_birth.region: must be a non-empty string"),
        ({"address": {"locality": 7}}, "address.locality: must be a non-empty string"),
        ({"birthdate": "2026-11-05"}, "birthdate: must be a past calendar date"),
        ({"birthdate": "yesterday"}, "birthdate: must be a past calendar date"),
        ({"place_of_birth": "Porto"}, "place_of_birth: needs at least one of country, region, locality"),
        ({"place_of_birth": {"region": ""}}, "place_of_birth: needs at least one of country, region, locality"),
        ({"place_of_birth": {"locality": "Porto", "country": "Portugal"}}, "place_of_birth.country: must be an ISO"),
        ({"nationalities": "PT"}, "nationalities: a non-empty list"),
        ({"nationalities": []}, "nationalities: a non-empty list"),
        ({"nationalities": {"PT": "x"}}, "nationalities: a non-empty list"),
        ({"nationalities": ["PT", "XX"]}, "nationalities: a non-empty list"),
        ({"issuing_country": "XX"}, "issuing_country: must be an ISO 3166-1 alpha-2 code"),
        ({"issuing_jurisdiction": "ES-MD"}, "issuing_jurisdiction: must be an ISO 3166-2 code"),
        ({"issuing_jurisdiction": 7}, "issuing_jurisdiction: must be an ISO 3166-2 code"),
        ({"picture": "data:image/png;base64,AAAA"}, "picture: must be a data URL with a base64 JPEG"),
        ({"picture": 7}, "picture: must be a data URL with a base64 JPEG"),
        ({"sex": 7}, "sex: must be one of"),
        ({"sex": True}, "sex: must be one of"),
        ({"address": "Rua"}, "address: must be an object"),
    ],
)
def test_pid_checks(change: dict[str, Any], problem: str) -> None:
    problems = validate_pid({**PID_SUBJECT, **change}, TODAY)
    assert any(p.startswith(problem) for p in problems), problems


def test_pid_checks_accept_their_boundaries() -> None:
    assert validate_pid({**PID_SUBJECT, "birthdate": "2026-11-04"}, TODAY) == [], "born today is not in the future"
    assert validate_pid({**PID_SUBJECT, "picture": ""}, TODAY) == [], "an opted-out portrait is empty"
    assert validate_pid({**PID_SUBJECT, "picture": "data:image/jpeg;base64,/9j/"}, TODAY) == []
    assert validate_pid({**PID_SUBJECT, "sex": 9, "place_of_birth": {"region": "Norte"}}, TODAY) == []
    no_birthdate = {k: v for k, v in PID_SUBJECT.items() if k != "birthdate"}
    assert validate_pid(no_birthdate, TODAY) == ["birthdate: mandatory and missing"], "missing, not malformed"
    no_country = {k: v for k, v in PID_SUBJECT.items() if k not in ("issuing_country", "issuing_jurisdiction")}
    problems = validate_pid(no_country, TODAY)
    assert problems == ["issuing_country: mandatory and missing"], problems
    without = {k: v for k, v in PID_SUBJECT.items() if k != "address"}
    assert validate_pid(without, TODAY) == []
    # A null picture is neither a JPEG nor the opt-out, which is the empty string (the second reviewer, M4 piece C).
    assert any(p.startswith("picture: must be") for p in validate_pid({**PID_SUBJECT, "picture": None}, TODAY))
    portrait_day = dt.date(2028, 8, 11)
    assert validate_pid({**PID_SUBJECT, "picture": ""}, portrait_day) == []
    assert any(p.startswith("picture: mandatory") for p in validate_pid(PID_SUBJECT, portrait_day))
    assert validate_pid(PID_SUBJECT, portrait_day - dt.timedelta(days=1)) == []


# audit internals ----------------------------------------------------------------------------------


class Forger:
    """Writes audit rows directly, MACed with the keyring: someone who holds the secret and the database."""

    def __init__(self, log: AuditLog, store: Any, keyring: Keyring) -> None:
        self.log, self.store, self.keyring = log, store, keyring

    def entry(self, seq: int, prev: str, **extra: Any) -> dict[str, Any]:
        body = {"seq": seq, "time": 1, "event": "x", "actor": "a", "data": extra, "prev": prev}
        return {**body, "mac": self.keyring.mac("audit-entry", _canonical(body))}

    def head(self, seq: int, mac: str) -> None:
        tag = self.keyring.mac("audit-head", f"{seq}:{mac}")
        self.store.put("audit-meta", "head", {"seq": seq, "mac": mac, "tag": tag}, None)

    def checkpoint(self, seq: int, mac: str, when: int) -> None:
        tag = self.keyring.mac("audit-checkpoint", f"{seq}:{mac}:{when}")
        self.store.put("audit-meta", "checkpoint", {"seq": seq, "mac": mac, "time": when, "tag": tag}, None)


def _setup(clock: Clock, path: Path | None = None) -> tuple[AuditLog, MemoryStore, Keyring, Forger]:
    store, keyring = MemoryStore(clock), Keyring.ephemeral()
    log = AuditLog(store, keyring, clock, retention=100, anchor=Anchor(path, keyring), create_anchor=True)
    return log, store, keyring, Forger(log, store, keyring)


def _crash_once(log: AuditLog, monkeypatch: pytest.MonkeyPatch, event: str) -> None:
    """Commit an entry without its anchor line, as a process that dies between the two would. Lines that a
    later transaction would catch up first are lost the same way, so several entries can be left behind."""
    assert log.anchor is not None
    real = log.anchor.write
    monkeypatch.setattr(log.anchor, "write", lambda marks: 0)
    log.append(event, "admin")
    monkeypatch.setattr(log.anchor, "write", real)


def test_catch_up_refuses_a_store_that_fell_behind_or_diverged(clock: Clock) -> None:
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    second = log.append("b", "admin")
    forger.head(1, first["mac"])
    store.delete("audit", _key(2))
    with pytest.raises(AuditError, match=r"the store \(head 1\) is behind the anchor \(sequence 2\)"):
        log.append("c", "admin")
    forger.head(2, "f" * 64)
    with pytest.raises(AuditError, match="the audit store diverges from its anchor"):
        log.append("c", "admin")
    store.put("audit", _key(2), second, None)
    forger.head(2, second["mac"])
    log.append("c", "admin")
    assert log.verify()[0]


def test_catch_up_checks_every_entry_it_anchors(clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    _crash_once(log, monkeypatch, "b")
    second = store.get("audit", _key(2))
    assert isinstance(second, dict)
    cases: list[tuple[Callable[[], None], str]] = [
        (lambda: store.delete("audit", _key(1)), "diverges from its anchor"),  # the anchored entry is gone
        (lambda: store.put("audit", _key(1), {**first, "mac": "e" * 64}, None), "diverges from its anchor"),
        (lambda: store.put("audit", _key(2), forger.entry(3, first["mac"]), None), "diverges from its anchor"),
        (lambda: store.put("audit", _key(2), forger.entry(2, "d" * 64), None), "diverges from its anchor"),
        (lambda: store.put("audit", _key(2), {**second, "event": "rewritten"}, None), "entry 2 was altered"),
        (lambda: forger.head(3, "c" * 64), "diverges from its anchor"),  # the head points past the entries
    ]
    for damage, reason in cases:
        store.put("audit", _key(1), first, None)
        store.put("audit", _key(2), second, None)
        forger.head(2, second["mac"])
        damage()
        with pytest.raises(AuditError, match=reason):
            log.append("c", "admin")
    store.put("audit", _key(1), first, None)
    store.put("audit", _key(2), second, None)
    forger.head(2, second["mac"])
    log.append("c", "admin")
    assert [line["seq"] for line in log.anchor.lines()] == [0, 1, 2, 3]  # type: ignore[union-attr]
    assert next(line for line in log.anchor.lines() if line["seq"] == 2)["time"] == second["time"]  # type: ignore[union-attr]


def test_catch_up_from_a_checkpoint(clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    _crash_once(log, monkeypatch, "b")
    forger.checkpoint(1, "b" * 64, 1)  # a checkpoint at the anchored sequence that names another entry
    with pytest.raises(AuditError, match=r"diverges from its anchor \(checkpoint\)"):
        log.append("c", "admin")
    forger.checkpoint(1, first["mac"], 1)
    store.delete("audit", _key(1))  # pruned: the checkpoint stands in for it
    log.append("c", "admin")
    assert log.verify(Mark(1, first["mac"]))[0]
    assert log.verify(Mark(1, "a" * 64)) == (False, "the store diverges from the signed head at sequence 1")


def test_append_refuses_a_sequence_already_taken(clock: Clock) -> None:
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    store.put("audit", _key(2), forger.entry(2, first["mac"]), None)
    with pytest.raises(AuditError, match="audit sequence 2 already written"):
        log.append("b", "admin")


def test_anchor_file_damage(tmp_path: Path, clock: Clock) -> None:
    keyring = Keyring.ephemeral()
    path = tmp_path / "a.anchor"
    log = AuditLog(MemoryStore(clock), keyring, clock, anchor=Anchor(path, keyring), create_anchor=True)
    log.append("a", "admin")
    content = path.read_bytes()
    path.write_bytes(b"")
    with pytest.raises(AuditError, match="the anchor file is empty; restore it"):
        log.append("b", "admin")
    path.write_bytes(b'{"seq": 0')  # nothing valid at all: not one of cunho's anchors
    with pytest.raises(AuditError, match="the anchor file holds no valid anchor line"):
        log.append("b", "admin")
    path.write_bytes(content)
    anchor = Anchor(path, keyring)
    lines = content.splitlines(keepends=True)
    jump = json.loads(lines[1])
    jump["seq"], jump["prev"] = 5, json.loads(lines[0])["tag"]
    jump.pop("tag")
    jump["tag"] = keyring.mac("audit-anchor", _canonical(jump))
    path.write_bytes(lines[0] + (_canonical(jump) + "\n").encode())
    with pytest.raises(AuditError, match="the anchor sequence jumps from 0 to 5"):
        list(anchor.lines())
    for first in ({"seq": 0, "mac": "a" * 64}, {"seq": 1, "mac": GENESIS}):
        line = {**first, "time": 0, "prev": GENESIS}
        line["tag"] = keyring.mac("audit-anchor", _canonical(line))
        path.write_text(_canonical(line) + "\n")
        with pytest.raises(AuditError, match="does not start with its genesis line"):
            list(anchor.lines())
    path.write_bytes(b"")
    with pytest.raises(AuditError, match="the anchor file is empty; restore it before anything is logged"):
        with anchor.locked():
            anchor.write([(Mark(1, "m"), 0, None)])
    seq_bool = {"seq": True, "mac": GENESIS, "time": 0, "prev": GENESIS}
    seq_bool["tag"] = keyring.mac("audit-anchor", _canonical(seq_bool))
    path.write_text(_canonical(seq_bool) + "\n")
    with pytest.raises(AuditError, match="the anchor file holds no valid anchor line"):
        list(anchor.lines())


def test_verify_against_a_signed_head_and_the_retention_boundary(clock: Clock) -> None:
    log, store, _, forger = _setup(clock)
    entries = [log.append("e", "admin", n=n) for n in range(3)]
    assert log.verify(Mark(2, entries[1]["mac"]))[0]
    assert log.verify(Mark(2, "a" * 64)) == (False, "the store diverges from the signed head at sequence 2")
    assert log.verify(Mark(4, "a" * 64)) == (
        False,
        "the store (head 3) is behind the signed head (4): entries were removed",
    )
    forger.checkpoint(2, entries[1]["mac"], int(clock()) - 100)  # exactly at the retention boundary
    store.delete("audit", _key(1))
    store.delete("audit", _key(2))
    assert log.verify()[0], "a checkpoint as old as the retention period is accepted"
    assert log.verify(Mark(2, "a" * 64)) == (False, "the store diverges from the signed head at sequence 2")
    assert log.verify(Mark(2, entries[1]["mac"]))[0]
    assert log.verify(Mark(1, "anything"))[0], "a signed head older than the checkpoint cannot be compared"
    forger.checkpoint(2, entries[1]["mac"], int(clock()) - 99)
    assert log.verify() == (False, "the checkpoint drops entries younger than the retention period")


def test_verify_checks_prev_even_under_a_valid_mac(clock: Clock) -> None:
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    log.append("b", "admin")
    store.put("audit", _key(2), forger.entry(2, "9" * 64), None)
    assert log.verify() == (False, "entry 2 was altered")
    store.put("audit", _key(2), forger.entry(1, first["mac"]), None)
    assert log.verify() == (False, "gap or reorder at sequence 2")
    assert first


def test_vault_needs_both_rows(clock: Clock, caplog: pytest.LogCaptureFixture) -> None:
    store = MemoryStore(clock)
    vault = Vault(store, Keyring.ephemeral())
    vault.put("sub_a", {"n": 1}, None, "o")
    sealed = store.get("vault", "sub_a")
    with caplog.at_level(logging.WARNING, logger="cunho.security"):
        store.delete("vault", "sub_a")
        assert vault.get("sub_a", "o") is None
        store.put("vault", "sub_a", sealed, None)
        store.delete("vault-key", "sub_a")
        assert vault.get("sub_a", "o") is None
    assert caplog.text == "", "erased data is no alert; only data that does not open is"


def test_pruning_never_takes_a_boolean_for_a_time(issuer: Issuer, clock: Clock) -> None:
    for n in range(3):
        issuer.audit.append("old", "admin", n=n)
    entry = dict(issuer.store.get("audit", _key(2)) or {})
    issuer.store.put("audit", _key(2), {**entry, "time": True}, None)
    assert issuer.audit.prune_before(clock() + 1) == 1, "pruning stops at the entry whose time is not a number"


def test_catch_up_needs_each_entry_to_follow_the_one_before(clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    """Entries 2 and 3 were committed but not anchored. Someone with the keyring rewrites them so that the
    last one still matches the head; each link in between must hold on its own."""
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    _crash_once(log, monkeypatch, "b")
    _crash_once(log, monkeypatch, "c")
    for seq, prev in ((1, first["mac"]), (2, "8" * 64)):  # a repeated sequence; then a broken link
        second = forger.entry(seq, prev)
        third = forger.entry(3, second["mac"])
        store.put("audit", _key(2), second, None)
        store.put("audit", _key(3), third, None)
        forger.head(3, third["mac"])
        with pytest.raises(AuditError, match="diverges from its anchor"):
            log.append("d", "admin")


def test_pruning_stops_at_the_anchor(clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    """Found by the extended mutation run: pruning entries that were committed but not yet anchored left a
    gap in the anchor that catch-up could never fill (the anchor sequence then jumped)."""
    log, store, _, forger = _setup(clock)
    first = log.append("a", "admin")
    _crash_once(log, monkeypatch, "b")
    _crash_once(log, monkeypatch, "c")
    clock.now += 200  # past the retention period of 100 s
    assert log.prune_before(clock()) == 1, "only the anchored entry is pruned"
    log.append("d", "admin")
    assert [line["seq"] for line in log.anchor.lines()] == [0, 1, 2, 3, 4]  # type: ignore[union-attr]
    assert log.verify()[0]
    _crash_once(log, monkeypatch, "e")
    entry = store.get("audit", _key(5))
    assert isinstance(entry, dict)
    forger.checkpoint(5, entry["mac"], 1)  # a checkpoint past the anchor (4), as an older version could leave
    with pytest.raises(AuditError, match="pruned before they were anchored"):
        log.append("f", "admin")
    assert first


# http layer ---------------------------------------------------------------------------------------


def test_status_route_takes_only_ascii_list_numbers(client: TestClient, issuer: Issuer) -> None:
    issuer.status.allocate()
    assert client.get("/status/1").status_code == 200
    for list_id in ("x", "١", "01x", "2"):
        response = client.get(f"/status/{list_id}")
        assert response.status_code == 404 and response.json()["error"] == "not_found", list_id
    for list_id in ("١", "x"):  # an Arabic-Indic digit that isdecimal(), and a letter
        issuer.store.put("status-meta", f"list:{list_id}", {"opened": 1}, None)
        assert client.get(f"/status/{list_id}").status_code == 404, list_id


def test_audit_verify_body_shape(client: TestClient) -> None:
    bodies: list[Any] = [[], {"signed_head": 7}, {"other": "x"}]
    for body in bodies:
        response = client.post("/admin/audit/verify", headers=AUTH, json=body)
        assert response.status_code == 400, body
    ok = client.post("/admin/audit/verify", headers=AUTH, json={"signed_head": "a.b.c"})
    assert ok.status_code == 200 and ok.json()["valid"] is False


def test_body_limit_boundaries(wallet: Wallet) -> None:
    from cunho.app import MAX_BODY

    def chunks(total: int) -> Any:
        body: bytes = b"{" + b" " * (total - 2) + b"}"
        assert len(body) == total
        yield body[: total // 2]
        yield body[total // 2 :]

    wallet.get_token()
    exact = wallet.credential_request(None, raw=b"{" + b" " * (MAX_BODY - 2) + b"}")
    assert exact.status_code == 400 and "too large" not in exact.json()["error_description"]
    over = wallet.credential_request(None, raw=b"{" + b" " * (MAX_BODY - 1) + b"}")
    assert over.status_code == 400 and "too large" in over.json()["error_description"]
    headers = {"Authorization": f"DPoP {wallet.token}", "Content-Type": "application/json"}
    streamed = wallet.client.post("/credential", content=chunks(MAX_BODY), headers=headers)
    assert "too large" not in streamed.json()["error_description"]
    streamed = wallet.client.post("/credential", content=chunks(MAX_BODY + 1), headers=headers)
    assert "too large" in streamed.json()["error_description"]


def test_offer_creation_in_sqlite(make_issuer: Callable[..., Issuer], pki: Pki, tmp_path: Path, clock: Clock) -> None:
    issuer = make_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        response = client.post(
            "/admin/offers", headers=AUTH, json={"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT}
        )
        assert response.status_code == 201


# settings: every startup refusal with its own message, and the value just inside each limit -------


SETTINGS_REFUSED: list[tuple[dict[str, Any], str]] = [
    ({"issuer_url": "http://issuer.example"}, "issuer_url must use https"),
    ({"issuer_url": "ftp://localhost"}, "issuer_url must use https"),
    ({"issuer_url": "http://localhost", "production": True}, "issuer_url must use https"),
    ({"issuer_url": "https://issuer.test?x=1"}, "no query, fragment or trailing slash"),
    ({"issuer_url": "https://issuer.test#x"}, "no query, fragment or trailing slash"),
    ({"issuer_url": "https://issuer.test/"}, "no query, fragment or trailing slash"),
    ({"admin_token": " Change-Me "}, "operator token 'admin' is missing, an example value"),
    ({"admin_token": "change-me".rjust(32)}, "operator token 'admin' is missing, an example value"),
    ({"admin_token": "t" * 31}, "operator token 'admin'"),
    ({"operators": {"bad-name": "u" * 40}}, "operator token 'bad-name'"),
    ({"operators": {"alice": "t" * 40}}, "every operator needs its own token"),
    ({"audit_retention_days": 0}, "audit_retention_days must be set"),
    ({"signer_certificate_url": None}, "PID, QEAA and PuB-EAA providers must publish the signer certificate"),
    ({"signer_certificate_url": "http://cdn.test/signer.pem"}, "signer_certificate_url must use https"),
    ({"signer_certificate_url": "https://issuer.test/other.pem"}, "cunho serves the signer certificate only at"),
    ({"batch_size": 1}, "batch_size must be 2 or more"),
    ({"rate_limit_per_minute": 0}, "rate limits must be at least 1"),
    ({"operator_rate_limit_per_minute": 0}, "rate limits must be at least 1"),
    ({"status_list_size": 1016}, "status_list_size must be a multiple of 8"),
    ({"status_list_size": 1028}, "status_list_size must be a multiple of 8"),
    ({"status_list_size": 8_388_616}, "status_list_size must be a multiple of 8"),
    ({"offer_ttl": 0}, "offer_ttl must be a whole number of at least 1"),
    ({"maintenance_interval": True}, "maintenance_interval must be a whole number"),
    ({"c_nonce_ttl": 1.5}, "c_nonce_ttl must be a whole number"),
    ({"dpop_iat_window": 601}, "dpop_iat_window must be at most 600 s"),
    ({"proof_iat_window": 3601}, "proof_iat_window at most 3600 s"),
    ({"timestamp_granularity": 7}, "timestamp_granularity must divide a day"),
    ({"timestamp_granularity": 172_800}, "timestamp_granularity must divide a day"),
    ({"status_token_lifetime": 3599}, "status_token_lifetime must be at least status_token_ttl"),
    ({"status_list_fill_limit": 0}, "status_list_fill_limit must be above 0 and at most 0.9"),
    ({"status_list_fill_limit": 0.91}, "status_list_fill_limit must be above 0"),
    ({"status_decoy_ratio": -0.01}, "status_decoy_ratio must be 0 or more"),
    ({"status_decoy_ratio": 0.25}, "status_decoy_ratio must be 0 or more and below half the fill limit"),
    ({"status_decoy_churn_per_day": -0.01}, "status_decoy_churn_per_day must be between 0 and 0.05"),
    ({"status_decoy_churn_per_day": 0.051}, "status_decoy_churn_per_day must be between 0 and 0.05"),
    ({"status_revocation_jitter": "60"}, "status_revocation_jitter must be a whole number of seconds"),
    ({"status_revocation_jitter": 1.5}, "status_revocation_jitter must be a whole number of seconds"),
]

SETTINGS_ACCEPTED: list[dict[str, Any]] = [
    {"issuer_url": "http://localhost"},
    {"issuer_url": "http://127.0.0.1:8000"},
    {"issuer_url": "http://testserver", "signer_certificate_url": "https://cdn.test/signer.pem"},
    {"admin_token": "t" * 32},
    {"operators": {"alice": "u" * 32}},
    {"audit_retention_days": 1},
    {"signer_certificate_url": "https://cdn.test/signer.pem"},
    {"batch_size": 2},
    {"rate_limit_per_minute": 1, "operator_rate_limit_per_minute": 1},
    {"status_list_size": 1024},
    {"status_list_size": 8_388_608},
    {"offer_ttl": 1},
    {"dpop_iat_window": 600, "proof_iat_window": 3600},
    {"timestamp_granularity": 86_400},
    {"timestamp_granularity": 60},
    {"status_token_lifetime": 3600},
    {"status_list_fill_limit": 0.9},
    {"status_decoy_ratio": 0},
    {"status_decoy_ratio": 0.249},
    {"status_decoy_churn_per_day": 0},
    {"status_decoy_churn_per_day": 0.05},
]


@pytest.mark.parametrize(("change", "reason"), SETTINGS_REFUSED, ids=[r for _, r in SETTINGS_REFUSED])
def test_each_unsafe_setting_is_refused_for_its_own_reason(pki: Pki, change: dict[str, Any], reason: str) -> None:
    from cunho.errors import ConfigError
    from cunho.settings import Settings

    from .helpers import settings_kwargs

    with pytest.raises(ConfigError) as caught:
        Settings(**{**settings_kwargs(pki), **change})
    assert reason in str(caught.value), caught.value


@pytest.mark.parametrize("change", SETTINGS_ACCEPTED)
def test_each_setting_limit_accepts_the_value_just_inside(pki: Pki, change: dict[str, Any]) -> None:
    from cunho.settings import Settings

    from .helpers import settings_kwargs

    Settings(**{**settings_kwargs(pki), **change})


@pytest.mark.parametrize(
    ("missing", "reason"),
    [
        ({"status_signing_key": None}, "production needs a separate status-list key and a persistent store"),
        ({"store_path": None}, "production needs a separate status-list key and a persistent store"),
        ({"secret_key_file": None}, "production needs secret_key_file"),
        ({"audit_anchor_path": None}, "production needs audit_anchor_path"),
        ({"signing_trust_anchors": None}, "production needs signing_trust_anchors"),
        ({"ka_signer_policy_oids": ()}, "production needs ka_signer_policy_oids"),
        ({"lote_path": None, "lote_signer": None}, "production needs lote_path and lote_signer"),
        ({"login_url": None}, "production needs login_url"),
        ({"wia_signer_policy_oids": ()}, "production needs wia_signer_policy_oids"),
    ],
)
def test_each_production_requirement(pki: Pki, tmp_path: Path, missing: dict[str, Any], reason: str) -> None:
    from cunho.errors import ConfigError
    from cunho.settings import Settings

    from .helpers import production_kwargs

    Settings(**production_kwargs(pki, tmp_path))
    with pytest.raises(ConfigError) as caught:
        Settings(**production_kwargs(pki, tmp_path, **missing))
    assert reason in str(caught.value)


def test_the_anchor_is_its_own_file(pki: Pki, tmp_path: Path) -> None:
    from cunho.errors import ConfigError
    from cunho.settings import Settings

    from .helpers import production_kwargs

    for other in ("store_path", "secret_key_file"):
        kwargs = production_kwargs(pki, tmp_path)
        with pytest.raises(ConfigError, match="its own file"):
            Settings(**{**kwargs, "audit_anchor_path": kwargs[other]})


def test_settings_from_the_environment(pki: Pki) -> None:
    from cunho.errors import ConfigError
    from cunho.settings import Settings

    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": "t" * 40,
        "CUNHO_SIGNING_KEY": "k",
        "CUNHO_SIGNING_CHAIN": "c",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "a",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_SIGNER_CERTIFICATE_URL": "https://cdn.test/s.pem",
        "CUNHO_OPERATORS": "alice=" + "a" * 40 + ",junk",
        "CUNHO_AUDIT_ANCHOR_INIT": "TRUE",
    }
    settings = Settings.from_env(env)
    assert settings.operators == {"alice": "a" * 40} and settings.audit_anchor_init is True
    for name in ("CUNHO_ISSUER_URL", "CUNHO_ADMIN_TOKEN"):
        with pytest.raises(ConfigError, match=f"{name} is required"):
            Settings.from_env({**env, name: ""})
        with pytest.raises(ConfigError, match=f"{name} is required"):
            Settings.from_env({k: v for k, v in env.items() if k != name})


# keyring and configuration loading ------------------------------------------------------------------


def test_keyring_refuses_a_short_or_readable_secret(tmp_path: Path) -> None:
    from cunho.errors import ConfigError

    with pytest.raises(ConfigError, match="at least 32 bytes"):
        Keyring(b"k" * 31)
    Keyring(b"k" * 32)
    path = tmp_path / "m.key"
    path.write_bytes(b"k" * 32)
    for mode in (0o640, 0o604, 0o610):
        path.chmod(mode)
        with pytest.raises(ConfigError, match="must not be readable by group or others"):
            Keyring.from_file(path, create=False)
    path.chmod(0o600)
    Keyring.from_file(path, create=False)
    with pytest.raises(ConfigError, match="does not exist"):
        Keyring.from_file(tmp_path / "missing.key", create=False)


def _metadata(tmp_path: Path, edit: Callable[[dict[str, Any]], None], extra: dict[str, Any] | None = None) -> Path:
    import shutil

    from cunho.settings import DEFAULT_METADATA_DIR

    target = tmp_path / "md"
    shutil.copytree(DEFAULT_METADATA_DIR, target)
    path = target / "credentials_supported" / "pid_jwt_vc.json"
    data = json.loads(path.read_text())
    edit(data[PID_CONFIG])
    path.write_text(json.dumps(data))
    if extra is not None:
        (target / "credentials_supported" / "zz_extra.json").write_text(json.dumps(extra))
    return target


def test_configuration_loading_refusals(make_issuer: Callable[..., Issuer], tmp_path: Path) -> None:
    from cunho.errors import ConfigError

    cases: list[tuple[Callable[[dict[str, Any]], None], str]] = [
        (lambda c: c.update(credential_signing_alg_values_supported=["ES384"]), "the signing key (ES256) is not in"),
        (lambda c: c.pop("cryptographic_binding_methods_supported"), "proof_types_supported must be present exactly"),
    ]
    for n, (edit, reason) in enumerate(cases):
        with pytest.raises(ConfigError) as caught:
            make_issuer(metadata_dir=_metadata(tmp_path / str(n), edit))
        assert reason in str(caught.value)
    twice = {PID_CONFIG: {"format": "dc+sd-jwt"}}
    with pytest.raises(ConfigError, match="is defined twice"):
        make_issuer(metadata_dir=_metadata(tmp_path / "twice", lambda c: None, twice))
    unbound_eaa = {
        "x.unbound": {
            "format": "dc+sd-jwt",
            "scope": "x",
            "vct": "urn:x",
            "credential_metadata": {
                "credential_reuse_policy": {
                    "id": "arf_annex_ii",
                    "options": [{"details": ["limited_time"], "reissue_trigger_lifetime_left": 86_400}],
                },
                "claims": [],
            },
        }
    }
    path = _metadata(tmp_path / "unbound", lambda c: None, unbound_eaa)
    with pytest.raises(ConfigError, match="x.unbound: a PID must be bound to a key"):
        make_issuer(metadata_dir=path, published_configurations=(PID_CONFIG, "x.unbound"))
    from cunho.metadata import validate

    iban = dict(make_issuer().configs.all["eu.europa.ec.eudi.iban_sd_jwt_vc"])
    iban["proof_types_supported"] = {
        "jwt": {"proof_signing_alg_values_supported": ["ES256"], "key_attestations_required": []}
    }
    with pytest.raises(ConfigError, match="key_attestations_required must be an object when present"):
        validate("iban", iban, 30)


# configuration validation, one rule at a time ---------------------------------------------------------


def _iban(make_issuer: Callable[..., Issuer]) -> dict[str, Any]:
    import copy

    return copy.deepcopy(make_issuer().configs.all["eu.europa.ec.eudi.iban_sd_jwt_vc"])


def test_configuration_rules_one_at_a_time(make_issuer: Callable[..., Issuer]) -> None:
    import copy

    from cunho.errors import ConfigError
    from cunho.metadata import ISO_18045, validate

    issuer = make_issuer()
    pid = copy.deepcopy(issuer.configs.all[PID_CONFIG])
    validate("pid", pid, 30)
    validate("pid", pid, None)  # no issuer batch_size to compare with

    def edited(change: Callable[[dict[str, Any]], None], base: dict[str, Any] | None = None) -> dict[str, Any]:
        config = copy.deepcopy(base or pid)
        change(config)
        return config

    def jwt(config: dict[str, Any]) -> dict[str, Any]:
        spec: dict[str, Any] = config["proof_types_supported"]["jwt"]
        return spec

    def required(config: dict[str, Any]) -> dict[str, Any]:
        value: dict[str, Any] = jwt(config)["key_attestations_required"]
        return value

    def option(config: dict[str, Any]) -> dict[str, Any]:
        value: dict[str, Any] = config["credential_metadata"]["credential_reuse_policy"]["options"][0]
        return value

    refused: list[tuple[dict[str, Any], str]] = [
        (edited(lambda c: c.update(proof_types_supported=["jwt"])), "proof_types_supported must be an object"),
        (edited(lambda c: c["proof_types_supported"].update(jwt=None)), "a key attestation with key_storage"),
        (edited(lambda c: jwt(c).update(proof_signing_alg_values_supported=[])), "non-empty subset"),
        (edited(lambda c: jwt(c).update(proof_signing_alg_values_supported="ES256")), "non-empty subset"),
        (edited(lambda c: jwt(c).update(proof_signing_alg_values_supported={"ES256": True})), "non-empty subset"),
        (edited(lambda c: jwt(c).update(proof_signing_alg_values_supported=["ES256", "HS256"])), "non-empty subset"),
        (edited(lambda c: required(c).update(user_authentication=["strong"])), "user_authentication values"),
        (edited(lambda c: required(c).update(user_authentication="iso_18045_high")), "user_authentication values"),
        (edited(lambda c: required(c).update(user_authentication={"iso_18045_high": 1})), "user_authentication values"),
        (edited(lambda c: required(c).update(preferred_key_storage_status_period="x")), "positive number"),
        (edited(lambda c: required(c).update(preferred_key_storage_status_period=True)), "positive number"),
        (edited(lambda c: required(c).update(preferred_key_storage_status_period=0)), "positive number"),
        (edited(lambda c: option(c).update(batch_size=True)), "need a batch_size of 2 or more"),
        (edited(lambda c: option(c).update(batch_size=0)), "need a batch_size of 2 or more"),
        (edited(lambda c: option(c).update(batch_size=1)), "need a batch_size of 2 or more"),
        (edited(lambda c: option(c).update(batch_size="30")), "need a batch_size of 2 or more"),
    ]
    for config, reason in refused:
        with pytest.raises(ConfigError) as caught:
            validate("x", config, 30)
        assert reason in str(caught.value), (reason, caught.value)
    accepted = [
        edited(lambda c: jwt(c).update(proof_signing_alg_values_supported=["ES512", "ES384", "ES256"])),
        edited(lambda c: required(c).update(key_storage=sorted(ISO_18045), user_authentication=sorted(ISO_18045))),
        edited(lambda c: required(c).pop("user_authentication")),
        edited(lambda c: required(c).update(preferred_key_storage_status_period=1)),
        edited(lambda c: option(c).update(batch_size=4)),
    ]
    for config in accepted:
        validate("x", config, 30)
    validate("x", edited(lambda c: option(c).update(batch_size=50)), None)
    iban = _iban(make_issuer)
    validate("iban", iban, 30)

    def with_jwt(value: Any) -> Callable[[dict[str, Any]], None]:
        return lambda c: c["proof_types_supported"].update(jwt=value)

    for spec in (None, ["ES256"]):
        with pytest.raises(ConfigError, match="the jwt proof type must be an object"):
            validate("iban", edited(with_jwt(spec), iban), 30)
    validate("iban", edited(lambda c: c["proof_types_supported"]["jwt"].pop("key_attestations_required"), iban), 30)
    mdoc = copy.deepcopy(issuer.configs.all["eu.europa.ec.eudi.pid_mdoc"])
    assert "vct" not in mdoc
    validate("mdoc", mdoc, 30)  # only dc+sd-jwt needs vct


def test_a_pid_needs_binding_with_key_storage_for_every_proof_type(make_issuer: Callable[..., Issuer]) -> None:
    import copy

    from cunho.errors import ConfigError
    from cunho.metadata import _require_device_binding

    pid = copy.deepcopy(make_issuer().configs.all[PID_CONFIG])
    _require_device_binding(pid)
    unbound = {k: v for k, v in pid.items() if k != "cryptographic_binding_methods_supported"}
    for config in (
        unbound,
        {**pid, "proof_types_supported": ["jwt"]},
        {**pid, "proof_types_supported": {}},
        {**pid, "proof_types_supported": None},
    ):
        with pytest.raises(ConfigError, match="a PID must be bound to a key"):
            _require_device_binding(config)
    specs: list[Any] = [None, {"key_attestations_required": None}, {"key_attestations_required": {"key_storage": []}}]
    for spec in specs:
        with pytest.raises(ConfigError, match="key_storage for jwt proofs"):
            _require_device_binding({**pid, "proof_types_supported": {"jwt": spec}})


def test_a_configuration_without_signing_algorithms_loads(make_issuer: Callable[..., Issuer], tmp_path: Path) -> None:
    path = _metadata(tmp_path, lambda c: c.pop("credential_signing_alg_values_supported", None))
    issuer = make_issuer(metadata_dir=path)
    assert PID_CONFIG in issuer.configs.published


# DPoP and tokens ------------------------------------------------------------------------------------


def test_server_nonces_are_checked_by_their_mac_and_age(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    issuer = make_issuer(dpop_server_nonce=True)
    nonces = issuer.nonces
    good = nonces.issue_dpop_nonce()
    stamp, mac = good.split(".")
    assert nonces.dpop_nonce_valid(good)
    for value in (None, 7, "no-dot", f"{stamp}.{'0' * 32}", f"{int(stamp) + 1}.{mac}", f"\udc80{stamp}.{mac}", "."):
        assert not nonces.dpop_nonce_valid(value), value
    clock.now += 60 * 5
    assert nonces.dpop_nonce_valid(good), "valid for five iat windows"
    clock.now += 1
    assert not nonces.dpop_nonce_valid(good)
    clock.now -= 2 * 60 * 5
    assert not nonces.dpop_nonce_valid(good), "a nonce from the future is not valid"


def _dpop_with(wallet: Wallet, **claims: Any) -> str:
    from eudi_probe.jose import jws

    key = wallet.dpop_key
    payload = {"jti": "j" * 20, "htm": "POST", "htu": f"{ISSUER}/token", "iat": int(wallet.clock()), **claims}
    payload = {k: v for k, v in payload.items() if v is not ...}
    header = claims.pop("_header", None) or {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}
    return jws(header, payload, key)


def test_dpop_claim_boundaries(wallet: Wallet) -> None:
    from .helpers import refused_by

    def token(proof: str) -> Callable[[], Any]:
        return lambda: wallet.token_request("unknown-code", dpop=proof)

    for jti in ("j" * 7, "j" * 257, 7):
        refused_by(token(_dpop_with(wallet, jti=jti)), "DPOP.JTI_PRESENT", "jti must be a string of 8 to 256")
    for jti in ("a" * 8, "a" * 15, "b" * 256):  # 15: the OIDF suite's own jti in its DPoP negative tests
        refused_by(token(_dpop_with(wallet, jti=jti)), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    now = int(wallet.clock())
    for iat in (now - 61, now + 61):
        refused_by(token(_dpop_with(wallet, iat=iat, jti=f"i{iat}" * 4)), "DPOP.IAT_WINDOW", "outside the accepted")
    for iat in (now - 60, now + 60):
        refused_by(token(_dpop_with(wallet, iat=iat, jti=f"k{iat}" * 4)), "VCI.TOKEN.INVALID_GRANT", "unknown")
    refused_by(token(_dpop_with(wallet, htu=7, jti="h" * 20)), "DPOP.HTU", "htu does not match")
    for jwk in (5, "x", ["kty"]):
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
        refused_by(token(_dpop_with(wallet, _header=header, jti="w" * 20)), "DPOP.NO_PRIVATE_KEY", "public key")


def test_a_bearer_scheme_with_an_unknown_token_is_a_scheme_error(wallet: Wallet) -> None:
    from .helpers import refused_by

    wallet.token = "unknown-token"
    refused_by(
        lambda: wallet.credential_request({"credential_configuration_id": PID_CONFIG}, scheme="Bearer"),
        "DPOP.AUTH_SCHEME",
        "use the DPoP authorization scheme",
    )
    wallet.get_token()
    refused_by(
        lambda: wallet.credential_request({"credential_configuration_id": PID_CONFIG}, scheme="Bearer"),
        "DPOP.NO_BEARER_DOWNGRADE",
        "DPoP-bound",
    )


def test_a_sealed_row_with_a_strange_expiry_is_ignored(issuer: Issuer, clock: Clock) -> None:
    from cunho.oauth import opened, seal

    for expires in ("soon", None, 1.5e12, True):
        row = seal(issuer.keyring, "token-record", "k", {"exp": expires})
        assert opened(issuer.keyring, "token-record", "k", row, clock()) is None, expires
    row = seal(issuer.keyring, "token-record", "k", {"exp": int(clock()) + 1})
    assert opened(issuer.keyring, "token-record", "k", row, clock()) == {"exp": int(clock()) + 1}
    assert opened(issuer.keyring, "offer-record", "k", row, clock()) is None, "the purpose is part of the MAC"


def test_a_crl_without_next_update_is_never_current(pki: Pki) -> None:
    from cryptography import x509 as x509_

    from cunho.jose import validate_path
    from cunho.proofs import parse_crls

    from .helpers import START as start
    from .helpers import crl_without_next_update

    der = crl_without_next_update(pki.wallet_ca, pki.wallet_ca_key)
    loaded = x509_.load_der_x509_crl(der)
    assert loaded.next_update_utc is None and loaded.is_signature_valid(pki.wallet_ca.public_key())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="without nextUpdate cannot be judged current"):
        parse_crls(der)
    now = dt.datetime.fromtimestamp(start, dt.UTC)
    with pytest.raises(JoseError, match="no current revocation list covers the leaf"):
        validate_path([pki.ka_leaf], [pki.wallet_ca], now, crls=[loaded])


def test_wallet_provider_anchors_must_load(tmp_path: Path) -> None:
    from cunho.errors import ConfigError
    from cunho.proofs import load_anchors

    with pytest.raises(ConfigError, match="cannot read wallet provider trust anchors"):
        load_anchors(tmp_path / "missing.pem")
    empty = tmp_path / "empty.pem"
    empty.write_text("no certificates here\n")
    with pytest.raises(ConfigError, match="cannot read wallet provider trust anchors"):
        load_anchors(empty)


def test_proof_header_and_attested_key_shapes(wallet: Wallet) -> None:
    from eudi_probe.jose import jws

    from .helpers import refused_by

    holder = EcKey.generate()
    wallet.get_token()

    def send(proof: str) -> Callable[[], Any]:
        return lambda: wallet.credential_request(
            {"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}}
        )

    header = {"typ": "openid4vci-proof+jwt", "alg": ["ES256"], "jwk": holder.public_jwk()}
    proof = jws(header, {"aud": ISSUER, "iat": int(wallet.clock()), "nonce": wallet.c_nonce()}, holder)
    refused_by(send(proof), "VCI.F1.PROOF_ALG_ASYMMETRIC", "alg must be one of")
    for key in (5, "x"):
        attestation = wallet.key_attestation([holder], attested_keys=[key])
        refused_by(
            send(wallet.proof(holder, wallet.c_nonce(), key_attestation=attestation)), "KA.VERIFY", "not a usable"
        )
    edge = wallet.key_attestation([holder], iat=int(wallet.clock()) + 60)
    response = wallet.credential_request(
        {
            "credential_configuration_id": PID_CONFIG,
            "proofs": {"jwt": [wallet.proof(holder, wallet.c_nonce(), key_attestation=edge)]},
        }
    )
    assert response.status_code == 200, "a key attestation 60 s ahead is within the allowed clock skew"


def test_an_empty_dpop_token_is_a_scheme_error(wallet: Wallet) -> None:
    from .helpers import refused_by

    wallet.token = " "
    refused_by(
        lambda: wallet.credential_request({"credential_configuration_id": PID_CONFIG}),
        "DPOP.AUTH_SCHEME",
        "use the DPoP authorization scheme",
    )


def test_the_status_period_is_required_for_pids_and_for_pid_providers(make_issuer: Callable[..., Issuer]) -> None:
    from cunho.errors import IssuerError
    from cunho.proofs import ProvenKeys
    from cunho.settings import Profile

    pid_provider = make_issuer()
    eaa_provider = make_issuer(profile=Profile.EAA_PROVIDER, signer_certificate_url=None)
    pid = pid_provider.configs.all[PID_CONFIG]
    iban = pid_provider.configs.all["eu.europa.ec.eudi.iban_sd_jwt_vc"]
    for issuer, config in ((pid_provider, pid), (pid_provider, iban), (eaa_provider, pid)):
        with pytest.raises(IssuerError, match="key_storage_status.exp"):
            issuer.proofs.require_status_period(ProvenKeys(), config)
    eaa_provider.proofs.require_status_period(ProvenKeys(), iban)
    pid_provider.proofs.require_status_period(ProvenKeys(status_exp=1), pid)


def test_attestation_requirements_only_bind_what_the_configuration_asks(wallet: Wallet, issuer: Issuer) -> None:
    from cunho.proofs import ProvenKeys

    holder = EcKey.generate()
    attestation = wallet.key_attestation([holder], user_authentication=...)
    keys = issuer.proofs.key_attestation(
        attestation, {"key_storage": ["iso_18045_high"]}, ProvenKeys(), nonce_rule=None, jwt_proof=True
    )
    assert keys == [holder.public_jwk()]


def test_key_proof_boundaries_and_shapes(wallet: Wallet) -> None:
    from eudi_probe.jose import jws

    from .helpers import refused_by

    def send(proof: str) -> Any:
        wallet.token = None
        wallet.get_token()
        return wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [proof]}})

    now = int(wallet.clock())
    for iat in (now - 300, now + 300):
        assert send(wallet.proof(EcKey.generate(), wallet.c_nonce(), iat=iat)).status_code == 200, iat

    def stale(iat: int) -> Callable[[], Any]:
        holder = EcKey.generate()
        return lambda: send(wallet.proof(holder, wallet.c_nonce(), iat=iat))

    for iat in (now - 301, now + 301):
        refused_by(stale(iat), "VCI.F1.PROOF_IAT", "iat")
    holder = EcKey.generate()
    header = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "key_attestation": wallet.key_attestation([holder])}
    no_jwk = jws(header, {"aud": ISSUER, "iat": now, "nonce": wallet.c_nonce()}, holder)
    assert send(no_jwk).status_code == 200, "with a key attestation the proof key is attested_keys[0]; jwk may go"


def test_attestation_proof_nonce_must_be_a_string(wallet: Wallet) -> None:
    from .helpers import refused_by

    wallet.get_token()
    attestation = wallet.key_attestation([EcKey.generate()], nonce=5)  # type: ignore[arg-type]
    refused_by(
        lambda: wallet.credential_request(
            {"credential_configuration_id": PID_CONFIG, "proofs": {"attestation": [attestation]}}
        ),
        "KA.ATTESTATION_PROOF_NONCE",
        "must carry a c_nonce",
    )


def test_rule_ids_must_be_in_the_binder() -> None:
    from cunho.rules import implements, known

    assert known("DPOP.JTI_REPLAY") == "DPOP.JTI_REPLAY"
    with pytest.raises(KeyError, match="is not in the binder"):
        known("NOT.A_RULE")
    with pytest.raises(KeyError, match="is not in the binder"):
        implements("DPOP.JTI_REPLAY", "NOT.A_RULE")


def test_issuance_without_its_audit_entry_returns_nothing(
    wallet: Wallet, issuer: Issuer, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cunho.status import StatusRef

    wallet.get_token()
    real = issuer.audit.append

    def failing(event: str, actor: str, **data: Any) -> Any:
        if event == "credential.issued":
            raise AuditError("disk full")
        return real(event, actor, **data)

    monkeypatch.setattr(issuer.audit, "append", failing)
    response = wallet.issue()
    assert response.status_code == 500 and "credentials" not in response.json()
    reserved = [
        StatusRef(k.split(":")[0], int(k.split(":")[1])) for k, v in issuer.store.items("status-slot") if v == 1
    ]
    decoys = {k for k, _ in issuer.store.items("status-decoy")}
    burned = [r for r in reserved if f"{r.list_id}:{r.index:08d}" not in decoys]
    assert len(burned) == 1, "the slot reserved for the credential that was never handed out is revoked"


# signers ----------------------------------------------------------------------------------------------


def test_file_signer_refusals(pki: Pki, tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from cunho.errors import ConfigError
    from cunho.signer import FileSigner, x5c_chain

    from .helpers import key_pem, pem

    key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate("Signer", key, san=["issuer.test"])
    with pytest.raises(ConfigError, match="signing key must be P-256, P-384 or P-521"):
        FileSigner(ec.generate_private_key(ec.SECP256K1()), [leaf])
    with pytest.raises(ConfigError, match="signing certificate chain is empty"):
        FileSigner(key, [])
    with pytest.raises(ConfigError, match="signing key does not match the leaf certificate"):
        FileSigner(ec.generate_private_key(ec.SECP256R1()), [leaf])
    assert FileSigner(key, [leaf]).alg == "ES256"
    p384 = ec.generate_private_key(ec.SECP384R1())
    assert FileSigner(p384, [certificate("S", p384)]).alg == "ES384"
    ed = ed25519.Ed25519PrivateKey.generate()
    ed_path = tmp_path / "ed.key"
    ed_path.write_bytes(
        ed.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (tmp_path / "chain.pem").write_bytes(pem(leaf))
    with pytest.raises(ConfigError, match="is not an EC private key"):
        FileSigner.from_files(ed_path, tmp_path / "chain.pem")
    (tmp_path / "k.pem").write_bytes(key_pem(key))
    assert FileSigner.from_files(tmp_path / "k.pem", tmp_path / "chain.pem").x5c()
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = certificate("Root", root_key, ca=True)
    signed = certificate("Signer", key, (root, root_key))
    with pytest.raises(ConfigError, match="the signing certificate is itself a trust anchor"):
        x5c_chain([root], [root])
    assert x5c_chain([signed, root], [root]) == [signed]
    with pytest.raises(ConfigError, match="not in order, leaf first"):
        x5c_chain([root, signed], None)


def test_signer_identity_by_uri_or_dns(pki: Pki, clock: Clock) -> None:
    from cryptography import x509 as x509_
    from cryptography.hazmat.primitives import hashes

    from cunho.errors import ConfigError
    from cunho.service import check_signer_identity
    from cunho.signer import FileSigner

    key = ec.generate_private_key(ec.SECP256R1())

    def signer(*names: x509_.GeneralName) -> FileSigner:
        now = dt.datetime.fromtimestamp(1_793_750_400, dt.UTC)
        cert = (
            x509_.CertificateBuilder()
            .subject_name(x509_.Name([]))
            .issuer_name(x509_.Name([]))
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509_.SubjectAlternativeName(list(names)), critical=False)
            .sign(key, hashes.SHA256())
        )
        return FileSigner(key, [cert])

    check_signer_identity(signer(x509_.UniformResourceIdentifier(ISSUER)), ISSUER)
    check_signer_identity(signer(x509_.DNSName("ISSUER.test")), ISSUER)
    check_signer_identity(signer(x509_.DNSName("issuer.test")), "https://issuer.test/tenant")
    for names in ((x509_.UniformResourceIdentifier("https://other.test"),), (x509_.DNSName("other.test"),)):
        with pytest.raises(ConfigError, match="does not name"):
            check_signer_identity(signer(*names), ISSUER)


# operator side ------------------------------------------------------------------------------------------


def test_offer_request_shapes(wallet: Wallet) -> None:
    from .helpers import refused_by

    def offer(**body: Any) -> Callable[[], Any]:
        request = {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT, **body}
        return lambda: wallet.admin("offers", request)

    shape = "credential_configuration_ids must be a non-empty array of distinct strings"
    for ids in ("abc", [1], [], [PID_CONFIG, PID_CONFIG], None):
        refused_by(offer(credential_configuration_ids=ids), "VCI.OFFER.SHAPE", shape)
    for length in ("6", 3, 11, True, 6.0):
        refused_by(offer(tx_code_length=length), "VCI.OFFER.SHAPE", "tx_code_length must be an integer from 4 to 10")
    for length in (4, 10):
        response = offer(tx_code_length=length)()
        assert response.status_code == 201 and len(response.json()["tx_code"]) == length


def test_only_a_bearer_token_names_an_operator(issuer: Issuer) -> None:
    assert issuer.operator(f"Bearer {ADMIN_TOKEN}") == "admin"
    assert issuer.operator(f"bearer  {ADMIN_TOKEN} ") == "admin"
    for value in (None, "", f"Basic {ADMIN_TOKEN}", f"DPoP {ADMIN_TOKEN}", "Bearer ", "Bearer x"):
        assert issuer.operator(value) is None, value


def test_a_signed_head_must_be_well_formed(wallet: Wallet, issuer: Issuer) -> None:
    from cunho.signer import sign_jws

    wallet.offer()
    entry = issuer.audit.entries()[0]
    good = {"iss": ISSUER, "iat": 0, "seq": 1, "mac": entry["mac"]}
    assert issuer.audit_verify(sign_jws(issuer.audit_signer, {"typ": "cunho-audit-head+jwt"}, good))[0]
    refusal = (False, "the signed head is not a JWS from this issuer")
    for header, claims in (
        ({"typ": "JWT"}, good),
        ({"typ": "cunho-audit-head+jwt"}, {**good, "seq": "1"}),
        ({"typ": "cunho-audit-head+jwt"}, {**good, "seq": True}),
        ({"typ": "cunho-audit-head+jwt"}, {**good, "mac": 5}),
        ({"typ": "cunho-audit-head+jwt"}, {**good, "iss": "https://other.test"}),
    ):
        assert issuer.audit_verify(sign_jws(issuer.audit_signer, header, claims)) == refusal, (header, claims)
    assert issuer.audit_verify("not a jws") == refusal


def test_proof_container_shapes(wallet: Wallet) -> None:
    from .helpers import refused_by

    wallet.get_token()
    proof = wallet.proof(EcKey.generate(), wallet.c_nonce())

    def send(proofs: Any) -> Callable[[], Any]:
        return lambda: wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": proofs})

    for proofs in ("j", ["jwt"]):
        refused_by(send(proofs), "VCI.CRED.PROOFS_SHAPE", "proofs must contain exactly one proof type")
    for items in ("abc", {"a": 1}):
        refused_by(send({"jwt": items}), "VCI.CRED.PROOFS_SHAPE", "the proofs array must hold strings")
    assert proof


def test_a_full_batch_is_accepted(wallet: Wallet) -> None:
    wallet.get_token()
    nonce = wallet.c_nonce()
    full = wallet.credential_request(
        {
            "credential_configuration_id": PID_CONFIG,
            "proofs": {"jwt": [wallet.proof(EcKey.generate(), nonce) for _ in range(30)]},
        }
    )
    assert full.status_code == 200 and len(full.json()["credentials"]) == 30
    wallet.token = None
    wallet.get_token()
    keys = [EcKey.generate() for _ in range(30)]
    attested = wallet.credential_request(
        {
            "credential_configuration_id": PID_CONFIG,
            "proofs": {"attestation": [wallet.key_attestation(keys, nonce=wallet.c_nonce())]},
        }
    )
    assert attested.status_code == 200 and len(attested.json()["credentials"]) == 30


def test_unbound_configurations_only_for_attestation_providers(make_issuer: Callable[..., Issuer]) -> None:
    import copy

    from cunho.errors import IssuerError
    from cunho.settings import Profile

    pid_provider = make_issuer()
    eaa_provider = make_issuer(profile=Profile.EAA_PROVIDER, signer_certificate_url=None)
    iban = copy.deepcopy(pid_provider.configs.all["eu.europa.ec.eudi.iban_sd_jwt_vc"])
    for key in ("proof_types_supported", "cryptographic_binding_methods_supported"):
        iban.pop(key, None)
    pid = copy.deepcopy(pid_provider.configs.all[PID_CONFIG])
    for key in ("proof_types_supported", "cryptographic_binding_methods_supported"):
        pid.pop(key, None)
    assert eaa_provider._proofs(iban, None).keys == []  # noqa: SLF001
    for issuer, config in ((pid_provider, iban), (eaa_provider, pid), (pid_provider, pid)):
        with pytest.raises(IssuerError, match="a PID is only issued bound to a key"):
            issuer._proofs(config, None)  # noqa: SLF001


def test_revocation_by_subject_takes_only_a_reference_string(wallet: Wallet) -> None:
    from .helpers import refused_by

    def revoke(ref: Any) -> Callable[[], Any]:
        return lambda: wallet.admin("revocations", {"subject_ref": ref, "reason": "death"})

    for ref in (5, ["sub_x"], "sub_short"):
        refused_by(revoke(ref), "STATUS.MONOTONIC", "subject_ref is not a reference this issuer handed out")


# status lists and the store -----------------------------------------------------------------------------


def test_no_decoy_rate_schedules_nothing(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    issuer = make_issuer(status_decoy_churn_per_day=0)
    issuer.status.allocate()
    assert issuer.status.churn() == 0 and issuer.store.items("status-pending") == []


def test_a_shorter_interval_never_shrinks_the_schedule(make_issuer: Callable[..., Issuer], clock: Clock) -> None:
    store = MemoryStore(clock)
    long = make_issuer(store=store, status_list_size=131_072, maintenance_interval=86_400)
    long.status.allocate()
    until = store.get("status-meta", "scheduled_until:1")
    short = make_issuer(store=store, status_list_size=131_072, maintenance_interval=60)
    assert short.status.churn() == 0, "the schedule already reaches further than the short horizon"
    assert store.get("status-meta", "scheduled_until:1") == until


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_entries_expire_exactly_at_their_ttl(backend: str, tmp_path: Path) -> None:
    clock = Clock()
    store: Any = MemoryStore(clock) if backend == "memory" else SqliteStore(tmp_path / "s.db", clock)
    store.put("n", "k", 1, 10)
    store.put("n", "forever", 1, None)
    clock.now += 9.5
    assert store.get("n", "k") == 1
    clock.now += 0.5
    assert store.get("n", "k") is None and store.take("n", "k") is None, "gone at exactly its expiry"
    assert store.add("n", "k", 2, 10) is True, "an expired key can be added again"
    assert store.add("n", "k", 3, 10) is False
    assert store.get("n", "forever") == 1 and store.take("n", "forever") == 1 and store.take("n", "forever") is None


def test_wal_switch_retries_only_on_a_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sqlite3

    import cunho.store as store_module

    monkeypatch.setattr(store_module.time, "sleep", lambda _: None)
    store = SqliteStore(tmp_path / "s.db")

    class Fake:
        def __init__(self, error: str, succeed_after: int | None = None) -> None:
            self.error, self.calls, self.succeed_after = error, 0, succeed_after

        def execute(self, sql: str) -> Any:
            self.calls += 1
            if self.succeed_after is not None and self.calls > self.succeed_after:
                return type("Row", (), {"fetchone": lambda _: ("wal",)})()
            raise sqlite3.OperationalError(self.error)

    for error in ("database is locked", "database table is busy"):
        store._db = Fake(error)  # type: ignore[assignment]  # noqa: SLF001
        with pytest.raises(sqlite3.OperationalError, match="could not switch the store to WAL mode"):
            store._wal()  # noqa: SLF001
        store._db = Fake(error, succeed_after=3)  # type: ignore[assignment]  # noqa: SLF001
        store._wal()  # noqa: SLF001
    store._db = Fake("disk I/O error")  # type: ignore[assignment]  # noqa: SLF001
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        store._wal()  # noqa: SLF001


def test_cluster_sizes_follow_the_issued_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    import cunho.status as status

    sizes = [(1, 2), (5, 1), (30, 3)]
    picks = iter(range(6))
    monkeypatch.setattr(status.secrets, "randbelow", lambda _: next(picks))
    assert [status._weighted(sizes) for _ in range(6)] == [1, 1, 5, 30, 30, 30]  # noqa: SLF001


# hand-written mutants (tools/mutation/patches.py) ---------------------------------------------------------


def test_a_dpop_proof_is_remembered_for_its_whole_window(wallet: Wallet) -> None:
    """O2: the jti cache must outlive the iat window, or a proof can be replayed inside it."""
    from .helpers import refused_by

    offer = wallet.offer()
    proof = wallet.dpop("POST", f"{ISSUER}/token")
    assert wallet.token_request(str(_code(offer)), dpop=proof).status_code == 200
    wallet.clock.now += 59
    refused_by(lambda: wallet.token_request(str(_code(wallet.offer())), dpop=proof), "DPOP.JTI_REPLAY", "already used")


def _code(offer: dict[str, Any]) -> str:
    return str(
        offer["credential_offer"]["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"][
            "pre-authorized_code"
        ]
    )


def test_htu_compares_scheme_host_and_port(wallet: Wallet) -> None:
    from .helpers import refused_by

    def token(htu: str) -> Callable[[], Any]:
        proof = wallet.dpop("POST", htu)
        return lambda: wallet.token_request("x", dpop=proof)

    bad = ("https://issuer.test:8443/token", "http://issuer.test/token", "https://other.test/token", "https:///token")
    for htu in (*bad, "urn:issuer:token"):
        refused_by(token(htu), "DPOP.HTU", "htu does not match")
    for htu in ("https://ISSUER.test:443/token", "HTTPS://issuer.test/token?x=1#y"):
        refused_by(token(htu), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")


def test_the_last_allowed_wrong_tx_code_burns_the_offer(wallet: Wallet, issuer: Issuer) -> None:
    """O8: after exactly tx_code_max_attempts wrong codes the offer is gone, not merely locked."""
    from .helpers import refused_by

    offer = wallet.offer(tx=6)
    code, tx = _code(offer), str(offer["tx_code"])
    wrong = "000000" if tx != "000000" else "111111"
    for _ in range(issuer.settings.tx_code_max_attempts):
        refused_by(lambda: wallet.token_request(code, tx_code=wrong), "VCI.TOKEN.TX_CODE_ERRORS", "wrong tx_code")
    refused_by(lambda: wallet.token_request(code, tx_code=tx), "VCI.TOKEN.INVALID_GRANT", "unknown or expired")
    almost = wallet.offer(tx=6)
    code, tx = _code(almost), str(almost["tx_code"])
    for _ in range(issuer.settings.tx_code_max_attempts - 1):
        wallet.token_request(code, tx_code=wrong)
    assert wallet.token_request(code, tx_code=tx).status_code == 200, "one wrong code fewer still works"


def test_the_shortest_status_period_of_a_batch_caps_it(wallet: Wallet) -> None:
    """P5: with several key attestations, validity ends before the earliest key_storage_status.exp."""
    wallet.get_token()
    now = int(wallet.clock())
    nonce = wallet.c_nonce()
    proofs = []
    for days in (10, 3, 20):
        holder = EcKey.generate()
        attestation = wallet.key_attestation(
            [holder],
            key_storage_status={
                "status": {"status_list": {"idx": 1, "uri": "https://wp.test/s"}},
                "exp": now + days * 86_400,
            },
        )
        proofs.append(wallet.proof(holder, nonce, key_attestation=attestation))
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}})
    assert response.status_code == 200, response.text
    from .helpers import disclosures

    exps = {disclosures(c["credential"])[1]["exp"] for c in response.json()["credentials"]}
    assert len(exps) == 1 and exps.pop() < now + 3 * 86_400


def test_a_nonce_inside_a_jwt_proof_key_attestation_is_used_up(wallet: Wallet) -> None:
    """P6."""
    from .helpers import refused_by

    inner = wallet.c_nonce()
    holder = EcKey.generate()
    wallet.get_token()
    first = wallet.proof(holder, wallet.c_nonce(), key_attestation=wallet.key_attestation([holder], nonce=inner))
    assert (
        wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [first]}}).status_code
        == 200
    )
    wallet.token = None
    wallet.get_token()
    again = wallet.proof(holder, wallet.c_nonce(), key_attestation=wallet.key_attestation([holder], nonce=inner))
    refused_by(
        lambda: wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": [again]}}),
        "VCI.NONCE.C_NONCE_VALID",
        "key attestation nonce is not a valid c_nonce",
    )


def test_the_vault_stays_until_every_configuration_of_the_offer_is_issued(
    make_issuer: Callable[..., Issuer], pki: Pki, clock: Clock, tmp_path: Path
) -> None:
    """S10: an offer for two configurations keeps its data until the second one is issued."""
    import copy
    import shutil

    from cunho.settings import DEFAULT_METADATA_DIR

    target = tmp_path / "md"
    shutil.copytree(DEFAULT_METADATA_DIR, target)
    data = json.loads((target / "credentials_supported" / "pid_jwt_vc.json").read_text())
    national = copy.deepcopy(data[PID_CONFIG])
    national.update(vct="urn:eudi:pid:pt:1", scope="pid_pt")
    (target / "credentials_supported" / "pid_pt.json").write_text(json.dumps({"pid.pt": national}))
    issuer = make_issuer(metadata_dir=target)
    with TestClient(create_app(issuer=issuer, background_maintenance=False), base_url=ISSUER) as client:
        wallet = Wallet(client, pki, clock)
        offer = wallet.offer(configs=[PID_CONFIG, "pid.pt"])
        wallet.get_token(offer)
        assert wallet.issue(config=PID_CONFIG).status_code == 200
        assert issuer.store.get("vault", offer["subject_ref"]) is not None, "one configuration is still to come"
        assert wallet.issue(config="pid.pt").status_code == 200
        assert issuer.store.get("vault", offer["subject_ref"]) is None


def test_issued_batch_sizes_are_counted(wallet: Wallet, issuer: Issuer) -> None:
    """S11: decoy clusters draw their sizes from these counts."""
    wallet.issue([EcKey.generate() for _ in range(3)])
    assert issuer.store.items("status-batch") == [("3", 1)]


def test_selective_disclosure_objects_carry_decoy_digests(wallet: Wallet) -> None:
    """C2 / L-3: across a batch of ten, some top-level _sd array holds more digests than claims."""
    from .helpers import disclosures

    response = wallet.issue([EcKey.generate() for _ in range(10)])
    top_level = {*PID_SUBJECT, "date_of_issuance"}
    decoys = []
    for item in response.json()["credentials"]:
        _, payload, decoded = disclosures(item["credential"])
        assert {d[1] for d in decoded if len(d) == 3} >= top_level
        decoys.append(len(payload["_sd"]) - len(top_level))
    assert min(decoys) >= 0 and max(decoys) > 0, decoys  # each array gets 0 to 3: all zero has odds 4**-10


def test_status_token_lives_for_its_configured_lifetime(issuer: Issuer, clock: Clock) -> None:
    """T10."""
    issuer.status.allocate()
    payload = parse_jws(issuer.status.token("1")).payload
    assert payload["exp"] - payload["iat"] == issuer.settings.status_token_lifetime
    assert payload["ttl"] == issuer.settings.status_token_ttl


def test_sqlite_take_is_one_transaction_against_another_process(tmp_path: Path) -> None:
    """ST1: take() reads and deletes inside one write transaction. Another worker that tries to take the
    same row between our first statement and our read must wait, so exactly one of the two gets it."""
    import sqlite3
    import threading
    import time

    other = sqlite3.connect(tmp_path / "s.db", isolation_level=None, timeout=30, check_same_thread=False)
    taken_by_other: list[int] = []

    def other_worker() -> None:
        other.execute("BEGIN IMMEDIATE")
        taken_by_other.append(other.execute("DELETE FROM kv WHERE ns='offer' AND key='k'").rowcount)
        time.sleep(0.3)
        other.execute("COMMIT")

    class Racing(SqliteStore):
        racer: threading.Thread | None = None

        def _purge(self, ns: str, key: str) -> None:
            super()._purge(ns, key)
            if self.racer is None:  # the other worker arrives right after our first statement
                self.racer = threading.Thread(target=other_worker)
                self.racer.start()
                time.sleep(0.1)

    store = Racing(tmp_path / "s.db")
    store.put("offer", "k", {"v": 1}, None)
    mine = store.take("offer", "k")
    assert store.racer is not None
    store.racer.join(10)
    assert (mine is not None) + taken_by_other[0] == 1, "the row was handed out exactly once"


def test_both_proof_types_are_published(issuer: Issuer) -> None:
    """M2: configurations that require a key attestation advertise jwt and attestation proofs (ARF WUA_10), also
    when the configuration file names only jwt. One that requires none offers jwt only: an attestation proof without
    key_attestations_required makes wallets on the EU reference library refuse the whole metadata."""
    from cunho.metadata import published_config

    published = issuer.issuer_metadata()["credential_configurations_supported"][PID_CONFIG]
    assert set(published["proof_types_supported"]) == {"jwt", "attestation"}
    required = {"key_storage": ["iso_18045_moderate"]}
    jwt_only = {
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256"], "key_attestations_required": required}
        }
    }
    proofs = published_config(jwt_only, "ES256")["proof_types_supported"]
    assert set(proofs) == {"jwt", "attestation"} and proofs["attestation"] == proofs["jwt"]
    empty = {
        "proof_types_supported": {
            "jwt": {"proof_signing_alg_values_supported": ["ES256"], "key_attestations_required": {}}
        }
    }
    assert set(published_config(empty, "ES256")["proof_types_supported"]) == {"jwt", "attestation"}
    plain = {"proof_types_supported": {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}}}
    assert set(published_config(plain, "ES256")["proof_types_supported"]) == {"jwt"}
    for spec in published["proof_types_supported"].values():
        assert "key_attestations_required" in spec
