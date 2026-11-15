"""Wallet providers' status lists for tests: tokens signed by a test wallet provider's status list signer, and a
fetcher that serves them from memory, so no test reaches the network."""

from __future__ import annotations

import base64
import datetime as dt
import zlib
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from cunho.fetch import Fetcher, FetchError
from eudi_probe.jose import EcKey, b64u, jws

from .helpers import START, certificate, der_b64

KA_STATUS_LIST = "https://wallet-provider.test/status/1"  # the list the test key attestations name (helpers.py)


def packed(entries: dict[int, int], bits: int = 1, size: int = 64) -> str:
    """`lst` for `size` entries of `bits` bits, all VALID but `entries`, the first in the lowest bits."""
    statuses = bytearray(size * bits // 8 or 1)
    for idx, value in entries.items():
        at = idx * bits
        statuses[at // 8] |= value << (at % 8)
    return b64u(zlib.compress(bytes(statuses)))


@dataclass
class StatusSigner:
    """A status list signer and the x5c it sends: its own certificate and the chain up to, not including, the
    anchor."""

    key: EcKey
    x5c: list[str]

    @classmethod
    def under(
        cls,
        issuer: x509.Certificate,
        issuer_key: ec.EllipticCurvePrivateKey,
        *chain: x509.Certificate,
        not_after: dt.datetime | None = None,
    ) -> StatusSigner:
        key = EcKey.generate()
        cert = certificate("Test Wallet Provider Status Signer", key.private, (issuer, issuer_key), not_after=not_after)
        return cls(key, [der_b64(cert), *(der_b64(c) for c in chain)])

    def token(
        self,
        uri: str,
        entries: dict[int, int] | None = None,
        *,
        bits: int = 1,
        size: int = 64,
        iat: int = START,
        exp: Any = START + 86_400,
        ttl: Any = None,
        header: dict[str, Any] | None = None,
        **claims: Any,
    ) -> str:
        payload: dict[str, Any] = {
            "sub": uri,
            "iat": iat,
            "exp": exp,
            "status_list": {"bits": bits, "lst": packed(entries or {}, bits, size)},
        }
        if ttl is not None:
            payload["ttl"] = ttl
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not ...}
        head = {"typ": "statuslist+jwt", "alg": "ES256", "x5c": self.x5c, **(header or {})}
        return jws({k: v for k, v in head.items() if v is not ...}, payload, self.key)

    def identifiers(
        self,
        uri: str,
        revoked: list[bytes] | None = None,
        *,
        iat: Any = START,
        exp: Any = START + 86_400,
        ttl: Any = None,
        protected: dict[int, Any] | None = None,
        claims: dict[int, Any] | None = None,
        tagged: bool = True,
        tag: int = 18,
        key: EcKey | None = None,
        raw_protected: bytes | None = None,
        raw_payload: bytes | None = None,
    ) -> bytes:
        """An identifier list (CIR 2024/2979 Annex II EAA-6.2.10.1-08 to -10), signed here with cbor2 and
        cryptography alone: a COSE_Sign1_Tagged CWT with its type and x5chain in the protected header."""
        chain = [base64.b64decode(c) for c in self.x5c]
        head: dict[int, Any] = {
            1: -7,
            16: "application/identifierlist+cwt",
            33: chain[0] if len(chain) == 1 else chain,
            **(protected or {}),
        }
        payload: dict[int, Any] = {2: uri, 6: iat, 4: exp, 65530: {"identifiers": {i: {} for i in revoked or []}}}
        if ttl is not None:
            payload[65534] = ttl
        payload.update(claims or {})
        head = {k: v for k, v in head.items() if v is not ...}
        payload = {k: v for k, v in payload.items() if v is not ...}
        header_bytes = raw_protected if raw_protected is not None else cbor2.dumps(head)
        payload_bytes = raw_payload if raw_payload is not None else cbor2.dumps(payload)
        signing = (key or self.key).private
        r, s = decode_dss_signature(
            signing.sign(cbor2.dumps(["Signature1", header_bytes, b"", payload_bytes]), ec.ECDSA(hashes.SHA256()))
        )
        message = [header_bytes, {}, payload_bytes, r.to_bytes(32) + s.to_bytes(32)]
        return cbor2.dumps(cbor2.CBORTag(tag, message) if tagged else message)


@dataclass
class ServedStatus(Fetcher):
    """A fetcher that answers from `lists`, by URL, and records each URL it is asked for."""

    lists: dict[str, bytes | str] = field(default_factory=dict)
    asked: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__init__(None)

    def get(self, url: str, *, types: Any, max_bytes: int, budget: float) -> bytes:
        self.asked.append(url)
        served = self.lists.get(url)
        if served is None:
            raise FetchError("not served")
        data = served.encode() if isinstance(served, str) else served
        if len(data) > max_bytes:
            raise FetchError("the reply is larger than allowed")
        return data
