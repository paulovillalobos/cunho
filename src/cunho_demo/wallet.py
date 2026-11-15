"""The demo wallet: for visitors with no EU wallet, a wallet run by the demo service itself, so they can watch an
issuance from offer to stored credential, look inside what was issued, and check its status as a verifier would.

It does what a wallet does with a pre-authorized offer (OpenID4VCI 1.0): it reads the issuer's metadata, gets a
DPoP-bound access token (typing the PIN when the offer asks for one), and for each credential it makes a fresh
holder key, has it attested by a wallet provider's key-attestation signer, proves possession with a key proof on
the issuer's nonce, takes the credential, and tells the issuer it stored it. Then it checks what it got: the
issuer's signature with the certificate the credential carries, and that every disclosed claim (SD-JWT VC) or data
element (mdoc) is one the issuer signed a digest of. It takes no code-flow offer, so it never meets a held
issuance (cunho holds code-flow issuances only).

It is not a wallet anyone should keep credentials in: its keys live in the demo's memory for the half hour of the
session. The page says so. It only ever talks to the two issuers the demo is configured with, by their internal
address: every URL it is given has to be on the public origin of the issuer that made the offer, and is sent to
that issuer's internal address instead (the address the demo already uses for the operator API), while the
proofs it signs name the public URL, as cunho checks them."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
import time
import uuid
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import cbor2
import httpx
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

PRE_AUTH = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
TIMEOUT = httpx.Timeout(10.0)
# Claims of an SD-JWT VC that say what the credential is rather than what it says about the person.
ENVELOPE = {"iss", "iat", "nbf", "exp", "vct", "vct#integrity", "cnf", "status", "_sd_alg", "sub"}
HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    "ES256": hashes.SHA256,
    "ES384": hashes.SHA384,
    "ES512": hashes.SHA512,
}
COSE_ALGS = {-7: "ES256", -35: "ES384", -36: "ES512"}


class WalletError(Exception):
    """The demo wallet could not go on; `key` names the reason the page shows."""

    def __init__(self, key: str, detail: str = "") -> None:
        super().__init__(f"{key}: {detail}" if detail else key)
        self.key = key
        self.detail = detail


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _json_part(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


@dataclass(frozen=True)
class Key:
    """A P-256 key that signs ES256."""

    private: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> Key:
        return cls(ec.generate_private_key(ec.SECP256R1()))

    def jwk(self) -> dict[str, str]:
        numbers = self.private.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }

    def sign(self, data: bytes) -> bytes:
        r, s = decode_dss_signature(self.private.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def jws(header: dict[str, Any], payload: dict[str, Any], key: Key) -> str:
    signing_input = f"{_json_part(header)}.{_json_part(payload)}"
    return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"


@dataclass(frozen=True)
class KeyAttester:
    """A wallet provider's key-attestation signer: its certificate chain (the signer first) and its key."""

    chain: tuple[str, ...]  # base64 DER, as an x5c header carries it
    key: Key

    @classmethod
    def from_files(cls, certificates: Path, private_key: Path) -> KeyAttester:
        chain = x509.load_pem_x509_certificates(certificates.read_bytes())
        loaded = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
        if not isinstance(loaded, ec.EllipticCurvePrivateKey) or loaded.curve.name != "secp256r1":
            raise ValueError("the key-attestation signer's key must be a P-256 key")
        signer = chain[0].public_key()
        if not isinstance(signer, ec.EllipticCurvePublicKey) or (
            signer.public_numbers() != loaded.public_key().public_numbers()
        ):
            raise ValueError("the key-attestation signer's key is not the key of the first certificate")
        der = tuple(base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in chain)
        return cls(der, Key(loaded))

    def attest(self, keys: list[Key], now: int) -> str:
        """A key attestation (OpenID4VCI 1.0 Appendix D.1) of the holder keys, with a placeholder status: the
        demo's wallet provider publishes no status list for its keys, which the issuers know."""
        payload = {
            "iat": now,
            "exp": now + 3600,
            "attested_keys": [k.jwk() for k in keys],
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_high"],
            "key_storage_status": {
                "status": {"status_list": {"idx": 0, "uri": "https://wallet-provider.invalid/status/1"}},
                "exp": now + 30 * 86_400,
            },
        }
        return jws({"typ": "key-attestation+jwt", "alg": "ES256", "x5c": list(self.chain)}, payload, self.key)


@dataclass
class Activity:
    """What the demo wallet has done in one session, for the page: the steps it went through (keys of the page's
    words), how it ended, and what it holds."""

    state: str = "running"  # running, done, failed
    steps: list[str] = field(default_factory=list)
    error: str | None = None
    credentials: list[dict[str, Any]] = field(default_factory=list)
    checked_at: str | None = None  # when the status was last checked as a verifier would

    @property
    def redeemed(self) -> bool:
        """Whether the run got a token, so the offer's pre-authorized code is spent."""
        return "wallet_token" in self.steps

    def view(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "retry": self.state == "failed" and not self.redeemed,
            "steps": list(self.steps),
            "error": self.error,
            "credentials": [{k: v for k, v in c.items() if not k.startswith("_")} for c in self.credentials],
            "checked_at": self.checked_at,
        }


@dataclass(frozen=True)
class Route:
    """How the demo wallet reaches one issuer: the issuer's internal base URL (the operator API's), the
    transport (tests pass one), and the TLS trust for it."""

    internal: str
    transport: httpx.AsyncBaseTransport | None = None
    verify: Any = True


class DemoWallet:
    def __init__(self, attester: KeyAttester, routes: dict[str, Route], clock: Callable[[], float] = time.time) -> None:
        self.attester = attester
        self.routes = routes
        self.clock = clock

    def _client(self, issuer: str, visitor: str | None = None) -> httpx.AsyncClient:
        """`visitor` is the address of the visitor the wallet acts for. The issuer limits requests per client address,
        and every request of this wallet reaches it from the demo service: named in X-Forwarded-For, as the proxy in
        front names a wallet that calls the issuer itself, the visitor is counted as themselves, and one visitor's
        runs never use up what the issuer allows the others (the security review). An issuer that does not take
        the header from the demo service counts all of them as one client, as before."""
        route = self.routes[issuer]
        return httpx.AsyncClient(
            timeout=TIMEOUT,
            transport=route.transport,
            verify=route.verify,
            follow_redirects=False,
            headers={"X-Forwarded-For": visitor} if visitor else None,
        )

    def _internal(self, issuer: str, public_issuer: str, url: str) -> str:
        """The URL to send a request to: a URL on the issuer's public origin, moved to its internal one. Anything
        else is refused, so the wallet never follows a URL somewhere else."""
        public, internal, target = urlsplit(public_issuer), urlsplit(self.routes[issuer].internal), urlsplit(url)
        if (target.scheme, target.netloc) != (public.scheme, public.netloc) or public.path != internal.path:
            raise WalletError("wallet_unreachable", url)
        return urlunsplit((internal.scheme, internal.netloc, target.path, target.query, ""))

    def _dpop(self, key: Key, method: str, url: str, token: str | None = None, nonce: str | None = None) -> str:
        payload: dict[str, Any] = {
            "jti": str(uuid.uuid4()),
            "htm": method,
            "htu": url.split("?")[0],
            "iat": int(self.clock()),
        }
        if token is not None:
            payload["ath"] = b64u(hashlib.sha256(token.encode()).digest())
        if nonce is not None:
            payload["nonce"] = nonce
        return jws({"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk()}, payload, key)

    async def run(
        self,
        issuer: str,
        offer: dict[str, Any],
        tx_code: str | None,
        activity: Activity,
        visitor: str | None = None,
    ) -> None:
        """Take every credential of a pre-authorized offer. Never raises: how it ended is in the activity."""
        try:
            await self._run(issuer, offer, tx_code, activity, visitor)
            activity.state = "done"
        except WalletError as exc:
            activity.state, activity.error = "failed", exc.key
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            activity.state, activity.error = "failed", "wallet_broken"

    async def _run(
        self,
        issuer: str,
        offer: dict[str, Any],
        tx_code: str | None,
        activity: Activity,
        visitor: str | None,
    ) -> None:
        public = offer["credential_issuer"]
        grant = offer["grants"][PRE_AUTH]
        async with self._client(issuer, visitor) as client:

            async def get(url: str) -> Any:
                answer = await client.get(self._internal(issuer, public, url))
                if answer.status_code != 200:
                    raise WalletError("wallet_metadata", f"{answer.status_code} at {url}")
                return answer.json()

            parts = urlsplit(public)
            metadata = await get(f"{parts.scheme}://{parts.netloc}/.well-known/openid-credential-issuer{parts.path}")
            server = (metadata.get("authorization_servers") or [public])[0]
            server_parts = urlsplit(server)
            oauth = await get(
                f"{server_parts.scheme}://{server_parts.netloc}/.well-known/oauth-authorization-server"
                f"{server_parts.path}"
            )
            activity.steps.append("wallet_metadata")

            dpop_key = Key.generate()
            server_nonce: list[str] = []  # the issuer's latest DPoP nonce (RFC 9449 section 8), once it gives one

            async def dpop_post(url: str, token: str | None = None, **send: Any) -> httpx.Response:
                """A POST with a DPoP proof; on a use_dpop_nonce challenge, once more with the nonce it gave."""
                for _ in range(2):
                    nonce = server_nonce[-1] if server_nonce else None
                    headers = {"DPoP": self._dpop(dpop_key, "POST", url, token, nonce)}
                    if token is not None:
                        headers["Authorization"] = f"DPoP {token}"
                    answer = await client.post(self._internal(issuer, public, url), headers=headers, **send)
                    if fresh := answer.headers.get("DPoP-Nonce"):
                        server_nonce.append(fresh)
                    if not (fresh and answer.status_code in (400, 401) and _asks_nonce(answer)):
                        return answer
                return answer

            token_endpoint = oauth["token_endpoint"]
            form = {"grant_type": PRE_AUTH, "pre-authorized_code": grant["pre-authorized_code"]}
            if "tx_code" in grant:
                if not tx_code:
                    raise WalletError("wallet_no_pin")
                form["tx_code"] = tx_code
                activity.steps.append("wallet_pin")
            answer = await dpop_post(token_endpoint, data=form)
            if answer.status_code != 200:
                raise WalletError("wallet_token", f"{answer.status_code} {answer.text[:200]}")
            token = answer.json()["access_token"]
            activity.steps.append("wallet_token")

            notices: list[str] = []
            for config_id in offer["credential_configuration_ids"]:
                configuration = metadata["credential_configurations_supported"][config_id]
                nonce_endpoint = metadata["nonce_endpoint"]
                nonce = await client.post(self._internal(issuer, public, nonce_endpoint))
                holder = Key.generate()
                proof_payload = {"aud": public, "iat": int(self.clock()), "nonce": nonce.json()["c_nonce"]}
                header = {
                    "typ": "openid4vci-proof+jwt",
                    "alg": "ES256",
                    "jwk": holder.jwk(),
                    "key_attestation": self.attester.attest([holder], int(self.clock())),
                }
                proof = jws(header, proof_payload, holder)
                activity.steps.append("wallet_proof")
                endpoint = metadata["credential_endpoint"]
                body = {"credential_configuration_id": config_id, "proofs": {"jwt": [proof]}}
                answer = await dpop_post(endpoint, token, json=body)
                if answer.status_code != 200:
                    # 202 too: cunho holds only code-flow issuances, which this wallet does not take.
                    raise WalletError("wallet_refused", f"{answer.status_code} {answer.text[:200]}")
                issued = answer.json()
                for item in issued["credentials"]:
                    activity.credentials.append(inspect(configuration["format"], item["credential"], holder.jwk()))
                activity.steps.append("wallet_issued")
                notices.append(issued["notification_id"])

            endpoint = metadata["notification_endpoint"]
            for notice in notices:
                answer = await dpop_post(
                    endpoint, token, json={"notification_id": notice, "event": "credential_accepted"}
                )
                if answer.status_code != 204:
                    raise WalletError("wallet_notification", str(answer.status_code))
            activity.steps.append("wallet_stored")

    async def check_status(
        self, issuer: str, public_issuer: str, activity: Activity, visitor: str | None = None
    ) -> None:
        """Read each credential's place on the issuer's status list as a verifier would: fetch the list, check
        its signature, and read the bits at the credential's index."""
        async with self._client(issuer, visitor) as client:
            for credential in activity.credentials:
                reference = credential.get("status")
                if not reference:
                    credential["status_value"] = "none"
                    continue
                answer = await client.get(
                    self._internal(issuer, public_issuer, reference["uri"]),
                    headers={"Accept": "application/statuslist+jwt"},
                )
                if answer.status_code != 200:
                    credential["status_value"] = "unknown"
                    continue
                credential["status_value"] = read_status(answer.text, reference["uri"], reference["idx"], self.clock())
        activity.checked_at = dt.datetime.fromtimestamp(self.clock(), dt.UTC).strftime("%H:%M:%S UTC")


def _asks_nonce(answer: httpx.Response) -> bool:
    """Whether an answer is a use_dpop_nonce challenge: in the body at the token endpoint, in WWW-Authenticate at
    a resource (RFC 9449 sections 8 and 9)."""
    if "use_dpop_nonce" in answer.headers.get("WWW-Authenticate", ""):
        return True
    try:
        body = answer.json()
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("error") == "use_dpop_nonce"


# --- what the wallet checks in a credential it was given ---------------------------------------------------------


def _subject_name(certificate: x509.Certificate) -> str:
    names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(names[0].value) if names else certificate.subject.rfc4514_string()


def _chain_holds(chain: list[x509.Certificate]) -> bool:
    """Each certificate of the chain is signed by the next one."""
    try:
        for lower, upper in zip(chain, chain[1:], strict=False):
            lower.verify_directly_issued_by(upper)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _verify(certificate: x509.Certificate, alg: str, signing_input: bytes, signature: bytes) -> bool:
    key = certificate.public_key()
    if alg not in HASHES or not isinstance(key, ec.EllipticCurvePublicKey):
        return False
    size = (key.curve.key_size + 7) // 8
    if len(signature) != 2 * size:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big"))
    try:
        key.verify(der, signing_input, ec.ECDSA(HASHES[alg]()))
    except InvalidSignature:
        return False
    return True


def _text(value: Any) -> str:
    """A claim's value as one line of text."""
    if isinstance(value, dict):
        # A place reads from the smallest part to the country, as people write it.
        parts = sorted(value.items(), key=lambda item: item[0] == "country")
        return ", ".join(_text(v) for _, v in parts)
    if isinstance(value, list):
        return ", ".join(_text(v) for v in value)
    if isinstance(value, cbor2.CBORTag):
        return _text(value.value)
    if isinstance(value, bytes):
        return f"{len(value)} bytes"
    return str(value)


def _date(value: Any) -> str | None:
    if isinstance(value, int):
        return dt.datetime.fromtimestamp(value, dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, cbor2.CBORTag):
        return str(value.value)
    return str(value) if value is not None else None


def inspect(fmt: str, credential: str, holder: dict[str, str]) -> dict[str, Any]:
    """What the page shows of a credential: its format and type, who signed it and whether the signature and
    digests hold, its validity, its place on the status list, and the claims it holds."""
    if fmt == "mso_mdoc":
        return inspect_mdoc(credential, holder)
    return inspect_sd_jwt(credential, holder)


def _same_point(holder: dict[str, str], x: Any, y: Any) -> bool:
    """Whether a key the credential names is the wallet's holder key (P-256: the same curve point)."""
    return (
        isinstance(x, bytes)
        and isinstance(y, bytes)
        and (x, y)
        == (
            b64u_decode(holder["x"]),
            b64u_decode(holder["y"]),
        )
    )


def inspect_sd_jwt(credential: str, holder: dict[str, str]) -> dict[str, Any]:
    parts = credential.split("~")
    issuer_jwt, disclosures = parts[0], [d for d in parts[1:] if d]
    head, body, signature = issuer_jwt.split(".")
    header = json.loads(b64u_decode(head))
    payload = json.loads(b64u_decode(body))
    chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header.get("x5c", [])]
    signed = bool(chain) and _verify(chain[0], header.get("alg", ""), f"{head}.{body}".encode(), b64u_decode(signature))
    by_digest = {b64u(hashlib.sha256(d.encode()).digest()): json.loads(b64u_decode(d)) for d in disclosures}
    used: set[str] = set()

    def reveal(node: Any) -> Any:
        if isinstance(node, dict):
            out = {k: reveal(v) for k, v in node.items() if k != "_sd"}
            for digest in node.get("_sd", []):
                if digest in by_digest and len(by_digest[digest]) == 3:
                    used.add(digest)
                    _, name, value = by_digest[digest]
                    out[name] = reveal(value)
            return out
        if isinstance(node, list):
            items = []
            for item in node:
                if isinstance(item, dict) and set(item) == {"..."}:
                    if item["..."] in by_digest and len(by_digest[item["..."]]) == 2:
                        used.add(item["..."])
                        items.append(reveal(by_digest[item["..."]][1]))
                    continue
                items.append(reveal(item))
            return items
        return node

    claims = reveal(payload)
    status = payload.get("status", {}).get("status_list")
    return {
        "format": "dc+sd-jwt",
        "type": str(payload.get("vct", "")),
        "signer": _subject_name(chain[0]) if chain else None,
        "signature": signed and _chain_holds(chain),
        "digests": payload.get("_sd_alg", "sha-256") == "sha-256" and used == set(by_digest),
        "disclosures": len(disclosures),
        "valid_from": _date(payload.get("iat")),
        "valid_until": _date(payload.get("exp")),
        # Bound to the key the wallet made for this credential, not merely to some key.
        "holder_bound": _bound_jwk(payload.get("cnf"), holder),
        "status": {"idx": status["idx"], "uri": status["uri"]} if isinstance(status, dict) else None,
        "claims": [[name, _text(value)] for name, value in claims.items() if name not in ENVELOPE],
        "raw": credential,
    }


def _bound_jwk(cnf: Any, holder: dict[str, str]) -> bool:
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return False
    try:
        return _same_point(holder, b64u_decode(str(jwk.get("x"))), b64u_decode(str(jwk.get("y"))))
    except ValueError:
        return False


def inspect_mdoc(credential: str, holder: dict[str, str]) -> dict[str, Any]:
    issuer_signed = cbor2.loads(b64u_decode(credential))
    protected, unprotected, payload, signature = issuer_signed["issuerAuth"]
    header = cbor2.loads(protected) if protected else {}
    chain_der = unprotected.get(33)
    chain_der = [chain_der] if isinstance(chain_der, bytes) else list(chain_der or [])
    chain = [x509.load_der_x509_certificate(c) for c in chain_der]
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    alg = COSE_ALGS.get(int(header.get(1, 0)), "")
    signed = bool(chain) and _verify(chain[0], alg, to_sign, signature)
    mso_item = cbor2.loads(payload)
    mso = cbor2.loads(mso_item.value if isinstance(mso_item, cbor2.CBORTag) else mso_item)
    digests_hold = mso.get("digestAlgorithm") == "SHA-256"
    claims: list[list[str]] = []
    for namespace, items in issuer_signed["nameSpaces"].items():
        expected = mso["valueDigests"].get(namespace, {})
        for tagged in items:
            raw = tagged.value if isinstance(tagged, cbor2.CBORTag) else tagged
            item = cbor2.loads(raw)
            digest = hashlib.sha256(cbor2.dumps(cbor2.CBORTag(24, raw))).digest()
            digests_hold = digests_hold and expected.get(item["digestID"]) == digest
            claims.append([str(item["elementIdentifier"]), _text(item["elementValue"])])
    status = mso.get("status", {}).get("status_list") if isinstance(mso.get("status"), dict) else None
    validity = mso.get("validityInfo", {})
    return {
        "format": "mso_mdoc",
        "type": str(mso.get("docType", "")),
        "signer": _subject_name(chain[0]) if chain else None,
        "signature": signed and _chain_holds(chain),
        "digests": digests_hold,
        "disclosures": len(claims),
        "valid_from": _date(validity.get("validFrom")),
        "valid_until": _date(validity.get("validUntil")),
        # The device key, a COSE_Key (EC2: 1 kty 2, -1 crv 1 for P-256, -2 x, -3 y), is the wallet's key.
        "holder_bound": isinstance(device := mso.get("deviceKeyInfo", {}).get("deviceKey"), dict)
        and device.get(1) == 2
        and device.get(-1) == 1
        and _same_point(holder, device.get(-2), device.get(-3)),
        "status": {"idx": status["idx"], "uri": status["uri"]} if isinstance(status, dict) else None,
        "claims": claims,
        "raw": credential,
    }


def read_status(token: str, uri: str, index: int, now: float) -> str:
    """The status a verifier reads for one index of a status list token (statuslist+jwt): "valid", "invalid",
    "suspended", or "unknown" when the token does not check out."""
    try:
        head, body, signature = token.strip().split(".")
        header = json.loads(b64u_decode(head))
        payload = json.loads(b64u_decode(body))
        chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header.get("x5c", [])]
        if header.get("typ") != "statuslist+jwt" or payload.get("sub") != uri or not chain:
            return "unknown"
        if not _verify(chain[0], header.get("alg", ""), f"{head}.{body}".encode(), b64u_decode(signature)):
            return "unknown"
        if "exp" in payload and payload["exp"] < now:
            return "unknown"
        bits = int(payload["status_list"]["bits"])
        data = zlib.decompress(b64u_decode(payload["status_list"]["lst"]))
        position = index * bits
        value = (data[position // 8] >> (position % 8)) & ((1 << bits) - 1)
    except (ValueError, KeyError, TypeError, IndexError, zlib.error):
        return "unknown"
    return {0: "valid", 1: "invalid", 2: "suspended"}.get(value, "unknown")


def offer_token() -> str:
    """The reference a credential offer is fetched by (credential_offer_uri) and the phone page is opened with."""
    return secrets.token_urlsafe(18)
