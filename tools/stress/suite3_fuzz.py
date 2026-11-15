"""Suite 3 - Property-based fuzzing (Hypothesis).

Two layers:
  * In-process: jose.parse_jws, jose.public_key_from_jwk, jose.load_x5c/validate_path,
    credentials.validate_subject / validate_pid, metadata.validate, status bit-encoding, and
    lote.read_lote over raw bytes and over lists correctly signed by the pinned signer with one member
    changed to an arbitrary value (M3).
    Property: the function returns, or raises one of its DECLARED exception types -- never an
    unhandled crash (RecursionError, TypeError, AttributeError, KeyError, MemoryError, ...),
    never a hang (> 2 s), and the whole run keeps memory bounded.
    M4 adds cunho's JWE request decryption over arbitrary text, the wallet's credential_response_encryption
    parameters, and mdoc subject data against the IBAN mdoc configuration.
  * HTTP: every endpoint fuzzed with arbitrary bodies/headers/methods, and DPoP proofs, key proofs and
    key attestations that are correctly signed but carry arbitrary claim values (huge integers, floats,
    nested values), so the checks after the signature are reached (review 3, N3-M1 and N3-L4). The
    authorization code flow likewise (M3): PAR with arbitrary forms, and with wallet attestations and
    their proofs of possession correctly signed but carrying arbitrary claims, /authorize with arbitrary
    queries, and the code grant at /token with arbitrary fields. M4: the deferred credential and notification
    endpoints with arbitrary bodies, and the credential endpoint with arbitrary application/jwt bodies, from
    random text to five-part JWEs whose protected header is arbitrary JSON, so the decryption's checks are reached.
    Property: no 5xx, every response within 2 s.

Text is drawn with lone surrogates, NUL and other characters that cannot be encoded or are rarely
expected: Hypothesis never puts a surrogate in st.text(), whatever its alphabet, so strings are joined
from single characters instead. Key attestation certificates are fuzzed byte by byte, in-process and
signed over HTTP, so the path checks meet certificates that load only in part (review 4, N4-M1, N4-M2,
N4-L7).
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import signal
import sys
import time
import tracemalloc
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType
from typing import Any
from urllib.parse import quote

import common
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cunho import credentials, jose, jwe, lote, metadata, proofs
from cunho.errors import ConfigError
from cunho.settings import Settings
from cunho.status import StatusLists, StatusRef
from cunho.store import MemoryStore

QUICK = "--quick" in sys.argv
SRC_METADATA = common.SRC / "src" / "cunho" / "metadata_config" / "credentials_supported"
MAX_EX = 60 if QUICK else 400
HANG_S = 2.0


class Hang(Exception):
    pass


@contextmanager
def deadline(seconds: float) -> Iterator[None]:
    def _fire(signum: int, frame: FrameType | None) -> None:
        raise Hang()

    old = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


# Outcome of a single fuzz call; "unexpected" means a crash the design forbids.
def run_target(fn: Callable[[], object], expected: tuple[type[BaseException], ...], bad: list[str]) -> None:
    try:
        with deadline(HANG_S):
            fn()
    except Hang:
        bad.append("HANG")
    except expected:
        pass
    except Exception as exc:  # noqa: BLE001
        bad.append(f"{type(exc).__name__}:{str(exc)[:80]}")


# --------------------------------------------------------------------------- strategies

ODD = st.sampled_from(["\ud800", "\udbff", "\udc00", "\udfff", "\x00", "\u2028", "\ufffe", "\U0010ffff"])


def texts(max_size: int) -> st.SearchStrategy[str]:
    """Any text, lone surrogates included, which st.text() never yields."""
    return st.lists(st.characters(exclude_categories=()) | ODD, max_size=max_size).map("".join)


json_atoms = st.none() | st.booleans() | st.integers() | st.floats() | texts(40)
json_vals = st.recursive(
    json_atoms,
    lambda c: st.lists(c, max_size=5) | st.dictionaries(texts(12), c, max_size=5),
    max_leaves=25,
)
jwk_strat = st.dictionaries(
    st.sampled_from(["kty", "crv", "x", "y", "d", "n", "e"]),
    st.one_of(texts(90), st.integers(), st.lists(texts(8), max_size=4), st.none()),
    max_size=6,
)
alg_strat = st.one_of(
    st.sampled_from(["ES256", "ES384", "ES512", "none", "HS256", "RS256"]),
    texts(8),
    st.lists(texts(4), max_size=3),
    st.none(),
)


def wallet_providers_payload(provider: Any, now: dt.datetime) -> dict[str, Any]:
    """A wallet providers list (ETSI TS 119 602 Annex E) naming `provider`, issued a day before `now`."""
    from cryptography.hazmat.primitives import serialization

    stamp = "%Y-%m-%dT%H:%M:%SZ"
    der = base64.b64encode(provider.public_bytes(serialization.Encoding.DER)).decode()

    def service(kind: str) -> dict[str, Any]:
        return {
            "ServiceInformation": {
                "ServiceName": [{"lang": "en", "value": "Stress Wallet Solution"}],
                "ServiceTypeIdentifier": f"http://uri.etsi.org/19602/SvcType/WalletSolution/{kind}",
                "ServiceDigitalIdentity": {"X509Certificates": [{"val": der}]},
            }
        }

    return {
        "LoTE": {
            "ListAndSchemeInformation": {
                "LoTEVersionIdentifier": 1,
                "LoTESequenceNumber": 1,
                "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
                "SchemeOperatorName": [{"lang": "en", "value": "cunho test scheme operator"}],
                "SchemeTerritory": "EU",
                "ListIssueDateTime": (now - dt.timedelta(days=1)).strftime(stamp),
                "NextUpdate": (now + dt.timedelta(days=30)).strftime(stamp),
            },
            "TrustedEntitiesList": [
                {
                    "TrustedEntityInformation": {
                        "TEName": [{"lang": "en", "value": "Stress Wallet Provider"}],
                        "TEAddress": {
                            "TEPostalAddress": [{"lang": "en", "StreetAddress": "Rua 1", "Country": "PT"}],
                            "TEElectronicAddress": [{"lang": "en", "uriValue": "mailto:wp@example.test"}],
                        },
                        "TEInformationURI": [{"lang": "en", "uriValue": "https://wp.example.test"}],
                    },
                    "TrustedEntityServices": [service("Issuance"), service("Revocation")],
                }
            ],
        }
    }


def fuzz_inprocess(suite: common.Suite) -> None:
    pki = common.gen_pki(common.WORK_DIR / "fuzz")
    settings_obj = Settings(
        issuer_url="https://localhost",
        admin_token="x" * 40,
        signing_key=pki / "signing.key",
        signing_chain=pki / "signing.pem",
        status_signing_key=pki / "status.key",
        status_signing_chain=pki / "status.pem",
        wallet_provider_anchors=pki / "wallet-providers.pem",
        audit_retention_days=365,
        signer_certificate_url="https://localhost/certs/signer.pem",
    )
    anchors = jose.x509.load_pem_x509_certificates((pki / "wallet-providers.pem").read_bytes())
    today = dt.date(2026, 11, 4)
    targets: dict[str, list] = {}

    tracemalloc.start()
    st_set = settings(max_examples=MAX_EX, deadline=None, suppress_health_check=list(HealthCheck))

    @st_set
    @given(st.one_of(texts(120), st.binary(max_size=120), json_vals))
    def t_parse_jws(x: Any) -> None:
        run_target(lambda: jose.parse_jws(x), (jose.JoseError,), targets.setdefault("parse_jws", []))

    t_parse_jws()

    @st_set
    @given(json_vals, st.booleans())
    def t_strict_json(value: Any, as_bytes: bool) -> None:
        # json.dumps writes every surrogate as the escape \udxxx, which is legal JSON syntax.
        text = json.dumps(value)
        run_target(
            lambda: jose.strict_json(text.encode() if as_bytes else text),
            (ValueError,),
            targets.setdefault("strict_json", []),
        )

    t_strict_json()

    @st_set
    @given(json_vals)
    def t_jws_payload(value: Any) -> None:
        token = f"e30.{jose.b64u(json.dumps({'v': value}).encode())}.e30"
        run_target(lambda: jose.parse_jws(token), (jose.JoseError,), targets.setdefault("parse_jws payloads", []))

    t_jws_payload()

    @st_set
    @given(jwk_strat, alg_strat)
    def t_pubkey(jwk: Any, alg: Any) -> None:
        run_target(
            lambda: jose.public_key_from_jwk(jwk, alg), (jose.JoseError,), targets.setdefault("public_key_from_jwk", [])
        )

    t_pubkey()

    @st_set
    @given(st.one_of(st.lists(texts(60), max_size=4), texts(40), json_vals))
    def t_x5c(x: Any) -> None:
        run_target(
            lambda: jose.validate_path(jose.load_x5c(x), anchors, dt.datetime.now(dt.UTC)),
            (jose.JoseError,),
            targets.setdefault("load_x5c+validate_path", []),
        )

    t_x5c()

    # validate_path with real certs in arbitrary (possibly broken) orderings
    real = anchors[0]

    @st_set
    @given(st.lists(st.just(real), max_size=4))
    def t_vpath(chain: list[Any]) -> None:
        if not chain:
            return
        run_target(
            lambda: jose.validate_path(list(chain), anchors, dt.datetime.now(dt.UTC)),
            (jose.JoseError,),
            targets.setdefault("validate_path_realcerts", []),
        )

    t_vpath()

    # A real key attestation signer certificate with bytes changed: it may load and fail later, which used to
    # raise DuplicateExtension, ValueError or UnsupportedAlgorithm from the path checks (review 4, N4-M2).
    from eudi_probe.wallet import AttestationIssuer

    signer = AttestationIssuer.from_ca_files(pki / "wallet-providers.pem", pki / "wallet-provider.key")
    leaf_der = base64.b64decode(signer.leaf_der_b64)
    crls = proofs.parse_crls((pki / "wallet-providers.crl").read_bytes())

    @st_set
    @given(st.lists(st.tuples(st.integers(0, len(leaf_der) - 1), st.integers(0, 255)), min_size=1, max_size=4))
    def t_x5c_bytes(changes: list[tuple[int, int]]) -> None:
        der = bytearray(leaf_der)
        for at, value in changes:
            der[at] = value
        entry = base64.b64encode(bytes(der)).decode()
        run_target(
            lambda: jose.validate_path(jose.load_x5c([entry]), anchors, dt.datetime.now(dt.UTC), crls=crls),
            (jose.JoseError,),
            targets.setdefault("load_x5c+validate_path (changed DER)", []),
        )

    t_x5c_bytes()

    pid_config = metadata.load(settings_obj).all[common.PID_CONFIG]

    @st_set
    @given(json_vals)
    def t_vsub(data: Any) -> None:
        # validate_subject returns a problem list; it must never raise.
        run_target(
            lambda: credentials.validate_subject(pid_config, data, today),
            (),
            targets.setdefault("validate_subject", []),
        )

    t_vsub()

    @st_set
    @given(st.dictionaries(texts(20), json_vals, max_size=8))
    def t_vpid(data: Any) -> None:
        run_target(lambda: credentials.validate_pid(data, today), (), targets.setdefault("validate_pid", []))

    t_vpid()

    @st_set
    @given(texts(20), json_vals, st.one_of(st.none(), st.integers()))
    def t_meta(cid: str, config: Any, batch: int | None) -> None:
        run_target(
            lambda: metadata.validate(cid, config if isinstance(config, dict) else {}, batch),
            (ConfigError,),
            targets.setdefault("metadata.validate", []),
        )

    t_meta()

    @st_set
    @given(
        st.lists(
            st.tuples(st.integers(min_value=0, max_value=4095), st.integers(min_value=0, max_value=1)), max_size=30
        )
    )
    def t_status(entries: list[tuple[int, int]]) -> None:
        def go() -> None:
            store = MemoryStore(lambda: 1.0)
            sl = StatusLists(settings_obj, store, None, lambda: 1.0)  # type: ignore[arg-type]
            sl.allocate()  # opens list 1 as cunho does: a stored size, published bits and decoys
            for idx, val in entries:
                store.put("status-slot", f"1:{idx:08d}", 0, None)
                if val:
                    sl.revoke(StatusRef("1", idx))
            out = sl.encoded("1")
            assert isinstance(out, str)

        run_target(go, (), targets.setdefault("status.encoded", []))

    t_status()

    # The Commission's list (M3): raw bytes, then lists the pinned signer signed with one member changed.
    from cryptography.hazmat.primitives import serialization

    from eudi_probe.jose import EcKey, b64u, b64u_json

    lote_signer = jose.x509.load_pem_x509_certificate((pki / "m3" / "lote-signer.pem").read_bytes())
    lote_key = EcKey(serialization.load_pem_private_key((pki / "m3" / "lote-signer.key").read_bytes(), None))  # type: ignore[arg-type]
    lote_x5c = [base64.b64encode(lote_signer.public_bytes(serialization.Encoding.DER)).decode()]
    now = dt.datetime.now(dt.UTC)

    @st_set
    @given(st.one_of(st.binary(max_size=400), texts(200).map(lambda t: t.encode("utf-8", "surrogatepass"))))
    def t_lote_bytes(data: bytes) -> None:
        run_target(
            lambda: lote.read_lote(data, lote_signer, now), (lote.LoteError,), targets.setdefault("read_lote", [])
        )

    t_lote_bytes()

    def signed_list(payload_text: str) -> bytes:
        signing_input = f"{b64u_json({'alg': 'ES256', 'x5c': lote_x5c})}.{b64u(payload_text.encode())}"
        return f"{signing_input}.{b64u(lote_key.sign(signing_input.encode()))}".encode()

    base = wallet_providers_payload(anchors[0], now)
    places = (
        [("scheme", k) for k in base["LoTE"]["ListAndSchemeInformation"]]
        + [
            ("service", k)
            for k in base["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]["ServiceInformation"]
        ]
        + [("root", "LoTE"), ("entities", "TrustedEntitiesList")]
    )

    @st_set
    @given(st.sampled_from(places), json_vals)
    def t_lote_signed(place: tuple[str, str], value: Any) -> None:
        payload = json.loads(json.dumps(base))
        where, name = place
        if where == "scheme":
            payload["LoTE"]["ListAndSchemeInformation"][name] = value
        elif where == "service":
            payload["LoTE"]["TrustedEntitiesList"][0]["TrustedEntityServices"][0]["ServiceInformation"][name] = value
        elif where == "entities":
            payload["LoTE"][name] = value
        else:
            payload[name] = value
        data = signed_list(json.dumps(payload))
        run_target(
            lambda: lote.read_lote(data, lote_signer, now),
            (lote.LoteError,),
            targets.setdefault("read_lote (signed, one member changed)", []),
        )

    t_lote_signed()
    run_target(
        lambda: lote.read_lote(signed_list(json.dumps(base)), lote_signer, now),
        (),
        targets.setdefault("read_lote (signed, one member changed)", []),
    )

    # Deterministic probes for the documented crash classes (so the suite exercises them
    # regardless of the random draw). Each must raise only its declared exception type.
    good_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    }
    deep = ('{"a":' * 20000 + "1" + "}" * 20000).encode()
    probes = [
        ("parse_jws", lambda: jose.parse_jws("e30." + jose.b64u(deep) + ".e30"), (jose.JoseError,)),
        ("public_key_from_jwk", lambda: jose.public_key_from_jwk(good_jwk, ["ES256"]), (jose.JoseError,)),
        ("public_key_from_jwk", lambda: jose.public_key_from_jwk(good_jwk, {"a": 1}), (jose.JoseError,)),
        (
            "public_key_from_jwk",
            lambda: jose.public_key_from_jwk({"kty": "EC", "crv": "P-256", "x": ["a"], "y": 5}, "ES256"),
            (jose.JoseError,),
        ),
        (
            "validate_subject",
            lambda: credentials.validate_subject(pid_config, {"family_name": float("nan")}, today),
            (),
        ),
        ("validate_pid", lambda: credentials.validate_pid({"nationalities": float("inf")}, today), ()),
        ("metadata.validate", lambda: metadata.validate("x", {"proof_types_supported": ["x"]}, None), (ConfigError,)),
    ]
    for name, fn, exp in probes:
        run_target(fn, exp, targets.setdefault(name, []))

    # M4 -------------------------------------------------------------------------------------------------
    request_keys = jwe.RequestKeys.load((pki / "encryption.key",), False)
    assert request_keys is not None

    @st_set
    @given(st.one_of(texts(200), json_vals.map(lambda v: f"{jose.b64u(json.dumps(v).encode())}.a.b.c.d")))
    def t_jwe_decrypt(token: str) -> None:
        run_target(lambda: request_keys.decrypt(token), (jwe.JweError,), targets.setdefault("jwe.decrypt", []))

    t_jwe_decrypt()

    @st_set
    @given(json_vals)
    def t_response_params(params: Any) -> None:
        run_target(lambda: jwe.ResponseKey.from_params(params), (jwe.JweError,), targets.setdefault("ResponseKey", []))

    t_response_params()

    iban = json.loads((SRC_METADATA / "iban_mdoc.json").read_text())["eu.europa.ec.eudi.iban_mdoc"]

    @st_set
    @given(st.one_of(json_vals, st.dictionaries(st.sampled_from(["eu.europa.ec.eudi.iban.1", "x"]), json_vals)))
    def t_mdoc_subject(data: Any) -> None:
        run_target(
            lambda: credentials.validate_mdoc_subject(iban, data, today),
            (credentials.ClaimsError,),
            targets.setdefault("validate_mdoc_subject", []),
        )

    t_mdoc_subject()

    peak_mb = tracemalloc.get_traced_memory()[1] / 1_048_576
    tracemalloc.stop()

    for name, bad in targets.items():
        suite.record(
            f"inprocess:{name}: no unhandled exception / no hang",
            not bad,
            examples=MAX_EX,
            failures=len(bad),
            first=bad[0] if bad else None,
        )
    suite.record("inprocess: traced memory peak < 512 MB", peak_mb < 512, peak_mb=round(peak_mb, 1))
    suite.meta["inprocess_targets"] = {k: {"failures": len(v), "sample": v[:3]} for k, v in targets.items()}


# --------------------------------------------------------------------------- HTTP fuzz


def fuzz_http(server: common.Server, suite: common.Suite) -> None:
    bad: dict[str, list] = {}
    token = None
    try:
        token = common.new_wallet(server).get_token()
    except Exception:  # noqa: BLE001
        pass

    import httpx

    def hit(label: str, method: str, path: str, **kw: Any) -> None:
        http = common.client(server.issuer_url, timeout=HANG_S + 1.0)
        try:
            t0 = time.time()
            try:
                r = http.request(method, path, **kw)
            except httpx.TimeoutException:
                bad.setdefault(label, []).append("HANG")
                return
            except (httpx.RemoteProtocolError, httpx.ConnectError) as exc:
                # dropped connection can mean a worker died: a genuine server fault
                bad.setdefault(label, []).append(f"conn:{type(exc).__name__}")
                return
            except Exception:  # noqa: BLE001
                # client could not even form the request (e.g. non-ASCII header); not a server fault
                return
            el = time.time() - t0
            if r.status_code >= 500:
                bad.setdefault(label, []).append(f"{r.status_code}:{r.text[:80]}")
            elif el > HANG_S:
                bad.setdefault(label, []).append(f"slow:{el:.1f}s")
        finally:
            http.close()

    st_set = settings(
        max_examples=MAX_EX // 3 if QUICK else MAX_EX // 2, deadline=None, suppress_health_check=list(HealthCheck)
    )
    ct = st.sampled_from(["application/json", "application/x-www-form-urlencoded", "text/plain", "x", ""])

    @st_set
    @given(st.binary(max_size=300), ct)
    def f_token(body: bytes, c: str) -> None:
        hit("/token", "POST", "/token", content=body, headers={"Content-Type": c})

    f_token()

    @st_set
    @given(st.binary(max_size=300), ct, texts(120))
    def f_cred(body: bytes, c: str, dpop: str) -> None:
        headers = {"Content-Type": c, "Authorization": f"DPoP {token}" if token else "x", "DPoP": dpop}
        hit("/credential", "POST", "/credential", content=body, headers=headers)

    f_cred()

    @st_set
    @given(texts(40))
    def f_status(lid: str) -> None:
        hit("/status", "GET", f"/status/{lid}")

    f_status()

    @st_set
    @given(st.binary(max_size=200), texts(60))
    def f_offer(body: bytes, auth: str) -> None:
        hit(
            "/admin/offers",
            "POST",
            "/admin/offers",
            content=body,
            headers={"Content-Type": "application/json", "Authorization": auth},
        )

    f_offer()

    @st_set
    @given(
        st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH"]),
        st.sampled_from(
            [
                "/nonce",
                "/.well-known/openid-credential-issuer",
                "/.well-known/oauth-authorization-server",
                "/admin/revocations",
                "/admin/audit/verify",
            ]
        ),
    )
    def f_methods(m: str, p: str) -> None:
        hit(p + f"[{m}]", m, p, content=b"{}", headers={"Content-Type": "application/json"})

    f_methods()

    # Signed proofs with arbitrary claim values: the signature verifies, so every claim check runs.
    from eudi_probe.jose import EcKey, b64u, b64u_json

    def signed(header: dict[str, Any], payload_text: str, key: EcKey) -> str:
        signing_input = f"{b64u_json(header)}.{b64u(payload_text.encode())}"
        return f"{signing_input}.{b64u(key.sign(signing_input.encode()))}"

    big = st.sampled_from(["1" + "0" * 400, "-1" + "0" * 400, "1e400", "-1e400", str(2**53 + 1), "9" * 25])
    leaves = st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | texts(12)
    values = st.recursive(
        leaves, lambda inner: st.lists(inner, max_size=3) | st.dictionaries(texts(4), inner, max_size=3)
    )
    claim_text = big | values.map(lambda v: json.dumps(v))

    def with_claim(claims: dict[str, Any], name: str, text: str) -> str:
        return json.dumps({**claims, name: "@@"}).replace('"@@"', text)

    wallet = common.new_wallet(server)

    @st_set
    @given(st.sampled_from(["jti", "htm", "htu", "iat", "nonce"]), claim_text)
    def f_dpop_claims(name: str, text: str) -> None:
        key = EcKey.generate()
        claims = {"jti": uuid.uuid4().hex, "htm": "POST", "htu": f"{server.issuer_url}/token", "iat": int(time.time())}
        proof = signed(
            {"typ": "dpop+jwt", "alg": "ES256", "jwk": key.public_jwk()}, with_claim(claims, name, text), key
        )
        hit(
            "/token signed DPoP claims",
            "POST",
            "/token",
            content=b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code&pre-authorized_code=x",
            headers={"Content-Type": "application/x-www-form-urlencoded", "DPoP": proof},
        )

    f_dpop_claims()

    if token is not None:
        wallet.token = token
        attestations = wallet.attestation_issuer()

        @st_set
        @given(st.sampled_from(["aud", "iat", "nonce", "iss"]), claim_text)
        def f_proof_claims(name: str, text: str) -> None:
            holder = EcKey.generate()
            header = {
                "typ": "openid4vci-proof+jwt",
                "alg": "ES256",
                "jwk": holder.public_jwk(),
                "key_attestation": attestations.key_attestation([holder], nonce=None),
            }
            claims = {"aud": server.issuer_url, "iat": int(time.time()), "nonce": "n"}
            proof = signed(header, with_claim(claims, name, text), holder)
            body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [proof]}}
            dpop = wallet.dpop("POST", "/credential", access_token=token)
            hit(
                "/credential signed key-proof claims",
                "POST",
                "/credential",
                content=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"DPoP {token}", "DPoP": dpop},
            )

        f_proof_claims()

        leaf_der = base64.b64decode(attestations.leaf_der_b64)

        @st_set
        @given(st.lists(st.tuples(st.integers(0, len(leaf_der) - 1), st.integers(0, 255)), min_size=1, max_size=4))
        def f_ka_certificate_bytes(changes: list[tuple[int, int]]) -> None:
            der = bytearray(leaf_der)
            for at, value in changes:
                der[at] = value
            holder = EcKey.generate()
            now = int(time.time())
            attestation = signed(
                {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [base64.b64encode(bytes(der)).decode()]},
                json.dumps(
                    {
                        "iat": now,
                        "exp": now + 3600,
                        "attested_keys": [holder.public_jwk()],
                        "key_storage": ["iso_18045_high"],
                        "user_authentication": ["iso_18045_high"],
                        "key_storage_status": {"status": {}, "exp": now + 30 * 86_400},
                    }
                ),
                attestations.leaf_key,
            )
            header = {
                "typ": "openid4vci-proof+jwt",
                "alg": "ES256",
                "jwk": holder.public_jwk(),
                "key_attestation": attestation,
            }
            proof = signed(header, json.dumps({"aud": server.issuer_url, "iat": now, "nonce": "n"}), holder)
            body = {"credential_configuration_id": common.PID_CONFIG, "proofs": {"jwt": [proof]}}
            dpop = wallet.dpop("POST", "/credential", access_token=token)
            hit(
                "/credential key attestation with changed certificate bytes",
                "POST",
                "/credential",
                content=json.dumps(body).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"DPoP {token}", "DPoP": dpop},
            )

        f_ka_certificate_bytes()

    # The authorization code flow (M3).
    coder = common.new_code_wallet(server)
    challenge = common.pkce_challenge("v" * 43)
    form_fields = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "scope"]
    form_fields += ["state", "authorization_details", "issuer_state", "dpop_jkt", "request", "request_uri"]

    def par_form(**changed: str) -> bytes:
        form = {
            "response_type": "code",
            "client_id": common.CLIENT_ID,
            "redirect_uri": common.REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": common.PID_SCOPE,
            **changed,
        }
        return "&".join(f"{quote(k)}={quote(v, safe='', errors='surrogatepass')}" for k, v in form.items()).encode(
            "utf-8", "surrogatepass"
        )

    def par(label: str, content: bytes, headers: list[tuple[str, str]]) -> None:
        sent = [("Content-Type", "application/x-www-form-urlencoded"), ("DPoP", coder.dpop("POST", "/par")), *headers]
        hit(label, "POST", "/par", content=content, headers=sent)

    accepted = coder.http.post(
        "/par",
        content=par_form(state="sane"),
        headers=[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("DPoP", coder.dpop("POST", "/par")),
            *coder.attested(),
        ],
    )
    suite.record("http: an unaltered PAR is accepted, so the fuzz below reaches past it", accepted.status_code == 201)

    @st_set
    @given(st.sampled_from(form_fields), texts(80))
    def f_par_form(name: str, value: str) -> None:
        par("/par form fields", par_form(**{name: value}), coder.attested())

    f_par_form()

    @st_set
    @given(st.binary(max_size=300))
    def f_par_body(body: bytes) -> None:
        par("/par body", body, coder.attested())

    f_par_body()

    wia_signer = coder.attestation()  # a correctly signed one, to take its header and key from
    from cryptography.hazmat.primitives import serialization

    wia_key = EcKey(serialization.load_pem_private_key((server.pki / "m3" / "wia-signer.key").read_bytes(), None))  # type: ignore[arg-type]
    wia_header = json.loads(base64.urlsafe_b64decode(wia_signer.split(".")[0] + "=="))
    wia_claims = json.loads(base64.urlsafe_b64decode(wia_signer.split(".")[1] + "=="))

    @st_set
    @given(st.sampled_from(sorted(wia_claims)), claim_text)
    def f_wia_claims(name: str, text: str) -> None:
        attestation = signed(wia_header, with_claim(wia_claims, name, text), wia_key)
        par("/par signed wallet attestation claims", par_form(), coder.attested(attestation=attestation))

    f_wia_claims()

    @st_set
    @given(st.sampled_from(["iss", "aud", "jti", "iat", "exp", "nbf", "nonce"]), claim_text)
    def f_pop_claims(name: str, text: str) -> None:
        claims = {"iss": common.CLIENT_ID, "aud": server.issuer_url, "jti": uuid.uuid4().hex, "iat": int(time.time())}
        pop = signed(
            {"typ": "oauth-client-attestation-pop+jwt", "alg": "ES256"},
            with_claim(claims, name, text),
            coder.instance_key,
        )
        par("/par signed attestation proof of possession claims", par_form(), coder.attested(pop=pop))

    f_pop_claims()

    wia_der = base64.b64decode(wia_header["x5c"][0])

    @st_set
    @given(st.lists(st.tuples(st.integers(0, len(wia_der) - 1), st.integers(0, 255)), min_size=1, max_size=4))
    def f_wia_certificate_bytes(changes: list[tuple[int, int]]) -> None:
        der = bytearray(wia_der)
        for at, value in changes:
            der[at] = value
        header = {**wia_header, "x5c": [base64.b64encode(bytes(der)).decode(), *wia_header["x5c"][1:]]}
        attestation = signed(header, json.dumps(wia_claims), wia_key)
        par(
            "/par wallet attestation with changed certificate bytes",
            par_form(),
            coder.attested(attestation=attestation),
        )

    f_wia_certificate_bytes()

    @st_set
    @given(
        st.dictionaries(st.sampled_from(["client_id", "request_uri", "response_type", "scope"]), texts(80), max_size=4)
    )
    def f_authorize(query: dict[str, str]) -> None:
        text = "&".join(f"{quote(k)}={quote(v, safe='', errors='surrogatepass')}" for k, v in query.items())
        hit("/authorize query", "GET", f"/authorize?{text}", follow_redirects=False)

    f_authorize()

    @st_set
    @given(st.sampled_from(["code", "code_verifier", "redirect_uri", "client_id", "grant_type"]), texts(80))
    def f_code_grant(name: str, value: str) -> None:
        form = {
            "grant_type": "authorization_code",
            "code": "c" * 43,
            "code_verifier": "v" * 43,
            "redirect_uri": common.REDIRECT_URI,
            "client_id": common.CLIENT_ID,
            name: value,
        }
        body = "&".join(f"{quote(k)}={quote(v, safe='', errors='surrogatepass')}" for k, v in form.items()).encode(
            "utf-8", "surrogatepass"
        )
        headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("DPoP", coder.dpop("POST", "/token")),
            *coder.attested(),
        ]
        hit("/token code grant fields", "POST", "/token", content=body, headers=headers)

    f_code_grant()

    # M4 ----------------------------------------------------------------------------------------------------
    holder = common.new_code_wallet(server)
    holder.get_token()

    def bearer(path: str) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"DPoP {holder.token}",
            "DPoP": holder.dpop("POST", path, access_token=holder.token),
        }

    @st_set
    @given(st.one_of(st.binary(max_size=200), json_vals.map(lambda v: json.dumps({"transaction_id": v}).encode())))
    def f_deferred(body: bytes) -> None:
        hit(
            "/deferred_credential", "POST", "/deferred_credential", content=body, headers=bearer("/deferred_credential")
        )

    f_deferred()

    @st_set
    @given(
        st.one_of(
            st.binary(max_size=200),
            st.fixed_dictionaries(
                {"notification_id": json_vals, "event": json_vals, "event_description": texts(60)}
            ).map(lambda v: json.dumps(v).encode()),
        )
    )
    def f_notification(body: bytes) -> None:
        hit("/notification", "POST", "/notification", content=body, headers=bearer("/notification"))

    f_notification()

    @st_set
    @given(
        st.one_of(
            texts(200),
            st.tuples(json_vals, texts(20), texts(20), texts(40), texts(30)).map(
                lambda t: ".".join([jose.b64u(json.dumps(t[0]).encode()), *t[1:]])
            ),
        )
    )
    def f_jwe(token: str) -> None:
        headers = {**bearer("/credential"), "Content-Type": "application/jwt"}
        hit(
            "/credential application/jwt",
            "POST",
            "/credential",
            content=token.encode("utf-8", "surrogatepass"),
            headers=headers,
        )

    f_jwe()

    for label, fails in sorted(bad.items()):
        suite.record(f"http:{label}: no 5xx / no hang", False, failures=len(fails), first=fails[0])
    # record the clean endpoints too
    hit_labels = {
        "/token",
        "/credential",
        "/status",
        "/admin/offers",
        "/token signed DPoP claims",
        "/credential signed key-proof claims",
        "/credential key attestation with changed certificate bytes",
        "/par form fields",
        "/par body",
        "/par signed wallet attestation claims",
        "/par signed attestation proof of possession claims",
        "/par wallet attestation with changed certificate bytes",
        "/authorize query",
        "/token code grant fields",
        "/deferred_credential",
        "/notification",
        "/credential application/jwt",
    }
    for label in sorted(hit_labels):
        if label not in bad:
            suite.record(f"http:{label}: no 5xx / no hang", True)
    suite.meta["http_failures"] = {k: v[:3] for k, v in bad.items()}


def run(out_dir: Path, quick: bool) -> dict:
    suite = common.Suite("suite3_fuzz")
    suite.meta["max_examples"] = MAX_EX
    fuzz_inprocess(suite)
    pki = common.gen_pki(common.WORK_DIR / "fuzzhttp")
    # A high limit, so fuzzed requests reach the parsers instead of stopping at 429.
    srv = common.Server(pki=pki, workers=1, rate_limit=common.HIGH_RATE_LIMIT).start()
    try:
        fuzz_http(srv, suite)
    finally:
        srv.stop()
    return suite.write(out_dir)


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else common.WORK_DIR / "out"
    raise SystemExit(0 if run(out, QUICK)["ok"] else 1)
