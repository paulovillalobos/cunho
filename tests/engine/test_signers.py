"""Signing keys in an HSM over PKCS#11 and in AWS KMS (M4 piece H).

The HSM is SoftHSM2, with the test PKI's own keys imported, so the certificate chains the other tests use fit. The
tests skip when SoftHSM2 is not installed; the CI job that runs them installs it. KMS is a fake client that signs the
digest it is sent, as the AWS documentation says KMS does with MessageType DIGEST, and checks every request against
botocore's own model of the KMS API, offline. (moto 5.2 hashes a DIGEST message a second time, so it cannot stand in.)
"""

from __future__ import annotations

import base64
import concurrent.futures
import ctypes
import datetime
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from cunho.errors import ConfigError
from cunho.jose import b64u_decode
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.signer import (
    LOGGED_IN,
    KmsSigner,
    Pkcs11Signer,
    SignerError,
    _Token,
    load_signer,
    parse_pkcs11_uri,
    read_pin,
)

from .helpers import Pki, Wallet, certificate, pem, production_kwargs

boto3 = pytest.importorskip("boto3")
pkcs11 = pytest.importorskip("pkcs11")
import botocore.session  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from botocore.validate import validate_parameters  # noqa: E402

MODULES = (
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
)
PIN = "1234"
KEYS = {
    "issuer": ("signing.key", "01"),
    "status": ("status.key", "02"),
    "mdoc": ("mdoc-signing.key", "03"),
    "access": ("access.key", "04"),
}


def verifies(public: Any, alg_hash: hashes.HashAlgorithm, data: bytes, raw: bytes) -> bool:
    size = len(raw) // 2
    signature = encode_dss_signature(int.from_bytes(raw[:size], "big"), int.from_bytes(raw[size:], "big"))
    try:
        public.verify(signature, data, ec.ECDSA(alg_hash))
    except Exception:
        return False
    return True


def leaf_key(chain: Path) -> Any:
    return x509.load_pem_x509_certificates(chain.read_bytes())[0].public_key()


# ---------------------------------------------------------------- SoftHSM2


@pytest.fixture(scope="session")
def hsm(pki: Pki, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Path]]:
    """A SoftHSM2 token, cunho, holding the issuer, status, mdoc and access keys of the test PKI by label and id;
    spare, with the issuer key, where one test holds the process's only session; and locked, which only the
    wrong-PIN test opens: a PKCS#11 login belongs to the process, so once a signer logged in to a token, a later
    session there is logged in whatever PIN it brings."""
    module = os.environ.get("CUNHO_TEST_PKCS11_MODULE") or next((m for m in MODULES if Path(m).exists()), None)
    util = shutil.which("softhsm2-util")
    if module is None or util is None:
        pytest.skip("SoftHSM2 is not installed")
    root = tmp_path_factory.mktemp("softhsm")
    (root / "tokens").mkdir()
    conf = root / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {root / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    before = os.environ.get("SOFTHSM2_CONF")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    run = runner(util)
    run("--init-token", "--free", "--label", "cunho", "--so-pin", "0000", "--pin", PIN)
    for label, (name, key_id) in KEYS.items():
        run("--import", str(pki.root / name), "--token", "cunho", "--label", label, "--id", key_id, "--pin", PIN)
    for token in ("spare", "locked"):
        run("--init-token", "--free", "--label", token, "--so-pin", "0000", "--pin", PIN)
        run(
            "--import", str(pki.root / "signing.key"), "--token", token, "--label", "issuer", "--id", "01", "--pin", PIN
        )
    pin_file = root / "pin"
    pin_file.write_text(PIN + "\n")
    pin_file.chmod(0o600)
    yield {"module": Path(module), "pin": pin_file}
    if before is None:
        os.environ.pop("SOFTHSM2_CONF", None)
    else:
        os.environ["SOFTHSM2_CONF"] = before


def runner(util: str) -> Callable[..., None]:
    def run(*args: str) -> None:
        subprocess.run([util, *args], check=True, capture_output=True)

    return run


def hsm_signer(hsm: dict[str, Path], pki: Pki, uri: str, chain: str = "signing.pem") -> Any:
    return load_signer(
        Path(uri),
        pki.root / chain,
        None,
        production=True,
        pkcs11_module=hsm["module"],
        pkcs11_pin_file=hsm["pin"],
    )


def test_an_hsm_key_signs_what_its_certificate_verifies(hsm: dict[str, Path], pki: Pki) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer;type=private")
    assert isinstance(signer, Pkcs11Signer) and signer.alg == "ES256"
    data = b"a JWS signing input" * 500
    raw = signer.sign(data)
    assert len(raw) == 64 and verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), data, raw)
    chain = x509.load_pem_x509_certificates((pki.root / "signing.pem").read_bytes())
    assert signer.certificate_der() == chain[0].public_bytes(serialization.Encoding.DER)
    assert signer.x5c() == [base64.b64encode(chain[0].public_bytes(serialization.Encoding.DER)).decode()]


def test_an_hsm_key_is_found_by_id_too(hsm: dict[str, Path], pki: Pki) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;id=%01")
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), b"x", signer.sign(b"x"))
    by_both = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=status;id=%02", chain="status.pem")
    assert verifies(leaf_key(pki.root / "status.pem"), hashes.SHA256(), b"y", by_both.sign(b"y"))


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        ("pkcs11:token=cunho;object=status", "cannot be used: the signer's signature does not verify"),
        ("pkcs11:token=cunho;object=nobody", "holds 0 EC private keys"),
        ("pkcs11:token=cunho;object=issuer;id=%02", "holds 0 EC private keys"),
        ("pkcs11:token=elsewhere;object=issuer", "cannot open PKCS#11 token 'elsewhere'"),
    ],
)
def test_an_hsm_key_that_is_not_the_certificates_stops_the_start(
    hsm: dict[str, Path], pki: Pki, uri: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        hsm_signer(hsm, pki, uri)


def test_an_hsm_signer_opens_its_session_again_once(hsm: dict[str, Path], pki: Pki) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    signer._session.close()  # noqa: SLF001 - the token dropped the session (a restart, a failover)
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), b"z", signer.sign(b"z"))


class _FailsOnce:
    """A key handle whose first signature fails while its session stays open, as a transient token error can."""

    def __init__(self) -> None:
        self.calls = 0

    def sign(self, data: bytes, mechanism: Any) -> bytes:
        self.calls += 1
        raise pkcs11.exceptions.FunctionFailed()


def test_a_session_left_open_by_a_failed_signature_is_given_back(hsm: dict[str, Path], pki: Pki) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    first = signer._session  # noqa: SLF001
    signer._key = _FailsOnce()  # noqa: SLF001
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), b"z", signer.sign(b"z"))
    assert signer._session is not first  # noqa: SLF001
    with pytest.raises(pkcs11.exceptions.SessionHandleInvalid):
        first.close()  # it was closed already


def test_signers_on_one_token_never_log_in_again(
    hsm: dict[str, Path], pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A login belongs to the process: asking again would fail and leave a session behind (the second reviewer)."""
    first = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    asked: list[dict[str, Any]] = []

    class Recording:
        def __init__(self, token: Any) -> None:
            self.token = token

        def open(self, **kwargs: Any) -> Any:
            asked.append(kwargs)
            return self.token.open(**kwargs)

    monkeypatch.setattr(first._token, "token", Recording(first._token.token))  # noqa: SLF001
    others = [
        hsm_signer(hsm, pki, "pkcs11:token=cunho;object=status", chain="status.pem"),
        hsm_signer(hsm, pki, "pkcs11:token=cunho;object=mdoc", chain="mdoc-signing.pem"),
    ]
    assert len(asked) == 2 and all("user_pin" not in kwargs for kwargs in asked)
    assert all(o._token is first._token for o in others)  # noqa: SLF001


def test_one_signer_recovering_leaves_the_others_signing(hsm: dict[str, Path], pki: Pki) -> None:
    """Replacing one signer's session logs nobody out: the others keep their sessions and keys (the second reviewer)."""
    failing = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    other = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=status", chain="status.pem")
    session = other._session  # noqa: SLF001
    failing._key = _FailsOnce()  # noqa: SLF001
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), b"a", failing.sign(b"a"))
    assert other._session is session  # noqa: SLF001
    assert verifies(leaf_key(pki.root / "status.pem"), hashes.SHA256(), b"b", other.sign(b"b"))


def logout(signer: Any) -> None:
    """C_Logout on the login session, which leaves every session open: the process's sessions turn public."""
    token = signer._token  # noqa: SLF001
    call = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_ulong)(token.module.functions.C_Logout)
    assert call(token.login.handle) == 0


def test_a_logout_that_keeps_the_sessions_is_logged_in_again(hsm: dict[str, Path], pki: Pki) -> None:
    """The second reviewer's reproduction: the session still answers, but it is public, and the key is out of view
    until the process logs in again."""
    signer = hsm_signer(hsm, pki, "pkcs11:token=spare;object=issuer")
    token = signer._token  # noqa: SLF001
    login = token.login
    logout(signer)
    assert token.module.state(login.handle) not in LOGGED_IN
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), b"w", signer.sign(b"w"))
    assert token.login is login and token.module.state(login.handle) in LOGGED_IN


def test_a_login_session_that_is_gone_is_opened_again(hsm: dict[str, Path], pki: Pki) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=spare;object=issuer")
    token = signer._token  # noqa: SLF001
    gone = token.login
    gone.close()
    signer._key = _FailsOnce()  # noqa: SLF001
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), b"v", signer.sign(b"v"))
    assert token.login is not gone and token.module.state(token.login.handle) in LOGGED_IN


def test_a_wrong_pin_leaves_one_public_login_session(hsm: dict[str, Path], pki: Pki, tmp_path: Path) -> None:
    wrong = tmp_path / "pin"
    wrong.write_text("9999")
    wrong.chmod(0o600)
    for _ in range(3):
        with pytest.raises(ConfigError, match=r"cannot log in to PKCS#11 token 'locked': .*CKR 0xa0"):
            load_signer(
                Path("pkcs11:token=locked;object=issuer"),
                pki.root / "signing.pem",
                None,
                production=True,
                pkcs11_module=hsm["module"],
                pkcs11_pin_file=wrong,
            )
    token = _Token._all[(str(hsm["module"]), "locked")]  # noqa: SLF001
    assert token.module.state(token.login.handle) not in LOGGED_IN, "one login session, reused, still public"


def test_an_hsm_that_stays_away_fails_the_signature(
    hsm: dict[str, Path], pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    signer._session.close()  # noqa: SLF001

    def gone() -> None:
        raise pkcs11.exceptions.DeviceRemoved()

    monkeypatch.setattr(signer, "_open", gone)
    with pytest.raises(SignerError, match="the HSM could not sign"):
        signer.sign(b"z")


class _Answers:
    """A key handle that answers what it is told to, as a faulty token might."""

    def __init__(self, signature: bytes) -> None:
        self.signature = signature

    def sign(self, data: bytes, mechanism: Any) -> bytes:
        return self.signature


@pytest.mark.parametrize(
    ("signature", "message"),
    [(b"\x01" * 63, "63 bytes, not 64"), (b"\x01" * 64, "does not verify with its certificate's key")],
)
def test_a_signature_the_hsm_got_wrong_is_never_used(
    hsm: dict[str, Path], pki: Pki, signature: bytes, message: str
) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    signer._key = _Answers(signature)  # noqa: SLF001
    with pytest.raises(SignerError, match=message):
        signer.sign(b"data")


def test_one_session_serves_many_threads(hsm: dict[str, Path], pki: Pki) -> None:
    signer = hsm_signer(hsm, pki, "pkcs11:token=cunho;object=issuer")
    public = leaf_key(pki.root / "signing.pem")
    messages = [f"message {i}".encode() for i in range(64)]
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        signatures = list(pool.map(signer.sign, messages))
    assert all(verifies(public, hashes.SHA256(), m, s) for m, s in zip(messages, signatures, strict=True))


@pytest.mark.parametrize(
    ("uri", "message"),
    [
        ("pkcs11-token=cunho", "named by a pkcs11: URI"),
        ("pkcs11:token=cunho;object=issuer?pin-value=1234", "takes no query"),
        ("pkcs11:token=cunho;object=issuer;slot-id=1", "takes only id, object, token, type"),
        ("pkcs11:token=cunho;issuer", "takes only id, object, token, type"),
        ("pkcs11:token=cunho;object=issuer;type", "as name=value"),
        ("pkcs11:token=cunho;object=a;object=b", "names object twice"),
        ("pkcs11:object=issuer", "must name the token"),
        ("pkcs11:token=cunho", "must name the token, and the key"),
        ("pkcs11:token=cunho;object=issuer;type=public", "type=private"),
    ],
)
def test_a_pkcs11_uri_names_one_private_key(uri: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_pkcs11_uri(uri)


def test_a_pkcs11_uri_is_percent_decoded() -> None:
    assert parse_pkcs11_uri("pkcs11:token=my%20token;object=key%3B1;id=%01%ff;type=private;") == {
        "token": b"my token",
        "object": b"key;1",
        "id": b"\x01\xff",
        "type": b"private",
    }


def test_the_pin_comes_from_a_private_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="needs pkcs11_pin_file"):
        read_pin(None)
    with pytest.raises(ConfigError, match="does not exist"):
        read_pin(tmp_path / "missing")
    pin = tmp_path / "pin"
    pin.write_text("1234\n")
    pin.chmod(0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        read_pin(pin)
    pin.chmod(0o600)
    assert read_pin(pin) == "1234"
    pin.write_text("12 34\n\n")
    assert read_pin(pin) == "12 34\n", "only one trailing newline is dropped"
    pin.write_text("\n")
    with pytest.raises(ConfigError, match="is empty"):
        read_pin(pin)


def test_a_pkcs11_key_needs_its_module(pki: Pki, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="needs pkcs11_module"):
        load_signer(Path("pkcs11:token=cunho;object=issuer"), pki.root / "signing.pem", None, production=False)


def test_an_empty_chain_stops_the_start(hsm: dict[str, Path]) -> None:
    with pytest.raises(ConfigError, match="chain is empty"):
        Pkcs11Signer(hsm["module"], "cunho", PIN, [], label="issuer")


def test_production_starts_with_every_key_in_the_hsm(
    hsm: dict[str, Path], pki: Pki, tmp_path: Path, wallet_for: Callable[[Issuer], Wallet]
) -> None:
    """A PID provider in production with its credential, status and mdoc keys in the HSM, and the access
    certificate's too: no file key anywhere, and a credential issued through it verifies."""
    keys = {
        "signing_key": Path("pkcs11:token=cunho;object=issuer"),
        "status_signing_key": Path("pkcs11:token=cunho;object=status"),
        "mdoc_signing_key": Path("pkcs11:token=cunho;object=mdoc"),
        "access_signing_key": Path("pkcs11:token=cunho;object=access"),
        "access_signing_chain": pki.root / "access.pem",
        "access_trust_anchors": pki.root / "issuer-root.pem",
        "pkcs11_module": hsm["module"],
        "pkcs11_pin_file": hsm["pin"],
    }
    (tmp_path / "m.key").write_bytes(b"k" * 32)
    (tmp_path / "m.key").chmod(0o600)
    for file_key in ("status_signing_key", "mdoc_signing_key", "access_signing_key"):
        settings = Settings(**production_kwargs(pki, tmp_path, **{**keys, file_key: pki.root / "status.key"}))
        with pytest.raises(ConfigError, match=f"{file_key} must be a pkcs11: or aws-kms: key"):
            Issuer(settings)
    issuer = Issuer(Settings(**production_kwargs(pki, tmp_path, **keys)))
    signers = issuer.signers
    assert all(isinstance(s, Pkcs11Signer) for s in (signers.credentials, signers.status, signers.mdoc, signers.access))


def test_a_credential_signed_in_the_hsm_verifies(
    hsm: dict[str, Path], pki: Pki, make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet]
) -> None:
    issuer = make_issuer(
        signing_key=Path("pkcs11:token=cunho;object=issuer"),
        pkcs11_module=hsm["module"],
        pkcs11_pin_file=hsm["pin"],
    )
    wallet = wallet_for(issuer)
    response = wallet.issue()
    assert response.status_code == 200, response.text
    token = response.json()["credentials"][0]["credential"].split("~")[0]
    header, payload, signature = token.split(".")
    assert json.loads(b64u_decode(header))["alg"] == "ES256"
    raw = b64u_decode(signature)
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), f"{header}.{payload}".encode(), raw)


# ---------------------------------------------------------------- AWS KMS

ARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
SPEC_OF = {"secp256r1": "ECC_NIST_P256", "secp384r1": "ECC_NIST_P384", "secp521r1": "ECC_NIST_P521"}
HASH_OF = {"ECDSA_SHA_256": hashes.SHA256(), "ECDSA_SHA_384": hashes.SHA384(), "ECDSA_SHA_512": hashes.SHA512()}


class FakeKms:
    """GetPublicKey and Sign as the KMS API reference describes them; each request is checked against botocore's
    model of the API. `answer` replaces what Sign returns, `fail` makes an operation raise ClientError."""

    def __init__(self, key: Any, *, usage: str = "SIGN_VERIFY", spec: str | None = None, public: bytes | None = None):
        self.key = key
        self.model = botocore.session.get_session().get_service_model("kms")
        self.usage = usage
        self.spec = spec or SPEC_OF.get(getattr(getattr(key, "curve", None), "name", ""), "RSA_2048")
        self.public = public or key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.signed: list[dict[str, Any]] = []
        self.answer: Callable[[dict[str, Any]], dict[str, Any]] | None = None
        self.fail: set[str] = set()

    def _check(self, operation: str, params: dict[str, Any]) -> None:
        validate_parameters(params, self.model.operation_model(operation).input_shape)
        if operation in self.fail:
            raise ClientError({"Error": {"Code": "KMSInternalException", "Message": "down"}}, operation)

    def get_public_key(self, **params: Any) -> dict[str, Any]:
        self._check("GetPublicKey", params)
        return {"KeyId": ARN, "PublicKey": self.public, "KeyUsage": self.usage, "KeySpec": self.spec}

    def sign(self, **params: Any) -> dict[str, Any]:
        self._check("Sign", params)
        self.signed.append(params)
        if self.answer is not None:
            return self.answer(params)
        assert params["MessageType"] == "DIGEST"
        algorithm = HASH_OF[params["SigningAlgorithm"]]
        signature = self.key.sign(params["Message"], ec.ECDSA(Prehashed(algorithm)))
        return {"KeyId": ARN, "Signature": signature, "SigningAlgorithm": params["SigningAlgorithm"]}


def chain_for(key: Any, pki_root: Path, name: str) -> list[x509.Certificate]:
    cert = certificate("KMS Signer", key)
    (pki_root / name).write_bytes(pem(cert))
    return [cert]


@pytest.mark.parametrize(
    ("curve", "alg", "algorithm", "size"),
    [
        (ec.SECP256R1(), "ES256", "ECDSA_SHA_256", 32),
        (ec.SECP384R1(), "ES384", "ECDSA_SHA_384", 48),
        (ec.SECP521R1(), "ES512", "ECDSA_SHA_512", 66),
    ],
)
def test_a_kms_key_signs_the_digest_and_is_pinned_to_its_arn(
    tmp_path: Path, curve: ec.EllipticCurve, alg: str, algorithm: str, size: int
) -> None:
    key = ec.generate_private_key(curve)
    kms = FakeKms(key)
    signer = KmsSigner("alias/cunho-issuer", chain_for(key, tmp_path, "c.pem"), client=kms)
    assert signer.alg == alg
    data = b"x" * 10_000  # more than KMS takes as a message
    raw = signer.sign(data)
    assert len(raw) == 2 * size and verifies(key.public_key(), HASH_OF[algorithm], data, raw)
    request = kms.signed[-1]
    digest = hashes.Hash(HASH_OF[algorithm])
    digest.update(data)
    assert request == {
        "KeyId": ARN,
        "Message": digest.finalize(),
        "MessageType": "DIGEST",
        "SigningAlgorithm": algorithm,
    }
    assert len(kms.signed) == 2, "one signature at the start, one asked for"


def test_kms_answers_with_customer_master_key_spec_too(tmp_path: Path) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    kms = FakeKms(key)
    original = kms.get_public_key

    def older(**params: Any) -> dict[str, Any]:
        answer = original(**params)
        answer["CustomerMasterKeySpec"] = answer.pop("KeySpec")
        return answer

    kms.get_public_key = older  # type: ignore[method-assign]
    assert KmsSigner(ARN, chain_for(key, tmp_path, "c.pem"), client=kms).alg == "ES256"


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda key: FakeKms(key, usage="ENCRYPT_DECRYPT"), "is not a signing key"),
        (lambda key: FakeKms(key, spec="ECC_SECG_P256K1"), "must be one of ECC_NIST_P256"),
        (lambda key: FakeKms(rsa.generate_private_key(65537, 2048)), "must be one of ECC_NIST_P256"),
        (
            lambda key: FakeKms(
                key,
                public=rsa.generate_private_key(65537, 2048)
                .public_key()
                .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            ),
            "has no EC public key",
        ),
        (lambda key: FakeKms(ec.generate_private_key(ec.SECP256R1())), "does not match the leaf certificate"),
    ],
)
def test_a_kms_key_cunho_cannot_use_stops_the_start(
    tmp_path: Path, make: Callable[[Any], FakeKms], message: str
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ConfigError, match=message):
        KmsSigner(ARN, chain_for(key, tmp_path, "c.pem"), client=make(key))


@pytest.mark.parametrize(
    ("operation", "message"), [("GetPublicKey", "cannot read KMS key"), ("Sign", "KMS could not sign")]
)
def test_kms_out_of_reach_at_the_start_stops_it(tmp_path: Path, operation: str, message: str) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    kms = FakeKms(key)
    kms.fail.add(operation)
    with pytest.raises(ConfigError, match=message):
        KmsSigner(ARN, chain_for(key, tmp_path, "c.pem"), client=kms)


def _der(r: int, s: int) -> bytes:
    return encode_dss_signature(r, s)


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (lambda p: (_ for _ in ()).throw(ClientError({"Error": {"Code": "Throttling"}}, "Sign")), "KMS could not sign"),
        (lambda p: {"KeyId": ARN}, "without a DER ECDSA signature"),
        (lambda p: {"Signature": b"not der"}, "without a DER ECDSA signature"),
        (lambda p: {"Signature": _der(1 << 256, 1)}, "too long for its curve"),
        (lambda p: {"Signature": _der(1, 1 << 256)}, "too long for its curve"),
        (lambda p: {"Signature": _der(5, 7)}, "does not verify with its certificate's key"),
    ],
)
def test_a_kms_signature_that_is_not_right_is_never_used(
    tmp_path: Path, answer: Callable[[dict[str, Any]], dict[str, Any]], message: str
) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    kms = FakeKms(key)
    signer = KmsSigner(ARN, chain_for(key, tmp_path, "c.pem"), client=kms)
    kms.answer = answer
    with pytest.raises(SignerError, match=message):
        signer.sign(b"data")


def test_the_kms_client_takes_the_region_from_an_arn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    chain_for(key, tmp_path, "c.pem")
    regions: list[Any] = []

    def client(service: str, region_name: Any = None) -> FakeKms:
        assert service == "kms"
        regions.append(region_name)
        return FakeKms(key)

    monkeypatch.setattr(boto3, "client", client)
    for reference in (f"aws-kms:{ARN}", "aws-kms:alias/cunho-issuer", "aws-kms:1234abcd-12ab-34cd-56ef-1234567890ab"):
        signer = load_signer(Path(reference), tmp_path / "c.pem", None, production=True)
        assert isinstance(signer, KmsSigner)
    assert regions == ["eu-west-1", None, None]
    with pytest.raises(ConfigError, match="followed by a key id"):
        load_signer(Path("aws-kms:"), tmp_path / "c.pem", None, production=True)


def test_a_credential_signed_in_kms_verifies(
    pki: Pki,
    tmp_path: Path,
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Wallet],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = serialization.load_pem_private_key((pki.root / "signing.key").read_bytes(), None)
    monkeypatch.setattr(boto3, "client", lambda service, region_name=None: FakeKms(key))
    wallet = wallet_for(make_issuer(signing_key=Path(f"aws-kms:{ARN}")))
    response = wallet.issue()
    assert response.status_code == 200, response.text
    header, payload, signature = response.json()["credentials"][0]["credential"].split("~")[0].split(".")
    data = f"{header}.{payload}".encode()
    assert verifies(leaf_key(pki.root / "signing.pem"), hashes.SHA256(), data, b64u_decode(signature))


def test_a_library_that_is_not_pkcs11_stops_the_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import cunho.signer as signer_module

    with pytest.raises(ConfigError, match="is not a PKCS#11 library"):
        signer_module._Module(tmp_path / "missing.so")  # noqa: SLF001

    class Library:
        """A loaded library whose C_GetFunctionList answers `rv` and fills in `pointer`."""

        def __init__(self, rv: int, fill: bool) -> None:
            self.rv, self.fill = rv, fill
            self.table = signer_module._FunctionList()  # noqa: SLF001

        def C_GetFunctionList(self, out: Any) -> int:  # noqa: N802 - the PKCS#11 name
            if self.fill:
                ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(self.table)
            return self.rv

    for rv, fill, message in ((0x5, True, "CKR 0x5"), (0x0, False, "CKR 0x0")):
        monkeypatch.setattr(signer_module.ctypes, "CDLL", lambda path, rv=rv, fill=fill: Library(rv, fill))
        with pytest.raises(ConfigError, match=f"gave no PKCS#11 function list .{message}"):
            signer_module._Module(tmp_path / "x.so")  # noqa: SLF001
    monkeypatch.setattr(signer_module.ctypes, "CDLL", lambda path: object())
    with pytest.raises(ConfigError, match="is not a PKCS#11 library"):
        signer_module._Module(tmp_path / "x.so")  # noqa: SLF001


@pytest.mark.parametrize(
    ("module", "make", "message"),
    [
        ("pkcs11", lambda: Pkcs11Signer(Path("m.so"), "cunho", PIN, []), "needs the pkcs11 extra"),
        ("boto3", lambda: KmsSigner(ARN, []), "needs the kms extra"),
    ],
)
def test_a_missing_extra_is_named(
    monkeypatch: pytest.MonkeyPatch, module: str, make: Callable[[], Any], message: str
) -> None:
    monkeypatch.setitem(sys.modules, module, None)  # import fails as if not installed
    with pytest.raises(ConfigError, match=message):
        make()


def test_an_hsm_key_with_a_certificate_that_is_not_ec_stops_the_start(hsm: dict[str, Path]) -> None:
    """The file and KMS signers refuse such a key before; the HSM signer takes its key from the certificate."""
    key = rsa.generate_private_key(65537, 3072)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "RSA Signer")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    with pytest.raises(ConfigError, match="signing key must be P-256, P-384 or P-521"):
        Pkcs11Signer(hsm["module"], "cunho", PIN, [cert], label="issuer")
