"""Signing keys behind one interface. Private keys never leave a Signer.

Three kinds: a PEM file (development only), a key in an HSM over PKCS#11, and a key in AWS KMS. A setting that names a
signing key takes a file path, a `pkcs11:` URI (RFC 7512) or `aws-kms:` followed by a key id, ARN or alias. The HSM and
KMS signers check every signature against their certificate's key before it is used, and sign once when they start,
so a key that is not the certificate's, or that cannot sign, stops the start rather than the first issuance.
"""

from __future__ import annotations

import base64
import ctypes
import os
import threading
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote_to_bytes

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from cunho.errors import ConfigError
from cunho.jose import CURVES, JSON, b64u, b64u_json, is_self_signed, jwk_from_public_key


class Signer(Protocol):
    alg: str

    def public_jwk(self) -> JSON: ...

    def x5c(self) -> list[str]:
        """Base64 DER certificates, leaf first, trust anchor excluded."""
        ...

    def certificate_der(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes:
        """JOSE signature bytes (raw r || s for ECDSA)."""
        ...


def sign_jws(signer: Signer, header: JSON, payload: JSON) -> str:
    signing_input = f"{b64u_json({**header, 'alg': signer.alg})}.{b64u_json(payload)}"
    return f"{signing_input}.{b64u(signer.sign(signing_input.encode('ascii')))}"


class SignerError(RuntimeError):
    """An HSM or KMS could not sign, or gave a signature that does not verify with the certificate's key."""


def _load_chain(chain_path: Path, anchors_path: Path | None) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    anchors = x509.load_pem_x509_certificates(anchors_path.read_bytes()) if anchors_path else []
    return x509.load_pem_x509_certificates(chain_path.read_bytes()), anchors


class _Chained:
    """What every signer with a certificate shares: its algorithm, from its curve, and the chain to send."""

    def __init__(
        self,
        public: Any,
        chain: list[x509.Certificate],
        anchors: list[x509.Certificate] | None,
    ) -> None:
        if not isinstance(public, ec.EllipticCurvePublicKey):
            raise ConfigError("signing key must be P-256, P-384 or P-521")
        alg = next((a for a, (_, curve, _, _) in CURVES.items() if curve.name == public.curve.name), None)
        if alg is None:
            raise ConfigError("signing key must be P-256, P-384 or P-521")
        if not chain:
            raise ConfigError("signing certificate chain is empty")
        if chain[0].public_key() != public:
            raise ConfigError("signing key does not match the leaf certificate")
        self.alg = alg
        self._public = public
        self._chain = x5c_chain(chain, anchors)

    def public_jwk(self) -> JSON:
        return jwk_from_public_key(self._public)

    def x5c(self) -> list[str]:
        return [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in self._chain]

    def certificate_der(self) -> bytes:
        return self._chain[0].public_bytes(serialization.Encoding.DER)

    def _digest(self, data: bytes) -> bytes:
        digest = hashes.Hash(CURVES[self.alg][2])
        digest.update(data)
        return digest.finalize()

    def _checked(self, data: bytes, signature: bytes) -> bytes:
        """`signature` (raw r || s), once it verifies over `data` with the certificate's key."""
        size = CURVES[self.alg][3]
        if len(signature) != 2 * size:
            raise SignerError(f"the signer answered a signature of {len(signature)} bytes, not {2 * size}")
        r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
        try:
            self._public.verify(encode_dss_signature(r, s), data, ec.ECDSA(CURVES[self.alg][2]))
        except InvalidSignature as exc:
            raise SignerError("the signer's signature does not verify with its certificate's key") from exc
        return signature

    def _start(self) -> None:
        """Sign once: a key that is not the certificate's, or a signer that cannot sign, stops the start."""
        try:
            self.sign(b"cunho start-up signature check")  # type: ignore[attr-defined]
        except SignerError as exc:
            raise ConfigError(f"the signing key cannot be used: {exc}") from exc


class FileSigner(_Chained):
    """Development signer: an EC private key and its certificate chain from PEM files."""

    def __init__(
        self,
        key: ec.EllipticCurvePrivateKey,
        chain: list[x509.Certificate],
        anchors: list[x509.Certificate] | None = None,
    ) -> None:
        super().__init__(key.public_key(), chain, anchors)
        self._key = key

    @classmethod
    def from_files(cls, key_path: Path, chain_path: Path, anchors_path: Path | None = None) -> FileSigner:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ConfigError(f"{key_path} is not an EC private key")
        anchors = x509.load_pem_x509_certificates(anchors_path.read_bytes()) if anchors_path else None
        return cls(key, x509.load_pem_x509_certificates(chain_path.read_bytes()), anchors)

    def sign(self, data: bytes) -> bytes:
        _, _, digest, size = CURVES[self.alg]
        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(digest)))
        return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def _same_entity(a: x509.Certificate, b: x509.Certificate) -> bool:
    """One CA, whichever certificate carries it: same subject and same key (a cross-signed copy included)."""
    return a.subject == b.subject and a.public_key() == b.public_key()


def x5c_chain(chain: list[x509.Certificate], anchors: list[x509.Certificate] | None) -> list[x509.Certificate]:
    """The certificates to send in x5c: leaf first, linked, and stopping before the trust anchor (HAIP 6.1.1).

    With `anchors` (the deployment's `signing_trust_anchors`), the chain is cut at the first certificate
    that is an anchor, however it is signed, so a cross-signed root or an intermediate registered as an
    anchor is never sent (review 2, L-12). Without them, only self-signed certificates are dropped.
    """
    for child, parent in zip(chain, chain[1:], strict=False):
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise ConfigError("the signing certificate chain is not in order, leaf first") from exc
    if anchors is None:
        return [c for c in chain if not is_self_signed(c)] or chain[:1]
    kept: list[x509.Certificate] = []
    for cert in chain:
        if any(_same_entity(cert, anchor) for anchor in anchors):
            break
        kept.append(cert)
    if not kept:
        raise ConfigError("the signing certificate is itself a trust anchor")
    for anchor in anchors:
        try:
            kept[-1].verify_directly_issued_by(anchor)
            return kept
        except (ValueError, TypeError, InvalidSignature):
            continue
    raise ConfigError("the signing certificate chain does not end at one of signing_trust_anchors")


PKCS11_ATTRIBUTES = frozenset({"token", "object", "id", "type"})


def parse_pkcs11_uri(uri: str) -> dict[str, bytes]:
    """The path attributes of a PKCS#11 URI (RFC 7512 §2.3) that name a private key: token, and object or id, with
    type private when given. Values are percent-decoded. No query: the PIN comes from a file, never from the URI."""
    if not uri.startswith("pkcs11:"):
        raise ConfigError("a PKCS#11 key is named by a pkcs11: URI")
    path = uri.removeprefix("pkcs11:")
    if "?" in path:
        raise ConfigError("the pkcs11: URI takes no query; the PIN comes from pkcs11_pin_file")
    attributes: dict[str, bytes] = {}
    for part in filter(None, path.split(";")):
        name, equals, value = part.partition("=")
        if not equals or name not in PKCS11_ATTRIBUTES:
            raise ConfigError(f"the pkcs11: URI takes only {', '.join(sorted(PKCS11_ATTRIBUTES))}, as name=value")
        if name in attributes:
            raise ConfigError(f"the pkcs11: URI names {name} twice")
        attributes[name] = unquote_to_bytes(value)
    if not attributes.get("token") or not (attributes.get("object") or attributes.get("id")):
        raise ConfigError("the pkcs11: URI must name the token, and the key by object (its label) or id")
    if attributes.get("type", b"private") != b"private":
        raise ConfigError("the pkcs11: URI must name a private key (type=private)")
    return attributes


def read_pin(path: Path | None) -> str:
    """The user PIN, from a file only its owner can read; one trailing newline is not part of it."""
    if path is None:
        raise ConfigError("a pkcs11: key needs pkcs11_pin_file")
    if not path.is_file():
        raise ConfigError(f"PIN file {path} does not exist")
    if os.stat(path).st_mode & 0o077:
        raise ConfigError(f"PIN file {path} must not be readable by group or others (chmod 600)")
    pin = path.read_text(encoding="utf-8").removesuffix("\n")
    if not pin:
        raise ConfigError(f"PIN file {path} is empty")
    return pin


# The CK_FUNCTION_LIST of PKCS#11 v2.40 §5.17 up to C_Logout, in its order: python-pkcs11 0.10 has no C_Login or
# C_GetSessionInfo on an open session, so cunho calls the module's own.
_FUNCTIONS = (
    "C_Initialize C_Finalize C_GetInfo C_GetFunctionList C_GetSlotList C_GetSlotInfo C_GetTokenInfo "
    "C_GetMechanismList C_GetMechanismInfo C_InitToken C_InitPIN C_SetPIN C_OpenSession C_CloseSession "
    "C_CloseAllSessions C_GetSessionInfo C_GetOperationState C_SetOperationState C_Login C_Logout"
).split()


class _Version(ctypes.Structure):
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class _FunctionList(ctypes.Structure):
    _fields_ = [("version", _Version)] + [(name, ctypes.c_void_p) for name in _FUNCTIONS]


class _SessionInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulong) for name in ("slot", "state", "flags", "device_error")]


CKR_OK = 0x0
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKU_USER = 1
LOGGED_IN = frozenset({1, 3})  # CKS_RO_USER_FUNCTIONS, CKS_RW_USER_FUNCTIONS (PKCS#11 v2.40 §5.6)


class _Module:
    """C_Login and C_GetSessionInfo from the module's function list. The library is the one python-pkcs11 loaded, so
    they act on the same sessions."""

    def __init__(self, module: Path) -> None:
        try:
            library = ctypes.CDLL(str(module))
            functions = ctypes.POINTER(_FunctionList)()
            rv = library.C_GetFunctionList(ctypes.byref(functions))
        except (OSError, AttributeError) as exc:
            raise ConfigError(f"{module} is not a PKCS#11 library: {exc}") from exc
        if rv != CKR_OK or not functions:
            raise ConfigError(f"{module} gave no PKCS#11 function list (CKR {rv:#x})")
        self.functions = functions.contents
        ulong = ctypes.c_ulong
        self._login = ctypes.CFUNCTYPE(ulong, ulong, ulong, ctypes.c_char_p, ulong)(self.functions.C_Login)
        self._info = ctypes.CFUNCTYPE(ulong, ulong, ctypes.POINTER(_SessionInfo))(self.functions.C_GetSessionInfo)

    def state(self, handle: int) -> int | None:
        """The session's state, or None when it is gone (or cannot be read, which cunho treats the same)."""
        info = _SessionInfo()
        return int(info.state) if self._info(handle, ctypes.byref(info)) == CKR_OK else None

    def log_in(self, handle: int, pin: str) -> int:
        data = pin.encode("utf-8")
        return int(self._login(handle, CKU_USER, data, len(data)))


class _Token:
    """One per PKCS#11 library and token in the process. A PKCS#11 login belongs to the process, not to a session
    (PKCS#11 v2.40 §5.6). Every session cunho opens is a public one, which python-pkcs11 closes without C_Logout, so
    closing one never logs the others out; the process logs in on one of them, kept for that, with C_Login, and
    finds out whether it still is from the session's state, not from whether the session answers (the second
    reviewer: a token may log the process out and keep its sessions)."""

    _all: dict[tuple[str, str], _Token] = {}
    _guard = threading.Lock()

    def __init__(self, token: Any, module: _Module, pin: str, errors: Any) -> None:
        self.token, self.module, self.pin, self.errors = token, module, pin, errors
        self.lock = threading.Lock()  # held to log in and to replace a session
        self.login: Any = None

    @classmethod
    def get(cls, pkcs11: Any, errors: Any, module: Path, label: str, pin: str) -> _Token:
        with cls._guard:
            known = cls._all.get((str(module), label))
            if known is not None:
                return known
            try:
                token = pkcs11.lib(str(module)).get_token(token_label=label)
            except (errors, RuntimeError, OSError) as exc:
                raise ConfigError(f"cannot open PKCS#11 token {label!r} through {module}: {exc!r}") from exc
            made = cls._all[(str(module), label)] = cls(token, _Module(module), pin, errors)
            return made

    def log_in(self) -> None:
        """Hold the lock. Make sure the process is logged in to the token: open the session it logs in on when there
        is none or it is gone, and log in when it is public. Raises ConfigError when the token refuses the PIN."""
        state = None if self.login is None else self.module.state(self.login.handle)
        if state is None:
            if self.login is not None:
                try:
                    self.login.close()  # public: only C_CloseSession, and a session already gone is fine
                except self.errors:
                    pass
            self.login = self.token.open()
            state = self.module.state(self.login.handle)
        if state in LOGGED_IN:
            return
        rv = self.module.log_in(self.login.handle, self.pin)
        if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
            raise ConfigError(f"the token refused the login (CKR {rv:#x})")


class Pkcs11Signer(_Chained):
    """A key in an HSM, used over PKCS#11 through python-pkcs11 (the `pkcs11` extra). The key never leaves the token:
    cunho hashes, the token signs with CKM_ECDSA. Each signer has a session of its own, used by one thread at a time;
    when the token drops it (a restart, a failover), the session is replaced once before the signature counts as
    failed, and the process logs in again only when its login is gone too."""

    def __init__(
        self,
        module: Path,
        token_label: str,
        pin: str,
        chain: list[x509.Certificate],
        anchors: list[x509.Certificate] | None = None,
        *,
        label: str | None = None,
        key_id: bytes | None = None,
    ) -> None:
        try:
            import pkcs11
            from pkcs11.exceptions import PKCS11Error
        except ImportError as exc:  # pragma: no cover - the extra is installed wherever this is tested
            raise ConfigError("a pkcs11: key needs the pkcs11 extra: pip install 'cunho[pkcs11]'") from exc
        if not chain:
            raise ConfigError("signing certificate chain is empty")
        # The token's key is checked against this one by the start-up signature, which must verify with it.
        super().__init__(chain[0].public_key(), chain, anchors)
        self._pkcs11, self._errors = pkcs11, PKCS11Error
        self._lock = threading.Lock()
        self._label, self._key_id = label, key_id
        self._token = _Token.get(pkcs11, PKCS11Error, module, token_label, pin)
        with self._token.lock:
            try:
                self._token.log_in()
            except (PKCS11Error, ConfigError) as exc:
                raise ConfigError(f"cannot log in to PKCS#11 token {token_label!r}: {exc}") from exc
            self._open()
        self._start()

    @classmethod
    def from_uri(
        cls, uri: str, module: Path | None, pin_file: Path | None, chain_path: Path, anchors_path: Path | None
    ) -> Pkcs11Signer:
        attributes = parse_pkcs11_uri(uri)
        if module is None:
            raise ConfigError("a pkcs11: key needs pkcs11_module, the path of the token's PKCS#11 library")
        chain, anchors = _load_chain(chain_path, anchors_path)
        label = attributes["object"].decode("utf-8") if "object" in attributes else None
        return cls(
            module,
            attributes["token"].decode("utf-8"),
            read_pin(pin_file),
            chain,
            anchors or None,
            label=label,
            key_id=attributes.get("id"),
        )

    def _open(self) -> None:
        """Hold the token's lock. Open a session that does not log in (closing it never logs the process out) and
        find exactly one EC private key with the label and id asked for: private keys show only while logged in."""
        pkcs11 = self._pkcs11
        self._session = self._token.token.open()
        wanted: dict[Any, Any] = {
            pkcs11.Attribute.CLASS: pkcs11.ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.KEY_TYPE: pkcs11.KeyType.EC,
        }
        if self._label is not None:
            wanted[pkcs11.Attribute.LABEL] = self._label
        if self._key_id is not None:
            wanted[pkcs11.Attribute.ID] = self._key_id
        found = list(self._session.get_objects(wanted))
        if len(found) != 1:
            self._close()
            raise ConfigError(f"the token holds {len(found)} EC private keys with that label and id, not one")
        self._key: Any = found[0]

    def _close(self) -> None:
        """Give the session back before opening another, so failures that leave it open do not use up the token's
        sessions (the second reviewer). It never logged in, so closing it logs nobody out."""
        try:
            self._session.close()
        except self._errors:
            pass  # the token dropped it already

    def sign(self, data: bytes) -> bytes:
        digest = self._digest(data)
        with self._lock:
            try:
                signature = self._key.sign(digest, mechanism=self._pkcs11.Mechanism.ECDSA)
            except self._errors:
                try:
                    with self._token.lock:
                        self._close()
                        self._token.log_in()
                        self._open()
                    signature = self._key.sign(digest, mechanism=self._pkcs11.Mechanism.ECDSA)
                except (self._errors, ConfigError) as exc:
                    raise SignerError(f"the HSM could not sign: {exc!r}") from exc
        return self._checked(data, bytes(signature))


# The key specs cunho signs with, their JOSE algorithm and KMS signing algorithm.
KMS_SPECS = {
    "ECC_NIST_P256": ("ES256", "ECDSA_SHA_256"),
    "ECC_NIST_P384": ("ES384", "ECDSA_SHA_384"),
    "ECC_NIST_P521": ("ES512", "ECDSA_SHA_512"),
}


class KmsSigner(_Chained):
    """A key in AWS KMS, used through boto3 (the `kms` extra) with the default credential chain. cunho sends the digest
    (MessageType DIGEST): a JWS signing input can pass the 4096 bytes KMS takes as a message. The key is pinned to the
    ARN KMS returns at the start, so an alias moved later changes nothing until a restart."""

    def __init__(
        self,
        key_id: str,
        chain: list[x509.Certificate],
        anchors: list[x509.Certificate] | None = None,
        client: Any = None,
    ) -> None:
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError as exc:  # pragma: no cover - the extra is installed wherever this is tested
            raise ConfigError("an aws-kms: key needs the kms extra: pip install 'cunho[kms]'") from exc
        self._errors = (BotoCoreError, ClientError)
        if client is None:
            region = key_id.split(":")[3] if key_id.startswith("arn:") and key_id.count(":") >= 5 else None
            client = boto3.client("kms", region_name=region)
        self._client = client
        try:
            described = client.get_public_key(KeyId=key_id)
        except self._errors as exc:
            raise ConfigError(f"cannot read KMS key {key_id}: {exc}") from exc
        if described.get("KeyUsage") != "SIGN_VERIFY":
            raise ConfigError(f"KMS key {key_id} is not a signing key (KeyUsage SIGN_VERIFY)")
        spec = described.get("KeySpec") or described.get("CustomerMasterKeySpec")
        if spec not in KMS_SPECS:
            raise ConfigError(f"KMS key {key_id} must be one of {', '.join(KMS_SPECS)}, not {spec}")
        public = serialization.load_der_public_key(described["PublicKey"])
        if not isinstance(public, ec.EllipticCurvePublicKey):
            raise ConfigError(f"KMS key {key_id} has no EC public key")
        super().__init__(public, chain, anchors)
        self._key_id, self._algorithm = str(described["KeyId"]), KMS_SPECS[spec][1]
        self._start()

    @classmethod
    def from_files(cls, key_id: str, chain_path: Path, anchors_path: Path | None) -> KmsSigner:
        if not key_id:
            raise ConfigError("aws-kms: must be followed by a key id, ARN or alias")
        chain, anchors = _load_chain(chain_path, anchors_path)
        return cls(key_id, chain, anchors or None)

    def sign(self, data: bytes) -> bytes:
        try:
            answer = self._client.sign(
                KeyId=self._key_id,
                Message=self._digest(data),
                MessageType="DIGEST",
                SigningAlgorithm=self._algorithm,
            )
            r, s = decode_dss_signature(answer["Signature"])
        except self._errors as exc:
            raise SignerError(f"KMS could not sign: {exc}") from exc
        except (KeyError, ValueError) as exc:
            raise SignerError("KMS answered without a DER ECDSA signature") from exc
        size = CURVES[self.alg][3]
        if r >= 1 << (8 * size) or s >= 1 << (8 * size):
            raise SignerError("KMS answered a signature too long for its curve")
        return self._checked(data, r.to_bytes(size, "big") + s.to_bytes(size, "big"))


def load_signer(
    key: Path,
    chain: Path,
    anchors: Path | None,
    *,
    production: bool,
    pkcs11_module: Path | None = None,
    pkcs11_pin_file: Path | None = None,
    name: str = "signing_key",
) -> Signer:
    """The signer a key setting names: a pkcs11: URI, aws-kms: and a key, or (in development only) a PEM file."""
    reference = str(key)
    if reference.startswith("pkcs11:"):
        return Pkcs11Signer.from_uri(reference, pkcs11_module, pkcs11_pin_file, chain, anchors)
    if reference.startswith("aws-kms:"):
        return KmsSigner.from_files(reference.removeprefix("aws-kms:"), chain, anchors)
    if production:
        raise ConfigError(
            f"production keeps its signing keys in an HSM or KMS: {name} must be a pkcs11: or aws-kms: key"
        )
    return FileSigner.from_files(key, chain, anchors)


def certificate_thumbprint_s256(signer: Signer) -> str:
    """x5t#S256: base64url SHA-256 of the DER leaf certificate (RFC 7515 §4.1.8)."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(signer.certificate_der())
    return b64u(digest.finalize())


class KeyringSigner:
    """A P-256 key derived from the keyring for one purpose, with no certificate.

    It signs the audit head statement, so that key is used for nothing else and is not the internet-facing
    status-list key (review 3, N3-L7). It is the same in every worker and survives restarts because it
    comes from the master secret; the operator pins its public key from the statement's `jwk` header.
    """

    alg = "ES256"

    def __init__(self, seed: bytes) -> None:
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        self._key = ec.derive_private_key(int.from_bytes(seed, "big") % (order - 1) + 1, ec.SECP256R1())

    def public_jwk(self) -> JSON:
        return jwk_from_public_key(self._key.public_key())

    def x5c(self) -> list[str]:
        return []

    def certificate_der(self) -> bytes:
        raise ConfigError("the audit head key has no certificate")

    def sign(self, data: bytes) -> bytes:
        r, s = decode_dss_signature(self._key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
