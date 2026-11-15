"""Key proofs (OpenID4VCI 1.0 App. F) and key attestations (App. D, TS3, CIR 2024/2979 Annex Ib)."""

from __future__ import annotations

import datetime as dt
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from cryptography import x509

from cunho.errors import ConfigError
from cunho.jose import (
    ALGORITHMS,
    JoseError,
    Jws,
    canonical_jwk,
    has_private_members,
    is_number,
    load_x5c,
    parse_jws,
    public_key_from_jwk,
    thumbprint,
    validate_path,
    verify,
)
from cunho.metadata import is_pid
from cunho.oauth import Nonces
from cunho.rules import enforce, implements, refuse
from cunho.settings import Profile, Settings
from cunho.status_refs import references

if TYPE_CHECKING:
    from cunho.trust import Trust
    from cunho.wallet_status import WalletStatus

PROOF_TYP = "openid4vci-proof+jwt"
KA_TYP = "key-attestation+jwt"
CLOCK_SKEW = 60
log = logging.getLogger("cunho")
# CRL extensions this validator understands. A delta CRL, a partitioned CRL (issuing distribution point) or an
# indirect CRL (certificate issuer entries) is refused when loaded rather than half processed.
KNOWN_CRL_EXTENSIONS = {x509.CRLNumber.oid, x509.AuthorityKeyIdentifier.oid}
KNOWN_CRL_ENTRY_EXTENSIONS = {x509.CRLReason.oid, x509.InvalidityDate.oid}


def parse_crls(data: bytes) -> list[x509.CertificateRevocationList]:
    """Every CRL in a PEM bundle, or one DER CRL. Raises ValueError on anything this validator cannot use.

    Whatever the library raises while the file is read (a duplicate extension raises DuplicateExtension, not
    a ValueError) refuses the file; anything a CRL can still raise later, in the path checks, is turned into a
    refusal there (review 4, N4-M2).
    """
    try:
        return _parse_crls(data)
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001 - whatever the library raises, the file cannot be used
        raise ValueError("the file holds a CRL that cannot be fully read") from exc


def _parse_crls(data: bytes) -> list[x509.CertificateRevocationList]:
    marker = b"-----BEGIN X509 CRL-----"
    if marker in data:
        crls = [x509.load_pem_x509_crl(marker + part) for part in data.split(marker)[1:]]
    else:
        crls = [x509.load_der_x509_crl(data)]
    for crl in crls:
        if any(e.oid not in KNOWN_CRL_EXTENSIONS for e in crl.extensions):
            raise ValueError("only complete CRLs are supported (no delta, partitioned or unknown extensions)")
        for entry in crl:
            if any(e.oid not in KNOWN_CRL_ENTRY_EXTENSIONS for e in entry.extensions):
                raise ValueError("a CRL entry carries an extension this validator does not process")
        if crl.next_update_utc is None:
            raise ValueError("a CRL without nextUpdate cannot be judged current")
    return crls


class CrlFile:
    """The wallet providers' CRLs, from a file the operator keeps current (review 3, N3-M4).

    The file is read again whenever it changes, so a job that refreshes it takes effect without a
    restart. cunho never fetches CRLs itself in M2. A file that disappears or no longer parses leaves no
    usable CRL, so every key attestation fails closed until it is fixed.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._crls: list[x509.CertificateRevocationList] = []
        # Taken before the read, so a file replaced during it is read again at the next use (as in cunho.lote).
        self._stamp = self._current_stamp()
        try:
            self._crls = parse_crls(path.read_bytes())
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot use the wallet provider CRLs in {path}: {exc}") from exc

    def _current_stamp(self) -> tuple[int, int, int] | None:
        """The file's inode, modification time and size. The inode tells a file renamed over the old one from it even
        when a coarse file system clock gives both the same time and they are the same size."""
        try:
            status = self._path.stat()
        except OSError:
            return None
        return status.st_ino, status.st_mtime_ns, status.st_size

    def current(self) -> list[x509.CertificateRevocationList]:
        stamp = self._current_stamp()
        with self._lock:
            if stamp != self._stamp:
                self._stamp = stamp
                try:
                    self._crls = parse_crls(self._path.read_bytes())
                except (OSError, ValueError):
                    log.error("the wallet provider CRL file cannot be used; key attestations fail until it is fixed")
                    self._crls = []
            return list(self._crls)


def load_anchors(path: Path) -> list[x509.Certificate]:
    """At least one certificate, or ConfigError: the loader refuses a file without one, so trust fails closed."""
    try:
        return x509.load_pem_x509_certificates(path.read_bytes())
    except Exception as exc:  # noqa: BLE001 - OSError, ValueError, InvalidVersion...: no usable anchors
        raise ConfigError(f"cannot read wallet provider trust anchors from {path}: {exc}") from exc


def _proof_error(rule: str, reason: str) -> NoReturn:
    refuse(rule, "invalid_proof", reason)


def _public(jwk: Any, rule: str) -> dict[str, Any]:
    """A validated public EC key in canonical form, so one key has one spelling and one thumbprint."""
    if isinstance(jwk, dict) and has_private_members(jwk):
        _proof_error("VCI.F4.PROOF_SIGNATURE", "a key in the proof contains private key material")
    try:
        return canonical_jwk(jwk)
    except JoseError as exc:
        _proof_error(rule, f"not a usable public key: {exc}")


@dataclass
class ProvenKeys:
    keys: list[dict[str, Any]] = field(default_factory=list)
    nonces: set[str] = field(default_factory=set)
    status_exp: int | None = None
    # A key attestation of the request states no end of its status maintenance period. A PID's validity ends before
    # the period of its own key's attestation, so one attestation that states a period does not stand in for
    # another of the same request that states none (the security review).
    unbounded: bool = False
    # each attested key's key_storage_status references, by the key's thumbprint, for revocation chaining (LC_GEN-4):
    # a credential is chained to its own key's attestation, never to another key's of the same batch
    key_status: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def add_key(self, jwk: dict[str, Any]) -> None:
        enforce(
            thumbprint(jwk) not in {thumbprint(k) for k in self.keys},
            "KA.BIND_TO_ATTESTED_KEY",
            "invalid_proof",
            "the same key appears twice; each key binds at most one credential",
        )
        self.keys.append(jwk)

    def watch(self, keys: list[dict[str, Any]], status: dict[str, Any]) -> None:
        """Keep a key attestation's status references for the keys it attests, to check again while their
        credentials live. They are never a wallet identifier: under the type-shared index option one entry stands for
        a kind of WSCD (R_KA_1)."""
        try:
            found = [each.member() for each in references(status)]
        except JoseError:
            return
        for key in keys:
            held = self.key_status.setdefault(thumbprint(key), [])
            held += [member for member in found if member not in held]

    def cap(self, exp: Any) -> None:
        if is_number(exp):
            self.status_exp = int(exp) if self.status_exp is None else min(self.status_exp, int(exp))
        else:
            self.unbounded = True


class ProofVerifier:
    def __init__(
        self,
        settings: Settings,
        nonces: Nonces,
        trust: Trust,
        clock: Callable[[], float],
        wallet_status: WalletStatus | None = None,
    ) -> None:
        self._settings = settings
        self._nonces = nonces
        self._trust = trust
        self._clock = clock
        self._wallet_status = wallet_status

    def _signed(self, token: Any, typ: str, typ_rule: str) -> Jws:
        try:
            jws = parse_jws(token)
        except JoseError as exc:
            _proof_error("VCI.F4.PROOF_SIGNATURE", f"proof is not a valid JWS: {exc}")
        if jws.header.get("typ") != typ:
            _proof_error(typ_rule, f"typ must be {typ}")
        alg = jws.header.get("alg")
        if not isinstance(alg, str) or alg not in ALGORITHMS:
            _proof_error("VCI.F1.PROOF_ALG_ASYMMETRIC", f"alg must be one of {sorted(ALGORITHMS)}")
        return jws

    def _check_nonce(self, value: Any, proven: ProvenKeys, missing_rule: str) -> None:
        enforce(
            isinstance(value, str) and bool(value),
            missing_rule,
            "invalid_proof",
            "the proof must carry a c_nonce from the nonce endpoint",
        )
        enforce(
            self._nonces.c_nonce_valid(value),
            "VCI.NONCE.C_NONCE_VALID",
            "invalid_nonce",
            "c_nonce is unknown, expired or already used",
        )
        proven.nonces.add(str(value))

    @implements(
        "KA.VERIFY",
        "KA.CHAIN_TO_WP_LIST",
        "KA.PID_KEY_IN_WSCD",
        "KA.STATUS_EXP_NOT_TOKEN_EXP",
        "KA.STATUS_AT_ISSUANCE",
        "PRIV.NO_KA_IDX_AS_WALLET_ID",
        "TS3.CONFORMANCE",
    )
    def key_attestation(
        self, token: Any, required: dict[str, Any], proven: ProvenKeys, *, nonce_rule: str | None, jwt_proof: bool
    ) -> list[dict[str, Any]]:
        """Verify a key attestation and return its attested keys, validated and canonical."""
        ka = self._signed(token, KA_TYP, "KA.VERIFY")
        now = self._clock()
        try:
            chain = load_x5c(ka.header.get("x5c"))
        except JoseError as exc:
            _proof_error("KA.CHAIN_TO_WP_LIST", f"key attestation is not from a trusted wallet provider: {exc}")
        # The signature before the path, whose check may fetch the chain's revocation: see ClientAuth.authenticate.
        if not verify(ka.header["alg"], chain[0].public_key(), ka.signing_input, ka.signature):
            _proof_error("KA.VERIFY", "key attestation signature does not verify")
        try:
            validate_path(
                chain,
                self._trust.issuance(),
                dt.datetime.fromtimestamp(now, dt.UTC),
                frozenset(self._settings.ka_signer_policy_oids),
                revocation=self._trust.revocation(),
            )
        except JoseError as exc:
            _proof_error("KA.CHAIN_TO_WP_LIST", f"key attestation is not from a trusted wallet provider: {exc}")
        claims = ka.payload
        iat = claims.get("iat")
        if not is_number(iat) or iat > now + CLOCK_SKEW:
            _proof_error("KA.VERIFY", "key attestation needs an iat that is not in the future")
        exp = claims.get("exp")
        if exp is not None and not is_number(exp):
            _proof_error("KA.VERIFY", "key attestation exp must be a number")
        if jwt_proof and exp is None:
            _proof_error("KA.VERIFY", "a key attestation in a jwt proof needs exp (OpenID4VCI App. D.1)")
        if exp is not None and exp <= now:
            _proof_error("KA.VERIFY", "key attestation has expired")
        listed = claims.get("attested_keys")
        if not isinstance(listed, list) or not listed:
            _proof_error("KA.VERIFY", "attested_keys must be a non-empty array of JWKs")
        keys = [_public(jwk, "KA.VERIFY") for jwk in listed]
        for member, rule in (("key_storage", "KA.PID_KEY_IN_WSCD"), ("user_authentication", "KA.VERIFY")):
            wanted = set(required.get(member) or [])
            offered = claims.get(member)
            if wanted and not (isinstance(offered, list) and wanted & {str(v) for v in offered}):
                _proof_error(rule, f"key attestation {member} does not meet {sorted(wanted)}")
        if nonce_rule is not None:
            self._check_nonce(claims.get("nonce"), proven, nonce_rule)
        elif "nonce" in claims:
            enforce(
                self._nonces.c_nonce_valid(claims["nonce"]),
                "VCI.NONCE.C_NONCE_VALID",
                "invalid_nonce",
                "key attestation nonce is not a valid c_nonce",
            )
            proven.nonces.add(str(claims["nonce"]))
        # CIR 2024/2979 Annex Ib C_KA-3: the maintenance period is key_storage_status.exp, never the top-level
        # exp. Its status entry must say VALID now (TS3 v1.5.2 §2.4.3), and its reference is kept with the
        # credentials for the check at least every 24 hours afterwards (LC_GEN-4), never as a wallet identifier.
        status = claims.get("key_storage_status")
        proven.cap(status.get("exp") if isinstance(status, dict) else None)
        if isinstance(status, dict):
            proven.watch(keys, status)
        if self._wallet_status is not None:
            try:
                self._wallet_status.check(status)
            except JoseError as exc:
                _proof_error("KA.STATUS_AT_ISSUANCE", f"key attestation status: {exc}")
        return keys

    @implements(
        "BIND.DEVICE_BOUND",
        "KA.BIND_TO_ATTESTED_KEY",
        "KA.JWT_PROOF_ATTESTED_KEY0",
        "VCI.F1.PROOF_TYP",
    )
    def jwt_proofs(self, tokens: list[Any], spec: dict[str, Any], client: str | None = None) -> ProvenKeys:
        """Each jwt proof binds exactly the key that signed it, so possession of every bound key is proven. `client`
        is the attested client of a code-flow token, whose client_id a proof may name in iss (App. F.1)."""
        required = spec.get("key_attestations_required")
        proven = ProvenKeys()
        for token in tokens:
            proof = self._signed(token, PROOF_TYP, "VCI.F1.PROOF_TYP")
            header, claims = proof.header, proof.payload
            refs = [name for name in ("kid", "jwk", "x5c") if name in header]
            attestation = header.get("key_attestation")
            if required is not None:
                enforce(
                    attestation is not None,
                    "KA.VERIFY",
                    "invalid_proof",
                    "this credential configuration requires a key attestation",
                )
            if attestation is not None:
                attested = self.key_attestation(attestation, required or {}, proven, nonce_rule=None, jwt_proof=True)
                signing_jwk = attested[0]
                # OpenID4VCI 1.0 App. F.1's own example names the attested key by its index ("kid": "0"); only key 0
                # may sign (CIR 2024/2979 Annex Ib TR_KA-6.1), so any other kid is refused.
                if refs == ["kid"] and header["kid"] == "0":
                    refs = []
                if refs not in ([], ["jwk"]):
                    _proof_error("VCI.F4.PROOF_SIGNATURE", "with a key attestation the proof key is attested_keys[0]")
                if "jwk" in header and thumbprint(_public(header["jwk"], "KA.JWT_PROOF_ATTESTED_KEY0")) != thumbprint(
                    signing_jwk
                ):
                    _proof_error("KA.JWT_PROOF_ATTESTED_KEY0", "the proof must be signed with attested_keys[0]")
            else:
                if refs != ["jwk"]:
                    _proof_error("VCI.F4.PROOF_SIGNATURE", "the proof must identify its key with jwk only")
                signing_jwk = _public(header["jwk"], "VCI.F4.PROOF_SIGNATURE")
            alg = header["alg"]
            try:
                key = public_key_from_jwk(signing_jwk, alg)
            except JoseError as exc:
                _proof_error("VCI.F4.PROOF_SIGNATURE", str(exc))
            if not verify(alg, key, proof.signing_input, proof.signature):
                _proof_error("VCI.F4.PROOF_SIGNATURE", "proof signature does not verify")
            if claims.get("aud") != self._settings.issuer_url:
                _proof_error("VCI.F1.PROOF_AUD", "aud must be the credential issuer identifier")
            iat = claims.get("iat")
            if not is_number(iat) or abs(self._clock() - iat) > self._settings.proof_iat_window:
                _proof_error("VCI.F1.PROOF_IAT", "iat is missing, not a finite number, or outside the accepted window")
            if "iss" in claims and client is None:
                # ignore_anonymous_proof_iss: the iss of a wallet that sends one all the same is read as nothing
                if not self._settings.ignore_anonymous_proof_iss:
                    _proof_error(
                        "VCI.F1.PROOF_ISS_ANON_PREAUTH", "iss must be omitted in the anonymous pre-authorized flow"
                    )
            elif "iss" in claims and claims["iss"] != client:
                _proof_error("VCI.F4.PROOF_SIGNATURE", "iss must be the client_id of the client (App. F.1)")
            self._check_nonce(claims.get("nonce"), proven, "VCI.NONCE.C_NONCE_VALID")
            proven.add_key(signing_jwk)
        return proven

    @implements("KA.ATTESTATION_PROOF_NONCE", "KA.POP_ALL_KEYS")
    def attestation_proofs(self, tokens: list[Any], spec: dict[str, Any]) -> ProvenKeys:
        """The attestation proof type (App. F.3): one key attestation that carries this issuer's c_nonce.

        Possession of every attested key rests on the wallet provider signing, over a fresh c_nonce, that the
        keys sit in the WSCD (TS3). This is how ARF WUA_12 is met for keys that do not sign a proof themselves.
        """
        enforce(
            len(tokens) == 1,
            "VCI.CRED.PROOFS_SHAPE",
            "invalid_proof",
            "the attestation proof type carries exactly one key attestation (OpenID4VCI App. F.3)",
        )
        proven = ProvenKeys()
        required = spec.get("key_attestations_required") or {}
        for jwk in self.key_attestation(
            tokens[0], required, proven, nonce_rule="KA.ATTESTATION_PROOF_NONCE", jwt_proof=False
        ):
            proven.add_key(jwk)
        return proven

    def require_status_period(self, proven: ProvenKeys, config: dict[str, Any]) -> None:
        if is_pid(config) or self._settings.profile is Profile.PID_PROVIDER:
            enforce(
                proven.status_exp is not None and not proven.unbounded,
                "VALIDITY.PID_LE_STATUS_EXP",
                "invalid_proof",
                "a PID needs a key attestation with key_storage_status.exp to cap its validity",
            )
