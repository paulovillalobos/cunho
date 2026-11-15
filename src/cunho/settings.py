"""Deployment settings. cunho refuses to start on a setting that would make it unsafe or non-conformant."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from cunho.errors import ConfigError

DEFAULT_METADATA_DIR = Path(__file__).resolve().parent / "metadata_config"
# The longest a request_uri and a login may be set to live (FAPI 2.0 §5.3.2.2 item 12: a request_uri under 600 s).
MAX_PAR_TTL = 599
MAX_LOGIN_TTL = 600
# Seconds a wall-clock reading may lie off the clock watch's time before it is reported as a clock that is off.
CLOCK_TOLERANCE = 120
EXAMPLE_SECRETS = {"", "change-me", "changeme", "secret", "admin", "password", "example", "test"}


class Profile(StrEnum):
    """Issuer type under eIDAS. It decides which binder rows apply (BINDER-STRENGTH issuer_types)."""

    PID_PROVIDER = "pid_provider"
    QEAA_PROVIDER = "qeaa_provider"
    PUB_EAA_PROVIDER = "pub_eaa_provider"
    EAA_PROVIDER = "eaa_provider"


# The providers whose credentials name their signer's certificate by x5u and x5t#S256.
SIGNER_URL_PROFILES = frozenset({Profile.PID_PROVIDER, Profile.QEAA_PROVIDER, Profile.PUB_EAA_PROVIDER})


@dataclass(frozen=True)
class Settings:
    issuer_url: str
    admin_token: str
    signing_key: Path
    signing_chain: Path
    audit_retention_days: int
    profile: Profile = Profile.PID_PROVIDER
    production: bool = False
    status_signing_key: Path | None = None
    status_signing_chain: Path | None = None
    signer_certificate_url: str | None = None
    metadata_dir: Path = DEFAULT_METADATA_DIR
    store_path: Path | None = None
    # A PostgreSQL store for workers on several hosts (M4), as a libpq connection URI, instead of store_path.
    store_url: str | None = None
    batch_size: int | None = None
    offer_ttl: int = 600
    access_token_ttl: int = 300
    c_nonce_ttl: int = 300
    dpop_iat_window: int = 60
    proof_iat_window: int = 300
    tx_code_max_attempts: int = 5
    dpop_server_nonce: bool = False
    credential_validity_days: int = 14
    timestamp_granularity: int = 3600
    status_list_size: int = 131_072
    status_list_fill_limit: float = 0.5
    status_decoy_ratio: float = 0.02
    status_token_ttl: int = 3600
    status_token_lifetime: int = 86_400
    status_decoy_churn_per_day: float = 0.001
    secret_key_file: Path | None = None
    operators: dict[str, str] = field(default_factory=dict)
    published_configurations: tuple[str, ...] | None = None
    display_name: str | None = None
    rate_limit_per_minute: int = 120
    operator_rate_limit_per_minute: int = 6000
    audit_anchor_path: Path | None = None
    maintenance_interval: int = 3600
    # Revocation chaining (M4): how often the status of the wallet and key attestations behind every credential that
    # lives more than a day is checked again, at most a day apart (CIR 2024/2979 Annex Ib LC_GEN-4). A PID provider
    # always chains; an attestation provider may (ARF VCR_07d). When a wallet provider's list cannot be read, cunho
    # alerts and keeps trying; it revokes only with chain_revoke_after_days set, after that many days unchecked.
    chain_interval: int = 6 * 3600
    chain_attestations: bool = False
    # Why a wallet's request was refused, logged to cunho.refusals: the route, the status, the error and the rule, and
    # nothing of who asked (no address, no header, no query, no token). Off by default; for finding out what a wallet
    # that does not get through expects, then off again.
    log_refusals: bool = False
    # OpenID4VCI 1.0 App. F.1: in the anonymous pre-authorized flow a wallet MUST omit iss from its key proof, and cunho
    # refuses a proof that has one. Some wallets send it all the same (Lissi). With this on, such an iss is ignored:
    # it binds the proof to no client, as there is none, and nothing else of the proof is relaxed.
    ignore_anonymous_proof_iss: bool = False
    # OpenID4VCI 1.0 §12.2.2 puts the well-known segment before an issuer's path. Some wallets in use still append it
    # (Sphereon's last release) and, finding nothing, go on with no credential configurations. With this on, an issuer
    # with a path also answers its metadata at <path>/.well-known/...; nothing else changes.
    appended_well_known: bool = False
    # HAIP binds every access token to the wallet's key by DPoP, and cunho requires it. Some wallets in use send no
    # DPoP proof (Sphereon's last release). With this on, a pre-authorized token request without one gets a plain
    # Bearer token (RFC 6750), used with the Bearer scheme; a request with a DPoP proof still gets a DPoP-bound one.
    # Only for an attestation provider that is neither qualified nor public (eaa_provider): never for a PID.
    accept_bearer_tokens: bool = False
    # OpenID4VCI 1.0 §8.2 takes key proofs in `proofs`. Some wallets in use still send one jwt proof in the earlier
    # drafts' singular `proof` object (Sphereon's last release). With this on, a request with no `proofs` and a
    # `proof` of type jwt is read as `proofs: {jwt: [<that proof>]}`, checked like any other. Only for an
    # eaa_provider, as accept_bearer_tokens.
    accept_singular_proof: bool = False
    # Deferred issuance (M4, OpenID4VCI 1.0 §9): how long an issuance held for the operator's review can be decided
    # and collected, and how long a wallet is told to wait between asks.
    deferred_ttl: int = 7 * 86_400
    deferred_interval: int = 600
    # Encrypted credential requests and responses (M4, OpenID4VCI 1.0 §10): cunho's request keys, PEM EC P-256
    # private keys readable by their owner only, all published; and whether the wallet must encrypt both ways.
    encryption_keys: tuple[Path, ...] = ()
    encryption_required: bool = False
    # Signing keys in an HSM (M4): a key setting may be a pkcs11: URI (RFC 7512), opened through this library with
    # the user PIN in this file (chmod 600). A key setting may also be aws-kms: and a key id, ARN or alias.
    pkcs11_module: Path | None = None
    pkcs11_pin_file: Path | None = None
    chain_revoke_after_days: int | None = None
    signing_trust_anchors: Path | None = None
    # mdoc (M4): the document signer, whose certificate carries the purpose id-mdl-kp-mdlDS (ISO/IEC 18013-5 Annex
    # B), under an issuing authority certificate authority (IACA) that verifiers trust and that x5chain never carries.
    # Without it no mdoc configuration is published. A PID, QEAA or PuB-EAA provider names the document signer's
    # certificate by x5u and x5t in the protected header too (CIR 2024/2977 Annex §4.1; ETSI TS 119 472-1
    # QEAA-6.6.2-02, PuB-EAA-6.6.3-02), at mdoc_signer_certificate_url.
    mdoc_signing_key: Path | None = None
    mdoc_signing_chain: Path | None = None
    mdoc_trust_anchors: Path | None = None
    mdoc_signer_certificate_url: str | None = None
    ka_signer_policy_oids: tuple[str, ...] = ()
    wallet_provider_crls: Path | None = None
    audit_anchor_init: bool = False
    store_upgrade: bool = False
    status_revocation_jitter: int = 3600
    status_publish_interval: int = 60
    status_rate_limit_per_minute: int = 600
    # The authorization code flow (M3). The operator's login service, where /authorize sends the browser with a
    # login_state; it reports the result to /admin/logins/{login_state}.
    login_url: str | None = None
    # A built-in login that serves fixture persons from a JSON file, for tests and the OIDF suite. Never in
    # production.
    test_login_persons: Path | None = None
    # The exact redirect URIs the operator allows, per wallet solution (the `sub` of its wallet attestation).
    redirect_uris: dict[str, tuple[str, ...]] = field(default_factory=dict)
    par_ttl: int = 60
    login_ttl: int = 600
    code_ttl: int = 60
    client_attestation_pop_window: int = 60
    wia_signer_policy_oids: tuple[str, ...] = ()
    # How long a refresh token from the code flow lets a wallet get credentials again without a new login. HAIP 1.0
    # §4.4 recommends against refreshing a year after issuance; the subject's data stays in the vault this long.
    refresh_token_ttl: int = 30 * 86_400
    # Wallet providers' status lists (M3), in a development run without the Commission's list: the trust anchors of
    # the certificates that sign them. Without them the status of wallet and key attestations is not checked.
    wallet_status_anchors: Path | None = None
    # The hosts cunho may fetch from: wallet providers' status lists, CRLs and OCSP. None allows any host with a
    # public address, which production refuses.
    fetch_hosts: tuple[str, ...] | None = None
    # Trust in wallet providers (M3): the Commission's list of wallet providers (ETSI TS 119 602 Annex E), as a file an
    # operator job keeps current, and the certificate that signs it, pinned from the Official Journal. With them the
    # anchors and revocation come from the list, CRL distribution points and OCSP (cunho.trust); production needs
    # them. Without them, a development run, wallet_provider_anchors and wallet_status_anchors are PEM files.
    lote_path: Path | None = None
    lote_signer: Path | None = None
    wallet_provider_anchors: Path | None = None
    # Signed metadata (M3): the access certificate signs the issuer metadata (OpenID4VCI §12.2.3, ETSI TS 119 472-3
    # §4.2.1, §4.2.2). Its anchors are the access certificate authority's, never sent in x5c. A development run may
    # sign with files; production takes the signer the deployment injects.
    access_signing_key: Path | None = None
    access_signing_chain: Path | None = None
    access_trust_anchors: Path | None = None
    signed_metadata_ttl: int = 86_400
    # issuer_info (TS 119 472-3 §4.2.3): the registration certificate as the registrar issued it, and the registrar
    # dataset, a JSON object with identifier, srvDescription, registryURI and providesAttestations.
    registration_certificate: Path | None = None
    registrar_dataset: Path | None = None
    # The remaining status maintenance period cunho prefers in the wallet attestations it receives, in seconds,
    # published at the top of the issuer metadata (TS3 v1.5.2 §2.4).
    preferred_client_status_period: int | None = None
    # A run under a conformance suite that tests HAIP alone, such as the OpenID Foundation's (tools/oidf): a wallet
    # attestation without client_status is taken, its status unchecked and no status period capping what is issued.
    # TS3 and the ARF ask for client_status of every EUDI wallet attestation, so production refuses this.
    conformance_mode: bool = False

    def __post_init__(self) -> None:
        parts = urlsplit(self.issuer_url)
        local = parts.hostname in ("localhost", "127.0.0.1", "testserver")
        if parts.scheme != "https" and not (parts.scheme == "http" and local and not self.production):
            raise ConfigError("issuer_url must use https (OpenID4VCI 1.0 §12.2.1)")
        if parts.query or parts.fragment or self.issuer_url.endswith("/"):
            raise ConfigError("issuer_url must have no query, fragment or trailing slash")
        if "admin" in self.operators:
            # The name of the operator behind admin_token: one in operators would silently take its place (review 7,
            # L7).
            raise ConfigError("no operator in operators may be named admin; that is the name of admin_token")
        tokens = {"admin": self.admin_token, **self.operators}
        for name, token in tokens.items():
            if not name.isidentifier() or token.strip().lower() in EXAMPLE_SECRETS or len(token) < 32:
                raise ConfigError(
                    f"operator token {name!r} is missing, an example value, or shorter than 32 characters"
                )
        if len(set(tokens.values())) != len(tokens):
            raise ConfigError("every operator needs its own token")
        if self.audit_retention_days <= 0:
            raise ConfigError("audit_retention_days must be set; EU law leaves the period to national law")
        if self.profile in SIGNER_URL_PROFILES and not self.signer_certificate_url:
            raise ConfigError(
                "PID, QEAA and PuB-EAA providers must publish the signer certificate at signer_certificate_url "
                "(CIR 2024/2977 Annex as amended by 2026/1731; ETSI TS 119 472-1 QEAA-5.6.2-02, PuB-EAA-5.6.3-02: "
                "x5u and x5t#S256)"
            )
        if self.signer_certificate_url and urlsplit(self.signer_certificate_url).scheme != "https":
            raise ConfigError("signer_certificate_url must use https (RFC 7515 §4.1.5)")
        own = f"{self.issuer_url}/certs/signer.pem"
        if (self.signer_certificate_url or "").startswith(f"{self.issuer_url}/") and self.signer_certificate_url != own:
            raise ConfigError(f"cunho serves the signer certificate only at {own}; use that URL or host it elsewhere")
        if self.store_path is not None and self.store_url is not None:
            raise ConfigError("set store_path or store_url, not both")
        if self.store_url is not None:
            if not self.store_url.startswith(("postgresql://", "postgres://")):
                raise ConfigError("store_url must be a postgresql:// connection URI")
            # The keys and the audit anchor never live in the database, and a database that outlives the process
            # needs them to outlive it too, in development as well.
            if self.secret_key_file is None or self.audit_anchor_path is None:
                raise ConfigError("a Postgres store needs secret_key_file and audit_anchor_path, outside the database")
        persistent = self.store_path is not None or self.store_url is not None
        if self.production and (self.status_signing_key is None or not persistent):
            raise ConfigError("production needs a separate status-list key and a persistent store")
        if self.production and self.secret_key_file is None:
            raise ConfigError("production needs secret_key_file, kept apart from the database and its backups")
        if self.batch_size is not None and self.batch_size < 2:
            raise ConfigError("batch_size must be 2 or more, or unset (OpenID4VCI 1.0 §12.2.4)")
        limits = (self.rate_limit_per_minute, self.operator_rate_limit_per_minute, self.status_rate_limit_per_minute)
        if min(limits) < 1:
            raise ConfigError("rate limits must be at least 1 request per minute")
        if not 1024 <= self.status_list_size <= 8_388_608 or self.status_list_size % 8:
            raise ConfigError("status_list_size must be a multiple of 8 between 1024 and 8388608")
        self._check_knobs()
        if self.production and self.audit_anchor_path is None:
            raise ConfigError(
                "production needs audit_anchor_path: an append-only (WORM) file outside the database that "
                "anchors the audit log, so deleting its newest entries is detected"
            )
        anchor = self.audit_anchor_path
        if anchor is not None and anchor in {self.store_path, self.secret_key_file}:
            raise ConfigError("audit_anchor_path must be its own file, apart from the store and the secret key")
        if self.production and not self.signing_trust_anchors:
            raise ConfigError("production needs signing_trust_anchors, so x5c never carries a trust anchor")
        if (self.mdoc_signing_key is None) != (self.mdoc_signing_chain is None):
            raise ConfigError("mdoc_signing_key and mdoc_signing_chain go together")
        if self.mdoc_signing_key is not None:
            if self.profile in SIGNER_URL_PROFILES and not self.mdoc_signer_certificate_url:
                raise ConfigError(
                    "PID, QEAA and PuB-EAA providers name the document signer certificate by x5u and x5t at "
                    "mdoc_signer_certificate_url (CIR 2024/2977 Annex §4.1; ETSI TS 119 472-1 QEAA-6.6.2-02)"
                )
            if self.production and not self.mdoc_trust_anchors:
                raise ConfigError("production needs mdoc_trust_anchors, so x5chain never carries the IACA")
        if self.mdoc_signer_certificate_url:
            if urlsplit(self.mdoc_signer_certificate_url).scheme != "https":
                raise ConfigError("mdoc_signer_certificate_url must use https (RFC 9360 §2)")
            own = f"{self.issuer_url}/certs/mdoc-signer.pem"
            if self.mdoc_signer_certificate_url.startswith(f"{self.issuer_url}/") and (
                self.mdoc_signer_certificate_url != own
            ):
                raise ConfigError(f"cunho serves the document signer certificate only at {own}")
        if self.production and not self.ka_signer_policy_oids:
            raise ConfigError(
                "production needs ka_signer_policy_oids: the certificate policy that marks a wallet provider's "
                "key attestation signer"
            )
        self._check_code_flow()
        if self.production and not self.wia_signer_policy_oids:
            raise ConfigError(
                "production needs wia_signer_policy_oids: the certificate policy that marks a wallet provider's "
                "wallet attestation signer, so a key attestation signer cannot vouch for a wallet instance"
            )
        if (self.lote_path is None) != (self.lote_signer is None):
            raise ConfigError("set lote_path and lote_signer together")
        if self.production and self.lote_path is None:
            raise ConfigError(
                "production needs lote_path and lote_signer: the wallet providers' trust anchors are the ones the "
                "Commission publishes in its list of wallet providers (ARF ISSU_19, ISSU_28, ETSI TS 119 602)"
            )
        if self.lote_path is None and self.wallet_provider_anchors is None:
            raise ConfigError("set lote_path and lote_signer, or wallet_provider_anchors in development")
        if self.production and not self.fetch_hosts:
            raise ConfigError("production needs fetch_hosts: the hosts cunho may fetch status lists and CRLs from")
        if self.fetch_hosts is not None and any(not isinstance(h, str) or not h or "/" in h for h in self.fetch_hosts):
            raise ConfigError("fetch_hosts must be host names")
        if self.production and (self.registration_certificate is None or self.registrar_dataset is None):
            # Decision 7: refused rather than warned about, as the rule is a MUST (ARF RPRC_22, TS 119 472-3 §4.2.3).
            raise ConfigError(
                "production needs registration_certificate and registrar_dataset: the issuer metadata carries them "
                "in issuer_info (ETSI TS 119 472-3 §4.2.3)"
            )
        period = self.preferred_client_status_period
        if period is not None and (
            isinstance(period, bool) or not isinstance(period, int) or not 0 < period <= 366 * 86_400
        ):
            raise ConfigError("preferred_client_status_period must be a whole number of seconds from 1 to a year")

    def _check_code_flow(self) -> None:
        """The login and the redirect allow-list (ISS.IDPROOF.PLUG_REQUIRED, OAUTH.REDIRECT_URI_EXACT)."""
        if self.production and self.test_login_persons is not None:
            raise ConfigError("the built-in test login is for tests only and refuses to start in production")
        if self.production and self.conformance_mode:
            raise ConfigError(
                "conformance_mode takes wallet attestations without client_status, which TS3 and the ARF require: "
                "it is for conformance suite runs only and refuses to start in production"
            )
        if self.production and not self.login_url:
            raise ConfigError(
                "production needs login_url: the operator's login service, which proves the person's identity at "
                "assurance level high and reports it to /admin/logins/{login_state}"
            )
        if self.login_url and self.test_login_persons is not None:
            raise ConfigError("set login_url or test_login_persons, not both")
        if self.login_url:
            login = urlsplit(self.login_url)
            if login.scheme != "https" or not login.hostname or "#" in self.login_url:
                raise ConfigError("login_url must be an https URL without a fragment")
        for sub, uris in self.redirect_uris.items():
            if not isinstance(sub, str) or not sub or not isinstance(uris, tuple):
                raise ConfigError("redirect_uris maps each wallet solution's sub to a list of URIs")
            for uri in uris:
                if not isinstance(uri, str) or not _redirect_ok(uri):
                    raise ConfigError(
                        f"redirect URI {uri!r} for {sub!r} must be absolute, without a fragment, and not http except "
                        "on a loopback address (FAPI 2.0 §5.3.2.2)"
                    )
        bounds = {
            "par_ttl": MAX_PAR_TTL,
            "login_ttl": MAX_LOGIN_TTL,
            "code_ttl": 60,
            "client_attestation_pop_window": 300,
            "refresh_token_ttl": 365 * 86_400,
            "signed_metadata_ttl": 7 * 86_400,
        }
        for name, most in bounds.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= most:
                # request_uri under 600 s (FAPI 2.0 §5.3.2.2 item 12), codes at most 60 s (§5.3.2.1 item 11).
                raise ConfigError(f"{name} must be a whole number from 1 to {most}")

    def _check_knobs(self) -> None:
        """Refuse values that would crash at run time or quietly defeat a protection (review 2, N-L6)."""
        positive = {
            "offer_ttl": self.offer_ttl,
            "access_token_ttl": self.access_token_ttl,
            "c_nonce_ttl": self.c_nonce_ttl,
            "dpop_iat_window": self.dpop_iat_window,
            "proof_iat_window": self.proof_iat_window,
            "tx_code_max_attempts": self.tx_code_max_attempts,
            "credential_validity_days": self.credential_validity_days,
            "timestamp_granularity": self.timestamp_granularity,
            "status_token_ttl": self.status_token_ttl,
            "status_token_lifetime": self.status_token_lifetime,
            "maintenance_interval": self.maintenance_interval,
            "status_publish_interval": self.status_publish_interval,
            "chain_interval": self.chain_interval,
            "deferred_ttl": self.deferred_ttl,
            "deferred_interval": self.deferred_interval,
        }
        for name, value in positive.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ConfigError(f"{name} must be a whole number of at least 1")
        if self.dpop_iat_window > 600 or self.proof_iat_window > 3600:
            raise ConfigError("dpop_iat_window must be at most 600 s and proof_iat_window at most 3600 s")
        if 86_400 % self.timestamp_granularity:  # also refuses anything longer than a day
            raise ConfigError("timestamp_granularity must divide a day (for example 60, 3600 or 86400)")
        if not 600 <= self.chain_interval <= 86_400:
            raise ConfigError(
                "chain_interval must be from 10 minutes to a day: LC_GEN-4 asks for a check every 24 hours, and a run "
                "holds its lease for an interval, renewed after each list, which must outlast any one list's fetch"
            )
        if not 3600 <= self.deferred_ttl <= 30 * 86_400:
            raise ConfigError("deferred_ttl must be from an hour to 30 days")
        if not 5 <= self.deferred_interval <= min(86_400, self.deferred_ttl):
            raise ConfigError("deferred_interval must be from 5 s to a day, and at most deferred_ttl")
        if self.accept_singular_proof and self.profile != Profile.EAA_PROVIDER:
            raise ConfigError("accept_singular_proof is only for an eaa_provider")
        if self.accept_bearer_tokens and self.profile != Profile.EAA_PROVIDER:
            raise ConfigError("accept_bearer_tokens is only for an eaa_provider; PID, QEAA, PuB-EAA keep DPoP")
        if self.encryption_required and not self.encryption_keys:
            raise ConfigError("encryption_required needs encryption_keys: a wallet must be able to encrypt to cunho")
        if self.chain_revoke_after_days is not None and (
            isinstance(self.chain_revoke_after_days, bool)
            or not isinstance(self.chain_revoke_after_days, int)
            or self.chain_revoke_after_days < 1
        ):
            raise ConfigError("chain_revoke_after_days must be a whole number of at least 1, or unset")
        if self.status_token_lifetime < self.status_token_ttl:
            raise ConfigError("status_token_lifetime must be at least status_token_ttl")
        if not 0 < self.status_list_fill_limit <= 0.9:
            raise ConfigError("status_list_fill_limit must be above 0 and at most 0.9")
        if not 0 <= self.status_decoy_ratio < self.status_list_fill_limit / 2:
            raise ConfigError("status_decoy_ratio must be 0 or more and below half the fill limit")
        if not 0 <= self.status_decoy_churn_per_day <= 0.05:
            raise ConfigError("status_decoy_churn_per_day must be between 0 and 0.05")
        jitter = self.status_revocation_jitter
        if isinstance(jitter, bool) or not isinstance(jitter, int) or jitter < 0:
            raise ConfigError("status_revocation_jitter must be a whole number of seconds, 0 or more")
        if self.status_publish_interval > min(self.status_token_ttl, 3600):
            raise ConfigError("status_publish_interval must be at most status_token_ttl and at most 3600 s")
        if jitter + CLOCK_TOLERANCE + self.status_publish_interval + self.status_token_ttl > 86_400:
            # A revocation is published within 24 hours (910/2014 Art. 24(3) for QEAA, STATUS.PUBLISH_24H).
            raise ConfigError(
                "status_revocation_jitter plus status_publish_interval plus status_token_ttl must be at most 86280 s "
                f"(86400 s less a margin of {CLOCK_TOLERANCE} s for the wall-clock reading the clock watch's time was "
                "laid from)"
            )

    @property
    def subject_window(self) -> int:
        """How long a subject can still lead to a token, and a token to a credential: an offer's lifetime, or a
        login's with its code and the refresh token it gives, whichever is longer, and the access token's."""
        login = self.login_ttl + self.code_ttl + self.refresh_token_ttl
        return max(self.offer_ttl, login) + self.access_token_ttl

    @property
    def credential_endpoint(self) -> str:
        return f"{self.issuer_url}/credential"

    @property
    def deferred_credential_endpoint(self) -> str:
        return f"{self.issuer_url}/deferred_credential"

    @property
    def notification_endpoint(self) -> str:
        return f"{self.issuer_url}/notification"

    @property
    def nonce_endpoint(self) -> str:
        return f"{self.issuer_url}/nonce"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer_url}/token"

    @property
    def par_endpoint(self) -> str:
        return f"{self.issuer_url}/par"

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer_url}/authorize"

    @property
    def continue_endpoint(self) -> str:
        return f"{self.issuer_url}/authorize/continue"

    @property
    def test_login_endpoint(self) -> str:
        return f"{self.issuer_url}/test-login"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ if env is None else env)

        def need(name: str) -> str:
            value = env.get(f"CUNHO_{name}")
            if not value:
                raise ConfigError(f"CUNHO_{name} is required")
            return value

        def path(name: str) -> Path | None:
            value = env.get(f"CUNHO_{name}")
            return Path(value) if value else None

        def number(name: str, default: int) -> int:
            value = env.get(f"CUNHO_{name}")
            if not value:
                return default
            try:
                return int(value)
            except ValueError:
                raise ConfigError(f"CUNHO_{name} must be a whole number") from None

        def flag(name: str) -> bool:
            """true or false, in the spellings operators use; anything else refuses to start (review 5, N5-L11)."""
            value = env.get(f"CUNHO_{name}", "").strip().lower()
            if value in ("", "false", "0", "no", "off"):
                return False
            if value in ("true", "1", "yes", "on"):
                return True
            raise ConfigError(f"CUNHO_{name} must be true or false")

        def fraction(name: str, default: float) -> float:
            value = env.get(f"CUNHO_{name}")
            if not value:
                return default
            try:
                return float(value)
            except ValueError:
                raise ConfigError(f"CUNHO_{name} must be a number") from None

        return cls(
            issuer_url=need("ISSUER_URL"),
            admin_token=need("ADMIN_TOKEN"),
            signing_key=Path(need("SIGNING_KEY")),
            signing_chain=Path(need("SIGNING_CHAIN")),
            wallet_provider_anchors=path("WALLET_PROVIDER_ANCHORS"),
            lote_path=path("LOTE_PATH"),
            lote_signer=path("LOTE_SIGNER"),
            audit_retention_days=number("AUDIT_RETENTION_DAYS", 0),
            profile=Profile(env.get("CUNHO_PROFILE", Profile.PID_PROVIDER.value)),
            production=flag("PRODUCTION"),
            status_signing_key=path("STATUS_SIGNING_KEY"),
            status_signing_chain=path("STATUS_SIGNING_CHAIN"),
            signer_certificate_url=env.get("CUNHO_SIGNER_CERTIFICATE_URL"),
            metadata_dir=path("METADATA_DIR") or DEFAULT_METADATA_DIR,
            store_path=path("STORE_PATH"),
            store_url=env.get("CUNHO_STORE_URL") or None,
            batch_size=number("BATCH_SIZE", 0) if env.get("CUNHO_BATCH_SIZE") else None,
            dpop_server_nonce=flag("DPOP_SERVER_NONCE"),
            secret_key_file=path("SECRET_KEY_FILE"),
            operators=dict(item.split("=", 1) for item in env.get("CUNHO_OPERATORS", "").split(",") if "=" in item),
            published_configurations=tuple(c for c in env.get("CUNHO_PUBLISHED_CONFIGURATIONS", "").split(",") if c)
            or None,
            display_name=env.get("CUNHO_DISPLAY_NAME") or None,
            rate_limit_per_minute=number("RATE_LIMIT_PER_MINUTE", 120),
            operator_rate_limit_per_minute=number("OPERATOR_RATE_LIMIT_PER_MINUTE", 6000),
            audit_anchor_path=path("AUDIT_ANCHOR_PATH"),
            maintenance_interval=number("MAINTENANCE_INTERVAL", 3600),
            chain_interval=number("CHAIN_INTERVAL", 6 * 3600),
            deferred_ttl=number("DEFERRED_TTL", 7 * 86_400),
            deferred_interval=number("DEFERRED_INTERVAL", 600),
            encryption_keys=tuple(Path(k) for k in env.get("CUNHO_ENCRYPTION_KEYS", "").split(",") if k),
            encryption_required=flag("ENCRYPTION_REQUIRED"),
            pkcs11_module=path("PKCS11_MODULE"),
            pkcs11_pin_file=path("PKCS11_PIN_FILE"),
            chain_attestations=flag("CHAIN_ATTESTATIONS"),
            log_refusals=flag("LOG_REFUSALS"),
            ignore_anonymous_proof_iss=flag("IGNORE_ANONYMOUS_PROOF_ISS"),
            appended_well_known=flag("APPENDED_WELL_KNOWN"),
            accept_bearer_tokens=flag("ACCEPT_BEARER_TOKENS"),
            accept_singular_proof=flag("ACCEPT_SINGULAR_PROOF"),
            chain_revoke_after_days=number("CHAIN_REVOKE_AFTER_DAYS", 0)
            if env.get("CUNHO_CHAIN_REVOKE_AFTER_DAYS")
            else None,
            signing_trust_anchors=path("SIGNING_TRUST_ANCHORS"),
            mdoc_signing_key=path("MDOC_SIGNING_KEY"),
            mdoc_signing_chain=path("MDOC_SIGNING_CHAIN"),
            mdoc_trust_anchors=path("MDOC_TRUST_ANCHORS"),
            mdoc_signer_certificate_url=env.get("CUNHO_MDOC_SIGNER_CERTIFICATE_URL"),
            ka_signer_policy_oids=tuple(o for o in env.get("CUNHO_KA_SIGNER_POLICY_OIDS", "").split(",") if o),
            wallet_provider_crls=path("WALLET_PROVIDER_CRLS"),
            audit_anchor_init=flag("AUDIT_ANCHOR_INIT"),
            store_upgrade=flag("STORE_UPGRADE"),
            conformance_mode=flag("CONFORMANCE_MODE"),
            status_revocation_jitter=number("STATUS_REVOCATION_JITTER", 3600),
            # Every setting DESIGN says the operator chooses can be set (review 4, N4-L5).
            offer_ttl=number("OFFER_TTL", 600),
            access_token_ttl=number("ACCESS_TOKEN_TTL", 300),
            c_nonce_ttl=number("C_NONCE_TTL", 300),
            dpop_iat_window=number("DPOP_IAT_WINDOW", 60),
            proof_iat_window=number("PROOF_IAT_WINDOW", 300),
            tx_code_max_attempts=number("TX_CODE_MAX_ATTEMPTS", 5),
            credential_validity_days=number("CREDENTIAL_VALIDITY_DAYS", 14),
            timestamp_granularity=number("TIMESTAMP_GRANULARITY", 3600),
            status_list_size=number("STATUS_LIST_SIZE", 131_072),
            status_list_fill_limit=fraction("STATUS_LIST_FILL_LIMIT", 0.5),
            status_decoy_ratio=fraction("STATUS_DECOY_RATIO", 0.02),
            status_token_ttl=number("STATUS_TOKEN_TTL", 3600),
            status_token_lifetime=number("STATUS_TOKEN_LIFETIME", 86_400),
            status_decoy_churn_per_day=fraction("STATUS_DECOY_CHURN_PER_DAY", 0.001),
            status_publish_interval=number("STATUS_PUBLISH_INTERVAL", 60),
            status_rate_limit_per_minute=number("STATUS_RATE_LIMIT_PER_MINUTE", 600),
            login_url=env.get("CUNHO_LOGIN_URL") or None,
            test_login_persons=path("TEST_LOGIN_PERSONS"),
            redirect_uris=_redirect_uris(env.get("CUNHO_REDIRECT_URIS")),
            par_ttl=number("PAR_TTL", 60),
            login_ttl=number("LOGIN_TTL", 600),
            code_ttl=number("CODE_TTL", 60),
            client_attestation_pop_window=number("CLIENT_ATTESTATION_POP_WINDOW", 60),
            wia_signer_policy_oids=tuple(o for o in env.get("CUNHO_WIA_SIGNER_POLICY_OIDS", "").split(",") if o),
            wallet_status_anchors=path("WALLET_STATUS_ANCHORS"),
            access_signing_key=path("ACCESS_SIGNING_KEY"),
            access_signing_chain=path("ACCESS_SIGNING_CHAIN"),
            access_trust_anchors=path("ACCESS_TRUST_ANCHORS"),
            signed_metadata_ttl=number("SIGNED_METADATA_TTL", 86_400),
            registration_certificate=path("REGISTRATION_CERTIFICATE"),
            registrar_dataset=path("REGISTRAR_DATASET"),
            preferred_client_status_period=(
                number("PREFERRED_CLIENT_STATUS_PERIOD", 0) if env.get("CUNHO_PREFERRED_CLIENT_STATUS_PERIOD") else None
            ),
            fetch_hosts=tuple(h for h in env["CUNHO_FETCH_HOSTS"].split(",") if h)
            if "CUNHO_FETCH_HOSTS" in env
            else None,
            refresh_token_ttl=number("REFRESH_TOKEN_TTL", 30 * 86_400),
        )


def _redirect_ok(uri: str) -> bool:
    try:
        parts = urlsplit(uri)
        parts.port  # noqa: B018 - raises ValueError on a port that is not a number
    except ValueError:
        return False
    if not parts.scheme or "#" in uri or not (parts.netloc or parts.path):
        return False
    if parts.scheme == "http":
        return parts.hostname in ("127.0.0.1", "::1", "localhost")
    return parts.scheme != "https" or bool(parts.hostname)


def _redirect_uris(text: str | None) -> dict[str, tuple[str, ...]]:
    """CUNHO_REDIRECT_URIS: a JSON object from each wallet solution's sub to its array of redirect URIs."""
    if not text:
        return {}
    try:
        value = json.loads(text)
    except ValueError:
        raise ConfigError("CUNHO_REDIRECT_URIS must be a JSON object of arrays") from None
    if not isinstance(value, dict) or not all(isinstance(v, list) for v in value.values()):
        raise ConfigError("CUNHO_REDIRECT_URIS must be a JSON object of arrays")
    return {str(k): tuple(v) for k, v in value.items()}
