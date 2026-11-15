"""Credential configurations and the two metadata documents.

The EC reference configuration files load unchanged. Startup fails on a configuration that breaks a
binder rule; publication strips implementation-internal keys and advertises only what cunho issues.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urlsplit

from cunho.cose import ALGORITHMS as ALGORITHM_VALUES
from cunho.errors import ConfigError
from cunho.jose import ALGORITHMS, strict_json
from cunho.jwe import ALG, ENCS, RequestKeys
from cunho.qualified import (
    CATEGORIES,
    EAA_NAMESPACE,
    ETSI_NAMESPACE,
    MDL_DOCTYPE,
    MDL_NAMESPACE,
    MDL_REQUIRED,
    MDOC_REFUSED,
    SDJWT_REFUSED,
    filled_elements,
)
from cunho.rules import implements
from cunho.settings import Profile, Settings

log = logging.getLogger("cunho.metadata")
SDJWT, MDOC = "dc+sd-jwt", "mso_mdoc"
SUPPORTED_FORMATS = {SDJWT, MDOC}
INTERNAL_KEYS = {
    "issuer_conditions",
    "issuer_config",
    "overall_issuer_conditions",
    "source",
    "selective_disclosure",
    "policy",
    "wallet_solutions",
}
ISO_18045 = {"iso_18045_high", "iso_18045_moderate", "iso_18045_enhanced-basic", "iso_18045_basic"}
PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
PID_VCT = "urn:eudi:pid:1"
PID_FAMILY = "urn:eudi:pid:"  # urn:eudi:pid:1 and national PID types such as urn:eudi:pid:pt:1
PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"  # CIR 2024/2977 Annex §4.1, ARF PID_04
# The PID as mdoc (PID Rulebook v1.7 §3.1, §4.1.1): the SD-JWT VC claim each data element of the PID namespace is
# issued from. The operator sends one PID, in the SD-JWT VC names, for both formats.
PID_NAMESPACE = PID_DOCTYPE  # the PID namespace has the document type's name (ARF PID_05)
PID_MDOC_ELEMENTS = {
    "family_name": "family_name",
    "given_name": "given_name",
    "birthdate": "birth_date",
    "place_of_birth": "place_of_birth",
    "nationalities": "nationality",
    "personal_administrative_number": "personal_administrative_number",
    "picture": "portrait",
    "birth_family_name": "family_name_birth",
    "birth_given_name": "given_name_birth",
    "sex": "sex",
    "email": "email_address",
    "phone_number": "mobile_phone_number",
    "date_of_expiry": "expiry_date",
    "issuing_authority": "issuing_authority",
    "issuing_country": "issuing_country",
    "document_number": "document_number",
    "issuing_jurisdiction": "issuing_jurisdiction",
    "date_of_issuance": "issuance_date",
}
PID_MDOC_ADDRESS = {
    "formatted": "resident_address",
    "country": "resident_country",
    "region": "resident_state",
    "locality": "resident_city",
    "postal_code": "resident_postal_code",
    "street_address": "resident_street",
}
# The rulebook also lists trust_anchor, attestation_legal_category and address.house_number, which the Annex of CIR
# 2024/2977 as replaced by 2026/1731 does not: outside the Annex, an attribute belongs in a domestic namespace (§4.1)
# or type (§4.2), and its resident_street already includes the house number. cunho issues none of the three in the
# PID. The SD-JWT VC claim paths of the PID's base type that are not the Annex's:
SDJWT_OUTSIDE_ANNEX = frozenset({("trust_anchor",), ("attestation_legal_category",), ("address", "house_number")})
PID_MDOC_RULEBOOK = frozenset(PID_MDOC_ELEMENTS.values()) | frozenset(PID_MDOC_ADDRESS.values())
# The value types an mdoc configuration may give a data element; anything else names a structure (a list or map of
# the rulebook's own), which is issued as the JSON the operator sends, converted to CBOR.
MDOC_VALUE_TYPES = frozenset({"string", "full-date", "full_date", "uint", "bool", "jpeg"})


def is_pid(config: dict[str, Any]) -> bool:
    """One test for 'this configuration is a PID', used everywhere (review 2, N-M3): an SD-JWT VC of a PID type, or
    an mdoc of the PID document type."""
    vct = config.get("vct")
    return (isinstance(vct, str) and vct.startswith(PID_FAMILY)) or config.get("doctype") == PID_DOCTYPE


def _strip(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip(v) for k, v in obj.items() if k not in INTERNAL_KEYS}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


TYPE_METADATA_DIR = "type_metadata"
MAX_TYPE_METADATA = 1024 * 1024


@dataclass(frozen=True)
class Configurations:
    all: dict[str, dict[str, Any]]
    batch_size: int | None
    findings: dict[str, str]
    published: frozenset[str]
    signer_alg: str
    # The vct#integrity of each vct with an SD-JWT VC Type Metadata document (load_type_metadata).
    integrity: Mapping[str, str] = field(default_factory=dict)
    mdoc_alg: str | None = None  # the algorithm of the mdoc document signer, when there is one

    def issuable(self) -> dict[str, dict[str, Any]]:
        return {cid: cfg for cid, cfg in self.all.items() if cid in self.published}

    def get(self, config_id: str) -> dict[str, Any] | None:
        return self.issuable().get(config_id)


def load(settings: Settings, signer_alg: str = "ES256", mdoc_alg: str | None = None) -> Configurations:
    """The configurations, checked. `mdoc_alg` is the algorithm of the mdoc document signer, or None without one: an
    mdoc configuration is then never published by default, and publishing one by name is refused."""
    base = json.loads((settings.metadata_dir / "metadata_config.json").read_text())
    configs: dict[str, dict[str, Any]] = {}
    for path in sorted((settings.metadata_dir / "credentials_supported").glob("*.json")):
        for config_id, config in json.loads(path.read_text()).items():
            if config_id in configs:
                raise ConfigError(f"credential configuration {config_id} is defined twice")
            configs[config_id] = config
    file_batch = (base.get("batch_credential_issuance") or {}).get("batch_size")
    batch = settings.batch_size if settings.batch_size is not None else file_batch
    findings: dict[str, str] = {}
    for config_id, config in configs.items():
        try:
            validate(config_id, config, batch)
        except ConfigError as exc:
            if config.get("format") == SDJWT:
                raise
            # Loaded unchanged for compatibility, but never published or issued while it breaks a rule: so are the
            # EC reference mdoc files, of which cunho publishes those that pass.
            findings[config_id] = str(exc)
    usable = {cid for cid, cfg in configs.items() if cfg.get("format") in SUPPORTED_FORMATS and cid not in findings}
    if settings.published_configurations is not None:
        unknown = set(settings.published_configurations) - usable
        if unknown:
            raise ConfigError(f"cannot publish {sorted(unknown)}: unknown, unsupported format, or failing validation")
        published = set(settings.published_configurations)
        unsigned = sorted(c for c in published if configs[c].get("format") == MDOC and mdoc_alg is None)
        if unsigned:
            raise ConfigError(f"cannot publish {unsigned}: mdoc needs a document signer (mdoc_signing_key)")
    else:
        # By default a PID provider publishes PIDs and attestation providers publish attestations; mdoc only with a
        # document signer to sign it.
        pid_provider = settings.profile is Profile.PID_PROVIDER
        published = {
            cid
            for cid in usable
            if is_pid(configs[cid]) == pid_provider and (configs[cid].get("format") != MDOC or mdoc_alg is not None)
        }
        for cid in sorted(published):
            refused = _profile_refuses(configs[cid], settings.profile)
            if refused is not None:
                # Kept out of what is published by default, as a configuration that breaks a rule is; naming it in
                # published_configurations stops the start below.
                findings[cid] = refused
                published.discard(cid)
    for config_id in published:
        if settings.profile is Profile.PID_PROVIDER:
            # A PID provider issues nothing that is not bound to a WSCD key (CIR 2024/2977 Art. 3(5)).
            try:
                _require_device_binding(configs[config_id])
            except ConfigError as exc:
                raise ConfigError(f"{config_id}: {exc}") from exc
        algs = configs[config_id].get("credential_signing_alg_values_supported")
        if configs[config_id].get("format") == MDOC:
            # OpenID4VCI 1.0 App. A.2.2: for mso_mdoc these are COSE algorithm values.
            assert mdoc_alg is not None
            if algs is not None and ALGORITHM_VALUES[mdoc_alg] not in algs:
                raise ConfigError(f"{config_id}: the document signer ({mdoc_alg}) is not in {algs}")
        elif algs is not None and signer_alg not in algs:
            raise ConfigError(f"{config_id}: the signing key ({signer_alg}) is not in {algs}")
        refused = _profile_refuses(configs[config_id], settings.profile)
        if refused is not None:
            raise ConfigError(f"{config_id}: {refused}")
        if configs[config_id].get("format") == MDOC and not is_pid(configs[config_id]):
            configs[config_id] = _with_filled(configs[config_id], settings.profile)
    for config_id in sorted(published):
        outside = ["/".join(map(str, path)) for path in _outside_annex(configs[config_id])]
        if outside:
            log.warning(
                "%s lists %s in the PID's base type or namespace, which the Annex of CIR 2024/2977 does not define; "
                "cunho neither publishes nor issues them (Annex §4.1, §4.2; ARF PID_06)",
                config_id,
                outside,
            )
    if settings.production and settings.profile is Profile.PID_PROVIDER:
        formats = {configs[c].get("format") for c in published if is_pid(configs[c])}
        if not {SDJWT, MDOC} <= formats:
            raise ConfigError(
                "a PID provider issues the PID in both formats: publish an SD-JWT VC PID and an mdoc PID (ARF PID_02, "
                "ISSU_12; CIR 2024/2977 Annex §4), which needs mdoc_signing_key"
            )
    integrity = load_type_metadata(settings.metadata_dir / TYPE_METADATA_DIR)
    if settings.production:
        untyped = sorted(missing_type_metadata(configs, published, integrity))
        if untyped:
            raise ConfigError(
                f"production needs the SD-JWT VC Type Metadata of {untyped} in {TYPE_METADATA_DIR}/: every credential "
                "carries vct#integrity (ETSI TS 119 472-1 EAA-5.2.1.2-03)"
            )
    return Configurations(configs, batch, findings, frozenset(published), signer_alg, integrity, mdoc_alg)


def missing_type_metadata(configs: dict[str, dict[str, Any]], published: Any, integrity: Mapping[str, str]) -> set[str]:
    """The vct of each published SD-JWT VC configuration that has no Type Metadata document."""
    return {
        str(configs[c].get("vct"))
        for c in published
        if configs[c].get("format") == SDJWT and configs[c].get("vct") not in integrity
    }


def load_type_metadata(folder: Path) -> dict[str, str]:
    """vct#integrity for each SD-JWT VC Type Metadata document in `folder` (SD-JWT VC §6, §7; ETSI TS 119 472-1
    EAA-5.2.1.2-02, -03): the W3C SRI digest, sha256- and the base64 of the SHA-256 of the document's bytes as they are,
    which are the bytes the vct leads a wallet to. Each document names its vct; the operator publishes it where the
    vct points. Raises ConfigError."""
    integrity: dict[str, str] = {}
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        data = path.read_bytes()
        if len(data) > MAX_TYPE_METADATA:
            raise ConfigError(f"type metadata {path.name} is larger than {MAX_TYPE_METADATA} bytes")
        try:
            document = strict_json(data)
        except ValueError:
            raise ConfigError(f"type metadata {path.name} is not JSON") from None
        vct = document.get("vct") if isinstance(document, dict) else None
        if not isinstance(vct, str) or not vct:
            raise ConfigError(f"type metadata {path.name} names no vct (SD-JWT VC §6.2)")
        if vct in integrity:
            raise ConfigError(f"two type metadata documents for {vct}")
        integrity[vct] = "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return integrity


def _claim_paths(config: dict[str, Any]) -> list[list[Any]]:
    claims = (config.get("credential_metadata") or {}).get("claims") or config.get("claims") or []
    return [c["path"] for c in claims if isinstance(c, dict) and isinstance(c.get("path"), list) and c["path"]]


REUSE_POLICY_ID = "arf_annex_ii"
ONCE_ONLY = frozenset({"once_only"})
LIMITED_TIME = frozenset({"limited_time", "limited-time"})
REUSE_METHODS = ONCE_ONLY | LIMITED_TIME | {"rotating-batch", "per-relying-party"}
REGISTRAR_MEMBERS = ("identifier", "srvDescription", "registryURI", "providesAttestations")


def _reuse_options(config: dict[str, Any]) -> list[dict[str, Any]]:
    policy = (config.get("credential_metadata") or {}).get("credential_reuse_policy")
    if not isinstance(policy, dict) or not isinstance(policy.get("options"), list) or not policy["options"]:
        return []
    return [o for o in policy["options"] if isinstance(o, dict)]


@implements(
    "VCI.META.SCOPE_PER_CONFIG",
    "META.PROOF_TYPES_JWT_AND_ATTESTATION",
    "META.KEY_STORAGE_LEVELS",
    "META.NO_KA_FOR_UNBOUND",
    "META.REUSE_POLICY.PRESENT_ORDERED",
    "META.REUSE_POLICY.METHOD_A_PARAMS",
    "META.REUSE_POLICY.REISSUE_TRIGGER_UNUSED",
    "META.REUSE_POLICY.A_OR_B",
    "META.REUSE_POLICY.CONFORMANCE_472_3",
    "META.REUSE_POLICY.METHOD_B_TRIGGER",
    "META.REUSE_POLICY.METHOD_C_PARAMS",
    "FMT.SDJWT.VCT_REQUIRED",
    "KA.PID_KEY_IN_WSCD",
)
def validate(config_id: str, config: dict[str, Any], issuer_batch: int | None) -> None:
    """Startup check of one configuration against the metadata rows of the binder."""

    def fail(reason: str) -> NoReturn:
        raise ConfigError(f"{config_id}: {reason}")

    if not config.get("scope"):
        fail("no scope (HAIP 1.0 §4.1)")
    if config.get("format") == SDJWT and not config.get("vct"):
        fail("dc+sd-jwt configuration without vct (OpenID4VCI A.3.2)")
    if config.get("format") == MDOC:
        _check_mdoc(config, fail)
    _check_wallet_solutions(config.get("wallet_solutions"), fail)
    bound = bool(config.get("cryptographic_binding_methods_supported"))
    proofs = config.get("proof_types_supported") or {}
    if not isinstance(proofs, dict):
        fail("proof_types_supported must be an object (OpenID4VCI §12.2.4)")
    if bound != bool(proofs):
        fail("proof_types_supported must be present exactly when key binding is (OpenID4VCI §12.2.4)")
    if is_pid(config):
        try:
            _require_device_binding(config)
        except ConfigError as exc:
            fail(str(exc))
    for proof_type, spec in proofs.items():
        if not isinstance(spec, dict):
            fail(f"the {proof_type} proof type must be an object")
        algs = spec.get("proof_signing_alg_values_supported")
        if not isinstance(algs, list) or not algs or not set(map(str, algs)) <= ALGORITHMS:
            fail(f"{proof_type} proof algorithms must be a non-empty subset of {sorted(ALGORITHMS)}")
        required = spec.get("key_attestations_required", {})
        if not isinstance(required, dict):
            fail("key_attestations_required must be an object when present (OpenID4VCI §12.2.4)")
        for member in ("key_storage", "user_authentication"):
            levels = required.get(member, [])
            if not isinstance(levels, list) or not set(map(str, levels)) <= ISO_18045:
                fail(f"{member} values must come from ISO/IEC 18045 (OpenID4VCI App. D.2)")
        period = required.get("preferred_key_storage_status_period")
        if period is not None and (not isinstance(period, int) or isinstance(period, bool) or period <= 0):
            fail("preferred_key_storage_status_period must be a positive number of seconds")
    _check_reuse_policy(config, issuer_batch, fail)


def _names(claim: Any, paths: set[tuple[Any, ...]]) -> bool:
    path = claim.get("path") if isinstance(claim, dict) else None
    return isinstance(path, list) and tuple(path) in paths


def _outside_annex(config: dict[str, Any]) -> list[tuple[Any, ...]]:
    """The claim paths a PID configuration lists in the PID's base type or namespace that the Annex of CIR 2024/2977
    does not define: they are neither published nor issued (Annex §4.1, §4.2; ARF PID_06)."""
    if not is_pid(config):
        return []
    paths = [tuple(path) for path in _claim_paths(config)]
    if config.get("format") == MDOC:
        return sorted(p for p in paths if len(p) == 2 and p[0] == PID_NAMESPACE and p[1] not in PID_MDOC_RULEBOOK)
    return sorted(p for p in paths if p in SDJWT_OUTSIDE_ANNEX)


@implements("FMT.MDOC.CONFIG_AND_ENCODING")
def _check_mdoc(config: dict[str, Any], fail: Callable[[str], NoReturn]) -> None:
    """An mso_mdoc configuration names its document type (OpenID4VCI 1.0 App. A.2.2), is bound to a COSE key, since
    every MSO carries the holder's device key (ETSI TS 119 472-1 EAA-6.5-01), names its data elements by namespace
    and identifier, and lists COSE algorithm values."""
    doctype = config.get("doctype")
    if not isinstance(doctype, str) or not doctype:
        fail("mso_mdoc configuration without doctype (OpenID4VCI A.2.2)")
    methods = config.get("cryptographic_binding_methods_supported")
    if not isinstance(methods, list) or "cose_key" not in methods:
        fail("an mdoc carries the holder's device key: cryptographic_binding_methods_supported needs cose_key")
    algs = config.get("credential_signing_alg_values_supported")
    if algs is not None and (not isinstance(algs, list) or not all(_whole(a, -(2**31)) for a in algs)):
        fail("credential_signing_alg_values_supported of an mdoc are COSE algorithm values (OpenID4VCI A.2.2)")
    seen: set[tuple[str, str]] = set()
    claims = (config.get("credential_metadata") or {}).get("claims") or config.get("claims") or []
    if not isinstance(claims, list) or not claims:
        fail("an mdoc configuration lists its data elements in claims")
    for claim in claims:
        if isinstance(claim, dict) and claim and set(claim) <= INTERNAL_KEYS:
            continue  # an EC-internal entry such as overall_issuer_conditions, never published
        path = claim.get("path") if isinstance(claim, dict) else None
        if not isinstance(path, list) or len(path) != 2 or not all(isinstance(p, str) and p for p in path):
            fail(f"an mdoc claim path is [namespace, data element identifier], not {path!r} (OpenID4VCI App. B.2)")
        if (path[0], path[1]) in seen:
            fail(f"{path[0]}/{path[1]} is listed twice")
        seen.add((path[0], path[1]))
        kind = claim.get("value_type")
        if kind is not None and not isinstance(kind, str):
            fail(f"{path[0]}/{path[1]}: value_type must be a string")
        if is_pid(config) and path[0] != PID_NAMESPACE:
            # ARF PID_06, PID_07: a domestic namespace needs its published scheme and data for it, which cunho does
            # not take yet; the PID's own elements live in the PID namespace (ARF PID_05).
            fail(f"{path[0]}/{path[1]}: cunho issues the PID's elements in {PID_NAMESPACE} only, no domestic namespace")
    if is_pid(config) and doctype != PID_DOCTYPE:
        fail(f"the mdoc PID's document type is {PID_DOCTYPE} (ARF PID_04)")
    if not is_pid(config):
        _check_mdoc_eaa(doctype, seen, fail)


@implements("FMT.ETSI_119472_1")
def _check_mdoc_eaa(doctype: str, listed: set[tuple[str, str]], fail: Callable[[str], NoReturn]) -> None:
    """ETSI TS 119 472-1 clause 6: an mDL lists the issuing authority, document number and issue date of ISO/IEC
    18013-5; any other mdoc attestation gets them from cunho in the ISO/IEC 23220-2 namespace, with the category of a
    qualified or public-body attestation, so its configuration lists none of them."""
    if doctype == MDL_DOCTYPE:
        missing = [name for name in MDL_REQUIRED if (MDL_NAMESPACE, name) not in listed]
        if missing:
            fail(f"an mDL lists {', '.join(missing)} in {MDL_NAMESPACE} (ETSI TS 119 472-1 EAA-6.2.3-03, -6.2.4.1-01)")
        return
    for ns, name in sorted(listed):
        if ns == EAA_NAMESPACE and name in ("issuing_authority_unicode", "document_number", "issue_date"):
            fail(f"{ns}/{name}: cunho fills it in for every mdoc attestation (ETSI TS 119 472-1 clause 6.2)")
        if ns == ETSI_NAMESPACE and name == "category":
            fail(f"{ns}/{name}: cunho fills it in for a qualified or public-body attestation (EAA-6.2.2)")


@implements("QEAA.ISSUER_IDENTITY", "QEAA.SUBJECT_OR_PSEUDONYM")
def _profile_refuses(config: dict[str, Any], profile: Profile) -> str | None:
    """Why a qualified or public-body provider may not issue this configuration, or None. Its SD-JWT VC names the
    provider by its qualified certificate alone and refers every attribute to its subject; cunho gives it its category
    and identity code (ETSI TS 119 472-1 clauses 5.2.2 to 5.2.5); its mdoc names no registration number of its own."""
    if profile not in CATEGORIES:
        return None
    paths = [tuple(path) for path in _claim_paths(config)]
    if config.get("format") == MDOC:
        reasons = [
            f"{ns}/{name}: {MDOC_REFUSED[(ns, name)]}"
            for ns, name in (p[:2] for p in paths if len(p) >= 2)
            if (ns, name) in MDOC_REFUSED
        ]
    else:
        reasons = [f"{path[0]}: {SDJWT_REFUSED[str(path[0])]}" for path in paths if str(path[0]) in SDJWT_REFUSED]
    return "; ".join(sorted(set(reasons))) or None


def _with_filled(config: dict[str, Any], profile: Profile) -> dict[str, Any]:
    """The configuration with the data elements cunho fills in listed among its claims, so that wallets see them in
    the metadata and the subject check knows them."""
    filled = filled_elements(config, profile)
    if not filled:
        return config
    out = copy.deepcopy(config)
    holder = out["credential_metadata"] if "claims" in (out.get("credential_metadata") or {}) else out
    holder["claims"] = [*holder["claims"], *filled]
    return out


def _check_wallet_solutions(solutions: Any, fail: Callable[[str], NoReturn]) -> None:
    """The wallet solutions a configuration is issued to alone, when it names any (ARF SUA_03): a non-empty list of
    objects, each with a wallet_name as the list of wallet providers gives it and, optionally, the versions allowed."""
    if solutions is None:
        return
    if not isinstance(solutions, list) or not solutions:
        fail("wallet_solutions must be a non-empty list (ARF SUA_03)")
    for entry in solutions:
        if not isinstance(entry, dict) or set(entry) - {"wallet_name", "wallet_versions"}:
            fail("each of wallet_solutions is an object of wallet_name and, optionally, wallet_versions")
        name, versions = entry.get("wallet_name"), entry.get("wallet_versions")
        if not isinstance(name, str) or not name:
            fail("each of wallet_solutions needs a wallet_name, as the list of wallet providers gives it")
        if "wallet_versions" in entry and (
            not isinstance(versions, list) or not versions or not all(isinstance(v, str) and v for v in versions)
        ):
            fail("wallet_versions must be a non-empty list of version strings")


def _whole(value: Any, least: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= least


def _check_reuse_policy(config: dict[str, Any], issuer_batch: int | None, fail: Callable[[str], NoReturn]) -> None:
    """credential_reuse_policy as ETSI TS 119 472-3 V1.1.1 §4.2.4 encodes ARF Annex II (ISSU_37 to ISSU_57).

    cunho publishes one and only the ARF policy (`arf_annex_ii`), since that is how method A or B is indicated
    (ISSU_40). Each option names method A (`once_only`) or B (`limited_time`), and may add C (`rotating-batch`) and
    per relying party, in the order the wallet should prefer them. A, C and per relying party give the batch size,
    2 or more; A gives the reissue trigger on unused credentials, below the batch size; B, C and per relying party
    give the reissue trigger on lifetime left, in seconds. §4.2.4.2-03 spells B `limited_time` and §4.2.4.2-12
    `limited-time`; both are accepted, as the same method.
    """
    policy = (config.get("credential_metadata") or {}).get("credential_reuse_policy")
    if not isinstance(policy, dict):
        fail("no credential_reuse_policy object (ARF ISSU_39, TS 119 472-3 §4.2.4.1)")
    if policy.get("id") != REUSE_POLICY_ID:
        fail(f"credential_reuse_policy id must be {REUSE_POLICY_ID!r}, the ARF policy (ARF ISSU_40)")
    options = policy.get("options")
    if not isinstance(options, list) or not options:
        fail("credential_reuse_policy needs options (TS 119 472-3 §4.2.4.2-01)")
    for option in options:
        if not isinstance(option, dict):
            fail("each credential_reuse_policy option must be an object (TS 119 472-3 §4.2.4.1-07)")
        details = option.get("details")
        if not isinstance(details, list) or not details or not all(isinstance(d, str) for d in details):
            fail("each reuse option needs details, an array of strings (TS 119 472-3 §4.2.4.2-02)")
        methods = ["limited_time" if d == "limited-time" else d for d in details]  # one method, two spellings
        if any(d not in REUSE_METHODS for d in details) or len(set(methods)) != len(methods):
            fail(f"reuse option details must be distinct values of {sorted(REUSE_METHODS)}")
        named = set(details)
        if bool(named & ONCE_ONLY) + bool(named & LIMITED_TIME) != 1:
            fail("a reuse option must name method A (once_only) or method B (limited_time), one of them (ARF ISSU_40)")
        size: Any = option.get("batch_size")
        if named & (ONCE_ONLY | {"rotating-batch", "per-relying-party"}):
            if not _whole(size, 2):
                fail("methods A and C and per relying party need a batch_size of 2 or more (TS 119 472-3 §4.2.4.2-08)")
            if issuer_batch is not None and size > issuer_batch:
                fail(f"reuse policy batch_size {size} exceeds the issuer batch_size {issuer_batch}")
        if named & ONCE_ONLY:
            unused: Any = option.get("reissue_trigger_unused")
            if not _whole(unused, 0) or unused >= size:
                fail("method A (once_only) needs reissue_trigger_unused below batch_size (ARF ISSU_45, §4.2.4.2-11)")
        if set(details) & (LIMITED_TIME | {"rotating-batch", "per-relying-party"}):
            if not _whole(option.get("reissue_trigger_lifetime_left"), 1):
                fail(
                    "methods B and C need reissue_trigger_lifetime_left in seconds (ARF ISSU_50, ISSU_54, §4.2.4.2-12)"
                )


def batch_limit(config: dict[str, Any], issuer_batch: int | None) -> int:
    """Proofs accepted in one request: the issuer batch_size, and no more than the reuse policy advertises."""
    limit = issuer_batch or 1
    sizes = [o["batch_size"] for o in _reuse_options(config) if isinstance(o.get("batch_size"), int)]
    return min(limit, max(sizes)) if sizes else limit


def _require_device_binding(config: dict[str, Any]) -> None:
    """Key binding, with a key attestation that states key_storage for every proof type (ARF ISSU_17)."""
    proofs = config.get("proof_types_supported")
    if not config.get("cryptographic_binding_methods_supported") or not isinstance(proofs, dict) or not proofs:
        raise ConfigError(
            "a PID must be bound to a key in the wallet's WSCD: cryptographic_binding_methods_supported and "
            "proof_types_supported are required (CIR 2024/2977 Art. 3(5), ARF ISSU_17)"
        )
    for proof_type, spec in proofs.items():
        required = spec.get("key_attestations_required") if isinstance(spec, dict) else None
        if not isinstance(required, dict) or not required.get("key_storage"):
            raise ConfigError(f"a PID must require a key attestation with key_storage for {proof_type} proofs")


@implements("CRYPTO.ES256_384_512")
def published_config(config: dict[str, Any], signer_alg: str, mdoc_alg: str | None = None) -> dict[str, Any]:
    """What wallets see: no internal keys, no PID claim outside the Annex, both proof types, every algorithm cunho
    verifies."""
    published = _strip(copy.deepcopy(config))
    outside = set(_outside_annex(config))
    holder = published.get("credential_metadata") if "claims" in published.get("credential_metadata", {}) else published
    if outside and isinstance(holder.get("claims"), list):
        holder["claims"] = [c for c in holder["claims"] if not _names(c, outside)]
    proofs = published.get("proof_types_supported")
    if proofs and "jwt" in proofs and "attestation" not in proofs and "key_attestations_required" in proofs["jwt"]:
        # ARF WUA_10/ISSU_27d: device-bound configurations advertise both proof types. An attestation proof is a key
        # attestation, so it is offered only where one is required; without key_attestations_required wallets built
        # on the EU reference library refuse the whole metadata.
        proofs["attestation"] = copy.deepcopy(proofs["jwt"])
    for spec in (proofs or {}).values():
        # CIR 2024/2979 Annex Ib SA-3: ES256, ES384 and ES512 are all supported for proofs.
        spec["proof_signing_alg_values_supported"] = sorted(ALGORITHMS)
    if published.get("format") == SDJWT and published.get("cryptographic_binding_methods_supported"):
        published["cryptographic_binding_methods_supported"] = ["jwk"]
    if published.get("format") == MDOC:
        # OpenID4VCI 1.0 App. A.2.2: an mdoc is bound to a COSE key and signed with a COSE algorithm.
        published["cryptographic_binding_methods_supported"] = ["cose_key"]
        if "credential_signing_alg_values_supported" in published and mdoc_alg is not None:
            published["credential_signing_alg_values_supported"] = [ALGORITHM_VALUES[mdoc_alg]]
    elif "credential_signing_alg_values_supported" in published:
        published["credential_signing_alg_values_supported"] = [signer_alg]
    return published


@implements(
    "VCI.META.FIELDS",
    "VCI.META.NONCE_ENDPOINT_WHEN_BINDING",
    "VCI.META.WELL_KNOWN_PATH",
    "META.PREFERRED_STATUS_PERIODS",
)
@implements(
    "META.PREFERRED_STATUS_PERIODS",
    "META.PREFERRED_CLIENT_STATUS_PERIOD",
    "META.EDP_BY_VALUE",
    "VCI.ENC.REQUEST",
    "VCI.ENC.RESPONSE",
)
def issuer_metadata(
    settings: Settings,
    configs: Configurations,
    info: list[dict[str, Any]] | None = None,
    request_keys: RequestKeys | None = None,
) -> dict[str, Any]:
    """The issuer metadata. Each configuration's `key_attestations_required` is published as configured, with
    its `preferred_key_storage_status_period`, and the wallet instance attestation's period is
    `preferred_client_status_period` at the top, which is how cunho tells wallets the status periods it prefers
    (ARF WUA_32, CIR 2024/2979 Annex Ib LC_KA-1, LC_WIA-1, TS3 v1.5.2 §2.4). `info` is issuer_info (TS 119 472-3
    §4.2.3). No embedded disclosure policy is published: none is configured, and no metadata member for one is
    standardised yet (TS 119 472-3 V1.1.1 §4.2.5 gives only its data model), so the rule's "if any" holds. With
    request keys, both encryption blocks (OpenID4VCI 1.0 §12.2.4): a wallet that asks for an encrypted response must
    encrypt its request (§8.2), so cunho offers the one only with the other. No zip_values_supported: no
    compression."""
    published = {
        cid: published_config(cfg, configs.signer_alg, configs.mdoc_alg) for cid, cfg in configs.issuable().items()
    }
    document: dict[str, Any] = {
        "credential_issuer": settings.issuer_url,
        "credential_endpoint": settings.credential_endpoint,
        "deferred_credential_endpoint": settings.deferred_credential_endpoint,
        "notification_endpoint": settings.notification_endpoint,
        "credential_configurations_supported": published,
    }
    if any(cfg.get("cryptographic_binding_methods_supported") for cfg in published.values()):
        document["nonce_endpoint"] = settings.nonce_endpoint
    if configs.batch_size is not None and configs.batch_size >= 2:
        document["batch_credential_issuance"] = {"batch_size": configs.batch_size}
    if settings.display_name:
        document["display"] = [{"name": settings.display_name}]
    if settings.preferred_client_status_period is not None:
        document["preferred_client_status_period"] = settings.preferred_client_status_period
    if info is not None:
        document["issuer_info"] = info
    if request_keys is not None:
        encs = sorted(ENCS)
        document["credential_request_encryption"] = {
            "jwks": request_keys.jwks(),
            "enc_values_supported": encs,
            "encryption_required": request_keys.required,
        }
        document["credential_response_encryption"] = {
            "alg_values_supported": [ALG],
            "enc_values_supported": encs,
            "encryption_required": request_keys.required,
        }
    return document


@implements("META.REGCERT_BY_VALUE")
def issuer_info(registration_certificate: Any, registrar_dataset: Any) -> list[dict[str, Any]]:
    """issuer_info as TS 119 472-3 §4.2.3 asks, in the shape of OpenID4VP §5.1 verifier_info: the registration
    certificate by value (format registration_cert) and the registrar dataset (format registrar_dataset) with
    identifier, srvDescription, registryURI and providesAttestations. Raises ConfigError."""
    if not isinstance(registration_certificate, str) or not registration_certificate.strip():
        raise ConfigError("the registration certificate is empty")
    certificate = registration_certificate.strip()
    if not certificate.isascii() or not certificate.isprintable() or len(certificate) > 64 * 1024:
        raise ConfigError("the registration certificate must be printable ASCII of at most 64 KiB, as issued")
    if not isinstance(registrar_dataset, dict) or not registrar_dataset:
        raise ConfigError("the registrar dataset must be a non-empty JSON object (TS 119 472-3 §4.2.3-09)")
    missing = [m for m in REGISTRAR_MEMBERS if m not in registrar_dataset]
    if missing:
        raise ConfigError(f"the registrar dataset lacks {', '.join(missing)} (TS 119 472-3 §4.2.3-10 to -13)")
    identifier, described = registrar_dataset["identifier"], registrar_dataset["srvDescription"]
    registry, provides = registrar_dataset["registryURI"], registrar_dataset["providesAttestations"]
    if not isinstance(identifier, str) or not identifier:
        raise ConfigError("the registrar dataset identifier must be a non-empty string")
    if not isinstance(described, list) or not described or not all(isinstance(d, dict) and d for d in described):
        raise ConfigError("the registrar dataset srvDescription must be a non-empty array of multilingual strings")
    if not isinstance(registry, str) or not registry.startswith("https://"):
        raise ConfigError("the registrar dataset registryURI must be an https URI")
    if not isinstance(provides, list) or not provides:
        raise ConfigError("the registrar dataset providesAttestations must be a non-empty array")
    return [
        {"format": "registration_cert", "data": certificate},
        {"format": "registrar_dataset", "data": registrar_dataset},
    ]


# The fields another part of cunho adds to the authorization server metadata, such as the endpoints of the
# authorization code flow: given the settings, a hook returns the fields it sets.
AsMetadataHook = Callable[[Settings], Mapping[str, Any]]


@implements("OAUTH.AS_METADATA", "OAUTH.DPOP_REQUIRED")
def authorization_server_metadata(settings: Settings, hooks: Sequence[AsMetadataHook] = ()) -> dict[str, Any]:
    """The authorization server metadata (RFC 8414 §2), with the fields of each hook on top. A hook may add a
    field or replace one set here, but never the issuer identifier, and no two hooks set the same field."""
    document: dict[str, Any] = {
        "issuer": settings.issuer_url,
        "token_endpoint": settings.token_endpoint,
        "grant_types_supported": [PRE_AUTH_GRANT],
        "response_types_supported": [],
        "pre-authorized_grant_anonymous_access_supported": True,
        "token_endpoint_auth_methods_supported": ["none"],
        "dpop_signing_alg_values_supported": sorted(ALGORITHMS),
    }
    added: set[str] = set()
    for hook in hooks:
        for name, value in hook(settings).items():
            if name == "issuer":
                raise ConfigError("an authorization server metadata hook cannot set the issuer identifier")
            if name in added:
                raise ConfigError(f"two authorization server metadata hooks set {name}")
            added.add(name)
            document[name] = copy.deepcopy(value)
    return document


def well_known_path(settings: Settings, suffix: str) -> str:
    """OpenID4VCI §12.2.2 / RFC 8414 §3: insert the well-known segment before the issuer path."""
    return f"/.well-known/{suffix}{urlsplit(settings.issuer_url).path}"


def base_path(settings: Settings) -> str:
    return urlsplit(settings.issuer_url).path
