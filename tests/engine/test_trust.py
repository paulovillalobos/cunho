"""Trust in wallet providers wired into the issuer (piece I): with the Commission's list of wallet providers, its
anchors sign wallet and key attestations and status lists, and revocation comes from the network with the
operator's CRL file pooled in; without it, a development run, the PEM files of M2."""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from cunho.errors import ConfigError
from cunho.revocation import FetchedRevocation
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import MemoryStore
from cunho.trust import Trust
from eudi_probe.jose import EcKey

from .helpers import START, Clock, Pki, certificate, crl, pem, refused_by, settings_kwargs, wallet_providers_list
from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner


@pytest.fixture
def signer_files(tmp_path: Path) -> tuple[EcKey, x509.Certificate, Path]:
    """A pinned list signer of its own for tests that write lists, with C=EU and O the scheme operator."""
    from cryptography.x509.oid import NameOID

    from .helpers import SCHEME_OPERATOR

    key = EcKey.generate()
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, SCHEME_OPERATOR),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test LoTE Signer"),
        ]
    )
    cert = certificate("Test LoTE Signer", key.private, name=name)
    path = tmp_path / "lote-signer.pem"
    path.write_bytes(pem(cert))
    return key, cert, path


def lote_settings(
    signer: tuple[EcKey, x509.Certificate, Path], path: Path, pki: Pki, *providers: x509.Certificate
) -> dict[str, Any]:
    """Settings for a list naming `providers`. The test key attestation signer names no distribution point or
    responder, so the operator's CRL file (empty) is what covers it."""
    key, cert, pinned = signer
    path.write_text(wallet_providers_list(key, cert, *providers))
    return {
        "lote_path": path,
        "lote_signer": pinned,
        "wallet_provider_anchors": None,
        "wallet_provider_crls": pki.root / "wallet-providers.crl",
    }


@pytest.mark.obligation("TRUST.WP_ANCHORS_FROM_LIST", "KA.CHAIN_TO_WP_LIST")
def test_with_the_list_a_credential_is_issued_against_its_anchors_and_its_status_lists(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Any],
    pki: Pki,
    tmp_path: Path,
    signer_files: tuple[EcKey, x509.Certificate, Path],
) -> None:
    served = ServedStatus({KA_STATUS_LIST: StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key).token(KA_STATUS_LIST)})
    issuer = make_issuer(**lote_settings(signer_files, tmp_path / "list.lote", pki, pki.wallet_ca), fetcher=served)
    assert issuer.trust.issuance() == [pki.wallet_ca] and issuer.trust.status() == [pki.wallet_ca]
    assert isinstance(issuer.trust.revocation(), FetchedRevocation)
    assert issuer.wallet_status is not None, "status is checked: the list names status list signers"
    issued = wallet_for(issuer).issue()
    assert issued.status_code == 200, issued.text
    assert served.asked == [KA_STATUS_LIST]


def test_a_provider_the_list_drops_is_refused_at_the_next_request(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Any],
    pki: Pki,
    tmp_path: Path,
    signer_files: tuple[EcKey, x509.Certificate, Path],
) -> None:
    """The list is read again when the file changes, so no restart is needed (ARF ISSU_28: only those anchors)."""
    served = ServedStatus({KA_STATUS_LIST: StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key).token(KA_STATUS_LIST)})
    path = tmp_path / "list.lote"
    issuer = make_issuer(**lote_settings(signer_files, path, pki, pki.wallet_ca), fetcher=served)
    wallet = wallet_for(issuer)
    assert wallet.issue().status_code == 200
    other = certificate("Another Wallet Provider", EcKey.generate().private, ca=True)
    key, cert, _ = signer_files
    path.write_text(wallet_providers_list(key, cert, other) + "\n")
    refused_by(wallet.issue, "KA.CHAIN_TO_WP_LIST", "not from a trusted wallet provider")


def test_the_operator_crl_file_is_pooled_with_fetched_revocation(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Any],
    pki: Pki,
    tmp_path: Path,
    signer_files: tuple[EcKey, x509.Certificate, Path],
) -> None:
    """The test key attestation signer names no distribution point or responder, so the operator's file decides."""
    now = dt.datetime.fromtimestamp(START, dt.UTC)
    entry = x509.RevokedCertificateBuilder().serial_number(pki.ka_leaf.serial_number).revocation_date(now).build()
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(pki.wallet_ca.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=30))
        .add_revoked_certificate(entry)
        .sign(pki.wallet_ca_key, hashes.SHA256())
    )
    crls = tmp_path / "wp.crl"
    crls.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    served = ServedStatus({KA_STATUS_LIST: StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key).token(KA_STATUS_LIST)})
    settings = lote_settings(signer_files, tmp_path / "list.lote", pki, pki.wallet_ca)
    issuer = make_issuer(**{**settings, "wallet_provider_crls": crls}, fetcher=served)
    refused_by(wallet_for(issuer).issue, "KA.CHAIN_TO_WP_LIST", "revoked")


def test_before_the_start_nothing_is_trusted_and_a_bad_list_stops_the_start(
    pki: Pki, tmp_path: Path, clock: Clock, signer_files: tuple[EcKey, x509.Certificate, Path]
) -> None:
    from cunho.fetch import Fetcher

    settings = Settings(
        **settings_kwargs(pki, **lote_settings(signer_files, tmp_path / "list.lote", pki, pki.wallet_ca))
    )
    trust = Trust.from_settings(settings, MemoryStore(clock), clock, Fetcher(None))
    assert trust.issuance() == [] and trust.status() == []
    trust.start()
    assert trust.issuance() == [pki.wallet_ca]
    (tmp_path / "list.lote").write_text("garbage")
    late = Trust.from_settings(settings, MemoryStore(clock), clock, Fetcher(None))
    with pytest.raises(ConfigError, match="cannot use the wallet providers list"):
        late.start()


def test_the_list_settings_come_together_and_one_source_of_trust_is_needed(
    pki: Pki, tmp_path: Path, signer_files: tuple[EcKey, x509.Certificate, Path]
) -> None:
    both = lote_settings(signer_files, tmp_path / "list.lote", pki, pki.wallet_ca)
    with pytest.raises(ConfigError, match="set lote_path and lote_signer together"):
        Settings(**settings_kwargs(pki, lote_path=both["lote_path"]))
    with pytest.raises(ConfigError, match="set lote_path and lote_signer together"):
        Settings(**settings_kwargs(pki, lote_signer=both["lote_signer"]))
    with pytest.raises(ConfigError, match="or wallet_provider_anchors in development"):
        Settings(**settings_kwargs(pki, wallet_provider_anchors=None))
    assert Settings(**settings_kwargs(pki, **both)).wallet_provider_anchors is None


def test_the_pinned_list_signer_file_holds_one_certificate(
    make_issuer: Callable[..., Issuer],
    pki: Pki,
    tmp_path: Path,
    signer_files: tuple[EcKey, x509.Certificate, Path],
) -> None:
    settings = lote_settings(signer_files, tmp_path / "list.lote", pki, pki.wallet_ca)
    two = tmp_path / "two.pem"
    two.write_bytes(signer_files[2].read_bytes() + pem(pki.wallet_ca))
    with pytest.raises(ConfigError, match="exactly the one certificate"):
        make_issuer(**{**settings, "lote_signer": two})


def test_the_settings_of_the_list_come_from_the_environment(pki: Pki) -> None:
    env = {
        "CUNHO_ISSUER_URL": "https://issuer.test",
        "CUNHO_ADMIN_TOKEN": "x" * 40,
        "CUNHO_SIGNING_KEY": str(pki.root / "signing.key"),
        "CUNHO_SIGNING_CHAIN": str(pki.root / "signing.pem"),
        "CUNHO_AUDIT_RETENTION_DAYS": "3650",
        "CUNHO_SIGNER_CERTIFICATE_URL": "https://issuer.test/certs/signer.pem",
        "CUNHO_LOTE_PATH": str(pki.root / "wallet-providers.lote"),
        "CUNHO_LOTE_SIGNER": str(pki.root / "lote-signer.pem"),
    }
    settings = Settings.from_env(env)
    assert settings.lote_path == pki.root / "wallet-providers.lote" and settings.wallet_provider_anchors is None


def test_each_service_of_the_list_anchors_its_own_signers(
    make_issuer: Callable[..., Issuer],
    wallet_for: Callable[[Issuer], Any],
    pki: Pki,
    tmp_path: Path,
    signer_files: tuple[EcKey, x509.Certificate, Path],
) -> None:
    """The issuance service's certificates anchor attestation signers, the revocation service's status list signers
    (ETSI TS 119 602 Annex E.3), and neither stands in for the other."""
    status_key = EcKey.generate()
    status_root = certificate("Wallet Provider Status Root", status_key.private, ca=True)
    served = ServedStatus({KA_STATUS_LIST: StatusSigner.under(status_root, status_key.private).token(KA_STATUS_LIST)})
    key, cert, pinned = signer_files
    path = tmp_path / "list.lote"
    path.write_text(wallet_providers_list(key, cert, pki.wallet_ca, status=(status_root,)))
    crls = tmp_path / "both.crl"
    crls.write_bytes((pki.root / "wallet-providers.crl").read_bytes() + crl(status_root, status_key.private))
    issuer = make_issuer(
        lote_path=path, lote_signer=pinned, wallet_provider_anchors=None, wallet_provider_crls=crls, fetcher=served
    )
    assert issuer.trust.issuance() == [pki.wallet_ca] and issuer.trust.status() == [status_root]
    issued = wallet_for(issuer).issue()
    assert issued.status_code == 200, issued.text


def test_the_list_goes_by_the_clock_watchs_time(
    make_issuer: Callable[..., Issuer],
    pki: Pki,
    clock: Clock,
    tmp_path: Path,
    signer_files: tuple[EcKey, x509.Certificate, Path],
) -> None:
    """A wall clock stepped past the list's next update moves nothing the watch decides by: the list is still in
    force (DESIGN.md, time)."""
    from .helpers import Host

    host = Host(clock)
    issuer = host.issuer(make_issuer, None, **lote_settings(signer_files, tmp_path / "list.lote", pki, pki.wallet_ca))
    issuer.sweep()  # the first background tick lays the base
    clock.now += 31 * 86_400
    assert issuer.trust.issuance() == [pki.wallet_ca]
    host.advance(31 * 86_400)
    assert issuer.trust.issuance() == [], "once the time that really passed is past it, the list is not used"


def _renamed_over(path: Path, data: bytes) -> None:
    """`data` written to a new file and renamed over `path` with `path`'s own times, as a file system whose clock
    ticks coarsely gives two writes in one tick."""
    import os

    before = path.stat()
    new = path.with_suffix(".new")
    new.write_bytes(data)
    os.utime(new, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.replace(new, path)
    assert path.stat().st_size == before.st_size and path.stat().st_mtime_ns == before.st_mtime_ns


def test_a_list_renamed_over_the_old_one_is_read_though_its_time_and_size_are_the_same(
    trust_pki: Any, tmp_path: Path, clock: Clock
) -> None:
    from cunho.lote import LoteFile

    from .test_lote import lote, sign

    clock.now = START
    path = tmp_path / "list.lote"
    path.write_bytes(sign(lote(trust_pki, LoTESequenceNumber=1), trust_pki.lote_signer))
    held = LoteFile(path, trust_pki.lote_signer.cert, MemoryStore(clock), clock)
    _renamed_over(path, sign(lote(trust_pki, LoTESequenceNumber=2), trust_pki.lote_signer))
    current = held.current()
    assert current is not None and current.sequence == 2


def test_a_crl_file_renamed_over_the_old_one_is_read_though_its_time_and_size_are_the_same(
    pki: Pki, tmp_path: Path
) -> None:
    from cunho.proofs import CrlFile

    path = tmp_path / "wp.crl"
    first = crl(pki.wallet_ca, pki.wallet_ca_key)
    path.write_bytes(first)
    held = CrlFile(path)
    later = dt.datetime.fromtimestamp(START, dt.UTC)
    second = next(
        data
        for data in (crl(pki.wallet_ca, pki.wallet_ca_key, last_update=later) for _ in range(200))
        if len(data) == len(first)
    )
    _renamed_over(path, second)
    assert [c.last_update_utc for c in held.current()] == [later]


def test_a_crl_file_replaced_while_it_is_read_at_the_start_is_read_again(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file changes during the read at the start: the CRLs in hand must not stand under the new stamp (as for the
    list, the second reviewer)."""
    from cunho import proofs

    path = tmp_path / "wp.crl"
    path.write_bytes(crl(pki.wallet_ca, pki.wallet_ca_key))
    revoking = crl(pki.wallet_ca, pki.wallet_ca_key, [pki.ka_leaf])
    parse = proofs.parse_crls

    def parse_then_replace(data: bytes) -> list[x509.CertificateRevocationList]:
        parsed = parse(data)
        path.write_bytes(revoking)
        return parsed

    monkeypatch.setattr(proofs, "parse_crls", parse_then_replace)
    held = proofs.CrlFile(path)
    monkeypatch.setattr(proofs, "parse_crls", parse)
    assert [len(list(c)) for c in held.current()] == [1]
