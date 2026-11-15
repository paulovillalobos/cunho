"""Where trust in wallet providers comes from: the anchors of each purpose and the revocation of the certificates under
them (TRUST.WP_ANCHORS_FROM_LIST, KA.CHAIN_TO_WP_LIST, WIA.CHAIN_TO_WP_LIST).

With the Commission's list of wallet providers configured (`lote_path` and its pinned `lote_signer`; production must),
the anchors are its WalletSolution/Issuance services' for wallet and key attestation signers and its
WalletSolution/Revocation services' for the signers of wallet providers' status lists (ETSI TS 119 602 Annex E), and
revocation comes from CRL distribution points and OCSP, with the operator's CRL file pooled in. Without the list, a
development run, they come from the operator's PEM files and CRL file as in M2.

Every call answers for now: a list the operator replaced is in force at the next request, and one that cannot be used
leaves no anchors, so trust fails closed.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass

from cryptography import x509

from cunho.errors import ConfigError
from cunho.fetch import Fetcher
from cunho.jose import CrlSet, Revocation
from cunho.lote import LoteFile
from cunho.proofs import CrlFile, load_anchors
from cunho.revocation import FetchedRevocation
from cunho.settings import Settings
from cunho.store import Store


@dataclass(frozen=True)
class _FileRevocation:
    """The operator's CRL file, read again whenever it changes (M2)."""

    crls: CrlFile

    def check(self, cert: x509.Certificate, issuer: x509.Certificate, now: dt.datetime, role: str) -> None:
        CrlSet(self.crls.current()).check(cert, issuer, now, role)


class Trust:
    def __init__(
        self,
        issuance: Callable[[], list[x509.Certificate]],
        status: Callable[[], list[x509.Certificate]] | None,
        revocation: Revocation | None,
        start: Callable[[], None] | None = None,
    ) -> None:
        self._issuance = issuance
        self._status = status
        self._revocation = revocation
        self._start = start

    @classmethod
    def from_settings(cls, settings: Settings, store: Store, clock: Callable[[], float], fetcher: Fetcher) -> Trust:
        crls = CrlFile(settings.wallet_provider_crls) if settings.wallet_provider_crls is not None else None
        if settings.lote_path is not None and settings.lote_signer is not None:
            signer = load_anchors(settings.lote_signer)
            if len(signer) != 1:
                raise ConfigError("lote_signer must hold exactly the one certificate that signs the list")
            path, pinned = settings.lote_path, signer[0]
            held: list[LoteFile] = []

            def start() -> None:
                held.append(LoteFile(path, pinned, store, clock))

            def issuance() -> list[x509.Certificate]:
                current = held[0].current() if held else None
                return current.issuance if current is not None else []

            def status() -> list[x509.Certificate]:
                current = held[0].current() if held else None
                return current.revocation if current is not None else []

            return cls(issuance, status, FetchedRevocation(fetcher, crls), start)
        assert settings.wallet_provider_anchors is not None  # Settings refuses a run with neither source of trust
        anchors = load_anchors(settings.wallet_provider_anchors)
        status_anchors = load_anchors(settings.wallet_status_anchors) if settings.wallet_status_anchors else None
        return cls(
            lambda: anchors,
            (lambda: status_anchors) if status_anchors is not None else None,
            _FileRevocation(crls) if crls is not None else None,
        )

    @classmethod
    def fixed(
        cls,
        issuance: list[x509.Certificate] | None = None,
        status: list[x509.Certificate] | None = None,
        crls: CrlFile | None = None,
    ) -> Trust:
        """Anchors given outright, for tests and tools."""
        held = list(issuance or [])
        return cls(
            lambda: held,
            (lambda: list(status)) if status is not None else None,
            _FileRevocation(crls) if crls is not None else None,
        )

    def start(self) -> None:
        """Read the list of wallet providers, once the store is ready: it records the highest sequence number seen, so
        it must not write a new store before its schema version is laid (cunho.service). A list that cannot be used
        stops the start (ConfigError). Before it, there are no anchors."""
        if self._start is not None:
            self._start()

    def issuance(self) -> list[x509.Certificate]:
        """The anchors of wallet and key attestation signers, now."""
        return self._issuance()

    def checks_status(self) -> bool:
        """Whether there are anchors for wallet providers' status lists at all, so that status is checked."""
        return self._status is not None

    def status(self) -> list[x509.Certificate]:
        """The anchors of the signers of wallet providers' status lists, now."""
        return self._status() if self._status is not None else []

    def revocation(self) -> Revocation | None:
        """The source of revocation status for paths to these anchors; None leaves it unchecked (development)."""
        return self._revocation
