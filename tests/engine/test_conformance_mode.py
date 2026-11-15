"""The conformance setting (tools/oidf): a suite that tests HAIP alone sends wallet attestations without the
client_status TS3 asks for. In a conformance run cunho takes them, checks no status for them and caps nothing by
them; anywhere else it refuses them, and production refuses the setting."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho.errors import ConfigError
from cunho.service import Issuer
from cunho.settings import Settings

from .codewallet import LOGIN, CodeWallet, Pkce, pid_scope
from .helpers import Pki, production_kwargs, refused_by


def without_status(wallet: CodeWallet) -> CodeWallet:
    real = wallet.attestation

    def attestation(**claims: Any) -> str:
        return real(**{"client_status": ..., **claims})

    wallet.attestation = attestation  # type: ignore[method-assign]
    return wallet


def test_a_wallet_attestation_without_client_status_is_refused_outside_a_conformance_run(
    code_issuer: Issuer, code_wallet: CodeWallet
) -> None:
    refused_by(lambda: without_status(code_wallet).par(Pkce.random()), "WIA.CLIENT_STATUS", "needs client_status")


def test_a_conformance_run_takes_it_and_caps_nothing_by_it(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    issuer = make_code_issuer(conformance_mode=True)
    wallet = without_status(code_wallet_for(issuer))
    wallet.get_code_token(LOGIN, scope=pid_scope(issuer))
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text
    full = make_code_issuer()
    with_status = code_wallet_for(full)
    with_status.client_status_offset = 3 * 86_400  # shorter than the credential validity, so it would cap
    with_status.get_code_token(LOGIN, scope=pid_scope(full))
    capped = with_status.issue()
    from .helpers import disclosures

    exp = disclosures(issued.json()["credentials"][0]["credential"])[1]["exp"]
    assert exp > disclosures(capped.json()["credentials"][0]["credential"])[1]["exp"]


def test_production_refuses_the_conformance_setting(pki: Pki, tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="conformance_mode takes wallet attestations without client_status"):
        Settings(**production_kwargs(pki, tmp_path, conformance_mode=True))
    assert Settings.from_env(
        {
            "CUNHO_ISSUER_URL": "https://issuer.test",
            "CUNHO_ADMIN_TOKEN": "x" * 40,
            "CUNHO_SIGNING_KEY": str(pki.root / "signing.key"),
            "CUNHO_SIGNING_CHAIN": str(pki.root / "signing.pem"),
            "CUNHO_AUDIT_RETENTION_DAYS": "30",
            "CUNHO_SIGNER_CERTIFICATE_URL": "https://issuer.test/certs/signer.pem",
            "CUNHO_WALLET_PROVIDER_ANCHORS": str(pki.root / "wallet-providers.pem"),
            "CUNHO_CONFORMANCE_MODE": "true",
        }
    ).conformance_mode
