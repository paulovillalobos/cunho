"""ARF SUA_03, a configuration issued only to the wallet solutions it names, and ARF ISSU_42, re-issuance with
nothing asked of the user."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho import metadata, oauth
from cunho.errors import ConfigError
from cunho.service import Issuer
from cunho.settings import Settings

from .codewallet import CodeWallet
from .helpers import PID_CONFIG, Pki, Wallet, refused_by, settings_kwargs, typed_metadata
from .test_preauth_attested import preauth_token
from .test_refresh import refreshable

WALLET = "cunho test wallet"  # what the test wallet attestation names (codewallet.py)
NOT_LISTED = "this credential is not issued to this wallet solution or version"


def gated(tmp_path: Path, solutions: Any) -> Path:
    """The shipped configurations, with the SD-JWT VC PID issued only to `solutions`."""
    folder = typed_metadata(tmp_path / "metadata")
    path = folder / "credentials_supported" / "pid_jwt_vc.json"
    configs = json.loads(path.read_text())
    configs[PID_CONFIG]["wallet_solutions"] = solutions
    path.write_text(json.dumps(configs))
    return folder


def gated_wallet(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    tmp_path: Path,
    solutions: Any,
) -> tuple[CodeWallet, Issuer]:
    issuer = make_code_issuer(metadata_dir=gated(tmp_path, solutions))
    return code_wallet_for(issuer), issuer


@pytest.mark.parametrize(
    "solutions",
    [
        [{"wallet_name": WALLET}],
        [{"wallet_name": "another wallet"}, {"wallet_name": WALLET, "wallet_versions": ["0.9", "1.0.0"]}],
    ],
)
def test_a_listed_wallet_solution_gets_the_credential(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    tmp_path: Path,
    solutions: Any,
) -> None:
    wallet, issuer = gated_wallet(make_code_issuer, code_wallet_for, tmp_path, solutions)
    refreshable(wallet, issuer)
    response = wallet.issue()
    assert response.status_code == 200, response.text
    published = wallet.client.get("/.well-known/openid-credential-issuer").json()
    assert "wallet_solutions" not in published["credential_configurations_supported"][PID_CONFIG], "never published"


@pytest.mark.covers("ISS.SUA.WALLET_GATE")
@pytest.mark.parametrize(
    "solutions",
    [
        [{"wallet_name": "another wallet"}],
        [{"wallet_name": WALLET, "wallet_versions": ["2.0.0"]}],
        [{"wallet_name": WALLET.upper()}],
    ],
)
def test_a_wallet_solution_not_listed_gets_nothing(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    tmp_path: Path,
    solutions: Any,
) -> None:
    wallet, issuer = gated_wallet(make_code_issuer, code_wallet_for, tmp_path, solutions)
    refreshable(wallet, issuer)
    response = refused_by(wallet.issue, "ISS.SUA.WALLET_GATE", NOT_LISTED)
    assert response.status_code == 400 and response.json()["error"] == "credential_request_denied"


@pytest.mark.covers("ISS.SUA.WALLET_GATE")
def test_a_wallet_attestation_without_its_name_gets_nothing(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], tmp_path: Path
) -> None:
    wallet, issuer = gated_wallet(make_code_issuer, code_wallet_for, tmp_path, [{"wallet_name": WALLET}])
    wallet.attestation = functools.partial(CodeWallet.attestation, wallet, wallet_name=...)  # type: ignore[method-assign]
    refreshable(wallet, issuer)
    refused_by(wallet.issue, "ISS.SUA.WALLET_GATE", NOT_LISTED)


@pytest.mark.covers("ISS.SUA.WALLET_GATE")
def test_a_refresh_by_a_version_taken_off_the_list_gets_nothing(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], tmp_path: Path
) -> None:
    """The gate goes by the attestation that got the access token: a refresh by a version not on the list gets a
    token, but no credential of the gated configuration."""
    solutions = [{"wallet_name": WALLET, "wallet_versions": ["1.0.0"]}]
    wallet, issuer = gated_wallet(make_code_issuer, code_wallet_for, tmp_path, solutions)
    refreshable(wallet, issuer)
    assert wallet.issue().status_code == 200
    wallet.attestation = functools.partial(CodeWallet.attestation, wallet, wallet_version="0.9")  # type: ignore[method-assign]
    again = wallet.refresh_request()
    assert again.status_code == 200, again.text
    wallet.token = again.json()["access_token"]
    refused_by(wallet.issue, "ISS.SUA.WALLET_GATE", NOT_LISTED)


@pytest.mark.covers("ISS.SUA.WALLET_GATE")
def test_a_token_got_without_a_wallet_attestation_gets_nothing(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], tmp_path: Path
) -> None:
    """A pre-authorized code redeemed without a wallet attestation names no wallet solution."""
    wallet = wallet_for(make_issuer(metadata_dir=gated(tmp_path, [{"wallet_name": WALLET}])))
    response = refused_by(wallet.issue, "ISS.SUA.WALLET_GATE", "authenticate with a wallet attestation")
    assert response.json()["error"] == "credential_request_denied"


def test_a_pre_authorized_token_got_by_a_listed_wallet_gets_the_credential(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], tmp_path: Path
) -> None:
    """A pre-authorized code redeemed with a wallet attestation keeps the wallet solution it names, as the code flow
    does."""
    wallet, _ = gated_wallet(make_code_issuer, code_wallet_for, tmp_path, [{"wallet_name": WALLET}])
    response = preauth_token(wallet, wallet.offer(), wallet.attestation_headers())
    assert response.status_code == 200, response.text
    wallet.token = response.json()["access_token"]
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text


def test_a_token_row_names_a_wallet_only_as_a_name_and_a_version() -> None:
    """A row from another version of cunho, or one broken in the store, names no wallet solution, so a gated
    configuration is not issued on it."""
    assert oauth._wallet([WALLET, "1.0.0"]) == (WALLET, "1.0.0")
    assert oauth._wallet([WALLET, None]) == (WALLET, None)
    for broken in (None, (WALLET, "1.0.0"), [WALLET], [WALLET, "1.0.0", "x"], [WALLET, 1], [1, "1.0.0"]):
        assert oauth._wallet(broken) is None, broken


@pytest.mark.parametrize(
    ("solutions", "reason"),
    [
        ([], "non-empty list"),
        ({"wallet_name": WALLET}, "non-empty list"),
        (["cunho test wallet"], "an object of wallet_name"),
        ([[]], "an object of wallet_name"),
        ([5], "an object of wallet_name"),
        ([{"wallet_name": WALLET, "version": "1"}], "an object of wallet_name"),
        ([{"wallet_versions": ["1"]}], "needs a wallet_name"),
        ([{"wallet_name": ""}], "needs a wallet_name"),
        ([{"wallet_name": 5}], "needs a wallet_name"),
        ([{"wallet_name": WALLET, "wallet_versions": []}], "non-empty list of version strings"),
        ([{"wallet_name": WALLET, "wallet_versions": None}], "non-empty list of version strings"),
        ([{"wallet_name": WALLET, "wallet_versions": "1.0.0"}], "non-empty list of version strings"),
        ([{"wallet_name": WALLET, "wallet_versions": ["1", ""]}], "non-empty list of version strings"),
        ([{"wallet_name": WALLET, "wallet_versions": [1]}], "non-empty list of version strings"),
    ],
)
def test_the_wallet_solutions_of_a_configuration_are_checked_at_start(
    pki: Pki, tmp_path: Path, solutions: Any, reason: str
) -> None:
    with pytest.raises(ConfigError, match=reason):
        metadata.load(Settings(**settings_kwargs(pki, metadata_dir=gated(tmp_path, solutions))))


@pytest.mark.obligation("BATCH.SILENT_REISSUANCE")
def test_re_issuance_asks_nothing_of_the_user(code_wallet: CodeWallet, code_issuer: Issuer) -> None:
    """ARF ISSU_42: once the user has logged in, the wallet gets the credential again with its refresh token alone.
    The login is gone from the issuer, the person can no longer log in, and no offer is made again; the refresh
    gives a credential anyway."""
    refreshable(code_wallet, code_issuer)
    assert code_wallet.issue().status_code == 200
    offers = [e for e in code_issuer.audit.entries() if e["event"] == "offer.created"]
    code_issuer.test_persons.clear()  # nobody can log in now
    for _ in range(2):
        again = code_wallet.refresh_request()
        assert again.status_code == 200, again.text
        code_wallet.token = again.json()["access_token"]
        response = code_wallet.issue()
        assert response.status_code == 200, response.text
    assert [e for e in code_issuer.audit.entries() if e["event"] == "offer.created"] == offers


@pytest.mark.covers("ISS.SUA.WALLET_GATE")
def test_a_held_issuance_is_collected_only_by_a_listed_wallet(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], tmp_path: Path
) -> None:
    """The wallet that collects a released issuance is the one behind the token it collects with: a refresh by a
    version taken off the list in the meantime collects nothing."""
    from .test_deferred import decide, deferred, held_refs, hold

    solutions = [{"wallet_name": WALLET, "wallet_versions": ["1.0.0"]}]
    wallet, issuer = gated_wallet(make_code_issuer, code_wallet_for, tmp_path, solutions)
    _, transaction_id = hold(wallet, issuer)
    [ref] = held_refs(wallet)
    decide(wallet, ref, "release")
    wallet.attestation = functools.partial(CodeWallet.attestation, wallet, wallet_version="0.9")  # type: ignore[method-assign]
    wallet.token = wallet.refresh_request().json()["access_token"]
    response = refused_by(
        lambda: deferred(wallet, {"transaction_id": transaction_id}), "ISS.SUA.WALLET_GATE", NOT_LISTED
    )
    assert response.json()["error"] == "credential_request_denied"
    wallet.attestation = functools.partial(CodeWallet.attestation, wallet)  # type: ignore[method-assign]
    wallet.token = wallet.refresh_request().json()["access_token"]
    collected = deferred(wallet, {"transaction_id": transaction_id})
    assert collected.status_code == 200, collected.text
