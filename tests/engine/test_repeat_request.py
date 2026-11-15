"""A credential request repeated under the same access token (OpenID4VCI 1.0 §8.3; the conformance suite asks a
token more than once). The same keys, proven again, get the credentials the first request got; other keys are
refused. No credential is made twice: a second one on the same key would share it (ARF ISSU_35), and one batch
is all a token yields (M-1). The reply is kept sealed and goes with the token or with the subject."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from cunho.service import Issuer
from cunho.store import SqliteStore
from eudi_probe.jose import EcKey

from .codewallet import CodeWallet
from .helpers import Clock, Wallet


def issued_rows(issuer: Issuer) -> int:
    return len(issuer.store.items("issued"))


def test_the_same_keys_get_the_same_credentials_and_nothing_new_is_made(wallet: Wallet, issuer: Issuer) -> None:
    first_key, second_key = EcKey.generate(), EcKey.generate()
    first = wallet.issue([first_key, second_key])
    assert first.status_code == 200, first.text
    rows = issued_rows(issuer)
    again = wallet.issue([second_key, first_key])  # fresh proofs, the keys in another order
    assert again.status_code == 200, again.text
    assert again.json() == first.json()
    assert issued_rows(issuer) == rows
    events = [e["event"] for e in issuer.audit.entries()]
    assert events.count("credential.issued") == 1


@pytest.mark.covers("VCI.CRED.ERROR_CODES")
def test_other_keys_are_refused(wallet: Wallet) -> None:
    key = EcKey.generate()
    assert wallet.issue([key]).status_code == 200
    for keys in ([EcKey.generate()], [key, EcKey.generate()]):
        refused = wallet.issue(keys)
        assert refused.status_code == 400 and refused.json()["error"] == "credential_request_denied"
        assert "with other keys" in refused.json()["error_description"]


def test_the_kept_reply_is_sealed(wallet: Wallet, issuer: Issuer) -> None:
    response = wallet.issue()
    credential = response.json()["credentials"][0]["credential"]
    stored = json.dumps(issuer.store.items("vault-reply"))
    assert issuer.store.items("vault-reply")
    for part in credential.split("~"):
        if part:
            assert part not in stored


@pytest.mark.parametrize("close", ["revocations", "cancel", "erase"])
def test_closing_the_subject_drops_the_reply(wallet: Wallet, issuer: Issuer, close: str) -> None:
    offer = wallet.offer(configs=None)
    wallet.get_token(offer)
    key = EcKey.generate()
    assert wallet.issue([key]).status_code == 200
    subject_ref = offer["subject_ref"]
    if close == "revocations":
        assert wallet.admin("revocations", {"subject_ref": subject_ref, "reason": "user_request"}).status_code == 200
    elif close == "cancel":
        issuer._close_subject(subject_ref)  # noqa: SLF001  (an offer with nothing left to issue cannot be cancelled)
    else:
        assert issuer.store.get("vault-key", subject_ref) is None  # emptied when the offer was done
        erased = issuer.erase_subject(subject_ref, "admin")
        assert erased == {"erased": True, "data_held": True}, "the kept reply is data held"
    assert issuer.store.items("vault-reply") == []
    refused = wallet.issue([key])
    assert refused.status_code == 400 and refused.json()["error"] == "credential_request_denied"


def test_the_reply_lives_as_long_as_the_token(wallet: Wallet, issuer: Issuer) -> None:
    wallet.issue()
    ((key, _),) = issuer.store.items("vault-reply")
    token_ttl = issuer.settings.access_token_ttl
    assert issuer.store.items("vault-reply", at=issuer.time() + token_ttl - 1)
    assert issuer.store.items("vault-reply", at=issuer.time() + token_ttl) == []
    assert key.startswith("sub_")


def test_a_reply_that_does_not_open_is_not_used(wallet: Wallet, issuer: Issuer) -> None:
    """A reply moved to another subject or slot does not open there (the AAD names both)."""
    wallet.issue()
    ((key, value),) = issuer.store.items("vault-reply")
    subject_ref, slot = key.split(":", 1)
    assert issuer.vault.reply(subject_ref, slot) is not None
    assert issuer.vault.reply(subject_ref, slot + "x") is None
    issuer.store.put("vault-reply", f"{subject_ref}:other", value, 60)
    assert issuer.vault.reply(subject_ref, "other") is None


def test_an_erasure_drops_a_reply_the_sweep_has_not_reached_yet(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    tmp_path: Path,
) -> None:
    """SQLite keeps an expired row until the sweep: an erasure in between must still drop it, and count it as data
    held (the second reviewer)."""
    issuer = make_code_issuer(store=SqliteStore(tmp_path / "s.db", clock))
    wallet = code_wallet_for(issuer)
    offer = wallet.offer()
    wallet.get_token(offer)
    assert wallet.issue().status_code == 200
    clock.now += issuer.settings.access_token_ttl + 1  # the reply has expired; no sweep has run
    assert issuer.store.items("vault-reply", at=0)
    erased = issuer.erase_subject(offer["subject_ref"], "admin")
    assert erased == {"erased": True, "data_held": True}
    assert issuer.store.items("vault-reply", at=0) == []
