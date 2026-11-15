"""Revocation chaining (CIR 2024/2979 Annex Ib LC_GEN-4; CIR 2024/2977 Art. 5(4)(b); ARF WUA_29, VCR_07c, VCR_07d,
WURevocation_11, _18; TS3 §2.3.1): the status of the wallet and key attestations behind every credential that lives
more than a day is read again at least every day, and the credential is revoked when either is revoked. A list that
cannot be read is alerted on, never revoked on, unless the operator asks for that after some days."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from cunho.errors import ConfigError
from cunho.service import Issuer, LeaseLost
from cunho.settings import Settings
from cunho.status import StatusRef
from eudi_probe.jose import EcKey, b64u

from .codewallet import LOGIN, WALLET_STATUS_LIST, CodeWallet, Pkce, code_of, pid_scope
from .helpers import PID_CONFIG, START, Clock, Pki, settings_kwargs
from .pki import TestPki
from .statuslists import KA_STATUS_LIST, ServedStatus, StatusSigner

DAY = 86_400
WIA_IDX, KA_IDX = 3, 7  # the entries the test wallet and key attestations name (codewallet.py, helpers.py)
WIA_IDENTIFIERS = "https://wallet-provider.test/identifiers/wia"


@pytest.fixture
def wia_lists(trust_pki: TestPki) -> StatusSigner:
    wp = trust_pki.wallet_provider
    return StatusSigner.under(wp.intermediate.cert, wp.intermediate.key, wp.intermediate.cert)


@pytest.fixture
def ka_lists(pki: Pki) -> StatusSigner:
    return StatusSigner.under(pki.wallet_ca, pki.wallet_ca_key)


@pytest.fixture
def served() -> ServedStatus:
    return ServedStatus()


class Lists:
    """Serves fresh wallet provider lists: each lives a second, so the next read fetches again."""

    def __init__(self, served: ServedStatus, wia: StatusSigner, ka: StatusSigner, clock: Clock) -> None:
        self.served, self.wia, self.ka, self.clock = served, wia, ka, clock

    def serve(self, *, wia: dict[int, int] | None = None, ka: dict[int, int] | None = None, wia_size: int = 64) -> None:
        now = int(self.clock())
        exp = now + 2 * DAY
        self.served.lists[WALLET_STATUS_LIST] = self.wia.token(
            WALLET_STATUS_LIST, wia or {}, size=wia_size, iat=now, exp=exp, ttl=1
        )
        self.served.lists[KA_STATUS_LIST] = self.ka.token(KA_STATUS_LIST, ka or {}, iat=now, exp=exp, ttl=1)
        self.clock.now += 2

    def drop(self) -> None:
        self.served.lists.clear()
        self.clock.now += 2


@pytest.fixture
def lists(served: ServedStatus, wia_lists: StatusSigner, ka_lists: StatusSigner, clock: Clock) -> Lists:
    served_lists = Lists(served, wia_lists, ka_lists, clock)
    served_lists.serve()
    return served_lists


@pytest.fixture
def make_chained(
    make_code_issuer: Callable[..., Issuer], code_files: dict[str, Path], served: ServedStatus
) -> Callable[..., Issuer]:
    def build(**overrides: Any) -> Issuer:
        return make_code_issuer(wallet_status_anchors=code_files["anchors"], fetcher=served, **overrides)

    return build


@pytest.fixture
def chained(make_chained: Callable[..., Issuer], lists: Lists) -> Issuer:
    return make_chained()


def issue(issuer: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], **attestation: Any) -> CodeWallet:
    """A credential through the code flow; `attestation` changes the wallet attestation shown at PAR, while the
    token request shows the usual one, so the token carries both references."""
    wallet = code_wallet_for(issuer)
    pkce = Pkce.random()
    if attestation:
        headers = wallet.attestation_headers(wallet.attestation(**attestation))
        code = code_of(wallet, issuer, pkce, attest=False, headers=headers)
    else:
        code = code_of(wallet, issuer, pkce)
    response = wallet.code_token_request(code, pkce)
    assert response.status_code == 200, response.text
    wallet.token = response.json()["access_token"]
    issued = wallet.issue()
    assert issued.status_code == 200, issued.text
    return wallet


def chain_rows(issuer: Issuer) -> list[tuple[str, Any]]:
    return issuer.store.items("chain", "", at=0)


def bit(issuer: Issuer, key: str) -> int:
    """Our own status bit of the credential a chain row is for, as the issuer holds it."""
    _, list_id, index = key.rsplit(":", 2)
    value = issuer.status.value(StatusRef(list_id, int(index)))
    assert value is not None
    return value


def hold_lease(issuer: Issuer) -> str:
    """Hold the job's lease, as a run does, for a test that calls one step of it; the run's token."""
    issuer.store.put("chain-run", "lease", "test", 3600)
    return "test"


def run(issuer: Issuer, clock: Clock, *, advance: int = 0) -> dict[str, int]:
    clock.now += advance
    issuer.clock_watch.trust(issuer.clock())
    issuer.status.publish()
    done = issuer.chain(force=True)
    issuer.status.publish()
    return done


@pytest.mark.obligation("REVOC.STORE_WIA_CLIENT_STATUS")
def test_a_credential_keeps_its_attestations_references_to_check_again(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    """ARF WURevocation_11: the wallet provider's references are kept with the credential, in the store; the audit
    log names none of them."""
    issue(chained, code_wallet_for)
    [(key, row)] = chain_rows(chained)
    assert row["watch"] == [
        {"status_list": {"idx": WIA_IDX, "uri": WALLET_STATUS_LIST}},
        {"status_list": {"idx": KA_IDX, "uri": KA_STATUS_LIST}},
    ]
    logged = json.dumps(chained.audit.entries())
    assert WALLET_STATUS_LIST not in logged and KA_STATUS_LIST not in logged


@pytest.mark.obligation("REVOC.CHAIN_WIA_KA", "VALIDITY.EAA_LE_STATUS_EXP")
@pytest.mark.parametrize("revoked", ["wia", "ka"])
def test_a_revoked_wallet_or_key_storage_revokes_the_credential(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock, revoked: str
) -> None:
    issue(chained, code_wallet_for)
    [(key, _)] = chain_rows(chained)
    assert run(chained, clock) == {"chain_checked": 1, "chain_revoked": 0, "chain_unchecked": 0}
    assert bit(chained, key) == 0
    if revoked == "wia":
        lists.serve(wia={WIA_IDX: 1})
    else:
        lists.serve(ka={KA_IDX: 1})
    assert run(chained, clock)["chain_revoked"] == 1
    assert bit(chained, key) == 1 and chain_rows(chained) == []
    entry = chained.audit.entries()[-1]
    assert entry["event"] == "credential.revoked" and entry["data"]["reason"] == "wallet_revoked"


def test_each_list_is_read_once_per_run(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, served: ServedStatus, clock: Clock
) -> None:
    for _ in range(3):
        issue(chained, code_wallet_for)
    assert len(chain_rows(chained)) == 3
    lists.serve()
    served.asked.clear()
    assert run(chained, clock)["chain_checked"] == 3
    assert sorted(served.asked) == [KA_STATUS_LIST, WALLET_STATUS_LIST]


def test_a_list_that_cannot_be_read_is_alerted_on_and_revokes_nothing(
    chained: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    issue(chained, code_wallet_for)
    [(key, before)] = chain_rows(chained)
    lists.drop()
    with caplog.at_level(logging.ERROR, logger="cunho.security"):
        done = run(chained, clock, advance=DAY)
    assert done == {"chain_checked": 0, "chain_revoked": 0, "chain_unchecked": 1}
    assert "could not read" in caplog.text
    assert bit(chained, key) == 0 and chain_rows(chained)[0][1]["ok"] == before["ok"]
    entry = chained.audit.entries()[-1]
    assert entry["event"] == "chain.unchecked" and entry["data"]["credentials"] == 1
    assert WALLET_STATUS_LIST not in json.dumps(entry)


def test_an_operator_may_revoke_what_stays_unchecked_too_long(
    make_chained: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    issuer = make_chained(chain_revoke_after_days=2)
    issue(issuer, code_wallet_for)
    [(key, _)] = chain_rows(issuer)
    lists.drop()
    assert run(issuer, clock, advance=DAY)["chain_unchecked"] == 1
    assert run(issuer, clock, advance=DAY + 3600)["chain_revoked"] == 1
    assert bit(issuer, key) == 1
    assert issuer.audit.entries()[-1]["data"]["reason"] == "wallet_unchecked"


def test_a_successful_check_restarts_the_unchecked_period(
    make_chained: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    issuer = make_chained(chain_revoke_after_days=2)
    issue(issuer, code_wallet_for)
    lists.drop()
    run(issuer, clock, advance=DAY + 3600)
    lists.serve()
    assert run(issuer, clock)["chain_checked"] == 1
    lists.drop()
    assert run(issuer, clock, advance=DAY + 3600)["chain_unchecked"] == 1, "the clock restarted at the last check"


def test_a_wallet_on_an_identifier_list_is_chained_too(
    chained: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,
    served: ServedStatus,
    wia_lists: StatusSigner,
    clock: Clock,
) -> None:
    ident = b"this wallet"
    status = {"status": {"identifier_list": {"id": b64u(ident), "uri": WIA_IDENTIFIERS}}, "exp": START + 60 * DAY}
    served.lists[WIA_IDENTIFIERS] = wia_lists.identifiers(WIA_IDENTIFIERS, [], iat=int(clock()), ttl=1)
    issue(chained, code_wallet_for, client_status=status)
    [(key, row)] = chain_rows(chained)
    assert {"identifier_list": {"id": b64u(ident), "uri": WIA_IDENTIFIERS}} in row["watch"]
    lists.serve()
    served.lists[WIA_IDENTIFIERS] = wia_lists.identifiers(WIA_IDENTIFIERS, [ident], iat=int(clock()), ttl=1)
    assert run(chained, clock)["chain_revoked"] == 1 and bit(chained, key) == 1


def test_a_credential_that_lives_a_day_or_less_is_not_chained(
    make_chained: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists
) -> None:
    """EAA-6.2.10.1-02.1: an attestation valid for 24 hours or less needs no revocation."""
    issuer = make_chained(credential_validity_days=1)
    issue(issuer, code_wallet_for)
    assert issuer.store.items("issued", "") and chain_rows(issuer) == []


@pytest.mark.parametrize(("opt_in", "rows"), [(False, 0), (True, 1)])
def test_an_attestation_provider_chains_only_when_it_says_so(
    make_chained: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,
    opt_in: bool,
    rows: int,
) -> None:
    """ARF VCR_07d: an attestation provider may revoke its attestations when the wallet unit is revoked."""
    issuer = make_chained(
        profile="eaa_provider",
        chain_attestations=opt_in,
        published_configurations=("eu.europa.ec.eudi.pid_vc_sd_jwt",),
    )
    issue(issuer, code_wallet_for)
    assert len(chain_rows(issuer)) == rows


def test_revoking_the_subject_drops_its_references_and_erasing_keeps_them(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    """A revoked credential has nothing left to chain; an erased subject's credentials stay valid, and the check
    every day the law asks for goes on while they live."""
    issue(chained, code_wallet_for)
    [(key, _)] = chain_rows(chained)
    subject_ref = key.rsplit(":", 2)[0]
    chained.erase_subject(subject_ref, "admin")
    assert len(chain_rows(chained)) == 1
    chained.revoke({"subject_ref": subject_ref, "reason": "user_request"}, "admin")
    assert chain_rows(chained) == []


def test_the_job_runs_once_per_interval(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    issue(chained, code_wallet_for)
    chained.clock_watch.trust(chained.clock())
    assert chained.chain()["chain_checked"] == 1
    assert chained.chain() == {}, "within the interval"
    lists.serve()
    clock.now += chained.settings.chain_interval
    chained.clock_watch.trust(chained.clock())
    assert chained.chain()["chain_checked"] == 1


def test_maintenance_runs_the_job(chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]) -> None:
    issue(chained, code_wallet_for)
    assert chained.maintenance(force=True)["chain_checked"] == 1


def test_without_wallet_status_lists_the_job_alerts(
    make_code_issuer: Callable[..., Issuer],
    code_wallet_for: Callable[[Issuer], CodeWallet],
    clock: Clock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    issuer = make_code_issuer()
    assert issuer.chain(force=True) == {}, "nothing to check, nothing said"
    issue(issuer, code_wallet_for)
    issuer.clock_watch.trust(issuer.clock())
    with caplog.at_level(logging.ERROR, logger="cunho.security"):
        assert issuer.chain(force=True) == {"chain_unavailable": 1}
    assert "cannot run" in caplog.text


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"chain_interval": 86_401}, "from 10 minutes to a day"),
        ({"chain_interval": 599}, "from 10 minutes to a day"),
        ({"chain_interval": 0}, "chain_interval must be a whole number"),
        ({"chain_revoke_after_days": 0}, "chain_revoke_after_days must be"),
        ({"chain_revoke_after_days": True}, "chain_revoke_after_days must be"),
        ({"chain_revoke_after_days": 1.5}, "chain_revoke_after_days must be"),
        ({"chain_revoke_after_days": "2"}, "chain_revoke_after_days must be"),
    ],
)
def test_chaining_settings_are_checked(pki: Pki, overrides: dict[str, Any], reason: str) -> None:
    with pytest.raises(ConfigError, match=reason):
        Settings(**settings_kwargs(pki, **overrides))


def test_one_day_is_the_shortest_revocation_delay(pki: Pki) -> None:
    assert Settings(**settings_kwargs(pki, chain_revoke_after_days=1)).chain_revoke_after_days == 1


WIA_WATCHED = {"status_list": {"idx": WIA_IDX, "uri": WALLET_STATUS_LIST}}


def test_a_pre_authorized_token_with_a_wallet_attestation_chains_it(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]
) -> None:
    from .test_preauth_attested import preauth_token

    wallet = code_wallet_for(chained)
    response = preauth_token(wallet, wallet.offer(), wallet.attestation_headers())
    assert response.status_code == 200, response.text
    wallet.token = response.json()["access_token"]
    assert wallet.issue().status_code == 200
    [(_, row)] = chain_rows(chained)
    assert WIA_WATCHED in row["watch"]


def test_a_refreshed_token_chains_the_attestation_shown_at_the_refresh(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists
) -> None:
    wallet = code_wallet_for(chained)
    wallet.get_code_token(LOGIN, scope=pid_scope(chained))
    # The wallet shows an attestation with another entry at the refresh: that one is watched for what it yields.
    shown = {"status": {"status_list": {"idx": 11, "uri": WALLET_STATUS_LIST}}, "exp": START + 60 * DAY}
    wallet.attestation = lambda **claims: CodeWallet.attestation(wallet, client_status=shown, **claims)  # type: ignore[method-assign]
    renewed = wallet.refresh_request()
    assert renewed.status_code == 200, renewed.text
    wallet.token = renewed.json()["access_token"]
    assert wallet.issue().status_code == 200
    [(_, row)] = chain_rows(chained)
    assert {"status_list": {"idx": 11, "uri": WALLET_STATUS_LIST}} in row["watch"]


def test_a_second_worker_waits_for_a_run_in_progress_even_across_intervals(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """A run still going when the clock crosses into the next interval keeps the job to itself: no other worker
    starts one beside it (the second reviewer). Once it ends, the next run comes an interval after it started."""
    issue(chained, code_wallet_for)
    interval = chained.settings.chain_interval
    started = int(clock())
    chained.store.put("chain-last", "run", started, None)  # another worker's run started then
    clock.now = started + interval + 5  # past its interval, the run still going and renewing its lease
    chained.store.put("chain-run", "lease", "theirs", interval)
    chained.clock_watch.trust(chained.clock())
    assert chained.chain() == {}
    assert chained.store.get("chain-run", "lease") == "theirs"
    chained.store.delete("chain-run", "lease")  # it ends
    clock.now += interval
    lists.serve()
    chained.clock_watch.trust(chained.clock())
    assert chained.chain()["chain_checked"] == 1
    assert chained.store.get("chain-run", "lease") is None, "a run gives the lease back"


def test_an_outage_costs_one_fetch_per_list_not_one_per_wallet(
    chained: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,
    served: ServedStatus,
    clock: Clock,
) -> None:
    """Many wallets with entries of their own in one list that cannot be read: the list is asked for once per run,
    so an outage does not stall the job wallet by wallet (the second reviewer)."""
    for idx in (20, 21, 22):
        status = {"status": {"status_list": {"idx": idx, "uri": WALLET_STATUS_LIST}}, "exp": START + 60 * DAY}
        issue(chained, code_wallet_for, client_status=status)
    lists.drop()
    served.asked.clear()
    assert run(chained, clock)["chain_unchecked"] == 3
    assert served.asked.count(WALLET_STATUS_LIST) == 1 and served.asked.count(KA_STATUS_LIST) == 1


def test_an_entry_past_the_end_of_a_readable_list_leaves_the_others_checked(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """Only the list itself failing makes every entry of it unknown; one entry outside it is that entry's alone."""
    far = {"status": {"status_list": {"idx": 40, "uri": WALLET_STATUS_LIST}}, "exp": START + 60 * DAY}
    issue(chained, code_wallet_for, client_status=far)
    issue(chained, code_wallet_for)
    lists.serve(wia_size=8)  # the list the provider serves now ends before entry 40
    done = run(chained, clock)
    assert done["chain_unchecked"] == 1 and done["chain_checked"] == 1


def test_the_background_loop_runs_the_job_whatever_the_maintenance_interval(
    make_chained: Callable[..., Issuer], lists: Lists
) -> None:
    """The job keeps its own interval: a long maintenance interval must not stretch the daily check (the second
    reviewer)."""
    import time

    from fastapi.testclient import TestClient

    from cunho.app import create_app

    issuer = make_chained(maintenance_interval=1)
    called: list[float] = []

    def chain(**kwargs: Any) -> dict[str, int]:
        called.append(time.monotonic())
        return {}

    issuer.chain = chain  # type: ignore[method-assign]
    issuer.maintenance = lambda **kwargs: {}  # type: ignore[method-assign]
    with TestClient(create_app(issuer=issuer), base_url="https://issuer.test"):
        deadline = time.monotonic() + 5
        while not called and time.monotonic() < deadline:
            time.sleep(0.05)
    assert called, "the background loop did not run the chaining job"


def test_a_credential_is_chained_to_its_own_key_attestation_only(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """A batch whose keys come with key attestations of different entries: revoking one entry revokes the credential
    of that key only (the second reviewer)."""
    wallet = code_wallet_for(chained)
    pkce = Pkce.random()
    wallet.token = wallet.code_token_request(code_of(wallet, chained, pkce), pkce).json()["access_token"]
    holders = [EcKey.generate(), EcKey.generate()]
    nonce = wallet.c_nonce()
    proofs = [
        wallet.proof(
            holder,
            nonce,
            key_attestation=wallet.key_attestation(
                [holder],
                key_storage_status={
                    "status": {"status_list": {"idx": idx, "uri": KA_STATUS_LIST}},
                    "exp": START + 60 * DAY,
                },
            ),
        )
        for holder, idx in zip(holders, (30, 31), strict=True)
    ]
    response = wallet.credential_request({"credential_configuration_id": PID_CONFIG, "proofs": {"jwt": proofs}})
    assert response.status_code == 200, response.text
    rows = dict(chain_rows(chained))
    watched = sorted(
        next(m["status_list"]["idx"] for m in row["watch"] if m["status_list"]["uri"] == KA_STATUS_LIST)
        for row in rows.values()
    )
    assert watched == [30, 31], "each credential watches its own key's entry"
    lists.serve(ka={30: 1})
    assert run(chained, clock) == {"chain_checked": 1, "chain_revoked": 1, "chain_unchecked": 0}
    assert sorted(bit(chained, key) for key in rows) == [0, 1]


def test_a_check_does_not_bring_back_a_row_a_revocation_deleted(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """The job read the row, then the subject was revoked: its check must not write the row back (the second
    reviewer)."""
    issue(chained, code_wallet_for)
    [(key, row)] = chain_rows(chained)
    chained.revoke({"subject_ref": key.rsplit(":", 2)[0], "reason": "user_request"}, "admin")
    assert chain_rows(chained) == []
    lists.serve()
    lease = hold_lease(chained)
    outcome = chained._chain_row(key, row, clock(), {}, lease)  # noqa: SLF001 - the job's step, on the snapshot it read
    assert outcome == "checked", "the check itself succeeds; only its write must not happen"
    assert chain_rows(chained) == []


def test_a_run_reads_lists_fresh_never_one_kept_from_before_it(
    chained: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    served: ServedStatus,
    wia_lists: StatusSigner,
    ka_lists: StatusSigner,
    clock: Clock,
) -> None:
    """A list issuance fetched, kept for its hour, must not stand for the daily check: a revocation after that fetch
    is seen by the next run (the second reviewer)."""
    now = int(clock())
    served.lists[WALLET_STATUS_LIST] = wia_lists.token(WALLET_STATUS_LIST, {}, iat=now, exp=now + 2 * DAY)
    served.lists[KA_STATUS_LIST] = ka_lists.token(KA_STATUS_LIST, {}, iat=now, exp=now + 2 * DAY)
    issue(chained, code_wallet_for)  # issuance fetches both lists and keeps them, without a ttl, for an hour
    [(key, _)] = chain_rows(chained)
    clock.now += 60
    served.lists[WALLET_STATUS_LIST] = wia_lists.token(
        WALLET_STATUS_LIST, {WIA_IDX: 1}, iat=now + 60, exp=now + 2 * DAY
    )
    assert run(chained, clock)["chain_revoked"] == 1 and bit(chained, key) == 1


def test_a_new_interval_period_does_not_start_a_run_early(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """Runs are chain_interval apart, even when the clock crosses into the next period just after one."""
    issue(chained, code_wallet_for)
    interval = chained.settings.chain_interval
    clock.now = (int(clock()) // interval + 1) * interval - 10  # ten seconds before the next period
    lists.serve()
    chained.clock_watch.trust(chained.clock())
    assert chained.chain()["chain_checked"] == 1
    clock.now += 20  # in the next period, twenty seconds later
    chained.clock_watch.trust(chained.clock())
    assert chained.chain() == {}


def test_each_list_is_fetched_once_per_run_even_when_its_ttl_runs_out_meanwhile(
    chained: Issuer,
    code_wallet_for: Callable[[Issuer], CodeWallet],
    lists: Lists,
    served: ServedStatus,
    clock: Clock,
) -> None:
    """Distinct entries of one list, and a list whose ttl lapses during the run as each fetch takes time: the run
    still fetches each list once, not once per entry (the second reviewer)."""
    for idx in (40, 41, 42):
        status = {"status": {"status_list": {"idx": idx, "uri": WALLET_STATUS_LIST}}, "exp": START + 60 * DAY}
        issue(chained, code_wallet_for, client_status=status)
    lists.serve()
    fetch = served.get

    def slow(url: str, **kwargs: Any) -> bytes:
        clock.now += 5  # longer than the lists' ttl of a second
        return fetch(url, **kwargs)

    served.get = slow  # type: ignore[method-assign]
    served.asked.clear()
    assert run(chained, clock)["chain_checked"] == 3
    assert served.asked.count(WALLET_STATUS_LIST) == 1 and served.asked.count(KA_STATUS_LIST) == 1


def test_an_entry_not_read_at_the_start_of_a_run_is_read_on_its_own(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """A credential issued while a run goes on names entries the run did not collect: they are read for it."""
    issue(chained, code_wallet_for)
    [(key, row)] = chain_rows(chained)
    lists.serve()
    lease = hold_lease(chained)
    assert chained._chain_row(key, row, clock(), {}, lease) == "checked"  # noqa: SLF001 - one step of the job


def test_a_run_renews_only_its_own_lease(chained: Issuer) -> None:
    chained.store.put("chain-run", "lease", "theirs", 60)
    with pytest.raises(LeaseLost):
        chained._keep_lease("mine")  # noqa: SLF001 - the run's own lease token
    assert chained.store.get("chain-run", "lease") == "theirs"
    chained.store.put("chain-run", "lease", "mine", 1)
    chained._keep_lease("mine")  # noqa: SLF001
    chained.clock.now += 30  # type: ignore[attr-defined]
    assert chained.store.get("chain-run", "lease") == "mine", "renewed for another interval"


def test_a_run_longer_than_an_interval_keeps_its_lease(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """A run that takes longer than an interval in all: the lease is renewed after each list, so no other worker
    starts a run while this one goes on."""
    issue(chained, code_wallet_for)
    assert chained.wallet_status is not None
    real = chained.wallet_status.verdicts
    seen: list[Any] = []

    def slow(found: list[Any]) -> dict[Any, str]:
        # The first list takes most of an interval; by the second, the run as a whole has outlived the lease it
        # started with, and holds it only because it renewed it after the first.
        clock.now += chained.settings.chain_interval - 10 if not seen else 20
        seen.append(chained.store.get("chain-run", "lease") if seen else "first")
        return real(found)

    chained.wallet_status.verdicts = slow  # type: ignore[method-assign]
    lists.serve()
    chained.clock_watch.trust(chained.clock())
    chained.chain()
    assert seen[0] == "first" and seen[1] is not None, "the lease was still held when the second list was read"


def test_a_run_that_lost_its_lease_leaves_the_new_one_alone(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists
) -> None:
    issue(chained, code_wallet_for)
    assert chained.wallet_status is not None
    real = chained.wallet_status.verdicts

    def taken(found: list[Any]) -> dict[Any, str]:
        chained.store.put("chain-run", "lease", "theirs", 3600)  # another worker took the lease meanwhile
        return real(found)

    chained.wallet_status.verdicts = taken  # type: ignore[method-assign]
    lists.serve()
    chained.clock_watch.trust(chained.clock())
    chained.chain()
    assert chained.store.get("chain-run", "lease") == "theirs"


def test_a_run_that_lost_its_lease_writes_nothing_more(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """A run paused past its lease while another worker took over stops: it neither revokes nor writes an older
    check over a newer one (the second reviewer)."""
    issue(chained, code_wallet_for)
    [(key, before)] = chain_rows(chained)
    assert chained.wallet_status is not None
    real = chained.wallet_status.verdicts

    def overtaken(found: list[Any]) -> dict[Any, str]:
        chained.store.put("chain-run", "lease", "theirs", 3600)
        return real(found)

    chained.wallet_status.verdicts = overtaken  # type: ignore[method-assign]
    lists.serve(wia={WIA_IDX: 1})
    chained.clock_watch.trust(chained.clock())
    assert chained.chain() == {"chain_lease_lost": 1}
    assert bit(chained, key) == 0 and chain_rows(chained) == [(key, before)]


def test_an_older_check_never_writes_over_a_newer_one(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    issue(chained, code_wallet_for)
    [(key, row)] = chain_rows(chained)
    lists.serve()
    lease = hold_lease(chained)
    later = clock() + 1000
    chained.store.put("chain", key, {**row, "ok": int(later)}, 3600)
    chained._chain_row(key, row, clock(), {}, lease)  # noqa: SLF001
    assert chain_rows(chained)[0][1]["ok"] == int(later)


def test_overdue_goes_by_the_row_as_it_is_not_as_the_run_read_it(
    make_chained: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """The unchecked period runs from the last successful check in the store, which a newer run may have just made."""
    issuer = make_chained(chain_revoke_after_days=2)
    issue(issuer, code_wallet_for)
    [(key, row)] = chain_rows(issuer)
    lists.drop()
    clock.now += 3 * DAY
    issuer.store.put("chain", key, {**row, "ok": int(clock()) - 60}, 3600)  # a newer run checked it a minute ago
    lease = hold_lease(issuer)
    assert issuer._chain_row(key, row, clock(), {}, lease) == "unchecked"  # noqa: SLF001
    assert bit(issuer, key) == 0


def test_a_forced_run_takes_the_lease(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists
) -> None:
    """An operator's forced run goes ahead while another holds the lease; the other one stops at its next step."""
    issue(chained, code_wallet_for)
    chained.store.put("chain-run", "lease", "theirs", 3600)
    lists.serve()
    chained.clock_watch.trust(chained.clock())
    assert chained.chain(force=True)["chain_checked"] == 1


def test_the_shortest_and_longest_intervals_are_taken(pki: Pki) -> None:
    for interval in (600, 86_400):
        Settings(**settings_kwargs(pki, chain_interval=interval))


def test_a_run_with_a_stale_token_stops_at_its_first_write(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists, clock: Clock
) -> None:
    """Each run carries its own lease token: a newer run in the same process, a forced one, holds the lease now, so
    the older run's next write stops it, whatever the newer one's token (the second reviewer)."""
    issue(chained, code_wallet_for)
    [(key, row)] = chain_rows(chained)
    lists.serve(wia={WIA_IDX: 1})
    chained.store.put("chain-run", "lease", "newer", 3600)
    with pytest.raises(LeaseLost):
        chained._chain_row(key, row, clock(), {}, "older")  # noqa: SLF001
    assert bit(chained, key) == 0 and len(chain_rows(chained)) == 1


def held_release(issuer: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]) -> tuple[CodeWallet, str]:
    """A login held for review, its credential request answered 202 and the operator's release given."""
    from .test_deferred import decide, held_login, held_refs

    wallet = code_wallet_for(issuer)
    held_login(wallet, issuer)
    response = wallet.issue()
    assert response.status_code == 202, response.text
    [ref] = held_refs(wallet)
    assert decide(wallet, ref, "release").status_code == 200
    return wallet, str(response.json()["transaction_id"])


@pytest.mark.covers("KA.STATUS_AT_ISSUANCE")
def test_a_key_attestation_revoked_during_review_stops_the_collection(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists
) -> None:
    from .helpers import refused_by
    from .test_deferred import deferred

    wallet, transaction_id = held_release(chained, code_wallet_for)
    lists.serve(ka={KA_IDX: 1})
    denied = refused_by(
        lambda: deferred(wallet, {"transaction_id": transaction_id}), "KA.STATUS_AT_ISSUANCE", "was revoked"
    )
    assert denied.status_code == 400 and denied.json()["error"] == "credential_request_denied"
    assert chained.store.items("issued") == []


def test_a_key_attestation_that_cannot_be_read_keeps_the_collection_waiting(
    chained: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet], lists: Lists
) -> None:
    from .test_deferred import deferred

    wallet, transaction_id = held_release(chained, code_wallet_for)
    lists.drop()
    waiting = deferred(wallet, {"transaction_id": transaction_id})
    assert waiting.status_code == 202 and waiting.json()["transaction_id"] == transaction_id
    assert chained.store.items("issued") == []
    lists.serve()
    collected = deferred(wallet, {"transaction_id": transaction_id})
    assert collected.status_code == 200, collected.text
