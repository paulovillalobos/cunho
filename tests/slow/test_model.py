"""A model-based test of cunho across worker processes on one SQLite file (review 5, the bar for a 10).

Hypothesis drives a state machine through offers (one or two configurations, with or without a person
handle), token exchanges, logins of the authorization code flow (PAR with the wallet attestation, the operator's
login service reporting to cunho, the code exchanged with PKCE), refreshes, a refresh by another wallet instance,
credential requests, revocation by subject, by person and by slot, cancellation, erasure, time moving on,
maintenance and the background sweep, each served by a worker process picked at random, with one of four workers.
Trust in wallet providers comes from the Commission's list, which the operator's job renews whenever time moves on;
it may also withdraw the wallet providers, or put an older list back, until the job writes a good one again. The
wallet providers' status lists are fetched, and the operator's CRL file covers their certificates.

Some steps run on several workers at once: the issuance of an offer's remaining configurations against the
revocation of its subject, and maintenance with its pruning against verify and a new offer. Revocations carry a
jitter, lists carry decoys from the start and new ones over time, and each worker's clock watch has a host clock
behind it. One step revokes while the wall clock reads hours or days off, ahead or behind; another steps the wall
clock and leaves it off for the steps that follow, every kind of step included, until a later step puts it right,
while the wallets' own clocks read right (review 7, M1 and N6-L2); maintenance runs unforced; others damage the
anchor as a torn write or a power loss does, and append a copy of one of its lines, as anyone who can append to it
can (review 6, N6-L2). A plain model says what each answer must be, and after every step these invariants are
checked:

- the audit log verifies, against its anchor, whichever worker asks;
- every revoked credential is revoked in the store, and shows in the published list once the jitter and the
  clock watch's tolerance have passed, measured on the time that really passed; every other credential handed
  out is valid;
- only revoked slots and decoys ever show, and none before the moment it was queued for;
- no credential was ever handed out for a request sent after its offer was revoked, cancelled or erased, and none
  while the list did not trust the wallet provider.
- no authorization code yields two tokens, and no refresh succeeds after its login was closed;
- no credential is valid past the status period of the wallet attestation or of the key attestation behind it;
- no held issuance outlives the closing of its subject (revocation, cancellation, erasure, a reused code);
- revocation chaining runs whenever its interval has passed, and a run that reads the wallet providers' lists
  revokes every live credential whose key attestation they revoked, so none outlives it by more than one interval.

M4 adds an mdoc attestation (the IBAN mdoc, with its own offers, as its data has the shape of its namespaces), logins
whose credentials the operator holds for review, released or refused, and collected at the deferred endpoint with
the token of the moment, notifications, the wallet provider revoking one wallet's key attestations on its status list,
and the chaining job those revocations reach credentials by. Revocation of wallet attestations by chaining is left to
the engine tests (test_chaining.py): the model revokes key attestations, which every credential carries.

Slow, so it runs in the slow CI job: pytest -m slow.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import itertools
import json
import os
import random
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    initialize,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from cunho.audit import AuditError
from cunho.jose import b64u_decode, parse_jws
from cunho.settings import CLOCK_TOLERANCE
from tests.engine.codewallet import CLIENT_ID, REDIRECT_URI, CodeWallet, Pkce
from tests.engine.helpers import (
    ADMIN_TOKEN,
    ISSUER,
    PID_CONFIG,
    PID_SUBJECT,
    PRE_AUTH,
    START,
    EcKey,
    Pki,
    Wallet,
    certificate,
    crl,
    key_pem,
    pem,
    settings_kwargs,
    wallet_providers_list,
    with_database,
)
from tests.engine.pki import Builder, TestPki
from tests.engine.test_deferred import deferred, notify
from tests.engine.test_mdoc import IBAN, IBAN_SUBJECT, decoded
from tests.engine.test_review5_revocation import NATIONAL, two_configurations

from .test_revocation_race import credential_request, slot
from .workers import RemoteClient, SharedClock, Worker, request, start

pytestmark = pytest.mark.slow
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
OFFER_TTL, TOKEN_TTL, VALIDITY, PUBLISH, JITTER = 600, 300, 14 * 86_400, 60, 600
WINDOW = OFFER_TTL + TOKEN_TTL
WORKERS = 4
DAY = 86_400
REFRESH = 3 * DAY  # refresh_token_ttl: short, so time moving on can outlast it
DEFERRED_TTL = 7 * DAY  # deferred_ttl, the default: longer than REFRESH, so the refresh token's expiry caps a hold
WALLET_STATUS = 7 * DAY  # the code flow wallet's client_status period: shorter than VALIDITY, so it caps exp
KA_STATUS = 30 * DAY  # the key attestation's key_storage_status period (helpers.Wallet)
LOGIN_URL = "https://login.test/start"
CHAIN = 6 * 3600  # chain_interval, the default
KA_LIST = "https://wallet-provider.test/status/1"  # the list every test key attestation names (helpers.Wallet)
SCOPES = {PID_CONFIG: "eu.europa.ec.eudi.pid_vc_sd_jwt", NATIONAL: "pt.pid"}


@dataclass
class Offer:
    """An offer of the pre-authorized flow, or a login of the code flow (`refresh_from`, when its code was exchanged
    and the refresh token given). `claimed` is what the current access token has claimed."""

    configs: list[str]
    person: str | None
    created: float
    code: str
    subject: str
    wallet: Wallet
    redeemed: bool = False
    token_at: float | None = None
    closed: bool = False
    erased: bool = False
    claimed: set[str] = field(default_factory=set)
    done: set[str] = field(default_factory=set)
    refresh_from: float | None = None
    status_until: float = float("inf")  # the end of the wallet attestation's status period, for the current token
    held: bool = False  # the operator holds this login's credentials for review (deferred issuance)
    transactions: dict[str, list[str]] = field(default_factory=dict)  # configuration: [transaction_id, state]
    held_until: dict[str, float] = field(default_factory=dict)  # configuration: when its held issuance expires
    notifications: list[str] = field(default_factory=list)

    @property
    def linked_until(self) -> float:
        """How long revocation by person finds it: as long as a credential from it can be valid."""
        if self.refresh_from is not None:
            return self.refresh_from + REFRESH + TOKEN_TTL + VALIDITY + 3600
        return self.created + WINDOW + VALIDITY + 3600


@dataclass
class Credential:
    subject: str
    slot: tuple[str, int]
    issued: float
    exp: float
    key_index: int  # the entry of its key attestation on the wallet provider's list
    revoked_at: float | None = None

    def row_expires(self) -> float:
        """When the issued row the revocation looks up goes (`credential` in service.py)."""
        return self.issued + max(self.exp - self.issued, 60)


class TrueTime:
    """A wallet's own clock, which reads right whatever the workers' wall clock reads."""

    def __init__(self, clock: SharedClock) -> None:
        self.clock = clock

    def __call__(self) -> float:
        return self.clock.now


class Cunho(RuleBasedStateMachine):
    workers: list[Worker]
    clock: SharedClock
    pki: Pki
    trust_pki: TestPki
    lote_key: EcKey
    root: Path
    examples = itertools.count()
    # The store every example runs on: SQLite, or PostgreSQL with a new database each time (M4 piece I).
    postgres: str | None = None
    databases: list[str] = []

    def __init__(self) -> None:
        super().__init__()
        self.offers: dict[str, Offer] = {}
        self.credentials: list[Credential] = []
        self.links: dict[str, set[str]] = {"p1": set(), "p2": set()}
        self.pick = random.Random()
        self.moments: dict[tuple[str, int], float] = {}  # every queued bit seen, with the moment it may show
        self.anchor = Path()
        self.lote = Path()
        self.sequence = self.writes = 0
        self.listed = True  # the list names the wallet providers
        self.rolled_back = False  # an older list than one cunho saw was put back
        self.indexes = itertools.count(100)  # each wallet's key attestations get an entry of their own
        self.revoked_keys: dict[int, float] = {}  # entries the wallet provider revoked, and when
        self.revoked_file = Path()

    @initialize()
    def start_over(self) -> None:
        root = self.root / f"example{next(self.examples)}"
        root.mkdir()
        self.clock.now, self.clock.skew, self.anchor = START + 1234, 0.0, root / "audit.anchor"
        self.lote, self.sequence = root / "wallet-providers.lote", 0
        self.write_list()
        self.revoked_file, self.revoked_keys = root / "revoked.json", {}
        config = settings_kwargs(
            self.pki,
            **self.store_for(root),
            secret_key_file=root / "m.key",
            audit_anchor_path=root / "audit.anchor",
            metadata_dir=two_configurations(root),
            audit_retention_days=1,
            maintenance_interval=3600,
            status_revocation_jitter=JITTER,
            status_decoy_churn_per_day=0.05,
            # Two PID types in SD-JWT VC and an attestation in mdoc: the mdoc PID left out, since publishing it would
            # have every PID offer name it too (ARF PID_02), which the engine tests cover.
            published_configurations=(PID_CONFIG, NATIONAL, IBAN),
            mdoc_signing_key=self.pki.root / "mdoc-signing.key",
            mdoc_signing_chain=self.pki.root / "mdoc-signing.pem",
            mdoc_trust_anchors=self.pki.root / "iaca.pem",
            mdoc_signer_certificate_url=f"{ISSUER}/certs/mdoc-signer.pem",
            **trust_settings(self.pki, self.trust_pki, self.root, self.lote),
        )
        config["_wallet_status"] = {**config["_wallet_status"], "revoked": str(self.revoked_file)}
        for worker in self.workers:
            worker.send("reset", config)
        assert all(worker.receive() for worker in self.workers)

    # helpers ------------------------------------------------------------------------------------------

    @classmethod
    def store_for(cls, root: Path) -> dict[str, Any]:
        if cls.postgres is None:
            return {"store_path": root / "s.db"}
        import psycopg

        name = f"model_{len(cls.databases)}_{os.getpid()}"
        with psycopg.connect(cls.postgres, autocommit=True) as admin:
            admin.execute(f"CREATE DATABASE {name}")
        cls.databases.append(name)
        return {"store_url": with_database(cls.postgres, name)}

    @property
    def now(self) -> float:
        """The time that really passed, which the host clock behind each worker's clock watch counts."""
        return self.clock.now

    @property
    def steady(self) -> bool:
        """Whether the wall clock the workers read is right. It is off while a step of the wall clock lasts, which
        may be one request or many steps (review 7, N6-L2)."""
        return self.clock.skew == 0

    def any_worker(self) -> Worker:
        return self.workers[self.pick.randrange(WORKERS)]

    def wallet(self) -> Wallet:
        client = RemoteClient(self.workers, lambda: self.pick.randrange(WORKERS))
        wallet = Wallet(client, self.pki, TrueTime(self.clock))  # type: ignore[arg-type]
        wallet.key_status_index = next(self.indexes)
        return wallet

    def code_wallet(self) -> CodeWallet:
        client = RemoteClient(self.workers, lambda: self.pick.randrange(WORKERS))
        clock = TrueTime(self.clock)
        wallet = CodeWallet(client, self.pki, clock, provider=self.trust_pki.wallet_provider)  # type: ignore[arg-type]
        wallet.client_status_offset = WALLET_STATUS
        wallet.key_status_index = next(self.indexes)
        return wallet

    @property
    def trusted(self) -> bool:
        """Whether the list in force trusts the wallet providers: their attestations, key attestations included,
        and their status lists."""
        return self.listed and not self.rolled_back

    def write_list(self, *, sequence: int | None = None) -> None:
        """The operator's job: the list as the Commission publishes it, renamed over the file cunho reads."""
        if sequence is None:
            self.sequence += 1
        named = [self.pki.wallet_ca, self.trust_pki.wallet_provider.root.cert] if self.listed else [OTHER_PROVIDER]
        signer = self.trust_pki.lote_signer.cert
        text = wallet_providers_list(self.lote_key, signer, *named, sequence=sequence or self.sequence, now=self.now)
        written = self.lote.with_suffix(".new")
        written.write_text(text)
        self.writes += 1  # a time of its own, however coarse the file system's clock
        os.utime(written, ns=(START * 10**9 + self.writes, START * 10**9 + self.writes))
        os.replace(written, self.lote)

    def live(self, offer: Offer) -> bool:
        """What `_offer_live` must answer: a login with a refresh token stays live while the token can be used."""
        if offer.closed:
            return False
        if offer.refresh_from is not None:
            return self.now < offer.refresh_from + REFRESH + TOKEN_TTL
        return self.now < offer.created + WINDOW and set(offer.configs) - offer.done != set()

    def subjects_of(self, person: str) -> list[Offer]:
        return [self.offers[s] for s in sorted(self.links[person]) if self.now < self.offers[s].linked_until]

    def live_rows(self, offers: list[Offer]) -> list[Credential]:
        subjects = {offer.subject for offer in offers}
        return [c for c in self.credentials if c.subject in subjects and self.now < c.row_expires()]

    def close(self, offers: list[Offer]) -> None:
        for offer in offers:
            offer.closed = True
        for credential in self.live_rows(offers):
            if credential.revoked_at is None:
                credential.revoked_at = self.now

    def offer_with_token(self, data: st.DataObject) -> Offer:
        candidates = [o for o in self.offers.values() if o.token_at is not None]
        return data.draw(st.sampled_from(candidates))

    def issued(self, offer: Offer, answer: Any, config: str) -> Credential:
        """A credential handed out: its validity ends no later than the status periods of the attestations behind
        it, the wallet attestation's (the code flow, VALIDITY.PID_LE_STATUS_EXP) and the key attestation's."""
        credential = answer.json()["credentials"][0]["credential"]
        if config == IBAN:
            exp, where = mdoc_validity_and_slot(credential)
        else:
            exp, where = parse_jws(credential.split("~")[0]).payload["exp"], slot(answer)
        assert exp <= min(offer.status_until, self.now + KA_STATUS), (exp, offer.status_until, self.now)
        if isinstance(answer.json().get("notification_id"), str):
            offer.notifications.append(answer.json()["notification_id"])
        return Credential(offer.subject, where, self.now, exp, offer.wallet.key_status_index)

    def issuance_expected(self, offer: Offer, config: str) -> bool:
        return (
            self.trusted
            and not offer.closed
            and not offer.erased
            and offer.wallet.key_status_index not in self.revoked_keys
            and config not in offer.claimed
            and offer.token_at is not None
            and self.now < offer.token_at + TOKEN_TTL
        )

    # rules ----------------------------------------------------------------------------------------------

    @rule(
        configs=st.sampled_from([[PID_CONFIG], [NATIONAL], [PID_CONFIG, NATIONAL], [IBAN]]),
        person=st.sampled_from([None, "p1", "p2"]),
        redeem=st.booleans(),
    )
    def create_offer(self, configs: list[str], person: str | None, redeem: bool) -> None:
        """An offer, redeemed at once when `redeem`, as a wallet scanning the code would. The mdoc attestation has
        offers of its own, its data being by namespace."""
        wallet = self.wallet()
        subject = json.loads(json.dumps(IBAN_SUBJECT)) if configs == [IBAN] else dict(PID_SUBJECT)
        body: dict[str, Any] = {"credential_configuration_ids": configs, "subject": subject}
        if person is not None:
            body["person"] = person
        reply = wallet.admin("offers", body)
        assert reply.status_code == 201, reply.text
        offer = reply.json()
        code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        self.offers[offer["subject_ref"]] = Offer(configs, person, self.now, code, offer["subject_ref"], wallet)
        if person is not None:
            self.links[person].add(offer["subject_ref"])
        if redeem:
            self._redeem(self.offers[offer["subject_ref"]])

    @rule(
        configs=st.sampled_from([[PID_CONFIG], [NATIONAL], [PID_CONFIG, NATIONAL]]),
        person=st.sampled_from([None, "p1", "p2"]),
        twice=st.booleans(),
        review=st.booleans(),
    )
    def log_in(self, configs: list[str], person: str | None, twice: bool, review: bool) -> None:
        """The code flow, each request to any worker: PAR with the wallet attestation, the browser sent to the
        operator's login service, which reports the person to cunho, and the code exchanged for an access token and
        a refresh token. When `twice`, the wallet sends the code to two workers at once: one token, and the use
        after it ends that token and closes the login (RFC 6749 §4.1.2)."""
        wallet, pkce = self.code_wallet(), Pkce.random()
        pushed = wallet.par(pkce, scope=" ".join(SCOPES[c] for c in configs), state="model")
        if not self.trusted:
            assert pushed.status_code == 401 and pushed.json()["error"] == "invalid_client", pushed.text
            return
        assert pushed.status_code == 201, pushed.text
        sent = wallet.client.get(
            f"/authorize?{urlencode({'client_id': CLIENT_ID, 'request_uri': pushed.json()['request_uri']})}",
            follow_redirects=False,
        )
        assert sent.status_code == 303 and sent.headers["location"].startswith(LOGIN_URL), sent.text
        login_state = parse_qs(urlsplit(sent.headers["location"]).query)["login_state"][0]
        report: dict[str, Any] = {"subject": dict(PID_SUBJECT), "loa": "high"}
        if person is not None:
            report["person"] = person
        if review:  # the operator holds what this login yields until it decides (deferred issuance)
            report["review"] = True
        reported = wallet.client.post(f"/admin/logins/{login_state}", json=report, headers=AUTH)
        assert reported.status_code == 200, reported.text
        subject = reported.json()["subject_ref"]
        back = wallet.client.get(reported.json()["continue"], follow_redirects=False)
        assert back.status_code == 303 and back.headers["location"].startswith(REDIRECT_URI), back.text
        params = parse_qs(urlsplit(back.headers["location"]).query)
        assert params["state"] == ["model"], params
        if twice:
            first, second = (self.workers[n] for n in self.pick.sample(range(WORKERS), 2))
            first.send("http", code_request(wallet, params["code"][0], pkce), self.pick.random() * 0.01)
            second.send("http", code_request(wallet, params["code"][0], pkce), self.pick.random() * 0.01)
            replies = [first.receive(), second.receive()]
            assert sorted(r.status_code for r in replies) == [200, 400], [r.text for r in replies]
            tokens = next(r for r in replies if r.status_code == 200)
        else:
            tokens = wallet.code_token_request(params["code"][0], pkce)
        assert tokens.status_code == 200, tokens.text
        wallet.token, wallet.refresh_token = tokens.json()["access_token"], tokens.json()["refresh_token"]
        offer = Offer(configs, person, self.now, "", subject, wallet, redeemed=True, token_at=self.now)
        offer.refresh_from, offer.status_until = self.now, self.now + WALLET_STATUS
        offer.closed = offer.erased = twice
        offer.held = review
        self.offers[subject] = offer
        if person is not None:
            self.links[person].add(subject)

    def logins(self) -> list[Offer]:
        return [o for o in self.offers.values() if o.refresh_from is not None]

    @precondition(lambda self: bool(self.logins()))
    @rule(data=st.data())
    def refresh(self, data: st.DataObject) -> None:
        """A new access token for the login, with a fresh wallet attestation of the same instance; the claims of
        the token before do not carry over."""
        offer = data.draw(st.sampled_from(self.logins()))
        assert isinstance(offer.wallet, CodeWallet) and offer.refresh_from is not None
        reply = offer.wallet.refresh_request()
        expected = self.trusted and not offer.closed and self.now < offer.refresh_from + REFRESH
        assert (reply.status_code == 200) == expected, (reply.status_code, reply.text, offer)
        if reply.status_code == 200:
            offer.wallet.token, offer.token_at, offer.claimed = reply.json()["access_token"], self.now, set()
            offer.status_until = self.now + WALLET_STATUS

    @precondition(lambda self: bool(self.logins()))
    @rule(data=st.data())
    def refresh_by_another_instance(self, data: st.DataObject) -> None:
        """The refresh token and DPoP key in another wallet instance of the same solution, attested with its own
        key: refused, whatever else holds (BATCH.REISSUE_SAME_WALLET_UNIT)."""
        offer = data.draw(st.sampled_from(self.logins()))
        assert isinstance(offer.wallet, CodeWallet)
        other = dataclasses.replace(offer.wallet, instance_key=EcKey.generate())
        reply = other.refresh_request()
        assert reply.status_code in (400, 401), (reply.status_code, reply.text)

    @precondition(lambda self: self.listed)
    @rule()
    def list_withdraws_the_wallet_providers(self) -> None:
        self.listed, self.rolled_back = False, False
        self.write_list()

    @precondition(lambda self: not self.trusted)
    @rule()
    def a_good_list_again(self) -> None:
        self.listed, self.rolled_back = True, False
        self.write_list()

    @precondition(lambda self: self.sequence > 1 and not self.rolled_back)
    @rule()
    def an_older_list_put_back(self) -> None:
        """A list with a lower sequence number than one cunho read: refused, and nothing is trusted until the job
        writes a good one (TRUST.LOTE_AUTHENTIC). cunho reads the list in force first: one it never saw cannot be
        told from the older one."""
        pushed = self.code_wallet().par(Pkce.random(), scope=SCOPES[PID_CONFIG])
        assert (pushed.status_code == 201) == self.trusted, pushed.text
        self.rolled_back = True
        self.write_list(sequence=self.sequence - 1)

    @precondition(lambda self: bool(self.offers))
    @rule(data=st.data())
    def redeem(self, data: st.DataObject) -> None:
        self._redeem(data.draw(st.sampled_from(list(self.offers.values()))))

    def _redeem(self, offer: Offer) -> None:
        reply = offer.wallet.token_request(offer.code)
        expected = not offer.closed and not offer.redeemed and self.now < offer.created + OFFER_TTL
        assert (reply.status_code == 200) == expected, (reply.status_code, reply.text, offer)
        if reply.status_code == 200:
            offer.redeemed, offer.token_at = True, self.now
            offer.wallet.token = reply.json()["access_token"]

    @precondition(lambda self: any(o.token_at is not None for o in self.offers.values()))
    @rule(data=st.data())
    def issue_one(self, data: st.DataObject) -> None:
        self.issue(data)

    @precondition(lambda self: any(o.token_at is not None for o in self.offers.values()))
    @rule(data=st.data())
    def issue(self, data: st.DataObject) -> None:
        offer = self.offer_with_token(data)
        config = data.draw(st.sampled_from(offer.configs))
        expected = self.issuance_expected(offer, config)
        reply = self.any_worker()
        reply.send("http", credential_request(offer.wallet, config))
        answer = reply.receive()
        if offer.held:  # held for review: the request is answered 202 with a transaction, and nothing is signed
            assert (answer.status_code == 202) == expected, (answer.status_code, answer.text, offer, config)
            if answer.status_code == 202:
                offer.claimed.add(config)
                self.hold(offer, config, answer.json()["transaction_id"])
            return
        assert (answer.status_code == 200) == expected, (answer.status_code, answer.text, offer, config)
        if answer.status_code == 200:
            offer.claimed.add(config)
            offer.done.add(config)
            self.credentials.append(self.issued(offer, answer, config))

    @precondition(lambda self: any(o.token_at is not None and not o.closed for o in self.offers.values()))
    @rule(data=st.data())
    def race(self, data: st.DataObject) -> None:
        self.race_issuance_and_revocation(data)

    @precondition(lambda self: any(o.token_at is not None and not o.closed for o in self.offers.values()))
    @rule(data=st.data())
    def race_issuance_and_revocation(self, data: st.DataObject) -> None:
        """The remaining configurations on some workers, the revocation of the subject on another."""
        offer = data.draw(st.sampled_from([o for o in self.offers.values() if o.token_at is not None and not o.closed]))
        rows = self.live_rows([offer])
        before = [c for c in rows if c.revoked_at is None]
        sends = [credential_request(offer.wallet, config) for config in offer.configs]
        revocation = request("post", "/admin/revocations", json={"subject_ref": offer.subject, "reason": "death"})
        revocation[2]["headers"] = AUTH
        order = self.pick.sample(range(WORKERS), len(sends) + 1)
        for worker, message in zip(order, [*sends, revocation], strict=True):
            self.workers[worker].send("http", message, self.pick.random() * 0.02)
        replies = [self.workers[worker].receive() for worker in order]
        *answers, revoked = replies
        issued = [answer for answer in answers if answer.status_code == 200]
        expected = bool(rows) or self.live(offer) or bool(issued)
        assert (revoked.status_code == 200) == expected, (revoked.text, offer)
        for config, answer in zip(offer.configs, answers, strict=True):
            if answer.status_code == 200:
                assert self.issuance_expected(offer, config), (offer, config)
                offer.done.add(config)
                self.credentials.append(self.issued(offer, answer, config))
            offer.claimed.add(config)
        if revoked.status_code == 200:
            assert revoked.json()["revoked"] == len(before) + len(issued), (revoked.json(), before, issued)
            self.close([offer])
            offer.erased = True

    @precondition(lambda self: bool(self.offers))
    @rule(data=st.data())
    def revoke_subject(self, data: st.DataObject) -> None:
        offer = data.draw(st.sampled_from(list(self.offers.values())))
        rows = self.live_rows([offer])
        live = self.live(offer)
        reply = self.wallet().admin("revocations", {"subject_ref": offer.subject, "reason": "compromise"})
        assert (reply.status_code == 200) == (bool(rows) or live), (reply.text, offer)
        if reply.status_code == 200:
            expected = {"revoked": sum(1 for c in rows if c.revoked_at is None)}
            if live:
                expected["offer_cancelled"] = True
            assert reply.json() == expected, (reply.json(), expected)
            self.close([offer])
            offer.erased = True

    @rule(person=st.sampled_from(["p1", "p2"]))
    def revoke_person(self, person: str) -> None:
        offers = self.subjects_of(person)
        rows = self.live_rows(offers)
        live = [offer for offer in offers if self.live(offer)]
        reply = self.wallet().admin("revocations", {"person": person, "reason": "death"})
        assert (reply.status_code == 200) == (bool(rows) or bool(live)), (reply.text, offers)
        if reply.status_code == 200:
            revoked = sum(1 for c in rows if c.revoked_at is None)
            assert reply.json() == {"revoked": revoked, "subjects": len(offers), "offers_cancelled": len(live)}
            self.close(offers)
            for offer in offers:
                offer.erased = True

    @precondition(lambda self: bool(self.offers))
    @rule(data=st.data())
    def cancel(self, data: st.DataObject) -> None:
        offer = data.draw(st.sampled_from(list(self.offers.values())))
        live = self.live(offer)
        reply = self.wallet().client.post(f"/admin/offers/{offer.subject}/cancel", headers=AUTH)
        assert (reply.status_code == 200) == live, (reply.text, offer)
        if live:
            offer.closed = offer.erased = True

    @precondition(lambda self: bool(self.offers))
    @rule(data=st.data())
    def erase(self, data: st.DataObject) -> None:
        offer = data.draw(st.sampled_from(list(self.offers.values())))
        reply = self.wallet().client.post(f"/admin/subjects/{offer.subject}/erase", headers=AUTH)
        assert reply.status_code == 204, reply.text
        offer.erased = offer.closed = True  # an erasure closes the offer too (N6-L3)
        if offer.person is not None:
            self.links[offer.person].discard(offer.subject)

    @rule(seconds=st.sampled_from([1, 1, 30, 30, 61, 61, 299, 601, 3600, 2 * 86_400]))
    def time_passes(self, seconds: int) -> None:
        """Time moves on, and the operator's job renews the list as it does, before its next update."""
        self.clock.now += seconds
        self.rolled_back = False
        self.write_list()

    @rule()
    def maintenance(self) -> None:
        """Maintenance as the background task runs it, not forced: when it is due, by the clock watch's time, and
        pruning only once the watch has settled and while the wall clock does not read behind (review 7,
        N6-L2)."""
        watched = self.chained()
        done = self.any_worker().call("maintenance")
        assert done == {} or "expired_entries" in done, done
        self.chain_ran(done, watched)  # maintenance runs the chaining job too, when it is due
        if not self.steady and self.clock.skew < -CLOCK_TOLERANCE and done:
            assert done["audit_pruning_held"] == 1, done

    @precondition(lambda self: self.steady)
    @rule(skew=st.sampled_from([-2 * DAY, -3 * 3600, -1200, 1200, 7000, 2 * DAY, 400 * DAY]))
    def wall_clock_steps(self, skew: int) -> None:
        """The wall clock is stepped, and stays off for the steps that follow, polls included (review 7, M1)."""
        self.clock.skew = skew

    @precondition(lambda self: not self.steady)
    @rule()
    def wall_clock_put_right(self) -> None:
        self.clock.skew = 0.0

    @rule()
    def background_tick(self) -> None:
        self.any_worker().call("sweep")

    @precondition(lambda self: self.steady and self.trusted)
    @rule(skew=st.integers(min_value=-2 * DAY, max_value=2 * DAY))
    def revoke_under_a_wrong_clock(self, skew: int) -> None:
        """A PID issued, then revoked by its slot on a worker whose wall clock reads `skew` seconds off (N6-M1)."""
        wallet = self.wallet()
        reply = wallet.admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": dict(PID_SUBJECT)})
        code = reply.json()["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        offer = Offer([PID_CONFIG], None, self.now, code, reply.json()["subject_ref"], wallet)
        self.offers[offer.subject] = offer
        self._redeem(offer)
        worker = self.any_worker()
        worker.send("http", credential_request(wallet, PID_CONFIG))
        answer = worker.receive()
        assert answer.status_code == 200, answer.text
        offer.claimed.add(PID_CONFIG)
        offer.done.add(PID_CONFIG)
        credential = self.issued(offer, answer, PID_CONFIG)
        self.credentials.append(credential)
        message = request("post", "/admin/revocations", json={"list": credential.slot[0], "index": credential.slot[1]})
        message[2]["json"]["reason"], message[2]["headers"] = "compromise", AUTH
        worker = self.any_worker()
        self.clock.skew = skew
        try:
            worker.send("http", message)
            reply = worker.receive()
        finally:
            self.clock.skew = 0.0
        assert reply.json() == {"revoked": 1}, reply.text
        credential.revoked_at = self.now

    @rule(kind=st.sampled_from(["torn", "nul", "garbage"]))
    def anchor_damaged(self, kind: str) -> None:
        """A write cut short, NUL bytes after a power loss, or bytes no line accounts for, then the background
        repair on another worker."""
        last = self.anchor.read_bytes().splitlines(keepends=True)[-1]
        junk = {"torn": last[: len(last) // 2], "nul": b"\x00" * 50, "garbage": b"\xff\n not a line \n"}[kind]
        with self.anchor.open("ab") as handle:
            handle.write(junk)
        ok, detail = self.any_worker().call("audit.verify")
        assert not ok and "after its last line" in detail, detail
        self.any_worker().call("sweep")

    @rule(data=st.data())
    def anchor_line_copied(self, data: st.DataObject) -> None:
        """A copy of one of the anchor's own lines appended: verify fails and nothing is logged until the operator
        removes it (N6-H1)."""
        content = self.anchor.read_bytes()
        lines = [line for line in content.splitlines(keepends=True) if _whole(line)]
        copy = lines[data.draw(st.integers(0, 10**6)) % len(lines)]  # how many lines there are is not the model's
        with self.anchor.open("ab") as handle:
            handle.write(copy)
        ok, detail = self.any_worker().call("audit.verify")
        assert not ok and "repeats or goes back" in detail, detail
        with pytest.raises(AuditError, match="repeats or goes back"):
            self.any_worker().call("audit.repair")
        reply = self.wallet().admin("offers", {"credential_configuration_ids": [PID_CONFIG], "subject": PID_SUBJECT})
        assert reply.status_code == 500, reply.text
        with self.anchor.open("r+b") as handle:
            handle.truncate(len(content))

    @rule()
    def maintenance_alongside_verify_and_an_offer(self) -> None:
        """Pruning on one worker while another verifies and a third logs a new offer. An interval passes first,
        so maintenance is due on every worker, and it runs unforced."""
        self.clock.now += 3600 + 2 * CLOCK_TOLERANCE
        self.rolled_back = False
        self.write_list()
        body = {"credential_configuration_ids": [PID_CONFIG], "subject": dict(PID_SUBJECT)}
        offer_request = request("post", "/admin/offers", json=body, headers=AUTH)
        first, second, third = (self.workers[n] for n in self.pick.sample(range(WORKERS), 3))
        watched = self.chained()
        first.send("maintenance", ((), {}))
        second.send("audit.verify", ((), {}))
        third.send("http", offer_request)
        done, (ok, detail), reply = first.receive(), second.receive(), third.receive()
        assert "expired_entries" in done and ok and reply.status_code == 201, (done, detail, reply.text)
        self.chain_ran(done, watched)
        offer = reply.json()
        code = offer["credential_offer"]["grants"][PRE_AUTH]["pre-authorized_code"]
        self.offers[offer["subject_ref"]] = Offer(
            [PID_CONFIG], None, self.now, code, offer["subject_ref"], self.wallet()
        )

    # M4: deferred issuance, notification, revocation chaining ---------------------------------------------

    def hold(self, offer: Offer, config: str, transaction_id: str) -> None:
        """A held issuance lasts deferred_ttl, but never past the last token its login can still get: the later of
        the current access token's and the refresh token's expiry (a refresh does not move the refresh token's)."""
        assert offer.token_at is not None and offer.refresh_from is not None
        reach = max(offer.token_at + TOKEN_TTL, offer.refresh_from + REFRESH) - int(self.now)
        offer.transactions[config] = [transaction_id, "held"]
        offer.held_until[config] = int(self.now) + max(min(DEFERRED_TTL, reach), 1)

    def expired(self, offer: Offer, config: str) -> bool:
        """Its time is up: the issuer forgets it, whatever its state, so the wallet's transaction_id is unknown."""
        return self.now >= offer.held_until[config]

    def transactions(self, *states: str) -> list[tuple[Offer, str]]:
        return [
            (offer, config)
            for offer in self.offers.values()
            for config, (_, state) in offer.transactions.items()
            if state in states
        ]

    @precondition(lambda self: bool(self.transactions("held")))
    @rule(data=st.data(), release=st.booleans())
    def operator_decides(self, data: st.DataObject, release: bool) -> None:
        """The operator releases or refuses a held issuance, by the reference /admin/deferred lists for it. Once its
        subject is closed (DEFERRED.DROPPED_ON_CLOSE) or its time is up, it is gone from the list."""
        offer, config = data.draw(st.sampled_from(self.transactions("held")))
        listed = self.wallet().client.get("/admin/deferred", headers=AUTH)
        assert listed.status_code == 200, listed.text
        rows = [
            r
            for r in listed.json()["deferred"]
            if r["subject_ref"] == offer.subject and r["configuration_id"] == config
        ]
        if offer.closed or self.expired(offer, config):
            assert rows == [], rows
            offer.transactions[config][1] = "dropped"
            return
        assert [r["state"] for r in rows] == ["held"], rows
        decision = "release" if release else "refuse"
        reply = self.wallet().client.post(f"/admin/deferred/{rows[0]['ref']}/{decision}", headers=AUTH)
        assert reply.status_code == 200 and reply.json() == {"state": f"{decision}d"}, reply.text
        offer.transactions[config][1] = f"{decision}d"

    @precondition(lambda self: bool(self.transactions("held", "released", "refused", "collected", "dropped")))
    @rule(data=st.data())
    def collect(self, data: st.DataObject) -> None:
        """The wallet asks the deferred endpoint, with the access token it holds now (a refresh may have replaced the
        one it asked with)."""
        offer, config = data.draw(
            st.sampled_from(self.transactions("held", "released", "refused", "collected", "dropped"))
        )
        transaction_id, state = offer.transactions[config]
        reply = deferred(offer.wallet, {"transaction_id": transaction_id})
        assert offer.token_at is not None
        if self.now >= offer.token_at + TOKEN_TTL:
            assert reply.status_code == 401, reply.text
            return
        if offer.closed:
            assert reply.status_code in (400, 401), reply.text
            if reply.status_code == 400:
                assert reply.json()["error"] in ("credential_request_denied", "invalid_transaction_id"), reply.text
            offer.transactions[config][1] = "dropped"
            return
        if self.expired(offer, config) and state != "collected":
            state = offer.transactions[config][1] = "dropped"
        error = reply.json().get("error") if reply.status_code == 400 else None
        if state in ("collected", "dropped"):
            assert error == "invalid_transaction_id", reply.text
        elif state == "held":
            assert reply.status_code == 202 and reply.json()["transaction_id"] == transaction_id, reply.text
        elif state == "refused":  # denied each time it is asked, until it is dropped with its subject or its time
            assert error == "credential_request_denied", reply.text
        elif offer.wallet.key_status_index in self.revoked_keys and self.trusted:
            assert error == "credential_request_denied", reply.text  # KA.STATUS_AT_ISSUANCE, read again
        elif not self.trusted:
            # The wallet provider's list cannot be read: the issuance waits, as the wallet may ask again (§9.2).
            assert reply.status_code == 202, reply.text
        else:
            assert reply.status_code == 200, reply.text
            offer.done.add(config)
            self.credentials.append(self.issued(offer, reply, config))
            offer.transactions[config][1] = "collected"

    @precondition(lambda self: self.trusted)
    @rule(release=st.booleans())
    def a_held_issuance_from_login_to_collection(self, release: bool) -> None:
        """One held issuance through every step at once, so the model sees the collected credential each run: the
        login with review, the request answered 202, the operator's decision, and the wallet collecting with the
        token it has, which answers 200 once released (its credential tracked as any other) and denied once
        refused."""
        before = set(self.offers)
        self.log_in([PID_CONFIG], None, False, True)
        [offer] = [self.offers[subject] for subject in set(self.offers) - before]
        reply = self.any_worker()
        reply.send("http", credential_request(offer.wallet, PID_CONFIG))
        answer = reply.receive()
        assert answer.status_code == 202, answer.text
        offer.claimed.add(PID_CONFIG)
        self.hold(offer, PID_CONFIG, answer.json()["transaction_id"])
        listed = self.wallet().client.get("/admin/deferred", headers=AUTH).json()["deferred"]
        [row] = [r for r in listed if r["subject_ref"] == offer.subject]
        decision = "release" if release else "refuse"
        decided = self.wallet().client.post(f"/admin/deferred/{row['ref']}/{decision}", headers=AUTH)
        assert decided.status_code == 200, decided.text
        offer.transactions[PID_CONFIG][1] = f"{decision}d"
        collected = deferred(offer.wallet, {"transaction_id": offer.transactions[PID_CONFIG][0]})
        if not release:
            assert collected.status_code == 400 and collected.json()["error"] == "credential_request_denied"
            return
        assert collected.status_code == 200, collected.text
        offer.done.add(PID_CONFIG)
        self.credentials.append(self.issued(offer, collected, PID_CONFIG))
        offer.transactions[PID_CONFIG][1] = "collected"

    @precondition(lambda self: self.trusted)
    @rule()
    def a_released_issuance_outlived_by_its_login(self) -> None:
        """A hold never outlasts the refresh token of its login, so random steps rarely reach its end: here one is
        released, the wallet refreshes just before the refresh token expires, and once that expiry passes the
        released issuance is gone, from the operator's list and for the wallet, whose access token still works."""
        before = set(self.offers)
        self.log_in([PID_CONFIG], None, False, True)
        [offer] = [self.offers[subject] for subject in set(self.offers) - before]
        assert isinstance(offer.wallet, CodeWallet) and offer.refresh_from is not None
        reply = self.any_worker()
        reply.send("http", credential_request(offer.wallet, PID_CONFIG))
        answer = reply.receive()
        assert answer.status_code == 202, answer.text
        offer.claimed.add(PID_CONFIG)
        self.hold(offer, PID_CONFIG, answer.json()["transaction_id"])
        listed = self.wallet().client.get("/admin/deferred", headers=AUTH).json()["deferred"]
        [row] = [r for r in listed if r["subject_ref"] == offer.subject]
        released = self.wallet().client.post(f"/admin/deferred/{row['ref']}/release", headers=AUTH)
        assert released.status_code == 200, released.text
        offer.transactions[PID_CONFIG][1] = "released"
        self.time_passes(int(offer.refresh_from + REFRESH - 60 - self.now))
        refreshed = offer.wallet.refresh_request()
        assert refreshed.status_code == 200, refreshed.text
        offer.wallet.token, offer.token_at, offer.claimed = refreshed.json()["access_token"], self.now, set()
        offer.status_until = self.now + WALLET_STATUS
        self.time_passes(120)
        assert self.expired(offer, PID_CONFIG) and self.now < offer.token_at + TOKEN_TTL
        listed = self.wallet().client.get("/admin/deferred", headers=AUTH).json()["deferred"]
        assert [r for r in listed if r["subject_ref"] == offer.subject] == [], listed
        collected = deferred(offer.wallet, {"transaction_id": offer.transactions[PID_CONFIG][0]})
        assert collected.status_code == 400 and collected.json()["error"] == "invalid_transaction_id", collected.text
        offer.transactions[PID_CONFIG][1] = "dropped"

    def notifiable(self) -> list[Offer]:
        return [
            o
            for o in self.offers.values()
            if o.notifications and not o.closed and o.token_at is not None and self.now < o.token_at + TOKEN_TTL
        ]

    @precondition(lambda self: bool(self.notifiable()))
    @rule(data=st.data(), event=st.sampled_from(["credential_accepted", "credential_failure", "credential_deleted"]))
    def notification(self, data: st.DataObject, event: str) -> None:
        """The wallet tells what became of an issuance; another wallet with a live token of its own cannot use that
        notification_id (VCI.NOTIF.VALIDATION)."""
        offer = data.draw(st.sampled_from(self.notifiable()))
        notification_id = data.draw(st.sampled_from(offer.notifications))
        reply = notify(offer.wallet, {"notification_id": notification_id, "event": event})
        assert reply.status_code == 204, reply.text
        others = [o for o in self.notifiable() if o.subject != offer.subject]
        if others:
            stranger = data.draw(st.sampled_from(others))
            refused = notify(stranger.wallet, {"notification_id": notification_id, "event": event})
            assert refused.status_code == 400 and refused.json()["error"] == "invalid_notification_id", refused.text

    @precondition(lambda self: any(c.revoked_at is None for c in self.credentials))
    @rule(data=st.data())
    def wallet_provider_revokes_a_key_attestation(self, data: st.DataObject) -> None:
        """The wallet provider revokes one wallet's key attestations on its status list (its key storage was
        compromised): what that wallet asks for from now is refused, and chaining revokes what it holds."""
        index = data.draw(st.sampled_from(sorted({c.key_index for c in self.credentials if c.revoked_at is None})))
        if index in self.revoked_keys:
            return
        self.revoked_keys[index] = self.now
        listed = {KA_LIST: sorted(self.revoked_keys)}
        written = self.revoked_file.with_suffix(".new")
        written.write_text(json.dumps(listed))
        os.replace(written, self.revoked_file)

    def chained(self) -> list[Credential]:
        """The live credentials chaining watches: unrevoked, valid, issued to live more than a day."""
        return [c for c in self.credentials if c.revoked_at is None and self.now < c.exp and c.exp - c.issued > DAY]

    def chain_ran(self, result: dict[str, Any], watched: list[Credential]) -> None:
        """What a chaining run that reported `result` must have done: revoked every credential it watched whose key
        attestation the wallet provider revoked, and nothing while the list of wallet providers is not trusted, as
        their status lists cannot be read then and a revocation could not be undone."""
        if not any(name.startswith("chain_") for name in result):
            return
        hit = [c for c in watched if c.key_index in self.revoked_keys]
        if not self.trusted:
            assert result.get("chain_revoked", 0) == 0, result
            return
        assert result.get("chain_revoked", 0) == len(hit), (result, hit)
        for credential in hit:
            credential.revoked_at = self.now

    @rule()
    def chaining_tick(self) -> None:
        """The background loop's chaining call, on any worker, unforced: it runs once its interval has passed since
        the last run started, by the time cunho recorded for that start, whichever worker started it, maintenance
        included; a due run with live credentials to watch reports what it did (LC_GEN-4: never more than an
        interval apart)."""
        worker = self.any_worker()
        last = worker.call("store.get", "chain-last", "run")
        due = last is None or self.now - float(last) >= CHAIN
        watched = self.chained()
        result = self.any_worker().call("chain")
        if not due:
            assert result == {}, (result, last, self.now)
            return
        if watched:
            assert result, ("a chaining run was due and did not run", watched, last, self.now)
        self.chain_ran(result, watched)

    # invariants -------------------------------------------------------------------------------------------

    @invariant()
    def no_held_issuance_outlives_its_subject(self) -> None:
        """Revocation, cancellation, erasure and a reused code close a subject, and its held issuances go with it."""
        worker = self.any_worker()
        for offer in self.offers.values():
            if offer.closed and offer.transactions:
                assert worker.call("store.items", "deferred", f"{offer.subject}:") == [], offer

    @invariant()
    def the_log_verifies(self) -> None:
        ok, detail = self.any_worker().call("audit.verify")
        assert ok, detail

    @invariant()
    def revoked_means_revoked(self) -> None:
        for credential in self.credentials:
            bit = self.any_worker().status(*credential.slot)
            assert bit == (1 if credential.revoked_at is not None else 0), credential

    @invariant()
    def the_published_list_agrees(self) -> None:
        if not self.credentials:
            return
        worker = self.any_worker()
        for list_id in sorted({c.slot[0] for c in self.credentials}):
            for key, _ in worker.call("store.items", "status-pending", f"{list_id}:"):
                _, moment, index = key.split(":")
                self.moments.setdefault((list_id, int(index)), int(moment) / 1000)
            payload = parse_jws(self.wallet().client.get(f"/status/{list_id}").text).payload
            publication = payload["iat"]
            bits = zlib.decompress(b64u_decode(payload["status_list"]["lst"]))
            shown = {n for n in range(len(bits) * 8) if bits[n // 8] >> (n % 8) & 1}
            slots = worker.call("store.items", "status-slot", f"{list_id}:")
            assert shown <= {int(key.split(":")[1]) for key, value in slots if value == 1}, "only revoked slots show"
            for index in shown:
                moment = self.moments.get((list_id, index), 0.0)
                assert moment <= publication, ("shown before its moment", list_id, index, moment, publication)
            for c in (c for c in self.credentials if c.slot[0] == list_id):
                if c.revoked_at is None:
                    assert c.slot[1] not in shown, c
                elif c.revoked_at + JITTER + CLOCK_TOLERANCE <= publication:
                    assert c.slot[1] in shown, (c, publication)


OTHER_PROVIDER = certificate("Another Wallet Provider", EcKey.generate().private, ca=True)


def mdoc_validity_and_slot(credential: str) -> tuple[float, tuple[str, int]]:
    """An mdoc's validUntil and the status list entry its MSO names."""
    mso = cbor2.loads(cbor2.loads(decoded(credential)["issuerAuth"][2]).value)
    ref = mso["status"]["status_list"]
    return mso["validityInfo"]["validUntil"].timestamp(), (ref["uri"].rsplit("/", 1)[1], ref["idx"])


def code_request(wallet: CodeWallet, code: str, pkce: Pkce) -> tuple[str, str, dict[str, Any]]:
    """The token request `CodeWallet.code_token_request` would send, built here so it can go to any worker."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": pkce.verifier,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
    }
    headers = [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("DPoP", wallet.dpop("POST", f"{ISSUER}/token")),
        *wallet.attestation_headers(),
    ]
    return request("post", "/token", content=urlencode(form), headers=headers)


def trust_settings(pki: Pki, trust: TestPki, root: Path, lote: Path) -> dict[str, Any]:
    """The Commission's list and its pinned signer, the operator's CRL file for certificates that name no
    distribution point, the code flow's login service and redirect URI, and the CA the workers' status lists are
    signed under."""
    crls = root / "wallet-providers.crl"
    if not crls.exists():
        build, far = Builder(trust.now), trust.now + dt.timedelta(days=3650)
        wp = trust.wallet_provider
        fresh = [build.crl(wp.root, next_update=far), build.crl(wp.intermediate, next_update=far)]
        crls.write_bytes(crl(pki.wallet_ca, pki.wallet_ca_key) + b"".join(c.public_bytes(PEM) for c in fresh))
        (root / "lote-signer.pem").write_bytes(trust.lote_signer.pem)
    return {
        "lote_path": lote,
        "lote_signer": root / "lote-signer.pem",
        "wallet_provider_anchors": None,
        "wallet_provider_crls": crls,
        "login_url": LOGIN_URL,
        "redirect_uris": {CLIENT_ID: (REDIRECT_URI,)},
        "refresh_token_ttl": REFRESH,
        "_wallet_status": {"certificate": pem(pki.wallet_ca), "key": key_pem(pki.wallet_ca_key)},
    }


PEM = serialization.Encoding.PEM


def _whole(line: bytes) -> bool:
    """A line of the anchor itself, not one of the damaged stretches a line declares."""
    try:
        return "tag" in json.loads(line)
    except ValueError:
        return False


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    return Pki.create(tmp_path_factory.mktemp("pki"))


@pytest.fixture(params=["sqlite", "postgres"])
def machine(pki: Pki, tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[type[Cunho]]:
    first = tmp_path / "first"
    first.mkdir()
    Cunho.postgres = request.getfixturevalue("postgres") if request.param == "postgres" else None
    Cunho.databases = []
    config = settings_kwargs(
        pki,
        **Cunho.store_for(first),
        secret_key_file=first / "m.key",
        audit_anchor_path=first / "audit.anchor",
        metadata_dir=two_configurations(first),
    )
    running, clock = start(first, config, WORKERS, START + 1234, slow_signing=0.01)
    Cunho.workers, Cunho.clock, Cunho.pki, Cunho.root = running, clock, pki, tmp_path
    Cunho.trust_pki = TestPki.create(dt.datetime.fromtimestamp(START, dt.UTC))
    Cunho.lote_key = EcKey(Cunho.trust_pki.lote_signer.key)
    try:
        yield Cunho
    finally:
        for worker in running:
            worker.stop()
        if Cunho.postgres is not None:
            import psycopg

            with psycopg.connect(Cunho.postgres, autocommit=True) as admin:
                for name in Cunho.databases:
                    admin.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")


def test_cunho_against_its_model_across_worker_processes(machine: type[Cunho]) -> None:
    run_state_machine_as_test(
        machine,
        settings=settings(
            max_examples=int(os.environ.get("CUNHO_MODEL_EXAMPLES", "150")),  # fewer for a quick look
            stateful_step_count=60,
            deadline=None,
            database=None,
            suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
        ),
    )
