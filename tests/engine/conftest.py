from __future__ import annotations

import datetime as dt
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.app import create_app
from cunho.errors import IssuerError, observers
from cunho.rules import reached
from cunho.service import Issuer
from cunho.settings import Settings
from cunho.store import MemoryStore

from .codewallet import CLIENT_ID, REDIRECT_URI, CodeWallet
from .helpers import ISSUER, PID_SUBJECT, START, Clock, Pki, Wallet, settings_kwargs
from .pki import TestPki
from .rulecheck import ENFORCED

# Rules fired per test function, summed over its parametrized cases, and how many cases are left to run.
_FIRED: dict[str, set[str]] = {}
_REACHED: dict[str, set[str]] = {}
_LEFT: dict[str, int] = {}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "covers(*rules): binder rule ids whose refusals this test proves")
    config.addinivalue_line("markers", "obligation(*rules): binder rule ids whose required behaviour this test proves")


def _function(item: pytest.Item) -> str:
    return item.nodeid.split("[", 1)[0]


def pytest_collection_finish(session: pytest.Session) -> None:
    for item in session.items:
        _LEFT[_function(item)] = _LEFT.get(_function(item), 0) + 1


@pytest.fixture(autouse=True)
def _covered_rules_fire(request: pytest.FixtureRequest) -> Iterator[None]:
    """A test marked covers(rule) must make that rule refuse something, in at least one of its cases.

    Every refusal reports its rule id as it is raised. Counting a marker as proof was not enough: a
    mutation run switched rules off with the suite still green (review 2, N-M6).
    """
    name = _function(request.node)
    fired = _FIRED.setdefault(name, set())
    ran = _REACHED.setdefault(name, set())

    def observe(error: IssuerError) -> None:
        fired.add(error.rule)

    def reach(rules: tuple[str, ...]) -> None:
        ran.update(rules)

    observers.append(observe)
    reached.append(reach)
    try:
        yield
    finally:
        observers.remove(observe)
        reached.remove(reach)
    _LEFT[name] = _LEFT.get(name, 1) - 1
    if _LEFT[name] > 0:
        return
    # An obligation test must at least run the code that claims to fulfil the rule. A marker alone let a rule
    # stand on a function that did something else (registry: META.PREFERRED_STATUS_PERIODS).
    obliged = {rule for marker in request.node.iter_markers("obligation") for rule in marker.args}
    unreached = sorted(obliged - ran)
    assert not unreached, f"{name} claims the obligations {unreached}, but no code that implements them ran"
    claimed = {rule for marker in request.node.iter_markers("covers") for rule in marker.args}
    never_refused = sorted(claimed - ENFORCED)
    assert not never_refused, f"covers names rules the code never refuses on (use obligation): {never_refused}"
    silent = sorted(claimed - fired)
    assert not silent, f"{name} claims to trigger {silent}, but those rules never refused anything"


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Pki:
    return Pki.create(tmp_path_factory.mktemp("pki"))


@pytest.fixture(scope="session")
def trust_pki(tmp_path_factory: pytest.TempPathFactory) -> TestPki:
    """The M3 test PKI (tests/engine/pki.py), with its files written once per session."""
    built = TestPki.create(dt.datetime.fromtimestamp(START, dt.UTC))
    built.write(tmp_path_factory.mktemp("trust-pki"))
    return built


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def make_issuer(pki: Pki, clock: Clock) -> Callable[..., Issuer]:
    def build(**overrides: Any) -> Issuer:
        store = overrides.pop("store", None)
        if store is None:  # not `or`: an empty MemoryStore is falsy and would be replaced by a new one
            store = MemoryStore(clock)
        fetcher = overrides.pop("fetcher", None)
        return Issuer(Settings(**settings_kwargs(pki, **overrides)), store=store, clock=clock, fetcher=fetcher)

    return build


@pytest.fixture
def issuer(make_issuer: Callable[..., Issuer]) -> Issuer:
    return make_issuer()


@pytest.fixture
def client(issuer: Issuer) -> Iterator[TestClient]:
    app = create_app(issuer=issuer, background_maintenance=False)
    with TestClient(app, base_url=ISSUER, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def wallet(client: TestClient, pki: Pki, clock: Clock) -> Wallet:
    return Wallet(client, pki, clock)


@pytest.fixture
def wallet_for(pki: Pki, clock: Clock) -> Iterator[Callable[[Issuer], Wallet]]:
    """A wallet in front of an issuer the test built itself, with settings of its own."""
    clients: list[TestClient] = []

    def make(issuer: Issuer) -> Wallet:
        app = create_app(issuer=issuer, background_maintenance=False)
        client = TestClient(app, base_url=ISSUER, raise_server_exceptions=False)
        clients.append(client.__enter__())
        return Wallet(client, pki, clock)

    yield make
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture(scope="session")
def code_files(pki: Pki, trust_pki: TestPki, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Anchors for both test PKIs (M2's key attestations, M3's wallet attestations) and the test login persons."""
    root = tmp_path_factory.mktemp("code-flow")
    anchors = root / "anchors.pem"
    anchors.write_bytes((pki.root / "wallet-providers.pem").read_bytes() + trust_pki.wallet_provider.root.pem)
    persons = root / "persons.json"
    persons.write_text(json.dumps({"ana": PID_SUBJECT}))
    return {"anchors": anchors, "persons": persons}


@pytest.fixture
def make_code_issuer(make_issuer: Callable[..., Issuer], code_files: dict[str, Path]) -> Callable[..., Issuer]:
    """An issuer that runs the authorization code flow with the built-in test login, and `overrides`."""

    def build(**overrides: Any) -> Issuer:
        settings = {
            "wallet_provider_anchors": code_files["anchors"],
            "test_login_persons": code_files["persons"],
            "redirect_uris": {CLIENT_ID: (REDIRECT_URI,)},
        }
        return make_issuer(**{**settings, **overrides})

    return build


@pytest.fixture
def code_issuer(make_code_issuer: Callable[..., Issuer]) -> Issuer:
    return make_code_issuer()


@pytest.fixture
def code_wallet_for(pki: Pki, clock: Clock, trust_pki: TestPki) -> Iterator[Callable[[Issuer], CodeWallet]]:
    """A code-flow wallet in front of an issuer, attested by the test PKI's wallet provider."""
    clients: list[TestClient] = []

    def make(issuer: Issuer) -> CodeWallet:
        app = create_app(issuer=issuer, background_maintenance=False)
        client = TestClient(app, base_url=ISSUER, raise_server_exceptions=False)
        clients.append(client.__enter__())
        return CodeWallet(client, pki, clock, provider=trust_pki.wallet_provider)

    yield make
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def code_wallet(code_issuer: Issuer, code_wallet_for: Callable[[Issuer], CodeWallet]) -> CodeWallet:
    return code_wallet_for(code_issuer)


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    return tmp_path
