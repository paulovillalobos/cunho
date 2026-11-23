"""Operator tokens with a scope of their own (operator_scopes): what each token may do at the admin API, for which
credential configurations, and at what rate. Without scopes every operator token is a master
key: a learning platform's token could create any offer, cancel, erase, decide deferred issuances, read the audit,
and revoke every credential the deployment issued by sweeping status list slots, and its learners shared the
operator console's rate limit."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from cunho.errors import ConfigError
from cunho.service import Issuer
from cunho.settings import DEFAULT_PERMISSIONS, OPERATOR_PERMISSIONS, OperatorScope, Settings

from .codewallet import CodeWallet, Pkce
from .helpers import ADMIN_TOKEN, ISSUER, Clock, Pki, Wallet, raised_by, refused_by, settings_kwargs
from .test_course_certificate import COURSE, COURSE_SUBJECT, MDOC, SD_JWT, mdoc_subject
from .test_mdoc import mdoc_settings

RULE = "ISS.SUBJECT.ENTITLEMENT"
MOODLE, REGISTRAR, SLOTS, DESK = "m" * 40, "r" * 40, "s" * 40, "d" * 40
LMS, CERTIFYGEN, REVIEWER, WIDE, LOGINS = "l" * 40, "c" * 40, "v" * 40, "w" * 40, "g" * 40
OPERATORS = {
    "moodle": MOODLE,
    "registrar": REGISTRAR,
    "slots": SLOTS,
    "desk": DESK,
    "lms": LMS,
    "certifygen": CERTIFYGEN,
    "reviewer": REVIEWER,
    "wide": WIDE,
    "loginsvc": LOGINS,
}
SCOPES = {
    # A learning platform: offers of the SD-JWT VC course certificate, and how they got on; nothing else.
    "moodle": OperatorScope(frozenset({"offers", "offers.read"}), frozenset({SD_JWT})),
    # A registrar's office: revokes and erases course certificates in SD-JWT VC, by subject or person.
    "registrar": OperatorScope(frozenset({"revoke", "erase", "offers.read"}), frozenset({SD_JWT})),
    # The one token that may revoke by slot, named for it.
    "slots": OperatorScope(frozenset({"revoke.slot"})),
    # The mdoc desk: logins and reviews of the mdoc only.
    "desk": OperatorScope(frozenset({"logins", "deferred", "offers"}), frozenset({MDOC})),
    # Two systems that issue the same configuration, as Moodle and certifygen do on one site.
    "lms": OperatorScope(frozenset({"offers", "offers.read", "offers.cancel", "revoke"}), frozenset({SD_JWT})),
    "certifygen": OperatorScope(frozenset({"offers", "offers.read", "offers.cancel", "revoke"}), frozenset({SD_JWT})),
    # A review office: decides the mdoc's held issuances, whoever offered them; offers nothing.
    "reviewer": OperatorScope(frozenset({"deferred"}), frozenset({MDOC})),
    # An issuing system scoped by permissions only, for every configuration.
    "wide": OperatorScope(frozenset({"offers", "offers.read", "offers.cancel", "revoke"})),
    # A login service: reports logins (which make subjects) and follows them; makes no offers.
    "loginsvc": OperatorScope(frozenset({"logins", "offers.read", "revoke"}), frozenset({SD_JWT})),
}


def course(pki: Pki, **overrides: Any) -> dict[str, Any]:
    return mdoc_settings(
        pki,
        metadata_dir=COURSE,
        published_configurations=(SD_JWT, MDOC),
        operators=OPERATORS,
        operator_scopes={**SCOPES, **overrides.pop("scopes", {})},
        **overrides,
    )


@pytest.fixture
def scoped(make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki) -> Wallet:
    return wallet_for(make_issuer(**course(pki)))


def call(wallet: Wallet, token: str, method: str, path: str, body: Any = None) -> Any:
    headers = {"Authorization": f"Bearer {token}"}
    if method == "GET":
        return wallet.client.get(f"/admin/{path}", headers=headers)
    return wallet.client.post(f"/admin/{path}", json=body, headers=headers)


def offer(wallet: Wallet, token: str, config: str = SD_JWT, **extra: Any) -> Any:
    subject = mdoc_subject(COURSE_SUBJECT) if config == MDOC else COURSE_SUBJECT
    return call(
        wallet, token, "POST", "offers", {"credential_configuration_ids": [config], "subject": subject, **extra}
    )


def forbidden(response: Any, reason: str) -> None:
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "insufficient_scope" and reason in response.json()["error_description"]
    assert response.headers["www-authenticate"].startswith('Bearer error="insufficient_scope"')


@pytest.mark.covers(RULE)
def test_a_token_without_a_scope_does_everything_but_revoke_by_slot(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """Backward compatible: CUNHO_OPERATORS as before, every permission, but revocation by list and index, which
    revokes a credential without knowing whose it is, is never granted unless a scope names it."""
    wallet = wallet_for(make_issuer(**settings_kwargs(pki, operator_scopes={})))
    assert Settings(**settings_kwargs(pki, operator_scopes={})).scope_of("admin").permissions == DEFAULT_PERMISSIONS
    made = wallet.offer()
    wallet.get_token(made)
    assert wallet.issue().status_code == 200
    body = {"list": "1", "index": 0, "reason": "compromise"}
    refused = refused_by(functools.partial(wallet.admin, "revocations", body), RULE, "does not allow revoke.slot")
    forbidden(refused, "revoke.slot")
    revoked = wallet.admin("revocations", {"subject_ref": made["subject_ref"], "reason": "compromise"})
    assert revoked.status_code == 200 and revoked.json()["revoked"] == 1


@pytest.mark.covers(RULE)
@pytest.mark.parametrize(
    ("method", "path", "permission"),
    [
        ("POST", "offers/sub_x/cancel", "offers.cancel"),
        ("POST", "subjects/sub_x/erase", "erase"),
        ("GET", "deferred", "deferred"),
        ("POST", "deferred/x/release", "deferred"),
        ("POST", "deferred/x/refuse", "deferred"),
        ("GET", "logins/x", "logins"),
        ("POST", "logins/x", "logins"),
        ("GET", "audit/head", "audit"),
        ("GET", "audit/verify", "audit"),
        ("POST", "audit/verify", "audit"),
    ],
)
def test_a_scoped_token_is_refused_what_its_permissions_leave_out(
    scoped: Wallet, method: str, path: str, permission: str
) -> None:
    """Refused before anything is read or looked up, with the permission named."""
    response = refused_by(lambda: call(scoped, MOODLE, method, path, {}), RULE, f"does not allow {permission}")
    forbidden(response, permission)


@pytest.mark.covers(RULE)
def test_a_scoped_token_offers_and_reads_only_its_own_configurations(scoped: Wallet) -> None:
    made = offer(scoped, MOODLE)
    assert made.status_code == 201, made.text
    forbidden(refused_by(lambda: offer(scoped, MOODLE, MDOC), RULE, "does not cover"), "does not cover")
    both = {"credential_configuration_ids": [SD_JWT, MDOC], "subject": COURSE_SUBJECT}
    forbidden(refused_by(lambda: call(scoped, MOODLE, "POST", "offers", both), RULE, "does not cover"), "not cover")
    code = {"credential_configuration_ids": [MDOC], "grant": "authorization_code"}
    forbidden(refused_by(lambda: call(scoped, MOODLE, "POST", "offers", code), RULE, "does not cover"), "not cover")
    assert call(scoped, MOODLE, "GET", f"offers/{made.json()['subject_ref']}").json()["state"] == "offered"
    other = offer(scoped, ADMIN_TOKEN, MDOC).json()["subject_ref"]
    forbidden(refused_by(lambda: call(scoped, MOODLE, "GET", f"offers/{other}"), RULE, "does not cover"), "not cover")
    # Revocation by subject, by person or by slot: none of them is the platform's.
    for body in ({"subject_ref": other}, {"person": "learner-7"}, {"list": "1", "index": 0}):
        revoke = functools.partial(call, scoped, MOODLE, "POST", "revocations", {**body, "reason": "compromise"})
        refused = refused_by(revoke, RULE, "does not allow revoke")
        forbidden(refused, "revoke")


@pytest.mark.covers(RULE)
def test_a_scoped_revocation_reaches_its_own_configurations_only(scoped: Wallet) -> None:
    mine = offer(scoped, ADMIN_TOKEN, person="learner-7").json()["subject_ref"]
    theirs = offer(scoped, ADMIN_TOKEN, MDOC, person="learner-7").json()["subject_ref"]
    revoke = functools.partial(call, scoped, REGISTRAR, "POST", "revocations")
    forbidden(
        refused_by(lambda: revoke({"subject_ref": theirs, "reason": "compromise"}), RULE, "does not cover"),
        "does not cover",
    )
    forbidden(refused_by(lambda: call(scoped, REGISTRAR, "POST", f"subjects/{theirs}/erase"), RULE, "not cover"), "")
    # By person, the registrar closes the person's subjects of its configuration and leaves the others alone.
    answer = revoke({"person": "learner-7", "reason": "compromise"})
    assert answer.status_code == 200 and answer.json()["subjects"] == 1, answer.text
    assert call(scoped, ADMIN_TOKEN, "GET", f"offers/{mine}").json()["state"] == "closed"
    assert call(scoped, ADMIN_TOKEN, "GET", f"offers/{theirs}").json()["state"] == "offered"
    forbidden(refused_by(lambda: revoke({"list": "1", "index": 0, "reason": "compromise"}), RULE, "slot"), "slot")


@pytest.mark.covers(RULE)
def test_only_a_token_whose_scope_names_it_revokes_by_slot(scoped: Wallet) -> None:
    scoped.get_token(scoped.offer(COURSE_SUBJECT, configs=[SD_JWT]))
    credential = scoped.issue(config=SD_JWT).json()["credentials"][0]["credential"]
    payload = json.loads(_b64(credential.split("~")[0].split(".")[1]))
    slot = payload["status"]["status_list"]
    body = {"list": slot["uri"].rsplit("/", 1)[1], "index": slot["idx"], "reason": "compromise"}
    forbidden(refused_by(lambda: call(scoped, ADMIN_TOKEN, "POST", "revocations", body), RULE, "slot"), "slot")
    assert call(scoped, SLOTS, "POST", "revocations", body).json() == {"revoked": 1}
    # The slot token can do nothing else.
    forbidden(refused_by(lambda: offer(scoped, SLOTS), RULE, "does not allow offers"), "offers")
    forbidden(
        refused_by(lambda: call(scoped, SLOTS, "POST", "revocations", {"person": "p", "reason": "x"}), RULE, "revoke"),
        "revoke",
    )


@pytest.mark.covers(RULE)
def test_a_scoped_login_service_reports_and_reads_only_its_own_configurations(
    make_code_issuer: Callable[..., Issuer], code_wallet_for: Callable[[Issuer], CodeWallet], pki: Pki, tmp_path: Any
) -> None:
    issuer = make_code_issuer(**course(pki))
    wallet = code_wallet_for(issuer)
    pushed = wallet.par(Pkce.random(), state="st-1", scope=str(issuer.configs.all[SD_JWT]["scope"]))
    assert pushed.status_code == 201, pushed.text
    request_uri = pushed.json()["request_uri"]
    sent = wallet.authorize(request_uri)
    state = parse_qs(urlsplit(sent.headers["location"]).query)["login_state"][0]
    headers = {"Authorization": f"Bearer {DESK}"}
    read = functools.partial(wallet.client.get, f"/admin/logins/{state}", headers=headers)
    forbidden(refused_by(read, RULE, "does not cover"), "does not cover")
    report = functools.partial(wallet.client.post, f"/admin/logins/{state}", json={"denied": True}, headers=headers)
    forbidden(refused_by(report, RULE, "does not cover"), "does not cover")
    admin = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    assert wallet.client.get(f"/admin/logins/{state}", headers=admin).status_code == 200


@pytest.mark.covers(RULE)
def test_a_scoped_token_sees_and_decides_only_the_reviews_of_its_configurations(
    make_issuer: Callable[..., Issuer], pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = make_issuer(**course(pki))
    course_ref, mdoc_ref = "a" * 32, "b" * 32
    held = {
        f"sub_a:{course_ref}": {"config": SD_JWT, "state": "held", "created": 1},
        f"sub_b:{mdoc_ref}": {"config": MDOC, "state": "held", "created": 2},
    }
    monkeypatch.setattr(issuer, "_held", held.get)  # two issuances held, as a review leaves them
    for key in held:
        subject_ref, ref = key.split(":")
        issuer.store.put("deferred", key, {}, 60)
        issuer.store.put("transaction", ref, subject_ref, 60)
    issuer.store.put("subject-scope", "sub_b", {"configs": [MDOC], "until": 10**10, "owner": "desk"}, 3600)
    assert [r["configuration_id"] for r in issuer.deferred_issuances()["deferred"]] == [SD_JWT, MDOC]
    assert [r["configuration_id"] for r in issuer.deferred_issuances("desk")["deferred"]] == [MDOC]
    error = raised_by(lambda: issuer.decide_deferred(course_ref, "release", "desk"), RULE, "does not cover")
    assert error.status == 403 and error.error == "insufficient_scope"


def test_each_operator_has_its_own_rate_limit(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """A learning platform's learners cannot use up the operator console's budget: each token has its own, and a
    scope may set it lower than operator_rate_limit_per_minute."""
    limited = OperatorScope(frozenset({"offers", "offers.read"}), frozenset({SD_JWT}), rate_limit_per_minute=2)
    wallet = wallet_for(make_issuer(**course(pki, scopes={"moodle": limited})))
    assert [offer(wallet, MOODLE).status_code for _ in range(3)] == [201, 201, 429]
    assert offer(wallet, ADMIN_TOKEN).status_code == 201
    assert offer(wallet, DESK, MDOC).status_code == 201


BROKEN: list[tuple[str, dict[str, Any], str]] = [
    ("an unknown operator", {"nobody": OperatorScope()}, "not an operator"),
    ("no permissions", {"moodle": OperatorScope(frozenset())}, "needs one or more permissions"),
    ("an unknown permission", {"moodle": OperatorScope(frozenset({"offers", "root"}))}, "not root"),
    ("no configurations", {"moodle": OperatorScope(configurations=frozenset())}, "non-empty list of ids"),
    (
        "slots for some configurations",
        {"moodle": OperatorScope(frozenset({"revoke.slot"}), frozenset({SD_JWT}))},
        "cannot have revoke.slot",
    ),
    ("an empty configuration id", {"moodle": OperatorScope(configurations=frozenset({""}))}, "non-empty list of ids"),
    ("a scope that is no OperatorScope", {"moodle": {"permissions": ["offers"]}}, "must be an OperatorScope"),
    ("a rate of zero", {"moodle": OperatorScope(rate_limit_per_minute=0)}, "at least 1 request per minute"),
    ("a rate that is no number", {"moodle": OperatorScope(rate_limit_per_minute=True)}, "at least 1 request"),
]


@pytest.mark.parametrize(("label", "scopes", "reason"), BROKEN, ids=[case[0] for case in BROKEN])
def test_a_scope_that_cannot_be_applied_stops_the_start(
    pki: Pki, label: str, scopes: dict[str, Any], reason: str
) -> None:
    with pytest.raises(ConfigError, match=reason):
        Settings(**settings_kwargs(pki, operators=OPERATORS, operator_scopes=scopes))


def test_a_scope_for_a_configuration_the_deployment_does_not_issue_stops_the_start(
    make_issuer: Callable[..., Issuer], pki: Pki
) -> None:
    with pytest.raises(ConfigError, match="limited to configurations this deployment does not issue: no.such"):
        make_issuer(**course(pki, scopes={"moodle": OperatorScope(configurations=frozenset({SD_JWT, "no.such"}))}))


def test_scopes_come_from_the_environment(pki: Pki) -> None:
    env = {
        "CUNHO_ISSUER_URL": ISSUER,
        "CUNHO_ADMIN_TOKEN": ADMIN_TOKEN,
        "CUNHO_SIGNING_KEY": "k",
        "CUNHO_SIGNING_CHAIN": "c",
        "CUNHO_AUDIT_RETENTION_DAYS": "30",
        "CUNHO_PROFILE": "eaa_provider",
        "CUNHO_WALLET_PROVIDER_ANCHORS": "a.pem",
        "CUNHO_OPERATORS": f"moodle={MOODLE}",
    }
    assert Settings.from_env(env).scope_of("moodle") == OperatorScope()
    scopes = {
        "moodle": {"permissions": ["offers", "offers.read"], "configurations": [SD_JWT], "rate_limit_per_minute": 60},
        "admin": {"permissions": list(OPERATOR_PERMISSIONS)},
    }
    settings = Settings.from_env(env | {"CUNHO_OPERATOR_SCOPES": json.dumps(scopes)})
    assert settings.scope_of("moodle") == OperatorScope(frozenset({"offers", "offers.read"}), frozenset({SD_JWT}), 60)
    assert "revoke.slot" in settings.scope_of("admin").permissions
    for text, reason in (
        ("{", "JSON object of operator scopes"),
        ("[]", "JSON object of operator scopes"),
        ('{"moodle": {"permissions": "offers"}}', "array of names"),
        ('{"moodle": {"permissions": ["offers"], "configurations": "x"}}', "array of ids"),
        ('{"moodle": {"permissions": ["offers"], "tokens": 1}}', "takes permissions"),
        ('{"moodle": ["permissions"]}', "takes permissions"),
        ('{"moodle": {"permissions": [1]}}', "array of names"),
        ('{"moodle": {"permissions": ["offers"], "configurations": [1]}}', "must be an array of ids"),
    ):
        with pytest.raises(ConfigError, match=reason):
            Settings.from_env(env | {"CUNHO_OPERATOR_SCOPES": text})


def _b64(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@pytest.mark.obligation(RULE)
def test_a_scoped_token_revokes_its_credentials_for_as_long_as_they_live(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock
) -> None:
    """What a subject is for is kept as long as its credentials, not only as long as its offer or login can lead to a
    token: the registrar revokes a certificate on its last day as on its first (the second reviewer)."""
    wallet = wallet_for(make_issuer(**course(pki, refresh_token_ttl=600, access_token_ttl=60)))
    made = offer(wallet, ADMIN_TOKEN, person="learner-9").json()
    other = offer(wallet, ADMIN_TOKEN, MDOC, person="learner-9").json()
    wallet.get_token(made)
    assert wallet.issue(config=SD_JWT).status_code == 200
    clock.now += 13 * 86_400  # long past the offer and any token; the certificate lives 14 days
    revoke = functools.partial(call, wallet, REGISTRAR, "POST", "revocations")
    answer = revoke({"person": "learner-9", "reason": "compromise"})
    assert answer.status_code == 200 and answer.json()["revoked"] == 1, answer.text
    # The mdoc offer was never taken and cunho has forgotten what it was for: nothing of it can be live, and the
    # registrar hears that, as for any subject that is over, rather than a refusal it could not tell from a real one.
    answer = revoke({"subject_ref": other["subject_ref"], "reason": "compromise"})
    assert answer.status_code == 400 and "nothing to revoke" in answer.json()["error_description"], answer.text


@pytest.mark.covers(RULE)
def test_a_scoped_token_hears_that_a_forgotten_subject_is_over(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock
) -> None:
    """A learning platform cancels a learner's old offer before making a new one, and revokes what it issued. Once
    cunho has forgotten a subject (no offer, login or credential of it can be live), a cancellation, a revocation or
    a read answers as for any subject that is over; before that, a subject of another configuration is refused; and
    an erasure, which is logged, is refused either way."""
    platform = OperatorScope(frozenset({"offers", "offers.read", "offers.cancel", "revoke"}), frozenset({SD_JWT}))
    settings = course(pki, scopes={"moodle": platform}, refresh_token_ttl=600, access_token_ttl=60)
    wallet = wallet_for(make_issuer(**settings))
    no_live_offer = "no live offer for this subject reference"
    mine = offer(wallet, MOODLE).json()["subject_ref"]
    theirs = offer(wallet, ADMIN_TOKEN, MDOC).json()["subject_ref"]
    cancel = lambda ref: call(wallet, MOODLE, "POST", f"offers/{ref}/cancel", {})  # noqa: E731
    forbidden(refused_by(lambda: cancel(theirs), RULE, "does not cover"), "does not cover")

    clock.now += 86_400  # long past both offers and any login they could lead to; neither was taken
    answer = cancel(mine)
    assert answer.status_code == 400 and answer.json()["error_description"] == no_live_offer
    answer = call(wallet, MOODLE, "POST", "revocations", {"subject_ref": mine, "reason": "administrative"})
    assert answer.status_code == 400 and answer.json()["error_description"] == "nothing to revoke for this reference"
    answer = call(wallet, MOODLE, "GET", f"offers/{mine}")
    assert answer.status_code == 200 and answer.json()["state"] == "expired", answer.text
    answer = cancel(theirs)
    assert answer.status_code == 400 and answer.json()["error_description"] == no_live_offer
    forbidden(
        refused_by(lambda: call(wallet, REGISTRAR, "POST", f"subjects/{theirs}/erase", {}), RULE, "does not cover"),
        "does not cover",
    )

    fresh = offer(wallet, ADMIN_TOKEN, MDOC).json()["subject_ref"]
    forbidden(refused_by(lambda: cancel(fresh), RULE, "does not cover"), "does not cover")


@pytest.mark.covers(RULE)
def test_a_subject_without_scope_records_is_refused_while_anything_of_it_lives(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """A store from before scopes keeps no record of what a subject was for once its offer is over, though its
    credentials still live: a scoped token is refused, not told the subject is over (the second reviewer)."""
    platform = OperatorScope(frozenset({"offers", "offers.read", "offers.cancel", "revoke"}), frozenset({SD_JWT}))
    issuer = make_issuer(**course(pki, scopes={"moodle": platform}))
    wallet = wallet_for(issuer)
    theirs = offer(wallet, ADMIN_TOKEN, MDOC).json()
    wallet.get_token(theirs)
    assert wallet.issue(config=MDOC).status_code == 200
    ref = theirs["subject_ref"]
    issuer.store.delete("subject-scope", ref)  # as a store from before scopes leaves it
    issuer.store.delete("subject-configs", ref)
    revoke = {"subject_ref": ref, "reason": "administrative"}
    forbidden(refused_by(lambda: call(wallet, MOODLE, "POST", "revocations", revoke), RULE, "not cover"), "not cover")
    forbidden(refused_by(lambda: call(wallet, MOODLE, "GET", f"offers/{ref}"), RULE, "not cover"), "not cover")


@pytest.mark.covers(RULE)
def test_an_issuing_system_acts_only_on_what_it_made(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki
) -> None:
    """Moodle and certifygen issue the same course certificate. A stolen Moodle token must not read, cancel or revoke
    what certifygen or the admin offered, by reference or by person; a registrar,
    which offers nothing, still revokes every certificate of its configuration."""
    issuer = make_issuer(**course(pki))
    wallet = wallet_for(issuer)
    mine = offer(wallet, LMS, person="learner-3").json()["subject_ref"]
    theirs = offer(wallet, CERTIFYGEN, person="learner-3").json()["subject_ref"]
    admins = offer(wallet, ADMIN_TOKEN, person="learner-3").json()["subject_ref"]
    for other in (theirs, admins):
        for method, path, body in (
            ("GET", f"offers/{other}", None),
            ("POST", f"offers/{other}/cancel", {}),
            ("POST", "revocations", {"subject_ref": other, "reason": "compromise"}),
        ):
            forbidden(
                refused_by(functools.partial(call, wallet, LMS, method, path, body), RULE, "another system"),
                "another system",
            )
    assert call(wallet, LMS, "GET", f"offers/{mine}").json()["state"] == "offered"
    # By person, only its own subject of the person's three.
    answer = call(wallet, LMS, "POST", "revocations", {"person": "learner-3", "reason": "compromise"})
    assert answer.status_code == 200 and answer.json()["subjects"] == 1, answer.text
    state = {ref: call(wallet, ADMIN_TOKEN, "GET", f"offers/{ref}").json()["state"] for ref in (mine, theirs, admins)}
    assert state == {mine: "closed", theirs: "offered", admins: "offered"}
    # The registrar offers nothing and is bound to no owner.
    answer = call(wallet, REGISTRAR, "POST", "revocations", {"subject_ref": theirs, "reason": "compromise"})
    assert answer.status_code == 200, answer.text
    # A subject made before owners were recorded: no issuing system's token may touch it, the admin still may.
    old = offer(wallet, LMS).json()["subject_ref"]
    kept = issuer.store.get("subject-scope", old)
    assert isinstance(kept, dict)
    issuer.store.put("subject-scope", old, {k: v for k, v in kept.items() if k != "owner"}, 3600)
    forbidden(refused_by(lambda: call(wallet, LMS, "GET", f"offers/{old}"), RULE, "another system"), "another system")
    assert call(wallet, ADMIN_TOKEN, "GET", f"offers/{old}").json()["state"] == "offered"


@pytest.mark.covers(RULE)
def test_the_owner_survives_the_issuance(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock
) -> None:
    """Issuance extends what cunho keeps about a subject to the credential's life: its owner stays the same, so on
    the certificate's last day the system that offered it can still revoke it, and no other can."""
    scoped = wallet_for(make_issuer(**course(pki, refresh_token_ttl=600, access_token_ttl=60)))
    made = offer(scoped, LMS).json()
    scoped.get_token(made)
    assert scoped.issue(config=SD_JWT).status_code == 200
    clock.now += 13 * 86_400  # long past the offer and any token: only what issuance kept remains
    ref = made["subject_ref"]
    forbidden(
        refused_by(
            lambda: call(scoped, CERTIFYGEN, "POST", "revocations", {"subject_ref": ref, "reason": "compromise"}),
            RULE,
            "another system",
        ),
        "another system",
    )
    answer = call(scoped, LMS, "POST", "revocations", {"subject_ref": ref, "reason": "compromise"})
    assert answer.status_code == 200 and answer.json()["revoked"] == 1, answer.text


def test_two_authorization_headers_authenticate_no_one(scoped: Wallet) -> None:
    """With two Authorization headers, which counted would depend on the server and every proxy on the way: none
    does."""
    two = [("Authorization", f"Bearer {MOODLE}"), ("Authorization", f"Bearer {ADMIN_TOKEN}")]
    assert scoped.client.get("/admin/audit/head", headers=two).status_code == 401
    assert scoped.client.get("/admin/audit/head", headers=list(reversed(two))).status_code == 401
    assert scoped.client.get("/admin/audit/head", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}).status_code == 200


@pytest.mark.covers(RULE)
def test_an_issuing_system_decides_only_its_own_reviews(
    make_issuer: Callable[..., Issuer], pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator that makes offers and decides reviews sees and decides only the held issuances of subjects it
    made; a review office that makes no offers decides them all."""
    issuer = make_issuer(**course(pki))
    own, other = "c" * 32, "d" * 32
    held = {
        f"sub_own:{own}": {"config": MDOC, "state": "held", "created": 1},
        f"sub_other:{other}": {"config": MDOC, "state": "held", "created": 2},
    }
    monkeypatch.setattr(issuer, "_held", held.get)
    for key in held:
        subject_ref, ref = key.split(":")
        issuer.store.put("deferred", key, {}, 60)
        issuer.store.put("transaction", ref, subject_ref, 60)
    issuer.store.put("subject-scope", "sub_own", {"configs": [MDOC], "until": 10**10, "owner": "desk"}, 3600)
    issuer.store.put("subject-scope", "sub_other", {"configs": [MDOC], "until": 10**10, "owner": "admin"}, 3600)
    assert [r["subject_ref"] for r in issuer.deferred_issuances("desk")["deferred"]] == ["sub_own"]
    assert [r["subject_ref"] for r in issuer.deferred_issuances("reviewer")["deferred"]] == ["sub_own", "sub_other"]
    error = raised_by(lambda: issuer.decide_deferred(other, "release", "desk"), RULE, "another system")
    assert error.status == 403 and error.error == "insufficient_scope"


def test_an_issuing_system_keeps_its_subject_while_anything_of_it_is_known(
    make_issuer: Callable[..., Issuer], wallet_for: Callable[[Issuer], Wallet], pki: Pki, clock: Clock
) -> None:
    """What a subject is for is extended at each later step (a token, an issuance); who made it lives as long, so the
    system that made it is never told, near the end, that another system did."""
    issuer = make_issuer(**course(pki))
    wallet = wallet_for(issuer)
    made = offer(wallet, LMS).json()
    clock.now += 500  # the wallet takes the code late in the offer's life
    wallet.get_token(made)
    assert wallet.issue(config=SD_JWT).status_code == 200
    clock.now += issuer.settings.subject_window - 500 + 60  # past the window counted from the offer
    ref = made["subject_ref"]
    assert issuer.store.get("subject-configs", ref) is not None  # the window the review found
    answer = call(wallet, LMS, "GET", f"offers/{ref}")
    assert answer.status_code == 200, answer.text
    answer = call(wallet, LMS, "POST", "revocations", {"subject_ref": ref, "reason": "compromise"})
    # The answer any owner gets about its own subject: revoked, or nothing left to revoke; never "another system".
    assert answer.status_code == 200 or "nothing to revoke" in answer.text, answer.text


@pytest.mark.covers(RULE)
def test_an_issuing_system_for_every_configuration_is_bound_too(scoped: Wallet) -> None:
    """A token whose scope lets it make offers is bound to what it made even when its scope lists no configurations:
    it cannot read, cancel or revoke another system's subjects; the admin can."""
    mine = offer(scoped, WIDE, person="learner-5").json()["subject_ref"]
    theirs = offer(scoped, CERTIFYGEN, person="learner-5").json()["subject_ref"]
    for method, path, body in (
        ("GET", f"offers/{theirs}", None),
        ("POST", f"offers/{theirs}/cancel", {}),
        ("POST", "revocations", {"subject_ref": theirs, "reason": "compromise"}),
    ):
        forbidden(
            refused_by(functools.partial(call, scoped, WIDE, method, path, body), RULE, "another system"),
            "another system",
        )
    answer = call(scoped, WIDE, "POST", "revocations", {"person": "learner-5", "reason": "compromise"})
    assert answer.status_code == 200 and answer.json()["subjects"] == 1, answer.text
    assert call(scoped, ADMIN_TOKEN, "GET", f"offers/{mine}").json()["state"] == "closed"
    assert call(scoped, ADMIN_TOKEN, "GET", f"offers/{theirs}").json()["state"] == "offered"


@pytest.mark.covers(RULE)
def test_a_login_service_is_bound_to_the_subjects_it_reported(scoped: Wallet) -> None:
    """Reporting a login makes a subject, as an offer does: a token that reports logins acts only on its own
    subjects, never on another system's offers of its configuration."""
    theirs = offer(scoped, CERTIFYGEN).json()["subject_ref"]
    forbidden(
        refused_by(lambda: call(scoped, LOGINS, "GET", f"offers/{theirs}"), RULE, "another system"), "another system"
    )
    body = {"subject_ref": theirs, "reason": "compromise"}
    forbidden(
        refused_by(lambda: call(scoped, LOGINS, "POST", "revocations", body), RULE, "another system"), "another system"
    )


def test_a_token_that_makes_subjects_cannot_revoke_by_slot(pki: Pki) -> None:
    """A slot names no subject: a token bound to the subjects it makes cannot have revoke.slot, with or without
    configurations, or the binding would be void. The admin may."""
    for permissions in ({"offers", "revoke.slot"}, {"logins", "revoke.slot"}):
        scope = {"wide": OperatorScope(frozenset(permissions))}
        with pytest.raises(ConfigError, match="makes subjects"):
            Settings(**settings_kwargs(pki, operators=OPERATORS, operator_scopes=scope))
    admin = {"admin": OperatorScope(frozenset({"offers", "revoke.slot"}))}
    Settings(**settings_kwargs(pki, operators=OPERATORS, operator_scopes=admin))
