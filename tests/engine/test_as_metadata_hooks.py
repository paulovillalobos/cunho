"""Fields added to the authorization server metadata by a hook, as the authorization code flow adds its own."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from cunho.errors import ConfigError
from cunho.metadata import authorization_server_metadata
from cunho.service import Issuer
from cunho.settings import Settings

from .helpers import ISSUER

# Fields no built-in hook sets: the issuer's own code-flow hook already sets the authorization endpoint and the
# response and grant types, and a second hook may not set them again.
EXTRA = {
    "revocation_endpoint": f"{ISSUER}/revoke",
    "op_policy_uri": f"{ISSUER}/policy",
    "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
}


def test_a_hook_adds_fields_and_replaces_fields_on_the_route(client: TestClient, issuer: Issuer) -> None:
    before = client.get("/.well-known/oauth-authorization-server").json()
    assert not set(EXTRA) & set(before)
    issuer.extend_as_metadata(lambda settings: EXTRA)
    issuer.extend_as_metadata(lambda settings: {"dpop_signing_alg_values_supported": ["ES256"]})
    after = client.get("/.well-known/oauth-authorization-server").json()
    assert after == {**before, **EXTRA, "dpop_signing_alg_values_supported": ["ES256"]}, "added and replaced"


def test_a_hook_is_given_the_settings(issuer: Issuer) -> None:
    seen: list[Settings] = []

    def hook(settings: Settings) -> dict[str, Any]:
        seen.append(settings)
        return {"op_tos_uri": f"{settings.issuer_url}/terms"}

    issuer.extend_as_metadata(hook)
    assert issuer.as_metadata()["op_tos_uri"] == f"{ISSUER}/terms"
    assert seen and all(s is issuer.settings for s in seen)


def test_a_hook_cannot_set_the_issuer_identifier(issuer: Issuer) -> None:
    with pytest.raises(ConfigError, match="issuer identifier"):
        issuer.extend_as_metadata(lambda settings: {"issuer": "https://elsewhere.test"})
    assert issuer.as_metadata()["issuer"] == ISSUER, "the refused hook was not kept"


def test_two_hooks_cannot_set_the_same_field(issuer: Issuer) -> None:
    """The code flow's own hook already sets response_types_supported, so another hook may not."""
    with pytest.raises(ConfigError, match="two authorization server metadata hooks set response_types_supported"):
        issuer.extend_as_metadata(lambda settings: {"response_types_supported": ["code", "token"]})
    assert issuer.as_metadata()["response_types_supported"] == ["code"]


def test_a_hook_whose_fields_change_later_does_not_change_a_document_already_built(issuer: Issuer) -> None:
    fields: dict[str, Any] = {"code_challenge_methods_supported": ["S256"]}
    document = authorization_server_metadata(issuer.settings, [lambda settings: fields])
    fields["code_challenge_methods_supported"].append("plain")
    assert document["code_challenge_methods_supported"] == ["S256"]


def test_without_hooks_the_document_is_the_m2_one(issuer: Issuer) -> None:
    m2 = authorization_server_metadata(issuer.settings)
    assert m2 == authorization_server_metadata(issuer.settings, [])
    assert m2["response_types_supported"] == [] and "authorization_endpoint" not in m2
    assert issuer.as_metadata() == {**m2, **issuer.authorization.metadata(issuer.settings)}
