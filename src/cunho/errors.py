"""One error type for every refusal, carrying the binder rule that caused it."""

from __future__ import annotations

from collections.abc import Callable

# Called with every refusal as it is raised. The test suite uses it to prove that a test marked
# `covers(rule)` really triggers that rule, and that each negative case is refused by the check it is
# about, not by some other one (review 2, N-M6; review 3, N3-H1).
observers: list[Callable[[IssuerError], None]] = []


class IssuerError(Exception):
    """A refusal the client must see as an OAuth / OpenID4VCI error response.

    `scheme` is set for protected-resource errors (RFC 6750 §3, RFC 9449 §7.1); the response then
    carries a WWW-Authenticate challenge instead of only a JSON body.
    """

    def __init__(
        self,
        rule: str,
        error: str,
        description: str,
        status: int = 400,
        *,
        scheme: str | None = None,
        headers: dict[str, str] | None = None,
        bare_challenge: bool = False,
    ) -> None:
        super().__init__(f"{rule}: {error}: {description}")
        self.rule = rule
        self.error = error
        self.description = description
        self.status = status
        self.scheme = scheme
        self.headers = headers or {}
        # RFC 6750 §3.1: a request without credentials gets a challenge with no error code.
        self.bare_challenge = bare_challenge
        for observe in observers:
            observe(self)


class ConfigError(Exception):
    """The deployment is misconfigured; cunho refuses to start."""
