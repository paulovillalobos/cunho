"""The binder, as the code sees it.

registry.json is generated from binder/ by binder/src/milestones.py. Code refers to rules only by id,
through `enforce`, `refuse` and `implements`, so tests can prove that every rule of a milestone is
both implemented and tested.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from importlib.resources import files
from typing import Any, NoReturn, TypeVar, cast

from cunho.errors import IssuerError

REGISTRY: dict[str, dict[str, Any]] = json.loads(files("cunho.rules").joinpath("registry.json").read_text())

F = TypeVar("F", bound=Callable[..., Any])


def known(rule: str) -> str:
    if rule not in REGISTRY:
        raise KeyError(f"rule {rule!r} is not in the binder")
    return rule


def refuse(rule: str, error: str, description: str, status: int = 400, **kwargs: Any) -> NoReturn:
    raise IssuerError(known(rule), error, description, status, **kwargs)


def enforce(condition: bool, rule: str, error: str, description: str, status: int = 400, **kwargs: Any) -> None:
    if not condition:
        refuse(rule, error, description, status, **kwargs)


# Called with the rules of an `implements` function each time it runs. The tests use it to check that a test
# claiming an obligation reaches the code that claims to fulfil it, as `covers` tests must see their refusals.
reached: list[Callable[[tuple[str, ...]], None]] = []


def implements(*rules: str) -> Callable[[F], F]:
    """Mark a function that fulfils an obligation (something the issuer must produce, not refuse)."""

    for rule in rules:
        known(rule)

    def mark(fn: F) -> F:
        @functools.wraps(fn)
        def run(*args: Any, **kwargs: Any) -> Any:
            for observe in reached:
                observe(rules)
            return fn(*args, **kwargs)

        run.__cunho_rules__ = rules  # type: ignore[attr-defined]
        return cast(F, run)

    return mark
