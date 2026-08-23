"""Test-owned reason bindings for the Windows adversarial matrix."""

from __future__ import annotations

import re
import unittest
from collections.abc import Callable
from typing import TypeVar, cast

_REASON_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,79}$")
_BINDING_ATTRIBUTE = "__master_agent_adversarial_reasons__"
_TestMethod = TypeVar("_TestMethod", bound=Callable[..., object])


def adversarial_reasons(*reasons: str) -> Callable[[_TestMethod], _TestMethod]:
    """Bind exact content-free evidence reasons to one test method."""

    if not reasons or any(not _REASON_PATTERN.fullmatch(reason) for reason in reasons):
        raise ValueError("adversarial reason binding is invalid")
    bound = frozenset(reasons)
    if len(bound) != len(reasons):
        raise ValueError("adversarial reason binding contains a duplicate")

    def decorate(method: _TestMethod) -> _TestMethod:
        if hasattr(method, _BINDING_ATTRIBUTE):
            raise ValueError("adversarial reason binding is already declared")
        setattr(method, _BINDING_ATTRIBUTE, bound)
        return method

    return decorate


def reasons_for_test(test: unittest.TestCase) -> frozenset[str]:
    """Return the exact reason set declared by one resolved test method."""

    method = getattr(type(test), test._testMethodName)
    value = getattr(method, _BINDING_ATTRIBUTE, frozenset())
    if not isinstance(value, frozenset) or any(
        not isinstance(reason, str) or not _REASON_PATTERN.fullmatch(reason)
        for reason in value
    ):
        raise ValueError("adversarial reason binding is invalid")
    return cast(frozenset[str], value)
