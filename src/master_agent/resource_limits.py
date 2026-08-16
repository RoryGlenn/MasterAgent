"""Shared local resource budgets for plans and generated artifacts."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from master_agent.errors import ValidationError

MAX_PLAN_BYTES = 8 * 1024 * 1024
MAX_PLAN_ACTIONS = 256
MAX_ACTION_DEPENDENCIES = 256
MAX_JSON_DEPTH = 32
MAX_JSON_COLLECTION_ITEMS = 1_024
MAX_JSON_NODES = 65_536
MAX_JSON_STRING_CHARACTERS = 1_048_576
MAX_ACTION_PARAMETER_BYTES = 4 * 1024 * 1024
MAX_PLAN_PARAMETER_BYTES = 8 * 1024 * 1024
MAX_LOCAL_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_RUN_ARTIFACT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class JsonResourceUsage:
    """Bounded structural and scalar-byte usage for one JSON-compatible value."""

    nodes: int
    scalar_bytes: int
    maximum_depth: int


def measure_json_resources(
    value: Any,
    *,
    context: str,
    max_bytes: int,
) -> JsonResourceUsage:
    """Validate an object iteratively and return its bounded resource usage.

    This walk runs before recursive model freezing or capability rendering. It
    rejects cycles, excessive depth/fan-out, oversized strings, unsupported
    values, and aggregate scalar content without serializing the whole object.
    """

    stack: list[tuple[bool, Any, int]] = [(False, value, 1)]
    active_containers: set[int] = set()
    nodes = 0
    scalar_bytes = 0
    maximum_depth = 0
    while stack:
        exiting, current, depth = stack.pop()
        if exiting:
            active_containers.remove(id(current))
            continue
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValidationError(f"{context} exceeds the {MAX_JSON_NODES}-node limit")
        maximum_depth = max(maximum_depth, depth)
        if depth > MAX_JSON_DEPTH:
            raise ValidationError(
                f"{context} exceeds the {MAX_JSON_DEPTH}-level nesting limit"
            )

        if isinstance(current, Mapping):
            if len(current) > MAX_JSON_COLLECTION_ITEMS:
                raise ValidationError(
                    f"{context} contains an object exceeding the "
                    f"{MAX_JSON_COLLECTION_ITEMS}-item limit"
                )
            identity = id(current)
            if identity in active_containers:
                raise ValidationError(f"{context} contains a cycle")
            active_containers.add(identity)
            stack.append((True, current, depth))
            children: list[Any] = []
            for key, item in current.items():
                if not isinstance(key, str):
                    raise ValidationError(f"{context} object keys must be strings")
                scalar_bytes += _bounded_string_bytes(key, context=context)
                children.append(item)
            for item in reversed(children):
                stack.append((False, item, depth + 1))
        elif isinstance(current, (tuple, list)):
            if len(current) > MAX_JSON_COLLECTION_ITEMS:
                raise ValidationError(
                    f"{context} contains an array exceeding the "
                    f"{MAX_JSON_COLLECTION_ITEMS}-item limit"
                )
            identity = id(current)
            if identity in active_containers:
                raise ValidationError(f"{context} contains a cycle")
            active_containers.add(identity)
            stack.append((True, current, depth))
            for item in reversed(current):
                stack.append((False, item, depth + 1))
        elif isinstance(current, str):
            scalar_bytes += _bounded_string_bytes(current, context=context)
        elif current is None:
            scalar_bytes += 4
        elif isinstance(current, bool):
            scalar_bytes += 4 if current else 5
        elif isinstance(current, int):
            scalar_bytes += _integer_characters(current)
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValidationError(f"{context} contains a non-finite number")
            scalar_bytes += 24
        else:
            raise ValidationError(
                f"{context} contains a non-JSON-compatible value: "
                f"{type(current).__name__}"
            )
        if scalar_bytes > max_bytes:
            raise ValidationError(
                f"{context} exceeds the {max_bytes}-byte content limit"
            )
    return JsonResourceUsage(
        nodes=nodes,
        scalar_bytes=scalar_bytes,
        maximum_depth=maximum_depth,
    )


def validate_bounded_string(value: str, *, context: str) -> None:
    """Reject a model string that exceeds the global plan-string ceiling."""

    _bounded_string_bytes(value, context=context)


def _bounded_string_bytes(value: str, *, context: str) -> int:
    if len(value) > MAX_JSON_STRING_CHARACTERS:
        raise ValidationError(
            f"{context} contains a string exceeding the "
            f"{MAX_JSON_STRING_CHARACTERS}-character limit"
        )
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValidationError(f"{context} contains invalid Unicode") from error


def _integer_characters(value: int) -> int:
    """Return a conversion-free upper bound for the decimal representation."""

    if value == 0:
        return 1
    bits = abs(value).bit_length()
    # ceil(bits * log10(2)) plus a possible sign.
    return ((bits * 30_103 + 99_999) // 100_000) + (1 if value < 0 else 0)
