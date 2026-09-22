"""Schema-aware value generators shared by the API and config fuzzers."""

from __future__ import annotations

import random
import string
from typing import Any

_LETTERS = string.ascii_letters + string.digits


def fuzz_string(
    min_length: int = 1,
    max_length: int = 100,
    *,
    rng: random.Random | None = None,
) -> str:
    rng = rng or random
    length = rng.randint(min_length, max_length)
    return "".join(rng.choices(string.punctuation + _LETTERS, k=length))


def fuzz_integer(
    minimum: int | None = None,
    maximum: int | None = None,
    *,
    rng: random.Random | None = None,
) -> int:
    rng = rng or random
    low = minimum if minimum is not None else -1000
    high = maximum if maximum is not None else 1000
    # Probe just outside the declared range to hit boundary checks.
    return rng.randint(low - 10, high + 10)


def fuzz_number(
    minimum: float | None = None,
    maximum: float | None = None,
    *,
    rng: random.Random | None = None,
) -> float:
    rng = rng or random
    low = minimum if minimum is not None else -1000.0
    high = maximum if maximum is not None else 1000.0
    return rng.uniform(low - 10.0, high + 10.0)


def fuzz_boolean(*, rng: random.Random | None = None) -> bool:
    rng = rng or random
    return rng.choice([True, False])


def fuzz_array(
    item_schema: dict[str, Any] | None = None,
    min_items: int = 1,
    max_items: int = 5,
    *,
    rng: random.Random | None = None,
) -> list[Any]:
    rng = rng or random
    count = rng.randint(min_items, max_items)
    item_schema = item_schema or {"type": "string"}
    return [fuzz_value(item_schema, rng=rng) for _ in range(count)]


def fuzz_object(schema: dict[str, Any], *, rng: random.Random | None = None) -> dict[str, Any]:
    rng = rng or random
    properties = schema.get("properties", {})
    return {name: fuzz_value(prop_schema, rng=rng) for name, prop_schema in properties.items()}


def fuzz_value(schema: dict[str, Any] | None, *, rng: random.Random | None = None) -> Any:
    """Generate a fuzzed value for an OpenAPI-style JSON schema."""
    rng = rng or random
    schema = schema or {"type": "string"}

    if "enum" in schema:
        return rng.choice(schema["enum"])
    if "const" in schema:
        return schema["const"]

    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((t for t in schema_type if t != "null"), "string")

    if schema_type == "integer":
        return fuzz_integer(schema.get("minimum"), schema.get("maximum"), rng=rng)
    if schema_type == "number":
        return fuzz_number(schema.get("minimum"), schema.get("maximum"), rng=rng)
    if schema_type == "boolean":
        return fuzz_boolean(rng=rng)
    if schema_type == "array":
        return fuzz_array(
            schema.get("items"),
            int(schema.get("minItems", 1)),
            int(schema.get("maxItems", 5)),
            rng=rng,
        )
    if schema_type == "object":
        return fuzz_object(schema, rng=rng)
    if schema_type == "null":
        return None

    # Unspecified or string-like types.
    if "format" in schema or schema_type in (None, "string"):
        return fuzz_string(rng=rng)
    return fuzz_string(rng=rng)
