"""Structured document I/O (JSON/YAML) and schema-aware fuzz value generation."""

from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Any

import yaml

# --- Document I/O -----------------------------------------------------------

_LETTERS = string.ascii_letters + string.digits


def _is_yaml(path: Path) -> bool:
    return path.suffix.lower() in {".yaml", ".yml"}


def load_document(path: str | Path) -> Any:
    """Load a JSON or YAML file, detecting format from the extension."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    text = file_path.read_text(encoding="utf-8")
    if _is_yaml(file_path):
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fall back to YAML for extension-less or mislabeled files.
        return yaml.safe_load(text)


def load_spec(path: str | Path) -> dict[str, Any]:
    """Load an OpenAPI specification and verify it has paths."""
    document = load_document(path)
    if not isinstance(document, dict):
        raise ValueError(f"OpenAPI spec must be a mapping, got {type(document).__name__}")
    if "paths" not in document:
        raise ValueError(f"OpenAPI spec missing 'paths': {path}")
    return document


def dump_document(document: Any, path: str | Path) -> None:
    """Write a structure to disk, matching format to the file extension."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if _is_yaml(file_path):
        file_path.write_text(
            yaml.safe_dump(document, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
    else:
        file_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


# --- Schema-aware value generation ------------------------------------------


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
