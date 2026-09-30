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


def _is_ini(path: Path) -> bool:
    return path.suffix.lower() in {".ini", ".cfg", ".conf"}


def load_document(path: str | Path) -> Any:
    """Load a JSON, YAML, or INI file, detecting format from the extension."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    if _is_ini(file_path):
        return load_ini(file_path)
    text = file_path.read_text(encoding="utf-8")
    if _is_yaml(file_path):
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fall back to YAML for extension-less or mislabeled files.
        return yaml.safe_load(text)


def load_ini(path: str | Path) -> dict[str, dict[str, Any]]:
    """Parse a simple INI file into {section: {key: value}}.

    `true`/`false` and integers are coerced so config mutation sees real
    scalars; comments and blank lines are skipped; keys before the first
    section are collected under the empty section name.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    document: dict[str, dict[str, Any]] = {}
    section = ""
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            document.setdefault(section, {})
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            document.setdefault(section, {})[key.strip()] = _coerce_scalar(value.strip())
    return document


def _coerce_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value


def dump_ini(document: dict[str, dict[str, Any]], path: str | Path) -> None:
    """Write {section: {key: value}} as INI; booleans become lowercase strings.

    Mutations that INI cannot represent are dropped: a null or non-mapping
    section becomes an absent section (service default), and null or
    non-scalar values are skipped rather than rendered as junk strings.
    """
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for section, values in document.items():
        if not isinstance(values, dict):
            continue
        if section:
            lines.append(f"[{section}]")
        for key, value in values.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            rendered = str(value).lower() if isinstance(value, bool) else str(value)
            lines.append(f"{key} = {rendered}")
        lines.append("")
    file_path.write_text("\n".join(lines), encoding="utf-8")


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
    if _is_ini(file_path):
        dump_ini(document, file_path)
        return
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
