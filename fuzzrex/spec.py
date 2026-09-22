"""Load structured documents (OpenAPI specs, config files) from JSON or YAML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


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
