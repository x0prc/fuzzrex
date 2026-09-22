"""Configuration-file fuzzer: generate typed mutations of JSON/YAML configs."""

from __future__ import annotations

import copy
import random
from pathlib import Path
from typing import Any

from fuzzrex.mutations import fuzz_value
from fuzzrex.spec import dump_document, load_document


class ConfigFuzzer:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.original = load_document(self.path)
        if not isinstance(self.original, (dict, list)):
            raise ValueError(
                f"Config root must be a mapping or sequence, got {type(self.original).__name__}",
            )

    def generate_variants(self, count: int = 20, seed: int | None = None) -> list[Any]:
        """Return `count` mutated copies of the original configuration."""
        if count < 1:
            raise ValueError("count must be >= 1")
        rng = random.Random(seed)
        return [self._mutate(copy.deepcopy(self.original), rng) for _ in range(count)]

    def run(self, out_dir: str | Path, count: int = 20, seed: int | None = None) -> list[Path]:
        """Generate variants and write them next to each other under `out_dir`."""
        out_path = Path(out_dir)
        written: list[Path] = []
        for index, variant in enumerate(self.generate_variants(count, seed=seed), start=1):
            target = out_path / f"{self.path.stem}.fuzz{index}{self.path.suffix}"
            dump_document(variant, target)
            written.append(target)
        return written

    def _mutate(self, document: Any, rng: random.Random) -> Any:
        leaves = _collect_leaves(document)
        if not leaves:
            return document

        strategy = rng.choice(["value", "value", "null", "delete", "structure"])
        container, key = rng.choice(leaves)

        if strategy == "value":
            container[key] = _fuzz_leaf(container[key], rng)
        elif strategy == "null":
            container[key] = None
        elif strategy == "delete" and isinstance(document, dict):
            _delete_key(document, key, rng)
        else:  # structure
            container[key] = _fuzz_leaf(container[key], rng)
            if isinstance(container[key], dict) and container[key] and rng.random() < 0.5:
                # Drop one nested field to break structure assumptions.
                nested_leaves = _collect_leaves(container[key])
                if nested_leaves:
                    nested_container, nested_key = rng.choice(nested_leaves)
                    if isinstance(nested_container, dict):
                        nested_container.pop(nested_key, None)
        return document


def _fuzz_leaf(value: Any, rng: random.Random) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return fuzz_value({"type": "integer"}, rng=rng)
    if isinstance(value, float):
        return fuzz_value({"type": "number"}, rng=rng)
    if isinstance(value, str):
        return fuzz_value({"type": "string"}, rng=rng)
    if isinstance(value, list):
        if not value:
            return [fuzz_value({"type": "string"}, rng=rng)]
        index = rng.randrange(len(value))
        value[index] = _fuzz_leaf(value[index], rng)
        return value
    if isinstance(value, dict):
        if not value:
            return {"fuzzed": fuzz_value({"type": "string"}, rng=rng)}
        key = rng.choice(list(value))
        value[key] = _fuzz_leaf(value[key], rng)
        return value
    return fuzz_value({"type": "string"}, rng=rng)


def _collect_leaves(document: Any) -> list[tuple[Any, Any]]:
    """Return (container, key) pairs for every mutable slot in the document."""
    leaves: list[tuple[Any, Any]] = []
    stack: list[Any] = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    stack.append(value)
                leaves.append((node, key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                if isinstance(value, (dict, list)):
                    stack.append(value)
                leaves.append((node, index))
    return leaves


def _delete_key(document: dict[str, Any], key: Any, rng: random.Random) -> None:
    if key in document and len(document) > 1:
        document.pop(key)
    else:
        # Fall back to deleting any top-level key when the target is nested.
        victim = rng.choice(list(document))
        if len(document) > 1:
            document.pop(victim)
