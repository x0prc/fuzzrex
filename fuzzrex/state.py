"""Track dynamic values observed in API responses for stateful request generation."""

from __future__ import annotations

from typing import Any

from requests import Response


class StateManager:
    """Collect scalar values from JSON responses so later requests can reuse them."""

    def __init__(self) -> None:
        self.known_values: dict[str, Any] = {}
        self.last_response: dict[str, Any] | None = None

    def update(self, response: Response) -> None:
        try:
            body = response.json()
        except ValueError:
            return
        if isinstance(body, dict):
            self.last_response = body
            self._collect(body)

    def resolve(self, name: str, default: Any = None) -> Any:
        return self.known_values.get(name, default)

    def _collect(self, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if isinstance(value, dict):
                self._collect(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._collect(item)
            elif value is not None:
                self.known_values[key] = value
