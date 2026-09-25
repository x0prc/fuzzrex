![f](https://github.com/user-attachments/assets/ecc42996-b9e9-4e85-8b15-395e36dbd117)

A CLI tool that fuzzes REST APIs from their OpenAPI spec and mutates configuration files (JSON/YAML) to surface unexpected behavior.

[Additional Docs](https://x0prc.github.io/notes/Notes/Published-Documentation/FuzzRex)

## Features

1. **API fuzzing** — loads an OpenAPI spec (JSON/YAML), generates type-aware request values (including out-of-range boundaries), routes parameters correctly (path/query/header/cookie/body), carries state across requests, and reports 5xx responses.
2. **Config fuzzing** — mutates JSON/YAML configs (typed value flips, null injection, key deletion, structure damage) and writes reproducible variants to disk.
3. **Auth** — bearer-token auth on the CLI; OAuth2 client-credentials available via the Python API.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Fuzz an API (base URL falls back to spec servers[0], then localhost:5000)
fuzzrex --api openapi.yaml --base-url http://localhost:5000

# With bearer auth
fuzzrex --api openapi.json --auth token --token "$API_TOKEN"

# Generate config variants
fuzzrex --config app.yaml --variants 25 --out findings/configs --seed 42

# Both in one run
fuzzrex --api openapi.yaml --config app.yaml
```

Exit codes: `0` clean, `1` findings reported, `2` usage/config error.

### Python API

```python
from fuzzrex.api_fuzzer import ApiFuzzer, AuthHandler
from fuzzrex.config_fuzzer import ConfigFuzzer

auth = AuthHandler(auth_type="token", token="...")
findings = ApiFuzzer("openapi.yaml", base_url="http://localhost:5000", auth=auth).run()

ConfigFuzzer("app.yaml").run("findings/configs", count=25, seed=42)
```

### Orchestrator (config x API)

Apply a config variant to a Dockerized SUT, fuzz under it, and restore:

```python
from fuzzrex.api_fuzzer import ApiFuzzer
from fuzzrex.orchestrator import DockerComposeOrchestrator, configured_service

orch = DockerComposeOrchestrator(
    "examples/demo-api/docker-compose.yml",
    "demo-api",
    "examples/demo-api/config.json",
    "http://127.0.0.1:5001",
)
orch.up(build=True)  # first time only
with configured_service(orch, {"debug": True, "require_auth": True}):
    findings = ApiFuzzer("openapi.json", base_url=orch.base_url).run()
```

Demo SUT: `examples/demo-api/` (config-gated auth + debug leak). Bring it up with:

```bash
docker compose -f examples/demo-api/docker-compose.yml up -d --build
```

### Differential oracle

Replay one planned request sequence under two config cells and keep only
security-relevant divergence (`auth-boundary`, `info-leak`, `server-error`,
`status`, `transport`):

```python
from fuzzrex.api_fuzzer import ApiFuzzer
from fuzzrex.oracle import differential_probe

sequence = ApiFuzzer("openapi.json", base_url="http://127.0.0.1:5001").plan()
divergences = differential_probe(
    orch,
    baseline_config={"debug": False, "require_auth": False, "greeting": "hello"},
    variant_config={"debug": True, "require_auth": True, "greeting": "hello"},
    sequence=sequence,
)
```

### Joint search

Alternate config mutation and API probing; divergent cells become the next
mutation base (with periodic restarts to the baseline for diversity):

```python
from fuzzrex.oracle import run_joint_search

results = run_joint_search(
    orch,
    baseline_config={"debug": False, "require_auth": False, "greeting": "hello"},
    sequence=sequence,
    iterations=20,
    seed=42,
)
for cell in results:
    print(cell.config, cell.divergences)
```

## Development

```bash
ruff check fuzzrex tests
pytest
```

## Motivation

Fuzzing API schemas and deployment configuration as one package shortens security assessments: both are attack surfaces, and interaction bugs between them are what this project is ultimately aiming to search.

## License

MIT
