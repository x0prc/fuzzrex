![f](https://github.com/user-attachments/assets/ecc42996-b9e9-4e85-8b15-395e36dbd117)

A CLI tool that fuzzes REST APIs from their OpenAPI spec and mutates configuration files (JSON/YAML) to surface unexpected behavior.

[Additional Docs](https://x0prc.github.io/notes/Notes/Published-Documentation/FuzzRex)

## Features

1. **API fuzzing** — loads an OpenAPI spec (JSON/YAML), generates type-aware request values (including out-of-range boundaries), routes parameters correctly (path/query/header/cookie/body), carries state across requests, and reports 5xx responses.
2. **Config fuzzing** — mutates JSON/YAML/INI configs (typed value flips, null injection, key deletion, structure damage; enum-constrained keys stay in their vocabulary) and writes reproducible variants to disk.
3. **Differential oracle** — replays one planned request sequence under two config cells and flags security-relevant divergence only: `auth-boundary` (401/403 or redirect-to-login flips), `info-leak`, `server-error`, `status`, `transport`. Redirects are not followed, so login redirects are compared raw.
4. **Joint Config×API search** — feedback loop that mutates the config, probes the API, and grows from divergent cells.
5. **Baseline runner** — replays Schemathesis per config cell for the single-cell comparison arm.

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
mutation base (with periodic restarts to the baseline for diversity).
Constrain enum-like keys with `enums` so mutation stays inside the
allowed vocabulary:

```python
from fuzzrex.oracle import run_joint_search

results = run_joint_search(
    orch,
    baseline_config={"debug": False, "require_auth": False, "greeting": "hello"},
    sequence=sequence,
    iterations=20,
    seed=42,
    enums={"log_level": ["debug", "info", "error"]},
)
for cell in results:
    print(cell.config, cell.divergences)
```

### Baseline runner (Schemathesis)

Run an off-the-shelf single-cell API fuzzer once per config cell to
produce the comparison arm for joint fuzzing:

```bash
pip install -e ".[baseline]"
```

```python
from fuzzrex.baseline import run_baseline_matrix

results = run_baseline_matrix(
    orch,
    configs=[baseline_config, variant_config],
    spec_path="examples/demo-api/openapi.json",
    seed=42,
    max_examples=25,
)
for cell in results:
    print(cell.config, "findings:", cell.total)
```

Each cell is applied with the orchestrator (restart + health check),
Schemathesis runs against it, and the original config is restored.
Findings come back as `BaselineFinding` groups (`failure` = failed
check, `error` = test crash), parsed from Schemathesis's JSON report.

On the demo API the contrast is already visible: across the same
config cells the baseline reports 0 findings while joint search finds
`info-leak` and `auth-boundary` divergences — config-gated issues that
single-cell API fuzzing does not observe.

### Real SUT examples

`examples/` bundles ready-to-run fixtures for third-party targets:

| SUT | Config model | Knobs | Health |
|---|---|---|---|
| `demo-api` | JSON sidecar | `require_auth`, `debug` | `/health` |
| `dvwa` | PHP shim overlays `matrix.json` | `disable_authentication`, `default_security_level` (enum) | `/vulnerabilities/api/v2/health/ping` |
| `grafana` | `grafana.ini` bind-mount | `[auth.anonymous] enabled` | `/api/health` |

```bash
docker compose -f examples/dvwa/compose.yml up -d
docker compose -f examples/grafana/compose.yml up -d
```

Joint-search smoke results (seed 42, local run):

| SUT | Divergent cells | Kinds |
|---|---|---|
| dvwa | 4/8 | `auth-boundary` (302→200 on session-gated pages) |
| grafana | 2/6 | `auth-boundary` + `info-leak` (401→200 on `/api/search` etc.) |

Notes: DVWA's stateless v2 API ignores the security-level knob, so its
fixture spec also carries the session-gated pages where
`disable_authentication` actually shows. Grafana's spec is a
probe-verified subset of 9 endpoints.

## Development

```bash
ruff check fuzzrex tests
pytest
```

## Motivation

Fuzzing API schemas and deployment configuration as one package shortens security assessments: both are attack surfaces, and interaction bugs between them are what this project is ultimately aiming to search.

## License

MIT
