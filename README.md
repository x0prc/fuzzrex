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
| `crapi` | compose `.env` (recreate mode) | `ENABLE_SHELL_INJECTION`, `TLS_ENABLED` | `/identity/health_check` |

```bash
docker compose -f examples/dvwa/compose.yml up -d
docker compose -f examples/grafana/compose.yml up -d
docker compose -f examples/crapi/compose.yml up -d
```

Notes: DVWA's stateless v2 API ignores the security-level knob, so its
fixture spec also carries the session-gated pages where
`disable_authentication` actually shows. Grafana's spec is a
probe-verified subset of 9 endpoints. crAPI's fixture is identity-only
and probes `127.0.0.1:8080` directly: the public nginx injects
`X-Forwarded-Host`, which makes `convert_video` answer 403 for every
external caller, hiding the `ENABLE_SHELL_INJECTION` branch. Its spec is
a probe-verified subset with chained requests (login token, upload →
video id resolved per config cell at send time), and both knobs are
probe-verified: shell-injection flips `convert_video` 500↔200, TLS flips
every endpoint 200↔400.

### Phase 1: joint vs baseline vs ablation

`fuzzrex.experiments.run_comparison` runs three arms under matched
seeds — joint search, the same search with the feedback loop disabled
(ablation), and Schemathesis once per cell of the static config grid —
and checkpoints a JSON summary per seed into `findings/phase1/`
(gitignored). Campaign: 10 seeds x 30 iterations, 5 examples/op for
the baseline (`examples/phase1_campaign.py`, crash-safe resume):

| SUT | Grid | joint | joint-no-feedback | paired (sign-flip) | baseline |
|---|---|---|---|---|---|
| dvwa | 8 cells | **11.20 ± 2.82** | 9.20 ± 3.19 | Δ=+2.00, p=0.13 | 41.6/seed → 3 unique |
| grafana | 2 cells | 12.40 ± 2.80 | **14.80 ± 2.30** | Δ=−2.40, p=0.037 | 0 |

Reading the table:

- **Baseline is config-blind**: DVWA's 41.6 findings/seed collapse to
  3 unique signatures, identical in every cell — per-cell API fuzzing
  cannot observe auth gating that only appears when the config flips.
- **Feedback depends on config-space depth**: on DVWA's 2-knob space
  growing from divergent cells helps (+2 cells/seed); on Grafana's
  single knob it hurts (p=0.037) because exploiting a one-shot cell
  mostly produces mutations that lose the divergence.
- Cell counts in this table are divergent *probes* (pre-refinement
  data); the metric now also records **unique effective configs**
  (`unique_cells`, canonical-JSON dedupe — mutations never add keys,
  so canonical form equals the on-disk cell). Definitive numbers
  come from the next campaign run.
- crAPI joins the campaign as a third SUT (4-cell grid:
  shell-injection × TLS); its numbers come from the same run.

Analyze any campaign directory (stdlib only, exact paired sign-flip
test):

```bash
python -m fuzzrex.analysis findings/phase1   # table + p-values + CSV
```

### Reproduce on GitHub Actions

The full campaign runs on a 4-core runner (no local Docker needed):
**Actions → Phase 1 campaign → Run workflow** (pick one SUT or run all
three). Each SUT job checkpoints its JSON into an artifact even on
failure, and the analyze job publishes the summary table to the
workflow's step summary plus `phase1-analysis` (CSV + report).

## Development

```bash
ruff check fuzzrex tests
pytest
```

## Motivation

Fuzzing API schemas and deployment configuration as one package shortens security assessments: both are attack surfaces, and interaction bugs between them are what this project is ultimately aiming to search.

## License

MIT
