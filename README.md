![f](https://github.com/user-attachments/assets/ecc42996-b9e9-4e85-8b15-395e36dbd117)

A CLI tool that fuzzes REST APIs from their OpenAPI spec and mutates configuration files (JSON/YAML) to surface unexpected behavior.

[Additional Docs](https://x0prc.github.io/notes/Notes/Published-Documentation/FuzzRex)

## Features

1. **API fuzzing** — loads an OpenAPI spec (JSON/YAML), generates type-aware request values (including out-of-range boundaries), routes parameters correctly (path/query/header/cookie/body), carries state across requests, and reports 5xx responses.
2. **Config fuzzing** — mutates JSON/YAML/INI configs (typed value flips, null injection, key deletion, structure damage; enum-constrained keys stay in their vocabulary) and writes reproducible variants to disk.
3. **Differential oracle** — replays one planned request sequence under two config cells and flags security-relevant divergence only: `auth-boundary` (401/403 or redirect-to-login flips), `info-leak`, `server-error`, `status`, `transport`. Redirects are not followed, so login redirects are compared raw.
4. **Joint Config×API search** — feedback loop that mutates the config, probes the API, and grows from divergent cells.
5. **Baseline runner** — replays Schemathesis per config cell for the single-cell comparison arm.
6. **Early stopping (opt-in)** — `run_comparison(..., stall_window=k)` stops a seed's joint arms once k consecutive iterations produce no new unique divergent cell; recorded per arm as `stopped_early`. Off by default, so the archived Phase 1 protocol is untouched.
7. **Discovery** — `fuzzrex.discover` mechanizes fixture prep against a running baseline cell: `prune_spec` keeps only operations the deployment serves (dropping 404/501/transport-dead ones and anything chained to them) and warns when a canary probe shows an auth middleware answering before routing, which makes reachability unverifiable without a chained login; `filter_knobs` keeps only candidate config keys whose values change an HTTP response.
8. **Request-side mutation (opt-in)** — `run_comparison(..., request_mutation=p)` makes an iteration replay a single-slot mutated copy of the planned sequence with probability p (query/cookie/JSON-body scalars resampled from typed boundary pools; methods, URLs, links, and files untouched). Pairing is preserved by lazily recording and caching each variant's baseline under c0, so only the config can explain a divergence; divergent cells record the patch that defined their request variant. Default 0.0 reproduces the fixed-sequence protocol exactly.
9. **Per-seed plan variety (opt-in)** — `run_comparison(..., plan_mutations=k)` re-varies k request slots of the planned sequence per seed from the same typed pools (deterministic in the seed; producer requests like logins are excluded so chained links keep resolving), so seeds no longer share one global plan. 0 keeps the archived protocol.

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

### Campaign runner (fuzzrex-campaign)

`fuzzrex-campaign` (equivalently `python -m fuzzrex.campaign`) runs the
full comparison against any docker-compose SUT from the command line
with per-seed checkpointing — re-running skips completed seeds
(crash-safe resume):

```bash
fuzzrex-campaign \
  --compose examples/crapi/compose.yml --service crapi-identity \
  --config examples/crapi/.env --base-url http://127.0.0.1:8080 \
  --health-path /identity/health_check --reload recreate \
  --spec examples/crapi/openapi.yml \
  --baseline-config baseline.json --cells knobs.json \
  --out findings/phase2/crapi.json \
  --seeds 10 --iterations 30 --stall 8 \
  --request-mutation 0.2 --plan-mutations 2
```

`--baseline-config` is the baseline cell (JSON/YAML/INI). `--cells`
takes either an explicit list of config documents or a domains object
`{key: [values]}` expanded with `config_grid` from the baseline —
dotted domain keys nest into it (grafana:
`auth.anonymous.enabled`, literal dotted keys stay flat), and every
cell is the baseline with the domain keys applied. Domains double as
the default enum constraints for mutation, keyed by the resolved leaf
name (`--enums` overrides). `--arms` selects joint arms by name,
`--no-baseline` skips the Schemathesis arm. The checkpoint JSON
records the whole budget (arms, stall, mutation probabilities) for
provenance, and resuming refuses a checkpoint whose protocol differs
from the current arguments, so budgets can never be mixed in one
results file. Phase 1's archived protocol stays in
`examples/phase1_campaign.py`, untouched.

### Phase 1: joint vs baseline vs ablation

`fuzzrex.experiments.run_comparison` runs three arms under matched
seeds — joint search, the same search with the feedback loop disabled
(ablation), and Schemathesis once per cell of the static config grid —
and checkpoints a JSON summary per seed into `findings/phase1/`
(gitignored). Campaign: 10 seeds x 30 iterations, 5 examples/op for
the baseline (`examples/phase1_campaign.py`, crash-safe resume;
[run 38034106363](https://github.com/x0prc/fuzzrex/actions/runs/38034106363)
plus the crAPI resume
[run 38145879213](https://github.com/x0prc/fuzzrex/actions/runs/38145879213)):

| SUT | Grid | joint (probes → unique) | no-feedback (probes → unique) | paired (sign-flip) | baseline |
|---|---|---|---|---|---|
| dvwa | 8 cells | **11.20 ± 2.82 → 3.80** | 9.20 ± 3.19 → 1.00 | Δ=+2.00, p=0.13 | 48.0/seed → 2 unique |
| grafana | 2 cells | 12.40 ± 2.80 → 1.00 | **14.80 ± 2.30 → 1.00** | Δ=−2.40, p=0.037 | 0 |
| crapi | 4 cells | **23.50 ± 4.74 → 3.00** | 14.30 ± 3.16 → 2.00 | **Δ=+9.20, p=0.002** | 18.0/seed → 2 unique |

Reading the table:

- **Unique effective configs (`unique_cells`) is the headline**:
  joint covers 3.80 of DVWA's 8 cells and 3.00 of crAPI's 4, versus
  1.00 and 2.00 for the ablation — exploiting divergent cells grows
  *config diversity*, not just probe volume. Probe counts alone
  understate this: on Grafana's depth-1 knob every visit lands the
  same cell (unique=1 for both arms) and the ablation wins on probes
  (p=0.037).
- **Baseline is config-blind**: DVWA's 48 findings/seed collapse to
  2 unique signatures (crAPI: 18 → 2; Grafana: 0) — per-cell API
  fuzzing cannot observe auth gating or the bash-exec 500 that only
  appear when the config flips.
- **crAPI is the strongest result**: `status` + `server-error` kinds
  (the `ENABLE_SHELL_INJECTION` bash branch), first divergence at
  iteration 0.9, and the only SUT where feedback is significant in
  the joint direction (Δ=+9.20, p=0.002, n=10 — assembled across two
  runs via cross-run checkpoint resume).
- **Reproducibility**: an independent fresh 10-seed rerun of the crAPI
  campaign
  ([run 38524313670](https://github.com/x0prc/fuzzrex/actions/runs/38524313670))
  reproduced every non-timing field exactly — same divergent cells,
  unique configs, kinds, and p=0.002 — at 2.4x lower wall time
  (deferred restores; ~460 s/arm vs ~1090 s/arm).

Analyze any campaign directory (stdlib only, exact paired sign-flip
test):

```bash
python -m fuzzrex.analysis findings/phase1   # table + p-values + CSV
```

### Reproduce on GitHub Actions

The full campaign runs on a 4-core runner (no local Docker needed):
**Actions → Phase 1 campaign → Run workflow** (pick one SUT or run all
three). Each SUT job checkpoints its JSON into an artifact even on
failure, and a re-dispatch restores the latest checkpoint first, so
long jobs resume across attempts instead of restarting (dispatch with
`fresh` to rerun every seed from scratch). The analyze job publishes
the summary table to the workflow's step summary plus
`phase1-analysis` (CSV + report).

## Development

```bash
ruff check fuzzrex tests
pytest
```

## Motivation

Fuzzing API schemas and deployment configuration as one package shortens security assessments: both are attack surfaces, and interaction bugs between them are what this project is ultimately aiming to search.

## License

MIT
