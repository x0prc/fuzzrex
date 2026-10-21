# Live validation of fuzzrex.discover

Date: 2026-10-19. Two SUTs, both fixtures local, 11/11 checks pass after
the two fixes below. Script exercised: grafana (restart-mode) + crapi
(recreate-mode), stacks up/down via the campaign orchestrators.

## What passed

| Check | grafana | crapi |
|---|---|---|
| Curated subset fully kept by `prune_spec` | 9/9 ops | 7/7 ops |
| Blind-reachability canary warning | fires (401) | fires (401 unauth) |
| Unserved path dropped | kept — blind (see below) | dropped when chained |
| Observable knob kept by `filter_knobs` | `auth.anonymous.enabled` | `ENABLE_SHELL_INJECTION` |
| Inert knob filtered | `[log] level` | `ENABLE_LOG4J` |

## Design findings (both became code fixes)

### 1. Auth-first middleware blinds unauthenticated pruning

Both SUTs run security filters *before routing*: an unknown path and a
gated path answer byte-identical 401s to anonymous probes
(grafana: `auth.unauthorized`; crapi: `Invalid Token`). Status-based
reachability therefore cannot classify unserved operations without a
session. crapi diagnoses cleanly:

- unauth unknown → 401 (filter), auth unknown → **404** (router)
- so pruning *does* work when the probe is chained-authenticated via
  `x-fuzzrex-token-from`; an unchained bogus path never classifies.

Fix shipped: `prune_spec` probes one random canary path first; a kept
status means the unauthenticated view is blind and a warning says so
(including the remedy: chain a login). `filter_knobs` unaffected —
observability is compared within authenticated replays anyway.

### 2. Raw snapshot comparison false-positives on volatile payloads

crapi login returns a JWT whose `iat` changes every request; raw body
comparison marked even the inert `ENABLE_LOG4J` knob observable,
reproducing none of the manual probe record. Fix shipped: evidence is
now structured — status + Location + sensitive-key names + body with
sensitive keys masked (oracle's `is_sensitive_key`); raw text sample
ignored. After the fix: `ENABLE_SHELL_INJECTION` survives masking
(structural response change) and `ENABLE_LOG4J` is filtered, matching
`targets.md`.

## Follow-ups

- `filter_knobs` limitation remains for SUTs that churn *plain* fields
  (request ids under innocent names): conservative direction (false
  keep costs applies; never drops a live knob).
- DVWA not re-validated live (mariadb stack heavier; its two knobs
  flip status classes, which masking cannot hide).
