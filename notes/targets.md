# Phase 1 SUT target triage

Scored against the adapter requirements: (1) config injected as a file the
orchestrator can rewrite + restart, (2) security-relevant config knobs,
(3) OpenAPI spec available, (4) health endpoint for `wait_healthy`.
Spike date: 2026-09-27. Evidence collected live on this machine.

## Tier 1 — Phase 1 set (verified hands-on)

### DVWA (digininja/DVWA) — verified

| Criterion | Result |
|---|---|
| Config model | `config/config.inc.php` bind-mounted over `/var/www/html/config/config.inc.php`; PHP re-reads per request, restart harmless |
| Security knobs | `disable_authentication` (bool), `default_security_level` (`low/medium/high/impossible` — gates which API vulns are active) |
| Spec | Shipped: `/vulnerabilities/api/openapi.yml` (OpenAPI 3.0, 4 controllers: health, login, user, order) — served live with 200 |
| Health | `GET /vulnerabilities/api/v2/health/ping` → `{"Ping":"Pong"}` |
| Weight | `ghcr.io/digininja/dvwa:latest` + `mariadb:10`, 2 services |

**Observed divergence:** `disable_authentication=false` →
`/vulnerabilities/sqli/` = 302; `=true` → 200 (auth-boundary class).
Security-level knob changes API behavior per docs (low: versioning vuln,
medium: mass assignment, high: command injection on `/health/connectivity`)
— expect `server-error` divergences at high.

**Adapter notes:** compose fixture + config file template; health_path
must be set to the ping endpoint (not `/health`).

### Grafana OSS — verified

| Criterion | Result |
|---|---|
| Config model | `grafana.ini` bind-mounted to `/etc/grafana/grafana.ini` (single file, no permission issue observed), restart applies |
| Security knobs | `[auth.anonymous] enabled`, `[auth] disable_login_form`, `[security] disable_brute_force_login_protection` |
| Spec | 🟡 not bundled; official spec generated in grafana/grafana repo — needs sourcing/curating (subset: org, dashboard search, user, admin endpoints) |
| Health | `GET /api/health` → 200 |
| Weight | single container `grafana/grafana-oss` |

**Observed divergence:** `[auth.anonymous] enabled=false` →
`/api/search` = 401; `=true` → 200 (auth-boundary class).

**Adapter notes:** standard single-service compose; spec curation is the
only open work.

## Tier 2 — hold

### crAPI (OWASP)

- Spec: ✅ ships `openapi-spec/crapi-openapi-spec.json` (public raw URL)
- Config: ⚠️ `.env` read by compose at `up` time; env changes need
  container **recreate**, our orchestrator only **restarts** — would
  require an orchestrator `recreate` mode first
- Knobs: 🟡 mostly deployment (ports, TLS, LLM keys), not deep
  security-behavior toggles
- Weight: ❌ 6+ services (postgres, mongo, identity, community,
  workshop, chatbot, mailhog) — heavy for iteration loops

### Juice Shop (OWASP)

- Spec: 🟡 `swagger.yml` covers only `/b2b` (ordering API)
- Knobs: ❌ config is CTF key / challenge options — no auth/debug toggles
- Health: ❌ none built in
- Verdict: reject for Phase 1; weak config surface for this thesis

## Decisions

1. **Phase 1 set: DVWA + Grafana** (+ demo-api as the fast unit SUT).
2. crAPI stays a stretch target only if an orchestrator `recreate` mode
   is added later (env-based config).
3. Open work before runs: Grafana spec subset, per-SUT compose
   fixtures under `examples/`, config-matrix definitions
   (DVWA: 2×4 cells; Grafana: anonymous × disable_login_form).
