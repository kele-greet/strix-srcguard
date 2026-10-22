# SRCGuard

**A compliance-first SRC / bug-bounty harness for [Strix](https://github.com/usestrix/strix).**

SRCGuard wraps Strix 1.7.0 from the outside — **zero changes to `strix-main`**. It gives Strix a
scope cage, an LLM gateway with policy injection and hard budget control, and an evidence trail
you can hand to a program owner.

> Only use this against systems you are explicitly authorized to test. SRCGuard enforces the
> scope you declare; it does not grant authorization.

---

## What it solves

Strix is powerful, but pointing it at a real SRC target has three problems:

1. **Scope** — the model may wander into newly discovered subdomains, sibling sites, CDNs or SaaS.
2. **Actions** — DELETE, bulk data pulls, stress, or credentials leaving the sandbox.
3. **Evidence** — "I sent GET / and got 200" is a claim; the report needs to be reproducible.

SRCGuard's answer:

| Layer | What it does |
|---|---|
| **L3 cage** | Per-run nftables table; only IPs resolved from the declared scope can leave. RFC1918 / link-local / metadata are blackholed. Per-host new-connection rate limits. |
| **L1 instruction** | Generates the SRC discipline brief Strix receives (scope, allowed methods, rate, data rules). Sub-agents do not inherit it, so the cage is the backstop. |
| **L2 gateway** | Injects a `<srcguard_policy>` block into every LLM call, redacts credential-like tool output, meters usage, and enforces a hard `--max-cost` / `--max-tokens` cap. |
| **Evidence** | Caido observer, nft egress log, write-request log, blocked-attempt log, OOB callbacks, MCP command log, and an audit report (`compliance.md`). |

SRCGuard does **not** plan tests, choose payloads, or filter findings. Strix does the hunting;
SRCGuard constrains the boundaries and records what happened.

---

## Architecture

```
Strix agents
  ├─ browser / proxy tools ──► Caido (in sandbox) ──┐
  └─ MCP sandbox_exec ──► [command guard] ──► exec ─┤
                                                     ▼
                                            sandbox container
                                                     │
                                              docker0 (host)
                                                     │
                        ┌────────────────────────────┴─────────────┐
                        │ nft table srcguard_<run>                  │
                        │  forward: rate → dns → allow4 → block4 → drop
                        │  input:   dns / oob / lab / allow4 / drop │
                        └────────────────────────────┬─────────────┘
                                                     │
                                              host NAT → internet

LLM path:  Strix ──► srcguard gateway ──► provider
                        ├ policy injection
                        ├ secret redaction
                        ├ usage metering
                        └ budget cap → 429
```

---

## Quick start

### 1. Requirements

- Linux with Docker (WSL2 verified).
- Strix 1.7.0 binary (not bundled here).
- Python 3.10+ with `pyyaml`, `httpx`, `pytest` (or `uv`).

```bash
uv run pytest -q        # 149 passed
./check_strix.sh        # verifies strix-main is untouched
```

### 2. Write a scope

```yaml
# /tmp/proj-scope.yaml
program: my-src
in_scope: ["www.example.edu.cn"]
methods:
  deny: [DELETE, PUT, PATCH]
  allow: [GET, HEAD, POST]
  post_mode: open
  max_body_bytes: 65536
rate: {default_rps: 1, burst_rps: 15}
limits: {max_blocked: 15}
oob: {mode: http, public: true}
web_search: {enabled: false}
budgets: {max_turns: 20, max_budget_usd: 2}
```

```bash
python3 -m srcguard.cli check --scope /tmp/proj-scope.yaml
```

### 3. Start the LLM gateway

```bash
python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Authorized scope: only the host in scope. GET/HEAD + POST open, no DELETE/PUT/PATCH. 1 rps." \
  --model deepseek-flash --listen-port 8797 \
  --price-input 0.28 --price-cached 0.07 --price-output 1.10 \
  --max-cost 3 --max-tokens 20000000
```

The gateway cap is a safety net. Use **Strix's own budget** as the control:
`--max-budget` + `--budget-model openai/gpt-4o-mini` makes Strix stop cleanly at the limit,
and `--resume` with a higher budget continues the same run.

### 4. Run

```bash
python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin /path/to/strix-1.7.0 \
  --out-dir srcguard_runs/example --launch
```

Add `--dry-run` instead of `--launch` to only print the Strix argv (no network traffic, no spend).

### 5. Continue when the budget stops it

```bash
python3 -m srcguard.cli run --resume <run_id> --scope /tmp/proj-scope.yaml \
  --max-turns 20 --max-budget 4 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --launch
```

### 6. Audit

```bash
python3 -m srcguard.cli audit --run srcguard_runs/example/<run_id> --scope /tmp/proj-scope.yaml
cat srcguard_runs/example/<run_id>/compliance.md
```

A run directory contains:

```
policy.json  instruction.md  mcp-servers.json  usage.json  compliance.md
audit/{caido,egress,writes,blocked,oob,rate,method}.jsonl  audit/mcp.log
strix_runs/<name>/{penetration_test_report.md, vulnerabilities/, coverage.json}
```

---

## Repository layout

```
srcguard/          # cage, gateway, monitor, observer, preflight, audit
tests/             # 149 unit/integration tests
samples/           # local lab scope
scripts/           # balance_gate, CI helpers
docs/zh/           # Chinese manual, run SOP, architecture, security baseline
evidence/          # local-lab proofs (no real-target findings)
```

## Safety boundaries (honest list)

- The **nft cage is the only hard network boundary**; method/path rules are command-level or
  post-hoc (Caido in this version cannot drop a request).
- `--caido-tamper` **rewrites** denied methods to GET (a downgrade, not a drop).
- `--docker-proxy` restricts sandbox capabilities (no NET_ADMIN, no privileged/host netns).
- Out-of-scope hosts that the cage drops are recorded as `blocked_attempt`, not killed.
- No authoritative DNS OOB (HTTP callbacks only).
- `strix-main` is never modified (`check_strix.sh` enforces a zero diff).

## License

MIT. See `LICENSE` and `NOTICE` (Strix is a separate project with its own license).
