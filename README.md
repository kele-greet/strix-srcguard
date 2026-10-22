# SRCGuard

**A compliance-first SRC / bug-bounty harness you can hand to an AI agent.**

SRCGuard wraps [Strix](https://github.com/usestrix/strix) 1.7.0 from the outside — **zero changes
to `strix-main`** — so an autonomous agent can hunt real, authorized targets without leaving the
scope you declared. Scope is enforced in the kernel. Every request, write and blocked attempt is
recorded. Budgets stop on a clean boundary and can be topped up.

> **This project does not grant authorization.** It enforces the scope *you* declare. Use it only
> against systems you are explicitly and verifiably authorized to test.
>
> [中文说明](README.zh-CN.md)

---

## Why this exists

Pointing an autonomous agent at a real SRC target raises three questions that a prompt alone
cannot answer:

1. **Scope** — will it wander into a newly discovered subdomain, a sibling site, a CDN, or SaaS?
2. **Blast radius** — will it DELETE, bulk-export, stress, or carry credentials out of the sandbox?
3. **Evidence** — when the report says "GET / returned 200", can you prove it to the program owner?

SRCGuard answers them **outside** the agent:

| Layer | Mechanism | Guarantee |
|---|---|---|
| **Scope cage** | per-run nftables table; only IPs resolved from the declared scope may egress | hard (kernel) |
| **Metadata guard** | RFC1918 / link-local / cloud metadata are blackholed | hard (kernel) |
| **Rate & burst** | per-host and global new-connection limits | hard (kernel) |
| **Command guard** | MCP `sandbox_exec` checks methods, POST paths, command quotas | soft (command level) |
| **LLM gateway** | policy injection into every model call, credential redaction, usage metering, hard budget cap | soft + accounting |
| **Evidence** | Caido observer, egress log, write log, blocked-attempt log, OOB callbacks, compliance report | read-only |

The agent still does the hunting. SRCGuard does not pick targets, payloads, or findings — it
constrains the boundary and records what crossed it.

---

## Hand it to an AI agent

This repository is written to be operated by an AI coding agent. Put the repo in front of your
agent and paste:

```text
You are operating SRCGuard, an external compliance harness around Strix.
Read AGENTS.md and README.md first.

Before doing anything, ask me for:
  1) written authorization for the target,
  2) the exact in-scope hosts (no wildcards unless I say so),
  3) allowed methods and rate limits,
  4) the budget in USD.

Then follow docs/zh/run-sop.md: check → gateway → dry-run → launch → audit.
Never widen the scope. Never claim a target is "safe" — report what was tested, what was
blocked, and what remains a gap. If a run stops at its budget, resume it with a higher
--max-budget instead of starting over.
```

`AGENTS.md` is the operating contract (scope, stop rules, budget, evidence, reporting) and is
picked up automatically by most agent runtimes.

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

LLM path:  Strix ──► SRCGuard gateway ──► provider
                        ├ policy injection
                        ├ credential redaction
                        ├ usage metering
                        └ hard budget cap → 429
```

---

## Quick start

### Requirements

- Linux with Docker (WSL2 verified).
- Strix 1.7.0 binary (not bundled — see below).
- Python 3.10+ with `pyyaml`, `httpx`, `pytest` (or `uv`).

```bash
uv run pytest -q        # 149 tests
./check_strix.sh        # zero-diff guard when a local strix-main exists
```

### Where Strix goes

Download the Strix 1.7.0 binary from its releases and place it anywhere, e.g.:

```bash
mkdir -p ~/tools && mv strix-1.7.0-linux-x86_64 ~/tools/strix-1.7.0
chmod +x ~/tools/strix-1.7.0
```

Never commit it (`.gitignore` covers `strix-*`). Point SRCGuard at it either way:

```bash
python3 -m srcguard.cli run ... --strix-bin ~/tools/strix-1.7.0 --launch
# or
export STRIX_BIN=~/tools/strix-1.7.0
```

Under the hood SRCGuard launches (printable with `--dry-run`):

```
strix -n -t <target> --scan-mode quick --max-turns N --max-budget M \
      --instruction-file <run>/instruction.md \
      --mcp-config <run>/mcp-servers.json
```

The sandbox image (`ghcr.io/usestrix/strix-sandbox:1.3.0`) is pulled by Strix itself.

### The four commands

```bash
# 1) validate the scope
python3 -m srcguard.cli check --scope /tmp/proj-scope.yaml

# 2) start the LLM gateway (safety net; keep it running)
python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Authorized scope: only the host in scope. GET/HEAD + POST open, no DELETE/PUT/PATCH. 1 rps." \
  --model deepseek-flash --listen-port 8797 \
  --price-input 0.28 --price-cached 0.07 --price-output 1.10 \
  --max-cost 3 --max-tokens 20000000

# 3) run inside the cage
python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin ~/tools/strix-1.7.0 --out-dir srcguard_runs/example --launch

# 4) audit
python3 -m srcguard.cli audit --run srcguard_runs/example/<run_id> --scope /tmp/proj-scope.yaml
```

Add `--dry-run` instead of `--launch` to print the Strix argv without any network traffic or spend.

### Two budgets, one clean stop

| Control | Flag | Behaviour |
|---|---|---|
| Strix budget (primary) | `--max-budget` + `--budget-model openai/gpt-4o-mini` | stops at the limit with agents in `stopped` state — **resumable** |
| Gateway cap (safety net) | `--max-cost` / `--max-tokens` | hard stop at 1.5–2× the primary budget; returns 429 |

`--budget-model` lets Strix price its spend (LiteLLM has no price for `deepseek-flash`), while the
gateway rewrites the upstream model to the real one. When the budget stops the run, continue the
same run:

```bash
python3 -m srcguard.cli run --resume <run_id> --scope /tmp/proj-scope.yaml \
  --max-turns 20 --max-budget 4 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --launch
```

### Scope example

```yaml
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

---

## What a run leaves behind

```
policy.json  instruction.md  mcp-servers.json  usage.json  compliance.md
audit/{caido,egress,writes,blocked,oob,rate,method}.jsonl   audit/mcp.log
strix_runs/<name>/{penetration_test_report.md, vulnerabilities/, coverage.json}
```

`compliance.md` is the report you hand to a program owner: contacted hosts, out-of-scope
attempts (blocked vs. successful), write requests, evidence cross-checks, and PII/secret hits.

---

---

## Capability impact, in numbers

SRCGuard lives at the boundary, not in the agent loop. It does not choose tools, endpoints or
payloads, does not rewrite findings, and does not touch in-scope traffic beyond recording it.

Data from **15 completed authorized runs** (Strix 1.7.0, quick mode, guard on):

| Metric | Observed |
|---|---|
| HTTP requests / responses | **2,263 / 1,606** |
| Surfaces reviewed / open gaps | **265 / 119** |
| Write requests (POST etc.) | **492 allowed and logged** (`writes.jsonl`) |
| Out-of-scope attempts dropped by the cage | **43** (`blocked.jsonl`, third-party/CDN only) |
| Findings produced by Strix under the guard | **3**, two manually confirmed |
| Guard kills in completed runs | **0** |
| Policy block added per LLM call | ~70–100 tokens against a 60–80K context → **<0.2%** |

What this shows:

- the agent kept its normal volume and surface coverage (71–261 requests and 14–30 surfaces per
  run) while the harness was active;
- the guard touched **edge traffic only**: a few dozen out-of-scope packets per engagement, while
  hundreds of in-scope writes went through untouched and were recorded;
- Strix still **found real issues under the guard** (CWE-209 stack-trace disclosure, CWE-639
  unauthenticated attachment IDOR), which is the strongest evidence that capability is preserved.

The only intentional behaviour changes are policy choices, not interception:

| Change | Type | Can be disabled |
|---|---|---|
| Instruction text (scope, methods, rate, data rules) | prompt constraint | edit the template |
| `--max-turns` / `--max-budget` | budget | raise them |
| `--caido-tamper` (denied method → GET) | traffic rewrite | omit the flag |
| `--docker-proxy` (drop NET_ADMIN, reject privileged) | sandbox capability | omit the flag |

Everything else — Caido observation, nft accept/rate rules, gateway metering, audit — is passive
or boundary-only. The network path for in-scope traffic is unchanged: one accept rule in the
kernel, and Caido is already part of Strix's default stack (SRCGuard only reads from it).

> Early versions of the guard did break scans (empty DNS allow-set, an inverted rate rule). Those
> were bugs, not design limits; each is fixed and covered by the 149 tests.

## Honest boundaries

- **The nft cage is the only hard network boundary.** Method and path rules are command-level or
  post-hoc; Caido in this version cannot drop a request.
- `--caido-tamper` **rewrites** denied methods to GET (a downgrade, not a drop).
- `--docker-proxy` restricts sandbox capabilities (no `NET_ADMIN`, no privileged/host netns).
- Out-of-scope hosts dropped by the cage are recorded as `blocked_attempt`, not killed.
- No authoritative DNS OOB; HTTP callbacks only.
- `strix-main` is never modified (`check_strix.sh` enforces the zero diff).

## Data hygiene

This repository is desensitized:

- no real-target findings are published; `evidence/` contains local-lab proofs only;
- run directories, gateway logs, cookies and API keys are gitignored and stay private;
- if you publish your own results, redact hostnames, tokens and unpatched vulnerability details
  until the program owner has fixed them.

## License

MIT — see `LICENSE` and `NOTICE`. Strix is a separate project with its own license; SRCGuard
contains none of its code.
