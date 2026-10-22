# SRCGuard tutorial — commands, start to finish

This is the hands-on companion to the README. Everything runs from the repository root.

`SRCGuard` in the examples means:

```bash
cd /path/to/srcguard
export PYTHONPATH=.
```

---

## 0. Check the machine

```bash
uv run pytest -q        # 149 tests
./check_strix.sh        # zero-diff guard (skips if no local strix-main)
```

Requirements: Linux + Docker, Python 3.10+ (`pyyaml`, `httpx`, `pytest`), and a Strix 1.7.0 binary.

---

## 1. Put Strix somewhere

```bash
mkdir -p ~/tools
mv strix-1.7.0-linux-x86_64 ~/tools/strix-1.7.0
chmod +x ~/tools/strix-1.7.0
```

Either pass `--strix-bin ~/tools/strix-1.7.0` on every run, or:

```bash
export STRIX_BIN=~/tools/strix-1.7.0
```

Do not commit the binary.

---

## 2. Write the scope

```bash
cat > /tmp/proj-scope.yaml <<'YAML'
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
YAML
```

Validate it:

```bash
python3 -m srcguard.cli check --scope /tmp/proj-scope.yaml
```

---

## 3. Start the LLM gateway

Keep it running in a separate terminal (or a background job):

```bash
export STRIX_LLM=openai/deepseek-flash
export LLM_API_KEY=gateway-local

python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Authorized scope: only the host in scope. GET/HEAD + POST open, no DELETE/PUT/PATCH. 1 rps." \
  --model deepseek-flash \
  --listen-host 127.0.0.1 --listen-port 8797 \
  --audit /tmp/proj-gateway.jsonl \
  --price-input 0.28 --price-cached 0.07 --price-output 1.10 \
  --max-cost 3 --max-tokens 20000000
```

`--max-cost` is a safety net (1.5–2× the Strix budget), not the primary control.

---

## 4. Preview the Strix command (no traffic, no spend)

```bash
python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --dry-run
```

It prints `run_dir`, `instruction`, and the exact `argv` handed to Strix.

---

## 5. Run

```bash
python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin ~/tools/strix-1.7.0 \
  --max-commands 60 --max-concurrent-runs 1 \
  --out-dir srcguard_runs/example --launch
```

---

## 6. When it stops at the budget, continue

```bash
python3 -m srcguard.cli run \
  --resume <run_id> --scope /tmp/proj-scope.yaml \
  --max-turns 20 --max-budget 4 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin ~/tools/strix-1.7.0 --out-dir srcguard_runs/example
```

Resume reuses the run directory, instruction, MCP config and `.state/`; the scope must hash to the
same policy. Repeat until the run reports `completed`.

---

## 7. Audit

```bash
python3 -m srcguard.cli audit \
  --run srcguard_runs/example/<run_id> --scope /tmp/proj-scope.yaml

cat srcguard_runs/example/<run_id>/compliance.md
```

Outputs:

```
policy.json  instruction.md  mcp-servers.json  usage.json  compliance.md
audit/{caido,egress,writes,blocked,oob,rate,method}.jsonl   audit/mcp.log
strix_runs/<name>/{penetration_test_report.md, vulnerabilities/, coverage.json}
```

Cost: read the gateway audit (`event: usage`), not `usage.json`.

---

## 8. Authenticated runs (cookie)

Operator logs in by hand, exports the Cookie header to a `0600` file:

```bash
install -m 600 /dev/null /tmp/target-cookie
printf 'SESSION=...; uid=...' > /tmp/target-cookie
```

Run with `--session-cookie-file /tmp/target-cookie`. The value is copied to the sandbox at
`/tmp/.srcguard-cookie` (0600) and never written into the run directory.

Tell the agent to use it **without printing it**:

```bash
curl -s -H @/tmp/.srcguard-headers https://www.example.edu.cn/protected
```

(create `/tmp/.srcguard-headers` with `printf 'Cookie: %s' "$(cat /tmp/.srcguard-cookie)"` and
`chmod 600`). Do not `cat` the cookie, do not use `curl -v`. Rotate the session afterwards.

---

## 9. Blind callbacks (OOB)

With `oob: {mode: http, public: true}` in scope, SRCGuard starts a local callback server and a
Cloudflare quick tunnel, then appends the public URL + token to the instruction. Hits land in
`audit/oob.jsonl`. Add `--kill-on-oob` to stop on the first callback. HTTP only.

---

## 10. Hand it to an AI agent

Give the agent the repository and this prompt:

```text
You are operating SRCGuard. Read AGENTS.md and docs/tutorial.md first.

Ask me for:
  1) written authorization for the target,
  2) the exact in-scope hosts,
  3) allowed methods and rate limits,
  4) the budget in USD.

Then execute the tutorial: check → gateway → dry-run → launch → audit.
Never widen the scope, never send DELETE/PUT/PATCH, never use real accounts.
If a run stops at its budget, resume it with a higher --max-budget.
Report: what was tested, what was blocked, what remains a gap, and the metered cost.
Never claim a target is "safe".
```

The agent should run `--dry-run` first and show you the argv before launching.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `repeated_403` kill | WAF rejecting probes | 1 rps; raise `limits.max_blocked` to 20–40 |
| `rate_exceeded` kill | burst/ sustained over-rate | lower `default_rps`, raise `burst_rps` |
| gateway 429 `srcguard budget` | safety net hit | raise `--max-cost`, or use Strix budget + resume |
| many `response: null` | target slow / WAF silent drop | retry later at 1 rps |
| no report | run was killed or stopped | check `coverage.json`; resume or rerun |
| `compliance FAIL` | evidence ids missing | inspect `evidence_issues`, rerun the finding |
| DNS failures | resolver not in allow set | look for `system DNS allowed on port 53` at startup |
| stale nft table after SIGKILL | supervisor did not clean | `NftCage.for_run("<run_id>").cleanup(ignore_missing=True)` |

---

## 12. Before you submit

- [ ] only authorized hosts in scope
- [ ] no DELETE/PUT/PATCH; POST only where allowed
- [ ] rate ≤ 1–2 rps; stopped when the WAF pushed back
- [ ] no WAF bypass, no real accounts, OOB token only
- [ ] cookie file `0600`, deleted after the run
- [ ] `compliance.md` + report + authorization proof kept together
