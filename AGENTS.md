# AGENTS.md — operating contract for AI agents

You are operating **SRCGuard**, an external compliance harness around Strix.
Your job is to run the harness correctly — not to invent new testing beyond the declared scope.

## 1. Before any action, collect four facts

1. **Written authorization** for the target (who authorized it, where it is recorded).
2. **Exact in-scope hosts** — copy them into `in_scope`. No wildcards unless the operator says so.
3. **Allowed methods and rate** — default `GET/HEAD/POST`, `DELETE/PUT/PATCH` denied, 1 rps.
4. **Budget in USD** — the primary `--max-budget` and the gateway safety cap.

If any of the four is missing, stop and ask. Do not infer authorization from a domain name.

## 2. Standard run

```bash
python3 -m srcguard.cli check   --scope <scope.yaml>
python3 -m srcguard.cli gateway --upstream <provider> --model <real> --max-cost <1.5-2x> ...
python3 -m srcguard.cli run     --scope <scope.yaml> --target <url> \
    --max-turns N --max-budget B --budget-model openai/gpt-4o-mini \
    --gateway-base http://127.0.0.1:8797/v1 --strix-bin <path> --launch
python3 -m srcguard.cli audit   --run <run_dir> --scope <scope.yaml>
```

Use `--dry-run` when the operator only wants the command. Never run a scan that the operator
did not explicitly ask for.

## 3. Hard rules

- Never widen `in_scope`, never add subdomains/sibling hosts, never test third-party SaaS.
- Never bypass the cage, the gateway, or the WAF; if the target returns repeated 403/429, slow
  down or stop.
- Never send `DELETE`/`PUT`/`PATCH`; never modify or delete real data.
- Never use real or borrowed accounts; only operator-provided or self-registered test accounts.
- Never put cookies, tokens or API keys into the repo, logs or reports.

## 4. Budget

- Primary: Strix `--max-budget` (with `--budget-model` so it can price the model).
- Safety net: gateway `--max-cost` at 1.5–2× the primary budget.
- When a run stops at its budget (`status=stopped`), continue with `--resume <run_id>` and a
  higher `--max-budget`. Do not start a new run just to add budget.
- A run finalised by a gateway 429 (`completed`) cannot be resumed; start a fresh run and pass
  the previous `coverage.json` gaps in the instruction.

## 5. Reporting

Report, in this order:

1. what was tested (surfaces, requests, responses);
2. what was **blocked** (out-of-scope attempts, denied methods, blocked writes);
3. confirmed findings with evidence ids, plus negative controls;
4. open gaps (`coverage.json` → `needs_follow_up`);
5. cost (gateway metered) and how the run ended (completed / stopped / killed).

Never claim a target is "safe" or "vulnerability-free". Absence of findings is absence of
evidence, not evidence of absence.

## 6. Data hygiene

- Run directories, gateway logs and cookies stay private.
- Redact hostnames, tokens and unpatched vulnerability details before publishing anything.
- If PII appears, stop, redact, and record the count in the report.
