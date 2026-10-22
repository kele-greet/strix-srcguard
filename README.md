# SRCGuard

**A compliance shell for Strix — plug it in, hand it to your AI agent, and let Strix hunt inside a scope you can defend.**

SRCGuard does not replace Strix and does not modify it. It wraps the Strix 1.7.0 binary from the
outside: scope is enforced in the kernel, model calls go through a policy gateway, every request
and every blocked attempt is recorded. Strix keeps doing the hunting.

> **SRCGuard does not grant authorization.** It enforces the scope *you* declare. Use it only on
> systems you are explicitly and verifiably authorized to test.
>
> 中文说明：[README.zh-CN.md](README.zh-CN.md) · 命令教程：[docs/tutorial.md](docs/tutorial.md)

---

## Plug-and-play

- One binary to point at: `strix-1.7.0-linux-x86_64`. Nothing to patch, nothing to rebuild.
- One command to preview, one to run, one to audit.
- Runs in **dry-run** by default for command generation — no traffic, no spend.
- If a run stops at its budget, resume the same run with a higher budget instead of starting over.

The whole integration is a wrapper: `check → gateway → run → audit`. No fork, no vendored Strix,
no changes to `strix-main`.

---

## The measures we took

| # | Measure | What it does | Nature |
|---|---|---|---|
| 1 | **Scope cage** | A per-run nftables table: only IPs resolved from the declared scope may leave the sandbox. Anything else is dropped and logged. | hard (kernel) |
| 2 | **Metadata guard** | RFC1918, link-local and cloud-metadata ranges are blackholed even if someone resolves a scope host there. | hard (kernel) |
| 3 | **Rate & burst** | Per-host and global new-connection limits, plus a sliding-window request rate in the monitor. | hard + monitor |
| 4 | **Command guard** | The MCP `sandbox_exec` channel checks denied methods, POST paths and command quotas before a shell command runs. | soft (command level) |
| 5 | **LLM gateway** | Injects the scope policy into every model call, meters usage with a price table, enforces a hard cost/token cap. | soft + accounting |
| 6 | **Evidence** | Caido observer, egress log, write-request log, blocked-attempt log, OOB callbacks, and a `compliance.md` report you can hand to a program owner. | read-only |
| 7 | **Clean stop** | Strix's own budget stops the run at a turn boundary with agents in `stopped` state; `--resume` continues the same run. | control |

What SRCGuard **never** does: choose targets, endpoints or payloads; edit findings; rewrite agent
messages beyond the policy block; block in-scope traffic.

---

## Does it hurt Strix's hunting ability? Data first.

Fifteen completed authorized runs, Strix 1.7.0, quick mode, guard fully on:

| Metric | Observed |
|---|---|
| HTTP requests / responses | **2,263 / 1,606** |
| Surfaces reviewed / gaps left open | **265 / 119** |
| Write requests (POST etc.) | **492 allowed and recorded** |
| Out-of-scope packets dropped by the cage | **43** (third-party/CDN only) |
| Findings produced by Strix under the guard | **3**, two manually confirmed |
| Guard kills in completed runs | **0** |
| Extra prompt per model call | ~70–100 tokens against 60–80K context → **<0.2%** |

The agent kept its normal volume (71–261 requests, 14–30 surfaces per run). The guard touched edge
traffic only: a few dozen out-of-scope packets per engagement, while hundreds of in-scope writes
went through untouched. And Strix still found real issues **while the guard was on** — a CWE-209
stack-trace disclosure and a CWE-639 unauthenticated attachment IDOR, both reproduced by hand.

**Conclusion: the guard is boundary-level, not capability-level.** The network path for in-scope
traffic is unchanged — one accept rule in the kernel — and Caido is already part of Strix's default
stack; SRCGuard only reads from it.

Only four things can change Strix's behaviour, and they are policy choices, not interception:
instruction text, turn/budget caps, optional `--caido-tamper` (rewrites a denied method to GET),
optional `--docker-proxy` (drops sandbox privileges). Everything else is passive.

> Early versions of the guard did interrupt scans (an empty DNS allow-set, an inverted rate rule).
> Those were bugs, not design limits; each is fixed and covered by the 149-test suite.

---

## Hand it to an AI agent

This repository is written to be operated by an AI agent. Give the agent the repo and say:

```text
You are operating SRCGuard. Read AGENTS.md first, then docs/tutorial.md.
Ask me for: written authorization, exact in-scope hosts, allowed methods/rate, and the budget.
Then run: check → gateway → dry-run → launch → audit. Never widen the scope.
Report what was tested, what was blocked, what remains a gap, and the metered cost.
```

`AGENTS.md` is the operating contract (scope, stop rules, budget, evidence, reporting). Most agent
runtimes pick it up automatically.

---

## Where Strix goes

SRCGuard does not bundle Strix. Download the 1.7.0 binary from Strix's releases, put it anywhere
(for example `~/tools/strix-1.7.0`), and point SRCGuard at it with `--strix-bin` or `STRIX_BIN`.
Never commit it. The sandbox image is pulled by Strix itself.

---

## Documentation

- **Command tutorial (EN):** [docs/tutorial.md](docs/tutorial.md)
- **命令教程（中文）:** [docs/zh/tutorial.md](docs/zh/tutorial.md)
- Agent contract: [AGENTS.md](AGENTS.md)
- Run SOP / manual / architecture (Chinese): [docs/zh/](docs/zh/)

## Honest boundaries

- The nft cage is the **only hard network boundary**; method/path rules are command-level or
  post-hoc (Caido in this version cannot drop a request).
- `--caido-tamper` rewrites denied methods to GET (a downgrade, not a drop).
- No authoritative DNS OOB; HTTP callbacks only.
- Out-of-scope hosts dropped by the cage are recorded as `blocked_attempt`, not killed.

## Data hygiene

No real-target findings are published here; `evidence/` contains local-lab proofs only. Run
directories, gateway logs, cookies and keys are gitignored. If you publish your own results,
redact hostnames, tokens and unpatched details until the owner has fixed them.

## License

MIT. See `LICENSE` and `NOTICE`. Strix is a separate project with its own license.
