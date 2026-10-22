# SRCGuard 命令教程（从零到报告）

配合 README 使用。所有命令都在仓库根目录执行。下文的 `SRCGuard` 指：

```bash
cd /path/to/srcguard
export PYTHONPATH=.
```

---

## 0. 检查环境

```bash
uv run pytest -q        # 153 tests
./check_strix.sh        # 本地有 strix-main 时校验零改动
```

要求：Linux + Docker、Python 3.10+（`pyyaml`、`httpx`、`pytest`）、Strix 1.7.0 二进制。

---

## 1. 放好 Strix

```bash
mkdir -p ~/tools
mv strix-1.7.0-linux-x86_64 ~/tools/strix-1.7.0
chmod +x ~/tools/strix-1.7.0
```

每次运行传 `--strix-bin ~/tools/strix-1.7.0`，或：

```bash
export STRIX_BIN=~/tools/strix-1.7.0
```

不要把二进制提交进仓库。

---

## 2. 写 scope

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

校验：

```bash
python3 -m srcguard.cli check --scope /tmp/proj-scope.yaml
```

---

## 3. 起 LLM 网关

单独开一个终端/后台任务，保持运行：

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

`--max-cost` 是安全网（主预算的 1.5–2 倍），不是主开关。

---

## 4. 先预览 Strix 命令（不发流量、不花钱）

```bash
python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --dry-run
```

会打印 `run_dir`、`instruction` 和真正传给 Strix 的 `argv`。

---

## 5. 运行

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

## 6. 预算停车后加钱续跑

```bash
python3 -m srcguard.cli run \
  --resume <run_id> --scope /tmp/proj-scope.yaml \
  --max-turns 20 --max-budget 4 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin ~/tools/strix-1.7.0 --out-dir srcguard_runs/example
```

resume 复用 run 目录、instruction、MCP 配置和 `.state/`；scope 必须 hash 一致。反复加预算直到
`completed`。

---

## 7. 审计

```bash
python3 -m srcguard.cli audit \
  --run srcguard_runs/example/<run_id> --scope /tmp/proj-scope.yaml

cat srcguard_runs/example/<run_id>/compliance.md
```

产物：

```
policy.json  instruction.md  mcp-servers.json  usage.json  compliance.md
audit/{caido,egress,writes,blocked,oob,rate,method}.jsonl   audit/mcp.log
strix_runs/<name>/{penetration_test_report.md, vulnerabilities/, coverage.json}
```

成本看网关 audit 里的 `event: usage`，不是 `usage.json`。

---

## 8. 认证态（cookie）

操作者自己登录，把 Cookie 头导出到 `0600` 文件：

```bash
install -m 600 /dev/null /tmp/target-cookie
printf 'SESSION=...; uid=...' > /tmp/target-cookie
```

运行时加 `--session-cookie-file /tmp/target-cookie`。值会被复制到沙箱
`/tmp/.srcguard-cookie`（0600），不会写进 run 目录。

让 Agent **不要打印值**，用文件读 header：

```bash
printf 'Cookie: %s' "$(cat /tmp/.srcguard-cookie)" > /tmp/.srcguard-headers
chmod 600 /tmp/.srcguard-headers
curl -s -H @/tmp/.srcguard-headers https://www.example.edu.cn/protected
```

不要 `cat` cookie、不要 `curl -v`。测完作废会话。

---

## 9. 盲打回调（OOB）

scope 里写 `oob: {mode: http, public: true}`，SRCGuard 会起本地回调 + Cloudflare 隧道，把公网
URL 和 token 追加进 instruction。命中记录在 `audit/oob.jsonl`；`--kill-on-oob` 可首次命中即停。
只支持 HTTP。

---

## 10. 交给 AI Agent

把仓库给它，加这段提示：

```text
你现在操作 SRCGuard。先读 AGENTS.md 和 docs/zh/tutorial.md。

先向我确认：
  1) 目标的书面授权；
  2) 精确的 in-scope host；
  3) 允许的方法与速率；
  4) 美元预算。

然后按教程执行：check → gateway → dry-run → launch → audit。
绝不扩大范围，不发 DELETE/PUT/PATCH，不用真实账号。
预算停车后用更高的 --max-budget 续跑。
报告：测了什么、拦了什么、还剩哪些 gap、网关计量成本。
绝不说目标“安全”。
```

Agent 应该先跑 `--dry-run`，把 argv 给你看过再 launch。

---

## 11. 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| `repeated_403` kill | WAF 拦探测 | 降到 1 rps；`limits.max_blocked` 提到 20–40 |
| `rate_exceeded` kill | 突发/持续超速 | 降 `default_rps`、提 `burst_rps` |
| 网关 429 `srcguard budget` | 安全网触发 | 提 `--max-cost`，或改用 Strix 预算 + resume |
| 大量 `response: null` | 目标慢 / WAF 静默丢包 | 换时间，1 rps 重试 |
| 没有报告 | 被 kill 或预算停车 | 看 `coverage.json`；resume 或重跑 |
| `compliance FAIL` | 证据 id 对不上 | 看 `evidence_issues`，重跑该发现 |
| DNS 解析失败 | 解析器不在 allow 集 | 启动日志应有 `system DNS allowed on port 53` |
| SIGKILL 后 nft 表残留 | supervisor 没来得及清理 | `NftCage.for_run("<run_id>").cleanup(ignore_missing=True)` |

---

## 12. 提交前自检

- [ ] scope 只有授权 host
- [ ] 没有 DELETE/PUT/PATCH；POST 只在允许范围
- [ ] 速率 ≤ 1–2 rps；WAF 推回就停
- [ ] 不绕 WAF、不用真实账号、OOB 只带 token
- [ ] cookie 文件 0600，测完删除
- [ ] `compliance.md` + 报告 + 授权证明放在一起
