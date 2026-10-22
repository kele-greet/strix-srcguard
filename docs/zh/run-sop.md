# SRCGuard 运行 SOP（跑一个完整项目）

> 目标：在合规边界内，用 Strix 把一个授权目标从 0 跑到报告。
> 核心：**Strix 管预算停车（可续跑），网关管安全网，nft/Caido 管证据。**

---

## 0. 一次性准备

```bash
cd /home/kele-1/strix2/srcguard
UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q     # 149 passed
./check_strix.sh                                # strix-main: zero changes

set -a; . /home/kele-1/.hermes/.env; set +a     # LLM key，只在环境里
export STRIX_LLM=openai/deepseek-flash          # 真实模型（网关会改写）
export LLM_API_KEY=gateway-local
export SRCGUARD_STATE_DIR=/tmp/srcguard-state
```

依赖：Linux、Docker、Strix 二进制（如 `/home/kele-1/strix2/strix-1.7.0-linux-x86_64`）。

---

## 1. 写 scope

```yaml
# /tmp/proj-scope.yaml
program: my-src
in_scope:
  - "www.example.edu.cn"        # 只写授权 host
methods:
  deny: [DELETE, PUT, PATCH]
  allow: [GET, HEAD, POST]
  post_mode: open
  max_body_bytes: 65536
rate:
  default_rps: 1
  burst_rps: 15
limits:
  max_blocked: 15
oob:
  mode: http
  public: true
web_search:
  enabled: false
budgets:
  max_turns: 20
  max_budget_usd: 2
```

## 2. 校验

```bash
PYTHONPATH=. python3 -m srcguard.cli check --scope /tmp/proj-scope.yaml
```

## 3. 起网关（安全网）

```bash
PYTHONPATH=. python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Authorized scope: only the host in scope. GET/HEAD + POST open, no DELETE/PUT/PATCH. 1 rps. OOB token only." \
  --model deepseek-flash \
  --listen-host 127.0.0.1 --listen-port 8797 \
  --audit /tmp/proj-gateway.jsonl \
  --price-input 0.28 --price-cached 0.07 --price-output 1.10 \
  --max-cost 3 --max-tokens 20000000
```

- `--max-cost` = Strix 主预算的 **1.5–2 倍**，只当保险；
- 不要拿网关 429 当预算开关（会让 Strix 收尾，之后 resume 叫不醒）。

## 4. （可选）先看命令

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --dry-run
```

确认打印的 `argv` 和 `instruction` 路径。

## 5. 跑第一轮

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --scan-mode quick --max-turns 20 --max-budget 2 \
  --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin /home/kele-1/strix2/strix-1.7.0-linux-x86_64 \
  --max-commands 60 --max-concurrent-runs 1 \
  --out-dir srcguard_runs/example --launch
```

关键参数：

| 参数 | 作用 |
|---|---|
| `--max-budget 2` | Strix 主预算：到这**干净停车**（status=stopped） |
| `--budget-model openai/gpt-4o-mini` | 让 Strix 能计价（deepseek-flash 在 LiteLLM 无价）；网关仍发真实模型 |
| `--launch` | 装 cage、起 Caido observer、拉起 Strix |

## 6. 判断怎么停的

```bash
D=srcguard_runs/example/<run_id>
cat $D/audit/kill.json 2>/dev/null        # 有：被 guard 杀（越权/限速/403）
tail -5 $D/strix_runs/*/strix.log         # "budget ... exceeded" / "finish_scan" / "completed"
jq .status $D/strix_runs/*/run.json       # stopped = 可续；completed = 已收尾
```

| 状态 | 含义 | 下一步 |
|---|---|---|
| `stopped` + `budget exceeded` | 预算停车 | 第 7 步加预算续跑 |
| `completed` + `finish_scan` | 正常结束 | 第 8 步审计 |
| `kill.json` 存在 | guard 介入 | 看 reason；403 就降速/提 `max_blocked`，越权就查 scope |

## 7. 加预算续跑（同一 run）

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --resume <run_id> --scope /tmp/proj-scope.yaml \
  --max-turns 20 --max-budget 4 \
  --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --launch \
  --strix-bin /home/kele-1/strix2/strix-1.7.0-linux-x86_64 \
  --out-dir srcguard_runs/example
```

- 复用 run 目录/instruction/mcp/`.state`；
- scope 必须 hash 一致；
- 预算可以反复加，直到 `completed`。

## 8. 审计与报告

```bash
PYTHONPATH=. python3 -m srcguard.cli audit \
  --run srcguard_runs/example/<run_id> --scope /tmp/proj-scope.yaml
cat srcguard_runs/example/<run_id>/compliance.md
```

产物位置：

```
<run>/strix_runs/<name>/penetration_test_report.md      # 完整报告
<run>/strix_runs/<name>/vulnerabilities/vuln-*.md       # 单条漏洞
<run>/strix_runs/<name>/coverage.json                   # surface / gap
<run>/compliance.md                                     # 合规报告
<run>/audit/{caido,egress,writes,blocked,oob,rate,method}.jsonl
<run>/usage.json                                        # 用量（Strix 口径，以网关为准）
```

## 9. 归档

```bash
# evidence/real-target/<host>.md：记录 run_id、请求/响应、surface/gap、成本、结论
git add -A evidence/ SRCGuard-使用手册.md
git commit -m "test: record <host> run ..."
# 同步 D 盘（如果保留副本）
cp evidence/real-target/<host>.md /mnt/d/srcguard-acceptance/real-target/
```

## 10. 合规自检（提交前）

- [ ] 只碰授权 host；子域/旁站只是线索
- [ ] DELETE/PUT/PATCH 没发出；POST 只在允许范围
- [ ] 速率 ≤ 1–2 rps；403 连续就降速
- [ ] 不绕 WAF；不用真实账号；OOB 只带 token
- [ ] cookie 只存在 0600 文件，测完作废
- [ ] 有 `compliance.md` + 报告 + 授权截图

---

## 一页速查

```bash
check → gateway → dry-run → run --launch → (budget stop) → run --resume --max-budget ↑ → audit
```

三句话：

1. **scope 决定能碰哪**；
2. **Strix 的 `--max-budget` 决定什么时候停，`--budget-model` 让它算得出来**；
3. **网关 cap 是保险，nft/Caido 是证据。**
