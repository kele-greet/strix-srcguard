# SRCGuard 使用手册

> 目的：让 **Strix 在合规边界内挖 SRC**。
> SRCGuard 自己不做渗透，只做三件事：**生成约束 → 拉起 Strix → 事后审计**。
> 对 `strix-main` 零改动，Strix 升级不受影响。

---

## 0. 一页看懂

```
你写 scope.yaml（范围/方法/速率/预算）
        │
        ▼
srcguard run  ──（不加 --launch）──► 只生成：instruction.md + mcp-servers.json + strix argv
        │                                          │
        │（加 --launch）                            └─ 想自己跑 Strix：把 argv 原样交给 strix（无笼子，不建议）
        ▼
装 nft 笼子 + 起 Caido observer + 拉起 strix + monitor
        │
        ▼
srcguard audit ──► compliance.md（contacted / out_of_scope / writes / 证据核对）
```

**记住三个开关**：

| 开关 | 作用 |
|---|---|
| 不加 `--launch` / 加 `--dry-run` | 只生成命令，**不发任何请求** |
| 加 `--launch` | 真正拉起 Strix 扫描 |
| 网关的 `--max-cost/--max-tokens` | 真正的钱/量上限（到顶返回 429，Strix 自动停） |

---

## 1. 前置条件

| 依赖 | 要求 |
|---|---|
| 系统 | Linux（非 Linux 会 fail-closed 拒绝启动） |
| Docker | 可用；nft/dmesg 需要 `--privileged` helper 容器 |
| Strix | 二进制路径，如 `/home/kele-1/strix2/strix-1.7.0-linux-x86_64` |
| Python | 3.10+，项目根目录用 `PYTHONPATH=.` |
| LLM Key | 只放环境变量或 `0600` 文件，**不进代码/日志**（本机在 `~/.hermes/.env`） |

自检：

```bash
cd /home/kele-1/strix2/srcguard
UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q     # 144 passed
./check_strix.sh                                # strix-main: zero changes verified
```

---

## 2. 五分钟快速开始

### 2.1 写 scope

```yaml
# /tmp/my-src.yaml
program: my-src
in_scope:
  - "www.example.edu.cn"          # 只写授权 host，不要写 *.edu.cn
methods:
  deny: [DELETE, PUT, PATCH]      # 改/删/覆盖：永远禁
  allow: [GET, HEAD, POST]        # POST 默认开放（见 4.3）
  post_mode: open
  max_body_bytes: 65536
rate:
  default_rps: 1                  # 公共站点建议 1 rps
  burst_rps: 15
limits:
  max_blocked: 15                 # 60s 内多少次 403/429 才停
oob:
  mode: http                      # 开 HTTP 回调
  public: true                    # 同时起 Cloudflare 隧道
web_search:
  enabled: false
budgets:
  max_turns: 15                   # 不传 CLI 时用这个
  max_budget_usd: 1
```

校验：

```bash
PYTHONPATH=. python3 -m srcguard.cli check --scope /tmp/my-src.yaml
```

### 2.2 起网关（带硬预算）

```bash
cd /home/kele-1/strix2/srcguard
set -a; . /home/kele-1/.hermes/.env; set +a
export STRIX_LLM=openai/deepseek-flash LLM_API_KEY=gateway-local
export SRCGUARD_STATE_DIR=/tmp/srcguard-state

PYTHONPATH=. python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Authorized scope: only the host in scope.yaml. GET/HEAD + POST open, no DELETE/PUT/PATCH. 1 rps. OOB token only." \
  --model deepseek-flash --listen-host 127.0.0.1 --listen-port 8797 \
  --audit /tmp/run-gateway.jsonl \
  --price-input 0.28 --price-cached 0.07 --price-output 1.10 \
  --max-cost 1 --max-tokens 8000000
```

> 价格按你实际套餐改；不填价格就只用 `--max-tokens` 兜底。
> 到上限后网关对所有 LLM 调用返回 `429 srcguard budget: ...`，Strix 会自行停止。

### 2.3 只生成命令（不花钱）

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --scope /tmp/my-src.yaml --target https://www.example.edu.cn/ \
  --out-dir srcguard_runs --dry-run
```

输出里三样东西就是“给 Strix 的命令”：

```
run_dir:     srcguard_runs/<run_id>
instruction: srcguard_runs/<run_id>/instruction.md
argv:        ['-n','-t','https://www.example.edu.cn/','--scan-mode','quick',
              '--max-turns','15','--max-budget','1.00',
              '--instruction-file','.../instruction.md',
              '--mcp-config','.../mcp-servers.json']
```

### 2.4 让项目拉起 Strix 跑

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --scope /tmp/my-src.yaml --target https://www.example.edu.cn/ \
  --scan-mode quick --max-turns 15 --max-budget 1 \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin /home/kele-1/strix2/strix-1.7.0-linux-x86_64 \
  --max-commands 60 --max-concurrent-runs 1 \
  --out-dir srcguard_runs --launch
```

### 2.5 审计

```bash
PYTHONPATH=. python3 -m srcguard.cli audit \
  --run srcguard_runs/<run_id> --scope /tmp/my-src.yaml
cat srcguard_runs/<run_id>/compliance.md
```

---

## 3. 三种使用模式

| 模式 | 命令 | 花钱吗 | 适用 |
|---|---|---|---|
| **只生成** | `run ... --dry-run`（或省略 `--launch`） | 否 | 想把命令交给别人跑、或先审 scope |
| **项目代拉** | `run ... --launch` | 是 | 推荐；自动装笼子、起 observer、跑完清理 |
| **自己跑** | 复制打印的 `argv` 直接执行 `strix` | 是 | 调试用；**没有 cage**，真实目标不建议 |

---

## 4. scope 字段参考

### 4.1 范围

| 字段 | 说明 |
|---|---|
| `program` | 项目名（必填） |
| `in_scope` | 授权 host / IP / CIDR；支持 `*.example.com`（仅子域） |
| `out_of_scope` | 显式排除，优先级高于 in_scope |
| `allow_spec_hosts` | 是否把 OpenAPI/Postman 里的 host 并入范围（默认 false） |

### 4.2 方法

| 字段 | 说明 |
|---|---|
| `methods.deny` | 默认 `[DELETE]`；建议 `[DELETE, PUT, PATCH]` |
| `methods.allow` | 默认 `[GET, HEAD, POST, PUT, PATCH]` |
| `methods.post_mode` | `open`（默认，只拦破坏性路径）/ `allowlist`（只放指定路径） |
| `methods.post_allow_paths` | allowlist 模式下的前缀白名单 |
| `methods.post_deny_paths` | POST 禁止前缀（优先级最高） |
| `methods.post_deny_keywords` | 路径中出现即拒绝，默认 `delete/remove/destroy/drop/refund/pay/send/sms/reset/shutdown/restart` |
| `methods.max_body_bytes` | 单请求 body 上限 |

### 4.3 POST 的两种模式

```yaml
# 推荐：默认开放，只挡破坏性动作
methods:
  post_mode: open
  post_deny_paths: ["/api/manage/"]
  post_deny_keywords: [delete, pay, send, sms]

# 极窄：只允许搜索接口
methods:
  post_mode: allowlist
  post_allow_paths: ["/api/search/", "/_dwr/call/"]
```

判定顺序：**deny 路径 → deny 关键词 → allowlist 前缀**；命中前两者 kill，allowlist 模式外 kill。
命令层（MCP）看 `curl -X POST/--data/-F/--post-data` 的 URL；代理层（Caido）看真实 method+path。

### 4.4 速率与 403

```yaml
rate: {default_rps: 1, burst_rps: 15}
limits:
  max_blocked: 12             # 全局兜底：60 秒窗口内 403/429 总数到该值才停
  blocked_same_path: 8        # 同一路径 300 秒内被拒 8 次 → 判死路
  blocked_paths_window_s: 300 # 按路径统计的窗口
```

403 的三种归宿（v2 规则）：

| 情况 | 处置 |
|---|---|
| 不同路径分散的 403（多为"方法不对/要会话"） | 记 `slow_down`，**不停**，让 Strix 换姿势 |
| 同一路径持续 403 | `repeated_403:<host>:<path>`，停 |
| 首页 `/` 或 `/index.*` 返回 403/429 | `waf_banned:<host>`，立即停（真被封的金标准） |

WAF 重的站点（探测 `.git`、`.env` 必 403）：`max_blocked` 调到 20–40，速率降到 1 rps。

### 4.5 OOB（盲打回调）

```yaml
oob:
  mode: http        # off / http / self_hosted / local / dns
  public: true      # Cloudflare quick tunnel，目标可公网访问
  domain: ""        # 可选 DNS 后缀
```

回调只带 token，不带目标数据；命中记录在 `audit/oob.jsonl`，`--kill-on-oob` 可在首次命中时停。

### 4.6 预算

```yaml
budgets: {max_turns: 15, max_budget_usd: 1}
```

- 不传 CLI 的 `--max-turns/--max-budget` 时用这里；
- **真正的钱上限在网关**（`--max-cost/--max-tokens`），scope 里的 `max_budget_usd` 只是 Strix 侧参数。

---

## 5. 预算与成本控制

**两层预算，各司其职：**

| 层 | 手段 | 行为 |
|---|---|---|
| Strix（主） | `--max-budget` + `--budget-model` | 在预算处**干净停车**（status=stopped），可以 `--resume` 加预算继续 |
| 网关（安全网） | `--max-cost` / `--max-tokens` | 到顶返回 429；Strix 会当成限流并**收尾**，之后 resume 叫不醒 |

推荐：`--budget-model openai/gpt-4o-mini`（Strix 能计价）+ 网关 `--model deepseek-flash`（真实模型），
网关上限设成 Strix 预算的 **1.5–2 倍**，只当保险。

> 为什么需要 `--budget-model`：LiteLLM 没有 `deepseek-flash` 的价格，Strix 会把 cost 算成 0，
> `--max-budget` 永远不触发。用一个已定价的别名给 Strix 记账，网关再把上游模型改成真实模型。

| 其他手段 | 位置 | 说明 |
|---|---|---|
| `--max-turns` | run/strix | 每 agent 的轮数上限 |
| `--max-commands` | run | MCP shell 命令配额 |
| `rate` + `max_blocked` | scope | 控制对目标的压力 |

实测参考（deepseek-flash，价格 0.28/0.07/1.10）：

| 配置 | token | 花费 |
|---|---|---|
| 15 turns / quick | 5–8M | $0.5–0.8 |
| 25 turns / quick | 10–15M | $0.9–1.5 |
| 40 turns / quick | 15–25M | $1.5–2.5 |

> `usage.json` 里的 `cost` 是 Strix 自己算的（常偏低/为 0）；以**网关 audit** 的 `event: usage` 为准。

---

## 6. 认证态（cookie）

自己注册/登录后，把 Cookie 头值存成 `0600` 单行文件：

```bash
install -m 600 /dev/null /tmp/target-cookie
printf 'SESSION=...; uid=...' > /tmp/target-cookie
```

跑的时候加：

```bash
--session-cookie-file /tmp/target-cookie
```

行为：

- 校验 0600 / 单行 / ≤8KB；
- 复制进沙箱 `/tmp/.srcguard-cookie`（0600），instruction 只写**路径和用法**；
- `mcp.log`、`method.jsonl` 里 `Cookie/Authorization/-b` 自动打码；
- **不会**写进 run 目录或报告。

---

## 7. 产物在哪

```
srcguard_runs/<run_id>/
├── policy.json                 # 编译后的策略（含 hash）
├── instruction.md              # 给 Strix 的约束文件
├── mcp-servers.json            # MCP shim 配置
├── usage.json                  # 本次用量（Strix 口径）
├── compliance.md               # 合规报告
├── audit/
│   ├── caido.jsonl             # 请求（method/path/query/状态码）
│   ├── egress.jsonl            # nft allow/drop/dns/rate
│   ├── writes.jsonl            # 所有非 GET 写请求
│   ├── blocked.jsonl           # 被 cage 丢弃的越权尝试
│   ├── rate.jsonl              # 速率/403 事件
│   ├── method.jsonl            # 命令层拦截
│   ├── oob.jsonl               # 带外回调
│   └── mcp.log                 # sandbox_exec 命令
└── strix_runs/<name>/
    ├── penetration_test_report.md     # 完整报告
    ├── vulnerabilities/vuln-XXXX.md   # 单条漏洞详情
    ├── vulnerabilities.json / .csv
    ├── findings.sarif
    └── coverage.json                 # surface / gap
```

> 被 kill 或预算截断的 run **可能没有 `penetration_test_report.md`**，只有 coverage/audit。

---

## 8. 典型场景配方

### 8.1 WAF 重、探测就 403 的站点

```yaml
rate: {default_rps: 1, burst_rps: 10}
limits: {max_blocked: 30}
```

### 8.2 认证后 IDOR / 越权

```bash
--session-cookie-file /tmp/target-cookie
```
scope 里把方法保持 `GET/HEAD/POST`，POST 默认 open。

### 8.3 盲 SSRF / XXE / 盲注

```yaml
oob: {mode: http, public: true}
```
把回调 URL 交给模型（instruction 会自动追加），命中看 `audit/oob.jsonl`。

### 8.4 打不透、想补 gap

看 `coverage.json` 里的 `gaps`，下一轮把 `budgets.max_turns` 提到 40–60，只保留同一 scope，让 Strix 继续。

### 8.5 本地 lab / 自测

```bash
--lab-host 172.17.0.1        # 显式放行本地 lab
```

---

## 8.6 断点续跑（--resume）

被预算/403/超时打断的 run 不用从头再花一轮：

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --resume <run_id> \
  --scope /tmp/my-src.yaml \
  --dry-run            # 先看 argv；确认后换 --launch
```

规则：

- 复用原 `run_dir` 的 `instruction.md`、`mcp-servers.json` 和 `.state/`（Strix 用它恢复 agent 对话、notes、todos、coverage）；
- 传给 Strix 的是 `--resume <strix_run_name>`，**不能再带 `-t`**（Strix 从 run.json 取目标）；
- `--scope` 必须编译出**和原 run 相同的 policy_hash**，否则拒绝（防止借 resume 扩大授权）；
- 笼子、Caido observer、monitor、网关预算都会重新建立，所以续跑仍然是合规的；
- 成本不是免费：恢复的上下文会在下次调用时重发（缓存可省一部分）。

前提：`strix_runs/<name>/.state/agents.json` 和 `agents.db` 还在（被 kill 的 run 一般都在）。

**重要限制（实测）**：resume 只能恢复**被中断、agent 还活着**的 run。
如果上一次 run 已经走到 `finish_scan`（root agent completed），resume 会瞬间收尾，日志里是
`agent.send dropped: ... is completed and cannot be woken`——这时应**开新 run**，
把上一轮的 `coverage.json` gaps 写进 instruction，而不是 resume。

**注意**：如果 supervisor 被强杀（SIGKILL），nft 表可能残留。清理：

```bash
PYTHONPATH=. python3 - <<'EOF'
from srcguard.cage import NftCage
NftCage.for_run("<run_id>").cleanup(ignore_missing=True)
EOF
```

## 9. 合规操作清单（提交前自检）

- [ ] `in_scope` 只含授权 host；没有 `*.edu.cn` 这种大范围
- [ ] 方法：`DELETE/PUT/PATCH` 禁用；POST 只开放必要范围
- [ ] 速率 ≤ 1–2 rps；`max_blocked` 合理，触发就降速
- [ ] 不绕 WAF；403/429 连续就停
- [ ] 不删除/修改真实数据；写操作只用自己账号/自己对象
- [ ] OOB 只带 token，不带目标数据
- [ ] cookie 只在 0600 文件里，测完作废
- [ ] 每个 run 保留：`compliance.md` + 报告 + 授权截图
- [ ] 发现 PII 立刻停、打码、写进报告

---

## 10. 故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| `repeated_403` kill | WAF 拦探测（`.git`/`.env` 等） | 降 1 rps；`limits.max_blocked` 提到 20–40 |
| `rate_exceeded` kill | 浏览器突发或持续超速 | 看 `rate.jsonl`；降 `default_rps`/提 `burst_rps` |
| 网关 429 `srcguard budget` | 到 `--max-cost/--max-tokens` | 提上限或分轮跑 |
| `response: null` 很多 | 目标慢/断、WAF 静默丢 | 换时间；确认不是 DNS（看 egress `-dns`） |
| 没有报告 | 被 kill/预算截断 | 看 coverage；提预算/降速重跑 |
| `compliance FAIL` | 证据 ID 对不上 | 看 `evidence_issues`；重跑或用 audit 复核 |
| `ExecTransportError`（docker proxy） | proxy exec hijack 已知限制 | 真实 run 不加 `--docker-proxy` |
| DNS 解析失败 | 解析器不在 allow 集 | 确认启动日志有 `system DNS allowed on port 53` |

---

## 11. 命令速查

```bash
# 校验 scope
PYTHONPATH=. python3 -m srcguard.cli check --scope s.yaml

# 只生成命令（不花钱）
PYTHONPATH=. python3 -m srcguard.cli run --scope s.yaml --target https://h/ --dry-run --out-dir srcguard_runs

# 真跑
PYTHONPATH=. python3 -m srcguard.cli run --scope s.yaml --target https://h/ \
  --scan-mode quick --max-turns 15 --max-budget 1 \
  --gateway-base http://127.0.0.1:8797/v1 --launch \
  --strix-bin /path/to/strix --max-commands 60 --max-concurrent-runs 1 \
  --out-dir srcguard_runs

# 认证态
... --session-cookie-file /tmp/target-cookie

# 审计
PYTHONPATH=. python3 -m srcguard.cli audit --run srcguard_runs/<id> --scope s.yaml

# 用量汇总
PYTHONPATH=. python3 -m srcguard.cli usage --root srcguard_runs
```

---

## 12. 一句话原则

**scope 决定“能碰哪”，网关决定“花多少”，caido/nft 决定“留什么证据”。**
三者都在，才叫“合规地让 Strix 挖 SRC”。
