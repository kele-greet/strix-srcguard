# SRCGuard 使用指南（个人 SRC / 本地 lab）

> 只用于**已授权**的 SRC/渗透测试。scope 是范围声明，不是授权本身。

## 0. 先看懂它现在是什么

SRCGuard 是 Strix 1.7.0 的**外部**护栏，不修改 Strix 源码：

```text
scope.yaml
  -> preflight（目标校验/策略哈希/instruction/MCP env）
  -> nftables cage（allowlist + 内网/metadata 黑洞 + 限速/配额 + 日志）
  -> Strix（Docker sandbox + Caido）
  -> audit（egress/Caido/MCP/OOB/DNS/方法日志 -> compliance.md）
```

关键口径：

- **硬边界在 nft**；instruction/网关注入只是软约束。
- `contacted` **包含尝试**，不是“成功连接”。
- P2-2 是 **DELETE→GET 降级**，不是 drop。
- OOB 当前是 **HTTP-only**（用户已接受）；**DNS 权威 OOB 不支持**。
- blind 85/75/85 是**本地 lab** 结果，不外推公网/真实 SRC。

## 1. 环境准备

在 WSL2/Ubuntu 下：

```bash
cd /home/kele-1/strix2/srcguard

# Python 依赖/测试
UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q          # 91 passed

# 检查 strix 源码零改动（工作区有 strix-main 时）
./check_strix.sh

# P2 DNS guard 的静态 helper（可选，--dns-guard 才需要）
./scripts/build_dnsguard.sh
```

需要：

- Docker 可用
- 宿主 `nft`（通过特权 Debian helper 调用）
- Strix 1.7.0：`/home/kele-1/strix2/strix-1.7.0-linux-x86_64`
- DeepSeek key：只放环境变量

```bash
export DEEPSEEK_API_KEY=...
export STRIX_LLM=openai/deepseek-flash
```

## 2. 第一次跑：本地 lab（推荐先做）

### 2.1 起一个目标

```bash
# 任选一个本地 HTTP 服务；Juice Shop 也行
docker run -d --rm --name juice -p 3000:3000 bkimminich/juice-shop
```

### 2.2 编译 scope

```bash
cd /home/kele-1/strix2/srcguard

PYTHONPATH=. python3 -m srcguard.cli check \
  --scope samples/lab-scope.yaml \
  --policy-out /tmp/lab-policy.json
```

### 2.3 先 dry-run

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --scope samples/lab-scope.yaml \
  --target http://172.17.0.1:3000/ \
  --lab-host 172.17.0.1 \
  --oob-host 172.17.0.1 \
  --dry-run
```

看输出里的：

- `run_dir`
- `argv` 是否含 `--mcp-config`
- `instruction` 文件
- env 是否清空搜索 key

### 2.4 起网关（另一个终端）

```bash
cd /home/kele-1/strix2/srcguard
export DEEPSEEK_API_KEY=...

PYTHONPATH=. python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Only test the supplied scope. Read-only first. Do not use DELETE, other hosts, or credentials." \
  --price-input 0.27 --price-cached 0.07 --price-output 1.10 \   # USD / 1M tokens，用于预算计量
  --max-cost 3 \                                                 # 累计成本到上限后网关返回 429
  --model deepseek-flash \
  --listen-host 127.0.0.1 --listen-port 8787 \
  --audit /tmp/srcguard-gateway.jsonl
```

网关只对 `openai/` + `chat_completions` 生效；`chatgpt/` 订阅模式绕过网关。

### 2.5 真跑

```bash
cd /home/kele-1/strix2/srcguard

export DEEPSEEK_API_KEY=...
export STRIX_LLM=openai/deepseek-flash
export LLM_API_KEY=gateway-local

PYTHONPATH=. python3 -m srcguard.cli run \
  --scope samples/lab-scope.yaml \
  --target http://172.17.0.1:3000/ \
  --lab-host 172.17.0.1 \
  --oob-host 172.17.0.1 \
  --gateway-base http://127.0.0.1:8787/v1 \
  --launch \
  --strix-bin /home/kele-1/strix2/strix-1.7.0-linux-x86_64 \
  --max-commands 80 \
  --max-concurrent-runs 1
```

没有网关时，也可以直连（但就没有 L2 注入/审计）：

```bash
export STRIX_LLM=openai/deepseek-flash
export LLM_API_KEY=$DEEPSEEK_API_KEY
export LLM_API_BASE=https://api.deepseek.com/v1
# 然后 run 时不传 --gateway-base
```

## 3. 审计一次 run

```bash
cd /home/kele-1/strix2/srcguard
PYTHONPATH=. python3 -m srcguard.cli audit \
  --run srcguard_runs/<run_id> \
  --scope samples/lab-scope.yaml
```

看：

- `status`：pass/fail
- `contacted` / `out_of_scope`
- `evidence_issues`：报告里的 ID 是否能核
- `dns_blocked` / `dns_oob`
- `method_blocked`
- `usage`
- 生成的 `compliance.md`

`audit` 以日志为准，不采信模型叙述。`contacted` 包含尝试；范围外尝试也会 fail。

## 4. 产物怎么读

每次 run 在 `srcguard_runs/<run_id>/`：

| 文件 | 含义 |
|---|---|
| `policy.json` / `run.json` | 策略哈希、目标、run 元数据 |
| `instruction.md` | 实际注入的 root 指令 |
| `mcp-servers.json` | MCP `sandbox_exec` 配置 |
| `audit/egress.jsonl` | nft allow/block/drop/rate + MCP 直接目标 |
| `audit/caido.jsonl` | Caido 请求（id/host/method/status） |
| `audit/oob.jsonl` | HTTP/DNS OOB 回调 |
| `audit/method.jsonl` | MCP 方法/命令配额事件 |
| `audit/docker.jsonl` | Docker create 变异/拒绝 |
| `audit/dns.jsonl` | DNS guard 查询 |
| `audit/llm.jsonl` | 网关请求/tool_call |
| `compliance.md` | 人看的审计结论 |
| `usage.json` | 每 run 命令/egress/token/cost 账本 |

多 run 汇总：

```bash
PYTHONPATH=. python3 -m srcguard.cli usage --root srcguard_runs
```

## 5. 真实授权目标怎么跑

把 scope 改成真实授权 host，**不要**用 `--lab-host`（那是本地例外）：

```yaml
program: my-src
in_scope:
  - api.example.com
methods:
  deny: [DELETE, PUT, PATCH]      # 改/删/覆盖：永远不给
  allow: [GET, HEAD, POST]        # POST 可以开，但只限下面列出的路径
  post_mode: open                 # open=默认允许 POST，只拦破坏性路径（推荐）
  post_deny_paths:                # 破坏性/管理接口前缀
    - "/api/manage/"
  post_deny_keywords:             # 默认：delete/remove/destroy/drop/refund/pay/send/sms/reset/...
    - "delete"
  # post_mode: allowlist + post_allow_paths: [...]  # 需要极窄范围时才用
  max_body_bytes: 65536
rate:
  default_rps: 2                  # 持续速率；模型真实跑通常在 1–2 rps
  burst_rps: 30                   # 页面并发加载的突发额度
oob:
  mode: http          # off / http / self_hosted / local；http 即开 HTTP 回调
  public: true        # true = 同时起 Cloudflare quick tunnel（目标可达的公网 URL）
web_search:
  enabled: false
budgets:
  max_turns: 60
  max_budget_usd: 5
```

写操作口径（instruction 会自动带上）：

- **读/登记/上传允许**：登记与上传必须带唯一标记 `SRCGUARD-<run_id>`，只写纯文本或 tiny 图片，单次、小体积；
- **修改/删除/消耗禁止**：用读侧证据写“推测可改/可删，未验证”；
- **登录**：只允许自己注册的测试账号；
- POST 默认开放（`post_mode: open`）：只有命中 `post_deny_paths` 或破坏性关键词（delete/remove/destroy/drop/refund/pay/send/sms/reset/...）才 kill；
- 所有非 GET 请求写进 `audit/writes.jsonl`，audit 单列 "Write requests" 供事后复核；
- `post_mode: allowlist` + `post_allow_paths` 是极窄模式，只在需要时用。

推荐命令：

```bash
PYTHONPATH=. python3 -m srcguard.cli run \
  --scope scope.yaml \
  --target https://api.example.com \
  --oob-host 127.0.0.1 \
  --public-oob \
  --caido-tamper \
  --docker-proxy \
  --max-commands 80 \
  --max-concurrent-runs 1 \
  --launch \
  --strix-bin /home/kele-1/strix2/strix-1.7.0-linux-x86_64
```

参数解释：

- `--public-oob`：Cloudflare quick tunnel 暴露 HTTP OOB（trycloudflare 临时域名）
- `--caido-tamper`：DELETE→GET 降级（不是 drop）
- `--docker-proxy`：去 NET_ADMIN/只读挂载/强制 DNS
- `--max-commands`：MCP 命令上限
- `--max-concurrent-runs`：本机并发 run 租约
- `--kill-on-oob`：需要“OOB 命中即停”时加；默认不杀

`--dns-guard` 只在需要强制容器 DNS 到本地 guard 时加；公网权威 DNS OOB 当前**不支持**。

## 6. 常用 P2 开关

| 开关 | 作用 | 注意 |
|---|---|---|
| `--docker-proxy` | Docker API 变异代理 | 创建走代理；MCP exec 走真实 daemon |
| `--dns-guard` | 强制容器 DNS 到 `172.17.0.1:53` | 需 `build_dnsguard.sh`；仅默认 bridge |
| `--caido-tamper` | DELETE→GET 降级 | 不是 drop；HTTPS E2E 已验证 |
| `--public-oob` | 公网 HTTP OOB | 需要 cloudflared 镜像 |
| `--kill-on-oob` | 首个 OOB 回调即停 | 默认关闭 |
| `--max-commands N` | MCP 命令配额 | 超限写 `method.jsonl` |
| `--max-concurrent-runs N` | 本机并发租约 | 本地文件锁，不是分布式 |
| `--lab-host H` | cage 的 lab 例外 | 只给 lab，不要给真实目标 |

## 7. 常见问题

### `ModuleNotFoundError: srcguard`
从 `srcguard/` 目录运行，并加 `PYTHONPATH=.`；或用 `uv run python -m srcguard.cli ...`。

### 模型不执行工具 / `exec_command` 没反应
Strix 1.7.0 的 capability 工具派发有问题；SRCGuard 默认走 MCP `call_mcp sandbox_exec`。不要用 `--no-mcp` 除非你在调试。

### 本地 lab 目标被 drop
cage 先 block RFC1918，再 allow；本地目标必须加 `--lab-host 172.17.0.1`。

### `nft` 失败
需要 Docker 特权 helper；没有宿主 root 时这是预期路径。检查 Docker 可用。

### `public-oob` 没有 URL
需要能拉 `cloudflare/cloudflared:latest`，并允许外网；失败时回退本地 OOB。

### evidence ID 不可核
先看 `audit/caido.jsonl` 是否有请求。没有 Caido 请求时，报告 ID 会被 audit 判 unknown；修复/重跑 observer（当前已用 `statusCode`）。

### DNS 盲打
当前 **HTTP-only**；不要指望 `--dns-guard` 提供公网权威 DNS。纯 DNS 外带需要你自己的 VPS + NS 委派。

### 跨 run 租约残留
`~/.srcguard/runs.json` 里是 PID 租约，死 PID 会自动清理；异常退出可检查该文件。

## 8. 交付验证

```bash
cd /home/kele-1/strix2/srcguard
UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q
./scripts/ci.sh
./check_strix.sh
```

当前：**91 tests passed**，CI OK，`strix-main` 零改动。

## 9. 明确不承诺

- 不承诺“通用自主漏洞发现率”：blind 85/75/85 只在本地 lab。
- 不承诺 DELETE 真 drop：只做降级。
- 不承诺 DNS 权威 OOB：HTTP-only。
- 不承诺租户计费：只有 usage 账本/并发租约。
- 不承诺网关能硬拦 tool_call：硬边界在 nft。
