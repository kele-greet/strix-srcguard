# SRCGuard

**一层可以交给 AI Agent 直接运行的、合规优先的 SRC / 漏洞赏金护栏。**

SRCGuard 在外部包裹 [Strix](https://github.com/usestrix/strix) 1.7.0——**不修改 `strix-main` 任何一行代码**——让自主 Agent 在你声明的范围内猎取真实授权目标。范围由内核强制，每一条请求、每一次写操作、每一次被拦截的越界尝试都有记录；预算在干净边界停车，可以加钱续跑。

> **本项目不授予授权。** 它只执行**你**声明的范围。请仅用于你拥有明确、可验证授权的系统。
>
> [English](README.md)

---

## 为什么需要它

把一个自主 Agent 放到真实 SRC 目标上，有三个光靠提示词回答不了的问题：

1. **范围**——它会不会顺手去打新发现的子域、旁站、CDN、第三方 SaaS？
2. **影响面**——会不会 DELETE、批量导出、压测、把凭据带出沙箱？
3. **证据**——报告里写“GET / 返回 200”，你能拿什么向厂商证明？

SRCGuard 在 Agent **外部**回答这三个问题：

| 层 | 机制 | 强度 |
|---|---|---|
| **范围笼子** | 每个 run 一张 nftables 表，只有 scope 解析出的 IP 能出去 | 硬（内核） |
| **元数据防护** | RFC1918 / 链路本地 / 云元数据段直接黑洞 | 硬（内核） |
| **速率与突发** | 每主机、全局新连接限速 | 硬（内核） |
| **命令护栏** | MCP `sandbox_exec` 检查方法、POST 路径、命令配额 | 软（命令层） |
| **LLM 网关** | 每次模型调用注入策略块、凭据脱敏、usage 计量、硬预算上限 | 软 + 记账 |
| **证据链** | Caido observer、egress 日志、写请求日志、拦截日志、OOB 回调、合规报告 | 只读 |

挖洞仍然是 Agent 的事。SRCGuard 不选目标、不选 payload、不筛选发现——它只约束边界，并记录越过了什么。

---

## 交给 AI Agent

这个仓库就是写给 AI Agent 操作的。把仓库放在它面前，粘贴：

```text
你现在操作 SRCGuard——一个包裹 Strix 的外部合规护栏。
先读 AGENTS.md 和 README.zh-CN.md。

动手之前先向我确认四件事：
  1) 目标的书面授权；
  2) 精确的 in-scope host（没有我明确同意不要用通配符）；
  3) 允许的方法与速率；
  4) 美元预算。

然后按 docs/zh/run-sop.md 执行：check → gateway → dry-run → launch → audit。
绝不扩大范围。绝不说目标“安全”——只报告测了什么、拦了什么、还剩哪些 gap。
如果 run 在预算处停下，用更高的 --max-budget 续跑，而不是从头再来。
```

`AGENTS.md` 是给 Agent 的操作契约（范围、停止规则、预算、证据、报告），多数 Agent 运行时会自动读取。

---

## 架构

```
Strix agents
  ├─ 浏览器 / 代理工具 ──► Caido（沙箱内）──┐
  └─ MCP sandbox_exec ──► [命令护栏] ──► exec ─┤
                                                ▼
                                        沙箱容器
                                                │
                                         docker0（宿主）
                                                │
                     ┌──────────────────────────┴───────────────┐
                     │ nft 表 srcguard_<run>                     │
                     │  forward: 限速 → dns → allow4 → block4 → drop
                     │  input:   dns / oob / lab / allow4 / drop │
                     └──────────────────────────┬───────────────┘
                                                │
                                         宿主 NAT → 互联网

LLM：Strix ──► SRCGuard 网关 ──► 模型提供方
                 ├ 策略注入
                 ├ 凭据脱敏
                 ├ usage 计量
                 └ 硬预算上限 → 429
```

---

## 快速开始

### 环境

- Linux + Docker（WSL2 已验证）。
- Strix 1.7.0 二进制（本仓库不捆绑，见下）。
- Python 3.10+，依赖 `pyyaml`、`httpx`、`pytest`（或用 `uv`）。

```bash
uv run pytest -q        # 149 tests
./check_strix.sh        # 本地有 strix-main 时校验零改动
```

### Strix 放哪、怎么用

从 Strix 的 releases 下载 1.7.0 二进制，放任意路径：

```bash
mkdir -p ~/tools && mv strix-1.7.0-linux-x86_64 ~/tools/strix-1.7.0
chmod +x ~/tools/strix-1.7.0
```

不要提交进仓库（`.gitignore` 已覆盖 `strix-*`）。两种指法：

```bash
python3 -m srcguard.cli run ... --strix-bin ~/tools/strix-1.7.0 --launch
# 或
export STRIX_BIN=~/tools/strix-1.7.0
```

SRCGuard 底层实际执行（`--dry-run` 可打印）：

```
strix -n -t <target> --scan-mode quick --max-turns N --max-budget M \
      --instruction-file <run>/instruction.md \
      --mcp-config <run>/mcp-servers.json
```

沙箱镜像（`ghcr.io/usestrix/strix-sandbox:1.3.0`）由 Strix 自己拉取。

### 四条命令

```bash
# 1) 校验 scope
python3 -m srcguard.cli check --scope /tmp/proj-scope.yaml

# 2) 起 LLM 网关（安全网，保持运行）
python3 -m srcguard.cli gateway \
  --upstream https://api.deepseek.com/v1/chat/completions \
  --policy "Authorized scope: only the host in scope. GET/HEAD + POST open, no DELETE/PUT/PATCH. 1 rps." \
  --model deepseek-flash --listen-port 8797 \
  --price-input 0.28 --price-cached 0.07 --price-output 1.10 \
  --max-cost 3 --max-tokens 20000000

# 3) 在笼子里跑
python3 -m srcguard.cli run \
  --scope /tmp/proj-scope.yaml --target https://www.example.edu.cn/ \
  --max-turns 20 --max-budget 2 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 \
  --strix-bin ~/tools/strix-1.7.0 --out-dir srcguard_runs/example --launch

# 4) 审计
python3 -m srcguard.cli audit --run srcguard_runs/example/<run_id> --scope /tmp/proj-scope.yaml
```

只想看命令、不花钱：把 `--launch` 换成 `--dry-run`。

### 两层预算，一次干净停车

| 控制 | 参数 | 行为 |
|---|---|---|
| Strix 预算（主） | `--max-budget` + `--budget-model openai/gpt-4o-mini` | 到预算干净停车（agents=stopped），**可续跑** |
| 网关上限（保险） | `--max-cost` / `--max-tokens` | 主预算的 1.5–2 倍，硬停，返回 429 |

`--budget-model` 让 Strix 能计价（LiteLLM 没有 `deepseek-flash` 的价格），网关再把上游改写成真实模型。预算停车后，续同一个 run：

```bash
python3 -m srcguard.cli run --resume <run_id> --scope /tmp/proj-scope.yaml \
  --max-turns 20 --max-budget 4 --budget-model openai/gpt-4o-mini \
  --gateway-base http://127.0.0.1:8797/v1 --launch
```

### scope 示例

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

## 一个 run 会留下什么

```
policy.json  instruction.md  mcp-servers.json  usage.json  compliance.md
audit/{caido,egress,writes,blocked,oob,rate,method}.jsonl   audit/mcp.log
strix_runs/<name>/{penetration_test_report.md, vulnerabilities/, coverage.json}
```

`compliance.md` 就是可以交给厂商的报告：接触过的 host、越界尝试（被拦 / 成功）、写请求、证据对账、PII/密钥命中。

---

## 诚实的边界

- **nft 笼子是唯一的硬网络边界**；方法与路径规则是命令层或事后的，Caido 这个版本不能丢弃请求。
- `--caido-tamper` 会把被禁方法**改写**成 GET（降级，不是 drop）。
- `--docker-proxy` 限制沙箱能力（去 NET_ADMIN、拒绝 privileged/宿主 netns）。
- 被笼子丢掉的越界 host 记为 `blocked_attempt`，不杀扫描。
- 没有 DNS 权威 OOB，只有 HTTP 回调。
- `strix-main` 永远不被修改（`check_strix.sh` 强制零 diff）。

## 数据脱敏

本仓库已脱敏：

- 不发布任何真实目标的漏洞细节；`evidence/` 只有本地 lab 证明；
- run 目录、网关日志、cookie、API key 都在 `.gitignore`，保持私有；
- 你要发布自己的结果时，先打码 host、token 和未修复的漏洞细节，直到厂商修复。

## License

MIT，见 `LICENSE` 与 `NOTICE`。Strix 是独立项目，遵循其自身许可；本仓库不包含它的代码。
