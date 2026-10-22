# SRCGuard 架构（v2.0 实现版）

> 目标：在**零改动** Strix 源码的前提下，给 Strix 加一层外部 SRC 护栏；硬边界在网络层，提示词/网关只做软约束与审计。

## 一页纸

```
用户 scope.yaml + targets
        │
        ▼
┌──────────────────────────────────────────────┐
│ L0 scope.py / preflight.py                   │
│ 解析 scope → allow/deny/method/rate/quota    │
│ 目标校验 → instruction + argv + env + MCP    │
└───────────────┬──────────────────────────────┘
                ▼
┌──────────────────────────────────────────────┐
│ supervisor.py（一次 run 的编排）              │
│  install cage → OOB → egress → monitor →     │
│  launch Strix → 发现容器 IP/Caido → 清理     │
└──────┬──────────────┬───────────────┬────────┘
       │              │               │
       ▼              ▼               ▼
  L3 cage.py     L2 gateway.py    L6 audit.py
  docker_proxy.py（可选） / dns_guard.py（可选）
  nftables       system 注入       contacted/
  硬 allowlist   脱敏/审计         evidence/密钥
  内网黑洞       软约束            compliance.md
  全局/每主机    （不硬拦）        kill.py/monitor.py
  限速
       │
       ▼
  Strix 1.7.0（Docker sandbox + Caido）
       │
       ├── 模型工具调用：MCP stdio shim（mcp_shim.py）
       └── 网络出口：nft forward hook → allow/block/drop/rate 日志
```

## 分层与职责

| 层 | 模块 | 职责 | 是否硬边界 |
|---|---|---|---|
| L0 预检 | `scope.py` | scope 解析、通配/排除/CIDR、API spec base_urls、策略哈希 | 否（但决定 allowlist） |
| L0 预检 | `preflight.py` | 目标校验、instruction 渲染、argv/env、MCP config、预算/轮次 | 部分（目标校验） |
| L1 指令 | `templates/instruction.md` | root 的 SRC 纪律、七类动作、五个数字、子 agent 约束 | 否 |
| L2 网关 | `gateway.py` | Chat `messages` / Responses `instructions|input` 注入 `<srcguard_policy>`；tool 结果脱敏；Chat/Responses tool_call 审计 | 否（软约束） |
| L2 MITM | `caido_tamper_guard.py`（P2，可选） | Caido tamper rule 把 deny_methods 改写为 GET；目标收不到 DELETE | 否（降级，非 drop） |
| L3 网络 | `cage.py` | 每 run 一张 nft 表：forward + docker0/br-* input 双链；元数据/RFC1918/ULA 黑洞、scope IP allowlist、OOB/lab 例外、全局新连接 cap、每主机新连接限速 | **是** |
| L3 观测 | `egress.py` | 特权 helper 读 `dmesg`，解析 nft 的 allow/block/drop/rate 日志 → `audit/egress.jsonl` | 否（ground truth） |
| L3 观测 | `caido_observer.py` | 只读 Caido：请求列表 → `audit/caido.jsonl`，拿到 method/status/host | 否（ground truth） |
| L4 容器 | `docker_proxy.py`（P2，可选） | Docker API 变更代理：去 NET_ADMIN、拒绝特权/host netns、敏感 bind mount 只读、强制容器 DNS | 可选 |
| L5 DNS | `dns_guard.py` + `dnsguard.c`（P2，可选） | 受控 resolver：scope/OOB allowlist、NXDOMAIN、`audit/dns.jsonl` | 可选 |
| L5 OOB | `oob.py` | 本地 HTTP 回连服务器 + token 校验；cage 单独放行 OOB 目的 | 否 |
| L6 审计 | `audit.py` | 汇总 contacted/out_of_scope/evidence/secret/PII → `compliance.md` | 否 |
| L6 停机 | `kill.py` / `monitor.py` | 越界/限速/403/429 → 杀进程组 + 删容器 | 否（事后） |
| 执行通道 | `mcp_shim.py` + `method_guard.py` | stdio MCP server，暴露 `sandbox_exec`；命令层拦截 deny_methods | 否（软） |

## 模块依赖方向

```
cli ──► preflight ──► scope
 │         │
 │         └──► supervisor ──► cage
 │                  │           ├──► egress
 │                  │           ├──► caido_observer
 │                  │           ├──► monitor ──► kill
 │                  │           └──► oob
 │                  └──► audit ──► scope? (只读 policy)
 └──► gateway（独立，不依赖 cage）
```

约束：

- `scope.py` 是纯函数层，不 import 运行时模块。
- `gateway.py` 不依赖 cage/supervisor，可单独启动。
- `audit.py` 只读产物，不改 run 状态。
- `mcp_shim.py` 不 import Strix，只依赖 Docker CLI；`method_guard.py` 只做纯字符串匹配。
- `docker_proxy.py` 不 import Strix；只接受 `DOCKER_HOST` 的 Docker HTTP API。
- `dns_guard.py` 只负责启动/停止静态 C helper，不依赖 Strix；helper 在 host-network Debian 容器内绑定 `172.17.0.1:53`。

## 一次 run 的顺序

1. `srcguard check`：scope → policy.json（哈希可复现）。
2. `srcguard run --launch`：
   - `prepare_run` 校验目标、生成 `run.json/policy.json/instruction.md/mcp-servers.json`；
   - `supervisor.launch` 解析 allow 域名 → IP；
   - 安装 per-run nft 表（先 drop 内网/元数据，再 allow scope，再 drop 其他）；
   - 启动 OOB、egress collector、Caido observer、monitor；
   - 用 `cwd=run_dir`、隔离 HOME/XDG、清空搜索 key 启动 Strix；
   - 按 label 找到沙箱容器，把容器 IP 加入 `containers` 集（此前规则不命中任何容器）；
   - 发现 Caido 端口/项目 id，开始轮询；
   - 等 Strix 退出，停止 collector/monitor，删除表/容器。
3. `srcguard audit --run <dir>`：读策略、egress、Caido、OOB、vulnerabilities → `compliance.md`。

## MCP sandbox_exec（为什么存在）

Strix 1.7.0 会把 `exec_command`/`write_stdin`/`apply_patch` 作为 SandboxAgent capability 工具广告给模型，但本构建中模型返回合法 tool_call 后**没有派发**（`strix.log` 无 `Invoking tool`），而 base tools（`call_mcp`/`create_agent`/`finish_scan`）正常。

因此 SRCGuard 默认：

- `prepare_run` 生成 stdio MCP server `srcguard`，工具 `sandbox_exec`；
- instruction 明确让模型用 `call_mcp(connection="srcguard", tool="sandbox_exec", ...)`；
- shim 用 `docker exec <container> sh -lc <cmd>` 执行，cage/Caido/egress 仍然生效；
- `--no-mcp` 可关闭，退回原始 Strix 工具（不推荐，可能无工具可派发）。

这不是修改 Strix，而是换一条模型可用的执行通道。

## 明确“不做什么”

- 不修改 `strix-main/` 任何文件；`check_strix.sh` + sha256 校验。
- 不承诺网关能硬拦 tool_call：L2 只能审计/注入/脱敏，模型仍可能不听话。
- 不把 `chatgpt/` 订阅模式纳入护栏：该模式绕过 `LLM_API_BASE`，网关不可见。
- P1 不做 MITM 方法级阻断：HTTPS 只能看到 CONNECT 的 SNI/host；方法阻断需要 P2 自建 MITM 或 Caido 规则。
- P1 不做 DNS OOB：只做 HTTP OOB；53/UDP 与公网隧道放 P2。
- P1 不做 Docker API 变更（cap/只读挂载/DNS）：需要 P2 的 Docker API 代理。
- 不把所有 scope 外的域名都解析成 IP 放行：wildcard 只给 warning，需 DNS-aware 层（P2）。
- 不保证“模型说扫了”就是扫了：`contacted` 只认 egress/Caido/MCP 命令日志。
