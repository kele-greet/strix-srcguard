# 安全底线（SRCGuard）

1. **不信任提示词**：范围校验只在 L0/L3；instruction 与网关注入只降低误报，不作为边界。
2. **默认拒绝**：未在 allowlist 的目的 IP 由 nft drop；元数据/RFC1918/ULA 先黑洞；OOB/lab 只按显式配置例外。
3. **子 agent 不继承 instruction**：子 agent 的任务从 root 来，root 可能被误导；网络层是最终兜底。
4. **凭据**：不读取、不使用、不落盘；tool 结果中的 AKIA/ASIA/AIDA/AROA 形态会被网关脱敏；报告只写“存在凭据泄露”。
5. **密钥**：只从环境变量读，不写代码/日志/git；`.hermes/.env` 之类文件必须 `0600`；仓库里不出现 `sk-`。
6. **最小权限**：SRCGuard 只读 Docker、只写 run 目录；不挂宿主敏感目录；特权 helper 只挂 nft/dmesg 所需二进制与库。
7. **零侵入**：`strix-main` 只读；`check_strix.sh` + sha256 校验，任何改动即失败。
8. **硬边界失败即停**：`cage.install` 失败直接抛错，不启动 Strix；`prepare_run` 目标校验失败直接退出。
9. **软边界失败不冒充成功**：egress collector/Caido/monitor 失败只 warn；此时 `contacted` 不完整，`compliance.md` 必须标注，不能据此说“没越界”。
10. **私有 lab 例外**：`NO_PROXY` 只对 scope 中显式私有目标绕过 Caido；公网仍走 Caido；nft 的 allow/lab 规则始终生效。
11. **MCP 方法护栏是软的**：只匹配 `sandbox_exec` 的 curl 形式，脚本/Python/浏览器可绕过；HTTPS 方法阻断仍需 MITM。
12. **DNS 护栏是可选加固**：`--dns-guard` 只按 QNAME 过滤，不检查 CNAME 链，不阻止 DoH/DoT；不能把它当完整 DNS 边界。
12. **不承诺网关硬拦**：L2 只能注入/审计/脱敏；模型仍可能不执行或换通道；真正的阻断在 L3。
12. **不把“模型说扫了”当证据**：`contacted` 只取 egress/Caido/MCP 命令日志；模型叙述只作线索。
13. **遥测**：默认 `STRIX_TELEMETRY=false`；SRCGuard 自身不外发。
14. **数据**：目标原始数据不额外持久化；报告打码；误带出的数据在报告中主动写数量与处置。
15. **授权**：只用于已授权 SRC；工具不创造授权。

## 检查清单

- scope 绕过（大小写、结尾点、IPv6、CNAME、重定向）
- DNS 逃逸（P1 残留：wildcard/DNS-aware 未做）
- 日志泄密（token/PII/Authorization）
- 临时文件权限（run 目录、mcp log）
- 依赖漏洞（pyyaml/httpx/Docker/nft）
- shell 注入（nft 参数拼接、MCP cmd 透传）
- Docker socket 暴露 / privileged helper
- Caido 盲区（private NO_PROXY 时无 method/status）
- egress collector 未启动时 contacted 不完整

## 已知未关闭

- HTTPS 方法级阻断（P2，需 MITM/Caido 规则）。
- Docker API 变更（cap/只读挂载/DNS）已做 P2-1；DNS 仅 QNAME 过滤，CNAME/DoH 未做。
- DNS OOB 仅本地 guard 记录，公网权威 DNS/隧道未做（P2）。
- wildcard/DNS-aware 放行未做（P2）。
- `chatgpt/` 订阅模式绕过 `LLM_API_BASE`，网关不可见。
