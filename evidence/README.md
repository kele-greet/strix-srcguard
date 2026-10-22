# 交付证据索引

> 所有文件均为本轮实际运行产物；大体积 `p0-gate/` 被 `.gitignore` 忽略，这里只保留可复核的关键证据。

| 文件 | 证明什么 |
|---|---|
| `pytest.txt` | `48 passed`（当前代码） |
| `check_strix.txt` | `strix-main: zero changes verified` |
| `nft-rate-proof.txt` | per-host nft 限速确实 drop：12 次请求 `0 0 1 0 0 1 ...`，dmesg 有 `-rate` 行 |
| `input-cage-proof.txt` | docker0 + br-* input 链：`lab4=[]` 阻断宿主本地目的，`lab4` 例外放行；自定义 bridge 同验 |
| `backup-drill.txt` | 备份→解包→恢复目录跑 48 tests |
| `docker-proxy-real.txt` | 真实 Docker create：去 `NET_ADMIN`、挂载只读、特权/host netns 403 |
| `docker-proxy-strix.txt` | Strix 走代理：`create_mutated` + MCP `200` |
| `dns-guard-real.txt` | 容器 DNS 强制到 guard：allow 解析、deny NXDOMAIN；cage dns4 开关 |
| `dns-guard-strix.txt` | Strix 走 `--docker-proxy --dns-guard`：`Dns -> 172.17.0.1` + MCP `200` |
| `dns-jsonl.txt` | DNS 查询审计样例 |
| `method-guard.txt` | MCP `curl -X DELETE/-XDELETE/--request=DELETE` 被拒 + `method.jsonl` |
| `caido/caido-tamper.txt` | Caido tamper DELETE→GET，目标收到 GET；Strix A/B 规则安装成功 |
| `dns-oob.txt` | 本地 DNS guard 记录 token label，audit 映射 `dns_oob`（非公网权威 DNS） |
| `responses-gateway.txt` | Responses `instructions/input` 注入、`output[].function_call` 审计、脱敏 |
| `balance/balance-report.md/.json` | 本地 SSRF/Web surface 4 次 A/B：web_recall=1.0、ssrf/flag=1、fluency=1.0、audit pass |
| `balance/*-mcp.log` | 每次四个 GET 的真实 MCP 输出 `200 200 200 403` |
| `balance/autonomy-report.md/.json` | 自主模式：模型用浏览器从根页发现路径，target-side SSRF 命中 flag；scope pass、evidence fail（报告 ID 不可核） |
| `ab/ab-report-docker-proxy.md/.json` | 1×2 A/B 走代理，control/treatment 均 recall 1.0、audit pass |
| `ab/ab-report-dns-guard.md/.json` | 1×2 A/B 走 proxy+guard，recall 1.0、audit pass |
| `ab/ab-report-juice-final.md/.json` | 最终 A/B：4/4 recall=1.0，audit pass |
| `ab/*-mcp.log` | 每次 MCP 命令真实输出 `exit=0 out='200200200'` |
| `ab/ab-report-juice-content.md/.json` | 反例：策略写“exactly one GET”时 treatment recall=0.33 |

## 复核命令

```bash
cd /home/kele-1/strix2/srcguard
UV_CACHE_DIR=/tmp/uv-cache uv run pytest -q   # 75 tests
./check_strix.sh
cat evidence/ab/ab-report-juice-final.md
```

## 口径

- `contacted` 来自 egress（nft）/Caido/MCP 命令日志；模型叙述不算证据。
- A/B 的 `path_recall` 是“三个指定路径是否都被命令真正请求”，不是漏洞检出率。
- A/B 的 lab 目标是 `172.17.0.1:3000`（Docker 宿主发布端口）；网络硬边界由 `nft-rate-proof` / `input-cage-proof` 单独证明，不把 A/B 当 cage E2E。
