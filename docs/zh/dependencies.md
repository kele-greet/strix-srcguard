# 依赖清单

> 规则：每加一个库/工具追加一行；优先标准库/已有依赖。

| 库/工具 | 版本 | 为什么加 | 谁在用 | 可否移除 |
|---|---|---|---|---|
| Python | 3.12（`uv` 管理） | 运行环境 | 全部 | 否 |
| PyYAML | `pyyaml>=6` | 解析 `scope.yaml` | `srcguard/scope.py` | 否（可换 JSON，但 scope 用 YAML 更可读） |
| httpx | `httpx>=0.27` | 网关转发、Caido GraphQL、OOB/测试客户端 | `gateway.py`、`caido_observer.py`、`scripts/*` | 否（可换 urllib，但流式/超时能力差） |
| pytest | `>=8`（dev group） | 单测/集成测试 | `tests/` | 仅开发期 |
| ruff | `>=0.11`（dev group） | lint/format | CI/本地 | 仅开发期 |
| mypy | `>=1.16`（dev group） | 类型检查（渐进，不阻塞） | CI/本地 | 仅开发期 |
| Docker CLI + daemon | 29.7.1（环境） | 启停沙箱、特权 nft helper、egress helper、探查容器 IP/Caido 端口 | `cage.py`、`egress.py`、`supervisor.py` | 否（Strix 本身依赖） |
| nftables（宿主 `nft` 1.0.2） | 1.0.2 | L3 硬边界；宿主机无 root，经特权 helper 调用 | `cage.py` | 否 |
| `debian:bookworm-slim` | 固定 tag（生产建议 digest） | 特权 helper 镜像，挂宿主 nft 及其依赖库 | `cage.py` | 否（可换自建固定镜像） |
| `alpine:3.20` | 固定 tag（生产建议 digest） | 特权 egress helper，循环读 `dmesg` | `egress.py` | 否（可换自建固定镜像） |
| gcc（static libc） | 系统 12.x | 编译 P2 DNS helper `srcguard-dnsguard`；运行时不需要 gcc | `scripts/build_dnsguard.sh` | 仅构建期（CI 也构建） |
| `srcguard-dnsguard` | 源码构建 | 静态 DNS allowlist guard；无 Python 运行时依赖 | `dns_guard.py` | 可移除（则 `--dns-guard` 不可用） |
| Strix | 1.7.0 Linux x86_64 | 被护栏的扫描器；零改动 | 全部 | 否 |
| Caido | Strix 自带/外部实例 | 容器内 MITM，提供 method/status/host 观测 | `caido_observer.py` | 可移除，但 audit 的 method/status 证据会缺失 |

## 说明

- 没有引入 Docker Python SDK：直接用 CLI，避免 socket 权限/版本耦合。
- 特权 helper 只用于 nft 与 dmesg，不跑业务代码；生产应固定镜像 digest。
- `uv` 缓存权限在部分环境不可写，测试命令用 `UV_CACHE_DIR=/tmp/uv-cache`。
- 任何新增依赖必须同步更新本文件，否则视为未完成。
