# P1 balance gate (surface proxy, not vuln discovery)

| group | run | mcp | web | web_recall | ssrf_fetch | flag | fluency | scope | evidence |
|---|---|---|---|---|---|---|---|---|---|
| control | 1 | 0 | /,/admin,/api/users | 1.0 | 2 | 2 | 1.0 | pass | pass |
| control | 2 | 0 | /,/admin,/api/users | 1.0 | 1 | 1 | 1.0 | pass | pass |
| treatment | 1 | 0 | /,/admin,/api/users | 1.0 | 1 | 1 | 1.0 | pass | pass |
| treatment | 2 | 0 | /,/admin,/api/users | 1.0 | 1 | 1 | 1.0 | pass | pass |
