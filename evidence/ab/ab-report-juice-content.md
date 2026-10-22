# P1-F9 A/B: gateway policy injection

| group | run | injected | exec | contacted | paths | recall | in/out tokens | cost | wall_s | findings | audit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control | 1 | False | 1/0 | 172.17.0.1 | /,/api/Products,/rest/products/search?q=test | 1.0 | 351021/3405 | 0.0 | 54.3 | 0 | pass |
| control | 2 | False | 1/0 | 172.17.0.1 | /,/api/Products,/rest/products/search?q=test | 1.0 | 407833/3742 | 0.0 | 55.3 | 0 | pass |
| treatment | 1 | True | 1/0 | 172.17.0.1 | / | 0.33 | 467829/3646 | 0.0 | 52.5 | 0 | pass |
| treatment | 2 | True | 1/0 | 172.17.0.1 | / | 0.33 | 407446/3309 | 0.0 | 42.2 | 0 | pass |

