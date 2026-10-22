# P1-F9 A/B: gateway policy injection

| group | run | injected | exec | contacted | paths | recall | in/out tokens | cost | wall_s | findings | audit |
|---|---|---|---|---|---|---|---|---|---|---|---|
| control | 1 | False | 1/0 | 172.17.0.1 | /,/api/Products,/rest/products/search?q=test | 1.0 | 407102/2956 | 0.0 | 39.5 | 0 | pass |
| control | 2 | False | 1/0 | 172.17.0.1 | /,/api/Products,/rest/products/search?q=test | 1.0 | 465860/2753 | 0.0 | 37.3 | 0 | pass |
| treatment | 1 | True | 1/0 | 172.17.0.1 | /,/api/Products,/rest/products/search?q=test | 1.0 | 407684/3339 | 0.0 | 39.9 | 0 | pass |
| treatment | 2 | True | 1/0 | 172.17.0.1 | /,/api/Products,/rest/products/search?q=test | 1.0 | 346748/2752 | 0.0 | 39.7 | 0 | pass |

