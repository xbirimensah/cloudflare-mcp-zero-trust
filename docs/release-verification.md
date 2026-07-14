# Release verification

Verified locally on 2026-07-14 before the initial private release.

| Check | Result |
|---|---|
| Unit/integration tests | 22 passed |
| Coverage | 81.07% (minimum 80%) |
| Ruff lint and format | passed |
| Pyright | 0 errors, 0 warnings |
| Python compileall | passed |
| Package build | sdist and wheel built |
| `pip-audit` | no known vulnerabilities |
| Bandit | 0 high, medium, or low findings |
| detect-secrets | 0 findings outside ignored build/cache paths |
| Owner/product marker scan | clean |
| FastMCP smoke test | actual in-process server exposed only `status` |

Cloudflare API behavior is tested with an HTTP mock transport. No production
Cloudflare resource was read or changed while verifying this framework.

