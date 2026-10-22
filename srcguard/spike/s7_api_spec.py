"""S7: API spec / Postman base URL extraction into the scope allowlist."""

from __future__ import annotations

import tempfile
from pathlib import Path

from .common import Result
from srcguard.scope import extract_api_spec_base_urls, host_allowed, load_scope, spec_hosts


def run(root: Path) -> Result:
    evidence: list[str] = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            openapi = base / "openapi.yaml"
            openapi.write_text(
                """
openapi: 3.0.0
servers:
  - url: https://api.example.com/v1
  - url: https://{env}.example.com
    variables:
      env: {default: staging}
""",
                encoding="utf-8",
            )
            postman = base / "postman.json"
            postman.write_text(
                '{"info":{"name":"x"},"item":[{"name":"r","request":{"url":{"raw":"https://api.example.com/a"}}}]}',
                encoding="utf-8",
            )
            urls = extract_api_spec_base_urls(openapi) + extract_api_spec_base_urls(postman)
            hosts = spec_hosts(openapi) + spec_hosts(postman)
            evidence.append(f"base_urls={urls}")
            evidence.append(f"hosts={hosts}")
            assert "api.example.com" in hosts and "staging.example.com" in hosts

            scope = base / "scope.yaml"
            scope.write_text(
                "program: x\nin_scope: ['*.example.com']\nallow_spec_hosts: true\n",
                encoding="utf-8",
            )
            policy = load_scope(scope)
            allowed, reason = host_allowed(policy, "staging.example.com")
            evidence.append(f"staging_allowed={allowed} reason={reason}")
            assert allowed
            denied, reason2 = host_allowed(policy, "api.other.com")
            evidence.append(f"other_allowed={denied} reason={reason2}")
            assert not denied
        return Result(
            "S7",
            "API spec base_urls",
            "PASS",
            "OpenAPI/Postman base URLs can be compiled into the allowlist; non-listed hosts stay denied",
            evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return Result("S7", "API spec base_urls", "FAIL", f"{type(exc).__name__}: {exc}", evidence)
