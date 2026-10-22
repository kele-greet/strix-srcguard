"""Scope compilation for SRCGuard.

Pure functions: parse a scope.yaml, compile it to allow/deny rules, and expose
host/url checks. No network, no Docker, no Strix imports.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


class ScopeError(ValueError):
    """Invalid scope file."""


@dataclass(frozen=True)
class SsrfProbe:
    mode: str = "limited"
    max_requests: int = 3
    methods: tuple[str, ...] = ("GET",)
    metadata_paths: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()
    max_response_bytes: int = 4096
    allow_token_fetch: bool = False


@dataclass(frozen=True)
class ScopePolicy:
    program: str
    in_scope: tuple[str, ...]
    out_of_scope: tuple[str, ...] = ()
    allow_third_party: tuple[str, ...] = ()
    allow_spec_hosts: bool = False
    ssrf: SsrfProbe = field(default_factory=SsrfProbe)
    deny_methods: tuple[str, ...] = ("DELETE",)
    post_mode: str = "open"
    post_allow_paths: tuple[str, ...] = ()
    post_deny_paths: tuple[str, ...] = ()
    post_deny_keywords: tuple[str, ...] = (
        "delete",
        "remove",
        "destroy",
        "drop",
        "refund",
        "pay",
        "send",
        "sms",
        "reset",
        "shutdown",
        "restart",
    )
    max_body_bytes: int = 65536
    default_rps: int = 5
    burst_rps: int = 50
    max_blocked: int = 5
    blocked_same_path: int = 8
    blocked_paths_window_s: int = 300
    max_requests_per_host: int = 0
    web_search_enabled: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def _normalize_name(value: str) -> str:
    """Lowercase, strip trailing dot, normalize IDN/IP/CIDR, drop a domain port."""
    raw = value.strip()
    if not raw:
        return ""
    if raw.startswith("[") and "]" in raw:
        raw = raw[1 : raw.find("]")]
    if "/" in raw:
        try:
            return ipaddress.ip_network(raw, strict=False).with_prefixlen
        except ValueError:
            return raw.lower().rstrip(".")
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        pass
    # domain pattern (possibly wildcard); strip :port
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    raw = raw.lower().rstrip(".")
    if raw.startswith("*."):
        return "*." + _idna(raw[2:])
    return _idna(raw)


def _as_tuple(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ScopeError(f"{name} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ScopeError(f"{name} contains a non-string/empty entry")
        normalized = _normalize_name(item)
        if not normalized:
            raise ScopeError(f"{name} contains an empty host")
        out.append(normalized)
    return tuple(out)


def _as_paths(value: Any, name: str) -> tuple[str, ...]:
    """Path prefixes for method-scoped rules; must start with '/'."""
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ScopeError(f"{name} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ScopeError(f"{name} contains a non-string/empty entry")
        path = item.strip()
        if not path.startswith("/"):
            raise ScopeError(f"{name} entries must start with '/': {path!r}")
        if path not in out:
            out.append(path)
    return tuple(out)


def _as_words(value: Any, name: str) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ScopeError(f"{name} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ScopeError(f"{name} contains a non-string/empty entry")
        word = item.strip().lower()
        if word not in out:
            out.append(word)
    return tuple(out)


def load_scope(path: str | Path) -> ScopePolicy:
    """Parse and validate a scope.yaml."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ScopeError("scope file must be a mapping")
    program = str(raw.get("program") or "").strip()
    if not program:
        raise ScopeError("program is required")
    in_scope = _as_tuple(raw.get("in_scope"), "in_scope")
    if not in_scope:
        raise ScopeError("in_scope must not be empty")
    if "*" in in_scope and not raw.get("allow_wildcard", False):
        raise ScopeError("bare '*' is not allowed without allow_wildcard: true")

    oob_raw = raw.get("oob") or {}
    if not isinstance(oob_raw, dict):
        raise ScopeError("oob must be a mapping")
    oob_mode = str(oob_raw.get("mode") or "off").strip().lower()
    if oob_mode not in {"off", "http", "self_hosted", "local", "dns"}:
        raise ScopeError("oob.mode must be off/http/self_hosted/local/dns")

    ssrf_raw = raw.get("ssrf_probe") or {}
    ssrf = SsrfProbe(
        mode=str(ssrf_raw.get("mode", "limited")).lower(),
        max_requests=int(ssrf_raw.get("max_requests", 3)),
        methods=tuple(str(m).upper() for m in ssrf_raw.get("methods", ["GET"])),
        metadata_paths=tuple(str(p) for p in ssrf_raw.get("metadata_paths", [])),
        denied_paths=tuple(str(p) for p in ssrf_raw.get("denied_paths", [])),
        max_response_bytes=int(ssrf_raw.get("max_response_bytes", 4096)),
        allow_token_fetch=bool(ssrf_raw.get("allow_token_fetch", False)),
    )
    if ssrf.mode not in {"off", "limited", "full"}:
        raise ScopeError("ssrf_probe.mode must be off/limited/full")
    if ssrf.max_requests < 0:
        raise ScopeError("ssrf_probe.max_requests must be >= 0")

    methods = raw.get("methods") or {}
    rate = raw.get("rate") or {}
    limits = raw.get("limits") or {}
    web_search = raw.get("web_search") or {}
    deny_methods = tuple(str(m).upper() for m in methods.get("deny", ["DELETE"]))
    post_allow_paths = _as_paths(methods.get("post_allow_paths"), "methods.post_allow_paths")
    post_deny_paths = _as_paths(methods.get("post_deny_paths"), "methods.post_deny_paths")
    post_deny_keywords = _as_words(methods.get("post_deny_keywords"), "methods.post_deny_keywords")
    if post_deny_keywords is None:
        post_deny_keywords = (
            "delete",
            "remove",
            "destroy",
            "drop",
            "refund",
            "pay",
            "send",
            "sms",
            "reset",
            "shutdown",
            "restart",
        )
    post_mode = str(methods.get("post_mode") or "").strip().lower()
    if not post_mode:
        # Backwards compatible: an explicit allowlist keeps the strict mode.
        post_mode = "allowlist" if post_allow_paths else "open"
    if post_mode not in {"open", "allowlist"}:
        raise ScopeError("methods.post_mode must be open or allowlist")
    if "DELETE" not in deny_methods:
        # Keep it explicit: this is the one destructive method we always block
        # unless the operator opts out with allow_delete: true.
        if not raw.get("allow_delete", False):
            deny_methods = (*deny_methods, "DELETE")

    return ScopePolicy(
        program=program,
        in_scope=in_scope,
        out_of_scope=_as_tuple(raw.get("out_of_scope"), "out_of_scope"),
        allow_third_party=_as_tuple(raw.get("allow_third_party"), "allow_third_party"),
        allow_spec_hosts=bool(raw.get("allow_spec_hosts", False)),
        ssrf=ssrf,
        deny_methods=deny_methods,
        post_mode=post_mode,
        post_allow_paths=post_allow_paths,
        post_deny_paths=post_deny_paths,
        post_deny_keywords=post_deny_keywords,
        max_body_bytes=int(methods.get("max_body_bytes", 65536)),
        default_rps=int(rate.get("default_rps", 5)),
        burst_rps=int(rate.get("burst_rps", 50)),
        max_blocked=int(limits.get("max_blocked", 5)),
        blocked_same_path=int(limits.get("blocked_same_path", 8)),
        blocked_paths_window_s=int(limits.get("blocked_paths_window_s", 300)),
        max_requests_per_host=int(raw.get("max_requests_per_host", limits.get("max_requests_per_host", 0))),
        web_search_enabled=bool(web_search.get("enabled", False)),
        raw=raw,
    )


def _host_of(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
        return _normalize_name(host) or None
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            return _normalize_name(value[1:end]) or None
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    else:
        value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return _normalize_name(value) or None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _pattern_matches_host(pattern: str, host: str) -> bool:
    """Match a host against one pattern.

    Rules:
    - exact: ``api.example.com``
    - wildcard: ``*.example.com`` matches subdomains only (not the apex)
    - CIDR/IP: matched only when ``host`` is an IP literal
    - bare ``*``: matches everything (already gated by allow_wildcard)
    """
    if pattern == "*":
        return True
    if "/" in pattern:
        if not _is_ip(host):
            return False
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return False
    if _is_ip(pattern):
        return host == pattern
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix[1:]
    return host == pattern


def host_allowed(policy: ScopePolicy, host: str) -> tuple[bool, str]:
    """Return (allowed, reason). Deny always wins over allow."""
    host = _normalize_name(host)
    if not host:
        return False, "empty host"
    for pattern in policy.out_of_scope:
        if _pattern_matches_host(pattern, host):
            return False, f"denied by out_of_scope:{pattern}"
    for pattern in policy.in_scope:
        if _pattern_matches_host(pattern, host):
            return True, f"allowed by in_scope:{pattern}"
    for pattern in policy.allow_third_party:
        if _pattern_matches_host(pattern, host):
            return True, f"allowed by allow_third_party:{pattern}"
    return False, "not in scope"


def url_allowed(policy: ScopePolicy, url: str) -> tuple[bool, str]:
    host = _host_of(url)
    if host is None:
        return False, "no host in url"
    return host_allowed(policy, host)


# ---------------------------------------------------------------------------
# API spec / Postman base URL extraction
# ---------------------------------------------------------------------------


def _load_doc(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".json"}:
        return json.loads(text)
    return yaml.safe_load(text)


def _openapi_servers(doc: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for server in doc.get("servers") or []:
        if isinstance(server, dict) and isinstance(server.get("url"), str):
            url = server["url"]
            # Replace simple {var} defaults where the spec provides them.
            for name, var in (server.get("variables") or {}).items():
                if isinstance(var, dict) and "default" in var:
                    url = url.replace("{" + str(name) + "}", str(var["default"]))
            urls.append(url)
    return urls


def _swagger_servers(doc: dict[str, Any]) -> list[str]:
    host = doc.get("host")
    if not isinstance(host, str) or not host:
        return []
    base = str(doc.get("basePath") or "")
    schemes = doc.get("schemes") or ["https"]
    return [f"{scheme}://{host}{base}" for scheme in schemes if isinstance(scheme, str)]


def _postman_servers(doc: dict[str, Any]) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            request = node.get("request")
            if isinstance(request, dict):
                url = request.get("url")
                raw = url.get("raw") if isinstance(url, dict) else url
                if isinstance(raw, str):
                    host = _host_of(raw)
                    if host:
                        scheme = urlparse(raw).scheme or "https" if "://" in raw else "https"
                        found.append(f"{scheme}://{host}")
                elif isinstance(url, dict):
                    host_parts = url.get("host")
                    if isinstance(host_parts, list) and host_parts:
                        host = ".".join(str(p) for p in host_parts)
                        protocol = str(url.get("protocol") or "https")
                        found.append(f"{protocol}://{host}")
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc.get("item") or [])
    return found


def extract_api_spec_base_urls(path: str | Path) -> list[str]:
    """Best-effort base URLs from OpenAPI/Swagger/Postman.

    This is host-side only, matching Strix's own ``utils/api_spec.py`` intent:
    identify the hosts a spec authorizes; do not parse the full contract.
    """
    doc = _load_doc(Path(path))
    if not isinstance(doc, dict):
        return []
    urls: list[str] = []
    if isinstance(doc.get("openapi"), str) or "servers" in doc:
        urls.extend(_openapi_servers(doc))
    if "swagger" in doc:
        urls.extend(_swagger_servers(doc))
    if "info" in doc and "item" in doc:
        urls.extend(_postman_servers(doc))
    out: list[str] = []
    for url in urls:
        if "://" not in url:
            # OpenAPI relative server: drop it; the caller cannot authorize a host.
            continue
        host = _host_of(url)
        if host and url not in out:
            out.append(url)
    return out


def spec_hosts(path: str | Path) -> list[str]:
    return sorted({_host_of(u) or "" for u in extract_api_spec_base_urls(path)} - {""})


@dataclass(frozen=True)
class CompiledPolicy:
    program: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    spec_hosts: tuple[str, ...]
    deny_methods: tuple[str, ...]
    allow_methods: tuple[str, ...]
    post_mode: str
    post_allow_paths: tuple[str, ...]
    post_deny_paths: tuple[str, ...]
    post_deny_keywords: tuple[str, ...]
    max_body_bytes: int
    default_rps: int
    burst_rps: int
    max_blocked: int
    blocked_same_path: int
    blocked_paths_window_s: int
    max_requests_per_host: int
    ssrf: dict[str, Any]
    oob: dict[str, Any]
    budgets: dict[str, Any]
    web_search: bool
    policy_hash: str

    @property
    def in_scope(self) -> tuple[str, ...]:
        return self.allow

    @property
    def out_of_scope(self) -> tuple[str, ...]:
        return self.deny

    @property
    def allow_third_party(self) -> tuple[str, ...]:
        return ()

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "program": self.program,
            "allow": list(self.allow),
            "deny": list(self.deny),
            "spec_hosts": list(self.spec_hosts),
            "methods": {
                "deny": list(self.deny_methods),
                "allow": list(self.allow_methods),
                "post_mode": self.post_mode,
                "post_allow_paths": list(self.post_allow_paths),
                "post_deny_paths": list(self.post_deny_paths),
                "post_deny_keywords": list(self.post_deny_keywords),
            },
            "max_body_bytes": self.max_body_bytes,
            "rate": {
                "default_rps": self.default_rps,
                "burst_rps": self.burst_rps,
                "max_blocked": self.max_blocked,
                "blocked_same_path": self.blocked_same_path,
                "blocked_paths_window_s": self.blocked_paths_window_s,
            },
            "max_requests_per_host": self.max_requests_per_host,
            "ssrf_probe": self.ssrf,
            "oob": self.oob,
            "budgets": self.budgets,
            "web_search": {"enabled": self.web_search},
        }
        if include_hash:
            doc["policy_hash"] = self.policy_hash
        return doc


def compile_policy(
    policy: ScopePolicy,
    *,
    spec_paths: tuple[str | Path, ...] = (),
) -> CompiledPolicy:
    """Compile a parsed scope into the runtime policy document.

    Spec hosts are only merged when ``allow_spec_hosts`` is true; otherwise they
    are recorded for the operator but never widen the allowlist.
    """
    spec_host_list: list[str] = []
    for path in spec_paths:
        for host in spec_hosts(path):
            if host not in spec_host_list:
                spec_host_list.append(host)

    allow = list(policy.in_scope)
    if policy.allow_spec_hosts:
        for host in spec_host_list:
            if host not in allow:
                allow.append(host)

    raw = policy.raw or {}
    methods = raw.get("methods") or {}
    allow_methods = tuple(str(m).upper() for m in methods.get("allow", ["GET", "HEAD", "POST", "PUT", "PATCH"]))
    oob = raw.get("oob") or {}
    budgets = raw.get("budgets") or {}
    ssrf = {
        "mode": policy.ssrf.mode,
        "max_requests": policy.ssrf.max_requests,
        "methods": list(policy.ssrf.methods),
        "metadata_paths": list(policy.ssrf.metadata_paths),
        "denied_paths": list(policy.ssrf.denied_paths),
        "max_response_bytes": policy.ssrf.max_response_bytes,
        "allow_token_fetch": policy.ssrf.allow_token_fetch,
    }
    doc = {
        "program": policy.program,
        "allow": allow,
        "deny": list(policy.out_of_scope),
        "spec_hosts": spec_host_list,
        "methods": {
            "deny": list(policy.deny_methods),
            "allow": list(allow_methods),
            "post_mode": policy.post_mode,
            "post_allow_paths": list(policy.post_allow_paths),
            "post_deny_paths": list(policy.post_deny_paths),
            "post_deny_keywords": list(policy.post_deny_keywords),
        },
        "max_body_bytes": policy.max_body_bytes,
        "rate": {
            "default_rps": policy.default_rps,
            "burst_rps": policy.burst_rps,
            "max_blocked": policy.max_blocked,
            "blocked_same_path": policy.blocked_same_path,
            "blocked_paths_window_s": policy.blocked_paths_window_s,
        },
        "max_requests_per_host": policy.max_requests_per_host,
        "ssrf_probe": ssrf,
        "oob": oob,
        "budgets": budgets,
        "web_search": {"enabled": policy.web_search_enabled},
    }
    canonical = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return CompiledPolicy(
        program=policy.program,
        allow=tuple(allow),
        deny=tuple(policy.out_of_scope),
        spec_hosts=tuple(spec_host_list),
        deny_methods=policy.deny_methods,
        allow_methods=allow_methods,
        post_mode=policy.post_mode,
        post_allow_paths=policy.post_allow_paths,
        post_deny_paths=policy.post_deny_paths,
        post_deny_keywords=policy.post_deny_keywords,
        max_body_bytes=policy.max_body_bytes,
        default_rps=policy.default_rps,
        burst_rps=policy.burst_rps,
        max_blocked=policy.max_blocked,
        blocked_same_path=policy.blocked_same_path,
        blocked_paths_window_s=policy.blocked_paths_window_s,
        max_requests_per_host=policy.max_requests_per_host,
        ssrf=ssrf,
        oob=oob,
        budgets=budgets,
        web_search=policy.web_search_enabled,
        policy_hash=digest,
    )


def write_policy(path: str | Path, compiled: CompiledPolicy) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(compiled.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out


def load_and_compile(
    scope_path: str | Path,
    *,
    spec_paths: tuple[str | Path, ...] = (),
) -> CompiledPolicy:
    return compile_policy(load_scope(scope_path), spec_paths=spec_paths)
