from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_HASH_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_WS_RE = re.compile(r"\s+")


def _cfg_get(cfg: Any, path: str, default: Any) -> Any:
    cur = cfg or {}
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def normalize_tags(tags: tuple[str, ...] | list[str] | str) -> tuple[str, ...]:
    if isinstance(tags, str):
        parts = [t.strip() for t in tags.split(";")]
    else:
        parts = [str(t).strip() for t in tags]
    out: list[str] = []
    seen: set[str] = set()
    for t in parts:
        if not t:
            continue
        k = t.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return tuple(out)


def _idna(domain: str) -> str:
    try:
        return domain.encode("idna").decode("ascii")
    except Exception:
        return domain


def normalize_domain(value: str, cfg: dict[str, Any] | None = None) -> str:
    v = value.strip()
    v = v.strip("[](){}<>\"'")
    v = _WS_RE.sub("", v)

    lower = bool(_cfg_get(cfg, "normalize.domains.lower", True))
    strip_dot = bool(_cfg_get(cfg, "normalize.domains.strip_trailing_dot", True))
    idna = bool(_cfg_get(cfg, "normalize.domains.idna", True))

    if lower:
        v = v.lower()
    if strip_dot:
        v = v.rstrip(".")
    if idna:
        v = _idna(v)
    return v


def normalize_email(value: str, cfg: dict[str, Any] | None = None) -> str:
    v = value.strip()
    v = v.strip("[](){}<>\"'")
    v = _WS_RE.sub("", v)
    lower = bool(_cfg_get(cfg, "normalize.emails.lower", True))
    if lower:
        v = v.lower()
    return v


def normalize_hash(value: str, cfg: dict[str, Any] | None = None) -> str:
    v = value.strip()
    v = _WS_RE.sub("", v)
    if not _HASH_HEX_RE.fullmatch(v):
        return v
    upper = bool(_cfg_get(cfg, "normalize.hashes.upper", False))
    return v.upper() if upper else v.lower()


def normalize_ip_or_cidr(value: str) -> str:
    v = value.strip()
    v = _WS_RE.sub("", v)
    return v


def normalize_url(value: str, cfg: dict[str, Any] | None = None) -> str:
    v = value.strip()
    v = v.strip("[](){}<>\"'")
    v = _WS_RE.sub(" ", v)

    lower_host = bool(_cfg_get(cfg, "normalize.urls.lower_host", True))
    strip_default_ports = bool(_cfg_get(cfg, "normalize.urls.strip_default_ports", True))
    drop_fragment = bool(_cfg_get(cfg, "normalize.urls.drop_fragment", True))
    drop_userinfo = bool(_cfg_get(cfg, "normalize.urls.drop_userinfo", True))
    keep_query = bool(_cfg_get(cfg, "normalize.urls.keep_query", True))

    parts = urlsplit(v)
    scheme = (parts.scheme or "http").lower()

    netloc = parts.netloc
    if not netloc and parts.path.startswith("//"):
        parts = urlsplit(f"{scheme}:{v}")
        netloc = parts.netloc

    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)

    host = hostport
    port = ""
    if hostport.startswith("[") and "]" in hostport:
        end = hostport.find("]")
        host = hostport[: end + 1]
        rest = hostport[end + 1 :]
        if rest.startswith(":"):
            port = rest[1:]
    elif ":" in hostport:
        host, port = hostport.rsplit(":", 1)

    if lower_host:
        host = host.lower()
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host
    else:
        host = normalize_domain(host, cfg)

    if strip_default_ports:
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            port = ""

    if drop_userinfo:
        userinfo = ""

    rebuilt_netloc = host
    if port:
        rebuilt_netloc = f"{rebuilt_netloc}:{port}"
    if userinfo:
        rebuilt_netloc = f"{userinfo}@{rebuilt_netloc}"

    path = parts.path or "/"
    query = parts.query if keep_query else ""
    fragment = "" if drop_fragment else parts.fragment

    return urlunsplit((scheme, rebuilt_netloc, path, query, fragment))


def normalize_ioc_value(ioc_type: str, value: str, cfg: dict[str, Any] | None = None) -> str:
    t = (ioc_type or "").strip().lower()
    if t == "domain":
        return normalize_domain(value, cfg)
    if t == "url":
        return normalize_url(value, cfg)
    if t == "email":
        return normalize_email(value, cfg)
    if t in {"sha256", "sha1", "md5"}:
        return normalize_hash(value, cfg)
    if t in {"ip", "cidr"}:
        return normalize_ip_or_cidr(value)
    return value.strip()