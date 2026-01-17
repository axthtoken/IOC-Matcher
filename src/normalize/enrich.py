from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from ioc_matcher.normalize.normalize import normalize_domain


def enrich_ioc_value(ioc_type: str, value: str, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    t = (ioc_type or "").strip().lower()
    v = (value or "").strip()

    if t == "ip":
        ip = ipaddress.ip_address(v)
        return {"ip_version": 6 if ip.version == 6 else 4}

    if t == "cidr":
        net = ipaddress.ip_network(v, strict=False)
        return {"ip_version": 6 if net.version == 6 else 4, "prefixlen": net.prefixlen}

    if t == "url":
        parts = urlsplit(v)
        host = parts.hostname or ""
        return {
            "scheme": (parts.scheme or "http").lower(),
            "host": normalize_domain(host, cfg) if host else "",
            "path": parts.path or "/",
            "has_query": bool(parts.query),
        }

    if t == "domain":
        return {"domain": normalize_domain(v, cfg)}

    if t == "email":
        _, _, domain = v.partition("@")
        return {"domain": normalize_domain(domain, cfg) if domain else ""}

    return {}