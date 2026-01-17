from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ioc_matcher.errors import NormalizeError

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _is_hex_len(v: str, n: int) -> bool:
    return len(v) == n and _HEX_RE.fullmatch(v) is not None


def validate_ioc(ioc_type: str, value: str) -> None:
    t = (ioc_type or "").strip().lower()
    v = (value or "").strip()

    if not t:
        raise NormalizeError("ioc type missing")
    if not v:
        raise NormalizeError(f"{t}: value missing")

    if t == "sha256":
        if not _is_hex_len(v, 64):
            raise NormalizeError("sha256: expected 64 hex characters")
        return

    if t == "sha1":
        if not _is_hex_len(v, 40):
            raise NormalizeError("sha1: expected 40 hex characters")
        return

    if t == "md5":
        if not _is_hex_len(v, 32):
            raise NormalizeError("md5: expected 32 hex characters")
        return

    if t == "ip":
        try:
            ipaddress.ip_address(v)
        except Exception as e:
            raise NormalizeError(f"ip: invalid address: {v}") from e
        return

    if t == "cidr":
        try:
            ipaddress.ip_network(v, strict=False)
        except Exception as e:
            raise NormalizeError(f"cidr: invalid network: {v}") from e
        return

    if t == "domain":
        d = v.rstrip(".").strip().lower()
        if d.startswith(("http://", "https://")):
            raise NormalizeError("domain: looks like a url")
        if d.startswith("[") and d.endswith("]"):
            raise NormalizeError("domain: looks like an ip literal")
        if d == "localhost":
            return
        if not _DOMAIN_RE.fullmatch(d):
            try:
                ascii_d = d.encode("idna").decode("ascii")
            except Exception:
                ascii_d = d
            if not _DOMAIN_RE.fullmatch(ascii_d):
                raise NormalizeError(f"domain: invalid: {v}")
        return

    if t == "url":
        try:
            parts = urlsplit(v)
        except Exception as e:
            raise NormalizeError("url: parse failed") from e
        scheme = (parts.scheme or "").lower()
        if scheme and scheme not in {"http", "https"}:
            raise NormalizeError("url: only http/https allowed")
        host = parts.hostname or ""
        if not host:
            raise NormalizeError("url: missing host")
        return

    if t == "email":
        if not _EMAIL_RE.fullmatch(v):
            raise NormalizeError("email: invalid format")
        local, _, domain = v.partition("@")
        if not local or not domain:
            raise NormalizeError("email: invalid format")
        return

    raise NormalizeError(f"unsupported ioc type: {t}")