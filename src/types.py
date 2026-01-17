from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

IocType = Literal["sha256", "sha1", "md5", "ip", "cidr", "domain", "url", "email"]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class Ioc:
    type: IocType
    value: str
    source: str = ""
    tags: tuple[str, ...] = ()
    confidence: float = 0.0
    severity: Severity = "medium"
    first_seen: str = ""
    last_seen: str = ""


@dataclass(frozen=True, slots=True)
class Match:
    ioc: Ioc
    matched_value: str
    field: str
    event_id: str = ""
    timestamp: str = ""
    host: str = ""
    extra: dict[str, Any] = None # city boi