from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IocType = Literal["sha256", "sha1", "md5", "ip", "cidr", "domain", "url", "email"]
Severity = Literal["low", "medium", "high", "critical"]


class IocRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    type: IocType
    value: str

    source: str = ""
    tags: list[str] = Field(default_factory=list)

    confidence: float = 0.0
    severity: Severity = "medium"

    first_seen: str = ""
    last_seen: str = ""


class MatchRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ioc_type: IocType
    ioc_value: str

    matched_value: str
    field: str

    source: str = ""
    tags: list[str] = Field(default_factory=list)

    confidence: float = 0.0
    severity: Severity = "medium"

    first_seen: str = ""
    last_seen: str = ""

    event_id: str = ""
    timestamp: str = ""
    host: str = ""

    extra: dict[str, Any] = Field(default_factory=dict)