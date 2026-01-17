from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ioc_matcher.types import Match


@dataclass(frozen=True, slots=True)
class MatchResult:
    matches: list[Match]
    took_ms: float
    stats: dict[str, Any]