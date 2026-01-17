from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ioc_matcher.store.memory import MemoryIndex
from ioc_matcher.match.engines.cidr import CidrEngine
from ioc_matcher.match.engines.exact import ExactEngine
from ioc_matcher.match.engines.url import UrlEngine


@dataclass(slots=True)
class CompiledMatchers:
    exact: ExactEngine
    cidr: CidrEngine
    url: UrlEngine


def compile_matchers(index: MemoryIndex, cfg: dict[str, Any] | None = None) -> CompiledMatchers:
    exact_enabled = bool(((cfg or {}).get("matching", {}) or {}).get("exact", {}).get("enabled", True))
    cidr_enabled = bool(((cfg or {}).get("matching", {}) or {}).get("cidr", {}).get("enabled", True))

    exact = ExactEngine(index) if exact_enabled else ExactEngine.empty()
    cidr = CidrEngine(index) if cidr_enabled else CidrEngine.empty()
    url = UrlEngine(index)

    return CompiledMatchers(exact=exact, cidr=cidr, url=url)