from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ioc_matcher.normalize.normalize import normalize_domain, normalize_url
from ioc_matcher.store.memory import MemoryIndex
from ioc_matcher.types import Ioc


@dataclass(slots=True)
class UrlEngine:
    _urls: dict[str, Ioc]
    _domains: dict[str, Ioc]
    _cfg: dict

    def __init__(self, index: MemoryIndex | None = None, cfg: dict | None = None) -> None:
        self._cfg = cfg or {}
        if index is None:
            self._urls = {}
            self._domains = {}
            return
        self._urls = index.url
        self._domains = index.domain

    def match_url(self, value: str) -> Ioc | None:
        raw = (value or "").strip()
        if not raw:
            return None

        nu = normalize_url(raw, self._cfg)
        hit = self._urls.get(nu)
        if hit:
            return hit

        try:
            host = urlsplit(nu).hostname or ""
        except Exception:
            host = ""
        if host:
            nd = normalize_domain(host, self._cfg)
            return self._domains.get(nd)

        return None