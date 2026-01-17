from __future__ import annotations

from dataclasses import dataclass

from ioc_matcher.normalize.normalize import normalize_ioc_value
from ioc_matcher.store.memory import MemoryIndex
from ioc_matcher.types import Ioc


@dataclass(slots=True)
class ExactEngine:
    _sha256: dict[str, Ioc]
    _sha1: dict[str, Ioc]
    _md5: dict[str, Ioc]
    _domain: dict[str, Ioc]
    _email: dict[str, Ioc]
    _ip: dict[str, Ioc]
    _url: dict[str, Ioc]
    _cfg: dict

    @classmethod
    def empty(cls) -> "ExactEngine":
        return cls({}, {}, {}, {}, {}, {}, {}, {})

    def __init__(self, index: MemoryIndex | None = None, cfg: dict | None = None) -> None:
        self._cfg = cfg or {}
        if index is None:
            self._sha256 = {}
            self._sha1 = {}
            self._md5 = {}
            self._domain = {}
            self._email = {}
            self._ip = {}
            self._url = {}
            return
        self._sha256 = index.sha256
        self._sha1 = index.sha1
        self._md5 = index.md5
        self._domain = index.domain
        self._email = index.email
        self._ip = index.ip
        self._url = index.url

    def lookup_hash(self, algo: str, value: str) -> Ioc | None:
        a = (algo or "").strip().lower()
        v = normalize_ioc_value(a, value, self._cfg)
        if a == "sha256":
            return self._sha256.get(v)
        if a == "sha1":
            return self._sha1.get(v)
        if a == "md5":
            return self._md5.get(v)
        return None

    def lookup_domain(self, value: str) -> Ioc | None:
        v = normalize_ioc_value("domain", value, self._cfg)
        return self._domain.get(v)

    def lookup_email(self, value: str) -> Ioc | None:
        v = normalize_ioc_value("email", value, self._cfg)
        return self._email.get(v)

    def lookup_ip(self, value: str) -> Ioc | None:
        v = normalize_ioc_value("ip", value, self._cfg)
        return self._ip.get(v)

    def lookup_url(self, value: str) -> Ioc | None:
        v = normalize_ioc_value("url", value, self._cfg)
        return self._url.get(v)