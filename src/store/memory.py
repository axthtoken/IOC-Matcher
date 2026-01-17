from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from ioc_matcher.types import Ioc


def _ioc_key(i: Ioc) -> str:
    return f"{i.type}|{i.value}|{i.source}|{';'.join(i.tags)}|{i.confidence}|{i.severity}|{i.first_seen}|{i.last_seen}"


def _fingerprint(iocs: list[Ioc]) -> str:
    h = hashlib.sha256()
    for k in sorted(_ioc_key(i) for i in iocs):
        h.update(k.encode("utf-8", "strict"))
        h.update(b"\n")
    return h.hexdigest()


@dataclass(slots=True)
class MemoryIndex:
    sha256: dict[str, Ioc]
    sha1: dict[str, Ioc]
    md5: dict[str, Ioc]
    domain: dict[str, Ioc]
    url: dict[str, Ioc]
    email: dict[str, Ioc]
    ip: dict[str, Ioc]
    cidr: list[Ioc]


class MemoryStore:
    def __init__(self) -> None:
        self._iocs: list[Ioc] = []
        self._index: MemoryIndex | None = None
        self._version: str = ""

    @property
    def version(self) -> str:
        return self._version

    def clear(self) -> None:
        self._iocs.clear()
        self._index = None
        self._version = ""

    def add(self, ioc: Ioc) -> None:
        self._iocs.append(ioc)
        self._index = None

    def add_many(self, iocs: Iterable[Ioc]) -> None:
        self._iocs.extend(iocs)
        self._index = None

    def all(self) -> list[Ioc]:
        return list(self._iocs)

    def build(self) -> None:
        sha256: dict[str, Ioc] = {}
        sha1: dict[str, Ioc] = {}
        md5: dict[str, Ioc] = {}
        domain: dict[str, Ioc] = {}
        url: dict[str, Ioc] = {}
        email: dict[str, Ioc] = {}
        ip: dict[str, Ioc] = {}
        cidr: list[Ioc] = []

        for i in self._iocs:
            t = i.type
            v = i.value
            if t == "sha256":
                sha256.setdefault(v, i)
            elif t == "sha1":
                sha1.setdefault(v, i)
            elif t == "md5":
                md5.setdefault(v, i)
            elif t == "domain":
                domain.setdefault(v, i)
            elif t == "url":
                url.setdefault(v, i)
            elif t == "email":
                email.setdefault(v, i)
            elif t == "ip":
                ip.setdefault(v, i)
            elif t == "cidr":
                cidr.append(i)

        self._index = MemoryIndex(
            sha256=sha256,
            sha1=sha1,
            md5=md5,
            domain=domain,
            url=url,
            email=email,
            ip=ip,
            cidr=cidr,
        )
        self._version = _fingerprint(self._iocs)

    def index(self) -> MemoryIndex:
        if self._index is None:
            self.build()
        return self._index  

    def stats(self) -> dict[str, Any]:
        idx = self.index()
        return {
            "total": len(self._iocs),
            "sha256": len(idx.sha256),
            "sha1": len(idx.sha1),
            "md5": len(idx.md5),
            "domain": len(idx.domain),
            "url": len(idx.url),
            "email": len(idx.email),
            "ip": len(idx.ip),
            "cidr": len(idx.cidr),
            "version": self._version,
        }