from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from ioc_matcher.store.memory import MemoryIndex
from ioc_matcher.types import Ioc


@dataclass(slots=True)
class _NetIoc:
    net: ipaddress._BaseNetwork
    ioc: Ioc


class CidrEngine:
    def __init__(self, index: MemoryIndex | None = None) -> None:
        self._v4: list[_NetIoc] = []
        self._v6: list[_NetIoc] = []
        if index is None:
            return

        for i in index.cidr:
            try:
                n = ipaddress.ip_network(i.value, strict=False)
            except Exception:
                continue
            ni = _NetIoc(net=n, ioc=i)
            if n.version == 4:
                self._v4.append(ni)
            else:
                self._v6.append(ni)

        self._v4.sort(key=lambda x: x.net.prefixlen, reverse=True)
        self._v6.sort(key=lambda x: x.net.prefixlen, reverse=True)

    @classmethod
    def empty(cls) -> "CidrEngine":
        return cls(None)

    def match_ip(self, ip: str) -> list[Ioc]:
        s = (ip or "").strip()
        if not s:
            return []
        try:
            addr = ipaddress.ip_address(s)
        except Exception:
            return []

        out: list[Ioc] = []
        nets = self._v4 if addr.version == 4 else self._v6
        for ni in nets:
            if addr in ni.net:
                out.append(ni.ioc)
        return out