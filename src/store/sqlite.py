from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ioc_matcher.types import Ioc


class SqliteStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    async def init(self) -> None:
        raise NotImplementedError

    async def put_many(self, iocs: Iterable[Ioc]) -> None:
        raise NotImplementedError

    async def get_all(self) -> list[Ioc]:
        raise NotImplementedError