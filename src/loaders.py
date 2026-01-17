from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from ioc_matcher.types import Ioc
from ioc_matcher.errors import LoadError


def load_iocs(rows: Iterable[dict[str, str]]) -> list[Ioc]:
    out: list[Ioc] = []
    for r in rows:
        try:
            out.append(
                Ioc(
                    type=r["type"].strip().lower(),
                    value=r["value"].strip(),
                    source=r.get("source", "").strip(),
                    tags=tuple(t.strip() for t in r.get("tags", "").split(";") if t),
                    confidence=float(r.get("confidence", 0.0) or 0.0),
                    severity=r.get("severity", "medium").strip().lower(),
                    first_seen=r.get("first_seen", "").strip(),
                    last_seen=r.get("last_seen", "").strip(),
                )
            )
        except Exception as e:
            raise LoadError(f"invalid IOC row: {r}") from e
    return out


def load_iocs_from_path(path: str | Path) -> list[Ioc]:
    p = Path(path)
    if not p.exists():
        raise LoadError(f"file not found: {p}")

    if p.suffix == ".csv":
        with p.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return load_iocs(reader)

    if p.suffix in {".json", ".jsonl"}:
        rows = []
        with p.open(encoding="utf-8") as f:
            if p.suffix == ".jsonl":
                for line in f:
                    if line.strip():
                        rows.append(json.loads(line))
            else:
                data = json.load(f)
                if isinstance(data, list):
                    rows = data
                else:
                    raise LoadError("json IOC file must contain a list")
        return load_iocs(rows)

    raise LoadError(f"unsupported IOC format: {p.suffix}")