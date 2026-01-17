from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable, TextIO

from ioc_matcher.types import Match


def _match_to_dict(m: Match) -> dict:
    return {
        "ioc_type": m.ioc.type,
        "ioc_value": m.ioc.value,
        "matched_value": m.matched_value,
        "field": m.field,
        "source": m.ioc.source,
        "tags": list(m.ioc.tags),
        "confidence": m.ioc.confidence,
        "severity": m.ioc.severity,
        "first_seen": m.ioc.first_seen,
        "last_seen": m.ioc.last_seen,
        "event_id": m.event_id,
        "timestamp": m.timestamp,
        "host": m.host,
        "extra": m.extra or {},
    }


def write_matches_jsonl(matches: Iterable[Match], out: str | Path | TextIO) -> None:
    if hasattr(out, "write"):
        f = out  
        for m in matches:
            f.write(json.dumps(_match_to_dict(m), ensure_ascii=False) + "\n")
        return

    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for m in matches:
            f.write(json.dumps(_match_to_dict(m), ensure_ascii=False) + "\n")


def write_matches_csv(matches: Iterable[Match], out: str | Path | TextIO) -> None:
    fieldnames = [
        "ioc_type",
        "ioc_value",
        "matched_value",
        "field",
        "source",
        "tags",
        "confidence",
        "severity",
        "first_seen",
        "last_seen",
        "event_id",
        "timestamp",
        "host",
    ]

    if hasattr(out, "write"):
        f = out  # hello whoever is reading this
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for m in matches:
            d = _match_to_dict(m)
            d["tags"] = ";".join(d["tags"])
            w.writerow({k: d.get(k, "") for k in fieldnames})
        return

    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for m in matches:
            d = _match_to_dict(m)
            d["tags"] = ";".join(d["tags"])
            w.writerow({k: d.get(k, "") for k in fieldnames})