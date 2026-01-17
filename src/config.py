from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

import yaml
from pydantic import BaseModel, ConfigDict


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="allow")


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(str(path))
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config root must be a mapping: {path}")
    return data


def _deep_merge(a: Mapping[str, Any], b: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | Path | None = None) -> AppConfig:
    base_dir = Path.cwd()
    env = (os.getenv("IOC_MATCHER_ENV") or "").strip().lower()
    override = (os.getenv("IOC_MATCHER_CONFIG") or "").strip()

    if override:
        path = override

    if path is not None:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = base_dir / p
        return AppConfig.model_validate(_read_yaml(p))

    cfg = _read_yaml(base_dir / "configs" / "default.yaml")
    if env in {"dev", "prod"}:
        env_cfg = _read_yaml(base_dir / "configs" / f"{env}.yaml")
        cfg = _deep_merge(cfg, env_cfg)

    return AppConfig.model_validate(cfg)