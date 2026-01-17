from __future__ import annotations

APP_NAME = "ioc-matcher"
ENV_VAR_ENV = "IOC_MATCHER_ENV"
ENV_VAR_CONFIG = "IOC_MATCHER_CONFIG"

DEFAULT_CONFIG_PATH = "configs/default.yaml"

IOC_TYPES = (
    "sha256",
    "sha1",
    "md5",
    "ip",
    "cidr",
    "domain",
    "url",
    "email",
)

DEFAULT_CONFIDENCE = 0.6
DEFAULT_SEVERITY = "medium"

OUTPUT_FORMATS = ("jsonl", "csv")
INPUT_FORMATS = ("csv", "txt", "json", "jsonl")