from __future__ import annotations


class IocMatcherError(Exception):
    pass


class ConfigError(IocMatcherError):
    pass


class LoadError(IocMatcherError):
    pass


class NormalizeError(IocMatcherError):
    pass


class StoreError(IocMatcherError):
    pass


class MatchError(IocMatcherError):
    pass