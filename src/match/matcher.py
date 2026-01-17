from __future__ import annotations

import json
import re
import time
from typing import Any, Iterable

from ioc_matcher.errors import MatchError
from ioc_matcher.match.compiler import CompiledMatchers, compile_matchers
from ioc_matcher.match.result import MatchResult
from ioc_matcher.store.memory import MemoryStore
from ioc_matcher.types import Ioc, Match


_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")
_EMAIL_RE = re.compile(r"(?i)(?<![\w.+-])[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}(?![\w.+-])")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"()]+")
_HASH_RE = re.compile(r"(?i)\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63})\b")


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float, bool)):
        return str(v)
    try:
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(v)


def _walk_values(obj: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = _as_str(k)
            if isinstance(v, (dict, list)):
                yield from ((f"{key}.{p}", x) for p, x in _walk_values(v))
            else:
                yield key, v
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, (dict, list)):
                yield from ((f"[{i}].{p}", x) for p, x in _walk_values(v))
            else:
                yield f"[{i}]", v
        return
    yield "", obj


def _pick_meta(event: dict[str, Any]) -> tuple[str, str, str]:
    event_id = _as_str(event.get("event_id") or event.get("id") or event.get("uuid") or "")
    ts = _as_str(event.get("timestamp") or event.get("@timestamp") or event.get("time") or "")
    host = _as_str(event.get("host") or event.get("hostname") or event.get("device") or "")
    return event_id, ts, host


class Matcher:
    def __init__(self, store: MemoryStore, cfg: dict[str, Any] | None = None) -> None:
        self.store = store
        self.cfg = cfg or {}
        self.compiled: CompiledMatchers | None = None

    def build(self) -> None:
        self.store.build()
        self.compiled = compile_matchers(self.store.index(), self.cfg)

    def _compiled(self) -> CompiledMatchers:
        if self.compiled is None:
            self.build()
        return self.compiled  # type: ignore[return-value]

    def match_event(self, event: dict[str, Any]) -> MatchResult:
        t0 = time.perf_counter()
        try:
            compiled = self._compiled()
            event_id, ts, host = _pick_meta(event)

            matches: list[Match] = []
            seen: set[tuple[str, str, str]] = set()

            def add(ioc: Ioc, matched_value: str, field: str, extra: dict[str, Any] | None = None) -> None:
                k = (ioc.type, ioc.value, field)
                if k in seen:
                    return
                seen.add(k)
                matches.append(
                    Match(
                        ioc=ioc,
                        matched_value=matched_value,
                        field=field,
                        event_id=event_id,
                        timestamp=ts,
                        host=host,
                        extra=extra or {},
                    )
                )

            for field, raw in _walk_values(event):
                s = _as_str(raw)
                if not s:
                    continue

                if field.lower() in {"sha256", "sha1", "md5"}:
                    i = compiled.exact.lookup_hash(field.lower(), s)
                    if i:
                        add(i, s, field)
                    continue

                if field.lower() in {"src_ip", "dst_ip", "ip", "client_ip", "remote_ip"}:
                    ip = s.strip()
                    i = compiled.exact.lookup_ip(ip)
                    if i:
                        add(i, ip, field)
                    for net_ioc in compiled.cidr.match_ip(ip):
                        add(net_ioc, ip, field, {"match": "cidr"})
                    continue

                if field.lower() in {"domain", "hostname", "fqdn"}:
                    d = s.strip()
                    i = compiled.exact.lookup_domain(d)
                    if i:
                        add(i, d, field)
                    continue

                if field.lower() in {"url", "uri", "request_url"}:
                    u = s.strip()
                    i = compiled.url.match_url(u)
                    if i:
                        add(i, u, field, {"match": "url"})
                    continue

                if field.lower() in {"email", "email_from", "from"}:
                    e = s.strip()
                    i = compiled.exact.lookup_email(e)
                    if i:
                        add(i, e, field)
                    continue

                for u in _URL_RE.findall(s):
                    i = compiled.url.match_url(u)
                    if i:
                        add(i, u, field, {"match": "url"})

                for e in _EMAIL_RE.findall(s):
                    i = compiled.exact.lookup_email(e)
                    if i:
                        add(i, e, field)

                for ip in _IPV4_RE.findall(s):
                    i = compiled.exact.lookup_ip(ip)
                    if i:
                        add(i, ip, field)
                    for net_ioc in compiled.cidr.match_ip(ip):
                        add(net_ioc, ip, field, {"match": "cidr"})

                for ip in _IPV6_RE.findall(s):
                    if ":" not in ip:
                        continue
                    i = compiled.exact.lookup_ip(ip)
                    if i:
                        add(i, ip, field)
                    for net_ioc in compiled.cidr.match_ip(ip):
                        add(net_ioc, ip, field, {"match": "cidr"})

                for h in _HASH_RE.findall(s):
                    hv = h.strip()
                    if len(hv) == 64:
                        i = compiled.exact.lookup_hash("sha256", hv)
                        if i:
                            add(i, hv, field)
                    elif len(hv) == 40:
                        i = compiled.exact.lookup_hash("sha1", hv)
                        if i:
                            add(i, hv, field)
                    elif len(hv) == 32:
                        i = compiled.exact.lookup_hash("md5", hv)
                        if i:
                            add(i, hv, field)

                allow_domains = bool(((self.cfg.get("matching", {}) or {}).get("text_scan", {}) or {}).get("allow_substring_domains", True))
                if allow_domains:
                    for d in _DOMAIN_RE.findall(s):
                        i = compiled.exact.lookup_domain(d)
                        if i:
                            add(i, d, field)

            took = (time.perf_counter() - t0) * 1000.0
            stats = {
                "version": self.store.version,
                "matches": len(matches),
            }
            return MatchResult(matches=matches, took_ms=took, stats=stats)
        except Exception as e:
            raise MatchError(str(e)) from e

    def match_text(self, text: str, field: str = "message", meta: dict[str, Any] | None = None) -> MatchResult:
        meta = meta or {}
        event = {"message": text, **meta}
        return self.match_event(event)

    def match_batch(self, events: Iterable[dict[str, Any]]) -> MatchResult:
        t0 = time.perf_counter()
        all_matches: list[Match] = []
        total = 0
        for ev in events:
            r = self.match_event(ev)
            all_matches.extend(r.matches)
            total += 1
        took = (time.perf_counter() - t0) * 1000.0
        return MatchResult(
            matches=all_matches,
            took_ms=took,
            stats={"version": self.store.version, "events": total, "matches": len(all_matches)},
        )