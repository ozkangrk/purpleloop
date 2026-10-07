"""Scope contract: allow-list of IPs/domains/ports/methods/time windows.

FAIL-CLOSED: any error, missing field, invalid JSON, or out-of-scope request
is DENIED. Nothing is ever implicitly allowed.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import re
from typing import Any, Optional


class ScopeError(Exception):
    """Raised on invalid scope contract definitions."""


_WILDCARD_RE = re.compile(r"^\*\.[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$")


def _validate_domain(dom: str) -> None:
    if dom == "*":
        raise ScopeError("bare '*' wildcard domain is forbidden (fail-closed)")
    if "*" in dom:
        if not _WILDCARD_RE.match(dom):
            raise ScopeError(f"invalid wildcard domain: {dom!r}")
        return
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+", dom):
        raise ScopeError(f"invalid domain: {dom!r}")


def _parse_hhmm(s: str) -> _dt.time:
    if not isinstance(s, str) or not re.fullmatch(r"\d{2}:\d{2}", s):
        raise ScopeError(f"invalid HH:MM time: {s!r}")
    h, m = int(s[:2]), int(s[3:])
    if h > 23 or m > 59:
        raise ScopeError(f"invalid HH:MM time: {s!r}")
    return _dt.time(h, m)


class ScopeContract:
    def __init__(self, doc: Any):
        if isinstance(doc, (str, bytes)):
            try:
                doc = json.loads(doc)
            except Exception as e:
                raise ScopeError(f"invalid JSON contract: {e}")
        if not isinstance(doc, dict):
            raise ScopeError("contract must be a JSON object")
        for field in ("targets", "ports", "methods"):
            if field not in doc:
                raise ScopeError(f"missing required field: {field}")
        self.doc = doc
        self.targets: list = doc["targets"]
        self.ports: list = doc["ports"]
        self.methods: list = doc["methods"]
        self.window = doc.get("time_window")  # {"start": "HH:MM", "end": "HH:MM"} optional

        if not isinstance(self.targets, list) or not self.targets:
            raise ScopeError("targets must be a non-empty list")
        if not isinstance(self.ports, list) or not self.ports:
            raise ScopeError("ports must be a non-empty list")
        if not isinstance(self.methods, list) or not self.methods:
            raise ScopeError("methods must be a non-empty list")

        for p in self.ports:
            if isinstance(p, bool) or not isinstance(p, int) or not (1 <= p <= 65535):
                raise ScopeError(f"invalid port: {p!r}")
        for m in self.methods:
            if not isinstance(m, str) or not re.fullmatch(r"[A-Z]+", m):
                raise ScopeError(f"invalid method: {m!r}")

        self._networks = []
        self._domains = set()
        self._wildcards = []
        for t in self.targets:
            if not isinstance(t, str):
                raise ScopeError(f"invalid target: {t!r}")
            if "/" in t:
                try:
                    self._networks.append(ipaddress.ip_network(t, strict=False))
                except ValueError as e:
                    raise ScopeError(f"invalid CIDR: {t!r}: {e}")
            else:
                try:
                    self._networks.append(ipaddress.ip_network(t + "/32", strict=False))
                except ValueError:
                    _validate_domain(t)
                    if re.fullmatch(r"[0-9.]+", t):
                        raise ScopeError(f"malformed IP literal: {t!r}")
                    if "*" in t:
                        self._wildcards.append(t[2:])  # strip "*."
                    else:
                        self._domains.add(t.lower())

        if self.window is not None:
            if not isinstance(self.window, dict) or "start" not in self.window or "end" not in self.window:
                raise ScopeError("time_window must have start and end (HH:MM)")
            try:
                self._w_start = _parse_hhmm(self.window["start"])
                self._w_end = _parse_hhmm(self.window["end"])
            except ScopeError:
                raise
            except Exception as e:
                raise ScopeError(f"invalid time_window: {e}")

    # ---------- helpers ----------

    def _in_window(self, now: Optional[_dt.time]) -> bool:
        if self.window is None:
            return True
        now = now or _dt.datetime.now().time()
        # minutes since midnight comparison, supports overnight windows
        n = now.hour * 60 + now.minute
        s = self._w_start.hour * 60 + self._w_start.minute
        e = self._w_end.hour * 60 + self._w_end.minute
        if s <= e:
            return s <= n < e
        return n >= s or n < e  # overnight window (e.g. 22:00-06:00)

    def _ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def _host_allowed(self, host: str) -> bool:
        h = host.lower().rstrip(".")
        if h in self._domains:
            return True
        for suffix in self._wildcards:
            if h.endswith("." + suffix):
                return True
        return self._ip_allowed(host)

    # ---------- main gate ----------

    def check_request(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        method: Optional[str] = None,
        now: Optional[_dt.time] = None,
    ) -> tuple:
        """Return (allowed: bool, reason: str). Everything missing => DENY."""
        if host is None:
            return (False, "missing host")
        if not isinstance(host, str) or not host.strip():
            return (False, "missing host")
        if port is None:
            return (False, "missing port")
        if not isinstance(port, int) or isinstance(port, bool):
            return (False, "missing port")
        if method is None or not isinstance(method, str) or not method.strip():
            return (False, "missing method")
        if method.upper() not in self.methods:
            return (False, f"method {method} not allowed")
        if port not in self.ports:
            return (False, f"port {port} not allowed")
        if not self._host_allowed(host):
            return (False, f"host {host} not in scope")
        if not self._in_window(now):
            return (False, "outside time window")
        return (True, "in scope")
