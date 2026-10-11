#!/usr/bin/env python3
"""agentguard-hook — Claude Code PreToolUse/PostToolUse hook'u.

Stdin'den JSON olay alır, PurpleLoop agentguard'a iletir, karar döndürür.
Kullanım (~/.claude/settings.json):
  {"hooks": {"PreToolUse": [{"hooks": [{"type": "command",
     "command": "python3 /home/ozkangu/Desktop/purpleloop/purpleloop/agentguard_hook.py"}]}]}}

Karar kuralları:
  - kill-switch aktif   -> exit 2 (blokla, Claude'a "block" dialogu gider)
  - yasak desen         -> exit 2
  - kapsam dışı hedef   -> exit 2
  - aksi halde          -> exit 0 (iznin) + audit kaydı
"""
import json
import os
import sys

sys.path.insert(0, "/home/ozkangu/Desktop/purpleloop")

from purpleloop.agentguard import AgentGuard
from purpleloop.audit import AuditLog
from purpleloop.killswitch import KillSwitch
from purpleloop.scope import ScopeContract

STATE_DIR = os.environ.get("AGENTGUARD_HOME", "/tmp/agentguard")
SCOPE_PATH = os.environ.get("AGENTGUARD_SCOPE", "")


def _payload_from_event(ev: dict) -> dict:
    """Claude Code olayını agentguard payload'ına çevir."""
    tool = ev.get("tool_name") or ev.get("tool") or "other"
    inp = ev.get("tool_input") or {}
    p = dict(inp)
    # URL'li araçlardan host/port çıkar (WebFetch/WebSearch vs.)
    url = inp.get("url") or ""
    if url.startswith("http"):
        import urllib.parse as up
        u = up.urlparse(url)
        p.setdefault("host", u.hostname)
        if u.port:
            p.setdefault("port", u.port)
    p["_tool"] = tool
    return p


def main() -> int:
    try:
        ev = json.load(sys.stdin)
    except Exception:
        return 0  # olay okunamıyorsa sessizce izin verme kararı verme — geç
    os.makedirs(STATE_DIR, exist_ok=True)
    scope = None
    if SCOPE_PATH and os.path.exists(SCOPE_PATH):
        try:
            scope = ScopeContract(open(SCOPE_PATH).read())
        except Exception:
            scope = None
    g = AgentGuard(STATE_DIR,
                   audit=AuditLog(os.path.join(STATE_DIR, "audit.jsonl")),
                   killswitch=KillSwitch(os.path.join(STATE_DIR, "KS")),
                   scope=scope)
    agent = ev.get("session_id") or "claude-code"
    tool = ev.get("tool_name") or ev.get("tool") or "other"
    r = g.check(agent, tool, _payload_from_event(ev))
    if r["karar"] == "RED":
        # Claude Code için standart block yanıtı
        print(json.dumps({
            "decision": "block",
            "reason": f"PurpleLoop agentguard: {r['neden']}",
        }))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
