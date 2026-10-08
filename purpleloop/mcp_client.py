"""PurpleLoop MCP istemcisi — ajanların platforma bağlanması için ince SDK.

Bağımsız bir ajan (Hermes çocuğu, başka LLM ajanı, CI betiği) bu modülle
PurpleLoop MCP sunucusuna stdio üzerinden bağlanır ve araçları çağırır.

Tasarım: STATELESS — her çağrı kendi bağlantısını açar ve kapatır.
Neden: anyio event-loop'u bir çağrıdan diğerine taşınamaz; parça parça
anyio.run'lar kapalı transport'a düşer ("Connection closed"). Tek çağrıda
stdio bağlantısı ~yüz ms — ajan iş akışında ihmal edilebilir; doğruluk
ve sadelik kazanır.

Kullanım:
    with PurpleLoopClient(scope_path="scope.json", out_dir="run") as pl:
        pl.tools()
        pl.scope_check("127.0.0.1", 3100)
        pl.scan(["127.0.0.1"], ["127.0.0.1:3100"])
        pl.campaign(["127.0.0.1"], ["127.0.0.1:3100"], max_steps=10)
        pl.gate("run")

Her çağrı sunucudan dönen JSON'u dict olarak verir; hata MCPError yükselir.
"""
from __future__ import annotations

import json
from typing import Optional


class PurpleLoopClient:
    """Stateless PurpleLoop MCP araç istemcisi (stdio)."""

    def __init__(self, scope_path: str, out_dir: str = "mcp-run",
                 killswitch: str = "KILLSWITCH", repo_root: Optional[str] = None,
                 python: Optional[str] = None):
        import os
        import sys
        self._scope = os.path.abspath(scope_path)
        self._out = os.path.abspath(out_dir)
        self._ks = os.path.abspath(killswitch)
        self._repo = repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._python = python or sys.executable
        self._entered = False

    def __enter__(self) -> "PurpleLoopClient":
        self._entered = True
        return self

    def __exit__(self, *exc) -> None:
        self._entered = False

    # ------------------------------------------------------------------
    # Bağlantı kurulumu
    # ------------------------------------------------------------------

    def _params(self):
        import os
        import sys
        from mcp.client.stdio import StdioServerParameters

        # stdio_client env'i beyaz listeye alır: mcp SDK'nın site-packages'ı
        # dahil TAM sys.path'i PYTHONPATH olarak taşı (yoksa alt süreç
        # 'No module named anyio' ile ölür).
        env = {"HOME": os.environ.get("HOME", "/root"),
               "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
        return StdioServerParameters(
            command=self._python,
            args=["-m", "purpleloop.mcp_server",
                  "--scope", self._scope,
                  "--out-dir", self._out,
                  "--killswitch", self._ks],
            env=env, cwd=self._repo)

    def _run(self, fn):
        """Tek anyio.run içinde: bağlantı aç → initialize → fn(session) → kapat."""
        import anyio
        from mcp.client.stdio import stdio_client
        from mcp.client.session import ClientSession

        params = self._params()

        async def _inner():
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await fn(session)

        return anyio.run(_inner)

    # ------------------------------------------------------------------
    # Araçlar
    # ------------------------------------------------------------------

    def tools(self) -> list:
        async def _fn(s):
            res = await s.list_tools()
            return [t.name for t in res.tools]
        return self._run(_fn)

    def _call(self, name: str, args: dict) -> dict:
        async def _fn(s):
            res = await s.call_tool(name, args)
            return json.loads(res.content[0].text)
        return self._run(_fn)

    def status(self) -> dict:
        return self._call("status", {})

    def scope_check(self, host: str, port: int, method: str = "GET") -> dict:
        return self._call("scope_check", {"host": host, "port": port,
                                          "method": method})

    def scan(self, hosts: list, endpoints: list,
             domains: Optional[list] = None, active: bool = True) -> dict:
        args = {"hosts": hosts, "endpoints": endpoints, "active": active}
        if domains:
            args["domains"] = domains
        return self._call("scan", args)

    def campaign(self, hosts: list, endpoints: list,
                 max_steps: int = 10) -> dict:
        return self._call("campaign", {"hosts": hosts,
                                       "endpoints": endpoints,
                                       "max_steps": max_steps})

    def gate(self, out_dir: Optional[str] = None) -> dict:
        return self._call("gate", {"out_dir": out_dir or self._out})

    def killswitch(self) -> dict:
        return self._call("killswitch", {})

    def audit(self, tail: int = 10) -> dict:
        return self._call("audit", {"tail": tail})
