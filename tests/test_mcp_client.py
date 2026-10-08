"""MCP istemci SDK testleri — bağımsız ajan PurpleLoop'a böyle bağlanır.

stdio alt süreci + gerçek protokol el sıkışması üzerinden her sarmalayıcı.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pytest.importorskip("mcp")

from purpleloop.mcp_client import PurpleLoopClient  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [8081, 9010],
             "methods": ["GET", "HEAD"]}


@pytest.fixture
def scope_path(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(SCOPE_DOC), encoding="utf-8")
    return str(p)


def test_client_tools_list(scope_path, tmp_path):
    with PurpleLoopClient(scope_path, out_dir=str(tmp_path / "run"),
                          killswitch=str(tmp_path / "KS"),
                          repo_root=REPO) as pl:
        names = pl.tools()
    assert {"status", "scope_check", "scan", "campaign", "gate"} <= set(names)


def test_client_scope_check_allow_and_deny(scope_path, tmp_path):
    with PurpleLoopClient(scope_path, out_dir=str(tmp_path / "run"),
                          killswitch=str(tmp_path / "KS"),
                          repo_root=REPO) as pl:
        evet = pl.scope_check("127.0.0.1", 8081)
        hayir = pl.scope_check("203.0.113.99", 80)
    assert evet["izinli"] is True
    assert hayir["izinli"] is False


def test_client_status_and_killswitch(scope_path, tmp_path):
    with PurpleLoopClient(scope_path, out_dir=str(tmp_path / "run"),
                          killswitch=str(tmp_path / "KS"),
                          repo_root=REPO) as pl:
        st = pl.status()
        ks = pl.killswitch()
    assert st["sunucu"] == "purpleloop-mcp"
    assert ks["aktif"] is False


def test_client_scan_live_lab(scope_path, tmp_path):
    """Canlı lab'a karşı scan (docker compose ayaktaysa)."""
    import socket
    try:
        socket.create_connection(("127.0.0.1", 8081), timeout=2).close()
    except OSError:
        pytest.skip("lab kapalı")

    with PurpleLoopClient(scope_path, out_dir=str(tmp_path / "run"),
                          killswitch=str(tmp_path / "KS"),
                          repo_root=REPO) as pl:
        d = pl.scan(["127.0.0.1"], ["127.0.0.1:8081", "127.0.0.1:9010"])
    assert d["toplam_bulgu"] > 0
    assert d["audit_chain_valid"] is True
    tips = {f["tip"] for f in d["findings"]}
    assert "secret" in tips  # lab'daki ekili parolalar
