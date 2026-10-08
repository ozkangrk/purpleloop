"""Zincir sömürü + remediation testleri."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.chainexploit import ChainExploiter, derive_next_probes  # noqa: E402
from purpleloop.agent_attack import ProbeProposer  # noqa: E402
from purpleloop.remediation import get_remediation, REMEDIATION_DB  # noqa: E402
from purpleloop.scope import ScopeContract  # noqa: E402
from purpleloop.audit import AuditLog  # noqa: E402
from purpleloop.killswitch import KillSwitch  # noqa: E402

SCOPE_DOC = {"targets": ["127.0.0.1"], "ports": [3100],
             "methods": ["GET", "HEAD"]}


# ---------------------------------------------------------------------------
# Remediation DB
# ---------------------------------------------------------------------------

def test_remediation_known_types_complete():
    for tip in ("sqli_data_leak", "auth_bypass", "idor", "path_traversal",
                "secret", "jwt_alg_none", "xss_reflection", "open_redirect",
                "error_disclosure", "missing_header", "bounty_solve",
                "agent_probe_leak", "nuclei_critical"):
        r = get_remediation(tip, "kanıt-örnek")
        assert r["baslik"]
        assert len(r["adimlar"]) >= 2
        assert r["owasp"]
        assert r["dogrulama"]
        assert "kanıt-örnek" in r["risk"]


def test_remediation_unknown_type_fallback():
    r = get_remediation("bilinmeyen_tip", "x")
    assert r["baslik"] == "bilinmeyen_tip"
    assert r["adimlar"]


# ---------------------------------------------------------------------------
# Zincir türetme
# ---------------------------------------------------------------------------

def test_derive_from_directory_listing():
    body = '<html>listing directory <a href="acquisitions.md">a</a> <a href="eastere.gg">e</a></html>'
    props = derive_next_probes("directory", "/ftp/", body)
    yollar = [p for p, _ in props]
    assert any("acquisitions.md" in y for y in yollar)
    assert all(g for _, g in props)  # her önerinin gerekçesi var


def test_derive_from_sqli_leak():
    body = '{"data":[{"email":"admin@x.op"},{"email":"jim@x.op"}]}'
    props = derive_next_probes("sqli_data_leak", "/search", body)
    assert any("admin@x.op" in p for p, _ in props)


def test_derive_from_error_disclosure():
    body = "Error: Unexpected path: /rest/secret/admin-panel"
    props = derive_next_probes("error_disclosure", "/rest/x", body)
    assert any("secret" in p for p, _ in props)


# ---------------------------------------------------------------------------
# Zincir motoru (FakeTransport ile uçtan uca)
# ---------------------------------------------------------------------------

class FakeChainTransport:
    def __init__(self):
        self.calls = []

    def tcp_connect(self, host, port, timeout=2.0):
        return port == 3100

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        self.calls.append(path)
        if "acquisitions.md" in path:
            return (200, "M&A secret document: acquire@corp.example", {})
        if "whoami" in path:
            return (200, '{"user":{"email":"admin@x.op"}}', {})
        if "secret" in path:
            return (200, '{"admin": true, "note": "internal-only"}', {})
        return (404, "not found", {})


def _setup(tmp_path, transport=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    scope = ScopeContract(json.dumps(SCOPE_DOC))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    ks = KillSwitch(str(tmp_path / "KS"))
    tr = transport or FakeChainTransport()
    proposer = ProbeProposer(scope=scope, killswitch=ks, audit=audit,
                             out_path=str(tmp_path / "probes.jsonl"),
                             transport=tr, rate_per_minute=50)
    ex = ChainExploiter(scope=scope, killswitch=ks, audit=audit,
                        out_path=str(tmp_path / "chains.jsonl"),
                        proposer=proposer, max_depth=3)
    return ex, audit, tr


def test_chain_directory_to_file_leak(tmp_path):
    ex, audit, tr = _setup(tmp_path)
    findings = [{"tip": "directory", "hedef": "127.0.0.1:3100/ftp/",
                 "kanit": "listing directory /ftp/ <a href=acquisitions.md>"}]
    chains = ex.run(findings, "127.0.0.1", 3100)
    # dizin → dosya okundu → içerikte e-posta KANITI → zincir kaydedildi
    assert chains, "dizin bulgusundan zincir türetilmeli"
    kanitli = [c for c in chains if c[-1].get("kanit")]
    assert kanitli
    assert "acquire@corp.example" in kanitli[0][-1]["kanit"]
    # zincir dosyaya düştü
    satirlar = [json.loads(l) for l in open(ex.out_path) if l.strip()]
    assert any(s["tip"] == "exploit_chain" for s in satirlar)
    assert audit.verify_chain()


def test_chain_respects_max_depth(tmp_path):
    ex, _, _ = _setup(tmp_path)
    ex.max_depth = 1
    findings = [{"tip": "error_disclosure",
                 "hedef": "127.0.0.1:3100/rest/x",
                 "kanit": "Unexpected path: /rest/secret/admin-panel"}]
    chains = ex.run(findings, "127.0.0.1", 3100)
    for c in chains:
        assert len(c) <= 1


def test_chain_dangerous_payload_never_runs(tmp_path):
    """Zincir türetse bile yıkıcı öneri proposer'da RED görmeli."""
    ex, audit, tr = _setup(tmp_path)
    # türetme fonksiyonu DROP üretmez; ama manuel kötü bulgu verelim
    findings = [{"tip": "error_disclosure",
                 "hedef": "127.0.0.1:3100/x",
                 "kanit": "Unexpected path: /api?cmd=DROP TABLE users"}]
    ex.run(findings, "127.0.0.1", 3100)
    assert all("DROP" not in c for c in tr.calls)
