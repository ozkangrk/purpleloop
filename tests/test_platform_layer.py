"""Platform katmanı testleri: SARIF export + policy gate + OSV zenginleştirme.

SARIF 2.1.0: CI güvenlik kapılarının ortak arayüzü (OWASP DevSecOps
önerisi). Policy gate: eşik aşılırsa CI exit kodu. OSV: sızan
package.json bağımlılıklarından bilinen CVE çıkarma.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from purpleloop.platform_layer import (  # noqa: E402
    to_sarif, PolicyGate, parse_lockfile_deps, OSVClient,
)

SAMPLE_FINDINGS = [
    {"tip": "sqli_data_leak", "hedef": "127.0.0.1:3100/rest/products/search",
     "kanit": "UNION(users) — email sızıntısı: admin@x.op",
     "zaman_damgasi": "2026-10-08T12:00:00+00:00", "kapsam_referansi": "127.0.0.1"},
    {"tip": "directory", "hedef": "127.0.0.1:3100/ftp/",
     "kanit": "HTTP 200 len=11024 | dizin listeleme açık",
     "zaman_damgasi": "2026-10-08T12:00:00+00:00", "kapsam_referansi": "127.0.0.1"},
    {"tip": "missing_header", "hedef": "127.0.0.1:3100",
     "kanit": "content-security-policy: CSP eksik — XSS riski",
     "zaman_damgasi": "2026-10-08T12:00:00+00:00", "kapsam_referansi": "127.0.0.1"},
]

# ---------------------------------------------------------------------------
# 1) SARIF 2.1.0 export
# ---------------------------------------------------------------------------

def test_sarif_structure():
    sarif = to_sarif(SAMPLE_FINDINGS, tool_version="1.6.0")
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "PurpleLoop"
    assert len(run["results"]) == 3
    # her sonuç en az ruleId, level, message, location içermeli
    for res in run["results"]:
        assert res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        assert res["locations"][0]["physicalLocation"]["logicalLocations"][0]["name"]


def test_sarif_severity_mapping():
    sarif = to_sarif(SAMPLE_FINDINGS)
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["sqli_data_leak"] == "error"       # kritik: veri sızıntısı
    assert levels["directory"] == "warning"
    assert levels["missing_header"] == "note"


def test_sarif_security_severity_score():
    """OWASP kapı deseni: rule properties.security-severity (0-10 CVSS benzeri)."""
    sarif = to_sarif(SAMPLE_FINDINGS)
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "security-severity" in rules["sqli_data_leak"]["properties"]
    assert float(rules["sqli_data_leak"]["properties"]["security-severity"]) >= 9.0
    assert float(rules["directory"]["properties"]["security-severity"]) < 9.0


# ---------------------------------------------------------------------------
# 2) Policy gate (CI exit kararı)
# ---------------------------------------------------------------------------

def test_policy_gate_pass_when_clean():
    g = PolicyGate(max_error=0, max_warning=10)
    karar = g.evaluate([])
    assert karar["durum"] == "PASS"


def test_policy_gate_fail_on_error():
    g = PolicyGate(max_error=0, max_warning=10)
    karar = g.evaluate(SAMPLE_FINDINGS)  # 1 error (sqli) + 1 warning + 1 note
    assert karar["durum"] == "FAIL"
    assert karar["error"] == 1
    assert karar["warning"] == 1


def test_policy_gate_baypas_kaydi():
    """Baypas biletli kapı: ticket olmadan FAIL kalır, kayda geçer."""
    g = PolicyGate(max_error=0, max_warning=10)
    k1 = g.evaluate(SAMPLE_FINDINGS, bypass_ticket="")
    assert k1["durum"] == "FAIL"
    k2 = g.evaluate(SAMPLE_FINDINGS, bypass_ticket="SEC-123")
    assert k2["durum"] == "FAIL_WITH_BYPASS"  # bilet kaydı ama yine de flag'li


# ---------------------------------------------------------------------------
# 3) Bağımlılık parse + OSV zenginleştirme
# ---------------------------------------------------------------------------

def test_parse_lockfile_deps_package_json():
    pkg = {"dependencies": {"body-parser": "~1.18.2", "marsdb": "^0.3.0"},
           "devDependencies": {"jest": "22.0.0"}}
    deps = parse_lockfile_deps(json.dumps(pkg))
    assert ("body-parser", "1.18.2") in [(n, v) for n, v in deps]
    assert ("jest", "22.0.0") in [(n, v) for n, v in deps]


def test_parse_lockfile_deps_requirements_txt():
    txt = "requests==2.19.1\nflask>=1.0\n# yorum\n"
    deps = parse_lockfile_deps(txt)
    # == kesin sürüm yakalanır; >= belirsiz olduğundan bilinerek atlanır
    assert ("requests", "2.19.1") in deps
    assert all(n != "flask" for n, _ in deps)


def test_osv_client_query_batch_shape():
    """OSVClient sorgu gövdesi querybatch sözleşmesine uymalı."""
    c = OSVClient()
    body = c.build_querybatch([("body-parser", "1.18.2"), ("jest", "22.0.0")])
    assert body["queries"][0]["package"]["name"] == "body-parser"
    assert body["queries"][0]["package"]["ecosystem"] == "npm"
    assert body["queries"][0]["version"] == "1.18.2"


@pytest.mark.anyio
async def test_osv_client_live_query():
    """Canlı OSV API (internet) — sızan eski body-parser CVE'sini bulmalı."""
    c = OSVClient()
    vulns = await c.query([("body-parser", "1.18.2")])
    assert vulns, "body-parser 1.18.2 için bilinen zafiyet dönmeli"
    ids = [v.get("id", "") for v in vulns]
    assert any(i.startswith("GHSA") or i.startswith("CVE") for i in ids)
