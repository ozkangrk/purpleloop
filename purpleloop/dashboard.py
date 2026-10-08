"""PurpleLoop canlı web dashboard'u — stdlib-only (http.server).

Kullanım:
    python3 -m purpleloop.dashboard --run-dir <dizin> [--host 127.0.0.1] [--port 8090]

JSON API:
    /api/summary       → KPI özeti
    /api/findings      → findings.jsonl kayıtları
    /api/validations   → findings-validated.jsonl kayıtları
    /api/proofs        → exploit.jsonl kayıtları
    /api/paths         → attack-paths.jsonl kayıtları
    /api/denies        → audit.jsonl içindeki SCOPE_DENY kayıtları
    /api/audit/verify  → AuditLog.verify_chain() sonucu ({ok, records} | {ok:false, error})
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .audit import AuditLog, AuditTamperError

FINDINGS = "findings.jsonl"
VALIDATIONS = "findings-validated.jsonl"
PROOFS = "exploit.jsonl"
PATHS = "attack-paths.jsonl"
AUDIT = "audit.jsonl"


def _read_jsonl(run_dir: str, name: str) -> list[dict]:
    path = os.path.join(run_dir, name)
    if not os.path.exists(path):
        return []
    rows: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _scope_denies(run_dir: str) -> list[dict]:
    denies = []
    for rec in _read_jsonl(run_dir, AUDIT):
        if rec.get("event") == "SCOPE_DENY":
            denies.append(
                {
                    "host": rec.get("host", ""),
                    "port": rec.get("port", ""),
                    "reason": rec.get("reason", ""),
                    "method": rec.get("method", ""),
                }
            )
    return denies


def _audit_verify(run_dir: str) -> dict:
    path = os.path.join(run_dir, AUDIT)
    if not os.path.exists(path):
        return {"ok": False, "error": "audit.jsonl bulunamadı"}
    records = sum(1 for r in _read_jsonl(run_dir, AUDIT))
    try:
        AuditLog(path).verify_chain()
        return {"ok": True, "records": records}
    except AuditTamperError as e:
        return {"ok": False, "error": str(e), "records": records}


def _summary(run_dir: str) -> dict:
    validations = _read_jsonl(run_dir, VALIDATIONS)
    verdicts = [v.get("verdict", "") for v in validations]
    paths = _read_jsonl(run_dir, PATHS)
    verify = _audit_verify(run_dir)
    return {
        "toplam_bulgu": len(_read_jsonl(run_dir, FINDINGS)),
        "confirmed": verdicts.count("CONFIRMED"),
        "rejected": verdicts.count("REJECTED"),
        "unverified": verdicts.count("UNVERIFIED"),
        "exploited": sum(
            1 for p in _read_jsonl(run_dir, PROOFS) if p.get("sonuc") == "EXPLOITED"
        ),
        "saldiri_zinciri": len(paths),
        "scope_deny": len(_scope_denies(run_dir)),
        "audit_zinciri": {
            "ok": verify.get("ok", False),
            "records": verify.get("records", 0),
            "error": verify.get("error"),
        },
    }


def _api_payload(endpoint: str, run_dir: str) -> dict | list:
    if endpoint == "/api/summary":
        return _summary(run_dir)
    if endpoint == "/api/findings":
        return {"findings": _read_jsonl(run_dir, FINDINGS)}
    if endpoint == "/api/validations":
        return {"validations": _read_jsonl(run_dir, VALIDATIONS)}
    if endpoint == "/api/proofs":
        return {"proofs": _read_jsonl(run_dir, PROOFS)}
    if endpoint == "/api/paths":
        return {"paths": _read_jsonl(run_dir, PATHS)}
    if endpoint == "/api/denies":
        return {"denies": _scope_denies(run_dir)}
    if endpoint == "/api/audit/verify":
        return _audit_verify(run_dir)
    return {}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "PurpleLoopDashboard/1.0"
    run_dir = "."

    def log_message(self, fmt, *args):  # sessiz log
        pass

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: Any, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, _PAGE.encode("utf-8"))
        elif path.startswith("/api/"):
            try:
                self._send_json(_api_payload(path, self.run_dir))
            except Exception as e:  # kaynak bozuksa bile 500 yerine tutarlı JSON
                self._send_json({"error": str(e)}, 500)
        else:
            self._send_json({"error": "bulunamadı"}, 404)


def make_server(run_dir: str, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (DashboardHandler,), {"run_dir": run_dir})
    return ThreadingHTTPServer((host, port), handler)


_PAGE = r"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PurpleLoop Dashboard</title>
<style>
:root{--bg:#0e0b16;--card:#1a1526;--card2:#221a33;--purple:#8b5cf6;--purple2:#a78bfa;
--txt:#e6e1f0;--dim:#8f86a8;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--blue:#3b82f6}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.5 ui-monospace,'JetBrains Mono',monospace;padding:24px}
h1{font-size:20px;color:var(--purple2);margin-bottom:4px}
.sub{color:var(--dim);font-size:12px;margin-bottom:20px}
h2{font-size:15px;color:var(--purple2);margin:28px 0 12px;border-left:3px solid var(--purple);padding-left:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid #2d2445;border-radius:10px;padding:14px}
.kpi .n{font-size:26px;font-weight:700;color:var(--purple2)}
.kpi .l{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700}
.b-green{background:#14351f;color:var(--green)}
.b-red{background:#3a1414;color:var(--red)}
.b-purple{background:#2a1f4d;color:var(--purple2)}
.b-amber{background:#3a2a10;color:var(--amber)}
.b-blue{background:#12253f;color:var(--blue)}
.b-gray{background:#26203a;color:var(--dim)}
.layout{display:grid;grid-template-columns:1fr 2fr;gap:16px;align-items:start}
@media(max-width:900px){.layout{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #2d2445;font-size:12px}
th{background:var(--card2);color:var(--purple2);font-size:11px;text-transform:uppercase}
.kanit{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dim)}
select,button{background:var(--card2);color:var(--txt);border:1px solid var(--purple);border-radius:8px;padding:6px 12px;font:inherit;cursor:pointer}
button:hover{background:var(--purple);color:#fff}
.chain{background:var(--card);border:1px solid #2d2445;border-radius:10px;padding:14px;margin-bottom:12px}
.chain h3{font-size:13px;color:var(--txt);margin-bottom:10px}
.steps{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.step{background:var(--card2);border:1px solid var(--purple);border-radius:8px;padding:6px 10px;font-size:11px}
.step .t{color:var(--purple2);font-weight:700}
.step-arrow{color:var(--purple);font-weight:700}
.item{background:var(--card);border-radius:8px;padding:10px;margin-bottom:8px;font-size:12px}
.item .k{color:var(--dim);font-size:11px}
.donut-legend{font-size:12px;display:flex;gap:12px;flex-wrap:wrap;margin-top:10px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:4px}
</style>
</head>
<body>
<h1>🟣 PurpleLoop Güvenlik Harness Dashboard</h1>
<div class="sub" id="rundir"></div>

<div class="grid" id="kpis"></div>

<h2>Verdict Dağılımı</h2>
<div class="layout">
  <div><svg id="donut" width="220" height="220" viewBox="0 0 42 42"></svg>
       <div class="donut-legend" id="legend"></div></div>
  <div>
    <h2 style="margin-top:0">Bulgular</h2>
    <select id="tipfilt" onchange="render()"></select>
    <table><thead><tr><th>Önem</th><th>Tip</th><th>Hedef</th><th>Kanıt</th><th>Verdict</th></tr></thead>
    <tbody id="ftbody"></tbody></table>
  </div>
</div>

<h2>Saldırı Zincirleri</h2><div id="chains"></div>
<h2>Exploit Kanıtları</h2><div id="proofs"></div>
<h2>Kapsam Dışı Reddedilen İstekler</h2><div id="denies"></div>

<script>
let S={},V=[],F=[],P=[],D=[];
const VCOL={CONFIRMED:'#22c55e',REJECTED:'#ef4444',UNVERIFIED:'#f59e0b',SKIPPED_SCOPE_DENIED:'#8f86a8'};
const SEV={high:'b-red',medium:'b-amber',low:'b-blue'};
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge=(t,cls)=>`<span class="badge ${cls}">${esc(t)}</span>`;

async function j(u){const r=await fetch(u);return r.json()}
async function load(){
  [S,V,F,P,D]=await Promise.all([j('/api/summary'),j('/api/validations').then(d=>d.validations||[]),
    j('/api/findings').then(d=>d.findings||[]),j('/api/proofs').then(d=>d.proofs||[]),
    j('/api/denies').then(d=>d.denies||[])]);
  render();
}
function verdictOf(hedef){
  const v=V.filter(x=>x.hedef===hedef).sort((a,b)=>(b.zaman_damgasi||'').localeCompare(a.zaman_damgasi||''))[0];
  return v?v.verdict:'—';
}
function renderKpis(){
  const a=S.audit_zinciri||{};
  const cells=[
    ['Toplam Bulgu',S.toplam_bulgu],['CONFIRMED',S.confirmed],['REJECTED',S.rejected],
    ['EXPLOITED',S.exploited],['Saldırı Zinciri',S.saldiri_zinciri]];
  let h=cells.map(c=>`<div class="kpi"><div class="n">${esc(c[1])}</div><div class="l">${esc(c[0])}</div></div>`).join('');
  h+=`<div class="kpi"><div class="n" id="auditbadge">${a.ok?badge('GEÇERLİ ✓','b-green'):badge('BOZUK ✗','b-red')}</div><div class="l">Audit Zinciri (${esc(a.records??0)} kayıt)</div></div>`;
  document.getElementById('kpis').innerHTML=h;
}
function renderDonut(){
  const keys=['CONFIRMED','REJECTED','UNVERIFIED','SKIPPED_SCOPE_DENIED'];
  const counts=keys.map(k=>V.filter(v=>v.verdict===k).length);
  const tot=counts.reduce((a,b)=>a+b,0)||1;
  let off=25,h='';
  keys.forEach((k,i)=>{const frac=counts[i]/tot;
    h+=`<circle r="15.915" cx="21" cy="21" fill="none" stroke="${VCOL[k]}" stroke-width="6"
      stroke-dasharray="${frac*100} ${100-frac*100}" stroke-dashoffset="${off}" pathLength="100"></circle>`;
    off-=frac*100;});
  h+=`<text x="21" y="20" text-anchor="middle" font-size="6" fill="#a78bfa">${V.length}</text>
      <text x="21" y="26" text-anchor="middle" font-size="2.6" fill="#8f86a8">VERDICT</text>`;
  document.getElementById('donut').innerHTML=h;
  document.getElementById('legend').innerHTML=keys.map((k,i)=>
    `<span><span class="dot" style="background:${VCOL[k]}"></span>${esc(k)}: <b>${counts[i]}</b></span>`).join('');
}
function renderTable(){
  const sel=document.getElementById('tipfilt');
  const tips=[...new Set(F.map(f=>f.tip))].sort();
  if(sel.dataset.init!=='1'){sel.innerHTML='<option value="">Tüm tipler</option>'+
    tips.map(t=>`<option>${esc(t)}</option>`).join('');sel.dataset.init='1';}
  const flt=sel.value;
  const rows=F.filter(f=>!flt||f.tip===flt).map(f=>{
    const vd=verdictOf(f.hedef);
    const vc=VDICT[vd]||'b-gray';
    const onem=(V.find(v=>v.hedef===f.hedef&&v.verdict===vd)||{}).onem;
    return `<tr><td>${badge(onem||'—',SEV[onem]||'b-gray')}</td><td>${esc(f.tip)}</td>
      <td>${esc(f.hedef)}</td><td class="kanit" title="${esc(f.kanit)}">${esc(f.kanit)}</td>
      <td>${badge(vd,vc)}</td></tr>`;}).join('');
  document.getElementById('ftbody').innerHTML=rows||'<tr><td colspan="5" style="color:#8f86a8">Kayıt yok</td></tr>';
}
const VDICT={CONFIRMED:'b-green',REJECTED:'b-red',UNVERIFIED:'b-amber',SKIPPED_SCOPE_DENIED:'b-gray'};
function renderChains(){
  document.getElementById('chains').innerHTML=(S.paths||P).length===0&&P.length===0?
    '<div class="item">Zincir yok</div>':P.map(p=>
    `<div class="chain"><h3>${badge(p.severity||'low',SEV[p.severity]||'b-blue')} ${esc(p.baslik)}</h3>
     <div class="steps">${(p.adimlar||[]).map((a,i)=>`${i?'<span class="step-arrow">→</span>':''}
       <span class="step"><span class="t">${esc(a.tip)}</span><br>${esc(a.bulgu_hedefi)}</span>`).join('')}</div></div>`).join('');
}
function renderProofs(){
  const C={EXPLOITED:'b-green',NOT_EXPLOITED:'b-gray',FAILED:'b-red',SKIPPED_SCOPE_DENIED:'b-amber'};
  document.getElementById('proofs').innerHTML=P.map(p=>
    `<div class="item">${badge(p.sonuc,C[p.sonuc]||'b-gray')} <b>${esc(p.eylem)}</b><br>
     <span class="k">Bulgu:</span> ${esc(p.bulgu)}<br><span class="k">Kanıt:</span> ${esc(p.kanit_metni)}</div>`).join('')
     ||'<div class="item">Kanıt yok</div>';
}
function renderDenies(){
  document.getElementById('denies').innerHTML=D.map(d=>
    `<div class="item">${badge('SCOPE_DENY','b-red')} <b>${esc(d.host)}:${esc(d.port)}</b> — ${esc(d.reason)}</div>`).join('')
     ||'<div class="item">Kapsam dışı reddedilen istek yok</div>';
}
async function verifyChain(){
  const r=await j('/api/audit/verify');
  const el=document.getElementById('auditbadge');
  el.innerHTML=r.ok?badge('GEÇERLİ ✓','b-green'):badge('BOZUK ✗','b-red');
  if(!r.ok&&r.error)el.title=r.error;
}
function render(){renderKpis();renderDonut();renderTable();renderChains();renderProofs();renderDenies();}
document.addEventListener('DOMContentLoaded',()=>{load();});
</script>
<div style="margin-top:24px"><button onclick="verifyChain()">Zinciri doğrula</button></div>
</body></html>
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PurpleLoop canlı dashboard")
    ap.add_argument("--run-dir", required=True, help="run dizini (JSONL dosyaları)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args(argv)

    if not os.path.isdir(args.run_dir):
        print(f"HATA: run dizini yok: {args.run_dir}", file=sys.stderr)
        return 2

    httpd = make_server(args.run_dir, args.host, args.port)
    host, port = httpd.server_address[:2]
    print(f"PurpleLoop dashboard: http://{host}:{port} (run-dir: {args.run_dir})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
