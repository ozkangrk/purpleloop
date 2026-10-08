"""Ürün deneyimi: init + demo — ilk 5 dakikada değer.

init : çalışma dizini kurar (scope.json şablonu, .gitignore, KILLSWITCH
       yolu, README başlangıcı). İnteraktif değil — her şey bayrakla.
demo : TAM ÜRÜN TURU tek komutla:
       1) izole demo lab ayağa kaldır (docker, zararsız zayıf uygulama)
       2) scope sözleşmesi yaz (yalnız o lab'a izin)
       3) recon → pentest → vektör → bounty zincirini koştur
       4) executive kapak raporu + SARIF üret
       5) her şeyi ~/purpleloop-demo/ altına koy, özet bas
       6) temizlik (konteyner kaldır)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

DEMO_PORT = 3611
DEMO_DIR = os.path.expanduser("~/purpleloop-demo")

_SCOPE_TEMPLATE = textwrap.dedent("""\
    {
      "targets": ["127.0.0.1"],
      "ports": [8080],
      "methods": ["GET", "HEAD"]
    }
    """)

_SCOPE_README = ("# scope.json — PurpleLoop kapsam sözleşmesi\n"
                 "# Kural: burada OLMAYAN her hedef REDDEDİLİR (fail-closed).\n"
                 "# targets: izinli host/CIDR/wildcard listesi\n"
                 "# ports: izinli portlar; methods: izinli HTTP metodları\n")

_DEMO_APP = textwrap.dedent("""\
    import http.server, json

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            p = self.path
            if p == "/rest/user/whoami":
                self._send(200, json.dumps({"user": {"id": 7,
                       "email": "victim@demo.local", "card": "4111-1111-1111"}}))
            elif p.startswith("/rest/user/") and p.count("/") >= 3:
                self._send(200, json.dumps({"user": {"id": 2,
                       "email": "colleague@demo.local", "role": "finance"}}))
            elif p.startswith("/admin"):
                self._send(200, json.dumps({"admin": True, "secrets": ["payroll", "keys"]}))
            elif "q=" in p:
                from urllib.parse import unquote
                q = unquote(p.split("q=", 1)[1])
                self._send(200, f"<html>results for {q}</html>", "text/html")
            elif "../" in p:
                self._send(200, "root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon")
            elif "redirect" in p and "to=" in p:
                self.send_response(302)
                self.send_header("Location", "https://attacker.example/steal")
                self.send_header("Content-Length", "0"); self.end_headers()
            else:
                self._send(404, "not found")

        def _send(self, code, body, ctype="application/json"):
            d = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(d)))
            self.end_headers(); self.wfile.write(d)

        def log_message(self, *a): pass

    http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
    """)


def _sh(cmd: list, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def cmd_init(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="purpleloop init",
                                 description="Çalışma dizini kur (scope şablonu vb.)")
    ap.add_argument("--dir", default=".")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    d = os.path.abspath(args.dir)
    os.makedirs(d, exist_ok=True)
    scope_p = os.path.join(d, "scope.json")
    if os.path.exists(scope_p) and not args.force:
        print(f"scope.json zaten var ({scope_p}) — --force ile ezilir")
        return 1
    with open(scope_p, "w", encoding="utf-8") as f:
        f.write(_SCOPE_TEMPLATE)
    with open(os.path.join(d, "SCOPE-OKU.md"), "w", encoding="utf-8") as f:
        f.write(_SCOPE_README)
    gi = os.path.join(d, ".gitignore")
    if not os.path.exists(gi):
        with open(gi, "w") as f:
            f.write("audit.jsonl\nfindings*.jsonl\n*.sarif\nKILLSWITCH\n")
    print(f" kuruldu: {scope_p}")
    print(" sonraki adım: hedef/port/method düzenle, sonra:")
    print("   purpleloop scan --scope scope.json --hosts <hedef> \\")
    print("       --endpoints <hedef:port> --out-dir run1")
    return 0


def cmd_demo(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="purpleloop.demo",
                                 description="Tek komutla tam ürün turu (izole demo lab)")
    ap.add_argument("--keep", action="store_true",
                    help="demo lab'ı açık bırak (temizlik yapma)")
    ap.add_argument("--dir", default=DEMO_DIR)
    args = ap.parse_args(argv)

    os.makedirs(args.dir, exist_ok=True)
    app_p = os.path.join(args.dir, "demo_app.py")
    with open(app_p, "w") as f:
        f.write(_DEMO_APP)
    scope_p = os.path.join(args.dir, "scope.json")
    with open(scope_p, "w") as f:
        f.write(json.dumps({"targets": ["127.0.0.1"],
                            "ports": [DEMO_PORT],
                            "methods": ["GET", "HEAD"]}))

    print(f"[demo] izole zayıf uygulama başlatılıyor (127.0.0.1:{DEMO_PORT})...")
    _sh(["docker", "rm", "-f", "purpleloop-demo"])
    r = _sh(["docker", "run", "-d", "--rm", "--name", "purpleloop-demo",
             "-p", f"{DEMO_PORT}:8000", "-v", f"{app_p}:/app.py",
             "python:3.12-alpine", "python3", "/app.py"], timeout=300)
    if r.returncode != 0:
        print(f"[demo] docker hatası: {r.stderr[:200]}")
        return 2

    import time
    import urllib.request
    ready = False
    for _ in range(20):
        time.sleep(1)
        try:
            # readiness: bağlantı KURULABİLİR olmalı (404 bile sunucunun
            # ayakta olduğunun kanıtı — uygulama / için içerik vermez)
            urllib.request.urlopen(f"http://127.0.0.1:{DEMO_PORT}/", timeout=2)
            ready = True
            break
        except urllib.error.HTTPError:
            ready = True   # HTTP yanıtı geldi = ayakta
            break
        except Exception:
            continue
    if not ready:
        print("[demo] uygulama açılmadı")
        return 2

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ, PYTHONPATH=repo)
    ks = os.path.join(args.dir, "KILLSWITCH")
    ep = f"127.0.0.1:{DEMO_PORT}"

    def run(mod_and_args, label, out_json=True):
        cmd = [sys.executable, "-m", *mod_and_args]
        rr = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=600, env=env, cwd=args.dir)
        tail = (rr.stdout or "").strip().splitlines()
        print(f"[demo] {label}: {'OK' if rr.returncode == 0 else 'rc=' + str(rr.returncode)}")
        return tail[-1] if tail else ""

    print("[demo] 1/5 kapsam kontrolü (kapsam dışı hedef reddi)...")
    from purpleloop.scope import ScopeContract
    scope = ScopeContract(open(scope_p).read())
    ok, why = scope.check_request(host="203.0.113.99", port=80, method="GET")
    print(f"[demo]    tuzak hedef 203.0.113.99 → {'REDDEDİLDİ (' + why + ')' if not ok else 'HATA: izin verildi!'}")

    print("[demo] 2/5 recon taraması...")
    run(["purpleloop.harness", "--scope", scope_p, "--out-dir",
         os.path.join(args.dir, "run"), "--hosts", "127.0.0.1",
         "--endpoints", ep, "--pipeline", "recon,validator"], "recon")

    print("[demo] 3/5 sızma denemeleri (pentest + vektörler)...")
    run(["purpleloop.pentest", "--scope", scope_p, "--targets", ep,
         "--out-dir", os.path.join(args.dir, "pentest"),
         "--killswitch", ks], "pentest")
    # vektör kütüphanesi: CLI değil kütüphane — aynı süreçte koştur
    from purpleloop.vectors import VectorLibrary
    from purpleloop.audit import AuditLog
    from purpleloop.killswitch import KillSwitch
    vdir = os.path.join(args.dir, "vectors")
    os.makedirs(vdir, exist_ok=True)
    _vscope = ScopeContract(open(scope_p).read())
    _vaudit = AuditLog(os.path.join(vdir, "audit.jsonl"))
    _vks = KillSwitch(ks)
    _vlib = VectorLibrary(scope=_vscope, killswitch=_vks, audit=_vaudit,
                          out_path=os.path.join(vdir, "vector-findings.jsonl"))
    _vfs = _vlib.run([("127.0.0.1", DEMO_PORT)])
    print(f"[demo] vektörler: {len(_vfs)} bulgu "
          f"({', '.join(sorted({f['tip'] for f in _vfs})) or 'yok'})")

    print("[demo] 4/5 SARIF + policy gate...")
    allf = os.path.join(args.dir, "run", "findings.jsonl")
    for extra in (os.path.join(args.dir, "pentest", "pentest-findings.jsonl"),
                  os.path.join(args.dir, "vectors", "vector-findings.jsonl")):
        if os.path.exists(extra):
            with open(allf, "a") as dst, open(extra) as src:
                dst.write(src.read())
    run(["purpleloop.platform_layer", "sarif", "--findings", allf,
         "--out", os.path.join(args.dir, "purpleloop.sarif")], "SARIF")
    gate = run(["purpleloop.platform_layer", "gate", "--findings", allf], "gate")

    print("[demo] 5/5 temizlik...")
    if not args.keep:
        _sh(["docker", "rm", "-f", "purpleloop-demo"])

    print(f"""
[demo] ═══ TAMAMLANDI — çıktılar: {args.dir} ═══
  run/findings.jsonl        — tarama bulguları
  pentest/ vectors/          — sızma denemeleri
  purpleloop.sarif           — CI'a hazır SARIF
  gate kararı: {gate[:120]}
Gerçek hedefte: purpleloop init → scope düzenle → purpleloop scan ...
""")
    return 0


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="purpleloop.product",
                                 description="Ürün deneyimi: init / demo")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("demo")
    args, rest = ap.parse_known_args(argv)
    if args.cmd == "init":
        return cmd_init(rest or [])
    return cmd_demo(rest or [])


if __name__ == "__main__":
    raise SystemExit(main())
