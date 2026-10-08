"""Hafta-2: recon (keşif) ajanı — tarama orkestratörü.

KURALLAR (fail-closed):
  * HER tarama isteği scope.check_request() üzerinden geçer; REDDET => adım atlanır
    ve audit'e SCOPE_DENY kaydı yazılır.
  * Kill-switch her aşama başında kontrol edilir; aktifse ajan durur.
  * Her bulgu Finding yapısında findings çıktısına VE audit zincirine yazılır.

Kullanım:
  python3 -m purpleloop.recon --scope scope.json --out findings.jsonl
"""
from __future__ import annotations

import argparse
import datetime as _dt
import http.client
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, asdict
from typing import Optional, Protocol
from urllib.parse import urlunsplit
import threading

from .audit import AuditLog
from .killswitch import KillSwitch
from .scope import ScopeContract

_emit_lock = threading.Lock()  # paralel taramada bulgu/deny yazımını serialize eder

# --------------------------------------------------------------------------
# Sabit kelime listeleri (lab içi; harici CT/DNS servisi kullanılmaz)
# --------------------------------------------------------------------------

SUBDOMAIN_CANDIDATES = [
    "www", "api", "dev", "test", "staging", "backup", "s3", "minio",
    "admin", "portal", "git", "jenkins", "mail",
]

PORT_CANDIDATES = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
                   587, 993, 995, 1080, 1433, 1521, 2049, 2375, 2376, 3000, 3128,
                   3306, 3389, 4443, 5000, 5432, 5672, 5900, 5984, 6379, 6443,
                   7001, 8000, 8080, 8081, 8443, 8888, 9000, 9001, 9010, 9011,
                   9200, 9300, 9418, 10000, 11211, 15672, 27017, 50000]

DIR_CANDIDATES = [
    "backup", "backup/", "backup/.env", "backup/.aws-credentials", "backup/secrets-old.txt",
    ".env", ".env.local", ".env.production", ".git/HEAD", ".git/config", ".htaccess",
    ".htpasswd", ".DS_Store", "admin", "administrator", "api", "assets", "auth",
    "aws", "bin", "cgi-bin", "composer.json", "config", "config.php", "config.json",
    "console", "dashboard", "debug", "dev", "docker-compose.yml", "docs", "dump",
    "etc", "graphql", "health", "home", "id_rsa", "internal", "jenkins", "kernel",
    "loadbalancer", "login", "logs", "mail", "metrics", "old", "phpinfo.php",
    "phpmyadmin", "private", "public", "queue", "root", "s3", "secret", "secrets",
    "server-status", "server-info", "setup", "site", "sql", "ssh", "staging",
    "swagger", "swagger.json", "temp", "test", "tmp", "token", "upload", "uploads",
    "var", "vendor", "web", "wp-admin", "wp-config.php", "wsdl",
    ".aws-credentials", ".aws/config", ".ssh/id_rsa", ".docker/config.json",
    ".gitlab-ci.yml", "Jenkinsfile", "kibana", "elasticsearch", "solr",
    "actuator", "actuator/health", "actuator/env", "actuator/heapdump",
    "trace", "jmx-console", "web-console", "manager/html", "status",
]

BUCKET_CANDIDATES = [
    "public", "public-backup", "backups", "backup", "data", "www", "assets", "logs",
    "media", "static", "files", "documents", "share", "internal", "test", "dev",
    "staging", "prod", "production", "database", "dumps", "exports", "reports",
    "user-data", "credentials", "secrets", "config", "deploy", "terraform",
]

# --------------------------------------------------------------------------
# Parola / gizli anahtar regex'leri (FP-düşük: katı desenler + filtre)
# --------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*(['\"]?)([A-Za-z0-9/+=-]{12,})\1")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("slack_token", re.compile(r"xox[bposa]-[A-Za-z0-9-]{10,}")),
    ("telegram_bot", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}\b")),
    ("google_api", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("stripe_key", re.compile(r"(?i)sk_live_[0-9a-zA-Z]{20,}")),
    ("sendgrid", re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}")),
    ("db_url", re.compile(
        r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s\"']+:[^\s\"']+@[^\s\"']+")),
    ("basic_auth_url", re.compile(r"(?i)https?://[^\s\"'/]+:[^\s\"'/]+@[^\s\"']+")),
    ("api_key_assignment", re.compile(
        r"(?im)(?:^|[^A-Za-z0-9])(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*(['\"])([A-Za-z0-9_\-./+=]{20,})\2")),
    ("password_assignment", re.compile(
        r"(?im)(?:^|[^A-Za-z0-9])(password|passwd|pwd|secret|token|root_password)\s*[:=]\s*(['\"]?)(\S{6,})\2")),
]

_REDACTED_VALUES = {"***", "changeme", "<password>", "redacted", "xxxxxx", "example", "placeholder", "none", "null", "true", "false"}


def scan_secrets(text: str) -> list:
    """Metindeki parola/anahtar adaylarını döndürür: [(tip, kanıt)]."""
    found = []
    for tip, rx in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            if tip == "password_assignment":
                val = m.group(3).strip().strip("'\"")
                if val.lower() in _REDACTED_VALUES:
                    continue
                # değer tamamen yıldız/nokta ise maskelenmiş say
                if set(val) <= {"*", "•", ".", "-"}:
                    continue
                found.append((tip, m.group(0)[:120]))
            else:
                found.append((tip, m.group(0)[:120]))
    # dedupe
    seen, out = set(), []
    for item in found:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# --------------------------------------------------------------------------
# Finding yapısı
# --------------------------------------------------------------------------

@dataclass
class Finding:
    tip: str            # bulgu tipi: subdomain|open_port|directory|bucket|secret
    hedef: str          # scope içindeki IP/domain(:port)
    kanit: str          # ham kanıt (banner, response snippet)
    zaman_damgasi: str  # ISO-8601 UTC
    kapsam_referansi: str  # scope sözleşmesindeki eşleşen hedef

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)


# --------------------------------------------------------------------------
# Taşıma katmanı (testlerde sahte impl enjekte edilir)
# --------------------------------------------------------------------------

class Transport(Protocol):
    def tcp_connect(self, host: str, port: int, timeout: float) -> bool: ...
    def http_get(self, host: str, port: int, path: str, timeout: float, use_tls: bool = False): ...


class RealTransport:
    def tcp_connect(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def http_get(self, host: str, port: int, path: str, timeout: float = 4.0, use_tls: bool = False):
        """Return (status:int, body:str, headers:dict) or None on failure."""
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path if path.startswith("/") else "/" + path)
            resp = conn.getresponse()
            body = resp.read(65536).decode("utf-8", errors="replace")
            status = resp.status
            headers = {k.lower(): v for k, v in resp.getheaders()}
            conn.close()
            return status, body, headers
        except OSError:
            return None


# Geriye dönük uyumluluk: eski 3'lü (status, body, banner-str) yerine artık
# (status, body, headers-dict) dönüyoruz. Test fake'leri banner str döndürür;
# bunu dict'e normalize eden sarmalayıcı:
def _norm_resp(r):
    if r is None:
        return None
    status, body, third = r
    if isinstance(third, str):
        return (status, body, {"server": third})
    return (status, body, third)


# --------------------------------------------------------------------------
# HTTP güvenlik başlığı denetimi (yeni bulgu tipi: missing_header)
# --------------------------------------------------------------------------

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS eksik — TLS zorlama yok",
    "content-security-policy": "CSP eksik — XSS riski",
    "x-content-type-options": "X-Content-Type-Options eksik — MIME sniffing",
    "x-frame-options": "X-Frame-Options eksik — clickjacking riski",
}


def audit_security_headers(headers: dict) -> list:
    """Eksik güvenlik başlıklarını döndürür: [(başlık, açıklama)]."""
    keys = {k.lower() for k in headers}
    return [(h, desc) for h, desc in _SECURITY_HEADERS.items() if h not in keys]


# --------------------------------------------------------------------------
# Recon ajanı
# --------------------------------------------------------------------------

class ReconAgent:
    def __init__(
        self,
        *,
        scope: ScopeContract,
        killswitch: KillSwitch,
        audit: AuditLog,
        out_path: str,
        transport: Optional[Transport] = None,
        subdomains: Optional[list] = None,
        ports: Optional[list] = None,
        dirs: Optional[list] = None,
        buckets: Optional[list] = None,
        max_workers: int = 32,
    ):
        self.scope = scope
        self.killswitch = killswitch
        self.audit = audit
        self.out_path = out_path
        self.tx = transport or RealTransport()
        self.subdomain_candidates = subdomains if subdomains is not None else SUBDOMAIN_CANDIDATES
        self.port_candidates = ports if ports is not None else PORT_CANDIDATES
        self.dir_candidates = dirs if dirs is not None else DIR_CANDIDATES
        self.bucket_candidates = buckets if buckets is not None else BUCKET_CANDIDATES
        self.max_workers = max_workers
        self.findings: list = []
        self.denied: list = []   # reddedilen istekler (test izleme + kanıt)
        self._stopped = False

    # ---- gate ----

    def _gate(self, host: str, port: int, method: str = "GET", now=None) -> bool:
        allowed, reason = self.scope.check_request(host=host, port=port, method=method, now=now)
        if not allowed:
            with _emit_lock:
                self.audit.append("SCOPE_DENY", host=host, port=port, method=method, reason=reason)
                self.denied.append({"host": host, "port": port, "reason": reason})
            return False
        return True

    def _halt_check(self, stage: str) -> bool:
        if self.killswitch.is_active():
            self.audit.append("KILLSWITCH_HALT", stage=stage)
            self._stopped = True
            return True
        return False

    def _scope_ref(self, host: str) -> str:
        h = host.lower().rstrip(".")
        for t in self.scope.targets:
            if t == host or t.lower() == h:
                return t
        # CIDR / wildcard eşleşmesi
        import ipaddress
        try:
            addr = ipaddress.ip_address(host)
            for t in self.scope.targets:
                if "/" in t:
                    try:
                        if addr in ipaddress.ip_network(t, strict=False):
                            return t
                    except ValueError:
                        continue
        except ValueError:
            for t in self.scope.targets:
                if t.startswith("*.") and h.endswith(t[1:].lower()):
                    return t
        return self.scope.targets[0]

    def _emit(self, tip: str, hedef: str, kanit: str, scope_ref: str) -> None:
        f = Finding(
            tip=tip,
            hedef=hedef,
            kanit=kanit[:500],
            zaman_damgasi=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            kapsam_referansi=scope_ref,
        )
        self.findings.append(f)
        with open(self.out_path, "a", encoding="utf-8") as fh:
            fh.write(f.to_json() + "\n")
        self.audit.append(
            "FINDING",
            tip=f.tip,
            hedef=f.hedef,
            kanit=f.kanit,
            kapsam=f.kapsam_referansi,
            zaman=f.zaman_damgasi,
        )

    # ---- aşamalar ----

    def stage_subdomains(self, base_domains: list) -> None:
        """Alt alan adı keşfi: sabit liste + DNS çözümlemesi (lab içi)."""
        if self._halt_check("subdomains"):
            return
        for base in base_domains:
            for sub in self.subdomain_candidates:
                fqdn = f"{sub}.{base}"
                if not self._gate(fqdn, 443, "HEAD"):
                    continue  # kapsam dışı alt alan denenmez
                try:
                    ip = socket.gethostbyname(fqdn)
                except OSError:
                    continue
                self._emit("subdomain", fqdn, f"resolved to {ip}", self._scope_ref(base))

    def stage_ports(self, hosts: list) -> None:
        """Port taraması: aday portların TAMAMI scope kapısından geçer.
        Paralel: iş parçacığı havuzu, kilitli emit + deny kaydı."""
        if self._halt_check("ports"):
            return
        jobs = []
        for host in hosts:
            for port in self.port_candidates:
                jobs.append((host, port))
        with _emit_lock:
            pass  # emit kilidi modül düzeyinde tanımlı
        self._run_parallel(self._probe_port, jobs)

    def _probe_port(self, host: str, port: int) -> None:
        if not self._gate(host, port, "GET"):
            return
        if self.tx.tcp_connect(host, port):
            self._emit_safe("open_port", f"{host}:{port}", "TCP connect succeeded", self._scope_ref(host))

    def _run_parallel(self, fn, jobs: list) -> None:
        if self.max_workers and self.max_workers > 1 and len(jobs) > 8:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futs = [ex.submit(fn, *j) for j in jobs]
                for f in as_completed(futs):
                    exc = f.exception()
                    if exc:  # tek iş hatası tüm taramayı durdurmaz, loglanır
                        with _emit_lock:
                            self.audit.append("PROBE_ERROR", error=str(exc)[:200])
        else:
            for j in jobs:
                if self._stopped:
                    break
                fn(*j)

    def _emit_safe(self, tip: str, hedef: str, kanit: str, scope_ref: str) -> None:
        with _emit_lock:
            self._emit(tip, hedef, kanit, scope_ref)

    def stage_dirs(self, endpoints: list) -> None:
        """Dizin keşfi: yaygın isim listesi (HTTP GET). Paralel + header denetimi."""
        if self._halt_check("dirs"):
            return
        jobs = []
        for host, port in endpoints:
            for d in self.dir_candidates:
                jobs.append((host, port, d))
        self._run_parallel(self._probe_dir, jobs)

    def _probe_dir(self, host: str, port: int, d: str) -> None:
        if not self._gate(host, port, "GET"):
            return
        r = _norm_resp(self.tx.http_get(host, port, "/" + d))
        if r is None:
            return
        status, body, headers = r
        is_xml = body.lstrip().startswith("<?xml")
        if status == 200 and not is_xml and ("<html" not in body[:200].lower() or "index of /" in body[:400].lower() or d.endswith((".env", ".aws-credentials", "secrets-old.txt"))):
            self._emit_safe("directory", f"{host}:{port}/{d}", f"HTTP {status} len={len(body)}", self._scope_ref(host))
            # güvenlik başlığı denetimi (ilk kez 200 alan yolda bir kez)
            for h, desc in audit_security_headers(headers):
                self._emit_safe("missing_header", f"{host}:{port}", f"{h}: {desc}", self._scope_ref(host))
        for tip, kanit in scan_secrets(body):
            self._emit_safe("secret", f"{host}:{port}/{d}", kanit, self._scope_ref(host))

    def stage_buckets(self, endpoints: list) -> None:
        """S3/bucket keşfi: yaygın bucket adları, anonim erişim testi."""
        if self._halt_check("buckets"):
            return
        for host, port in endpoints:
            # S3 API yaşıyor mu (reddedilen anonim istek bile servisi kanıtlar)
            if not self._gate(host, port, "GET"):
                continue
            r = self.tx.http_get(host, port, "/")
            if r is not None and r[0] in (200, 403) and r[1].lstrip().startswith("<?xml"):
                self._emit("bucket_service", f"{host}:{port}", f"S3-like API exposed (HTTP {r[0]})", self._scope_ref(host))
            for b in self.bucket_candidates:
                if not self._gate(host, port, "GET"):
                    continue
                rb = self.tx.http_get(host, port, f"/{b}/")
                if rb is None:
                    continue
                status, body, banner = rb
                if status == 200 and body.lstrip().startswith("<?xml"):
                    self._emit("open_bucket", f"{host}:{port}/{b}/", f"anonymous list allowed (HTTP 200, len={len(body)})", self._scope_ref(host))
                    for tip, kanit in scan_secrets(body):
                        self._emit("secret", f"{host}:{port}/{b}/", kanit, self._scope_ref(host))
                    # bucket listesinde geçen nesneleri indir, içerik tara (safe: GET only)
                    for key in re.findall(r"<Key>([^<]+)</Key>", body)[:10]:
                        if not self._gate(host, port, "GET"):
                            continue
                        robj = self.tx.http_get(host, port, f"/{b}/{key}")
                        if robj is None:
                            continue
                        ostatus, obody, _ = robj
                        if ostatus == 200:
                            self._emit("directory", f"{host}:{port}/{b}/{key}", f"object readable (HTTP 200, len={len(obody)})", self._scope_ref(host))
                            for otip, okanit in scan_secrets(obody):
                                self._emit("secret", f"{host}:{port}/{b}/{key}", okanit, self._scope_ref(host))

    def run(self, base_domains: list, hosts: list, endpoints: list) -> list:
        self.audit.append("RECON_START",
                          targets=list(self.scope.targets),
                          out=self.out_path)
        self.stage_subdomains(base_domains)
        self.stage_ports(hosts)
        self.stage_dirs(endpoints)
        self.stage_buckets(endpoints)
        self.audit.append("RECON_END", findings=len(self.findings), denied=len(self.denied), stopped=self._stopped)
        return self.findings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="purpleloop.recon", description="PurpleLoop Hafta-2 recon agent")
    ap.add_argument("--scope", required=True, help="scope sözleşme JSON yolu")
    ap.add_argument("--out", required=True, help="bulgu çıktısı (findings.jsonl)")
    ap.add_argument("--audit", default="audit.jsonl", help="audit zinciri dosyası")
    ap.add_argument("--killswitch", default="KILLSWITCH", help="kill-switch dosya yolu")
    ap.add_argument("--domains", default="", help="alt alan keşfi taban alan adları (virgülle)")
    ap.add_argument("--hosts", default="127.0.0.1", help="port taraması hostları (virgülle)")
    ap.add_argument("--endpoints", default="127.0.0.1:8081,127.0.0.1:9010",
                    help="HTTP endpoint'ler host:port (virgülle)")
    args = ap.parse_args(argv)

    try:
        with open(args.scope, "r", encoding="utf-8") as f:
            scope = ScopeContract(f.read())
    except Exception as e:
        print(f"FAIL-CLOSED: scope yüklenemedi: {e}", file=sys.stderr)
        return 2

    ks = KillSwitch(args.killswitch)
    if ks.is_active():
        print("FAIL-CLOSED: kill-switch aktif, ajan başlatılmıyor.", file=sys.stderr)
        return 3

    audit = AuditLog(args.audit)
    open(args.out, "w").close()  # çıktıyı sıfırla

    endpoints = []
    for ep in filter(None, args.endpoints.split(",")):
        host, _, port = ep.rpartition(":")
        endpoints.append((host, int(port)))

    agent = ReconAgent(scope=scope, killswitch=ks, audit=audit, out_path=args.out)
    findings = agent.run(
        base_domains=[d for d in args.domains.split(",") if d],
        hosts=[h for h in args.hosts.split(",") if h],
        endpoints=endpoints,
    )
    ok = audit.verify_chain()
    print(json.dumps({
        "findings": len(findings),
        "denied": len(agent.denied),
        "audit_chain_valid": ok,
        "out": args.out,
    }, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
