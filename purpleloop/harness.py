"""Hafta-4: Security Harness — ajan kaydı + pipeline orkestrasyon + plugin yükleyici.

MİMARİ:
  PurpleLoop = GÜVENLİK HARNESS'i (kontrol düzlemi + koşu iskeleti).
  Ajanlar (recon, validator, report, üçüncü parti plugin'ler) değiştirilebilir
  parçalardır. Harness ajanlara şunları ZORUNLU kılar:
    - kill-switch kontrolü her ajan öncesi (fail-closed)
    - AGENT_START / AGENT_END / AGENT_ERROR audit kayıtları
    - ajan çökmesi => pipeline durur (fail-closed), yarım koşu audit'te kanıtlı
    - üçüncü taraf ajanlar ağ erişimini YALNIZCA ScopeGatedTransport üzerinden
      alır: her tcp/http çağrısı scope kapısından geçer, REDDET audit'e yazılır

Kullanım:
  python3 -m purpleloop.harness --scope scope.json --out-dir run1 \
      --pipeline recon,validator,report --hosts 127.0.0.1 \
      --endpoints 127.0.0.1:8081,127.0.0.1:9010 \
      [--plugin mypkg.agents:MyAgent]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from .audit import AuditLog
from .killswitch import KillSwitch
from .recon import RealTransport, ReconAgent
from .scope import ScopeContract
from .validator import ValidatorAgent


class HarnessError(Exception):
    """Fail-closed harness ihlali."""


# --------------------------------------------------------------------------
# Context — ajanların gördüğü her şey
# --------------------------------------------------------------------------

@dataclass
class HarnessContext:
    scope: ScopeContract
    killswitch: KillSwitch
    audit: AuditLog
    out_dir: str
    raw_transport: RealTransport = field(default_factory=RealTransport)
    artifacts: dict = field(default_factory=dict)   # aşamalar arası veri
    started: str = ""

    @property
    def gated_transport(self) -> "ScopeGatedTransport":
        """Üçüncü taraf ajanlar MUTLAKA bunu kullanır (ağ = scope kapılı)."""
        return ScopeGatedTransport(self.scope, self.audit, self.raw_transport)


# --------------------------------------------------------------------------
# Ajan sözleşmesi
# --------------------------------------------------------------------------

class SecurityAgent:
    """Harness'e takılan her ajan bu sözleşmeyi uygular."""
    name: str = "unnamed"
    description: str = ""

    def run(self, ctx: HarnessContext):
        raise NotImplementedError


# --------------------------------------------------------------------------
# Scope-gated transport (üçüncü taraf ajanlar için ZORUNLU ağ katmanı)
# --------------------------------------------------------------------------

class ScopeGatedTransport:
    """Her tcp/http çağrısı öncesi scope kontrolü; REDDET => çağrı yapılmaz."""

    def __init__(self, scope: ScopeContract, audit: AuditLog, inner=None):
        self.scope = scope
        self.audit = audit
        self.inner = inner or RealTransport()

    def _gate(self, host, port, method) -> bool:
        allowed, reason = self.scope.check_request(host=host, port=port, method=method)
        if not allowed:
            self.audit.append("SCOPE_DENY", host=host, port=port, method=method,
                              reason=f"[gated-transport] {reason}")
            return False
        return True

    def tcp_connect(self, host, port, timeout=2.0):
        if not self._gate(host, port, "GET"):
            return False
        return self.inner.tcp_connect(host, port, timeout)

    def http_get(self, host, port, path, timeout=4.0, use_tls=False):
        if not self._gate(host, port, "GET"):
            return None
        return self.inner.http_get(host, port, path, timeout, use_tls)

    def raw_get(self, host, port, path, headers=None, timeout=6.0):
        """Header'lı ham GET — yine kapıdan geçer. Exploit kanıtları için.
        Test edilebilirlik: inner'da raw_get varsa ona delege edilir."""
        if not self._gate(host, port, "GET"):
            return None
        inner_raw = getattr(self.inner, "raw_get", None)
        if callable(inner_raw):
            return inner_raw(host, port, path, headers=headers, timeout=timeout)
        import http.client
        try:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path if path.startswith("/") else "/" + path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read(65536).decode("utf-8", errors="replace")
            out = (resp.status, body, resp.getheader("Server") or "")
            conn.close()
            return out
        except OSError:
            return None


# --------------------------------------------------------------------------
# Yerleşik aşamalar
# --------------------------------------------------------------------------

class ReconStage(SecurityAgent):
    name = "recon"
    description = "kapsam içi tarama: port/dizin/bucket/parola keşfi"

    def __init__(self, hosts=None, endpoints=None, base_domains=()):
        self.hosts = hosts or ["127.0.0.1"]
        self.endpoints = endpoints or [("127.0.0.1", 8081)]
        self.base_domains = list(base_domains)

    def run(self, ctx: HarnessContext):
        out = os.path.join(ctx.out_dir, "findings.jsonl")
        agent = ReconAgent(scope=ctx.scope, killswitch=ctx.killswitch,
                           audit=ctx.audit, out_path=out)
        findings = agent.run(self.base_domains, self.hosts, self.endpoints)
        ctx.artifacts["findings"] = [f.__dict__ for f in findings]
        return len(findings)


class ValidatorStage(SecurityAgent):
    name = "validator"
    description = "her bulgunun deterministik yeniden doğrulanması"

    def run(self, ctx: HarnessContext):
        findings = ctx.artifacts.get("findings") or []
        out = os.path.join(ctx.out_dir, "findings-validated.jsonl")
        agent = ValidatorAgent(scope=ctx.scope, killswitch=ctx.killswitch,
                               audit=ctx.audit, out_path=out)
        vals = agent.run(findings)
        ctx.artifacts["validations"] = [v.__dict__ for v in vals]
        return len(vals)


SEVERITY = {
    "secret": "medium", "open_bucket": "medium",
    "bucket_service": "low", "directory": "low",
    "open_port": "info", "subdomain": "info",
}


class ReportStage(SecurityAgent):
    name = "report"
    description = "doğrulanmış bulgulardan yönetim/uyumluluk raporu (md)"

    def run(self, ctx: HarnessContext):
        findings = ctx.artifacts.get("findings") or []
        vals = {v["hedef"] + "|" + v["tip"]: v for v in (ctx.artifacts.get("validations") or [])}
        order = {"medium": 0, "low": 1, "info": 2}
        rows = sorted(
            ({"sev": SEVERITY.get(f["tip"], "info"), **f} for f in findings),
            key=lambda r: order.get(r["sev"], 3),
        )
        lines = [
            "# PurpleLoop Güvenlik Tarama Raporu",
            "",
            f"- Zaman: {ctx.started}",
            f"- Kapsam: {', '.join(ctx.scope.targets)}",
            f"- Toplam bulgu: {len(findings)} | Doğrulanmış (CONFIRMED): "
            f"{sum(1 for v in vals.values() if v['verdict'] == 'CONFIRMED')}",
            "",
            "| Önem | Tip | Hedef | Kanıt | Doğrulama |",
            "|------|-----|-------|-------|-----------|",
        ]
        for r in rows:
            v = vals.get(r["hedef"] + "|" + r["tip"], {})
            lines.append(f"| {r['sev']} | {r['tip']} | {r['hedef']} "
                         f"| {r['kanit'][:60]} | {v.get('verdict', '-')} |")
        report = "\n".join(lines) + "\n"
        path = os.path.join(ctx.out_dir, "report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report)
        digest = hashlib.sha256(report.encode("utf-8")).hexdigest()
        ctx.audit.append("REPORT", path=path, sha256=digest, findings=len(findings))
        ctx.artifacts["report_path"] = path
        return digest


# --------------------------------------------------------------------------
# Harness çekirdeği
# --------------------------------------------------------------------------

class Harness:
    def __init__(self, ctx: HarnessContext):
        self.ctx = ctx
        self.agents: dict = {}
        self.register(ReconStage())
        self.register(ValidatorStage())
        self.register(ReportStage())

    def register(self, agent) -> None:
        if not hasattr(agent, "name") or not hasattr(agent, "run"):
            raise HarnessError(f"ajan sözleşmesi eksik (name/run): {agent!r}")
        if agent.name in self.agents:
            raise HarnessError(f"ajan adı çakışıyor: {agent.name}")
        self.agents[agent.name] = agent

    def load_plugin(self, spec: str):
        """'module.path:ClassName' → sınıfı yükler, örneğini kaydeder. Fail-closed."""
        mod_path, _, cls_name = spec.partition(":")
        if not mod_path or not cls_name:
            raise HarnessError(f"plugin spec 'module:Class' olmalı: {spec!r}")
        try:
            cls = getattr(importlib.import_module(mod_path), cls_name)
        except Exception as e:
            raise HarnessError(f"plugin yüklenemedi ({spec}): {e}") from e
        self.register(cls())

    def run_pipeline(self, stage_names: list) -> dict:
        ctx = self.ctx
        ctx.audit.append("PIPELINE_START", stages=stage_names,
                         agents=sorted(self.agents))
        stages, halted, reason = [], False, None
        for name in stage_names:
            if ctx.killswitch.is_active():
                ctx.audit.append("KILLSWITCH_HALT", stage=name)
                halted, reason = True, f"kill-switch before {name}"
                break
            agent = self.agents.get(name)
            if agent is None:
                ctx.audit.append("PIPELINE_ERROR", stage=name,
                                 reason="bilinmeyen aşama")
                halted, reason = True, f"bilinmeyen aşama: {name}"
                break
            ctx.audit.append("AGENT_START", stage=name)
            try:
                result = agent.run(ctx)
            except Exception as e:  # fail-closed: ajan hatası pipeline'ı durdurur
                ctx.audit.append("AGENT_ERROR", stage=name, error=str(e)[:300])
                halted, reason = True, f"{name} hatası: {e}"
                stages.append({"stage": name, "ok": False})
                break
            ctx.audit.append("AGENT_END", stage=name, result=str(result)[:200])
            stages.append({"stage": name, "ok": True})
        summary = {"stages": stages, "halted": halted, "reason": reason}
        ctx.audit.append("PIPELINE_END", **summary)
        return summary


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="purpleloop.harness",
                                 description="PurpleLoop security harness")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out-dir", default="run")
    ap.add_argument("--pipeline", default="recon,validator,report")
    ap.add_argument("--hosts", default="127.0.0.1")
    ap.add_argument("--endpoints", default="127.0.0.1:8081,127.0.0.1:9010")
    ap.add_argument("--domains", default="")
    ap.add_argument("--killswitch", default="KILLSWITCH")
    ap.add_argument("--plugin", action="append", default=[],
                    help="üçüncü parti ajan: 'module:Class' (tekrarlanabilir)")
    args = ap.parse_args(argv)

    try:
        with open(args.scope, encoding="utf-8") as f:
            scope = ScopeContract(f.read())
    except Exception as e:
        print(f"FAIL-CLOSED: scope yüklenemedi: {e}", file=sys.stderr)
        return 2

    ks = KillSwitch(args.killswitch)
    if ks.is_active():
        print("FAIL-CLOSED: kill-switch aktif.", file=sys.stderr)
        return 3

    os.makedirs(args.out_dir, exist_ok=True)
    ctx = HarnessContext(scope=scope, killswitch=ks,
                         audit=AuditLog(os.path.join(args.out_dir, "audit.jsonl")),
                         out_dir=args.out_dir,
                         started=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"))

    harness = Harness(ctx)
    # yerleşik recon aşamasına hedefleri enjekte et
    harness.agents["recon"] = ReconStage(
        hosts=[h for h in args.hosts.split(",") if h],
        endpoints=[(ep.rpartition(":")[0], int(ep.rpartition(":")[2]))
                   for ep in args.endpoints.split(",") if ep],
        base_domains=[d for d in args.domains.split(",") if d],
    )
    try:
        for spec in args.plugin:
            harness.load_plugin(spec)
    except HarnessError as e:
        print(f"FAIL-CLOSED: {e}", file=sys.stderr)
        return 2

    summary = harness.run_pipeline([s for s in args.pipeline.split(",") if s])
    ok = ctx.audit.verify_chain()
    print(json.dumps({**summary, "audit_chain_valid": ok,
                      "report": ctx.artifacts.get("report_path")}, ensure_ascii=False))
    return 0 if (ok and not summary["halted"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
