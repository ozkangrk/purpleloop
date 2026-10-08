"""v1.7: Çoklu-proje defteri — platformun müşteri/hedef yönetim katmanı.

Her proje: kendi scope sözleşmesi + çalışma dizini + policy ayarı.
Defter JSON dosyasında kalıcı; bozuk dosya FAIL-CLOSED (sessiz boş liste
asla — izinli tarama listesi kaybolursa varsayılan davranış DURMAK olmalı).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from typing import Callable, Optional


@dataclass
class ProjectRecord:
    id: str                    # benzersiz kısa kimlik (slug)
    ad: str                    # görünen ad
    hedef: list                # host listesi
    portlar: list
    scope_dosyasi: str         # izin sözleşmesi yolu (mutlak önerilir)
    out_dir: str               # bulgu/audit dizini
    policy: dict = field(default_factory=lambda: {"max_error": 0, "max_warning": 10})
    aktif: bool = True


class ProjectRegistry:
    """Proje defteri: ekle/listele/kaldır + toplu tarama orkestrasyonu."""

    def __init__(self, path: str):
        self.path = path
        self._records: dict[str, ProjectRecord] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as f:
            raw = f.read()
        if not raw.strip():
            return
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            # FAIL-CLOSED: defter bozuksa varsayılan "tarama yok"a düşme
            raise RuntimeError(f"Proje defteri bozuk ({self.path}): {e}") from e
        for d in data:
            rec = ProjectRecord(**d)
            self._records[rec.id] = rec

    def _save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in self._records.values()], f,
                      ensure_ascii=False, indent=1)

    def add(self, rec: ProjectRecord) -> None:
        if rec.id in self._records:
            raise ValueError(f"proje id zaten var: {rec.id}")
        self._records[rec.id] = rec
        self._save()

    def remove(self, proje_id: str) -> bool:
        if proje_id in self._records:
            del self._records[proje_id]
            self._save()
            return True
        return False

    def get(self, proje_id: str) -> Optional[ProjectRecord]:
        return self._records.get(proje_id)

    def list_all(self) -> list:
        return [r for r in self._records.values() if r.aktif]

    def scan_all(self, scanner: Callable[[ProjectRecord], dict]) -> dict:
        """Her aktif proje için scanner(record) çağırır.

        scanner: taramayı yapan callable (enjeksiyon — testlerde sahte).
        Bir projenin scope dosyası yoksa/hatalıysa o proje {'hata': ...}
        döner, diğerleri koşmaya devam eder (fail-closed ama tarama bloğu değil).
        """
        results = {}
        for rec in self.list_all():
            if not os.path.exists(rec.scope_dosyasi):
                results[rec.id] = {"hata": f"scope dosyası yok: {rec.scope_dosyasi}"}
                continue
            try:
                results[rec.id] = scanner(rec)
            except Exception as e:  # tek proje hatası turu durdurmaz
                results[rec.id] = {"hata": str(e)[:200]}
        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="purpleloop.projects",
                                 description="Çoklu-proje defteri")
    sub = ap.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("list", help="projeleri listele")
    lp.add_argument("--registry", default="projects.json")

    ap_add = sub.add_parser("add", help="proje ekle")
    ap_add.add_argument("--registry", default="projects.json")
    ap_add.add_argument("--id", required=True)
    ap_add.add_argument("--ad", required=True)
    ap_add.add_argument("--hedef", required=True, help="virgüllü host listesi")
    ap_add.add_argument("--portlar", required=True, help="virgüllü portlar")
    ap_add.add_argument("--scope", required=True)
    ap_add.add_argument("--out-dir", required=True)

    rp = sub.add_parser("remove", help="proje kaldır")
    rp.add_argument("--registry", default="projects.json")
    rp.add_argument("--id", required=True)

    sp = sub.add_parser("scan", help="tüm projeleri tara (recon+validator+gate)")
    sp.add_argument("--registry", default="projects.json")

    args = ap.parse_args(argv)
    try:
        reg = ProjectRegistry(args.registry)
    except RuntimeError as e:
        print(f"FAIL-CLOSED: {e}", file=sys.stderr)
        return 2

    if args.cmd == "list":
        for r in reg.list_all():
            print(f"{r.id:16} {r.ad:24} hedef={','.join(r.hedef)} port={','.join(map(str, r.portlar))}")
        return 0

    if args.cmd == "add":
        rec = ProjectRecord(
            id=args.id, ad=args.ad,
            hedef=[h for h in args.hedef.split(",") if h],
            portlar=[int(p) for p in args.portlar.split(",") if p],
            scope_dosyasi=os.path.abspath(args.scope),
            out_dir=os.path.abspath(args.out_dir))
        try:
            reg.add(rec)
        except ValueError as e:
            print(f"HATA: {e}", file=sys.stderr)
            return 1
        print(f"eklendi: {rec.id}")
        return 0

    if args.cmd == "remove":
        ok = reg.remove(args.id)
        print("kaldırıldı" if ok else "bulunamadı")
        return 0 if ok else 1

    if args.cmd == "scan":
        def _scan(rec: ProjectRecord) -> dict:
            from .harness import Harness, HarnessContext, ReconStage
            from .scope import ScopeContract
            from .audit import AuditLog
            from .killswitch import KillSwitch
            from .platform_layer import PolicyGate
            os.makedirs(rec.out_dir, exist_ok=True)
            with open(rec.scope_dosyasi, encoding="utf-8") as f:
                scope = ScopeContract(f.read())
            ks = KillSwitch(os.path.join(rec.out_dir, "KILLSWITCH"))
            if ks.is_active():
                return {"hata": "kill-switch aktif"}
            audit = AuditLog(os.path.join(rec.out_dir, "audit.jsonl"))
            ctx = HarnessContext(scope=scope, killswitch=ks, audit=audit,
                                 out_dir=rec.out_dir)
            harness = Harness(ctx)
            eps = [(h, p) for h in rec.hedef for p in rec.portlar]
            harness.agents["recon"] = ReconStage(hosts=rec.hedef, endpoints=eps)
            summary = harness.run_pipeline(["recon", "validator"])
            findings = []
            fp = os.path.join(rec.out_dir, "findings.jsonl")
            if os.path.exists(fp):
                with open(fp, encoding="utf-8") as f:
                    findings = [json.loads(l) for l in f if l.strip()]
            gate = PolicyGate(**rec.policy).evaluate(findings)
            return {"bulgu": len(findings), "gate": gate["durum"],
                    "halted": summary["halted"]}
        results = reg.scan_all(_scan)
        print(json.dumps(results, ensure_ascii=False, indent=1))
        return 0 if all("hata" not in v for v in results.values()) else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
