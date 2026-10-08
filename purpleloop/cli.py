"""PurpleLoop unified CLI: subcommand dispatch over module mains."""
import sys
import argparse

PROG = "purpleloop"


def _build_parser():
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="PurpleLoop — fail-closed security harness. "
                    "Yalnızca izinli sistemlerde kullanın.",
    )
    sub = ap.add_subparsers(dest="command", metavar="<sub>")
    for name, mod, help_ in [
        ("scan", "purpleloop.harness",
         "Tam harness çalıştır (recon, validator, exploit, report)"),
        ("validate", "purpleloop.validator",
         "Bulgu/çıktı doğrulama (validator)"),
        ("exploit", "purpleloop.exploit",
         "Safe-mode exploit aşaması"),
        ("chain", "purpleloop.chainreact",
         "Attack-path / zincir reaksiyon analizi"),
        ("monitor", "purpleloop.monitor",
         "Sürekli izleme: delta tarama + kritik değişim alert'leri"),
        ("bench", "purpleloop.bench",
         "Lab benchmark: recall / FP / kapsam-ihlali metrikleri"),
        ("dashboard", "purpleloop.dashboard",
         "Sonuç panosu"),
        ("mcp", "purpleloop.mcp_server",
         "MCP server (stdio): AI agent'lara scope-gated araçlar"),
        ("platform", "purpleloop.platform_layer",
         "Platform katmanı: SARIF export / policy gate / OSV zenginleştirme"),
        ("projects", "purpleloop.projects",
         "Çoklu-proje defteri: müşteri/hedef yönetimi + toplu tarama"),
        ("campaign", "purpleloop.campaign",
         "Kampanya orkestratörü: otonom recon→önceliklendir→prob döngüsü"),
        ("nucleus", "purpleloop.nucleus",
         "Nuclei backend: güçlü tarayıcı scope+audit arkasında"),
        ("pentest", "purpleloop.pentest",
         "White-hat sızma denemeleri: auth bypass / traversal / oturum"),
    ]:
        sp = sub.add_parser(name, help=help_, add_help=True)
        sp.set_defaults(_module=mod)
    return ap


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    ap = _build_parser()
    if not argv:
        ap.print_help()
        return 1
    args, rest = ap.parse_known_args(argv)
    if args.command is None:
        ap.print_help()
        return 1
    # dashboard dahil tüm modüller lazily import edilir.
    try:
        import importlib
        module = importlib.import_module(args._module)
    except ImportError as e:
        if args._module == "purpleloop.dashboard":
            print(f"purpleloop: 'dashboard' henüz mevcut değil / kurulum eksik ({e}).\n"
                  "Bu alt komut sonraki sürümlerde eklenecek.", file=sys.stderr)
            return 2
        print(f"purpleloop: modül yüklenemedi: {args._module} ({e})", file=sys.stderr)
        return 2
    sub_main = getattr(module, "main", None)
    if sub_main is None:
        print(f"purpleloop: {args._module} içinde main() yok.", file=sys.stderr)
        return 2
    rc = sub_main(rest)
    return int(rc) if rc is not None else 0


if __name__ == "__main__":
    sys.exit(main())
