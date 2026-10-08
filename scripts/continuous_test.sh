#!/bin/bash
# PurpleLoop sürekli test turu — watchdog deseni:
# her şey yolundaysa SESSİZ (stdout boş => Telegram'a mesaj gitmez),
# sorun varsa özet çıktı basar (cron bunu Telegram'a teslim eder).
# Tüm detay: evidence/continuous/tour-*.log
set -u
cd /home/ozkangu/Desktop/purpleloop
OUT=evidence/continuous
mkdir -p "$OUT"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="$OUT/tour-$TS.log"

PYTEST_OUT=$(python3 -m pytest -q 2>&1 | tail -2)
HEALTH=$(python3 - <<'PY'
import socket
lines=[]
for h,p,label in [("127.0.0.1",8081,"nginx"),("127.0.0.1",9010,"minio"),("127.0.0.1",8888,"qwen-tensorfold")]:
    try:
        socket.create_connection((h,p),timeout=3).close(); lines.append(f"{label}({h}:{p}) OK")
    except OSError:
        lines.append(f"{label}({h}:{p}) DOWN")
print("\n".join(lines))
PY
)
BENCH_JSON=$(python3 -m purpleloop.bench --scope scope.json --out "$OUT/bench-$TS.json" --audit "$OUT/audit-$TS.jsonl" 2>/dev/null | tail -1)
LLM_JSON=$(python3 -m purpleloop.llmbench --limit 15 --out "$OUT/llmbench-$TS.json" 2>/dev/null | tail -1)

{
echo "=== PurpleLoop sürekli test turu $TS ==="
echo "--- 1) birim testler ---"; echo "$PYTEST_OUT"
echo "--- 2) lab/model sağlık ---"; echo "$HEALTH"
echo "--- 3) lab benchmark ---"; echo "$BENCH_JSON"
echo "--- 4) LLM güvenlik benchmark (qwen3.8-flash-next @ tensorfold) ---"; echo "$LLM_JSON"
} > "$LOG" 2>&1
ln -sf "$(basename "$LOG")" "$OUT/latest.log"

# ---- watchdog değerlendirme ----
FLAGS=$(python3 - "$PYTEST_OUT" "$HEALTH" "$BENCH_JSON" <<'PY'
import sys
pytest_out, health, bench = sys.argv[1], sys.argv[2], sys.argv[3]
flags = []
if "failed" in pytest_out or "error" in pytest_out.lower():
    flags.append("birim-testler-basarisiz")
flags += [f"servis-down: {l}" for l in health.splitlines() if "DOWN" in l]
try:
    import json
    r = json.loads(bench)
    if r.get("recall", 1) < 0.9: flags.append("benchmark-recall<0.9")
    if r.get("fp_bulgu", 0) > 0: flags.append("benchmark-FP>0")
    if r.get("kapsam_ihlali", 0) > 0: flags.append("KAPSAM-IHLALI")
except Exception:
    flags.append("benchmark-yaniti-bozuk")
print("\n".join(flags))
PY
)

if [ -n "$FLAGS" ]; then
  echo "⚠️ PurpleLoop test turu sorun buldu ($TS):"
  echo "$FLAGS" | sed 's/^/• /'
  echo "Detay: ~/Desktop/purpleloop/$LOG"
  exit 1
fi
# her şey yolunda => sessiz
exit 0
