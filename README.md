# PurpleLoop

**Autonomous security testing you can prove.** Fail-closed security harness:
scope-gated recon, deterministic validation, safe-mode exploit proofs,
attack-path chaining, compliance reporting (KVKK / ISO 27001 / SOC 2),
continuous monitoring — every step hash-chained into an immutable audit log.

> İlke: kapsam dışı veya belirsiz her durum = REDDET + audit kaydı. Fail-open yok.
> Use only on systems you are explicitly authorized to test.

[![CI](https://github.com/ozkangrk/purpleloop/actions/workflows/ci.yml/badge.svg)](https://github.com/ozkangrk/purpleloop/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

- **Site:** https://ozkangrk.github.io/purpleloop/
- **Repo:** https://github.com/ozkangrk/purpleloop

## Why

Scanners dump findings; auditors ask why they should trust them. PurpleLoop is
built the other way around: **every claim is evidence-backed** —

- **Scope contract**: an allow-list JSON; every network call passes the gate.
  Out-of-scope ⇒ request is never sent + `SCOPE_DENY` audit record.
- **Hash-chained audit**: append-only JSONL, each record SHA256-chained to the
  previous. Tamper with any line and `verify_chain()` raises `AuditTamperError`.
- **Deterministic validation**: each finding is re-verified by replay
  (reconnect / re-fetch). LLM advisors may summarize; they can never change a
  verdict. *The model advises. The harness decides.*
- **Safe-mode exploit proofs**: read-only proof actions only (GET/HEAD);
  secrets masked in all evidence; kill-switch halts everything.

## Quickstart

```bash
git clone https://github.com/ozkangrk/purpleloop && cd purpleloop
python3 -m pip install pytest
python3 -m pytest -q                          # 169 tests
docker compose up -d --wait                   # lab: nginx :8081 + minio :9010
python3 -m purpleloop scan --scope scope.json --out-dir run1 \
  --hosts 127.0.0.1 --endpoints 127.0.0.1:8081,127.0.0.1:9010
python3 -m purpleloop dashboard --run-dir run1   # http://127.0.0.1:8090
```

## CLI

| Command | What it does |
|---|---|
| `purpleloop scan` | Full harness pipeline (recon → validator → report) |
| `purpleloop validate` | Deterministic re-verification of findings |
| `purpleloop exploit` | Safe-mode read-only exploit proofs |
| `purpleloop chain` | Attack-path chaining + Turkish compliance report |
| `purpleloop monitor` | Continuous delta scanning + critical alerts |
| `purpleloop bench` | Lab benchmark: recall / FP / scope violations |
| `purpleloop dashboard` | Live web dashboard (stdlib-only) |
| `purpleloop mcp` | MCP server (stdio) — AI agents get scope-gated tools |

## Benchmark (measured, not claimed)

Scored against a 16-asset ground-truth lab with out-of-scope decoy hosts:

| Metric | Result |
|---|---|
| Recall | **100%** (16/16 planted assets) |
| False positives | **0** |
| Scope violations | **0** (48 decoy requests denied) |
| Full scan duration | 0.32 s |

Reproduce: `python3 -m purpleloop.bench --scope scope.json --out bench.json`

## Architecture

```
scope gate → recon → validator → safe-mode exploit → attack paths → compliance report
└──────────────── SHA256 hash-chained audit log (every step) ────────────────┘
```

PurpleLoop is a **security harness**: agents (recon, validator, report, 3rd-party
plugins) are replaceable parts; the control plane (scope gate, audit chain,
kill-switch) belongs to the harness and is never delegated. External LLMs /
agent frameworks plug in as advisors only — they cannot perform network actions
or change verdicts. Third-party agents get network access exclusively through
`ScopeGatedTransport`.

## Components

| Module | Purpose |
|---|---|
| `scope.py` | Allow-list contract; gate before every request (suffix-spoof resistant) |
| `audit.py` | SHA256 hash-chained append-only JSONL |
| `killswitch.py` | File-based stop; OSError ⇒ active (fail-closed) |
| `recon.py` | Port / directory / bucket / secret scanning (bucket object fetch, autoindex detect) |
| `validator.py` | Per-finding deterministic replay validation |
| `exploit.py` | Safe-mode (read-only) exploit proofs, masked secrets |
| `harness.py` | Agent registry + pipeline + plugins + gated transport |
| `chainreact.py` | Attack-path rules + KVKK/ISO/SOC2-mapped Turkish report |
| `monitor.py` | Continuous delta scanning + critical-leak alerts |
| `bench.py` | Ground-truth benchmark (recall / FP / violations) |
| `dashboard.py` | Stdlib-only live web dashboard + JSON API |

## Lab (docker-compose)

- `nginx-misconfigured` → `:8081` (autoindex, fake creds in `/backup/`)
- `minio-s3` → `:9010` (public bucket with planted fake credentials; `minio-init` provisions)

## Test evidence

- **207 tests green** (`python3 -m pytest -q`)
- Week-by-week run logs: `evidence/first_run.log`, `evidence/week2..8_run.log`
- Benchmark: `evidence/bench-result.json` — 100% recall / 0 FP / 0 violations
- Continuous monitoring: `evidence/monitoring.jsonl` + 5 critical alerts
- MCP server live run: `evidence/v13_mcp_run.log` — real client → stdio server
  → live lab, 33 findings, chain valid, decoy denied

## Roadmap

See [ROADMAP.md](ROADMAP.md) — GOAD benchmark, pip release, hosted offering.

## License

Apache-2.0 — see [LICENSE](LICENSE). Responsible use: [SECURITY.md](SECURITY.md).
