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
| `purpleloop report_hub --bounty F.json` | Executive cover report: bounty scoreboard evidence + risk summary |

## Benchmark (measured, not claimed)

| Benchmark | Recall | FP | Scope violations | Evidence |
|---|---|---|---|---|
| Own lab (16 planted assets) | 100% | 0 | 0 | `evidence/week7_run.log` |
| **OWASP Juice Shop v17.3.0** (GET-recon class, 11 surfaces) | **100%** | **0** | **0** | `evidence/v14_juice_benchmark.log` |

Scored against a 16-asset ground-truth lab with out-of-scope decoy hosts:

| Metric | Result |
|---|---|
| Recall | **100%** (16/16 planted assets) |
| False positives | **0** |
| Scope violations | **0** (48 decoy requests denied) |
| Full scan duration | 0.32 s |

Reproduce: `python3 -m purpleloop.bench --scope scope.json --out bench.json`

## Bounty & Exploitation

PurpleLoop's bounty harness **proves exploitation with the target's own
scoreboard**, not with the agent's word: the agent only *attempts* GET-only
vectors; a solve counts **only if the target application itself records it**
(`/api/challenges` → `solved: true`). False positives are structurally
near-impossible — the verifier is the server, never the agent.

**Mechanic (attempt → server verify → reward):**

1. Fetch challenge catalog (`/api/challenges`), snapshot `solved` set.
2. Fire GET-only exploitation vectors (each one passes the scope gate;
   content-signature checks where 200 alone is not proof).
3. Re-fetch the scoreboard — `solved_after − solved_before` = newly solved,
   each mapped CTF-difficulty → severity → bounty points
   (low 100 / medium 400 / high 900 / critical 2000).

**Live proof — OWASP Juice Shop, 6 challenges solved in one run**
(scoreboard-verified, chain-logged in `evidence/`):

| Vector category | Example vector | Target challenge class |
|---|---|---|
| Hidden surface discovery | `/score-board`, `/metrics` | scoreBoard, metrics |
| Sensitive file exposure | `/ftp/`, `/ftp/acquisitions.md` | confidentialDocument |
| SQL injection (UNION) | `/rest/products/search?q=')) union select …` | dbSchema, userCredentials |
| Filter bypass (Poison Null Byte) | `/ftp/package.json.bak%2500.md` | nullByte |
| Easter egg / backup exposure | `/ftp/eastere.gg` | easterEgg |

Cover report: `python3 -m purpleloop.report_hub --findings run.jsonl \
--bounty bounty-result.json --out-dir rapor/` → `rapor_kapak.md`
(3-sentence risk summary, solved-bounty table with severity/points,
remaining risks, recommended actions).

## Architecture

```
scope gate → recon → validator → safe-mode exploit → attack paths → compliance report
      └──────────── pentest (active, read-only proofs) ────────────────┘
                          └──→ bounty (scoreboard-verified solves) ──┘
                                      └──→ report_hub → executive cover report
└──────────────── SHA256 hash-chained audit log (every step) ────────────────┘
```

Penetration chain: **recon → pentest → bounty → report** — recon discovers
the surface, pentest proves vulnerabilities safely, bounty converts proven
exploits into server-verified scores, report_hub rolls everything into
executive/auditor/technical reports.

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

- **297+ tests green** (`python3 -m pytest -q`)
- Week-by-week run logs: `evidence/first_run.log`, `evidence/week2..8_run.log`
- Benchmark: `evidence/bench-result.json` — 100% recall / 0 FP / 0 violations
- Continuous monitoring: `evidence/monitoring.jsonl` + 5 critical alerts
- MCP server live run: `evidence/v13_mcp_run.log` — real client → stdio server
  → live lab, 33 findings, chain valid, decoy denied

## Roadmap

See [ROADMAP.md](ROADMAP.md) — GOAD benchmark, pip release, hosted offering.

## License

Apache-2.0 — see [LICENSE](LICENSE). Responsible use: [SECURITY.md](SECURITY.md).
