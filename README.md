# myc

A small, self-contained verifier for C written by LLMs (and humans). It treats
source as **untrusted input**: never a shell string; the compiler is always
`program + argv[]`.

> myc is a best-effort safety net, **not** a proof of correctness. Default
> `OK` means **compile-clean** (gcc `-Werror` + memory-tier warnings). It does
> **not** mean memory-safe. See [Assurance](#assurance).

## For coding agents

Inner loop (one action, not a flag soup):

```
myc check prog.c --lite
```

Read `action` and stop guessing:

| `action` | What to do |
|---|---|
| `STOP_COMPILE_CLEAN` | Stop. Compile-clean, **not** "memory-safe". |
| `FIX_ONE` | Edit only `allowed_span`. Use `fix_or_null` if present; do not guess if null. |
| `ESCALATE_RUNTIME` | `myc check prog.c --run --lite` |
| `ESCALATE_CONTRACT` | `myc check prog.c --driver --lite` |
| `GIVE_UP_NO_TEMPLATE` | `myc context prog.c --budget 4K` |

MCP: prefer tool `verify` (`myc.lite.v1`, default `--scenario auto`). Frontier
models can still use `agent_check` (`myc.agent.v2`).

- Cursor rule: [`examples/cursor-rule.md`](examples/cursor-rule.md)
- MCP config: [`examples/mcp.json`](examples/mcp.json)
- Tool reference: [`docs/mcp-tools.md`](docs/mcp-tools.md)

Every C repo that agents touch should keep a **project pack** next to the
sources (not optional if you care what the model writes):

| File | Role |
|---|---|
| `myc.prompt.md` | Free-text project rules (verbatim, cap 8 KiB) |
| `myc.spec.json` | Structured spec: `version`, `name`, optional `rules` / `allow_headers` / `deny_functions` |

myc loads them from the project directory (`--pack-dir`, `--no-pack` to skip).
Example: [`test/fixtures/pack/`](test/fixtures/pack/). Invalid spec = fail-fast.

## Install

```
build.bat        # MinGW-w64 / GCC  → myc.exe, mcp.exe, argv_probe.exe
bash build.sh    # POSIX / GCC      → myc, mcp, argv_probe
```

Requires GCC. Clang (`--run`), Frama-C (`--prove`), and Fil-C (`--filc`) are
optional and used only when present.

Release zips: GitHub Releases (`myc-windows-latest.zip` / `myc-linux-latest.tar.gz`).

## Usage

```
myc check FILE.c --lite
myc check FILE.c --run --lite
myc check FILE.c --watch-diff --lite
myc check FILE.c --json
myc check -                         (source on stdin)
myc prompt FILE.c --harness cursor
myc context FILE.c --budget 4K
myc version
```

`myc --help` lists every command. Full flag encyclopedia and honest gate
limits: [`docs/capabilities.md`](docs/capabilities.md). Registry:
[`capabilities.json`](capabilities.json).

Common extras (all optional; missing backends stay non-blocking):

- `--scenario auto` — smallest sufficient gate recipe from source shape
- `--eig-apply [--budget-ms N]` — after L1, run **at most one** EIG experiment (default off)
- `--parallel-gates` — overlap `--analyze` with `--run` after compile-clean (default off)
- `--production` — require-complete + backend min-version floor (no silent weaker OK)
- `--require-complete` — verification gaps fail CI (`MYC-INCOMPLETE-*`)
- `--no-cache` — disable evidence replay from `.myc/evidence_cache.json`

## How it works

Hard gates come only from **semantic evidence** (compiler diagnostics,
sanitizer reports, fat-pointer checks, Frama-C, Fil-C). Lint, include
scanning, and other heuristics are observations — they never lower the
verdict.

```
scan includes / lint / denylist     → warnings (non-blocking)
gcc -E (skipped if no # directive)  → preprocessed source
gcc -c -O2 -Wall -Wextra -Werror -pedantic + memory-tier
                                    → COMPILE_ERROR on violation
optional:
  --analyze     gcc -fanalyzer
  --checked     MYC_BUF fat pointers → L4 SPATIAL
  --run         clang ASan/UBSan     → L3 RUNTIME
  --driver      contract edge harness
  --metamorphic -O0 vs -O2
  --divergence  {gcc,clang,tcc} × {-O0,-O2}
  --negative    missing-pattern observations
  --quorum      cross-backend agreement
  --require-complete → gap = CI failure
  --production      → require-complete + min-version floor
```

## Policy

- **Headers are free.** The include whitelist is a conservative default, not a ban.
- **Denylisted calls** (`system`, `exec*`, `popen`, file I/O, …) are warnings, never blockers.
- Unknown functions are caught by `-Werror=implicit-function-declaration`.

## MCP server

`mcp.exe` is JSON-RPC 2.0 over stdio. Tools:

| Tool | Output |
|---|---|
| `verify` | `myc.lite.v1` (default `--scenario auto`) |
| `check` | `myc.result.v1` |
| `agent_check` | `myc.agent.v2` |
| `context` / `next` / `compare_candidates` | frontier: package, EIG (no apply), Pareto |
| `repair` / `lint` / `contracts` / `version` / `policy` | as named |

See [`docs/mcp-tools.md`](docs/mcp-tools.md). Example Cursor config:
[`examples/mcp.json`](examples/mcp.json).

## In CI

```yaml
- name: Verify generated C
  shell: bash
  run: |
    for f in src/*.c; do
      myc check "$f" --json || exit 1
    done
```

Negative guard (Windows): `test\_anti_false_ok.bat` — fails if a known-bad
fixture stops producing a negative verdict.

GitHub Actions (`.github/workflows/ci.yml`): Windows `build.bat` +
`test\_regress_run.bat`; Linux `build.sh` + `test/_ci_linux.sh`. Both compile
with `-Werror`, pre-flight `prove.c`, `git diff --check`, and trust-core
regression.

## Learn more

| Doc | Contents |
|---|---|
| [`docs/quickstart.md`](docs/quickstart.md) | Build, `MYC_BUF` (L4), `--run`, contracts |
| [`docs/capabilities.md`](docs/capabilities.md) | Gate matrix: what each flag does **and does not** guarantee |
| [`docs/mcp-tools.md`](docs/mcp-tools.md) | MCP tool schemas |
| [`docs/result-schema.md`](docs/result-schema.md) | Frozen `myc.result.v1` / `myc.agent.v2` / `myc.lite.v1` |
| [`docs/backends.md`](docs/backends.md) | Backend tiers + host support contract |
| [`docs/release.md`](docs/release.md) | Tag, checksums, rebuild (not bit-identical) |
| [`docs/incident.md`](docs/incident.md) | False-OK / rollback / what to keep |
| [`CHANGELOG.md`](CHANGELOG.md) | Release notes |

Baseline bench: `bash bench/run_bench.sh` (20 tasks; reports in `bench/reports/`).

## Assurance

Results are an **assurance vector** `C1 S0 R1 B0 P0 D0 F0` (Compile / Static /
Runtime / Checked / Proof / Driver / Filc; `0` = not run, `1` = clean, `2` =
findings, `3` = inconclusive, `4` = observations).

Scalar L1–L5 labels are **legacy**: they name the strongest backend that ran,
not a formal guarantee. Trust the gate matrix, `receipt_sha256`, and source
hash — not the label.

## License

MIT — [`LICENSE`](LICENSE). Copyright (c) 2026 megaalive.
