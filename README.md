# myc

A small, self-contained verifier for C code written by LLMs (and humans). It
checks that a C source file is at least *plausibly* safe before you trust it,
using a layered pipeline of cheap static checks plus optional, real
compiler/run-time verification.

myc treats C source as **untrusted input**: it is never passed through a
shell. Source goes in via stdin; the compiler is always launched with an
explicit `program + argv[]`.

> myc is a best-effort safety net, **not** a proof of correctness. See
> [Assurance](#assurance) for exactly what each result does and does not mean.

## How it works

```
scan includes (whitelist)        -> warning (non-blocking)
lint (heuristic memory-safety)   -> observations (non-blocking)
gcc -E (preprocess, argv-exact)  -> preprocessed source
scan "# 1" markers (depth 2)     -> warning (non-blocking)
scan denylisted calls            -> warning (non-blocking)
gcc -c -O2 -Wall -Wextra -Werror -pedantic + memory-tier warnings
    (-Warray-bounds, -Wstringop-overflow, -Wuse-after-free, ...)
                              -> COMPILE_ERROR on violation
gcc -c -O2 -fanalyzer        (--analyze, optional) -> COMPILE_ERROR
gcc -c -O2 -DMYC_CHECKED=1   (--checked, optional) -> L4 SPATIAL (fat-pointer bounds)
clang -O0 -fsanitize=address,undefined (--run, optional) -> L3 RUNTIME
driver-generator (--driver, optional) -> L3 RUNTIME on contract edge cases
metamorphic -O0 vs -O2 (--metamorphic, optional) -> UB / toolchain-sensitive
negative-space (--negative, optional) -> "missing pattern" observations
quorum (--quorum, optional) -> cross-backend agreement
--require-complete -> verification gap = CI failure (MYC-INCOMPLETE-*)
```

The hard gates come only from **semantic evidence** (compiler diagnostics,
sanitizer reports, fat-pointer bounds checks, Frama-C, Fil-C). Everything else
is a warning or a non-blocking observation.

## Usage

```
myc check <file.c> [--json] [--analyze] [--strict] [--no-lint] [--cwd DIR]
myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc] [--driver]
myc check <file.c> [--metamorphic] [--negative] [--quorum] [--require-complete]
myc check <file.c> [--json-summary] [--timeout MS] [--output-cap BYTES] [--no-cache]
myc check -            [--json] [--analyze] [--strict] [--no-lint]   (source from stdin)
myc context <file.c> [--finding-id ID] [--budget 4K|8K|16K] [gate flags...]
myc policy
myc probe
myc version
mcp.exe               (MCP server; see docs/mcp-tools.md)
```

Flags:

- `--analyze` — also run `gcc -fanalyzer`.
- `--checked` — build with `-DMYC_CHECKED=1`. `MYC_BUF` becomes a fat-pointer
  struct and every access must go through `MYC_AT` (a direct `b[i]` is a
  compile error). A clean build ⇒ **L4 SPATIAL** for `MYC_BUF` buffers.
- `--run` — compile with Clang + ASan/UBSan and run under controlled
  execution. Clean (exit 0, no sanitizer report) ⇒ **L3 RUNTIME**.
- `--run-stdin FILE` — provide stdin to the verification build.
- `--prove` — run Frama-C Eva (optional backend).
- `--filc` — run under Fil-C (optional backend, Linux/x86_64).
- `--driver` — generate and run a driver that exercises contract-tagged
  functions at edge cases (optional backend).
- `--metamorphic` — build and run the source twice (`-O0` vs `-O2`) and
  compare results; a discrepancy signals UB / toolchain-sensitive code.
- `--negative` — negative-space analysis: mine "missing patterns" (e.g. an
  unchecked `malloc`), as confidence-scored observations.
- `--quorum` — compare all requested backends; report clean / conflict /
  inconclusive agreement.
- `--require-complete` — treat verification gaps as CI failures (emits
  `MYC-INCOMPLETE-*` debt), never silent silence.
- `--json-summary` — compact JSON for LLM agents (verdict, assurance vector,
  receipt, finding, gate matrix, debt).
- `--timeout MS` — per-process timeout (0–600000, default 30000).
- `--output-cap BYTES` — cap captured child output (0–104857600, default 1 MiB).
- `--strict` — extra strict warnings (`-Wconversion`, `-Wsign-conversion`, …).
- `--no-lint` — disable the heuristic memory-safety lint.
- `--no-cache` — disable the incremental evidence cache (replay of identical
  input + scenario + tool runs from `.myc/evidence_cache.json`).
- `--budget N` — (with `context`) target package size in tokens: `4K`, `8K`,
  `16K` (default `8K`). Sections are dropped in priority order when over
  budget, and `context_sha256` stays deterministic across budgets.
- `--budget-contract JSON` — an explicit **assurance budget contract**
  (SOL-30): a target per gate plus optional time/output limits, e.g.
  `'{"required":{"runtime":"clean"},"max_time_ms":10000}'`. myc never
  silently picks a weaker recipe: a gate required `clean` that was not run
  / unavailable / found findings makes the target unmet
  (`MYC-INCOMPLETE-BUDGET-UNMET`), the verdict becomes `INCONCLUSIVE`
  (unless a real bug already set it), and the report lists exactly which
  dimension was sacrificed.
- `--no-assumptions` — disable the portability **assumption ledger** (Fase 4
  A1): a non-blocking scan that lists which code bets on implementation-
  defined facts (char signedness, int width, bit-field endianness, alignment
  casts, `sizeof` assumptions) next to the host toolchain truth from
  `gcc -dM -E`.
- `--require-assumptions-closed` — treat open assumptions (status
  `observed`/`contradicted`) as a verification gap (`MYC-INCOMPLETE-`
  `ASSUMPTIONS-OPEN`), making the verdict `INCONCLUSIVE` (DS-01 closure
  loop).
- `--assumption-ack id:status,...` — close specific assumptions
  (`declared|tested|contradicted|eliminated|accepted-risk`); the status is
  persisted in `.myc/assumptions.json` so later runs show which assumptions
  are closed, without removing them from the receipt.

## Agent context (`myc context`)

`myc context <file.c>` runs the normal verification pipeline, then emits a
minimal, deterministic **context package** (`myc.context.v1`) for an LLM agent:

- header: source hash, receipt hash, verdict, assurance vector, scenario,
  exact tool identities, and the exact `verify` command to reproduce the run;
- finding slice: the `--finding-id` target (or the confirmed root), the
  containing function's source slice, callers/callees, and its `//@` contracts;
- witness summary and a single **one action** (next-best experiment) with the
  cheapest ranked experiment for the current frontier;
- preservation obligations (what the agent must not change).

The hash covers the full package regardless of `--budget`, so agents can
compare contexts across runs without re-verification.

All optional backends (`--run` / `--checked` / `--filc` / `--driver` /
`--prove` / `--metamorphic`) are **non-blocking**: if a backend is
unavailable, myc still reports the static result plus a diagnostic.

## Policy

- **Headers are free.** The include whitelist is only a conservative default;
  include / marker / call scanning is non-blocking (warnings only).
- **Denylisted calls** (`system`, `exec*`, `popen`, file I/O, network, …) are
  reported as warnings, never as blockers.
- **Hard gates come only from semantic evidence** (compiler, sanitizer,
  fat-pointer, Frama-C, Fil-C). Unknown functions are caught by
  `-Werror=implicit-function-declaration`.

## MCP server

`mcp.exe` exposes myc as an MCP server (JSON-RPC 2.0 over stdio) with six
tools: `check`, `version`, `policy`, `contracts`, `lint`, and `repair` (minimal
template patch for a compile finding). Results use typed `structuredContent`
schemas (`myc.result.v1`, `myc.repair.v1`) plus a text JSON payload. See
`docs/mcp-tools.md`. A dependency-free example client is `mcp_client.py`.

## Learn more

- `docs/quickstart.md` — build, basic check, `MYC_BUF` (L4), `--run`,
  contracts, CI.
- `docs/capabilities.md` — honest gate matrix and limitations (what each flag
  guarantees, and what it does **not**).
- `docs/mcp-tools.md` — MCP server tool reference for coding agents.

## In CI

A minimal GitHub Actions step (after building `myc.exe`):

```yaml
- name: Verify generated C
  shell: bash
  run: |
    for f in src/*.c; do
      myc check "$f" --json || exit 1
    done
```

To guard against regressions where myc silently reports OK on broken input,
run the bundled negative guard (Windows):

```
test\_anti_false_ok.bat
```

It fails the build if any known-bad fixture stops producing a negative
verdict.

## Build

```
build.bat        # MinGW-w64 / GCC  -> myc.exe, mcp.exe, argv_probe.exe
build.sh         # POSIX / GCC       -> myc, mcp, argv_probe
```

Requires a MinGW-w64 / GCC toolchain. Clang (for `--run`), Frama-C (for
`--prove`), and Fil-C (for `--filc`) are optional and only used when present.

## CI

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push to
`master` and on pull requests:

- **Windows**: MSYS2 gcc + LLVM clang → `build.bat` + `test\_regress_run.bat`
- **Linux**: gcc + clang → `bash build.sh` + `bash test/_ci_linux.sh`

Both jobs include:
1. `-Werror` compile check for all source files (catches `unused variable`
   / `unused function` warnings as errors).
2. Pre-flight `prove.c -Werror` check (fast fail for WSL/Frama-C code).
3. `git diff --check` (whitespace / CRLF hygiene).
4. Full trust-core regression: self-dogfooding, fixtures, driver, audit018,
   json_abuse, and MCP smoke tests.

## Release binaries

Pre-built binaries are attached to GitHub Releases. Download the latest
`myc-windows-latest.zip` or `myc-linux-latest.tar.gz` from the Releases page.

## License

MIT License — see [`LICENSE`](LICENSE). Copyright (c) 2026 megaalive.

## Assurance

Results are reported as an **assurance vector** `C1 S0 R1 B0 P0 D0 F0`
(Compile / Static / Runtime / Checked / Proof / Driver / Filc; `0` = n/a,
`1` = clean, `2` = findings, `3` = inconclusive, `4` = observations).

The older scalar L1–L5 labels are **legacy and experimental**: they describe
the strongest backend that happened to run, not a formal guarantee. Treat the
real evidence — the gate matrix, the per-finding `receipt_sha256`, and the
source hash — as the source of truth, not the label.
