# Capabilities & Limitations

myc checks C source in layers. Every gate produces **evidence**; the final
verdict is derived from typed gate status and reported as an **assurance
vector** `C S R B P D F` (Compile / Static / Runtime / Checked / Proof /
Driver / Filc; `0` = n/a, `1` = clean, `2` = findings, `3` = inconclusive).

> myc is a best-effort safety net, **not** a proof of correctness. The real
> evidence is the gate matrix, the per-finding `receipt_sha256`, and the source
> hash — not the label.

## Gate matrix

| Gate                | Flag       | Requires            | What it guarantees                                  | Notes / limits                                                              |
| ------------------- | ---------- | ------------------- | --------------------------------------------------- | --------------------------------------------------------------------------- |
| preprocess          | (always)   | gcc                 | source compiles under `gcc -E`                     | warnings non-blocking                                                        |
| lint                | (always)   | —                   | memory-safety *observations* (confidence-scored)    | **Non-blocking** (MYC-AUDIT-014); text heuristic, not proof                  |
| compile             | (always)   | gcc                 | `-Werror` clean under `-O2 -Wall -Wextra -pedantic` + memory tier (`-Warray-bounds`, `-Wstringop-overflow`, `-Wuse-after-free`, `-Wfree-nonheap-object`, `-Wformat-overflow`, …) | **hard gate**                                                       |
| include-marker-call | (always)   | —                   | whitelist / `# 1` depth-2 / denylist *warnings*    | **Non-blocking** (intended as extra signal, never a blocker)                |
| analyzer            | `--analyze`| gcc                 | `gcc -fanalyzer` clean                              | extra static analysis                                                        |
| checked             | `--checked`| gcc                 | `MYC_BUF` fat-pointer bounds ⇒ **L4 SPATIAL**       | covers **only `MYC_BUF` buffers**; plain `malloc` arrays not covered         |
| runtime             | `--run`    | clang + ASan/UBSan  | clean run under sanitizers ⇒ **L3 RUNTIME**        | optional; non-blocking if clang absent                                       |
| metamorphic         | `--metamorphic` | clang + ASan  | `-O0` vs `-O2` discrepancy ⇒ UB / toolchain-sensitive | optional; non-blocking if clang absent; divergence ≠ proof of bug          |
| divergence          | `--divergence`  | gcc+clang+[tcc] × {-O0,-O2} | sanitizer divergence across toolchains ⇒ **hard RUNTIME_VIOLATION** (toolchain-sensitive); semantic/diagnostic divergence ⇒ observation | optional; non-blocking if toolchain absent; cells without ASan never claim sanitizer evidence |
| negative            | `--negative` | —                | "missing pattern" observations (e.g. unchecked alloc) | **Non-blocking** (MYC-AUDIT-014); confidence-scored                        |
| quorum              | `--quorum` | —                   | cross-backend agreement (clean / conflict / inconclusive) | optional; extra signal, never a blocker                                |
| require-complete    | `--require-complete` | —        | verification gap = CI failure (`MYC-INCOMPLETE-*`) | makes verdict INCONCLUSIVE when debt exists                                 |
| driver              | `--driver` | clang + ASan        | edge-case harness on contract-tagged functions     | optional; non-blocking if clang absent / no contracts                        |
| exhaustive          | `--exhaustive` | clang + ASan   | full enumeration of a **declared finite domain** ⇒ **P1 EXHAUSTIVE** (proof *within* that domain) | only for functions with `//@ requires n >= LO && n <= HI`; domain firewall rejects widths > 1024/dim or products > 1e6; **never** claims beyond the declared domain; DS-03 state detects SCOPE_LAUNDERING when the domain is narrowed across runs |
| prove               | `--prove`  | Frama-C (Eva)       | abstract interpretation ⇒ **L2 EVA**               | optional; non-blocking if Frama-C absent (typically Linux)                   |
| filc                | `--filc`   | Fil-C               | memory-safe execution ⇒ **L5 FILC**                | optional; non-blocking if Fil-C absent (Linux/x86_64)                       |

> Registry: daftar kanonik gate/flag/tool ada di `capabilities.json` (single
> source of truth). `test/_cap_sync.sh` memverifikasi doc ini sinkron dengan
> registry dan implementasi.

## Honest limitations

- **No formal proof.** A clean run means "no evidence of this class of bug
  with the available toolchains", not "correct".
- **L1–L5 scalar labels are legacy/experimental.** Prefer the assurance
  vector.
- **`MYC_BUF` only.** The L4 SPATIAL guarantee applies *only* to buffers
  declared with `MYC_BUF(...)` and accessed via `MYC_AT(...)`. Plain C arrays
  (even correct ones) get L1/L3 only. Also, due to the anonymous-struct design
  of `myc_buf.h`, you **cannot** pass a `MYC_BUF` variable to another function
  or assign one `MYC_BUF` to another — keep the buffer in one scope and access
  it via `MYC_AT`. (See `docs/quickstart.md` for the idiomatic pattern.)
- **`--run` needs Clang + ASan.** On Windows the ASan runtime DLL must be
  resolvable at run time.
- **Denylist is a warning, not a blocker.** Calls to `system`, `exec*`,
  `popen`, file I/O, networking, etc. are reported but never reject the program.
- **Source is untrusted input.** It is never passed through a shell; the
  compiler is always launched with an explicit `program + argv[]`.

## What myc is NOT

- Not a replacement for cppcheck / clang-tidy breadth (no deep data-flow
  rules beyond what gcc/anitizer/Frama-C provide).
- Not a substitute for human review or testing.
- Not a sandbox: it analyzes and (optionally) runs the code; it does not
  confine the program beyond the sanitizer/OS job-object limits used for
  timeouts.
