# myc — Verifikator C aman untuk agent

`myc` mengecek kode C yang ditulis model (terutama model non-frontier) dengan
pipeline terstruktur. Kode C adalah **data tidak tepercaya** — tidak pernah
masuk ke shell string. Source hanya lewat stdin, gcc dipanggil dengan
`program + argv[]` langsung.

## Prinsip (dari rencana fpagnt)

- structured di model boundary
- canonical di dalam harness
- `program + argv[]` langsung di boundary proses
- policy **sebelum** launch gate
- stdin di-hash (SHA-256), tidak pernah di-log mentah

## Pipeline

```
scan include mentah (whitelist)   -> warning (non-blocking)
lint memory-safety (lint.c)       -> LINT_VIOLATION  (gate hard)
gcc -E (argv eksak, via stdin)    -> preprocessed output
scan penanda "# 1" (depth 2)      -> warning (non-blocking)
scan panggilan fungsi denylist    -> warning (non-blocking)
gcc -c -O2 -Wall -Wextra -Werror -pedantic
  + tier memori (Warray-bounds, stringop-overflow, use-after-free, ...)
                                    -> COMPILE_ERROR
gcc -c -O2 -fanalyzer -o NUL (--analyze, opsional)
                                    -> COMPILE_ERROR
gcc -c -O2 -DMYC_CHECKED (--checked, opsional)
   myc_buf.h fat-pointer; akses       -> L4 SPATIAL; COMPILE_ERROR bila
   langsung b[i] pada MYC_BUF gagal     disiplin fat-struct dilanggar
filc-clang build + run (--filc,      -> L5 FULL (opsional backend;
   opsional; native PATH / WSL)         FILC_VIOLATION bila panic Fil-C)
clang verification build + run      -> L3 RUNTIME (--run, opsional;
   (ASan+UBSan, -O0, eksekusi          RUNTIME_VIOLATION bila ada laporan
   terkendali via proc.c;              sanitizer; --checked juga aktif
   --checked: +MYC_CHECKED fat)        di verification build)
OK (assurance: L1 SANE, L2 PROVEN, L3 RUNTIME, L4 SPATIAL, atau L5 FULL)
```

> Catatan: gate memori memakai `-c -O2` karena `-Warray-bounds` dan
> `-Wstringop-overflow` hanya aktif saat kompilasi beroptimisasi.

## Penggunaan

```text
myc check <file.c> [--json] [--analyze] [--strict] [--no-lint] [--cwd DIR]
myc check <file.c> [--run [--run-stdin FILE]] [--prove] [--checked] [--filc]
myc check -          [--json] [--analyze] [--strict] [--no-lint] (stdin)
myc policy                                 (tampilkan whitelist header)
myc probe                                  (self-test exact argv)
myc version
mcp.exe                                    (MCP server, lihat bawah)
```

Flag:
- `--strict` (alias `--level strict`) — tier ketat `-Wconversion
  -Wsign-conversion -Wint-conversion` (BISING, bukan default).
- `--no-lint` — matikan lint memory-safety.
- `--analyze` — tambah gate `-fanalyzer`.
- `--run` — verification build (clang ASan+UBSan, `-O0`) + eksekusi
  terkendali. Bersih (exit 0, tanpa laporan sanitizer) → assurance **L3
  RUNTIME**. `--run-stdin FILE` memberi stdin untuk program hasil build.
- `--run` bersifat **opsional & non-blocking**: bila clang tidak tersedia atau
  kode bukan program executable (tanpa `main`), myc tetap memberi verdict
  statis (L1) plus diagnostic, tidak menahan.
- `--checked` (D1.2, P8) — bangun source dua kali: produksi normal (T* polos)
  + `-DMYC_CHECKED=1` sehingga `MYC_BUF` (dari `myc_buf.h`) menjadi
  **fat-struct** yang memaksa semua akses lewat `MYC_AT` (akses langsung
  `b[i]` = error kompilasi). Build checked lolos → assurance **L4 SPATIAL**
  untuk buffer MYC_BUF. Non-blocking: source tanpa pola MYC_BUF → skip +
  diagnostic. `--run --checked` memakai verification build fat-pointer di
  bawah ASan (pelanggaran batas → RUNTIME_VIOLATION).
- `--filc` (D4.1, P8) — verification build dengan **Fil-C** (memory-safe C,
  driver `filc-clang`, Linux/X86_64; di Windows otomatis lewat WSL). Run
  bersih tanpa marker panic → assurance **L5 FULL** (backend opsional).
  Panic Fil-C (`filc safety error` dll) → **FILC_VIOLATION**. Non-blocking:
  bila filc-clang tidak tersedia (PATH/WSL), gate di-skip + diagnostic.

## MCP server (P9)

`mcp.exe` mengekspos pipeline myc sebagai **MCP server** (JSON-RPC 2.0 over
stdio, newline-delimited — satu pesan per baris). Agen (harness yang
mendukung MCP) dapat memanggil `myc check` sebagai tool. Tool yang tersedia:

- `check` — verifikasi source C. Args: `source` (string, wajib), `flags`
  (array string opsional: `--run --prove --checked --filc --analyze
  --strict --no-lint`), `cwd` (opsional). Hasil: teks JSON lengkap
  (verdict, assurance L0–L5, error, diagnostics, output gate).
- `version` — versi myc + ketersediaan gcc/clang.
- `policy` — whitelist header default.

MCP server memanggil pipeline **in-process** (myc.c dibangun dengan
`-DMYC_NO_MAIN`); tidak ada shell string, source hanya lewat stdin.
Parser/serializer JSON sendiri (`json.c`, depth cap 64, tanpa dependensi
pustaka).

## Kebijakan (pivot 2026-08-01: memory-safety, bukan pembatasan library)

- **Header bebas**. Whitelist header hanyalah *default konservatif*; semua
  scan policy (include, markers, calls) bersifat **non-blocking** — hanya
  menambah warning, tidak pernah menolak program sah.
- **Denylist fungsi** (`system`, `exec*`, `spawn*`, `fork`, `popen`, file I/O,
  jaringan, `mmap`, env, utas) tetap dilaporkan sebagai warning (safety
  tambahan), bukan penghalang.
- **Gate hard = lint memory-safety** (intptr_t cast → VIOLATION, realloc
  invalidasi → VIOLATION) **+ gate gcc** (tier memori, `-Werror`).
- Fungsi tak dikenal ditangkap gcc via `-Werror=implicit-function-declaration`.

## Aturan untuk coding agent

Saat memanggil gcc atau proses lain dalam kode ini, gunakan process API
dengan `program + argv[]`. **Jangan pernah menyusun shell command string.**
Gunakan `shell` hanya bila sintaks shell memang dibutuhkan, dan jelaskan.

## Status

- P0–P7 selesai: `myc check` end-to-end, policy non-blocking, lint
  memory-safety (intptr_t/realloc), tier memori gcc + `-fanalyzer`,
  assurance L1 SANE, **verification run clang ASan+UBSan → L3 RUNTIME**
  (`--run`, eksekusi terkendali via proc.c, timeout kill pohon proses),
  contract-lite (D1.5) + **Frama-C Eva → L2 PROVEN** (`--prove`),
  self-dogfooding (11 source myc OK) + dogfooding lintas-program
  (`dogfood_ring.c` → L3, lalu L4 dengan `--checked`).
- **P8 D1.2 selesai**: checked-build makro (`myc_buf.h`, `--checked`) →
  assurance **L4 SPATIAL** untuk buffer MYC_BUF; fixture `ok_checked.c` →
  L4, `bad_checked.c` → COMPILE_ERROR, `bad_checked_oob.c` →
  RUNTIME_VIOLATION.
- **P8 D4.1 selesai**: gate **Fil-C** (`--filc`) → **L5 FULL** bila
  filc-clang tersedia (native PATH / WSL) dan run bersih; FILC_VIOLATION
  bila panic. Non-blocking: fixture `ok_filc.c`/`bad_filc_oob.c` di-skip
  bila Fil-C tidak terpasang.
- **P9 selesai**: **MCP server** (`mcp.exe` — JSON-RPC 2.0 over stdio,
  tool `check`/`version`/`policy`, in-process via `myc_run`; parser JSON
  sendiri `json.c`), **soak** (`test/_soak.bat`), dan **corpus abuse**
  (`test/_corpus_abuse.bat` + `test/corpus/*.c` — input ganas tidak boleh
  membuat myc crash/hang). Smoke test MCP: `test/_mcp_smoke.bat`.
- Belum: driver-generator otomatis (D2.2).
- **Arah (2026-08-01)**: fokus = **memory-safety & minim bug**, bukan
  pembatasan library. Policy = warning non-blocking (lihat Kebijakan). Detail
  di `AGENTS.md` dan `docs/rencana-memory-safety.md`.

## Build

```bat
build.bat
```
Menghasilkan `myc.exe`, `mcp.exe`, dan `argv_probe.exe`.
