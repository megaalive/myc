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
OK (assurance: L1 SANE)
```

> Catatan: gate memori memakai `-c -O2` karena `-Warray-bounds` dan
> `-Wstringop-overflow` hanya aktif saat kompilasi beroptimisasi.

## Penggunaan

```text
myc check <file.c> [--json] [--analyze] [--strict] [--no-lint] [--cwd DIR]
myc check -          [--json] [--analyze] [--strict] [--no-lint] (stdin)
myc policy                                 (tampilkan whitelist header)
myc probe                                  (self-test exact argv)
myc version
```

Flag:
- `--strict` (alias `--level strict`) — tier ketat `-Wconversion
  -Wsign-conversion -Wint-conversion` (BISING, bukan default).
- `--no-lint` — matikan lint memory-safety.
- `--analyze` — tambah gate `-fanalyzer`.

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

- P0–P5 selesai: `myc check` end-to-end, policy non-blocking, lint
  memory-safety (intptr_t/realloc), tier memori gcc + `-fanalyzer`,
  assurance L1 SANE, self-dogfooding (9 source myc OK).
- Belum: eksekusi kode (hanya compile+static), Frama-C (L2), sanitizer build
  (L3), MCP server, corpus abuse lintas platform (WSL tersedia), soak.
- **Arah (2026-08-01)**: fokus = **memory-safety & minim bug**, bukan
  pembatasan library. Policy = warning non-blocking (lihat Kebijakan). Detail
  di `AGENTS.md` dan `docs/rencana-memory-safety.md`.

## Build

```bat
build.bat
```
Menghasilkan `myc.exe` dan `argv_probe.exe` (86 KB + 53 KB).
