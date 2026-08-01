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
scan include mentah (whitelist)   -> VIOLATION
gcc -E (argv eksak, via stdin)    -> preprocessed output
scan penanda "# 1" (depth 2)      -> VIOLATION  (tangkis makro-smuggle)
scan panggilan fungsi denylist    -> VIOLATION
gcc -fsyntax-only -Wall -Wextra -Werror -pedantic
  + -Werror=implicit-function-declaration
                                    -> COMPILE_ERROR
gcc -c -fanalyzer -o NUL (--analyze, opsional)
                                    -> COMPILE_ERROR
OK
```

## Penggunaan

```text
myc check <file.c> [--json] [--analyze] [--cwd DIR]
myc check -          [--json] [--analyze]   (source dari stdin)
myc policy                                 (tampilkan whitelist header)
myc probe                                  (self-test exact argv)
myc version
```

## Kebijakan

- **Whitelist header**: assert, ctype, errno, float, limits, locale, math,
  stdarg, stdbool, stddef, stdint, stdio, stdlib, string, time.
- **Denylist fungsi**: `system`, `exec*`, `spawn*`, `fork`, `popen`, file I/O
  ke disk (`fopen`, `fread`, ...), jaringan, `mmap`, env, utas.
- Fungsi user-defined bebas; fungsi tak dikenal ditangkap gcc via
  `-Werror=implicit-function-declaration`.
- Header yang diizinkan boleh menarik header sistem transitif (perilaku C
  normal); hanya include langsung (depth 2) yang wajib di whitelist.

## Aturan untuk coding agent

Saat memanggil gcc atau proses lain dalam kode ini, gunakan process API
dengan `program + argv[]`. **Jangan pernah menyusun shell command string.**
Gunakan `shell` hanya bila sintaks shell memang dibutuhkan, dan jelaskan.

## Status

- P0–P3 selesai: `myc check` end-to-end jalan.
- Belum: eksekusi kode (hanya compile+static), MCP server, corpus abuse
  lintas platform (WSL tersedia), soak.
- **Arah baru (2026-08-01)**: fokus bergeser dari pembatasan library
  (whitelist/denylist header) ke **memory-safety & minim bug**. Detail di
  `AGENTS.md`. Whitelist saat ini menjadi *default konservatif*, bukan
  larangan mutlak; denylist fungsi tetap ada sebagai safety tambahan.

## Build

```bat
build.bat
```
Menghasilkan `myc.exe` dan `argv_probe.exe` (86 KB + 53 KB).
