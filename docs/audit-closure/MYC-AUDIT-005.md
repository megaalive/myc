# MYC-AUDIT-005 closure

Status: **CLOSED di kode** — fix terverifikasi + regresi deterministik +
varian ASan terverifikasi lokal (T8 audit_lampiran OK di
`test/_audit018.sh`, 2026-08-12; lane ASan skip jujur bila toolchain tak
punya `-fsanitize=address`); penutupan issue GitHub menyusul setelah CI
membawa regresi ini (persyaratan PR-004: close only after CI carries the
regression).

Catatan proses PR-004: reproduksi terhadap commit lama + pembuktian
kegagalan + reproduksi terhadap HEAD tidak dijalankan ulang di batch ini
(tanpa checkout historis); bukti = root cause terdokumentasi + fixing
commit + regression test yang sudah ada dan terverifikasi lokal.
Referensi: `docs/myc-serious-review-and-roadmap.md` (baris MYC-AUDIT-005),
`docs/audit-history.md` (entri fix trust-core 2026-08-02),
`test/audit_lampiran.c` (T8), `test/_audit018.sh` (blok 6b).

## Root cause

Di `compile.c`, fingerprint dibangun dengan `snprintf` ke buffer tetap
`buf[512]`. Bila material fingerprint (path gcc + cwd + policy + flags)
> 511 byte, `snprintf` **truncated** dan mengembalikan panjang yang
*seharusnya* ditulis — bukan panjang aktual di buffer. Nilai itu dipakai
sebagai length ke `sha256_hex(buf, n, ...)` → **out-of-bounds read** di
luar `buf[512]`.

## Trigger

Cwd atau path executable yang panjang (material fingerprint > 512 byte) —
mis. direktori proyek bertingkat dalam / CI runner dengan path panjang;
reproduksi test memakai cwd 3.000 byte.

## Impact on trust

OOB read di verifier sendiri → crash/ASan abort, atau hash fingerprint
**sampah** (membaca stack garbage) → identitas backend/evidence korup →
receipt/cache identity tidak dapat dipercaya (melanggar INV-004/013).

## Affected versions

Semua build sebelum commit `7be12b5` (2026-08-02). Fingerprint version
di-bump `v7` → `v8` pada fix.

## Fix

Commit `7be12b5`: `snprintf(NULL, 0, ...)` dulu untuk menghitung panjang
exact, alokasi dinamis sesuai panjang, baru `sha256_hex` pada buffer yang
cukup. Tidak ada lagi truncation diam-diam pada material fingerprint.

## Regression test

- `test/audit_lampiran.c` T8 (`--fp-long`): cwd 3.000 byte → fingerprint
  harus tetap 64-hex dan **deterministik** (dua run identik). Menangkap
  hash sampah akibat OOB/stack garbage.
- `test/_audit018.sh` blok 6b: varian **ASan** `audit_lampiran_asan
  --fp-long` — bila regresi OOB read muncul, ASan meng-abort proses
  (exit ≠ 0) → `run_built` menandai `[FAIL]`. Skip jujur bila toolchain
  tanpa ASan (bukan klaim).
- Dijalankan CI Linux + Windows (`_regress_run.bat` + `_ci_linux.sh`).

## Why the regression cannot silently pass

Dua lapis independen: (1) determinisme — fingerprint yang membaca stack
garbage menghasilkan nilai yang berubah antar run → `r1 != r2` →
`[FAIL]`; (2) ASan — OOB read langsung meng-abort proses sebelum
perbandingan, exit code ≠ 0 → `[FAIL]`. Lapisan mana pun yang aktif
mendeteksi regresi.

## Residual risk

ASan lane di-skip bila toolchain tidak menyediakan `-fsanitize=address`
(dokumentasi eksplisit, bukan silent). Jalur lain yang memakai
`snprintf`-ke-buffer-tetap di verifier (receipt buf[4096], gbuf[64])
tidak di-stress panjang penuh di test ini; P2-T03 (parser fuzzing) dan
P6-T03 (architecture assumptions, truncation) menutup kelas bug ini.
