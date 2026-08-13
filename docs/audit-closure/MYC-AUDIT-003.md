# MYC-AUDIT-003 closure

Status: **CLOSED di kode** — fix dua bagian terverifikasi + regresi
terverifikasi lokal (`test/_audit018.sh` SELESAI OK, 2026-08-12;
`test/_ci_linux.sh` membawa regresi driver POSIX); penutupan issue GitHub
menyusul setelah CI membawa regresi ini (persyaratan PR-004: close only
after CI carries the regression).

Catatan proses PR-004: reproduksi terhadap commit lama + pembuktian
kegagalan + reproduksi terhadap HEAD tidak dijalankan ulang di batch ini
(tanpa checkout historis); bukti = root cause terdokumentasi + fixing
commit (atribusi `7aae6df` diverifikasi via `git show` — memuat perubahan
TMPDIR di driver.c) + regression test yang sudah ada dan terverifikasi
lokal.
Referensi: `docs/myc-serious-review-and-roadmap.md` (baris MYC-AUDIT-003),
`docs/audit-history.md` (entri fix trust-core 2026-08-02; entri
MYC-AUDIT-027 "bug portabilitas POSIX (kelas MYC-AUDIT-003)").

## Root cause

Dua bagian terpisah:

1. **`proc.c` (exec-vs-exit-127):** parent tidak bisa membedakan `execvp`
   gagal dari program yang memang `exit(127)` — keduanya tampil sebagai
   exit 127 → klasifikasi error salah.
2. **`run.c` / `driver.c` (temp dir relatif):** fallback base temp dir
   `"."` menghasilkan path **relatif**; setelah child `chdir(tmp_dir)`
   path executable relatif rusak → gate run/driver gagal jalan di POSIX
   (ok_driver jadi INCONCLUSIVE padahal build sukses).

## Trigger

- (1) Executable hilang / tidak dapat dieksekusi di POSIX.
- (2) Run/driver gate di POSIX (WSL) ketika `TEMP`/`TMPDIR` tidak ter-set
  (fallback `"."`).

## Impact on trust

- (1) Error transport salah diklasifikasikan sebagai hasil program.
- (2) Backend yang sehat terlihat gagal (`INCONCLUSIVE` palsu) → assurance
  runtime/driver tidak pernah tercapai di Linux — hasil jujur tapi
  capability hilang; di sisi lain "exec failed" yang nyata bisa lolos
  sebagai hasil valid.

## Affected versions

- (1)+(2)-run.c: sebelum commit `7be12b5` (2026-08-02).
- (2)-driver.c: sebelum commit `7aae6df` (2026-08-04, MYC-AUDIT-027 —
  `drv_make_temp_dir` fallback `TEMP → TMPDIR → /tmp` + canonicalize
  relatif via `my_getcwd`, mirror `make_temp_dir` run.c).

## Fix

- Commit `7be12b5` — `proc.c`: exec-error pipe dengan `FD_CLOEXEC`; child
  menulis `errno` saat `execvp` gagal, parent membacanya untuk
  mengklasifikasikan `MYC_ERR_EXECUTE_FAILED` dengan tepat. `run.c`:
  fallback `/tmp` (POSIX) / `C:/Temp` (Windows) + canonicalize via
  `getcwd` bila base masih relatif.
- Commit `7aae6df` — `driver.c`: `drv_make_temp_dir` mirror fix yang sama.

## Regression test

- `test/audit_lampiran.c` T1: exec failure vs aplikasi exit 127
  (mode `--child-exit127` + child tidak dapat dieksekusi) — diklasifikasi
  tepat (`MYC_ERR_EXECUTE_FAILED` vs exit 127 valid).
- `test/_ci_linux.sh`: gate driver di POSIX — `ok_driver --driver` harus
  `L3 RUNTIME` dengan harness sha IDENTIK lintas platform
  (`6919dfb9...`) → membuktikan temp path absolut + run sukses di POSIX.
- `test/_regress_run.bat`: regresi driver penuh (ok_driver L3,
  bad_driver_oob DRIVER_VIOLATION).

## Why the regression cannot silently pass

- Exec-vs-127: fixture `--child-exit127` memaksa dua kasus yang
  sebelumnya tercampur; klasifikasi salah → assert `[FAIL]`.
- Temp dir POSIX: bila fallback relatif kembali, `ok_driver` di
  `_ci_linux.sh` kembali `INCONCLUSIVE` + `funcs: 0` (pola bug lama) →
  assert `[FAIL]`; harness sha lintas platform juga mengunci path absolut
  yang identik.

## Residual risk

Path dengan karakter non-ASCII/spasi di POSIX belum di-stress penuh di
matriks ini (P1-T05 executable discovery + P6-T02 platform-hostile
menutupnya). Windows Job Object / PATH lookup tetap diuji terpisah
(`argv_probe`, `myc probe`).
