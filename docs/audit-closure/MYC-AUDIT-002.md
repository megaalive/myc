# MYC-AUDIT-002 closure

Status: **CLOSED di kode** — fix + regresi terverifikasi lokal
(`test/_audit018.sh` SELESAI OK, 2026-08-12); penutupan issue GitHub
menyusul setelah CI membawa regresi ini (persyaratan PR-004: close only
after CI carries the regression).

Catatan proses PR-004: reproduksi terhadap commit lama + pembuktian
kegagalan + reproduksi terhadap HEAD tidak dijalankan ulang di batch ini
(tanpa checkout historis); bukti = root cause terdokumentasi + fixing
commit + regression test yang sudah ada dan terverifikasi lokal.
Referensi: `docs/myc-serious-review-and-roadmap.md` (baris MYC-AUDIT-002),
`docs/audit-history.md` (entri fix trust-core 2026-08-02 + entri
MYC-AUDIT-018/proc_flood).

## Root cause

Di `proc.c` urutan lama: **tulis stdin penuh dulu → baru buat drain
thread**. Jika child mulai mengisi pipe output sebelum selesai membaca
stdin, pipe output penuh → child memblok; parent masih memblok menulis
stdin (pipe stdin penuh) → **deadlock** (keduanya menunggu).

## Trigger

Child yang menulis > ukuran pipe (≈64 KiB) ke stdout/stderr **sebelum**
membaca stdin sampai EOF. Fixture reproduksi: `proc_flood.c` mode
`--child-deadlock` (tulis 1 MiB stdout → baca 1 MiB stdin → tulis 1 MiB
stderr).

## Impact on trust

Verifier **hang** (timeout di sisi caller atau CI hang) pada program yang
sah → denial of service pada pipeline verifikasi; tidak ada verdict yang
dihasilkan.

## Affected versions

Semua build sebelum commit `7be12b5` (2026-08-02).

## Fix

Commit `7be12b5`: drain thread dibuat **sebelum** menulis stdin. Child
dapat selalu mengosongkan pipe outputnya (drain berjalan) sehingga aliran
stdin→child dan child→parent tidak saling memblok.

## Regression test

`test/proc_flood.c` T1 (mengunci fix secara eksplisit — komentar test
menyebut "mengunci fix MYC-AUDIT-002"): child 1 MiB stdout → baca 1 MiB
stdin → 1 MiB stderr, parent kirim 1 MiB stdin, timeout 60.000 ms;
assert `!timed_out`, `exit_code == 0`, `stdout_total == 1 MiB`,
`stderr_total == 1 MiB`. Dijalankan `test/_audit018.sh` (Windows + POSIX)
dan `_regress_run.bat`.

## Why the regression cannot silently pass

Tanpa fix, child memblok di stdout → parent memblok menulis stdin →
`timed_out=1` → `CHECK(!pres.timed_out, ...)` **gagal** dan test exit ≠ 0.
Byte total yang kurang dari 1 MiB juga gagal. Tidak ada jalur di mana
deadlock lolos sebagai sukses.

## Residual risk

Satu pola deadlock (stdout-first) ter-cover; kombinasi ukuran stdin/out/
err dan interleaving lain ditangani matriks P1-T03 (pairwise + Cartesian
terpilih, 10.000 eksekusi per OS).
