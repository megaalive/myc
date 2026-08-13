# MYC-AUDIT-001 closure

Status: **CLOSED di kode** — fix + regresi terverifikasi lokal
(`test/_audit018.sh` SELESAI OK, 2026-08-12); penutupan issue GitHub
menyusul setelah CI membawa regresi ini (persyaratan PR-004: close only
after CI carries the regression).

Catatan proses PR-004: reproduksi terhadap commit lama + pembuktian
kegagalan + reproduksi terhadap HEAD tidak dijalankan ulang di batch ini
(tanpa checkout historis); bukti = root cause terdokumentasi + fixing
commit + regression test yang sudah ada dan terverifikasi lokal.
Referensi: `docs/myc-serious-review-and-roadmap.md` (baris MYC-AUDIT-001),
`docs/audit-history.md` (entri fix trust-core 2026-08-02).

## Root cause

Di `proc.c` (jalur POSIX), `pthread_t` dari drain thread stdout/stderr
**dibuang** — parent tidak menyimpan handle thread. Setelah child berhenti,
parent langsung menyalin buffer hasil sementara drain thread masih bisa
menulis ke buffer yang sama → **race / use-after-scope** (thread menulis ke
memori yang sudah dianggap milik hasil).

## Trigger

Program POSIX dengan output cukup besar sehingga drain thread masih aktif
saat parent mentransfer hasil (produksi: run gate `--run`, canary,
metamorphic, driver di Linux/WSL).

## Impact on trust

Race/UAF di **verifier sendiri** (bukan program yang diperiksa): output
evidence bisa korup (byte hilang/tercampur) atau myc crash → hasil
verifikasi tidak dapat dipercaya / verifier tidak tersedia.

## Affected versions

Semua build sebelum commit `7be12b5` (2026-08-02, "fix: trust core
stabilization fase 1 partial (MYC-AUDIT-001/002/003/005/007/011)").
Rilis terdampak: semua versi sebelum `v2026-08-02`.

## Fix

Commit `7be12b5`: simpan `pthread_t to`/`te`, periksa return
`pthread_create`, dan panggil `pthread_join` keduanya **setelah** child
berhenti dan pipe ditutup — baru salin buffer hasil ke struct milik parent.
Drain thread dijamin selesai sebelum hasil dibaca.

## Regression test

- `test/proc_flood.c` (dijalankan `test/_audit018.sh` + `_regress_run.bat`
  + CI Linux/Windows): stress drain — child tulis 1 MiB stdout + 1 MiB
  stderr + baca 1 MiB stdin; byte total + prefix/tail harus persis.
- `test/stress_threads.c`: 8×200 `myc_run` paralel (drain concurrent).
- `test/_audit018.sh` blok 6b: varian ASan (`audit_lampiran_asan`) — build
  ASan menangkap use-after-free bila regresi drain/join muncul.

## Why the regression cannot silently pass

`proc_flood` T1/T2 menegaskan `stdout_total`/`stderr_total` dan isi
prefix+tail **persis**; race buffer menghasilkan byte hilang/tercampur →
`[FAIL]`. Varian ASan: UAF → runtime abort → exit ≠ 0 → `run_built` gagal.
`stress_threads` menegaskan determinisme output lintas thread (kehilangan
data drain terlihat sebagai beda total byte).

## Residual risk

Race adalah fenomena probabilistik — stress ini memperbesar peluang deteksi
tetapi bukan bukti matematis. Penguatan lanjut: P1-T03 (deadlock matrix
10.000 eksekusi) dan P2-T05 (mutation testing proc runner).
