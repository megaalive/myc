# AGENTS.md — Aturan proyek myc

## Arah & filosofi (keputusan 2026-08-01)

**Tujuan myc adalah memory-safety dan minimnya bug yang ditimbulkannya — BUKAN
membatasi library yang boleh dipakai user.**

Poin penting:

- User memakai **banyak agent harness yang berbeda**, dan **model yang berbeda**
  di dalam masing-masing harness.
- Permintaan user ke agent beragam: **hardware, game, web, dst.** Setiap domain
  butuh library yang berbeda (mis. untuk hardware butuh syscalls/register,
  untuk game butuh library grafis, dst).
- Karena itu **tidak boleh** membatasi dengan white/black list library/header.
  Header yang user butuhkan harus diizinkan.
- Yang diinginkan user dari myc: **memory-safety** dan **minimal bug** yang
  disebabkan masalah memori (buffer overflow, use-after-free, double-free,
  null deref, integer overflow, dst).

### Konsekuensi terhadap desain saat ini

- Model whitelist/denylist **header** saat ini (15 header) bertentangan dengan
  arah baru. Arah baru: whitelist header hanyalah *default konservatif*,
  bukan larangan mutlak — perlu mekanisme izin/override per proyek.
- Denylist **fungsi berbahaya** (system, exec*, fopen, ...) tetap berguna
  sebagai *safety* tambahan (mis. mencegah model memanggil system tanpa sadar),
  tapi **bukan fokus utama** dan tidak boleh menghalangi program yang sah.
- Focus utama berpindah ke **static analysis untuk memory-safety**:
  memaksimalkan `-fanalyzer`, menangkap jalur yang melewati batas buffer,
  dll.

### Status arah

- Arah baru **sudah diimplementasikan (Fase A, P4+P5, selesai 2026-08-01)**.
- Keputusan user: **policy = non-blocking warning**. Header & fungsi denylist
  tidak lagi menolak program sah. Satu-satunya gate hard = **lint
  memory-safety** (lint.c: intptr_t cast, realloc invalidasi) **+ gate gcc**
  (tier memori `-Werror`, `-fanalyzer`).
- Self-dogfooding sekarang lolos penuh: 9 source myc dicek myc sendiri → OK.
  (Catatan lama "akan selalu VIOLATION karena windows.h" TIDAK berlaku lagi —
  policy non-blocking.)
- Perubahan perilaku: `bad_system.c`, `bad_fopen.c`, `bad_include.c`,
  `bad_macro.c` kini **OK** (hanya warning policy). `bad_intptr.c`,
  `bad_realloc.c` tetap VIOLATION (lint).

## Dogfooding (keputusan 2026-08-01)

Dogfooding myc dilakukan **dua cara**:

1. **Self-dogfooding**: source myc sendiri diperiksa myc. Setelah pivot
   (policy non-blocking), seluruh 9 source myc lulus OK — ini wajib
   dipertahankan di setiap perubahan: tiap source harus tetap OK.
2. **Dogfooding lintas-program**: buat tool/aplikasi lain (C murni) yang
   *realistis* untuk user, ditulis dan diperiksa dengan myc, untuk
   mematangkan jalur "lolos" (OK) myc pada kode yang sah.

Ciri tool dogfooding yang baik:
- Murni API yang sah (console, in-memory), sehingga melatih jalur OK.
- Sebaiknya relevan dengan domain user (hardware/game/web/dst) agar sekaligus
  mengekspos kebutuhan library baru → bahan revisi whitelist.
- Setiap fitur baru di tool tersebut = uji nyata untuk myc.
