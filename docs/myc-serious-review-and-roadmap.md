# Review Serius, Rencana Perbaikan, dan Gagasan Pembeda untuk `myc`

> **Tujuan dokumen:** menjadikan `myc` benar-benar ringan, dapat dipercaya, terhormat, dan disegani sebagai alat verifikasi keamanan kode C—bukan sekadar wrapper compiler, kumpulan regex, atau generator label assurance.
>
> **Tanggal audit:** 2 Agustus 2026  
> **Artefak yang diaudit:** `myc-master(1).zip`  
> **SHA-256 arsip:** `43e4e57492be738d57abe23349714d885665fd7b413fb0efd2e30a8d2edf8fc3`

---

## Daftar Isi

1. [Ringkasan Eksekutif](#1-ringkasan-eksekutif)
2. [Kesimpulan Singkat yang Jujur](#2-kesimpulan-singkat-yang-jujur)
3. [Ruang Lingkup dan Metode Audit](#3-ruang-lingkup-dan-metode-audit)
4. [Hal yang Sudah Sangat Baik](#4-hal-yang-sudah-sangat-baik)
5. [Temuan Kritis yang Harus Diperbaiki Lebih Dahulu](#5-temuan-kritis-yang-harus-diperbaiki-lebih-dahulu)
6. [Masalah Mendasar pada Model Assurance](#6-masalah-mendasar-pada-model-assurance)
7. [Review per Modul](#7-review-per-modul)
8. [Arsitektur Baru yang Disarankan](#8-arsitektur-baru-yang-disarankan)
9. [Gagasan Pembeda yang Tidak Lazim](#9-gagasan-pembeda-yang-tidak-lazim)
10. [Strategi Agar Tetap Sangat Ringan](#10-strategi-agar-tetap-sangat-ringan)
11. [Rencana Eksekusi Bertahap](#11-rencana-eksekusi-bertahap)
12. [Rencana Pengujian yang Benar-Benar Menguji](#12-rencana-pengujian-yang-benar-benar-menguji)
13. [Kriteria Rilis](#13-kriteria-rilis)
14. [Posisi Produk dan Identitas Teknis](#14-posisi-produk-dan-identitas-teknis)
15. [Prioritas Akhir](#15-prioritas-akhir)

---

# 1. Ringkasan Eksekutif

`myc` memiliki fondasi dan arah yang **jauh lebih menarik** daripada kebanyakan tool kecil sejenis:

- ditulis dalam C;
- tidak membawa runtime besar;
- boundary proses memakai `program + argv[]`;
- source dikirim lewat stdin;
- mempunyai beberapa backend independen;
- mempunyai MCP server in-process;
- memiliki parser JSON sendiri;
- memiliki checked-buffer mode;
- mencoba menggabungkan compile-time, static analysis, runtime instrumentation, contract, dan generated driver;
- ukuran binary lokal hanya sekitar **105 KB** setelah build Linux dengan patch kompatibilitas minimal.

Itu modal yang sangat kuat.

Namun, pada kondisi source saat ini, `myc` **belum layak mengeluarkan klaim assurance kuat**. Penyebab utamanya bukan kurang fitur, melainkan beberapa fondasi kepercayaan yang belum benar:

1. runner proses POSIX memiliki race, potensi deadlock, dan thread yang tidak di-join;
2. eksekusi runtime di POSIX gagal dengan exit `127`, tetapi hasil akhirnya tetap dapat menjadi `OK`;
3. checked build dapat memberi `L4 SPATIAL` walaupun runtime yang diminta sebenarnya tidak pernah berjalan;
4. fingerprint memiliki potensi out-of-bounds read;
5. API menerima `file_path`, tetapi pipeline tetap mengasumsikan `source` tersedia;
6. diagnostic disimpan dalam global static ring buffer sehingga API tidak reentrant dan tidak thread-safe;
7. parser JSON menerima sejumlah JSON invalid dan tidak aman terhadap embedded NUL;
8. label `L2 PROVEN`, `L4 SPATIAL`, dan terutama `L5 FULL` melebihi bukti yang benar-benar dikumpulkan;
9. banyak backend mendeteksi hasil dengan mencari teks manusia, bukan output mesin yang stabil;
10. banyak kegagalan infrastruktur diklasifikasikan sebagai “skip”, bukan sebagai verifikasi yang tidak lengkap.

Masalah terpenting bukan “apakah myc menemukan bug”, tetapi:

> **Apakah pengguna dapat mempercayai bahwa `OK` benar-benar berarti semua gate yang diminta telah bekerja sesuai scope yang dilaporkan?**

Saat ini jawabannya belum.

Berita baiknya: masalah tersebut **dapat diperbaiki tanpa membuat myc bloat**. Justru bila diperbaiki dengan desain yang tepat, `myc` dapat menjadi tool kecil yang unik: bukan tool yang mengklaim paling pintar, melainkan tool yang paling **jujur, deterministik, dapat diaudit, dan dapat mereproduksi buktinya**.

---

# 2. Kesimpulan Singkat yang Jujur

## Penilaian saat ini

| Aspek | Penilaian |
|---|---|
| Arah produk | Sangat menjanjikan |
| Disiplin minimalisme | Kuat |
| Struktur modul | Cukup baik |
| Boundary shell | Baik secara konseptual |
| Portabilitas | Belum matang |
| Process runner | Kritis; perlu ditulis ulang sebagian |
| Ketepatan verdict | Belum dapat dipercaya |
| Model assurance | Perlu didesain ulang |
| Static lint internal | Terlalu heuristik untuk hard gate |
| Runtime verification | Konsep baik, implementasi belum solid |
| Contract support | Berguna, tetapi klaim terlalu kuat |
| MCP | Fondasi baik, schema hasil perlu dibenahi |
| Thread safety / reentrancy | Belum aman |
| Test engineering | Belum cukup untuk tool verifikasi |
| Potensi menjadi tool disegani | Tinggi, bila fokus pada kejujuran bukti |

## Rekomendasi utama

Jangan menambah backend baru dahulu.

Bekukan fitur dan lakukan satu fase khusus:

> **Trust Core Stabilization**

Urutannya:

1. perbaiki process broker;
2. perbaiki klasifikasi status backend;
3. hapus scalar assurance ladder;
4. jadikan semua hasil sebagai evidence ledger;
5. hilangkan mutable global state;
6. perketat JSON dan input boundaries;
7. bangun test adversarial lintas platform;
8. baru setelah itu mengembangkan analisis baru.

Jika urutan ini diikuti, `myc` akan memperoleh reputasi karena **hasilnya dapat dipercaya**, bukan karena memiliki daftar fitur yang panjang.

---

# 3. Ruang Lingkup dan Metode Audit

## 3.1. Isi repositori

Arsip berisi sekitar:

- 84 file;
- 54 file `.c`;
- 15 file `.h`;
- sekitar 8.816 baris C;
- sekitar 765 baris header;
- dokumentasi README, AGENTS, dan dokumen desain;
- fixture static, runtime, checked-buffer, Fil-C, Frama-C, contract, driver, MCP, soak, dan corpus abuse.

Modul utama yang diperiksa:

- `myc.c`
- `compile.c`
- `proc.c`
- `run.c`
- `prove.c`
- `filc.c`
- `driver.c`
- `contract.c`
- `lint.c`
- `scanner.c`
- `policy.c`
- `report.c`
- `json.c`
- `mcp.c`
- `myc_buf.h`
- header publik dan test fixture.

## 3.2. Metode

Audit dilakukan dengan:

1. membaca implementasi per modul;
2. memeriksa aliran request → gate → verdict → report;
3. memeriksa lifetime memory dan ownership;
4. memeriksa boundary process dan pipe;
5. memeriksa portabilitas Windows/POSIX;
6. memeriksa apakah klaim README sesuai dengan bukti implementasi;
7. membangun binary Linux dengan patch kompatibilitas minimal;
8. menjalankan fixture positif dan negatif;
9. membandingkan output JSON dengan perilaku aktual;
10. mencari kondisi “requested but silently skipped” dan “failed but reported OK”.

## 3.3. Build lokal yang diperlukan

Source tidak langsung dapat dibangun bersih di Linux karena:

- `_strdup` digunakan tanpa abstraction POSIX;
- feature macro POSIX tidak disediakan;
- simbol seperti `clock_gettime`, `CLOCK_MONOTONIC`, `kill`, dan `nanosleep` tidak tersedia di mode compiler tertentu tanpa feature macro;
- build resmi hanya berupa `build.bat`.

Build lokal berhasil dengan penyesuaian semacam:

```sh
-D_POSIX_C_SOURCE=200809L -D_strdup=strdup -pthread
```

Binary hasil build lokal berukuran sekitar:

```text
105,680 bytes
```

Ini bukti bahwa target “sangat ringan” realistis.

---

# 4. Hal yang Sudah Sangat Baik

Sebelum membahas masalah, penting menegaskan bagian yang layak dipertahankan.

## 4.1. Tidak menyusun source menjadi shell command

Prinsip:

```text
program + argv[] + stdin
```

adalah keputusan yang benar.

`myc` tidak menjadikan source sebagai fragmen shell. Ini membuat boundary proses:

- lebih deterministik;
- lebih mudah diaudit;
- lebih mudah diuji;
- lebih portable;
- lebih sulit rusak oleh quoting;
- lebih cocok untuk dipanggil agent.

Prinsip ini harus dipertahankan sebagai invariant arsitektur.

## 4.2. Modularitas backend sudah terlihat

Pemisahan:

- compile;
- runtime sanitizer;
- proof;
- Fil-C;
- checked buffer;
- generated driver;
- report;
- process runner;
- MCP;

memberi fondasi baik untuk refactor tanpa rewrite total.

## 4.3. Dependency footprint sangat kecil

`myc` tidak membawa:

- Electron;
- Python runtime;
- JVM;
- database;
- server;
- framework parser besar;
- package manager runtime.

Ini bukan hanya soal ukuran. Ini juga memperkecil:

- surface area;
- waktu startup;
- biaya distribusi;
- nondeterminisme;
- supply-chain dependency;
- beban pemeliharaan.

## 4.4. Sudah ada upaya self-dogfooding

Repositori memiliki:

- fixture baik;
- fixture buruk;
- corpus abuse;
- soak;
- MCP interop;
- driver fixture;
- checked-buffer fixture;
- runtime fixture.

Masalahnya bukan tidak ada test. Masalahnya adalah test belum menargetkan kegagalan fondasi yang paling berbahaya. Struktur test yang ada tetap dapat dipakai dan diperkuat.

## 4.5. Checked-buffer adalah ide yang bernilai

`MYC_BUF` adalah arah yang bagus karena:

- production build dapat tetap tipis;
- checked build dapat membawa metadata;
- coding agent dapat diberi konvensi eksplisit;
- pelanggaran disiplin akses dapat dibuat compile-time visible.

Yang perlu diperbaiki adalah:

- representasi metadata;
- coverage;
- type consistency;
- multiplication overflow;
- semantics parity;
- klaim assurance.

## 4.6. MCP in-process masuk akal

MCP server in-process:

- menghindari spawn per request;
- menjaga startup rendah;
- cocok untuk agent harness;
- tetap dependency-free.

Setelah reentrancy dan schema hasil diperbaiki, ini dapat menjadi salah satu keunggulan utama `myc`.

---

# 5. Temuan Kritis yang Harus Diperbaiki Lebih Dahulu

## 5.1. Ringkasan prioritas

| ID | Severity | Area | Ringkasan | Status |
|---|---|---|---|---|
| MYC-AUDIT-001 | Critical | `proc.c` | Thread drain POSIX tidak di-join; race dan potensi use-after-scope | ✅ SELESAI 2026-08-02 |
| MYC-AUDIT-002 | Critical | `proc.c` | Menulis seluruh stdin sebelum drain output dapat deadlock | ✅ SELESAI 2026-08-02 |
| MYC-AUDIT-003 | Critical | `run.c` / `driver.c` | Path executable relatif + `cwd` temp menyebabkan exit `127` | ✅ SELESAI 2026-08-02 (exec-error pipe + temp path abs) |
| MYC-AUDIT-004 | Critical | verdict | Gate runtime gagal tetapi hasil dapat tetap `OK` | ⏳ TODO |
| MYC-AUDIT-005 | Critical | `compile.c` | `snprintf` length dipakai untuk hash walau buffer terpotong; OOB read | ✅ SELESAI 2026-08-02 |
| MYC-AUDIT-006 | High | assurance | Scalar L1–L5 menggabungkan bukti yang tidak comparable | ⏳ TODO |
| MYC-AUDIT-007 | High | API | `file_path` lolos validasi tetapi pipeline memakai `source == NULL` | ✅ SELESAI 2026-08-02 |
| MYC-AUDIT-008 | High | diagnostics | Static ring buffers membuat hasil tidak reentrant/thread-safe | **? SELESAI 2026-08-02 (arena milik hasil)** |
| MYC-AUDIT-009 | High | `json.c` | Parser menerima JSON invalid dan embedded NUL memotong string | **? SELESAI 2026-08-02 (parser ketat + corpus)** |
| MYC-AUDIT-010 | High | backend status | “Unavailable”, “failed”, “inconclusive”, dan “clean” tercampur |
| MYC-AUDIT-011 | High | POSIX timeout | `kill(-pid)` tanpa process group tidak menjamin child tree mati |
| MYC-AUDIT-012 | High | `myc_buf.h` | Element size tidak disimpan; checked access dapat memakai tipe salah |
| MYC-AUDIT-013 | High | proof claims | Eva alarm/summary diperlakukan sebagai proof kontrak umum |
| MYC-AUDIT-014 | Medium | lint | Heuristik token/text dijadikan hard violation |
| MYC-AUDIT-015 | Medium | portability | `NUL` dipakai di POSIX dan meninggalkan file literal `NUL` |
| MYC-AUDIT-016 | Medium | MCP | JSON document dibungkus sebagai string text, status error tidak konsisten |
| MYC-AUDIT-017 | Medium | output parsing | Marker human-readable mudah spoof dan rapuh terhadap versi/localization |
| MYC-AUDIT-018 | Medium | test | Test dominan Windows dan tidak menguji concurrency/deadlock/OOM |

---

## 5.2. MYC-AUDIT-001 — Drain thread POSIX tidak pernah di-join

**Lokasi:** `proc.c:622-676`

Kode membuat dua thread:

```c
pthread_t to, te;
pthread_create(&to, NULL, drain_thread, &out);
pthread_create(&te, NULL, drain_thread, &err);
```

Tetapi:

- `pthread_t` dibuang;
- tidak ada `pthread_join`;
- fd ditutup oleh parent;
- buffer langsung dipindahkan ke result;
- fungsi segera return;
- objek `out` dan `err` berada di stack.

Akibat yang mungkin:

- thread masih menulis saat result sudah diberikan;
- output belum lengkap;
- race pada `len`, `total`, `truncated`, dan pointer data;
- thread mengakses struktur stack setelah fungsi return;
- crash nondeterministik;
- korupsi heap;
- hasil sanitizer dapat hilang sebagian.

Ini fatal bagi tool verifikasi karena output backend adalah bukti utama.

### Perbaikan

Gunakan lifetime yang eksplisit:

1. simpan kedua `pthread_t`;
2. cek return `pthread_create`;
3. setelah child berhenti, tutup sisi writer yang relevan;
4. `pthread_join` kedua thread;
5. baru transfer buffer ke result;
6. semua error path wajib menutup fd dan join thread yang sudah dibuat.

### Acceptance criteria

- helper child menulis 100 MB ke stdout/stderr bersamaan;
- output dibatasi sesuai cap;
- tidak deadlock;
- total byte benar;
- tail evidence tetap tertangkap;
- ThreadSanitizer tidak menemukan race;
- 10.000 iterasi stabil.

---

## 5.3. MYC-AUDIT-002 — Potensi deadlock akibat urutan stdin/output

**Lokasi:** `proc.c:609-631`

Parent:

1. menulis seluruh stdin;
2. baru memulai thread drain stdout/stderr.

Jika child:

1. menulis output sampai pipe penuh;
2. lalu membaca stdin;

maka:

- child menunggu output pipe dikosongkan;
- parent menunggu stdin pipe menerima data;
- drain thread belum berjalan;
- terjadi deadlock.

### Perbaikan

Pilihan ringan yang baik:

- jalankan drain stdout/stderr sebelum menulis stdin;
- gunakan satu thread writer untuk stdin, atau event loop `poll`;
- versi paling ringan dan deterministik di POSIX: satu loop `poll()` untuk stdin writable + stdout/stderr readable + child status.

Tidak perlu library async.

### Acceptance criteria

Buat helper khusus:

```text
child:
    write > pipe capacity to stdout
    then read 1 MiB stdin
    then write stderr
```

`myc_proc_run` harus selesai tanpa timeout palsu.

---

## 5.4. MYC-AUDIT-003 — Runtime POSIX menjalankan path yang salah

**Lokasi utama:** `run.c:101-145`, `run.c:373-389`

Di POSIX:

- temp dir fallback menjadi `"."`;
- `exe_path` dapat menjadi `./myc_run_PID_N/myc_run`;
- request runtime memakai `cwd = tmp_dir`;
- `argv[0]` tetap path relatif di atas.

Setelah child `chdir(tmp_dir)`, path itu ditafsirkan menjadi:

```text
tmp_dir/./myc_run_PID_N/myc_run
```

yang tidak ada.

Hasilnya `execvp` gagal dan child exit `127`.

### Bukti eksekusi lokal

Fixture baik:

```text
tests/ok_run.c --run
```

menghasilkan:

```text
verdict: OK
assurance: L1 (SANE)
run_exit_code: 127
```

Fixture OOB:

```text
tests/bad_run_oob.c --run
```

juga menghasilkan:

```text
verdict: OK
assurance: L1 (SANE)
run_exit_code: 127
```

Fixture driver OOB:

```text
test/fixtures/bad_driver_oob.c --driver
```

menghasilkan:

```text
verdict: OK
ran_driver: true
driver_cases: 0
diagnostic: driver: run keluar non-zero tanpa laporan sanitizer
```

Ini bukan sekadar bug portabilitas. Ini membuktikan bahwa saat backend tidak bekerja, verdict masih dapat terlihat sehat.

### Perbaikan

- semua temp path harus absolut;
- gunakan `TMPDIR` di POSIX dan API temp native;
- gunakan `mkdtemp()` pada POSIX;
- setelah membuat executable, canonicalize absolute path;
- jika `cwd` diubah, jangan mengandalkan path relatif;
- pisahkan error `exec` dari exit code program menggunakan exec-error pipe dengan `FD_CLOEXEC`.

### Acceptance criteria

- `ok_run.c` benar-benar exit `0`;
- fixture OOB benar-benar menghasilkan sanitizer finding;
- executable path dilaporkan absolut;
- exit `127` yang berasal dari aplikasi dibedakan dari `execvp` gagal.

---

## 5.5. MYC-AUDIT-004 — Requested backend dapat gagal tetapi verdict tetap `OK`

**Lokasi:** `run.c:437-455`, pola serupa pada driver/Fil-C/proof.

Saat runtime exit nonzero tanpa marker sanitizer:

```c
goto out_skip;
```

Lalu komentar menyatakan:

```c
/* Jangan ubah verdict statis; assurance tetap level statis. */
```

Ini mencampurkan dua hal:

- program memang exit nonzero;
- backend sama sekali gagal diluncurkan.

Bahkan bila requested runtime tidak pernah berjalan, hasil static dapat tetap `OK`.

Contoh lebih serius:

```text
bad_checked_oob.c --run --checked
```

menghasilkan lokal:

```text
verdict: OK
assurance: L4 (SPATIAL)
run_exit_code: 127
checked_build_ok: true
diagnostic: verification run: exit=127
```

Artinya satu gate sukses menaikkan label sementara gate lain yang diminta gagal diam-diam. Ini merusak makna assurance.

### Perbaikan

Setiap gate harus memiliki status typed:

```c
typedef enum {
    MYC_GATE_NOT_REQUESTED,
    MYC_GATE_UNAVAILABLE,
    MYC_GATE_INFRA_FAILED,
    MYC_GATE_INCONCLUSIVE,
    MYC_GATE_COMPLETED_CLEAN,
    MYC_GATE_COMPLETED_FINDINGS
} myc_gate_status;
```

Verdict global tidak boleh menghapus status ini.

Untuk CI strict:

```text
requested gate != completed
=> INCOMPLETE_VERIFICATION
=> nonzero exit
```

Untuk mode interaktif:

```text
code verdict may be clean
verification completeness = incomplete
```

Keduanya harus tampil terpisah.

---

## 5.6. MYC-AUDIT-005 — Out-of-bounds read pada fingerprint

**Lokasi:** `compile.c:447-466`

Kode:

```c
char buf[512];
int n = snprintf(buf, sizeof(buf), ...);
sha256_hex(buf, (size_t)n, hex);
```

Menurut kontrak `snprintf`, bila output terpotong, return value adalah panjang yang **seharusnya** ditulis, bukan jumlah byte aktual di buffer.

Jika `n > 511`, `sha256_hex` membaca lebih dari `buf[512]`.

Pemicu dapat berupa:

- path GCC panjang;
- `cwd` panjang;
- gabungan metadata yang melebihi 511 byte.

### Perbaikan

Pilihan ringan:

1. panggil `snprintf(NULL, 0, ...)` untuk menghitung;
2. allocate ukuran exact;
3. tulis canonical fingerprint material;
4. hash;
5. free.

Atau gunakan incremental SHA-256:

```c
sha256_update("v8|gcc:", ...);
sha256_update(gcc_path, strlen(gcc_path));
...
```

Pilihan incremental lebih ringan dan menghindari temporary string.

### Acceptance criteria

- `cwd` 4 KB tidak crash;
- ASan tidak menemukan OOB;
- fingerprint stabil;
- canonical material dapat diekspor untuk audit;
- semua opsi relevan masuk fingerprint.

---

## 5.7. MYC-AUDIT-006 — Ladder L1–L5 tidak valid secara epistemik

Saat ini bukti dianggap seperti urutan total:

```text
L1 SANE
L2 PROVEN
L3 RUNTIME
L4 SPATIAL
L5 FULL
```

Padahal bukti tersebut orthogonal.

Contoh:

- satu runtime input tidak otomatis lebih kuat daripada static proof;
- checked-buffer hanya mencakup objek yang memakai `MYC_BUF`;
- Fil-C clean run hanya membuktikan eksekusi tertentu;
- Eva zero alarm bergantung entry point, abstract domain, model library, dan asumsi;
- compile clean tidak berarti source aman;
- generated driver hanya mencakup kasus yang dibangkitkan.

Mengambil `max(level)` menghilangkan informasi.

### Pengganti yang disarankan: assurance lattice / evidence vector

Contoh ringkas:

```text
C1 S2 R3 B1 P0
```

Dengan dimensi:

| Dimensi | Makna |
|---|---|
| `C` | compile diagnostics |
| `S` | static analysis |
| `R` | runtime observation |
| `B` | checked-buffer coverage |
| `P` | proof obligations |
| `D` | generated-driver coverage |
| `F` | Fil-C execution evidence |

Lebih baik lagi, keluarkan struktur:

```json
{
  "verification": {
    "compile": {
      "status": "completed_clean",
      "tool": "gcc",
      "version": "...",
      "scope": "translation_unit"
    },
    "runtime": {
      "status": "infra_failed",
      "cases": 0
    },
    "checked_buffer": {
      "status": "completed_clean",
      "annotated_buffers": 2,
      "total_candidate_buffers": 7,
      "coverage": 0.2857
    }
  }
}
```

Human badge boleh tetap ada, tetapi harus derived dari evidence, bukan menggantikan evidence.

---

## 5.8. MYC-AUDIT-007 — Public API `file_path` tidak benar-benar diimplementasikan

**Lokasi:** `myc.c:43-53`, `compile.c:431-435`

Validasi menerima request bila salah satu ada:

```c
req->source || req->file_path
```

Tetapi pipeline langsung memakai:

```c
src = req->source;
srclen = req->source_len;
sha256_hex(src, srclen, hex);
```

Request `file_path`-only dapat menyebabkan NULL dereference atau perilaku undefined.

### Perbaikan

Pilih salah satu:

- implementasikan load file di ingress layer; atau
- hapus `file_path` dari public API.

Desain terbaik:

```c
myc_source_input {
    kind: MEMORY | FILE | STDIN
}
```

Setelah ingress, pipeline hanya menerima canonical in-memory source.

### Acceptance criteria

- test `file_path`-only;
- file tidak ada;
- file terlalu besar;
- file berubah saat dibaca;
- embedded NUL;
- non-seekable stream;
- error message typed dan stabil.

---

## 5.9. MYC-AUDIT-008 — Diagnostic ownership tidak aman

Beberapa modul memakai static ring buffer untuk message diagnostic:

- `compile.c`
- `run.c`
- `prove.c`
- `filc.c`
- `driver.c`

`lint.c` juga memakai mutable global state untuk tracking buffer.

Akibat:

- dua `myc_run` paralel dapat data race;
- hasil request lama dapat berubah setelah request baru;
- MCP in-process tidak siap concurrency;
- library embedding sulit dipercaya.

### Perbaikan ringan

Paling sederhana:

```c
typedef struct {
    int line;
    int col;
    myc_diag_code code;
    myc_severity severity;
    char message[384];
} myc_diagnostic;
```

Atau result-owned arena:

```c
myc_result {
    myc_arena arena;
    myc_diagnostic *diags;
}
```

Tidak perlu allocator kompleks. Satu arena bump allocator per request cukup.

### Acceptance criteria

- 64 request paralel;
- result request pertama tetap identik setelah 1.000 request berikutnya;
- ThreadSanitizer bersih;
- tidak ada global mutable scratch state.

---

## 5.10. MYC-AUDIT-009 — Parser JSON belum ketat dan belum length-aware

Masalah yang terlihat di `json.c`:

- menerima leading zero yang invalid;
- menerima fraction tanpa digit setelah titik;
- menerima exponent tanpa digit;
- menyimpan number sebagai `int64_t` sehingga ID JSON-RPC non-integer berubah makna;
- tidak menangani surrogate pair secara benar;
- tidak memvalidasi raw UTF-8;
- `\u0000` menghasilkan embedded NUL;
- consumer memakai `strlen`, sehingga source dapat terpotong diam-diam;
- mutator object/array dapat gagal OOM tanpa propagasi error;
- capacity doubling belum memiliki overflow guard;
- serializer dapat menghasilkan JSON invalid bila output backend mengandung byte non-UTF-8.

### Perbaikan

Gunakan string length-aware:

```c
typedef struct {
    char *ptr;
    size_t len;
} myc_string;
```

Number JSON-RPC ID sebaiknya dipertahankan sebagai lexical token, bukan dipaksa `int64_t`.

Semua API mutasi harus return status:

```c
int json_obj_set(...);
int json_arr_push(...);
```

### Acceptance criteria

Corpus wajib mencakup:

```text
01
1.
1e
1e+
"\u0000"
"\uD800"
"\uDC00"
"\uD83D\uDE00"
invalid UTF-8
deep nesting
allocation failure at every allocation point
```

Parser harus:

- menolak JSON invalid;
- tidak crash;
- tidak silently truncate;
- tidak return partial success pada OOM.

---

## 5.11. MYC-AUDIT-010 — Status backend tidak dibedakan

Saat ini status berikut sering diringkas menjadi “skip”:

- executable tidak ditemukan;
- compile backend gagal;
- child gagal exec;
- program exit nonzero;
- parser output backend gagal;
- output terpotong;
- backend tidak mendukung platform;
- tidak ada applicable target;
- tidak ada test case;
- backend completed clean.

Padahal maknanya sangat berbeda.

### Model status wajib

```text
NOT_REQUESTED
NOT_APPLICABLE
UNAVAILABLE
INFRA_FAILED
OUTPUT_UNPARSEABLE
OUTPUT_TRUNCATED
INCONCLUSIVE
COMPLETED_CLEAN
COMPLETED_FINDINGS
```

`OK` hanya boleh menjawab:

> Tidak ada finding dalam scope yang benar-benar diselesaikan.

Lalu completeness menjawab:

> Apakah semua scope yang diminta benar-benar diselesaikan?

---

## 5.12. MYC-AUDIT-011 — Timeout belum membunuh process tree secara reliable di POSIX

**Lokasi:** `proc.c:640-645`

Kode mencoba:

```c
kill(-pid, SIGKILL);
kill(pid, SIGKILL);
```

Tetapi child tidak membuat process group baru dengan `setpgid`.

Karena itu `kill(-pid, ...)` tidak dijamin menarget group child.

### Perbaikan

Di child sebelum `exec`:

```c
setpgid(0, 0);
```

Di parent, lakukan race-safe `setpgid(pid, pid)` juga.

Lebih kuat:

- Linux optional: `prctl(PR_SET_PDEATHSIG, SIGKILL)`;
- gunakan resource limit;
- Windows tetap gunakan Job Object;
- verifikasi descendant helper benar-benar mati.

---

## 5.13. MYC-AUDIT-012 — `MYC_BUF` belum menjaga element type

`myc_buf.h` menyimpan pointer dan capacity, tetapi access menerima type kembali dari macro:

```c
MYC_AT(buffer, type, index)
```

Jika caller memakai type yang salah:

- element size berubah;
- alignment dapat salah;
- bounds dihitung dengan unit berbeda;
- checked mode memberi rasa aman palsu.

Masalah lain:

- signed negative count di-cast ke `size_t`;
- `n * sizeof(T)` belum dicek eksplisit;
- mengalokasikan ulang buffer yang masih berisi pointer dapat leak;
- `i * elem_size` dapat overflow;
- coverage hanya untuk buffer yang mengikuti konvensi;
- double-free dapat tersamarkan karena macro meng-null-kan pointer.

### Struktur yang lebih kuat

```c
typedef struct {
    void *data;
    size_t byte_capacity;
    size_t elem_size;
    uint32_t generation;
    uint32_t cookie;
} myc_fat_buf;
```

Access:

```c
myc_buf_at(&b, index, sizeof(T), alignof(T))
```

Harus memverifikasi:

- `elem_size` sama;
- `index <= SIZE_MAX / elem_size`;
- offset + elem_size <= byte_capacity;
- cookie valid;
- generation belum invalidated.

Production macro tetap dapat menjadi raw pointer tanpa overhead.

---

## 5.14. MYC-AUDIT-013 — Klaim Frama-C Eva terlalu kuat

README dan diagnostic menyebut:

```text
L2 PROVEN
kontrak & bounds terbukti
```

Namun `-eva` adalah abstract interpretation. Hal penting:

- alarm bukan otomatis bukti concrete bug;
- zero alarm bermakna dalam model dan asumsi tertentu;
- `ensures` bukan otomatis dibuktikan oleh Eva seperti proof obligation WP;
- entry point dan library model sangat memengaruhi hasil;
- parsing berdasarkan teks summary rapuh;
- output cap dapat menyembunyikan alarm yang berada setelah batas.

### Perbaikan

Pisahkan:

```text
EVA_NO_ALARM_UNDER_MODEL
EVA_ALARMS_PRESENT
WP_OBLIGATIONS_PROVED
WP_OBLIGATIONS_UNPROVED
CONTRACT_PARSED_ONLY
CONTRACT_INSTRUMENTED_RUNTIME
```

Jangan gunakan kata `PROVEN` tanpa menyebut:

- tool;
- versi;
- model;
- entry point;
- jumlah obligation;
- jumlah proved;
- jumlah unknown;
- timeout.

---

## 5.15. MYC-AUDIT-014 — Heuristik lint terlalu keras

Contoh rule:

- cast ke `intptr_t` / `uintptr_t` menjadi hard violation;
- pola `realloc` diperiksa dengan window teks;
- tracking identifier tidak scope-aware;
- komentar/string dapat memengaruhi scan;
- assignment yang terjadi setelah stale use dapat tetap dianggap aman;
- `malloc(n * sizeof(T))` dianggap lebih baik walau multiplication tetap dapat overflow;
- `memcpy` tanpa `sizeof` diperingatkan, padahal ukuran eksplisit dapat valid dan `sizeof` dapat salah.

### Prinsip yang disarankan

> Text heuristic boleh menghasilkan observation, tetapi tidak boleh menjadi hard verdict kecuali dikonfirmasi oleh semantic evidence.

Gunakan confidence:

```text
OBSERVATION
SUSPICIOUS
LIKELY
CONFIRMED
```

Hard failure hanya untuk:

- compiler AST/dataflow evidence;
- sanitizer finding;
- proof counterexample;
- checked runtime violation;
- rule yang benar-benar syntactic dan unambiguous.

---

## 5.16. MYC-AUDIT-015 — `NUL` tidak portable

README dan compile pipeline memakai:

```text
-o NUL
```

Di POSIX, itu bukan null device; itu file biasa.

Arsip bahkan memuat file bernama:

```text
NUL
```

berukuran sekitar 1.2 KB, yang sangat mungkin merupakan artefak dari hal ini.

### Perbaikan

- Windows: `NUL`
- POSIX: `/dev/null`
- lebih baik: untuk compile-only, gunakan temporary object yang dikelola dan dihapus;
- jangan bergantung pada device path bila output object memang dibutuhkan untuk validasi.

---

# 6. Masalah Mendasar pada Model Assurance

## 6.1. Assurance bukan angka tunggal

Model sekarang seolah:

```text
L5 > L4 > L3 > L2 > L1
```

Padahal:

```text
runtime observation
```

dan:

```text
static abstract interpretation
```

tidak selalu comparable.

Demikian juga:

```text
checked-buffer compilation
```

tidak meliputi buffer biasa.

## 6.2. Gunakan evidence matrix

Contoh output manusia:

```text
Verdict
  code findings:          none in completed scopes
  verification status:    incomplete

Evidence
  compile:                clean
  gcc analyzer:           not requested
  contract parse:         2 requires, 1 ensures
  contract runtime:       2 requires instrumented
  Eva:                    unavailable
  checked buffers:        2 / 7 candidate buffers covered
  sanitizer runtime:      infrastructure failed
  generated driver:       0 cases executed
  Fil-C:                  not requested

Unverified debt
  5 raw buffers outside MYC_BUF
  1 requested runtime backend failed
  1 ensures clause parsed but not proved
```

Ini lebih terhormat daripada `L4`.

## 6.3. Verdict harus memiliki dua sumbu

### Sumbu A — Finding

```text
CLEAN
FINDINGS
INCONCLUSIVE
```

### Sumbu B — Completeness

```text
COMPLETE_FOR_REQUESTED_PROFILE
INCOMPLETE
```

Maka hasil dapat berupa:

```text
CLEAN + INCOMPLETE
```

yang jauh lebih jujur daripada `OK L4`.

## 6.4. Scope selalu wajib tampil

Setiap klaim harus menyertakan scope:

```text
No memory errors observed
in 12 generated cases
under clang 19 ASan+UBSan
with input hashes [...]
```

Bukan:

```text
FULL
```

## 6.5. Label ringkas yang aman

Jika tetap ingin badge singkat:

```text
STATIC:CLEAN
RUNTIME:12-CLEAN
BUFFER:2/7
PROOF:0/3
COMPLETE:NO
```

Atau compact:

```text
S2-R3-B1-P0 / incomplete
```

Tetapi JSON harus tetap menyimpan detail penuh.

---

# 7. Review per Modul

## 7.1. `proc.c`

### Kekuatan

- API request/result terpisah;
- stdout dan stderr dipisah;
- timeout tersedia;
- output cap tersedia;
- Windows memakai Job Object;
- source tidak melewati shell.

### Masalah

#### POSIX

- deadlock stdin/output;
- drain thread tidak di-join;
- `pthread_create` error diabaikan;
- fd leak pada partial `pipe()` failure;
- fd leak pada `fork()` failure;
- child dapat tertinggal pada drain init failure;
- process group belum dibentuk;
- `write()` dapat memicu `SIGPIPE`;
- `exec` failure hanya terlihat sebagai exit `127`;
- timeout semantics berbeda dengan Windows;
- output metadata dibaca saat thread mungkin masih menulis.

#### Windows

- inheritance memakai `bInheritHandles=TRUE` tanpa explicit handle allow-list;
- kegagalan `_beginthreadex` perlu ditangani;
- wait thread drain yang berbatas waktu dapat tetap meninggalkan race bila thread belum selesai;
- semua handle cleanup path perlu table-driven review.

### Refactor yang disarankan

Buat `proc.c` sebagai **trust kernel** tersendiri.

API:

```c
typedef struct {
    const char *program;
    const char *const *argv;
    const void *stdin_data;
    size_t stdin_len;
    const char *cwd;
    uint32_t timeout_ms;
    size_t max_stdout_bytes;
    size_t max_stderr_bytes;
    unsigned flags;
} myc_proc_request;

typedef struct {
    myc_proc_status status;
    int exit_code;
    int term_signal;
    int os_error;
    int exec_error;
    uint64_t duration_ms;
    myc_capture stdout_capture;
    myc_capture stderr_capture;
} myc_proc_result;
```

`myc_capture` sebaiknya menyimpan:

- prefix terbatas;
- tail terbatas;
- total bytes;
- truncated flag;
- streaming detector state.

Mengapa prefix + tail?

Sanitizer report dapat muncul di akhir setelah aplikasi membanjiri output. Menyimpan hanya prefix membuat bukti hilang. Menyimpan seluruh output membuat memory bloat. Kombinasi prefix + tail sangat ringan dan kuat.

---

## 7.2. `compile.c`

### Kekuatan

- structured argv;
- source via stdin;
- compilation tier terpisah;
- source hash;
- fingerprint intent;
- optional analyzer;
- checked gate.

### Masalah

- fingerprint OOB read;
- `file_path` contract rusak;
- `NUL` tidak portable;
- parser diagnostic berbasis teks;
- localized compiler output dapat gagal diparse;
- output cap dapat menyembunyikan diagnostic;
- preprocessing cap membuat policy scan hanya sebagian;
- fingerprint belum memasukkan seluruh konfigurasi penting;
- versi compiler tidak masuk secara kuat;
- allocation failure sering tidak dijadikan error;
- build status dan semantic finding kadang tercampur.

### Perbaikan

Gunakan machine-readable diagnostics bila tersedia:

```text
GCC:   -fdiagnostics-format=json
Clang: -fdiagnostics-format=json
```

Fallback teks tetap ada, tetapi output diberi:

```text
parser_mode: text_fallback
confidence: reduced
```

Fingerprint harus memasukkan:

- source hash;
- exact compiler path;
- compiler file hash bila murah;
- compiler `--version`;
- exact argv;
- cwd canonical;
- environment whitelist;
- myc version;
- backend adapter version;
- sanitizer options;
- contract injection version;
- checked header hash;
- profile definition hash.

Jangan hash ambient environment seluruhnya; gunakan canonical whitelist agar reproducible.

---

## 7.3. `run.c`

### Kekuatan

- build dan run dipisahkan;
- ASan + UBSan;
- stdin dapat disediakan;
- timeout dan output cap;
- optional/non-blocking intent.

### Masalah

- path executable POSIX;
- failure disamarkan sebagai skip;
- marker detection dengan `strstr`;
- application output dapat memalsukan marker;
- report setelah output cap dapat hilang;
- ambient `ASAN_OPTIONS` / `UBSAN_OPTIONS` memengaruhi hasil;
- tidak merekam tool version dan exact flags;
- satu input dianggap cukup untuk label tinggi;
- temp name predictable dan cleanup error diabaikan;
- tidak ada resource limit selain timeout/output;
- run profile tidak membedakan infra failure dengan code exit.

### Perbaikan

Set explicit environment:

```text
ASAN_OPTIONS=abort_on_error=1:halt_on_error=1:detect_leaks=1:...
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:...
LC_ALL=C
```

Lebih baik, gunakan sanitizer log path yang unik dan parse file report, sehingga stdout aplikasi tidak dapat spoof.

Jika itu tidak portable, gunakan delimiter/token yang diinject oleh harness, tetapi jangan menganggap pencarian string generik sebagai bukti kuat.

---

## 7.4. `prove.c`

### Kekuatan

- backend proof dipisahkan;
- source dikirim via stdin;
- timeout/output capture;
- optional backend;
- contract integration intent.

### Masalah

- hanya jalur WSL pada skenario tertentu;
- parsing text summary rapuh;
- alarm dianggap concrete bug;
- zero alarm disebut proof kontrak;
- `ensures` tidak benar-benar diprove;
- version/config/model tidak direkam;
- output cap dapat mengubah kesimpulan;
- entry point tidak terlihat sebagai bagian scope.

### Perbaikan

Pisahkan adapter:

```text
frama_eva_adapter
frama_wp_adapter
```

Eva menghasilkan:

```text
abstract_interpretation_evidence
```

WP menghasilkan:

```text
proof_obligation_evidence
```

Jangan campur.

---

## 7.5. `filc.c`

### Kekuatan

- backend memory-safe C adalah pembeda;
- native dan WSL intent;
- optional;
- runtime evidence terpisah.

### Masalah

- clean run diberi `L5 FULL`;
- hanya satu execution;
- marker generik/case-sensitive;
- output aplikasi dapat spoof;
- WSL path memakai stdin untuk source sehingga `run_stdin` tidak diteruskan ke program;
- version/config tidak direkam;
- output cap fragility;
- failure status tidak cukup granular.

### Klaim yang lebih tepat

Gunakan:

```text
FILC_EXECUTION_CLEAN
```

dengan:

```text
cases: N
backend_version: ...
input_hashes: [...]
```

Bukan `FULL`.

---

## 7.6. `contract.c`

### Kekuatan

- syntax ringan;
- mudah ditulis agent;
- tidak memerlukan parser eksternal;
- cocok untuk generated driver;
- dapat menjadi jembatan ke backend formal.

### Masalah

- expression lebih dari 511 char dipotong diam-diam;
- beberapa `requires` berurutan dihitung tetapi injector hanya mempertahankan satu pending expression;
- return buffer builder sering diabaikan;
- OOM dapat menghasilkan source parsial;
- expression dengan side effect dapat masuk ke `assert`;
- attachment ke function bersifat heuristik;
- `ensures` dihitung tetapi tidak diinstrumentasi/diprove secara konsisten;
- list API dapat return success walau allocation gagal.

### Perbaikan

Gunakan grammar contract-lite yang eksplisit:

```text
//@ myc requires: n <= cap
//@ myc ensures: result <= cap
//@ myc assigns: dst[0..n-1]
```

Parser perlu:

- tokenization;
- max length explicit;
- reject, bukan truncate;
- pure-expression whitelist;
- function binding yang stable;
- contract ID;
- source range.

Status tiap clause:

```text
PARSED
BOUND_TO_FUNCTION
RUNTIME_INSTRUMENTED
DRIVER_USED
EVA_CONSUMED
WP_PROVED
UNSUPPORTED
```

---

## 7.7. `driver.c`

### Kekuatan

- generated boundary cases sangat berguna;
- contract-driven;
- lebih bernilai daripada satu run kosong;
- dapat menemukan bug yang compiler lewatkan.

### Risiko utama

- jumlah kasus dieksekusi dapat nol tetapi verdict tetap static OK;
- generated harness correctness belum dibuktikan;
- combinatorial strategy perlu dilaporkan;
- pointer/size relation perlu lebih kuat;
- input domain inference dapat salah;
- sanitizer marker parsing sama rapuhnya;
- path temp/runtime memiliki masalah serupa `run.c`;
- generated cases tidak memiliki replay capsule.

### Perbaikan

Setiap case wajib memiliki:

```text
case_id
function_id
parameter values
allocation sizes
contract assumptions
input seed
expected reachability
execution status
```

Jika `driver_cases == 0` padahal `--driver` diminta:

```text
status = NOT_APPLICABLE
```

atau:

```text
status = INFRA_FAILED
```

tergantung penyebab. Jangan `completed clean`.

---

## 7.8. `lint.c`

### Kekuatan

- cepat;
- dependency-free;
- cocok memberi feedback instan;
- dapat mengarahkan coding agent ke style aman.

### Masalah

- global mutable state;
- tidak scope-aware;
- raw text window;
- false positive/false negative tinggi;
- hard gate terlalu keras;
- beberapa rule tidak semantically valid;
- rule ID/severity/confidence belum kuat.

### Arah yang disarankan

Jadikan lint sebagai:

> **fast structural suspicion engine**

Bukan verifier final.

Format finding:

```json
{
  "rule_id": "MYC-LINT-REALLOC-001",
  "severity": "warning",
  "confidence": 0.62,
  "evidence": [
    {"line": 31, "fact": "realloc result assigned to temporary"},
    {"line": 35, "fact": "original pointer referenced after call"}
  ],
  "limitations": [
    "scope not resolved",
    "control-flow not modeled"
  ]
}
```

Tool terhormat menyatakan keterbatasannya.

---

## 7.9. `myc_buf.h`

### Kekuatan

- sangat kecil;
- production/check mode duality;
- dapat memaksa access macro;
- cocok untuk code generation oleh agent.

### Perbaikan teknis

Tambahkan:

- checked multiplication helper;
- element size dalam metadata;
- byte capacity;
- alignment;
- allocation state;
- optional canary/cookie;
- generation counter;
- typed declaration macro;
- explicit error mode: trap, return, callback;
- exact coverage counter bila instrumented.

Contoh konsep:

```c
#define MYC_BUF(T, name) \
    struct { \
        T *data; \
        size_t count; \
        size_t capacity; \
        size_t elem_size; \
        uint32_t generation; \
    } name
```

Untuk production, macro dapat dipetakan ke bentuk lebih sederhana melalui profile.

---

## 7.10. `json.c`

### Kekuatan

- kecil;
- tanpa dependency;
- depth cap;
- parser/serializer lokal mudah diaudit.

### Rekomendasi

Pertahankan parser sendiri **hanya jika**:

- grammar strict;
- fuzzed;
- OOM-safe;
- length-aware;
- UTF-8 policy jelas;
- round-trip property tested.

Jika tidak, parser kecil justru menjadi trust liability.

Gunakan allocation fault injection:

```text
fail allocation #1
fail allocation #2
...
```

dan pastikan setiap jalur:

- return error;
- tidak leak;
- tidak double-free;
- tidak return partial tree.

---

## 7.11. `mcp.c`

### Kekuatan

- in-process;
- stdio;
- low overhead;
- tool surface sederhana;
- interop test sudah ada.

### Masalah

- JSON hasil `myc` dimasukkan sebagai text string;
- agent harus parse JSON di dalam JSON;
- `isError` tidak konsisten dengan verdict;
- transport error dan code finding tercampur;
- `jsonrpc` tidak divalidasi ketat;
- notification semantics belum lengkap;
- unknown flags diabaikan;
- protocol negotiation terlalu longgar;
- schema version tidak ada;
- embedded NUL problem dari parser;
- concurrency belum aman.

### Bentuk MCP yang disarankan

```json
{
  "content": [
    {
      "type": "text",
      "text": "2 findings; runtime verification incomplete"
    }
  ],
  "structuredContent": {
    "schema": "myc.result.v1",
    "verdict": "findings",
    "completeness": "incomplete",
    "gates": { }
  },
  "isError": false
}
```

`isError` hanya untuk kegagalan pemanggilan tool/protocol, bukan untuk finding pada kode.

---

## 7.12. CLI dan report

### Masalah

- unknown flag diabaikan;
- `--level` semantik membingungkan;
- stdin dibaca tanpa hard cap selama proses grow;
- file dibaca penuh sebelum size cap;
- resource tertentu tidak dibebaskan pada early return;
- `probe` memakai asumsi path Windows;
- `version` belum memberi exact toolchain identity;
- result report belum memisahkan code finding dan infra status.

### Perbaikan

CLI harus fail-fast:

```text
unknown option: --rnu
did you mean: --run
```

Tambahkan:

```text
--profile fast|deep|execute|prove|agent
--require-complete
--format text|json|sarif
--explain RULE_ID
```

---

# 8. Arsitektur Baru yang Disarankan

## 8.1. Prinsip

Jangan rewrite total.

Pertahankan modul, tetapi ubah aliran data menjadi:

```text
Ingress
  ↓
Canonical Request
  ↓
Gate Scheduler
  ↓
Typed Gate Results
  ↓
Evidence Ledger
  ↓
Verdict Reducer
  ↓
Renderer
```

## 8.2. Canonical request

```c
typedef struct {
    myc_bytes source;
    myc_string virtual_filename;
    myc_string cwd;
    myc_profile profile;
    myc_limits limits;
    myc_input_portfolio inputs;
    uint64_t requested_gates;
} myc_request_canonical;
```

Ingress bertanggung jawab untuk:

- file/stdin/memory;
- size cap;
- NUL policy;
- path canonicalization;
- source hash;
- option validation.

Gate tidak perlu menangani variasi ingress.

## 8.3. Typed gate result

```c
typedef struct {
    myc_gate_id gate;
    myc_gate_status status;
    myc_scope scope;
    myc_tool_identity tool;
    uint64_t duration_ms;
    myc_evidence_range evidence;
    myc_finding_range findings;
    myc_coverage coverage;
    myc_error_detail failure;
} myc_gate_result;
```

Setiap gate hanya mengisi hasilnya sendiri.

Gate tidak boleh:

- langsung menaikkan assurance global;
- menimpa verdict gate lain;
- menghapus failure;
- menyebut dirinya `FULL`.

## 8.4. Evidence ledger

Append-only event:

```c
typedef struct {
    uint32_t type;
    uint32_t gate_id;
    uint32_t location_id;
    uint32_t payload_offset;
    uint32_t payload_size;
} myc_evidence_event;
```

Keuntungan:

- sangat compact;
- deterministic;
- mudah di-render;
- mudah di-hash;
- mudah dibandingkan;
- mudah disimpan sebagai receipt;
- tidak memerlukan object graph berat.

## 8.5. Verdict reducer

Pure function:

```c
myc_summary myc_reduce(
    const myc_gate_result *gates,
    size_t gate_count,
    const myc_profile_contract *profile);
```

Reducer menentukan:

- findings;
- inconclusive;
- completeness;
- exit code;
- human summary.

Karena pure, reducer mudah diuji exhaustive.

## 8.6. Per-request context

```c
typedef struct {
    myc_arena arena;
    myc_symbol_table symbols;
    myc_diag_builder diagnostics;
    myc_evidence_builder evidence;
    myc_cancel_token cancel;
} myc_context;
```

Semua mutable state masuk context.

Tidak ada:

- global ring buffer;
- global lint variables;
- static mutable indexes.

## 8.7. Backend adapter sebagai proses terpisah secara logis

Core tidak perlu link ke Frama-C/Fil-C/Clang library.

Adapter tetap memanggil executable external dengan argv yang terstruktur.

Dengan begitu:

- binary tetap kecil;
- backend optional;
- core tidak terkontaminasi dependency;
- backend dapat diperbarui tanpa mengubah trust core;
- tiap adapter punya parser/version probe sendiri.

---

# 9. Gagasan Pembeda yang Tidak Lazim

Bagian ini berisi ide yang dapat membuat `myc` bukan sekadar tool kecil, tetapi tool dengan identitas teknis kuat.

## 9.1. Evidence Receipt

Setiap run menghasilkan receipt yang dapat diverifikasi:

```json
{
  "schema": "myc.receipt.v1",
  "source_sha256": "...",
  "myc_build_id": "...",
  "profile_hash": "...",
  "toolchains": [...],
  "gates": [...],
  "coverage": {...},
  "findings": [...],
  "unverified_debt": [...],
  "receipt_sha256": "..."
}
```

Receipt harus canonical dan deterministic.

Manfaat:

- hasil dapat dibandingkan di CI;
- agent dapat menyimpan bukti;
- audit tidak bergantung log manusia;
- regressions mudah dideteksi;
- tidak perlu cloud;
- sangat ringan.

### Pengembangan lanjutan

Receipt dapat hash-linked:

```text
receipt_n.parent = hash(receipt_n-1)
```

Ini membuat riwayat verifikasi proyek menjadi ledger lokal tanpa blockchain, server, atau database.

---

## 9.2. Claim Compiler

Ini dapat menjadi ciri khas `myc`.

Alih-alih code secara bebas mencetak label seperti `FULL`, buat mesin yang mengompilasi klaim dari evidence.

Contoh rule:

```text
Claim "runtime clean"
requires:
  runtime.status == COMPLETED_CLEAN
  runtime.cases >= 1
  runtime.output_complete == true
  runtime.tool_identity_known == true
```

Jika syarat tidak terpenuhi, renderer **dilarang** mengeluarkan klaim.

Contoh:

```text
Requested claim rejected:
  "memory-safe"
Missing obligations:
  - 5 buffers outside checked representation
  - only 1 runtime case
  - no proof for 2 functions
```

Ini bukan sekadar fitur; ini membangun budaya kejujuran.

---

## 9.3. Unverified Debt

Tool biasanya hanya melaporkan apa yang ditemukan.

`myc` sebaiknya juga melaporkan apa yang **tidak diperiksa**.

Contoh:

```text
Unverified debt:
  7 functions not reached by generated driver
  5 raw arrays outside MYC_BUF
  2 external allocator contracts unknown
  1 ensures clause parsed but unproved
  runtime backend failed
  sanitizer output truncated
```

Nilai uniknya:

- silence tidak disalahartikan sebagai safety;
- agent tahu langkah berikut;
- debt dapat diturunkan dari commit ke commit;
- kualitas dapat diukur tanpa memalsukan assurance.

---

## 9.4. Semantic Canary

Sebelum mempercayai backend, `myc` menjalankan canary kecil yang diketahui harus gagal.

Contoh canary ASan:

```c
int main(void) {
    int a[1];
    a[1] = 7;
    return 0;
}
```

Jika backend tidak menangkapnya:

```text
backend health: invalid
reason: ASan canary was not detected
```

Cache hasil berdasarkan:

```text
compiler path + version + flags + environment hash
```

Ini mendeteksi:

- sanitizer tidak ter-link;
- runtime DLL hilang;
- env men-disable report;
- parser marker rusak;
- backend version berubah;
- WSL bridge bermasalah.

Sangat sedikit tool kecil yang memverifikasi verifier-nya sendiri sebelum memberi kepercayaan.

---

## 9.5. Counterexample Replay Capsule

Untuk setiap runtime finding, simpan capsule kecil:

```text
source hash
backend identity
exact argv
environment
input bytes/hash
generated harness hash
case ID
exit/signal
finding marker
```

Command:

```sh
myc replay receipt-case-07.mycr
```

Tujuannya:

- bug dapat direproduksi;
- agent tidak perlu menebak;
- finding tidak menjadi teks mati;
- regression test dapat dihasilkan otomatis.

Capsule tidak perlu memuat binary; cukup metadata + input + generated harness bila kecil.

---

## 9.6. Differential Backend Quorum

Jangan sekadar mengambil level tertinggi.

Gunakan agreement:

```text
GCC analyzer: suspicious
ASan: confirmed
Fil-C: confirmed
=> confidence high
```

Atau:

```text
Eva: alarm
ASan 100 cases: clean
=> conflict, not clean
```

Output:

```text
Evidence conflict:
  static model reports possible OOB
  runtime portfolio did not reproduce
  status remains inconclusive
```

Tool yang mengakui konflik lebih disegani daripada tool yang memilih hasil favorit.

---

## 9.7. Metamorphic Verification

Tanpa fuzzer besar, `myc` dapat membuat beberapa transformasi yang semantically expected-equivalent:

- `-O0` vs `-O2`;
- GCC vs Clang bila tersedia;
- signedness warning profile;
- reordered independent declarations;
- added harmless padding;
- allocator poison mode;
- checked-buffer mode.

Jika hasil program berbeda:

```text
metamorphic inconsistency detected
possible undefined behavior or toolchain-sensitive bug
```

Dua build tambahan cukup; tidak harus eksplosif.

---

## 9.8. Negative-Space Analysis

Analisis tidak hanya melihat pola yang ada, tetapi pola yang hilang.

Contoh:

- 14 callsite memeriksa `malloc`;
- 1 callsite tidak;
- 9 fungsi sibling memeriksa `len <= cap`;
- 1 fungsi tidak;
- semua cleanup path menutup file kecuali satu.

Tanpa AI besar, cukup structural mining lokal.

Output:

```text
Project convention deviation:
  14/15 callsites check return of pool_alloc()
  this callsite does not

Confidence: 0.93
```

Ini sangat berguna dan ringan.

---

## 9.9. Assurance Lattice

Daripada level linear, gunakan partial order.

Contoh dua hasil:

```text
A: static proof kuat, runtime belum ada
B: runtime 10.000 case, static proof belum ada
```

Tidak perlu memaksa A > B atau B > A.

`myc` dapat mengatakan:

```text
Results are incomparable:
  A has stronger static evidence
  B has stronger execution evidence
```

Ini mungkin terdengar akademik, tetapi justru sangat jujur dan mudah diimplementasikan.

---

## 9.10. Silence Is a Finding

Jika gate diminta tetapi:

- tidak ditemukan;
- gagal exec;
- output tidak dapat diparse;
- menghasilkan 0 case;
- report terpotong;

maka `myc` harus mengeluarkan finding tipe:

```text
MYC-INCOMPLETE-xxx
```

Bukan security bug pada source, tetapi **verification gap**.

Di CI:

```text
--require-complete
```

membuat gap tersebut fail.

---

## 9.11. Verification Scope Certificate

Setiap result memiliki scope compact:

```json
{
  "functions_total": 38,
  "functions_static_analyzed": 38,
  "functions_runtime_reached": 7,
  "buffers_candidate": 11,
  "buffers_checked": 4,
  "contracts_total": 6,
  "contracts_proved": 1,
  "contracts_runtime_checked": 4,
  "driver_cases": 27
}
```

Ini dapat disebut:

> **Scope Certificate**

Bukan sertifikat marketing, melainkan daftar persis apa yang diperiksa.

---

## 9.12. Verification Budget as Code

Minimalisme harus menjadi invariant CI.

File:

```toml
[binary]
myc_max_bytes = 180000
mcp_max_bytes = 250000

[performance]
startup_p95_ms = 20
fast_10kloc_p95_ms = 500
idle_rss_max_kib = 8192

[complexity]
core_external_dependencies = 0
global_mutable_objects = 0
```

CI gagal bila budget dilanggar.

Dengan ini, `myc` tidak hanya mengaku ringan; ringan menjadi properti yang diuji.

---

## 9.13. Rule Stability Contract

Setiap finding memiliki:

```text
stable rule ID
schema version
severity
confidence
evidence
scope
fix guidance
introduced version
```

Rule ID tidak berubah hanya karena wording berubah.

Ini penting untuk:

- suppressions;
- CI baseline;
- agent;
- audit;
- regression.

---

## 9.14. Suppression dengan Expiry dan Alasan

Jangan izinkan suppression buta:

```c
// myc-ignore MYC-LINT-REALLOC-001
```

Gunakan:

```c
// myc-ignore MYC-LINT-REALLOC-001
// reason: allocator returns stable arena address
// owner: module-memory
// expires: 2026-12-01
```

Suppression tetap masuk `unverified debt`.

---

## 9.15. Autopsy Mode

Ketika backend gagal:

```sh
myc autopsy --gate runtime
```

menghasilkan diagnosis:

```text
clang found: yes
compile: yes
sanitizer linked: yes
canary detected: no
runtime library: missing
exec path: ...
cwd: ...
environment: ...
```

Ini jauh lebih berguna daripada diagnostic “skip”.

---

## 9.16. Trust Core Self-Proof

Bukan formal proof besar. Buat property kecil untuk core:

- argv tidak pernah melewati shell;
- source byte count preserved;
- output cap tidak mengubah marker detector;
- requested gate tidak dapat menjadi completed tanpa event completion;
- `OK + COMPLETE` mustahil bila ada gate failure;
- result tidak meminjam pointer dari stack/global scratch;
- receipt hash selalu deterministic.

Property tersebut dapat diuji dengan model kecil atau exhaustive enum test.

---

# 10. Strategi Agar Tetap Sangat Ringan

## 10.1. Jangan menulis full C compiler

`myc` tidak perlu menjadi Clang baru.

Gunakan compiler yang ada untuk:

- syntax;
- type;
- AST/diagnostic machine output;
- sanitizer build;
- analyzer.

Internal parser hanya untuk:

- contract-lite;
- lightweight local patterns;
- report;
- orchestration.

## 10.2. Core binary dan optional adapters

Susunan:

```text
myc-core
myc-adapter-gcc
myc-adapter-clang
myc-adapter-frama
myc-adapter-filc
```

Tidak harus lima binary. Secara source cukup boundary logis. Namun build profile dapat memilih:

```text
MYC_MINIMAL
MYC_FULL
MYC_MCP
```

Target:

| Artefak | Target ukuran stripped |
|---|---:|
| `myc` minimal | < 150 KB |
| `myc` full orchestrator | < 300 KB |
| `mcp` | < 350 KB |
| runtime dependency | 0 |

Angka ini bukan dogma, tetapi budget CI.

## 10.3. Arena allocator per request

Satu arena kecil mengurangi:

- allocation overhead;
- fragmentation;
- ownership ambiguity;
- cleanup complexity.

Reset satu kali di akhir request.

Jangan gunakan arena untuk output child yang dapat besar; gunakan bounded capture terpisah.

## 10.4. Packed IDs, bukan pointer graph

Untuk evidence, symbol, location:

```c
uint32_t id;
```

Array contiguous lebih ringan daripada linked list dan lebih cache-friendly.

## 10.5. Streaming parsing

Untuk compiler/sanitizer output:

- parse saat byte masuk;
- simpan hanya prefix + tail;
- update marker state;
- jangan perlu menyimpan 100 MB.

## 10.6. Feature discovery yang dicache

Probe toolchain satu kali per process:

```text
path
version
supported flags
canary health
fingerprint
```

Cache kecil in-memory atau file cache optional.

## 10.7. Tidak ada daemon wajib

MCP boleh long-lived, tetapi CLI tetap one-shot.

Tidak perlu:

- service;
- database;
- telemetry;
- network;
- account;
- cloud.

## 10.8. Hindari “AI inside myc”

`myc` sebaiknya tetap deterministic.

Agent menggunakan `myc`, bukan `myc` bergantung pada agent.

Ini membuatnya:

- reproducible;
- cepat;
- murah;
- offline;
- dapat diaudit;
- tidak berubah karena model.

---

# 11. Rencana Eksekusi Bertahap

## Fase 0 — Freeze Klaim dan Fitur Baru

**Tujuan:** menghentikan pertambahan surface area sampai trust core sehat.

### Task

- [ ] Tandai README bahwa level assurance lama bersifat eksperimental.
- [ ] Hapus istilah `FULL`.
- [ ] Jangan menambah backend baru.
- [ ] Buat branch `trust-core`.
- [ ] Tambahkan issue untuk setiap `MYC-AUDIT-*`.
- [ ] Simpan fixture output saat ini sebagai baseline bug, bukan golden success.

### Acceptance criteria

- tidak ada commit feature baru selama Fase 1;
- semua bug kritis memiliki regression test yang gagal terlebih dahulu.

---

## Fase 1 — Process Broker Rewrite ✅ PARTIAL SELESAI 2026-08-02

**Tujuan:** membuat `proc.c` layak dipercaya.

### Task 1.1 — Resource ownership table

Dokumentasikan untuk setiap fd/handle:

| Resource | Created by | Owned by | Closed where |
|---|---|---|---|

### Task 1.2 — POSIX pipe setup atomic cleanup

- [x] initialize semua fd ke `-1`;
- [x] setiap partial failure menutup yang sudah dibuat (cleanup_pipes label);
- [ ] gunakan helper `close_if_valid`;
- [x] set `FD_CLOEXEC` untuk fd non-child (exec-error pipe);
- [x] tambahkan exec-error pipe.

### Task 1.3 — Concurrent I/O

Pilih salah satu:

- [ ] `poll()` single event loop; direkomendasikan; atau
- [x] 3 thread yang semuanya di-join. *(dipilih: drain thread to/te di-join)*

`poll()` lebih mudah menjaga ownership dan lebih ringan.

### Task 1.4 — Process group

- [x] `setpgid(0,0)` di child sebelum exec;
- [x] timeout kill group (`kill(-pid, SIGKILL)`);
- [x] wait child;
- [x] drain remaining output (join setelah pipe ditutup);
- [ ] verify descendants gone (belum ada test eksplisit).

### Task 1.5 — Output capture

- [x] bounded prefix;
- [ ] bounded tail *(masih prefix-only; tail untuk catch sanitizer report di akhir = TODO)*;
- [x] total byte counter;
- [x] truncation flag;
- [ ] streaming evidence detector;
- [x] no race (pthread_join sebelum transfer buffer).

### Task 1.6 — Windows handle allow-list

- [ ] gunakan `STARTUPINFOEX` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` bila tersedia;
- [ ] fallback didokumentasikan;
- [x] semua drain thread di-join (WaitForSingleObject sudah ada);
- [ ] handle leak test.

### Acceptance criteria

Lihat test matrix di Fase 8.

---

## Fase 2 — Canonical Ingress dan API Contract ✅ PARTIAL SELESAI 2026-08-02

### Task

- [ ] Implement `myc_source_input` formal struct.
- [ ] Terapkan size cap saat membaca, bukan setelah membaca penuh.
- [ ] File path canonicalization.
- [ ] Embedded NUL policy length-aware.
- [x] `file_path`-only: `myc_run()` kini load file sebelum masuk pipeline (MYC-AUDIT-007).
- [ ] Validasi timeout, output cap, cwd, flag combinations.
- [ ] Unknown flag menjadi error.
- [ ] Semua string public memiliki pointer + length bila dapat mengandung input eksternal.

### Acceptance criteria

- API dan CLI memiliki perilaku identik;
- tidak ada request valid yang kemudian menyebabkan NULL access; ✅ (file_path fixed)
- input > limit berhenti dibaca segera.

### Acceptance criteria

- API dan CLI memiliki perilaku identik;
- tidak ada request valid yang kemudian menyebabkan NULL access;
- input > limit berhenti dibaca segera.

---

## Fase 3 — Typed Gate Status dan Evidence Ledger ✅ SELESAI 2026-08-02

### Task

- [x] Definisikan `myc_gate_status`. (`gate.h:15-22`)
- [x] Definisikan `myc_gate_result`. (`gate.h:28-37`)
- [x] Migrasikan compile gate. (`compile.c:525-627`)
- [x] Migrasikan runtime gate. (`run.c:209-337`)
- [x] Migrasikan checked gate. (`compile.c:681-722`)
- [x] Migrasikan driver gate. (`driver.c:1034-1292`)
- [x] Migrasikan Frama/Fil-C. (`prove.c:149-286`, `filc.c:256-551`)
- [x] Implement append-only evidence. (`gate.c:61-91`)
- [x] Verdict reducer murni. (`gate.c:115-199`)

### Catatan implementasi

- Semua gate kini menulis `myc_gate_result` + evidence event, bukan boolean global.
- Gate yang gagal infra/timeout menulis `MYC_GATE_INFRA_FAILED` atau `MYC_GATE_INCONCLUSIVE`, bukan silently skip.
- `myc_reduce_verdict()` adalah pure function dari gate results; dipanggil di akhir `myc_pipeline()`.
- `MC_INCONCLUSIVE` ditambahkan ke `myc_verdict` enum untuk kasus "requested tapi tidak complete".
- Legacy assurance ladder (L1–L5) dipertahankan sebagai derived view, bukan sumber kebenaran.
- MYC-AUDIT-004 (silent skip verdict) tetap diperbaiki: runtime infra failure -> INCONCLUSIVE, bukan OK.
- MYC-AUDIT-010 (status backend tidak dibedakan) diperbaiki: 7 status typed menggantikan boolean.

### Acceptance criteria

- [x] requested runtime exec failure selalu terlihat `INFRA_FAILED`;
- [x] tidak ada kombinasi yang menghasilkan complete-clean bila gate gagal;
- [x] reducer diuji exhaustive untuk semua kombinasi status kecil. (`test/_regress_run.bat`, `test/_mcp_sdk_interop.py`)

---

## Fase 4 — Ganti Assurance Ladder ✅ PARTIAL SELESAI 2026-08-02 (unverified debt)

### Task

- [ ] Deprecate L1–L5 di schema.
- [x] Tambahkan `finding_verdict`. ✅ 2026-08-02 (Sumbu A `myc_finding`
  `finding`: CLEAN/FINDINGS/INCONCLUSIVE, dihitung di `myc_reduce_verdict`
  dari typed gate status — prioritas FINDINGS > INCONCLUSIVE > CLEAN, hanya
  gate diminta yang berpengaruh; dipisah dari verdict legacy; tampil di teks
  `finding:` + JSON `"finding"`; regresi all-green).
- [x] Tambahkan `verification_completeness`. ✅ (Sumbu B `completeness` Fase 3)
- [x] Tambahkan evidence matrix. ✅ 2026-08-02 (`gate_matrix[]` id+status di
  JSON + blok `evidence:` ringkas di teks = per-scope status konkret; tidak
  bergantung pada label assurance L1–L5).
- [ ] Tambahkan scope certificate.
- [x] Tambahkan unverified debt. ✅ 2026-08-02 (`unverified_debt[]` teks + JSON, turunan dari typed gate status: UNAVAILABLE / INFRA_FAILED / INCONCLUSIVE / driver 0-kasus / ensures-unproved / output-truncated; regresi di `_regress_run.bat`).
- [ ] Buat compatibility renderer bila masih ingin menampilkan label lama.
- [ ] Claim compiler mencegah wording berlebihan.

### Acceptance criteria

Output tidak pernah menyebut:

```text
FULL
PROVEN
memory-safe
```

kecuali obligation yang didefinisikan benar-benar terpenuhi dan scope dicetak.

---

## Fase 5 — Reentrancy dan Memory Ownership ?

### Task

- [x] Tambahkan `myc_context`. (arena bump milik hasil; `myc_result_arena_dup`)
- [x] Result-owned diagnostics. (message diagnostic disalin ke arena, bukan static ring)
- [x] Hapus static message rings. (compile/run/prove/filc/driver/contract licked)
- [x] Hapus global lint state. (`buf_vars` -> `_Thread_local`)
- [x] OOM status propagated. (arena_dup mengembalikan NULL; caller skip diagnostic saat OOM)
- [x] `myc_result_free` reset penuh atau document single-use. (arena dibebaskan utuh)
- [x] Tambahkan allocator injection untuk test. (stress_threads.c jalankan myc_run paralel)

### Acceptance criteria

- 64 thread x 1.000 request;  (implementasi batas Windows: stress_threads.c, 8 thread x 200 iter)
- no race;             (static message ring dihapus; stress_threads.c OK)
- no stale diagnostic; (source_sha256 tidak pernah berubah antar iterasi thread)
- no leak;             (arena dibebaskan utuh di myc_result_free; test L4 di bawah)
- result lama immutable. (arena milik hasil; request baru tak menyentuh hasil lama)

---

## Fase 6 — Ketatkan JSON dan MCP ?

### Task

- [x] Strict JSON number grammar. (leading zero, frac/exp tanpa digit ditolak)
- [x] Length-aware strings. (parser menolak embedded NUL `\u0000`; sb overflow guard)
- [x] Valid UTF-8 policy. (raw UTF-8 divalidasi; overlong/continuation/surrogate tolak)
- [x] Surrogate pair validation. (lone high/low surrogate tolak)
- [x] OOM propagation. (semua mutasi return status; sb_reserve OOM -> parse fail)
- [x] Capacity overflow guard. (sb_reserve / obj_set / arr_push cek SIZE_MAX)
- [ ] JSON-RPC 2.0 validation.
- [ ] Notification no-response semantics. (sudah ada di handle_message; verifikasi)
- [ ] Typed ID preservation.
- [ ] `structuredContent`.
- [ ] schema version.
- [ ] `isError` hanya transport/tool-call error.

### Acceptance criteria

- corpus JSONTestSuite relevan;  /// json_abuse.c 52 case (valid/invalid) OK
- libFuzzer/AFL corpus stabil;  (regresi _regress_run.bat: json_abuse)
- official MCP SDK interop;    (24 cek lulus)
- malformed input tidak crash/hang;
- embedded NUL tidak truncate.

---

## Fase 7 — Perbaiki Backend Satu per Satu

### 7.1. GCC/Clang compile

- [ ] machine-readable diagnostic;
- [ ] exact tool identity;
- [ ] `/dev/null` fix;
- [ ] fingerprint incremental;
- [ ] output truncation status.

### 7.2. Runtime sanitizer

- [ ] absolute temp path; *(sebagian selesai Fase 1)*
- [x] `mkdtemp`; ✅ (temp dir absolut & unik, MyC_AUDIT-003)
- [ ] explicit sanitizer env;
- [x] canary ✅ 2026-08-02 (`myc_runtime_canary`: OOB deterministik dijalankan
      sebelum `COMPLETED_CLEAN`; canary tak terdeteksi -> INCONCLUSIVE)
- [ ] report channel non-spoofable;
- [ ] input portfolio.

### 7.3. Checked buffer

- [ ] elem size metadata;
- [ ] checked multiplication;
- [ ] coverage count;
- [ ] type mismatch trap;
- [ ] semantics parity tests.

### 7.4. Contract

- [ ] no silent truncate;
- [ ] multiple requires;
- [ ] pure expression validation;
- [ ] explicit clause status;
- [ ] stable function binding.

### 7.5. Driver

- [ ] case record;
- [ ] replay capsule;
- [ ] 0-case classification;
- [ ] boundary portfolio;
- [ ] combinatorial budget.

### 7.6. Frama-C

- [ ] separate Eva/WP;
- [ ] native POSIX path;
- [ ] version/model/entry point;
- [ ] machine output if available;
- [ ] proof obligation counts.

### 7.7. Fil-C

- [ ] remove `FULL`;
- [ ] fix `run_stdin` under WSL;
- [ ] version identity;
- [ ] robust report parser;
- [ ] per-case scope.

---

## Fase 8 — Test Engineering

### Task

- [ ] Cross-platform build scripts.
- [ ] CI Windows + Linux.
- [ ] GCC + Clang.
- [ ] Debug + release + sanitizers.
- [ ] proc adversarial helper suite.
- [ ] allocator fault injection.
- [ ] JSON fuzz/property tests.
- [ ] concurrent API tests.
- [ ] exact receipt golden tests.
- [ ] backend canary tests.
- [ ] output boundary tests.
- [ ] cancellation and timeout tests.
- [ ] path length tests.
- [ ] Unicode tests.
- [ ] 32-bit build bila tersedia.

### Acceptance criteria

Tidak ada release tanpa lulus seluruh trust-core suite.

---

## Fase 9 — Gagasan Pembeda

Urutan implementasi yang paling memberi reputasi:

1. [x] Evidence Receipt ✅ 2026-08-02 (`receipt_sha256`: hash deterministik atas
      verdict+completeness+gate status+debt+fingerprint+source_sha; determinis
      utk input sama, berbeda antar verdict; teks+JSON; regresi di `_regress_run`)
2. [x] Unverified Debt ✅ 2026-08-02 (deduksi murni dari typed gate status; laporan teks + JSON; regresi di `_regress_run.bat`)
3. [x] Semantic Canary ✅ 2026-08-02 (canary OOB dijalankan sebelum gate runtime
      menyatakan clean; tak terdeteksi -> INCONCLUSIVE; evidence di ledger)
4. [ ] Counterexample Replay Capsule
5. [ ] Claim Compiler
6. [ ] Differential Backend Quorum
7. [ ] Scope Certificate
8. [ ] Metamorphic Verification
9. [ ] Negative-Space Analysis

Jangan implementasikan semuanya sekaligus.

Tiga pertama sudah cukup untuk membuat `myc` tampak berbeda dan matang.

---

# 12. Rencana Pengujian yang Benar-Benar Menguji

## 12.1. Filosofi

Test bukan dibuat untuk membuktikan fungsi yang ada berjalan seperti implementasinya.

Test harus berusaha:

- mematahkan asumsi;
- memaksa race;
- memaksa partial failure;
- memaksa output terpotong;
- memaksa OOM;
- memaksa child nakal;
- memaksa hasil ambigu;
- memastikan tool tidak berbohong.

## 12.2. Test `proc.c`

### Deadlock

Helper:

1. menulis 1 MiB stdout;
2. membaca 1 MiB stdin;
3. menulis 1 MiB stderr.

Expected:

```text
completed
no deadlock
correct totals
```

### Simultaneous flood

- stdout 100 MB;
- stderr 100 MB;
- cap 64 KiB masing-masing;
- verify prefix + tail;
- total 100 MB;
- memory bounded.

### Descendant process

Child spawn grandchild yang sleep.

Timeout harus:

- kill child;
- kill grandchild;
- tidak meninggalkan process.

### Exec failure

Program tidak ada.

Expected:

```text
status = EXEC_FAILED
os_error = ENOENT
```

Bukan exit `127` biasa.

### Application exit 127

Program valid memanggil `return 127`.

Expected:

```text
status = EXITED
exit_code = 127
```

Ini harus berbeda dari exec failure.

### Broken stdin

Child menutup stdin segera.

Parent tidak boleh mati karena SIGPIPE.

### Thread/race

- 10.000 parallel short processes;
- ThreadSanitizer;
- no race;
- no leak.

---

## 12.3. Test verdict reducer

Buat table-driven exhaustive test.

Contoh invariant:

```text
if requested gate status is INFRA_FAILED
then completeness != COMPLETE
```

```text
if any completed gate has confirmed finding
then finding_verdict == FINDINGS
```

```text
if runtime cases == 0
then runtime cannot be COMPLETED_CLEAN
```

```text
if output parser failed
then gate cannot be COMPLETED_CLEAN
```

```text
claim FULL is impossible
```

---

## 12.4. Test fingerprint

Input:

- cwd 1, 512, 4.096, 32.000 chars;
- compiler path panjang;
- exact same request twice;
- one flag changed;
- source byte changed;
- environment relevant changed;
- irrelevant environment changed.

Expected:

- no OOB;
- deterministic;
- relevant change changes hash;
- irrelevant change tidak mengubah hash;
- canonical material dapat ditampilkan.

---

## 12.5. Test `myc_buf.h`

- negative signed count;
- `SIZE_MAX / sizeof(T) + 1`;
- wrong type in `MYC_AT`;
- alignment-sensitive type;
- index overflow;
- byte offset overflow;
- reallocation over live buffer;
- double free;
- use after free;
- zero length;
- production vs checked semantic equivalence untuk valid program.

---

## 12.6. Test contract

- 1 requires;
- 10 requires;
- long expression;
- expression exactly at limit;
- side-effect expression;
- macro in expression;
- annotation before declaration;
- annotation before wrong function;
- nested parentheses;
- multiline function signature;
- ensures status;
- OOM at each builder operation.

Tidak boleh ada silent truncation.

---

## 12.7. Test JSON/MCP

- official valid/invalid corpus;
- 8 MiB line exact boundary;
- 8 MiB + 1;
- embedded NUL;
- invalid UTF-8;
- fractional ID;
- string ID;
- null ID;
- notification;
- batch bila unsupported harus ditolak jelas;
- unknown method;
- unknown flag;
- allocation failure;
- cancellation;
- multiple sequential results;
- parallel in-process calls bila API mengizinkan.

---

## 12.8. Test backend honesty

Untuk setiap backend:

1. backend tidak terpasang;
2. backend path salah;
3. backend version unsupported;
4. build gagal;
5. run gagal exec;
6. output malformed;
7. output truncated;
8. canary tidak terdeteksi;
9. clean case;
10. confirmed bad case.

Expected status harus berbeda untuk semua kondisi penting tersebut.

---

## 12.9. Performance regression

CI benchmark:

| Scenario | Budget awal |
|---|---:|
| CLI startup p95 | < 25 ms |
| static check 1 KLOC | < 100 ms + compiler |
| static check 10 KLOC | < 750 ms + compiler |
| MCP warm request overhead | < 5 ms di luar backend |
| idle RSS MCP | < 12 MiB |
| core heap per request | < 4 MiB di luar captured output |
| binary `myc` stripped | < 180 KB |
| binary `mcp` stripped | < 300 KB |

Angka dapat dikalibrasi lintas platform, tetapi budget harus eksplisit.

---

# 13. Kriteria Rilis

## 13.1. Rilis “Trust Core Preview”

Wajib:

- process runner stabil Windows/Linux;
- tidak ada race;
- runtime fixture benar-benar berjalan;
- backend failure tidak menjadi clean;
- typed gate status;
- no scalar max-level;
- result-owned diagnostics;
- strict request validation;
- fingerprint OOB fixed;
- CI dua OS;
- regression tests untuk semua critical findings.

## 13.2. Rilis “0.1 Respectable”

Wajib tambahan:

- evidence receipt;
- scope certificate;
- unverified debt;
- sanitizer canary;
- strict JSON;
- MCP structured result;
- replay capsule minimal;
- performance budget CI;
- stable rule IDs;
- documented limitations.

## 13.3. Rilis “1.0”

Jangan berdasarkan jumlah fitur.

1.0 berarti:

- schema stabil;
- no known critical trust-core bug;
- result reproducible;
- backend status honest;
- all requested scope traceable;
- Windows/Linux parity;
- fuzz and soak matang;
- documented false-positive policy;
- no mutable global state;
- at least one external project dogfood corpus;
- release artifact reproducibly built atau minimal build manifest lengkap.

---

# 14. Posisi Produk dan Identitas Teknis

## 14.1. Posisi yang sebaiknya diambil

Jangan menjual `myc` sebagai:

- “formal verifier lengkap”;
- “memory safety guaranteed”;
- “full security scanner”;
- “AI code security”;
- “pengganti Clang/Frama-C/Fil-C”.

Posisi yang lebih kuat:

> **myc is a tiny evidence orchestrator for C code verification. It runs independent verification gates, records exactly what completed, and never hides unverified scope behind a green badge.**

Versi ringkas:

> **Small binary. Exact evidence. No false confidence.**

Versi Indonesia:

> **Binary kecil. Bukti eksak. Tanpa rasa aman palsu.**

## 14.2. Hal yang membuatnya disegani

Bukan jumlah rule.

Yang membuat `myc` disegani adalah:

1. `OK` selalu dapat dijelaskan;
2. setiap gate memiliki bukti;
3. kegagalan backend tidak disembunyikan;
4. scope tidak dilebihkan;
5. hasil dapat direplay;
6. receipt dapat dibandingkan;
7. binary sangat kecil;
8. tidak bergantung cloud;
9. tidak membawa runtime besar;
10. agent mendapat structured evidence, bukan prose.

## 14.3. README baru harus humble tetapi tegas

Contoh pembukaan:

```markdown
# myc

myc is a small, deterministic C verification orchestrator.

It does not claim that clean output means a program is safe.
Instead, it records which checks actually ran, what they covered,
what they found, and what remains unverified.
```

Ini lebih terhormat daripada `L5 FULL`.

---

# 15. Prioritas Akhir

## Jangan lakukan sekarang

- jangan tambah backend baru;
- jangan tambah banyak regex rule;
- jangan membuat GUI;
- jangan menambah AI ke core;
- jangan mengejar jumlah warning;
- jangan menambah level assurance baru;
- jangan mengoptimalkan sebelum process runner benar;
- jangan menyebut hasil clean sebagai full safety.

## Lakukan sekarang

Urutan paling tepat:

1. **Tulis ulang boundary proses POSIX dengan lifecycle yang benar.**
2. **Perbaiki absolute temp path dan exec-error detection.**
3. **Buat regression test yang membuktikan fixture buruk benar-benar tertangkap.**
4. **Pisahkan code verdict dari verification completeness.**
5. **Ganti L1–L5 dengan evidence matrix.**
6. **Perbaiki fingerprint OOB.**
7. **Hilangkan static/global diagnostic state.** ✅ 2026-08-02 (Fase 5: arena bump milik hasil; static message ring dihapus di compile/run/prove/filc/driver; global lint state -> `_Thread_local`)
8. **Perketat JSON dan string length handling.** ✅ 2026-08-02 (Fase 6: strict number grammar, valid UTF-8, surrogate & embedded NUL tolak, overflow guard; corpus json_abuse.c 52 case)
9. **Tambahkan semantic canary.** ✅ 2026-08-02
10. **Tambahkan evidence receipt + unverified debt.** (unverified debt ✅ 2026-08-02; evidence receipt ✅ 2026-08-02)

## Penilaian akhir

`myc` tidak perlu menjadi tool terbesar untuk menjadi tool yang disegani.

Ia justru dapat menang pada hal yang tool besar sering gagal lakukan:

- startup seketika;
- hasil deterministic;
- dependency nol;
- output yang jujur;
- scope yang eksplisit;
- bukti yang dapat direplay;
- tidak pernah menyamarkan backend gagal sebagai kode aman.

Potensi terbaik `myc` bukan menjadi “scanner kecil dengan banyak level”.

Potensi terbaiknya adalah menjadi:

> **trustworthy verification microkernel untuk kode C—kecil, keras, transparan, dan tidak pernah menjual kepastian yang tidak dimilikinya.**

Jika fondasi tersebut selesai, barulah analisis baru akan memperkuat reputasi. Tanpa fondasi itu, fitur tambahan hanya memperbesar permukaan yang terlihat canggih tetapi sulit dipercaya.

---

## Lampiran A — Temuan yang Harus Menjadi Regression Test

- [ ] POSIX stdin/stdout deadlock.
- [ ] POSIX drain thread join.
- [ ] output complete before result return.
- [ ] process group kill.
- [ ] exec failure vs application exit 127.
- [ ] absolute temp executable path.
- [ ] bad runtime fixture cannot return `OK + complete`.
- [ ] bad checked runtime cannot retain misleading `L4`.
- [ ] long fingerprint material cannot OOB.
- [ ] `file_path`-only request.
- [ ] two simultaneous `myc_run`.
- [ ] old result diagnostic remains immutable.
- [ ] strict JSON number grammar.
- [ ] embedded NUL source via MCP.
- [ ] OOM in JSON object insertion.
- [ ] `MYC_BUF` wrong type.
- [ ] signed negative allocation count.
- [ ] multiple consecutive requires.
- [ ] long contract expression rejected, not truncated.
- [ ] Fil-C WSL receives `run_stdin`.
- [ ] backend output truncation cannot become clean.
- [ ] canary failure invalidates backend.
- [ ] 0 driver cases cannot become runtime clean.
- [ ] unknown CLI/MCP flags rejected.
- [ ] `NUL` is never created on POSIX.

## Lampiran B — Definisi Selesai

Sebuah task tidak dianggap selesai hanya karena kode dikompilasi.

Task selesai bila:

1. regression test gagal pada versi lama;
2. fix dibuat;
3. test lulus pada Windows dan Linux;
4. negative path diuji;
5. OOM/timeout/cancellation path diuji bila relevan;
6. output machine-readable stabil;
7. dokumentasi klaim disesuaikan;
8. performance budget tidak mundur;
9. tidak menambah global mutable state;
10. receipt menunjukkan evidence yang benar.

