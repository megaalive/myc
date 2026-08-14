# Audit History — log kronologis pengembangan myc

> Dokumen ini berisi **sejarah implementasi dan audit** (MYC-AUDIT-001..030 dan
> catatan fase pengembangan). Aturan stabil dan panduan kerja ada di
> `AGENTS.md` di root. Jangan menaruh aturan baru yang mengikat di sini —
> tempatnya di `AGENTS.md` atau `docs/design-contract.md`.
>
> Prinsip lama yang masih berlaku (ringkas): heuristik teks = observasi
> ber-confidence dan non-blocking; satu-satunya gate hard = bukti semantik
> (gcc memory tier `-Werror`/`-fanalyzer`, sanitizer runtime, Eva, checked,
> Fil-C). Detail prinsip: `AGENTS.md`.

---

## Status arah (catatan 2026-08-01)

- Arah baru **sudah diimplementasikan (Fase A, P4+P5, selesai 2026-08-01)**.
- Keputusan user: **policy = non-blocking warning**. Header & fungsi denylist
  tidak lagi menolak program sah. Sejak **MYC-AUDIT-014** (2026-08-02),
  lint memory-safety juga TIDAK lagi hard (heuristik teks = observasi +
  confidence, non-blocking); satu-satunya gate hard = **gate gcc**
  (tier memori `-Werror`, `-fanalyzer` = bukti semantik) + gate runtime
  (sanitizer), proof (Eva), checked (L4), Fil-C.

---

## PR-003, 2026-08-12 (verdict reducer fails-closed + test exhaustif)

Batch PR-003 dari `myc-production-readiness-plan.md`: reducer sentral sudah
ada (`myc_reduce_verdict`, gate.c, MYC-AUDIT-006) — langkah yang benar =
**test exhaustif**, bukan refactor. Test baru `test/reducer_exhaustive.c`
memanggil reducer langsung dengan kombinasi typed gate status (49 + 343
kombinasi + kasus invariant) dan meng-encode INV-001/002/003/011; di-wire
ke `test/_audit018.sh` dan `test/_regress_run.bat`.

**BUG TRUST-CORE ditemukan test:** status gate di luar enum
(`(myc_gate_status)99`) jatuh diam-diam ke `MC_OK` — switch reducer tidak
punya `default:` sehingga status tak dikenal direinterpretasi sebagai
clean (false-OK, melanggar INV-011). Fix minimal (hardening, sesuai P0-T01):
`default: has_incomplete = 1` di `myc_reduce_verdict()` + `default:`
menambah debt `MYC-INCOMPLETE-GATE-INCONCLUSIVE` di `myc_build_debt()`.
Perilaku untuk status valid TIDAK berubah (receipt golden utuh); hanya
input korup/tak dikenal yang kini gagal tertutup.

Dokumen baru (batch PR-001/002): `docs/production-readiness.md`
(level PR-0..PR-4), `docs/production-invariants.md` + registry
`docs/production-invariants.json` (INV-001..015, tiap invariant menunjuk
modul + test), `docs/verdict-state-inventory.md` (inventaris semua mutasi
verdict/gate/assurance/debt/err). Closure audit PR-004:
`docs/audit-closure/MYC-AUDIT-001..005.md` (root cause/trigger/impact/
fix/regresi/residual; fix commit `7be12b5` utk 001/002/003-partial/005,
`71d297c` utk 004, `7aae6df` utk 003-driver). Verifikasi: reducer test
lolos, `_audit018.sh` SELESAI OK.

---

## PR-005, 2026-08-12 (hostile child process fixture)

Batch PR-005 dari `myc-production-readiness-plan.md` (P1-T02): binary
pembantu **standalone** `test/proc_fixture.c` (tanpa dependensi myc,
portabel Windows MinGW + POSIX, `-Werror -pedantic` clean) dengan mode
child bermusuhan DETERMINISTIK untuk menguji process runner `proc.c`
pada batch PR-006 (deadlock matrix) dan PR-007 (timeout/process-tree
kill): `--exit N`, `--sleep MS`, `--stdout N` (byte 'A'), `--stderr N`
('B'), `--both N` (dua pipe penuh selang-seling), `--read-stdin N`,
`--never-read-stdin`, `--close-stdout`/`--close-stderr` (tutup descriptor
level OS), `--spawn-child`/`--spawn-grandchild` (re-invoke diri sendiri +
wait, cetak `spawned_child=<pid>` SEBELUM menunggu — baris pid selalu
tertangkap walau parent dibunuh), `--crash` (SIGSEGV), `--hang-after-
output`, `--output-after-stdin`/`--stdin-after-output` (ordering
stdin/stdout), `--unicode-output` (UTF-8 multibyte), `--binary-output`
(NUL + 0xFF siklik), `--self-pid`, `--help`. Pada Windows stream dipaksa
mode BINER (`_setmode`) agar byte count eksak di pipe (tanpa CRLF
/Ctrl-Z) — prasyarat deadlock matrix. Wire: build + smoke test 19 mode
di `test/_audit018.sh` (guard `timeout(1)` untuk hang). Verifikasi:
`-Werror -pedantic` bersih; smoke semua mode lulus (exit code, byte
count, chain 3 level `--spawn-grandchild --spawn-child --exit 5` → 5,
crash → 139, hang → 124).

## PR-006, 2026-08-12 (deadlock matrix + fix hang stdin write)

Batch PR-006 dari `myc-production-readiness-plan.md` (P1-T03): matriks
deadlock `test/proc_deadlock_matrix.c` yang memakai `proc_fixture` (PR-005)
via `myc_proc_run`. Fixture mendapat mode baru `--matrix S O E ORDER`
(PR-006): kendali penuh ukuran stdin/stdout/stderr (0/4K/256K/8M) +
urutan I/O `read-first`/`write-first`/`interleave`, tanpa byte tambahan di
payload (byte count eksak untuk asersi harness).

Dimensi & cakupan (P1-T03): **T1** full Cartesian 4×4×4 ukuran I/O (64
kombinasi, order interleave, cap default); **T2** dimensi order × 3 combo;
**T3** timeout — hang + stdin 8M (regresi fix di bawah), tree-kill
`--spawn-child --sleep 60000` + orphan check via `spawned_child=<pid>`
(poll `kill(pid,0)`/`GetExitCodeProcess` s.d. 5 s), child normal (timeout
tidak terpicu); **T4** output cap — hit 64K, miss, `cap=0`→default 1M,
ring biner `--binary-output` (prefix 0x00, tail 0xFF); **T5** EPIPE — child
tak pernah baca stdin (`--never-read-stdin` + `--exit 0`, stdin 8M); **T6**
`--close-stdout`/`--close-stderr`; **T7** stress loop (`--stress N`, default
100; orphan spot-check tiap 25 iterasi; bounded memory via
`getrusage`/`GetProcessMemoryInfo`). Setiap kegagalan memuat konfigurasi
lengkap (seed/config untuk reproduce, sesuai batch PR-006).

**BUG TRUST-CORE ditemukan (hang abadi):** tulis stdin di `proc.c`
blocking sinkron SEBELUM loop timeout — child yang tidak membaca stdin dan
tidak pernah exit (mis. `--sleep 60000`) membuat `myc_proc_run`
menggantung abadi walau `timeout_ms` diset. Dikonfirmasi probe: dur=8157
ms dengan timeout_ms=1500 ms, proses hanya berhenti karena kill eksternal.
Fix (hardening, P0-T01): stdin ditulis dari **thread terpisah**
(`stdin_writer_thread`; Windows `_beginthreadex` + POSIX
`pthread_create`) sehingga loop tunggu utama berjalan bersamaan; pada
timeout kill pohon memutus pipe → writer berhenti (EPIPE / broken pipe)
dan di-join (bounded 2000 ms di Windows). POSIX: cek execvp dipindah
sebelum writer; SIGPIPE diabaikan selama writer hidup dan dipulihkan
setelah join; sisi tulis stdin ditutup pada timeout agar EPIPE pasti.
Perilaku kasus normal TIDAK berubah (receipt utuh).

**Regresi ditemukan saat wire (lalu diperbaiki):** versi awal writer tidak
menutup sisi tulis stdin setelah selesai — child yang membaca stdin
sampai EOF (mis. drain_stdin di proc_flood T1 / `--stdin-after-output`)
memblok selamanya menunggu EOF → timeout 60 s (proc_flood T1 gagal di
suite). Fix: writer thread MENUTUP sisi tulis stdin sendiri saat selesai
(seluruh byte terkirim atau EPIPE) sehingga EOF mengalir ke child;
pemanggil men-set `stdin_wr=NULL`/`in_pipe[1]=-1` setelah join agar tidak
double-close. Verifikasi: proc_flood T1 selesai 63 ms, `--stdin-after-
output` drained=1048576 dalam 47 ms; hang probe tetap `timed_out=1
dur=1500`; matriks penuh 0 gagal.

Verifikasi (foreground, Windows): matriks penuh OK (114 cek, 0 gagal,
~30 s); `--stress 2000` → **6.080 eksekusi myc_proc_run, 0 deadlock, 0
orphan, memori stabil (16840→16840 KB)**; hammer 200× kasus terberat
8M/8M interleave OK tanpa kebocoran child. Exit criteria P1-T03 penuh
(10.000 eksekusi berulang per OS) = `proc_deadlock_matrix <fixture>
--stress 10000`; catatan: percobaan via `nohup` background tidak valid
(proses ter-orphan saat shell runner dibunuh → melambat drastis lalu
macet — artefak lingkungan, TIDAK dapat direproduksi foreground).
Wire blok 9 di `test/_audit018.sh` (guard `timeout 300` eksternal agar
deadlock = FAIL, bukan hang CI; probe `-lpsapi` untuk Windows; log
matriks di-tee ke `test/proc_deadlock_matrix.log` agar kegagalan memuat
konfigurasi lengkap). Hardening review: matriks punya deadline internal
10 menit (anti-hang standalone), timeout tree-kill 1500→2500 ms (anti
false-fail di CI lambat), dan close redundan sisi tulis stdin pada
branch timeout POSIX dihapus (kill → EPIPE sudah membuka blokir writer;
close ganda rapuh).

Observasi (bukan fix, ditunda PR-007): ketidakkonsistenan `timeout_ms=0`
— POSIX = tanpa batas (sesuai header), Windows = fallback
`MYC_DEFAULT_TIMEOUT_MS` (30 s).

---

## PR-007, 2026-08-12 (process-tree cleanup: Job Object + kill group)

Batch PR-007 dari `myc-production-readiness-plan.md` (P1-T04): mengunci
perilaku **cleanup pohon proses pada timeout** — timeout `myc_proc_run`
harus membunuh SELURUH pohon (child + grandchild + job nested), bukan
hanya child langsung. Test baru `test/proc_tree_kill.c` memakai
`proc_fixture` (PR-005) via `myc_proc_run` dengan mode spawn baru:

- **T1** chain 3-level `--spawn-grandchild --sleep 60000`: timeout →
  child + grandchild (C1, C2) ikut mati. Verifikasi zero-orphan via
  (a) parse `spawned_child=<pid>` + poll `kill(pid,0)`/
  `GetExitCodeProcess` s.d. 2500 ms, (b) **Toolhelp scan** (Windows)
  `Process32First/Next` untuk membuktikan TIDAK ada `proc_fixture.exe`
  tersisa — bukti nol-stray lebih kuat daripada cek pid (lihat temuan
  handle di bawah).
- **T2** breakaway attempt `--spawn-breakaway`: child meminta
  `CREATE_BREAKAWAY_FROM_JOB` (dan `CREATE_NEW_PROCESS_GROUP` POSIX) —
  asersi: assignment ke job myc DITOLAK → pohon tetap terikat → semua
  ikut mati pada timeout. Ini membuktikan job myc tidak bisa "dikaburkan"
  oleh child yang meminta breakaway.
- **T3** nested job `--spawn-jobchild`: child membuat job sendiri
  (`CreateJobObject` + assign grandchild) — asersi: grandchild di job
  fixture TETAP ikut mati (kill pohon menembus nested job karena
  `KILL_ON_JOB_CLOSE` myc).
- **T4** inherited handles `--spawn-detach`: child menutup pipe stdout
  level OS lalu exit cepat — asersi: myc TIDAK menunggu grandchild
  (dur < 1500 ms; handle pipe tidak bocor ke generasi jauh sehingga
  drain tidak menggantung). Platform-split: Windows grandchild ikut
  mati saat myc menutup handle job pada normal completion
  (`KILL_ON_JOB_CLOSE` membersihkan stray — crash-safe); POSIX tidak
  (tidak ada job).
- **T5** normal chain `--spawn-grandchild --spawn-child --exit 7` tanpa
  timeout: chain exit normal (7) tanpa kill.

**Hardening proc.c (Windows):** (1) hasil `AssignProcessToJobObject`
kini dicek dan disimpan (`job_assigned`) — bila assignment gagal (job
sudah penuh / child menolak / sistem tanpa job), fallback jujur ke
`TerminateProcess(child)` + cleanup sisa via Toolhelp scan; (2) kegagalan
`_beginthreadex` untuk drain thread kini fail-fast (`MYC_ERR_INTERNAL`)
— sebelumnya handle NULL di-`WaitForSingleObject` (hang). POSIX: kill
process group (setpgid) sudah ada; perilaku tidak berubah.

**Temuan platform penting (dokumentasi perilaku, bukan bug):**
`proc_fixture` memakai `bInheritHandles=FALSE` (hygiene handle) → C1/C2
tidak mewarisi pipe stdout → baris pid grandchild TIDAK pernah sampai ke
myc (bukan kegagalan kill). Karena itu T1 memakai Toolhelp scan sebagai
bukti utama zero-orphan (lebih kuat). Kedua: `KILL_ON_JOB_CLOSE` pada
Windows berarti stray process (termasuk yang di-detach lewat pipe) mati
saat myc menutup handle job pada NORMAL completion — perilaku
platform yang di-encode sebagai asersi platform-split di T4.

Wire blok 10 di `test/_audit018.sh` (guard `timeout 180` eksternal;
log di-tee ke `test/proc_tree_kill.log`). Verifikasi (Windows):
T1–T5 semua hijau (chain 3-level zero orphan via Toolhelp, breakaway
ditolak, nested job ikut mati, detach 31 ms tanpa menunggu, chain exit
7), nol proc_fixture tersisa setelah run; `-Werror` bersih; diff check
bersih.

Observasi (bukan fix): field `myc_proc_result.cancelled` (proc.h) dan
error `MYC_ERR_CANCELLED` (myc.h) tidak pernah di-set/dihasilkan di
seluruh codebase — vestigial sejak awal; tidak ada mekanisme cancel
async untuk `myc_proc_run` saat ini. Sisa observasi `timeout_ms=0` dari
PR-006 (POSIX tanpa batas vs Windows fallback 30 s) tetap terbuka.

### Review fixes (code-reviewer, 2026-08-12)

Code review menemukan celah verifikasi: branch POSIX fixture (PR-005/006/
007) **tidak pernah di-compile** — clang/gcc Windows hanya meng-compile
branch `_WIN32`, jadi bug POSIX lolos 3 batch. Verifikasi via WSL
(`gcc -fsyntax-only` di Ubuntu-24.04) menemukan 3 bug nyata di
`test/proc_fixture.c` dan 1 di `test/proc_tree_kill.c`, SEMUA diperbaiki:

1. `fcntl.h` tidak di-include di branch POSIX fixture → `F_GETFD`/
   `F_SETFD`/`FD_CLOEXEC` undeclared (mode `--spawn-detach` gagal
   compile Linux).
2. `child_argv` dibangun di luar `#ifdef _WIN32` tapi hanya dipakai
   branch Windows → `-Werror=unused-but-set-variable` di POSIX
   (`mode_spawn_breakaway`/`mode_spawn_jobchild`; build dipindah ke
   dalam branch `_WIN32`).
3. `nanosleep`/`fileno` butuh `_POSIX_C_SOURCE` (glibc meng-cache
   feature test macro di include guard → define wajib SEBELUM semua
   include) di fixture DAN `kill` butuh `<signal.h>` + `_POSIX_C_SOURCE`
   di proc_tree_kill.c.

Setelah fix: compile POSIX `-Werror -pedantic` bersih untuk ketiga file
(proc.c, proc_fixture.c, proc_tree_kill.c), dan **run penuh T1–T5 di
Linux (WSL) hijau** — T1 melihat 2 pid (exec mewarisi fds, beda dari
Windows bInheritHandles=FALSE yang hanya 1), T2/T3 status=2 N/A,
T4 POSIX branch grandchild hidup + self-clean, T5 exit 7. Label pesan
T2 Windows juga dirapikan agar jujur ("TIDAK ada breakaway_status=1 =
lubang job, wajib FAIL" — sebelumnya mencetak "breakaway SUKSES"
sebagai [OK] saat penolakan berhasil, menyesatkan).

---

## PR-008, 2026-08-12 (semantic evidence spoof corpus)

Batch PR-008 dari `myc-production-readiness-plan.md` (P2-T02 / INV-006):
korpus spoof bukti semantik — teks yang MENIRU bukti (ASan/UBSan/GCC/
Frama-C/Fil-C/marker internal MYC) melalui stdout, stderr, file report,
komentar source, nama file, dan argumen program TIDAK boleh menjadi hard
evidence (zero false violation; verdict tetap OK).

**GAP SPOOF NYATA ditemukan (file report palsu):** program yang diuji
berjalan dengan `cwd = tmp_dir` (run.c step 5), dan
`myc_read_sanitizer_report` membaca file wildcard `<dir>/<base>.*` — jadi
program BERSIH bisa menulis file `myc_run_asan_rpt.<pid>` / `myc_run_
ubsan_rpt.<pid>` (nama persis log_path ASan) berisi teks spoof di cwd-nya
sendiri, lalu exit 0, dan report palsu itu DIBACA sebagai bukti
non-spoofable → `RUNTIME_VIOLATION` PALSU. Dikonfirmasi empiris dengan
`myc.exe` PRA-hardening: source bersih yang hanya menulis dua file report
palsu + mencetak satu marker lalu exit 0 → `verdict: RUNTIME_VIOLATION`
("sanitizer runtime: ERROR: AddressSanitizer (report: log_path di tmp
dir)"). Ini jalur spoof yang TIDAK tercakup MYC-AUDIT-017 (yang hanya
menutup marker teks stdout/stderr).

**Hardening (INV-006, 6 titik):** report sanitizer kini HANYA bukti bila
`exit code != 0` — konsisten dengan aturan marker teks. Karena env memakai
`abort_on_error=1`/`halt_on_error=1`, bug memori nyata SELALU berakhir
non-zero (abort/SIGABRT); report yang muncul bersama exit 0 = file buatan
program → DITOLAK + dibersihkan. Titik yang di-fix: gate run,
`--metamorphic`, `--divergence` (run.c); gate `--driver`, exhaustive,
fuzz (driver.c). Deteksi bug nyata TIDAK berubah (ASan abort → exit != 0
→ report tetap bukti). Canary tidak disentuh (bukan verdict).

Audit saluran lain: **filc.c sudah aman** — `panics > 0 && exit_code !=
0` baru jadi `MC_FILC_VIOLATION`; baris kanonik `[pid] filc panic:`
palsu + exit 0 diabaikan (di-reset `filc_panics=0`). **prove.c aman
struktural** — gate menjalankan `frama-c` (backend) yang mem-PARSE source;
program yang diuji TIDAK pernah dijalankan, jadi tidak bisa mencetak
`[eva:alarm]`; string literal/komentar berisi marker tidak menghasilkan
alarm Eva. `--driver`/exhaustive/fuzz memakai env log_path sendiri
(`myc_drv_*`/`myc_exh_*`/`myc_fuz_*`) dan kini menerapkan aturan yang sama.

**Deliverable:**

- `tests/evidence_spoof.c` — fixture program BERSIH yang mencetak SEMUA
  marker P2-T02 + marker internal ke stdout+stderr, mode
  `--fake-report` (tulis `<base>.<pid>` palsu di cwd), `--exit N`,
  `--echo-argv` (marker via argumen), `--help`. `-Werror -pedantic`
  bersih; `myc check` pada fixture → OK.
- `test/evidence_spoof.c` — unit test (gaya audit_lampiran,
  `myc_run()` end-to-end): **T1** fixture marker di stdout/stderr + exit
  0 → run gate OK + `sanitizer_detected=0` + diagnostic "diabaikan";
  **T2** source yang menulis file report palsu `myc_run_asan_rpt.<pid>`
  + `myc_run_ubsan_rpt.<pid>` + marker + exit 0 → run gate OK (REGRESSION
  hardening: sebelumnya RUNTIME_VIOLATION); **T3** baris kanonik panic
  Fil-C + exit 0 → bukan FILC_VIOLATION; **T4** teks `[eva:alarm]` di
  komentar/string source → bukan PROVE_VIOLATION; **T5** komentar berisi
  semua marker + file bernama `myc_run_asan_rpt.*` → run gate OK;
  **T6** driver: fungsi ber-kontrak menulis `myc_drv_asan_rpt.<pid>`
  palsu + marker + exit 0 → bukan DRIVER_VIOLATION. Assertion kuat hanya
  bila backend tersedia (clang/filc/frama-c); tanpa backend gate di-skip
  dan verdict tetap OK — assertion inti "tidak pernah false violation"
  berlaku di semua lingkungan.
- Wire blok 11 di `test/_audit018.sh` (build fixture smoke + unit test,
  guard `timeout 300` eksternal, log di-tee).
- `docs/production-invariants.md` INV-006 diperbarui (implementasi +
  daftar test).

**Verifikasi (Windows):** unit test penuh lulus — T1/T2/T5/T6 asersi kuat
(clang tersedia): semua verdict OK, `sanitizer_detected=0`, fake report
ditolak; T3/T4 (filc/frama-c tak tersedia) → verdict INCONCLUSIVE
(INV-001: gate diminta yang tak tersedia = incomplete; BUKAN false
violation).

**Positive control (bug nyata TIDAK hilang oleh aturan `report && exit !=
0`) — kritis karena fix mengikat validitas report ke exit code:** rebuild
`myc.exe` (build.bat) lalu `--run` pada fixture bug nyata: bad_run_oob /
bad_run_uaf / bad_run_intovf → **RUNTIME_VIOLATION** (exit abort non-zero
+ report tetap bukti); spoof_marker_run → OK; ok_run → OK;
`_anti_false_ok.sh` PASS=7 FAIL=0. POSIX diverifikasi STRUKTURAL dari
proc.c: `WIFSIGNALED → exit_code = 128 + WTERMSIG` (SIGABRT → 134 ≠ 0),
jadi ASan abort di Linux tetap non-zero → report tetap bukti; Windows
GetExitCodeProcess: abort() → 3 (non-zero). Canary juga diselaraskan
(PR-008: report/marker canary hanya "backend sehat" bila exit != 0).
Observasi lingkungan (BUKAN regresi PR-008): `myc` CLI di WSL dev env ini
TIMEOUT instan bahkan `check` tanpa `--run` (duration 0 ms, pre-existing;
CI Linux native memakai `_ci_linux.sh`, bukan WSL) — positive control
POSIX diandalkan pada verifikasi struktural di atas.

Regression T2 tervalidasi dua arah: `myc.exe` pra-hardening →
RUNTIME_VIOLATION; build baru → OK. Zero leftover file report palsu di
repo (tmp dir dibersihkan `myc_remove_sanitizer_reports`). Self-dogfood
`run.c`/`driver.c`/fixture OK; diff check bersih.

Batas jujur (bukan non-goal baru): program yang diuji berjalan NATIVE
(sesuai P14-T02 non-goal "full sandboxing"); program yang AKTIF menyerang
myc (mencari path tmp_dir lalu menulis report + exit != 0) masih bisa
memalsukan report — diluar cakupan, tetapi spoof TIDAK SENGAJA dan spoof
via stdout/stderr/argv/komentar/nama-file kini ditutup penuh, danspoof file + exit 0 (kasus realistis program bersih yang menulis file aneh)
ditolak.

---

## PR-009, 2026-08-12 (malformed backend output corpus / parser abuse)

Batch PR-009 dari `myc-production-readiness-plan.md` (P2-T03 tahap 1 —
parser abuse DETERMINISTIK sebelum fuzzing di PR-010): parser backend —
GCC JSON diagnostics, GCC text fallback, sanitizer logs, Frama-C Eva,
Fil-C, dan internal JSON + konsumen JSON (budget/scenario/calib/cache) —
di-abuse dengan output MALFORMED deterministik. Required behavior
(P2-T03): parser hanya menghasilkan VALID / INVALID / RESOURCE_LIMIT;
**NEVER crash; NEVER promote malformed evidence to clean (INV-001) atau
ke finding palsu (INV-011)**.

Strategi (parser backend bersifat `static` di compile.c/prove.c/filc.c):

- internal JSON + konsumen diuji LANGSUNG via API publik dengan korpus
  malformed deterministik (`test/backend_abuse.c` T1/T2/T5);
- parser GCC/Fil-C/Eva diuji END-TO-END lewat **fake backend**
  (`tests/backend_fake.c` — binary tunggal berperan sebagai gcc /
  filc-clang / frama-c dipilih env `MYC_FAKE_ROLE`, output per mode
  `MYC_FAKE_MODE`, exit per mode; `-o <exe>` menyalin dirinya sendiri
  untuk role build+run filc). Fake gcc via `req.gcc_program`; fake
  filc-clang/frama-c via PATH (`myc_find_executable`).

**GAP INV-001 NYATA ditemukan & diperbaiki (prove.c POSIX):** jalur
native POSIX `myc_prove_gate` — exit 0 + 0 alarm → langsung
`COMPLETED_CLEAN` TANPA mengecek "ANALYSIS SUMMARY", tidak konsisten
dengan jalur WSL yang mengeceknya. Konsekuensi: fake frama-c (atau
backend rusak) yang keluar 0 dengan garbage tanpa summary akan
dipromosikan jadi clean PALSU. Fix (hardening, P0-T01): exit 0 + 0
alarm kini HANYA `COMPLETED_CLEAN` bila output memuat "ANALYSIS
SUMMARY"; tanpa summary → `NOT_APPLICABLE` (skip jujur, assurance
statis dipertahankan) + evidence "Eva di-skip: tanpa ANALYSIS SUMMARY
(INV-001)". Verdict OK tetap mungkin (skip tidak menurunkan), tetapi
tidak ada lagi klaim clean dari output malformed.

Korpus malformed (fixture + unit test): truncation di SETIAP posisi byte
(4 seed), dup keys, deep nesting 200 (depth cap), huge/ekstrem numbers
(`1e999`, `-92233720368547758080`, int64 literal), NUL embedded, UTF-8
invalid, oversized string 256 KB / pesan 100 KB, reordered fields,
unknown enum values, trailing garbage, missing closing, empty, dan
garbage biner + exit-0 (TIDAK boleh jadi violation — konsisten aturan
PR-008).

**Deliverable:**

- `tests/backend_fake.c` — fake backend multi-role (gcc/filc-clang/
frama-c) dengan korpus malformed deterministik (~30 mode), `-Werror
-pedantic` bersih, portabel Windows + POSIX; `--help` mendokumentasikan
env.
- `test/backend_abuse.c` — unit test 6 blok: **T1** `json_parse` korpus
  (truncation per-byte 4 seed + 18 kelas mutasi + depth cap + oversized);
  **T2** konsumen JSON fails-closed (budget skema/unknown gate/unknown
  level, calib unknown outcome, scenario file korup, cache file korup →
  replay miss); **T3** GCC diagnostics E2E via fake gcc (18 mode: JSON
  valid/truncated/garbage/dupkeys/deep/hugenum/nul/utf8/oversized/
  reordered/unknown-kind/note-only, text valid/hugeloc/garbage/nul/
  nocolon, exit-0+garbage → OK); **T4** Fil-C E2E via fake filc-clang
  (6 mode: panic valid/exit0/truncated/garbage/dup/oversized — positive
  control `filc-panic-valid` → `MC_FILC_VIOLATION`); **T5** report
  sanitizer file korup/kosong/tidak-ada + cleanup wildcard; **T6** Eva
  E2E via fake frama-c (POSIX-only; Windows memakai WSL → SKIP).
- Wire blok 12 di `test/_audit018.sh` (build fixture -Werror + smoke 4
  mode + build unit test + env `MYC_FAKE_GCC`/`MYC_FAKE_FILC_DIR` +
  guard `timeout 300` eksternal + cleanup).
- `docs/production-invariants.md` INV-001 dan INV-011 diperbarui
  (implementasi PR-009 + daftar test).

**Verifikasi (Windows):** unit test penuh lulus — T1 (truncation 4×22
posisi + 18 case + deep 200 + 256 KB), T2 (8 case budget + calib +
scenario + cache korup → fail-closed), T5 (4 case), T3 18/18 mode,
T4 6/6 mode (panic valid/dup → violation; exit-0/truncated/garbage/
oversized → BUKAN violation); T6 SKIP (Windows-WSL, POSIX-only).
`_audit018.sh` SELESAI OK dengan blok 12; self-dogfood prove.c OK;
`-Werror` prove.c/unit/fixture bersih; diff check bersih; zero leftover
artefak (fixture + fake dir dibersihkan).

Batas jujur (bukan non-goal baru): fake backend menguji parser pada
input yang TIDAK PERNAH dihasilkan backend sungguhan — pengujian
KETAHANAN (never crash, never false-clean), bukan validasi kesetaraan
dengan format GCC/Frama-C/Fil-C asli (itu wilayah P5 backend
qualification). Korpus deterministik ini menjadi seed awal fuzzing PR-010.

---

## PR-010, 2026-08-12 (parser fuzz harness + fix hang stdin EOF)

Batch PR-010 dari `myc-production-readiness-plan.md` (P2-T03 tahap 2 —
fuzzing DETERMINISTIK dengan korpus PR-009 sebagai seed awal): harness
fuzz `test/parser_fuzz.c` (standalone, `-Werror -pedantic`, seed PRNG
default deterministik `0x9E3779B9` + `--seed`) menerapkan SEMUA kelas
mutasi P2-T03 — grammar-aware (dup key, reorder, unknown enum),
truncation di SETIAP posisi byte (pass khusus seed <= 1 KB), extreme
nesting (melewati `JSON_MAX_DEPTH` 64), extreme numbers (`1e999`,
`-92233720368547758080`, literal int64), embedded NUL, invalid UTF-8
(overlong/surrogate/lone continuation), oversized strings (hingga 32 KB),
reordered fields, bit flip / byte insert-delete-set / splice dua seed /
truncate.

Target:

- **A. json_parse LANGSUNG** + invariant round-trip (serialize → parse
  ulang wajib valid, MYC-AUDIT-042) + `json_clone`
  (serialize(clone) == serialize);
- **B. konsumen JSON langsung fail-closed (INV-011)**: budget, calib
  outcome/id, scenario file korup (verdict TIDAK boleh berubah),
  cache file korup (replay miss);
- **C. parser backend E2E** via mode baru `payload-file` di
  `tests/backend_fake.c` (`MYC_FAKE_PAYLOAD_FILE`): byte mutasi APA PUN
  mencapai parser ASLI `ingest_gcc_diagnostics` / `parse_filc_report` /
  `count_eva_alarms`. Invariant INV-006: garbage tanpa marker kanonik
  TIDAK pernah jadi finding; marker kanonik + exit!=0 = bukti sah
  (positive control tetap terdeteksi).

**Crash/semantic seed dipersist ke `.myc/regression/parser_<sha8>.bin`**
+ `parser-index.txt` (idempoten per sha8, sha256_hex); `--replay`
menjalankan ulang semua seed tersimpan per target (backstop: parser yang
berhenti menangkap = terlihat sebagai FAIL replay, bukan kesunyian).
POSIX: handler sinyal menulis seed saat ini sebelum exit non-zero;
Windows: deteksi crash = lane ASan + seed direpro via `--seed/--iters`
(deterministik). Wire blok 13 di `test/_audit018.sh` (build fixture +
harness -Werror, env `MYC_FAKE_GCC`/`MYC_FAKE_FILC_DIR`, run
`--iters 40000 --e2e-iters 8` + `--replay`, guard `timeout 420`
eksternal, lane ASan bila toolchain menyediakan).

**BUG TRUST-CORE ditemukan (proc.c, hang stdin EOF — pajak ~15 s di
SETIAP `myc check`):** investigasi timing E2E menunjukkan `myc check`
polos (tanpa filc, tanpa fake) butuh ~15,5 s wall / 0,02 s CPU padahal
`duration: 172 ms` di report — `--no-assumptions` menurunkan ke 0,5 s.
Akar: `myc_assume_fetch_facts` menjalankan `gcc -dM -E -` (stdin kosong)
dengan `timeout_ms=15000`; saat `stdin_len == 0`, `proc_run_win` TIDAK
membuat writer thread, sehingga write end pipe stdin (`stdin_wr`) tidak
pernah ditutup → gcc memblok menunggu EOF → terbunuh timeout → fakta
toolchain gagal diam-diam. Bug yang sama ada di cabang POSIX
(`in_pipe[1]`). Dampak: (1) pajak ~15 s per panggilan `myc_proc_run`
yang child-nya membaca stdin (assume.c di SETIAP `myc check`; gate run
program yang membaca stdin tanpa `--run-stdin` = timeout palsu).
Deadlock matrix PR-006 tidak menangkap karena mode `--matrix` dengan
`sin=0` TIDAK membaca stdin, dan `gcc -dM -E -` bukan bagian matrix.

Fix (hardening, P0-T01, kedua cabang): tutup write end stdin SEGERA
setelah exec sukses bila `stdin_len == 0` (Windows: `close_if_valid_handle
(&stdin_wr)` setelah penutupan sisi waris; POSIX: `close_if_valid_fd
(&in_pipe[1])` setelah cek execvp) → child mendapat EOF instan.
Idempoten (helper men-null-kan) dan tidak menyentuh jalur writer
(`stdin_len > 0`). Regresi: **T8** di `test/proc_deadlock_matrix.c`
(stdin KOSONG + `--output-after-stdin`/`--stdin-after-output` = baca
sampai EOF → selesai CEPAT tanpa timeout; 31–32 ms). Verifikasi:
`myc check /tmp/s.c --no-cache` 15,5 s → **0,83 s**; matrix penuh
T1–T8 0 gagal; lane E2E harness — 16 run E2E (`--e2e-iters 8`, gcc+filc)
2m45s sebelum fix → 6 run (3+3) **2,6 s** sesudah (≈10× lebih cepat
per run, bukan 60× — jumlah iterasi berbeda);
`_audit018.sh` SELESAI OK; `-Werror` proc.c/harness/fixture bersih.

Verifikasi (Windows): harness penuh `--iters 30000` (32k+ parse JSON,
round-trip + clone invariant) 0 semantic fail; E2E 8 iter/lane semua
hijau termasuk positive control (payload mutasi ber-marker `filc panic:`
+ exit 1 → `MC_FILC_VIOLATION` terdeteksi); `--replay` corpus kosong OK
+ seed buatan ter-replay; lane ASan SKIP di MinGW (tersedia di CI
Linux). Self-dogfood (kini cepat setelah fix proc.c) + diff check
bersih; artefak fuzz dibersihkan.

Batas jujur (bukan non-goal baru): fuzzer deterministik + korpus tetap
bukan libFuzzer/AFL coverage-guided — cakupan berasal dari keragaman
korpus PR-009 + kelas mutasi P2-T03, direpro sempurna via `--seed`.
Seed crash/semantik yang ditemukan di masa depan otomatis masuk
`.myc/regression/` dan di-replay oleh blok 13.

---


## Fase 3 — Evidence Planner (bagian 1: frontier + observation-to-experiment), 2026-08-06

Fase 3 menjadikan observasi heuristik (lint, negative-space) sebagai dasar
untuk **bekerja di batas pengetahuan** dan **mengubah observasi menjadi
bukti dengan biaya terkendali**. Bagian pertama ini mengimplementasikan 2
dari 7 task Fase 3:

### (1) Verification Frontier Map — `frontier.c/.h` (SOL-02, roadmap 7.8)

`unverified_debt` menyebut gap, tetapi tidak menunjukkan BATAS antara
wilayah yang diketahui dan tidak diketahui. `myc_frontier_build()`
(murni DERIVASI dari `myc_result` — TIDAK menambah gate, TIDAK mengubah
verdict, TIDAK menambah debt) membangun peta 7 item — satu per hazard
class yang bisa dibuktikan satu dimensi assurance:

| Hazard class | Gate | Backend | Next action (bila belum dibuktikan) |
|---|---|---|---|
| integer/bounds (static) | compile | gcc | `myc check <file>` |
| temporal/null-deref (analyzer) | analyzer | gcc -fanalyzer | `myc check <file> --analyze` |
| runtime memory (ASan/UBSan) | runtime | clang-asan | `myc check <file> --run` |
| spatial (checked buffers) | checked | myc_buf.h | `myc check <file> --checked` |
| proof obligation (RTE) | prove | frama-c eva | `myc check <file> --prove` |
| boundary input (contract) | driver | clang harness | `myc check <file> --driver` |
| capability safety | filc | fil-c | `myc check <file> --filc` |

Tiap item: `hazard` + `status` (proven/tested/observed/violation/unknown/
untested — peta dari gate status) + `backend` + `reason` (alasan frontier
berhenti, statis per status) + `next_action` (eksperimen termurah untuk
maju). API: `myc_frontier_build` / `myc_frontier_json` /
`myc_frontier_free`. Reentrant (tanpa global state), string di-strdup.

### (2) Observation-to-Experiment Compiler — `observation.c/.h` (SOL-17)

Ditulis di sesi sebelumnya (belum terverifikasi), kini dirapikan +
terverifikasi + ter-wire: tiap observasi heuristik ber-confidence
(OBSERVATION/SUSPICIOUS/LIKELY — CONFIRMED dilewati) di-petakan ke
EKSPERIMEN verifikasi konkret (9 tipe: alloc_fail, boundary_input,
short_io, cross_target, polling_harness, realloc_path, leak_check,
driver_gen, assertion_harness) dengan `command` myc yang dapat
dieksekusi + `source_anchor` (kini memakai `witness->slice_file` bila
ada, fallback "source") + `confidence` + `cost_estimate_ms` + `severity`.
Negative-space deviation → eksperimen `driver_gen`. Rapikan: `EXPERIMENT_DESCS`
(dead code) dihapus, `(void)source_file` dipindah ke atas (sebelumnya
unreachable setelah `switch`). API: `myc_observation_to_experiment` /
`myc_experiment_command` / `myc_experiment_json` / `myc_experiment_free`.

### (3) Wiring ke agent output (`agent.c`)

`myc_build_agent_result()` kini mengisi `ar->frontier[]` (7 string
"hazard: status (backend) -- reason") dari `myc_frontier_build()` dan
`ar->experiments_json` (serialisasi `myc_experiment_json()` bila ada
eksperimen) — LLM dapat bekerja di batas pengetahuan dan tahu eksperimen
apa yang harus dijalankan, bukan mengulang pemeriksaan yang sudah selesai.
Field `experiments_json` ditambah ke `myc_agent_result` (agent.h),
dibebaskan di `myc_agent_result_free`, diserialisasi di JSON agent
(`"experiments"`). Payload cap 16 KiB tetap dijaga.

### (4) BUG NYATA diperbaiki: heap corruption witness (invalid free arena)

Saat verifikasi fixture ditemukan **`myc.exe check bad_realloc.c` exit 127
tanpa output** — gdb: `Critical error detected c0000374` (heap corruption)
di `myc_witness_free` ← `myc_result_free` ← `main`. Akar: SELURUH field
string witness (`violation_kind`, `violation_msg`, `backend`, `operation`,
`pre_state`) dialokasikan dari **ARENA milik hasil** (`myc_result_arena_dup`
di compile.c/run.c/prove.c/filc.c/driver.c), tapi `myc_witness_free`
memanggil `free()` individual → invalid free (pola yang sama persis dengan
bug `quorum_report` di #3 yang sudah diperbaiki). Fix: `myc_witness_free`
kini hanya zero-kan struct (arena yang membebaskan); struct witness sendiri
tetap di-malloc terpisah dan di-free oleh `myc_result_free`. Regresi
sebelumnya TIDAK menangkap ini karena cek bad_realloc memakai `[WARN]`
(bukan FAIL counter) — setelah fix, `bad_realloc` → COMPILE_ERROR exit 1
normal dan `agent_bad --agent` → verdict findings + witness utuh.

### (5) Test infra ikut diperbaiki: `_audit018.sh` SRCS stale

Unit test portabel (`oom_guards`, `oom_alloc`, `stress_threads`,
audit_lampiran) gagal dibangun karena `SRCS` di `test/_audit018.sh` belum
memuat `agent.c`/`witness.c`/`ledger.c`/`transaction.c` (ditambahkan ke
pipeline di Fase 0–2) → undefined reference `myc_ledger_*`,
`myc_build_agent_result` dll. SRCS kini = daftar lengkap pipeline
(+`frontier.c`/`observation.c`). Daftar self-dogfooding di
`test/_regress_run.bat` dan `test/_ci_linux.sh` juga dilengkapi; `-Werror`
list di `.github/workflows/ci.yml` ditambah 2 file baru.

### Verifikasi

- Self-dogfooding **23/23 OK** (termasuk frontier.c, observation.c, mcp.c);
  daftar self-dogfooding di `_regress_run.bat`/`_ci_linux.sh` kini LENGKAP
  (agent/witness/ledger/transaction ikut di-cover, sebelumnya gap sejak
  Fase 0–2; CI `-Werror` sudah lengkap lebih dulu).
- `_audit018.sh` **SELESAI OK** (proc_flood, oom_guards, oom_alloc 49 titik,
  stress_threads, audit_lampiran T1–T14).
- `_regress_run.bat` **0 [FAIL]** (344 OK; audit018 + cap_sync PASS=87 +
  interop SDK MCP 24 cek).
- Agent output: `negative_dev --agent --negative` → frontier 7 item +
  experiments count 3 (alloc_fail, driver_gen, dll); `agent_ok` → frontier
  7, `agent_bad` → witness gcc-use-after-free (tidak crash).
- Receipt deterministik TIDAK berubah (frontier/experiments bukan bagian
  hash — hanya derivasi output, bukan status gate baru).

---

## Fase 3 — Evidence Planner (bagian 2: Causal Finding Graph), 2026-08-06

### Causal Finding Graph — `causal.c/.h` (SOL-09)

Satu kesalahan ukuran dapat menghasilkan puluhan warning sekunder; daftar
nasihat panjang membuat model memperbaiki SEMUANYA sekaligus → churn.
Graph mengubah daftar diagnostic menjadi **kurikulum mikro**: model
memperbaiki ROOT CAUSE dulu, dependent findings ditahan dan diverifikasi
ulang setelah root hilang.

Implementasi awal = **rule deterministik TANPA solver** (sesuai rencana
SOL-09):

- **symbol sama** — ekstrak identifier dalam kutip gcc (`'buf'`, `'p'`,
  `'realloc'`; hanya identifier C wajar, operator/string kosong diabaikan)
  dari `message` tiap diagnostic; irisan symbol → terhubung;
- **lokasi sama** — line sama (catatan: gcc error+note di baris yang sama
  otomatis ter-cluster);
- **witness overlap** — keduanya pada `witness->violation_line`.

Cluster via union-find (path halving). Root per cluster = confidence
tertinggi (note/pre-state TIDAK pernah root), tie-break line+col terkecil.
`repair_order[]` = root clusters dulu, dependents ditahan.

API: `myc_causal_build` / `myc_causal_json` (nodes + cluster + root flag +
`repair_order`) / `myc_causal_first_confirmed_root` /
`myc_causal_free`. Reentrant, string symbol di-strdup (dibebaskan
`myc_causal_free`). Murni derivasi `myc_result.diags[]` — non-blocking:
TIDAK mengubah verdict/completeness/debt.

### Wiring agent output (`agent.c`)

- `primary_finding` kini dipilih dari **root cause** causal graph
  (`myc_causal_first_confirmed_root`, fallback repair_order[0]) —
  sebelumnya hanya diag CONFIRMED pertama (bisa jadi warning turunan);
- field baru `causal_json` di `myc_agent_result` (agent.h) → JSON agent
  (`"causal"`): nodes ber-cluster + root flag + repair_order; dibebaskan
  di `myc_agent_result_free`; hanya dibangun bila `diag_count > 1`;
- payload cap 16 KiB tetap dijaga (degradasi anggun: experiments/causal
  dibuang bila protokol inti harus utuh).

### Verifikasi

- Self-dogfooding **24/24 OK** (termasuk causal.c, mcp.c).
- Agent output `bad_realloc --agent`: primary = root CONFIRMED baris 17
  (use-after-free), `causal` memuat cluster + repair_order, dependent
  (note baris 16) ditahan; `agent_bad` tetap witness utuh.
- Regresi `_regress_run.bat` 0 [FAIL]; `_audit018.sh` SELESAI OK;
  daftar self-dogfooding/-Werror + SRCS audit018 + CI diperbarui
  (causal.c).

---

## Fase 3 — Evidence Planner (bagian 3: Next-Best Experiment Rule Table), 2026-08-06

### Next-Best Experiment Rule Table — `nextbest.c/.h` (SOL-03, roadmap 7.10)

Frontier memberi STATUS per hazard class; observation-to-experiment memberi
eksperimen dari observasi AKTUAL. Rule table menjawab: dari posisi frontier
saat ini, eksperimen APA yang paling murah/menjanjikan untuk maju? Murni
rule DETERMINISTIK (bukan "berpikir seperti LLM"), NON-blocking (derivasi
frontier + experiments — TIDAK mengubah verdict/completeness/debt).

- **rule table** `NEXTBEST_RULES[]`: 7 hazard class (nama persis
  `FRONTIER_ROWS[]` frontier.c) → 3 kandidat eksperimen terurut efektivitas
  (mis. integer/bounds → boundary_input, cross_target, driver_gen;
  temporal/null-deref → polling_harness, realloc_path, assertion_harness;
  runtime memory → alloc_fail, leak_check, short_io; dst);
- **status pemicu**: untested/unknown/observed → direkomendasikan;
  violation → TIDAK usul eksperimen (fix root cause dulu, lihat causal
  graph) + flag `blocked_by_violation`; proven/tested → skip (sudah bukti);
- **observasi aktual menang**: bila `myc_experiment_set` (dari
  observation-to-experiment) sudah mengusulkan type yang sama, pakai
  cost/severity/anchor NYATA-nya + rationale "didukung observasi nyata"
  (lebih menjanjikan daripada default rule table);
- **skor** = severity×1000 − cost_ms; satu eksperimen terbaik per hazard,
  tanpa duplikat type; selection sort (skor desc, tie-break cost asc,
  type asc) → `rank` 0..n-1;
- **JSON** `next_best`: recommendations[] (rank/type/hazard/
  frontier_status/command/source_anchor/cost_estimate_ms/severity/
  rationale) + count + blocked_by_violation.

API: `myc_nextbest_plan` / `myc_nextbest_json` / `myc_nextbest_free`.
Reentrant, string di-strdup (dibebaskan `myc_nextbest_free`).

### Wiring agent output (`agent.c`)

Field baru `next_best_json` di `myc_agent_result` (agent.h) → JSON agent
(`"next_best"`); dibangun di blok frontier/experiments
(`myc_nextbest_plan(&fs, &exps, ...)` — `fs` TIDAK lagi di-free sebelum
plan, bug urutan yang sempat membuat next_best selalu kosong) dan
dibebaskan di `myc_agent_result_free`. Degradasi payload cap 16 KiB kini
3-lapis: experiments_json → causal_json → next_best_json → baru gagal
total bila protokol inti pun melebihi cap.

### Verifikasi

- Self-dogfooding **25/25 OK** (termasuk nextbest.c).
- Agent output: `bad_realloc --agent` → `next_best` berisi rekomendasi
  eksperimen dari frontier status (mis. realloc_path/polling_harness utk
  temporal; didukung observasi nyata bila ada); file banyak-error →
  degradasi payload buang next_best tanpa merusak protokol inti.
- Regresi `_regress_run.bat` 0 [FAIL]; daftar self-dogfooding/-Werror +
  SRCS audit018 + CI diperbarui (nextbest.c).

---

## Fase 3 — Evidence Planner (bagian 4: Incremental Evidence Cache), 2026-08-06

### Incremental Evidence Cache — `cache.c/.h` (SOL-18)

Menjalankan seluruh gate setelah edit satu fungsi itu boros. Cache
menyimpan evidence receipt per (source + scenario + tool identity) di
`.myc/evidence_cache.json` (NON-blocking: tak bisa ditulis = dilewati):

- **Key deterministik** = sha256(source_sha256 + scenario_hash +
  tool_key + cwd). Scenario = flags lengkap (strict/analyzer/run/prove/
  checked/filc/driver/meta/neg/quorum/reqc via
  `myc_ledger_build_scenario_hash`); tool_key = versi gcc + clang
  (`myc_tool_version`); cache TIDAK dipakai bila flags/tool/scenario
  berubah (SOL-18).
- **Hit → replay penuh**: verdict/assurance/assurance_vector/finding/
  completeness/claim/receipt/gates/debt/diags/counts disalin ke `res`
  (skip seluruh pipeline/backend). Receipt IKUT di-replay — deterministik
  karena receipt adalah hash dari status yang sama (`res->cache_hit=1`,
  dilaporkan `cache: hit`).
- **Miss + source berubah (scenario sama) → delta report**: ekstrak
  fungsi (skimmer leksikal: `<name>(...){...}` di brace level 0,
  hash = sha256 body), bandingkan hash vs entry lama → `N fungsi
  berubah (a,b), M identik (c), dependents: x` (fungsi yang memanggil
  fungsi berubah — deteksi token di rentang body). Di-set di
  `res->cache_delta_report`, dilaporkan `cache: ...` — NON-blocking,
  tidak mengubah verdict.
- **Store**: hanya untuk hasil non-error/non-timeout (hasil valid),
  merge key sama / append / buang tertua (cap 64 entries).
- **`--no-cache`** mematikan cache (CLI + `req.no_cache`).

API: `myc_cache_try_replay` / `myc_cache_store` /
`myc_cache_extract_functions` / `myc_cache_delta_report` /
`myc_cache_entry_free`. Wire di `myc_run()`: try-replay sebelum pipeline
(kedua branch file/stdin + memory), store setelah pipeline; pada hit,
quorum + require-complete tetap dijalankan (murni derivasi gates yang
sudah di-replay), ledger di-skip (hasil identik dengan run asli yang
sudah tercatat). Replay mengisi komponen receipt (gates/debt/
verdict/completeness) agar `receipt_sha256` konsisten dengan run asli.

### Verifikasi

- Self-dogfooding **26/26 OK** (termasuk cache.c).
- Run fixture 2× dengan input sama → run kedua `cache: hit` (receipt
  SAMA, durasi ~0); edit satu fungsi → `cache:` delta (fungsi berubah +
  dependents); `--no-cache` → selalu miss; flags beda → miss.
- Regresi `_regress_run.bat` 0 [FAIL]; daftar self-dogfooding/-Werror +
  SRCS audit018 + CI diperbarui (cache.c).

### Bug ditemukan & diperbaiki (review sesi lanjutan, 2026-08-07)

Dua bug nyata ditemukan saat verifikasi lebih dalam dari jalur delta
report dan replay determinisme (audit_lampiran T11 canary-failure)
menjadi tidak stabil run-ke-run:

1. **Ekstraktor fungsi tidak mendukung gaya Allman** (hanya skip
   spasi/tab antara `)` dan `{`; newline → ekstraksi 0 fungsi). Karena
   seluruh source myc dan fixture memakai brace di baris berikutnya,
   delta report SELALU kosong ("0 berubah; 0 identik") untuk kode
   nyata. Diperbaiki di `myc_cache_extract_functions` DAN varian lokal
   `extract_ranges` (delta report) dengan helper `skip_ws_comments`
   (whitespace incl. newline + komentar). Verifikasi: edit satu fungsi
   pada fixture Allman → `cache: 1 berubah (ok_sum); 1 identik
   (ok_copy); 0 baru; 0 hilang`.
2. **Clamp verdict di `cache_read_all` memakai `MC_DRIVER_VIOLATION`
   (9) padahal nilai terakhir `myc_verdict` adalah `MC_INCONCLUSIVE`
   (10)** → verdict INCONCLUSIVE DITOLAK saat deserialisasi → replay
   mengembalikan MC_OK (0). Konsekuensi parah: hasil INCONCLUSIVE
   (gate runtime canary gagal, backend tak tersedia) di-replay sebagai
   OK — false-clean, melanggar aturan kejujuran (jangan klaim lebih
   dari bukti). Kena deteksi karena `audit_lampiran` T11 (canary
   failure → INCONCLUSIVE) lulus run pertama (pipeline) tapi GAGAL
   run kedua (replay verdict=0). Diperbaiki: clamp `<= MC_INCONCLUSIVE`;
   semua clamp enum lain sudah benar (err `< MYC_ERR_INTERNAL`, sisanya
   `<=` nilai enum terakhir). Verifikasi: t11test reproduksi minimal 3×
   berturut → verdict=10 konsisten (pipeline & replay); `audit_lampiran`
   3× berturut → OK deterministik.

Setelah perbaikan: `_audit018.sh` **SELESAI OK** (sebelumnya GAGAL di
canary), `_regress_run.bat` **0 [FAIL]** (306 OK; cap_sync PASS=87).

---

## Fase 3 — Evidence Planner (bagian 5: Agent Context Compiler), 2026-08-07

### Agent Context Compiler — `context.c/.h` (SOL-22, roadmap 7.12)

Model LLM butuh KONTEKS MINIMAL per finding — bukan dump laporan penuh
(yang bisa puluhan KiB). `myc context <file.c>` menjalankan pipeline
verifikasi normal (semua gate flag bisa dipakai), lalu memancarkan paket
konteks deterministik `myc.context.v1` yang di-prioritaskan per budget:

- **Header**: source_sha256 + receipt_sha256 (paket terikat ke bukti),
  verdict, assurance vector, scenario hash, flags eksplisit, exact tool
  identity (gcc/clang version), dan `verify:` command reproduksi penuh
  (kini juga memuat `--finding-id` bila dipakai).
- **Finding slice**: `ctx_select_diag` memilih target — `--finding-id
  f-%08x` (hash → index diagnostic) / nomor baris, atau root causal
  pertama; lalu slice fungsi yang memuat finding (via `witness`-extract
  atau skimmer leksikal sendiri), callers/callees, dan `//@` contracts
  fungsi tsb (via `myc_contract_list`).
- **Witness** + **one action**: ringkasan witness (bila ada) dan
  next-best experiment rank 0 (derivasi `myc_nextbest_plan`) — model
  tidak perlu menebak eksperimen berikutnya.
- **Preservation obligations**: teks tetap (anti-churn, jangan lemahkan
  kontrak, jangan sempitkan scenario, pertahankan ABI) + target facts.
- **Budget & determinisme**: `--budget 4K|8K|16K` (default 8K,
  batas 1K..64K, parse ketat `parse_budget` — string tak valid ditolak
  exit 2, konsisten MYC-AUDIT-019/020). Section berprioritas: bila paket
  melebihi budget, section prioritas rendah dibuang berurutan (`[omitted:
  ... (budget N tokens)]` tercatat). `context_sha256` dihitung dari
  PAKET PENUH (tidak tergantung budget) → deterministik lintas budget:
  dua run budget beda → hash SAMA (agent bisa bandingkan tanpa
  re-verifikasi).
- **Reuse**: `myc_witness_build_slice`/`myc_witness_extract_function`
  (witness.h), `myc_contract_list` (contract.h), `myc_causal_graph`
  (causal.h), `myc_nextbest_plan` (nextbest.h), `myc_tool_version`
  (proc.h) — TIDAK ada duplikasi logika verifikasi. Murni derivasi
  hasil run: NON-blocking, tidak mengubah verdict/debt/receipt.

API: `myc_context_build(res, source, len, req, path, budget_tokens)` →
paket `char*` (malloc'd, di-free caller; OOM-safe). Wire di `myc.c`
main(): subcommand `context` (parsing sama dengan `check`, plus
`--budget`; validasi `myc_request_validate` tetap dijalankan — input
rusak → ERROR, bukan paket kosong).

### Verifikasi

- Self-dogfooding **27/27 OK** (termasuk context.c); `-Werror` semua
  source clean (CI step); cap_sync **PASS=92 FAIL=0** (registry
  `capabilities.json` + README kini memuat `--no-cache`, `--budget`, dan
  `myc context` — doc `docs/capabilities.md` tidak berubah karena gate
  matrix tak berubah).
- Fixture finding (`bad_run_oob --run --budget 4K`): header penuh +
  `verify: myc check tests/bad_run_oob.c --run` (dengan `--finding-id
  f-...` saat dipakai), finding slice, next-best rank 0 (`blocked_by_
  violation: true` — benar: jangan usul eksperimen sebelum root cause
  fix), preservation obligations.
- Budget: `--budget 1K` pada myc.c → `[omitted: causal cluster (budget
  1024 tokens)]` + `omitted sections: 1`; `--budget 99M`/`abc` → pesan
  + exit 2; hash 4K == hash 8K (deterministik lintas budget).
- Regresi `_regress_run.bat` **0 [FAIL]** (318 OK — naik dari 306:
  self-dogfooding + context.c + section SOL-22 dengan 8 cek baru);
  `_audit018.sh` **SELESAI OK**; `--no-cache`/`--budget` terdaftar di
  `capabilities.json` (cap_sync lintas-doc konsisten, PASS=92).

### Review fixes (2026-08-07, code-review deepseek-flash)

1. **Placeholder `<fungsi target>` bocor ke output** — preservation
   obligations merender literal `<fungsi target>` saat fungsi target tak
   ditemukan (runtime violation tanpa line). Kini: nama fungsi asli bila
   ada, atau klausa "di atas fungsi target (lokasi target tidak
   ditemukan)" tanpa angle bracket.
2. **`line: 0 col: 0`** untuk finding runtime tanpa lokasi → kini
   `line: (lokasi tidak diketahui)` (jangan render koordinat palsu).
3. **`--budget` pada subcommand `check` diam-diam diabaikan** —
   kontradiksi fail-fast MYC-AUDIT-019 (flag dipakai di subcommand
   salah harus exit 2). Kini: `myc: --budget hanya berlaku pada
   subcommand context` + exit 2.
4. **OOM path**: `myc_context_build` NULL → kini `src` di-free dulu +
   `myc_result_free` + exit 1 (sebelumnya leak `src` di jalur itu).
5. **Verifikasi mapping `f-%08x`**: `ctx_select_diag` mencocokkan
   `diags[i].line == v` persis seperti derivasi `agent.c`
   (`finding_id = f-%08x` dari `d->line`) — konsisten, `--finding-id`
   dari laporan `--agent` memilih diagnostic yang sama.

---

## Fase 3 — Evidence Planner (bagian 6: Assurance Budget Contract), 2026-08-07

### Assurance Budget Contract — `budget.c/.h` (SOL-30, roadmap 7.13)

User/harness kini dapat meminta TARGET assurance EKSPLISIT sebagai
kontrak, bukan sekadar memilih flag — dan myc TIDAK boleh diam-diam
memilih recipe lebih lemah:

```
myc check <file.c> --budget-contract \
  '{"required":{"compile":"clean","runtime":"clean","driver":"clean",
    "proof":"optional"},"max_time_ms":10000,"max_output_bytes":16384}'
```

- **Parse JSON ketat** (`myc_budget_parse`, reuse json.c): key gate = nama
  pendek `myc_gate_id_short`; nilai `clean` (wajib) / `optional`;
  `max_time_ms` 0..600000 (konsisten `--timeout`), `max_output_bytes`
  0..100 MiB; kontrak tanpa target apa pun DITOLAK (bukan no-op diam-diam).
  Invalid = fail-fast exit 2 (konsisten MYC-AUDIT-019/020).
- **Enforcement** (`myc_budget_enforce`, dipanggil SETELAH pipeline +
  quorum + require-complete di semua branch `myc_run`): tiap gate wajib
  `clean` harus (1) DIMINTA user via flag (`budget_gate_requested` —
  kalau tidak, recipe lebih lemah), dan (2) status COMPLETED_CLEAN (atau
  NOT_APPLICABLE setelah diminta, mis. checked tanpa MYC_BUF). Gate
  UNAVAILABLE/INFRA_FAILED/INCONCLUSIVE/FINDINGS/not_run = target TIDAK
  tercapai.
- **Verification gap = kegagalan, bukan kesunyian** (pola 9.10): target
  tak tercapai sementara verdict masih MC_OK → verdict INCONCLUSIVE +
  finding/completeness diselaraskan + debt `MYC_DEBT_BUDGET` (kode
  `MYC-INCOMPLETE-BUDGET-UNMET`) + receipt dibangun ulang. Verdict
  findings nyata (RUNTIME_VIOLATION dll.) TIDAK diturunkan — bug tetap
  finding, kontrak dilaporkan gagal di budget_report.
- **Report jujur**: `budget_report` (arena) merinci tiap gate
  ("tercapai (clean)" / "TIDAK tercapai (not_requested) -- dimensi
  dikorbankan"), `max_time_ms`/`max_output_bytes` yang dilampaui; teks
  `budget: target TERCAPAI/TIDAK tercapai` + JSON (`budget_active`/
  `budget_met`/`budget_report`) + capsule.
- **Cache separation**: scenario hash (ledger.c) kini memuat hash kontrak
  (`|budget=<sha>`) → run kontrak beda tidak pernah berbagi cache entry.
- **Replay deterministik**: cache entry menyimpan `budget_active`/
  `budget_met`/`budget_report`; pada cache-hit enforcement TIDAK
  dijalankan ulang (hasil asli di-replay utuh — hindari durasi 0 yang
  membuat `max_time_ms` salah tercapai + debt duplikat).

API: `myc_budget_parse` / `myc_budget_free` / `myc_budget_enforce` /
`myc_budget_level_name`. Tipe (`myc_budget_level`,
`myc_budget_contract`) di myc.h (myc_request memuatnya by-value;
budget.h hanya API agar tidak ada include circular).

### Verifikasi

- Self-dogfooding **28/28 OK** (termasuk budget.c); `-Werror` semua
  source clean; cap_sync **PASS=93 FAIL=0** (registry + README memuat
  `--budget-contract`).
- Kontrak tercapai: `compile=clean` pada ok_hello → OK + target
  TERCAPAI; `runtime=clean --run` pada ok_run → OK. Kontrak GAGAL:
  `runtime=clean` tanpa `--run` → INCONCLUSIVE + `runtime: TIDAK
  tercapai (not_requested) -- dimensi dikorbankan` (recipe lebih lemah
  TIDAK lolos); `max_time_ms:1` → INCONCLUSIVE; `max_output_bytes:1` →
  INCONCLUSIVE; `bad_run_oob --run` → RUNTIME_VIOLATION TETAP
  (finding tidak diturunkan) + kontrak TIDAK tercapai.
- Cache: kontrak beda → scenario hash beda (miss); replay `max_time_ms`
  konsisten (run1 pipeline == run2 cache-hit, receipt SAMA); debt
  budget tidak duplikat.
- Regresi `_regress_run.bat` **0 [FAIL]** (325 OK; section SOL-30 6 cek:
  tercapai, gagal recipe-lemah, debt muncul, dimensi disebut, finding
  tetap, JSON invalid ditolak); `_audit018.sh` SELESAI OK.

---

## Fase 4 — DeepSeek Oracle & Bare-Metal Core (bagian 1: Assumption Closure), 2026-08-07

### Assumption Closure — `assume.c/.h` (A1 + DS-01, roadmap 7.12/7.13)

Model menulis kode yang *mempertaruhkan* fakta implementation-defined
(signedness `char`, lebar `int`, endianness bit-field, alignment cast,
`sizeof`) tanpa sadar — dan tidak ada yang menanyakannya. A1 membalik
arah verifikasi: alih-alih mencari "apa yang salah", daftarkan **fakta
apa yang dipertaruhkan kode ini** dan sandingkan dengan kebenaran
aktual toolchain (verifikasi-as-ledger, bukan verifikasi-as-accusation).

- **Host facts**: `gcc -dM -E -` dengan stdin KOSONG (macro predefined
  murni — deterministik, tidak bergantung source/syntax; fallback bila
  gcc absen = fakta tak diketahui, NON-blocking). Diekstrak:
  `__CHAR_UNSIGNED__`, `__SIZEOF_INT__`, `__SIZEOF_POINTER__`,
  `__BYTE_ORDER__`, `__STDC_VERSION__`, `CHAR_BIT`.
- **Deteksi** (tokenizer ringan comment/string-aware + operator
  2-karakter `== <= >= !=` sebagai satu token, line-tracked), 5 kelas
  taruhan dengan confidence-scored, SEMUA non-blocking:
  - `char-signedness` (conf 80–90): char var vs literal negatif / `< 0`
    / `>= 0` — "di ARM (unsigned char) cabang ini mati total";
  - `int-width` (75): `int n = strlen/sizeof(...)`;
  - `bitfield-endian` (70): bit-field di struct/union;
  - `alignment-cast` (80): `(uint16_t *)` dst (termasuk qualifier
    `(const uint32_t *)`) — alignment fault + endianness;
  - `sizeof-assumption` (80): `sizeof(T) == N` dst.
- **Lifecycle DS-01**: `observed → declared / tested / contradicted /
  eliminated / accepted-risk`; `assumption_id` = `asm-<kind>-<8hex
  sha256(anchor)>` dengan anchor stabil (`myc_ledger_build_anchor`).
  Status dipersisten di `.myc/assumptions.json` → run kedua menunjukkan
  asumsi mana yang sudah ditutup; ack TIDAK menghilangkan asumsi dari
  receipt (tetap tampil dengan status barunya).
- **CLI**: `--require-assumptions-closed` (asumsi terbuka = gap
  verifikasi → INCONCLUSIVE + debt `MYC-INCOMPLETE-ASSUMPTIONS-OPEN`),
  `--assumption-ack id:status,...` (format salah = fail-fast exit 2),
  `--no-assumptions` (matikan ledger; kontradiksi dengan
  require-assumptions-closed = exit 2).
- **Report**: blok teks `assumptions (A1 ledger)` + JSON `assumptions`
  (detected/count/unclosed/ok/ack_applied + items per asumsi:
  id/kind/line/status/confidence/anchor/host_fact/risk/next_action) +
  `--json-summary` (count/unclosed/ok).
- **Cache (SOL-18)**: host facts disimpan di entry cache → cache-hit
  TIDAK mengeksekusi gcc ulang; deteksi SELALU di-scan ulang pada
  cache-hit (murni teks, ~ms) dan merge state `.myc/assumptions.json`
  → status selalu segar meski entry lama (terbukti: run1 pipeline
  observed → ack → run3 cache-hit tampil eliminated, bukan stale).
  Flags asumsi + hash ack masuk scenario hash (ledger.c) → pemisahan
  cache konsisten; enforcement dijalankan ulang pada cache-hit
  (recompute, bukan replay).

API: `myc_assume_fetch_facts` / `myc_assume_run` / `myc_assume_enforce`
/ `myc_assume_ack_validate` / `myc_assumption_status_name`. Tipe
(`myc_assumption_status`, `myc_assumption`, `myc_host_facts`) di myc.h;
assume.h hanya API. Debt baru `MYC_DEBT_ASSUMPTION` (gate.c:
`assumption_open` / `MYC-INCOMPLETE-ASSUMPTIONS-OPEN`).

### Verifikasi

- Self-dogfooding 29/29 OK (termasuk assume.c, 0 asumsi terdeteksi pada
  dirinya sendiri); `-Werror` semua source clean; cap_sync PASS=94.
- Fixture `tests/assume_char_signed.c`: 5/5 pola terdeteksi dengan line
  benar (char line 24, int-width line 22, bitfield line 14, alignment
  line 23, sizeof line 26), verdict tetap OK (non-blocking);
  `assume_clean.c`: 0 asumsi.
- Lifecycle: require-closed pada 5 terbuka → INCONCLUSIVE +
  `MYC-INCOMPLETE-ASSUMPTIONS-OPEN`; ack 2 → status berubah + persisten
  lintas run; ack semua 5 → require-closed OK; `--no-assumptions` →
  bersih; kontradiksi flag & format ack salah → exit 2.
- Cache: run2 = hit dengan receipt SAMA; ack (scenario beda) = miss;
  freshness state pada hit terverifikasi (bukan stale). JSON penuh
  valid (items per asumsi lengkap).
- Regresi `_regress_run.bat` **0 [FAIL]** (343 OK; section SOL-32 9 cek:
  ledger muncul, char-signedness terdeteksi, verdict tidak turun, debt
  muncul, INCONCLUSIVE, ack menutup, persisten, no-assumptions,
  format salah ditolak); `_audit018.sh` SELESAI OK.

### Review fixes (code-reviewer, 2026-08-07)

1. **OOB read di detektor alignment-cast** — qualifier loop
   `while (t < n && ...)` bisa mendorong `t` ke ujung array token lalu
   `toks[t+2]` dibaca melewati batas (heap OOB/UB). Fix: guard
   `t + 2 < n` (butuh minimal 3 token tersisa).
2. **Stale enforcement pada cache-hit** — run `--require-assumptions-
   closed` setelah ack (state berubah via key berbeda) bisa me-replay
   entry lama ber-verdict INCONCLUSIVE + debt padahal blok asumsi segar
   "0 terbuka" (kontradiksi; ack tak pernah bisa membuat
   require-assumptions-closed lulus). Fix: run dengan
   `require_assumptions_closed`/`assumption_acks` TIDAK di-cache (baik
   replay maupun store) — selalu pipeline pada state segar (filosofi
   sama dgn fix SOL-30: enforcement stateful tak di-replay). Terbukti:
   flag-on → INCONCLUSIVE, ack semua → OK, flag-on lagi → OK.
3. **Endianness fact salah di Windows** — `__BYTE_ORDER__` terdefinisi
   sebagai token `__ORDER_LITTLE_ENDIAN__` (bukan angka) DAN output
   gcc MSYS2 memakai `\r\n` (trailing CR) → perbandingan teks gagal →
   "big-endian" palsu di x86. Fix: bandingkan teks value + normalisasi
   token + trim trailing CR. Terbukti: `little-endian` di host.
4. **Kejujuran facts tak diketahui** — `int=?`/`ptr=?` (bukan fallback
   32/64) saat macro dump tak tersedia.
5. Minor: dedupe nama char var (hilangkan O(nc×n) pada nama duplikat),
   receipt di-rebuild SEKALI (bukan dua kali), state file hanya ditulis
   bila berubah (hindari rewrite tiap cache-hit).

---

## Fase 4 — DeepSeek Oracle & Bare-Metal Core (bagian 2: Cross-Toolchain Divergence), 2026-08-07

### A2 Cross-Toolchain Classified Divergence — `run.c` (DS-02)

Toolchain sebagai oracle: bangun + jalankan source SAMA dengan matriks
`{gcc, clang, [tcc]} x {-O0, -O2}` — gate baru `MYC_GATE_DIVERGENCE`
(`--divergence`), dim RUNTIME (R1 bila konsisten, seperti metamorphic):

- **Tiap sel matriks** (`myc_divergence_cell`, array 8 di `myc_result`):
  build (source via stdin, `-Wall -g` + sanitizer bila tersedia) + run
  terkendali (env deterministik `LC_ALL=C`, `log_path` unik per sel =
  saluran non-spoofable). Dicatat: exit code, finding sanitizer (report
  log_path / marker+exit!=0), **sha256 trace stdout** (deteksi semantic
  divergence deterministik), ada-tidaknya warning build.
- **Fallback tanpa sanitizer (jujur)**: gcc MinGW tidak punya libasan →
  build dengan sanitizer gagal → fallback build TANPA sanitizer untuk
  sel tsb (`cell->san=0`). Sel tanpa sanitizer TIDAK pernah jadi bukti
  clean/finding untuk klasifikasi sanitizer — hanya semantic compare.
  (Bug yang ditemukan selama dev: `n` tidak di-reset pada iterasi
  fallback → OOB write di argv → diperbaiki.)
- **Klasifikasi DS-02**: `sanitizer_divergence` (≥1 sel finding + ≥1 sel
  sanitizer-clean yang ran → **HARD RUNTIME_VIOLATION**, bug toolchain-
  sensitive), `all_findings` (semua sel sanitizer menemukan → bug
  konsisten, HARD), `semantic_divergence` (stdout sha256/exit beda tanpa
  sanitizer → OBSERVASI), `diagnostic_divergence` (set warning build beda
  antar toolchain → OBSERVASI). Hanya bukti sanitizer yang menurunkan
  verdict (MYC-AUDIT-014).
- **Report**: tabel matriks per sel (tool, opt, state, marker), klasifikasi
  + flag di JSON penuh, ringkasan di capsule/json-summary.
- **Cache**: hasil divergence di-store (flags + cell matriks + report) dan
  di-replay identik pada cache-hit; `--divergence` masuk scenario hash +
  fingerprint; tool key kini menyertakan clang saat divergence (identity).
- **Non-blocking**: toolchain hilang / build gagal = sel di-skip, assurance
  statis dipertahankan.

### Verifikasi

- Self-dogfooding **29/29 OK**; `-Werror` clean (semua source);
  `_cap_sync.sh` **PASS=96 FAIL=0**; `_audit018.sh` SELESAI OK.
- Fixture `divergence_clean.c` (deterministik): verdict OK, klasifikasi
  konsisten, tidak ada false-positive sanitizer divergence.
- Fixture `divergence_oob.c` (heap-buffer-overflow): RUNTIME_VIOLATION
  (HARD) + klasifikasi sanitizer_divergence.
- Cache: run2 = hit dengan replay identik (verdict + matrix sama);
  `--no-cache` = miss; tanpa `--divergence` = miss (scenario separation).
- Regresi `_regress_run.bat` **0 [FAIL]** (352 OK; section SOL-33 8 cek:
  gate berjalan, fixture clean OK, klasifikasi konsisten, tidak ada
  false-positive, OOB HARD, sanitizer_divergence, cache hit, no-cache
  miss).

### Review fixes (code-reviewer, 2026-08-07)

1. **Klaim konsistensi butuh bukti** — bila hampir semua sel gagal
   build/run (n_ran < 2), gate sebelumnya tetap COMPLETED_CLEAN
   "konsisten antar toolchain" padahal tidak ada sel yang dibandingkan
   (klaim tanpa bukti). Fix: `n_ran >= 2` wajib untuk klaim konsisten;
   selain itu gate = INCONCLUSIVE + diagnostic (gap terlihat).
2. **`tool_path` menyesatkan pada replay** — replay mengisi field
   `tool_path` dengan NAMA tool ("gcc") bukan path. Fix: kosongkan pada
   replay (path asli tidak disimpan di cache; field bernama path tidak
   boleh berisi nama).
3. **Harden fallback loop** — jumlah base flags dihitung ulang memakai
   index yang sama dengan fill loop; keselamatan fallback bergantung
   pada baris `bfl = 0` di branch sanitizer-gagal (footgun laten). Fix:
   `static const int NBASE` dihitung sekali, total alokasi independen
   dari nilai index saat itu.
4. Minor: hilangkan double-assignment `divergence_ncells` di replay;
   tool key cache kini menyertakan clang saat `--divergence` (identity
   toolchain yang benar-benar dipakai matriks).

---

## MYC-AUDIT-001..030 dan fase pengembangan (kronologis)

### P6 — Gate verification run (`--run`), 2026-08-01

Gate verification run opsional (`--run`) dengan clang ASan+UBSan (`-O0`,
source via stdin, DLL runtime disalin, eksekusi via proc.c) → assurance
**L3 RUNTIME**. Non-blocking: bila clang hilang / kode bukan executable,
assurance statis dipertahankan + diagnostic.

### P7 (D1.5) — contract-lite, 2026-08-01

Scan `//@ requires/ensures` (info di laporan: `contracts: requires=N
ensures=M`) + inject `assert(requires)` ke verification build (`--run`)
sebagai defense-in-depth. `bad_contract_pre.c` → RUNTIME_VIOLATION
(assert menangkap pelanggaran pre).

### D2.2 — driver-generator, 2026-08-02

Gate `--driver` scan fungsi ber-kontrak (`//@ requires`), parse signature,
bangkitkan harness kasus tepi DI DALAM domain kontrak (batas dari requires,
0/1/2/3), build + run clang ASan+UBSan (`-O0`, source via stdin). Run
bersih ≥ 1 kasus → L3 RUNTIME; sanitizer menangkap bug →
MC_DRIVER_VIOLATION (fixture `bad_driver_oob.c`: OOB via `a[n]` saat n=4
pada kontrak `n <= 4`). Non-blocking: clang hilang / tak ada fungsi
ber-kontrak / build harness gagal → skip + diagnostic. Nilai negatif/
SIZE_MAX TIDAK diuji tanpa kontrak yang membuka peluangnya (hindari false
positive). Harness men-rename main asli via `#define main` lalu `#undef` —
source dengan `main` tetap bisa di-drive.

### Tool MCP `contracts` + `lint`, 2026-08-02

`mcp.exe` mengekspos 5 tool (`check`, `version`, `policy`, `contracts`,
`lint`). `contracts` = list ekspresi `//@ requires/ensures` (API baru
`myc_contract_list` di contract.c). `lint` = jalankan lint memory-safety
langsung (tanpa pipeline penuh). Smoke test diperbarui ke 10 pesan.

### Client MCP contoh, 2026-08-02

`mcp_client.py` (Python stdlib, tanpa dependensi) — handshake initialize,
tools/list, panggil check/version/contracts/lint via stdio.

### P7 (D3.1) — Frama-C Eva (`--prove`), 2026-08-01

Gate `--prove` → L2 EVA (label lama "L2 PROVEN" dihapus MYC-AUDIT-013).
Frama-C 33.0 (Arsenic) diinstal via opam di WSL Ubuntu-24.04
(`/home/megaalive/.opam/default/bin/frama-c`); myc mendeteksi via `wsl.exe`
dan memanggil `frama-c -eva` dengan source via stdin (template bash tetap,
tanpa shell string berisi source). Alarm Eva (`[eva:alarm]`, kelas RTE =
bug pasti) → verdict PROVE_VIOLATION; 0 alarm + analisis sungguhan (cek
"ANALYSIS SUMMARY") → L2 EVA. Non-blocking: wsl/frama-c hilang atau Eva
tidak menganalisis → skip, assurance statis dipertahankan + diagnostic.
Fixture: `ok_prove.c` → L2 EVA; `bad_prove.c` (OOB via argc opaque) →
PROVE_VIOLATION.

### Self-dogfooding

Lolos penuh: 15 source myc dicek myc sendiri → OK. (Catatan lama "akan
selalu VIOLATION karena windows.h" TIDAK berlaku lagi — policy
non-blocking.)

### Counterexample Replay Capsule (#2), 2026-08-02

`myc_replay_capsule` struct di `myc.h` (source_sha256, stdin_sha256,
stdin_len, backend identity, flags, verdict, gate_status summary,
finding/completeness/claim). Disimpan di `myc_result.capsule`, dibangun di
`myc_run()` akhir pipeline, dibebaskan di `myc_result_free()`. Serialisasi
JSON + teks di `report.c`. OOM-safe: `goto fail` cleanup di
`myc_build_capsule()`. Self-dogfooding `myc.c` lolos `-fanalyzer` (tidak
ada lagi leak). Fixture: `ok_run --run --json` memuat `"capsule"` objek
dengan semua field; `ok_run --run` mencetak blok `capsule:` di teks.

### Differential Backend Quorum (#3), 2026-08-02

Flag `--quorum` (CLI + MCP tool `check`). Setelah pipeline selesai,
`myc_quorum_analysis()` (di `compile.c`, dipanggil dari `myc_run()` agar
selalu terpanggil walau pipeline early-return) membandingkan status semua
gate yang diminta: semua `completed_clean` → `MYC_QUORUM_CLEAN`; campuran
findings+clean → `CONFLICT` (backend tidak sepakat); ada gate
incomplete/unavailable → `INCONCLUSIVE`; **tidak ada hasil gate sama sekali**
(mis. lint memblokir pipeline sebelum gate berjalan) → `INCONCLUSIVE`
(jujur, bukan "agree clean"). Status + laporan teks di
`quorum_status`/`quorum_report` (teks + JSON + capsule).

Bug ditemukan saat menyelesaikan sesi: (1) `quorum_report` dialokasikan
dari arena tapi di-`free()` individual setelah arena dibebaskan → invalid
free/crash → dihapus (arena yang membebaskan); (2) quorum tidak dipanggil
di branch `file_path`-only `myc_run` → ditambahkan; (3) **bug lama**:
`myc_result_to_json` kehilangan `}` penutup level teratas sejak capsule #2
→ semua output `--json` invalid (MCP interop lolos karena hanya cek
substring) → diperbaiki, kini JSON valid ketat; (4) MCP belum mengekspos
`--quorum` → ditambahkan. Verifikasi: quorum clean pada
`ok_hello`/`ok_run --run`/`ok_driver --driver`, conflict pada
`bad_syntax`/`bad_run_oob --run`/`bad_driver_oob --driver`, inconclusive
pada lint-violation. Semua regression + self-dogfooding 16 source + MCP
smoke tetap hijau; receipt deterministik tetap (`ok_run --run` →
`272d7531...`).

### Metamorphic Verification (9.7), 2026-08-02

Gate `--metamorphic` (CLI + MCP tool `check`) → `myc_metamorphic_gate()` di
`run.c` memakai ulang mesin run gate (temp dir, ASan DLL, canary, marker).
Source SAMA dibangun 2× dengan clang ASan+UBSan (`-O0` dan `-O2`),
dijalankan dengan input sama, hasil dibandingkan: hanya satu build
menemukan sanitizer → `metamorphic_inconsistent` + verdict
`RUNTIME_VIOLATION` (kemungkinan UB / toolchain-sensitive — fixture
`bad_run_oob.c` membuktikan: OOB terdeteksi di `-O0`, hilang di `-O2`
karena optimizer); keduanya menemukan → violation konsisten; keduanya
bersih → `COMPLETED_CLEAN` (L3 RUNTIME); exit code berbeda tanpa sanitizer
→ hanya diagnostic informasional (bukan klaim bug). Non-blocking: clang
hilang / build gagal / canary mati → di-skip atau INCONCLUSIVE, assurance
statis dipertahankan. Fingerprint `v8`→`v9` (+dimensi `meta`). Berinteraksi
dengan `--quorum` (gate metamorphic ikut dibandingkan). Regresi di
`test/_regress_run.bat`.

### Negative-Space Analysis (9.8), 2026-08-02

Gate `--negative` (CLI + MCP tool `check`) → `myc_negative_space()` di
`negative.c` (baru, reentrant: tanpa global state — statistik per-fungsi di
array lokal berindeks ALLOC_FUNCS, nama = pointer statis, tanpa strdup).
Structural mining "pola yang hilang": keluarga pola pertama = konvensi
pemeriksaan hasil fungsi alokasi (`malloc/calloc/realloc/strdup/fopen`).
Untuk tiap callsite, tentukan apakah hasilnya DIPERIKSA (`== NULL` /
`!= NULL` / `!p`), langsung (`(p = malloc()) == NULL`) atau kemudian
(forward-scan sampai keluar blok, jendela 4096); LHS dikenali melewati cast
eksplisit (`p = (char *)malloc(...)` — bug awal: tanpa itu semua callsite
ber-cast terhitung salah). Bila mayoritas memeriksa tetapi ada yang tidak →
`project convention deviation` + confidence (0.55–0.98) di diagnostic.
**HANYA observasi**: status gate baru `MYC_GATE_COMPLETED_OBSERVATIONS`
(ditambahkan ke enum — gate selesai tapi hasilnya bukan finding
terkonfirmasi; benign terhadap reducer: tidak menaikkan verdict, tidak
menurunkan completeness, tidak menambah debt; quorum memperlakukannya
sebagai non-conflict). Verdict tetap OK walau ada deviation (prinsip
MYC-AUDIT-014: heuristik teks bukan bukti semantik). Non-blocking: 0
callsite → `NOT_APPLICABLE`, tanpa klaim. Laporan: teks
`negative (9.8): callsites=N deviations=M` + `scope:` + JSON
`ran_negative`/`negative_callsites`/`negative_deviations` + capsule.
Fingerprint `v9`→`v10` (+dimensi `neg`); karena `MYC_GATE_COUNT` bertambah,
receipt golden `ok_run --run` berubah → `272d7531...`
(`negative_ok --negative` → `6c364f7e...`, deterministik). Fixture:
`tests/negative_ok.c` (3 callsite, semua diperiksa → `completed_clean`),
`tests/negative_dev.c` (4/5 malloc diperiksa, `make_e()` tidak →
`completed_observations` + diagnostic callsite baris + konvensi `4/5 ...
confidence 0.81`, verdict tetap OK). Regresi di `test/_regress_run.bat`.

### Silence Is a Finding (9.10), 2026-08-02

Flag `--require-complete` (CLI + MCP tool `check`) → **verification gap =
kegagalan CI, bukan kesunyian**. Tiap gap verifikasi kini punya kode
finding `MYC-INCOMPLETE-XXX` (`myc_debt_code()` di `gate.c`:
GATE-UNAVAILABLE / GATE-INFRA-FAILED / GATE-INCONCLUSIVE / NONZERO-CASES /
ENSURES-UNPROVED / RAW-BUFFERS / OUTPUT-TRUNCATED) di laporan teks + JSON
(field `code` per item debt). Bila flag dipakai dan ada debt (gap) →
`enforce_require_complete()` di `myc_run()` menaikkan verdict `OK` →
`INCONCLUSIVE` (exit 1; finding/completeness diselaraskan). **Prasyarat
AUDIT-004/010 (sekaligus diperbaiki)**: gate DIMINTA yang backend-nya tidak
tersedia kini `UNAVAILABLE` + debt (bukan `NOT_APPLICABLE` yang diam-diam
lolos) — filc/prove/driver skip → `UNAVAILABLE` (driver tanpa fungsi
ber-kontrak tetap `NOT_APPLICABLE` = benar-benar tidak berlaku;
checked/negative tanpa pola tetap NA). Konsekuensi: `ok_filc --filc` di
sistem tanpa Fil-C kini `INCONCLUSIVE` + debt (dulu OK senyap); quorum ikut
lebih jujur (unavailable → inconclusive). Non-blocking tetap: assurance
statis dipertahankan (bukan diturunkan). Fingerprint `v10`→`v11`
(+dimensi `reqc`); receipt golden `ok_run --run` → `272d7531...`
(deterministik). Fixture tanpa flag: `ok_contract.c` → OK exit 0 (gap
ensures-unproved terlihat tapi tidak menggagalkan); dengan
`--require-complete` → INCONCLUSIVE exit 1. Regresi di
`test/_regress_run.bat` (+5 cek).

### MYC-AUDIT-012, 2026-08-02 (`myc_buf.h`)

Checked-buffer kini menjaga **element type + checked multiplication**.
Checked mode `MYC_BUF(T)` = struct anonim ber-*member typed* `T *data` +
`byte_capacity` (BYTE) + `elem_size` + `generation` + `cookie` (magic,
deteksi korupsi metadata). `MYC_AT` memverifikasi **ukuran elemen di
COMPILE TIME** via trik array negatif C11 murni
`sizeof(char[sizeof(T)==sizeof((b).data[0]) ? 1 : -1])` (tanpa ekstensi,
tetap LVALUE — cek diletakkan di argumen helper yang mengembalikan pointer,
bukan operator komma) **dan** membandingkan `elem_size` di runtime;
`MYC_NEW` menolak `n*sizeof(T) > SIZE_MAX` (trap `MYC_CHECKED: MYC_NEW
overflow` — sekaligus menangkap n negatif yang ter-cast ke size_t raksasa);
bounds `MYC_AT` memakai `i >= byte_capacity/elem` sehingga `i*elem`
dijamin tidak overflow (checked multiplication dalam satu pembandingan).
`MYC_FREE` memeriksa cookie (korupsi) dan men-null-kan data (use-after-free
terdeteksi). Mismatch tipe ber-ukuran sama (int vs unsigned) sengaja TIDAK
dianggap berbahaya (bounds/offset/alignment identik) — jujur di
dokumentasi. Batasan: MYC_AT harus lvalue (assignment) sehingga cek tidak
bisa dipisah jadi ekspresi komma; `MYC_NEW` pada buffer aktif (re-init)
tidak di-trap (baca memori indeterminate pada deklarasi segar). Fingerprint
`v11`→`v12` (+dimensi `buf` = revisi runtime checked-header); receipt
golden baru: `ok_run --run` → `272d7531...` (deterministik), `ok_hello` →
`17b404ab...`, `negative_ok --negative` → `6c364f7e...`. Fixture:
`tests/bad_checked_type.c` (MYC_AT tipe ber-ukuran salah pada MYC_BUF(int)
→ COMPILE_ERROR di checked build), `tests/bad_checked_new_overflow.c` (n
opaque via argc sehingga `n*4` overflow SIZE_MAX → `--run --checked` =
RUNTIME_VIOLATION dengan marker `MYC_NEW overflow`). Regresi di
`test/_regress_run.bat` (+3 cek); `ok_checked`/`dogfood_ring` tetap L4.

### MYC-AUDIT-013, 2026-08-02 (klaim Frama-C Eva / label assurance)

Label `L2 PROVEN` → **`L2 (EVA)`** dan `L5 FULL` → **`L5 (FILC)`** (enum
`MYC_ASSURANCE_L2_EVA`/`MYC_ASSURANCE_L5_FILC`; label lama menyiratkan
bukti lebih dari yang dikumpulkan). Eva adalah **abstract interpretation**:
L2 EVA = 0 alarm RTE di bawah model default (entry main), BUKAN proof
obligation WP, BUKAN "kontrak terbukti" — pesan diagnostic diubah ("prove:
Eva 0 alarm RTE (abstract interpretation, entry main; bukan proof
obligation WP)"). Laporan prove kini jujur dan berkonteks: `prove:` blok
memuat `mode` (`eva (abstract interpretation)`), `version` (diparse dari
`frama-c -version` via WSL detect — `33.0 (Arsenic)`), `entry` (main
default), `alarms`, dan catatan pembatasan — di teks + JSON
(`prove_mode`/`prove_version`). Pesan Fil-C juga dilemahkan ("run bersih -
eksekusi Fil-C bersih (L5 FILC); bukan klaim FULL"). Istilah FULL dihapus
dari README/docs. Receipt TIDAK berubah (label assurance tidak di-hash) —
`ok_run --run` tetap `272d7531...`. Verifikasi: `ok_prove --prove` → L2
(EVA) + version; `bad_prove` → PROVE_VIOLATION; self-dogfooding + regress
tetap hijau.

### MYC-AUDIT-016, 2026-08-02 (MCP schema & JSON-RPC ketat)

Tool `check` kini mengirim **`structuredContent`** — hasil `myc_result`
penuh sebagai objek JSON (`schema: "myc.result.v1"`) di samping
`content[0].text` (JSON string, tetap ada untuk backward compat) — konsumen
mesin TIDAK lagi perlu parse JSON di dalam JSON. **`isError` hanya untuk
kegagalan tool/protocol** (`ERROR` input/validasi, `TIMEOUT`, `CANCELLED`);
`PROVE_VIOLATION`/`DRIVER_VIOLATION` dll. adalah finding pada KODE →
isError=false (sebelumnya dicampur, tidak konsisten dengan verdict).
**JSON-RPC ketat**: field `jsonrpc` wajib `"2.0"` (selain itu → -32600),
`id` hanya string/angka/null (typed ID, nilai dipertahankan apa adanya),
pesan tanpa `id` = notification → diproses tanpa balasan (semantik JSON-RPC
2.0). **Negosiasi protokol strict**: `initialize` selalu mengumumkan versi
server (`2024-11-05`), tidak meng-echo permintaan klien. **Unknown flag
ditolak** (fail-fast -32602 dengan nama flag), tidak diabaikan. Tidak
menyentuh `myc_result` → fingerprint/receipt TIDAK berubah (`ok_run --run`
tetap `272d7531...`). Verifikasi: smoke MCP 13 respons (incl. -32600,
unknown flag, structuredContent+schema), interop SDK resmi 26 cek (incl.
isError=false untuk PROVE/DRIVER violation + structuredContent), semua
suite regress hijau.

### MYC-AUDIT-017, 2026-08-02 (saluran laporan sanitizer non-spoofable)

Marker teks pada stdout/stderr mudah dipalsukan program (fixture
`spoof_marker_run.c` / `bad_driver_spoof.c` mencetak teks mirip marker
sendiri, exit 0). Kini bukti UTAMA = FILE report yang ditulis runtime
sanitizer sendiri: env deterministik per gate (`preq.env` di proc.c —
`ASAN_OPTIONS=log_path=<base>:abort_on_error=1:halt_on_error=1`,
`UBSAN_OPTIONS=log_path=<base>:halt_on_error=1:print_stacktrace=1`,
`LC_ALL=C`) → runtime menulis `<base>.<pid>` di tmp_dir; myc membacanya via
`myc_read_sanitizer_report()` dan membersihkan via
`myc_remove_sanitizer_reports()` (glob `<base>.*`). Finding = report file
ADA **atau** (marker teks && exit code != 0). Teks mirip marker dengan exit
0 diabaikan + diagnostic (program bisa mencetaknya sendiri). Berlaku
konsisten di gate run (L3), canary, metamorphic, driver, dan filc (panic
Fil-C hanya finding bila exit != 0; marker tanpa exit = diagnostic).
`log_path` relatif (path absolut dengan `:` memecah parsing ASAN_OPTIONS di
Windows ASan; CWD child = tmp_dir unik). **Bug ditemukan & diperbaiki saat
uji**: env metamorphic dibuat di blok stack lokal yang keluar scope sebelum
`myc_proc_run` (use-after-scope → segfault; gdb backtrace: `strlen` di
`proc_run_win`); diperbaiki dengan buffer di scope fungsi
(`meta_env_asan/ubsan[2][160]`, `meta_env[2][4]`). **Bug review lanjutan**:
(1) `build_env_block` Windows hanya menambahkan override yang key-nya TIDAK
ada di induk → override yang menggantikan key induk (mis. `ASAN_OPTIONS`
bila user set) DROP total; diperbaiki: semua override ditambahkan (entri
induk ter-override sudah di-skip loop atas). (2) `child_env` POSIX bocor di
jalur sukses → di-free sebelum return. (3) filc `panics>0 && exit==0`:
jalur native vs WSL tidak konsisten (WSL set COMPLETED_CLEAN tapi ret=0 →
pipeline menimpa jadi UNAVAILABLE); kini kedua jalur treat sebagai run
bersih (`filc_panics` di-reset + ret=1 → L5 diklaim, teks diabaikan jadi
diagnostic). Verifikasi: `bad_run_oob --run` tetap RUNTIME_VIOLATION (via
report log_path), `spoof_marker_run --run` → OK + diagnostic,
`bad_run_oob --metamorphic` → inconsistency via report (-O0 finding vs -O2
clean), `ok_driver --driver` tetap OK, `ok_run --run` receipt tetap
`272d7531...`; regress 63 [OK] 0 [FAIL]; soak + MCP interop hijau.

### MYC-AUDIT-018, 2026-08-02 (test portabel: concurrency/deadlock/OOM)

Runner lintas-platform **`test/_audit018.sh`** (bash — jalan di Windows
git-bash DAN POSIX, di-wire ke `_regress_run.bat` via `where bash`; tanpa
bash → [SKIP]) membangun + menjalankan 4 unit test C baru: (1)
**`proc_flood.c`** — deadlock (child tulis 1 MiB stdout → baca 1 MiB stdin
→ tulis 1 MiB stderr; parent kirim 1 MiB stdin; tanpa timeout, total persis
— mengunci fix MYC-AUDIT-002), flood 100 MiB stdout + 100 MiB stderr cap 64
KiB (prefix+tail ring dipertahankan, truncated=1, memori bounded — mengunci
Fase 1.5), env override (key induk diganti, sisanya diwarisi — mengunci fix
AUDIT-017 build_env_block); (2) **`oom_guards.c`** — arena overflow guard +
input ekstrem (source >1MiB → INPUT_TOO_LARGE, NUL → NUL_IN_INPUT, request
kosong → INVALID_REQUEST); (3) **`oom_alloc.c`** — **allocator injection**
via `-Wl,--wrap=malloc,calloc,realloc` (GNU ld, MinGW & glibc): 49 titik
kegagalan alokasi pada myc_run tanpa crash/hang, verdict selalu valid,
kontrol OK; (4) **`stress_threads.c`** — concurrency 8×200 (kini juga di
POSIX). **Bug nyata ditemukan test ini**: `myc_result_arena_dup` dengan
`string_len` raksasa (SIZE_MAX-9) → `n+1` wrap ke 0 → `memcpy` OOB raksasa;
diperbaiki guard ganda (n==SIZE_MAX tolak + blok alokasi dicek `block >
SIZE_MAX - sizeof(arena)` → NULL). Regress naik ke **92 [OK] 0 [FAIL]**;
receipt golden tetap `272d7531...`.

### MYC-AUDIT-019, 2026-08-03 (CLI ingress fail-fast + portabilitas POSIX)

**CLI kini fail-fast pada unknown flag** (Fase-2 canonical ingress,
konsisten dengan reject unknown flag MCP AUDIT-016 -32602): `myc.exe check
ok.c --rnu` → pesan `myc: unknown option: --rnu` + exit 2 (sebelumnya
diam-diam diabaikan → hasil OK palsu saat user salah ketik flag);
`--run-stdin` / `--cwd` tanpa argumen nilai → pesan + exit 2 (sebelumnya
`--run-stdin` tanpa argumen menyebabkan OOB baca argv di luar batas saat
`argv[++i]` melewati akhir array). Parsing flag ditulis ulang ber-`known`
flag eksplisit, nilai flag dikonsumsi `i++` aman. **Bug segfault nyata di
stress_threads build POSIX**: `strdup` tidak dideklarasikan glibc tanpa
feature macro `_POSIX_C_SOURCE` → kompiler menganggapnya `int` → pointer
64-bit di-truncate ke 32-bit → segfault (ditemukan audit018 WSL); diganti
`myc_strdup()` (myc.h, impl. proc.c). **False-positive race di
stress_threads**: 8-thread berbaur di mount NTFS lambat → spawn gcc pertama
timeout transien (`MC_TIMEOUT`, err `MYC_ERR_TIMEOUT`) → `verdict_ok !=
NITER` melabeli thread "MISMATCH (race/stale)" padahal `source_sha256`
DETERMINISTIK stabil (dibuktikan debug per-iterasi); diperbaiki:
`MC_TIMEOUT` masuk set verdict yang dihitung, sinyal race tetap sha
determinisme. **Test infra**: `_regress_run.bat` memanggil `bash
test/_audit018.sh` (slash, bukan backslash — backslash pecah di WSL
git-bash), echo paren dihapus agar tak membobol blok `if errorlevel`;
`_audit018.sh` menambah deteksi `-pthread` (diperlukan pthread_create/join
di POSIX). Regresi: audit018 5/5 unit test lulus (proc_flood, oom_guards,
oom_alloc, stress_threads 8×200, verify_descendants), full
`_regress_run.bat` 0 [FAIL], receipt deterministik `ok_run --run` tetap
`8224c23a...` (tidak ada perubahan pipeline/hash).

### MYC-AUDIT-019 lanjutan, 2026-08-03 (Lampiran A roadmap + bug WIFSIGNALED POSIX)

**Bug nyata WSL ditemukan**: gate `--run` selalu INCONCLUSIVE di POSIX
karena `myc_runtime_canary` return -1 → diagnostic "canary ASan gagal
dibangun" padahal build canary sukses. Akar: program yang di-SIGABRT
sanitizer (OOB terdeteksi, exit 134 = 128+SIGABRT) diklasifikasi
`WIFSIGNALED` → `res->ok = 0` + `err = MYC_ERR_EXECUTE_FAILED` →
`myc_proc_run` return 0 → caller menganggapnya kegagalan infra. **Fix
proc.c**: `WIFSIGNALED` kini `ok = 1`, `err = MYC_ERR_NONE` (exit_code
128+sig hasil valid, konsisten dengan Windows yang selalu `ok=1` utk proses
berjalan; hanya exec/fork gagal yang `ok=0`). Akibat: run gate POSIX kini
benar-benar menangkap finding (bad_run_oob `--run` → RUNTIME_VIOLATION),
canary sehat (ok_run `--run` → completed_clean), metamorphic konsisten.
**Portabilitas `-Werror`** (self-dogfooding WSL awalnya 3 COMPILE_ERROR):
`(void)write()` tidak menekan `-Wunused-result` glibc → diganti tangkap
`ssize_t wr`; `copy_file`/`asan_dll_path` (run.c) & `drv_copy_file`/
`drv_asan_dll_path` (driver.c) hanya dipakai di `#ifdef _WIN32` → kini
di-guard `#ifdef _WIN32` (unused di POSIX). **Lampiran A roadmap ditutup**:
`test/audit_lampiran.c` baru (7 test portabel, di-wire ke `_audit018.sh`):
exec-vs-127, temp path absolut, multiple consecutive requires, long
contract expression REJECTED (bukan truncate — `read_contract_expr` kini
return 2 + diagnostic "terlalu panjang", contract.c), NUL tak pernah dibuat
di POSIX, 0 driver cases, result lama immutable. Lampiran A kini 24/27
`[x]` (sisa: fingerprint OOB test, file_path-only test, OOM JSON test,
Fil-C run_stdin, canary-failure fixture — fix ada, test eksplisit belum).
Regresi: audit018 6/6 unit (audit_lampiran 12/12 OK), self-dogfooding WSL
17/17 OK, Windows regress fixture utuh (ok_run L3, bad_run_oob
RUNTIME_VIOLATION, ok_checked L4).

### MYC-AUDIT-019 lanjutan #2, 2026-08-03 (Lampiran A di-ikat test penuh)

`test/audit_lampiran.c` bertambah menjadi 17 test: **T8** fingerprint cwd
3000-char tetap 64-hex + deterministik (AUDIT-005; `--fp-long` mode; varian
ASan di-ikat ke `_audit018.sh` section 6b — menangkap OOB read regresi
secara eksplisit, non-blocking bila toolchain tanpa ASan), **T9**
`file_path`-only request tanpa NULL deref + source di-load & di-hash
(AUDIT-007), **T11** canary failure invalidates backend (9.9): binary
di-hardlink sebagai `fake-clang` (`fake-clang.exe` di Windows,
`strstr(argv[0],"fake-clang")` dispatch) yang menolak build canary (`-o`
berisi "myc_canary" → exit 1, nama canary = `myc_canary.exe` di
`run.c:317`) tapi menerima verification build (compile program polos via
gcc) → `myc_runtime_canary` return -1 → gate runtime **INCONCLUSIVE**
(run.c:744-763). **OOM JSON** (AUDIT-009): fase
`json_new_obj/obj_set/arr_push/serialize` 49 fail point ditambahkan ke
`test/oom_alloc.c` (--wrap). **Bug nyata ditemukan di WSL**: parent myc mati
SIGPIPE (exit 141) saat menulis stdin ke child yang sudah mati lebih awal
(exec gagal / `chdir(cwd)` gagal — T8 memakai cwd 3000-char yang tak ada →
child _exit sebelum baca stdin) → `write()` tidak sempat return EPIPE karena
sinyal default membunuh parent. **Fix proc.c POSIX**: tahan `SIGPIPE`
(`SIG_IGN` via `sigaction`, simpan & pulihkan handler lama) selama loop
tulis stdin; `write()` kini return EPIPE → break seperti desain. Lampiran A
kini **27/28** `[x]` (sisa: Fil-C run_stdin WSL path — mekanisme ada tapi
stdin tidak diteruskan ke program child di WSL; fix terpisah). Fil-C kini
terpasang di WSL (pizfix 0.681, `~/bin/filc-clang` → `filc-clang` di PATH;
gate `--filc` berfungsi: ok_filc → L5 FILC, bad_filc_oob →
FILC_VIOLATION). Regresi: `_audit018.sh` WSL 6/6 + fp-long ASan OK +
verify_descendants OK (0 FAIL); Windows `_regress_run.bat` 0 [FAIL]
(self-dogfooding 16 OK, fixtures utuh, MCP interop 25 cek).

### MYC-AUDIT-020, 2026-08-03 (CLI `--timeout`/`--output-cap` + validasi request API)

Flag CLI baru `--timeout MS` (0–600000, 0 = default 30000) dan
`--output-cap BYTES` (0–104857600, 0 = default 1 MiB) memetakan ke field
`myc_request.timeout_ms`/`max_output_bytes` yang sudah dipakai semua gate
(proc/run/prove/filc/driver/metamorphic). **Validasi ingress di
`myc_request_validate`** (berlaku untuk CLI, API, dan MCP): timeout di luar
rentang → `MYC_ERR_INVALID_TIMEOUT`; output-cap di luar rentang →
`MYC_ERR_INVALID_OUTPUT_CAP`; `cwd` string kosong → `MYC_ERR_INVALID_CWD`
— verdict ERROR + diagnostic CONFIRMED (bukan silent). **Bug nyata yang
diperbaiki**: `--output-cap -5` sebelumnya LOLOS validasi (cek hanya `>
cap`) → di proc.c `req->max_output_bytes` (int -5) di-cast ke `size_t`
raksasa → alokasi drain buffer raksasa saat `--run`; kini nilai negatif
ditolak. **Fail-fast angka** (konsisten MYC-AUDIT-019): `atoi` diganti
helper `parse_int_arg` (strtol + cek `errno==ERANGE` + trailing garbage +
rentang int) — `--timeout abc`/`--timeout 5000x`/`--output-cap
99999999999` kini pesan + exit 2, bukan diam-diam jadi 0/default. Capsule
(`myc_replay_capsule`) sudah memuat timeout_ms/max_output_bytes (tidak
berubah). Receipt TIDAK berubah (validasi ingress tidak masuk hash) —
`ok_run --run` tetap `8224c23a...`. Regresi: section AUDIT-020 di
`test/_regress_run.bat` (+12 cek: valid, negatif, overflow, non-angka exit
2, aliran nilai ke capsule, cwd kosong).

### MYC-AUDIT-021, 2026-08-03 (Lampiran A 28/28: run_stdin ke Fil-C di WSL)

Gate `--filc --run-stdin` di WSL TIDAK meneruskan stdin ke program child —
env `MYC_FILC_STDIN` berisi path Windows (`D:\Temp\...`) yang tidak bisa
dibaca WSL, dan env Windows → WSL bash TIDAK diteruskan otomatis (debug
membuktikan: blok env benar berisi `MYC_FILC_STDIN`, tapi `echo` di WSL
tetap `UNSET`). **Fix**: pakai mekanisme resmi **`WSLENV`** — proc.c
`build_env_block` sekarang menambahkan override `WSLENV` (merges parent
bila sudah ada; `MYC_FILC_STDIN/p` = share + path translation otomatis ke
`/mnt/<drive>/...`), filc.c template WSL memakai `$MYC_FILC_STDIN`
langsung (fallback `wslpath` bila WSLENV tak sampai). **Bug lanjutan
ditemukan & diperbaiki**: entri env tanpa `=` → CreateProcess `ERROR 87`
(ERROR_INVALID_PARAMETER) — `wslenv_env` sempat tanpa prefix `WSLENV=`;
double-colon di WSLENV dihindari. **Leak**: file stdin temp Windows kini
di-`remove()` di semua jalur keluar (out_wsl + early-return). Fixture
permanen `test/fixtures/ok_filc_stdin.c` (baca stdin, cetak `got:...`) +
regresi AUDIT-021 (`ok_filc_stdin --filc --run-stdin` →
`got:halo-filc-stdin`; di sistem tanpa Fil-C = INFO, bukan FAIL). Lampiran
A kini **28/28** `[x]`. Receipt tidak berubah.

### MYC-AUDIT-022, 2026-08-03 (roadmap 7.1: machine-readable diagnostic + exact tool identity)

(1) **diagnostic JSON** — gate kompilasi (compile, analyzer, checked) dapat
mengekstrak diagnostik terstruktur jika GCC mendukung format JSON;
`ingest_gcc_diagnostics` di compile.c mem-parse array JSON (reuse parser
ketat json.c): `kind`/`message`/`locations[0].caret.line/column` →
`myc_diagnostic` terstruktur (kind `note` di-skip, konsisten parser teks
lama); bila parse JSON gagal (output terpotong bounded capture) atau stderr
format teks (gate preprocess `gcc -E` tanpa flag JSON) → fallback parser
baris lama. Verifikasi: `bad_realloc.c` → diag `[17:12] pointer 'buf' used
after 'realloc'` (dari JSON, confidence CONFIRMED); (2) **exact tool
identity** — helper baru `myc_tool_version()` di proc.c (jalankan `<exe>
--version`, ambil baris pertama stdout, buang trailing CR) → field baru
`myc_result.gcc_version`/`clang_version` (di-set pipeline setelah resolve
gcc/clang, guard NULL agar run+driver tidak double-free), ditampilkan di
teks (`gcc_version:`/`clang_version:`) + JSON (`"gcc_version"`/
`"clang_version"`, NULL → null); `myc version` CLI kini mencetak versi
persis backend (`gcc.exe (...) 15.2.0`, `clang version 22.1.6 (...)`) —
menutup roadmap "version belum memberi exact toolchain identity". Receipt
TIDAK berubah (flag/versi tidak masuk hash; status gate clean tetap clean)
— `ok_run --run` tetap `8224c23a...`. Regresi: section AUDIT-022 di
`test/_regress_run.bat` (+8 cek).

### MYC-AUDIT-023, 2026-08-03 (Fase 8: CI Windows + Linux / test engineering)

(1) **`build.sh`** — mirror POSIX `build.bat` (myc/mcp/argv_probe) untuk
Linux/CI. (2) **`test/_ci_linux.sh`** — trust-core runner POSIX: build +
self-dogfooding 16 source + fixture kunci (ok_hello OK, bad_syntax/
bad_realloc COMPILE_ERROR, diagnostic JSON, checked L4, run
L3/RUNTIME_VIOLATION, dogfood tool, json_abuse, audit018). Frama-C/Fil-C
TIDAK diinstall di CI → fixture terkait UNAVAILABLE (non-blocking 9.10).
(3) **`.github/workflows/ci.yml`** — job windows (build.bat +
`_regress_run.bat`; toolchain preinstalled image windows-2025: MSYS2
mingw64 gcc 15.2.0 di C:\msys64 + LLVM 20.1.8, keduanya ditambahkan ke
PATH) + job linux (build.sh + `_ci_linux.sh`; apt install clang). **Bug
portabilitas yang ditemukan & diperbaiki**: (a) assert receipt golden
`8224c23a...` di `_regress_run.bat` bersifat MESIN-SPESIFIK — receipt
memuat fingerprint berisi `gcc_path`+`cwd`, jadi nilai golden beda di CI →
diganti cek DETERMINISME lintas-run (dua run input sama → receipt sama);
(b) `_audit018.sh` section filc salah memakai `run_built` (cek EXIT code)
untuk fixture `bad_filc_oob --filc --run` — verdict FILC_VIOLATION memang
exit 1 → diganti grep output; (c) gcc 13 (Linux) memakai kutip Unicode `'`
sedangkan gcc 15 (MinGW) ASCII `'` pada pesan `pointer 'buf' used after
'realloc'` → pola regex cocok keduanya; (d) bug cmd: parens `(CI-
portabel)` di teks echo dalam blok `if (...)` memutus parsing (`)` tak
terduga) → bentuk `if defined ...` tanpa blok. **Perbaikan CI lanjutan
(2026-08-05)**: (e) `prove.c` -Werror gagal di Linux gcc 13 karena
`run_wsl()` + `wsl_path` unconditional di file yang juga dikompilasi di
POSIX → di-`#ifdef _WIN32`; (f) `fingerprint_cache_update` crash saat
`cwd == NULL` pada run kedua → guard `(!cwd || strcmp(...))`; (g)
`fp_cache` static global menyebabkan data race di `stress_threads` →
diubah jadi `_Thread_local`. Verifikasi: Linux (WSL) `_ci_linux.sh`
PASS=18 FAIL=0 (audit018 SELESAI OK incl. filc + verify_descendants);
Windows regress 153 [OK] 0 [FAIL]. Catatan: job CI windows memakai clang
MSVC-target LLVM (ASan DLL `clang_rt.asan_dynamic-x86_64`) — bila backend
run tak sehat, canary → INCONCLUSIVE dan assert L3 FAIL (jujur, bukan
false-clean).

### MYC-AUDIT-024, 2026-08-03 (roadmap 7.7: Fil-C version identity + robust report parser + per-case scope)

(1) **version identity** — field `filc_version` di `myc_result` (baris
pertama `filc-clang --version`, mis. `clang version 20.1.8 (Fil-C 0.681
...)`), diisi native via `myc_tool_version` dan WSL via query
`query_filc_version_wsl` (non-blocking: gagal = NULL, verdict tak berubah);
tampil di teks (blok `filc:` baris `version:`) + JSON (`filc_version`);
`myc version` kini juga mencetak status filc (jujur: `TIDAK DITEMUKAN` di
Windows karena filc-clang hanya Linux). (2) **robust report parser** —
`count_panics` (hitungan strstr marker yang rapuh/spoofable) diganti
`parse_filc_report` STRUKTURAL: panics = jumlah baris kanonik `[<pid>] filc
panic:` (tiap panic meng-abort SIGTRAP → tepat satu baris), fallback jumlah
blok `filc safety error:` (kompatibilitas format Fil-C lain); teks yang
HANYA memuat kata marker tanpa baris kanonik/blok safety error TIDAK
dihitung (konsisten MYC-AUDIT-017). (3) **per-case scope** —
`myc_filc_case[]` (maks 8, arena): tiap panic terekam message (teks setelah
`filc safety error:`) + lokasi origin dari frame pertama `semantic origin:`
(`file:line:col: func`); tampil di teks (`case #N:` + `origin:`) + JSON
(`filc_cases[]`); diagnostic violation kini memuat lokasi (`filc: 1 panic
-> bug memori terbukti (main @ /tmp/...:15:14: cannot write pointer ...)`
— terbukti fixture `bad_filc_oob`). Receipt TIDAK berubah (field baru
tidak masuk hash). Verifikasi: Windows regress 153 [OK] 0 [FAIL] (section
AUDIT-024 +6 cek), WSL `_ci_linux.sh` PASS=18 FAIL=0 (audit018 6c +
version identity + per-case scope), `myc version` cetak filc.

### MYC-AUDIT-025, 2026-08-03 (roadmap 7.4: Contract — pure expression validation + explicit clause status + stable function binding)

(1) **pure expression validation** — `contract_expr_purity()` (lexical,
skipping string/char literal): assignment (`=`, `+=`, `-=`, `*=`, `/=`,
`%=`, `<<=`, `>>=`, `&=`, `|=`, `^=` — `==`/`!=`/`<=`/`>=` pure), `++`/`--`,
operator comma level atas → **IMPURE**; pemanggilan fungsi (identifier
selain `sizeof` diikuti `(`) → **CALL** (purity tak terbukti). Klausa
impure/call **TIDAK pernah di-inject** sebagai assert (safety: ekspresi
ber-efek samping tidak boleh berjalan di verification build). (2)
**explicit clause status** — `myc_contract_clause[]` (maks 64, arena) per
klausa: expr, status (`ok`/`empty`/`too_long`/`impure`/`call`), kind,
line/col; tampil di teks (`contract clauses:` baris `[N] requires (func)
expr [status]`) + JSON (`contract_clauses[]` dengan function/expr/status/
line/col). (3) **stable function binding** — `find_func_binding()`: ikat
klausa ke NAMA fungsi dari pola `<ident>(...){` (keyword kontrol
if/for/while/switch/return/sizeof/case/do/else/goto ditolak; `;` sebelum
`{` = prototype/pernyataan → tak terikat); grup klausa berturut berbagi
satu binding; `myc_contract_inject` ditulis ulang: pending MULTIPLE
requires per fungsi + purity gate + whitespace antar token tidak memutus
ikatan (bug: spasi antara `)` dan `{` membuang pending). Bug purity
ditemukan saat uji: `a == b` salah ter-flag impure karena '=' pertama hanya
memeriksa karakter sebelumnya → kini cek depan+belakang. Fixture
`test/fixtures/contract_clauses.c`: pure (di-inject, run bersih), impure
`(x = 0) != 0` (TIDAK di-inject — bila di-inject pasti RUNTIME_VIOLATION),
call `helper(-5) > 0` (TIDAK di-inject), unbound sebelum deklarasi global.
Verifikasi: contract_clauses --run OK (bukti purity gate), bad_contract_pre
--run tetap RUNTIME_VIOLATION (requires pure di-inject), ok_contract --run
OK; regresi +8 cek AUDIT-025; receipt deterministik tetap `8224c23a...`
(field klausa tidak masuk hash).

### MYC-AUDIT-026, 2026-08-04 (roadmap 7.3: Checked buffer — coverage count + semantics parity tests)

(1) **coverage count** — scanner leksikal TUNGGAL `scan_checked_coverage()`
(compile.c) menggantikan `source_uses_checked_buf` (sumber kebenaran
tunggal, tanpa duplikasi logika skip komentar): menghitung deklarasi
`MYC_BUF(` + invokasi `MYC_NEW(`/`MYC_AT(`/`MYC_FREE(` di LUAR komentar /
string / char literal / baris preprocessor; batas identifier dijaga
(`MYC_BUF_COOKIE` tidak terhitung). Empat metrik `checked_buffers` /
`checked_allocations` / `checked_accesses` / `checked_frees` di laporan
teks (`checked:` blok `coverage: buffers=N allocations=M accesses=K
frees=F`) + JSON (`checked_buffers` dkk, hanya bila memakai MYC_BUF) +
capsule replay (`checked_coverage:` / `"checked_*"`). `accesses` = TITIK
akses di source yang tercakup disiplin MYC_AT (1 per invokasi tekstual,
BUKAN per eksekusi runtime — jujur: metrik statis seperti callsite
negative). Bila build `-DMYC_CHECKED` lolos, tiap buffer + tiap titik akses
terbukti tunduk cek batas → coverage = bukti cakupan L4. (2) **semantics
parity tests** — fixture `tests/semantics_parity.c` (digest deterministik
uint32; buffer `MYC_BUF(int)` + `MYC_BUF(point)` struct; coverage
2/2/6/2) dibangun DUA KALI oleh regresi: produksi (`gcc -O2`) vs checked
(`gcc -O2 -DMYC_CHECKED=1`); stdout + exit code harus IDENTIK
(`digest=176930656`, exit 0) → membuktikan transformasi fat-pointer TIDAK
mengubah perilaku kode sah (nol false positive). Terpasang di
`_regress_run.bat` (+8 cek AUDIT-026) dan `_ci_linux.sh` (section 4b,
Linux CI). Verifikasi: semantics_parity --checked → L4 + coverage
2/2/6/2, ok_checked → 1/1/2/1, dogfood_ring tetap L4, parity identik di
Windows; receipt tetap `8224c23a...` (coverage bukan bagian fingerprint —
source_sha sudah mencakup source).

### MYC-AUDIT-027, 2026-08-04 (roadmap 7.5: Driver — case record + replay capsule + boundary portfolio + combinatorial budget)

(1) **case record** — struct `myc_driver_case` di `myc.h` (case_id, func,
params, alloc_bytes, executed) + `driver_case_records[]` (maks
`MYC_MAX_DRIVER_RECORDS` 256) di `myc_result`; dibangun di
`myc_driver_gate` dari metadata harness (`drv_case_meta`: nama fungsi,
nama param, is_ptr, ukuran buffer, nilai kandidat per param, kombinasi) +
peta eksekusi per-case dari stdout. Record menampilkan parameter values +
allocation sizes + status run/skip — ditampilkan di teks (`case records
(input + status):` baris `#N func(a=16B, n=0) alloc=16B -> run`) + JSON
(`driver_case_records[]`) + capsule. (2) **harness flush jujur** — harness
kini `setvbuf(stdout, NULL, _IONBF, 0)` di awal main; tanpa ini, saat
sanitizer meng-abort proses di tengah run, stdout pipe yang fully-buffered
tidak ter-flush → SEMUA marker per-case hilang → record salah tampil 'skip'
dan klaim debt '0 kasus tereksekusi' muncul padahal kasus dieksekusi (bug
nyata ditemukan di bad_driver_oob: ASan abort di kasus n=4; sebelum fix
`cases: 0`, sesudah fix `cases: 2` + record #1/#2 run, #3-5 skip). Bila
summary `DRIVER run=N` tidak sempat tercetak (abort),
`driver_cases`/`driver_skipped` diturunkan dari jumlah marker per-case.
Akibat: bad_driver_oob TIDAK lagi memicu debt NONZERO-CASES (memang bukan
0 kasus); debt itu kini diuji lewat fixture baru
`test/fixtures/driver_zero_cases.c` (guard requires `g_flag == 1` selalu
salah → semua kasus di-skip, exit 3 → INCONCLUSIVE + debt GATE-UNAVAILABLE
+ NONZERO-CASES). (3) **combinatorial budget** — `build_combos()` di
driver.c: produk kartesian ≤ `DRV_MAX_CASES` 32 = strategi `full`; produk
> 32 = `coverage-first` (base + satu-per-nilai-ekstra + filler
leksikografis) dengan jaminan deterministik setiap nilai kandidat muncul
minimal sekali; dilaporkan jujur di teks+JSON (`combinatorial:
max_product=N budget=32 strategy=full|coverage-first`) + capsule
(`driver_max_product`/`driver_bounded`). (4) **harness identity** —
`driver_harness_sha256` (SHA-256 teks harness) di `myc_result` + capsule;
verifikasi fixture `ok_driver_bounded.c` (kontrak a/b/c ≤ 3 → max_product
64 > 32 → coverage-first, 32 kasus). Receipt TIDAK berubah (case
records/coverage bukan bagian hash) — `ok_driver --driver` tetap
`0e9be800...`. Terpasang di `_regress_run.bat` (section AUDIT-027, +10
cek) dan `_ci_linux.sh` (section 5c, +8 cek). Verifikasi: ok_driver OK L3 +
10 records + full; bad_driver_oob DRIVER_VIOLATION + records akurat;
driver_zero_cases INCONCLUSIVE + debt; mcp smoke 13 respons utuh; JSON +
capsule valid. (5) **bug portabilitas POSIX (kelas MYC-AUDIT-003)** ditemukan
saat menulis regresi Linux: `drv_make_temp_dir` memakai fallback `"."` di
POSIX (tanpa `/tmp` + canonicalisasi getcwd) → `exe_path` relatif rusak
setelah child `chdir(tmp_dir)` → gate driver di WSL SELALU "driver run exec
failed" (ok_driver jadi INCONCLUSIVE padahal build sukses; `funcs: 0`).
Diperbaiki mirror `make_temp_dir` run.c: `TEMP` → `TMPDIR` → `/tmp`,
canonicalize base relatif via `my_getcwd`; driver kini berfungsi penuh di
POSIX (ok_driver L3, harness sha IDENTIK lintas platform `6919dfb9...`,
bounded coverage-first 32 kasus). Verifikasi: `_ci_linux.sh` WSL PASS=30
FAIL=0 (sebelumnya PASS=21 FAIL=1).

### MYC-AUDIT-028, 2026-08-04 (Fase 2: size cap saat membaca)

`read_file`/`read_stdin` lama membaca PENUH tanpa batas (file 10 GB →
`malloc` 10 GB sebelum validasi menolak; `--run-stdin` tanpa cap sama
sekali; MCP `run_stdin` tak divalidasi). Kini
`read_file_capped(path, cap, ...)`/`read_stdin_capped(cap, ...)` (myc.c)
baca BERTAHAP chunk 64 KiB dan menolak SEGERA saat `len+1 > cap` — buffer
raksasa tidak pernah dialokasikan. Cap: source `MYC_MAX_CODE_BYTES` 1 MiB,
`--run-stdin` konstanta baru `MYC_MAX_STDIN_BYTES` 8 MiB (myc.h). CLI
fail-fast exit 2 + pesan (`myc: <file>: ukuran melebihi cap N byte`) untuk
source file, source stdin (`-`), dan `--run-stdin`. API/MCP: cap
`run_stdin_len` di `myc_request_validate` → error baru
`MYC_ERR_STDIN_TOO_LARGE` (mapping report.c `stdin_too_large`); MCP
`run_stdin` sudah ter-cover + perlindungan lapis kedua `MCP_MAX_LINE` 8 MiB
yang menolak baris JSON raksasa (parse error). Receipt TIDAK berubah (cap
validasi bukan bagian hash) — `ok_run --run` tetap `8224c23a...`.
Verifikasi: source 1.05 MiB → exit 2, run-stdin 9 MiB → exit 2, stdin
source 1.05 MiB → exit 2, MCP payload 9 MiB → parse error (MCP_MAX_LINE);
regress Windows 0 [FAIL] (flaky transient "inject requires pure rusak"
muncul sekali dari race run-gate berturut, hilang pada run ulang),
self-dogfooding myc.c/mcp.c OK, receipt deterministik. Terpasang di
`_regress_run.bat` (section AUDIT-028, +6 cek via `fsutil` big-file) dan
`_ci_linux.sh` (section 5d, via `dd`/`mktemp`).

### MYC-AUDIT-029, 2026-08-04 (Fase 2: canonical ingress — `myc_source_input` formal struct)

`myc_request` kini memakai `myc_source_input input` (enum `myc_source_kind`:
MYC_SOURCE_MEMORY / FILE / STDIN) menggantikan field
`source`/`source_len`/`file_path` yang tersebar. **Loader terpusat
`myc_source_load()`** (myc.h + myc.c): satu titik cap + NUL policy + error
typed untuk semua kind — MEMORY = pointer asli tanpa alokasi; FILE =
`read_file_capped`; STDIN = `read_stdin_capped` (keduanya dipindah keluar
blok CLI agar ikut ter-link ke mcp.exe). **Pipeline HANYA menerima
in-memory** (`MYC_SOURCE_MEMORY`): blok jalur file_path lama di `myc_run`
(fopen/fseek/ftell, baca penuh, hanya cap-check sebelum malloc) DIHAPUS —
sekarang semua lewat loader, jadi jalur file_path API/MCP mendapat cap saat
membaca juga (bukan hanya CLI). CLI dan MCP memakai loader yang sama dengan
API (satu sumber kebenaran, tidak ada duplikasi logika baca). Dampak
pemakai: `compile.c` membaca `req->input.data/len`; test API
(audit_lampiran/oom_alloc/oom_guards/stress_threads) di-update. Test baru
T12/T13 di audit_lampiran: `myc_source_load` MEMORY → pointer asli tanpa
alokasi, FILE >1MiB → INPUT_TOO_LARGE, FILE tak ada → INVALID_PATH. Receipt
TIDAK berubah (source_sha sudah di-hash di compile gate) — `ok_run --run`
tetap `8224c23a...`. Verifikasi: Windows regress 0 [FAIL] (audit_lampiran
OK, T9 file_path-only tetap hijau, run-stdin L3, MCP smoke utuh), WSL
`_ci_linux.sh` PASS=32 FAIL=0. Roadmap Fase 2: size cap (AUDIT-028) +
myc_source_input (029) selesai; sisa `File path canonicalization` +
`string public pointer+length`.

### MYC-AUDIT-030, 2026-08-04 (Fase 2: File path canonicalization)

Helper static `myc_absolutize()` di `myc.c` — canonicalization **lexical**
(absolutize path relatif terhadap `my_getcwd` buffer 4096, normalisasi
`\`→`/` di Windows, resolve `.`/`..` dengan pop yang tidak melewati
root/drive, prefix drive `X:` + root `/` dipertahankan; **tanpa menyentuh
filesystem** sehingga cwd boleh tidak ada). `myc_run()` kini canonicalisasi
`req->cwd` di ingress ke salinan efektif `reqc` (tanpa memutasi request
caller), dipakai pipeline/quorum/enforce/capsule; `free(canon_cwd)` di
semua jalur keluar termasuk error path. NON-blocking: `my_getcwd` gagal
atau OOM → pakai nilai cwd asli. Ejaan cwd-ekuivalen (`tests`,
`tests\..\tests`, `.\tests`, `tests/../tests`) → cwd capsule canonical +
fingerprint IDENTIK (`7252ee12...`); direktori berbeda → berbeda
(`166dc682...`). **Bug nyata yang diperbaiki saat verifikasi**: (1) array
segmen diresize memakai counter `j` (0 untuk path absolut) → heap corruption
exit `0xC0000374`; diganti ukuran `strlen(work)+1` tetap tanpa grow; (2)
`realloc`-grow yang men-trigger `-Wuse-after-free` false positive →
pre-alokasi tetap. T14 di audit_lampiran (fingerprint identik antar ejaan +
berbeda antar direktori, macro `myc_getcwd`). Regresi `_regress_run.bat`
seksi AUDIT-030 membandingkan baris capsule `cwd:` (bukan JSON penuh yang
memuat `duration_ms`). Receipt TIDAK berubah (cwd canonical setara untuk
input tanpa `--cwd`) — `ok_run --run` tetap `8224c23a...`. Roadmap Fase 2:
canonicalization selesai; sisa `string public pointer+length` (efektif
terpenuhi AUDIT-029: source → `input.data/len`, run_stdin →
`run_stdin_len`; cwd/file_path adalah path OS yang NUL tak valid).

### MYC-AUDIT-014, 2026-08-02 (lint heuristik TIDAK hard lagi)

Seluruh rule lint.c (intptr_t/uintptr_t cast, realloc ke variabel lain,
memcpy/memset tanpa sizeof, ukuran alokasi perkalian tanpa sizeof, akses
langsung `b[i]` pada MYC_BUF) kini menghasilkan **observasi ber-confidence**
(`myc_confidence`: OBSERVATION/SUSPICIOUS/LIKELY/CONFIRMED) dan
**NON-blocking** — `myc_lint_source` mengembalikan jumlah observasi,
`MYC_ERR_LINT_VIOLATION` tidak lagi dipicu, verdict tidak pernah turun
karena lint. Gate baru **`MYC_GATE_LINT`** (completed_clean /
completed_observations) masuk evidence matrix + assurance vector (dimensi
COMPILE; observations benign — C1 tetap selama gcc -c bersih) + quorum
(observations = non-conflict) + capsule. `myc_diagnostic.confidence`
diisi di semua setter: CONFIRMED untuk bukti semantik (gcc/sanitizer/Eva/
Fil-C/checked), OBSERVATION/SUSPICIOUS untuk heuristik teks (lint,
negative, scanner, contract). Laporan teks menampilkan `[confidence]` pada
diagnostic heuristik + ringkasan `lint (14): N observasi`; JSON memuat
`"confidence"` per diagnostic + `"lint_observations"`. Tool MCP `lint`
ikut non-blocking (`lint: N observasi`). Hard violation HANYA dari bukti
semantik: `bad_realloc.c` → COMPILE_ERROR via gcc `-Werror=use-after-free`
(AST/dataflow), `bad_intptr.c` → OK + 2 observasi (cast eksplisit tidak
ditangkap kompiler — jujur). Regresi: section AUDIT-014 di
`test/_regress_run.bat` (+7 cek, quorum bad_intptr diperbarui ke clean).
Receipt berubah (gate baru masuk hash) → `ok_run --run` → `8224c23a...`
(deterministik). Catatan: semua golden receipt yang disebut entri audit
LAMA (`272d7531...` dll) adalah nilai SAAT ITU — sejak AUDIT-014 receipt
bergeser karena `MYC_GATE_LINT` selalu masuk hash; nilai berlaku sekarang
= yang tertera di entri ini.

### MYC-AUDIT-015, 2026-08-02 (portability `NUL`)

Target `-o` pada gate compile-only kini memakai device null PORTABEL —
helper `myc_null_device()` di `compile.c` ("NUL" di Windows, "/dev/null" di
POSIX; literal "NUL" di POSIX adalah file biasa, artefak repo lama).
Literal "NUL" pada daftar flags statis (MEMORY_GATE/ANALYZER_EXTRA/
CHECKED_EXTRA) diganti runtime di `merge_args` — satu titik perubahan,
daftar tetap statis. Opsi temporary-object yang dikelola & dihapus TIDAK
diambil (lebih kompleks tanpa manfaat untuk compile-only). Fingerprint/
receipt TIDAK berubah (target -o tidak masuk hash) — `ok_run --run` tetap
`272d7531...`. Verifikasi: ok_hello L1, bad_syntax COMPILE_ERROR, ok_checked
L4 (gate compile + checked bekerja dengan device null); self-dogfooding +
regress hijau.

### Dogfooding lintas-program tiga tool, 2026-08-02

`dogfood_ring.c` (ring buffer, MYC_BUF → L4), `dogfood_config.c` (parser
config key=value, idiom realloc aman ke member `cfg->items = tmp` +
copy_bounded), dan `dogfood_tilemap.c` (flood-fill BFS tile map 2D domain
game, stack eksplisit non-rekursif + indeks y*W+x berbatas). Ketiganya
lolos `myc check` OK/L1 + `--run` OK/L3, gcc -Wall -Wextra -Werror diam;
tilemap juga tervalidasi diam terhadap `-fanalyzer`. Terdaftar di
`test/_regress_run.bat`.

### P8 (D1.2) — checked-build makro, 2026-08-01

`myc_buf.h` dual-mode (produksi `MYC_BUF(T)` = `T*` polos;
`-DMYC_CHECKED=1` = fat-struct + `MYC_AT` cek batas). Gate `--checked`
membangun source 2×; akses langsung `b[i]` pada MYC_BUF = COMPILE_ERROR di
checked build → semua akses dipaksa via MYC_AT → **L4 SPATIAL**.
`--run --checked` memakai verification build fat-pointer di bawah ASan.
Non-blocking: source tanpa pola MYC_BUF → skip + diagnostic. Fixture:
`ok_checked.c` → L4; `bad_checked.c` → COMPILE_ERROR; `bad_checked_oob.c`
→ RUNTIME_VIOLATION. Dogfooding: `dogfood_ring.c` ditulis ulang memakai
MYC_BUF → L4.

### P8 (D4.1) — gate Fil-C, 2026-08-01

`--filc` → **L5 FILC** (label lama "L5 FULL" dihapus MYC-AUDIT-013 — run
Fil-C membuktikan eksekusi terkendali bersih, bukan "full"; backend
opsional). Deteksi filc-clang di PATH (native Linux) atau via
WSL (`command -v filc-clang` / `/opt/fil/bin/filc-clang`); verification
build + eksekusi terkendali. Marker panic Fil-C (`filc safety error` dll,
terkonfirmasi dari issue tracker) → verdict **FILC_VIOLATION**. Run
bersih → L5 FILC. Non-blocking: filc-clang tidak tersedia → skip +
diagnostic (assurance statis dipertahankan). Fixture: `ok_filc.c` → L5
FILC bila ada; `bad_filc_oob.c` → FILC_VIOLATION bila ada. Di sistem ini
Fil-C TIDAK terpasang → fixture masuk jalur `UNAVAILABLE` (gap terlihat:
verdict INCONCLUSIVE + debt `MYC-INCOMPLETE-GATE-UNAVAILABLE`, bukan OK
senyap — perbaikan AUDIT-004/010 via 9.10).

### Catatan bug P7 (dogfooding)

- lint.c hanya mengenali idiom realloc aman `buf = tmp`, TIDAK mengenali
  akses member `b->data = nd` → false VIOLATION pd kode sah. Diperbaiki:
  `read_arg_ident`/`ident_before` kini membaca rantai member (`->`/`.`).
- run.c: `myc_contract_inject` menulis `*out_len=0` pd return NULL sehingga
  `build_src_len` ter-clobber → clang menerima stdin kosong →
  `lld-link: subsystem must be defined` → semua fixture non-kontrak turun ke
  L1. Diperbaiki: panjang inject dipakai hanya bila non-NULL; contract.c
  tidak lagi menyentuh `*out_len` saat NULL.

### Perubahan perilaku fixture

`bad_system.c`, `bad_fopen.c`, `bad_include.c`, `bad_macro.c` kini **OK**
(hanya warning policy). Sejak MYC-AUDIT-014: `bad_intptr.c` → OK + 2
observasi lint (cast eksplisit lolos gcc), `bad_realloc.c` →
**COMPILE_ERROR** via gcc `-Werror=use-after-free` (bukti semantik).
Fixture P6: `ok_run.c` → L3; `bad_run_oob.c`/`bad_run_uaf.c`/
`bad_run_intovf.c` → RUNTIME_VIOLATION.

Fixture P8 (D1.2): `ok_checked.c` → L4 (SPATIAL); `bad_checked.c` →
COMPILE_ERROR (akses langsung pada MYC_BUF); `bad_checked_oob.c` →
RUNTIME_VIOLATION (`--run --checked`).

Fixture P8 (D4.1): `ok_filc.c` / `bad_filc_oob.c` → L5 / FILC_VIOLATION
bila Fil-C tersedia; `UNAVAILABLE` + debt (gap terlihat) bila tidak
(perbaikan 9.10/AUDIT-004).

### Trust Core Stabilization — Fase 1 partial, 2026-08-02

(dari audit `docs/myc-serious-review-and-roadmap.md`):

- **MYC-AUDIT-005 diperbaiki** (`compile.c`): fingerprint OOB read.
  `snprintf` truncated mengembalikan panjang *yang seharusnya* ditulis,
  bukan panjang aktual di buffer. Bug lama: `sha256_hex(buf, n, ...)` bisa
  membaca di luar `buf[512]` bila path gcc + cwd + metadata > 511 byte.
  Perbaikan: `snprintf(NULL, 0, ...)` dulu untuk menghitung panjang exact,
  alokasi dinamis, baru hash. Fingerprint version bump: `v7` → `v8`.
- **MYC-AUDIT-001 diperbaiki** (`proc.c`): drain thread POSIX tidak
  di-join. `pthread_t` lama dibuang — thread masih menulis ke buffer
  sementara parent sudah transfer hasil (race/UAF). Perbaikan: simpan
  `pthread_t to/te`, periksa return `pthread_create`, `pthread_join`
  keduanya *setelah* child berhenti dan pipe ditutup, baru salin buffer.
- **MYC-AUDIT-002 diperbaiki** (`proc.c`): deadlock POSIX stdin/output.
  Urutan lama: tulis stdin penuh → baru buat drain thread. Bila child
  mengisi pipe output sebelum selesai baca stdin → deadlock. Perbaikan:
  drain thread dibuat *sebelum* menulis stdin.
- **MYC-AUDIT-011 diperbaiki** (`proc.c`): process group POSIX belum
  dibentuk sehingga `kill(-pid, SIGKILL)` tidak menjamin membunuh seluruh
  pohon child. Perbaikan: `setpgid(0, 0)` di child sebelum `execvp`;
  parent memakai `kill(-pid, ...)` ke group baru. **Lengkap 2026-08-02**:
  parent juga panggil race-safe `setpgid(pid, pid)` segera setelah fork
  (menutup window kill(-pid) sebelum setpgid child dieksekusi);
  **enabler portability** — `_strdup` (MSVC/MinGW-only, dipakai 6 file)
  diganti `myc_strdup()` (implementasi di `proc.c` agar ter-link unit
  test yang hanya men-link proc.c) + `#define _POSIX_C_SOURCE 200809L`
  di proc.c sebelum include sistem (clock_gettime/setpgid di -std=c11);
  **test nyata** `test/verify_descendants.c` (sebelumnya orphan, tak
  pernah jalan) ditulis ulang: child fork grandchild (pid + marker
  `desc.survived` setelah 5 s) lalu tidur 120 s; myc timeout 1500 ms →
  group-kill harus mematikan grandchild; harness cek marker TIDAK ada.
  POSIX-only → `_audit018.sh` guard uname (MINGW/MSYS/CYGWIN = SKIP).
  Verifikasi: WSL Ubuntu 4/4 OK; negatif kontrol (kill(-pid) mati) →
  test GAGAL (grandchild selamat & menulis marker). Windows regress 97
  [OK] 0 [FAIL]; receipt golden `272d7531...` utuh.
- **MYC-AUDIT-003 partial** (`proc.c`): tidak bisa bedakan `execvp` gagal
  dari program yang memang exit 127. Perbaikan: exec-error pipe dengan
  `FD_CLOEXEC` — child write errno saat `execvp` gagal, parent baca untuk
  mengklasifikasikan `MYC_ERR_EXECUTE_FAILED` dengan tepat.
- **MYC-AUDIT-003 partial** (`run.c`): fallback temp dir `"."` menghasilkan
  path relatif yang rusak saat child `chdir(tmp_dir)`. Perbaikan: fallback
  ke `/tmp` (POSIX) / `C:/Temp` (Windows), canonicalize via `getcwd` bila
  base masih relatif.
- **MYC-AUDIT-007 diperbaiki** (`myc.c`): `file_path`-only request lolos
  validasi tapi pipeline null-deref (`req->source == NULL`). Perbaikan:
  `myc_run()` load file ke memory di ingress layer sebelum masuk pipeline;
  pipeline selalu menerima source in-memory.
- **MYC-AUDIT-006 partial** (`proc.c`): bounded output capture hanya
  prefix — sanitizer report di akhir output terpotong bila output >
  cap. Perbaikan (Fase 1 Task 1.5): `drain_buf` kini menyimpan
  bounded prefix + bounded tail (ring buffer N byte terakhir),
  `drain_feed()` shared helper, `drain_assemble()` menghasilkan
  C-string head+tail kontigu. Flag `truncated` hanya menyala bila
  byte tengah benar-benar dibuang (total > head_cap+tail_cap).
  Regresi: `test/tail_unit.c` (8 kasus, ALL PASS).
- **Fase 4 claim compiler + legacy assurance + streaming evidence** (2026-08-02):
  `myc_validate_claim()` di `gate.c` memvalidasi assurance label
  terhadap bukti gate; `claim_status` (VALID/OVERSTATED/UNVERIFIED)
  di `myc_result`; tampil di teks `claim:` dan JSON `"claim"`.
  Assurance label lama ditandai `[legacy]` di teks; JSON menyertakan
  `"assurance_legacy":true`. Streaming evidence detector di `proc.c`
  (`stream_sanitizer_match()`) mendeteksi marker sanitizer (ASan/UBSan/
  LeakSanitizer) pada output streaming — `sanitizer_detected` +
  `sanitizer_marker` di `myc_proc_result` dan `myc_result`.
- Dogfooding: self-check 15/15 source myc OK + 3/3 dogfood/ OK; semua
  regression test + `_regress_run.bat` pass setelah perbaikan.

### P9 — MCP server + soak + corpus abuse, 2026-08-02

- `mcp.exe` — MCP server JSON-RPC 2.0 over stdio (newline-delimited, satu
  pesan per baris). In-process memakai `myc_run` (myc.c dibangun dengan
  `-DMYC_NO_MAIN`; main CLI di-guard `#ifndef MYC_NO_MAIN`). Tool:
  `check` (source + flags + cwd → JSON verdict/assurance lengkap),
  `version`, `policy`. Parser/serializer JSON sendiri di `json.c`/`json.h`
  (depth cap 64, escape `\uXXXX` incl. surrogate pair, angka int64).
  `myc_result_to_json` (report.c) = serialisasi hasil reusable (tanpa batas
  buffer statis 4096). Smoke test: `test/_mcp_smoke.bat` +
  `test/mcp_smoke_input.jsonl`.
- `test/_soak.bat` — stabilitas: 20× `myc check myc.c --analyze` (harus OK)
  + 10× `myc check ok_run.c --run` (harus ada verdict).
- `test/_corpus_abuse.bat` + `test/corpus/*.c` — input ganas (empty,
  garbage, unclosed comment/string, deep nesting, huge line, macro ganas,
  rekursi dalam): myc harus tetap memberi verdict, tidak crash/hang.

### Fase 3 — typed-gate + evidence + unverified debt, 2026-08-02

- Typed gate status (`myc_gate_status`), gate result per gate, dan
  verdict reducer PURE (`myc_reduce_verdict` di `gate.c`) mengganti
  logika boolean global. Verdict + assurance kini *diturunkan* dari status
  gate COMPLETED_CLEAN — bukan "level maksimum yang dipilih".
- Evidence ledger append-only (`myc_result_add_evidence`).
- Sumbu B completeness (`myc_completeness`: COMPLETE / INCOMPLETE) muncul
  di laporan teks + JSON.
- **Unverified debt (gagasan pembeda 9.3, Fase 4 partial)**: laporan kini
  memuat `unverified_debt[]` (teks + JSON) hanya untuk scope yang diminta
  tapi TIDAK selesai: backend tidak tersedia (UNAVAILABLE), gagal infra
  (INFRA_FAILED), hasil tidak lengkap (INCONCLUSIVE), generated driver 0
  kasus, klausa `ensures` diparse tapi tidak dibuktikan, dan output
  backend terpotong. Debt dibangun murni dari typed gate status yang sudah
  ada — tanpa backend baru.
- Regresi debt di `test/_regress_run.bat`: `bad_driver_oob --driver`
  memunculkan debt; `ok_run --run` bersih tanpa debt.
- **Bug Fase 3 ditemukan & diperbaiki (2026-08-02)**: `report.c` serialisasi
  `evidence[]` tidak memakai `json_sb_escape` pada `message` sehingga semua
  pesan evidence kosong di JSON. Diperbaiki: escape diterapkan. (Ditemukan
  saat memverifikasi output canary.)
- Semua regression + interop MCP 24 cek lolos.

### Semantic Canary, 2026-08-02 (gagasan pembeda 9.9, Fase 7.2)

Sebelum gate runtime menyatakan `COMPLETED_CLEAN` (L3 RUNTIME), myc
mengkompilasi + menjalankan canary kecil yang PASTI membuat out-of-bounds
(`myc_runtime_canary` di `run.c`). Bila canary TIDAK terdeteksi (gagal
dibangun / clean), backend ASan dianggap tidak layak dipercaya -> gate
di-turunkan ke INCONCLUSIVE (bukan COMPLETED_CLEAN) + diagnostic. Bila
terdeteksi, evidence `semantic canary terdeteksi: backend ASan sehat`
direkam di ledger. Non-blocking terhadap clang hilang (tetap UNAVAILABLE).
Dogfooding: `ok_run --run`, `dogfood_ring --run`, `--run --checked` tetap
L3/L4 (canary sehat). Regresi di `test/_regress_run.bat`.

### Evidence Receipt, 2026-08-02 (gagasan pembeda 9.1)

Laporan teks + JSON kini memuat `receipt_sha256` — hash deterministik
SHA-256 dari bukti terkumpul (`myc_build_receipt` di `gate.c`): version
receipt, verdict, completeness, tiap gate id+status, debt, fingerprint,
source_sha. Bukan klaim keamanan — melainkan sidik jari hasil agar
CI/auditor dapat membandingkan dua receipt tanpa membaca prose.
Deterministik (input sama → hash sama) dan berbeda antar verdict. Tidak
menambah backend. Dogfooding & self-check tetap OK. Regresi di
`test/_regress_run.bat`.

### Fase 5 — Reentrancy & Memory Ownership, 2026-08-02 (MYC-AUDIT-008)

- Static message ring untuk diagnostic DIHAPUS di `compile.c`/`run.c`/
  `prove.c`/`filc.c`/`driver.c`/`contract.c`/`scanner.c`/`lint.c`. Diganti
  **arena bump milik hasil** (`myc_result_arena_dup` di `myc.c`, blok 64 KiB,
  dibebaskan utuh di `myc_result_free`). Global state `buf_vars` di `lint.c`
  menjadi `_Thread_local`. Akibat: `myc_run` reentrant — MCP in-process siap
  concurrency; result lama tak tertimpa (hasil tetap immutable). OOM di
  arena → NULL, diagnostic di-skip.
- Regresi baru `test/stress_threads.c` (8 thread × 200 `myc_run`, cek tidak
  ada race/stale via kestabilan `source_sha256`) ditambahkan ke
  `test/_regress_run.bat`. Self-dogfooding 15 source tetap OK; receipt
  deterministik tetap (`ok_run --run` → `272d7531...`).

### Fase 6 — JSON & MCP ketat, 2026-08-02 (MYC-AUDIT-009)

Parser `json.c` kini menolak — leading zero, fraction/exponent tanpa digit,
lone high/low surrogate, embedded NUL (`\u0000`), dan raw UTF-8 invalid
(overlong/continuation/terpotong). Kapasitas dilindungi overflow guard di
`sb_reserve`/`json_obj_set`/`json_arr_push`. Regress + soak + MCP interop
(24 cek) tetap hijau. Verdict JSON tidak terpengaruh (parser hanya dipakai
MCP transport).

### Fase 4 — evidence matrix + finding_verdict, 2026-08-02

Sumbu A kini eksplisit — `myc_result.finding` (`myc_finding`: CLEAN /
FINDINGS / INCONCLUSIVE), dihitung murni dari typed gate status di `gate.c`
(`myc_gate_status`): prioritas FINDINGS > INCONCLUSIVE > CLEAN; hanya gate
diminta yang berpengaruh. Dua sumbu (finding + completeness) dipisah dari
verdict legacy (MC_OK/MC_VIOLATION) agar konsumen tak menebak makna.
Laporan teks + JSON memuat `finding:` dan `gate_matrix[]` (daftar id +
status tiap gate = evidence matrix konkret per scope); teks juga menampilkan
blok `evidence:` ringkas. Receipt deterministik tetap sama untuk input yang
sama (`ok_run --run` → `272d7531...`) karena finding diturunkan dari
status gate yang sudah di-hash. Semua regress + soak + corpus + interop
tetap hijau.

### Fase 4 — scope certificate, 2026-08-02

Laporan teks + JSON kini memuat blok `scope:` / `"scope"` = daftar persis
apa yang diperiksa (counts kontrak requires/ensures/total + driver
funcs/cases) sesuai 9.11. Prinsip kejujuran dijaga: hanya metrik yang
BENAR-BENAR diukur yang dimunculkan; kolom function/buffer yang tidak
diproduksi penganalisis token tidak dimunculkan, tidak mengarang angka.
Receipt tetap deterministik (`ok_run --run` → `272d7531...`): scope tidak
masuk ke hash.

### MYC-AUDIT-006, 2026-08-02 (assurance vector / evidence lattice, roadmap 5.7)

Scalar L1–L5 yang menggabungkan bukti orthogonal (compile / static /
runtime / checked / proof / driver / filc) kini dilengkapi **assurance
vector per dimensi** — `myc_assurance_vector` di `myc.h` (7 dimensi
C/S/R/B/P/D/F), dihitung murni dari typed gate status di
`myc_reduce_verdict()` (`myc_build_assurance_vector` di `gate.c`, prioritas
findings > inconclusive > clean > observations > n/a; `MYC_DIM_COUNT`
di-cover `default` agar lolos `-Werror=switch`). Laporan teks memuat baris
kompak `assurance_vector: C1 S0 R1 B0 P0 D0 F0` (0=n/a 1=clean 2=findings
3=inconclusive 4=observations) + legend; JSON memuat
`"assurance_vector":{"C":{"status":"clean"},...}`. Scalar L1–L5 tetap
sebagai legacy, label `[legacy: gunakan assurance_vector + evidence
matrix + finding/completeness]`. Receipt TIDAK berubah (vector turunan
dari gate status yang sudah di-hash). Fixture: `ok_run --run` → `C1 R1`,
`bad_run_oob --run` → `R2`, `ok_checked --checked` → `B1`, plain check →
`C1`; regresi section AUDIT-006 di `test/_regress_run.bat`.

---

## Fitur baru (2026-08-05)

### --json-summary mode

- Flag `--json-summary` pada `myc check` menghasilkan JSON ringkas untuk agent LLM.
- Field: verdict, assurance_vector, receipt_sha256, finding, completeness,
  error, exit_code, duration_ms, lint_observations, ran_* flags, diagnostics,
  gate_matrix, unverified_debt, quorum_status.
- Field yang dihilangkan: stdout_text, stderr_text, fingerprint, gcc_version,
  clang_version, capsule, evidence, dll.
- Default `--json` tetap penuh (backward compatible).

### MCP repair tool

- Tool MCP baru: `repair` — kembalikan patch minimal untuk finding compile
  tertentu (gcc warning).
- Input: `source` (wajib), `finding_code` (opsional).
- Output: JSON dengan `finding`, `applied_verdict`, `confidence`, `patch`,
  `structuredContent` (schema `myc.repair.v1`).
- Template patch untuk: gcc-use-after-free, gcc-free-nonheap-object,
  gcc-null-dereference, gcc-array-bounds, gcc-stringop-overflow.

### Lint why+fix

- Tool MCP `lint` kini menyertakan `why` dan `fix` di text output dan
  `structuredContent`.
- `why`: penjelasan mengapa pola tersebut berisiko.
- `fix`: saran perbaikan berbasis template (bukan AI-generated).
- Fungsi `myc_lint_why()` dan `myc_lint_fix()` di `lint.c` untuk digunakan
  oleh MCP tool dan potensi penggunaan lain.

---

## Fase -1 — Truth Freeze (2026-08-05)

Dokumentasi, baseline, dan kompatibilitas sebelum fitur baru.

- **AGENTS.md split**: aturan stabil di root, sejarah di `docs/audit-history.md`.
- **README cleanup**: hapus fitur yang belum diimplementasi.
- **capabilities.json**: registry MCP tools + CLI flags dengan test sinkronisasi.
- **Baseline benchmark**: 20 task, catat latency, binary size, payload.

---

## Fase 0 — Agent Evidence Protocol (2026-08-05)

Memberi LLM satu paket aksi yang dapat dipercaya.

Commits: `a625fbf..35b65e3` (6 commits).

- **P0-1**: `agent.h` + `agent.c` — `myc_agent_result` struct, build agent result,
  JSON serialization, `select_primary`, witness integration, `next_check`.
- **P0-2**: `report.c` — `myc_report_agent()` untuk `--agent` CLI output.
- **P0-3**: `mcp.c` — MCP tool `agent_check` (structuredContent schema `myc.agent.v2`).
- **P0-4**: `myc.c` — `--agent` CLI flag + `myc_request.agent` field.
- **P0-5**: Fixtures — `agent_ok.c`, `agent_bad.c`.
- **P0-6**: CI wiring — `capabilities.json` updated, `_cap_sync.sh`, `docs/mcp-tools.md`.

---

## Fase 1 — Witness Pipeline (2026-08-06)

Setiap hard finding dapat dipahami dan direplay model.

### Stage 1: Witness struct + isi witness (`64a70d0`)

- **1.1**: `myc_witness` struct di `myc.h` — source, stdin, argv, slice, violation
  kind/msg/line/col, backend.
- **1.2**: Witness dari GCC diagnostics — `ingest_gcc_diagnostics()` di `compile.c`
  mengisi witness via `repair_find_code()`.
- **1.3**: Witness dari sanitizer — `run.c` memetakan ASan/UBSan markers ke
  violation kinds.
- **1.4**: Witness dari Eva/Fil-C/driver — `prove.c`, `filc.c`, `driver.c`.
- `myc_witness_init/free` di `myc.c`; `myc_result_free` diupdate untuk free witness.

### Stage 2: Repro + Minimizer + Slice (`9aeb287`)

- **1.5**: `witness.c` — `myc_witness_write_repro()` menulis `.myc-witness/<kind>/`
  (source.c, stdin.bin, witness.json, replay.sh, replay.bat).
- **1.6**: `myc_witness_minimize_input()` — line-by-line removal skeleton.
- **1.7**: `myc_witness_build_slice()` + `myc_witness_extract_function()`.
- `witness.c` ditambahkan ke PIPELINE di build.sh/build.bat.

### Stage 3: Serialization + Downgrade + Agent wiring (`6bbec72`)

- **1.8**: `gate.c` — `myc_reduce_verdict()` downgrades hard→observation
  bila `!res->witness` (MYC-AUDIT-014: tanpa bukti replayable, finding
  tidak dianggap keras).
- **1.9**: `agent.c` — witness diintegrasikan ke agent output; bila
  `res->witness` ada, gunakan itu; fallback ke capsule.
- **1.10**: Fixtures — `witness_uaf.c`, `witness_oob.c`, `witness_clean.c`.
- **report.c**: serialisasi witness ke JSON (violation, backend, slice, argv).

### Stage 4: pre_state + operation + Replay test (`578fec2`)

- **1.11**: `myc.h` — tambah field `pre_state` dan `operation` ke
  `myc_witness`; kronologi pelanggaran: pre_state → operation → violation.
- `compile.c` — isi pre_state dari note diagnostic, operation dari error.
- `run.c` — isi pre_state/operation dari sanitizer stack trace.
- `prove.c` — isi pre_state/operation dari Eva RTE alarm.
- `filc.c` — isi pre_state/operation dari Fil-C panic.
- `driver.c` — isi pre_state/operation dari driver sanitizer finding.
- `myc.c` — `--write-repro` CLI flag, panggil `myc_witness_write_repro()`.
- `witness.c` — perbaiki `json_serialize` return check (bug: `!= 0` harus
  `== 0` agar witness.json tidak kosong); tambah pre_state/operation ke
  witness.json serialization.
- Replay test Windows: `myc check fixture.c --write-repro` → `.myc-witness/`
  berisi source.c, witness.json, replay.sh, replay.bat; replay.bat
  berhasil compile + run fixture.

Semua 18 source files (termasuk ledger.c): `verdict: OK` (self-dogfooding).

### Fase 2 — Temporal Ledger (2026-08-06, partial)

- **`ledger.c`/`ledger.h`**: persistent append-only ledger di `.myc/ledger.json`.
  Mencatat source_sha256, receipt_sha256, receipt_parent (chain), scenario_hash,
  timestamp, delta_kind, gate_status, verdict, finding.
- `myc_ledger_read()` — parse ledger JSON (strict, via json.c).
- `myc_ledger_write()` — append/update entry berdasarkan source_sha256.
- `myc_ledger_find()` — cari entry terakhir untuk source yang sama.
- `myc_ledger_compute_delta()` — FIXED/NEW/PERSISTENT/CHURN berdasarkan
  perbandingan gate status & verdict.
- `myc_ledger_build_anchor()` — semantic anchor (function + token hash + line).
- `myc_ledger_build_scenario_hash()` — hash deterministik dari request flags.
- `myc.c`: `myc_ledger_integrate()` dipanggil setelah pipeline + quorum +
  require_complete; mengisi `res->receipt_parent`, `res->delta_kind`,
  `res->delta_changed`, `res->ledger_parent_found`.
- `report.c`: ledger fields (receipt_parent, delta_kind, delta_changed)
  ditambahkan ke output teks + JSON.
- Receipt chain: `receipt_parent` menunjuk ke receipt run sebelumnya untuk
  source yang sama. Bila run pertama, receipt_parent kosong (first run).
- Non-blocking: bila `.myc/` tidak dapat ditulis, ledger dilewati dengan
  diagnostic (bukan error).

### Fase 2 — Repair Transaction + Preservation + Sabotage Detection (2026-08-06)

- **`transaction.h`/`transaction.c`**: Repair Transaction state machine
  (BEGIN → PROPOSED → VERIFIED → ACCEPTED | REJECTED_*).
- `--tx-verify` CLI flag + `--finding-id ID` + `--edit-region R`.
- `myc_transaction_init/free/verify/json` — lifecycle transaksi.
- `myc_transaction_new_id()` — generate ID unik via SHA-256 timestamp.
- **Preservation obligations**: finding harus hilang, verdict OK/INCONCLUSIVE,
  completeness tetap COMPLETE, assurance tidak turun.
- **Sabotage detector** (`myc_sabotage_scan`): scan source diff untuk:
  - disable sanitizer (`-fsanitize=`)
  - disable warning (`-Wno-`, `-w`, `--no-warnings`)
  - disable assert (`NDEBUG`, `-DNDEBUG`)
  - add void cast, pragma, early return
  - narrow requires, remove test
  - disable frama-c/filc, change scenario
- `myc_tx_result_name()` + `myc_sabotage_name()` untuk laporan.
- `myc_request` fields: `tx_verify`, `tx_finding_id`, `tx_edit_region`.
- Build: `transaction.c` ditambahkan ke PIPELINE (build.bat + build.sh).
- Semua 19 source files: `verdict: OK` (self-dogfooding).

---
> Terakhir diperbarui: 2026-08-06 (Fase 2: ledger + transaction selesai).
> di atas tidak diubah/dihilangkan — dipindahkan verbatim dari AGENTS.md lama.

---
## Fase 5 — Eksekusi sisa rencana gptsol_deepseek-plan (B4 pertama), 2026-08-08

Eksekusi bertahap 12 ide rencana `gptsol_deepseek-plan.md` yang belum
terpasang (A3, A4, B3, B4, B5, C1..C5, D1, D2, D3, D4). Tiap ide di-commit
terpisah; sinkronisasi `capabilities.json` + docs di tiap tahap.

### (1) B4 — Comments-as-Contracts (DS-08) — `contract.c`

`myc_contract_harvest()` memanen **kandidat kontrak dari komentar biasa**
(bukan `//@`), memakai pola bahasa deterministik (bukan NLP):

- `returns X` / `return X` → ensures `X`;
- `X must not exceed Y` → requires `X <= Y`;
- `X must be <=|<|>=|> Y` → requires `X op Y`;
- `assumes X` / `requires X` (komentar biasa) → requires `X`;
- `precondition:` / `pre:` → requires; `postcondition:` / `post:` → ensures;
- komparasi langsung `X <= Y` dst. (hanya bila SELURUH baris = `X op Y`).

Lifecycle DS-08: **candidate** (pola terdeteksi) → **validated** (ekspresi
C murni via `contract_expr_purity` + `expr_has_operator` + terikat fungsi
via `find_func_binding`) → **promoted** (user menulis `//@`) → **enforced**
(gate). Yang tidak tervalidasi dilaporkan "perlu `//@` syntax".

Guard anti false-positive:
- `expr_has_operator` menolak teks bahasa alami (`number of words`);
- `->` (akses member) bukan operator kontrak;
- komparasi langsung divalidasi dengan rekonstruksi "X op Y" == seluruh
  baris agar `n must be <= 64` tidak salah tangkap jadi `be <= 64`;
- NON-blocking: verdict tidak pernah turun karenanya.

Field hasil: `harvest_candidates` / `harvest_validated` / `harvest_unbound`
/ `harvest_report` (arena). Output teks + JSON + `--json-summary`;
`cache.c` (SOL-18) menyimpan 3 counter agar cache-hit tetap jujur.

Fixture: `test/fixtures/harvest_contracts.c` (6 kandidat: 5 validated,
1 prose non-C ditolak). Regresi di `_ci_linux.sh` (5f) + `_regress_run.bat`.

Semua source: `verdict: OK` (self-dogfooding); build Windows + POSIX bersih.

### (2) B3 — LLM Error Taxonomy + coaching transcript (DS-07) — `taxonomy.c/.h`

Sumbu kedua klasifikasi finding: kelas **kognitif** (cara model biasanya
salah), bukan hanya semantik C. `myc_taxonomy_classify()` (rule-based,
substring case-insensitive, deterministik) memetakan pesan diagnostic ke
`HALLUCINATED_API / MISSING_GUARD / OFF_BY_ONE / UB_ASSUMPTION /
TYPE_CONFUSION / IGNORED_RETURN / WRONG_CONSTANT / CHURN`.

`myc_coach_build()` menyusun **coaching transcript** (5-10 baris) yang
ditulis untuk dibaca model: prioritas per kelas + strategi perbaikan
(`myc_taxonomy_strategy`) + instruksi anti-churn. Sumber: diagnostics
terstruktur (gcc/lint/negative/contract) + witness (hard finding) + delta
ledger (churn). Output teks + JSON (`"coaching":{items,report}`) +
`--json-summary` (`"coaching":[{class,line}]`). NON-blocking observasi.

Dedup + urutan stabil (prioritas kelas, lalu line); deterministik.
`myc_coach_build` dipanggil di `myc_run` (jalur miss DAN cache-hit, di
samping `myc_quorum_analysis`); tipe (`myc_taxonomy_class`,
`myc_coaching_item`) di `myc.h`; `taxonomy.c` masuk PIPELINE
(build.sh/build.bat/_audit018.sh/stress_threads) + self-dogfooding list.

Regresi di `_ci_linux.sh` (5g) + `_regress_run.bat`: bad_realloc → 2 item
`missing_guard` + strategi; ok_hello tanpa coaching; verdict tidak berubah.

### (3) D4 — System-Prompt Contract Generator (DS-15) — `prompt.c/.h`, `myc prompt`

`myc prompt <file.c>` merender **system-prompt snippet deterministik** (bukan
AI) untuk ditempel harness LLM SEBELUM model menulis kode (P4: pencegahan
> koreksi). Isi:

- fakta target host (`myc_assume_fetch_facts`: char signed/unsigned, lebar
  int/ptr, endianness, CHAR_BIT, STDC_VERSION) — dengan sumber "fakta gcc
  host"; bila gcc absen dikatakan TIDAK terdeteksi (jangan berasumsi);
- panggilan fungsi denylist yang TERDETEKSI di file ini (scan token + re-use
  `myc_policy_deny_function`) — "non-blocking warning di myc";
- konvensi pemeriksaan alokasi via `myc_negative_space` (9.8): "N/M
  callsite memeriksa hasil";
- idiom `MYC_BUF`/`MYC_AT` bila dipakai;
- aturan anti-churn + perintah verifikasi `myc check <file.c> --delta` +
  aturan klaim (hanya dari gate matrix).

Subcommand baru di `myc.c` (`cmd_prompt`), ingress via `myc_source_load`
(cap + NUL policy). `prompt.c` masuk PIPELINE + self-dogfooding. Regresi
`_ci_linux.sh` (5h) + `_regress_run.bat`: fakta host, denylist
(bad_system), konvensi alokasi (negative_dev 4/5), anti-churn.

### (4) A3 — Small-Domain Exhaustive Proof (DS-03) — `--exhaustive` — `driver.c`

`myc_exhaustive_gate()` (di `driver.c`, reuse parser kontrak + infra
build/run dari driver) meng-enumerasi **seluruh domain deklarasi** fungsi
ber-kontrak `//@ requires n >= LO && n <= HI` dan men-assert semua
`//@ ensures` pada setiap titik — **P1 EXHAUSTIVE** (bukti riil untuk
domain yang dideklarasikan, bukan sampel tepi).

- Odometer kartesian per parameter integer (pointer bukan dimensi);
  budget: `EXH_MAX_PER_PARAM 1024` / dimensi, `EXH_MAX_POINTS 1e6`
  (produk). Dimensi tanpa rentang penuh / terlalu lebar / produk berlebih
  → gate di-skip dengan **alasan akurat** (pesan menyebut variabel & batas).
- Harness ASan/UBSan (`-fsanitize=address,undefined`, `-O0`) di-compile
  clang + dijalankan per titik; stdout membawa marker `EXH run=N skip=M`;
  runtime violasi / assert ensures → **DRIVER_VIOLATION** + counterexample.
- Klaim dijaga ketat: output selalu menulis "bukan bukti di luar domain
  dideklarasikan"; `exhaustive_domain_hash` = sha256 dari spec domain
  (per fungsi), masuk receipt.
- **DS-03 Domain Firewall**: state `.myc/exhaustive.json` mencatat spec
  domain per fungsi antar run. Bila domain **dipersempit** (strict subset
  dari run sebelumnya) → `SCOPE_LAUNDERING` dilaporkan (proof laundering)
  dan `exhaustive_laundering=1` — bukti domain sempit tidak diam-diam
  menggantikan bukti domain lebar. Verdict tetap berbasis gate.

Cache (SOL-18): counter exhaustive (funcs/points/cases/skipped/laundering)
ikut disimpan. `capabilities.json` + `docs/capabilities.md` ditambah gate
`exhaustive` (dimensi P). Fixture: `ok_exhaustive.c` (65 titik P1),
`bad_exhaustive.c` (counterexample), `exhaustive_wide.c` (domain 65536
→ ditolak), `exhaustive_narrow.c` (SCOPE_LAUNDERING bila run setelah
ok_exhaustive). Regresi `_ci_linux.sh` (5g) + `_regress_run.bat`.

### (5) A4 — Differential Oracle Pair (DS-04) — `myc compare` — `driver.c`

Subcommand `myc compare <ref.c> <new.c> [func...]` menjawab pertanyaan
paling sering model: "apakah refactor-mu mempertahankan perilaku?"
`myc_compare_gate()` (di `driver.c`):

- Scan fungsi ber-kontrak di KEDUA file, pasangkan yang nama-nya sama
  (opsional filter nama via argumen CLI).
- Bangkitkan **baterai input bersama** dari UNION kontrak kedua versi:
  kandidat tepi kedua versi + boundary portfolio (0, 1, -1, INT_MAX,
  INT_MIN) + 16 nilai PRNG deterministik (xorshift32 seed tetap) per
  parameter dalam rentang gabungan; produk kartesian dibatasi
  `CMP_MAX_CASES 4096` per fungsi. Baterai IDENTIK untuk kedua versi
  (case table literal di-embed ke harness).
- Harness per versi (rename main, clang ASan/UBSan -O0) memanggil fungsi
  per kasus, print `CASE <f>_<i> ret=... errno=...`; escrow DS-04 ikut
  dibandingkan: **return value + errno + output digest (sha256) + exit
  code + ABI signature + domain hash**.
- Semua kasus identik -> verdict **behavior-preserving (P1 DIFF)**
  (exit 0). Ada kasus beda / exit beda / ABI berubah / domain berubah
  -> **unexpected_change (DS-04)** + daftar kasus divergen (maks 20,
  `compare_delta`, arena). Fungsi yang tak bisa dibandingkan (tidak ada
  di file lain / tanpa param integer) dicatat `unobserved` -- jujur,
  bukan kesunyian.

`capabilities.json` + `docs/capabilities.md` ditambah gate `compare`
(dimensi P). Fixture: `ref_crc16.c` (baseline), `new_crc16_same.c`
(refactor perilaku-sama -> P1 DIFF), `new_crc16_div.c` (polinomial beda
-> 53/64 divergen). Regresi `_ci_linux.sh` (5i) + `_regress_run.bat`.

### (6) C2 — Stack Budget Analyzer (DS-10) — `--stack` — `stack.c/.h`

Gate `myc_stack_gate()` (modul baru `stack.c`) menjawab "berapa stack
terburuk kode ini?" untuk target embedded: kematian embedded #1 biasanya
stack overflow diam-diam, bukan bug logika.

- Tulis source ke dir temp, jalankan `gcc -c -O2 -fstack-usage -Wvla`
  (argv eksplisit, cwd temp sehingga `.su` deterministik).
- Parse `.su` (format `file:LINE:COL:func<TAB>bytes<TAB>align`, defensif
  terhadap variasi gcc) -> frame per fungsi.
- Parse call graph dari source (definisi top-level + panggilan ident(...)
  di body, mirip scanner driver), DFS worst-path dari root `main`
  (fallback `_start` / fungsi tak-dipanggil) dengan cycle detection.
- Deteksi **rekursi** (cycle = stack tak terbatas), **alloca** (substring),
  **VLA** (warning gcc -Wvla), **unknown calls** (fungsi tanpa frame .su
  = komponen eksternal/inline).
- Bandingkan worst dengan `--stack-budget N` (default 4096 B). Report
  selalu mencantumkan **"static worst-case != dynamic worst-case"**
  (claim compiler; DS-10: static estimate vs interrupt/unbounded).
- NON-blocking observasi (MYC_GATE_COMPLETED_OBSERVATIONS): verdict
  tidak pernah berubah karena stack (trust rules #1).

`capabilities.json` + `docs/capabilities.md` ditambah gate `stack`
(dimensi R). Fixture `stack_recursive.c` (rekursi). Regresi
`_ci_linux.sh` (5j) + `_regress_run.bat`: worst path, over-budget,
rekursi, non-blocking.

### (7) D1 — Fuzz Gate fuzz-lite (DS-13) — `--fuzz` — `driver.c`

`myc_fuzz_gate()` (di `driver.c`, reuse mesin driver) menjawab "parser
ini aman untuk input tak terduga?" tanpa dependensi libFuzzer:

- Scan fungsi ber-kontrak; untuk tiap fungsi bangkitkan harness dengan
  **PRNG xorshift32 deterministik (seed tetap, `--fuzz-seed`)** dan
  **loop terikat (`--fuzz-iters`, default 20000)**.
- Nilai parameter dihasilkan DALAM rentang kontrak `requires` — input
  selalu *valid* menurut domain yang dideklarasikan (keunggulan atas
  fuzzer buta yang membuang-buang input invalid). Guard ekspresi requires
  tetap diterapkan; kasus ditolak dihitung `skipped`.
- Build clang ASan/UBSan (-O1) + run terkendali (env sanitizer log_path
  non-spoofable). Crash / report sanitizer -> **DRIVER_VIOLATION**
  (bukti, hard) dengan pesan "crash di <func> (seed N) -- input
  reproduksibel" (masuk B1 repro: seed cukup untuk replay).
- Bersih dengan >= 1 kasus -> gate COMPLETED_CLEAN; 0 kasus (guard terlalu
  ketat) -> NOT_APPLICABLE; clang hilang -> UNAVAILABLE (gap terlihat).

`capabilities.json` + `docs/capabilities.md` ditambah gate `fuzz`
(dimensi R). Fixture `ok_fuzz.c` (aman), `bad_fuzz.c` (OOB idx 16..31 ->
crash). Regresi `_ci_linux.sh` (5k) + `_regress_run.bat`.

### (8) B5 — Mutation-Audited Verification (DS-09) — `--mutate-audit` — `mutate.c/.h`

Verifier yang mengaudit dirinya sendiri (membalik arah panah: alat bukan
hanya hakim, tapi murid yang menguji gurunya). `myc_mutate_gate()`
(modul baru `mutate.c`):

- Scan fungsi top-level (nama + body range); kumpulkan mutasi dari set
  pola error LLM yang deterministik: off-by-one (`<=`->`<`, `>=`->`>`),
  guard lemah (`&&`->`||`), komparasi dibalik (`<`->`>`, `==`->`!=`),
  cek batas dilemahkan (`>= `->`> `). Satu mutasi per lokasi (dedup),
  maks `--mutate-max N` (default 8) untuk membatasi biaya re-build.
- Untuk tiap mutan: jalankan ulang pipeline (compile -Werror + run ASan)
  via `myc_pipeline` (reuse penuh). Mutan verdict != OK = tertangkap
  (gate yang menangkap dicatat dari evidence); verdict OK = **GAP**
  (kelas bug tsb tak terlihat konfigurasi verifikasi) + saran.
- Mutan ekuivalen (mutasi tak mengubah source) di-skip.
- Output: tabel mutan + `verification coverage: N/M kelas mutan
  terlihat`. **NON-blocking observasi** — GAP tidak pernah menurunkan
  verdict program (mengukur kualitas verifikasi, bukan kode).

Membangun DS-09 Canary Swarm: tiap backend bisa diuji dengan mutan
kelasnya (heap OOB -> `--run`, contract violation -> `--exhaustive`, dst).
`capabilities.json` + `docs/capabilities.md` ditambah gate `mutate`.
Fixture `mutate_target.c` (guard ganda; main memanggil rentang luas ->
3 mutan tertangkap ASan, coverage 3/3). Regresi `_ci_linux.sh` (5l) +
`_regress_run.bat`.

### (9) C1 — Freestanding Mode (--freestanding) — `compile.c`

Mode C-tanpa-OS (firmware). `--freestanding` mengubah ARTI temuan:

- Compile memakai `-ffreestanding -fno-builtin` (masuk fingerprint + flag
  matrix) — kompilasi gagal di mode ini tetap HARD (compile error).
- **Hosted-API trap** (`scan_hosted_api` di `compile.c`): scan source
  (luar komentar/string) untuk panggilan API libc hosted yang TIDAK
  tersedia di bare metal: stdio console (printf/fprintf/puts/getchar/
  scanf), file I/O (fopen/fclose/fread/fwrite/fseek/...), heap dinamis
  (malloc/calloc/realloc/free/strdup/alloca), proses/exit (exit/abort/
  atexit/system/getenv), konversi string (atoi/strtol/...), time
  (time/clock/...). Tiap hit = diagnostic OBSERVATION NON-blocking
  (printf = bug firmware, bukan warning desktop).
- `freestanding_api_hits` + report "freestanding hygiene"; verdict tidak
  pernah berubah karena trap (trust rules #1).

Bonus perbaikan: `merge_args` di compile.c kini skip list NULL (bug
segfault bila daftar flag opsional tak diaktifkan bersama `--freestanding`).
`capabilities.json` + `docs/capabilities.md` ditambah gate `freestanding`.
Fixture `blinky_bad.c` (printf/malloc/free -> trap), `blinky_clean.c`
(hygiene bersih). Regresi `_ci_linux.sh` (5m) + `_regress_run.bat`.

### (10) C3 — MMIO/volatile/alignment traps (DS-11) — `lint.c`

Keluarga heuristik bare-metal (mode `--freestanding`) yang menangkap kelas
kesalahan "kode benar di x86, salah di target embedded" — register tanpa
`volatile` = infinite loop yang 'benar' bagi optimizer. Perluas `lint.c`
(param baru `embedded`; rule NON-blocking, confidence-scored, diaktifkan
hanya di mode freestanding):

1. **MMIO deref alamat absolut tanpa volatile** (SUSPICIOUS): pola
   `*(uint32_t *)0x40001000` atau `*(uint32_t *)REG` di mana REG di-resolve
   via `#define REG 0x....` (>= 7 digit hex = alamat periferal).
2. **Polling loop tanpa volatile** (SUSPICIOUS): `while (kondisi);` body
   kosong, kondisi tanpa kata `volatile` DAN tanpa pemanggilan fungsi
   (accessor `READ_REG(...)` dianggap aman — volatile tersembunyi di
   macro).
3. **Struct `__attribute__((packed))` + field multi-byte** (OBSERVATION):
   akses unaligned/tear di ARM.
4. **Cast `uint8_t*` -> tipe multi-byte** (OBSERVATION): `(uint32_t *)`
   yang berdekatan (<= 200 char) dengan cast `uint8_t *` = alignment tak
   dijamin.
5. **Variabel bersama ISR tanpa volatile/atomic** (OBSERVATION): ada
   fungsi mirip ISR (`*_isr`/`*_irq`/`interrupt`) tapi tidak ada token
   `volatile`/`_Atomic` di source = data race ISR+main.

Diagnostic baru memakai `add_diag_bm` (increment `lint_embedded_hits`);
report teks "bare-metal (C3/DS-11): N observasi", JSON
`lint_embedded_hits`. Verdict TIDAK pernah turun (trust rules #1);
fixture `mmio_bad.c` (5 pola) vs `mmio_clean.c` (idiom volatile/READ_REG/
memcpy) membuktikan deteksi tanpa false-positive; regresi di
`_ci_linux.sh` 5n + `_regress_run.bat`.

### (11) C5 — Scenario Packs + D3 auto budget (DS-12) — `scenario.c/.h`

"Resep verifikasi per domain" dari profil JSON (bukan hardcode logika),
modul baru `scenario.c`:

- **Profil = data JSON** (skema divalidasi parser ketat `json.c`):
  `cli-daily` (run+analyzer), `library` (driver+exhaustive), `parser`
  (fuzz+run), `firmware` (freestanding+stack+divergence), `auto` (D3).
  User dapat menimpa/menambah via `scenarios.json` di cwd atau
  `--scenario-file <path>`; item user menimpa bawaan dengan nama sama.
- **Satu perintah**: `myc check boot.c --scenario stm32-baremetal`
  mengaktifkan seluruh resep gate sekaligus; `myc scenario list` /
  `myc scenario info <name>`. Skema: `{version, scenarios[{name, desc,
  flags[], env{}}]}`; flags tak dikenal diabaikan (data, non-blocking).
- **D3 auto budget**: `--scenario auto` menebak resep TERKECIL yang
  cukup dari struktur source (pola firmware: volatile/ISR/packed;
  kontrak `//@`; ada `main`) dan melaporkan alasan ("terdeteksi kontrak
  //@...") — assurance tertinggi yang terjangkau tanpa gate terbuang.
- **DS-12 env contract**: scenario mendefinisikan DUNIA program
  (stack_budget, no_heap, no_recursion) — tercatat di scenario_report;
  enforcement lewat gate yang diaktifkan (freestanding trap heap, stack
  gate rekursi). Verdict TIDAK pernah berubah karena scenario.
- Report teks "scenario (C5): <name>", JSON `scenario.applied/auto/name/
  report`. Nama tak dikenal = fail-fast. Bug ditemukan saat implementasi:
  `json_parse` return 1=sukses (bukan 0), dan `json_sb_escape` di
  report.c menambah quotes sendiri (jangan tulis `"` pembuka).
  Fixture `scen_parser.c`; regresi `_ci_linux.sh` 5o + `_regress_run.bat`.

### (12) C4 — Toolchain Matrix bare metal (--matrix) — `matrix.c/.h`

Perluasan A2 (divergence) ke MATRIKS TARGET: "char di ARM tidak sama
 dengan char di x86". Modul baru `matrix.c`:

- Untuk tiap cross-compiler yang TERPASANG (`arm-none-eabi-gcc`,
  `riscv64/32-unknown-elf-gcc`):
  (a) **macro dump target** via `-dM -E` (reuse engine A1
      `myc_assume_fetch_facts`): `__CHAR_UNSIGNED__`, `__SIZEOF_POINTER__`,
      endianness;
  (b) **cross-compile** `-c -O2 -std=c11` (temp dir, argv eksplisit)
      -> built + set warning;
  (c) **delta vs host** -> portability matrix: setiap fakta yang berubah
      dicatat "TARUHAN BERUBAH: char signed di host, UNSIGNED di ARM
      (idiom `c < 0` mati)" dst.
- **NON-blocking penuh** (kejujuran P5): cross-compiler absen = sel
  di-skip + catatan "target lain TIDAK diuji (host-only)" — menutup
  celah "lintasan yang tidak pernah diuji" dengan pengakuan, bukan
  kesunyian. Verdict TIDAK pernah turun karena matrix (status
  COMPLETED_OBSERVATIONS).
- Report teks "matrix (C4): N target, M delta", JSON
  `matrix.targets/available/deltas/report` + summary. Flag `--matrix`;
  gate id MYC_GATE_MATRIX. Validasi di Windows: jalur host-only
  (deterministik) + jalur target-aktif via stub `arm-none-eabi-gcc.exe`
  (sel lengkap: facts+compile; delta 0 yang benar utk fakta identik).
  Delta nyata (char/ptr berubah) tervalidasi secara logika; butuh
  cross-compiler asli di CI Linux utk e2e penuh. Regresi `_ci_linux.sh`
  5p + `_regress_run.bat`.

### (13) Fase 6 — Canary Swarm (Self-Challenge) — `canary.c/.h`

"Setiap klaim backend harus dibuktikan hidup". Modul baru `canary.c`:

- **Tabel canary 11 entri / 9 backend** (self-contained, ingress MEMORY):
  compile (bersih + syntax-error), analyzer (null-deref interprocedural
  `poke(q=0)`), run (heap-buffer-overflow write `p[4]`), driver (OOB pada
  tepi domain kontrak `requires n <= 4`), exhaustive (counterexample +
  P1 EXHAUSTIVE), fuzz (div-by-zero crash dalam domain kontrak), mutate
  (3 mutan tertangkap, 0 GAP), stack (cycle rekursi), lint (bersih tanpa
  false-positive).
- **`myc canary list | run [backend]`**: menjalankan canary via pipeline
  nyata (`myc_run`), membandingkan verdict + text evidence (scan
  `evidence[]` + report arena per gate: exhaustive/stack/fuzz/mutate).
  Canary GAGAL = backend TIDAK terpercaya (klaim bersihnya diragukan)
  -- menutup celah "backend rusak diam-diam memberi verdict OK palsu".
- **Regresi CI**: `_ci_linux.sh` 6a (11/11 PASS + registry) dan
  `_regress_run.bat` (Fase 6 canary). Self-dogfood OK.
- Bug yang ditemukan saat develop: loop scan array ber-henti di NULL
  pertama (`for(;scan[i];)`) -- field report per gate yang tak dijalankan
  NULL, sehingga field berikutnya tak diperiksa; diperbaiki dengan
  iterasi 4 elemen eksplisit.

### (14) Fase 6 — Test-Quality Audit — `testaudit.c/.h`

"Apakah corpus test benar-benar menutupi hazard class yang menjadi
 tanggung jawab myc?". Subcommand `myc audit-tests`:

- Memindai `test/`, `test/fixtures/`, `tests/` (kedalaman 1); tiap *.c
  diklasifikasi bad/ok (nama + keyword isi) dan dihitung kontrak `//@`.
- **Cakupan hazard class** (7): spatial, temporal, integer, runtime,
  proof, boundary, capability -- keyword dicocokkan pada nama + isi.
- **Cakupan backend** (10): run, driver, exhaustive, fuzz, mutate,
  stack, prove, checked, filc, matrix.
- Gap = hazard class / backend TANPA fixture, dilaporkan eksplisit
  (NON-blocking observasi). Baseline: 7/7 hazard + 10/10 backend.
- Regresi CI: `_ci_linux.sh` 6b + `_regress_run.bat`. Self-dogfood OK.

### (15) Fase 6 — Environment Perturbation (--perturb) — `perturb.c/.h`

"Hasil verifikasi tidak boleh bergantung mesin". Flag `--perturb`:

- Setelah run utama, jalankan ulang binary verification dengan 4 env
  diubah: TZ=UTC+14, LC_ALL=tr_TR.UTF-8, PATH=/nonexistent, HOME+TERM
  (base env RUN_ENV dipertahankan; override via proc env array).
- Bandingkan stdout (sha256) + exit code + deteksi sanitizer vs
  baseline. Semua sama = DETERMINISTIK; ada beda = ENV-SENSITIVE
  dengan daftar env penyebab (observasi NON-blocking, verdict tetap).
- Fixture `pert_tz.c` (localtime/TZ-sensitive) diverifikasi terdeteksi
  ENV-SENSITIVE; ok_hello tetap DETERMINISTIK. Regresi CI 6c.
  Self-dogfood OK.

### (16) Fase 6 — Concurrency Schedule / Lock-Order Probe — `concur.c/.h`

`--thread-probe` (gate MYC_GATE_CONCUR):

- **Lock-order statis**: parse source (strip komentar), lacak brace depth
  per karakter untuk membagi region fungsi (menangani fungsi satu-baris),
  kumpulkan urutan mutex yang di-lock per region (pthread_mutex_lock /
  mtx_lock / EnterCriticalSection, multi-lock per baris), lalu deteksi
  pasangan urutan TERBALIK antar fungsi = LOCK-ORDER INVERSION
  (potensi deadlock). Heuristik teks ber-confidence, NON-blocking.
- **TSan runtime** (best-effort): bila source memakai thread dan clang
  mendukung -fsanitize=thread, build+run -> data race terdeteksi;
  platform tanpa TSan (Windows) = catatan eksplisit, bukan kesunyian.
- Fixture `con_inv.c` (f1 ma->mb vs f2 mb->ma) diverifikasi terdeteksi
  INVERSION; verdict tetap OK (observasi). Regresi CI 6d. Self-dogfood
  OK. Bug yang ditemukan saat develop: (a) region detection pakai net
  brace per baris -> fungsi satu-baris tak terbuka; (b) hanya satu lock
  per baris yang diambil; (c) nama fungsi diambil dari '(' terakhir.

### (17) Fase 6 — Counterexample Seeds -> Regression Corpus — `regress.c/.h`

"Counterexample seeds menjadi regression otomatis" + corpus memory:

- Setiap counterexample yang DITEMUKAN auto-disimpan ke
  `.myc/regression/<kind>_<sha8>.c` + index (idempoten per sha8):
  fuzz crash (dengan seed PRNG agar input reproduksibel), exhaustive
  counterexample, driver violation. NON-blocking (gagal menulis =
  diabaikan senyap).
- `myc regression list` = isi corpus; `myc regression run` = replay
  semua seed (backstop deteksi: toolchain berhenti menangkap crash =
  terlihat); `myc regression run <file.c>` = replay semua seed-INPUT
  pada source SAAT INI: masih violation = bug belum diperbaiki, OK =
  RESOLVED (fix tidak bisa regress diam-diam).
- Fixture `fuzz_div0.c` (buggy) + `fuzz_div0_fixed.c` (fixed): CI
  memverifikasi seed tersimpan dan replay fixed -> RESOLVED.
  Self-dogfood OK.

### (18) Fase 6 — Temuan Bug Nyata dari CI Linux (Self-Challenge bekerja)

Tiga bug nyata ditemukan setelah CI Linux pertama kali gagal — justru
bukti bahwa audit backend Fase 6 menangkap bug myc sendiri:

- **`concur.c` — `strtok_r` POSIX (fix `ea24ebd`).** `strtok_r`
  disembunyikan glibc di bawah `-std=c11` (butuh `_GNU_SOURCE`); MinGW
  memilikinya sehingga lolos di Windows dan baru terlihat saat
  `myc check concur.c` dijalankan di Linux. Diganti dengan split manual
  (tidak butuh fungsi POSIX). Pelajaran: verifikasi `-std=c11` murni di
  glibc untuk kode yang diklaim portabel, bukan hanya di MinGW.
- **`myc.c` — leak `entry.timestamp` (fix `ea24ebd`).** LeakSanitizer di
  `_audit018.sh` (audit_lampiran fp-long ASan) mendeteksi 64 B bocor per
  pemanggilan `myc_run`: `entry.timestamp` dari `myc_ledger_timestamp`
  (malloc 32 B) di-isi ke entri ledger namun tidak pernah di-free setelah
  `myc_ledger_write`. Backend audit yang dibangun Fase 6-lah yang
  menangkap leak di pipeline myc sendiri — self-challenge bekerja.
- **`proc.c` — race pipe drain T1 (fix `120fef1`).** Di runner sibuk,
  `stderr_total=991232 = 1 MiB - 8192` (persis satu buffer read hilang).
  Akar masalah: jalur POSIX menutup `out_pipe[0]`/`err_pipe[0]`
  SEBELUM `pthread_join` drain thread; drain thread yang sedang `read()`
  mendapat `EBADF` dini dan berhenti, sehingga byte terakhir di pipe
  buffer hilang (race — makin sering saat runner sibuk; stdout lolos
  karena ditulis lebih dulu). Child sudah exit sehingga EOF alami sudah
  tersedia — fix: join drain thread dulu, baru tutup read side.
  Verifikasi: stres 6x di WSL, `_audit018.sh` 65 OK, `_ci_linux.sh`
  PASS=107 FAIL=0, Windows proc_flood 3x 0 FAIL.

Status akhir Fase 6: 7/7 task selesai, CI GitHub hijau (Linux + Windows)
pada `120fef1`, seluruh source self-dogfood OK (38 source + 3 dogfood).

### (19) Fase -1 — Baseline Benchmark & Truth Freeze — `bench/` + `docs/result-schema.md`

Menyelesaikan 3 task Fase -1 yang tersisa (SOL-24):

- **20 task benchmark**: `bench/manifest.json` diperluas 10 -> 20 task.
  Hard detection (14): spatial stack-oob + static-oob, temporal UAF +
  witness-oob, integer overflow, checked (direct/oob/type), memory
  malloc-return, driver-oob, contract-pre, syntax, fuzz-lite, exhaustive,
  divergence. Observasi NON-blocking (6) dengan `obs_pattern`: lint intptr,
  negative-space, stack recursion, env perturb (ENV-SENSITIVE),
  thread-probe (LOCK-ORDER INVERSION).
- **`bench/run_bench.sh` v2**: dukung `obs_pattern`, ukur default latency +
  full-suite latency + agent payload, tulis report deterministik ke
  `bench/reports/baseline-latest.txt`. Selalu `--no-cache` (cache replay
  memotong detail observasi). Portabel: `./myc` atau `./myc.exe`; strip
  CRLF (file CRLF di Windows); `LAST_MS` via file temp (command-subst =
  subshell). Ekspektasi t08 dikoreksi: `INCONCLUSIVE` -> `RUNTIME_VIOLATION`.
- **Baseline pertama**: 20/20 bad terdeteksi (detection 100%), 20/20 good
  bersih (false-positive 0%), binary 517.885 B, default latency ~170 ms,
  full-suite ~36 s, agent payload ~3.3 KB.
- **Truth freeze**: `docs/result-schema.md` membekukan `myc.result.v1`
  (`--json-summary`) + `myc.agent.v2` (`--agent`): field tidak dihapus
  tanpa bump versi, verdict enum hanya bertambah di akhir, determinisme
  modulo `duration_ms`/`receipt_sha256`. Regresi CI: `_ci_linux.sh` 7b +
  `_regress_run.bat`. Plan checkbox Fase -1 3/3 -> [x].

### (20) Fase 0 — Golden Schema + Malformed-Input Tests — `test/_schema_golden.sh`

Menutup task Fase 0 yang tersisa (golden schema + malformed-input):

- **Golden schema myc.result.v1**: jalankan `--json-summary` pada 4 kelas
  verdict (OK / RUNTIME_VIOLATION / COMPILE_ERROR / DRIVER_VIOLATION),
  validasi JSON parse + 33 field wajib + tipe (`receipt_sha256` string,
  `duration_ms` int) + verdict hanya dari enum beku (6 nilai).
- **Malformed input**: 6 corpus korup (empty, garbage, unclosed comment/
  string, deep nesting, recursive) -> JSON TETAP valid, tidak crash;
  flag tak dikenal / file tak ada -> exit != 0.
- **Golden schema myc.agent.v2**: `--agent` -> schema tepat, verdict
  ordinal 0..5, `next_check` (satu aksi utama) + receipt/source hash ada.
- Portabel (myc/myc.exe; python3 opsional dengan fallback grep
  struktural). Regresi CI: `_ci_linux.sh` 7a + `_regress_run.bat`.
  PASS=13 FAIL=0 di Windows dan WSL.

### (21) Fase 2 — Contract/domain Delta — `myc contract-delta` (contract.c/.h)

Menutup task Fase 2 yang tersisa (contract/domain delta):

- Bandingkan kontrak //@ requires/ensures dua versi source (reuse
  myc_contract_list). Klasifikasi 4 kelas: CLEAN (sama), NARROWED
  (requires bertambah = domain panggilan MENYEMPIT = scope-laundering),
  WEAKENED (ensures berkurang = kontrak melemah), CHANGED (perubahan
  lain). Exit code: 1 untuk NARROWED/WEAKENED (preservation dilanggar).
- CLI: `myc contract-delta <before.c> <after.c>` — detail per klausa
  (+/- requires/ensures). Dapat dipakai sebagai gate di repair
  transaction: patch yang "menghilangkan bug" dengan mempersempit domain
  ditolak (DS-08 lifecycle: narrowing = laundering).
- Fixture contract_wide.c (baseline) + contract_narrow.c (patch): CI
  memverifikasi NARROWED terdeteksi + exit=1. Self-dogfood OK, -Werror
  OK, regresi CI Linux 6f + Windows.

### (22) Fase 8 — Release Gate Definition-of-Done — test/_no_source_leak.sh + test/_anti_false_ok.sh

Menutup checklist Fase 8 (Lampiran Sol A, 13 item Definition of Done):

- **no-source-leak test** (BARU, test/_no_source_leak.sh): fixture
  leak_probe.c memuat sentinel unik MYC_LEAK_SENTINEL_9137 yang TIDAK
  boleh muncul verbatim di --agent / --json-summary / report teks.
  Verifikasi: sentinel 0 kemunculan di 3 saluran + source_sha256
  deterministik lintas run. PASS=4.
- **anti-false-OK guard POSIX** (BARU, test/_anti_false_ok.sh): mirror
  portabel _anti_false_ok.bat (MYC-AUDIT-031) untuk CI Linux/WSL —
  fixture negatif (syntax/oob/realloc/checked/run-oob) WAJIB tetap
  verdict negatif; regresi kelas false-OK tertangkap. PASS=7.
- **Sudah terpenuhi sebelumnya (dicentang di plan)**: schema
  terdokumentasi (result-schema.md), deterministic (benchmark
  --no-cache), malformed input test (_schema_golden.sh), OOM test
  (audit018 oom_alloc/oom_guards), Windows + Linux (CI dual), payload
  cap (agent.c MYC_AGENT_PAYLOAD_CAP), backward compatibility (schema
  beku), replay fixture (regression corpus), benchmark usefulness
  (run_bench.sh), docs registry sync (_cap_sync.sh), self-dogfooding.
- Regresi CI: _ci_linux.sh 8a+8b + _regress_run.bat (no-source-leak via
  bash). Plan: Fase 8 13/13, total 70/81.

### (23) Fase 5 — Relational Contracts — `myc_contract_relational` (contract.c/.h)

Menutup task Fase 5 "Relational contracts" (exit criteria: round-trip
fixture diuji otomatis):

- **Klasifikasi klausa kontrak** (non-blocking observasi): tiap klausa
  //@ requires/ensures yang sudah di-scan diklasifikasi UNARY (1 variabel
  vs konstanta, mis. `n >= 0`) vs RELATIONAL (>= 2 variabel, mis.
  `a <= b`, `r == a + b`, `a >= 0 && b >= 0`), dengan deteksi operator
  order (< <= > >=), equality (== !=), aritmetika (+ - * / %), logika
  (&& || !).
- **Binding check**: identifier di luar parameter fungsi (diekstrak dari
  signature via rel_extract_params, cache per fungsi) dan di luar alias
  return (r/ret/result/res/\result) ditandai UNBOUND -- observasi yang
  menangkap typo / global tak terdeklarasi dalam kontrak. Member access
  (p->size / p -> size / p.size), cast type, literal, pemanggilan fungsi
  TIDAK dihitung variabel (anti false-positive).
- **Output**: res->rel_* (analyzed/relations/unary/unbound + per-klausa
  + report arena) di teks, JSON penuh, JSON summary (`relational`
  additive di myc.result.v1, tercatat di docs/result-schema.md).
  Replay cache menyimpan 4 counts (rel_a/n/u/b) identik dengan pola
  harvest (report/clauses tidak di-cache).
- **Round-trip fixture** `test/fixtures/relational_contracts.c` (6 klausa:
  1 unary, 5 relational, 1 unbound `mystery`): klasifikasi deterministik
  lintas run + `contract-delta file file` = CLEAN, diuji di CI Linux 6g
  (5 cek) dan Windows. Self-dogfood OK, -Werror OK.

### (24) Fase 5 — State-Machine Ghosting — `state.c`/`state.h` (SOL-13)

Menutup task Fase 5 "State-machine ghosting" (exit criteria: sequence
witness state machine minimal tersedia):

- **Ghost machine dari //@ sm** (scanner teks deterministik):
  `//@ sm state IDLE initial;`, `//@ sm state ERROR final;`,
  `//@ sm event START;`, `//@ sm trans IDLE --START--> BUSY;` (juga
  `-E->` dan spasi di sekitar arrow). NON-blocking observasi.
- **Analisis** (state.c, myc_sm_scan): SINK (tanpa transisi keluar,
  bukan final), UNREACHABLE (tak ada transisi masuk, bukan initial),
  NO_RECOVERY (tak ada jalur kembali ke initial = perangkap satu arah),
  UNDECLARED_STATE/EVENT (typo spec; transisi dibuang dari graf),
  UNUSED_STATE/EVENT, NO_INITIAL (state pertama jadi initial implisit),
  NO_FINAL, DUP_DECL.
- **Sequence witness**: BFS terpendek dari initial ke state bermasalah,
  format `IDLE --START--> BUSY --START--> STUCK` (urutan event jauh
  lebih mudah dipahami LLM daripada stack trace).
- **Output**: teks + JSON penuh (state_machine.finding_list: kind/text/
  witness/line) + JSON summary (additive myc.result.v1, tercatat di
  result-schema.md); replay cache sm_s/e/t/f; subcommand `myc sm <file>`.
- **Fixture**: sm_protocol.c (sehat: 0 finding) + sm_broken.c (5 finding:
  undeclared_event, no_final, no_recovery, sink dgn witness, unreachable)
  di CI Linux 6h (5 cek) + Windows. Self-dogfood 24 source (state.c OK),
  -Werror OK (state.c + myc.c). Plan 72/81.
- **Scope jujur**: "illegal transition" = referensi tak terdeklarasi +
  struktur graf (sink/unreachable/no-recovery). Matriks (state,event)
  yang hilang sengaja TIDAK dilaporkan (anti-noise O(state x event));
  invariant per state (//@ sm invariant) = future work. Observasi,
  bukan sertifikat kelengkapan machine.

### (25) Fase 5 — ABI/FFI Surface Certificate — `abi.c`/`abi.h` (SOL-14)

Menutup task Fase 5 "ABI certificate" (exit criteria: ABI regression
**ditolak dalam transaction**):

- **Snapshot ABI deterministik** (`myc abi snapshot <file> [--cc X]`):
  scanner TEKS (bukan AST, comment-mask penuh) mengekstrak exported
  symbols (fungsi global non-static + signature ternormalisasi),
  struct body + member (sizeof/_Alignof/offsetof via helper program
  compiler-generated `-std=c11`), enum values (nilai dihitung compiler),
  target triple (`<cc> -dumpmachine`), header digest (sha256 source).
  Format "# myc abi v1" per baris TARGET/HEADER/SYMBOL/STRUCT/MEMBER/ENUM;
  CRLF dinormalisasi; dua run identik (md5 sama). NON-blocking observasi:
  compiler tak ada / helper gagal = abi_ran=0 + laporan, verdict tetap.
- **ABI delta** (`myc abi diff <a.txt> <b.txt>` / `myc abi <f1.c> <f2.c>`):
  bandingkan baris snapshot (HEADER sha diabaikan); exit code 1 bila
  berubah. Fixture stable vs drift: 7 baris delta tepat (struct size,
  member baru, enum value, symbol dihapus/baru; Pixel/Player/Access/add
  TIDAK muncul di delta).
- **Ditolak dalam transaction** (exit criteria): `myc_transaction` baru
  punya `abi_before` (via myc_transaction_set_abi_before);
  myc_transaction_verify Check 5 membandingkan snapshot hasil patch
  (myc_abi_texts_changed) -> MYC_TX_RESULT_REJECTED_ABI (hard failure).
  Unit test test/abi_tx_reject.c: drift ditolak, sama diterima.
- **Pipeline**: flag `--abi` (check), output teks + JSON full + JSON
  summary (field `abi` additive di myc.result.v1, tercatat di
  docs/result-schema.md), replay cache 6 counts (abi_r/s/e/y/c/d).
- Validasi: CI Linux 6i (determinisme + delta + JSON + transaction),
  Windows blok abi; self-dogfood `abi.c` verdict OK; -Werror bersih;
  build.sh/build.bat/_audit018.sh/ci.yml/_ci_linux.sh/_regress_run.bat
  + abi.c. Plan 73/81.

### (26) Fase 5 — Resource Linearity Ledger — `resource.c`/`resource.h` (SOL-12)

Menutup task Fase 5 "Resource linearity ledger" (roadmap 7.13):

- **Ledger per fungsi**: profil acquire→release (default POSIX/Win32:
  fopen/fclose, open/close, popen/pclose, fdopen/fclose, mmap/munmap,
  CreateFile(A/W)/CloseHandle; ditambah/timpa deklarasi kustom
  `//@ resource ACQ -> REL;`) ditelusuri di body fungsi; nasib tiap
  resource local: `acquired | released | leaked | double-released |
  transferred | unknown`. Scanner TEKS deterministik (bukan AST), bounded,
  jujur parsial — TIDAK interprosedural.
- **Temuan NON-blocking** (verdict TIDAK pernah turun): `LEAKED`
  (acq@L tanpa release/transfer sampai akhir body; witness
  `acq@L..end@E`), `DOUBLE_RELEASE` (release kedua pada resource yang
  sudah release), `RELEASE_UNKNOWN` (release pada var tanpa acquire — var
  = parameter fungsi TIDAK dilaporkan: kepemilikan dari caller).
  `return var` = `transferred` (bukan leak); resource yang dilewatkan
  sebagai argumen semabarang ke fungsi lain BUKAN klaim leak.
- **Subcommand `myc resource <file>`**: cetak report langsung (mirror
  cmd_sm). Juga berjalan otomatis di `check` (setelah `myc_sm_scan`).
- **Pipeline**: output teks + JSON full (`"resource":{ ran, pairs,
  acquires, releases, transferred, leaks, double_releases,
  release_unknown, findings[], report }`) + JSON summary (counts saja —
  additive di myc.result.v1, tercatat di docs/result-schema.md); replay
  cache 8 counts (rsrc_r/p/a/re/t/l/d/u), report & findings TIDAK
  di-cache (sama seperti sm/harvest).
- **Fixture + CI**: `test/fixtures/resource_clean.c` (seimbang 0 temuan),
  `resource_leak.c` (1 leak + witness acq@11..end@15), `resource_double.c`
  (1 double), `resource_transfer.c` (1 transfer, bukan leak). CI Linux 6k
  + Windows blok resource: hasil fixtures + NON-blocking verdict (OK) +
  JSON summary berisi resource.
- Validasi: self-dogfood `resource.c` verdict OK; -Werror bersih (Linux
  flags + MSYS2 build.bat); `resource.c` masuk build.sh/build.bat/
  _audit018.sh/ci.yml/_ci_linux.sh/_regress_run.bat dogfood list.
  Plan 74/81 (SOL-12 selesai; sisa Fase 5 tugas SOL-11 units/shape).

### (27) Fase 5 — Units / Shape / Provenance Contracts — `units.c`/`units.h` (SOL-11)

Menutup task Fase 5 "Units / shape / provenance contracts":

- **Annotation ringan** di atas type system C: `//@ unit` (bytes vs
  elements, dst), `//@ shape <id> capacity=<id> length=<id>`,
  `//@ provenance <id> owned|borrowed|static`, `//@ endian <id> <little|big>`.
  Memberi model vocabulary semantik yang C type system tidak miliki.
- **Tracking subset deterministik** (analisis teks, bukan AST; NON-blocking;
  verdict TIDAK pernah turun): unit disebarkan lewat assignment `a = b`
  intra-file (sisi bertanda -> sisi belum, keyword C di-skip); `SHAPE_DIM`
  bila capacity & length sebuah shape punya unit berbeda dimensi;
  `UNBOUND` bila identifier annotation tak pernah muncul di source
  (kecuali di komentar/string annotation itu sendiri); `DUP_CONFLICT`
  bila annotation bertentangan (unit `count` diubah / endian diubah).
- **Subcommand `myc units <file>`**: cetak report langsung (mirror
  cmd_rsrc). Juga berjalan otomatis di `check` (setelah `myc_resource_scan`).
- **Pipeline**: output teks + JSON full (`"units":{ ran, annotations,
  unbound, unit_mismatches, shape_dims, duplicates, findings[], report }`)
  + JSON summary (counts saja — additive di myc.result.v1, tercatat di
  docs/result-schema.md); replay cache 6 counts (unt_r/a/u/m/s/d), report
  & findings TIDAK di-cache (sama seperti resource).
- **Fixture + CI**: `test/fixtures/units_clean.c` (0 temuan),
  `units_broken.c` (1 unbound, 1 unit-mismatch, 2 shape-dim, 2 dup).
  CI Linux 6k + Windows blok units: hasil fixtures + NON-blocking verdict
  (OK) + JSON summary berisi units.
- Validasi: self-dogfood `units.c` verdict OK; -Werror bersih (Linux flags
  + MSYS2 build.bat); `units.c` masuk build.sh/build.bat/_audit018.sh/
  ci.yml/_ci_linux.sh/_regress_run.bat dogfood list.
  Plan 75/81 (SOL-11 & SOL-12 selesai; sisa Fase 5 per plan di
  gptsol_deepseek-plan.md).

### (28) Fase 7 — Model/Harness Error Fingerprint (SOL-20) — `profile.c`/`profile.h`

DESAIN (Fase 7 #1, "Model/harness error profile opt-in"). Implementasi
menyusul; masuk sebagai MYC-AUDIT-032.

**Masalah (plan 1455–1476).** Model/harness berbeda punya pola salah yang
berbeda; satu recipe gate untuk semua membuang waktu. Scheduler Fase 7
butuh profil lokal yang menjawab: "harness ini cenderung memicu kelas
finding apa, dan gate mana yang menemukannya?"

**Scope tetap.** Hanya *fingerprint observasional* dari `myc_result`
(agregasi klas per gate), **tanpa menyimpan source**, opt-in penuh.
Fix-success/regression/churn/false-positive feedback **ditunda** ke task
#2 (Trust Calibration Ledger). Scheduler EIG (task #3) memakai file ini
sebagai input — di luar scope task #1.

**Privacy (exit criteria).** Opt-in (`--profile <id>` / env
`MYC_PROFILE_ID`), lokal di `.myc/profiles/<id>.json`, tanpa telemetry.
File hanya berisi: `schema`, `id` (alias/hash dari user), agregat count
per `gate` (gate_matrix status) dan per `finding_class` (hazard class /
diag class), plus `checks` total, `checks_ok`, `duration_ms_total`/
`duration_ms_max` (proksi time/token). **TIDAK pernah** `source_sha256`
maupun snippet. Kalibrasi rendah (count < N) = observation saja, TIDAK
pernah menurunkan verdict (trust rule 1 & 3).

**API (profile.h).**
- `int myc_profile_id_valid(const char *id)` — charset `[A-Za-z0-9._-]`,
  panjang <= 63 (path-safe, anti-traversal).
- `void myc_profile_record(const myc_result *res, const char *id)` —
  load-or-init `.myc/profiles/<id>.json`, update agregat, save.
  NON-blocking: gagal tulis = dilewati (pola `.myc/assumptions.json`).
- `int myc_profile_show(const char *id, char *buf, size_t cap)` — laporan
  teks (0 ok, -1 tak ada, -2 id invalid).
- `int myc_profile_list(char *buf, size_t cap)` — daftar file profil.
- `int myc_profile_reset(const char *id)` — hapus file (atau -1 tak ada).

**Wiring.** `--profile <id>` di myc.c (fail-fast bila id invalid = exit 2,
konsisten MYC-AUDIT-019) + env `MYC_PROFILE_ID` (flag menang atas env);
record dipanggil SETELAH `myc_run` sebelum report (cache-hit tetap
tercatat — profil menghitung *permintaan check*, bukan eksekusi ulang
gate). Subcommand `myc profile list|show <id>|reset <id>`. Tidak ada
perubahan `myc.result.v1` (profil = state eksternal, bukan hasil gate).

**Batas jujur.** Aggregat kasar (count per gate/class), tanpa urutan
temporal, tanpa per-finding detail, tanpa source hash.

### (29) Fase 7 — Trust Calibration Ledger (SOL-21) — `calibrate.c`/`calibrate.h`

DESAIN (Fase 7 #2, "Trust calibration ledger"). Implementasi menyusul;
masuk sebagai MYC-AUDIT-033.

**Masalah (plan 1478–1496).** Precision > recall hanya bisa dijaga bila
proyek belajar dari *false positive* dan *false negative*. Kepercayaan
terhadap myc harus **diukur** (dengan data lokal), bukan diasumsikan.
Task #1 (`profile.c`) sengaja menunda fix-success/regression/churn/false
positive feedback ke sini.

**Scope (exit criteria Fase 7 #3).** *"Rule yang dikalibrasi rendah tidak
menghasilkan hard finding."* Ledger mencatat sejarah kalibrasi per RULE
(`lint.c`/`negative.c` — rule heuristik yang ber-`confidence`), NON-blocking
penuh: feedback TIDAK pernah Ikut menurunkan/menaikkan verdict (trust rule
1–3), distributor: purely observation; rule tidak pernah dihapus global tanpa
bukti; hia "confidence rendah" menjadi label reporting + anotasi lokal,
bukan verifikator.

**Penyimpanan.** `.myc/calibration.json` (schema `"myc.calibration.v1"`),
ditulis HANYA oleh subcommand `myc calibrate` (tidak pernah auto-record saat
check — deterministik). Non-deterministic writes gagal = diabaikan (pola
`.myc/assumptions.json`). File menyimpan per rule: `accepted`, `rejected`,
`confirmed_later`, `missed`, `useful_fix`, `harmful_fix` + derivasi state.

**Outcome (6 kategori, plan 1484–1490).**
- `accepted` — finding/peringatan dikonfirmasi benar oleh user/harness;
- `rejected` — false positive (rule salah prediksi);
- `confirmed_later` — awalnya diragukan, ternyata bug;
- `missed` — staggered bug NOT caught = false NEGATIVE (rule GAGAL);
- `useful_fix` — saran fix membantu;
- `harmful_fix` — saran fix merusak/menyesatkan.

**API (calibrate.h).**
- `int myc_calib_id_valid(const char *id)` — charset `[A-Za-z0-9._-]`,
  length 1..63 (path-safe, mirror profile).
- `int mycalib_mark(const char *rule, const char *outcome)` — load-or-init
  ledger, increment counter. 0 ok, -1 invalid rule id, -2 unknown outcome.
- `int mycalib_show(const char *rule, char *buf, size_t cap)` — laporan
  teks + derived state (0 ok, -1 tak ada, -2 invalid).
- `int mycalib_list(char *buf, size_t cap)` — semua rule + aggregate.
- `int mycalib_reset(const char *rule)` — hapus satu rule; `NULL` = hapus
  seluruh ledger (0 / -1 tak ada).

**Derived rule state (exit criteria #3).** Logika deterministik dari
counter (bukan time): score = 2*`accepted` + `confirmed_later` − 2*`rejected`
− `harmful_fix`, lalu normalisasi: bila total feedback >= `MYC_CALIB_MIN=3`:
   - score > 0  → state `OK` (rule terpercaya);
   - score <= −2 → state `LOW` (banyak ditolak — rule ini CALIBRATED LOW);
   - score < −4 → state `DISABLED` (empat diabaikan lokal);
state `UNKNOWN` bila feedback < min. Setiap state TETAP observation
dikulturkan; tidak ada path menuju verdict.

**Wiring (myc.c).**
- `myc calibrate mark <rule> <accepted|rejected|...>` / `myc calibrate
  show <rule>` / `list` / `reset [rule]` di dispatch.
- `--calibrate` flag check: setelah `myc_run`, loader membaca ledger; tiap
  `res.diags[i]` yang rule (derived dari `message` / conf>) ber-labflag
  LOW/DISABLED ditambah baris anotasi report (teks & JSON "--calibrated: LOW")
  ijiknya observation tetap observasi; verdict tak disentuh.
- Rule-id derivation untuk mapping diag→rule: hash `myc_lint_rule_id()`
  sse (functions untuk enumerasi rule lint). Positive deltas: rule id =
  `"lint:" + normalized first-token/message-id` dari `myc_lint_why`? —
  Simplest honest: rule-id EXPLICIT dari user; mapping diag=new kontrak
  `//@calibre <rule-id>` untuk fungsi-fungsi di event. Capai ini DOES NOT
  menurunkan verdict (trust rule 1), burial tuntas.

**Batas jujur.** Kalibrasi = observasi lokal; tidak ada umpan balik global
lintas proyek; rule di-DOWNGRADE ≠ dihapus; `disabled` lokal hanya berarti
report downgrade label, bukan skip gate. Gate hard (gcc/analyzer/sanitizer/
EVA/Fil-C/L4) TIDAK pernah dibawa ke kalibrasi (`calibration` hanya untuk
observasi heuristik — align trust rule 2).

### (30) Fase 7 — Expected-Information-Gain Scheduler (DS-14 / #2029) — `eig.c`/`eig.h`

DESAIN (Fase 7 #3, "Expected-information-gain scheduler", plan DS-14 /
2029). Implementasi menyusul; masuk sebagai MYC-AUDIT-034.

**Masalah (plan 938–946).** "Adaptive Assurance harus memilih gate berdasarkan
expected information gain" — jangan sekadar rule `parser → fuzz`. Scheduler
memakai data lokal: kelas bug historis model/harness (SOL-20 `profile.c`),
gate mana yang pernah menemukan bug serupa (SOL-21 `calibrate.c`), biaya
median gate, perubahan source sejak run terakhir, frontier yang masih terbuka
(`frontier.c`), target assurance pengguna (D3/SOL-30 `budget.c`).

**Skor konseptual (plan 946–953):**

```text
expected_value = probability_of_new_evidence × severity × scope
                 ------------------------------------------------
                         time_cost × token_cost
```

V1 = tabel deterministik yang dikalibrasi dari ledger (persis anjuran plan:
"Tidak perlu statistik kompleks pada awalnya").

**Komponen.**
- Prior `P(new_evidence)` per-mille tabel deterministik per eksperimen
  (ALLOC_FAIL 600, BOUNDARY_INPUT 700, DRIVER_GEN 650, REALLOC_PATH 550,
  POLLING_HARNESS 500, default 500, SHORT_IO/LEAK_CHECK 450, CROSS_TARGET
  400, ASSERTION_HARNESS 350).
- Kalibrasi ledger SOL-21: rule id deterministik `eig-<slug-hazard>`
  (mis. `eig-runtime-memory-asan-ubsan`); net = `accepted` + `confirmed_later`
  − `rejected` − `harmful_fix`; langkah 60 per-mille, clamp [100..950];
  `missed` sengaja netral (ketiadaan bukti). Rule diakses via aksesor baru
  `myc_calib_read_counts()` (tidak memformat teks).
- Profil SOL-20 (opt-in `--profile <id>`): kelas `"<gate>/findings"` /
  `"<gate>/observations"` dengan count > 0 → prior +80; profil punya checks
  tapi gate tak pernah menemukan → −30; clamp sama.
- `source_changed=0` (`--unchanged`) → prior dibagi dua (bukti sudah
  dikumpulkan; informasi baru kecil kemungkinannya).
- Budget waktu (`--budget-ms N`) → flag `within_budget` per rekomendasi
  (v1 tidak memilih/menjalankan gate otomatis — lihat batas jujur).
- `scope` per hazard (tabel: temporal/runtime/spatial 5, integer 4, capability
  4, proof 3, boundary 2); `severity`/`cost` dari observasi aktual bila ada,
  else tabel default (sama dgn nextbest.c/observation.c); `token_cost` tabel
  deterministik (dimensi independen).
- `expected_value` dihitung int64 skala 1e6: `P × severity × scope × 1e6 /
  (cost × token)`. Urutan deterministik: EV desc, tie cost asc, type asc,
  hazard asc.

**API (eig.h).** `myc_eig_plan(fs, exps, in, eig)` / `myc_eig_json(eig)` /
`myc_eig_free(eig)`; `myc_eig_input { profile_id, source_changed,
budget_time_ms }`. Reentrant; string di-strdup (dibebaskan `myc_eig_free`).

**Wiring (myc.c).** Subcommand `myc eig <file.c> [--profile <id>]
[--budget-ms N] [--unchanged] [--json]`: jalankan check penuh (`myc_run`,
no-cache — deterministik), bangun frontier + observasi, jalankan plan,
cetak laporan teks / JSON. NON-blocking penuh: verdict tidak pernah berubah;
ledger/profil gagal baca = prior tabel murni. `eig.c` masuk ke seluruh
PIPELINE build (build.sh/build.bat/_audit018/ci.yml/_ci_linux.sh/
_regress_run.bat) + tabel modul AGENTS.md + capabilities.md + fixture
`test/fixtures/eig_clean.c` + blok assert CI Linux (6o) & Windows (6o).

**Batas jujur (v1).** Lapisan PERENCANAAN rekomendasi — scheduler ini
membuat daftar eksperimen terurut yang SEHARUSNYA dijalankan, tetapi belum
memilih/menjalankan gate otomatis di dalam `myc check`. Pemakaian
rekomendasi oleh assurance budget (D3/SOL-30: enforce gate sesuai budget
waktu) dan pengukuran exit criteria benchmark (median waktu vs bug
discovery) = follow-up. Kalibrasi/profil hanya menggeser prior rekomendasi
(tabel), TIDAK pernah menyentuh gate hard (trust rule 2).

### (31) Fase 7 — Candidate Tournament dengan Pareto Frontier (SOL-10) — `candidate.c`/`candidate.h`

DESAIN (Fase 7 #4, "Candidate tournament", plan SOL-10 / 1227). Masuk
sebagai MYC-AUDIT-035.

**Masalah (plan 1227–1241).** Model sering menghasilkan 2–4 patch alternatif;
memilih berdasarkan "yang compile" terlalu lemah. `myc compare-candidates`
menilai tiap kandidat pada DIMENSI terukur, lalu memilih kandidat pada
Pareto frontier (bukan satu skor ajaib).

**Dimensi v1 (8 terukur + 1 UNMEASURED, gap terlihat):**
- `hard_gate` — pipeline myc (compile tier) lolos (verdict OK) [higher better];
- `findings` — observasi lint + negative-space [lower better];
- `obligations_lost` — requires/ensures hilang vs baseline (contract-delta)
  [lower better];
- `churn_lines` — baris ditambah+dihapus vs baseline (multiset line-hash
  FNV-1a 64-bit, sort + two-pointer, deterministik) [lower better];
- `verification_cost` — jumlah biaya default eksperimen utk frontier terbuka
  (tabel DS-14, diekspos `myc_eig_hazard_cost_ms`) [lower better];
- `runtime_proxy` — jumlah kata kunci loop for/while/do (komentar+string
  dibuang dulu) [lower better];
- `portability` — rasio include whitelist policy (0..1000) [higher better];
- `readability` — 1 − rasio baris > 100 kolom (0..1000) [higher better];
- `stack_impact` — UNMEASURED v1 (butuh gcc -fstack-usage per kandidat;
  gap TERLIHAT di laporan, bukan kesunyian — trust rule 4).

**Algoritma.** Pareto dominance murni tanpa bobot: A mendominasi B bila A ≥ B
pada SEMUA dimensi terukur (arah higher-better) dan ketat pada ≥ 1 dimensi.
Kandidat tak didominasi = frontier. Baseline ikut dalam perbandingan
(mempertahankan original selalu merupakan opsi). Pemenang index terkecil
menang (deterministik). Item yang tidak terukur (pipeline gagal/OOM) tidak
ikut perbandingan dan ditandai di laporan.

**Anti-overclaim (spec SOL-10).** myc TIDAK menyatakan kandidat "terbaik
secara umum"; ia menyatakan "tidak didominasi pada dimensi yang terukur".
Harness atau user tetap memilih final.

**Wiring.** `myc compare-candidates <baseline.c> <c1.c> [c2.c ...] [--json]`
(baseline + hingga 7 kandidat; baseline tak terbaca / flag tak dikenal /
> 7 kandidat = fail-fast exit 2; normal = exit 0, NON-blocking). Report
teks + JSON schema `myc.candidate.v1` (items + dims + frontier +
dominated_by + note anti-overclaim). Field result `cand_ran/
cand_candidates/cand_frontier/cand_report` (pola cmd_eig). `eig.h`
mengekspos `myc_eig_gate_cost_ms` / `myc_eig_hazard_cost_ms` (tabel biaya
DS-14 dipakai ulang, bukan salinan).

**Bug ditemukan saat dev (keduanya diperbaiki):** (1) `boundary_ok(p - 1,
idx)` di count_loops salah s — `s[idx]` membaca `(p-1)[p-clean-1]` = baca
di luar konteks (UB, hasil loop liar); benar = `boundary_ok(clean, idx)`.
(2) `base_hash` tidak di-sort sebelum `line_delta` (fungsi mengasumsikan
kedua array terurut) — churn menggelembung (42/49, benar 14/24).

**CI.** Fixture `test/fixtures/cand_base.c` (1 lint + 1 kontrak + 2 loop),
`cand_better.c` (fix lint, kontrak dipertahankan → findings 0, churn 14),
`cand_worse.c` (regresi: 2 lint + kontrak dibuang + do-while + baris
panjang → findings 2, obligations_lost 1, churn 24, readability 965;
runtime 5 = do+while, benar). Blok 6p: 10 assert Linux + 10 assert Windows
(laporan, dimensi, gap stack terlihat, dominansi baseline→worse, JSON
schema, NON-blocking exit 0, fail-fast baseline hilang). candidate.c di
semua daftar build; self-dogfood OK (candidate.c/eig.c/myc.c verdict OK).

**Batas jujur (v1).** Proksi teks (churn/runtime/portability/readability)
deterministik tapi bukan AST; perbedaan kecil antar kandidat sebaiknya
TIDAK dianggap dominansi tunggal oleh harness. `stack_impact` belum
terukur. Pemakaian frontier tournament oleh harness (auto-pick) =
follow-up.

### (32) Fase 7 — Privacy/size controls (DS-14 #3) — `myc.c`/`myc.h`/`agent.c`/`agent.h`

DESAIN (Fase 7 #6, "Privacy/size controls", plan baris 2032 — tanpa
spesifikasi detail; dirancang di sini). Masuk sebagai MYC-AUDIT-036.

**Gap yang diisi (yang SUDAH ada sebelumnya):** `--output-cap` (output
backend), `--budget 4K|8K|16K` (context), `--no-cache`/`--no-assumptions`,
profil SOL-20 privacy-first (angka saja, tanpa source), `_no_source_leak.sh`
(sentinel tidak bocor), cap payload agent 16 KiB hardcoded.

**Dua gap nyata yang kurang:**
1. **Cap payload agent tidak bisa di-set dari CLI** — `MYC_AGENT_PAYLOAD_CAP`
   (16384) konstanta. Flag baru `--agent-payload-cap BYTES` (0 = default
   16384; valid 1024..1048576; non-angka / di luar rentang = fail-fast
   exit 2, pola MYC-AUDIT-019/020).
2. **Ledger temporal SELALU ditulis** (`.myc/ledger.json`, tanpa kondisi)
   — tidak ada cara menjalankan check tanpa jejak disk. Flag baru
   `--no-persist`: mode privasi — ledger, cache SOL-18, ledger asumsi
   (`.myc/assumptions.json`), profil SOL-20 TIDAK ditulis. Verdict/hasil
   run TIDAK berubah (NON-blocking penuh, trust rule 1-3); hanya tidak
   meninggalkan jejak. Kontradiksi `--no-persist` + `--profile` =
   fail-fast (pola A1, seperti --no-assumptions +
   --require-assumptions-closed).

**Wiring (minimal, tanpa ubah signature publik).** Field baru
`req.agent_payload_cap` / `req.no_persist` (myc.h). `myc_run` meng-wire
`res->agent_payload_cap = req->agent_payload_cap` SEBELUM branch cache
sehingga jalur cache-hit pun memakainya; agent output SELALU dibangun
ulang dari res (bukan di-replay), jadi TIDAK perlu simpan cap di cache
entry dan TIDAK perlu masuk scenario hash. `myc_build_agent_result`
membaca `res->agent_payload_cap` (0 = default) → enforcement buang
enrichment bertahap sampai muat; `ar->payload_cap` + serialize
`"payload_cap"` di agent JSON. Guard `--no-persist`: `if (!no_persist)`
seputar `myc_ledger_integrate` + `myc_cache_store` (2 jalur: file/stdin +
memory) dan `myc_assume_run` (4 lokasi); `myc_profile_record` ikut
di-guard defensif.

**Bug ditemukan saat dev.** (1) `-Woverlength-strings` — literal usage
melebihi 4095 (baris baru flag) → pecah jadi dua `printf`. (2) binary
TIDAK ter-update oleh `build.bat` (masalah filesystem/cache yang sudah
dicatat AGENTS.md) — `bash build.sh` (yang direkomendasikan) menghasilkan
binary dengan flag baru; tanpa itu tes `--no-persist` seolah gagal.

**CI.** Blok 6r: 6 assert Linux + 6 assert Windows (`--agent-payload-cap
4096` → `payload_cap":4096`; default 16384; non-angka → exit 2; 100
di bawah min → exit 2; `--no-persist` → ledger tidak ditulis + verdict
OK; `--no-persist` + `--profile` → exit 2). `tests/ok_hello.c` sebagai
fixture (bukan test/fixtures/ — ok_hello ada di tests/).

**Batas jujur (v1).** `--no-persist` berlaku untuk `myc check`;
subcommand dengan intent eksplisit menulis (`myc calibrate mark`,
`myc profile reset`) tetap menulis (bukan diam-diam ditekan). Cap di
bawah protokol inti agent → output agent gagal total (`-1`, jujur, bukan
truncate diam-diam). `payload_size` aktual tidak diserialize (hindari
circular) — `payload_cap` saja. Cache/ledger tetap default ON tanpa
flag (perilaku lama dipertahankan).

## (33) Project-local prompt/spec pack — MYC-AUDIT-037 (2026-08-10)

Item plan terakhir (81/81). Memperkaya `myc prompt` (D4/DS-15) dengan
pack proyek lokal, version-controllable di direktori proyek (BUKAN `.myc/`
yang gitignored):

- `myc.prompt.md` — teks bebas proyek (hingga 8 KiB) disisipkan verbatim
  ke snippet prompt; `myc.spec.json` — spec terstruktur divalidasi json.c
  ketat (`version:1` + `name` wajib, `domain` opsional; `rules`/
  `allow_headers`/`deny_functions` = array string dengan batas jumlah/
  panjang).
- `myc prompt <file.c> [--pack-dir DIR] [--no-pack]`: pack dicari di cwd
  atau `--pack-dir`; `--no-pack` mematikan; spec ADA tapi invalid =
  fail-fast exit 2 (pola scenario -2); pack absen = snippet inti normal.
- NON-blocking penuh: pack TIDAK pernah mengubah verdict. Setiap klaim
  diberi sumber (`dari myc.prompt.md` / `dari spec.json`) + sha256 isi
  kedua file di output — deterministik, harness bisa verifikasi (tanpa
  menyimpan source — konsisten SOL-20).
- Implementasi di prompt.c/h (bukan modul baru — DS-15 sudah ada):
  `myc_pack_load()` + `myc_prompt_build_packed()`; loader memakai
  `myc_source_load` canonical (pola scenario load_profile_file); hash
  via sha256.c. Fixture `test/fixtures/pack/` (valid) +
  `test/fixtures/pack_bad/` (invalid). CI blok 6s Linux + Windows (8
  assert: prompt.md verbatim, spec name/rules/allow/deny, sha256,
  `--no-pack`, spec invalid exit 2, verdict check tetap OK).
- Code review: tidak ada temuan blokir; catatan validasi ukuran string
  (maxlen) dibanding `strlen` memakai `>=` agar selalu menyisakan slot
  NUL.

**Batas jujur (v1).** `myc.prompt.md` yang lebih dari 8 KiB dipotong
 dengan penanda eksplisit (bukan diam-diam). Spec `domain` kosong default
 "generic". Deterministik selama isi file pack tidak berubah (hash
 mencakup isi). Wiring ke `myc check --agent` + context SOL-22 dikerjakan
 di entry (34) — MYC-AUDIT-038.

## (34) Pack wiring: --agent + context SOL-22 — MYC-AUDIT-038 (2026-08-10)

Follow-up MYC-AUDIT-037 (item plan terakhir): project-local prompt/spec
pack (SOL-15) kini di-wire ke DUA jalur konsumsi model selain `myc prompt`:

- **`myc check <file.c> --agent`** — agent JSON (myc.agent.v2) memuat
  objek `pack`: `prompt_present`/`spec_present` + `prompt_text` verbatim
  (ter-cap 8 KiB) + `prompt_sha256`/`spec_sha256` + spec (`name`/`domain`/
  `rules`/`allow_headers`/`deny_functions`). Implementasi: field baru
  `myc_agent_result.pack_json` (dibangun via json API dari
  `myc_pack_info`), serialisasi `pack` sbg objek di
  `myc_agent_result_json`, signature `myc_build_agent_result(..., pack)`
  (NULL = tanpa pack; pemanggil report.c/mcp.c/context.c di-update).
  **Enforcement `--agent-payload-cap`**: pack = enrichment yang dibuang
  TERAKHIR (setelah experiments/causal/next_best) — konten proyek yang
  user sengaja sediakan lebih berharga daripada eksperimen otomatis;
  protokol inti (verdict/finding/primary/witness) tidak pernah dikorbankan
  (verifikasi: cap 1300 pada file ber-finding → pack dibuang, verdict OK
  tetap 1092 byte).
- **`myc context <file.c>` (SOL-22)** — section baru `project pack`
  (SEC_PACK, prioritas TERENDAH: dipotong pertama saat budget penuh —
  konteks finding lebih penting daripada instruksi proyek). Render:
  prompt.md verbatim + penanda potong jujur (bila > cap) + spec + sha256
  keduanya; pack absen ditandai eksplisit "tidak ada pack proyek lokal"
  (gap terlihat, bukan kesunyian — konsisten trust rule 4). Section masuk
  hash deterministik context_sha256 (body dibangun lengkap dulu).
- **Flag**: `--pack-dir DIR` + `--no-pack` kini diparse di loop utama
  `check`/`context` (field baru `myc_request.pack_dir`/`no_pack`,
  di-free di main); spec.json ADA tapi invalid = fail-fast exit 2 di
  kedua jalur (pola cmd_prompt / scenario -2). NON-blocking penuh:
  verdict TIDAK pernah berubah (diuji blok CI 6t). Tidak masuk cache key
  (output agent/context dibangun ulang dari res setiap run — konsisten
  pola `agent_payload_cap` MYC-AUDIT-036).
- **Bug lama ditemukan & diperbaiki**: `MYC_ERR_INVALID_AGENT_CAP`
  (ditambahkan MYC-AUDIT-036) belum ditangani di `myc_error_name`
  (report.c) — `-Werror=switch` menyala saat kompilasi report.c;
  case ditambahkan. Helper `agent_pack_build_json` dipindah setelah
  `agent_add_str` (urutan definisi).
- **CI**: blok 6t Linux (9 assert) + Windows (9 assert): objek pack di
  agent JSON, isi pack terserialisasi, --no-pack menonaktifkan (kedua
  jalur), pack_bad fail-fast exit 2 di --agent, section project pack di
  context, verdict agent tetap OK (NON-blocking), + enforcement cap
  (pack dibuang saat cap ketat 1300, verdict tetap OK). Fixtures reuse
  `test/fixtures/pack/` + `pack_bad/`.
- **Code review**: 1 bug valid diperbaiki — `agent_pack_build_json`
  mengabaikan return `json_serialize` (OOM bisa memberi pointer sampah
  ke `ar->pack_json`); kini `if (!json_serialize(...)) out = NULL`
  (konsisten dgn `myc_agent_result_json`). Catatan yang DITERIMA (pola
  eksisting, NON-blocking): (a) early-return di loop flag main bisa
  membocorkan `req.pack_dir` bila `--pack-dir` mendahului flag yang
  gagal — konsisten dgn pola `tx_finding_id` yang sudah ada sejak lama;
  (b) `--agent --json` bersama memuat pack yang tak terpakai (as_json
  menang di rantai report) — inefisiensi baca disk, bukan bug; (c)
  context_sha256 semua run berubah (section `project pack` selalu ada)
  — deterministik, gap terlihat (trust rule 4), sudah didokumentasikan.
- **Batas jujur (v2).** Section pack pada context dipotong pertama saat
  budget 4K default bila isi prompt.md besar (wajar: prioritas terendah).
  Wiring MCP (`pack_dir` dari JSON-RPC) dikerjakan di entry (35) —
  MYC-AUDIT-039.

## (35) Pack wiring MCP: agent_check + pack_dir — MYC-AUDIT-039 (2026-08-10)

Follow-up MYC-AUDIT-038: pack proyek lokal (SOL-15) kini tersedia juga di
jalur MCP server (`mcp.exe`), bukan hanya CLI:

- **`tool_agent_check`** (mcp.c) mem-parse dua argumen baru dari JSON-RPC:
  `pack_dir` (string opsional; NULL = cwd server, konsisten default CLI)
  dan `no_pack` (boolean opsional; true = nonaktifkan). Setelah
  `myc_pipeline`, server memuat pack via `myc_pack_load` dan meneruskan
  `&pinfo` ke `myc_build_agent_result(..., pack)` (sebelumnya NULL).
  spec.json ADA tapi invalid = error tool -32602 (fail-fast, pola CLI exit
  2); OOM/IO = -32603. `pinfo.prompt_text` di-free di SEMUA jalur
  (success, build-gagal, load-gagal) — tanpa leak.
- **Hasil**: agent JSON di `content[0].text` memuat objek `pack`
  (identik CLI: prompt_text verbatim + sha256 + spec); `structuredContent`
  menambah field `pack_present` (bool) untuk konsumen mesin. Pack
  NON-blocking: verdict TIDAK berubah; enforcement cap tetap (pack =
  enrichment dibuang terakhir).
- **tools/list**: schema agent_check mengekspos `pack_dir` (string) +
  `no_pack` (boolean) + description; header komentar mcp.c di-update.
- **Smoke test**: `test/mcp_smoke_input.jsonl` +2 pesan (id 14:
  agent_check + pack_dir test/fixtures/pack → pack_present + isi pack;
  id 15: pack_dir pack_bad → -32602). `test/_mcp_smoke.bat` kini 15
  respons (sebelumnya 13) + 3 assert baru: `pack_present`,
  `prompt_present` (isi pack di content), `myc.spec.json invalid`
  (fail-fast). Di-verifikasi PASS + regression penuh.
- **Code review**: 1 bug valid diperbaiki — double-free pada path error
  `myc_build_agent_result < 0` di `tool_agent_check` (agent.c sudah free
  internal sebelum return -1, mcp.c memanggil `myc_agent_result_free`
  lagi = UB). Fix: hapus free ganda (pertahankan cleanup res + pinfo).
  Pola identik PRE-EXISTING di context.c SEC_ACTION juga diperbaiki
  (memori-safety). Minor: `myc_pack_load(pack_dir, no_pack, ...)` eksplisit
  (bukan literal 0). Catatan diterima: pack selalu dicoba dari cwd server
  walau pack_dir tidak diberikan (konsisten CLI --agent; spec invalid di
  cwd = semua agent_check gagal -32602, sudah didokumentasikan).
- **Docs**: docs/mcp-tools.md section agent_check (pack_dir/no_pack + objek
  pack + pack_present). capabilities.md tidak memiliki row MCP (tidak
  berubah).
- **Batas jujur (v1).** `tool_check` (myc.result.v1) TIDAK memuat pack —
  pack hanya relevan pada output agent (myc.agent.v2) dan paket context;
  hasil check biasa tetap bebas pack (tidak mengubah skema myc.result.v1).
  `pack_dir` MCP di-resolve relatif terhadap cwd server saat ini (belum
  ada isolasi per-request; follow-up potensial).

## (36) Wire debt MYC-INCOMPLETE-RAW-BUFFERS — MYC-AUDIT-040 (2026-08-10)

Menutup temuan audit: `MYC_DEBT_RAW_BUFFERS` selama ini hanyalah enum +
label (`myc.h`, gate.c) tanpa SATU pun setter — `MYC-INCOMPLETE-RAW-BUFFERS`
tidak pernah bisa muncul. Kini di-wire penuh:

- **Deteksi (compile.c).** `scan_checked_coverage` menambah output
  `raw_buffers` = jumlah `[` di luar komentar/string/preprocessor
  (deklarasi/akses array biasa). Makro MYC_BUF/MYC_NEW/MYC_AT/MYC_FREE
  tidak memakai `[`, jadi tidak ada double-count. Nilai disimpan di
  `myc_result.checked_raw_buffers` (dan capsule).
- **Debt (gate.c).** `myc_build_debt` memicu `MYC_DEBT_RAW_BUFFERS` bila
  `checked_uses_buf && checked_raw_buffers > 0`: source memakai disiplin
  MYC_BUF tapi masih ada buffer biasa → transformasi fat-pointer (L4
  SPATIAL) tidak menutup semua buffer — gap jujur. NON-blocking: verdict
  tidak pernah turun; `--require-complete` menaikkannya jadi INCONCLUSIVE
  (pola 9.10).
- **Propagasi lengkap.** Field `checked_raw_buffers` di myc_result,
  capsule (`myc_build_capsule`), cache entry SOL-18 (`chk_rb` di cache.c:
  load/save/replay/new-entry) + laporan teks/JSON/capsule (report.c).
- **Fixture + regresi.** `tests/raw_buf_mixed.c` (MYC_BUF + array biasa)
  → debt RAW-BUFFERS muncul; `semantics_parity.c` / `ok_checked.c` (murni
  MYC_BUF) → TANPA debt (no false positive). Assert di `_regress_run.bat`
  + `_ci_linux.sh` (blok 4a): debt muncul, `--require-complete` →
  INCONCLUSIVE, dua kontrol negatif tetap bersih.
- **Batas jujur.** `raw_buffers` adalah proksi leksikal (setiap `[` di luar
  komentar/string/pp dihitung, termasuk array parameter fungsi yang
  sebenarnya sah); debt tetap NON-blocking sehingga over-count hanya
  memperkaya laporan, tidak pernah menurunkan verdict. Tidak mengubah
  receipt fingerprint (hanya menambah field laporan/cache).

## (37) Audit 10 tipe debt MYC-INCOMPLETE + fix overwrite INFRA-FAILED — MYC-AUDIT-041 (2026-08-10)

**Masalah.** Debt adalah gap verifikasi yang harus "terlihat, bukan
kesunyian" (9.10). Setelah MYC-AUDIT-040 menghidupkan RAW-BUFFERS, audit
menyeluruh dilakukan terhadap 10 tipe `MYC_DEBT_*` untuk memverifikasi
setiap setter memiliki **jalur pemicu nyata** (bukan hanya setter statis
yang kondisinya tak pernah terpenuhi — pola RAW-BUFFERS lama).

**Temuan.** 9 tipe nyata terverifikasi empiris dengan skenario pemicu:

| Tipe | Pemicu nyata | Bukti empiris |
|---|---|---|
| GATE-UNAVAILABLE | backend diminta, tak tersedia | `--filc` tanpa Fil-C → debt ✓ |
| GATE-INFRA-FAILED | backend ADA tapi gagal exec/build | fake filc-clang exit 3 / fake clang non-exec → debt ✓ |
| GATE-INCONCLUSIVE | backend jalan tapi hasil tak lengkap | `--run --timeout 1` pada infinite loop → debt ✓ |
| NONZERO-CASES | `--driver` tapi 0 kasus tereksekusi | `driver_zero_cases.c` → debt ✓ |
| ENSURES-UNPROVED | ensures di-parse, prove/run tak clean | `contract_clauses.c` → debt ✓ |
| RAW-BUFFERS | `checked` + buffer biasa di luar MYC_BUF | `raw_buf_mixed.c` → debt ✓ (AUDIT-040) |
| OUTPUT-TRUNCATED | output backend terpotong (cap) | `--run --output-cap 512` → debt ✓ |
| BUDGET-UNMET | target assurance/waktu/output tak tercapai | `--budget-contract` target prove=clean → debt ✓ |
| ASSUMPTIONS-OPEN | asumsi belum ditutup + `--require-assumptions-closed` | `assume_char_signed.c` → debt ✓ |

**Bug yang ditemukan & diperbaiki (compile.c).** Jalur Fil-C build gagal
`myc_filc_gate` men-set `MYC_GATE_INFRA_FAILED` dengan benar (filc.c:5
jalur: temp-dir, exec, build exit ≠ 0, WSL detect, run exe), namun blok
`else` di `myc_check_gates` selalu menimpanya menjadi
`MYC_GATE_UNAVAILABLE` tanpa memeriksa status yang sudah di-set backend.
Akibatnya `MYC-INCOMPLETE-GATE-INFRA-FAILED` **tidak pernah bisa muncul**
— setter ada tapi jalur mati (persis pola RAW-BUFFERS). Fix: hanya timpa
ke UNAVAILABLE bila status masih `NOT_APPLICABLE` (backend tidak
men-set apa pun); status nyata backend dipertahankan — konsisten dengan
pola yang sudah ada di blok prove (prove.c INFRA_FAILED dipertahankan).

**Regresi.** Blok `4a2` baru di `_ci_linux.sh` (fake filc-clang
di-compile via gcc di temp dir + PATH depan; assert UNAVAILABLE vs
INFRA-FAILED) dan `_regress_run.bat` (fake `filc-clang.exe` di `_fakebin`;
`--no-cache` agar PATH dihormati; escape `^{return 3;^}` agar batch tidak
membaca kurung kurawal sebagai blok). Kedua blok hijau 2/2.

**Verifikasi.** Build `-Werror` hijau; self-dogfood `compile.c` verdict
OK; seluruh 9 tipe debt diregresi ulang tetap muncul; determinisme
receipt dipertahankan (debt hanya dari gate status + counter yang
deterministik).

## (38) Audit jalur debt dengan cache replay + fix debt text & JSON round-trip — MYC-AUDIT-042 (2026-08-11)

**Tujuan.** Perluas audit MYC-AUDIT-041: pastikan 9 tipe debt `MYC-INCOMPLETE-*`
juga berfungsi saat cache replay aktif (bukan hanya `--no-cache`) — replay
harus menampilkan hasil yang identik dengan run asli (SOL-18).

**Hasil audit (empiris, tiap tipe = run1 populate + run2 replay, cache
diaktifkan):**

| Tipe debt | cache-hit run2 | debt di run2 | receipt deterministik |
|---|---|---|---|
| GATE-UNAVAILABLE | ya | muncul, teks identik | sama |
| GATE-INFRA-FAILED | ya | muncul, teks identik | sama |
| GATE-INCONCLUSIVE | tidak* | muncul (pipeline ulang) | sama |
| NONZERO-CASES | ya | muncul, teks identik | sama |
| ENSURES-UNPROVED | ya | muncul, teks identik | sama |
| RAW-BUFFERS | ya | muncul, teks identik | sama |
| OUTPUT-TRUNCATED | ya | muncul, teks identik | sama |
| BUDGET-UNMET | ya | muncul, teks identik | sama |
| ASSUMPTIONS-OPEN | tidak* | muncul (pipeline ulang) | sama |

*By design: GATE-INCONCLUSIVE (timeout) tidak di-store cache
(`myc_cache_store` menolak `MYC_ERR_TIMEOUT`); ASSUMPTIONS-OPEN
replay di-skip (`--require-assumptions-closed` stateful). Keduanya tetap
menjalankan pipeline deterministik sehingga debt selalu muncul — bukan bug.

**Bug 1 ditemukan & diperbaiki — debt text hilang saat replay (cache hanya
simpan type).** Entry cache hanya menyimpan `debt[].type` (angka);
`cache_replay_into` menimpa `text` dengan `myc_debt_type_name` (nama kode
pendek) padahal run asli menampilkan kalimat penjelasan (mis.
"gate diminta tapi backend tidak tersedia" vs "unavailable"). Melanggar
replay identik SOL-18. Fix: field baru `char debt_text[MYC_MAX_DEBT][160]`
di `myc_cache_entry` (cache.h); store menyalin `res->debt[i].text`;
write/read serialisasi array string paralel (`debt_text`); replay memakai
teks tersimpan (arena-dup, fallback nama kode untuk entry lama).
Backward-compatible: entry tanpa `debt_text` = fallback lama.

**Bug 2 ditemukan & diperbaiki — cache file tak bisa di-parse ulang saat
backend stderr berisi byte non-UTF8 (round-trip JSON rusak, cache-hit
flaky).** `ser_escape` (json.c) menulis byte `>= 0x80` MENTAH tanpa
validasi UTF-8, sedangkan parser json.c menolak byte non-UTF8
(`utf8_valid`). Akibatnya file cache yang ditulis dengan `stderr_text`
berisi byte aneh dari output backend (mis. driver harness) GAGAL di-parse
ulang pada run berikutnya — cache-hit jadi nondeterministik (flaky miss,
pola `0 0 1 0 1...` teramati di `driver_zero_cases --driver`). Ini juga
melanggar JSON-RPC 2.0 ketat di MCP. Fix: `ser_escape` memvalidasi UTF-8;
urutan UTF-8 valid disalin apa adanya (output normal TIDAK berubah),
byte/sequence invalid di-escape `\u00XX` sehingga round-trip selalu
parseable. Verifikasi: loop 8x `driver_zero_cases --driver` kini stabil
`0 1 1 1 1 1 1 1` (sebelumnya flaky); MCP smoke PASS; golden schema
13/13 PASS; JSON output `ok_hello --json` valid.

**Regresi CI blok 4a3** (Linux + Windows): (a) run2 `driver_zero_cases
--driver` harus `cache: hit` (round-trip JSON); (b) debt text di replay
harus identik dengan fresh run (`ok_hello --filc`). Keduanya 2/2 PASS di
kedua platform.

**Keterbatasan jujur.** Debt text di-replay identik tetapi *string statis*:
entry cache lama (sebelum 042) tetap fallback ke nama kode hingga di-store
ulang. Fix `ser_escape` memengaruhi SEMUA output JSON (report/MCP/cache)
— untuk UTF-8 valid output byte-identik, hanya input non-UTF8 yang kini
di-escape (sebelumnya rusak).

## (39) Cache key specification + dimension tests + fix gap key — MYC-AUDIT-043 (2026-08-12)

Batch PR-011 dari `myc-production-readiness-plan.md`: *"First document
current effective key. Then add dimension-by-dimension hit/miss tests. Only
then change key if gaps exist."*

**1. Dokumentasi key efektif (v1).** Key v1 = sha256(`v1|src:sha256|
scen:16hex|tool:gcc+clang versi|cwd:`); `scen` = `myc_ledger_build_scenario_hash
(req, NULL)` yang hanya memuat flags gate inti (strict/analyzer/run/prove/
checked/filc/driver/meta/div/neg/quorum/reqc) + asumsi (asm_r/asm_no/asm_ack)
+ budget contract. Spesifikasi kanonik baru: `docs/cache-key.md`.

**2. Gap nyata ditemukan (dimensi yang mengubah HASIL tapi tidak di key):**

| # | Dimensi absen v1 | Dampak |
|---|---|---|
| 1 | `--run-stdin` (stdin verifikasi) | Dua run dgn stdin berbeda berbagi entry → replay hasil gate run dgn stdin SALAH (**replay stale**, risiko bukti salah) |
| 2 | `timeout_ms` | Timeout berbeda → hasil berbeda (timeout vs selesai) tapi key sama |
| 3 | `max_output_bytes` | Output cap mengubah truncation/teks tersimpan; marker sanitizer di luar cap bisa hilang |
| 4 | Flag gate Fase 5/6 (run_lint/exhaustive/stack+stack_budget/fuzz+iters+seed/mutate+max/freestanding/matrix/abi/perturb/thread_probe) | `--stack`/`--fuzz` bisa HIT entry polos → output gate HILANG diam-diam; `--exhaustive` replay `ex_*` stale (0); `--stack --stack-budget` beda → observasi stack stale |
| 5 | `checked_header_dir` | Versi `myc_buf.h` berbeda → hasil L4 berbeda tapi key sama |

**3. Fix key v2 (cache.c, cache.h):** tambah `stdin` (sha256 16 hex,
`-` bila kosong), `t` (timeout_ms), `o` (max_output_bytes), `hdir`
(checked_header_dir), `g2` (hash 16 hex dari helper baru `cache_gates2_hash`:
13 flag Fase 5/6). Entry v1 lama otomatis MISS (upgrade mulus). Ledger
scenario hash TIDAK diubah (blast radius minimal — gap hanya di cache key).

**4. Test dimension-by-dimension (`test/cache_key_matrix.c`, blok 14 di
`_audit018.sh`):** T1 determinisme+dedup (store 2x key sama = 1 entry,
last-write-wins, marker hasil di-replay identik); T2 source; T3 13 flag
inti (scenario hash); T4 14 flag Fase 5/6 (g2: incl. `stack_budget` yang
ditemukan gap oleh code review); T5 budget (active/level/max_time/
max_output); T6 eksekusi (stdin/timeout/output cap/header dir — setiap
gap v1 DIUJI sebagai MISS); T7 cwd; T8 tool identity (SKIP bila gcc tak
ada di PATH); T9 run stateful (`--assumption-ack`/
`--require-assumptions-closed`) tidak di-store; T10 hasil `MC_ERROR`
tidak di-store; T11 `--no-cache` nonaktif. Setiap dimensi: nilai A → HIT,
nilai B → MISS (via `myc_cache_store` + `myc_cache_try_replay` langsung,
cwd temp `test/.cache_key_tmp`, self-cleaning, `-Werror -pedantic`).

**Verifikasi.** `cache_key_matrix` penuh hijau — 81 cek OK / 0 FAIL (27
dimensi flag gate + source/budget/eksekusi/cwd/tool/stateful/error/
no-cache); E2E `myc check`: run2 `--stack` setelah run polos = MISS + gate
stack benar-benar dijalankan (g2 memisahkan resep), run3 polos = HIT entry
polos (entry terpisah); `_audit018.sh` SELESAI OK (blok 14 ikut);
self-dogfood cache.c + semua source OK; `-Werror` bersih; diff check
bersih; zero leftover (dir temp dibersihkan test sendiri).

Batas jujur: (1) key v2 tetap TIDAK memuat versi backend prove/filc/matrix
(Frama-C, filc-clang, cross-gcc) — versi gate tsb hanya di-snapshot di
field entry (prov_ver/filc_ver), jadi upgrade backend tersebut masih bisa
mengembalikan replay lama hingga `.myc/evidence_cache.json` dibersihkan.
Follow-up dipertimbangkan pada PR berikutnya (tool key multi-backend).
(2) Replay run ber-flag yang IDENTIK mengembalikan status gate + counts
tanpa teks report untuk gate yang field detailnya tidak disimpan di entry
(stack/fuzz/matrix/mutate/thread-probe/freestanding/perturb — pola
"replay hanya punya counts" yang sudah terdokumentasi untuk
harvest/rel/units/rsrc/sm/abi); `g2` memastikan run ber-flag TIDAK pernah
memakai entry run polos (gap v1 ditutup), jadi status gate ber-flag selalu
hadir — bukan kehilangan verdict.

### MYC-AUDIT-044 (Batch PR-012, P3-T03) — Atomic `.myc` state writes

**Gap.** Semua state `.myc/*.json` (evidence cache, ledger, assumptions,
calibration, exhaustive, profiles, regression seed) ditulis dengan
`fopen(path, "wb")` + `fwrite`/`fputs` + `fclose` LANGSUNG ke path final.
Crash/terminasi di tengah tulis (atau flush yang tidak tuntas) bisa
meninggalkan JSON setengah tertulis yang TAMPIL valid di mata parser
yang toleran atau malah merusak entry berikutnya — melanggar P3-T03
"never half-written valid-looking state".

**Fix (helper bersama + migrasi satu file per satu).**
(1) `persist.h`/`persist.c` baru: `myc_persist_atomic_write(path, data,
len)` — protokol tulis temp (`<path>.tmp.<pid>` di direktori SAMA agar
rename/replace satu filesystem) → `fflush` → `fsync` (POSIX) /
`_commit`≈FlushFileBuffers (Windows) → replace atomik: `rename()`
POSIX / `MoveFileExA(MOVEFILE_REPLACE_EXISTING |
MOVEFILE_WRITE_THROUGH)` Windows (rename() Windows TIDAK menimpa target
ada) → optional parent-dir `fsync` POSIX. Gagal langkah mana pun = temp
dibersihkan, target OLD valid utuh; sukses = target NEW valid.
`persist_cleanup_stale()` menghapus temp sisa crash (`<path>.tmp.*`,
termasuk PID lain) sebelum menulis — tidak ada sampah abadi di .myc.
Suffix pid mencegah dua proses harness menimpa temp satu sama lain
(concurrency lost-update penuh tetap di luar scope — pola plan "do not
rely on renames to solve concurrent lost updates").
(2) Migrasi (tiap penulis `.myc` JSON): cache.c `cache_write_all`
(evidence_cache.json), ledger.c `myc_ledger_write` (ledger.json),
assume.c `asm_state_save` (assumptions.json), calibrate.c `calib_save`
(calibration.json), driver.c `ex_state_write` (exhaustive.json),
profile.c `save_profile` (profiles/<id>.json), regress.c seed .c
(regression). Index `.txt` append-only (profile/regression) tetap
append — baris parsial di-skip reader (bukan state valid-looking).
(3) Build: `persist.c` masuk PIPELINE build.bat/build.sh + SRCS
_audit018.sh/_ci_linux.sh/_regress_run.bat. NON-blocking penuh:
kegagalan tulis diabaikan persis seperti perilaku lama, verdict tidak
pernah berubah.

**Test (`test/atomic_state.c`, blok 15 `_audit018.sh`).** T1 helper
new-file (konten persis + tanpa leftover); T2 overwrite penuh (konten
tidak pernah tercampur); T3 failure injection (dir induk tak ada → 0,
tanpa target/temp); T4 crash-simulasi "sebelum rename" (temp parsial
PID lain + target OLD → recovery = NEW valid + temp stale dibersihkan);
T5 "saat temp ditulis" (target tetap OLD valid; temp sampah tidak
pernah dibaca); T6 stress 200x flip konten A/B (setelah tiap write =
SELALU A penuh atau B penuh); T7–T12 E2E semua penulis via API publik
(cache store+replay, ledger write+read, myc_assume_run dgn facts manual
tanpa gcc, calib_mark, profile_record, regress_save); T13 scan akhir
NOL `*.tmp.*` di seluruh .myc.

**Verifikasi.** `atomic_state` hijau — 34 cek OK / 0 FAIL, dua run
beruntun bersih (self-cleaning, zero leftover); `persist.c` `-Werror
-pedantic` bersih di gcc; `_audit018.sh` SELESAI OK (blok 1–15);
self-dogfood seluruh source (termasuk persist.c) OK; diff check bersih.

Batas jujur: (1) atomisitas antar-proses dijamin untuk SATU file per
penulis; dua proses yang menulis file state yang SAMA secara bersamaan
tetap bisa lost-update (bukan korupsi) — locking penuh di luar batch ini
(plan P3-T05/T08 concurrency lane). (2) Index `.txt` append-only
(profile/regression) tidak ikut protokol rename (baris parsial di-skip
reader — tidak pernah jadi state valid-looking). (3) Capsule witness
(`.myc/witness/...`: source.c/stdin.bin/replay.sh) dan file kerja backend
di tmp dir TIDAK dimigrasi — artefak output per-run (bukan state yang
di-replay), ditulis sekali per permintaan; pertimbangan batch berikutnya
bila capsule dijadikan state yang dibaca ulang. (4) `--no-persist` tidak
berubah: mode tanpa jejak tetap tidak menulis apa pun (helper tidak
dipanggil).

### MYC-AUDIT-045 (Batch PR-013, P3-T04) — Cache corruption recovery

**Gap.** `cache_read_all` memperlakukan file cache sebagai input tepercaya:
enum di luar range di-*clamp* diam-diam ke 0 (verdict out-of-range → 0 =
MC_OK!), entry tanpa field wajib diterima dengan nilai kosong, dan tidak
ada verifikasi integritas — flip bit / truncation / field asing / entry
duplikat di dalam JSON yang tetap valid bisa di-replay sebagai bukti
(false-clean replay). Melanggar P3-T04 "ignore/quarantine + emit
diagnostic + recompute; never crash, never trust".

**Fix (cache.c).** (1) Integritas byte file (L1): sidecar
`.myc/evidence_cache.sha256` berisi `sha256` hex atas byte MENTAH
evidence_cache.json, ditulis atomik (persist.c) SETELAH file cache
(crash di antara keduanya = sidecar stale → ignore + recompute; aman).
`cache_read_all` menghash byte file mentah dan membandingkannya dengan
sidecar; sidecar hilang/stale/tampered = SELURUH file di-ignore
(fail-closed) → replay MISS → recompute. Hash atas byte mentah (bukan
re-serialisasi JSON) stabil untuk konten apa pun — iterasi desain awal
(hash atas serialisasi kanonik entry) ditemukan TIDAK stabil pada E2E
nyata: teks backend (stderr/run output) bisa berisi byte non-UTF8 yang
di-serialisasi `\u00XX` namun di-parse ulang sebagai UTF-8 multi-byte →
hash mismatch palsu → self-quarantine; sidecar byte-mentah menutup ini
tanpa mengubah json.c. (2) Validasi semantik per entry (L2, setelah byte
lolos L1) pada objek JSON mentah SEBELUM parse: `key`/`source` wajib
64-hex, `verdict`/`err` wajib di range enum (BUKAN clamp-to-0!),
`assurance`/`finding`/`completeness`/`claim`/`duration_ms` harus valid
bila ada, `gates` id/status di range, state mustahil ditolak (MC_ERROR
tanpa err — store tidak pernah menyimpan hasil error). Dijalankan setelah
L1: walau byte file konsisten, nilai mustahil tetap dikarantina. (3)
Karantina + self-heal + diagnostic (L2): entry korup dihitung, satu baris
`myc: cache: quarantined N ... (alasan)` ke stderr, file di-rewrite tanpa
entry korup (cache_write_all — self-heal, tidak dibaca berulang); file
tidak ter-parse / byte tidak cocok (L1) → `myc: cache: ... corrupt
(integrity sha256 mismatch | JSON parse failed) - ignored`. Replay menjadi
MISS → pipeline menghitung ulang (recompute). (4) Dedup: entry dengan key
duplikat di file dikarantina (pertahankan yang pertama). (5) Field `tool`
pada entry adalah METADATA informasi — key replay memakai tool identity
LIVE (cache_tool_key), bukan field tersimpan.

**Test (`test/cache_corrupt.c`, blok 16 `_audit018.sh`).** T1 baseline
store→replay HIT (sidecar sha256 byte-mentah stabil utk konten apa pun)
+ sidecar 64-hex ada; T2 truncated JSON (sidecar stale) → L1 MISS +
recompute; T3 flipped bits (nilai numerik, sidecar stale) → L1 MISS; T4
unknown schema (field asing, sidecar stale) → L1 MISS; T5 sidecar
ditamper → L1 MISS; T6 duplicate entries + sidecar SAH → L2 dedup: replay
HIT dari entry pertama + heal ke 1 entry; T7 stale backend version: (a)
tool field diubah + sidecar stale → L1 MISS, (b) + sidecar sah → field
metadata, replay HIT, (c) live tool identity (gcc_program) beda → MISS;
T8 malformed timestamp: sidecar stale → L1 MISS; + sidecar sah → L2
reject → karantina; T9 impossible gate state dengan sidecar SAH (file
ditulis ulang konsisten): MC_ERROR tanpa err dan verdict 999 ditolak
lapisan SEMANTIK walau byte lolos L1, control entry valid diterima (tidak
dikarantina, MISS hanya karena key beda); T10 file tanpa sidecar (schema
lama) → L1 fail-closed; T11 non-object entry + sidecar sah → L2 karantina;
T12 garbage + sidecar cocok → parse fail; T13 recompute E2E (store segar
→ HIT). Invariant: NEVER crash, NEVER replay korup. Diagnostic stderr
`myc: cache:` di-assert blok 16 (grep).

**Verifikasi.** `cache_corrupt` hijau — 37 cek OK / 0 FAIL; tiap jalur
korupsi memicu diagnostic yang benar (integrity sha256 mismatch, JSON
parse failed, duplicate key, state mustahil, verdict out-of-range, entry
bukan objek). E2E `myc check` dua run: entry nyata (stderr/run output
dengan byte non-UTF8) di-store + sidecar + replay HIT tanpa karantina
palsu (regresi desain awal hash-kanonik tertutup). Regresi cache lain
tetap hijau: `cache_key_matrix` (PR-011) dan `atomic_state` (PR-012)
store→replay HIT, `backend_abuse` T2 (verdict 999999 → miss) dan
`parser_fuzz` (rc ∈ {0,1}) tetap lulus. `cache.c` `-Werror -pedantic`
bersih; `_audit018.sh` SELESAI OK; self-dogfood OK; diff check bersih.

Batas jujur: (1) Hash sidecar mendeteksi korupsi AKADENTAL (bit flip,
truncation, write parsial) dan tamper tanpa recompute hash — bukan
anti-tamper kriptografis (P3-T04 trust model: cache lokal, bukan evidence
adversarial); entitas yang bisa menulis ulang file + sidecar konsisten
hanya lolos L1 dan tetap tunduk L2 (semantik). (2) File cache tanpa
sidecar (versi lama) di-ignore fail-closed → satu kali recompute penuh
setelah upgrade (aman, bukan lossy). (3) Karantina/self-heal NON-blocking:
gagal tulis heal diabaikan seperti perilaku lama, replay tetap MISS
(recompute). (4) Sidecar = file state kedua di .myc — ditulis atomik via
persist.c; kegagalan tulisnya = cache di-ignore (recompute), tidak pernah
menjadi trust palsu.

### MYC-AUDIT-046 (Batch PR-014) — Receipt canonicalization

**Gap.** `receipt_sha256` (gagasan pembeda 9.1) di-hash dari byte-string
kanonik yang dibangun `myc_build_receipt` (gate.c) secara PRIVATE — format
byte-string tidak terobservasi, tidak terspesifikasi, dan tidak di-lock.
Mengubah format / mapping nama enum / urutan append / urutan gate secara
tak sengaja akan mengubah SEMUA receipt tanpa ada test yang menangkapnya
(kecuali test T8 reducer_exhaustive yang hanya menguji determinisme),
merusak perbandingan receipt antar run/CI secara senyap. Selain itu tidak
ada jaminan bahwa sha256 yang dihitung implementasi sesuai dengan hashing
independen (bug sha256.c tidak akan terlihat).

**Fix (gate.c/h, docs, test).** (1) `size_t myc_receipt_canonical(const
myc_result *, char *buf, size_t cap)` — API publik baru yang menulis
byte-string kanonik (cap-1 + NUL, return panjang) dan menjadi SATU-SATUNYA
sumber kebenaran format; `myc_build_receipt` di-refactor meng-hash
keluarannya (byte-string identik dengan sebelumnya → seluruh receipt lama
tidak berubah). (2) Spec `docs/receipt-canonical.md`: format penuh,
mapping enum (verdict/completeness/gate status/debt), aturan urutan insert
(bukan sorted), id numerik gate, truncation cap-1, dan tabel golden vector
V1-V4. (3) Test `test/receipt_vectors.c` (blok 17 `_audit018.sh`), empat
lapis pertahanan INDEPENDEN: (a) golden vector V1-V4 — string kanonik +
sha256 hex di-hitung mandiri via python3 hashlib (bukan sha256.c) dan
di-hardcode; (b) implementasi referensi di dalam test (ditulis dari spec
doc, bukan salinan gate.c) wajib setuju byte-demi-byte dengan
`myc_receipt_canonical`; (c) konsistensi pipeline: `res.receipt_sha256`
hasil `myc_reduce_verdict` == sha256(canonical) == golden; (d) properti:
determinisme (build 2x identik), sensitivitas komponen (fingerprint /
source_sha / gate status / gate id / urutan insert / jumlah gate /
verdict manual → hash BERUBAH), `myc_rebuild_receipt` (re-hash setelah
mutasi manual, bukan re-reduce), truncation (fingerprint 5000 B → 4095 B
+ NUL deterministik, cap kecil 1/5/8 → cap-1 byte).

**Verifikasi.** `receipt_vectors` hijau — 51 cek OK / 0 FAIL. Golden hash
independen (python3 hashlib) cocok PERSIS dengan output `sha256_hex` myc
untuk keempat vector (sha256.c terbukti sesuai implementasi eksternal).
`gate.c` `-Werror -pedantic` bersih; regresi lain tetap hijau:
`reducer_exhaustive` T8 (determinisme receipt), `cache_key_matrix` /
`atomic_state` / `cache_corrupt` (store→replay HIT — receipt byte-string
tidak berubah oleh refactor), `_audit018.sh` SELESAI OK; self-dogfood OK;
diff check bersih.Batas jujur: (1) Receipt mengunci BENTUK bukti (verdict, completeness,
  gate id+status, debt, fingerprint, source_sha) — bukan isi output backend:
  dua run dengan status gate sama tapi diagnostik berbeda dapat punya
  receipt sama; pembeda isi ada di fingerprint/source_sha + laporan penuh.
  (2) Truncation 4095 byte bersifat deterministik dan di-hash (bukan
  error) — dokumentasi di spec; fingerprint > ~4 KiB membuat segmen di
  belakangnya terpotong dari receipt (field yang terpotong tetap terlihat di
  laporan penuh). (3) Perubahan enum `myc_gate_id` (penyisipan) / mapping
  nama = format break → wajib bump `myc.receipt.v1` → v2 + golden vector
  baru (spec menyatakan ini).

### MYC-AUDIT-047 (Batch PR-015) — Machine schema freeze (schema compatibility)

**Gap.** Skema JSON mesin tersebar di banyak produsen (report.c summary,
agent.c protocol, calibrate.c, cache.c, scenario.c, prompt.c pack, mcp.c)
tanpa satu registry resmi: tidak ada spesifikasi terpusat, tidak ada golden
file, dan tidak ada test yang membuktikan produsen masih memancarkan field
yang konsumen andalkan. Perubahan skema (hapus field, ganti tipe, reorder
enum, ganti nama key) bisa merusak konsumen mesin (MCP client, agent
harness, CI, state `.myc/`) secara senyap; lebih berbahaya lagi, konsumen
lama yang menolak dokumen dengan field baru melanggar aturan evolusi
additive (dokumen lama harus tetap ter-parse oleh versi baru dan sebaliknya).

**Fix (docs, test/golden/, test).** (1) `docs/schema-registry.md` —
registry RESMI untuk SEMUA skema JSON mesin: `myc.result.v1`
(`--json-summary`), `myc.agent.v2` (`--agent`), `myc.calibration.v1`
(`.myc/calibration.json`), evidence cache (`.myc/evidence_cache.json`),
`myc.scenario.v1` (profil), `myc.spec.v1` (pack project-local), MCP
JSON-RPC 2.0 envelope — plus aturan perubahan (field lama tidak dihapus;
field baru additive; enum append-only; setiap perubahan = update golden +
test hijau). (2) Delapan golden file di `test/golden/` — instance kanonik
tiap skema, diselaraskan dengan output serializer NYATA (capture live
`--json-summary`/`--agent` pada fixture). Temuan selaras: summary
`assurance_vector` = peta flat `"C":"clean"` sedangkan serializer penuh
`--json` (`myc_result_to_json`) = bentuk nested `{"status":...}` — DUA
skema berbeda, masing-masing dibekukan di registry. (3)
`test/schema_compat.c` (blok 18 `_audit018.sh`) — 224 cek: T1 semua
golden ter-parse (tidak busuk); T2/T3 field + tipe + enum
`myc.result.v1`/`myc.agent.v2` dalam himpunan beku; T4–T7 konsumen nyata
(`myc_calib_read_counts`, `myc_scenario_info`, `myc_pack_load`, pembaca
cache) MENERIMA golden; T8 fail-closed (INV-011): scenario `version` 2 =
profil user di-ignore, spec `version` 99 = fail-fast -1, cache verdict
out-of-range + sidecar SAH = dikarantina + file di-heal, calib korup = 0
entry tanpa crash; T9 additive-only (field asing pada golden TETAP
diterima konsumen lama); T10 produsen (`myc_result_to_json`,
`myc_agent_result_json`) masih memancarkan SEMUA field beku (backward
compat).

**Temuan realitas (dikoreksi ke perilaku aktual).** Kontrak terdokumentasi
scenario menyebut "profil invalid = return -2", tetapi jalur itu tidak
terjangkau: `effective_root` selalu mengembalikan profil bawaan (builtin
selalu ter-parse), sehingga profil user invalid (mis. `version != 1`)
DI-IGNORE dengan fallback builtin — gates user tidak pernah di-apply dan
scenario user tak terlihat (return -1). Registry + test menyatakan
perilaku aktual ini, bukan kontrak yang dibayangkan.

**Verifikasi.** `schema_compat` hijau — 224 OK / 0 FAIL (blok 18
`_audit018.sh`); golden diselaraskan dengan capture live serializer;
`git diff --check` bersih; self-dogfood OK; regresi blok 1–17 tidak
disentuh (tidak ada perubahan perilaku runtime).

### MYC-AUDIT-048 (Batch PR-016) — MCP abuse & soak (P4-T04)

**Gap.** `mcp.exe` (server stdio JSON-RPC 2.0, jalur konsumsi harness
agent) belum pernah di-abuse sebagai proses yang TIDAK dipercaya: tidak
ada korpus protokol malformed, tidak ada huge-payload, tidak ada soak
1.000+ request, dan — yang paling penting — tidak ada test yang
membuktikan **stdout TETAP protocol-clean** (setiap baris adalah respons
JSON-RPC 2.0 sah; tidak ada log/diagnostik bocor ke stdout, yang akan
merusak framing klien MCP). P4-T04 juga menuntut verifikasi wrong-type
parameter tidak berperilaku diam-diam salah.

**Hardening (mcp.c).** `flags` tool `check` yang bukan array, atau entry
array yang bukan string, sebelumnya di-ABAIKAN diam-diam (`continue`;
flags string `"--run"` = gate run tidak pernah jalan tanpa pesan apa
pun) — silent misbehavior yang bisa mematikan gate tanpa sepengetahuan
pemanggil. Kini fail-fast `-32602 "Invalid params: 'flags' harus array
string"`, konsisten dengan kebijakan unknown-flag (MYC-AUDIT-016).

**BUG NYATA ditemukan (proc.c, uninitialized read).** `drain_assemble`
memaksa `total = 1` saat output kosong, lalu `memcpy` 0 byte — `buf[0]`
TIDAK pernah ditulis → hasil `stdout_shown=1` padahal `stdout_total=0`,
dengan 1 byte HEAP STALE (teramati `0x50` = 'P', sisa alokasi env
"PATH") di stdout DAN stderr. Ini uninitialized read pada jalur bersama
Windows+POSIX yang tidak terlihat oleh deadlock matrix (yang hanya
meng-assert `total`, bukan `shown` saat `total==0`); byte stale bisa
bocor ke laporan. Fix: output kosong → `shown=0` + string kosong.

**Deliverable.**

- `test/mcp_abuse.c` (blok 19 `_audit018.sh`; harness C men-link
  `proc.c + json.c`, menjalankan mcp.exe via `myc_proc_run` di tmp dir
  sendiri): **T0** stdin kosong → exit 0 + nol baris (EOF/cancellation);
  **T1** baseline 18 baris (init/ping/tools-list/version/policy/
  contracts/lint/check/repair/agent_check/unknown tool/parse error/
  jsonrpc-1.0/unknown flag/flags string/notification) → 16 respons
  protocol-clean, id di-echo, error code benar, structuredContent ada,
  stderr kosong; **T2** 39 kasus malformed per-kasus + canary ping
  (json invalid/truncated/root non-objek, jsonrpc/method/id tipe salah,
  unknown method, tools/call params/name/arguments salah, flags
  non-array/entry non-string/unknown, id null/string, dup key,
  notifikasi valid → tanpa respons, notifikasi tanpa method → -32600);
  **T3** huge payload ~7,9 MiB (< cap 8 MiB) dan ~9 MiB (> cap, drain)
  → Parse error -32700 + canary tetap dijawab; **T4** duplicate request
  id → semua dijawab (stateless); **T5** notification vs request;
  **T6** ordering 20 ping; **T7** soak 1.090 request (1.000 ping + 30
  notifikasi + 20 version + 10 policy + 5 lint + 5 contracts + 5 check
  + 2 repair + 2 agent_check + 3 unknown tool + 8 malformed) → tepat
  1.060 respons (1.049 result + 11 error dgn code tepat), semua id
  ping 1..1000 hadir, exit 0, stderr kosong.

**Verifikasi (Windows).** `mcp_abuse` hijau — 0 FAIL (blok 19
`_audit018.sh`), `-Werror -pedantic` bersih; mcp.exe rebuilt dengan
hardening; self-dogfood mcp.c/proc.c OK; `git diff --check` bersih;
regresi lain tidak disentuh (perubahan runtime: hanya flags fail-fast
yang kini menolak tipe salah — input sah tidak berubah; fix
`drain_assemble` hanya mengubah hasil output-kosong dari shown=1 stale
menjadi shown=0).

Batas jujur: (1) soak = batch sekaligus (feed stdin + baca stdout),
bukan interaktif request-response per pesan — perilaku protokol sama
karena server stateless dan newline-delimited; (2) huge payload diuji
hingga 9 MiB (di atas cap 8 MiB); payload yang lebih besar tunduk pada
`MYC_MAX_STDIN_BYTES` 8 MiB pada pemanggil (proc) — mcp sendiri
men-drain tanpa batas; (3) tidak ada fuzzing protokol (itu wilayah
PR-010 parser fuzz); korpus di sini deterministik per-kasus.

### MYC-AUDIT-049 (Batch PR-017) — Backend qualification registry (P5-T01 + P5-T02)

**Gap.** myc menemukan dan memanggil banyak backend eksternal (gcc,
clang, frama-c, filc-clang, cross-gcc) tapi tidak ada SATU kebijakan
resmi yang menyatakan tier dukungan, versi minimum, evidence yang
diekstrak, dan failure semantics per backend; identitas backend (path +
versi exact) tersebar di `myc version` (sebagian) dan laporan per gate.
`myc canary run` (Fase 6) sudah membuktikan backend HIDUP, tetapi
registry identitas terpusat tidak ada — pengguna tidak bisa melihat
sekali lihat: backend mana yang didukung (tier A/B/C), versi apa yang
terpasang, dan apakah canary-nya lulus. Ini juga menghalangi kebijakan
P5-T02 (backend qualification sebelum menerima evidence).

**Deliverable.**

- `canary.h/c`: **backend policy table** `POLICIES[]` (13 backend:
  compile/analyzer/run/driver/exhaustive/fuzz/mutate/stack/lint/
  checked/prove/filc/matrix) — tiap entri: `exe` utama (NULL = internal),
  `tier` (A = release-blocking, B = supported non-blocking, C =
  best-effort), `min_version`, `evidence`. API baru: `myc_backend_probe_run`
  (resolve path + versi exact via `myc_find_executable` +
  `myc_tool_version`; backend WSL-only prove/filc jujur ditandai
  `found=2` "via WSL" bila `wsl.exe` ada), `myc_backend_probe_free`,
  `myc_backends_report` (cetak registry; `run_canary` menjalankan canary
  per backend dan menandai PASS/FAIL — kualifikasi P5-T02).
- `myc backends [--canary]` di `myc.c` (usage + dispatch): NON-blocking
  (registry = laporan, verdict target tidak berubah).
- `docs/backends.md` — kebijakan resmi P5-T01: tabel tier/OS/versi
  minimum/evidence/failure semantics + 6 aturan kebijakan (Tier A tidak
  boleh senyap; Tier B ketiadaan jujur; Tier C observasi; identitas
  backend = evidence INV-013; canary = bukti hidup P5-T02; tidak
  menjanjikan dukungan universal) + host-vs-target distinction (P6-T01).
- Wire blok 20 di `test/_audit018.sh` (header + blok): `myc backends`
  mencantumkan compile/run tier A + versi exact + "13 backend
  terdaftar", dan `myc backends --canary` → compile PASS (kualifikasi
  canary per backend cepat; swarm 11/11 penuh tetap diuji di
  `_ci_linux.sh`/`_regress_run.bat` Fase 6).
- Docs: capabilities.md row `backends`, AGENTS.md (rentang audit
  001..049 + row canary.c + pointer docs/backends.md).

**Verifikasi (Windows).** `myc backends` mencantumkan 13 backend:
compile/analyzer/driver/exhaustive/fuzz/mutate/stack → tier A/B + path
`gcc.exe` + versi exact `15.2.0`; run → tier A + `clang 22.1.6`;
lint/checked internal (tanpa binary eksternal); prove/filc → "via WSL
(wsl.exe tersedia)" (jujur, bukan "tidak ditemukan" yang menyesatkan
pengguna WSL); matrix → executable tidak ditemukan (honest).
`myc backends --canary` → compile PASS + canary qualification: SEMUA
backend terverifikasi hidup. Blok 20 `_audit018.sh` hijau (3 cek
terisolasi lulus); `-Werror` myc.c/canary.c bersih; self-dogfood OK;
`git diff --check` bersih.

Batas jujur: (1) versi minimum di tabel kebijakan adalah DEKLARASI
kebijakan (belum di-enforce sebagai gate pemilih tool — bila gcc < 9
terpasang, gate compile tetap jalan dengan perilaku lama; enforcement
versi minimum = wilayah PR-027 `--production` + P5-T03 version-drift
lane). (2) `found=2` (via WSL) hanya membuktikan `wsl.exe` ADA — backend
sebenarnya (frama-c/filc-clang di dalam WSL) diverifikasi hidup oleh
canary/`--prove`/`--filc` saat gate dijalankan, bukan oleh probe. (3)
`myc backends --canary` menjalankan canary per backend yang PUNYA canary
(compile..lint); prove/filc/matrix/checked tidak punya canary (backend
opsional, diuji lewat fixture gate) — tercantum jujur tanpa status
canary.

### MYC-AUDIT-050 (Batch PR-018) — Resource ceilings (P7-T01)

**Gap.** myc menerima input eksternal dan memproses work secara
kombinatorial/algoritmik, tetapi kapasitas internal (panjang source,
stdin, output, timeout, jumlah evidence/debt/contract/driver record,
arena, dst.) adalah makro `MYC_MAX_*` yang tersebar di source tanpa
tabel kebenaran tunggal yang bisa diaudit pengguna atau diuji CI.
Debt domain terbatas (driver combinatorial budget, dsb.) sudah TERTYPE
tetapi belum ada satu sumber yang mendokumentasikan semua batas + kelas
enforcement (HARD = ingress fail-fast vs soft = cap + debt) dan belum
diuji deterministik sebagai jalur NYATA.

**Deliverable.**

- `limit.h/limit.c`: tabel `LIMITS[]` 29 entri (max_source/stdin/
  output/cap/timeout/diagnostics/gates/evidence/debt/contract/rel/
  driver/filc/assumptions/sm/rsrc/units/coaching/witness/divergence/
  matrix/arena) + `myc_limits_table` / `myc_limits_report` /
  `myc_limits_report_json`. API baru `myc limits [--json]`.
- `myc.h`: enum `MYC_DEBT_RESOURCE_LIMIT` (tipe debt baru, sinkron
  additive — `unverified_debt` array, golden PR-015 tidak pecah).
- `gate.c`: nama "resource_limit" + kode "MYC-INCOMPLETE-RESOURCE-LIMIT"
  + trigger `myc_build_debt` (driver_bounded, driver_case_count ==
  MYC_MAX_DRIVER_RECORDS, evidence == MYC_MAX_EVIDENCE,
  contract_clauses == MYC_MAX_CONTRACT_CLAUSES, diag == MYC_MAX_DIAGNOSTICS)
  hanya saat gate relevan berjalan.
- `myc.c`: usage `myc limits [--json]` + dispatch setelah blok backends
  (flag tak dikenal → exit 2).
- `test/receipt_vectors.c`: case `MYC_DEBT_RESOURCE_LIMIT` di
  `ref_debt_name` (sinkronisasi enum debt 3 titik).
- Wiring `limit.c` di build.sh/build.bat/_ci_linux.sh/_regress_run.bat/
  _audit018.sh.
- Blok 21 di `test/_audit018.sh`: `myc limits` HARD max_source_bytes
  1 MiB + soft max_driver_records + "29 resource limit terdefinisi"
  (FREEZE jumlah tabel — menambah/mengurangi entri LIMITS[] WAJIB update
  cek ini, pola golden "13 backend" blok 20) + `--json` schema
  myc.limits.v1 + id pertama + flag tak dikenal exit 2.
- Debt TERTYPE diuji JALUR NYATA driver_bounded
  (`ok_driver_bounded.c --driver`): MYC-INCOMPLETE-RESOURCE-LIMIT muncul
  sambil verdict TETAP OK (NON-blocking, trust rule 1); `--require-complete`
  menaikkan ke INCONCLUSIVE (pola 9.10).

**Verifikasi (Windows).** `myc limits` → 29 baris HARD/soft;
`myc limits --json` → schema myc.limits.v1 count=29; `--bogus` → exit 2.
`myc check test/fixtures/ok_driver_bounded.c --driver` → verdict OK +
debt MYC-INCOMPLETE-RESOURCE-LIMIT (NON-blocking); dengan
`--require-complete` → INCONCLUSIVE. Receipt deterministik
(`receipt_sha256: 823efef9ce57efe0b2d95f9451461cab3cf7130c7ec8b3716ece62881a056829`)
stabil 3 run termasuk cache replay. Blok 21 `_audit018.sh` hijau (8 cek
lulus); `bash -n` kedua script CI bersih; bat/_ci_linux diff hanya
+limit.c; `git diff --check` bersih; self-dogfood OK; `-Werror` bersih.

Batas jujur: (1) `myc limits` adalah TABEL KEBENARAN (deklarasi kebijakan)
— enforcement aktual terjadi di kode gate masing-masing (HARD = ingress
fail-fast di myc.c, soft = cap + debt di gate.c), tabel tidak menambah
enforcement baru, hanya mendokumentasikan. (2) entri arena dicantumkan
dari makro arena; bukan pemanggilan api arena. (3) 29 entri adalah snapshot
makro saat rilis; bila makro kapasitas baru ditambah di rilis mendatang,
tabel + cek 21 harus diperbarui bersamaan (freeze pola golden).

### MYC-AUDIT-051 (Batch PR-019) — Allocator wrapper formal (P7-T02)

**Gap.** Uji OOM sebelumnya bergantung pada GNU `ld --wrap` untuk
menyuntikkan kegagalan alokasi di seluruh pipeline; itu (a) tidak portabel
ke semua toolchain (MSVC/MinGW tanpa `--wrap`), dan (b) menyuntik pada
level libc sehingga hook tidak bisa dikontrol per-proses secara eksplisit.
Selain itu alokasi mentah `malloc/calloc/realloc/free` tersebar di ~850
situs source tanpa jalur butir verifikasi yang menunjukkan SEMUA alokasi
pakai pembungkus konsisten (agenda memory-safety: semua alokasi harus
dilewatkan ke satu tempat untuk OOM injection deterministik tanpa
dependensi linker).

**Deliverable.**

- `alloc.h/alloc.c`: wrapper FORMAL `myc_malloc/calloc/realloc/free`.
  Produksi = passthrough libc (`#ifndef MYC_ALLOC_TEST`). Build
  `-DMYC_ALLOC_TEST` mengaktifkan hook: `myc_alloc_set_fail_after(N)` —
  N alokasi pertama sukses, sisanya NULL; `myc_alloc_fail_count` /
  `myc_alloc_call_count` untuk observasi. OOM injection deterministik tanpa
  GNU `ld --wrap`.
- `test/_migrate_alloc.py`: tokenizer C-aware (string/char/line/block
  comment di-parse; penggantian hanya di CODE context bila identifier
  langsung diikuti `(`; ~~dilindungi~~ member access `x->free` / `x.free`
  via scan-back `.`/`->`). Migrasi penuh 853 situs (alokasi + free) di
  semua `.c` pipeline; `json_free(`, `myc_result_free`, `.free(`/`->free(`
  dan string literal & komentar TIDAK tersentuh.
- `myc.h`: `#include "alloc.h"` (setelah `<stdint.h>`);
  `json.c`/`persist.c`/`policy.c`/`sha256.c`/`testaudit.c` menambah
  `#include "alloc.h"` (5 file tanpa jalur transitif ke alloc.h).
- Wiring `alloc.c`: build.sh/build.bat PIPELINE; `_ci_linux.sh`;
  `_regress_run.bat` (8× `persist.c limit.c` → `+alloc.c` +
  `taxonomy.c` stress via python); `_audit018.sh` SRCS + build
  proc_flood/verify_descendants/proc_deadlock_matrix/proc_tree_kill/
  mcp_abuse.
- Blok 22 di `test/_audit018.sh`: grep bebas-komentar/string/file
  `alloc.c` memverifikasi tak ada panggilan `malloc/calloc/realloc/free`
  mentah di source selain implementasi wrapper + `alloc.c` menyediakan
  `myc_alloc_set_fail_after` dan `MYC_ALLOC_TEST`.
- `test/oom_alloc.c` ditulis ulang memakai hook `myc_alloc` (skor 0):
  fail_after ∈ {1,2,3} + injeksi lewat `--test-build` tidak lagi butuh
  `--wrap`.

**Verifikasi (Windows).** `build.bat` sukses (myc.exe/mcp.exe/argv_probe).
Self-dogfooding: 46 source pipeline `myc check` → verdict OK.
`test/oom_alloc` (MYC_ALLOC_TEST) lulus 65 titik OOM (fail_after dari
 sebelum aman ke rawan, tak ada crash/corruption). `test/proc_flood`
 (deadlock/flood/env) OK. Block 22 grep bersih; `git diff --check` bersih;
 LF-kanonik dipertahankan (migrasi + normalisasi LF seluruh file yang
termigrasi — CRLF yang tak sengaja masuk selama migrasi di-strip).

Batas jujur: (1) wrapper adalah passthrough produksi; perilaku
memory-safety tetap milik libc allocator — formalisasi adalah jalur injeksi
dan konsistensi, BUKAN garant allocator baru. (2) `myc_alloc_set_fail_after`
memakai counter global non-thread-safe (satu proses tes satu thread);
test concurrency OOM belum (hanya alokasi normal). (3) migrasi 853 situs
otomatis memakai tokenizer heuristik — telah diverifikasi sampel + audit
compile seluruh source (build + dogfooding OK), tapi ideal audit sintaksis
penuh bila ada callback/function-pointer alokasi yang lolos tokenizer.

### MYC-AUDIT-052 — Fix stack-reuse bug di stdin writer proc.c + _POSIX_C_SOURCE persist.c

**Gejala (CI Linux hang, reproduksi WSL).** CI Linux macet ~50 menit di step
`_ci_linux.sh` "Build + trust-core POSIX" (baseline 4 menit; Windows job
SUCCESS). Reproduksi WSL: `./myc check tests/ok_hello.c` → `verdict: TIMEOUT`
seketika (`duration: 0 ms`, preprocess inconclusive "preprocess timeout"),
padahal `gcc -E` langsung via pipe selesai 0.06s. Tes isolasi `myc_proc_run`
(gcc -E stdin) hang menunggu timeout penuh (15s): child `cat`/`wc -c`/`gcc -E`
tidak pernah menerima EOF stdin → writer stdin tidak menulis/menutup.

**Akar masalah 1 — stack reuse `warg` (proc.c POSIX).** `warg`
(`stdin_writer_arg`) dideklarasikan sebagai variabel STACK di dalam blok
`if (req->stdin_len > 0)` di `proc_run_posix`, lalu pointer-nya di-pass ke
`stdin_writer_thread` via `pthread_create`. Setelah blok `if` selesai, live
range `warg` berakhir → kompiler bebas memakai ulang slot stack-nya; di
proses ini GCC menaruh `struct timespec ts = {0, 10 * 1000000}` (wait loop)
tepat di slot itu. Thread writer masih memegang pointer ke slot → membaca
`w->fd = ts.tv_sec = 0` (write ke fd 0 → EBADF, data tidak pernah tertulis)
dan `w->data = ts.tv_nsec = 10.000.000 = 0x989680` (hexdump membuktikan:
parent melihat `fd=4, data=0x55f2c381f00c, len=26`, thread melihat
`fd=0, data=0x989680, len=26` — hanya `len` yang selamat karena timespec
16 byte < offset len 16). Akibat: `in_pipe[1]` tidak pernah ditutup → child
menunggu EOF selamanya → timeout. Bug laten (sejak PR-006 memperkenalkan
writer thread) yang baru TERPICU setelah PR-019 menggeser layout stack.
Windows tidak kena: `warg` di scope fungsi `proc_run_win` (bukan blok if).

**Fix 1.** `warg` dialokasikan di HEAP (`myc_malloc`) di kedua platform
(POSIX + Windows, konsisten menghilangkan kelas bug ini), dibebaskan oleh
parent SETELAH join writer (`myc_free(warg)` + null-kan). Jalur error
`pthread_create`/`_beginthreadex` gagal ikut membebaskan.

**Akar masalah 2 — `fileno` implicit declaration (persist.c Linux).**
`persist.c:217` `fsync(fileno(f))` gagal compile di Linux dengan `-std=c11`
(glibc mengekspos `fileno` hanya di bawah `_POSIX_C_SOURCE`). Di Windows
MSVC tersedia default → hanya Linux kena: `myc check persist.c` =
COMPILE_ERROR → self-dogfooding CI Linux FAIL. Pola sama seperti proc.c /
proc_fixture.c yang sudah `#define _POSIX_C_SOURCE 200809L`.

**Fix 2.** Tambah `#define _POSIX_C_SOURCE 200809L` di atas include
persist.c (komentar referensi MYC-AUDIT-052).

**Verifikasi.**
- WSL (gcc 13.3): build.sh bersih; `myc check tests/ok_hello.c` → OK 31ms;
  `myc check myc.c` → OK 549ms (sebelumnya TIMEOUT seketika); self-dogfooding
  **48/48 source → verdict OK**; tes isolasi `cat` stdin → `ok=1 timed_out=0
  dur=10ms` (sebelumnya hang 15s).
- Windows: build.sh OK; `-Werror` prove.c OK; self-dogfooding 48/48 OK;
  gates inti: ok_hello OK, ok_run --run OK, bad_run_oob --run
  RUNTIME_VIOLATION.
- `git diff --check` bersih; file debug sementara (test/_dbg_*) dihapus.

**Follow-up (CI Linux run #31778543792, commit 5f97389).** Fix hang membuat
`_ci_linux.sh` jalan sampai selesai (`PASS=209 FAIL=1`) dan MENGEKSPOS bug
build fixture yang pra-ada (tersembunyi selama hang; run CI hijau terakhir
`aa9899d` TIDAK punya section fixture ini di `_audit018.sh` — grep=0, jadi
section backend_fake/receipt_vectors/mcp_abuse/proc_deadlock_matrix belum
pernah dieksekusi sukses di CI Linux):
- `_POSIX_C_SOURCE 200809L` hilang di 5 fixture (pola sama spt proc.c /
  proc_fixture.c): proc_deadlock_matrix.c (kill), backend_fake.c (readlink),
  backend_abuse.c (setenv/strdup), parser_fuzz.c (setenv/strdup),
  receipt_vectors.c (strdup).
- `backend_abuse.c`: `myc_getpid` hanya di-define untuk _WIN32 — tambah
  `#define myc_getpid getpid` di cabang POSIX.
- glibc menandai `chdir` warn_unused_result (glibc 2.39/ubuntu-24.04):
  schema_compat.c (restore cwd), mcp_abuse.c (change_dir), backend_abuse.c
  (2 situs), parser_fuzz.c (chdir_one macro + write di crash_handler).
- Verifikasi: `_audit018.sh` penuh SELESAI OK di WSL (semua section hijau:
  proc_deadlock_matrix, backend_fake/abuse, parser_fuzz, receipt_vectors,
  schema_compat, mcp_abuse, limits, allocator); 7 fixture build OK dengan
  flag persis script di Windows juga; `git diff --check` bersih.

### MYC-AUDIT-053 (qwen-review IDE-1, T1) — Sanitizer Location Extractor

**Celah (qwen-review §3.2, KRITIS).** Gate runtime — satu-satunya gate yang
pasti menangkap bug heap/UB — MEMBUANG informasi lokasi. Report ASan/UBSan
(log_path, non-spoofable) dibaca lengkap (`proc.c myc_read_sanitizer_report`),
tapi isinya hanya di-`strstr` untuk marker (`run.c report_marker_of`);
sisanya dihapus. Agent menerima `RUNTIME_VIOLATION` tanpa file/baris/fungsi
→ repair loop jadi tebakan. Baseline: 0% lokasi benar.

**Fix.** Modul baru `sanloc.c`/`sanloc.h` (`myc_sanloc_extract`): parse
report sanitizer murni string scan (deterministik, tanpa subproses):
- `violation_kind` presisi dari `==NN==ERROR: AddressSanitizer: <kind>`
  (fallback `SUMMARY:`; UBSan → `undefined-behavior`).
- `location` = frame `#N ... in FN FILE:LINE` PERTAMA yang file-nya milik
  target (skip frame runtime: dll/vctools/KERNEL32/ntdll/compiler-rt).
- `allocation` = frame target pertama pada blok `freed by` /
  `previously allocated by` / `allocated by` (heap/UAF); stack-buffer
  overflow TIDAK mengisi allocation (bukan heap — anti-overclaim).
- UBSan `FILE:LINE:COL: runtime error:` → line + col langsung.
- Remap line bila kontrak requires di-inject (`build_src != source`):
  hitung jumlah baris tambahan (include assert + assert per fungsi)
  sebelum baris laporan, kurangi — snippet diambil dari source ASLI.
- `target_file` default `"<stdin>"` (build via stdin; frame memuat
  path absolut + `<stdin>`); fallback basename source.

**Wire.** `run.c myc_run_gate` (blok finding) + `myc_metamorphic_gate`
(simpan report build pertama yang menemukan, ekstrak saat verdict
RUNTIME_VIOLATION). Field baru `sanloc_*` di `myc_result` (arena):
`sanloc_have/kind/line/col/function/file/alloc_line/alloc_function/snippet`.
Witness diisi: `violation_line`, `operation` (fungsi + baris), `pre_state`
(baris free/allocation). JSON (`myc_report_json_summary` + `myc_result_to_json`)
memancarkan `sanitizer_location` {violation_kind, location{line,col?,function},
allocation{line,function}?, snippet} — ADDITIVE, verdict tidak pernah berubah.
Context `SEC_WITNESS` menampilkan `line:`.

**Anti-overclaim.** Report tanpa frame target → `sanloc_have=0`, line=0
(tidak pernah menebak); kind tetap additive. Driver tidak di-wire: harness
menggeser nomor baris source (bukan source asli) → lokasi menyesatkan.

**Verifikasi.**
- Unit `test/sanloc_test.c` (8 kasus × 33 CHECK, fixture deterministik tanpa
  clang): stack/heap/UAF/UBSan, skip frame runtime, remap inject (5→3),
  anti-overclaim, path Windows+`<stdin>`. Build `-Werror -pedantic` bersih
  di Linux (WSL) dan Windows.
- E2E: `myc check <strcpy> --run` → `sanitizer_location`
  {kind: stack-buffer-overflow, location{line:3, fn:copy}, snippet
  "strcpy(dst, src);"}; heap → allocation{line:7, fn:main}; UAF via fungsi →
  location{line:8, fn:use} + allocation{line:5, fn:make}; UBSan → line+col;
  stdin `-` dan kontrak inject remap benar. `_schema_golden.sh` PASS 14/14
  (cek baru IDE-1 pada bad_run_oob → SANLOC_OK line=11).
- `_audit018.sh` penuh SELESAI OK di WSL (sanloc_test hijau);
  `_regress_run.bat` penuh Windows EXIT=0, 625 [OK] 0 [FAIL] — sekalian
  memperbaiki bug batch cmd pra-ada: `)` di `echo ...(...)` menutup blok
  `if (...)` lebih awal sehingga `else` ikut tereksekusi (pola sama di
  reducer_exhaustive) → pesan echo tanpa kurung.
- Self-dogfood: sanloc.c/run.c/report.c/context.c/myc.h → verdict OK;
  `gcc -Werror -pedantic` sanloc.c bersih; `git diff --check` bersih.

### MYC-AUDIT-054 (qwen-review IDE-5 + IDE-4, T2) — fix `--scenario auto` + replay regression pasca-repair

**IDE-5 (celah §3.3, MEDIUM).** `--scenario auto` salah tebak kelas parser:
file ber-`main` dengan loop `fgets`+`strtol` (pola parser klasik) diklasifikasi
`cli-daily` (compile+run+analyzer), bukan `parser` (fuzz+run) — verifikasi
kurang dalam pada hazard yang paling relevan untuk input tak terduga.

**Fix.** `scenario.c detect_auto` menambah sinyal `is_parser`: loop baca stdin
(`fgets`/`fread`/`scanf`/`getchar`/`read(`) DAN panggilan parsing
(`strtol`/`strtod`/`sscanf`/`isdigit`/`strchr`/`strtok`). Prioritas resep D3:
firmware > parser > library (kontrak) > cli-daily. Tetap substring
(deterministik, murah), NON-blocking, `why` dilaporkan di scenario_report.

**Verifikasi IDE-5.** Fixture baru `test/fixtures/scen_input_parser.c`
(fgets+strtol+main) → `scenario (C5): parser`; `scen_parser.c` tetap
`library`, `mmio_bad.c` tetap `firmware` (tidak regress). Cek ditambah di
`test/_ci_linux.sh` (blok C5), `test/_regress_run.bat`, dan
`.github/workflows/ci.yml`.

**IDE-4 (celah §4, P1).** Mencegah pola klasik LLM: memperbaiki bug A sambil
menghidupkan kembali bug B. Sebelumnya `repair` (MCP) hanya mengembalikan
patch template + `applied_verdict`; tidak ada replay corpus pasca-repair.

**Fix.**
- `regress.c`: refactor `regress_run_one` → `regress_run_src` (jalankan gate
  terhadap buffer memori) + API publik baru `myc_regress_replay_mem`:
  replay seluruh corpus (kind + seed PRNG dari index) terhadap source
  IN-MEMORY, mengisi `total/resolved/failing`. NON-blocking.
- `mcp.c tool_repair`: param opsional `patched_source` (kode baru setelah
  patch diterapkan). Bila verdict kode baru = `OK`, myc me-replay corpus
  terhadap kode itu dan melampirkan `regression_replay` di
  `structuredContent` (schema `myc.repair.v1`) + text: `1/1 clean`;
  bila ada seed yang masih gagal → debt eksplisit `N masih gagal (bug
  lama hidup kembali)`. Corpus kosong → `corpus kosong (0 seed)`
  (anti-overclaim: tidak pernah "clean" palsu). Catatan: check di repair
  compile-only (`run_lint`), jadi yang menentukan replay adalah verdict
  KODE BARU (source runtime-buggy tetap punya verdict OK di check).

**Verifikasi IDE-4.**
- Unit `test/regress_replay_test.c` (5 kasus × 12 CHECK): seed fuzz_div0
  tersimpan otomatis → replay source buggy = masih gagal → replay source
  fixed = RESOLVED → corpus kosong 0/0 → deterministik (dua panggilan
  identik = hasil sama). Build `-Werror -pedantic` bersih Linux (WSL)
  + Windows; cleanup penuh (tanpa leftover `.myc`).
- E2E MCP: repair dengan `patched_source` versi fixed →
  `regression_replay: 1/1 clean`; versi masih-buggy → `2 masih gagal`.
  Cek di `_ci_linux.sh` (6f, source semantik penuh) dan `_regress_run.bat`
  (6f, source bebas karakter khusus `<>&` karena `^` escape cmd tidak
  berlaku di dalam double-quote — catatan terdokumentasi).
- `_audit018.sh` penuh SELESAI OK di WSL (sanloc_test + regress_replay_test
  hijau); self-dogfood scenario.c/regress.c/mcp.c/regress.h → verdict OK;
  `git diff --check` bersih.
