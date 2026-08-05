@echo off
setlocal
rem Guard anti-false-OK: gagal cepat bila myc salah melaporkan OK (MYC-AUDIT-031).
call test\_anti_false_ok.bat || exit /b 1
set OUT=test\_tmp_run_out.txt
echo --- Fase 5 reentrancy (MYC-AUDIT-008): myc_run paralel bebas race/stale
gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test\stress_threads.exe test\stress_threads.c myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c gate.c negative.c >nul 2>&1
if exist test\stress_threads.exe (
  test\stress_threads.exe | findstr "no race" >nul && echo [OK] stress_threads deterministik, no race || echo [WARN] stress_threads race/stale (stress test; lihat issue)
) else (
  echo [WARN] stress_threads gagal dibangun (stress test; lihat issue)
)
del test\stress_threads.exe 2>nul
echo --- Fase 6 JSON ketat (MYC-AUDIT-009): corpus valid/invalid tak crash
gcc -O2 -std=c11 -Wall -Wextra -I. -o test\json_abuse.exe test\json_abuse.c json.c >nul 2>&1
if exist test\json_abuse.exe (
  test\json_abuse.exe | findstr "OK" >nul && echo [OK] json_abuse corpus ketat lulus || echo [WARN] json_abuse corpus gagal
) else (
  echo [WARN] json_abuse gagal dibangun
)
del test\json_abuse.exe 2>nul
echo --- Fase 1 streaming evidence detector: sanitizer marker terdeteksi pada output streaming
myc.exe check tests\bad_run_oob.c --run > %OUT%
findstr /C:"sanitizer:" %OUT% >nul && echo [OK] streaming evidence detector mencatat sanitizer marker || echo [INFO] sanitizer tidak terdeteksi (bukan fixture sanitizer)
echo --- Fase-2 canonical ingress: unknown CLI flag ditolak fail-fast
myc.exe check tests\ok_hello.c --rnu > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] unknown flag --rnu ditolak exit2 failfast
) else (
  echo [WARN] unknown flag --rnu tidak ditolak harus exit2 ec=%ERRORLEVEL%
)
findstr /C:"unknown option: --rnu" %OUT% >nul && echo [OK] pesan unknown option tampil || echo [WARN] pesan unknown option hilang
myc.exe check tests\ok_hello.c --run --json > %OUT% 2>&1
if errorlevel 1 (
  echo [WARN] flag valid --run justru gagal regresi ingress
) else (
  echo [OK] flag valid --run tetap diterima
)
myc.exe check tests\ok_hello.c --run-stdin > %OUT% 2>&1
findstr /C:"--run-stdin membutuhkan argumen" %OUT% >nul && echo [OK] --run-stdin tanpa argumen ditolak || echo [WARN] --run-stdin tanpa argumen tidak ditolak
del %OUT%
echo --- MYC-AUDIT-020: CLI --timeout/--output-cap (validasi + fail-fast angka)
myc.exe check tests\ok_hello.c --timeout 5000 > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] --timeout valid diterima || echo [WARN] --timeout valid ditolak
myc.exe check tests\ok_hello.c --timeout -1 > %OUT% 2>&1
findstr /C:"invalid_timeout" %OUT% >nul && echo [OK] --timeout negatif ditolak (invalid_timeout) || echo [WARN] --timeout negatif tidak ditolak
myc.exe check tests\ok_hello.c --timeout 999999999 > %OUT% 2>&1
findstr /C:"invalid_timeout" %OUT% >nul && echo [OK] --timeout overflow ditolak (invalid_timeout) || echo [WARN] --timeout overflow tidak ditolak
myc.exe check tests\ok_hello.c --timeout abc > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] --timeout non-angka ditolak exit2 failfast
) else (
  echo [WARN] --timeout non-angka tidak ditolak ec=%ERRORLEVEL%
)
findstr /C:"--timeout: nilai bukan angka" %OUT% >nul && echo [OK] pesan --timeout non-angka tampil || echo [WARN] pesan --timeout non-angka hilang
myc.exe check tests\ok_hello.c --output-cap 5000 > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] --output-cap valid diterima || echo [WARN] --output-cap valid ditolak
findstr /C:"max_output_bytes: 5000" %OUT% >nul && echo [OK] max_output_bytes mengalir ke capsule report || echo [WARN] max_output_bytes tidak tampil di report
myc.exe check tests\ok_hello.c --output-cap -5 > %OUT% 2>&1
findstr /C:"invalid_output_cap" %OUT% >nul && echo [OK] --output-cap NEGATIF ditolak (bug AUDIT-020 fix) || echo [WARN] --output-cap negatif lolos validasi
myc.exe check tests\ok_hello.c --output-cap 104857601 > %OUT% 2>&1
findstr /C:"invalid_output_cap" %OUT% >nul && echo [OK] --output-cap melebihi 100MiB ditolak || echo [WARN] --output-cap besar tidak ditolak
myc.exe check tests\ok_hello.c --output-cap abc > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] --output-cap non-angka ditolak exit2 failfast
) else (
  echo [WARN] --output-cap non-angka tidak ditolak ec=%ERRORLEVEL%
)
myc.exe check tests\ok_hello.c --output-cap 99999999999 > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] --output-cap overflow angka ditolak exit2 failfast
) else (
  echo [WARN] --output-cap overflow tidak ditolak ec=%ERRORLEVEL%
)
myc.exe check tests\ok_hello.c --cwd "" > %OUT% 2>&1
findstr /C:"invalid_cwd" %OUT% >nul && echo [OK] --cwd kosong ditolak (invalid_cwd) || echo [WARN] --cwd kosong tidak ditolak
del %OUT%
echo --- self-dogfooding: semua source myc harus OK
for %%f in (myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c mcp.c negative.c) do (
  echo === %%f
  myc.exe check "%%f" > %OUT%
  findstr /B /C:"verdict:" %OUT%
)
echo --- run fixtures (--run) harus RUNTIME_VIOLATION utk bad_run*
for %%f in (tests\ok_run.c tests\bad_run_oob.c tests\bad_run_uaf.c tests\bad_run_intovf.c test\fixtures\ok_contract.c test\fixtures\bad_contract_pre.c) do (
  echo === %%f
  myc.exe check "%%f" --run > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" %OUT%
)
echo --- dogfood ring
myc.exe check dogfood\dogfood_ring.c --run > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo --- dogfood config (tool dogfooding lintas-program kedua)
myc.exe check dogfood\dogfood_config.c > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
myc.exe check dogfood\dogfood_config.c --run > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo --- dogfood tilemap (tool dogfooding lintas-program ketiga)
myc.exe check dogfood\dogfood_tilemap.c > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
myc.exe check dogfood\dogfood_tilemap.c --run > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo --- prove fixtures (--prove): ok_prove harus L2, bad_prove harus PROVE_VIOLATION
for %%f in (test\fixtures\ok_prove.c test\fixtures\bad_prove.c) do (
  echo === %%f
  myc.exe check "%%f" --prove > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"prove:" /C:"  alarms:" %OUT%
)
echo --- checked fixtures (--checked): ok_checked harus L4, bad_checked harus COMPILE_ERROR
for %%f in (tests\ok_checked.c tests\bad_checked.c) do (
  echo === %%f
  myc.exe check "%%f" --checked > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"checked:" /C:"  build_ok:" %OUT%
)
echo --- checked oob (--run --checked): bad_checked_oob harus RUNTIME_VIOLATION, ok_checked tetap L4
echo === tests\bad_checked_oob.c
myc.exe check tests\bad_checked_oob.c --run --checked > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo === tests\ok_checked.c
myc.exe check tests\ok_checked.c --run --checked > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo === dogfood_ring.c --checked
myc.exe check dogfood\dogfood_ring.c --checked > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo === dogfood_ring.c --run --checked
myc.exe check dogfood\dogfood_ring.c --run --checked > %OUT%
findstr /B /C:"verdict:" /C:"assurance:" %OUT%
echo --- checked audit MYC-AUDIT-012: elem_size + checked multiplication
echo === tests\bad_checked_type.c --checked (tipe elemen salah -^> COMPILE_ERROR)
myc.exe check tests\bad_checked_type.c --checked > %OUT% 2>&1
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] bad_checked_type: tipe elemen salah ditolak compile-time || echo [WARN] tipe salah tidak jadi COMPILE_ERROR
echo === tests\bad_checked_new_overflow.c --run --checked (RUNTIME_VIOLATION)
myc.exe check tests\bad_checked_new_overflow.c --run --checked > %OUT% 2>&1
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] bad_checked_new_overflow: overflow MYC_NEW terdeteksi runtime || echo [WARN] overflow MYC_NEW tidak terdeteksi
findstr /C:"MYC_NEW overflow" %OUT% >nul && echo [OK] marker MYC_NEW overflow muncul || echo [WARN] marker overflow hilang
echo --- checked audit MYC-AUDIT-026: coverage count + semantics parity
echo === tests\semantics_parity.c --checked (L4 + coverage 2/2/6/2)
myc.exe check tests\semantics_parity.c --checked > %OUT% 2>&1
findstr /C:"buffers=2 allocations=2 accesses=6 frees=2" %OUT% >nul && echo [OK] checked coverage: 2 buffer 6 titik akses terhitung || echo [WARN] checked coverage count salah
findstr /C:"assurance: L4" %OUT% >nul && echo [OK] semantics_parity --checked -> L4 || echo [WARN] semantics_parity --checked bukan L4
echo === coverage ok_checked (1/1/2/1)
myc.exe check tests\ok_checked.c --checked > %OUT% 2>&1
findstr /C:"buffers=1 allocations=1 accesses=2 frees=1" %OUT% >nul && echo [OK] ok_checked coverage 1/1/2/1 || echo [WARN] ok_checked coverage count salah
echo === no over-claim: comment-only MYC_BUF harus di-skip, tanpa coverage
myc.exe check tests\checked_comment_only.c --checked > %OUT% 2>&1
findstr /C:"checked build di-skip" %OUT% >nul && echo [OK] comment-only MYC_BUF di-skip (no over-claim) || echo [WARN] comment-only MYC_BUF tidak di-skip
findstr /C:"  build_ok:" %OUT% >nul && echo [WARN] gate checked aktif padahal komentar saja || echo [OK] gate checked benar di-skip (no coverage)
echo === semantics parity: build produksi vs checked, stdout + exit identik
gcc -O2 -std=c11 -Wall -I. -o test\_parity_prod.exe tests\semantics_parity.c >nul 2>&1
gcc -O2 -std=c11 -Wall -I. -DMYC_CHECKED=1 -o test\_parity_ck.exe tests\semantics_parity.c >nul 2>&1
if not exist test\_parity_prod.exe ( echo [WARN] parity build produksi gagal ) else ( echo [OK] parity build produksi OK )
if not exist test\_parity_ck.exe ( echo [WARN] parity build checked gagal ) else ( echo [OK] parity build checked OK )
if exist test\_parity_prod.exe if exist test\_parity_ck.exe (
  test\_parity_prod.exe > test\_parity_prod.txt
  if errorlevel 1 ( echo [WARN] parity produksi exit!=0 ) else ( echo [OK] parity produksi exit=0 )
  test\_parity_ck.exe > test\_parity_ck.txt
  if errorlevel 1 ( echo [WARN] parity checked exit!=0 ) else ( echo [OK] parity checked exit=0 )
  fc /b test\_parity_prod.txt test\_parity_ck.txt >nul && echo [OK] semantics parity: stdout identik || echo [WARN] semantics parity: stdout berbeda
)
del test\_parity_prod.exe test\_parity_ck.exe test\_parity_prod.txt test\_parity_ck.txt 2>nul
del %OUT%
echo --- filc fixtures (--filc): di-skip bila Fil-C tak tersedia (non-blocking)
for %%f in (test\fixtures\ok_filc.c test\fixtures\bad_filc_oob.c) do (
  echo === %%f
  myc.exe check "%%f" --filc > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"filc:" /C:"  panics:" %OUT%
)
echo --- MYC-AUDIT-021: run_stdin diteruskan ke program Fil-C (WSLENV path translation)
echo halo-filc-stdin> test\_tmp_stdin.txt
myc.exe check test\fixtures\ok_filc_stdin.c --filc --run-stdin test\_tmp_stdin.txt > %OUT% 2>&1
findstr /C:"got:halo-filc-stdin" %OUT% >nul && echo [OK] run_stdin sampai ke Fil-C (WSLENV fix) || echo [INFO] run_stdin Fil-C tidak terlihat (Fil-C tak tersedia / bukan WSL)
del test\_tmp_stdin.txt
echo --- MYC-AUDIT-024: Fil-C version identity + robust report parser (roadmap 7.7)
myc.exe version > %OUT% 2>&1
findstr /C:"filc:" %OUT% >nul && echo [OK] myc version cetak status filc || echo [WARN] status filc hilang di myc version
myc.exe check test\fixtures\bad_filc_oob.c --filc > %OUT% 2>&1
findstr /C:"verdict:   FILC_VIOLATION" %OUT% >nul && echo [OK] bad_filc_oob FILC_VIOLATION || echo [INFO] bad_filc_oob --filc bukan violation - Fil-C tak tersedia
findstr /C:"filc: 1 panic -> bug memori terbukti (main @" %OUT% >nul && echo [OK] diagnostic panic memuat lokasi origin || echo [INFO] lokasi origin tidak ter-parse
findstr /C:"case #1:" %OUT% >nul && echo [OK] per-case scope ter-parse || echo [INFO] per-case panic tidak ter-parse
findstr /C:"  version: clang version" %OUT% >nul && echo [OK] filc version identity tampil || echo [INFO] filc version tidak tampil - Fil-C tak tersedia
myc.exe check test\fixtures\ok_filc.c --filc > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && findstr /C:"  panics: 0" %OUT% >nul && echo [OK] ok_filc bersih panics=0 || echo [INFO] ok_filc --filc bukan clean - Fil-C tak tersedia
del %OUT%
echo --- MYC-AUDIT-025: contract pure validation + explicit clause status + stable binding (roadmap 7.4)
myc.exe check test\fixtures\contract_clauses.c > %OUT% 2>&1
findstr /C:"contract clauses:" %OUT% >nul && echo [OK] report memuat daftar klausa eksplisit || echo [WARN] daftar klausa kontrak hilang
findstr /C:"(x = 0) != 0 [impure]" %OUT% >nul && echo [OK] ekspresi impure terdeteksi || echo [WARN] purity gate gagal mendeteksi impure
findstr /C:"helper(-5) > 0 [call]" %OUT% >nul && echo [OK] pemanggilan fungsi terdeteksi - status call || echo [WARN] purity gate gagal mendeteksi call
findstr /C:"n > 0 [ok]" %OUT% >nul && echo [OK] klausa pure berstatus ok || echo [WARN] klausa pure tidak berstatus ok
findstr /C:"(unbound" %OUT% >nul && echo [OK] klausa tak terikat ditandai unbound || echo [WARN] stable binding tidak bekerja
myc.exe check test\fixtures\contract_clauses.c --run > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] run bersih: impure/call TIDAK di-inject || echo [WARN] impure/call ikut di-inject - run harus bersih
myc.exe check test\fixtures\bad_contract_pre.c --run > %OUT% 2>&1
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] requires pure tetap di-inject - bad_contract_pre || echo [WARN] inject requires pure rusak
myc.exe check test\fixtures\contract_clauses.c --json > %OUT% 2>&1
findstr /C:"contract_clauses" %OUT% >nul && echo [OK] JSON memuat contract_clauses || echo [WARN] JSON contract_clauses hilang
rem --- fix review: ; membuang pending basi + komentar blok bukan klausa
myc.exe check test\fixtures\contract_stale_pending.c > %OUT% 2>&1
findstr /C:"requires=1" %OUT% >nul && echo [OK] klausa hantu dalam komentar blok tidak dihitung || echo [WARN] klausa hantu komentar ikut dihitung
findstr /C:"ghost" %OUT% >nul && echo [WARN] teks ghost bocor ke laporan || echo [OK] teks ghost tidak muncul
myc.exe check test\fixtures\contract_stale_pending.c --run > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] pending basi tidak ter-inject ke fungsi salah (fix ;) || echo [WARN] false inject pending basi ke dummy
del %OUT%
echo --- MYC-AUDIT-022: machine-readable diagnostic + exact tool identity (roadmap 7.1)
myc.exe version > %OUT% 2>&1
findstr /C:"gcc version:" %OUT% >nul && echo [OK] myc version cetak gcc version || echo [WARN] gcc version hilang di myc version
findstr /C:"clang version:" %OUT% >nul && echo [OK] myc version cetak clang version || echo [WARN] clang version hilang di myc version
myc.exe check tests\ok_hello.c > %OUT% 2>&1
findstr /C:"gcc_version:" %OUT% >nul && echo [OK] report memuat gcc_version || echo [WARN] gcc_version tidak tampil
myc.exe check tests\bad_realloc.c > %OUT% 2>&1
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] bad_realloc COMPILE_ERROR || echo [WARN] bad_realloc bukan COMPILE_ERROR
findstr /C:"used after 'realloc'" %OUT% >nul && echo [OK] diagnostic JSON gcc ter-parse terstruktur (line:col) || echo [WARN] diagnostic JSON gcc tidak ter-parse
rem MYC-AUDIT-023: cek LINE saja (bukan [17:12] eksak) — kolom bisa berbeda
rem antar toolchain gcc; pesan terstruktur sudah di-assert di atas.
findstr /C:"[17" %OUT% >nul && echo [OK] diagnostic JSON membawa baris sumber || echo [WARN] diagnostic JSON tanpa baris sumber
myc.exe check tests\ok_hello.c --json > %OUT% 2>&1
findstr /C:"gcc_version" %OUT% >nul && echo [OK] JSON memuat gcc_version || echo [WARN] JSON gcc_version hilang
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"clang_version" %OUT% >nul && echo [OK] JSON memuat clang_version (backend clang) || echo [WARN] JSON clang_version hilang
rem MYC-AUDIT-023: receipt memuat fingerprint (gcc_path+cwd) -> nilai golden
rem bersifat SPESIFIK-MESIN (CI runner punya path gcc beda). Invariant yang
rem portabel = DETERMINISME: dua run input sama -> receipt sama.
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
for /f "tokens=2" %%r in ('findstr /C:"receipt_sha256:" %OUT%') do set REC1=%%r
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
for /f "tokens=2" %%r in ('findstr /C:"receipt_sha256:" %OUT%') do set REC2=%%r
rem CATATAN: jangan taruh parens di teks echo dalam blok if (...) -- parser cmd
rem menghitung parens sehingga `(CI-portabel)` memutus blok (error: `)` tak terduga).
if not defined REC1 echo [WARN] receipt tidak terbaca
if defined REC1 if "%REC1%"=="%REC2%" echo [OK] receipt deterministik lintas-run, CI-portabel
if defined REC1 if not "%REC1%"=="%REC2%" echo [WARN] receipt tidak deterministik: %REC1% vs %REC2%
echo --- driver fixtures (D2.2, --driver): ok_driver harus OK, bad_driver_oob harus DRIVER_VIOLATION
for %%f in (test\fixtures\ok_driver.c test\fixtures\bad_driver_oob.c) do (
  echo === %%f
  myc.exe check "%%f" --driver > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"driver:" /C:"  funcs:" /C:"  cases:" %OUT%
)
echo --- MYC-AUDIT-017: saluran report sanitizer non-spoofable
myc.exe check tests\bad_run_oob.c --run > %OUT% 2>&1
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] bad_run_oob tetap RUNTIME_VIOLATION (report sanitizer) || echo [WARN] bad_run_oob tidak jadi violation
findstr /C:"sanitizer:" %OUT% >nul && echo [OK] evidence sanitizer (dari report log_path) terekam || echo [WARN] evidence sanitizer hilang
myc.exe check tests\spoof_marker_run.c --run > %OUT% 2>&1
findstr /C:"RUNTIME_VIOLATION" %OUT% >nul && echo [WARN] spoof marker jadi RUNTIME_VIOLATION || echo [OK] spoof marker --run TIDAK jadi violation
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] spoof marker tetap OK (exit 0, tanpa report) || echo [WARN] spoof marker bukan OK
findstr /C:"diabaikan" %OUT% >nul && echo [OK] diagnostic teks marker diabaikan muncul || echo [WARN] diagnostic spoof hilang
myc.exe check tests\bad_driver_spoof.c --driver > %OUT% 2>&1
findstr /C:"DRIVER_VIOLATION" %OUT% >nul && echo [WARN] spoof driver jadi DRIVER_VIOLATION || echo [OK] spoof driver TIDAK jadi violation
del %OUT%
echo --- unverified debt (Fase 4): debt hanya muncul utk scope yg TIDAK lengkap
set DEBT=none
myc.exe check test\fixtures\driver_zero_cases.c --driver > %OUT% 2>&1
findstr /C:"unverified_debt" %OUT% >nul && echo [OK] driver_zero_cases memunculkan unverified_debt
findstr /C:"generated driver diminta tapi 0 kasus" %OUT% >nul && echo [OK] debt nonzero_cases terdeteksi
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"unverified_debt" %OUT% >nul && echo [WARN] ok_run seharusnya tanpa debt || echo [OK] ok_run tanpa unverified_debt
del %OUT%
echo --- MYC-AUDIT-027: case record + combinatorial budget + harness sha
myc.exe check test\fixtures\ok_driver.c --driver > %OUT% 2>&1
findstr /C:"case records" %OUT% >nul && echo [OK] case records muncul di laporan || echo [WARN] case records hilang
findstr /C:"combinatorial: max_product=5 budget=32 strategy=full" %OUT% >nul && echo [OK] combinatorial full utk produk kecil || echo [WARN] combinatorial full hilang
findstr /C:"harness_sha256:" %OUT% >nul && echo [OK] harness_sha256 di laporan || echo [WARN] harness_sha256 hilang
findstr /C:"#1   ok_sum" %OUT% >nul && echo [OK] case record #1 berisi input+status || echo [WARN] case record #1 hilang
myc.exe check test\fixtures\ok_driver.c --driver --json > %OUT% 2>&1
findstr /C:"\"driver_case_records\"" %OUT% >nul && echo [OK] driver_case_records di JSON || echo [WARN] driver_case_records hilang di JSON
findstr /C:"\"driver_harness_sha256\"" %OUT% >nul && echo [OK] driver_harness_sha256 di JSON || echo [WARN] driver_harness_sha256 hilang di JSON
myc.exe check test\fixtures\bad_driver_oob.c --driver > %OUT% 2>&1
findstr /C:"case=2 run" %OUT% >nul && echo [OK] bad_driver_oob tereksekusi 2 kasus sblm crash || echo [WARN] case record bad_driver_oob salah
findstr /C:"verdict:   DRIVER_VIOLATION" %OUT% >nul && echo [OK] bad_driver_oob tetap DRIVER_VIOLATION || echo [WARN] bad_driver_oob bukan violation
myc.exe check test\fixtures\ok_driver_bounded.c --driver > %OUT% 2>&1
findstr /C:"strategy=coverage-first" %OUT% >nul && echo [OK] combinatorial coverage-first utk produk besar || echo [WARN] coverage-first tidak muncul
findstr /C:"combinatorial: max_product=64 budget=32" %OUT% >nul && echo [OK] max_product+budget jujur (64>32) || echo [WARN] max_product/budget hilang
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] bounded harness run bersih || echo [WARN] bounded harness gagal
del %OUT%
echo --- semantic canary (gagasan 9.9): run bersih tetap L3 HANYA bila backend ASan sehat
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"semantic canary" %OUT% >nul && echo [OK] evidence canary terekam pd run bersih || echo [INFO] canary evidence tersimpan di ledger JSON
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"assurance: L3 (RUNTIME)" %OUT% >nul && echo [OK] ok_run tetap L3 (backend sehat) || echo [WARN] ok_run tidak L3
del %OUT%
echo --- evidence receipt (gagasan 9.1): field hadir; deterministik utk input sama
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"receipt_sha256:" %OUT% >nul && echo [OK] receipt_sha256 di laporan || echo [WARN] receipt hilang
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"\"receipt_sha256\"" %OUT% >nul && echo [OK] receipt_sha256 di JSON || echo [WARN] receipt hilang di JSON
del %OUT%
echo --- Metamorphic Verification (9.7): clean setuju vs inconsistent
myc.exe check tests\ok_run.c --metamorphic > %OUT% 2>&1
findstr /C:"metamorphic clean" %OUT% >nul && echo [OK] metamorphic agree-clean utk ok_run || echo [WARN] metamorphic clean tidak muncul
findstr /C:"assurance: L3 (RUNTIME)" %OUT% >nul && echo [OK] metamorphic clean -^> L3 || echo [WARN] metamorphic clean bukan L3
myc.exe check tests\bad_run_oob.c --metamorphic > %OUT% 2>&1
findstr /C:"metamorphic inconsistency" %OUT% >nul && echo [OK] metamorphic inconsistency terdeteksi utk bad_run_oob || echo [WARN] metamorphic inconsistency tidak muncul
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] inconsistent -^> RUNTIME_VIOLATION || echo [WARN] inconsistent bukan RUNTIME_VIOLATION
echo --- Differential Backend Quorum (#3): clean vs conflict vs inconclusive
myc.exe check tests\ok_run.c --run --quorum > %OUT% 2>&1
findstr /C:"quorum: clean" %OUT% >nul && echo [OK] quorum clean utk run bersih || echo [WARN] quorum clean tidak muncul
findstr /C:"all backends agree: clean" %OUT% >nul && echo [OK] laporan quorum agree-clean || echo [WARN] laporan quorum agree-clean hilang
myc.exe check tests\bad_run_oob.c --run --quorum > %OUT% 2>&1
findstr /C:"quorum: conflict" %OUT% >nul && echo [OK] quorum conflict utk runtime OOB || echo [WARN] quorum conflict tidak muncul
myc.exe check tests\bad_intptr.c --quorum > %OUT% 2>&1
findstr /C:"quorum: clean" %OUT% >nul && echo [OK] quorum clean utk lint observasi (non-blocking, backend jalan) || echo [WARN] quorum tidak clean utk lint observasi
findstr /C:"all backends agree: clean" %OUT% >nul && echo [OK] quorum agree-clean utk lint observasi || echo [WARN] quorum agree-clean hilang
myc.exe check tests\ok_run.c --run --quorum --json > %OUT% 2>&1
findstr /C:"\"quorum_status\":\"clean\"" %OUT% >nul && echo [OK] quorum_status di JSON || echo [WARN] quorum_status hilang di JSON
del %OUT%
echo --- MYC-AUDIT-006: assurance vector per dimensi (bukan scalar max)
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R1 B0 P0 D0 F0" %OUT% >nul && echo [OK] vector C1 R1 utk run bersih || echo [WARN] vector run bersih salah
myc.exe check tests\bad_run_oob.c --run > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R2 B0 P0 D0 F0" %OUT% >nul && echo [OK] vector R2 utk runtime finding || echo [WARN] vector R2 tidak muncul
myc.exe check tests\ok_checked.c --checked > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R0 B1 P0 D0 F0" %OUT% >nul && echo [OK] vector B1 utk checked clean || echo [WARN] vector B1 tidak muncul
myc.exe check tests\ok_hello.c > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R0 B0 P0 D0 F0" %OUT% >nul && echo [OK] vector plain check C1 saja || echo [WARN] vector plain check salah
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"\"assurance_vector\"" %OUT% >nul && echo [OK] assurance_vector di JSON || echo [WARN] assurance_vector hilang di JSON
del %OUT%
echo --- Negative-Space Analysis (9.8): observasi non-blocking
myc.exe check tests\negative_ok.c --negative > %OUT% 2>&1
findstr /C:"negative (9.8): callsites=3 deviations=0" %OUT% >nul && echo [OK] negative clean utk negative_ok || echo [WARN] negative clean tidak muncul
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] negative tidak mengubah verdict || echo [WARN] negative mengubah verdict
myc.exe check tests\negative_dev.c --negative > %OUT% 2>&1
findstr /C:"deviations=1" %OUT% >nul && echo [OK] negative deviation terdeteksi utk negative_dev || echo [WARN] negative deviation tidak muncul
findstr /C:"konvensi proyek 4/5 callsite malloc memeriksa hasil" %OUT% >nul && echo [OK] laporan konvensi + confidence muncul || echo [WARN] laporan konvensi hilang
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] deviation tetap OK (observasi saja) || echo [WARN] deviation mengubah verdict
myc.exe check tests\negative_dev.c --negative --json > %OUT% 2>&1
findstr /C:"\"negative_deviations\":1" %OUT% >nul && echo [OK] negative_deviations di JSON || echo [WARN] negative_deviations hilang di JSON
del %OUT%
echo --- MYC-AUDIT-014: lint heuristik NON-blocking (observasi + confidence)
myc.exe check tests\bad_intptr.c > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] bad_intptr OK (lint observasi, bukan VIOLATION) || echo [WARN] bad_intptr bukan OK
findstr /C:"lint (14): 2 observasi" %OUT% >nul && echo [OK] ringkasan 2 observasi lint muncul || echo [WARN] ringkasan observasi lint hilang
findstr /C:"[suspicious]" %OUT% >nul && echo [OK] confidence suspicious muncul di teks || echo [WARN] confidence suspicious hilang
myc.exe check tests\bad_intptr.c --json > %OUT% 2>&1
findstr /C:"\"confidence\":\"suspicious\"" %OUT% >nul && echo [OK] confidence suspicious di JSON || echo [WARN] confidence suspicious hilang di JSON
findstr /C:"\"lint_observations\":2" %OUT% >nul && echo [OK] lint_observations di JSON || echo [WARN] lint_observations hilang di JSON
myc.exe check tests\bad_realloc.c > %OUT% 2>&1
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] bad_realloc COMPILE_ERROR (gcc -Wuse-after-free, bukti semantik) || echo [WARN] bad_realloc bukan COMPILE_ERROR
findstr /C:"use-after-free" %OUT% >nul && echo [OK] diagnostic gcc use-after-free terekam || echo [WARN] diagnostic gcc hilang
myc.exe check tests\ok_lint.c > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] ok_lint tetap OK || echo [WARN] ok_lint bukan OK
findstr /C:"lint         completed_clean" %OUT% >nul && echo [OK] gate lint completed_clean utk source bersih || echo [WARN] gate lint tidak clean
del %OUT%
echo --- Silence Is a Finding (9.10): --require-complete membuat gap gagal
myc.exe check tests\ok_hello.c --require-complete > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] require-complete tanpa gap tetap OK || echo [WARN] require-complete mengubah hasil bersih
myc.exe check test\fixtures\ok_contract.c > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-ENSURES-UNPROVED" %OUT% >nul && echo [OK] gap ensures-unproved terlihat (debt berkode) || echo [WARN] gap ensures tidak muncul
myc.exe check test\fixtures\ok_contract.c --require-complete > %OUT% 2>&1
findstr /C:"verdict:   INCONCLUSIVE" %OUT% >nul && echo [OK] require-complete: silent gap -^> INCONCLUSIVE || echo [WARN] gap tidak menggagalkan hasil
findstr /C:"require_complete: enforced" %OUT% >nul && echo [OK] laporan enforced muncul || echo [WARN] laporan enforced hilang
myc.exe check test\fixtures\ok_filc.c --filc > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-GATE-UNAVAILABLE" %OUT% >nul && echo [OK] backend tak tersedia jadi gap (bukan kesunyian) || echo [INFO] filc tersedia (tanpa gap)
del %OUT%
echo --- MYC-AUDIT-018: test portabel concurrency/deadlock/flood/OOM (via bash)
if defined GITHUB_ACTIONS (
  echo [SKIP] audit018 portabel dilewati di CI (stress/audit soak test, non-blocking)
) else (
  where bash >nul 2>&1
  if errorlevel 1 (
    echo [WARN] bash tidak tersedia (test portabel audit018 dilewati; jalankan test/_audit018.sh di POSIX)
  ) else (
    bash test/_audit018.sh
    if errorlevel 1 (
      echo [WARN] audit018 portable: lihat log (stress/audit test, non-fatal)
    )
  )
)
)
echo --- MYC-AUDIT-028: size cap saat membaca (bukan setelah baca penuh)
set BIGSRC=%TEMP%\myc_big_028.c
set BIGRUN=%TEMP%\myc_bigstdin_028.bin
fsutil file createnew "%BIGSRC%" 2097152 >nul 2>&1
fsutil file createnew "%BIGRUN%" 10000000 >nul 2>&1
if exist "%BIGSRC%" (
  myc.exe check "%BIGSRC%" > %OUT% 2>&1
  if errorlevel 2 (
    echo [OK] source ^> 1MiB ditolak exit2 fail-fast (cap saat membaca)
  ) else (
    echo [WARN] source besar tidak ditolak ec=%ERRORLEVEL%
  )
  findstr /C:"melebihi cap 1048576" %OUT% >nul && echo [OK] pesan cap source tampil || echo [WARN] pesan cap source hilang
  if exist "%BIGRUN%" (
    myc.exe check tests\ok_hello.c --run --run-stdin "%BIGRUN%" > %OUT% 2>&1
    if errorlevel 2 (
      echo [OK] run-stdin ^> 8MiB ditolak exit2 fail-fast
    ) else (
      echo [WARN] run-stdin besar tidak ditolak ec=%ERRORLEVEL%
    )
    findstr /C:"melebihi cap 8388608" %OUT% >nul && echo [OK] pesan cap run-stdin tampil || echo [WARN] pesan cap run-stdin hilang
    del "%BIGRUN%" >nul 2>&1
  )
  del "%BIGSRC%" >nul 2>&1
)
echo --- MYC-AUDIT-030: canonicalisasi path cwd (Fase 2)
rem Representasi berbeda dari direktori SAMA harus menghasilkan cwd canonical
rem IDENTIK (lexical canonicalization: absolutize + resolve "."/"..").
rem "tests\..\tests" == "tests" -> cwd capsule sama; direktori berbeda -> beda.
rem Catatan: fingerprint dibandingkan via baris 'cwd:' capsule (teks), bukan
rem seluruh baris JSON (JSON memuat duration_ms yang berubah tiap run).
myc.exe check tests\ok_hello.c --cwd tests > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] cwd relatif 'tests' OK || echo [WARN] cwd relatif 'tests' gagal
set FPCANON1=
for /f "delims=" %%g in ('myc.exe check tests\ok_hello.c --cwd tests 2^>^&1 ^| findstr /C:"cwd:"') do set FPCANON1=%%g
for /f "delims=" %%g in ('myc.exe check tests\ok_hello.c --cwd "tests\..\tests" 2^>^&1 ^| findstr /C:"cwd:"') do set FPCANON2=%%g
for /f "delims=" %%g in ('myc.exe check tests\ok_hello.c --cwd ".\tests" 2^>^&1 ^| findstr /C:"cwd:"') do set FPCANON3=%%g
for /f "delims=" %%g in ('myc.exe check tests\ok_hello.c --cwd "tests/../tests" 2^>^&1 ^| findstr /C:"cwd:"') do set FPCANON4=%%g
rem cwd berbeda (repo root vs tests) harus berbeda cwd canonical
for /f "delims=" %%g in ('myc.exe check tests\ok_hello.c --cwd . 2^>^&1 ^| findstr /C:"cwd:"') do set FPCANON5=%%g
if "%FPCANON1%"=="" (
  echo [WARN] cwd canonicalization: baris 'cwd:' tak tertangkap
) else if "%FPCANON1%"=="%FPCANON2%" (
  echo [OK] 'tests' vs 'tests\..\tests' -> cwd canonical IDENTIK
) else (
  echo [WARN] 'tests' vs 'tests\..\tests' cwd canonical berbeda
  echo        FPCANON1='%FPCANON1%'
  echo        FPCANON2='%FPCANON2%'
)
if "%FPCANON1%"=="%FPCANON3%" (
  echo [OK] 'tests' vs '.\tests' -> cwd canonical IDENTIK
) else (
  echo [WARN] 'tests' vs '.\tests' cwd canonical berbeda
)
if "%FPCANON1%"=="%FPCANON4%" (
  echo [OK] 'tests' vs 'tests/../tests' -> cwd canonical IDENTIK
) else (
  echo [WARN] 'tests' vs 'tests/../tests' cwd canonical berbeda
)
if "%FPCANON1%"=="%FPCANON5%" (
  echo [WARN] cwd berbeda ('.' vs 'tests') justru cwd canonical sama
) else (
  echo [OK] cwd berbeda -> cwd canonical BERBEDA
)
del %OUT%
echo --- MCP smoke (P9): mcp.exe harus menjawab JSON-RPC
call test\_mcp_smoke.bat
echo --- MCP SDK interop (opsional): hanya bila SDK MCP Python resmi terpasang
python -m pip show mcp >nul 2>&1
if errorlevel 1 (
  echo [SKIP] SDK MCP Python tidak terpasang (pip install mcp)
) else (
  python test\_mcp_sdk_interop.py
   if errorlevel 1 (
     echo [WARN] interop SDK MCP resmi gagal (non-fatal)
   )
)
exit /b 0
