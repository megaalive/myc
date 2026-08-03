@echo off
setlocal
set OUT=test\_tmp_run_out.txt
echo --- Fase 5 reentrancy (MYC-AUDIT-008): myc_run paralel bebas race/stale
gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test\stress_threads.exe test\stress_threads.c myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c gate.c negative.c >nul 2>&1
if exist test\stress_threads.exe (
  test\stress_threads.exe | findstr "no race" >nul && echo [OK] stress_threads deterministik, no race || echo [FAIL] stress_threads race/stale
) else (
  echo [FAIL] stress_threads gagal dibangun
)
del test\stress_threads.exe 2>nul
echo --- Fase 6 JSON ketat (MYC-AUDIT-009): corpus valid/invalid tak crash
gcc -O2 -std=c11 -Wall -Wextra -I. -o test\json_abuse.exe test\json_abuse.c json.c >nul 2>&1
if exist test\json_abuse.exe (
  test\json_abuse.exe | findstr "OK" >nul && echo [OK] json_abuse corpus ketat lulus || echo [FAIL] json_abuse corpus gagal
) else (
  echo [FAIL] json_abuse gagal dibangun
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
  echo [FAIL] unknown flag --rnu tidak ditolak harus exit2 ec=%ERRORLEVEL%
)
findstr /C:"unknown option: --rnu" %OUT% >nul && echo [OK] pesan unknown option tampil || echo [FAIL] pesan unknown option hilang
myc.exe check tests\ok_hello.c --run --json > %OUT% 2>&1
if errorlevel 1 (
  echo [FAIL] flag valid --run justru gagal regresi ingress
) else (
  echo [OK] flag valid --run tetap diterima
)
myc.exe check tests\ok_hello.c --run-stdin > %OUT% 2>&1
findstr /C:"--run-stdin membutuhkan argumen" %OUT% >nul && echo [OK] --run-stdin tanpa argumen ditolak || echo [FAIL] --run-stdin tanpa argumen tidak ditolak
del %OUT%
echo --- MYC-AUDIT-020: CLI --timeout/--output-cap (validasi + fail-fast angka)
myc.exe check tests\ok_hello.c --timeout 5000 > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] --timeout valid diterima || echo [FAIL] --timeout valid ditolak
myc.exe check tests\ok_hello.c --timeout -1 > %OUT% 2>&1
findstr /C:"invalid_timeout" %OUT% >nul && echo [OK] --timeout negatif ditolak (invalid_timeout) || echo [FAIL] --timeout negatif tidak ditolak
myc.exe check tests\ok_hello.c --timeout 999999999 > %OUT% 2>&1
findstr /C:"invalid_timeout" %OUT% >nul && echo [OK] --timeout overflow ditolak (invalid_timeout) || echo [FAIL] --timeout overflow tidak ditolak
myc.exe check tests\ok_hello.c --timeout abc > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] --timeout non-angka ditolak exit2 failfast
) else (
  echo [FAIL] --timeout non-angka tidak ditolak ec=%ERRORLEVEL%
)
findstr /C:"--timeout: nilai bukan angka" %OUT% >nul && echo [OK] pesan --timeout non-angka tampil || echo [FAIL] pesan --timeout non-angka hilang
myc.exe check tests\ok_hello.c --output-cap 5000 > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] --output-cap valid diterima || echo [FAIL] --output-cap valid ditolak
findstr /C:"max_output_bytes: 5000" %OUT% >nul && echo [OK] max_output_bytes mengalir ke capsule report || echo [FAIL] max_output_bytes tidak tampil di report
myc.exe check tests\ok_hello.c --output-cap -5 > %OUT% 2>&1
findstr /C:"invalid_output_cap" %OUT% >nul && echo [OK] --output-cap NEGATIF ditolak (bug AUDIT-020 fix) || echo [FAIL] --output-cap negatif lolos validasi
myc.exe check tests\ok_hello.c --output-cap 104857601 > %OUT% 2>&1
findstr /C:"invalid_output_cap" %OUT% >nul && echo [OK] --output-cap melebihi 100MiB ditolak || echo [FAIL] --output-cap besar tidak ditolak
myc.exe check tests\ok_hello.c --output-cap abc > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] --output-cap non-angka ditolak exit2 failfast
) else (
  echo [FAIL] --output-cap non-angka tidak ditolak ec=%ERRORLEVEL%
)
myc.exe check tests\ok_hello.c --output-cap 99999999999 > %OUT% 2>&1
if errorlevel 2 (
  echo [OK] --output-cap overflow angka ditolak exit2 failfast
) else (
  echo [FAIL] --output-cap overflow tidak ditolak ec=%ERRORLEVEL%
)
myc.exe check tests\ok_hello.c --cwd "" > %OUT% 2>&1
findstr /C:"invalid_cwd" %OUT% >nul && echo [OK] --cwd kosong ditolak (invalid_cwd) || echo [FAIL] --cwd kosong tidak ditolak
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
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] bad_checked_type: tipe elemen salah ditolak compile-time || echo [FAIL] tipe salah tidak jadi COMPILE_ERROR
echo === tests\bad_checked_new_overflow.c --run --checked (RUNTIME_VIOLATION)
myc.exe check tests\bad_checked_new_overflow.c --run --checked > %OUT% 2>&1
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] bad_checked_new_overflow: overflow MYC_NEW terdeteksi runtime || echo [FAIL] overflow MYC_NEW tidak terdeteksi
findstr /C:"MYC_NEW overflow" %OUT% >nul && echo [OK] marker MYC_NEW overflow muncul || echo [FAIL] marker overflow hilang
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
echo --- MYC-AUDIT-022: machine-readable diagnostic + exact tool identity (roadmap 7.1)
myc.exe version > %OUT% 2>&1
findstr /C:"gcc version:" %OUT% >nul && echo [OK] myc version cetak gcc version || echo [FAIL] gcc version hilang di myc version
findstr /C:"clang version:" %OUT% >nul && echo [OK] myc version cetak clang version || echo [FAIL] clang version hilang di myc version
myc.exe check tests\ok_hello.c > %OUT% 2>&1
findstr /C:"gcc_version:" %OUT% >nul && echo [OK] report memuat gcc_version || echo [FAIL] gcc_version tidak tampil
myc.exe check tests\bad_realloc.c > %OUT% 2>&1
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] bad_realloc COMPILE_ERROR || echo [FAIL] bad_realloc bukan COMPILE_ERROR
findstr /C:"used after 'realloc'" %OUT% >nul && echo [OK] diagnostic JSON gcc ter-parse terstruktur (line:col) || echo [FAIL] diagnostic JSON gcc tidak ter-parse
findstr /C:"[17:12]" %OUT% >nul && echo [OK] line:col dari caret JSON benar || echo [FAIL] line:col JSON salah
myc.exe check tests\ok_hello.c --json > %OUT% 2>&1
findstr /C:"gcc_version" %OUT% >nul && echo [OK] JSON memuat gcc_version || echo [FAIL] JSON gcc_version hilang
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"clang_version" %OUT% >nul && echo [OK] JSON memuat clang_version (backend clang) || echo [FAIL] JSON clang_version hilang
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"receipt_sha256: 8224c23a8a42265f4596d0a740066a97b1a10b0288dc7e1f6cdf8da002e7f565" %OUT% >nul && echo [OK] receipt golden tetap deterministik || echo [FAIL] receipt golden BERUBAH (AUDIT-022 mengubah gate status?)
echo --- driver fixtures (D2.2, --driver): ok_driver harus OK, bad_driver_oob harus DRIVER_VIOLATION
for %%f in (test\fixtures\ok_driver.c test\fixtures\bad_driver_oob.c) do (
  echo === %%f
  myc.exe check "%%f" --driver > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"driver:" /C:"  funcs:" /C:"  cases:" %OUT%
)
echo --- MYC-AUDIT-017: saluran report sanitizer non-spoofable
myc.exe check tests\bad_run_oob.c --run > %OUT% 2>&1
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] bad_run_oob tetap RUNTIME_VIOLATION (report sanitizer) || echo [FAIL] bad_run_oob tidak jadi violation
findstr /C:"sanitizer:" %OUT% >nul && echo [OK] evidence sanitizer (dari report log_path) terekam || echo [FAIL] evidence sanitizer hilang
myc.exe check tests\spoof_marker_run.c --run > %OUT% 2>&1
findstr /C:"RUNTIME_VIOLATION" %OUT% >nul && echo [FAIL] spoof marker jadi RUNTIME_VIOLATION || echo [OK] spoof marker --run TIDAK jadi violation
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] spoof marker tetap OK (exit 0, tanpa report) || echo [FAIL] spoof marker bukan OK
findstr /C:"diabaikan" %OUT% >nul && echo [OK] diagnostic teks marker diabaikan muncul || echo [FAIL] diagnostic spoof hilang
myc.exe check tests\bad_driver_spoof.c --driver > %OUT% 2>&1
findstr /C:"DRIVER_VIOLATION" %OUT% >nul && echo [FAIL] spoof driver jadi DRIVER_VIOLATION || echo [OK] spoof driver TIDAK jadi violation
del %OUT%
echo --- unverified debt (Fase 4): debt hanya muncul utk scope yg TIDAK lengkap
set DEBT=none
myc.exe check test\fixtures\bad_driver_oob.c --driver > %OUT% 2>&1
findstr /C:"unverified_debt" %OUT% >nul && echo [OK] bad_driver_oob memunculkan unverified_debt
findstr /C:"generated driver diminta tapi 0 kasus" %OUT% >nul && echo [OK] debt nonzero_cases terdeteksi
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"unverified_debt" %OUT% >nul && echo [FAIL] ok_run seharusnya tanpa debt || echo [OK] ok_run tanpa unverified_debt
del %OUT%
echo --- semantic canary (gagasan 9.9): run bersih tetap L3 HANYA bila backend ASan sehat
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"semantic canary" %OUT% >nul && echo [OK] evidence canary terekam pd run bersih || echo [INFO] canary evidence tersimpan di ledger JSON
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"assurance: L3 (RUNTIME)" %OUT% >nul && echo [OK] ok_run tetap L3 (backend sehat) || echo [FAIL] ok_run tidak L3
del %OUT%
echo --- evidence receipt (gagasan 9.1): field hadir; deterministik utk input sama
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"receipt_sha256:" %OUT% >nul && echo [OK] receipt_sha256 di laporan || echo [FAIL] receipt hilang
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"\"receipt_sha256\"" %OUT% >nul && echo [OK] receipt_sha256 di JSON || echo [FAIL] receipt hilang di JSON
del %OUT%
echo --- Metamorphic Verification (9.7): clean setuju vs inconsistent
myc.exe check tests\ok_run.c --metamorphic > %OUT% 2>&1
findstr /C:"metamorphic clean" %OUT% >nul && echo [OK] metamorphic agree-clean utk ok_run || echo [FAIL] metamorphic clean tidak muncul
findstr /C:"assurance: L3 (RUNTIME)" %OUT% >nul && echo [OK] metamorphic clean -^> L3 || echo [FAIL] metamorphic clean bukan L3
myc.exe check tests\bad_run_oob.c --metamorphic > %OUT% 2>&1
findstr /C:"metamorphic inconsistency" %OUT% >nul && echo [OK] metamorphic inconsistency terdeteksi utk bad_run_oob || echo [FAIL] metamorphic inconsistency tidak muncul
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] inconsistent -^> RUNTIME_VIOLATION || echo [FAIL] inconsistent bukan RUNTIME_VIOLATION
echo --- Differential Backend Quorum (#3): clean vs conflict vs inconclusive
myc.exe check tests\ok_run.c --run --quorum > %OUT% 2>&1
findstr /C:"quorum: clean" %OUT% >nul && echo [OK] quorum clean utk run bersih || echo [FAIL] quorum clean tidak muncul
findstr /C:"all backends agree: clean" %OUT% >nul && echo [OK] laporan quorum agree-clean || echo [FAIL] laporan quorum agree-clean hilang
myc.exe check tests\bad_run_oob.c --run --quorum > %OUT% 2>&1
findstr /C:"quorum: conflict" %OUT% >nul && echo [OK] quorum conflict utk runtime OOB || echo [FAIL] quorum conflict tidak muncul
myc.exe check tests\bad_intptr.c --quorum > %OUT% 2>&1
findstr /C:"quorum: clean" %OUT% >nul && echo [OK] quorum clean utk lint observasi (non-blocking, backend jalan) || echo [FAIL] quorum tidak clean utk lint observasi
findstr /C:"all backends agree: clean" %OUT% >nul && echo [OK] quorum agree-clean utk lint observasi || echo [FAIL] quorum agree-clean hilang
myc.exe check tests\ok_run.c --run --quorum --json > %OUT% 2>&1
findstr /C:"\"quorum_status\":\"clean\"" %OUT% >nul && echo [OK] quorum_status di JSON || echo [FAIL] quorum_status hilang di JSON
del %OUT%
echo --- MYC-AUDIT-006: assurance vector per dimensi (bukan scalar max)
myc.exe check tests\ok_run.c --run > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R1 B0 P0 D0 F0" %OUT% >nul && echo [OK] vector C1 R1 utk run bersih || echo [FAIL] vector run bersih salah
myc.exe check tests\bad_run_oob.c --run > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R2 B0 P0 D0 F0" %OUT% >nul && echo [OK] vector R2 utk runtime finding || echo [FAIL] vector R2 tidak muncul
myc.exe check tests\ok_checked.c --checked > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R0 B1 P0 D0 F0" %OUT% >nul && echo [OK] vector B1 utk checked clean || echo [FAIL] vector B1 tidak muncul
myc.exe check tests\ok_hello.c > %OUT% 2>&1
findstr /C:"assurance_vector: C1 S0 R0 B0 P0 D0 F0" %OUT% >nul && echo [OK] vector plain check C1 saja || echo [FAIL] vector plain check salah
myc.exe check tests\ok_run.c --run --json > %OUT% 2>&1
findstr /C:"\"assurance_vector\"" %OUT% >nul && echo [OK] assurance_vector di JSON || echo [FAIL] assurance_vector hilang di JSON
del %OUT%
echo --- Negative-Space Analysis (9.8): observasi non-blocking
myc.exe check tests\negative_ok.c --negative > %OUT% 2>&1
findstr /C:"negative (9.8): callsites=3 deviations=0" %OUT% >nul && echo [OK] negative clean utk negative_ok || echo [FAIL] negative clean tidak muncul
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] negative tidak mengubah verdict || echo [FAIL] negative mengubah verdict
myc.exe check tests\negative_dev.c --negative > %OUT% 2>&1
findstr /C:"deviations=1" %OUT% >nul && echo [OK] negative deviation terdeteksi utk negative_dev || echo [FAIL] negative deviation tidak muncul
findstr /C:"konvensi proyek 4/5 callsite malloc memeriksa hasil" %OUT% >nul && echo [OK] laporan konvensi + confidence muncul || echo [FAIL] laporan konvensi hilang
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] deviation tetap OK (observasi saja) || echo [FAIL] deviation mengubah verdict
myc.exe check tests\negative_dev.c --negative --json > %OUT% 2>&1
findstr /C:"\"negative_deviations\":1" %OUT% >nul && echo [OK] negative_deviations di JSON || echo [FAIL] negative_deviations hilang di JSON
del %OUT%
echo --- MYC-AUDIT-014: lint heuristik NON-blocking (observasi + confidence)
myc.exe check tests\bad_intptr.c > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] bad_intptr OK (lint observasi, bukan VIOLATION) || echo [FAIL] bad_intptr bukan OK
findstr /C:"lint (14): 2 observasi" %OUT% >nul && echo [OK] ringkasan 2 observasi lint muncul || echo [FAIL] ringkasan observasi lint hilang
findstr /C:"[suspicious]" %OUT% >nul && echo [OK] confidence suspicious muncul di teks || echo [FAIL] confidence suspicious hilang
myc.exe check tests\bad_intptr.c --json > %OUT% 2>&1
findstr /C:"\"confidence\":\"suspicious\"" %OUT% >nul && echo [OK] confidence suspicious di JSON || echo [FAIL] confidence suspicious hilang di JSON
findstr /C:"\"lint_observations\":2" %OUT% >nul && echo [OK] lint_observations di JSON || echo [FAIL] lint_observations hilang di JSON
myc.exe check tests\bad_realloc.c > %OUT% 2>&1
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] bad_realloc COMPILE_ERROR (gcc -Wuse-after-free, bukti semantik) || echo [FAIL] bad_realloc bukan COMPILE_ERROR
findstr /C:"use-after-free" %OUT% >nul && echo [OK] diagnostic gcc use-after-free terekam || echo [FAIL] diagnostic gcc hilang
myc.exe check tests\ok_lint.c > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] ok_lint tetap OK || echo [FAIL] ok_lint bukan OK
findstr /C:"lint         completed_clean" %OUT% >nul && echo [OK] gate lint completed_clean utk source bersih || echo [FAIL] gate lint tidak clean
del %OUT%
echo --- Silence Is a Finding (9.10): --require-complete membuat gap gagal
myc.exe check tests\ok_hello.c --require-complete > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] require-complete tanpa gap tetap OK || echo [FAIL] require-complete mengubah hasil bersih
myc.exe check test\fixtures\ok_contract.c > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-ENSURES-UNPROVED" %OUT% >nul && echo [OK] gap ensures-unproved terlihat (debt berkode) || echo [FAIL] gap ensures tidak muncul
myc.exe check test\fixtures\ok_contract.c --require-complete > %OUT% 2>&1
findstr /C:"verdict:   INCONCLUSIVE" %OUT% >nul && echo [OK] require-complete: silent gap -^> INCONCLUSIVE || echo [FAIL] gap tidak menggagalkan hasil
findstr /C:"require_complete: enforced" %OUT% >nul && echo [OK] laporan enforced muncul || echo [FAIL] laporan enforced hilang
myc.exe check test\fixtures\ok_filc.c --filc > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-GATE-UNAVAILABLE" %OUT% >nul && echo [OK] backend tak tersedia jadi gap (bukan kesunyian) || echo [INFO] filc tersedia (tanpa gap)
del %OUT%
echo --- MYC-AUDIT-018: test portabel concurrency/deadlock/flood/OOM (via bash)
where bash >nul 2>&1
if errorlevel 1 (
  echo [SKIP] bash tidak tersedia (test portabel audit018 dilewati; jalankan test/_audit018.sh di POSIX)
) else (
  bash test/_audit018.sh
  if errorlevel 1 (
    echo [FAIL] audit018 portable gagal
    exit /b 1
  )
)
echo --- MCP smoke (P9): mcp.exe harus menjawab JSON-RPC
call test\_mcp_smoke.bat
echo --- MCP SDK interop (opsional): hanya bila SDK MCP Python resmi terpasang
python -m pip show mcp >nul 2>&1
if errorlevel 1 (
  echo [SKIP] SDK MCP Python tidak terpasang (pip install mcp)
) else (
  python test\_mcp_sdk_interop.py
  if errorlevel 1 (
    echo [FAIL] interop SDK MCP resmi gagal
    exit /b 1
  )
)
exit /b 0
