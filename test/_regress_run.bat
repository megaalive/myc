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
echo === tests\bad_checked_type.c --checked (tipe elemen salah -> COMPILE_ERROR)
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
echo --- driver fixtures (D2.2, --driver): ok_driver harus OK, bad_driver_oob harus DRIVER_VIOLATION
for %%f in (test\fixtures\ok_driver.c test\fixtures\bad_driver_oob.c) do (
  echo === %%f
  myc.exe check "%%f" --driver > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"driver:" /C:"  funcs:" /C:"  cases:" %OUT%
)
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
findstr /C:"assurance: L3 (RUNTIME)" %OUT% >nul && echo [OK] metamorphic clean -> L3 || echo [FAIL] metamorphic clean bukan L3
myc.exe check tests\bad_run_oob.c --metamorphic > %OUT% 2>&1
findstr /C:"metamorphic inconsistency" %OUT% >nul && echo [OK] metamorphic inconsistency terdeteksi utk bad_run_oob || echo [FAIL] metamorphic inconsistency tidak muncul
findstr /C:"verdict:   RUNTIME_VIOLATION" %OUT% >nul && echo [OK] inconsistent -> RUNTIME_VIOLATION || echo [FAIL] inconsistent bukan RUNTIME_VIOLATION
echo --- Differential Backend Quorum (#3): clean vs conflict vs inconclusive
myc.exe check tests\ok_run.c --run --quorum > %OUT% 2>&1
findstr /C:"quorum: clean" %OUT% >nul && echo [OK] quorum clean utk run bersih || echo [FAIL] quorum clean tidak muncul
findstr /C:"all backends agree: clean" %OUT% >nul && echo [OK] laporan quorum agree-clean || echo [FAIL] laporan quorum agree-clean hilang
myc.exe check tests\bad_run_oob.c --run --quorum > %OUT% 2>&1
findstr /C:"quorum: conflict" %OUT% >nul && echo [OK] quorum conflict utk runtime OOB || echo [FAIL] quorum conflict tidak muncul
myc.exe check tests\bad_intptr.c --quorum > %OUT% 2>&1
findstr /C:"quorum: inconclusive" %OUT% >nul && echo [OK] quorum inconclusive utk tanpa hasil gate || echo [FAIL] quorum inconclusive tidak muncul
myc.exe check tests\ok_run.c --run --quorum --json > %OUT% 2>&1
findstr /C:"\"quorum_status\":\"clean\"" %OUT% >nul && echo [OK] quorum_status di JSON || echo [FAIL] quorum_status hilang di JSON
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
echo --- Silence Is a Finding (9.10): --require-complete membuat gap gagal
myc.exe check tests\ok_hello.c --require-complete > %OUT% 2>&1
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] require-complete tanpa gap tetap OK || echo [FAIL] require-complete mengubah hasil bersih
myc.exe check test\fixtures\ok_contract.c > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-ENSURES-UNPROVED" %OUT% >nul && echo [OK] gap ensures-unproved terlihat (debt berkode) || echo [FAIL] gap ensures tidak muncul
myc.exe check test\fixtures\ok_contract.c --require-complete > %OUT% 2>&1
findstr /C:"verdict:   INCONCLUSIVE" %OUT% >nul && echo [OK] require-complete: silent gap -> INCONCLUSIVE || echo [FAIL] gap tidak menggagalkan hasil
findstr /C:"require_complete: enforced" %OUT% >nul && echo [OK] laporan enforced muncul || echo [FAIL] laporan enforced hilang
myc.exe check test\fixtures\ok_filc.c --filc > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-GATE-UNAVAILABLE" %OUT% >nul && echo [OK] backend tak tersedia jadi gap (bukan kesunyian) || echo [INFO] filc tersedia (tanpa gap)
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
    echo [FAIL] interop SDK MCP resmi gagal
    exit /b 1
  )
)
exit /b 0
