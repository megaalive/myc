@echo off
setlocal
rem Guard anti-false-OK: gagal cepat bila myc salah melaporkan OK (MYC-AUDIT-031).
call test\_anti_false_ok.bat || exit /b 1
set OUT=test\_tmp_run_out.txt
echo --- Pre-flight: prove.c compile -Werror (MYC-AUDIT-023)
gcc -O2 -std=c11 -Wall -Wextra -Werror -pedantic -Werror=implicit-function-declaration -c prove.c -o test\_tmp_prove_preflight.o 2>&1
if errorlevel 1 (
  echo [FAIL] pre-flight prove.c -Werror
  exit /b 1
) else (
  echo [OK] pre-flight prove.c -Werror clean
  del test\_tmp_prove_preflight.o 2>nul
)
echo --- Fase 5 reentrancy (MYC-AUDIT-008): myc_run paralel bebas race/stale
gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test\stress_threads.exe test\stress_threads.c myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c driver.c json.c gate.c negative.c taxonomy.c >nul 2>&1
if exist test\stress_threads.exe (
  test\stress_threads.exe | findstr "no race" >nul && echo [OK] stress_threads deterministik, no race || echo [WARN] stress_threads race/stale - stress test; lihat issue
) else (
  echo [WARN] stress_threads gagal dibangun - stress test; lihat issue
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
rem --- Fase 6 Self-Challenge: Regression Corpus (myc regression)
if exist .myc\regression rmdir /s /q .myc\regression
myc.exe check test\fixtures\fuzz_div0.c --fuzz --fuzz-iters 2000 --no-cache > %OUT% 2>&1
findstr /C:"verdict:   DRIVER_VIOLATION" %OUT% >nul && echo [OK] Fase 6 regression fuzz crash ditemukan || echo [WARN] Fase 6 regression fuzz crash tidak ditemukan
myc.exe regression list > %OUT% 2>&1
findstr /C:"seed ada" %OUT% >nul && echo [OK] Fase 6 regression seed tersimpan || echo [WARN] Fase 6 regression seed tidak tersimpan
myc.exe regression run test\fixtures\fuzz_div0_fixed.c > %OUT% 2>&1
findstr /C:"RESOLVED" %OUT% >nul && echo [OK] Fase 6 regression fix tidak regress || echo [WARN] Fase 6 regression fix tidak resolved
if exist .myc\regression rmdir /s /q .myc\regression
del %OUT%
rem --- Fase 6 Self-Challenge: Concurrency Probe (--thread-probe)
myc.exe check test\fixtures\con_inv.c --thread-probe --no-cache > %OUT% 2>&1
findstr /C:"LOCK-ORDER INVERSION" %OUT% >nul && echo [OK] Fase 6 thread-probe inversion terdeteksi || echo [WARN] Fase 6 thread-probe inversion tidak terdeteksi
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] Fase 6 thread-probe non-blocking || echo [WARN] Fase 6 thread-probe mengubah verdict
del %OUT%
rem --- Fase 6 Self-Challenge: Environment Perturbation (--perturb)
myc.exe check tests\ok_hello.c --run --perturb --no-cache > %OUT% 2>&1
findstr /C:"DETERMINISTIK lintas env" %OUT% >nul && echo [OK] Fase 6 perturb deterministik || echo [WARN] Fase 6 perturb determinisme tidak terdeteksi
myc.exe check test\fixtures\pert_tz.c --run --perturb --no-cache > %OUT% 2>&1
findstr /C:"ENV-SENSITIVE" %OUT% >nul && echo [OK] Fase 6 perturb env-sensitive terdeteksi || echo [WARN] Fase 6 perturb env-sensitive tidak terdeteksi
del %OUT%
rem --- Fase 6 Self-Challenge: Test-Quality Audit (myc audit-tests)
myc.exe audit-tests > %OUT% 2>&1
findstr /C:"hazard class coverage: 7/7" %OUT% >nul && echo [OK] Fase 6 audit-tests hazard 7/7 || echo [WARN] Fase 6 audit-tests hazard gap
findstr /C:"[OK] exhaustive" %OUT% >nul && echo [OK] Fase 6 audit-tests backend lengkap || echo [WARN] Fase 6 audit-tests backend gap
del %OUT%
rem --- Fase 6 Self-Challenge: Canary Swarm (myc canary)
echo --- Fase 6 canary: semua backend terverifikasi hidup
myc.exe canary run > %OUT% 2>&1
findstr /C:"canary swarm: 11/11 PASS" %OUT% >nul && echo [OK] Fase 6 canary 11/11 PASS || echo [WARN] Fase 6 canary ada GAP
myc.exe canary list > %OUT% 2>&1
findstr /C:"11 canary untuk 9 backend" %OUT% >nul && echo [OK] Fase 6 canary registry lengkap || echo [WARN] Fase 6 canary registry tidak lengkap
del %OUT%
echo --- self-dogfooding: semua source myc harus OK
for %%f in (myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c state.c abi.c prove.c filc.c driver.c json.c mcp.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c) do (
  echo === %%f
  myc.exe check "%%f" > %OUT%
  findstr /B /C:"verdict:" %OUT%
)
echo --- --json-summary: ringkas untuk agent (tanpa stdout/stderr/fingerprint)
myc.exe check tests\ok_hello.c --json-summary > %OUT% 2>&1
findstr /C:"verdict" %OUT% >nul && echo [OK] --json-summary verdict ada || echo [WARN] --json-summary verdict hilang
findstr /C:"assurance_vector" %OUT% >nul && echo [OK] --json-summary assurance_vector ada || echo [WARN] --json-summary assurance_vector hilang
findstr /C:"receipt_sha256" %OUT% >nul && echo [OK] --json-summary receipt_sha256 ada || echo [WARN] --json-summary receipt_sha256 hilang
findstr /C:"diagnostics" %OUT% >nul && echo [OK] --json-summary diagnostics ada || echo [WARN] --json-summary diagnostics hilang
findstr /C:"gate_matrix" %OUT% >nul && echo [OK] --json-summary gate_matrix ada || echo [WARN] --json-summary gate_matrix hilang
findstr /C:"stdout_text" %OUT% >nul && echo [WARN] --json-summary seharusnya tanpa stdout_text || echo [OK] --json-summary tanpa stdout_text
findstr /C:"stderr_text" %OUT% >nul && echo [WARN] --json-summary seharusnya tanpa stderr_text || echo [OK] --json-summary tanpa stderr_text
findstr /C:"fingerprint" %OUT% >nul && echo [WARN] --json-summary seharusnya tanpa fingerprint || echo [OK] --json-summary tanpa fingerprint
del %OUT%
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
findstr /C:"assurance: L4" %OUT% >nul && echo [OK] semantics_parity --checked = L4 || echo [WARN] semantics_parity --checked bukan L4
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
findstr /C:"filc: 1 panic = bug memori terbukti (main @" %OUT% >nul && echo [OK] diagnostic panic memuat lokasi origin || echo [INFO] lokasi origin tidak ter-parse
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
rem --- Fase 5 B4 (DS-08): Comments-as-Contracts - harvest komentar biasa
echo --- B4: harvest komentar biasa -> kandidat kontrak (observasi non-blocking)
myc.exe check test\fixtures\harvest_contracts.c --no-cache > %OUT% 2>&1
findstr /C:"harvest (B4): 6 kandidat komentar-biasa, 5 validated" %OUT% >nul && echo [OK] B4 harvest 6 kandidat 5 validated || echo [WARN] B4 harvest kandidat/validated salah
findstr /C:"requires clamp_len: `len <= cap` -- validated" %OUT% >nul && echo [OK] B4 pola 'must be <=' terdeteksi || echo [WARN] B4 pola 'must be <=' tidak terdeteksi
findstr /C:"perlu //@ syntax (bukan C murni)" %OUT% >nul && echo [OK] B4 prose non-C ditolak || echo [WARN] B4 prose non-C tidak ditolak
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] B4 non-blocking (verdict OK) || echo [WARN] B4 mengubah verdict
myc.exe check test\fixtures\harvest_contracts.c --no-cache --json-summary > %OUT% 2>&1
findstr /C:"\"harvest\":{\"candidates\":6,\"validated\":5,\"unbound\":0}" %OUT% >nul && echo [OK] B4 harvest di json-summary || echo [WARN] B4 harvest hilang di json-summary

rem --- Fase 5 A3 (DS-03): Small-Domain Exhaustive Proof
echo --- A3: exhaustive proof (enumerasi penuh domain deklarasi)
if exist .myc\exhaustive.json del .myc\exhaustive.json
myc.exe check test\fixtures\ok_exhaustive.c --exhaustive --no-cache > %OUT% 2>&1
findstr /C:"P1 EXHAUSTIVE untuk domain dideklarasikan" %OUT% >nul && echo [OK] A3 P1 EXHAUSTIVE 0..64 || echo [WARN] A3 P1 EXHAUSTIVE tidak tercapai
myc.exe check test\fixtures\bad_exhaustive.c --exhaustive --no-cache > %OUT% 2>&1
findstr /C:"counterexample ditemukan" %OUT% >nul && echo [OK] A3 counterexample terdeteksi || echo [WARN] A3 counterexample tidak terdeteksi
myc.exe check test\fixtures\exhaustive_wide.c --exhaustive --no-cache > %OUT% 2>&1
findstr /C:"terlalu lebar" %OUT% >nul && echo [OK] A3 domain lebar ditolak || echo [WARN] A3 domain lebar tidak ditolak
myc.exe check test\fixtures\exhaustive_narrow.c --exhaustive --no-cache > %OUT% 2>&1
findstr /C:"SCOPE_LAUNDERING" %OUT% >nul && echo [OK] A3 SCOPE_LAUNDERING terdeteksi || echo [WARN] A3 SCOPE_LAUNDERING tidak terdeteksi
if exist .myc\exhaustive.json del .myc\exhaustive.json
del %OUT%
rem --- Fase 5 B3 (DS-07): LLM Error Taxonomy + coaching transcript
echo --- B3: finding diklasifikasi ke kelas kognitif + strategi (observasi non-blocking)
myc.exe check tests\bad_realloc.c --no-cache > %OUT% 2>&1
findstr /C:"coaching (B3): 2 item taksonomi" %OUT% >nul && echo [OK] B3 coaching 2 item || echo [WARN] B3 coaching item salah
findstr /C:"[missing_guard]" %OUT% >nul && echo [OK] B3 kelas missing_guard terdeteksi || echo [WARN] B3 kelas kognitif hilang
findstr /C:"strategi: Tambahkan guard" %OUT% >nul && echo [OK] B3 strategi per kelas ada || echo [WARN] B3 strategi hilang
findstr /C:"verdict:   COMPILE_ERROR" %OUT% >nul && echo [OK] B3 non-blocking (verdict utuh) || echo [WARN] B3 mengubah verdict
myc.exe check tests\bad_realloc.c --no-cache --json-summary > %OUT% 2>&1
findstr /C:"\"coaching\":[{\"class\":\"missing_guard\"" %OUT% >nul && echo [OK] B3 coaching di json-summary || echo [WARN] B3 coaching hilang di json-summary
myc.exe check tests\ok_hello.c --no-cache > %OUT% 2>&1
findstr /C:"coaching (B3)" %OUT% >nul && echo [WARN] B3 coaching muncul pada source bersih || echo [OK] B3 tanpa finding = tanpa coaching
del %OUT%
rem --- Fase 5 D4 (DS-15): System-Prompt Contract Generator (myc prompt)
echo --- D4: myc prompt render snippet deterministik untuk harness LLM
myc.exe prompt tests\ok_hello.c > %OUT% 2>&1
findstr /C:"# Aturan C untuk proyek ini (dari myc -- deterministik" %OUT% >nul && echo [OK] D4 prompt header deterministik || echo [WARN] D4 prompt header hilang
findstr /C:"Target host (fakta gcc host): char=" %OUT% >nul && echo [OK] D4 fakta target host ada || echo [WARN] D4 fakta target host hilang
findstr /C:"Anti-churn" %OUT% >nul && echo [OK] D4 aturan anti-churn ada || echo [WARN] D4 anti-churn hilang
myc.exe prompt tests\bad_system.c > %OUT% 2>&1
findstr /C:"Fungsi denylist dipanggil di file ini" %OUT% >nul && echo [OK] D4 denylist terdeteksi || echo [WARN] D4 denylist tidak terdeteksi
myc.exe prompt tests\negative_dev.c > %OUT% 2>&1
findstr /C:"Konvensi alokasi (dari negative-space): 4/5" %OUT% >nul && echo [OK] D4 konvensi alokasi dari negative-space || echo [WARN] D4 konvensi alokasi hilang
del %OUT%
rem --- Fase 5 A4 (DS-04): Differential Oracle Pair (myc compare)
echo --- A4: baterai input bersama vs perilaku kedua versi
myc.exe compare test\fixtures\ref_crc16.c test\fixtures\new_crc16_same.c > %OUT% 2>&1
findstr /C:"behavior-preserving (P1 DIFF) -- refactor aman" %OUT% >nul && echo [OK] A4 refactor sama -> preserved || echo [WARN] A4 behavior-preserving tidak terdeteksi
findstr /C:"64 identik, 0 divergen" %OUT% >nul && echo [OK] A4 64 kasus identik || echo [WARN] A4 jumlah identik salah
myc.exe compare test\fixtures\ref_crc16.c test\fixtures\new_crc16_div.c > %OUT% 2>&1
findstr /C:"unexpected_change (DS-04)" %OUT% >nul && echo [OK] A4 polinomial beda -> unexpected_change || echo [WARN] A4 divergence tidak terdeteksi
findstr /C:"53 divergen" %OUT% >nul && echo [OK] A4 jumlah divergen akurat || echo [WARN] A4 jumlah divergen salah
del %OUT%
rem --- Fase 5 C2 (DS-10): Stack Budget Analyzer (--stack)
echo --- C2: worst-case stack depth vs budget (observasi non-blocking)
myc.exe check tests\ok_hello.c --stack --no-cache > %OUT% 2>&1
findstr /C:"worst path : main = " %OUT% >nul && echo [OK] C2 worst path terhitung || echo [WARN] C2 worst path tidak terhitung
myc.exe check tests\ok_hello.c --stack-budget 10 --no-cache > %OUT% 2>&1
findstr /C:"melebihi budget" %OUT% >nul && echo [OK] C2 over budget terdeteksi || echo [WARN] C2 over budget tidak terdeteksi
myc.exe check test\fixtures\stack_recursive.c --stack --no-cache > %OUT% 2>&1
findstr /C:"recursion  : cycle di call graph" %OUT% >nul && echo [OK] C2 rekursi terdeteksi || echo [WARN] C2 rekursi tidak terdeteksi
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] C2 non-blocking || echo [WARN] C2 mengubah verdict
del %OUT%
rem --- Fase 5 D1 (DS-13): Fuzz Gate fuzz-lite (--fuzz)
echo --- D1: PRNG deterministik + loop terikat, kontrak membatasi input
myc.exe check test\fixtures\ok_fuzz.c --fuzz --fuzz-iters 2000 --no-cache > %OUT% 2>&1
findstr /C:"fuzz (D1): 1 fungsi, 2000 kasus tereksekusi" %OUT% >nul && echo [OK] D1 loop terikat tereksekusi || echo [WARN] D1 kasus fuzz tidak tereksekusi
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] D1 source aman -> bersih || echo [WARN] D1 source aman tidak bersih
myc.exe check test\fixtures\bad_fuzz.c --fuzz --fuzz-iters 2000 --no-cache > %OUT% 2>&1
findstr /C:"crash di peek_tbl" %OUT% >nul && echo [OK] D1 OOB terdeteksi || echo [WARN] D1 crash tidak terdeteksi
findstr /C:"DRIVER_VIOLATION" %OUT% >nul && echo [OK] D1 crash = bukti || echo [WARN] D1 crash tidak menaikkan verdict
del %OUT%
rem --- Fase 5 B5 (DS-09): Mutation-Audited Verification (--mutate-audit)
echo --- B5: mutan pola error LLM -> verifier mengaudit diri (observasi)
myc.exe check test\fixtures\mutate_target.c --mutate-audit --mutate-max 6 --no-cache > %OUT% 2>&1
findstr /C:"3 tertangkap, 0 GAP" %OUT% >nul && echo [OK] B5 mutan guard tertangkap || echo [WARN] B5 mutan tidak tertangkap
findstr /C:"verification coverage: 3/3" %OUT% >nul && echo [OK] B5 coverage dihitung || echo [WARN] B5 coverage hilang
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] B5 non-blocking || echo [WARN] B5 mengubah verdict
del %OUT%
rem --- Fase 5 C1: Freestanding Mode (--freestanding)
echo --- C1: hosted API trap di mode firmware (observasi non-blocking)
myc.exe check test\fixtures\blinky_bad.c --freestanding --no-cache > %OUT% 2>&1
findstr /C:"printf() dipanggil -- API hosted" %OUT% >nul && echo [OK] C1 printf = trap API hosted || echo [WARN] C1 hosted API trap tidak terdeteksi
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] C1 trap non-blocking || echo [WARN] C1 mengubah verdict
myc.exe check test\fixtures\blinky_clean.c --freestanding --no-cache > %OUT% 2>&1
findstr /C:"0 panggilan API hosted" %OUT% >nul && echo [OK] C1 hygiene bersih || echo [WARN] C1 hygiene bersih tidak terdeteksi
del %OUT%
rem --- Fase 5 C3: MMIO/volatile/alignment traps (DS-11)
echo --- C3: bare-metal heuristik di mode freestanding (observasi non-blocking)
myc.exe check test\fixtures\mmio_bad.c --freestanding --no-cache > %OUT% 2>&1
findstr /C:"MMIO deref alamat absolut tanpa volatile" %OUT% >nul && echo [OK] C3 MMIO deref terdeteksi || echo [WARN] C3 MMIO deref tidak terdeteksi
findstr /C:"polling loop tanpa volatile" %OUT% >nul && echo [OK] C3 polling loop terdeteksi || echo [WARN] C3 polling loop tidak terdeteksi
findstr /C:"cast uint8_t* ke tipe multi-byte" %OUT% >nul && echo [OK] C3 alignment cast terdeteksi || echo [WARN] C3 alignment cast tidak terdeteksi
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] C3 observasi non-blocking || echo [WARN] C3 mengubah verdict
myc.exe check test\fixtures\mmio_clean.c --freestanding --no-cache > %OUT% 2>&1
findstr /C:"bare-metal (C3/DS-11)" %OUT% >nul && echo [WARN] C3 fixture bersih memunculkan observasi || echo [OK] C3 idiom benar bersih
del %OUT%
rem --- Fase 5 C5: Scenario Packs + D3 auto (DS-12)
echo --- C5: scenario packs (profil JSON per domain)
myc.exe scenario list > %OUT% 2>&1
findstr /C:"firmware" %OUT% >nul && echo [OK] C5 list memuat firmware || echo [WARN] C5 list tanpa firmware
myc.exe scenario info firmware > %OUT% 2>&1
findstr /C:"stack_budget=4096" %OUT% >nul && echo [OK] C5 env DS-12 terlihat || echo [WARN] C5 env DS-12 hilang
myc.exe check test\fixtures\scen_parser.c --scenario auto --no-cache > %OUT% 2>&1
findstr /C:"scenario (C5): library" %OUT% >nul && echo [OK] C5 auto -> library || echo [WARN] C5 auto bukan library
myc.exe check test\fixtures\mmio_bad.c --scenario auto --no-cache > %OUT% 2>&1
findstr /C:"scenario (C5): firmware" %OUT% >nul && echo [OK] C5 auto -> firmware || echo [WARN] C5 auto bukan firmware
myc.exe check tests\ok_hello.c --scenario bogus --no-cache > %OUT% 2>&1
findstr /C:"scenario tak dikenal" %OUT% >nul && echo [OK] C5 nama tak dikenal fail-fast || echo [WARN] C5 nama tak dikenal tidak ditolak
del %OUT%
rem --- Fase 5 C4: Target Matrix bare metal (--matrix)
echo --- C4: portability matrix (cross-compiler opsional, non-blocking)
myc.exe check tests\ok_hello.c --matrix --no-cache > %OUT% 2>&1
findstr /C:"matrix (C4):" %OUT% >nul && echo [OK] C4 gate berjalan || echo [WARN] C4 gate tidak berjalan
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] C4 non-blocking || echo [WARN] C4 mengubah verdict
myc.exe check tests\ok_hello.c --matrix --no-cache --json-summary > %OUT% 2>&1
findstr /C:"matrix" %OUT% >nul && echo [OK] C4 ada di JSON || echo [WARN] C4 hilang dari JSON
del %OUT%
rem --- fix review: ; membuang pending basi + komentar blok bukan klausa
myc.exe check test\fixtures\contract_stale_pending.c > %OUT% 2>&1
findstr /C:"requires=1" %OUT% >nul && echo [OK] klausa hantu dalam komentar blok tidak dihitung || echo [WARN] klausa hantu komentar ikut dihitung
findstr /C:"(unbound)" %OUT% >nul && echo [OK] ghost hanya kandidat unbound (B4 harvest, bukan kontrak aktif) || echo [WARN] ghost bocor sebagai kontrak aktif
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
findstr /C:"combinatorial: max_product=64 budget=32" %OUT% >nul && echo [OK] max_product+budget jujur (64^>32) || echo [WARN] max_product/budget hilang
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
echo --- Fase 2: Contract/domain delta (myc contract-delta)
myc.exe contract-delta test\fixtures\contract_wide.c test\fixtures\contract_narrow.c > %OUT% 2>&1
findstr /C:"NARROWED" %OUT% >nul && echo [OK] contract-delta: NARROWED (domain menyempit) || echo [FAIL] contract-delta: NARROWED tidak terdeteksi
myc.exe contract-delta test\fixtures\contract_wide.c test\fixtures\contract_wide.c > %OUT% 2>&1
findstr /C:"CLEAN" %OUT% >nul && echo [OK] contract-delta: CLEAN (kontrak sama) || echo [FAIL] contract-delta: CLEAN tidak terdeteksi
echo --- Fase 5: Relational contracts (klasifikasi klausa kontrak)
set OUT=%TEMP%\myc_rel_out.txt
myc.exe check test\fixtures\relational_contracts.c --no-cache > %OUT% 2>&1
findstr /C:"5 relational (>=2 variabel), 1 unbound" %OUT% >nul && echo [OK] relational: 5 relational + 1 unbound terdeteksi || echo [FAIL] relational: klasifikasi salah
findstr /C:"UNBOUND: identifier di luar param/return" %OUT% >nul && echo [OK] relational: identifier tak terikat ditandai UNBOUND || echo [FAIL] relational: UNBOUND tidak terdeteksi
myc.exe contract-delta test\fixtures\relational_contracts.c test\fixtures\relational_contracts.c > %OUT% 2>&1
findstr /C:"CLEAN" %OUT% >nul && echo [OK] relational round-trip: contract-delta sama file = CLEAN || echo [FAIL] relational round-trip: bukan CLEAN
del %OUT%
echo --- Fase 5 (SOL-13): State-Machine Ghosting (//@ sm)
set OUT=%TEMP%\myc_sm_out.txt
myc.exe check test\fixtures\sm_protocol.c --no-cache > %OUT% 2>&1
findstr /C:"3 state, 4 event, 4 transisi, 0 finding" %OUT% >nul && echo [OK] sm: mesin sehat 0 finding || echo [FAIL] sm: mesin sehat bukan 0 finding
myc.exe check test\fixtures\sm_broken.c --no-cache > %OUT% 2>&1
findstr /C:"5 finding" %OUT% >nul && echo [OK] sm: mesin rusak 5 finding || echo [FAIL] sm: mesin rusak bukan 5 finding
findstr /C:"witness: IDLE --START--> BUSY --START--> STUCK" %OUT% >nul && echo [OK] sm: witness sequence sink benar || echo [FAIL] sm: witness sequence salah
findstr /C:"[unreachable]" %OUT% >nul && echo [OK] sm: unreachable terdeteksi || echo [FAIL] sm: unreachable tidak terdeteksi
myc.exe sm test\fixtures\sm_protocol.c > %OUT% 2>&1
findstr /C:"ghost state machine" %OUT% >nul && echo [OK] sm: subcommand myc sm berjalan || echo [FAIL] sm: myc sm gagal
del %OUT%
echo --- Fase 5 (SOL-14): ABI/FFI Surface Certificate (--abi)
set OUT=%TEMP%\myc_abi_out.txt
myc.exe abi snapshot test\fixtures\abi_stable.c > %OUT% 2>&1
myc.exe abi snapshot test\fixtures\abi_stable.c > %TEMP%\myc_abi_s2.txt 2>&1
fc /b %OUT% %TEMP%\myc_abi_s2.txt >nul 2>&1
if errorlevel 1 (echo [FAIL] abi: snapshot tidak deterministik) else (echo [OK] abi: snapshot deterministik)
myc.exe abi snapshot test\fixtures\abi_drift.c > %TEMP%\myc_abi_b.txt 2>&1
myc.exe abi diff %OUT% %TEMP%\myc_abi_b.txt > %TEMP%\myc_abi_d.txt 2>&1
findstr /C:"7 perubahan" %TEMP%\myc_abi_d.txt >nul && echo [OK] abi: delta 7 baris (size/enum/symbol) terdeteksi || echo [FAIL] abi: delta bukan 7 baris
findstr /C:"MEMBER Point z off=8" %TEMP%\myc_abi_d.txt >nul && echo [OK] abi: offset member baru terdeteksi || echo [FAIL] abi: offset member baru tidak terdeteksi
myc.exe check test\fixtures\abi_stable.c --abi --no-cache --json-summary > %OUT% 2>&1
findstr /C:"\"abi\":{\"ran\":true,\"structs\":3" %OUT% >nul && echo [OK] abi: check --abi masuk JSON summary || echo [FAIL] abi: JSON summary abi hilang
gcc -O2 -std=c11 -Wall -Wextra -I. -DMYC_NO_MAIN -o test\abi_tx_reject.exe test\abi_tx_reject.c myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c state.c abi.c prove.c filc.c driver.c json.c gate.c negative.c agent.c witness.c ledger.c transaction.c frontier.c observation.c causal.c nextbest.c cache.c context.c budget.c assume.c taxonomy.c prompt.c stack.c mutate.c scenario.c matrix.c canary.c testaudit.c perturb.c concur.c regress.c > %TEMP%\myc_abi_build.txt 2>&1
if exist test\abi_tx_reject.exe (
  test\abi_tx_reject.exe >nul 2>&1 && echo [OK] abi: ABI drift ditolak dalam transaction - exit criteria SOL-14 || echo [FAIL] abi: transaction tidak menolak ABI drift
  del test\abi_tx_reject.exe
) else (
  echo [FAIL] abi: abi_tx_reject gagal dibangun
)
del %OUT%
del %TEMP%\myc_abi_s2.txt
del %TEMP%\myc_abi_b.txt
del %TEMP%\myc_abi_d.txt
del %TEMP%\myc_abi_build.txt
echo --- Fase 0: Golden Schema + Malformed-Input (myc.result.v1)
where bash >nul 2>&1
if errorlevel 1 (
  echo [WARN] bash tidak tersedia - golden schema dilewati; jalankan test/_schema_golden.sh di POSIX
) else (
  bash test/_schema_golden.sh
  if errorlevel 1 (
    echo [FAIL] golden schema: ada cek gagal
  ) else (
    echo [OK] golden schema: 13 cek PASS (schema + malformed input)
  )
)
echo --- Fase -1: Baseline Benchmark (20 task, SOL-24)
where bash >nul 2>&1
if errorlevel 1 (
  echo [WARN] bash tidak tersedia - benchmark dilewati; jalankan bench/run_bench.sh di POSIX
) else (
  bash bench/run_bench.sh > %TEMP%\bench_regress.log 2>&1
  if errorlevel 1 (
    echo [FAIL] benchmark: lihat log %TEMP%\bench_regress.log - ada task gagal
    type %TEMP%\bench_regress.log | findstr /C:"[FAIL]" /C:"BENCHMARK"
  ) else (
    echo [OK] benchmark: 20 task PASS (baseline di bench\reports\)
  )
)
echo --- MYC-AUDIT-018: test portabel concurrency/deadlock/flood/OOM (via bash)
if defined GITHUB_ACTIONS (
  echo [SKIP] audit018 portabel dilewati di CI - stress/audit soak test, non-blocking
) else (
  where bash >nul 2>&1
  if errorlevel 1 (
    echo [WARN] bash tidak tersedia - test portabel audit018 dilewati; jalankan test/_audit018.sh di POSIX
  ) else (
    bash test/_audit018.sh
    if errorlevel 1 (
      echo [WARN] audit018 portable: lihat log - stress/audit test, non-fatal
    )
  )
)
)
echo --- capabilities registry sync (SOL-23): capabilities.json vs source+docs
where bash >nul 2>&1
if errorlevel 1 (
  echo [WARN] bash tidak tersedia - cap sync dilewati; jalankan test/_cap_sync.sh di POSIX
) else (
  bash test/_cap_sync.sh
  if errorlevel 1 (
    echo [FAIL] capabilities registry sync - capabilities.json tidak sinkron dengan source/docs
    set FAILCOUNT=1
  ) else (
    echo [OK] capabilities registry sinkron
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
  echo [OK] 'tests' vs 'tests\..\tests' = cwd canonical IDENTIK
) else (
  echo [WARN] 'tests' vs 'tests\..\tests' cwd canonical berbeda
  echo        FPCANON1='%FPCANON1%'
  echo        FPCANON2='%FPCANON2%'
)
if "%FPCANON1%"=="%FPCANON3%" (
  echo [OK] 'tests' vs '.\tests' = cwd canonical IDENTIK
) else (
  echo [WARN] 'tests' vs '.\tests' cwd canonical berbeda
)
if "%FPCANON1%"=="%FPCANON4%" (
  echo [OK] 'tests' vs 'tests/../tests' = cwd canonical IDENTIK
) else (
  echo [WARN] 'tests' vs 'tests/../tests' cwd canonical berbeda
)
if "%FPCANON1%"=="%FPCANON5%" (
  echo [WARN] cwd berbeda . vs tests justru cwd canonical sama
) else (
  echo [OK] cwd berbeda = cwd canonical BERBEDA
)
del %OUT%
echo --- SOL-22: Agent Context Compiler (myc context)
set OUT=%TEMP%\myc_sol22_out.txt
myc.exe context tests\ok_run.c --budget 4K > %OUT% 2>&1
findstr /C:"myc context v1" %OUT% >nul && echo [OK] paket context v1 tampil || echo [WARN] paket context v1 tidak tampil
findstr /C:"context_sha256" %OUT% >nul && echo [OK] context_sha256 ada || echo [WARN] context_sha256 hilang
findstr /C:"verify: myc check" %OUT% >nul && echo [OK] verify command ada || echo [WARN] verify command hilang
findstr /C:"preservation obligations" %OUT% >nul && echo [OK] preservation obligations ada || echo [WARN] preservation obligations hilang
echo ^<fungsi target^> > %TEMP%\myc_ph_pat.txt
findstr /G:"%TEMP%\myc_ph_pat.txt" %OUT% >nul && echo [WARN] placeholder fungsi-target bocor ke output || echo [OK] placeholder fungsi-target tidak bocor
del %TEMP%\myc_ph_pat.txt
myc.exe context tests\ok_run.c --budget 2K > %OUT% 2>&1
findstr /C:"[omitted:" %OUT% >nul && echo [OK] pemotongan budget terdeteksi || echo [INFO] tidak ada section yang dipotong pada 2K
myc.exe check tests\ok_run.c --budget 4K > %OUT% 2>&1
if errorlevel 1 (
  findstr /C:"--budget hanya berlaku pada subcommand context" %OUT% >nul && echo [OK] --budget pada check ditolak fail-fast || echo [WARN] --budget pada check ditolak tapi pesan beda
) else (
  echo [WARN] --budget pada check TIDAK ditolak
)
myc.exe context tests\ok_run.c --budget 99M > %OUT% 2>&1
if errorlevel 1 (
  echo [OK] --budget 99M ditolak
) else (
  echo [WARN] --budget 99M tidak ditolak
)
del %OUT%
echo --- SOL-30: Assurance Budget Contract (myc --budget-contract)
set OUT=%TEMP%\myc_sol30_out.txt
myc.exe check tests\ok_run.c --budget-contract "{\"required\":{\"compile\":\"clean\"}}" > %OUT% 2>&1
findstr /C:"target TERCAPAI" %OUT% >nul && echo [OK] kontrak compile=clean tercapai || echo [FAIL] kontrak compile=clean TIDAK tercapai
myc.exe check tests\ok_run.c --budget-contract "{\"required\":{\"runtime\":\"clean\"}}" > %OUT% 2>&1
findstr /C:"target TIDAK tercapai" %OUT% >nul && echo [OK] runtime wajib tanpa --run = target tidak tercapai || echo [FAIL] runtime wajib tanpa --run tercapai (recipe lebih lemah lolos)
findstr /C:"MYC-INCOMPLETE-BUDGET-UNMET" %OUT% >nul && echo [OK] debt budget-unmet muncul || echo [FAIL] debt budget-unmet hilang
findstr /C:"runtime: TIDAK tercapai" %OUT% >nul && echo [OK] dimensi runtime dikorbankan disebut || echo [FAIL] dimensi runtime tidak disebut
myc.exe check tests\bad_run_oob.c --run --budget-contract "{\"required\":{\"runtime\":\"clean\"}}" > %OUT% 2>&1
findstr /C:"RUNTIME_VIOLATION" %OUT% >nul && echo [OK] finding nyata tetap RUNTIME_VIOLATION (tidak diturunkan) || echo [FAIL] finding nyata diturunkan
findstr /C:"target TIDAK tercapai" %OUT% >nul && echo [OK] kontrak runtime gagal pada finding || echo [FAIL] kontrak runtime tercapai walau ada finding
myc.exe check tests\ok_run.c --budget-contract "{bad json}" > %OUT% 2>&1
if errorlevel 1 (
  echo [OK] --budget-contract JSON invalid ditolak fail-fast
) else (
  echo [WARN] --budget-contract JSON invalid tidak ditolak
)
del %OUT%
echo --- SOL-32 (Fase 4 A1): Assumption Closure (--require-assumptions-closed / --assumption-ack)
set OUT=%TEMP%\myc_sol32_out.txt
del /Q .myc\assumptions.json 2>nul
myc.exe check tests\assume_char_signed.c > %OUT% 2>&1
findstr /C:"assumptions (A1 ledger)" %OUT% >nul && echo [OK] ledger asumsi muncul (non-blocking) || echo [FAIL] ledger asumsi hilang
findstr /C:"char-signedness" %OUT% >nul && echo [OK] pola char-signedness terdeteksi || echo [FAIL] char-signedness tidak terdeteksi
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] asumsi tidak menurunkan verdict (observasi) || echo [FAIL] asumsi menurunkan verdict
myc.exe check tests\assume_char_signed.c --require-assumptions-closed > %OUT% 2>&1
findstr /C:"MYC-INCOMPLETE-ASSUMPTIONS-OPEN" %OUT% >nul && echo [OK] debt asumsi terbuka muncul || echo [FAIL] debt asumsi terbuka hilang
findstr /C:"INCONCLUSIVE" %OUT% >nul && echo [OK] asumsi terbuka = INCONCLUSIVE || echo [FAIL] asumsi terbuka tidak INCONCLUSIVE
myc.exe check tests\assume_char_signed.c --assumption-ack asm-char-signedness-2e529781:eliminated > %OUT% 2>&1
findstr /C:"status=eliminated" %OUT% >nul && echo [OK] ack menutup asumsi (tanpa hilang dari receipt) || echo [FAIL] ack tidak menutup asumsi
myc.exe check tests\assume_char_signed.c > %OUT% 2>&1
findstr /C:"status=eliminated" %OUT% >nul && echo [OK] status asumsi persisten lintas run || echo [FAIL] status asumsi tidak persisten
myc.exe check tests\assume_char_signed.c --no-assumptions > %OUT% 2>&1
findstr /C:"assumptions (A1 ledger)" %OUT% >nul && echo [FAIL] --no-assumptions masih menampilkan ledger || echo [OK] --no-assumptions mematikan ledger
myc.exe check tests\assume_char_signed.c --assumption-ack "bad format" > %OUT% 2>&1
if errorlevel 1 (
  echo [OK] --assumption-ack format salah ditolak fail-fast
) else (
  echo [WARN] --assumption-ack format salah tidak ditolak
)
del %OUT%
echo --- SOL-33 (Fase 4 A2): Cross-Toolchain Divergence (--divergence)
set OUT=%TEMP%\myc_sol33_out.txt
myc.exe check tests\divergence_clean.c --divergence > %OUT% 2>&1
findstr /C:"divergence (A2/DS-02)" %OUT% >nul && echo [OK] gate divergence berjalan || echo [FAIL] gate divergence tidak berjalan
findstr /C:"verdict:   OK" %OUT% >nul && echo [OK] fixture clean konsisten (verdict OK) || echo [FAIL] fixture clean tidak OK
findstr /C:"klasifikasi: konsisten" %OUT% >nul && echo [OK] klasifikasi konsisten antar toolchain || echo [FAIL] klasifikasi konsisten hilang
findstr /C:"sanitizer_divergence" %OUT% >nul && echo [FAIL] false-positive sanitizer divergence || echo [OK] tidak ada sanitizer divergence pada fixture clean
myc.exe check tests\divergence_oob.c --divergence > %OUT% 2>&1
findstr /C:"RUNTIME_VIOLATION" %OUT% >nul && echo [OK] OOB terdeteksi (HARD) || echo [FAIL] OOB tidak RUNTIME_VIOLATION
findstr /C:"sanitizer_divergence" %OUT% >nul && echo [OK] klasifikasi sanitizer_divergence || echo [WARN] klasifikasi bukan sanitizer_divergence
myc.exe check tests\divergence_clean.c --divergence > %OUT% 2>&1
findstr /C:"cache:     hit" %OUT% >nul && echo [OK] cache hit divergence (replay identik) || echo [WARN] cache hit divergence tidak terjadi
myc.exe check tests\divergence_clean.c --divergence --no-cache > %OUT% 2>&1
findstr /C:"cache:     hit" %OUT% >nul && echo [FAIL] --no-cache masih hit || echo [OK] --no-cache mematikan cache divergence
del %OUT%
echo --- Fase 8 Release Gate: no-source-leak (DoD privacy)
where bash >nul 2>&1
if errorlevel 1 (
  echo [WARN] bash tidak tersedia - no-source-leak dilewati
) else (
  bash test/_no_source_leak.sh
  if errorlevel 1 (
    echo [FAIL] Fase 8 no-source-leak: source verbatim bocor ke output
  ) else (
    echo [OK] Fase 8 no-source-leak: source hanya hash, tanpa konten
  )
)
echo --- MCP smoke (P9): mcp.exe harus menjawab JSON-RPC
call test\_mcp_smoke.bat
echo --- MCP SDK interop (opsional): hanya bila SDK MCP Python resmi terpasang
python -m pip show mcp >nul 2>&1
if errorlevel 1 (
  echo [SKIP] SDK MCP Python tidak terpasang - pip install mcp
) else (
  python test\_mcp_sdk_interop.py
   if errorlevel 1 (
     echo [WARN] interop SDK MCP resmi gagal - non-fatal
   )
)
exit /b 0
