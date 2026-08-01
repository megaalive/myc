@echo off
setlocal
set OUT=test\_tmp_run_out.txt
echo --- self-dogfooding: semua source myc harus OK
for %%f in (myc.c proc.c scanner.c policy.c compile.c report.c sha256.c lint.c run.c contract.c prove.c filc.c json.c mcp.c) do (
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
echo --- filc fixtures (--filc): di-skip bila Fil-C tak tersedia (non-blocking)
for %%f in (test\fixtures\ok_filc.c test\fixtures\bad_filc_oob.c) do (
  echo === %%f
  myc.exe check "%%f" --filc > %OUT%
  findstr /B /C:"verdict:" /C:"assurance:" /C:"filc:" /C:"  panics:" %OUT%
)
del %OUT%
echo --- MCP smoke (P9): mcp.exe harus menjawab JSON-RPC
call test\_mcp_smoke.bat
exit /b 0
